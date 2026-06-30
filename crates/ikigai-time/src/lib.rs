//! The **time transport** — a standalone transport that *originates* kernel
//! resource-requests on a timer.
//!
//! The embedded/IPC/QUIC transports are *inbound*: a request arrives and they drive
//! the kernel. The time transport is the inverse — it *holds* a [`Resolver`] handle
//! and issues a request on its own schedule, like a cron job that fires a resource
//! invocation when its timer elapses. A job is `(target IRI, verb, interval,
//! recurring?)`; recurring jobs re-fire every interval, one-shot jobs fire once.
//!
//! The timing backend is **injected** (the same pattern as the kernel's `Spawner`,
//! `Clock`, and the HTTP transport): native hosts supply [`ThreadTimer`] (a
//! `std::thread` that sleeps); the browser supplies a `setInterval`-backed one. The
//! registry, the schedule parser, and the `urn:time:*` control resources are all
//! environment-agnostic.
//!
//! The job registry surfaces through three resources the host mounts:
//! - `source urn:time:schedule target=<iri> every=<dur>` (or `after=<dur>` for a
//!   one-shot, `method=<verb>` to pick the verb) — registers a job, returns its id;
//! - `source urn:time:cancel id=<n>` — stops and removes a job;
//! - `source urn:time:jobs` — the live job list (id, target, interval, runs, last
//!   output), which the Control page composes alongside the scheduler and cache.
//!
//! `every=`/`after=` take a simple duration today (`500ms`, `1s`, `10s`, `1m`, `2h`).
//! [`Schedule`] is an enum so a cron-expression variant can slot in later (parsed by
//! a wasm-friendly crate) without changing the registry or the resources.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ikigai_core::{
    ArgSpec, Capability, Description, EndpointSpace, Error, Exact, FnEndpoint, Invocation, Iri,
    ReprType, Representation, Request, Verb,
};
use ikigai_resolve::Resolver;

/// When a job fires. Today only a fixed interval; a `Cron(..)` variant (parsed by a
/// wasm-friendly cron crate) is the planned extension — the registry only needs the
/// next interval, so adding it won't disturb anything here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Schedule {
    /// Fire every `Duration`.
    Every(Duration),
}

impl Schedule {
    /// The delay until the next (or only) fire.
    pub fn interval(&self) -> Duration {
        match self {
            Schedule::Every(d) => *d,
        }
    }
}

/// Parse a schedule string. Today a bare duration — `500ms`, `1s`, `10s`, `1m`, `2h`
/// (a unitless number is seconds). Future: a cron expression dispatches to a
/// `Schedule::Cron` variant here.
pub fn parse_schedule(s: &str) -> std::result::Result<Schedule, String> {
    Ok(Schedule::Every(parse_duration(s)?))
}

/// Parse `<n><unit>` into a [`Duration`]. Units: `ms`, `s` (default), `m`, `h`.
fn parse_duration(s: &str) -> std::result::Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid duration '{s}' (expected e.g. 1s, 10s, 1m)"))?;
    let d = match unit.trim() {
        "ms" => Duration::from_millis(n),
        "s" | "" => Duration::from_secs(n),
        "m" => Duration::from_secs(n * 60),
        "h" => Duration::from_secs(n * 3600),
        other => return Err(format!("unknown time unit '{other}' (use ms, s, m, h)")),
    };
    if d.is_zero() {
        return Err("duration must be greater than zero".to_string());
    }
    Ok(d)
}

fn parse_verb(s: &str) -> Verb {
    match s.trim().to_ascii_lowercase().as_str() {
        "sink" => Verb::Sink,
        "exists" => Verb::Exists,
        "delete" => Verb::Delete,
        "meta" => Verb::Meta,
        _ => Verb::Source,
    }
}

fn verb_label(v: Verb) -> &'static str {
    match v {
        Verb::Source => "source",
        Verb::Sink => "sink",
        Verb::Exists => "exists",
        Verb::Delete => "delete",
        Verb::Meta => "meta",
    }
}

fn fmt_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms != 0 && ms.is_multiple_of(3_600_000) {
        format!("{}h", ms / 3_600_000)
    } else if ms != 0 && ms.is_multiple_of(60_000) {
        format!("{}m", ms / 60_000)
    } else if ms.is_multiple_of(1000) {
        format!("{}s", ms / 1000)
    } else {
        format!("{ms}ms")
    }
}

/// A handle to a running timer; calling [`TimerHandle::cancel`] (or dropping it)
/// stops future ticks.
pub struct TimerHandle {
    cancel: Box<dyn Fn() + Send + Sync>,
}

impl TimerHandle {
    /// Build a handle from a cancel closure.
    pub fn new(cancel: impl Fn() + Send + Sync + 'static) -> Self {
        TimerHandle {
            cancel: Box::new(cancel),
        }
    }

    /// Stop future ticks.
    pub fn cancel(&self) {
        (self.cancel)();
    }
}

/// The injected timing backend: arrange for `on_tick` to be called every `interval`
/// (once if `!recurring`), out of band. Native = a sleeping thread; browser =
/// `setInterval`. Returns a [`TimerHandle`] that cancels it.
pub trait TimerBackend: Send + Sync {
    fn start(
        &self,
        interval: Duration,
        recurring: bool,
        on_tick: Arc<dyn Fn() + Send + Sync>,
    ) -> TimerHandle;
}

/// Native timing backend: each job gets a `std::thread` that sleeps for the interval,
/// fires, and (if recurring) loops. Cancellation flips an atomic the loop checks.
#[cfg(not(target_family = "wasm"))]
pub struct ThreadTimer;

#[cfg(not(target_family = "wasm"))]
impl TimerBackend for ThreadTimer {
    fn start(
        &self,
        interval: Duration,
        recurring: bool,
        on_tick: Arc<dyn Fn() + Send + Sync>,
    ) -> TimerHandle {
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancelled);
        std::thread::spawn(move || loop {
            std::thread::sleep(interval);
            if flag.load(Ordering::Relaxed) {
                break;
            }
            on_tick();
            if !recurring {
                break;
            }
        });
        TimerHandle::new(move || cancelled.store(true, Ordering::Relaxed))
    }
}

struct JobRecord {
    id: u64,
    target: String,
    verb: Verb,
    schedule: Schedule,
    recurring: bool,
    runs: u64,
    last_output: String,
    handle: TimerHandle,
}

struct Inner {
    next_id: u64,
    jobs: BTreeMap<u64, JobRecord>,
    resolver: Option<Arc<dyn Resolver>>,
    capability: Capability,
    backend: Arc<dyn TimerBackend>,
}

/// The registry of timed jobs — shared (cheaply cloneable) between the `urn:time:*`
/// control endpoints and the timer backend. A job fires a kernel request through the
/// installed [`Resolver`] under [`Inner::capability`].
#[derive(Clone)]
pub struct JobRegistry {
    inner: Arc<Mutex<Inner>>,
}

impl JobRegistry {
    /// A registry driven by `backend`, firing under full authority until
    /// [`with_capability`](Self::with_capability) narrows it. The [`Resolver`] must be
    /// installed with [`set_resolver`](Self::set_resolver) before any job is scheduled
    /// (the host does this once the kernel is built).
    pub fn new(backend: Arc<dyn TimerBackend>) -> Self {
        JobRegistry {
            inner: Arc::new(Mutex::new(Inner {
                next_id: 1,
                jobs: BTreeMap::new(),
                resolver: None,
                capability: Capability::root(),
                backend,
            })),
        }
    }

    /// Set the authority timed requests fire under (defaults to root).
    pub fn with_capability(self, capability: Capability) -> Self {
        self.inner.lock().expect("time registry lock").capability = capability;
        self
    }

    /// Install the kernel handle jobs fire requests on. Called once by the host after
    /// the kernel is built (the endpoints are bound into that same kernel).
    pub fn set_resolver(&self, resolver: Arc<dyn Resolver>) {
        self.inner.lock().expect("time registry lock").resolver = Some(resolver);
    }

    /// Register a job and start its timer. Returns the new job id, or an error if no
    /// resolver is installed yet.
    pub fn schedule(
        &self,
        target: String,
        verb: Verb,
        schedule: Schedule,
        recurring: bool,
    ) -> std::result::Result<u64, String> {
        // Reserve an id and grab the backend handle under a *short* lock, then release
        // it before calling into the backend. `start()` runs injected code that ticks
        // out of band, and every tick re-acquires this same lock in `fire()`; holding
        // it across `start()` would deadlock any backend that ticks eagerly (the trap
        // the synchronous test backend originally fell into).
        let (id, backend) = {
            let mut inner = self.inner.lock().expect("time registry lock");
            if inner.resolver.is_none() {
                return Err("time transport not ready (no kernel handle installed)".to_string());
            }
            let id = inner.next_id;
            inner.next_id += 1;
            (id, Arc::clone(&inner.backend))
        };

        // The per-fire action: issue the request through the kernel, then record the
        // outcome. `fire` takes the registry lock itself only after resolving, so a
        // slow resolve never holds the lock.
        let reg = self.clone();
        let target_for_tick = target.clone();
        let on_tick: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            reg.fire(id, &target_for_tick, verb);
        });

        // Start the timer with the lock released. A tick that somehow fires before we
        // insert the record below finds no job and is dropped (benign); real backends
        // wait a full interval first, so this window never matters in practice.
        let handle = backend.start(schedule.interval(), recurring, on_tick);

        self.inner.lock().expect("time registry lock").jobs.insert(
            id,
            JobRecord {
                id,
                target,
                verb,
                schedule,
                recurring,
                runs: 0,
                last_output: String::new(),
                handle,
            },
        );
        Ok(id)
    }

    /// Stop and remove a job. Returns whether it existed.
    pub fn cancel(&self, id: u64) -> bool {
        let mut inner = self.inner.lock().expect("time registry lock");
        if let Some(job) = inner.jobs.remove(&id) {
            job.handle.cancel();
            true
        } else {
            false
        }
    }

    /// Fire one tick of a job: resolve its request and fold the outcome into the
    /// record. A one-shot's timer won't tick again; we leave the record listed (runs
    /// = 1) so the result is visible.
    fn fire(&self, id: u64, target: &str, verb: Verb) {
        // Clone the handle out under a short lock; resolve without holding it.
        let resolver = {
            let inner = self.inner.lock().expect("time registry lock");
            match &inner.resolver {
                Some(r) => (Arc::clone(r), inner.capability.clone()),
                None => return,
            }
        };
        let (resolver, capability) = resolver;
        let outcome = match Iri::parse(target) {
            Ok(iri) => match resolver.issue_as(Request::new(verb, iri), &capability) {
                Ok((rep, _status)) => one_line(&String::from_utf8_lossy(&rep.bytes)),
                Err(e) => format!("error: {}", one_line(&e)),
            },
            Err(e) => format!("error: bad target: {e}"),
        };
        let mut inner = self.inner.lock().expect("time registry lock");
        if let Some(job) = inner.jobs.get_mut(&id) {
            job.runs += 1;
            job.last_output = outcome;
        }
    }

    /// Render the job list as the `urn:time:jobs` readout.
    fn render(&self) -> String {
        let inner = self.inner.lock().expect("time registry lock");
        let mut s = String::from("time jobs\n");
        if inner.jobs.is_empty() {
            s.push_str("  (none scheduled)\n");
            return s;
        }
        for job in inner.jobs.values() {
            let when = if job.recurring { "every" } else { "after" };
            s.push_str(&format!(
                "  #{}  {} {}  {} {}  runs {}\n",
                job.id,
                verb_label(job.verb),
                job.target,
                when,
                fmt_duration(job.schedule.interval()),
                job.runs,
            ));
            if !job.last_output.is_empty() {
                s.push_str(&format!("       last: {}\n", job.last_output));
            }
        }
        s
    }
}

/// Collapse a (possibly multi-line) body to a single trimmed line, capped, for the
/// jobs readout.
fn one_line(s: &str) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() > 80 {
        let cut: String = flat.chars().take(77).collect();
        format!("{cut}…")
    } else {
        flat
    }
}

fn text(body: String) -> Representation {
    Representation::new(
        ReprType::new("text/plain").with_param("charset", "utf-8"),
        body.into_bytes(),
    )
}

/// The `urn:time:*` control plane bound against `registry`. Mount this in the host's
/// root space; install the kernel handle with [`JobRegistry::set_resolver`] once the
/// kernel is built.
pub fn space(registry: JobRegistry) -> EndpointSpace {
    let schedule_reg = registry.clone();
    let cancel_reg = registry.clone();
    let jobs_reg = registry;

    EndpointSpace::new()
        .bind(
            Exact::new("urn:time:schedule"),
            FnEndpoint::new("time-schedule", move |inv: &Invocation<'_>| {
                let target = inv.inline_str("target").map_err(|_| {
                    Error::Endpoint("urn:time:schedule needs target=<iri>".to_string())
                })?;
                let (dur_str, recurring) = if let Ok(every) = inv.inline_str("every") {
                    (every, true)
                } else if let Ok(after) = inv.inline_str("after") {
                    (after, false)
                } else {
                    return Err(Error::Endpoint(
                        "urn:time:schedule needs every=<dur> (recurring) or after=<dur> (one-shot), e.g. every=1s"
                            .to_string(),
                    ));
                };
                let schedule = parse_schedule(dur_str).map_err(Error::Endpoint)?;
                let verb = inv
                    .inline_str("method")
                    .map(parse_verb)
                    .unwrap_or(Verb::Source);
                // Validate the IRI before registering, so a bad target fails the call
                // rather than every silent tick.
                Iri::parse(target)
                    .map_err(|e| Error::Endpoint(format!("bad target '{target}': {e}")))?;
                let interval = schedule.interval();
                let id = schedule_reg
                    .schedule(target.to_string(), verb, schedule, recurring)
                    .map_err(Error::Endpoint)?;
                let when = if recurring { "every" } else { "after" };
                Ok(text(format!(
                    "scheduled job #{id}: {} {target} {when} {}\n",
                    verb_label(verb),
                    fmt_duration(interval),
                )))
            })
            .with_description(
                Description::new("time-schedule")
                    .title("Schedule a timed request")
                    .summary(
                        "Register a job that fires a resource-request on a timer. \
                         every=<dur> recurs; after=<dur> is one-shot; method=<verb> picks the verb.",
                    )
                    .verb(Verb::Source)
                    .input(ArgSpec::new("target").summary("the resource IRI to invoke"))
                    .input(
                        ArgSpec::new("every")
                            .summary("recurring interval, e.g. 1s, 10s, 1m")
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("after")
                            .summary("one-shot delay, e.g. 5s")
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("method")
                            .summary("verb to invoke (source|sink|exists|delete|meta); default source")
                            .optional(),
                    )
                    .output("text/plain;charset=utf-8"),
            ),
        )
        .bind(
            Exact::new("urn:time:cancel"),
            FnEndpoint::new("time-cancel", move |inv: &Invocation<'_>| {
                let id_str = inv
                    .inline_str("id")
                    .map_err(|_| Error::Endpoint("urn:time:cancel needs id=<n>".to_string()))?;
                let id: u64 = id_str
                    .trim()
                    .parse()
                    .map_err(|_| Error::Endpoint(format!("invalid job id '{id_str}'")))?;
                let body = if cancel_reg.cancel(id) {
                    format!("cancelled job #{id}\n")
                } else {
                    format!("no job #{id}\n")
                };
                Ok(text(body))
            })
            .with_description(
                Description::new("time-cancel")
                    .title("Cancel a timed job")
                    .summary("Stop and remove a scheduled job by id.")
                    .verb(Verb::Source)
                    .input(ArgSpec::new("id").summary("the job id to cancel"))
                    .output("text/plain;charset=utf-8"),
            ),
        )
        .bind(
            Exact::new("urn:time:jobs"),
            FnEndpoint::new("time-jobs", move |_inv: &Invocation<'_>| {
                Ok(text(jobs_reg.render()))
            })
            .with_description(
                Description::new("time-jobs")
                    .title("Scheduled timed jobs")
                    .summary("The live list of time-transport jobs: target, interval, runs, last output.")
                    .verb(Verb::Source)
                    .output("text/plain;charset=utf-8"),
            ),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::SpaceEntry;
    use ikigai_resolve::CacheStatus;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("5").unwrap(), Duration::from_secs(5)); // unitless = seconds
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("1w").is_err());
    }

    #[test]
    fn formats_durations_round_trip() {
        assert_eq!(fmt_duration(Duration::from_secs(1)), "1s");
        assert_eq!(fmt_duration(Duration::from_secs(60)), "1m");
        assert_eq!(fmt_duration(Duration::from_secs(7200)), "2h");
        assert_eq!(fmt_duration(Duration::from_millis(500)), "500ms");
    }

    /// A backend that *captures* each job's tick closure instead of firing it. The
    /// test fires the ticks itself via [`ManualBackend::fire_all`] — out of band,
    /// after `schedule()` has returned and released the registry lock, exactly the way
    /// the real thread/`setInterval` backends do. Firing in-band from inside `start()`
    /// (which runs while `schedule()` holds the lock) would re-enter the registry mutex
    /// and deadlock.
    #[derive(Default)]
    struct ManualBackend {
        ticks: Mutex<Vec<Arc<dyn Fn() + Send + Sync>>>,
    }
    impl ManualBackend {
        /// Fire every captured job's tick `times` times.
        fn fire_all(&self, times: usize) {
            let ticks = self.ticks.lock().expect("ticks lock").clone();
            for tick in ticks {
                for _ in 0..times {
                    tick();
                }
            }
        }
    }
    impl TimerBackend for ManualBackend {
        fn start(
            &self,
            _interval: Duration,
            _recurring: bool,
            on_tick: Arc<dyn Fn() + Send + Sync>,
        ) -> TimerHandle {
            self.ticks.lock().expect("ticks lock").push(on_tick);
            TimerHandle::new(|| {})
        }
    }

    /// A stub resolver that echoes a fixed body, counting how many times it's issued.
    struct StubResolver {
        issued: Arc<AtomicU64>,
    }
    impl Resolver for StubResolver {
        fn issue(
            &self,
            _request: Request,
        ) -> std::result::Result<(Representation, CacheStatus), String> {
            self.issued.fetch_add(1, Ordering::SeqCst);
            Ok((text("Hello, World".to_string()), CacheStatus::Uncacheable))
        }
        fn is_cached(&self, _request: &Request, _capability: &Capability) -> bool {
            false
        }
        fn entries(&self) -> Option<Vec<SpaceEntry>> {
            None
        }
    }

    #[test]
    fn schedules_fires_and_renders() {
        let issued = Arc::new(AtomicU64::new(0));
        let backend = Arc::new(ManualBackend::default());
        let reg = JobRegistry::new(backend.clone());
        reg.set_resolver(Arc::new(StubResolver {
            issued: Arc::clone(&issued),
        }));

        let id = reg
            .schedule(
                "urn:demo:greeter".to_string(),
                Verb::Source,
                Schedule::Every(Duration::from_secs(1)),
                true,
            )
            .expect("scheduled");
        assert_eq!(id, 1);

        // Fire out of band — after schedule() released the registry lock, the way the
        // real thread/setInterval backends tick. Firing inside start() would deadlock.
        backend.fire_all(3);
        assert_eq!(issued.load(Ordering::SeqCst), 3);

        let rendered = reg.render();
        assert!(rendered.contains("#1"));
        assert!(rendered.contains("urn:demo:greeter"));
        assert!(rendered.contains("runs 3"));
        assert!(rendered.contains("last: Hello, World"));

        assert!(reg.cancel(1));
        assert!(!reg.cancel(1));
        assert!(reg.render().contains("(none scheduled)"));
    }

    #[test]
    fn schedule_without_resolver_errors() {
        let reg = JobRegistry::new(Arc::new(ManualBackend::default()));
        let err = reg
            .schedule(
                "urn:demo:greeter".to_string(),
                Verb::Source,
                Schedule::Every(Duration::from_secs(1)),
                true,
            )
            .unwrap_err();
        assert!(err.contains("not ready"));
    }
}
