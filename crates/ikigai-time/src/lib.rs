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
//! - `source urn:time:cancel id=<n>` — stops a job (or `id=all` for every
//!   non-persistent job, or `target=<iri>` for every job firing that resource);
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
    ArgSpec, Capability, Clock, Description, EndpointSpace, Error, Exact, FnEndpoint, Invocation,
    Iri, ReprType, Representation, Request, Time, Verb,
};
use ikigai_resolve::Resolver;

/// A resource IRI — what `target=` is, on both `urn:time:schedule` and `urn:time:cancel`.
const XSD_ANY_URI: &str = "http://www.w3.org/2001/XMLSchema#anyURI";
/// A duration spelling (`1s`, `10m`) or a job id: a string on the wire.
///
/// ⚠ **Not** `xsd:duration`. `every=1m` / `after=5s` are this module's own compact grammar,
/// not ISO 8601 (`PT1M`), so declaring the XSD duration type would tell
/// `urn:kernel:validate` that every value this endpoint actually accepts is malformed —
/// a class that is a lie in the direction that breaks callers. `xsd:string` is what the
/// wire carries; the summary carries the grammar (conformance PENDING #14/#15).
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

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
    /// A persistent job is skipped by [`cancel_all`](JobRegistry::cancel_all) — a
    /// blanket "cancel all" leaves it running. For host-registered background timers
    /// (e.g. the nav clock) that a demo's cancel-all shouldn't stop. Still cancellable
    /// explicitly by id or target.
    persistent: bool,
    runs: u64,
    last_output: String,
    /// When this job last COMPLETED a fire, stamped from the kernel's injected
    /// [`Clock`]. The fact staleness is computed from: a recurring job that declares
    /// its own cadence can be judged against it without anyone configuring a threshold.
    ///
    /// **This is WALL-CLOCK time, not monotonic.** `std::time::Instant` — the obvious
    /// monotonic choice — is unimplemented on `wasm32-unknown-unknown`: it compiles and
    /// panics at runtime, and this line is where it did. Wall-clock is what the kernel's
    /// clock seam offers and it is good enough for staleness reporting, but the trade is
    /// real: a backwards clock adjustment between a fire and a [`JobRegistry::health`]
    /// read makes `now` earlier than this stamp. That case clamps to zero rather than
    /// underflowing — see `since_last` on [`JobHealth`].
    last_run: Option<Time>,
    /// The [`SleepClock`] reading taken with `last_run` — how long the machine had been
    /// asleep, cumulatively, when this job last completed. `None` without a sleep clock.
    asleep_at_last_run: Option<Duration>,
    /// When this job last completed a fire that did NOT fail, on the same wall clock.
    last_success: Option<Time>,
    /// Consecutive completed fires that failed; any success resets it.
    failures_in_a_row: u64,
    handle: TimerHandle,
}

/// Cumulative time this machine has spent **asleep** (suspended), measured from a fixed
/// origin such as boot — the evidence that separates a job that was LATE from a machine
/// that was not running at all.
///
/// A second injected seam beside the kernel's [`Clock`], not a replacement for it. `Clock`
/// is wall time, and wall time keeps moving while a laptop or a sleepy Mac mini is
/// suspended, so "overdue by three cadences" measured on it calls every job stale after
/// every nap. Two readings of this clock bracket a window: their difference is the part of
/// that window spent asleep, which a health report can discount and say it discounted.
///
/// Only DIFFERENCES are meaningful, so the origin is the implementor's. Return `None` when
/// the platform cannot tell; the registry then reports no discount, which errs toward
/// calling a sleeping machine's jobs stale — the behavior before this seam existed —
/// rather than toward excusing a job that really stopped.
pub trait SleepClock: Send + Sync {
    /// Total time asleep since this clock's origin, or `None` if it cannot be measured.
    fn asleep(&self) -> Option<Duration>;
}

struct Inner {
    next_id: u64,
    jobs: BTreeMap<u64, JobRecord>,
    resolver: Option<Arc<dyn Resolver>>,
    capability: Capability,
    backend: Arc<dyn TimerBackend>,
}

/// One job's liveness, as [`JobRegistry::health`] reports it.
#[derive(Clone, Debug)]
pub struct JobHealth {
    pub id: u64,
    pub target: String,
    /// The cadence the job DECLARED. Staleness is judged against this, so no threshold
    /// has to be configured anywhere.
    pub interval: std::time::Duration,
    pub recurring: bool,
    pub persistent: bool,
    pub runs: u64,
    /// How long since the job last completed, measured on the injected wall clock.
    /// `None` means exactly one thing: **it has never completed a run** — so a
    /// backwards clock adjustment reports `Some(0)` ("just now"), never `None`.
    /// Conflating the two would tell a health report that a job which has run 400
    /// times has never run at all.
    pub since_last: Option<std::time::Duration>,
    /// How much of `since_last` the machine spent asleep, from the registry's
    /// [`SleepClock`]. `None` when there is no evidence — no sleep clock installed, the
    /// platform cannot measure it, or the job has never completed — and never a guess:
    /// `None` means "count all of `since_last` as lateness".
    pub asleep_since_last: Option<std::time::Duration>,
    /// How long since the job last completed a run that did not fail, on the wall clock.
    /// `None` means it has never succeeded (it may still have run and failed).
    pub since_last_success: Option<std::time::Duration>,
    /// Consecutive completed runs that failed. A job can run exactly on time and fail every
    /// time; `since_last` alone reads that as healthy.
    pub failures_in_a_row: u64,
    pub last_output: String,
}

/// The registry of timed jobs — shared (cheaply cloneable) between the `urn:time:*`
/// control endpoints and the timer backend. A job fires a kernel request through the
/// installed [`Resolver`] under the private `Inner::capability`.
#[derive(Clone)]
pub struct JobRegistry {
    inner: Arc<Mutex<Inner>>,
    /// The kernel's injected clock, held deliberately OUTSIDE the mutex. Reading it
    /// runs host code (a browser clock calls into JS), and host code must not run
    /// inside this critical section: a panic there is not a lost tick but a dead
    /// registry — native poisons the mutex, and wasm's `no_threads` mutex fails every
    /// later acquisition, so every `urn:time:*` read afterwards panics too. Keeping
    /// the clock outside the lock makes "stamp before you lock" structural instead of
    /// a rule someone has to remember.
    clock: Arc<dyn Clock>,
    /// Evidence of machine sleep, read beside `clock` and for the same reason outside the
    /// mutex. Optional: a browser host has none to offer, and a registry without it reports
    /// lateness in wall time exactly as it always did.
    sleep: Option<Arc<dyn SleepClock>>,
}

impl JobRegistry {
    /// A registry driven by `backend` and stamped by `clock`, firing under full
    /// authority until [`with_capability`](Self::with_capability) narrows it. The
    /// [`Resolver`] must be installed with [`set_resolver`](Self::set_resolver) before
    /// any job is scheduled (the host does this once the kernel is built).
    ///
    /// `clock` is the same [`Clock`] the host injects into its kernel: a native host
    /// passes [`ikigai_core::SystemClock`], a browser host passes its `Date.now()`-backed
    /// one. It is a **required** argument rather than a defaulted one on purpose —
    /// the obvious default, `SystemClock`, reads `std::time::SystemTime`, which panics
    /// on `wasm32-unknown-unknown` exactly like the `Instant` it replaced. A default
    /// would move the wasm landmine rather than remove it; a required argument makes a
    /// clockless registry a compile error in the host that forgot.
    pub fn new(backend: Arc<dyn TimerBackend>, clock: Arc<dyn Clock>) -> Self {
        JobRegistry {
            inner: Arc::new(Mutex::new(Inner {
                next_id: 1,
                jobs: BTreeMap::new(),
                resolver: None,
                capability: Capability::root(),
                backend,
            })),
            clock,
            sleep: None,
        }
    }

    /// Install a [`SleepClock`], so [`health`](Self::health) can report how much of each
    /// job's lateness the machine spent asleep. Install it before scheduling: a job that
    /// completed without one has no reading to difference against until it runs again.
    pub fn with_sleep_clock(mut self, sleep: Arc<dyn SleepClock>) -> Self {
        self.sleep = Some(sleep);
        self
    }

    /// Whether this registry can currently measure machine sleep — a sleep clock is
    /// installed AND it answers. A health report says so when it cannot, because then a
    /// late job may only have been asleep.
    pub fn measures_sleep(&self) -> bool {
        self.sleep.as_ref().and_then(|s| s.asleep()).is_some()
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
        self.schedule_inner(target, verb, schedule, recurring, false)
    }

    /// Like [`schedule`](Self::schedule), but the job is **persistent** —
    /// [`cancel_all`](Self::cancel_all) skips it. For host-registered background timers
    /// (the nav clock) that a demo's "cancel all" button shouldn't stop. Cancel it
    /// explicitly with [`cancel`](Self::cancel) or [`cancel_target`](Self::cancel_target).
    pub fn schedule_persistent(
        &self,
        target: String,
        verb: Verb,
        schedule: Schedule,
        recurring: bool,
    ) -> std::result::Result<u64, String> {
        self.schedule_inner(target, verb, schedule, recurring, true)
    }

    fn schedule_inner(
        &self,
        target: String,
        verb: Verb,
        schedule: Schedule,
        recurring: bool,
        persistent: bool,
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
                persistent,
                runs: 0,
                last_output: String::new(),
                last_run: None,
                asleep_at_last_run: None,
                last_success: None,
                failures_in_a_row: 0,
                handle,
            },
        );
        Ok(id)
    }

    /// Stop and remove a job. Returns whether it existed.
    ///
    /// The record is dropped from the map under the lock; the timer is cancelled with
    /// the lock RELEASED. [`TimerHandle::cancel`] runs injected host code (the
    /// browser's `clearInterval`), and injected code may panic or re-enter the
    /// registry — either of which, under the lock, kills the registry permanently.
    /// This is the same hazard `schedule_inner` already avoids around `start()`; it
    /// applies just as much on the way out.
    pub fn cancel(&self, id: u64) -> bool {
        let removed = self
            .inner
            .lock()
            .expect("time registry lock")
            .jobs
            .remove(&id);
        match removed {
            Some(job) => {
                job.handle.cancel();
                true
            }
            None => false,
        }
    }

    /// Stop and remove every **non-persistent** job. Returns how many were cancelled —
    /// persistent jobs are left running (cancel those explicitly by id or target). Ids
    /// keep incrementing — a later schedule still gets a fresh id.
    pub fn cancel_all(&self) -> usize {
        self.remove_and_cancel(|job| !job.persistent)
    }

    /// Stop and remove every job whose target IRI is `target` (persistent or not — an
    /// explicit target is deliberate). Returns how many were cancelled.
    pub fn cancel_target(&self, target: &str) -> usize {
        self.remove_and_cancel(|job| job.target == target)
    }

    /// Drop every job matching `predicate` from the map under the lock, then cancel
    /// their timers with the lock RELEASED — see [`cancel`](Self::cancel) for why the
    /// second half must not happen inside the critical section. Returns how many.
    fn remove_and_cancel(&self, predicate: impl Fn(&JobRecord) -> bool) -> usize {
        let handles: Vec<TimerHandle> = {
            let mut inner = self.inner.lock().expect("time registry lock");
            let ids: Vec<u64> = inner
                .jobs
                .iter()
                .filter(|(_, job)| predicate(job))
                .map(|(id, _)| *id)
                .collect();
            ids.iter()
                .filter_map(|id| inner.jobs.remove(id))
                .map(|job| job.handle)
                .collect()
        };
        for handle in &handles {
            handle.cancel();
        }
        handles.len()
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
        let (outcome, succeeded) = match Iri::parse(target) {
            Ok(iri) => match resolver.issue_as(Request::new(verb, iri), &capability) {
                Ok((rep, _status)) => (one_line(&String::from_utf8_lossy(&rep.bytes)), true),
                Err(e) => (format!("error: {}", one_line(&e.to_string())), false),
            },
            Err(e) => (format!("error: bad target: {e}"), false),
        };
        // Stamp BEFORE locking. The clocks are host-injected code; reading one inside the
        // critical section is what turned one panic into a permanently dead registry.
        let at = self.clock.now();
        let asleep = self.sleep.as_ref().and_then(|s| s.asleep());
        let mut inner = self.inner.lock().expect("time registry lock");
        if let Some(job) = inner.jobs.get_mut(&id) {
            job.runs += 1;
            job.last_output = outcome;
            job.last_run = Some(at);
            job.asleep_at_last_run = asleep;
            if succeeded {
                job.last_success = Some(at);
                job.failures_in_a_row = 0;
            } else {
                job.failures_in_a_row += 1;
            }
        }
    }

    /// A machine-readable snapshot of every job's liveness, for a health report.
    ///
    /// Deliberately reports FACTS, not a verdict: how often the job is meant to run, how
    /// long since it did, and what it last said. Whether that is "stale" belongs to the
    /// caller, because the answer depends on what the job is for.
    pub fn health(&self) -> Vec<JobHealth> {
        // Read the clock before locking, for the same reason `fire` does.
        let now = self.clock.now().as_millis();
        let asleep_now = self.sleep.as_ref().and_then(|s| s.asleep());
        let inner = self.inner.lock().expect("time registry lock");
        // `saturating_sub`: a wall clock can step BACKWARDS between the fire and this read,
        // and an age of zero ("just now") is the honest answer there. Underflowing would
        // report ~584 million years, and reporting `None` would claim a job that has run
        // has never run.
        let age = |at: Time| Duration::from_millis(now.saturating_sub(at.as_millis()));
        inner
            .jobs
            .values()
            .map(|job| {
                let since_last = job.last_run.map(age);
                // Evidence needs BOTH readings. A sleep clock that answered at the fire but
                // not now (or the reverse) proves nothing, and no discount is taken. The
                // discount can never exceed the window it is taken from.
                let asleep_since_last = match (job.asleep_at_last_run, asleep_now, since_last) {
                    (Some(then), Some(latest), Some(window)) => {
                        Some(latest.saturating_sub(then).min(window))
                    }
                    _ => None,
                };
                JobHealth {
                    id: job.id,
                    target: job.target.clone(),
                    interval: job.schedule.interval(),
                    recurring: job.recurring,
                    persistent: job.persistent,
                    runs: job.runs,
                    since_last,
                    asleep_since_last,
                    since_last_success: job.last_success.map(age),
                    failures_in_a_row: job.failures_in_a_row,
                    last_output: job.last_output.clone(),
                }
            })
            .collect()
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
            let tag = if job.persistent { "  (persistent)" } else { "" };
            s.push_str(&format!(
                "  #{}  {} {}  {} {}  runs {}{}\n",
                job.id,
                verb_label(job.verb),
                job.target,
                when,
                fmt_duration(job.schedule.interval()),
                job.runs,
                tag,
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
                    .input(ArgSpec::new("target")
                            .summary("the resource IRI to invoke")
                            .class(XSD_ANY_URI))
                    .input(
                        ArgSpec::new("every")
                            .summary("recurring interval, e.g. 1s, 10s, 1m")
                            .class(XSD_STRING)
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("after")
                            .summary("one-shot delay, e.g. 5s")
                            .class(XSD_STRING)
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("method")
                            .summary("verb to invoke (source|sink|exists|delete|meta); default source")
                            .class(XSD_STRING)
                            .one_of(["source", "sink", "exists", "delete", "meta"])
                            .default_value("source")
                            .optional(),
                    )
                    .output("text/plain;charset=utf-8"),
            ),
        )
        .bind(
            Exact::new("urn:time:cancel"),
            FnEndpoint::new("time-cancel", move |inv: &Invocation<'_>| {
                let plural = |n: usize| if n == 1 { "" } else { "s" };
                // `target=<iri>` cancels every job firing that resource — precise, and
                // leaves other timers (e.g. the nav clock on urn:time:now) alone.
                if let Ok(target) = inv.inline_str("target") {
                    let target = target.trim();
                    let n = cancel_reg.cancel_target(target);
                    return Ok(text(format!("cancelled {n} job{} for {target}\n", plural(n))));
                }
                let id_str = inv.inline_str("id").map_err(|_| {
                    Error::Endpoint(
                        "urn:time:cancel needs id=<n>, id=all, or target=<iri>".to_string(),
                    )
                })?;
                let id_str = id_str.trim();
                // `id=all` cancels every non-persistent job — a demo "stop" button that
                // can't know the running job's id (ids increment and never reuse); it
                // leaves persistent jobs (the nav clock) running.
                if id_str.eq_ignore_ascii_case("all") {
                    let n = cancel_reg.cancel_all();
                    return Ok(text(format!("cancelled {n} job{}\n", plural(n))));
                }
                let id: u64 = id_str.parse().map_err(|_| {
                    Error::Endpoint(format!(
                        "invalid job id '{id_str}' (expected a number, 'all', or target=<iri>)"
                    ))
                })?;
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
                    .summary(
                        "Stop and remove a timed job: id=<n> (one), id=all (every \
                         non-persistent job), or target=<iri> (every job firing that resource).",
                    )
                    .verb(Verb::Source)
                    .input(ArgSpec::new("id")
                            .summary("the job id to cancel, or 'all'")
                            .class(XSD_STRING)
                            .optional())
                    .input(
                        ArgSpec::new("target")
                            .summary("cancel every job firing this target IRI")
                            .class(XSD_ANY_URI)
                            .optional(),
                    )
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
    use ikigai_core::{SpaceEntry, SystemClock};
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
        ) -> std::result::Result<(Representation, CacheStatus), Error> {
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
        let reg = JobRegistry::new(backend.clone(), Arc::new(SystemClock));
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
        let reg = JobRegistry::new(Arc::new(ManualBackend::default()), Arc::new(SystemClock));
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

    #[test]
    fn cancel_all_clears_every_job() {
        let issued = Arc::new(AtomicU64::new(0));
        let reg = JobRegistry::new(Arc::new(ManualBackend::default()), Arc::new(SystemClock));
        reg.set_resolver(Arc::new(StubResolver {
            issued: Arc::clone(&issued),
        }));
        let sched = |t: &str| {
            reg.schedule(
                t.to_string(),
                Verb::Source,
                Schedule::Every(Duration::from_secs(1)),
                true,
            )
            .expect("scheduled")
        };
        sched("urn:demo:a");
        sched("urn:demo:b");
        sched("urn:demo:c");
        assert_eq!(reg.cancel_all(), 3);
        assert!(reg.render().contains("(none scheduled)"));
        // Idempotent, and ids keep advancing (the next schedule is #4, not #1).
        assert_eq!(reg.cancel_all(), 0);
        assert_eq!(sched("urn:demo:d"), 4);
    }

    #[test]
    fn cancel_all_skips_persistent_but_target_and_id_still_remove_it() {
        let issued = Arc::new(AtomicU64::new(0));
        let reg = JobRegistry::new(Arc::new(ManualBackend::default()), Arc::new(SystemClock));
        reg.set_resolver(Arc::new(StubResolver {
            issued: Arc::clone(&issued),
        }));
        let every = || Schedule::Every(Duration::from_secs(1));
        // A persistent clock + two cancelable demo jobs.
        let clock = reg
            .schedule_persistent("urn:time:now".to_string(), Verb::Source, every(), true)
            .expect("scheduled");
        reg.schedule("urn:demo:greeter".to_string(), Verb::Source, every(), true)
            .unwrap();
        reg.schedule("urn:demo:greeter".to_string(), Verb::Source, every(), true)
            .unwrap();

        // cancel_all removes the two greeters, leaves the persistent clock.
        assert_eq!(reg.cancel_all(), 2);
        let rendered = reg.render();
        assert!(
            rendered.contains("urn:time:now"),
            "clock survives: {rendered}"
        );
        assert!(rendered.contains("(persistent)"), "marked: {rendered}");
        assert!(!rendered.contains("urn:demo:greeter"));

        // cancel_target removes the persistent clock explicitly (an explicit target
        // is deliberate, so it overrides persistence).
        assert_eq!(reg.cancel_target("urn:time:now"), 1);
        assert!(reg.render().contains("(none scheduled)"));
        // It's gone now, so a follow-up cancel by id finds nothing.
        assert!(!reg.cancel(clock));
    }

    #[test]
    fn cancel_target_removes_only_matching_jobs() {
        let issued = Arc::new(AtomicU64::new(0));
        let reg = JobRegistry::new(Arc::new(ManualBackend::default()), Arc::new(SystemClock));
        reg.set_resolver(Arc::new(StubResolver {
            issued: Arc::clone(&issued),
        }));
        let every = || Schedule::Every(Duration::from_secs(1));
        reg.schedule("urn:demo:greeter".to_string(), Verb::Source, every(), true)
            .unwrap();
        reg.schedule("urn:demo:greeter".to_string(), Verb::Source, every(), true)
            .unwrap();
        reg.schedule("urn:time:now".to_string(), Verb::Source, every(), true)
            .unwrap();
        assert_eq!(reg.cancel_target("urn:demo:greeter"), 2);
        let rendered = reg.render();
        assert!(rendered.contains("urn:time:now"));
        assert!(!rendered.contains("urn:demo:greeter"));
        assert_eq!(reg.cancel_target("urn:nope:missing"), 0);
    }

    /// A clock the test drives by hand, standing in for the host's injected one.
    struct FixedClock(Arc<AtomicU64>);
    impl Clock for FixedClock {
        fn now(&self) -> Time {
            Time::from_millis(self.0.load(Ordering::SeqCst))
        }
    }

    #[test]
    fn since_last_is_measured_on_the_injected_clock() {
        let millis = Arc::new(AtomicU64::new(1_000_000));
        let backend = Arc::new(ManualBackend::default());
        let reg = JobRegistry::new(
            backend.clone(),
            Arc::new(FixedClock(Arc::clone(&millis))) as Arc<dyn Clock>,
        );
        reg.set_resolver(Arc::new(StubResolver {
            issued: Arc::new(AtomicU64::new(0)),
        }));
        reg.schedule(
            "urn:demo:greeter".to_string(),
            Verb::Source,
            Schedule::Every(Duration::from_secs(1)),
            true,
        )
        .expect("scheduled");

        // Never fired: `None` means never, and nothing else ever means it.
        let health = reg.health();
        assert_eq!(health.len(), 1);
        assert_eq!(health[0].runs, 0);
        assert_eq!(health[0].since_last, None);

        backend.fire_all(1);
        millis.store(1_005_000, Ordering::SeqCst); // five seconds later
        let health = reg.health();
        assert_eq!(health[0].runs, 1);
        assert_eq!(health[0].since_last, Some(Duration::from_secs(5)));

        // A backwards clock adjustment (NTP step, a laptop waking in another timezone)
        // must clamp to zero — not underflow into ~584 million years, and not report
        // `None`, which would claim a job that has run has never run.
        millis.store(1, Ordering::SeqCst);
        let health = reg.health();
        assert_eq!(health[0].runs, 1);
        assert_eq!(health[0].since_last, Some(Duration::ZERO));
    }

    /// A sleep clock the test drives by hand; `u64::MAX` stands for "cannot measure".
    struct ManualSleep(Arc<AtomicU64>);
    impl SleepClock for ManualSleep {
        fn asleep(&self) -> Option<Duration> {
            match self.0.load(Ordering::SeqCst) {
                u64::MAX => None,
                secs => Some(Duration::from_secs(secs)),
            }
        }
    }

    /// A resolver whose every issue fails while `failing` is set.
    struct FlakyResolver {
        failing: Arc<AtomicBool>,
    }
    impl Resolver for FlakyResolver {
        fn issue(
            &self,
            _request: Request,
        ) -> std::result::Result<(Representation, CacheStatus), Error> {
            if self.failing.load(Ordering::SeqCst) {
                Err(Error::Endpoint("drain refused".to_string()))
            } else {
                Ok((text("drained".to_string()), CacheStatus::Uncacheable))
            }
        }
        fn is_cached(&self, _request: &Request, _capability: &Capability) -> bool {
            false
        }
        fn entries(&self) -> Option<Vec<SpaceEntry>> {
            None
        }
    }

    /// The asleep part of a job's lateness is measured from two sleep-clock readings — one
    /// taken when the job completed, one when health is read — and never exceeds the window.
    #[test]
    fn asleep_since_last_differences_the_sleep_clock_across_the_window() {
        let millis = Arc::new(AtomicU64::new(1_000_000));
        let asleep = Arc::new(AtomicU64::new(40));
        let backend = Arc::new(ManualBackend::default());
        let reg = JobRegistry::new(
            backend.clone(),
            Arc::new(FixedClock(Arc::clone(&millis))) as Arc<dyn Clock>,
        )
        .with_sleep_clock(Arc::new(ManualSleep(Arc::clone(&asleep))));
        reg.set_resolver(Arc::new(StubResolver {
            issued: Arc::new(AtomicU64::new(0)),
        }));
        reg.schedule(
            "urn:booking:drain".to_string(),
            Verb::Source,
            Schedule::Every(Duration::from_secs(30)),
            true,
        )
        .expect("scheduled");
        assert!(reg.measures_sleep());
        assert_eq!(
            reg.health()[0].asleep_since_last,
            None,
            "never ran: no window"
        );

        backend.fire_all(1);
        // A 300s nap, then 20s awake: 320s of wall clock, 300 of it asleep.
        millis.store(1_320_000, Ordering::SeqCst);
        asleep.store(340, Ordering::SeqCst);
        let health = reg.health();
        assert_eq!(health[0].since_last, Some(Duration::from_secs(320)));
        assert_eq!(health[0].asleep_since_last, Some(Duration::from_secs(300)));

        // A sleep clock that cannot answer now proves nothing: no discount, not a stale one.
        asleep.store(u64::MAX, Ordering::SeqCst);
        assert!(!reg.measures_sleep());
        assert_eq!(reg.health()[0].asleep_since_last, None);

        // Readings that disagree with the wall clock are clamped to the window.
        asleep.store(10_000, Ordering::SeqCst);
        assert_eq!(
            reg.health()[0].asleep_since_last,
            Some(Duration::from_secs(320))
        );
    }

    /// Without a sleep clock nothing changes: no evidence, and no claim of any.
    #[test]
    fn a_registry_without_a_sleep_clock_reports_no_evidence() {
        let reg = JobRegistry::new(Arc::new(ManualBackend::default()), Arc::new(SystemClock));
        assert!(!reg.measures_sleep());
    }

    /// LATE IS NOT FAILING. A job that completes on time and fails every time used to read
    /// as healthy; the run of failures and the last SUCCESS are now facts of their own.
    #[test]
    fn failures_in_a_row_and_last_success_are_tracked_apart_from_last_run() {
        let millis = Arc::new(AtomicU64::new(1_000_000));
        let failing = Arc::new(AtomicBool::new(false));
        let backend = Arc::new(ManualBackend::default());
        let reg = JobRegistry::new(
            backend.clone(),
            Arc::new(FixedClock(Arc::clone(&millis))) as Arc<dyn Clock>,
        );
        reg.set_resolver(Arc::new(FlakyResolver {
            failing: Arc::clone(&failing),
        }));
        reg.schedule(
            "urn:booking:drain".to_string(),
            Verb::Source,
            Schedule::Every(Duration::from_secs(30)),
            true,
        )
        .expect("scheduled");
        let health = reg.health();
        assert_eq!(health[0].since_last_success, None);
        assert_eq!(health[0].failures_in_a_row, 0);

        backend.fire_all(1); // succeeds at t=1000s
        failing.store(true, Ordering::SeqCst);
        millis.store(1_030_000, Ordering::SeqCst);
        backend.fire_all(3); // three failures at t=1030s
        millis.store(1_035_000, Ordering::SeqCst);
        let health = reg.health();
        assert_eq!(health[0].runs, 4);
        assert_eq!(health[0].failures_in_a_row, 3);
        assert_eq!(health[0].since_last, Some(Duration::from_secs(5)));
        assert_eq!(health[0].since_last_success, Some(Duration::from_secs(35)));
        assert!(health[0].last_output.starts_with("error"));

        failing.store(false, Ordering::SeqCst);
        backend.fire_all(1);
        let health = reg.health();
        assert_eq!(health[0].failures_in_a_row, 0, "a success resets the run");
        assert_eq!(health[0].since_last_success, Some(Duration::ZERO));
    }

    /// A backend whose cancel closure re-enters the registry — the shape of real
    /// injected host code (`clearInterval` calling back into the page).
    struct ReentrantBackend {
        reg: Arc<std::sync::OnceLock<JobRegistry>>,
        seen: Arc<Mutex<Vec<String>>>,
    }
    impl TimerBackend for ReentrantBackend {
        fn start(
            &self,
            _interval: Duration,
            _recurring: bool,
            _on_tick: Arc<dyn Fn() + Send + Sync>,
        ) -> TimerHandle {
            let reg = Arc::clone(&self.reg);
            let seen = Arc::clone(&self.seen);
            TimerHandle::new(move || {
                if let Some(reg) = reg.get() {
                    seen.lock().expect("seen lock").push(reg.render());
                }
            })
        }
    }

    #[test]
    fn cancel_runs_host_code_with_the_registry_lock_released() {
        // `TimerHandle::cancel` runs INJECTED host code. Running it inside the critical
        // section is a latent brick: a panic there poisons the mutex natively and makes
        // wasm's `no_threads` mutex fail every later acquisition, so every `urn:time:*`
        // read afterwards dies too — which is exactly how one bad tick took out the
        // browser demo's whole Control panel. Re-entry is the observable half of the
        // same property, so test that.
        //
        // Run it on a worker with a deadline: a regression DEADLOCKS, and a test that
        // hangs until CI's six-hour timeout is not a signal.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let cell = Arc::new(std::sync::OnceLock::new());
            let seen = Arc::new(Mutex::new(Vec::new()));
            let backend = Arc::new(ReentrantBackend {
                reg: Arc::clone(&cell),
                seen: Arc::clone(&seen),
            });
            let reg = JobRegistry::new(backend, Arc::new(SystemClock));
            let _ = cell.set(reg.clone());
            reg.set_resolver(Arc::new(StubResolver {
                issued: Arc::new(AtomicU64::new(0)),
            }));
            reg.schedule(
                "urn:demo:greeter".to_string(),
                Verb::Source,
                Schedule::Every(Duration::from_secs(1)),
                true,
            )
            .expect("scheduled");
            assert!(reg.cancel(1));
            // cancel_all and cancel_target take the same path.
            reg.schedule(
                "urn:demo:greeter".to_string(),
                Verb::Source,
                Schedule::Every(Duration::from_secs(1)),
                true,
            )
            .expect("scheduled");
            assert_eq!(reg.cancel_all(), 1);
            reg.schedule(
                "urn:demo:greeter".to_string(),
                Verb::Source,
                Schedule::Every(Duration::from_secs(1)),
                true,
            )
            .expect("scheduled");
            assert_eq!(reg.cancel_target("urn:demo:greeter"), 1);
            let seen = seen.lock().expect("seen lock").clone();
            let _ = tx.send(seen);
        });

        let seen = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("cancel re-entered the registry without deadlocking");
        assert_eq!(
            seen.len(),
            3,
            "all three cancel paths ran host code: {seen:?}"
        );
        for rendered in &seen {
            // The record is gone before the host code runs, and the lock is free.
            assert!(
                rendered.contains("(none scheduled)"),
                "cancel removed the job before calling host code: {rendered}"
            );
        }
    }
}
