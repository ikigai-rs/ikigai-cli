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
//!
//! ## Authority
//!
//! **A job fires under the authority that scheduled it — never more.** Each job records
//! the [`Capability`] it was scheduled with (the invocation's, through `urn:time:schedule`;
//! an explicit argument through [`JobRegistry::schedule`]), and every tick resolves under
//! `ceiling.clamp(&recorded)` — the strongest capability BOTH the registry's ceiling and
//! the scheduler grant. The ceiling defaults to root, which clamps to exactly what the
//! scheduler held; [`JobRegistry::with_capability`] narrows it for every job at once.
//! Deferring a request to later is therefore never a way to borrow authority: a caller
//! that cannot Sink an IRI cannot schedule a Sink of it that succeeds either.
//!
//! The control plane is gated three ways, each declared on its action so the manifold
//! offers exactly what the kernel admits:
//! - [`CAP_SCHEDULE`] for `urn:time:schedule` — a job costs the host a timer (a thread,
//!   natively), so registering one is an authority of its own even though the job itself
//!   borrows nothing;
//! - [`CAP_CANCEL`] for `urn:time:cancel` — and beyond the token, a caller cancels only jobs
//!   whose recorded capability its own COVERS (holds every scope of): stopping work you
//!   could not have scheduled is not yours to do;
//! - [`CAP_READ`] for `urn:time:jobs` — every job's existence (id, verb, target, cadence,
//!   runs) is listed to the holder, but a job's last output only to a caller that covers
//!   the job's authority, because that output is what the job's authority READ.

use std::collections::BTreeMap;
// Only the native `ThreadTimer` flips an atomic; on wasm these would be unused imports, which
// `clippy --target wasm32-unknown-unknown -D warnings` refuses.
#[cfg(not(target_family = "wasm"))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ikigai_core::{
    ArgSpec, Capability, Clock, Description, EndpointSpace, Error, Exact, FnEndpoint, Invocation,
    Iri, ReprType, Representation, Request, Time, Verb,
};
use ikigai_resolve::Resolver;

/// Register a job on `urn:time:schedule`. The job itself fires under the scheduler's own
/// capability; this token gates only the act of adding a timer to the host.
pub const CAP_SCHEDULE: &str = "urn:cap:time:schedule";
/// Stop jobs on `urn:time:cancel` — only those whose authority the caller covers.
pub const CAP_CANCEL: &str = "urn:cap:time:cancel";
/// Read the job list on `urn:time:jobs` — a job's last output only where the caller covers
/// the job's authority.
pub const CAP_READ: &str = "urn:cap:time:read";

/// Whether `holder` COVERS `recorded` — grants every scope `recorded` grants, so anything a
/// job under `recorded` could do, `holder` could have done itself. Root covers everything;
/// only root covers root.
///
/// Stated through [`Capability::clamp`] rather than by walking scope sets: clamping `recorded`
/// to `holder` leaves it unchanged exactly when `holder` already grants all of it. Matching is
/// exact, as `Capability::allows` is — a held wildcard is not unfolded here, which errs toward
/// "not covered".
fn covers(holder: &Capability, recorded: &Capability) -> bool {
    holder.clamp(recorded) == *recorded
}

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
    /// The authority this job was scheduled with — what every tick fires under, clamped to
    /// the registry's ceiling. Recorded at schedule time and never widened.
    capability: Capability,
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
    /// The CEILING every job is clamped to — never the authority a job fires under by
    /// itself. Root by default (clamping to root yields the job's own capability), narrowed
    /// only by [`JobRegistry::with_capability`].
    ceiling: Capability,
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
/// installed [`Resolver`] under the capability it was scheduled with, clamped to the
/// registry's ceiling (see the crate docs, *Authority*).
///
/// Holding a `JobRegistry` is holding the HOST's handle: [`cancel`](Self::cancel),
/// [`cancel_all`](Self::cancel_all), [`cancel_target`](Self::cancel_target) and
/// [`health`](Self::health) act on every job, because only host code can reach them. Callers
/// arriving through the kernel reach the registry only through `urn:time:*`, which gates each
/// of those by the caller's own capability.
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
    /// A registry driven by `backend` and stamped by `clock`. Its ceiling starts at root, so
    /// each job fires under exactly the capability it was scheduled with until
    /// [`with_capability`](Self::with_capability) narrows every job at once. The
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
                ceiling: Capability::root(),
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

    /// Narrow the CEILING every job fires under: each tick resolves under
    /// `ceiling.clamp(&job's capability)`, so a host can bound every job — root-scheduled or
    /// not — to `capability` without knowing who scheduled what.
    ///
    /// Only ever narrows. The new ceiling is the old one clamped to `capability`, so calling
    /// this twice keeps the intersection and passing root changes nothing: there is no call
    /// that widens a ceiling, the same structural non-escalation `Capability` itself keeps.
    /// It is not, and never was, the authority a job fires under by itself — that is the
    /// capability passed to [`schedule`](Self::schedule).
    pub fn with_capability(self, capability: Capability) -> Self {
        {
            let mut inner = self.inner.lock().expect("time registry lock");
            inner.ceiling = inner.ceiling.clamp(&capability);
        }
        self
    }

    /// Install the kernel handle jobs fire requests on. Called once by the host after
    /// the kernel is built (the endpoints are bound into that same kernel).
    pub fn set_resolver(&self, resolver: Arc<dyn Resolver>) {
        self.inner.lock().expect("time registry lock").resolver = Some(resolver);
    }

    /// Register a job that fires under `capability` (clamped to the registry's ceiling) and
    /// start its timer. Returns the new job id, or an error if no resolver is installed yet.
    ///
    /// `capability` is a **required** argument rather than a defaulted one on purpose, for the
    /// reason [`new`](Self::new) requires a `Clock`: every default moves the hazard rather
    /// than removing it. The obvious default — the registry's own authority — is what made
    /// every job fire at root whoever scheduled it (ledger #79). A required argument makes
    /// "fires at some ambient authority" a compile error in the host that forgot, and makes
    /// every host job state the authority it fires under at the call site.
    ///
    /// Pass the authority the job NEEDS, not the host's: a job that only reads a clock needs
    /// no scopes at all (`Capability::scoped(Vec::<String>::new())`).
    pub fn schedule(
        &self,
        target: String,
        verb: Verb,
        schedule: Schedule,
        recurring: bool,
        capability: Capability,
    ) -> std::result::Result<u64, String> {
        self.schedule_inner(target, verb, schedule, recurring, false, capability)
    }

    /// Like [`schedule`](Self::schedule), but the job is **persistent** —
    /// [`cancel_all`](Self::cancel_all) skips it. For host-registered background timers
    /// (the nav clock) that a demo's "cancel all" button shouldn't stop. Cancel it
    /// explicitly with [`cancel`](Self::cancel) or [`cancel_target`](Self::cancel_target).
    /// `capability` is required for the reason [`schedule`](Self::schedule) gives.
    pub fn schedule_persistent(
        &self,
        target: String,
        verb: Verb,
        schedule: Schedule,
        recurring: bool,
        capability: Capability,
    ) -> std::result::Result<u64, String> {
        self.schedule_inner(target, verb, schedule, recurring, true, capability)
    }

    fn schedule_inner(
        &self,
        target: String,
        verb: Verb,
        schedule: Schedule,
        recurring: bool,
        persistent: bool,
        capability: Capability,
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
        // outcome. `fire` reads the job's target, verb and authority from its RECORD under a
        // short lock and resolves with the lock released, so a slow resolve never holds it.
        let reg = self.clone();
        let on_tick: Arc<dyn Fn() + Send + Sync> = Arc::new(move || reg.fire(id));

        // Start the timer with the lock released. A tick that somehow fires before we
        // insert the record below finds no job and is dropped (benign — it has no recorded
        // authority to fire under); real backends wait a full interval first, so this
        // window never matters in practice.
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
                capability,
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

    /// The kernel-facing cancel: stop job `id` only if `caller` covers the authority it was
    /// scheduled with. A job the caller could not have scheduled is left running and
    /// reported as withheld, not as absent — its existence is already public to any
    /// `urn:time:jobs` reader, so pretending otherwise would hide nothing and mislead.
    fn cancel_as(&self, id: u64, caller: &Capability) -> CancelOutcome {
        let removed = {
            let mut inner = self.inner.lock().expect("time registry lock");
            match inner.jobs.get(&id) {
                None => return CancelOutcome::NotFound,
                Some(job) if !covers(caller, &job.capability) => return CancelOutcome::Withheld,
                Some(_) => inner.jobs.remove(&id),
            }
        };
        // Host code (the backend's cancel) runs with the lock released — see `cancel`.
        if let Some(job) = removed {
            job.handle.cancel();
        }
        CancelOutcome::Cancelled
    }

    /// The kernel-facing bulk cancel: every job matching `predicate` AND covered by `caller`
    /// is stopped. Returns `(cancelled, withheld)` — how many matched but were left running
    /// because `caller` does not cover their authority, so a reply can say so rather than
    /// let "cancelled 0" read as "there was nothing".
    fn cancel_matching_as(
        &self,
        caller: &Capability,
        predicate: impl Fn(&JobRecord) -> bool,
    ) -> (usize, usize) {
        // Count and remove in ONE critical section, so the two numbers describe the same
        // registry; the timers are cancelled after it, with the lock released (see `cancel`).
        let (handles, withheld) = {
            let mut inner = self.inner.lock().expect("time registry lock");
            let mut withheld = 0;
            let mut ids = Vec::new();
            for (id, job) in inner.jobs.iter().filter(|(_, job)| predicate(job)) {
                if covers(caller, &job.capability) {
                    ids.push(*id);
                } else {
                    withheld += 1;
                }
            }
            let handles: Vec<TimerHandle> = ids
                .iter()
                .filter_map(|id| inner.jobs.remove(id))
                .map(|job| job.handle)
                .collect();
            (handles, withheld)
        };
        for handle in &handles {
            handle.cancel();
        }
        (handles.len(), withheld)
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
    ///
    /// ★ The request resolves under `ceiling.clamp(&job.capability)` — the job's RECORDED
    /// authority, bounded by the registry's ceiling — and never under the ceiling alone.
    /// That one line is the whole of ledger #79: this used to pass the registry's own
    /// capability, which was root, so every job fired at root whoever scheduled it. A tick
    /// for a job no longer in the map (cancelled, or not yet inserted) has no recorded
    /// authority and does not fire at all.
    fn fire(&self, id: u64) {
        // Copy what the tick needs out under a short lock; resolve without holding it.
        let (resolver, target, verb, capability) = {
            let inner = self.inner.lock().expect("time registry lock");
            let (Some(resolver), Some(job)) = (&inner.resolver, inner.jobs.get(&id)) else {
                return;
            };
            (
                Arc::clone(resolver),
                job.target.clone(),
                job.verb,
                inner.ceiling.clamp(&job.capability),
            )
        };
        let (outcome, succeeded) = match Iri::parse(&target) {
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

    /// Render the job list as the `urn:time:jobs` readout, as `caller` may see it: every job's
    /// existence, but a job's last output only where `caller` covers the job's authority.
    /// A withheld output is SAID to be withheld — an absent `last:` line already means "has
    /// not run yet", and the two must not read the same.
    fn render(&self, caller: &Capability) -> String {
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
            // Never run: no line, as before — nothing to show or to withhold.
            if !job.last_output.is_empty() {
                let last = if covers(caller, &job.capability) {
                    job.last_output.as_str()
                } else {
                    "(withheld: scheduled under authority you do not hold)"
                };
                s.push_str(&format!("       last: {last}\n"));
            }
        }
        s
    }
}

/// What a kernel-facing cancel of one job id did.
enum CancelOutcome {
    Cancelled,
    NotFound,
    /// The job exists and the caller does not cover its authority; it was left running.
    Withheld,
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
                // The job fires under THIS invocation's capability — the caller's own, as the
                // kernel handed it here — clamped to the registry's ceiling at every tick.
                let id = schedule_reg
                    .schedule(
                        target.to_string(),
                        verb,
                        schedule,
                        recurring,
                        inv.capability.clone(),
                    )
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
                        "Register a job that fires a resource-request on a timer, under the \
                         caller's own capability. every=<dur> recurs; after=<dur> is one-shot; \
                         method=<verb> picks the verb.",
                    )
                    .verb(Verb::Source)
                    .requires(CAP_SCHEDULE)
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
                let caller = inv.capability;
                // Jobs the caller does not cover are left running and COUNTED, so a reply of
                // "cancelled 0" can never be mistaken for "there was nothing to cancel".
                let withheld = |n: usize| {
                    if n == 0 {
                        String::new()
                    } else {
                        format!(
                            " ({n} left running: scheduled under authority you do not hold)"
                        )
                    }
                };
                // `target=<iri>` cancels every job firing that resource — precise, and
                // leaves other timers (e.g. the nav clock on urn:time:now) alone.
                if let Ok(target) = inv.inline_str("target") {
                    let target = target.trim();
                    let (n, kept) = cancel_reg.cancel_matching_as(caller, |job| job.target == target);
                    return Ok(text(format!(
                        "cancelled {n} job{} for {target}{}\n",
                        plural(n),
                        withheld(kept)
                    )));
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
                    let (n, kept) = cancel_reg.cancel_matching_as(caller, |job| !job.persistent);
                    return Ok(text(format!(
                        "cancelled {n} job{}{}\n",
                        plural(n),
                        withheld(kept)
                    )));
                }
                let id: u64 = id_str.parse().map_err(|_| {
                    Error::Endpoint(format!(
                        "invalid job id '{id_str}' (expected a number, 'all', or target=<iri>)"
                    ))
                })?;
                match cancel_reg.cancel_as(id, caller) {
                    CancelOutcome::Cancelled => Ok(text(format!("cancelled job #{id}\n"))),
                    CancelOutcome::NotFound => Ok(text(format!("no job #{id}\n"))),
                    // Typed, so a caller can tell "not yours" from "not there" without
                    // parsing prose — and so a trace records it as the refusal it is.
                    CancelOutcome::Withheld => Err(Error::Denied(format!(
                        "job #{id} was scheduled under authority you do not hold; \
                         cancelling it needs a capability that covers it"
                    ))),
                }
            })
            .with_description(
                Description::new("time-cancel")
                    .title("Cancel a timed job")
                    .summary(
                        "Stop and remove a timed job: id=<n> (one), id=all (every \
                         non-persistent job), or target=<iri> (every job firing that resource) \
                         — only jobs whose authority the caller's capability covers.",
                    )
                    .verb(Verb::Source)
                    .requires(CAP_CANCEL)
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
            FnEndpoint::new("time-jobs", move |inv: &Invocation<'_>| {
                Ok(text(jobs_reg.render(inv.capability)))
            })
            .with_description(
                Description::new("time-jobs")
                    .title("Scheduled timed jobs")
                    .summary(
                        "The live list of time-transport jobs: target, interval, runs, and last \
                         output where the caller's capability covers the job's.",
                    )
                    .verb(Verb::Source)
                    .requires(CAP_READ)
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
                Capability::root(),
            )
            .expect("scheduled");
        assert_eq!(id, 1);

        // Fire out of band — after schedule() released the registry lock, the way the
        // real thread/setInterval backends tick. Firing inside start() would deadlock.
        backend.fire_all(3);
        assert_eq!(issued.load(Ordering::SeqCst), 3);

        let rendered = reg.render(&Capability::root());
        assert!(rendered.contains("#1"));
        assert!(rendered.contains("urn:demo:greeter"));
        assert!(rendered.contains("runs 3"));
        assert!(rendered.contains("last: Hello, World"));

        assert!(reg.cancel(1));
        assert!(!reg.cancel(1));
        assert!(reg.render(&Capability::root()).contains("(none scheduled)"));
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
                Capability::root(),
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
                Capability::root(),
            )
            .expect("scheduled")
        };
        sched("urn:demo:a");
        sched("urn:demo:b");
        sched("urn:demo:c");
        assert_eq!(reg.cancel_all(), 3);
        assert!(reg.render(&Capability::root()).contains("(none scheduled)"));
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
            .schedule_persistent(
                "urn:time:now".to_string(),
                Verb::Source,
                every(),
                true,
                Capability::root(),
            )
            .expect("scheduled");
        reg.schedule(
            "urn:demo:greeter".to_string(),
            Verb::Source,
            every(),
            true,
            Capability::root(),
        )
        .unwrap();
        reg.schedule(
            "urn:demo:greeter".to_string(),
            Verb::Source,
            every(),
            true,
            Capability::root(),
        )
        .unwrap();

        // cancel_all removes the two greeters, leaves the persistent clock.
        assert_eq!(reg.cancel_all(), 2);
        let rendered = reg.render(&Capability::root());
        assert!(
            rendered.contains("urn:time:now"),
            "clock survives: {rendered}"
        );
        assert!(rendered.contains("(persistent)"), "marked: {rendered}");
        assert!(!rendered.contains("urn:demo:greeter"));

        // cancel_target removes the persistent clock explicitly (an explicit target
        // is deliberate, so it overrides persistence).
        assert_eq!(reg.cancel_target("urn:time:now"), 1);
        assert!(reg.render(&Capability::root()).contains("(none scheduled)"));
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
        reg.schedule(
            "urn:demo:greeter".to_string(),
            Verb::Source,
            every(),
            true,
            Capability::root(),
        )
        .unwrap();
        reg.schedule(
            "urn:demo:greeter".to_string(),
            Verb::Source,
            every(),
            true,
            Capability::root(),
        )
        .unwrap();
        reg.schedule(
            "urn:time:now".to_string(),
            Verb::Source,
            every(),
            true,
            Capability::root(),
        )
        .unwrap();
        assert_eq!(reg.cancel_target("urn:demo:greeter"), 2);
        let rendered = reg.render(&Capability::root());
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
            Capability::root(),
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
            Capability::root(),
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
            Capability::root(),
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

    // ── Authority: a job fires under the capability that scheduled it (ledger #79) ──
    //
    // These drive the REAL kernel, not a stub resolver: the defect lived in which capability
    // a tick hands the kernel, and only a kernel enforces a declared `requires`. The engine is
    // not involved (every argument is named), so a meta-less `Kernel::new` hides nothing here.

    /// A Sink/Delete endpoint at `urn:x` gated on `urn:cap:x:write`, counting every entry —
    /// the counter proves a denial happened BEFORE dispatch, not merely that an error came back.
    fn gated_target(entered: Arc<AtomicU64>) -> FnEndpoint {
        FnEndpoint::new("x", move |_inv: &Invocation<'_>| {
            entered.fetch_add(1, Ordering::SeqCst);
            Ok(text("written".to_string()))
        })
        .with_description(
            Description::new("x")
                .verb(Verb::Sink)
                .verb(Verb::Delete)
                .requires("urn:cap:x:write"),
        )
    }

    /// A registry and a kernel that binds the `urn:time:*` plane beside `urn:x`, with the
    /// registry's resolver set to that same kernel — the shape every host builds.
    fn kernel_with_time(
        registry: &JobRegistry,
        entered: Arc<AtomicU64>,
    ) -> Arc<ikigai_core::Kernel> {
        let space = space(registry.clone()).bind(Exact::new("urn:x"), gated_target(entered));
        let kernel = Arc::new(ikigai_core::Kernel::new(Arc::new(space)));
        registry.set_resolver(Arc::clone(&kernel) as Arc<dyn Resolver>);
        kernel
    }

    /// Issue `source <iri> k=v…` through the kernel under `capability`.
    fn call(
        kernel: &ikigai_core::Kernel,
        iri: &str,
        args: &[(&str, &str)],
        capability: &Capability,
    ) -> std::result::Result<String, Error> {
        let mut request = Request::new(Verb::Source, Iri::parse(iri).expect("valid IRI"));
        for (k, v) in args {
            request = request.with_arg(*k, ikigai_core::ArgRef::Inline(v.as_bytes().to_vec()));
        }
        Resolver::issue_as(kernel, request, capability)
            .map(|(rep, _)| String::from_utf8_lossy(&rep.bytes).into_owned())
    }

    /// A caller that may schedule and read jobs but holds NO authority over `urn:x`.
    fn attenuated() -> Capability {
        Capability::scoped(["urn:cap:time:schedule", "urn:cap:time:read"])
    }

    /// ★ THE ESCALATION, reproduced: a caller that cannot Sink `urn:x` schedules a Sink of
    /// `urn:x`, and the tick must be DENIED — the endpoint never entered — rather than fired
    /// at the registry's root.
    #[test]
    fn a_scheduled_sink_fires_under_the_scheduler_capability_not_root() {
        let entered = Arc::new(AtomicU64::new(0));
        let backend = Arc::new(ManualBackend::default());
        let reg = JobRegistry::new(backend.clone(), Arc::new(SystemClock));
        let kernel = kernel_with_time(&reg, Arc::clone(&entered));

        // The caller cannot sink urn:x directly — the premise.
        let direct = Resolver::issue_as(
            &*kernel,
            Request::new(Verb::Sink, Iri::parse("urn:x").unwrap()),
            &attenuated(),
        );
        assert!(matches!(direct, Err(Error::Denied(_))), "{direct:?}");

        call(
            &kernel,
            "urn:time:schedule",
            &[("target", "urn:x"), ("every", "1s"), ("method", "sink")],
            &attenuated(),
        )
        .expect("scheduling is within the caller's authority");
        backend.fire_all(1);

        assert_eq!(
            entered.load(Ordering::SeqCst),
            0,
            "the tick must not reach an endpoint its scheduler could not"
        );
        let health = reg.health();
        assert_eq!(health[0].runs, 1);
        assert_eq!(health[0].failures_in_a_row, 1);
        assert!(
            health[0].last_output.contains("denied"),
            "the job records the Denied: {}",
            health[0].last_output
        );
    }

    /// The same hole through the other mutating verb.
    #[test]
    fn a_scheduled_delete_fires_under_the_scheduler_capability_not_root() {
        let entered = Arc::new(AtomicU64::new(0));
        let backend = Arc::new(ManualBackend::default());
        let reg = JobRegistry::new(backend.clone(), Arc::new(SystemClock));
        let kernel = kernel_with_time(&reg, Arc::clone(&entered));

        call(
            &kernel,
            "urn:time:schedule",
            &[("target", "urn:x"), ("after", "1s"), ("method", "delete")],
            &attenuated(),
        )
        .expect("scheduled");
        backend.fire_all(1);

        assert_eq!(entered.load(Ordering::SeqCst), 0);
        assert!(reg.health()[0].last_output.contains("denied"));
    }

    /// The REPL's normal case is unchanged: a job scheduled at root fires at root.
    #[test]
    fn a_job_scheduled_at_root_still_fires() {
        let entered = Arc::new(AtomicU64::new(0));
        let backend = Arc::new(ManualBackend::default());
        let reg = JobRegistry::new(backend.clone(), Arc::new(SystemClock));
        let kernel = kernel_with_time(&reg, Arc::clone(&entered));

        call(
            &kernel,
            "urn:time:schedule",
            &[("target", "urn:x"), ("every", "1s"), ("method", "sink")],
            &Capability::root(),
        )
        .expect("scheduled");
        backend.fire_all(2);

        assert_eq!(entered.load(Ordering::SeqCst), 2);
        let health = reg.health();
        assert_eq!(health[0].failures_in_a_row, 0);
        assert_eq!(health[0].last_output, "written");
    }

    /// Attenuation is not a ban: a caller that DOES hold `urn:x`'s authority schedules a
    /// Sink that succeeds — the job carries exactly what its scheduler held.
    #[test]
    fn a_job_scheduled_by_a_holder_of_the_target_authority_fires() {
        let entered = Arc::new(AtomicU64::new(0));
        let backend = Arc::new(ManualBackend::default());
        let reg = JobRegistry::new(backend.clone(), Arc::new(SystemClock));
        let kernel = kernel_with_time(&reg, Arc::clone(&entered));
        let writer = Capability::scoped([CAP_SCHEDULE, "urn:cap:x:write"]);

        call(
            &kernel,
            "urn:time:schedule",
            &[("target", "urn:x"), ("every", "1s"), ("method", "sink")],
            &writer,
        )
        .expect("scheduled");
        backend.fire_all(1);
        assert_eq!(entered.load(Ordering::SeqCst), 1);
    }

    /// The registry's capability is a CEILING: a root-scheduled job fires under it.
    #[test]
    fn the_registry_ceiling_narrows_a_root_scheduled_job() {
        let entered = Arc::new(AtomicU64::new(0));
        let backend = Arc::new(ManualBackend::default());
        let reg = JobRegistry::new(backend.clone(), Arc::new(SystemClock))
            .with_capability(Capability::scoped(["urn:cap:other"]));
        let kernel = kernel_with_time(&reg, Arc::clone(&entered));

        call(
            &kernel,
            "urn:time:schedule",
            &[("target", "urn:x"), ("every", "1s"), ("method", "sink")],
            &Capability::root(),
        )
        .expect("scheduled");
        backend.fire_all(1);
        assert_eq!(
            entered.load(Ordering::SeqCst),
            0,
            "root clamped to the ceiling"
        );
        assert!(reg.health()[0].last_output.contains("denied"));

        // A ceiling that grants the target's authority lets the same job through.
        let entered = Arc::new(AtomicU64::new(0));
        let backend = Arc::new(ManualBackend::default());
        let reg = JobRegistry::new(backend.clone(), Arc::new(SystemClock))
            .with_capability(Capability::scoped(["urn:cap:x:write"]));
        let kernel = kernel_with_time(&reg, Arc::clone(&entered));
        call(
            &kernel,
            "urn:time:schedule",
            &[("target", "urn:x"), ("every", "1s"), ("method", "sink")],
            &Capability::root(),
        )
        .expect("scheduled");
        backend.fire_all(1);
        assert_eq!(entered.load(Ordering::SeqCst), 1);
    }

    /// `with_capability` only narrows: a later root (or broader) ceiling cannot undo an
    /// earlier narrowing, so no host code path can widen what every job fires under.
    #[test]
    fn the_ceiling_never_widens() {
        let entered = Arc::new(AtomicU64::new(0));
        let backend = Arc::new(ManualBackend::default());
        let reg = JobRegistry::new(backend.clone(), Arc::new(SystemClock))
            .with_capability(Capability::scoped(["urn:cap:other"]))
            .with_capability(Capability::root())
            .with_capability(Capability::scoped(["urn:cap:other", "urn:cap:x:write"]));
        let kernel = kernel_with_time(&reg, Arc::clone(&entered));
        call(
            &kernel,
            "urn:time:schedule",
            &[("target", "urn:x"), ("every", "1s"), ("method", "sink")],
            &Capability::root(),
        )
        .expect("scheduled");
        backend.fire_all(1);
        assert_eq!(entered.load(Ordering::SeqCst), 0);
    }

    /// Declared = enforced, for all three: without the token the kernel refuses before
    /// dispatch — nothing is registered, cancelled, or read.
    #[test]
    fn each_control_resource_requires_its_declared_token() {
        let entered = Arc::new(AtomicU64::new(0));
        let reg = JobRegistry::new(Arc::new(ManualBackend::default()), Arc::new(SystemClock));
        let kernel = kernel_with_time(&reg, entered);
        let nothing = Capability::scoped(Vec::<String>::new());

        let scheduled = call(
            &kernel,
            "urn:time:schedule",
            &[("target", "urn:x"), ("every", "1s")],
            &nothing,
        );
        assert!(matches!(scheduled, Err(Error::Denied(_))), "{scheduled:?}");
        assert!(reg.health().is_empty(), "denied before dispatch: no job");

        reg.schedule(
            "urn:x".to_string(),
            Verb::Source,
            Schedule::Every(Duration::from_secs(1)),
            true,
            nothing.clone(),
        )
        .expect("host schedules");
        let cancelled = call(&kernel, "urn:time:cancel", &[("id", "all")], &nothing);
        assert!(matches!(cancelled, Err(Error::Denied(_))), "{cancelled:?}");
        assert_eq!(reg.health().len(), 1, "nothing cancelled");

        let listed = call(&kernel, "urn:time:jobs", &[], &nothing);
        assert!(matches!(listed, Err(Error::Denied(_))), "{listed:?}");

        // And each is declared where the manifold reads it — on the action, per verb.
        let root = space(reg.clone());
        for (iri, token) in [
            ("urn:time:schedule", CAP_SCHEDULE),
            ("urn:time:cancel", CAP_CANCEL),
            ("urn:time:jobs", CAP_READ),
        ] {
            let request = Request::new(Verb::Source, Iri::parse(iri).unwrap());
            let ikigai_core::Resolution::Hit(found) =
                ikigai_core::Space::resolve(&root, &request, &ikigai_core::Scope::empty())
            else {
                panic!("{iri} is bound");
            };
            let specs = found.endpoint.describe().action_specs();
            let source = specs
                .iter()
                .find(|spec| spec.verb == Verb::Source)
                .expect("a Source action");
            assert_eq!(source.requires, vec![token.to_string()], "{iri}");
        }
    }

    /// Cancel reaches only what the caller covers. A job scheduled at root (the host's) is
    /// withheld from an attenuated caller by id — typed Denied, left running — and by
    /// `id=all`, which says how many it left; the caller's own job is its to cancel, and root
    /// can cancel anything.
    #[test]
    fn a_caller_cancels_only_jobs_its_capability_covers() {
        let entered = Arc::new(AtomicU64::new(0));
        let reg = JobRegistry::new(Arc::new(ManualBackend::default()), Arc::new(SystemClock));
        let kernel = kernel_with_time(&reg, entered);
        let agent = Capability::scoped([CAP_SCHEDULE, CAP_CANCEL, CAP_READ]);
        let every = || Schedule::Every(Duration::from_secs(1));

        let host_job = reg
            .schedule(
                "urn:x".to_string(),
                Verb::Source,
                every(),
                true,
                Capability::root(),
            )
            .unwrap();
        call(
            &kernel,
            "urn:time:schedule",
            &[("target", "urn:x"), ("every", "1s")],
            &agent,
        )
        .expect("the agent schedules its own");

        let by_id = call(
            &kernel,
            "urn:time:cancel",
            &[("id", &host_job.to_string())],
            &agent,
        );
        assert!(matches!(by_id, Err(Error::Denied(_))), "{by_id:?}");
        assert_eq!(reg.health().len(), 2, "the host job is still running");

        let all = call(&kernel, "urn:time:cancel", &[("id", "all")], &agent).unwrap();
        assert!(all.starts_with("cancelled 1 job ("), "{all}");
        assert!(all.contains("1 left running"), "{all}");
        let left = reg.health();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, host_job);

        let by_target = call(&kernel, "urn:time:cancel", &[("target", "urn:x")], &agent).unwrap();
        assert!(
            by_target.starts_with("cancelled 0 jobs for urn:x (1 left"),
            "{by_target}"
        );

        // Root covers everything.
        let root = call(
            &kernel,
            "urn:time:cancel",
            &[("id", &host_job.to_string())],
            &Capability::root(),
        )
        .unwrap();
        assert_eq!(root, format!("cancelled job #{host_job}\n"));
        assert!(reg.health().is_empty());
    }

    /// The listing shows every job's EXISTENCE to a reader, but a job's last output only to
    /// a caller that covers its authority — that output is what the job's authority read.
    #[test]
    fn the_job_list_withholds_output_the_reader_could_not_have_read() {
        let entered = Arc::new(AtomicU64::new(0));
        let backend = Arc::new(ManualBackend::default());
        let reg = JobRegistry::new(backend.clone(), Arc::new(SystemClock));
        let kernel = kernel_with_time(&reg, Arc::clone(&entered));
        let agent = attenuated();

        reg.schedule(
            "urn:x".to_string(),
            Verb::Sink,
            Schedule::Every(Duration::from_secs(1)),
            true,
            Capability::root(),
        )
        .unwrap();
        call(
            &kernel,
            "urn:time:schedule",
            &[("target", "urn:x"), ("every", "1s"), ("method", "sink")],
            &agent,
        )
        .unwrap();
        backend.fire_all(1);

        let seen = call(&kernel, "urn:time:jobs", &[], &agent).unwrap();
        assert!(
            seen.contains("#1  sink urn:x"),
            "existence is listed: {seen}"
        );
        assert!(
            !seen.contains("last: written"),
            "the root job's output is withheld: {seen}"
        );
        assert!(seen.contains("last: (withheld"), "and says so: {seen}");
        assert!(
            seen.contains("last: error: denied"),
            "the agent's own job's output is its to read: {seen}"
        );

        let all = call(&kernel, "urn:time:jobs", &[], &Capability::root()).unwrap();
        assert!(all.contains("last: written"), "{all}");
        assert!(!all.contains("withheld"), "{all}");
    }

    /// `covers` is "grants everything the recorded capability grants".
    #[test]
    fn covers_is_scope_containment_and_only_root_covers_root() {
        let ab = Capability::scoped(["a", "b"]);
        let a = Capability::scoped(["a"]);
        let none = Capability::scoped(Vec::<String>::new());
        assert!(covers(&Capability::root(), &Capability::root()));
        assert!(covers(&Capability::root(), &ab));
        assert!(!covers(&ab, &Capability::root()));
        assert!(covers(&ab, &a));
        assert!(!covers(&a, &ab));
        assert!(covers(&a, &none));
        assert!(covers(&none, &none));
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
                    seen.lock()
                        .expect("seen lock")
                        .push(reg.render(&Capability::root()));
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
                Capability::root(),
            )
            .expect("scheduled");
            assert!(reg.cancel(1));
            // cancel_all and cancel_target take the same path.
            reg.schedule(
                "urn:demo:greeter".to_string(),
                Verb::Source,
                Schedule::Every(Duration::from_secs(1)),
                true,
                Capability::root(),
            )
            .expect("scheduled");
            assert_eq!(reg.cancel_all(), 1);
            reg.schedule(
                "urn:demo:greeter".to_string(),
                Verb::Source,
                Schedule::Every(Duration::from_secs(1)),
                true,
                Capability::root(),
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
