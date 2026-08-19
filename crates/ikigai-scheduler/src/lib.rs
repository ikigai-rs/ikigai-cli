//! `ikigai-scheduler` — the async work scheduler that drives the kernel.
//!
//! The kernel (`ikigai-core`) is runtime-free: it produces `async` futures but owns
//! no executor. This crate is the **host-side seam** that runs them — today's
//! single-threaded `block_on` or a configurable threadpool — so the host chooses how
//! work is scheduled without the kernel ever depending on a runtime.
//!
//! Two ideas from NetKernel shape it (see `docs/scheduler-design.md`):
//!
//! - **Scheduled, not attached.** Work is submitted to the executor and attaches to
//!   a worker thread only when one is free.
//! - **Park, don't block.** A task that `await`s something external yields its
//!   thread back to the pool rather than holding a CPU while it waits — which is also
//!   what makes bounded-pool *re-entrant* resolution (compose issuing sub-requests)
//!   safe: a parent that parks frees a thread for its child to run on.
//!
//! [`Scheduler`] is the seam; [`Scheduler::run`] is the top-level blocking submit
//! (the synchronous REPL call sits here), and [`Scheduler::spawn`] fans work out onto
//! the executor. [`Scheduler::stats`] feeds the `urn:kernel:scheduler` resource.

use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::executor::{block_on, ThreadPool};
use futures::future::RemoteHandle;
use futures::task::SpawnExt;

/// The async executor that drives kernel work. Cheap to clone (a pool clone shares
/// its worker threads); pass it around as the host's one scheduler.
#[derive(Clone)]
pub enum Scheduler {
    /// Run futures to completion on the calling thread (`block_on`). Cooperative and
    /// runtime-light — the safe default, and the only option on a single-threaded
    /// host (e.g. today's browser build).
    Single(Arc<Counters>),
    /// A fixed pool of `size` worker threads. Spawned tasks attach to a free worker;
    /// awaiting tasks park and release their worker.
    Pool {
        pool: ThreadPool,
        size: usize,
        counters: Arc<Counters>,
    },
}

/// A scheduler configuration — `single`, `pool`, or `pool:N` — parsed but not yet built.
///
/// Parsing is deliberately separate from construction: [`Scheduler::pool`] SPAWNS WORKER
/// THREADS, while a `--scheduler` flag has to be validated as argv is read, before the
/// process has decided anything at all. Without the split, "is this spec valid?" could
/// only be answered by building a threadpool and throwing it away — so a host would be
/// pushed toward accepting a typo and falling back silently, which is exactly the failure
/// a flag must not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerSpec {
    /// `single` — [`Scheduler::single`].
    Single,
    /// `pool:N`, and bare `pool` as `Pool(0)` — one worker per available core, resolved
    /// at build time (the core count is a property of the machine, not of the spec).
    Pool(usize),
}

impl SchedulerSpec {
    /// Build the scheduler this spec names. `Pool(0)` resolves to one worker per core.
    pub fn build(self) -> Scheduler {
        match self {
            SchedulerSpec::Single => Scheduler::single(),
            SchedulerSpec::Pool(size) => Scheduler::pool(size),
        }
    }
}

impl FromStr for SchedulerSpec {
    type Err = String;

    fn from_str(spec: &str) -> Result<Self, String> {
        match spec.trim() {
            "single" => Ok(SchedulerSpec::Single),
            "pool" => Ok(SchedulerSpec::Pool(0)),
            s => match s.strip_prefix("pool:") {
                Some(n) => n
                    .parse::<usize>()
                    .map(SchedulerSpec::Pool)
                    .map_err(|_| format!("invalid pool size in `{spec}` (expected `pool:N`)")),
                None => Err(format!(
                    "unknown scheduler `{spec}` (single | pool | pool:N)"
                )),
            },
        }
    }
}

impl std::fmt::Display for SchedulerSpec {
    /// The canonical spelling of the spec — round-trips through [`FromStr`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchedulerSpec::Single => f.write_str("single"),
            SchedulerSpec::Pool(0) => f.write_str("pool"),
            SchedulerSpec::Pool(size) => write!(f, "pool:{size}"),
        }
    }
}

impl Scheduler {
    /// A single-threaded scheduler (`block_on`).
    pub fn single() -> Self {
        Scheduler::Single(Arc::new(Counters::default()))
    }

    /// A threadpool of `size` workers; `size == 0` means "one per available core".
    pub fn pool(size: usize) -> Self {
        let size = if size == 0 { default_threads() } else { size };
        let pool = ThreadPool::builder()
            .pool_size(size)
            .name_prefix("ikigai-sched-")
            .create()
            .expect("create scheduler threadpool");
        Scheduler::Pool {
            pool,
            size,
            counters: Arc::new(Counters::default()),
        }
    }

    /// Parse a scheduler from a config string (`single`, `pool` (cores), or `pool:N`)
    /// and build it. Sugar over [`SchedulerSpec`]: parse and construction are separate
    /// steps because a *flag* must be rejected while argv is being read, long before
    /// anything decides to spawn threads.
    pub fn from_config(spec: &str) -> Result<Self, String> {
        spec.parse::<SchedulerSpec>().map(SchedulerSpec::build)
    }

    /// Run `task` to completion, blocking the calling thread (the top-level submit)
    /// while the work runs on the executor. Sub-tasks it [`spawn`](Self::spawn)s run
    /// concurrently on the pool.
    pub fn run<F>(&self, task: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        block_on(self.spawn(task))
    }

    /// Spawn `task` onto the scheduler, returning a handle that resolves to its
    /// output. On a `Pool` it runs concurrently with other spawned tasks; on `Single`
    /// it runs cooperatively when the handle is driven.
    pub fn spawn<F>(&self, task: F) -> Task<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let counters = self.counters().clone();
        counters.spawned.fetch_add(1, Ordering::SeqCst);
        let wrapped = async move {
            counters.active.fetch_add(1, Ordering::SeqCst);
            let out = task.await;
            counters.active.fetch_sub(1, Ordering::SeqCst);
            counters.completed.fetch_add(1, Ordering::SeqCst);
            out
        };
        match self {
            Scheduler::Pool { pool, .. } => {
                Task::Spawned(pool.spawn_with_handle(wrapped).expect("spawn onto pool"))
            }
            Scheduler::Single(_) => Task::Inline(Box::pin(wrapped)),
        }
    }

    /// A snapshot of the scheduler's live state — what the `urn:kernel:scheduler`
    /// resource reports.
    pub fn stats(&self) -> SchedulerStats {
        let counters = self.counters();
        SchedulerStats {
            backend: self.backend(),
            threads: self.threads(),
            active: counters.active.load(Ordering::SeqCst),
            spawned: counters.spawned.load(Ordering::SeqCst),
            completed: counters.completed.load(Ordering::SeqCst),
        }
    }

    /// The backend name (`single` / `pool:N`).
    pub fn backend(&self) -> String {
        match self {
            Scheduler::Single(_) => "single".to_string(),
            Scheduler::Pool { size, .. } => format!("pool:{size}"),
        }
    }

    /// Worker-thread count (1 for `single`).
    pub fn threads(&self) -> usize {
        match self {
            Scheduler::Single(_) => 1,
            Scheduler::Pool { size, .. } => *size,
        }
    }

    fn counters(&self) -> &Arc<Counters> {
        match self {
            Scheduler::Single(c) => c,
            Scheduler::Pool { counters, .. } => counters,
        }
    }
}

/// Live task counters behind [`Scheduler::stats`].
#[derive(Default)]
pub struct Counters {
    spawned: AtomicU64,
    active: AtomicUsize,
    completed: AtomicU64,
}

/// A point-in-time view of the scheduler (for `urn:kernel:scheduler`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerStats {
    /// Backend name: `single` or `pool:N`.
    pub backend: String,
    /// Worker-thread count.
    pub threads: usize,
    /// Tasks currently running (attached to a worker).
    pub active: usize,
    /// Tasks ever spawned.
    pub spawned: u64,
    /// Tasks ever completed.
    pub completed: u64,
}

/// A handle to a spawned task; awaiting it yields the task's output.
pub enum Task<T> {
    Spawned(RemoteHandle<T>),
    Inline(Pin<Box<dyn Future<Output = T> + Send>>),
}

impl<T: 'static> Future for Task<T> {
    type Output = T;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        match self.get_mut() {
            Task::Spawned(handle) => Pin::new(handle).poll(cx),
            Task::Inline(fut) => fut.as_mut().poll(cx),
        }
    }
}

/// The kernel's concurrent-fan-out executor: `Invocation::fan_out` spawns each
/// sub-request through this and parks on the join. The returned completion future
/// resolves when the task finishes (on a `Pool` the task is already running on a
/// worker; on `Single` it runs cooperatively when the future is driven).
impl ikigai_core::Spawner for Scheduler {
    fn spawn(&self, task: ikigai_core::BoxFuture<()>) -> ikigai_core::BoxFuture<()> {
        Box::pin(Scheduler::spawn(self, task))
    }

    /// How many spawned tasks make progress **at once** — the worker count, which for
    /// `Single` is honestly 1.
    ///
    /// `Single` does not spawn: it hands the task back as an inline future polled
    /// cooperatively on the calling thread, and the native HTTP transport is blocking
    /// `ureq`, so a call inside such a future holds that thread to completion. Nothing
    /// interleaves, whatever the caller hands over. The default `width()` is `None` —
    /// *unknown* — and a caller that reads unknown as "wide" routes a serialized run to a
    /// backend that only wins under real concurrency, measured ~1.8x slower. Answering is
    /// therefore not a nicety: it is the difference between the fan-out router seeing this
    /// host's real width and guessing.
    fn width(&self) -> Option<usize> {
        Some(self.threads())
    }
}

/// Reports the scheduler's live state for `urn:kernel:scheduler`, so the kernel can
/// surface it intrinsically (the [`SchedulerReporter`](ikigai_core::SchedulerReporter)
/// is injected like a `Clock`). Same fields as [`Scheduler::stats`].
impl ikigai_core::SchedulerReporter for Scheduler {
    fn rows(&self) -> Vec<(String, String)> {
        let stats = self.stats();
        vec![
            ("backend".to_string(), stats.backend),
            ("threads".to_string(), stats.threads.to_string()),
            ("active".to_string(), stats.active.to_string()),
            ("spawned".to_string(), stats.spawned.to_string()),
            ("completed".to_string(), stats.completed.to_string()),
        ]
    }
}

/// One worker per available core, or 1 if the count can't be determined.
fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::join_all;
    use std::collections::HashSet;
    use std::thread::{self, ThreadId};
    use std::time::Duration;

    #[test]
    fn run_returns_the_output_on_both_backends() {
        assert_eq!(Scheduler::single().run(async { 2 + 2 }), 4);
        assert_eq!(Scheduler::pool(2).run(async { 2 + 2 }), 4);
    }

    #[test]
    fn a_pool_runs_spawned_tasks_on_multiple_threads() {
        let sched = Scheduler::pool(4);
        // Each task sleeps briefly so they overlap, then reports its worker thread.
        let handles: Vec<_> = (0..8)
            .map(|_| {
                sched.spawn(async {
                    thread::sleep(Duration::from_millis(20));
                    thread::current().id()
                })
            })
            .collect();
        let ids: HashSet<ThreadId> = sched.run(join_all(handles)).into_iter().collect();
        assert!(
            ids.len() >= 2,
            "pool should use >1 worker, saw {}",
            ids.len()
        );
    }

    #[test]
    fn single_runs_everything_on_one_thread() {
        let sched = Scheduler::single();
        let handles: Vec<_> = (0..4)
            .map(|_| sched.spawn(async { thread::current().id() }))
            .collect();
        let ids: HashSet<ThreadId> = sched.run(join_all(handles)).into_iter().collect();
        assert_eq!(ids.len(), 1, "single is one thread");
    }

    /// The width a caller reads to SIZE a fan-out. `single` answers 1 rather than
    /// `None`: it runs one task to completion before the next, and the damaging guess
    /// about an unknown width is "wide" — which sends a serialized workload to a batching
    /// backend and runs it slower than sequencing it would have.
    #[test]
    fn a_scheduler_reports_its_achievable_width_and_single_says_one() {
        use ikigai_core::Spawner;
        assert_eq!(Spawner::width(&SchedulerSpec::Single.build()), Some(1));
        assert_eq!(Spawner::width(&SchedulerSpec::Pool(4).build()), Some(4));
        // Never `None`: this host always knows its own worker count.
        assert!(Spawner::width(&SchedulerSpec::Pool(0).build()).is_some_and(|w| w >= 1));
    }

    #[test]
    fn stats_report_backend_threads_and_completion() {
        let sched = Scheduler::pool(3);
        assert_eq!(sched.backend(), "pool:3");
        assert_eq!(sched.threads(), 3);
        sched.run(async { 1 });
        let s = sched.stats();
        assert_eq!(s.backend, "pool:3");
        assert_eq!(s.threads, 3);
        assert_eq!(s.active, 0, "nothing running after run() returns");
        assert!(s.spawned >= 1 && s.completed >= 1);

        let single = Scheduler::single();
        assert_eq!(single.backend(), "single");
        assert_eq!(single.threads(), 1);
    }

    #[test]
    fn reentrant_fan_out_does_not_deadlock_on_one_worker() {
        use ikigai_core::{BoxFuture, Spawner};
        // The whole point of park-don't-block: a "parent" task on a 1-worker pool
        // spawns children onto the SAME pool and joins them. It must PARK (free the
        // worker) so the children can run — if it blocked, the single worker would be
        // stuck on the parent and the children would never run (deadlock).
        let sched = Scheduler::pool(1);
        let spawner: Arc<dyn Spawner> = Arc::new(sched.clone());
        let ran = Arc::new(AtomicUsize::new(0));

        let ran_in_parent = ran.clone();
        sched.run(async move {
            let children: Vec<BoxFuture<()>> = (0..3)
                .map(|_| {
                    let ran = ran_in_parent.clone();
                    spawner.spawn(Box::pin(async move {
                        ran.fetch_add(1, Ordering::SeqCst);
                    }))
                })
                .collect();
            futures::future::join_all(children).await;
        });

        assert_eq!(
            ran.load(Ordering::SeqCst),
            3,
            "all children ran on the 1-worker pool — the parent parked rather than blocked"
        );
    }

    /// A spec is validated WITHOUT building: this is what lets `--scheduler pool:xyz`
    /// be rejected at argv time instead of quietly becoming `single`.
    #[test]
    fn a_spec_parses_and_round_trips_without_building_anything() {
        assert_eq!(
            "single".parse::<SchedulerSpec>().unwrap(),
            SchedulerSpec::Single
        );
        assert_eq!(
            "pool".parse::<SchedulerSpec>().unwrap(),
            SchedulerSpec::Pool(0)
        );
        assert_eq!(
            " pool:4 ".parse::<SchedulerSpec>().unwrap(),
            SchedulerSpec::Pool(4)
        );
        assert!("pool:xyz".parse::<SchedulerSpec>().is_err());
        assert!("nonsense".parse::<SchedulerSpec>().is_err());
        // The canonical spelling round-trips, so a host can report the spec it resolved
        // and have that report be re-readable as configuration.
        for spec in [
            SchedulerSpec::Single,
            SchedulerSpec::Pool(0),
            SchedulerSpec::Pool(4),
        ] {
            assert_eq!(spec.to_string().parse::<SchedulerSpec>().unwrap(), spec);
        }
    }

    /// `pool:N` gives the fan-out N workers — the width the whole point of configuring
    /// this is to obtain.
    #[test]
    fn a_pool_spec_builds_the_width_it_names() {
        assert_eq!(SchedulerSpec::Pool(4).build().threads(), 4);
        assert_eq!(SchedulerSpec::Single.build().threads(), 1);
        assert!(SchedulerSpec::Pool(0).build().threads() >= 1);
    }

    #[test]
    fn from_config_parses_backends_and_rejects_garbage() {
        assert!(matches!(
            Scheduler::from_config("single"),
            Ok(Scheduler::Single(_))
        ));
        assert_eq!(Scheduler::from_config("pool:6").unwrap().threads(), 6);
        assert!(Scheduler::from_config("pool").unwrap().threads() >= 1);
        assert!(Scheduler::from_config("pool:xyz").is_err());
        assert!(Scheduler::from_config("nonsense").is_err());
    }
}
