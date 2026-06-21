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

    /// Parse a scheduler from a config string: `single`, `pool` (cores), or `pool:N`.
    pub fn from_config(spec: &str) -> Result<Self, String> {
        match spec.trim() {
            "single" => Ok(Self::single()),
            "pool" => Ok(Self::pool(0)),
            s => match s.strip_prefix("pool:") {
                Some(n) => n
                    .parse::<usize>()
                    .map(Self::pool)
                    .map_err(|_| format!("invalid pool size in `{spec}` (expected `pool:N`)")),
                None => Err(format!(
                    "unknown scheduler `{spec}` (single | pool | pool:N)"
                )),
            },
        }
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
