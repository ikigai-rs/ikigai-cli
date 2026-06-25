# ikigai-scheduler

The **async work scheduler** for the [ikigai](https://crates.io/crates/ikigai-core)
kernel. The kernel is **runtime-free**: it produces `async` futures but owns no
executor. This crate is the host-side seam that *runs* them — so the host chooses
how work is scheduled without the kernel ever depending on a runtime. It runs
futures on [`futures`](https://crates.io/crates/futures) (no Tokio), staying a thin
layer, and implements `ikigai-core`'s spawner trait so the kernel can inject it as
its concurrent-fan-out executor (`Kernel::into_scheduled`).

Two ideas from NetKernel shape it:

- **Scheduled, not attached.** Work is submitted to the executor and attaches to a
  worker thread only when one is free.
- **Park, don't block.** A task that `await`s something external yields its thread
  back to the pool rather than holding a CPU while it waits — which is what makes
  bounded-pool *re-entrant* resolution (a `compose` issuing sub-requests) safe: a
  parent that parks frees a thread for its child to run on.

## The `Scheduler`

A cheap-to-clone enum, passed around as the host's one scheduler:

| variant | behavior |
|---------|----------|
| `Scheduler::single()` | run futures to completion on the calling thread (`block_on`) — the runtime-light default, and the only option on a single-threaded host (the browser build) |
| `Scheduler::pool(size)` | a fixed pool of `size` workers (`0` = one per core); spawned tasks attach to a free worker, awaiting tasks park and release theirs |

| method | role |
|--------|------|
| `run(task)` | top-level blocking submit — where the synchronous REPL call sits; sub-tasks it spawns run concurrently on the pool |
| `spawn(task)` | fan work out onto the executor |
| `stats()` | live counters that feed the `urn:kernel:scheduler` resource |
| `from_config(spec)` | parse `single` \| `pool` \| `pool:N` (e.g. from `IKIGAI_SCHEDULER`) |

## License

MIT OR Apache-2.0.
