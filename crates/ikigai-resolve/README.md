# ikigai-resolve

The **resolver seam** between the [ikigai](https://crates.io/crates/ikigai-core)
REPL engine and a kernel — local or remote. The engine drives a `Resolver` trait
object rather than a concrete `Kernel`, so the same engine resolves against an
in-process kernel today and an [ikigai-ipc](https://crates.io/crates/ikigai-ipc)-
or [ikigai-quic](https://crates.io/crates/ikigai-quic)-attached one over the wire,
without knowing which.

The trait is deliberately small — exactly what [ikigai-engine](https://crates.io/crates/ikigai-engine)
needs: issue a request, ask whether one is cached, and list the bound resources.
It is **synchronous** by surface (the REPL loop is blocking): the local impl hides
a `block_on`, and a wire impl hides its socket round-trip, behind the same methods.
Every issue reports the `CacheStatus` the resolution had, which a remote server
knows directly — no client-side cache probing across the wire.

## The `Resolver` trait

| method | role |
|--------|------|
| `issue(request) -> (Representation, CacheStatus)` | resolve under the resolver's default authority |
| `issue_as(request, &Capability)` | resolve under an explicit capability (the local kernel enforces it; a wire resolver carries it for the server to clamp) |
| `issue_as_async(request, &Capability)` *(async)* | what the engine `await`s when driving a stage on the scheduler, so a spawned fork/map branch **parks** rather than blocking a worker |
| `issue_as_async_with_incoming(request, &Capability, Provenance)` *(async)* | folds an upstream pipe stage's provenance into the result's cacheability — `source X \| transform` is no more cacheable than `X` |
| `is_cached(&request, &Capability) -> bool` | read-only probe — would this resolve from cache, without resolving it |
| `entries() -> Option<Vec<SpaceEntry>>` | the resources bound in the kernel's space |
| `set_tracer` / `clear_tracer` | install an execution tracer for the next resolution (the `trace` command) |
| `transport() -> String` | a short human label for the transport this resolver speaks over |

The async, capability, tracer, and provenance methods have sensible defaults, so a
minimal remote resolver implements only `issue`, `is_cached`, and `entries`.

## `CacheStatus`

How the representation cache served a resolution: `Hit` (from cache), `Miss`
(computed now, then cached), or `Uncacheable` (computed now, opts out of caching,
recomputes every time).

## Provided impls

- **`impl Resolver for Kernel`** — drives the in-process kernel directly under the
  root capability (the trusted, same-process path), inferring the cache outcome
  from a probe before each issue and overriding the async/provenance/tracer methods
  to thread them into the kernel's real machinery.
- **`impl<R: Resolver + ?Sized> Resolver for Arc<R>`** — a blanket impl so a kernel
  held as `Arc<Kernel>` can be *shared*: driven by the engine while a file watcher
  cuts golden threads on the very same kernel and cache. Every method delegates, so
  the inner resolver's overrides are preserved.

The wire protocol that remote resolvers speak lives in the companion
[ikigai-wire](https://crates.io/crates/ikigai-wire) crate.

## License

MIT OR Apache-2.0.
