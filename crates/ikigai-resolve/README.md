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
| `try_entries() -> Result<Option<Vec<SpaceEntry>>, Error>` | the same enumeration, **keeping the failure** |
| `set_tracer` / `clear_tracer` | install an execution tracer for the next resolution (the `trace` command) |
| `transport() -> String` | a short human label for the transport this resolver speaks over |

The async, capability, tracer, and provenance methods have sensible defaults, so a
minimal remote resolver implements only `issue`, `is_cached`, and `entries`.

## A mount that cannot enumerate says so

`entries()` cannot tell *"this peer does not enumerate"* from *"this peer did not
answer"* — both are `None`, and a `None` mount contributes nothing to the catalog. So
a peer that went silent read exactly like a peer that has nothing, and the manifold
quietly **under-offered**: a caller concluded a capability did not exist when the truth
was that nobody had asked successfully.

`try_entries()` keeps the third case. `Ok(None)` still means *does not enumerate*;
`Err(_)` means *should have answered and did not*, and a `MountedRemote` that gets one
contributes exactly one row instead of vanishing:

```
urn:iki:store:ikigai:mount-unavailable   mount-unavailable   via ipc:~/.ikigai/gonk.sock
```

That row is a real resource — `source` it and it names the namespace whose contents are
missing, the peer they were coming from, and the transport's own reason. It declares a
`Source` action, so it appears in `urn:kernel:actions` and not only in
`urn:kernel:catalog`; a description with no actions would be invisible in exactly the
resource an agent reads.

It lives **inside the mount's own prefix**, which looks like namespace pollution and is
the load-bearing choice: a host wraps a mount in whatever it needs (`--prefer` puts a
prefix guard in front of a failover), and such a guard misses every IRI outside the
prefix *before the mount is consulted*. A status IRI in a neutral namespace enumerated
and then failed to resolve — present in the catalog, absent from the manifold. Inside
the prefix it travels through every prefix-scoped wrapper, in this host and any other,
without those wrappers knowing it exists.

One row **per mount**, because the prefix is the namespace whose contents are missing
and one peer may be mounted twice. One verdict **per peer**, because silence is a
property of the process, not of the local name: a composer hands every mount it builds
one `PeerHealth` (`MountedRemote::new(…).sharing(&peers)`), so two mounts of one silent
peer cost one deadline, not two. It is scoped to a composition rather than being a
process-global, so two kernels in one process never share a verdict about peers they
reached differently — and a test suite does not become order-dependent.

Two bounds keep this cheap. The transports run a **self-description** call — an
enumeration, or the `Meta` behind `describe()` — under a deadline of their own
(`describe.timeout` in the config home, 30s by default), separate from the patient
deadline a resolution gets. And a mount that has seen its peer miss that deadline stops
asking for a cooldown, because a manifold read is one `describe()` *per catalog row*:
the deadline bounds a call, the cooldown bounds the walk. Resolutions through the mount
are untouched — a peer too slow to describe itself may still be serving reads.

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
  the inner resolver's overrides are preserved. ⚠ *Every* method — a defaulted method
  left out of this impl is silently **replaced** by its default rather than inherited,
  and since every mount holds its resolver as an `Arc`, that is not a corner case.

## Naming a target from a catalog

`naming_entry(&[SpaceEntry], &Iri)` answers "which catalog row names this IRI" —
the **most specific** matching pattern (the most literal, non-variable characters),
ties broken by catalog order. Mounts use it to label a forwarded target with the
remote's own endpoint name, and the REPL's `trace` uses it to label a span.

Specificity, not first-match, because routes NEST: `urn:repo:{repo}:pr:{n}` matches
`urn:repo:acme:pr:12:explain` too (its trailing variable swallows the rest), so a
first match names the parent route for every child. It remains a heuristic — a
remote's grammar can apply predicates no pattern string carries — and the shapes
that would let the wire carry the resolved name instead are written up in
`docs/resolved-name-on-the-wire-design.md`.

The wire protocol that remote resolvers speak lives in the companion
[ikigai-wire](https://crates.io/crates/ikigai-wire) crate.

## License

MIT OR Apache-2.0.
