# Mount over the wire: a local kernel composing a remote one

**Status:** design / brief. Phase 1 in progress.
**Home:** the ikigai-cli workspace (`ikigai-resolve` for the space + endpoint; the
embedded host + engine for the mount point). **No core change** — `Space`,
`Endpoint`, and `Mount` already exist; `RemoteSpace` wraps a `Resolver`, a
cli-workspace type. So this arc needs **no `ikigai-core` publish**.

## Why

Today `--connect` is all-or-nothing: the REPL drives *either* the local kernel
*or* a remote one. Mount-over-wire lets a *local* kernel include a *remote* kernel
as one **sub-space** of its resolution graph — `urn:remote:*` resolves over the
wire, everything else locally, in one composed kernel. That turns "one kernel per
process" into "one resolution graph federated across kernels": a session can mount
the calendar daemon, a compute server, or a peer's exposed space and *compose
across them* (transclude, join, pipe) as if local. It is the distributed-substrate
keystone several parked designs assume (peer-devices, layer-servers, multi-connect
QUIC, Hydra federation), and it delivers **3b** (the cross-boundary trace) as a
follow-on once the forward carries a trace context.

## The model (confirmed by Phase-0 read)

- `Space::resolve(&Request, &Scope) -> Resolution::Hit(Resolved{endpoint, bindings})`
  is synchronous, pure routing. `Mount::new(prefix, inner)` delegates a prefix to
  an inner space — the exact composition primitive. The `Space::entries` doc even
  anticipates "a remote space" returning `None`.
- `Endpoint::invoke(&Invocation) -> Result<Representation>` is **async**, and
  `Invocation.capability` is a public field — so a forwarding endpoint can do the
  wire round-trip on invoke, under the caller's authority.
- `Resolver` (issue/issue_as, entries) is the wire client; `RemoteSpace` holds an
  `Arc<dyn Resolver>` (an `IpcResolver`/`QuicResolver`).

**Shape:**
```
RemoteSpace { resolver: Arc<dyn Resolver> }
  resolve(req) -> Hit(ForwardingEndpoint { resolver, request: req.clone() })  // capture the whole request
  entries()   -> resolver.entries()                                           // forward (a round-trip; off hot path)

ForwardingEndpoint { resolver, request }
  invoke(inv) -> resolver.issue_as(self.request.clone(), inv.capability).map(|(repr, _status)| repr)
```
`resolve` captures the full request (target + verb + args), so `invoke` forwards it
verbatim with the invocation's capability — no reconstruction from `Invocation`.
An outer `Mount` prefix means only the chosen namespace goes remote, so
`RemoteSpace` can optimistically `Hit` (a genuinely-absent remote resource comes
back as an error on invoke, not a resolution miss).

## Phases

### Phase 1 — resolution crosses the boundary (this arc's core)
- `RemoteSpace` + `ForwardingEndpoint` in `ikigai-resolve`.
- A mount point: a `mount <prefix> <target>` REPL command (or a startup flag) that
  `connect`s a resolver and wraps the local root in `Fallback[ existing, Mount(prefix, RemoteSpace) ]`.
- **Demo:** `serve` a kernel; in another session `mount urn:remote: <sock>` then
  `source urn:remote:<something>` resolves on the *remote* kernel, composed into
  the local graph. `catalog` shows the remote's entries under the mount.

### Phase 2 — the cross-boundary trace (this is 3b)
`ForwardingEndpoint::invoke`, when the *local* kernel is tracing, installs itself so
the forward goes as `Call::IssueTraced` (carrying the local mount span as
`TraceContext.parent_span`), then **re-bases** the returned remote spans into the
local span space and parents the remote root under the mount span, merging them
into the local trace. Demo: a `trace` whose tree spans local nodes + a remote
subtree. (Depends on Phase 1 + the 3a wire primitives, already shipped.)

### Phase 3 — per-node capability diff-render
The mount **clamps** the forwarded capability to the remote principal — so this is
the first place a node's authority differs from its parent's. Render a node's
capability only when it differs from its parent (attenuation pops; the uniform
common case stays clean). Now demonstrable, because the mount creates the variation.

## Open decisions / risks

- **Cache & golden threads across the boundary.** A remote result's threads live on
  the remote kernel; the local kernel can't cut them. v1: treat a remote result as
  **time-bounded or uncacheable locally** (fold in the reported `CacheStatus` but
  don't trust local golden-thread invalidation for it). Revisit with a
  remote-invalidation signal later.
- **Capability at the mount.** The forward carries `inv.capability`; the server
  clamps to its authenticated principal (IPC = peercred owner ≈ root; QUIC = the
  client cert). This clamp *is* the attenuation Phase 3 renders.
- **Sync issue inside async invoke.** `Resolver::issue_as` is synchronous (hides a
  `block_on`/round-trip); calling it inside the async `invoke` blocks that task.
  Fine for the single-threaded REPL; under the scheduler pool it would park a
  worker — note before mounting a remote in a pooled server.
- **Mount specification.** v1: a `mount` REPL command / startup flag. A config
  resource (`urn:host:mounts`) and per-URI rerouting are the multi-connect follow-on.
- **entries() forwarding** does a round-trip; acceptable on `catalog`/`entries`, not
  a hot path.

## Logistics

All in the ikigai-cli workspace — no core dependency, **no publish gate**. Every
change via PR with green CI (checked explicitly). The 3a wire primitives
(`Call::IssueTraced` / `Reply::ResolvedTraced` / `SpanCollector`) are already in
place for Phase 2.
