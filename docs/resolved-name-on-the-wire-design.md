# The resolved name on the wire

**Status:** recommendation. Not implemented — it is a protocol change and wants a
deliberate decision. **Home:** `ikigai-wire` (a `PROTOCOL_VERSION` event) and, for
the variant this doc recommends first, `ikigai-core` (`TraceEvent`).
**Shipped meanwhile:** the client-side heuristic described under "What ships today".

## The problem

A mount resolves nothing locally. `MountedRemote`/`RemoteSpace` always hit with a
`ForwardingEndpoint`, and that endpoint has to answer `name()` — the *remote's*
name for the target — without a wire round-trip on the resolve path. It answers by
replaying the remote catalog's pattern STRINGS through a `UriTemplate` and taking a
match (`RemoteNames::name_for`, `crates/ikigai-resolve/src/lib.rs`).

That is structurally unsound, and not by accident: **grammar semantics are not
recoverable from a pattern string.** A `Grammar` is Rust code. ikigai-browse's
`PrPageRow` (`src/pr.rs`) matches `urn:repo:{repo}:pr:{n}` and then *rejects* an `n`
containing a `:` — a predicate no pattern string can express — which is exactly what
makes `urn:repo:{repo}:pr:{n}:explain` and `…:review` distinct routes on the server
and indistinguishable to a naive client replay.

## What ships today (the heuristic, and its limits)

`name_for` now takes the **most specific** match — the most literal (non-variable)
characters in the pattern — with ties broken by catalog order, instead of the first
match. The same rule is exposed as `ikigai_resolve::naming_entry` and used by the
REPL's trace renderer (`endpoint_name`), which labels a span by scanning the catalog
and previously compared only the literal head before the first `{`, so *every* row
under `urn:repo:` collided.

It is well founded — a nested route is spelled by ADDING literals to its parent's
pattern — and it fixes the whole nesting class. What it still cannot do:

- express any predicate a `Grammar` applies beyond its pattern (browse's `:`
  rejection; a regex grammar; a grammar that consults state);
- separate two rows with equal literal counts and overlapping languages — those stay
  catalog-order-decided;
- survive a remote that reorders its catalog (the tie-break is positional).

So the guess is better, and still a guess. Removing it means the *server* — the only
party that knows its own grammars — must say what it resolved.

## Two consumers, and they are not the same

1. **The manifold probe guard**, `select.rs::describe_entry` in ikigai-core. It
   probe-expands a template row and keeps the description only if the resolved
   endpoint identifies as the row's endpoint. Since **core 0.1.55** (PR #85) it takes
   **either witness** — `Endpoint::name()` OR the resolved `Description`'s `id` — and
   over a mount the description comes from a real `Meta` round-trip to the remote,
   i.e. the remote's own answer for that very IRI. **This consumer is already sound
   without any protocol change**; the guess only supplies a redundant witness.
2. **Trace labels**, `engine.rs::endpoint_name`. It never consults
   `ForwardingEndpoint::name()` at all — it infers the label client-side from catalog
   rows, for local and remote spans alike. This is the consumer a wire-carried name
   would actually serve.

That split is what determines the shape below: the resolution reply is the wrong
place to start, because the consumer that reads a resolution already has a better
witness, and the consumer that mislabels reads *spans*.

## Recommended shape (1): the span carries its own endpoint

Add to `ikigai_core::TraceEvent`:

```rust
pub struct TraceEvent {
    pub target: String,
    /// The name of the endpoint that served this invocation — `Endpoint::name()`
    /// as the kernel that INVOKED it saw it. A remote subtree stitched into a
    /// local trace therefore carries the remote's own names, with no client-side
    /// inference from pattern strings.
    pub endpoint: String,
    // … thread, started, ended, cache_hit, span, parent, capability, notes
}
```

The resolved endpoint is already in scope at both `Kernel::trace_record` call sites
(the cache-hit arm and the post-invocation arm), so filling it is one parameter and
two call sites, not a restructuring. The renderer then prefers `event.endpoint` and
keeps `naming_entry` only for the no-events path (a resolver that doesn't trace).

Cost: `TraceEvent` crosses the wire inside `Reply::ResolvedTraced`, so its postcard
layout changes → **`PROTOCOL_VERSION` 7 → 8**. That is a documented, already-walked
path: `kernel.rs` carries the same note for `notes` (core 0.1.48 → protocol v5).

Why first: it fixes the mislabeling *at the root*, for local traces as well as
mounted ones, and it deletes the inference from the rendering path rather than
improving it.

## Recommended shape (2): the reply names what it resolved

For the non-traced path — any future consumer that needs the name at resolve time
without paying the `Meta` round-trip `describe()` pays:

```rust
/// What the SERVER knows about a resolution and the client would otherwise have to
/// infer from pattern strings. Fields are APPEND-ONLY: postcard is positional, so
/// adding one is a PROTOCOL_VERSION event (the same rule WireError's variants obey).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ResolvedMeta {
    /// The endpoint name the server's kernel resolved for this target.
    pub endpoint: String,
    /// The catalog pattern that matched (exact IRI or template source), so the
    /// client can attribute the name to a row it already holds.
    pub pattern: String,
}

pub enum Reply {
    Resolved(Representation, CacheStatus),
    Cached(bool),
    Entries(Option<Vec<SpaceEntry>>),
    Error(String),
    ResolvedTraced(Representation, CacheStatus, Vec<TraceEvent>),
    ErrorTyped(WireError),
    // ── v8, appended (existing discriminants unchanged) ──
    /// `Resolved`, plus what the server resolved it to.
    ResolvedNamed(Representation, CacheStatus, ResolvedMeta),
    /// `ResolvedTraced`, plus the same.
    ResolvedTracedNamed(Representation, CacheStatus, Vec<TraceEvent>, ResolvedMeta),
}
```

Notes on the shape:

- **No `Call` change.** The reply is strictly richer for the same three calls
  (`Issue`, `IssueAs`, `IssueTraced`), which matters: `Call` is not
  `#[non_exhaustive]`, and its discriminant order is the postcard contract.
- **The hello is what makes this safe.** Since v7 the hello exchange is REQUIRED, so
  a server always knows the peer's version and sends `*Named` only to a v8+ client;
  a v7 client is answered exactly as today. Appending keeps every existing
  discriminant, so a v8 client also decodes a v7 server's replies.
- **Adding a `Reply` variant is source-breaking for out-of-tree matchers** (that is a
  Rust concern, not a postcard one — `#[non_exhaustive]` governs matching, not
  encoding). If `Reply` is to keep growing, mark it `#[non_exhaustive]` in a separate
  small change *before* the next variant lands, so later additions are semver-minor
  for anyone matching on it.
- If both shapes land together, `ResolvedTracedNamed` is redundant with shape (1) —
  every span already names its endpoint, including the root. Prefer landing (1)
  alone, and (2) only when a caller for it exists.

## Rejected alternatives

- **`Call::NameFor(Iri)`** — a round-trip on the resolve path. `RemoteNames` exists
  precisely to avoid that; a name lookup must never cost a network hop.
- **Ship the grammar in `SpaceEntry`** (a serialized regex/predicate the client
  re-evaluates) — re-encodes grammar semantics as data, which is the same guess with
  a larger surface: every new `Grammar` impl becomes a wire concern, and a client
  that evaluates it can still diverge from the server that authored it.
- **Drop `Endpoint::name()` from the guard entirely** — already effectively done by
  the either-witness fix; going further (name-less endpoints) would cost the local
  kernel a real signal to fix a remote-only defect.

## A no-protocol refinement worth doing either way

`ForwardingEndpoint::describe()` performs a `Meta` round-trip whose `Description.id`
IS the remote's name for that exact IRI. Caching it (`OnceLock<String>`, consulted by
`name()` before falling back to the replayed guess) makes `name()` agree with
`describe()` by construction, with no new protocol and no extra round-trip on the
path that already describes. It does not help the trace renderer — that consumer
never calls `name()` — which is why it is a refinement and not the answer.

## Recommendation

1. Land `TraceEvent.endpoint` in core, adopt in ikigai-cli with `PROTOCOL_VERSION`
   8. That is the change that removes the inference from the mislabeling path.
2. Hold `Reply::ResolvedNamed`/`ResolvedMeta` until a consumer needs a resolve-time
   name — spending a version event before there is a caller buys nothing, and the
   probe guard (the only candidate today) is already sound on its own witness.
3. Keep most-specific-wins as the fallback regardless. A peer older than the change,
   or a grammar the wire can't describe, still needs *some* answer — and the honest
   framing is that it is a heuristic label, not an identity.
