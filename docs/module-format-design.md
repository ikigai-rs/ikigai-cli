# ikigai dynamically-loadable module format

Status: **design / proposal**; **Phase 1 proven in code** (the `ikigai-module` crate —
see §10). Sketches how a module can be a *separately-compiled, lazily-loaded* WASM
artifact instead of a statically-linked crate — using `ikigai-xslt` as the worked
example. ASCII diagrams so it reads in a terminal and on GitHub alike.

---

## 1. Why

Modules today are **statically linked crates**. The host's `build_kernel` chains them
into the root `Fallback`:

```rust
let root = Fallback::new(vec![
    Arc::new(space),
    Arc::new(ikigai_http::space(Arc::new(BrowserFetchTransport))),
    Arc::new(ikigai_rdf::space()),
    Arc::new(ikigai_xslt::space()),   // ← compiled INTO the host wasm
    Arc::new(ikigai_runbook::space()),
]);
```

That's simple and fast, but every module's code ships in the host binary whether or
not it's ever used. Concretely: linking `ikigai-xslt` (xrust) grew the web-demo wasm
**1.7 MB → 3.9 MB** — 2.2 MB that's dead weight unless you open the Catalog page.
oxigraph (SPARQL) and the candidate data modules (PGlite/DuckDB/SQLite) are far
bigger. We want:

- **Lazy cost.** A module's code (and download) is paid only when one of its IRIs is
  first resolved.
- **Independent lifecycle.** A module is compiled, versioned, and distributed on its
  own, not recompiled into every host.
- **One contract, two homes.** The same module artifact runs in the browser (a second
  wasm instance) and natively (an embedded wasm runtime) — no per-host rebuild.

`ikigai-xslt` is the right pilot: it's the heaviest optional payload, it's a **pure
function** (no state, no auth), and bytes-in/bytes-out marshals trivially — so it
exposes the *one* genuinely new primitive (host-callbacks over the wire) without the
noise of state, persistence, or capability minting.

---

## 2. The model: a module is a space reached over a transport — **with a callback channel**

ikigai already turns "a kernel reached over a transport" into a `Resolver`
(`ikigai-ipc`, `ikigai-quic` speak `ikigai-wire`'s `Call`/`Reply`). A module is *not*
that. The remote-kernel pattern is **one-directional**: the client issues a top-level
request and the server resolves **all sub-requests on its own kernel**. A module is the
inverse — it owns a *few endpoints* but must resolve their `src`/`stylesheet` refs
against the **host's** kernel (the host owns `urn:kernel:catalog`, the cache, the file
space, the network). So the module needs to call **back** to the host mid-invocation.

That callback is the whole new idea, and it lands on a seam that already exists:
`Invocation` reaches the kernel through the **`Issuer`** trait.

```
ikigai-core (unchanged):

  trait Space    { fn resolve(&self, &Request, &Scope) -> Resolution; }
  trait Endpoint { async fn invoke(&self, &Invocation) -> Result<Representation>; }
  trait Issuer   { async fn issue(&self, Request, &Capability) -> Result<Representation>; }

  Invocation::source(iri)  ==  self.issue(Request::Source(iri))  ==  issuer.issue(...)
                                                                       └─ the callback seam
```

A module's endpoint runs with an `Invocation` whose `issuer` is **the host, across the
transport**. `inv.source(&iri)` inside the module marshals an `issue` over the channel,
the host resolves it on its real kernel (hitting its cache), and the bytes come back.
The module reuses `Endpoint` / `Invocation` / `Issuer` **verbatim** — only the *issuer
implementation* is remote.

```
        host process / page                         module artifact (xslt.wasm)
   ┌──────────────────────────┐                 ┌──────────────────────────────┐
   │ Kernel (catalog, cache,  │  Invoke(req)    │  XsltEndpoint::invoke(inv)    │
   │ rdf, file, http …)       │ ───────────────▶│    inv.source("…catalog.rdf") │
   │                          │                 │         │                     │
   │ RemoteModuleSpace        │◀── Source(iri) ─┼─────────┘  (HostIssuer)       │
   │   resolves urn:xslt:* ───┼── Repr(bytes) ─▶│    inv.source("…cards.xsl")   │
   │   here, against the      │◀── Source(iri) ─┼─────────┐                     │
   │   host kernel            │── Repr(bytes) ─▶│         ▼                     │
   │                          │                 │    transform() [sync xrust]   │
   │  caches the result ◀─────┼── Resolved(rep)─│    return Representation      │
   └──────────────────────────┘                 └──────────────────────────────┘
```

---

## 3. Reused vs. new

| Piece | Status | Note |
|---|---|---|
| `Space` / `Endpoint` / `Issuer` / `Invocation` | **reuse as-is** | the module's endpoint is an ordinary `Endpoint`; its issuer is remote |
| `ikigai-xslt` crate (`space()`, `XsltEndpoint`) | **reuse as-is** | compiled to a standalone wasm artifact instead of linked in |
| Cache, golden threads, provenance | **reuse, host-side** | the module is stateless; the host kernel caches the top-level result and the callbacks hit the host cache |
| `ikigai-wire` postcard codec (`encode`/`decode`) | **reuse** | same framing; new message *types* |
| `Capability` clamp-on-receipt (the `IssueAs` pattern) | **reuse** | host passes the clamped cap in `Invoke`; callbacks carry it back, host re-clamps |
| **Bidirectional session** (module ⇄ host mid-call) | **NEW** | `Call`/`Reply` is one round-trip; a module call is a *session* with nested host calls |
| `RemoteModuleSpace` (host) + `HostIssuer` (module) | **NEW** | the two ends of the channel |
| Lazy instantiation + the wasm transport | **NEW** | browser: second wasm instance; native: embedded runtime |

---

## 4. The protocol: a session, not a round-trip

`ikigai-wire` today: `Call` (client→server), `Reply` (server→client), one exchange.
A module invocation is a **session** — the module may interleave host calls before it
replies. Add a module sub-protocol (its own version, kept separate from the kernel
`Call`/`Reply` so their postcard discriminants don't move):

```rust
// host → module: start an invocation
enum ModuleCall {
    Invoke { request: Request, capability: Capability },
    // a reply to one of the module's own HostCalls:
    HostResult(Result<Representation, String>),
    Describe,            // for entries()/Meta of the module's bound IRIs
}

// module → host: either a callback during invoke, or the final answer
enum ModuleReply {
    // the module needs a sub-resource resolved on the host kernel:
    HostCall { request: Request, capability: Capability },
    // the invocation finished:
    Resolved(Representation),
    Error(String),
    Bindings(Vec<SpaceEntry>),   // answer to Describe
}
```

The exchange is a little state machine driven by the host:

```
host                                   module
 │  ModuleCall::Invoke(req, cap)  ───────▶│   invoke begins
 │◀── ModuleReply::HostCall(src, cap) ────│   inv.source(catalog.rdf)
 │      (host resolves on its kernel)     │
 │  ModuleCall::HostResult(Ok(rep))  ────▶│   …resumes
 │◀── ModuleReply::HostCall(style, cap) ──│   inv.source(cards.xsl)
 │  ModuleCall::HostResult(Ok(rep))  ────▶│   …resumes, runs xrust
 │◀── ModuleReply::Resolved(rep) ─────────│   done
```

The module side is a thin shim: it builds an `Invocation` whose issuer is a
`HostIssuer` (implements `Issuer::issue` by emitting a `HostCall` and awaiting the next
`HostResult`), resolves the request in `ikigai_xslt::space()`, and returns the
`Representation`. **No xrust-specific protocol** — `ModuleCall`/`ModuleReply` is generic
over any module, which is the point.

---

## 5. Where it plugs into the host: `RemoteModuleSpace`

The host binds a `Space` for the module's prefix(es), instead of `ikigai_xslt::space()`:

```rust
Fallback::new(vec![
    Arc::new(space),
    Arc::new(ikigai_http::space(Arc::new(BrowserFetchTransport))),
    Arc::new(ikigai_rdf::space()),
    Arc::new(RemoteModuleSpace::new(           // ← was ikigai_xslt::space()
        ["urn:xslt:"],                          // prefixes it claims
        ModuleSource::Lazy("xslt.wasm"),        // not loaded until first hit
        host_issuer.clone(),                    // how its callbacks reach this kernel
    )),
    Arc::new(ikigai_runbook::space()),
])
```

- `Space::resolve` matches the prefix and returns a `Hit` whose `Endpoint` is a
  `RemoteEndpoint`. (First match also *triggers* instantiation; see §7.)
- `RemoteEndpoint::invoke(inv)` runs the §4 session: send `Invoke`, and for each
  `HostCall` the module makes, resolve it via `inv.issue(...)` — i.e. back into **this**
  kernel — then send `HostResult`. Finally return the module's `Resolved` representation.
- `Space::entries()` answers via `ModuleCall::Describe`, so the module's bound IRIs show
  up in `urn:kernel:catalog`, the CLI Docs tab, and `list` — the catalog stays whole.

Because `RemoteEndpoint::invoke` resolves the module's callbacks through the *host*
`inv.issue`, the host kernel records their golden threads and the result is cached and
invalidated **exactly as the statically-linked version is** — "Turtle all the way down"
is unchanged.

---

## 6. Deployment families: linked · loaded · served

A module is just a `space()` + endpoints crate, so **what it does is orthogonal to how
it's shipped.** Two independent axes — and `ikigai-xslt` already compiles clean on all
three targets (native, `wasm32-unknown-unknown`, `wasm32-wasip1`):

```
                      in-process                       out-of-process
                ┌───────────────────────┐      ┌────────────────────────────┐
   native       │ linked (today)        │      │ standalone server:         │
                │ — or — embedded        │      │ a kernel with just         │
                │ wasmtime (lazy)       │      │ ikigai_xslt::space(),      │
                │                       │      │ serve()'d over QUIC/IPC    │
                ├───────────────────────┤      ├────────────────────────────┤
   wasm /       │ second wasm instance  │      │ WASI service / serverless: │
   WASI         │ in the page (lazy)    │      │ the .wasm run by a WASI    │
                │                       │      │ host (wasmtime, Spin,      │
                │                       │      │ wasmCloud, edge)           │
                └───────────────────────┘      └────────────────────────────┘
```

The host's root `Fallback` mixes them freely behind the one `Space`/`Resolver`
abstraction: a statically-linked space, a lazy in-page wasm module, and a *remote*
space (a QUIC/IPC client) pointing at a specialized server can all coexist — which is
the `multi-connect` story (connect to several specialized kernels at runtime) and the
"dynamic-offload target" idea (a GPU/SPARQL/XSLT server is just a specialized remote
kernel). "Different standalone servers compiled with different deps built in" = a thin
`main()` that binds one `space()` and calls the existing `serve()` (the
`web-demo/src/bin/server.rs` pattern).

### The one thing that decides whether "served" needs new code: by-value vs by-reference

- **By-value inputs** (inline `content` piped in + an inline stylesheet literal) make an
  invocation **self-contained** — no `inv.source` callbacks. That's a pure
  `Request → Representation` function, which already rides the **existing**
  one-directional `Call::Issue`/`Reply::Resolved`. So an XSLT (or SPARQL) **standalone
  server works on today's wire with zero protocol changes** — build a specialized kernel,
  `serve()` it, done. The bidirectional session of §4 is **not** needed here.
- **By-reference inputs** (`src=<uri>`, `stylesheet=<uri>` resolved against the *host's*
  kernel) are what require the callback channel — the module has to reach back for
  resources the host owns. That's the upgrade §4 buys; it's also what makes the
  *in-process lazy-loaded* form (where by-ref is the whole point) work.

`ikigai-xslt` supports both (it has the piped-`content` fallback **and** the `src`/
`stylesheet` refs), so it can be served by-value over the existing wire **now**, and
gains the by-ref form once the callback session lands. Good incremental path.

## 7. The transport: one protocol, several homes

`ModuleCall`/`ModuleReply` are postcard bytes (`ikigai-wire::encode`/`decode`). What
carries them differs per host; the module shim and the host `RemoteModuleSpace` don't
care:

- **Browser (Phase 1).** The module is a second wasm instance in the same page. The
  channel is a JS-mediated byte pump: the host wasm hands encoded bytes to a JS shim,
  which calls the module instance's exported `on_message(bytes) -> bytes`; the module's
  `HostCall`s come back through a JS import the host services. Single-threaded, so it's
  a cooperative message loop — the same shape as the existing `spawn_local` + `oneshot`
  bridge `BrowserFetchTransport` already uses. (xslt makes its two `source` callbacks
  *before* the sync transform, so there's no reentrancy into the module.)
- **Native (Phase 2).** The host embeds a wasm runtime (wasmtime). The module's
  *imports* are the host callbacks (`HostCall`), its *exports* are `Invoke`/`Describe`.
  Same postcard bytes across the host-function boundary. (A heavier module could instead
  be an out-of-process peer over IPC/QUIC — same `ModuleCall` protocol, socket
  transport — reusing the existing servers.)
- **Component Model (Phase 3, optional).** The host↔module contract (`Invoke` + the
  `Issuer` callback) is expressible as a WIT interface; wasmtime runs components
  natively and the browser via transpilation (jco). This formalizes the ABI and gets
  language-agnostic modules, at the cost of the toolchain. The postcard sketch is the
  pragmatic interim that ships on what we already have.

---

## 8. Lazy instantiation

`ModuleSource::Lazy("xslt.wasm")` means the artifact is fetched + instantiated on the
**first** `resolve` that matches its prefix, then reused. A `OnceCell<ModuleInstance>`
behind the `RemoteModuleSpace` does it; concurrent first-hits await the same init.
Until then the host carries only the small `RemoteModuleSpace` (a prefix list + a URL),
not xrust. The manifest a host needs to bind one is tiny:

```
{ "prefixes": ["urn:xslt:"], "artifact": "xslt.wasm", "version": "0.1.0" }
```

(`entries()`/`Describe` can stay lazy too — answer from the manifest's declared IRIs
until the module is up, or instantiate on first introspection.)

---

## 9. Capabilities & trust

- The host puts the **clamped** session capability in `ModuleCall::Invoke` (the module
  resolves under exactly the caller's authority — the `IssueAs` clamp pattern, reused).
- Each `HostCall` carries a capability the **host re-clamps** to the session before
  resolving (a module can only ever *narrow*, never widen — `Capability` has no widening
  op, so this is structural).
- A module is sandboxed by wasm itself: no ambient FS/network, only the host callbacks
  it's granted. A future signed-manifest step gates *which* prefixes an artifact may
  claim and which capabilities the host will honour from it.

---

## 10. Phasing

1. **Protocol + shim, statically (proof).** ✅ **Done** — `ikigai-module` crate.
   Defines `ModuleCall`/`ModuleReply` (the wire session), a `ModuleTransport` seam with
   an `InProcessTransport` (direct call), a host-side `ModuleSpace` (routes a prefix to
   the module), and a `HostBridge` `Issuer` so the module's `inv.source` resolves back
   through the host. Tests run `ikigai-xslt` behind it: the module pulls its `src` +
   `stylesheet` back from the host kernel and the host caches the result — the
   callback machinery, with zero transport risk. (Needed one core change:
   `Invocation::with_issuer` is now `pub` — "run an endpoint under a host-supplied
   issuer.")
2. **Browser two-wasm.** Compile `ikigai-xslt` to its own wasm with the module shim;
   lazy-load it from the web-demo; the Catalog page drives it. Drops ~2.2 MB off the
   host's initial download.
3. **Native wasmtime.** Same artifact, embedded runtime; the CLI loads it on first
   `urn:xslt:*`.
4. **Generalize.** Move SPARQL (oxigraph — bigger win) and the candidate data modules
   behind the same format; optionally formalize with WIT/Component Model.

## Open questions

- **Async reentrancy** if a module makes callbacks that re-resolve into the *same*
  module (xslt doesn't; a future module might). Likely needs per-session isolation or a
  reentrancy guard.
- **Streaming / large bodies** — `Representation` is bytes today; a big graph round-trips
  in full. Fine for now; chunking later if needed.
- **Provenance over the module boundary** — the host already gets the result's `expiry`
  + threads in `Resolved(rep)`; confirm pipe `Provenance` (Part C) need not cross into
  the module (it shouldn't — the module is a leaf transform).
- **Versioning** — `PROTOCOL_VERSION` for the module sub-protocol, negotiated at
  instantiation (host and module no longer ship together).
