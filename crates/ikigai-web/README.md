# ikigai-web

The **inbound HTTP transport** for [ikigai](https://crates.io/crates/ikigai-core):
serve a kernel over HTTP. A thin adapter, not an app — it maps the HTTP request
onto a kernel `Request` and the `Representation` back onto an HTTP response, and
leaves all behavior (scheduling, forms, policy) in resources, compositions, and
capabilities *above* it, exactly as [ikigai-quic](https://crates.io/crates/ikigai-quic)
and [ikigai-mcp](https://crates.io/crates/ikigai-mcp) keep the kernel out of the
wire layer.

```text
<METHOD> /<noun>/<partition>/<key>?<filters>
   →  Request(verb_of(method), urn:<noun>:<partition>:<key>, args)  under  cap_of(request)
   →  Representation  →  HTTP response
```

```rust
use std::sync::Arc;
// Serve under the default edge policy (strict security headers, CORS closed).
ikigai_web::serve(kernel, ikigai_web::public_cap(), addr).await?;

// …or configure the edge policy + routes.
ikigai_web::serve_with(kernel, cap_fn, addr, config).await?;
```

From the CLI: `ikigai serve --http <port>` (loopback — front it with TLS at your
proxy; see below), with `--trust-proxy` and `--cors-origin <o>` to configure the
edge.

### Provenance on a write

A mutating request (`PUT`/`POST`/`DELETE`) reaches the endpoint with three arguments
the transport owns, all **read off the connection, never the payload**: `received`
(RFC 3339, UTC), `client` (the socket peer, or the trusted proxy's rightmost
`X-Forwarded-For` hop), and — when the host wires a `PrincipalFn` into
`EdgeConfig::principal_fn` — `principal`, the opaque string the door authenticated the
request as (a stable IRI, a label; the transport does not interpret it). A principal is
**not authority**: the capability from `cap_fn` alone decides what the request may do.
Reads carry none of the three (an argument is part of the cache key), and all three are
dropped from the query string on a write, so a submitter cannot name their own origin or
identity; `principal` is dropped from a read's query string too, so a read names nobody.
The doctest on `PrincipalFn` pins the shape.

### Admission before anything answers

`EdgeConfig::admit_fn` (an `AdmitFn`) sees each request before ANY answer the door gives
and may refuse it with a `Refusal` (`400`, `403`, `404`, `421` or `429`; any other status
is a `403`). That matters because three answers never reach the kernel, so a host overlay
there cannot refuse them: `OPTIONS`, the `?description` face and the push stream. A door
that refused by handing a request an empty capability still disclosed those. `None` (the
default) admits everything. The doctest on `AdmitFn` pins the behavior.

## The mapping

| HTTP | kernel |
|------|--------|
| `GET` / `HEAD` | `Source` |
| `PUT` / `POST` / `PATCH` | `Sink` |
| `DELETE` | `Delete` |
| `OPTIONS` | the allow-list |
| `Accept:` / `?as=` | the `as=` face, negotiated against the faces the resource declares |
| query params | inspectable request args |
| request body (a write) | the piped `content`, with `Content-Type` as `content-type` |

- **The allow-list and `405` come from the endpoint's declared `describe().verbs`** —
  a Source+Sink resource `405`s a `DELETE`, and `OPTIONS` reports the real method set.
  An endpoint that declares no verbs is not pre-empted (resolution runs and the
  endpoint reports the outcome); declare verbs for a precise `OPTIONS`/`405`.
- **`cap_of(request)` is the multi-tenant door** — every request resolves under a
  capability derived from its identity. The default is a public (empty-scope)
  capability, or a fixed `--cap` ceiling that narrows the edge; a per-user capability
  (magic-link / passkey) fills the same seam.
- **Typed error → status:** `Denied` → 403, `NotFound` and `Unresolved` (no endpoint
  bound to the path) → 404, invalid/missing arg → 400, `Conflict` (the resource's
  current state refuses the request) → 409, transient → 503, else 500. A failed
  `If-Match` / `If-None-Match` stays 412: that is a precondition the caller stated, and
  it is checked before the write reaches the endpoint.

## Content negotiation

`Accept` is negotiated per RFC 9110 §12.5.1 against the **faces the resource declares**
for the verb: its `as` input's `one_of` when it has one, otherwise the verb's `outputs`.

- Every range is read with its `q`; `q=0` means "not acceptable". Each face takes the
  weight of the most specific range matching it (`text/turtle` over `text/*` over `*/*`),
  and the heaviest face wins, ties going to the default face (the `as` default, else the
  first declared).
- The winning face is sent as `as` unless the client can be said not to have asked for it:
  no `Accept` at all, or a winner that is the default face and was matched only by a
  wildcard. Then no `as` is sent and the resource answers in its own default. A browser's
  navigation header (`text/html,…,*/*;q=0.8`) therefore reads a plain-text resource
  through its trailing `*/*` rather than being refused.
- ⚠ How the winner was MATCHED decides that, never whether it equals the default:
  `Accept: text/html` on a resource whose HTML face is its first declared output is a
  request for HTML and is answered with `as=text/html`. (0.1.22 elided `as` there, and the
  HTML face of `urn:iki:foaf` went missing over `Accept` while `?as=` still worked.)
- The default face is the `as` input's `default_value` when the resource DECLARED one,
  else this adapter's guess at the first declared face. A guess breaks ties but is not a
  promise about the bytes a request carrying no `as` returns, so a guessed default only
  elides `as` for a `*/*` client — one that reads anything, whatever the default turns out
  to be. Declare `as` with `one_of` and a `default_value` to be negotiated for exactly.
- Nothing acceptable is **`406 Not Acceptable`**, listing the faces. `Accept: text/turtle`
  on a plain-only resource is still refused.
- **`?as=<type>`** names the face explicitly and beats `Accept` — a link in a page cannot
  set a header. A type outside the declared faces is a 406 too.
- A resource that declares no faces cannot be negotiated for and is never refused: it is
  handed the client's most preferred concrete type as `as`, and judges it itself.

## Conditional requests and caching

Reads project a strong **`ETag`** (a content hash) and a **`Cache-Control`**
derived from the representation's cache validity:

| kernel answer | `Cache-Control` |
|---|---|
| `Always` | `no-store` |
| `Never` | `no-cache` |
| `At(t)`, nothing a write can cut | `max-age` until `t` |
| `At(t)`, hangs from a golden thread (or the resource is writable) | `no-cache` |
| `At(t)`, already passed | `no-cache` |

A cacheable answer is `public` when any caller would have been handed it, and
`private` when the request's credentials shaped its capability — the edge asks the
host's capability function what the same request would get without its
`Authorization` and `Cookie` headers. `Never` is **never** `immutable`: the kernel's
`Never` means "valid until a thread is cut, while this kernel runs", which a restart,
an upgrade or a mount breaks without cutting anything, and `no-cache` against the
strong `ETag` costs a bodyless `304` while nothing changed.

`Vary` names what selected the answer: `Accept` (unless `?as=` named the face or
the resource has only one), `Authorization` and `Cookie` (unless a route pins the
capability), and `Origin` whenever CORS allows any origin.

`If-None-Match` on a read yields `304`, carrying the same `ETag`, `Cache-Control` and `Vary`. Writes
are conditional: `If-Match` / `If-None-Match` are checked against the resource's
current ETag before the mutation (optimistic concurrency → `412`; `If-None-Match: *`
is create-only). `DELETE` is idempotent — a repeat delete of a resource we deleted
returns `204`, while one that never existed is `404`.

`PATCH` is read-modify-write through a **content-type registry**: the request
`Content-Type` selects a patch strategy (RFC 7386 JSON Merge Patch today) that
transforms the current representation before it is Sunk. An unknown patch type is
`415`.

## Server push

A page learns that something it shows changed by holding one **event stream** open instead of
polling. Set `EdgeConfig::push` (`ikigai serve --http <port> --push` from the CLI) and a `GET`
of `/_ikigai/push` answers `text/event-stream` and stays open, backed by one core cut listener
(`Kernel::listen`, core 0.1.82) registered under the capability the door grants that request.

```text
GET /_ikigai/push?path=/l/default/item/5/card&path=/queue/rows

event: cut
id: 17
data: {"thread":"urn:…","sequence":17,"invalidated":["urn:…"],"more":0,"paths":["/queue/rows"]}
```

- **Subscribe by what the page shows**: `path=` (repeatable) names a fragment by its URL, is
  matched by what a cut INVALIDATED (so a composite hanging from a store's thread is heard), and
  comes back in `paths`. `thread=` (exact) and `prefix=` name threads directly; no parameter
  hears every cut the capability may hear. Anything else, or more than 64, is a `400`.
- **Authority**: the capability must hold `urn:cap:kernel:listen` (else `403`), and a non-root
  one hears only threads its OWN cached reads rest on, so an anonymous stream hears exactly what
  anonymous reads would. The edge never adds the scope for you: that would be another cache
  partition, and it would hear nothing. Only cached reads are heard; a `no-store` fragment
  must still be polled.
- **Losing history is said out loud**: an overflowing listener queue, or a reconnect carrying
  `Last-Event-ID`, sends `event: resync`, and the page refreshes everything it shows.
- **Expiry is not a cut**: a deadline passing sends nothing. Revalidating on a deadline is the
  page's job, from the `max-age` its fragment was served with.
- **Bounds**: a stream holds a slot under `max_connections`; every write is under
  `write_timeout`; a heartbeat comment every 15 s; closed after 10 minutes with no event
  (`EventSource` reconnects and resyncs).

The page side is a few lines of plain `EventSource` that trigger htmx re-fetches; the event
shape, the page script and the bounds are in the `push` module docs, where a doctest pins the
shape over a real socket. Measured on an M-series laptop, release build
(`examples/push_cost.rs`): an idle stream costs about 7 KiB of resident memory (both ends
in-process); one write with 1000 streams open takes the writer about 0.45 ms (the cut
queues on every listener on its stack, versus 2 µs with none), and the last of the 1000 clients
has the event within about 4–6 ms.

## Edge policy

`EdgeConfig` is a safe public-edge posture by default — **strict security headers,
CORS closed, proxy not trusted**:

- **Security headers:** `Content-Security-Policy` (`default-src 'self'`;
  `frame-ancestors 'none'`; …), `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`. **HSTS rides only on an HTTPS request** — and
  HTTPS is inferred *only* from a trusted proxy's `X-Forwarded-Proto`, never from an
  untrusted client (`--trust-proxy` enables it).
- **CORS** is closed unless you allow-list origins (`--cors-origin`, or per route).
  Allowed origins are echoed, and every response carries `Vary: Origin` while any
  origin is allowed; preflight (`OPTIONS` +
  `Access-Control-Request-Method`) advertises methods from the resource's own
  `describe()` Allow.

### Request bounds

What an anonymous client can make the server hold is bounded before it is read, and
an over-bound request is **refused rather than trimmed to fit**:

- **Headers** cap at 64 KiB → `431 Request Header Fields Too Large`.
- **Bodies** cap at `max_body_bytes` (default 1 MiB, `--max-body <bytes>`). A
  `Content-Length` above the cap is refused with `413` *without reading the body*,
  so the refusal costs nothing.
- **Framing must agree.** A `Content-Length` that will not parse is a `400`, not a
  zero-length body; a body shorter than declared is a `400`, not a partial
  submission; bytes past `Content-Length` are the next pipelined request and never
  join this one; and a `Transfer-Encoding` this server does not implement is a
  `501`, not an absent length.
- **Time.** The request line and headers must arrive within `header_timeout`
  (default 10 s), the declared body within `body_timeout` (default 30 s), both
  answered `408` when missed; the response must be taken within `write_timeout`
  (default 30 s) or the connection is dropped. These are deadlines on the whole
  read, not idle timeouts, so a slow-loris trickle of one byte at a time is cut off
  on schedule.
- **Connections.** At most `max_connections` (default 256) are served at once. One
  past the cap is answered `503` with `Retry-After: 1` without its request being
  handled, then closed after draining what it sent, so the answer arrives instead of
  a reset.
- **The target is decoded as bytes, and a malformed escape is a `400`.** `%` must be
  followed by two hex digits (`%`, `%4`, `%zz` and `%+1` are refused, never guessed
  at), and the decoded bytes must be UTF-8. The **path** is split on `/` first and
  each segment decoded on its own, so an encoded `%2F` is data inside its segment
  and never a separator (RFC 3986): `/k/a%2Fb` is the IRI `urn:k:a/b`, and a client
  cannot add a segment by encoding one. A `+` in the path is a `+`. Only the
  **query** is form-encoded, so there `+` is a space.

The point of refusing rather than trimming is that an endpoint cannot tell a
truncated submission from a complete one — so a bound that silently shortens input
turns a rejected request into an accepted, wrong one.

### TLS terminates at the proxy

`ikigai serve --http <port>` binds `127.0.0.1` and speaks **plain HTTP** — TLS is
expected to terminate at a fronting reverse proxy (Apache/Caddy/nginx) that holds
the certificate and proxies to loopback. There is no cleartext on the network (the
client↔proxy hop is HTTPS, the proxy↔ikigai hop is loopback). A full `host:port`
overrides the bind for deployments that firewall the port instead.

## The route table

The mechanical `/<noun>/<partition>/<key>` → `urn:<noun>:<partition>:<key>` mapping
handles the common case. A **route table** — the resource `urn:web:routes`, a graph
of [`ik:Route`](https://ikigai-rs.dev/ns#Route) nodes — carries the *variations*:
path patterns → IRI templates, with optional per-route capability, CORS, and CSP.
A path matching no route falls through to the mechanical default; among routes,
lowest `ik:order` wins.

Author it in Turtle, JSON-LD, YAML-LD, or plain non-LD JSON/YAML — they all
transrept to the same graph. Turtle:

```turtle
@prefix ik: <https://ikigai-rs.dev/ns#> .

<urn:web:route:scheduler> a ik:Route ;
    ik:order  10 ;
    ik:match  "/book/{host}" ;         # {var} captures one path segment (strict, below)
    ik:target "urn:schedule:{host}" ;  # …substituted into the IRI template
    ik:cap    "urn:cap:personal:calendar:read:freebusy" ;   # per-route ceiling
    ik:csp    "default-src 'self'; frame-ancestors 'none'" ;
    ik:cors   <urn:web:cors:public> ;
    ik:shape  <urn:shape:route:scheduler> .

<urn:web:cors:public> a ik:CorsPolicy ;
    ik:corsOrigin "https://sletten.com" ;
    ik:corsMaxAge 600 .
```

…the same routes, non-LD (no `@`-noise — ikigai supplies the context):

```json
{
  "routes": [
    { "id": "scheduler", "order": 10,
      "match": "/book/{host}", "target": "urn:schedule:{host}",
      "cap": ["urn:cap:personal:calendar:read:freebusy"],
      "csp": "default-src 'self'; frame-ancestors 'none'",
      "cors": { "origin": ["https://sletten.com"], "maxAge": 600 } }
  ]
}
```

```yaml
routes:
  - id: scheduler
    order: 10
    match: "/book/{host}"
    target: "urn:schedule:{host}"
    cap: [urn:cap:personal:calendar:read:freebusy]
    csp: "default-src 'self'; frame-ancestors 'none'"
    cors: { origin: [https://sletten.com], maxAge: 600 }
```

### Route variables: strict `{var}`, raw `{+var}`

A route variable captures exactly one path segment, decoded. It has two spellings,
after RFC 6570's simple and reserved expansion:

| spelling | its decoded value may carry `:` `/` `?` `#` `[` `]` `@` | use it for |
|---|---|---|
| `{var}` | **no** — the request is refused `400`, naming the variable | a name, an id, a key: anything that is one piece of an IRI |
| `{+var}` | yes, substituted as it is | a variable that IS an IRI or a path |

Those seven are RFC 3986's gen-delims: they are what give an IRI its structure. If
`/u/{name}` → `urn:user:{name}` passed them, `/u/alice:private` would address
`urn:user:alice:private` — a deeper resource than the route names, and under
`--routes-only` one that no route serves at all. Percent-encoding does not get a
delimiter past the check: `/u/alice%3Aprivate` and `/u/a%2Fb` are refused too, because
the check reads the value after decoding.

```turtle
<urn:web:route:user> a ik:Route ;
    ik:match  "/u/{name}" ;            # /u/alice → urn:user:alice; /u/alice:private → 400
    ik:target "urn:user:{name}" .

<urn:web:route:browse> a ik:Route ;
    ik:match  "/browse/{+iri}" ;       # /browse/urn:repo:x:file:src%2Flib.rs →
    ik:target "urn:page:browse:{+iri}" .  #   urn:page:browse:urn:repo:x:file:src/lib.rs
```

- **A refusal is final.** The route whose shape (segment count and literals) fits the
  path claims it; a strict refusal does not fall through to a later route or to the
  mechanical default, because either could resolve the value to some other resource.
- **Spell `{+var}` in both places.** A variable is raw only when the pattern AND the
  template say `{+var}`; a disagreement is strict.
- **`{+var}` still captures ONE segment** — an encoded `%2F` is data inside it, a raw `/`
  is a separator. It opts out of the guard above, so give it to a route only where any
  value is a resource the route means to expose (under that route's `ik:cap`).
- The template is expanded in one pass, so a captured value that reads `{other}` is data.

### Guarding the templates (injection / IDOR)

A route splices a client-controlled path segment into a resource IRI, so two
concerns need care — **IRI injection** (a capture containing `:` reaching a sibling
namespace) and **IDOR** (addressing another principal's object). A strict `{var}`
closes the structural half of injection by itself (above); a `{+var}`, and anything
finer than "no delimiters", needs the declarative defenses, which compose with the
capability model:

- **`ik:bind`** sources a template variable from the authenticated principal instead
  of the path, so an identity-owned id is never client-supplied — `/account/me` →
  `urn:account:id:{sub}` with `ik:bind [ ik:var "sub" ; ik:from "principalId" ]`
  *eliminates* IDOR for the self-object case.
- **`ik:shape`** points a route at a SHACL `NodeShape` validating the resolved
  request (its captured `{var}`s + the principal, as an `ik:RouteRequest`) through
  `urn:kernel:validate` **before dispatch** — `sh:pattern` kills injection, and a
  cross-check (`sh:equals`, or an allow-set) expresses "you may address only your
  own." The authorization becomes a shape you can read and audit.
- **`ik:cap`** is attenuated to the affordance (`…:read:freebusy`, not the whole
  calendar), so even a valid cross-object address exposes only what is meant to be
  public.

## Build

Native, opt-in behind the CLI's `web` feature (it pulls **tokio**; the default and
wasm binaries stay lean). A minimal hand-rolled HTTP/1.1 handler over tokio — the
proxy in front owns internet-hostility hardening.

## License

MIT OR Apache-2.0.
