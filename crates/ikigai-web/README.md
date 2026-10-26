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

A mutating request (`PUT`/`POST`/`PATCH`/`DELETE`) reaches the endpoint with three arguments
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

Since core 0.1.93 the door's principal is ALSO minted into the request's capability, on
every verb, reads included (`urn:cap:principal:<iri>`, read with
`inv.capability.principal()`). That one does partition the kernel's cache per principal,
deliberately, and such an answer is sent `Cache-Control: private` with the credential
headers in `Vary`. Only an answer core can carry verbatim is minted (an absolute IRI of at
most 512 bytes with no `*`), and nothing is minted under a root capability.

### Admission before anything answers

`EdgeConfig::admit_fn` (an `AdmitFn`) sees each request before ANY answer the door gives
and may refuse it with a `Refusal` (`400`, `403`, `404`, `421` or `429`; any other status
is a `403`). That matters because three answers never reach the kernel, so a host overlay
there cannot refuse them: `OPTIONS`, the `?description` face and the push stream. A door
that refused by handing a request an empty capability still disclosed those. `None` (the
default) admits everything. The doctest on `AdmitFn` pins the behavior.

### Response headers from an endpoint

A kernel `Representation` is a media type and bytes, with nowhere to say "and set this
cookie". An endpoint that needs a response header answers an **entity envelope** instead: the
media type `application/vnd.ikigai.http-entity` (`ikigai_web::HTTP_ENTITY`), whose bytes are
header lines, an empty line, then the content, the shape of a multipart body part.
`Content-Type` is required and names the content's own type. In Rust, `ikigai_web::with_headers`
builds one (and keeps the representation's expiry and golden threads); any other language
writes the same bytes.

```text
Content-Type: application/json
Set-Cookie: session=abc; Path=/; HttpOnly; SameSite=Strict

{"signed_in":true}
```

The door serves the content with those headers, after two checks. The header must be on a
CLOSED allowlist (`EndpointHeader`), and the door must accept it
(`EdgeConfig::endpoint_headers`). Anything else is refused with `500` naming the header, never
dropped: a cookie an endpoint thinks it set and the client never got is a failure nobody would
see. A value is at most 4096 bytes of visible ASCII, space and tab, so no CR or LF can start a
header of its own.

| header | merged how |
|--------|------------|
| `Cache-Control` | replaces the value the door projects from the answer's expiry; when the request's credentials shaped the answer, `public` is dropped and `private` added |
| `Vary` | added to the names the door already varies on |
| `Set-Cookie` | one header per line; only on an answer no cache can hold (a write, or an uncacheable read), and only at a door that adds `EndpointHeader::SetCookie` (it is not in the defaults) |
| `Content-Disposition`, `Content-Language` | as given; left off a `304` |
| `Location` | makes the answer `303 See Other` (Post/Redirect/Get); only on a write's answer, and only to a same-origin relative reference: an absolute path (`/…`, never `//…`) or a query alone (`?…`, resolved against the request's own path) |

Everything else is refused: the hop-by-hop headers and the framing (`Connection`,
`Transfer-Encoding`, `Content-Length`), and every header the door owns (`ETag`, `Allow`, the
security and CORS headers). ⚠ The envelope is an HTTP concern carried through a
transport-neutral kernel, so a CLI `source`, QUIC or MCP caller sees the envelope bytes as they
are: use it on resources browsers call.

### A form POST's success page

A route can name a page IRI in `redirect` (RDF: `ik:redirect`). After a successful
plain POST's Sink, the edge answers **303 See Other** with that page's same-origin
path in `Location`, so following it or reloading the result is a GET. A request with
`HX-Request: true` keeps the endpoint's in-place answer. Other methods and routes
without `redirect` keep their existing behavior. A failed Sink or refused request
never redirects, and an endpoint's explicit `Location` keeps its outcome.

```json
{ "routes": [
  { "match": "/note", "target": "urn:note", "redirect": "urn:page:inspector" },
  { "match": "/inspect", "target": "urn:page:inspector" }
] }
```

The same field works in YAML. In Turtle, add `ik:redirect <urn:page:inspector>`
(or a string literal for a template) to the write route. Captures expand once using
the route's `{var}` / `{+var}` rules, including strict spellings in the redirect
template. For example, `"redirect": "urn:page:note:{name}"` can return to a page
route with target `urn:page:note:{name}`. Captured values are URL-encoded as single
path segments when building `Location`.

The edge prefers the first page route whose template can be inverted and whose
path routes back to the page IRI under first-match routing. Without a page route,
a `urn:` IRI can use the mechanical path (`urn:page:inspector` → `/page/inspector`),
unless `routes_only` is set. An unaddressable destination is a configuration error
(`500`) **before the Sink runs**. Redirects use the same route-table snapshot as
the write, including on a hot-reloaded door. A successful POST on a redirect route
carries `Vary: HX-Request`. Page IRIs and their captures become visible URLs; keep
personal data out of them.

Adding `Route::redirect` requires Rust callers constructing a `Route` to supply
`redirect: None` to keep the previous behavior.

### Errors as pages, and HEAD

Every refusal is a sentence. A client that names `text/html` in `Accept` and prefers it to
`text/plain` (a browser navigating) gets that sentence as a minimal, accessible HTML page
(`lang`, a title, a `main` landmark, a heading naming the status, the message escaped, no
style or script); every other client gets `text/plain` as before. Both carry `Vary: Accept`.
A door that chose `ErrorBody::Json` keeps JSON.

A door can write that page itself (ledger #2025): `EdgeConfig::error_page` takes an
`ErrorPageFn`, `Fn(&HttpRequest, &ErrorView) -> Option<String>`, shown the status, the
sentence, the typed kernel error or the admission refusal, its failure class, and whether the
browser is navigating. `Some(html)` is the body; `None` keeps the minimal page. It is asked only
for a request a browser made (it carries `Sec-Fetch-Mode`) that is not an htmx fragment request
(`HX-Request: true`), so curl, a script asking for JSON and htmx never get the door's HTML. Only
the body changes: the status and the headers (`Retry-After`, `Allow`) are the answer's own, the
door's CSP governs the page, and `Vary` also names `Sec-Fetch-Mode` and `HX-Request`. A browser
sends fetch metadata only to HTTPS or `localhost`, so a plain-`http` LAN door keeps the minimal
page.

A `HEAD` is answered with the head GET would carry (its `Content-Length` included) and no
content on every path: the adapter's answers, the admission refusal, the push stream's
refusals, every framing refusal `read_request` makes (its method is read off the raw request
line when the rest cannot be parsed), and the busy door's `503`.

### A door with its own router

A door that routes for itself (the layer host's HTTPS front, say) reads with `read_request` and
answers with `write_response` or `write_answer`, so the parsing, the bounds and the head are
this crate's in every door. Every header such a door sets on its `Response` is checked before
a byte is written, the same way an endpoint's are: a name is a token, a value (the content
type's included) is at most 4096 bytes of visible ASCII, space and tab, and the headers the
writer owns are refused (`Content-Length`, `Content-Type`, `Connection`, `Transfer-Encoding` and
the other hop-by-hop headers). A refused response is not written at all: the writer returns an
`InvalidInput` error carrying the `HeaderRefusal`, and the door decides what the client hears
(`Response::check` asks first). `write_answer` takes the request's method and answers a `HEAD`
with the head alone, as the routed adapter does.

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
| `?description` | the offered actions as a minimal OpenAPI 3.1 document: a read's inputs as query parameters, a write's as the request body. An input the IRI template BINDS from the path (`InputSource::Binding`) is already in the path asked about, and is left out |

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
- **Error bodies:** the error's message as `text/plain` by default. A door that sets
  `EdgeConfig::error_body` to `ErrorBody::Json` answers the same status with a typed
  `application/json` object instead: `kind` (core's `Error::kind()`, one stable word),
  `message` (the same text the plain body carries), and the variant's own fields
  (`name` and `detail` for an invalid argument, `name` for a missing one, `target` for an
  unresolved path, `depth` and `target` for a nesting refusal). `ikigai_web::error_json`
  renders it, so a host can produce the same body elsewhere. Refusals the edge makes on
  its own (`405`, `406`, `413`, a strict route variable's `400`) stay `text/plain`. A
  `text/plain` body is a page for a browser (see "Errors as pages, and HEAD" above).
- **A write's answer:** a `PUT`/`POST` or `DELETE` whose endpoint answers with a
  representation is `200` with it — a take returns what it took — and an empty answer
  is `204`.

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
  set a header. A type outside the declared faces is a 406 too. ⚠ The query is
  form-encoded, so a raw `+` in it is a SPACE: `?as=application/ld+json` asks for
  `application/ld json` and is refused. Write `?as=application/ld%2Bjson`.
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
is create-only). `DELETE` is idempotent — a repeat of a delete that succeeded
returns `204`, while one that never existed is `404` carrying the endpoint's message.
"A repeat" means the same path AND the same query arguments (in any order; `as` and the
provenance names do not count): one path can front many things chosen by an argument,
and a delete of one of them says nothing about the others.

`PATCH` is read-modify-write through a **content-type registry**: the request
`Content-Type` selects a patch strategy (RFC 7386 JSON Merge Patch today) that
transforms the current representation before it is Sunk. An unknown patch type is
`415`. The Sink a `PATCH` issues is stamped like every other write: it carries `received`,
`client` and `principal` (above), so a patched resource records who wrote it and when. (Before
0.1.62 it carried none of the three, and a patched resource was written anonymously.)

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
- **Bounds**: a stream holds a slot under `max_connections`; a write that stalls past
  `write_timeout` drops it; a heartbeat comment every 15 s; closed after 10 minutes with no
  event (`EventSource` reconnects and resyncs). Over HTTP/1.1 the stream is framed chunked.

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

### A door that serves HTML

One call adopts the page policy:

```rust
let config = EdgeConfig { routes, ..EdgeConfig::html_door(["https://door.example"])? };
```

- **The page CSP** (`SecurityHeaders::html_door`, `HTML_DOOR_CSP`): `default-src 'self';
  script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none';
  frame-ancestors 'none'; form-action 'self'`, so no inline script and no inline style,
  plus `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and
  `Cross-Origin-Opener-Policy: same-origin`. A route's own `csp` still replaces the CSP on
  that route. The default edge is unchanged and sends no opener policy.
- **The Origin check** (`OriginCheck`, installed as `admit_fn`): every method but `GET`,
  `HEAD` and `OPTIONS` is refused `403` when its `Origin` is not one of the door's
  CONFIGURED origins (never the request's `Host`), when `Origin` is `null` or malformed, or,
  with no `Origin`, when `Sec-Fetch-Site` is anything but `same-origin` or `none`. A write
  with neither header is not from a current browser: it is admitted when it carries no
  ambient credential, and refused when it carries a `Cookie` or an `Authorization` in any
  scheme but `Bearer`. A door with its own admission rule calls `OriginCheck::check` inside
  its own `AdmitFn`.

### Request bounds

What an anonymous client can make the server hold is bounded before it is read, and
an over-bound request is **refused rather than trimmed to fit**:

- **Headers** cap at 64 KiB → `431 Request Header Fields Too Large`.
- **Bodies** cap at `max_body_bytes` (default 1 MiB, `--max-body <bytes>`). A
  `Content-Length` above the cap is refused with `413` *without reading the body*,
  so the refusal costs nothing.
- **Framing is hyper's** (ledger #2236). A `Content-Length` that will not parse is a
  `400`, not a zero-length body; a body shorter than declared is a `400`, not a partial
  submission; bytes past `Content-Length` are the next pipelined request and never
  join this one. A **chunked** body is taken under the same cap: it is refused with
  `413` the moment it passes `max_body_bytes`, never cut to fit. A transfer coding that
  does not end in `chunked` is a `400`. A request hyper cannot parse is answered by
  hyper (`400`, `431`, `414`) and never reaches the door.
- **Time.** The request line and headers must arrive within `header_timeout`
  (default 10 s), the body within `body_timeout` (default 30 s), both
  answered `408` when missed; a write that makes no progress for `write_timeout`
  (default 30 s) drops the connection. The header and body limits are deadlines on the
  whole read, not idle timeouts, so a slow-loris trickle of one byte at a time is cut
  off on schedule.
- **Keep-alive is opt-in.** A client whose `Connection` header names `keep-alive` (a
  browser does) keeps the connection for its next request, until it idles for
  `header_timeout`, when it is closed without an answer. Any other client is answered
  `Connection: close`, one request per connection.
- **Connections.** At most `max_connections` (default 256) are served at once. One
  past the cap is answered `503` with `Retry-After: 1` without its request being
  handled, then closed after draining what it sent, so the answer arrives instead of
  a reset.
- **Per-client rates (opt-in).** `source_limits` (a `SourceLimits` of `SourceRate`
  rules, each an IRI prefix and `max` requests per `window`) counts every request to a
  governed resource by its client: the socket peer, or the `X-Forwarded-For` hop the
  proxy appended under `trust_proxy`, with an IPv6 client counted as its /64. Past the
  budget the answer is `429` with `Retry-After` and the resource does not run. The
  limiter's own table is bounded (`max_sources`, default 4096): emptied windows are
  reclaimed first, and past it a new client is refused rather than let through
  untracked.
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
