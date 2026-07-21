# ikigai-web

The **inbound HTTP transport** for [ikigai](https://crates.io/crates/ikigai-core):
serve a kernel over HTTP. A thin adapter, not an app — it maps the HTTP request
onto a kernel `Request` and the `Representation` back onto an HTTP response, and
leaves all behaviour (scheduling, forms, policy) in resources, compositions, and
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

## The mapping

| HTTP | kernel |
|------|--------|
| `GET` / `HEAD` | `Source` |
| `PUT` / `POST` / `PATCH` | `Sink` |
| `DELETE` | `Delete` |
| `OPTIONS` | the allow-list |
| `Accept:` | the `as=` conneg target (transreptor selection) |
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
- **Typed error → status:** `Denied` → 403, `NotFound` → 404, invalid/missing arg →
  400, transient → 503, else 500.

## Conditional requests and caching

Reads project a strong **`ETag`** (a content hash) and a **`Cache-Control`**
derived from the representation's cache validity (`Never` → immutable, `At` →
`max-age`, `Always` → `no-store`). `If-None-Match` on a read yields `304`. Writes
are conditional: `If-Match` / `If-None-Match` are checked against the resource's
current ETag before the mutation (optimistic concurrency → `412`; `If-None-Match: *`
is create-only). `DELETE` is idempotent — a repeat delete of a resource we deleted
returns `204`, while one that never existed is `404`.

`PATCH` is read-modify-write through a **content-type registry**: the request
`Content-Type` selects a patch strategy (RFC 7386 JSON Merge Patch today) that
transforms the current representation before it is Sunk. An unknown patch type is
`415`.

## Edge policy

`EdgeConfig` is a safe public-edge posture by default — **strict security headers,
CORS closed, proxy not trusted**:

- **Security headers:** `Content-Security-Policy` (`default-src 'self'`;
  `frame-ancestors 'none'`; …), `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`. **HSTS rides only on an HTTPS request** — and
  HTTPS is inferred *only* from a trusted proxy's `X-Forwarded-Proto`, never from an
  untrusted client (`--trust-proxy` enables it).
- **CORS** is closed unless you allow-list origins (`--cors-origin`, or per route).
  Allowed origins are echoed with `Vary: Origin`; preflight (`OPTIONS` +
  `Access-Control-Request-Method`) advertises methods from the resource's own
  `describe()` Allow.

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
    ik:match  "/book/{host}" ;         # {var} captures one path segment
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

### Guarding the templates (injection / IDOR)

A route splices a client-controlled path segment into a resource IRI, so two
concerns need care — **IRI injection** (a capture containing `:` reaching a sibling
namespace) and **IDOR** (addressing another principal's object). The vocabulary
makes the defenses declarative, and they compose with the capability model:

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
