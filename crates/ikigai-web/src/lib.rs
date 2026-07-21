//! `ikigai-web` — an **inbound HTTP transport**: serve an ikigai kernel over HTTP.
//!
//! A thin adapter, not an app. One idea does the work:
//!
//! ```text
//! <METHOD> /<noun>/<partition>/<key>?<filters>
//!    →  Request(verb_of(method), urn:<noun>:<partition>:<key>, args)  under  cap_of(request)
//!    →  Representation  →  HTTP response
//! ```
//!
//! - **method ↔ verb**: GET/HEAD → `Source`, PUT/POST/PATCH → `Sink`, DELETE → `Delete`,
//!   OPTIONS → the allow-list. The allow-list and the `405` gate come from the endpoint's
//!   declared `describe().verbs` — an endpoint that declares no verbs isn't pre-empted.
//! - **path ↔ iri**: `/account/id/alice` → `urn:account:id:alice` (singular noun, partition
//!   key baked in) is the mechanical default; a [`RouteTable`] carries the *variations* —
//!   path patterns → IRI templates with optional per-route capability / CORS / CSP.
//! - **Accept ↔ conneg**: the `Accept` header drives the `as=` transreptor selection.
//! - **query + body → inputs**: query params become inspectable request args; a write's body
//!   is the piped `content`, with the request Content-Type surfaced as `content-type`.
//! - **PATCH is read-modify-write**: the request Content-Type selects a strategy from a
//!   registry (RFC 7386 JSON Merge Patch today) that transforms the current representation
//!   before it is Sunk; conditional (`If-Match`) writes get optimistic-concurrency (→412).
//! - **`cap_of(request)` is the multi-tenant door** — every request resolves under a
//!   capability derived from its identity. A public default (or a fixed `--cap` ceiling that
//!   narrows the edge); a per-user capability (magic-link / passkey) fills the same seam later.
//! - **typed error → status**: `Denied`→403, invalid/missing arg→400, transient→503, else 500.
//!
//! App logic — scheduling, forms, policy — stays in resources, compositions, and
//! capabilities *above* this transport, exactly as the other transports (quic/ipc/mcp) keep
//! the kernel's behaviour out of the wire layer.
#![forbid(unsafe_code)]

use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request, Verb};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A parsed HTTP request — what the router and the capability function see.
pub struct HttpRequest {
    pub method: String,
    /// The decoded path, no query (e.g. `/account/id/alice`).
    pub path: String,
    /// Query pairs (filters over a partition; the partition itself is in the path).
    pub query: Vec<(String, String)>,
    /// Header names are lowercased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// A header value by (lowercase) name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Map a request → the capability it resolves under. **The multi-tenant door.** A host
/// supplies this: a public default now, an identity→capability lookup (session/passkey) later.
pub type CapFn = Arc<dyn Fn(&HttpRequest) -> Capability + Send + Sync>;

/// The S0 default: a public (empty-scope) capability for every request.
pub fn public_cap() -> CapFn {
    Arc::new(|_req| Capability::scoped(Vec::<String>::new()))
}

/// A fixed capability ceiling for every request — the `--cap` clamp. This is how the
/// public HTTP face is narrowed for the edge: a request can reach only what the ceiling
/// grants, never widening it (the same posture the QUIC server's `--cap` takes). An
/// empty `scopes` is equivalent to [`public_cap`].
pub fn fixed_cap(scopes: Vec<String>) -> CapFn {
    Arc::new(move |_req| Capability::scoped(scopes.clone()))
}

/// Edge response policy: security headers, CORS, and whether to trust a fronting proxy's
/// `X-Forwarded-*`. [`Default`] is a safe public-edge posture — strict security headers,
/// CORS **closed**, proxy **not** trusted. (Per-route policy is a later slice; this is the
/// server-wide baseline.)
#[derive(Clone)]
pub struct EdgeConfig {
    /// Trust `X-Forwarded-Proto`/`-For` from the upstream. Enable ONLY behind a proxy you
    /// control (Apache) — a direct client could otherwise spoof them.
    pub trust_proxy: bool,
    /// Outbound security headers. `None` sends none (e.g. when the fronting proxy owns them).
    pub security: Option<SecurityHeaders>,
    /// Cross-origin policy. Default = closed (no `Access-Control-Allow-Origin`).
    pub cors: CorsPolicy,
    /// The route table: path patterns → IRI templates, with optional per-route cap/CORS/CSP.
    /// Default empty → every path uses the mechanical `/noun/partition/key` → `urn:` default.
    pub routes: RouteTable,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        EdgeConfig {
            trust_proxy: false,
            security: Some(SecurityHeaders::default()),
            cors: CorsPolicy::default(),
            routes: RouteTable::default(),
        }
    }
}

/// A single route: a path pattern → an IRI template, with optional per-route overrides. The
/// pattern and template share `{var}` capture names (`/book/{host}` → `urn:schedule:{host}`).
#[derive(Clone)]
pub struct Route {
    /// Path pattern; `{var}` captures exactly one segment, a literal must match exactly.
    pub pattern: String,
    /// IRI template; each `{var}` from the pattern is substituted in.
    pub iri_template: String,
    /// Per-route capability ceiling (scopes). `None` → the server's `cap_fn` applies.
    pub cap: Option<Vec<String>>,
    /// Per-route CORS policy. `None` → the server default.
    pub cors: Option<CorsPolicy>,
    /// Per-route `Content-Security-Policy` (e.g. a looser CSP for an HTML/CoD face). `None` →
    /// the server default.
    pub csp: Option<String>,
}

/// An ordered set of [`Route`]s. **First match wins**; a path matching none falls through to
/// the mechanical `/noun/partition/key` → `urn:` default. The map carries only the *variations*
/// from that default (aliases, per-route policy) — the default handles the 90% case.
#[derive(Clone, Default)]
pub struct RouteTable {
    pub routes: Vec<Route>,
}

/// A resolved route match: the target IRI plus the per-route overrides (all owned, so it
/// threads cleanly through the async request path).
#[derive(Clone)]
struct Matched {
    iri: String,
    cap: Option<Vec<String>>,
    cors: Option<CorsPolicy>,
    csp: Option<String>,
}

impl RouteTable {
    /// A table from an ordered list of routes.
    pub fn new(routes: Vec<Route>) -> Self {
        RouteTable { routes }
    }

    /// Match `path` against the routes in order; the first hit resolves the IRI template with
    /// the captured vars and returns it with the route's overrides. `None` → fall through.
    fn match_path(&self, path: &str) -> Option<Matched> {
        let segs: Vec<&str> = path
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        for route in &self.routes {
            let pat: Vec<&str> = route
                .pattern
                .trim_matches('/')
                .split('/')
                .filter(|s| !s.is_empty())
                .collect();
            if pat.len() != segs.len() {
                continue;
            }
            let mut binds: Vec<(&str, &str)> = Vec::new();
            let mut matched = true;
            for (p, s) in pat.iter().zip(&segs) {
                if let Some(var) = p.strip_prefix('{').and_then(|v| v.strip_suffix('}')) {
                    binds.push((var, s));
                } else if p != s {
                    matched = false;
                    break;
                }
            }
            if !matched {
                continue;
            }
            let mut iri = route.iri_template.clone();
            for (var, val) in &binds {
                iri = iri.replace(&format!("{{{var}}}"), val);
            }
            return Some(Matched {
                iri,
                cap: route.cap.clone(),
                cors: route.cors.clone(),
                csp: route.csp.clone(),
            });
        }
        None
    }
}

/// Outbound security response headers. Defaults are strict — safe for an API/data face; an
/// HTML/CoD face loosens `csp` per route (a later slice). `frame-ancestors 'none'` in the
/// CSP subsumes `X-Frame-Options`.
#[derive(Clone)]
pub struct SecurityHeaders {
    /// `Content-Security-Policy`. Default locks everything to same-origin and forbids framing.
    pub csp: Option<String>,
    /// `X-Content-Type-Options: nosniff` (default on).
    pub nosniff: bool,
    /// `Referrer-Policy` (default `no-referrer`).
    pub referrer_policy: Option<String>,
    /// `Strict-Transport-Security` — emitted ONLY on an HTTPS request (per RFC 6797), which
    /// behind a trusted proxy means `X-Forwarded-Proto: https`.
    pub hsts: Option<String>,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        SecurityHeaders {
            csp: Some(
                "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
                    .to_string(),
            ),
            nosniff: true,
            referrer_policy: Some("no-referrer".to_string()),
            hsts: Some("max-age=31536000; includeSubDomains".to_string()),
        }
    }
}

/// Cross-origin resource sharing. `Default` = **closed** (no cross-origin access). Populate
/// `allowed_origins` to allow specific origins, or a single `*` for any (avoid `*` with
/// credentials — the code echoes the concrete origin in that case, per the Fetch spec).
#[derive(Clone, Default)]
pub struct CorsPolicy {
    /// Exact origins allowed (e.g. `https://app.example.com`), or a single `*`.
    pub allowed_origins: Vec<String>,
    /// Methods advertised on preflight. Empty → the resource's own `Allow` list.
    pub allowed_methods: Vec<String>,
    /// Request headers allowed on preflight. Empty → echo the requested ones.
    pub allowed_headers: Vec<String>,
    /// Send `Access-Control-Allow-Credentials: true`.
    pub allow_credentials: bool,
    /// `Access-Control-Max-Age` (preflight cache seconds); 0 → omit.
    pub max_age: u32,
}

/// Per-server state shared across connections: the kernel, the capability function, the
/// edge policy, and the tombstone ledger that makes DELETE idempotent.
struct Shared {
    kernel: Arc<Kernel>,
    cap_fn: CapFn,
    config: EdgeConfig,
    /// IRIs deleted through this server, with when — a resource we already deleted
    /// answers a repeat DELETE with 204 (idempotent) rather than 404, for a bounded
    /// window. In-process only (lost on restart); a persistent ledger is a later step.
    tombstones: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
}

/// How long a tombstone makes a repeat DELETE idempotent (204) before the resource
/// reverts to reporting 404.
const TOMBSTONE_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// Serve `kernel` over HTTP on `addr` under the default edge policy (strict security
/// headers, CORS closed, proxy not trusted). See [`serve_with`] to configure it.
pub async fn serve(kernel: Arc<Kernel>, cap_fn: CapFn, addr: SocketAddr) -> std::io::Result<()> {
    serve_with(kernel, cap_fn, addr, EdgeConfig::default()).await
}

/// Serve `kernel` over HTTP on `addr`, resolving each request under `cap_fn(request)` and
/// applying `config` (security headers, CORS, proxy trust). One request per connection
/// (`Connection: close`). Runs until the listener errors.
pub async fn serve_with(
    kernel: Arc<Kernel>,
    cap_fn: CapFn,
    addr: SocketAddr,
    config: EdgeConfig,
) -> std::io::Result<()> {
    let shared = Arc::new(Shared {
        kernel,
        cap_fn,
        config,
        tombstones: std::sync::Mutex::new(std::collections::HashMap::new()),
    });
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (sock, _) = listener.accept().await?;
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let _ = handle(sock, shared).await;
        });
    }
}

/// The response the adapter builds before writing it to the socket.
struct Resp {
    status: u16,
    reason: &'static str,
    content_type: String,
    body: Vec<u8>,
    /// The `Allow` header value (the resource's method set), when relevant.
    allow: Option<String>,
    /// A strong `ETag` (a content hash), the validity token clients revalidate against.
    etag: Option<String>,
    /// `Cache-Control`, projected from the representation's [`Expiry`](ikigai_core::Expiry).
    cache_control: Option<String>,
    /// Extra headers layered on by the edge policy (security headers, CORS).
    headers: Vec<(String, String)>,
}

impl Resp {
    /// An empty response (no body/headers) with the given status — the base every
    /// constructor fills in.
    fn status(status: u16, reason: &'static str) -> Resp {
        Resp {
            status,
            reason,
            content_type: String::new(),
            body: Vec::new(),
            allow: None,
            etag: None,
            cache_control: None,
            headers: Vec::new(),
        }
    }

    fn text(status: u16, reason: &'static str, body: &str) -> Resp {
        Resp {
            content_type: "text/plain; charset=utf-8".to_string(),
            body: body.as_bytes().to_vec(),
            ..Resp::status(status, reason)
        }
    }
}

async fn handle(mut sock: TcpStream, shared: Arc<Shared>) -> std::io::Result<()> {
    // Read up to the end of the headers (blank line).
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 64 * 1024 {
            return write(
                &mut sock,
                Resp::text(431, "Request Header Fields Too Large", ""),
            )
            .await;
        }
    };
    let mut req = match parse_head(&String::from_utf8_lossy(&buf[..header_end])) {
        Some(r) => r,
        None => {
            return write(
                &mut sock,
                Resp::text(400, "Bad Request", "malformed request"),
            )
            .await
        }
    };
    // Read the body up to Content-Length (bounded).
    let cl: usize = req
        .header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < cl {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
        if body.len() > 1024 * 1024 {
            break;
        }
    }
    req.body = body;

    // Resolve the route once; it drives the target IRI + per-route cap (in respond) and the
    // per-route CORS/CSP (in the policy layer). No match → the mechanical default throughout.
    let matched = shared.config.routes.match_path(&req.path);
    let mut resp = respond(&shared, &req, matched.as_ref()).await;
    apply_edge_policy(&mut resp, &shared.config, &req, matched.as_ref());
    write(&mut sock, resp).await
}

/// The core adapter: method → verb (gated by `describe().verbs`), path → iri,
/// query → args, body → piped `content`, Accept → conneg, resolved under the cap.
async fn respond(shared: &Shared, req: &HttpRequest, matched: Option<&Matched>) -> Resp {
    let kernel = &shared.kernel;
    let cap_fn = &shared.cap_fn;
    // A matched route supplies the target IRI (from its template); otherwise the mechanical
    // `/noun/partition/key` → `urn:` default.
    let iri_str = match matched {
        Some(m) => m.iri.clone(),
        None => iri_from_path(&req.path),
    };
    let iri = match Iri::parse(&iri_str) {
        Ok(i) => i,
        Err(_) => return Resp::text(400, "Bad Request", "not a resource path"),
    };

    // Declared verbs drive the Allow list and the 405 gate. An endpoint that declares
    // NO verbs (or an unknown IRI) is not pre-empted — resolution runs and the
    // kernel/endpoint reports the outcome. Declare verbs for a precise OPTIONS/405.
    let described = kernel.describe(&iri);
    let declared: &[Verb] = described
        .as_ref()
        .map(|d| d.verbs.as_slice())
        .unwrap_or(&[]);
    let allow = allow_header(declared);

    if req.method == "OPTIONS" {
        return Resp {
            allow: Some(allow),
            ..Resp::status(204, "No Content")
        };
    }

    let verb = match verb_for_method(&req.method) {
        Some(v) => v,
        None => return method_not_allowed(allow),
    };
    if !declared.is_empty() && !declared.contains(&verb) {
        return method_not_allowed(allow);
    }

    // Build the request. Query params are inspectable inputs (filters/data) the
    // composition can read; a write verb carries the body as the piped `content`,
    // with the request Content-Type surfaced as `content-type`.
    let mut request = Request::new(verb, iri.clone());
    if let Some(accept) = req.header("accept") {
        let media = first_media(accept);
        if !media.is_empty() && media != "*/*" {
            request = request.with_arg("as", ArgRef::Inline(media.into_bytes()));
        }
    }
    for (k, v) in &req.query {
        if k != "as" && k != "content" {
            request = request.with_arg(k.clone(), ArgRef::Inline(v.clone().into_bytes()));
        }
    }
    if verb == Verb::Sink {
        request = request.with_arg("content", ArgRef::Inline(req.body.clone()));
        if let Some(ct) = req.header("content-type") {
            request = request.with_arg("content-type", ArgRef::Inline(ct.as_bytes().to_vec()));
        }
    }

    // A matched route may pin a per-route capability ceiling (the multi-tenant seam);
    // otherwise the server-wide `cap_fn` applies.
    let cap = match matched.and_then(|m| m.cap.as_ref()) {
        Some(scopes) => Capability::scoped(scopes.clone()),
        None => cap_fn(req),
    };

    // Write-side preconditions (optimistic concurrency): If-Match / If-None-Match are
    // checked against the resource's CURRENT ETag before the mutation runs — a lost-update
    // guard for Sink and a conditional guard for Delete. Failing → 412 (or 403 if the cap
    // can't even read to check). Reads carry no precondition here (304 is handled below).
    if verb.is_mutating() && has_precondition(req) {
        if let Some(resp) = check_write_precondition(kernel, &iri, &cap, req).await {
            return resp;
        }
    }

    // PATCH is read-modify-write: the request Content-Type selects a patch strategy from
    // the registry, which transforms the current representation before it is Sunk.
    if req.method == "PATCH" {
        return apply_patch(kernel, &iri, &cap, req).await;
    }

    match kernel.issue(request, &cap).await {
        // Reads project a strong ETag + Cache-Control and honour `If-None-Match` (→304).
        Ok(repr) if verb == Verb::Source => read_resp(&req.method, req, repr),
        Ok(repr) if verb == Verb::Delete => {
            record_tombstone(shared, &iri_str);
            write_resp(verb, repr)
        }
        Ok(repr) => write_resp(verb, repr),
        // A DELETE of an already-absent resource is idempotent (204) within the tombstone
        // window; otherwise it's a genuine 404.
        Err(ikigai_core::Error::NotFound(_)) if verb == Verb::Delete => {
            if tombstoned(shared, &iri_str) {
                Resp::status(204, "No Content")
            } else {
                Resp::text(404, "Not Found", "not found")
            }
        }
        Err(e) => error_resp(&e),
    }
}

/// Whether the request carries a write precondition header.
fn has_precondition(req: &HttpRequest) -> bool {
    req.header("if-match").is_some() || req.header("if-none-match").is_some()
}

/// A patch strategy: transform the current representation's bytes with the patch body →
/// the new bytes (or a reason it couldn't).
type PatchStrategy = fn(&[u8], &[u8]) -> Result<Vec<u8>, String>;

/// The PATCH content-type registry: request `Content-Type` → a patch strategy, extensible
/// per media type. Today RFC 7386 JSON Merge Patch; json-patch (RFC 6902), SPARQL Update,
/// LDP, and Solid PATCH are future registry entries (some routed through kernel resources).
fn patch_strategy(content_type: &str) -> Option<PatchStrategy> {
    match content_type {
        "application/merge-patch+json" => Some(merge_patch_json),
        _ => None,
    }
}

/// PATCH = read-modify-write. Select a strategy by `Content-Type` (unknown → 415), Source
/// the current representation (absent → 404, denied → 403), apply the patch (malformed →
/// 422), and Sink the result — returning it with a fresh `ETag` for chained updates.
async fn apply_patch(kernel: &Kernel, iri: &Iri, cap: &Capability, req: &HttpRequest) -> Resp {
    let ct = req
        .header("content-type")
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    let strategy = match patch_strategy(ct) {
        Some(s) => s,
        None => {
            return Resp::text(
                415,
                "Unsupported Media Type",
                "no patch strategy for this Content-Type",
            )
        }
    };
    let current = match kernel
        .issue(Request::new(Verb::Source, iri.clone()), cap)
        .await
    {
        Ok(repr) => repr,
        Err(e) => return error_resp(&e), // NotFound → 404, Denied → 403
    };
    let patched = match strategy(&current.bytes, &req.body) {
        Ok(bytes) => bytes,
        Err(detail) => return Resp::text(422, "Unprocessable Content", &detail),
    };
    let sink = Request::new(Verb::Sink, iri.clone())
        .with_arg("content", ArgRef::Inline(patched))
        .with_arg(
            "content-type",
            ArgRef::Inline(media_type_of(&current).into_bytes()),
        );
    match kernel.issue(sink, cap).await {
        Ok(repr) if repr.bytes.is_empty() => Resp::status(204, "No Content"),
        Ok(repr) => {
            let etag = etag_of(&repr);
            Resp {
                content_type: media_type_of(&repr),
                body: repr.bytes,
                etag: Some(etag),
                ..Resp::status(200, "OK")
            }
        }
        Err(e) => error_resp(&e),
    }
}

/// RFC 7386 JSON Merge Patch: recursively merge the patch object into the current value;
/// a `null` value deletes that key; a non-object patch replaces the target wholesale.
fn merge_patch_json(current: &[u8], patch: &[u8]) -> Result<Vec<u8>, String> {
    let mut target: serde_json::Value = if current.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(current).map_err(|e| format!("current is not JSON: {e}"))?
    };
    let patch: serde_json::Value =
        serde_json::from_slice(patch).map_err(|e| format!("patch is not JSON: {e}"))?;
    merge_json(&mut target, &patch);
    serde_json::to_vec(&target).map_err(|e| e.to_string())
}

/// The recursive core of RFC 7386.
fn merge_json(target: &mut serde_json::Value, patch: &serde_json::Value) {
    use serde_json::Value;
    if let Value::Object(patch_map) = patch {
        if !target.is_object() {
            *target = Value::Object(serde_json::Map::new());
        }
        let tmap = target.as_object_mut().expect("just set to object");
        for (k, v) in patch_map {
            if v.is_null() {
                tmap.remove(k);
            } else {
                merge_json(tmap.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
    } else {
        *target = patch.clone();
    }
}

/// Check `If-Match` / `If-None-Match` against the resource's current state (fetched via
/// `Source` under the same cap). Returns `Some(resp)` to short-circuit (412/403), or
/// `None` if the precondition holds and the write should proceed.
async fn check_write_precondition(
    kernel: &Kernel,
    iri: &Iri,
    cap: &Capability,
    req: &HttpRequest,
) -> Option<Resp> {
    // Current state: Some(etag) if it exists and is readable, None if absent.
    let current = match kernel
        .issue(Request::new(Verb::Source, iri.clone()), cap)
        .await
    {
        Ok(repr) => Some(etag_of(&repr)),
        Err(ikigai_core::Error::NotFound(_)) => None,
        // Can't read to verify (denied) — surface that rather than guessing.
        Err(ikigai_core::Error::Denied(m)) => {
            return Some(error_resp(&ikigai_core::Error::Denied(m)))
        }
        // Any other read failure: treat as "can't confirm existence" → absent.
        Err(_) => None,
    };
    let failed = |detail: &str| Some(Resp::text(412, "Precondition Failed", detail));

    // If-Match: the resource must exist and (for a list) match. `*` = must exist.
    if let Some(im) = req.header("if-match") {
        match &current {
            Some(etag) if im.trim() == "*" || etag_list_contains(im, etag) => {}
            _ => return failed("if-match precondition failed"),
        }
    }
    // If-None-Match: `*` = must NOT exist (create-only); a list must NOT match.
    if let Some(inm) = req.header("if-none-match") {
        let hit = match &current {
            Some(etag) => inm.trim() == "*" || etag_list_contains(inm, etag),
            None => false,
        };
        if hit {
            return failed("if-none-match precondition failed");
        }
    }
    None
}

/// Whether a comma-separated ETag list contains the given (strong) validator, ignoring
/// any `W/` weakness prefix (we only mint strong tags).
fn etag_list_contains(header: &str, etag: &str) -> bool {
    let bare = etag.trim_start_matches("W/");
    header
        .split(',')
        .any(|tok| tok.trim().trim_start_matches("W/") == bare)
}

/// Record that we deleted `iri`, so a repeat DELETE is idempotent for a bounded window.
fn record_tombstone(shared: &Shared, iri: &str) {
    if let Ok(mut t) = shared.tombstones.lock() {
        t.insert(iri.to_string(), std::time::Instant::now());
    }
}

/// Whether `iri` has a live (unexpired) tombstone — i.e. we deleted it recently.
/// Prunes the entry when it has aged past the TTL.
fn tombstoned(shared: &Shared, iri: &str) -> bool {
    if let Ok(mut t) = shared.tombstones.lock() {
        if let Some(at) = t.get(iri) {
            if at.elapsed() < TOMBSTONE_TTL {
                return true;
            }
            t.remove(iri);
        }
    }
    false
}

/// A `405` carrying the resource's `Allow` list.
fn method_not_allowed(allow: String) -> Resp {
    Resp {
        allow: Some(allow),
        ..Resp::text(405, "Method Not Allowed", "method not allowed")
    }
}

/// A read response: 200 with the representation + a strong `ETag` and a projected
/// `Cache-Control`; `304 Not Modified` (headers only) when `If-None-Match` matches;
/// HEAD carries the same headers with no body.
fn read_resp(method: &str, req: &HttpRequest, repr: ikigai_core::Representation) -> Resp {
    let etag = etag_of(&repr);
    let cc = cache_control_of(repr.expiry);
    if let Some(inm) = req.header("if-none-match") {
        if if_none_match_hit(inm, &etag) {
            return Resp {
                etag: Some(etag),
                cache_control: cc,
                ..Resp::status(304, "Not Modified")
            };
        }
    }
    let head_only = method == "HEAD";
    Resp {
        content_type: media_type_of(&repr),
        body: if head_only { Vec::new() } else { repr.bytes },
        etag: Some(etag),
        cache_control: cc,
        ..Resp::status(200, "OK")
    }
}

/// A write response: DELETE, or a Sink returning no body → 204; otherwise 200 with
/// whatever representation the write produced.
fn write_resp(verb: Verb, repr: ikigai_core::Representation) -> Resp {
    if verb == Verb::Delete || (verb == Verb::Sink && repr.bytes.is_empty()) {
        return Resp::status(204, "No Content");
    }
    Resp {
        content_type: media_type_of(&repr),
        body: repr.bytes,
        ..Resp::status(200, "OK")
    }
}

/// A strong ETag: a content hash over the representation's type + bytes (quoted, per
/// RFC 9110). Changes iff the representation's content changes.
fn etag_of(repr: &ikigai_core::Representation) -> String {
    let mut h = blake3::Hasher::new();
    h.update(repr.repr_type.canonical().as_bytes());
    h.update(&[0]); // domain separator between type and body
    h.update(&repr.bytes);
    format!("\"{}\"", h.finalize().to_hex())
}

/// `Cache-Control`, projected from the representation's cache validity:
/// `Never` → long-lived immutable; `At(deadline)` → `max-age` until it (or revalidate
/// if already past); `Always` (the volatile default) → `no-store`.
fn cache_control_of(expiry: ikigai_core::Expiry) -> Option<String> {
    use ikigai_core::Expiry;
    match expiry {
        Expiry::Always => Some("no-store".to_string()),
        Expiry::Never => Some("public, max-age=31536000, immutable".to_string()),
        Expiry::At(deadline) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            if deadline.as_millis() > now {
                Some(format!(
                    "public, max-age={}",
                    (deadline.as_millis() - now) / 1000
                ))
            } else {
                Some("no-cache".to_string())
            }
        }
    }
}

/// Whether an `If-None-Match` header matches the current ETag (`*` matches any existing
/// representation; otherwise a comma-separated list of validators). Weak-compares by
/// ignoring a `W/` prefix, since we only mint strong tags.
fn if_none_match_hit(header: &str, etag: &str) -> bool {
    let bare = etag.trim_start_matches("W/");
    header.split(',').any(|tok| {
        let t = tok.trim();
        t == "*" || t.trim_start_matches("W/") == bare
    })
}

/// The HTTP methods a resource offers, from its declared verbs. An endpoint that
/// declares no verbs falls back to the conservative read set (it isn't gated, but
/// OPTIONS can't enumerate what wasn't declared). HEAD rides with GET; OPTIONS always.
fn allow_header(verbs: &[Verb]) -> String {
    if verbs.is_empty() {
        return "GET, HEAD, OPTIONS".to_string();
    }
    let mut methods: Vec<&str> = Vec::new();
    if verbs.contains(&Verb::Source) {
        methods.push("GET");
        methods.push("HEAD");
    }
    if verbs.contains(&Verb::Sink) {
        methods.push("POST");
        methods.push("PUT");
        methods.push("PATCH");
    }
    if verbs.contains(&Verb::Delete) {
        methods.push("DELETE");
    }
    methods.push("OPTIONS");
    methods.join(", ")
}

/// The kernel verb an HTTP method maps to. `None` for OPTIONS (handled specially) and
/// for methods the transport doesn't support (→ 405).
fn verb_for_method(method: &str) -> Option<Verb> {
    match method {
        "GET" | "HEAD" => Some(Verb::Source),
        "PUT" | "POST" | "PATCH" => Some(Verb::Sink),
        "DELETE" => Some(Verb::Delete),
        _ => None,
    }
}

/// Map a typed kernel error onto an HTTP status. (NotFound→404 lands when the host links
/// ikigai-core ≥0.1.47; for now a missing resource surfaces as the endpoint's own error.)
fn error_resp(e: &ikigai_core::Error) -> Resp {
    use ikigai_core::Error;
    let (status, reason) = match e {
        Error::Denied(_) => (403, "Forbidden"),
        Error::NotFound(_) => (404, "Not Found"),
        Error::MissingArgument(_) | Error::InvalidArgument { .. } => (400, "Bad Request"),
        _ if e.is_transient() => (503, "Service Unavailable"),
        _ => (500, "Internal Server Error"),
    };
    Resp::text(status, reason, &format!("{e}"))
}

/// Layer the edge policy onto every response: security headers, and CORS headers when the
/// request's `Origin` is allowed. HSTS rides only on an HTTPS request (via a trusted proxy's
/// `X-Forwarded-Proto`). Applied uniformly in `handle`, so it covers 2xx, 4xx, and 5xx alike.
fn apply_edge_policy(
    resp: &mut Resp,
    config: &EdgeConfig,
    req: &HttpRequest,
    matched: Option<&Matched>,
) {
    // A matched route may override the CSP (e.g. a looser one for an HTML/CoD face) and the
    // CORS policy; otherwise the server-wide defaults apply.
    let csp_override = matched.and_then(|m| m.csp.as_deref());
    let cors = matched
        .and_then(|m| m.cors.as_ref())
        .unwrap_or(&config.cors);

    if let Some(sec) = &config.security {
        if let Some(csp) = csp_override.or(sec.csp.as_deref()) {
            resp.headers
                .push(("Content-Security-Policy".to_string(), csp.to_string()));
        }
        if sec.nosniff {
            resp.headers
                .push(("X-Content-Type-Options".to_string(), "nosniff".to_string()));
        }
        if let Some(rp) = &sec.referrer_policy {
            resp.headers
                .push(("Referrer-Policy".to_string(), rp.clone()));
        }
        if let Some(hsts) = &sec.hsts {
            if request_is_https(config, req) {
                resp.headers
                    .push(("Strict-Transport-Security".to_string(), hsts.clone()));
            }
        }
    }

    // CORS: only when the request carries an Origin the (effective) policy allows.
    let Some(origin) = req.header("origin") else {
        return;
    };
    let Some(allow_origin) = cors_allow_origin(cors, origin) else {
        return; // origin not allowed → no CORS headers (the browser blocks it)
    };
    resp.headers
        .push(("Access-Control-Allow-Origin".to_string(), allow_origin));
    resp.headers
        .push(("Vary".to_string(), "Origin".to_string()));
    if cors.allow_credentials {
        resp.headers.push((
            "Access-Control-Allow-Credentials".to_string(),
            "true".to_string(),
        ));
    }
    // Preflight (OPTIONS carrying Access-Control-Request-Method) gets the method/header lists.
    let is_preflight =
        req.method == "OPTIONS" && req.header("access-control-request-method").is_some();
    if is_preflight {
        let methods = if cors.allowed_methods.is_empty() {
            resp.allow.clone().unwrap_or_default()
        } else {
            cors.allowed_methods.join(", ")
        };
        if !methods.is_empty() {
            resp.headers
                .push(("Access-Control-Allow-Methods".to_string(), methods));
        }
        let headers = if config.cors.allowed_headers.is_empty() {
            req.header("access-control-request-headers")
                .unwrap_or("")
                .to_string()
        } else {
            cors.allowed_headers.join(", ")
        };
        if !headers.is_empty() {
            resp.headers
                .push(("Access-Control-Allow-Headers".to_string(), headers));
        }
        if cors.max_age > 0 {
            resp.headers.push((
                "Access-Control-Max-Age".to_string(),
                cors.max_age.to_string(),
            ));
        }
    }
}

/// Whether the request arrived over HTTPS — true only when a trusted proxy says so via
/// `X-Forwarded-Proto: https` (we never infer it from an untrusted client).
fn request_is_https(config: &EdgeConfig, req: &HttpRequest) -> bool {
    config.trust_proxy
        && req
            .header("x-forwarded-proto")
            .map(|p| p.eq_ignore_ascii_case("https"))
            .unwrap_or(false)
}

/// The `Access-Control-Allow-Origin` value for an origin, or `None` if disallowed. `*`
/// allows any, but with credentials the concrete origin is echoed instead (per the spec,
/// `*` is invalid with credentials).
fn cors_allow_origin(cors: &CorsPolicy, origin: &str) -> Option<String> {
    if cors.allowed_origins.iter().any(|o| o == origin) {
        return Some(origin.to_string());
    }
    if cors.allowed_origins.iter().any(|o| o == "*") {
        return Some(if cors.allow_credentials {
            origin.to_string()
        } else {
            "*".to_string()
        });
    }
    None
}

/// `/account/id/alice` → `urn:account:id:alice` (singular noun, partition key baked in).
fn iri_from_path(path: &str) -> String {
    let joined = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(":");
    format!("urn:{joined}")
}

/// The first media type in an `Accept` header (ignoring q-values, for now).
fn first_media(accept: &str) -> String {
    accept
        .split(',')
        .next()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

/// The representation's media type as a header value.
fn media_type_of(repr: &ikigai_core::Representation) -> String {
    repr.repr_type.to_string()
}

/// Parse the request line + headers (body is read separately). Header names are lowercased.
fn parse_head(head: &str) -> Option<HttpRequest> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?;
    let (raw_path, query_str) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };
    let path = urldecode(raw_path);
    let query = query_str
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (urldecode(k), urldecode(v))
        })
        .collect();
    let headers = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        })
        .collect();
    Some(HttpRequest {
        method,
        path,
        query,
        headers,
        body: Vec::new(),
    })
}

/// Minimal percent-decoding (`%XX` and `+`→space in query values).
fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(b);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Write the response and close the connection.
async fn write(sock: &mut TcpStream, resp: Resp) -> std::io::Result<()> {
    let mut head = format!("HTTP/1.1 {} {}\r\n", resp.status, resp.reason);
    if !resp.content_type.is_empty() {
        head.push_str(&format!("Content-Type: {}\r\n", resp.content_type));
    }
    if let Some(allow) = resp.allow {
        head.push_str(&format!("Allow: {allow}\r\n"));
    }
    if let Some(etag) = resp.etag {
        head.push_str(&format!("ETag: {etag}\r\n"));
    }
    if let Some(cc) = resp.cache_control {
        head.push_str(&format!("Cache-Control: {cc}\r\n"));
    }
    for (name, value) in &resp.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
    head.push_str("Connection: close\r\n\r\n");
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(&resp.body).await?;
    sock.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::{
        Description, EndpointSpace, Error, Exact, FnEndpoint, Invocation, ReprType, Representation,
    };
    use std::sync::Arc;

    // A kernel exercising the verbs: a Source-only resource, a cap-denied one, a
    // Sink that echoes its piped `content`, a Source that echoes a query arg, and a
    // Delete. Verbs are declared so the Allow list and the 405 gate are exercised.
    fn test_kernel() -> Arc<Kernel> {
        let hello = FnEndpoint::new("hello", |_inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain").with_param("charset", "utf-8"),
                b"hi".to_vec(),
            ))
        })
        .with_description(Description::new("hello").verb(Verb::Source));
        let guarded = FnEndpoint::new("guarded", |inv: &Invocation<'_>| {
            if !inv.capability.allows("urn:cap:test") {
                return Err(Error::Denied("needs urn:cap:test".into()));
            }
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"secret".to_vec(),
            ))
        });
        // A writer: echoes the piped `content` back (declares Sink).
        let writable = FnEndpoint::new("writable", |inv: &Invocation<'_>| {
            let body = inv.inline_arg("content").unwrap_or(b"");
            Ok(Representation::new(
                ReprType::new("text/plain"),
                body.to_vec(),
            ))
        })
        .with_description(Description::new("writable").verb(Verb::Sink));
        // A reader echoing a query arg (params are inspectable inputs).
        let echo = FnEndpoint::new("echo", |inv: &Invocation<'_>| {
            let name = inv.inline_str("name").unwrap_or("");
            Ok(Representation::new(
                ReprType::new("text/plain"),
                name.as_bytes().to_vec(),
            ))
        })
        .with_description(Description::new("echo").verb(Verb::Source));
        // A deletable resource (declares Delete).
        let deletable = FnEndpoint::new("deletable", |_inv: &Invocation<'_>| {
            Ok(Representation::new(ReprType::new("text/plain"), Vec::new()))
        })
        .with_description(Description::new("deletable").verb(Verb::Delete));
        // A permanently-cacheable resource (Expiry::Never → immutable Cache-Control).
        let cacheable = FnEndpoint::new("cacheable", |_inv: &Invocation<'_>| {
            Ok(Representation::new(ReprType::new("text/plain"), b"stable".to_vec()).cacheable())
        })
        .with_description(Description::new("cacheable").verb(Verb::Source));
        // A bound endpoint reporting the resource is absent (Error::NotFound → 404).
        let missing = FnEndpoint::new("missing", |_inv: &Invocation<'_>| {
            Err(Error::NotFound("no such thing".into()))
        })
        .with_description(Description::new("missing").verb(Verb::Source));
        // A read-write doc: Source returns a fixed "v1"; Sink echoes the body. Declares
        // Source+Sink, so conditional writes can read its current ETag.
        let doc = FnEndpoint::new("doc", |inv: &Invocation<'_>| {
            if inv.request.verb == Verb::Source {
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"v1".to_vec(),
                ))
            } else {
                let body = inv.inline_arg("content").unwrap_or(b"v1");
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    body.to_vec(),
                ))
            }
        })
        .with_description(Description::new("doc").verb(Verb::Source).verb(Verb::Sink));
        // An absent-but-writable resource: Source → NotFound, Sink → Ok (create).
        let newdoc = FnEndpoint::new("newdoc", |inv: &Invocation<'_>| {
            if inv.request.verb == Verb::Source {
                Err(Error::NotFound("not yet".into()))
            } else {
                Ok(Representation::new(ReprType::new("text/plain"), Vec::new()))
            }
        })
        .with_description(
            Description::new("newdoc")
                .verb(Verb::Source)
                .verb(Verb::Sink),
        );
        // A resource that exists once: first Delete succeeds, later Deletes → NotFound.
        let present = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let vanishing = FnEndpoint::new("vanishing", move |_inv: &Invocation<'_>| {
            if present.swap(false, std::sync::atomic::Ordering::SeqCst) {
                Ok(Representation::new(ReprType::new("text/plain"), Vec::new()))
            } else {
                Err(Error::NotFound("already gone".into()))
            }
        })
        .with_description(Description::new("vanishing").verb(Verb::Delete));
        // A resource that never existed: Delete always → NotFound.
        let ghost = FnEndpoint::new("ghost", |_inv: &Invocation<'_>| {
            Err(Error::NotFound("never here".into()))
        })
        .with_description(Description::new("ghost").verb(Verb::Delete));
        // A JSON doc for PATCH: Source → {"a":1,"b":2}; Sink echoes the (patched) body.
        let jdoc = FnEndpoint::new("jdoc", |inv: &Invocation<'_>| {
            if inv.request.verb == Verb::Source {
                Ok(Representation::new(
                    ReprType::new("application/json"),
                    br#"{"a":1,"b":2}"#.to_vec(),
                ))
            } else {
                let body = inv.inline_arg("content").unwrap_or(b"");
                Ok(Representation::new(
                    ReprType::new("application/json"),
                    body.to_vec(),
                ))
            }
        })
        .with_description(Description::new("jdoc").verb(Verb::Source).verb(Verb::Sink));
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:test:id:hello"), hello)
            .bind(Exact::new("urn:test:guarded"), guarded)
            .bind(Exact::new("urn:test:writable"), writable)
            .bind(Exact::new("urn:test:echo"), echo)
            .bind(Exact::new("urn:test:deletable"), deletable)
            .bind(Exact::new("urn:test:cacheable"), cacheable)
            .bind(Exact::new("urn:test:missing"), missing)
            .bind(Exact::new("urn:test:doc"), doc)
            .bind(Exact::new("urn:test:newdoc"), newdoc)
            .bind(Exact::new("urn:test:vanishing"), vanishing)
            .bind(Exact::new("urn:test:ghost"), ghost)
            .bind(Exact::new("urn:test:jdoc"), jdoc);
        Arc::new(Kernel::new(Arc::new(space)))
    }

    // Drive one request through the socket and return the raw response.
    async fn roundtrip(addr: SocketAddr, raw: &str) -> String {
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(raw.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    async fn start() -> SocketAddr {
        start_with(EdgeConfig::default()).await
    }

    async fn start_with(config: EdgeConfig) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener); // free the port for serve() to rebind (racy but fine for a test)
        let kernel = test_kernel();
        tokio::spawn(async move {
            let _ = serve_with(kernel, public_cap(), addr, config).await;
        });
        // give serve() a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        addr
    }

    #[tokio::test]
    async fn get_maps_path_to_urn_and_returns_the_representation() {
        let addr = start().await;
        let resp = roundtrip(addr, "GET /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.contains("Content-Type: text/plain"), "got: {resp}");
        assert!(
            resp.ends_with("hi"),
            "body should be the representation, got: {resp}"
        );
    }

    #[tokio::test]
    async fn head_returns_headers_no_body() {
        let addr = start().await;
        let resp = roundtrip(addr, "HEAD /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(
            resp.contains("Content-Length: 0"),
            "HEAD has no body, got: {resp}"
        );
        assert!(!resp.ends_with("hi"));
    }

    #[tokio::test]
    async fn a_denied_resource_is_403() {
        let addr = start().await;
        let resp = roundtrip(addr, "GET /test/guarded HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 403 Forbidden"), "got: {resp}");
    }

    #[tokio::test]
    async fn an_unsupported_method_is_405_with_allow() {
        let addr = start().await;
        let resp = roundtrip(addr, "PUT /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(
            resp.starts_with("HTTP/1.1 405 Method Not Allowed"),
            "got: {resp}"
        );
        assert!(resp.contains("Allow: GET, HEAD, OPTIONS"), "got: {resp}");
    }

    #[tokio::test]
    async fn options_lists_the_allowed_methods() {
        let addr = start().await;
        let resp = roundtrip(addr, "OPTIONS /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 204"), "got: {resp}");
        assert!(resp.contains("Allow: GET, HEAD, OPTIONS"), "got: {resp}");
    }

    #[test]
    fn path_maps_to_partitioned_urn() {
        assert_eq!(iri_from_path("/account/id/alice"), "urn:account:id:alice");
        assert_eq!(
            iri_from_path("/account/status/new"),
            "urn:account:status:new"
        );
    }

    #[tokio::test]
    async fn put_writes_the_body_as_piped_content() {
        let addr = start().await;
        let resp = roundtrip(
            addr,
            "PUT /test/writable HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.ends_with("hello"), "body should echo, got: {resp}");
    }

    #[tokio::test]
    async fn query_params_are_visible_as_args() {
        let addr = start().await;
        let resp = roundtrip(
            addr,
            "GET /test/echo?name=priya HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.ends_with("priya"), "arg should echo, got: {resp}");
    }

    #[tokio::test]
    async fn delete_returns_204() {
        let addr = start().await;
        let resp = roundtrip(addr, "DELETE /test/deletable HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 204 No Content"), "got: {resp}");
    }

    #[tokio::test]
    async fn options_reflects_declared_verbs() {
        let addr = start().await;
        // writable declares Sink → POST/PUT/PATCH offered, plus OPTIONS.
        let resp = roundtrip(addr, "OPTIONS /test/writable HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 204"), "got: {resp}");
        assert!(
            resp.contains("Allow: POST, PUT, PATCH, OPTIONS"),
            "got: {resp}"
        );
    }

    #[tokio::test]
    async fn a_declared_verb_gap_is_405() {
        let addr = start().await;
        // writable declares Sink only → GET is not offered.
        let resp = roundtrip(addr, "GET /test/writable HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(
            resp.starts_with("HTTP/1.1 405 Method Not Allowed"),
            "got: {resp}"
        );
        assert!(
            resp.contains("Allow: POST, PUT, PATCH, OPTIONS"),
            "got: {resp}"
        );
    }

    // Pull the ETag value out of a raw response.
    fn etag_of_response(resp: &str) -> String {
        resp.lines()
            .find_map(|l| l.strip_prefix("ETag: "))
            .unwrap_or("")
            .trim()
            .to_string()
    }

    #[tokio::test]
    async fn a_read_carries_an_etag_and_conditional_get_is_304() {
        let addr = start().await;
        let first = roundtrip(addr, "GET /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let etag = etag_of_response(&first);
        assert!(
            etag.starts_with('"'),
            "expected a strong ETag, got: {first}"
        );
        let again = roundtrip(
            addr,
            &format!("GET /test/id/hello HTTP/1.1\r\nHost: x\r\nIf-None-Match: {etag}\r\n\r\n"),
        )
        .await;
        assert!(
            again.starts_with("HTTP/1.1 304 Not Modified"),
            "got: {again}"
        );
        assert!(again.contains("Content-Length: 0"), "got: {again}");
        assert!(!again.ends_with("hi"), "304 has no body, got: {again}");
    }

    #[tokio::test]
    async fn if_none_match_star_is_304_when_present() {
        let addr = start().await;
        let resp = roundtrip(
            addr,
            "GET /test/id/hello HTTP/1.1\r\nHost: x\r\nIf-None-Match: *\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 304"), "got: {resp}");
    }

    #[tokio::test]
    async fn a_cacheable_read_projects_cache_control() {
        let addr = start().await;
        let resp = roundtrip(addr, "GET /test/cacheable HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(
            resp.contains("Cache-Control: public, max-age=31536000, immutable"),
            "got: {resp}"
        );
    }

    #[tokio::test]
    async fn a_volatile_read_is_no_store() {
        let addr = start().await;
        // hello uses the default Expiry::Always.
        let resp = roundtrip(addr, "GET /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.contains("Cache-Control: no-store"), "got: {resp}");
    }

    #[tokio::test]
    async fn a_not_found_endpoint_is_404() {
        let addr = start().await;
        let resp = roundtrip(addr, "GET /test/missing HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 404 Not Found"), "got: {resp}");
    }

    #[tokio::test]
    async fn if_match_matching_etag_allows_the_write() {
        let addr = start().await;
        let etag =
            etag_of_response(&roundtrip(addr, "GET /test/doc HTTP/1.1\r\nHost: x\r\n\r\n").await);
        let resp = roundtrip(
            addr,
            &format!(
                "PUT /test/doc HTTP/1.1\r\nHost: x\r\nIf-Match: {etag}\r\nContent-Length: 2\r\n\r\nv2"
            ),
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.ends_with("v2"), "got: {resp}");
    }

    #[tokio::test]
    async fn if_match_wrong_etag_is_412() {
        let addr = start().await;
        let resp = roundtrip(
            addr,
            "PUT /test/doc HTTP/1.1\r\nHost: x\r\nIf-Match: \"nope\"\r\nContent-Length: 2\r\n\r\nv2",
        )
        .await;
        assert!(
            resp.starts_with("HTTP/1.1 412 Precondition Failed"),
            "got: {resp}"
        );
    }

    #[tokio::test]
    async fn if_none_match_star_on_existing_is_412() {
        let addr = start().await;
        // doc exists (Source → v1) → create-only guard fails.
        let resp = roundtrip(
            addr,
            "PUT /test/doc HTTP/1.1\r\nHost: x\r\nIf-None-Match: *\r\nContent-Length: 2\r\n\r\nv2",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 412"), "got: {resp}");
    }

    #[tokio::test]
    async fn if_none_match_star_on_absent_allows_create() {
        let addr = start().await;
        // newdoc's Source → NotFound → create-only guard passes → the write runs.
        let resp = roundtrip(
            addr,
            "PUT /test/newdoc HTTP/1.1\r\nHost: x\r\nIf-None-Match: *\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 204"), "got: {resp}");
    }

    #[tokio::test]
    async fn delete_is_idempotent_via_tombstone() {
        let addr = start().await;
        // First DELETE succeeds (204) and lays a tombstone.
        let first = roundtrip(addr, "DELETE /test/vanishing HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(first.starts_with("HTTP/1.1 204"), "first: {first}");
        // Second DELETE: the endpoint now reports NotFound, but the tombstone → 204.
        let second = roundtrip(addr, "DELETE /test/vanishing HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(second.starts_with("HTTP/1.1 204"), "second: {second}");
    }

    #[tokio::test]
    async fn delete_of_never_existing_is_404() {
        let addr = start().await;
        let resp = roundtrip(addr, "DELETE /test/ghost HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 404 Not Found"), "got: {resp}");
    }

    // A raw PATCH request with a merge-patch body.
    fn merge_patch(path: &str, body: &str) -> String {
        format!(
            "PATCH {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/merge-patch+json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn patch_merges_json() {
        let addr = start().await;
        // current {"a":1,"b":2} + patch {"b":3,"c":4} → {"a":1,"b":3,"c":4}
        let resp = roundtrip(addr, &merge_patch("/test/jdoc", r#"{"b":3,"c":4}"#)).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.ends_with(r#"{"a":1,"b":3,"c":4}"#), "got: {resp}");
        assert!(
            resp.contains("ETag: "),
            "PATCH should return a fresh ETag, got: {resp}"
        );
    }

    #[tokio::test]
    async fn patch_null_deletes_a_key() {
        let addr = start().await;
        let resp = roundtrip(addr, &merge_patch("/test/jdoc", r#"{"a":null}"#)).await;
        assert!(resp.ends_with(r#"{"b":2}"#), "got: {resp}");
    }

    #[tokio::test]
    async fn patch_unsupported_content_type_is_415() {
        let addr = start().await;
        let resp = roundtrip(
            addr,
            "PATCH /test/jdoc HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi",
        )
        .await;
        assert!(
            resp.starts_with("HTTP/1.1 415 Unsupported Media Type"),
            "got: {resp}"
        );
    }

    #[tokio::test]
    async fn patch_of_absent_resource_is_404() {
        let addr = start().await;
        // newdoc's Source → NotFound → nothing to patch.
        let resp = roundtrip(addr, &merge_patch("/test/newdoc", r#"{"a":1}"#)).await;
        assert!(resp.starts_with("HTTP/1.1 404 Not Found"), "got: {resp}");
    }

    #[tokio::test]
    async fn patch_with_malformed_body_is_422() {
        let addr = start().await;
        let resp = roundtrip(addr, &merge_patch("/test/jdoc", "not json")).await;
        assert!(
            resp.starts_with("HTTP/1.1 422 Unprocessable Content"),
            "got: {resp}"
        );
    }

    #[tokio::test]
    async fn security_headers_are_on_by_default() {
        let addr = start().await;
        let resp = roundtrip(addr, "GET /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(
            resp.contains("Content-Security-Policy: default-src 'self'"),
            "got: {resp}"
        );
        assert!(
            resp.contains("X-Content-Type-Options: nosniff"),
            "got: {resp}"
        );
        assert!(resp.contains("Referrer-Policy: no-referrer"), "got: {resp}");
    }

    #[tokio::test]
    async fn hsts_needs_https_and_a_trusted_proxy() {
        // Default config does not trust the proxy → no HSTS even with the header.
        let untrusting = start().await;
        let r1 = roundtrip(
            untrusting,
            "GET /test/id/hello HTTP/1.1\r\nHost: x\r\nX-Forwarded-Proto: https\r\n\r\n",
        )
        .await;
        assert!(!r1.contains("Strict-Transport-Security"), "got: {r1}");

        // Trusting the proxy + X-Forwarded-Proto: https → HSTS present.
        let trusting = start_with(EdgeConfig {
            trust_proxy: true,
            ..Default::default()
        })
        .await;
        let r2 = roundtrip(
            trusting,
            "GET /test/id/hello HTTP/1.1\r\nHost: x\r\nX-Forwarded-Proto: https\r\n\r\n",
        )
        .await;
        assert!(
            r2.contains("Strict-Transport-Security: max-age=31536000"),
            "got: {r2}"
        );
    }

    #[tokio::test]
    async fn cors_is_closed_by_default() {
        let addr = start().await;
        let resp = roundtrip(
            addr,
            "GET /test/id/hello HTTP/1.1\r\nHost: x\r\nOrigin: https://evil.example\r\n\r\n",
        )
        .await;
        assert!(
            !resp.contains("Access-Control-Allow-Origin"),
            "closed CORS must not echo an origin, got: {resp}"
        );
    }

    #[tokio::test]
    async fn cors_echoes_an_allowed_origin() {
        let addr = start_with(EdgeConfig {
            cors: CorsPolicy {
                allowed_origins: vec!["https://app.example".to_string()],
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
        let resp = roundtrip(
            addr,
            "GET /test/id/hello HTTP/1.1\r\nHost: x\r\nOrigin: https://app.example\r\n\r\n",
        )
        .await;
        assert!(
            resp.contains("Access-Control-Allow-Origin: https://app.example"),
            "got: {resp}"
        );
        assert!(resp.contains("Vary: Origin"), "got: {resp}");
    }

    #[tokio::test]
    async fn cors_preflight_advertises_methods() {
        let addr = start_with(EdgeConfig {
            cors: CorsPolicy {
                allowed_origins: vec!["https://app.example".to_string()],
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
        // Preflight for a PUT on a Source+Sink resource.
        let resp = roundtrip(
            addr,
            "OPTIONS /test/doc HTTP/1.1\r\nHost: x\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: PUT\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 204"), "got: {resp}");
        assert!(
            resp.contains("Access-Control-Allow-Origin: https://app.example"),
            "got: {resp}"
        );
        assert!(
            resp.contains("Access-Control-Allow-Methods:"),
            "preflight should advertise methods, got: {resp}"
        );
    }

    // A route with no per-route overrides.
    fn plain_route(pattern: &str, iri_template: &str) -> Route {
        Route {
            pattern: pattern.to_string(),
            iri_template: iri_template.to_string(),
            cap: None,
            cors: None,
            csp: None,
        }
    }

    #[tokio::test]
    async fn a_route_rewrites_the_path_to_an_iri() {
        let addr = start_with(EdgeConfig {
            routes: RouteTable::new(vec![plain_route("/alias", "urn:test:id:hello")]),
            ..Default::default()
        })
        .await;
        let resp = roundtrip(addr, "GET /alias HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.ends_with("hi"), "got: {resp}");
    }

    #[tokio::test]
    async fn a_route_template_substitutes_captured_vars() {
        let addr = start_with(EdgeConfig {
            routes: RouteTable::new(vec![plain_route("/thing/{id}", "urn:test:id:{id}")]),
            ..Default::default()
        })
        .await;
        let resp = roundtrip(addr, "GET /thing/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(
            resp.ends_with("hi"),
            "capture should resolve to hello, got: {resp}"
        );
    }

    #[tokio::test]
    async fn an_unmatched_path_falls_through_to_the_default() {
        let addr = start_with(EdgeConfig {
            routes: RouteTable::new(vec![plain_route("/alias", "urn:test:id:hello")]),
            ..Default::default()
        })
        .await;
        // /test/id/hello matches no route → mechanical urn:test:id:hello.
        let resp = roundtrip(addr, "GET /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.ends_with("hi"), "got: {resp}");
    }

    #[tokio::test]
    async fn a_route_can_pin_a_per_route_capability() {
        // The server is public (no cap); the route grants urn:cap:test so the guarded
        // resource resolves. This is the per-route multi-tenant seam.
        let addr = start_with(EdgeConfig {
            routes: RouteTable::new(vec![Route {
                pattern: "/secret".to_string(),
                iri_template: "urn:test:guarded".to_string(),
                cap: Some(vec!["urn:cap:test".to_string()]),
                cors: None,
                csp: None,
            }]),
            ..Default::default()
        })
        .await;
        let resp = roundtrip(addr, "GET /secret HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "route cap should grant access, got: {resp}"
        );
        assert!(resp.ends_with("secret"), "got: {resp}");
        // The same guarded resource under the mechanical default (no route cap) → 403.
        let denied = roundtrip(addr, "GET /test/guarded HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(denied.starts_with("HTTP/1.1 403"), "got: {denied}");
    }

    #[tokio::test]
    async fn a_route_can_override_csp() {
        let addr = start_with(EdgeConfig {
            routes: RouteTable::new(vec![Route {
                pattern: "/page".to_string(),
                iri_template: "urn:test:id:hello".to_string(),
                cap: None,
                cors: None,
                csp: Some("default-src 'none'".to_string()),
            }]),
            ..Default::default()
        })
        .await;
        let resp = roundtrip(addr, "GET /page HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(
            resp.contains("Content-Security-Policy: default-src 'none'"),
            "route CSP should win, got: {resp}"
        );
    }

    #[tokio::test]
    async fn a_route_can_open_cors_while_the_server_stays_closed() {
        let addr = start_with(EdgeConfig {
            routes: RouteTable::new(vec![Route {
                pattern: "/api".to_string(),
                iri_template: "urn:test:id:hello".to_string(),
                cap: None,
                cors: Some(CorsPolicy {
                    allowed_origins: vec!["https://client.example".to_string()],
                    ..Default::default()
                }),
                csp: None,
            }]),
            ..Default::default()
        })
        .await;
        // The route opens CORS to the client origin.
        let open = roundtrip(
            addr,
            "GET /api HTTP/1.1\r\nHost: x\r\nOrigin: https://client.example\r\n\r\n",
        )
        .await;
        assert!(
            open.contains("Access-Control-Allow-Origin: https://client.example"),
            "got: {open}"
        );
        // A non-routed path keeps the server default (closed) for the same origin.
        let closed = roundtrip(
            addr,
            "GET /test/id/hello HTTP/1.1\r\nHost: x\r\nOrigin: https://client.example\r\n\r\n",
        )
        .await;
        assert!(
            !closed.contains("Access-Control-Allow-Origin"),
            "server default stays closed off-route, got: {closed}"
        );
    }
}
