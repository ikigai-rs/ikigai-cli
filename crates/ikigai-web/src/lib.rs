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
//! - **typed error → status**: `Denied`→403, `NotFound`/`Unresolved`→404, invalid/missing
//!   arg→400, `Conflict`→409, transient→503, else 500.
//!
//! App logic — scheduling, forms, policy — stays in resources, compositions, and
//! capabilities *above* this transport, exactly as the other transports (quic/ipc/mcp) keep
//! the kernel's behavior out of the wire layer.
#![forbid(unsafe_code)]

use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request, Verb};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A parsed HTTP request — what the router and the capability function see.
pub struct HttpRequest {
    pub method: String,
    /// The path, no query, each segment percent-decoded ON ITS OWN after splitting
    /// (e.g. `/account/id/alice`).
    ///
    /// ⚠ An encoded `%2F` is DATA inside its segment, never a separator (RFC 3986 §2.2): a
    /// client cannot add a segment by encoding one. To keep that true of this one string, a
    /// decoded `/` or `%` inside a segment stays escaped here (`%2F`, `%25`), so splitting
    /// `path` on `/` always yields the request's own segments. Every other escape is
    /// decoded, and `+` is a literal `+` — form encoding applies to the query only.
    pub path: String,
    /// Query pairs (filters over a partition; the partition itself is in the path), decoded
    /// as `application/x-www-form-urlencoded`: percent-escapes, and `+` as a space.
    pub query: Vec<(String, String)>,
    /// Header names are lowercased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The connection's peer address, when the caller knows it (the accept loop sets it).
    /// The socket's own view — the one thing on a request a submitter cannot author.
    pub peer: Option<IpAddr>,
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

/// Map a request → the principal the door authenticated it as, if any. **The identity
/// twin of [`CapFn`]**: a host that knows WHICH session cookie or passkey signed a request
/// supplies this, and the transport hands the answer to the endpoint as provenance.
///
/// The value is an opaque string the door chooses — a stable IRI
/// (`urn:iki:gonk:passkey:<credential-id>`) or a label — and the transport does not
/// interpret it. It is **never authority**: what a request may do is decided by [`CapFn`]
/// alone; this only says who asked. Wire it through [`EdgeConfig::principal_fn`]; `None`
/// (the default) stamps nothing and behaves exactly as before the hook existed.
///
/// The shape leaving the process, pinned below rather than described: on a **mutating**
/// verb (Sink, Delete) the answer lands on the request as an inline argument named
/// **`principal`**, beside `received` and `client`; a **read** carries none (an argument is
/// part of the cache key, and a per-principal key on every GET would partition the
/// representation cache by identity); and `?principal=…` in the query string is **dropped**
/// on a write, so a submitter cannot name their own principal.
///
/// ```
/// use ikigai_core::{
///     Description, EndpointSpace, Exact, FnEndpoint, Invocation, Kernel, ReprType,
///     Representation, Verb,
/// };
/// use ikigai_web::{EdgeConfig, HttpRequest, PrincipalFn};
/// use std::sync::Arc;
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
///
/// # #[tokio::main]
/// # async fn main() {
/// // An endpoint that answers with the principal it was handed, or `-` for none.
/// let whoami = FnEndpoint::new("whoami", |inv: &Invocation<'_>| {
///     let who = inv.inline_str("principal").unwrap_or("-").to_string();
///     Ok(Representation::new(ReprType::new("text/plain"), who.into_bytes()))
/// })
/// .with_description(Description::new("whoami").verb(Verb::Source).verb(Verb::Sink));
/// let kernel = Arc::new(Kernel::new(Arc::new(
///     EndpointSpace::new().bind(Exact::new("urn:test:whoami"), whoami),
/// )));
///
/// // The door authenticated the connection and names its principal.
/// let door: PrincipalFn = Arc::new(|_req: &HttpRequest| Some("urn:example:alice".to_string()));
/// let config = EdgeConfig { principal_fn: Some(door), ..EdgeConfig::default() };
/// let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
/// let addr = listener.local_addr().unwrap();
/// tokio::spawn(async move {
///     let _ = ikigai_web::serve_with_listener(kernel, ikigai_web::public_cap(), listener, config).await;
/// });
///
/// async fn send(addr: std::net::SocketAddr, raw: &str) -> String {
///     let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
///     c.write_all(raw.as_bytes()).await.unwrap();
///     let mut out = Vec::new();
///     c.read_to_end(&mut out).await.unwrap();
///     String::from_utf8_lossy(&out).into_owned()
/// }
///
/// // A write carries the principal, as the argument named `principal`.
/// let post = send(addr, "POST /test/whoami HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi").await;
/// assert!(post.ends_with("urn:example:alice"), "{post}");
/// // A read carries none.
/// let get = send(addr, "GET /test/whoami HTTP/1.1\r\nHost: x\r\n\r\n").await;
/// assert!(get.ends_with("\r\n-"), "{get}");
/// // The query string cannot name one: the connection's principal wins.
/// let forged = send(
///     addr,
///     "POST /test/whoami?principal=urn:example:mallory HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi",
/// )
/// .await;
/// assert!(forged.ends_with("urn:example:alice"), "{forged}");
/// # }
/// ```
pub type PrincipalFn = Arc<dyn Fn(&HttpRequest) -> Option<String> + Send + Sync>;

/// The largest request body accepted from a client, in bytes.
///
/// This is a TRANSPORT bound, not a form bound: the same door carries `PUT`/`PATCH` of
/// documents as well as the intake forms, so it is sized for the widest legitimate write
/// rather than for the widest legitimate submission. One mebibyte is what this server has
/// in fact enforced since it was written (as a silent truncation — see `handle`), so
/// naming it changes no request that succeeds today; it only makes the number arguable and
/// [overridable](EdgeConfig::max_body_bytes) instead of magic.
///
/// For scale on the intake side of the door: `ikigai-intake` bounds each declared field at
/// 4000 characters by default and booking's widest field at 500, so a form with twenty
/// generous fields cannot honestly approach this even fully percent-encoded.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// How long a client may take to send its request line and headers, from the moment the
/// connection is accepted. A client that has not finished by then is answered `408` and
/// dropped. Ten seconds is generous for any real client (a browser sends its headers in one
/// write) and short enough that a slow-loris trickle holds a connection for seconds, not
/// forever. [Overridable](EdgeConfig::header_timeout).
pub const DEFAULT_HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a client may take to deliver the body it declared, once the headers are in.
/// Past it the request is answered `408`. Thirty seconds carries a full
/// [`DEFAULT_MAX_BODY_BYTES`] at about 35 KB/s. [Overridable](EdgeConfig::body_timeout).
pub const DEFAULT_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long writing the response may take. A client that stops reading would otherwise hold
/// its connection (and its place under [`DEFAULT_MAX_CONNECTIONS`]) for as long as it
/// liked. Past it the connection is dropped. [Overridable](EdgeConfig::write_timeout).
pub const DEFAULT_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How many connections are served at once. A connection past the cap is answered `503`
/// with `Retry-After` straight away, without its request being handled. Every current door
/// (gonk, ttt-host, a LAN `serve --http`) serves a handful of people, and one request per
/// connection means a connection lives only as long as one request; 256 is far above any of
/// them and far below what exhausts a process's descriptors. [Overridable](EdgeConfig::max_connections).
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

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
    /// A live, swappable route handle for hot-reload. When set, it supersedes `routes` and
    /// the host may swap it (e.g. when a watched route file changes) without a restart; each
    /// request reads whatever the handle currently holds. `None` → the static `routes`.
    pub live_routes: Option<LiveRoutes>,
    /// The largest request body accepted, in bytes; a larger one is refused with `413`
    /// before it is read. Default [`DEFAULT_MAX_BODY_BYTES`]. Raise it for a door that
    /// takes genuinely large writes, lower it for one that only takes forms.
    pub max_body_bytes: usize,
    /// Routes-only: an un-routed path is **not** part of the public surface — it 404s instead
    /// of falling through to the mechanical `/noun/partition/key` → `urn:` default. This turns
    /// the route table into an exhaustive allow-list (no accidental export), the right posture
    /// for a public edge. Default `false` (fall-through on).
    pub routes_only: bool,
    /// The principal hook — see [`PrincipalFn`] for the shape it stamps. `None` (the
    /// default) attaches no `principal` argument to anything.
    pub principal_fn: Option<PrincipalFn>,
    /// The deadline for the request line and headers. Default [`DEFAULT_HEADER_TIMEOUT`].
    pub header_timeout: std::time::Duration,
    /// The deadline for the declared body. Default [`DEFAULT_BODY_TIMEOUT`].
    pub body_timeout: std::time::Duration,
    /// The deadline for writing the response. Default [`DEFAULT_WRITE_TIMEOUT`].
    pub write_timeout: std::time::Duration,
    /// Connections served at once; one past it is answered `503`. Default
    /// [`DEFAULT_MAX_CONNECTIONS`]. `0` refuses every connection.
    pub max_connections: usize,
}

/// A shared, swappable [`RouteTable`] for hot-reload. The server reads the current table per
/// request (a cheap `Arc` clone); the host swaps it in place via
/// [`swap_routes`](LiveRoutes) — no restart. Build one with [`live_routes`].
pub type LiveRoutes = Arc<std::sync::RwLock<Arc<RouteTable>>>;

/// Wrap a [`RouteTable`] in a swappable [`LiveRoutes`] handle. Keep a clone to `store` an
/// updated table into later (the server holds the other clone).
pub fn live_routes(table: RouteTable) -> LiveRoutes {
    Arc::new(std::sync::RwLock::new(Arc::new(table)))
}

/// Swap the table a [`LiveRoutes`] handle serves. Takes effect on the next request.
pub fn swap_routes(handle: &LiveRoutes, table: RouteTable) {
    if let Ok(mut w) = handle.write() {
        *w = Arc::new(table);
    }
}

impl Default for EdgeConfig {
    fn default() -> Self {
        EdgeConfig {
            trust_proxy: false,
            security: Some(SecurityHeaders::default()),
            cors: CorsPolicy::default(),
            routes: RouteTable::default(),
            live_routes: None,
            routes_only: false,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            principal_fn: None,
            header_timeout: DEFAULT_HEADER_TIMEOUT,
            body_timeout: DEFAULT_BODY_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
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
        let segs = path_segments(path);
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
    /// The live route table read per request — the config's `live_routes` handle, or a
    /// fresh wrap of its static `routes`. Reading is a cheap `Arc` clone.
    routes: LiveRoutes,
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
    let listener = TcpListener::bind(addr).await?;
    serve_with_listener(kernel, cap_fn, listener, config).await
}

/// Like [`serve_with`], but drives an already-bound listener. Binding before this call
/// lets a caller learn the actual `local_addr()` (e.g. an ephemeral `:0` port) and start
/// accepting from a socket that is already listening — no bind/rebind window, so a client
/// that connects the instant it has the address lands in the accept backlog rather than
/// racing the bind.
pub async fn serve_with_listener(
    kernel: Arc<Kernel>,
    cap_fn: CapFn,
    listener: TcpListener,
    config: EdgeConfig,
) -> std::io::Result<()> {
    // The live route handle: the config's own (so the host can hot-swap it), or a fresh
    // wrap of the static routes when no live handle was supplied.
    let routes = config
        .live_routes
        .clone()
        .unwrap_or_else(|| live_routes(config.routes.clone()));
    let shared = Arc::new(Shared {
        kernel,
        cap_fn,
        config,
        routes,
        tombstones: std::sync::Mutex::new(std::collections::HashMap::new()),
    });
    // The connection cap. A permit is taken at accept and held until the connection's task
    // ends, so the cap counts connections, not requests (the same thing here: one request
    // per connection). `Semaphore::new` panics above `MAX_PERMITS`, hence the clamp.
    let permits = Arc::new(tokio::sync::Semaphore::new(
        shared
            .config
            .max_connections
            .min(tokio::sync::Semaphore::MAX_PERMITS),
    ));
    loop {
        let (sock, peer) = listener.accept().await?;
        let shared = Arc::clone(&shared);
        match Arc::clone(&permits).try_acquire_owned() {
            Ok(permit) => {
                tokio::spawn(async move {
                    let _ = handle(sock, peer.ip(), shared).await;
                    drop(permit);
                });
            }
            // Over the cap: answer 503 without handling the request, on its own task so a
            // client that will not take the answer cannot stall the accept loop.
            Err(_) => {
                tokio::spawn(async move { refuse_busy(sock, &shared.config).await });
            }
        }
    }
}

/// Answer a connection past the cap: `503` with `Retry-After`, then a LINGERING close.
///
/// The request is never parsed, but it has usually arrived, and closing a socket with unread
/// bytes in its receive buffer sends a reset — which on most stacks destroys the `503` before
/// the client reads it (measured: the first version of this test saw `ECONNRESET`, not a
/// status). So: write, half-close, then drain what the client sent until it hangs up, bounded
/// by the header deadline and 64 KiB. Holds no permit, so it is bounded by those two alone.
async fn refuse_busy(mut sock: TcpStream, config: &EdgeConfig) {
    let mut busy = Resp::text(503, "Service Unavailable", "too many connections");
    busy.headers
        .push(("Retry-After".to_string(), "1".to_string()));
    if write_within(&mut sock, busy, config.write_timeout)
        .await
        .is_err()
    {
        return;
    }
    let _ = sock.shutdown().await;
    let drain = async {
        let mut tmp = [0u8; 1024];
        let mut seen = 0usize;
        while seen < 64 * 1024 {
            match sock.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => seen += n,
            }
        }
    };
    let _ = tokio::time::timeout(config.header_timeout, drain).await;
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
    /// The request headers that selected this answer, emitted as ONE `Vary` header (a
    /// cache keys a stored response on these, so a missing name lets it hand one client's
    /// answer to another). Kept apart from `headers` so the read path and the edge policy
    /// can both contribute without writing `Vary` twice.
    vary: Vec<&'static str>,
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
            vary: Vec::new(),
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

/// How reading the request line and headers ended.
enum Head {
    /// The blank line arrived; the headers end at this offset in the buffer.
    End(usize),
    /// The client hung up first.
    Closed,
    /// The headers outgrew the bound before they ended.
    TooLarge,
}

/// Read up to the end of the headers (the blank line), into `buf`.
async fn read_head(sock: &mut TcpStream, buf: &mut Vec<u8>) -> std::io::Result<Head> {
    let mut tmp = [0u8; 1024];
    loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok(Head::End(pos));
        }
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return Ok(Head::Closed);
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 64 * 1024 {
            return Ok(Head::TooLarge);
        }
    }
}

async fn handle(mut sock: TcpStream, peer: IpAddr, shared: Arc<Shared>) -> std::io::Result<()> {
    let wt = shared.config.write_timeout;
    // THE HEADERS ARE READ UNDER A DEADLINE. Without one a client that sends a byte every few
    // seconds (slow-loris) holds this connection, and its place under the cap, forever.
    let mut buf = Vec::new();
    let header_end =
        match tokio::time::timeout(shared.config.header_timeout, read_head(&mut sock, &mut buf))
            .await
        {
            Err(_) => {
                let resp = Resp::text(408, "Request Timeout", "request headers took too long");
                return write_within(&mut sock, resp, wt).await;
            }
            Ok(read) => match read? {
                Head::End(pos) => pos,
                Head::Closed => return Ok(()),
                Head::TooLarge => {
                    let resp = Resp::text(431, "Request Header Fields Too Large", "");
                    return write_within(&mut sock, resp, wt).await;
                }
            },
        };
    let mut req = match parse_head(&buf[..header_end]) {
        Ok(r) => r,
        Err(why) => return write_within(&mut sock, Resp::text(400, "Bad Request", why), wt).await,
    };
    // THE FRAMING IS SETTLED BEFORE A BODY BYTE IS READ. Everything here decides how much
    // an anonymous client may make this process hold and hand onward, and this door is
    // public — bosatsu's contact and booking forms front it — so the decision cannot come
    // after the read it is meant to bound.
    //
    // A transfer-coding this server does not implement is REFUSED rather than ignored.
    // `chunked` carries its length inside the body, so falling through to "no
    // Content-Length" would both skip the bound below and hand the endpoint the raw chunk
    // framing as if it were the submission.
    if req.header("transfer-encoding").is_some() {
        return write_within(
            &mut sock,
            Resp::text(501, "Not Implemented", "unsupported transfer-encoding"),
            wt,
        )
        .await;
    }
    let max = shared.config.max_body_bytes;
    // A `Content-Length` that is present but unreadable is a disagreement about framing,
    // not a zero-length body: treating it as 0 would silently deliver whatever trailed the
    // headers in the read buffer as the body.
    let cl: usize = match req.header("content-length") {
        None => 0,
        Some(raw) => match raw.parse() {
            Ok(n) => n,
            Err(_) => {
                return write_within(
                    &mut sock,
                    Resp::text(400, "Bad Request", "malformed Content-Length"),
                    wt,
                )
                .await
            }
        },
    };
    // REFUSE, DO NOT TRUNCATE — the whole point of this block. The declared length is the
    // cheapest check there is (it costs no read at all) and 413 is the honest answer to a
    // client whose submission this server will not take.
    //
    // What stood here stopped READING at the same threshold and then went on to parse and
    // dispatch what it had. An oversize POST therefore became a silently truncated one that
    // the endpoint had no way to tell from a complete submission, and the submitter was
    // told nothing — mangled input accepted, rather than large input refused.
    if cl > max {
        return write_within(
            &mut sock,
            Resp::text(413, "Payload Too Large", "request body too large"),
            wt,
        )
        .await;
    }
    // Whatever already arrived behind the headers. Bounded by the 64 KiB header cap above,
    // but checked against `max` too so a deliberately small `max_body_bytes` still holds.
    let mut body = buf[header_end + 4..].to_vec();
    if body.len() > max {
        return write_within(
            &mut sock,
            Resp::text(413, "Payload Too Large", "request body too large"),
            wt,
        )
        .await;
    }
    // No second size check is needed in the loop: it stops at `cl`, and `cl <= max`. The
    // read may overshoot by one buffer, which is why the body is cut to the length the
    // client declared — those trailing bytes are the next pipelined request, not this body.
    //
    // The body is read under its own deadline, for the reason the headers are: a client that
    // declares a length and then trickles it would otherwise hold the connection for as long
    // as it cared to.
    let read_body = async {
        let mut tmp = [0u8; 1024];
        while body.len() < cl {
            let n = sock.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        Ok::<(), std::io::Error>(())
    };
    match tokio::time::timeout(shared.config.body_timeout, read_body).await {
        Err(_) => {
            let resp = Resp::text(408, "Request Timeout", "request body took too long");
            return write_within(&mut sock, resp, wt).await;
        }
        Ok(read) => read?,
    }
    // The other end of the same principle. A client that declares more than it sends and
    // then hangs up has produced a PARTIAL submission, and delivering it would put the
    // endpoint back in the position this whole block exists to get it out of: unable to
    // tell an incomplete body from a complete one.
    if body.len() < cl {
        return write_within(
            &mut sock,
            Resp::text(400, "Bad Request", "incomplete request body"),
            wt,
        )
        .await;
    }
    body.truncate(cl);
    req.body = body;
    req.peer = Some(peer);

    // Resolve the route once; it drives the target IRI + per-route cap (in respond) and the
    // per-route CORS/CSP (in the policy layer). No match → the mechanical default throughout.
    // Read the current route table (hot-swappable); a cheap Arc clone, held only for the match.
    let table = shared
        .routes
        .read()
        .map(|g| Arc::clone(&g))
        .unwrap_or_else(|_| Arc::new(RouteTable::default()));
    let matched = table.match_path(&req.path);
    let mut resp = respond(&shared, &req, matched.as_ref()).await;
    apply_edge_policy(&mut resp, &shared.config, &req, matched.as_ref());
    write_within(&mut sock, resp, wt).await
}

/// The core adapter: method → verb (gated by `describe().verbs`), path → iri,
/// query → args, body → piped `content`, Accept → conneg, resolved under the cap.
async fn respond(shared: &Shared, req: &HttpRequest, matched: Option<&Matched>) -> Resp {
    // Routes-only edge: an un-routed path is not part of the public surface — 404 before it
    // can reach the mechanical default (the exhaustive-allow-list posture).
    if shared.config.routes_only && matched.is_none() {
        return Resp::text(404, "Not Found", "no route");
    }
    let kernel = &shared.kernel;
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

    // `?description` (a reserved query param) is the self-description face: a GET projects the
    // resource's contract into an API description — OpenAPI today, Hydra/Turtle by conneg
    // later. It's what a code-on-demand client reads to generate a form for the resource.
    //
    // ★ UNDER THE REQUEST'S CAPABILITY, like every other answer here. It projects only the
    // actions `urn:kernel:actions` would offer this capability (see `offered_actions`), and a
    // resource offering none answers exactly as a missing one does. It used to answer for any
    // bound IRI BEFORE the capability was even computed, so a door that empties the capability
    // to refuse a request (gonk's foreign `Host`, a cross-site write) still disclosed the
    // contract of every resource behind it.
    if (req.method == "GET" || req.method == "HEAD")
        && req.query.iter().any(|(k, _)| k == "description")
    {
        let cap = request_capability(shared, req, matched);
        let offered = described
            .as_ref()
            .map(|d| offered_actions(kernel, &iri, d, &cap))
            .unwrap_or_default();
        return describe_response(
            described.as_ref(),
            &offered,
            &req.path,
            req.method == "HEAD",
        );
    }

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
    // CONTENT NEGOTIATION, against the faces the resource DECLARES for this verb. A face
    // asked for explicitly (`?as=`) beats `Accept`; nothing acceptable is a 406, never a 400
    // — a client naming the format it can read has not supplied an invalid argument.
    let faces = Faces::declared(described.as_ref(), verb);
    let explicit = req
        .query
        .iter()
        .find(|(k, _)| k == "as")
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.trim().is_empty());
    let negotiated = match explicit {
        Some(asked) => faces.explicit(asked),
        None => faces.negotiate(req.header("accept")),
    };
    match negotiated {
        Negotiated::Default => {}
        Negotiated::Face(face) => {
            request = request.with_arg("as", ArgRef::Inline(face.into_bytes()));
        }
        Negotiated::NotAcceptable => return not_acceptable(&faces, explicit, req),
    }
    for (k, v) in &req.query {
        // `as`/`content` are the adapter's own (`as` was negotiated above). On a write, so
        // are the provenance names (`received`, `client`, `principal`): the transport
        // supplies them below, and a submitter must not be able to forge an origin by
        // appending `?client=…` to the URL, nor an identity by appending `?principal=…`.
        let reserved = k == "as" || k == "content" || (verb.is_mutating() && is_provenance(k));
        if !reserved {
            request = request.with_arg(k.clone(), ArgRef::Inline(v.clone().into_bytes()));
        }
    }
    if verb == Verb::Sink {
        request = request.with_arg("content", ArgRef::Inline(req.body.clone()));
        if let Some(ct) = req.header("content-type") {
            request = request.with_arg("content-type", ArgRef::Inline(ct.as_bytes().to_vec()));
        }
    }

    // PROVENANCE on a write: who sent it, and when — read off the CONNECTION, never the
    // payload. A public form endpoint records these alongside the submitted fields, so a
    // stored submission carries an origin its submitter did not get to choose.
    //
    // Writes only, and not for want of tidiness: an argument is part of a request's content
    // address, which is the kernel's cache key. A per-request timestamp on a read would give
    // every GET a fresh key and quietly defeat the representation cache. Mutating verbs are
    // never cached, so attaching it there costs nothing.
    if verb.is_mutating() {
        request = request.with_arg("received", ArgRef::Inline(now_rfc3339().into_bytes()));
        if let Some(client) = client_ip(req, &shared.config) {
            request = request.with_arg("client", ArgRef::Inline(client.into_bytes()));
        }
        // The third provenance name: WHO the door authenticated, when it knows. Read off
        // the connection through the host's hook (a session cookie → a passkey → an IRI),
        // never off the payload — the same rule as `client`, for the same reason. Not
        // authority: the capability above already decided what this request may do.
        if let Some(principal) = shared.config.principal_fn.as_ref().and_then(|f| f(req)) {
            request = request.with_arg("principal", ArgRef::Inline(principal.into_bytes()));
        }
    }

    let cap = request_capability(shared, req, matched);

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
        // Reads project a strong ETag + Cache-Control and honor `If-None-Match` (→304).
        Ok(repr) if verb == Verb::Source => {
            let freshness = Freshness {
                self_contained: self_contained(&repr, &iri, declared),
                shared: !shaped_by_credentials(shared, req, matched, &cap),
            };
            let mut vary = Vec::new();
            // `Accept` selected this face unless the client named it in the URL (`?as=`, which
            // every cache keys on already) or the resource has exactly one face to give.
            if explicit.is_none() && faces.served.len() != 1 {
                vary.push("Accept");
            }
            // The headers a capability function reads identity from. The edge cannot see
            // inside `cap_fn`, so it names them whenever `cap_fn` was consulted; a route that
            // pins its capability makes the answer the same for every caller.
            if matched.and_then(|m| m.cap.as_ref()).is_none() {
                vary.extend(CREDENTIAL_HEADERS.iter().map(|(_, name)| *name));
            }
            read_resp(req, repr, freshness, vary)
        }
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

/// The capability a request resolves under: a matched route's per-route ceiling (the
/// multi-tenant seam) when it pins one, otherwise the server-wide `cap_fn`. One function, so
/// the description face and resolution cannot disagree about who is asking.
fn request_capability(shared: &Shared, req: &HttpRequest, matched: Option<&Matched>) -> Capability {
    match matched.and_then(|m| m.cap.as_ref()) {
        Some(scopes) => Capability::scoped(scopes.clone()),
        None => (shared.cap_fn)(req),
    }
}

/// The actions of `desc` that the capability-scoped action manifold offers `cap` at `iri`.
///
/// ★ This REUSES the manifold's predicate rather than restating it: it asks
/// `Kernel::select_actions` — the call `urn:kernel:actions` answers — under `cap`, and keeps
/// the rows that name this resource. A second copy of "is this action offered" (each
/// `requires` against `Capability::allows`, the `…:*` wildcard, template drivability) would
/// drift from the one agents and the MCP projection read, and this face would then disagree
/// with the manifold about what a caller may do. The price is a walk of every binding per
/// `?description` request — a form load, not a hot path.
///
/// A row names this resource when its pattern IS this IRI or a template this IRI matches, AND
/// its description id is this resource's; the id alone would let a same-id sibling bound
/// elsewhere vouch for it. Conservative by construction: a resource the manifold cannot name
/// (a template whose variables are not declared bindings, an entry no probe can describe) is
/// offered nothing here, exactly as it is offered nothing there.
fn offered_actions(
    kernel: &Kernel,
    iri: &Iri,
    desc: &ikigai_core::Description,
    cap: &Capability,
) -> Vec<ikigai_core::ActionSpec> {
    let query = ikigai_core::ActionQuery {
        capability: Some(cap),
        ..Default::default()
    };
    let verbs: Vec<Verb> = kernel
        .select_actions(&query)
        .into_iter()
        .filter(|m| m.id == desc.id && row_names(&m.endpoint, iri))
        .map(|m| m.verb)
        .collect();
    desc.action_specs()
        .into_iter()
        .filter(|a| verbs.contains(&a.verb))
        .collect()
}

/// Whether a manifold row's pattern (an exact IRI or a URI template) names `iri`.
fn row_names(pattern: &str, iri: &Iri) -> bool {
    use ikigai_core::Grammar;
    pattern == iri.as_str()
        || ikigai_core::UriTemplate::parse(pattern).is_ok_and(|t| t.match_iri(iri).is_some())
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
                // `shift_remove`, not `remove`: under `preserve_order` (which this workspace
                // enables) `Map::remove` is `swap_remove`, so deleting a key would drag the
                // document's LAST key into the hole. A merge patch that removes one field
                // must not reshuffle the ones it left alone.
                //
                // It doubles as a canary, which is why it is worth the extra word here:
                // `shift_remove` does not EXIST on a BTreeMap-backed `Map`, so dropping
                // `preserve_order` from the workspace fails to compile right here instead of
                // silently re-alphabetizing every projection this crate serves.
                tmap.shift_remove(k);
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
        // Native-only: `ikigai-web` is the INBOUND HTTP transport — a tokio TcpListener
        // bound to a port — so it has no wasm build. This is the DELETE tombstone's
        // monotonic expiry mark, which must not move when the wall clock does.
        #[allow(clippy::disallowed_methods)]
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

/// A read response: 200 with the representation + a strong `ETag`, the projected
/// `Cache-Control` and the `Vary` that names what selected it; `304 Not Modified` (headers
/// only, the SAME validator, `Cache-Control` and `Vary`, per RFC 9110 §15.4.5) when
/// `If-None-Match` matches; HEAD carries the same headers with no body.
fn read_resp(
    req: &HttpRequest,
    repr: ikigai_core::Representation,
    freshness: Freshness,
    vary: Vec<&'static str>,
) -> Resp {
    let etag = etag_of(&repr);
    // Native-only: `ikigai-web` is the inbound HTTP transport (a tokio TcpListener), so it has
    // no wasm build and no kernel handle to take an injected Clock from here. Wall-clock now
    // is what turns an `Expiry::At` deadline into a `max-age` a remote cache counts down.
    #[allow(clippy::disallowed_methods)]
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let cc = Some(cache_control_of(repr.expiry, freshness, now));
    if let Some(inm) = req.header("if-none-match") {
        if if_none_match_hit(inm, &etag) {
            return Resp {
                etag: Some(etag),
                cache_control: cc,
                vary,
                ..Resp::status(304, "Not Modified")
            };
        }
    }
    let head_only = req.method == "HEAD";
    Resp {
        content_type: media_type_of(&repr),
        body: if head_only { Vec::new() } else { repr.bytes },
        etag: Some(etag),
        cache_control: cc,
        vary,
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

/// The request headers a capability function can read an identity from: `(lowercase name
/// as parsed, name as written in `Vary`)`.
const CREDENTIAL_HEADERS: [(&str, &str); 2] =
    [("authorization", "Authorization"), ("cookie", "Cookie")];

/// What the edge knows about a read answer beyond its [`Expiry`](ikigai_core::Expiry): the two
/// facts [`cache_control_of`] needs and the representation does not carry on its own.
#[derive(Clone, Copy, Debug)]
struct Freshness {
    /// Nothing but the passage of time can change this answer: every golden thread it hangs
    /// from is its OWN target, and the resource declares verbs, none of them mutating — so no
    /// write can cut it, here or through a sibling. See [`self_contained`].
    self_contained: bool,
    /// Any caller would have been handed this answer: the request's capability is the one it
    /// would hold with its credentials removed. See [`shaped_by_credentials`].
    shared: bool,
}

/// `Cache-Control` for a read, projected from the representation's cache validity. The two
/// caching models do NOT line up one to one, so this is a translation, not a rename:
///
/// | kernel answer                            | `Cache-Control`                  |
/// |------------------------------------------|----------------------------------|
/// | `Always`                                 | `no-store`                       |
/// | `Never`                                  | `no-cache`                       |
/// | `At(t)`, t ahead, self-contained         | `max-age=<seconds until t>`      |
/// | `At(t)`, t ahead, hangs from a thread    | `no-cache`                       |
/// | `At(t)`, t passed                        | `no-cache`                       |
///
/// each cacheable one prefixed `public` when any caller would get the same answer and
/// `private` when the request's credentials shaped it.
///
/// ★ **`Never` is `no-cache`, never `immutable`.** Kernel `Never` means "valid until a golden
/// thread is cut, for as long as this kernel runs". HTTP `immutable` means "the bytes at this
/// URL never change: do not revalidate, ever, across every restart and upgrade of the server".
/// Three things in the kernel make the first strictly weaker than the second:
/// - since core 0.1.73 every cacheable answer hangs from its own target's thread, so a
///   `Never` answer with NO threads does not reach this function at all;
/// - a restart empties the kernel's cache, and a resource that reads configuration or a
///   crate version at startup (the standalone server's `urn:repo:style`) changes its bytes
///   across one without any thread being cut — that server shipped `immutable` for `Never`
///   and every correct change was invisible short of a hard reload;
/// - threads do not cross a mount (`serde(skip)`), so an answer from a peer arrives looking
///   independent of everything.
///
/// `no-cache` is not `no-store`: a cache keeps the bytes and revalidates before reuse, and
/// against the strong [`etag_of`] validator that is a bodyless `304` for as long as nothing
/// was cut — most of what `immutable` bought, honestly.
///
/// ★ **A deadline with threads is `no-cache`, not `max-age` + `must-revalidate`.** The kernel
/// holds an `At` entry valid while BOTH the deadline is ahead AND its threads are uncut.
/// `must-revalidate` only binds once the answer is stale, so inside `max-age` a cache would
/// serve it without asking and a write in that window would go unseen. HTTP has no way to
/// push a cut to a cache, so asking on every use is the only projection that keeps the
/// second half of the condition.
fn cache_control_of(expiry: ikigai_core::Expiry, freshness: Freshness, now_ms: u64) -> String {
    use ikigai_core::Expiry;
    let scope = if freshness.shared {
        "public"
    } else {
        "private"
    };
    match expiry {
        Expiry::Always => "no-store".to_string(),
        Expiry::At(deadline) if freshness.self_contained && deadline.as_millis() > now_ms => {
            format!(
                "{scope}, max-age={}",
                (deadline.as_millis() - now_ms) / 1000
            )
        }
        Expiry::Never | Expiry::At(_) => format!("{scope}, no-cache"),
    }
}

/// Whether nothing but time can change `repr` as the answer at `iri`: every thread it hangs
/// from is `iri` itself, and the resource declares its verbs, none of them mutating.
///
/// Conservative in both directions it can fail. A thread under any other name (a store's
/// write thread, a watched file) means some OTHER write cuts it. Its own thread is cut by a
/// write to this very IRI, so a resource that declares Sink or Delete is out; one that
/// declares nothing cannot be said not to. And the thread names the CANONICAL target, so an
/// aliased name compares unequal and is treated as threaded — the safe way to be wrong.
fn self_contained(repr: &ikigai_core::Representation, iri: &Iri, declared: &[Verb]) -> bool {
    repr.threads().iter().all(|t| t.as_str() == iri.as_str())
        && !declared.is_empty()
        && !declared.iter().any(|v| v.is_mutating())
}

/// Whether the request's credentials SHAPED its capability — and so its answer, which the
/// kernel itself keys on the capability — making it unfit for a shared cache.
///
/// ★ The edge cannot see inside the host's [`CapFn`], so it ASKS it: the same request with
/// its credential headers (`Authorization`, `Cookie`) removed is what an anonymous caller in
/// the same position would send, and if `cap_fn` grants that request the same capability, the
/// answer is one anyone would be handed (`public`); if not, a credential chose it
/// (`private`). This follows the capability, not the presence of a header: an expired
/// session cookie, or any cookie at all on a door that grants one fixed ceiling, grants
/// nothing beyond the anonymous capability and leaves the answer `public`. A route that pins
/// its capability never consults `cap_fn`, so it is the same for every caller.
///
/// It costs one more `cap_fn` call per read, which for every door in the ecosystem is a
/// lookup, not I/O.
fn shaped_by_credentials(
    shared: &Shared,
    req: &HttpRequest,
    matched: Option<&Matched>,
    cap: &Capability,
) -> bool {
    if matched.and_then(|m| m.cap.as_ref()).is_some() {
        return false;
    }
    let carries = |name: &str| CREDENTIAL_HEADERS.iter().any(|(h, _)| *h == name);
    if !req.headers.iter().any(|(k, _)| carries(k)) {
        return false;
    }
    let anonymous = HttpRequest {
        method: req.method.clone(),
        path: req.path.clone(),
        query: req.query.clone(),
        headers: req
            .headers
            .iter()
            .filter(|(k, _)| !carries(k))
            .cloned()
            .collect(),
        body: req.body.clone(),
        peer: req.peer,
    };
    (shared.cap_fn)(&anonymous) != *cap
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

/// Map a typed kernel error onto an HTTP status.
///
/// `Unresolved` — the kernel found no endpoint bound to the target — is a **404**, the same
/// as a bound endpoint reporting `NotFound`: to a client both are "nothing here". It used to
/// fall through to 500, which told every visitor to an unrouted path that the server had
/// broken, and made consumers compose their own not-found catch-all to avoid it.
///
/// ⚠ This does not widen what a narrower capability can learn. Resolution runs BEFORE the
/// declared-capability floor (core's `issue`), so an out-of-scope resource that exists is
/// already a 403 and a missing one was already distinguishable (as a 500). A 404 here names
/// no more than that already does. (`?description` once answered for any bound IRI without
/// consulting the capability; it now answers an out-of-scope resource with this same 404.)
///
/// `Conflict` — the resource's CURRENT STATE refuses the request (a taken square, a move after
/// the game is over) — is a **409**. It used to fall to 500, worse than the 400 a bad argument
/// gets. Distinct from **412**, which stays the answer when a precondition the CALLER stated
/// (`If-Match` / `If-None-Match`) fails; that is checked before the write is attempted, so a
/// write carrying a failed precondition never reaches the endpoint to conflict at all.
fn error_resp(e: &ikigai_core::Error) -> Resp {
    use ikigai_core::Error;
    let (status, reason) = match e {
        Error::Denied(_) => (403, "Forbidden"),
        Error::NotFound(_) | Error::Unresolved(_) => (404, "Not Found"),
        Error::MissingArgument(_) | Error::InvalidArgument { .. } => (400, "Bad Request"),
        Error::Conflict(_) => (409, "Conflict"),
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

    // A policy that allows ANY origin makes every answer depend on `Origin` — the same URL
    // carries `Access-Control-Allow-Origin` for one caller and not for the next — so `Vary`
    // names it on every response, not only the ones that echo an origin. Naming it only there
    // let a cache store the answer to a same-origin request (no CORS headers) and hand it to
    // a cross-origin one, which the browser then blocks.
    if !cors.allowed_origins.is_empty() && !resp.vary.contains(&"Origin") {
        resp.vary.push("Origin");
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
    format!("urn:{}", path_segments(path).join(":"))
}

/// The faces a resource declares for one verb, read from its description the way the
/// resource itself reads them: an `as` input's `one_of` when it has one (that is the list an
/// endpoint refuses outside of), else the verb's declared `outputs`. Media types are kept
/// bare and lowercase; the first listed is the default unless `as` names one.
#[derive(Debug, Default)]
struct Faces {
    served: Vec<String>,
    default: Option<String>,
    /// Whether `default` is what the resource SAID its default face is (an `as` input's
    /// `default_value`) or what this adapter guessed from declaration order. A guess is
    /// good enough to break a tie — first listed is a real preference order — but it is
    /// not a promise about the bytes a request carrying no `as` gets back, so it cannot
    /// license leaving `as` off a request whose client named a face.
    default_declared: bool,
}

/// What negotiation decided to hand the resource as `as`.
#[derive(Debug, PartialEq)]
enum Negotiated {
    /// Send no `as`: the client accepts the resource's own default face (a `*/*` or
    /// `type/*` match, or no preference at all).
    Default,
    /// Send this face as `as`.
    Face(String),
    /// None of the declared faces is acceptable to the client → 406.
    NotAcceptable,
}

impl Faces {
    fn declared(desc: Option<&ikigai_core::Description>, verb: Verb) -> Faces {
        let Some(action) = desc.and_then(|d| d.action_specs().into_iter().find(|a| a.verb == verb))
        else {
            return Faces::default();
        };
        let as_input = action.inputs.iter().find(|i| i.name == "as");
        let listed: Vec<String> = match as_input {
            Some(input) if !input.one_of.is_empty() => input.one_of.clone(),
            _ => action.outputs.clone(),
        };
        let mut served: Vec<String> = Vec::new();
        for face in listed.iter().map(|f| bare_media(f)) {
            if !face.is_empty() && !served.contains(&face) {
                served.push(face);
            }
        }
        let declared_default = as_input
            .and_then(|i| i.default.as_deref())
            .map(bare_media)
            .filter(|d| served.contains(d));
        let default_declared = declared_default.is_some();
        let default = declared_default.or_else(|| served.first().cloned());
        Faces {
            served,
            default,
            default_declared,
        }
    }

    /// An explicit `?as=`: it names the face, and `Accept` is not consulted. Refused only
    /// when the resource declares its faces and this is not one of them.
    fn explicit(&self, asked: &str) -> Negotiated {
        if self.served.is_empty() || self.served.contains(&bare_media(asked)) {
            Negotiated::Face(asked.trim().to_string())
        } else {
            Negotiated::NotAcceptable
        }
    }

    /// RFC 9110 §12.5.1 proactive negotiation over the declared faces.
    ///
    /// Each face scores the quality of the MOST SPECIFIC range that matches it (`type/sub`
    /// over `type/*` over `*/*`), so `text/plain;q=0, */*` excludes plain while admitting
    /// everything else. The highest non-zero score wins; ties go to the default face, then
    /// to declaration order.
    ///
    /// The winner is then NAMED as `as` unless the client can be said to have expressed no
    /// preference for it — which is the case only when the winner is the default face AND
    /// nothing in `Accept` named it concretely: a browser's trailing `*/*;q=0.8` tolerates
    /// the default, it does not ask for it. Then no `as` is sent and the resource's own
    /// default answers, exactly as it does for a client with no `Accept` at all. ⚠ How the
    /// winner was MATCHED is what decides this, never whether it happens to equal the
    /// default: `Accept: text/html` on a resource whose first declared output is
    /// `text/html` is a request for HTML, and answering it with the resource's own default
    /// is how the HTML face of `urn:iki:foaf` went missing in 0.1.22. When the default face
    /// was only GUESSED from declaration order, that tolerance narrows once more: only a
    /// `*/*` client gets `as` withheld, since it reads whatever the unknown default turns
    /// out to be. A `type/*` client is handed the winning face by name instead, because a
    /// guessed default may be a type that wildcard excludes and no one can ask the resource.
    ///
    /// A resource that declares no faces cannot be negotiated for, and is never refused: it
    /// is handed the client's most preferred concrete type (the only party that can judge it
    /// is the endpoint), unless the client prefers a wildcard over every concrete type.
    fn negotiate(&self, accept: Option<&str>) -> Negotiated {
        let ranges = accept.map(parse_accept).unwrap_or_default();
        if ranges.is_empty() {
            return Negotiated::Default;
        }
        if self.served.is_empty() {
            let best_concrete = ranges
                .iter()
                .filter(|r| r.kind != "*" && r.subtype != "*" && r.q > 0.0)
                .fold(None::<&MediaRange>, |best, r| match best {
                    Some(b) if b.q >= r.q => Some(b),
                    _ => Some(r),
                });
            let best_wild = ranges
                .iter()
                .filter(|r| r.kind == "*" || r.subtype == "*")
                .map(|r| r.q)
                .fold(0.0_f32, f32::max);
            return match best_concrete {
                Some(r) if r.q >= best_wild => {
                    Negotiated::Face(format!("{}/{}", r.kind, r.subtype))
                }
                _ => Negotiated::Default,
            };
        }
        let mut winner: Option<(&String, Match)> = None;
        for face in &self.served {
            let Some(matched) = match_of(face, &ranges) else {
                continue;
            };
            if matched.q <= 0.0 {
                continue;
            }
            let better = match winner {
                None => true,
                Some((current, best)) => {
                    matched.q > best.q
                        || (matched.q == best.q
                            && Some(face) == self.default.as_ref()
                            && current != face)
                }
            };
            if better {
                winner = Some((face, matched));
            }
        }
        match winner {
            None => Negotiated::NotAcceptable,
            Some((face, matched))
                if Some(face) == self.default.as_ref()
                    && matched.tolerated_only(self.default_declared) =>
            {
                Negotiated::Default
            }
            Some((face, _)) => Negotiated::Face(face.clone()),
        }
    }
}

/// How the range that decided a face's quality named it. Ordered least to most specific,
/// so the derived `Ord` is the "most specific range wins" rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MatchedBy {
    /// `*/*` — this client reads anything, so it tolerates the face without asking for it.
    AnyWildcard,
    /// `type/*` — narrower, but still not a request for this particular face.
    TypeWildcard,
    /// `type/subtype` — the client named this face. That is a request, not tolerance.
    Name,
}

/// One face's standing with a client: how it was named and at what quality.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Match {
    by: MatchedBy,
    q: f32,
}

impl Match {
    /// Is this face merely TOLERATED — matched by a wildcard rather than named — so that
    /// letting the resource answer with its own default serves the client as well as
    /// naming the face would? `default_is_declared` says whether the resource told us what
    /// its default face is: when it did not, only `*/*` is broad enough to be sure the
    /// unknown default is acceptable, because a `type/*` client excludes whole types.
    fn tolerated_only(&self, default_is_declared: bool) -> bool {
        match self.by {
            MatchedBy::Name => false,
            MatchedBy::TypeWildcard => default_is_declared,
            MatchedBy::AnyWildcard => true,
        }
    }
}

/// One media range from `Accept`, lowercased, with its quality weight.
#[derive(Debug, PartialEq)]
struct MediaRange {
    kind: String,
    subtype: String,
    q: f32,
}

/// Parse a whole `Accept` header. A bare `*` (sent by some older clients) reads as `*/*`. A
/// range that is not `type/subtype`, or whose `q` is not a number in 0..=1, is dropped rather
/// than guessed at — an unreadable preference is no preference.
fn parse_accept(accept: &str) -> Vec<MediaRange> {
    let mut ranges = Vec::new();
    for part in accept.split(',') {
        let mut pieces = part.split(';');
        let media = pieces.next().unwrap_or("").trim().to_ascii_lowercase();
        if media.is_empty() {
            continue;
        }
        let (kind, subtype) = match media.split_once('/') {
            Some((k, s)) if !k.trim().is_empty() && !s.trim().is_empty() => {
                (k.trim().to_string(), s.trim().to_string())
            }
            None if media == "*" => ("*".to_string(), "*".to_string()),
            _ => continue,
        };
        if kind == "*" && subtype != "*" {
            continue;
        }
        let mut q = 1.0_f32;
        let mut readable = true;
        for param in pieces {
            if let Some((name, value)) = param.split_once('=') {
                if name.trim().eq_ignore_ascii_case("q") {
                    match value.trim().parse::<f32>() {
                        Ok(v) if (0.0..=1.0).contains(&v) => q = v,
                        _ => readable = false,
                    }
                }
            }
        }
        if readable {
            ranges.push(MediaRange { kind, subtype, q });
        }
    }
    ranges
}

/// How a client's `Accept` matches one face: the weight of the most specific range that
/// matches it and how that range named it, or `None` when no range matches at all.
fn match_of(face: &str, ranges: &[MediaRange]) -> Option<Match> {
    let (kind, subtype) = face.split_once('/').unwrap_or((face, ""));
    let mut best: Option<Match> = None;
    for r in ranges {
        let by = if r.kind == kind && r.subtype == subtype {
            MatchedBy::Name
        } else if r.kind == kind && r.subtype == "*" {
            MatchedBy::TypeWildcard
        } else if r.kind == "*" && r.subtype == "*" {
            MatchedBy::AnyWildcard
        } else {
            continue;
        };
        // The most specific range decides; among equally specific ranges, the first stated.
        if best.is_none_or(|b| by > b.by) {
            best = Some(Match { by, q: r.q });
        }
    }
    best
}

/// A media type without parameters, lowercased.
fn bare_media(media: &str) -> String {
    media
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// 406: the client named what it can read and this resource serves none of it. The body
/// lists the faces it does serve, so the next request can be right.
fn not_acceptable(faces: &Faces, explicit: Option<&str>, req: &HttpRequest) -> Resp {
    let asked = match explicit {
        Some(asked) => format!("as={asked}"),
        None => format!("Accept: {}", req.header("accept").unwrap_or("")),
    };
    Resp::text(
        406,
        "Not Acceptable",
        &format!(
            "not acceptable ({asked}); this resource serves one of {}",
            faces.served.join(", ")
        ),
    )
}

/// The representation's media type as a header value.
fn media_type_of(repr: &ikigai_core::Representation) -> String {
    repr.repr_type.to_string()
}

/// `?description` → project the resource's `describe()` into an API description. Today this
/// emits OpenAPI 3.1 (JSON) — the format a code-on-demand client turns into a form; Hydra
/// (`application/ld+json`) and the raw Turtle manifold are the conneg follow-ups.
///
/// Only `offered` is projected — the actions this request's capability is offered (see
/// `offered_actions`). A resource with no description, and one offering this capability no
/// projectable action, answer the SAME 404, byte for byte: telling them apart would tell a
/// caller what exists beyond its authority.
fn describe_response(
    desc: Option<&ikigai_core::Description>,
    offered: &[ikigai_core::ActionSpec],
    path: &str,
    head_only: bool,
) -> Resp {
    let projectable = offered
        .iter()
        .any(|a| matches!(a.verb, Verb::Source | Verb::Sink | Verb::Delete));
    let Some(desc) = desc.filter(|_| projectable) else {
        let mut resp = Resp::text(404, "Not Found", "no such resource to describe");
        // HEAD carries no body on the refusal either; `Resp::text` does not know the method.
        if head_only {
            resp.body.clear();
        }
        return resp;
    };
    let body = serde_json::to_vec_pretty(&openapi_of(desc, offered, path)).unwrap_or_default();
    Resp {
        content_type: "application/vnd.oai.openapi+json; charset=utf-8".to_string(),
        body: if head_only { Vec::new() } else { body },
        etag: None,
        ..Resp::status(200, "OK")
    }
}

/// Project a [`Description`](ikigai_core::Description) to a minimal OpenAPI 3.1 document at
/// `path`: one operation per action in `actions` (Source→get, Sink→post, Delete→delete), with
/// a write verb's inputs as the request-body schema and a read verb's as query parameters.
/// `actions` is the caller's offered subset, never simply `desc.action_specs()`.
fn openapi_of(
    desc: &ikigai_core::Description,
    actions: &[ikigai_core::ActionSpec],
    path: &str,
) -> serde_json::Value {
    use ikigai_core::Verb;
    use serde_json::{json, Map, Value};

    let mut ops = Map::new();
    for action in actions {
        let method = match action.verb {
            Verb::Source => "get",
            Verb::Sink => "post",
            Verb::Delete => "delete",
            _ => continue, // Meta / Exists aren't projected as HTTP operations
        };
        let mut op = Map::new();
        // A summary is required by strict linters; fall back to a synthesized one.
        let summary = if action.summary.is_empty() {
            format!("{} {path}", method.to_uppercase())
        } else {
            action.summary.clone()
        };
        op.insert("summary".to_string(), json!(summary));
        op.insert("operationId".to_string(), json!(operation_id(method, path)));
        if action.verb == Verb::Sink {
            let (props, required) = schema_properties(&action.inputs);
            op.insert(
                "requestBody".to_string(),
                json!({
                    "content": { "application/json": {
                        "schema": { "type": "object", "properties": props, "required": required }
                    } }
                }),
            );
        } else {
            let params: Vec<Value> = action
                .inputs
                .iter()
                .filter(|a| !ADAPTER_OWNED.contains(&a.name.as_str()))
                .map(|a| {
                    json!({
                        "name": a.name,
                        "in": "query",
                        "required": a.required,
                        "description": a.summary,
                        "schema": arg_schema(a),
                    })
                })
                .collect();
            if !params.is_empty() {
                op.insert("parameters".to_string(), json!(params));
            }
        }
        op.insert(
            "responses".to_string(),
            json!({
                "200": { "description": "OK" },
                "400": { "description": "Bad Request" },
                "404": { "description": "Not Found" }
            }),
        );
        ops.insert(method.to_string(), Value::Object(op));
    }

    let title = if desc.title.is_empty() {
        desc.id.clone()
    } else {
        desc.title.clone()
    };
    json!({
        "openapi": "3.1.0",
        "info": { "title": title, "version": "0", "description": desc.summary },
        // A relative server → "same origin as this document", valid regardless of scheme/host.
        "servers": [ { "url": "/" } ],
        "paths": { path: Value::Object(ops) }
    })
}

/// A stable `operationId` from the method + path, e.g. `get_host_history`.
fn operation_id(method: &str, path: &str) -> String {
    let slug: String = path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("{method}{}", slug.trim_end_matches('_'))
        .trim_end_matches('_')
        .to_string()
}

/// The JSON-Schema object properties + required list for a set of inputs (a write's body).
///
/// **Order is part of the contract.** `properties` comes out in the order the endpoint's
/// author declared the inputs, because that order is the intended reading order of a form
/// generated from it — adjacent fields were meant to be adjacent. This holds only because
/// the workspace enables serde_json's `preserve_order`; without it `Map` is a `BTreeMap`
/// and the keys silently alphabetize on the way out while `required` (a `Vec`) does not,
/// which is exactly the asymmetry that gave this away. Pinned by
/// `description_projects_properties_in_declaration_order`.
/// Input names this ADAPTER owns, and which therefore must not be projected as a query
/// parameter or a request-body property.
///
/// Both are already reserved on the way IN (see `handle`: an `?as=` or `?content=` on the
/// query string is dropped, and a write's body becomes `content`), so projecting them on the
/// way OUT describes a call no client can make. `content` matters most: an endpoint that
/// declares it — which the module recipe asks every mutating action to do, and which
/// `ikigai-conformance`'s PIPELINE check enforces — would otherwise appear in its own
/// request body as a property named `content`, i.e. the body inside the body. `as` is the
/// same mistake on the read side: it is the `Accept` header here, not a query parameter.
const ADAPTER_OWNED: &[&str] = &["as", "content"];

fn schema_properties(inputs: &[ikigai_core::ArgSpec]) -> (serde_json::Value, Vec<String>) {
    use serde_json::{Map, Value};
    let mut props = Map::new();
    let mut required = Vec::new();
    for a in inputs
        .iter()
        .filter(|a| !ADAPTER_OWNED.contains(&a.name.as_str()))
    {
        props.insert(a.name.clone(), arg_schema(a));
        if a.required {
            required.push(a.name.clone());
        }
    }
    (Value::Object(props), required)
}

/// One input's JSON-Schema: type from its `class` (XSD datatype), `enum` from `one_of`,
/// `default`, and its summary as the description.
fn arg_schema(a: &ikigai_core::ArgSpec) -> serde_json::Value {
    use serde_json::{json, Map, Value};
    let ty = a.class.as_deref().map(xsd_to_json_type).unwrap_or("string");
    let mut s = Map::new();
    s.insert("type".to_string(), json!(ty));
    if !a.summary.is_empty() {
        s.insert("description".to_string(), json!(a.summary));
    }
    if !a.one_of.is_empty() {
        s.insert("enum".to_string(), json!(a.one_of));
    }
    if let Some(d) = &a.default {
        s.insert("default".to_string(), json!(d));
    }
    Value::Object(s)
}

/// Map an XSD datatype IRI to a JSON-Schema primitive type (default `string`).
fn xsd_to_json_type(class: &str) -> &'static str {
    match class {
        c if c.ends_with("#integer") || c.ends_with("#int") || c.ends_with("#long") => "integer",
        c if c.ends_with("#boolean") => "boolean",
        c if c.ends_with("#decimal") || c.ends_with("#double") || c.ends_with("#float") => "number",
        _ => "string",
    }
}

/// Parse the request line + headers (body is read separately). Header names are lowercased.
///
/// The request target is decoded from the RAW BYTES, never from a lossy string: a lossy
/// conversion turns one invalid byte into a three-byte U+FFFD, and a decoder that then slices
/// the string by byte offset splits that character and panics (ledger #80). The refusal
/// names what was wrong; every refusal is a `400`.
fn parse_head(head: &[u8]) -> Result<HttpRequest, &'static str> {
    const MALFORMED: &str = "malformed request";
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(head.len());
    let mut parts = head[..line_end]
        .split(|b| b.is_ascii_whitespace())
        .filter(|p| !p.is_empty());
    let method = std::str::from_utf8(parts.next().ok_or(MALFORMED)?)
        .map_err(|_| MALFORMED)?
        .to_string();
    let target = parts.next().ok_or(MALFORMED)?;
    let (raw_path, query_str) = match target.iter().position(|b| *b == b'?') {
        Some(q) => (&target[..q], &target[q + 1..]),
        None => (target, &b""[..]),
    };
    let path = decode_path(raw_path)?;
    let mut query = Vec::new();
    for kv in query_str.split(|b| *b == b'&').filter(|s| !s.is_empty()) {
        let (k, v) = match kv.iter().position(|b| *b == b'=') {
            Some(eq) => (&kv[..eq], &kv[eq + 1..]),
            None => (kv, &b""[..]),
        };
        query.push((decode_form(k)?, decode_form(v)?));
    }
    let rest = head.get(line_end + 2..).unwrap_or_default();
    let headers = String::from_utf8_lossy(rest)
        .split("\r\n")
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        })
        .collect();
    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
        body: Vec::new(),
        peer: None,
    })
}

/// The value of one ASCII hex digit, or `None`. Deliberately not `u8::from_str_radix`, which
/// accepts a leading sign and so decoded `%+1` as byte 1 (ledger #591).
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode `raw` as BYTES. A `%` must be followed by exactly two hex digits; anything
/// else (`%`, `%4`, `%zz`, `%+1`, `%` before a non-ASCII byte) is refused rather than passed
/// through, since a server that guesses at a malformed escape and a proxy in front of it that
/// guesses differently disagree about what was asked for. `plus_is_space` is form encoding,
/// and only a query string is form-encoded.
fn percent_decode(raw: &[u8], plus_is_space: bool) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'%' => {
                let hi = raw.get(i + 1).copied().and_then(hex_digit);
                let lo = raw.get(i + 2).copied().and_then(hex_digit);
                match (hi, lo) {
                    (Some(hi), Some(lo)) => out.push(hi << 4 | lo),
                    _ => return Err("malformed percent-escape"),
                }
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Percent-decode, then validate UTF-8 once, over the whole decoded value.
fn decode_utf8(raw: &[u8], plus_is_space: bool) -> Result<String, &'static str> {
    String::from_utf8(percent_decode(raw, plus_is_space)?).map_err(|_| "not UTF-8 once decoded")
}

/// A query key or value: `application/x-www-form-urlencoded`, so `+` is a space.
fn decode_form(raw: &[u8]) -> Result<String, &'static str> {
    decode_utf8(raw, true)
}

/// The path, split on `/` FIRST and each segment decoded on its own (RFC 3986 §2.2: an
/// encoded delimiter is data). `+` stays `+`. The decoded segments are re-joined into the one
/// string [`HttpRequest::path`] carries, with a `/` or `%` inside a segment kept escaped so
/// [`path_segments`] can split it back without a client-encoded slash becoming a separator.
fn decode_path(raw: &[u8]) -> Result<String, &'static str> {
    let mut out = String::with_capacity(raw.len());
    for (n, seg) in raw.split(|b| *b == b'/').enumerate() {
        if n > 0 {
            out.push('/');
        }
        for c in decode_utf8(seg, false)?.chars() {
            match c {
                '%' => out.push_str("%25"),
                '/' => out.push_str("%2F"),
                c => out.push(c),
            }
        }
    }
    Ok(out)
}

/// The decoded segments of an [`HttpRequest::path`] — the inverse of [`decode_path`]'s
/// escaping. Empty segments (a leading, trailing or doubled `/`) are dropped, as they always
/// were. Only the two escapes `decode_path` writes are undone; any other `%` is literal.
fn path_segments(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|seg| {
            let mut out = String::with_capacity(seg.len());
            let mut rest = seg;
            while let Some(at) = rest.find('%') {
                out.push_str(&rest[..at]);
                let tail = &rest[at..];
                rest = if let Some(after) = tail
                    .strip_prefix("%2F")
                    .or_else(|| tail.strip_prefix("%2f"))
                {
                    out.push('/');
                    after
                } else if let Some(after) = tail.strip_prefix("%25") {
                    out.push('%');
                    after
                } else {
                    out.push('%');
                    &tail[1..]
                };
            }
            out.push_str(rest);
            out
        })
        .collect()
}

/// The argument names the transport owns on a write. A request may carry them in its
/// query string, but they are dropped there — provenance the submitter can author is
/// not provenance. `principal` is reserved even on a door with no [`PrincipalFn`]: a
/// submitter must not be able to name a principal that no door authenticated.
fn is_provenance(name: &str) -> bool {
    name == "received" || name == "client" || name == "principal"
}

/// The submitter's address.
///
/// Untrusted, this is the socket peer: the only address nobody can lie about. Behind a
/// proxy we trust (`--trust-proxy`), the peer is the proxy, so `X-Forwarded-For` carries
/// the real client — but note it is the LAST entry we want, not the first. A proxy that
/// appends leaves any header the client itself sent sitting in front of the hop the proxy
/// actually observed; the leftmost entries are attacker-authored. With one trusted hop,
/// the rightmost entry is the address our proxy saw the connection come from.
fn client_ip(req: &HttpRequest, config: &EdgeConfig) -> Option<String> {
    if config.trust_proxy {
        if let Some(forwarded) = req.header("x-forwarded-for") {
            if let Some(hop) = forwarded.rsplit(',').map(str::trim).find(|h| !h.is_empty()) {
                return Some(hop.to_string());
            }
        }
    }
    req.peer.map(|ip| ip.to_string())
}

/// Now, as RFC 3339 UTC — the lexical form `urn:tz:*` and the schedulers already parse.
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// [`write`] under a deadline: a client that stops reading cannot hold the connection past
/// `limit`. On expiry the connection is simply dropped — there is no one left to tell.
async fn write_within(
    sock: &mut TcpStream,
    resp: Resp,
    limit: std::time::Duration,
) -> std::io::Result<()> {
    match tokio::time::timeout(limit, write(sock, resp)).await {
        Ok(done) => done,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "response write took too long",
        )),
    }
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
    if !resp.vary.is_empty() {
        head.push_str(&format!("Vary: {}\r\n", resp.vary.join(", ")));
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
        ActionSpec, ArgSpec, Description, EndpointSpace, Error, Exact, FnEndpoint, Invocation,
        ReprType, Representation, UriTemplate,
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
        // A resource whose STATE refuses a write: readable, but every Sink is a Conflict.
        let board = FnEndpoint::new("board", |inv: &Invocation<'_>| {
            if inv.request.verb == Verb::Source {
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"X..".to_vec(),
                ))
            } else {
                Err(Error::Conflict("1,1 is taken".into()))
            }
        })
        .with_description(
            Description::new("board")
                .verb(Verb::Source)
                .verb(Verb::Sink),
        );
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
        // An availability-shaped resource: GET reads it, POST books against it, with declared
        // inputs (the `?description` → OpenAPI source).
        let booking = FnEndpoint::new("booking", |_inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("application/json"),
                b"{}".to_vec(),
            ))
        })
        .with_description(
            Description::new("booking")
                .title("Availability")
                .verb(Verb::Source)
                .verb(Verb::Sink)
                .input(
                    ArgSpec::new("slot")
                        .class("http://www.w3.org/2001/XMLSchema#dateTime")
                        .summary("the requested time"),
                )
                .input(ArgSpec::new("timezone").summary("an IANA zone"))
                .input(ArgSpec::new("email"))
                .input(
                    ArgSpec::new("preference")
                        .optional()
                        .one_of(["morning", "afternoon"]),
                ),
        );
        // Echoes back the provenance the transport attached, so a test can see exactly what
        // the endpoint was told about who called and when. A Delete answers 204 with no body
        // whatever the endpoint returns, so on that verb the echo rides the one channel a
        // Delete response does carry: the error body (`error_resp` renders `{e}`).
        let provenance = FnEndpoint::new("provenance", |inv: &Invocation<'_>| {
            let seen = format!(
                "received={} client={} principal={}",
                inv.inline_str("received").unwrap_or("-"),
                inv.inline_str("client").unwrap_or("-"),
                inv.inline_str("principal").unwrap_or("-")
            );
            if inv.request.verb == Verb::Delete {
                return Err(Error::Denied(seen));
            }
            Ok(Representation::new(
                ReprType::new("text/plain"),
                seen.into_bytes(),
            ))
        })
        .with_description(
            Description::new("provenance")
                .verb(Verb::Source)
                .verb(Verb::Sink)
                .verb(Verb::Delete),
        );
        // Negotiation fixtures: each echoes the `as` it was handed, or `default` when none.
        let echo_as = |inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                inv.inline_str("as")
                    .unwrap_or("default")
                    .as_bytes()
                    .to_vec(),
            ))
        };
        // Two faces declared the way the ledger declares them: an `as` with `one_of`.
        let faces = FnEndpoint::new("faces", echo_as).with_description(
            Description::new("faces").verb(Verb::Source).input(
                ArgSpec::new("as")
                    .optional()
                    .one_of(["text/plain", "text/turtle"])
                    .default_value("text/plain"),
            ),
        );
        // One face, declared only as an output.
        let plain_only = FnEndpoint::new("plain-only", echo_as).with_description(
            Description::new("plain-only")
                .verb(Verb::Source)
                .output("text/plain"),
        );
        // ★ The FOAF shape: several faces declared FLAT as outputs, HTML first, no `as`
        // input at all — and a default representation (`application/rdf+xml`, the document
        // itself) that is NOT the first declared output. Declaration order is a reading
        // order, not a statement about what the resource returns when asked for nothing in
        // particular, and the adapter must not read it as one. Echoes the `as` it was
        // handed (or its own default when it was handed none) and the `fragment` flag,
        // which rides the same request as an ordinary query argument.
        let foaf_shaped = FnEndpoint::new("foaf-shaped", |inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!(
                    "as={} fragment={}",
                    inv.inline_str("as").unwrap_or("application/rdf+xml"),
                    inv.inline_str("fragment").unwrap_or("-")
                )
                .into_bytes(),
            ))
        })
        .with_description(
            Description::new("foaf-shaped")
                .verb(Verb::Source)
                .output("text/html")
                .output("application/rdf+xml")
                .output("application/ld+json")
                .output("text/turtle"),
        );
        // No faces declared at all.
        let undeclared = FnEndpoint::new("undeclared", echo_as)
            .with_description(Description::new("undeclared").verb(Verb::Source));
        // Capability-scoped `?description` fixtures. `sealed` requires one scope for its only
        // verb; `split` requires a different scope per verb, the way a calendar's read and
        // write do; `tpl` is template-bound, so its manifold row is a pattern, not its IRI.
        let sealed = FnEndpoint::new("sealed", echo_as).with_description(
            Description::new("sealed").title("Sealed").action(
                ActionSpec::new(Verb::Source)
                    .summary("read the sealed thing")
                    .requires("urn:cap:test:sealed"),
            ),
        );
        let split = FnEndpoint::new("split", echo_as).with_description(
            Description::new("split")
                .action(
                    ActionSpec::new(Verb::Source)
                        .summary("read")
                        .requires("urn:cap:test:split:read"),
                )
                .action(
                    ActionSpec::new(Verb::Sink)
                        .summary("write")
                        .input(ArgSpec::new("content"))
                        .requires("urn:cap:test:split:write"),
                ),
        );
        let tpl = FnEndpoint::new("tpl", echo_as).with_description(
            Description::new("tpl").action(
                ActionSpec::new(Verb::Source)
                    .summary("read one")
                    .input(ArgSpec::new("name").binding()),
            ),
        );
        // The target IRI as the kernel saw it — how a test observes what a path decoded to.
        let seg = FnEndpoint::new("seg", |inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                inv.request.target.as_str().as_bytes().to_vec(),
            ))
        })
        .with_description(Description::new("seg").verb(Verb::Source));
        // A representation far larger than any socket buffer, so a client that never reads
        // it leaves the server's write blocked.
        let big = FnEndpoint::new("big", |_inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("application/octet-stream"),
                vec![0u8; 32 * 1024 * 1024],
            ))
        })
        .with_description(Description::new("big").verb(Verb::Source));
        let space = EndpointSpace::new()
            .bind(UriTemplate::parse("urn:test:seg:{key}").unwrap(), seg)
            .bind(Exact::new("urn:test:big"), big)
            .bind(Exact::new("urn:test:board"), board)
            .bind(Exact::new("urn:test:sealed"), sealed)
            .bind(Exact::new("urn:test:split"), split)
            .bind(UriTemplate::parse("urn:test:tpl:{name}").unwrap(), tpl)
            .bind(Exact::new("urn:test:faces"), faces)
            .bind(Exact::new("urn:test:plain-only"), plain_only)
            .bind(Exact::new("urn:test:foaf-shaped"), foaf_shaped)
            .bind(Exact::new("urn:test:undeclared"), undeclared)
            .bind(Exact::new("urn:test:provenance"), provenance)
            .bind(Exact::new("urn:test:booking"), booking)
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
        let mut c = connect(addr).await;
        c.write_all(raw.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    // Connect to the (already-listening) test server. The listener is bound before its addr
    // is handed out, so the first attempt normally lands in the accept backlog; the bounded
    // retry is belt-and-suspenders against a transient loopback hiccup under CI load, so a
    // single dropped SYN never fails the whole test.
    async fn connect(addr: SocketAddr) -> TcpStream {
        let mut last = None;
        for _ in 0..50 {
            match TcpStream::connect(addr).await {
                Ok(sock) => return sock,
                Err(e) => {
                    last = Some(e);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
        panic!("could not connect to {addr}: {}", last.unwrap());
    }

    async fn start() -> SocketAddr {
        start_with(EdgeConfig::default()).await
    }

    async fn start_with(config: EdgeConfig) -> SocketAddr {
        start_with_cap(config, public_cap()).await
    }

    async fn start_with_cap(config: EdgeConfig, cap_fn: CapFn) -> SocketAddr {
        // Bind the ephemeral port here and hand the live listener to the server. Because the
        // socket is already listening before we return `addr`, any connect the caller makes
        // queues in the accept backlog — there is no bind/rebind window and no need to sleep
        // hoping the server is up. Deterministic in place of the old drop-and-rebind race.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let kernel = test_kernel();
        tokio::spawn(async move {
            let _ = serve_with_listener(kernel, cap_fn, listener, config).await;
        });
        addr
    }

    #[tokio::test]
    async fn a_write_carries_the_connections_provenance() {
        let addr = start().await;
        let out = roundtrip(
            addr,
            "POST /test/provenance HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi",
        )
        .await;
        // The clock's stamp, and the loopback peer the socket actually reported.
        assert!(
            out.contains("received=20") && out.contains("client=127.0.0.1"),
            "provenance should reach the endpoint: {out}"
        );
    }

    #[tokio::test]
    async fn a_read_carries_no_provenance_so_it_stays_cacheable() {
        let addr = start().await;
        let out = roundtrip(addr, "GET /test/provenance HTTP/1.1\r\nHost: x\r\n\r\n").await;
        // A per-request timestamp is part of the content address; on a read it would give
        // every GET a distinct cache key.
        assert!(
            out.contains("received=- client=-"),
            "a read must not be stamped: {out}"
        );
    }

    #[tokio::test]
    async fn provenance_in_the_query_string_cannot_forge_an_origin() {
        let addr = start().await;
        let out = roundtrip(
            addr,
            "POST /test/provenance?client=1.2.3.4&received=1999-01-01T00:00:00Z HTTP/1.1\r\n\
             Host: x\r\nContent-Length: 2\r\n\r\nhi",
        )
        .await;
        assert!(
            !out.contains("1.2.3.4") && !out.contains("1999"),
            "the submitter's own claim must be dropped: {out}"
        );
        assert!(out.contains("client=127.0.0.1"), "the socket wins: {out}");
    }

    // A door whose hook names every connection `p`.
    fn naming_door() -> EdgeConfig {
        let door: PrincipalFn = Arc::new(|_req: &HttpRequest| Some("p".to_string()));
        EdgeConfig {
            principal_fn: Some(door),
            ..EdgeConfig::default()
        }
    }

    #[tokio::test]
    async fn a_write_carries_the_principal_the_door_authenticated() {
        let addr = start_with(naming_door()).await;
        let out = roundtrip(
            addr,
            "POST /test/provenance HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi",
        )
        .await;
        assert!(
            out.contains("principal=p"),
            "the hook's answer should reach the endpoint: {out}"
        );
    }

    #[tokio::test]
    async fn a_delete_carries_the_principal_too() {
        // Provenance is a rule over MUTATING verbs, not over Sink: a Delete is stamped exactly
        // as a Sink is.
        let addr = start_with(naming_door()).await;
        let out = roundtrip(addr, "DELETE /test/provenance HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(
            out.contains("principal=p") && out.contains("received=20"),
            "a Delete is stamped like a Sink: {out}"
        );
    }

    #[tokio::test]
    async fn a_read_carries_no_principal_so_the_cache_is_not_partitioned_by_identity() {
        let addr = start_with(naming_door()).await;
        let out = roundtrip(addr, "GET /test/provenance HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(
            out.contains("principal=-"),
            "a read must not carry the principal: {out}"
        );
    }

    #[tokio::test]
    async fn a_door_without_a_principal_stamps_none() {
        // Both absent hook and a hook that declines: the request is exactly today's.
        let declining: PrincipalFn = Arc::new(|_req: &HttpRequest| None);
        for config in [
            EdgeConfig::default(),
            EdgeConfig {
                principal_fn: Some(declining),
                ..EdgeConfig::default()
            },
        ] {
            let addr = start_with(config).await;
            let out = roundtrip(
                addr,
                "POST /test/provenance HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi",
            )
            .await;
            assert!(
                out.contains("client=127.0.0.1 principal=-"),
                "no door, no principal: {out}"
            );
        }
    }

    #[tokio::test]
    async fn a_principal_in_the_query_string_cannot_name_an_identity() {
        // With a door: the connection's principal wins over the submitter's claim.
        let addr = start_with(naming_door()).await;
        let out = roundtrip(
            addr,
            "POST /test/provenance?principal=forged HTTP/1.1\r\nHost: x\r\n\
             Content-Length: 2\r\n\r\nhi",
        )
        .await;
        assert!(
            out.contains("principal=p") && !out.contains("forged"),
            "the door's answer wins over the submitter's claim: {out}"
        );
        // Without one: the claim is dropped and nothing replaces it. `principal` is reserved
        // whether or not a door is wired — a submitter cannot name a principal that no door
        // authenticated.
        let addr = start().await;
        let out = roundtrip(
            addr,
            "DELETE /test/provenance?principal=forged HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await;
        assert!(
            out.contains("principal=-") && !out.contains("forged"),
            "the claim is dropped even with no door: {out}"
        );
    }

    #[tokio::test]
    async fn every_provenance_name_is_reserved_on_every_mutating_verb() {
        for name in ["received", "client", "principal"] {
            assert!(is_provenance(name), "{name} is provenance");
        }
        assert!(!is_provenance("slot"), "an ordinary input is not");
        // The reservation is keyed on the VERB being mutating, not on Sink alone.
        assert!(Verb::Sink.is_mutating() && Verb::Delete.is_mutating());
        assert!(!Verb::Source.is_mutating());
    }

    #[tokio::test]
    async fn an_untrusted_forwarded_for_is_ignored() {
        let addr = start().await;
        let out = roundtrip(
            addr,
            "POST /test/provenance HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 9.9.9.9\r\n\
             Content-Length: 2\r\n\r\nhi",
        )
        .await;
        // Anyone can send that header. Without --trust-proxy it is not evidence.
        assert!(
            out.contains("client=127.0.0.1") && !out.contains("9.9.9.9"),
            "unproxied XFF must not win: {out}"
        );
    }

    #[tokio::test]
    async fn a_trusted_proxy_supplies_the_client_and_a_prepended_hop_cannot_spoof_it() {
        let addr = start_with(EdgeConfig {
            trust_proxy: true,
            ..EdgeConfig::default()
        })
        .await;
        // A client that sends its own XFF has its value APPENDED to by the proxy, so the
        // forged hop sits on the left and the address the proxy saw sits on the right.
        let out = roundtrip(
            addr,
            "POST /test/provenance HTTP/1.1\r\nHost: x\r\n\
             X-Forwarded-For: 6.6.6.6, 203.0.113.9\r\nContent-Length: 2\r\n\r\nhi",
        )
        .await;
        assert!(
            out.contains("client=203.0.113.9") && !out.contains("6.6.6.6"),
            "the rightmost hop is the one our proxy observed: {out}"
        );
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
        // `Never` revalidates against the ETag; it is never `immutable` (see
        // `cache_control_of`, and `cache_control::` below for every row).
        assert!(
            resp.contains("Cache-Control: public, no-cache\r\n"),
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

    /// ★ A Conflict (the state refuses the request) is 409 — ledger #583. It was a 500.
    #[tokio::test]
    async fn a_conflict_is_409() {
        let addr = start().await;
        let resp = roundtrip(
            addr,
            "PUT /test/board HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n1,1",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 409 Conflict\r\n"), "got: {resp}");
        assert!(resp.ends_with("conflict: 1,1 is taken"), "got: {resp}");
    }

    /// …and a precondition the CALLER stated still answers 412 on the same resource: it is
    /// checked before the write, so the endpoint never gets the chance to conflict.
    #[tokio::test]
    async fn a_failed_if_match_is_412_even_where_the_write_would_conflict() {
        let addr = start().await;
        let resp = roundtrip(
            addr,
            "PUT /test/board HTTP/1.1\r\nHost: x\r\nIf-Match: \"nope\"\r\nContent-Length: 3\r\n\r\n1,1",
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
        assert!(
            cache_control::vary_of(&resp).contains(&"Origin".to_string()),
            "got: {resp}"
        );
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
    async fn routes_only_404s_unrouted_paths_but_serves_routed_ones() {
        let addr = start_with(EdgeConfig {
            routes_only: true,
            routes: RouteTable::new(vec![plain_route("/alias", "urn:test:id:hello")]),
            ..Default::default()
        })
        .await;
        // A routed path resolves.
        let routed = roundtrip(addr, "GET /alias HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(routed.starts_with("HTTP/1.1 200 OK"), "got: {routed}");
        // An un-routed path 404s instead of hitting the mechanical default.
        let unrouted = roundtrip(addr, "GET /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(unrouted.starts_with("HTTP/1.1 404"), "got: {unrouted}");
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
    async fn description_projects_openapi() {
        let addr = start().await;
        let resp = roundtrip(
            addr,
            "GET /test/booking?description HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(
            resp.contains("Content-Type: application/vnd.oai.openapi+json"),
            "got: {resp}"
        );
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        let v: serde_json::Value = serde_json::from_str(body).expect("openapi json");
        assert_eq!(v["openapi"], "3.1.0");
        assert_eq!(v["info"]["title"], "Availability");
        assert_eq!(v["servers"][0]["url"], "/"); // a server for tooling (Swagger UI etc.)
        let op = &v["paths"]["/test/booking"];
        // Source → get (params), Sink → post (requestBody).
        assert!(op["get"].is_object() && op["post"].is_object(), "got: {v}");
        assert!(op["get"]["operationId"].is_string()); // for code generators
        assert!(op["post"]["responses"]["400"].is_object()); // a documented 4xx
        let schema = &op["post"]["requestBody"]["content"]["application/json"]["schema"];
        assert_eq!(schema["properties"]["slot"]["type"], "string"); // xsd:dateTime → string
        assert_eq!(schema["properties"]["preference"]["enum"][0], "morning");
        // slot/timezone/email required, preference optional.
        let required = schema["required"].as_array().unwrap();
        assert!(required.iter().any(|r| r == "slot") && required.iter().any(|r| r == "email"));
        assert!(!required.iter().any(|r| r == "preference"));
    }

    #[tokio::test]
    async fn description_projects_properties_in_declaration_order() {
        // The endpoint author's declaration order IS the intended reading order of a form
        // generated from `?description`: fields declared adjacently were meant to render
        // adjacently. `serde_json::Map` is a BTreeMap unless `preserve_order` is enabled, so
        // for a long time this came back alphabetized while `required` — a Vec — did not,
        // and a form generator had no way to recover what the author wrote.
        let addr = start().await;
        let resp = roundtrip(
            addr,
            "GET /test/booking?description HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await;
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        let v: serde_json::Value = serde_json::from_str(body).expect("openapi json");
        let properties = v["paths"]["/test/booking"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"]["properties"]
            .as_object()
            .expect("an object of properties");
        let projected: Vec<&str> = properties.keys().map(String::as_str).collect();

        // The order `urn:test:booking` declares its inputs in, above. Asserted whole, not as
        // a set and not as a pairwise "x before y": a future re-alphabetization has to fail
        // this, and a pairwise check would let one through whenever the pair happens to sort
        // the way it was written.
        let declared = ["slot", "timezone", "email", "preference"];
        assert_eq!(projected, declared, "got: {body}");

        // …and this declaration is deliberately not in alphabetical order, so the assertion
        // above cannot be satisfied by a sorted map. Without this, the test would quietly
        // stop testing anything the day someone reorders the fixture.
        let mut sorted = declared;
        sorted.sort_unstable();
        assert_ne!(
            declared, sorted,
            "the fixture must declare its inputs out of alphabetical order, or this test \
             passes under a BTreeMap and proves nothing"
        );
    }

    #[tokio::test]
    async fn a_merge_patch_that_deletes_a_field_leaves_the_others_in_place() {
        // Under `preserve_order`, `Map::remove` is `swap_remove` — it fills the hole with the
        // map's LAST entry. A patch removing one field would then reorder the fields it did
        // not mention, which for a document whose key order now carries meaning is a silent
        // edit nobody asked for.
        let mut target: serde_json::Value =
            serde_json::from_str(r#"{"a":1,"b":2,"c":3,"d":4}"#).unwrap();
        merge_json(&mut target, &serde_json::json!({ "b": null }));
        let keys: Vec<&str> = target
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["a", "c", "d"], "swap_remove would give a, d, c");
    }

    #[tokio::test]
    async fn description_of_unknown_resource_is_404() {
        let addr = start().await;
        let resp = roundtrip(addr, "GET /nope/x?description HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {resp}");
    }

    /// `METHOD path` under `Host: host`, as one raw HTTP/1.1 request.
    fn raw_request(method: &str, path: &str, host: &str) -> String {
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n")
    }

    /// A response's OpenAPI body, parsed.
    fn openapi_body(resp: &str) -> serde_json::Value {
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        serde_json::from_str(body).unwrap_or_else(|e| panic!("openapi json ({e}): {resp}"))
    }

    #[tokio::test]
    async fn a_description_in_scope_projects_the_offered_action() {
        let addr = start_with_cap(
            EdgeConfig::default(),
            fixed_cap(vec!["urn:cap:test:sealed".to_string()]),
        )
        .await;
        let resp = roundtrip(addr, &raw_request("GET", "/test/sealed?description", "x")).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        let v = openapi_body(&resp);
        assert_eq!(v["info"]["title"], "Sealed");
        assert_eq!(
            v["paths"]["/test/sealed"]["get"]["summary"],
            "read the sealed thing"
        );
    }

    #[tokio::test]
    async fn a_description_out_of_scope_is_byte_identical_to_a_missing_resource() {
        // Public (empty) capability: `sealed` is bound and described, but not offered.
        let addr = start().await;
        let out_of_scope =
            roundtrip(addr, &raw_request("GET", "/test/sealed?description", "x")).await;
        let missing = roundtrip(
            addr,
            &raw_request("GET", "/test/nothing-bound?description", "x"),
        )
        .await;
        assert!(
            out_of_scope.starts_with("HTTP/1.1 404"),
            "got: {out_of_scope}"
        );
        assert_eq!(
            out_of_scope, missing,
            "an out-of-scope description must not be distinguishable from an absent one"
        );
        // The mechanism, not just the outcome: resolution sees the same boundary.
        let read = roundtrip(addr, &raw_request("GET", "/test/sealed", "x")).await;
        assert!(read.starts_with("HTTP/1.1 403"), "got: {read}");
    }

    #[tokio::test]
    async fn an_emptied_capability_describes_only_what_it_could_invoke() {
        // The gonk shape: a door that answers a foreign `Host` with an EMPTY capability rather
        // than a refusal. The description face must follow it, not answer ahead of it.
        let cap: CapFn = Arc::new(|req: &HttpRequest| {
            if req.header("host") == Some("ours") {
                Capability::scoped(vec!["urn:cap:test:sealed".to_string()])
            } else {
                Capability::scoped(Vec::<String>::new())
            }
        });
        let addr = start_with_cap(EdgeConfig::default(), cap).await;
        let ours = roundtrip(
            addr,
            &raw_request("GET", "/test/sealed?description", "ours"),
        )
        .await;
        assert!(ours.starts_with("HTTP/1.1 200 OK"), "got: {ours}");
        let foreign = roundtrip(
            addr,
            &raw_request("GET", "/test/sealed?description", "evil"),
        )
        .await;
        let missing = roundtrip(
            addr,
            &raw_request("GET", "/test/nothing-bound?description", "evil"),
        )
        .await;
        assert!(foreign.starts_with("HTTP/1.1 404"), "got: {foreign}");
        assert_eq!(foreign, missing);
        // ⚠ The manifold's predicate, stated: an action requiring NOTHING is offered to the
        // empty capability — because the empty capability can invoke it. Describing it is no
        // wider than serving it; a door that wants a foreign Host to see nothing at all must
        // refuse the request, not empty its capability.
        let free = roundtrip(
            addr,
            &raw_request("GET", "/test/booking?description", "evil"),
        )
        .await;
        assert!(free.starts_with("HTTP/1.1 200 OK"), "got: {free}");
    }

    #[tokio::test]
    async fn a_multi_verb_description_is_trimmed_to_the_offered_verbs() {
        let read_only = start_with_cap(
            EdgeConfig::default(),
            fixed_cap(vec!["urn:cap:test:split:read".to_string()]),
        )
        .await;
        let v = openapi_body(
            &roundtrip(
                read_only,
                &raw_request("GET", "/test/split?description", "x"),
            )
            .await,
        );
        let ops = v["paths"]["/test/split"]
            .as_object()
            .expect("an operations object");
        assert_eq!(ops.keys().collect::<Vec<_>>(), ["get"], "got: {v}");

        let write_only = start_with_cap(
            EdgeConfig::default(),
            fixed_cap(vec!["urn:cap:test:split:write".to_string()]),
        )
        .await;
        let v = openapi_body(
            &roundtrip(
                write_only,
                &raw_request("GET", "/test/split?description", "x"),
            )
            .await,
        );
        let ops = v["paths"]["/test/split"]
            .as_object()
            .expect("an operations object");
        assert_eq!(ops.keys().collect::<Vec<_>>(), ["post"], "got: {v}");

        let both = start_with_cap(
            EdgeConfig::default(),
            fixed_cap(vec![
                "urn:cap:test:split:read".to_string(),
                "urn:cap:test:split:write".to_string(),
            ]),
        )
        .await;
        let v = openapi_body(
            &roundtrip(both, &raw_request("GET", "/test/split?description", "x")).await,
        );
        let ops = v["paths"]["/test/split"]
            .as_object()
            .expect("an operations object");
        assert_eq!(ops.keys().collect::<Vec<_>>(), ["get", "post"], "got: {v}");
    }

    #[tokio::test]
    async fn a_template_bound_resource_is_described_through_its_manifold_row() {
        // The manifold names this resource by PATTERN (`urn:test:tpl:{name}`), never by the
        // concrete IRI asked for — the row must still be recognised as this resource.
        let addr = start().await;
        let resp = roundtrip(
            addr,
            &raw_request("GET", "/test/tpl/anything?description", "x"),
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
    }

    #[tokio::test]
    async fn head_on_a_description_matches_get() {
        /// Status line and headers, minus `Content-Length` (this transport sends 0 on every
        /// HEAD, reads included), plus the body.
        fn parts(resp: &str) -> (Vec<&str>, &str) {
            let (head, body) = resp.split_once("\r\n\r\n").unwrap_or((resp, ""));
            let lines = head
                .split("\r\n")
                .filter(|l| !l.to_ascii_lowercase().starts_with("content-length:"))
                .collect();
            (lines, body)
        }
        let addr = start_with_cap(
            EdgeConfig::default(),
            fixed_cap(vec!["urn:cap:test:sealed".to_string()]),
        )
        .await;
        for path in ["/test/sealed?description", "/test/split?description"] {
            let got = roundtrip(addr, &raw_request("GET", path, "x")).await;
            let head = roundtrip(addr, &raw_request("HEAD", path, "x")).await;
            let (got_head, got_body) = parts(&got);
            let (head_head, head_body) = parts(&head);
            assert_eq!(
                got_head, head_head,
                "{path}: HEAD must carry GET's status and headers"
            );
            assert!(!got_body.is_empty(), "{path}: GET has a body");
            assert!(head_body.is_empty(), "{path}: HEAD has none, got: {head}");
        }
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

    // ---- The body bound. -------------------------------------------------------------
    //
    // The door these guard is public (bosatsu's contact and booking forms sit behind it),
    // and the reactor behind it is serial, so what a stranger can make this server read and
    // hand onward is a security property rather than a nicety.

    /// The defect these tests exist for: the bound used to `break` out of the read and then
    /// parse what it had, so an oversize body arrived at the endpoint as a SHORTER one that
    /// looked complete. Refusing is the only answer that cannot be mistaken for a
    /// submission.
    #[tokio::test]
    async fn an_oversize_body_is_refused_rather_than_quietly_cut_down_to_the_bound() {
        let addr = start_with(EdgeConfig {
            max_body_bytes: 64,
            ..Default::default()
        })
        .await;
        let body = "x".repeat(100);
        let out = roundtrip(
            addr,
            &format!(
                "PUT /test/writable HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 413 "), "got: {out}");
        // The endpoint echoes what it was handed. Nothing was handed to it.
        assert!(
            !out.contains("xxxx"),
            "a refused body must not reach the endpoint at all, got: {out}"
        );
    }

    /// `Content-Length` is checked BEFORE the body is read, which is what makes the bound
    /// worth having: the refusal has to cost nothing.
    ///
    /// This test proves the ordering rather than asserting it. It declares 50 MB and then
    /// sends two bytes, holding the connection open. A server that read up to the declared
    /// length before deciding would block here until the test timed out; a prompt 413 is
    /// only reachable by deciding on the header alone.
    #[tokio::test]
    async fn a_declared_length_over_the_bound_is_refused_without_reading_the_body() {
        let addr = start().await;
        let out = roundtrip(
            addr,
            "PUT /test/writable HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: 50000000\r\n\r\nhi",
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 413 "), "got: {out}");
    }

    /// The bound is a ceiling, not a target: a body that exactly reaches it is ordinary.
    #[tokio::test]
    async fn a_body_at_the_bound_is_delivered_whole() {
        let addr = start_with(EdgeConfig {
            max_body_bytes: 64,
            ..Default::default()
        })
        .await;
        let body = "y".repeat(64);
        let out = roundtrip(
            addr,
            &format!(
                "PUT /test/writable HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: 64\r\n\r\n{body}"
            ),
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 200 "), "got: {out}");
        assert!(
            out.ends_with(&body),
            "all 64 bytes should reach the endpoint, got: {out}"
        );
    }

    /// `chunked` carries its length in the body. Ignoring it meant `Content-Length` was
    /// absent, so the bound never applied AND the endpoint was handed the chunk framing as
    /// if a person had typed it.
    #[tokio::test]
    async fn a_chunked_body_is_refused_rather_than_delivered_as_its_own_framing() {
        let addr = start().await;
        let out = roundtrip(
            addr,
            "PUT /test/writable HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 501 "), "got: {out}");
        assert!(
            !out.contains("hello"),
            "the chunk framing must not reach the endpoint as content, got: {out}"
        );
    }

    /// A `Content-Length` that will not parse is a disagreement about framing. Reading it as
    /// zero delivered whatever trailed the headers in the read buffer instead.
    #[tokio::test]
    async fn a_malformed_content_length_is_a_framing_error_not_an_empty_body() {
        let addr = start().await;
        let out = roundtrip(
            addr,
            "PUT /test/writable HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: eleven\r\n\r\nhello",
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 400 "), "got: {out}");
        assert!(!out.contains("hello"), "got: {out}");
    }

    /// A body SHORTER than declared is the same defect from the other side: the client
    /// hung up mid-submission, and handing the endpoint what arrived would let a partial
    /// form read as a complete one.
    #[tokio::test]
    async fn a_body_shorter_than_declared_is_refused_rather_than_delivered_partial() {
        let addr = start().await;
        let mut c = connect(addr).await;
        // Declares twenty bytes, sends five, then closes the write half — the shape of a
        // submission cut off in flight.
        c.write_all(
            b"PUT /test/writable HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: 20\r\n\r\nhello",
        )
        .await
        .unwrap();
        c.shutdown().await.unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).await.unwrap();
        let out = String::from_utf8_lossy(&out).into_owned();
        assert!(out.starts_with("HTTP/1.1 400 "), "got: {out}");
        assert!(
            !out.ends_with("hello"),
            "a partial body must not reach the endpoint, got: {out}"
        );
    }

    /// The body is exactly what the client declared. Bytes past `Content-Length` are the
    /// next pipelined request, and appending them to this one let a client add content the
    /// framing said was not part of it.
    #[tokio::test]
    async fn the_body_is_cut_to_the_length_the_client_declared() {
        let addr = start().await;
        let out = roundtrip(
            addr,
            "PUT /test/writable HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhelloAND MORE",
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 200 "), "got: {out}");
        assert!(
            out.ends_with("hello"),
            "only the declared five bytes are the body, got: {out}"
        );
    }

    // Real headers, verbatim. A suite that only ever sends `*/*` is exactly how a
    // browser-refusing adapter shipped: curl's header matches everything.
    const CHROME: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,\
                          image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
    const FIREFOX: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    const SAFARI: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    const CURL: &str = "*/*";

    async fn get(addr: SocketAddr, path: &str, accept: Option<&str>) -> String {
        let accept = accept
            .map(|a| format!("Accept: {a}\r\n"))
            .unwrap_or_default();
        roundtrip(
            addr,
            &format!("GET {path} HTTP/1.1\r\nHost: x\r\n{accept}\r\n"),
        )
        .await
    }

    /// The `/test/faces` shape: two faces and a DECLARED default (`as` … `default_value`).
    fn two_faces() -> Faces {
        Faces {
            served: vec!["text/plain".into(), "text/turtle".into()],
            default: Some("text/plain".into()),
            default_declared: true,
        }
    }

    /// Every browser's navigation header, curl's, and none at all reach a resource that
    /// serves only plain text and Turtle — and each is answered by its DEFAULT face, not
    /// refused. This is the defect: the first type (`text/html`) used to be forced as `as`.
    #[tokio::test]
    async fn every_browser_curl_and_no_accept_get_the_default_face() {
        let addr = start().await;
        for (who, accept) in [
            ("chrome", Some(CHROME)),
            ("firefox", Some(FIREFOX)),
            ("safari", Some(SAFARI)),
            ("curl", Some(CURL)),
            ("none", None),
        ] {
            let out = get(addr, "/test/faces", accept).await;
            assert!(out.starts_with("HTTP/1.1 200 "), "{who}: {out}");
            assert!(
                out.ends_with("default"),
                "{who} gets the default face: {out}"
            );
            let out = get(addr, "/test/plain-only", accept).await;
            assert!(
                out.starts_with("HTTP/1.1 200 "),
                "{who} on plain-only: {out}"
            );
        }
    }

    /// ★ The regression #333 shipped (0.1.22, caught on the live `urn:iki:foaf` edge): a
    /// resource that declares its faces as flat `outputs` and whose own default is NOT the
    /// first of them lost every face it declared first. A browser asks for `text/html`
    /// CONCRETELY and at top quality; the adapter picked `text/html`, saw it equal the face
    /// it had GUESSED was the default (the first output), and sent no `as` at all — so the
    /// resource answered with its own default, `application/rdf+xml`, and the HTML page was
    /// unreachable over `Accept` while `?as=text/html` still worked.
    #[tokio::test]
    async fn a_concretely_asked_face_is_named_even_when_it_is_the_first_declared_output() {
        let addr = start().await;
        for (who, accept) in [
            ("chrome", CHROME),
            ("firefox", FIREFOX),
            ("safari", SAFARI),
            ("a bare header", "text/html"),
        ] {
            let out = get(addr, "/test/foaf-shaped", Some(accept)).await;
            assert!(out.starts_with("HTTP/1.1 200 "), "{who}: {out}");
            assert!(
                out.ends_with("as=text/html fragment=-"),
                "{who} asked for HTML by name: {out}"
            );
        }
        // The other faces were never broken — they are not the guessed default.
        for face in ["application/ld+json", "text/turtle"] {
            let out = get(addr, "/test/foaf-shaped", Some(face)).await;
            assert!(out.ends_with(&format!("as={face} fragment=-")), "{out}");
        }
        // A client with no face preference still gets the resource's OWN default, not the
        // first declared output: `*/*` and no `Accept` are not requests for HTML.
        for (who, accept) in [("curl", Some(CURL)), ("no accept", None)] {
            let out = get(addr, "/test/foaf-shaped", accept).await;
            assert!(
                out.ends_with("as=application/rdf+xml fragment=-"),
                "{who}: {out}"
            );
        }
    }

    /// The fragment face is the same request with one more query argument: it broke with
    /// the page face and comes back with it, rather than being a second code path here.
    #[tokio::test]
    async fn a_query_argument_rides_along_with_the_negotiated_face() {
        let addr = start().await;
        let out = get(addr, "/test/foaf-shaped?fragment=1", Some(CHROME)).await;
        assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
        assert!(out.ends_with("as=text/html fragment=1"), "{out}");
    }

    /// A concrete preference for a served face is honoured, by quality, not by position.
    #[tokio::test]
    async fn a_preferred_served_face_is_handed_to_the_resource() {
        let addr = start().await;
        let out = get(addr, "/test/faces", Some("text/turtle")).await;
        assert!(out.ends_with("text/turtle"), "{out}");
        let out = get(
            addr,
            "/test/faces",
            Some("text/plain;q=0.2, text/turtle;q=0.9"),
        )
        .await;
        assert!(
            out.ends_with("text/turtle"),
            "higher q wins over position: {out}"
        );
        // q=0 is "not acceptable": plain is excluded, so turtle answers via `*/*`.
        let out = get(addr, "/test/faces", Some("text/plain;q=0, */*")).await;
        assert!(out.ends_with("text/turtle"), "{out}");
    }

    /// Explicit stays strict: asking ONLY for a face the resource does not serve is a 406
    /// that lists what it does serve — not a 400, and not a substituted default.
    #[tokio::test]
    async fn nothing_acceptable_is_406_listing_the_faces() {
        let addr = start().await;
        let out = get(addr, "/test/plain-only", Some("text/turtle")).await;
        assert!(out.starts_with("HTTP/1.1 406 "), "{out}");
        assert!(out.contains("text/plain"), "the faces are listed: {out}");
        let out = get(addr, "/test/faces", Some("text/html")).await;
        assert!(out.starts_with("HTTP/1.1 406 "), "{out}");
        assert!(out.contains("text/plain, text/turtle"), "{out}");
        let out = get(addr, "/test/faces", Some("text/plain;q=0, text/turtle;q=0")).await;
        assert!(out.starts_with("HTTP/1.1 406 "), "all excluded: {out}");
    }

    /// `?as=` is an explicit face selection and beats `Accept` — a link in a page cannot set
    /// a header. A face the resource does not serve is refused the same way `Accept` is.
    #[tokio::test]
    async fn a_query_as_beats_accept_and_is_checked_against_the_faces() {
        let addr = start().await;
        let out = get(addr, "/test/faces?as=text/turtle", Some(CHROME)).await;
        assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
        assert!(out.ends_with("text/turtle"), "{out}");
        let out = get(addr, "/test/faces?as=text/html", Some(CURL)).await;
        assert!(out.starts_with("HTTP/1.1 406 "), "{out}");
        assert!(
            out.contains("as=text/html"),
            "the refusal names what was asked: {out}"
        );
    }

    /// A resource that declares no faces cannot be negotiated for, so it is never refused:
    /// it is handed the client's most preferred concrete type, which only it can judge.
    #[tokio::test]
    async fn an_undeclared_resource_is_handed_the_preferred_type_and_never_refused() {
        let addr = start().await;
        let out = get(addr, "/test/undeclared", Some(CHROME)).await;
        assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
        assert!(out.ends_with("text/html"), "{out}");
        let out = get(addr, "/test/undeclared", Some(CURL)).await;
        assert!(out.ends_with("default"), "{out}");
        let out = get(addr, "/test/undeclared", Some("text/csv;q=0.1, */*")).await;
        assert!(
            out.ends_with("default"),
            "a preferred wildcard is no preference: {out}"
        );
    }

    /// A path nothing is bound to is a 404, not a 500 — nothing broke, nothing is here.
    #[tokio::test]
    async fn an_unrouted_path_is_404_not_500() {
        let addr = start().await;
        for accept in [Some(CHROME), Some(CURL), None] {
            let out = get(addr, "/nothing/bound/here", accept).await;
            assert!(out.starts_with("HTTP/1.1 404 "), "{out}");
        }
        let out = get(addr, "/", Some(CHROME)).await;
        assert!(out.starts_with("HTTP/1.1 404 "), "{out}");
    }

    #[test]
    fn accept_parses_every_range_with_its_quality() {
        let ranges = parse_accept(CHROME);
        assert_eq!(ranges.len(), 8);
        assert_eq!(
            ranges[6],
            MediaRange {
                kind: "*".into(),
                subtype: "*".into(),
                q: 0.8
            }
        );
        // A non-q parameter is not a quality: signed-exchange keeps its own q=0.7.
        assert_eq!(ranges[7].q, 0.7);
        // A bare `*`, case, whitespace; malformed ranges and weights are dropped.
        let ranges = parse_accept(" Text/HTML ; Q=0.5 ,*, nonsense, text/plain;q=2, */x");
        assert_eq!(
            ranges,
            vec![
                MediaRange {
                    kind: "text".into(),
                    subtype: "html".into(),
                    q: 0.5
                },
                MediaRange {
                    kind: "*".into(),
                    subtype: "*".into(),
                    q: 1.0
                },
            ]
        );
        assert!(parse_accept("").is_empty());
    }

    #[test]
    fn negotiation_follows_the_most_specific_matching_range() {
        let faces = two_faces();
        for header in [CHROME, FIREFOX, SAFARI, CURL] {
            assert_eq!(
                faces.negotiate(Some(header)),
                Negotiated::Default,
                "{header}"
            );
        }
        assert_eq!(faces.negotiate(None), Negotiated::Default);
        assert_eq!(faces.negotiate(Some("")), Negotiated::Default);
        // `text/*` matches both; the tie goes to the default.
        assert_eq!(faces.negotiate(Some("text/*")), Negotiated::Default);
        // The specific range decides even when a broader one is heavier.
        assert_eq!(
            faces.negotiate(Some("text/*;q=1, text/plain;q=0.1")),
            Negotiated::Face("text/turtle".into())
        );
        assert_eq!(faces.negotiate(Some("image/*")), Negotiated::NotAcceptable);
        // The default is not always reachable by wildcard; a matching face still is.
        let faces = Faces {
            served: vec!["text/plain".into(), "application/ld+json".into()],
            default: Some("text/plain".into()),
            default_declared: true,
        };
        assert_eq!(
            faces.negotiate(Some("application/*")),
            Negotiated::Face("application/ld+json".into())
        );
    }

    /// Whether the default face was DECLARED or GUESSED decides how far tolerance goes.
    /// A resource that named its default can answer a `text/*` client with it; one whose
    /// default this adapter merely guessed from declaration order cannot be trusted to —
    /// its real default may be a type that `text/*` excludes, and nothing can ask it — so
    /// the winning face is named instead. `*/*` admits anything, so both elide.
    #[test]
    fn a_guessed_default_is_named_unless_the_client_reads_anything() {
        assert_eq!(two_faces().negotiate(Some("text/*")), Negotiated::Default);
        // The FOAF shape: faces read off `outputs`, so the default is a guess.
        let guessed = Faces {
            served: vec![
                "text/html".into(),
                "application/rdf+xml".into(),
                "text/turtle".into(),
            ],
            default: Some("text/html".into()),
            default_declared: false,
        };
        assert_eq!(guessed.negotiate(Some(CURL)), Negotiated::Default);
        assert_eq!(guessed.negotiate(None), Negotiated::Default);
        assert_eq!(
            guessed.negotiate(Some("text/*")),
            Negotiated::Face("text/html".into()),
            "a guessed default cannot answer a client that excludes whole types"
        );
        assert_eq!(
            guessed.negotiate(Some(CHROME)),
            Negotiated::Face("text/html".into()),
            "named concretely at the top quality: a request, not tolerance"
        );
    }

    #[test]
    fn faces_are_read_from_as_one_of_before_outputs() {
        let desc = Description::new("x")
            .verb(Verb::Source)
            .output("text/html")
            .input(
                ArgSpec::new("as")
                    .one_of(["text/plain", "Text/Turtle; charset=utf-8"])
                    .default_value("text/turtle"),
            );
        let faces = Faces::declared(Some(&desc), Verb::Source);
        assert_eq!(faces.served, vec!["text/plain", "text/turtle"]);
        assert_eq!(faces.default.as_deref(), Some("text/turtle"));
        assert!(faces.default_declared, "the resource named its default");
        let desc = Description::new("y")
            .verb(Verb::Source)
            .output("text/html")
            .output("application/json");
        // Flat `.output()` faces ARE the declaration for a verb with no explicit
        // `ActionSpec` — core synthesizes one from the flat fields. The default, though,
        // is only this adapter's guess at declaration order.
        let faces = Faces::declared(Some(&desc), Verb::Source);
        assert_eq!(faces.served, vec!["text/html", "application/json"]);
        assert_eq!(faces.default.as_deref(), Some("text/html"));
        assert!(!faces.default_declared, "nothing declared a default face");
        assert!(Faces::declared(None, Verb::Source).served.is_empty());
        // Faces are per verb: a Sink-only description declares none for Source.
        let desc = Description::new("z").verb(Verb::Sink).output("text/plain");
        assert!(Faces::declared(Some(&desc), Verb::Source).served.is_empty());
    }

    // ---- the request target's decoder (ledger #80, #591) ----

    #[test]
    fn the_decoder_refuses_every_malformed_escape() {
        let cases: [&[u8]; 11] = [
            b"%",
            b"%4",
            b"%zz",
            b"%+1",
            b"%-1",
            b"%\xff",
            b"%4\xff",
            b"a%",
            b"%%41",
            b"%\xc3\xa9",
            b"% 1",
        ];
        for bad in cases {
            assert!(percent_decode(bad, false).is_err(), "path form: {bad:?}");
            assert!(percent_decode(bad, true).is_err(), "form form: {bad:?}");
        }
    }

    #[test]
    fn the_decoder_works_on_bytes_and_validates_utf8_once() {
        assert_eq!(decode_utf8(b"caf%C3%A9", false).unwrap(), "caf\u{e9}");
        // One character split between an escape and a raw byte is still one character: the
        // UTF-8 check runs over the decoded whole, not per escape.
        assert_eq!(decode_utf8(b"caf%C3\xa9", false).unwrap(), "caf\u{e9}");
        assert_eq!(decode_utf8(b"caf\xc3\xa9", false).unwrap(), "caf\u{e9}");
        assert!(decode_utf8(b"%FF", false).is_err());
        assert!(decode_utf8(b"\xff", false).is_err());
        assert!(decode_utf8(b"%C3", false).is_err(), "a truncated sequence");
        assert_eq!(decode_utf8(b"%4a%4A", false).unwrap(), "JJ");
        assert_eq!(decode_utf8(b"a+b", false).unwrap(), "a+b");
        assert_eq!(decode_utf8(b"a+b", true).unwrap(), "a b");
        assert_eq!(decode_utf8(b"a%2Bb", true).unwrap(), "a+b");
    }

    #[test]
    fn plus_is_a_space_in_the_query_and_a_plus_in_the_path() {
        let req = parse_head(b"GET /a+b/c?k+1=v+1&x=%2B HTTP/1.1\r\nHost: x").unwrap();
        assert_eq!(req.path, "/a+b/c");
        assert_eq!(
            req.query,
            vec![
                ("k 1".to_string(), "v 1".to_string()),
                ("x".to_string(), "+".to_string())
            ]
        );
    }

    #[test]
    fn an_encoded_slash_stays_inside_its_segment() {
        let path = decode_path(b"/test/seg/a%2Fb").unwrap();
        assert_eq!(path, "/test/seg/a%2Fb");
        assert_eq!(path_segments(&path), ["test", "seg", "a/b"]);
        assert_eq!(iri_from_path(&path), "urn:test:seg:a/b");
        assert_eq!(path_segments(&decode_path(b"/a%2fb").unwrap()), ["a/b"]);
        // A literal `%` round-trips, and an escaped escape is never decoded twice.
        let path = decode_path(b"/x/100%25/a%252Fb").unwrap();
        assert_eq!(path_segments(&path), ["x", "100%", "a%2Fb"]);
        // Routing splits the same way: an encoded slash cannot add a segment. This is the
        // link gonk's `percent` builds for a hostile ledger name.
        let table = RouteTable::new(vec![plain_route(
            "/l/{ledger}/item/{id}",
            "urn:x:{ledger}:{id}",
        )]);
        let hit = table
            .match_path(&decode_path(b"/l/..%2F..%2Fetc/item/244").unwrap())
            .expect("four segments, so the route matches");
        assert_eq!(hit.iri, "urn:x:../../etc:244");
        assert!(table
            .match_path(&decode_path(b"/l/a/b/item/1").unwrap())
            .is_none());
    }

    /// Exhaustive over the two bytes after a `%`, in the path, a query key and a query value:
    /// each of the 65,536 pairs either decodes to exactly its character or is refused, and
    /// none panics. Before ledger #80 a raw non-ASCII byte here panicked the connection.
    #[test]
    fn every_byte_pair_after_a_percent_decodes_or_is_refused() {
        for hi in 0..=255u8 {
            for lo in 0..=255u8 {
                let expect = match (hex_digit(hi), hex_digit(lo)) {
                    (Some(h), Some(l)) if (h << 4 | l) < 0x80 => Some(char::from(h << 4 | l)),
                    _ => None,
                };
                for place in 0..3 {
                    let mut head = b"GET ".to_vec();
                    head.extend_from_slice(match place {
                        0 => &b"/p/"[..],
                        1 => b"/p?",
                        _ => b"/p?k=",
                    });
                    head.extend_from_slice(&[b'%', hi, lo]);
                    head.extend_from_slice(b" HTTP/1.1\r\nHost: x");
                    let got = parse_head(&head);
                    match expect {
                        None => assert!(got.is_err(), "{hi:#04x} {lo:#04x} at {place}"),
                        Some(c) => {
                            let req = got
                                .unwrap_or_else(|e| panic!("{hi:#04x} {lo:#04x} at {place}: {e}"));
                            let decoded = match place {
                                0 => path_segments(&req.path)[1].clone(),
                                1 => req.query[0].0.clone(),
                                _ => req.query[0].1.clone(),
                            };
                            assert_eq!(decoded, c.to_string(), "{hi:#04x} {lo:#04x} at {place}");
                        }
                    }
                }
            }
        }
    }

    async fn roundtrip_bytes(addr: SocketAddr, raw: &[u8]) -> String {
        let mut c = connect(addr).await;
        c.write_all(raw).await.unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn a_malformed_target_is_400_over_the_socket_and_the_server_lives_on() {
        let addr = start().await;
        // (target, Some(body) for a 200 that echoes it, None for a 400)
        let cases: [(&[u8], Option<&str>); 20] = [
            (b"/test/echo?name=%", None),
            (b"/test/echo?name=%4", None),
            (b"/test/echo?name=%zz", None),
            (b"/test/echo?name=%+1", None),
            (b"/test/echo?name=%-1", None),
            (b"/test/echo?name=%\xff", None),
            (b"/test/echo?name=%FF", None),
            (b"/test/echo?%zz=1", None),
            (b"/test/echo?%\xc3\xa9=1", None),
            (b"/test/%\xc3\xa9cho", None),
            (b"/test/ech%", None),
            (b"/test/%+1", None),
            (b"/test/\xff", None),
            (b"/test/echo?name=a+b", Some("a b")),
            (b"/test/echo?name=a%2Bb", Some("a+b")),
            (b"/test/echo?name=caf%C3%A9", Some("caf\u{e9}")),
            (b"/test/echo?name=%26%3D", Some("&=")),
            (b"/test/%65cho?name=x", Some("x")),
            (b"/test/seg/a+b", Some("urn:test:seg:a+b")),
            (b"/test/seg/a%2Fb", Some("urn:test:seg:a/b")),
        ];
        for (target, expect) in cases {
            let mut raw = b"GET ".to_vec();
            raw.extend_from_slice(target);
            raw.extend_from_slice(b" HTTP/1.1\r\nHost: x\r\n\r\n");
            let resp = roundtrip_bytes(addr, &raw).await;
            let shown = String::from_utf8_lossy(target);
            match expect {
                None => assert!(resp.starts_with("HTTP/1.1 400 "), "{shown}: {resp}"),
                Some(body) => {
                    assert!(resp.starts_with("HTTP/1.1 200 "), "{shown}: {resp}");
                    assert!(
                        resp.ends_with(&format!("\r\n\r\n{body}")),
                        "{shown}: {resp}"
                    );
                }
            }
        }
        let alive = roundtrip(addr, "GET /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(alive.starts_with("HTTP/1.1 200 OK"), "{alive}");
    }

    // ---- time and concurrency bounds (ledger #80) ----

    #[test]
    fn the_bounds_default_to_explicit_finite_values() {
        let config = EdgeConfig::default();
        assert_eq!(config.header_timeout, std::time::Duration::from_secs(10));
        assert_eq!(config.body_timeout, std::time::Duration::from_secs(30));
        assert_eq!(config.write_timeout, std::time::Duration::from_secs(30));
        assert_eq!(config.max_connections, 256);
    }

    fn short(ms: u64) -> std::time::Duration {
        std::time::Duration::from_millis(ms)
    }

    /// Read until the server hangs up, failing the test (instead of hanging it) if it never
    /// does — the failure this whole section exists to prevent.
    async fn read_until_closed(sock: &mut (impl AsyncReadExt + Unpin)) -> String {
        let mut out = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            sock.read_to_end(&mut out),
        )
        .await
        .expect("the server must hang up rather than wait on the client forever")
        .unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn a_slow_loris_header_trickle_is_cut_off_at_the_deadline_with_408() {
        let addr = start_with(EdgeConfig {
            header_timeout: short(300),
            ..EdgeConfig::default()
        })
        .await;
        let (mut rx, mut tx) = connect(addr).await.into_split();
        // A byte every 50 ms, never the blank line: an IDLE timeout would never fire, so this
        // proves the deadline is on the whole header read.
        let trickle = tokio::spawn(async move {
            let _ = tx.write_all(b"GET /test/id/hello HTTP/1.1\r\n").await;
            for _ in 0..400 {
                if tx.write_all(b"X").await.is_err() {
                    break;
                }
                tokio::time::sleep(short(50)).await;
            }
        });
        // The trickle outlasts `read_until_closed`'s own 10 s bound, so only a deadline on the
        // whole read can make the server hang up in time.
        let resp = read_until_closed(&mut rx).await;
        assert!(resp.starts_with("HTTP/1.1 408 "), "{resp}");
        trickle.abort();
    }

    #[tokio::test]
    async fn a_body_that_never_arrives_is_408_at_the_body_deadline() {
        let addr = start_with(EdgeConfig {
            body_timeout: short(300),
            ..EdgeConfig::default()
        })
        .await;
        let mut c = connect(addr).await;
        c.write_all(b"PUT /test/writable HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc")
            .await
            .unwrap();
        let resp = read_until_closed(&mut c).await;
        assert!(resp.starts_with("HTTP/1.1 408 "), "{resp}");
    }

    /// Retry a plain GET until it is served, proving a slot came back. Every answer before
    /// that must be the cap's `503` — never a reset, which would mean the refusal was lost.
    async fn served_eventually(addr: SocketAddr) -> String {
        for _ in 0..250 {
            let answer = roundtrip(addr, "GET /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
            if answer.starts_with("HTTP/1.1 200 ") {
                return answer;
            }
            assert!(answer.starts_with("HTTP/1.1 503 "), "{answer}");
            tokio::time::sleep(short(40)).await;
        }
        panic!("the slot never came back");
    }

    #[tokio::test]
    async fn a_connection_past_the_cap_is_503_and_the_slot_comes_back() {
        let addr = start_with(EdgeConfig {
            max_connections: 1,
            ..EdgeConfig::default()
        })
        .await;
        // The holder is accepted first (the accept loop is sequential and FIFO) and takes the
        // one permit; half a request line keeps it inside the header read.
        let mut holder = connect(addr).await;
        holder.write_all(b"GET /test/id/hello").await.unwrap();
        // The refused client sends a whole request, as a real one does. It is never handled,
        // and the lingering close is what lets the 503 reach it instead of a reset.
        let mut refused = connect(addr).await;
        refused
            .write_all(b"GET /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let busy = read_until_closed(&mut refused).await;
        assert!(busy.starts_with("HTTP/1.1 503 "), "{busy}");
        assert!(busy.contains("Retry-After: 1\r\n"), "{busy}");
        drop(holder);
        let ok = served_eventually(addr).await;
        assert!(ok.ends_with("hi"), "{ok}");
    }

    #[tokio::test]
    async fn a_client_that_stops_reading_releases_its_slot_at_the_write_deadline() {
        let addr = start_with(EdgeConfig {
            max_connections: 1,
            write_timeout: short(300),
            ..EdgeConfig::default()
        })
        .await;
        // Ask for 32 MiB and never read a byte of it: the write blocks on a full socket.
        let mut stalled = connect(addr).await;
        stalled
            .write_all(b"GET /test/big HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        // Without the write deadline this slot is held for as long as `stalled` lives.
        let ok = served_eventually(addr).await;
        assert!(ok.ends_with("hi"), "{ok}");
        drop(stalled);
    }

    /// `Cache-Control`, `Vary` and revalidation, over a real socket (ledger #604, and the cli
    /// half of ledger #570). A kernel of its own, so every row of `cache_control_of`'s table
    /// has exactly one resource standing for it.
    mod cache_control {
        use super::*;
        use ikigai_core::{Expiry, Time};
        use std::sync::Mutex;

        /// Wall-clock now in milliseconds, which an `Expiry::At` deadline is measured against.
        fn now_ms() -> u64 {
            // Native-only test: a deadline relative to the wall clock the edge also reads.
            #[allow(clippy::disallowed_methods)]
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            now
        }

        fn text(body: &[u8]) -> Representation {
            Representation::new(ReprType::new("text/plain"), body.to_vec())
        }

        /// The kernel: one resource per row of the table, a ledger-shaped pair (a log a Sink
        /// appends to, and a read that hangs from the log's thread), and a resource whose
        /// answer depends on the capability.
        fn kernel() -> Arc<Kernel> {
            let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec!["one".to_string()]));
            // `Never`, and nothing but its own target's thread (which the kernel adds).
            let pure =
                FnEndpoint::new(
                    "pure",
                    |_inv: &Invocation<'_>| Ok(text(b"pure").cacheable()),
                )
                .with_description(Description::new("pure").verb(Verb::Source));
            // The ledger's shape: a cacheable read over state a DIFFERENT resource writes,
            // hanging from that resource's thread, so a write there cuts it.
            let items = {
                let log = Arc::clone(&log);
                FnEndpoint::new("items", move |_inv: &Invocation<'_>| {
                    let body = log.lock().unwrap().join("\n");
                    Ok(text(body.as_bytes())
                        .cacheable()
                        .depends_on("urn:test:c:append"))
                })
                .with_description(Description::new("items").verb(Verb::Source))
            };
            let append = {
                let log = Arc::clone(&log);
                FnEndpoint::new("append", move |inv: &Invocation<'_>| {
                    let entry = inv.inline_str("content").unwrap_or("").to_string();
                    log.lock().unwrap().push(entry);
                    Ok(text(b""))
                })
                .with_description(Description::new("append").verb(Verb::Sink))
            };
            let in_two_minutes = || Expiry::At(Time::from_millis(now_ms() + 120_000));
            // A deadline, and nothing a write could cut.
            let deadline = FnEndpoint::new("deadline", move |_inv: &Invocation<'_>| {
                Ok(text(b"deadline").with_expiry(in_two_minutes()))
            })
            .with_description(Description::new("deadline").verb(Verb::Source));
            // A deadline AND a thread another resource's write cuts.
            let deadline_threaded =
                FnEndpoint::new("deadline-threaded", move |_inv: &Invocation<'_>| {
                    Ok(text(b"deadline")
                        .with_expiry(in_two_minutes())
                        .depends_on("urn:test:c:append"))
                })
                .with_description(Description::new("deadline-threaded").verb(Verb::Source));
            // A deadline on a resource that can be WRITTEN: its own thread is cut by a Sink.
            let deadline_writable =
                FnEndpoint::new("deadline-writable", move |_inv: &Invocation<'_>| {
                    Ok(text(b"deadline").with_expiry(in_two_minutes()))
                })
                .with_description(
                    Description::new("deadline-writable")
                        .verb(Verb::Source)
                        .verb(Verb::Sink),
                );
            // A deadline already behind us.
            let lapsed = FnEndpoint::new("lapsed", |_inv: &Invocation<'_>| {
                Ok(text(b"lapsed").with_expiry(Expiry::At(Time::from_millis(now_ms() - 1_000))))
            })
            .with_description(Description::new("lapsed").verb(Verb::Source));
            // The default `Always`.
            let volatile =
                FnEndpoint::new("volatile", |_inv: &Invocation<'_>| Ok(text(b"volatile")))
                    .with_description(Description::new("volatile").verb(Verb::Source));
            // An answer the capability shapes, cacheable like everything the kernel keys on it.
            let whoami = FnEndpoint::new("whoami", |inv: &Invocation<'_>| {
                let who: &[u8] = if inv.capability.allows("urn:cap:member") {
                    b"member"
                } else {
                    b"anonymous"
                };
                Ok(text(who).cacheable())
            })
            .with_description(Description::new("whoami").verb(Verb::Source));
            // Two faces, so `Accept` chooses between them.
            let faces = FnEndpoint::new("faces", |inv: &Invocation<'_>| {
                Ok(text(inv.inline_str("as").unwrap_or("text/plain").as_bytes()).cacheable())
            })
            .with_description(
                Description::new("faces").verb(Verb::Source).input(
                    ArgSpec::new("as")
                        .optional()
                        .one_of(["text/plain", "text/turtle"])
                        .default_value("text/plain"),
                ),
            );
            // Exactly one face, so `Accept` chooses nothing.
            let one_face = FnEndpoint::new("one-face", |_inv: &Invocation<'_>| {
                Ok(text(b"one").cacheable())
            })
            .with_description(
                Description::new("one-face")
                    .verb(Verb::Source)
                    .output("text/plain"),
            );
            let space = EndpointSpace::new()
                .bind(Exact::new("urn:test:c:pure"), pure)
                .bind(Exact::new("urn:test:c:items"), items)
                .bind(Exact::new("urn:test:c:append"), append)
                .bind(Exact::new("urn:test:c:deadline"), deadline)
                .bind(
                    Exact::new("urn:test:c:deadline-threaded"),
                    deadline_threaded,
                )
                .bind(
                    Exact::new("urn:test:c:deadline-writable"),
                    deadline_writable,
                )
                .bind(Exact::new("urn:test:c:lapsed"), lapsed)
                .bind(Exact::new("urn:test:c:volatile"), volatile)
                .bind(Exact::new("urn:test:c:whoami"), whoami)
                .bind(Exact::new("urn:test:c:faces"), faces)
                .bind(Exact::new("urn:test:c:one-face"), one_face);
            Arc::new(Kernel::new(Arc::new(space)))
        }

        /// A door that grants `urn:cap:member` to a request carrying the good session cookie
        /// or the good bearer token, and nothing to anyone else.
        fn door() -> CapFn {
            Arc::new(|req: &HttpRequest| {
                let cookie = req
                    .header("cookie")
                    .is_some_and(|c| c.contains("session=good"));
                let bearer = req.header("authorization") == Some("Bearer good");
                if cookie || bearer {
                    Capability::scoped(vec!["urn:cap:member".to_string()])
                } else {
                    Capability::scoped(Vec::<String>::new())
                }
            })
        }

        async fn serve(config: EdgeConfig) -> SocketAddr {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let kernel = kernel();
            tokio::spawn(async move {
                let _ = serve_with_listener(kernel, door(), listener, config).await;
            });
            addr
        }

        async fn get(addr: SocketAddr, path: &str, extra: &str) -> String {
            roundtrip(
                addr,
                &format!("GET {path} HTTP/1.1\r\nHost: x\r\n{extra}\r\n"),
            )
            .await
        }

        /// The one `Cache-Control` header of a raw response.
        fn cache_control(resp: &str) -> String {
            let found: Vec<&str> = resp
                .lines()
                .filter_map(|l| l.strip_prefix("Cache-Control: "))
                .collect();
            assert_eq!(found.len(), 1, "exactly one Cache-Control: {resp}");
            found[0].to_string()
        }

        /// The names in the one `Vary` header of a raw response (none → empty).
        pub(super) fn vary_of(resp: &str) -> Vec<String> {
            let found: Vec<&str> = resp
                .lines()
                .filter_map(|l| l.strip_prefix("Vary: "))
                .collect();
            assert!(found.len() <= 1, "Vary is written once: {resp}");
            found
                .first()
                .map(|v| v.split(',').map(|n| n.trim().to_string()).collect())
                .unwrap_or_default()
        }

        fn etag(resp: &str) -> String {
            resp.lines()
                .find_map(|l| l.strip_prefix("ETag: "))
                .unwrap_or_else(|| panic!("no ETag: {resp}"))
                .to_string()
        }

        fn body(resp: &str) -> &str {
            resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
        }

        // --- the table, row by row -------------------------------------------------------

        #[tokio::test]
        async fn always_is_no_store() {
            let addr = serve(EdgeConfig::default()).await;
            let resp = get(addr, "/test/c/volatile", "").await;
            assert_eq!(cache_control(&resp), "no-store", "{resp}");
        }

        #[tokio::test]
        async fn never_hanging_from_a_foreign_thread_is_no_cache() {
            // The live defect: the ledger's `items` answered `public, max-age=31536000,
            // immutable`, so a browser kept the list it first saw.
            let addr = serve(EdgeConfig::default()).await;
            let resp = get(addr, "/test/c/items", "").await;
            assert_eq!(cache_control(&resp), "public, no-cache", "{resp}");
        }

        #[tokio::test]
        async fn never_with_only_its_own_thread_is_still_no_cache_never_immutable() {
            // The control the brief asked for, inverted on the evidence: a `Never` answer that
            // no write can cut is as close to immutable as the kernel can say, and it is
            // still not `immutable`, because the kernel's `Never` ends at a restart and HTTP's
            // `immutable` does not. The standalone server's `urn:repo:style` is this shape.
            let addr = serve(EdgeConfig::default()).await;
            let resp = get(addr, "/test/c/pure", "").await;
            assert_eq!(cache_control(&resp), "public, no-cache", "{resp}");
            assert!(!resp.contains("immutable"), "{resp}");
        }

        #[tokio::test]
        async fn a_deadline_nothing_can_cut_is_max_age_until_it() {
            let addr = serve(EdgeConfig::default()).await;
            let resp = get(addr, "/test/c/deadline", "").await;
            let cc = cache_control(&resp);
            let secs: u64 = cc
                .strip_prefix("public, max-age=")
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("expected public, max-age=N: {resp}"));
            assert!((100..=120).contains(&secs), "about two minutes: {cc}");
        }

        #[tokio::test]
        async fn a_deadline_with_a_thread_is_no_cache() {
            let addr = serve(EdgeConfig::default()).await;
            let resp = get(addr, "/test/c/deadline-threaded", "").await;
            assert_eq!(cache_control(&resp), "public, no-cache", "{resp}");
        }

        #[tokio::test]
        async fn a_deadline_on_a_writable_resource_is_no_cache() {
            // Its only thread is its own, and a write to it cuts exactly that.
            let addr = serve(EdgeConfig::default()).await;
            let resp = get(addr, "/test/c/deadline-writable", "").await;
            assert_eq!(cache_control(&resp), "public, no-cache", "{resp}");
        }

        #[tokio::test]
        async fn a_lapsed_deadline_is_no_cache() {
            let addr = serve(EdgeConfig::default()).await;
            let resp = get(addr, "/test/c/lapsed", "").await;
            assert_eq!(cache_control(&resp), "public, no-cache", "{resp}");
        }

        #[test]
        fn the_projection_covers_every_row_for_both_audiences() {
            let now = 1_000_000_000;
            let later = Expiry::At(Time::from_millis(now + 60_000));
            let earlier = Expiry::At(Time::from_millis(now - 1));
            for (shared, scope) in [(true, "public"), (false, "private")] {
                let contained = Freshness {
                    self_contained: true,
                    shared,
                };
                let threaded = Freshness {
                    self_contained: false,
                    shared,
                };
                assert_eq!(cache_control_of(Expiry::Always, contained, now), "no-store");
                assert_eq!(
                    cache_control_of(Expiry::Never, contained, now),
                    format!("{scope}, no-cache")
                );
                assert_eq!(
                    cache_control_of(Expiry::Never, threaded, now),
                    format!("{scope}, no-cache")
                );
                assert_eq!(
                    cache_control_of(later, contained, now),
                    format!("{scope}, max-age=60")
                );
                assert_eq!(
                    cache_control_of(later, threaded, now),
                    format!("{scope}, no-cache")
                );
                assert_eq!(
                    cache_control_of(earlier, contained, now),
                    format!("{scope}, no-cache")
                );
            }
        }

        // --- who may share it ------------------------------------------------------------

        #[tokio::test]
        async fn an_anonymous_answer_is_public() {
            let addr = serve(EdgeConfig::default()).await;
            let resp = get(addr, "/test/c/whoami", "").await;
            assert_eq!(body(&resp), "anonymous");
            assert_eq!(cache_control(&resp), "public, no-cache", "{resp}");
        }

        #[tokio::test]
        async fn a_session_cookie_that_grants_more_makes_it_private() {
            let addr = serve(EdgeConfig::default()).await;
            let resp = get(
                addr,
                "/test/c/whoami",
                "Cookie: theme=dark; session=good\r\n",
            )
            .await;
            assert_eq!(body(&resp), "member");
            assert_eq!(cache_control(&resp), "private, no-cache", "{resp}");
        }

        #[tokio::test]
        async fn a_bearer_token_that_grants_more_makes_it_private() {
            let addr = serve(EdgeConfig::default()).await;
            let resp = get(addr, "/test/c/whoami", "Authorization: Bearer good\r\n").await;
            assert_eq!(body(&resp), "member");
            assert_eq!(cache_control(&resp), "private, no-cache", "{resp}");
        }

        #[tokio::test]
        async fn a_credential_that_grants_nothing_leaves_it_public() {
            // It is the capability that decides, not the presence of a header: an expired or
            // bogus session grants what an anonymous caller holds, so anyone may share it.
            let addr = serve(EdgeConfig::default()).await;
            let resp = get(addr, "/test/c/whoami", "Cookie: session=expired\r\n").await;
            assert_eq!(body(&resp), "anonymous");
            assert_eq!(cache_control(&resp), "public, no-cache", "{resp}");
        }

        #[tokio::test]
        async fn a_route_that_pins_the_capability_is_public_and_does_not_vary_on_credentials() {
            let addr = serve(EdgeConfig {
                routes: RouteTable::new(vec![Route {
                    pattern: "/members/whoami".to_string(),
                    iri_template: "urn:test:c:whoami".to_string(),
                    cap: Some(vec!["urn:cap:member".to_string()]),
                    cors: None,
                    csp: None,
                }]),
                ..EdgeConfig::default()
            })
            .await;
            // Every caller holds the route's ceiling, so the good cookie changes nothing.
            let resp = get(addr, "/members/whoami", "Cookie: session=good\r\n").await;
            assert_eq!(body(&resp), "member");
            assert_eq!(cache_control(&resp), "public, no-cache", "{resp}");
            let vary = vary_of(&resp);
            assert!(!vary.contains(&"Cookie".to_string()), "{resp}");
            assert!(!vary.contains(&"Authorization".to_string()), "{resp}");
        }

        // --- Vary ------------------------------------------------------------------------

        #[tokio::test]
        async fn vary_names_accept_and_the_credential_headers_on_a_negotiated_read() {
            let addr = serve(EdgeConfig::default()).await;
            let resp = get(addr, "/test/c/faces", "Accept: text/turtle\r\n").await;
            assert_eq!(body(&resp), "text/turtle");
            assert_eq!(
                vary_of(&resp),
                ["Accept", "Authorization", "Cookie"],
                "{resp}"
            );
        }

        #[tokio::test]
        async fn vary_leaves_out_accept_when_the_url_names_the_face() {
            // `?as=` is in the URL, which every cache keys on already.
            let addr = serve(EdgeConfig::default()).await;
            let resp = get(
                addr,
                "/test/c/faces?as=text/turtle",
                "Accept: text/plain\r\n",
            )
            .await;
            assert_eq!(body(&resp), "text/turtle");
            assert_eq!(vary_of(&resp), ["Authorization", "Cookie"], "{resp}");
        }

        #[tokio::test]
        async fn vary_leaves_out_accept_when_there_is_one_face() {
            let addr = serve(EdgeConfig::default()).await;
            let resp = get(addr, "/test/c/one-face", "Accept: text/plain\r\n").await;
            assert_eq!(vary_of(&resp), ["Authorization", "Cookie"], "{resp}");
        }

        #[tokio::test]
        async fn vary_names_origin_whenever_cors_is_open_even_without_an_origin() {
            // A same-origin answer carries no Access-Control-Allow-Origin; a cross-origin one
            // does. Without `Origin` in Vary a cache hands the first to the second.
            let addr = serve(EdgeConfig {
                cors: CorsPolicy {
                    allowed_origins: vec!["https://app.example".to_string()],
                    ..Default::default()
                },
                ..EdgeConfig::default()
            })
            .await;
            let plain = get(addr, "/test/c/faces", "").await;
            assert_eq!(
                vary_of(&plain),
                ["Accept", "Authorization", "Cookie", "Origin"],
                "{plain}"
            );
            let cross = get(addr, "/test/c/faces", "Origin: https://app.example\r\n").await;
            assert_eq!(vary_of(&cross), vary_of(&plain), "{cross}");
        }

        #[tokio::test]
        async fn vary_leaves_out_origin_when_cors_is_closed() {
            let addr = serve(EdgeConfig::default()).await;
            let resp = get(addr, "/test/c/faces", "Origin: https://app.example\r\n").await;
            assert!(!vary_of(&resp).contains(&"Origin".to_string()), "{resp}");
        }

        // --- revalidation ----------------------------------------------------------------

        #[tokio::test]
        async fn a_thread_dependent_read_revalidates_to_304_until_a_sink_cuts_it() {
            let addr = serve(EdgeConfig::default()).await;

            // 200, and an instruction to come back and ask.
            let first = get(addr, "/test/c/items", "").await;
            assert!(first.starts_with("HTTP/1.1 200 OK"), "{first}");
            assert_eq!(body(&first), "one");
            let tag = etag(&first);

            // Unchanged: a bodyless 304 carrying the same validator, Cache-Control and Vary.
            let inm = format!("If-None-Match: {tag}\r\n");
            let again = get(addr, "/test/c/items", &inm).await;
            assert!(again.starts_with("HTTP/1.1 304 Not Modified"), "{again}");
            assert_eq!(body(&again), "", "{again}");
            assert_eq!(etag(&again), tag);
            assert_eq!(cache_control(&again), cache_control(&first));
            assert_eq!(vary_of(&again), vary_of(&first));

            // A write to ANOTHER resource, whose thread the read hangs from.
            let wrote = roundtrip(
                addr,
                "POST /test/c/append HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\ntwo",
            )
            .await;
            assert!(wrote.starts_with("HTTP/1.1 204"), "{wrote}");

            // The same conditional request now gets the new list and a new validator.
            let after = get(addr, "/test/c/items", &inm).await;
            assert!(after.starts_with("HTTP/1.1 200 OK"), "{after}");
            assert_eq!(body(&after), "one\ntwo");
            assert_ne!(etag(&after), tag, "{after}");

            // …and the new validator revalidates in turn.
            let settled = get(
                addr,
                "/test/c/items",
                &format!("If-None-Match: {}\r\n", etag(&after)),
            )
            .await;
            assert!(settled.starts_with("HTTP/1.1 304"), "{settled}");
        }

        #[tokio::test]
        async fn head_carries_the_same_cache_headers_as_get() {
            let addr = serve(EdgeConfig::default()).await;
            let got = get(addr, "/test/c/whoami", "Cookie: session=good\r\n").await;
            let head = roundtrip(
                addr,
                "HEAD /test/c/whoami HTTP/1.1\r\nHost: x\r\nCookie: session=good\r\n\r\n",
            )
            .await;
            assert_eq!(cache_control(&head), cache_control(&got));
            assert_eq!(vary_of(&head), vary_of(&got));
            assert_eq!(body(&head), "");
        }
    }
}
