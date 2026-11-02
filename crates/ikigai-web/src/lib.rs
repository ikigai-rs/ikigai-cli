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
//!   path patterns → IRI templates with optional per-route capability / CORS / CSP. A
//!   route's `{var}` is STRICT — its value may not carry `:` `/` `?` `#` `[` `]` `@`, so one
//!   segment cannot address a deeper resource than the route names (`400` instead) — and
//!   `{+var}` opts a variable into carrying them raw. See [`Route`].
//! - **Accept ↔ conneg**: the `Accept` header drives the `as=` transreptor selection.
//! - **query + body → inputs**: query params become inspectable request args; a write's body
//!   is the piped `content`, with the request Content-Type surfaced as `content-type`.
//! - **PATCH is read-modify-write**: the request Content-Type selects a strategy from a
//!   registry (RFC 7386 JSON Merge Patch today) that transforms the current representation
//!   before it is Sunk; conditional (`If-Match`) writes get optimistic-concurrency (→412).
//! - **`cap_of(request)` is the multi-tenant door** — every request resolves under a
//!   capability derived from its identity. A public default (or a fixed `--cap` ceiling that
//!   narrows the edge); a per-user capability (magic-link / passkey) fills the same seam later.
//! - **typed error → status** (ledger #1546's table, see [`error_status`]): `Denied`→403,
//!   `NotFound`/`Unresolved`→404, invalid/missing arg→400, `Conflict`→409, `Timeout`→504,
//!   `Unavailable`→503, `RetryAfter`→429 with `Retry-After`, `OverBudget`→422, `Refused`→502,
//!   `Unsupported`→405 with `Allow` (a verb) or 501 (a facility), else 500. The body is the message as
//!   `text/plain`, or a typed JSON object (see [`error_json`]) when [`EdgeConfig::error_body`]
//!   asks for [`ErrorBody::Json`]. A plain-text error is a minimal HTML page for a client that
//!   asks for `text/html` over `text/plain` (a browser), with `Vary: Accept` either way; a
//!   door writes that page itself with [`EdgeConfig::error_page`] ([`ErrorPageFn`]).
//! - **response headers from an endpoint**: an endpoint that needs `Set-Cookie`,
//!   `Cache-Control`, `Vary`, `Content-Disposition`, `Content-Language` or `Location` answers an
//!   [`HTTP_ENTITY`] envelope ([`with_headers`]); the door checks each header against a closed
//!   allowlist ([`EndpointHeader`]) and its own [`EdgeConfig::endpoint_headers`], and refuses
//!   anything else with `500` naming it. A `Location` on a write's answer makes it
//!   `303 See Other` to a same-origin page (Post/Redirect/Get).
//! - **HEAD**: the head GET would carry and no content, on every path, refusals included.
//! - **a write's answer**: a Sink or Delete whose endpoint answers with a representation is
//!   `200` with it (a take returns what it took); an empty answer is `204`.
//! - **per-source rate limits**: with [`EdgeConfig::source_limits`] set, one client past a
//!   rule's budget is answered `429` with `Retry-After` before the resource runs; see
//!   [`SourceLimits`].
//! - **a door that serves HTML**: [`EdgeConfig::html_door`] is one call that adopts the
//!   strict page CSP and its companion headers ([`SecurityHeaders::html_door`]) and refuses a
//!   write another origin started ([`OriginCheck`]).
//! - **server push**: with [`EdgeConfig::push`] set, one `GET` of the push path holds an
//!   event stream open and tells the page when a golden thread its reads rest on is cut —
//!   see [`push`].
//! - **streams** (ledger #2244): an answer is read through the kernel's body path and written
//!   as it is read, framed by `Content-Length` when its length is known and chunked when not,
//!   and a failure part-way ends it short rather than as a whole. A `GET` over a seekable body
//!   with a strong validator answers one byte range (`206`, `416`, `If-Range`). An upload route
//!   ([`serve_with_uploads`], [`Uploads`]) spills its body to disk as it arrives and issues the
//!   Sink with `content=b3:…`.
//! - **the connection is hyper's** (ledger #2236): HTTP/1.1 framing, a chunked request body,
//!   `Expect: 100-continue` and the header read deadline. A client that names `keep-alive` in
//!   its `Connection` header keeps the connection for its next request, until
//!   [`EdgeConfig::header_timeout`] passes with no new request; any other client is answered
//!   `Connection: close`, one request per connection, as before the move. What the door
//!   answers is decided behind a seam that knows no HTTP version (the private `door` module),
//!   so another listener can feed the same door.
//!
//! App logic — scheduling, forms, policy — stays in resources, compositions, and
//! capabilities *above* this transport, exactly as the other transports (quic/ipc/mcp) keep
//! the kernel's behavior out of the wire layer.
#![forbid(unsafe_code)]

mod accept;
mod door;
mod entity;
mod error_page;
mod h1;
mod origin;
pub mod push;
mod redirect;
mod source_limit;
mod stream;
mod upload;
pub use entity::{
    with_headers, EndpointHeader, HeaderRefusal, HTTP_ENTITY, MAX_HEADER_BLOCK, MAX_HEADER_LINES,
    MAX_HEADER_VALUE,
};
pub use origin::{InvalidOrigin, OriginCheck};
pub use push::{PushConfig, DEFAULT_PUSH_PATH};
pub use source_limit::{source_key, SourceLimits, SourceRate, DEFAULT_MAX_SOURCES};
pub use upload::{Uploads, DEFAULT_UPLOAD_GRACE, DEFAULT_UPLOAD_MIN_RATE};

use ikigai_core::{ArgRef, Capability, FailureClass, Iri, Kernel, Request, Verb};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
/// on every verb, so a submitter cannot name their own principal, and a read names nobody.
///
/// ★ **Since core 0.1.93 the answer is ALSO minted into the request's capability** (ledger
/// #1077), on every verb, reads included: `urn:cap:principal:<iri>`, which an endpoint reads
/// with `inv.capability.principal()`. That one does partition the kernel's cache per
/// principal, deliberately (an answer for alice is alice's), and an answer under a named
/// capability is sent `Cache-Control: private` with the credential headers in `Vary`. Only an
/// answer core can carry verbatim is minted (an absolute IRI, at most 512 bytes, no `*`; a
/// label like `p` is not), and nothing is minted under a root capability. The stamped
/// argument is kept for hosts that still read it.
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

/// A door's answer to a request it will not serve at all: the status and the sentence the
/// refused client is told. Returned by an [`AdmitFn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// One of `400`, `403`, `404`, `421` or `429`; any other value is answered `403`, so a
    /// typo cannot turn a refusal into a success.
    pub status: u16,
    /// The body of the refusal, as `text/plain`.
    pub reason: String,
}

/// Decide, from the request alone and BEFORE anything else answers it, whether the door
/// serves it at all. `Some` refuses: no route is matched, no endpoint is described or invoked,
/// and the client gets the [`Refusal`] (with the edge's security headers and CORS policy).
///
/// ★ **Why it exists beside [`CapFn`].** A capability decides what a request may DO, and a
/// host can refuse one by handing it a capability no resource satisfies, which an overlay in
/// the kernel then answers. But three answers never reach the kernel: `OPTIONS` (the declared
/// verbs), the `?description` face (the contract of every action the capability is offered,
/// which for an empty capability is the capability-free ones) and the push stream. A refusal
/// computed as a capability therefore still disclosed those (ledger #879, from gonk's foreign
/// `Host` and cross-site refusals). This hook runs ahead of all of them. `None` (the default
/// [`EdgeConfig::admit_fn`]) admits everything, exactly as before the hook existed.
///
/// ```
/// use ikigai_core::{EndpointSpace, Exact, FnEndpoint, Description, Kernel, ReprType, Representation, Verb};
/// use ikigai_web::{AdmitFn, EdgeConfig, HttpRequest, Refusal};
/// use std::sync::Arc;
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
///
/// # #[tokio::main]
/// # async fn main() {
/// let page = FnEndpoint::new("page", |_inv: &ikigai_core::Invocation<'_>| {
///     Ok(Representation::new(ReprType::new("text/plain"), b"hello".to_vec()))
/// })
/// .with_description(Description::new("page").verb(Verb::Source));
/// let kernel = Arc::new(Kernel::new(Arc::new(
///     EndpointSpace::new().bind(Exact::new("urn:test:page"), page),
/// )));
/// // Serve only requests addressed to this server's own name.
/// let admit: AdmitFn = Arc::new(|req: &HttpRequest| {
///     (req.header("host") != Some("localhost")).then(|| Refusal {
///         status: 421,
///         reason: "this server answers only to localhost".to_string(),
///     })
/// });
/// let config = EdgeConfig { admit_fn: Some(admit), ..EdgeConfig::default() };
/// let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
/// let addr = listener.local_addr().unwrap();
/// tokio::spawn(async move {
///     let _ = ikigai_web::serve_with_listener(kernel, ikigai_web::public_cap(), listener, config).await;
/// });
/// async fn send(addr: std::net::SocketAddr, raw: &str) -> String {
///     let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
///     c.write_all(raw.as_bytes()).await.unwrap();
///     let mut out = Vec::new();
///     c.read_to_end(&mut out).await.unwrap();
///     String::from_utf8_lossy(&out).into_owned()
/// }
/// let ok = send(addr, "GET /test/page HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
/// assert!(ok.starts_with("HTTP/1.1 200") && ok.ends_with("hello"), "{ok}");
/// // Refused before anything answers: the page, its OPTIONS and its description alike.
/// for raw in [
///     "GET /test/page HTTP/1.1\r\nHost: evil.example\r\n\r\n",
///     "OPTIONS /test/page HTTP/1.1\r\nHost: evil.example\r\n\r\n",
///     "GET /test/page?description HTTP/1.1\r\nHost: evil.example\r\n\r\n",
/// ] {
///     let refused = send(addr, raw).await;
///     assert!(refused.starts_with("HTTP/1.1 421 Misdirected Request"), "{refused}");
///     assert!(refused.ends_with("this server answers only to localhost"), "{refused}");
/// }
/// # }
/// ```
pub type AdmitFn = Arc<dyn Fn(&HttpRequest) -> Option<Refusal> + Send + Sync>;

/// The response a [`Refusal`] is answered with. The reason phrase is a `&'static str` in
/// [`Resp`], so the status is mapped from a closed list rather than taken on trust.
fn refusal_resp(refusal: &Refusal) -> Resp {
    let (status, phrase) = match refusal.status {
        400 => (400, "Bad Request"),
        404 => (404, "Not Found"),
        421 => (421, "Misdirected Request"),
        429 => (429, "Too Many Requests"),
        _ => (403, "Forbidden"),
    };
    // The class the decided status table (ledger #1546) gives the status: `403` is the
    // caller's capability, `429` a stated wait, the rest a wrong request.
    let class = match status {
        403 => FailureClass::Denied,
        429 => FailureClass::RetryAfter,
        _ => FailureClass::Permanent,
    };
    Resp {
        refusal: Some(refusal.clone()),
        class: Some(class),
        ..Resp::text(status, phrase, &refusal.reason)
    }
}

/// What an [`ErrorPageFn`] is shown of the error it may write a page for. Fields are added as
/// doors need them (`#[non_exhaustive]`), so a door reads them and never builds one.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ErrorView<'a> {
    /// The status the answer carries, whatever page is written: the hook chooses the body,
    /// never the status.
    pub status: u16,
    /// The status's reason phrase (`"Forbidden"`).
    pub reason: &'a str,
    /// The sentence the answer would carry as `text/plain`, unescaped: the error's message,
    /// the refusal's reason, or the edge's own sentence. Escape it before putting it in HTML
    /// (`ikigai_fn::html::html_text`).
    pub message: &'a str,
    /// The typed kernel error, when the answer reports one (a `Denied` read, a `NotFound`).
    pub error: Option<&'a ikigai_core::Error>,
    /// The [`AdmitFn`]'s refusal, when the door refused the request before anything answered.
    pub refusal: Option<&'a Refusal>,
    /// The failure class (ledger #1546): the error's [`Error::class`](ikigai_core::Error::class),
    /// or for a refusal the class its status is decided as (`403` denied, `429` retry-after,
    /// the rest permanent), and retry-after for a per-source rate limit. `None` when the edge
    /// answered on its own with no class decided (a `405`, `406`, `413`, a route's `400`).
    pub class: Option<FailureClass>,
    /// Whether the browser is navigating to a page (`Sec-Fetch-Mode: navigate`, a link
    /// followed, a URL typed, a form submitted) rather than fetching from script (`cors`,
    /// `same-origin`). A door may write a whole page for the first and `None` for the second.
    pub navigation: bool,
}

/// A door's own HTML page for an error a browser asked for as a page (ledger #2025): a
/// refusal in the door's own shell, styled, with whatever the error calls for on it (a
/// sign-in, a way back). `Some(html)` is the body, served as `text/html; charset=utf-8`;
/// `None` keeps the minimal page this crate writes.
///
/// It is asked only when all of these hold, so a JSON client, a script and curl never see
/// the door's HTML:
/// - the answer is past ordinary in-memory intake (its pre-admission `413` uses only the
///   built-in page, without calling this hook);
/// - the answer is an error (`>= 400`) whose body is the sentence (`text/plain`); a door
///   answering [`ErrorBody::Json`] keeps its JSON;
/// - `Accept` names `text/html` over `text/plain` (the rule of [`EdgeConfig::error_body`]);
/// - the request carries `Sec-Fetch-Mode`, which only a browser sends, and is not htmx
///   asking for a fragment (`HX-Request: true`).
///
/// The status and every header the answer was built with (`Retry-After`, `Allow`) are
/// unchanged, and the edge policy applies to the page as to any answer: the door's
/// `Content-Security-Policy` governs it, so an inline `<style>` or `<script>` the CSP does not
/// allow is blocked; link the door's own stylesheet instead. With a hook set, `Vary` names
/// `Sec-Fetch-Mode` and `HX-Request` beside `Accept`.
///
/// ⚠ A browser sends `Sec-Fetch-Mode` only to a potentially trustworthy origin (HTTPS or
/// `localhost`), so over plain `http://` to a LAN address the hook is never asked.
///
/// ```
/// use ikigai_core::{Description, EndpointSpace, Error, Exact, FailureClass, FnEndpoint, Invocation, Kernel, Verb};
/// use ikigai_fn::html::html_text;
/// use ikigai_web::{EdgeConfig, ErrorPageFn, ErrorView, HttpRequest};
/// use std::sync::Arc;
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
///
/// # #[tokio::main]
/// # async fn main() {
/// let ledger = FnEndpoint::new("ledger", |_inv: &Invocation<'_>| -> ikigai_core::Result<_> {
///     Err(Error::Denied("sign in to read this ledger".into()))
/// })
/// .with_description(Description::new("ledger").verb(Verb::Source));
/// let kernel = Arc::new(Kernel::new(Arc::new(
///     EndpointSpace::new().bind(Exact::new("urn:test:ledger"), ledger),
/// )));
/// // A denied page navigation gets the door's own page; anything else keeps the default.
/// let error_page: ErrorPageFn = Arc::new(|req: &HttpRequest, view: &ErrorView<'_>| {
///     (view.class == Some(FailureClass::Denied) && view.navigation).then(|| {
///         format!(
///             "<!DOCTYPE html><html lang=\"en\"><title>Sign in</title><main><h1>Sign in</h1>\
///              <p>{}</p><a href=\"/signin?back={}\">Sign in with a passkey</a></main></html>",
///             html_text(view.message),
///             html_text(&req.path),
///         )
///     })
/// });
/// let config = EdgeConfig { error_page: Some(error_page), ..EdgeConfig::default() };
/// let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
/// let addr = listener.local_addr().unwrap();
/// tokio::spawn(async move {
///     let _ = ikigai_web::serve_with_listener(kernel, ikigai_web::public_cap(), listener, config).await;
/// });
/// async fn send(addr: std::net::SocketAddr, raw: &str) -> String {
///     let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
///     c.write_all(raw.as_bytes()).await.unwrap();
///     let mut out = Vec::new();
///     c.read_to_end(&mut out).await.unwrap();
///     String::from_utf8_lossy(&out).into_owned()
/// }
/// let browser = send(
///     addr,
///     "GET /test/ledger HTTP/1.1\r\nHost: localhost\r\nAccept: text/html\r\nSec-Fetch-Mode: navigate\r\n\r\n",
/// )
/// .await;
/// assert!(browser.starts_with("HTTP/1.1 403 Forbidden"), "{browser}");
/// assert!(browser.contains("Sign in with a passkey"), "{browser}");
/// // curl asking for HTML sends no fetch metadata, and gets the default page.
/// let curl = send(addr, "GET /test/ledger HTTP/1.1\r\nHost: localhost\r\nAccept: text/html\r\n\r\n").await;
/// assert!(curl.starts_with("HTTP/1.1 403 Forbidden") && !curl.contains("passkey"), "{curl}");
/// # }
/// ```
pub type ErrorPageFn = Arc<dyn Fn(&HttpRequest, &ErrorView<'_>) -> Option<String> + Send + Sync>;

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
///
/// It is also the keep-alive idle limit: a kept connection with no new request after this long
/// is closed, without an answer, since no request was started.
pub const DEFAULT_HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a client may take to deliver the body it declared, once the headers are in.
/// Past it the request is answered `408`. Thirty seconds carries a full
/// [`DEFAULT_MAX_BODY_BYTES`] at about 35 KB/s. [Overridable](EdgeConfig::body_timeout).
pub const DEFAULT_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a write to the client may make no progress. A client that stops reading would
/// otherwise hold its connection (and its place under [`DEFAULT_MAX_CONNECTIONS`]) for as long
/// as it liked. Past it the connection is dropped. [Overridable](EdgeConfig::write_timeout).
///
/// On the door's own connections it bounds each stall, not the whole answer: the deadline
/// starts when the socket stops taking bytes and is cleared when it takes some.
/// [`write_response`] and [`write_answer`] bound the whole write, as they always did.
pub const DEFAULT_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How many connections are served at once. A connection past the cap is answered `503`
/// with `Retry-After` straight away, without its request being handled. Every current door
/// (gonk, ttt-host, a LAN `serve --http`) serves a handful of people. A connection lives as
/// long as one request, or, kept alive, until it sits idle for [`DEFAULT_HEADER_TIMEOUT`]; a
/// browser keeps about six. 256 is far above any of them and far below what exhausts a
/// process's descriptors. [Overridable](EdgeConfig::max_connections).
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
    /// The largest request body accepted, in bytes; a larger one is refused with `413`,
    /// before it is read when its `Content-Length` says so, and as soon as it passes the bound
    /// when it is chunked. Never truncated. Default [`DEFAULT_MAX_BODY_BYTES`]. Raise it for a
    /// door that takes genuinely large writes, lower it for one that only takes forms.
    /// An ordinary intake's `413` negotiates the built-in error page and carries global edge
    /// policy, before admission and without identity, capability or custom error-page hooks.
    pub max_body_bytes: usize,
    /// Routes-only: an un-routed path is **not** part of the public surface — it 404s instead
    /// of falling through to the mechanical `/noun/partition/key` → `urn:` default. This turns
    /// the route table into an exhaustive allow-list (no accidental export), the right posture
    /// for a public edge. Default `false` (fall-through on).
    pub routes_only: bool,
    /// The principal hook — see [`PrincipalFn`] for the shape it stamps. `None` (the
    /// default) attaches no `principal` argument to anything.
    pub principal_fn: Option<PrincipalFn>,
    /// The admission hook — see [`AdmitFn`]. `None` (the default) admits every request.
    pub admit_fn: Option<AdmitFn>,
    /// The deadline for the request line and headers. Default [`DEFAULT_HEADER_TIMEOUT`].
    pub header_timeout: std::time::Duration,
    /// The deadline for the declared body. Default [`DEFAULT_BODY_TIMEOUT`].
    pub body_timeout: std::time::Duration,
    /// The deadline for writing the response. Default [`DEFAULT_WRITE_TIMEOUT`].
    pub write_timeout: std::time::Duration,
    /// Connections served at once; one past it is answered `503`. Default
    /// [`DEFAULT_MAX_CONNECTIONS`]. `0` refuses every connection.
    pub max_connections: usize,
    /// Server push: an event stream at [`PushConfig::path`] that tells a page when a golden
    /// thread its reads rest on is cut. `None` (the default) serves no stream, and the path is
    /// routed like any other. See [`push`].
    pub push: Option<PushConfig>,
    /// The body a typed kernel error is answered with. [`ErrorBody::Text`] (the default) is
    /// the error's message as `text/plain`, exactly as before the option existed;
    /// [`ErrorBody::Json`] is the typed object [`error_json`] renders, as `application/json`.
    /// The status is the same either way. Refusals the edge makes on its own (`405`, `406`,
    /// `413`, a strict route variable's `400`) carry no kernel error and stay `text/plain`.
    ///
    /// Either way, a `text/plain` error body is answered as a minimal HTML page to a client
    /// that names `text/html` in `Accept` and prefers it to `text/plain` (a browser
    /// navigating), and every such answer carries `Vary: Accept`. A JSON body is left as it is.
    /// [`error_page`](Self::error_page) lets the door write that page itself.
    pub error_body: ErrorBody,
    /// The door's own page for an error a browser asked for as a page — see [`ErrorPageFn`].
    /// `None` (the default) answers the minimal page, exactly as before the hook existed.
    pub error_page: Option<ErrorPageFn>,
    /// The response headers this door accepts from an endpoint's [`HTTP_ENTITY`] envelope
    /// (see [`with_headers`]), out of the closed list [`EndpointHeader::ALL`]. An envelope
    /// asking for a header not listed here is refused with `500` naming it. Default
    /// [`EndpointHeader::DEFAULTS`], which leaves out `Set-Cookie`: add it on a door whose
    /// endpoints mint sessions.
    pub endpoint_headers: Vec<EndpointHeader>,
    /// Per-source rate limits (see [`SourceLimits`]): a client past a rule's budget is answered
    /// `429 Too Many Requests` with `Retry-After`, before the resource is invoked. The source is
    /// the connection's peer, or the `X-Forwarded-For` hop the proxy appended when
    /// [`trust_proxy`](Self::trust_proxy) is set. `None` (the default) limits nothing.
    pub source_limits: Option<SourceLimits>,
}

/// How a typed kernel error is rendered into a response body. See [`EdgeConfig::error_body`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorBody {
    /// The error's message, as `text/plain; charset=utf-8`.
    #[default]
    Text,
    /// The typed object of [`error_json`], as `application/json`.
    Json,
}

/// A typed kernel error as the JSON object [`ErrorBody::Json`] answers with.
///
/// Always `kind` (core's [`Error::kind`](ikigai_core::Error::kind), one stable word) and
/// `message` (the error's display text, the same string the `text/plain` body carries), plus
/// the fields the variant itself carries, under these names:
///
/// | `kind`             | extra fields                                   |
/// |--------------------|------------------------------------------------|
/// | `invalid-argument` | `name`, `detail`                               |
/// | `missing-argument` | `name`                                         |
/// | `unresolved`       | `target`                                       |
/// | `depth-exceeded`   | `depth`, `target`                              |
/// | `retry-after`      | `retry_after` (the header's seconds, when known) |
/// | `unsupported`      | `verb` (its serde name, when one is named)     |
///
/// Every body also carries `class`, the failure class (`Error::class`, ledger #1546), so a
/// client decides who may repeat the request without a table of kinds. Every other kind
/// carries only its message. A variant core adds later renders with its own `kind`,
/// `class` and `message` and no extra fields until this table names them.
///
/// ```
/// use std::time::Duration;
/// use ikigai_core::{Error, Iri, Verb};
/// use ikigai_web::error_json;
///
/// let limited = Error::RetryAfter { delay: Some(Duration::from_millis(1_500)), detail: "5 per minute".into() };
/// assert_eq!(
///     error_json(&limited),
///     r#"{"kind":"retry-after","class":"retry-after","message":"retry after 1500 ms: 5 per minute","retry_after":2}"#
/// );
/// let read_only = Error::Unsupported { verb: Some(Verb::Sink), detail: "append-only".into() };
/// assert_eq!(
///     error_json(&read_only),
///     r#"{"kind":"unsupported","class":"permanent","message":"unsupported: append-only","verb":"Sink"}"#
/// );
/// let invalid = Error::InvalidArgument { name: "tuple".into(), detail: "not a name".into() };
/// assert_eq!(
///     error_json(&invalid),
///     r#"{"kind":"invalid-argument","class":"permanent","message":"invalid argument `tuple`: not a name","name":"tuple","detail":"not a name"}"#
/// );
/// assert_eq!(
///     error_json(&Error::NotFound("no tuple z yet".into())),
///     r#"{"kind":"not-found","class":"permanent","message":"not found: no tuple z yet"}"#
/// );
/// let deep = Error::DepthExceeded { depth: 65, target: Iri::parse("urn:x").unwrap() };
/// assert_eq!(
///     error_json(&deep),
///     r#"{"kind":"depth-exceeded","class":"permanent","message":"nesting budget exceeded: sub-request for urn:x would run at depth 65","depth":65,"target":"urn:x"}"#
/// );
/// ```
pub fn error_json(e: &ikigai_core::Error) -> String {
    use ikigai_core::Error;
    use serde_json::{Map, Value};
    let mut body = Map::new();
    body.insert("kind".into(), Value::from(e.kind()));
    body.insert("class".into(), Value::from(e.class().word()));
    body.insert("message".into(), Value::from(e.to_string()));
    match e {
        Error::InvalidArgument { name, detail } => {
            body.insert("name".into(), Value::from(name.as_str()));
            body.insert("detail".into(), Value::from(detail.as_str()));
        }
        Error::MissingArgument(name) => {
            body.insert("name".into(), Value::from(name.as_str()));
        }
        Error::Unresolved(target) => {
            body.insert("target".into(), Value::from(target.as_str()));
        }
        Error::DepthExceeded { depth, target } => {
            body.insert("depth".into(), Value::from(*depth));
            body.insert("target".into(), Value::from(target.as_str()));
        }
        Error::RetryAfter { .. } => {
            if let Some(seconds) = retry_after_seconds(e) {
                body.insert("retry_after".into(), Value::from(seconds));
            }
        }
        Error::Unsupported {
            verb: Some(verb), ..
        } => {
            body.insert("verb".into(), Value::from(format!("{verb:?}")));
        }
        _ => {}
    }
    Value::Object(body).to_string()
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
            admit_fn: None,
            header_timeout: DEFAULT_HEADER_TIMEOUT,
            body_timeout: DEFAULT_BODY_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            push: None,
            error_body: ErrorBody::Text,
            error_page: None,
            endpoint_headers: EndpointHeader::DEFAULTS.to_vec(),
            source_limits: None,
        }
    }
}

impl EdgeConfig {
    /// The edge policy for a door that serves HTML, in one call: [`EdgeConfig::default`] with
    /// the page preset [`SecurityHeaders::html_door`] and, as [`admit_fn`](Self::admit_fn),
    /// an [`OriginCheck`] over `origins`, the door's own origins as configured (never read off
    /// the request). Fails when an origin does not parse, or when there is none.
    ///
    /// Set the rest of the policy over it, a route CSP included:
    /// `EdgeConfig { routes, ..EdgeConfig::html_door(["https://door.example"])? }`. A door
    /// that has its own [`AdmitFn`] keeps it and calls [`OriginCheck::check`] inside it, since
    /// a second assignment of `admit_fn` replaces the first.
    ///
    /// ```
    /// use ikigai_core::{Description, EndpointSpace, Exact, FnEndpoint, Kernel, ReprType, Representation, Verb};
    /// use ikigai_web::EdgeConfig;
    /// use std::sync::Arc;
    /// use tokio::io::{AsyncReadExt, AsyncWriteExt};
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let note = FnEndpoint::new("note", |_inv: &ikigai_core::Invocation<'_>| {
    ///     Ok(Representation::new(ReprType::new("text/plain"), b"saved".to_vec()))
    /// })
    /// .with_description(Description::new("note").verb(Verb::Source).verb(Verb::Sink));
    /// let kernel = Arc::new(Kernel::new(Arc::new(
    ///     EndpointSpace::new().bind(Exact::new("urn:test:note"), note),
    /// )));
    /// let config = EdgeConfig::html_door(["https://door.example"]).unwrap();
    /// let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    /// let addr = listener.local_addr().unwrap();
    /// tokio::spawn(async move {
    ///     let _ = ikigai_web::serve_with_listener(kernel, ikigai_web::public_cap(), listener, config).await;
    /// });
    /// async fn post(addr: std::net::SocketAddr, origin: &str) -> String {
    ///     let raw = format!(
    ///         "POST /test/note HTTP/1.1\r\nHost: door.example\r\nOrigin: {origin}\r\n\
    ///          Cookie: s=1\r\nContent-Length: 2\r\n\r\nhi"
    ///     );
    ///     let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    ///     c.write_all(raw.as_bytes()).await.unwrap();
    ///     let mut out = String::new();
    ///     c.read_to_string(&mut out).await.unwrap();
    ///     out
    /// }
    /// let ours = post(addr, "https://door.example").await;
    /// assert!(ours.starts_with("HTTP/1.1 200") && ours.ends_with("saved"), "{ours}");
    /// let theirs = post(addr, "https://evil.example").await;
    /// assert!(theirs.starts_with("HTTP/1.1 403 Forbidden"), "{theirs}");
    /// assert!(theirs.contains("\r\nCross-Origin-Opener-Policy: same-origin\r\n"), "{theirs}");
    /// assert!(EdgeConfig::html_door(["door.example"]).is_err());
    /// # }
    /// ```
    pub fn html_door<I, S>(origins: I) -> Result<EdgeConfig, InvalidOrigin>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Ok(EdgeConfig {
            security: Some(SecurityHeaders::html_door()),
            admit_fn: Some(OriginCheck::new(origins)?.admit_fn()),
            ..EdgeConfig::default()
        })
    }
}

/// A single route: a path pattern → an IRI template, with optional per-route overrides. The
/// pattern and template share capture names (`/book/{host}` → `urn:schedule:{host}`).
///
/// **Two spellings of a variable** (RFC 6570's simple and reserved expansion):
///
/// - `{var}` is **strict**: it captures one path segment whose DECODED value carries none of
///   RFC 3986's gen-delims `:` `/` `?` `#` `[` `]` `@`. A value that does (`/u/alice:private`,
///   or `/u/a%2Fb` once `%2F` is decoded) does not fill the variable, and the request is
///   refused `400 Bad Request` naming it — never re-tried against a later route or the
///   mechanical default, either of which could resolve it to some other resource. This is the
///   default because an IRI's structure IS those delimiters: a raw `:` in `urn:user:{name}`
///   turns `alice:private` into a different, deeper resource than the route names, which
///   under [`EdgeConfig::routes_only`] is a resource no route serves.
/// - `{+var}` is **raw**: it still captures exactly one segment, but its decoded value is
///   substituted as it is, delimiters and all — for a route whose variable IS an IRI or a
///   path (`/browse/{+iri}` → `urn:page:browse:{+iri}`). It opts out of the guard above, so
///   use it only where any value is a resource the route means to expose.
///
/// A variable is raw only when EVERY spelling of it, in the pattern and the template, is
/// `{+var}`; a pattern and template that disagree are strict. Substitution is one pass over
/// the template, so a captured value containing `{…}` is never itself expanded.
///
/// ```
/// use ikigai_web::{Route, RouteTable};
/// let route = |pattern: &str, iri: &str| Route {
///     pattern: pattern.into(), iri_template: iri.into(), redirect: None, cap: None, cors: None, csp: None,
/// };
/// // `/u/alice` → `urn:user:alice`; `/u/alice:private` → 400, the variable refuses `:`.
/// let strict = route("/u/{name}", "urn:user:{name}");
/// // `/browse/urn:repo:x:file:src%2Flib.rs` → `urn:page:browse:urn:repo:x:file:src/lib.rs`.
/// let raw = route("/browse/{+iri}", "urn:page:browse:{+iri}");
/// let _ = RouteTable::new(vec![strict, raw]);
/// ```
#[derive(Clone)]
pub struct Route {
    /// Page IRI template to redirect to after a successful non-htmx POST. Captures use
    /// the same rules as `iri_template`. `None` keeps the endpoint's answer. The page is
    /// addressed through this route table, or the mechanical `urn:` path default.
    pub redirect: Option<String>,
    /// Path pattern; a `{var}` or `{+var}` segment captures exactly one path segment, a
    /// literal segment must match exactly.
    pub pattern: String,
    /// IRI template; each variable the pattern captured is substituted in.
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
    redirect: Option<String>,
    /// The expanded IRI template, or — when a strict `{var}` refused its value — the `400`
    /// body naming the variable. A refusal still MATCHED: the route's shape claimed the path,
    /// so no later route and no mechanical default may answer it instead.
    iri: Result<String, String>,
    cap: Option<Vec<String>>,
    cors: Option<CorsPolicy>,
    csp: Option<String>,
}

/// RFC 3986 §2.2's gen-delims — the characters that give an IRI its structure, and so the
/// ones a strict `{var}` refuses to carry into one.
const GEN_DELIMS: [char; 7] = [':', '/', '?', '#', '[', ']', '@'];

/// The variable a `{name}` / `{+name}` token names, and whether it is the raw `+` spelling.
/// `None` for anything that is not one whole placeholder.
fn placeholder(token: &str) -> Option<(&str, bool)> {
    let inner = token.strip_prefix('{')?.strip_suffix('}')?;
    Some(match inner.strip_prefix('+') {
        Some(name) => (name, true),
        None => (inner, false),
    })
}

/// Expand `template` in ONE pass: each `{name}` or `{+name}` whose name is bound is replaced
/// by its value, and anything else (an unbound name, a stray brace) is kept as written. One
/// pass, so a value that itself reads `{other}` is data, never a second placeholder.
fn expand(template: &str, binds: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let from = &rest[open..];
        let Some(close) = from.find('}') else {
            break;
        };
        let token = &from[..=close];
        match placeholder(token).and_then(|(name, _)| binds.iter().find(|(v, _)| *v == name)) {
            Some((_, value)) => out.push_str(value),
            None => out.push_str(token),
        }
        rest = &from[close + 1..];
    }
    out.push_str(rest);
    out
}

impl RouteTable {
    /// A table from an ordered list of routes.
    pub fn new(routes: Vec<Route>) -> Self {
        RouteTable { routes }
    }

    /// Match `path` against the routes in order. The first route whose SHAPE fits (segment
    /// count and literals) wins: its captures are checked — a strict `{var}` refuses a value
    /// carrying a gen-delim, see [`Route`] — and expanded into the IRI template. `None` →
    /// no route's shape fits; fall through.
    fn match_path(&self, path: &str) -> Option<Matched> {
        let segs = path_segments(path);
        for route in &self.routes {
            // (name, value, raw in the pattern)
            let Some(binds) = shape_binds(&route.pattern, &segs) else {
                continue;
            };
            let refusal = binds.iter().find_map(|(var, val, raw)| {
                // Raw only when the template agrees: a `{var}` spelling there is strict.
                if *raw
                    && !route.iri_template.contains(&format!("{{{var}}}"))
                    && !route
                        .redirect
                        .as_deref()
                        .is_some_and(|t| t.contains(&format!("{{{var}}}")))
                {
                    return None;
                }
                let delim = val.chars().find(|c| GEN_DELIMS.contains(c))?;
                Some(format!(
                    "route variable {{{var}}} cannot carry '{delim}': a strict {{var}} refuses \
                     : / ? # [ ] @"
                ))
            });
            let iri = match refusal {
                Some(why) => Err(why),
                None => {
                    let pairs: Vec<(&str, &str)> = binds.iter().map(|(n, v, _)| (*n, *v)).collect();
                    Ok(expand(&route.iri_template, &pairs))
                }
            };
            let pairs: Vec<(&str, &str)> = binds.iter().map(|(n, v, _)| (*n, *v)).collect();
            return Some(Matched {
                redirect: route.redirect.as_ref().map(|t| expand(t, &pairs)),
                iri,
                cap: route.cap.clone(),
                cors: route.cors.clone(),
                csp: route.csp.clone(),
            });
        }
        None
    }
}

/// Whether a route `pattern`'s SHAPE fits a path split into `segs` (segment count and
/// literals), and if so its captures as `(name, value, raw in the pattern)`. The one shape
/// test: [`RouteTable`]'s match and an upload route's ([`Uploads::route`]) both read it.
fn shape_binds<'a>(pattern: &'a str, segs: &'a [String]) -> Option<Vec<(&'a str, &'a str, bool)>> {
    let pat: Vec<&str> = pattern
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if pat.len() != segs.len() {
        return None;
    }
    let mut binds = Vec::new();
    for (p, s) in pat.into_iter().zip(segs) {
        if let Some((var, raw)) = placeholder(p) {
            binds.push((var, s.as_str(), raw));
        } else if p != s {
            return None;
        }
    }
    Some(binds)
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
    /// `Cross-Origin-Opener-Policy`. Default `None` (not sent), so a door that already opens
    /// or is opened by a window on another origin keeps working; [`SecurityHeaders::html_door`]
    /// sends `same-origin`.
    pub coop: Option<String>,
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
            coop: None,
        }
    }
}

/// The `Content-Security-Policy` of [`SecurityHeaders::html_door`]: everything from this
/// origin only, no inline script and no inline style (neither `script-src` nor `style-src`
/// allows `'unsafe-inline'`, so a `<script>` block, an `onclick=` and a `style=` attribute are
/// all blocked), no plugins, no `<base>`, no framing by anyone, and forms posting only here.
/// A page under it loads its script and its stylesheet as files from its own door.
pub const HTML_DOOR_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
     object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

impl SecurityHeaders {
    /// The preset for a door that serves HTML pages: the CSP [`HTML_DOOR_CSP`],
    /// `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
    /// `Cross-Origin-Opener-Policy: same-origin`, and the default's HSTS (sent on an HTTPS
    /// request only). It is at least as strict as [`Default`] on every header: it adds
    /// `object-src 'none'` and the opener policy, and it loosens nothing. A route that needs
    /// another CSP still sets [`Route::csp`], which replaces this one on that route alone.
    ///
    /// The exact lines it sends, pinned:
    ///
    /// ```
    /// use ikigai_core::{Description, EndpointSpace, Exact, FnEndpoint, Kernel, ReprType, Representation, Verb};
    /// use ikigai_web::{EdgeConfig, SecurityHeaders};
    /// use std::sync::Arc;
    /// use tokio::io::{AsyncReadExt, AsyncWriteExt};
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let page = FnEndpoint::new("page", |_inv: &ikigai_core::Invocation<'_>| {
    ///     Ok(Representation::new(ReprType::new("text/html"), b"<p>hi</p>".to_vec()))
    /// })
    /// .with_description(Description::new("page").verb(Verb::Source));
    /// let kernel = Arc::new(Kernel::new(Arc::new(
    ///     EndpointSpace::new().bind(Exact::new("urn:test:page"), page),
    /// )));
    /// let config = EdgeConfig { security: Some(SecurityHeaders::html_door()), ..EdgeConfig::default() };
    /// let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    /// let addr = listener.local_addr().unwrap();
    /// tokio::spawn(async move {
    ///     let _ = ikigai_web::serve_with_listener(kernel, ikigai_web::public_cap(), listener, config).await;
    /// });
    /// let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    /// c.write_all(b"GET /test/page HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    /// let mut out = String::new();
    /// c.read_to_string(&mut out).await.unwrap();
    /// for line in [
    ///     "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; \
    ///      object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    ///     "X-Content-Type-Options: nosniff",
    ///     "Referrer-Policy: no-referrer",
    ///     "Cross-Origin-Opener-Policy: same-origin",
    /// ] {
    ///     assert!(out.contains(&format!("\r\n{line}\r\n")), "{line}\n{out}");
    /// }
    /// // HSTS rides on an HTTPS request only; this one was plain HTTP.
    /// assert!(!out.contains("Strict-Transport-Security"), "{out}");
    /// # }
    /// ```
    pub fn html_door() -> SecurityHeaders {
        SecurityHeaders {
            csp: Some(HTML_DOOR_CSP.to_string()),
            coop: Some("same-origin".to_string()),
            ..SecurityHeaders::default()
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
    /// DELETE requests that succeeded through this server, with when — a repeat of one
    /// answers 204 (idempotent) rather than 404, for a bounded window. Keyed on the whole
    /// request (see [`tombstone_key`]). In-process only (lost on restart); a persistent
    /// ledger is a later step.
    tombstones: std::sync::Mutex<std::collections::HashMap<TombstoneKey, std::time::Instant>>,
    /// The upload routes and the content store their spills are held in
    /// ([`serve_with_uploads`]); `None` takes every body into memory, as before.
    uploads: Option<Uploads>,
}

/// A DELETE tombstone's key: the target IRI and the query arguments, ordered by name.
type TombstoneKey = (String, Vec<(String, String)>);

/// How long a tombstone makes a repeat DELETE idempotent (204) before the resource
/// reverts to reporting 404.
const TOMBSTONE_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// Serve `kernel` over HTTP on `addr` under the default edge policy (strict security
/// headers, CORS closed, proxy not trusted). See [`serve_with`] to configure it.
pub async fn serve(kernel: Arc<Kernel>, cap_fn: CapFn, addr: SocketAddr) -> std::io::Result<()> {
    serve_with(kernel, cap_fn, addr, EdgeConfig::default()).await
}

/// Serve `kernel` over HTTP on `addr`, resolving each request under `cap_fn(request)` and
/// applying `config` (security headers, CORS, proxy trust). Each connection is served by hyper's
/// HTTP/1.1 server: one request per connection (`Connection: close`) unless the client names
/// `keep-alive`, in which case the connection serves its next request too, until it sits idle
/// for [`EdgeConfig::header_timeout`]. Runs until the listener itself fails: a per-connection accept error
/// is skipped and descriptor exhaustion is backed off and retried (see the private `accept`
/// module), so only a dead listener (`EBADF`, `EINVAL`, …) returns.
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
    serve_shared(listener, shared(kernel, cap_fn, config, None)).await
}

/// Like [`serve_with_listener`], and an upload route (one [`Uploads`] names) takes a body
/// larger than memory: the door spills it through the kernel's spill facility while it
/// arrives, holds it in `uploads`' content store, and issues the Sink with `content=b3:…`
/// ([`ArgRef::Content`]). See [`Uploads`] for the bounds and the capability a caller needs.
///
/// Refuses to start (`InvalidInput`) unless the kernel can carry it: it has a spill facility
/// ([`Kernel::with_spill`]) and resolves a content id through the very store `uploads` puts
/// into ([`Kernel::with_content_store`]). Either missing would refuse every upload at its
/// first byte instead, so it is checked once, here.
pub async fn serve_with_uploads(
    kernel: Arc<Kernel>,
    cap_fn: CapFn,
    listener: TcpListener,
    config: EdgeConfig,
    uploads: Uploads,
) -> std::io::Result<()> {
    uploads.check(&kernel)?;
    serve_shared(listener, shared(kernel, cap_fn, config, Some(uploads))).await
}

/// The state every connection shares.
fn shared(
    kernel: Arc<Kernel>,
    cap_fn: CapFn,
    config: EdgeConfig,
    uploads: Option<Uploads>,
) -> Arc<Shared> {
    // The live route handle: the config's own (so the host can hot-swap it), or a fresh
    // wrap of the static routes when no live handle was supplied.
    let routes = config
        .live_routes
        .clone()
        .unwrap_or_else(|| live_routes(config.routes.clone()));
    Arc::new(Shared {
        kernel,
        cap_fn,
        config,
        routes,
        tombstones: std::sync::Mutex::new(std::collections::HashMap::new()),
        uploads,
    })
}

/// The accept loop over `shared`, until the listener itself fails.
async fn serve_shared(listener: TcpListener, shared: Arc<Shared>) -> std::io::Result<()> {
    // The connection cap. A permit is taken at accept and held until the connection's task
    // ends, so the cap counts connections, not requests (a kept-alive connection holds its
    // permit while it idles). `Semaphore::new` panics above `MAX_PERMITS`, hence the clamp.
    let permits = Arc::new(tokio::sync::Semaphore::new(
        shared
            .config
            .max_connections
            .min(tokio::sync::Semaphore::MAX_PERMITS),
    ));
    loop {
        let (sock, peer) = accept_next(&listener).await?;
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
                tokio::spawn(async move {
                    let busy = Response::new(
                        503,
                        "text/plain; charset=utf-8",
                        b"too many connections".to_vec(),
                    )
                    .with_header("Retry-After", "1");
                    let _ = refuse_busy(sock, busy, &shared.config).await;
                });
            }
        }
    }
}

/// Accept the next connection the way every door this crate serves accepts them (ledger
/// #720): an error that belongs to one would-be connection (aborted, reset) is skipped, running
/// out of descriptors or memory is waited out with a bounded, doubling backoff (logged once when
/// it starts and once when it ends), and only a DEAD listener (`EBADF`, `ENOTSOCK`, `EINVAL`)
/// returns its error. A door with its own router (a TLS front) accepts with this, so one
/// `EMFILE` cannot end it either.
pub async fn accept_next(listener: &TcpListener) -> std::io::Result<(TcpStream, SocketAddr)> {
    let mut backoff = accept::Backoff::default();
    loop {
        match listener.accept().await {
            Ok(accepted) => {
                backoff.succeeded();
                return Ok(accepted);
            }
            Err(e) => match accept::classify(&e) {
                accept::Fault::Skip => continue,
                accept::Fault::BackOff => tokio::time::sleep(backoff.failed(&e)).await,
                accept::Fault::Fatal => return Err(e),
            },
        }
    }
}

/// Answer a connection past the cap with `busy` (a `503` with `Retry-After`, in the door's own
/// format), then close it LINGERING. Every door this crate serves answers its busy connections
/// this way, over TCP or over TLS once the handshake is done (the layers front, ledger #1594).
///
/// The request is never parsed, but it has usually arrived, and closing a socket with unread
/// bytes in its receive buffer sends a reset — which on most stacks destroys the `503` before
/// the client reads it (measured: the first version of this test saw `ECONNRESET`, not a
/// status). So: write, half-close, then drain what the client sent until it hangs up, bounded
/// by the header deadline and 64 KiB. Holds no permit, so it is bounded by those two alone.
///
/// The first line is read BEFORE the answer, under the same deadline as the drain, so a `HEAD`
/// is answered with the head alone like every other refusal (ledger #117). A client that
/// sends nothing is answered when the deadline passes, as a request this door never saw.
///
/// `busy` is written by [`write_answer`], so it passes [`Response::check`] first: a refused
/// response writes nothing and returns that error, as does a write that fails or outlasts
/// [`EdgeConfig::write_timeout`]. Once the answer is written the result is `Ok`, however the
/// drain ends.
///
/// ```
/// use ikigai_web::{refuse_busy, EdgeConfig, Response};
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
///
/// # #[tokio::main]
/// # async fn main() {
/// let (mut client, server) = tokio::io::duplex(4096);
/// client.write_all(b"HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n").await.unwrap();
/// client.shutdown().await.unwrap();
/// let busy = Response::new(503, "application/json", br#"{"kind":"unavailable"}"#.to_vec())
///     .with_header("Retry-After", "1");
/// refuse_busy(server, busy, &EdgeConfig::default()).await.unwrap();
/// let mut out = String::new();
/// client.read_to_string(&mut out).await.unwrap();
/// assert!(out.starts_with("HTTP/1.1 503 Service Unavailable\r\n"), "{out}");
/// assert!(out.contains("\r\nRetry-After: 1\r\n"), "{out}");
/// assert!(out.ends_with("\r\n\r\n"), "a HEAD gets the head alone: {out:?}");
/// # }
/// ```
pub async fn refuse_busy<S: AsyncRead + AsyncWrite + Unpin>(
    mut sock: S,
    busy: Response,
    config: &EdgeConfig,
) -> std::io::Result<()> {
    let deadline = tokio::time::Instant::now() + config.header_timeout;
    let mut seen = Vec::new();
    let first_line = async {
        let mut tmp = [0u8; 1024];
        while seen.len() < 64 * 1024 && !seen.contains(&b'\n') {
            match sock.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => seen.extend_from_slice(&tmp[..n]),
            }
        }
    };
    let _ = tokio::time::timeout_at(deadline, first_line).await;
    let method = if is_head(&seen) { "HEAD" } else { "" };
    write_answer(&mut sock, method, busy, config).await?;
    let _ = sock.shutdown().await;
    let drain = async {
        let mut tmp = [0u8; 1024];
        let mut drained = seen.len();
        while drained < 64 * 1024 {
            match sock.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => drained += n,
            }
        }
    };
    let _ = tokio::time::timeout_at(deadline, drain).await;
    Ok(())
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
    vary: Vec<String>,
    /// Extra headers layered on by the edge policy (security headers, CORS).
    headers: Vec<(String, String)>,
    /// The typed kernel error this answer reports, when it reports one: what an
    /// [`ErrorPageFn`] is shown as [`ErrorView::error`].
    error: Option<ikigai_core::Error>,
    /// The [`AdmitFn`]'s refusal this answer reports, when it reports one
    /// ([`ErrorView::refusal`]).
    refusal: Option<Refusal>,
    /// The failure class of the error or refusal ([`ErrorView::class`]).
    class: Option<FailureClass>,
    /// An answer to HEAD: the head GET would carry, `Content-Length` included, and no
    /// content (RFC 9110 §9.3.2). Set once, by [`into_head`](Self::into_head), after the answer
    /// is complete, so every path that builds a body builds GET's and none has to know the
    /// method.
    head_only: bool,
    /// Content that streams instead of `body` (ledger #2244): read as it is written, framed by
    /// `Content-Length` when its length is known and chunked when it is not. `None` for every
    /// answer held in `body`.
    stream: Option<stream::Sending>,
}

impl Resp {
    /// Name one more request header in `Vary`, once whatever its case.
    fn add_vary(&mut self, name: &str) {
        if !self.vary.iter().any(|v| v.eq_ignore_ascii_case(name)) {
            self.vary.push(name.to_string());
        }
    }

    /// This answer as HEAD sends it: the same status and headers, `Content-Length` the length
    /// of the content GET would send, and no content. The length used to be 0 on every HEAD,
    /// reads included, because each read path emptied its body before the head was written
    /// (ledger #118).
    fn into_head(mut self) -> Resp {
        self.head_only = true;
        self
    }

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
            error: None,
            refusal: None,
            class: None,
            head_only: false,
            stream: None,
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
async fn read_head<S: AsyncRead + Unpin>(sock: &mut S, buf: &mut Vec<u8>) -> std::io::Result<Head> {
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

/// Read ONE request off `sock` under `config`'s limits, exactly as the edge reads every
/// request it serves: the head within [`EdgeConfig::header_timeout`] and 64 KiB, a body only
/// by `Content-Length` (a transfer coding is refused, not ignored), at most
/// [`EdgeConfig::max_body_bytes`] (refused with `413`, never truncated), delivered within
/// [`EdgeConfig::body_timeout`], and never a partial one. An HTTP/1.1 request that asks
/// `Expect: 100-continue` is sent the interim `HTTP/1.1 100 Continue` once its head has passed
/// every check made on the head alone, and before the body is read, so a client holding its
/// body back is never left waiting out its own timeout.
///
/// `Ok(Some(request))` is a whole request, `peer` set on it. `Ok(None)` means there is nothing
/// to answer: the client hung up before a request arrived, or the request was REFUSED and the
/// refusal has already been written to `sock` (`400`, `408`, `413`, `431` or `501`, as
/// `text/plain`). A door with a router of its own (a TLS front, say) reads with this and
/// answers with [`write_response`], so the parsing and the bounds are this crate's in every
/// door rather than a copy per door.
///
/// ⚠ This reader is still the hand-written one, one request per connection: the routed door
/// ([`serve_with_listener`]) moved onto hyper (ledger #2236) and takes chunked bodies and
/// keep-alive, which this reader refuses (`501`) and does not offer.
///
/// ```
/// use ikigai_web::{read_request, write_response, EdgeConfig, Response};
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
///
/// # #[tokio::main]
/// # async fn main() {
/// let config = EdgeConfig::default();
/// let (mut client, mut server) = tokio::io::duplex(4096);
/// client
///     .write_all(b"POST /say?as=application%2Fjson HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi")
///     .await
///     .unwrap();
/// let req = read_request(&mut server, None, &config).await.unwrap().expect("a request");
/// assert_eq!((req.method.as_str(), req.path.as_str()), ("POST", "/say"));
/// assert_eq!(req.query, vec![("as".to_string(), "application/json".to_string())]);
/// assert_eq!(req.body, b"hi");
/// let answer = Response::new(200, "application/json", br#"{"ok":true}"#.to_vec());
/// write_response(&mut server, answer, &config).await.unwrap();
/// drop(server);
/// let mut out = String::new();
/// client.read_to_string(&mut out).await.unwrap();
/// assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "{out}");
/// assert!(out.ends_with(r#"{"ok":true}"#), "{out}");
///
/// // Over the body bound: refused here, answered, and nothing is handed to the caller.
/// let small = EdgeConfig { max_body_bytes: 1, ..EdgeConfig::default() };
/// let (mut client, mut server) = tokio::io::duplex(4096);
/// client.write_all(b"POST /say HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
/// assert!(read_request(&mut server, None, &small).await.unwrap().is_none());
/// drop(server);
/// let mut out = String::new();
/// client.read_to_string(&mut out).await.unwrap();
/// assert!(out.starts_with("HTTP/1.1 413 Payload Too Large"), "{out}");
/// # }
/// ```
pub async fn read_request<S>(
    sock: &mut S,
    peer: Option<IpAddr>,
    config: &EdgeConfig,
) -> std::io::Result<Option<HttpRequest>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let wt = config.write_timeout;
    // THE HEADERS ARE READ UNDER A DEADLINE. Without one a client that sends a byte every few
    // seconds (slow-loris) holds this connection, and its place under the cap, forever.
    let mut buf = Vec::new();
    let header_end =
        match tokio::time::timeout(config.header_timeout, read_head(sock, &mut buf)).await {
            Err(_) => {
                let resp = Resp::text(408, "Request Timeout", "request headers took too long");
                return refused(sock, resp, &buf, wt).await;
            }
            Ok(read) => match read? {
                Head::End(pos) => pos,
                Head::Closed => return Ok(None),
                Head::TooLarge => {
                    let resp = Resp::text(431, "Request Header Fields Too Large", "");
                    return refused(sock, resp, &buf, wt).await;
                }
            },
        };
    let mut req = match parse_head(&buf[..header_end]) {
        Ok(r) => r,
        Err(why) => return refused(sock, Resp::text(400, "Bad Request", &why), &buf, wt).await,
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
        return refused(
            sock,
            Resp::text(501, "Not Implemented", "unsupported transfer-encoding"),
            &buf,
            wt,
        )
        .await;
    }
    let max = config.max_body_bytes;
    // A `Content-Length` that is present but unreadable is a disagreement about framing,
    // not a zero-length body: treating it as 0 would silently deliver whatever trailed the
    // headers in the read buffer as the body.
    let cl: usize = match req.header("content-length") {
        None => 0,
        Some(raw) => match raw.parse() {
            Ok(n) => n,
            Err(_) => {
                return refused(
                    sock,
                    Resp::text(400, "Bad Request", "malformed Content-Length"),
                    &buf,
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
        return refused(
            sock,
            Resp::text(413, "Payload Too Large", "request body too large"),
            &buf,
            wt,
        )
        .await;
    }
    // Whatever already arrived behind the headers. Bounded by the 64 KiB header cap above,
    // but checked against `max` too so a deliberately small `max_body_bytes` still holds.
    let mut body = buf[header_end + 4..].to_vec();
    if body.len() > max {
        return refused(
            sock,
            Resp::text(413, "Payload Too Large", "request body too large"),
            &buf,
            wt,
        )
        .await;
    }
    // INVITE A BODY THE CLIENT IS HOLDING BACK (ledger #1408). A client that sends `Expect:
    // 100-continue` sends the head alone and waits for the interim `100` before the body, so a
    // door that reads the body without saying it costs every write the client's whole expect
    // timeout (curl's 1 s, a JVM HTTP client's 3 s), or, for a client that never gives up, the
    // body deadline and a 408. It is sent HERE, after every refusal that is decided on the head
    // alone (framing, the declared length), so a refused client is spared the upload: that is
    // what the expectation is for. Not for HTTP/1.0, which cannot read an interim answer and
    // whose expectation a server MUST ignore, and not when the whole body has already arrived
    // (RFC 9110 §10.1.1). Any other expectation is ignored, as RFC 9110 permits.
    if body.len() < cl && expects_continue(&buf[..header_end], &req) {
        let invite = async {
            sock.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            sock.flush().await
        };
        match tokio::time::timeout(wt, invite).await {
            Ok(done) => done?,
            // A client that will not take the invitation has no one left to answer.
            Err(_) => return Ok(None),
        }
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
    match tokio::time::timeout(config.body_timeout, read_body).await {
        Err(_) => {
            let resp = Resp::text(408, "Request Timeout", "request body took too long");
            return refused(sock, resp, &buf, wt).await;
        }
        Ok(read) => read?,
    }
    // The other end of the same principle. A client that declares more than it sends and
    // then hangs up has produced a PARTIAL submission, and delivering it would put the
    // endpoint back in the position this whole block exists to get it out of: unable to
    // tell an incomplete body from a complete one.
    if body.len() < cl {
        return refused(
            sock,
            Resp::text(400, "Bad Request", "incomplete request body"),
            &buf,
            wt,
        )
        .await;
    }
    body.truncate(cl);
    req.body = body;
    req.peer = peer;
    Ok(Some(req))
}

/// Whether a request asks `Expect: 100-continue` in a version that can take the interim
/// answer: HTTP/1.1, read off the request line of `head` (the request head through its last
/// header line), and the expectation's token in any case (RFC 9110 §10.1.1).
fn expects_continue(head: &[u8], req: &HttpRequest) -> bool {
    let line = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let version = line
        .split(|b| b.is_ascii_whitespace())
        .rfind(|part| !part.is_empty());
    version == Some(&b"HTTP/1.1"[..])
        && req.header("expect").is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("100-continue"))
        })
}

/// Write a refusal [`read_request`] decided on, and report that there is no request.
///
/// `raw` is whatever of the request arrived. When its method is `HEAD` the refusal is sent
/// as a head alone (RFC 9110 §9.3.2), even when the rest of the request could not be parsed:
/// the method is the first token of the first line, and nothing else is needed to know it.
async fn refused<S: AsyncWrite + Unpin>(
    sock: &mut S,
    resp: Resp,
    raw: &[u8],
    limit: std::time::Duration,
) -> std::io::Result<Option<HttpRequest>> {
    let resp = if is_head(raw) { resp.into_head() } else { resp };
    write_within(sock, resp, limit).await.map(|()| None)
}

/// Whether the request that begins `raw` is a `HEAD`: its first token, read the way
/// [`parse_head`] reads the method (whitespace-separated, case-sensitive as RFC 9110 §9.1
/// has it), whether or not the rest of the line has arrived.
fn is_head(raw: &[u8]) -> bool {
    let line = raw.split(|&b| b == b'\n').next().unwrap_or_default();
    let mut tokens = line
        .split(|b| b.is_ascii_whitespace())
        .filter(|t| !t.is_empty());
    // A method still arriving ("HEA") is not yet a HEAD; one followed by anything is.
    tokens.next() == Some(&b"HEAD"[..]) && (tokens.next().is_some() || line.len() > 4)
}

/// Serve one accepted connection: hyper's HTTP/1.1 server around the door ([`h1`]).
async fn handle(sock: TcpStream, peer: IpAddr, shared: Arc<Shared>) -> std::io::Result<()> {
    h1::serve_connection(sock, peer, shared).await
}

/// What the door answers one whole request with, before any HTTP version frames it.
pub(crate) enum Reply {
    /// A complete answer: status, headers and content (or the head alone, for `HEAD`).
    Whole(Resp),
    /// An answer whose content is not known when its head is sent: the push stream. `head`
    /// carries the status and headers; each item of `events` is written as it arrives, and the
    /// answer ends when the sender is dropped.
    Stream {
        head: Resp,
        events: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    },
}

/// The door's logic for one request that has already arrived whole (the bounds and the
/// deadlines of intake are [`door::exchange`]'s): admission, the push stream, routing,
/// dispatch, the error page and the edge policy. It knows nothing about the connection or the
/// HTTP version, so every listener answers through it.
pub(crate) async fn answer(shared: &Shared, req: HttpRequest) -> Reply {
    if let Some(refused) = refuse_admission(shared, &req) {
        return Reply::Whole(refused);
    }
    answer_admitted(shared, req, None).await
}

/// The current route table (hot-swappable): a cheap `Arc` clone, held only for one request.
fn route_table(shared: &Shared) -> Arc<RouteTable> {
    shared
        .routes
        .read()
        .map(|g| Arc::clone(&g))
        .unwrap_or_else(|_| Arc::new(RouteTable::default()))
}

/// ADMISSION, ahead of every answer this door gives: the push stream, OPTIONS, the
/// `?description` face and dispatch alike (ledger #879), and an upload before a byte of it is
/// spilled. Nothing below has run, so a refused request learns nothing about what is behind
/// the door. `Some` is the finished refusal.
fn refuse_admission(shared: &Shared, req: &HttpRequest) -> Option<Resp> {
    let refusal = shared.config.admit_fn.as_ref().and_then(|f| f(req))?;
    let mut resp = finish(refusal_resp(&refusal), req, &shared.config);
    apply_edge_policy(&mut resp, &shared.config, req, None);
    Some(resp)
}

/// [`answer`] once admission has passed. `content` is a spilled upload's content id
/// ([`upload`]): a Sink is issued with `content=b3:…` instead of the request body.
pub(crate) async fn answer_admitted(
    shared: &Shared,
    req: HttpRequest,
    content: Option<ikigai_core::ContentId>,
) -> Reply {
    // Resolve the route once; it drives the target IRI + per-route cap (in respond) and the
    // per-route CORS/CSP (in the policy layer). No match → the mechanical default throughout.
    let table = route_table(shared);
    // The event stream is not a resource read: it holds the answer open and sends cut
    // notices as they arrive, so it leaves the request/response path here, before routing.
    if let Some(push) = shared.config.push.as_ref() {
        if req.path == push.path {
            return push::open(&req, shared, &table, push);
        }
    }
    let matched = table.match_path(&req.path);
    let mut resp = finish(
        respond(shared, &req, matched.as_ref(), &table, content).await,
        &req,
        &shared.config,
    );
    apply_edge_policy(&mut resp, &shared.config, &req, matched.as_ref());
    Reply::Whole(resp)
}

/// The last word on any answer to a parsed request, whichever path built it: an error body
/// negotiated as a page or plain text ([`error_page::negotiate`]), then, for `HEAD`, the head
/// alone ([`Resp::into_head`]). Every path that writes an answer to a request it has parsed
/// goes through here, so no path has to remember either rule (ledger #117: a refusal written
/// on its own path sent its body to HEAD).
fn finish(resp: Resp, req: &HttpRequest, config: &EdgeConfig) -> Resp {
    let resp = error_page::negotiate(resp, req, config);
    if req.method == "HEAD" {
        resp.into_head()
    } else {
        resp
    }
}

/// The core adapter: method → verb (gated by `describe().verbs`), path → iri,
/// query → args, body → piped `content`, Accept → conneg, resolved under the cap.
async fn respond(
    shared: &Shared,
    req: &HttpRequest,
    matched: Option<&Matched>,
    table: &RouteTable,
    content: Option<ikigai_core::ContentId>,
) -> Resp {
    // Routes-only edge: an un-routed path is not part of the public surface — 404 before it
    // can reach the mechanical default (the exhaustive-allow-list posture).
    if shared.config.routes_only && matched.is_none() {
        return Resp::text(404, "Not Found", "no route");
    }
    let kernel = &shared.kernel;
    let config = &shared.config;
    // A matched route supplies the target IRI (from its template); otherwise the mechanical
    // `/noun/partition/key` → `urn:` default.
    let iri_str = match matched.map(|m| &m.iri) {
        Some(Ok(iri)) => iri.clone(),
        // A strict `{var}` refused its value: the route claimed the path, so nothing else may.
        Some(Err(why)) => return Resp::text(400, "Bad Request", why),
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
        return describe_response(described.as_ref(), &offered, &req.path);
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
    // A REPEATED ARGUMENT (ledger #387, #1547). A `Request` holds one value per name, so
    // `?graph=A&graph=B` reached the resource as `graph=B` and a join answered 200 with an
    // empty table; `?as=` kept the FIRST. Now the repeats of a LIST argument are JOINED with
    // its separator's canonical character (core's `ActionSpec::join_repeats`, the rule the
    // engine and MCP apply), so `?graph=A&graph=B` and `?graph=A,B` are one request and one
    // cache key; a repeat of any other name the request carries is a 400 naming it, before
    // anything is counted or built.
    let forwarded = match joined_query(req, verb, described.as_ref()) {
        Ok(forwarded) => forwarded,
        Err(refused) => return error_resp(config, &refused),
    };
    // PER-SOURCE RATE LIMIT (ledger #1717): counted once the request is one the resource would
    // run, and refused before anything is built or invoked. `OPTIONS` and `?description` have
    // answered above and are never counted.
    if let Some(limits) = config.source_limits.as_ref() {
        let source = source_key(client_ip(req, config).as_deref());
        if let Some(limited) = limits.check(&iri_str, &source) {
            return rate_limited(config, &limited);
        }
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
    for (k, v) in forwarded {
        request = request.with_arg(k, ArgRef::Inline(v.into_bytes()));
    }
    if verb == Verb::Sink {
        // A spilled upload travels as its content id, resolved inside the Sink's own
        // invocation (`Invocation::content_body`); any other body inline, as always.
        let body = match content {
            Some(id) => ArgRef::Content(id),
            None => ArgRef::Inline(req.body.clone()),
        };
        request = request.with_arg("content", body);
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

    // Resolve configuration before issuing the write: a bad destination must not leave
    // a successful mutation behind an error page. htmx keeps the in-place answer.
    let redirect = if req.method == "POST"
        && !req
            .header("hx-request")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"))
    {
        match matched.and_then(|m| m.redirect.as_deref()) {
            Some(iri) => match redirect::page_path(table, iri, config.routes_only) {
                Some(path) => Some(path),
                None => {
                    return Resp::text(
                        500,
                        "Internal Server Error",
                        "route redirect has no page path",
                    )
                }
            },
            None => None,
        }
    } else {
        None
    };

    let cap = request_capability(shared, req, matched);

    // Write-side preconditions (optimistic concurrency): If-Match / If-None-Match are
    // checked against the resource's CURRENT ETag before the mutation runs — a lost-update
    // guard for Sink and a conditional guard for Delete. Failing → 412 (or 403 if the cap
    // can't even read to check). Reads carry no precondition here (304 is handled below).
    if verb.is_mutating() && has_precondition(req) {
        if let Some(resp) = check_write_precondition(config, kernel, &iri, &cap, req).await {
            return resp;
        }
    }

    // PATCH is read-modify-write: the request Content-Type selects a patch strategy from
    // the registry, which transforms the current representation before it is Sunk. The
    // Sink it issues is THIS request — stamped above with `received`, `client` and
    // `principal` like any other write — with only its content replaced (ledger #520).
    if req.method == "PATCH" {
        let shared = !shaped_by_credentials(shared, req, matched, &cap);
        return apply_patch(config, kernel, request, &cap, req, shared).await;
    }

    // THROUGH THE BODY PATH (ledger #2244): the answer as the endpoint produced it, never
    // collected on the way. A buffer, a small body, and an `HTTP_ENTITY` envelope settle into
    // the whole-answer path below, exactly as before; anything else streams (`stream`).
    let settled = match kernel.issue_body(request, &cap).await {
        Ok(repr) => stream::settle(repr, verb == Verb::Source).await,
        Err(e) => Err(e),
    };
    let answer = match settled {
        Ok(stream::Settled::Whole(repr)) => Ok(repr),
        Ok(stream::Settled::Streamed(repr)) if verb == Verb::Source => {
            let freshness = Freshness {
                self_contained: self_contained(&repr, &iri, declared),
                shared: !shaped_by_credentials(shared, req, matched, &cap),
            };
            let vary = read_vary(explicit, &faces, matched, &cap);
            return stream::read(req, repr, freshness, vary);
        }
        Ok(stream::Settled::Streamed(repr)) => {
            if verb == Verb::Delete {
                record_tombstone(shared, tombstone_key(&iri_str, req));
            }
            return post_redirect(stream::write(repr), req, matched, redirect);
        }
        Err(e) => Err(e),
    };
    let answer = answer.map(|repr| {
        // An endpoint's response headers, when it asked for any (ledger #117). Checked here,
        // after the endpoint ran: a refused header refuses the ANSWER, never the work, so a
        // Delete that ran is still remembered below. Whether the credentials shaped the
        // answer costs a `cap_fn` call, so a write asks only when an envelope may need it.
        let shared = if verb == Verb::Source || entity::is_entity(&repr) {
            !shaped_by_credentials(shared, req, matched, &cap)
        } else {
            true
        };
        open_answer(config, &iri, verb, repr, shared)
    });
    match answer {
        Ok(Err(refused)) if verb == Verb::Delete => {
            record_tombstone(shared, tombstone_key(&iri_str, req));
            header_refused(&refused)
        }
        Ok(Err(refused)) => header_refused(&refused),
        // Reads project a strong ETag + Cache-Control and honor `If-None-Match` (→304).
        Ok(Ok(served)) if verb == Verb::Source => {
            let repr = &served.repr;
            let freshness = Freshness {
                self_contained: self_contained(repr, &iri, declared),
                shared: served.shared,
            };
            read_resp(
                req,
                served,
                freshness,
                read_vary(explicit, &faces, matched, &cap),
            )
        }
        Ok(Ok(served)) if verb == Verb::Delete => {
            record_tombstone(shared, tombstone_key(&iri_str, req));
            write_resp(verb, served)
        }
        Ok(Ok(served)) => post_redirect(write_resp(verb, served), req, matched, redirect),
        // A DELETE of an already-absent resource is idempotent (204) within the tombstone
        // window; otherwise it's a genuine 404, carrying the endpoint's own message.
        Err(e @ ikigai_core::Error::NotFound(_)) if verb == Verb::Delete => {
            if tombstoned(shared, &tombstone_key(&iri_str, req)) {
                Resp::status(204, "No Content")
            } else {
                error_resp_allowing(config, &e, Some(&allow))
            }
        }
        // The resource's declared methods are at hand here, so a 405 from an endpoint
        // that refuses a verb it declares (`Unsupported`) carries `Allow`.
        Err(e) => error_resp_allowing(config, &e, Some(&allow)),
    }
}

/// The request headers that selected a read's answer, for its `Vary`.
fn read_vary(
    explicit: Option<&str>,
    faces: &Faces,
    matched: Option<&Matched>,
    cap: &Capability,
) -> Vec<String> {
    let mut vary: Vec<String> = Vec::new();
    // `Accept` selected this face unless the client named it in the URL (`?as=`, which
    // every cache keys on already) or the resource has exactly one face to give.
    if explicit.is_none() && faces.served.len() != 1 {
        vary.push("Accept".to_string());
    }
    // The headers a capability function reads identity from. The edge cannot see
    // inside `cap_fn`, so it names them whenever `cap_fn` was consulted; a route that
    // pins its capability makes the answer the same for every caller — unless the
    // door named a principal, which it read off the same credentials.
    if matched.and_then(|m| m.cap.as_ref()).is_none() || cap.principal().is_some() {
        vary.extend(CREDENTIAL_HEADERS.iter().map(|(_, name)| name.to_string()));
    }
    vary
}

/// A successful write's answer, after Post/Redirect/Get: a non-htmx `POST` to a route that
/// names a page answers `303 See Other` to it (its content dropped), unless the endpoint's
/// own `Location` already chose the outcome.
fn post_redirect(
    mut resp: Resp,
    req: &HttpRequest,
    matched: Option<&Matched>,
    redirect: Option<String>,
) -> Resp {
    if req.method == "POST" && matched.is_some_and(|m| m.redirect.is_some()) {
        resp.add_vary("HX-Request");
    }
    // An explicit endpoint Location already chose the outcome; keep it.
    if let Some(path) = redirect.filter(|_| matches!(resp.status, 200 | 204)) {
        resp.status = 303;
        resp.reason = "See Other";
        resp.body.clear();
        resp.stream = None;
        resp.headers.push(("Location".into(), path));
    }
    resp
}

/// The capability a request resolves under: a matched route's per-route ceiling (the
/// multi-tenant seam) when it pins one, otherwise the server-wide `cap_fn`. One function, so
/// the description face and resolution cannot disagree about who is asking.
///
/// The door's [`PrincipalFn`] answer is MINTED into it as core's principal scope (ledger
/// #1077, core 0.1.93), on every verb, reads included: an endpoint asks who it serves with
/// `inv.capability.principal()`, and the kernel's cache, which keys on the capability, keeps
/// one principal's answer from another's. Nothing is minted under a root capability (root
/// names nobody), or for an answer core cannot carry verbatim (not an absolute IRI, over 512
/// bytes, holding `*`); the stamped `principal` argument on a write is unchanged either way.
fn request_capability(shared: &Shared, req: &HttpRequest, matched: Option<&Matched>) -> Capability {
    let capability = match matched.and_then(|m| m.cap.as_ref()) {
        Some(scopes) => Capability::scoped(scopes.clone()),
        None => (shared.cap_fn)(req),
    };
    match shared.config.principal_fn.as_ref().and_then(|f| f(req)) {
        Some(principal) => capability.with_principal(&principal).unwrap_or(capability),
        None => capability,
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
///
/// `sink` is the request the edge built for this PATCH: the Sink of the target, already
/// carrying the provenance every write carries (`received`, `client`, `principal`) and
/// the forwarded query. Only `content` and `content-type` are replaced, by the patched
/// document and its current media type, so a patched resource records who wrote it and
/// when exactly as a `PUT` does.
async fn apply_patch(
    config: &EdgeConfig,
    kernel: &Kernel,
    sink: Request,
    cap: &Capability,
    req: &HttpRequest,
    shared: bool,
) -> Resp {
    let iri = sink.target.clone();
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
        // The content a read serves, so the patch applies to what the client saw.
        Ok(repr) => served_content(repr),
        Err(e) => return error_resp(config, &e), // NotFound → 404, Denied → 403
    };
    let patched = match strategy(&current.bytes, &req.body) {
        Ok(bytes) => bytes,
        Err(detail) => return Resp::text(422, "Unprocessable Content", &detail),
    };
    let sink = sink.with_arg("content", ArgRef::Inline(patched)).with_arg(
        "content-type",
        ArgRef::Inline(media_type_of(&current).into_bytes()),
    );
    match kernel.issue(sink, cap).await {
        Ok(repr) => match open_answer(config, &iri, Verb::Sink, repr, shared) {
            Err(refused) => header_refused(&refused),
            Ok(served) if served.repr.bytes.is_empty() => write_resp(Verb::Sink, served),
            Ok(served) => {
                let mut resp = Resp {
                    etag: Some(etag_of(&served.repr)),
                    ..Resp::status(200, "OK")
                };
                served.answer(&mut resp);
                resp
            }
        },
        Err(e) => error_resp(config, &e),
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
/// `Source` under the same cap). Returns `Some(resp)` to short-circuit (412, or the read's
/// own failure status when the state could not be read: 403, 503, …), or `None` if the
/// precondition holds and the write should proceed.
async fn check_write_precondition(
    config: &EdgeConfig,
    kernel: &Kernel,
    iri: &Iri,
    cap: &Capability,
    req: &HttpRequest,
) -> Option<Resp> {
    // Current state: `Some(validator)` if it exists and is readable, `None` if absent. The
    // validator is the one a read of it hands out (`None` for a streamed body that has none),
    // so it is read through the body path too and settled the way a read settles it.
    let current = match kernel
        .issue_body(Request::new(Verb::Source, iri.clone()), cap)
        .await
    {
        Ok(repr) => match stream::settle(repr, true).await {
            Ok(stream::Settled::Whole(repr)) => Some(Some(etag_of(&served_content(repr)))),
            Ok(stream::Settled::Streamed(repr)) => Some(stream::validator_etag(&repr)),
            Err(e) => return Some(error_resp(config, &e)),
        },
        // Only an answer that SAYS the resource is absent is absent: the bound endpoint's
        // NotFound, or no endpoint bound at all.
        Err(ikigai_core::Error::NotFound(_) | ikigai_core::Error::Unresolved(_)) => None,
        // Any other failure (denied, a transient Unavailable or Timeout, an endpoint error)
        // means the state could not be read, and a precondition cannot be judged against a
        // state nobody read. Answer the failure's own status and write nothing (ledger
        // #1883): counting it as "absent" let a create-only `If-None-Match: *` write over a
        // resource whose store was briefly unavailable.
        Err(e) => return Some(error_resp(config, &e)),
    };
    let failed = |detail: &str| Some(Resp::text(412, "Precondition Failed", detail));

    // If-Match: the resource must exist and (for a list) match. `*` = must exist.
    if let Some(im) = req.header("if-match") {
        match &current {
            Some(_) if im.trim() == "*" => {}
            Some(Some(etag)) if etag_list_contains(im, etag, Compare::Strong) => {}
            _ => return failed("if-match precondition failed"),
        }
    }
    // If-None-Match: `*` = must NOT exist (create-only); a list must NOT match.
    if let Some(inm) = req.header("if-none-match") {
        let hit = match &current {
            Some(_) if inm.trim() == "*" => true,
            Some(Some(etag)) => etag_list_contains(inm, etag, Compare::Weak),
            _ => false,
        };
        if hit {
            return failed("if-none-match precondition failed");
        }
    }
    None
}

/// The two entity-tag comparisons of RFC 9110 §8.8.3.2.
#[derive(Clone, Copy)]
enum Compare {
    /// Both tags strong and identical — what `If-Match` requires (§13.1.1).
    Strong,
    /// Identical once any `W/` is set aside — what `If-None-Match` uses (§13.1.2).
    Weak,
}

/// Whether a comma-separated ETag list contains our validator under `compare`. We only
/// mint strong tags, so under [`Compare::Strong`] a listed `W/` tag never matches: a weak
/// validator does not promise the bytes a lost-update guard protects.
fn etag_list_contains(header: &str, etag: &str, compare: Compare) -> bool {
    let bare = etag.trim_start_matches("W/");
    header.split(',').any(|tok| {
        let tok = tok.trim();
        match compare {
            Compare::Strong => !tok.starts_with("W/") && tok == bare,
            Compare::Weak => tok.trim_start_matches("W/") == bare,
        }
    })
}

/// The query arguments a request hands the kernel, in the order the client sent them.
///
/// `as`/`content` are the adapter's own (`as` is negotiated separately). On a write, so are
/// the provenance names (`received`, `client`, `principal`): the transport supplies them, and
/// a submitter must not be able to forge an origin by appending `?client=…` to the URL, nor an
/// identity by appending `?principal=…`. `principal` is reserved on a READ as well (ledger
/// #879): a read carries none, and a host that reads the stamped principal off a request must
/// never find a submitter's there.
fn forwarded_query(req: &HttpRequest, verb: Verb) -> impl Iterator<Item = (&str, &str)> {
    req.query
        .iter()
        .filter(move |(k, _)| {
            let reserved = k == "as"
                || k == "content"
                || k == "principal"
                || (verb.is_mutating() && is_provenance(k));
            !reserved
        })
        .map(|(k, v)| (k.as_str(), v.as_str()))
}

/// The query arguments [`forwarded_query`] passes on, one value per name: the repeats of a
/// LIST argument of the resource's `verb` action joined with its separator's canonical
/// character (ledger #1547, core's `ActionSpec::join_repeats`), in first-seen order. A
/// repeat of `as` or of any other forwarded name is the typed `InvalidArgument … given
/// twice` (ledger #387). Reserved names the door drops are not arguments of the request, so
/// their repeats are not counted. With no contract, nothing is a list.
fn joined_query(
    req: &HttpRequest,
    verb: Verb,
    described: Option<&ikigai_core::Description>,
) -> Result<Vec<(String, String)>, ikigai_core::Error> {
    let given_twice = |name: &str| ikigai_core::Error::InvalidArgument {
        name: name.to_string(),
        detail: ikigai_core::GIVEN_TWICE.to_string(),
    };
    if req.query.iter().filter(|(k, _)| k == "as").count() > 1 {
        return Err(given_twice("as"));
    }
    // The verb's action, or one with no inputs (nothing is a list) when there is no contract.
    let action = described
        .and_then(|d| d.action_specs().into_iter().find(|a| a.verb == verb))
        .unwrap_or_else(|| ikigai_core::ActionSpec::new(verb));
    let proposed = ikigai_core::ProposedArgs::from_pairs(forwarded_query(req, verb));
    Ok(action
        .join_repeats(&proposed)?
        .pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect())
}

/// What a DELETE tombstone is keyed on: the target IRI AND the query arguments the kernel was
/// handed. HTTP names a request's target by its path and its query together, and so does the
/// endpoint: one path can front many things, chosen by an argument (a take of one item out of
/// a collection). Keyed on the path alone, one successful delete made every later absent
/// answer on that path read as `204` for the tombstone's whole window, whatever was asked for.
/// An argument-free DELETE keys on the IRI alone, exactly as before.
///
/// The arguments are ordered by name (a stable sort, so repeats of one name keep the client's
/// order): the kernel reads arguments by name, so `?a=1&b=2` and `?b=2&a=1` are one request.
/// `as` and the provenance names are excluded by [`forwarded_query`]: they shape the answer or
/// record its origin, and never choose what is deleted.
fn tombstone_key(iri: &str, req: &HttpRequest) -> TombstoneKey {
    let mut args: Vec<(String, String)> = forwarded_query(req, Verb::Delete)
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    args.sort_by(|a, b| a.0.cmp(&b.0));
    (iri.to_string(), args)
}

/// Record that this request deleted something, so its repeat is idempotent for a bounded
/// window. Expired entries are dropped here: the key now carries the query, so the table
/// would otherwise keep one entry per distinct successful delete for the life of the process.
fn record_tombstone(shared: &Shared, key: TombstoneKey) {
    if let Ok(mut t) = shared.tombstones.lock() {
        t.retain(|_, at| at.elapsed() < TOMBSTONE_TTL);
        // Native-only: `ikigai-web` is the INBOUND HTTP transport — a tokio TcpListener
        // bound to a port — so it has no wasm build. This is the DELETE tombstone's
        // monotonic expiry mark, which must not move when the wall clock does.
        #[allow(clippy::disallowed_methods)]
        t.insert(key, std::time::Instant::now());
    }
}

/// Whether this request has a live (unexpired) tombstone — i.e. it deleted something
/// recently. Prunes the entry when it has aged past the TTL.
fn tombstoned(shared: &Shared, key: &TombstoneKey) -> bool {
    if let Ok(mut t) = shared.tombstones.lock() {
        if let Some(at) = t.get(key) {
            if at.elapsed() < TOMBSTONE_TTL {
                return true;
            }
            t.remove(key);
        }
    }
    false
}

/// The `429` a request past its per-source budget is answered with: `Retry-After` in whole
/// seconds, and the refusal as a sentence (a page for a browser, through [`finish`]) or, under
/// [`ErrorBody::Json`], as `{"kind":"rate-limited","message":…,"retry_after":…}`.
fn rate_limited(config: &EdgeConfig, limited: &source_limit::Limited) -> Resp {
    let retry_after = limited.retry_after_secs();
    let mut resp = match config.error_body {
        ErrorBody::Json => Resp {
            content_type: "application/json".to_string(),
            body: serde_json::json!({
                "kind": "rate-limited",
                "message": limited.message(),
                "retry_after": retry_after,
            })
            .to_string()
            .into_bytes(),
            ..Resp::status(429, "Too Many Requests")
        },
        ErrorBody::Text => Resp::text(429, "Too Many Requests", &limited.message()),
    };
    resp.headers
        .push(("Retry-After".to_string(), retry_after.to_string()));
    resp.class = Some(FailureClass::RetryAfter);
    resp
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
/// `If-None-Match` matches. A HEAD is answered from this same response (see [`Resp::into_head`]).
fn read_resp(req: &HttpRequest, served: Served, freshness: Freshness, vary: Vec<String>) -> Resp {
    let repr = &served.repr;
    let etag = etag_of(repr);
    let cc = Some(cache_control_of(repr.expiry, freshness, wall_clock_ms()));
    if let Some(inm) = req.header("if-none-match") {
        if if_none_match_hit(inm, &etag) {
            let mut resp = Resp {
                etag: Some(etag),
                cache_control: cc,
                vary,
                ..Resp::status(304, "Not Modified")
            };
            served.asked_for(&mut resp);
            return resp;
        }
    }
    let mut resp = Resp {
        etag: Some(etag),
        cache_control: cc,
        vary,
        ..Resp::status(200, "OK")
    };
    served.answer(&mut resp);
    resp
}

/// Wall-clock now, in milliseconds since the epoch: what turns an `Expiry::At` deadline into a
/// `max-age` a remote cache counts down.
///
/// Native-only: `ikigai-web` is the inbound HTTP transport (a tokio TcpListener), so it has no
/// wasm build and no kernel handle to take an injected Clock from here. The function is the
/// smallest item the opt-out can sit on, and it reads the clock and nothing else.
#[allow(clippy::disallowed_methods)]
fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A write response: a Sink or Delete returning no body → 204; otherwise 200 with whatever
/// representation the write produced. A Delete can answer with one (a take returns the thing
/// it took), and a 204 would discard it.
fn write_resp(verb: Verb, served: Served) -> Resp {
    let mut resp = if verb.is_mutating() && served.repr.bytes.is_empty() {
        Resp::status(204, "No Content")
    } else {
        Resp::status(200, "OK")
    };
    served.answer(&mut resp);
    resp
}

/// An endpoint's answer as the door serves it: the content (an [`HTTP_ENTITY`] envelope
/// opened, anything else as it came), its `Content-Type`, and the response headers it asked
/// for, already checked.
struct Served {
    repr: ikigai_core::Representation,
    content_type: String,
    asked: Vec<(EndpointHeader, String)>,
    /// Any caller would have been handed this answer (see [`shaped_by_credentials`]); when
    /// false, an endpoint's `Cache-Control` is made `private`.
    shared: bool,
}

impl Served {
    /// Fill `resp` with this answer: its content (none for a `204`, which carries none) and
    /// every header the endpoint asked for.
    fn answer(self, resp: &mut Resp) {
        self.apply(resp, true);
    }

    /// Only the headers a `304` repeats (RFC 9110 §15.4.5): `Cache-Control`, `Vary`, and a
    /// `Set-Cookie`, which is not representation metadata. No content and no content metadata.
    fn asked_for(self, resp: &mut Resp) {
        self.apply(resp, false);
    }

    fn apply(self, resp: &mut Resp, with_content: bool) {
        // A `Location` (only ever on a write's answer, see `entity::open`) makes the answer a
        // `303 See Other` before anything else is decided, so its content rides as the 303's
        // body even where an empty write would have been `204`.
        if self
            .asked
            .iter()
            .any(|(h, _)| *h == EndpointHeader::Location)
        {
            resp.status = 303;
            resp.reason = "See Other";
        }
        if with_content && resp.status != 204 {
            resp.content_type = self.content_type;
            resp.body = self.repr.bytes;
        }
        for (header, value) in self.asked {
            match header {
                EndpointHeader::CacheControl => {
                    resp.cache_control = Some(if self.shared {
                        value
                    } else {
                        private_cache_control(&value)
                    });
                }
                EndpointHeader::Vary => {
                    for name in value.split(',').map(str::trim).filter(|n| !n.is_empty()) {
                        resp.add_vary(name);
                    }
                }
                EndpointHeader::SetCookie | EndpointHeader::Location => {
                    resp.headers.push((header.name().to_string(), value))
                }
                EndpointHeader::ContentDisposition | EndpointHeader::ContentLanguage => {
                    if with_content && resp.status != 204 {
                        resp.headers.push((header.name().to_string(), value));
                    }
                }
            }
        }
    }
}

/// Open an endpoint's answer for serving (see [`Served`]). An [`HTTP_ENTITY`] envelope the
/// door cannot accept is refused (see [`header_refused`]), and logged, because the fault is
/// the endpoint's and only its operator can fix it.
fn open_answer(
    config: &EdgeConfig,
    iri: &Iri,
    verb: Verb,
    mut repr: ikigai_core::Representation,
    shared: bool,
) -> Result<Served, HeaderRefusal> {
    if !entity::is_entity(&repr) {
        return Ok(Served {
            content_type: media_type_of(&repr),
            repr,
            asked: Vec::new(),
            shared,
        });
    }
    match entity::open(&mut repr, &config.endpoint_headers, verb.is_mutating()) {
        Ok(opened) => Ok(Served {
            repr,
            content_type: opened.content_type,
            asked: opened.headers,
            shared,
        }),
        Err(refused) => {
            eprintln!("ikigai-web: {} ({})", refused, iri.as_str());
            Err(refused)
        }
    }
}

/// The answer to an endpoint whose response headers the door refused: `500`, naming the
/// header and why. None of the refused answer is served, its content included.
fn header_refused(refused: &HeaderRefusal) -> Resp {
    Resp::text(500, "Internal Server Error", &refused.to_string())
}

/// The content an answer serves, for computing its validator: an [`HTTP_ENTITY`] envelope
/// opened (whatever its headers), anything else as it is. So a precondition is checked
/// against the same `ETag` a read of the resource hands out.
fn served_content(mut repr: ikigai_core::Representation) -> ikigai_core::Representation {
    if entity::is_entity(&repr) {
        // On a refusal `open` leaves `repr` as it was, and the envelope is hashed whole.
        let _ = entity::open(&mut repr, &EndpointHeader::ALL, true);
    }
    repr
}

/// An endpoint's `Cache-Control` for an answer the request's credentials shaped: `public`
/// dropped, and `private` added unless it already says `private` or `no-store`. The endpoint
/// cannot see what the door's capability function made of the credentials; the door can.
fn private_cache_control(value: &str) -> String {
    let directives: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|d| !d.is_empty() && !d.eq_ignore_ascii_case("public"))
        .collect();
    let named = |name: &str| {
        directives.iter().any(|d| {
            d.split('=')
                .next()
                .is_some_and(|n| n.trim().eq_ignore_ascii_case(name))
        })
    };
    if named("private") || named("no-store") {
        directives.join(", ")
    } else {
        std::iter::once("private")
            .chain(directives)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// A strong ETag: a content hash over the representation's type + bytes (quoted, per
/// RFC 9110). Changes iff the representation's content changes. See [`etag_from`].
fn etag_of(repr: &ikigai_core::Representation) -> String {
    etag_from(&repr.repr_type, &ikigai_core::ContentId::of(&repr.bytes))
}

/// The strong ETag of content `id` served as `repr_type`: a hash over the type's canonical
/// form and the content id. One rule whatever the body's shape (ledger #2244), so a buffer
/// and a streamed body of the same bytes and type carry the same tag, and a streamed body
/// whose producer knows its content id ([`Replay::validator`](ikigai_core::Replay::validator),
/// what a spill computes while it writes) has a tag without being read.
///
/// ```text
/// "<hex of blake3(canonical type, 0x00, the 32-byte content id)>"
/// ```
///
/// Before ledger #2244 the hash ran over the bytes themselves rather than their id, so every
/// tag changed once with it: a cache revalidates each stored answer once (a `200` where it
/// would have had a `304`) and is right from then on.
fn etag_from(repr_type: &ikigai_core::ReprType, id: &ikigai_core::ContentId) -> String {
    let mut h = blake3::Hasher::new();
    h.update(repr_type.canonical().as_bytes());
    h.update(&[0]); // domain separator between type and content
    h.update(id.as_bytes());
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
/// - threads do not cross a mount (`serde(skip)`), so an answer from a peer arrived looking
///   independent of everything; since ledger #92 a mount hands its kernel every peer answer
///   as `Always` instead (`ikigai-resolve`'s `as_held_here`), but a host that serves a peer's
///   answer by some other route still cannot see the peer's threads.
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
fn self_contained<B>(repr: &ikigai_core::Representation<B>, iri: &Iri, declared: &[Verb]) -> bool {
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
    // A capability naming a principal is that party's answer (ledger #1077), whatever else
    // the credentials did or did not grant.
    if cap.principal().is_some() {
        return true;
    }
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
///
/// The body follows [`EdgeConfig::error_body`]: the message as `text/plain` by default, the
/// typed object of [`error_json`] when the door asked for JSON.
///
/// The headers the status calls for ride along (ledger #1546): a `RetryAfter` answers `429`
/// with `Retry-After` in seconds, rounded up and never 0 ([`retry_after_seconds`]); an
/// `Unsupported` that names a verb answers `405`, with `Allow` when the caller knows the
/// resource's declared methods ([`error_resp_allowing`]).
fn error_resp(config: &EdgeConfig, e: &ikigai_core::Error) -> Resp {
    error_resp_allowing(config, e, None)
}

/// [`error_resp`] with the resource's `Allow` list at hand, for a `405`.
fn error_resp_allowing(config: &EdgeConfig, e: &ikigai_core::Error, allow: Option<&str>) -> Resp {
    let status = error_status(e);
    let reason = reason_phrase(status);
    let mut resp = match config.error_body {
        ErrorBody::Json => Resp {
            content_type: "application/json".to_string(),
            body: error_json(e).into_bytes(),
            ..Resp::status(status, reason)
        },
        ErrorBody::Text => Resp::text(status, reason, &format!("{e}")),
    };
    if let Some(seconds) = retry_after_seconds(e) {
        resp.headers
            .push(("Retry-After".to_string(), seconds.to_string()));
    }
    resp.class = Some(e.class());
    resp.error = Some(e.clone());
    if status == 405 {
        resp.allow = allow.map(str::to_string);
    }
    resp
}

/// The `Retry-After` an error is answered with, in delay-seconds: a `RetryAfter`
/// (`ikigai_core::Error::RetryAfter`) with a known delay, rounded UP and never 0 (a `0` would tell the
/// client to retry at once, which is not what a stated delay means; RFC 9110 §10.2.3).
/// `None` for every other error, and for a `RetryAfter` with no delay: no header is sent.
/// The rule is core's shared `failure_class_vectors.json`, which the faces pin too.
///
/// ```
/// use std::time::Duration;
/// use ikigai_core::Error;
/// use ikigai_web::retry_after_seconds;
///
/// let after = |delay| Error::RetryAfter { delay: Some(delay), detail: "limited".into() };
/// assert_eq!(retry_after_seconds(&after(Duration::from_secs(30))), Some(30));
/// assert_eq!(retry_after_seconds(&after(Duration::from_millis(1_500))), Some(2));
/// assert_eq!(retry_after_seconds(&after(Duration::from_micros(1_200))), Some(1));
/// assert_eq!(retry_after_seconds(&after(Duration::ZERO)), Some(1));
/// assert_eq!(retry_after_seconds(&Error::RetryAfter { delay: None, detail: "x".into() }), None);
/// assert_eq!(retry_after_seconds(&Error::Timeout("slow".into())), None);
/// ```
pub fn retry_after_seconds(e: &ikigai_core::Error) -> Option<u64> {
    e.retry_after_millis()
        .map(|millis| millis.div_ceil(1000).max(1))
}

/// The HTTP status a typed kernel error is answered with, in every door this crate serves,
/// the DECIDED table of ledger #1546 (core's shared `failure_class_vectors.json`, which the
/// Python and Deno faces pin to the same numbers): `Denied` 403, `NotFound`/`Unresolved`
/// 404, a missing or invalid argument 400, `Conflict` 409, `Timeout` 504 (was 503 before
/// 0.1.66: the edge waited on something that did not answer, which is a gateway's timeout),
/// `Unavailable` 503, `RetryAfter` 429 (with `Retry-After`, see [`retry_after_seconds`]),
/// `OverBudget` 422, `Refused` 502 (a remote authority refused the credential this side
/// presented), `Unsupported` 405 when it names a verb (with `Allow`) and 501 when it names a
/// missing host facility, `DepthExceeded` and `Endpoint` 500, and any variant core adds later
/// 500 until this table names it.
///
/// ```
/// use std::time::Duration;
/// use ikigai_core::{Error, Iri, Verb};
/// use ikigai_web::error_status;
///
/// assert_eq!(error_status(&Error::Denied("no".into())), 403);
/// assert_eq!(error_status(&Error::Conflict("taken by bob".into())), 409);
/// assert_eq!(error_status(&Error::MissingArgument("tuple".into())), 400);
/// assert_eq!(error_status(&Error::Timeout("slow".into())), 504);
/// assert_eq!(error_status(&Error::Unavailable("down".into())), 503);
/// assert_eq!(error_status(&Error::RetryAfter { delay: Some(Duration::from_secs(30)), detail: "limited".into() }), 429);
/// assert_eq!(error_status(&Error::OverBudget { detail: "past 5000 ms".into() }), 422);
/// assert_eq!(error_status(&Error::Refused("401".into())), 502);
/// assert_eq!(error_status(&Error::Unsupported { verb: Some(Verb::Sink), detail: "read-only".into() }), 405);
/// assert_eq!(error_status(&Error::Unsupported { verb: None, detail: "no clock".into() }), 501);
/// assert_eq!(error_status(&Error::DepthExceeded { depth: 65, target: Iri::parse("urn:x").unwrap() }), 500);
/// assert_eq!(error_status(&Error::Endpoint("boom".into())), 500);
/// ```
pub fn error_status(e: &ikigai_core::Error) -> u16 {
    use ikigai_core::Error;
    match e {
        Error::Denied(_) => 403,
        Error::NotFound(_) | Error::Unresolved(_) => 404,
        Error::MissingArgument(_) | Error::InvalidArgument { .. } => 400,
        Error::Conflict(_) => 409,
        Error::Timeout(_) => 504,
        Error::Unavailable(_) => 503,
        Error::RetryAfter { .. } => 429,
        Error::OverBudget { .. } => 422,
        Error::Refused(_) => 502,
        Error::Unsupported { verb: Some(_), .. } => 405,
        Error::Unsupported { verb: None, .. } => 501,
        _ => 500,
    }
}

/// The reason phrase for a status this crate answers with; `""` for one it never sends.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        303 => "See Other",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Timeout",
        409 => "Conflict",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

/// A response a door with its own router writes with [`write_response`]: a status, a
/// content type (empty for none), extra headers and a body. `Connection: close` is always
/// written, and `Content-Length` on every status but `204` and `304`, which carry no content
/// and must not claim a length (RFC 9110 §8.6, ledger #1597); one request is served per
/// connection, as the edge serves them.
///
/// The writer checks every header before it writes a byte ([`Response::check`], ledger #1593):
/// a name is an RFC 9110 `token`; a value, the content type's included, is at most
/// [`MAX_HEADER_VALUE`] bytes of visible ASCII, space and tab, the same check an endpoint's
/// headers pass, so no CR, LF or NUL can end a line and start a header of its own; and the
/// headers the writer owns are refused from the list: `Content-Length`, `Content-Type`
/// (written from `content_type`), `Connection`, `Transfer-Encoding` and the other hop-by-hop
/// headers (`Keep-Alive`, `Proxy-Connection`, `TE`, `Trailer`, `Upgrade`). Any other name is
/// the door's to set (`Allow`, `WWW-Authenticate`, `Retry-After`, `Cache-Control`, …).
///
/// The status line is checked too (ledger #1594), and its refusal names no header (`header`
/// is empty): the status is a final one, `200..=599`, since a `1xx` is interim and is never
/// followed by the `Content-Length` and `Connection: close` this writer always sends, and a
/// code outside `100..=599` is no status at all; and a `204` or a `304` carries no content
/// (RFC 9110 §15.3.5, §15.4.5), so one with a body is refused rather than written with it.
///
/// ```
/// use ikigai_web::Response;
///
/// let ok = Response::new(405, "application/json", b"{}".to_vec()).with_header("Allow", "GET, HEAD");
/// assert_eq!(ok.check(), Ok(()));
///
/// let smuggled = Response::new(200, "text/plain", Vec::new())
///     .with_header("X-Note", "hi\r\nSet-Cookie: stolen=1");
/// assert_eq!(smuggled.check().unwrap_err().header, "X-Note");
///
/// let framing = Response::new(200, "text/plain", Vec::new()).with_header("Content-Length", "0");
/// assert_eq!(framing.check().unwrap_err().header, "Content-Length");
///
/// let interim = Response::new(101, "", Vec::new());
/// assert_eq!(interim.check().unwrap_err().header, "");
/// assert!(Response::new(600, "text/plain", Vec::new()).check().is_err());
/// assert!(Response::new(204, "", b"x".to_vec()).check().is_err());
/// assert!(Response::new(304, "", Vec::new()).check().is_ok());
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// `status` with `body` as `content_type` and no extra headers.
    pub fn new(status: u16, content_type: &str, body: Vec<u8>) -> Response {
        Response {
            status,
            content_type: content_type.to_string(),
            headers: Vec::new(),
            body,
        }
    }

    /// One more header. Nothing is checked here (the fields are public, so a check here could
    /// be walked around); [`write_response`] checks every header before it writes.
    pub fn with_header(mut self, name: &str, value: &str) -> Response {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Whether [`write_response`] will write this response: `Err` names the first header it
    /// would refuse and why, or no header when it is the status line it refuses (see
    /// [`Response`] for the rules). A door that wants to answer something rather than drop the
    /// connection checks first and writes its own `500`.
    pub fn check(&self) -> Result<(), HeaderRefusal> {
        if !(200..=599).contains(&self.status) {
            return Err(HeaderRefusal::new(
                "",
                format!(
                    "status {} is not a final status (200..=599); this writer sends one \
                     complete answer per connection",
                    self.status
                ),
            ));
        }
        if matches!(self.status, 204 | 304) && !self.body.is_empty() {
            return Err(HeaderRefusal::new(
                "",
                format!(
                    "a {} carries no content, and this one has {} bytes",
                    self.status,
                    self.body.len()
                ),
            ));
        }
        if !self.content_type.is_empty() {
            entity::check_value("Content-Type", &self.content_type)?;
        }
        self.headers
            .iter()
            .try_for_each(|(name, value)| entity::check_door_header(name, value))
    }
}

/// Write `response` to `sock` within [`EdgeConfig::write_timeout`], then flush. The other half
/// of [`read_request`]: the head is formatted exactly as the edge formats its own answers.
///
/// A response [`Response::check`] refuses is NOT written: not one byte reaches `sock`, and the
/// result is an [`InvalidInput`](std::io::ErrorKind::InvalidInput) error whose inner error is
/// the [`HeaderRefusal`]. An `Err`, not a panic and not a `500` written in its place, because
/// the bad header is the calling door's own bug: a panic would take the connection's task with
/// it and say nothing to the client, and a `500` written here would be in this crate's format,
/// not the door's (the layers front answers JSON), and would hide the bug from the door that
/// must fix it. The caller decides what the client hears; [`Response::check`] lets it decide
/// before writing.
///
/// This writes the content whatever the method was. A door answering a `HEAD` writes with
/// [`write_answer`].
///
/// The head frames the content with `Content-Length`, except on a `204` or a `304`, which
/// carry none and claim no length (RFC 9110 §8.6, ledger #1597):
///
/// ```
/// use ikigai_web::{write_response, EdgeConfig, Response};
/// use tokio::io::AsyncReadExt;
///
/// # #[tokio::main]
/// # async fn main() {
/// for (status, length) in [(200, Some("Content-Length: 2")), (204, None), (304, None)] {
///     let body = if status == 200 { b"hi".to_vec() } else { Vec::new() };
///     let (mut client, mut server) = tokio::io::duplex(4096);
///     write_response(&mut server, Response::new(status, "", body), &EdgeConfig::default())
///         .await
///         .unwrap();
///     drop(server);
///     let mut out = String::new();
///     client.read_to_string(&mut out).await.unwrap();
///     match length {
///         Some(line) => assert!(out.contains(line), "{out}"),
///         None => assert!(!out.contains("Content-Length"), "{out}"),
///     }
/// }
/// # }
/// ```
pub async fn write_response<S: AsyncWrite + Unpin>(
    sock: &mut S,
    response: Response,
    config: &EdgeConfig,
) -> std::io::Result<()> {
    write_checked(sock, response, false, config).await
}

/// Write `response` as the answer to a request whose method was `method`: exactly as
/// [`write_response`] does, the same checks included, except that the answer to a `HEAD` is
/// the head alone. Its status and headers are GET's, `Content-Length` is the length of the
/// content GET would carry, and no content follows (RFC 9110 §9.3.2), the way the routed
/// adapter answers every `HEAD`, a refusal's included.
///
/// ```
/// use ikigai_web::{write_answer, EdgeConfig, Response};
/// use tokio::io::AsyncReadExt;
///
/// # #[tokio::main]
/// # async fn main() {
/// let (mut client, mut server) = tokio::io::duplex(4096);
/// let answer = Response::new(200, "application/json", br#"{"ok":true}"#.to_vec());
/// write_answer(&mut server, "HEAD", answer, &EdgeConfig::default()).await.unwrap();
/// drop(server);
/// let mut out = String::new();
/// client.read_to_string(&mut out).await.unwrap();
/// assert!(out.contains("\r\nContent-Length: 11\r\n"), "{out}");
/// assert!(out.ends_with("\r\n\r\n"), "the head alone: {out:?}");
/// # }
/// ```
pub async fn write_answer<S: AsyncWrite + Unpin>(
    sock: &mut S,
    method: &str,
    response: Response,
    config: &EdgeConfig,
) -> std::io::Result<()> {
    write_checked(sock, response, method == "HEAD", config).await
}

/// Check `response` ([`Response::check`]) and write it, the head alone when `head_only`.
async fn write_checked<S: AsyncWrite + Unpin>(
    sock: &mut S,
    response: Response,
    head_only: bool,
    config: &EdgeConfig,
) -> std::io::Result<()> {
    if let Err(refusal) = response.check() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            refusal,
        ));
    }
    let resp = Resp {
        content_type: response.content_type,
        body: response.body,
        headers: response.headers,
        ..Resp::status(response.status, reason_phrase(response.status))
    };
    let resp = if head_only { resp.into_head() } else { resp };
    write_within(sock, resp, config.write_timeout).await
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
        if let Some(coop) = &sec.coop {
            resp.headers
                .push(("Cross-Origin-Opener-Policy".to_string(), coop.clone()));
        }
    }

    // A policy that allows ANY origin makes every answer depend on `Origin` — the same URL
    // carries `Access-Control-Allow-Origin` for one caller and not for the next — so `Vary`
    // names it on every response, not only the ones that echo an origin. Naming it only there
    // let a cache store the answer to a same-origin request (no CORS headers) and hand it to
    // a cross-origin one, which the browser then blocks.
    if !cors.allowed_origins.is_empty() {
        resp.add_vary("Origin");
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
        // The EFFECTIVE policy's list (the route's, else the server's) — reading the
        // server-wide one here echoed any requested header past a route that names an
        // allow-list (ledger #733, finding W2).
        let headers = if cors.allowed_headers.is_empty() {
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
fn media_type_of<B>(repr: &ikigai_core::Representation<B>) -> String {
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
) -> Resp {
    let projectable = offered
        .iter()
        .any(|a| matches!(a.verb, Verb::Source | Verb::Sink | Verb::Delete));
    let Some(desc) = desc.filter(|_| projectable) else {
        return Resp::text(404, "Not Found", "no such resource to describe");
    };
    let body = serde_json::to_vec_pretty(&openapi_of(desc, offered, path)).unwrap_or_default();
    Resp {
        content_type: "application/vnd.oai.openapi+json; charset=utf-8".to_string(),
        body,
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
            let (props, required) = schema_properties(action);
            let schema = json!({ "type": "object", "properties": props, "required": required });
            // ★ An ENVELOPE action (ledger #358, #1547) declares its body: the fields ARE the
            // request body's properties and the carrier is the body itself, so it is no
            // property. A form submission is urlencoded as often as it is JSON, and the
            // contract says the fields are the carrier's either way.
            let content = match envelope_carrier(action) {
                Some(_) => json!({
                    "application/json": { "schema": schema },
                    "application/x-www-form-urlencoded": { "schema": schema },
                }),
                None => json!({ "application/json": { "schema": schema } }),
            };
            op.insert("requestBody".to_string(), json!({ "content": content }));
        } else {
            let params: Vec<Value> = action
                .inputs
                .iter()
                .filter(|a| projected(a))
                .map(|a| {
                    let mut param = json!({
                        "name": a.name,
                        "in": "query",
                        "required": a.required,
                        "description": a.summary,
                        "schema": arg_schema(a),
                    });
                    // A LIST argument (ledger #1547) may be repeated, `?graph=A&graph=B`,
                    // which the door joins: OpenAPI's form style, exploded.
                    if a.list.is_some() {
                        param["style"] = json!("form");
                        param["explode"] = json!(true);
                    }
                    param
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

/// Whether an input is something a client SENDS, and so belongs in the projection: not one the
/// adapter owns ([`ADAPTER_OWNED`]), and not one the resolving grammar BINDS from the IRI
/// (`InputSource::Binding`, ledger #1065). A description is asked of a concrete path, so a
/// template variable is already in it: listing it as a required query parameter (as this did)
/// described a call that sends the value twice, and a client generated from it would.
fn projected(input: &ikigai_core::ArgSpec) -> bool {
    !ADAPTER_OWNED.contains(&input.name.as_str())
        && input.source != ikigai_core::InputSource::Binding
}

/// The carrier of an ENVELOPE action (`Arguments::Envelope`, ledger #358): the input whose
/// body the other inputs are fields of.
fn envelope_carrier(action: &ikigai_core::ActionSpec) -> Option<&str> {
    match &action.arguments {
        ikigai_core::Arguments::Envelope(carrier) => Some(carrier.as_str()),
        _ => None,
    }
}

fn schema_properties(action: &ikigai_core::ActionSpec) -> (serde_json::Value, Vec<String>) {
    use serde_json::{Map, Value};
    let carrier = envelope_carrier(action);
    let mut props = Map::new();
    let mut required = Vec::new();
    for a in action
        .inputs
        .iter()
        .filter(|a| projected(a) && Some(a.name.as_str()) != carrier)
    {
        props.insert(a.name.clone(), arg_schema(a));
        if a.required {
            required.push(a.name.clone());
        }
    }
    (Value::Object(props), required)
}

/// One input's JSON-Schema: type from its `class` (XSD datatype), `enum` from `one_of`
/// (`[]` for an empty enumeration, which accepts nothing: ledger #41), `default`, and its
/// summary as the description. A LIST argument (ledger #1547) is an array of such items.
fn arg_schema(a: &ikigai_core::ArgSpec) -> serde_json::Value {
    use serde_json::{json, Map, Value};
    let ty = a.class.as_deref().map(xsd_to_json_type).unwrap_or("string");
    let mut item = Map::new();
    item.insert("type".to_string(), json!(ty));
    if a.is_enumerated() {
        item.insert("enum".to_string(), json!(a.one_of));
    }
    let mut s = match a.list {
        Some(_) => {
            let mut array = Map::new();
            array.insert("type".to_string(), json!("array"));
            array.insert("items".to_string(), Value::Object(item));
            array
        }
        None => item,
    };
    if !a.summary.is_empty() {
        s.insert("description".to_string(), json!(a.summary));
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
fn parse_head(head: &[u8]) -> Result<HttpRequest, String> {
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
    let (path, query) = parse_target(target)?;
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

/// Decoded query pairs, in the order the target carried them.
type Query = Vec<(String, String)>;

/// The request target (path and query, as the request line carried it) as
/// [`HttpRequest::path`] and [`HttpRequest::query`]: the path through [`decode_path`], the
/// query as form pairs. Shared by the hand-written reader and the hyper door, so both decode a
/// target the same way and refuse the same targets with `400`, in a sentence that names the
/// byte offset in the target where the problem is.
fn parse_target(target: &[u8]) -> Result<(String, Query), String> {
    let (raw_path, query_str, query_at) = match target.iter().position(|b| *b == b'?') {
        Some(q) => (&target[..q], &target[q + 1..], q + 1),
        None => (target, &b""[..], target.len()),
    };
    let path = decode_path(raw_path)?;
    let mut query = Vec::new();
    let mut at = query_at;
    for kv in query_str.split(|b| *b == b'&') {
        let start = at;
        at += kv.len() + 1;
        if kv.is_empty() {
            continue;
        }
        let (k, v) = match kv.iter().position(|b| *b == b'=') {
            Some(eq) => (&kv[..eq], &kv[eq + 1..]),
            None => (kv, &b""[..]),
        };
        query.push((
            decode_text(k, true, start, "query name")?,
            decode_text(v, true, start + k.len() + 1, "query value")?,
        ));
    }
    Ok((path, query))
}

/// Percent-decode one part of the request target with the ecosystem's one strict decoder
/// (`ikigai_fn::html::percent_decode_bytes`, ledger #1878), then validate UTF-8 once, over the
/// whole decoded value. Over BYTES, because the target may carry raw non-UTF-8 bytes; a `%`
/// must be followed by exactly two hex digits (`%`, `%4`, `%zz`, `%+1`, `%` before a non-ASCII
/// byte are refused, never passed through), since a server that guesses at a malformed escape
/// and a proxy in front of it that guesses differently disagree about what was asked for.
/// `plus_is_space` is form encoding, and only a query string is form-encoded. `at` is where
/// `raw` starts in the target, so the refusal names an offset in what the client sent.
fn decode_text(raw: &[u8], plus_is_space: bool, at: usize, what: &str) -> Result<String, String> {
    use ikigai_fn::html::{percent_decode_bytes, PercentDecodeError};
    let bytes = percent_decode_bytes(raw, plus_is_space).map_err(|e| match e {
        PercentDecodeError::MalformedEscape { offset } => format!(
            "malformed percent-escape at byte {} of the request target: a `%` must be followed \
             by two hex digits",
            at + offset
        ),
        // The byte form never checks UTF-8; that is done once, below, over the whole value.
        other => other.to_string(),
    })?;
    String::from_utf8(bytes).map_err(|_| {
        format!("the {what} at byte {at} of the request target is not UTF-8 once percent-decoded")
    })
}

/// The path, split on `/` FIRST and each segment decoded on its own (RFC 3986 §2.2: an
/// encoded delimiter is data). `+` stays `+`. The decoded segments are re-joined into the one
/// string [`HttpRequest::path`] carries, with a `/` or `%` inside a segment kept escaped so
/// [`path_segments`] can split it back without a client-encoded slash becoming a separator.
/// `raw` starts the request target, so an offset in a refusal is an offset in the target.
fn decode_path(raw: &[u8]) -> Result<String, String> {
    let mut out = String::with_capacity(raw.len());
    let mut at = 0;
    for (n, seg) in raw.split(|b| *b == b'/').enumerate() {
        if n > 0 {
            out.push('/');
        }
        for c in decode_text(seg, false, at, "path segment")?.chars() {
            match c {
                '%' => out.push_str("%25"),
                '/' => out.push_str("%2F"),
                c => out.push(c),
            }
        }
        at += seg.len() + 1;
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
async fn write_within<S: AsyncWrite + Unpin>(
    sock: &mut S,
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
async fn write<S: AsyncWrite + Unpin>(sock: &mut S, resp: Resp) -> std::io::Result<()> {
    let head = head_of(&resp, Some(resp.body.len() as u64));
    sock.write_all(head.as_bytes()).await?;
    if !resp.head_only {
        sock.write_all(&resp.body).await?;
    }
    sock.flush().await
}

/// The status line and headers of `resp`, through the blank line, as the hand-written writer
/// ([`write`], behind [`write_response`] and the refusals of [`read_request`]) sends them; the
/// hyper door frames the same [`header_fields`] itself.
///
/// A `204` or a `304` never carries `Content-Length`, whatever `content_length` says (ledger
/// #1597). Neither has content, and both end at the blank line (RFC 9112 §6.3, the first rule),
/// so the header frames nothing; RFC 9110 §8.6 forbids it on a `204` outright, and allows it on
/// a `304` only as the length a `200` would have carried. This writer omits it on a `304`
/// rather than send that length: it is optional, a `304` built from an `If-None-Match` hit has
/// no content to measure, and a wrong one (a `0`, as this used to send) misleads a cache that
/// updates its stored response from the `304`'s headers. A HEAD of either is the same head.
fn head_of(resp: &Resp, content_length: Option<u64>) -> String {
    let mut head = format!("HTTP/1.1 {} {}\r\n", resp.status, resp.reason);
    for (name, value) in header_fields(resp, content_length) {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    head
}

/// The header fields of `resp`, in the order they are written, `Content-Length` last and never
/// on a `204` or `304` (see [`head_of`]). No `Connection`: that is the connection's business, not
/// the answer's, and HTTP/2 and HTTP/3 forbid it. One list for both writers, the hand-written
/// [`head_of`] and the hyper door ([`door`]), so they cannot drift apart.
fn header_fields(resp: &Resp, content_length: Option<u64>) -> Vec<(&str, String)> {
    let content_length = content_length.filter(|_| !matches!(resp.status, 204 | 304));
    let mut fields = Vec::new();
    if !resp.content_type.is_empty() {
        fields.push(("Content-Type", resp.content_type.clone()));
    }
    if let Some(allow) = &resp.allow {
        fields.push(("Allow", allow.clone()));
    }
    if let Some(etag) = &resp.etag {
        fields.push(("ETag", etag.clone()));
    }
    if let Some(cc) = &resp.cache_control {
        fields.push(("Cache-Control", cc.clone()));
    }
    if !resp.vary.is_empty() {
        fields.push(("Vary", resp.vary.join(", ")));
    }
    for (name, value) in &resp.headers {
        fields.push((name.as_str(), value.clone()));
    }
    if let Some(length) = content_length {
        fields.push(("Content-Length", length.to_string()));
    }
    fields
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
        // The failure classes of core 0.1.108 (ledger #1546), one endpoint each, so the
        // status table is pinned over the socket and not only in `error_status`'s doctest.
        let limited = FnEndpoint::new("limited", |_inv: &Invocation<'_>| {
            Err(Error::RetryAfter {
                delay: Some(std::time::Duration::from_millis(1_500)),
                detail: "5 per minute".into(),
            })
        })
        .with_description(Description::new("limited").verb(Verb::Source));
        let budget = FnEndpoint::new("budget", |_inv: &Invocation<'_>| {
            Err(Error::OverBudget {
                detail: "the query ran past its 5000 ms budget".into(),
            })
        })
        .with_description(Description::new("budget").verb(Verb::Source));
        let refused = FnEndpoint::new("refused", |_inv: &Invocation<'_>| {
            Err(Error::Refused("api.example.com answered 401".into()))
        })
        .with_description(Description::new("refused").verb(Verb::Source));
        let slow = FnEndpoint::new("slow", |_inv: &Invocation<'_>| {
            Err(Error::Timeout("the origin did not answer in 30 s".into()))
        })
        .with_description(Description::new("slow").verb(Verb::Source));
        // Declares Sink and refuses it: the 405 comes from the ENDPOINT, not the method gate.
        let readonly = FnEndpoint::new("readonly", |inv: &Invocation<'_>| {
            if inv.request.verb == Verb::Source {
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"ro".to_vec(),
                ))
            } else {
                Err(Error::Unsupported {
                    verb: Some(Verb::Sink),
                    detail: "the log is append-only".into(),
                })
            }
        })
        .with_description(
            Description::new("readonly")
                .verb(Verb::Source)
                .verb(Verb::Sink),
        );
        let noclock = FnEndpoint::new("noclock", |_inv: &Invocation<'_>| {
            Err(Error::Unsupported {
                verb: None,
                detail: "the host configured no clock".into(),
            })
        })
        .with_description(Description::new("noclock").verb(Verb::Source));
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
        // A resource whose backing store is briefly unavailable (ledger #1883): it exists
        // ("v1"), but its FIRST Source answers the transient `Unavailable`, as a store
        // between connections would. A Sink replaces the state, so a write that slipped past
        // a precondition shows on the next read.
        let flaky_state = std::sync::Arc::new(std::sync::Mutex::new(b"v1".to_vec()));
        let flaky_down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let flaky = FnEndpoint::new("flaky", move |inv: &Invocation<'_>| {
            if inv.request.verb == Verb::Source {
                if flaky_down.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    return Err(Error::Unavailable("the store is reconnecting".into()));
                }
                let state = flaky_state.lock().unwrap().clone();
                Ok(Representation::new(ReprType::new("text/plain"), state))
            } else {
                let body = inv.inline_arg("content").unwrap_or_default().to_vec();
                *flaky_state.lock().unwrap() = body.clone();
                Ok(Representation::new(ReprType::new("text/plain"), body))
            }
        })
        .with_description(
            Description::new("flaky")
                .verb(Verb::Source)
                .verb(Verb::Sink),
        );
        // A form that answers with Post/Redirect/Get (ledger #1879): `Location` in an entity
        // envelope, by default to a query on its own path. Its `to` argument names the
        // Location, so a test can ask for one the door must refuse; it asks on a read too.
        let redirecting = FnEndpoint::new("redirecting", |inv: &Invocation<'_>| {
            // Built by hand rather than with `with_headers`, which refuses a bad `Location`
            // itself: these tests are about what the DOOR accepts, whoever wrote the envelope.
            let to = inv.inline_str("to").unwrap_or("?outcome=recorded");
            let mut bytes =
                format!("Content-Type: text/html\r\nLocation: {to}\r\n\r\n").into_bytes();
            bytes.extend_from_slice(b"<p>Recorded.</p>");
            Ok(Representation::new(
                ReprType::new(entity::HTTP_ENTITY),
                bytes,
            ))
        })
        .with_description(
            Description::new("redirecting")
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
        // A take: one path, many things behind it, chosen by a query argument. A Delete with
        // `tuple=<name>` removes that one and ANSWERS with it; an absent one is NotFound with
        // a message naming it; `tuple=bad` is refused as an invalid argument.
        let pending = std::sync::Arc::new(std::sync::Mutex::new(vec![
            "a".to_string(),
            "b".to_string(),
        ]));
        let tuples = FnEndpoint::new("tuples", move |inv: &Invocation<'_>| {
            let name = inv.inline_str("tuple").unwrap_or("").to_string();
            if name == "bad" {
                return Err(Error::InvalidArgument {
                    name: "tuple".into(),
                    detail: "not a tuple name".into(),
                });
            }
            let mut pending = pending.lock().unwrap();
            match pending.iter().position(|t| *t == name) {
                Some(i) => {
                    pending.remove(i);
                    Ok(Representation::new(
                        ReprType::new("text/plain"),
                        format!("took {name}").into_bytes(),
                    ))
                }
                None => Err(Error::NotFound(format!("no tuple {name} yet"))),
            }
        })
        .with_description(Description::new("tuples").verb(Verb::Delete));
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
        // A JSON doc whose Sink echoes the provenance it was handed beside the patched body,
        // so a PATCH test can see what its read-modify-write wrote with (ledger #520).
        let jprov = FnEndpoint::new("jprov", |inv: &Invocation<'_>| {
            if inv.request.verb == Verb::Source {
                return Ok(Representation::new(
                    ReprType::new("application/json"),
                    br#"{"a":1}"#.to_vec(),
                ));
            }
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!(
                    "received={} client={} principal={} content={}",
                    inv.inline_str("received").unwrap_or("-"),
                    inv.inline_str("client").unwrap_or("-"),
                    inv.inline_str("principal").unwrap_or("-"),
                    inv.inline_str("content").unwrap_or("-"),
                )
                .into_bytes(),
            ))
        })
        .with_description(
            Description::new("jprov")
                .verb(Verb::Source)
                .verb(Verb::Sink),
        );
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
                "received={} client={} principal={} cap={}",
                inv.inline_str("received").unwrap_or("-"),
                inv.inline_str("client").unwrap_or("-"),
                inv.inline_str("principal").unwrap_or("-"),
                inv.capability.principal().unwrap_or("-")
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
        // ledger #1547: a LIST argument (`graph`) beside a plain one (`query`), echoed; and an
        // ENVELOPE write whose form fields arrive inside `content`.
        let graphs = FnEndpoint::new("graphs", |inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!(
                    "graph={} query={}",
                    inv.inline_str("graph").unwrap_or("-"),
                    inv.inline_str("query").unwrap_or("-")
                )
                .into_bytes(),
            ))
        })
        .with_description(
            Description::new("graphs")
                .verb(Verb::Source)
                .input(
                    ArgSpec::new("graph")
                        .optional()
                        .list(ikigai_core::ListSeparator::CommaOrWhitespace),
                )
                .input(ArgSpec::new("query").optional()),
        );
        let form = FnEndpoint::new("form", |inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                inv.inline_arg("content").unwrap_or(b"").to_vec(),
            ))
        })
        .with_description(
            Description::new("form").action(
                ikigai_core::ActionSpec::new(Verb::Sink)
                    .summary("submit the form")
                    .input(ArgSpec::new("email").summary("where to answer"))
                    .input(ArgSpec::new("note").optional())
                    .input(ArgSpec::new("content"))
                    .envelope("content"),
            ),
        );
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:test:graphs"), graphs)
            .bind(Exact::new("urn:test:form"), form)
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
            .bind(Exact::new("urn:test:limited"), limited)
            .bind(Exact::new("urn:test:budget"), budget)
            .bind(Exact::new("urn:test:refused"), refused)
            .bind(Exact::new("urn:test:slow"), slow)
            .bind(Exact::new("urn:test:readonly"), readonly)
            .bind(Exact::new("urn:test:noclock"), noclock)
            .bind(Exact::new("urn:test:doc"), doc)
            .bind(Exact::new("urn:test:newdoc"), newdoc)
            .bind(Exact::new("urn:test:flaky"), flaky)
            .bind(Exact::new("urn:test:redirecting"), redirecting)
            .bind(Exact::new("urn:test:vanishing"), vanishing)
            .bind(Exact::new("urn:test:ghost"), ghost)
            .bind(Exact::new("urn:test:tuples"), tuples)
            .bind(Exact::new("urn:test:jdoc"), jdoc)
            .bind(Exact::new("urn:test:jprov"), jprov);
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

    // A door whose hook names every connection with an IRI core can carry as a principal.
    fn alice_door() -> EdgeConfig {
        let door: PrincipalFn =
            Arc::new(|_req: &HttpRequest| Some("urn:example:alice".to_string()));
        EdgeConfig {
            principal_fn: Some(door),
            ..EdgeConfig::default()
        }
    }

    /// ledger #1077: the door's principal is MINTED into the request capability on every
    /// verb, reads included, so an endpoint can ask who it serves; the stamped argument stays
    /// on writes only, as before.
    #[tokio::test]
    async fn the_doors_principal_is_minted_into_the_capability_on_reads_and_writes() {
        let addr = start_with(alice_door()).await;
        let read = roundtrip(addr, "GET /test/provenance HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(
            read.contains("principal=- cap=urn:example:alice"),
            "a read is attributed through its capability, not an argument: {read}"
        );
        let write = roundtrip(
            addr,
            "POST /test/provenance HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi",
        )
        .await;
        assert!(
            write.contains("principal=urn:example:alice cap=urn:example:alice"),
            "a write carries both: {write}"
        );
        // A name core cannot carry (`p` is no IRI) is stamped as before and minted nowhere.
        let addr = start_with(naming_door()).await;
        let named = roundtrip(
            addr,
            "POST /test/provenance HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi",
        )
        .await;
        assert!(named.contains("principal=p cap=-"), "{named}");
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

    /// ledger #879 (3), R6's library half: a READ cannot name a principal either. The
    /// reservation was keyed on mutating verbs only, so `GET …?principal=forged` reached the
    /// endpoint as `principal=forged`, and a host reading its stamped principal off any
    /// request (gonk's access log, its author rule) had to know to ignore reads.
    #[tokio::test]
    async fn a_principal_in_a_read_query_string_is_dropped_too() {
        for config in [naming_door(), EdgeConfig::default()] {
            let addr = start_with(config).await;
            let out = roundtrip(
                addr,
                "GET /test/provenance?principal=forged HTTP/1.1\r\nHost: x\r\n\r\n",
            )
            .await;
            assert!(
                out.contains("principal=-") && !out.contains("forged"),
                "a read carries no principal, and never the submitter's: {out}"
            );
        }
    }

    /// A door that refuses every request whose `Host` is not `localhost`, with `status`.
    fn admitting(status: u16) -> EdgeConfig {
        let admit: AdmitFn = Arc::new(move |req: &HttpRequest| {
            (req.header("host") != Some("localhost")).then(|| Refusal {
                status,
                reason: "refused at the door".to_string(),
            })
        });
        EdgeConfig {
            admit_fn: Some(admit),
            push: Some(crate::push::PushConfig::default()),
            ..EdgeConfig::default()
        }
    }

    /// ledger #879 (1): admission runs before EVERY answer the door gives, including the
    /// three that never reach the kernel (OPTIONS, `?description`, the push stream), so a
    /// host overlay in the kernel could not refuse them.
    #[tokio::test]
    async fn admission_refuses_before_options_description_push_and_dispatch() {
        let addr = start_with(admitting(403)).await;
        let push = crate::push::PushConfig::default().path;
        for raw in [
            "GET /test/id/hello HTTP/1.1\r\nHost: evil\r\n\r\n".to_string(),
            "OPTIONS /test/writable HTTP/1.1\r\nHost: evil\r\n\r\n".to_string(),
            "GET /test/booking?description HTTP/1.1\r\nHost: evil\r\n\r\n".to_string(),
            "POST /test/provenance HTTP/1.1\r\nHost: evil\r\nContent-Length: 2\r\n\r\nhi"
                .to_string(),
            format!("GET {push} HTTP/1.1\r\nHost: evil\r\n\r\n"),
        ] {
            let out = roundtrip(addr, &raw).await;
            assert!(
                out.starts_with("HTTP/1.1 403 Forbidden") && out.ends_with("refused at the door"),
                "{raw:?} answered before admission: {out}"
            );
            assert!(
                !out.contains("Allow:") && !out.contains("openapi") && !out.contains("received="),
                "a refusal discloses nothing behind the door: {out}"
            );
        }
        // An admitted request is served exactly as before.
        let out = roundtrip(
            addr,
            "GET /test/id/hello HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert!(
            out.starts_with("HTTP/1.1 200") && out.ends_with("hi"),
            "{out}"
        );
        let out = roundtrip(
            addr,
            "OPTIONS /test/writable HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert!(out.contains("Allow: POST, PUT, PATCH, OPTIONS"), "{out}");
    }

    /// A refusal's status comes from a closed list; anything else is a 403, so a typo in a
    /// host's hook can never turn a refusal into a success.
    #[tokio::test]
    async fn a_refusal_status_outside_the_list_is_answered_403() {
        for (asked, line) in [
            (421, "HTTP/1.1 421 Misdirected Request"),
            (429, "HTTP/1.1 429 Too Many Requests"),
            (200, "HTTP/1.1 403 Forbidden"),
            (302, "HTTP/1.1 403 Forbidden"),
        ] {
            let addr = start_with(admitting(asked)).await;
            let out = roundtrip(addr, "GET /test/id/hello HTTP/1.1\r\nHost: evil\r\n\r\n").await;
            assert!(out.starts_with(line), "{asked} -> {out}");
        }
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

    /// A door whose only resource, `urn:test:counted`, is a Sink that counts its invocations,
    /// served under per-source limits of two requests an hour.
    async fn counted_door(
        trust_proxy: bool,
        error_body: ErrorBody,
    ) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = Arc::clone(&runs);
        let counted = FnEndpoint::new("counted", move |_inv: &Invocation<'_>| {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"ok".to_vec(),
            ))
        })
        .with_description(Description::new("counted").verb(Verb::Sink));
        let kernel = Arc::new(Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:counted"), counted),
        )));
        let config = EdgeConfig {
            trust_proxy,
            error_body,
            source_limits: Some(SourceLimits::new(vec![SourceRate::new(
                "urn:test:counted",
                2,
                std::time::Duration::from_secs(3600),
            )])),
            ..EdgeConfig::default()
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_with_listener(kernel, public_cap(), listener, config).await;
        });
        (addr, runs)
    }

    fn post_counted(forwarded_for: &str, accept: &str) -> String {
        format!(
            "POST /test/counted HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: {forwarded_for}\r\n\
             Accept: {accept}\r\nContent-Length: 2\r\n\r\nhi"
        )
    }

    /// The `Retry-After` value of a raw response, in seconds.
    fn retry_after(resp: &str) -> u64 {
        resp.lines()
            .find_map(|l| l.strip_prefix("Retry-After: "))
            .unwrap_or_else(|| panic!("a Retry-After header: {resp}"))
            .trim()
            .parse()
            .unwrap()
    }

    /// Ledger #1717: one client past its budget is answered 429 with Retry-After and the
    /// resource does not run; the client is the hop OUR proxy appended, so a forged leftmost
    /// `X-Forwarded-For` buys no fresh budget; another client keeps its own; a browser gets the
    /// refusal as a page; and `OPTIONS` is never counted.
    #[tokio::test]
    async fn a_source_past_its_budget_is_429_with_retry_after_and_the_resource_does_not_run() {
        let (addr, runs) = counted_door(true, ErrorBody::Text).await;
        let runs_now = || runs.load(std::sync::atomic::Ordering::SeqCst);
        for n in 0..2 {
            let ok = roundtrip(addr, &post_counted("203.0.113.9", "*/*")).await;
            assert!(
                ok.starts_with("HTTP/1.1 200 "),
                "request {n} is in budget: {ok}"
            );
        }
        assert_eq!(runs_now(), 2);
        let refused = roundtrip(addr, &post_counted("203.0.113.9", "*/*")).await;
        assert!(
            refused.starts_with("HTTP/1.1 429 Too Many Requests\r\n"),
            "{refused}"
        );
        let wait = retry_after(&refused);
        assert!((3590..=3600).contains(&wait), "about an hour: {refused}");
        assert!(
            refused.contains("rate-limited: `urn:test:counted`"),
            "{refused}"
        );
        assert_eq!(
            runs_now(),
            2,
            "the refused request never reached the resource"
        );

        // A forged leftmost hop is not the client: the proxy's appended hop still counts.
        let forged = roundtrip(addr, &post_counted("6.6.6.6, 203.0.113.9", "*/*")).await;
        assert!(forged.starts_with("HTTP/1.1 429 "), "{forged}");
        // A browser is told the same thing as a page.
        let page = roundtrip(
            addr,
            &post_counted("203.0.113.9", "text/html,application/xhtml+xml"),
        )
        .await;
        assert!(page.starts_with("HTTP/1.1 429 "), "{page}");
        assert!(page.contains("Retry-After: "), "{page}");
        assert!(page.contains("<h1>429 Too Many Requests</h1>"), "{page}");
        // Another client has its own budget.
        let other = roundtrip(addr, &post_counted("198.51.100.7", "*/*")).await;
        assert!(other.starts_with("HTTP/1.1 200 "), "{other}");
        assert_eq!(runs_now(), 3);
        // OPTIONS answers without being counted or refused.
        let options = roundtrip(
            addr,
            "OPTIONS /test/counted HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n",
        )
        .await;
        assert!(options.starts_with("HTTP/1.1 204 "), "{options}");
    }

    /// Without `trust_proxy` the source is the socket peer, so a client cannot buy a fresh
    /// budget by writing a different `X-Forwarded-For` on each request.
    #[tokio::test]
    async fn an_untrusted_forwarded_for_buys_no_fresh_budget() {
        let (addr, runs) = counted_door(false, ErrorBody::Text).await;
        for hop in ["1.1.1.1", "2.2.2.2"] {
            let ok = roundtrip(addr, &post_counted(hop, "*/*")).await;
            assert!(ok.starts_with("HTTP/1.1 200 "), "{ok}");
        }
        let refused = roundtrip(addr, &post_counted("3.3.3.3", "*/*")).await;
        assert!(refused.starts_with("HTTP/1.1 429 "), "{refused}");
        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// Under `ErrorBody::Json` the refusal is typed: `kind` is `rate-limited` and
    /// `retry_after` repeats the header.
    #[tokio::test]
    async fn a_json_door_types_the_rate_limit_refusal() {
        let (addr, _) = counted_door(true, ErrorBody::Json).await;
        for _ in 0..2 {
            roundtrip(addr, &post_counted("203.0.113.9", "*/*")).await;
        }
        let refused = roundtrip(addr, &post_counted("203.0.113.9", "*/*")).await;
        assert!(refused.starts_with("HTTP/1.1 429 "), "{refused}");
        let (_, body) = refused.split_once("\r\n\r\n").unwrap();
        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(json["kind"], "rate-limited", "{body}");
        assert_eq!(json["retry_after"].as_u64(), Some(retry_after(&refused)));
        assert!(json["message"]
            .as_str()
            .unwrap()
            .starts_with("rate-limited: "));
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

    /// HEAD carries the head GET would, and no content: `Content-Length` is the length of
    /// the representation GET sends (2, for `hi`), not 0 (ledger #118; RFC 9110 §9.3.2).
    #[tokio::test]
    async fn head_returns_headers_no_body() {
        let addr = start().await;
        let resp = roundtrip(addr, "HEAD /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(
            resp.contains("Content-Length: 2\r\n"),
            "HEAD names the length GET sends, got: {resp}"
        );
        let (_, body) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
        assert!(body.is_empty(), "HEAD has no content, got: {resp}");
    }

    /// The same holds when the answer is a refusal: a HEAD of a name nothing binds is GET's
    /// 404 head, its length included, with no content behind it.
    #[tokio::test]
    async fn head_of_a_refusal_has_get_s_length_and_no_content() {
        let addr = start().await;
        let get = roundtrip(addr, "GET /test/nowhere HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let head = roundtrip(addr, "HEAD /test/nowhere HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let (get_head, get_body) = get.split_once("\r\n\r\n").unwrap();
        let (head_head, head_body) = head.split_once("\r\n\r\n").unwrap();
        assert!(
            !get_body.is_empty(),
            "GET of a missing name explains: {get}"
        );
        assert_eq!(get_head, head_head, "HEAD carries GET's head exactly");
        assert!(head_body.is_empty(), "HEAD has no content, got: {head}");
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

    /// ledger #387: `?name=priya&name=ada` reached the resource as `name=ada` (last-wins) and
    /// answered 200; `?as=` kept the first. A repeated argument is now a 400 naming it, typed.
    #[tokio::test]
    async fn a_repeated_query_argument_is_refused_by_name() {
        let addr = start().await;
        for (query, name) in [("name=priya&name=ada", "name"), ("as=a&name=x&as=b", "as")] {
            let resp = roundtrip(
                addr,
                &format!("GET /test/echo?{query} HTTP/1.1\r\nHost: x\r\n\r\n"),
            )
            .await;
            assert!(resp.starts_with("HTTP/1.1 400 "), "{query}: {resp}");
            assert!(
                resp.ends_with(&format!(
                    "invalid argument `{name}`: given twice; an argument takes one value, so \
                     name it once"
                )),
                "{query}: {resp}"
            );
        }
        // The typed body, when the door answers errors as JSON.
        let addr = start_with(EdgeConfig {
            error_body: ErrorBody::Json,
            ..EdgeConfig::default()
        })
        .await;
        let resp = roundtrip(
            addr,
            "GET /test/echo?name=priya&name=ada HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 400 "), "{resp}");
        assert!(
            resp.contains(r#""kind":"invalid-argument""#) && resp.contains(r#""name":"name""#),
            "{resp}"
        );
        // Two different names, and a repeat of a name the door drops, are not refused.
        let addr = start().await;
        let resp = roundtrip(
            addr,
            "GET /test/echo?name=priya&other=1&principal=a&principal=b HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.ends_with("priya"), "{resp}");
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
        // A header name is case-insensitive, and hyper writes this one `Etag` (ledger #2236).
        resp.lines()
            .find_map(|l| {
                l.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("etag"))
                    .map(|(_, value)| value)
            })
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
        assert!(!again.contains("Content-Length"), "got: {again}");
        assert!(!again.ends_with("hi"), "304 has no body, got: {again}");
    }

    /// Ledger #1597: a `204` and a `304` carry no `Content-Length` (RFC 9110 §8.6: never on a
    /// `204`; on a `304` only the length a `200` would carry, and this writer omits it). The
    /// adapter used to write `Content-Length: 0` on both. Every answer here is read as raw
    /// bytes off the socket, and each is the head alone.
    #[tokio::test]
    async fn a_204_and_a_304_carry_no_content_length() {
        let addr = start().await;
        let get = roundtrip(addr, "GET /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let etag = etag_of_response(&get);
        let conditional = |method: &str| {
            format!("{method} /test/id/hello HTTP/1.1\r\nHost: x\r\nIf-None-Match: {etag}\r\n\r\n")
        };
        let answers = [
            (
                "DELETE",
                "204",
                roundtrip(addr, "DELETE /test/deletable HTTP/1.1\r\nHost: x\r\n\r\n").await,
            ),
            (
                "OPTIONS",
                "204",
                roundtrip(addr, "OPTIONS /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await,
            ),
            ("GET", "304", roundtrip(addr, &conditional("GET")).await),
            ("HEAD", "304", roundtrip(addr, &conditional("HEAD")).await),
        ];
        for (method, status, resp) in answers {
            assert!(
                resp.starts_with(&format!("HTTP/1.1 {status} ")),
                "{method}: {resp}"
            );
            assert!(
                !resp.to_ascii_lowercase().contains("content-length"),
                "{method} {status}: {resp}"
            );
            assert!(
                resp.ends_with("\r\n\r\n"),
                "{method}: the head alone: {resp:?}"
            );
        }
        // The other answers keep their length: a 200, and its HEAD (ledger #118).
        assert!(get.contains("Content-Length: 2\r\n"), "{get}");
        let head = roundtrip(addr, "HEAD /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(head.contains("Content-Length: 2\r\n"), "{head}");
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

    /// `If-Match` uses the STRONG comparison (RFC 9110 §13.1.1): a weak validator never
    /// satisfies it, because a weak tag does not promise the bytes the lost-update guard is
    /// protecting (ledger #733, finding W5). `If-None-Match` stays weak (§13.1.2).
    #[tokio::test]
    async fn if_match_refuses_a_weak_validator() {
        let addr = start().await;
        let etag =
            etag_of_response(&roundtrip(addr, "GET /test/doc HTTP/1.1\r\nHost: x\r\n\r\n").await);
        let resp = roundtrip(
            addr,
            &format!(
                "PUT /test/doc HTTP/1.1\r\nHost: x\r\nIf-Match: W/{etag}\r\nContent-Length: 2\r\n\r\nv2"
            ),
        )
        .await;
        assert!(
            resp.starts_with("HTTP/1.1 412 Precondition Failed"),
            "got: {resp}"
        );
        let resp = roundtrip(
            addr,
            &format!(
                "PUT /test/doc HTTP/1.1\r\nHost: x\r\nIf-None-Match: W/{etag}\r\nContent-Length: 2\r\n\r\nv2"
            ),
        )
        .await;
        assert!(
            resp.starts_with("HTTP/1.1 412 Precondition Failed"),
            "If-None-Match compares weakly, so a weak tag still matches: {resp}"
        );
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

    /// Ledger #1546: the failure classes' statuses, over the socket, as the shared vectors
    /// decide them: RetryAfter 429 with `Retry-After` in seconds rounded up, OverBudget 422,
    /// Refused 502, Timeout 504 (was 503), Unsupported 405 with `Allow` when it names a verb
    /// and 501 when it names a facility.
    #[tokio::test]
    async fn the_failure_classes_answer_the_decided_statuses() {
        let addr = start().await;
        let get = |path: &str| format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n");
        let limited = roundtrip(addr, &get("/test/limited")).await;
        assert!(
            limited.starts_with("HTTP/1.1 429 Too Many Requests\r\n"),
            "{limited}"
        );
        assert!(limited.contains("\r\nRetry-After: 2\r\n"), "{limited}");
        assert!(
            limited.ends_with("retry after 1500 ms: 5 per minute"),
            "{limited}"
        );
        let budget = roundtrip(addr, &get("/test/budget")).await;
        assert!(
            budget.starts_with("HTTP/1.1 422 Unprocessable Content\r\n"),
            "{budget}"
        );
        let refused = roundtrip(addr, &get("/test/refused")).await;
        assert!(
            refused.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "{refused}"
        );
        let slow = roundtrip(addr, &get("/test/slow")).await;
        assert!(
            slow.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"),
            "{slow}"
        );
        assert!(!slow.contains("Retry-After"), "{slow}");
        let readonly = roundtrip(
            addr,
            "PUT /test/readonly HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi",
        )
        .await;
        assert!(
            readonly.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
            "{readonly}"
        );
        assert!(
            readonly.contains("\r\nAllow: GET, HEAD, POST, PUT, PATCH, OPTIONS\r\n"),
            "the declared methods, from the resource: {readonly}"
        );
        assert!(
            readonly.ends_with("unsupported: the log is append-only"),
            "{readonly}"
        );
        let noclock = roundtrip(addr, &get("/test/noclock")).await;
        assert!(
            noclock.starts_with("HTTP/1.1 501 Not Implemented\r\n"),
            "{noclock}"
        );
        assert!(!noclock.contains("\r\nAllow:"), "{noclock}");
    }

    /// The JSON face of the same: `class` on every body, `retry_after` beside the header.
    #[tokio::test]
    async fn the_json_error_body_carries_the_class_and_the_retry_after() {
        let addr = start_with(EdgeConfig {
            error_body: ErrorBody::Json,
            ..EdgeConfig::default()
        })
        .await;
        let resp = roundtrip(addr, "GET /test/limited HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 429 "), "{resp}");
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or_default();
        let json: serde_json::Value = serde_json::from_str(body).expect("a JSON body");
        assert_eq!(json["kind"], "retry-after", "{body}");
        assert_eq!(json["class"], "retry-after", "{body}");
        assert_eq!(json["retry_after"], 2, "{body}");
        let resp = roundtrip(addr, "GET /test/missing HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or_default();
        let json: serde_json::Value = serde_json::from_str(body).expect("a JSON body");
        assert_eq!(json["class"], "permanent", "{body}");
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

    /// ★ Ledger #1883. A create-only write (`If-None-Match: *`) whose read of the current
    /// state fails TRANSIENTLY must not go ahead: the resource may well exist, and the read
    /// only failed to say so. It answers the failure's own status (503 for `Unavailable`) and
    /// writes nothing. It used to count any failed read as "absent", so the write ran over
    /// the existing state.
    #[tokio::test]
    async fn if_none_match_star_under_a_transient_read_failure_refuses_and_writes_nothing() {
        let addr = start().await;
        let resp = roundtrip(
            addr,
            "PUT /test/flaky HTTP/1.1\r\nHost: x\r\nIf-None-Match: *\r\nContent-Length: 2\r\n\r\nv2",
        )
        .await;
        assert!(
            resp.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
            "got: {resp}"
        );
        let after = roundtrip(addr, "GET /test/flaky HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(
            after.ends_with("\r\n\r\nv1"),
            "nothing was written: {after}"
        );
    }

    /// …and `If-Match` the same way (ledger #1883): a transient read failure is not "the
    /// resource is absent, so the precondition failed" (a 412 telling the caller its state is
    /// stale when nothing was compared). It answers 503 and writes nothing.
    #[tokio::test]
    async fn if_match_under_a_transient_read_failure_answers_the_failure_and_writes_nothing() {
        let addr = start().await;
        let resp = roundtrip(
            addr,
            "PUT /test/flaky HTTP/1.1\r\nHost: x\r\nIf-Match: *\r\nContent-Length: 2\r\n\r\nv2",
        )
        .await;
        assert!(
            resp.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
            "got: {resp}"
        );
        let after = roundtrip(addr, "GET /test/flaky HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(
            after.ends_with("\r\n\r\nv1"),
            "nothing was written: {after}"
        );
    }

    /// ★ Ledger #1879, Post/Redirect/Get: a write whose answer carries `Location` is `303 See
    /// Other` to it, with the endpoint's page as the body, so a browser that restores the page
    /// later restores a GET and never offers to post again.
    #[tokio::test]
    async fn a_writes_location_answers_303_see_other() {
        let addr = start().await;
        for location in ["?outcome=recorded", "/done/page?x=1"] {
            let resp = roundtrip(
                addr,
                &format!(
                    "POST /test/redirecting?to={} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
                    url_query(location)
                ),
            )
            .await;
            assert!(resp.starts_with("HTTP/1.1 303 See Other\r\n"), "{resp}");
            assert!(
                resp.contains(&format!("\r\nLocation: {location}\r\n")),
                "{resp}"
            );
            assert!(resp.ends_with("<p>Recorded.</p>"), "{resp}");
        }
    }

    /// …and only to the same origin, and only from a write: a `Location` with a host, a
    /// scheme, a backslash or a bare relative path is refused with `500` naming it, and so is
    /// one on a read's answer. Nothing of the refused answer is served.
    #[tokio::test]
    async fn a_location_off_the_origin_or_on_a_read_is_refused() {
        let addr = start().await;
        for location in [
            "//evil.example/x",
            "https://evil.example/",
            "/\\evil.example",
            "done",
        ] {
            let resp = roundtrip(
                addr,
                &format!(
                    "POST /test/redirecting?to={} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
                    url_query(location)
                ),
            )
            .await;
            assert!(resp.starts_with("HTTP/1.1 500 "), "{location}: {resp}");
            assert!(!resp.contains("\r\nLocation:"), "{location}: {resp}");
            assert!(resp.contains("`Location`"), "{location}: {resp}");
        }
        let resp = roundtrip(addr, "GET /test/redirecting HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 500 "), "{resp}");
        assert!(
            resp.contains("only a write's answer may redirect"),
            "{resp}"
        );
    }

    /// Percent-encode a query value for these tests.
    fn url_query(value: &str) -> String {
        ikigai_fn::html::url_segment(value)
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

    // A DELETE request for `path` (query included).
    fn delete(path: &str) -> String {
        format!("DELETE {path} HTTP/1.1\r\nHost: x\r\n\r\n")
    }

    #[tokio::test]
    async fn a_delete_that_answers_with_a_representation_is_200_with_it() {
        let addr = start().await;
        let resp = roundtrip(addr, &delete("/test/tuples?tuple=a")).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.contains("Content-Type: text/plain"), "got: {resp}");
        assert!(
            resp.ends_with("\r\n\r\ntook a"),
            "the taken thing is the body: {resp}"
        );
        // An empty answer is still 204, as before.
        let resp = roundtrip(addr, &delete("/test/vanishing")).await;
        assert!(resp.starts_with("HTTP/1.1 204"), "got: {resp}");
    }

    #[tokio::test]
    async fn a_tombstone_covers_the_whole_request_not_just_the_path() {
        let addr = start().await;
        let took = roundtrip(addr, &delete("/test/tuples?tuple=a")).await;
        assert!(took.starts_with("HTTP/1.1 200"), "took: {took}");
        // The same path with a different query: a NotFound there is a 404, not the 204 the
        // first request's tombstone would answer if it keyed on the path alone.
        let other = roundtrip(addr, &delete("/test/tuples?tuple=z")).await;
        assert!(other.starts_with("HTTP/1.1 404"), "other: {other}");
        // The repeat of the request that succeeded is still idempotent.
        let again = roundtrip(addr, &delete("/test/tuples?tuple=a")).await;
        assert!(again.starts_with("HTTP/1.1 204"), "again: {again}");
    }

    #[tokio::test]
    async fn a_delete_not_found_keeps_the_endpoints_message() {
        let addr = start().await;
        let resp = roundtrip(addr, &delete("/test/tuples?tuple=z")).await;
        assert!(resp.starts_with("HTTP/1.1 404 Not Found"), "got: {resp}");
        assert!(
            resp.ends_with("\r\n\r\nnot found: no tuple z yet"),
            "got: {resp}"
        );
    }

    #[tokio::test]
    async fn an_error_body_is_text_by_default() {
        let addr = start().await;
        let resp = roundtrip(addr, &delete("/test/tuples?tuple=bad")).await;
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"), "got: {resp}");
        assert!(resp.contains("Content-Type: text/plain"), "got: {resp}");
        assert!(
            resp.ends_with("\r\n\r\ninvalid argument `tuple`: not a tuple name"),
            "got: {resp}"
        );
    }

    fn json_errors() -> EdgeConfig {
        EdgeConfig {
            error_body: ErrorBody::Json,
            ..EdgeConfig::default()
        }
    }

    // The body of a raw response, parsed as JSON.
    fn json_body(resp: &str) -> serde_json::Value {
        let body = resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        serde_json::from_str(body).unwrap_or_else(|e| panic!("not JSON ({e}): {resp}"))
    }

    #[tokio::test]
    async fn a_door_can_answer_errors_as_typed_json() {
        let addr = start_with(json_errors()).await;
        // The variant's own fields ride along with its kind and message.
        let resp = roundtrip(addr, &delete("/test/tuples?tuple=bad")).await;
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"), "got: {resp}");
        assert!(
            resp.contains("Content-Type: application/json\r\n"),
            "got: {resp}"
        );
        assert_eq!(
            json_body(&resp),
            serde_json::json!({
                "kind": "invalid-argument",
                "class": "permanent",
                "message": "invalid argument `tuple`: not a tuple name",
                "name": "tuple",
                "detail": "not a tuple name",
            })
        );
        // A DELETE's NotFound, with the endpoint's message.
        let resp = roundtrip(addr, &delete("/test/tuples?tuple=z")).await;
        assert!(resp.starts_with("HTTP/1.1 404 Not Found"), "got: {resp}");
        assert_eq!(
            json_body(&resp),
            serde_json::json!({"kind": "not-found", "class": "permanent", "message": "not found: no tuple z yet"})
        );
        // A path no endpoint is bound to names the target it could not resolve.
        let resp = get(addr, "/test/nothing-here", None).await;
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {resp}");
        let body = json_body(&resp);
        assert_eq!(body["kind"], "unresolved", "{resp}");
        assert_eq!(body["target"], "urn:test:nothing-here", "{resp}");
        // A successful answer is untouched by the option.
        let resp = roundtrip(addr, &delete("/test/tuples?tuple=a")).await;
        assert!(resp.ends_with("\r\n\r\ntook a"), "got: {resp}");
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
            resp.to_ascii_lowercase().contains("\r\netag: "),
            "PATCH should return a fresh ETag, got: {resp}"
        );
    }

    /// ledger #520: PATCH is a mutating verb, so its Sink carries the provenance a PUT/POST
    /// carries — `received`, `client`, and the door's `principal` — not an anonymous write.
    #[tokio::test]
    async fn a_patch_is_stamped_like_any_other_write() {
        let addr = start_with(naming_door()).await;
        let resp = roundtrip(addr, &merge_patch("/test/jprov", r#"{"b":2}"#)).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(
            resp.contains("received=20")
                && resp.contains("client=127.0.0.1")
                && resp.contains("principal=p"),
            "a patched resource must be written with its provenance: {resp}"
        );
        // The merged document is still what is written, not the patch body.
        assert!(resp.ends_with(r#"content={"a":1,"b":2}"#), "got: {resp}");
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

    /// Ledger #1905: a machine finding read the early return on a request with no `Origin`
    /// (`apply_edge_policy`) as a gap. It is the rule. CORS headers answer a browser's
    /// cross-origin READ, and a browser names the origin on every such request; a request
    /// with no `Origin` is same-origin or not from a browser, so there is nothing to allow,
    /// and the answer is otherwise the same one. A cross-site WRITE is the other layer's
    /// question ([`OriginCheck`], an admission rule, which runs before any of this and
    /// refuses a credentialed write that carries no `Origin`): the CORS layer never gates
    /// whether a request is served, only what a browser may read of the answer.
    #[tokio::test]
    async fn a_request_with_no_origin_is_the_same_answer_without_cors_headers() {
        let addr = start_with(EdgeConfig {
            cors: CorsPolicy {
                allowed_origins: vec!["https://app.example".to_string()],
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
        let plain = roundtrip(addr, "GET /test/id/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let cross = roundtrip(
            addr,
            "GET /test/id/hello HTTP/1.1\r\nHost: x\r\nOrigin: https://app.example\r\n\r\n",
        )
        .await;
        // Served, and no CORS header of any kind without an Origin.
        assert!(plain.starts_with("HTTP/1.1 200"), "{plain}");
        assert!(!plain.contains("Access-Control-"), "{plain}");
        // The cross-origin answer is the SAME answer plus exactly the allow-origin header.
        assert!(
            cross.contains("Access-Control-Allow-Origin: https://app.example"),
            "{cross}"
        );
        let without_cors: Vec<&str> = cross
            .lines()
            .filter(|l| !l.starts_with("Access-Control-"))
            .collect();
        assert_eq!(without_cors, plain.lines().collect::<Vec<_>>(), "{cross}");

        // The write question belongs to admission: an HTML door refuses a cookie-carrying
        // POST with no Origin before routing, CORS policy or not.
        let door = start_with(EdgeConfig {
            cors: CorsPolicy {
                allowed_origins: vec!["https://app.example".to_string()],
                ..Default::default()
            },
            ..EdgeConfig::html_door(["https://x"]).unwrap()
        })
        .await;
        let forged = roundtrip(
            door,
            "POST /test/writable HTTP/1.1\r\nHost: x\r\nCookie: s=1\r\nContent-Length: 2\r\n\r\nhi",
        )
        .await;
        assert!(forged.starts_with("HTTP/1.1 403"), "{forged}");
        let anonymous = roundtrip(
            door,
            "POST /test/writable HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi",
        )
        .await;
        assert!(anonymous.starts_with("HTTP/1.1 200"), "{anonymous}");
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

    /// A route's CORS header allow-list governs its preflight; the server-wide default (empty,
    /// which echoes) must not override it.
    #[tokio::test]
    async fn a_routes_cors_header_allow_list_governs_its_preflight() {
        let route = Route {
            pattern: "/doc".to_string(),
            iri_template: "urn:test:doc".to_string(),
            redirect: None,
            cap: None,
            cors: Some(CorsPolicy {
                allowed_origins: vec!["https://a.example".to_string()],
                allowed_headers: vec!["x-ok".to_string()],
                ..Default::default()
            }),
            csp: None,
        };
        let addr = start_with(EdgeConfig {
            routes: RouteTable::new(vec![route]),
            ..Default::default()
        })
        .await;
        let resp = roundtrip(
            addr,
            "OPTIONS /doc HTTP/1.1\r\nHost: x\r\nOrigin: https://a.example\r\nAccess-Control-Request-Method: GET\r\nAccess-Control-Request-Headers: x-evil\r\n\r\n",
        )
        .await;
        assert!(
            resp.contains("Access-Control-Allow-Origin: https://a.example"),
            "got: {resp}"
        );
        assert!(
            resp.contains("Access-Control-Allow-Headers: x-ok"),
            "the route's list is advertised, got: {resp}"
        );
        assert!(
            !resp.contains("x-evil"),
            "a header outside the route's list is not echoed, got: {resp}"
        );
    }

    // A route with no per-route overrides.
    fn plain_route(pattern: &str, iri_template: &str) -> Route {
        Route {
            pattern: pattern.to_string(),
            iri_template: iri_template.to_string(),
            redirect: None,
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

    /// W1 (ledger #740): a route variable used to be substituted into its IRI template RAW,
    /// so one path segment carrying `:` addressed a DIFFERENT resource than the route names —
    /// under `routes_only`, the exhaustive allow-list, an un-routed one. `/u/{name}` →
    /// `urn:test:{name}` routes `urn:test:<one name>`; `/u/id:hello` must not reach
    /// `urn:test:id:hello`, which no route serves.
    #[tokio::test]
    async fn a_strict_variable_cannot_escape_its_route_under_routes_only() {
        let addr = start_with(EdgeConfig {
            routes: RouteTable::new(vec![plain_route("/u/{name}", "urn:test:{name}")]),
            routes_only: true,
            ..Default::default()
        })
        .await;
        let ok = roundtrip(addr, "GET /u/echo HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(ok.starts_with("HTTP/1.1 200 OK"), "got: {ok}");
        for escape in ["/u/id:hello", "/u/id%3Ahello", "/u/id%3ahello"] {
            let resp = roundtrip(addr, &format!("GET {escape} HTTP/1.1\r\nHost: x\r\n\r\n")).await;
            assert!(
                resp.starts_with("HTTP/1.1 400 Bad Request"),
                "{escape} must be refused, got: {resp}"
            );
            assert!(
                !resp.ends_with("hi"),
                "{escape} reached urn:test:id:hello: {resp}"
            );
            assert!(
                resp.contains("{name}"),
                "the refusal names the variable: {resp}"
            );
        }
    }

    /// Every gen-delim, raw where HTTP lets it stand in a path segment and percent-encoded
    /// always (in both hex cases): a strict `{var}` refuses each, and `{+var}` carries each
    /// into the IRI as decoded. `?` and `#` cannot appear raw in a path — they end it — and a
    /// raw `/` is a separator, so those three are tested encoded only.
    #[test]
    fn a_strict_variable_refuses_every_gen_delim_and_a_raw_one_carries_it() {
        let strict = RouteTable::new(vec![plain_route("/s/{key}", "urn:test:seg:{key}")]);
        let raw = RouteTable::new(vec![plain_route("/s/{+key}", "urn:test:seg:{+key}")]);
        let mut cases: Vec<(String, char)> = vec![
            ("a:b".into(), ':'),
            ("a[b".into(), '['),
            ("a]b".into(), ']'),
            ("a@b".into(), '@'),
        ];
        for delim in GEN_DELIMS {
            let hex = format!("{:02X}", delim as u32);
            cases.push((format!("a%{hex}b"), delim));
            cases.push((format!("a%{}b", hex.to_lowercase()), delim));
        }
        for (seg, delim) in cases {
            let path = decode_path(format!("/s/{seg}").as_bytes()).unwrap();
            let refused = strict
                .match_path(&path)
                .expect("one segment, so it matches");
            let why = refused.iri.expect_err("strict refuses");
            assert!(
                why.contains("{key}") && why.contains(&format!("'{delim}'")),
                "{seg}: {why}"
            );
            let carried = raw.match_path(&path).expect("matches").iri;
            assert_eq!(carried, Ok(format!("urn:test:seg:a{delim}b")), "{seg}");
        }
        // A value with no delimiter fills either spelling, and the two agree.
        let plain = decode_path(b"/s/alice").unwrap();
        assert_eq!(
            strict.match_path(&plain).unwrap().iri.as_deref(),
            Ok("urn:test:seg:alice")
        );
        assert_eq!(
            raw.match_path(&plain).unwrap().iri.as_deref(),
            Ok("urn:test:seg:alice")
        );
    }

    /// `{+var}` is raw only when EVERY spelling of the variable says so: a pattern and a
    /// template that disagree are strict, whichever side carries the `+`.
    #[test]
    fn a_pattern_and_template_that_disagree_are_strict() {
        let path = decode_path(b"/s/a:b").unwrap();
        for (pattern, template) in [
            ("/s/{+key}", "urn:test:seg:{key}"),
            ("/s/{key}", "urn:test:seg:{+key}"),
            ("/s/{+key}", "urn:test:seg:{+key}:{key}"),
        ] {
            let table = RouteTable::new(vec![plain_route(pattern, template)]);
            assert!(
                table.match_path(&path).expect("matches").iri.is_err(),
                "{pattern} -> {template} must be strict"
            );
        }
    }

    /// The template is expanded in ONE pass: a captured value that reads like another
    /// placeholder is data. (Sequential `replace` used to expand `{b}` inside `a`'s value.)
    #[test]
    fn a_captured_value_is_never_expanded_as_a_placeholder() {
        let table = RouteTable::new(vec![plain_route("/p/{a}/{b}", "urn:test:{a}:{b}")]);
        let hit = table
            .match_path(&decode_path(b"/p/%7Bb%7D/x").unwrap())
            .unwrap();
        assert_eq!(hit.iri.as_deref(), Ok("urn:test:{b}:x"));
        // An unbound placeholder stays as written, as it always did.
        let table = RouteTable::new(vec![plain_route("/q/{a}", "urn:test:{a}:{other}")]);
        let hit = table.match_path(&decode_path(b"/q/x").unwrap()).unwrap();
        assert_eq!(hit.iri.as_deref(), Ok("urn:test:x:{other}"));
    }

    /// A strict refusal is final: the route's shape claimed the path, so neither a later
    /// route nor the mechanical default answers it — either could name another resource.
    #[tokio::test]
    async fn a_strict_refusal_does_not_fall_through() {
        let addr = start_with(EdgeConfig {
            routes: RouteTable::new(vec![
                plain_route("/test/{who}/hello", "urn:test:{who}:hello"),
                plain_route("/test/{+who}/hello", "urn:test:id:hello"),
            ]),
            ..Default::default()
        })
        .await;
        // Without the route, `/test/id:x/hello` would be the mechanical `urn:test:id:x:hello`;
        // with only the second route it would be `urn:test:id:hello` ("hi").
        let resp = roundtrip(addr, "GET /test/id:x/hello HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"), "got: {resp}");
        assert!(resp.contains("{who}"), "got: {resp}");
        // `{+var}` end to end: the decoded `/` and `:` reach the endpoint as written.
        let addr = start_with(EdgeConfig {
            routes: RouteTable::new(vec![plain_route("/b/{+iri}", "urn:test:seg:{+iri}")]),
            routes_only: true,
            ..Default::default()
        })
        .await;
        let resp = roundtrip(
            addr,
            "GET /b/urn:repo:x:file:src%2Flib.rs HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(
            resp.ends_with("urn:test:seg:urn:repo:x:file:src/lib.rs"),
            "got: {resp}"
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
                redirect: None,
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
                redirect: None,
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

    /// ledger #1065: an input the resolving grammar BINDS from the IRI (`InputSource::Binding`)
    /// is already satisfied by the path the description was asked of, so it is not a query
    /// parameter a client could send. It used to be listed as `in: query, required`.
    #[tokio::test]
    async fn description_omits_an_input_the_path_already_binds() {
        let addr = start().await;
        let resp = roundtrip(
            addr,
            "GET /test/tpl/alice?description HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        let v = openapi_body(&resp);
        let get = &v["paths"]["/test/tpl/alice"]["get"];
        assert!(get.is_object(), "the read is projected: {v}");
        let named = get["parameters"]
            .as_array()
            .map(|params| params.iter().any(|p| p["name"] == "name"))
            .unwrap_or(false);
        assert!(!named, "a bound input is not a query parameter: {v}");
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

    /// ledger #1547: a LIST argument repeated in the query string is JOINED with its
    /// separator's canonical character, so `?graph=A&graph=B` and `?graph=A,B` are one
    /// request; a repeat of a non-list name is still the typed 400.
    #[tokio::test]
    async fn a_list_argument_repeated_in_the_query_is_joined() {
        let addr = start().await;
        for query in [
            "graph=urn:a&query=q&graph=urn:b",
            "graph=urn:a,urn:b&query=q",
        ] {
            let resp = get(addr, &format!("/test/graphs?{query}"), None).await;
            assert!(resp.starts_with("HTTP/1.1 200 "), "{query}: {resp}");
            assert!(
                resp.ends_with("graph=urn:a,urn:b query=q"),
                "{query}: {resp}"
            );
        }
        let resp = get(addr, "/test/graphs?query=a&query=b", None).await;
        assert!(resp.starts_with("HTTP/1.1 400 "), "{resp}");
        assert!(
            resp.ends_with(
                "invalid argument `query`: given twice; an argument takes one value, so name it \
                 once"
            ),
            "{resp}"
        );
        // The description says the list may repeat.
        let resp = get(addr, "/test/graphs?description", None).await;
        let v = openapi_body(&resp);
        let graph = &v["paths"]["/test/graphs"]["get"]["parameters"][0];
        assert_eq!(graph["name"], "graph", "{v}");
        assert_eq!(graph["schema"]["type"], "array", "{v}");
        assert_eq!(graph["explode"], true, "{v}");
    }

    /// ledger #1547 (#358): an ENVELOPE action's request body IS the carrier, so the fields
    /// are its properties and the carrier is not one of them, as JSON and as a urlencoded
    /// form alike.
    #[tokio::test]
    async fn the_openapi_of_an_envelope_projects_its_fields_as_the_body() {
        let addr = start().await;
        let resp = get(addr, "/test/form?description", None).await;
        let v = openapi_body(&resp);
        let content = &v["paths"]["/test/form"]["post"]["requestBody"]["content"];
        for media in ["application/json", "application/x-www-form-urlencoded"] {
            let schema = &content[media]["schema"];
            let names: Vec<&str> = schema["properties"]
                .as_object()
                .unwrap_or_else(|| panic!("{media}: {v}"))
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(names, ["email", "note"], "{media}: {v}");
            assert_eq!(
                schema["required"],
                serde_json::json!(["email"]),
                "{media}: {v}"
            );
        }
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

    /// ★ The fail-closed path of `?description` (ledger #118): a name that RESOLVES, through a
    /// space whose manifold row is not that name — a mount listing one representative IRI for
    /// a family it serves by prefix — offers no action for the name, so it is described as
    /// missing (404) even though a plain GET of it answers. Failing closed is the safe
    /// direction, which is exactly why a defect here would be silent: this pins it, and the
    /// control (the row's own name IS described) shows the 404 is the row match and not the
    /// space.
    #[tokio::test]
    async fn a_mounted_name_its_rows_do_not_name_is_not_described() {
        use ikigai_core::{Bindings, Resolution, Resolved, Scope, Space, SpaceEntry};
        /// Serves every `urn:test:mnt:…` name, and enumerates one row for all of them.
        struct Mounted(Arc<dyn ikigai_core::Endpoint>);
        impl Space for Mounted {
            fn resolve(&self, request: &Request, _scope: &Scope) -> Resolution {
                if request.target.as_str().starts_with("urn:test:mnt:") {
                    Resolution::Hit(Resolved::new(Arc::clone(&self.0), Bindings::new()))
                } else {
                    Resolution::Miss
                }
            }
            fn entries(&self) -> Option<Vec<SpaceEntry>> {
                Some(vec![
                    SpaceEntry::new("urn:test:mnt:root", "mnt").with_origin("peer")
                ])
            }
        }
        let endpoint = FnEndpoint::new("mnt", |_inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"mounted".to_vec(),
            ))
        })
        .with_description(
            Description::new("mnt").action(ActionSpec::new(Verb::Source).summary("read it")),
        );
        let kernel = Arc::new(Kernel::new(Arc::new(Mounted(Arc::new(endpoint)))));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ =
                serve_with_listener(kernel, public_cap(), listener, EdgeConfig::default()).await;
        });

        let named = roundtrip(addr, &raw_request("GET", "/test/mnt/root?description", "x")).await;
        assert!(
            named.starts_with("HTTP/1.1 200 OK"),
            "the row's own name: {named}"
        );
        let other = roundtrip(
            addr,
            &raw_request("GET", "/test/mnt/other?description", "x"),
        )
        .await;
        assert!(
            other.starts_with("HTTP/1.1 404 Not Found"),
            "no row names it, so nothing is offered: {other}"
        );
        let read = roundtrip(addr, &raw_request("GET", "/test/mnt/other", "x")).await;
        assert!(
            read.starts_with("HTTP/1.1 200 OK") && read.ends_with("mounted"),
            "the name itself resolves, so the 404 above is the row match: {read}"
        );
    }

    #[tokio::test]
    async fn head_on_a_description_matches_get() {
        /// Status line and headers, `Content-Length` included (HEAD names GET's length,
        /// ledger #118), plus the body.
        fn parts(resp: &str) -> (Vec<&str>, &str) {
            let (head, body) = resp.split_once("\r\n\r\n").unwrap_or((resp, ""));
            (head.split("\r\n").collect(), body)
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
                redirect: None,
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
    /// if a person had typed it. The hand-written door refused it (`501`); since the door moved
    /// onto hyper (ledger #2236) it is taken, de-framed, under the same bound: the endpoint is
    /// handed the content and never the framing.
    #[tokio::test]
    async fn a_chunked_body_is_delivered_as_its_content_never_its_framing() {
        let addr = start().await;
        let out = roundtrip(
            addr,
            "PUT /test/writable HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 200 "), "got: {out}");
        assert!(out.ends_with("\r\n\r\nhello"), "got: {out}");
        assert!(
            !out.contains("5\r\nhello"),
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

    /// How long a client that sent `Expect: 100-continue` may wait for the door's first word.
    /// A JVM HTTP client waits 3 s and curl 1 s before sending the body anyway, so a door that
    /// says nothing costs every write that long (ledger #1408); a prompt door answers in
    /// milliseconds.
    const PROMPT: std::time::Duration = std::time::Duration::from_secs(1);

    /// Send `head` the way a client honoring `Expect: 100-continue` does: the head alone, then
    /// wait (at most [`PROMPT`]) for the door's first answer before the body. Returns that first
    /// answer's head and the final response: after a `100`, the body is sent and the final
    /// response is what follows; a door may instead answer its final status at once (RFC 9110
    /// §10.1.1), and then the body is never sent.
    async fn expect_continue(addr: SocketAddr, head: &str, body: &[u8]) -> (String, String) {
        let mut c = connect(addr).await;
        c.write_all(head.as_bytes()).await.unwrap();
        let mut got = Vec::new();
        let mut tmp = [0u8; 1024];
        let first = tokio::time::timeout(PROMPT, async {
            loop {
                if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                    return end + 4;
                }
                match c.read(&mut tmp).await {
                    Ok(0) | Err(_) => return got.len(),
                    Ok(n) => got.extend_from_slice(&tmp[..n]),
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the door said nothing within {PROMPT:?} to a head asking `Expect: \
                 100-continue`, so the client sits out its whole expect timeout"
            )
        });
        let interim = String::from_utf8_lossy(&got[..first]).into_owned();
        let mut rest = got[first..].to_vec();
        if interim.starts_with("HTTP/1.1 100 ") {
            c.write_all(body).await.unwrap();
        } else {
            rest = got;
        }
        let _ = c.read_to_end(&mut rest).await;
        (interim, String::from_utf8_lossy(&rest).into_owned())
    }

    /// ledger #1408: a write whose client asks `Expect: 100-continue` gets the interim `100`
    /// at once, then its answer. The door reads the body only after inviting it, so a door
    /// that never invites leaves the client waiting out its own timeout on every write.
    #[tokio::test]
    async fn an_expecting_write_is_invited_to_send_its_body_at_once() {
        let addr = start().await;
        let (interim, out) = expect_continue(
            addr,
            "POST /test/writable HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n\
             Expect: 100-continue\r\nContent-Length: 5\r\n\r\n",
            b"hello",
        )
        .await;
        assert_eq!(interim, "HTTP/1.1 100 Continue\r\n\r\n");
        assert!(out.starts_with("HTTP/1.1 200 "), "got: {out}");
        assert!(
            out.ends_with("hello"),
            "the body reached the endpoint: {out}"
        );
    }

    /// The token is case-insensitive (RFC 9110 §10.1.1), as clients spell it variously.
    #[tokio::test]
    async fn the_expectation_is_read_case_insensitively() {
        let addr = start().await;
        let (interim, out) = expect_continue(
            addr,
            "PUT /test/writable HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n\
             expect: 100-Continue\r\nContent-Length: 2\r\n\r\n",
            b"hi",
        )
        .await;
        assert_eq!(interim, "HTTP/1.1 100 Continue\r\n\r\n");
        assert!(out.starts_with("HTTP/1.1 200 "), "got: {out}");
    }

    /// A route that does not take the method is not a reason to leave the client waiting:
    /// it answers promptly (its `405` after the body, or before it), never after a stall.
    #[tokio::test]
    async fn an_expecting_post_to_a_read_only_path_is_answered_promptly() {
        let addr = start().await;
        let (_, out) = expect_continue(
            addr,
            "POST /test/id/hello HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n\
             Content-Length: 5\r\n\r\n",
            b"hello",
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 405 "), "got: {out}");
    }

    /// The same for a door that refuses the caller at admission (the general door's form of
    /// an unauthenticated write; the layers front's `401` is pinned in the cli's own suite).
    #[tokio::test]
    async fn an_expecting_write_refused_at_admission_is_answered_promptly() {
        let addr = start_with(admitting(403)).await;
        let (_, out) = expect_continue(
            addr,
            "POST /test/writable HTTP/1.1\r\nHost: evil\r\nExpect: 100-continue\r\n\
             Content-Length: 5\r\n\r\n",
            b"hello",
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 403 "), "got: {out}");
    }

    /// A declared length over the bound is refused with its final status and NO invitation:
    /// saving the client that upload is what `Expect` is for.
    #[tokio::test]
    async fn an_expecting_body_over_the_bound_is_refused_without_an_invitation() {
        let addr = start().await;
        let (interim, out) = expect_continue(
            addr,
            "PUT /test/writable HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n\
             Content-Length: 50000000\r\n\r\n",
            b"",
        )
        .await;
        assert!(interim.starts_with("HTTP/1.1 413 "), "got: {interim}");
        assert!(!out.contains("100 Continue"), "got: {out}");
    }

    /// An HTTP/1.0 client cannot read an interim answer, so the expectation is ignored there
    /// (RFC 9110 §10.1.1): the answer is the final one alone.
    #[tokio::test]
    async fn an_http_1_0_request_gets_no_invitation() {
        let addr = start().await;
        let out = roundtrip(
            addr,
            "PUT /test/writable HTTP/1.0\r\nHost: x\r\nExpect: 100-continue\r\n\
             Content-Length: 5\r\n\r\nhello",
        )
        .await;
        // hyper answers an HTTP/1.0 request in HTTP/1.0 (ledger #2236); the hand-written door
        // wrote `HTTP/1.1` on every answer.
        assert!(out.starts_with("HTTP/1.0 200 "), "got: {out}");
        assert!(!out.contains("100 Continue"), "got: {out}");
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
            // The adapter forces no `as`, so the kernel fills the DECLARED default before
            // the endpoint runs (core 0.1.105, ledger #19): the default face is
            // `text/plain`, spelled out, where the fixture once fell back to its own word.
            assert!(
                out.ends_with("text/plain"),
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
            assert!(
                decode_text(bad, false, 0, "x").is_err(),
                "path form: {bad:?}"
            );
            assert!(
                decode_text(bad, true, 0, "x").is_err(),
                "form form: {bad:?}"
            );
        }
    }

    /// Ledger #1878: a refusal names the byte offset in the request target where the bad
    /// escape starts, or where the part that is not UTF-8 starts, in the path, a query name
    /// and a query value alike. (The private decoder this replaced refused the same targets
    /// with a bare `malformed percent-escape` or `not UTF-8 once decoded`.)
    #[test]
    fn a_refused_target_names_the_byte_offset() {
        let escape = |at: usize| {
            format!(
                "malformed percent-escape at byte {at} of the request target: a `%` must be \
                 followed by two hex digits"
            )
        };
        let utf8 = |what: &str, at: usize| {
            format!(
                "the {what} at byte {at} of the request target is not UTF-8 once percent-decoded"
            )
        };
        for (target, why) in [
            (&b"/a/b%zz"[..], escape(4)),
            (b"/100%", escape(4)),
            (b"/p?k=v&x%4=1", escape(8)),
            (b"/p?k=v&x=1%", escape(10)),
            (b"/a/%FF", utf8("path segment", 3)),
            (b"/a/\xff", utf8("path segment", 3)),
            (b"/p?k=%C3", utf8("query value", 5)),
            (b"/p?a=1&%FF=2", utf8("query name", 7)),
        ] {
            assert_eq!(parse_target(target).unwrap_err(), why, "{target:?}");
        }
        // Both readers carry the sentence into the 400.
        assert_eq!(
            parse_head(b"GET /p?q=%G1 HTTP/1.1\r\nHost: x").err(),
            Some(escape(5))
        );
    }

    #[test]
    fn the_decoder_works_on_bytes_and_validates_utf8_once() {
        let text = |raw: &[u8], plus| decode_text(raw, plus, 0, "x");
        assert_eq!(text(b"caf%C3%A9", false).unwrap(), "caf\u{e9}");
        // One character split between an escape and a raw byte is still one character: the
        // UTF-8 check runs over the decoded whole, not per escape.
        assert_eq!(text(b"caf%C3\xa9", false).unwrap(), "caf\u{e9}");
        assert_eq!(text(b"caf\xc3\xa9", false).unwrap(), "caf\u{e9}");
        assert!(text(b"%FF", false).is_err());
        assert!(text(b"\xff", false).is_err());
        assert!(text(b"%C3", false).is_err(), "a truncated sequence");
        assert_eq!(text(b"%4a%4A", false).unwrap(), "JJ");
        assert_eq!(text(b"a+b", false).unwrap(), "a+b");
        assert_eq!(text(b"a+b", true).unwrap(), "a b");
        assert_eq!(text(b"a%2Bb", true).unwrap(), "a+b");
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
        // link gonk's `percent` builds for a hostile ledger name. The route still MATCHES
        // (four segments), and a strict `{ledger}` then refuses the decoded `/`; a raw
        // `{+ledger}` carries it, still as one segment.
        let hostile = decode_path(b"/l/..%2F..%2Fetc/item/244").unwrap();
        let strict = RouteTable::new(vec![plain_route(
            "/l/{ledger}/item/{id}",
            "urn:x:{ledger}:{id}",
        )]);
        let hit = strict
            .match_path(&hostile)
            .expect("four segments, so the route matches");
        let why = hit
            .iri
            .expect_err("a strict {ledger} refuses a decoded '/'");
        assert!(why.contains("{ledger}") && why.contains("'/'"), "{why}");
        let raw = RouteTable::new(vec![plain_route(
            "/l/{+ledger}/item/{id}",
            "urn:x:{+ledger}:{id}",
        )]);
        assert_eq!(
            raw.match_path(&hostile).expect("matches").iri.as_deref(),
            Ok("urn:x:../../etc:244")
        );
        assert!(strict
            .match_path(&decode_path(b"/l/a/b/item/1").unwrap())
            .is_none());
        assert!(raw
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
                // Not `u8::from_str_radix`, which accepts a leading sign (ledger #591).
                let hex = |b: u8| char::from(b).to_digit(16);
                let expect = match (hex(hi), hex(lo)) {
                    (Some(h), Some(l)) if (h << 4 | l) < 0x80 => char::from_u32(h << 4 | l),
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
            // A header name is case-insensitive, and hyper writes this one `Etag` (ledger #2236).
            resp.lines()
                .find_map(|l| {
                    l.split_once(':')
                        .filter(|(name, _)| name.eq_ignore_ascii_case("etag"))
                        .map(|(_, value)| value.trim())
                })
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

        /// ledger #1077: a door that names a principal makes the answer that party's — the
        /// kernel keys it on the minted capability — so no shared cache may hand it to another,
        /// and a route that pins its capability still varies on the credentials it was read from.
        #[tokio::test]
        async fn a_named_principal_makes_it_private_even_on_a_pinned_route() {
            let door: PrincipalFn =
                Arc::new(|_req: &HttpRequest| Some("urn:example:alice".to_string()));
            let addr = serve(EdgeConfig {
                principal_fn: Some(door.clone()),
                ..EdgeConfig::default()
            })
            .await;
            let resp = get(addr, "/test/c/whoami", "").await;
            assert_eq!(cache_control(&resp), "private, no-cache", "{resp}");
            let addr = serve(EdgeConfig {
                principal_fn: Some(door),
                routes: RouteTable::new(vec![Route {
                    pattern: "/members/whoami".to_string(),
                    iri_template: "urn:test:c:whoami".to_string(),
                    redirect: None,
                    cap: Some(vec!["urn:cap:member".to_string()]),
                    cors: None,
                    csp: None,
                }]),
                ..EdgeConfig::default()
            })
            .await;
            let resp = get(addr, "/members/whoami", "").await;
            assert_eq!(cache_control(&resp), "private, no-cache", "{resp}");
            assert!(vary_of(&resp).contains(&"Cookie".to_string()), "{resp}");
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
                    redirect: None,
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
