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
//!   key baked in). The path is canonical.
//! - **Accept ↔ conneg**: the `Accept` header drives the `as=` transreptor selection.
//! - **query + body → inputs**: query params become inspectable request args; a write's body
//!   is the piped `content`, with the request Content-Type surfaced as `content-type`.
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

/// Serve `kernel` over HTTP on `addr`, resolving each request under `cap_fn(request)`.
/// One request per connection (`Connection: close`). Runs until the listener errors.
pub async fn serve(kernel: Arc<Kernel>, cap_fn: CapFn, addr: SocketAddr) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (sock, _) = listener.accept().await?;
        let kernel = Arc::clone(&kernel);
        let cap_fn = Arc::clone(&cap_fn);
        tokio::spawn(async move {
            let _ = handle(sock, kernel, cap_fn).await;
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
}

impl Resp {
    fn text(status: u16, reason: &'static str, body: &str) -> Resp {
        Resp {
            status,
            reason,
            content_type: "text/plain; charset=utf-8".to_string(),
            body: body.as_bytes().to_vec(),
            allow: None,
        }
    }
}

async fn handle(mut sock: TcpStream, kernel: Arc<Kernel>, cap_fn: CapFn) -> std::io::Result<()> {
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

    let resp = respond(&kernel, &cap_fn, &req).await;
    write(&mut sock, resp).await
}

/// The core adapter: method → verb (gated by `describe().verbs`), path → iri,
/// query → args, body → piped `content`, Accept → conneg, resolved under the cap.
async fn respond(kernel: &Kernel, cap_fn: &CapFn, req: &HttpRequest) -> Resp {
    let iri_str = iri_from_path(&req.path);
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
            status: 204,
            reason: "No Content",
            content_type: String::new(),
            body: Vec::new(),
            allow: Some(allow),
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
    let mut request = Request::new(verb, iri);
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

    let cap = cap_fn(req);
    match kernel.issue(request, &cap).await {
        Ok(repr) => success_resp(&req.method, verb, repr),
        Err(e) => error_resp(&e),
    }
}

/// A `405` carrying the resource's `Allow` list.
fn method_not_allowed(allow: String) -> Resp {
    let mut r = Resp::text(405, "Method Not Allowed", "method not allowed");
    r.allow = Some(allow);
    r
}

/// Shape a success response by method/verb: HEAD → headers only; DELETE → 204; a
/// write returning no body → 204; otherwise 200 with the representation.
fn success_resp(method: &str, verb: Verb, repr: ikigai_core::Representation) -> Resp {
    if method == "HEAD" {
        return Resp {
            status: 200,
            reason: "OK",
            content_type: media_type_of(&repr),
            body: Vec::new(),
            allow: None,
        };
    }
    if verb == Verb::Delete || (verb == Verb::Sink && repr.bytes.is_empty()) {
        return Resp {
            status: 204,
            reason: "No Content",
            content_type: String::new(),
            body: Vec::new(),
            allow: None,
        };
    }
    Resp {
        status: 200,
        reason: "OK",
        content_type: media_type_of(&repr),
        body: repr.bytes,
        allow: None,
    }
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
        Error::MissingArgument(_) | Error::InvalidArgument { .. } => (400, "Bad Request"),
        _ if e.is_transient() => (503, "Service Unavailable"),
        _ => (500, "Internal Server Error"),
    };
    Resp::text(status, reason, &format!("{e}"))
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
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:test:id:hello"), hello)
            .bind(Exact::new("urn:test:guarded"), guarded)
            .bind(Exact::new("urn:test:writable"), writable)
            .bind(Exact::new("urn:test:echo"), echo)
            .bind(Exact::new("urn:test:deletable"), deletable);
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener); // free the port for serve() to rebind (racy but fine for a test)
        let kernel = test_kernel();
        tokio::spawn(async move {
            let _ = serve(kernel, public_cap(), addr).await;
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
}
