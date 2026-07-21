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
//! - **method ↔ verb**: GET/HEAD → `Source`, OPTIONS → the allow-list; write verbs land in a
//!   later slice. An unsupported method is `405` with `Allow`.
//! - **path ↔ iri**: `/account/id/alice` → `urn:account:id:alice` (singular noun, partition
//!   key baked in). The path is canonical.
//! - **Accept ↔ conneg**: the `Accept` header drives the `as=` transreptor selection.
//! - **`cap_of(request)` is the multi-tenant door** — every request resolves under a
//!   capability derived from its identity. This slice ships a public default; a per-user
//!   capability (magic-link / passkey) fills the same seam later.
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
    allow: Option<&'static str>,
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

/// The core adapter: method → verb, path → iri, Accept → conneg, resolve under the cap.
async fn respond(kernel: &Kernel, cap_fn: &CapFn, req: &HttpRequest) -> Resp {
    let verb = match req.method.as_str() {
        "GET" | "HEAD" => Verb::Source,
        // S0 ships the read path + the allow-list; write verbs are the next slice.
        "OPTIONS" => {
            return Resp {
                status: 204,
                reason: "No Content",
                content_type: String::new(),
                body: Vec::new(),
                allow: Some("GET, HEAD, OPTIONS"),
            }
        }
        _ => {
            let mut r = Resp::text(405, "Method Not Allowed", "method not allowed");
            r.allow = Some("GET, HEAD, OPTIONS");
            return r;
        }
    };

    let iri_str = iri_from_path(&req.path);
    let iri = match Iri::parse(&iri_str) {
        Ok(i) => i,
        Err(_) => return Resp::text(400, "Bad Request", "not a resource path"),
    };

    let mut request = Request::new(verb, iri);
    // Accept → `as=` conneg (skip the wildcard).
    if let Some(accept) = req.header("accept") {
        let media = first_media(accept);
        if !media.is_empty() && media != "*/*" {
            request = request.with_arg("as", ArgRef::Inline(media.into_bytes()));
        }
    }

    let cap = cap_fn(req);
    match kernel.issue(request, &cap).await {
        Ok(repr) => {
            let head_only = req.method == "HEAD";
            Resp {
                status: 200,
                reason: "OK",
                content_type: media_type_of(&repr),
                body: if head_only { Vec::new() } else { repr.bytes },
                allow: None,
            }
        }
        Err(e) => error_resp(&e),
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
        EndpointSpace, Error, Exact, FnEndpoint, Invocation, ReprType, Representation,
    };
    use std::sync::Arc;

    // A kernel with two endpoints: a plain resource and a cap-denied one.
    fn test_kernel() -> Arc<Kernel> {
        let hello = FnEndpoint::new("hello", |_inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain").with_param("charset", "utf-8"),
                b"hi".to_vec(),
            ))
        });
        let guarded = FnEndpoint::new("guarded", |inv: &Invocation<'_>| {
            if !inv.capability.allows("urn:cap:test") {
                return Err(Error::Denied("needs urn:cap:test".into()));
            }
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"secret".to_vec(),
            ))
        });
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:test:id:hello"), hello)
            .bind(Exact::new("urn:test:guarded"), guarded);
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
}
