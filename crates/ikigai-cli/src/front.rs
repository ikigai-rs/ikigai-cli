//! The layer host's HTTPS front: participant verbs over HTTP and JSON, beside the QUIC door.
//!
//! A participant that has only an HTTP client and a JSON parser takes part in layers here.
//! `serve quic://… --layers-https <addr>` (or `layers.https` in the config home, instance-scoped
//! as `<instance>.layers.https`) opens it beside the QUIC door of a door that hosts layers; it
//! is off unless one of the two names an address.
//!
//! **One authority, two faces.** The front serves the SAME kernel object the QUIC door serves
//! (`ikigai_quic::serve_shared_on`), mints every request's session with the QUIC door's own
//! minter (the one that reads `clients.json` and `grants.json`), and answers through
//! `ikigai_quic::dispatch`, the function every door to a kernel answers through. So a
//! participant's grant, principal, admission, shapes and refusals are the layer host's, whichever
//! face it came through: this module routes and authenticates and decides nothing else.
//!
//! **Authentication: a bearer token bound to ONE enrolled participant.** `Authorization: Bearer
//! <token>`; the token resolves through `layer-tokens.json` ([`ikigai_embedded::tokens`], read on
//! every request) to the `clients.json` key it was minted for, and the QUIC door's minter turns
//! that key into the session it would mint for the certificate. No token, an unknown or revoked
//! token, or a client the enrollment no longer holds: `401`, and nothing is resolved. The
//! transport is TLS with the QUIC door's own server certificate, which a client pins.
//!
//! **Routes**, GET and POST only (a DELETE that answers with a body is not something every HTTP
//! client can read, so `take` is a POST that answers 200 with what it took). A HEAD is a GET
//! that answers with the head alone, as ikigai-web's routed adapter answers it: GET's status and
//! headers, `Content-Length` GET's length, no content; a refusal to a HEAD is a head alone too,
//! and a read route's `Allow` names HEAD beside GET (ledger #1593):
//!
//! | method | path | resource | default `as` |
//! | --- | --- | --- | --- |
//! | GET | `/layers/me` | `urn:layers:me` | `application/json` |
//! | GET | `/layers/feed?after=talk:3,tasks:0&wait=` | `urn:layers:feed` | `application/json` |
//! | GET | `/layer/{layer}/context` | `urn:layer:{layer}:context` | (its JSON-LD) |
//! | GET | `/layer/{layer}/entries?after=&from=&type=` | `…:entries` | `application/ld+json` |
//! | GET | `/layer/{layer}/entry/{id}` | `…:entry:{id}` | `application/ld+json` |
//! | GET | `/layer/{layer}/graph/{slug}` | `…:graph:{slug}` | `application/ld+json` |
//! | GET | `/layer/{layer}/latest?about=` | `…:latest` | `application/ld+json` |
//! | GET | `/layer/{layer}/feed?after=&wait=` | `…:feed` | `application/json` |
//! | GET | `/layer/{layer}/rd?tuple=&after=&state=` | `…:tuples` (Source) | `application/json`; `application/ld+json` with `tuple=` |
//! | GET | `/layer/{layer}/receipt/{id}` | `…:receipt:{id}` | `application/ld+json` |
//! | POST | `/layer/{layer}/say` | `…:say` (Sink, the body is `content`) | `application/json` |
//! | POST | `/layer/{layer}/out` | `…:tuples` (Sink, the body is `content`) | `application/json` |
//! | POST | `/layer/{layer}/take?tuple=` | `…:tuples` (Delete) | `application/ld+json` |
//! | GET, POST | `/layer/{layer}/tuples` | the same three by the resource's own name: GET is `rd`, POST is `out`, POST with `X-HTTP-Method-Override: DELETE` is `take` | as above |
//!
//! Every path is the resource's IRI with `:` as `/` under `/layer/{layer}/` (or `/layers/`),
//! the mechanical mapping ikigai-web uses, except the three verb names `rd`, `out` and `take`,
//! which name the tuplespace's verbs on `…:tuples`. A long poll (`feed?wait=`, at most 60 s) is
//! HELD until an event arrives or the wait runs out, never answered early with nothing.
//!
//! Query parameters are the resource's own arguments, forwarded by name (`as=` overrides the
//! default face; a face the resource does not offer is refused by the resource, not here). A
//! `principal` parameter is dropped: who asks is the token's, never the caller's to say.
//!
//! **A write's body is Turtle or JSON-LD**, as the layer reads it. A JSON object with no
//! `@context` of its own is written UNDER THE LAYER'S CONTEXT: the front reads
//! `urn:layer:{layer}:context` as the caller and puts its `@context` on the object, so a
//! participant writes `{"@id": "urn:layer:new", "@type": "Message", "body": "hi"}` in the terms
//! it reads back.
//!
//! **Errors** are JSON with the right status: `{"kind", "message", …}`, `kind` being core's
//! `Error::kind()` and the extra fields `ikigai_web::error_json`'s (`name` and `detail` for an
//! argument). A take that lost a race, or whose reply was lost and is retried, is `409` with
//! kind `conflict`; the taker reads its take back from the receipt with `GET
//! /layer/{layer}/rd?state=taken&tuple=<iri>`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use ikigai_core::{ArgRef, Error, Iri, Kernel, Request, Verb};
use ikigai_http::auth::Scheme;
use ikigai_web::{EdgeConfig, HttpRequest, Response};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// What the front serves and how it authenticates.
pub struct Front {
    /// The kernel the QUIC door serves: the same object, never a second one.
    pub kernel: Arc<Kernel>,
    /// The QUIC door's minter, so a token's session is the one its certificate would get.
    pub minter: ikigai_quic::Minter,
    /// `layer-tokens.json`, read on every request.
    pub tokens: PathBuf,
    /// The bounds every request is read under (ikigai-web's own).
    pub edge: EdgeConfig,
}

/// One request the router decided on: a verb on a resource with its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routed {
    pub verb: Verb,
    pub iri: String,
    pub args: Vec<(String, Vec<u8>)>,
    /// The layer whose context a JSON body without one is written under (`say`, `out`).
    pub write_layer: Option<String>,
}

/// The JSON-LD and JSON faces, by name.
const LD: &str = "application/ld+json";
const JSON: &str = "application/json";

/// A front refusal as the typed JSON every error carries.
fn refusal(status: u16, kind: &str, message: &str) -> Response {
    let body = serde_json::json!({ "kind": kind, "message": message }).to_string();
    Response::new(status, JSON, body.into_bytes())
}

/// The answer to a kernel error: its status and its typed JSON.
fn error_response(e: &Error) -> Response {
    Response::new(
        ikigai_web::error_status(e),
        JSON,
        ikigai_web::error_json(e).into_bytes(),
    )
}

/// Whether `method` reads: GET, or HEAD, which is GET answered with the head alone.
fn is_read(method: &str) -> bool {
    method == "GET" || method == "HEAD"
}

/// A layer name as the layer host names them: `[a-z0-9-]`, 1 to 24 characters.
fn is_layer(name: &str) -> bool {
    (1..=24).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// An entry id, receipt id or graph slug: one IRI segment of unreserved characters.
fn is_segment(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'~'))
}

/// Route `req` to the resource it names, or answer it here (404 for no route, 405 for a
/// route that does not take the method).
pub fn route(req: &HttpRequest) -> Result<Routed, Response> {
    let segments: Vec<&str> = req.path.split('/').filter(|s| !s.is_empty()).collect();
    let not_found = || refusal(404, "not-found", &format!("no route for {}", req.path));
    // (allowed method, verb, iri, default face, the layer a write's body is under)
    let (method, verb, iri, face, write_layer): (&str, Verb, String, Option<&str>, Option<&str>) =
        match segments.as_slice() {
            ["layers", "me"] => (
                "GET",
                Verb::Source,
                "urn:layers:me".into(),
                Some(JSON),
                None,
            ),
            ["layers", "feed"] => (
                "GET",
                Verb::Source,
                "urn:layers:feed".into(),
                Some(JSON),
                None,
            ),
            ["layer", layer, rest @ ..] if is_layer(layer) => {
                let at = |local: &str| format!("urn:layer:{layer}:{local}");
                match rest {
                    ["context"] => ("GET", Verb::Source, at("context"), None, None),
                    ["entries"] => ("GET", Verb::Source, at("entries"), Some(LD), None),
                    ["entry", id] if is_segment(id) => (
                        "GET",
                        Verb::Source,
                        at(&format!("entry:{id}")),
                        Some(LD),
                        None,
                    ),
                    ["graph", slug] if is_segment(slug) => (
                        "GET",
                        Verb::Source,
                        at(&format!("graph:{slug}")),
                        Some(LD),
                        None,
                    ),
                    ["latest"] => ("GET", Verb::Source, at("latest"), Some(LD), None),
                    ["feed"] => ("GET", Verb::Source, at("feed"), Some(JSON), None),
                    ["rd"] => {
                        // One tuple (or one receipt) is a graph; a list is a list.
                        let one = req.query.iter().any(|(k, _)| k == "tuple");
                        let face = if one { LD } else { JSON };
                        ("GET", Verb::Source, at("tuples"), Some(face), None)
                    }
                    ["receipt", id] if is_segment(id) => (
                        "GET",
                        Verb::Source,
                        at(&format!("receipt:{id}")),
                        Some(LD),
                        None,
                    ),
                    ["say"] => ("POST", Verb::Sink, at("say"), Some(JSON), Some(*layer)),
                    ["out"] => ("POST", Verb::Sink, at("tuples"), Some(JSON), Some(*layer)),
                    ["take"] => ("POST", Verb::Delete, at("tuples"), Some(LD), None),
                    // The resource's own name, the mechanical IRI-to-path mapping: GET is `rd`,
                    // POST is `out`, and POST with `X-HTTP-Method-Override: DELETE` is `take`
                    // (still a POST that answers with the tuple, for a client whose DELETE
                    // cannot read a body).
                    ["tuples"] if is_read(&req.method) => {
                        let one = req.query.iter().any(|(k, _)| k == "tuple");
                        let face = if one { LD } else { JSON };
                        ("GET", Verb::Source, at("tuples"), Some(face), None)
                    }
                    ["tuples"] => match req.header("x-http-method-override") {
                        None => ("POST", Verb::Sink, at("tuples"), Some(JSON), Some(*layer)),
                        Some(o) if o.trim().eq_ignore_ascii_case("DELETE") => {
                            ("POST", Verb::Delete, at("tuples"), Some(LD), None)
                        }
                        Some(other) => {
                            return Err(refusal(
                                400,
                                "invalid-argument",
                                &format!(
                                    "X-HTTP-Method-Override: {other} — only DELETE (a take) is \
                                     overridden here"
                                ),
                            ))
                        }
                    },
                    _ => return Err(not_found()),
                }
            }
            _ => return Err(not_found()),
        };
    if req.method != method && !(method == "GET" && is_read(&req.method)) {
        // `/tuples` takes both; every other route one. HEAD rides with GET.
        let allow = if segments.last() == Some(&"tuples") {
            "GET, HEAD, POST"
        } else if method == "GET" {
            "GET, HEAD"
        } else {
            method
        };
        return Err(refusal(
            405,
            "method-not-allowed",
            &format!("{} takes {method} only", req.path),
        )
        .with_header("Allow", allow));
    }
    // The resource's own arguments, by name. `content` is the body's alone (a write's), and
    // `principal` is never the caller's to name: the door stamps who asked.
    let mut args: Vec<(String, Vec<u8>)> = req
        .query
        .iter()
        .filter(|(k, _)| k != "principal" && k != "content")
        .map(|(k, v)| (k.clone(), v.clone().into_bytes()))
        .collect();
    // ledger #387: a request holds one value per name and `with_arg` keeps the last, so a
    // repeated name is refused here rather than narrowed silently on its way in.
    let mut seen: Vec<&str> = Vec::new();
    for (name, _) in &args {
        if seen.contains(&name.as_str()) {
            return Err(error_response(&Error::InvalidArgument {
                name: name.clone(),
                detail: "given twice; an argument takes one value, so name it once".into(),
            }));
        }
        seen.push(name);
    }
    if let Some(face) = face {
        if !args.iter().any(|(k, _)| k == "as") {
            args.push(("as".to_string(), face.as_bytes().to_vec()));
        }
    }
    if verb == Verb::Sink {
        args.push(("content".to_string(), req.body.clone()));
    }
    Ok(Routed {
        verb,
        iri,
        args,
        write_layer: write_layer.map(str::to_string),
    })
}

/// The token an `Authorization: Bearer <token>` header presents, read through the shared
/// header reader (ledger #1857): the scheme matches case-insensitively, and only SP and HTAB
/// separate it from the token or pad the value (RFC 9110 §11.4).
fn bearer(req: &HttpRequest) -> Option<&str> {
    match ikigai_http::auth::scheme(req.header("authorization")?) {
        Some((Scheme::Bearer, token)) if !token.is_empty() => Some(token),
        _ => None,
    }
}

/// The `401` every authentication failure gets, whatever the reason: a stranger learns nothing
/// about which tokens or participants exist.
fn unauthenticated() -> Response {
    refusal(
        401,
        "denied",
        "authentication required: send `Authorization: Bearer <token>` with a token the \
         operator minted for you (`ikigai layers-token mint`)",
    )
    .with_header("WWW-Authenticate", "Bearer realm=\"layers\"")
}

impl Front {
    /// The session `req`'s token mints, through the QUIC door's minter; `Err` is the `401`.
    fn session(&self, req: &HttpRequest) -> Result<ikigai_quic::Session, Response> {
        let Some(token) = bearer(req) else {
            return Err(unauthenticated());
        };
        let tokens = match ikigai_embedded::tokens::load_from(&self.tokens) {
            Ok(tokens) => tokens,
            Err(why) => {
                crate::diagnose(format_args!(
                    "ikigai: layers https: REFUSED every token: {why}"
                ));
                return Err(unauthenticated());
            }
        };
        // An unknown token is NOT logged: anyone who can reach the port can send one, and a
        // line per request would hand them a lever on the door's log (ikigai-web's accept
        // module makes the same call for per-connection errors). The two refusals below need
        // the operator's own file or a token it minted, so they are logged.
        let Some(binding) = tokens.binding_for(token) else {
            return Err(unauthenticated());
        };
        // The QUIC door keys a connection's file namespace by a hash of its certificate,
        // which a token does not carry. Nothing the front routes to is a file, so the
        // namespace is the token's own and never shared with the certificate's.
        let peer = ikigai_quic::PeerIdentity {
            segment_id: format!("token-{}", binding.id),
            fingerprint: binding.client.clone(),
            source_address: None,
        };
        (self.minter)(&peer).ok_or_else(|| {
            crate::diagnose(format_args!(
                "ikigai: layers https: REFUSED token {} ({}): its client is not enrolled",
                binding.id, binding.label
            ));
            unauthenticated()
        })
    }

    /// Issue one routed request under `session`, through the door every kernel answers by.
    fn issue(
        &self,
        routed: &Routed,
        session: &ikigai_quic::Session,
    ) -> Result<ikigai_core::Representation, Error> {
        let iri = Iri::parse(routed.iri.as_str()).map_err(|e| Error::InvalidArgument {
            name: "path".into(),
            detail: format!("{e:?}"),
        })?;
        let mut request = Request::new(routed.verb, iri);
        for (name, value) in &routed.args {
            request = request.with_arg(name.as_str(), ArgRef::Inline(value.clone()));
        }
        match ikigai_quic::dispatch(&self.kernel, ikigai_wire::Call::Issue(request), session) {
            ikigai_wire::Reply::Resolved(repr, _)
            | ikigai_wire::Reply::ResolvedTraced(repr, _, _) => Ok(repr),
            ikigai_wire::Reply::ErrorTyped(e) => Err(Error::from(e)),
            ikigai_wire::Reply::Error(message) => Err(Error::Endpoint(message)),
            other => Err(Error::Endpoint(format!("unexpected reply: {other:?}"))),
        }
    }

    /// Put the layer's context on a JSON object that names none, read as the caller. Anything
    /// else (Turtle, an array, an object with its own `@context`, JSON too deep or too broken
    /// to read, a context the caller may not read) is left exactly as sent, for the layer to
    /// judge.
    fn under_context(&self, layer: &str, body: Vec<u8>, session: &ikigai_quic::Session) -> Vec<u8> {
        if body.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
            return body;
        }
        // serde_json refuses past its own recursion limit rather than overflowing, so a deep
        // body is an Err here and goes to the layer unchanged, which refuses it by its bound.
        let Ok(serde_json::Value::Object(mut object)) = serde_json::from_slice(&body) else {
            return body;
        };
        if object.contains_key("@context") {
            return body;
        }
        let context = Routed {
            verb: Verb::Source,
            iri: format!("urn:layer:{layer}:context"),
            args: Vec::new(),
            write_layer: None,
        };
        let Ok(repr) = self.issue(&context, session) else {
            return body;
        };
        let Ok(serde_json::Value::Object(mut doc)) = serde_json::from_slice(&repr.bytes) else {
            return body;
        };
        let Some(terms) = doc.remove("@context") else {
            return body;
        };
        let mut with = serde_json::Map::new();
        with.insert("@context".into(), terms);
        with.append(&mut object);
        serde_json::Value::Object(with).to_string().into_bytes()
    }

    /// Answer one request: authenticate, route, resolve.
    fn answer(&self, req: &HttpRequest) -> Response {
        // Authentication first, before anything about the routes is disclosed.
        let session = match self.session(req) {
            Ok(session) => session,
            Err(refused) => return refused,
        };
        let mut routed = match route(req) {
            Ok(routed) => routed,
            Err(answered) => return answered,
        };
        if let Some(layer) = routed.write_layer.clone() {
            if let Some((_, content)) = routed.args.iter_mut().find(|(k, _)| k == "content") {
                *content = self.under_context(&layer, std::mem::take(content), &session);
            }
        }
        match self.issue(&routed, &session) {
            Ok(repr) => {
                let content_type = repr.repr_type.to_string();
                Response::new(200, &content_type, repr.bytes)
            }
            Err(e) => error_response(&e),
        }
        .with_header("Cache-Control", "no-store")
        .with_header("X-Content-Type-Options", "nosniff")
    }
}

/// Serve the front on `listener` with `tls`, on a runtime of its own, until the listener
/// dies. One request per connection, as ikigai-web serves them; a connection past
/// [`EdgeConfig::max_connections`] is answered `503` once TLS is up.
pub fn serve(
    front: Front,
    listener: std::net::TcpListener,
    tls: tokio_rustls::rustls::ServerConfig,
) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("layers-https")
        .build()?;
    runtime.block_on(async move {
        listener.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(listener)?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let front = Arc::new(front);
        let permits = Arc::new(tokio::sync::Semaphore::new(
            front
                .edge
                .max_connections
                .min(tokio::sync::Semaphore::MAX_PERMITS),
        ));
        loop {
            // ikigai-web's accept: only a dead listener ends the front.
            let (sock, peer) = ikigai_web::accept_next(&listener).await?;
            let permit = Arc::clone(&permits).try_acquire_owned().ok();
            let acceptor = acceptor.clone();
            let front = Arc::clone(&front);
            tokio::spawn(async move {
                let admitted = permit.is_some();
                let _ = connection(front, acceptor, sock, peer, admitted).await;
                drop(permit);
            });
        }
    })
}

/// One connection: TLS within the header deadline, one request under ikigai-web's bounds,
/// one answer.
async fn connection(
    front: Arc<Front>,
    acceptor: tokio_rustls::TlsAcceptor,
    sock: tokio::net::TcpStream,
    peer: SocketAddr,
    admitted: bool,
) -> std::io::Result<()> {
    let config = front.edge.clone();
    let mut tls = match tokio::time::timeout(config.header_timeout, acceptor.accept(sock)).await {
        Ok(Ok(tls)) => tls,
        // A failed or slow handshake has no one to answer in HTTP.
        _ => return Ok(()),
    };
    if !admitted {
        return refuse_over_cap(tls, &config).await;
    }
    let Some(req) = ikigai_web::read_request(&mut tls, Some(peer.ip()), &config).await? else {
        return Ok(());
    };
    // A resolution is synchronous and a feed may wait up to a minute, so it runs on the
    // blocking pool, never on a runtime worker.
    let method = req.method.clone();
    let answer = tokio::task::spawn_blocking(move || front.answer(&req))
        .await
        .unwrap_or_else(|_| refusal(500, "endpoint", "the front failed answering this request"));
    // The writer refuses a header it cannot write safely (a content type with a CR or LF from
    // an endpoint, say) and writes nothing; check first, so the client hears a JSON 500 rather
    // than a dropped connection.
    let answer = match answer.check() {
        Ok(()) => answer,
        Err(why) => refusal(500, "endpoint", &why.to_string()),
    };
    ikigai_web::write_answer(&mut tls, &method, answer, &config).await?;
    tls.shutdown().await
}

/// A connection past the cap, once TLS is up: the front's JSON `503` with `Retry-After`,
/// answered by ikigai-web's busy door. It reads the request line first, under the header
/// deadline, so a `HEAD` gets the head alone (ledger #1594: this front used to write its `503`
/// before reading anything, content and all), and then closes lingering so the client reads it.
async fn refuse_over_cap<S: AsyncRead + AsyncWrite + Unpin>(
    sock: S,
    config: &EdgeConfig,
) -> std::io::Result<()> {
    let busy = refusal(503, "unavailable", "too many connections").with_header("Retry-After", "1");
    ikigai_web::refuse_busy(sock, busy, config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, path: &str, query: &[(&str, &str)], body: &[u8]) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            raw_target: path.to_string(),
            query: query
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            headers: Vec::new(),
            body: body.to_vec(),
            peer: None,
        }
    }

    fn arg<'a>(routed: &'a Routed, name: &str) -> Option<&'a str> {
        routed
            .args
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| std::str::from_utf8(v).unwrap())
    }

    /// Ledger #1594: a connection past the cap is answered after its request line is read, so
    /// a `HEAD` hears the `503`'s head alone and a `GET` its JSON. The front used to write the
    /// `503` before reading anything, so a `HEAD` got the content too.
    #[test]
    fn a_busy_answer_to_head_is_the_head_alone() {
        use tokio::io::AsyncReadExt;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            for method in ["HEAD", "GET"] {
                let (mut client, server) = tokio::io::duplex(8192);
                let request = format!("{method} /layers/me HTTP/1.1\r\nHost: h\r\n\r\n");
                client.write_all(request.as_bytes()).await.unwrap();
                client.shutdown().await.unwrap();
                refuse_over_cap(server, &EdgeConfig::default())
                    .await
                    .unwrap();
                let mut out = String::new();
                client.read_to_string(&mut out).await.unwrap();
                assert!(out.starts_with("HTTP/1.1 503 "), "{method}: {out}");
                assert!(out.contains("\r\nRetry-After: 1\r\n"), "{method}: {out}");
                assert!(
                    out.contains(&format!("\r\nContent-Type: {JSON}\r\n")),
                    "{out}"
                );
                let (_, content) = out.split_once("\r\n\r\n").unwrap();
                if method == "HEAD" {
                    assert_eq!(content, "", "a HEAD gets the head alone: {out:?}");
                } else {
                    assert!(content.contains(r#""kind":"unavailable""#), "{out}");
                }
            }
        });
    }

    #[test]
    fn each_participant_verb_routes_to_its_resource_with_its_json_face() {
        let cases = [
            (
                "GET",
                "/layers/me",
                Verb::Source,
                "urn:layers:me",
                Some(JSON),
            ),
            (
                "GET",
                "/layers/feed",
                Verb::Source,
                "urn:layers:feed",
                Some(JSON),
            ),
            (
                "GET",
                "/layer/talk/context",
                Verb::Source,
                "urn:layer:talk:context",
                None,
            ),
            (
                "GET",
                "/layer/talk/entries",
                Verb::Source,
                "urn:layer:talk:entries",
                Some(LD),
            ),
            (
                "GET",
                "/layer/talk/entry/01m4",
                Verb::Source,
                "urn:layer:talk:entry:01m4",
                Some(LD),
            ),
            (
                "GET",
                "/layer/talk/graph/bob",
                Verb::Source,
                "urn:layer:talk:graph:bob",
                Some(LD),
            ),
            (
                "GET",
                "/layer/talk/latest",
                Verb::Source,
                "urn:layer:talk:latest",
                Some(LD),
            ),
            (
                "GET",
                "/layer/talk/feed",
                Verb::Source,
                "urn:layer:talk:feed",
                Some(JSON),
            ),
            (
                "GET",
                "/layer/tasks/rd",
                Verb::Source,
                "urn:layer:tasks:tuples",
                Some(JSON),
            ),
            (
                "GET",
                "/layer/tasks/receipt/9z",
                Verb::Source,
                "urn:layer:tasks:receipt:9z",
                Some(LD),
            ),
            (
                "POST",
                "/layer/talk/say",
                Verb::Sink,
                "urn:layer:talk:say",
                Some(JSON),
            ),
            (
                "POST",
                "/layer/tasks/out",
                Verb::Sink,
                "urn:layer:tasks:tuples",
                Some(JSON),
            ),
            (
                "POST",
                "/layer/tasks/take",
                Verb::Delete,
                "urn:layer:tasks:tuples",
                Some(LD),
            ),
        ];
        for (method, path, verb, iri, face) in cases {
            let routed = route(&req(method, path, &[], b"body")).unwrap();
            assert_eq!((routed.verb, routed.iri.as_str()), (verb, iri), "{path}");
            assert_eq!(arg(&routed, "as"), face, "{path}");
            // Only a write carries the body, and only as `content`.
            assert_eq!(
                arg(&routed, "content").is_some(),
                verb == Verb::Sink,
                "{path}"
            );
        }
        // A write's body is under its own layer's context; nothing else's is.
        let say = route(&req("POST", "/layer/talk/say", &[], b"{}")).unwrap();
        assert_eq!(say.write_layer.as_deref(), Some("talk"));
        let take = route(&req("POST", "/layer/tasks/take", &[], b"")).unwrap();
        assert_eq!(take.write_layer, None);
    }

    #[test]
    fn one_tuple_is_a_graph_and_the_callers_as_wins() {
        let one = route(&req(
            "GET",
            "/layer/tasks/rd",
            &[("tuple", "urn:layer:tasks:o:1")],
            b"",
        ))
        .unwrap();
        assert_eq!(arg(&one, "as"), Some(LD));
        assert_eq!(arg(&one, "tuple"), Some("urn:layer:tasks:o:1"));
        let turtle = route(&req(
            "GET",
            "/layer/talk/entries",
            &[("as", "text/turtle")],
            b"",
        ))
        .unwrap();
        assert_eq!(arg(&turtle, "as"), Some("text/turtle"));
        assert_eq!(turtle.args.iter().filter(|(k, _)| k == "as").count(), 1);
    }

    /// ledger #387: `?after=3&after=9` reached the layer as `after=9`, silently. A repeated
    /// argument is a 400 naming it, in the typed JSON every refusal carries.
    #[test]
    fn a_repeated_query_argument_is_refused_by_name() {
        for (path, query) in [
            ("/layer/talk/entries", [("after", "3"), ("after", "9")]),
            ("/layer/talk/entries", [("as", "text/turtle"), ("as", LD)]),
        ] {
            let refused = route(&req("GET", path, &query, b"")).unwrap_err();
            assert_eq!(refused.status, 400, "{query:?}");
            let body: serde_json::Value = serde_json::from_slice(&refused.body).unwrap();
            assert_eq!(body["kind"], "invalid-argument", "{body}");
            assert_eq!(body["name"], query[0].0, "{body}");
            assert_eq!(
                body["message"],
                format!(
                    "invalid argument `{}`: given twice; an argument takes one value, so name \
                     it once",
                    query[0].0
                ),
                "{body}"
            );
        }
        // A repeat of a name the front drops is not an argument, so it is not refused.
        let routed = route(&req(
            "GET",
            "/layer/talk/entries",
            &[("principal", "a"), ("principal", "b"), ("after", "3")],
            b"",
        ))
        .unwrap();
        assert_eq!(arg(&routed, "after"), Some("3"));
    }

    #[test]
    fn a_caller_cannot_name_its_principal_or_smuggle_content() {
        let routed = route(&req(
            "GET",
            "/layer/talk/entries",
            &[
                ("principal", "urn:collab:participant:mallory"),
                ("content", "x"),
                ("after", "3"),
            ],
            b"",
        ))
        .unwrap();
        assert_eq!(arg(&routed, "principal"), None);
        assert_eq!(arg(&routed, "content"), None);
        assert_eq!(arg(&routed, "after"), Some("3"));
        let say = route(&req(
            "POST",
            "/layer/talk/say",
            &[("content", "query")],
            b"body",
        ))
        .unwrap();
        assert_eq!(arg(&say, "content"), Some("body"));
    }

    #[test]
    fn an_unknown_route_is_404_and_a_wrong_method_is_405() {
        for path in [
            "/",
            "/layers",
            "/layer/talk",
            "/layer/talk/nope",
            "/layer/Talk/entries",
            "/layer/a-name-longer-than-twenty-four/entries",
            "/layer/talk/entry/a%2Fb",
            "/layer/talk/entry/a:b",
            "/other/talk/entries",
        ] {
            let refused = route(&req("GET", path, &[], b"")).unwrap_err();
            assert_eq!(refused.status, 404, "{path}");
            let body: serde_json::Value = serde_json::from_slice(&refused.body).unwrap();
            assert_eq!(body["kind"], "not-found", "{path}");
        }
        for (method, path, allow) in [
            ("GET", "/layer/talk/say", "POST"),
            ("DELETE", "/layer/tasks/take", "POST"),
            ("POST", "/layer/talk/entries", "GET, HEAD"),
            ("PUT", "/layers/me", "GET, HEAD"),
        ] {
            let refused = route(&req(method, path, &[], b"")).unwrap_err();
            assert_eq!(refused.status, 405, "{method} {path}");
            assert!(refused
                .headers
                .contains(&("Allow".to_string(), allow.to_string())));
        }
    }

    #[test]
    fn head_routes_as_get_and_nowhere_else() {
        let me = route(&req("HEAD", "/layers/me", &[], b"")).unwrap();
        assert_eq!((me.verb, me.iri.as_str()), (Verb::Source, "urn:layers:me"));
        let rd = route(&req("HEAD", "/layer/tasks/tuples", &[], b"")).unwrap();
        assert_eq!((rd.verb, arg(&rd, "as")), (Verb::Source, Some(JSON)));
        let say = route(&req("HEAD", "/layer/talk/say", &[], b"")).unwrap_err();
        assert_eq!(say.status, 405);
        assert!(say
            .headers
            .contains(&("Allow".to_string(), "POST".to_string())));
    }

    #[test]
    fn the_tuples_resource_answers_by_its_own_name_too() {
        let rd = route(&req("GET", "/layer/tasks/tuples", &[("after", "2")], b"")).unwrap();
        assert_eq!((rd.verb, arg(&rd, "as")), (Verb::Source, Some(JSON)));
        let out = route(&req("POST", "/layer/tasks/tuples", &[], b"{}")).unwrap();
        assert_eq!(
            (out.verb, out.write_layer.as_deref()),
            (Verb::Sink, Some("tasks"))
        );
        let mut take = req(
            "POST",
            "/layer/tasks/tuples",
            &[("tuple", "urn:layer:tasks:o")],
            b"",
        );
        take.headers = vec![("x-http-method-override".into(), "delete".into())];
        let take = route(&take).unwrap();
        assert_eq!((take.verb, arg(&take, "as")), (Verb::Delete, Some(LD)));
        assert_eq!(arg(&take, "content"), None);
        let mut odd = req("POST", "/layer/tasks/tuples", &[], b"");
        odd.headers = vec![("x-http-method-override".into(), "PUT".into())];
        assert_eq!(route(&odd).unwrap_err().status, 400);
        let put = route(&req("PUT", "/layer/tasks/tuples", &[], b"")).unwrap_err();
        assert_eq!(put.status, 405);
        assert!(put
            .headers
            .contains(&("Allow".to_string(), "GET, HEAD, POST".to_string())));
    }

    #[test]
    fn only_a_bearer_header_presents_a_token() {
        let mut with = req("GET", "/layers/me", &[], b"");
        with.headers = vec![("authorization".into(), "Bearer iklt_abc".into())];
        assert_eq!(bearer(&with), Some("iklt_abc"));
        with.headers = vec![("authorization".into(), "bearer   iklt_abc ".into())];
        assert_eq!(bearer(&with), Some("iklt_abc"));
        for value in ["Basic dXNlcjpwYXNz", "Bearer", "Bearer   ", "iklt_abc"] {
            with.headers = vec![("authorization".into(), value.into())];
            assert_eq!(bearer(&with), None, "{value}");
        }
        assert_eq!(bearer(&req("GET", "/layers/me", &[], b"")), None);
        // A tab separates and pads too; any other whitespace does not (RFC 9110 §11.4).
        with.headers = vec![("authorization".into(), "Bearer\tiklt_abc\t".into())];
        assert_eq!(bearer(&with), Some("iklt_abc"));
        with.headers = vec![("authorization".into(), "Bearer\u{a0}iklt_abc".into())];
        assert_eq!(bearer(&with), None);
    }
}
