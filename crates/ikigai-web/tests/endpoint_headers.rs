//! An endpoint can ask for response headers, and only the ones it may (ledger #117).
//!
//! Before this, a route had no way to set ANY response header: gonk's passkey session
//! cookie was set by page script, so it could not be `HttpOnly`, and no route could say
//! `Cache-Control` or `Vary` either. An endpoint now answers an `HTTP_ENTITY` envelope
//! (`ikigai_web::with_headers`), and the door serves its content with the headers it asked
//! for, checked against a closed allowlist and the door's own list. Every test here fails on
//! a door without the envelope: it served the envelope as opaque bytes, headers and all.
mod common;

use common::{header, headers, send, split, start};
use ikigai_core::{
    Capability, Description, EndpointSpace, Error, Exact, FnEndpoint, Invocation, Kernel, ReprType,
    Representation, UriTemplate, Verb,
};
use ikigai_web::{public_cap, with_headers, CapFn, EdgeConfig, EndpointHeader, HTTP_ENTITY};
use std::sync::Arc;

const COOKIE: &str = "s=abc; Path=/; HttpOnly; SameSite=Strict; Max-Age=60";

fn json(body: &str) -> Representation {
    Representation::new(ReprType::new("application/json"), body.as_bytes().to_vec())
}

/// An envelope written by hand, as an endpoint in another language would, so a test can
/// carry what `with_headers` itself refuses to build.
fn raw_envelope(block: &str, body: &str) -> Representation {
    Representation::new(
        ReprType::new(HTTP_ENTITY),
        format!("{block}\r\n\r\n{body}").into_bytes(),
    )
}

fn kernel() -> Arc<Kernel> {
    // A sign-in: a write that mints a session and sets it as an HttpOnly cookie.
    let login = FnEndpoint::new("login", |_inv: &Invocation<'_>| {
        with_headers(json(r#"{"signed_in":true}"#), &[("Set-Cookie", COOKIE)])
            .map_err(|e| Error::Endpoint(e.to_string()))
    })
    .with_description(Description::new("login").verb(Verb::Sink));
    // A sign-out: an empty answer (204) that clears the cookie.
    let logout = FnEndpoint::new("logout", |_inv: &Invocation<'_>| {
        with_headers(
            Representation::new(ReprType::new("text/plain"), Vec::new()),
            &[("Set-Cookie", "s=; Path=/; HttpOnly; Max-Age=0")],
        )
        .map_err(|e| Error::Endpoint(e.to_string()))
    })
    .with_description(Description::new("logout").verb(Verb::Sink));
    // A read the kernel never caches may set one too; one it may cache may not.
    let fresh = FnEndpoint::new("fresh", |_inv: &Invocation<'_>| {
        with_headers(json("{}"), &[("Set-Cookie", COOKIE)])
            .map_err(|e| Error::Endpoint(e.to_string()))
    })
    .with_description(Description::new("fresh").verb(Verb::Source));
    let cached = FnEndpoint::new("cached", |_inv: &Invocation<'_>| {
        with_headers(json("{}").cacheable(), &[("Set-Cookie", COOKIE)])
            .map_err(|e| Error::Endpoint(e.to_string()))
    })
    .with_description(Description::new("cached").verb(Verb::Source));
    // A download: its own caching, language and file name.
    let asset = FnEndpoint::new("asset", |_inv: &Invocation<'_>| {
        with_headers(
            Representation::new(ReprType::new("text/plain"), b"hello".to_vec()),
            &[
                ("Cache-Control", "public, max-age=3600"),
                ("Vary", "Accept-Language"),
                ("Content-Language", "en"),
                ("Content-Disposition", "attachment; filename=\"hello.txt\""),
            ],
        )
        .map_err(|e| Error::Endpoint(e.to_string()))
    })
    .with_description(Description::new("asset").verb(Verb::Source));
    // A readable, writable document whose read sets a language: a conditional write must
    // compare against the ETag the READ handed out, which is the content's, not the envelope's.
    let doc = FnEndpoint::new("doc", |inv: &Invocation<'_>| {
        if inv.request.verb == Verb::Source {
            with_headers(
                Representation::new(ReprType::new("text/plain"), b"v1".to_vec()),
                &[("Content-Language", "en")],
            )
            .map_err(|e| Error::Endpoint(e.to_string()))
        } else {
            Ok(Representation::new(ReprType::new("text/plain"), Vec::new()))
        }
    })
    .with_description(Description::new("doc").verb(Verb::Source).verb(Verb::Sink));
    // Envelopes no `with_headers` would build, one per way an endpoint can be wrong.
    let raw = FnEndpoint::new("raw", |inv: &Invocation<'_>| {
        let kind = inv.request.target.as_str().rsplit(':').next().unwrap_or("");
        let long = "a".repeat(ikigai_web::MAX_HEADER_VALUE + 1);
        let block = match kind {
            // A CR/LF inside a value starts a line of its own, which is then judged as a
            // header of its own: here a hop-by-hop one.
            "crlf" => {
                "Content-Type: text/plain\r\nVary: Cookie\r\nConnection: keep-alive".to_string()
            }
            // A bare CR (no LF) inside a value.
            "cr" => "Content-Type: text/plain\r\nVary: Cookie\rX-Injected: 1".to_string(),
            "transfer-encoding" => {
                "Content-Type: text/plain\r\nTransfer-Encoding: chunked".to_string()
            }
            "content-length" => "Content-Type: text/plain\r\nContent-Length: 0".to_string(),
            "location" => "Content-Type: text/plain\r\nLocation: https://evil.example/".to_string(),
            "csp" => {
                "Content-Type: text/plain\r\nContent-Security-Policy: default-src *".to_string()
            }
            "oversized" => format!("Content-Type: text/plain\r\nContent-Disposition: {long}"),
            _ => "Content-Type: text/plain".to_string(),
        };
        Ok(raw_envelope(&block, "payload"))
    })
    .with_description(Description::new("raw").verb(Verb::Source));
    let space = EndpointSpace::new()
        .bind(Exact::new("urn:t:login"), login)
        .bind(Exact::new("urn:t:logout"), logout)
        .bind(Exact::new("urn:t:fresh"), fresh)
        .bind(Exact::new("urn:t:cached"), cached)
        .bind(Exact::new("urn:t:asset"), asset)
        .bind(Exact::new("urn:t:doc"), doc)
        .bind(UriTemplate::parse("urn:t:raw:{kind}").unwrap(), raw);
    Arc::new(Kernel::new(Arc::new(space)))
}

/// A door that takes cookies from its endpoints.
fn cookie_door() -> EdgeConfig {
    EdgeConfig {
        endpoint_headers: EndpointHeader::ALL.to_vec(),
        ..EdgeConfig::default()
    }
}

fn post(path: &str) -> Vec<u8> {
    format!("POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{{}}").into_bytes()
}

fn get(path: &str, extra: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: x\r\n{extra}\r\n").into_bytes()
}

#[tokio::test]
async fn a_sign_in_sets_an_httponly_cookie_and_serves_only_the_content() {
    let addr = start(kernel(), cookie_door(), public_cap()).await;
    let resp = send(addr, &post("/t/login")).await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    assert_eq!(header(&resp, "set-cookie"), Some(COOKIE), "{resp}");
    assert_eq!(
        header(&resp, "content-type"),
        Some("application/json"),
        "{resp}"
    );
    assert_eq!(split(&resp).1, r#"{"signed_in":true}"#);
}

#[tokio::test]
async fn a_sign_out_clears_the_cookie_on_an_empty_answer() {
    let addr = start(kernel(), cookie_door(), public_cap()).await;
    let resp = send(addr, &post("/t/logout")).await;
    assert!(resp.starts_with("HTTP/1.1 204 No Content"), "{resp}");
    assert_eq!(
        header(&resp, "set-cookie"),
        Some("s=; Path=/; HttpOnly; Max-Age=0"),
        "{resp}"
    );
    assert_eq!(
        header(&resp, "content-type"),
        None,
        "a 204 carries no content: {resp}"
    );
}

#[tokio::test]
async fn a_door_that_did_not_opt_in_refuses_a_cookie_by_name() {
    let addr = start(kernel(), EdgeConfig::default(), public_cap()).await;
    let resp = send(addr, &post("/t/login")).await;
    assert!(
        resp.starts_with("HTTP/1.1 500 Internal Server Error"),
        "{resp}"
    );
    assert!(headers(&resp, "set-cookie").is_empty(), "{resp}");
    let body = split(&resp).1;
    assert!(
        body.contains("`Set-Cookie`") && body.contains("endpoint_headers"),
        "{body}"
    );
    assert!(
        !body.contains("signed_in"),
        "nothing of the refused answer leaks: {body}"
    );
}

#[tokio::test]
async fn a_cookie_rides_an_uncacheable_read_and_never_a_cacheable_one() {
    let addr = start(kernel(), cookie_door(), public_cap()).await;
    let fresh = send(addr, &get("/t/fresh", "")).await;
    assert!(fresh.starts_with("HTTP/1.1 200 OK"), "{fresh}");
    assert_eq!(header(&fresh, "set-cookie"), Some(COOKIE), "{fresh}");
    let cached = send(addr, &get("/t/cached", "")).await;
    assert!(cached.starts_with("HTTP/1.1 500"), "{cached}");
    assert!(headers(&cached, "set-cookie").is_empty(), "{cached}");
    assert!(split(&cached).1.contains("cacheable"), "{cached}");
}

#[tokio::test]
async fn an_endpoint_sets_its_caching_language_and_file_name() {
    let addr = start(kernel(), EdgeConfig::default(), public_cap()).await;
    let resp = send(addr, &get("/t/asset", "")).await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    // REPLACES the door's projection (which for this uncacheable answer is `no-store`).
    assert_eq!(
        header(&resp, "cache-control"),
        Some("public, max-age=3600"),
        "{resp}"
    );
    // ADDED to the names the door varies on (here the credential headers), not replacing them.
    let vary = header(&resp, "vary").unwrap_or_default();
    assert!(
        vary.contains("Accept-Language") && vary.contains("Cookie"),
        "{resp}"
    );
    assert_eq!(header(&resp, "content-language"), Some("en"), "{resp}");
    assert_eq!(
        header(&resp, "content-disposition"),
        Some("attachment; filename=\"hello.txt\""),
        "{resp}"
    );
    assert_eq!(header(&resp, "content-type"), Some("text/plain"), "{resp}");
    assert_eq!(split(&resp).1, "hello");
}

#[tokio::test]
async fn an_answer_the_credentials_shaped_is_private_whatever_the_endpoint_says() {
    // A capability function that grants more to a caller carrying a cookie: the answer that
    // caller gets is theirs, and only the door can see that.
    let cap_fn: CapFn = Arc::new(|req: &ikigai_web::HttpRequest| {
        if req.header("cookie").is_some() {
            Capability::scoped(vec!["urn:cap:t:member".to_string()])
        } else {
            Capability::scoped(Vec::<String>::new())
        }
    });
    let addr = start(kernel(), EdgeConfig::default(), cap_fn).await;
    let anonymous = send(addr, &get("/t/asset", "")).await;
    assert_eq!(
        header(&anonymous, "cache-control"),
        Some("public, max-age=3600")
    );
    let member = send(addr, &get("/t/asset", "Cookie: s=abc\r\n")).await;
    assert_eq!(
        header(&member, "cache-control"),
        Some("private, max-age=3600"),
        "{member}"
    );
}

#[tokio::test]
async fn private_no_store_overrides_endpoint_caching_on_get_head_and_304() {
    let addr = start(
        kernel(),
        EdgeConfig {
            private_no_store: true,
            principal_fn: Some(Arc::new(|_| Some("urn:test:alice".into()))),
            ..EdgeConfig::default()
        },
        public_cap(),
    )
    .await;
    let first = send(addr, &get("/t/asset", "")).await;
    let tag = header(&first, "etag").unwrap();
    let again = send(addr, &get("/t/asset", &format!("If-None-Match: {tag}\r\n"))).await;
    assert!(again.starts_with("HTTP/1.1 304 "), "{again}");
    let head = send(addr, b"HEAD /t/asset HTTP/1.1\r\nHost: x\r\n\r\n").await;
    for answer in [&first, &again, &head] {
        assert_eq!(headers(answer, "cache-control"), vec!["private, no-store"]);
        assert_eq!(header(answer, "etag"), Some(tag));
    }
    assert!(split(&again).1.is_empty());
    assert!(split(&head).1.is_empty());
}

#[tokio::test]
async fn a_304_repeats_caching_and_vary_but_no_content_metadata() {
    let addr = start(kernel(), EdgeConfig::default(), public_cap()).await;
    let first = send(addr, &get("/t/asset", "")).await;
    let etag = header(&first, "etag").unwrap().to_string();
    let again = send(
        addr,
        &get("/t/asset", &format!("If-None-Match: {etag}\r\n")),
    )
    .await;
    assert!(again.starts_with("HTTP/1.1 304 Not Modified"), "{again}");
    assert_eq!(
        header(&again, "cache-control"),
        Some("public, max-age=3600"),
        "{again}"
    );
    assert!(header(&again, "vary")
        .unwrap_or_default()
        .contains("Accept-Language"));
    assert_eq!(header(&again, "content-language"), None, "{again}");
    assert_eq!(header(&again, "content-disposition"), None, "{again}");
}

#[tokio::test]
async fn a_conditional_write_compares_against_the_etag_a_read_handed_out() {
    let addr = start(kernel(), EdgeConfig::default(), public_cap()).await;
    let read = send(addr, &get("/t/doc", "")).await;
    assert_eq!(
        split(&read).1,
        "v1",
        "the read serves the content alone: {read}"
    );
    let etag = header(&read, "etag").unwrap();
    let raw = format!(
        "PUT /t/doc HTTP/1.1\r\nHost: x\r\nIf-Match: {etag}\r\nContent-Length: 2\r\n\r\nv2"
    );
    let write = send(addr, raw.as_bytes()).await;
    assert!(write.starts_with("HTTP/1.1 204"), "{write}");
}

/// The security half: what an endpoint may NOT do. Each is refused with `500` naming the
/// header, and none of the asked-for header lines reaches the client.
#[tokio::test]
async fn header_injection_and_door_owned_headers_are_refused_by_name() {
    let addr = start(kernel(), cookie_door(), public_cap()).await;
    for (kind, named) in [
        ("crlf", "Connection"),
        ("cr", "Vary"),
        ("transfer-encoding", "Transfer-Encoding"),
        ("content-length", "Content-Length"),
        ("location", "Location"),
        ("csp", "Content-Security-Policy"),
        ("oversized", "Content-Disposition"),
    ] {
        let resp = send(addr, &get(&format!("/t/raw/{kind}"), "")).await;
        assert!(resp.starts_with("HTTP/1.1 500"), "{kind}: {resp}");
        let (head, body) = split(&resp);
        assert!(body.contains(&format!("`{named}`")), "{kind}: {body}");
        assert!(
            !body.contains("payload"),
            "{kind}: the content is not served: {body}"
        );
        for line in &head {
            assert!(
                !line.starts_with("X-Injected")
                    && !line.starts_with("Location")
                    && !line.starts_with("Transfer-Encoding")
                    && *line != "Connection: keep-alive"
                    && *line != "Content-Length: 0"
                    && !line.contains("default-src *"),
                "{kind}: an asked-for line reached the head: {resp}"
            );
        }
        assert_eq!(header(&resp, "content-disposition"), None, "{kind}: {resp}");
    }
    // The plain envelope behind those cases is served, so each refusal is the header's.
    let fine = send(addr, &get("/t/raw/fine", "")).await;
    assert!(
        fine.starts_with("HTTP/1.1 200") && fine.ends_with("payload"),
        "{fine}"
    );
}
