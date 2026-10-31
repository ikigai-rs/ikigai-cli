//! A browser asking for a page gets an error as a page (ledger #117).
//!
//! Every error body was `text/plain`, so a person who followed a dead link saw a bare
//! sentence. A client that NAMES `text/html` over `text/plain` now gets a minimal, accessible
//! page carrying the same sentence, escaped; every other client gets the sentence as before,
//! and both answers say `Vary: Accept`. Each test but the last two (pins of what does NOT
//! change) failed before the fix.
mod common;

use common::{header, send, split, start};
use ikigai_core::{
    ActionSpec, Description, EndpointSpace, Error, Exact, FnEndpoint, Invocation, Kernel, ReprType,
    Representation, Verb,
};
use ikigai_web::{public_cap, AdmitFn, EdgeConfig, ErrorBody, HttpRequest, Refusal};
use std::sync::Arc;

const BROWSER: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

fn kernel() -> Arc<Kernel> {
    let hostile = FnEndpoint::new("hostile", |_inv: &Invocation<'_>| {
        Err(Error::NotFound("<script>alert('x')</script> & co".into()))
    })
    .with_description(Description::new("hostile").verb(Verb::Source));
    let json_only = FnEndpoint::new("json", |_inv: &Invocation<'_>| {
        Ok(Representation::new(
            ReprType::new("application/json"),
            b"{}".to_vec(),
        ))
    })
    .with_description(
        Description::new("json").action(ActionSpec::new(Verb::Source).output("application/json")),
    );
    Arc::new(Kernel::new(Arc::new(
        EndpointSpace::new()
            .bind(Exact::new("urn:t:hostile"), hostile)
            .bind(Exact::new("urn:t:json"), json_only),
    )))
}

fn get(path: &str, accept: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: x\r\nAccept: {accept}\r\n\r\n").into_bytes()
}

fn assert_page(resp: &str, status: &str) {
    assert!(resp.starts_with(&format!("HTTP/1.1 {status}")), "{resp}");
    assert_eq!(
        header(resp, "content-type"),
        Some("text/html; charset=utf-8"),
        "{resp}"
    );
    assert!(
        header(resp, "vary").unwrap_or_default().contains("Accept"),
        "{resp}"
    );
    let body = split(resp).1;
    assert!(body.starts_with("<!DOCTYPE html>"), "{body}");
    assert!(body.contains("<html lang=\"en\">"), "{body}");
    assert!(body.contains(&format!("<title>{status}")), "{body}");
    assert!(body.contains(&format!("<main><h1>{status}")), "{body}");
}

#[tokio::test]
async fn a_browser_gets_a_404_as_a_page() {
    let addr = start(kernel(), EdgeConfig::default(), public_cap()).await;
    let resp = send(addr, &get("/t/nowhere", BROWSER)).await;
    assert_page(&resp, "404 Not Found");
}

#[tokio::test]
async fn the_message_is_escaped() {
    let addr = start(kernel(), EdgeConfig::default(), public_cap()).await;
    let resp = send(addr, &get("/t/hostile", BROWSER)).await;
    assert_page(&resp, "404 Not Found");
    let body = split(&resp).1;
    assert!(!body.contains("<script>"), "{body}");
    assert!(
        body.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; co"),
        "{body}"
    );
}

#[tokio::test]
async fn a_406_is_a_page_for_a_client_naming_html() {
    let addr = start(kernel(), EdgeConfig::default(), public_cap()).await;
    let resp = send(addr, &get("/t/json", "text/html")).await;
    assert_page(&resp, "406 Not Acceptable");
    assert!(split(&resp).1.contains("application/json"), "{resp}");
}

#[tokio::test]
async fn an_admission_refusal_is_a_page_too() {
    let admit: AdmitFn = Arc::new(|_req: &HttpRequest| {
        Some(Refusal {
            status: 421,
            reason: "this server answers only to localhost".to_string(),
        })
    });
    let config = EdgeConfig {
        admit_fn: Some(admit),
        ..EdgeConfig::default()
    };
    let addr = start(kernel(), config, public_cap()).await;
    let resp = send(addr, &get("/t/hostile", BROWSER)).await;
    assert_page(&resp, "421 Misdirected Request");
}

#[tokio::test]
async fn any_other_client_gets_the_sentence_and_the_vary() {
    let addr = start(kernel(), EdgeConfig::default(), public_cap()).await;
    for accept in ["*/*", "application/json", "text/plain, text/html"] {
        let resp = send(addr, &get("/t/nowhere", accept)).await;
        assert!(resp.starts_with("HTTP/1.1 404"), "{accept}: {resp}");
        assert_eq!(
            header(&resp, "content-type"),
            Some("text/plain; charset=utf-8"),
            "{accept}: {resp}"
        );
        assert!(
            header(&resp, "vary").unwrap_or_default().contains("Accept"),
            "{resp}"
        );
    }
}

/// A pin: a door that chose JSON error bodies keeps them, browser or not.
#[tokio::test]
async fn a_json_door_keeps_json() {
    let config = EdgeConfig {
        error_body: ErrorBody::Json,
        ..EdgeConfig::default()
    };
    let addr = start(kernel(), config, public_cap()).await;
    let resp = send(addr, &get("/t/hostile", BROWSER)).await;
    assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");
    assert_eq!(
        header(&resp, "content-type"),
        Some("application/json"),
        "{resp}"
    );
}

/// A pin: a success is never touched.
#[tokio::test]
async fn a_success_is_not_a_page() {
    let addr = start(kernel(), EdgeConfig::default(), public_cap()).await;
    let resp = send(addr, &get("/t/json", BROWSER)).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert_eq!(split(&resp).1, "{}");
}

/// Intake refuses before admission or authentication, for declared and streamed lengths.
#[tokio::test]
async fn an_ordinary_oversize_body_negotiates_a_page_before_admission() {
    let config = EdgeConfig {
        max_body_bytes: 3,
        admit_fn: Some(Arc::new(|_| panic!("oversize intake reached admission"))),
        principal_fn: Some(Arc::new(|_| panic!("oversize intake reached identity"))),
        error_page: Some(Arc::new(|_, _| panic!("oversize intake reached host page"))),
        ..EdgeConfig::default()
    };
    let addr = start(
        kernel(),
        config,
        Arc::new(|_| panic!("oversize intake reached capability")),
    )
    .await;
    for framing in [
        "Content-Length: 4\r\nExpect: 100-continue\r\n\r\n",
        "Transfer-Encoding: chunked\r\n\r\n2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n",
    ] {
        for accept in [BROWSER, "text/plain", "*/*"] {
            let mut content_length = None;
            for method in ["PUT", "HEAD"] {
                let request = format!("{method} /t/hostile HTTP/1.1\r\nHost: x\r\nAccept: {accept}\r\nSec-Fetch-Mode: navigate\r\nAuthorization: Bearer ignored\r\nCookie: session=ignored\r\n{framing}");
                let resp = send(addr, request.as_bytes()).await;
                assert!(resp.starts_with("HTTP/1.1 413 Payload Too Large"), "{resp}");
                assert_eq!(header(&resp, "x-content-type-options"), Some("nosniff"));
                assert!(header(&resp, "content-security-policy").is_some(), "{resp}");
                assert_eq!(header(&resp, "connection"), Some("close"));
                assert!(header(&resp, "vary").unwrap_or_default().contains("Accept"));
                if method == "HEAD" {
                    assert!(split(&resp).1.is_empty(), "{resp}");
                    assert_eq!(header(&resp, "content-length"), content_length.as_deref());
                } else {
                    content_length = header(&resp, "content-length").map(str::to_owned);
                    if accept == BROWSER {
                        assert_page(&resp, "413 Payload Too Large");
                        assert!(
                            split(&resp).1.contains(
                                "request body too large: this route takes at most 3 bytes"
                            ),
                            "{resp}"
                        );
                    } else {
                        assert_eq!(
                            header(&resp, "content-type"),
                            Some("text/plain; charset=utf-8")
                        );
                        assert_eq!(
                            split(&resp).1,
                            "request body too large: this route takes at most 3 bytes"
                        );
                    }
                }
            }
        }
    }
}
