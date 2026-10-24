//! A HEAD is answered with a head and no content on EVERY path, refusals included (ledger
//! #117, folding in the half of cli PR #335 that #508 did not reach).
//!
//! #508 made the answers built by the adapter's main path HEAD-safe. The refusals written on
//! paths of their own still sent their sentence to a HEAD: the admission refusal, the push
//! stream's, every framing refusal `read_request` makes, and the busy door's `503`. One test
//! per path; each sends a HEAD and asserts the status it expects and an empty body. Each but
//! the two noted below failed before the fix by carrying the sentence as content.
mod common;

use common::{send, split, start};
use ikigai_core::{
    Description, EndpointSpace, Exact, FnEndpoint, Kernel, ReprType, Representation, Verb,
};
use ikigai_web::{public_cap, AdmitFn, EdgeConfig, HttpRequest, PushConfig, Refusal};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn kernel() -> Arc<Kernel> {
    let page = FnEndpoint::new("page", |_inv: &ikigai_core::Invocation<'_>| {
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"hello".to_vec(),
        ))
    })
    .with_description(Description::new("page").verb(Verb::Source));
    Arc::new(Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:t:page"), page),
    )))
}

/// The status line of `resp`, and that it carries no content.
fn assert_bodiless(resp: &str, status: &str) {
    assert!(resp.starts_with(&format!("HTTP/1.1 {status}")), "{resp}");
    let (head, body) = split(resp);
    assert!(
        body.is_empty(),
        "HEAD must carry no content, got {body:?} in: {resp}"
    );
    // The head names the length GET would carry (RFC 9110 §9.3.2), not zero.
    assert!(
        head.iter().any(|l| l.starts_with("Content-Length: ")),
        "{resp}"
    );
}

async fn door(config: EdgeConfig) -> std::net::SocketAddr {
    start(kernel(), config, public_cap()).await
}

#[tokio::test]
async fn an_admission_refusal() {
    let admit: AdmitFn = Arc::new(|_req: &HttpRequest| {
        Some(Refusal {
            status: 421,
            reason: "this server answers only to localhost".to_string(),
        })
    });
    let addr = door(EdgeConfig {
        admit_fn: Some(admit),
        ..EdgeConfig::default()
    })
    .await;
    let resp = send(addr, b"HEAD /t/page HTTP/1.1\r\nHost: evil\r\n\r\n").await;
    assert_bodiless(&resp, "421");
    assert!(resp.contains(&format!(
        "Content-Length: {}",
        "this server answers only to localhost".len()
    )));
}

#[tokio::test]
async fn the_push_streams_method_refusal() {
    let addr = door(EdgeConfig {
        push: Some(PushConfig::default()),
        ..EdgeConfig::default()
    })
    .await;
    let raw = format!(
        "HEAD {} HTTP/1.1\r\nHost: x\r\n\r\n",
        ikigai_web::DEFAULT_PUSH_PATH
    );
    assert_bodiless(&send(addr, raw.as_bytes()).await, "405");
}

#[tokio::test]
async fn an_unreadable_request_target() {
    // `%zz` cannot be decoded: `parse_head` refuses the whole head, so the method is read off
    // the raw request line.
    let addr = door(EdgeConfig::default()).await;
    assert_bodiless(
        &send(addr, b"HEAD /t/%zz HTTP/1.1\r\nHost: x\r\n\r\n").await,
        "400",
    );
}

#[tokio::test]
async fn a_transfer_coding() {
    let addr = door(EdgeConfig::default()).await;
    let raw = b"HEAD /t/page HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert_bodiless(&send(addr, raw).await, "501");
}

#[tokio::test]
async fn a_malformed_content_length() {
    let addr = door(EdgeConfig::default()).await;
    let raw = b"HEAD /t/page HTTP/1.1\r\nHost: x\r\nContent-Length: ten\r\n\r\n";
    assert_bodiless(&send(addr, raw).await, "400");
}

#[tokio::test]
async fn a_declared_length_over_the_bound() {
    let addr = door(EdgeConfig {
        max_body_bytes: 4,
        ..EdgeConfig::default()
    })
    .await;
    let raw = b"HEAD /t/page HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n";
    assert_bodiless(&send(addr, raw).await, "413");
}

#[tokio::test]
async fn bytes_past_the_bound_behind_the_head() {
    // The declared length is within the bound; what already arrived behind the head is not.
    let addr = door(EdgeConfig {
        max_body_bytes: 1,
        ..EdgeConfig::default()
    })
    .await;
    let raw = b"HEAD /t/page HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nabc";
    assert_bodiless(&send(addr, raw).await, "413");
}

#[tokio::test]
async fn a_body_that_never_arrives() {
    let addr = door(EdgeConfig {
        body_timeout: Duration::from_millis(200),
        ..EdgeConfig::default()
    })
    .await;
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    c.write_all(b"HEAD /t/page HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).await.unwrap();
    assert_bodiless(&String::from_utf8_lossy(&out), "408");
}

#[tokio::test]
async fn a_body_cut_short() {
    let addr = door(EdgeConfig::default()).await;
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    c.write_all(b"HEAD /t/page HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nab")
        .await
        .unwrap();
    c.shutdown().await.unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).await.unwrap();
    assert_bodiless(&String::from_utf8_lossy(&out), "400");
}

#[tokio::test]
async fn headers_that_never_end() {
    let addr = door(EdgeConfig {
        header_timeout: Duration::from_millis(200),
        ..EdgeConfig::default()
    })
    .await;
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    c.write_all(b"HEAD /t/page HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).await.unwrap();
    assert_bodiless(&String::from_utf8_lossy(&out), "408");
}

/// A pin, not a fix: the `431` has always had an empty sentence, so it never carried content.
/// It is here so the path is covered if it ever gains one. Driven through `read_request` over
/// an in-memory pipe rather than TCP: the refusal leaves the oversized head unread, and a
/// socket closed with unread bytes sends a reset that can destroy the answer before it is read.
#[tokio::test]
async fn headers_over_the_bound() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let writer = tokio::spawn(async move {
        let mut raw = b"HEAD /t/page HTTP/1.1\r\nHost: x\r\nX-Big: ".to_vec();
        raw.extend(std::iter::repeat_n(b'a', 70 * 1024));
        raw.extend_from_slice(b"\r\n\r\n");
        // The door stops reading at its bound; the rest of this write fails once it is gone.
        let _ = client.write_all(&raw).await;
        let mut out = Vec::new();
        let _ = client.read_to_end(&mut out).await;
        out
    });
    let config = EdgeConfig::default();
    let req = ikigai_web::read_request(&mut server, None, &config)
        .await
        .unwrap();
    assert!(req.is_none(), "refused, so no request is handed on");
    drop(server);
    let out = writer.await.unwrap();
    assert_bodiless(&String::from_utf8_lossy(&out), "431");
}

#[tokio::test]
async fn the_busy_doors_503() {
    let addr = door(EdgeConfig {
        max_connections: 0,
        ..EdgeConfig::default()
    })
    .await;
    let resp = send(addr, b"HEAD /t/page HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_bodiless(&resp, "503");
    // And a GET there still gets the sentence.
    let get = send(addr, b"GET /t/page HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(
        get.starts_with("HTTP/1.1 503") && get.ends_with("too many connections"),
        "{get}"
    );
}

/// A pin, not a fix: #508 already made the adapter's own refusals HEAD-safe. Every one of them,
/// so a later path that skips `finish` is caught here.
#[tokio::test]
async fn the_adapters_own_refusals() {
    let routes = ikigai_web::RouteTable::new(vec![ikigai_web::Route {
        pattern: "/u/{name}".to_string(),
        iri_template: "urn:t:{name}".to_string(),
        redirect: None,
        cap: None,
        cors: None,
        csp: None,
    }]);
    let addr = door(EdgeConfig {
        routes,
        ..EdgeConfig::default()
    })
    .await;
    for (path, status) in [
        ("/t/nowhere", "404"),
        ("/u/a:b", "400"),
        ("/t/nowhere?description", "404"),
    ] {
        let raw = format!("HEAD {path} HTTP/1.1\r\nHost: x\r\nAccept: text/html\r\n\r\n");
        assert_bodiless(&send(addr, raw.as_bytes()).await, status);
    }
}
