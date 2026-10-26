//! What the door gained by moving onto hyper (ledger #2236), and the bounds it kept: keep-alive
//! for a client that asks for it, a chunked request body under the same bound, the header
//! deadline on a slow client and on an idle kept connection, and a malformed request answered
//! by hyper without taking the door down.
mod common;

use common::{send, split, start};
use ikigai_core::{
    Description, EndpointSpace, Exact, FnEndpoint, Invocation, Kernel, ReprType, Representation,
    Verb,
};
use ikigai_web::{public_cap, EdgeConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A page to read, and a sink that answers with the content it was handed.
fn kernel() -> Arc<Kernel> {
    let page = FnEndpoint::new("page", |_inv: &Invocation<'_>| {
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"hello".to_vec(),
        ))
    })
    .with_description(Description::new("page").verb(Verb::Source));
    let echo = FnEndpoint::new("echo", |inv: &Invocation<'_>| {
        let content = inv.inline_arg("content").unwrap_or(b"");
        Ok(Representation::new(
            ReprType::new("text/plain"),
            content.to_vec(),
        ))
    })
    .with_description(Description::new("echo").verb(Verb::Sink));
    Arc::new(Kernel::new(Arc::new(
        EndpointSpace::new()
            .bind(Exact::new("urn:t:page"), page)
            .bind(Exact::new("urn:t:echo"), echo),
    )))
}

async fn door(config: EdgeConfig) -> SocketAddr {
    start(kernel(), config, public_cap()).await
}

fn short(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

/// Read one whole answer framed by `Content-Length` off `sock`, leaving the connection open.
async fn read_answer(sock: &mut TcpStream) -> String {
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end]).into_owned();
            let length = head
                .lines()
                .find_map(|l| {
                    l.split_once(':')
                        .filter(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                        .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if seen.len() >= end + 4 + length {
                return String::from_utf8_lossy(&seen[..end + 4 + length]).into_owned();
            }
        }
        let n = tokio::time::timeout(Duration::from_secs(10), sock.read(&mut buf))
            .await
            .expect("the door went quiet")
            .unwrap();
        assert!(
            n > 0,
            "the door closed early: {:?}",
            String::from_utf8_lossy(&seen)
        );
        seen.extend_from_slice(&buf[..n]);
    }
}

/// Read until the door hangs up, within ten seconds, or fail.
async fn until_closed(sock: &mut TcpStream) -> String {
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), sock.read_to_end(&mut out))
        .await
        .expect("the door must hang up")
        .unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn two_requests_ride_one_kept_connection() {
    let addr = door(EdgeConfig::default()).await;
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"GET /t/page HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
        .await
        .unwrap();
    let first = read_answer(&mut sock).await;
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"), "{first}");
    assert!(first.ends_with("\r\n\r\nhello"), "{first}");
    assert!(!first.contains("Connection: close"), "kept: {first}");
    // The second request on the same socket asks to close, and is the last.
    sock.write_all(
        b"PUT /t/echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\nagain",
    )
    .await
    .unwrap();
    let second = until_closed(&mut sock).await;
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"), "{second}");
    assert!(second.contains("\r\nConnection: close\r\n"), "{second}");
    assert!(second.ends_with("\r\n\r\nagain"), "{second}");
}

#[tokio::test]
async fn a_client_that_does_not_ask_is_answered_once_and_closed() {
    let addr = door(EdgeConfig::default()).await;
    let resp = send(addr, b"GET /t/page HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
    assert!(resp.contains("\r\nConnection: close\r\n"), "{resp}");
}

#[tokio::test]
async fn a_kept_connection_that_idles_is_closed_without_an_answer() {
    let addr = door(EdgeConfig {
        header_timeout: short(300),
        ..EdgeConfig::default()
    })
    .await;
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"GET /t/page HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
        .await
        .unwrap();
    let first = read_answer(&mut sock).await;
    assert!(first.starts_with("HTTP/1.1 200 "), "{first}");
    // No second request: the idle limit closes the connection, and no request is owed a 408.
    let rest = until_closed(&mut sock).await;
    assert_eq!(rest, "", "an idle connection is closed in silence");
}

#[tokio::test]
async fn a_slow_second_request_on_a_kept_connection_is_cut_off_with_408() {
    let addr = door(EdgeConfig {
        header_timeout: short(300),
        ..EdgeConfig::default()
    })
    .await;
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"GET /t/page HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
        .await
        .unwrap();
    read_answer(&mut sock).await;
    let (mut rx, mut tx) = sock.into_split();
    // A slow-loris on the kept connection: a byte every 50 ms, never the blank line.
    let trickle = tokio::spawn(async move {
        let _ = tx.write_all(b"HEAD /t/page HTTP/1.1\r\n").await;
        for _ in 0..400 {
            if tx.write_all(b"X").await.is_err() {
                break;
            }
            tokio::time::sleep(short(50)).await;
        }
    });
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), rx.read_to_end(&mut out))
        .await
        .expect("the deadline must cut the trickle off")
        .unwrap();
    let resp = String::from_utf8_lossy(&out).into_owned();
    assert!(
        resp.starts_with("HTTP/1.1 408 Request Timeout\r\n"),
        "{resp}"
    );
    // It began `HEAD`, so the 408 is the head alone.
    assert_eq!(split(&resp).1, "", "{resp}");
    trickle.abort();
}

#[tokio::test]
async fn a_chunked_body_under_the_bound_is_delivered_whole() {
    let addr = door(EdgeConfig {
        max_body_bytes: 10,
        ..EdgeConfig::default()
    })
    .await;
    let raw = b"PUT /t/echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n\
                4\r\nchun\r\n6\r\nked ok\r\n0\r\n\r\n";
    let resp = send(addr, raw).await;
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
    assert!(resp.ends_with("\r\n\r\nchunked ok"), "{resp}");
}

#[tokio::test]
async fn a_chunked_body_past_the_bound_is_413_and_never_reaches_the_endpoint() {
    let addr = door(EdgeConfig {
        max_body_bytes: 8,
        ..EdgeConfig::default()
    })
    .await;
    // Nine bytes in two chunks: the bound is crossed inside the second.
    let raw = b"PUT /t/echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n\
                5\r\nfirst\r\n4\r\nmore\r\n0\r\n\r\n";
    let resp = send(addr, raw).await;
    assert!(
        resp.starts_with("HTTP/1.1 413 Payload Too Large\r\n"),
        "{resp}"
    );
    assert!(resp.contains("\r\nConnection: close\r\n"), "{resp}");
    assert!(!resp.contains("first"), "nothing was handed on: {resp}");
}

#[tokio::test]
async fn a_chunked_body_that_never_ends_is_408_at_the_body_deadline() {
    let addr = door(EdgeConfig {
        body_timeout: short(300),
        ..EdgeConfig::default()
    })
    .await;
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(
        b"PUT /t/echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
    )
    .await
    .unwrap();
    let resp = until_closed(&mut sock).await;
    assert!(
        resp.starts_with("HTTP/1.1 408 Request Timeout\r\n"),
        "{resp}"
    );
}

#[tokio::test]
async fn a_malformed_request_line_is_refused_and_the_door_stays_up() {
    let addr = door(EdgeConfig::default()).await;
    for raw in [
        &b"GARBAGE\r\n\r\n"[..],
        b"GET /t/page HTTP/9.9\r\nHost: x\r\n\r\n",
        b"GET /t/page HTTP/1.1\r\nBad Header Line\r\n\r\n",
        b"\x00\x01\x02 / HTTP/1.1\r\n\r\n",
    ] {
        let resp = send(addr, raw).await;
        // hyper answers `400` (or `505` for a version it does not speak), or closes; either way
        // no request reached the door.
        assert!(
            resp.is_empty() || resp.starts_with("HTTP/1.1 4") || resp.starts_with("HTTP/1.1 5"),
            "{raw:?}: {resp}"
        );
        assert!(!resp.contains("hello"), "{raw:?}: {resp}");
    }
    let alive = send(addr, b"GET /t/page HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(alive.starts_with("HTTP/1.1 200 OK\r\n"), "{alive}");
}

/// The head bound holds as the hand-written reader held it. hyper's own read-buffer limit let a
/// 70 KiB head through when it arrived in one read (the first run of this test answered `200`),
/// so the door counts the head itself.
#[tokio::test]
async fn an_oversized_head_is_431() {
    let addr = door(EdgeConfig::default()).await;
    let mut sock = TcpStream::connect(addr).await.unwrap();
    let mut raw = b"GET /t/page HTTP/1.1\r\nHost: x\r\nX-Big: ".to_vec();
    raw.extend(std::iter::repeat_n(b'a', 70 * 1024));
    raw.extend_from_slice(b"\r\n\r\n");
    // The door stops reading at its bound, so the tail of this write may fail.
    let _ = sock.write_all(&raw).await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), sock.read_to_end(&mut out)).await;
    let resp = String::from_utf8_lossy(&out);
    // A reset can destroy the answer (unread bytes at close), so the status is checked only
    // when it arrived; what must never happen is a 200.
    assert!(
        resp.is_empty() || resp.starts_with("HTTP/1.1 431 "),
        "{resp}"
    );
}
