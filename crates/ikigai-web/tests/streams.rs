//! The door streams answers (ledger #2244): written as they are read, and ranges over a
//! seekable body with a strong validator. Uploads are `uploads.rs`. Every test goes through the
//! real door (hyper, a real socket).
mod common;

use async_trait::async_trait;
use common::{header, send, split};
use ikigai_core::{
    Body, ByteStream, Bytes, ContentId, Description, Endpoint, EndpointSpace, Exact, Invocation,
    Kernel, Replay, ReprType, Representation, Verb,
};
use ikigai_web::{public_cap, EdgeConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// `TEXT`, as a seekable body that knows its length and its content id: what a spill answers.
const TEXT: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

struct Seekable;

impl Replay for Seekable {
    fn open(&self) -> ByteStream {
        self.open_at(0).expect("seekable")
    }
    fn open_at(&self, offset: u64) -> Option<ByteStream> {
        // In chunks of five, so a range crosses chunk boundaries.
        let rest = &TEXT[(offset as usize).min(TEXT.len())..];
        let chunks: Vec<_> = rest
            .chunks(5)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        Some(Box::pin(futures::stream::iter(chunks)))
    }
    fn len_hint(&self) -> Option<u64> {
        Some(TEXT.len() as u64)
    }
    fn validator(&self) -> Option<ContentId> {
        Some(ContentId::of(TEXT))
    }
}

/// The bodies the door is asked to serve, by IRI.
struct Bodies;

#[async_trait]
impl Endpoint for Bodies {
    async fn invoke(&self, inv: &Invocation<'_>) -> ikigai_core::Result<Representation> {
        let body = self.invoke_body(inv).await?;
        body.collect(1 << 20).await
    }

    async fn invoke_body(&self, inv: &Invocation<'_>) -> ikigai_core::Result<Representation<Body>> {
        let chunks =
            |parts: Vec<ikigai_core::Result<Bytes>>| Body::once(futures::stream::iter(parts));
        let body = match inv.request.target.as_str() {
            "urn:t:seekable" => Body::replay(Seekable),
            "urn:t:once" => chunks(vec![
                Ok(Bytes::from_static(b"first ")),
                Ok(Bytes::from_static(b"second")),
            ]),
            // The first chunk, then a failure a moment later: once the head and that chunk
            // are on the wire (a failure in the same instant only closes the connection
            // before anything is sent, which a client sees as plainly).
            "urn:t:broken" => {
                use futures::StreamExt;
                let first = futures::stream::iter([Ok(Bytes::from_static(b"the part before"))]);
                let then = futures::stream::once(async {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Err(ikigai_core::Error::Endpoint("the producer failed".into()))
                });
                Body::once(first.chain(then))
            }
            other => return Err(ikigai_core::Error::NotFound(other.to_string())),
        };
        Ok(Representation::from_body(ReprType::new("text/plain"), body))
    }

    fn describe(&self) -> Description {
        Description::new("bodies").verb(Verb::Source)
    }
}

fn reading_kernel() -> Arc<Kernel> {
    let space = EndpointSpace::new()
        .bind(Exact::new("urn:t:seekable"), Bodies)
        .bind(Exact::new("urn:t:once"), Bodies)
        .bind(Exact::new("urn:t:broken"), Bodies);
    Arc::new(Kernel::new(Arc::new(space)))
}

async fn reading_door() -> SocketAddr {
    common::start(reading_kernel(), EdgeConfig::default(), public_cap()).await
}

fn get(path: &str, extra: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: x\r\n{extra}\r\n").into_bytes()
}

#[tokio::test]
async fn a_body_of_known_length_is_sent_with_content_length() {
    let addr = reading_door().await;
    let out = send(addr, &get("/t/seekable", "")).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert_eq!(header(&out, "content-length"), Some("36"), "{out}");
    assert_eq!(header(&out, "transfer-encoding"), None, "{out}");
    assert_eq!(header(&out, "accept-ranges"), Some("bytes"), "{out}");
    assert!(header(&out, "etag").is_some(), "{out}");
    assert_eq!(split(&out).1.as_bytes(), TEXT);
    // HEAD: the same length, no content.
    let head = send(addr, b"HEAD /t/seekable HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_eq!(header(&head, "content-length"), Some("36"), "{head}");
    assert_eq!(split(&head).1, "", "{head}");
}

#[tokio::test]
async fn a_body_of_unknown_length_is_chunked() {
    let addr = reading_door().await;
    let out = send(addr, &get("/t/once", "")).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert_eq!(header(&out, "transfer-encoding"), Some("chunked"), "{out}");
    assert_eq!(header(&out, "content-length"), None, "{out}");
    // A one-shot body has no validator and is never ranged.
    assert_eq!(header(&out, "etag"), None, "{out}");
    assert_eq!(header(&out, "accept-ranges"), None, "{out}");
    let body = split(&out).1;
    assert!(body.contains("first ") && body.contains("second"), "{out}");
    assert!(
        body.ends_with("0\r\n\r\n"),
        "a whole chunked body ends in its last chunk: {out}"
    );
    // HEAD of a body of unknown length claims no length (a `0` would be false).
    let head = send(addr, b"HEAD /t/once HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    assert_eq!(header(&head, "content-length"), None, "{head}");
    assert_eq!(split(&head).1, "", "{head}");
}

/// The producer fails part-way: the client must be able to tell. The answer ends without its
/// final zero-length chunk and the connection closes, so what arrived cannot be read as whole.
#[tokio::test]
async fn a_failure_part_way_ends_the_chunked_answer_without_its_final_chunk() {
    let addr = reading_door().await;
    let out = send(addr, &get("/t/broken", "")).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert_eq!(header(&out, "transfer-encoding"), Some("chunked"), "{out}");
    let body = split(&out).1;
    assert!(body.contains("the part before"), "{out}");
    assert!(
        !body.ends_with("0\r\n\r\n"),
        "no final chunk after a failure: {out:?}"
    );
}

#[tokio::test]
async fn one_range_is_a_206_and_a_range_past_the_end_is_a_416() {
    let addr = reading_door().await;
    let part = send(addr, &get("/t/seekable", "Range: bytes=3-11\r\n")).await;
    assert!(
        part.starts_with("HTTP/1.1 206 Partial Content\r\n"),
        "{part}"
    );
    assert_eq!(
        header(&part, "content-range"),
        Some("bytes 3-11/36"),
        "{part}"
    );
    assert_eq!(header(&part, "content-length"), Some("9"), "{part}");
    assert_eq!(split(&part).1, "3456789ab");
    let suffix = send(addr, &get("/t/seekable", "Range: bytes=-4\r\n")).await;
    assert_eq!(
        header(&suffix, "content-range"),
        Some("bytes 32-35/36"),
        "{suffix}"
    );
    assert_eq!(split(&suffix).1, "wxyz");

    let past = send(addr, &get("/t/seekable", "Range: bytes=36-\r\n")).await;
    assert!(
        past.starts_with("HTTP/1.1 416 Range Not Satisfiable\r\n"),
        "{past}"
    );
    assert_eq!(header(&past, "content-range"), Some("bytes */36"), "{past}");
    // Its error page follows ACCESSIBILITY.md like every other: a page for a browser.
    let page = send(
        addr,
        &get("/t/seekable", "Range: bytes=99-\r\nAccept: text/html\r\n"),
    )
    .await;
    assert!(page.starts_with("HTTP/1.1 416 "), "{page}");
    let body = split(&page).1;
    assert!(body.contains("<html lang=\"en\">"), "{page}");
    assert!(
        body.contains("<main><h1>416 Range Not Satisfiable</h1>"),
        "{page}"
    );

    // Several ranges: the whole body, 200 (no multipart/byteranges).
    let several = send(addr, &get("/t/seekable", "Range: bytes=0-1, 4-5\r\n")).await;
    assert!(several.starts_with("HTTP/1.1 200 "), "{several}");
    assert_eq!(split(&several).1.as_bytes(), TEXT);
}

#[tokio::test]
async fn if_range_gives_the_part_on_a_match_and_the_whole_body_otherwise() {
    let addr = reading_door().await;
    let whole = send(addr, &get("/t/seekable", "")).await;
    let etag = header(&whole, "etag")
        .expect("a strong validator")
        .to_string();
    let matched = send(
        addr,
        &get(
            "/t/seekable",
            &format!("Range: bytes=0-3\r\nIf-Range: {etag}\r\n"),
        ),
    )
    .await;
    assert!(matched.starts_with("HTTP/1.1 206 "), "{matched}");
    assert_eq!(split(&matched).1, "0123");
    let stale = send(
        addr,
        &get(
            "/t/seekable",
            "Range: bytes=0-3\r\nIf-Range: \"another\"\r\n",
        ),
    )
    .await;
    assert!(stale.starts_with("HTTP/1.1 200 "), "{stale}");
    assert_eq!(split(&stale).1.as_bytes(), TEXT);
    // The validator also answers If-None-Match with a 304, as a whole read's does.
    let fresh = send(
        addr,
        &get("/t/seekable", &format!("If-None-Match: {etag}\r\n")),
    )
    .await;
    assert!(fresh.starts_with("HTTP/1.1 304 "), "{fresh}");
}

#[tokio::test]
async fn a_one_shot_body_ignores_range() {
    let addr = reading_door().await;
    let out = send(addr, &get("/t/once", "Range: bytes=0-2\r\n")).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert_eq!(header(&out, "accept-ranges"), None, "{out}");
    assert_eq!(header(&out, "content-range"), None, "{out}");
    assert!(split(&out).1.contains("second"), "{out}");
}
