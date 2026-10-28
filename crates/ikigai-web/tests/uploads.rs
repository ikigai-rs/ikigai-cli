//! Uploads spilled to disk instead of read into memory (ledger #2244), through the real door
//! (hyper, a real socket). Unix only: the spill facility they spill through, ikigai-fs's
//! `FileSpill`, is.
#![cfg(unix)]
mod common;

use common::{send, split};
use ikigai_core::{
    cap_stream_spill, ArgRef, AsyncFnEndpoint, ContentHasher, ContentId, Description,
    EndpointSpace, Exact, Kernel, MemoryContentStore, ReprType, Representation, Verb,
};
use ikigai_web::{fixed_cap, public_cap, CapFn, EdgeConfig, Uploads};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A spill directory of this test's own: the file-backed facility removes the spill files of
/// the directory it opens, so no two tests may share one.
struct SpillDir(PathBuf);

impl SpillDir {
    fn new(name: &str) -> SpillDir {
        let dir =
            std::env::temp_dir().join(format!("ikigai-web-streams-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        SpillDir(dir)
    }

    /// The spill files in the directory now.
    fn files(&self) -> Vec<String> {
        files_in(&self.0)
    }
}

fn files_in(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

impl Drop for SpillDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A Sink that reports how its content arrived: `content-id` or `inline`, its length and its
/// digest, read as a body.
fn measuring_sink() -> AsyncFnEndpoint {
    AsyncFnEndpoint::new("measure", |inv| {
        Box::pin(async move {
            let how = match inv.request.args.get("content") {
                Some(ArgRef::Content(id)) => format!("content-id {id}"),
                Some(_) => "inline".to_string(),
                None => "none".to_string(),
            };
            let mut stream = inv.content_body("content").await?.into_stream();
            let (mut n, mut hasher) = (0u64, ContentHasher::new());
            use futures::StreamExt;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                n += chunk.len() as u64;
                hasher.update(&chunk);
            }
            let line = format!("{how} {n} {}", hasher.finish());
            Ok(Representation::new(
                ReprType::new("text/plain"),
                line.into_bytes(),
            ))
        })
    })
    .with_description(Description::new("measure").verb(Verb::Sink))
}

struct UploadDoor {
    addr: SocketAddr,
    spill: SpillDir,
}

/// A door with one upload route, `/t/upload` (at most 4096 bytes), over a kernel spilling to
/// a fresh directory, its callers granted `grant` bytes of spill.
async fn upload_door(name: &str, grant: Option<u64>, rate: Option<(u64, Duration)>) -> UploadDoor {
    let spill = SpillDir::new(name);
    let store = Arc::new(MemoryContentStore::new(1 << 30));
    let space = EndpointSpace::new().bind(Exact::new("urn:t:upload"), measuring_sink());
    let kernel = Kernel::new(Arc::new(space))
        .with_spill(Arc::new(ikigai_fs::FileSpill::new(&spill.0).unwrap()))
        .with_content_store(store.clone());
    let mut uploads = Uploads::new(store).route("/t/upload", 4096);
    if let Some((rate, grace)) = rate {
        uploads = uploads.min_rate(rate, grace);
    }
    let cap_fn: CapFn = match grant {
        Some(bytes) => fixed_cap(vec![cap_stream_spill(bytes)]),
        None => public_cap(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let kernel = Arc::new(kernel);
    let config = EdgeConfig {
        max_body_bytes: 64,
        ..EdgeConfig::default()
    };
    tokio::spawn(async move {
        let served =
            ikigai_web::serve_with_uploads(kernel, cap_fn, listener, config, uploads).await;
        panic!("the door stopped: {served:?}");
    });
    UploadDoor { addr, spill }
}

fn put(path: &str, body: &[u8]) -> Vec<u8> {
    let mut raw = format!(
        "PUT {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(body);
    raw
}

#[tokio::test]
async fn an_upload_spills_and_the_sink_reads_it_by_content_id() {
    let door = upload_door("spills", Some(1 << 20), None).await;
    let body = vec![7u8; 3000]; // past the door's 64-byte in-memory bound
    let out = send(door.addr, &put("/t/upload", &body)).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    let id = ContentId::of(&body);
    assert_eq!(split(&out).1, format!("content-id {id} 3000 {id}"), "{out}");
    // Answered, the spill is released and its file removed.
    assert!(door.spill.files().is_empty(), "{:?}", door.spill.files());
}

#[tokio::test]
async fn an_upload_past_its_bound_is_413_and_leaves_no_spill_file() {
    let door = upload_door("past", Some(2048), None).await;
    // Past the route's own bound, refused on Content-Length before a byte is read.
    let out = send(door.addr, &put("/t/upload", &[1u8; 5000])).await;
    assert!(out.starts_with("HTTP/1.1 413 "), "{out}");
    assert!(out.contains("at most 4096 bytes"), "{out}");
    // Within the route's bound, past the caller's spill grant.
    let out = send(door.addr, &put("/t/upload", &[1u8; 3000])).await;
    assert!(out.starts_with("HTTP/1.1 413 "), "{out}");
    assert!(out.contains("urn:cap:stream:spill"), "{out}");
    assert!(door.spill.files().is_empty(), "{:?}", door.spill.files());
    // A browser gets the refusal as a page.
    let mut page = put("/t/upload", &[1u8; 5000]);
    let at = page.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    page.splice(at + 2..at + 2, b"Accept: text/html\r\n".iter().copied());
    let out = send(door.addr, &page).await;
    assert!(out.starts_with("HTTP/1.1 413 "), "{out}");
    assert!(
        split(&out)
            .1
            .contains("<main><h1>413 Payload Too Large</h1>"),
        "{out}"
    );
}

#[tokio::test]
async fn a_too_slow_upload_is_cut_and_leaves_no_spill_file() {
    // 100 KiB a second after a 300 ms grace.
    let door = upload_door(
        "slow",
        Some(1 << 20),
        Some((100 * 1024, Duration::from_millis(300))),
    )
    .await;
    let mut c = TcpStream::connect(door.addr).await.unwrap();
    c.write_all(
        b"PUT /t/upload HTTP/1.1\r\nHost: x\r\nContent-Length: 4000\r\n\r\nthe first bytes",
    )
    .await
    .unwrap();
    // Then nothing more: the door cuts it once the grace and what it earned have passed.
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), c.read_to_end(&mut out))
        .await
        .expect("the door should cut a stalled upload")
        .unwrap();
    let out = String::from_utf8_lossy(&out);
    assert!(out.starts_with("HTTP/1.1 408 "), "{out}");
    assert!(out.contains("slower than 102400 bytes a second"), "{out}");
    assert!(door.spill.files().is_empty(), "{:?}", door.spill.files());
}

#[tokio::test]
async fn request_transfer_encoding_on_an_upload_route_is_501() {
    let door = upload_door("chunked", Some(1 << 20), None).await;
    let out = send(
        door.addr,
        b"PUT /t/upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
    assert!(out.starts_with("HTTP/1.1 501 "), "{out}");
    assert!(door.spill.files().is_empty(), "{:?}", door.spill.files());
}

/// A caller holding no spill grant does not spill: its body is taken into memory under the
/// door's own bound, exactly as on any other route.
#[tokio::test]
async fn without_a_spill_grant_an_upload_route_takes_the_body_into_memory() {
    let door = upload_door("ungranted", None, None).await;
    let small = send(door.addr, &put("/t/upload", b"hello")).await;
    assert!(small.starts_with("HTTP/1.1 200 "), "{small}");
    assert!(split(&small).1.starts_with("inline 5 "), "{small}");
    let large = send(door.addr, &put("/t/upload", &[1u8; 3000])).await;
    assert!(large.starts_with("HTTP/1.1 413 "), "{large}");
}

/// The door will not start over a kernel that cannot carry its uploads.
#[tokio::test]
async fn uploads_refuse_a_kernel_without_a_spill_or_with_another_store() {
    let listener = || async { tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap() };
    let store = Arc::new(MemoryContentStore::new(1 << 20));
    let bare =
        Arc::new(Kernel::new(Arc::new(EndpointSpace::new())).with_content_store(store.clone()));
    let refused = ikigai_web::serve_with_uploads(
        bare,
        public_cap(),
        listener().await,
        EdgeConfig::default(),
        Uploads::new(store),
    )
    .await
    .unwrap_err();
    assert!(refused.to_string().contains("spill facility"), "{refused}");

    let spill = SpillDir::new("store");
    let other = Arc::new(MemoryContentStore::new(1 << 20));
    let kernel = Arc::new(
        Kernel::new(Arc::new(EndpointSpace::new()))
            .with_spill(Arc::new(ikigai_fs::FileSpill::new(&spill.0).unwrap()))
            .with_content_store(other),
    );
    let refused = ikigai_web::serve_with_uploads(
        kernel,
        public_cap(),
        listener().await,
        EdgeConfig::default(),
        Uploads::new(Arc::new(MemoryContentStore::new(1 << 20))),
    )
    .await
    .unwrap_err();
    assert!(refused.to_string().contains("same store"), "{refused}");
}
