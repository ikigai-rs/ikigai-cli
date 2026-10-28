//! Peak memory of a 1 GiB download and a 1 GiB upload through the HTTP door, streamed against
//! held in memory (ledger #2244). The door and its client run in this one process, so its peak
//! resident set is the exchange's, both sides. Run each mode in its own process and read the
//! peak:
//!
//! ```text
//! cargo build --release -p ikigai-web --example web_stream_rss
//! /usr/bin/time -l target/release/examples/web_stream_rss download-streamed           # macOS
//! /usr/bin/time -v target/release/examples/web_stream_rss download-streamed           # Linux
//! /usr/bin/time -l target/release/examples/web_stream_rss upload-spilled <spill dir>
//! ```
//!
//! Modes:
//!
//! - `download-streamed`: the producer answers a 1 GiB body of known length that it reads a
//!   piece at a time (a [`Replay`], as a file is read); the door writes it as it reads it, with
//!   `Content-Length`, and the client counts what arrives.
//! - `download-buffered`: the producer answers one 1 GiB buffer, which the door writes whole.
//! - `upload-spilled`: the client sends 1 GiB to an upload route; the door spills it into
//!   `<spill dir>` (which must exist) as it arrives and the Sink reads it back as a body.
//! - `upload-collected`: the same 1 GiB to an ordinary route whose bound admits it, taken into
//!   memory as every upload was before ledger #2244; the Sink reads it as inline content.

use async_trait::async_trait;
use ikigai_core::{
    cap_stream_spill, ArgRef, AsyncFnEndpoint, Body, ByteStream, Bytes, Description, Endpoint,
    EndpointSpace, Exact, Invocation, Kernel, MemoryContentStore, Replay, ReprType, Representation,
    Verb,
};
use ikigai_web::{fixed_cap, EdgeConfig, Uploads};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TOTAL: u64 = 1024 * 1024 * 1024;
const PIECE: usize = 256 * 1024;

/// 1 GiB read a piece at a time, every time it is opened.
struct Gibibyte;

impl Replay for Gibibyte {
    fn open(&self) -> ByteStream {
        let pieces = TOTAL / PIECE as u64;
        Box::pin(futures::stream::iter(
            (0..pieces).map(|i| Ok(Bytes::from(vec![i as u8; PIECE]))),
        ))
    }
    fn len_hint(&self) -> Option<u64> {
        Some(TOTAL)
    }
}

/// The download: lazy (a replay) or one buffer.
struct Download {
    lazy: bool,
}

#[async_trait]
impl Endpoint for Download {
    async fn invoke(&self, inv: &Invocation<'_>) -> ikigai_core::Result<Representation> {
        let body = self.invoke_body(inv).await?;
        body.collect(usize::MAX).await
    }

    async fn invoke_body(&self, _: &Invocation<'_>) -> ikigai_core::Result<Representation<Body>> {
        let body = if self.lazy {
            Body::replay(Gibibyte)
        } else {
            Body::from(vec![7u8; TOTAL as usize])
        };
        Ok(Representation::from_body(
            ReprType::new("application/octet-stream"),
            body,
        ))
    }

    fn describe(&self) -> Description {
        Description::new("download").verb(Verb::Source)
    }
}

/// The upload's Sink: counts its content, reading a spilled one as a body and an inline one
/// where it lies (no copy).
fn counting_sink() -> AsyncFnEndpoint {
    AsyncFnEndpoint::new("count", |inv| {
        Box::pin(async move {
            let n = match inv.request.args.get("content") {
                Some(ArgRef::Inline(bytes)) => bytes.len() as u64,
                _ => {
                    use futures::StreamExt;
                    let mut stream = inv.content_body("content").await?.into_stream();
                    let mut n = 0u64;
                    while let Some(chunk) = stream.next().await {
                        n += chunk?.len() as u64;
                    }
                    n
                }
            };
            Ok(Representation::new(
                ReprType::new("text/plain"),
                n.to_string().into_bytes(),
            ))
        })
    })
    .with_description(Description::new("count").verb(Verb::Sink))
}

/// `kernel` spilling into `dir` through ikigai-fs's file-backed facility, which is Unix only.
#[cfg(unix)]
fn spilling(kernel: Kernel, dir: String) -> Kernel {
    kernel
        .with_spill(Arc::new(
            ikigai_fs::FileSpill::new(dir).expect("spill directory"),
        ))
        .with_stream_spill(0, 2 * TOTAL)
}

#[cfg(not(unix))]
fn spilling(_: Kernel, _: String) -> Kernel {
    panic!("upload-spilled needs ikigai-fs's spill facility, which is Unix only")
}

#[tokio::main]
async fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "download-streamed".into());
    let space = EndpointSpace::new()
        .bind(Exact::new("urn:rss:lazy"), Download { lazy: true })
        .bind(Exact::new("urn:rss:buffer"), Download { lazy: false })
        .bind(Exact::new("urn:rss:upload"), counting_sink())
        .bind(Exact::new("urn:rss:collect"), counting_sink());
    let store = Arc::new(MemoryContentStore::new(2 * TOTAL));
    let mut kernel = Kernel::new(Arc::new(space)).with_content_store(store.clone());
    if mode == "upload-spilled" {
        let dir = std::env::args()
            .nth(2)
            .expect("upload-spilled needs a spill directory");
        kernel = spilling(kernel, dir);
    }
    let kernel = Arc::new(kernel);
    let config = EdgeConfig {
        // Admit the collected upload, which the in-memory path holds to this bound.
        max_body_bytes: (TOTAL + 1024) as usize,
        body_timeout: std::time::Duration::from_secs(600),
        ..EdgeConfig::default()
    };
    let cap = fixed_cap(vec![cap_stream_spill(2 * TOTAL)]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    if mode == "upload-spilled" {
        let uploads = Uploads::new(store).route("/rss/upload", 2 * TOTAL);
        tokio::spawn(ikigai_web::serve_with_uploads(
            kernel, cap, listener, config, uploads,
        ));
    } else {
        tokio::spawn(ikigai_web::serve_with_listener(
            kernel, cap, listener, config,
        ));
    }
    // Native-only: an example measured on the host, never built for wasm.
    #[allow(clippy::disallowed_methods)]
    let started = Instant::now();
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let outcome = match mode.as_str() {
        "download-streamed" | "download-buffered" => {
            let path = if mode == "download-streamed" {
                "/rss/lazy"
            } else {
                "/rss/buffer"
            };
            let head = format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n");
            sock.write_all(head.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; PIECE];
            let mut n = 0u64;
            let mut first = Vec::new();
            loop {
                let read = sock.read(&mut buf).await.unwrap();
                if read == 0 {
                    break;
                }
                if first.len() < 256 {
                    first.extend_from_slice(&buf[..read.min(256)]);
                }
                n += read as u64;
            }
            let status = String::from_utf8_lossy(&first)
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            format!("{status}: {n} bytes on the wire")
        }
        "upload-spilled" | "upload-collected" => {
            let path = if mode == "upload-spilled" {
                "/rss/upload"
            } else {
                "/rss/collect"
            };
            let head = format!(
                "PUT {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n\
                 Content-Length: {TOTAL}\r\n\r\n"
            );
            sock.write_all(head.as_bytes()).await.unwrap();
            let piece = vec![3u8; PIECE];
            for _ in 0..TOTAL / PIECE as u64 {
                sock.write_all(&piece).await.unwrap();
            }
            let mut answer = Vec::new();
            sock.read_to_end(&mut answer).await.unwrap();
            let answer = String::from_utf8_lossy(&answer);
            let status = answer.lines().next().unwrap_or("").to_string();
            let body = answer.split("\r\n\r\n").nth(1).unwrap_or("");
            format!("{status}: the Sink counted {body} bytes")
        }
        other => panic!("unknown mode {other}"),
    };
    println!("web {mode}: {outcome} in {:?}", started.elapsed());
}
