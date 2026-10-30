//! Peak memory of a 100 MiB answer over the IPC socket, streamed against collected (wire
//! v10, ledger #2242). Server and client run in this one process, so its peak resident set
//! is the exchange's, both sides. Run each mode in its own process and read the peak:
//!
//! ```text
//! cargo build --release -p ikigai-ipc --example ipc_stream_rss
//! /usr/bin/time -l target/release/examples/ipc_stream_rss streamed    # macOS
//! /usr/bin/time -v target/release/examples/ipc_stream_rss streamed    # Linux
//! ```
//!
//! Modes: `streamed` (the server's producer is lazy, the client copies chunks to a sink),
//! `collected` (the same producer, the client collects the body), `buffered` (the server's
//! answer is one 100 MiB buffer, the client collects it), `plain` (the pre-v10 call, which a
//! 100 MiB answer cannot cross in one frame: refused with `OverBudget`).
//!
//! And `upload [MiB]` (ledger #2454): the client streams a caller's body of 100 MiB (or
//! `MiB`), produced a piece at a time, to a Sink that reads `content` as a body and counts it,
//! so the peak is what the door holds of an upload.

use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use futures::StreamExt;
use ikigai_core::{
    ArgSpec, AsyncFnEndpoint, Body, Bytes, Capability, Description, Endpoint, EndpointSpace, Exact,
    Invocation, Iri, Kernel, ReprType, Representation, Request, Verb,
};
use ikigai_resolve::{Resolver, RunContext};

const TOTAL: usize = 100 * 1024 * 1024;
const PIECE: usize = 256 * 1024;

/// 100 MiB, produced a piece at a time (`lazy`) or held as one buffer.
struct Hundred {
    lazy: bool,
}

#[async_trait]
impl Endpoint for Hundred {
    async fn invoke(&self, inv: &Invocation<'_>) -> ikigai_core::Result<Representation> {
        let body = self.invoke_body(inv).await?;
        let bytes = inv.collect(body.bytes).await?;
        Ok(Representation::new(
            ReprType::new("application/octet-stream"),
            bytes.to_vec(),
        ))
    }

    async fn invoke_body(&self, _: &Invocation<'_>) -> ikigai_core::Result<Representation<Body>> {
        let body = if self.lazy {
            Body::once(futures::stream::iter(
                (0..TOTAL / PIECE).map(|i| Ok(Bytes::from(vec![i as u8; PIECE]))),
            ))
        } else {
            Body::from(vec![7u8; TOTAL])
        };
        Ok(Representation::from_body(
            ReprType::new("application/octet-stream"),
            body,
        ))
    }
}

/// A Sink that reads its `content` as a body, a chunk at a time, and answers how many bytes
/// it read: it holds no more of an upload than the chunk in hand.
fn counter() -> AsyncFnEndpoint {
    AsyncFnEndpoint::new("count", |inv| {
        Box::pin(async move {
            let mut chunks = inv.content_body("content").await?.into_stream();
            let mut n = 0u64;
            while let Some(chunk) = chunks.next().await {
                n += chunk?.len() as u64;
            }
            Ok(Representation::new(
                ReprType::new("text/plain"),
                n.to_string().into_bytes(),
            ))
        })
    })
    .with_description(
        Description::new("count")
            .verb(Verb::Sink)
            .input(ArgSpec::new("content").reads_body()),
    )
}

/// `total` bytes, made a piece at a time as they are read.
struct Generated {
    left: usize,
}

impl std::io::Read for Generated {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.left);
        buf[..n].fill(7);
        self.left -= n;
        Ok(n)
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "streamed".into());
    let path = std::path::PathBuf::from(format!("/tmp/ikr{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind");
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new()
            .bind(Exact::new("urn:rss:lazy"), Hundred { lazy: true })
            .bind(Exact::new("urn:rss:buffer"), Hundred { lazy: false })
            .bind(Exact::new("urn:rss:count"), counter()),
    ))
    // Root may buffer the whole answer when a mode collects it on the server.
    .with_stream_memory(TOTAL as u64 * 2, TOTAL as u64 * 2);
    std::thread::spawn(move || {
        let _ = ikigai_ipc::serve_on(kernel, listener);
    });
    let client = ikigai_ipc::connect(&path).expect("connect");
    let read = |target: &str| Request::new(Verb::Source, Iri::parse(target).unwrap());
    // Native-only: an example measured on the host, never built for wasm.
    #[allow(clippy::disallowed_methods)]
    let started = Instant::now();
    let outcome = match mode.as_str() {
        "streamed" | "collected" | "buffered" => {
            let target = if mode == "buffered" {
                "urn:rss:buffer"
            } else {
                "urn:rss:lazy"
            };
            let mut answer = client
                .issue_streamed(
                    read(target),
                    &Capability::root(),
                    &RunContext::default(),
                    None,
                )
                .expect("issue");
            if mode == "streamed" {
                let n = answer.copy_to(&mut std::io::sink()).expect("read");
                format!("{n} bytes copied to a sink")
            } else {
                let (whole, _) = answer.collect(TOTAL).expect("collect");
                format!("{} bytes collected", whole.bytes.len())
            }
        }
        "plain" => match client.issue_as(read("urn:rss:lazy"), &Capability::root()) {
            Ok((whole, _)) => format!("{} bytes in one frame", whole.bytes.len()),
            Err(error) => format!("refused: {error}"),
        },
        "upload" => {
            let total = std::env::args().nth(2).map_or(TOTAL, |mib| {
                mib.parse::<usize>().expect("MiB") * 1024 * 1024
            });
            let mut body = Generated { left: total };
            let upload = ikigai_wire::Upload {
                arg: "content".into(),
                body: &mut body,
                len: Some(total as u64),
            };
            let sink = Request::new(Verb::Sink, Iri::parse("urn:rss:count").unwrap());
            let answer = client
                .issue_streamed(
                    sink,
                    &Capability::root(),
                    &RunContext::default(),
                    Some(upload),
                )
                .and_then(|answer| answer.collect(64));
            match answer {
                Ok((count, _)) => format!(
                    "{total} bytes sent, the Sink counted {}",
                    String::from_utf8_lossy(&count.bytes)
                ),
                Err(error) => format!("{total} bytes refused: {error}"),
            }
        }
        other => panic!("unknown mode {other}"),
    };
    println!("ipc {mode}: {outcome} in {:?}", started.elapsed());
    let _ = std::fs::remove_file(&path);
}
