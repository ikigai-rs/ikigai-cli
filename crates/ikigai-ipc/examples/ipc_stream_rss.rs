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

use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use ikigai_core::{
    Body, Bytes, Capability, Endpoint, EndpointSpace, Exact, Invocation, Iri, Kernel, ReprType,
    Representation, Request, Verb,
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

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "streamed".into());
    let path = std::path::PathBuf::from(format!("/tmp/ikr{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind");
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new()
            .bind(Exact::new("urn:rss:lazy"), Hundred { lazy: true })
            .bind(Exact::new("urn:rss:buffer"), Hundred { lazy: false }),
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
        other => panic!("unknown mode {other}"),
    };
    println!("ipc {mode}: {outcome} in {:?}", started.elapsed());
    let _ = std::fs::remove_file(&path);
}
