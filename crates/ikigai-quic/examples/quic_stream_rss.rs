//! Peak memory of a 100 MiB answer over QUIC, streamed against collected (wire v10, ledger
//! #2242). Server and client run in this one process, so its peak resident set
//! is the exchange's, both sides. Run each mode in its own process and read the peak:
//!
//! ```text
//! cargo build --release -p ikigai-quic --example quic_stream_rss
//! /usr/bin/time -l target/release/examples/quic_stream_rss streamed    # macOS
//! /usr/bin/time -v target/release/examples/quic_stream_rss streamed    # Linux
//! ```
//!
//! Modes: `streamed` (the server's producer is lazy, the client copies chunks to a sink),
//! `collected` (the same producer, the client collects the body), `buffered` (the server's
//! answer is one 100 MiB buffer, the client collects it), `plain` (the pre-v10 call, which a
//! 100 MiB answer cannot cross in one message: refused with `OverBudget`).

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
    let server_id = ikigai_quic::generate();
    let client_id = ikigai_quic::generate();
    // Port 0, read back from the bound socket.
    let socket = ikigai_quic::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
    let addr = socket.local_addr().expect("bound address");
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new()
            .bind(Exact::new("urn:rss:lazy"), Hundred { lazy: true })
            .bind(Exact::new("urn:rss:buffer"), Hundred { lazy: false }),
    ))
    // Root may buffer the whole answer when a mode collects it on the server.
    .with_stream_memory(TOTAL as u64 * 2, TOTAL as u64 * 2);
    let trusted = vec![client_id.cert_pem.clone()];
    let minter: ikigai_quic::Minter = Arc::new(|_| {
        Some(ikigai_quic::Session {
            capability: Capability::root(),
            file_segment: String::new(),
            principal: None,
        })
    });
    let identity = ikigai_quic::Identity {
        cert_pem: server_id.cert_pem.clone(),
        key_pem: server_id.key_pem.clone(),
    };
    std::thread::spawn(move || {
        let _ = ikigai_quic::serve_bounded_on(
            kernel,
            socket,
            &identity,
            &trusted,
            minter,
            ikigai_quic::DEFAULT_IDLE_TIMEOUT,
            None,
        );
    });
    let client = ikigai_quic::connect(addr, &client_id, &server_id.cert_pem).expect("connect");
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
    println!("quic {mode}: {outcome} in {:?}", started.elapsed());
}
