//! What server push costs: an idle stream's memory, and one write fanned out to N streams.
//!
//! ```text
//! ulimit -n 8192; cargo run --release -p ikigai-web --example push_cost
//! ```
//!
//! Server and clients share this process, so the resident-set delta per stream counts both
//! ends' user-space state (the kernel's socket buffers are not in RSS). Fan-out times one
//! write through the kernel with N streams listening: the writer's own latency (the cut runs on
//! its stack) and the time until the LAST of the N clients has read the event.

// A native-only measurement: it times wall-clock latency over real sockets, so the wasm
// clock rule (take time from the injected `Clock`) has nothing to protect here.
#![allow(clippy::disallowed_methods)]

use ikigai_core::{
    ArgRef, Capability, Description, EndpointSpace, Exact, FnEndpoint, Invocation, Iri, Kernel,
    ReprType, Representation, Request, Verb,
};
use ikigai_web::{EdgeConfig, HttpRequest, PushConfig};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CELL: &str = "urn:bench:cell:a";

fn rss_kib() -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

async fn open(addr: std::net::SocketAddr) -> TcpStream {
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"GET /_ikigai/push?path=/bench/cell/a HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    read_until(&mut sock, "event: ready\n").await;
    sock
}

async fn read_until(sock: &mut TcpStream, needle: &str) {
    let mut seen = String::new();
    let mut buf = [0u8; 2048];
    while !seen.contains(needle) {
        let n = sock.read(&mut buf).await.unwrap();
        assert!(n > 0, "closed: {seen}");
        seen.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
}

#[tokio::main]
async fn main() {
    let cell = FnEndpoint::new("cell", |_inv: &Invocation<'_>| {
        Ok(Representation::new(ReprType::new("text/plain"), b"1".to_vec()).cacheable())
    })
    .with_description(Description::new("cell").verb(Verb::Source).verb(Verb::Sink));
    let kernel = Arc::new(Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new(CELL), cell),
    )));
    let cap = Capability::scoped(["urn:cap:kernel:listen"]);
    let door_cap = cap.clone();
    let door = Arc::new(move |_req: &HttpRequest| door_cap.clone());
    let config = EdgeConfig {
        push: Some(PushConfig {
            heartbeat: Duration::from_secs(3600),
            idle_timeout: Duration::from_secs(3600),
            ..PushConfig::default()
        }),
        max_connections: 100_000,
        ..EdgeConfig::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(ikigai_web::serve_with_listener(
        Arc::clone(&kernel),
        door,
        listener,
        config,
    ));

    let read = || Request::new(Verb::Source, Iri::parse(CELL).unwrap());
    let write = || {
        Request::new(Verb::Sink, Iri::parse(CELL).unwrap())
            .with_arg("content", ArgRef::Inline(b"2".to_vec()))
    };

    // The writer with nobody listening, for the baseline.
    kernel.issue(read(), &cap).await.unwrap();
    let t = Instant::now();
    for _ in 0..1000 {
        kernel.issue(read(), &cap).await.unwrap();
        kernel.issue(write(), &cap).await.unwrap();
    }
    println!("no streams: read+write pair {:?}", t.elapsed() / 1000);

    let mut streams: Vec<TcpStream> = Vec::new();
    for n in [1usize, 10, 100, 1000] {
        let before = rss_kib();
        let grew = n - streams.len();
        while streams.len() < n {
            streams.push(open(addr).await);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let after = rss_kib();
        kernel.issue(read(), &cap).await.unwrap();
        let t = Instant::now();
        kernel.issue(write(), &cap).await.unwrap();
        let writer = t.elapsed();
        let mut readers = Vec::new();
        for sock in streams.drain(..) {
            readers.push(tokio::spawn(async move {
                let mut sock = sock;
                read_until(&mut sock, "event: cut\n").await;
                sock
            }));
        }
        for reader in readers {
            streams.push(reader.await.unwrap());
        }
        let delivered = t.elapsed();
        println!(
            "{n:>5} streams: rss +{} KiB for {grew} new ({:.1} KiB/stream); write {:?}; last delivery {:?}",
            after.saturating_sub(before),
            after.saturating_sub(before) as f64 / grew.max(1) as f64,
            writer,
            delivered
        );
    }
}
