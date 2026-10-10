//! A loopback HTTP stub that COUNTS what reaches it — the instrument for the egress tests
//! (`tests/egress.rs`, `tests/egress_shared.rs`; ledger #1083, #1085).
//!
//! It answers like a real endpoint on purpose: a SPARQL results document for anything
//! but `/data.ttl`, and a one-triple Turtle document for `/data.ttl`. A stub that answered
//! garbage would let a fetch FAIL after it left the process, and a test asserting "the
//! query failed" would then pass on a host that did reach the network. The assertion that
//! matters is the count, and the realistic answer is what makes a leak visible in the
//! result as well (`from the network`).
//!
//! ⚠ Loopback only, on a port the OS picks: it never collides with a live service
//! (gonk's 1060, the QUIC 4433) and is torn down with the test process.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// The marker a leaked SERVICE or LOAD carries back into a result.
pub const LEAK_MARKER: &str = "from the network";

pub struct Stub {
    port: u16,
    hits: Arc<AtomicUsize>,
}

impl Stub {
    /// Bind `127.0.0.1:0` and serve on a detached thread for the life of the process.
    pub fn start() -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let port = listener.local_addr().expect("the bound address").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buf = [0u8; 16 * 1024];
                let n = stream.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]);
                let (media, body) = if head.contains("/data.ttl") {
                    (
                        "text/turtle",
                        format!("<urn:stub:s> <urn:stub:p> \"{LEAK_MARKER}\" .\n"),
                    )
                } else {
                    (
                        "application/sparql-results+json",
                        format!(
                            r#"{{"head":{{"vars":["s","p","o"]}},"results":{{"bindings":[{{"s":{{"type":"uri","value":"urn:stub:s"}},"p":{{"type":"uri","value":"urn:stub:p"}},"o":{{"type":"literal","value":"{LEAK_MARKER}"}}}}]}}}}"#
                        ),
                    )
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        Stub { port, hits }
    }

    /// `http://127.0.0.1:<port><path>`.
    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    /// How many connections have reached the stub so far.
    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}
