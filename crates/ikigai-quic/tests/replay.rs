//! A Sink whose reply is lost is NOT run twice (ledger #733, finding Q2).
//!
//! `Wire::round_trip` used to reconnect and re-send after ANY failure. When the request had
//! reached the peer and only the reply was lost — here, the client's 1s idle timeout firing
//! during 2.5s of work — the Sink ran a second time on the fresh connection. The IPC
//! transport draws the line in `replay_may_follow`; QUIC now draws the same one: a read may
//! be replayed, a Sink or Delete surfaces the transient to its caller.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ikigai_core::{
    ArgRef, Capability, Description, EndpointSpace, Exact, FnEndpoint, Invocation, Iri, Kernel,
    ReprType, Representation, Request, Verb,
};
use ikigai_quic::{connect_with, generate, serve_with, Identity, Minter, Session};
use ikigai_resolve::Resolver;

fn free_port() -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("a free UDP port");
    socket.local_addr().expect("its address")
}

fn root_minter() -> Minter {
    Arc::new(|_| {
        Some(Session {
            capability: Capability::root(),
            file_segment: String::new(),
            principal: None,
        })
    })
}

#[test]
fn a_sink_whose_reply_is_lost_runs_once() {
    let runs = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&runs);
    // Longer than the client's idle timeout below, so the reply is lost after the work ran.
    let append = FnEndpoint::new("append", move |_inv: &Invocation<'_>| {
        counter.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(2500));
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"appended".to_vec(),
        ))
    })
    .with_description(Description::new("append").verb(Verb::Sink));
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:test:append"), append),
    ));
    let server_id = generate();
    let client_id = generate();
    let addr = free_port();
    let client_cert = client_id.cert_pem.clone();
    // `Identity` is not Clone; carry the PEMs across the thread boundary.
    let (cert_pem, key_pem) = (server_id.cert_pem.clone(), server_id.key_pem.clone());
    std::thread::spawn(move || {
        let identity = Identity { cert_pem, key_pem };
        let _ = serve_with(
            kernel,
            addr,
            &identity,
            &[client_cert],
            root_minter(),
            Duration::from_secs(300),
        );
    });
    std::thread::sleep(Duration::from_millis(300));
    let client = connect_with(
        addr,
        &client_id,
        &server_id.cert_pem,
        Duration::from_secs(1),
    )
    .expect("the client connects");
    let sink = Request::new(Verb::Sink, Iri::parse("urn:test:append").unwrap())
        .with_arg("content", ArgRef::Inline(b"one line".to_vec()));
    let result = client.issue(sink);
    // Long enough for a replayed call to have run to completion too.
    std::thread::sleep(Duration::from_millis(3000));
    assert!(
        matches!(
            result,
            Err(ikigai_core::Error::Unavailable(_)) | Err(ikigai_core::Error::Timeout(_))
        ),
        "the lost reply surfaces as a transient for the caller: {result:?}"
    );
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "one Sink call executed the endpoint more than once"
    );
}

/// The other half: a connection that idled out BEFORE the call is still healed for a Sink,
/// because a stream that cannot open on a dead connection carried nothing to the peer. This
/// is the daemon-mount case the reconnect exists for.
#[test]
fn a_sink_on_an_idled_out_connection_reconnects_and_runs_once() {
    let runs = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&runs);
    let append = FnEndpoint::new("append", move |_inv: &Invocation<'_>| {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"appended".to_vec(),
        ))
    })
    .with_description(Description::new("append").verb(Verb::Sink));
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:test:append"), append),
    ));
    let server_id = generate();
    let client_id = generate();
    let addr = free_port();
    let client_cert = client_id.cert_pem.clone();
    let (cert_pem, key_pem) = (server_id.cert_pem.clone(), server_id.key_pem.clone());
    std::thread::spawn(move || {
        let identity = Identity { cert_pem, key_pem };
        let _ = serve_with(
            kernel,
            addr,
            &identity,
            &[client_cert],
            root_minter(),
            Duration::from_secs(300),
        );
    });
    std::thread::sleep(Duration::from_millis(300));
    let client = connect_with(
        addr,
        &client_id,
        &server_id.cert_pem,
        Duration::from_secs(1),
    )
    .expect("the client connects");
    // Outlive the 1s idle timeout with no traffic: the connection is closed locally.
    std::thread::sleep(Duration::from_millis(2000));
    let sink = Request::new(Verb::Sink, Iri::parse("urn:test:append").unwrap())
        .with_arg("content", ArgRef::Inline(b"one line".to_vec()));
    let (repr, _) = client
        .issue(sink)
        .expect("a call that never reached the peer is sent again on a fresh connection");
    assert_eq!(repr.bytes, b"appended");
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}
