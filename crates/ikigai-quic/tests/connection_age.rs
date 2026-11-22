//! A door bounds connection age, so an enrolment edit revokes within a known time
//! (ledger #1179).
//!
//! The [`Minter`] runs once per CONNECTION. A host that re-reads its enrolment per connection
//! therefore revokes a client only when that client next connects, and a client holding one
//! connection open (a daemon's standing mount) may never do so. `serve_bounded` closes a
//! connection once it is `max_age` old; the resolver heals onto a fresh one at its next call,
//! and the minter decides afresh. These tests pin the three halves: the unbounded door keeps
//! one connection (the gap, reproduced), the bounded door re-mints, and a revoked client's
//! next call after the bound is refused. A fourth pins that a call in flight when the bound
//! passes still gets its reply, run once.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ikigai_core::{
    ArgRef, Capability, Description, EndpointSpace, Exact, FnEndpoint, Invocation, Iri, Kernel,
    ReprType, Representation, Request, Verb,
};
use ikigai_quic::{connect_with, generate, serve_bounded, Identity, Minter, Session};
use ikigai_resolve::Resolver;

/// The bound every bounded door here runs under.
const AGE: Duration = Duration::from_millis(800);

/// Comfortably past [`AGE`], so a connection that should have been closed has been.
const PAST_AGE: Duration = Duration::from_millis(1600);

fn free_port() -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("a free UDP port");
    socket.local_addr().expect("its address")
}

/// What the door's minter has done: how many connections it minted, and whether the client
/// is revoked (the minter then refuses, as an enrolment edit makes the cli's minter do).
#[derive(Default)]
struct Enrolment {
    mints: AtomicUsize,
    revoked: AtomicBool,
}

impl Enrolment {
    fn minter(self: &Arc<Self>) -> Minter {
        let enrolment = Arc::clone(self);
        Arc::new(move |peer| {
            if enrolment.revoked.load(Ordering::SeqCst) {
                return None;
            }
            enrolment.mints.fetch_add(1, Ordering::SeqCst);
            Some(Session {
                capability: Capability::scoped(["urn:cap:test:who".to_string()]),
                file_segment: String::new(),
                principal: Some(format!("urn:iki:host:test:client:{}", peer.fingerprint)),
            })
        })
    }

    fn mints(&self) -> usize {
        self.mints.load(Ordering::SeqCst)
    }
}

/// A kernel whose `urn:test:who` answers the principal the call resolved under, and whose
/// `urn:test:slow` Sink counts its runs and takes `slow` to answer.
#[allow(clippy::disallowed_methods)] // internal: a test fixture's kernel; it routes no user arguments
fn kernel(runs: Arc<AtomicUsize>, slow: Duration) -> Kernel {
    let who = FnEndpoint::new("who", |inv: &Invocation<'_>| {
        Ok(Representation::new(
            ReprType::new("text/plain"),
            inv.capability
                .principal()
                .unwrap_or("-")
                .as_bytes()
                .to_vec(),
        ))
    })
    .with_description(Description::new("who").verb(Verb::Source));
    let append = FnEndpoint::new("slow", move |_inv: &Invocation<'_>| {
        runs.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(slow);
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"appended".to_vec(),
        ))
    })
    .with_description(Description::new("slow").verb(Verb::Sink));
    Kernel::new(Arc::new(
        EndpointSpace::new()
            .bind(Exact::new("urn:test:who"), who)
            .bind(Exact::new("urn:test:slow"), append),
    ))
}

/// Serve `kernel` under `enrolment`'s minter with `max_age`, and connect one client to it.
fn door(kernel: Kernel, enrolment: &Arc<Enrolment>, max_age: Option<Duration>) -> impl Resolver {
    let server_id = generate();
    let client_id = generate();
    let addr = free_port();
    let client_cert = client_id.cert_pem.clone();
    let (cert_pem, key_pem) = (server_id.cert_pem.clone(), server_id.key_pem.clone());
    let minter = enrolment.minter();
    std::thread::spawn(move || {
        let identity = Identity { cert_pem, key_pem };
        let _ = serve_bounded(
            kernel,
            addr,
            &identity,
            &[client_cert],
            minter,
            Duration::from_secs(300),
            max_age,
        );
    });
    std::thread::sleep(Duration::from_millis(300));
    connect_with(
        addr,
        &client_id,
        &server_id.cert_pem,
        Duration::from_secs(300),
    )
    .expect("the client connects")
}

fn who(client: &impl Resolver) -> Result<String, ikigai_core::Error> {
    client
        .issue(Request::new(
            Verb::Source,
            Iri::parse("urn:test:who").unwrap(),
        ))
        .map(|(representation, _)| String::from_utf8(representation.bytes).unwrap())
}

/// The gap, reproduced: without a bound, one connection carries every call, so the minter
/// runs once however long the client stays, and an enrolment edit would never reach it.
#[test]
fn an_unbounded_door_mints_a_standing_connection_once() {
    let enrolment = Arc::new(Enrolment::default());
    let client = door(kernel(Arc::default(), Duration::ZERO), &enrolment, None);
    let first = who(&client).expect("the first call");
    assert!(first.starts_with("urn:iki:host:test:client:"), "{first}");
    std::thread::sleep(PAST_AGE);
    who(&client).expect("the second call");
    assert_eq!(enrolment.mints(), 1, "one connection, minted once");
}

/// With a bound, the connection is closed once it is that old and the client's next call
/// heals onto a new one, minted afresh, still named the same.
#[test]
fn a_bounded_door_re_mints_after_the_age_bound() {
    let enrolment = Arc::new(Enrolment::default());
    let client = door(
        kernel(Arc::default(), Duration::ZERO),
        &enrolment,
        Some(AGE),
    );
    let first = who(&client).expect("the first call");
    assert_eq!(enrolment.mints(), 1);
    std::thread::sleep(PAST_AGE);
    let second = who(&client).expect("the call after the bound heals onto a new connection");
    assert_eq!(second, first, "the same certificate, the same principal");
    assert_eq!(
        enrolment.mints(),
        2,
        "the door closed the old connection and minted anew"
    );
}

/// The point of the bound: a client revoked while connected keeps its connection only until
/// the bound, and then cannot reconnect.
#[test]
fn a_revoked_client_is_refused_once_its_connection_ages_out() {
    let enrolment = Arc::new(Enrolment::default());
    let client = door(
        kernel(Arc::default(), Duration::ZERO),
        &enrolment,
        Some(AGE),
    );
    who(&client).expect("served while enrolled");
    enrolment.revoked.store(true, Ordering::SeqCst);
    std::thread::sleep(PAST_AGE);
    let refused = who(&client);
    assert!(
        refused.is_err(),
        "a revoked client must not be served past the bound: {refused:?}"
    );
    assert_eq!(
        enrolment.mints(),
        1,
        "nothing was minted for the revoked client"
    );
}

/// A call still running when the bound passes is answered before the door closes, and a
/// Sink is not run twice for it.
#[test]
fn a_call_in_flight_at_the_bound_gets_its_reply_and_runs_once() {
    let enrolment = Arc::new(Enrolment::default());
    let runs = Arc::new(AtomicUsize::new(0));
    let client = door(kernel(Arc::clone(&runs), PAST_AGE), &enrolment, Some(AGE));
    let sink = Request::new(Verb::Sink, Iri::parse("urn:test:slow").unwrap())
        .with_arg("content", ArgRef::Inline(b"one line".to_vec()));
    let (reply, _) = client
        .issue(sink)
        .expect("the reply to a call in flight at the bound is delivered");
    assert_eq!(reply.bytes, b"appended");
    assert_eq!(runs.load(Ordering::SeqCst), 1, "the Sink ran once");
    // And the connection it ran on was then closed: the next call is a new mint.
    who(&client).expect("the next call heals");
    assert_eq!(enrolment.mints(), 2);
}
