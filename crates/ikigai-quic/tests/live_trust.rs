//! A door's trust list is read at EVERY handshake, so a certificate added to it is trusted at
//! its next connection and one removed is refused at its next connection, with no restart
//! (ledger #1825).
//!
//! Through cli 0.1.63 a door pinned the PEMs it was handed at startup for its whole life: a
//! removed client certificate kept connecting until the process restarted, and a new one could
//! not connect until it did. [`serve_trusting_on`] takes a [`TrustList`] instead, and these
//! tests change the list under a running door.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ikigai_core::{
    Capability, Description, EndpointSpace, Exact, FnEndpoint, Invocation, Iri, Kernel, ReprType,
    Representation, Request, Verb,
};
use ikigai_quic::{
    bind, connect_with, generate, serve_trusting_on, Identity, Minter, Session, TrustList,
};
use ikigai_resolve::Resolver;

/// A kernel with one endpoint, `urn:test:hello`, so a connection can prove it was served.
#[allow(clippy::disallowed_methods)] // internal: a test fixture's kernel; it routes no user arguments
fn kernel() -> Kernel {
    let hello = FnEndpoint::new("hello", |_inv: &Invocation<'_>| {
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"hello".to_vec(),
        ))
    })
    .with_description(Description::new("hello").verb(Verb::Source));
    Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:test:hello"), hello),
    ))
}

/// What the door's trust list reads: the PEMs, or a failure.
type Listed = Arc<Mutex<Result<Vec<String>, String>>>;

/// Serve [`kernel`] trusting whatever `listed` holds at each handshake; returns the address
/// and the server's identity (a client pins its certificate).
fn door(listed: &Listed) -> (std::net::SocketAddr, Identity) {
    let server = generate();
    // Bound here, port 0 in the door itself: no port picked by bind-and-release (ledger #1223).
    let socket = bind("127.0.0.1:0".parse().unwrap()).expect("a UDP socket");
    let addr = socket.local_addr().expect("its address");
    let read = Arc::clone(listed);
    let trust: TrustList =
        Arc::new(move || read.lock().unwrap().clone().map_err(std::io::Error::other));
    let minter: Minter = Arc::new(|_| {
        Some(Session {
            capability: Capability::root(),
            file_segment: String::new(),
            principal: None,
        })
    });
    let identity = Identity {
        cert_pem: server.cert_pem.clone(),
        key_pem: server.key_pem.clone(),
    };
    std::thread::spawn(move || {
        let _ = serve_trusting_on(
            Arc::new(kernel()),
            socket,
            &identity,
            trust,
            minter,
            Duration::from_secs(300),
            None,
        );
    });
    (addr, server)
}

/// Whether `client` is served: a NEW connection (so a new handshake) and one call on it.
fn served(addr: std::net::SocketAddr, client: &Identity, server: &Identity) -> bool {
    let Ok(resolver) = connect_with(addr, client, &server.cert_pem, Duration::from_secs(10)) else {
        return false;
    };
    resolver
        .issue(Request::new(
            Verb::Source,
            Iri::parse("urn:test:hello").unwrap(),
        ))
        .is_ok_and(|(answer, _)| answer.bytes == b"hello")
}

#[test]
fn a_certificate_added_or_removed_while_the_door_serves_counts_at_its_next_connection() {
    let (alice, bob) = (generate(), generate());
    let listed: Listed = Arc::new(Mutex::new(Ok(vec![alice.cert_pem.clone()])));
    let (addr, server) = door(&listed);

    assert!(served(addr, &alice, &server), "alice is on the list");
    assert!(!served(addr, &bob, &server), "bob is not, yet");

    // Bob's certificate is added: trusted at his next connection, no restart.
    listed
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .push(bob.cert_pem.clone());
    assert!(
        served(addr, &bob, &server),
        "bob, added while the door serves"
    );

    // Alice's is removed: refused at her next connection, no restart.
    *listed.lock().unwrap() = Ok(vec![bob.cert_pem.clone()]);
    assert!(
        !served(addr, &alice, &server),
        "alice was removed from the trust list: her next connection must be refused"
    );
    assert!(served(addr, &bob, &server));
}

/// A list that cannot be read trusts NOBODY, never the last reading; and a PEM that does not
/// parse trusts nobody while the rest of the list still does.
#[test]
fn an_unreadable_list_trusts_nobody_and_a_bad_pem_only_itself() {
    let alice = generate();
    let listed: Listed = Arc::new(Mutex::new(Ok(vec![alice.cert_pem.clone()])));
    let (addr, server) = door(&listed);
    assert!(served(addr, &alice, &server));

    *listed.lock().unwrap() = Err("the trust directory went away".to_string());
    assert!(
        !served(addr, &alice, &server),
        "an unreadable trust list must not fall back to the last reading"
    );

    *listed.lock().unwrap() = Ok(vec![
        "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n".to_string(),
        alice.cert_pem.clone(),
    ]);
    assert!(
        served(addr, &alice, &server),
        "the good PEM still pins alice"
    );
}

/// The list is read once before anything is served, too: one that does not read, or holds a
/// PEM that does not parse, stops the door at start, as a bad fixed set always did.
#[test]
fn a_bad_list_at_start_stops_the_door() {
    let server = generate();
    let serve = |trust: TrustList| {
        let socket = bind("127.0.0.1:0".parse().unwrap()).expect("a UDP socket");
        serve_trusting_on(
            Arc::new(kernel()),
            socket,
            &server,
            trust,
            Arc::new(|_| None),
            Duration::from_secs(300),
            None,
        )
    };
    assert!(serve(Arc::new(|| Err(std::io::Error::other("unreadable")))).is_err());
    assert!(serve(Arc::new(|| Ok(vec!["not a certificate".to_string()]))).is_err());
}
