//! The spike's claims, on one machine: two peers that can reach each other ONLY through a
//! relay exchange a real wire call under a narrow grant; an unmapped PeerId is denied before
//! the kernel runs; the relay refuses a peer not on its allowlist; and a DCUtR attempt's
//! outcome is reported. ⚠ All on loopback — none of this is evidence of mobility. See the
//! design note for the off-LAN trial.
#![cfg(feature = "p2p")]

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ikigai_core::{
    Capability, EndpointSpace, Exact, FnEndpoint, Invocation, Iri, Kernel, ReprType,
    Representation, Request, Verb,
};
use ikigai_p2p::{
    circuit_addr, run_relay, spawn_peer, Answered, Multiaddr, Path, PeerConfig, PeerHandle, PeerId,
    PeerMinter, RelayAddrs, RelayPolicy, RelayReport, Report,
};
use ikigai_quic::Session;
use ikigai_wire::{Call, Reply, WireError};
use libp2p::identity::Keypair;
use tokio::sync::mpsc;

const LOOPBACK: &str = "/ip4/127.0.0.1/udp/0/quic-v1";
const PATIENCE: Duration = Duration::from_secs(30);

/// `urn:demo:cal` projects on the session capability — DETAIL with the detail scope,
/// freebusy otherwise — and counts every time it actually runs.
fn gated_kernel(runs: Arc<AtomicUsize>) -> Kernel {
    let cal = FnEndpoint::new("cal", move |inv: &Invocation<'_>| {
        runs.fetch_add(1, Ordering::SeqCst);
        let body = if inv.capability.allows("urn:cap:demo:detail") {
            "DETAIL"
        } else {
            "freebusy"
        };
        Ok(Representation::new(
            ReprType::new("text/plain"),
            body.as_bytes().to_vec(),
        ))
    });
    Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:demo:cal"), cal),
    ))
}

fn cal() -> Request {
    Request::new(Verb::Source, Iri::parse("urn:demo:cal").unwrap())
}

/// A minter over a one-entry table: `enrolled` gets a NARROW grant, everyone else nothing.
fn minter_for(enrolled: PeerId) -> PeerMinter {
    Arc::new(move |peer: &PeerId| {
        (*peer == enrolled).then(|| Session {
            capability: Capability::scoped(["urn:cap:demo:freebusy".to_string()]),
            file_segment: String::new(),
        })
    })
}

async fn wait_for<T>(
    rx: &mut mpsc::UnboundedReceiver<T>,
    what: &str,
    mut matches: impl FnMut(&T) -> bool,
) -> T
where
    T: std::fmt::Debug,
{
    let mut skipped = Vec::new();
    let found = tokio::time::timeout(PATIENCE, async {
        loop {
            let event = rx.recv().await.expect("reporter closed");
            if matches(&event) {
                return event;
            }
            skipped.push(format!("{event:?}"));
        }
    })
    .await;
    // On a timeout, say what DID happen — a `Failed` report skipped past is the diagnosis.
    found.unwrap_or_else(|_| panic!("timed out waiting for {what}; saw instead: {skipped:#?}"))
}

struct Relay {
    addr: Multiaddr,
    reports: mpsc::UnboundedReceiver<RelayReport>,
}

async fn start_relay(allowed: impl IntoIterator<Item = PeerId>) -> Relay {
    let keypair = Keypair::generate_ed25519();
    let relay_id = keypair.public().to_peer_id();
    let (tx, mut reports) = mpsc::unbounded_channel();
    let policy = RelayPolicy {
        allowed: allowed.into_iter().collect::<HashSet<_>>(),
        max_circuit_duration: Duration::from_secs(60),
        max_circuit_bytes: 1 << 20,
        max_reservations: 8,
        max_circuits: 8,
    };
    tokio::spawn(run_relay(
        keypair,
        policy,
        RelayAddrs {
            listen: vec![LOOPBACK.parse().unwrap()],
            external: vec![],
            confirm_listen_addrs: true,
        },
        Some(tx),
    ));
    let listening = wait_for(&mut reports, "the relay to listen", |e| {
        matches!(e, RelayReport::Listening(_))
    })
    .await;
    let RelayReport::Listening(addr) = listening else {
        unreachable!()
    };
    Relay {
        addr: addr.with_p2p(relay_id).unwrap(),
        reports,
    }
}

struct Peer {
    handle: PeerHandle,
    reports: mpsc::UnboundedReceiver<Report>,
}

struct Setup {
    keypair: Keypair,
    serve: Option<(Arc<Kernel>, PeerMinter)>,
    listen: Vec<Multiaddr>,
    relays: Vec<Multiaddr>,
    confirm_observed_addrs: bool,
}

fn start_peer(setup: Setup) -> Peer {
    let (tx, reports) = mpsc::unbounded_channel();
    let handle = spawn_peer(PeerConfig {
        keypair: setup.keypair,
        serve: setup.serve,
        listen: setup.listen,
        relays: setup.relays,
        external: vec![],
        confirm_observed_addrs: setup.confirm_observed_addrs,
        reports: Some(tx),
    })
    .unwrap();
    Peer { handle, reports }
}

/// Drain whatever a peer has reported so far without waiting.
fn drain(rx: &mut mpsc::UnboundedReceiver<Report>) -> Vec<Report> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        out.push(event);
    }
    out
}

fn text(answered: Answered) -> String {
    match answered.reply {
        Reply::Resolved(representation, _) => String::from_utf8(representation.bytes).unwrap(),
        other => panic!("expected a resolution, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wire_call_reaches_a_peer_that_is_reachable_only_through_the_relay() {
    let server_key = Keypair::generate_ed25519();
    let client_key = Keypair::generate_ed25519();
    let server_id = server_key.public().to_peer_id();
    let client_id = client_key.public().to_peer_id();
    let mut relay = start_relay([server_id, client_id]).await;

    let runs = Arc::new(AtomicUsize::new(0));
    let kernel = Arc::new(gated_kernel(runs.clone()));
    // The server has NO direct listen address and confirms no external one: the relay
    // circuit is the only way to it, and no hole punch has a candidate to punch from.
    let mut server = start_peer(Setup {
        keypair: server_key,
        serve: Some((kernel, minter_for(client_id))),
        listen: vec![],
        relays: vec![relay.addr.clone()],
        confirm_observed_addrs: false,
    });
    wait_for(&mut server.reports, "the reservation", |e| {
        matches!(e, Report::ReservationAccepted { .. })
    })
    .await;
    wait_for(
        &mut relay.reports,
        "the relay to accept it",
        |e| matches!(e, RelayReport::ReservationAccepted { peer } if *peer == server_id),
    )
    .await;

    let mut client = start_peer(Setup {
        keypair: client_key,
        serve: None,
        listen: vec![],
        relays: vec![],
        confirm_observed_addrs: false,
    });
    let through = circuit_addr(&relay.addr, server_id);

    // A plain call resolves under the NARROW grant the minter gave this PeerId, and says it
    // travelled through the relay.
    let answered = client
        .handle
        .call(server_id, vec![through.clone()], Call::Issue(cal()))
        .await
        .unwrap();
    assert_eq!(answered.path, Some(Path::Relayed));
    assert_eq!(text(answered), "freebusy");

    // A carried ROOT capability is clamped to the session — `IssueAs` behaves exactly as it
    // does on QUIC, because it is answered by the same function.
    let answered = client
        .handle
        .call(
            server_id,
            vec![through],
            Call::IssueAs(cal(), Capability::root()),
        )
        .await
        .unwrap();
    assert_eq!(
        text(answered),
        "freebusy",
        "a carried capability must never widen"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 2);

    // And the client never had a direct connection to the server.
    let seen = drain(&mut client.reports);
    let to_server: Vec<Path> = seen
        .iter()
        .filter_map(|e| match e {
            Report::Connected { peer, path, .. } if *peer == server_id => Some(*path),
            _ => None,
        })
        .collect();
    assert!(
        !to_server.is_empty() && to_server.iter().all(|p| *p == Path::Relayed),
        "expected only relayed connections to the server, saw {seen:#?}"
    );
    wait_for(&mut relay.reports, "the relay to carry the circuit", |e| {
        matches!(e, RelayReport::CircuitAccepted { src, dst } if *src == client_id && *dst == server_id)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unmapped_peer_id_is_denied_and_the_kernel_never_runs() {
    let server_key = Keypair::generate_ed25519();
    let enrolled = Keypair::generate_ed25519().public().to_peer_id();
    let stranger_key = Keypair::generate_ed25519();
    let server_id = server_key.public().to_peer_id();
    let stranger_id = stranger_key.public().to_peer_id();
    // The relay admits the stranger — relaying is reachability, not authority. The KERNEL's
    // grant table is what must say no.
    let relay = start_relay([server_id, stranger_id]).await;

    let runs = Arc::new(AtomicUsize::new(0));
    let kernel = Arc::new(gated_kernel(runs.clone()));
    let mut server = start_peer(Setup {
        keypair: server_key,
        serve: Some((kernel, minter_for(enrolled))),
        listen: vec![],
        relays: vec![relay.addr.clone()],
        confirm_observed_addrs: false,
    });
    wait_for(&mut server.reports, "the reservation", |e| {
        matches!(e, Report::ReservationAccepted { .. })
    })
    .await;

    let stranger = start_peer(Setup {
        keypair: stranger_key,
        serve: None,
        listen: vec![],
        relays: vec![],
        confirm_observed_addrs: false,
    });
    for call in [
        Call::Issue(cal()),
        Call::IssueAs(cal(), Capability::root()),
        Call::Entries,
    ] {
        let answered = stranger
            .handle
            .call(server_id, vec![circuit_addr(&relay.addr, server_id)], call)
            .await
            .unwrap();
        assert!(
            matches!(answered.reply, Reply::ErrorTyped(WireError::Denied(_))),
            "an unmapped PeerId must get a typed permanent denial, got {:?}",
            answered.reply
        );
    }
    assert_eq!(
        runs.load(Ordering::SeqCst),
        0,
        "a refused call must never reach the kernel"
    );
    wait_for(
        &mut server.reports,
        "the refusal to be reported",
        |e| matches!(e, Report::Refused { peer, .. } if *peer == stranger_id),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_relay_refuses_a_reservation_from_a_peer_not_on_its_allowlist() {
    let outsider_key = Keypair::generate_ed25519();
    let outsider_id = outsider_key.public().to_peer_id();
    // An allowlist that names someone else.
    let mut relay = start_relay([Keypair::generate_ed25519().public().to_peer_id()]).await;
    let mut outsider = start_peer(Setup {
        keypair: outsider_key,
        serve: None,
        listen: vec![],
        relays: vec![relay.addr.clone()],
        confirm_observed_addrs: false,
    });
    wait_for(
        &mut relay.reports,
        "the reservation to be denied",
        |e| matches!(e, RelayReport::ReservationDenied { peer } if *peer == outsider_id),
    )
    .await;
    assert!(
        !drain(&mut outsider.reports)
            .iter()
            .any(|e| matches!(e, Report::ReservationAccepted { .. })),
        "an unlisted peer must never hold a reservation"
    );
}

/// DCUtR on loopback. ⚠ This proves the MACHINERY runs and reports, not that hole punching
/// works across NATs: on loopback there is no NAT, so even a success here would be trivial.
/// It asserts that the relayed call works with both peers holding direct listeners, and
/// REPORTS the punch outcome and the path of later calls without requiring either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hole_punch_is_attempted_and_its_outcome_reported() {
    let server_key = Keypair::generate_ed25519();
    let client_key = Keypair::generate_ed25519();
    let server_id = server_key.public().to_peer_id();
    let client_id = client_key.public().to_peer_id();
    let relay = start_relay([server_id, client_id]).await;

    // Both peers listen directly AND confirm what identify reports observing — on loopback
    // that observation is exactly right (there is no NAT to rewrite it). The client learns
    // the server's direct address only through the DCUtR exchange over the relayed connection.
    let runs = Arc::new(AtomicUsize::new(0));
    let kernel = Arc::new(gated_kernel(runs));
    let mut server = start_peer(Setup {
        keypair: server_key,
        serve: Some((kernel, minter_for(client_id))),
        listen: vec![LOOPBACK.parse().unwrap()],
        relays: vec![relay.addr.clone()],
        confirm_observed_addrs: true,
    });
    // The snapshot applies at BOTH ends: the server's handler for the inbound circuit is
    // created with whatever candidates the server holds at that instant, and an empty list
    // is what the client reads as `NoAddresses`. A reservation can be accepted before the
    // relay's identify observation reaches the server, so wait for BOTH — in one pass, since
    // `wait_for` discards what it skips and either may arrive first.
    let (mut reserved, mut observed) = (false, false);
    tokio::time::timeout(PATIENCE, async {
        while !(reserved && observed) {
            match server.reports.recv().await.expect("reporter closed") {
                Report::ReservationAccepted { .. } => reserved = true,
                Report::Observed { .. } => observed = true,
                _ => {}
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("server: reservation accepted = {reserved}, observation received = {observed}")
    });

    let mut client = start_peer(Setup {
        keypair: client_key,
        serve: None,
        listen: vec![LOOPBACK.parse().unwrap()],
        relays: vec![],
        confirm_observed_addrs: true,
    });
    // Connect to the relay FIRST and wait for its identify observation. dcutr snapshots its
    // address candidates when a relayed connection is established (libp2p-dcutr 0.15
    // `behaviour.rs`), so a caller that dials the relay and the circuit at once cannot have
    // any. ⚠ NECESSARY, NOT SHOWN SUFFICIENT: with both ends waiting, the loopback punch
    // still fails with "Protocol error" (NoAddresses). The root cause is not established.
    client.handle.dial(relay.addr.clone()).unwrap();
    wait_for(
        &mut client.reports,
        "the relay's observation of the client",
        |e| matches!(e, Report::Observed { .. }),
    )
    .await;
    let through = vec![circuit_addr(&relay.addr, server_id)];
    let answered = client
        .handle
        .call(server_id, through.clone(), Call::Issue(cal()))
        .await
        .unwrap();
    assert_eq!(text(answered), "freebusy");

    let outcome = tokio::time::timeout(PATIENCE, async {
        loop {
            let (event, side) = tokio::select! {
                Some(event) = server.reports.recv() => (event, "server"),
                Some(event) = client.reports.recv() => (event, "client"),
            };
            if let Report::HolePunch { peer, result } = event {
                return (peer, result, side);
            }
        }
    })
    .await;
    match &outcome {
        Err(_) => eprintln!("DCUtR: no attempt was reported within {PATIENCE:?}"),
        Ok((peer, result, side)) => eprintln!("DCUtR ({side} side, with {peer}): {result:?}"),
    }
    // Whatever the punch did, calls keep working — and each says which path carried it.
    // (request-response spreads calls across EVERY connection to a peer, so after a
    // successful punch the relayed and direct paths alternate; see the design note.)
    let mut paths = Vec::new();
    for _ in 0..4 {
        let answered = client
            .handle
            .call(server_id, through.clone(), Call::Issue(cal()))
            .await
            .unwrap();
        paths.push(answered.path);
        assert_eq!(text(answered), "freebusy");
    }
    eprintln!("DCUtR: paths of the next four calls: {paths:?}");
    if let Ok((_, Ok(()), _)) = outcome {
        assert!(
            paths.contains(&Some(Path::Direct)),
            "a reported punch success must yield a direct path, saw {paths:?}"
        );
    }
}
