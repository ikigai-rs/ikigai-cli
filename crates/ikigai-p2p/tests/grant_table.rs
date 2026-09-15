//! ONE identity table: a PeerId is authorized by the host's own `clients.json` +
//! `grants.json`, read by `ikigai_embedded::clients::authority` — the very function the QUIC
//! server's minter calls with a certificate fingerprint — and an edit to that file revokes
//! the peer on its NEXT CALL over a connection that stays up.
//!
//! Its own test binary on purpose: it points `IKIGAI_CLIENTS`/`IKIGAI_GRANTS` at scratch
//! files, and environment variables are process-global.
#![cfg(feature = "p2p")]

use std::sync::Arc;
use std::time::Duration;

use ikigai_core::{
    Capability, EndpointSpace, Exact, FnEndpoint, Invocation, Iri, Kernel, ReprType,
    Representation, Request, Verb,
};
use ikigai_p2p::{
    circuit_addr, run_relay, spawn_peer, Path, PeerConfig, PeerId, PeerMinter, RelayAddrs,
    RelayPolicy, RelayReport, Report,
};
use ikigai_quic::Session;
use ikigai_wire::{Call, Reply, WireError};
use libp2p::identity::Keypair;
use tokio::sync::mpsc;

const LOOPBACK: &str = "/ip4/127.0.0.1/udp/0/quic-v1";

fn kernel() -> Kernel {
    let cal = FnEndpoint::new("cal", |inv: &Invocation<'_>| {
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

/// The minter a host would write: the PeerId's base58 form is the key, looked up in the
/// same file, through the same function, under the same fail-closed rules.
fn host_minter() -> PeerMinter {
    Arc::new(|peer: &PeerId| {
        ikigai_embedded::clients::authority(&peer.to_base58(), &Capability::root())
            .ok()
            .map(|(_, capability)| Session {
                capability,
                file_segment: String::new(),
            })
    })
}

async fn next<T>(rx: &mut mpsc::UnboundedReceiver<T>, mut hit: impl FnMut(&T) -> bool) -> T {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let event = rx.recv().await.expect("reporter closed");
            if hit(&event) {
                return event;
            }
        }
    })
    .await
    .expect("timed out")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_id_is_authorized_by_the_same_clients_json_and_an_edit_revokes_it() {
    let dir = std::env::temp_dir().join(format!("ikigai-p2p-grants-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let clients = dir.join("clients.json");
    let grants = dir.join("grants.json");
    std::fs::write(
        &grants,
        r#"{"freebusy": ["urn:cap:demo:freebusy"], "detail": ["urn:cap:demo:detail"]}"#,
    )
    .unwrap();
    std::env::set_var("IKIGAI_CLIENTS", &clients);
    std::env::set_var("IKIGAI_GRANTS", &grants);

    let server_key = Keypair::generate_ed25519();
    let client_key = Keypair::generate_ed25519();
    let server_id = server_key.public().to_peer_id();
    let client_id = client_key.public().to_peer_id();
    // A certificate fingerprint enrolled BESIDE the PeerId, naming a wider grant: one map.
    std::fs::write(
        &clients,
        format!(
            r#"{{"clients": {{
                "6f1c00000000000000000000000000000000000000000000000000000000abcd": "detail",
                "{client_id}": {{"grant": "freebusy", "label": "bug over p2p"}}
            }}}}"#
        ),
    )
    .unwrap();

    let relay_key = Keypair::generate_ed25519();
    let relay_id = relay_key.public().to_peer_id();
    let (relay_tx, mut relay_reports) = mpsc::unbounded_channel();
    tokio::spawn(run_relay(
        relay_key,
        RelayPolicy {
            allowed: [server_id, client_id].into_iter().collect(),
            max_circuit_duration: Duration::from_secs(60),
            max_circuit_bytes: 1 << 20,
            max_reservations: 4,
            max_circuits: 4,
        },
        RelayAddrs {
            listen: vec![LOOPBACK.parse().unwrap()],
            external: vec![],
            confirm_listen_addrs: true,
        },
        Some(relay_tx),
    ));
    let RelayReport::Listening(relay_addr) = next(&mut relay_reports, |e| {
        matches!(e, RelayReport::Listening(_))
    })
    .await
    else {
        unreachable!()
    };
    let relay_addr = relay_addr.with_p2p(relay_id).unwrap();

    let (server_tx, mut server_reports) = mpsc::unbounded_channel();
    spawn_peer(PeerConfig {
        keypair: server_key,
        serve: Some((Arc::new(kernel()), host_minter())),
        listen: vec![],
        relays: vec![relay_addr.clone()],
        external: vec![],
        confirm_observed_addrs: false,
        reports: Some(server_tx),
    })
    .unwrap();
    next(&mut server_reports, |e| {
        matches!(e, Report::ReservationAccepted { .. })
    })
    .await;

    let client = spawn_peer(PeerConfig {
        keypair: client_key,
        serve: None,
        listen: vec![],
        relays: vec![],
        external: vec![],
        confirm_observed_addrs: false,
        reports: None,
    })
    .unwrap();
    let cal = || Request::new(Verb::Source, Iri::parse("urn:demo:cal").unwrap());
    let through = vec![circuit_addr(&relay_addr, server_id)];

    // Enrolled: the grant's scopes, nothing more — even when root is carried.
    let answered = client
        .call(
            server_id,
            through.clone(),
            Call::IssueAs(cal(), Capability::root()),
        )
        .await
        .unwrap();
    assert_eq!(answered.path, Some(Path::Relayed));
    match answered.reply {
        Reply::Resolved(r, _) => assert_eq!(r.bytes, b"freebusy"),
        other => panic!("expected freebusy, got {other:?}"),
    }

    // The operator deletes the entry. The relayed connection stays up; the NEXT call is
    // minted afresh from the edited file and refused.
    std::fs::write(&clients, r#"{"clients": {}}"#).unwrap();
    let answered = client
        .call(server_id, through, Call::Issue(cal()))
        .await
        .unwrap();
    assert!(
        matches!(answered.reply, Reply::ErrorTyped(WireError::Denied(_))),
        "a revoked PeerId must be refused on its next call, got {:?}",
        answered.reply
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
