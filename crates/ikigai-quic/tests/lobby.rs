//! A door with a LOBBY (ledger #2009) admits a client certificate that is not on its trust list,
//! and hands it to a separate minter that decides what a stranger may do.
//!
//! Through cli 0.1.68 every door refused an unlisted certificate at the TLS handshake, so a new
//! node could not reach a layer host's lobby to ask to be enrolled. [`serve_lobby_on`] accepts
//! any certificate inside its validity window at TLS and routes it after the handshake: a
//! listed certificate to the door's usual minter, any other to the lobby's.
//!
//! Whether a connection got past TLS is read from the minters, not from error text: a refusal
//! at the handshake reaches NEITHER minter, so each counts the fingerprints it was asked about.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ikigai_core::{
    Capability, Description, EndpointSpace, Error, Exact, FnEndpoint, Invocation, Iri, Kernel,
    ReprType, Representation, Request, Verb,
};
use ikigai_quic::{
    bind, connect_with, fingerprint_of_pem, generate, serve_lobby_on, serve_trusting_on, Identity,
    Minter, Session, TrustList,
};
use ikigai_resolve::Resolver;

/// The capability a lobby mints in these tests: the one endpoint a stranger may use.
const SAY: &str = "urn:cap:test:say";

/// A kernel with three endpoints: `urn:test:say` (requires [`SAY`]), `urn:test:other`
/// (requires another capability) and `urn:test:admin` (requires a third).
fn kernel() -> Kernel {
    let endpoint = |name: &'static str, requires: &'static str| {
        FnEndpoint::new(name, move |_inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                name.as_bytes().to_vec(),
            ))
        })
        .with_description(Description::new(name).verb(Verb::Source).requires(requires))
    };
    Kernel::new(Arc::new(
        EndpointSpace::new()
            .bind(Exact::new("urn:test:say"), endpoint("say", SAY))
            .bind(
                Exact::new("urn:test:other"),
                endpoint("other", "urn:cap:test:other"),
            )
            .bind(
                Exact::new("urn:test:admin"),
                endpoint("admin", "urn:cap:test:admin"),
            ),
    ))
}

/// A self-signed identity valid from `from` to `until` (year, month, day).
fn identity_valid(from: (i32, u8, u8), until: (i32, u8, u8)) -> Identity {
    let mut params = rcgen::CertificateParams::new(vec!["ikigai".to_string()]).unwrap();
    params.not_before = rcgen::date_time_ymd(from.0, from.1, from.2);
    params.not_after = rcgen::date_time_ymd(until.0, until.1, until.2);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    Identity {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

/// The fingerprints a minter was asked about, in order.
type Asked = Arc<Mutex<Vec<String>>>;

/// What the trust list reads.
type Listed = Arc<Mutex<Result<Vec<String>, String>>>;

/// A minter that records each fingerprint and mints `scopes` (`None`: root), or refuses when
/// `refuse` is set.
fn recording(asked: &Asked, scopes: Option<Vec<&'static str>>, refuse: bool) -> Minter {
    let asked = Arc::clone(asked);
    Arc::new(move |peer| {
        asked.lock().unwrap().push(peer.fingerprint.clone());
        if refuse {
            return None;
        }
        Some(Session {
            capability: scopes
                .clone()
                .map_or_else(Capability::root, Capability::scoped),
            file_segment: String::new(),
            principal: None,
        })
    })
}

struct Door {
    addr: std::net::SocketAddr,
    server: Identity,
    trusted: Asked,
    lobby: Asked,
}

/// A door over `listed`: a lobby door when `lobby` is `Some(refuse)`, a plain trusting door
/// (`serve_trusting_on`, the door with no lobby) when it is `None`. A trusted client gets root;
/// the lobby mints only [`SAY`].
fn door(listed: &Listed, lobby: Option<bool>) -> Door {
    let server = generate();
    let socket = bind("127.0.0.1:0".parse().unwrap()).expect("a UDP socket");
    let addr = socket.local_addr().expect("its address");
    let read = Arc::clone(listed);
    let trust: TrustList =
        Arc::new(move || read.lock().unwrap().clone().map_err(std::io::Error::other));
    let trusted: Asked = Arc::default();
    let lobbied: Asked = Arc::default();
    let minter = recording(&trusted, None, false);
    let identity = Identity {
        cert_pem: server.cert_pem.clone(),
        key_pem: server.key_pem.clone(),
    };
    let lobby_minter = lobby.map(|refuse| recording(&lobbied, Some(vec![SAY]), refuse));
    std::thread::spawn(move || {
        let kernel = Arc::new(kernel());
        let idle = Duration::from_secs(300);
        let _ = match lobby_minter {
            Some(lobby) => {
                serve_lobby_on(kernel, socket, &identity, trust, minter, lobby, idle, None)
            }
            None => serve_trusting_on(kernel, socket, &identity, trust, minter, idle, None),
        };
    });
    Door {
        addr,
        server,
        trusted,
        lobby: lobbied,
    }
}

/// One Source of `target` on a NEW connection: the answer's bytes, or the error.
fn source(door: &Door, client: &Identity, target: &str) -> Result<String, String> {
    let resolver = connect_with(
        door.addr,
        client,
        &door.server.cert_pem,
        Duration::from_secs(10),
    )
    .map_err(|e| format!("connect: {e}"))?;
    resolver
        .issue(Request::new(Verb::Source, Iri::parse(target).unwrap()))
        .map(|(answer, _)| String::from_utf8(answer.bytes).unwrap())
        .map_err(|e| match e {
            Error::Denied(why) => format!("denied: {why}"),
            other => format!("{other}"),
        })
}

fn fp(identity: &Identity) -> String {
    fingerprint_of_pem(&identity.cert_pem).unwrap()
}

fn asked(list: &Asked) -> Vec<String> {
    list.lock().unwrap().clone()
}

#[test]
fn an_unlisted_certificate_reaches_what_the_lobby_mints_and_nothing_else() {
    let (enrolled, stranger) = (generate(), generate());
    let listed: Listed = Arc::new(Mutex::new(Ok(vec![enrolled.cert_pem.clone()])));
    let door = door(&listed, Some(false));

    assert_eq!(
        source(&door, &stranger, "urn:test:say").as_deref(),
        Ok("say")
    );
    for target in ["urn:test:other", "urn:test:admin"] {
        let answer = source(&door, &stranger, target);
        assert!(
            answer.as_ref().is_err_and(|e| e.starts_with("denied")),
            "a stranger holds only the lobby's capability, so {target} is Denied: {answer:?}"
        );
    }
    assert!(
        asked(&door.lobby).iter().all(|f| *f == fp(&stranger)),
        "the lobby was asked about the stranger's own fingerprint"
    );
    assert!(
        asked(&door.trusted).is_empty(),
        "an unlisted certificate never reaches the trusted minter"
    );
}

#[test]
fn a_listed_certificate_is_served_by_the_trusted_minter_exactly_as_before() {
    let enrolled = generate();
    let listed: Listed = Arc::new(Mutex::new(Ok(vec![enrolled.cert_pem.clone()])));
    let door = door(&listed, Some(false));

    for (target, name) in [
        ("urn:test:say", "say"),
        ("urn:test:other", "other"),
        ("urn:test:admin", "admin"),
    ] {
        assert_eq!(source(&door, &enrolled, target).as_deref(), Ok(name));
    }
    assert_eq!(asked(&door.trusted), vec![fp(&enrolled); 3]);
    assert!(
        asked(&door.lobby).is_empty(),
        "a listed certificate never reaches the lobby"
    );
}

/// The trust list is read per connection on a lobby door too: a certificate added to it moves
/// from the lobby to its full grant at the next connection, and one removed moves back, with
/// no restart (ledger #1825 on this door).
#[test]
fn a_certificate_added_to_or_removed_from_the_list_moves_at_its_next_connection() {
    let node = generate();
    let listed: Listed = Arc::new(Mutex::new(Ok(Vec::new())));
    let door = door(&listed, Some(false));

    assert!(
        source(&door, &node, "urn:test:admin").is_err(),
        "lobby only"
    );
    listed
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .push(node.cert_pem.clone());
    assert_eq!(
        source(&door, &node, "urn:test:admin").as_deref(),
        Ok("admin"),
        "enrolled while the door serves: the full grant at its next connection"
    );
    *listed.lock().unwrap() = Ok(Vec::new());
    assert!(
        source(&door, &node, "urn:test:admin").is_err(),
        "removed from the list: back to the lobby, never to the trusted minter"
    );
    assert_eq!(asked(&door.trusted), vec![fp(&node)]);
    assert_eq!(asked(&door.lobby), vec![fp(&node); 2]);
}

#[test]
fn a_lobby_that_refuses_closes_the_connection() {
    let stranger = generate();
    let listed: Listed = Arc::new(Mutex::new(Ok(Vec::new())));
    let door = door(&listed, Some(true));
    assert!(source(&door, &stranger, "urn:test:say").is_err());
    // The resolver redials once when a connection closes under a read, so the lobby may be
    // asked twice; what matters is that it WAS asked (past TLS) and only about this stranger.
    let lobby = asked(&door.lobby);
    assert!(
        !lobby.is_empty() && lobby.iter().all(|f| *f == fp(&stranger)),
        "past TLS, refused by the lobby: {lobby:?}"
    );
    assert!(asked(&door.trusted).is_empty());
}

#[test]
fn an_unreadable_list_serves_nobody_on_a_lobby_door() {
    let enrolled = generate();
    let listed: Listed = Arc::new(Mutex::new(Ok(vec![enrolled.cert_pem.clone()])));
    let door = door(&listed, Some(false));
    *listed.lock().unwrap() = Err("the trust directory went away".to_string());
    assert!(source(&door, &enrolled, "urn:test:say").is_err());
    assert!(
        asked(&door.trusted).is_empty() && asked(&door.lobby).is_empty(),
        "a door that cannot tell an enrolled client from a stranger mints for neither"
    );
}

#[test]
fn an_unlisted_certificate_outside_its_window_is_refused_at_tls() {
    let expired = identity_valid((2000, 1, 1), (2001, 1, 1));
    let early = identity_valid((4000, 1, 1), (4001, 1, 1));
    let window = identity_valid((2000, 1, 1), (4000, 1, 1));
    let listed: Listed = Arc::new(Mutex::new(Ok(Vec::new())));
    let door = door(&listed, Some(false));

    assert!(source(&door, &expired, "urn:test:say").is_err());
    assert!(source(&door, &early, "urn:test:say").is_err());
    assert!(
        asked(&door.lobby).is_empty(),
        "a certificate outside its window never gets past TLS to the lobby"
    );
    assert_eq!(
        source(&door, &window, "urn:test:say").as_deref(),
        Ok("say"),
        "one inside its window does"
    );
    assert_eq!(asked(&door.lobby), vec![fp(&window)]);
}

/// The default is unchanged: a door with no lobby refuses an unlisted certificate at TLS, so
/// its minter is never asked.
#[test]
fn a_door_without_a_lobby_still_refuses_an_unlisted_certificate_at_tls() {
    let (enrolled, stranger) = (generate(), generate());
    let listed: Listed = Arc::new(Mutex::new(Ok(vec![enrolled.cert_pem.clone()])));
    let door = door(&listed, None);

    assert!(source(&door, &stranger, "urn:test:say").is_err());
    assert!(
        asked(&door.trusted).is_empty(),
        "refused at the handshake: the minter is never asked"
    );
    assert_eq!(
        source(&door, &enrolled, "urn:test:say").as_deref(),
        Ok("say")
    );
    assert_eq!(asked(&door.trusted), vec![fp(&enrolled)]);
}

/// A lobby door's list is checked at start, as every trusting door's is.
#[test]
fn a_bad_list_at_start_stops_a_lobby_door() {
    let server = generate();
    let serve = |trust: TrustList| {
        let socket = bind("127.0.0.1:0".parse().unwrap()).expect("a UDP socket");
        serve_lobby_on(
            Arc::new(kernel()),
            socket,
            &server,
            trust,
            Arc::new(|_| None),
            Arc::new(|_| None),
            Duration::from_secs(300),
            None,
        )
    };
    assert!(serve(Arc::new(|| Err(std::io::Error::other("unreadable")))).is_err());
    assert!(serve(Arc::new(|| Ok(vec!["not a certificate".to_string()]))).is_err());
}
