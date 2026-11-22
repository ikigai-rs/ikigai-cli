//! A door refuses a pinned client certificate outside its validity window: past its
//! `notAfter`, or before its `notBefore` (ledger #1826).
//!
//! Through cli 0.1.63 the door's verifier compared the presented certificate with the pinned
//! ones byte for byte and nothing else, so an expired certificate that was still on the trust
//! list kept connecting. Pinning says WHICH certificate; the window says WHEN, and both must
//! hold. Certificates minted by `ikigai cert generate` (and by the Python client) are valid
//! from 1975 to 4096, so this refuses only a certificate someone minted with a real window.
use std::sync::Arc;
use std::time::Duration;

use ikigai_core::{
    Capability, Description, EndpointSpace, Exact, FnEndpoint, Invocation, Iri, Kernel, ReprType,
    Representation, Request, Verb,
};
use ikigai_quic::{
    bind, connect_with, generate, serve_bounded_on, serve_trusting_on, Identity, Minter, Session,
    TrustList,
};
use ikigai_resolve::Resolver;

/// A kernel with one endpoint, so a connection can prove it was served.
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

fn minter() -> Minter {
    Arc::new(|_| {
        Some(Session {
            capability: Capability::root(),
            file_segment: String::new(),
            principal: None,
        })
    })
}

/// Whether `client` is served on a new connection to `addr`.
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

/// A door over a FIXED trust set (`serve_bounded_on`, every door before ledger #1825) and one
/// over a live list (`serve_trusting_on`, `serve quic://`): the window is the verifier's, so
/// both refuse alike.
#[test]
fn an_expired_or_not_yet_valid_pinned_certificate_is_refused_at_every_door() {
    let current = generate();
    let expired = identity_valid((2000, 1, 1), (2001, 1, 1));
    let early = identity_valid((4000, 1, 1), (4001, 1, 1));
    let window = identity_valid((2000, 1, 1), (4000, 1, 1));
    let pems: Vec<String> = [&current, &expired, &early, &window]
        .iter()
        .map(|identity| identity.cert_pem.clone())
        .collect();

    let server = generate();
    let fixed = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let fixed_addr = fixed.local_addr().unwrap();
    let live = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let live_addr = live.local_addr().unwrap();
    for (socket, live) in [(fixed, false), (live, true)] {
        let identity = Identity {
            cert_pem: server.cert_pem.clone(),
            key_pem: server.key_pem.clone(),
        };
        let pems = pems.clone();
        std::thread::spawn(move || {
            let _ = if live {
                let trust: TrustList = Arc::new(move || Ok(pems.clone()));
                serve_trusting_on(
                    Arc::new(kernel()),
                    socket,
                    &identity,
                    trust,
                    minter(),
                    Duration::from_secs(300),
                    None,
                )
            } else {
                serve_bounded_on(
                    kernel(),
                    socket,
                    &identity,
                    &pems,
                    minter(),
                    Duration::from_secs(300),
                    None,
                )
            };
        });
    }

    for addr in [fixed_addr, live_addr] {
        assert!(served(addr, &current, &server), "a current certificate");
        assert!(
            served(addr, &window, &server),
            "a certificate inside its window"
        );
        assert!(
            !served(addr, &expired, &server),
            "a pinned certificate past its notAfter must be refused"
        );
        assert!(
            !served(addr, &early, &server),
            "a pinned certificate before its notBefore must be refused"
        );
    }
}
