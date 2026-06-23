//! QUIC transport with mutually-pinned TLS between the `ikigai` REPL and a remote
//! kernel server.
//!
//! Like the IPC transport, [`serve`] runs a kernel and [`connect`] returns a
//! [`Resolver`] driving it — here over QUIC (TLS 1.3) instead of a Unix socket, so
//! it works across the network. Each call is one bidirectional QUIC stream
//! carrying a postcard [`Call`]/[`Reply`]; the stream boundary frames the message.
//!
//! Trust is **mutual certificate pinning**, no CA: each side is configured with
//! its own self-signed identity ([`generate`]) and the *exact* peer certificate
//! it will accept. The client pins the server's cert; the server requires and
//! pins the client's. A capability bound to that identity can layer on later.
//!
//! quinn is async; the sync [`Resolver`] hides a `tokio` runtime, just as the
//! embedded kernel hides its executor.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use ikigai_core::{Capability, Kernel, Representation, Request, SpaceEntry};
use ikigai_resolve::{CacheStatus, Resolver};
use ikigai_wire::{decode, encode, Call, Reply};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use tokio::runtime::Runtime;

/// The ALPN protocol id — both ends must agree on it.
const ALPN: &[u8] = b"ikigai/0";

/// The largest message accepted off a stream (guards `read_to_end`).
const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// A self-signed certificate and its private key, as PEM.
pub struct Identity {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Generate a fresh self-signed identity. Trust is by pinning the exact
/// certificate, so the subject name is cosmetic.
pub fn generate() -> Identity {
    let certified = rcgen::generate_simple_self_signed(vec!["ikigai".to_string()])
        .expect("self-signed certificate generation");
    Identity {
        cert_pem: certified.cert.pem(),
        key_pem: certified.key_pair.serialize_pem(),
    }
}

/// Run `kernel` as a QUIC server on `addr`, presenting `identity` and accepting
/// only the client whose certificate is `trusted_client_cert_pem`. Blocks until
/// an unrecoverable endpoint error.
pub fn serve(
    kernel: Kernel,
    addr: SocketAddr,
    identity: &Identity,
    trusted_client_cert_pem: &str,
) -> io::Result<()> {
    let config = server_config(identity, trusted_client_cert_pem)?;
    let runtime = Runtime::new()?;
    runtime.block_on(async move {
        let endpoint = quinn::Endpoint::server(config, addr)?;
        let kernel = Arc::new(kernel);
        while let Some(incoming) = endpoint.accept().await {
            let kernel = Arc::clone(&kernel);
            tokio::spawn(async move {
                if let Ok(connection) = incoming.await {
                    serve_connection(&kernel, connection).await;
                }
            });
        }
        Ok(())
    })
}

/// Answer calls on one connection until the peer closes it.
async fn serve_connection(kernel: &Kernel, connection: quinn::Connection) {
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        let bytes = match recv.read_to_end(MAX_MESSAGE).await {
            Ok(bytes) => bytes,
            Err(_) => return,
        };
        let reply = match decode::<Call>(&bytes) {
            Ok(call) => dispatch(kernel, call),
            Err(e) => Reply::Error(format!("malformed call: {e}")),
        };
        if let Ok(out) = encode(&reply) {
            let _ = send.write_all(&out).await;
            let _ = send.finish();
        }
    }
}

/// Answer one [`Call`] against the local kernel, reusing its [`Resolver`] impl.
fn dispatch(kernel: &Kernel, call: Call) -> Reply {
    match call {
        Call::Issue(request) => match Resolver::issue(kernel, request) {
            Ok((representation, status)) => Reply::Resolved(representation, status),
            Err(message) => Reply::Error(message),
        },
        // QUIC does not honor capability-on-the-wire yet: a QUIC peer isn't
        // authenticated (gated on remote auth, #36), so a carried capability is
        // not trusted. Resolve under the server's default authority, ignoring it.
        // (The QUIC client never sends this today — its resolver doesn't override
        // `issue_as` — but the arm keeps the match safe and exhaustive.)
        Call::IssueAs(request, _capability) => match Resolver::issue(kernel, request) {
            Ok((representation, status)) => Reply::Resolved(representation, status),
            Err(message) => Reply::Error(message),
        },
        Call::IsCached(request) => {
            Reply::Cached(Resolver::is_cached(kernel, &request, &Capability::root()))
        }
        Call::Entries => Reply::Entries(Resolver::entries(kernel)),
    }
}

/// Connect to a QUIC kernel server at `addr`, presenting `identity` and pinning
/// the server certificate `trusted_server_cert_pem`.
pub fn connect(
    addr: SocketAddr,
    identity: &Identity,
    trusted_server_cert_pem: &str,
) -> io::Result<QuicResolver> {
    let config = client_config(identity, trusted_server_cert_pem)?;
    let runtime = Runtime::new()?;
    let (endpoint, connection) = runtime.block_on(async move {
        let bind: SocketAddr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        }
        .parse()
        .expect("valid bind address");
        let mut endpoint = quinn::Endpoint::client(bind)?;
        endpoint.set_default_client_config(config);
        let connection = endpoint
            .connect(addr, "ikigai")
            .map_err(other)?
            .await
            .map_err(other)?;
        io::Result::Ok((endpoint, connection))
    })?;
    Ok(QuicResolver {
        runtime,
        _endpoint: endpoint,
        connection,
    })
}

/// A [`Resolver`] backed by a kernel server over QUIC.
pub struct QuicResolver {
    runtime: Runtime,
    /// Kept alive for the duration of the connection.
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

impl QuicResolver {
    /// One call → one bidirectional stream → one reply.
    fn round_trip(&self, call: Call) -> io::Result<Reply> {
        let request = encode(&call)?;
        self.runtime.block_on(async {
            let (mut send, mut recv) = self.connection.open_bi().await.map_err(other)?;
            send.write_all(&request).await.map_err(other)?;
            send.finish().map_err(other)?;
            let bytes = recv.read_to_end(MAX_MESSAGE).await.map_err(other)?;
            decode(&bytes)
        })
    }
}

impl Drop for QuicResolver {
    fn drop(&mut self) {
        // Tell the peer we're done so it stops promptly instead of waiting out
        // the idle timeout; then let the endpoint flush the close frame.
        self.connection.close(0u32.into(), b"bye");
        let _ = self.runtime.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                self._endpoint.wait_idle(),
            )
            .await
        });
    }
}

impl Resolver for QuicResolver {
    fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), String> {
        match self
            .round_trip(Call::Issue(request))
            .map_err(|e| e.to_string())?
        {
            Reply::Resolved(representation, status) => Ok((representation, status)),
            Reply::Error(message) => Err(message),
            other => Err(format!("unexpected reply to Issue: {other:?}")),
        }
    }

    fn is_cached(&self, request: &Request, capability: &Capability) -> bool {
        // Resolves under the server's authority; the wire doesn't carry the caller's
        // capability yet (capability-on-the-wire is a TODO), so it's accepted but not sent.
        let _ = capability;
        matches!(
            self.round_trip(Call::IsCached(request.clone())),
            Ok(Reply::Cached(true))
        )
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        match self.round_trip(Call::Entries) {
            Ok(Reply::Entries(entries)) => entries,
            _ => None,
        }
    }

    fn transport(&self) -> String {
        "quic · network (HTTP/3), mutually-pinned TLS".to_string()
    }
}

// --- TLS configuration ------------------------------------------------------

fn server_config(
    identity: &Identity,
    trusted_client_cert_pem: &str,
) -> io::Result<quinn::ServerConfig> {
    let verifier = Arc::new(PinnedPeer::new(load_cert(trusted_client_cert_pem)?));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(other)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![load_cert(&identity.cert_pem)?],
            load_key(&identity.key_pem)?,
        )
        .map_err(other)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(other)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic)))
}

fn client_config(
    identity: &Identity,
    trusted_server_cert_pem: &str,
) -> io::Result<quinn::ClientConfig> {
    let verifier = Arc::new(PinnedPeer::new(load_cert(trusted_server_cert_pem)?));
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(other)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            vec![load_cert(&identity.cert_pem)?],
            load_key(&identity.key_pem)?,
        )
        .map_err(other)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(other)?;
    Ok(quinn::ClientConfig::new(Arc::new(quic)))
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A verifier that accepts exactly one pinned peer certificate (used as both the
/// client's server-verifier and the server's client-verifier). Signature
/// checking is delegated to the crypto provider; only the certificate identity
/// is pinned.
#[derive(Debug)]
struct PinnedPeer {
    pinned: CertificateDer<'static>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedPeer {
    fn new(pinned: CertificateDer<'static>) -> Self {
        PinnedPeer {
            pinned,
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }

    fn matches(&self, presented: &CertificateDer<'_>) -> bool {
        presented.as_ref() == self.pinned.as_ref()
    }
}

impl ServerCertVerifier for PinnedPeer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.matches(end_entity) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate does not match the pinned certificate".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

impl ClientCertVerifier for PinnedPeer {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if self.matches(end_entity) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "client certificate does not match the pinned certificate".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

// --- PEM loading ------------------------------------------------------------

fn load_cert(pem: &str) -> io::Result<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no certificate in PEM"))?
        .map_err(other)
}

fn load_key(pem: &str) -> io::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut pem.as_bytes())?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key in PEM"))
}

fn other<E: std::fmt::Display>(error: E) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    use ikigai_core::{builtins, ArgRef, EndpointSpace, Exact, Iri, Verb};

    fn kernel() -> Kernel {
        Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:fn:toUpper"), builtins::to_upper()),
        ))
    }

    fn upper(text: &str) -> Request {
        Request::new(Verb::Source, Iri::parse("urn:fn:toUpper").unwrap())
            .with_arg("in", ArgRef::Inline(text.as_bytes().to_vec()))
    }

    #[test]
    fn round_trips_over_quic_with_pinned_certs() {
        let server_id = generate();
        let client_id = generate();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Bind the server first so we can learn its actual (ephemeral) port.
        let server_cfg = server_config(&server_id, &client_id.cert_pem).unwrap();
        let rt = Runtime::new().unwrap();
        let endpoint = rt
            .block_on(async { quinn::Endpoint::server(server_cfg, addr) })
            .unwrap();
        let server_addr = endpoint.local_addr().unwrap();

        let kernel = Arc::new(kernel());
        let server = {
            let kernel = Arc::clone(&kernel);
            thread::spawn(move || {
                rt.block_on(async move {
                    let incoming = endpoint.accept().await.unwrap();
                    let connection = incoming.await.unwrap();
                    serve_connection(&kernel, connection).await;
                });
            })
        };

        let client = connect(server_addr, &client_id, &server_id.cert_pem).unwrap();
        let (representation, first) = client.issue(upper("hi")).unwrap();
        assert_eq!(representation.bytes, b"HI");
        assert_eq!(first, CacheStatus::Miss);
        let (_, second) = client.issue(upper("hi")).unwrap();
        assert_eq!(second, CacheStatus::Hit);
        assert!(client.is_cached(&upper("hi"), &Capability::root()));
        assert!(client
            .entries()
            .unwrap()
            .iter()
            .any(|e| e.endpoint == "toUpper"));

        drop(client); // closes the connection → the handler loop ends
        server.join().unwrap();
    }

    #[test]
    fn a_wrong_pin_is_rejected() {
        let server_id = generate();
        let client_id = generate();
        let impostor = generate();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let server_cfg = server_config(&server_id, &client_id.cert_pem).unwrap();
        let rt = Runtime::new().unwrap();
        let endpoint = rt
            .block_on(async { quinn::Endpoint::server(server_cfg, addr) })
            .unwrap();
        let server_addr = endpoint.local_addr().unwrap();
        let server = thread::spawn(move || {
            rt.block_on(async move {
                if let Some(incoming) = endpoint.accept().await {
                    let _ = incoming.await; // handshake will fail
                }
            });
        });

        // The client pins the impostor's cert, not the server's → connection fails.
        let result = connect(server_addr, &client_id, &impostor.cert_pem)
            .and_then(|client| client.issue(upper("hi")).map_err(other));
        assert!(result.is_err());
        server.join().unwrap();
    }
}
