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
//! pins the client's. The authenticated certificate is then the CREDENTIAL: a
//! [`Minter`] turns the peer's [`PeerIdentity`] into the [`Session`] whose
//! capability bounds every call on that connection — or refuses it outright.
//!
//! quinn is async; the sync [`Resolver`] hides a `tokio` runtime, just as the
//! embedded kernel hides its executor.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use ikigai_core::{Capability, Error, Iri, Kernel, Representation, Request, SpaceEntry, Tracer};
use ikigai_resolve::{scoped_entries, CacheStatus, Resolver, SpanCollector};
use ikigai_wire::{decode, encode, Call, Reply, TraceContext};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use tokio::runtime::Runtime;

/// The ALPN protocol ids — since v7, exactly one: `ikigai/{PROTOCOL_VERSION}`.
/// The TLS handshake IS the version gate on this transport; a version-mismatched
/// peer fails the handshake at connect (mDNS TXT advertises the version
/// pre-connect, which is where the human-readable hint lives).
fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![ikigai_wire::alpn()]
}

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
/// The per-connection authority and namespace, minted from the authenticated client
/// certificate. `capability` bounds every call on the connection; `file_segment`
/// transparently roots its `urn:file:` namespace at `<file_segment>/…`, so a tenant
/// addresses files as if its segment were the root and never sees another's.
pub struct Session {
    pub capability: Capability,
    pub file_segment: String,
}

/// Who the mTLS handshake authenticated, in the two spellings a host needs.
///
/// Passed as a struct rather than as widening positional arguments because the two
/// ids are NOT interchangeable and a call site should have to say which it means:
/// `segment_id` is a *namespace* (it names on-disk tenant directories, so it can
/// never be recomputed differently without orphaning data), `fingerprint` is an
/// *identity* (it is what an operator writes in a config file, so it must be stable
/// across toolchains and match what certificate tooling prints). A third derived
/// attribute later adds a field instead of rewriting every minter signature.
pub struct PeerIdentity {
    /// The legacy namespace id — see [`peer_cert_id`].
    pub segment_id: String,
    /// Lowercase hex SHA-256 of the leaf certificate DER — see [`fingerprint`].
    pub fingerprint: String,
}

impl PeerIdentity {
    /// Derive both ids from a post-handshake connection.
    fn of(connection: &quinn::Connection) -> Self {
        PeerIdentity {
            segment_id: peer_cert_id(connection),
            fingerprint: cert_fingerprint(connection),
        }
    }
}

/// Mints the authority for one connection from the identity that authenticated it,
/// or **refuses** the connection by returning `None`.
///
/// Refusal is the fail-closed path: a host that cannot decide what a certificate may
/// do must not fall back to a shared ceiling or to root. The minter is also where the
/// refusal is *logged* — it holds the operator context (config paths, grant names)
/// that makes a log line actionable; this crate only closes the connection.
pub type Minter = Arc<dyn Fn(&PeerIdentity) -> Option<Session> + Send + Sync>;

/// The QUIC application close code for a peer whose certificate authenticated but
/// carries no authority. Distinct from a handshake failure: the cert IS trusted, the
/// *authorization* is missing.
const UNAUTHORIZED: u32 = 1;

/// How long a connection may be SILENT before either side declares it dead.
///
/// Generous on purpose, mirroring `ipc.timeout` (cli #259): the server says nothing
/// until a resolution finishes, so for a long resolution — a 70B loading ~40GB, a
/// hard question generating for minutes — the silence IS the work. quinn's ~30s
/// default killed exactly those calls mid-generation while the model kept computing.
/// The cost is symmetric: a peer that dies MID-REQUEST now takes up to this long to
/// notice (the 5s dial bound still catches a dead peer at connect time). A deadline
/// that cannot tell "hung" from "busy" reports the wrong thing confidently, which is
/// worse than reporting late. `quic.timeout` (seconds) in the host config overrides.
pub const DEFAULT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

pub fn serve(
    kernel: Kernel,
    addr: SocketAddr,
    identity: &Identity,
    trusted_client_cert_pems: &[String],
    minter: Minter,
) -> io::Result<()> {
    serve_with(
        kernel,
        addr,
        identity,
        trusted_client_cert_pems,
        minter,
        DEFAULT_IDLE_TIMEOUT,
    )
}

/// [`serve`] with an explicit idle timeout (see [`DEFAULT_IDLE_TIMEOUT`]).
pub fn serve_with(
    kernel: Kernel,
    addr: SocketAddr,
    identity: &Identity,
    trusted_client_cert_pems: &[String],
    minter: Minter,
    idle: std::time::Duration,
) -> io::Result<()> {
    let config = server_config(identity, trusted_client_cert_pems, idle)?;
    let runtime = Runtime::new()?;
    runtime.block_on(async move {
        let endpoint = bind_endpoint(config, addr)?;
        let kernel = Arc::new(kernel);
        while let Some(incoming) = endpoint.accept().await {
            let kernel = Arc::clone(&kernel);
            let minter = Arc::clone(&minter);
            tokio::spawn(async move {
                if let Ok(connection) = incoming.await {
                    // mTLS verified the peer is one of the enrolled clients; mint that
                    // principal's session from *which* cert authenticated — multi-tenant
                    // capability-on-the-wire. Minted PER CONNECTION and never cached, so
                    // an operator editing the authority config revokes a client's rights
                    // on its next connection rather than at the end of some TTL.
                    match minter(&PeerIdentity::of(&connection)) {
                        Some(session) => serve_connection(&kernel, connection, &session).await,
                        // Authenticated but not authorized: close rather than serve. The
                        // alternative — falling back to a shared ceiling — is how a
                        // forgotten config entry silently becomes an over-grant.
                        None => connection.close(
                            UNAUTHORIZED.into(),
                            b"no authority is configured for this client certificate",
                        ),
                    }
                }
            });
        }
        Ok(())
    })
}

/// Bind the server endpoint. On a **wildcard** address (`0.0.0.0` or `[::]`), bind a
/// single **dual-stack** IPv6 socket (`IPV6_V6ONLY` off) so it accepts BOTH IPv4
/// (as v4-mapped) and IPv6 — a client dialing either family reaches it. This is the
/// real fix for the `.local`-resolves-to-both-families-and-picks-IPv6 timeout: the
/// server no longer cares which family the name resolved to. A specific bind address
/// is honored as-is (`quinn::Endpoint::server`), single-family.
fn bind_endpoint(config: quinn::ServerConfig, addr: SocketAddr) -> io::Result<quinn::Endpoint> {
    if !addr.ip().is_unspecified() {
        return quinn::Endpoint::server(config, addr);
    }
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?; // dual-stack: also accept IPv4 (v4-mapped)
    let bind = SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), addr.port());
    socket.bind(&bind.into())?;
    let udp: std::net::UdpSocket = socket.into();
    udp.set_nonblocking(true)?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        udp,
        Arc::new(quinn::TokioRuntime),
    )
}

/// The leaf certificate DER the peer presented, if any (quinn exposes it
/// post-handshake).
fn peer_leaf_der(connection: &quinn::Connection) -> Option<Vec<u8>> {
    connection
        .peer_identity()
        .and_then(|any| any.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|chain| chain.first().map(|c| c.as_ref().to_vec()))
}

/// The **stable** fingerprint of the connection's authenticated client: lowercase
/// hex SHA-256 of its leaf certificate DER. `anonymous` if the peer presented no
/// cert (unreachable with the client-cert verifier in force).
///
/// This is the id an operator writes in a config file, so it has two hard
/// requirements [`peer_cert_id`] cannot meet. It must be stable *forever* —
/// `DefaultHasher` is explicitly not guaranteed stable across Rust releases, so
/// keying a config on it would silently re-map every enrolled client on some
/// future toolchain upgrade. And it must be *obtainable*: this is byte-for-byte
/// what `openssl x509 -noout -fingerprint -sha256` prints (minus the colons and
/// the case), so a client is enrolled by pasting what the tooling already gives.
pub fn cert_fingerprint(connection: &quinn::Connection) -> String {
    match peer_leaf_der(connection) {
        Some(der) => fingerprint(&der),
        None => "anonymous".to_string(),
    }
}

/// Lowercase hex SHA-256 of a certificate's DER bytes. See [`cert_fingerprint`].
pub fn fingerprint(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(der);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// [`fingerprint`] of the first certificate in a PEM — so the tool that MINTS a
/// client identity can print the id the operator must enrol, instead of sending
/// them to `openssl`.
pub fn fingerprint_of_pem(pem: &str) -> io::Result<String> {
    Ok(fingerprint(load_cert(pem)?.as_ref()))
}

/// A per-tenant namespace id for the connection's authenticated client — a hash of
/// its leaf certificate. `anonymous` if the peer presented no cert.
///
/// **Deliberately unchanged**, `DefaultHasher` and all: `file_segment` is derived
/// from it and existing tenant workspace directories on disk are NAMED by it, so
/// recomputing it differently would orphan every tenant's files. It is a namespace,
/// not an identity — use [`cert_fingerprint`] for anything an operator configures.
fn peer_cert_id(connection: &quinn::Connection) -> String {
    use std::hash::{Hash, Hasher};
    match peer_leaf_der(connection) {
        Some(der) => {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            der.hash(&mut hasher);
            format!("{:016x}", hasher.finish())
        }
        None => "anonymous".to_string(),
    }
}

/// Answer calls on one connection until the peer closes it, every call resolved
/// under the connection's [`Session`] (the authenticated principal).
async fn serve_connection(kernel: &Kernel, connection: quinn::Connection, session: &Session) {
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        let bytes = match recv.read_to_end(MAX_MESSAGE).await {
            Ok(bytes) => bytes,
            Err(_) => return,
        };
        let reply = match decode::<Call>(&bytes) {
            Ok(call) => dispatch(kernel, call, session),
            Err(e) => Reply::ErrorTyped(ikigai_wire::WireError::Endpoint(format!(
                "malformed call: {e}"
            ))),
        };
        if let Ok(out) = encode(&reply) {
            let _ = send.write_all(&out).await;
            let _ = send.finish();
        }
    }
}

/// Transparently root the connection's `urn:file:` namespace at its segment: rewrite
/// `urn:file:<rel>` → `urn:file:<segment>/<rel>` so a tenant addresses files as if its
/// own segment were the root (and the session capability — scoped to that segment —
/// then refuses anything outside it). Non-file targets and an empty segment pass through.
fn localize(request: &mut Request, segment: &str) {
    if segment.is_empty() {
        return;
    }
    if let Some(rel) = request.target.as_str().strip_prefix("urn:file:") {
        if let Ok(rooted) = Iri::parse(format!("urn:file:{segment}/{rel}")) {
            request.target = rooted;
        }
    }
}

/// Answer one [`Call`] against the local kernel, resolved under the connection's
/// `session` (the principal the mTLS handshake authenticated), with its file namespace
/// rooted at its segment.
fn dispatch(kernel: &Kernel, call: Call, session: &Session) -> Reply {
    let issue = |mut request: Request, capability: &Capability| {
        localize(&mut request, &session.file_segment);
        match Resolver::issue_as(kernel, request, capability) {
            Ok((representation, status)) => Reply::Resolved(representation, status),
            Err(error) => Reply::ErrorTyped(ikigai_wire::WireError::from(&error)),
        }
    };
    match call {
        // Resolve under the session — capability-on-the-wire via the client cert.
        Call::Issue(request) => issue(request, &session.capability),
        // A carried capability is untrusted: the peer can only *narrow* its own
        // authority, so clamp it to the session before resolving (never widen past
        // the authenticated principal).
        Call::IssueAs(request, carried) => issue(request, &session.capability.clamp(&carried)),
        Call::IsCached(mut request) => {
            localize(&mut request, &session.file_segment);
            Reply::Cached(Resolver::is_cached(kernel, &request, &session.capability))
        }
        // List the manifold the client's authenticated capability actually permits —
        // never the full catalog. Affordance = authorization: a scoped principal must
        // not even enumerate what it may not invoke (the leak this closes).
        Call::Entries => Reply::Entries(Some(scoped_entries(kernel, &session.capability))),
        // Trace-over-the-wire: resolve under the clamped authority with a
        // PER-CALL collector (`issue_traced_as`), ship the recorded spans back.
        // Each tenant's trace records into its own scope — concurrent traced
        // calls can no longer interleave through the process-global tracer, which
        // closes the cross-tenant trace leak (a tracing tenant observing another
        // tenant's IRIs and cap scopes). `_ctx.parent_span` is for a future
        // mount-stitch.
        Call::IssueTraced(mut request, carried, _ctx) => {
            localize(&mut request, &session.file_segment);
            let capability = session.capability.clamp(&carried);
            let collector = Arc::new(SpanCollector::default());
            match ikigai_resolve::issue_traced_as(kernel, request, &capability, collector.clone()) {
                Ok((representation, status)) => {
                    Reply::ResolvedTraced(representation, status, collector.take())
                }
                Err(error) => Reply::ErrorTyped(ikigai_wire::WireError::from(&error)),
            }
        }
    }
}

/// Connect to a QUIC kernel server at `addr`, presenting `identity` and pinning
/// the server certificate `trusted_server_cert_pem`.
pub fn connect(
    addr: SocketAddr,
    identity: &Identity,
    trusted_server_cert_pem: &str,
) -> io::Result<QuicResolver> {
    connect_with(
        addr,
        identity,
        trusted_server_cert_pem,
        DEFAULT_IDLE_TIMEOUT,
    )
}

/// [`connect`] with an explicit idle timeout (see [`DEFAULT_IDLE_TIMEOUT`]).
pub fn connect_with(
    addr: SocketAddr,
    identity: &Identity,
    trusted_server_cert_pem: &str,
    idle: std::time::Duration,
) -> io::Result<QuicResolver> {
    let config = client_config(identity, trusted_server_cert_pem, idle)?;
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
        let connection = dial(&endpoint, addr).await?;
        io::Result::Ok((endpoint, connection))
    })?;
    Ok(QuicResolver {
        runtime,
        endpoint,
        addr,
        connection: Mutex::new(connection),
        tracer: Mutex::new(None),
    })
}

/// A [`Resolver`] backed by a kernel server over QUIC.
pub struct QuicResolver {
    runtime: Runtime,
    /// The client endpoint — kept alive, and reused to re-`connect` when the current
    /// connection has died (see [`round_trip`](Self::round_trip)).
    endpoint: quinn::Endpoint,
    /// The server address, held so a dropped connection can be re-established.
    addr: SocketAddr,
    /// Swappable so a stale connection can be replaced in place: a long-lived resolver
    /// (a daemon's mount) must survive the peer restarting or an idle timeout, not wedge
    /// on the one connection it opened at startup.
    connection: Mutex<quinn::Connection>,
    /// The tracer the `trace` command installs; when set, a resolution is sent as
    /// [`Call::IssueTraced`] and the server's returned spans are forwarded here.
    tracer: Mutex<Option<Arc<dyn Tracer>>>,
}

impl QuicResolver {
    /// One call → one bidirectional stream → one reply.
    ///
    /// A QUIC connection does not live forever: the peer may restart, or an idle spell may
    /// let it time out. A resolver that opened its connection once at startup — a daemon's
    /// standing mount — would then fail every call thereafter, silently, forever. So a
    /// transport failure is not fatal here: reconnect once and try again. A failure that
    /// survives the reconnect (the peer is genuinely down) surfaces as normal, for the
    /// reliability overlays to treat as the transient [`Unavailable`](Error::Unavailable)
    /// it is.
    fn round_trip(&self, call: Call) -> io::Result<Reply> {
        let request = encode(&call)?;
        self.runtime.block_on(async {
            match self.attempt(&request).await {
                Ok(reply) => Ok(reply),
                Err(_) => {
                    self.reconnect().await?;
                    self.attempt(&request).await
                }
            }
        })
    }

    /// One attempt on the current connection. Cloning the connection out of the lock
    /// (cheap — it is an `Arc` inside) keeps the guard from being held across an await.
    async fn attempt(&self, request: &[u8]) -> io::Result<Reply> {
        let connection = { self.connection.lock().unwrap().clone() };
        let (mut send, mut recv) = connection.open_bi().await.map_err(other)?;
        send.write_all(request).await.map_err(other)?;
        send.finish().map_err(other)?;
        let bytes = recv.read_to_end(MAX_MESSAGE).await.map_err(other)?;
        decode(&bytes)
    }

    /// Re-establish the connection through the surviving endpoint, reusing the same pinned
    /// identity and trust (they live in the endpoint's default client config). The lock is
    /// taken only to swap the result in, after the await completes.
    async fn reconnect(&self) -> io::Result<()> {
        let connection = dial(&self.endpoint, self.addr).await?;
        *self.connection.lock().unwrap() = connection;
        Ok(())
    }
}

impl Drop for QuicResolver {
    fn drop(&mut self) {
        // Tell the peer we're done so it stops promptly instead of waiting out
        // the idle timeout; then let the endpoint flush the close frame.
        self.connection.lock().unwrap().close(0u32.into(), b"bye");
        let _ = self.runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(1), self.endpoint.wait_idle()).await
        });
    }
}

/// A QUIC round-trip failure means the remote kernel is unreachable — a **transient**
/// [`Unavailable`](Error::Unavailable) the reliability overlays (Retry/Failover) can
/// act on, rather than a permanent error.
fn quic_error(e: io::Error) -> Error {
    Error::Unavailable(format!("quic transport: {e}"))
}

impl Resolver for QuicResolver {
    fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
        match self.round_trip(Call::Issue(request)).map_err(quic_error)? {
            Reply::Resolved(representation, status) => Ok((representation, status)),
            // The server already rendered its error to a string; don't re-prefix an
            // already-"endpoint error: …" message into a doubled one across the wire.
            Reply::ErrorTyped(wire_error) => Err(wire_error.into()),
            Reply::Error(message) => Err(Error::Endpoint(
                message
                    .strip_prefix("endpoint error: ")
                    .map(str::to_string)
                    .unwrap_or(message),
            )),
            other => Err(Error::Endpoint(format!(
                "unexpected reply to Issue: {other:?}"
            ))),
        }
    }

    /// QUIC carries the caller's authority in the client cert (the server's
    /// session), so an untraced resolution goes as plain `Call::Issue`. When a
    /// tracer is installed, send `Call::IssueTraced` and forward the returned
    /// spans — so a `--connect` QUIC trace shows the remote execution tree.
    fn issue_as(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        let tracer = self.tracer.lock().expect("tracer lock").clone();
        let call = if tracer.is_some() {
            Call::IssueTraced(
                request,
                capability.clone(),
                TraceContext {
                    trace_id: 1,
                    parent_span: None,
                },
            )
        } else {
            Call::Issue(request)
        };
        match self.round_trip(call).map_err(quic_error)? {
            Reply::Resolved(representation, status) => Ok((representation, status)),
            Reply::ResolvedTraced(representation, status, events) => {
                if let Some(tracer) = &tracer {
                    for event in events {
                        tracer.record(event);
                    }
                }
                Ok((representation, status))
            }
            // The server already rendered its error to a string; don't re-prefix an
            // already-"endpoint error: …" message into a doubled one across the wire.
            Reply::ErrorTyped(wire_error) => Err(wire_error.into()),
            Reply::Error(message) => Err(Error::Endpoint(
                message
                    .strip_prefix("endpoint error: ")
                    .map(str::to_string)
                    .unwrap_or(message),
            )),
            other => Err(Error::Endpoint(format!(
                "unexpected reply to IssueAs: {other:?}"
            ))),
        }
    }

    fn set_tracer(&self, tracer: Arc<dyn Tracer>) {
        *self.tracer.lock().expect("tracer lock") = Some(tracer);
    }

    fn clear_tracer(&self) {
        *self.tracer.lock().expect("tracer lock") = None;
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
    trusted_client_cert_pems: &[String],
    idle: std::time::Duration,
) -> io::Result<quinn::ServerConfig> {
    let certs = trusted_client_cert_pems
        .iter()
        .map(|pem| load_cert(pem))
        .collect::<io::Result<Vec<_>>>()?;
    let verifier = Arc::new(PinnedPeer::set(certs));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(other)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![load_cert(&identity.cert_pem)?],
            load_key(&identity.key_pem)?,
        )
        .map_err(other)?;
    tls.alpn_protocols = alpn_protocols();
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(other)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    config.transport_config(Arc::new(transport(idle)?));
    Ok(config)
}

/// A transport config carrying the idle timeout. Each side enforces its OWN, so both
/// the server and the client builders apply it. Keep-alive stays deliberately absent:
/// RFC 9000 restarts the idle timer on ack-eliciting SENDS too, so pinging would keep
/// a dead peer's connection looking alive forever — patience bounded by `idle` beats
/// liveness theater that never expires.
fn transport(idle: std::time::Duration) -> io::Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(quinn::IdleTimeout::try_from(idle).map_err(other)?));
    Ok(transport)
}

/// How long a dial may run before the peer is declared unreachable.
///
/// Without this, quinn retries the handshake against a silent address for as long as its
/// defaults allow, and a mount whose peer has gone BLOCKS the caller instead of failing.
/// A closed port on loopback answers ICMP-unreachable and fails fast, which is why this
/// hides in local testing — but a real LAN peer that stops responding just drops packets,
/// and the caller hangs. Observed on bug↔plasma: `--override` took minutes to give up and
/// `--prefer` appeared to hang outright, which defeats the entire point of a mount that is
/// supposed to degrade to the local binding.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Dial with a bound: a peer that never answers must not block forever.
async fn dial(endpoint: &quinn::Endpoint, addr: SocketAddr) -> io::Result<quinn::Connection> {
    let connecting = endpoint.connect(addr, "ikigai").map_err(other)?;
    match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
        Ok(result) => result.map_err(other),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "connect {addr}: timed out after {}s",
                CONNECT_TIMEOUT.as_secs()
            ),
        )),
    }
}

fn client_config(
    identity: &Identity,
    trusted_server_cert_pem: &str,
    idle: std::time::Duration,
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
    tls.alpn_protocols = alpn_protocols();
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(other)?;
    // The idle timeout is OURS to set (see [`DEFAULT_IDLE_TIMEOUT`]): quinn's ~30s
    // default killed long-silent work (a 70B generating) mid-request. Keep-alive stays
    // off — an earlier attempt showed pinging makes a DEAD peer take LONGER to notice
    // (RFC 9000 restarts the idle timer on ack-eliciting sends); see [`transport`].
    let mut config = quinn::ClientConfig::new(Arc::new(quic));
    config.transport_config(Arc::new(transport(idle)?));
    Ok(config)
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
    /// The accepted peer certificates. One for the client (it pins the single server
    /// cert); one *or more* for the server (it accepts any enrolled tenant's client
    /// cert — multi-tenant mTLS, each identity its own cert).
    pinned: Vec<CertificateDer<'static>>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedPeer {
    fn new(pinned: CertificateDer<'static>) -> Self {
        Self::set(vec![pinned])
    }

    fn set(pinned: Vec<CertificateDer<'static>>) -> Self {
        PinnedPeer {
            pinned,
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }

    fn matches(&self, presented: &CertificateDer<'_>) -> bool {
        self.pinned.iter().any(|c| c.as_ref() == presented.as_ref())
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

    use ikigai_core::{
        builtins, ArgRef, EndpointSpace, Error, Exact, FnEndpoint, Invocation, Iri, ReprType,
        Representation, UriTemplate, Verb,
    };

    fn kernel() -> Kernel {
        Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:fn:toUpper"), builtins::to_upper()),
        ))
    }

    /// A kernel whose `urn:demo:cal` projects on the session capability — full DETAIL at
    /// root, the minimized `freebusy` otherwise — so a test can see which authority a
    /// connection actually resolved under.
    fn gated_kernel() -> Kernel {
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

    /// Serve `kernel` under `session` on an ephemeral port, run `urn:demo:cal` from a
    /// pinned client, and return what it resolved — the projection reveals the authority
    /// the connection resolved under.
    fn cal_over_quic(capability: Capability) -> String {
        let server_id = generate();
        let client_id = generate();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_cfg = server_config(
            &server_id,
            std::slice::from_ref(&client_id.cert_pem),
            DEFAULT_IDLE_TIMEOUT,
        )
        .unwrap();
        let rt = Runtime::new().unwrap();
        let endpoint = rt
            .block_on(async { quinn::Endpoint::server(server_cfg, addr) })
            .unwrap();
        let server_addr = endpoint.local_addr().unwrap();
        let kernel = Arc::new(gated_kernel());
        let session = Session {
            capability,
            file_segment: String::new(),
        };
        let server = thread::spawn(move || {
            rt.block_on(async move {
                let incoming = endpoint.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                serve_connection(&kernel, connection, &session).await;
            });
        });
        let client = connect(server_addr, &client_id, &server_id.cert_pem).unwrap();
        let cal = Request::new(Verb::Source, Iri::parse("urn:demo:cal").unwrap());
        let (representation, _) = client.issue(cal).unwrap();
        drop(client);
        server.join().unwrap();
        String::from_utf8(representation.bytes).unwrap()
    }

    #[test]
    fn the_connection_resolves_under_its_session_capability() {
        // A root session is full authority — the endpoint sees DETAIL.
        assert_eq!(cal_over_quic(Capability::root()), "DETAIL");
        // A scoped session (no `detail` scope) confines the whole connection — the
        // endpoint resolves under it, not root, so it sees only `freebusy`. This is
        // capability-on-the-wire: the mTLS-authenticated principal's authority, enforced
        // server-side for every call on the connection.
        let scoped = Capability::root().attenuate(["urn:cap:demo:other".to_string()]);
        assert_eq!(cal_over_quic(scoped), "freebusy");
    }

    /// Serve `gated_kernel` under a fixed `server_ceiling` (as `serve --cap` mints per
    /// connection), then MOUNT that remote kernel into a fresh local kernel via a
    /// `RemoteSpace` and resolve `urn:demo:cal` under `local_capability`. Returns what
    /// the mounted resolution saw — DETAIL or freebusy — i.e. the authority that
    /// actually governed after the server clamped the forwarded capability.
    fn cal_through_mount(server_ceiling: Capability, local_capability: Capability) -> String {
        use ikigai_core::{Fallback, Space};
        use ikigai_resolve::{RemoteSpace, Resolver};

        let server_id = generate();
        let client_id = generate();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_cfg = server_config(
            &server_id,
            std::slice::from_ref(&client_id.cert_pem),
            DEFAULT_IDLE_TIMEOUT,
        )
        .unwrap();
        let rt = Runtime::new().unwrap();
        let endpoint = rt
            .block_on(async { quinn::Endpoint::server(server_cfg, addr) })
            .unwrap();
        let server_addr = endpoint.local_addr().unwrap();
        let kernel = Arc::new(gated_kernel());
        let session = Session {
            capability: server_ceiling,
            file_segment: String::new(),
        };
        let server = thread::spawn(move || {
            rt.block_on(async move {
                let incoming = endpoint.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                serve_connection(&kernel, connection, &session).await;
            });
        });
        let client = connect(server_addr, &client_id, &server_id.cert_pem).unwrap();
        // Federation: compose the remote kernel into a LOCAL one as a fallback space.
        let local = Fallback::new(vec![
            Arc::new(EndpointSpace::new()) as Arc<dyn Space>,
            Arc::new(RemoteSpace::new(Arc::new(client))) as Arc<dyn Space>,
        ]);
        let local_kernel = Kernel::new(Arc::new(local));
        let cal = Request::new(Verb::Source, Iri::parse("urn:demo:cal").unwrap());
        let (representation, _) =
            Resolver::issue_as(&local_kernel, cal, &local_capability).unwrap();
        drop(local_kernel);
        server.join().unwrap();
        String::from_utf8(representation.bytes).unwrap()
    }

    #[test]
    fn a_mount_clamps_a_locally_root_client_to_the_servers_ceiling() {
        // The federation guarantee: the laptop composes the remote kernel and resolves
        // under its OWN (here root) authority, but the server's per-connection ceiling
        // clamps the forwarded capability — the client cannot widen past what the remote
        // grants. A freebusy-only ceiling → the mounted, locally-root client sees only
        // freebusy. (The calendar story: `serve --cap …:read:freebusy` on the daemon →
        // the laptop mounts it and gets free/busy, never detail.)
        let freebusy = Capability::scoped(["urn:cap:demo:freebusy".to_string()]);
        assert_eq!(
            cal_through_mount(freebusy, Capability::root()),
            "freebusy",
            "a freebusy server ceiling clamps a locally-root mounted client"
        );
        // Control: a ceiling that DOES grant detail lets the same locally-root client
        // see detail — proving the server's ceiling governs, not the client's authority.
        let detail = Capability::scoped(["urn:cap:demo:detail".to_string()]);
        assert_eq!(
            cal_through_mount(detail, Capability::root()),
            "DETAIL",
            "a detail-granting ceiling lets the mounted client see detail"
        );
    }

    /// A kernel mimicking the file module enough to show wire-side rooting + scoping:
    /// `urn:file:{path}` echoes the (localized) path it received, gated by a prefix ACL
    /// over the session's `urn:cap:fs:read:<segment>` scopes — as ikigai-fs does for real
    /// (the live fs is exercised by the CLI end-to-end).
    fn files_kernel() -> Kernel {
        let files = FnEndpoint::new("file", |inv: &Invocation<'_>| {
            let path = inv.bindings.get("path").unwrap_or_default().to_string();
            let allowed = match inv.capability.scopes() {
                None => true,
                Some(scopes) => scopes.iter().any(|s| {
                    s.strip_prefix("urn:cap:fs:read:")
                        .is_some_and(|p| path == p || path.starts_with(&format!("{p}/")))
                }),
            };
            if allowed {
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    path.into_bytes(),
                ))
            } else {
                Err(Error::Denied(format!(
                    "capability does not grant read on `{path}`"
                )))
            }
        });
        Kernel::new(Arc::new(
            EndpointSpace::new().bind(UriTemplate::parse("urn:file:{path}").unwrap(), files),
        ))
    }

    /// Resolve `urn:file:<path>` over QUIC under `session`, returning the echoed
    /// (localized) path or the endpoint error.
    fn file_over_quic(session: Session, path: &str) -> Result<String, Error> {
        let server_id = generate();
        let client_id = generate();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_cfg = server_config(
            &server_id,
            std::slice::from_ref(&client_id.cert_pem),
            DEFAULT_IDLE_TIMEOUT,
        )
        .unwrap();
        let rt = Runtime::new().unwrap();
        let endpoint = rt
            .block_on(async { quinn::Endpoint::server(server_cfg, addr) })
            .unwrap();
        let server_addr = endpoint.local_addr().unwrap();
        let kernel = Arc::new(files_kernel());
        let server = thread::spawn(move || {
            rt.block_on(async move {
                let incoming = endpoint.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                serve_connection(&kernel, connection, &session).await;
            });
        });
        let client = connect(server_addr, &client_id, &server_id.cert_pem).unwrap();
        let target = Iri::parse(format!("urn:file:{path}")).unwrap();
        let result = client
            .issue(Request::new(Verb::Source, target))
            .map(|(r, _)| String::from_utf8(r.bytes).unwrap());
        drop(client);
        server.join().unwrap();
        result
    }

    #[test]
    fn tenants_get_isolated_transparently_rooted_workspaces() {
        let session = |seg: &str| Session {
            capability: Capability::root().attenuate([format!("urn:cap:fs:read:{seg}")]),
            file_segment: seg.to_string(),
        };
        // Each tenant addresses `urn:file:notes.txt` as if rooted at its own segment — it
        // resolves to `<segment>/notes.txt`, so the SAME name is a different file per
        // tenant: transparent rooting + isolation, neither seeing the other's.
        assert_eq!(
            file_over_quic(session("alice"), "notes.txt").unwrap(),
            "alice/notes.txt"
        );
        assert_eq!(
            file_over_quic(session("bob"), "notes.txt").unwrap(),
            "bob/notes.txt"
        );
        // A tenant cannot address outside its segment: even naming another's id just roots
        // it under its own (`alice` asking for `bob/x` → `alice/bob/x`), so there is no way
        // to reach another tenant's files.
        assert_eq!(
            file_over_quic(session("alice"), "bob/x").unwrap(),
            "alice/bob/x"
        );
    }

    fn upper(text: &str) -> Request {
        Request::new(Verb::Source, Iri::parse("urn:fn:toUpper").unwrap())
            .with_arg("in", ArgRef::Inline(text.as_bytes().to_vec()))
    }

    /// The idle timeout decides whether LONG-SILENT WORK survives: the server says
    /// nothing while a resolution runs, and quinn's old ~30s default killed a hard
    /// LLM question mid-generation (observed bug->plasma) while the model kept
    /// computing. A client outliving the silence gets the reply; one with a shorter
    /// idle than the work loses the connection.
    #[test]
    fn a_slow_resolution_survives_a_generous_idle_and_dies_under_a_short_one() {
        let server_id = generate();
        let client_id = generate();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_cfg = server_config(
            &server_id,
            std::slice::from_ref(&client_id.cert_pem),
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let rt = Runtime::new().unwrap();
        let endpoint = rt
            .block_on(async { quinn::Endpoint::server(server_cfg, addr) })
            .unwrap();
        let server_addr = endpoint.local_addr().unwrap();
        let slow = FnEndpoint::new("slow", |_inv: &Invocation<'_>| {
            // Blocking sleep stands in for a model generating: the connection carries
            // NOTHING until the work finishes. (Multi-thread runtime; one connection.)
            std::thread::sleep(std::time::Duration::from_secs(3));
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"eventually".to_vec(),
            ))
        });
        let kernel = Arc::new(Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:demo:slow"), slow),
        )));
        let session = Session {
            capability: Capability::root(),
            file_segment: String::new(),
        };
        // A real accept loop: the impatient client's RETRY (round_trip reconnects once
        // after a failure) dials a second connection while the first is still being
        // served, so connections must be handled concurrently, as `serve` itself does.
        drop(session);
        let _server = thread::spawn(move || {
            rt.block_on(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let kernel = Arc::clone(&kernel);
                    tokio::spawn(async move {
                        let connection = match incoming.await {
                            Ok(c) => c,
                            Err(_) => return,
                        };
                        let session = Session {
                            capability: Capability::root(),
                            file_segment: String::new(),
                        };
                        serve_connection(&kernel, connection, &session).await;
                    });
                }
            });
        });

        let req = || Request::new(Verb::Source, Iri::parse("urn:demo:slow").unwrap());
        // 1s of patience for 3s of work: the connection idles out, the call fails.
        let impatient = connect_with(
            server_addr,
            &client_id,
            &server_id.cert_pem,
            std::time::Duration::from_secs(1),
        )
        .unwrap();
        assert!(
            impatient.issue(req()).is_err(),
            "a 1s idle must not survive 3s of silent work"
        );
        drop(impatient);
        // 10s of patience: the same call completes.
        let patient = connect_with(
            server_addr,
            &client_id,
            &server_id.cert_pem,
            std::time::Duration::from_secs(10),
        )
        .unwrap();
        let (repr, _) = patient.issue(req()).expect("slow work completes");
        assert_eq!(repr.bytes, b"eventually");
    }

    /// A dial to a peer that never answers must FAIL, not hang.
    ///
    /// The regression: quinn's defaults retry the handshake for a very long time, so a mount
    /// whose peer had gone blocked the caller. Loopback hides it — a closed port answers
    /// ICMP-unreachable and fails fast — so this test binds a real UDP socket and simply
    /// never speaks QUIC on it, which is what a silent LAN peer looks like. Measured on
    /// bug↔plasma before the fix: ~60s of dead air before `--prefer` fell back to local.
    #[test]
    fn a_dial_to_a_silent_peer_times_out_rather_than_hanging() {
        // Bound to a real socket, so packets are accepted and dropped rather than refused.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = silent.local_addr().unwrap();
        let server_id = generate();
        let client_id = generate();

        let started = std::time::Instant::now();
        let result = connect(addr, &client_id, &server_id.cert_pem);
        let elapsed = started.elapsed();

        assert!(result.is_err(), "a silent peer must not appear to connect");
        assert!(
            elapsed < CONNECT_TIMEOUT * 3,
            "must give up near the {}s bound, took {:?}",
            CONNECT_TIMEOUT.as_secs(),
            elapsed
        );
    }

    /// The fingerprint is a CONFIG KEY, so it must be reproducible outside this
    /// process: fixed bytes in, fixed hex out, forever. Vectors are the published
    /// SHA-256 of the empty string and of `abc` — the same digest
    /// `openssl x509 -noout -fingerprint -sha256` prints over a certificate's DER
    /// (minus its colons and case), which is how a client is enrolled by paste.
    ///
    /// Deliberately NOT a property of `peer_cert_id`: that one hashes with
    /// `DefaultHasher`, whose output is explicitly not stable across Rust releases.
    #[test]
    fn the_fingerprint_is_the_sha256_of_the_der_and_never_moves() {
        assert_eq!(
            fingerprint(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            fingerprint(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // A real certificate: the PEM path and the DER path agree, and the id is a
        // 64-character lowercase hex digest.
        let identity = generate();
        let der = load_cert(&identity.cert_pem).unwrap();
        let from_pem = fingerprint_of_pem(&identity.cert_pem).unwrap();
        assert_eq!(from_pem, fingerprint(der.as_ref()));
        assert_eq!(from_pem.len(), 64);
        assert!(from_pem
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        // Distinct certificates are distinct identities.
        assert_ne!(from_pem, fingerprint_of_pem(&generate().cert_pem).unwrap());
    }

    /// Run the real accept loop (minter and all) against `minter`, dialing `dials`
    /// times with the same client cert, and return what `urn:demo:cal` resolved to on
    /// each dial — `Err` when the connection was refused.
    fn dials_under(minter: Minter, dials: usize) -> Vec<Result<String, ()>> {
        let server_id = generate();
        let client_id = generate();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_cfg = server_config(
            &server_id,
            std::slice::from_ref(&client_id.cert_pem),
            DEFAULT_IDLE_TIMEOUT,
        )
        .unwrap();
        let rt = Runtime::new().unwrap();
        let endpoint = rt
            .block_on(async { quinn::Endpoint::server(server_cfg, addr) })
            .unwrap();
        let server_addr = endpoint.local_addr().unwrap();
        let kernel = Arc::new(gated_kernel());
        // The accept loop as `serve_with` runs it: mint per connection, refuse on None.
        let _server = thread::spawn(move || {
            rt.block_on(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let kernel = Arc::clone(&kernel);
                    let minter = Arc::clone(&minter);
                    tokio::spawn(async move {
                        let Ok(connection) = incoming.await else {
                            return;
                        };
                        match minter(&PeerIdentity::of(&connection)) {
                            Some(session) => serve_connection(&kernel, connection, &session).await,
                            None => connection.close(UNAUTHORIZED.into(), b"unauthorized"),
                        }
                    });
                }
            });
        });
        let cal = || Request::new(Verb::Source, Iri::parse("urn:demo:cal").unwrap());
        (0..dials)
            .map(|_| {
                let client = connect(server_addr, &client_id, &server_id.cert_pem).unwrap();
                let result = client
                    .issue(cal())
                    .map(|(r, _)| String::from_utf8(r.bytes).unwrap())
                    .map_err(|_| ());
                drop(client);
                result
            })
            .collect()
    }

    /// FAIL CLOSED on the wire. A certificate the mTLS layer TRUSTS — the handshake
    /// succeeds — still gets nothing when the host mints no authority for it. The
    /// dangerous alternative is falling back to a shared ceiling, which is how a
    /// forgotten config entry becomes a silent over-grant.
    #[test]
    fn a_trusted_certificate_with_no_authority_is_refused_not_served() {
        let refuse: Minter = Arc::new(|_| None);
        assert_eq!(dials_under(refuse, 1), vec![Err(())]);
        // Control: the same handshake, with authority minted, resolves.
        let grant: Minter = Arc::new(|peer: &PeerIdentity| {
            assert_eq!(peer.fingerprint.len(), 64, "the minter sees the stable id");
            Some(Session {
                capability: Capability::root(),
                file_segment: peer.segment_id.clone(),
            })
        });
        assert_eq!(dials_under(grant, 1), vec![Ok("DETAIL".to_string())]);
    }

    /// REVOCATION BY EDITING A FILE. Authority is minted per connection and never
    /// cached, so a change made between two connections governs the second one —
    /// including all the way down to refusal. (Here an atomic counter stands in for
    /// the operator editing `clients.json`; the host's minter re-reads it per call.)
    #[test]
    fn each_connection_mints_afresh_so_an_edit_governs_the_next_one() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let nth = Arc::new(AtomicUsize::new(0));
        let minter: Minter = Arc::new(move |peer: &PeerIdentity| {
            let session = |capability| {
                Some(Session {
                    capability,
                    file_segment: peer.segment_id.clone(),
                })
            };
            match nth.fetch_add(1, Ordering::SeqCst) {
                // First: full authority.
                0 => session(Capability::root()),
                // The operator narrows the grant — same client, same certificate.
                1 => session(Capability::scoped(["urn:cap:demo:other".to_string()])),
                // The operator deletes the entry: revoked.
                _ => None,
            }
        });
        assert_eq!(
            dials_under(minter, 3),
            vec![
                Ok("DETAIL".to_string()),
                Ok("freebusy".to_string()),
                Err(())
            ]
        );
    }

    #[test]
    fn round_trips_over_quic_with_pinned_certs() {
        let server_id = generate();
        let client_id = generate();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Bind the server first so we can learn its actual (ephemeral) port.
        let server_cfg = server_config(
            &server_id,
            std::slice::from_ref(&client_id.cert_pem),
            DEFAULT_IDLE_TIMEOUT,
        )
        .unwrap();
        let rt = Runtime::new().unwrap();
        let endpoint = rt
            .block_on(async { quinn::Endpoint::server(server_cfg, addr) })
            .unwrap();
        let server_addr = endpoint.local_addr().unwrap();

        let kernel = Arc::new(kernel());
        let session = Session {
            capability: Capability::root(),
            file_segment: String::new(),
        };
        let server = {
            let kernel = Arc::clone(&kernel);
            thread::spawn(move || {
                rt.block_on(async move {
                    let incoming = endpoint.accept().await.unwrap();
                    let connection = incoming.await.unwrap();
                    serve_connection(&kernel, connection, &session).await;
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

        let server_cfg = server_config(
            &server_id,
            std::slice::from_ref(&client_id.cert_pem),
            DEFAULT_IDLE_TIMEOUT,
        )
        .unwrap();
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

#[cfg(test)]
mod reconnect_tests {
    use super::*;
    use ikigai_core::{ArgRef, Capability, Verb};
    use std::sync::Arc;
    use std::thread;

    fn upper(text: &str) -> Request {
        Request::new(Verb::Source, Iri::parse("urn:fn:toUpper").unwrap())
            .with_arg("in", ArgRef::Inline(text.as_bytes().to_vec()))
    }

    /// Serve exactly one connection on `server_cfg` at `addr`, then return — the caller
    /// spawns this again to simulate a server that went away and came back.
    fn serve_one(server_cfg: quinn::ServerConfig, addr: SocketAddr) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(async move {
                let endpoint = quinn::Endpoint::server(server_cfg, addr).unwrap();
                let session = Session {
                    capability: Capability::root(),
                    file_segment: String::new(),
                };
                let kernel = Arc::new(Kernel::new(Arc::new(
                    ikigai_core::EndpointSpace::new().bind(
                        ikigai_core::Exact::new("urn:fn:toUpper"),
                        ikigai_core::builtins::to_upper(),
                    ),
                )));
                if let Some(incoming) = endpoint.accept().await {
                    if let Ok(connection) = incoming.await {
                        serve_connection(&kernel, connection, &session).await;
                    }
                }
                // Let the close frame flush before the endpoint drops.
                endpoint.wait_idle().await;
            });
        })
    }

    #[test]
    fn a_resolver_survives_the_server_going_away_and_coming_back() {
        let server_id = generate();
        let client_id = generate();

        // A FIXED port, so the second server instance is reachable at the same address the
        // resolver already knows — exactly the "same edge, restarted" case.
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let cfg = || {
            server_config(
                &server_id,
                std::slice::from_ref(&client_id.cert_pem),
                DEFAULT_IDLE_TIMEOUT,
            )
            .unwrap()
        };
        // Bind once to claim a concrete port, then hand that port to the servers.
        let probe = Runtime::new()
            .unwrap()
            .block_on(async { quinn::Endpoint::server(cfg(), addr).unwrap() });
        let port = probe.local_addr().unwrap();
        drop(probe);

        // First server instance. A SHORT idle timeout, explicitly: noticing the dead
        // first connection costs up to the idle bound, and this test is about the
        // reconnect, not about sitting out the generous production default.
        let first = serve_one(cfg(), port);
        let client = connect_with(
            port,
            &client_id,
            &server_id.cert_pem,
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(client.issue(upper("one")).unwrap().0.bytes, b"ONE");

        // The server goes away — this is what leaves the resolver holding a dead connection.
        first.join().unwrap();

        // It comes back at the same address, and the resolver — which never restarted —
        // must recover on its own rather than fail forever.
        let second = serve_one(cfg(), port);
        // Give the new instance a moment to bind.
        thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(
            client.issue(upper("two")).unwrap().0.bytes,
            b"TWO",
            "the resolver reconnected to the restarted server"
        );

        drop(client);
        second.join().unwrap();
    }
}

#[cfg(test)]
mod idle_timeout {
    use super::*;
    use std::net::SocketAddr;
    use tokio::runtime::Runtime;

    /// The configured idle timeout actually reaches the connection: a QUIET
    /// connection (nothing sent either way) closes once it elapses. Guards the
    /// regression where the transport config was built but never applied.
    #[test]
    fn a_quiet_connection_dies_at_the_configured_idle_timeout() {
        let server_id = generate();
        let client_id = generate();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_cfg = server_config(
            &server_id,
            std::slice::from_ref(&client_id.cert_pem),
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let rt = Runtime::new().unwrap();
        let endpoint = rt
            .block_on(async { quinn::Endpoint::server(server_cfg, addr) })
            .unwrap();
        let server_addr = endpoint.local_addr().unwrap();
        let _server = std::thread::spawn(move || {
            rt.block_on(async move {
                let incoming = endpoint.accept().await.unwrap();
                let _connection = incoming.await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            });
        });
        let client = connect_with(
            server_addr,
            &client_id,
            &server_id.cert_pem,
            std::time::Duration::from_secs(1),
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(3));
        let reason = {
            let conn = client.connection.lock().unwrap().clone();
            conn.close_reason()
        };
        assert!(
            reason.is_some(),
            "a 1s idle must close a connection quiet for 3s"
        );
    }
}
