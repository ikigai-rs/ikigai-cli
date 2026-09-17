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
use tokio::runtime::{Handle, Runtime};

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
    /// The legacy namespace id — see the private `peer_cert_id`.
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

/// The deadline for a peer's **self-description** — an `Entries` enumeration or a `Meta`
/// issue — as opposed to [`DEFAULT_IDLE_TIMEOUT`], which bounds a *resolution*.
///
/// The reasoning is `ikigai_ipc::DEFAULT_DESCRIBE_TIMEOUT`'s, and the value is deliberately
/// the same: the two transports mount the same kind of peer, and an operator who raises one
/// bound and not the other would get a federation whose legibility depended on which socket
/// a peer happened to be behind. What it bounds is a peer describing itself, and nothing is
/// ever *working* during a self-description — except transitively, which is why it is thirty
/// seconds and not one (ledger #404: the hub blocked here, three kernels deep, with no bound
/// at any hop).
pub const DEFAULT_DESCRIBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
/// requirements the private `peer_cert_id` cannot meet. It must be stable *forever* —
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
///
/// Public so that ANOTHER transport answers calls through exactly this function
/// (`ikigai-p2p`, behind its `p2p` feature): the clamp of a carried capability to the
/// session, the capability-scoped `Entries`, and the per-call trace collector are the
/// server half of capability-on-the-wire, and a second copy of them is how two doors
/// to one kernel end up enforcing different rules.
///
/// ★ **A panic in an endpoint costs ONE CALL, never the connection.** Without this
/// boundary the panic unwinds the door's task, the connection dies mid-stream, and the
/// caller is told `unavailable: quic transport: read error: connection lost` — a
/// diagnosis that names the transport for a fault that was never in it, with the real
/// cause visible only in the server's own log. That misdirection was most of the cost of
/// the mounted-resolver panic this crate also fixes, and it would be paid again by the
/// next endpoint that panics for some other reason. The panic still prints through the
/// default hook, so the server's log keeps the backtrace; what changes is that the client
/// now learns a *typed* reason. It sits inside `dispatch` rather than in
/// `serve_connection` deliberately: both doors that answer through here get it once.
pub fn dispatch(kernel: &Kernel, call: Call, session: &Session) -> Reply {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        dispatch_call(kernel, call, session)
    })) {
        Ok(reply) => reply,
        Err(payload) => Reply::ErrorTyped(ikigai_wire::WireError::Endpoint(format!(
            "the server panicked handling this call: {}",
            panic_message(payload)
        ))),
    }
}

/// The message a panic carried, for the two payload types `panic!` actually produces.
fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "panicked".to_string()
}

fn dispatch_call(kernel: &Kernel, call: Call, session: &Session) -> Reply {
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
    // ⚠ THE DIAL IS A `block_on` TOO, and it is the one that gets missed. A host that
    // wrapped every mounted *call* off-thread and left the dial here still panics on the
    // first resolve — measured in gonk 2026-09-16, and the reason `drive` is used here
    // rather than a bare `runtime.block_on`.
    let (endpoint, connection) = drive(&runtime, async move {
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
    })??;
    Ok(QuicResolver {
        runtime: Some(runtime),
        wire: Arc::new(Wire {
            endpoint,
            addr,
            connection: Mutex::new(connection),
        }),
        tracer: Mutex::new(None),
        describe_timeout: Some(DEFAULT_DESCRIBE_TIMEOUT),
    })
}

/// Drive `future` to completion on `runtime` and hand its value back to this
/// **synchronous** caller — which may itself be running on somebody else's tokio runtime.
///
/// ★ **A [`Resolver`] is a sync trait and this one owns a runtime, so every call is a
/// `block_on`. Tokio panics — "Cannot start a runtime from within a runtime" — when
/// `block_on` is entered from a thread that is already driving one**, and every wire door
/// in the ecosystem dispatches from exactly such a thread ([`serve`] spawns each connection
/// as a task; an inbound HTTP door resolves inside its async handler). So a mounted resolve
/// from any of them did not fail, it PANICKED the worker — and the caller was told
/// `connection lost`, with the real cause visible only in the server's log.
///
/// [`Handle::try_current`] is the detector, and the fix is to put the work somewhere that
/// is not the caller's runtime. It goes on the resolver's OWN runtime — which already
/// exists and already has worker threads — and this thread blocks on a channel for the
/// answer. The alternatives were weighed and rejected:
///
/// - **A thread per call** (the shape `ikigai-gonk` derived for its mount) works and is
///   what a host can build from outside, but it pays a thread spawn per resolve for a
///   runtime we already own. Measured on a loopback round trip (release, 2000 calls after
///   a warm-up, M-series): 55.6µs/call for a plain `block_on`, 53.1µs through this hop
///   (free — within run-to-run noise), 67.0µs with a thread per call. So the thread costs
///   ~12µs, which is ~25% of a loopback round trip and nothing at all against a real
///   network hop or a model call — it is affordable, just unnecessary. Fixing it here
///   instead of in each host is the point: every embedder otherwise re-derives the same
///   wrapper, and one already had.
/// - **`tokio::task::block_in_place`** is multi-thread-only, so it would make correctness
///   depend on how the CALLER built its runtime — coupling that comes back.
///
/// Blocking a caller's worker thread is a real cost and is unavoidable: the trait is sync.
/// It cannot deadlock, because the work makes progress on a different runtime's threads
/// than the one being blocked — including when the caller is a current-thread runtime.
///
/// A panic inside the spawned task drops the sender, so it arrives here as a closed channel
/// and becomes a typed [`Unavailable`](Error::Unavailable) naming the cause, rather than
/// unwinding a door's worker.
fn drive<T: Send + 'static>(
    runtime: &Runtime,
    future: impl std::future::Future<Output = T> + Send + 'static,
) -> io::Result<T> {
    if Handle::try_current().is_err() {
        // Not on a runtime thread: this thread is ours to block, as it always was.
        return Ok(runtime.block_on(future));
    }
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    runtime.spawn(async move {
        let _ = tx.send(future.await);
    });
    rx.recv()
        .map_err(|_| io::Error::other("the resolver's task panicked before replying"))
}

/// A [`Resolver`] backed by a kernel server over QUIC.
pub struct QuicResolver {
    /// The resolver's own tokio runtime. `Option` ONLY so [`Drop`] can move it out and
    /// hand it to a thread that is allowed to block; it is `Some` for every call.
    runtime: Option<Runtime>,
    /// The connection state, behind an `Arc` so a round trip can be a `'static` future
    /// spawned onto [`runtime`](Self::runtime) (see [`drive`]).
    wire: Arc<Wire>,
    /// The tracer the `trace` command installs; when set, a resolution is sent as
    /// [`Call::IssueTraced`] and the server's returned spans are forwarded here.
    tracer: Mutex<Option<Arc<dyn Tracer>>>,
    /// The deadline a SELF-DESCRIPTION call runs under (see [`DEFAULT_DESCRIBE_TIMEOUT`]);
    /// `None` leaves it on the connection's idle timeout like everything else.
    describe_timeout: Option<std::time::Duration>,
}

/// Everything a round trip touches, shared with the spawned task.
struct Wire {
    /// The client endpoint — kept alive, and reused to re-`connect` when the current
    /// connection has died (see [`round_trip`](Wire::round_trip)).
    endpoint: quinn::Endpoint,
    /// The server address, held so a dropped connection can be re-established.
    addr: SocketAddr,
    /// Swappable so a stale connection can be replaced in place: a long-lived resolver
    /// (a daemon's mount) must survive the peer restarting or an idle timeout, not wedge
    /// on the one connection it opened at startup.
    connection: Mutex<quinn::Connection>,
}

impl Wire {
    /// One call → one bidirectional stream → one reply.
    ///
    /// A QUIC connection does not live forever: the peer may restart, or an idle spell may
    /// let it time out. A resolver that opened its connection once at startup — a daemon's
    /// standing mount — would then fail every call thereafter, silently, forever. So a
    /// transport failure is not fatal here: reconnect once and try again. A failure that
    /// survives the reconnect (the peer is genuinely down) surfaces as normal, for the
    /// reliability overlays to treat as the transient [`Unavailable`](Error::Unavailable)
    /// it is.
    async fn round_trip(&self, request: Vec<u8>) -> io::Result<Reply> {
        match self.attempt(&request).await {
            Ok(reply) => Ok(reply),
            Err(_) => {
                self.reconnect().await?;
                self.attempt(&request).await
            }
        }
    }

    /// One attempt on the current connection. Cloning the connection out of the lock
    /// (cheap — it is an `Arc` inside) keeps the guard from being held across an await.
    async fn attempt(&self, request: &[u8]) -> io::Result<Reply> {
        let connection = { self.connection().clone() };
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
        *self.connection() = connection;
        Ok(())
    }

    /// The connection lock, taken through the poison. A panic while this lock was held
    /// must cost one call, never wedge the mount for the life of the process: the guarded
    /// value is a `quinn::Connection` handle, which no unwind can leave half-written.
    fn connection(&self) -> std::sync::MutexGuard<'_, quinn::Connection> {
        self.connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Whether `call` asks the peer to DESCRIBE ITSELF rather than to do work — the calls that
/// run under [`DEFAULT_DESCRIBE_TIMEOUT`]. The IPC transport draws the same line, in
/// `ikigai_ipc::is_describe`, and for the same reasons: `Entries` is the enumeration, a
/// `Meta` issue is one endpoint's contract, and `IsCached` is a question about work.
fn is_describe(call: &Call) -> bool {
    match call {
        Call::Entries => true,
        Call::Issue(request) | Call::IssueAs(request, _) | Call::IssueTraced(request, _, _) => {
            request.verb == ikigai_core::Verb::Meta
        }
        Call::IsCached(_) => false,
    }
}

impl QuicResolver {
    /// Set the deadline a SELF-DESCRIPTION call runs under (builder) — see
    /// [`DEFAULT_DESCRIBE_TIMEOUT`], which is what [`connect`] installs. `None` takes the
    /// bound off.
    pub fn with_describe_timeout(mut self, describe_timeout: Option<std::time::Duration>) -> Self {
        self.describe_timeout = describe_timeout;
        self
    }

    /// The resolver's runtime. See [`runtime`](Self::runtime) for why it is an `Option`.
    fn runtime(&self) -> &Runtime {
        self.runtime
            .as_ref()
            .expect("the resolver's runtime is taken only by Drop")
    }

    fn round_trip(&self, call: Call) -> io::Result<Reply> {
        let request = encode(&call)?;
        let wire = Arc::clone(&self.wire);
        // A self-description is bounded; a resolution is not (the idle timeout is its
        // only ceiling, and for a long resolution the silence IS the work). `deadline`
        // is computed here, outside the future, because `call` does not cross the spawn.
        let deadline = is_describe(&call)
            .then_some(self.describe_timeout)
            .flatten();
        drive(self.runtime(), async move {
            match deadline {
                None => wire.round_trip(request).await,
                // ★ This bounds the WHOLE exchange — the reconnect-and-retry inside
                // `Wire::round_trip` included. Bounding each attempt separately would let
                // a peer that accepts and never answers cost two deadlines per call.
                Some(deadline) => {
                    match tokio::time::timeout(deadline, wire.round_trip(request)).await {
                        Ok(reply) => reply,
                        Err(_) => Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "the peer did not describe itself within {}s",
                                deadline.as_secs()
                            ),
                        )),
                    }
                }
            }
        })?
    }

    /// The tracer lock, taken through the poison — same reasoning as
    /// [`Wire::connection`].
    fn tracer(&self) -> std::sync::MutexGuard<'_, Option<Arc<dyn Tracer>>> {
        self.tracer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Drop for QuicResolver {
    fn drop(&mut self) {
        // Tell the peer we're done so it stops promptly instead of waiting out
        // the idle timeout; then let the endpoint flush the close frame.
        self.wire.connection().close(0u32.into(), b"bye");
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        let wire = Arc::clone(&self.wire);
        let flush = async move {
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(1), wire.endpoint.wait_idle())
                    .await;
        };
        // ★ THE THIRD `block_on` SITE, and the one where a panic would be worst. Dropping
        // a resolver from inside a runtime is ordinary — a mount released mid-resolution,
        // a `LazyResolver` swapping a dead peer out — and here BOTH the flush and the
        // `Runtime`'s own drop want to block, which tokio refuses on a runtime thread.
        // So hand both to a thread that is allowed to block and do not wait for it: the
        // close frame is best-effort by nature (the peer's idle timeout is the backstop),
        // and a drop must not stall a caller's worker for up to a second.
        if Handle::try_current().is_ok() {
            std::thread::spawn(move || runtime.block_on(flush));
        } else {
            runtime.block_on(flush);
        }
    }
}

/// A QUIC round-trip failure means the remote kernel is unreachable — a **transient**
/// [`Unavailable`](Error::Unavailable) the reliability overlays (Retry/Failover) can
/// act on, rather than a permanent error.
fn quic_error(e: io::Error) -> Error {
    // A deadline is its own transient, distinct from unreachability: the peer IS there and
    // accepted the stream, it just did not answer in time. A mount reads the difference —
    // `Unavailable` means "nothing is listening", `Timeout` means "it is listening and
    // silent", and only the second says a degraded catalog is hiding real resources.
    if e.kind() == io::ErrorKind::TimedOut {
        return Error::Timeout(format!("quic transport: {e}"));
    }
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
        let tracer = self.tracer().clone();
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
        *self.tracer() = Some(tracer);
    }

    fn clear_tracer(&self) {
        *self.tracer() = None;
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
        self.try_entries().ok().flatten()
    }

    fn try_entries(&self) -> Result<Option<Vec<SpaceEntry>>, Error> {
        match self.round_trip(Call::Entries).map_err(quic_error)? {
            Reply::Entries(entries) => Ok(entries),
            Reply::ErrorTyped(wire) => Err(wire.into()),
            Reply::Error(message) => Err(Error::Endpoint(message)),
            other => Err(Error::Endpoint(format!(
                "unexpected reply to Entries: {other:?}"
            ))),
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
            EndpointSpace::new().bind(Exact::new("urn:test:upper"), builtins::to_upper()),
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
        Request::new(Verb::Source, Iri::parse("urn:test:upper").unwrap())
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
    // Native-only test: the QUIC transport is built on real UDP sockets and has no
    // wasm target at all. The test times a dial to a silent peer to prove it gives
    // up rather than hanging, which needs a genuine monotonic clock.
    #[allow(clippy::disallowed_methods)]
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
        Request::new(Verb::Source, Iri::parse("urn:test:upper").unwrap())
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
                        ikigai_core::Exact::new("urn:test:upper"),
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
            let conn = client.wire.connection().clone();
            conn.close_reason()
        };
        assert!(
            reason.is_some(),
            "a 1s idle must close a connection quiet for 3s"
        );
    }
}

#[cfg(test)]
mod runtime_reentrancy {
    use super::*;
    use ikigai_core::{
        builtins, ArgRef, Capability, EndpointSpace, Error, Exact, FnEndpoint, Invocation, Iri,
        Representation, Verb,
    };
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::thread;

    fn kernel() -> Kernel {
        Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:upper"), builtins::to_upper()),
        ))
    }

    /// Serve `kernel` at root on an ephemeral port until the client goes away. Returns
    /// the address, a client identity pinned to it, the server's certificate, and the
    /// serving thread.
    fn serve_scratch(kernel: Kernel) -> (SocketAddr, Identity, String, thread::JoinHandle<()>) {
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
        let kernel = Arc::new(kernel);
        let session = Session {
            capability: Capability::root(),
            file_segment: String::new(),
        };
        let server = thread::spawn(move || {
            rt.block_on(async move {
                let incoming = endpoint.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                serve_connection(&kernel, connection, &session).await;
            });
        });
        (server_addr, client_id, server_id.cert_pem, server)
    }

    fn upper(word: &str) -> Request {
        Request::new(Verb::Source, Iri::parse("urn:test:upper").unwrap())
            .with_arg("in", ArgRef::Inline(word.as_bytes().to_vec()))
    }

    /// ★ **The regression test, and "from inside a runtime" IS the test.** Every other
    /// test in this module dials and resolves from a plain thread, where `block_on` is
    /// legal — which is exactly why a whole release shipped with every mounted call
    /// panicking. The condition that triggers the bug had never been exercised.
    ///
    /// All three `block_on` sites are covered here, in the order a host hits them: the
    /// DIAL inside `connect`, the round trip inside `issue`, and the `Drop` when the
    /// resolver is released — each on a worker thread of somebody else's multi-thread
    /// runtime, which is what `serve` and an inbound HTTP door both are.
    #[test]
    fn a_resolver_dials_resolves_and_drops_inside_someone_elses_runtime() {
        let (server_addr, client_id, server_cert, server) = serve_scratch(kernel());
        let caller = Runtime::new().unwrap();
        let answer = caller.block_on(async move {
            tokio::spawn(async move {
                let client = connect(server_addr, &client_id, &server_cert).unwrap();
                let (representation, _) = client.issue(upper("hi")).unwrap();
                drop(client);
                String::from_utf8(representation.bytes).unwrap()
            })
            .await
            .expect("the mounted resolve must not panic the caller's worker")
        });
        assert_eq!(answer, "HI");
        server.join().unwrap();
    }

    /// The same three sites from the OTHER runtime-thread shape: directly inside
    /// `block_on`, which is where an inbound HTTP handler resolves. `Handle::try_current`
    /// answers `Ok` here too, and a `block_on` would panic just the same.
    #[test]
    fn a_resolver_works_directly_inside_block_on() {
        let (server_addr, client_id, server_cert, server) = serve_scratch(kernel());
        let caller = Runtime::new().unwrap();
        let answer = caller.block_on(async {
            let client = connect(server_addr, &client_id, &server_cert).unwrap();
            let (representation, _) = client.issue(upper("ok")).unwrap();
            String::from_utf8(representation.bytes).unwrap()
        });
        assert_eq!(answer, "OK");
        server.join().unwrap();
    }

    /// A panicking endpoint must cost ONE CALL, not the connection — and the caller must
    /// be told what happened. Before the boundary in [`dispatch`], the panic unwound the
    /// door's task, the stream died, and the client reported `read error: connection
    /// lost`: the transport blamed for a fault that was never in it.
    ///
    /// (The panic still prints through the default hook, so this test is noisy on
    /// purpose — that output is the server log keeping the backtrace.)
    #[test]
    fn an_endpoint_panic_becomes_a_typed_error_and_the_connection_survives() {
        let boom = FnEndpoint::new(
            "boom",
            |_: &Invocation<'_>| -> Result<Representation, Error> {
                panic!("the endpoint fell over")
            },
        );
        let kernel = Kernel::new(Arc::new(
            EndpointSpace::new()
                .bind(Exact::new("urn:test:upper"), builtins::to_upper())
                .bind(Exact::new("urn:test:boom"), boom),
        ));
        let (server_addr, client_id, server_cert, server) = serve_scratch(kernel);
        let client = connect(server_addr, &client_id, &server_cert).unwrap();

        let error = client
            .issue(Request::new(
                Verb::Source,
                Iri::parse("urn:test:boom").unwrap(),
            ))
            .expect_err("a panicking endpoint must not resolve");
        let rendered = error.to_string();
        assert!(
            rendered.contains("panicked") && rendered.contains("the endpoint fell over"),
            "the error must NAME the panic, not the transport: {rendered}"
        );
        assert!(
            !rendered.contains("connection lost"),
            "the connection must not be what the caller is told about: {rendered}"
        );

        // The connection is still usable — the whole point of catching it.
        let (representation, _) = client.issue(upper("after")).unwrap();
        assert_eq!(String::from_utf8(representation.bytes).unwrap(), "AFTER");
        drop(client);
        server.join().unwrap();
    }
}

#[cfg(test)]
mod describe_timeout {
    use super::*;
    use std::net::SocketAddr;
    use tokio::runtime::Runtime;

    /// ★ The QUIC half of ledger #404: a peer that ACCEPTS the connection and never
    /// answers the enumeration. This is the shape the hub's own `ikigai-gonk` was in —
    /// blocked in `QuicResolver::entries` one hop further down — and with no bound here a
    /// mount of that peer takes the manifold of every kernel that can reach it.
    ///
    /// The idle timeout is left long on purpose: a test that passes proves the DESCRIBE
    /// bound fired, not that the connection eventually gave up.
    #[test]
    // Native-only (QUIC is not built for wasm), and elapsed time is the measurement: it is
    // the only way to tell a bound that fired from a hang that was lucky.
    #[allow(clippy::disallowed_methods)]
    fn a_peer_that_never_answers_an_enumeration_is_bounded_not_awaited() {
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
        // Accepts the connection, then never reads a stream and never writes a reply.
        let _server = std::thread::spawn(move || {
            rt.block_on(async move {
                let Some(incoming) = endpoint.accept().await else {
                    return;
                };
                let _connection = incoming.await;
                tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            });
        });

        let client = connect_with(
            server_addr,
            &client_id,
            &server_id.cert_pem,
            std::time::Duration::from_secs(30),
        )
        .unwrap()
        .with_describe_timeout(Some(std::time::Duration::from_millis(300)));

        let start = std::time::Instant::now();
        let error = client
            .try_entries()
            .expect_err("a peer that never answers is an ERROR, not a wait");
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "bounded by the describe deadline, not the 30s idle timeout: {elapsed:?}"
        );
        // A deadline is a TRANSIENT Timeout, distinct from `Unavailable`: the peer is
        // there and accepted the stream, it is simply silent. A mount reads that
        // difference when it decides whether real resources are missing from its catalog.
        assert!(matches!(error, Error::Timeout(_)), "{error:?}");
        assert!(error.is_transient(), "{error:?}");
    }
}
