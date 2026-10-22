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

use ikigai_core::{
    Capability, Clock, Error, Iri, Kernel, Representation, Request, SpaceEntry, SystemClock, Tracer,
};
use ikigai_resolve::{scoped_entries, CacheStatus, Resolver, RunContext, SpanCollector};
use ikigai_wire::{decode, encode, Call, Reply, TraceContext, PROTOCOL_VERSION};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use tokio::runtime::{Handle, Runtime};

/// The ALPN protocol ids, newest first — since v9, `ikigai/9`, `ikigai/8` then `ikigai/7`
/// ([`ikigai_wire::alpns`]). The TLS handshake IS the version gate on this transport,
/// and there is no hello frame on it: the NEGOTIATED id is the connection's version.
/// Both sides list 9 first, so a v9 pair speaks 9 and a v8 or v7 peer (which offers or
/// accepts only its own ids) still finds its own. A peer outside the range fails the
/// handshake at connect (mDNS TXT advertises the version pre-connect, which is where
/// the human-readable hint lives).
fn alpn_protocols() -> Vec<Vec<u8>> {
    ikigai_wire::alpns()
}

/// The wire version a connection negotiated, read from its ALPN id. `None` when no id
/// was negotiated or it names a version this build does not speak — and both sides
/// REFUSE such a connection rather than guess (a TLS stack that skips ALPN when the
/// server configured none would otherwise hand us a connection with no version at all).
fn negotiated_version(connection: &quinn::Connection) -> Option<u32> {
    let data = connection.handshake_data()?;
    let data = data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?;
    ikigai_wire::version_of_alpn(data.protocol.as_deref()?)
}

/// The QUIC application close code for a connection that negotiated no wire version
/// this build speaks.
const NO_VERSION: u32 = 2;

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
///
/// ★ **`principal` is WHO, never WHAT.** It names the client the minter recognized (an IRI
/// the host derives from the certificate; the convention every host's door follows is
/// `urn:iki:host:{name}:client:<fingerprint>`, the fingerprint being [`fingerprint`]'s
/// lowercase hex SHA-256 of the certificate DER, unless the host's enrolment names the
/// client otherwise).
/// [`dispatch`] carries it two ways:
///
/// - **minted into the capability** ([`Session::authority`]): core 0.1.93's
///   `urn:cap:principal:<iri>` scope, which an endpoint reads with
///   `inv.capability.principal()` and gates on with `acts_as`. A clamp keeps the CEILING's
///   principal (core's rule), so a client that carries a narrower capability of its own (the
///   `ikigai mcp --grant hermes` shape, ledger #879) still arrives named, and one it carries
///   never enters. Not authority either: a principal scope grants nothing a resource requires
///   unless it requires exactly that name.
/// - **stamped** as the inline argument [`PRINCIPAL_ARG`] on every request, replacing anything
///   a client sent under that name. The older channel, kept while a host still reads it
///   (ikigai-gonk did until its own 0.1.93 adoption); it partitions the cache per client at
///   the door, which the minted scope does anyway.
///
/// `None` mints and stamps nothing, and a client-sent `principal` is still removed. Under a
/// ROOT `capability` nothing is minted: root holds every principal and names none.
pub struct Session {
    pub capability: Capability,
    pub file_segment: String,
    pub principal: Option<String>,
}

impl Session {
    /// The capability every call on the connection resolves under (or is clamped to): the
    /// session's `capability` with its `principal` MINTED in as core's principal scope
    /// (ledger #1077), so an endpoint can ask who it serves and a clamp cannot shed the name.
    ///
    /// The capability as given when there is no principal, when it is root (root names
    /// nobody, and `with_principal` refuses it), or when the principal is not a name core can
    /// carry verbatim (not an absolute IRI, longer than 512 bytes, holding `*`): then the
    /// stamped [`PRINCIPAL_ARG`] is the only channel, as before.
    ///
    /// ```
    /// use ikigai_core::Capability;
    /// use ikigai_quic::Session;
    ///
    /// let session = Session {
    ///     capability: Capability::scoped(["urn:cap:demo:read".to_string()]),
    ///     file_segment: String::new(),
    ///     principal: Some("urn:example:alice".to_string()),
    /// };
    /// let authority = session.authority();
    /// assert_eq!(authority.principal(), Some("urn:example:alice"));
    /// // A client carrying a narrower capability of its own stays named after the clamp.
    /// let carried = Capability::scoped(["urn:cap:demo:read".to_string()]);
    /// assert_eq!(authority.clamp(&carried).principal(), Some("urn:example:alice"));
    ///
    /// // Root names nobody.
    /// let root = Session { capability: Capability::root(), ..session };
    /// assert_eq!(root.authority(), Capability::root());
    /// ```
    pub fn authority(&self) -> Capability {
        match self.principal.as_deref() {
            Some(principal) => self
                .capability
                .with_principal(principal)
                .unwrap_or_else(|_| self.capability.clone()),
            None => self.capability.clone(),
        }
    }
}

/// The inline argument a [`Session`]'s principal arrives under, on every request the
/// connection carries: the same name `ikigai-web` stamps on a write, so a host reads one
/// argument whichever door a request came through.
///
/// ```
/// use ikigai_core::{ArgRef, Capability, Iri, Kernel, EndpointSpace, Request, Verb};
/// use ikigai_quic::{dispatch, Session, PRINCIPAL_ARG};
/// use ikigai_wire::{Call, Reply};
/// use std::sync::Arc;
///
/// assert_eq!(PRINCIPAL_ARG, "principal");
/// // An endpoint that answers with the principal it was handed, or `-` for none.
/// let whoami = ikigai_core::FnEndpoint::new("whoami", |inv: &ikigai_core::Invocation<'_>| {
///     let who = inv.inline_str(PRINCIPAL_ARG).unwrap_or("-").to_string();
///     Ok(ikigai_core::Representation::new(
///         ikigai_core::ReprType::new("text/plain"),
///         who.into_bytes(),
///     ))
/// });
/// let kernel = Kernel::new(Arc::new(
///     EndpointSpace::new().bind(ikigai_core::Exact::new("urn:test:whoami"), whoami),
/// ));
/// let session = Session {
///     capability: Capability::root(),
///     file_segment: String::new(),
///     principal: Some("urn:example:alice".to_string()),
/// };
/// // The client names someone else; the connection's principal wins.
/// let forged = Request::new(Verb::Source, Iri::parse("urn:test:whoami").unwrap())
///     .with_arg(PRINCIPAL_ARG, ArgRef::Inline(b"urn:example:mallory".to_vec()));
/// match dispatch(&kernel, Call::Issue(forged), &session) {
///     Reply::Resolved(answer, _) => assert_eq!(answer.bytes, b"urn:example:alice"),
///     other => panic!("{other:?}"),
/// }
/// ```
pub const PRINCIPAL_ARG: &str = "principal";

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

/// Where a door reads the client certificates it trusts (PEMs), called at **every TLS
/// handshake**, so a certificate added to the list is trusted at its next connection and one
/// removed is refused at its next connection, without a restart (ledger #1825).
///
/// `Err` refuses the handshake: a trust list that cannot be read trusts nobody, it never
/// falls back to the last reading. A PEM that does not parse trusts nobody either, and the
/// rest of the list still does. The function is where a failure is LOGGED, as a [`Minter`]
/// logs its refusals: it holds the paths that make a log line actionable, and this crate
/// only refuses. It runs on the connection's handshake path, so it should be cheap (reading a
/// directory of a few small files is).
///
/// [`serve_trusting_on`] takes one; the doors that take a slice of PEMs pin that slice for
/// their whole life, as they always did.
pub type TrustList = Arc<dyn Fn() -> io::Result<Vec<String>> + Send + Sync>;

/// The QUIC application close code for a peer whose certificate authenticated but
/// carries no authority. Distinct from a handshake failure: the cert IS trusted, the
/// *authorization* is missing.
const UNAUTHORIZED: u32 = 1;

/// The QUIC application close code for a connection closed because it reached the door's
/// connection-age bound ([`serve_bounded`]). Not an error: the client's next call redials,
/// and the new connection is minted afresh, which is the point.
const AGED: u32 = 3;

/// How long a connection that reached its age bound mid-call waits for the peer to
/// acknowledge that call's reply before the door closes it. A reply the door has finished
/// writing is not yet DELIVERED, and closing at once would throw it away.
const REPLY_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// How long a CALL may be silent: the default per-call deadline ([`connect_with`] starts
/// [`QuicResolver::with_call_timeout`] at the `idle` it is given), and a SERVER's idle timeout.
///
/// Generous on purpose, mirroring `ipc.timeout` (cli #259): the server says nothing
/// until a resolution finishes, so for a long resolution — a 70B loading ~40GB, a
/// hard question generating for minutes — the silence IS the work. quinn's ~30s
/// default killed exactly those calls mid-generation while the model kept computing.
/// A deadline that cannot tell "hung" from "busy" reports the wrong thing confidently,
/// which is worse than reporting late. `quic.timeout` (seconds) in the host config overrides.
///
/// ★ Until cli 0.1.56 this was also how long a peer that died MID-REQUEST took to notice.
/// Now the client pings and its connection's idle timeout is [`LIVENESS_TIMEOUT`], so a dead
/// peer is found in seconds while a silent call keeps this much patience (ledger
/// [#1359](http://localhost:1060/l/default/item/1359)). A server built with it and talking to
/// a client older than 0.1.56 (which does not ping) still idles out at this bound, as before.
pub const DEFAULT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// How long a CLIENT's connection may go without hearing anything from its peer before it is
/// declared dead: the QUIC idle timeout a client actually runs with (capped by the `idle` it
/// was given, if that is shorter), negotiated down to the server's too, since QUIC takes the
/// smaller of the two. Since cli 0.1.56 (ledger
/// [#1359](http://localhost:1060/l/default/item/1359)).
///
/// A peer that vanishes (power, network, a wedged host) without closing is found within this
/// bound by BOTH ends, where it used to cost the whole [`DEFAULT_IDLE_TIMEOUT`]. It can be
/// this short because the client pings ([`KEEP_ALIVE_INTERVAL`]): a live peer is never silent
/// at the transport, however long the call it is working on.
///
/// Why fifteen seconds: short enough that a dead peer is found while a person is still
/// waiting, long enough to ride out a Wi-Fi roam or a congested link that loses two pings in
/// a row. quinn's own default idle timeout is thirty seconds with no pings at all.
pub const LIVENESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// How often a client PINGs a connection that has carried nothing else for that long: a third
/// of [`LIVENESS_TIMEOUT`], so a live connection is declared dead only after three pings in a
/// row (or their acknowledgments) are lost, and quinn's loss recovery probes again in
/// between. A busy connection sends no pings at all. The cost of an idle one is one small
/// packet each way every five seconds, which also keeps a NAT's UDP mapping warm (those
/// commonly expire after thirty seconds or more) through a long silent call.
pub const KEEP_ALIVE_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(LIVENESS_TIMEOUT.as_secs() / 3);

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

/// The QUIC application error code a client sends when it gives up on a call: `STOP_SENDING`
/// on the reply half, and `RESET_STREAM` on the request half if that was still being written.
/// Ordinary QUIC frames, so a peer of any version understands them: canceling is not a wire
/// change (ledger [#1335](http://localhost:1060/l/default/item/1335)).
pub const CANCELED: u32 = 0x1335;

/// How many calls a door answers AT ONCE on one connection (ledger
/// [#1692](http://localhost:1060/l/default/item/1692)).
///
/// ★ Every call is its own bidirectional stream, and a mount holds ONE connection to its peer
/// for everything its host asks of it. Through cli 0.1.63 a door answered a connection's streams
/// one at a time, so a long poll (`urn:layers:feed … wait=50`) held every other call on that
/// mount past its deadline; gonk's Layers page had to give its follower a connection of its
/// own. Now each call runs as its own task, up to this many at once per connection.
///
/// **Past the bound a call is REFUSED at once**, as a transient
/// [`Unavailable`](Error::Unavailable) naming the bound, never queued: a queue at the door
/// would be the same silent stall with a longer fuse, while a refusal tells the caller now, and
/// a reliability overlay may retry it. The bound frees as calls finish.
///
/// Why sixteen: a connection belongs to ONE enrolled client (mTLS), and what one client runs
/// at once is a handful of long polls (a follower per layer it watches) beside its ordinary
/// calls, well under it. It is a per-connection bound, not the door's: the door still caps
/// neither connections nor calls across them, and each call in progress takes a thread for as
/// long as it runs (`block_in_place`), as it always did, drawn from the door runtime's
/// blocking pool (tokio's default, 512 threads) that every connection shares. What it costs: a
/// connection may now hold sixteen requests in memory at once, each under the per-message
/// bound (64 MiB), where it used to hold one. Above it, QUIC's own stream limit (quinn's
/// default, 100 streams open at once per connection) still caps how many calls a client can
/// have open, refused ones included; past THAT the client waits for a stream, under its own
/// call deadline.
pub const MAX_CALLS_PER_CONNECTION: usize = 16;

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
    serve_bounded(
        kernel,
        addr,
        identity,
        trusted_client_cert_pems,
        minter,
        idle,
        None,
    )
}

/// [`serve_with`], closing every connection once it is `max_age` old (`None`: never).
///
/// ★ **Why a door bounds connection age** (ledger #1179). The [`Minter`] runs once per
/// CONNECTION, so the authority it minted — and the principal it named — holds for as long
/// as that connection lives. A host that re-reads its enrolment per connection makes an
/// edit a revocation only on the client's NEXT connection, and a client that reuses one
/// connection (a daemon's standing mount, an MCP server) may never make one. The bound
/// turns "eventually, if the client reconnects" into "within `max_age`".
///
/// What the client sees: nothing, normally. When the bound passes the door stops accepting
/// calls on the connection; the calls already in progress (up to [`MAX_CALLS_PER_CONNECTION`])
/// finish and their replies are delivered (each waited for up to five seconds) before the
/// door closes with code 3; a connection that is idle when it passes is closed then. A call
/// the client opens while those finish is turned away at once (its stream reset under code
/// 3), so the resolver redials rather than wait behind them; a read is replayed on the new
/// connection, a Sink or Delete is not (it did not run). The resolver from
/// [`connect_with`] heals onto a new connection at its next call, minted afresh — refused,
/// if the client was revoked. ⚠ One race remains: a call the client opens in the instant
/// the door closes fails as a lost reply, and a Sink or Delete is then NOT replayed (the
/// resolver's rule for any lost reply); the caller sees a transient error and decides.
pub fn serve_bounded(
    kernel: Kernel,
    addr: SocketAddr,
    identity: &Identity,
    trusted_client_cert_pems: &[String],
    minter: Minter,
    idle: std::time::Duration,
    max_age: Option<std::time::Duration>,
) -> io::Result<()> {
    serve_bounded_on(
        kernel,
        bind(addr)?,
        identity,
        trusted_client_cert_pems,
        minter,
        idle,
        max_age,
    )
}

/// Bind the UDP socket a door serves on, BEFORE it serves: [`serve_bounded_on`] takes it.
///
/// ★ **Why a door binds first** (ledger #1188, the QUIC face of ledger #1223). A door that
/// announces readiness before it binds can only name the address it was GIVEN, so `quic://
/// 127.0.0.1:0` announced port 0 and every harness had to pick a port itself, by binding one
/// and releasing it. On macOS a child spawned in the instant between `socket()` and
/// `FD_CLOEXEC` inherits that socket and holds the port, so the door then fails to bind and
/// the test reads a door bug. Bound here, the door names [`std::net::UdpSocket::local_addr`]:
/// port 0 becomes the port the kernel chose, and nobody has to choose one.
///
/// A **wildcard** address (`0.0.0.0` or `[::]`) binds ONE dual-stack IPv6 socket
/// (`IPV6_V6ONLY` off), so it accepts both IPv4 (as v4-mapped) and IPv6: a client dialing
/// either family reaches it (the `.local`-resolves-to-both-families-and-picks-IPv6 timeout).
/// A specific address is bound as given, single-family.
pub fn bind(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let udp = if addr.ip().is_unspecified() {
        use socket2::{Domain, Protocol, Socket, Type};
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(false)?; // dual-stack: also accept IPv4 (v4-mapped)
        let bind = SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), addr.port());
        socket.bind(&bind.into())?;
        socket.into()
    } else {
        std::net::UdpSocket::bind(addr)?
    };
    udp.set_nonblocking(true)?;
    Ok(udp)
}

/// [`serve_bounded`] on a socket [`bind`] already bound, so the caller can name the bound
/// address (and announce readiness) before serving.
pub fn serve_bounded_on(
    kernel: Kernel,
    socket: std::net::UdpSocket,
    identity: &Identity,
    trusted_client_cert_pems: &[String],
    minter: Minter,
    idle: std::time::Duration,
    max_age: Option<std::time::Duration>,
) -> io::Result<()> {
    serve_shared_on(
        Arc::new(kernel),
        socket,
        identity,
        trusted_client_cert_pems,
        minter,
        idle,
        max_age,
    )
}

/// [`serve_bounded_on`] over a kernel the caller SHARES with another door.
///
/// ★ Two doors onto one kernel must be one kernel, not two kernels over the same state: a
/// kernel's cache and its golden threads are its own, so a write through one would cut a thread
/// only the other's readers hang from, and a read through the second could answer from a cache
/// the write never touched. A host serving a second face (an HTTPS front for participants who
/// speak only HTTP) hands both doors this one `Arc`.
pub fn serve_shared_on(
    kernel: Arc<Kernel>,
    socket: std::net::UdpSocket,
    identity: &Identity,
    trusted_client_cert_pems: &[String],
    minter: Minter,
    idle: std::time::Duration,
    max_age: Option<std::time::Duration>,
) -> io::Result<()> {
    let config = server_config(identity, trusted_client_cert_pems, idle)?;
    serve_config_on(kernel, socket, identity, config, minter, max_age)
}

/// [`serve_shared_on`] with a [`TrustList`] read at every handshake instead of a fixed set
/// of PEMs, so the door's trust list can change while it serves.
///
/// The list is read once here too, before anything is served: a list that cannot be read, or
/// holds a PEM that does not parse, stops the door at start, as a bad fixed set does.
pub fn serve_trusting_on(
    kernel: Arc<Kernel>,
    socket: std::net::UdpSocket,
    identity: &Identity,
    trust: TrustList,
    minter: Minter,
    idle: std::time::Duration,
    max_age: Option<std::time::Duration>,
) -> io::Result<()> {
    for pem in trust()? {
        load_cert(&pem)?;
    }
    let config = server_config_pinning(identity, Pins::Live(trust), idle, alpn_protocols())?;
    serve_config_on(kernel, socket, identity, config, minter, max_age)
}

/// [`serve_trusting_on`] for a door with a LOBBY (ledger #2009): it also admits a client
/// certificate that is NOT on its trust list, and hands that connection to `lobby` instead of
/// `minter`.
///
/// At TLS the door accepts ANY client certificate inside its validity window (ledger #1826).
/// TLS 1.3's CertificateVerify still proves the client holds the certificate's key, so the
/// [`PeerIdentity`] fingerprint is a real identity; it is just not a TRUSTED one. After the
/// handshake the trust list is read, once per connection:
///
/// - a certificate ON the list goes to `minter`, exactly as [`serve_trusting_on`] would hand it
///   over, so an enrolled client is served as before and removing its certificate from the
///   list still takes it out of `minter`'s reach at its next connection;
/// - a certificate NOT on the list goes to `lobby`, which mints what an unenrolled certificate
///   may do (a host's lobby capability, and nothing more) or refuses with `None`;
/// - a list that does not read refuses the connection: a door that cannot tell an enrolled
///   client from a stranger serves neither.
///
/// Either minter's `None` closes the connection with the same application code a refused
/// trusted client gets today. A door that has no lobby keeps calling [`serve_trusting_on`],
/// which still refuses an unlisted certificate at the handshake.
///
/// The list is read once at start too, as [`serve_trusting_on`] does.
#[allow(clippy::too_many_arguments)] // one door's whole configuration, in the order its siblings take it
pub fn serve_lobby_on(
    kernel: Arc<Kernel>,
    socket: std::net::UdpSocket,
    identity: &Identity,
    trust: TrustList,
    minter: Minter,
    lobby: Minter,
    idle: std::time::Duration,
    max_age: Option<std::time::Duration>,
) -> io::Result<()> {
    for pem in trust()? {
        load_cert(&pem)?;
    }
    let config = server_config_pinning(identity, Pins::AnyInWindow, idle, alpn_protocols())?;
    serve_config_on(
        kernel,
        socket,
        identity,
        config,
        lobby_router(trust, minter, lobby),
        max_age,
    )
}

/// The [`Minter`] a lobby door runs: the trusted path for a listed certificate, the lobby for
/// any other, nothing when the list does not read. See [`serve_lobby_on`].
///
/// A listed certificate is matched by [`fingerprint`] (SHA-256 of its DER), which is what the
/// [`PeerIdentity`] carries; a PEM in the list that does not parse lists nobody, as it pins
/// nobody on the other doors.
fn lobby_router(trust: TrustList, minter: Minter, lobby: Minter) -> Minter {
    Arc::new(move |peer: &PeerIdentity| {
        let listed = trust().ok()?.iter().any(|pem| {
            load_cert(pem).is_ok_and(|der| fingerprint(der.as_ref()) == peer.fingerprint)
        });
        if listed {
            minter(peer)
        } else {
            lobby(peer)
        }
    })
}

/// The accept loop every server door runs, under a built `config`.
fn serve_config_on(
    kernel: Arc<Kernel>,
    socket: std::net::UdpSocket,
    identity: &Identity,
    config: quinn::ServerConfig,
    minter: Minter,
    max_age: Option<std::time::Duration>,
) -> io::Result<()> {
    let endpoint_config = endpoint_config(identity);
    let runtime = Runtime::new()?;
    runtime.block_on(async move {
        let endpoint = endpoint_on(config, socket, endpoint_config)?;
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
                        Some(session) => {
                            serve_connection_aged(kernel, connection, session, max_age).await
                        }
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

/// The server endpoint over a bound socket, under `endpoint_config` (see
/// [`endpoint_config`]): what `quinn::Endpoint::server` would build is a RANDOM
/// stateless-reset key per process. Must run inside the Tokio runtime that drives it.
fn endpoint_on(
    config: quinn::ServerConfig,
    socket: std::net::UdpSocket,
    endpoint_config: quinn::EndpointConfig,
) -> io::Result<quinn::Endpoint> {
    quinn::Endpoint::new(
        endpoint_config,
        Some(config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
}

/// The server endpoint's config, with a stateless-reset key DERIVED FROM ITS IDENTITY
/// (ledger #1092).
///
/// A QUIC server that loses a connection's state (it restarted, or crashed) answers that
/// connection's next packet with a STATELESS RESET, and the client drops the connection at
/// once — but only if the reset's token checks out, and the token is an HMAC under the
/// server's reset key. quinn's default key is random per process, so a RESTARTED server's
/// resets were ignored: the client kept the dead connection and every call on it waited out
/// the idle timeout ([`DEFAULT_IDLE_TIMEOUT`], five minutes; gonk's explain took 304 s after
/// its model peer restarted). Keyed on the identity, the restarted server's resets carry the
/// tokens its predecessor issued, so the client's next call fails at once, redials (its
/// existing heal-on-use path) and succeeds.
///
/// The key is a hash of the server's PRIVATE key under a domain label: as stable as the
/// identity, and as secret (someone who could forge resets could only end connections). The
/// connection-ID generator is keyed from the same material, for the reason in the body.
fn endpoint_config(identity: &Identity) -> quinn::EndpointConfig {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ikigai-quic stateless-reset key v1\0");
    hasher.update(identity.key_pem.as_bytes());
    let material = hasher.finalize();
    let mut config = quinn::EndpointConfig::new(Arc::new(ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        &material,
    )));
    // ★ The connection IDs too. quinn's default generator signs each ID under a RANDOM
    // per-process key and drops a packet whose ID does not validate, before it would reset
    // it: so a restarted server with the right reset key still never sent a reset (found by
    // `restart::a_restarted_server_resets_…`, which waited out the full idle timeout). A key
    // from the same material makes the predecessor's IDs the successor's own.
    let mut cid_key = [0u8; 8];
    cid_key.copy_from_slice(&Sha256::digest([b"cid:".as_slice(), &material].concat())[..8]);
    let cid_key = u64::from_le_bytes(cid_key);
    config.cid_generator(move || {
        Box::new(quinn_proto::HashedConnectionIdGenerator::from_key(cid_key))
    });
    config
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
///
/// Every reply is encoded AT THE VERSION THE CONNECTION NEGOTIATED ([`Reply::for_peer`]),
/// so a v7 client never meets a variant it cannot decode.
/// (The unbounded form, which this crate's tests drive directly; a door goes through
/// [`serve_connection_aged`].)
#[cfg(test)]
async fn serve_connection(kernel: &Arc<Kernel>, connection: quinn::Connection, session: Session) {
    serve_connection_aged(Arc::clone(kernel), connection, session, None).await;
}

/// [`serve_connection`], closing the connection once it is `max_age` old — see
/// [`serve_bounded`] for when, and what a client sees.
///
/// Each call is answered by its own task ([`answer`]), up to [`MAX_CALLS_PER_CONNECTION`] at
/// once; past that a call is refused ([`refuse`]). This loop only accepts streams, so a long
/// call never holds up the next one on the same connection (ledger
/// [#1692](http://localhost:1060/l/default/item/1692)).
async fn serve_connection_aged(
    kernel: Arc<Kernel>,
    connection: quinn::Connection,
    session: Session,
    max_age: Option<std::time::Duration>,
) {
    let Some(version) = negotiated_version(&connection) else {
        connection.close(
            NO_VERSION.into(),
            b"no ikigai wire version was negotiated (ALPN)",
        );
        return;
    };
    let session = Arc::new(session);
    // tokio's clock, not `std::time::Instant` (banned workspace-wide for wasm's sake): this
    // crate is native-only, and the deadline is compared only with tokio's own timers.
    let deadline = max_age.map(|age| tokio::time::Instant::now() + age);
    // One permit per call in progress. A call holds its permit until its reply is written
    // (and, past the age bound, delivered), so taking EVERY permit is how the age bound
    // waits for the calls in progress to finish.
    let in_flight = Arc::new(tokio::sync::Semaphore::new(MAX_CALLS_PER_CONNECTION));
    loop {
        let next = match deadline {
            Some(at) => match tokio::time::timeout_at(at, connection.accept_bi()).await {
                Ok(next) => next,
                Err(_elapsed) => break,
            },
            None => connection.accept_bi().await,
        };
        let Ok((send, recv)) = next else {
            return;
        };
        match Arc::clone(&in_flight).try_acquire_owned() {
            Ok(permit) => {
                let kernel = Arc::clone(&kernel);
                let session = Arc::clone(&session);
                tokio::spawn(async move {
                    answer(&kernel, &session, send, recv, version, deadline).await;
                    drop(permit);
                });
            }
            Err(_) => {
                tokio::spawn(refuse(send, recv, version));
            }
        }
    }
    // The bound passed: run nothing more, let the calls in progress finish and their replies
    // land (idle, this returns at once), then close. Meanwhile a call opened on this connection
    // is turned away at once, both halves reset under code 3, rather than left unaccepted
    // behind a long call (a long poll) past its own deadline: its client heals onto a new
    // connection, where a read is replayed and a Sink or Delete fails as a transient (not run).
    let turn_away = tokio::spawn({
        let connection = connection.clone();
        async move {
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                let _ = send.reset(AGED.into());
                let _ = recv.stop(AGED.into());
            }
        }
    });
    let all = u32::try_from(MAX_CALLS_PER_CONNECTION).unwrap_or(u32::MAX);
    let _ = in_flight.acquire_many(all).await;
    connection.close(
        AGED.into(),
        b"this door bounds connection age; reconnect to continue",
    );
    turn_away.abort();
}

/// Answer ONE call: read it (at most [`MAX_MESSAGE`]), resolve it under the connection's
/// session off the runtime's workers ([`dispatch_off_worker`]), and write the reply at the
/// connection's wire `version`. A stream that fails or overruns the message bound while being
/// read gets no reply; that costs this call and never the connection's other calls.
async fn answer(
    kernel: &Kernel,
    session: &Session,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    version: u32,
    deadline: Option<tokio::time::Instant>,
) {
    let Ok(bytes) = recv.read_to_end(MAX_MESSAGE).await else {
        return;
    };
    let reply = match decode::<Call>(&bytes) {
        Ok(call) => dispatch_off_worker(kernel, call, session),
        Err(e) => Reply::ErrorTyped(ikigai_wire::WireError::Endpoint(format!(
            "malformed call: {e}"
        ))),
    };
    if let Ok(out) = encode(&reply.for_peer(version)) {
        let _ = send.write_all(&out).await;
        let _ = send.finish();
    }
    // The age bound passed while this call ran: the door closes once every call in progress
    // is done, so let this reply land first.
    if deadline.is_some_and(|at| tokio::time::Instant::now() >= at) {
        let _ = tokio::time::timeout(REPLY_GRACE, send.stopped()).await;
    }
}

/// Refuse ONE call because its connection already has [`MAX_CALLS_PER_CONNECTION`] in
/// progress: a transient [`Unavailable`](Error::Unavailable) naming the bound, at once. The
/// request is read to its end first (under the same message bound), so the client sees a
/// reply to a call it finished sending, never a stream cut off mid-write.
async fn refuse(mut send: quinn::SendStream, mut recv: quinn::RecvStream, version: u32) {
    if recv.read_to_end(MAX_MESSAGE).await.is_err() {
        return;
    }
    let reply = Reply::ErrorTyped(ikigai_wire::WireError::Unavailable(format!(
        "this connection already has {MAX_CALLS_PER_CONNECTION} calls in progress, the most a \
         door answers at once on one connection; the call was not run, retry it when one \
         finishes"
    )));
    if let Ok(out) = encode(&reply.for_peer(version)) {
        let _ = send.write_all(&out).await;
        let _ = send.finish();
    }
}

/// Put the connection's principal on `request` under [`PRINCIPAL_ARG`], removing whatever
/// the client sent there first (in any form, inline or by reference), so the only principal
/// an endpoint can see is the one the minter named. On EVERY verb, unlike `ikigai-web`, which
/// stamps writes only: an HTTP read has no authenticated connection behind it in general,
/// while every call on a QUIC connection does, and a host's access log wants who READ as
/// much as who wrote. The cost is the one `ikigai-web` avoids: an argument is part of the
/// cache key, so two clients reading the same resource under the same capability no longer
/// share a cached answer. On a QUIC door they rarely did, since each enrolled client
/// normally holds its own grant.
fn stamp_principal(request: &mut Request, principal: Option<&str>) {
    request.args.remove(PRINCIPAL_ARG);
    if let Some(principal) = principal {
        request.args.insert(
            PRINCIPAL_ARG.to_string(),
            ikigai_core::ArgRef::Inline(principal.as_bytes().to_vec()),
        );
    }
}

/// Everything the door does to a request before it resolves: the file namespace rooted at
/// the session's segment ([`localize`]) and the principal stamped ([`stamp_principal`]).
fn admit(request: &mut Request, session: &Session) {
    localize(request, &session.file_segment);
    stamp_principal(request, session.principal.as_deref());
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

/// [`dispatch`], from a door's async task, WITHOUT stalling the transport while it runs.
///
/// ★ A resolution is synchronous and may run for minutes (a model generating), and it runs
/// on a runtime worker. tokio puts a task woken by the running one in that worker's LIFO
/// slot, which no other worker may steal, and reading the call to its end wakes the
/// CONNECTION'S DRIVER there. Blocking the worker then froze the connection for the whole
/// resolution: no packet read, no acknowledgment sent. Nothing needed either while nothing
/// pinged, but a client that pings (cli 0.1.56, ledger
/// [#1359](http://localhost:1060/l/default/item/1359)) hears no acknowledgment and declares
/// a live, working peer dead at its liveness bound, which is exactly the honest long call
/// keep-alive must keep (`keep_alive::an_honest_call_silent_past_the_old_idle_window_still_answers`
/// failed that way against this door before this function). `block_in_place` hands the
/// worker's queued tasks, the LIFO slot included, to another thread first. It exists only on
/// a multi-thread runtime, which is what every door here builds ([`serve_bounded_on`]); on
/// any other, the call is made in place as before.
fn dispatch_off_worker(kernel: &Kernel, call: Call, session: &Session) -> Reply {
    let multi_thread = Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
    if multi_thread {
        tokio::task::block_in_place(|| dispatch(kernel, call, session))
    } else {
        dispatch(kernel, call, session)
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
    // The session's capability with its principal minted in (ledger #1077): every arm below
    // resolves under it or clamps to it, so the name rides the capability on every verb.
    let authority = session.authority();
    let issue = |mut request: Request, capability: &Capability| {
        admit(&mut request, session);
        match Resolver::issue_as(kernel, request, capability) {
            Ok((representation, status)) => Reply::Resolved(representation, status),
            Err(error) => Reply::ErrorTyped(ikigai_wire::WireError::from(&error)),
        }
    };
    match call {
        // Resolve under the session — capability-on-the-wire via the client cert.
        Call::Issue(request) => issue(request, &authority),
        // A carried capability is untrusted: the peer can only *narrow* its own
        // authority, so clamp it to the session before resolving (never widen past
        // the authenticated principal).
        Call::IssueAs(request, carried) => issue(request, &authority.clamp(&carried)),
        // Admitted exactly as an issue is, or the answer would name a cache key no issue
        // on this connection ever uses.
        Call::IsCached(mut request) => {
            admit(&mut request, session);
            Reply::Cached(Resolver::is_cached(kernel, &request, &authority))
        }
        // List the manifold the client's authenticated capability actually permits —
        // never the full catalog. Affordance = authorization: a scoped principal must
        // not even enumerate what it may not invoke (the leak this closes).
        Call::Entries => Reply::Entries(Some(scoped_entries(kernel, &authority))),
        // Trace-over-the-wire: resolve under the clamped authority with a
        // PER-CALL collector (`issue_traced_as`), ship the recorded spans back.
        // Each tenant's trace records into its own scope — concurrent traced
        // calls can no longer interleave through the process-global tracer, which
        // closes the cross-tenant trace leak (a tracing tenant observing another
        // tenant's IRIs and cap scopes). `_ctx.parent_span` is for a future
        // mount-stitch.
        Call::IssueTraced(mut request, carried, _ctx) => {
            admit(&mut request, session);
            let capability = authority.clamp(&carried);
            let collector = Arc::new(SpanCollector::default());
            match ikigai_resolve::issue_traced_as(kernel, request, &capability, collector.clone()) {
                Ok((representation, status)) => {
                    Reply::ResolvedTraced(representation, status, collector.take())
                }
                Err(error) => Reply::ErrorTyped(ikigai_wire::WireError::from(&error)),
            }
        }
        // Wire v9: the caller's run context, under the clamped authority like every
        // other arm. The time left is added to THIS door's now (the system clock, which
        // the kernel reads by default; core exposes no accessor for a pinned one), and the
        // kernel narrows the retries to the clamped capability's entitlement, so a peer
        // shortens its own budget and never lengthens it.
        Call::IssueWith(mut request, carried, with) => {
            admit(&mut request, session);
            let capability = authority.clamp(&carried);
            let context = with.issue_context(SystemClock.now());
            match with.trace {
                Some(_ctx) => {
                    let collector = Arc::new(SpanCollector::default());
                    match ikigai_resolve::issue_traced_as_with_context(
                        kernel,
                        request,
                        &capability,
                        collector.clone(),
                        context,
                    ) {
                        Ok((representation, status)) => {
                            Reply::ResolvedTraced(representation, status, collector.take())
                        }
                        Err(error) => Reply::ErrorTyped(ikigai_wire::WireError::from(&error)),
                    }
                }
                None => match ikigai_resolve::issue_as_with_context(
                    kernel,
                    request,
                    &capability,
                    context,
                ) {
                    Ok((representation, status)) => Reply::Resolved(representation, status),
                    Err(error) => Reply::ErrorTyped(ikigai_wire::WireError::from(&error)),
                },
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
///
/// The resolver's per-call deadline ([`QuicResolver::with_call_timeout`]) starts at the same
/// value as `idle`: see that method for why. The connection itself pings and runs under the
/// shorter [`LIVENESS_TIMEOUT`] (or `idle`, if that is shorter still), so a dead peer is
/// found in seconds however patient the calls are.
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
            stale: std::sync::atomic::AtomicBool::new(false),
        }),
        tracer: Mutex::new(None),
        describe_timeout: Some(DEFAULT_DESCRIBE_TIMEOUT),
        call_timeout: Some(idle),
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
    /// The deadline every OTHER call runs under, start to finish (see
    /// [`with_call_timeout`](Self::with_call_timeout)); `None` leaves it unbounded.
    call_timeout: Option<std::time::Duration>,
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
    /// Set when a self-description timed out on the current connection (ledger #1092): the
    /// next round trip redials FIRST instead of trying that connection again. A peer that
    /// restarted without resetting it (one older than this release, or one killed outright
    /// with nothing listening) leaves a connection that looks alive and answers nothing, and
    /// trying it again is what cost a second describe deadline and then the whole idle
    /// timeout. The old connection is not closed: a call already in flight on it keeps it.
    stale: std::sync::atomic::AtomicBool,
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
    ///
    /// ★ What may be REPLAYED is the IPC transport's discipline (`replay_may_follow`
    /// there): a call that never reached the peer is always safe to send again, but once
    /// the request was handed over whole, the peer may have run it and only the reply was
    /// lost. Then only a `replayable` call (a read) is sent again; a Sink or Delete
    /// surfaces the transient for its CALLER to decide, because running it twice is not
    /// the transport's choice to make (ledger #733, finding Q2). The connection still
    /// heals: the next call's stream fails to open on the dead one and reconnects.
    async fn round_trip(&self, request: Vec<u8>, replayable: bool) -> io::Result<Reply> {
        use std::sync::atomic::Ordering;
        if self.stale.swap(false, Ordering::SeqCst) {
            if let Err(error) = self.reconnect().await {
                self.stale.store(true, Ordering::SeqCst);
                return Err(error);
            }
        }
        match self.attempt(&request).await {
            Ok(reply) => Ok(reply),
            Err(Attempt::Sent(error)) if !replayable => Err(error),
            Err(_) => {
                self.reconnect().await?;
                self.attempt(&request).await.map_err(Attempt::into_error)
            }
        }
    }

    /// One attempt on the current connection. Cloning the connection out of the lock
    /// (cheap — it is an `Arc` inside) keeps the guard from being held across an await.
    async fn attempt(&self, request: &[u8]) -> Result<Reply, Attempt> {
        let connection = { self.connection().clone() };
        // The peer runs a call only once it reads the stream to its end, so until
        // `finish` succeeds nothing can have run: a failure here is `Unsent`.
        let (send, recv) = connection.open_bi().await.map_err(Attempt::unsent)?;
        let mut stream = InFlight {
            send,
            recv,
            sent: false,
            answered: false,
        };
        stream
            .send
            .write_all(request)
            .await
            .map_err(Attempt::unsent)?;
        stream.send.finish().map_err(Attempt::unsent)?;
        stream.sent = true;
        let bytes = stream
            .recv
            .read_to_end(MAX_MESSAGE)
            .await
            .map_err(|e| Attempt::Sent(other(e)))?;
        stream.answered = true;
        decode(&bytes).map_err(Attempt::Sent)
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

    /// The wire version the CURRENT connection negotiated (its ALPN id), what a call is
    /// shaped for ([`Call::as_sent_to`]). This build's own version when the connection
    /// has none this build speaks, which [`dial`] never lets stand for long.
    fn version(&self) -> u32 {
        negotiated_version(&self.connection()).unwrap_or(PROTOCOL_VERSION)
    }
}

/// How an [`attempt`](Wire::attempt) failed, as far as replaying it is concerned.
enum Attempt {
    /// The request never reached the peer whole, so it cannot have run.
    Unsent(io::Error),
    /// The request was handed over; the peer may have run it and the reply been lost.
    Sent(io::Error),
}

impl Attempt {
    fn unsent<E: std::fmt::Display>(error: E) -> Self {
        Attempt::Unsent(other(error))
    }

    fn into_error(self) -> io::Error {
        match self {
            Attempt::Unsent(error) | Attempt::Sent(error) => error,
        }
    }
}

/// One call's stream, CANCELED on the wire if it is dropped before its reply was read.
///
/// ★ This is how a deadline ends a call rather than merely stops waiting for it (ledger
/// [#1335](http://localhost:1060/l/default/item/1335)). A deadline drops the round trip's
/// future, and with it this value: the reply half is STOPPED (the peer's write of a reply
/// nobody will read fails at once instead of filling a buffer), and a request half still
/// being written is RESET. quinn's own `Drop` would do the first, but would FINISH a
/// half-written request, handing the peer a truncated call to decode: canceling says so
/// explicitly, under [`CANCELED`]. Both frames are plain QUIC, so no peer needs to know a
/// deadline exists.
struct InFlight {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    /// The request was written whole and finished, so there is nothing to reset.
    sent: bool,
    /// The reply was read to its end, so there is nothing to stop.
    answered: bool,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if self.answered {
            return;
        }
        let code = quinn::VarInt::from_u32(CANCELED);
        if !self.sent {
            // `ClosedStream` means it is already finished or reset: nothing left to cancel.
            let _ = self.send.reset(code);
        }
        let _ = self.recv.stop(code);
    }
}

/// Whether `call` may be sent again after a failure that may have reached the peer: the
/// enumeration, the cache probe, and the read verbs. A Sink or Delete may not — the same
/// line `ikigai_ipc` draws in its `replay_may_follow`.
fn replay_may_follow(call: &Call) -> bool {
    match call {
        Call::Entries | Call::IsCached(_) => true,
        Call::Issue(request)
        | Call::IssueAs(request, _)
        | Call::IssueTraced(request, _, _)
        | Call::IssueWith(request, _, _) => {
            matches!(
                request.verb,
                ikigai_core::Verb::Source | ikigai_core::Verb::Exists | ikigai_core::Verb::Meta
            )
        }
    }
}

/// Whether `call` asks the peer to DESCRIBE ITSELF rather than to do work — the calls that
/// run under [`DEFAULT_DESCRIBE_TIMEOUT`]. The IPC transport draws the same line, in
/// `ikigai_ipc::is_describe`, and for the same reasons: `Entries` is the enumeration, a
/// `Meta` issue is one endpoint's contract, and `IsCached` is a question about work.
fn is_describe(call: &Call) -> bool {
    match call {
        Call::Entries => true,
        Call::Issue(request)
        | Call::IssueAs(request, _)
        | Call::IssueTraced(request, _, _)
        | Call::IssueWith(request, _, _) => request.verb == ikigai_core::Verb::Meta,
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

    /// Set the deadline every call that is NOT a self-description runs under, from the first
    /// byte to the last, the reconnect-and-retry included (builder). `None` takes the bound
    /// off. [`connect_with`] starts it at the connection's idle timeout.
    ///
    /// ★ Why this exists (ledger [#1335](http://localhost:1060/l/default/item/1335)): before
    /// it, a resolution's only ceiling was the idle timeout, and the idle timer restarts on
    /// ANY packet. A peer that accepts the call and never answers it, but keeps its QUIC stack
    /// talking (a keep-alive does it), held the caller for ever; one that went silent cost
    /// twice the idle timeout, because a read is replayed once on a fresh connection. On
    /// expiry the call's stream is canceled on the wire ([`CANCELED`]: the reply half
    /// stopped, a half-written request reset), the connection is marked stale so the next
    /// call redials rather than queueing behind the abandoned one, and the caller gets a
    /// typed [`Timeout`](Error::Timeout) naming the peer and the deadline. Nothing is left
    /// running: the round trip is a future on this resolver's runtime, and the deadline drops
    /// it.
    ///
    /// ★ **Why the default is the idle timeout.** The server says nothing until a resolution
    /// finishes, and before cli 0.1.56 nothing pinged, so a silent resolution could not outlive
    /// the idle timeout against an honest peer. Starting the deadline there removed the
    /// unbounded cases and changed nothing that used to succeed; and an operator who raised
    /// `quic.timeout` for long model calls keeps them, because the deadline follows. Since
    /// 0.1.56 the client pings ([`KEEP_ALIVE_INTERVAL`]), so the connection no longer ends a
    /// silent call at all: this deadline is the ONE bound on a call's silence, which is what
    /// made keep-alive safe to turn on (ledger
    /// [#1359](http://localhost:1060/l/default/item/1359)).
    /// A caller that knows its calls are short (a mirror pass over a layer host) sets a short
    /// one here, or per call with [`issue_as_within`](Self::issue_as_within).
    pub fn with_call_timeout(mut self, call_timeout: Option<std::time::Duration>) -> Self {
        self.call_timeout = call_timeout;
        self
    }

    /// The per-call deadline ([`with_call_timeout`](Self::with_call_timeout)).
    pub fn call_timeout(&self) -> Option<std::time::Duration> {
        self.call_timeout
    }

    /// [`Resolver::issue_as`], under `deadline` for THIS call instead of the resolver's
    /// standing one ([`with_call_timeout`](Self::with_call_timeout), or the describe deadline
    /// for a `Meta` request). What a host with its own idea of how long one call may take
    /// passes, without a resolver per deadline.
    ///
    /// # Errors
    ///
    /// As [`Resolver::issue_as`]; a missed deadline is [`Error::Timeout`], naming the peer
    /// and the deadline.
    pub fn issue_as_within(
        &self,
        request: Request,
        capability: &Capability,
        deadline: std::time::Duration,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.issue_as_under(request, capability, Some(deadline), &RunContext::default())
    }

    /// The resolver's runtime. See [`runtime`](Self::runtime) for why it is an `Option`.
    fn runtime(&self) -> &Runtime {
        self.runtime
            .as_ref()
            .expect("the resolver's runtime is taken only by Drop")
    }

    fn round_trip(&self, call: Call) -> io::Result<Reply> {
        self.round_trip_within(call, None)
    }

    /// One round trip under `explicit` if given, else the deadline its kind of call runs
    /// under: the describe deadline for a self-description, the call deadline otherwise.
    fn round_trip_within(
        &self,
        call: Call,
        explicit: Option<std::time::Duration>,
    ) -> io::Result<Reply> {
        let request = encode(&call)?;
        let wire = Arc::clone(&self.wire);
        // A self-description runs under the short describe deadline, a resolution under the
        // patient call deadline (for a long resolution the silence IS the work). Both are
        // computed here, outside the future, because `call` does not cross the spawn.
        let describing = is_describe(&call);
        let deadline = explicit.or(if describing {
            self.describe_timeout
        } else {
            self.call_timeout
        });
        let replayable = replay_may_follow(&call);
        // Named in a deadline's error: a host relaying it to its own caller must say WHICH
        // peer was silent, or the message reads as being about the host (ledger #1288).
        let addr = wire.addr;
        drive(self.runtime(), async move {
            match deadline {
                None => wire.round_trip(request, replayable).await,
                // ★ This bounds the WHOLE exchange — the reconnect-and-retry inside
                // `Wire::round_trip` included. Bounding each attempt separately would let
                // a peer that accepts and never answers cost two deadlines per call.
                Some(deadline) => {
                    match tokio::time::timeout(deadline, wire.round_trip(request, replayable)).await
                    {
                        Ok(reply) => reply,
                        Err(_) => {
                            // Dropping the round trip canceled its stream (`InFlight`). The
                            // connection answered nothing for a whole deadline: the next call
                            // redials rather than trusting it (ledger #1092), and so does not
                            // queue behind the abandoned call on a door of cli 0.1.63 or older,
                            // which served one connection's calls in order (ledger #1692).
                            wire.stale.store(true, std::sync::atomic::Ordering::SeqCst);
                            // `Debug` keeps the unit (`300ms`, `30s`); `as_secs()` would
                            // report a sub-second bound as `0s`.
                            let message = if describing {
                                format!(
                                    "the peer at quic://{addr} did not describe itself within \
                                     {deadline:?}"
                                )
                            } else {
                                format!(
                                    "the peer at quic://{addr} did not answer within \
                                     {deadline:?}; the call was canceled"
                                )
                            };
                            Err(io::Error::new(io::ErrorKind::TimedOut, message))
                        }
                    }
                }
            }
        })?
    }

    /// [`Resolver::issue_as`] under `explicit` if given, else the standing deadline.
    fn issue_as_under(
        &self,
        request: Request,
        capability: &Capability,
        explicit: Option<std::time::Duration>,
        run: &RunContext,
    ) -> Result<(Representation, CacheStatus), Error> {
        let tracer = self.tracer().clone();
        let trace = tracer.as_ref().map(|_| TraceContext {
            trace_id: 1,
            parent_span: None,
        });
        // A run that carries a pool or a deadline goes as `IssueWith` (wire v9), shaped for
        // the version the current connection negotiated: a v7 or v8 server is sent the
        // `IssueAs`/`IssueTraced` it has always served. (A redial mid-call that lands on a
        // server of another version is the one case this read-before-encode misses; the
        // next call reads the new version.)
        let call =
            Call::issue_in_run(request, capability, trace, run).for_peer(self.wire.version());
        match self.round_trip_within(call, explicit).map_err(quic_error)? {
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

    /// Resolve under `capability`, CARRIED on every call: `Call::IssueAs`, or
    /// `Call::IssueTraced` when a tracer is installed (its returned spans are forwarded,
    /// so a `--connect` QUIC trace shows the remote execution tree). The client cert
    /// names the connection's CEILING (the server's session); the carried capability is
    /// the caller's own, and the server answers at the NARROWER of the two
    /// (`Capability::clamp`) — never wider than either. Root carried clamps to the
    /// ceiling, so a root caller is answered exactly as before.
    ///
    /// ⚠ Until ledger #734 the untraced path sent plain `Call::Issue`, which resolves at
    /// the full session authority: a `cap`-narrowed `--connect` session, or a mount
    /// forwarding an agent's attenuated grant, was not narrowed at all. IPC has always
    /// carried it. Every v7+ server answers `IssueAs` with the same clamp (it has since
    /// wire v2), so no peer this build can handshake with is new to it.
    fn issue_as(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.issue_as_under(request, capability, None, &RunContext::default())
    }

    /// Resolve carrying the caller's run (wire v9): what is left of its retry pool and its
    /// deadline cross as `Call::IssueWith` to a v9 server, which bounds the resolution by
    /// them; a v7 or v8 server is sent the plain `IssueAs` it has always served.
    fn issue_as_in_run(
        &self,
        request: Request,
        capability: &Capability,
        run: &RunContext,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.issue_as_under(request, capability, None, run)
    }

    fn set_tracer(&self, tracer: Arc<dyn Tracer>) {
        *self.tracer() = Some(tracer);
    }

    fn clear_tracer(&self) {
        *self.tracer() = None;
    }

    fn is_cached(&self, request: &Request, capability: &Capability) -> bool {
        // ⚠ NOT CARRIED, and it cannot be without a wire change: `Call::IsCached` has no
        // capability field (resolutions do — `Call::IssueAs`), so the server answers under
        // the SESSION's capability, the one the client certificate authenticated. That
        // cannot LEAK: the session principal may already resolve anything that capability
        // grants, so the probe reveals nothing beyond its own authority. What it can be is
        // WRONG for a caller narrower than its session — the cache is namespaced by
        // capability, so "cached" is a claim about the session's namespace. Carrying it is
        // a new appended `Call` variant, a wire version event (ledger #849).
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
    server_config_accepting(identity, trusted_client_cert_pems, idle, alpn_protocols())
}

/// [`server_config`] accepting exactly `alpns` — the seam a test uses to stand up a
/// v7-only server (`["ikigai/7"]`) or one that negotiates nothing (`[]`).
fn server_config_accepting(
    identity: &Identity,
    trusted_client_cert_pems: &[String],
    idle: std::time::Duration,
    alpns: Vec<Vec<u8>>,
) -> io::Result<quinn::ServerConfig> {
    let certs = trusted_client_cert_pems
        .iter()
        .map(|pem| load_cert(pem))
        .collect::<io::Result<Vec<_>>>()?;
    server_config_pinning(identity, Pins::Fixed(certs), idle, alpns)
}

/// The server config over either kind of [`Pins`].
fn server_config_pinning(
    identity: &Identity,
    pins: Pins,
    idle: std::time::Duration,
    alpns: Vec<Vec<u8>>,
) -> io::Result<quinn::ServerConfig> {
    quic_server_config(server_tls(identity, pins, alpns)?, idle)
}

/// The TLS half of [`server_config_pinning`]: TLS 1.3 only, the client certificate checked
/// by a [`PinnedPeer`] over `pins`, and NO session resumption.
///
/// ★ Resumption is off (ledger #2084). rustls never calls the client-certificate verifier
/// on a resumed TLS 1.3 handshake: it restores the chain it stored at the full handshake and
/// skips the CertificateRequest. With its defaults (a 256-session in-memory cache, two
/// tickets per handshake, each resumption issuing two more) a client that once passed the
/// verifier could keep resuming after its certificate's `notAfter` (ledger #1826) or after
/// it was removed from a live trust list (ledger #1825), for as long as the process ran, and
/// `QuicResolver` redials on the same client config, so its tickets were offered on every
/// redial. With no session storage and no tickets, every connection is a full handshake and
/// the verifier's answer is the one that holds.
fn server_tls(
    identity: &Identity,
    pins: Pins,
    alpns: Vec<Vec<u8>>,
) -> io::Result<rustls::ServerConfig> {
    let verifier = Arc::new(PinnedPeer::pinning(pins));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(other)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![load_cert(&identity.cert_pem)?],
            load_key(&identity.key_pem)?,
        )
        .map_err(other)?;
    tls.alpn_protocols = alpns;
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    tls.send_tls13_tickets = 0;
    Ok(tls)
}

/// A QUIC server config over a built `tls`, with the server's idle-only [`transport`].
fn quic_server_config(
    tls: rustls::ServerConfig,
    idle: std::time::Duration,
) -> io::Result<quinn::ServerConfig> {
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(other)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    config.transport_config(Arc::new(transport(idle)?));
    Ok(config)
}

/// A transport config carrying the idle timeout and nothing else: what a SERVER runs with
/// ([`server_config`]). Each side enforces its own idle timeout, and QUIC NEGOTIATES the
/// smaller of the two (RFC 9000 section 10.1), so the client's [`client_transport`] decides
/// how soon a connection to a new client dies, whatever this side was configured with.
///
/// ★ **The server does not ping** (ledger [#1359](http://localhost:1060/l/default/item/1359)).
/// Keep-alive is safe only for a caller that bounds its own calls, because a peer whose QUIC
/// stack still answers while its kernel is wedged keeps a pinged connection alive for ever,
/// and then only a per-call deadline ends the call. The client has that deadline
/// ([`QuicResolver::with_call_timeout`], cli 0.1.55). A client older than it has none, and a
/// server that pinged would hand that client the unbounded wedge; not pinging leaves it the
/// idle bound it always had (`keep_alive::an_older_client_without_pings_keeps_its_idle_bound`).
/// A new client pings for both ends: the server hears the pings and the client hears the
/// acknowledgments, so both idle timers restart.
fn transport(idle: std::time::Duration) -> io::Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(quinn::IdleTimeout::try_from(idle).map_err(other)?));
    Ok(transport)
}

/// A CLIENT's transport: the liveness bound ([`LIVENESS_TIMEOUT`], or `idle` if shorter) as
/// its idle timeout, and a PING every third of it ([`KEEP_ALIVE_INTERVAL`]) whenever nothing
/// else was sent (ledger [#1359](http://localhost:1060/l/default/item/1359)).
///
/// What keep-alive changes, and what it does not. Pinging does not find a dead peer sooner:
/// the idle timeout does that, and RFC 9000 section 10.1 restarts the idle timer on a send
/// only for the first ack-eliciting packet after one was received, so pings to a dead peer
/// cannot hold its connection open (ledger #1288 corrected an earlier comment that said they
/// could). What pinging does is keep a connection to a LIVE but silent peer open, and that is
/// what lets the idle timeout shrink from the five-minute silence an honest resolution may
/// need to the fifteen seconds a dead peer is allowed to hide: the silence of a long call no
/// longer reaches the idle timer, and its bound is the call deadline instead (which starts
/// at `idle`, the old idle timeout, so the patience a call gets is unchanged).
fn client_transport(idle: std::time::Duration) -> io::Result<quinn::TransportConfig> {
    let (bound, ping) = liveness(idle);
    let mut transport = transport(bound)?;
    transport.keep_alive_interval(ping);
    Ok(transport)
}

/// The client's idle timeout and keep-alive interval for a configured `idle`: the liveness
/// bound capped at `idle`, and a third of it. A zero `idle` is QUIC's "no idle timeout", as it
/// always was here, and then nothing pings (a zero interval would ping without pause).
fn liveness(idle: std::time::Duration) -> (std::time::Duration, Option<std::time::Duration>) {
    let bound = idle.min(LIVENESS_TIMEOUT);
    let ping = bound / 3;
    (bound, (!ping.is_zero()).then_some(ping))
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
        Ok(Ok(connection)) if negotiated_version(&connection).is_some() => Ok(connection),
        Ok(Ok(connection)) => {
            connection.close(NO_VERSION.into(), b"no ikigai wire version was negotiated");
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "connect {addr}: the server negotiated no ikigai wire version this client \
                     speaks (v{}..=v{}) — update the older side",
                    ikigai_wire::MIN_PROTOCOL_VERSION,
                    ikigai_wire::PROTOCOL_VERSION
                ),
            ))
        }
        Ok(Err(e)) => Err(other(e)),
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
    client_config_offering(identity, trusted_server_cert_pem, idle, alpn_protocols())
}

/// [`client_config`] offering exactly `alpns` — the seam a test uses to stand up a
/// v7-only client.
fn client_config_offering(
    identity: &Identity,
    trusted_server_cert_pem: &str,
    idle: std::time::Duration,
    alpns: Vec<Vec<u8>>,
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
    tls.alpn_protocols = alpns;
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(other)?;
    // The idle timeout and keep-alive are OURS to set: quinn's ~30s default idle killed
    // long-silent work (a 70B generating) mid-request, and it pings nothing. The client pings
    // and keeps a short liveness bound; the silence of a long call is the call deadline's to
    // bound. See [`client_transport`].
    let mut config = quinn::ClientConfig::new(Arc::new(quic));
    config.transport_config(Arc::new(client_transport(idle)?));
    Ok(config)
}

/// The TLS configuration for an HTTPS face that presents the SAME server identity as this
/// QUIC door: a client that pins the door's certificate pins the HTTPS face with the same
/// file. TLS 1.3 and 1.2 (an HTTP client on an older runtime may speak only 1.2), ALPN
/// `http/1.1`, and NO client certificate: an HTTPS face authenticates its callers some other
/// way (a bearer token bound to an enrolled participant, say), so it does not ask for one.
///
/// ```
/// let identity = ikigai_quic::generate();
/// let tls = ikigai_quic::https_server_tls(&identity).unwrap();
/// assert_eq!(tls.alpn_protocols, vec![b"http/1.1".to_vec()]);
/// ```
pub fn https_server_tls(identity: &Identity) -> io::Result<rustls::ServerConfig> {
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(other)?
        .with_no_client_auth()
        .with_single_cert(
            vec![load_cert(&identity.cert_pem)?],
            load_key(&identity.key_pem)?,
        )
        .map_err(other)?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tls)
}

/// The client half of [`https_server_tls`]: trust exactly the pinned server certificate (no
/// CA, no name check: the certificate IS the identity, as on the QUIC transport), present no
/// client certificate, offer ALPN `http/1.1`.
///
/// ```
/// let server = ikigai_quic::generate();
/// let tls = ikigai_quic::pinned_https_client_tls(&server.cert_pem).unwrap();
/// assert_eq!(tls.alpn_protocols, vec![b"http/1.1".to_vec()]);
/// assert!(ikigai_quic::pinned_https_client_tls("not a certificate").is_err());
/// ```
pub fn pinned_https_client_tls(trusted_server_cert_pem: &str) -> io::Result<rustls::ClientConfig> {
    let verifier = Arc::new(PinnedPeer::new(load_cert(trusted_server_cert_pem)?));
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(other)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tls)
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
    pinned: Pins,
    algorithms: WebPkiSupportedAlgorithms,
}

/// The certificates a [`PinnedPeer`] accepts: a set fixed when the door was built, or a
/// [`TrustList`] read at every handshake, or (a lobby door's client side only) any
/// certificate inside its validity window.
enum Pins {
    Fixed(Vec<CertificateDer<'static>>),
    Live(TrustList),
    /// Pins nothing: a lobby door ([`serve_lobby_on`]) admits every client certificate inside
    /// its window and decides what it may do after the handshake. Only a SERVER builds this,
    /// and a server certificate is never verified against it ([`PinnedPeer::verify_server_cert`]
    /// refuses).
    AnyInWindow,
}

impl std::fmt::Debug for Pins {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pins::Fixed(certs) => write!(f, "Pins::Fixed({} certificate(s))", certs.len()),
            Pins::Live(_) => f.write_str("Pins::Live(read at every handshake)"),
            Pins::AnyInWindow => f.write_str("Pins::AnyInWindow(a lobby door)"),
        }
    }
}

impl PinnedPeer {
    fn new(pinned: CertificateDer<'static>) -> Self {
        Self::pinning(Pins::Fixed(vec![pinned]))
    }

    fn pinning(pinned: Pins) -> Self {
        PinnedPeer {
            pinned,
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }

    /// Whether `presented` is pinned. A live list is read NOW, and a read that fails pins
    /// nothing (the [`TrustList`] contract: fail closed, never the last reading).
    fn matches(&self, presented: &CertificateDer<'_>) -> bool {
        match &self.pinned {
            Pins::Fixed(pinned) => pinned.iter().any(|c| c.as_ref() == presented.as_ref()),
            Pins::Live(trust) => trust().is_ok_and(|pems| {
                pems.iter()
                    .filter_map(|pem| load_cert(pem).ok())
                    .any(|c| c.as_ref() == presented.as_ref())
            }),
            Pins::AnyInWindow => true,
        }
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
        // A client always pins the server it dials; "any certificate" is a lobby door's rule
        // for its CLIENTS and must never verify a server.
        if !matches!(self.pinned, Pins::AnyInWindow) && self.matches(end_entity) {
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
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if self.matches(end_entity) {
            // Pinning says WHICH certificate; its window says WHEN (ledger #1826). Checked
            // after the match, so on a pinning door only a certificate the operator trusts is
            // ever parsed. A lobby door (`Pins::AnyInWindow`) parses every presented one here:
            // that is the price of admitting strangers, and x509-parser is the parser webpki's
            // signature check would run over the same bytes moments later anyway.
            within_validity(end_entity, now)?;
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

/// Refuse a certificate outside its validity window at `now`: before its `notBefore` or after
/// its `notAfter` (both inclusive bounds, RFC 5280 section 4.1.2.5).
///
/// ★ Through cli 0.1.63 a door's verifier compared certificates byte for byte and never looked
/// at the window, so an expired certificate still on the trust list kept connecting (ledger
/// #1826). `ikigai cert generate` mints certificates valid from 1975 to 4096, so this refuses
/// only one minted with a real window. A certificate whose window does not parse is refused
/// too: an operator cannot have meant to trust bytes that are not a certificate.
fn within_validity(der: &CertificateDer<'_>, now: UnixTime) -> Result<(), rustls::Error> {
    use rustls::CertificateError;
    let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref())
        .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
    let now = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
    let validity = cert.validity();
    if now < validity.not_before.timestamp() {
        Err(rustls::Error::InvalidCertificate(
            CertificateError::NotValidYet,
        ))
    } else if now > validity.not_after.timestamp() {
        Err(rustls::Error::InvalidCertificate(CertificateError::Expired))
    } else {
        Ok(())
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
        cal_over_quic_as(capability, None)
    }

    /// [`cal_over_quic`], with the client resolving through `Resolver::issue_as` under
    /// `caller` when one is given (plain `issue` otherwise).
    fn cal_over_quic_as(capability: Capability, caller: Option<Capability>) -> String {
        use ikigai_resolve::Resolver;
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
            principal: None,
        };
        let server = thread::spawn(move || {
            rt.block_on(async move {
                let incoming = endpoint.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                serve_connection(&kernel, connection, session).await;
            });
        });
        let client = connect(server_addr, &client_id, &server_id.cert_pem).unwrap();
        let cal = Request::new(Verb::Source, Iri::parse("urn:demo:cal").unwrap());
        let (representation, _) = match caller {
            Some(caller) => Resolver::issue_as(&client, cal, &caller).unwrap(),
            None => client.issue(cal).unwrap(),
        };
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

    /// ledger #734 (q1): the caller's narrowed capability CROSSES the wire on an untraced
    /// call, and the server answers at the narrower of it and the connection's session.
    /// Before, `issue_as` sent plain `Call::Issue` and a freebusy caller on a root
    /// connection was answered DETAIL.
    #[test]
    fn issue_as_answers_at_the_narrower_of_the_caller_and_the_connection() {
        let freebusy = || Capability::scoped(["urn:cap:demo:freebusy".to_string()]);
        let detail = || Capability::scoped(["urn:cap:demo:detail".to_string()]);
        assert_eq!(
            cal_over_quic_as(Capability::root(), Some(freebusy())),
            "freebusy",
            "a caller narrowed to freebusy was answered at the connection's full authority"
        );
        // A root caller is answered at the connection's authority, exactly as before.
        assert_eq!(
            cal_over_quic_as(Capability::root(), Some(Capability::root())),
            "DETAIL"
        );
        // The carried capability never WIDENS the connection: a detail-carrying caller on
        // a freebusy connection gets freebusy.
        assert_eq!(cal_over_quic_as(freebusy(), Some(detail())), "freebusy");
        // Both grant detail: the narrower of the two is still detail.
        assert_eq!(cal_over_quic_as(detail(), Some(detail())), "DETAIL");
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
            principal: None,
        };
        let server = thread::spawn(move || {
            rt.block_on(async move {
                let incoming = endpoint.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                serve_connection(&kernel, connection, session).await;
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

    /// ledger #734 (q1b): the other direction through a mount. A ROOT connection, and a
    /// local caller ATTENUATED to freebusy (an MCP agent's grant, a `cap`-narrowed
    /// session): the attenuation survives the hop and the peer answers freebusy. Before,
    /// the mount forwarded the capability to `issue_as`, which dropped it on the wire.
    #[test]
    fn a_mount_carries_the_local_callers_attenuation_to_the_peer() {
        let freebusy = Capability::scoped(["urn:cap:demo:freebusy".to_string()]);
        assert_eq!(
            cal_through_mount(Capability::root(), freebusy),
            "freebusy",
            "attenuation lost across the QUIC mount"
        );
        assert_eq!(
            cal_through_mount(Capability::root(), Capability::root()),
            "DETAIL",
            "a root caller through a root connection is unchanged"
        );
    }

    /// ★ Ledger #92 over QUIC: a cut on the PEER reaches a read made through a mount. The
    /// peer's endpoint is cacheable and threaded (`depends_on`); a pure one would pass either
    /// way. The IPC test of the same name pins the same rule; the rule lives in the mount
    /// (`ikigai-resolve`), so this one shows it holds whatever carries the call.
    #[test]
    fn a_cut_on_the_peer_reaches_a_read_through_the_mount() {
        use std::sync::Mutex;

        use ikigai_core::{Fallback, Space};
        use ikigai_resolve::{MountedRemote, Resolver};

        const STATE: &str = "urn:test:state";
        let value = Arc::new(Mutex::new(b"v1".to_vec()));
        let cell = {
            let value = Arc::clone(&value);
            FnEndpoint::new("cell", move |_inv: &Invocation<'_>| {
                Ok(
                    Representation::new(ReprType::new("text/plain"), value.lock().unwrap().clone())
                        .cacheable()
                        .depends_on(STATE),
                )
            })
        };
        let peer = Arc::new(Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:cell"), cell),
        )));

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
        let served = Arc::clone(&peer);
        let session = Session {
            capability: Capability::root(),
            file_segment: String::new(),
            principal: None,
        };
        let server = thread::spawn(move || {
            rt.block_on(async move {
                let incoming = endpoint.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                serve_connection(&served, connection, session).await;
            });
        });
        let client = connect(server_addr, &client_id, &server_id.cert_pem).unwrap();
        let mounting = Kernel::new(Arc::new(Fallback::new(vec![
            Arc::new(EndpointSpace::new()) as Arc<dyn Space>,
            Arc::new(MountedRemote::overriding(
                Arc::new(client),
                "urn:test:",
                format!("quic:{server_addr}"),
            )) as Arc<dyn Space>,
        ])));
        let read = |kernel: &Kernel| {
            let cell = Request::new(Verb::Source, Iri::parse("urn:test:cell").unwrap());
            Resolver::issue_as(kernel, cell, &Capability::root())
                .unwrap()
                .0
                .bytes
        };

        assert_eq!(read(&mounting), b"v1");
        *value.lock().unwrap() = b"v2".to_vec();
        peer.cut(STATE);
        assert_eq!(read(&peer), b"v2", "the peer serves the new state");
        assert_eq!(
            read(&mounting),
            b"v2",
            "the mounting kernel must not serve a peer answer whose thread the peer has cut"
        );

        drop(mounting);
        server.join().unwrap();
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
                serve_connection(&kernel, connection, session).await;
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
            principal: None,
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

    /// `idle` (`quic.timeout`) decides whether LONG-SILENT WORK survives: the server says
    /// nothing while a resolution runs, and quinn's old ~30s default killed a hard
    /// LLM question mid-generation (observed bug->plasma) while the model kept
    /// computing. A client outliving the silence gets the reply; one with a shorter
    /// `idle` than the work misses its call deadline, which starts at `idle`. Since cli
    /// 0.1.56 it is that DEADLINE that ends the call, not the connection: the client pings,
    /// so the connection stays up (ledger #1359).
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
            principal: None,
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
                            principal: None,
                        };
                        serve_connection(&kernel, connection, session).await;
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
        let missed = impatient
            .issue(req())
            .expect_err("a 1s idle must not survive 3s of silent work");
        assert!(
            matches!(&missed, Error::Timeout(said) if said.contains("did not answer within 1s")),
            "ended by the call deadline the 1s idle set, not a lost connection: {missed:?}"
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
                            Some(session) => serve_connection(&kernel, connection, session).await,
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
                principal: None,
            })
        });
        assert_eq!(dials_under(grant, 1), vec![Ok("DETAIL".to_string())]);
    }

    /// What `urn:test:whoami` reports: the `principal` argument it was handed (`-` for
    /// none), whether the capability it ran under still holds the scope a host could have
    /// used to TAG the connection with its identity (`tagged`/`untagged`, the channel gonk
    /// used before ledger #879), and which projection that capability reached.
    fn whoami_kernel() -> Kernel {
        let whoami = FnEndpoint::new("whoami", |inv: &Invocation<'_>| {
            let who = inv.inline_str(PRINCIPAL_ARG).unwrap_or("-").to_string();
            let tagged = inv
                .capability
                .scopes()
                .is_some_and(|held| held.iter().any(|scope| scope == WHOAMI_TAG));
            let reach = if inv.capability.allows("urn:cap:demo:detail") {
                "DETAIL"
            } else {
                "freebusy"
            };
            let tag = if tagged { "tagged" } else { "untagged" };
            let named = inv.capability.principal().unwrap_or("-");
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!("{who} {tag} {reach} cap={named}").into_bytes(),
            ))
        })
        .with_description(
            ikigai_core::Description::new("whoami")
                .verb(Verb::Source)
                .verb(Verb::Sink),
        );
        Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:whoami"), whoami),
        ))
    }

    /// The identity scope a host could hide inside a session capability.
    const WHOAMI_TAG: &str = "urn:example:client:tag";

    /// Run the real accept loop over [`whoami_kernel`] under `minter`, dial once, and
    /// answer each request in `calls` with what the endpoint saw. `traced` installs a
    /// tracer first, so a capability-carrying call goes out as `Call::IssueTraced`.
    fn whoami_over(minter: Minter, calls: Vec<WhoamiCall>) -> Vec<String> {
        use ikigai_resolve::Resolver;
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
        let kernel = Arc::new(whoami_kernel());
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
                            Some(session) => serve_connection(&kernel, connection, session).await,
                            None => connection.close(UNAUTHORIZED.into(), b"unauthorized"),
                        }
                    });
                }
            });
        });
        let client = connect(server_addr, &client_id, &server_id.cert_pem).unwrap();
        let answers = calls
            .into_iter()
            .map(|call| {
                if call.traced {
                    client.set_tracer(Arc::new(SpanCollector::default()));
                } else {
                    client.clear_tracer();
                }
                let mut request = Request::new(call.verb, Iri::parse("urn:test:whoami").unwrap());
                if let Some(forged) = call.forged {
                    request = request.with_arg(PRINCIPAL_ARG, ArgRef::Inline(forged.into()));
                }
                let answer = match call.carried {
                    Some(carried) => Resolver::issue_as(&client, request, &carried),
                    None => client.issue(request),
                };
                String::from_utf8(answer.expect("whoami resolves").0.bytes).unwrap()
            })
            .collect();
        drop(client);
        answers
    }

    struct WhoamiCall {
        verb: Verb,
        carried: Option<Capability>,
        forged: Option<&'static str>,
        traced: bool,
    }

    fn whoami(verb: Verb, carried: Option<Capability>) -> WhoamiCall {
        WhoamiCall {
            verb,
            carried,
            forged: None,
            traced: false,
        }
    }

    /// A minter that grants `detail` and `other`, hides [`WHOAMI_TAG`] in the capability the
    /// way gonk did, and names the client's principal from its certificate.
    fn naming_minter() -> Minter {
        Arc::new(|peer: &PeerIdentity| {
            Some(Session {
                capability: Capability::scoped([
                    "urn:cap:demo:detail".to_string(),
                    "urn:cap:demo:other".to_string(),
                    WHOAMI_TAG.to_string(),
                ]),
                file_segment: peer.segment_id.clone(),
                principal: Some(format!("urn:example:client:{}", &peer.fingerprint[..8])),
            })
        })
    }

    /// ledger #879: the principal is not a capability. A client that carries root and a
    /// client that carries a capability NARROWER than its session both reach the endpoint
    /// with the principal the minter named, on a read and on a write, traced or not.
    ///
    /// The `untagged` column is the defect reproduced: the identity a host hid inside the
    /// session capability survives a root carry and is intersected away by a narrowed one
    /// (`ikigai mcp --grant hermes` against gonk, 2026-10-07), so a host reading it there
    /// saw nobody. The stamped principal does not travel through the capability at all.
    #[test]
    fn the_session_principal_survives_any_capability_the_client_carries() {
        let narrowed = || Some(Capability::scoped(["urn:cap:demo:other".to_string()]));
        let answers = whoami_over(
            naming_minter(),
            vec![
                whoami(Verb::Source, None),
                whoami(Verb::Source, Some(Capability::root())),
                whoami(Verb::Source, narrowed()),
                whoami(Verb::Sink, narrowed()),
                WhoamiCall {
                    traced: true,
                    ..whoami(Verb::Source, narrowed())
                },
            ],
        );
        let principal = answers[0].split(' ').next().unwrap().to_string();
        assert!(
            principal.starts_with("urn:example:client:") && principal.len() == 27,
            "the minter's principal reached the endpoint: {answers:?}"
        );
        // ledger #1077: the principal is ALSO minted into the capability, and a clamp keeps
        // the session's, so the narrowed carries (the Hermes shape) are attributed through the
        // capability too, on a read and a write, traced or not.
        assert_eq!(
            answers,
            vec![
                format!("{principal} tagged DETAIL cap={principal}"),
                format!("{principal} tagged DETAIL cap={principal}"),
                format!("{principal} untagged freebusy cap={principal}"),
                format!("{principal} untagged freebusy cap={principal}"),
                format!("{principal} untagged freebusy cap={principal}"),
            ]
        );
    }

    /// ledger #1077: a ROOT session names nobody in its capability, even with a principal
    /// (root holds every principal and carries none; `with_principal` refuses it). The
    /// stamped argument still names the client, and a client carrying a narrower capability
    /// cannot bring a principal of its own in.
    #[test]
    fn a_root_session_carries_no_principal_in_its_capability() {
        let rooted: Minter = Arc::new(|peer: &PeerIdentity| {
            Some(Session {
                capability: Capability::root(),
                file_segment: peer.segment_id.clone(),
                principal: Some(format!("urn:example:client:{}", &peer.fingerprint[..8])),
            })
        });
        let answers = whoami_over(
            rooted,
            vec![
                whoami(Verb::Source, None),
                whoami(Verb::Source, Some(Capability::root())),
            ],
        );
        for answer in &answers {
            assert!(
                answer.starts_with("urn:example:client:") && answer.ends_with(" cap=-"),
                "stamped, not minted: {answers:?}"
            );
        }
        // A client of a NAMED session carrying a principal of its own: the session's wins.
        let forged_cap = Capability::scoped([
            "urn:cap:demo:other".to_string(),
            "urn:cap:principal:urn:example:mallory".to_string(),
        ]);
        let named = whoami_over(
            naming_minter(),
            vec![whoami(Verb::Source, Some(forged_cap))],
        );
        assert!(
            named[0].contains(" cap=urn:example:client:") && !named[0].contains("mallory"),
            "{named:?}"
        );
    }

    /// A client cannot name a principal: one it sends is replaced by the minter's, under
    /// any capability and on any verb, and removed when the minter names none.
    #[test]
    fn a_forged_principal_argument_never_wins() {
        let forged = |verb, carried| WhoamiCall {
            forged: Some("urn:example:mallory"),
            ..whoami(verb, carried)
        };
        let narrowed = || Some(Capability::scoped(["urn:cap:demo:other".to_string()]));
        let named = whoami_over(
            naming_minter(),
            vec![
                forged(Verb::Source, None),
                forged(Verb::Source, narrowed()),
                forged(Verb::Sink, Some(Capability::root())),
                WhoamiCall {
                    traced: true,
                    ..forged(Verb::Sink, narrowed())
                },
            ],
        );
        for answer in &named {
            assert!(
                answer.starts_with("urn:example:client:") && !answer.contains("mallory"),
                "the connection's principal wins: {named:?}"
            );
        }
        let anonymous: Minter = Arc::new(|peer: &PeerIdentity| {
            Some(Session {
                capability: Capability::root(),
                file_segment: peer.segment_id.clone(),
                principal: None,
            })
        });
        let unnamed = whoami_over(
            anonymous,
            vec![
                forged(Verb::Source, None),
                forged(Verb::Sink, Some(Capability::root())),
            ],
        );
        assert_eq!(
            unnamed,
            vec!["- untagged DETAIL cap=-", "- untagged DETAIL cap=-"],
            "a session with no principal stamps none, and a client's is removed"
        );
    }

    /// `IsCached` is admitted exactly as an issue is, so it asks about the key the issue
    /// stored: a principal-stamped read is reported cached after it resolves.
    #[test]
    fn is_cached_asks_about_the_key_the_stamped_issue_stored() {
        let kernel = Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:upper"), builtins::to_upper()),
        ));
        let session = Session {
            capability: Capability::root(),
            file_segment: String::new(),
            principal: Some("urn:example:alice".to_string()),
        };
        let upper = || {
            Request::new(Verb::Source, Iri::parse("urn:test:upper").unwrap())
                .with_arg("in", ArgRef::Inline(b"hi".to_vec()))
        };
        assert!(matches!(
            dispatch(&kernel, Call::IsCached(upper()), &session),
            Reply::Cached(false)
        ));
        assert!(matches!(
            dispatch(&kernel, Call::Issue(upper()), &session),
            Reply::Resolved(..)
        ));
        assert!(matches!(
            dispatch(&kernel, Call::IsCached(upper()), &session),
            Reply::Cached(true)
        ));
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
                    principal: None,
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
            principal: None,
        };
        let server = {
            let kernel = Arc::clone(&kernel);
            thread::spawn(move || {
                rt.block_on(async move {
                    let incoming = endpoint.accept().await.unwrap();
                    let connection = incoming.await.unwrap();
                    serve_connection(&kernel, connection, session).await;
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
            .any(|e| e.endpoint == "to-upper"));

        drop(client); // closes the connection → the handler loop ends
        server.join().unwrap();
    }

    // ---- wire v8 over QUIC: the ALPN is the version (ledger #583) ----

    fn conflict_kernel() -> Kernel {
        let taken = FnEndpoint::new("taken", |_inv: &Invocation<'_>| {
            Err(Error::Conflict("x".into()))
        });
        Kernel::new(Arc::new(
            EndpointSpace::new()
                .bind(Exact::new("urn:test:upper"), builtins::to_upper())
                .bind(Exact::new("urn:test:taken"), taken),
        ))
    }

    fn taken() -> Request {
        Request::new(Verb::Source, Iri::parse("urn:test:taken").unwrap())
    }

    /// Serve ONE connection of `conflict_kernel` on a server accepting `alpns`, returning
    /// its address and a handle that yields the version the server saw negotiated.
    fn serve_alpn(
        server_id: &Identity,
        client_id: &Identity,
        alpns: Vec<Vec<u8>>,
    ) -> (SocketAddr, thread::JoinHandle<Option<u32>>) {
        serve_kernel_alpn(server_id, client_id, alpns, conflict_kernel())
    }

    /// [`serve_alpn`] over any kernel.
    fn serve_kernel_alpn(
        server_id: &Identity,
        client_id: &Identity,
        alpns: Vec<Vec<u8>>,
        kernel: Kernel,
    ) -> (SocketAddr, thread::JoinHandle<Option<u32>>) {
        let cfg = server_config_accepting(
            server_id,
            std::slice::from_ref(&client_id.cert_pem),
            DEFAULT_IDLE_TIMEOUT,
            alpns,
        )
        .unwrap();
        let rt = Runtime::new().unwrap();
        let endpoint = rt
            .block_on(async { quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()) })
            .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let server = thread::spawn(move || {
            rt.block_on(async move {
                let incoming = endpoint.accept().await?;
                let connection = incoming.await.ok()?;
                let version = negotiated_version(&connection);
                let session = Session {
                    capability: Capability::root(),
                    file_segment: String::new(),
                    principal: None,
                };
                serve_connection(&Arc::new(kernel), connection, session).await;
                endpoint.wait_idle().await;
                version
            })
        });
        (addr, server)
    }

    /// A kernel whose one endpoint reports the run it sees: `{retries},{time_left_ms}`, `-`
    /// for a half the run does not carry; a retry budget (ceiling 3) so a pool exists.
    fn run_kernel() -> Kernel {
        let left = FnEndpoint::new("left", |inv: &Invocation<'_>| {
            let retries = inv
                .retry_budget()
                .map(|pool| pool.remaining().to_string())
                .unwrap_or_else(|| "-".to_string());
            let time_left = inv
                .time_left()
                .map(|left| left.as_millis().to_string())
                .unwrap_or_else(|| "-".to_string());
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!("{retries},{time_left}").into_bytes(),
            ))
        });
        // A clock, so `time_left` can be measured against the deadline the door sets.
        Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:left"), left),
        ))
        .with_retry_budget(0, 3)
        .with_clock(Arc::new(SystemClock))
    }

    /// Wire v9 over QUIC (ledger #1546): a run context crosses to a v9 server under the
    /// clamped authority, and the peer's endpoint sees the carried retries and a deadline
    /// about the carried time left away on its own clock; the same client's plain
    /// `issue_as` carries nothing and the peer runs under its own policy. A v8-only server
    /// (accepting just `ikigai/8`) is sent the `IssueAs` it has always served.
    #[test]
    fn a_run_context_crosses_over_quic_and_is_dropped_for_a_v8_server() {
        let left = Request::new(Verb::Source, Iri::parse("urn:test:left").unwrap());
        let run = RunContext {
            retries: Some(1),
            time_left: Some(std::time::Duration::from_secs(30)),
        };
        let split = |bytes: &[u8]| -> (String, Option<u64>) {
            let text = String::from_utf8_lossy(bytes);
            let (retries, time_left) = text.split_once(',').expect("retries,time_left");
            (retries.to_string(), time_left.parse().ok())
        };
        for (alpns, expect_version) in [
            (alpn_protocols(), PROTOCOL_VERSION),
            (vec![b"ikigai/8".to_vec()], 8),
        ] {
            let (server_id, client_id) = (generate(), generate());
            let (addr, server) = serve_kernel_alpn(&server_id, &client_id, alpns, run_kernel());
            let client = connect(addr, &client_id, &server_id.cert_pem).unwrap();
            let (answer, _) = client
                .issue_as_in_run(left.clone(), &Capability::root(), &run)
                .unwrap();
            let (retries, time_left) = split(&answer.bytes);
            if expect_version == PROTOCOL_VERSION {
                assert_eq!(retries, "1", "the carried count narrows the pool");
                let time_left = time_left.expect("a deadline crossed");
                assert!(
                    (25_000..=30_000).contains(&time_left),
                    "about 30 s left on the peer's clock: {time_left} ms"
                );
            } else {
                // Dropped at the client: the v8 server runs it under its own policy.
                assert_eq!((retries, time_left), ("3".to_string(), None));
            }
            let (plain, _) = client.issue_as(left.clone(), &Capability::root()).unwrap();
            assert_eq!(
                split(&plain.bytes),
                ("3".to_string(), None),
                "nothing carried"
            );
            drop(client);
            assert_eq!(server.join().unwrap(), Some(expect_version));
        }
    }

    /// A v8 server meeting a v7-ONLY client (offering just `ikigai/7`): the connection
    /// negotiates 7, and a Conflict arrives as the untyped Endpoint a v7 peer always got.
    #[test]
    fn a_v7_only_client_negotiates_7_and_gets_the_downgraded_conflict() {
        let (server_id, client_id) = (generate(), generate());
        let (addr, server) = serve_alpn(&server_id, &client_id, alpn_protocols());
        let rt = Runtime::new().unwrap();
        let reply = rt.block_on(async {
            let cfg = client_config_offering(
                &client_id,
                &server_id.cert_pem,
                DEFAULT_IDLE_TIMEOUT,
                vec![b"ikigai/7".to_vec()],
            )
            .unwrap();
            let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            endpoint.set_default_client_config(cfg);
            let connection = endpoint.connect(addr, "ikigai").unwrap().await.unwrap();
            assert_eq!(negotiated_version(&connection), Some(7));
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            send.write_all(&encode(&Call::Issue(taken())).unwrap())
                .await
                .unwrap();
            send.finish().unwrap();
            let bytes = recv.read_to_end(MAX_MESSAGE).await.unwrap();
            connection.close(0u32.into(), b"done");
            decode::<Reply>(&bytes).unwrap()
        });
        assert_eq!(
            reply,
            Reply::ErrorTyped(ikigai_wire::WireError::Endpoint("conflict: x".into()))
        );
        assert_eq!(server.join().unwrap(), Some(7));
    }

    /// A current pair negotiates the newest version — the server lists it first — and
    /// the Conflict crosses TYPED and permanent.
    #[test]
    fn a_current_pair_negotiates_the_newest_version_and_the_conflict_crosses_typed() {
        let (server_id, client_id) = (generate(), generate());
        let (addr, server) = serve_alpn(&server_id, &client_id, alpn_protocols());
        let client = connect(addr, &client_id, &server_id.cert_pem).unwrap();
        let err = client.issue(taken()).unwrap_err();
        assert!(matches!(err, Error::Conflict(ref m) if m == "x"), "{err:?}");
        assert!(!err.is_transient());
        drop(client);
        assert_eq!(server.join().unwrap(), Some(PROTOCOL_VERSION));
    }

    /// This build's client against a v7-only SERVER (accepting just `ikigai/7`): the
    /// handshake settles on 7 and the connection is served.
    #[test]
    fn a_v8_client_negotiates_7_with_a_v7_only_server() {
        let (server_id, client_id) = (generate(), generate());
        let (addr, server) = serve_alpn(&server_id, &client_id, vec![b"ikigai/7".to_vec()]);
        let client = connect(addr, &client_id, &server_id.cert_pem).unwrap();
        let (representation, _) = client.issue(upper("hi")).unwrap();
        assert_eq!(representation.bytes, b"HI");
        drop(client);
        assert_eq!(server.join().unwrap(), Some(7));
    }

    /// A server outside the spoken range — a v6 one (`ikigai/6`), or one configured with
    /// no id at all — is refused AT THE HANDSHAKE: QUIC requires ALPN, so rustls aborts
    /// with `no_application_protocol` before any connection exists. (Measured: the
    /// no-version branch in `dial` is therefore defensive; this is the gate that fires.)
    #[test]
    fn a_server_outside_7_to_9_is_refused_at_the_handshake() {
        for alpns in [
            vec![b"ikigai/6".to_vec()],
            vec![b"ikigai/10".to_vec()],
            Vec::new(),
        ] {
            let (server_id, client_id) = (generate(), generate());
            let shown = format!("{alpns:?}");
            let (addr, server) = serve_alpn(&server_id, &client_id, alpns);
            let message = match connect(addr, &client_id, &server_id.cert_pem) {
                Err(err) => err.to_string(),
                Ok(_) => panic!("a server accepting {shown} must be refused"),
            };
            assert!(message.contains("protocol"), "{shown}: {message}");
            let _ = server.join();
        }
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
    /// spawns this again to simulate a server that went away and came back. With `stop`, the
    /// server goes away when it fires, closing its endpoint; without, when the client leaves.
    ///
    /// ⚠ The server must be TOLD to go away (ledger #1359). This used to wait for the
    /// connection to idle out, and since cli 0.1.56 a client pings, so a connection between
    /// two live peers never idles out: the first server would have served for ever.
    fn serve_one(
        server_cfg: quinn::ServerConfig,
        addr: SocketAddr,
        stop: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(async move {
                let endpoint = quinn::Endpoint::server(server_cfg, addr).unwrap();
                let session = Session {
                    capability: Capability::root(),
                    file_segment: String::new(),
                    principal: None,
                };
                let kernel = Arc::new(Kernel::new(Arc::new(
                    ikigai_core::EndpointSpace::new().bind(
                        ikigai_core::Exact::new("urn:test:upper"),
                        ikigai_core::builtins::to_upper(),
                    ),
                )));
                if let Some(incoming) = endpoint.accept().await {
                    if let Ok(connection) = incoming.await {
                        let serving = tokio::spawn(async move {
                            serve_connection(&kernel, connection, session).await;
                        });
                        match stop {
                            Some(stop) => {
                                let _ = stop.await;
                                endpoint.close(0u32.into(), b"going away");
                                serving.abort();
                            }
                            None => {
                                let _ = serving.await;
                            }
                        }
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

        // First server instance. A SHORT idle timeout, explicitly: this test is about the
        // reconnect, not about sitting out the generous production default.
        let (go_away, stop) = tokio::sync::oneshot::channel();
        let first = serve_one(cfg(), port, Some(stop));
        let client = connect_with(
            port,
            &client_id,
            &server_id.cert_pem,
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(client.issue(upper("one")).unwrap().0.bytes, b"ONE");

        // The server goes away — this is what leaves the resolver holding a closed connection.
        go_away.send(()).unwrap();
        first.join().unwrap();

        // It comes back at the same address, and the resolver — which never restarted —
        // must recover on its own rather than fail forever.
        let second = serve_one(cfg(), port, None);
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
            principal: None,
        };
        let server = thread::spawn(move || {
            rt.block_on(async move {
                let incoming = endpoint.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                serve_connection(&kernel, connection, session).await;
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
        // The message names the bound that fired. `as_secs()` truncated it, so this 300ms
        // deadline was reported as "within 0s": a bound the operator never set.
        assert!(error.to_string().contains("within 300ms"), "{error}");
    }
}

/// ledger #1092: a peer that RESTARTS under a standing client. The server is run on a
/// runtime the test owns, and "crashes" by [`Server::crash`], which drops its endpoint
/// driver mid-connection: nothing sends a close frame, exactly like a SIGTERMed or
/// launchd-restarted `ikigai serve`. The replacement binds the same address.
#[cfg(test)]
mod restart {
    use super::*;
    use ikigai_core::{builtins, EndpointSpace, Exact, Verb};
    use tokio::runtime::Runtime;

    /// A server on a runtime the test owns, and every connection it accepted.
    struct Server {
        runtime: Runtime,
        connections: Arc<std::sync::Mutex<Vec<quinn::Connection>>>,
    }

    impl Server {
        /// Crash the server so that it says NOTHING to its clients, and return once it is
        /// gone (its socket released).
        ///
        /// ★ `shutdown_background` alone does not guarantee the silence (ledger #1535). It
        /// drops the runtime's tasks in no particular order and returns at once, and the task
        /// serving a connection holds that connection's last handle: dropping the last handle
        /// CLOSES the connection (quinn's implicit close), and when the connection's driver
        /// is still being polled it SENDS that close frame. The client then sees a closed
        /// connection, redials inside the same call and answers, so "the dead connection
        /// answers nothing" failed on Linux CI with `Some(entries)`. So the handles are held
        /// across the shutdown, which waits for every task to be dropped, and are released
        /// only after it: by then no driver is left to send anything, and the last handle's
        /// drop releases the socket, as a killed process's would.
        fn crash(self) {
            let held = std::mem::take(&mut *self.connections.lock().unwrap());
            self.runtime
                .shutdown_timeout(std::time::Duration::from_secs(10));
            drop(held);
        }
    }

    /// A server answering `urn:test:upper` at `addr`, under `endpoint_config`, on a runtime
    /// the caller owns ([`Server::crash`] crashes it).
    fn serve_on(
        addr: SocketAddr,
        server_id: &Identity,
        client_id: &Identity,
        endpoint_config: quinn::EndpointConfig,
    ) -> Server {
        let config = server_config(
            server_id,
            std::slice::from_ref(&client_id.cert_pem),
            DEFAULT_IDLE_TIMEOUT,
        )
        .unwrap();
        let rt = Runtime::new().unwrap();
        // A crashed server's socket was once released on its own schedule (`shutdown_background`
        // returned at once), so the replacement could find the port still held for a moment
        // (macOS CI did). `crash` now returns after the release, and the bind is still retried,
        // boundedly, rather than raced.
        let mut tries = 0;
        let endpoint = loop {
            match rt.block_on(async {
                endpoint_on(config.clone(), bind(addr)?, endpoint_config.clone())
            }) {
                Ok(endpoint) => break endpoint,
                Err(e) if e.kind() == io::ErrorKind::AddrInUse && tries < 100 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => panic!("bind {addr}: {e}"),
            }
        };
        let kernel = Arc::new(Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:upper"), builtins::to_upper()),
        )));
        let connections = Arc::new(std::sync::Mutex::new(Vec::new()));
        let held = Arc::clone(&connections);
        rt.spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let kernel = Arc::clone(&kernel);
                let held = Arc::clone(&held);
                tokio::spawn(async move {
                    if let Ok(connection) = incoming.await {
                        held.lock().unwrap().push(connection.clone());
                        let session = Session {
                            capability: Capability::root(),
                            file_segment: String::new(),
                            principal: None,
                        };
                        serve_connection(&kernel, connection, session).await;
                    }
                });
            }
        });
        Server {
            runtime: rt,
            connections,
        }
    }

    fn free_udp_addr() -> SocketAddr {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap()
    }

    fn upper(text: &str) -> Request {
        Request::new(Verb::Source, Iri::parse("urn:test:upper").unwrap())
            .with_arg("in", ikigai_core::ArgRef::Inline(text.as_bytes().to_vec()))
    }

    /// The server half: the replacement's stateless reset is honored because its key is the
    /// identity's, so the client's next call fails at once, redials and answers — well inside
    /// the five-minute idle timeout this client keeps.
    #[test]
    // Native-only (QUIC is not built for wasm); elapsed time is the measurement.
    #[allow(clippy::disallowed_methods)]
    fn a_restarted_server_resets_the_old_connection_and_the_next_call_heals() {
        let server_id = generate();
        let client_id = generate();
        let addr = free_udp_addr();
        let first = serve_on(addr, &server_id, &client_id, endpoint_config(&server_id));
        let client = connect(addr, &client_id, &server_id.cert_pem).unwrap();
        let (answer, _) = client.issue(upper("one")).unwrap();
        assert_eq!(answer.bytes, b"ONE");

        first.crash();
        let _second = serve_on(addr, &server_id, &client_id, endpoint_config(&server_id));

        let start = std::time::Instant::now();
        let (answer, _) = client
            .issue(upper("two"))
            .expect("the call heals onto the restarted server");
        let elapsed = start.elapsed();
        assert_eq!(answer.bytes, b"TWO");
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "reset and redialled, not the idle timeout: {elapsed:?}"
        );
    }

    /// The client half, against a replacement whose resets the client cannot verify (a random
    /// key: a peer older than this release). A self-description that times out marks the
    /// connection stale, so the NEXT one redials first instead of timing out again.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn a_describe_timeout_makes_the_next_call_redial() {
        let server_id = generate();
        let client_id = generate();
        let addr = free_udp_addr();
        let first = serve_on(
            addr,
            &server_id,
            &client_id,
            quinn::EndpointConfig::default(),
        );
        let client = connect(addr, &client_id, &server_id.cert_pem)
            .unwrap()
            .with_describe_timeout(Some(std::time::Duration::from_secs(2)));
        assert!(
            client.try_entries().is_ok(),
            "the first enumeration answers"
        );

        first.crash();
        let _second = serve_on(
            addr,
            &server_id,
            &client_id,
            quinn::EndpointConfig::default(),
        );

        let timed_out = client
            .try_entries()
            .expect_err("the dead connection answers nothing");
        assert!(
            timed_out.to_string().contains("did not describe itself"),
            "{timed_out}"
        );
        assert!(
            timed_out.to_string().contains(&format!("quic://{addr}")),
            "the deadline names the silent peer: {timed_out}"
        );
        let start = std::time::Instant::now();
        let entries = client.try_entries();
        let elapsed = start.elapsed();
        assert!(entries.is_ok(), "the next call redialled: {entries:?}");
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "redialled, not another deadline: {elapsed:?}"
        );
    }
}

/// ledger #1335: a peer that ACCEPTS a call and never answers it must cost the caller its
/// deadline and no more, cancel the call on the wire, and leave nothing running.
#[cfg(test)]
mod call_deadline {
    use super::*;
    use ikigai_core::{EndpointSpace, Exact, FnEndpoint, Invocation, ReprType, Verb};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// Far above every deadline under test, on both sides: a test that passes proves the
    /// CALL deadline fired, not the connection's.
    const IDLE: Duration = Duration::from_secs(60);

    /// A hostile peer: it accepts every connection and every call, reads the call whole, and
    /// never answers, while its QUIC stack PINGS so the connection never idles out. That is
    /// the case no idle timeout can end. Each call's stream reports what the client did to
    /// it: the application code of the `STOP_SENDING` that canceled it.
    fn hostile_peer() -> (SocketAddr, Identity, String, mpsc::Receiver<Option<u64>>) {
        let server_id = generate();
        let client_id = generate();
        let mut config =
            server_config(&server_id, std::slice::from_ref(&client_id.cert_pem), IDLE).unwrap();
        let mut keep_alive = transport(IDLE).unwrap();
        keep_alive.keep_alive_interval(Some(Duration::from_millis(100)));
        config.transport_config(Arc::new(keep_alive));
        let rt = Runtime::new().unwrap();
        let endpoint = rt
            .block_on(async { quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()) })
            .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let (stops, stopped) = mpsc::channel();
        std::thread::spawn(move || {
            rt.block_on(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let Ok(connection) = incoming.await else {
                        continue;
                    };
                    let stops = stops.clone();
                    tokio::spawn(async move {
                        while let Ok((send, mut recv)) = connection.accept_bi().await {
                            let stops = stops.clone();
                            tokio::spawn(async move {
                                let _ = recv.read_to_end(MAX_MESSAGE).await;
                                let code = send.stopped().await.ok().flatten();
                                let _ = stops.send(code.map(|c| c.into_inner()));
                            });
                        }
                    });
                }
            });
        });
        (addr, client_id, server_id.cert_pem, stopped)
    }

    /// A peer that answers `urn:test:slow` after `delay`, served on its own runtime.
    fn slow_peer(delay: Duration) -> (SocketAddr, Identity, String) {
        let server_id = generate();
        let client_id = generate();
        let config =
            server_config(&server_id, std::slice::from_ref(&client_id.cert_pem), IDLE).unwrap();
        let rt = Runtime::new().unwrap();
        let endpoint = rt
            .block_on(async { quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()) })
            .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let slow = FnEndpoint::new("slow", move |_: &Invocation<'_>| {
            std::thread::sleep(delay);
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"slow".to_vec(),
            ))
        });
        let kernel = Arc::new(Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:slow"), slow),
        )));
        std::thread::spawn(move || {
            rt.block_on(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let kernel = Arc::clone(&kernel);
                    tokio::spawn(async move {
                        if let Ok(connection) = incoming.await {
                            let session = Session {
                                capability: Capability::root(),
                                file_segment: String::new(),
                                principal: None,
                            };
                            serve_connection(&kernel, connection, session).await;
                        }
                    });
                }
            });
        });
        (addr, client_id, server_id.cert_pem)
    }

    fn source(iri: &str) -> Request {
        Request::new(Verb::Source, Iri::parse(iri).unwrap())
    }

    /// Tasks alive on the resolver's own runtime: its endpoint and connection drivers, plus
    /// any round trip still running.
    fn alive(client: &QuicResolver) -> usize {
        client.runtime().metrics().num_alive_tasks()
    }

    /// Wait (boundedly) for the resolver's runtime to settle back to `baseline` tasks: a
    /// finished task is reaped asynchronously, so one look straight after the call can race.
    // Native-only (QUIC is not built for wasm): a bounded wait in wall-clock time.
    #[allow(clippy::disallowed_methods)]
    fn settles_to(client: &QuicResolver, baseline: usize) -> bool {
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            if alive(client) <= baseline {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[test]
    // Native-only (QUIC is not built for wasm), and elapsed time is the measurement: it is
    // the only way to tell a bound that fired from a hang that was lucky.
    #[allow(clippy::disallowed_methods)]
    fn a_peer_that_never_answers_costs_the_call_deadline_and_the_call_is_canceled() {
        let (addr, client_id, server_pem, stopped) = hostile_peer();
        let deadline = Duration::from_millis(500);
        let client = connect_with(addr, &client_id, &server_pem, IDLE)
            .unwrap()
            .with_call_timeout(Some(deadline));
        let baseline = alive(&client);

        let start = Instant::now();
        let error = client
            .issue(source("urn:test:anything"))
            .expect_err("a peer that never answers is an ERROR, not a wait");
        let elapsed = start.elapsed();

        assert!(
            elapsed >= deadline && elapsed < deadline + Duration::from_secs(2),
            "bounded by the call deadline, not the {IDLE:?} idle timeout: {elapsed:?}"
        );
        assert!(matches!(error, Error::Timeout(_)), "{error:?}");
        assert!(error.is_transient(), "{error:?}");
        let said = error.to_string();
        assert!(
            said.contains(&format!("quic://{addr}")) && said.contains("within 500ms"),
            "the deadline names the peer and the bound: {said}"
        );
        // ★ Canceled ON THE WIRE, not merely abandoned: the peer's stream was stopped with
        // this transport's code, so its reply (were it ever written) fails at once.
        assert_eq!(
            stopped.recv_timeout(Duration::from_secs(5)),
            Ok(Some(u64::from(CANCELED))),
            "the peer saw the call canceled"
        );
        // And nothing is left running on the resolver's runtime.
        assert!(
            settles_to(&client, baseline),
            "a round trip outlived its deadline: {} tasks alive, {baseline} before",
            alive(&client)
        );

        // The next call is bounded the same way (it redials the stale connection first,
        // and does not spend two deadlines).
        let start = Instant::now();
        let again = client.issue(source("urn:test:anything"));
        assert!(matches!(again, Err(Error::Timeout(_))), "{again:?}");
        assert!(
            start.elapsed() < deadline + Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
    }

    /// The same peer, a resolver with NO standing call deadline, and a deadline passed for
    /// one call: what a host that knows how long ITS calls should take uses.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn a_deadline_passed_for_one_call_bounds_that_call() {
        let (addr, client_id, server_pem, stopped) = hostile_peer();
        let client = connect_with(addr, &client_id, &server_pem, IDLE)
            .unwrap()
            .with_call_timeout(None);
        assert_eq!(client.call_timeout(), None);

        let start = Instant::now();
        let error = client
            .issue_as_within(
                source("urn:test:anything"),
                &Capability::root(),
                Duration::from_millis(300),
            )
            .expect_err("bounded by the deadline this call was given");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
        assert!(matches!(error, Error::Timeout(_)), "{error:?}");
        assert!(error.to_string().contains("within 300ms"), "{error}");
        assert_eq!(
            stopped.recv_timeout(Duration::from_secs(5)),
            Ok(Some(u64::from(CANCELED)))
        );
    }

    /// From inside a caller's runtime the round trip runs as a task on the resolver's own
    /// runtime (`drive`), which is the path where a missed deadline could leak a task.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn a_missed_deadline_from_inside_a_runtime_leaves_no_task_behind() {
        let (addr, client_id, server_pem, _stopped) = hostile_peer();
        let client = Arc::new(
            connect_with(addr, &client_id, &server_pem, IDLE)
                .unwrap()
                .with_call_timeout(Some(Duration::from_millis(300))),
        );
        let baseline = alive(&client);
        let caller = Runtime::new().unwrap();
        let inside = Arc::clone(&client);
        let error = caller
            .block_on(async move { inside.issue(source("urn:test:anything")) })
            .expect_err("bounded from a runtime thread too");
        assert!(matches!(error, Error::Timeout(_)), "{error:?}");
        assert!(
            settles_to(&client, baseline),
            "the spawned round trip outlived its deadline: {} tasks alive, {baseline} before",
            alive(&client)
        );
    }

    /// The bound costs an honest peer nothing: a call answered inside its deadline is a
    /// call answered, on the same resolver, and the next one too.
    #[test]
    fn a_slow_peer_that_answers_inside_the_deadline_still_succeeds() {
        let (addr, client_id, server_pem) = slow_peer(Duration::from_millis(300));
        let client = connect_with(addr, &client_id, &server_pem, IDLE)
            .unwrap()
            .with_call_timeout(Some(Duration::from_secs(5)));
        for _ in 0..2 {
            let (answer, _) = client
                .issue(source("urn:test:slow"))
                .expect("answered inside the deadline");
            assert_eq!(answer.bytes, b"slow");
        }
        let (answer, _) = client
            .issue_as_within(
                source("urn:test:slow"),
                &Capability::root(),
                Duration::from_secs(5),
            )
            .expect("and per call");
        assert_eq!(answer.bytes, b"slow");
    }

    /// The default follows the connection's idle timeout, so an operator who raised
    /// `quic.timeout` for long calls keeps them.
    #[test]
    fn the_default_call_deadline_is_the_idle_timeout() {
        let (addr, client_id, server_pem) = slow_peer(Duration::ZERO);
        let client = connect_with(addr, &client_id, &server_pem, IDLE).unwrap();
        assert_eq!(client.call_timeout(), Some(IDLE));
    }
}

/// ledger [#1359](http://localhost:1060/l/default/item/1359): the client PINGS, so a quiet
/// connection to a live peer stays up, a long silent call survives a short liveness bound,
/// and a peer that vanishes without closing is found in seconds rather than at the call
/// deadline. The server does NOT ping, so an older client (no call deadline) keeps exactly
/// the idle bound it always had.
#[cfg(test)]
mod keep_alive {
    use super::*;
    use ikigai_core::{EndpointSpace, Exact, FnEndpoint, Invocation, ReprType, Verb};
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// A UDP relay between one client and `upstream` that can be CUT: from then on it drops
    /// every datagram both ways and sends nothing of its own. That is what a peer that loses
    /// power or its network looks like from the other end: no close frame, no stateless
    /// reset, no ICMP, only silence. A closed socket on loopback is NOT that (it answers
    /// port-unreachable, and a restarted server resets), which is why this test needs a relay.
    struct Relay {
        addr: SocketAddr,
        cut: Arc<AtomicBool>,
    }

    impl Relay {
        fn to(upstream: SocketAddr) -> Relay {
            let front = UdpSocket::bind("127.0.0.1:0").unwrap();
            let back = UdpSocket::bind("127.0.0.1:0").unwrap();
            back.connect(upstream).unwrap();
            let addr = front.local_addr().unwrap();
            let cut = Arc::new(AtomicBool::new(false));
            let client = Arc::new(Mutex::new(None::<SocketAddr>));
            {
                let (front, back) = (front.try_clone().unwrap(), back.try_clone().unwrap());
                let (cut, client) = (Arc::clone(&cut), Arc::clone(&client));
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 65_536];
                    while let Ok((n, from)) = front.recv_from(&mut buf) {
                        *client.lock().unwrap() = Some(from);
                        if !cut.load(Ordering::SeqCst) {
                            let _ = back.send(&buf[..n]);
                        }
                    }
                });
            }
            {
                let cut = Arc::clone(&cut);
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 65_536];
                    while let Ok(n) = back.recv(&mut buf) {
                        let to = *client.lock().unwrap();
                        if let (false, Some(to)) = (cut.load(Ordering::SeqCst), to) {
                            let _ = front.send_to(&buf[..n], to);
                        }
                    }
                });
            }
            Relay { addr, cut }
        }

        fn cut(&self) {
            self.cut.store(true, Ordering::SeqCst);
        }
    }

    /// A server built exactly as [`serve`] builds one (`idle` for its idle timeout) that
    /// accepts every call, reads it whole and never answers. Each connection reports how it
    /// ended, and when.
    fn mute_peer(
        idle: Duration,
    ) -> (
        SocketAddr,
        Identity,
        String,
        mpsc::Receiver<(Instant, quinn::ConnectionError)>,
    ) {
        let server_id = generate();
        let client_id = generate();
        let config =
            server_config(&server_id, std::slice::from_ref(&client_id.cert_pem), idle).unwrap();
        let rt = Runtime::new().unwrap();
        let endpoint = rt
            .block_on(async { quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()) })
            .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let (ended, endings) = mpsc::channel();
        std::thread::spawn(move || {
            rt.block_on(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let Ok(connection) = incoming.await else {
                        continue;
                    };
                    let ended = ended.clone();
                    tokio::spawn(async move {
                        let streams = connection.clone();
                        tokio::spawn(async move {
                            while let Ok((send, mut recv)) = streams.accept_bi().await {
                                tokio::spawn(async move {
                                    let _ = recv.read_to_end(MAX_MESSAGE).await;
                                    // Hold the reply half open: never answer, never finish.
                                    let _ = send.stopped().await;
                                });
                            }
                        });
                        let reason = connection.closed().await;
                        // Native-only test code: the moment the server gave up is the measurement.
                        #[allow(clippy::disallowed_methods)]
                        let now = Instant::now();
                        let _ = ended.send((now, reason));
                    });
                }
            });
        });
        (addr, client_id, server_id.cert_pem, endings)
    }

    /// A peer that answers `urn:test:slow` after `delay` of SILENCE (a blocking sleep: the
    /// connection carries nothing while it works), its server built with idle timeout `idle`.
    fn slow_peer(delay: Duration, idle: Duration) -> (SocketAddr, Identity, String) {
        let server_id = generate();
        let client_id = generate();
        let config =
            server_config(&server_id, std::slice::from_ref(&client_id.cert_pem), idle).unwrap();
        let rt = Runtime::new().unwrap();
        let endpoint = rt
            .block_on(async { quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()) })
            .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let slow = FnEndpoint::new("slow", move |_: &Invocation<'_>| {
            std::thread::sleep(delay);
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"slow".to_vec(),
            ))
        });
        let kernel = Arc::new(Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:slow"), slow),
        )));
        std::thread::spawn(move || {
            rt.block_on(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let kernel = Arc::clone(&kernel);
                    tokio::spawn(async move {
                        if let Ok(connection) = incoming.await {
                            let session = Session {
                                capability: Capability::root(),
                                file_segment: String::new(),
                                principal: None,
                            };
                            serve_connection(&kernel, connection, session).await;
                        }
                    });
                }
            });
        });
        (addr, client_id, server_id.cert_pem)
    }

    fn source(iri: &str) -> Request {
        Request::new(Verb::Source, Iri::parse(iri).unwrap())
    }

    /// ★ The claim of ledger #1359, at the DEFAULTS a host runs with: a peer that vanishes in
    /// the middle of a call is found in seconds, by both ends. Before keep-alive the client
    /// learned nothing until its call deadline (the five-minute `quic.timeout`; sixty seconds
    /// here, so a regression fails in one minute rather than five), and the server until its
    /// own five-minute idle timeout.
    #[test]
    // Native-only (QUIC is not built for wasm); elapsed time is the measurement.
    #[allow(clippy::disallowed_methods)]
    fn a_peer_that_vanishes_mid_call_is_found_in_seconds_by_both_ends() {
        let (server, client_id, server_pem, endings) = mute_peer(DEFAULT_IDLE_TIMEOUT);
        let relay = Relay::to(server);
        let deadline = Duration::from_secs(60);
        let client = connect(relay.addr, &client_id, &server_pem)
            .unwrap()
            .with_call_timeout(Some(deadline));
        let call = std::thread::spawn(move || {
            let result = client.issue(source("urn:test:anything"));
            (Instant::now(), result)
        });
        // Let the call reach the peer, then the peer vanishes.
        std::thread::sleep(Duration::from_secs(1));
        relay.cut();
        let cut = Instant::now();

        let (failed, result) = call.join().unwrap();
        let error = result.expect_err("a vanished peer is an error");
        let found = failed - cut;
        assert!(
            found < Duration::from_secs(30),
            "the client found the vanished peer in {found:?}: the liveness bound \
             ({LIVENESS_TIMEOUT:?}) and one bounded redial, not the {deadline:?} call deadline"
        );
        assert!(
            !error.to_string().contains("did not answer within"),
            "found by the transport, not the call deadline: {error}"
        );

        let (closed, reason) = endings
            .recv_timeout(Duration::from_secs(30))
            .expect("the server gave up on the vanished client too");
        assert!(
            matches!(reason, quinn::ConnectionError::TimedOut),
            "{reason:?}"
        );
        let found = closed.saturating_duration_since(cut);
        assert!(
            found < Duration::from_secs(25),
            "the server found the vanished client in {found:?}"
        );
    }

    /// The other half of the claim: an HONEST long call, silent for longer than the liveness
    /// bound, still answers inside its call deadline, because the client's pings keep the
    /// connection alive while the peer works. Scaled down: a one-second bound on both sides
    /// (what was the whole idle window) and three seconds of silent work.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn an_honest_call_silent_past_the_old_idle_window_still_answers() {
        let window = Duration::from_secs(1);
        let (addr, client_id, server_pem) = slow_peer(Duration::from_secs(3), window);
        let client = connect_with(addr, &client_id, &server_pem, window)
            .unwrap()
            .with_call_timeout(Some(Duration::from_secs(10)));
        let start = Instant::now();
        let (answer, _) = client
            .issue(source("urn:test:slow"))
            .expect("the pings kept the connection alive through 3s of silence");
        assert_eq!(answer.bytes, b"slow");
        assert!(
            start.elapsed() >= Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
    }

    /// Keep-alive is actually applied: a quiet connection (no call at all) to a live peer
    /// outlives its one-second liveness bound. Guards the regression where a transport config
    /// is built and never applied, which a vanished-peer test alone cannot see.
    #[test]
    fn a_quiet_connection_to_a_live_peer_stays_up() {
        let (addr, client_id, server_pem, _endings) = mute_peer(Duration::from_secs(30));
        let client = connect_with(addr, &client_id, &server_pem, Duration::from_secs(1)).unwrap();
        std::thread::sleep(Duration::from_secs(3));
        let reason = client.wire.connection().close_reason();
        assert!(
            reason.is_none(),
            "closed while both peers lived: {reason:?}"
        );
    }

    /// The numbers a host actually runs with: at the default `quic.timeout`, fifteen seconds
    /// of liveness and a ping every five; a shorter `idle` caps the bound and the ping follows
    /// it; zero is "no idle timeout", and nothing pings.
    #[test]
    fn the_liveness_bound_and_ping_interval() {
        assert_eq!(
            liveness(DEFAULT_IDLE_TIMEOUT),
            (Duration::from_secs(15), Some(Duration::from_secs(5)))
        );
        assert_eq!(KEEP_ALIVE_INTERVAL, Duration::from_secs(5));
        assert_eq!(
            liveness(Duration::from_secs(3)),
            (Duration::from_secs(3), Some(Duration::from_secs(1)))
        );
        assert_eq!(liveness(Duration::ZERO), (Duration::ZERO, None));
        for idle in [
            Duration::from_millis(1),
            Duration::from_secs(1),
            DEFAULT_IDLE_TIMEOUT,
        ] {
            let (bound, ping) = liveness(idle);
            assert!(ping.is_some_and(|ping| ping < bound), "{idle:?}");
        }
    }

    /// ★ The SERVER does not ping, so a client older than keep-alive (no pings and, before
    /// cli 0.1.55, no call deadline either) sees exactly the idle bound it always had. If the
    /// server pinged, a server whose kernel wedged while its QUIC stack answered would hold
    /// such a client for ever: the unbounded wedge `transport` warned of, for the one client
    /// with no deadline to end it. Simulated with a client built on the plain idle-only
    /// transport, one second, quiet for three.
    #[test]
    fn an_older_client_without_pings_keeps_its_idle_bound() {
        let (addr, client_id, server_pem, _endings) = mute_peer(Duration::from_secs(30));
        let mut config = client_config(&client_id, &server_pem, Duration::from_secs(1)).unwrap();
        config.transport_config(Arc::new(transport(Duration::from_secs(1)).unwrap()));
        let rt = Runtime::new().unwrap();
        let reason = rt.block_on(async move {
            let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            endpoint.set_default_client_config(config);
            let connection = endpoint.connect(addr, "ikigai").unwrap().await.unwrap();
            tokio::time::sleep(Duration::from_secs(3)).await;
            connection.close_reason()
        });
        assert!(
            matches!(reason, Some(quinn::ConnectionError::TimedOut)),
            "the server kept a ping-less client's quiet connection alive: {reason:?}"
        );
    }
}

/// A door's verifier answers for EVERY connection, a resumed one too (ledger #2084).
///
/// rustls does not call the client-certificate verifier on a resumed TLS 1.3 handshake, and
/// a client that keeps one config across dials (as [`QuicResolver`] does when it redials)
/// offers the tickets its last connection received. These tests dial twice on ONE client
/// endpoint, so the second dial offers the first one's tickets, and change what the verifier
/// would say in between: the server's clock passes the certificate's `notAfter`, or the
/// certificate leaves a live trust list. Both must refuse the second connection.
#[cfg(test)]
mod resumption {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    /// A server clock the test sets, in seconds since the Unix epoch.
    #[derive(Debug)]
    struct Clock(Arc<AtomicU64>);

    impl rustls::time_provider::TimeProvider for Clock {
        fn current_time(&self) -> Option<UnixTime> {
            Some(UnixTime::since_unix_epoch(Duration::from_secs(
                self.0.load(Ordering::SeqCst),
            )))
        }
    }

    /// Seconds since the Unix epoch at midnight UTC on `year`-01-01.
    fn new_year(year: i32) -> u64 {
        rcgen::date_time_ymd(year, 1, 1).unix_timestamp() as u64
    }

    /// A self-signed client identity valid from 2000 to the start of 2030.
    fn expiring_identity() -> Identity {
        let mut params = rcgen::CertificateParams::new(vec!["ikigai".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Identity {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    /// Stand up `tls` as a server, then dial it twice from ONE client endpoint, calling
    /// `between` after the first connection. Returns whether the server admitted each dial
    /// (its handshake completed, so its verifier, if it ran, accepted).
    fn dial_twice(
        tls: rustls::ServerConfig,
        client: &Identity,
        server: &Identity,
        between: impl FnOnce(),
    ) -> (bool, bool) {
        let config = quic_server_config(tls, Duration::from_secs(10)).unwrap();
        let client_config =
            client_config(client, &server.cert_pem, Duration::from_secs(10)).unwrap();
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();
        let server_endpoint =
            quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server_endpoint.local_addr().unwrap();
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);

        // One dial: the server's verdict on its handshake. On admission the server sends a
        // byte on a stream, and the client reads it before closing: the session tickets were
        // sent ahead of it, so a client that can resume has them by then.
        let dial = || {
            rt.block_on(async {
                let connecting = client_endpoint.connect(addr, "ikigai").unwrap();
                let incoming = server_endpoint.accept().await.unwrap();
                let admitted = tokio::spawn(async move { incoming.await });
                let connection = connecting.await;
                let admitted = admitted.await.unwrap();
                let admitted = match admitted {
                    Ok(served) => {
                        let mut stream = served.open_uni().await.unwrap();
                        stream.write_all(b"!").await.unwrap();
                        stream.finish().unwrap();
                        if let Ok(connection) = &connection {
                            let mut stream = connection.accept_uni().await.unwrap();
                            stream.read_to_end(1).await.unwrap();
                        }
                        true
                    }
                    Err(_) => false,
                };
                if let Ok(connection) = connection {
                    connection.close(0u32.into(), b"done");
                }
                admitted
            })
        };
        let first = dial();
        between();
        let second = dial();
        (first, second)
    }

    #[test]
    fn a_resumed_connection_is_refused_once_the_certificate_has_expired() {
        let (client, server) = (expiring_identity(), generate());
        let now = Arc::new(AtomicU64::new(new_year(2029)));
        let mut tls = server_tls(
            &server,
            Pins::Fixed(vec![load_cert(&client.cert_pem).unwrap()]),
            alpn_protocols(),
        )
        .unwrap();
        tls.time_provider = Arc::new(Clock(Arc::clone(&now)));

        let (first, second) = dial_twice(tls, &client, &server, || {
            now.store(new_year(2031), Ordering::SeqCst)
        });
        assert!(first, "a pinned certificate inside its window is admitted");
        assert!(
            !second,
            "the certificate expired between the dials: its next connection, resumed or not, \
             must be refused"
        );
    }

    #[test]
    fn a_resumed_connection_is_refused_once_the_certificate_leaves_the_trust_list() {
        let (client, server) = (generate(), generate());
        let listed = Arc::new(Mutex::new(vec![client.cert_pem.clone()]));
        let read = Arc::clone(&listed);
        let trust: TrustList = Arc::new(move || Ok(read.lock().unwrap().clone()));
        let tls = server_tls(&server, Pins::Live(trust), alpn_protocols()).unwrap();

        let (first, second) = dial_twice(tls, &client, &server, || listed.lock().unwrap().clear());
        assert!(first, "a listed certificate is admitted");
        assert!(
            !second,
            "the certificate left the trust list between the dials: its next connection, \
             resumed or not, must be refused"
        );
    }

    /// The door's config sends no tickets and keeps no sessions.
    #[test]
    fn a_door_offers_no_resumption() {
        let server = generate();
        let tls = server_tls(&server, Pins::Fixed(Vec::new()), alpn_protocols()).unwrap();
        assert_eq!(tls.send_tls13_tickets, 0);
        assert!(!tls.ticketer.enabled());
        assert!(!tls.session_storage.can_cache());
    }
}
