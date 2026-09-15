use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use ikigai_core::Kernel;
use ikigai_quic::Session;
use ikigai_wire::{decode, encode, Call, Reply, WireError};
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport};
use libp2p::swarm::{ConnectionId, NetworkBehaviour, SwarmEvent};
use libp2p::{dcutr, identify, ping, relay, tls, yamux, StreamProtocol, Swarm, SwarmBuilder};
use tokio::sync::{mpsc, oneshot};

pub use libp2p::{Multiaddr, PeerId};

/// The libp2p protocol id the wire rides. The version is the wire's
/// [`PROTOCOL_VERSION`](ikigai_wire::PROTOCOL_VERSION) — a mismatched peer fails protocol
/// negotiation, just as a mismatched ALPN fails the QUIC handshake. (A `&'static str`
/// because `StreamProtocol::new` wants one; a test pins it to the wire constant.)
pub const WIRE_PROTOCOL: &str = "/ikigai/wire/7";

/// The identify protocol version string both peers and the relay announce.
const IDENTIFY_PROTOCOL: &str = "/ikigai/7";

/// The largest message accepted off a stream — the same bound as the QUIC transport. A
/// larger one is REFUSED, never truncated: a truncated postcard message that happened to
/// decode would be partial input accepted as complete.
pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// How long one call may take end to end — generous for the same reason
/// `ikigai_quic::DEFAULT_IDLE_TIMEOUT` is: the silence of a long resolution is the work.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// Mints the authority for one call from the PeerId that authenticated its connection, or
/// REFUSES it with `None`. The p2p twin of [`ikigai_quic::Minter`].
///
/// Called **per request**, not per connection: a relayed connection can outlive an edit to
/// `clients.json` by its whole circuit duration, and a direct one indefinitely, so minting
/// on every call is what keeps "editing the file revokes" true on this door.
pub type PeerMinter = Arc<dyn Fn(&PeerId) -> Option<Session> + Send + Sync>;

// ── the codec ──────────────────────────────────────────────────────────────────────────

/// Postcard [`Call`]/[`Reply`] framed by the stream itself, exactly as on QUIC: the writer
/// closes its half after one message, so the reader reads to end.
#[derive(Clone, Default)]
pub struct WireCodec;

async fn read_bounded<T: futures::AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    io.take(MAX_MESSAGE as u64 + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("a wire message exceeded {MAX_MESSAGE} bytes and was refused"),
        ));
    }
    Ok(bytes)
}

impl request_response::Codec for WireCodec {
    type Protocol = StreamProtocol;
    type Request = Call;
    type Response = Reply;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Call>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        decode(&read_bounded(io).await?)
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Reply>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        decode(&read_bounded(io).await?)
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        call: Call,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        io.write_all(&encode(&call)?).await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        reply: Reply,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        io.write_all(&encode(&reply)?).await
    }
}

// ── what a node reports ────────────────────────────────────────────────────────────────

/// Which path a connection took. The whole point of the off-LAN trial is to learn which
/// one won, so it is reported for every connection AND every call rather than folded into
/// "connected".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    Direct,
    Relayed,
}

/// Observable events, for tests and for the trial binaries' output.
#[derive(Clone, Debug)]
pub enum Report {
    /// A local listen address is live (direct, or a relay circuit address).
    Listening(Multiaddr),
    /// A relay accepted this node's reservation — it is now dialable through the relay.
    ReservationAccepted { relay: PeerId },
    /// A connection to `peer` was established over `path`.
    Connected {
        peer: PeerId,
        path: Path,
        remote: Multiaddr,
    },
    /// A connection to `peer` over `path` closed.
    Disconnected { peer: PeerId, path: Path },
    /// Identify from `by` reported the address it observes this node at. ⚠ A hole punch can
    /// only use observations that arrived BEFORE the relayed connection it upgrades was
    /// established: libp2p-dcutr 0.15 snapshots its candidates when that connection's handler
    /// is created. So a caller waits for this from the relay before dialing a circuit. (That
    /// wait is necessary; the spike did not show it sufficient — see the design note.)
    Observed { by: PeerId, addr: Multiaddr },
    /// A DCUtR hole-punch attempt with `peer` finished. `Ok` means a direct connection now
    /// exists beside the relayed one.
    HolePunch {
        peer: PeerId,
        result: Result<(), String>,
    },
    /// A call from `peer`, arriving over `path`, was answered under a minted session.
    Served { peer: PeerId, path: Option<Path> },
    /// A call from `peer` was REFUSED: no authority is configured for its PeerId.
    Refused { peer: PeerId, path: Option<Path> },
    /// A dial or listen failed.
    Failed(String),
}

/// A reply, and the path of the connection that carried it (`None` only if that
/// connection closed before the reply was delivered).
#[derive(Clone, Debug)]
pub struct Answered {
    pub reply: Reply,
    pub path: Option<Path>,
}

fn path_of(endpoint: &libp2p::core::ConnectedPoint) -> Path {
    if endpoint.is_relayed() {
        Path::Relayed
    } else {
        Path::Direct
    }
}

fn report(reports: &Option<mpsc::UnboundedSender<Report>>, event: Report) {
    if let Some(tx) = reports {
        let _ = tx.send(event);
    }
}

// ── the relay ──────────────────────────────────────────────────────────────────────────

/// What a circuit relay admits. Deliberately without `Default`: a public relay is an abuse
/// surface, so whoever runs one states who may use it and how much.
///
/// The allowlist is **fail-closed** and applies to BOTH ends: a reservation (the peer that
/// wants to be reachable) and a circuit's source (the peer dialing through) must each be on
/// it. An empty allowlist relays nothing.
#[derive(Clone, Debug)]
pub struct RelayPolicy {
    pub allowed: HashSet<PeerId>,
    /// How long one relayed circuit may live before the relay closes it.
    pub max_circuit_duration: Duration,
    /// How many bytes one circuit may carry (each direction) before the relay closes it.
    pub max_circuit_bytes: u64,
    /// How many reservations the relay holds at once, across all peers.
    pub max_reservations: usize,
    /// How many circuits the relay carries at once, across all peers.
    pub max_circuits: usize,
}

impl RelayPolicy {
    fn into_config(self) -> relay::Config {
        let allowed = Arc::new(self.allowed);
        // `Config::default()` carries libp2p's own per-peer and per-IP rate limiters; the
        // allowlist is ADDED to them, so a listed peer is still rate limited.
        let mut config = relay::Config {
            max_circuit_duration: self.max_circuit_duration,
            max_circuit_bytes: self.max_circuit_bytes,
            max_reservations: self.max_reservations,
            max_reservations_per_peer: 1,
            max_circuits: self.max_circuits,
            ..relay::Config::default()
        };
        let reserve = Arc::clone(&allowed);
        config
            .reservation_rate_limiters
            .push(Box::new(move |peer: PeerId, _: &Multiaddr, _| {
                reserve.contains(&peer)
            }));
        config
            .circuit_src_rate_limiters
            .push(Box::new(move |peer: PeerId, _: &Multiaddr, _| {
                allowed.contains(&peer)
            }));
        config
    }
}

#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    relay: relay::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

/// Events a relay reports.
#[derive(Clone, Debug)]
pub enum RelayReport {
    Listening(Multiaddr),
    ReservationAccepted {
        peer: PeerId,
    },
    /// A reservation was refused — the allowlist or a limit said no.
    ReservationDenied {
        peer: PeerId,
    },
    CircuitAccepted {
        src: PeerId,
        dst: PeerId,
    },
    CircuitDenied {
        src: PeerId,
        dst: PeerId,
    },
    CircuitClosed {
        src: PeerId,
        dst: PeerId,
    },
}

/// Where a relay listens and what it claims as its public address.
pub struct RelayAddrs {
    pub listen: Vec<Multiaddr>,
    /// The address(es) peers reach the relay at — edge's public IP and port. ⚠ A relay
    /// with NO confirmed external address does not offer the hop protocol at all
    /// (libp2p-relay 0.22 `behaviour.rs`, the `Status` switch), so every reservation
    /// silently fails to start. Stated by the operator, never inferred from what a peer
    /// says it observed: a relay is a trust decision, and so is the address it advertises.
    pub external: Vec<Multiaddr>,
    /// Confirm each concrete listen address as external — for a loopback test, where the
    /// port is ephemeral and so cannot be stated in advance. Never on a public relay.
    pub confirm_listen_addrs: bool,
}

/// Run a circuit relay until the task is dropped.
pub async fn run_relay(
    keypair: Keypair,
    policy: RelayPolicy,
    addrs: RelayAddrs,
    reports: Option<mpsc::UnboundedSender<RelayReport>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let RelayAddrs {
        listen,
        external,
        confirm_listen_addrs,
    } = addrs;
    let config = policy.into_config();
    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic()
        .with_behaviour(|key| RelayBehaviour {
            relay: relay::Behaviour::new(key.public().to_peer_id(), config),
            identify: identify::Behaviour::new(identify::Config::new(
                IDENTIFY_PROTOCOL.to_string(),
                key.public(),
            )),
            ping: ping::Behaviour::default(),
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    for addr in listen {
        swarm.listen_on(addr)?;
    }
    for addr in external {
        swarm.add_external_address(addr);
    }
    let send = |event: RelayReport| {
        if let Some(tx) = &reports {
            let _ = tx.send(event);
        }
    };
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                if confirm_listen_addrs {
                    swarm.add_external_address(address.clone());
                }
                send(RelayReport::Listening(address))
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(event)) => match event {
                relay::Event::ReservationReqAccepted { src_peer_id, .. } => {
                    send(RelayReport::ReservationAccepted { peer: src_peer_id })
                }
                relay::Event::ReservationReqDenied { src_peer_id, .. } => {
                    send(RelayReport::ReservationDenied { peer: src_peer_id })
                }
                relay::Event::CircuitReqAccepted {
                    src_peer_id,
                    dst_peer_id,
                } => send(RelayReport::CircuitAccepted {
                    src: src_peer_id,
                    dst: dst_peer_id,
                }),
                relay::Event::CircuitReqDenied {
                    src_peer_id,
                    dst_peer_id,
                    ..
                } => send(RelayReport::CircuitDenied {
                    src: src_peer_id,
                    dst: dst_peer_id,
                }),
                relay::Event::CircuitClosed {
                    src_peer_id,
                    dst_peer_id,
                    ..
                } => send(RelayReport::CircuitClosed {
                    src: src_peer_id,
                    dst: dst_peer_id,
                }),
                _ => {}
            },
            _ => {}
        }
    }
}

// ── a peer ─────────────────────────────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct PeerBehaviour {
    relay_client: relay::client::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    dcutr: dcutr::Behaviour,
    wire: request_response::Behaviour<WireCodec>,
}

/// How a peer is set up.
pub struct PeerConfig {
    pub keypair: Keypair,
    /// The kernel this peer SERVES, with the minter that authorizes each call. `None`: the
    /// peer only calls out, and every inbound call is refused.
    pub serve: Option<(Arc<Kernel>, PeerMinter)>,
    /// Direct listen addresses. Empty is legal: a peer reachable ONLY through a relay.
    pub listen: Vec<Multiaddr>,
    /// Relays to reserve a slot on, each `…/p2p/<relay PeerId>`. The peer becomes dialable
    /// at `…/p2p/<relay>/p2p-circuit/p2p/<self>`.
    pub relays: Vec<Multiaddr>,
    /// Addresses to confirm as externally reachable — the candidates DCUtR punches from.
    pub external: Vec<Multiaddr>,
    /// Confirm every address a remote peer's identify reports observing. Behind a
    /// symmetric or carrier-grade NAT the observation is wrong for the next peer, and the
    /// hole punch fails — which is reported, not hidden.
    pub confirm_observed_addrs: bool,
    pub reports: Option<mpsc::UnboundedSender<Report>>,
}

type AnswerTo = oneshot::Sender<Result<Answered, String>>;

enum Command {
    Dial(Multiaddr),
    Call {
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        call: Call,
        reply: AnswerTo,
    },
}

/// A handle to a running peer: its identity, and the ability to call another peer.
#[derive(Clone)]
pub struct PeerHandle {
    pub peer_id: PeerId,
    commands: mpsc::UnboundedSender<Command>,
}

impl PeerHandle {
    /// Dial `addr` without calling anything — used to connect to a relay ahead of a circuit
    /// dial, so identify has reported an observation before DCUtR needs one (see
    /// [`Report::Observed`]). The outcome arrives as a report.
    pub fn dial(&self, addr: Multiaddr) -> Result<(), String> {
        self.commands
            .send(Command::Dial(addr))
            .map_err(|_| "the peer task has stopped".to_string())
    }

    /// Send one wire [`Call`] to `peer`, dialing `addresses` if no connection exists (a
    /// relay circuit address for a peer off the LAN). The answer says which path carried it.
    pub async fn call(
        &self,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        call: Call,
    ) -> Result<Answered, String> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Call {
                peer,
                addresses,
                call,
                reply,
            })
            .map_err(|_| "the peer task has stopped".to_string())?;
        answer
            .await
            .map_err(|_| "the peer task dropped the call".to_string())?
    }
}

/// The address at which `target` is dialable through `relay` (which must end in
/// `/p2p/<relay PeerId>`).
pub fn circuit_addr(relay: &Multiaddr, target: PeerId) -> Multiaddr {
    relay
        .clone()
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(target))
}

/// Build a peer and run it on the current tokio runtime (the swarm runs on a spawned task
/// for as long as the runtime lives).
pub fn spawn_peer(
    config: PeerConfig,
) -> Result<PeerHandle, Box<dyn std::error::Error + Send + Sync>> {
    let PeerConfig {
        keypair,
        serve,
        listen,
        relays,
        external,
        confirm_observed_addrs,
        reports,
    } = config;
    let peer_id = keypair.public().to_peer_id();
    let mut swarm: Swarm<PeerBehaviour> = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic()
        // The relay circuit is a plain byte stream, so it needs its own security and
        // multiplexing upgrade: TLS 1.3 authenticates the REMOTE PEER end to end over the
        // circuit, which is why the relay forwards ciphertext it cannot read.
        .with_relay_client(tls::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| PeerBehaviour {
            relay_client,
            identify: identify::Behaviour::new(identify::Config::new(
                IDENTIFY_PROTOCOL.to_string(),
                key.public(),
            )),
            ping: ping::Behaviour::default(),
            dcutr: dcutr::Behaviour::new(key.public().to_peer_id()),
            wire: request_response::Behaviour::new(
                [(StreamProtocol::new(WIRE_PROTOCOL), ProtocolSupport::Full)],
                request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
            ),
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    for addr in listen {
        swarm.listen_on(addr)?;
    }
    for addr in external {
        swarm.add_external_address(addr);
    }
    for relay in relays {
        swarm.listen_on(relay.with(Protocol::P2pCircuit))?;
    }
    let (commands, rx) = mpsc::unbounded_channel();
    tokio::spawn(run_peer(swarm, rx, serve, confirm_observed_addrs, reports));
    Ok(PeerHandle { peer_id, commands })
}

async fn run_peer(
    mut swarm: Swarm<PeerBehaviour>,
    mut commands: mpsc::UnboundedReceiver<Command>,
    serve: Option<(Arc<Kernel>, PeerMinter)>,
    confirm_observed_addrs: bool,
    reports: Option<mpsc::UnboundedSender<Report>>,
) {
    let mut pending: HashMap<OutboundRequestId, AnswerTo> = HashMap::new();
    // The path of every live connection, so a call's answer can say which one carried it.
    let mut paths: HashMap<ConnectionId, Path> = HashMap::new();
    // Answers computed off the swarm task: a resolution can take minutes, and the swarm
    // must keep polling (pings, relay renewals, other peers' calls) meanwhile.
    let (answered_tx, mut answered) =
        mpsc::unbounded_channel::<(request_response::ResponseChannel<Reply>, Reply)>();
    let mut handles_open = true;
    loop {
        tokio::select! {
            command = commands.recv(), if handles_open => match command {
                Some(Command::Dial(addr)) => {
                    if let Err(error) = swarm.dial(addr) {
                        report(&reports, Report::Failed(format!("dial: {error}")));
                    }
                }
                Some(Command::Call { peer, addresses, call, reply }) => {
                    let id = swarm
                        .behaviour_mut()
                        .wire
                        .send_request_with_addresses(&peer, call, addresses);
                    pending.insert(id, reply);
                }
                // Every handle is gone: nobody can call out any more. A SERVING peer keeps
                // answering; a calling-only one has nothing left to do.
                None if serve.is_none() => return,
                None => handles_open = false,
            },
            Some((channel, reply)) = answered.recv() => {
                let _ = swarm.behaviour_mut().wire.send_response(channel, reply);
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => report(&reports, Report::Listening(address)),
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => {
                    let path = path_of(&endpoint);
                    paths.insert(connection_id, path);
                    report(
                        &reports,
                        Report::Connected {
                            peer: peer_id,
                            path,
                            remote: endpoint.get_remote_address().clone(),
                        },
                    )
                }
                SwarmEvent::ConnectionClosed { peer_id, connection_id, endpoint, .. } => {
                    paths.remove(&connection_id);
                    report(&reports, Report::Disconnected { peer: peer_id, path: path_of(&endpoint) })
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    report(&reports, Report::Failed(format!("dial: {error}")))
                }
                SwarmEvent::ListenerError { error, .. } => {
                    report(&reports, Report::Failed(format!("listen: {error}")))
                }
                SwarmEvent::ListenerClosed { reason: Err(error), .. } => {
                    report(&reports, Report::Failed(format!("listener closed: {error}")))
                }
                SwarmEvent::Behaviour(PeerBehaviourEvent::RelayClient(
                    relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
                )) => report(&reports, Report::ReservationAccepted { relay: relay_peer_id }),
                SwarmEvent::Behaviour(PeerBehaviourEvent::Dcutr(dcutr::Event { remote_peer_id, result })) => {
                    report(
                        &reports,
                        Report::HolePunch {
                            peer: remote_peer_id,
                            result: result.map(|_| ()).map_err(|e| e.to_string()),
                        },
                    )
                }
                SwarmEvent::Behaviour(PeerBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                    if confirm_observed_addrs {
                        swarm.add_external_address(info.observed_addr.clone());
                    }
                    report(&reports, Report::Observed { by: peer_id, addr: info.observed_addr });
                }
                SwarmEvent::Behaviour(PeerBehaviourEvent::Wire(event)) => match event {
                    request_response::Event::Message { peer, connection_id, message } => {
                        let path = paths.get(&connection_id).copied();
                        match message {
                            request_response::Message::Request { request, channel, .. } => {
                                answer(&serve, peer, path, request, channel, &answered_tx, &reports);
                            }
                            request_response::Message::Response { request_id, response } => {
                                if let Some(reply) = pending.remove(&request_id) {
                                    let _ = reply.send(Ok(Answered { reply: response, path }));
                                }
                            }
                        }
                    }
                    request_response::Event::OutboundFailure { request_id, error, .. } => {
                        if let Some(reply) = pending.remove(&request_id) {
                            let _ = reply.send(Err(error.to_string()));
                        }
                    }
                    _ => {}
                },
                _ => {}
            },
        }
    }
}

/// Authorize and answer one inbound call. The minter runs FIRST and a refused peer never
/// reaches the kernel; an authorized one is answered by `ikigai_quic::dispatch`, the QUIC
/// server's own function, so the clamp and the scoped manifold cannot drift between doors.
fn answer(
    serve: &Option<(Arc<Kernel>, PeerMinter)>,
    peer: PeerId,
    path: Option<Path>,
    call: Call,
    channel: request_response::ResponseChannel<Reply>,
    answered: &mpsc::UnboundedSender<(request_response::ResponseChannel<Reply>, Reply)>,
    reports: &Option<mpsc::UnboundedSender<Report>>,
) {
    let Some((kernel, minter)) = serve else {
        report(reports, Report::Refused { peer, path });
        let _ = answered.send((channel, denied("this peer serves no kernel")));
        return;
    };
    let (kernel, minter) = (Arc::clone(kernel), Arc::clone(minter));
    let answered = answered.clone();
    let reports = reports.clone();
    tokio::task::spawn_blocking(move || {
        let reply = match minter(&peer) {
            Some(session) => {
                report(&reports, Report::Served { peer, path });
                ikigai_quic::dispatch(&kernel, call, &session)
            }
            // A typed PERMANENT denial rather than a closed connection: the reply must say,
            // in the taxonomy a Failover respects, that retrying elsewhere will not help. (QUIC
            // closes the connection instead, because there the connection IS the principal;
            // here one connection can be a relay circuit carrying calls minted one by one.)
            None => {
                report(&reports, Report::Refused { peer, path });
                denied("no authority is configured for this peer")
            }
        };
        let _ = answered.send((channel, reply));
    });
}

fn denied(why: &str) -> Reply {
    Reply::ErrorTyped(WireError::Denied(why.to_string()))
}

/// Read a libp2p keypair from `path` (protobuf encoding), or generate an Ed25519 one and
/// write it there, owner-readable only. The PeerId — the thing an operator enrols — is a
/// function of this key, so a lost key file is a changed identity.
pub fn load_or_generate_keypair(path: &std::path::Path) -> io::Result<Keypair> {
    match std::fs::read(path) {
        Ok(bytes) => Keypair::from_protobuf_encoding(&bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let keypair = Keypair::generate_ed25519();
            let bytes = keypair
                .to_protobuf_encoding()
                .map_err(|e| io::Error::other(e.to_string()))?;
            write_private(path, &bytes)?;
            Ok(keypair)
        }
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_protocol_id_carries_the_wire_version() {
        assert_eq!(
            WIRE_PROTOCOL,
            format!("/ikigai/wire/{}", ikigai_wire::PROTOCOL_VERSION)
        );
    }

    #[test]
    fn a_circuit_address_names_the_relay_then_the_target() {
        let relay_id = Keypair::generate_ed25519().public().to_peer_id();
        let target = Keypair::generate_ed25519().public().to_peer_id();
        let relay: Multiaddr = format!("/ip4/203.0.113.7/udp/4001/quic-v1/p2p/{relay_id}")
            .parse()
            .unwrap();
        assert_eq!(
            circuit_addr(&relay, target).to_string(),
            format!("/ip4/203.0.113.7/udp/4001/quic-v1/p2p/{relay_id}/p2p-circuit/p2p/{target}")
        );
    }

    #[test]
    fn a_keypair_file_is_the_identity_and_survives_a_reload() {
        let dir = std::env::temp_dir().join(format!("ikigai-p2p-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p2p.key");
        let _ = std::fs::remove_file(&path);
        let first = load_or_generate_keypair(&path)
            .unwrap()
            .public()
            .to_peer_id();
        let again = load_or_generate_keypair(&path)
            .unwrap()
            .public()
            .to_peer_id();
        assert_eq!(first, again, "a reload must not mint a new PeerId");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A relay with an empty allowlist admits nobody: both limiter hooks say no to any peer.
    #[test]
    fn an_empty_relay_allowlist_admits_nobody() {
        let mut config = RelayPolicy {
            allowed: HashSet::new(),
            max_circuit_duration: Duration::from_secs(60),
            max_circuit_bytes: 1 << 20,
            max_reservations: 1,
            max_circuits: 1,
        }
        .into_config();
        let anyone = Keypair::generate_ed25519().public().to_peer_id();
        let addr: Multiaddr = "/ip4/198.51.100.1/udp/1/quic-v1".parse().unwrap();
        // libp2p names `web_time::Instant`, which on a native target IS `std::time::Instant`.
        // The allowlist hooks ignore the time; any value will do, and this test is native-only.
        #[allow(clippy::disallowed_methods)] // a native unit test; the value is never read
        fn any_instant() -> std::time::Instant {
            std::time::Instant::now()
        }
        let now = any_instant();
        let allowlist_reserve = config.reservation_rate_limiters.last_mut().unwrap();
        assert!(!allowlist_reserve.try_next(anyone, &addr, now));
        let allowlist_circuit = config.circuit_src_rate_limiters.last_mut().unwrap();
        assert!(!allowlist_circuit.try_next(anyone, &addr, now));
    }
}
