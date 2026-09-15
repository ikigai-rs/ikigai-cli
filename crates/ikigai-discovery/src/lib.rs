//! Announce and find ikigai kernels on the local network, over multicast DNS.
//!
//! A served kernel ANNOUNCES itself (`_ikigai._udp.local.`) carrying its name, port, and —
//! the interesting part — what it serves: the capability ceiling and the surface its serve
//! banner already prints. A client BROWSES, so a mount can name a peer instead of an
//! address. Addresses move; names don't.
//!
//! # Discovery supplies an address, never trust
//!
//! An announced name is attacker-controlled: anything on the LAN can claim to be `plasma`.
//! What makes identity real is the pinned certificate the connection is made with, so
//! nothing here widens the trust set. A peer is listed with whether the local machine holds
//! a pinned cert for it ([`Peer::trusted`]), and a mount by name still refuses to connect
//! without one — an impostor gets a failed handshake, not a connection.
//!
//! Note the honest limit of that flag: it says "this machine holds a server cert for that
//! peer", NOT "I can connect". The peer must also trust *our* client cert, and only a dial
//! proves that.
//!
//! # Absence of an announcement is not evidence of absence
//!
//! mDNS is best-effort multicast — a packet is lost, an interface sleeps, a peer sits on
//! another segment. So [`Browser::presence`] distinguishes a peer we watched LEAVE from one
//! we have simply never heard of, and only the former is [`Presence::Withdrawn`]. A caller
//! may skip a dial on `Withdrawn`; skipping on `Unknown` would refuse a peer that is right
//! there, which is worse than the wait it saves.
//!
//! # An announcement says what it actually advertises
//!
//! [`announce`] owns the address set it puts in the record rather than delegating it to the
//! responder, re-reads the host's addresses every [`ADDRESS_CHECK_INTERVAL`], and reports
//! every change as an [`AnnounceEvent`] naming the addresses. A record with no routable
//! address is never registered: no peer could use it (see [`AnnounceEvent::Withheld`]).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use mdns_sd::{DaemonEvent, ServiceDaemon, ServiceEvent, ServiceInfo};

/// The DNS-SD service type every ikigai kernel announces under. UDP because the transport
/// that matters is QUIC.
pub const SERVICE_TYPE: &str = "_ikigai._udp.local.";

/// TXT key: the served surface, verbatim from the serve banner (e.g. `host + fs + llm`).
pub const TXT_SURFACE: &str = "surface";
/// TXT key: the capability ceiling every connection is clamped to.
pub const TXT_CEILING: &str = "cap";
/// TXT key: the wire protocol version, so a client can tell an incompatible peer apart from
/// an absent one before it dials.
pub const TXT_VERSION: &str = "v";

/// How often an announcement re-reads this host's addresses. The same period `mdns-sd` polls
/// its own interface list on, so the watcher adds no new cadence to the machine.
pub const ADDRESS_CHECK_INTERVAL: Duration =
    Duration::from_secs(mdns_sd::IP_CHECK_INTERVAL_IN_SECS_DEFAULT as u64);

/// One kernel heard on the network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The instance name it announced — what a mount refers to (`peer:plasma`).
    pub name: String,
    pub addrs: Vec<IpAddr>,
    pub port: u16,
    /// What it says it serves. Advertisement, not proof: the ceiling is enforced by the
    /// peer at resolution time regardless of what it announced here.
    pub surface: Option<String>,
    pub ceiling: Option<String>,
    pub version: Option<String>,
    /// Whether THIS machine holds a pinned server certificate for the peer. See the module
    /// note: it means "I could try", not "I can connect".
    pub trusted: bool,
}

impl Peer {
    /// The address a mount should dial, paired with the announced port.
    ///
    /// NOT simply the first: mdns-sd hands back a HashSet, so "first" varies run to run —
    /// the same peer was reported as `192.168.4.178` and `[fe80::1]` on consecutive calls.
    /// A mount that dials a different address each time is unreproducible, and a link-local
    /// or loopback address may not reach the peer at all. So rank them and take the best.
    pub fn socket_addr(&self) -> Option<std::net::SocketAddr> {
        let mut usable: Vec<&IpAddr> = self.addrs.iter().collect();
        usable.sort_by_key(|ip| (address_rank(ip), ip.to_string()));
        usable.first().map(|ip| (**ip, self.port).into())
    }
}

/// Lower is better. A routable IPv4 first (what a LAN peer is actually reachable on), then
/// routable IPv6, then link-local, and loopback last — a peer only reachable on loopback is
/// on this very machine, which is the least useful answer to "where do I dial it".
fn address_rank(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(v4) if v4.is_loopback() => 4,
        IpAddr::V4(v4) if v4.is_link_local() => 3,
        IpAddr::V4(_) => 0,
        IpAddr::V6(v6) if v6.is_loopback() => 4,
        // No stable `is_unicast_link_local` on stable Rust: fe80::/10 by inspection.
        IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80 => 3,
        IpAddr::V6(_) => 1,
    }
}

/// How long a withdrawal is trusted before it decays back to [`Presence::Unknown`].
///
/// A negative must not be permanent. The browse socket is bound to an interface, and an
/// interface goes away — sleep/wake, a VPN, changing networks — so a browse can outlive its
/// ability to hear anything. If `Withdrawn` never expired, a caller that skips the dial on
/// absence would skip it FOREVER, and a peer that came back would never be used again until
/// something restarted. Absence expires; presence does not need to.
///
/// Two minutes: long enough that a peer which really left is not dialled repeatedly, short
/// enough that its return costs at most one bounded dial to notice.
pub const WITHDRAWN_TTL: std::time::Duration = std::time::Duration::from_secs(120);

/// What is known about a peer right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    /// Announced, and not withdrawn since.
    Present,
    /// We heard it announce and then heard it LEAVE (or its record expired). Positive
    /// evidence of absence — the only state on which skipping a dial is sound.
    Withdrawn,
    /// Never heard of. NOT evidence of absence: the peer may be up and simply unheard.
    Unknown,
}

/// One address this host holds, and the interface it is on.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostAddr {
    pub interface: String,
    pub ip: IpAddr,
}

impl HostAddr {
    /// Whether a peer on ANOTHER machine could dial it: neither loopback nor link-local.
    ///
    /// Link-local does not count, and that is load-bearing rather than fussy: an interface
    /// gets its `fe80::` address the moment the link comes up, well before DHCP hands out
    /// the address a peer can actually use, so counting it would re-open exactly the
    /// login-before-the-network window this rule exists to close. A peer's
    /// [`Peer::socket_addr`] ranks link-local below every routable address for the same
    /// reason.
    pub fn is_routable(&self) -> bool {
        address_rank(&self.ip) <= 1
    }
}

impl fmt::Display for HostAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.ip, self.interface)
    }
}

/// What an announcement did, reported as it happens. Its `Display` is the log line, and it
/// names ADDRESSES — "announcing as plasma" alone is an assertion of intent that stayed true
/// for an hour while the only address in the record was `127.0.0.1`.
///
/// ```
/// use ikigai_discovery::{AnnounceEvent, HostAddr};
///
/// let lan = HostAddr { interface: "en0".into(), ip: "192.168.4.178".parse().unwrap() };
/// let lo = HostAddr { interface: "lo0".into(), ip: "127.0.0.1".parse().unwrap() };
///
/// let up = AnnounceEvent::Announced { name: "plasma".into(), addrs: vec![lan.clone(), lo.clone()] };
/// assert_eq!(
///     up.to_string(),
///     "announcing \"plasma\" on _ikigai._udp.local. at 192.168.4.178 (en0), 127.0.0.1 (lo0)"
/// );
///
/// let waiting = AnnounceEvent::Withheld { name: "plasma".into(), addrs: vec![lo], withdrawn: false };
/// assert_eq!(
///     waiting.to_string(),
///     "warning: NOT announcing \"plasma\": no routable address (only 127.0.0.1 (lo0)), so no \
///      peer could reach it; will announce when one appears"
/// );
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnnounceEvent {
    /// A record is registered carrying exactly `addrs`, most dialable first.
    Announced { name: String, addrs: Vec<HostAddr> },
    /// The host's addresses changed, and the record was re-registered in place (no goodbye,
    /// so a peer never sees a false withdrawal).
    Reannounced {
        name: String,
        added: Vec<HostAddr>,
        removed: Vec<HostAddr>,
        addrs: Vec<HostAddr>,
    },
    /// This host has no routable address, so nothing is registered: a loopback-only record
    /// is one no peer can use. `withdrawn` is true when a live record was just taken down
    /// because its last routable address went away. Announcing resumes by itself.
    Withheld {
        name: String,
        addrs: Vec<HostAddr>,
        withdrawn: bool,
    },
    /// The responder lost a name conflict and renamed a record. A peer looking for the
    /// original name will not find it under the new one.
    Renamed {
        original: String,
        renamed: String,
        interface: String,
    },
    /// Something failed. The watcher retries on its next check; a repeat of the same error
    /// is not reported again.
    Failed { name: String, error: String },
}

impl fmt::Display for AnnounceEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnnounceEvent::Announced { name, addrs } => {
                write!(
                    f,
                    "announcing \"{name}\" on {SERVICE_TYPE} at {}",
                    list(addrs)
                )
            }
            AnnounceEvent::Reannounced {
                name,
                added,
                removed,
                addrs,
            } => write!(
                f,
                "re-announcing \"{name}\": addresses changed (added {}; removed {}), now at {}",
                list(added),
                list(removed),
                list(addrs)
            ),
            AnnounceEvent::Withheld {
                name,
                addrs,
                withdrawn: false,
            } => write!(
                f,
                "warning: NOT announcing \"{name}\": no routable address (only {}), so no peer \
                 could reach it; will announce when one appears",
                list(addrs)
            ),
            AnnounceEvent::Withheld {
                name,
                addrs,
                withdrawn: true,
            } => write!(
                f,
                "warning: WITHDREW the announcement of \"{name}\": no routable address left \
                 (only {}); will announce again when one appears",
                list(addrs)
            ),
            AnnounceEvent::Renamed {
                original,
                renamed,
                interface,
            } => write!(
                f,
                "warning: mDNS name conflict on {interface}: \"{original}\" was renamed \
                 \"{renamed}\", so a peer looking for the original name will not find it"
            ),
            AnnounceEvent::Failed { name, error } => {
                write!(
                    f,
                    "warning: announcing \"{name}\" failed: {error}; retrying"
                )
            }
        }
    }
}

fn list(addrs: &[HostAddr]) -> String {
    if addrs.is_empty() {
        return "no addresses".to_string();
    }
    addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Most dialable first, then stable — the order a reader of the log wants.
fn ranked<'a>(addrs: impl IntoIterator<Item = &'a HostAddr>) -> Vec<HostAddr> {
    let mut out: Vec<HostAddr> = addrs.into_iter().cloned().collect();
    out.sort_by(|a, b| {
        (address_rank(&a.ip), &a.interface, a.ip).cmp(&(address_rank(&b.ip), &b.interface, b.ip))
    });
    out
}

/// Where an announcement learns this host's addresses. The seam exists so the property that
/// matters — an address that appears AFTER startup ends up in the record — can be tested
/// without multicast, which a CI runner does not reliably carry.
trait AddressSource: Send + 'static {
    fn addresses(&self) -> io::Result<BTreeSet<HostAddr>>;
}

/// The real interfaces, filtered the way `mdns-sd` filters the ones it will send on: up, not
/// point-to-point (so not a `utun`), and not Apple's peer-to-peer Wi-Fi. An address the
/// responder would never announce must not appear in a log line claiming it is announced.
struct HostInterfaces;

impl AddressSource for HostInterfaces {
    fn addresses(&self) -> io::Result<BTreeSet<HostAddr>> {
        Ok(if_addrs::get_if_addrs()?
            .into_iter()
            .filter(|i| i.is_oper_up() && !i.is_p2p() && !is_apple_p2p(&i.name))
            .map(|i| HostAddr {
                ip: i.ip(),
                interface: i.name,
            })
            .collect())
    }
}

/// `awdl*` / `llw*`: AirDrop-style peer-to-peer links, which `mdns-sd` skips by default.
fn is_apple_p2p(interface: &str) -> bool {
    interface.starts_with("awdl") || interface.starts_with("llw")
}

/// Where a record goes. The daemon in production; a recorder in tests.
trait Registrar: Send + 'static {
    fn register(&mut self, record: ServiceInfo) -> io::Result<()>;
    fn unregister(&mut self, fullname: &str) -> io::Result<()>;
}

impl Registrar for ServiceDaemon {
    fn register(&mut self, record: ServiceInfo) -> io::Result<()> {
        ServiceDaemon::register(self, record).map_err(other)
    }

    fn unregister(&mut self, fullname: &str) -> io::Result<()> {
        ServiceDaemon::unregister(self, fullname)
            .map(|_| ())
            .map_err(other)
    }
}

/// The SRV target for an instance: `ikigai-plasma.local.`, NEVER `plasma.local.`.
///
/// `plasma.local.` is the machine's OWN mDNS hostname, owned by the operating system's
/// responder, so announcing under it starts a name conflict with the host itself. Measured
/// 2026-09-14 by standing a second responder on the host name and registering our service
/// before the LAN interface was in use: once the LAN interface came in, the loser renamed its
/// host AND its instance (`victim (4)`), and a fresh browser resolved it with only loopback
/// and link-local addresses — plasma's exact symptom, `peer:plasma … no peer is announcing
/// under that name` included. Plasma's own LocalHostName was `plasma-2` when that was
/// measured, which is what macOS does to itself after losing that conflict.
///
/// Still derived from the instance name, so two kernels on one machine (a peer server and a
/// scratch server) do not collide with each other either.
fn host_name(name: &str) -> String {
    format!("ikigai-{name}.local.")
}

/// Keeps one record truthful: re-reads the host's addresses and re-registers whenever the
/// set changes. Synchronous and clock-free on purpose — the watcher thread supplies the
/// cadence, and a test drives [`Announcer::check`] directly.
struct Announcer<S, R> {
    source: S,
    registrar: R,
    name: String,
    host: String,
    fullname: String,
    port: u16,
    props: HashMap<String, String>,
    /// The address set in the registered record, if one is registered.
    advertised: Option<BTreeSet<HostAddr>>,
    /// The last loopback-only set reported as withheld, so it is reported once, not per check.
    withheld: Option<BTreeSet<HostAddr>>,
    last_failure: Option<String>,
}

impl<S: AddressSource, R: Registrar> Announcer<S, R> {
    fn new(source: S, registrar: R, name: &str, port: u16, props: HashMap<String, String>) -> Self {
        Announcer {
            source,
            registrar,
            name: name.to_string(),
            host: host_name(name),
            fullname: format!("{name}.{SERVICE_TYPE}"),
            port,
            props,
            advertised: None,
            withheld: None,
            last_failure: None,
        }
    }

    /// Bring the record in line with the host's addresses, reporting what changed.
    fn check(&mut self) -> Option<AnnounceEvent> {
        let current = match self.source.addresses() {
            Ok(addrs) => addrs,
            Err(e) => return self.failed(format!("could not read this host's addresses: {e}")),
        };

        if !current.iter().any(HostAddr::is_routable) {
            let withdrawn = self.advertised.take().is_some();
            if withdrawn {
                // Best-effort goodbye. The interface it would have gone out on is the one
                // that just lost its address, so a failure here says nothing new.
                let _ = self.registrar.unregister(&self.fullname);
            }
            if withdrawn || self.withheld.as_ref() != Some(&current) {
                let addrs = ranked(&current);
                self.withheld = Some(current);
                return Some(AnnounceEvent::Withheld {
                    name: self.name.clone(),
                    addrs,
                    withdrawn,
                });
            }
            return None;
        }
        self.withheld = None;

        if self.advertised.as_ref() == Some(&current) {
            return None;
        }

        // Re-registering the same fullname REPLACES the record and re-announces it with the
        // cache-flush bit, so a peer drops the old addresses. Unregistering first would send
        // a goodbye, and a peer would briefly (and falsely) hold this kernel as `Withdrawn`.
        let registered = self
            .record(&current)
            .and_then(|record| self.registrar.register(record));
        if let Err(e) = registered {
            // `advertised` is left as it was, so the next check tries again.
            return self.failed(e.to_string());
        }
        self.last_failure = None;

        let addrs = ranked(&current);
        let event = match self.advertised.replace(current) {
            None => AnnounceEvent::Announced {
                name: self.name.clone(),
                addrs,
            },
            Some(previous) => {
                let now = self.advertised.as_ref().unwrap_or(&previous);
                AnnounceEvent::Reannounced {
                    name: self.name.clone(),
                    added: ranked(now.difference(&previous)),
                    removed: ranked(previous.difference(now)),
                    addrs,
                }
            }
        };
        Some(event)
    }

    /// The record itself, with the addresses given EXPLICITLY. `enable_addr_auto` would let
    /// the responder choose them, and then nothing in this process could say — or test —
    /// what a peer is actually being told.
    fn record(&self, addrs: &BTreeSet<HostAddr>) -> io::Result<ServiceInfo> {
        let ips: Vec<IpAddr> = addrs.iter().map(|a| a.ip).collect();
        ServiceInfo::new(
            SERVICE_TYPE,
            &self.name,
            &self.host,
            &ips[..],
            self.port,
            self.props.clone(),
        )
        .map_err(other)
    }

    fn failed(&mut self, error: String) -> Option<AnnounceEvent> {
        if self.last_failure.as_deref() == Some(error.as_str()) {
            return None;
        }
        self.last_failure = Some(error.clone());
        Some(AnnounceEvent::Failed {
            name: self.name.clone(),
            error,
        })
    }

    /// Send the goodbye for a live record.
    fn withdraw(&mut self) {
        if self.advertised.take().is_some() {
            let _ = self.registrar.unregister(&self.fullname);
        }
    }
}

/// A live announcement. Dropping it withdraws the service, so a peer that exits cleanly
/// tells its neighbours rather than leaving them to time it out.
pub struct Announcement {
    daemon: ServiceDaemon,
    fullname: String,
    stop: Arc<AtomicBool>,
    watcher: Option<JoinHandle<()>>,
}

impl Announcement {
    /// The full DNS-SD name this kernel registers under.
    pub fn fullname(&self) -> &str {
        &self.fullname
    }
}

impl Drop for Announcement {
    fn drop(&mut self) {
        // The watcher sends the goodbye on its way out (it owns the record); only then stop
        // the daemon. A peer that vanishes without the goodbye is exactly the
        // `Unknown`-vs-`Withdrawn` distinction the browser has to make.
        self.stop.store(true, Ordering::Relaxed);
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
        let _ = self.daemon.shutdown();
    }
}

/// Announce this kernel under `name` on `port`, carrying `props` as TXT records, reporting
/// what is advertised to stderr. See [`announce_with`].
pub fn announce(name: &str, port: u16, props: &[(&str, &str)]) -> io::Result<Announcement> {
    announce_with(name, port, props, |event| {
        eprintln!("ikigai-discovery: {event}")
    })
}

/// Announce this kernel under `name` on `port`, carrying `props` as TXT records, and hand
/// every [`AnnounceEvent`] to `report` as it happens.
///
/// The first check runs before this returns, so the caller's log shows what was actually
/// advertised (or withheld) at once. After that a watcher thread re-reads the host's
/// addresses every [`ADDRESS_CHECK_INTERVAL`] and re-registers when they change: an agent
/// started at login, before DHCP finished, announces as soon as the LAN has an address, and
/// a new lease or a wake from sleep replaces the old address in the record.
///
/// `Err` only when the responder cannot start at all. A failure to register is reported
/// through `report` and retried; it does not stop a kernel from serving everyone who
/// already knows its address.
pub fn announce_with<F>(
    name: &str,
    port: u16,
    props: &[(&str, &str)],
    report: F,
) -> io::Result<Announcement>
where
    F: Fn(&AnnounceEvent) + Send + 'static,
{
    let daemon = ServiceDaemon::new().map_err(other)?;
    let monitor = daemon.monitor().map_err(other)?;
    let properties: HashMap<String, String> = props
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    let mut announcer = Announcer::new(HostInterfaces, daemon.clone(), name, port, properties);
    let fullname = announcer.fullname.clone();
    if let Some(event) = announcer.check() {
        report(&event);
    }

    // Short slices so dropping the announcement is prompt; the check runs once per interval.
    const SLICE: Duration = Duration::from_millis(250);
    let slices = (ADDRESS_CHECK_INTERVAL.as_millis() / SLICE.as_millis()).max(1);
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = Arc::clone(&stop);
    let watcher = std::thread::Builder::new()
        .name("ikigai-announce".to_string())
        .spawn(move || {
            // One rename is reported once, not once per record type it touched.
            let mut renames: HashSet<(String, String)> = HashSet::new();
            'watch: loop {
                for _ in 0..slices {
                    if stopping.load(Ordering::Relaxed) {
                        break 'watch;
                    }
                    match monitor.recv_timeout(SLICE) {
                        Ok(DaemonEvent::NameChange(change)) => {
                            if renames.insert((change.original.clone(), change.new_name.clone())) {
                                report(&AnnounceEvent::Renamed {
                                    original: change.original,
                                    renamed: change.new_name,
                                    interface: change.intf_name,
                                });
                            }
                        }
                        Ok(DaemonEvent::Error(e)) => report(&AnnounceEvent::Failed {
                            name: announcer.name.clone(),
                            error: e.to_string(),
                        }),
                        Ok(_) => {}
                        // A dead daemon returns at once; do not spin on it.
                        Err(_) if monitor.is_disconnected() => std::thread::sleep(SLICE),
                        Err(_) => {}
                    }
                }
                if let Some(event) = announcer.check() {
                    report(&event);
                }
            }
            announcer.withdraw();
        })?;

    Ok(Announcement {
        daemon,
        fullname,
        stop,
        watcher: Some(watcher),
    })
}

/// A running browse, maintaining a cache of what has been heard.
///
/// Deliberately explicit to start: a background multicast listener is a daemon-ish thing,
/// and "every process that builds a kernel silently starts one" is a pattern this codebase
/// has already been bitten by. Start it when something actually needs peers.
pub struct Browser {
    daemon: ServiceDaemon,
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    /// Everything currently announced, by instance name.
    present: HashMap<String, Peer>,
    /// Peers we watched leave, and when. Distinct from "never heard of".
    withdrawn: HashMap<String, Instant>,
}

impl Browser {
    /// Start browsing. The returned handle owns the listener; drop it to stop.
    pub fn start() -> io::Result<Browser> {
        let daemon = ServiceDaemon::new().map_err(other)?;
        let receiver = daemon.browse(SERVICE_TYPE).map_err(other)?;
        let state = Arc::new(Mutex::new(State::default()));
        let sink = Arc::clone(&state);
        std::thread::spawn(move || {
            while let Ok(event) = receiver.recv() {
                let Ok(mut state) = sink.lock() else { return };
                match event {
                    ServiceEvent::ServiceResolved(service) => {
                        let name = instance_name(&service.fullname);
                        let peer = Peer {
                            name: name.clone(),
                            addrs: service.addresses.iter().map(|a| a.to_ip_addr()).collect(),
                            port: service.port,
                            surface: txt(&service, TXT_SURFACE),
                            ceiling: txt(&service, TXT_CEILING),
                            version: txt(&service, TXT_VERSION),
                            // Filled in by the caller, which knows where certs live.
                            trusted: false,
                        };
                        state.withdrawn.remove(&name);
                        state.present.insert(name, peer);
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        let name = instance_name(&fullname);
                        state.present.remove(&name);
                        // POSITIVE evidence of absence — the whole point of tracking this
                        // separately from "never heard of".
                        // Native-only: mDNS discovery is multicast UDP through `mdns-sd`, which a browser
                        // sandbox does not expose, so this crate has no wasm build. The withdrawal mark
                        // is monotonic on purpose — a positive record of absence must not be aged out or
                        // revived by a wall-clock adjustment.
                        #[allow(clippy::disallowed_methods)]
                        state.withdrawn.insert(name, Instant::now());
                    }
                    _ => {}
                }
            }
        });
        Ok(Browser { daemon, state })
    }

    /// Everything currently announced, name-sorted so output is stable.
    pub fn peers(&self) -> Vec<Peer> {
        let mut peers: Vec<Peer> = self
            .state
            .lock()
            .map(|s| s.present.values().cloned().collect())
            .unwrap_or_default();
        peers.sort_by(|a, b| a.name.cmp(&b.name));
        peers
    }

    /// One peer by announced name, if it is currently announced.
    pub fn peer(&self, name: &str) -> Option<Peer> {
        self.state.lock().ok()?.present.get(name).cloned()
    }

    /// What is known about `name` right now — see [`Presence`], and the module note on why
    /// `Unknown` and `Withdrawn` must not be conflated.
    pub fn presence(&self, name: &str) -> Presence {
        let Ok(state) = self.state.lock() else {
            return Presence::Unknown;
        };
        if state.present.contains_key(name) {
            return Presence::Present;
        }
        match state.withdrawn.get(name) {
            // A FRESH withdrawal is knowledge; a stale one is just an old opinion, and
            // acting on it forever is how a returning peer becomes invisible.
            Some(since) if since.elapsed() < WITHDRAWN_TTL => Presence::Withdrawn,
            _ => Presence::Unknown,
        }
    }

    /// How long ago `name` was seen to leave, if it was.
    pub fn withdrawn_since(&self, name: &str) -> Option<Instant> {
        self.state.lock().ok()?.withdrawn.get(name).copied()
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        let _ = self.daemon.stop_browse(SERVICE_TYPE);
        let _ = self.daemon.shutdown();
    }
}

/// `plasma._ikigai._udp.local.` → `plasma`.
fn instance_name(fullname: &str) -> String {
    fullname
        .strip_suffix(SERVICE_TYPE)
        .unwrap_or(fullname)
        .trim_end_matches('.')
        .to_string()
}

fn txt(service: &mdns_sd::ResolvedService, key: &str) -> Option<String> {
    service
        .txt_properties
        .get_property_val_str(key)
        .map(str::to_string)
}

fn other(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(name: &str) -> Peer {
        Peer {
            name: name.to_string(),
            addrs: vec![],
            port: 4433,
            surface: None,
            ceiling: None,
            version: None,
            trusted: false,
        }
    }

    #[test]
    fn an_instance_name_is_the_fullname_without_the_service_type() {
        assert_eq!(instance_name("plasma._ikigai._udp.local."), "plasma");
        assert_eq!(instance_name("bug._ikigai._udp.local."), "bug");
        // Not one of ours: left alone rather than mangled.
        assert_eq!(instance_name("something-else"), "something-else");
    }

    /// The distinction the whole short-circuit rests on: a peer never heard of is UNKNOWN,
    /// not absent. Skipping a dial on `Unknown` would refuse a peer that is right there —
    /// worse than the wait it saves, because mDNS loses packets routinely.
    #[test]
    // Native-only test in that same multicast crate: it forges withdrawal timestamps
    // to check presence classification.
    #[allow(clippy::disallowed_methods)]
    fn never_heard_of_is_unknown_but_heard_leaving_is_withdrawn() {
        let state = Arc::new(Mutex::new(State::default()));
        let browser = Browser {
            daemon: ServiceDaemon::new().expect("a daemon for the test"),
            state: Arc::clone(&state),
        };
        assert_eq!(
            browser.presence("plasma"),
            Presence::Unknown,
            "silence is not absence"
        );

        state
            .lock()
            .unwrap()
            .present
            .insert("plasma".to_string(), peer("plasma"));
        assert_eq!(browser.presence("plasma"), Presence::Present);

        // Heard leaving — only NOW is absence positive knowledge.
        {
            let mut s = state.lock().unwrap();
            s.present.remove("plasma");
            s.withdrawn.insert("plasma".to_string(), Instant::now());
        }
        assert_eq!(browser.presence("plasma"), Presence::Withdrawn);

        // And a peer that comes back stops being withdrawn.
        {
            let mut s = state.lock().unwrap();
            s.withdrawn.remove("plasma");
            s.present.insert("plasma".to_string(), peer("plasma"));
        }
        assert_eq!(browser.presence("plasma"), Presence::Present);
    }

    /// The address a mount dials must be DETERMINISTIC and routable. mdns-sd returns a
    /// HashSet, so taking `.first()` reported the same peer as `192.168.4.178:4433` and
    /// `[fe80::1]:4433` on consecutive calls — one of which a mount cannot use.
    #[test]
    fn the_dialled_address_prefers_routable_and_is_stable() {
        let mut p = peer("plasma");
        p.addrs = vec![
            "fe80::1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
            "192.168.4.178".parse().unwrap(),
            "::1".parse().unwrap(),
        ];
        assert_eq!(
            p.socket_addr().unwrap().to_string(),
            "192.168.4.178:4433",
            "a routable IPv4 beats link-local and loopback"
        );

        // Same set, different order in — same answer out.
        p.addrs.reverse();
        assert_eq!(p.socket_addr().unwrap().to_string(), "192.168.4.178:4433");

        // With nothing routable, still deterministic rather than arbitrary.
        p.addrs = vec!["fe80::2".parse().unwrap(), "fe80::1".parse().unwrap()];
        assert_eq!(p.socket_addr().unwrap().to_string(), "[fe80::1]:4433");
    }

    /// A withdrawal DECAYS. If it did not, a caller that skips the dial on absence would
    /// skip it FOREVER — and a peer that came back after a network change the browse never
    /// heard would never be used again. Absence is the claim that expires; presence needs
    /// no such rule, because hearing an announcement is positive evidence.
    #[test]
    // Native-only test in that same multicast crate: it forges both a stale and a
    // fresh withdrawal timestamp to check the TTL boundary.
    #[allow(clippy::disallowed_methods)]
    fn a_stale_withdrawal_decays_to_unknown() {
        let state = Arc::new(Mutex::new(State::default()));
        let browser = Browser {
            daemon: ServiceDaemon::new().expect("a daemon for the test"),
            state: Arc::clone(&state),
        };
        state.lock().unwrap().withdrawn.insert(
            "plasma".to_string(),
            Instant::now() - (WITHDRAWN_TTL + std::time::Duration::from_secs(1)),
        );
        assert_eq!(
            browser.presence("plasma"),
            Presence::Unknown,
            "a stale negative must not keep a returning peer out"
        );

        // A recent withdrawal is still knowledge.
        state
            .lock()
            .unwrap()
            .withdrawn
            .insert("plasma".to_string(), Instant::now());
        assert_eq!(browser.presence("plasma"), Presence::Withdrawn);
    }

    #[test]
    fn peers_are_listed_in_a_stable_order() {
        let state = Arc::new(Mutex::new(State::default()));
        let browser = Browser {
            daemon: ServiceDaemon::new().expect("a daemon for the test"),
            state: Arc::clone(&state),
        };
        {
            let mut s = state.lock().unwrap();
            for name in ["plasma", "bug", "edge"] {
                s.present.insert(name.to_string(), peer(name));
            }
        }
        let names: Vec<String> = browser.peers().into_iter().map(|p| p.name).collect();
        assert_eq!(names, vec!["bug", "edge", "plasma"]);
    }

    // ---- announcing: an injected address source and a recording registrar, no multicast ----

    fn addr(interface: &str, ip: &str) -> HostAddr {
        HostAddr {
            interface: interface.to_string(),
            ip: ip.parse().unwrap(),
        }
    }

    /// The host's addresses, as a test changes them.
    #[derive(Clone, Default)]
    struct Addrs(Arc<Mutex<BTreeSet<HostAddr>>>);

    impl Addrs {
        fn set(&self, addrs: &[HostAddr]) {
            *self.0.lock().unwrap() = addrs.iter().cloned().collect();
        }
    }

    impl AddressSource for Addrs {
        fn addresses(&self) -> io::Result<BTreeSet<HostAddr>> {
            Ok(self.0.lock().unwrap().clone())
        }
    }

    #[derive(Debug)]
    enum Op {
        // Boxed: a `ServiceInfo` is ~264 bytes and clippy's large_enum_variant is denied.
        Register(Box<ServiceInfo>),
        Unregister(String),
    }

    /// Every record handed to the responder, in order.
    #[derive(Clone, Default)]
    struct Recorded(Arc<Mutex<Vec<Op>>>);

    impl Recorded {
        fn ops(&self) -> usize {
            self.0.lock().unwrap().len()
        }
        /// The addresses in the most recently registered record.
        fn last_record(&self) -> Option<BTreeSet<IpAddr>> {
            self.0.lock().unwrap().iter().rev().find_map(|op| match op {
                Op::Register(info) => Some(info.get_addresses().iter().copied().collect()),
                Op::Unregister(_) => None,
            })
        }
        fn unregistered(&self) -> bool {
            self.0.lock().unwrap().iter().any(
                |op| matches!(op, Op::Unregister(name) if name == "plasma._ikigai._udp.local."),
            )
        }
    }

    impl Registrar for Recorded {
        fn register(&mut self, record: ServiceInfo) -> io::Result<()> {
            self.0.lock().unwrap().push(Op::Register(Box::new(record)));
            Ok(())
        }
        fn unregister(&mut self, fullname: &str) -> io::Result<()> {
            self.0
                .lock()
                .unwrap()
                .push(Op::Unregister(fullname.to_string()));
            Ok(())
        }
    }

    fn announcer(addrs: &Addrs, recorded: &Recorded) -> Announcer<Addrs, Recorded> {
        Announcer::new(
            addrs.clone(),
            recorded.clone(),
            "plasma",
            4433,
            HashMap::new(),
        )
    }

    /// ★ The field failure (2026-09-14): an agent started at login, before DHCP finished,
    /// with only loopback addressed. The LAN address appears later — and the record a peer
    /// is told about MUST carry it. Before this, plasma logged `announcing as "plasma"` for an
    /// hour while its record said only `127.0.0.1`.
    #[test]
    fn an_address_that_appears_after_startup_is_in_the_record() {
        let addrs = Addrs::default();
        let recorded = Recorded::default();
        addrs.set(&[addr("lo0", "127.0.0.1"), addr("lo0", "fe80::1")]);
        let mut announcer = announcer(&addrs, &recorded);
        announcer.check();

        // DHCP finishes.
        addrs.set(&[
            addr("lo0", "127.0.0.1"),
            addr("lo0", "fe80::1"),
            addr("en0", "192.168.4.178"),
        ]);
        let event = announcer.check();

        let lan: IpAddr = "192.168.4.178".parse().unwrap();
        let record = recorded
            .last_record()
            .expect("a record once a routable address exists");
        assert!(
            record.contains(&lan),
            "the record must carry the LAN address that appeared after startup; it carries {record:?}"
        );
        match event {
            Some(AnnounceEvent::Announced { addrs, .. }) => {
                assert_eq!(
                    addrs[0],
                    addr("en0", "192.168.4.178"),
                    "most dialable first"
                )
            }
            other => panic!("expected Announced, got {other:?}"),
        }
    }

    /// A record whose only addresses are loopback and link-local is one no peer can use, so
    /// it is not registered at all — and the log says so, once, rather than claiming success.
    #[test]
    fn a_loopback_only_announcement_is_withheld_and_said_so_once() {
        let addrs = Addrs::default();
        let recorded = Recorded::default();
        addrs.set(&[addr("lo0", "127.0.0.1"), addr("en0", "fe80::425:1")]);
        let mut announcer = announcer(&addrs, &recorded);

        match announcer.check() {
            Some(AnnounceEvent::Withheld {
                withdrawn: false, ..
            }) => {}
            other => panic!("expected Withheld, got {other:?}"),
        }
        assert_eq!(recorded.ops(), 0, "nothing registered while unreachable");
        assert_eq!(announcer.check(), None, "reported once, not every check");
        assert_eq!(recorded.ops(), 0);
    }

    /// A new lease (plasma went `.91` → `.178` on the day this was written) replaces the
    /// address IN PLACE: re-registered with the new set, no goodbye in between — a goodbye
    /// would make every peer hold this kernel as `Withdrawn` for a moment it was not.
    #[test]
    fn a_changed_lease_is_reannounced_in_place() {
        let addrs = Addrs::default();
        let recorded = Recorded::default();
        addrs.set(&[addr("lo0", "127.0.0.1"), addr("en0", "192.168.4.91")]);
        let mut announcer = announcer(&addrs, &recorded);
        assert!(matches!(
            announcer.check(),
            Some(AnnounceEvent::Announced { .. })
        ));
        assert_eq!(announcer.check(), None, "no change, no re-registration");
        assert_eq!(recorded.ops(), 1);

        addrs.set(&[addr("lo0", "127.0.0.1"), addr("en0", "192.168.4.178")]);
        match announcer.check() {
            Some(AnnounceEvent::Reannounced { added, removed, .. }) => {
                assert_eq!(added, vec![addr("en0", "192.168.4.178")]);
                assert_eq!(removed, vec![addr("en0", "192.168.4.91")]);
            }
            other => panic!("expected Reannounced, got {other:?}"),
        }
        let record = recorded.last_record().unwrap();
        assert!(record.contains(&"192.168.4.178".parse().unwrap()));
        assert!(!record.contains(&"192.168.4.91".parse().unwrap()));
        assert!(!recorded.unregistered(), "no goodbye for a lease change");
    }

    /// When the last routable address goes, the record is withdrawn (a record pointing at an
    /// address this host no longer holds is a lie), and it comes back by itself.
    #[test]
    fn losing_the_network_withdraws_and_regaining_it_reannounces() {
        let addrs = Addrs::default();
        let recorded = Recorded::default();
        addrs.set(&[addr("lo0", "127.0.0.1"), addr("en0", "192.168.4.178")]);
        let mut announcer = announcer(&addrs, &recorded);
        announcer.check();

        addrs.set(&[addr("lo0", "127.0.0.1")]);
        assert!(matches!(
            announcer.check(),
            Some(AnnounceEvent::Withheld {
                withdrawn: true,
                ..
            })
        ));
        assert!(recorded.unregistered());

        addrs.set(&[addr("lo0", "127.0.0.1"), addr("en0", "192.168.4.178")]);
        assert!(matches!(
            announcer.check(),
            Some(AnnounceEvent::Announced { .. })
        ));
    }

    /// A registration that fails is retried on the next check, and the same error is not
    /// logged every five seconds.
    #[test]
    fn a_failed_registration_is_retried_and_reported_once() {
        struct Refuses(Arc<Mutex<usize>>);
        impl Registrar for Refuses {
            fn register(&mut self, _: ServiceInfo) -> io::Result<()> {
                *self.0.lock().unwrap() += 1;
                Err(io::Error::other("responder not ready"))
            }
            fn unregister(&mut self, _: &str) -> io::Result<()> {
                Ok(())
            }
        }
        let attempts = Arc::new(Mutex::new(0));
        let addrs = Addrs::default();
        addrs.set(&[addr("en0", "192.168.4.178")]);
        let mut announcer = Announcer::new(
            addrs,
            Refuses(Arc::clone(&attempts)),
            "plasma",
            4433,
            HashMap::new(),
        );
        assert!(matches!(
            announcer.check(),
            Some(AnnounceEvent::Failed { .. })
        ));
        assert_eq!(announcer.check(), None, "the same error is not repeated");
        assert_eq!(*attempts.lock().unwrap(), 2, "but it IS retried");
    }

    /// The SRV target must not be the machine's own mDNS hostname — see [`host_name`].
    #[test]
    fn the_record_host_is_not_the_machines_own_hostname() {
        assert_eq!(host_name("plasma"), "ikigai-plasma.local.");
        let addrs = Addrs::default();
        let recorded = Recorded::default();
        addrs.set(&[addr("en0", "192.168.4.178")]);
        let mut announcer = announcer(&addrs, &recorded);
        announcer.check();
        let guard = recorded.0.lock().unwrap();
        let Some(Op::Register(info)) = guard.first() else {
            panic!("expected a registration");
        };
        assert_ne!(info.get_hostname(), "plasma.local.");
        assert_eq!(info.get_fullname(), "plasma._ikigai._udp.local.");
    }

    #[test]
    fn routable_means_neither_loopback_nor_link_local() {
        for ip in [
            "192.168.4.178",
            "10.0.0.2",
            "fd4d:3dde:5b1:4894::1",
            "2001:db8::1",
        ] {
            assert!(addr("en0", ip).is_routable(), "{ip} is routable");
        }
        for ip in ["127.0.0.1", "::1", "169.254.3.4", "fe80::1"] {
            assert!(!addr("en0", ip).is_routable(), "{ip} is not");
        }
        assert!(is_apple_p2p("awdl0") && is_apple_p2p("llw0") && !is_apple_p2p("en0"));
    }

    /// A REAL announce + browse over the loopback/LAN multicast group. Ignored by default:
    /// it needs multicast to work in the sandbox CI runs in, and on macOS it can trip the
    /// local-network privacy prompt. Run it by hand:
    ///
    ///     cargo test -p ikigai-discovery -- --ignored --nocapture
    #[test]
    #[ignore]
    // Native-only test in that same multicast crate: it announces on the real network
    // and polls against a monotonic deadline rather than sleeping a fixed guess.
    #[allow(clippy::disallowed_methods)]
    fn announce_and_browse_round_trip() {
        let _announced = announce(
            "discovery-selftest",
            4499,
            &[(TXT_SURFACE, "host + fs + llm"), (TXT_VERSION, "1")],
        )
        .expect("announce");
        let browser = Browser::start().expect("browse");

        // Multicast is not instant; poll rather than sleep a fixed guess.
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        let found = loop {
            if let Some(peer) = browser.peer("discovery-selftest") {
                break Some(peer);
            }
            if Instant::now() > deadline {
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        };

        let peer = found.expect("the announcement should be heard within 10s");
        println!("heard: {peer:?}");
        assert_eq!(peer.port, 4499);
        assert_eq!(peer.surface.as_deref(), Some("host + fs + llm"));
        assert!(
            peer.addrs.iter().any(|ip| address_rank(ip) <= 1),
            "a ROUTABLE address is what a mount on another machine needs; heard {:?}",
            peer.addrs
        );
    }
}
