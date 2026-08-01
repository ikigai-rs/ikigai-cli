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

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

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
    /// The first address, paired with the announced port — what a mount would dial.
    pub fn socket_addr(&self) -> Option<std::net::SocketAddr> {
        self.addrs.first().map(|ip| (*ip, self.port).into())
    }
}

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

/// A live announcement. Dropping it withdraws the service, so a peer that exits cleanly
/// tells its neighbours rather than leaving them to time it out.
pub struct Announcement {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Announcement {
    /// The full DNS-SD name this kernel registered under.
    pub fn fullname(&self) -> &str {
        &self.fullname
    }
}

impl Drop for Announcement {
    fn drop(&mut self) {
        // Best-effort: send the goodbye, then stop the daemon. A peer that vanishes without
        // this is exactly the `Unknown`-vs-`Withdrawn` distinction the browser has to make.
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

/// Announce this kernel under `name` on `port`, carrying `props` as TXT records.
///
/// The host name is derived from `name` so two kernels on one machine (a peer server and a
/// scratch server) don't collide.
pub fn announce(name: &str, port: u16, props: &[(&str, &str)]) -> io::Result<Announcement> {
    let daemon = ServiceDaemon::new().map_err(other)?;
    let properties: HashMap<String, String> = props
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    // `enable_addr_auto` fills in this host's addresses and keeps them current: a hardcoded
    // address is the very thing discovery exists to avoid.
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        name,
        &format!("{name}.local."),
        "",
        port,
        properties,
    )
    .map_err(other)?
    .enable_addr_auto();
    let fullname = info.get_fullname().to_string();
    daemon.register(info).map_err(other)?;
    Ok(Announcement { daemon, fullname })
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
            Presence::Present
        } else if state.withdrawn.contains_key(name) {
            Presence::Withdrawn
        } else {
            Presence::Unknown
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

    /// A REAL announce + browse over the loopback/LAN multicast group. Ignored by default:
    /// it needs multicast to work in the sandbox CI runs in, and on macOS it can trip the
    /// local-network privacy prompt. Run it by hand:
    ///
    ///     cargo test -p ikigai-discovery -- --ignored --nocapture
    #[test]
    #[ignore]
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
        assert!(!peer.addrs.is_empty(), "an address is what a mount needs");
    }
}
