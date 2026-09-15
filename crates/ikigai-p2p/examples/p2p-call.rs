//! The calling peer for the off-LAN trial (run it on bug). See
//! `docs/design/p2p-mobility-design.md`.
//!
//! ```text
//! p2p-call --key bug-p2p.key \
//!          --relay /ip4/<edge public IP>/udp/4001/quic-v1/p2p/<relay PeerId> \
//!          --peer <plasma PeerId> \
//!          [--calls 12] [--interval-secs 10] [--iri urn:demo:cal]
//! ```
//!
//! Makes `--calls` wire calls, `--interval-secs` apart, and prints the PATH that carried each
//! one, every connection it saw, and any hole-punch outcome, ending in one `SUMMARY` line.
//! "Connected" is not the result being measured — which path WON is.

use std::time::{Duration, Instant};

use ikigai_core::{Iri, Request, Verb};
use ikigai_p2p::{
    circuit_addr, load_or_generate_keypair, spawn_peer, Multiaddr, Path, PeerConfig, PeerId, Report,
};
use ikigai_wire::{Call, Reply};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn main() -> Result<(), BoxError> {
    let flags = Flags::parse()?;
    let keypair = load_or_generate_keypair(std::path::Path::new(&flags.one("key")?))?;
    let me = keypair.public().to_peer_id();
    // Printed before anything else can fail: this id goes in the relay's `--allow` and the
    // served host's clients.json, so a first run with only `--key` is how an operator learns it.
    println!(
        "this peer: {me}   (enrol it in the served host's clients.json and the relay's --allow)"
    );
    let relay: Multiaddr = flags.one("relay")?.parse()?;
    let peer: PeerId = flags.one("peer")?.parse()?;
    let iri = flags
        .all("iri")
        .pop()
        .unwrap_or_else(|| "urn:demo:cal".to_string());
    let calls: usize = flags.all("calls").pop().map_or(Ok(12), |v| v.parse())?;
    let interval = Duration::from_secs(
        flags
            .all("interval-secs")
            .pop()
            .map_or(Ok(10), |v| v.parse())?,
    );
    let mut listen: Vec<Multiaddr> = flags.parsed("listen")?;
    if listen.is_empty() {
        listen.push("/ip4/0.0.0.0/udp/0/quic-v1".parse()?);
    }
    let through = circuit_addr(&relay, peer);
    println!("dialing: {through}");

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        #[allow(clippy::disallowed_methods)] // a native trial binary stamping stdout for a human; never built for wasm
        fn wall_clock() -> Instant {
            Instant::now()
        }
        let started = wall_clock();
        let stamp = move || format!("+{:>7.1}s", started.elapsed().as_secs_f64());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let handle = spawn_peer(PeerConfig {
            keypair,
            serve: None,
            listen,
            relays: vec![],
            external: vec![],
            confirm_observed_addrs: true,
            reports: Some(tx),
        })?;
        // Connect to the relay FIRST and wait for what it observes: dcutr snapshots its
        // address candidates when the relayed connection is made, so dialing the circuit
        // before this arrives leaves the punch nothing to use. Necessary, not shown sufficient:
        // the spike's loopback punch fails even with this wait (see the design note).
        handle.dial(relay.clone())?;
        let observed = tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(event) = rx.recv().await {
                println!("{} {event:?}", stamp());
                if let Report::Observed { addr, .. } = event {
                    return Some(addr);
                }
            }
            None
        })
        .await;
        match observed {
            Ok(Some(addr)) => println!("{} the relay observes this peer at {addr}", stamp()),
            _ => println!("{} WARNING: no observation from the relay in 15s — a hole punch will have no candidates", stamp()),
        }
        let (mut relayed, mut direct, mut failed) = (0usize, 0usize, 0usize);
        let mut hole_punch = "not attempted".to_string();
        for n in 1..=calls {
            let request = Request::new(Verb::Source, Iri::parse(iri.as_str())?);
            let outcome = handle.call(peer, vec![through.clone()], Call::Issue(request)).await;
            match outcome {
                Ok(answered) => {
                    match answered.path {
                        Some(Path::Relayed) => relayed += 1,
                        Some(Path::Direct) => direct += 1,
                        None => {}
                    }
                    let body = match answered.reply {
                        Reply::Resolved(r, _) => String::from_utf8_lossy(&r.bytes).into_owned(),
                        other => format!("{other:?}"),
                    };
                    println!("{} CALL {n}/{calls} via {:?}: {body}", stamp(), answered.path);
                }
                Err(e) => {
                    failed += 1;
                    println!("{} CALL {n}/{calls} FAILED: {e}", stamp());
                }
            }
            // Print what happened on the network meanwhile, then wait for the next call.
            let deadline = tokio::time::Instant::now() + interval;
            while let Ok(Some(event)) = tokio::time::timeout_at(deadline, rx.recv()).await {
                if let Report::HolePunch { result, .. } = &event {
                    hole_punch = match result {
                        Ok(()) => "succeeded".to_string(),
                        Err(e) => format!("failed ({e})"),
                    };
                }
                println!("{} {event:?}", stamp());
            }
        }
        println!(
            "SUMMARY calls={calls} relayed={relayed} direct={direct} failed={failed} hole_punch={hole_punch}"
        );
        Ok(())
    })
}

/// `--name value` flags, repeatable.
struct Flags(Vec<(String, String)>);

impl Flags {
    fn parse() -> Result<Self, BoxError> {
        let mut args = std::env::args().skip(1);
        let mut pairs = Vec::new();
        while let Some(name) = args.next() {
            let name = name
                .strip_prefix("--")
                .ok_or_else(|| format!("expected --flag, got `{name}`"))?
                .to_string();
            let value = args
                .next()
                .ok_or_else(|| format!("--{name} needs a value"))?;
            pairs.push((name, value));
        }
        Ok(Flags(pairs))
    }
    fn all(&self, name: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .collect()
    }
    fn one(&self, name: &str) -> Result<String, BoxError> {
        self.all(name)
            .pop()
            .ok_or_else(|| format!("--{name} is required").into())
    }
    fn parsed<T: std::str::FromStr>(&self, name: &str) -> Result<Vec<T>, BoxError>
    where
        T::Err: std::error::Error + Send + Sync + 'static,
    {
        self.all(name).iter().map(|v| Ok(v.parse()?)).collect()
    }
}
