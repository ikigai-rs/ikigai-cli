//! The served peer for the off-LAN trial (run it on plasma). See
//! `docs/design/p2p-mobility-design.md`.
//!
//! ```text
//! p2p-serve --key plasma-p2p.key \
//!           --relay /ip4/<edge public IP>/udp/4001/quic-v1/p2p/<relay PeerId> \
//!           [--listen /ip4/0.0.0.0/udp/0/quic-v1] \
//!           [--clients scratch/clients.json --grants scratch/grants.json]
//! ```
//!
//! Serves a demo kernel — `urn:demo:cal` answers DETAIL under `urn:cap:demo:detail` and
//! freebusy otherwise — so a trial exercises reachability and the grant table without
//! putting anything real on the wire. Each call is authorized by
//! `ikigai_embedded::clients::authority` keyed on the caller's PeerId: the host's own
//! `clients.json`/`grants.json` from the config home, or the scratch files named by
//! `--clients`/`--grants`.

use std::sync::Arc;
use std::time::Instant;

use ikigai_core::{
    Capability, EndpointSpace, Exact, FnEndpoint, Invocation, Kernel, ReprType, Representation,
};
use ikigai_p2p::{
    circuit_addr, load_or_generate_keypair, spawn_peer, Multiaddr, PeerConfig, PeerId, PeerMinter,
};
use ikigai_quic::Session;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn main() -> Result<(), BoxError> {
    let flags = Flags::parse()?;
    // ⚠ Spike-only plumbing: the flags are carried to the grant reader through its existing
    // override variables, set here while the process is still single-threaded (before the
    // runtime exists). A real `serve --p2p` would pass paths, not environment.
    if let Some(clients) = flags.all("clients").pop() {
        std::env::set_var("IKIGAI_CLIENTS", clients);
    }
    if let Some(grants) = flags.all("grants").pop() {
        std::env::set_var("IKIGAI_GRANTS", grants);
    }
    let keypair = load_or_generate_keypair(std::path::Path::new(&flags.one("key")?))?;
    let me = keypair.public().to_peer_id();
    // Printed before anything else can fail: this is the id the relay's `--allow` and the
    // caller's `--peer` need, so a first run with only `--key` is how an operator learns it.
    println!("this peer: {me}");
    let relays: Vec<Multiaddr> = flags.parsed("relay")?;
    if relays.is_empty() {
        return Err("--relay <multiaddr ending in /p2p/<relay PeerId>> is required".into());
    }
    let mut listen: Vec<Multiaddr> = flags.parsed("listen")?;
    if listen.is_empty() {
        listen.push("/ip4/0.0.0.0/udp/0/quic-v1".parse()?);
    }
    println!(
        "grant table: {}",
        ikigai_embedded::clients::clients_path()
            .map_or_else(|| "(none)".to_string(), |p| p.display().to_string())
    );
    for relay in &relays {
        println!("dial me at: {}", circuit_addr(relay, me));
    }

    #[allow(clippy::disallowed_methods)] // a native trial binary stamping stdout for a human; never built for wasm
    fn wall_clock() -> Instant {
        Instant::now()
    }
    let started = wall_clock();
    let minter: PeerMinter = Arc::new(move |peer: &PeerId| {
        let elapsed = started.elapsed().as_secs_f64();
        match ikigai_embedded::clients::authority(&peer.to_base58(), &Capability::root()) {
            Ok((grant, capability)) => {
                println!("+{elapsed:>7.1}s MINT {peer} → grant \"{grant}\"");
                Some(Session {
                    capability,
                    file_segment: String::new(),
                })
            }
            Err(why) => {
                println!("+{elapsed:>7.1}s REFUSE {peer}: {why}");
                None
            }
        }
    });

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let _handle = spawn_peer(PeerConfig {
            keypair,
            serve: Some((Arc::new(demo_kernel()), minter)),
            listen,
            relays,
            external: vec![],
            confirm_observed_addrs: true,
            reports: Some(tx),
        })?;
        while let Some(event) = rx.recv().await {
            println!("+{:>7.1}s {event:?}", started.elapsed().as_secs_f64());
        }
        Ok(())
    })
}

fn demo_kernel() -> Kernel {
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
