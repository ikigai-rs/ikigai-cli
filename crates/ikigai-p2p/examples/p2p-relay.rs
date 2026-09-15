//! The circuit relay for the off-LAN trial (run it on edge). See
//! `docs/design/p2p-mobility-design.md` for the whole procedure.
//!
//! ```text
//! p2p-relay --key relay.key \
//!           --listen /ip4/0.0.0.0/udp/4001/quic-v1 \
//!           --external /ip4/<edge public IP>/udp/4001/quic-v1 \
//!           --allow <plasma PeerId> --allow <bug PeerId> \
//!           --max-circuit-secs 600 --max-circuit-bytes 67108864
//! ```
//!
//! Every limit is REQUIRED: a public relay is an abuse surface, so its limits are stated by
//! the operator, never defaulted.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use ikigai_p2p::{load_or_generate_keypair, run_relay, Multiaddr, PeerId, RelayAddrs, RelayPolicy};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn main() -> Result<(), BoxError> {
    let flags = Flags::parse()?;
    let keypair = load_or_generate_keypair(std::path::Path::new(&flags.one("key")?))?;
    let relay_id = keypair.public().to_peer_id();
    // Printed before anything else can fail, so a first run that only mints the key still
    // tells the operator the PeerId the peers' `--relay` addresses must end in.
    println!("relay PeerId: {relay_id}");
    let allowed: HashSet<PeerId> = flags
        .all("allow")
        .iter()
        .map(|p| p.parse())
        .collect::<Result<_, _>>()?;
    if allowed.is_empty() {
        return Err(
            "at least one --allow <PeerId> is required: an empty allowlist relays nothing".into(),
        );
    }
    let policy = RelayPolicy {
        allowed,
        max_circuit_duration: Duration::from_secs(flags.one("max-circuit-secs")?.parse()?),
        max_circuit_bytes: flags.one("max-circuit-bytes")?.parse()?,
        max_reservations: 8,
        max_circuits: 16,
    };
    let listen: Vec<Multiaddr> = flags.parsed("listen")?;
    let external: Vec<Multiaddr> = flags.parsed("external")?;
    if external.is_empty() {
        return Err(
            "--external <public multiaddr> is required: a relay with no confirmed \
                    external address offers no reservations at all"
                .into(),
        );
    }
    println!("relay PeerId: {relay_id}");
    for addr in &external {
        println!("peers reach this relay at: {addr}/p2p/{relay_id}");
    }
    println!("policy: {policy:?}");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        #[allow(clippy::disallowed_methods)] // a native trial binary stamping stdout for a human; never built for wasm
        fn wall_clock() -> Instant {
            Instant::now()
        }
        let started = wall_clock();
        let relay = tokio::spawn(run_relay(
            keypair,
            policy,
            RelayAddrs {
                listen,
                external,
                confirm_listen_addrs: false,
            },
            Some(tx),
        ));
        while let Some(event) = rx.recv().await {
            println!("+{:>7.1}s {event:?}", started.elapsed().as_secs_f64());
        }
        relay.await?
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
