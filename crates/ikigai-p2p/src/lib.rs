//! **SPIKE** — the ikigai wire protocol (v7) over libp2p, so a peer stays reachable when it
//! is not on the LAN: through a circuit relay, upgrading to a direct connection by hole
//! punching (DCUtR) where the networks allow it.
//!
//! Read `docs/design/p2p-mobility-design.md` first. The shape, in three rules:
//!
//! 1. **Transport and reachability only.** A wire `Call` rides one request-response stream
//!    under `WIRE_PROTOCOL` and is answered by `ikigai_quic::dispatch` — the SAME function
//!    the QUIC server calls — so capabilities, the `IssueAs` clamp and the capability-scoped
//!    manifold are unchanged. libp2p's notion of authorization ("you are connected") never
//!    reaches the kernel: an authenticated PeerId is only ever an input to a `PeerMinter`.
//! 2. **One identity table.** A PeerId is enrolled in the same `clients.json` as a
//!    certificate fingerprint, naming a grant the same way. This crate does not read that
//!    file; a host's minter does (`ikigai_embedded::clients::authority`).
//! 3. **The relay is a trust decision.** `RelayPolicy` has no `Default`: the allowlist and
//!    the limits are stated by whoever runs one.
//!
//! Everything is behind the non-default `p2p` feature. Without it this crate is empty — which
//! is also why the names above are code spans rather than doc links: the workspace doc gate
//! builds WITHOUT features, where none of them exist.

#[cfg(feature = "p2p")]
mod transport;

#[cfg(feature = "p2p")]
pub use transport::*;
