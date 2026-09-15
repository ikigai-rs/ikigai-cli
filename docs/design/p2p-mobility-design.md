# ikigai mobility over libp2p

**Status:** design note plus a feature-gated spike (`crates/ikigai-p2p`, feature `p2p`), 2026-09-14.
Nothing here is wired into the `ikigai` binary, and nothing is deployed. The off-LAN trial in the
last section has **not been run**.

## What this is for, and what it is not for

**Not for today's instability.** The failures of 2026-09-14 were an mDNS hostname collision (our
bug, fixed in cli #331), a `quic` feature dropped by an install, agents running stale binaries, and
a DHCP lease change. libp2p touches none of those. `libp2p-mdns` would be one more multicast stack
under the same macOS Local Network permission, so it could only add failures of that kind.

**For mobility.** plasma travels, and today bug reaches it only on the LAN. The goal:

> plasma reachable from bug when plasma is off the LAN, through a relay on edge, upgrading to a
> direct connection by hole punching where the networks allow, **with one identity mapping and no
> change to the capability model.**

## libp2p or iroh

Measured on 2026-09-14, on this workspace.

**The QUIC stack.** `libp2p-quic` 0.14 builds on `quinn` 0.11, the line `ikigai-quic` already uses,
so the QUIC *implementation* is shared. The *crypto provider* is not. `libp2p-quic` turns on
quinn's `rustls-aws-lc-rs`, and `libp2p-tls` 0.7 turns on rustls's `aws-lc-rs`. Neither can be
switched off, so the `p2p` feature compiles `aws-lc-sys`, a C library, beside the `ring` that
`ikigai-quic` chose specifically to avoid that toolchain. iroh 1.2 runs `noq`, its own QUIC
implementation, and doubles the whole stack.

**Identity fit.** A libp2p PeerId is a hash of a public key, and the key types include ECDSA P-256,
the type `rcgen` gives our certificates today. An iroh identity is Ed25519 only.

**Relay operations.** Circuit relay v2 is a protocol any libp2p node can run, so the relay is our
own binary on edge. It exposes the hooks this design needs: a fail-closed allowlist on reservations
and on circuit sources, and explicit duration and byte limits. `iroh-relay` is a separate
HTTPS/WebSocket service with its own certificate and DNS needs, and iroh's defaults point at
number0's public relays and discovery, which a deployment would have to turn off. (iroh-relay's
access control was not evaluated in this spike.)

**Churn.** libp2p shipped 0.56 in June 2025 and 0.57 on 2026-09-11: one release in 14 months. But
0.57 is three days old, and every libp2p minor is breaking. iroh shipped about 20 releases in a
year and has been semver-stable only since 1.0 (June 2026).

**Build cost, measured.** Cold `dev` builds, each in a fresh target directory, no compiler cache,
on an 18-core Apple Silicon machine (another satellite's cargo job may have shared the machine):

| Build | Crates compiled | Wall | CPU (user) |
|---|---|---|---|
| `cargo build -p ikigai-quic` (the stack we already ship) | 96 | 5.2 s | 26.6 s |
| `cargo build -p ikigai-p2p --features p2p` | 232 | 14.1 s | 90.7 s |
| `cargo build -p ikigai-p2p` (feature off) | the crate is empty | — | — |

So the feature adds about **136 crates and 64 CPU-seconds** over the QUIC transport, including
`aws-lc-sys`. CPU seconds carry over to a slower machine better than wall time does. Release builds
were not measured. **The default build pays nothing**: nothing in the workspace depends on
`ikigai-p2p`, and without `p2p` it compiles no libp2p. iroh's cost was not measured; that would
take adding it to this workspace.

**Choice for the spike: libp2p.** The relay is ours, its trust controls are hooks we can hold, the
identity model admits our key type, and quinn is shared. The cost is `aws-lc-sys`, and it is real.

## Constraint 1: transport and reachability only

A wire `Call` rides one request-response stream under `/ikigai/wire/7`. The version is
`ikigai_wire::PROTOCOL_VERSION`, pinned by a test, so a mismatched peer fails protocol negotiation
the way a mismatched ALPN fails the QUIC handshake. Framing is the stream itself, as on QUIC: the
writer closes its half after one postcard message, and the reader reads to end under the same
64 MiB bound. An oversized message is **refused**, never truncated.

The server half is not reimplemented. `ikigai_quic::dispatch` is now public, and the p2p transport
answers every authorized call through it: the `IssueAs` clamp, the capability-scoped `Entries`, and
the per-call trace collector are one function behind two doors. libp2p's notion of authorization
("you are connected") never reaches the kernel. An authenticated PeerId is only ever an input to a
minter.

Two deliberate differences from QUIC:

- **Minting is per request, not per connection.** A relayed connection outlives an edit to
  `clients.json` by its whole circuit duration, and a direct one indefinitely. Minting on every call
  keeps "editing the file revokes" true on this door. `tests/grant_table.rs` deletes a PeerId's
  entry while its relayed connection stays up, and the next call is refused.
- **A refusal is a typed `WireError::Denied` reply, not a closed connection.** On QUIC the
  connection *is* the principal, so closing it is the refusal. Here calls are minted one by one,
  and a permanent `Denied` tells a Failover that retrying elsewhere will not help.

## Constraint 2: one identity, one grant table

**Decision: a PeerId is enrolled in the same `clients` map as a certificate fingerprint**, naming a
grant the same way. It is looked up by the same function (`ikigai_embedded::clients::authority`),
under the same fail-closed rules, bounded by the same ceiling:

```json
{
  "clients": {
    "6f1c…64 hex…": { "grant": "calendar-ro", "label": "bug over QUIC" },
    "12D3KooW…":   { "grant": "calendar-ro", "label": "bug over p2p" }
  }
}
```

**Why the fingerprint cannot simply be reused.** `libp2p-tls` generates a **fresh certificate
keypair** every time it builds a TLS config (`certificate.rs`, `KeyPair::generate_for`), then signs
it with the host key in a libp2p extension. The certificate, and therefore its SHA-256 fingerprint,
changes on every process start. The only stable handle on a libp2p peer is its PeerId.

**Option A, enrol beside (chosen).**
*What breaks:* one device holds two entries, one per door, and revoking the device means deleting
both. A label makes the pairing legible to a human, but nothing enforces it. *Follow-up, not built:*
let one entry name both credentials (for example a `peer_id` field in the object form), so one
device is one entry, one grant and one delete. That changes the `clients.json` grammar, which
ikigai-gonk shares, so it is reported up rather than done here.

**Option B, derive the PeerId from the certificate's own key.**
Possible in principle with libp2p's `ecdsa` feature, since both are P-256. Loading an rcgen PKCS#8
key into libp2p was not tried. *What breaks:*
1. It still yields **two keys** in the table. A fingerprint hashes the certificate DER and a PeerId
   hashes the public key. One shared secret is not one table key, unless the table is re-keyed by
   public key, which re-keys every existing entry.
2. **Re-issuing the certificate over the same key** changes the fingerprint but not the PeerId, so
   the two doors disagree about whether this is the same identity.
3. **One secret for two protocols:** a leaked QUIC client key is also a leaked p2p identity, and the
   two cannot be rotated independently.

**Found and fixed on the way.** `clients.rs` normalized every key by stripping colons and
lowercasing, which is right for a hex fingerprint. A PeerId is base58 and case-sensitive, so every
PeerId entry would have become a key no connection can present: fail-closed, but silently inert.
Keys are now folded only when they are 64 hex digits, and anything else is kept verbatim
(`a_peer_id_enrols_beside_a_fingerprint_and_keeps_its_case`).

**Ruled out:**
- A `peers.json` beside `clients.json` (two tables for one concept).
- Relay admission as authority. The relay allowlist decides who may be *reachable*, not what they
  may *do*. `an_unmapped_peer_id_is_denied_and_the_kernel_never_runs` runs a relay that admits a
  stranger, and the kernel still refuses every call without executing anything.

**Open, for the hub.** A QUIC session carries a `file_segment`, derived from a hash of the client
certificate, which names the tenant's on-disk workspace. The spike's p2p sessions use an empty
segment. A real host must decide what a PeerId's segment is. Under option A, one device reaching a
host through both doors would get two workspaces.

## Constraint 3: the relay is a trust decision

`RelayPolicy` has no `Default`, and the trial relay's limits are required flags.

- **Allowlist, fail-closed, both ends.** A closure is added to libp2p's reservation rate limiters
  and another to its circuit-source limiters. A peer not on the list cannot reserve (be reachable)
  or open a circuit (dial through). An empty list relays nothing. Tested by
  `an_empty_relay_allowlist_admits_nobody` and
  `the_relay_refuses_a_reservation_from_a_peer_not_on_its_allowlist`. libp2p's own per-peer and
  per-IP limiters stay in place underneath.
- **Limits, stated.** libp2p's defaults are 2 minutes and **128 KiB** per circuit, 128
  reservations, and 16 circuits. 128 KiB is smaller than one large wire reply (the message bound is
  64 MiB), so a default relay would kill a real call mid-stream. The trial states
  `--max-circuit-secs` and `--max-circuit-bytes`. Reservations are one per peer.
- **An explicit external address.** Reverse-engineered: a libp2p relay with **no confirmed external
  address does not offer the hop protocol at all** (libp2p-relay 0.22, the `Status` switch in
  `behaviour.rs`), so every reservation silently never starts. The spike's first test run failed
  exactly this way. The relay takes `--external` from the operator and never infers it from what a
  peer says it observed.
- **What the relay can see.** A circuit is a byte pipe: the relay copies bytes between the two ends
  (`copy_future.rs`). The two peers run their own security upgrade over that pipe
  (`with_relay_client(tls::Config::new, yamux::Config::default)`): a TLS 1.3 handshake in which each
  side verifies the other's libp2p certificate extension against the expected PeerId
  (`libp2p-tls` `verifier.rs`). The relay therefore forwards ciphertext and cannot impersonate
  either end. It **does** learn who talks to whom, when, for how long, and how many bytes.
  *Evidence level:* source reading, plus tests that authenticate the far PeerId through the relay.
  No packet capture was taken.
- **What stays exposed.** The relay's UDP listener is public, so handshake-level denial of service
  is not addressed by an allowlist that applies after authentication.

Deploying the relay on edge is a separate step, with its runbook in devtools.

## Constraint 4: never two mDNS responders

The `p2p` feature does **not** enable `libp2p-mdns`, and the manifest says why. *Evidence:*
`cargo tree -p ikigai-p2p --features p2p -e normal -i libp2p-mdns` prints nothing (the crate is not
in the resolved graph), and the cold build above never compiles it. It does appear in `Cargo.lock`,
as one of the umbrella's optional dependencies; being listed is not being compiled.

Proposed for later, **not built**: `ikigai-discovery` stays the only LAN responder and gains a TXT
key carrying the PeerId (e.g. `p2p=12D3KooW…`). `peer:plasma` then resolves to a PeerId, its LAN
addresses from mDNS, and a relay circuit address from config. libp2p is handed addresses and never
listens for multicast.

## Constraint 5: the constitution

- **Non-default feature.** Without `p2p` the crate is empty (`src/lib.rs` is two `cfg` lines), so
  the default workspace build compiles no libp2p.
- **CI.** `ci.yml` already passes `features: "*"` to the shared workflow, so the feature, its tests,
  and the three `required-features` examples are linted and tested in CI (9c). No new input was
  needed.
- **Pins.** `libp2p = "0.57.0"` is both floor and ceiling (`<0.58`), and the manifest says so. The
  `ikigai-quic` pin is honest only via the path: see the manifest comment.
- **Lockstep.** `publish = false`. A new member that publishes nothing changes no published version,
  so it forces no bump. The one published-crate change is additive: `ikigai_quic::dispatch` becomes
  `pub`, and `ikigai-embedded`'s key folding changes for non-fingerprint keys only.
- **Lockfile.** `Cargo.lock` gains the umbrella's *optional* crates too (`libp2p-mdns`, `-tcp`,
  `-dns`, `-upnp`, `-metrics`). They are listed, not compiled.

## What the spike proves, and what it cannot

On one machine, over loopback QUIC (`crates/ikigai-p2p/tests/`):

- **Proved:** a peer with **no direct listen address** is reachable only through a relay. A real
  wire call reaches it, resolves under a **narrow** grant, and reports that the path was relayed. A
  carried root capability is clamped (`IssueAs`). The client never holds a direct connection.
- **Proved:** an **unmapped PeerId** gets a typed `Denied` for `Issue`, `IssueAs` and `Entries`, and
  the endpoint's run counter stays at zero.
- **Proved:** the relay refuses a reservation from a peer not on its allowlist.
- **Proved:** a PeerId is authorized by the host's own `clients.json`/`grants.json`, beside a
  fingerprint entry, and deleting the entry revokes it on the next call over a live connection.
- **DCUtR on loopback: attempted, reported, FAILED, cause not established.** Every run reports
  `Failed to hole-punch connection: Inbound stream error: Protocol error` on the client. In
  libp2p-dcutr 0.15 that is `NoAddresses`: the server's hole-punch message carried an **empty**
  candidate list (`protocol/inbound.rs` checks the list as received, before any filtering). All
  later calls stay relayed. This held in three configurations: both peers listening directly with
  identify observations confirmed; the caller also waiting for the relay's observation before
  dialing; and the server also waiting for its own. The machinery runs and reports honestly, but
  **the spike has not shown a hole punch succeed anywhere**, loopback included. The next step is
  libp2p's own `tracing` output for the `libp2p_dcutr` and `libp2p_identify` targets. The Verizon
  trial should still run: the relayed path is the floor of the goal, and it works.
- **Not provable here:** anything about NAT. On loopback there is no NAT, so even a successful punch
  would be trivial. "Works on loopback" is not mobility.

**Reverse-engineered, and worth stating wherever this becomes real:**
1. **DCUtR candidates are a snapshot.** libp2p-dcutr 0.15 takes its address candidates only from
   identify's `NewExternalAddrCandidate` events, not from addresses confirmed with
   `add_external_address`. It copies them when a relayed connection's handler is created. A caller
   that dials the relay and the circuit at the same moment therefore **cannot** hold any
   candidates for that connection. So a caller connects to the relay first and waits for
   identify's observation (`Report::Observed`), and the trial client does. ⚠ **Necessary, not shown
   sufficient:** the loopback punch fails with `NoAddresses` both with and without that wait (see
   "DCUtR on loopback" above), so this is a constraint read from the source, not the explanation
   of the failure the spike saw.
2. **request-response spreads calls across every connection to a peer** (`request_id %
   connections.len()`). After a successful punch, calls **alternate** between the relayed and the
   direct path. The relayed ones still spend the relay's byte budget and die at its duration limit.
   A real transport must close the relayed connection once a direct one exists, or pin calls to the
   direct one. The spike reports the path of every call rather than hiding this.

## Browser peers: later

`libp2p-webrtc` (a separate crate, not an umbrella feature) and `webtransport-websys` are the
path for a browser to be a peer. Neither is built or depended on here.

## The off-LAN trial: exactly what to run

Nothing below touches the installed `ikigai` binary, the live launchd agents, or the real
`clients.json` (the served side takes scratch files). UDP port 4001 must be open inbound on edge.

**1. Build on each machine** (edge, plasma, bug), from an `ikigai-cli` checkout at the merged commit:

```sh
cargo build --release --locked -p ikigai-p2p --features p2p --examples
# binaries: target/release/examples/{p2p-relay,p2p-serve,p2p-call}
```

**2. Mint the identities.** Each binary prints its PeerId as soon as it loads its key, then exits
on the missing flags:

```sh
# edge
target/release/examples/p2p-relay --key ~/p2p-trial/relay.key    # → relay PeerId: <RELAY>
# plasma
target/release/examples/p2p-serve --key ~/p2p-trial/plasma.key   # → this peer: <PLASMA>
# bug
target/release/examples/p2p-call  --key ~/p2p-trial/bug.key      # → this peer: <BUG>
```

**3. edge: run the relay.**

```sh
target/release/examples/p2p-relay --key ~/p2p-trial/relay.key \
  --listen   /ip4/0.0.0.0/udp/4001/quic-v1 \
  --external /ip4/<EDGE_PUBLIC_IP>/udp/4001/quic-v1 \
  --allow <PLASMA> --allow <BUG> \
  --max-circuit-secs 600 --max-circuit-bytes 67108864
```

**4. plasma: enrol bug in a scratch grant table and serve.**

```sh
mkdir -p ~/p2p-trial
echo '{"freebusy": ["urn:cap:demo:freebusy"]}' > ~/p2p-trial/grants.json
echo '{"clients": {"<BUG>": {"grant": "freebusy", "label": "bug over p2p"}}}' > ~/p2p-trial/clients.json
target/release/examples/p2p-serve --key ~/p2p-trial/plasma.key \
  --relay /ip4/<EDGE_PUBLIC_IP>/udp/4001/quic-v1/p2p/<RELAY> \
  --clients ~/p2p-trial/clients.json --grants ~/p2p-trial/grants.json
```

**5. bug: call it.** Run once with plasma on the home LAN as a control, then again with plasma on
the Verizon network:

```sh
target/release/examples/p2p-call --key ~/p2p-trial/bug.key \
  --relay /ip4/<EDGE_PUBLIC_IP>/udp/4001/quic-v1/p2p/<RELAY> \
  --peer <PLASMA> --calls 12 --interval-secs 10
```

**What the output means.** bug prints `the relay observes this peer at …`, one
`CALL n/12 via Some(Relayed|Direct): freebusy` line per call, every `HolePunch` report, and finally:

```text
SUMMARY calls=12 relayed=R direct=D failed=F hole_punch=succeeded|failed (<reason>)|not attempted
```

| Result | Meaning |
|---|---|
| `failed=0`, `relayed>0` | **Mobility goal met at the floor:** plasma reachable off the LAN through edge. |
| `hole_punch=succeeded`, `direct>0` | A direct path also won, for some calls (they alternate; see finding 2). |
| `hole_punch=failed`, `direct=0` | Expected behind carrier-grade NAT: the relay carried everything. |
| `failed>0` | Reachability failed: read the `Failed(...)` reports, and plasma's and edge's logs. |
| a `WARNING: no observation` line | The punch had no candidates, so its failure says nothing about the NAT. |

**Negative check, during the run.** On plasma, replace `clients.json` with `{"clients": {}}`. bug's
next call must print `ErrorTyped(Denied(...))`, and plasma prints `REFUSE <BUG>`.

**Risks for the Verizon leg.** A carrier network may throttle or block UDP to non-standard ports,
and relayed QUIC is still UDP. If every call fails with plasma on Verizon but succeeds on the LAN
control, that is the first thing to test.
