# The wire hello: version (and mount mode) at connection open

Status: v8, shipping (v6 introduced the hello; v7 and v8 are sections below). Companion
changes in ikigai-python and ikigai-deno.

## The problem

`PROTOCOL_VERSION` was a compile-time constant that never crossed the wire.
Nothing negotiated: a v5 peer meeting a v6 peer failed as garbled postcard —
a codec error, or silently wrong field values — never as "I speak 5, you
speak 6". That was tolerable while client and server shipped in one binary;
it stopped being tolerable the day a second implementation existed
(ikigai-python reverse-engineered the codec and had NOTHING to check against;
its brief's "fail loud naming both versions" was unimplementable).

A second, related blindness: **a mounted peer cannot know its mount mode.**
An alias mount (`--mount urn:py:=…`) strips the prefix before forwarding and
re-prefixes returned entry patterns; an override/prefer mount forwards IRIs
unchanged. A peer whose canonical IRIs already carry a prefix (`urn:py:hello`)
must guess which form to list in `entries` — guess wrong and the mount's
catalog is foreign, so nothing projects (this bit `ikigai mcp --prefer` +
the Python demo within hours of both existing; the `--verbatim` flag is the
workaround). The dialing side KNOWS the mode; it just had nowhere to say it.

## The shape

One principle, two transports, each idiomatic:

### UDS (ikigai-ipc): a hello frame

The first frame in each direction, using the existing u32-BE length framing.
The payload is deliberately NOT postcard (the codec whose version is being
negotiated must not be needed to negotiate it):

    client hello payload:  "IKWH" + u32 BE version + u8 mode [+ future bytes]
    server hello payload:  "IKWH" + u32 BE version           [+ future bytes]

    mode: 0 = verbatim (a plain client, --connect, --override/--prefer:
              IRIs arrive canonical, entries wanted canonical)
          1 = alias    (an alias mount: IRIs arrive prefix-stripped,
              entries wanted prefix-stripped)

Readers parse the prefix they know and IGNORE trailing bytes — that is the
extension mechanism, so future fields never need a new negotiation scheme.
The magic makes the hello self-describing: a first frame that does not start
with "IKWH" is a legacy (≤v5) Call.

Sequence: client sends hello; server answers hello. Versions equal → serve.
Versions differ → the server still answers (so the client can NAME both
versions in its error) and closes; the client errors with
"the kernel server speaks wire v{S}, this client speaks v{C} — update the
older side".

The mode is a HINT. The Rust server ignores it (a served kernel always
speaks canonical IRIs; alias rewriting is client-side in MountedRemote).
ikigai-python uses it to pick the entries form per connection, which retires
the guessing — `--verbatim` remains only as a default for legacy clients.

### QUIC (ikigai-quic): ALPN carries the version

ALPN existed (`ikigai/0`) but never tracked `PROTOCOL_VERSION`. Now the id is
`ikigai/{PROTOCOL_VERSION}`; both ends must agree or the TLS handshake fails
at connect — the QUIC-native version gate, no extra round trip, no new frame.
No mode hint on QUIC yet: today's only prefix-canonical peer (Python) is
UDS-only; add it as a first-stream hello if that changes.

## Rollout: tolerate for one version, loudly

The deployed base (bug, plasma, the ikigai-rs.dev edge, launchd daemons,
emacs-spawned binaries) cannot update atomically, and the drain must not
break overnight. So v6 negotiates DOWN, once, with warnings:

- UDS client: send hello; if the server hangs up on it (a ≤v5 server drops a
  frame it cannot decode, silently), reconnect WITHOUT the hello and warn.
- UDS server: a legacy first frame (no magic) is served as v5, with a warning.
- QUIC client offers [`ikigai/6`, `ikigai/0`]; the server accepts both and
  prefers the versioned id. A connection that negotiates `ikigai/0` warns.

v7 removes all three tolerances: hello required, single ALPN. The warnings
are the pressure to get there.

## v7 (2026-08-08): typed errors, tolerances removed

- **`Reply::ErrorTyped(WireError)`** — the error taxonomy crosses the wire: a
  wire-local, append-only mirror of `ikigai_core::Error` (Unresolved /
  MissingArgument / InvalidArgument / Endpoint / Denied / NotFound / Timeout /
  Unavailable). The client rebuilds the same core variant, so a remote Denied
  stays a permanent denial (Failover must not paper over it), a remote
  Timeout/Unavailable stays TRANSIENT (Failover/Retry may act — "graceful"
  now reaches through the wire), and an HTTP face can answer 403/404/400
  instead of a blanket 502. Wire-local on purpose: a taxonomy addition is a
  WIRE VERSION event for a public ABI with independent implementations, not a
  silent core cascade; core is non_exhaustive and unknown-future variants
  degrade to Endpoint with the message preserved.
- **Tolerances gone**: a UDS first frame without the hello magic is refused
  (not served as v5); a server that hangs up on the hello is diagnosed as
  pre-v6 (a server that is merely SILENT is reported as hung, not ancient);
  QUIC offers and accepts exactly `ikigai/7`.
- v6↔v7 still fails CLEANLY — the hello itself names both versions. Only
  pre-v6 peers fail without explanation, and none remain in this fleet.
- Deployment order: land Rust v7 on main → ship the Python and Deno v7
  mirrors → THEN install binaries and update bug + the edge together.

## v8 (2026-09-28): Conflict, and the first backward-compatible bump

Core 0.1.80 added `Error::Conflict(String)`: well-formed, authorized, the thing exists,
and its CURRENT STATE refuses the request (HTTP 409; permanent). Under v7 it crossed the
wire untyped, as `Endpoint("conflict: …")`, because core is `non_exhaustive` and the map
fell back to `Display`.

- **`WireError::Conflict(String)`, appended** after `Unavailable`, so it is variant
  **8**. The reference vector, pinned byte-exact in all three suites beside Denied's
  `05 04 01 78`: `Reply::ErrorTyped(WireError::Conflict("x"))` is **`05 08 01 78`**.
- **`PROTOCOL_VERSION = 8`, `MIN_PROTOCOL_VERSION = 7`: not a flag day.** v7 was one.
  v8 adds a single error variant, and a flag day would have stopped the plasma↔bug
  federation, gonk, ttt-host and every installed Python/Deno client at once. So a v8
  peer speaks both, and each connection remembers which one it negotiated.
- **The downgrade.** A v8 peer never sends variant 8 to a v7 peer: `Reply::for_peer`
  turns `Conflict(msg)` into `Endpoint("conflict: {msg}")`, byte-identical to what a v7
  server sent (`05 03 0b "conflict: x"`). Every door that encodes a reply for a peer
  goes through it: the IPC server, the QUIC server, and the p2p codec. A v8 CLIENT does
  NOT reconstruct a typed Conflict from a v7 server's `"conflict: "` text; guessing a
  type from a message prefix is not typing.

Two negotiation rules the first draft did not state, found by the Python half and
required for "accepts v7" to be true in practice:

1. **UDS: a server answers an accepted hello with the PEER's version**, not its own. A
   v7 client refuses any answer that is not exactly 7, so answering 8 would refuse
   every installed v7 client. A hello outside 7..=8 is answered with our own version
   (8) and the connection closes, so the client can still name both.
2. **UDS: a v8 client REDIALS once at the server's lower answer.** A v7 server answers
   a v8 hello with 7 and CLOSES — it cannot serve a version it does not speak — so the
   downgrade cannot happen inside that connection. When the answer is lower than the
   offer and still spoken, the client opens a new connection offering it. That is
   per-connection negotiation; nothing persists to the next connection.

**QUIC has no hello; the negotiated ALPN id IS the connection's version.** Both sides
list `ikigai/8` then `ikigai/7`, so a v8 pair settles on 8 and a v7 peer still finds 7.
The server encodes every reply at the negotiated version, and both sides refuse a
connection whose negotiated id names no version they speak. (In practice rustls already
refuses at the handshake with `no_application_protocol`, since QUIC requires ALPN; the
check behind it is defensive. There is no separate hello to disagree with, so "the ALPN
agrees with the hello" reduces to "the ALPN names a spoken version".)

**p2p** offers `/ikigai/wire/8` then `/ikigai/wire/7`; libp2p hands the codec the
negotiated protocol on every response, so the codec is where it downgrades.

**Not changed:** the mDNS TXT `v` record advertises `PROTOCOL_VERSION` (now 8). It
is a hint, as before; nothing in this workspace compares it for equality.

## What this deliberately does not do

- No capability negotiation, no feature flags — version + mode only. The
  manifold already describes capabilities; the hello is transport plumbing.
- No per-frame version tag: the hello covers the connection.
- No mDNS change: TXT already advertises the wire version pre-connect;
  the hello is the enforcement, TXT stays the hint.
