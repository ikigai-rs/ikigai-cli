# The wire hello: version (and mount mode) at connection open

Status: v6, shipping. Companion change in ikigai-python.

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

## What this deliberately does not do

- No capability negotiation, no feature flags — version + mode only. The
  manifold already describes capabilities; the hello is transport plumbing.
- No per-frame version tag: the hello covers the connection.
- No mDNS change: TXT already advertises the wire version pre-connect;
  the hello is the enforcement, TXT stays the hint.
