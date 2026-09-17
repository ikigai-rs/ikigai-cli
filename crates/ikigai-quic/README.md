# ikigai-quic

The **QUIC transport** for [ikigai](https://crates.io/crates/ikigai-core): a
`Resolver` over QUIC (TLS 1.3), so the `ikigai` REPL can drive a kernel across the
**network** the same way [ikigai-ipc](https://crates.io/crates/ikigai-ipc) drives
one across a local socket. It implements the
[ikigai-resolve](https://crates.io/crates/ikigai-resolve) `Resolver` seam and
carries the [ikigai-wire](https://crates.io/crates/ikigai-wire) `Call`/`Reply`
protocol — one bidirectional QUIC stream per call, the stream boundary framing the
message.

```rust
let id = ikigai_quic::generate();                 // a self-signed Identity

// server — minting a per-connection Session from the authenticated client cert
ikigai_quic::serve(kernel, addr, &id, &[client_cert_pem], minter)?;

// client — a QuicResolver the engine drives like any other Resolver
let resolver = ikigai_quic::connect(addr, &id, &server_cert_pem)?;
```

## Trust: mutual certificate pinning, no CA

Each side is configured with its own self-signed identity (`generate`) and the
**exact peer certificate** it will accept — the client pins the server's cert, and
the server requires and pins the client's. A wrong pin fails the handshake. The
subject name is cosmetic; only the certificate identity is pinned (signature
checking is delegated to the `ring` crypto provider).

## Capability- and tenant-on-the-wire

The mTLS handshake authenticates *which* client cert connected, so `serve` mints a
per-connection `Session` from it:

- **`capability`** bounds every call on the connection; a carried `IssueAs`
  capability is clamped to the session (a peer can only narrow its own authority,
  never widen past the authenticated principal).
- **`file_segment`** transparently roots the connection's `urn:file:` namespace at
  `<segment>/…`, so each tenant addresses files as if its segment were the root and
  never sees another's.

## Two deadlines: patience for work, a bound for self-description

`DEFAULT_IDLE_TIMEOUT` is **five minutes**, because what a connection's idle bound
measures is SILENCE and a resolution is silent while it works — a 70B model loads ~40GB
before its first token, and a bound that cannot tell *hung* from *busy* reports the
wrong thing confidently.

Nothing is ever working during a **self-description**, so those calls run under
`DEFAULT_DESCRIBE_TIMEOUT` (**30s**, `describe.timeout` in the config home) instead: a
`Call::Entries`, and a `Meta` issue — the one `MountedRemote`'s forwarding endpoint
sends to read a peer's contract. Without that split, one silent peer took out
`urn:kernel:catalog` and `urn:kernel:actions` for every kernel that could reach it,
and the manifold is the resource an agent must read before it can do anything at all.

⚠ Enumeration is **transitive**, so the bound is per hop and per-hop bounds do not
compose: three kernels deep, the outer hop cuts off at exactly the moment the inner hop
would have answered with its own degraded catalog. A deep federation raises
`describe.timeout` at the outermost kernel. Carrying a decrementing *budget* on the wire
is the real answer and is a protocol change.

## Build

Native only, opt-in behind the CLI's `quic` feature. Built on **quinn + rustls +
rcgen + tokio**, all on the **`ring`** crypto provider (no cmake/nasm toolchain, so
it builds portably in CI). The async stack is hidden behind the synchronous
`Resolver`, just as the embedded kernel hides its executor.

## License

MIT OR Apache-2.0.
