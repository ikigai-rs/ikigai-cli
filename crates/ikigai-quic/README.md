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

## Build

Native only, opt-in behind the CLI's `quic` feature. Built on **quinn + rustls +
rcgen + tokio**, all on the **`ring`** crypto provider (no cmake/nasm toolchain, so
it builds portably in CI). The async stack is hidden behind the synchronous
`Resolver`, just as the embedded kernel hides its executor.

## License

MIT OR Apache-2.0.
