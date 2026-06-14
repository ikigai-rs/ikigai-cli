# ikigai-cli

The `ikigai` command — a REPL client for resource-resolution kernels. It attaches to
a kernel instance over a pluggable transport and lets you issue requests, inspect
self-descriptions, and observe the cache.

This repository carries the transport dependencies, keeping
[`ikigai-core`](https://github.com/ikigai-rs/ikigai-core) lean and WebAssembly-friendly.

## Transports (feature-gated)
| crate | feature | targets |
|-------|---------|---------|
| `transport-embedded` | `embedded` (default) | native + wasm |
| `transport-ipc`      | `ipc`  | native only (shared memory) |
| `transport-quic`     | `quic` | native only (QUIC/HTTP3 + mTLS) |

The WebAssembly build enables only `embedded`; `ipc`/`quic` are gated out by target.

## Local development against a core checkout
Copy `.cargo/config.toml.example` to `.cargo/config.toml` (gitignored) to redirect
the `ikigai-core` dependency to a sibling `../ikigai-core` checkout.

## License
MIT OR Apache-2.0. See `LICENSE-MIT` / `LICENSE-APACHE`. See `ACKNOWLEDGEMENTS.md`.
