# ikigai-cli

The `ikigai` command — a REPL client for resource-resolution kernels. It attaches to
a kernel instance over a pluggable transport and lets you issue requests, inspect
self-descriptions, and observe the cache.

This repository carries the transport dependencies, keeping
[`ikigai-core`](https://github.com/ikigai-rs/ikigai-core) lean and WebAssembly-friendly.

## Run it

```bash
cargo run --bin ikigai          # full-screen TUI on a terminal
cargo run --bin ikigai -- --plain   # line REPL (also used automatically when piped)
```

You attach to an in-process kernel and issue one request per line. The response is
the resolved representation's bytes. On an interactive terminal this is a
full-screen [`ratatui`](https://ratatui.rs) REPL — a scrollback transcript above
an input line; when output is piped or `--plain` is passed it falls back to a
line-oriented REPL (handy for scripting). Both drive the same engine.

```
ikigai> source urn:fn:toUpper resource-oriented computing
RESOURCE-ORIENTED COMPUTING
ikigai> source urn:demo:echo/hello          # {message} captured during resolution
hello
ikigai> describe urn:fn:toUpper             # META → text/turtle self-description
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:ikigai:endpoint:toUpper> a ik:Endpoint ;
    ik:id "toUpper" .
```

Commands: `source <iri> [input]` (SOURCE; `input` → the `in` argument),
`describe <iri> [type]` (META; `type` defaults to `text/turtle`), `help`, `quit`.
In the TUI, **↑/↓** recall input history, **PgUp/PgDn** scroll the transcript,
**Esc** clears the line, and **Ctrl-C** / **Ctrl-D** exit. The demo space is
composed in `transport-embedded`; a real host binds its own endpoints there.

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
