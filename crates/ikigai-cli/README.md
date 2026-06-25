# ikigai-cli

The `ikigai` **command-line binary** — a REPL client for
[ikigai](https://crates.io/crates/ikigai-core) resource-resolution kernels. Each
line is a request issued against a kernel's address space; the response is the
resolved representation's bytes. It attaches to a kernel over a **pluggable
transport** and lets you issue requests, inspect self-descriptions, observe the
cache, and attenuate capabilities — locally or across a network.

This crate carries the transport and terminal dependencies, keeping
`ikigai-core` lean and WebAssembly-friendly.

```bash
cargo install ikigai-cli            # installs the `ikigai` binary

ikigai                              # full-screen TUI REPL on a terminal
ikigai --plain                      # line REPL (also used automatically when piped)
ikigai -c 'source urn:fn:toUpper hi'  # run a command and exit (repeatable; composes in a shell)
```

## Transports

It chooses a transport by how it attaches; `serve` runs a kernel server and
`--connect` attaches the REPL to one:

| transport | feature | how |
|-----------|---------|-----|
| [embedded](https://crates.io/crates/ikigai-embedded) | `embedded` (default) | kernel runs in-process — native + wasm |
| [ipc](https://crates.io/crates/ikigai-ipc) | `ipc` (default) | `ikigai serve` / `--connect` over a Unix socket (peercred-verified, same user) |
| [quic](https://crates.io/crates/ikigai-quic) | `quic` (opt-in) | `ikigai serve quic://addr` / `--connect quic://host:port` over QUIC with mutually-pinned TLS |

`quic` is opt-in (it pulls quinn/rustls/tokio); the default build is `embedded` +
`ipc`. On wasm the binary builds with only `embedded` and falls back to the line
REPL.

## Architecture

All four modes drive the renderer-agnostic
[ikigai-engine](https://crates.io/crates/ikigai-engine) over the
[ikigai-resolve](https://crates.io/crates/ikigai-resolve) `Resolver` seam — so the
full-screen [`ratatui`](https://ratatui.rs) TUI, the line REPL, and one-shot `-c`
mode all behave identically whether the kernel is in-process or across a wire. The
remote transports speak the [ikigai-wire](https://crates.io/crates/ikigai-wire)
`Call`/`Reply` protocol.

REPL commands: `source`, `describe`, `list`, `cache`, `cap`, `trace`, `config`,
`help`, `quit`. The pipeline grammar (`|` pipe, `..` map, `( ; )` fork/join,
`"…"` quoting), Emacs/vi keybindings, and cache visibility are documented in the
**workspace README**.

## License

MIT OR Apache-2.0. See `LICENSE-MIT` / `LICENSE-APACHE`.
