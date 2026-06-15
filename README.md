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
cargo run --bin ikigai -- -c 'source urn:fn:toUpper hello'   # run and exit (one-shot)
```

`-c '<command>'` runs a command non-interactively and exits — repeat it to run
several in order (`-c '…' -c '…'`). Output goes to stdout, errors to stderr, and
the exit code is non-zero if any command failed, so it composes in a shell.

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

Commands: `source <iri> [input]` (SOURCE; `input` is routed to the endpoint's
**declared argument**, discovered from its self-description rather than assumed),
`describe <iri> [type]` (META; `type` defaults to `text/turtle`),
`list` (show the resources bound in the current space, pattern → endpoint),
`help`, `quit`.
So `toUpper` receives `input` as its `in` argument, while `echo` reads a binding
captured from the IRI — pass *that* in the identifier (`source urn:demo:echo/hi`),
and the REPL will say so if you try to pass it as a value.

**Pipelines.** `source a [input] | b | c` feeds each stage's output into the next
as its input (the first stage may take a literal input; later stages get the pipe):

```
ikigai> source urn:fn:toUpper hello | urn:fn:toUpper
HELLO
```

Each stage is just a `source`, so input is routed to each endpoint's declared
argument — and piping into a binding-only endpoint reports the same helpful error.
(A literal `|` inside an IRI or input isn't supported yet; that needs a quoting
parser, which will also bring `..` map and fork/join.)
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
