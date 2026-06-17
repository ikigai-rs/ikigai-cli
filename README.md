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

By default you attach to an **in-process** kernel. You can also attach to a kernel
running in **another process** over IPC — same REPL, same commands:

```bash
ikigai serve                    # run a kernel server on the default per-user socket
ikigai --connect                # attach the REPL to it
ikigai serve /tmp/k.sock        # …or an explicit socket path, on both sides
ikigai --connect /tmp/k.sock -c 'source urn:fn:toUpper hi'
```

The cache indicator then reflects the *server's* cache, so two clients sharing a
server see each other's `cached` results. The socket lives in a `0700` per-user
directory and is `0600`; the server checks each peer's kernel-verified UID and
refuses other users — no certificates, because the OS already authenticates a
local peer.

Across a **network**, the same `serve` / `--connect` work over QUIC (built with
`--features quic`), authenticated by **mutually-pinned TLS certificates**:

```bash
ikigai cert generate                       # writes server/client certs to your config dir
ikigai serve quic://0.0.0.0:4433           # run a QUIC kernel server
ikigai --connect quic://host:4433          # attach the REPL over QUIC
```

A `quic://host:port` target selects QUIC; a plain path stays a Unix socket. Each
side presents its own self-signed cert and pins the exact peer cert — no CA. On
the same machine both default to the generated certs; to attach from another
machine, copy `client.crt`, `client.key`, and `server.crt` there (or point the
`--server-cert` / `--client-cert` / `--server-key` / `--client-key` flags at
them). The response is the resolved representation's bytes. On an interactive terminal
this is a full-screen [`ratatui`](https://ratatui.rs) REPL — a scrollback
transcript above an input line; when output is piped or `--plain` is passed it
falls back to a line-oriented REPL (handy for scripting). All drive the same
engine, whether the kernel is in-process or across a socket.

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
`config [key=value]` (show settings or save one — see below), `help`, `quit`.
The demo space exercises every input style: `toUpper` / `reverseList` read the
`in` argument; `wrap` reads a differently-named `text` argument; `echo` reads a
`{message}` binding captured from the IRI; `split` turns a comma-list into a
newline list (a list producer for `..` map); `greet` takes two arguments. The
routing follows each endpoint's self-description, so `source urn:demo:wrap hello`
→ `[hello]` lands the input in `text` (not `in`) — and passing a value to `echo`
(`source urn:demo:echo/hi x`) reports that its parameter belongs in the
identifier instead.

**Named arguments.** An endpoint can declare more than one argument. Name one
with `key=value`, where `key` is a declared argument of the target; any other
word is positional and fills the single argument left unnamed (so the one-argument
case above is just the degenerate form). A piped value fills that unnamed argument
too, and `..` can pin some arguments while mapping items into the rest:

```
ikigai> source urn:demo:greet greeting=Hello name=World
Hello, World
ikigai> source urn:demo:greet Hello name=World        # positional fills `greeting`
Hello, World
ikigai> source urn:demo:split "a,b,c" .. urn:demo:greet greeting=Hi   # items fill `name`
Hi, a
Hi, b
Hi, c
```

Because the split is contract-driven, an `=` in ordinary input is harmless when
the key isn't a declared argument (`source urn:fn:toUpper a=b` → `A=B`). If a
positional value is left over with no unnamed argument to take it — or two
arguments are unnamed and only one value is given — `source` says so.

**Pipelines.** `source a [input] | b | c` feeds each stage's output into the next
as its input (the first stage may take a literal input; later stages get the pipe):

```
ikigai> source urn:fn:toUpper hi | urn:demo:wrap
[HI]
```

Each stage is just a `source`, so input is routed to each endpoint's declared
argument — and piping into a binding-only endpoint reports the same helpful error.

**Map.** Where `|` pipes a stage's whole output into the next, `..` maps the next
stage over the output's **newline-separated items**, running it once per item and
rejoining with newlines. That newline-list is the convention `reverseList` and
`split` already speak, so `..` threads a list endpoint through a per-item transform:

```
ikigai> source urn:demo:split "a,b,c" .. urn:fn:toUpper
A
B
C
```

`|` and `..` compose freely — `split "c,b,a" | urn:fn:reverseList .. urn:demo:wrap`
reverses the list as one value, then wraps each item: `[a]` / `[b]` / `[c]`.

**Fork/join.** A stage can be a `( a | b ; c )` fork: each `;`-separated branch is
itself a pipeline, the same input is fanned to all of them, and their outputs are
joined (newline-concatenated, the same list convention):

```
ikigai> source urn:demo:split "a,b,c" | ( urn:fn:toUpper ; urn:fn:reverseList )
A
B
C
c
b
a
```

Forks nest and compose with the connectors: a branch can be multi-stage
(`( urn:fn:reverseList | urn:demo:wrap ; … )`), and `..` can map a whole fork over
each item. At the top level a fork has no incoming value, so each branch takes its
own literal input (`source ( urn:fn:toUpper hi ; urn:demo:wrap there )`).

**Quoting.** Wrap a word in `"…"` to keep an operator — `|`, `..`, `(`, `)`, `;` —
or whitespace literal inside an IRI or input, so it's data rather than structure:

```
ikigai> source urn:fn:toUpper "a | (b ; c)"
A | (B ; C)
```

Inside a quoted span, `\"` is a literal quote and `\\` a literal backslash. (`..`
is an operator only as a whole, unquoted word, so a dotted IRI like `urn:x/../y`
needs no quoting; `|`, `(`, `)`, and `;` split even mid-word, so quote them to use
them literally.) These three operators are parsed by one recursive-descent parser.

**Cache visibility.** Every resolution reports how the kernel's representation
cache served it: `computed` the first time (and cached for next time), `cached`
when it came straight from the cache, or `uncacheable` for a result that opts out
of caching and recomputes each time. A pipeline summarises its stages, so you can
see partial reuse:

```
ikigai> source urn:fn:toUpper hi        (computed)
HI
ikigai> source urn:fn:toUpper hi        (cached)
HI
ikigai> source urn:fn:toUpper hi | urn:demo:wrap   (1 cached · 1 computed)
[HI]
```

In the full-screen TUI the tag is dimmed after the prompt; in the line REPL it
goes to stderr (prefixed `[…]`) so piped stdout stays clean.

To ask *without* resolving, `cache <iri> [args]` reports whether the request is
already in the cache — a read-only probe (it takes the same `<iri> [key=value …]
[input]` as one `source` stage, but no pipelines):

```
ikigai> cache urn:fn:toUpper hi
not cached
ikigai> source urn:fn:toUpper hi
HI
ikigai> cache urn:fn:toUpper hi
cached
```

In the TUI the input line is a real editor with **Emacs / readline keybindings**:

| keys | action |
|------|--------|
| `Ctrl-A` / `Ctrl-E` | start / end of line |
| `Ctrl-F` / `Ctrl-B` (or `←`/`→`) | char forward / back |
| `Alt-F` / `Alt-B` | word forward / back |
| `Ctrl-P` / `Ctrl-N` (or `↑`/`↓`) | history previous / next |
| `Ctrl-K` / `Ctrl-U` | kill to end / start of line |
| `Ctrl-Space`, move, `Alt-W` / `Ctrl-W` | set mark, then **copy** / **cut** the region |
| `Ctrl-W` (no mark) | cut the previous word |
| `Ctrl-Y` | **yank** (paste) the last cut/copied text |
| `Ctrl-D` | delete forward, or exit on an empty line |
| `PgUp` / `PgDn` · `Esc` · `Ctrl-C` | scroll · clear line · exit |

Kill/copy/cut feed a kill buffer that **Ctrl-Y** yanks back; it also flows
through the **system clipboard**, so you can cut in the REPL and paste in another
app (and vice versa). Clipboard access is best-effort via the platform tools
(`pbcopy`/`pbpaste`, `wl-copy`/`xclip`, `clip`/PowerShell); with none present it
falls back to an in-process buffer. Over SSH (or with no tool installed) copies
also go out as an **OSC-52** escape sequence, which sets your *local* terminal's
clipboard rather than the unreachable remote one. The active scheme is shown in
the title.

**`vi` keybindings** are also available — modal editing with an Insert mode (type
text; `Esc` → Normal) and a Normal mode: `h`/`l` (or `←`/`→`), `w`/`b`/`e`, and
`0`/`$` to move; `i`/`a`/`A`/`I` to enter Insert; `x`/`X`/`D`/`C` to delete;
`p`/`P` to paste; `j`/`k` for history. **Operators** compose with motions —
`dw`/`db`/`d$`/`dd` delete, `cw`/`cc` change (then Insert; `cw` stops at the word
end like `ce`), `yw`/`yy` yank — and the title shows the pending operator. A fresh
line starts in Insert (like `set -o vi`). (Counts like `3w` aren't in yet.)

The scheme is configurable — set `keybindings` from inside the REPL with
`config keybindings=vi`, or edit `$XDG_CONFIG_HOME/ikigai-cli/config.toml`
(falling back to `~/.config/ikigai-cli/config.toml`):

```toml
keybindings = "emacs"   # "emacs" (default) · "vi" · "native"
```

`config` with no argument shows the file path and current settings; `config
key=value` validates and saves a property. `native` resolves to the platform's
terminal default, which is Emacs on every supported OS — a terminal can't capture
OS GUI shortcuts (⌘C etc.), so terminal-native editing *is* readline/Emacs. The
demo space is composed in `ikigai-embedded`; a real host binds its own
endpoints there.

## Crates
The engine drives a `Resolver` — the seam in `ikigai-resolve` (`issue` / `is_cached`
/ `entries`) that a kernel implements, local or remote. `ikigai-engine` is the
renderer-agnostic REPL engine over that seam; `ikigai-wire` is the postcard Call/Reply
protocol the remote transports speak. The transports are feature-gated:

| crate | feature | targets |
|-------|---------|---------|
| `ikigai-embedded` | `embedded` (default) | native + wasm |
| `ikigai-ipc`      | `ipc` (default) | Unix only (Unix domain socket) |
| `ikigai-quic`     | `quic` (opt-in) | native (QUIC + mutually-pinned TLS) |

`quic` is opt-in (it pulls quinn/rustls/tokio); the default build is `embedded` +
`ipc`. The WebAssembly build enables only `embedded`; `ipc`/`quic` are gated out
by target.

## Local development against a core checkout
Copy `.cargo/config.toml.example` to `.cargo/config.toml` (gitignored) to redirect
the `ikigai-core` dependency to a sibling `../ikigai-core` checkout.

## License
MIT OR Apache-2.0. See `LICENSE-MIT` / `LICENSE-APACHE`. See `ACKNOWLEDGEMENTS.md`.
