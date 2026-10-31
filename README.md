# ikigai-cli

The `ikigai` command — a REPL client for resource-resolution kernels. It attaches to
a kernel instance over a pluggable transport and lets you issue requests, inspect
self-descriptions, and observe the cache.

**New here? Start with [The ikigai Book](https://ikigai-rs.github.io/ikigai-tutorial/)** —
the tutorial walks from resolution to a kernel behind a socket, and its Part III is this
crate's transports, identity and mounts seen from the outside.

This repository carries the transport dependencies, keeping
[`ikigai-core`](https://github.com/ikigai-rs/ikigai-core) lean and WebAssembly-friendly.

## Run it

```bash
cargo run --bin ikigai          # full-screen TUI on a terminal
cargo run --bin ikigai -- --plain   # line REPL (also used automatically when piped)
cargo run --bin ikigai -- --quiet   # line REPL with no greeting, and no prompt on a piped stdin
cargo run --bin ikigai -- -c 'source urn:iki:fn:toUpper hello'   # run and exit (one-shot)
cargo run --bin ikigai -- --daemon  # headless kernel: timers + watchers, no REPL
```

`-c '<command>'` runs a command non-interactively and exits — repeat it to run
several in order (`-c '…' -c '…'`). Output goes to stdout, errors to stderr, and
the exit code is non-zero if any command failed, so it composes in a shell.
A refused `cap` stops the batch immediately, including when it occurs in a stored
script. In either REPL, a refused `cap` blocks further evaluation until a valid
`cap <scope or profile>` or `cap reset`; displaying `cap` alone does not resume it.
A valid narrowing uses the capability held before the refusal. `cap reset` returns
to the session identity, within any sealed ceiling.

A `-c` batch is not quite a REPL session: its non-terminal stdin can feed the first
command that needs a value (a content-less `sink`, or a `source` left with one required
argument), so a bare `source` asks for its target's contract when stdin may hold that value.
A stdin already at its end with nothing (`/dev/null`, a closed empty pipe) holds none, and
no contract is fetched for it. To replay what a person types, feed the lines to
`ikigai --quiet` on its stdin instead: it is the line REPL without the version banner and
the topology lines, and with no prompt when stdin is not a terminal, so its output is the
answers (and their `[cache]` notes on stderr) in order:

```bash
printf 'source urn:iki:fn:toUpper hi\nsource urn:kernel:cache\n' | ikigai --quiet
```

By default you attach to an **in-process** kernel. You can also attach to a kernel
running in **another process** over IPC — same REPL, same commands:

```bash
ikigai serve                    # run a kernel server on the default per-user socket
ikigai --connect                # attach the REPL to it
ikigai serve /tmp/k.sock        # …or an explicit socket path, on both sides
ikigai --connect /tmp/k.sock -c 'source urn:iki:fn:toUpper hi'
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
ikigai> source urn:iki:fn:toUpper resource-oriented computing
RESOURCE-ORIENTED COMPUTING
ikigai> source urn:demo:echo/hello          # {message} captured during resolution
hello
ikigai> describe urn:iki:fn:toUpper         # META → text/turtle self-description
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
the key isn't a declared argument (`source urn:iki:fn:toUpper a=b` → `A=B`). If a
positional value is left over with no unnamed argument to take it — or two
arguments are unnamed and only one value is given — `source` says so. A named
value can be quoted to carry whitespace — `title="Dinner with the Hendersons"`
stays one argument (`\"` and `\\` escape inside the quotes); an undeclared key
or an unterminated quote falls back to ordinary positional input.

**Pipelines.** `source a [input] | b | c` feeds each stage's output into the next
as its input (the first stage may take a literal input; later stages get the pipe):

```
ikigai> source urn:iki:fn:toUpper hi | urn:demo:wrap
[HI]
```

Each stage is just a `source`, so input is routed to each endpoint's declared
argument — and piping into a binding-only endpoint reports the same helpful error.

**Map.** Where `|` pipes a stage's whole output into the next, `..` maps the next
stage over the output's **newline-separated items**, running it once per item and
rejoining with newlines. That newline-list is the convention `reverseList` and
`split` already speak, so `..` threads a list endpoint through a per-item transform:

```
ikigai> source urn:demo:split "a,b,c" .. urn:iki:fn:toUpper
A
B
C
```

`|` and `..` compose freely — `split "c,b,a" | urn:iki:fn:reverseList .. urn:demo:wrap`
reverses the list as one value, then wraps each item: `[a]` / `[b]` / `[c]`.

**Fork/join.** A stage can be a `( a | b ; c )` fork: each `;`-separated branch is
itself a pipeline, the same input is fanned to all of them, and their outputs are
joined (newline-concatenated, the same list convention):

```
ikigai> source urn:demo:split "a,b,c" | ( urn:iki:fn:toUpper ; urn:iki:fn:reverseList )
A
B
C
c
b
a
```

Forks nest and compose with the connectors: a branch can be multi-stage
(`( urn:iki:fn:reverseList | urn:demo:wrap ; … )`), and `..` can map a whole fork over
each item. At the top level a fork has no incoming value, so each branch takes its
own literal input (`source ( urn:iki:fn:toUpper hi ; urn:demo:wrap there )`).

**Quoting.** Wrap a word in `"…"` to keep an operator — `|`, `..`, `(`, `)`, `;` —
or whitespace literal inside an IRI or input, so it's data rather than structure:

```
ikigai> source urn:iki:fn:toUpper "a | (b ; c)"
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
ikigai> source urn:iki:fn:toUpper hi        (computed)
HI
ikigai> source urn:iki:fn:toUpper hi        (cached)
HI
ikigai> source urn:iki:fn:toUpper hi | urn:demo:wrap   (1 cached · 1 computed)
[HI]
```

In the full-screen TUI the tag is dimmed after the prompt; in the line REPL it
goes to stderr (prefixed `[…]`) so piped stdout stays clean.

To ask *without* resolving, `cache <iri> [args]` reports whether the request is
already in the cache — a read-only probe (it takes the same `<iri> [key=value …]
[input]` as one `source` stage, but no pipelines):

```
ikigai> cache urn:iki:fn:toUpper hi
not cached
ikigai> source urn:iki:fn:toUpper hi
HI
ikigai> cache urn:iki:fn:toUpper hi
cached
```

**Why did it resolve that way?** Four views answer the module author's questions, each a
thin face over a kernel resource (so they work the same over `--connect`):

- `explain <iri> [verb] [scopes=a,b] [as=text/turtle]` is a dry run of resolution from
  `urn:kernel:explain` (nothing is invoked): the rewrites that would fire, each space in the
  chain and whether it answers, declines or is **shadowed** by one ahead of it, the door and
  grammar bindings, and the scopes a capability lacks. Beside it, from the live
  `urn:kernel:cached`, whether a read is cached right now. `scopes=` answers for a narrower
  capability (never a wider one); `as-of=` explains inside that temporal corridor.
- `why <iri>` is that name's rows of `urn:kernel:uncached`: why its last computations were not
  stored (`declared`, `dependency <iri>`, `upstream`, …) and how many times.
- `dependents <thread>` is `urn:kernel:dependents`: the live cache entries a cut of that golden
  thread (a resource's IRI, or `urn:kernel:bindings`) would make stale.
- `show <iri> [args]` draws a resource that answers `image/svg+xml` (`urn:diagram:kernel`,
  `urn:diagram:arrangement of=<iri>`): a terminal cannot, so the SVG is written to the temporary
  directory, its path printed, and it is opened with `show.opener` from the config home (the
  platform's opener by default; `none` only writes it).

```
ikigai> explain urn:test:guarded scopes=urn:cap:kernel:inspect
explain source urn:test:guarded
  capability  attenuated to urn:cap:kernel:inspect
  chain       root
  spaces, in the order they are consulted:
    1. root  endpoint-space  answered
  endpoint    guarded (urn:ikigai:endpoint:guarded)
  door        urn:test:guarded (exact)
  bindings    (none)
  requires    urn:cap:test:secret
  denied      yes: the capability lacks urn:cap:test:secret — a real request is refused before the endpoint is entered
  cacheable   decided by the endpoint per answer — …
  cached now  no (for this session's capability, not the `scopes=` one)   (urn:kernel:cached, live)
ikigai> why urn:test:volatile
why urn:test:volatile
  cached now  no   (urn:kernel:cached, live)
  uncached    ×2  declared  [root]
  reasons     declared = the endpoint answered uncacheable; …
```

**Representation cache capacity.** Every host kernel (the embedded host, REPL, daemon,
MCP, and served doors) reads these optional flat keys from the config home's `config.toml`
at startup:

```toml
cache.max_entries = 32_768
cache.max_bytes = 536_870_912
```

Omitting a key keeps its default: **4,096 entries and 64 MiB**. The policy remains LRU;
both bounds apply, so increase both for a large working set. Values are nonnegative whole
numbers of entries or bytes, with optional `_` digit separators; zero sets that bound
to zero. A malformed value, unknown `cache.*` key, or duplicate cache key stops startup
with an error naming the config file. Restart to apply changes. `source urn:kernel:cache`
reports the bounds actually in use; a connected client sees the server's cache.

For feed sizing, the 2026-10-30 scale measurement found about **220 KB and six cache entries
per mapped feed**. Budget room for the rest of the host's working set as well. In that
workload the default cache began thrashing between 300 and 350 feeds: sequential river
reads evicted entries needed next and refetched every origin. A 512 MiB byte bound moved
the measured cliff to about 2,400 feeds, and 1 GiB to about 4,900, with a sufficiently large
entry bound. These are workload measurements, not guaranteed capacities.

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
`config keybindings=vi`, or edit `$XDG_CONFIG_HOME/ikigai/config.toml`
(falling back to `~/.config/ikigai/config.toml` — the one shared config home, the
same file the host reads `mail.*`, `mount` and `scheduler` from).

`--config-home <dir>` names the config home outright, in every mode (REPL, `-c`, `serve`,
`mcp`, `--daemon`, `--connect`, `cert`), so a scratch run needs no environment variable:
`ikigai --config-home ./scratch -c config`. `<dir>` IS the config home (it holds
`config.toml`, `grants.json`, …), and a relative one is made absolute against the working
directory. **The flag wins**: when both it and `XDG_CONFIG_HOME` are set, the environment is
not read for the config home. It moves the config home only; the data home (`~/.ikigai`)
stays put.

```toml
keybindings = "emacs"   # "emacs" (default) · "vi" · "native"
```

`config` with no argument shows the file path and current settings; `config
key=value` validates and saves a property. `native` resolves to the platform's
terminal default, which is Emacs on every supported OS — a terminal can't capture
OS GUI shortcuts (⌘C etc.), so terminal-native editing *is* readline/Emacs. The
demo space is composed in `ikigai-embedded`; a real host binds its own
endpoints there.

## Scripts

A `.iki` file is the lines a person would type, run in order. A line whose first non-blank
character is `#` is a comment, so a shebang is one; `# @param <name>` declares a parameter
(`# @param <name> = <default>` gives it a default), and a line uses it as `{name}`:

```bash
#!/usr/bin/env -S ikigai --quiet --script
# @param who
# @param greeting = hello
source urn:iki:fn:toUpper "{greeting}, {who}"
```

```bash
ikigai greet.iki who=brian            # HELLO, BRIAN
ikigai --script greet who=brian       # the same, for a file of any name
chmod +x greet.iki && ./greet.iki who=brian   # the shebang runs `ikigai --quiet --script`
```

A script stops at its first failing line: it prints `error: line N: …` to stderr and exits
1, and no later line runs. A parameter the script does not declare, or one with no default
that is left out, is refused before any line runs, with exit 2. Flags go before the file;
every word after it is a `name=value` parameter. Answers go to stdout and each line's notes
(`[cache]` and the like) to stderr, as in a `-c` batch; `--quiet` prints only the answers.

In the REPL (or a `-c` batch), `script <iri> [name=value …]` runs a script stored in the
workspace, for example `script urn:file:refresh.iki since=2026-10-01`. The command is
`script`, not `run`: `run` is still the old name of `execute`, which runs a stored plan.

## Hosting layers on the QUIC door

When the config home has a **`layers/` directory**, `ikigai serve quic://…` hosts
[ikigai-layers](https://crates.io/crates/ikigai-layers): independent shared spaces
(`urn:layer:{layer}`), each a channel (append-only messages) or a tuplespace (work taken
atomically, with receipts), with the host-wide `urn:layers:feed`, `urn:layers:participants`
and `urn:collab:{name}`. The config home is the layer host's configuration directory:
`layers/*.toml` with their shapes and contexts, `participants.ttl`, `collabs/*.toml`, and
`enrollment.toml`. Without `layers/` the door is built exactly as before.

```bash
ikigai-layers grants ~/.config/ikigai        # write grants.json + clients.json from the manifests
ikigai serve quic://0.0.0.0:4434 --name layers
```

- **Who writes** is the door's enrollment. `ikigai-layers grants <config home>` writes
  `grants.json` (each participant's `urn:cap:layer:{verb}:{layer}` scopes) and
  `clients.json` (each certificate fingerprint → its grant, with `principal` = the
  participant's IRI). The door mints that principal into each connection's capability, and
  a layer stamps it into every entry, tuple and receipt; a writer that sends an attribution,
  a time or a sequence is refused. Both files are re-read per connection, and the door's
  trust list (`client.crt` and `clients/*.crt` under `--cert-dir`) at every handshake, so a
  manifest edit plus a regenerate, or a participant's new certificate, needs no restart; a new
  or changed layer definition does. A pinned certificate outside its validity window (before its
  `notBefore`, after its `notAfter`) is refused at the handshake. A certificate with no
  `clients.json` entry is refused: a
  `"default"` grant there serves only an enrolled entry that names no grant, so removing an
  entry refuses that client at its next connection (and every token bound to it).
  **A door that hosts layers refuses to start without a `clients.json`**, `--cap` or not: it
  would otherwise fall to the per-client-workspace posture, where no participant has a grant
  and every trusted certificate gets a private filesystem instead.
- **Admission** is the layer host's own call (ikigai-layers 0.2.1+): it validates every write
  against the layer's closed shapes itself, and a layer whose shapes cannot be compiled stops
  the door at start. So the door binds the layer space alone, on a kernel with a clock, and
  offers no participant a `urn:shacl:validate` (an endpoint that declares no capability).
  `urn:layers:me` answers each participant who the door says it is.
- **State location** (entries, tuples, receipts, feeds), first match wins:
  `--layers-state <dir>` on `serve`; `layers.state = "<dir>"` in `config.toml`
  (instance-scoped as `<name>.layers.state`; relative to the config home, a leading `~` to `$HOME`);
  else `~/.ikigai/layers/<name>` under the data home. No environment variable names it. One
  door per state directory: the host holds `<state>/host.lock` while it lives, and a second
  door over the same directory is refused with the holder's pid.
- **Encryption at rest** (ikigai-cli 0.1.67+, ikigai-layers 0.3.0): every file the
  host writes is age ciphertext sealed to the host's key, so the files, a backup of them or an
  image of the disk say nothing without it. The key is an age identity FILE
  (`age-keygen -o layers.key`), named by `--layers-key <file>` on `serve`, else
  `layers.key = "<file>"` in `config.toml` (instance-scoped as `<name>.layers.key`; relative to
  the config home, a leading `~` to `$HOME`). It is **required**: a door that hosts layers and
  names no key refuses to start, a file that is missing or holds no identity is refused naming
  it, and a key that is not this state's is refused before anything is read. No environment
  variable names it, and a path rather than the key itself lets a deployment hand the file over
  from an in-memory credential store (systemd's `LoadCredentialEncrypted`, as
  `--layers-key %d/<credential>`).
- **Legacy plaintext state** (from before 0.1.67) is refused by a door, naming `--layers-reseal`.
  Start the door ONCE with `--layers-reseal` beside the key: it seals every state file in place,
  file by file, then serves. Running it again is safe (it resumes a run that stopped part-way
  and changes nothing over sealed state); later starts leave it off. The same flag rotates the
  key: put the new identity first in the key file and keep the old one after it, start once with
  `--layers-reseal`, then drop the old line. A directory under the state directory that no layer
  definition names is not the host's state, and is neither read nor sealed.
- **Startup banner** names each hosted layer and its model, where the state is and which of the
  three channels chose it, the recipient (`age1…`, the public half) the state is sealed to and which
  channel named the key, and the surface gains `+ layers`. `--layers-state`, `--layers-key` or
  `--layers-reseal` on a door that hosts no layer (no `layers/`, or not a QUIC door) is refused
  rather than ignored.

### The HTTPS front: a participant with only an HTTP client

A door that hosts layers can also serve the participant verbs over HTTPS, for a participant
that has an HTTP client and a JSON parser and nothing else (ikigai-cli 0.1.57+, built with
`--features quic,web`). It is off unless `--layers-https <host:port>` on `serve quic://…`, or
`layers.https` in `config.toml` (instance-scoped as `<name>.layers.https`), names an address:

```bash
ikigai layers-token mint urn:collab:participant:relay --label "relay host"   # prints the token once
ikigai serve quic://0.0.0.0:4434 --name layers --layers-https 0.0.0.0:4435
# the certificate's name is `ikigai`, so a name-checking client is pointed at that name
curl --cacert server.crt --resolve ikigai:4435:<door address> https://ikigai:4435/layers/me \
     -H "Authorization: Bearer $TOKEN"
```

- **One authority, two faces.** The front serves the QUIC door's own kernel and mints each
  request with the QUIC door's own per-identity grants: a participant's layers, admission,
  shapes, refusals and receipts are the same whichever face it uses, and a take raced between
  the two has exactly one winner.
- **A token is bound to ONE enrolled participant**: a `clients.json` entry (its fingerprint, or
  a participant IRI that exactly one entry names), and it mints that entry's grant and
  principal. `ikigai layers-token list` and `revoke <id>` manage them; `layer-tokens.json`
  beside `clients.json` keeps their SHA-256 hashes, never the tokens, and is read on every
  request, so a revocation (or removing the participant's `clients.json` entry, whatever its
  `"default"` says) refuses its next request. No token, or one the file does not hold: `401`.
- **TLS (1.3 or 1.2) with the door's server certificate**, the one a QUIC client pins; an
  HTTPS client pins the same file. ⚠ Its subject name is `ikigai`, not the host's, so a client
  that checks names either connects by that name (`--resolve` above) or pins the certificate
  or its key and skips the name check, as the QUIC client does.
- **GET and POST only**, every answer JSON:

  | method | path | answers |
  | --- | --- | --- |
  | GET | `/layers/me`, `/layers/feed?after=talk:3,tasks:0&wait=` | JSON |
  | GET | `/layer/{layer}/entries`, `/entry/{id}`, `/graph/{slug}`, `/latest?about=` | JSON-LD |
  | GET | `/layer/{layer}/feed?after=&wait=` | JSON (a long poll, `wait` up to 60 s) |
  | GET | `/layer/{layer}/rd` (pending tuples), `?state=taken` (receipts), `?tuple=<iri>` | JSON; one tuple JSON-LD |
  | GET | `/layer/{layer}/receipt/{id}`, `/layer/{layer}/context` | JSON-LD |
  | POST | `/layer/{layer}/say`, `/layer/{layer}/out` (the body: JSON-LD or Turtle) | `{"@id"}` |
  | POST | `/layer/{layer}/take?tuple=<iri>` | the tuple as taken, JSON-LD |
  | GET, POST | `/layer/{layer}/tuples` | the resource's own name: GET is `rd`, POST is `out`, POST with `X-HTTP-Method-Override: DELETE` is `take` |

  **The layout is exact**: a path is the resource's IRI with `:` as `/` (`urn:layer:talk:entry:01m4…`
  is `/layer/talk/entry/01m4…`, `urn:layers:me` is `/layers/me`), the mechanical mapping
  ikigai-web uses, plus the three tuplespace verb names `rd`, `out` and `take` on
  `urn:layer:{layer}:tuples`. Authentication is the one header `Authorization: Bearer <token>`
  on every request. A long poll (`feed?wait=<seconds>`, at most 60) is HELD until an event
  arrives or the wait runs out, and then answers `{"events": []}`; it never answers early with
  nothing (a client whose own timeout is shorter than its `wait` should raise it). There is no
  DELETE: a take is a POST that answers with what it took.

  Query parameters are the resource's own arguments (`as=` picks another face it offers). A
  JSON body with no `@context` is written under the layer's context, so a participant writes
  in the terms it reads back. An error is `{"kind", "message", …}` with its status (`kind` is
  the kernel's error kind): a take that lost a race, or a retried take whose answer was lost,
  is `409 conflict`, and the taker reads its take back with `GET
  /layer/{layer}/rd?state=taken&tuple=<iri>`.

## Mounting peers, and following a layer door

`--mount <prefix>=<target>` (alias), `--override` (the same names, served remotely) and
`--prefer` (an override that falls back to the local binding) compose a remote kernel into
the one this process builds; `<target>` is a Unix socket path, `quic://host:port`, or
`peer:<name>`. Certificate flags (`--cert-dir`, `--client-cert`, …) belong to the mount
they FOLLOW, so two peers never share a certificate set. The config home's `mount` lines
(`mount = "override urn:x:=quic://host:4433 ~/certs/x"`) say the same thing for the whole
machine.

An alias mount at a whole first segment (`--mount urn:quakes:=…`) strips it: the peer
receives `urn:quakes:regions` as `urn:regions`. An alias mount DEEPER than one segment
(`--mount urn:quakes:near:=…`, ledger #2735) forwards the name UNCHANGED: the peer receives
`urn:quakes:near:37.5:137.2` and serves the same name the reader uses. For a name under both,
the deeper mount wins, whatever order they were declared in. The startup banner's line for
such a mount ends `[names forwarded unchanged under <prefix>]`.

**A read through a mount is uncacheable here, whatever the peer declares** (ikigai-cli 0.1.64+, ledger #92, #2613).
A peer endpoint's `cacheable: true` still holds on the peer: it sends `Never` over the wire, and
its own cache answers every read made through the mount, so the endpoint runs once. What changes
is the MOUNTING kernel: it stores no copy of a peer's answer, because a cut on the peer (a
watcher, `urn:kernel:cut`, a write that reaches the peer another way) never crosses back to cut
it here, and a stored copy would be served stale for the life of the process. So every read
through `--mount`, `--override` or `--prefer` costs one round trip to the peer's cache, the cache
note says `[uncacheable]`, and `why <iri>` (`urn:kernel:uncached`) names the mounted read
`declared`: the mount's forwarding endpoint is what declared it. A cacheable local composite over
a mounted read is uncacheable too, named `dependency <the mounted iri>`. Before cli 0.1.64 the
peer's expiry crossed unchanged and a mounted read printed `[computed]`, then `[cached]`, even
after the peer's state had moved on.

```
$ ikigai --plain --mount urn:ts:=/tmp/hello.sock -c 'source urn:ts:hello who=Ada' \
         -c 'source urn:ts:hello who=Ada' -c 'source urn:kernel:uncached'
  urn:ts:hello      ×2  declared  [root]
```

**Nothing mounts under `urn:kernel:`** (ikigai-cli 0.1.62+). Every kernel answers its own
`urn:kernel:*` names itself, ahead of any mount, so a mount, override or prefer under that
prefix would never apply: before 0.1.62 `--override urn:kernel:=quic://door` was accepted and
read THIS kernel's manifold as if it were the door's. It is refused at startup, naming the
prefix. To read another kernel's catalog or action manifold, connect to it:
`ikigai --connect quic://door:4433 -c 'source urn:kernel:actions'`. A broader prefix such as
`urn:` still mounts, and the kernel's own names stay the kernel's.

**A leading `~` in a config-home path** (ikigai-cli 0.1.58+). Every config-home value that
names a path expands a leading `~` to the current user's home by one rule: a `mount` line's
socket and certificate directory (`mount = "prefer urn:x:=~/.ikigai/x.sock"`), `files`,
`layers.state`, `layers.key`, `arrangement`, `browse.root` and `browse.store`, and the `--config-home` and
`--files` flags. Since 0.1.59 the `--mount`/`--override`/`--prefer` flags' targets do too, so
`--mount 'urn:x:=~/x.sock'` works even though no shell expands a `~` that follows `=`. Only `~`
and `~/…` are expanded. Another user's `~name/…`, and any `~` while `HOME` is unset, stop the
start with a message naming the key or flag, rather than becoming a literal path. Before 0.1.58
a `mount` line's socket was dialed as the literal `~/x.sock`, and before 0.1.59 a mount flag's.

**One flag, several prefixes, one connection** (ikigai-cli 0.1.53+). A prefix may be a
comma-separated list: every prefix in it is served through ONE connection with ONE
certificate set. A layer door's names live under three prefixes (`urn:layers:` does not
start with `urn:layer:`), so following one is:

```bash
ikigai --override urn:layer:,urn:layers:,urn:collab:=quic://door.example:4434 \
       --cert-dir ~/.ikigai/layers-client/me -c 'source urn:layers:feed after=talk:0'
```

**A layer door serves only its layers** (the release after 0.1.63). A `serve quic://` whose
config home has `layers/` binds the layers, `urn:layers:*` and `urn:collab:*`, and none of the
general served surface: no host or demo resources, no files, no intake doors, decision links or
passkey endpoints. Every other name resolves nowhere, under every grant. It refuses to start
with a mount or with a ceiling (or an enrolled grant) that would open the calendar, inference or
the governed eval beside the layers; serve those on a door of their own.

**Posting briefs, issues and files** (ledger #1629). A layer whose shapes take them holds an
`ik:Brief` (work, written to be done), an `ik:Issue` (a problem, written to be fixed) and an
`ik:File` (an attachment) beside its messages. `ikigai layers post` composes the entry for you
(every Turtle literal escaped; a file's SHA-256, size, and its bytes as text or base64) and
sends it as `sink urn:layer:{layer}:say`, through whatever routes `urn:layer:` in this process,
so the connection flags come BEFORE `layers`:

```bash
at() { ikigai --override urn:layer:,urn:layers:,urn:collab:=quic://door.example:4434 \
             --cert-dir ~/.ikigai/layers-client/me "$@"; }
at layers post brief talk brief.md --repo ikigai-rs/ikigai-core   # title: its first `# ` heading
at layers post issue talk --title "Crash on start" --severity major < issue.md
at layers post file talk ./trace.log --in-reply-to urn:layer:talk:entry:…
at layers save urn:layer:talk:entry:… ./incoming/                 # size and digest checked
at layers save urn:layer:talk:entry:…                             # no PATH: ~/Downloads
```

Each post prints the IRI the door gave the entry; every kind takes `--in-reply-to ENTRY` and
`--supersedes ENTRY`. A file over the layer's content bound is refused before it is sent, saying how large a file the layer takes.
`save` writes a file entry's bytes only after checking them against its `ik:byteSize` and
`ik:contentHash`: a door checks an entry's shape, never that its digest is true, so this is the
check that matters, and on a mismatch nothing is written and it exits 1. It replaces an existing
file only with `--force`. With no PATH it writes to your downloads directory (`~/Downloads`, else
the XDG download directory or the Windows Downloads folder), never the directory you are in, and
asks for a PATH when there is none. An entry's file name is the poster's choice, so `save`
refuses one that would arm something on your machine (ledger #1748): a name an agent or a shell
loads as configuration (`CLAUDE.md`, `AGENTS.md`, `.mcp.json`, `.envrc`, any `.git` name), any
name beginning with a dot, any `:` (a Windows drive or alternate data stream), a Windows device
name (`CON`, `nul.txt`), and an invisible character. `--as NAME` saves it under a name you chose,
held to the same rules, and `post file` refuses to send such a file, pointing at `--file-name`. Reading one kind needs no subcommand:
`source urn:layer:talk:entries type=https://ikigai-rs.dev/ns#Brief`. The commands, flags and
refusals are the Python participant client's
([ikigai-layers-client](https://github.com/ikigai-rs/ikigai-layers-client): `ikigai-layers post`,
`ikigai-layers save`); `ikigai layers --help` lists them.

The three-flag form (`--override urn:layer:=… --cert-dir D --override urn:layers:=…
--cert-dir D …`) still works; it opens three connections. A comma cannot appear inside a
prefix, and an empty or repeated prefix in a list is refused. ⚠ An older binary reads the
list as ONE prefix that matches nothing, so the names resolve locally (or not at all).

**Describe deadlines.** A peer's self-description (an enumeration, a `describe`) runs
under `describe.timeout` (seconds, default 30, `0` for none). A process that SERVES a door
gives its own mounts two thirds of it, so when a client asks a host about a peer that has
gone silent, the host's deadline fires first and the answer names the peer, rather than the
client's deadline blaming the host.

**Call deadlines** (ikigai-cli 0.1.55+). Every other call to a mounted or `--connect`ed peer
runs under `call.timeout` (seconds, `0` for none), start to finish. Unset, it is the
transport's own silence bound (`quic.timeout`, or the socket's five minutes), so nothing that
used to succeed is cut; what it ends is a peer that accepts a call and never answers it while
keeping the connection alive, or trickles its reply a byte at a time. On expiry the call is
canceled on the wire (QUIC: the stream is stopped; a socket: the connection is dropped) and
the answer is a `timeout` naming the peer. As with describe, a process that serves a door
gives its own mounts two thirds of a configured value. An embedding host passes its own,
per mount (`with_call_timeout`) or per call (`issue_as_within`).

**Dead peers in seconds** (ikigai-cli 0.1.56+). A QUIC client pings a quiet connection every
5 s and declares its peer dead after 15 s of hearing nothing, so a mounted peer that loses
power or its network mid-call is found in seconds instead of at `quic.timeout`. A live peer
working on a long call answers the pings, so the call keeps its whole deadline. ⚠ Upgrade a
door (`serve quic://…`) before its clients: an older door stops acknowledging while it works,
and a newer client then gives up on a call silent for longer than 15 s.

**MCP for a mounted peer.** `ikigai mcp` takes the same mount flags, and `--show <pattern>`
(repeatable) narrows the tool LIST to what matches: a tool name, or, with a `:`, an IRI prefix
the tool is bound under. `ikigai mcp --scope … --override urn:layer:,urn:layers:,urn:collab:=…
--cert-dir … --show urn:layer: --show urn:layers: --show urn:collab:` lists the door's tools
without the local kernel's capability-free ones (`about`, `echo`, `sparql-*`, …). It is
relevance, never authority: the capability still decides what may be called.

## File root

The local file module (`urn:file:*`) is jailed to one directory, first match wins:

1. `--files <dir>`, in any mode that builds a kernel (relative to the working directory;
   refused beside `--connect`, which builds none);
2. `files = "<dir>"` in `config.toml`, instance-scoped as `<name>.files` (relative to the
   config home, a leading `~` to `$HOME`). ⚠ The config home is shared by every process on the
   machine, so an unscoped `files` line moves the daemon's, every door's and the REPL's root;
3. `$IKIGAI_FILES`, kept as a fallback;
4. `~/.ikigai/workspace`.

**A file changed on disk is served fresh, in every mode.** `urn:file:*` reads are cached on a
golden thread, and a filesystem watcher over the file root cuts that thread when a file changes
outside ikigai (an editor, a deploy replacing `foaf.xsl`), so the next read recomputes. The REPL
and `--daemon` have always run it; every `serve` door (IPC, QUIC, `--http`) now starts one per
process, says `watching <dir>` on stderr before its banner, and needs no restart after a
workspace edit. A door whose surface binds no `urn:file:` (the calendar-only QUIC surface)
starts none. Through 0.1.63 the doors ran no watcher and served a replaced file's first-read
bytes until the process restarted.

## Spam filter (`ikigai-bayes`)

The local root binds [`ikigai-bayes`](https://github.com/ikigai-rs/ikigai-bayes), a
SpamBayes-style text classifier, when it is given a state directory and at least one model:

```sh
ikigai --daemon --name edge --bayes-state ~/.ikigai/bayes --bayes-model contact
printf 'buy now' | ikigai -c 'source urn:bayes:contact:score'            # spam / ham / unsure, and why
printf '%s' "$msg" | ikigai -c 'sink urn:bayes:contact:train label=spam'  # or label=ham
```

- `--bayes-state <dir>` (relative to the working directory), else `bayes.state` in `config.toml`
  (instance-scoped as `<name>.bayes.state`; relative to the config home, a leading `~` to
  `$HOME`). `--bayes-model <name>` repeats, else every `bayes.models` line (instance-scoped as
  `<name>.bayes.models`; a line may name several, separated by commas). Both halves or neither:
  with neither nothing is bound; one without the other stops the start.
- Each model is `urn:bayes:<name>:score`, `:train`, `:untrain` and `:stats`, plus
  `urn:bayes:models`. A pipe fills `content`.
- **One process per state directory.** The module holds `<state>/LOCK` for the life of the process,
  so a second process on the same directory stops at startup with the holder's pid. The flags are
  accepted by the REPL and `-c`, `--daemon`, `mcp` and `serve <socket>`, and refused by the served
  doors (`serve quic://…`, `serve --http`) and `--connect`. ⚠ The config home is shared by every
  process on the machine, so prefer the flags on the one unit that holds the model, or the
  `<name>.` keys: unscoped `bayes.*` lines make every REPL try to open it.
- **The state is as sensitive as the messages** (it keeps every trained message's token set). A
  missing directory is created at mode 0700; an existing one that group or others can read is
  reported on stderr.
- Startup prints one line: `ikigai: bayes: contact (N messages: S spam, H ham) — state in <dir>
  (flag)` (not in a `-c` batch or `--quiet`).

**Authority.** Each model's doors declare `urn:cap:bayes:read:<name>` (score, stats) and
`urn:cap:bayes:train:<name>` (train, untrain); `urn:bayes:models` needs none. Nothing grants them
by default: a REPL's root session holds everything, and anything narrower needs the grant. A
reactive space's handler runs under the host's `<config home>/space-authority/<space>` file (one
`urn:cap:` scope per line), so on the edge the contact reactor scores and the block reactor
trains with:

```text
# ~/.config/ikigai/space-authority/contact          (the contact reactor scores)
urn:cap:bayes:read:contact

# ~/.config/ikigai/space-authority/contact-blocks   (a block or not-spam click trains)
urn:cap:space:read:contact
urn:cap:bayes:train:contact
```

Each line is added beside the scopes the file already lists; the file is re-read on every tuple.

**Teaching it from the enquiry email (shadow mode).** The contact handler scores every enquiry and
still mails every one; the subject carries the verdict (`[spam 0.97]`, `[unsure 0.55]`,
`[ham 0.03]`) and the body the strongest clues. Three signed links teach the model, each a GET
that shows a confirm page and a POST that only drops a tuple into `urn:space:contact-blocks`:

| link | minted by (edge daemon) | the click drops | the apply reactor |
|---|---|---|---|
| `/contact-block?email=…&id=…` | `urn:contactblock:link email= enquiry=` | `((block-email …) (enquiry …) (exp …))` | writes the block, trains `spam` |
| `/contact-label?id=…&label=ham` | `urn:contactlabel:link label=ham enquiry=` | `((label "ham") (enquiry …) (exp …))` | trains `ham` |
| `/contact-label?id=…&label=spam` | `urn:contactlabel:link label=spam enquiry=` | `((label "spam") (enquiry …) (exp …))` | trains `spam` |

- **A link names its enquiry, never carries it.** `id` is the enquiry tuple's id in the contact
  space (its content address, `ikigai_intray::tuple_id`); the minter is handed the tuple exactly as
  the reactor handed it to the handler and computes the id. The apply reactor reads the text back
  through the kernel, `source urn:space:contact tuple=<id> state=outbox`, under
  `urn:cap:space:read:contact`: the one-space read grant (`urn:cap:space:read:{name}`, beside the
  broad `urn:cap:space:read`), so it can read that space and no other.
- **One key, two actions.** Both links are signed with `contact-block.key` and minted under
  `urn:cap:contactblock:mint`. Each signed payload starts with its action (`contact-block|…`,
  `contact-label|…`), so a block token never verifies as a label token or the reverse; a "not
  spam" link edited to say `spam` is refused; every bad link answers the same "That link didn't
  work" page. A block link minted before this change (it signed the bare `<email>|<exp>`) still
  blocks for its week, and trains nothing.
- **The public door gains nothing that touches the model.** `urn:contact-label` verifies a link
  and drops a tuple, under the same ceiling as `urn:contact-block` (`urn:cap:space:out`).
  Training is the apply reactor's, under its own authority file.

## HTTP door

`ikigai serve --http <port> --routes <file> --routes-only --cap <scope>…` serves the
kernel over plain HTTP behind a reverse proxy (`crates/ikigai-web`): a route maps a
path to a resource (a `{var}` in it refuses a value carrying `:` `/` `?` `#` `[` `]` `@`,
so one segment cannot reach a deeper resource; `{+var}` opts into carrying them — see
[the route table](crates/ikigai-web/README.md#route-variables-strict-var-raw-var)),
`Accept` becomes the `as=` face, query parameters become named
arguments, and every request resolves under the `--cap` ceiling. Besides the public
intakes (`urn:contact:submit`, `urn:booking:submit` — validated forms that drop a
tuple into a space), the emailed decision links and the passkey ceremony (whose two
endpoints declare `urn:cap:passkey:challenge` and `urn:cap:passkey:register` since the
release after 0.1.63, so a ceiling that serves the ceremony lists both), it carries
**`urn:iki:foaf`**: one FOAF document (`src=`), every face by negotiation — the RDF/XML as
fetched by default, `text/html` through a workspace stylesheet (`urn:file:foaf.xsl`;
`fragment=1` for just `<main>`), `application/ld+json` compacted against a workspace
context, and Turtle / N-Triples / N-Quads / TriG re-serialized (`format=turtle` for a
plain link, since a link has no `Accept`). The source must sit
under a `urn:cap:net:<host>` grant on the unit, so the allowlist is the capability,
not code in the endpoint.

**Per-client rate limits, on by default.** One client (the connection's peer, or, under
`--trust-proxy`, the hop the proxy appended to `X-Forwarded-For`; an IPv6 client counts as its
/64) may reach a limited resource only so often. Past its budget it is answered **`429 Too Many
Requests` with `Retry-After`** (whole seconds until its oldest counted request ages out), and the
resource does not run. The body is a sentence beginning `rate-limited:`, a page for a browser;
`OPTIONS` and `?description` are never counted. The defaults, and the `config.toml` keys that
change them (a bad line stops the door at start-up, naming it):

| key | default | what it does |
|---|---|---|
| `http.rate_limit` | `urn:contact:submit 10/3600`, `urn:booking:submit 10/3600`, `urn:passkey:challenge 30/120` | one line per rule, `"<IRI prefix> <requests>/<seconds>"`; a line replaces the default for its prefix, and `"<IRI prefix> off"` drops it |
| `http.rate_limit_sources` | 4096 | how many client windows the door tracks at once. Emptied windows are reclaimed first; past it a NEW client is refused (`429`), never let through untracked |
| `passkey.max_challenges` | 4096 | passkey challenges outstanding at once (each lives 120 s). Past it a new challenge is refused with a transient error (`503`); none is evicted, so a sign-in already under way still completes. It bounds the challenge store on every door that serves `urn:passkey:challenge` |

The banner names the limits in force (`rate limits per client: …`).

**Large answers stream, and upload routes spill to disk** (ledger #2244). An answer is
written as it is read, framed by `Content-Length` when its length is known and chunked when
it is not, and a `GET` of a seekable body with a strong validator answers byte ranges (`206`,
`416`). On Unix the door installs a file-backed spill under the config home,
`<config home>/spill/http-<port>` (made `0700`, never `TMPDIR`), so an **upload route** takes
a body larger than memory: written to disk as it arrives, hashed while written, and handed to
the Sink as `content=b3:…`. A caller spills only when its capability holds
`urn:cap:stream:spill:<bytes>` (grant it with `--cap`); without one, an upload route takes the
body into memory under `--max-body` like any route. The `config.toml` keys (a bad line stops
the door at start-up, naming it):

| key | default | what it does |
|---|---|---|
| `http.upload` | none | one line per route, `"<path pattern> <largest body in bytes>"`, the route grammar of `--routes` |
| `http.upload_min_rate` | 16384 | bytes a second an upload must keep once its grace has passed; behind it, `408` and the spill removed |
| `http.upload_grace` | 30 | seconds an upload may take before that rate applies |
| `http.spill_ceiling` | 1073741824 | the most one request may spill, whatever its grant |
| `http.spill_total` | 4294967296 | the most every upload in flight may hold at once; past it, `503` |

The banner names the upload routes and the spill directory.

The REPL, a `-c` batch and a script spill too (ledger #2724): on Unix their kernel writes
`| urn:stream:spill` through a file-backed spill under `<config home>/spill/repl-<pid>`,
made `0700` at the first spill (a batch that never spills leaves nothing), and answers the body
as one that can be read again, at most 1 GiB a request. That first spill also removes the
`repl-<pid>` directories processes that have gone left behind. Without a config home the step
is refused as unsupported, as before; it never spills to `TMPDIR`.

> **Renamed in 0.1.20.** This shipped as a bare `urn:foaf` in 0.1.19 — an invented
> top-level namespace rather than one we own. The old name still resolves, through an
> `exact` rule in the host's alias table (`urn:kernel:aliases` lists it), so an existing
> route or link keeps working; because that is a rewrite and not a second binding, both
> spellings share one cache entry and one golden thread. New callers should write
> `urn:iki:foaf`; the catalog advertises only that.

**Outbound HTTP response bodies are bounded.** The native transport shared by the
`urn:http:*`, LLM, and meeting endpoints reads at most 16 MiB of decoded body data
per response by default. Set `http.max_response_bytes = "16777216"` in the host's
`config.toml` to change the byte limit; nonnegative integers allow `_` separators,
zero allows only empty bodies, and an absent or malformed value uses the default.
The setting is read when the kernel's transports are built. A body exactly at the
limit is returned in full; one byte over is refused as `OverBudget`, never returned
as a truncated success. The limit applies to error and redirect bodies too, and to
chunked and compressed responses. HEAD reads no body.

**Outbound HTTP requests name the host.** The same transport sends
`User-Agent: ikigai/<version>` (for example `ikigai/0.2.4`) when a request names no
`User-Agent` of its own. An operator who wants to be identifiable, say to a site that
asks crawlers for a contact, sets `http.user_agent = "feeds-bot/1.0 (+https://example.org/bot)"`
in `config.toml`; it is read when the kernel's transports are built. A blank value, or
one that is not printable ASCII, keeps the default. A `User-Agent` passed in a request's
own `headers` still wins over both.

**Outbound HTTP requests time out.** The same transport gives up on connecting, and on
any single read or write of the socket, after 30 seconds by default, so a server that
accepts the connection and never answers cannot hold a REPL line, a river rebuild or a
scheduled job. Set `http.timeout = 10` in `config.toml` to change the bound; the value is
a whole number of seconds, at least 1, and `_` separators are allowed. A bad value stops
every mode at start-up, naming the key and the file, rather than reading as the default.
A request past the bound is refused as a transient `Timeout`, never as a partial body:
the bytes that arrived before the stall are dropped. The bound is on each wait, not on
the whole exchange, so a large body that keeps arriving is read in full. The LLM
endpoints wait at least 300 seconds (a longer `http.timeout` raises that), because a
non-streamed answer arrives in one piece only after the model has finished.

## Lisp, s-expressions, and signing

The embedded host mounts a family of modules that make **code, queries, and graphs
one substrate** — all addressable as `urn:*` resources, composable with `|`.

**Lisp** ([`ikigai-lisp`](https://github.com/ikigai-rs/ikigai-lisp)) — `urn:lisp:eval`
runs an s-expression whose builtins *are* the kernel verbs. In the REPL a line
starting with `(` evaluates as Lisp; from the command line `-e` evaluates an
expression and `--load <uri>` runs a script:

```bash
ikigai -e '(source "urn:iki:fn:toUpper" "hi")'      # -> HI
ikigai -e '(cacheable (+ 1 2))'                 # opt-in cacheable eval
```

`:lisp` opens a multi-line mode; the TUI has a **Scratch (Lisp) tab** where `F5`
evaluates the buffer.

**The sandbox is an allowlist, the REPL's included.** Since ikigai-lisp 0.2 a program
reaches the world through the kernel verbs and a short list of pure Steel functions,
and nothing else: `display`, `vector-ref`, `string-join`, `when` and `struct` are refused,
and so are `require` and `defmacro`. The REPL gets no wider list on purpose: its
`urn:lisp:eval` is the same door the IPC daemon serves to every client that holds
`urn:cap:lisp`, so a wider evaluator would be a second door to keep off every served
surface. The REPL prints a form's value, so `(+ 1 2)` needs no `display`. A stored
program (`urn:booking:confirm` and the others) serves **Source** only, so it is
invoked with `source`. A `sink` is refused.

**Bounds and a governor, from the config home.** These keys go in `config.toml`. Each is
a whole number of at least 1, and `_` separators are allowed. A bad value, an unknown
`lisp.*` key or a key given twice stops every mode at start-up rather than reading as
the default:

| key | default | what it bounds |
|---|---|---|
| `lisp.timeout` | 300 | seconds any Lisp door this host runs for itself may take: `urn:lisp:eval` and every stored program. Past it the eval is interrupted and the caller gets a transient `Timeout` |
| `lisp.workers` | available parallelism, ≥ 8 | live eval worker threads; past it, a transient `Unavailable` |
| `lisp.worker_stack_bytes` | 128 MiB | each worker's reserved stack. Lower it only with `lisp.max_nesting`: an overflow aborts the process |
| `lisp.max_program_bytes` | 4 MiB | program text |
| `lisp.max_input_bytes` | 16 MiB | `(input)` data |
| `lisp.max_nesting` | 1,000 | nesting in program text, `read` data and values passed to the s-expression compilers |

The 300 s default is set by the longest legitimate handler. The booking handler on its
live host settles in a median of 1 s, takes 5 s on its `urn:llm:ask` path and took 37 s
at worst. `ikigai-llm` has no timeout of its own, and the operator already runs 300
everywhere. The derivation is in `crates/ikigai-embedded/src/lisp.rs`.

A served kernel runs a stranger's program under a separate, tighter budget:
`serve --eval-timeout <s>`, default 10. When that flag is absent it reads `lisp.timeout`.

**S-expressions as an RDF surface** ([`ikigai-sexpr`](https://github.com/ikigai-rs/ikigai-sexpr))
— write queries and graphs *as data*, transrepted on the fly:

```bash
source urn:file:q.sexpr | urn:sparql:from-sexpr | urn:sparql:select  # query -> SPARQL -> run
source urn:file:g.sexpr | urn:rdf:from-sexpr                         # graph -> Turtle
source urn:file:prog.sexpr | urn:sexpr:to-rdf | urn:sexpr:from-rdf   # code <-> graph, losslessly
```

**Signing** ([`ikigai-sign`](https://github.com/ikigai-rs/ikigai-sign)) — sign any
representation, verify it later; the signature is an RDF graph and keys are
resources:

```bash
source urn:file:msg | urn:sign:sign key=urn:file:key.pem   # -> a signature graph
```

Together these are the beginnings of **portable, verifiable code**: encode a
program as a content-addressed graph, sign that graph, and it can be shipped and
checked on the far side.

## Instance names and the daemon

Every process has an **instance name** — `repl`, `serve`, or `daemon` by mode,
or `--name <x>` to override — and configuration can be **scoped to a name**:
a `<name>.key` property applies only to the instance so named. Scoped-only is
deliberate (explicit beats ambient): a kernel server you spin up for something
else never starts a background job just because a config file exists.

`ikigai --daemon` runs the embedded kernel headless — persistent timers and
filesystem watchers stay live, nothing is printed but their output — which is
the shape a LaunchAgent/systemd unit wants.

## Startup jobs

The time transport's registry is in memory. `persistent` exempts a job from cancel-all;
by itself it does not restore the job after a restart. To declare recurring host jobs,
put a `jobs` file in the config home (`--config-home <dir>`, else `$XDG_CONFIG_HOME/ikigai` or `~/.config/ikigai`): one JSON object per line, with blank
lines and whole-line `#` comments allowed. For example:

```json
{"instance":"clock-worker","target":"urn:time:now","method":"Source","every":"1s","scopes":[]}
```

Run `ikigai --daemon --name clock-worker` with that config home. Each fresh start registers
the job again, and the first tick runs after the interval. The daemon, local REPL/`-c`, and
local MCP host read this file; served HTTP/QUIC/IPC surfaces and `--connect` clients do not
run it. Each entry must name the instance that runs it (`--name`, otherwise `daemon`,
`repl`, or `mcp`). Use one running process per worker name to avoid duplicate work.
`source urn:time:jobs` in that local host lists its registrations and run results.

All five fields are required. `method` is `Source`, `Sink`, `Delete`, `Exists`, or `Meta`;
`every` uses the same duration grammar as `urn:time:schedule` (`500ms`, `30s`, `5m`, `2h`,
or seconds without a unit). `target` is an IRI, not a command line. To schedule a pipeline,
bind it as a named request in the host's arrangement and target that name; a REPL can also
use its `names` file. The target and its dependencies must be present in that host's root.
A judge or feed refresh uses the same declaration with its target, method, and interval.

**The operator chooses the job's capability in `scopes`.** Every tick runs with exactly
those scope IRIs, clamped to the registry's ceiling, never the root capability by default.
`[]` grants no capabilities; it suffices for the public clock above. For a protected target,
list the scopes its action and the requests it issues require. The job does not inherit the
REPL's, MCP session's, or another job's grants. No declaration can request the root capability.
The file is trusted host configuration: keep it in the operator-controlled config home,
never in a workspace an untrusted caller can write.

A malformed declaration (including an unknown field, missing scopes, bad method, IRI, or
interval) stops startup with exit 2 and an `ikigai: <path>/jobs:<line>: …` diagnostic.
The entire file is validated, including entries for other instances, before any declared
job is registered. An absent file declares no jobs; other read errors stop startup.

An existing config directory is watched for live edits, including creating, replacing,
or removing `jobs`. Prefer an atomic file replacement when editing. A valid changed file replaces this file's registrations and resets their
timers; removal cancels them. An invalid edit keeps the previous registrations and reports
its line on stderr. Cancellation stops future ticks; a request already running can finish.
These jobs are persistent for cancel-all, and can still be canceled explicitly through the
time transport. Restarting or changing the file registers them again. Run counts, outputs,
and missed ticks are not restored or replayed after a restart.

## Scheduler (how wide the fan-out actually is)

Every host in this workspace — REPL, `serve`, `mcp`, `--daemon` — drives one process
**scheduler**, and it is what makes `( a ; b )` forks and `..` maps run *concurrently*.
The default is `single`, which does not spawn: tasks are polled cooperatively on one
thread, and the native HTTP transport blocks that thread for the length of a call. So at
the default **a ten-branch fan-out is ten sequential calls**, and from outside the process
that is indistinguishable from a slow server (ten concurrent 27B LLM calls measured 17.9s
against one local backend and 49.3s against another).

Set it on the command line, in the config home, or — deprecated — in the environment:

```bash
ikigai --scheduler pool:8            # any mode: repl, serve, mcp, --daemon
ikigai serve --scheduler pool        # `pool` = one worker per available core
```

```toml
# ~/.config/ikigai/config.toml  ($XDG_CONFIG_HOME/ikigai/config.toml when set)
scheduler = "pool:8"
serve.scheduler = "pool:16"   # instance-scoped: this applies to `serve` alone
```

**Precedence: flag > config > env > `single`.** `IKIGAI_SCHEDULER` still works so
already-running services keep their width, but it warns when it is the channel that
decided the value. An invalid *flag* is a hard error — a typo'd `--scheduler pool:xyz`
must not quietly become one-wide — while an invalid config or environment value warns and
falls through to the next channel, so a bad line cannot brick a supervised daemon.

Read it back from the running host, which is the point: `urn:kernel:scheduler` reports the
backend, the worker count, live task counters, **and the channel that set it**.

```
source urn:kernel:scheduler
scheduler
  backend    pool:8
  threads    8
  active     0
  spawned    31
  completed  31
  source     config
```

The TUI's Control tab composes the same rows. `config` inside the REPL shows the
*configured* value (`config scheduler=pool:8` persists it to the same file).

### Routing a fan-out by the width it actually reaches (opt-in)

Backend choice follows load shape. On one machine, against one model, a *single* request
ran ~1.8× better on the serializing backend (53.0 vs 28.9 tok/s) while *ten concurrent*
ones finished in 17.9s against the batching backend and 49.3s against the other. A caller
can declare that with [`ikigai-llm`](https://github.com/ikigai-rs/ikigai-llm)'s
`needs=batchAt<=10` — but the runtime already knows the number: a `..` map or a `( a ; b )`
fork builds its whole request vector before dispatching any of it.

With `--width-routing on` (or `width-routing = "on"` in the config home, instance-scoped as
`<name>.width-routing`), a fan-out appends `needs=batchAt<=W` to its requests, where **W is
the width the run will actually reach** — the request count bounded by the scheduler's
worker count. On the default `single` scheduler that is **1** however many branches there
are, and a width of 1 appends nothing: routing a serialized run to a batching backend is
the ~1.8×-slower direction, so the hint is never emitted on a guess.

It is off by default and it stays out of everyone else's way:

- **Only targets that declare an optional `needs` argument ever see it.** Every other
  request is byte-identical, so its cache key — request id ⊕ capability fingerprint — does
  not move with the width of the construct it happened to be resolved inside. The same
  resource resolved inside a 3-wide map and a 10-wide map is *one* cache entry.
- **Explicit routing wins.** `provider=` first, then `needs=`, then the automatic width
  hint, then the endpoint's configured default. (`ikigai-browse` keys its durable
  explanation archive on model identity; an automatic override of a caller's own choice
  would write width-dependent nondeterminism into a store.)
- **A no-match falls back rather than failing.** `needs=` is a hard filter and a no-match
  is a loud error, so when nothing declares a crossover at or below W the request is
  re-issued without the term. An unrelated failure is *not* retried.

Every fan-out reports itself on stderr, routed or not — the unrouted number is the useful
one, since a ten-branch fork that ran one-wide is invisible from outside the process:

```
$ ikigai -c 'source urn:test:items .. urn:llm:ask'
[10 uncacheable]
[fan-out 10 → 8 wide · needs=batchAt<=8]
```

and `urn:kernel:scheduler` carries `routing` (`by-width`/`off`) and `routing.by`
(`flag`/`config`/`default`) beside the width itself.

## Local root as a declared arrangement

The local kernel's root — which spaces are consulted, in what order, with which doors bound to
which endpoints — is an **arrangement**, and the host can run one from a file instead of the
built-in one. The file is a **declaration**: the same `ik:` graph `urn:kernel:topology` writes,
read back in. It arranges the endpoints the host already has, by name, and never creates one.

```bash
ikigai -c 'source urn:iki:host:arrangement' > root.ttl   # what the host runs today, as a declaration
ikigai --arrangement root.ttl                           # edit it, then start from it
```

```toml
# ~/.config/ikigai/config.toml
arrangement = "root.ttl"                  # relative to the config home
daemon.arrangement = "daemon-root.ttl"    # instance-scoped
```

**Precedence: flag > `<instance>.arrangement` > `arrangement` > the built-in arrangement.** It
applies to the REPL, `-c`, `--daemon`, `mcp` and `serve <socket>`; the served doors (`serve
quic://…`, `serve --http`) never read it, and refuse the flag. The alias table, config-home mounts
and the demo runbook stay layered around the declared root. A declaration that is missing,
malformed or does not build **stops the start** with the reason, naming the node — never a quiet
fall back to the default.

The declaration can also be an **`.arrangement` file**, the same arrangement as an s-expression,
converted to Turtle on the way in losslessly (`ikigai-fs` types the file, `ikigai-sexpr` transrepts
it):

```lisp
;; game.arrangement
(fallback :id "urn:game:root"
  (endpoints (door "urn:host:demo" host-demo))
  (endpoints (door "urn:host:info" host-info)))
```

```bash
ikigai --arrangement game.arrangement
ikigai -c 'source urn:iki:host:arrangement as=text/x-ikigai-arrangement'   # the running root, as one
```

And the arrangement can be **seen**: `urn:diagram:kernel` draws the one you are in as an accessible
SVG (it needs `urn:cap:kernel:inspect`, like `urn:kernel:topology`), and `urn:diagram:arrangement
of=<iri>` draws any declaration by name. Both are bound in the local root only.

⚠ The built-in root's own dump does not start as it stands: `file`, `meeting` and `org-agenda` (and
the `llm-*` backends, with two or more providers) each name two different endpoints, so a door
naming one cannot say which, and the host refuses it. The dump marks them in its header. Every
declaration, in any surface, is bounded — 48 spaces deep, 65,536 nodes and 16 MiB of text once every
reference is expanded — and one past a bound stops the start with exit 2 and a message naming the bound,
never an abort (core 0.1.84, ledger [#643](http://localhost:1060/l/default/item/643)). See
[`docs/declared-arrangement.md`](docs/declared-arrangement.md).

## Consolidated calendar (the embedded host's standing job)

The embedded host wires the [`ikigai-personal`](https://github.com/ikigai-rs/ikigai-personal)
calendar, the [`ikigai-org`](https://github.com/ikigai-rs/ikigai-org) agenda,
and `urn:rdf:diff` into a **derived-calendar pipeline**, configured by
`~/.config/ikigai/calendar.json` (or `$IKIGAI_CALENDAR_CONFIG`):

```json
{ "view": "Brian-Busy", "account": "iCloud",
  "sources": ["Brian", "Bosatsu"], "inbox": "Brian-New",
  "org_dir": "~/Dropbox/org-mode-files", "org_files": ["calendar.org"],
  "repl.derive_every": "300s", "daemon.derive_every": "300s" }
```

- **`urn:view:derive`** — one materialization pass: desired (the org agenda ∪
  each source calendar, over a rolling `today−7d..today+400d` window) minus
  current (the view calendar) via `urn:rdf:diff`; gone/changed events deleted,
  new/changed created. Identity rides as `urn:event:{uid}`, so the pass is
  idempotent and alarms (`:ALERT: 1h 1d` in org → `ik:alert` → `EKAlarm`)
  survive the round-trip.
- **`urn:view:ingest`** — drains the capture-inbox calendar into the first org
  file (heading + `:ID:` drawer + `:ALERT:` line + round-trippable timestamp),
  then deletes the inbox copies; derive runs it first each pass.
- **Freshness** — `<name>.derive_every` registers a persistent timer, and two
  watchers make it event-driven from both directions: the org directory
  (your edits, incl. Dropbox arrivals) and the calendar store (the world's —
  an invitation lands, the view re-derives within seconds).
- A per-source projection (`"project": {"Bosatsu": "busy"}`) renders that
  source as `Busy (Bosatsu)` — titles, locations, and alarms withheld.

macOS note: calendar access is TCC-gated per *hosting* process — terminal
launches prompt normally; a non-bundled binary under launchd may be silently
denied.

## Crates
The engine drives a `Resolver` — the seam in `ikigai-resolve` (`issue` / `is_cached`
/ `entries`) that a kernel implements, local or remote. `ikigai-engine` is the
renderer-agnostic REPL engine over that seam. Both, and `ikigai-intray`, live in their own
repo, [github.com/ikigai-rs/ikigai-engine](https://github.com/ikigai-rs/ikigai-engine), and
this workspace takes them from crates.io. `ikigai-wire` is the postcard Call/Reply
protocol the remote transports speak. The transports are feature-gated:

| crate | `ikigai-cli` feature | targets |
|-------|----------------------|---------|
| `ikigai-embedded` | `embedded` (default) | native (mDNS discovery, SMTP, the filesystem) |
| `ikigai-ipc`      | `ipc` (default) | Unix only (Unix domain socket) |
| `ikigai-quic`     | `quic` (opt-in) | native (QUIC + mutually-pinned TLS) |

`quic` is opt-in (it pulls quinn/rustls/tokio); the default build is `embedded` +
`ipc`. None of the three builds for WebAssembly: `ikigai-embedded` pulls `socket2`
through `mdns-sd` and `lettre`, which has no wasm32 target. The wasm face is
`ikigai-engine` on its own (ikigai-web-demo runs a kernel in a browser through it), and
that repo's CI checks it. Here, CI's `wasm-lib` job checks `ikigai-time`, the member the
same demo runs in the browser.

The modules and pieces the host composes, each published on crates.io from this workspace:

| crate | what it is |
|-------|------------|
| `ikigai-discovery` | announce and find ikigai kernels on the local network over multicast DNS (`--announce`, `peer:<name>` targets, `urn:peer:list`) |
| `ikigai-email` | `urn:email:send`: a capability-gated Sink that submits a message over SMTP, with typed transient/permanent failures |
| `ikigai-intake` | public form intake: parse an untrusted urlencoded/JSON submission, validate it against declared fields, drop it into a tuplespace |
| `ikigai-mcp` | `ikigai mcp`: the capability-scoped manifold projected as an MCP (Model Context Protocol) server |
| `ikigai-passkey` | a minimal single-user WebAuthn (ES256) assertion verifier, the second factor on the edge's decision links |
| `ikigai-scheduler` | the kernel's work scheduler: `single` or a threadpool (`pool`, `pool:N`) that parks rather than blocks on awaits |
| `ikigai-time` | the time transport: originates resource requests on a timer, one-shot or recurring, under the scheduling capability |
| `ikigai-tz` | `urn:tz:convert` (IANA/DST-correct) and `urn:tz:now` (a zoned clock) |
| `ikigai-view` | the org⊕calendar consolidated-view derivation, reconciled entirely through the kernel |

`ikigai-time` is released on its own version line; the rest move in lockstep with the
workspace.

## Local development against a core checkout
Copy `.cargo/config.toml.example` to `.cargo/config.toml` (gitignored) to redirect
the `ikigai-core` dependency to a sibling `../ikigai-core` checkout.

## Accessibility

[ACCESSIBILITY.md](ACCESSIBILITY.md) lists what this repository emits that people read (the HTTP
door's error pages, the embedded host's pages, the REPLs' text), the rules that output follows,
how it is tested and what is not, and how to report a barrier. Read it before changing any of
that output.

## License
MIT OR Apache-2.0. See `LICENSE-MIT` / `LICENSE-APACHE`. See `ACKNOWLEDGEMENTS.md`.
