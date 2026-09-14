# The durable store on this host — who opens it, and what to do when you are not them

`ikigai-store` gives this host a dataset that survives a restart: `urn:iki:store:select`
/ `ask` / `construct` / `describe` / `info` / `update` / `load`, and whatever is built on
top of it. It is **opt-in twice**, and this page is about the second switch, because the
first question it generates is *"why does my second terminal say the store is not bound?"*

## The rule the whole design hangs on

**RocksDB permits one writer per directory** and enforces it with a `LOCK` file. That is a
property of the storage engine. A second `DurableStore::open` on a held path is refused —
including from the same process — and `Store::open_read_only` is not a way around it: it
succeeds beside a live writer and hands back a **frozen snapshot** that never sees a later
commit. So exactly one process owns the dataset, for as long as it lives, and a second
process reaches the data **over the wire**. That is the ikigai answer and it needs nothing
new: IPC, QUIC and mount-over-wire already exist.

`ikigai-store`'s `docs/design/handle-model.md` has the measurements this was decided on
(`Store::open` is ~5 ms and flat in population; open-per-request was costed and rejected).

## Turning it on

Two switches, both deliberate.

**1. Build with the feature.** The code is behind `store`, like `quic` and `web`:

```sh
cargo install --locked --features store --path crates/ikigai-cli
```

**2. Name the process that holds the dataset**, in `~/.config/ikigai/config.toml`:

```toml
# (a) SOLO — every ikigai process on this machine opens the dataset at startup.
#     Right for one operator with no daemon. The moment two run at once, the second
#     finds the directory held and says so.
store = true
```

```toml
# (b) SERVED — one named instance holds the directory; everything else resolves
#     through its socket. This is the topology of record, and the same shape
#     `serve.browse.root` already uses for the browse archive.
serve.store = true
mount = "prefer urn:iki:store:=/Users/you/.ikigai/serve.sock"
```

and run the holder:

```sh
ikigai serve /Users/you/.ikigai/serve.sock
```

The instance name follows the MODE unless `--name` overrides it: `serve` for
`ikigai serve`, `daemon` for `--daemon`, `mcp` for `ikigai mcp`, and `repl` for everything
else — which includes both the interactive REPL and every `ikigai -c '…'` one-shot. So
`serve.store = true` needs no flag, and `repl.store = true` would give the dataset to
whichever terminal got there first, which is the solo case wearing a scoped spelling.
Mixing the two spellings — a scoped line for one instance plus an unscoped line every
other process still honours — is **refused at startup**, because it re-creates exactly the
collision the scoping exists to prevent.

`prefer` rather than `override`: the remote when it answers, quiet absence when it does
not. Mounts are tried after every local space, so on the holder itself the local binding
wins and the mount line is inert — one config file can serve every process on the machine.

## Where the dataset lives

Not here. `store.toml` in the same config home names it, and defaults to `~/.ikigai/store`
under the data home:

```toml
# ~/.config/ikigai/store.toml
path = "/Volumes/fast/ikigai-store"   # optional; relative paths resolve against the data home
```

`<instance>.store.toml` beside it overrides the key for one host. **No environment
variable names it**, ever: an env var is invisible to `ikigai config`, is not inherited by
a launchd agent, and two processes that disagree about it never meet.

Config home for the setting, data home for the bytes.

## What you see when somebody else has it

Three lines on stderr — the fact, the fix, the underlying error — and the store is
simply **not bound** in this process:

```text
ikigai: urn:iki:store:* is NOT bound here — the durable store at /Users/you/.ikigai/store
is held by another process, and RocksDB permits one writer per directory.
  fix: this is topology, not a retry. Let ONE process hold the dataset and resolve through
  it — mount = "prefer urn:iki:store:=<its socket>" in /Users/you/.config/ikigai/config.toml
  (and urn:iki:ledger: beside it for the ledger). See docs/durable-store.md.
  underlying: unavailable: … IO error: While lock file: …/store/LOCK: Resource temporarily
  unavailable
```

It is a warning and not a panic on purpose. A held directory is not a misconfiguration —
the config is right and another process is simply running — and it is the one failure the
system has an answer for: with a `mount` line naming the holder, the absent local binding
is precisely what lets the mount answer, and the resource resolves remotely with nothing
else to do.

Everything else **is** a misconfiguration and **panics**: an unwritable directory, a
`store.toml` that cannot be parsed, a `store` value that is neither `true` nor `false`. A
host that started anyway would be one whose durable store silently was not there.

## Typing at it

```sh
# read — a named `query=` works, and so does a trailing value
ikigai -c 'source urn:iki:store:info'
ikigai -c 'source urn:iki:store:select query="SELECT ?s ?o WHERE { GRAPH <urn:demo:g> { ?s ?p ?o } }"'

# write — the remainder after the IRI is the body, VERBATIM and unquoted
ikigai -c 'sink urn:iki:store:update INSERT DATA { GRAPH <urn:demo:g> { <urn:demo:s> <urn:demo:p> "it survives" } }'

# or pipe the body in, which is what a heredoc or a file wants
echo 'INSERT DATA { <urn:a> <urn:b> 42 }' | ikigai -c 'sink urn:iki:store:update'
```

⚠ **Two engine behaviours to know before you write your first update**, neither of them
this module's and both silent:

* On `sink`, the text after the IRI is taken **verbatim** — quotes included. So
  `sink urn:iki:store:update "INSERT DATA { … }"` sends a body that literally begins with
  a double quote, and the store rejects it as not-a-SPARQL-update. Leave the quotes off.
* `sink <iri> content="…"` **does not work**: `content` is a declared argument, so it is
  consumed as a named argument and then *overwritten* by the (empty) verbatim remainder.
  An empty SPARQL update is a valid no-op, so the answer is `updated: 0 -> 0 quads` and
  nothing says the body was dropped. Use the remainder or a pipe.
* A `sink` with no remainder **reads piped stdin** — that is how a secret gets in without
  reaching the command line. The reader is installed only when stdin is *not* a terminal
  (`main.rs` checks `is_terminal`), so an interactive one-shot is unaffected. In a
  NON-interactive context whose stdin is an open pipe nobody closes — a supervisor, a CI
  step, an agent harness — `ikigai -c 'sink urn:X'` blocks until EOF. Redirect
  `< /dev/null` in scripts.

## Capabilities

The REPL's own session is root, so nothing is needed for ordinary use. A narrowed session
(`cap`), a served connection or an agent needs the store's own scopes:

| scope | what it opens |
| --- | --- |
| `urn:cap:store:read` | `select`, `ask`, `construct`, `describe`, `info` |
| `urn:cap:store:write` | `update`, `load` |

⚠ **`urn:cap:store:write` is the keys to the whole dataset**, `DROP ALL` included: the
store's write scope is all-or-nothing, with no per-graph attenuation. Anything built on
this store inherits that — a domain module's write action needs `urn:cap:store:write`
transitively, because a sub-request carries the **caller's** capability unchanged. Grant
it to the host and to trusted local sessions; do not hand it down a wire.

That is also why the store is bound in the **embedded root space only** — never in
`served_space` and never behind the HTTP door. A peer reaches it by mounting this kernel
over IPC, under that connection's own clamped ceiling.

## Two RocksDB directories, not one

A host with `browse.root` configured already holds a second RocksDB directory
(`~/.ikigai/browse-store`, the explanation and annotation archive, shared with
`urn:sparql:*`). They are different datasets with different locks and they do not
interfere — but they are two exclusive resources, so if you designate a serving instance,
designate it for both.
