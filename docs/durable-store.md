# The durable store and the work ledger on this host — who opens them, and what to do when you are not them

`ikigai-store` gives this host a dataset that survives a restart: `urn:iki:store:select`
/ `ask` / `construct` / `describe` / `info` / `update` / `load`, their per-graph twins
(`graph-select`, `graph-update`, …), and whatever is built on top of it. **`ikigai-ledger`
is what is built on top of it here** — `urn:iki:ledger:*`, the work items — and the two are
bound by the **same switch**, because the ledger owns no bytes: every read it makes is a
scoped SPARQL query at `urn:iki:store:graph-select` and every write a scoped UPDATE at
`urn:iki:store:graph-update`. A ledger without a store beside it is a set of resources that
resolve and then fail, so this host never binds one without the other.

It is **opt-in twice**, and this page is about the second switch, because the first
question it generates is *"why does my second terminal say the store is not bound?"*

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
# ⚠ A mount claims ONE prefix, so the ledger needs its own line — exactly as the browse
#   family needs one for urn:repo: and one for urn:iki:annotation:. One switch binds both
#   locally; two lines reach both remotely.
mount = "prefer urn:iki:ledger:=/Users/you/.ikigai/serve.sock"
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
ikigai: urn:iki:store:* and urn:iki:ledger:* are NOT bound here — the durable store at
/Users/you/.ikigai/store is held by another process, and RocksDB permits one writer per
directory.
  fix: this is topology, not a retry. Let ONE process hold the dataset and resolve through
  it — mount = "prefer urn:iki:store:=<its socket>" in /Users/you/.config/ikigai/config.toml,
  and a SECOND line for urn:iki:ledger: (a mount matches one prefix, so the ledger needs its
  own). See docs/durable-store.md.
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

# write — a named `content=` is the body, quotes stripped
ikigai -c 'sink urn:iki:store:update content="INSERT DATA { GRAPH <urn:demo:g> { <urn:demo:s> <urn:demo:p> \"it survives\" } }"'

# or the remainder after the IRI, which is VERBATIM and unquoted
ikigai -c 'sink urn:iki:store:update INSERT DATA { GRAPH <urn:demo:g> { <urn:demo:s> <urn:demo:p> "it survives" } }'

# or pipe the body in, which is what a heredoc or a file wants
echo 'INSERT DATA { <urn:a> <urn:b> 42 }' | ikigai -c 'sink urn:iki:store:update'
```

⚠ **Two engine behaviours to know before you write your first update**, neither of them
this module's and both silent:

* On `sink`, the text after the IRI is taken **verbatim** — quotes included. So
  `sink urn:iki:store:update "INSERT DATA { … }"` sends a body that literally begins with
  a double quote, and the store rejects it as not-a-SPARQL-update. Leave the quotes off,
  or name the body with `content="…"` (which does strip the quotes, and is the form to
  reach for with any structured body).
* A `sink` with no remainder **reads piped stdin** — that is how a secret gets in without
  reaching the command line. The reader is installed only when stdin is *not* a terminal
  (`main.rs` checks `is_terminal`), so an interactive one-shot is unaffected. In a
  NON-interactive context whose stdin is an open pipe nobody closes — a supervisor, a CI
  step, an agent harness — `ikigai -c 'sink urn:X'` blocks until EOF. Redirect
  `< /dev/null` in scripts.

## Typing at the ledger

```sh
# file one — the text after the IRI is the item: first line the title, the rest the body
ikigai -c 'sink urn:iki:ledger:append Bind the ledger into the embedded host'
#=> #1 urn:iki:ledger:default:item:01m2h5t1z80m3b2f

ikigai -c 'sink urn:iki:ledger:append priority=0 labels=cli Say what to type'

# read — `items` lists the OPEN items; `status=` takes open (default), closed or all
ikigai -c 'source urn:iki:ledger:items'
ikigai -c 'source urn:iki:ledger:items status=all'
ikigai -c 'source urn:iki:ledger:item:1'

# comment, rank, close
ikigai -c 'sink urn:iki:ledger:comment item=#1 author=brian It resolves from a one-shot'
ikigai -c 'source urn:iki:ledger:next'
ikigai -c 'sink urn:iki:ledger:close item=#2 reason=done Shipped'

# a second ledger is a NAME in the IRI, not an argument and not a tag
ikigai -c 'sink urn:iki:ledger:acme:append Their Q4 migration'
ikigai -c 'source urn:iki:ledger:ledgers'

# query is the store's, not the ledger's — one graph per ledger
ikigai -c 'source urn:iki:store:graph-select graph=urn:iki:ledger:graph:default query="SELECT ?t WHERE { ?i <http://purl.org/dc/terms/title> ?t }"'
```

⚠ **`urn:iki:ledger:append` is the ledger called `default`**, not a ledger called
`append` — the bare forms are an alias for `urn:iki:ledger:default:*`, one binding under
one capability. The catalog lists the canonical template (`urn:iki:ledger:{ledger}:append`)
and never the sugar, so a tool reading the manifold expands the `ledger` argument's
declared default rather than looking for the short name.

⚠ The two engine behaviours in the section above apply here unchanged: the text after the
IRI is **verbatim**, quotes included, and a `sink` with no remainder reads piped stdin.

### Loading a batch

`-c` is repeatable and **`run_commands` returns exit 1 if any command failed**, so a batch
that must not half-apply goes in one process as a list of `-c` flags:

```sh
ikigai -c 'sink urn:iki:ledger:gonk:append First' \
       -c 'sink urn:iki:ledger:gonk:append Second' \
       -c 'sink urn:iki:ledger:gonk:link item=#2 type=blocks #1'
```

⚠ **A script on stdin (`ikigai --plain < items.iki`) has NO exit status.** That path is the
line REPL reading to EOF: a failed line prints `error: …` on stderr and the loop carries on,
and the process still exits 0. It is the convenient form for twenty appends and the wrong
form for a load you need to trust — so if you use it, verify afterwards with a count:

```sh
ikigai --plain < items.iki
ikigai -c 'source urn:iki:ledger:gonk:items status=all'   # does the count match the file?
```

## Capabilities

The REPL's own session is root, so nothing is needed for ordinary use. A narrowed session
(`cap`), a served connection or an agent needs scopes — and **which ones depends on which
door**, because the store has two families:

| scope | what it opens |
| --- | --- |
| `urn:cap:store:read` | the whole dataset: `select`, `ask`, `construct`, `describe`, `info` |
| `urn:cap:store:write` | the whole dataset: `update`, `load` — `DROP ALL` included |
| `urn:cap:store:read:graph:<G>` | `graph-select` / `graph-ask` / … over the one graph `<G>` |
| `urn:cap:store:write:graph:<G>` | `graph-update` over the one graph `<G>` |

⚠ **The broad pair is the keys to the whole dataset and the narrow doors REFUSE it.** They
are not a hierarchy: `urn:iki:store:graph-update` declares and enforces
`urn:cap:store:write:graph:*`, and `urn:cap:store:write` is not under that prefix, so a
grant list built around the powerful token opens the broad doors and **nothing else**.
Grant the broad pair to the host and to trusted local sessions; do not hand it down a wire.

### The ledger's grants

Every ledger read and write goes through the narrow doors, so a ledger caller needs **two
halves** — the ledger's own grant and the store's token for that ledger's graph. Per ledger
`L`:

| to do this in `L` | at the ledger | …and at the store |
| --- | --- | --- |
| read | `urn:cap:ledger:read:L` | `urn:cap:store:read:graph:urn:iki:ledger:graph:L` |
| write | `urn:cap:ledger:write:L` | the above **and** `urn:cap:store:write:graph:urn:iki:ledger:graph:L` |
| delete | `urn:cap:ledger:delete:L` | both of those **and** `urn:cap:store:write:graph:urn:iki:ledger:graph:L:deleted` |
| purge | `urn:cap:ledger:purge:L` | the same three as delete |

⚠ **Delete and purge need write authority over TWO graphs**: the graveyard is a second
graph and a scoped write cannot reach across. That is the row an operator gets wrong.

⚠ **The name goes LAST in the token** — `urn:cap:ledger:write:acme`, never
`urn:cap:ledger:acme:write`. The kernel matches a wildcard only as a trailing `*`, so a
parameter that is not last cannot be a family at all.

Rather than transcribe that table, compute it — `ikigai_embedded::store::grants_for("acme",
Authority::Write)` returns exactly the list, built from `ikigai-ledger`'s and
`ikigai-store`'s own spellings, so a host one version behind fails to compile instead of
handing you a grant list that silently denies.

⚠ **Known gap, `ikigai-ledger` 0.2.0:** `urn:iki:ledger:{ledger}:item:{id}` over-declares
the *broad* `urn:cap:store:read` on its `Source` and `Exists`, so a caller holding exactly
the table above is denied on reading one item even though the listing works. Pinned by
`crates/ikigai-cli/tests/ledger.rs::reading_one_item_still_demands_the_broad_store_read_grant`,
which is written to fail when the ledger is fixed.

That two-family split is also why the store is bound in the **embedded root space only** —
never in `served_space` and never behind the HTTP door. A peer reaches it by mounting this
kernel over IPC, under that connection's own clamped ceiling.

## Two RocksDB directories, not one

A host with `browse.root` configured already holds a second RocksDB directory
(`~/.ikigai/browse-store`, the explanation and annotation archive, shared with
`urn:sparql:*`). They are different datasets with different locks and they do not
interfere — but they are two exclusive resources, so if you designate a serving instance,
designate it for both.
