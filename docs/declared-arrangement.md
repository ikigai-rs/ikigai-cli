# Run a declared arrangement

**Status:** built (ledger [#637](http://localhost:1060/l/default/item/637), the host half of spaces as
data, arc 1). Needs `ikigai-core` 0.1.84 (0.1.83 builds it; 0.1.84 bounds it); the `.arrangement` form needs `ikigai-fs` 0.1.7 and
`ikigai-sexpr` 0.1.4, and the picture needs `ikigai-diagram` 0.1.0. Core's side is
`ikigai-core/docs/design/space-declarations.md`.

The local kernel's root is an *arrangement*: which spaces are consulted, in what order, with which
doors bound to which endpoints. By default the host composes it in Rust. You can run a different one
by handing the host a **declaration**: the same `ik:` graph `urn:kernel:topology` writes, coming in.
A declaration arranges endpoints the host already has, by name. It never creates one.

## Start from what the host runs today

```bash
ikigai -c 'source urn:iki:host:arrangement' > root.ttl
```

`urn:iki:host:arrangement` answers the arrangement this process built its root from, as Turtle, with
a `#` header saying where it came from. Edit the file (drop a door, reorder layers, add a `Limit`),
then start from it:

```bash
ikigai --arrangement root.ttl                  # any mode that builds the local root
```

## Or write it as an s-expression

The same arrangement reads as an `.arrangement` file — shorter to write by hand, and the host takes it
exactly as it takes Turtle:

```lisp
;; game.arrangement: two layers, consulted in order.
(fallback :id "urn:game:root"
  (endpoints (door "urn:host:demo" host-demo))
  (endpoints (door "urn:host:info" host-info)))
```

```bash
ikigai --arrangement game.arrangement
ikigai -c 'source urn:iki:host:arrangement as=text/x-ikigai-arrangement' > root.arrangement
```

`ikigai-fs` types a `*.arrangement` file as `text/x-ikigai-arrangement`, and `ikigai-sexpr`'s
`urn:sexpr:arrangement-to-rdf` transrepts it to Turtle on the way in: **losslessly**, checked by
reading its own output back, so a file that means one arrangement cannot start another. The one thing
the round trip drops is presentation — comments, layout, and the choice between equivalent spellings.
`urn:iki:host:arrangement` answers either face: Turtle by default, and the s-expression with
`as=text/x-ikigai-arrangement`, each with its header as comments (`#` or `;;`), so either dump starts
the same host. The grammar (`endpoints`, `fallback`, `mount`, `alias`, `limit`, `level`, `ref`, and
`door` with an optional `:match` and `:confined`) is ikigai-sexpr's `arrangement` module.

A malformed file stops the start with ikigai-sexpr's reason, which says where:

```
ikigai: the declared arrangement `/…/game.arrangement` cannot be read: it is
`text/x-ikigai-arrangement`, and <urn:sexpr:arrangement-to-rdf> refused it: invalid argument
`content`: urn:sexpr:arrangement-to-rdf: at root (fallback) › layer 2 (endpoints) › door 1:
(endpoints …) holds only `(door "pattern" endpoint)` forms; found `(portal …)`
```

## Name it in the config home

A relative path is taken against the config home:

```toml
# ~/.config/ikigai/config.toml  ($XDG_CONFIG_HOME/ikigai/config.toml when set)
arrangement = "root.ttl"
daemon.arrangement = "daemon-root.ttl"   # instance-scoped: this applies to --daemon alone
```

**Precedence: flag > `<instance>.arrangement` > `arrangement` > the built-in arrangement.** The host
says on stderr, once, which declaration it is running.

## What reads it

A declaration names the **local** kernel's root: the REPL, `-c`, `--daemon`, `mcp`, and the trusted
IPC socket (`serve <socket>`). The served doors (`serve quic://…`, `serve --http`, the calendar server)
never read one: they are minimal by design, and a declaration must never widen what a served door
exposes. `--arrangement` on one of them, or beside `--connect`, is refused rather than ignored.

The host still layers the rest around the declared root, as before: the alias table, the clock, the
subclass axioms, config-home mounts, the demo runbook (gated by `urn:host:demo`, a runtime switch no
declaration can state) and `urn:iki:host:arrangement` itself.

## It fails loud

A declaration that is missing, is not a declaration, or does not build stops the start (exit 2) with
the reason, and the reason names the node:

```
ikigai: the declared arrangement `/…/root.ttl` cannot be built: <urn:ikigai:space:_:1:door:1> binds
`no-such-endpoint`, which the host did not register: a declaration arranges registered endpoints and
never mints one
```

There is no fall back to the built-in root. An operator who asked for a declaration and silently got
the default would have no way to know.

## ⚠ What you cannot declare yet

**A name that means two endpoints.** A door binds an endpoint by its name, and names are not unique.
Where the host binds one name to two *different* endpoints, a declaration cannot say which one it
means, and the host refuses it, naming every door the name is bound at. The dump marks those names in
its header (`# ⚠ Not declarable as it stands: …`). On every machine today that is:

| name | bound at | why they differ |
|---|---|---|
| `file` | `urn:orgfile:{path}`, `urn:file:{path}` | two jails: the org directory and the workspace |
| `meeting` | `urn:meeting:zoom:schedule`, `urn:meeting:schedule` | `ikigai-meeting` binds two clones of one backend |
| `org-agenda` | `urn:org:agenda`, `urn:org:agenda:{period}` | `ikigai-org` binds two instances with the same files |

and every `llm-*` backend name (`llm-openai`, `llm-up`, `llm-installed`, `llm-model`) once `llm.json`
declares a second provider. So the dump of the built-in root does not start as it stands: remove those
doors (or the layers holding them) and the rest runs exactly as the built-in root does, which the
tests prove name by name. The fix belongs to the modules (a distinct name per endpoint) or to core (a
door identity other than the name), not to a rename here: a name is on the wire.

**A space that does not describe itself.** An `ik:OpaqueSpace` (a remote peer, a hand-written
resolver), a closure `Rewrite`, and a door whose grammar core does not know (`matchKind "custom"`)
are refused by core. A host with `browse.root` configured binds custom doors, so its dump does not
start either.

**A surface nothing here transrepts losslessly.** The file is read through a bootstrap kernel and
transrepted to Turtle, so another surface arrives with no host change: Turtle, N-Triples, JSON-LD and
`.arrangement` work today. A file whose type has no lossless path to Turtle is refused, naming it.

**Changing it while running.** The declaration is read at start. Hot reload is ledger
[#628](http://localhost:1060/l/default/item/628).

## A declaration is bounded (ledger [#643](http://localhost:1060/l/default/item/643))

A declaration is operator input, so core (0.1.84 and later) reads and builds it within three bounds,
and refuses one past any of them whole — never reads it partway, never crashes on it:

| bound | limit | what it counts |
|---|---|---|
| `MAX_DECLARATION_DEPTH` | 48 | spaces nested in spaces, checked before each descent |
| `MAX_DECLARATION_NODES` | 65,536 | nodes once every reference is expanded |
| `MAX_DECLARATION_TEXT` | 16 MiB | the text those nodes carry, expanded the same way |

A named node is expanded at every place it is used (core's `Topology` is a tree of values), so the
node and text bounds are what stop a few lines of named spaces that reference each other several times
("billion laughs") from growing exponentially: the read is refused once it passes the bound, not after
the expansion. The depth bound is what stops a chain of spaces thousands deep from overflowing the
stack. Every surface reaches the same bounds, because every surface reaches core as Turtle; the
`.arrangement` reader in ikigai-sexpr also bounds its own tree (48 deep, 65,536 in all) before it
transrepts.

Past a bound the start stops with exit 2 and core's message, which names the bound, its limit and
the node that passed it:

```text
ikigai: the declared arrangement `/path/to/root.ttl`: <urn:t:deep:49> nests deeper than 48 spaces (MAX_DECLARATION_DEPTH): a declaration past a bound is refused whole, never read partway
```

`crates/ikigai-cli/tests/arrangement.rs` pins it through the binary: a chain at the depth bound
starts, one space deeper is refused, one 20,000 deep is refused the same way (exit 2, not an abort),
and a few-KB billion-laughs file is refused on the node bound. Below core 0.1.84 none of this held —
the Turtle path recursed without a bound — which is why the workspace pins 0.1.84 as a floor.

## See the arrangement

`ikigai-diagram` draws an arrangement as an accessible SVG of nested boxes, and the local root binds
it (the REPL, `-c`, `--daemon`, `mcp`, `serve <socket>`; never a served door):

```bash
ikigai -c 'source urn:diagram:kernel' > root.svg                                   # the arrangement you are in
ikigai -c 'source urn:diagram:arrangement of=urn:file:game.arrangement' > game.svg # a declaration, by name
```

`urn:diagram:kernel` needs `urn:cap:kernel:inspect`, as `urn:kernel:topology` does, and declares it:
a session without it is refused, and `ikigai mcp` projects the tool only where the capability holds.
`urn:diagram:arrangement` declares nothing of its own: it reads `of` under the caller's capability,
so a caller can draw only what it can already read. Both are cacheable and redrawn when what they
read changes.
