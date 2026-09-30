# Run a declared arrangement

**Status:** built (ledger [#637](http://localhost:1060/l/default/item/637), the host half of spaces as
data, arc 1). Needs `ikigai-core` 0.1.83. Core's side is `ikigai-core/docs/design/space-declarations.md`.

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

or name it in the config home, where a relative path is taken against the config home:

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

**Anything but Turtle, for now.** The file is read through a bootstrap kernel and transrepted to
Turtle, so another surface arrives with no host change. N-Triples and JSON-LD work through the host's
transreptors today; s-expressions need `ikigai-fs` to recognize their extension first.

**Changing it while running.** The declaration is read at start. Hot reload is ledger
[#628](http://localhost:1060/l/default/item/628).
