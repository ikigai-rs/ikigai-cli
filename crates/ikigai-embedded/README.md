# ikigai-embedded

The **in-process host assembly** for [ikigai](https://crates.io/crates/ikigai-core):
the simplest "attach to a kernel" binding, where the kernel, its endpoints, and its
cache all live in the calling process — no network, no IPC. It wires the standard
module set into a `Kernel` for the `ikigai` CLI; the IPC and QUIC transports
([ikigai-ipc](https://crates.io/crates/ikigai-ipc),
[ikigai-quic](https://crates.io/crates/ikigai-quic)) front a kernel built the same
way over a wire.

## What it composes

The host assembles a `Space` from the published module crates and adds its own demo
shapes (`urn:data:page` / `urn:data:about` compose templates, `urn:host:info`):

- function endpoints — `ikigai-fn` (`toUpper`, `reverseList`, `wrap`, `split`,
  `greet`, `echo`, `compose`)
- `ikigai-fs` (filesystem), `ikigai-http` (outbound HTTP client, native via `ureq`),
  `ikigai-personal`, `ikigai-rdf`, `ikigai-sparql`, `ikigai-xslt`,
  and the `ikigai-runbook` demo (gated off by default)
- a `CliRenderer` that adds an `application/json` projection of an endpoint's
  `Description`, which the REPL reads to learn its parameter contract

## Kernel builders

| function | builds |
|----------|--------|
| `kernel()` | the embedded kernel (full local space + system clock) |
| `watched_kernel()` | the embedded kernel as a shared `Arc`, with a **filesystem watcher** behind it and the process [scheduler](https://crates.io/crates/ikigai-scheduler) injected for concurrent fan-out |
| `trusted_kernel_for(nature)` | a **served** kernel for IPC — *includes* the personal space, safe because the peer is peercred-verified as the same OS user |
| `kernel_for(nature)` | a **served** kernel for an *unauthenticated* transport (QUIC) — **omits** the personal space, since a QUIC peer isn't authenticated yet |

The watcher is the first *external* golden-thread freshness source: an out-of-band
change to a workspace file (an editor, `git checkout`, another process) cuts that
file's `urn:file:<rel>` thread, so the kernel's cached reads — and any composite over
them — recompute, exactly as a kernel-mediated `Sink` already does. Because the
watcher and the engine share one `Arc<Kernel>`, they share one cache.

Builds for both native and wasm (the browser frontend mounts the same space).

## Reactive spaces: the host decides what fires, and under what

`reactive_kernel_with_mounts` (the `--daemon` writer, or `--react`) runs the
[ikigai-intray](https://crates.io/crates/ikigai-intray) reactor over
`<workspace>/spaces/`: a tuple dropped into `urn:space:<name>` fires that space's
handler. Everything in a space's own directory sits beside the `inbox` a dropper
writes into, so the host keeps both halves of a handler's configuration in the
**config home** (`$XDG_CONFIG_HOME/ikigai/`, or `~/.config/ikigai/`), one file per
space, named for the space, read fresh on every tuple:

| file | holds | when it is absent |
|------|-------|-------------------|
| `space-authority/<space>` | the scopes the handler runs under, one IRI per line (`#` comments allowed) | the three tuplespace verbs only |
| `space-handler/<space>` | the ONE IRI the space's tuples fire at (`#` comments and blank lines allowed) | the migration fallback below |

What fires, given the host entry and the space's `<workspace>/spaces/<space>/handler` file:

| `space-handler/<space>` | `handler` file | fires |
|-------------------------|----------------|-------|
| names `H` | absent, or names `H` | `H` |
| names `H` | names something else | nothing: each tuple is dead-lettered with a note naming the file's target |
| names nothing, several IRIs, a non-IRI, or is unreadable | any | nothing (refused, dead-lettered when there is a file) |
| absent | names `F` | `F`, the **migration fallback** |
| absent | absent | nothing: not a reactive space |

A refused tuple is loud: it lands in `error/`, the dead-letter line is logged, and
the heartbeat goes FAILING. Once the two agree, `sink urn:space:<space> retry=<id>`
runs it again; re-arming a dead letter needs `urn:cap:space:retry` beside
`urn:cap:space:out`, which the REPL's root capability holds and a dropper does not.

### Migrating a space

The fallback keeps a deployed writer handling bookings while its spaces are unpinned,
and says so. At start-up the writer prints one line per space that is not the host's
decision alone, for example:

```text
ikigai: space `bookings`: fires `urn:booking:handle` from /…/spaces/bookings/handler, a file in the drop tree anyone who can write the workspace can retarget, because the host entry /…/space-handler/bookings is ABSENT (the migration fallback, ledger #887). If `urn:booking:handle` is right, pin it: mkdir -p '/…/space-handler' && cp '/…/spaces/bookings/handler' '/…/space-handler/bookings'
```

Check the IRI, run the command, and the line goes away on the next start; nothing
needs a restart to take effect, since the entry is read per tuple. The first tuple a
space fires under the fallback is logged too, so a space created (or retargeted) after
start-up is not silent. A pinned space no longer needs its `handler` file, and the
heartbeat still counts its dead letters.

## License

MIT OR Apache-2.0.
