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

## License

MIT OR Apache-2.0.
