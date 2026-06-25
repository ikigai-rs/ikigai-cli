# ikigai-engine

The **renderer-agnostic REPL engine** for [ikigai](https://crates.io/crates/ikigai-core).
`Engine` parses a request line, issues it against a kernel through the
[ikigai-resolve](https://crates.io/crates/ikigai-resolve) `Resolver` seam, and
returns an `Action` describing what to display — knowing nothing about terminals or
rendering. The plain line REPL, the `ratatui` TUI, and the browser frontend all
drive this *same* engine and present its `Action` however suits their medium, so it
was pulled out of the [ikigai-cli](https://crates.io/crates/ikigai-cli) binary into
its own crate for the browser build to reuse unchanged.

## What it does

- **Self-description-driven `source`.** Rather than assuming an `in` argument, the
  engine asks the target endpoint for its parameter contract (a `Meta` request
  rendered as `application/json`) and routes by it — handling an endpoint that reads
  a differently-named argument, several arguments, or only a grammar binding. A
  `key=value` word names a declared argument; positional or piped text fills the one
  argument left unnamed. The contract is fetched through `issue`, so it works the
  same against a remote kernel.
- **A pipeline grammar**, parsed by one recursive-descent parser:

  | connector | meaning |
  |-----------|---------|
  | `a \| b` | pipe — feed each stage's whole output into the next as its input |
  | `a .. b` | map — run `b` once per newline-separated item of `a`'s output, rejoining |
  | `( a ; b )` | fork/join — fan the same input to each branch, join their outputs |
  | `"…"` | quote an operator or whitespace so it's data, not structure |

  `compose` (`$a{<iri>}` transclusion) markers assemble nested resources in one pull.

- **Cache-status tracking.** Each resolution reports `computed` / `cached` /
  `uncacheable`; a pipeline summarises its stages (`1 cached · 1 computed`). Pipe
  stages thread their `Provenance` downstream, so a transform is no more cacheable
  than its piped input.
- **Concurrent fan-out.** Fork/map branches run in parallel via `block_on` +
  `join_all` over the resolver's async `issue_*` methods (on
  [ikigai-scheduler](https://crates.io/crates/ikigai-scheduler) when one is
  injected); with no spawner the path is a sequential fallback, so the engine still
  compiles to wasm.

`config` is a small user-settings reader (used by the `config` command and the TUI's
keybindings); on a target with no config directory it reports defaults.

## License

MIT OR Apache-2.0.
