# Terminal resolver audit (#3417)

Audited the CLI adapter and its installation in `main.rs`, starting at
`ec4c8e064e4199a1706cdf452a46f7e43eb927e6` (PR #699). Dependencies examined:
`ikigai-engine` 0.5.0, `ikigai-resolve` 0.5.0, and `ikigai-core` 0.3.5,
as resolved in `Cargo.lock`.

## Reproduced and fixed

- **An explicit attached `as` was overwritten.** A Source request attaching
  `as=text/html` succeeded through the inner resolver, but the adapter inserted
  another `as=text/plain`. `an_explicit_attached_as_is_preserved_by_both_attachment_methods`
  failed with `InvalidArgument { name: "as", detail: "given twice; ..." }`.
  Both attachment methods now forward an explicit attached face without negotiation.
- **A non-JSON Meta representation influenced terminal negotiation.** A Meta renderer
  returning a JSON description's bytes labeled `text/plain` made the adapter select
  text. `non_json_meta_answers_do_not_select_a_terminal_face` failed before the fix
  (`text/plain` returned instead of the original `text/html`). The adapter now checks
  for `application/json` before parsing, including the body path. The regression
  exercises synchronous, asynchronous, and body resolution, rejects three other
  media types, and accepts JSON with parameters and case-insensitive media types.
- **Face selection discarded declared parameters and spelling.** A Source contract
  offering `text/plain;charset=utf-8` selected bare `text/plain` instead.
  `the_selected_face_preserves_its_declared_parameters_and_spelling` failed before
  the fix. Selection now sends the actual offered face rather than substituting
  a constant. The test also covers `Text/Plain`.

Run the fixed regressions and other adapter checks with:

```sh
cargo test -p ikigai-cli --bin ikigai terminal_resolver --locked
```

## Reproduced, requiring an engine change

These are retained as explicitly ignored **failing reproductions**, not passing
regression coverage. Neither is fixed by this PR. Run them explicitly:

```sh
cargo test -p ikigai-cli --bin ikigai terminal_resolver::tests::audit_ --locked -- --ignored
```

- **Duplicate Meta requests.** `audit_routing_and_face_selection_fetch_one_contract`
  counts calls at the inner Resolver boundary. Evaluating
  `source urn:test:page name=example` fetches the identical Meta request twice:
  once for engine argument routing, once for terminal negotiation. Its assertion
  fails with `left: 2, right: 1`. An embedded kernel can serve the second Meta
  from its cache, but an IPC resolver sends each issue across the wire, even
  when the server's cache hits. The adapter cannot reuse the engine's already-read
  description through the current Resolver API. Adding an independent adapter
  cache would introduce another invalidation and authority boundary.
- **Pipeline bytes depend on the reference optimization.**
  `audit_reference_and_value_pipes_receive_the_same_face` binds one HTML-default
  page offering text and two identity consumers. The ordinary consumer receives
  `text/plain`; the incremental consumer receives `text/html`. Its equality
  assertion fails with those two strings. Engine `pipe_by_reference` reads a bare
  upstream through the kernel as a nested reference, bypassing this adapter;
  the value path rewrites the upstream. Thus the adapter also changes intermediate
  pipeline bytes, contrary to the audit's preservation criterion. The preexisting
  binary test explicitly expects text in a value pipeline and is left intact.
  A complete correction needs the engine to distinguish output displayed to the
  terminal from intermediate data, across ordinary pipes, reference pipes, forks,
  maps, and stored plans. Merely exempting the body-returning Resolver method
  would not cover all those paths.

## Other checks

- Explicit `as` values (including attached, empty, and unsupported values), Meta, Sink, and
  Delete are preserved. Contract requests are restricted to Source without `as`.
  Denied, absent, malformed, and non-description contracts leave the request alone.
- The Meta request is the engine routing request: same target, `Verb::Meta`,
  `as=application/json`, session capability, and scope. The adapter has no separate
  contract cache. Scope and capability are forwarded for resolution and cache probes.
- Rewriting precedes inner cache lookup, so the text request includes `as` in its
  identity. `rebinding_invalidates_the_contract_and_keeps_terminal_cache_identity_separate`
  checks HTML before and after terminal reads, then removes and restores the text
  contract with `bindings_changed()`. The adapter sees each changed contract.
- All 16 current Resolver methods are implemented: `issue`, `issue_as`,
  `issue_as_in_run`, `issue_as_async`, `issue_body_as_in_run`,
  `issue_as_async_with_incoming`, `issue_as_async_in`, `issue_attached_in`,
  `issue_body_attached_in`, `set_tracer`, `clear_tracer`, `is_cached`,
  `is_cached_in`, `entries`, `try_entries`, and `transport`. Read through their
  forwarding: capabilities, run contexts, provenance, scopes, attachments, and
  body results reach their corresponding inner methods. Cache probes intentionally
  prepare the negotiated request before probing; ordinary Source reads do not
  spawn the cache-probe thread.
- Installation is confined to CLI engines: embedded REPL/batches and IPC/QUIC
  clients. Socket and HTTP serving receive the kernel directly. Nested endpoint
  reads also use the kernel, which explains the reference-pipe discrepancy above.
- No version change, publishing, or assistive technology evaluation.
