# ikigai-mcp

Project the capability-scoped ikigai manifold as an **MCP** (Model Context
Protocol) server. An MCP client — Claude Desktop, Claude Code, any host — sees
ikigai's resources as tools, scoped to a capability *grant*.

## Why it's mostly translation, not construction

MCP asks a server for three things, and ikigai already has all three:

| MCP needs | ikigai provides |
|-----------|-----------------|
| a tool list | `urn:kernel:actions` — the capability-scoped action manifold |
| a typed input schema per tool | `ArgSpec` contracts (`one_of` → enum, `class` → type, a typed `default`, `required`, a list → array, `needs` → `dependentRequired`, a closed argument set → `additionalProperties: false`) |
| a way to call a tool safely | validate the arguments, then invoke through the kernel |

So this crate is a thin, runtime-free translator (newline-framed JSON-RPC over
stdio — no tokio): each `ik:Action` becomes a tool, the tool name reverses to the
`(endpoint, verb)` it came from, and a `tools/call` validates and invokes.

## Run it

```bash
ikigai mcp --grant <name>        # serve under a named grant (the ceiling)
ikigai mcp --scope urn:cap:…     # …or an ad-hoc scope union
ikigai mcp --principal <iri> --grants /etc/ikigai/grants.json
                                 # …or as an AGENT, its grant checked against its person's
ikigai mcp --root                # root (unrestricted), only by asking for it
ikigai mcp … --show urn:layer:   # list only the tools bound under an IRI prefix (repeatable)
```

A bare `ikigai mcp` refuses to start and names these flags: it used to serve root, and an
agent's tool server that is root because nobody said otherwise is the default this removes
(ledger #1830). `--root` cannot be combined with the others, and the banner says
UNRESTRICTED.

`--show <pattern>` narrows the LIST, never the authority. A pattern is a tool name
(`grep__source`), a bare endpoint id (`grep`, every verb), a trailing-`*` prefix
(`repo-*`), or, with a `:` in it, an **IRI prefix** matched against where a tool is bound
rather than its name. The same patterns go in a grant's `"show"` / `"hide"` lists in
`grants.json` (the object form, `{"scopes": […], "show": […], "hide": […]}`), and `--show`
unions with them. An IRI prefix lets an MCP entry for a mounted peer leave the local
kernel's own tools out:

```bash
ikigai mcp --scope urn:cap:layer:read:talk \
  --override urn:layer:,urn:layers:,urn:collab:=quic://door.example:4434 --cert-dir ~/certs/me \
  --show urn:layer: --show urn:layers: --show urn:collab:
```

Wire it into an MCP host, e.g. Claude Desktop's `claude_desktop_config.json`:

```json
{ "mcpServers": {
    "ikigai": { "command": "ikigai", "args": ["mcp", "--grant", "booking-agent"] }
} }
```

## Grants — capability as a named union

A **grant** is a named union of capability scopes, in
`~/.config/ikigai/grants.json` (or `$IKIGAI_GRANTS`):

```json
{ "booking-agent": ["urn:cap:personal:calendar:read:freebusy"],
  "research-agent": ["urn:cap:net:query.wikidata.org", "urn:cap:fs:read:*"] }
```

## Agents: `--principal`

`ikigai mcp --principal <agent IRI>` serves as an agent acting for a person. The grants
file gains a reserved `principals` table (so no grant may be named `principals`):

```json
{ "brian":  ["urn:cap:ledger:read:default", "urn:cap:ledger:write:default"],
  "claude": ["urn:cap:ledger:read:default"],
  "principals": {
    "urn:collab:participant:brian": { "kind": "person", "grant": "brian" },
    "urn:collab:participant:hub":   { "kind": "agent", "acts_for": "urn:collab:participant:brian",
                                      "grant": "claude" } } }
```

- The principal is MINTED into every call's capability (`urn:cap:principal:<iri>`) and stamped
  as the `principal` argument; a `principal` argument the MCP client sends is removed (it is
  removed in every session, named or not).
- The agent's authority is its entry's `grant` plus any `--grant`/`--scope`, and every scope in
  it must be one its person's grant lists, compared literally. Anything outside is refused at
  start, naming each scope; it is never trimmed. Only `agent` and `machine` entries are served:
  a person's principal is never minted for a program. No grant may name a principal scope.
- The grants file must be one **its user cannot write**: not owned by this user, not writable
  by it, in directories it cannot write, with no symbolic link it owns on the way, and the
  process not running as root. Otherwise an agent could widen itself through a shell or through
  its own tools. In practice: `sudo install -o root -m 0644 grants.json /etc/ikigai/grants.json`
  and `--grants /etc/ikigai/grants.json`. The check runs at start and at every reload.

The grant is the **ceiling**. Because the manifold gates each action
independently, a union grant yields a union of affordances *across features* —
"read the calendar's free/busy **and** hit this host," with the calendar's write
and detail actions simply absent from the tool list. Affordance equals
authorization: an attenuated client can't see, let alone call, what its grant
forbids.

## What the server does

- **`tools/list`** — `select_actions` under the grant → `describe` each →
  project. The manifold *is* the tool list. A tool is one id, verb and
  **contract**: an endpoint served at several doors with one contract is one tool
  (the doors become a selector argument where they align), while a mounted copy
  whose contract differs (another capability, another input) is its own tool,
  `{id}-{first 8 hex of its contract digest}__{verb}`, beside the plain
  `{id}__{verb}` the first contract keeps.
- **`tools/call`** — reverse the name to `(endpoint, verb)`, route Binding
  inputs into the IRI and Argument inputs as request args, **validate** the JSON
  arguments against the typed contract with core's one checker,
  `ActionSpec::check` (a non-conforming call returns a SHACL report the model
  repairs from — never a protocol error), then invoke. A list argument takes a
  JSON array, joined with its separator; an open argument set passes its extra
  names through; an envelope's fields are serialized into its carrier as one
  JSON object (0.1.65+). Input groups (exactly one of, at least one of, at most
  one of) and a value's `needs` are stated in the tool's DESCRIPTION, not its
  schema: Claude's API refuses `oneOf`/`anyOf`/`allOf` at the root of a tool's
  `input_schema`, and fails the whole request when one tool has them. The
  server-side check enforces them either way. A
  Binding value is substituted as given (a file path keeps its `/`, an IRI its
  `:`), but a call must reach the tool's OWN endpoint: a value that turns the
  target into another endpoint's IRI (`alice:private` under `urn:x:user:{name}`,
  when `urn:x:user:alice:private` is bound elsewhere) is refused naming the
  argument (0.1.62+; before, the other endpoint answered).
- **Tool answers** — valid UTF-8 text (including JSON, XML and RDF text media
  types) remains MCP text content. Other answers, including invalid UTF-8 labeled
  as text or text with another declared charset, are embedded resource content:
  `resource.uri` is the invoked target IRI, `resource.mimeType` preserves the
  representation type and parameters, and `resource.blob` is standard padded
  base64. This uses MCP 2024-11-05's
  [embedded resources](https://modelcontextprotocol.io/specification/2024-11-05/server/tools#embedded-resources)
  and [binary resource content](https://modelcontextprotocol.io/specification/2024-11-05/server/resources#resource-contents).
  Answers over `MAX_TOOL_RESULT_BYTES` (8 MiB of raw body bytes) return an
  `isError: true` refusal, with no truncated payload. The check runs before text
  conversion, base64 and JSON serialization; the kernel still allocates the
  complete representation before this check. Embedded answers do not add a
  `resources/read` service.
- **Protocol errors per JSON-RPC 2.0 §5.1** — a line that is not JSON gets
  `-32700 Parse error` under `"id": null`; JSON that is not a valid Request (no
  `"jsonrpc": "2.0"`, no `method`, an `id` that is not a string, number or null, a
  scalar, or any array: batching is not part of MCP 2024-11-05, the revision this
  server implements) gets `-32600 Invalid Request`, under the request's `id` when it
  is readable. The reason rides in `error.data`. A notification, or a client's own
  response (a `result` or an `error` with no `method`), is never answered.
- **Concurrent calls** (0.1.64+) — each `tools/call` runs on its own thread and
  is answered when it finishes, so one long call (a feed's `wait=50`) holds no
  other tool up; responses to calls come back in the order they finish, matched
  by `id`. Everything else is answered in arrival order before the next line is
  read. At most `MAX_CONCURRENT_CALLS` (16) run at once: past it a call is
  refused at once with `-32000 Server busy` under its own `id`, the bound in
  `error.data`, never queued. A call runs under the grant in force when its line
  was read. At end of input the server still answers every running call.
- **Live grant-swap** — the server watches the grants file; edit the active
  grant and it emits `notifications/tools/list_changed`, so a connected client's
  tool list morphs with no restart. A reload NARROWS live, and can restore what an
  earlier reload narrowed, but never widens past the authority the session started
  with: a widening is reported on stderr and applies at the next start (ledger
  #1830). A file the session's own user can write can still be widened for the
  next start; an agent session (`--principal`) refuses such a file.

## Try it without a client

`../../demos/mcp-handshake.sh` drives a scripted JSON-RPC session (handshake,
capability-scoped `tools/list`, and a couple of `tools/call`s), and
`../../demos/grants.json.example` documents the grant shape.

## Boundary

The grant is a **policy** boundary enforced kernel-side: a compromised or
prompt-injected *model* cannot exceed it. It is **not** a defense against an
attacker who can already edit the config files — that threat is answered by
identity-bound grants (mTLS / passkey / OAuth) and signed config, not by MCP.

## License
MIT OR Apache-2.0. See `../../LICENSE-MIT` / `../../LICENSE-APACHE`.
