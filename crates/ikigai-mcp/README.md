# ikigai-mcp

Project the capability-scoped ikigai manifold as an **MCP** (Model Context
Protocol) server. An MCP client — Claude Desktop, Claude Code, any host — sees
ikigai's resources as tools, scoped to a capability *grant*.

## Why it's mostly translation, not construction

MCP asks a server for three things, and ikigai already has all three:

| MCP needs | ikigai provides |
|-----------|-----------------|
| a tool list | `urn:kernel:actions` — the capability-scoped action manifold |
| a typed input schema per tool | `ArgSpec` contracts (`one_of` → enum, `class` → type, `default`, `required`) |
| a way to call a tool safely | validate the arguments, then invoke through the kernel |

So this crate is a thin, runtime-free translator (newline-framed JSON-RPC over
stdio — no tokio): each `ik:Action` becomes a tool, the tool name reverses to the
`(endpoint, verb)` it came from, and a `tools/call` validates and invokes.

## Run it

```bash
ikigai mcp --grant <name>        # serve under a named grant (the ceiling)
ikigai mcp --scope urn:cap:…     # …or an ad-hoc scope union
ikigai mcp                       # no grant → root (unrestricted; warns)
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

The grant is the **ceiling**. Because the manifold gates each action
independently, a union grant yields a union of affordances *across features* —
"read the calendar's free/busy **and** hit this host," with the calendar's write
and detail actions simply absent from the tool list. Affordance equals
authorization: an attenuated client can't see, let alone call, what its grant
forbids.

## What the server does

- **`tools/list`** — `select_actions` under the grant → `describe` each →
  project. The manifold *is* the tool list.
- **`tools/call`** — reverse the name to `(endpoint, verb)`, route Binding
  inputs into the IRI and Argument inputs as request args, **validate** the JSON
  arguments against the typed contract (a non-conforming call returns a SHACL
  report the model repairs from — never a protocol error), then invoke.
- **Live grant-swap** — the server watches the grants file; edit the active
  grant and it emits `notifications/tools/list_changed`, so a connected client's
  tool list morphs with no restart. (Broadening is safe here: it is the human
  editing the grant — root re-granting — never the client escalating itself.)

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
