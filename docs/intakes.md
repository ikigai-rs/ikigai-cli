# Configured contact intakes

Put a JSON array in `<config home>/intakes.json`. The host reads it once at startup, in
both the local kernel and the general served kernel. Each row binds
`urn:intake:id:<id>:submit`; `urn:contact:submit` is an alias of the **first** row. The file
replaces the built-in contact intake. Without the file, the existing contact fields,
space, redirect, client attribution and blocklist remain in use. The booking intake is
unchanged. Restart the host after editing this file.

For example, two sites can write into the same owner's contact space with distinct trusted
site values:

```json
[
  {
    "id": "studio",
    "space": "urn:space:contact",
    "fields": [
      {"name": "name", "required": true, "summary": "Your name"},
      {"name": "email", "required": true, "summary": "Your email address"},
      {"name": "message", "required": true, "summary": "Your message"}
    ],
    "email_field": "email",
    "honeypot": "_honey",
    "redirect": "https://studio.example/thanks",
    "fixed_fields": {"site": "studio"},
    "blocklist": "urn:blocked:owner:{key}",
    "block_key_file": "/etc/ikigai/block.key"
  },
  {
    "id": "workshop",
    "space": "urn:space:contact",
    "fields": [
      {"name": "email", "required": true, "summary": "Your email address"},
      {"name": "message", "required": true, "summary": "Your message"}
    ],
    "email_field": "email",
    "redirect": "https://workshop.example/thanks",
    "fixed_fields": {"site": "workshop"},
    "blocklist": "urn:blocked:owner:{key}",
    "block_key_file": "/etc/ikigai/block.key"
  }
]
```

Route each site's form POST to its endpoint using the HTTP door's existing route table.
The alias in this example submits to `studio`. Intakes still require the submitting capability
and the ability to write to the destination space; configuration does not grant authority.
A layer-only served surface still exposes only layers, without contact intakes.

Each row requires `id`, `space` and `fields`. IDs are unique and start with an ASCII letter
or underscore, followed by ASCII letters, digits, underscores or hyphens. `space` is the
IRI receiving the validated tuple. Optional row keys are:

| Key | Default | Meaning |
|---|---|---|
| `fixed_fields` | `{}` | String values supplied by the operator, appended after validation. |
| `redirect` | `null` | An `http(s)://` URL or same-origin `/path` shown on success; otherwise a plain `received` answer. |
| `email_field` | `null` | A declared submitted field to validate as an email address. |
| `honeypot` | `null` | A body key that must be empty; a filled trap is silently discarded. |
| `requires` | `urn:cap:contact:submit` | Capability required to submit. |
| `blocklist` | `null` | The block set, as an IRI template naming each member once as `{key}`; requires `email_field` and `block_key_file`. See below. |
| `block_key_file` | `null` | Absolute path to the key sender addresses are hashed with for `blocklist`: 64 hexadecimal digits, mode 600 (or root-owned 640). |

### The blocklist

The intake never sends or stores a sender's address to check it. It computes two keys with
keyed BLAKE3 under the key in `block_key_file`: one over the trimmed, lowercased address and
one over `domain:<domain>` (the part after the `@`), each as 64 lowercase hexadecimal digits.
It asks `Exists` on the `blocklist` template with each key filled in, the address first. If
either member exists, the submission is silently discarded with the same answer as a real
submission. Any other answer admits it: `NotFound` (an expired block, or none), or an
unreachable or refused block set. The submitting ceiling must permit the lookup. A block set
entry for an address is the same keyed hash, so whoever adds entries needs the same key.

Each field requires `name`. Optional field keys are `required` (false), `summary` (the
name), `one_of` (an empty list), `iana_zone` (false), and `max_len` (the intake's
`DEFAULT_MAX_LEN`, currently 4000 characters). Names follow the ID alphabet, and submitted
field names must be unique. A maximum length must be greater than zero.

A submitted key that names a fixed field is discarded, in both JSON and form-encoded
bodies. Fixed fields are absent from the endpoint's form description, even if also listed
in `fields`; an overlapping declaration does not require a submitted value. Unknown body
keys are also discarded. The fixed values are escaped as string data in the tuple.
`via`, `via-*` and `received` are reserved provenance names and cannot be fixed fields.
The body and its message remain untrusted data; fixed fields do not turn them into instructions.
These endpoints retain the existing tuplespace storage path and do not configure downstream
scoring, layer routing or encryption; configure those separately before accepting public messages.

An empty list, repeated ID, invalid IRI or redirect, invalid field, blocklist without one `{key}`
or a block key, block key file that is relative, unreadable, reachable by others or not a key,
unknown configuration key, unreadable file or malformed JSON refuses startup. Row errors
name their position and ID when available. The binary exits with code 2 and a plain sentence beginning `ikigai:`, for
example:

```text
ikigai: /config/intakes.json: intake row 1 (`studio`) is refused: invalid argument `redirect`: the intake `studio` has redirect `thanks.html`, which is not a link target: use an http(s):// URL or a same-origin /path
```

A row missing its ID is named by its position as `unnamed`. Configured rows do not enable
client-token attribution; the absent-file compatibility intake retains its existing policy.
