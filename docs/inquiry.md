# The contact-inquiry edge half

The host mounts the edge half of `ikigai-inquiry` (ledger #3836; the design is ledger #3680,
gaps G1 and G5) when the config home has an `inquiry.json`. The host reads it once at startup,
like `intakes.json`. Restart the host after editing it.

**Without `inquiry.json` the host is exactly as before:** nothing is opened and nothing is
bound.

## A complete example

```json
{
  "sender_key_file": "/etc/ikigai/block.key",
  "store": "/var/lib/ikigai/inquiry",
  "model": "contact",
  "owner": "brian",
  "layers": {
    "inquiry": "inquiry-brian",
    "spam": "inquiry-spam-brian",
    "holding": "inquiry-hold-brian",
    "examples": "inquiry-example-brian",
    "intents": "inquiry-intent-brian"
  },
  "block_days": 180
}
```

| Key | Required | Meaning |
|---|---|---|
| `sender_key_file` | yes | Absolute path to the 32-byte sender-key secret: 64 hexadecimal digits (an optional trailing newline), or the 32 raw bytes. Mode 600: a file its group or others can read or write is refused. |
| `store` | yes | Absolute path to the directory the block set and the day counters are kept in. Created if missing. It holds keys and numbers, never an address. |
| `model` | yes | The `ikigai-bayes` model the router scores with at `urn:bayes:{model}:score` (lowercase letters, digits and hyphens, at most 40 characters). The model itself is armed separately (`bayes.state` and `bayes.models`). |
| `owner` | yes | Whose layers the router writes. Without `layers`, the names are the conventional ones for this owner (`inquiry-{owner}`, `inquiry-spam-{owner}`, `inquiry-hold-{owner}`, `inquiry-example-{owner}`, `inquiry-intent-{owner}`; `inq-` instead of `inquiry-` for an owner longer than 8 characters). An owner is 1 to 12 lowercase letters, digits or hyphens. |
| `layers` | no | All five layer names, given explicitly. Each is lowercase letters, digits and hyphens, at most 24 characters, starting with a letter. |
| `block_days` | no | How long a block holds, in days: 1 to 3650. Default 180 (`DEFAULT_BLOCK_DAYS`). |

## What is bound where

| resource | verb | capability | local root | served kernel |
|---|---|---|---|---|
| `urn:iki:inquiry:route` | Sink | `urn:cap:inquiry:route` | yes | no |
| `urn:iki:inquiry:sender-key` | Source | `urn:cap:inquiry:sender-key` | yes | no |
| `urn:iki:inquiry:block:key:{key}` | Exists | `urn:cap:inquiry:block:check` | yes | yes |
| `urn:iki:inquiry:block:key:{key}` | Source | `urn:cap:inquiry:block:read` | yes | yes |
| `urn:iki:inquiry:block:key:{key}` | Delete | `urn:cap:inquiry:block:lift` | yes | yes |
| `urn:iki:inquiry:apply` | Sink | `urn:cap:inquiry:apply` | yes | yes |
| `urn:iki:inquiry:count:date:{date}` | Source | `urn:cap:inquiry:count:read` | yes | no |
| `urn:iki:inquiry:count:kind:confusion:date:{date}` | Source | `urn:cap:inquiry:count:read` | yes | no |

The served kernel (`serve quic://…`, `serve --http`, a socket door) binds only what a
configured intake and the airlock reach. Nothing is added to the HTTP door's route table: a
stranger can name an intake's submit endpoint, never the edge half.

## Capabilities, by unit

Each door declares its capability; `inquiry.json` grants nothing. Grant each where it is used
and nowhere else:

| unit | needs | why |
|---|---|---|
| the public intake (the HTTP door's `--cap` ceiling, beside `urn:cap:contact:submit`) | `urn:cap:inquiry:block:check` | the intake's `Exists` on its `blocklist`. Without it the lookup is refused and the sender is admitted. |
| the airlock's handler (the reactor that drains the intents layer) | `urn:cap:inquiry:apply` | apply. It also holds the model's `urn:cap:bayes:train:{model}`, `read` on each policy layer, and `read` and `take` on the intents layer. |
| the router (the unit that replaces the contact handler at stage 2) | `urn:cap:inquiry:route` | the router. It also holds `urn:cap:bayes:read:{model}` and `out` on each policy layer. |

`urn:cap:inquiry:sender-key`, `urn:cap:inquiry:block:read`, `urn:cap:inquiry:block:lift` and
`urn:cap:inquiry:count:read` are the operator's, held by the local root session; no unit above
needs them.

## One key, both sides

An intake asks its `blocklist` with keyed BLAKE3 hashes under its `block_key_file`; the edge
half writes blocks under `sender_key_file`. They must be the same key. Name the same file in
both. When any intake row, or the booking intake's `booking.json`, names a `block_key_file`
that hashes a sender differently from `sender_key_file`, the start is refused, naming the row
or the booking intake. Point the intake at the edge half's
block set with:

```json
"blocklist": "urn:iki:inquiry:block:key:{key}",
"block_key_file": "/etc/ikigai/block.key"
```

Both sides trim and lowercase an address before hashing it, and hash a domain as
`domain:<domain>`, so `  Spam@Example.org ` and `spam@example.org` are one sender.

## Importing the legacy blocklist

The contact host's decisions log keeps its blocks as `{"action":"block","email":…}` lines,
each an address or a domain. Write them once into the block set:

```text
ikigai inquiry import-blocks --from /srv/ikigai/files/decisions.jsonl --days 180
read 4, written 3, already present 0, unreadable 1
```

- `--days` is how long each block holds: 1 to 3650, default `block_days` (180).
- It prints counts only, never an address: block lines read, blocks written, blocks already
  holding (left alone), and lines that are not an address or a domain.
- It does not edit the decisions log. Remove the old lines by hand afterwards, as the
  runbook says.
- Running it again writes nothing new.
- A running host reads the block set when it starts: restart it after an import.

## What refuses the start

The binary exits with code 2 and one line beginning `ikigai:` naming `inquiry.json` and the
problem when:

- the file is not JSON, or has an unknown key, or misses `sender_key_file`, `store`, `model`
  or `owner`;
- `sender_key_file` or `store` is relative;
- the key file is missing, unreadable, open to its group or others, or not a key;
- the key file and an intake row's or `booking.json`'s `block_key_file` hold different keys;
- the owner, a layer name or the model name is not one the edge accepts;
- `block_days` is outside 1 to 3650;
- the store cannot be created, or its block set document is damaged.

For example:

```text
ikigai: /config/inquiry.json: `store` must be an absolute path, not `relative`
```
