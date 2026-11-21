# Where each host takes its authority at startup (ledger #2950)

Every input that can widen or redirect a host's authority before its first request, for the
Operations Book. Audited at commit b0e87cc: `ikigai` 0.4.2 and `ikigai-layers` 0.9.4. "Driven"
rows were observed against the real binary; the others were read from source. One account was
available, so behavior that crosses a real second account was not driven. Windows and macOS were
not covered.

"Peer" means a client admitted to a door. No input below can be changed by a peer unless its row
says so. Inputs that only the process starter controls name no writer.

## `ikigai` (the binary, embedded host, and ipc, quic and web doors)

### Environment (set by whoever starts the process)

| Input | Protection checked | Missing or malformed | Basis |
| --- | --- | --- | --- |
| `HOME`, `USERPROFILE` | Value trusted | Unset or empty `HOME`: the config home is relative to the working directory. `USERPROFILE` is used when `HOME` is unset or empty | Driven |
| `XDG_CONFIG_HOME` | Value trusted; a relative value is accepted | Empty counts as unset. Relative: resolved against the working directory. `--config-home` wins | Driven |
| `XDG_RUNTIME_DIR`, `TMPDIR` | Socket directory set to 0700 | Unset: `/tmp/ikigai-<uid>/ikigai`. Empty: socket under the working directory | Driven |
| `IKIGAI_GRANTS` | Refused whenever set | Exits 2 naming `--grants` | Driven |
| `IKIGAI_CLIENTS` | Not checked; overrides `--config-home` | Empty or a missing path reads as no enrollment file. Malformed stops the door | Driven |
| `IKIGAI_FILES` | Not checked | Empty ignored; otherwise used, created if missing | Source |
| `IKIGAI_CALENDAR_CONFIG`, `IKIGAI_LLM_CONFIG`, `IKIGAI_LLM_ANNOTATIONS` | Not checked | Missing skipped; malformed warns and falls back | Driven (calendar, LLM config) |
| `IKIGAI_SECRETS` | Relative value refused; refused with no `HOME` | Refused rather than guessed | Source |
| `IKIGAI_SCHEDULER`, `IKIGAI_REPO_ROOT`, `IKIGAI_DRAIN_EVERY`, `IKIGAI_SMTP_*`, `IKIGAI_MAIL_FROM`, `IKIGAI_DECIDE_BASE`, `IKIGAI_CONTACTBLOCK_BASE`, `IKIGAI_CONTACTLABEL_BASE`, `IKIGAI_BOOKING_URL`, `STEEL_HOME` | Not checked | Unset uses the default | Source |
| `CARGO_*`, `OUT_DIR` | Build time only | Build fails | Source |

### Command-line flags and unit arguments (set by whoever starts the process)

No unit file ships in this repository; flags in a systemd or launchd unit have the protection of
that unit file, which the binary does not check.

| Input | Protection checked | Missing or malformed | Basis |
| --- | --- | --- | --- |
| `--config-home` | Owner and mode not checked | Must resolve to an absolute path; two different values refused | Driven |
| `--grants` | Only with `--principal` (`check_protected`: file, folders above it, symlinks) | With `--principal`: missing or unprotected refused. With `serve <socket>`: a missing path reads as no principals | Driven |
| `--files` | Passkey HTTP door refuses a group- or world-writable workspace | Created at 0700. Peers stay in their own workspace segment | Driven |
| `--cert-dir`, `--server-cert`, `--server-key`, `--client-cert`, `--client-key` | Owner and mode not checked | Missing stops with the path named | Driven |
| `serve <target>`, `--http` | A bare port binds loopback | Parse or bind failure exits | Driven |
| `--cap` | Operator ceiling | A bare flag is refused (exit 2) | Driven |
| `--require-enrollment` | Refuses without `clients.json` | Stops the door | Driven |
| `--name` | Path form not filtered | Joined into the default layer state path | Driven |
| `--mount`, `--override`, `--prefer`, `--no-config-mounts`, `--pending` | Operator topology | An undialable peer stops the start unless `--prefer` or `--pending` | Driven |
| `--code-signer`, `--code-signers-dir`, `--arrangement`, `--names` | Owner and mode not checked | Missing key answers NotFound; a bad arrangement stops the start | Source |
| `--layers-state`, `--layers-key`, `--layers-reseal` | State directory set to 0700; key owner and mode not checked | Missing or wrong key refused | Driven |
| `--trust-proxy`, `--passkey-*`, `--cors-origin`, `--routes`, `--max-body` and other serving flags | Validated at startup | A bad value stops the door | Source |

### The config home (writable by its owner)

| Input | Protection checked | Missing or malformed | Peer | Basis |
| --- | --- | --- | --- | --- |
| `config.toml` | Owner and mode not checked | Absent: defaults. Unreadable or not UTF-8 stops every mode. Unknown keys and lines without `=` are not errors | No, unless `files` is pointed at the config home | Driven |
| `grants.json` | Checked for `--principal` and for socket accounts; not for the QUIC door | MCP refuses and the socket door refuses on a parse error. The QUIC door starts and refuses each client | No | Driven |
| `clients.json` | Owner and mode not checked; re-read per connection | Missing: posture falls through, except the layer door and `--require-enrollment`, which refuse. Malformed stops the door | No | Driven |
| `quic/server.*`, `quic/client.*` | Generated 0700 and 0600; not checked at load | Missing stops the door | No | Driven |
| `quic/clients/*.crt` | Not checked; re-read at every handshake | Malformed at start exits 1 after the banner; added while serving is tolerated | Only through a controller-signed layer entitlement | Driven (source for the entitlement) |
| `quic-<name>/` | The name must be one path segment; contents not checked | `peer:` mounts need a pinned certificate | No | Source |
| `layer-tokens.json` | Saved 0600; not checked at load | Malformed refuses every token | No | Source |
| `calendar.json`, `llm.json`, `code-signers/`, `names`, `store.toml`, `a11y.toml` | Not checked | Calendar and LLM warn and ignore; a bad store stops the process | No | Driven (calendar, LLM config) |
| `layers/` | Not checked; its presence selects the layer door | Absent: no layer door, and layer flags are refused | No | Driven |
| Passkey credentials | Mode and directory checked at start | Unsafe mode refused with a `chmod` hint | Written by ceremonies through the HTTP door, by design | Driven |

### Fixed defaults

| Input | Behavior | Basis |
| --- | --- | --- |
| Socket door | 0600 socket; the owner uid holds root authority; other uids need an entry in `principals` | Driven |
| HTTP door | Public capability when `--cap` is absent | Driven |

## `ikigai-layers` 0.9.4

| Input | Written by | Protection checked | Missing or malformed | Peer | Basis |
| --- | --- | --- | --- | --- | --- |
| `ikigai-layers grants <dir>`, `onboard setup` | Operator | Not checked | A missing directory is treated as empty and files are written | No | Driven |
| `layers/*.toml`, `collabs/*.toml`, shapes, `layers.toml` | Config home owner | Owner and mode not checked | Malformed stops the host | No | Source |
| `participants.ttl`, `enrollment.toml`, `entitlements.toml` | Config home owner; `Onboard::apply` | Owner and mode not checked | Missing is empty; malformed errors | Through controller-signed entitlements | Source |
| `deny.txt` | Config home owner | Owner and mode not checked | Absent is empty; an unreadable file refuses at connect | No | Source |
| State directory | Host process | Set to 0700 | Wrong key refused; plaintext refused without `--layers-reseal` | Writes through the layer model only | Driven |
| Age identity | Operator | Owner and mode not checked | Missing or malformed refused | No | Driven |
| `trust_dir` | `Onboard::apply`, operator | Private directory | Created if missing | A controller-signed entitlement adds a certificate; revocation removes it | Source |

## `ikigai-gonk` (read from source only, nothing driven)

| Input | Written by | Notes from source |
| --- | --- | --- |
| `HOME`, `XDG_CONFIG_HOME` | Process starter | The only environment read for configuration; refuses when neither home is known |
| `--config-home`, `--data-home`, `--store`, `--config` | Process starter | Made absolute |
| `config.toml`, `store.toml`, `gonk.store.toml` | Config home owner | Absent reads empty |
| `gonk/clients.json`, `gonk/grants.json`, `gonk/quic/` | Config home owner | Written 0600; server identity generated on first use |
| Invite and session files | gonk process | Written 0600 |
| Unit arguments | Operator | The README and `docs/fresh-machine.md` show a systemd user unit; nothing enforces it |
