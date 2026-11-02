# A page over the shared UI shell

The REPL and the general served surface bind `ikigai-ui` 0.3.0. Try:

```text
source urn:iki:ui:tokens.css
source urn:iki:ui:template:shell
```

A page can use the shared shell without Rust. Put its content in your workspace:

- `title.txt`: `Quakes & more` (text, escaped by the shell's `$h` marker).
- `header.html`: `<nav aria-label="Site"><a href="/quakes">Quakes</a></nav>`.
- `page.html`: `<h1>Quakes</h1><p>North: 4.5</p>`.
- `head.html`: an empty file, or trusted markup linking your own stylesheets.

Bind the content and the composition in a `names` file:

```text
urn:quakes:page = source urn:iki:fn:compose src=<urn:iki:ui:template:shell> family=quakes name=home theme=auto
urn:iki:ui:title:quakes:home = source urn:file:title.txt
urn:iki:ui:header:quakes = source urn:file:header.html
urn:iki:ui:head:quakes = source urn:file:head.html
urn:iki:ui:main:quakes:home = source urn:file:page.html
```

The shell uses `$h` for the title and theme, and `$r` for trusted header, head and main markup.
Escape untrusted values in your view before producing that markup. An XSLT view can supply the
main resource instead of the static `page.html` file.

Route the page and the shell's same-origin assets in `routes.json`:

```json
{"routes": [
  {"match": "/quakes", "target": "urn:quakes:page"},
  {"match": "/ui/{name}", "target": "urn:iki:ui:{name}"}
]}
```

Serve it with your workspace's absolute path as the file-read ceiling:

```sh
ikigai serve --http 8080 --names /absolute/path/to/names \
  --routes urn:file:routes.json --routes-only \
  --cap urn:cap:fs:read:/absolute/path/to/workspace
```

The page links `/ui/tokens.css`, `/ui/shell.js` and `/ui/htmx`. The shell supplies landmarks,
a skip link, a polite status region, shared themes, focus and refusal behavior, and vendored
htmx with its SRI hash. Keep the asset route when authoring your own route table; `--routes-only`
serves only paths you explicitly route. The calendar-only and layer surfaces keep their own
restricted resource sets.

## Overrides

If `<config home>/ui/` exists when the kernel starts, it is published at
`urn:iki:ui:dir:{path}`. Config home is the same directory that holds `config.toml` (normally
`$XDG_CONFIG_HOME/ikigai` or `~/.config/ikigai`; see the host's config-home rules). These files
replace the corresponding compiled artifacts:

| File | Resource |
| --- | --- |
| `shell.html` | `urn:iki:ui:template:shell` |
| `shell.js` | `urn:iki:ui:shell.js` |
| `htmx.min.js` | `urn:iki:ui:htmx` |
| `tokens.template.css` | `urn:iki:ui:template:tokens` |

The directory is deliberately public for reads, including on a door with no filesystem grant.
Its file jail refuses traversal and symlinks. Neither the artifacts nor the directory accept
Sink or Delete, even under root authority. Keep only files intended for publication there.
The directory cannot add shared artifact names or replace the tested palette tables.

REPL and serving hosts watch the directory alongside the workspace. Editing an override cuts
its golden thread, so the next read after the filesystem notification recomputes the shell
and compositions over it. Removing an override restores the compiled artifact. Create the
directory before starting the host; creating it afterward requires restarting. A custom host
constructing a kernel directly must hold `watch_workspace`'s handle to observe editor changes.

`crates/ikigai-cli/tests/names_served.rs` serves this example and its assets through HTTP.
Export that served page and its assets with ikigai-ui's test kit:

```sh
IKIGAI_UI_AXE_SITE="$PWD/target/ui-axe-site" cargo test -p ikigai-cli --locked \
  --features web --test names_served a_named_page_composes_the_shared_ui_shell
```

Run ikigai-ui's `axe/check.mjs target/ui-axe-site` over the export to check light, dark and
more-contrast media under the door's default CSP. Its README documents the checker setup
and reusable axe workflow. Custom overrides and application markup need their own
accessibility evaluation.
