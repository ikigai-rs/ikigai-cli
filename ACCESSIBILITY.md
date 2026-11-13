# Accessibility

What `ikigai-cli` emits that people read, the rules that output follows, how it is tested, and
how to report a barrier. It is not a conformance claim. Adapted from the
[ACCESSIBILITY.md template](https://github.com/mgifford/ACCESSIBILITY.md) (MIT).

| Field | Value |
|---|---|
| Target | WCAG 2.2 Level AA for the HTML this repository writes |
| Status | Evaluation in progress. No conformance claim. |
| Owner | the maintainers of this repository |
| Report a barrier | [a GitHub issue](https://github.com/ikigai-rs/ikigai-cli/issues/new?labels=accessibility) with the `accessibility` label; anything security-sensitive through [private vulnerability reporting](https://github.com/ikigai-rs/ikigai-cli/security/advisories/new) |
| Last reviewed | 2026-11-12 |

## What it emits that people read

- **Error pages** from the HTTP door (`crates/ikigai-web/src/error_page.rs`): a refusal, as a page,
  for a client that names `text/html` over `text/plain` (a browser); every other client gets the
  same sentence as text. A door that sets `EdgeConfig::error_page` writes that page itself for a
  browser's request; that page, its markup and its accessibility, is the door's (gonk's, say), and
  this repository guarantees only the status and headers it is served with.
- **Redirect pages** from the HTTP door (`crates/ikigai-web/src/redirect_answer.rs`): the body of
  a read that an endpoint answers with core's typed redirect, for a client that does not follow it
  and names `text/html` over `text/plain`; every other client gets the same target as a sentence.
- **Pages from the embedded host's HTTP face**: the emailed decision, contact-block and label
  links and the passkey enrollment page (`crates/ikigai-embedded`: `decide.rs`, `contactblock.rs`,
  `passkey.rs`, all through `decide::page`), and the contact intake's redirect page
  (`crates/ikigai-intake`).
- **Shared UI compositions**: the REPL and general served surface bind ikigai-ui artifacts
  and its page-shell template (`urn:iki:ui:*`). Author-provided views can compose that shell;
  the existing embedded-host pages above are unchanged. See [the recipe](docs/shared-ui.md).
- **Terminal text**: the full-screen REPL (`tui.rs`, the default on an interactive terminal), the
  line REPL (`--plain`, or when stdin is not a terminal), `-c` batches, scripts (`ikigai
  <file>.iki`, and `script <iri>` in either REPL), `--quiet` output, usage text and error lines.
  A script's failure is an `error:` line that names the failing line's number.
- **Pictures**: `show <iri>` writes an SVG another crate drew (for example `urn:diagram:kernel`,
  from `ikigai-diagram`) to a file and opens it. The picture's accessibility is that crate's.

Not this repository's: markup an endpoint or a workspace stylesheet produces behind a route (for
example `urn:iki:foaf`'s HTML face, from the operator's `urn:file:foaf.xsl`).

## The rules that output follows

- An error page has `<html lang="en">`, a `<title>` and one `<h1>` naming the status, a `<main>`,
  and the message as escaped text; no style, no script. Its status code is the same as the text
  answer's, and both carry `Vary: Accept`.
- A redirect page has the error page's shape: `<html lang="en">`, a `<title>` and one `<h1>` naming
  the status, a `<main>`, no style and no script, and one sentence with the target as a link whose
  text is the location, escaped. A location that is not `http` or `https` (`javascript:`, a `urn:`)
  is shown as text and is never a link. Its status and `Location` are the same as the text answer's,
  and both carry `Vary: Accept`.
- A request whose percent-encoding is malformed or does not decode to UTF-8 is a `400` whose
  sentence names the byte offset in what the client sent, in words. From the door: "malformed
  percent-escape at byte N of the request target: a % must be followed by two hex digits" (the
  `%` is in backquotes in the sentence), or "the path segment (query name, query value) at byte N
  of the request target is not UTF-8 once percent-decoded". For a form body the intake or an
  embedded-host page reads, the same words about "the form body", after "invalid argument
  `content`:". A browser gets the same sentence on the error page. Nothing is passed on with a
  literal `%` or a U+FFFD the client did not send.
- An embedded-host page (`decide::page`) and the intake's redirect page have `<html lang="en">`
  and one `<main>` holding the heading and the content, and the viewport meta, so they read on
  a phone. An embedded-host page keeps a 32rem column, and its look is one linked same-origin
  stylesheet (`/decide/css`, `urn:decide:css`) and no inline style, so a door's `style-src
  'self'` CSP applies it; without it the page is still a readable, working form in the
  browser's defaults. The intake's redirect page redirects at once and carries no style at all:
  its fallback link reads in the browser's defaults.
- A decision POST (the decision, contact-block and label pages) answers `303 See Other` to an
  outcome page on the same path (`?outcome=<word>`), so the browser's history holds a GET: going
  back or restoring the tab shows the outcome again and never asks to post again. The outcome
  page is a `decide::page` like the others, says what happened in one sentence, and works with no
  script.
- A web route can name a success page IRI with `redirect` (`ik:redirect` in RDF). A
  successful plain form POST answers `303 See Other` to that page on the same origin, so
  restoring or reloading the resulting page uses GET. `HX-Request: true` keeps its in-place
  answer. The route supplies no HTML; the destination page owns its markup.
- A host can declare read redirects in `EdgeConfig::read_redirects`: GET and HEAD answer
  `308 Permanent Redirect` to a same-origin path, keeping the raw query. The answer carries
  no page body and uses the existing HEAD and security/CORS policy after intake and admission.
- A message a script writes after the page loads goes into a status line that is a polite live
  region (`role=status aria-live=polite`), present and empty in the served markup before the
  script runs: the passkey pages' `#status` and `#pkstatus`. Its gray (`#666`) is 5.7:1 on white.
- Nothing is said by color alone. An evaluation error in either REPL starts with the word
  `error:` and the binary's own failures with `ikigai:`, a cache verdict is a word (`cached`,
  `computed`, `uncacheable`), and the full-screen REPL's colors (cyan prompt,
  green output, red error) repeat what the text already says.
- A set, non-empty `NO_COLOR` ([no-color.org](https://no-color.org)) removes every color from the
  full-screen REPL. Bold, dim and the reverse that marks the selected tab stay; they are emphasis,
  not color. Runbook content, including step notes, is never dim; faint styling is reserved
  for chrome such as hints and separators on those pages. The other faces write no color.
- Full-screen runbook pages keep the page name above a scrollable body. `PgUp`/`PgDn`
  scroll wrapped text, with a visible line range; `Up`/`Down` select any step and `Enter`
  runs it. `1`–`9` and `0` remain shortcuts for steps 1–10. The selected step has a `>`
  marker as well as reverse emphasis. Running a step reveals its answer, and the demo tab
  strip moves to keep the selected tab visible.
- The full-screen REPL clock uses a steady colon; it does not blink.
- `--plain` is a line-oriented REPL with no full-screen redraw, so a screen reader or braille
  display reads it as ordinary terminal output; `--quiet` prints only the answers. (Not yet tested
  with either; see below.)
- Terminal reads choose `text/plain` when no `as` is supplied and the target's Source
  contract offers that face, including `-c` and the line REPL. Faces come from the `as`
  input's `one_of` list, or the action's outputs when there is no such list. Explicit types
  are preserved. Without a text face or a readable contract, the request keeps its default.
  An explicit face supplied as an attached body is also preserved.
  The selected face keeps its declared media-type parameters. Only a Meta answer
  labeled `application/json` is used for this negotiation. The shared kernel and
  HTTP door keep their defaults, including runbook HTML. The audit's reproduced
  pipeline and duplicate-contract-read limitations are documented in
  [the terminal resolver audit](docs/audits/terminal-resolver-3417.md).

## How it is tested

Every check named here has a result: Pass, Fail or Blocked, with its evidence. A Pass covers
only the stated check, on this repository's `main` as of the date given, not the output's
accessibility as a whole. Every Pass below was run on 2026-11-12 on macOS 27.2 (arm64) with
Rust and Cargo 1.99.1, by the command in its row; CI (`.github/workflows/ci.yml`) runs the same
tests on every pull request under `cargo test --workspace --all-features` on Linux and macOS. A
run that CI does not repeat (a browser, a checker, a PTY session) is Blocked with its date, not
Pass. None of these tests is a browser or assistive technology evaluation.

| Check | Result | Evidence |
|---|---|---|
| Error page shape: `lang`, title, one `h1` naming the status, `main`, escaped message, no style or script; which clients get a page; `Vary: Accept` | Pass | `cargo test -p ikigai-web --locked`: the unit tests in `error_page.rs`, `tests/error_pages.rs` (also an ordinary intake's pre-admission `413`, declared and chunked, with `HEAD`), `tests/streams.rs` (`416`), `tests/uploads.rs` (`413`), and `push.rs`'s `a_zero_stream_cap_refuses_with_the_doors_accessible_error_page` (`503`, `Retry-After: 1`, "too many event streams"). `tests/door_error_page.rs` pins that a door's own page keeps the status and headers, is served under the door's CSP, and never reaches a JSON client, curl or an htmx fragment request. Socket and unit tests; the markup is not rendered. |
| Redirect page shape; a target that is not `http` or `https` is never a link; `410 Gone` page | Pass | `cargo test -p ikigai-web --locked --test redirect_answers`: raw HTTP pins each status and exact `Location`, an off-site target, percent-encoding, `HEAD` with no body, the page's `lang`, title, `main`, `h1`, escaped link and absence of style or script, and `text/plain` for other clients. Socket tests. |
| Percent-decoding refusals name the byte offset in words | Pass | `cargo test -p ikigai-web -p ikigai-intake -p ikigai-embedded --locked`: `ikigai-web`'s `a_refused_target_names_the_byte_offset`, the intake's `a_malformed_form_body_is_refused_with_its_byte_offset` and `people.rs`'s `a_form_body_is_decoded_strictly` pin the sentences word for word. |
| Post/Redirect/Get and read redirects | Pass | `cargo test -p ikigai-web --locked --test post_redirect_get --test read_redirects`, and `cargo test -p ikigai-cli --locked --all-features --test decision_prg`: the `303` and `Location`, a reload without another Sink, the htmx answer, failed writes and refusals; the `308` with unchanged query bytes and an empty body. Socket tests. |
| Embedded-host and intake pages: `lang`, one `main`, linked same-origin stylesheet, no inline style or script, live status regions present before the script, labeled code field | Pass | `cargo test -p ikigai-embedded -p ikigai-intake --locked`: `decide.rs`'s `a_page_states_its_language_and_has_one_main_holding_its_content`, `the_page_shell_links_its_stylesheet_and_carries_no_inline_style` and `a_get_shows_the_decision_but_records_nothing`; `passkey.rs`'s `the_passkey_status_lines_are_live_regions_present_before_the_script` and `the_register_page_has_a_labeled_code_field_the_script_sends`; the intake's `with_a_redirect_the_response_is_an_html_page_to_the_url` and `the_redirect_shim_carries_no_inline_style_or_script`. Also `cargo test -p ikigai-cli --locked --all-features --test html_door_pages`: the stylesheet and script the pages name are served same-origin with their types. String checks of the markup; the `#666` gray's 5.7:1 is computed, not tested. |
| Shared ikigai-ui shell page: landmarks, skip link, escaped title, one live status region, labeled theme chooser, same-origin assets with the SRI hash | Pass | `cargo test -p ikigai-cli --locked --all-features --test names_served`, with ikigai-ui 0.5.0 from `Cargo.lock`. Serves a named page over the shell and checks its markup as strings. It covers the fixture's `theme=auto` binding, not the recipe's `theme` input, author views or overrides. `crates/ikigai-embedded/tests/ui.rs` checks the override directory's read-only boundary, file jail and invalidation. |
| Automated accessibility checker (axe) on the shared shell page | Blocked | Not run on `main`: this machine had no Node for ikigai-ui's `axe/check.mjs`, and CI does not run it. Historical: on 2026-11-01, with ikigai-ui 0.4.0, the page exported by `names_served` passed 19 axe rules with zero failures in light, dark and more-contrast media (ikigai-ui `axe/` at commit `adc0394bc6196ac417fddc06bcbd350af8c01b67`, macOS 27.0.1, Node 26.12.0, Chromium 156.0.8078.4, Playwright 1.64.0, axe 4.13.0). `Cargo.lock` now holds ikigai-ui 0.5.0, which has not been checked. [The recipe](docs/shared-ui.md) gives the export command. |
| Automated accessibility checker on the error, redirect, embedded-host and intake pages | Blocked | No axe or other checker has been run on these pages, and CI runs none. |
| Full-screen REPL: `NO_COLOR` removes every color, the clock keeps its colon, runbook notes are not dim, runbook scrolling, step picker and tab visibility | Pass | `cargo test -p ikigai-cli --locked --all-features --bin ikigai`, its `tui::` tests: `no_color_takes_every_color_escape_out_of_the_frame` writes a frame through the crossterm backend and finds no color escape under `NO_COLOR`, and some without it; `clock_colon_stays_visible_across_redraws`; the runbook note tests check every note cell for normal intensity with and without `NO_COLOR`; the runbook regressions render at 100×40 with eighteen pages and twelve steps and drive the same key handler as the event loop. Ratatui's test backend, not a terminal. |
| Full-screen runbook in a real terminal | Blocked | Not repeated on `main`, and CI runs no PTY. Historical: on 2026-10-30 a Linux PTY at 100×40 ran `ikigai --demo` with a scratch config home and file root, checking runbook scrolling, Lisp step eleven, selected-tab visibility and page headings. |
| Terminal reads choose the text face; `-c` and line REPL output | Pass | `cargo test -p ikigai-cli --locked --all-features --test runbook_text`: an untyped runbook read in `-c` and the line REPL equals its explicit `text/plain` face; explicit HTML and JSON, quoted names and a pipeline are kept. Resolver and kernel unit tests (`cargo test -p ikigai-cli --locked --all-features --bin ikigai`) cover the shared kernel's HTML default, explicit HTML, a resource without a text face, unreadable contracts and `one_of` declarations. The two limitations [the audit](docs/audits/terminal-resolver-3417.md) reproduced (a by-reference pipe's face, a second contract read) are ignored tests there, not part of this Pass. |
| Terminal diagnostics are words, with no color escape | Pass | `cargo test -p ikigai-cli --locked --all-features --test broken_pipe --test lisp_bounds --test lobby_door --test config_toml --test llm_config --test batch_summary`, and `cargo test -p ikigai-ipc --locked` (`who_is_refused`). They pin the `ikigai:` and `error:` lines' words (in full, or the parts each row of the change history names); `lobby_door` also checks for no color escapes. `broken_pipe`'s check that another stdout failure produces an `ikigai:` line runs on Linux only, so it ran in CI, not on this machine. |
| No-script theme Apply with the recipe's `theme` input | Blocked | No test covers it. Historical: one `GET /quakes?theme=dark` sent with `curl` through the door with ikigai-ui 0.4.1 on 2026-11-03; not repeated with 0.5.0, in a browser, or through axe. |
| Browser rendering, reflow at 320 px and zoom of the HTML pages | Blocked | No browser run has been recorded for the error, redirect, embedded-host or intake pages; no browser was configured for this review. |
| Manual keyboard | Blocked | No person has made a keyboard pass of the HTML pages or the full-screen REPL; no interactive session was available for this review. |
| Screen reader | Blocked | No screen reader has been used on any of this output, including `--plain`; none was available for this review. |
| Screen magnifier | Blocked | No screen magnifier has been used on this output; none was available for this review. |
| Speech input | Blocked | No speech-input software has been used on this output; none was available for this review. |
| Switch access | Blocked | No switch-access software has been used on this output; none was available for this review. |
| Braille display | Blocked | No braille display has been used on this output, including `--plain`; none was available for this review. |

### ikigai-ui's per-kind criteria

ikigai-ui names accessibility criteria per kind of control
(`urn:iki:ui:criterion:kind:{kind}:target:{target}`, ikigai-ui [PR 65](https://github.com/ikigai-rs/ikigai-ui/pull/65),
[66](https://github.com/ikigai-rs/ikigai-ui/pull/66) and [67](https://github.com/ikigai-rs/ikigai-ui/pull/67)). This repository
relies on none of them: it binds ikigai-ui 0.5.0 (`Cargo.lock`), whose source names no
criterion, and it uses the page shell and its artifacts (tokens, palettes, the theme chooser, htmx). So
no SEE check of a kind is verified by a test here, and every HEAR check is Blocked: no
screen-reader job runs yet. ikigai-ui's own `ACCESSIBILITY.md` holds the results for its
controls.

## Known limitations

Found by reading the source on 2026-10-15, not by testing:

- The full-screen REPL redraws the whole terminal; use `--plain` with a screen reader.
- On a page composed over ikigai-ui's shell from a `names` file that fixes `theme` on its binding,
  the theme chooser's Apply button, which only a browser without script uses, is answered with a
  `400` naming the fixed argument rather than the page in the chosen theme. With the shell script
  the choice applies at once. Found by a socket test on 2026-11-01. [The recipe](docs/shared-ui.md)
  now declares a `theme` input instead. Its `GET /quakes?theme=dark` was sent once through the door
  with `curl` on 2026-11-03, with ikigai-ui 0.4.1: not by a test, in a browser or through the axe
  checker. This repository's `Cargo.lock` now holds ikigai-ui 0.5.0, and the recipe has not been
  sent through the door with it; the recipe's text still names 0.4.0 and 0.4.1.
- Nothing above has been tried with a screen reader, magnifier, speech input, switch access or
  braille display.

## Change history

| Date | Change |
|---|---|
| 2026-11-12 | "How it is tested" becomes a Check, Result and Evidence table in the a11y sweep's Pass, Fail and Blocked form: every check names its result and evidence, each Pass was rerun on `main` with the command in its row, and runs CI does not repeat (the 2026-11-01 axe run, the 2026-10-30 PTY run, the 2026-11-03 `curl`) are Blocked with their dates. Screen reader, magnifier, speech input, switch access and braille display rows are Blocked. A section says this repository relies on none of ikigai-ui's per-kind criteria. The known limitation that said `Cargo.lock` holds ikigai-ui 0.4.0 now says 0.5.0. Docs only; no output changed. |
| 2026-11-11 | The batch summary labels cache counts as “request outcomes” (ledger #2699), so pipeline and fan-out requests are distinguished from commands. A binary regression checks two commands with six request outcomes. No color is added; no assistive technology testing was performed. |
| 2026-11-11 | A set `IKIGAI_LLM_CONFIG` that names no readable file, or is empty, stops startup with exit 2 and one plain `ikigai:` line on stderr naming the variable and the path, and saying to point it at an LLM registry JSON file or unset it to use the config home's `llm.json`. No color. `tests/llm_config.rs` pins the variable and the path in the line, not its full wording; no assistive technology testing was performed. |
| 2026-11-10 | A layer door whose default state directory would join a `--name` that is not one plain file name stops startup with one plain `ikigai:` line on stderr quoting the name, naming `--name`, and naming `--layers-state` and `layers.state` as the other ways to set the directory. No color. A library test pins that the line names `--name` and `--layers-state`, not its full wording; no assistive technology testing was performed. |
| 2026-11-11 | Terminal reads (ledger #2695) choose the text face when the caller names no type and the target's contract offers `text/plain`. The policy applies to every resource family. Binary regressions reproduced HTML in both `-c` and the line REPL before the fix and now compare the output to explicit `text/plain`; explicit HTML/JSON and the shared kernel's HTML default are preserved. No assistive technology testing was performed. |
| 2026-11-10 | A socket server closing during the version hello is reported as unavailable, with a plain sentence saying it may be restarting or predate wire v6, and advising a retry or server update. Socket tests cover a legacy decoder closing, a partial hello, and a close during redial. No assistive technology testing was performed. |
| 2026-11-10 | A `config.toml` line the host cannot read, or an unknown key in one of the host's own families (another program's keys are left alone), stops startup with one plain `ikigai:` line on stderr naming the file, the line number and the line or key in backquotes, and saying what to write instead. No color. `tests/config_toml.rs` pins the file, line number and key in the sentence, not its full wording; no assistive technology testing was performed. |
| 2026-11-09 | A QUIC door being drained (ledger #3325) closes its connections with the reason `this door is shutting down; reconnect to continue`, a plain sentence that can reach a person inside a transient `unavailable` error on a call whose reply was lost, in the same place the age bound's reason already can. No new output otherwise and no color. The sentence is not pinned by a test; no assistive technology testing was performed. |
| 2026-11-09 | The HTTP door answers core's new outcomes (ledger #3151). `Error::Gone` is a `410 Gone`, on the existing negotiated error page. A read answering core's typed redirect is sent as its status with `Location`, and a client asking for HTML gets a new short page with the target as a link (shown as text when it is not `http` or `https`); any other client gets a `text/plain` sentence. Socket tests pin both; no browser or assistive technology testing was performed. |
| 2026-11-08 | A QUIC door's refusal after TLS (ledger #3304) says that the door refused the connection and the client certificate is not admitted, before a mount or direct connection asks for contracts. A socket regression pins the sentence and distinguishes an admitted peer without a Meta renderer. Plain `ikigai:` line, no color; no assistive technology testing was performed. |
| 2026-11-07 | The full-screen REPL clock (ledger #2696) keeps a steady colon instead of blinking indefinitely. A ratatui test-backend regression reproduces the missing colon before the fix and checks it stays visible across redraws after it. No assistive technology testing was performed. |
| 2026-11-06 | The HTTP door refuses a push stream beyond `PushConfig::max_streams` with `503`, `Retry-After: 1` and "too many event streams", using the existing negotiated error page. A socket regression pins the sentence and page landmarks; no assistive technology testing was performed. |
| 2026-10-15 | First version ([PR 521](https://github.com/ikigai-rs/ikigai-cli/pull/521)). |
| 2026-10-15 | The embedded host's pages and the intake's redirect page gain `<html lang="en">` and a `<main>`; the passkey status lines become live regions; the full-screen REPL honors `NO_COLOR`. Three known limitations removed ([PR 522](https://github.com/ikigai-rs/ikigai-cli/pull/522)). |
| 2026-10-15 | Reports use the `accessibility` issue label instead of a word in the title; `AGENTS.md` (with `CLAUDE.md` a link to it) asks for this file to be read before any change to rendered output. |
| 2026-10-15 | `ikigai layers post` and `ikigai layers save` (ledger #1629) add terminal text under the same rules: plain lines, no color, the entry's IRI or a `saved …` line on stdout, and every refusal on stderr starting with `ikigai:`. |
| 2026-10-16 | The passkey register page gains a field for the enrollment window's one-time code (ledger #1689): a visible `<label>` tied to the input by `for`, `autocomplete=one-time-code`, placed before the button; a missing code is reported in the existing `#status` live region and moves focus to the field. |
| 2026-10-17 | The embedded host's pages move their inline styles, unchanged in value, into one served stylesheet, `/decide/css` (ledger #1834). The door's CSP had been dropping the inline styles in a browser, so on the edge the column width, the button padding and the muted gray now apply where they did not. |
| 2026-10-18 | The intake's redirect page drops its inline `<style>` (ledger #1866). The door's CSP had been dropping it in a browser already, so on the edge the page looks as it did: browser defaults, for the instant before the redirect. |
| 2026-10-18 | A decision, contact-block or label POST answers `303 See Other` to an outcome page (Post/Redirect/Get, ledger #1879), so a phone that returns to the tab no longer asks to post again; the outcome page names no address or booking, and a second POST of the same link says "Already recorded". |
| 2026-10-26 | The HTTP door moves onto hyper (ledger #2236). Its error pages are unchanged. A request hyper cannot parse (a malformed request line or header, an unreadable `Content-Length`, a transfer coding that does not end in `chunked`) is now answered by hyper with its status and no sentence, where the door's own `400` carried one (`malformed request`, `malformed Content-Length`); a refusal the door makes keeps its sentence and its page. |
| 2026-10-28 | The line under an unresolved name in the REPLs and `-c` (ledger #2481) becomes two plain lines indented under `error:`: this build binds no such name, and an upgrade may help only if `cargo search ikigai-cli` names a newer release. It no longer says the name is newer than the build. No color is added. |
| 2026-10-29 | The REPL's names layer (ledger #2515) adds terminal text under the same rules: `source urn:iki:space:dynamic:names:status` appends plain lines (`names file:`, `not read:`, `shadowed: <name> …`) to the dynamic space's status, a names file that does not read is said once on stderr starting with `ikigai:`, and a config home holding both `names` and `names.ttl` stops the start with an `ikigai:` line naming both. No color is added. |
| 2026-10-29 | The usage text gains four plain lines under the mount flags (ledger #2613): a read through any mount is `uncacheable` here even when the peer's endpoint is cacheable, and why. No color is added. |
| 2026-10-30 | `serve --http … --names <file>` (ledger #2516) adds terminal text under the same rules: the usage text gains plain lines for the option, the door's banner says `names from <file>`, a names file that does not read and a binding a served name shadows are said on stderr starting with `ikigai:`, and `--names` on another door stops the start with an `ikigai:` line. The door's pages are unchanged: a name answers as its target does. No color is added. |
| 2026-10-30 | Config-home startup jobs (ledger #2678) report a refused file as a plain `ikigai: <path>/jobs:<line>: …` line on stderr and stop startup with exit 2. A refused live edit says it keeps the previous jobs. The daemon banner says “timers + watchers” when no standing sync is configured, since declared jobs can still run. Binary tests pin the startup and live-edit diagnostics; no assistive technology testing was performed. |
| 2026-10-30 | The outbound HTTP transport times out (ledger #2692). A bad `http.timeout` stops startup with exit 2 and one plain `ikigai: \`http.timeout = …\` …` line on stderr naming the key, what it must be and the config file. A request past the bound reads as the REPL's existing `error: timeout: …` line. Binary tests pin both; no color is added and no assistive technology testing was performed. |
| 2026-10-31 | A refused `cap` stops a `-c` batch and blocks subsequent evaluation in both REPLs until an explicit valid narrowing or reset (ledger #2717). The plain `error:` diagnostic names how to resume; no color is added. Binary tests cover batches, stdin replay, and scripts; a TUI unit test covers command and scratch evaluation. No assistive technology testing was performed. |
| 2026-10-31 | An alias mount deeper than one segment forwards names unchanged (ledger #2735). The usage text gains three plain lines under `--mount` stating the rule, and the startup banner's and `urn:host:posture`'s `mount` line for such a mount ends `[names forwarded unchanged under <prefix>]`. A unit test pins the line; no color is added and no assistive technology testing was performed. |
| 2026-10-30 | Full-screen runbook pages (ledger #2694) gain scrolling with a visible line range, an Up/Down and Enter step picker, persistent page headings, and a tab strip that keeps the selected demo visible. Tested with the ratatui backend and a Linux PTY at 100×40 on scratch data; no assistive technology testing. |
| 2026-10-31 | Full-screen runbook step notes (ledger #2734) use normal intensity because they carry page content. Ratatui test-backend regressions check note cells with and without `NO_COLOR`; color behavior is unchanged. No assistive technology testing was performed. |
| 2026-11-01 | The local root and general served surface bind ikigai-ui's shared shell and artifacts (ledger #2822), with read-only config-home overrides. A named-page HTTP fixture can be exported for the shared axe checker; the existing embedded pages and REPL text are unchanged. No assistive technology testing was performed. |
| 2026-11-01 | Percent-decoding moves onto `ikigai_fn::html` (ledger #1878). The door's `400` for a malformed or non-UTF-8 request target now names the byte offset (it said only `malformed percent-escape` or `not UTF-8 once decoded`). The intake and the embedded host's form pages now refuse such a form body with a `400` naming the offset, where they kept a malformed escape literally and replaced invalid UTF-8 with U+FFFD. An intake configured with a redirect that is not a link target is refused at load (`try_submit`) with a sentence naming the intake and the redirect, where it was silently ignored. Unit tests pin each sentence; no assistive technology testing was performed. |
| 2026-11-01 | The served shell moves to ikigai-ui 0.4.0 (ledger #2854). Every page over it holds one announcing status region (`role="status"`, `aria-live="polite"`; ikigai-ui's notes are tied by `aria-describedby` and carry no role), and a theme chooser in its `<header>` after the page's own header: a GET form with a visible "Theme" label, a native select of Auto (system), Light, Dark and High contrast in words, and an Apply button the shell script hides. A `names`-file page must now name its chooser (`urn:iki:ui:chooser:{family}:{theme}`); the recipe says how. The socket test pins the one region and the chooser; the shared axe checker passed 19 rules in light, dark and more-contrast media. No assistive technology testing was performed. |
| 2026-11-02 | The idle-stdin warning (ledger #2437) drops its hard-coded `content=…` advice. The engine's following missing-argument diagnostic already names the required input and how to supply it (for example, `in=…` for a Source). A binary regression holds stdin open and silent and pins that the output gives the correct `in=…` hint without conflicting `content=…` advice. No color is added; no assistive technology testing was performed. |
| 2026-11-02 | `--grants <file>` becomes a global host flag. A set `IKIGAI_GRANTS` stops startup with a plain `ikigai:` diagnostic naming the variable and replacement flag. Binary regression tests cover the refusal and the socket host's flag; no assistive technology testing was performed. |
| 2026-11-02 | The global `--grants` parser names `<file>` in missing-value refusals (ledger #2952). Library grant lookups preserve the `IKIGAI_GRANTS` refusal instead of reporting an unknown grant. Library and binary regression tests pin these diagnostics; no color is added and no assistive technology testing was performed. |
| 2026-11-03 | The `names`-file recipe in `docs/shared-ui.md` declares a `theme` input instead of fixing `theme`, so a no-script Apply is answered with the page in the chosen theme, and it names the override for turning the chooser off (ledger #2955). Docs only, so no output changed. One `GET /quakes?theme=dark` was sent through the door with `curl` and ikigai-ui 0.4.1. No test covers it, and no browser, axe or assistive technology testing was performed. |
| 2026-11-09 | `--clients <file>` names the client enrollment file. A set `IKIGAI_CLIENTS`, a `--clients` file that is not there, and `--clients` on a mode that reads no enrollment each stop startup with a plain `ikigai:` line on stderr; the usage text gains three plain lines. Binary and library regression tests pin the diagnostics; no color is added and no assistive technology testing was performed. |
| 2026-11-08 | A layer door's refusal of an unlisted certificate with no lobby capability (ledger #3295) says on stderr that the host's `deny.txt` names it or the host has no lobby now, where it said only that the host has no lobby. Plain `ikigai:` line, no color. No test pins this wording, and no assistive technology testing was performed. |
| 2026-11-09 | `ikigai serve … --mount <p>=<t> --pending` (ledger #3169) adds terminal text under the same rules: six plain usage lines (which also say a served host's mount flags go after the word `serve`), the startup banner's and `urn:host:posture`'s `mount` line for such a mount carries `[pending: dials on first use, Unavailable until the peer answers]`, and a misplaced `--pending` stops the start with a plain `ikigai:` line naming the rule. A binary regression pins the banner, unit tests pin the refusals; no color is added and no assistive technology testing was performed. |
| 2026-11-09 | A host with no usable config home, or no usable home for its default workspace, stops at startup with exit 2 and one plain `ikigai:` line on stderr naming `XDG_CONFIG_HOME`, `HOME`, `USERPROFILE` and `--config-home`, or `HOME`, `USERPROFILE` and `--files`. The default socket's banner names an absolute path. Binary tests pin the lines; no color is added and no assistive technology testing was performed. |
| 2026-11-07 | The org-directory file jail identifies itself as `orgfile` in descriptions and arrangement dumps (ledger #2751), so a declared arrangement can distinguish it from the workspace's `file` endpoint. The resource IRIs stay the same. Binary arrangement tests cover both named jails and loading the default dump; no browser or assistive technology testing was performed. |

## Contributing

Read this file before changing any output listed above. A change to an HTML page keeps the rules
above and adds a test that pins them; a change to terminal output keeps meaning in words. In the
pull request's `## Accessibility` section, give each check a row in a Check | Result | Evidence
table: Pass, Fail or Blocked, with the test or command, the tool and its version, or why it could
not run. Keep a check nobody ran as Blocked, including a screen reader nobody used; never call it
"not applicable" and never leave it out.

## Reporting a barrier

[Open an issue](https://github.com/ikigai-rs/ikigai-cli/issues/new?labels=accessibility) with the
`accessibility` label (the link sets it when GitHub lets you add labels; otherwise a maintainer
adds it): what you were doing, what happened, and your terminal or browser and any assistive
technology, if you are comfortable sharing them. Anything security-sensitive goes through
[private vulnerability reporting](https://github.com/ikigai-rs/ikigai-cli/security/advisories/new).
**We acknowledge a report within 7 days**, and promise nothing further.
