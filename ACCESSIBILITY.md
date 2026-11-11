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
| Last reviewed | 2026-11-01 |

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

## How it is tested

- `crates/ikigai-web/src/push.rs`'s
  `a_zero_stream_cap_refuses_with_the_doors_accessible_error_page` pins the stream-cap
  refusal: `503` with `Retry-After: 1`, the plain sentence "too many event streams",
  and the same sentence on the browser's error page with `lang`, `main` and the status
  heading. This is a socket test, with no browser or assistive technology evaluation.

- `crates/ikigai-cli/tests/broken_pipe.rs` runs the binary with closed stdout and a
  consumer that closes after reading a response: help, version, batches, and the line REPL
  exit quietly on a broken pipe. On Linux it also checks that another stdout failure
  produces an `ikigai:` diagnostic and a failing exit status.
- `crates/ikigai-cli/tests/lisp_bounds.rs` checks that successful `-e` evaluations under a
  sparse HOME emit only their answer and cache verdict, without Steel's missing-parent
  diagnostic. It covers default, XDG, existing `.steel` and explicit `STEEL_HOME` selection.
- `crates/ikigai-web/tests/streams.rs` and `tests/uploads.rs` pin that a `416 Range Not
  Satisfiable` and an upload's `413 Payload Too Large` are answered as the same page (`lang`,
  `main`, `h1` naming the status) for a browser.
- `crates/ikigai-web/tests/error_pages.rs` also pins an ordinary intake's pre-admission
  `413 Payload Too Large`: declared and chunked bodies negotiate the built-in page, with
  global security headers, without admission, identity, capability or custom page hooks;
  plain clients keep the sentence, and `HEAD` carries the matching length without content.
- `crates/ikigai-web/tests/redirect_answers.rs` sends raw HTTP to a read answering core's typed
  redirect and pins each status and its exact `Location`, an off-site target, the percent-encoding
  of what a URI cannot carry, `HEAD` with no body, and the page's `lang`, title, `main`, `h1`,
  escaped link and absence of style or script; that a location not `http` or `https` is never a
  link; that other clients get `text/plain`; and that `Error::Gone` is a `410` page. These are
  socket tests, with no browser or assistive technology evaluation.
- `crates/ikigai-web/tests/error_pages.rs` and the unit tests in `error_page.rs` pin the
  page's shape (`lang`, title, `main`, `h1`), escaping, which clients get a page, `Vary: Accept`,
  and that a JSON door and a success are left alone. `crates/ikigai-web/tests/door_error_page.rs`
  pins that a door's own page keeps the status and headers, is served under the door's CSP, and
  never reaches a JSON client, curl or an htmx fragment request.
- `decide.rs` (`a_page_states_its_language_and_has_one_main_holding_its_content`, and the served
  decision page in `a_get_shows_the_decision_but_records_nothing`) and the intake's
  `with_a_redirect_the_response_is_an_html_page_to_the_url` pin `lang` and the one `main`;
  `passkey.rs`'s `the_passkey_status_lines_are_live_regions_present_before_the_script` pins the
  live regions, their place before the script, and that the script writes into them;
  `the_page_shell_links_its_stylesheet_and_carries_no_inline_style` and
  `crates/ikigai-cli/tests/html_door_pages.rs` pin that the pages carry no inline style or
  script and that the stylesheet and script they name are served same-origin with their types,
  and the intake's `the_redirect_shim_carries_no_inline_style_or_script` pins the same for the
  redirect page;
  `the_register_page_has_a_labeled_code_field_the_script_sends` pins that the enrollment code
  field has a `<label>` tied to it by `for`, and comes before the button.
- The full-screen REPL is rendered against ratatui's test backend in `tui.rs`'s tests, mostly for
  layout and editing. `clock_colon_stays_visible_across_redraws` checks that the clock keeps
  its colon across frames sampled over a second, covering the former blink phase.
  `no_color_takes_every_color_escape_out_of_the_frame` writes a frame through
  the crossterm backend and finds no color escape in the bytes under `NO_COLOR`, and finds some
  without it. The runbook note tests render a step through the test backend and check every
  note cell for normal intensity, with and without `NO_COLOR`.
- Runbook regression tests in `tui.rs` render at 100×40 with eighteen synthetic pages
  and twelve steps, including wrapped prose and output. They check the selected tab and
  page heading, distinct step numbers, the line range, scrolling to the answer, and
  selection/evaluation of every step through the same key handler the event loop uses.
  On 2026-10-30, a Linux PTY at 100×40 also ran `ikigai --demo` with a scratch config
  home and file root: runbook scrolling and Lisp step eleven were checked before and
  after the fix, along with selected-tab visibility and page headings. This checkout
  serves six Selection steps and eleven Lisp steps; it has no “The thread” page.
  No assistive technology was used.
- `crates/ikigai-web/src/lib.rs`'s `a_refused_target_names_the_byte_offset`, the intake's
  `a_malformed_form_body_is_refused_with_its_byte_offset` and `people.rs`'s
  `a_form_body_is_decoded_strictly` pin the percent-decoding sentences above word for word.
- `crates/ikigai-web/tests/post_redirect_get.rs` sends raw HTTP form submissions and pins
  the route's `303` and `Location`, follows the GET and reloads it without another Sink,
  and checks the htmx answer, failed writes, page aliases, encoded captures, and refusals
  before writing when a destination cannot be addressed. These are socket tests, not
  browser or assistive technology tests.
- `crates/ikigai-web/tests/read_redirects.rs` sends raw HTTP GET and HEAD requests and
  checks the `308`, unchanged query bytes, empty body, security and route CORS/CSP headers,
  and refusals before redirecting. POST still invokes its endpoint. These are socket tests;
  no browser or assistive technology evaluation was performed.
- `crates/ikigai-cli/tests/names_served.rs` serves a named page over ikigai-ui's shell and
  checks its landmarks, skip link, escaped title and same-origin assets, that the page holds
  exactly one live status region (one `role="status"`, one `aria-live`), and that its header
  holds the theme chooser with a visible "Theme" label and the page's theme selected.
  It checks the served htmx bytes against the shell's SRI hash. The fixture can be exported
  through ikigai-ui's test kit for its shared browser/axe checker in
  light, dark and more-contrast media. This evaluates the fixture, not arbitrary author views
  or overrides. On 2026-11-01, with ikigai-ui 0.4.0, the exported page passed the shared
  checker at ikigai-ui `v0.4.0` (its `axe/` is unchanged at commit
  `adc0394bc6196ac417fddc06bcbd350af8c01b67`, where it was run) on macOS 27.0.1, using Node
  26.12.0, Chromium 156.0.8078.4, Playwright 1.64.0 and axe 4.13.0: 19 rules passed in each of
  the light, dark and more-contrast media settings, with zero failures. (At ikigai-ui 0.3.0,
  before the chooser, 14 rules had passed.)
  `crates/ikigai-embedded/tests/ui.rs` checks the override directory's read-only
  boundary, file jail and golden-thread invalidation after an editor change.
- `crates/ikigai-ipc/src/lib.rs`'s `who_is_refused` pins, word for word, the sentence that
  refuses a socket server under another UID, which reaches the terminal as an `ikigai:` line.
- `crates/ikigai-cli/tests/lobby_door.rs`'s
  `a_denied_certificate_is_reported_as_a_connection_refusal` runs the client against an
  in-process QUIC door using a real layer host's `deny.txt` decision. It pins the sentence
  naming the door and saying the client certificate is not admitted, for both `--override`
  and `--connect`, with no color escapes or Meta-renderer advice. Clearing the deny list
  admits the same certificate, and a peer without a Meta renderer keeps its contract warning.
  This is a socket test, with no assistive technology evaluation.
- The other output above has had no automated accessibility checker or browser evaluation.
  No assistive technology has been used on any of this output.

## Known limitations

Found by reading the source on 2026-10-15, not by testing:

- The full-screen REPL redraws the whole terminal; use `--plain` with a screen reader.
- On a page composed over ikigai-ui's shell from a `names` file that fixes `theme` on its binding,
  the theme chooser's Apply button, which only a browser without script uses, is answered with a
  `400` naming the fixed argument rather than the page in the chosen theme. With the shell script
  the choice applies at once. Found by a socket test on 2026-11-01. [The recipe](docs/shared-ui.md)
  now declares a `theme` input instead. Its `GET /quakes?theme=dark` was sent once through the door
  with `curl` on 2026-11-03, with ikigai-ui 0.4.1: not by a test, in a browser or through the axe
  checker. This repository's `Cargo.lock` still holds ikigai-ui 0.4.0, which also needs the
  chooser line the recipe gives.
- Nothing above has been tried with a screen reader, magnifier or braille display.

## Change history

| Date | Change |
|---|---|
| 2026-11-11 | A set `IKIGAI_LLM_CONFIG` that names no readable file, or is empty, stops startup with exit 2 and one plain `ikigai:` line on stderr naming the variable and the path, and saying to point it at an LLM registry JSON file or unset it to use the config home's `llm.json`. No color. `tests/llm_config.rs` pins the variable and the path in the line, not its full wording; no assistive technology testing was performed. |
| 2026-11-10 | A layer door whose default state directory would join a `--name` that is not one plain file name stops startup with one plain `ikigai:` line on stderr quoting the name, naming `--name`, and naming `--layers-state` and `layers.state` as the other ways to set the directory. No color. A library test pins that the line names `--name` and `--layers-state`, not its full wording; no assistive technology testing was performed. |
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
above and adds a test that pins them; a change to terminal output keeps meaning in words. Say in
the pull request what was tested, with what, and what was not.

## Reporting a barrier

[Open an issue](https://github.com/ikigai-rs/ikigai-cli/issues/new?labels=accessibility) with the
`accessibility` label (the link sets it when GitHub lets you add labels; otherwise a maintainer
adds it): what you were doing, what happened, and your terminal or browser and any assistive
technology, if you are comfortable sharing them. Anything security-sensitive goes through
[private vulnerability reporting](https://github.com/ikigai-rs/ikigai-cli/security/advisories/new).
**We acknowledge a report within 7 days**, and promise nothing further.
