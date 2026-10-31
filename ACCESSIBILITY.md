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
| Last reviewed | 2026-10-30 |

## What it emits that people read

- **Error pages** from the HTTP door (`crates/ikigai-web/src/error_page.rs`): a refusal, as a page,
  for a client that names `text/html` over `text/plain` (a browser); every other client gets the
  same sentence as text. A door that sets `EdgeConfig::error_page` writes that page itself for a
  browser's request; that page, its markup and its accessibility, is the door's (gonk's, say), and
  this repository guarantees only the status and headers it is served with.
- **Pages from the embedded host's HTTP face**: the emailed decision, contact-block and label
  links and the passkey enrollment page (`crates/ikigai-embedded`: `decide.rs`, `contactblock.rs`,
  `passkey.rs`, all through `decide::page`), and the contact intake's redirect page
  (`crates/ikigai-intake`).
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
- A message a script writes after the page loads goes into a status line that is a polite live
  region (`role=status aria-live=polite`), present and empty in the served markup before the
  script runs: the passkey pages' `#status` and `#pkstatus`. Its gray (`#666`) is 5.7:1 on white.
- Nothing is said by color alone. An evaluation error in either REPL starts with the word
  `error:` and the binary's own failures with `ikigai:`, a cache verdict is a word (`cached`,
  `computed`, `uncacheable`), and the full-screen REPL's colors (cyan prompt,
  green output, red error) repeat what the text already says.
- A set, non-empty `NO_COLOR` ([no-color.org](https://no-color.org)) removes every color from the
  full-screen REPL. Bold, dim and the reverse that marks the selected tab stay; they are emphasis,
  not color. The other faces write no color.
- Full-screen runbook pages keep the page name above a scrollable body. `PgUp`/`PgDn`
  scroll wrapped text, with a visible line range; `Up`/`Down` select any step and `Enter`
  runs it. `1`–`9` and `0` remain shortcuts for steps 1–10. The selected step has a `>`
  marker as well as reverse emphasis. Running a step reveals its answer, and the demo tab
  strip moves to keep the selected tab visible.
- `--plain` is a line-oriented REPL with no full-screen redraw, so a screen reader or braille
  display reads it as ordinary terminal output; `--quiet` prints only the answers. (Not yet tested
  with either; see below.)

## How it is tested

- `crates/ikigai-cli/tests/broken_pipe.rs` runs the binary with closed stdout and a
  consumer that closes after reading a response: help, version, batches, and the line REPL
  exit quietly on a broken pipe. On Linux it also checks that another stdout failure
  produces an `ikigai:` diagnostic and a failing exit status.
- `crates/ikigai-web/tests/streams.rs` and `tests/uploads.rs` pin that a `416 Range Not
  Satisfiable` and an upload's `413 Payload Too Large` are answered as the same page (`lang`,
  `main`, `h1` naming the status) for a browser.
- `crates/ikigai-web/tests/error_pages.rs` also pins an ordinary intake's pre-admission
  `413 Payload Too Large`: declared and chunked bodies negotiate the built-in page, with
  global security headers, without admission, identity, capability or custom page hooks;
  plain clients keep the sentence, and `HEAD` carries the matching length without content.
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
  layout and editing. `no_color_takes_every_color_escape_out_of_the_frame` writes a frame through
  the crossterm backend and finds no color escape in the bytes under `NO_COLOR`, and finds some
  without it.
- Runbook regression tests in `tui.rs` render at 100×40 with eighteen synthetic pages
  and twelve steps, including wrapped prose and output. They check the selected tab and
  page heading, distinct step numbers, the line range, scrolling to the answer, and
  selection/evaluation of every step through the same key handler the event loop uses.
  On 2026-10-30, a Linux PTY at 100×40 also ran `ikigai --demo` with a scratch config
  home and file root: runbook scrolling and Lisp step eleven were checked before and
  after the fix, along with selected-tab visibility and page headings. This checkout
  serves six Selection steps and eleven Lisp steps; it has no “The thread” page.
  No assistive technology was used.
- `crates/ikigai-web/tests/post_redirect_get.rs` sends raw HTTP form submissions and pins
  the route's `303` and `Location`, follows the GET and reloads it without another Sink,
  and checks the htmx answer, failed writes, page aliases, encoded captures, and refusals
  before writing when a destination cannot be addressed. These are socket tests, not
  browser or assistive technology tests.
- No automated accessibility checker (axe or similar), no browser run and no assistive technology
  has been used on any of this output.

## Known limitations

Found by reading the source on 2026-10-15, not by testing:

- The full-screen REPL redraws the whole terminal; use `--plain` with a screen reader.
- Nothing above has been tried with a screen reader, magnifier or braille display.

## Change history

| Date | Change |
|---|---|
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

| 2026-10-30 | Full-screen runbook pages (ledger #2694) gain scrolling with a visible line range, an Up/Down and Enter step picker, persistent page headings, and a tab strip that keeps the selected demo visible. Tested with the ratatui backend and a Linux PTY at 100×40 on scratch data; no assistive technology testing. |

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
