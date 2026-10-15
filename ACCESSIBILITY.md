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
| Last reviewed | 2026-10-15 |

## What it emits that people read

- **Error pages** from the HTTP door (`crates/ikigai-web/src/error_page.rs`): a refusal, as a page,
  for a client that names `text/html` over `text/plain` (a browser); every other client gets the
  same sentence as text.
- **Pages from the embedded host's HTTP face**: the emailed decision, contact-block and label
  links and the passkey enrollment page (`crates/ikigai-embedded`: `decide.rs`, `contactblock.rs`,
  `passkey.rs`, all through `decide::page`), and the contact intake's redirect page
  (`crates/ikigai-intake`).
- **Terminal text**: the full-screen REPL (`tui.rs`, the default on an interactive terminal), the
  line REPL (`--plain`, or when stdin is not a terminal), `-c` batches, `--quiet` output, usage
  text and error lines.
- **Pictures**: `show <iri>` writes an SVG another crate drew (for example `urn:diagram:kernel`,
  from `ikigai-diagram`) to a file and opens it. The picture's accessibility is that crate's.

Not this repository's: markup an endpoint or a workspace stylesheet produces behind a route (for
example `urn:iki:foaf`'s HTML face, from the operator's `urn:file:foaf.xsl`).

## The rules that output follows

- An error page has `<html lang="en">`, a `<title>` and one `<h1>` naming the status, a `<main>`,
  and the message as escaped text; no style, no script. Its status code is the same as the text
  answer's, and both carry `Vary: Accept`.
- An embedded-host page (`decide::page`) and the intake's redirect page have `<html lang="en">`
  and one `<main>` holding the heading and the content. They keep the viewport meta and a
  32rem column, so they read on a phone.
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
- `--plain` is a line-oriented REPL with no full-screen redraw, so a screen reader or braille
  display reads it as ordinary terminal output; `--quiet` prints only the answers. (Not yet tested
  with either; see below.)

## How it is tested

- `crates/ikigai-web/tests/error_pages.rs` (7 tests) and the unit tests in `error_page.rs` pin the
  page's shape (`lang`, title, `main`, `h1`), escaping, which clients get a page, `Vary: Accept`,
  and that a JSON door and a success are left alone.
- `decide.rs` (`a_page_states_its_language_and_has_one_main_holding_its_content`, and the served
  decision page in `a_get_shows_the_decision_but_records_nothing`) and the intake's
  `with_a_redirect_the_response_is_an_html_page_to_the_url` pin `lang` and the one `main`;
  `passkey.rs`'s `the_passkey_status_lines_are_live_regions_present_before_the_script` pins the
  live regions, their place before the script, and that the script writes into them.
- The full-screen REPL is rendered against ratatui's test backend in `tui.rs`'s tests, mostly for
  layout and editing. `no_color_takes_every_color_escape_out_of_the_frame` writes a frame through
  the crossterm backend and finds no color escape in the bytes under `NO_COLOR`, and finds some
  without it.
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
