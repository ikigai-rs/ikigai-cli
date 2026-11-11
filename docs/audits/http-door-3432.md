# Unled audit of the HTTP door, `ikigai-web` (ledger #3432)

On 2026-11-11 I read `crates/ikigai-web/src` for what an anonymous internet caller can do
to the door. I found one defect and could reproduce it.

## The defect: a tab in an endpoint's `Location`

`entity::check_same_origin` keeps a write's `Location` on this door. It refuses a scheme, an
authority (`//x`) and a backslash. It did not refuse a tab, and `check_value` lets a tab
through, since a header value may hold one. A browser removes every ASCII tab and newline
from a URL before parsing it (WHATWG URL, the basic URL parser), so `/<TAB>/evil.example/`
is followed as `//evil.example/`, which is another site. Python's `urljoin`, which follows
that rule, resolves it to `https://evil.example/`.

To reproduce: `cargo test -p ikigai-web --test endpoint_headers
a_tab_cannot_turn_a_write_redirect_off_site`. Before the fix, a Sink endpoint answering
that `Location` was served as `303 See Other` with `Location: /<TAB>/evil.example/`. With the
fix, the door refuses the answer with `500`, names `Location`, and serves none of the body.
`with_headers` refuses to build such an envelope too. The fix refuses a tab anywhere in the
value. A trailing tab never reached the check, because the envelope parser trims values.

Who can exploit it: someone who can get an endpoint to put their input into its `Location`
(a `next` argument on a form, say). No endpoint in this workspace does that today, so this
is a hardening of the one check that exists to stop it.

## Checked, no defect found

- **Path to IRI mapping.** Each segment is decoded on its own, after splitting on `/`.
  `%2F` and `%25` stay escaped, so an encoded slash never becomes a separator. A malformed
  escape and non-UTF-8 input get `400`. A strict `{var}` refuses the gen-delims once
  decoded, and its route still claims the path, so no later route or mechanical default
  answers it instead. `routes_only` answers `404` before the mechanical default. A
  `{+var}` is raw only when every spelling of it is `{+var}`. Template expansion is one
  pass. The PRG redirect path round-trips through first-match routing, and its segments are
  URL-encoded, with `.` and `..` refused.
- **Writes across sites (`OriginCheck`).** A missing `Origin`, `Origin: null`, a malformed
  `Origin`, a duplicated `Origin` and `Sec-Fetch-Site: same-site` are each refused. A request
  with neither header is admitted only when it carries no cookie and no non-Bearer
  `Authorization`. Methods are compared case-insensitively there, and case-sensitively in
  `verb_for_method`, so a lowercase `post` gets `405`, not a write. Uploads are admitted
  before anything is spilled.
- **Header injection.** The hyper door builds every field through `HeaderValue::from_bytes`
  and answers `500` on a byte HTTP forbids. `write_response` runs `Response::check`.
  Endpoint envelope headers are on an allowlist and go through `check_value`. A read
  redirect checks the raw path it appends for same-origin, whitespace and bytes.
  `Retry-After` is an integer.
- **Error pages.** Every built-in page goes through `error_page::page` or `shell`, which
  escape with `ikigai_fn::html::html_text`. The redirect-answer page links only through
  `safe_href` and `attr`.
- **Limits.** The head is at most 64 KiB (`431`), under a header deadline (`408`, then a
  bounded linger). A body over the declared or chunked bound gets `413` and is never
  truncated. A slow body gets `408`. A write that stalls has its own deadline. There are a
  connection cap and optional per-source rate limits.
- **Caching.** `Expiry::Never` is `no-cache` with a strong ETag, never `immutable`. An
  answer shaped by credentials is `private`. `Set-Cookie` is refused on a cacheable read.
- **Tracking.** The door sets no cookie and no identifier of its own. `Set-Cookie` comes
  only from an endpoint, on a door that opted in (`EndpointHeader::SetCookie`). The door's
  logs (`eprintln!`) name the refused header and the IRI, never the client.

Not changed, and worth knowing: a `500` from `Error::Endpoint` carries the endpoint's own
message, so an endpoint that puts an internal path into its error shows that path to the
caller. Whether a message is safe to show is up to each endpoint. I did not find one in this
crate that leaks.

These are socket and unit tests. No browser or assistive technology was tested.
