# A no-tracking certificate for a host

Design spike, ledger #3753. Status: proposal. Nothing here is built except one test that pins
a fact the design relies on (see [The fact this spike pins](#the-fact-this-spike-pins)).

## The problem

The product property is: nothing we run tracks individuals. Aggregate counts only; no cookies
used for tracking, no fingerprints, no stored IP addresses, no profiles. It is a promise about
what *our code* does, not about what a customer does with data their visitors type into a form.

Today that promise is held by comments and a handful of tests scattered through the crates.
Each is true where it stands, but nobody can look at a running host and see that it holds *for
that host's configuration*: the same binary is a different privacy story with `--trust-proxy`
on or off, with a principal hook or without one, with an endpoint allowed to set `Set-Cookie`
or not. The ask (Brian, 2026-11-14) is to **demonstrate and visualize** the property for a host
rather than assert it.

This document proposes a **certificate**: a resource a host serves, `urn:host:privacy:certificate`,
that lists every place a per-person datum can enter that host (each door, each provenance
argument, each log line, each header) and where it goes (dropped, held in memory under a bound,
stored, and for how long), **derived from the host's mounts and configuration** and never typed
by hand, with each claim naming the test that pins it.

### What "per-person datum" means here

Anything that singles out one person or one device across requests:

- a network address (the socket peer, an `X-Forwarded-For` hop);
- an authenticated identity (`principal`, a client certificate fingerprint, a link token);
- a cookie or any other client-held identifier the host could read back;
- a contact address the host itself derives or looks up (as opposed to one the visitor typed
  as message content, which is covered under [Submitted content](#submitted-content-is-listed-not-judged)).

A timestamp (`received`) is not per-person on its own; it is listed because it travels with
the others.

## What the code does today (the inventory a first certificate would print)

Every row below was read in this checkout. Line numbers are as of `eb73853`.

| # | Door | Datum | Enters at | Fate today | Pinned by |
|---|---|---|---|---|---|
| 1 | HTTP | remote address as `client` | attached to every mutating request, `crates/ikigai-web/src/lib.rs:1975-1979`, value from `client_ip` (`lib.rs:4182-4190`) | handed to the endpoint as an argument; what happens next is the endpoint's | `every_provenance_name_is_reserved_on_every_mutating_verb` (`lib.rs:5128`) |
| 2 | HTTP | `X-Forwarded-For` rightmost hop | read only when `EdgeConfig::trust_proxy` is set (`lib.rs:500`, `lib.rs:4183-4188`) | becomes row 1's `client` and row 4's source key; the header itself is not stored by the door | none yet |
| 3 | HTTP | `principal` | attached to a write only when `EdgeConfig::principal_fn` is set (`lib.rs:529`, `lib.rs:1984-1986`) | handed to the endpoint; reserved even with no hook (`lib.rs:4166-4172`) | `every_provenance_name_is_reserved_on_every_mutating_verb` |
| 4 | HTTP | remote address as a rate-limit key | `lib.rs:1918-1922`, only when `EdgeConfig::source_limits` is set (`lib.rs:573`, default `None` at `lib.rs:714`) | **memory only**: at most `DEFAULT_MAX_SOURCES` = 4,096 windows (`crates/ikigai-web/src/source_limit.rs:29`), IPv6 reduced to its /64 (`source_limit.rs:228-246`); an emptied window keeps its address until the table is full and a new source needs the place (`source_limit.rs:171-185`), or until restart | `the_table_is_bounded_reclaims_emptied_windows_and_refuses_a_new_source_past_it`; `an_emptied_window_keeps_its_address_until_the_table_needs_the_place` (new, this spike) |
| 5 | HTTP | submitter-authored `received`, `client`, `principal` in the query string | `forwarded_query`, `lib.rs:2448-2459` | **dropped** before the request is built | `provenance_comes_from_the_transport_and_cannot_be_forged_in_the_body` (`crates/ikigai-intake/src/lib.rs:1965`) for the body; the query path has no named test yet |
| 6 | HTTP | the request, including `peer`, given to the capability hook | `lib.rs:2930-2942` | the host's `cap_fn` sees it; fate is the host's hook's | none |
| 7 | HTTP | `Set-Cookie` from an endpoint | `EndpointHeader::DEFAULTS` (`crates/ikigai-web/src/entity.rs:100-106`), the default at `lib.rs:713` | **cannot be set** unless a door opts in by adding `EndpointHeader::SetCookie` (`entity.rs:78-81`, `lib.rs:563-568`) | the `entity.rs` tests using `DEFAULTS` (`entity.rs:460`, `entity.rs:563`) |
| 8 | HTTP | door log lines | `eprintln!` at `lib.rs:2092` and `lib.rs:2731` | stderr; the line names the refused header and the IRI, **no address** | none |
| 9 | Intake | `client` | arrives as row 1 | **dropped**: not copied into the tuple (`crates/ikigai-intake/src/lib.rs:880-895`) | `a_dropped_tuple_carries_no_ip_address` (`ikigai-intake/src/lib.rs:1985`) |
| 10 | Intake | sender address checked against a blocklist | `blocklist` + `block_key` (`ikigai-intake/src/lib.rs:162-172`) | the address is never sent, only a keyed hash | the #3685 tests in `ikigai-intake` |
| 11 | Intake | sender address, legacy blocklist | `check_blocked` (`ikigai-intake/src/lib.rs:843-860`) | **the address itself** is sent to `urn:decisions` as an argument of a *read*; a read's arguments are part of its content address, the cache key (`ikigai-web/src/lib.rs:1971-1974` says why), so the address can sit in a representation cache keyed by it, unless `urn:decisions` answers uncacheable | none |
| 12 | Intake | link token | `clients` (`ikigai-intake/src/lib.rs:179-186`) | the token is held for one lookup; the tuple records the client's *id*, not the token (`lib.rs:189-195`, `lib.rs:862-877`) | the `tokened_kernel` tests (`lib.rs:1727`) |
| 13 | QUIC | source address | `PeerIdentity::source_address` (`crates/ikigai-quic/src/lib.rs:225-246`) | handed to the minter; the `ikigai` host passes it to `ikigai-layers`' `door_capability` for the join's per-address limit (`crates/ikigai-cli/src/main.rs:4500-4506`). That crate's 0.9.4 notes say "the join keeps no address" (`Cargo.toml:2187`): **declared upstream, not provable here** | upstream |
| 14 | QUIC | client certificate fingerprint | `PeerIdentity::fingerprint`; principal `urn:iki:host:{name}:client:<fingerprint>` (`ikigai-quic/src/lib.rs:107-111`) | an authentication identifier, by design. Stamped as `principal` on every request, which "partitions the cache per client at the door" (`ikigai-quic/src/lib.rs:121-124`): held in the representation cache under its bound. **Logged** to stderr on refusal (`ikigai-cli/src/main.rs:4517-4521`, via `diagnose` at `main.rs:4087`) | none |
| 15 | Passkey | — | `crates/ikigai-embedded/src/passkey.rs:21` | no cookie and no session store | — |

Three things the inventory shows, each of which the certificate exists to make visible:

1. **The certificate must be configuration-shaped.** Rows 2, 3, 4, 7 and 11 each exist or not
   depending on one `EdgeConfig` or `IntakeConfig` field.
2. **Row 4's bound is a count, not a time.** The intake's comment says the limiter "holds an
   address in memory only for its window" (`ikigai-intake/src/lib.rs:885-889`). The limiter
   only reclaims emptied windows when its table is full (`source_limit.rs:171-180`), so on a
   quiet host an address stays in memory until restart. That is still memory-only and bounded
   at 4,096. But "for one window" is not what the code does, and a certificate that said so
   would be wrong. The test this spike adds pins what the code actually does (see
   [Decision 2](#decisions-for-brian)).
3. **Row 11 is the one place where our code sends an address somewhere it can be kept.**
   The newer `blocklist` path (row 10) fixes this. The legacy path is still accepted
   configuration.

## The shape of the certificate

### A declaration beside each door, a derivation at the host

The certificate is not a document someone writes. It has two halves:

- **Declarations, in code, beside the code they describe.** Each crate that opens a door or
  consumes a per-person datum exports a `const` table of `DataFlow` entries: `door`, `datum`,
  `entered_at` (the condition, in configuration terms), `fate`, `bound`, `retention`, and
  `pinned_by` (the test names). For example, `ikigai_web::DATA_FLOWS` would carry rows 1-8,
  each with a `when` predicate over `&EdgeConfig`. The declaration lives in the same file as
  the code, so a reviewer sees both in one diff.
- **A derivation, in the host.** At startup the host walks what it actually composed: each
  door it bound, with its `EdgeConfig`; each mounted module, with its configuration (an
  intake's `IntakeConfig`, say). It evaluates each declaration's `when` against that
  configuration and keeps the rows that apply. A mounted module with **no** declaration
  produces an `undeclared` row; it is never silently left out.

```rust
// Sketch, not an API commitment.
pub struct DataFlow {
    pub door: &'static str,          // "http", "quic", "intake"
    pub datum: Datum,                // Address, Principal, CertFingerprint, Cookie, Token, ContactAddress
    pub entered_at: &'static str,    // "crates/ikigai-web/src/lib.rs: write provenance"
    pub fate: Fate,                  // Dropped | Memory { bound } | Forwarded { to } | Stored { retention } | Logged { sink }
    pub pinned_by: &'static [&'static str],
}
pub enum Fate {
    Dropped,
    Memory { bound: Bound },                 // Bound::Count(4096), Bound::Time(..), Bound::Cache
    Forwarded { to: &'static str },          // the fate is the receiver's declaration
    Stored { retention: Retention },
    Logged { sink: &'static str },           // "stderr"
}
```

`Forwarded` is what makes the derivation compose: row 1 says "forwarded to the endpoint", and
the host resolves it against the receiving endpoint's own declaration (row 9 for an intake).
A forward to an endpoint with no declaration ends in `undeclared`.

### Status

Each row has a status, worded so color is never the only signal:

- **holds**: the fate is `Dropped` or `Memory` with a bound, and every named test exists.
- **stored**: the fate is `Stored` or `Logged` of an address. That is what the property
  forbids, so the certificate is **red**.
- **undeclared**: a mounted module or a forward with no declaration. Red (see Decision 3).
- **unprovable**: the fate is declared by code outside this repository (row 13). Shown
  as such, never as "holds".

The certificate as a whole is **holds** only when every row is.

## Resource map

All names are singular and type-first; keyed partitions name their key.

| IRI | Kind | Holds | What it answers |
|---|---|---|---|
| `urn:host:privacy:certificate` | composition | nothing | the whole certificate for this host: every entry, the overall status, the build id and a digest of the configuration it was derived from. `text/turtle` by default; `text/html` face for a browser |
| `urn:host:privacy:entry:{door}:{datum}` | composition, keyed partition | nothing | one row, e.g. `urn:host:privacy:entry:http:client` |
| `urn:host:privacy:declaration:{crate}` | atom | the crate's compiled-in `DATA_FLOWS` table (immutable for the life of the binary) | the declarations before configuration is applied: what this build *could* do |
| `urn:host:privacy:configuration` | composition | nothing | the configuration facts the derivation read (`trust_proxy`, `principal_fn` set or not, `source_limits`, `endpoint_headers`, each intake's `check_blocked`/`blocklist`), with no secrets: a `block_key` is shown as "set", never its value |
| `urn:host:privacy:diagram` | composition | nothing | the SVG drawing of the certificate (see Visualization) |

There is no mutable state. The only atoms are compile-time tables. Everything else is a pure
function of (binary, configuration, mounts), so it is rebuilt at startup and when a live route
reload changes the mounts.

## Capabilities

| Action | Verb | Declares | Enforces |
|---|---|---|---|
| read the certificate, an entry, a declaration, the diagram | `Source` | `urn:cap:host:privacy:read` | the kernel's capability check, as every endpoint |
| read the configuration facts | `Source` | `urn:cap:host:privacy:configuration:read` | separately gated: it says which hooks a host runs, which is operator information (Decision 1) |
| anything else | `Sink`, `Delete` | — | refused `Denied`: the certificate is derived, never written |

A public door that wants to show it grants `urn:cap:host:privacy:read` on a `/privacy` route,
like any other public route.

## Failure modes and refusals

| Situation | Answer |
|---|---|
| reading without `urn:cap:host:privacy:read` | `Denied` |
| `Sink` or `Delete` on any `urn:host:privacy:*` | `Denied` (no capability grants writing a derived resource) |
| `urn:host:privacy:entry:{door}:{datum}` for a pair this host does not have | `NotFound`. An entry that exists but does not apply under this configuration is shown with status "not in effect" and is not `NotFound`, so a reader can see that `X-Forwarded-For` is off rather than wonder |
| a malformed key (an empty `{door}`, a `{datum}` outside the closed `Datum` vocabulary) | `InvalidArgument`, naming the segment |
| a declaration that names a `pinned_by` test this build does not contain | `Conflict` at derivation; the entry shows "evidence missing" and the certificate is red. Checked by the CI test below, so in a released build this cannot happen |
| `ikigai serve --require-no-tracking` (proposed) with a red certificate | the host refuses to start, with a `Conflict` that names each red row |

A red certificate is **an answer, not an error**: reading it succeeds and says red. Only the
opt-in startup flag turns red into a refusal.

## Visualization

The HTML face of `urn:host:privacy:certificate` follows the error-page rules in
[ACCESSIBILITY.md](../ACCESSIBILITY.md): `<html lang="en">`, a `<title>`, one `<h1>`
("Privacy certificate for {host}: holds" or "...: 2 entries store a per-person datum"), a
`<main>`, no script, and the shared stylesheet only.

**A table first.** One `<table>` with a `<caption>`. Columns: Door, Datum, Enters when, Fate,
Bound, Retention, Status, Pinned by. Header cells use `scope="col"`; the Door cell of each row
is a `<th scope="row">`. Status is a word ("holds", "stored", "undeclared", "unprovable", "not
in effect") and may also carry color, never color alone. "Pinned by" lists test names as text
with a link to the source line. A row "not in effect" stays in the table so a reader can see
what the configuration turned off.

**A diagram second**, after the table and never in its place: `urn:host:privacy:diagram`, one
lane per door, an arrow from each entry point to one of five fate boxes (Dropped, Memory with
its bound, Forwarded, Stored, Logged). It is drawn from the same derived rows as the table, so
the two cannot disagree. The SVG has a `<title>` and `<desc>`, and the page links "the table
above is this diagram's text" as its alternative. `show urn:host:privacy:diagram` opens it from
the REPL, as `show` does for `urn:diagram:kernel`.

## What is cacheable

Everything. The certificate is a pure function of (build id, configuration digest, mount set).
It is answered with a strong ETag over those three and `Cache-Control: public`, and it stays
valid until the host is reconfigured. It carries no per-request data, so there is nothing to
`Vary` on beyond `Accept` for the HTML face. A live route reload that changes the mount set
changes the ETag.

## How a door that stores an address turns it red

Three checks. Each catches what the one before it cannot:

1. **Completeness, at compile and test time.** A test in `ikigai-web` iterates the provenance
   names (`received`, `client`, `principal`, `lib.rs:4170-4172`) and asserts each has a
   `DATA_FLOWS` row. Adding a fourth provenance name without a declaration fails CI. Each
   declaration's `pinned_by` names are checked to exist (by a test-name registry the crate's
   tests populate, or a `#[test]` per declaration that calls the named function).
2. **Undeclared is red, at derivation.** A newly mounted module that receives `client` (every
   write endpoint does, row 1) and has no declaration is an `undeclared` row. The author has
   to write a declaration, and that declaration is reviewed in the same diff as the code.
3. **A canary sweep, end to end** (an `ikigai-cli` integration test, beside
   `crates/ikigai-cli/tests/layers_serve.rs`). It stands the host up with a real serve
   configuration, sends writes through every bound door from sentinel addresses (TEST-NET
   `203.0.113.0/24`, `2001:db8::/32`, through `X-Forwarded-For` with `trust_proxy` on), then
   scans every place the host persists: the durable store, every space's tuples, files under
   the workspace, captured stderr, and the representation cache's keys. Any sentinel found
   fails the test **and** names the place. This is the check that catches a door whose
   declaration is wrong: it tests behavior, not what someone said about it.

A deliberately bad test door ("stores `client` into a space") is part of the suite, to prove
that checks 2 and 3 turn the certificate red.

## Tests that would prove it

- `every_provenance_name_has_a_declared_fate` (ikigai-web): check 1.
- `every_pinned_by_names_a_test_that_exists` (each declaring crate).
- `the_certificate_follows_the_configuration` (ikigai-web): toggling `trust_proxy`,
  `principal_fn`, `source_limits` and `EndpointHeader::SetCookie` adds and removes exactly
  rows 2, 3, 4 and 7.
- `an_intake_with_check_blocked_is_red_and_one_with_a_keyed_blocklist_holds` (ikigai-intake):
  rows 10 and 11.
- `an_undeclared_mount_is_red` and `a_door_that_stores_client_is_red` (ikigai-cli).
- `no_sentinel_address_survives_a_serve` (ikigai-cli): check 3.
- `the_certificate_page_is_a_table_then_a_diagram` (ikigai-cli): `lang`, one `h1`, `<main>`,
  `<caption>`, `scope` on header cells, no `<script>`, status words present, the table
  before the `<img>`/`<svg>`.
- `the_certificate_etag_is_stable_and_follows_reconfiguration`.
- `writing_the_certificate_is_denied` and `an_unknown_entry_is_not_found`.

### The fact this spike pins

`an_emptied_window_keeps_its_address_until_the_table_needs_the_place`
(`crates/ikigai-web/src/source_limit.rs`) pins row 4's real bound. An address is held past its
window, until the table is full and a new source needs the place. Then the emptied window is
reclaimed and a live one is kept. If the limiter later gains a time-based sweep
(Decision 2), this test changes in the same PR, and row 4's declared retention tightens from
"until reclaimed or restart" to "one window".

## What the certificate cannot prove

- **A module's internals beyond its declaration.** The certificate checks declarations for
  completeness, and the canary sweep checks what a test configuration persists. Neither reads
  a module's code. A module that keeps an address in a private in-memory map, or sends it over
  the network, passes both unless the sweep happens to look there. Row 13 (`ikigai-layers`) is
  the standing example: its fate is declared upstream.
- **The operator's surroundings.** A reverse proxy's access log, a load balancer, a CDN, the
  TLS terminator, journald capturing our stderr (rows 8 and 14 end there), and the OS's own
  connection tracking. The certificate can say "this host writes no address to stderr". It
  cannot say what the operator's proxy writes. The page says so in a sentence under the table.
- **Configurations it was not derived from.** It describes the running host, not the binary in
  general. `urn:host:privacy:declaration:{crate}` is the closest it comes to "what this build
  could do".
- **Intent.** A `Forwarded` row's endpoint may be the customer's own module, doing what the
  customer wants with their visitors' data. The certificate reports that the datum reaches it.
  Whether that is acceptable is the customer's call.

### Submitted content is listed, not judged

An intake stores the fields a visitor typed: a name, an email address, a message. That is the
customer's data, given on purpose, and it is outside the promise. The certificate lists each
intake's stored fields in a separate section ("Stored because the visitor submitted it") so
the line between "we tracked them" and "they told the customer" is drawn on the page, not left
for the reader to guess.

## Relation to the dispersion certificate

The dispersion certificate (a separate ledger item) is a **signed** statement over an
organization's whole grant set: who can reach what, across hosts. This certificate is
**per host** and about **data fate**, and it is unsigned. It is content-addressed: its ETag is
a digest of build, configuration and mounts. That lets the dispersion certificate include each
host's privacy certificate **by digest**, so one signature covers "these grants, on hosts whose
privacy certificates are these". Signing, keys and the organization-wide view stay that item's.
This one only has to be stable and addressable.

## Migration

Nothing published changes. The certificate adds new resources under `urn:host:privacy:*` and a
new optional `DATA_FLOWS` export per crate, both additive. Two existing things would change
alongside it, each its own item:

- the intake comment at `ikigai-intake/src/lib.rs:885-889` ("only for its window") is
  corrected to match the code, or the code is changed to match the comment (Decision 2);
- `IntakeConfig::check_blocked` is deprecated in favor of `blocklist` (Decision 4). Existing
  configurations keep working and show red until they move.

## Decisions for Brian

1. **Who may read the certificate?** Recommendation: `urn:cap:host:privacy:read` granted
   publicly on every door that serves pages, at `/privacy`. The promise is made to visitors,
   so they should be able to check it. `urn:host:privacy:configuration` stays operator-only.
2. **Should the rate limiter's bound become a time as well as a count?** Today an address
   stays in memory until the table fills or the host restarts (pinned by this spike's test).
   Recommendation: yes. Sweep emptied windows on each check, so retention is one window. That
   is cheap, it makes the existing intake comment true, and it gives the certificate the
   strongest honest sentence. Track it as its own item.
3. **Is an undeclared module red or amber?** Recommendation: red. "Undeclared" is the case
   the promise cannot cover, and amber would teach readers to ignore it. Serving with a red
   certificate stays allowed. Only `--require-no-tracking` refuses.
4. **Deprecate the legacy `check_blocked`?** It sends the sender's address as a read argument
   (row 11). Recommendation: deprecate now, red when enabled, remove at the next minor.
5. **Do authentication identifiers count?** A client certificate fingerprint, a `principal`,
   a link token's client id. Recommendation: list them all with their fate. Mark them
   "authentication, not tracking" when they are only used to decide authority. Count them
   against the property when they are logged or stored beyond that (row 14's stderr line is
   the case to look at).
6. **Should submitted content appear at all?** Recommendation: yes, in its own section
   (above). Leaving it out invites the reading "the form stores my email, so the certificate
   lies".
7. **What counts as evidence?** Recommendation: test names with links to their source lines,
   checked to exist. A CI run's URL and result belong to the signed dispersion certificate,
   which can attest to a build. An unsigned per-host page cannot.
8. **Ship the canary sweep first?** Recommendation: yes. It is the one check that tests
   behavior rather than declarations, and it is useful before any page exists.
