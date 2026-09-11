//! `ikigai-conformance` over the two kernels this workspace COMPOSES.
//!
//! ## This crate is a host, not a module, and that changes what a clean report means
//!
//! `ikigai-embedded` binds about thirty endpoints of its own and inherits a hundred more
//! from twenty-odd published module crates, each with its own repo and its own adoption of
//! this same suite. No inherited finding is this workspace's to FIX — they are walked,
//! attributed to the crate that owns them, and left; they drop on their own as each module's
//! release lands on crates.io. What IS this workspace's is [`OWN`], and the assertion is
//! that **no finding names an id in it**. [`the_walked_catalog_is_classified`] holds the two
//! tables to the actual catalog, so an endpoint added later fails one test or the other and
//! whoever added it has to classify it, type its inputs, and decide whether the walk may
//! fire it.
//!
//! Two kernels, because this crate composes two and they are different compositions:
//!
//! | kernel | what it is | who reaches it |
//! |---|---|---|
//! | [`ikigai_embedded::kernel`] | the REPL/TUI root: personal, Lisp, browse, the lot | the owner, in process |
//! | [`ikigai_embedded::kernel_for`] | the HTTP door (`ikigai serve --http`) | the public edge, under a `--cap` ceiling |
//!
//! The second is a SUBSET with a different posture, and the walk over it is the check that
//! the subset is what it is claimed to be: no personal space, no Lisp, no subprocess seam.
//! [`the_http_door_serves_no_owner_only_resource`] states that as a list rather than a
//! sentence.
//!
//! ## ★ What the walk is NOT allowed to do — decided BEFORE the first bare run
//!
//! A conformance walk fires every non-opted-out action under `Capability::root()`. On a
//! MODULE that is a read of the module's own data; on a composing host it is a remote-code-
//! execution surface, and nothing in the suite warns (conformance PENDING #139: the bare
//! first run over `ikigai-dev-server` really executed `git`, shelled out to `gh` over the
//! network, and POSTed to a live inference server). This workspace binds a subprocess seam,
//! six outbound HTTP verbs, an SMTP sender, a Zoom scheduler, the macOS EventKit calendar,
//! a Keychain with a Touch ID prompt, mDNS multicast, a job scheduler and a Steel evaluator.
//!
//! So the opt-out list in [`suite`] was written from the CATALOG, before this file ever
//! ran an invoking check — not from reading the first report. Every entry says which of the
//! five hazards it is: **spawns a process**, **reaches the network**, **sends a message**,
//! **touches the platform**, or **evaluates code**. The description-only checks (ARGSPECS,
//! NAMES, REQUIRES-VERB) still run over every one of them, and that is where nearly all of
//! the inherited findings are anyway.
//!
//! ## Hermetic, and the three things that leak if it is not
//!
//! `HOME` and `XDG_CONFIG_HOME` are redirected and [`ikigai_embedded::set_file_root`] is
//! called before any kernel is built, because:
//!
//! * the file module is jailed to `file_root()`, and the walk FIRES its Sink and Delete;
//! * `urn:orgfile:{path}` is jailed to whatever `calendar.json` names as `org_dir` — and
//!   with no config at all that is the empty path, which is the process's own working
//!   directory. A walk that fired a Sink there would write into the checkout;
//! * `browse.root` and the a11y layering read the config home, so a walk against the real
//!   one is about the machine it ran on rather than about the code.
//!
//! `set_file_root` is the typed channel this crate documents for exactly this: `cfg(test)`
//! does not reach a `tests/` binary, so the redirect has to be a call, not a compile flag.
//!
//! ## Fixtures and declarations, stated here because 0.1.0 prints the declarations only
//!
//! (Conformance PENDING #3.) Real Turtle for the `urn:rdf:*` trio, real queries for the four
//! `sparql-*` reads, a real JSON-LD document for the three `jsonld-*` operators, a stylesheet
//! and a document for `xslt-transform`, and `path` / `name` / `token` / `action` bindings for
//! the template-bound entries. Without them those endpoints report "did not resolve with the
//! minimal inputs", which reads as a caching finding (PENDING #33) and means the walk failed
//! to CALL rather than that the endpoint failed to conform.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ikigai_conformance::{Fixture, Report, Suite};
use ikigai_core::{Kernel, Verb};

// ---------------------------------------------------------------------------
// Who owns what.
// ---------------------------------------------------------------------------

/// Every description id bound by a crate in THIS workspace, with that crate.
///
/// The list is the claim the `conforms` test makes: these are ours, so a finding against one
/// of them is a defect here and turns the test red. It is also a linkage inventory — a
/// member crate that grows an endpoint puts it on the REPL, the HTTP door or both, and
/// nothing else would say so.
const OWN: &[(&str, &str)] = &[
    // ikigai-embedded's own endpoints.
    ("about", "ikigai-embedded"),
    ("agent-select", "ikigai-embedded"),
    ("alias-demo", "ikigai-embedded"),
    ("calendar-request", "ikigai-embedded"),
    ("catalog-cards-xsl", "ikigai-embedded"),
    ("client", "ikigai-embedded"),
    ("client-issue", "ikigai-embedded"),
    ("clock-now", "ikigai-embedded"),
    ("contact-block", "ikigai-embedded"),
    ("contactblock-link", "ikigai-embedded"),
    ("control", "ikigai-embedded"),
    ("decide-accept", "ikigai-embedded"),
    ("decide-link", "ikigai-embedded"),
    ("decisions", "ikigai-embedded"),
    ("foaf", "ikigai-embedded"),
    ("greeter", "ikigai-embedded"),
    ("host-demo", "ikigai-embedded"),
    ("host-heartbeat", "ikigai-embedded"),
    ("host-history", "ikigai-embedded"),
    ("host-identity", "ikigai-embedded"),
    ("host-info", "ikigai-embedded"),
    ("kernel-health", "ikigai-embedded"),
    ("lisp-aliases", "ikigai-embedded"),
    ("page", "ikigai-embedded"),
    ("passkey-challenge", "ikigai-embedded"),
    ("passkey-enroll-open", "ikigai-embedded"),
    ("passkey-js", "ikigai-embedded"),
    ("passkey-register", "ikigai-embedded"),
    ("peer-list", "ikigai-embedded"),
    ("people", "ikigai-embedded"),
    // Sibling members of this workspace.
    ("booking", "ikigai-intake"),
    ("contact", "ikigai-intake"),
    ("send", "ikigai-email"),
    ("space", "ikigai-intray"),
    ("time-cancel", "ikigai-time"),
    ("time-jobs", "ikigai-time"),
    ("time-schedule", "ikigai-time"),
    ("tz-convert", "ikigai-tz"),
    ("tz-now", "ikigai-tz"),
    ("view-derive", "ikigai-view"),
    ("view-derive-tick", "ikigai-view"),
    ("view-ingest", "ikigai-view"),
];

/// Every description id that arrives from a PUBLISHED module crate, with that crate.
///
/// Findings against these are recorded and printed, never fixed here — the fix belongs in
/// the module's own repo, where its own adoption of this suite will make it (most already
/// have; those releases are simply not on crates.io yet). Listed rather than matched by
/// prefix so that a module quietly gaining an endpoint is visible in a diff.
const INHERITED: &[(&str, &str)] = &[
    ("bookmarks", "ikigai-cms"),
    ("compose", "ikigai-fn"),
    ("conditional", "ikigai-fn"),
    ("echo", "ikigai-fn"),
    ("greet", "ikigai-fn"),
    ("reverseList", "ikigai-fn"),
    ("split", "ikigai-fn"),
    ("toUpper", "ikigai-fn"),
    ("wrap", "ikigai-fn"),
    ("availability", "ikigai-personal"),
    ("calendar", "ikigai-personal"),
    ("calendar-config", "ikigai-personal"),
    ("calendars", "ikigai-personal"),
    ("contacts", "ikigai-personal"),
    ("eval", "ikigai-lisp"),
    ("file", "ikigai-fs"),
    ("httpDelete", "ikigai-http"),
    ("httpGet", "ikigai-http"),
    ("httpHead", "ikigai-http"),
    ("httpPatch", "ikigai-http"),
    ("httpPost", "ikigai-http"),
    ("httpPut", "ikigai-http"),
    ("ikigai-vocab", "ikigai-vocab"),
    ("jsonld-compact", "ikigai-jsonld"),
    ("jsonld-expand", "ikigai-jsonld"),
    ("jsonld-flatten", "ikigai-jsonld"),
    ("llm-ask", "ikigai-llm"),
    ("llm-config", "ikigai-llm"),
    ("llm-models", "ikigai-llm"),
    ("llm-ollama-ask", "ikigai-llm"),
    ("llm-ollama-installed", "ikigai-llm"),
    ("llm-ollama-model", "ikigai-llm"),
    ("llm-ollama-up", "ikigai-llm"),
    ("llm-select", "ikigai-llm"),
    ("org-agenda", "ikigai-org"),
    ("rdf-diff", "ikigai-rdf"),
    ("rdf-from-sexpr", "ikigai-sexpr"),
    ("rdf-transrept", "ikigai-rdf"),
    ("rdf-union", "ikigai-rdf"),
    ("repo-branch", "ikigai-repo"),
    ("repo-list", "ikigai-repo"),
    ("repo-log", "ikigai-repo"),
    ("repo-pr-checks", "ikigai-repo"),
    ("repo-pr-view", "ikigai-repo"),
    ("repo-status", "ikigai-repo"),
    ("system-exec", "ikigai-repo"),
    ("sexpr-from-rdf", "ikigai-sexpr"),
    ("sexpr-to-rdf", "ikigai-sexpr"),
    ("shacl-validate", "ikigai-shacl"),
    ("sign", "ikigai-sign"),
    ("verify", "ikigai-sign"),
    ("encrypt", "ikigai-encrypt"),
    ("decrypt", "ikigai-encrypt"),
    ("sniff", "ikigai-sniff"),
    ("transrept-auto", "ikigai-sniff"),
    ("sparql-ask", "ikigai-sparql"),
    ("sparql-construct", "ikigai-sparql"),
    ("sparql-describe", "ikigai-sparql"),
    ("sparql-from-sexpr", "ikigai-sexpr"),
    ("sparql-select", "ikigai-sparql"),
    ("urn:meeting:zoom:schedule", "ikigai-meeting"),
    ("urn:secret", "ikigai-secret"),
    ("grep", "ikigai-text"),
    ("head", "ikigai-text"),
    ("nl", "ikigai-text"),
    ("rev", "ikigai-text"),
    ("sort", "ikigai-text"),
    ("tail", "ikigai-text"),
    ("uniq", "ikigai-text"),
    ("wc", "ikigai-text"),
    ("xslt-transform", "ikigai-xslt"),
];

/// Resources the REPL's root kernel binds that the public HTTP door must NOT.
///
/// The door resolves under an operator `--cap` ceiling and (in the edge posture)
/// `--routes-only`, so authority and surface are gated twice above this list. It is still
/// worth pinning as a catalog fact: a capability ceiling is configuration, and a binding is
/// code. Nothing here should ever be reachable on the public face even at full authority.
const OWNER_ONLY: &[&str] = &[
    "contacts",
    "calendar",
    "availability",
    "calendars",
    "calendar-config",
    "eval",
    "system-exec",
    "repo-status",
    "urn:secret",
    "send",
    "urn:meeting:zoom:schedule",
    "client-issue",
    "peer-list",
];

// ---------------------------------------------------------------------------
// The hermetic fixture home.
// ---------------------------------------------------------------------------

/// Redirect every ambient path this crate reads, once for the whole test binary.
///
/// Returns the scratch root. Called by every test before it builds a kernel; `OnceLock`
/// makes the writes happen exactly once however many threads arrive.
fn fixture_home() -> &'static Path {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "ikigai-embedded-conformance-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config/ikigai")).expect("config home");
        std::fs::create_dir_all(dir.join("workspace")).expect("workspace");
        std::fs::create_dir_all(dir.join("org")).expect("org dir");
        std::fs::write(
            dir.join("org/agenda.org"),
            "* TODO a fixture task\n  SCHEDULED: <2026-01-01 Thu>\n",
        )
        .expect("org file");
        // `urn:orgfile:{path}` is jailed to this directory. ⚠ With no `calendar.json` at all
        // the jail root is the EMPTY path — the process's working directory — and the walk
        // fires the file module's Sink. Writing this config is what keeps a conformance run
        // out of the checkout.
        std::fs::write(
            dir.join("config/ikigai/calendar.json"),
            format!(
                r#"{{"org_dir":"{}","org_files":["agenda.org"]}}"#,
                dir.join("org").display()
            ),
        )
        .expect("calendar.json");
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join("config"));
        ikigai_embedded::set_file_root(dir.join("workspace"));
        seed_workspace(&dir.join("workspace"));
        dir
    })
    .as_path()
}

/// Seed the workspace state the edge's decision faces read, so the walk PROBES them.
///
/// Without this, four endpoints report "did not resolve with the minimal inputs" — which
/// reads as a caching finding (conformance PENDING #33) and means the walk failed to CALL
/// rather than that the endpoint failed to conform. An empty fixture is the most likely
/// place for a composing host to mistake "nothing was checked" for "clean" (PENDING #142).
///
/// Two keypairs and one client record:
///
/// * `decide.pub` / `contact-block.pub` — SPKI PEM verifying halves. `urn:calendar-request`
///   and `urn:contact-block` read these BEFORE looking at a token, so with no file at all
///   they fail at the first line of `invoke` and nothing downstream is ever reached.
/// * `contact-block.key` — the PKCS8 PEM signing half, so `urn:contactblock:link` can mint.
/// * `clients/conformance.json` — so `urn:client:{token}` resolves for the bound fixture.
///
/// A FIXED key (`[9u8; 32]`), not a generated one: the walk only needs the file to parse,
/// and a deterministic fixture is one less thing that differs between runs.
fn seed_workspace(root: &Path) {
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use ed25519_dalek::SigningKey;

    let key = SigningKey::from_bytes(&[9u8; 32]);
    let public = key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("SPKI PEM");
    for name in ["decide.pub", "contact-block.pub"] {
        std::fs::write(root.join(name), &public).expect("verifying key");
    }
    std::fs::write(
        root.join("contact-block.key"),
        key.to_pkcs8_pem(LineEnding::LF)
            .expect("PKCS8 PEM")
            .as_str(),
    )
    .expect("signing key");
    std::fs::create_dir_all(root.join("clients")).expect("clients dir");
    std::fs::write(
        root.join("clients/conformance.json"),
        r#"{"id":"conformance","name":"Conformance Fixture"}"#,
    )
    .expect("client record");
}

fn root_kernel() -> Kernel {
    fixture_home();
    ikigai_embedded::kernel()
}

fn http_kernel() -> Kernel {
    fixture_home();
    ikigai_embedded::kernel_for("conformance")
}

// ---------------------------------------------------------------------------
// The suite.
// ---------------------------------------------------------------------------

/// A graph small enough to read and real enough to parse — the `content` every `urn:rdf:*`
/// fixture hands over.
///
/// ⚠ `http://`, not the `urn:` everything here is named with: `ikigai-rdf`'s sniff tells an
/// IRI from an XML element tag by looking for `://` in the first `<…>` token, so a document
/// whose first subject is `<urn:demo:a>` is sniffed as RDF/XML and fails to parse. Recorded
/// for ikigai-rdf rather than worked around silently (the same note ikigai-dev-server #10
/// made).
const TURTLE: &str = "<http://example.org/a> <http://purl.org/dc/terms/title> \"demo\" .\n";

/// A JSON-LD document with an actual node, not `{}`.
///
/// `{}` expands to zero triples, which makes every RDF check on the `jsonld-*` operators
/// pass without seeing anything — a report that reads as coverage and is not (conformance
/// PENDING #26, which the suite's own README example has).
const JSON_LD: &str = r#"{"@context":{"title":"http://purl.org/dc/terms/title"},"@id":"http://example.org/a","title":"demo"}"#;

/// An identity stylesheet — enough for `xslt-transform` to have a real transform to run.
const XSL: &str = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="xml"/><xsl:template match="/"><ok/></xsl:template></xsl:stylesheet>"#;

fn suite() -> Suite {
    Suite::new()
        // ---- fired, with inputs that work ----------------------------------------
        .fixture(
            Fixture::new("rdf-union", Verb::Source)
                .arg("content", TURTLE)
                .arg("with", TURTLE),
        )
        .fixture(
            Fixture::new("rdf-diff", Verb::Source)
                .arg("content", TURTLE)
                .arg("with", TURTLE)
                .arg("mode", "added"),
        )
        .fixture(
            Fixture::new("rdf-transrept", Verb::Source)
                .arg("content", TURTLE)
                .arg("as", "application/n-triples"),
        )
        .fixture(Fixture::new("sniff", Verb::Source).arg("content", TURTLE))
        .fixture(Fixture::new("transrept-auto", Verb::Source).arg("content", TURTLE))
        .fixture(Fixture::new("jsonld-expand", Verb::Source).arg("content", JSON_LD))
        .fixture(Fixture::new("jsonld-flatten", Verb::Source).arg("content", JSON_LD))
        .fixture(Fixture::new("jsonld-compact", Verb::Source).arg("content", JSON_LD))
        .fixture(
            Fixture::new("xslt-transform", Verb::Source)
                .arg("content", "<doc/>")
                .arg("stylesheet", XSL),
        )
        .fixture(
            Fixture::new("sparql-select", Verb::Source)
                .arg("query", "SELECT * WHERE { ?s ?p ?o } LIMIT 1"),
        )
        .fixture(Fixture::new("sparql-ask", Verb::Source).arg("query", "ASK { ?s ?p ?o }"))
        .fixture(
            Fixture::new("sparql-describe", Verb::Source).arg("query", "DESCRIBE <urn:demo:a>"),
        )
        .fixture(
            Fixture::new("sparql-construct", Verb::Source)
                .arg("query", "CONSTRUCT { ?s ?p ?o } WHERE { ?s ?p ?o } LIMIT 1"),
        )
        // Bindings are per ENTRY and a binding-only fixture's verb is ignored
        // (conformance PENDING #2): one binding per template variable is all the walk reads.
        .fixture(Fixture::new("file", Verb::Source).binding("path", "conformance.txt"))
        .fixture(Fixture::new("space", Verb::Source).binding("name", "conformance"))
        .fixture(Fixture::new("client", Verb::Source).binding("token", "conformance"))
        .fixture(Fixture::new("calendar-request", Verb::Source).binding("action", "decline"))
        // Real IANA zones: the suite's `x` is refused by the tzdata lookup, which reads as a
        // caching finding on an endpoint whose caching is fine (PENDING #33).
        .fixture(
            Fixture::new("tz-convert", Verb::Source)
                .arg("in", "2026-01-01T12:00:00Z")
                .arg("from", "UTC")
                .arg("to", "America/New_York"),
        )
        // An address, because the endpoint refuses anything that is not one before it mints.
        .fixture(
            Fixture::new("contactblock-link", Verb::Source).arg("email", "someone@example.org"),
        )
        // ---- declared -------------------------------------------------------------
        // Constant documents compiled into the binary: `urn:data:page` / `:control` /
        // `:about` and the catalog stylesheet are `include_str!`-shaped resources with no
        // state behind them, so an empty thread set is correct rather than a cache nothing
        // can cut. (A document that ever starts reading a file must lose this declaration
        // and grow a `depends_on` — which is what makes the declaration worth making.)
        .pure("page")
        .pure("control")
        .pure("about")
        .pure("catalog-cards-xsl")
        // A genuinely pure function: an instant and two IANA zone names in, the same instant
        // in the target zone out. It reads the bundled tzdata, which is compiled in and
        // therefore not a resource anything could cut — its own module docs say "Pure and
        // cacheable". (`urn:tz:now` below is the sibling that is NOT this, and the two
        // declarations sitting next to each other is the point.)
        .pure("tz-convert")
        // ⚠ A STATED DEVIATION, not a claim of purity. `urn:time:now` and `urn:tz:now` read
        // the kernel's CLOCK, so by the wave's rule 3 they are not pure functions of their
        // inputs. They are `cacheable_until(next minute)` — `Expiry::At` — and 0.1.0 has no
        // declaration for that: `pure` is the only spelling that says "an empty thread set is
        // correct here", and it is correct here for a reason the suite cannot express, namely
        // that a clock is not a resource and no `depends_on` could name it. The expiry itself
        // is pinned by hand in `a_clock_derived_result_expires_rather_than_threading` below,
        // so the declaration covers nothing that test does not check. Reported as conformance
        // PENDING #86/#123 (`Suite::cacheable_until`), which ikigai-web-demo #57 also wanted.
        .pure("clock-now")
        .pure("tz-now")
        // ---- NOT fired, and which hazard each one is -----------------------------
        //
        // ★ Written from the catalog BEFORE the first invoking run. See the module docs.
        //
        // Spawns a process.
        .opt_out("system-exec", None, "spawns a subprocess")
        .opt_out("eval", None, "evaluates arbitrary Steel code")
        // Runs git/gh against the invoking working tree, which this test does not own — and
        // CI checkouts are shallow, so what these read differs between machines.
        .opt_out("repo-status", None, "runs git in the invoking working tree")
        .opt_out("repo-log", None, "runs git in the invoking working tree")
        .opt_out("repo-branch", None, "runs git in the invoking working tree")
        .opt_out("repo-list", None, "enumerates repositories on the machine")
        .opt_out(
            "repo-pr-checks",
            None,
            "shells out to `gh`: network and auth",
        )
        .opt_out("repo-pr-view", None, "shells out to `gh`: network and auth")
        // Reaches the network. All six HTTP verbs are backed by a REAL transport here
        // (`ureq`), so the walk would issue live requests to whatever the sample `url`
        // happens to be.
        .opt_out("httpGet", None, "outbound HTTP over a real transport")
        .opt_out("httpHead", None, "outbound HTTP over a real transport")
        .opt_out("httpPost", None, "outbound HTTP over a real transport")
        .opt_out("httpPut", None, "outbound HTTP over a real transport")
        .opt_out("httpPatch", None, "outbound HTTP over a real transport")
        .opt_out("httpDelete", None, "outbound HTTP over a real transport")
        // Ours, and it fetches: every face of `urn:iki:foaf` starts with a `urn:httpGet` of
        // `src=`. Its capability floor is pinned by hand instead, in
        // `foaf::tests::without_a_net_grant_the_door_refuses` — which is the check `opt_out`
        // drops (conformance PENDING #21) and the one that matters for a network-backed
        // action.
        .opt_out("foaf", None, "issues urn:httpGet: reaches the network")
        .opt_out("llm-ask", None, "POSTs to a live inference server")
        .opt_out("llm-ollama-ask", None, "POSTs to a live inference server")
        .opt_out("llm-ollama-up", None, "probes a live inference server")
        .opt_out(
            "llm-ollama-installed",
            None,
            "queries a live inference server",
        )
        .opt_out("llm-ollama-model", None, "queries a live inference server")
        .opt_out("llm-models", None, "may discover over the network")
        .opt_out("llm-select", None, "may discover over the network")
        .opt_out("peer-list", None, "mDNS multicast on the local network")
        // Sends a message to a person or a third party. These are not reversible by
        // deleting a file afterwards, which is what makes them a different class from the
        // hermetic Sinks the walk is welcome to fire.
        .opt_out("send", None, "submits real mail over SMTP")
        .opt_out(
            "urn:meeting:zoom:schedule",
            None,
            "creates a real Zoom meeting through the provider API",
        )
        .opt_out(
            "decide-accept",
            None,
            "runs booking confirmation: schedules and emails downstream",
        )
        .opt_out(
            "client-issue",
            None,
            "mints a durable client credential, and `send=` emails it",
        )
        // Touches the platform. EventKit is macOS-gated and TCC-prompted (an agent shell is
        // silently denied), and the calendar Sink and Delete write the USER'S real calendar.
        .opt_out(
            "contacts",
            None,
            "reads the macOS contact store (EventKit/TCC)",
        )
        .opt_out(
            "calendar",
            None,
            "reads and WRITES the macOS calendar (EventKit/TCC)",
        )
        .opt_out(
            "calendars",
            None,
            "reads and writes the macOS calendar set (EventKit/TCC)",
        )
        .opt_out(
            "calendar-config",
            None,
            "reads the macOS calendar set (EventKit/TCC)",
        )
        .opt_out(
            "availability",
            None,
            "reads the macOS calendar (EventKit/TCC)",
        )
        .opt_out(
            "view-derive",
            None,
            "writes the derived calendar through EventKit",
        )
        .opt_out(
            "view-derive-tick",
            None,
            "writes the derived calendar through EventKit",
        )
        .opt_out(
            "view-ingest",
            None,
            "writes the derived calendar through EventKit",
        )
        .opt_out(
            "urn:secret",
            None,
            "macOS Keychain, behind a Touch ID prompt",
        )
        // Mutates process-global state the rest of the binary shares: the job registry is a
        // static, so a walk that schedules or cancels is not confined to its own kernel.
        .opt_out(
            "time-schedule",
            None,
            "registers a real job on the process-global registry",
        )
        .opt_out(
            "time-cancel",
            None,
            "cancels real jobs on the process-global registry",
        )
        // Ours, and it reaches the platform through a sub-resolution the manifold cannot
        // show: minting a link reads `urn:secret:booking-decide`, which on this machine is
        // the macOS Keychain behind a Touch ID prompt. The same reason `urn:secret` is out.
        .opt_out(
            "decide-link",
            None,
            "reads the signing key through urn:secret:*: Keychain, behind a Touch ID prompt",
        )
        // ★ A FALSE POSITIVE with a real observation inside it, and the reason it is an
        // opt-out rather than a fix.
        //
        // ENFORCED reports "declares no capability but refused with `Denied` under no
        // grants". True, and the refusal is `no enrollment window is open` — a STATE gate,
        // not an authority gate. There is no capability to declare: the window is opened by
        // a different, cap-gated resource (`urn:passkey:enroll-open`), and registration
        // during the window is deliberately open to an anonymous browser. Nor can the type
        // change: `Denied` is what the HTTP face maps to 403, and a closed enrollment window
        // answering 500 would be worse than a wrong label.
        //
        // What the finding is really pointing at is real and has no spelling: a description
        // has no way to say "this action is offered only while the host is in state S", so
        // the manifold over-offers on an axis that is not the capability axis. Reported for
        // the hub rather than worked around in the endpoint.
        .opt_out(
            "passkey-register",
            Some(Verb::Sink),
            "refuses with a typed Denied on a STATE gate (no enrollment window), which \
             ENFORCED reads as an undeclared capability; there is no capability to declare",
        )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Every non-kernel pattern a kernel binds, mapped to the id it describes itself under.
fn walked(kernel: &Kernel) -> BTreeMap<String, String> {
    kernel
        .entries()
        .expect("an enumerable root")
        .iter()
        .filter(|e| !e.pattern.starts_with("urn:kernel:"))
        .map(|e| {
            let id = kernel
                .describe_pattern(&e.pattern)
                .unwrap_or_else(|| panic!("`{}` describes itself", e.pattern))
                .id;
            (e.pattern.clone(), id)
        })
        .collect()
}

fn owners() -> BTreeMap<&'static str, &'static str> {
    OWN.iter().chain(INHERITED).copied().collect()
}

/// The findings, tallied by the crate that owns the endpoint each names.
fn by_owner(report: &Report) -> BTreeMap<&'static str, usize> {
    let owners = owners();
    let mut tally: BTreeMap<&'static str, usize> = BTreeMap::new();
    for finding in &report.findings {
        if let Some(owner) = owners.get(finding.endpoint.as_str()) {
            *tally.entry(*owner).or_default() += 1;
        }
    }
    tally
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// **Every endpoint either belongs to this workspace or names the crate it came from.**
///
/// The classification is what makes `conforms` meaningful: without it, "no finding names an
/// id in `OWN`" is satisfiable by leaving an id out of `OWN`. This test closes that by
/// requiring the union to cover the catalog exactly — an endpoint added to a member crate
/// fails here until it is listed, and a module crate that grows one fails here too, which is
/// the notification a dependency bump otherwise does not give.
#[test]
fn the_walked_catalog_is_classified() {
    let known: BTreeSet<&str> = owners().keys().copied().collect();
    let own: BTreeSet<&str> = OWN.iter().map(|(id, _)| *id).collect();

    let mut seen: BTreeSet<String> = BTreeSet::new();
    for kernel in [root_kernel(), http_kernel()] {
        for (pattern, id) in walked(&kernel) {
            assert!(
                known.contains(id.as_str()),
                "`{pattern}` describes itself as `{id}`, which is in neither OWN nor \
                 INHERITED: classify it (and if it is ours, its inputs need classes)"
            );
            seen.insert(id);
        }
    }
    let listed: BTreeSet<&str> = known.iter().copied().collect();
    let unseen: Vec<&&str> = listed
        .iter()
        .filter(|id| !seen.contains(**id))
        .collect::<Vec<_>>();
    assert!(
        unseen.is_empty(),
        "these ids are classified but no longer bound — drop them from the tables: {unseen:?}"
    );
    assert!(
        own.len() >= 40,
        "OWN lost entries without the catalog shrinking: {}",
        own.len()
    );
}

/// ★ **The suite over both compositions: nothing unattributed, and nothing of ours.**
///
/// The inherited count is printed rather than pinned. It drops on its own as each module's
/// own adoption reaches crates.io, and pinning it would turn another crate's improvement
/// into a failure here.
#[test]
fn conforms() {
    let mut ours: Vec<String> = Vec::new();
    let own: BTreeSet<&str> = OWN.iter().map(|(id, _)| *id).collect();

    for (label, kernel) in [
        (
            "ikigai_embedded::kernel() — the REPL/TUI root",
            root_kernel(),
        ),
        (
            "ikigai_embedded::kernel_for() — the HTTP door",
            http_kernel(),
        ),
    ] {
        let report = suite().run_blocking(&kernel);
        // The fixtures are not printed by 0.1.0 (PENDING #3) and neither is which run
        // produced a report, so the header is this file's own (PENDING #138).
        eprintln!("--- {label} ---\n{report}");
        eprintln!("findings by owning crate: {:?}", by_owner(&report));

        let owners = owners();
        let unattributed: Vec<String> = report
            .findings
            .iter()
            .filter(|f| !owners.contains_key(f.endpoint.as_str()))
            .map(|f| format!("{} {}", f.endpoint, f.check.label()))
            .collect();
        assert!(
            unattributed.is_empty(),
            "every finding must name a classified endpoint; these do not: {unattributed:?}"
        );
        ours.extend(
            report
                .findings
                .iter()
                .filter(|f| own.contains(f.endpoint.as_str()))
                .map(|f| format!("[{label}] {} {} {}", f.endpoint, f.check.label(), f.detail)),
        );
        assert_eq!(
            report.checks.skipped().count(),
            0,
            "every check runs over a composing host: {report}"
        );
    }

    assert!(
        ours.is_empty(),
        "findings against endpoints this workspace owns:\n{}",
        ours.join("\n")
    );
}

/// ★ **A clock-derived result EXPIRES rather than threading — and the HTTP door has a clock.**
///
/// Two things the `pure("clock-now")` / `pure("tz-now")` declarations would otherwise be
/// covering, both pinned here so the declaration certifies nothing this test does not.
///
/// 1. The expiry is `Expiry::At`, never `Never`. A clock-derived result cached forever is
///    the bug the empty-thread rule exists to catch, and `pure` silences that rule; if one
///    of these ever became `.cacheable()` outright, the suite would stay green and this
///    would not. (`Suite::cacheable_until` is the missing declaration — conformance PENDING
///    #86; ikigai-web-demo #57 wanted it too.)
/// 2. **`kernel_for` HAS a clock.** This is the regression line under a real defect the
///    walk found: the HTTP door was built without one until 0.1.20, and `Expiry::At` on a
///    clockless kernel is not a deadline — it is simply uncacheable. The door binds
///    `http_space()`, whose `Cache-Control: max-age` deadlines are exactly that expiry, so
///    the FOAF face re-fetched its source on every single hit. The symptom the suite printed
///    was two lines about `clock-now` and `tz-now`; the cost was on `urn:httpGet`, which is
///    opted out of the walk and could not have reported it itself.
#[test]
fn a_clock_derived_result_expires_rather_than_threading() {
    use ikigai_core::{Expiry, Iri, Request, Verb};

    for (label, kernel) in [("root", root_kernel()), ("http door", http_kernel())] {
        for target in ["urn:time:now", "urn:tz:now"] {
            let repr = futures::executor::block_on(kernel.issue(
                Request::new(Verb::Source, Iri::parse(target.to_string()).expect("iri")),
                &ikigai_core::Capability::root(),
            ))
            .unwrap_or_else(|e| panic!("{label}: {target}: {e}"));
            assert!(
                matches!(repr.expiry, Expiry::At(_)),
                "{label}: `{target}` must expire at a deadline, not be cached forever or be \
                 live: {:?}",
                repr.expiry
            );
            // The deadline is honoured only by a kernel that can ask the time. A second
            // resolution inside the same minute is therefore a cache HIT — on BOTH kernels,
            // which is the property the door lacked.
            assert!(
                kernel.is_cached(
                    &Request::new(Verb::Source, Iri::parse(target.to_string()).expect("iri")),
                    &ikigai_core::Capability::root(),
                ),
                "{label}: `{target}` is not cached — this kernel has no clock, so every \
                 `Expiry::At` result on it (including every `urn:httpGet` max-age) \
                 recomputes on every request"
            );
        }
    }
}

/// **The HTTP door is a subset, stated as a list.**
///
/// `kernel_for` is what `ikigai serve --http` exposes to the public edge. Its posture is
/// documented ("no personal space") and enforced twice above the kernel — by the `--cap`
/// ceiling and by `--routes-only`. Both of those are CONFIGURATION. What is code is the
/// binding, and this is the red line under it: an owner-only resource must not be bound on
/// the door at all, so a mistake in the config cannot reach one.
#[test]
fn the_http_door_serves_no_owner_only_resource() {
    let door: BTreeSet<String> = walked(&http_kernel()).into_values().collect();
    let root: BTreeSet<String> = walked(&root_kernel()).into_values().collect();
    for id in OWNER_ONLY {
        assert!(
            root.contains(*id),
            "`{id}` is not bound on the REPL root either: this list has gone stale"
        );
        assert!(
            !door.contains(*id),
            "`{id}` is bound on the PUBLIC HTTP door: authority gates it, but it should not \
             be reachable there at all"
        );
    }
    // And the door does carry the resources it exists for.
    for id in [
        "foaf",
        "contact",
        "booking",
        "passkey-challenge",
        "decisions",
    ] {
        assert!(door.contains(id), "`{id}` is missing from the HTTP door");
    }
}
