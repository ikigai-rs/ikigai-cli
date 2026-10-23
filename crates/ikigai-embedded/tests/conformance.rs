//! `ikigai-conformance` over the two kernels this workspace COMPOSES.
//!
//! ## This crate is a host, not a module, and that changes what a clean report means
//!
//! `ikigai-embedded` binds about thirty endpoints of its own and inherits a hundred more
//! from twenty-odd published module crates, each with its own repo and its own adoption of
//! this same suite. No inherited endpoint is this workspace's to FIX, so since conformance
//! 0.8.0 each walk is scoped with `Suite::own` to [`OWN`]: an inherited endpoint is listed on
//! the report's `inherited:` line and not walked at all, and its record is its own repo's
//! conformance test. What IS this workspace's is [`OWN`], and the assertion is that **the
//! report is clean**. [`the_walked_catalog_is_classified`] holds the two tables to the actual
//! catalog, so an endpoint added later fails one test or the other and whoever added it has
//! to classify it, type its inputs, and decide whether the walk may fire it.
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
//! So the opt-out list in [`root_suite`] was written from the CATALOG, before this file ever
//! ran an invoking check — not from reading the first report. Every entry says which of the
//! five hazards it is: **spawns a process**, **reaches the network**, **sends a message**,
//! **touches the platform**, or **evaluates code**. The description-only checks (ARGSPECS,
//! NAMES, REQUIRES-VERB) still run over every one of them. Most of those seams belong to
//! crates this host composes (the subprocess seam, the HTTP verbs, inference, EventKit, the
//! Keychain, Zoom); since the walk is scoped with `Suite::own` they are inherited and never
//! fired, and the opt-outs left are for hazards this workspace owns.
//!
//! ## Hermetic, and the three things that leak if it is not
//!
//! `HOME` and `XDG_CONFIG_HOME` are redirected and [`ikigai_embedded::set_file_root`] is
//! called before any kernel is built, because:
//!
//! * our decision links and client records read keys and files under `file_root()`, and the
//!   walk FIRES the hermetic intake Sinks, which write there;
//! * `urn:orgfile:{path}` is jailed to whatever `calendar.json` names as `org_dir` — and
//!   with no config at all that is the empty path, which is the process's own working
//!   directory. The file module is inherited and not walked now, but a host built without
//!   that config is not the host this test means to describe;
//! * `browse.root` and the a11y layering read the config home, so a walk against the real
//!   one is about the machine it ran on rather than about the code.
//!
//! `set_file_root` is the typed channel this crate documents for exactly this: `cfg(test)`
//! does not reach a `tests/` binary, so the redirect has to be a call, not a compile flag.
//!
//! ## Fixtures
//!
//! Urlencoded submissions for the two public intake Sinks, a real plan for the three plan
//! resources, real IANA zones for `tz-convert`, an address for `contactblock-link`, and
//! `name` / `token` / `action` bindings for the template-bound entries. Without them those
//! endpoints report "did not resolve with the minimal inputs", which reads as a caching
//! finding (conformance PENDING #33) and means the walk failed to CALL rather than that the
//! endpoint failed to conform. (The fixtures for other crates' endpoints, Turtle, SPARQL,
//! JSON-LD and XSLT among them, went when the walk was scoped to [`OWN`].)
//!
//! ⚠ **A fixture is a claim, and 0.2.0 is the first version that audits it.** Under the 0.1.0
//! pin this file carried six fixtures that bought nothing — three whose ids the walk never
//! reached on the kernel being walked, and three (`xslt-transform`, `jsonld-compact`, and the
//! `contact`/`booking` Sinks) that named inputs the endpoint could not use, so the endpoint
//! was never probed while the report printed a `fixture:` line for it. Its DECLARATIONS check
//! is what said so; see [`base`] for the structural half of the same lesson.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ikigai_conformance::{rdf, Check, Fixture, Suite};
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
    ("contact-label", "ikigai-embedded"),
    ("contactblock-link", "ikigai-embedded"),
    ("contactlabel-link", "ikigai-embedded"),
    ("control", "ikigai-embedded"),
    ("decide-accept", "ikigai-embedded"),
    ("decide-css", "ikigai-embedded"),
    ("decide-link", "ikigai-embedded"),
    ("decisions", "ikigai-embedded"),
    ("foaf", "ikigai-embedded"),
    ("greeter", "ikigai-embedded"),
    ("host-arrangement", "ikigai-embedded"),
    ("host-demo", "ikigai-embedded"),
    ("host-heartbeat", "ikigai-embedded"),
    ("host-history", "ikigai-embedded"),
    ("host-identity", "ikigai-embedded"),
    ("host-info", "ikigai-embedded"),
    ("host-posture", "ikigai-embedded"),
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
    // Plans as resources (ledger #956): `urn:plan:eval`, `urn:plan:validate`,
    // `urn:plan:requires`, beside the runner they share with the REPL's `run`.
    ("plan-eval", "ikigai-engine"),
    ("plan-requires", "ikigai-engine"),
    ("plan-validate", "ikigai-engine"),
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
    ("diagram-arrangement", "ikigai-diagram"),
    ("diagram-kernel", "ikigai-diagram"),
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
    ("http-delete", "ikigai-http"),
    ("http-get", "ikigai-http"),
    ("http-head", "ikigai-http"),
    ("http-patch", "ikigai-http"),
    ("http-post", "ikigai-http"),
    // WebDAV `PROPFIND` and `REPORT`, bound by ikigai-http since 0.3.0.
    ("http-propfind", "ikigai-http"),
    ("http-put", "ikigai-http"),
    ("http-report", "ikigai-http"),
    ("ikigai-vocab", "ikigai-vocab"),
    ("jsonld-compact", "ikigai-jsonld"),
    ("jsonld-expand", "ikigai-jsonld"),
    ("jsonld-flatten", "ikigai-jsonld"),
    // 0.2.2 (ledger #1371, through ikigai-layers 0.2.7): the prune the layer host's JSON faces use.
    ("jsonld-prune", "ikigai-jsonld"),
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
    ("repo-pr-diff", "ikigai-repo"),
    ("repo-pr-files", "ikigai-repo"),
    ("repo-pr-list", "ikigai-repo"),
    ("repo-pr-view", "ikigai-repo"),
    ("repo-status", "ikigai-repo"),
    ("system-exec", "ikigai-repo"),
    ("sexpr-arrangement-from-rdf", "ikigai-sexpr"),
    ("sexpr-arrangement-to-rdf", "ikigai-sexpr"),
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
    ("meeting", "ikigai-meeting"),
    ("secret", "ikigai-secret"),
    ("secret-generate", "ikigai-secret"),
    ("secret-unlock", "ikigai-secret"),
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
    "secret",
    "secret-generate",
    "secret-unlock",
    "send",
    "meeting",
    "client-issue",
    "peer-list",
    // The picture of THIS host's arrangement: local root only (ikigai-diagram), like
    // `host-arrangement`, which says the same thing as a declaration.
    "diagram-arrangement",
    "diagram-kernel",
    // A plan is a request AMPLIFIER — one request, many steps, a map over a list — so the
    // door does not offer one until someone decides a public surface should (ledger #956).
    "plan-eval",
    "plan-requires",
    "plan-validate",
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
        //
        // ⚠ `view` is REQUIRED and was missing until 2026-09-12. ONE file, TWO independent
        // readers: `org_config` parses it with raw serde_json (so the org jail was always
        // set correctly), while `calendar_config` parses it as `CalendarConfig` — which
        // has no `serde(default)` for `view` and so rejected the whole document, printing
        // eight "parse error … — ignoring" lines per run. Nothing failed, and that is the
        // problem: a fixture that half-parses is a fixture whose reach nobody measures.
        std::fs::write(
            dir.join("config/ikigai/calendar.json"),
            format!(
                r#"{{"view":"Conformance-View","org_dir":"{}","org_files":["agenda.org"]}}"#,
                dir.join("org").display()
            ),
        )
        .expect("calendar.json");
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join("config"));
        ikigai_embedded::set_file_root(dir.join("workspace"));
        seed_workspace(&dir.join("workspace"));
        // ★ RECORD a posture, so the walk probes the graph a SERVING host emits rather than
        // the "unrecorded" placeholder. Without this the `text/turtle` face under test is
        // four triples long and the VOCABULARY finding names one term — which would make
        // the pinned waiver below look complete while covering almost none of the graph.
        // That is the fixture-is-a-claim lesson from this file's own header, in the one
        // place where the endpoint's output depends on process state instead of inputs.
        ikigai_embedded::posture::set_posture(ikigai_embedded::posture::Posture {
            door: "quic://127.0.0.1:14433".to_string(),
            mounts: ikigai_embedded::posture::MountPosture::Composed(vec![
                ikigai_embedded::posture::ComposedMount {
                    mode: "prefer",
                    prefix: "urn:iki:store:".to_string(),
                    target: "/tmp/conformance.sock".to_string(),
                    cert_dir: Some("/tmp/conformance/quic".to_string()),
                },
            ]),
            clients: vec![ikigai_embedded::posture::TrustedIdentity {
                label: "base".to_string(),
                fingerprint: "0123456789abcdef".to_string(),
                path: "/tmp/conformance/quic/client.crt".to_string(),
            }],
            surface: Some("host + fs".to_string()),
            authority: Some("per-client workspaces".to_string()),
            reloads: vec!["clients.json — per connection".to_string()],
        });
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
/// (The `file` and `xslt-transform` documents this used to seed went with their fixtures:
/// both endpoints are inherited since the walk is scoped with `Suite::own`.)
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

/// A plan that is safe to fire under root: one pure step, and nothing it reads touches the
/// network, a process or the platform — so the walk RUNS `urn:plan:eval` rather than
/// reporting a plan that did not resolve.
const PLAN: &str = "\
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:conformance> a ik:Process ;
    ik:step <urn:plan:conformance:step:1> ;
    ik:result <urn:plan:conformance:step:1> .
<urn:plan:conformance:step:1> a ik:Step ;
    ik:verb \"Source\" ;
    ik:resolves <urn:iki:fn:toUpper> ;
    ik:argument <urn:plan:conformance:step:1:arg:in> .
<urn:plan:conformance:step:1:arg:in> a ik:Argument ;
    ik:inputName \"in\" ;
    ik:value \"conformance\" .
";

/// ★ **A `Suite` is a statement about the MANIFOLD it walks — so there are three of them.**
///
/// This crate composes two kernels, and they are not the same catalog: the personal, Lisp,
/// repo and LLM surface is on the REPL root only, seven ids are on the HTTP door only (`foaf`,
/// the passkey trio, `calendar-request`, `contact-block`, `contact-label`), and the rest are on
/// both. One
/// shared builder therefore carried, on every run, declarations that could not apply to the
/// kernel being walked, and DECLARATIONS reports every one of those. So [`base`] is what is
/// true of both manifolds, and [`root_suite`] and [`door_suite`] add what is true of one.
/// (Same shape and same conclusion as ikigai-module #17.) Moving an endpoint between the two
/// compositions has to move its declarations too, and `the_walked_catalog_is_classified`
/// fails first if it does not.
///
/// ★ **Since conformance 0.8.0 the walk is scoped to [`OWN`] with `Suite::own`** ([`conforms`]
/// adds one `own` per OWN id the kernel binds). Every [`INHERITED`] endpoint is listed on the
/// report's `inherited:` line and is NOT walked: no check reads it and no probe fires it.
/// That replaced two things this file used to carry by hand. One was the partition in
/// `conforms` that tolerated every inherited finding and failed only on ours. The other was
/// about thirty hazard opt-outs (`urn:system:exec`, the six HTTP verbs, the `gh` facades,
/// the inference endpoints, EventKit, the Keychain, Zoom) and a dozen fixtures for other
/// crates' endpoints, which only existed so that walking a dependency would neither fire
/// a hazard nor fail to call it. Each module's record is its own repo's conformance test.
/// The opt-outs that remain below are for endpoints this workspace OWNS.
fn base() -> Suite {
    Suite::new()
        // FAILURES (conformance 0.10.0, ledger #1546): declared failure classes = produced. Opted
        // into here because this walk asserts that NO check is skipped, and the default from
        // 0.11.0 anyway. An action that declares nothing is listed, never a finding.
        .check_failures()
        // ---- fired, with inputs that work ----------------------------------------
        // Take reads `content` as the id to take since ledger #877 (the engine puts the value
        // of `delete urn:space:q <id>` there), so the walk's sample `x` now names a tuple that
        // does not exist. An EMPTY `content` is what the engine sends on a bare delete: the
        // work-queue pop, which is exactly what this walk exercised before ledger #877.
        .fixture(Fixture::new("space", Verb::Source).binding("name", "conformance"))
        .fixture(Fixture::new("space", Verb::Delete).arg("content", ""))
        .fixture(Fixture::new("client", Verb::Source).binding("token", "conformance"))
        // ★ The two public intake Sinks, FIRED — and the reason a fixture is right here
        // rather than a waiver. `content` is a urlencoded submission, so the walk's sample
        // value (`x`) can never satisfy the declared fields and OUTPUTS reported only "the
        // minimal resolution failed". These are hermetic: the handler consults `urn:decisions`
        // and `urn:client:*` (local files under the fixture root) and drops a tuple into a
        // local space. Nothing is mailed and nothing leaves the machine — the reactive handler
        // that would act on the tuple is a WATCHER, and no watcher runs in this binary.
        .fixture(Fixture::new("contact", Verb::Sink).arg(
            "content",
            "name=Conformance&email=someone%40example.org&message=a+fixture+enquiry",
        ))
        .fixture(Fixture::new("booking", Verb::Sink).arg(
            "content",
            "name=Conformance&email=someone%40example.org&period=week&zone=UTC",
        ))
        // Real IANA zones: the suite's `x` is refused by the tzdata lookup, which reads as a
        // caching finding on an endpoint whose caching is fine (PENDING #33).
        .fixture(
            Fixture::new("tz-convert", Verb::Source)
                .arg("in", "2026-01-01T12:00:00Z")
                .arg("from", "UTC")
                .arg("to", "America/New_York"),
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
        // inputs. They are `cacheable_until(next minute)` — `Expiry::At` — and since
        // conformance 0.6.1 an `At` deadline is a bound, but `pure` is still the declaration
        // this file has used for "an empty thread set is correct here", for a reason the suite
        // cannot express: a clock is not a resource and no `depends_on` could name it. The
        // expiry itself is pinned by hand in `a_clock_derived_result_expires_rather_than_threading`
        // below, so the declaration covers nothing that test does not check.
        .pure("clock-now")
        .pure("tz-now")
        // ★ THE SECOND REAL VOCABULARY GAP, in a repo that cannot fix it — `urn:host:health`
        // next door is the first. Declaring `urn:host:posture`'s `text/turtle` face brings
        // it under VOCABULARY, which finds fifteen `ik:` terms `ikigai-vocab` does not
        // define, at the pinned version or at HEAD. (Sixteen until vocab 0.1.78 defined
        // `ik:Mount` — for the TOPOLOGY, not for this graph; see the pinning test.) The fix is `vocabulary.ttl` in
        // ikigai-core plus a manual deploy of https://ikigai-rs.dev/ns; both belong to that
        // repo, so this waits and the need is reported up.
        //
        // ⚠ `opt_out_check`, never `opt_out`: the coarse lever would take ENFORCED,
        // CACHEABLE and SKOLEM-RDF down with it — on an endpoint whose whole point is a
        // capability gate and an uncacheable read. The exact set is pinned by hand in
        // `the_posture_graph_uses_exactly_fifteen_undefined_terms`, so this goes red in both
        // directions, including the day the terms land.
        .opt_out_check(
            "host-posture",
            Check::Vocabulary,
            "ik:Posture / ik:TrustedClient and their properties are undefined in ikigai-vocab \
             (at the pin AND at HEAD), and ik:Mount is defined for a different thing; the \
             fix is vocabulary.ttl in ikigai-core plus a /ns deploy. The exact undefined set \
             is pinned by hand below.",
        )
}

/// [`base`] plus everything of OURS bound only on the REPL/TUI root — which is where nearly
/// every one of this host's hazards lives.
fn root_suite() -> Suite {
    base()
        // ---- fired, with inputs that work ----------------------------------------
        // An address, because the endpoint refuses anything that is not one before it mints.
        .fixture(
            Fixture::new("contactblock-link", Verb::Source).arg("email", "someone@example.org"),
        )
        // A label from the closed set and an enquiry to name (the tuple's text; the link
        // carries only its id), because the endpoint refuses anything else before it mints.
        .fixture(
            Fixture::new("contactlabel-link", Verb::Source)
                .arg("label", "ham")
                .arg("enquiry", "((message \"a fixture enquiry\"))"),
        )
        // The plan resources, over a real plan: one pure step, so evaluating it is a read.
        .fixture(Fixture::new("plan-eval", Verb::Source).arg("in", PLAN))
        .fixture(Fixture::new("plan-validate", Verb::Source).arg("in", PLAN))
        .fixture(Fixture::new("plan-requires", Verb::Source).arg("in", PLAN))
        // ---- declared -------------------------------------------------------------
        // `urn:iki:host:arrangement` serves the arrangement this host was BUILT from: the
        // `Dump` is captured once, when the kernel is constructed, and the endpoint only
        // re-renders it (Turtle, or the `.arrangement` s-expression by `as=`). Nothing can
        // change it for the life of the kernel, because a different arrangement is a
        // different kernel. So an empty thread set is correct, exactly as for the compiled-in
        // documents in [`base`]. Conformance 0.5.0's purity rule reported it as "cached with
        // no thread but its own name", which is what kept this crate's pin at 0.2.0 until
        // the wave of 2026-10-14.
        .pure("host-arrangement")
        // ---- waived, per check, with the exception pinned by hand -----------------
        // ★ A REAL VOCABULARY GAP, in a repo that cannot fix it. Declaring `urn:host:health`'s
        // `text/turtle` face (it was served and unannounced) brought it under VOCABULARY,
        // which found four `ik:` terms `ikigai-vocab` does not define — not at the pinned
        // version and not at HEAD. The fix is `vocabulary.ttl` in ikigai-core plus a manual
        // deploy of https://ikigai-rs.dev/ns; both belong to that repo, so this waits.
        //
        // ⚠ `opt_out_check`, never `opt_out`: the coarse lever would take ENFORCED,
        // CACHEABLE and SKOLEM-RDF down with it on a capability-gated endpoint. And the
        // exception is pinned EXACTLY in `the_health_graph_uses_exactly_four_undefined_terms`
        // below, so this goes red in both directions — including the day the terms land.
        .opt_out_check(
            "kernel-health",
            Check::Vocabulary,
            "ik:Health / ik:verdict / ik:uptimeSeconds / ik:staleJobs are undefined in \
             ikigai-vocab (at the pin AND at HEAD); the fix is vocabulary.ttl in ikigai-core \
             plus a /ns deploy. The exact undefined set is pinned by hand below.",
        )
        // ★ THE THIRD, from the same gap. `urn:time:jobs` grew a `text/turtle` face for the
        // UI book's inspector (ledger #2142), and its job terms (`ik:JobList`, `ik:Job` and
        // their properties) are not in `ikigai-vocab` either: they belong beside core's
        // `ik:Scheduler` in `vocabulary.ttl`, which is ikigai-core's to change. Waived per
        // check for the same reason as the two above, and pinned EXACTLY — over a registry
        // that has jobs, run and unrun, read and withheld — in
        // `the_jobs_graph_uses_exactly_thirteen_undefined_terms`.
        .opt_out_check(
            "time-jobs",
            Check::Vocabulary,
            "ik:JobList / ik:Job and their properties are undefined in ikigai-vocab; the fix \
             is vocabulary.ttl in ikigai-core beside ik:Scheduler plus a /ns deploy. The exact \
             undefined set is pinned by hand below.",
        )
        // ---- NOT fired, and which hazard each one is -----------------------------
        //
        // ★ Written from the catalog BEFORE the first invoking run. See the module docs.
        // Every id here is OURS; the hazards of the crates this host composes (a subprocess
        // seam, outbound HTTP, inference, EventKit, the Keychain, Zoom) are inherited and
        // not walked at all (see [`base`]).
        //
        // Reaches the network.
        .opt_out("peer-list", None, "mDNS multicast on the local network")
        // Sends a message to a person or a third party. These are not reversible by
        // deleting a file afterwards, which is what makes them a different class from the
        // hermetic Sinks the walk is welcome to fire.
        .opt_out("send", None, "submits real mail over SMTP")
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
        // silently denied), and these write the USER'S real calendar.
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
        // the macOS Keychain behind a Touch ID prompt.
        //
        // ★ **A hazard waiver keyed on an endpoint ID does not survive the module splitting
        // that endpoint**, and the failure is silent in the direction that matters: when
        // ikigai-secret 0.1.6 bound `urn:secret:unlock` and `urn:secret:generate` as their own
        // endpoints, the waiver on `urn:secret` stopped reaching them, and the walk fired both
        // against the real Keychain, as far as a Touch ID prompt. Those are inherited now and
        // not walked; the lesson stands for every id below: **re-read the hazard list whenever
        // a pin moves, not only when this host binds something new.**
        .opt_out(
            "decide-link",
            None,
            "reads the signing key through urn:secret:*: Keychain, behind a Touch ID prompt",
        )
}

/// [`base`] plus the seven resources bound only on the public HTTP door.
///
/// A short list, and that is the door's whole point: it is the SUBSET, and
/// `the_http_door_serves_no_owner_only_resource` states the other half as a red line.
fn door_suite() -> Suite {
    base()
        // A binding-only fixture: `urn:calendar-request:{action}` cannot be formed without it.
        .fixture(Fixture::new("calendar-request", Verb::Source).binding("action", "decline"))
        // ★ The two emailed decision links, and why REQUIRED and AUTHORITY are WAIVED on
        // them rather than "fixed" (conformance 0.8.0 found both on the HTTP door).
        //
        // REQUIRED: `id`/`exp`/`t` (`email`/`exp`/`t` for the block link) are declared
        // required, and a call without one resolves. Two reasons, both deliberate. The fields
        // have TWO channels, a named argument or the urlencoded form body a browser POSTs as
        // `content` (`decide::param`), so the honest contract is "exactly one of", which an
        // ArgSpec cannot say; marking them optional would tell the manifold a link works
        // without them, which it does not. And a link missing a field is answered with the
        // SAME "that link didn't work" page as an expired, forged or used one, so a prober
        // learns nothing from which kind of bad link it sent. A typed refusal for one kind
        // would be the first oracle.
        //
        // AUTHORITY: the Sink's authority is the Ed25519-signed, expiring token in the link
        // (plus the passkey second factor once one is enrolled), checked BEFORE anything is
        // recorded. A call without a valid token records nothing and answers that same page,
        // which the walk reads as "mutated under no grants" because it cannot see the space
        // the decision would have been written to. `a_forged_or_expired_token_records_nothing`
        // in `src/decide.rs` and `src/contactblock.rs` pins that the write did not happen.
        // There is no kernel capability to declare: the link is opened by an anonymous
        // browser on purpose.
        .opt_out_check(
            "calendar-request",
            Check::Required,
            "id/exp/t arrive as named arguments OR in the form body (`content`), an \
             exactly-one-of intake an ArgSpec cannot state; a link missing one answers the \
             same uniform bad-link page as an expired or forged one, so there is no oracle",
        )
        .opt_out_check(
            "calendar-request",
            Check::Authority,
            "authority is the signed, expiring link token (plus passkey once enrolled), \
             verified before anything is recorded; without a valid token the Sink records \
             nothing and answers the bad-link page (pinned by \
             a_forged_or_expired_token_records_nothing in src/decide.rs)",
        )
        .opt_out_check(
            "contact-block",
            Check::Required,
            "email/exp/t arrive as named arguments OR in the form body (`content`), an \
             exactly-one-of intake an ArgSpec cannot state; a link missing one answers the \
             same uniform bad-link page as an expired or forged one, so there is no oracle",
        )
        .opt_out_check(
            "contact-block",
            Check::Authority,
            "authority is the signed, expiring link token (plus passkey once enrolled), \
             verified before anything is recorded; without a valid token the Sink records \
             nothing and answers the bad-link page (pinned by \
             a_forged_or_expired_token_records_nothing in src/contactblock.rs)",
        )
        // The label link (ledger #1513) is the block link's shape exactly, for the same two
        // reasons.
        .opt_out_check(
            "contact-label",
            Check::Required,
            "id/label/exp/t arrive as named arguments OR in the form body (`content`), an \
             exactly-one-of intake an ArgSpec cannot state; a link missing one answers the \
             same uniform bad-link page as an expired or forged one, so there is no oracle",
        )
        .opt_out_check(
            "contact-label",
            Check::Authority,
            "authority is the signed, expiring link token (plus passkey once enrolled), \
             verified before anything is recorded; without a valid token the Sink records \
             nothing and answers the bad-link page (pinned by \
             every_bad_label_link_records_nothing in src/contactblock.rs)",
        )
        // Ours, and it fetches: every face of `urn:iki:foaf` starts with a `urn:http:get` of
        // `src=`. Its capability floor is pinned by hand instead, in
        // `foaf::tests::without_a_net_grant_the_door_refuses` — which is the check `opt_out`
        // drops (conformance PENDING #21) and the one that matters for a network-backed
        // action.
        .opt_out("foaf", None, "issues urn:http:get: reaches the network")
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
        //
        // ⚠ Per VERB, and per this manifold: `urn:passkey:register` is bound on the door
        // alone, so the same line on the root suite would be a DECLARATIONS finding.
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

/// The ids of `table` that `kernel` binds.
fn bound_from(kernel: &Kernel, table: &[(&'static str, &'static str)]) -> BTreeSet<String> {
    let bound: BTreeSet<String> = walked(kernel).into_values().collect();
    table
        .iter()
        .map(|(id, _)| id.to_string())
        .filter(|id| bound.contains(id))
        .collect()
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// **Every endpoint either belongs to this workspace or names the crate it came from.**
///
/// The classification is what makes `conforms` meaningful: it scopes each walk to [`OWN`]
/// with `Suite::own`, so "the report is clean" is satisfiable by leaving an id out of `OWN`.
/// This test closes that by requiring the union to cover the catalog exactly, with no id in
/// both tables — an endpoint added to a member crate fails here until it is listed, and a
/// module crate that grows one fails here too, which is the notification a dependency bump
/// otherwise does not give.
#[test]
fn the_walked_catalog_is_classified() {
    let known: BTreeSet<&str> = owners().keys().copied().collect();
    let own: BTreeSet<&str> = OWN.iter().map(|(id, _)| *id).collect();
    let both: Vec<&str> = INHERITED
        .iter()
        .map(|(id, _)| *id)
        .filter(|id| own.contains(id))
        .collect();
    assert!(
        both.is_empty(),
        "these ids are in BOTH OWN and INHERITED; an endpoint has one owner: {both:?}"
    );

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

/// ★ **The suite over both compositions, scoped to what this workspace owns.**
///
/// Each walk declares one `Suite::own` per [`OWN`] id its kernel binds, so every [`INHERITED`]
/// endpoint is reported as inherited and not walked (see [`base`]). The report must be clean,
/// and both halves of the scope are pinned against the classification: the walk reached
/// exactly our ids on that kernel, and the inherited list is exactly the other crates' ids
/// on it. A module whose new release grows an endpoint therefore turns
/// `the_walked_catalog_is_classified` red, never this report silently longer.
#[test]
fn conforms() {
    // Each composition gets the suite written FOR it — see `base` for why one shared
    // builder is a statement about a manifold that is only half true of either kernel.
    for (label, kernel, suite) in [
        (
            "ikigai_embedded::kernel() — the REPL/TUI root",
            root_kernel(),
            root_suite(),
        ),
        (
            "ikigai_embedded::kernel_for() — the HTTP door",
            http_kernel(),
            door_suite(),
        ),
    ] {
        let ours = bound_from(&kernel, OWN);
        let theirs = bound_from(&kernel, INHERITED);
        let suite = ours.iter().fold(suite, |suite, id| suite.own(id.as_str()));
        let report = suite.run_blocking(&kernel);
        // The report does not say which kernel it walked, so the header is this file's own.
        eprintln!("--- {label} ---\n{report}");

        assert!(report.is_clean(), "{label}:\n{report}");
        let walked: BTreeSet<String> = report.walked.iter().cloned().collect();
        assert_eq!(walked, ours, "{label}: the walk reached exactly our ids");
        let inherited: BTreeSet<String> = report.declared.inherited.iter().cloned().collect();
        assert_eq!(
            inherited, theirs,
            "{label}: everything else is inherited, and nothing more"
        );
        assert_eq!(
            report.checks.skipped().count(),
            0,
            "every check runs over a composing host: {report}"
        );
    }
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
///    was two lines about `clock-now` and `tz-now`; the cost was on `urn:http:get`, which is
///    inherited (not walked) and could not have reported it itself.
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
                 `Expiry::At` result on it (including every `urn:http:get` max-age) \
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

/// ★ **The posture graph's undefined terms, as an EXACT list — that waiver's other half.**
///
/// `opt_out_check("host-posture", Check::Vocabulary, …)` in [`base`] silences a rule this
/// repo cannot satisfy: `urn:host:posture`'s `text/turtle` face names fifteen `ik:` terms no
/// version of `ikigai-vocab` defines. A waiver alone would also waive the SIXTEENTH term
/// somebody adds next, so the set is pinned here, reproducing `VOCABULARY` from the public
/// [`rdf`] helpers. It fails in both directions: a new invented term, and the day
/// `vocabulary.ttl` defines these.
///
/// ⚠ Unlike the health graph's list, this one is COMPLETE for the graph as emitted, because
/// [`fixture_home`] records a posture carrying one of everything — a mount with its own cert
/// dir, a trusted client, a surface, a ceiling and a reload. An empty posture would emit two
/// terms and this test would look just as green.
///
/// The reused terms are as deliberate as the invented ones: `ik:path` and `rdfs:label` are
/// DEFINED, and the properties the vocabulary already has for a target, a capability or an
/// id (`ik:target`, `ik:cap`, `ik:id`) carry an `rdfs:domain` of `ik:Route` or `ik:Endpoint`,
/// so reusing them here would entail that a mount IS a route. A synonym is the lesser evil;
/// widening those domains is the vocabulary change to argue for.
///
/// ⚠ **It was sixteen until vocab 0.1.78, and the one that left did not leave because it was
/// FIXED.** 0.1.78 defines `ik:Mount` for `urn:kernel:topology`: `rdfs:subClassOf ik:Space`, "a
/// prefix-guarded import … No rewrite". This graph's `ik:Mount` is a CONFIGURED mount — a posture
/// record with `ik:mountPrefix`/`ik:mountTarget`, and for the alias kind it DOES rewrite
/// (`MountedRemote` strips the prefix). So the term is now defined, the check is satisfied, and
/// the triple entails that a posture record is a space that does not rewrite. That is a
/// vocabulary collision, not a closed gap — reported up with the 0.1.29 arc rather than
/// renamed here, because the right spelling (a posture-side class, or the topology node's IRI
/// as the object) is the vocabulary's call.
#[test]
fn the_posture_graph_uses_exactly_fifteen_undefined_terms() {
    use ikigai_core::{Capability, Iri, Request, Verb};

    let kernel = root_kernel();
    let repr = futures::executor::block_on(
        kernel.issue(
            Request::new(
                Verb::Source,
                Iri::parse("urn:host:posture".to_string()).expect("iri"),
            )
            .with_arg("as", ikigai_core::ArgRef::Inline(b"text/turtle".to_vec())),
            &Capability::root(),
        ),
    )
    .expect("the posture graph face resolves");
    let triples =
        rdf::parse(&repr.repr_type.media_type, &repr.bytes).expect("the face parses as Turtle");
    let undefined: Vec<String> = rdf::terms(&triples)
        .into_iter()
        .filter(|t| !rdf::is_defined(t, &[]))
        .collect();
    assert_eq!(
        undefined,
        vec![
            "https://ikigai-rs.dev/ns#Posture",
            "https://ikigai-rs.dev/ns#TrustedClient",
            "https://ikigai-rs.dev/ns#asOf",
            "https://ikigai-rs.dev/ns#authority",
            "https://ikigai-rs.dev/ns#certDir",
            "https://ikigai-rs.dev/ns#door",
            "https://ikigai-rs.dev/ns#fingerprint",
            "https://ikigai-rs.dev/ns#mount",
            "https://ikigai-rs.dev/ns#mountMode",
            "https://ikigai-rs.dev/ns#mountPosture",
            "https://ikigai-rs.dev/ns#mountPrefix",
            "https://ikigai-rs.dev/ns#mountTarget",
            "https://ikigai-rs.dev/ns#reloads",
            "https://ikigai-rs.dev/ns#surface",
            "https://ikigai-rs.dev/ns#trustedClient",
        ],
        "the waived vocabulary exception has changed — widen the waiver's reason, or drop \
         both it and this test if `vocabulary.ttl` now defines these"
    );
}

/// ★ **The jobs graph's undefined terms, as an EXACT list — that waiver's other half.**
///
/// `opt_out_check("time-jobs", Check::Vocabulary, …)` in [`root_suite`] silences a rule this
/// repo cannot satisfy: the `text/turtle` face of `urn:time:jobs` names `ik:` terms no version
/// of `ikigai-vocab` defines. The set is pinned here so the waiver cannot quietly grow, and
/// so this fails the day `vocabulary.ttl` defines them.
///
/// ⚠ NOT read from the composed kernel. Its registry is a process-global static driven by
/// real timer threads, and the walk sees it with no jobs, which would pin one term. This
/// reads the same `ikigai_time::space` over a registry of its own, with a job that has run
/// and one that has not, read once by a caller that covers them and once by one that does
/// not, so every term the face can emit is in the graph. `ik:verb` is the one it reuses: it
/// is defined, with no domain, for the same five words.
#[test]
fn the_jobs_graph_uses_exactly_thirteen_undefined_terms() {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use ikigai_core::{
        ArgRef, Capability, Description, EndpointSpace, Exact, FnEndpoint, Invocation, Iri,
        ReprType, Representation, Request, SystemClock,
    };
    use ikigai_resolve::Resolver;
    use ikigai_time::{JobRegistry, Schedule, TimerBackend, TimerHandle};

    /// Holds each job's tick for the test to fire by hand.
    #[derive(Default)]
    struct Manual(Mutex<Vec<Arc<dyn Fn() + Send + Sync>>>);
    impl TimerBackend for Manual {
        fn start(
            &self,
            _interval: Duration,
            _recurring: bool,
            on_tick: Arc<dyn Fn() + Send + Sync>,
        ) -> TimerHandle {
            self.0.lock().unwrap().push(on_tick);
            TimerHandle::new(|| {})
        }
    }

    let backend = Arc::new(Manual::default());
    let registry = JobRegistry::new(backend.clone(), Arc::new(SystemClock));
    let space: EndpointSpace = ikigai_time::space(registry.clone()).bind(
        Exact::new("urn:x"),
        FnEndpoint::new("x", |_: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"ok".to_vec(),
            ))
        })
        .with_description(Description::new("x").verb(Verb::Source)),
    );
    let kernel = Arc::new(Kernel::new(Arc::new(space)));
    registry.set_resolver(Arc::clone(&kernel) as Arc<dyn Resolver>);
    let every = Schedule::Every(Duration::from_secs(1));
    registry
        .schedule(
            "urn:x".into(),
            Verb::Source,
            every.clone(),
            true,
            Capability::root(),
        )
        .expect("schedule");
    backend.0.lock().unwrap()[0]();
    registry
        .schedule(
            "urn:x".into(),
            Verb::Source,
            every,
            false,
            Capability::root(),
        )
        .expect("schedule");

    let mut undefined = BTreeSet::new();
    for reader in [
        Capability::root(),
        Capability::scoped([ikigai_time::CAP_READ]),
    ] {
        let request = Request::new(Verb::Source, Iri::parse("urn:time:jobs").expect("iri"))
            .with_arg("as", ArgRef::Inline(b"text/turtle".to_vec()));
        let (repr, _) = Resolver::issue_as(kernel.as_ref(), request, &reader)
            .expect("the jobs graph face resolves");
        let triples =
            rdf::parse(&repr.repr_type.media_type, &repr.bytes).expect("the face parses as Turtle");
        assert!(rdf::blank_nodes(&triples).is_empty(), "skolemized");
        undefined.extend(
            rdf::terms(&triples)
                .into_iter()
                .filter(|t| !rdf::is_defined(t, &[])),
        );
    }
    assert_eq!(
        undefined.into_iter().collect::<Vec<_>>(),
        vec![
            "https://ikigai-rs.dev/ns#Job",
            "https://ikigai-rs.dev/ns#JobList",
            "https://ikigai-rs.dev/ns#interval",
            "https://ikigai-rs.dev/ns#job",
            "https://ikigai-rs.dev/ns#jobId",
            "https://ikigai-rs.dev/ns#jobTarget",
            "https://ikigai-rs.dev/ns#lastOutput",
            "https://ikigai-rs.dev/ns#lastOutputWithheld",
            "https://ikigai-rs.dev/ns#lastRunAt",
            "https://ikigai-rs.dev/ns#nextRunAt",
            "https://ikigai-rs.dev/ns#persistent",
            "https://ikigai-rs.dev/ns#recurring",
            "https://ikigai-rs.dev/ns#runs",
        ],
        "the waived vocabulary exception has changed — widen the waiver's reason, or drop \
         both it and this test if `vocabulary.ttl` now defines these"
    );
}

/// ★ **The health graph's undefined terms, as an EXACT list — the waiver's other half.**
///
/// `opt_out_check("kernel-health", Check::Vocabulary, …)` in [`root_suite`] silences a rule
/// this repo cannot satisfy: `urn:host:health`'s `text/turtle` face names four `ik:` terms no
/// version of `ikigai-vocab` defines. A waiver alone would also waive the FIFTH invented term
/// somebody adds next, so the set is pinned here instead, reproducing `VOCABULARY` from the
/// public [`rdf`] helpers. It fails in both directions: a new invented term, and the day
/// `vocabulary.ttl` defines these.
///
/// ⚠ **What this does NOT cover, stated because the count looks complete and is not.** The
/// same face emits `ik:Job`, `ik:intervalSeconds`, `ik:runs`, `ik:stale`, `ik:sinceLastSeconds`,
/// `ik:failuresInARow`, `ik:sinceLastSuccessSeconds` and `ik:asleepSeconds` for each recurring
/// job, and those are undefined too — the fixture kernel simply schedules none, so the walk
/// never sees them. Twelve terms need defining; four are what a test can hold.
#[test]
fn the_health_graph_uses_exactly_four_undefined_terms() {
    use ikigai_core::{Capability, Iri, Request, Verb};

    let kernel = root_kernel();
    let repr = futures::executor::block_on(
        kernel.issue(
            Request::new(
                Verb::Source,
                Iri::parse("urn:host:health".to_string()).expect("iri"),
            )
            .with_arg("as", ikigai_core::ArgRef::Inline(b"text/turtle".to_vec())),
            &Capability::root(),
        ),
    )
    .expect("the health graph face resolves");
    let triples =
        rdf::parse(&repr.repr_type.media_type, &repr.bytes).expect("the face parses as Turtle");
    let undefined: Vec<String> = rdf::terms(&triples)
        .into_iter()
        .filter(|t| !rdf::is_defined(t, &[]))
        .collect();
    assert_eq!(
        undefined,
        vec![
            "https://ikigai-rs.dev/ns#Health",
            "https://ikigai-rs.dev/ns#staleJobs",
            "https://ikigai-rs.dev/ns#uptimeSeconds",
            "https://ikigai-rs.dev/ns#verdict",
        ],
        "the waived vocabulary exception has changed — widen the waiver's reason, or drop \
         both it and this test if `vocabulary.ttl` now defines these"
    );
}
