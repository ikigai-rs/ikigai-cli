//! `urn:plan:eval`, `urn:plan:validate` and `urn:plan:requires` over the CMS link-check
//! plans — the fixtures that pin the process vocabulary.
//!
//! Reader-only, like the round trip: without `plan-reader` there is no plan space.
#![cfg(feature = "plan-reader")]

//! The fixtures under `tests/fixtures/` are VERBATIM copies of
//! `ikigai-core/crates/ikigai-vocab/tests/fixtures/plan-linkcheck*.ttl` as published in
//! ikigai-vocab 0.1.87. They name resources that do not exist yet (`urn:http:reachable`,
//! `urn:cms:policy:*`, a plan-driven `urn:cms:linkstatus` Sink …), so this file binds a
//! recording stub at each one — what is under test is the RUNNER, and the transcript of
//! what every stub was asked is the evidence that two runs were the same run.
//!
//! The bar, from the brief (ledger #956):
//!
//! * each fixture runs through `urn:plan:eval` with the same result, and the same requests,
//!   as the REPL's `run` — one runner, two hosts;
//! * validation refuses a malformed plan: two feeds (the shapes catch it) and a cycle
//!   through an `ik:ref` (the shapes cannot; the reader does);
//! * `urn:plan:requires` derives the right scopes, and a run under a narrower capability is
//!   refused exactly where it said.

use std::sync::{Arc, Mutex};

use futures::executor::block_on;
use ikigai_core::{
    ArgRef, ArgSpec, Capability, Description, EndpointSpace, Error, Exact, FnEndpoint, Invocation,
    Iri, Kernel, MetaRenderer, ReprType, Representation, Request, Verb,
};
use ikigai_engine::{Action, Engine};

const FIXTURES: [&str; 4] = [
    "plan-linkcheck",
    "plan-linkcheck-strict",
    "plan-linkcheck-repair",
    "plan-linkcheck-scoped",
];

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}.ttl", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

type Log = Arc<Mutex<Vec<String>>>;

/// What an endpoint saw: verb, target, and every argument by name, sorted — argument order
/// is not part of a request's identity.
fn entry(inv: &Invocation<'_>) -> String {
    let mut args: Vec<String> = inv
        .request
        .args
        .keys()
        .map(|name| match inv.inline_str(name) {
            Ok(value) => format!("{name}={value}"),
            Err(_) => format!("{name}=<non-inline>"),
        })
        .collect();
    args.sort();
    format!(
        "{:?} {} [{}]",
        inv.request.verb,
        inv.request.target.as_str(),
        args.join(" ")
    )
}

/// The engine reads contracts as `Meta as=application/json` and fails OPEN without them
/// (every value routed to `in`), so a routing test on a kernel without this proves nothing.
struct JsonRenderer;
impl MetaRenderer for JsonRenderer {
    fn render(
        &self,
        description: &Description,
        _target: &ReprType,
    ) -> ikigai_core::Result<Representation> {
        Ok(Representation::new(
            ReprType::new("application/json"),
            serde_json::to_vec(description).expect("serialize description"),
        ))
    }
}

/// One world: a kernel, the transcript its stubs keep, and the plan `urn:t:plan` holds.
struct World {
    kernel: Arc<Kernel>,
    log: Log,
    plan: Arc<Mutex<String>>,
}

/// A recording stub. Its answer is cacheable when `cacheable` — the pure reads — so the
/// cacheability of a whole plan is visibly what its steps make it.
fn stub(
    tag: &'static str,
    log: &Log,
    description: Description,
    cacheable: bool,
    answer: impl Fn(&Invocation<'_>) -> String + Send + Sync + 'static,
) -> FnEndpoint {
    let log = Arc::clone(log);
    FnEndpoint::new(tag, move |inv: &Invocation<'_>| {
        log.lock().expect("log").push(entry(inv));
        let representation =
            Representation::new(ReprType::new("text/plain"), answer(inv).into_bytes());
        Ok(if cacheable {
            representation.cacheable()
        } else {
            representation
        })
    })
    .with_description(description)
}

fn arg(inv: &Invocation<'_>, name: &str) -> String {
    inv.inline_str(name).unwrap_or("").to_string()
}

fn input(name: &str) -> ArgSpec {
    ArgSpec::new(name).summary(format!("the {name}"))
}

fn world() -> World {
    let log: Log = Arc::default();
    let plan: Arc<Mutex<String>> = Arc::default();
    let reads = |name: &str| Description::new(name).verb(Verb::Source);

    let held = Arc::clone(&plan);
    let mut space = EndpointSpace::new()
        // The stored plan — what `run urn:t:plan` reads. Not recorded: the transcript
        // holds only what the PLAN asked for.
        .bind(
            Exact::new("urn:t:plan"),
            FnEndpoint::new("plan-store", move |_: &Invocation<'_>| {
                Ok(Representation::new(
                    ReprType::new("text/turtle"),
                    held.lock().expect("plan").clone().into_bytes(),
                ))
            })
            .with_description(Description::new("plan-store").verb(Verb::Source)),
        )
        .bind(
            Exact::new("urn:cms:bookmarks"),
            stub(
                "bookmarks",
                &log,
                reads("bookmarks")
                    .input(input("root").optional())
                    .input(input("tag").optional())
                    .input(input("as").optional()),
                true,
                |inv| {
                    if arg(inv, "tag") == "research" {
                        "https://a.example/\nhttps://b.example/".to_string()
                    } else {
                        "https://a.example/\nhttps://b.example/\nhttps://c.example/".to_string()
                    }
                },
            ),
        )
        .bind(
            Exact::new("urn:http:reachable"),
            stub(
                "reachable",
                &log,
                reads("reachable")
                    .input(input("url"))
                    .input(input("ttl").optional())
                    .requires("urn:cap:net:*"),
                true,
                |inv| {
                    let url = arg(inv, "url");
                    let status = if url.contains("//b.") { 404 } else { 200 };
                    format!("{url} {status}")
                },
            ),
        )
        .bind(
            Exact::new("urn:text:wc"),
            stub(
                "wc",
                &log,
                reads("wc")
                    .input(input("in"))
                    .input(input("count").optional()),
                true,
                |inv| arg(inv, "in").lines().count().to_string(),
            ),
        )
        .bind(
            Exact::new("urn:wayback:latest"),
            stub(
                "wayback",
                &log,
                reads("wayback")
                    .input(input("in"))
                    .requires("urn:cap:net:*"),
                true,
                |inv| match arg(inv, "in") {
                    url if url.is_empty() => String::new(),
                    url => format!("https://web.archive.org/web/{url}"),
                },
            ),
        );
    // The three decision tables: a verdict per checked line, and a filter.
    for (name, verdict) in [("strict", "gone"), ("lenient", "review")] {
        space = space.bind(
            Exact::new(format!("urn:cms:policy:{name}")),
            stub(
                "policy",
                &log,
                reads("policy").input(input("in")),
                true,
                move |inv| {
                    let line = arg(inv, "in");
                    let url = line.split(' ').next().unwrap_or("").to_string();
                    if line.ends_with(" 404") {
                        format!("{url} {verdict}")
                    } else {
                        format!("{url} keep")
                    }
                },
            ),
        );
    }
    space = space.bind(
        Exact::new("urn:cms:policy:only-gone"),
        stub(
            "only-gone",
            &log,
            reads("only-gone").input(input("in")),
            true,
            |inv| {
                let line = arg(inv, "in");
                match line.strip_suffix(" review").or(line.strip_suffix(" gone")) {
                    Some(url) => url.to_string(),
                    None => String::new(),
                }
            },
        ),
    );
    for name in ["link-remove", "link-replace"] {
        space = space.bind(
            Exact::new(format!("urn:cms:{name}")),
            stub(
                "sink",
                &log,
                Description::new(name)
                    .verb(Verb::Sink)
                    .input(input("content"))
                    .requires("urn:cap:fs:write:*"),
                false,
                |inv| format!("stored {} lines", arg(inv, "content").lines().count()),
            ),
        );
    }
    // The status store: a Sink that keeps what it is given and a Source that reads it back
    // in two faces. ⚠ `in` is declared because the fixture's fork branches are FED the
    // sink's receipt (`@stored | ( … )`), and the runner routes a fed value exactly as the
    // text face does — to the one unnamed by-value input, which must exist. The fixture's
    // comment says the branches ignore it; this stub does.
    let status: Arc<Mutex<String>> = Arc::default();
    let kept = Arc::clone(&status);
    space = space.bind(
        Exact::new("urn:cms:linkstatus"),
        stub(
            "linkstatus",
            &log,
            Description::new("linkstatus")
                .verb(Verb::Sink)
                .verb(Verb::Source)
                .input(input("in").summary("ignored: a fork branch's fed receipt"))
                .input(input("content").optional())
                .input(input("checked").optional())
                .input(input("as").optional()),
            false,
            move |inv| match inv.request.verb {
                Verb::Sink => {
                    *kept.lock().expect("status") =
                        format!("{} checked: {}", arg(inv, "checked"), arg(inv, "content"));
                    "stored".to_string()
                }
                _ => format!("[{}] {}", arg(inv, "as"), kept.lock().expect("status")),
            },
        ),
    );

    let kernel = Kernel::with_meta_renderer(
        Arc::new(ikigai_core::Fallback::new(vec![
            Arc::new(space) as Arc<dyn ikigai_core::Space>,
            Arc::new(ikigai_shacl::space()),
            Arc::new(ikigai_engine::plan_space::space()),
        ])),
        Arc::new(JsonRenderer),
    );
    World {
        kernel: Arc::new(kernel),
        log,
        plan,
    }
}

impl World {
    fn drain(&self) -> Vec<String> {
        std::mem::take(&mut *self.log.lock().expect("log"))
    }

    /// The REPL's `run` over the plan stored at `urn:t:plan`, under `capability`.
    fn run(&self, plan: &str, capability: Capability) -> Result<String, String> {
        *self.plan.lock().expect("plan") = plan.to_string();
        let engine = Engine::with_identity(Arc::clone(&self.kernel), capability);
        output(engine.eval("run urn:t:plan"))
    }

    /// `urn:plan:eval` as a SUB-REQUEST would issue it — what `ikigai-script` does.
    fn eval(
        &self,
        plan: &str,
        args: &[(&str, &str)],
        capability: &Capability,
    ) -> ikigai_core::Result<Representation> {
        self.issue("urn:plan:eval", plan, args, capability)
    }

    fn issue(
        &self,
        target: &str,
        plan: &str,
        args: &[(&str, &str)],
        capability: &Capability,
    ) -> ikigai_core::Result<Representation> {
        let mut request = Request::new(Verb::Source, Iri::parse(target).expect("IRI"))
            .with_arg("in", ArgRef::Inline(plan.as_bytes().to_vec()));
        for (name, value) in args {
            request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
        }
        block_on(self.kernel.issue(request, capability))
    }

    fn text(&self, target: &str, plan: &str, args: &[(&str, &str)]) -> String {
        let answer = self
            .issue(target, plan, args, &Capability::root())
            .unwrap_or_else(|e| panic!("{target}: {e}"));
        String::from_utf8(answer.bytes).expect("text")
    }
}

fn output(action: Action) -> Result<String, String> {
    match action {
        Action::Output(entry) => entry.result,
        _ => Err("expected output".to_string()),
    }
}

// --- one runner, two hosts -----------------------------------------------------------

#[test]
fn every_fixture_runs_the_same_through_eval_as_through_run() {
    for name in FIXTURES {
        let plan = fixture(name);

        let repl = world();
        let by_run = repl
            .run(&plan, Capability::root())
            .unwrap_or_else(|e| panic!("{name} through `run`: {e}"));
        let run_transcript = repl.drain();
        assert!(
            run_transcript.len() > 3,
            "{name}: the run issued {run_transcript:?}, which proves nothing"
        );

        let resource = world();
        let by_eval = resource
            .eval(&plan, &[], &Capability::root())
            .unwrap_or_else(|e| panic!("{name} through urn:plan:eval: {e}"));
        assert_eq!(
            run_transcript,
            resource.drain(),
            "{name}: urn:plan:eval issued different requests than `run`"
        );
        assert_eq!(
            by_run,
            String::from_utf8(by_eval.bytes).expect("text"),
            "{name}: urn:plan:eval answered differently than `run`"
        );
    }
}

#[test]
fn a_plan_piped_from_a_resource_into_eval_runs_like_run() {
    // The text face can reach the resource too: `in` is the sole required input, so a
    // piped plan lands there — the engine's pipeline rule, held by the description.
    let plan = fixture("plan-linkcheck-strict");
    let repl = world();
    let by_run = repl.run(&plan, Capability::root()).expect("run");
    let run_transcript = repl.drain();

    let piped = world();
    *piped.plan.lock().expect("plan") = plan;
    let engine = Engine::new(Arc::clone(&piped.kernel));
    let by_pipe = output(engine.eval("source urn:t:plan | urn:plan:eval")).expect("pipe");
    assert_eq!(by_run, by_pipe);
    assert_eq!(run_transcript, piped.drain());
}

#[test]
fn the_strict_plan_answers_with_its_sink_receipt() {
    // What the runner actually did, spelled out once, so the equivalence test above is not
    // two runs agreeing on nothing.
    let w = world();
    let answer = w.text("urn:plan:eval", &fixture("plan-linkcheck-strict"), &[]);
    assert_eq!(answer, "stored 3 lines");
    let transcript = w.drain();
    assert_eq!(
        transcript.first().map(String::as_str),
        Some("Source urn:cms:bookmarks [as=text/uri-list root=urn:cms:graph]"),
        "the `root` parameter took its default: {transcript:#?}"
    );
    assert!(
        transcript
            .contains(&"Source urn:http:reachable [ttl=604800 url=https://b.example/]".to_string()),
        "{transcript:#?}"
    );
    assert_eq!(
        transcript.last().map(String::as_str),
        Some(
            "Sink urn:cms:link-remove [content=https://a.example/ keep\nhttps://b.example/ \
             gone\nhttps://c.example/ keep]"
        ),
        "{transcript:#?}"
    );
}

#[test]
fn parameters_are_arguments_by_name_and_strangers_are_refused() {
    let w = world();
    let plan = fixture("plan-linkcheck-scoped");
    w.eval(&plan, &[("ttl", "5")], &Capability::root())
        .expect("ttl supplied");
    let transcript = w.drain();
    assert!(
        transcript
            .iter()
            .any(|line| line.starts_with("Source urn:http:reachable [ttl=5 ")),
        "the supplied ttl replaced the default 86400: {transcript:#?}"
    );
    match w.eval(&plan, &[("bogus", "1")], &Capability::root()) {
        Err(Error::InvalidArgument { name, detail }) => {
            assert_eq!(name, "bogus");
            assert!(detail.contains("declares no parameter"), "{detail}");
        }
        other => panic!("expected InvalidArgument(bogus), got {other:?}"),
    }
}

#[test]
fn a_pure_plan_is_cached_and_a_writing_one_is_not() {
    // Every step is a recorded sub-request, so the answer is exactly as cacheable as its
    // least cacheable step: four cacheable reads cache; a Sink's volatile receipt does not.
    let pure = r#"
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:pure> a ik:Process ;
    ik:step <urn:plan:pure:step:1> , <urn:plan:pure:step:2> ;
    ik:result <urn:plan:pure:step:2> .
<urn:plan:pure:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:cms:bookmarks> .
<urn:plan:pure:step:2> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:text:wc> ;
    ik:pipeFrom <urn:plan:pure:step:1> .
"#;
    let w = world();
    assert_eq!(w.text("urn:plan:eval", pure, &[]), "3");
    assert_eq!(w.drain().len(), 2, "first evaluation runs both steps");
    assert_eq!(w.text("urn:plan:eval", pure, &[]), "3");
    assert!(w.drain().is_empty(), "a pure plan is served from the cache");

    let writes = fixture("plan-linkcheck-strict");
    w.eval(&writes, &[], &Capability::root()).expect("first");
    w.drain();
    w.eval(&writes, &[], &Capability::root()).expect("second");
    assert!(
        w.drain().iter().any(|line| line.starts_with("Sink ")),
        "a plan that writes runs again"
    );
}

#[test]
fn as_names_the_face_and_an_unreachable_one_is_refused() {
    let w = world();
    let plan = fixture("plan-linkcheck-strict");
    let same = w
        .eval(&plan, &[("as", "text/plain")], &Capability::root())
        .expect("text/plain is what it served");
    assert_eq!(same.repr_type.media_type, "text/plain");
    match w.eval(
        &plan,
        &[("as", "application/x-nothing")],
        &Capability::root(),
    ) {
        Err(Error::InvalidArgument { name, .. }) => assert_eq!(name, "as"),
        other => panic!("expected InvalidArgument(as), got {other:?}"),
    }
}

// --- validation ----------------------------------------------------------------------

/// A step fed two ways — the shapes catch this one.
const TWO_FEEDS: &str = r#"
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:two> a ik:Process ;
    ik:step <urn:plan:two:step:1> , <urn:plan:two:step:2> ;
    ik:result <urn:plan:two:step:2> .
<urn:plan:two:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:cms:bookmarks> .
<urn:plan:two:step:2> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:text:wc> ;
    ik:pipeFrom <urn:plan:two:step:1> ; ik:mapOver <urn:plan:two:step:1> .
"#;

/// A cycle closed only through names — the hop the shapes cannot take.
const REF_CYCLE: &str = r#"
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:loop> a ik:Process ;
    ik:step <urn:plan:loop:step:1> , <urn:plan:loop:step:2> ;
    ik:result <urn:plan:loop:step:2> .
<urn:plan:loop:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:text:wc> ;
    ik:binds "a" ; ik:argument <urn:plan:loop:step:1:arg:in> .
<urn:plan:loop:step:1:arg:in> a ik:Argument ; ik:inputName "in" ; ik:ref <urn:plan:loop:var:b> .
<urn:plan:loop:step:2> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:text:wc> ;
    ik:binds "b" ; ik:argument <urn:plan:loop:step:2:arg:in> .
<urn:plan:loop:step:2:arg:in> a ik:Argument ; ik:inputName "in" ; ik:ref <urn:plan:loop:var:a> .
"#;

#[test]
fn every_fixture_validates() {
    let w = world();
    for name in FIXTURES {
        let report = w.text("urn:plan:validate", &fixture(name), &[]);
        assert!(report.contains(" conforms:"), "{name}: {report}");
    }
}

#[test]
fn two_feeds_are_refused_by_the_shapes_before_anything_runs() {
    let w = world();
    match w.eval(TWO_FEEDS, &[], &Capability::root()) {
        Err(Error::InvalidArgument { name, detail }) => {
            assert_eq!(name, "in");
            assert!(
                detail.contains("urn:ikigai:shape:"),
                "names the shape: {detail}"
            );
        }
        other => panic!("expected InvalidArgument(in), got {other:?}"),
    }
    assert!(w.drain().is_empty(), "a refused plan runs nothing");
    let report = w.text("urn:plan:validate", TWO_FEEDS, &[]);
    assert!(report.contains("does not conform"), "{report}");
}

#[test]
fn a_cycle_through_a_reference_is_refused_though_the_shapes_pass_it() {
    let w = world();
    let report = w.text("urn:plan:validate", REF_CYCLE, &[]);
    assert!(report.contains("urn:ikigai:plan:check:acyclic"), "{report}");
    // The shapes alone pass it — which is exactly why the reader's check is there.
    let outcome = ikigai_shacl::validate_outcome(REF_CYCLE, ikigai_vocab::SHAPES).expect("shacl");
    assert!(
        outcome.conforms,
        "the shapes cannot see a cycle through a name"
    );

    let graph = w.text("urn:plan:validate", REF_CYCLE, &[("as", "text/turtle")]);
    assert!(graph.contains("urn:ikigai:plan:check:acyclic"), "{graph}");
    assert!(
        oxttl::TurtleParser::new()
            .for_slice(graph.as_bytes())
            .all(|triple| triple.is_ok()),
        "the report face is a graph: {graph}"
    );
    assert!(graph.contains("false"), "sh:conforms is corrected: {graph}");

    match w.eval(REF_CYCLE, &[], &Capability::root()) {
        Err(Error::InvalidArgument { name, detail }) => {
            assert_eq!(name, "in");
            assert!(detail.contains("urn:ikigai:plan:check:acyclic"), "{detail}");
        }
        other => panic!("expected InvalidArgument(in), got {other:?}"),
    }
    assert!(w.drain().is_empty(), "a refused plan runs nothing");
}

#[test]
fn not_turtle_is_a_bad_argument() {
    let w = world();
    match w.eval("this is not < turtle", &[], &Capability::root()) {
        Err(Error::InvalidArgument { name, detail }) => {
            assert_eq!(name, "in");
            assert!(detail.contains("not valid Turtle"), "{detail}");
        }
        other => panic!("expected InvalidArgument(in), got {other:?}"),
    }
}

// --- derived authority -----------------------------------------------------------------

#[test]
fn requires_is_derived_from_the_steps_not_read_from_the_plan() {
    let w = world();
    // The strict fixture CLAIMS `urn:cap:net:*` and `urn:cap:fs:write:*`; the derivation
    // agrees, from the stubs' contracts alone.
    let report = w.text("urn:plan:requires", &fixture("plan-linkcheck-strict"), &[]);
    assert!(
        report.starts_with(
            "<urn:plan:linkcheck-strict> requires urn:cap:fs:write:*, urn:cap:net:*\n"
        ),
        "{report}"
    );
    assert!(
        report.contains("this capability holds all of it"),
        "{report}"
    );

    let graph = w.text(
        "urn:plan:requires",
        &fixture("plan-linkcheck-strict"),
        &[("as", "text/turtle")],
    );
    assert!(
        graph.contains("ik:requires <urn:cap:fs:write:*> , <urn:cap:net:*>"),
        "{graph}"
    );
    assert!(
        graph.contains("<urn:ikigai:plan:requires:outcome:complete>"),
        "{graph}"
    );
    // The scoped fixture writes nothing but its status Sink, which declares nothing.
    let scoped = w.text("urn:plan:requires", &fixture("plan-linkcheck-scoped"), &[]);
    assert!(
        scoped.starts_with("<urn:plan:linkcheck-scoped> requires urn:cap:net:*\n"),
        "{scoped}"
    );
    assert!(
        w.drain().is_empty(),
        "deriving a requirement invokes nothing"
    );
}

#[test]
fn a_target_that_resolves_nowhere_is_reported_not_guessed() {
    let plan = r#"
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:gap> a ik:Process ;
    ik:step <urn:plan:gap:step:1> , <urn:plan:gap:step:2> ;
    ik:result <urn:plan:gap:step:2> .
<urn:plan:gap:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:cms:bookmarks> .
<urn:plan:gap:step:2> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:t:nowhere> ;
    ik:pipeFrom <urn:plan:gap:step:1> .
"#;
    let w = world();
    let report = w.text("urn:plan:requires", plan, &[]);
    assert!(report.contains("AT LEAST nothing — incomplete"), "{report}");
    assert!(report.contains("UNRESOLVED <urn:t:nowhere>"), "{report}");
    let graph = w.text("urn:plan:requires", plan, &[("as", "text/turtle")]);
    assert!(graph.contains("outcome:incomplete"), "{graph}");
    assert!(graph.contains("outcome:unresolved"), "{graph}");
    assert!(
        !graph.contains("<urn:plan:gap> a ik:Process ;\n    ik:outcome <urn:ikigai:plan:requires:outcome:incomplete> ;\n    ik:requires"),
        "no union is claimed for an incomplete plan: {graph}"
    );
}

/// The step `urn:plan:requires` says a capability lacks, read from its text face.
fn first_lacking_step(report: &str) -> String {
    report
        .lines()
        .find(|line| line.contains("LACKS"))
        .unwrap_or_else(|| panic!("no step lacks anything: {report}"))
        .split_whitespace()
        .nth(2)
        .expect("the step's target")
        .to_string()
}

#[test]
fn a_narrower_capability_is_refused_exactly_where_requires_said() {
    let plan = fixture("plan-linkcheck-strict");
    for (capability, expected) in [
        // No grants at all: the reachability check is the first step that needs one.
        (
            Capability::scoped(Vec::<String>::new()),
            "urn:http:reachable",
        ),
        // Some net grant, no write: everything runs up to the removal Sink.
        (
            Capability::scoped(["urn:cap:net:example.org"]),
            "urn:cms:link-remove",
        ),
    ] {
        let w = world();
        let asked = w
            .issue("urn:plan:requires", &plan, &[], &capability)
            .expect("requires answers under any capability");
        let report = String::from_utf8(asked.bytes).expect("text");
        assert_eq!(
            first_lacking_step(&report),
            format!("<{expected}>"),
            "{report}"
        );

        let refused = w.eval(&plan, &[], &capability).expect_err("refused");
        assert!(
            matches!(refused, Error::Denied(_)),
            "a step's typed denial reaches the caller typed: {refused:?}"
        );
        let transcript = w.drain();
        assert!(
            !transcript.iter().any(|line| line.contains(expected)),
            "the refused step was never entered: {transcript:#?}"
        );

        // The REPL's `run` is refused at the same step: one runner.
        let repl = world();
        let err = repl
            .run(&plan, capability.clone())
            .expect_err("run refused too");
        assert!(err.contains(expected) || err.contains("urn:cap:"), "{err}");
        assert_eq!(transcript, repl.drain(), "both stop at the same step");
    }
}
