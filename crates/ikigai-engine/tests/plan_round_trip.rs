//! The round trip that IS the bar for the plan face.
//!
//! Reader-only: without `plan-reader` this build renders plans but cannot read one back,
//! so there is no round trip to make. `cargo test --all-features` (what the gates and CI
//! run) has it on.
#![cfg(feature = "plan-reader")]

//!
//! For each shape the REPL grammar can make: run the spec, render it as an `ik:Process`
//! graph, read that graph back, run it — and require **the same execution**, witnessed as
//! the exact sequence of requests every endpoint received. Not the same AST: a plan is the
//! *resolved* form, so `source urn:x hello` becomes a named argument the contract chose,
//! and the two ASTs differ while the two runs do not. The requests are what the world sees.
//!
//! Every rendered graph is also validated against `ikigai_vocab::SHAPES`, so a renderer
//! that emits a shape-invalid plan fails the build rather than the reader.

use std::sync::{Arc, Mutex};

use ikigai_core::{
    ArgSpec, Description, EndpointSpace, Exact, FnEndpoint, Invocation, Kernel, MetaRenderer,
    ReprType, Representation, Verb,
};
use ikigai_engine::{Action, Engine};

/// What an endpoint saw: the verb, the target, and every argument by name. Argument order
/// is not part of a request's identity, so the transcript sorts — two runs that differ
/// only in the order arguments were attached ARE the same execution.
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

type Log = Arc<Mutex<Vec<String>>>;

/// A stage that records what it was asked and answers deterministically, so a transcript
/// is reproducible and a downstream stage has something to chew on.
fn stage(tag: &'static str, log: &Log, description: Description) -> FnEndpoint {
    let log = Arc::clone(log);
    FnEndpoint::new(tag, move |inv: &Invocation<'_>| {
        log.lock().expect("log").push(entry(inv));
        let input = inv
            .inline_str("in")
            .or_else(|_| inv.inline_str("content"))
            .unwrap_or("");
        Ok(Representation::new(
            ReprType::new("text/plain"),
            match tag {
                // A list, so `..` has items to map over.
                "list" => format!("{input}/1\n{input}/2"),
                other => format!("{other}({input})"),
            }
            .into_bytes(),
        ))
    })
    .with_description(description)
}

fn reads(name: &str) -> Description {
    Description::new(name).input(ArgSpec::new("in").summary("the value to transform"))
}

fn fixture() -> (Engine, Log, Arc<Mutex<String>>) {
    let log: Log = Arc::default();
    let stored: Arc<Mutex<String>> = Arc::default();

    // The stored plan, resolved through the kernel like any resource — this is what
    // `run <spec>` reads. It does NOT record, so the transcript holds only plan steps.
    let plan_resource = {
        let stored = Arc::clone(&stored);
        FnEndpoint::new("plan-store", move |_: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/turtle"),
                stored.lock().expect("stored").clone().into_bytes(),
            ))
        })
        .with_description(Description::new("plan-store"))
    };

    let mut space = EndpointSpace::new().bind(Exact::new("urn:t:plan"), plan_resource);
    for tag in ["up", "down", "a", "b", "c", "d"] {
        space = space.bind(
            Exact::new(format!("urn:t:{tag}")),
            stage(tag, &log, reads(tag)),
        );
    }
    space = space.bind(Exact::new("urn:t:list"), stage("list", &log, reads("list")));
    // An IRI carrying `..` inside a word: the tokenizer treats `..` as the map operator
    // only as a WHOLE unquoted word, and this case is why that rule exists.
    space = space.bind(
        Exact::new("urn:t:dots/../x"),
        stage("dots", &log, reads("dots")),
    );
    // A second, OPTIONAL argument beside the required one — the shape where the piped or
    // positional value fills the sole *required* input and the optional one stays unset.
    space = space.bind(
        Exact::new("urn:t:opt"),
        stage(
            "opt",
            &log,
            Description::new("opt")
                // `in` is required (the default) and `flavor` is not, so the value fills
                // `in` and leaves `flavor` unset — the `many =>` routing arm.
                .input(ArgSpec::new("in"))
                .input(ArgSpec::new("flavor").optional()),
        ),
    );
    space = space.bind(
        Exact::new("urn:t:store"),
        stage(
            "store",
            &log,
            Description::new("store")
                .verb(Verb::Sink)
                .input(ArgSpec::new("content").summary("the body")),
        ),
    );

    let engine = Engine::new(Kernel::with_meta_renderer(
        Arc::new(space),
        Arc::new(JsonRenderer),
    ));
    (engine, log, stored)
}

/// The engine fetches an endpoint's contract as `Meta as=application/json`, and when that
/// fails it fails OPEN — routing every value to an input named `in` and making a routing
/// defect invisible. A plan's whole claim is that it resolves that routing, so these tests
/// must run on a kernel that can actually answer.
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

fn output(action: Action) -> Result<String, String> {
    match action {
        Action::Output(entry) => entry.result,
        _ => Err("expected output".to_string()),
    }
}

fn drain(log: &Log) -> Vec<String> {
    std::mem::take(&mut *log.lock().expect("log"))
}

/// Run `spec` directly, then render it, store it, and run the stored graph — and require
/// that the world saw the same thing both times.
fn round_trip(spec: &str) -> String {
    // A fresh engine per phase, so neither run can be served from the other's cache — a
    // cache hit skips the endpoint, and a transcript is only evidence if every step ran.
    let (engine, log, _) = fixture();
    let direct = output(engine.eval(&format!("source {spec}")))
        .unwrap_or_else(|e| panic!("running `{spec}` directly: {e}"));
    let directly_issued = drain(&log);
    assert!(
        !directly_issued.is_empty(),
        "`{spec}` issued nothing, so the transcript proves nothing"
    );

    let (engine, log, stored) = fixture();
    let turtle = output(engine.eval(&format!("plan {spec}")))
        .unwrap_or_else(|e| panic!("rendering `{spec}`: {e}"));
    assert_eq!(
        drain(&log),
        Vec::<String>::new(),
        "rendering a plan must not RUN it — `{spec}` issued steps while being planned"
    );
    conforms(&turtle, spec);

    *stored.lock().expect("stored") = turtle.clone();
    let replayed = output(engine.eval("run urn:t:plan"))
        .unwrap_or_else(|e| panic!("running the stored plan for `{spec}`: {e}\n{turtle}"));

    assert_eq!(
        directly_issued,
        drain(&log),
        "the stored plan for `{spec}` issued different requests than the spec did\n{turtle}"
    );
    assert_eq!(
        direct, replayed,
        "the stored plan for `{spec}` answered differently\n{turtle}"
    );
    turtle
}

/// Every rendered plan satisfies the published shapes. The shapes pin cardinalities, the
/// five verbs, one feed per step, distinct argument names, plan-local edges and the
/// structural half of acyclicity — so a renderer that emits an invalid graph is caught
/// here rather than by whoever tries to read it.
fn conforms(turtle: &str, spec: &str) {
    let outcome = ikigai_shacl::validate_outcome(turtle, ikigai_vocab::SHAPES)
        .unwrap_or_else(|e| panic!("validating the plan for `{spec}`: {e}"));
    assert!(
        outcome.conforms,
        "the plan for `{spec}` does not satisfy ikigai_vocab::SHAPES: {:#?}\n{turtle}",
        outcome.violations
    );
}

#[test]
fn a_pipe_round_trips() {
    let turtle = round_trip("urn:t:up hello | urn:t:down");
    assert!(turtle.contains("ik:pipeFrom"), "{turtle}");
    // The positional value became a NAMED argument, resolved from the contract. That is
    // the whole difference between a plan and a transcription of the words.
    assert!(turtle.contains("ik:inputName \"in\""), "{turtle}");
    assert!(turtle.contains("ik:value \"hello\""), "{turtle}");
}

#[test]
fn a_map_round_trips() {
    let turtle = round_trip("urn:t:list seed .. urn:t:up");
    assert!(turtle.contains("ik:mapOver"), "{turtle}");
}

#[test]
fn a_fork_round_trips() {
    let turtle = round_trip("urn:t:up hi | ( urn:t:a ; urn:t:b )");
    assert!(turtle.contains("a ik:Fork"), "{turtle}");
    assert!(turtle.contains("ik:join \"newline\""), "{turtle}");
    assert!(turtle.contains("ik:order 1"), "{turtle}");
    assert!(turtle.contains("ik:order 2"), "{turtle}");
}

#[test]
fn a_fork_nested_inside_a_branch_round_trips() {
    // The inner fork is the TAIL of the first branch, reached through that branch's head —
    // which is the only nesting the vocabulary can spell (see the refusals below).
    let turtle = round_trip("urn:t:up hi | ( urn:t:a | ( urn:t:b ; urn:t:c ) ; urn:t:d )");
    assert_eq!(turtle.matches("a ik:Fork").count(), 2, "{turtle}");
}

#[test]
fn a_fork_with_no_upstream_round_trips() {
    // A fork as the plan's FIRST stage: no ik:upstream, and its branches take no input.
    let turtle = round_trip("( urn:t:a one ; urn:t:b two )");
    assert!(!turtle.contains("ik:upstream"), "{turtle}");
}

#[test]
fn quoted_operators_round_trip() {
    // The quoted span holds every operator character literally; it must survive being a
    // Turtle literal and coming back, or the plan means something else than the spec.
    round_trip("urn:t:up \"a | b ; c ( ) .. d\"");
}

#[test]
fn an_iri_containing_dot_dot_round_trips() {
    // `..` is the map operator only as a whole unquoted word — this is the case that rule
    // exists for, and the IRI has to survive the graph unchanged.
    let turtle = round_trip("urn:t:dots/../x hello | urn:t:up");
    assert!(turtle.contains("<urn:t:dots/../x>"), "{turtle}");
}

#[test]
fn a_sink_terminal_round_trips() {
    let turtle = round_trip("urn:t:up hi | sink urn:t:store");
    assert!(turtle.contains("ik:verb \"Sink\""), "{turtle}");
    // The piped body is the EDGE, not an argument — the vocabulary is explicit that a
    // piped input arrives through ik:pipeFrom rather than as an ik:Argument.
    assert!(!turtle.contains("ik:inputName \"content\""), "{turtle}");
}

#[test]
fn a_named_argument_beside_an_optional_one_round_trips() {
    // The value fills the sole REQUIRED input; the optional one is named explicitly.
    let turtle = round_trip("urn:t:opt hello flavor=salty | urn:t:up");
    assert!(turtle.contains("ik:value \"salty\""), "{turtle}");
}

#[test]
fn a_conneg_selector_round_trips() {
    // `as` is the universal conneg selector — carried as a request argument rather than
    // endpoint input, so it has to ride in the graph as a plain named argument.
    let turtle = round_trip("urn:t:up hi as=text/plain | urn:t:down");
    assert!(turtle.contains("ik:inputName \"as\""), "{turtle}");
}

// --- what a plan cannot say, said out loud ------------------------------------

/// Two grammar shapes have no spelling in the process vocabulary, both for the same
/// reason: `ik:mapOver`, `ik:forkOf` and `ik:order` are properties of an `ik:Step`, and a
/// fork is not a step. A plan that came back meaning something subtly different would be
/// worse than one that will not come back at all, so both are refused by name.
#[test]
fn a_fork_that_is_a_forks_branch_is_refused_not_degraded() {
    let (engine, _, _) = fixture();
    // It RUNS as text — this is a gap in the graph, not in the grammar.
    assert!(
        output(engine.eval("source urn:t:up hi | ( ( urn:t:a ; urn:t:b ) ; urn:t:c )")).is_ok()
    );
    let err =
        output(engine.eval("plan urn:t:up hi | ( ( urn:t:a ; urn:t:b ) ; urn:t:c )")).unwrap_err();
    assert!(err.contains("ik:forkOf"), "{err}");
}

#[test]
fn a_map_over_a_fork_is_refused_not_degraded() {
    let (engine, _, _) = fixture();
    assert!(output(engine.eval("source urn:t:list seed .. ( urn:t:a ; urn:t:b )")).is_ok());
    let err = output(engine.eval("plan urn:t:list seed .. ( urn:t:a ; urn:t:b )")).unwrap_err();
    assert!(err.contains("ik:mapOver"), "{err}");
}

#[test]
fn a_plan_carrying_named_results_is_refused_rather_than_run_without_them() {
    // Named results (`x = …`, `@x`) are the next arc. Nothing emits ik:binds or ik:ref
    // yet — but a graph that carries them means something this engine cannot honour, and
    // running it with the references dropped would be a different plan that looked fine.
    let (engine, _, stored) = fixture();
    *stored.lock().expect("stored") = r#"
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:named> a ik:Process ;
    ik:step <urn:plan:named:step:1> ;
    ik:result <urn:plan:named:step:1> .
<urn:plan:named:step:1> a ik:Step ;
    ik:verb "Source" ;
    ik:resolves <urn:t:up> ;
    ik:binds "greeting" .
"#
    .to_string();
    let err = output(engine.eval("run urn:t:plan")).unwrap_err();
    assert!(err.contains("ik:binds"), "{err}");
}

#[test]
fn a_graph_that_is_not_a_plan_says_so() {
    let (engine, _, stored) = fixture();
    *stored.lock().expect("stored") = "<urn:a> <urn:b> \"not a plan\" .\n".to_string();
    let err = output(engine.eval("run urn:t:plan")).unwrap_err();
    assert!(err.contains("not a plan"), "{err}");
}

#[test]
fn a_cycle_in_a_stored_plan_is_refused_rather_than_run() {
    let (engine, _, stored) = fixture();
    *stored.lock().expect("stored") = r#"
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:cycle> a ik:Process ;
    ik:step <urn:plan:cycle:step:1> , <urn:plan:cycle:step:2> ;
    ik:result <urn:plan:cycle:step:2> .
<urn:plan:cycle:step:1> a ik:Step ;
    ik:verb "Source" ; ik:resolves <urn:t:up> ; ik:pipeFrom <urn:plan:cycle:step:2> .
<urn:plan:cycle:step:2> a ik:Step ;
    ik:verb "Source" ; ik:resolves <urn:t:down> ; ik:pipeFrom <urn:plan:cycle:step:1> .
"#
    .to_string();
    let err = output(engine.eval("run urn:t:plan")).unwrap_err();
    assert!(err.contains("DAG"), "{err}");
}

/// The shapes catch this one, which is worth pinning: the same graph the executor refuses
/// is a graph a validator refuses, so a pre-flight and the runtime agree.
#[test]
fn the_shapes_refuse_the_cycle_too() {
    let outcome = ikigai_shacl::validate_outcome(
        r#"
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:cycle> a ik:Process ;
    ik:step <urn:plan:cycle:step:1> , <urn:plan:cycle:step:2> ;
    ik:result <urn:plan:cycle:step:2> .
<urn:plan:cycle:step:1> a ik:Step ;
    ik:verb "Source" ; ik:resolves <urn:t:up> ; ik:pipeFrom <urn:plan:cycle:step:2> .
<urn:plan:cycle:step:2> a ik:Step ;
    ik:verb "Source" ; ik:resolves <urn:t:down> ; ik:pipeFrom <urn:plan:cycle:step:1> .
"#,
        ikigai_vocab::SHAPES,
    )
    .expect("validate");
    assert!(!outcome.conforms, "a cycle must not pass the shapes");
}
