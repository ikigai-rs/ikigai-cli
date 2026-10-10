//! A `match=` template that would overflow the stack is refused, or parsed and evaluated on a
//! stack big enough for it — on BOTH doors that take one, rd and take (ledger #963).
//!
//! The claim: `match=` is caller SPARQL, parsed by oxigraph's recursive parser and evaluated
//! by its recursive evaluator, so a template nested or chained far enough aborts the whole
//! host process (a stack overflow is an abort, not a panic, on any thread). gonk wraps this
//! space and `ikigai-embedded` mounts it unwrapped, so the bound belongs here, in the space,
//! where every host that mounts it gets it.
//!
//! Every reproduction runs in a CHILD PROCESS — this test binary re-executed with one probe
//! named in its environment — on a 2 MiB thread, the size of a tokio worker's. The parent
//! asserts on the child's exit: an abort kills the child, never this binary, and reads as a
//! failure with the signal named. (The same harness `ikigai-store`'s `sparql_nesting.rs`
//! uses for its own doors.)

mod common;

use common::{drop_tuple, iri, scratch};
use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Kernel, Request, Verb};
use ikigai_intray::{space, CAP_OUT, CAP_READ, CAP_TAKE};
use std::process::Command;
use std::sync::Arc;

const PROBE: &str = "IKIGAI_INTRAY_MATCH_STACK_PROBE";
/// `ikigai_store::limits::MAX_SPARQL_NESTING`, restated so a change upstream is noticed here.
const BOUND: usize = 64;

/// `ASK { FILTER((…n…1…)) }`: `{` and `FILTER(` are two levels, so this nests `n + 2` deep.
fn parens(n: usize) -> String {
    format!("ASK {{ FILTER({}1{}) }}", "(".repeat(n), ")".repeat(n))
}

/// `ASK { ?s ?p ?o FILTER(1 || 1 || …) }`: flat, so no nesting bound refuses it, and long
/// enough to overflow a 2 MiB thread in a debug build when parsed and evaluated inline.
fn or_chain(n: usize) -> String {
    format!("ASK {{ ?s ?p ?o FILTER({}1) }}", "1 || ".repeat(n))
}

fn template(shape: &str, n: usize) -> String {
    match shape {
        "parens" => parens(n),
        "or-chain" => or_chain(n),
        other => panic!("unknown shape {other}"),
    }
}

/// One `match=` request on a space holding one tuple, so the template is both parsed and
/// evaluated. `door` is `rd` or `take`.
fn issue(door: &str, shape: &str, n: usize) -> Result<String, ikigai_core::Error> {
    let k = Kernel::new(Arc::new(space(scratch(&format!(
        "stack-{door}-{shape}-{n}"
    )))));
    drop_tuple(
        &k,
        &Capability::scoped([CAP_OUT]),
        "urn:space:q",
        b"<urn:a> <urn:b> \"c\" .",
    )
    .expect("dropping the tuple");
    let (verb, cap) = match door {
        "rd" => (Verb::Source, CAP_READ),
        "take" => (Verb::Delete, CAP_TAKE),
        other => panic!("unknown door {other}"),
    };
    block_on(
        k.issue(
            Request::new(verb, iri("urn:space:q"))
                .with_arg("match", ArgRef::Inline(template(shape, n).into_bytes())),
            &Capability::scoped([cap]),
        ),
    )
    .map(|r| String::from_utf8_lossy(&r.bytes).into_owned())
}

/// The child's half: inert unless a parent named a probe. Runs it on a 2 MiB thread, prints
/// the outcome, and exits before the harness can.
#[test]
fn probe_child() {
    let Ok(spec) = std::env::var(PROBE) else {
        return;
    };
    let mut parts = spec.split(':');
    let (door, shape, n) = (
        parts.next().unwrap().to_string(),
        parts.next().unwrap().to_string(),
        parts.next().unwrap().parse::<usize>().unwrap(),
    );
    let outcome = std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || match issue(&door, &shape, n) {
            Ok(text) => format!("ok {}", text.replace('\n', " ")),
            Err(e) => format!("err {}", e.to_string().replace('\n', " ")),
        })
        .unwrap()
        .join()
        .unwrap();
    println!("\nOUTCOME {outcome}");
    std::process::exit(0);
}

/// The parent's half: run one probe in a child and return what it said, or fail naming how
/// it died — an abort is the defect.
fn probe(door: &str, shape: &str, n: usize) -> String {
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "probe_child", "--nocapture", "--test-threads=1"])
        .env(PROBE, format!("{door}:{shape}:{n}"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the `{door}` `{shape}` probe at {n} did not survive a 2 MiB thread: {} — {}",
        out.status,
        stderr
            .lines()
            .find(|l| l.contains("overflow"))
            .unwrap_or(&stderr)
    );
    let at = stdout
        .find("\nOUTCOME ")
        .unwrap_or_else(|| panic!("the `{door}` `{shape}` probe reported nothing: {stdout}"));
    stdout[at + "\nOUTCOME ".len()..]
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

#[test]
fn three_thousand_parentheses_are_refused_at_both_doors_and_abort_nothing() {
    for door in ["rd", "take"] {
        let outcome = probe(door, "parens", 3000);
        assert!(
            outcome.starts_with("err invalid argument `match`")
                && outcome.contains(&format!("deeper than {BOUND}")),
            "{door}: {outcome}"
        );
    }
}

#[test]
fn a_long_flat_chain_is_parsed_and_evaluated_on_the_stack_it_is_given() {
    // Not nesting, so nothing refuses it, and a generated template may really look like
    // this. Inline on a 2 MiB thread it aborts a debug build; here it runs, and matches.
    let outcome = probe("rd", "or-chain", 600);
    assert!(
        outcome.starts_with("ok ") && outcome.len() > "ok ".len(),
        "{outcome}"
    );
    let outcome = probe("take", "or-chain", 600);
    assert!(outcome.starts_with("ok "), "{outcome}");
}

#[test]
fn a_template_at_the_bound_still_matches() {
    // Two levels for `{` and `FILTER(`, the rest brings it to exactly the bound.
    let outcome = issue("rd", "parens", BOUND - 2).unwrap();
    assert!(!outcome.is_empty(), "the tuple matches: {outcome:?}");
    let refused = issue("rd", "parens", BOUND - 1).unwrap_err().to_string();
    assert!(refused.contains("`match`"), "{refused}");
}
