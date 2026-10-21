//! A tuple whose Turtle nests RDF 1.2 triple terms past the bound is refused when it is
//! dropped, and one already on disk is never parsed by a match, so it cannot abort ANOTHER
//! caller's `rd match=` or `take match=` (ledger #992).
//!
//! The claim: a `match=` parses every pending tuple as Turtle, and in a build with RDF 1.2 on
//! (`oxrdf/rdf-12`, which the host gets by feature unification through rudof, and this
//! crate's tests get from their own dev-dependency) oxttl builds a nested triple term, and
//! oxrdf copies and drops it, RECURSIVELY, once per level. A stack overflow is not an error a
//! caller gets back: Rust aborts the whole process. `out` stored any bytes, so one caller
//! holding only `urn:cap:space:out` could plant a tuple that took down the host on the next
//! match anyone made, on a stack sized for the TEMPLATE, which says nothing about the tuples.
//!
//! Every reproduction runs in a CHILD PROCESS (this test binary re-executed with one probe
//! named in its environment) on a 2 MiB thread, the size of a tokio worker's. The parent
//! asserts on the child's exit: an abort kills the child, never this binary, and reads as a
//! failure with the signal named. (The harness `match_stack.rs` uses.)

mod common;

use common::{drop_tuple, iri, scratch};
use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Kernel, Request, Verb};
use ikigai_intray::{space, tuple_id, CAP_OUT, CAP_READ, CAP_TAKE};
use std::process::Command;
use std::sync::Arc;

const PROBE: &str = "IKIGAI_INTRAY_TUPLE_NESTING_PROBE";
/// `ikigai_rdf::MAX_TURTLE_NESTING`, restated so a change upstream is noticed here.
const BOUND: usize = 64;
/// The tuple every probe drops beside the planted one, and the only one that can match.
const SHALLOW: &[u8] = b"<urn:a> <urn:b> \"c\" .";

/// A one-triple Turtle document whose object nests `n` triple terms.
fn nested(n: usize) -> Vec<u8> {
    format!(
        "<urn:s> <urn:p> {}<urn:o>{} .\n",
        "<<( <urn:s> <urn:p> ".repeat(n),
        " )>>".repeat(n)
    )
    .into_bytes()
}

/// A space holding the shallow tuple, dropped through `out`, and a tuple nesting `n` deep
/// PLANTED on disk beside it: written as a tuple from before this bound, or by anything
/// else that writes the tree, would be. The id is the content's hash, as `out` names it.
fn planted(sub: &str, n: usize) -> Kernel {
    let root = scratch(sub);
    let k = Kernel::new(Arc::new(space(root.clone())));
    drop_tuple(&k, &Capability::scoped([CAP_OUT]), "urn:space:q", SHALLOW).expect("drop");
    let deep = nested(n);
    std::fs::write(
        root.join("q")
            .join("inbox")
            .join(format!("{}.tuple", tuple_id(&deep))),
        &deep,
    )
    .expect("plant");
    k
}

/// One `match=` request that every RDF tuple satisfies, at `door` (`rd` or `take`), on a
/// space holding the shallow tuple and a planted one nesting `n` deep.
fn issue(door: &str, n: usize) -> Result<String, ikigai_core::Error> {
    let k = planted(&format!("nesting-{door}-{n}"), n);
    let (verb, cap) = match door {
        "rd" => (Verb::Source, CAP_READ),
        "take" => (Verb::Delete, CAP_TAKE),
        other => panic!("unknown door {other}"),
    };
    block_on(
        k.issue(
            Request::new(verb, iri("urn:space:q"))
                .with_arg("match", ArgRef::Inline(b"ASK { ?s ?p ?o }".to_vec())),
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
    let (door, n) = spec.split_once(':').expect("door:n");
    let (door, n) = (door.to_string(), n.parse::<usize>().expect("n"));
    let outcome = std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || match issue(&door, n) {
            Ok(text) => format!("ok {}", text.trim().replace('\n', " ")),
            Err(e) => format!("err {}", e.to_string().replace('\n', " ")),
        })
        .expect("spawn")
        .join()
        .expect("join");
    println!("\nOUTCOME {outcome}");
    std::process::exit(0);
}

/// The parent's half: run one probe in a child and return what it said, or fail naming how
/// it died (an abort is the defect).
fn probe(door: &str, n: usize) -> String {
    let out = Command::new(std::env::current_exe().expect("exe"))
        .args(["--exact", "probe_child", "--nocapture", "--test-threads=1"])
        .env(PROBE, format!("{door}:{n}"))
        .output()
        .expect("child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "a `{door}` match over a tuple planted {n} deep did not survive a 2 MiB thread: {} - {}",
        out.status,
        stderr
            .lines()
            .find(|l| l.contains("overflow"))
            .unwrap_or(&stderr)
    );
    let at = stdout
        .find("\nOUTCOME ")
        .unwrap_or_else(|| panic!("the `{door}` probe at {n} reported nothing: {stdout}"));
    stdout[at + "\nOUTCOME ".len()..]
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

#[test]
fn a_planted_deep_tuple_aborts_no_match_and_never_matches() {
    // Deep enough to overflow the stack the match runs on (sized for the template, 16 MiB
    // and up), and well inside anything a size bound would refuse: about 1 MB of Turtle.
    let n = 50_000;
    // rd lists exactly the shallow tuple: the planted one is not RDF a match reads, like a
    // tuple that is not RDF at all, and the caller's match goes on over the rest.
    assert_eq!(probe("rd", n), format!("ok {}", tuple_id(SHALLOW)));
    // take claims the shallow one, never the planted one.
    assert_eq!(
        probe("take", n),
        format!("ok {}", String::from_utf8_lossy(SHALLOW))
    );
}

#[test]
fn out_refuses_a_tuple_nested_past_the_bound_and_keeps_one_at_it() {
    let k = Kernel::new(Arc::new(space(scratch("nesting-out"))));
    let out = Capability::scoped([CAP_OUT]);
    let refused = drop_tuple(&k, &out, "urn:space:q", &nested(BOUND + 1))
        .expect_err("one past the bound")
        .to_string();
    assert!(
        refused.starts_with("invalid argument `content`")
            && refused.contains(&format!("deeper than {BOUND}"))
            && refused.contains("MAX_RDF_NESTING"),
        "{refused}"
    );
    let kept = drop_tuple(&k, &out, "urn:space:q", &nested(BOUND)).expect("at the bound");
    assert_eq!(kept, tuple_id(&nested(BOUND)));
    // ... and a tuple at the bound is still RDF a match reads.
    let listed = block_on(
        k.issue(
            Request::new(Verb::Source, iri("urn:space:q"))
                .with_arg("match", ArgRef::Inline(b"ASK { ?s ?p ?o }".to_vec())),
            &Capability::scoped([CAP_READ]),
        ),
    )
    .expect("match");
    assert_eq!(String::from_utf8_lossy(&listed.bytes).trim(), kept);
}

#[test]
fn binary_tuples_keep_their_bytes_and_cannot_hide_deep_nesting() {
    let k = Kernel::new(Arc::new(space(scratch("nesting-binary"))));
    let out = Capability::scoped([CAP_OUT]);
    let bytes = b"\xff\0binary tuple";
    let id = drop_tuple(&k, &out, "urn:space:q", bytes).expect("binary tuple");
    let read = block_on(
        k.issue(
            Request::new(Verb::Source, iri("urn:space:q"))
                .with_arg("tuple", ArgRef::Inline(id.into_bytes())),
            &Capability::scoped([CAP_READ]),
        ),
    )
    .expect("read binary tuple");
    assert_eq!(read.bytes, bytes);

    // Invalid UTF-8 before the Turtle delimiters must not bypass the nesting scan.
    let mut deep = vec![0xff];
    deep.extend(nested(BOUND + 1));
    let refused = drop_tuple(&k, &out, "urn:space:q", &deep)
        .expect_err("deep binary tuple")
        .to_string();
    assert!(refused.starts_with("invalid argument `content`"));
    assert!(refused.contains("MAX_RDF_NESTING"));
}
