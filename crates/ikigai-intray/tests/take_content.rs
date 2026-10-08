//! Audit round 5, root cause 5 (ledger #877): `delete urn:space:q <id>` puts the id in
//! `content`, which take neither declared nor read, so it popped the FIRST tuple instead of the
//! one named. These drive the REAL engine, so the request is exactly the one a person's
//! `delete` line builds; the kernel carries a JSON Meta renderer because without one the engine
//! cannot route named arguments and fails open.

mod common;

use common::{drop_tuple, iri, scratch};
use futures::executor::block_on;
use ikigai_core::{
    ArgRef, Capability, Description, Error, Kernel, MetaRenderer, ReprType, Representation,
    Request, Verb,
};
use ikigai_engine::{Action, Engine};
use ikigai_intray::{space, CAP_OUT, CAP_READ, CAP_TAKE};
use std::path::Path;
use std::sync::Arc;

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

fn kernel(root: &Path) -> Kernel {
    Kernel::with_meta_renderer(Arc::new(space(root.to_path_buf())), Arc::new(JsonRenderer))
}

fn all() -> Capability {
    Capability::scoped([CAP_OUT, CAP_READ, CAP_TAKE])
}

fn eval(engine: &Engine, line: &str) -> Result<String, String> {
    match engine.eval(line) {
        Action::Output(entry) => entry.result,
        _ => panic!("expected output for `{line}`"),
    }
}

fn inbox(k: &Kernel) -> Vec<String> {
    let r = block_on(k.issue(Request::new(Verb::Source, iri("urn:space:q")), &all())).unwrap();
    String::from_utf8(r.bytes)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

/// Two tuples, returned as (the one that sorts LAST, the other): a work-queue pop takes the
/// first in id order, so naming the last one tells a named take from a pop.
fn two_tuples(k: &Kernel) -> (String, String, Vec<u8>) {
    let a = drop_tuple(k, &all(), "urn:space:q", b"tuple one").unwrap();
    let b = drop_tuple(k, &all(), "urn:space:q", b"tuple two").unwrap();
    if a > b {
        (a, b, b"tuple one".to_vec())
    } else {
        (b, a, b"tuple two".to_vec())
    }
}

#[test]
fn delete_with_a_trailing_id_takes_that_tuple() {
    let root = scratch("take-trailing");
    let k = kernel(&root);
    let (named, other, bytes) = two_tuples(&k);
    let engine = Engine::new(kernel(&root));
    let taken = eval(&engine, &format!("delete urn:space:q {named}")).unwrap();
    assert_eq!(
        taken.as_bytes(),
        bytes,
        "the named tuple's content comes back"
    );
    assert_eq!(
        inbox(&k),
        vec![other],
        "asked for {named}; the other one is left"
    );
}

#[test]
fn delete_with_a_named_tuple_still_takes_that_tuple() {
    let root = scratch("take-named");
    let k = kernel(&root);
    let (named, other, _) = two_tuples(&k);
    let engine = Engine::new(kernel(&root));
    eval(&engine, &format!("delete urn:space:q tuple={named}")).unwrap();
    assert_eq!(inbox(&k), vec![other]);
}

/// The engine sends `content` (empty) on EVERY delete, so an empty one must still be the
/// no-selector work-queue pop, not a refusal and not a take of a tuple named "".
#[test]
fn a_bare_delete_is_still_a_work_queue_pop() {
    let root = scratch("take-bare");
    let k = kernel(&root);
    let (named, other, _) = two_tuples(&k);
    let engine = Engine::new(kernel(&root));
    eval(&engine, "delete urn:space:q").unwrap();
    assert_eq!(
        inbox(&k),
        vec![named],
        "the first in id order ({other}) was popped"
    );
}

#[test]
fn a_piped_id_with_its_trailing_newline_takes_that_tuple() {
    let root = scratch("take-newline");
    let k = kernel(&root);
    let (named, other, _) = two_tuples(&k);
    block_on(
        k.issue(
            Request::new(Verb::Delete, iri("urn:space:q"))
                .with_arg("content", ArgRef::Inline(format!("{named}\n").into_bytes())),
            &all(),
        ),
    )
    .unwrap();
    assert_eq!(inbox(&k), vec![other]);
}

#[test]
fn tuple_and_content_naming_different_tuples_is_refused() {
    let root = scratch("take-conflict");
    let k = kernel(&root);
    let (named, other, _) = two_tuples(&k);
    let r = block_on(
        k.issue(
            Request::new(Verb::Delete, iri("urn:space:q"))
                .with_arg("tuple", ArgRef::Inline(named.clone().into_bytes()))
                .with_arg("content", ArgRef::Inline(other.clone().into_bytes())),
            &all(),
        ),
    );
    assert!(
        matches!(r, Err(Error::InvalidArgument { ref name, .. }) if name == "content"),
        "got {r:?}"
    );
    assert_eq!(inbox(&k).len(), 2, "nothing was taken");
}

/// A selector that is present but not UTF-8 is refused, never read as absent: on take,
/// "absent" is the pop, so a caller naming one tuple consumed another.
#[test]
fn a_non_utf8_selector_is_refused_not_ignored() {
    let root = scratch("take-utf8");
    let k = kernel(&root);
    two_tuples(&k);
    for (verb, arg) in [
        (Verb::Delete, "tuple"),
        (Verb::Delete, "content"),
        (Verb::Delete, "match"),
        (Verb::Source, "tuple"),
        (Verb::Source, "state"),
        (Verb::Source, "match"),
        (Verb::Sink, "retry"),
    ] {
        let r = block_on(k.issue(
            Request::new(verb, iri("urn:space:q")).with_arg(arg, ArgRef::Inline(vec![0xff, 0xfe])),
            &all(),
        ));
        assert!(
            matches!(r, Err(Error::InvalidArgument { ref name, .. }) if name == arg),
            "{verb:?} {arg}=<not utf-8> was not refused: {r:?}"
        );
    }
    assert_eq!(inbox(&k).len(), 2, "nothing was taken");
}

/// Pipeline citizenship: a mutating verb that can receive a pipe declares `content`.
#[test]
fn take_declares_content() {
    let d = ikigai_core::Endpoint::describe(&ikigai_intray::SpaceEndpoint::new(scratch("d")));
    let take = d
        .action_specs()
        .into_iter()
        .find(|a| a.verb == Verb::Delete)
        .expect("a Delete action");
    assert!(
        take.inputs.iter().any(|i| i.name == "content"),
        "Delete does not declare `content`: {:?}",
        take.inputs.iter().map(|i| &i.name).collect::<Vec<_>>()
    );
}
