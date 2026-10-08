//! Ledger #887 item 4: `retry=` re-arms a dead letter, and it needed only `urn:cap:space:out`
//! — the authority a stranger drops under (the public HTTP door grants exactly that). So anyone
//! who could drop could also undo a dead letter the reactor parked ON PURPOSE: a tuple the
//! `Interrupted::DeadLetter` policy refused to run twice (a booking whose mail may already have
//! gone), or one the host refused for a retargeted handler. Re-arming is the operator's call.

mod common;

use common::{drop_tuple, iri, scratch, Counting};
use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Error, Kernel, Request, Verb};
use ikigai_intray::{
    space, Interrupted, Recovered, SpaceReactor, CAP_OUT, CAP_READ, CAP_RETRY, CAP_TAKE,
    PROCESSING_DIR,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A space holding one tuple that a stopped reactor left mid-pass, which the default policy
/// dead-letters rather than runs again. Returns the root, the kernel and the tuple id.
fn parked(tag: &str) -> (PathBuf, Kernel, String) {
    let root = scratch(tag);
    std::fs::create_dir_all(root.join("jobs")).unwrap();
    std::fs::write(root.join("jobs/handler"), "urn:test:handler").unwrap();
    let k = Kernel::new(Arc::new(space(root.clone())));
    let id = drop_tuple(
        &k,
        &Capability::scoped([CAP_OUT]),
        "urn:space:jobs",
        b"send the mail",
    )
    .unwrap();
    // The claim a crashed reactor left behind.
    let processing = root.join("jobs").join(PROCESSING_DIR);
    std::fs::create_dir_all(&processing).unwrap();
    std::fs::rename(
        root.join("jobs/inbox").join(format!("{id}.tuple")),
        processing.join(format!("{id}.tuple")),
    )
    .unwrap();
    let handler = Arc::new(Counting::new());
    let reactor = SpaceReactor::new(root.clone(), handler.clone(), Capability::root());
    let recovered = reactor.recover_interrupted().expect("the only reactor");
    assert_eq!(
        recovered,
        [Recovered {
            space: "jobs".to_string(),
            tuple: id.clone(),
            outcome: Ok(Interrupted::DeadLetter),
        }]
    );
    assert_eq!(handler.calls(), 0, "parked, not run");
    (root, k, id)
}

fn retry(k: &Kernel, cap: &Capability, id: &str) -> Result<(), Error> {
    block_on(
        k.issue(
            Request::new(Verb::Sink, iri("urn:space:jobs"))
                .with_arg("retry", ArgRef::Inline(id.as_bytes().to_vec())),
            cap,
        ),
    )
    .map(|_| ())
}

fn in_error(root: &Path, id: &str) -> bool {
    root.join("jobs/error")
        .join(format!("{id}.tuple"))
        .is_file()
}

/// ★ The reproduction: a holder of `out` alone (a stranger at the public door) re-armed a
/// parked dead letter. On 0.1.41 this `retry` succeeded and the tuple went back to the inbox,
/// where the next pass would run it a second time.
#[test]
fn dropping_authority_cannot_re_arm_a_parked_dead_letter() {
    let (root, k, id) = parked("retry-out-only");
    for cap in [
        Capability::scoped([CAP_OUT]),
        // Neither read nor take is the operator's decision either.
        Capability::scoped([CAP_OUT, CAP_READ, CAP_TAKE]),
    ] {
        match retry(&k, &cap, &id) {
            Err(Error::Denied(why)) => assert!(why.contains(CAP_RETRY), "{why}"),
            other => panic!("`retry=` under {cap:?} must be denied, got {other:?}"),
        }
        assert!(in_error(&root, &id), "the dead letter stays parked");
        assert!(
            root.join("jobs/error").join(format!("{id}.err")).is_file(),
            "its note stays too"
        );
    }
}

/// The operator's authority re-arms it, as before.
#[test]
fn the_retry_grant_re_arms_it() {
    let (root, k, id) = parked("retry-granted");
    retry(&k, &Capability::scoped([CAP_OUT, CAP_RETRY]), &id).expect("granted");
    assert!(!in_error(&root, &id));
    assert!(root
        .join("jobs/inbox")
        .join(format!("{id}.tuple"))
        .is_file());
}

/// `retry` is still refused BEFORE it looks at the tree, so a denied caller learns nothing
/// about which ids are dead letters (NotFound vs Denied would tell it).
#[test]
fn a_denied_retry_does_not_reveal_whether_the_id_exists() {
    let (_root, k, _id) = parked("retry-oracle");
    match retry(&k, &Capability::scoped([CAP_OUT]), "deadbeef") {
        Err(Error::Denied(_)) => {}
        other => panic!("denied before the lookup, got {other:?}"),
    }
}

/// The contract says so: the `retry` input names the scope it needs (the verb's own
/// `requires` cannot, since a plain drop must not need it).
#[test]
fn the_contract_names_the_retry_scope() {
    let described = format!(
        "{:?}",
        ikigai_core::Endpoint::describe(&ikigai_intray::SpaceEndpoint::new(scratch(
            "retry-describe"
        )))
    );
    assert!(described.contains(CAP_RETRY), "{described}");
}
