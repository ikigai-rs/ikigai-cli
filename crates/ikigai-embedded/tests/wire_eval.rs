//! Wire-eval L1, proven on the served kernels themselves: the governed
//! `urn:lisp:eval` binding times out a runaway at the wall clock, the kernel's
//! declared-`requires` floor keeps it from a ceiling that doesn't grant
//! `urn:cap:lisp`, and the ungoverned posture simply doesn't bind it.
//! Own process (integration binary): the lisp worker pool is a global.

use std::time::{Duration, Instant};

use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Error, Iri, Request, Verb};

fn eval(src: &str) -> Request {
    Request::new(
        Verb::Source,
        Iri::parse("urn:lisp:eval").expect("valid IRI"),
    )
    .with_arg("in", ArgRef::Inline(src.as_bytes().to_vec()))
}

#[test]
fn the_served_eval_is_governed_clamped_and_absent_without_optin() {
    std::env::set_var("IKIGAI_EVAL_TIMEOUT_SECS", "2");

    // Warm the (global) worker pool through an ungoverned kernel first: a fresh
    // worker builds its Steel template on first use, which on a slow CI runner
    // in a debug build can alone exceed the tight budget below — the governed
    // assertions are about the GOVERNOR, not template build speed.
    let warm = ikigai_core::Kernel::new(std::sync::Arc::new(ikigai_lisp::space()));
    block_on(warm.issue(eval("(+ 1 1)"), &Capability::root())).expect("warm-up eval");

    // 1. The opt-in posture: eval resolves, and a clamped ceiling that grants
    //    the cap can run a program — while a runaway is cut at the wall clock.
    let kernel = ikigai_embedded::calendar_server_kernel_with_eval();
    let ceiling = Capability::root().attenuate([
        "urn:cap:lisp".to_string(),
        "urn:cap:personal:calendar:read:freebusy".to_string(),
    ]);
    let out = block_on(kernel.issue(eval("(+ 20 22)"), &ceiling)).expect("a granted eval runs");
    assert_eq!(out.bytes, b"42");

    let started = Instant::now();
    let err =
        block_on(kernel.issue(eval("(let loop ((i 0)) (loop (+ i 1)))"), &ceiling)).unwrap_err();
    assert!(
        matches!(err, Error::Timeout(_)),
        "the governor bounds a served runaway: {err:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "released at the budget: {:?}",
        started.elapsed()
    );

    // 2. The kernel's declared-requires floor: a ceiling WITHOUT urn:cap:lisp is
    //    a typed Denied — the eval is bound but not invocable (and the manifold
    //    projection under that capability would not even offer it).
    let no_lisp =
        Capability::root().attenuate(["urn:cap:personal:calendar:read:freebusy".to_string()]);
    let err = block_on(kernel.issue(eval("(+ 1 1)"), &no_lisp)).unwrap_err();
    assert!(matches!(err, Error::Denied(_)), "got {err:?}");

    // 3. No opt-in, no binding: the plain calendar server doesn't resolve eval
    //    at all — the minimal surface stays minimal.
    let plain = ikigai_embedded::calendar_server_kernel();
    let err = block_on(plain.issue(eval("(+ 1 1)"), &Capability::root())).unwrap_err();
    assert!(
        matches!(err, Error::Unresolved(_)),
        "eval is not even nameable without the opt-in: {err:?}"
    );
}
