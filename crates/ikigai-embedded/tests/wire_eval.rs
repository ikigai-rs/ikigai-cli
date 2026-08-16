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
    // ALL process-global config — including the signed-run door's — before any
    // kernel exists; this single test fn owns it (see signed_run_door).
    ikigai_embedded::set_eval_timeout_secs(2);

    // The workspace root FIRST, before any kernel: the served kernels below bind the file
    // module, the intray spaces and the client registry to `file_root()`, so without this
    // they would create and bind the developer's real `~/.ikigai/workspace`. `cfg(test)`
    // does not reach an integration test — it links the crate compiled without it — so the
    // hermetic root has to be asked for here.
    let workspace = std::env::temp_dir().join("ikigai-wire-eval-workspace");
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(&workspace).expect("workspace root");
    ikigai_embedded::set_file_root(workspace);
    let dir = std::env::temp_dir().join("ikigai-code-signers-test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("signers dir");
    std::fs::write(dir.join("k1.pub"), K1_PUB).expect("write pub key");
    ikigai_embedded::set_code_signers_dir(dir.clone());
    ikigai_embedded::set_code_signers(vec!["urn:codekey:k1.pub".to_string()]);

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

    signed_run_door(&kernel);
    demo_wakes_on_the_served_surface();
}

/// The regression that motivated serving the FULL root over IPC: a connected
/// client's `demo on` (a remote sink of urn:host:demo) must actually wake the
/// demo endpoints on the SERVED kernel — which requires the gated runbook to be
/// mounted there at all. (It used to live only in the embedded root, so the flag
/// flipped with nothing listening.)
fn demo_wakes_on_the_served_surface() {
    let kernel = ikigai_embedded::trusted_kernel_for("Remote (IPC)");
    let cap = Capability::root();

    // Off by default: the demo IRI is absent, exactly as a fresh server starts.
    // (The flag is process-global; earlier sections never touch it.)
    let err = block_on(kernel.issue(
        Request::new(
            Verb::Source,
            Iri::parse("urn:demo:jury").expect("valid IRI"),
        ),
        &cap,
    ))
    .unwrap_err();
    assert!(matches!(err, Error::Unresolved(_)), "got {err:?}");

    // `demo on` exactly as a connected REPL sends it: a SINK of urn:host:demo
    // through the served kernel.
    let out = block_on(
        kernel.issue(
            Request::new(Verb::Sink, Iri::parse("urn:host:demo").expect("valid IRI"))
                .with_arg("content", ArgRef::Inline(b"on".to_vec())),
            &cap,
        ),
    )
    .expect("the demo toggle is served");
    assert_eq!(out.bytes, b"demo on\n");

    // And the jury demo now resolves on the same served kernel — offline-safe:
    // with no model provider reachable the shape still renders (with a note).
    block_on(kernel.issue(
        Request::new(
            Verb::Source,
            Iri::parse("urn:demo:jury").expect("valid IRI"),
        ),
        &cap,
    ))
    .expect("the demo endpoint woke on the served surface");
}

// The same fixed Ed25519 pair ikigai-sign's tests use (PKCS8 private + SPKI
// public, PEM).
const K1_PRIV: &str = "-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIEIW/m80W4IrD82k3Mos0l4aeyfOkZMMZXqEYt6jpawc\n\
-----END PRIVATE KEY-----\n";
const K1_PUB: &str = "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAa9JuLzyLESJBF9LPZZ4RJk13iu5OhgKvLRQ3q0oQ4pE=\n\
-----END PUBLIC KEY-----\n";

/// The signed-run door on a SERVED kernel: a declared trust set binds
/// `urn:lisp:run`, the key resolves as `urn:codekey:{file}` from the signers
/// dir, verification runs through the served kernel's own `urn:sign:verify`,
/// and a ceiling holding ONLY `urn:cap:lisp:run` (+ freebusy) executes a
/// trusted program it could never have eval'd arbitrarily. (Continues the test
/// above IN THE SAME test fn: env vars are process-global and integration-test
/// fns run on parallel threads — two tests setting different budgets raced.)
fn signed_run_door(_governed_2s: &ikigai_core::Kernel) {
    // A generous budget for THIS section, on its own kernel. The 2s ceiling above
    // exists to prove a runaway is cut quickly; the signed path does strictly more
    // work (verify through the kernel, THEN evaluate) and on a slow shared CI
    // runner in a debug build it raced that ceiling — the failure was a flaky
    // Timeout, not a real one. The budget is read when the kernel is BUILT, so
    // raising it needs a fresh kernel.
    ikigai_embedded::set_eval_timeout_secs(60);
    let kernel = &ikigai_embedded::calendar_server_kernel_with_eval();
    // Sign the program through a scratch kernel holding the PRIVATE key — the
    // author's side; the served kernel only ever sees the public half.
    let author = ikigai_core::Kernel::new(std::sync::Arc::new(ikigai_sign::space().bind(
        ikigai_core::Exact::new("urn:author:key"),
        StaticKey(K1_PRIV),
    )));
    let program = "(+ 40 2)";
    let sig = {
        let out = block_on(
            author.issue(
                Request::new(
                    Verb::Source,
                    Iri::parse("urn:sign:sign").expect("valid IRI"),
                )
                .with_arg("in", ArgRef::Inline(program.as_bytes().to_vec()))
                .with_arg("key", ArgRef::Inline(b"urn:author:key".to_vec())),
                &Capability::root().attenuate(["urn:cap:sign".to_string()]),
            ),
        )
        .expect("author signs");
        String::from_utf8(out.bytes).expect("sig graph utf-8")
    };

    let run = |sig: &str| {
        Request::new(Verb::Source, Iri::parse("urn:lisp:run").expect("valid IRI"))
            .with_arg("in", ArgRef::Inline(program.as_bytes().to_vec()))
            .with_arg("sig", ArgRef::Inline(sig.as_bytes().to_vec()))
            .with_arg("key", ArgRef::Inline(b"urn:codekey:k1.pub".to_vec()))
    };
    // Signed-only ceiling: may submit signed programs, may NOT arbitrary-eval.
    let ceiling = Capability::root().attenuate([
        "urn:cap:lisp:run".to_string(),
        "urn:cap:personal:calendar:read:freebusy".to_string(),
    ]);

    let out = block_on(kernel.issue(run(&sig), &ceiling)).expect("the signed program runs");
    assert_eq!(out.bytes, b"42");

    // The same ceiling cannot use the arbitrary-eval door.
    let err = block_on(kernel.issue(eval("(+ 1 1)"), &ceiling)).unwrap_err();
    assert!(
        matches!(err, Error::Denied(_)),
        "signed-only means signed-only: {err:?}"
    );
}

/// Fixed bytes as a key resource (the author's private-key stand-in).
struct StaticKey(&'static str);

#[async_trait::async_trait]
impl ikigai_core::Endpoint for StaticKey {
    async fn invoke(
        &self,
        _inv: &ikigai_core::Invocation<'_>,
    ) -> ikigai_core::Result<ikigai_core::Representation> {
        Ok(ikigai_core::Representation::new(
            ikigai_core::ReprType::new("application/x-pem-file"),
            self.0.as_bytes().to_vec(),
        ))
    }
}
