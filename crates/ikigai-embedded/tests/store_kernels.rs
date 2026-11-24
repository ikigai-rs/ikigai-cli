//! Each embedded kernel must bind its own space over the process-wide durable store.
#![cfg(feature = "store")]

use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request, Verb};

fn issue(kernel: &Kernel, verb: Verb, iri: &str, args: &[(&str, &str)]) -> String {
    let request = args.iter().fold(
        Request::new(verb, Iri::parse(iri).unwrap()),
        |request, (name, value)| request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec())),
    );
    String::from_utf8(
        block_on(kernel.issue(request, &Capability::root()))
            .unwrap()
            .bytes,
    )
    .unwrap()
}

fn ask(kernel: &Kernel) -> String {
    issue(
        kernel,
        Verb::Source,
        "urn:iki:store:ask",
        &[("query", "ASK { <urn:s> <urn:p> <urn:o> }")],
    )
}

#[test]
fn kernels_over_one_durable_store_see_each_others_writes() {
    let dir = std::env::temp_dir().join(format!("ikigai-store-kernels-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config/ikigai")).unwrap();
    std::fs::create_dir_all(dir.join("workspace")).unwrap();
    std::env::set_var("HOME", &dir);
    std::env::set_var("XDG_CONFIG_HOME", dir.join("config"));
    ikigai_embedded::set_file_root(dir.join("workspace"));
    ikigai_embedded::store::set_store_path(dir.join("store"));
    let writer = ikigai_embedded::kernel();
    let reader = ikigai_embedded::kernel();
    assert!(ask(&reader).contains("false"));
    issue(
        &writer,
        Verb::Sink,
        "urn:iki:store:update",
        &[("content", "INSERT DATA { <urn:s> <urn:p> <urn:o> }")],
    );
    assert!(ask(&writer).contains("true"), "writer sees its own write");
    assert!(
        ask(&reader).contains("true"),
        "reader served a stale cached answer after the other kernel wrote"
    );
    issue(
        &reader,
        Verb::Sink,
        "urn:iki:store:update",
        &[("content", "DELETE DATA { <urn:s> <urn:p> <urn:o> }")],
    );
    assert!(
        ask(&writer).contains("false"),
        "writer sees the other kernel's deletion"
    );
    for kernel in [&writer, &reader] {
        let info = issue(kernel, Verb::Source, "urn:iki:store:info", &[]);
        assert!(info.contains("covered: false\n"), "{info}");
        let request = Request::new(Verb::Source, Iri::parse("urn:iki:store:ask").unwrap())
            .with_arg(
                "query",
                ArgRef::Inline(b"ASK { <urn:s> <urn:p> <urn:o> }".to_vec()),
            );
        assert!(!kernel.is_cached(&request, &Capability::root()));
    }

    // Once all kernels are dropped, a sole kernel may cache again. A newcomer must
    // then refuse rather than gain a write door beneath that existing cache.
    drop(reader);
    drop(writer);
    let sole = ikigai_embedded::kernel();
    assert!(ask(&sole).contains("false"));
    let late = ikigai_embedded::kernel();
    let request = Request::new(Verb::Sink, Iri::parse("urn:iki:store:update").unwrap()).with_arg(
        "content",
        ArgRef::Inline(b"INSERT DATA { <urn:s> <urn:p> <urn:o> }".to_vec()),
    );
    let error = block_on(late.issue(request, &Capability::root())).unwrap_err();
    assert!(
        error.to_string().contains("before the first read"),
        "{error}"
    );
    assert!(ask(&sole).contains("false"));
    drop(late);
    drop(sole);
    let replacement = ikigai_embedded::kernel();
    assert!(
        ask(&replacement).contains("false"),
        "dropping every cache permits a fresh binding"
    );
}
