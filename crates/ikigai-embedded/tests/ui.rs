//! Shared UI resources in the HTTP composition, including its published override directory.
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request, Verb};

fn request(verb: Verb, iri: &str) -> Request {
    Request::new(verb, Iri::parse(iri).unwrap())
}

fn source(kernel: &Kernel, iri: &str) -> String {
    let rep = block_on(kernel.issue(
        request(Verb::Source, iri),
        &Capability::scoped([] as [&str; 0]),
    ))
    .unwrap();
    String::from_utf8(rep.bytes).unwrap()
}

#[test]
// A native filesystem watcher test: this wall clock bounds notification delivery only.
#[allow(clippy::disallowed_methods)]
fn the_http_surface_sources_the_shared_shell_and_watches_read_only_overrides() {
    let home = std::env::temp_dir().join(format!("iki-ui-door-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join("config/ikigai")).unwrap();
    std::fs::create_dir_all(home.join("files")).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join("config"));
    ikigai_embedded::set_file_root(home.join("files"));
    let kernel = ikigai_embedded::kernel_for("ui-test");
    assert!(source(&kernel, ikigai_ui::SHELL).contains("Skip to content"));
    assert!(source(&kernel, ikigai_ui::TOKENS_CSS).contains("--"));

    let directory = home.join("config/ikigai/ui");
    std::fs::create_dir_all(&directory).unwrap();
    let shell = directory.join("shell.html");
    std::fs::write(&shell, "<main>First shell</main>").unwrap();
    let kernel = Arc::new(ikigai_embedded::kernel_for("ui-test"));
    let _watch = ikigai_embedded::watch_workspace(&kernel).unwrap().unwrap();
    // Overrides are published resources: a public viewer needs no filesystem authority.
    assert_eq!(
        source(&kernel, ikigai_ui::SHELL),
        "<main>First shell</main>"
    );
    let read = request(Verb::Source, ikigai_ui::SHELL);
    let public = Capability::scoped([] as [&str; 0]);
    assert!(
        kernel.is_cached(&read, &public),
        "the override read is golden-threaded"
    );
    let composed = request(Verb::Source, "urn:iki:fn:compose").with_arg(
        "src",
        ArgRef::Reference(Iri::parse(ikigai_ui::SHELL).unwrap()),
    );
    let page = block_on(kernel.issue(composed.clone(), &public)).unwrap();
    assert_eq!(page.bytes, b"<main>First shell</main>");
    assert!(kernel.is_cached(&composed, &public));
    std::fs::write(&shell, "<main>Edited shell</main>").unwrap();
    let until = Instant::now() + Duration::from_secs(20);
    while kernel.is_cached(&read, &public) {
        assert!(
            Instant::now() < until,
            "the editor change did not cut the shell's thread"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        source(&kernel, ikigai_ui::SHELL),
        "<main>Edited shell</main>"
    );
    let page = block_on(kernel.issue(composed, &public)).unwrap();
    assert_eq!(page.bytes, b"<main>Edited shell</main>");
    // Missing overrides keep the other compiled artifacts available.
    assert!(source(&kernel, "urn:iki:ui:htmx").contains("htmx"));

    for iri in ikigai_ui::ARTIFACTS.iter().map(|a| a.iri).chain([
        ikigai_ui::TOKENS_CSS,
        "urn:iki:ui:palette:light",
        "urn:iki:ui:dir:shell.html",
    ]) {
        let description = kernel.describe(&Iri::parse(iri).unwrap()).unwrap();
        assert!(!description.verbs.contains(&Verb::Sink), "{iri}");
        for verb in [Verb::Sink, Verb::Delete] {
            assert!(
                block_on(kernel.issue(request(verb, iri), &Capability::root())).is_err(),
                "{verb:?} {iri}"
            );
        }
    }
    assert_eq!(
        std::fs::read_to_string(&shell).unwrap(),
        "<main>Edited shell</main>"
    );
    // Even the published directory cannot walk out of its jail or follow a link.
    assert!(block_on(kernel.issue(
        request(Verb::Source, "urn:iki:ui:dir:../config.toml"),
        &Capability::root()
    ))
    .is_err());
    #[cfg(unix)]
    {
        std::fs::write(home.join("private.txt"), "private").unwrap();
        std::os::unix::fs::symlink(home.join("private.txt"), directory.join("linked.txt")).unwrap();
        assert!(block_on(kernel.issue(
            request(Verb::Source, "urn:iki:ui:dir:linked.txt"),
            &Capability::root()
        ))
        .is_err());
    }
    std::fs::remove_file(&shell).unwrap();
    let until = Instant::now() + Duration::from_secs(20);
    while kernel.is_cached(&read, &public) {
        assert!(
            Instant::now() < until,
            "removing the override did not cut its thread"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(source(&kernel, ikigai_ui::SHELL).contains("Skip to content"));
    drop(_watch);
    std::fs::remove_dir_all(home).unwrap();
}
