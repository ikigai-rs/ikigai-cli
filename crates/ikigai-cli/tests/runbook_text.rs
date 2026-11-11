//! Terminal runbook reads choose the text face unless a caller names a type.
#![cfg(all(feature = "embedded", unix))]

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Mutex;

// Serialize pipe creation/spawning so a sibling child cannot inherit a pipe on macOS.
static SPAWN: Mutex<()> = Mutex::new(());

fn read(command: &str, batch: bool) -> String {
    let home = std::env::temp_dir().join(format!(
        "iki-runbook-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(home.join("config")).unwrap();
    std::fs::create_dir_all(home.join("files")).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    child
        .args(["--demo", "--plain", "--quiet"])
        .current_dir(&home)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if batch {
        child.args(["-c", command]).stdin(Stdio::null());
    } else {
        child.stdin(Stdio::piped());
    }
    let mut child = {
        let _lock = SPAWN.lock().unwrap_or_else(|error| error.into_inner());
        child.spawn().unwrap()
    };
    if !batch {
        writeln!(child.stdin.take().unwrap(), "{command}\nquit").unwrap();
    }
    let output = child.wait_with_output().unwrap();
    std::fs::remove_dir_all(home).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn batch_runbook_defaults_to_its_text_face() {
    let plain = read("source urn:runbook:basics as=text/plain", true);
    assert!(plain.contains("Basics"));
    assert!(!plain.contains("<section"));
    assert_eq!(read("source urn:runbook:basics", true), plain);
}

#[test]
fn line_repl_runbook_defaults_to_its_text_face() {
    let plain = read("source urn:runbook:basics as=text/plain", false);
    assert_eq!(read("source urn:runbook:basics", false), plain);
}

#[test]
fn explicit_runbook_faces_are_preserved() {
    for batch in [true, false] {
        let html = read("source urn:runbook:basics as=text/html", batch);
        assert!(html.contains("<"));
        assert!(html.contains("hx-get="));
        let json = read("source urn:runbook:basics as=application/json", batch);
        let page: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(page["id"], "basics");
    }
}

#[test]
fn quoted_runbook_names_and_pipeline_stages_choose_text() {
    let plain = read(
        "source urn:runbook:basics as=text/plain | urn:fn:toUpper",
        true,
    );
    assert_eq!(
        read("source \"urn:runbook:basics\" | urn:fn:toUpper", true),
        plain
    );
}
