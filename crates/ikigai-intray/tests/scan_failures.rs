//! Filesystem failures must be distinguishable from an empty, healthy intray.
mod common;

use common::{scratch, Counting};
use ikigai_core::Capability;
use ikigai_intray::{dead_letters, dead_letters_of, SpaceReactor};
use std::process::Command;
use std::sync::Arc;

const CHILD: &str = "IKIGAI_INTRAY_SCAN_FAILURE_CHILD";

fn child_stderr(case: &str) -> String {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", case, "--nocapture"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stderr).unwrap()
}

#[test]
fn an_unreadable_dead_letter_root_is_reported() {
    if std::env::var_os(CHILD).is_some() {
        let root = scratch("dead-letter-root-file");
        std::fs::create_dir_all(root.parent().unwrap()).unwrap();
        std::fs::write(&root, b"not a directory").unwrap();
        assert!(dead_letters(&root).is_empty());
        return;
    }
    let stderr = child_stderr("an_unreadable_dead_letter_root_is_reported");
    assert!(stderr.contains("cannot read dead letters"), "{stderr:?}");
    assert!(stderr.contains("dead-letter-root-file"), "{stderr:?}");
}

#[test]
fn an_unreadable_dead_letter_stage_is_reported() {
    if std::env::var_os(CHILD).is_some() {
        let root = scratch("dead-letter-stage-file");
        std::fs::create_dir_all(root.join("jobs")).unwrap();
        std::fs::write(root.join("jobs/error"), b"not a directory").unwrap();
        assert_eq!(dead_letters_of(&root, ["jobs".to_string()])[0].count, 0);
        return;
    }
    let stderr = child_stderr("an_unreadable_dead_letter_stage_is_reported");
    assert!(stderr.contains("cannot read dead letters"), "{stderr:?}");
    assert!(
        stderr.contains("jobs") && stderr.contains("error"),
        "{stderr:?}"
    );
}

#[test]
fn a_missing_dead_letter_tree_is_quiet() {
    if std::env::var_os(CHILD).is_some() {
        let root = scratch("dead-letter-absent");
        assert!(dead_letters(&root).is_empty());
        assert_eq!(dead_letters_of(&root, ["jobs".to_string()])[0].count, 0);
        return;
    }
    assert!(child_stderr("a_missing_dead_letter_tree_is_quiet").is_empty());
}

#[test]
fn a_watch_refuses_an_inbox_it_cannot_create() {
    let root = scratch("blocked-inbox");
    std::fs::create_dir_all(root.join("jobs")).unwrap();
    std::fs::write(root.join("jobs/handler"), "urn:test:handler").unwrap();
    std::fs::write(root.join("jobs/inbox"), b"not a directory").unwrap();
    let handler = Arc::new(Counting::new());
    let result = Arc::new(SpaceReactor::new(
        root.clone(),
        handler.clone(),
        Capability::root(),
    ))
    .try_watch();
    assert!(
        matches!(result, Err(ref why) if why.contains("cannot create") && why.contains("jobs") && why.contains("inbox")),
        "{result:?}"
    );
    assert_eq!(handler.calls(), 0);
}
