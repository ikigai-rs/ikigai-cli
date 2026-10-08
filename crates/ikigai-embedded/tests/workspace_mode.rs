//! The production workspace is created PRIVATE, whatever the umask (ledger #868).
//!
//! `file_root()` created `$IKIGAI_FILES` (else `~/.ikigai/workspace`) with
//! `create_dir_all`, which follows the umask, so a new install under `umask 002` got a
//! `0775` workspace, and the passkey directory check (`judge_directory`, ledger #850) then
//! refused it at `serve --http` startup: a fresh install that could not start.
//!
//! ⚠ **This file holds ONE test, and must.** The umask is per PROCESS, so a test that
//! loosens it would loosen it for every test running beside it in the same binary, and
//! the environment variable it sets is process-wide too. An integration-test file is its
//! own process; keeping it to one test keeps both changes from reaching anything else.
//! It also exercises the PRODUCTION branch of `file_root()`: an integration test links the
//! crate without `cfg(test)`, so the per-thread test substitution does not apply.

#[cfg(unix)]
#[test]
fn a_new_workspace_is_created_0700_under_a_permissive_umask_and_an_existing_one_is_left_alone() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = std::env::temp_dir().join(format!("ikigai-ws-mode-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let workspace = scratch.join("fresh").join("workspace");

    // SAFETY: `umask` takes a mode, has no preconditions and cannot fail. This binary
    // runs no other test (see the module comment), so nothing else observes the change.
    let previous = unsafe { libc::umask(0o002) };
    std::env::set_var("IKIGAI_FILES", &workspace);
    let root = ikigai_embedded::file_root();
    let mode = |path: &std::path::Path| {
        std::fs::metadata(path)
            .expect("the workspace exists")
            .permissions()
            .mode()
            & 0o7777
    };
    let created = mode(&root);

    // An EXISTING directory is the operator's: its mode is left for `judge_directory` to
    // judge, never silently tightened.
    let existing = scratch.join("existing");
    std::fs::create_dir_all(&existing).unwrap();
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::env::set_var("IKIGAI_FILES", &existing);
    let kept = mode(&ikigai_embedded::file_root());

    // SAFETY: as above.
    unsafe { libc::umask(previous) };
    std::fs::remove_dir_all(&scratch).ok();

    assert_eq!(root, workspace);
    assert_eq!(
        created, 0o700,
        "a new workspace must be private whatever the umask, not {created:04o}"
    );
    assert_eq!(kept, 0o755, "an existing workspace's mode is not rewritten");
}
