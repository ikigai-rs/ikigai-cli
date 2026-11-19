//! A grant naming a retired exec scope stops the cli at start (ledger #3828).
//!
//! ikigai-repo 0.6.0 (the exec split, ledger #3818) serves git and gh under
//! `urn:cap:exec:read:git` and `urn:cap:exec:read:gh` and grants nothing for the old
//! `urn:cap:exec:git` / `urn:cap:exec:gh`; `urn:cap:exec:cargo` and `urn:cap:exec:just` have had
//! no facade since ikigai-repo 0.3.0. A grant still naming one would quietly lose what it
//! meant to grant, so the cli refuses to start, naming the file, the grant, the scope and what
//! to write instead, and never rewrites the hand-edited file.
//!
//! Hermetic by the child's environment, as `mcp_grant.rs` is.
#![cfg(all(feature = "embedded", unix))]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const TOOLS_LIST: &str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";

/// Each retired spelling and the advice its refusal must give.
const RETIRED: [(&str, &str); 4] = [
    ("urn:cap:exec:git", "urn:cap:exec:read:git"),
    ("urn:cap:exec:gh", "urn:cap:exec:read:gh"),
    ("urn:cap:exec:cargo", "remove it; nothing serves it"),
    ("urn:cap:exec:just", "remove it; nothing serves it"),
];

fn scratch(case: &str, grants: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-rx-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config = dir.join("config").join("ikigai");
    std::fs::create_dir_all(&config).expect("scratch config home");
    std::fs::write(config.join("grants.json"), grants).expect("scratch grants.json");
    dir
}

fn grants_file(home: &Path) -> PathBuf {
    home.join("config").join("ikigai").join("grants.json")
}

/// `ikigai mcp <args>` with one `tools/list` and stdin closed: the whole output.
fn mcp(home: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .arg("mcp")
        .args(args)
        .arg("--no-config-mounts")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .env_remove("IKIGAI_GRANTS")
        .env_remove("IKIGAI_CLIENTS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary under test starts");
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        // A process that refused to start has already closed its end.
        let _ = writeln!(stdin, "{TOOLS_LIST}");
    }
    child.wait_with_output().expect("the process is reaped")
}

fn assert_refused(out: &Output, says: &[&str]) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "a refusal, stderr:\n{stderr}");
    assert!(
        out.stdout.is_empty(),
        "nothing is served: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    for part in says {
        assert!(stderr.contains(part), "no `{part}` in:\n{stderr}");
    }
}

#[test]
fn a_grant_naming_a_retired_exec_scope_refuses_to_start() {
    for (i, (scope, advice)) in RETIRED.iter().enumerate() {
        // The grant under test is not the one asked for: any grant in the file stops the start.
        let grants = format!(
            "{{\"reader\": [\"urn:cap:fs:read:*\"], \"claude\": {{\"scopes\": [\"urn:cap:exec:read:git\", \"{scope}\"]}}}}\n"
        );
        let home = scratch(&format!("grant-{i}"), &grants);
        let file = grants_file(&home);
        let out = mcp(&home, &["--grant", "reader"]);
        assert_refused(
            &out,
            &[&file.display().to_string(), "`claude`", scope, advice],
        );
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            grants,
            "the file is never rewritten"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}

#[test]
fn a_scope_flag_naming_a_retired_exec_scope_refuses_to_start() {
    for (i, (scope, advice)) in RETIRED.iter().enumerate() {
        let home = scratch(&format!("flag-{i}"), "{}\n");
        let out = mcp(&home, &["--scope", scope]);
        assert_refused(&out, &["--scope", scope, advice]);
        let _ = std::fs::remove_dir_all(&home);
    }
}

#[test]
fn a_grants_file_with_only_new_spellings_loads_unchanged() {
    let grants =
        "{\"claude\": {\"scopes\": [\"urn:cap:exec:read:git\", \"urn:cap:exec:read:gh\"]}}\n";
    let home = scratch("new", grants);
    let out = mcp(&home, &["--grant", "claude"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "the grant serves; stderr:\n{stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().next().expect("one tools/list response");
    let v: serde_json::Value = serde_json::from_str(line).expect("a JSON-RPC line");
    assert!(v["result"]["tools"].is_array(), "a tool list: {line}");
    assert_eq!(std::fs::read_to_string(grants_file(&home)).unwrap(), grants);
    let _ = std::fs::remove_dir_all(&home);
}
