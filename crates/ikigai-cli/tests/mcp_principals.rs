//! `ikigai mcp`'s authority, through the real binary (ledger #1830, FND-A item 10, row D11).
//!
//! Each test was written to FAIL on the binary before this change:
//!
//! 1. **No root default.** A bare `ikigai mcp` served root. It now refuses to start and names
//!    the flags; `--root` asks for root explicitly and the banner says so.
//! 2. **A live reload never widens.** The grants poller applied an edit within a second, so an
//!    agent that could write `grants.json` widened its own session. A reload now narrows, or
//!    restores, never past what the session started with.
//! 3. **An agent session reads only a file its user cannot write.** `--principal` refuses a
//!    grants file this user owns, naming it. (The accept path needs a root-owned file, which a
//!    hermetic test cannot make: it is pinned by `ikigai-embedded`'s `agents` tests, against
//!    `/etc/hosts`, and by its subset tests.)
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `mcp_grant.rs`: `HOME` and `XDG_CONFIG_HOME` point
//! into a scratch tree on the spawned process only, `IKIGAI_GRANTS` is removed, and
//! `--no-config-mounts` keeps the developer's topology out.
#![cfg(all(feature = "embedded", unix))]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const PATIENCE: Duration = Duration::from_secs(90);

const TOOLS_LIST: &str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";

/// `narrow` grants nothing the default manifold requires; `inspect` adds the scope that
/// projects the kernel's inspection tools, so a session widened to it lists more tools.
const GRANTS: &str = "{\"narrow\": [\"urn:cap:nothing:much\"]}\n";
const WIDENED: &str = "{\"narrow\": [\"urn:cap:nothing:much\", \"urn:cap:kernel:inspect\"]}\n";

fn scratch(case: &str, grants: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-mp-{}-{case}", std::process::id()));
    let config = dir.join("config").join("ikigai");
    std::fs::create_dir_all(&config).expect("scratch config home");
    std::fs::write(config.join("grants.json"), grants).expect("scratch grants.json");
    dir
}

fn grants_file(home: &Path) -> PathBuf {
    home.join("config").join("ikigai").join("grants.json")
}

fn spawn(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .arg("mcp")
        .args(args)
        .arg("--no-config-mounts")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .env_remove("IKIGAI_GRANTS");
    command
}

fn one_shot(home: &Path, args: &[&str]) -> Output {
    let mut child = spawn(home, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary under test starts");
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        let _ = writeln!(stdin, "{TOOLS_LIST}");
    }
    child.wait_with_output().expect("the process is reaped")
}

fn tool_count(line: &str) -> usize {
    let v: serde_json::Value =
        serde_json::from_str(line).unwrap_or_else(|e| panic!("a JSON-RPC line, got {line:?}: {e}"));
    v["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("a tools/list result, got {line}"))
        .len()
}

#[test]
fn a_bare_mcp_refuses_to_start_and_names_the_flags() {
    let home = scratch("bare", GRANTS);
    let out = one_shot(&home, &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a bare mcp must not serve root:\n{stderr}"
    );
    assert!(out.stdout.is_empty(), "no tool list is served");
    for flag in ["--grant", "--scope", "--principal", "--root"] {
        assert!(stderr.contains(flag), "the refusal names {flag}:\n{stderr}");
    }
    // `--show` is visibility, never authority: it does not stand in for a grant.
    let shown = one_shot(&home, &["--show", "echo"]);
    assert!(!shown.status.success(), "--show alone names no authority");
}

#[test]
fn root_is_served_only_when_asked_for_and_the_banner_says_so() {
    let home = scratch("root", GRANTS);
    let out = one_shot(&home, &["--root"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains("--root") && stderr.contains("UNRESTRICTED"),
        "{stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let root = tool_count(stdout.lines().next().expect("one response"));

    let narrow = one_shot(&home, &["--grant", "narrow"]);
    let stdout = String::from_utf8_lossy(&narrow.stdout);
    assert!(tool_count(stdout.lines().next().expect("one response")) < root);
}

#[test]
fn root_beside_a_grant_scope_or_principal_is_refused() {
    let home = scratch("conflict", GRANTS);
    for extra in [
        &["--grant", "narrow"][..],
        &["--scope", "urn:cap:nothing:much"][..],
        &["--principal", "urn:example:agent"][..],
    ] {
        let mut args = vec!["--root"];
        args.extend_from_slice(extra);
        let out = one_shot(&home, &args);
        assert!(!out.status.success(), "{args:?} must not start");
        assert!(out.stdout.is_empty());
    }
}

struct Session {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
    errors: mpsc::Receiver<String>,
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Session {
    fn start(home: &Path, args: &[&str]) -> Self {
        let mut child = spawn(home, args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the binary under test starts");
        let stdin = child.stdin.take().expect("piped stdin");
        let pipe = |reader: Box<dyn std::io::Read + Send>| {
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                for line in BufReader::new(reader).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
            rx
        };
        let lines = pipe(Box::new(child.stdout.take().expect("piped stdout")));
        let errors = pipe(Box::new(child.stderr.take().expect("piped stderr")));
        Session {
            child,
            stdin,
            lines,
            errors,
        }
    }

    fn next(rx: &mpsc::Receiver<String>, want: impl Fn(&str) -> bool) -> String {
        loop {
            let line = rx
                .recv_timeout(PATIENCE)
                .unwrap_or_else(|e| panic!("no matching line within {PATIENCE:?}: {e}"));
            if want(&line) {
                return line;
            }
        }
    }

    fn tools(&mut self) -> usize {
        writeln!(self.stdin, "{TOOLS_LIST}").expect("the session reads stdin");
        self.stdin.flush().expect("flush");
        tool_count(&Session::next(&self.lines, |l| l.contains("\"id\":1")))
    }
}

#[test]
fn a_grant_widened_mid_session_does_not_widen_the_session() {
    let home = scratch("widen", GRANTS);
    let wider = one_shot(&scratch("widen-ref", WIDENED), &["--grant", "narrow"]);
    let wider = tool_count(
        String::from_utf8_lossy(&wider.stdout)
            .lines()
            .next()
            .expect("one response"),
    );

    let mut session = Session::start(&home, &["--grant", "narrow"]);
    let before = session.tools();
    assert!(
        before < wider,
        "the widened grant lists more tools ({before} vs {wider})"
    );

    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(grants_file(&home), WIDENED).expect("widen the grant");
    // The poller looks once a second; give it three looks before asking.
    std::thread::sleep(Duration::from_secs(3));
    let after = session.tools();
    assert_eq!(
        after, before,
        "a widening waits for a restart: {before} → {after}"
    );
    let said = Session::next(&session.errors, |l| l.contains("the grant now adds"));
    assert!(said.contains("urn:cap:kernel:inspect"), "{said}");
}

#[test]
fn a_narrowed_grant_still_narrows_live_and_can_be_restored() {
    let home = scratch("narrow", WIDENED);
    let mut session = Session::start(&home, &["--grant", "narrow"]);
    let before = session.tools();

    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(grants_file(&home), GRANTS).expect("narrow the grant");
    Session::next(&session.lines, |l| {
        l.contains("notifications/tools/list_changed")
    });
    let narrowed = session.tools();
    assert!(
        narrowed < before,
        "a narrowing applies live: {before} → {narrowed}"
    );

    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(grants_file(&home), WIDENED).expect("restore the grant");
    Session::next(&session.lines, |l| {
        l.contains("notifications/tools/list_changed")
    });
    assert_eq!(
        session.tools(),
        before,
        "restoring up to the starting grant applies live"
    );
}

#[test]
fn an_agent_session_refuses_a_grants_file_its_user_can_write() {
    let grants = r#"{
      "brian": ["urn:cap:nothing:much"],
      "claude": ["urn:cap:nothing:much"],
      "principals": {
        "urn:example:brian": {"kind": "person", "grant": "brian"},
        "urn:example:hub": {"kind": "agent", "acts_for": "urn:example:brian", "grant": "claude"}
      }
    }"#;
    let home = scratch("agent", grants);
    let file = grants_file(&home);
    for args in [
        vec!["--principal", "urn:example:hub"],
        vec![
            "--principal",
            "urn:example:hub",
            "--grants",
            file.to_str().unwrap(),
        ],
    ] {
        let out = one_shot(&home, &args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?} must not serve:\n{stderr}");
        assert!(out.stdout.is_empty());
        assert!(
            stderr.contains("cannot protect an agent session") && stderr.contains("grants.json"),
            "the refusal names the file and why:\n{stderr}"
        );
    }
}
