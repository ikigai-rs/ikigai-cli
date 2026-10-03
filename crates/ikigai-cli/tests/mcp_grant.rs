//! `ikigai mcp --grant` fails CLOSED, through the real binary (ledger #733, finding M1).
//!
//! A grant is the ceiling of an agent's session. Before this file, a `--grant` that resolved
//! to no scopes — a misspelled name, a deleted entry, an empty list, a `grants.json` that did
//! not parse — produced an empty scope union, and an empty union was read as "no ceiling", so
//! the agent ran with ROOT authority. The live grants poller made the same choice
//! mid-session: break the file while an agent is connected and its tool list widened to
//! everything.
//!
//! The rule now, pinned here end to end:
//!
//! 1. **At startup, a named grant that resolves to nothing refuses to start**, naming it.
//!    Root stays reachable only by giving neither `--grant` nor `--scope`, which the banner
//!    states as UNRESTRICTED.
//! 2. **Mid-session, a grant that stops resolving drops the session to NO authority** (and
//!    re-emits `tools/list_changed`), never to root.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT: `HOME` and `XDG_CONFIG_HOME` point into a scratch
//! tree on the spawned process only, `IKIGAI_GRANTS` is removed from it, and
//! `--no-config-mounts` keeps the developer's topology out.
#![cfg(all(feature = "embedded", unix))]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// A watchdog against a hang, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

const TOOLS_LIST: &str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";

/// One grant with a scope nothing in the default manifold requires: the session it mints is
/// narrow, so its tool list is visibly shorter than root's.
const GRANTS: &str = "{\"reader\": [\"urn:cap:nothing:much\"], \"empty\": []}\n";

/// A scratch home whose config home carries `grants` as `grants.json`.
fn scratch(case: &str, grants: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-mg-{}-{case}", std::process::id()));
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

/// One `tools/list` round trip with stdin closed after it: the whole output of the process.
fn one_shot(home: &Path, args: &[&str]) -> Output {
    let mut child = spawn(home, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary under test starts");
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        // A process that refused to start has already closed its end; that is the case
        // under test, not a failure of the test.
        let _ = writeln!(stdin, "{TOOLS_LIST}");
    }
    child.wait_with_output().expect("the process is reaped")
}

/// The number of tools in a `tools/list` response line.
fn tool_count(line: &str) -> usize {
    let v: serde_json::Value =
        serde_json::from_str(line).unwrap_or_else(|e| panic!("a JSON-RPC line, got {line:?}: {e}"));
    v["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("a tools/list result, got {line}"))
        .len()
}

fn root_count() -> usize {
    let home = scratch("root", GRANTS);
    let out = one_shot(&home, &[]);
    assert!(out.status.success(), "no flags serves root: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    tool_count(stdout.lines().next().expect("one response"))
}

#[test]
fn an_unknown_grant_refuses_to_start() {
    let home = scratch("unknown", GRANTS);
    let out = one_shot(&home, &["--grant", "raeder"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a misspelled grant must not serve; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("`raeder`"),
        "the refusal names the grant:\n{stderr}"
    );
    assert!(
        out.stdout.is_empty(),
        "no tool list is served: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn an_empty_grant_refuses_to_start() {
    let home = scratch("empty", GRANTS);
    let out = one_shot(&home, &["--grant", "empty"]);
    assert!(
        !out.status.success(),
        "an empty grant is undecided, not root"
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn an_unparseable_grants_file_refuses_to_start() {
    let home = scratch("garbled", "{\"reader\": [\"urn:cap:nothing:much\"\n");
    let out = one_shot(&home, &["--grant", "reader"]);
    assert!(
        !out.status.success(),
        "a broken grants file must not degrade into root"
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn one_unknown_grant_beside_a_good_one_still_refuses() {
    let home = scratch("mixed", GRANTS);
    let out = one_shot(&home, &["--grant", "reader", "--grant", "raeder"]);
    assert!(
        !out.status.success(),
        "a typo is refused, not silently dropped"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("`raeder`"));
}

#[test]
fn a_known_grant_serves_a_narrower_list_than_root() {
    let home = scratch("known", GRANTS);
    let out = one_shot(&home, &["--grant", "reader"]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let scoped = tool_count(stdout.lines().next().expect("one response"));
    assert!(scoped < root_count(), "the grant narrows the manifold");
}

/// The process kept alive across a grants-file edit, killed when the test ends.
struct Session {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
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
            .stderr(Stdio::null())
            .spawn()
            .expect("the binary under test starts");
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Session {
            child,
            stdin,
            lines,
        }
    }

    /// The next stdout line satisfying `want`, skipping the others.
    fn next(&self, want: impl Fn(&str) -> bool) -> String {
        loop {
            let line = self
                .lines
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
        tool_count(&self.next(|l| l.contains("\"id\":1")))
    }
}

#[test]
fn a_grant_broken_mid_session_drops_authority_instead_of_widening_it() {
    let root = root_count();
    let home = scratch("live", GRANTS);
    let mut session = Session::start(&home, &["--grant", "reader"]);
    let before = session.tools();
    assert!(before < root, "the session starts narrow");

    // The poller compares mtimes; make sure the edit lands in a later instant than the
    // file the session started with, whatever the filesystem's timestamp granularity.
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(grants_file(&home), "{ not json").expect("break the grants file");
    session.next(|l| l.contains("notifications/tools/list_changed"));

    let after = session.tools();
    assert!(
        after < root,
        "a broken grant must never widen the session to root ({after} of {root} tools)"
    );
    assert!(
        after <= before,
        "authority only narrows: {before} → {after}"
    );
}
