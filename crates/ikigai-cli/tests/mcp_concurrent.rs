//! `ikigai mcp` answers a fast `tools/call` while a slow one is still running, through the
//! real binary (ledger #1695).
//!
//! The server used to read one line, run it to the end and only then read the next, so one long
//! poll (the layers feed's `wait=50`) held every other tool on that MCP server behind it. Now a
//! `tools/call` runs on its own thread and its answer is written when it finishes; everything
//! else is still answered on the reading thread, in arrival order. The library's tests
//! (`ikigai_mcp::server`) pin the bound and the busy answer; this file pins that the binary's
//! own loop is the concurrent one.
//!
//! The slow call is a Lisp runaway under a `lisp.timeout` of an hour, so it is still running
//! for as long as this test can care: nothing about it depends on how fast the machine is.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `lisp_bounds.rs`: the config home is named by
//! `--config-home`, and `HOME`, `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set on the spawned
//! process only; `--no-config-mounts` keeps any topology out.
#![cfg(all(feature = "embedded", unix))]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long the test waits for an answer it is owed before calling the server stuck. A guard
/// against a hang, not a measurement: the answers it waits for are an echo and a ping.
const HANG_GUARD: Duration = Duration::from_secs(120);

/// The server under test, killed and reaped however the test ends: its slow call is a runaway
/// with an hour's budget, and a failed assertion must not leave it spinning.
struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_fast_call_answers_while_a_slow_one_runs() {
    let home = std::env::temp_dir().join(format!("iki-mcpc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join("config")).expect("config home");
    std::fs::create_dir_all(home.join("files")).expect("scratch workspace");
    std::fs::write(
        home.join("config").join("config.toml"),
        "lisp.timeout = 3600\n",
    )
    .expect("config.toml");
    let mut child = Reaped(
        Command::new(env!("CARGO_BIN_EXE_ikigai"))
            .arg("--config-home")
            .arg(home.join("config"))
            .args(["mcp", "--root", "--no-config-mounts"])
            .current_dir(&home)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join("decoy"))
            .env("IKIGAI_FILES", home.join("files"))
            .env_remove("IKIGAI_GRANTS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the binary under test starts"),
    );
    let mut stdin = child.0.stdin.take().expect("piped stdin");
    let stdout = child.0.stdout.take().expect("piped stdout");
    let (lines, replies) = mpsc::channel::<serde_json::Value>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            let reply = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("a JSON line, {line:?}: {e}"));
            if lines.send(reply).is_err() {
                return;
            }
        }
    });
    let next = |owed: &str| {
        replies.recv_timeout(HANG_GUARD).unwrap_or_else(|_| {
            panic!(
                "no answer in {HANG_GUARD:?} for {owed}: the server is stuck behind the slow call"
            )
        })
    };
    let mut send = |line: serde_json::Value| {
        writeln!(stdin, "{line}").expect("the server reads its stdin");
        stdin.flush().expect("flushed");
    };

    send(
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "eval__source",
        "arguments": {"in": "(define (spin n) (spin (+ n 1))) (spin 0)"}}}),
    );
    send(
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "echo__source", "arguments": {"message": "fast"}}}),
    );
    let fast = next("the fast call");
    assert_eq!(fast["id"], 2, "the fast call answers first: {fast}");
    assert_eq!(fast["result"]["isError"], false, "{fast}");
    assert!(
        fast["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("fast")),
        "{fast}"
    );

    // Messages that are not calls are still answered in order, slow call or not.
    send(serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}));
    send(serde_json::json!({"jsonrpc": "2.0", "id": 4, "method": "initialize"}));
    let ping = next("the ping");
    assert_eq!(ping["id"], 3, "{ping}");
    assert_eq!(ping["result"], serde_json::json!({}), "{ping}");
    let initialize = next("the initialize");
    assert_eq!(initialize["id"], 4, "{initialize}");
    assert!(
        initialize["result"]["capabilities"]["tools"].is_object(),
        "{initialize}"
    );

    // The runaway is still running: it has had no answer.
    assert!(
        replies.try_recv().is_err(),
        "the slow call is a runaway under an hour's budget and has not answered"
    );
    drop(child);
    let _ = std::fs::remove_dir_all(&home);
}
