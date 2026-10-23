//! `ikigai mcp` answers invalid input per JSON-RPC 2.0 §5.1, through the real binary
//! (ledger #1309).
//!
//! The binary runs its OWN stdin loop (it shares the grant and the stdout lock with the
//! grants poller), not `ikigai_mcp::server::serve`, so the library's loop test does not
//! cover it. Before this file, an unparseable line, a non-object, a batch and a method-less
//! object were all skipped in silence, a message without `"jsonrpc":"2.0"` was answered as
//! if valid, and a line that was not UTF-8 ended the session.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `mcp_grant.rs`: `HOME` and `XDG_CONFIG_HOME`
//! point into a scratch tree on the spawned process only, and `--no-config-mounts` keeps
//! the developer's topology out.
#![cfg(all(feature = "embedded", unix))]

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn every_invalid_line_gets_its_json_rpc_error_and_the_session_goes_on() {
    let home = std::env::temp_dir().join(format!("iki-mj-{}", std::process::id()));
    std::fs::create_dir_all(home.join("config").join("ikigai")).expect("scratch config home");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .arg("mcp")
        .arg("--root")
        .arg("--no-config-mounts")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .env_remove("IKIGAI_GRANTS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary under test starts");
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        let lines: [&[u8]; 9] = [
            b"not json\n",
            b"[]\n",
            b"{\"jsonrpc\":\"2.0\",\"id\":7}\n",
            b"{\"id\":8,\"method\":\"ping\"}\n",
            b"\xff\xfe\n",
            // Owed nothing: a client response, and a notification.
            b"{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}\n",
            b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            b"\n",
            // Still serving after all of the above.
            b"{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"ping\"}\n",
        ];
        for line in lines {
            stdin.write_all(line).expect("the server reads its stdin");
        }
    }
    let out = child.wait_with_output().expect("the process is reaped");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "a clean exit on EOF: {out:?}");
    let got: Vec<serde_json::Value> = String::from_utf8(out.stdout)
        .expect("UTF-8 replies")
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("a JSON line, {l:?}: {e}")))
        .collect();
    let null = serde_json::Value::Null;
    let expect = [
        (null.clone(), Some(-32700), "Parse error"),
        (null.clone(), Some(-32600), "Invalid Request"),
        (serde_json::json!(7), Some(-32600), "Invalid Request"),
        (serde_json::json!(8), Some(-32600), "Invalid Request"),
        (null, Some(-32700), "Parse error"),
        (serde_json::json!(10), None, ""),
    ];
    assert_eq!(
        got.len(),
        expect.len(),
        "one reply per owed line: {got:#?}\n{stderr}"
    );
    for (reply, (id, code, message)) in got.iter().zip(expect) {
        assert_eq!(reply["jsonrpc"], "2.0", "{reply}");
        assert_eq!(reply["id"], id, "{reply}");
        assert_eq!(reply["error"]["code"].as_i64(), code, "{reply}");
        if code.is_some() {
            assert_eq!(reply["error"]["message"], message, "{reply}");
        } else {
            assert_eq!(reply["result"], serde_json::json!({}), "{reply}");
        }
    }
}
