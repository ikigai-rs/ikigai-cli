//! `urn:diagram:*` through the REAL binary: bound in the local root, drawn under root, refused
//! without `urn:cap:kernel:inspect`, and projected into MCP only where that capability holds.
//!
//! The embedded crate pins the binding against a constructed kernel. This file pins what an
//! operator and an agent see: `-c`, and `ikigai mcp`'s `tools/list` under a `--scope`.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `arrangement.rs`: `HOME`, `XDG_CONFIG_HOME` and
//! `IKIGAI_FILES` are set on the spawned process only.
#![cfg(all(feature = "embedded", unix))]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// A scratch home for one case, with an empty config home.
fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-dia-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    std::fs::create_dir_all(dir.join("files")).expect("scratch workspace");
    dir
}

fn command(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"));
    command
}

/// Run `ikigai <args…>` and wait for it (`output` reaps, so the status is real).
fn run(home: &Path, args: &[&str]) -> Output {
    command(home, args)
        .output()
        .expect("the binary under test runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `urn:diagram:kernel` draws this host's arrangement under root — and a capability without
/// `urn:cap:kernel:inspect` is refused, naming the scope and the endpoint that declares it.
#[test]
fn the_kernel_diagram_answers_under_root_and_is_refused_without_inspect() {
    let home = scratch("cli");
    let out = run(&home, &["-c", "source urn:diagram:kernel"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(stdout.starts_with("<svg"), "{stdout}");
    assert!(stdout.contains("role=\"img\""), "accessible root: {stdout}");

    let out = run(
        &home,
        &[
            "-c",
            "cap urn:cap:net:example.org",
            "-c",
            "source urn:diagram:kernel",
        ],
    );
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("does not grant `urn:cap:kernel:inspect`")
            && stderr.contains("urn:diagram:kernel"),
        "{stderr}"
    );
    assert!(!text(&out.stdout).contains("<svg"), "nothing was drawn");

    let out = run(
        &home,
        &[
            "-c",
            "cap urn:cap:kernel:inspect",
            "-c",
            "source urn:diagram:kernel",
        ],
    );
    assert!(text(&out.stdout).contains("<svg"), "{}", text(&out.stderr));
}

/// `urn:diagram:arrangement` draws a DECLARED arrangement by name: here an `.arrangement` file
/// in the workspace, which the kernel transrepts to Turtle on the way in.
#[test]
fn the_arrangement_diagram_draws_a_declaration_file() {
    let home = scratch("file");
    std::fs::write(
        home.join("files").join("game.arrangement"),
        "(endpoints (door \"urn:host:demo\" host-demo))\n",
    )
    .unwrap();
    let out = run(
        &home,
        &[
            "-c",
            "source urn:diagram:arrangement of=urn:file:game.arrangement",
        ],
    );
    let stdout = text(&out.stdout);
    assert!(stdout.starts_with("<svg"), "{stdout}{}", text(&out.stderr));
    assert!(
        stdout.contains("urn:host:demo") && stdout.contains("host-demo"),
        "{stdout}"
    );
}

/// The MCP tool names `ikigai mcp` projects under `scopes` (none = root).
fn mcp_tools(home: &Path, scopes: &[&str]) -> Vec<String> {
    let mut args = vec!["mcp"];
    for scope in scopes {
        args.extend(["--scope", scope]);
    }
    let mut child = command(home, &args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("ikigai mcp starts");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n")
        .expect("request written");
    // Dropping stdin closes it: the server answers the one request and exits at EOF.
    let out = child.wait_with_output().expect("ikigai mcp exits");
    let reply = text(&out.stdout);
    let line = reply
        .lines()
        .find(|line| line.contains("\"tools\""))
        .unwrap_or_else(|| panic!("no tools/list reply: {reply}"));
    let value: serde_json::Value = serde_json::from_str(line).expect("a JSON-RPC reply");
    value["result"]["tools"]
        .as_array()
        .expect("a tool list")
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_string))
        .collect()
}

/// ★ The manifold is the tool list: `diagram-kernel` is projected only where the session's
/// capability holds `urn:cap:kernel:inspect`, and `diagram-arrangement` (which declares no
/// scope — it reads `of` under the caller's own) everywhere.
#[test]
fn mcp_projects_the_kernel_diagram_only_where_inspect_holds() {
    let home = scratch("mcp");
    let kernel = "diagram-kernel__source".to_string();
    let arrangement = "diagram-arrangement__source".to_string();

    let root = mcp_tools(&home, &[]);
    assert!(
        root.contains(&kernel) && root.contains(&arrangement),
        "{root:?}"
    );

    let narrow = mcp_tools(&home, &["urn:cap:net:example.org"]);
    assert!(!narrow.contains(&kernel), "{narrow:?}");
    assert!(narrow.contains(&arrangement), "{narrow:?}");

    let inspect = mcp_tools(&home, &["urn:cap:kernel:inspect"]);
    assert!(inspect.contains(&kernel), "{inspect:?}");
}
