//! The REPL's "why" views through the REAL binary (ledger #908): `show` writes the picture and
//! prints where, `explain`/`why`/`dependents` answer the same over `--connect` as in process.
//!
//! The engine's own tests pin each view against a constructed kernel (`ikigai-engine`,
//! `engine/why.rs`). This file pins what an operator sees: the file viewer the binary hands the
//! engine, and that the views are remote-transparent — sourced from a serving door, over its
//! socket, with nothing of their own.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `host_posture.rs`: `HOME`, `XDG_CONFIG_HOME`,
//! `IKIGAI_FILES` and `TMPDIR` (where `show` writes) are set on the spawned process only, and the
//! scratch config home says `show.opener = "none"`, so no test opens a window.
#![cfg(all(feature = "embedded", feature = "ipc", unix))]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

/// A bounded wait for the IPC socket (see `host_posture.rs` for why a count and a gap).
const TRIES: usize = 1800;
const GAP: Duration = Duration::from_millis(50);

/// A child killed when the test ends, whatever the test does.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch home whose config home turns the opener off.
fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-wv-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config = dir.join("config").join("ikigai");
    std::fs::create_dir_all(&config).expect("scratch config home");
    std::fs::create_dir_all(dir.join("files")).expect("scratch workspace");
    std::fs::create_dir_all(dir.join("tmp")).expect("scratch temp dir");
    std::fs::write(config.join("config.toml"), "show.opener = \"none\"\n")
        .expect("scratch config.toml");
    dir
}

fn command(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .env("TMPDIR", home.join("tmp"));
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

/// `show` writes the SVG into the temporary directory, prints the path, opens nothing when
/// the config home says so, and refuses a resource with no picture face without writing.
#[test]
fn show_writes_the_picture_and_prints_where() {
    let home = scratch("show");
    let out = run(&home, &["-c", "show urn:diagram:kernel"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        stdout.contains("not opened (show.opener = none)"),
        "{stdout}"
    );
    let path = stdout
        .split_whitespace()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("no path in: {stdout}"));
    assert!(
        path.starts_with(home.join("tmp")) || path.starts_with(home.canonicalize().unwrap()),
        "written under TMPDIR: {}",
        path.display()
    );
    let svg = std::fs::read_to_string(&path).expect("the picture was written");
    assert!(
        svg.starts_with("<svg") && svg.contains("role=\"img\""),
        "{svg}"
    );

    let out = run(&home, &["-c", "show urn:host:info"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("no picture face"), "{stderr}");
    let written = std::fs::read_dir(home.join("tmp")).unwrap().count();
    assert_eq!(written, 1, "a refusal writes nothing");
}

/// ★ Remote-transparent: a `--connect` session explains, asks why and lists dependents on the
/// SERVING kernel, through its socket — the views are names, so nothing about them is local.
#[test]
fn the_views_answer_over_a_socket() {
    let home = scratch("ipc");
    // A SHORT socket path: `sockaddr_un` fits 104 bytes on macOS (field guide 9h).
    let sock = format!("/tmp/iki-wv-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&sock);
    let _door = Door(
        command(&home, &["serve", &sock])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the door starts"),
    );
    let mut bound = false;
    for _ in 0..TRIES {
        if Path::new(&sock).exists() {
            bound = true;
            break;
        }
        std::thread::sleep(GAP);
    }
    assert!(bound, "`{sock}` was never bound");

    let out = run(
        &home,
        &[
            "--connect",
            &sock,
            "--plain",
            "-c",
            "source urn:host:info",
            "-c",
            "explain urn:host:info",
            "-c",
            "why urn:host:info",
            "-c",
            "dependents urn:kernel:bindings",
            "-c",
            "explain urn:nothing:bound:here",
        ],
    );
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("explain source urn:host:info"), "{stdout}");
    assert!(stdout.contains("endpoint    host-info"), "{stdout}");
    assert!(stdout.contains("why urn:host:info"), "{stdout}");
    // The served host's read of `urn:host:info` is uncacheable, and its log says so.
    assert!(stdout.contains("declared  [root]"), "{stdout}");
    assert!(
        stdout.contains("dependents of urn:kernel:bindings"),
        "{stdout}"
    );
    assert!(
        stdout.contains("unresolved: nothing in the chain answers this name"),
        "{stdout}"
    );
    let _ = std::fs::remove_file(&sock);
}
