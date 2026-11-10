//! A grants file the door cannot use stops it at start: a QUIC door whose grants file does not
//! parse, or whose enrollment names a grant the file does not define (or defines with no
//! scopes), and any host started with a `--grants` naming a file that is not there.
//!
//! Hermetic by the child's environment, as `clients_flag.rs` is: `HOME`, `XDG_CONFIG_HOME` and
//! `IKIGAI_FILES` are set on each spawned process only.
#![cfg(all(feature = "embedded", unix))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// How long a door gets to stop or to print its banner before the test decides it will not.
const PATIENCE: Duration = Duration::from_secs(30);

fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-gf-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(config_home(&dir)).expect("scratch config home");
    dir
}

fn config_home(home: &Path) -> PathBuf {
    home.join("config").join("ikigai")
}

fn command(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .env_remove("IKIGAI_CLIENTS")
        .env_remove("IKIGAI_GRANTS")
        .stdin(Stdio::null());
    command
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

enum Door {
    /// It exited: its code and what it wrote to stderr.
    Stopped(Option<i32>, String),
    /// It printed `banner` and was still running, so the test ended it.
    Serving(String),
}

/// Run a door until it stops or prints `banner`, and end it if it is still up.
fn door(mut command: Command, home: &Path, banner: &str) -> Door {
    let log = home.join("door.err");
    let mut child = command
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .expect("the binary runs");
    let read = || std::fs::read_to_string(&log).unwrap_or_default();
    #[allow(clippy::disallowed_methods)] // a native test's own deadline; never built for wasm
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Door::Stopped(status.code(), read());
        }
        if read().contains(banner) || started.elapsed() > PATIENCE {
            let _ = child.kill();
            let _ = child.wait();
            let written = read();
            assert!(
                written.contains(banner),
                "the door neither stopped nor said `{banner}`: {written}"
            );
            return Door::Serving(written);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The door must have stopped at start, saying each of `says`.
fn assert_stopped(outcome: Door, says: &[&str]) {
    match outcome {
        Door::Stopped(code, written) => {
            // A refusal, not a crash: the door exits with a code of its own.
            assert!(matches!(code, Some(c) if c != 0), "{code:?}: {written}");
            for part in says {
                assert!(written.contains(part), "no `{part}` in: {written}");
            }
        }
        Door::Serving(written) => panic!("the door started: {written}"),
    }
}

#[cfg(feature = "quic")]
mod quic {
    use super::*;

    const FINGERPRINT: &str = "6f1c00000000000000000000000000000000000000000000000000000000abcd";

    fn certs(home: &Path) -> String {
        let dir = home.join("certs");
        let dir = dir.to_str().unwrap().to_string();
        let out = command(home, &["cert", "generate", "--dir", &dir])
            .output()
            .expect("the binary runs");
        assert!(out.status.success(), "{}", stderr(&out));
        dir
    }

    /// A config home enrolling one client under the grant `reader`, with `grants` (if any) as
    /// its grants file.
    fn enrolled(case: &str, grants: Option<&str>) -> PathBuf {
        let home = scratch(case);
        std::fs::write(
            config_home(&home).join("clients.json"),
            format!(r#"{{"clients": {{"{FINGERPRINT}": "reader"}}}}"#),
        )
        .unwrap();
        if let Some(grants) = grants {
            std::fs::write(config_home(&home).join("grants.json"), grants).unwrap();
        }
        home
    }

    fn quic_door(home: &Path, certs: &str, extra: &[&str]) -> Door {
        let mut args = vec!["serve", "quic://127.0.0.1:0", "--cert-dir", certs];
        args.extend(extra);
        door(command(home, &args), home, "serving on")
    }

    /// The control: a grants file defining the enrolled grant opens the door.
    #[test]
    fn a_usable_grants_file_opens_the_door() {
        let home = enrolled(
            "usable",
            Some(r#"{"reader": ["urn:cap:personal:contacts:read"]}"#),
        );
        let certs = certs(&home);
        assert!(matches!(
            quic_door(&home, &certs, &[]),
            Door::Serving(written) if written.contains("per-identity grants")
        ));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_grants_file_that_does_not_parse_stops_the_door() {
        let home = enrolled("malformed", Some("{ \"reader\": [ not json"));
        let certs = certs(&home);
        let file = config_home(&home).join("grants.json");
        assert_stopped(
            quic_door(&home, &certs, &[]),
            &[file.to_str().unwrap(), "does not parse"],
        );
        // Valid JSON that is not an object of grants is no grants file either.
        std::fs::write(&file, r#"["urn:cap:personal:contacts:read"]"#).unwrap();
        assert_stopped(
            quic_door(&home, &certs, &[]),
            &[file.to_str().unwrap(), "object"],
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// An enrolled grant the file does not define, defines with no scopes, or a grants file
    /// that is not there at all: every client under it would be refused, so the door stops.
    #[test]
    fn an_enrolled_grant_that_resolves_to_nothing_stops_the_door() {
        for (case, grants) in [
            ("unknown", Some(r#"{"writer": ["urn:cap:fs:write:notes"]}"#)),
            ("empty", Some(r#"{"reader": []}"#)),
            ("empty-object", Some(r#"{"reader": {"show": ["*"]}}"#)),
            ("no-file", None),
        ] {
            let home = enrolled(case, grants);
            let certs = certs(&home);
            assert_stopped(quic_door(&home, &certs, &[]), &["`reader`", "grants.json"]);
            let _ = std::fs::remove_dir_all(&home);
        }
    }

    #[test]
    fn a_grants_flag_naming_a_missing_file_stops_the_quic_door() {
        let home = enrolled(
            "flag",
            Some(r#"{"reader": ["urn:cap:personal:contacts:read"]}"#),
        );
        let certs = certs(&home);
        let missing = home.join("no-such-grants.json");
        let missing = missing.to_str().unwrap();
        assert_stopped(
            quic_door(&home, &certs, &["--grants", missing]),
            &["--grants", missing],
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}

/// The socket door reads the grants file for the accounts it admits: an explicit `--grants`
/// that is not there stops it rather than serving as though no file was named.
#[cfg(feature = "ipc")]
#[test]
fn a_grants_flag_naming_a_missing_file_stops_the_socket_door() {
    let home = scratch("socket");
    let missing = home.join("no-such-grants.json");
    let missing = missing.to_str().unwrap();
    let socket = home.join("door.sock");
    let args = [
        "--grants",
        missing,
        "serve",
        socket.to_str().unwrap(),
        "--no-config-mounts",
    ];
    assert_stopped(
        door(command(&home, &args), &home, "serving on"),
        &["--grants", missing],
    );
    // The control: with no `--grants`, the config home's absent grants.json is no account
    // table, and the door serves its own user.
    let args = ["serve", socket.to_str().unwrap(), "--no-config-mounts"];
    assert!(matches!(
        door(command(&home, &args), &home, "serving on"),
        Door::Serving(_)
    ));
    let _ = std::fs::remove_dir_all(&home);
}

/// Every host reads the flag, so every mode but `--version` refuses a missing one.
#[test]
fn a_grants_flag_naming_a_missing_file_stops_a_local_mode() {
    let home = scratch("modes");
    let missing = home.join("no-such-grants.json");
    let missing = missing.to_str().unwrap();
    let out = command(&home, &["--grants", missing, "-c", "list"])
        .output()
        .expect("the binary runs");
    let error = stderr(&out);
    assert_eq!(out.status.code(), Some(2), "{error}");
    assert!(error.contains("--grants"), "{error}");
    assert!(error.contains(missing), "{error}");

    let out = command(&home, &["--grants", missing, "--version"])
        .output()
        .expect("the binary runs");
    assert!(out.status.success(), "{}", stderr(&out));
    let _ = std::fs::remove_dir_all(&home);
}
