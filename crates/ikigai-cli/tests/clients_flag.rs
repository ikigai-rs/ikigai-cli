//! The client enrollment file is named by `--clients` or found in the config home. A set
//! `IKIGAI_CLIENTS` stops startup, and a `--clients` naming a file that is not there stops the
//! door, through the real binary.
//!
//! Hermetic by the child's environment, as `airlock_enrollment.rs` is: `HOME`,
//! `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set on each spawned process only.
#![cfg(all(feature = "embedded", feature = "quic", unix))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const FINGERPRINT: &str = "6f1c00000000000000000000000000000000000000000000000000000000abcd";

/// How long a door gets to stop or to print its banner before the test decides it will not.
const PATIENCE: Duration = Duration::from_secs(30);

fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-cf-{}-{case}", std::process::id()));
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

fn certs(home: &Path) -> String {
    let dir = home.join("certs");
    let dir = dir.to_str().unwrap().to_string();
    let out = command(home, &["cert", "generate", "--dir", &dir])
        .output()
        .expect("the binary runs");
    assert!(out.status.success(), "{}", stderr(&out));
    dir
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn enrollment() -> String {
    format!(r#"{{"clients": {{"{FINGERPRINT}": "reader"}}}}"#)
}

/// The grants file every enrollment here names, and a valid enrollment in the config home.
fn enroll_in_config_home(home: &Path) {
    std::fs::write(
        config_home(home).join("grants.json"),
        r#"{"reader": ["urn:cap:personal:contacts:read"]}"#,
    )
    .unwrap();
    std::fs::write(config_home(home).join("clients.json"), enrollment()).unwrap();
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

/// The door must have stopped at start, saying `says`.
fn assert_stopped(outcome: Door, says: &[&str]) -> Option<i32> {
    match outcome {
        Door::Stopped(code, written) => {
            assert_ne!(code, Some(0), "{written}");
            for part in says {
                assert!(written.contains(part), "no `{part}` in: {written}");
            }
            code
        }
        Door::Serving(written) => panic!("the door started: {written}"),
    }
}

/// The door the variable must stop, with a good enrollment in the config home it names.
fn quic_door<'a>(certs: &'a str, config: &'a str) -> Vec<&'a str> {
    vec![
        "--config-home",
        config,
        "serve",
        "quic://127.0.0.1:0",
        "--cert-dir",
        certs,
    ]
}

/// A set variable stops the door before it reads any enrollment: a path that is not there, an
/// empty value, and either of them beside an explicit `--clients`.
#[test]
fn a_set_clients_variable_stops_the_door() {
    let home = scratch("variable");
    enroll_in_config_home(&home);
    let certs = certs(&home);
    let config = config_home(&home);
    let config = config.to_str().unwrap();
    let missing = home.join("no-such-clients.json");
    let flag_file = home.join("flag-clients.json");
    std::fs::write(&flag_file, enrollment()).unwrap();
    for value in [missing.to_str().unwrap(), ""] {
        for explicit in [false, true] {
            let mut args = quic_door(&certs, config);
            if explicit {
                args.extend(["--clients", flag_file.to_str().unwrap()]);
            }
            let mut door_command = command(&home, &args);
            door_command.env("IKIGAI_CLIENTS", value);
            let code = assert_stopped(
                door(door_command, &home, "serving on"),
                &["IKIGAI_CLIENTS", "--clients <file>"],
            );
            assert_eq!(code, Some(2), "value `{value}`, explicit {explicit}");
        }
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// The refusal is the host's, not the QUIC door's: a local mode stops on it too, and
/// `--version` still answers.
#[test]
fn a_set_clients_variable_stops_every_mode_but_version() {
    let home = scratch("modes");
    let out = command(&home, &["-c", "list"])
        .env("IKIGAI_CLIENTS", "")
        .output()
        .expect("the binary runs");
    let error = stderr(&out);
    assert_eq!(out.status.code(), Some(2), "{error}");
    assert!(error.contains("IKIGAI_CLIENTS"), "{error}");
    assert!(error.contains("--clients <file>"), "{error}");

    let out = command(&home, &["--version"])
        .env("IKIGAI_CLIENTS", "")
        .output()
        .expect("the binary runs");
    assert!(out.status.success(), "{}", stderr(&out));
    let _ = std::fs::remove_dir_all(&home);
}

/// An explicit file that is not there stops the door. A missing `clients.json` in the config
/// home stops it too, unless `--allow-unenrolled` asks for the shared posture.
#[test]
fn a_clients_flag_naming_a_missing_file_stops_the_door() {
    let home = scratch("missing");
    let certs = certs(&home);
    let missing = home.join("no-such-clients.json");
    let missing = missing.to_str().unwrap();
    let args = [
        "serve",
        "quic://127.0.0.1:0",
        "--cert-dir",
        &certs,
        "--clients",
        missing,
    ];
    assert_stopped(
        door(command(&home, &args), &home, "serving on"),
        &["--clients", missing],
    );

    // The config home's own file is required by default: this door stops.
    let args = ["serve", "quic://127.0.0.1:0", "--cert-dir", &certs];
    assert_stopped(
        door(command(&home, &args), &home, "serving on"),
        &["clients.json", "--allow-unenrolled"],
    );
    // And starts when the shared posture is asked for by name.
    let args = [
        "serve",
        "quic://127.0.0.1:0",
        "--cert-dir",
        &certs,
        "--allow-unenrolled",
    ];
    assert!(matches!(
        door(command(&home, &args), &home, "per-client workspaces"),
        Door::Serving(_)
    ));
    let _ = std::fs::remove_dir_all(&home);
}

/// The flag names the file the door reads, ahead of the config home's, whose broken
/// `clients.json` would otherwise stop it. Before or after `serve`, as `--grants` is.
#[test]
fn a_clients_flag_is_read_ahead_of_the_config_home() {
    let home = scratch("flag");
    enroll_in_config_home(&home);
    std::fs::write(config_home(&home).join("clients.json"), "{ invalid JSON").unwrap();
    let certs = certs(&home);
    let file = home.join("flag-clients.json");
    std::fs::write(&file, enrollment()).unwrap();
    let file = file.to_str().unwrap();
    let after = [
        "serve",
        "quic://127.0.0.1:0",
        "--cert-dir",
        &certs,
        "--clients",
        file,
    ];
    let before = [
        "--clients",
        file,
        "serve",
        "quic://127.0.0.1:0",
        "--cert-dir",
        &certs,
    ];
    for args in [&after, &before] {
        assert!(matches!(
            door(
                command(&home, args),
                &home,
                "per-identity grants: 1 enrolled"
            ),
            Door::Serving(_)
        ));
    }

    // And a broken file at the flag stops it, naming that file.
    let broken = home.join("broken-clients.json");
    std::fs::write(&broken, "{ invalid JSON").unwrap();
    let broken = broken.to_str().unwrap();
    let args = [
        "serve",
        "quic://127.0.0.1:0",
        "--cert-dir",
        &certs,
        "--clients",
        broken,
    ];
    assert_stopped(door(command(&home, &args), &home, "serving on"), &[broken]);
    let _ = std::fs::remove_dir_all(&home);
}

/// A token is bound to an enrolled participant, so `layers-token` reads the same file the door
/// was told to.
#[test]
fn layers_token_reads_the_clients_flag() {
    let home = scratch("token");
    let file = home.join("flag-clients.json");
    std::fs::write(&file, enrollment()).unwrap();
    let file = file.to_str().unwrap();
    let out = command(
        &home,
        &["--clients", file, "layers-token", "mint", FINGERPRINT],
    )
    .output()
    .expect("the binary runs");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!String::from_utf8_lossy(&out.stdout).trim().is_empty());
    let _ = std::fs::remove_dir_all(&home);
}

/// A mode that reads no enrollment refuses the flag rather than ignoring it.
#[test]
fn a_mode_that_reads_no_enrollment_refuses_the_flag() {
    let home = scratch("refused");
    let file = home.join("flag-clients.json");
    std::fs::write(&file, enrollment()).unwrap();
    let file = file.to_str().unwrap();
    let socket = home.join("door.sock");
    let socket = socket.to_str().unwrap();
    for args in [
        vec!["-c", "list", "--clients", file],
        vec!["serve", socket, "--clients", file],
        vec!["serve", "--http", "127.0.0.1:0", "--clients", file],
        vec!["mcp", "--grant", "reader", "--clients", file],
    ] {
        let out = command(&home, &args).output().expect("the binary runs");
        let error = stderr(&out);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {error}");
        assert!(
            error.contains("--clients applies to `serve quic://"),
            "{args:?}: {error}"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// A missing value names what the flag wants.
#[test]
fn the_clients_flag_names_a_file_in_its_refusal() {
    let home = scratch("value");
    for args in [vec!["serve", "--clients"], vec!["--clients=", "serve"]] {
        let out = command(&home, &args).output().expect("the binary runs");
        let error = stderr(&out);
        assert_eq!(out.status.code(), Some(2), "{error}");
        assert!(error.contains("--clients needs <file>"), "{error}");
    }
    let _ = std::fs::remove_dir_all(&home);
}
