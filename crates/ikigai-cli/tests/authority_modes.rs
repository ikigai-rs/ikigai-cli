//! The QUIC door checks the owner and mode of the files it takes its authority from before it
//! opens: a private key another account could read, or a certificate, trust directory or
//! enrollment file another account could write, stops it, naming the `chmod` to run. Files
//! with the modes `cert generate` writes, and a certificate others may read, keep working.
#![cfg(all(feature = "embedded", feature = "quic", unix))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const FINGERPRINT: &str = "6f1c00000000000000000000000000000000000000000000000000000000abcd";

/// How long a door gets to stop or to print its banner before the test decides it will not.
const PATIENCE: Duration = Duration::from_secs(30);

fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-am-{}-{case}", std::process::id()));
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

fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn serve(home: &Path, certs: &str) -> Door {
    let config = config_home(home);
    let args = [
        "--config-home",
        config.to_str().unwrap(),
        "serve",
        "quic://127.0.0.1:0",
        "--cert-dir",
        certs,
    ];
    door(command(home, &args), home, "serving on")
}

/// Enrolled with safe modes, the door serves; a certificate others may read changes nothing.
#[test]
fn safe_modes_and_a_readable_certificate_serve() {
    let home = scratch("safe");
    enroll_in_config_home(&home);
    let certs = certs(&home);
    assert!(matches!(serve(&home, &certs), Door::Serving(_)));
    chmod(&Path::new(&certs).join("server.crt"), 0o644);
    chmod(&Path::new(&certs).join("client.crt"), 0o644);
    chmod(Path::new(&certs), 0o755);
    assert!(matches!(serve(&home, &certs), Door::Serving(_)));
    let _ = std::fs::remove_dir_all(&home);
}

/// Each loosened mode stops the door at start and names the fix.
#[test]
fn a_loosened_mode_stops_the_door() {
    let home = scratch("loose");
    enroll_in_config_home(&home);
    let certs = certs(&home);
    let base = Path::new(&certs);

    let key = base.join("server.key");
    chmod(&key, 0o644);
    assert_stopped(
        serve(&home, &certs),
        &[&format!("`chmod 600 {}`", key.display())],
    );
    chmod(&key, 0o600);

    let crt = base.join("client.crt");
    chmod(&crt, 0o666);
    assert_stopped(
        serve(&home, &certs),
        &[&format!("`chmod go-w {}`", crt.display())],
    );
    chmod(&crt, 0o600);

    let clients = base.join("clients");
    std::fs::create_dir_all(&clients).unwrap();
    chmod(&clients, 0o777);
    assert_stopped(
        serve(&home, &certs),
        &[&format!("`chmod go-w {}`", clients.display())],
    );
    chmod(&clients, 0o700);

    let tenant = clients.join("tenant.crt");
    std::fs::copy(&crt, &tenant).unwrap();
    chmod(&tenant, 0o622);
    assert_stopped(
        serve(&home, &certs),
        &[&format!("`chmod go-w {}`", tenant.display())],
    );
    std::fs::remove_file(&tenant).unwrap();

    for name in ["clients.json", "grants.json"] {
        let file = config_home(&home).join(name);
        chmod(&file, 0o664);
        assert_stopped(
            serve(&home, &certs),
            &[&format!("`chmod go-w {}`", file.display())],
        );
        chmod(&file, 0o644);
    }

    assert!(matches!(serve(&home, &certs), Door::Serving(_)));
    let _ = std::fs::remove_dir_all(&home);
}
