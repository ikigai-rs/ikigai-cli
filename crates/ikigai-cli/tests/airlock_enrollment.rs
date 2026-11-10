//! The booking airlock with per-drainer enrollment (ledger #1826), through the REAL binary.
//!
//! The edge's drain door ran `serve quic://… --cap urn:cap:space:read --cap urn:cap:space:take
//! --cap urn:cap:space:out` with no `clients.json`, so every certificate on its trust list got
//! that one shared ceiling over every space. It now runs the same ceiling with
//! `--require-enrollment`: each drainer is enrolled in `clients.json` under its own grant, the
//! `--cap` ceiling clamps every grant (it never replaces one), a drainer with no entry is
//! refused, and the door will not start without the file.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `quic_principals.rs` is: `HOME`,
//! `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set on each spawned process only, and the door binds
//! port 0 and the test reads the bound port off its banner (field guide 9h).
#![cfg(all(feature = "embedded", feature = "quic", unix))]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long a door gets to print its banner. A watchdog, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

/// The airlock's ceiling, exactly as the edge's unit sets it.
const CEILING: [&str; 6] = [
    "--cap",
    "urn:cap:space:read",
    "--cap",
    "urn:cap:space:take",
    "--cap",
    "urn:cap:space:out",
];

/// A child killed when the test ends, whatever the test does.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-ae-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(config_home(&dir)).expect("scratch config home");
    dir
}

fn config_home(home: &Path) -> PathBuf {
    home.join("config").join("ikigai")
}

fn spawn(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .env_remove("IKIGAI_CLIENTS")
        .env_remove("IKIGAI_GRANTS");
    command
}

fn run(home: &Path, args: &[&str]) -> Output {
    spawn(home, args)
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs")
}

fn ok(out: Output, what: &str) -> String {
    assert!(
        out.status.success(),
        "{what} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// The airlock's certificate set: the server pair, the base client (the host that drains it)
/// and `extra` drainers under `clients/`.
fn certs(home: &Path, extra: &[&str]) -> PathBuf {
    let dir = home.join("certs");
    let d = dir.to_str().unwrap();
    ok(
        run(home, &["cert", "generate", "--dir", d]),
        "cert generate",
    );
    for name in extra {
        ok(
            run(home, &["cert", "add-client", name, "--cert-dir", d]),
            "cert add-client",
        );
    }
    dir
}

fn fingerprint(cert: &Path) -> String {
    let pem = std::fs::read_to_string(cert).expect("the client certificate");
    ikigai_quic::fingerprint_of_pem(&pem).expect("a certificate")
}

/// `serve quic://127.0.0.1:0 --cert-dir <certs> <extra…>`: the door and its banner.
fn serve(home: &Path, certs: &Path, extra: &[&str]) -> (Door, String) {
    let mut args = vec![
        "serve",
        "quic://127.0.0.1:0",
        "--cert-dir",
        certs.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let mut child = spawn(home, &args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the door starts");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut seen = String::new();
        let mut lines = BufReader::new(stderr).lines().map_while(Result::ok);
        for line in lines.by_ref() {
            seen.push_str(&line);
            seen.push('\n');
            if line.contains("serving on") {
                break;
            }
        }
        let _ = tx.send(seen);
        lines.for_each(drop);
    });
    let door = Door(child);
    let seen = rx
        .recv_timeout(PATIENCE)
        .unwrap_or_else(|e| panic!("`{args:?}` never printed its banner: {e}"));
    (door, seen)
}

fn target(banner: &str) -> String {
    banner
        .lines()
        .find_map(|line| line.split("serving on ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no address in the banner:\n{banner}"))
        .to_string()
}

/// Run `command` against the door as the client `name` (`None`: the base client).
fn as_client(home: &Path, certs: &Path, name: Option<&str>, target: &str, command: &str) -> Output {
    let dir = certs.to_str().unwrap().to_string();
    let mut args = vec!["--cert-dir".to_string(), dir.clone()];
    if let Some(name) = name {
        args.extend([
            "--client-cert".to_string(),
            format!("{dir}/clients/{name}.crt"),
            "--client-key".to_string(),
            format!("{dir}/clients/{name}.key"),
        ]);
    }
    args.extend(
        ["--connect", target, "--plain", "-c", command]
            .iter()
            .map(|s| s.to_string()),
    );
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    run(home, &argv)
}

fn describe(out: &Output) -> String {
    format!(
        "status {}: {}{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// `--require-enrollment` with no `clients.json` stops the door at start, naming the file: an
/// airlock must never fall back to the shared ceiling because a file went missing.
#[test]
fn a_door_that_requires_enrollment_will_not_start_without_it() {
    let home = scratch("absent");
    let certs = certs(&home, &[]);
    let mut args = vec![
        "serve",
        "quic://127.0.0.1:0",
        "--cert-dir",
        certs.to_str().unwrap(),
        "--require-enrollment",
    ];
    args.extend_from_slice(&CEILING);
    let out = run(&home, &args);
    assert!(!out.status.success(), "{}", describe(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("clients.json") && stderr.contains("--require-enrollment"),
        "{stderr}"
    );
    // And a door that is not a QUIC door refuses the flag rather than ignoring it.
    let sock = format!("/tmp/iki-ae-{}.sock", std::process::id());
    let out = run(&home, &["serve", &sock, "--require-enrollment"]);
    assert!(!out.status.success(), "{}", describe(&out));
    let _ = std::fs::remove_dir_all(&home);
}

/// The airlock's whole shape, per drainer: the host drains as before under its own grant; a
/// drainer whose grant reaches past the ceiling is clamped to it; a narrower grant narrows; and
/// a trusted certificate with no entry is refused.
///
/// The `wide` grant's personal scope also pins the surface: a scope the ceiling takes away
/// must not switch a face on. Before, it turned this door into the calendar-only kernel, and
/// the host's first drop answered `no endpoint resolved for urn:space:bookings`.
#[test]
fn each_drainer_gets_its_own_grant_under_the_ceiling() {
    let home = scratch("drain");
    let certs = certs(&home, &["wide", "peeker", "stranger"]);
    let fp = |file: &str| fingerprint(&certs.join(file));
    std::fs::write(
        config_home(&home).join("grants.json"),
        r#"{
            "drain": ["urn:cap:space:read", "urn:cap:space:take", "urn:cap:space:out"],
            "wide": ["urn:cap:space:read", "urn:cap:space:take", "urn:cap:space:out",
                     "urn:cap:personal:calendar:read:detail"],
            "peek": ["urn:cap:space:read"]
        }"#,
    )
    .unwrap();
    std::fs::write(
        config_home(&home).join("clients.json"),
        format!(
            r#"{{"clients": {{
                "{}": {{"grant": "drain", "label": "the host"}},
                "{}": {{"grant": "wide", "label": "wide"}},
                "{}": {{"grant": "peek", "label": "peeker"}}
            }}}}"#,
            fp("client.crt"),
            fp("clients/wide.crt"),
            fp("clients/peeker.crt"),
        ),
    )
    .unwrap();
    let mut extra = vec!["--name", "edge", "--require-enrollment"];
    extra.extend_from_slice(&CEILING);
    let (_door, banner) = serve(&home, &certs, &extra);
    assert!(banner.contains("per-identity grants"), "{banner}");
    let target = target(&banner);
    let ask = |name: Option<&str>, command: &str| as_client(&home, &certs, name, &target, command);

    // The host: drop, peek and take, as bug's drain does.
    let id = ok(ask(None, "sink urn:space:bookings a-booking"), "drop")
        .trim()
        .to_string();
    assert_eq!(id.len(), 64, "a tuple id: {id}");
    assert!(ok(ask(None, "source urn:space:bookings"), "peek").contains(&id));

    // The peeker reads, and may not take.
    assert!(ok(
        ask(Some("peeker"), "source urn:space:bookings"),
        "peeker peeks"
    )
    .contains(&id));
    let took = ask(Some("peeker"), &format!("delete urn:space:bookings {id}"));
    assert!(
        !took.status.success() || !String::from_utf8_lossy(&took.stdout).contains("a-booking"),
        "a read-only grant must not take: {}",
        describe(&took)
    );

    // The wide grant is clamped to the ceiling: three scopes, not four.
    let identity = ok(
        ask(Some("wide"), "source urn:host:identity"),
        "wide identity",
    );
    assert!(
        identity.contains("3 scopes"),
        "the ceiling clamps a grant that reaches past it: {identity}"
    );

    // The host takes it.
    assert_eq!(
        ok(
            ask(None, &format!("delete urn:space:bookings {id}")),
            "take"
        )
        .trim(),
        "a-booking"
    );

    // A trusted certificate with no entry is refused.
    let refused = ask(Some("stranger"), "source urn:space:bookings");
    assert!(
        !refused.status.success(),
        "a drainer that is not enrolled must be refused: {}",
        describe(&refused)
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// Enrollment is required by default: a QUIC door with no `clients.json` and no flag stops at
/// start, naming the file and the opt-out, with `--cap` or without it. It never opens to every
/// trusted certificate because the file is missing.
#[test]
fn a_door_with_no_enrollment_will_not_start_by_default() {
    let home = scratch("default");
    let certs = certs(&home, &[]);
    let c = certs.to_str().unwrap();
    for extra in [&[][..], &CEILING[..]] {
        let mut args = vec!["serve", "quic://127.0.0.1:0", "--cert-dir", c];
        args.extend_from_slice(extra);
        let out = run(&home, &args);
        assert!(!out.status.success(), "{}", describe(&out));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("clients.json") && stderr.contains("--allow-unenrolled"),
            "{stderr}"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// `--allow-unenrolled` is the opt-out: the door starts in the shared posture and says so on
/// its own line, distinct from the banner. It cannot be given with `--require-enrollment`, nor
/// to a door that is not a QUIC door.
#[test]
fn a_door_that_allows_unenrolled_clients_says_so() {
    let home = scratch("optout");
    let certs = certs(&home, &[]);
    let (_door, banner) = serve(&home, &certs, &["--allow-unenrolled"]);
    assert!(banner.contains("per-client workspaces"), "{banner}");
    assert!(
        banner.contains("warning:") && banner.contains("--allow-unenrolled"),
        "{banner}"
    );
    let (_door, banner) = serve(
        &home,
        &certs,
        &["--allow-unenrolled", "--cap", "urn:cap:space:read"],
    );
    assert!(banner.contains("fixed ceiling"), "{banner}");
    assert!(banner.contains("warning:"), "{banner}");

    let c = certs.to_str().unwrap();
    let both = [
        "serve",
        "quic://127.0.0.1:0",
        "--cert-dir",
        c,
        "--allow-unenrolled",
        "--require-enrollment",
    ];
    let out = run(&home, &both);
    assert!(!out.status.success(), "{}", describe(&out));
    let sock = format!("/tmp/iki-ae-u-{}.sock", std::process::id());
    let out = run(&home, &["serve", &sock, "--allow-unenrolled"]);
    assert!(!out.status.success(), "{}", describe(&out));
    let _ = std::fs::remove_dir_all(&home);
}
