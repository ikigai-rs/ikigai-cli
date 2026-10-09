//! `--config-home <dir>` through the REAL binary (ledger #919): every door reads its config
//! home from the flag, the flag wins over `XDG_CONFIG_HOME`, and a relative directory is made
//! absolute.
//!
//! Before the flag, a scratch run needed `XDG_CONFIG_HOME`, against the rule that the config
//! home plus flags is the channel and an environment variable is not. Each case below sets the
//! environment to a DIFFERENT config home (the decoy) than the flag names, so a door that read
//! the environment instead of the flag fails visibly rather than by luck.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `host_posture.rs`: `HOME`, `XDG_CONFIG_HOME`
//! and `IKIGAI_FILES` are set on the spawned process only.
#![cfg(all(feature = "embedded", unix))]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// A watchdog against a hang, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

/// A child killed when the test ends, whatever the test does.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch tree: `flag/` is the config home the flag names (holding `files`), `decoy/ikigai/`
/// is the one the environment names, holding a `config.toml` the flag must hide.
fn scratch(case: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-ch-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("flag")).expect("the flag's config home");
    std::fs::create_dir_all(dir.join("decoy").join("ikigai")).expect("the decoy config home");
    std::fs::create_dir_all(dir.join("files")).expect("scratch workspace");
    std::fs::write(
        dir.join("decoy").join("ikigai").join("config.toml"),
        "keybindings = \"vi\"\nmount = \"prefer urn:decoy:=/tmp/iki-ch-decoy.sock\"\n",
    )
    .expect("decoy config.toml");
    for (name, body) in files {
        std::fs::write(dir.join("flag").join(name), body).expect("flag config file");
    }
    dir
}

fn command(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("decoy"))
        .env("IKIGAI_FILES", home.join("files"))
        .env_remove("IKIGAI_GRANTS");
    command
}

fn run(home: &Path, args: &[&str]) -> Output {
    command(home, args)
        .output()
        .expect("the binary under test runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The engine's settings (`config`) and the host's (`mount` lines, read by `urn:host:posture`)
/// both come from the flag's directory, and the decoy's are not seen.
#[test]
fn the_repl_reads_the_flag_s_config_home_and_not_the_environment_s() {
    let home = scratch(
        "repl",
        &[(
            "config.toml",
            "keybindings = \"emacs\"\nmount = \"prefer urn:flagged:=/tmp/iki-ch-flag.sock\"\n",
        )],
    );
    let flag = home.join("flag");
    let out = run(
        &home,
        &[
            "--config-home",
            flag.to_str().unwrap(),
            "--plain",
            "-c",
            "config",
            "-c",
            "source urn:host:posture",
        ],
    );
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(
        stdout.contains(&format!(
            "config file: {}",
            flag.join("config.toml").display()
        )),
        "{stdout}"
    );
    assert!(stdout.contains("keybindings = emacs"), "{stdout}");
    assert!(
        stdout.contains("urn:flagged:"),
        "the host's mount: {stdout}"
    );
    assert!(
        !stdout.contains("urn:decoy:"),
        "the decoy is hidden: {stdout}"
    );
}

/// A relative directory is made absolute against the working directory, and a write lands
/// there (the `=` spelling, after the command, works the same).
#[test]
fn a_relative_config_home_is_absolutized_and_written_there() {
    let home = scratch("relative", &[]);
    let out = run(
        &home,
        &["-c", "config keybindings=vi", "--config-home=flag/./nested"],
    );
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    // The child's working directory is the CANONICAL path (macOS's temp dir sits behind the
    // `/var` -> `/private/var` symlink), so that is what a relative flag is joined to.
    let written = home
        .canonicalize()
        .expect("the scratch home exists")
        .join("flag")
        .join("nested")
        .join("config.toml");
    assert!(
        stdout.contains(&format!("(saved to {})", written.display())),
        "the reported path is absolute and has no `.`: {stdout}"
    );
    assert!(std::fs::read_to_string(&written)
        .expect("written under the flag's directory")
        .contains("keybindings = \"vi\""));
}

#[test]
fn a_doubled_or_empty_config_home_refuses_to_start() {
    let home = scratch("refuse", &[]);
    let out = run(
        &home,
        &["--config-home", "/a", "--config-home", "/b", "-c", "list"],
    );
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("a process has one config home"));
    let out = run(&home, &["-c", "list", "--config-home"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("--config-home needs <dir>"));
}

/// `mcp` reads `grants.json` from the flag's config home: the decoy has none, so a door that
/// read the environment would refuse the grant.
#[test]
fn mcp_reads_its_grants_from_the_flag_s_config_home() {
    let home = scratch(
        "mcp",
        &[("grants.json", "{\"reader\": [\"urn:cap:nothing:much\"]}\n")],
    );
    let flag = home.join("flag");
    let mut child = command(
        &home,
        &[
            "mcp",
            "--grant",
            "reader",
            "--no-config-mounts",
            "--config-home",
            flag.to_str().unwrap(),
        ],
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("mcp starts");
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        let _ = writeln!(
            stdin,
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}"
        );
    }
    let out = child.wait_with_output().expect("mcp is reaped");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("\"tools\""),
        "{}",
        text(&out.stdout)
    );
}

/// `serve` composes the topology the flag's config home declares, and says so in its banner.
#[test]
fn serve_composes_the_flag_s_topology() {
    let home = scratch(
        "serve",
        &[(
            "config.toml",
            "mount = \"prefer urn:flagged:=/tmp/iki-ch-absent.sock\"\n",
        )],
    );
    let flag = home.join("flag");
    // A SHORT socket path: `sockaddr_un` fits 104 bytes on macOS (field guide 9h).
    let sock = format!("/tmp/iki-ch-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&sock);
    let mut child = command(
        &home,
        &["serve", &sock, "--config-home", flag.to_str().unwrap()],
    )
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .spawn()
    .expect("the door starts");
    let stderr = child.stderr.take().expect("piped stderr");
    let _door = Door(child);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut seen = String::new();
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let done = line.contains("serving on");
            seen.push_str(&line);
            seen.push('\n');
            if done {
                break;
            }
        }
        let _ = tx.send(seen);
    });
    let banner = rx
        .recv_timeout(PATIENCE)
        .expect("the door printed its banner");
    assert!(banner.contains("urn:flagged:"), "{banner}");
    assert!(!banner.contains("urn:decoy:"), "{banner}");
    let _ = std::fs::remove_file(&sock);
}
