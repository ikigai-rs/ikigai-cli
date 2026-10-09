//! The host's Lisp through the REAL binary (ledger #920): the `lisp.*` keys are validated at
//! start-up, the root's governor interrupts a runaway at `lisp.timeout`, and the REPL's Lisp is
//! ikigai-lisp 0.2's allowlist with nothing widened.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `config_home.rs`: the config home is named by
//! `--config-home`, and `HOME`, `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set on the spawned
//! process only.
#![cfg(all(feature = "embedded", unix))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// A scratch tree whose `config/` is the config home, holding `config_toml`.
fn scratch(case: &str, config_toml: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-lisp-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config")).expect("config home");
    std::fs::create_dir_all(dir.join("files")).expect("scratch workspace");
    std::fs::write(dir.join("config").join("config.toml"), config_toml).expect("config.toml");
    dir
}

fn command(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .arg("--config-home")
        .arg(home.join("config"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("decoy"))
        .env("IKIGAI_FILES", home.join("files"))
        .env_remove("IKIGAI_GRANTS")
        .stdin(Stdio::null());
    command
}

fn run(home: &Path, args: &[&str]) -> Output {
    command(home, args)
        .output()
        .expect("the binary under test runs")
}

/// [`run`] with a watchdog: a child still running at `patience` is killed and the test fails
/// saying so, rather than hanging the suite — which is what an ungoverned runaway does.
// Native-only (a spawned process): the wall clock is the watchdog's deadline.
#[allow(clippy::disallowed_methods)]
fn run_within(home: &Path, args: &[&str], patience: Duration) -> Output {
    let mut child = command(home, args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary under test starts");
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if child.try_wait().expect("the child can be polled").is_some() {
            return child.wait_with_output().expect("the child's output");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("still running after {patience:?}: nothing stopped the eval");
}

fn both(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A misspelled bound, a bad value, or one given twice stops the host before any mode runs,
/// naming the key: a bound that silently reads as its default is the failure a bound exists to
/// prevent.
#[test]
fn a_bad_lisp_line_stops_every_mode_at_start_up() {
    for (case, line, says) in [
        (
            "unknown",
            "lisp.worker = 3",
            "`lisp.worker` is not a Lisp setting",
        ),
        ("zero", "lisp.timeout = 0", "`lisp.timeout = 0`"),
        (
            "garbage",
            "lisp.max_nesting = \"deep\"",
            "`lisp.max_nesting = deep`",
        ),
        (
            "twice",
            "lisp.workers = 2\nlisp.workers = 4",
            "`lisp.workers` is set twice",
        ),
    ] {
        let home = scratch(case, &format!("{line}\n"));
        let out = run(&home, &["-e", "(+ 1 2)"]);
        assert_eq!(out.status.code(), Some(2), "{case}: {}", both(&out));
        assert!(both(&out).contains(says), "{case}: {}", both(&out));
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains('3'),
            "{case}: nothing evaluated: {}",
            both(&out)
        );
    }
}

/// ★ The root's governor stops a runaway in the REPL's own Lisp (`-e` is the REPL's seam to
/// `urn:lisp:eval`). Before ledger #920 nothing dropped an embedded eval, so this program held
/// its worker until the process exited.
#[test]
// Native-only (a spawned process): the wall clock measures when the governor fired.
#[allow(clippy::disallowed_methods)]
fn a_runaway_in_the_repl_s_lisp_is_stopped_at_lisp_timeout() {
    let home = scratch("runaway", "lisp.timeout = 3\n");
    let started = Instant::now();
    let out = run_within(
        &home,
        &["-e", "(define (spin n) (spin (+ n 1))) (spin 0)"],
        Duration::from_secs(60),
    );
    let took = started.elapsed();
    let said = both(&out);
    assert!(
        said.contains("urn:lisp:eval` exceeded 3000ms"),
        "the governor's Timeout names the door and the budget: {said}"
    );
    assert!(
        took < Duration::from_secs(60),
        "stopped by the governor, not by something slower: {took:?}"
    );
}

/// The REPL's Lisp is the sandbox's allowlist, unwidened (the decision is in the README):
/// arithmetic and the verbs answer, `display` is refused as unavailable to a program.
#[test]
fn the_repl_s_lisp_is_the_allowlist_with_nothing_widened() {
    let home = scratch("allowlist", "");
    let out = run(&home, &["-e", "(+ 1 2)"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains('3'),
        "{}",
        both(&out)
    );
    let out = run(&home, &["-e", "(display \"hi\")"]);
    assert!(
        both(&out).contains("is not available to a program"),
        "`display` is refused: {}",
        both(&out)
    );
}
