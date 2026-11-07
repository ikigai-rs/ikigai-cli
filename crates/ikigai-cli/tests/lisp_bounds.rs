//! The host's Lisp through the REAL binary (ledger #920): the `lisp.*` keys are validated at
//! start-up, the root's governor interrupts a runaway at `lisp.timeout`, and the REPL's Lisp is
//! ikigai-lisp 0.2's allowlist with nothing widened.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `config_home.rs`: the config home is named by
//! `--config-home`, and `HOME`, `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set on the spawned
//! process only.
#![cfg(all(feature = "embedded", unix))]

use std::io::Read;
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

/// How much CPU the runaway's process may burn beyond its budget before the test calls the
/// governor broken: start-up, the kernel and the Steel engine builds, each well under a second
/// of CPU in a debug build. Generous on purpose: it bounds how long a BROKEN governor takes to
/// fail, never how fast a working one must be.
const CPU_SLACK: Duration = Duration::from_secs(30);

/// A guard against a child that neither finishes nor burns CPU (stopped, starved, or waiting on
/// the OS to scan a freshly linked binary). It keeps the suite from hanging forever and is NOT a
/// verdict on the governor, which is judged by CPU alone (see [`run_governed`]).
const HANG_GUARD: Duration = Duration::from_secs(600);

/// The CPU time `pid` has used so far, from `ps -o time=`: `[[dd-]hh:]mm:ss.ss` on macOS,
/// `[dd-]hh:mm:ss` on Linux. `None` once the process is gone.
fn cpu_time(pid: u32) -> Option<Duration> {
    let out = Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let text = text.trim();
    if !out.status.success() || text.is_empty() {
        return None;
    }
    let (days, clock) = match text.split_once('-') {
        Some((days, clock)) => (days.parse::<f64>().ok()?, clock),
        None => (0.0, text),
    };
    let mut seconds = 0.0;
    for part in clock.split(':') {
        seconds = seconds * 60.0 + part.parse::<f64>().ok()?;
    }
    Some(Duration::from_secs_f64(days * 86_400.0 + seconds))
}

/// Run the binary under a runaway's watchdog that does not depend on how fast the machine is.
///
/// A runaway that nothing stops burns CPU without end; one the governor stops burns at most its
/// budget of spinning (the governor's clock is wall time, and one thread spins). So the verdict
/// is the child's own CPU time: past `budget` + [`CPU_SLACK`] the governor did not fire, the
/// child is killed and the test fails saying so. Load cannot fake that, because a loaded
/// machine gives the child LESS CPU per second, never more. Wall time feeds only
/// [`HANG_GUARD`]. Before ledger #1696 this was a 60 s wall-clock deadline from spawn, which a
/// loaded machine could spend before the eval even began and then report as "nothing stopped
/// the eval".
///
/// stdout and stderr are drained on their own threads, so a chatty child cannot block on a full
/// pipe while the watchdog waits for it to exit.
// Native-only (a spawned process): the wall clock bounds only the hang guard.
#[allow(clippy::disallowed_methods)]
fn run_governed(home: &Path, args: &[&str], budget: Duration) -> Output {
    let mut child = command(home, args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary under test starts");
    fn drain(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            bytes
        })
    }
    let stdout = drain(child.stdout.take().expect("piped stdout"));
    let stderr = drain(child.stderr.take().expect("piped stderr"));
    let collect = |status| Output {
        status,
        stdout: stdout.join().expect("stdout drained"),
        stderr: stderr.join().expect("stderr drained"),
    };
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("the child can be polled") {
            return collect(status);
        }
        let burned = cpu_time(child.id());
        let verdict = match burned {
            Some(cpu) if cpu > budget + CPU_SLACK => Some(format!(
                "the runaway burned {cpu:?} of CPU against a {budget:?} budget: the governor \
                 did not stop it"
            )),
            _ if started.elapsed() > HANG_GUARD => Some(format!(
                "the child neither finished nor burned its budget in {HANG_GUARD:?} (CPU so \
                 far: {burned:?}): it stalled, which says nothing about the governor"
            )),
            _ => None,
        };
        if let Some(verdict) = verdict {
            let _ = child.kill();
            let status = child.wait().expect("the killed child is reaped");
            panic!("{verdict}\n{}", both(&collect(status)));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn both(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A fresh account has no XDG data directory. Steel must not add a diagnostic to
/// otherwise successful evaluations, including a second invocation on that account.
#[test]
fn evaluation_is_quiet_with_a_sparse_home() {
    let home = scratch("sparse-home", "");
    assert!(!home.join(".local/share").exists());
    for _ in 0..2 {
        let out = command(&home, &["--quiet", "-e", "(+ 1 2)"])
            .env_remove("STEEL_HOME")
            .env_remove("XDG_DATA_HOME")
            .output()
            .expect("evaluation runs");
        assert!(out.status.success(), "{}", both(&out));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "3");
        assert_eq!(
            String::from_utf8_lossy(&out.stderr).trim(),
            "[uncacheable]",
            "{}",
            both(&out)
        );
    }
    std::fs::remove_dir_all(home).expect("remove scratch home");
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
///
/// What proves it, none of it a speed (ledger #1696): the governor's own `Timeout` names the
/// door and the configured budget; the program's first form wrote `started`, so the program was
/// RUNNING when it was stopped, not a job canceled before it began; and the process came back
/// inside the CPU the budget allows ([`run_governed`]). On a machine so loaded that building the
/// evaluator outlasts the budget, the governor rightly fires before the program starts, which
/// proves nothing about a runaway: the test then tries a larger budget rather than pass on it.
#[test]
fn a_runaway_in_the_repl_s_lisp_is_stopped_at_lisp_timeout() {
    for seconds in [3u64, 12, 48] {
        let home = scratch(
            &format!("runaway-{seconds}"),
            &format!("lisp.timeout = {seconds}\n"),
        );
        let out = run_governed(
            &home,
            &[
                "-e",
                "(sink \"urn:file:started\" \"yes\") (define (spin n) (spin (+ n 1))) (spin 0)",
            ],
            Duration::from_secs(seconds),
        );
        let said = both(&out);
        assert!(
            said.contains(&format!("urn:lisp:eval` exceeded {}ms", seconds * 1000)),
            "the governor's Timeout names the door and the budget: {said}"
        );
        assert!(!out.status.success(), "a stopped eval is a failure: {said}");
        if home.join("files").join("started").exists() {
            return;
        }
        eprintln!(
            "the governor fired before the program started under a {seconds} s budget (a \
             loaded machine building the evaluator); trying a larger one"
        );
    }
    panic!("the program never started inside any budget, so no runaway was ever stopped");
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
