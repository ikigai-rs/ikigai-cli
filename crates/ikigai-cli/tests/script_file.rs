//! A `.iki` script through the REAL binary (ledger #2649): `ikigai <file>.iki key=value`, the
//! `--script` flag a shebang line names, and the REPL's `script <iri>` command. The script
//! format is ikigai-engine's (ledger #2485); what is pinned here is the host's half: the
//! parameters reach the script, an undeclared one is refused before any line runs, a failing
//! line stops the run with a non-zero exit and `error: line N: …`, and a shebang runs the file.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `scripted_session.rs`: `HOME`,
//! `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set on the spawned process only, and stdin is
//! `/dev/null` unless a test pipes the REPL its lines.
#![cfg(all(feature = "embedded", unix))]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Greets `who`; `greeting` has a default.
const GREET: &str = "\
#!/usr/bin/env -S ikigai --quiet --script
# Greets someone.
# @param who
# @param greeting = hello
source urn:iki:fn:toUpper \"{greeting}, {who}\"
";

/// Line 1 writes a file, line 2 fails, line 3 would write another.
const STOPS: &str = "\
sink urn:file:one.txt first
source urn:nope:missing
sink urn:file:three.txt third
";

fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-script-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    std::fs::create_dir_all(dir.join("files")).expect("scratch workspace");
    dir
}

fn write(path: &Path, text: &str) {
    std::fs::write(path, text).expect("write the script");
}

fn ikigai(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn run(mut command: Command) -> Output {
    command.output().expect("run ikigai")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn parameters_reach_the_script_and_a_default_fills_the_rest() {
    let home = scratch("params");
    write(&home.join("greet.iki"), GREET);

    let out = run(ikigai(&home, &["--quiet", "greet.iki", "who=brian smith"]));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "HELLO, BRIAN SMITH\n");
    assert_eq!(stderr(&out), "", "--quiet prints only the answers");

    let out = run(ikigai(&home, &["greet.iki", "who=ann", "greeting=hi"]));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "HI, ANN\n");
    assert!(
        stderr(&out).contains("[computed]"),
        "without --quiet a line's cache note goes to stderr: {}",
        stderr(&out)
    );
}

#[test]
fn an_undeclared_or_missing_parameter_is_refused_before_any_line_runs() {
    let home = scratch("undeclared");
    write(&home.join("greet.iki"), GREET);

    let out = run(ikigai(&home, &["greet.iki", "who=brian", "whom=brian"]));
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "", "no line ran");
    assert!(
        stderr(&out).contains("error: the script declares no parameter `whom`"),
        "{}",
        stderr(&out)
    );

    let out = run(ikigai(&home, &["greet.iki"]));
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert!(
        stderr(&out).contains("`who` has no default"),
        "{}",
        stderr(&out)
    );

    // A flag after the file is one of its words, not a flag.
    let out = run(ikigai(&home, &["greet.iki", "who=brian", "--quiet"]));
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("`--quiet` is not a parameter"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_failing_line_two_stops_before_line_three_with_a_non_zero_exit() {
    let home = scratch("stops");
    write(&home.join("stops.iki"), STOPS);

    let out = run(ikigai(&home, &["--quiet", "stops.iki"]));
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).starts_with("error: line 2: "),
        "the failure names its line: {}",
        stderr(&out)
    );
    assert!(home.join("files").join("one.txt").exists(), "line 1 ran");
    assert!(
        !home.join("files").join("three.txt").exists(),
        "line 3 must not run after line 2 failed"
    );
}

#[test]
fn a_script_with_a_shebang_runs_as_a_program() {
    use std::os::unix::fs::PermissionsExt;

    let home = scratch("shebang");
    let script = home.join("greet");
    write(&script, GREET);
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    // `/usr/bin/env -S ikigai …` finds the binary under test on PATH.
    let bin = Path::new(env!("CARGO_BIN_EXE_ikigai"))
        .parent()
        .expect("the binary's directory");
    let path = std::env::join_paths(std::iter::once(bin.to_path_buf()).chain(
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
    ))
    .expect("PATH");

    // A file being written can still be open for writing in a child another test thread is
    // forking, so the exec may briefly see ETXTBSY ("text file busy"); try again then.
    let mut attempts = 0;
    let out = loop {
        let mut command = Command::new(&script);
        command
            .arg("who=sam")
            .current_dir(&home)
            .env("PATH", &path)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("IKIGAI_FILES", home.join("files"))
            .stdin(Stdio::null());
        match command.output() {
            Err(e) if e.raw_os_error() == Some(26) && attempts < 50 => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            result => break result.expect("run the script as a program"),
        }
    };
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "HELLO, SAM\n");
    assert_eq!(stderr(&out), "", "the shebang passes --quiet");
}

#[test]
fn the_repl_runs_a_stored_script_by_name_and_carries_on() {
    let home = scratch("repl");
    write(&home.join("files").join("greet.iki"), GREET);
    write(&home.join("files").join("stops.iki"), STOPS);

    let mut child = ikigai(&home, &["--quiet"])
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn ikigai");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(
            b"script urn:file:greet.iki who=\"brian smith\"\n\
              script urn:file:stops.iki\n\
              source urn:iki:fn:toUpper after\n",
        )
        .expect("write the session");
    let out = child.wait_with_output().expect("reap ikigai");

    assert_eq!(
        stdout(&out),
        "HELLO, BRIAN SMITH\nwrote 5 bytes to one.txt\nAFTER\n",
        "both scripts' answers, up to the failing line, then the REPL's next line"
    );
    assert!(
        stderr(&out).contains("error: line 2: "),
        "the stored script's failure names its line: {}",
        stderr(&out)
    );
    assert!(!home.join("files").join("three.txt").exists());
    // The REPL continues after a failed line and exits 1 at its end, as for any failure.
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn a_c_batch_runs_a_stored_script_too() {
    let home = scratch("batch");
    write(&home.join("files").join("greet.iki"), GREET);

    let out = run(ikigai(&home, &["-c", "script urn:file:greet.iki who=ann"]));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "HELLO, ANN\n");

    let out = run(ikigai(&home, &["-c", "script urn:file:absent.iki"]));
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("error: cannot read the script urn:file:absent.iki"),
        "{}",
        stderr(&out)
    );
}
