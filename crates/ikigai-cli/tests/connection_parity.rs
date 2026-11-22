//! Connection-mode parity (ledger #4039): ONE fixed set of call shapes, run against every way
//! the cli reaches a kernel, and the same answer asserted for each, through the REAL binary
//! and a real QUIC hub on a port it binds itself (the harness of `connect_retry.rs`).
//!
//! The class this prevents is ledger #4037. The connect-retry tests checked the retry with an
//! argument-free read, so `--connect` under a `connect.retry.*` policy, whose issuer had no
//! Meta renderer, passed CI while every named argument was routed as text. A mode tested with
//! one shape is a mode tested for that shape only; here every mode gets every shape.
//!
//! - [`SHAPES`] are the calls: an argument-free Source, a named argument, a positional value,
//!   a pipe into a Source, a Sink with content (read back), a saved script given named
//!   parameters, and a `-c` batch whose stdin fills the one required argument.
//! - [`MODES`] are the ways in: in-process, a `--mount` of the hub, `--connect` to the hub,
//!   and `--connect` with `connect.retry.*` set.
//!
//! A new mode or transport is ONE row in [`MODES`]; it then runs every shape. A new shape is
//! one row in [`SHAPES`]; every mode then runs it. A shape names its targets with `{ns}`,
//! which a mode fills with the prefix its kernel reaches the hub's names by (`urn:` in
//! process and over `--connect`, `urn:hub:` through the mount).
//!
//! The modes run side by side, each with its own home and hub, and a failure lists EVERY cell
//! (mode and shape) that answered wrong, not only the first.
#![cfg(all(feature = "embedded", feature = "quic", unix))]

mod support;

use std::io::Write;
use std::path::PathBuf;
use std::process::{Output, Stdio};

use support::{generate, peer, scratch, spawn, text_of, Door, CONNECT_POLICY};

/// One call, as a person would make it, and the answer every mode must give.
struct Shape {
    name: &'static str,
    /// The `-c` commands, in order, with `{ns}` for the target prefix.
    commands: &'static [&'static str],
    /// What the client's stdin holds; `None` is `/dev/null`.
    stdin: Option<&'static str>,
    /// A saved `.iki` script (its text, with `{ns}`) and the parameters it is run with,
    /// instead of `commands`.
    script: Option<(&'static str, &'static [&'static str])>,
    /// The last line the client writes on stdout (a Sink's own report names the workspace it
    /// wrote to, which is the mode's; the read after it is the answer).
    answer: &'static str,
}

const SHAPES: &[Shape] = &[
    Shape {
        name: "an argument-free Source",
        commands: &["source {ns}demo:greeter"],
        stdin: None,
        script: None,
        answer: "Hello from the ikigai kernel.",
    },
    Shape {
        name: "a named argument",
        // Routed by name, `in` holds `hello`. Routed as text (no contract read), the word
        // fails open to `in` whole and the answer is `IN=HELLO` (ledger #4037).
        commands: &["source {ns}iki:fn:toUpper in=hello"],
        stdin: None,
        script: None,
        answer: "HELLO",
    },
    Shape {
        name: "two named arguments",
        // Neither is `in`: with no contract both stay text and the call is refused.
        commands: &["source {ns}tz:convert in=2026-01-01T12:00:00Z to=Asia/Tokyo"],
        stdin: None,
        script: None,
        answer: "2026-01-01T21:00:00+09:00",
    },
    Shape {
        name: "a positional value",
        commands: &["source {ns}iki:fn:toUpper hello"],
        stdin: None,
        script: None,
        answer: "HELLO",
    },
    Shape {
        name: "a pipe into a Source",
        commands: &["source {ns}iki:fn:toUpper hi | {ns}demo:wrap"],
        stdin: None,
        script: None,
        answer: "[HI]",
    },
    Shape {
        name: "a Sink with content",
        // `{mode}` keeps the file the mode's own, so a mode whose Sink wrote nothing cannot
        // read back what another mode wrote to the same hub workspace.
        commands: &[
            "sink {ns}file:parity-{mode}.txt written",
            "source {ns}file:parity-{mode}.txt",
        ],
        stdin: None,
        script: None,
        answer: "written",
    },
    Shape {
        name: "a saved script with named parameters",
        commands: &[],
        stdin: None,
        script: Some((
            "# @param word\nsource {ns}iki:fn:toUpper in={word}\n",
            &["word=quiet"],
        )),
        answer: "QUIET",
    },
    Shape {
        name: "a -c batch whose stdin fills the one required argument",
        commands: &["source {ns}iki:fn:toUpper"],
        stdin: Some("piped\n"),
        script: None,
        answer: "PIPED",
    },
];

/// How the client reaches the hub's kernel.
#[derive(Clone, Copy)]
enum Reach {
    /// No hub: the client's own in-process kernel answers.
    InProcess,
    /// `--mount urn:hub:=<hub>`: the in-process kernel forwards `urn:hub:*` to the hub.
    Mount,
    /// `--connect <hub>`: the client's REPL drives the hub's kernel.
    Connect,
}

/// One way the cli reaches a kernel.
struct Mode {
    /// Short and path-safe: it names the scratch home, which holds no socket here but is kept
    /// short like every home of this harness.
    tag: &'static str,
    reach: Reach,
    /// The client's `config.toml`.
    config: &'static str,
}

const MODES: &[Mode] = &[
    Mode {
        tag: "inproc",
        reach: Reach::InProcess,
        config: "",
    },
    Mode {
        tag: "mount",
        reach: Reach::Mount,
        config: "",
    },
    Mode {
        tag: "connect",
        reach: Reach::Connect,
        config: "",
    },
    Mode {
        tag: "cretry",
        reach: Reach::Connect,
        config: CONNECT_POLICY,
    },
];

/// A mode made live: its scratch home and, unless it is in-process, the hub it reaches.
struct Live {
    mode: &'static Mode,
    home: PathBuf,
    certs: PathBuf,
    hub: Option<(Door, String)>,
}

impl Live {
    fn start(mode: &'static Mode) -> Live {
        let home = scratch(&format!("par-{}", mode.tag));
        std::fs::create_dir_all(home.join("files")).expect("scratch workspace");
        std::fs::write(
            home.join("config").join("ikigai").join("config.toml"),
            mode.config,
        )
        .expect("config.toml");
        let certs = generate(&home);
        let hub = match mode.reach {
            Reach::InProcess => None,
            Reach::Mount | Reach::Connect => {
                Some(peer(&home, &certs, "quic://127.0.0.1:0", "hub").expect("the hub serves"))
            }
        };
        Live {
            mode,
            home,
            certs,
            hub,
        }
    }

    /// The prefix this mode's kernel reaches the hub's names by.
    fn ns(&self) -> &'static str {
        match self.mode.reach {
            Reach::InProcess | Reach::Connect => "urn:",
            Reach::Mount => "urn:hub:",
        }
    }

    fn fill(&self, template: &str) -> String {
        template
            .replace("{ns}", self.ns())
            .replace("{mode}", self.mode.tag)
    }

    /// Run `shape` through this mode's client.
    fn call(&self, shape: &Shape) -> Output {
        let address = self.hub.as_ref().map(|(_, address)| address.as_str());
        let certs = self.certs.to_str().unwrap().to_string();
        let mut args: Vec<String> = Vec::new();
        match (self.mode.reach, address) {
            (Reach::InProcess, _) => {}
            (Reach::Mount, Some(address)) => {
                args.extend(["--mount".into(), format!("urn:hub:={address}")]);
                args.extend(["--cert-dir".into(), certs]);
            }
            (Reach::Connect, Some(address)) => {
                args.extend(["--connect".into(), address.to_string()]);
                args.extend(["--cert-dir".into(), certs]);
            }
            _ => unreachable!("a mode that reaches a hub has one"),
        }
        args.push("--plain".into());
        match shape.script {
            Some((text, parameters)) => {
                let script = self.home.join(format!("{}.iki", self.mode.tag));
                std::fs::write(&script, self.fill(text)).expect("the script");
                args.extend(["--script".into(), script.to_str().unwrap().to_string()]);
                args.extend(parameters.iter().map(|p| p.to_string()));
            }
            None => {
                for command in shape.commands {
                    args.extend(["-c".into(), self.fill(command)]);
                }
            }
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut command = spawn(&self.home, &args);
        command
            .current_dir(&self.home)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match shape.stdin {
            None => command
                .stdin(Stdio::null())
                .output()
                .expect("the client runs"),
            Some(text) => {
                let mut child = command
                    .stdin(Stdio::piped())
                    .spawn()
                    .expect("the client starts");
                let mut stdin = child.stdin.take().expect("piped stdin");
                stdin
                    .write_all(text.as_bytes())
                    .expect("the client's stdin");
                drop(stdin);
                child.wait_with_output().expect("the client runs")
            }
        }
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        // The hub first: it serves out of this home.
        self.hub.take();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// Run every shape in [`SHAPES`] through `mode`, and describe each shape whose answer was not
/// the shape's.
fn wrong_answers(mode: &'static Mode) -> Vec<String> {
    let live = Live::start(mode);
    let mut wrong = Vec::new();
    for shape in SHAPES {
        let out = live.call(shape);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let last = stdout.lines().rev().find(|line| !line.trim().is_empty());
        if !out.status.success() || last.map(str::trim) != Some(shape.answer) {
            wrong.push(format!(
                "- mode `{}`, {} (exit {:?}): expected `{}`, got:\n{}",
                mode.tag,
                shape.name,
                out.status.code(),
                shape.answer,
                text_of(&out)
            ));
        }
    }
    wrong
}

/// The matrix: every mode, each on its own thread with its own home and hub, runs every shape,
/// and the test fails with every cell that answered wrong.
#[test]
fn every_mode_answers_every_shape_the_same() {
    let modes: Vec<_> = MODES
        .iter()
        .map(|mode| (mode.tag, std::thread::spawn(move || wrong_answers(mode))))
        .collect();
    let mut wrong = Vec::new();
    for (tag, mode) in modes {
        match mode.join() {
            Ok(cells) => wrong.extend(cells),
            Err(_) => wrong.push(format!("- mode `{tag}` panicked before it answered")),
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} cells answered wrong:\n{}",
        wrong.len(),
        MODES.len() * SHAPES.len(),
        wrong.join("\n")
    );
}
