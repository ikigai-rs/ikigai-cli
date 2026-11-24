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
//! - [`MODES`] are the ways in: in-process, a `--mount` of the hub, the same mount with
//!   `connect.retry.*` set, `--connect` to the hub, and `--connect` with `connect.retry.*` set.
//!
//! A new mode or transport is ONE row in [`MODES`]; it then runs every shape. A new shape is
//! one row in [`SHAPES`]; every mode then runs it. A shape names its targets with `{ns}`,
//! which a mode fills with the prefix its kernel reaches the hub's names by (`urn:` in
//! process and over `--connect`, `urn:hub:` through the mount).
//!
//! The modes run side by side, each with its own home and hub, and a failure lists EVERY cell
//! (mode and shape) that answered wrong, not only the first.
//!
//! The peer down (ledger #4084): every mode with a peer (all but in-process) runs a named
//! argument in one REPL session, the hub killed between two calls. A hub that stays down is
//! the transport's error, in the call's `error:` line and in the contract note, never
//! "declares no arguments"; under the policy, both after its attempts. A hub back within the
//! policy answers the call routed by its contract, through a mount as over `--connect`,
//! because the cli retries the contract read above the kernel
//! (`ikigai_embedded::retry::MetaRetry`; ledger #4084 for `--connect`, ledger #4161 for a
//! mount).
#![cfg(all(feature = "embedded", feature = "quic", unix))]

mod support;

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use support::{
    generate, hub_back_after, peer, scratch, spawn, text_of, Door, CONNECT_POLICY, PATIENCE,
};

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
        tag: "mretry",
        reach: Reach::Mount,
        config: CONNECT_POLICY,
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
        Live::start_in(mode, "par")
    }

    /// [`start`](Self::start), its home named `<case>-<tag>`, so cases running side by side
    /// in one process never share one.
    fn start_in(mode: &'static Mode, case: &str) -> Live {
        let home = scratch(&format!("{case}-{}", mode.tag));
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

    /// The arguments that make the client reach the hub at `address` this mode's way.
    fn reach_args(&self, address: Option<&str>) -> Vec<String> {
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
        args
    }

    /// Run `shape` through this mode's client.
    fn call(&self, shape: &Shape) -> Output {
        let address = self.hub.as_ref().map(|(_, address)| address.as_str());
        let mut args = self.reach_args(address);
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

/// The call the peer-down case makes: a named argument, the shape whose routing needs the
/// target's contract (with no contract, `in=hello` goes to `in` whole and the answer is
/// `IN=HELLO`, ledger #4037).
const NAMED: &str = "source {ns}iki:fn:toUpper in=hello";

/// What the client wrote after the hub went down, and how it exited.
struct Outage {
    /// The client's stdout lines after the hub was killed.
    after: Vec<String>,
    /// Everything it wrote on stderr.
    stderr: String,
    status: std::process::ExitStatus,
}

impl Outage {
    fn text(&self) -> String {
        format!("{}\n{}", self.after.join("\n"), self.stderr)
    }
}

/// One session of `mode`'s client, a `--quiet` REPL on a piped stdin: [`NAMED`] while the
/// hub is up, then the hub killed and [`NAMED`] again, with the hub brought back on the same
/// address after `back_after` (or never), and stdin closed so the client exits once it has
/// answered.
fn through_an_outage(mode: &'static Mode, back_after: Option<Duration>) -> Outage {
    let case = if back_after.is_some() { "back" } else { "down" };
    let mut live = Live::start_in(mode, case);
    let (hub, address) = live.hub.take().expect("a mode that reaches a hub has one");
    let mut args = live.reach_args(Some(&address));
    args.push("--quiet".into());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut client = spawn(&live.home, &args)
        .current_dir(&live.home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the client starts");
    let mut stdin = client.stdin.take().expect("piped stdin");
    let stdout = client.stdout.take().expect("piped stdout");
    let mut stderr = client.stderr.take().expect("piped stderr");
    let (tx, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let errors = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    // Killed when the case ends, a panic included.
    let mut client = Door(client);
    let call = live.fill(NAMED);
    writeln!(stdin, "{call}").expect("the first call");
    loop {
        match lines.recv_timeout(PATIENCE) {
            Ok(line) if line.trim() == "HELLO" => break,
            Ok(_) => continue,
            Err(e) => panic!("mode `{}`: no answer while the hub was up ({e})", mode.tag),
        }
    }
    drop(hub);
    let back = back_after.map(|delay| hub_back_after(&live.home, &live.certs, &address, delay));
    writeln!(stdin, "{call}").expect("the second call");
    drop(stdin);
    // The policy's limit is a minute for the contract read and a minute for the call: this
    // is a watchdog, not a measurement.
    let mut after = Vec::new();
    loop {
        match lines.recv_timeout(Duration::from_secs(240)) {
            Ok(line) => after.push(line),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("mode `{}`: the client never finished: {after:?}", mode.tag)
            }
        }
    }
    let status = client.0.wait().expect("the client exits");
    let stderr = errors.join().unwrap_or_default();
    // The hub that came back, if it did, lives until here.
    drop(back.map(|back| back.recv_timeout(PATIENCE)));
    Outage {
        after,
        stderr,
        status,
    }
}

/// The modes with a peer to lose: every mode but in-process, which reaches no hub.
fn modes_with_a_peer() -> impl Iterator<Item = &'static Mode> {
    MODES
        .iter()
        .filter(|mode| !matches!(mode.reach, Reach::InProcess))
}

/// The peer down for good (ledger #4084): in every mode that has a peer, a named-argument
/// call answers the transport's own error, the contract read too, and never "declares no
/// arguments" or an answer routed without the contract. Under the policy that is after its
/// attempts, as the typed `GaveUp`.
#[test]
fn a_peer_down_answers_the_transport_error_in_every_mode() {
    let modes: Vec<_> = modes_with_a_peer()
        .map(|mode| {
            (
                mode,
                std::thread::spawn(move || through_an_outage(mode, None)),
            )
        })
        .collect();
    let mut wrong = Vec::new();
    for (mode, outage) in modes {
        let Ok(outage) = outage.join() else {
            wrong.push(format!("- mode `{}` panicked before it answered", mode.tag));
            continue;
        };
        let text = outage.text();
        let mut fault = |what: &str| {
            wrong.push(format!("- mode `{}`: {what}, got:\n{text}", mode.tag));
        };
        if outage.status.success() {
            fault("the client exits nonzero after the failed call");
        }
        if text.contains("declares no arguments") {
            fault("the contract read is never the empty placeholder");
        }
        if outage
            .after
            .iter()
            .any(|line| matches!(line.trim(), "HELLO" | "IN=HELLO"))
        {
            fault("a call to a dead peer answers nothing");
        }
        if !text
            .lines()
            .any(|line| line.starts_with("error:") && line.contains("quic transport"))
        {
            fault("the call answers the transport's error");
        }
        if !text.lines().any(|line| {
            line.contains("contract unavailable for") && line.contains("quic transport")
        }) {
            fault("the contract read answers the transport's error");
        }
        if !mode.config.is_empty()
            && !text.lines().any(|line| {
                line.contains("contract unavailable for") && line.contains("gave up after")
            })
        {
            fault("under the policy, the contract read is retried before it fails");
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The peer down for longer than one contract read, then back within the policy (ledger
/// #4084 for `--connect`, ledger #4161 for a mount): the contract read is retried under
/// `connect.retry.*` as the call is, so the named argument is routed by the contract and the
/// call answers as if the hub had never left. Without that retry the contract read failed at
/// once, the word went to `in` as text, and the retried call answered `IN=HELLO`.
#[test]
fn a_peer_back_within_the_policy_routes_the_named_argument() {
    let modes: Vec<_> = MODES
        .iter()
        .filter(|mode| !mode.config.is_empty())
        .map(|mode| {
            (
                mode,
                // Longer than a dial's own timeout (5 s), so the first contract read fails.
                std::thread::spawn(move || through_an_outage(mode, Some(Duration::from_secs(20)))),
            )
        })
        .collect();
    assert_eq!(modes.len(), 2, "a mount and a --connect under the policy");
    let mut wrong = Vec::new();
    for (mode, outage) in modes {
        let Ok(outage) = outage.join() else {
            wrong.push(format!("- mode `{}` panicked before it answered", mode.tag));
            continue;
        };
        let text = outage.text();
        let mut fault = |what: &str| {
            wrong.push(format!("- mode `{}`: {what}, got:\n{text}", mode.tag));
        };
        if !outage.status.success() {
            fault("the client exits 0");
        }
        if !outage.after.iter().any(|line| line.trim() == "HELLO") {
            fault("the call answers by its contract once the hub is back");
        }
        if outage.after.iter().any(|line| line.trim() == "IN=HELLO") {
            fault("never routed without the contract");
        }
        if text.contains("contract unavailable for") {
            fault("the contract was read");
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
