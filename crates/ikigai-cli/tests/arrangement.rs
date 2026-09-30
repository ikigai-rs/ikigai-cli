//! `--arrangement` through the REAL binary (ledger #637): the local root built from a declared
//! arrangement, named by the flag or by the config home, and every way that must STOP the start
//! instead of falling back to the built-in root.
//!
//! The unit tests in `ikigai-embedded` pin the round trip against constructed roots. This file
//! pins what an operator types: a file on disk, a flag or a config key, and a process that either
//! runs that arrangement or exits saying why — never one that quietly runs the default, which an
//! operator who asked for a declaration could not tell from the one they asked for.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `host_posture.rs`: `HOME`, `XDG_CONFIG_HOME` and
//! `IKIGAI_FILES` are set on the spawned process only, so the developer's config home is never
//! read.
#![cfg(all(feature = "embedded", unix))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ikigai_core::{Door, MatchKind, SpaceKind, Topology};

/// A scratch home for one case, with an empty config home.
fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-arr-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    std::fs::create_dir_all(dir.join("files")).expect("scratch workspace");
    dir
}

/// Run `ikigai <args…>` against `home` and wait for it (`output` waits, so the exit status
/// is the reaped one).
fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .output()
        .expect("the binary under test runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A declaration with ONE door, `urn:host:demo`, bound to the host's own `host-demo` endpoint
/// — so every other name the built-in root answers is gone, which is the observable proof the
/// declaration and not the default is running.
fn one_door() -> String {
    Topology::new(SpaceKind::EndpointSpace {
        doors: vec![Door::new("urn:host:demo", MatchKind::Exact, "host-demo")],
    })
    .to_turtle()
}

/// The flag runs the declaration: its one door answers, a name the built-in root binds does
/// not, and the process says, once, which arrangement it is running.
#[test]
fn the_flag_runs_the_declared_arrangement() {
    let home = scratch("flag");
    std::fs::write(home.join("root.ttl"), one_door()).unwrap();
    let out = run(
        &home,
        &[
            "--arrangement",
            "root.ttl",
            "-c",
            "source urn:host:demo",
            "-c",
            "source urn:host:info",
        ],
    );
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(
        stdout.contains("demo off"),
        "the declared door answers: {stdout}\n{stderr}"
    );
    assert!(
        stderr.contains("no endpoint resolved for urn:host:info"),
        "a door the declaration dropped is not answered: {stderr}"
    );
    assert!(
        stderr.contains("local root arranged from") && stderr.contains("(from the flag)"),
        "{stderr}"
    );
}

/// The config home names it too — relative to the config home — and the host's own resource
/// answers the arrangement it is running, header and all.
#[test]
fn the_config_home_names_it_and_the_host_answers_it() {
    let home = scratch("config");
    let config = home.join("config").join("ikigai");
    std::fs::write(config.join("root.ttl"), one_door()).unwrap();
    std::fs::write(config.join("config.toml"), "arrangement = \"root.ttl\"\n").unwrap();
    let out = run(&home, &["-c", "source urn:iki:host:arrangement"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(stderr.contains("(from the config)"), "{stderr}");
    assert!(
        stdout.contains("# The arrangement this host built its local root from"),
        "{stdout}"
    );
    assert!(stdout.contains("ik:endpointName \"host-demo\""), "{stdout}");
    assert!(
        !stdout.contains("urn:host:info"),
        "only the declared door: {stdout}"
    );
}

/// A declaration that is named and missing stops the start. Exit 2, and the message names
/// the file.
#[test]
fn a_missing_declaration_stops_the_start() {
    let home = scratch("missing");
    let out = run(
        &home,
        &["--arrangement", "absent.ttl", "-c", "source urn:host:demo"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("absent.ttl") && stderr.contains("cannot be read"),
        "{stderr}"
    );
    assert!(!text(&out.stdout).contains("demo off"), "nothing ran");
}

/// A document that is not a declaration stops the start with core's message.
#[test]
fn a_malformed_declaration_stops_the_start() {
    let home = scratch("malformed");
    let odd = one_door().replace("ik:EndpointSpace", "ik:Tunnel");
    std::fs::write(home.join("root.ttl"), odd).unwrap();
    let out = run(
        &home,
        &["--arrangement", "root.ttl", "-c", "source urn:host:demo"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("not a declaration") && stderr.contains("ik:Tunnel"),
        "{stderr}"
    );
}

/// A declaration that parses and does not BUILD stops the start too, with core's message
/// naming the node: here, an endpoint the host never registered.
#[test]
fn an_unbuildable_declaration_stops_the_start() {
    let home = scratch("unbuildable");
    let conjured = Topology::new(SpaceKind::EndpointSpace {
        doors: vec![Door::new("urn:x:y", MatchKind::Exact, "no-such-endpoint")],
    })
    .to_turtle();
    std::fs::write(home.join("root.ttl"), conjured).unwrap();
    let out = run(
        &home,
        &["--arrangement", "root.ttl", "-c", "source urn:x:y"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("`no-such-endpoint`") && stderr.contains("<urn:ikigai:space:_:1:door:1>"),
        "{stderr}"
    );
}

/// ★ The built-in root dumped and fed back is REFUSED on this host, and says why: `file` names
/// two different endpoints (the org-file jail and the workspace jail), so a door naming it cannot
/// say which. Pinned end to end so the day a module gives each its own name, this test is what
/// changes.
#[test]
fn the_dumped_default_is_refused_on_an_ambiguous_name() {
    let home = scratch("dump");
    let dump = run(&home, &["-c", "source urn:iki:host:arrangement"]);
    let turtle = text(&dump.stdout);
    assert!(
        turtle.contains("⚠ Not declarable as it stands: `file`"),
        "{turtle}"
    );
    std::fs::write(home.join("root.ttl"), &turtle).unwrap();
    let out = run(
        &home,
        &["--arrangement", "root.ttl", "-c", "source urn:host:demo"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("binds `file`, which names 2 different endpoints in this host"),
        "{stderr}"
    );
}

/// `--connect` resolves on another kernel, so it builds no local root to arrange: the flag is
/// refused there rather than ignored.
#[test]
fn the_flag_is_refused_where_no_local_root_is_built() {
    let home = scratch("connect");
    std::fs::write(home.join("root.ttl"), one_door()).unwrap();
    let out = run(
        &home,
        &[
            "--arrangement",
            "root.ttl",
            "--connect",
            "/tmp/iki-arr-nobody.sock",
            "-c",
            "source urn:host:demo",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("does not build one"), "{stderr}");
}

// ---------------------------------------------------------------------------------------------
// The s-expression surface: an `.arrangement` file (ikigai-fs 0.1.7 types it
// `text/x-ikigai-arrangement`; ikigai-sexpr 0.1.4 transrepts it to Turtle losslessly).
// ---------------------------------------------------------------------------------------------

/// One arrangement, written by hand as an `.arrangement` file: a NAMED fallback over two
/// endpoint spaces, with a comment the round trip is allowed to drop.
const GAME_ARRANGEMENT: &str = "\
;; Two layers, consulted in order.
(fallback :id \"urn:game:root\"
  (endpoints (door \"urn:host:demo\" host-demo))
  (endpoints (door \"urn:host:info\" host-info)))
";

/// The SAME arrangement, built independently through core's typed tree and rendered as Turtle
/// — not derived from the file above, so agreement between the two is evidence.
fn game_turtle() -> String {
    let mut root = Topology::new(SpaceKind::Fallback)
        .child(Topology::new(SpaceKind::EndpointSpace {
            doors: vec![Door::new("urn:host:demo", MatchKind::Exact, "host-demo")],
        }))
        .child(Topology::new(SpaceKind::EndpointSpace {
            doors: vec![Door::new("urn:host:info", MatchKind::Exact, "host-info")],
        }));
    root.id = Some(ikigai_core::Iri::parse("urn:game:root").unwrap());
    root.to_turtle()
}

/// A document without its leading comment block and the blank line after it: the part of
/// `urn:iki:host:arrangement`'s answer that is the arrangement, not where it came from.
fn body(dump: &str) -> String {
    dump.lines()
        .skip_while(|line| line.starts_with('#') || line.starts_with(";;"))
        .skip_while(|line| line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// ★ The same declaration as Turtle and as `.arrangement` starts the SAME host: the same doors
/// answer, the same door the declaration left out does not, and the host answers the same
/// arrangement back — in Turtle and as an s-expression.
#[test]
fn turtle_and_arrangement_files_start_identical_hosts() {
    let home = scratch("sexpr-same");
    std::fs::write(home.join("game.ttl"), game_turtle()).unwrap();
    std::fs::write(home.join("game.arrangement"), GAME_ARRANGEMENT).unwrap();
    let ask = |file: &str| {
        let out = run(
            &home,
            &[
                "--arrangement",
                file,
                "-c",
                "source urn:host:demo",
                "-c",
                "source urn:host:info",
                "-c",
                "source urn:tz:now",
            ],
        );
        (text(&out.stdout), text(&out.stderr), out.status.code())
    };
    let (ttl_out, ttl_err, _) = ask("game.ttl");
    let (arr_out, arr_err, _) = ask("game.arrangement");
    assert!(ttl_out.contains("demo off"), "{ttl_out}\n{ttl_err}");
    assert!(
        arr_out.contains("demo off") && arr_out.contains("ikigai"),
        "both declared doors answer from the .arrangement: {arr_out}\n{arr_err}"
    );
    assert!(
        arr_err.contains("no endpoint resolved for urn:tz:now")
            && ttl_err.contains("no endpoint resolved for urn:tz:now"),
        "a door neither declares is not answered:\n{ttl_err}\n{arr_err}"
    );
    assert!(
        arr_err.contains("game.arrangement` (from the flag)"),
        "{arr_err}"
    );

    let dump = |file: &str, face: &str| {
        let out = run(
            &home,
            &[
                "--arrangement",
                file,
                "-c",
                &format!("source urn:iki:host:arrangement{face}"),
            ],
        );
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        text(&out.stdout)
    };
    let (ttl_turtle, arr_turtle) = (dump("game.ttl", ""), dump("game.arrangement", ""));
    assert_eq!(body(&ttl_turtle), body(&arr_turtle));
    assert_eq!(
        Topology::from_turtle(&arr_turtle).unwrap(),
        Topology::from_turtle(&game_turtle()).unwrap()
    );
    let face = " as=text/x-ikigai-arrangement";
    let (ttl_sexpr, arr_sexpr) = (dump("game.ttl", face), dump("game.arrangement", face));
    assert_eq!(body(&ttl_sexpr), body(&arr_sexpr));
    assert!(
        arr_sexpr.starts_with(";; The arrangement this host built its local root from"),
        "{arr_sexpr}"
    );
    // Printed back canonically: the source's comment is the one thing it does not keep.
    assert!(
        body(&arr_sexpr).starts_with("(fallback :id \"urn:game:root\""),
        "{arr_sexpr}"
    );
    assert!(!arr_sexpr.contains("Two layers"), "{arr_sexpr}");
    // And the s-expression the host prints starts the same host again.
    std::fs::write(home.join("again.arrangement"), &arr_sexpr).unwrap();
    assert_eq!(body(&dump("again.arrangement", "")), body(&arr_turtle));
}

/// A malformed `.arrangement` stops the start (exit 2), and ikigai-sexpr's refusal — which
/// says WHERE — reaches the operator, naming the transreptor that refused.
#[test]
fn a_malformed_arrangement_file_stops_the_start_naming_where() {
    let home = scratch("sexpr-bad");
    std::fs::write(
        home.join("game.arrangement"),
        "(fallback\n  (endpoints (door \"urn:host:demo\" host-demo))\n  (endpoints (portal \"urn:x\" y)))\n",
    )
    .unwrap();
    let out = run(
        &home,
        &[
            "--arrangement",
            "game.arrangement",
            "-c",
            "source urn:host:demo",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("game.arrangement")
            && stderr.contains("<urn:sexpr:arrangement-to-rdf> refused it")
            && stderr.contains("layer 2")
            && stderr.contains("(portal …)"),
        "{stderr}"
    );
    assert!(!text(&out.stdout).contains("demo off"), "nothing ran");

    // Unbalanced text is refused by the reader, before any tree exists.
    std::fs::write(
        home.join("open.arrangement"),
        "(endpoints (door \"urn:host:demo\" host-demo)\n",
    )
    .unwrap();
    let out = run(
        &home,
        &[
            "--arrangement",
            "open.arrangement",
            "-c",
            "source urn:host:demo",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("missing `)`"), "{stderr}");
}
