//! `ikigai --help` says which transports THIS binary has and which it lacks (ledger #109).
//!
//! The usage text names every transport the source knows, so a build without `quic` listed
//! `quic://` and then refused it. The closing `this build:` line is read from the same
//! features this test is compiled with (an integration test sees its package's features),
//! so the test holds under default features and under CI's `--all-features` alike.
#![cfg(feature = "embedded")]

use std::process::Command;

fn help() -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .arg("--help")
        .output()
        .expect("the binary under test runs");
    assert!(out.status.success(), "--help exits 0");
    String::from_utf8(out.stdout).expect("utf-8 help")
}

/// The `has …` and `lacks …` halves of the closing line.
fn halves(text: &str) -> (String, String) {
    let has = text
        .lines()
        .find_map(|line| line.strip_prefix("this build: has "))
        .unwrap_or_else(|| panic!("no `this build: has` line in --help:\n{text}"))
        .to_string();
    let lacks = text
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("lacks "))
        .unwrap_or_else(|| panic!("no `lacks` line in --help:\n{text}"))
        .to_string();
    (has, lacks)
}

#[test]
fn help_names_the_transports_this_build_has_and_lacks() {
    let (has, lacks) = halves(&help());
    let cases = [
        (cfg!(all(feature = "ipc", unix)), "Unix socket"),
        (cfg!(feature = "quic"), "quic://"),
        (cfg!(feature = "web"), "serve --http"),
        (
            cfg!(all(feature = "quic", feature = "web")),
            "--layers-https",
        ),
    ];
    for (built, what) in cases {
        if built {
            assert!(has.contains(what), "`{what}` is built in: has {has}");
            assert!(!lacks.contains(what), "`{what}` is built in: lacks {lacks}");
        } else {
            assert!(
                lacks.contains(what),
                "`{what}` is not built in: lacks {lacks}"
            );
            assert!(!has.contains(what), "`{what}` is not built in: has {has}");
        }
    }
    if !cfg!(feature = "quic") {
        assert!(
            lacks.contains("quic:// (needs the `quic` feature)"),
            "the missing feature is named: {lacks}"
        );
    }
}

#[test]
fn help_explains_replay_continuation_and_failure_status() {
    let text = help();
    assert!(text.contains("The line REPL continues after errors; exits 1 if any line failed,"));
    assert!(text.contains("otherwise 0, at EOF or quit."));
}
