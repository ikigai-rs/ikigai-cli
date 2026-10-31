//! A refused narrowing must stop batches and keep replayed sessions refusing (#2717).
#![cfg(all(feature = "embedded", unix))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn scratch(case: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!("iki-cap-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join("config/ikigai")).unwrap();
    std::fs::create_dir_all(home.join("files")).unwrap();
    home
}

fn ikigai(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .arg("--quiet")
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .stdin(Stdio::null());
    command
}

fn refused(out: &Output) {
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not a capability scope"),
        "{out:?}"
    );
}

#[test]
fn a_refused_cap_stops_the_c_batch_before_a_write_or_reset() {
    let home = scratch("batch");
    let out = ikigai(&home)
        .args([
            "-c",
            "cap read-only lisp",
            "-c",
            "sink urn:file:blocked.txt unsafe",
            "-c",
            "cap reset",
            "-c",
            "sink urn:file:after.txt unsafe",
        ])
        .output()
        .unwrap();
    refused(&out);
    assert!(
        !home.join("files/blocked.txt").exists(),
        "a refused cap allowed a write: {out:?}"
    );
    assert!(
        !home.join("files/after.txt").exists(),
        "the batch continued after the refusal: {out:?}"
    );
}

#[test]
fn a_replayed_file_refuses_until_an_explicit_recovery() {
    let home = scratch("replay");
    std::fs::write(home.join("files/readable.txt"), "read recovered").unwrap();
    let replay = home.join("replay.txt");
    std::fs::write(&replay, "cap read-only lisp\nsink urn:file:blocked.txt unsafe\ncap\nsink urn:file:still-blocked.txt unsafe\ncap read-only\nsource urn:file:readable.txt\nsink urn:file:read-only.txt unsafe\ncap reset\nsink urn:file:after.txt safe\n").unwrap();
    let out = ikigai(&home)
        .stdin(std::fs::File::open(replay).unwrap())
        .output()
        .unwrap();
    refused(&out);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("read recovered\n"),
        "{out:?}"
    );
    for name in ["blocked.txt", "still-blocked.txt", "read-only.txt"] {
        assert!(
            !home.join("files").join(name).exists(),
            "{name} was written: {out:?}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(home.join("files/after.txt")).unwrap(),
        "safe"
    );
}

#[test]
fn a_script_file_stops_at_the_refused_cap() {
    let home = scratch("script");
    std::fs::write(
        home.join("refused.iki"),
        "cap read-only lisp\nsink urn:file:blocked.txt unsafe\n",
    )
    .unwrap();
    let out = ikigai(&home).arg("refused.iki").output().unwrap();
    refused(&out);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("error: line 1:"),
        "{out:?}"
    );
    assert!(!home.join("files/blocked.txt").exists(), "{out:?}");
}

#[test]
fn a_refused_cap_stops_before_a_lisp_write() {
    let home = scratch("lisp");
    let out = ikigai(&home)
        .args([
            "-c",
            "cap read-only lisp",
            "-e",
            "(sink \"urn:file:blocked.txt\" \"unsafe\")",
        ])
        .output()
        .unwrap();
    refused(&out);
    assert!(!home.join("files/blocked.txt").exists(), "{out:?}");
    assert!(out.stdout.is_empty(), "the Lisp form must not run: {out:?}");
}

#[test]
fn a_refused_cap_in_a_stored_script_stops_the_outer_batch() {
    let home = scratch("stored");
    std::fs::write(
        home.join("files/refused.iki"),
        "cap read-only lisp\nsink urn:file:blocked.txt unsafe\n",
    )
    .unwrap();
    let out = ikigai(&home)
        .args([
            "-c",
            "script urn:file:refused.iki",
            "-c",
            "cap reset",
            "-c",
            "sink urn:file:after.txt unsafe",
        ])
        .output()
        .unwrap();
    refused(&out);
    assert!(!home.join("files/blocked.txt").exists(), "{out:?}");
    assert!(!home.join("files/after.txt").exists(), "{out:?}");
}

#[test]
fn only_an_explicit_valid_cap_recovers_a_replayed_session() {
    for (case, recovery) in [("reset", "cap reset"), ("valid", "cap write")] {
        let home = scratch(case);
        std::fs::write(
            home.join("files/escape.iki"),
            "cap reset\nsink urn:file:escaped.txt unsafe\n",
        )
        .unwrap();
        let replay = home.join("replay.txt");
        std::fs::write(&replay, format!("cap invalid-profile\nlogout\nlogin urn:cap:fs:write:*\ncap seal\ncap another-invalid-profile\nscript urn:file:escape.iki\n(sink \"urn:file:lisp.txt\" \"unsafe\")\nsink urn:file:blocked.txt unsafe\n{recovery}\nsink urn:file:after.txt safe\n")).unwrap();
        let out = ikigai(&home)
            .stdin(std::fs::File::open(replay).unwrap())
            .output()
            .unwrap();
        refused(&out);
        for name in ["escaped.txt", "lisp.txt", "blocked.txt"] {
            assert!(
                !home.join("files").join(name).exists(),
                "{name} was written: {out:?}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(home.join("files/after.txt")).unwrap(),
            "safe"
        );
        assert!(
            String::from_utf8_lossy(&out.stderr)
                .contains("session is refusing after a failed `cap`"),
            "{out:?}"
        );
    }
}
