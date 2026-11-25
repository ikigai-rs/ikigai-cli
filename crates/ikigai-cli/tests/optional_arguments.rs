//! A refused optional argument is a plain-language error at the terminal.
#![cfg(all(feature = "embedded", unix))]

use std::process::{Command, Stdio};

#[test]
fn the_clock_refusal_names_the_argument_and_what_to_write() {
    let home = std::env::temp_dir().join(format!("iki-optional-args-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let run = |request: &str| {
        Command::new(env!("CARGO_BIN_EXE_ikigai"))
            .arg("--config-home")
            .arg(home.join("config"))
            .args(["--quiet", "-c", request])
            .env("HOME", &home)
            .env("IKIGAI_FILES", home.join("files"))
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let default = run("source urn:time:now");
    let html = run("source urn:time:now html=true");
    let bad = run("source urn:time:now html=maybe");
    std::fs::remove_dir_all(&home).unwrap();

    assert!(default.status.success(), "{default:?}");
    assert!(!String::from_utf8_lossy(&default.stdout).contains("<span"));
    assert!(html.status.success(), "{html:?}");
    assert!(String::from_utf8_lossy(&html.stdout).contains("ik-clock-colon"));
    assert_eq!(bad.status.code(), Some(1), "{bad:?}");
    assert!(bad.stdout.is_empty(), "{bad:?}");
    let diagnostic = String::from_utf8(bad.stderr).unwrap();
    assert!(
        diagnostic
            .lines()
            .any(|line| line == "error: invalid argument `html`: expected true or false"),
        "{diagnostic}"
    );
}
