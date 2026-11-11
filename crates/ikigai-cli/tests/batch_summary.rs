//! Batch cache outcomes count requests, including pipeline and fork stages.
#![cfg(all(feature = "embedded", unix))]

use std::process::{Command, Stdio};

#[test]
fn batch_summary_names_request_outcomes_separately_from_commands() {
    let home = std::env::temp_dir().join(format!("iki-batch-summary-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .arg("--config-home")
        .arg(home.join("config"))
        .args([
            "--quiet",
            "-c",
            "source urn:fn:toUpper in=hello | ( urn:fn:reverseList ; urn:fn:toUpper )",
            "-c",
            "source urn:fn:toUpper in=hello | ( urn:fn:reverseList ; urn:fn:toUpper )",
        ])
        .env("HOME", &home)
        .env("IKIGAI_FILES", home.join("files"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    std::fs::remove_dir_all(&home).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("— batch: 2 commands · request outcomes: 3 cached · 3 computed"),
        "{stderr}"
    );
}
