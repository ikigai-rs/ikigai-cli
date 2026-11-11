//! `IKIGAI_LLM_CONFIG`, when set, must name a file that is there.
#![cfg(feature = "embedded")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn scratch(tag: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!("iki-llm-config-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join("config")).unwrap();
    std::fs::create_dir_all(home.join("files")).unwrap();
    // The config home declares a provider the built-in default does not have.
    std::fs::write(
        home.join("config/llm.json"),
        r#"{"default":"home","providers":{"home":{"base_url":"http://127.0.0.1:1/v1","model":"home-model"}}}"#,
    )
    .unwrap();
    home
}

fn models(home: &Path, llm_config: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .arg("--quiet")
        .arg("--config-home")
        .arg(home.join("config"))
        .args(["-c", "source urn:llm:models"])
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .env("IKIGAI_SECRETS", home.join("secrets"))
        .env_remove("IKIGAI_LLM_CONFIG")
        .env_remove("IKIGAI_LLM_ANNOTATIONS")
        .env_remove("IKIGAI_GRANTS")
        .stdin(Stdio::null());
    if let Some(path) = llm_config {
        command.env("IKIGAI_LLM_CONFIG", path);
    }
    command.output().unwrap()
}

fn diagnostic(out: &Output) -> String {
    format!(
        "status: {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_set_variable_naming_a_missing_file_stops_the_start() {
    let home = scratch("missing");
    let missing = home.join("no-such-llm.json");
    let out = models(&home, Some(&missing));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{}", diagnostic(&out));
    assert!(stderr.contains("IKIGAI_LLM_CONFIG"), "{}", diagnostic(&out));
    assert!(
        stderr.contains(&missing.display().to_string()),
        "{}",
        diagnostic(&out)
    );
    // Neither the config home's file nor the built-in default stands in for it.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("home-model"), "{}", diagnostic(&out));
    assert!(!stdout.contains("llama3.2"), "{}", diagnostic(&out));
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn an_empty_variable_stops_the_start() {
    let home = scratch("empty");
    let out = models(&home, Some(Path::new("")));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{}", diagnostic(&out));
    assert!(stderr.contains("IKIGAI_LLM_CONFIG"), "{}", diagnostic(&out));
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn a_set_variable_naming_a_file_is_read() {
    let home = scratch("present");
    let file = home.join("override.json");
    std::fs::write(
        &file,
        r#"{"default":"env","providers":{"env":{"base_url":"http://127.0.0.1:1/v1","model":"env-model"}}}"#,
    )
    .unwrap();
    let out = models(&home, Some(&file));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", diagnostic(&out));
    assert!(stdout.contains("env-model"), "{}", diagnostic(&out));
    assert!(!stdout.contains("home-model"), "{}", diagnostic(&out));
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn an_unset_variable_reads_the_config_home() {
    let home = scratch("unset");
    let out = models(&home, None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", diagnostic(&out));
    assert!(stdout.contains("home-model"), "{}", diagnostic(&out));
    let _ = std::fs::remove_dir_all(home);
}
