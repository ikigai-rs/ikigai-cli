//! The retired environment override must never silently select authority.
#![cfg(feature = "embedded")]

#[test]
fn the_retired_grants_variable_is_refused() {
    for value in ["retired-grants.json", ""] {
        for explicit in [false, true] {
            let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_ikigai"));
            command.args(["mcp", "--grant", "missing"]);
            if explicit {
                command.args(["--grants", "explicit-grants.json"]);
            }
            let output = command.env("IKIGAI_GRANTS", value).output().unwrap();
            let error = String::from_utf8(output.stderr).unwrap();
            assert_eq!(output.status.code(), Some(2), "{error}");
            assert!(error.contains("IKIGAI_GRANTS"), "{error}");
            assert!(error.contains("--grants"), "{error}");
        }
    }
}

#[cfg(all(feature = "ipc", unix))]
#[test]
fn the_socket_host_reads_the_global_grants_flag() {
    let dir = std::env::temp_dir().join(format!("iki-grants-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let grants = dir.join("explicit-grants.json");
    std::fs::write(&grants, "{ invalid JSON").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .arg("--config-home")
        .arg(&dir)
        .args(["serve", "--grants"])
        .arg(&grants)
        .arg(dir.join("door.sock"))
        .env_remove("IKIGAI_GRANTS")
        .output()
        .unwrap();
    let error = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2), "{error}");
    assert!(error.contains(&*grants.to_string_lossy()), "{error}");
    assert!(!error.contains("unknown argument"), "{error}");
    std::fs::remove_dir_all(dir).unwrap();
}
