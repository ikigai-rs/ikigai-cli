//! Config-home intake rows are checked before the host starts.
#![cfg(all(feature = "embedded", unix))]

use std::process::Command;

#[test]
fn a_bad_intake_row_refuses_start_and_names_the_row() {
    let home = std::env::temp_dir().join(format!("iki-intakes-bad-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("intakes.json"),
        r#"[{"id":"broken-site","space":"urn:space:contact","fields":[],"redirect":"javascript:alert(1)"}]"#,
    ).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args([
            "--config-home",
            home.to_str().unwrap(),
            "--files",
            home.join("files").to_str().unwrap(),
            "--quiet",
            "-c",
            "source urn:host:identity",
        ])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &home)
        .env_remove("IKIGAI_GRANTS")
        .env_remove("IKIGAI_CLIENTS")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("ikigai:") && stderr.contains("broken-site") && stderr.contains("redirect"),
        "{stderr}"
    );
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn the_config_home_binds_both_intakes_and_the_legacy_alias() {
    let home = std::env::temp_dir().join(format!("iki-intakes-two-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("intakes.json"), r#"[
        {"id":"alpha","space":"urn:space:alpha","fields":[{"name":"message","required":true}],"fixed_fields":{"site":"alpha"}},
        {"id":"beta","space":"urn:space:beta","fields":[{"name":"message","required":true}],"fixed_fields":{"site":"beta"}}
    ]"#).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args([
            "--config-home",
            home.to_str().unwrap(),
            "--files",
            home.join("files").to_str().unwrap(),
            "--quiet",
        ])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &home)
        .env_remove("IKIGAI_GRANTS")
        .env_remove("IKIGAI_CLIENTS");
    for endpoint in [
        "urn:intake:alpha:submit",
        "urn:intake:beta:submit",
        "urn:contact:submit",
    ] {
        command.args([
            "-c",
            &format!("sink {endpoint} content=message=hello&site=forged"),
        ]);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout)
            .matches("received")
            .count(),
        3
    );
    std::fs::remove_dir_all(home).unwrap();
}
