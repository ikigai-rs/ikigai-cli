//! The contact-inquiry edge half, mounted from the config home's `inquiry.json` (ledger #3836).
#![cfg(all(feature = "embedded", unix))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn home(name: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!("iki-inquiry-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    home
}

fn configure(home: &Path) {
    let key = home.join("sender.key");
    std::fs::write(&key, KEY).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(
        home.join("inquiry.json"),
        serde_json::json!({
            "sender_key_file": key,
            "store": home.join("inquiry-store"),
            "model": "contact",
            "owner": "brian",
        })
        .to_string(),
    )
    .unwrap();
}

fn ikigai(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args([
            "--config-home",
            home.to_str().unwrap(),
            "--files",
            home.join("files").to_str().unwrap(),
        ])
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env_remove("IKIGAI_GRANTS")
        .env_remove("IKIGAI_CLIENTS")
        .output()
        .unwrap()
}

fn catalog(home: &Path) -> String {
    let output = ikigai(home, &["--quiet", "-c", "source urn:kernel:catalog"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn without_inquiry_json_nothing_is_bound_and_with_it_the_edge_half_is() {
    let home = home("catalog");
    let before = catalog(&home);
    assert!(before.contains("urn:"), "{before}");
    assert!(!before.contains("urn:ikigai:endpoint:inquiry-"), "{before}");
    configure(&home);
    let after = catalog(&home);
    for name in [
        "inquiry-route",
        "inquiry-sender-key",
        "inquiry-apply",
        "inquiry-block",
        "inquiry-count",
    ] {
        let name = format!("<urn:ikigai:endpoint:{name}>");
        assert!(after.contains(&name), "{name}: {after}");
    }
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn a_malformed_inquiry_json_refuses_the_start_naming_the_file() {
    let home = home("bad");
    std::fs::write(home.join("inquiry.json"), r#"{"store":"relative"}"#).unwrap();
    let output = ikigai(&home, &["--quiet", "-c", "source urn:host:identity"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.starts_with("ikigai: ") && stderr.contains("inquiry.json"),
        "{stderr}"
    );
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn the_import_prints_counts_only_and_a_rerun_writes_nothing() {
    let home = home("import");
    configure(&home);
    let log = home.join("decisions.jsonl");
    let text = [
        r#"{"action":"approve","email":"friend@example.org"}"#,
        r#"{"action":"block","email":"Spam@Example.org"}"#,
        r#"{"action":"block","email":"seo@agency.example"}"#,
        r#"{"action":"block","email":"spam-domain.example"}"#,
        r#"{"action":"block","email":"not a sender"}"#,
    ]
    .join("\n");
    std::fs::write(&log, &text).unwrap();
    let run = || {
        let output = ikigai(
            &home,
            &["inquiry", "import-blocks", "--from", log.to_str().unwrap()],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let printed = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for address in ["spam@", "seo@", "agency", "spam-domain", "not a sender"] {
            assert!(!printed.to_lowercase().contains(address), "{printed}");
        }
        printed
    };
    assert_eq!(
        run().trim(),
        "read 4, written 3, already present 0, unreadable 1"
    );
    assert_eq!(
        run().trim(),
        "read 4, written 0, already present 3, unreadable 1"
    );
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        text,
        "the log is never edited"
    );
    std::fs::remove_dir_all(home).unwrap();
}
