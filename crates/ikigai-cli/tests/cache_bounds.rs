//! Representation cache bounds must reach the host's kernel, not just its config reader.
#![cfg(all(feature = "embedded", unix))]

use std::process::{Command, Output, Stdio};

fn run(case: &str, config: &str) -> Output {
    let home = std::env::temp_dir().join(format!("iki-cache-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join("config")).unwrap();
    std::fs::create_dir_all(home.join("files")).unwrap();
    std::fs::write(home.join("config/config.toml"), config).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .arg("--config-home")
        .arg(home.join("config"))
        .args(["--quiet", "-c", "source urn:kernel:cache"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("decoy"))
        .env("IKIGAI_FILES", home.join("files"))
        .env_remove("IKIGAI_GRANTS")
        .current_dir(&home)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    std::fs::remove_dir_all(home).unwrap();
    output
}

#[test]
fn configured_bounds_reach_the_kernel() {
    let out = run(
        "configured",
        "cache.max_entries = 12_345\ncache.max_bytes = 536_870_912\n",
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(text.contains(" / 12345 "), "{text}");
    assert!(text.contains(" / 512.0 MB"), "{text}");
}

#[test]
fn absent_bounds_keep_the_defaults() {
    let out = run("default", "");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(text.contains(" / 4096 "), "{text}");
    assert!(text.contains(" / 64.0 MB"), "{text}");
}

#[test]
fn malformed_bounds_stop_startup() {
    for (case, config, key) in [
        ("negative", "cache.max_bytes = -1", "cache.max_bytes"),
        ("text", "cache.max_entries = many", "cache.max_entries"),
        (
            "overflow",
            "cache.max_bytes = 18446744073709551616",
            "cache.max_bytes",
        ),
        (
            "duplicate",
            "cache.max_bytes = 1\ncache.max_bytes = 2",
            "cache.max_bytes",
        ),
        ("unknown", "cache.max_byte = 1", "cache.max_byte"),
    ] {
        let out = run(case, config);
        let text = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{case}: {out:?}");
        assert!(text.contains(key) && text.contains("config.toml"), "{text}");
    }
}
