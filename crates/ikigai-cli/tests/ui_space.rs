//! Shared UI artifacts must resolve through the real REPL host.
#![cfg(feature = "embedded")]

#[test]
fn repl_sources_the_shared_tokens() {
    let home = std::env::temp_dir().join(format!("iki-ui-{}", std::process::id()));
    std::fs::create_dir_all(home.join("config/ikigai")).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args(["--quiet", "-c", "source urn:iki:ui:tokens.css"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(home);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let css = String::from_utf8_lossy(&output.stdout);
    assert!(css.contains(":root {"), "{css}");
    assert!(
        !css.contains("$h{"),
        "the palette markers were composed: {css}"
    );
}
