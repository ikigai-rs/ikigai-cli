//! A separate process keeps path overrides and environment changes isolated.
#[test]
fn legacy_environment_cannot_redirect_grants() {
    let home = std::env::temp_dir().join(format!("ikigai-grants-path-{}", std::process::id()));
    ikigai_embedded::config::set_config_home(home.clone()).unwrap();
    std::env::set_var("IKIGAI_GRANTS", home.join("untrusted.json"));
    assert_eq!(
        ikigai_embedded::grants_path(),
        Some(home.join("grants.json"))
    );
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("config.toml"),
        "grants.path = \"protected/grants.json\"\n",
    )
    .unwrap();
    assert_eq!(
        ikigai_embedded::grants_path(),
        Some(home.join("protected/grants.json"))
    );
    let absolute = home.join("absolute.json");
    std::fs::write(
        home.join("config.toml"),
        format!(
            "grants.path = {:?}\n",
            absolute.to_str().unwrap().replace('\\', "/")
        ),
    )
    .unwrap();
    assert_eq!(ikigai_embedded::grants_path(), Some(absolute));
    let flag = home.join("flag.json");
    ikigai_embedded::set_grants_path(flag.clone());
    assert_eq!(ikigai_embedded::grants_path(), Some(flag));
    std::fs::remove_dir_all(home).unwrap();
}
