//! Exercise the public policy entry point as another socket host would.
#![cfg(all(feature = "ipc", unix))]

#[test]
fn the_shared_policy_reads_the_configured_table_and_refuses_invalid_input() {
    let home = std::env::temp_dir().join(format!("ikigai-socket-policy-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    ikigai_embedded::config::set_config_home(home.clone()).unwrap();
    assert!(ikigai_embedded::socket::shared_socket().unwrap().is_none());
    std::fs::write(home.join("config.toml"), "grants.path = \"policy.json\"\n").unwrap();
    let path = home.join("policy.json");
    std::fs::write(&path, "{}").unwrap();
    assert!(ikigai_embedded::socket::shared_socket().unwrap().is_none());
    std::fs::write(&path, "not JSON").unwrap();
    let error = ikigai_embedded::socket::shared_socket().err().unwrap();
    assert!(error.contains(&path.display().to_string()), "{error}");
    // An unreadable table must not silently become owner-only either.
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(ikigai_embedded::socket::shared_socket().is_err());
    std::fs::remove_dir_all(home).unwrap();
}
