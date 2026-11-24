//! Library hosts must receive configuration refusals without a binary startup check.
use ikigai_core::Capability;

#[test]
fn an_enrolled_client_receives_the_legacy_grants_refusal() {
    let dir = std::env::temp_dir().join(format!("ikigai-grants-refusal-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let clients = dir.join("clients.json");
    let grants = dir.join("grants.json");
    let fingerprint = "6f1c00000000000000000000000000000000000000000000000000000000abcd";
    std::fs::write(
        &clients,
        format!(r#"{{"clients":{{"{fingerprint}":"reader"}}}}"#),
    )
    .unwrap();
    std::fs::write(&grants, r#"{"reader":["urn:cap:personal:contacts:read"]}"#).unwrap();
    ikigai_embedded::clients::set_clients_path(clients);
    std::env::remove_var("IKIGAI_GRANTS");
    ikigai_embedded::set_grants_path(grants);
    assert!(ikigai_embedded::clients::authorize(fingerprint, &Capability::root()).is_ok());
    assert_eq!(
        ikigai_embedded::grant_scopes("reader").unwrap(),
        vec!["urn:cap:personal:contacts:read"]
    );
    assert!(ikigai_embedded::grant_scopes("missing").unwrap().is_empty());
    assert_eq!(
        ikigai_embedded::grant_visibility("reader").unwrap(),
        (vec![], vec![])
    );
    for value in ["", "legacy-grants.json"] {
        std::env::set_var("IKIGAI_GRANTS", value);
        let expected = ikigai_embedded::grants_path().unwrap_err();
        let error = ikigai_embedded::clients::authorize(fingerprint, &Capability::root())
            .expect_err("legacy environment must refuse authorization");
        assert_eq!(error, expected);
        for name in ["reader", "missing", "principals"] {
            assert_eq!(ikigai_embedded::grant_scopes(name).unwrap_err(), expected);
            assert_eq!(
                ikigai_embedded::grant_visibility(name).unwrap_err(),
                expected
            );
        }
    }
    std::env::remove_var("IKIGAI_GRANTS");
    std::fs::remove_dir_all(dir).unwrap();
}
