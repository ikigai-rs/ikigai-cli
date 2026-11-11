//! Library hosts receive the `IKIGAI_CLIENTS` refusal, and the refusal of a `--clients` file
//! that is not there, from the enrollment reader itself. Its own test binary because the
//! variable and the path override are process-global.
use ikigai_core::Capability;

const FINGERPRINT: &str = "6f1c00000000000000000000000000000000000000000000000000000000abcd";

#[test]
fn the_enrollment_reader_refuses_a_set_variable_and_a_missing_explicit_file() {
    let dir = std::env::temp_dir().join(format!("ikigai-clients-refusal-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let clients = dir.join("clients.json");
    let grants = dir.join("grants.json");
    std::fs::write(
        &clients,
        format!(r#"{{"clients":{{"{FINGERPRINT}":"reader"}}}}"#),
    )
    .unwrap();
    std::fs::write(&grants, r#"{"reader":["urn:cap:personal:contacts:read"]}"#).unwrap();
    std::env::remove_var("IKIGAI_CLIENTS");
    std::env::remove_var("IKIGAI_GRANTS");
    ikigai_embedded::set_grants_path(grants);
    ikigai_embedded::clients::set_clients_path(clients.clone());

    assert_eq!(
        ikigai_embedded::clients::clients_path().unwrap(),
        Some(clients.clone())
    );
    assert!(ikigai_embedded::clients::authorize(FINGERPRINT, &Capability::root()).is_ok());

    // A set variable refuses, whatever it names and even beside an explicit path.
    for value in ["", "legacy-clients.json"] {
        std::env::set_var("IKIGAI_CLIENTS", value);
        let expected = ikigai_embedded::clients::clients_path().unwrap_err();
        assert!(expected.contains("IKIGAI_CLIENTS"), "{expected}");
        assert!(expected.contains("--clients <file>"), "{expected}");
        assert_eq!(ikigai_embedded::clients::enrolment().unwrap_err(), expected);
        assert_eq!(
            ikigai_embedded::clients::authorize(FINGERPRINT, &Capability::root()).unwrap_err(),
            expected
        );
    }
    std::env::remove_var("IKIGAI_CLIENTS");

    // An explicit file that goes away is an error, not an absent enrollment.
    std::fs::remove_file(&clients).unwrap();
    let error = ikigai_embedded::clients::enrolment().unwrap_err();
    assert!(error.contains("--clients"), "{error}");
    assert!(error.contains(&*clients.to_string_lossy()), "{error}");
    assert!(ikigai_embedded::clients::authorize(FINGERPRINT, &Capability::root()).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
