//! The embedded host's secret stores come from the config home's `[secret]` section (ledger
//! #4487): with no section the host reads the same secrets under the same names as before; a
//! section that routes a name to a second file store reads it from there; a malformed section
//! stops the start with ikigai-secret's sentence.
//!
//! With no section, the store follows what an older release left in the home (ledger #4548):
//! an existing file store (`IKIGAI_SECRETS`, or a secret in the data home's `secrets`
//! directory) is kept, unchanged, and the host says so once at start; an empty home gets an
//! `age-file` store sealed to a key the host makes; that store's marker keeps it an `age-file`
//! store at every later start.
//!
//! Linux only: the platform default store is the file store there (`IKIGAI_SECRETS`), and a
//! scratch `HOME` does not isolate a Mac's Keychain.
#![cfg(all(feature = "embedded", target_os = "linux"))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// A scratch home for one test: `config/` (the config home) and `secrets/` (`IKIGAI_SECRETS`).
fn scratch(test: &str) -> PathBuf {
    let home =
        std::env::temp_dir().join(format!("iki-secret-stores-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join("config")).unwrap();
    std::fs::create_dir_all(home.join("files")).unwrap();
    home
}

/// Store `value` under `name` the way the file store lays it out: one `0600` file named for the
/// secret (these names are all of the verbatim set) in a `0700` directory.
fn put(store: &Path, name: &str, value: &str) {
    std::fs::create_dir_all(store).unwrap();
    std::fs::set_permissions(store, std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = store.join(name);
    std::fs::write(&file, value).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn run(home: &Path, config: &str, args: &[&str]) -> Output {
    run_with(home, config, args, Some(&home.join("secrets")))
}

/// [`run`] with `IKIGAI_SECRETS` set to `secrets`, or unset with `None` (the store is then the
/// one ikigai-secret chooses from what is in the data home, `~/.ikigai/secrets`).
fn run_with(home: &Path, config: &str, args: &[&str], secrets: Option<&Path>) -> Output {
    std::fs::write(home.join("config/config.toml"), config).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .arg("--config-home")
        .arg(home.join("config"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("decoy"))
        .env("IKIGAI_FILES", home.join("files"))
        .env_remove("IKIGAI_SECRETS")
        .env_remove("CREDENTIALS_DIRECTORY")
        .env_remove("IKIGAI_GRANTS")
        .env_remove("IKIGAI_LLM_CONFIG")
        .stdin(Stdio::null());
    if let Some(secrets) = secrets {
        command.env("IKIGAI_SECRETS", secrets);
    }
    command.output().unwrap()
}

/// The start-up line ikigai-secret gives an install from before that keeps its store.
const NOTICE: &str = "ikigai-secret: secrets stay in the file store, as before. New installs now \
                      get an age-file store";

fn shown(out: &Output) -> String {
    format!(
        "status: {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// No `[secret]` section: the same store (`IKIGAI_SECRETS`) and the same names as before, a
/// secret named `store` or `route` included, and no start-up line about secrets.
#[test]
fn no_section_reads_the_same_secrets_under_the_same_names() {
    let home = scratch("none");
    put(&home.join("secrets"), "api-token", "plain-token");
    put(&home.join("secrets"), "store", "named-store");
    put(&home.join("secrets"), "route", "named-route");
    let out = run(
        &home,
        "",
        &[
            "--quiet",
            "-c",
            "source urn:secret:api-token",
            "-c",
            "source urn:secret:store",
            "-c",
            "source urn:secret:route",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", shown(&out));
    for value in ["plain-token", "named-store", "named-route"] {
        assert!(stdout.contains(value), "{value}: {}", shown(&out));
    }
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("[secret]"),
        "{}",
        shown(&out)
    );
    let _ = std::fs::remove_dir_all(home);
}

/// A section that routes `zoom.*` to a second file store reads such a name from there, and
/// every other name from the default store; the routed space's inspection resources answer.
#[test]
fn a_routed_name_is_read_from_its_store() {
    let home = scratch("routed");
    put(&home.join("main"), "api-token", "from-main");
    put(&home.join("main"), "zoom.token", "stale-in-main");
    put(&home.join("team"), "zoom.token", "from-team");
    // The `~/` paths are read under HOME, the scratch home.
    let config = "files = \"~/files\"\n\
                  \n\
                  [secret]\n\
                  default = \"main\"\n\
                  \n\
                  [secret.store.main]\n\
                  kind = \"file\"\n\
                  path = \"~/main\"\n\
                  \n\
                  [secret.store.team]\n\
                  kind = \"file\"\n\
                  path = \"~/team\"\n\
                  write = false\n\
                  \n\
                  [[secret.route]]\n\
                  match = \"zoom.*\"\n\
                  store = \"team\"\n";
    let out = run(
        &home,
        config,
        &[
            "--quiet",
            "-c",
            "source urn:secret:zoom.token",
            "-c",
            "source urn:secret:api-token",
            "-c",
            "source urn:secret:route as=text/plain",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", shown(&out));
    assert!(stdout.contains("from-team"), "{}", shown(&out));
    assert!(!stdout.contains("stale-in-main"), "{}", shown(&out));
    assert!(stdout.contains("from-main"), "{}", shown(&out));
    assert!(stdout.contains("zoom.*"), "{}", shown(&out));
    let _ = std::fs::remove_dir_all(home);
}

/// A host that builds the local root says once at start that the section is in use and which
/// names it reserves: here the line REPL with no `-c`, on an empty stdin, so it starts, says
/// it, and ends.
#[test]
fn a_configured_section_is_announced_with_its_reserved_names() {
    let home = scratch("announced");
    let config = "[secret]\n\
                  default = \"main\"\n\
                  [secret.store.main]\n\
                  kind = \"file\"\n\
                  path = \"~/main\"\n";
    let out = run(&home, config, &["--plain"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{}", shown(&out));
    let line = stderr
        .lines()
        .find(|line| line.starts_with("ikigai: secrets: the [secret] section is in use"))
        .unwrap_or_else(|| panic!("{}", shown(&out)));
    for named in [
        "`main` (file)",
        "default `main`",
        "0 routes",
        "urn:secret:store,",
        "urn:secret:route,",
        "urn:secret:store:name:",
        "urn:secret:route:secret:",
        "urn:cap:secret:inspect",
    ] {
        assert!(line.contains(named), "{named}: {line}");
    }
    let _ = std::fs::remove_dir_all(home);
}

/// A malformed section stops the start, exit 2, with ikigai-secret's sentence after the file's
/// path, and nothing is read from any store.
#[test]
fn a_malformed_section_refuses_to_start() {
    let home = scratch("malformed");
    put(&home.join("secrets"), "api-token", "plain-token");
    let config = "[secret]\n\
                  default = \"nowhere\"\n\
                  [secret.store.main]\n\
                  kind = \"file\"\n\
                  path = \"~/main\"\n\
                  [[secret.route]]\n\
                  match = \"zoom.*\"\n\
                  store = \"team\"\n";
    let out = run(
        &home,
        config,
        &["--quiet", "-c", "source urn:secret:api-token"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{}", shown(&out));
    assert!(out.stdout.is_empty(), "{}", shown(&out));
    let file = home.join("config/config.toml");
    assert!(
        stderr.starts_with(&format!(
            "ikigai: {}: The [secret] section was refused and nothing in it was applied (2 \
             problems):\n- `default = \"nowhere\"` in [secret] names no configured store",
            file.display()
        )),
        "{}",
        shown(&out)
    );
    assert!(
        stderr.contains("- `store = \"team\"` in [[secret.route]] number 1"),
        "{}",
        shown(&out)
    );
    let _ = std::fs::remove_dir_all(home);
}

/// A key ikigai-secret does not read, or a table other than `[secret]` after it, stops the start
/// naming the file and the line.
#[test]
fn an_unreadable_section_names_its_line() {
    for (case, config, line) in [
        (
            "unknown-key",
            "files = \"~/files\"\n[secret]\ndefault = \"main\"\nkeybindings = \"vi\"\n",
            "line 4: ",
        ),
        (
            "other-table",
            "[secret]\ndefault = \"main\"\n[mail]\nfrom = \"a@b.example\"\n",
            "line 3: ",
        ),
        ("dotted", "secret.default = \"main\"\n", "line 1: "),
    ] {
        let home = scratch(case);
        let out = run(&home, config, &["--quiet", "-c", "source urn:secret:x"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{case}: {}", shown(&out));
        assert!(
            stderr.contains("config.toml") && stderr.contains(line),
            "{case}: {}",
            shown(&out)
        );
        let _ = std::fs::remove_dir_all(home);
    }
}

/// An install from before that set `IKIGAI_SECRETS` keeps that file store: its secrets read as
/// before, nothing is encrypted or moved, no key is made, and an interactive start says once
/// that new installs get an age-file store (a `-c` batch with `--quiet` stays quiet).
#[test]
fn an_existing_file_store_by_variable_is_kept_and_noticed() {
    let home = scratch("existing-variable");
    put(&home.join("secrets"), "api-token", "plain-token");
    let out = run(&home, "", &["--quiet", "-c", "source urn:secret:api-token"]);
    assert!(out.status.success(), "{}", shown(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("plain-token"),
        "{}",
        shown(&out)
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("ikigai-secret:"),
        "{}",
        shown(&out)
    );
    let out = run(&home, "", &["--plain"]);
    assert!(out.status.success(), "{}", shown(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    let notices: Vec<_> = stderr.lines().filter(|l| l.starts_with(NOTICE)).collect();
    assert_eq!(notices.len(), 1, "{}", shown(&out));
    assert!(
        notices[0].contains("IKIGAI_SECRETS is deprecated"),
        "{}",
        shown(&out)
    );
    assert_eq!(
        std::fs::read(home.join("secrets/api-token")).unwrap(),
        b"plain-token",
        "the secret is left as it was"
    );
    assert!(!home.join("config/secret.key").exists());
    assert!(!home.join(".ikigai/secrets").exists());
    let _ = std::fs::remove_dir_all(home);
}

/// An install from before with its file store in the data home (no `IKIGAI_SECRETS`) keeps it:
/// the secret reads as before, stays plaintext, gets no marker, and the notice is said.
#[test]
fn an_existing_file_store_in_the_data_home_is_kept_and_noticed() {
    let home = scratch("existing-data-home");
    let store = home.join(".ikigai/secrets");
    put(&store, "api-token", "plain-token");
    let out = run_with(
        &home,
        "",
        &["--quiet", "-c", "source urn:secret:api-token"],
        None,
    );
    assert!(out.status.success(), "{}", shown(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("plain-token"),
        "{}",
        shown(&out)
    );
    let out = run_with(&home, "", &["--plain"], None);
    assert!(out.status.success(), "{}", shown(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .lines()
            .any(|l| l.starts_with(NOTICE)),
        "{}",
        shown(&out)
    );
    assert_eq!(
        std::fs::read(store.join("api-token")).unwrap(),
        b"plain-token"
    );
    assert!(!store.join(".ikigai-age-file").exists());
    assert!(!home.join("config/secret.key").exists());
    let _ = std::fs::remove_dir_all(home);
}

/// A home with nothing in it gets the age-file store: a secret written is age ciphertext in the
/// data home, under a key the host made (`0600`) in the config home; a later start finds the
/// store's marker, stays age-file and reads the secret back; neither start gives the notice.
#[test]
fn an_empty_home_gets_an_age_file_store_that_stays_one() {
    let home = scratch("new-install");
    let out = run_with(&home, "", &["--plain"], None);
    assert!(out.status.success(), "{}", shown(&out));
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("ikigai-secret:"),
        "{}",
        shown(&out)
    );
    let stored = run_with(
        &home,
        "",
        &[
            "--quiet",
            "-c",
            "sink urn:secret:api-token content=sealed-4548",
        ],
        None,
    );
    assert!(stored.status.success(), "{}", shown(&stored));
    let store = home.join(".ikigai/secrets");
    let item = std::fs::read(store.join("api-token")).unwrap();
    assert!(
        item.starts_with(b"age-encryption.org/v1\n"),
        "{}",
        shown(&stored)
    );
    assert!(!String::from_utf8_lossy(&item).contains("sealed-4548"));
    assert!(store.join(".ikigai-age-file").exists());
    let key = home.join("config/secret.key");
    let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let out = run_with(
        &home,
        "",
        &["--quiet", "-c", "source urn:secret:api-token"],
        None,
    );
    assert!(out.status.success(), "{}", shown(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("sealed-4548"),
        "{}",
        shown(&out)
    );
    let out = run_with(&home, "", &["--plain"], None);
    assert!(out.status.success(), "{}", shown(&out));
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("ikigai-secret:"),
        "{}",
        shown(&out)
    );
    let _ = std::fs::remove_dir_all(home);
}

/// An age-file store an earlier start made whose key file was lost is not given a new key: a
/// read is refused naming the key file, and no key file appears.
#[test]
fn an_age_file_store_without_its_key_is_refused_not_rekeyed() {
    let home = scratch("lost-key");
    let stored = run_with(
        &home,
        "",
        &[
            "--quiet",
            "-c",
            "sink urn:secret:api-token content=sealed-4548",
        ],
        None,
    );
    assert!(stored.status.success(), "{}", shown(&stored));
    let key = home.join("config/secret.key");
    std::fs::remove_file(&key).unwrap();
    let out = run_with(
        &home,
        "",
        &["--quiet", "-c", "source urn:secret:api-token"],
        None,
    );
    assert!(!out.status.success(), "{}", shown(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&key.display().to_string()),
        "{}",
        shown(&out)
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("sealed-4548"));
    assert!(!key.exists());
    let _ = std::fs::remove_dir_all(home);
}

/// A malformed section still stops the start with exit 2 whatever older store the home holds,
/// and nothing is written to any store.
#[test]
fn a_malformed_section_refuses_over_every_older_store() {
    let config = "[secret]\ndefault = \"nowhere\"\n[secret.store.main]\nkind = \"file\"\n";
    for case in ["empty", "data-home", "age-file"] {
        let home = scratch(&format!("malformed-{case}"));
        match case {
            "data-home" => put(&home.join(".ikigai/secrets"), "api-token", "plain-token"),
            "age-file" => {
                let made = run_with(
                    &home,
                    "",
                    &["--quiet", "-c", "sink urn:secret:api-token content=x"],
                    None,
                );
                assert!(made.status.success(), "{case}: {}", shown(&made));
            }
            _ => {}
        }
        let out = run_with(
            &home,
            config,
            &["--quiet", "-c", "sink urn:secret:other content=y"],
            None,
        );
        assert_eq!(out.status.code(), Some(2), "{case}: {}", shown(&out));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("The [secret] section was refused"),
            "{case}: {}",
            shown(&out)
        );
        assert!(!home.join(".ikigai/secrets/other").exists(), "{case}");
        let _ = std::fs::remove_dir_all(home);
    }
}
