//! The embedded host's secret stores come from the config home's `[secret]` section (ledger
//! #4487): with no section the host reads the same secrets under the same names as before; a
//! section that routes a name to a second file store reads it from there; a malformed section
//! stops the start with ikigai-secret's sentence.
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
    std::fs::write(home.join("config/config.toml"), config).unwrap();
    Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .arg("--config-home")
        .arg(home.join("config"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("decoy"))
        .env("IKIGAI_FILES", home.join("files"))
        .env("IKIGAI_SECRETS", home.join("secrets"))
        .env_remove("IKIGAI_GRANTS")
        .env_remove("IKIGAI_LLM_CONFIG")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

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
