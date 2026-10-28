//! What the binary says about its own build, through the REAL binary: `--version --verbose`
//! lists the `ikigai-*` crates it links (ledger #1338), and an unresolved name names the
//! running build and how to upgrade it (ledger #288).
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `arrangement.rs`: `HOME`, `XDG_CONFIG_HOME` and
//! `IKIGAI_FILES` are set on the spawned process only.
#![cfg(feature = "embedded")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-ver-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    std::fs::create_dir_all(dir.join("files")).expect("scratch workspace");
    dir
}

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the binary under test runs")
}

/// Every `ikigai-*` package in this workspace's lock, by name → versions.
fn locked() -> BTreeMap<String, Vec<String>> {
    let lock = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    let lock: toml::Table = std::fs::read_to_string(&lock)
        .expect("the workspace lock")
        .parse()
        .expect("a lock parses");
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for package in lock["package"].as_array().expect("[[package]]") {
        let name = package["name"].as_str().unwrap().to_string();
        if name.starts_with("ikigai-") {
            out.entry(name)
                .or_default()
                .push(package["version"].as_str().unwrap().to_string());
        }
    }
    out
}

/// `--version` alone is still the one line a script reads; `--verbose` adds one
/// `<crate> <x.y.z>` line per linked crate, each at a version the lock holds — and only the
/// crates this build LINKS: a dev-dependency (`ikigai-conformance`), a member nothing here
/// depends on (`ikigai-p2p`) and an optional crate this build's features left out are absent.
#[test]
fn verbose_version_lists_the_linked_ikigai_crates_from_the_lock() {
    let home = scratch("verbose");
    let plain = run(&home, &["--version"]);
    let plain = String::from_utf8(plain.stdout).unwrap();
    assert_eq!(plain, format!("ikigai {}\n", env!("CARGO_PKG_VERSION")));

    let out = run(&home, &["--version", "--verbose"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some(plain.trim_end()), "{text}");
    let lock = locked();
    let mut listed: BTreeMap<&str, &str> = BTreeMap::new();
    for line in lines {
        let (name, version) = line
            .split_once(' ')
            .unwrap_or_else(|| panic!("`<crate> <version>`: {line:?}"));
        assert!(
            lock.get(name)
                .is_some_and(|v| v.iter().any(|x| x == version)),
            "{name} {version} is not in the lock"
        );
        listed.insert(name, version);
    }
    assert!(listed.contains_key("ikigai-core"), "{text}");
    assert!(listed.contains_key("ikigai-embedded"), "{text}");
    assert!(
        listed.contains_key("ikigai-fn"),
        "a registry crate via embedded: {text}"
    );
    assert!(
        !listed.contains_key("ikigai-cli"),
        "the first line is the cli: {text}"
    );
    assert!(
        !listed.contains_key("ikigai-conformance"),
        "a dev-dependency: {text}"
    );
    assert!(
        !listed.contains_key("ikigai-p2p"),
        "nothing here depends on it: {text}"
    );
    assert_eq!(
        listed.contains_key("ikigai-quic"),
        cfg!(feature = "quic"),
        "{text}"
    );
    assert_eq!(
        listed.contains_key("ikigai-web"),
        cfg!(feature = "web"),
        "{text}"
    );
    assert_eq!(
        listed.contains_key("ikigai-ledger"),
        cfg!(feature = "store"),
        "optional in ikigai-embedded, on with `store`: {text}"
    );
}

/// An unresolved name names this build and the command that replaces it (ledger #288), the
/// way an operator following newer docs than their binary hits it first. It says only what the
/// build knows (ledger #2481): that it binds no such name, and that an upgrade helps only if a
/// newer release exists. It never says the name is NEWER than this build: until 0.2.3 that
/// sent a reader asking for `urn:json:query`, which no release bound, to reinstall the binary
/// they had.
#[test]
fn an_unresolved_name_names_the_running_build() {
    let home = scratch("unresolved");
    let out = run(&home, &["-c", "source urn:iki:no-such:thing"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        stderr.contains("no endpoint resolved for urn:iki:no-such:thing"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "\n       this host is ikigai {version}, and it binds no such name\n"
        )),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "\n       a newer release may bind it; if `cargo search ikigai-cli` names one past \
             {version}: cargo install --locked ikigai-cli"
        )),
        "{stderr}"
    );
    assert!(
        !stderr.contains("newer than this build"),
        "the build cannot know the name is newer: {stderr}"
    );
}
