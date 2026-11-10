//! `config.toml` is read strictly: a line the reader cannot read, or a key the host does not
//! know, stops startup with the line named, and a trailing comment is not part of a value.
#![cfg(all(feature = "embedded", unix))]

use std::process::{Command, Output, Stdio};

/// Run `ikigai -c <command>` with `config` as the config home's `config.toml`. `config` may
/// name `{root}`, which is replaced by a scratch file root holding `marker.txt`.
fn run(case: &str, config: &str, command: &str) -> Output {
    let home = std::env::temp_dir().join(format!("iki-config-toml-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join("config")).unwrap();
    let root = home.join("root");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("marker.txt"), "marked\n").unwrap();
    let config = config.replace("{root}", &root.display().to_string());
    std::fs::write(home.join("config/config.toml"), config).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .arg("--config-home")
        .arg(home.join("config"))
        .args(["--quiet", "-c", command])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("decoy"))
        .env_remove("IKIGAI_FILES")
        .env_remove("IKIGAI_GRANTS")
        .current_dir(&home)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    // Nothing but the file root itself may appear beside it: a value that kept its comment
    // would have made a second directory here.
    let siblings: Vec<_> = std::fs::read_dir(&home)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    std::fs::remove_dir_all(&home).unwrap();
    assert!(
        siblings
            .iter()
            .all(|n| n == "root" || !n.starts_with("root")),
        "{case}: unexpected entries {siblings:?}"
    );
    output
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A line the reader cannot read stops every mode, naming the file and the line.
#[test]
fn an_unreadable_line_stops_startup() {
    for (case, config, shown) in [
        ("table", "files = \"{root}\"\n[ipc\n", "line 2"),
        ("header", "[mail]\nfrom = \"a@b.example\"\n", "line 1"),
        (
            "no-equals",
            "files = \"{root}\"\njust some words\n",
            "line 2",
        ),
        ("unterminated", "files = \"{root}\n", "line 1"),
        ("after-string", "files = \"{root}\" trailing\n", "line 1"),
        ("no-key", "= \"x\"\n", "line 1"),
        ("no-value", "mail.from =\n", "line 1"),
    ] {
        let out = run(case, config, "source urn:file:marker.txt");
        let text = stderr(&out);
        assert_eq!(out.status.code(), Some(2), "{case}: {out:?}");
        assert!(
            text.contains("config.toml") && text.contains(shown),
            "{case}: {text}"
        );
    }
}

/// A key no part of the host reads is refused rather than ignored: a misspelled `mount`
/// used to leave the host with no topology and no word about why.
#[test]
fn an_unknown_key_stops_startup() {
    for (case, config, key) in [
        ("mounts", "mounts = \"alias urn:x:=peer:p\"\n", "mounts"),
        ("scoped", "serve.filez = \"{root}\"\n", "serve.filez"),
        ("mail", "mail.form = \"a@b.example\"\n", "mail.form"),
    ] {
        let out = run(case, config, "source urn:file:marker.txt");
        let text = stderr(&out);
        assert_eq!(out.status.code(), Some(2), "{case}: {out:?}");
        assert!(
            text.contains(&format!("`{key}`")) && text.contains("config.toml"),
            "{case}: {text}"
        );
    }
}

/// A `#` after a quoted value starts a comment; it is not part of the path.
#[test]
fn a_trailing_comment_is_not_part_of_the_value() {
    for (case, config) in [
        ("basic", "files = \"{root}\" # the file root\n"),
        ("literal", "files = '{root}'   # the file root\n"),
        (
            "hash-inside",
            "# host config\nmail.from = \"a#b@c.example\" # x\nfiles = \"{root}\"\n",
        ),
        ("scoped", "repl.files = \"{root}\"  # this REPL's root\n"),
    ] {
        let out = run(case, config, "source urn:file:marker.txt");
        assert!(out.status.success(), "{case}: {out:?}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "marked",
            "{case}"
        );
    }
}

/// The shapes existing configs use keep working: dotted and instance-scoped keys, bare
/// numbers and words, repeated `mount` lines, comments and blank lines.
#[test]
fn the_flat_shape_still_reads() {
    let config = "# host config\n\n\
                  files = \"{root}\"\n\
                  mail.port = 587\n\
                  mail.host = localhost\n\
                  keybindings = \"emacs\"\n\
                  serve.scheduler = \"single\"\n\
                  cache.max_entries = 4096\n\
                  lisp.timeout = 5\n";
    let out = run("flat", config, "source urn:file:marker.txt");
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "marked");
}
