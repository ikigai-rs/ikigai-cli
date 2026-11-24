//! A host's config home, file root and default socket are absolute, whatever the environment
//! says, through the REAL binary: each case starts from an empty environment (`env_clear`) in a
//! scratch working directory, and nothing may appear under that directory.
#![cfg(all(feature = "embedded", feature = "ipc", unix))]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

/// A killed-on-drop child, whatever the test does.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// An empty scratch directory. Short, because the socket path under it is length-limited.
fn scratch(case: &str) -> PathBuf {
    let dir = Path::new("/tmp").join(format!("iki-ah-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("cwd")).expect("scratch working directory");
    dir.canonicalize().expect("scratch path")
}

/// `ikigai <args…>` in `<dir>/cwd` with exactly `env`.
fn command(dir: &Path, env: &[(&str, &str)], args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .current_dir(dir.join("cwd"))
        .env_clear()
        .envs(env.iter().copied())
        .stdin(Stdio::null());
    command
}

fn run(dir: &Path, env: &[(&str, &str)], args: &[&str]) -> Output {
    command(dir, env, args).output().expect("the binary runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// What the working directory now holds.
fn left_in_cwd(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir.join("cwd"))
        .expect("scratch working directory reads")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

/// Every environment with no usable home stops the host, says how to fix it, and writes
/// nothing under the working directory.
#[test]
fn a_host_with_no_usable_config_home_stops_and_names_the_way_out() {
    let cases: [&[(&str, &str)]; 6] = [
        &[],
        &[("HOME", "")],
        &[("HOME", "rel")],
        &[("XDG_CONFIG_HOME", "")],
        &[("XDG_CONFIG_HOME", "rel")],
        &[("XDG_CONFIG_HOME", "rel"), ("HOME", "./rel")],
    ];
    for (n, env) in cases.iter().enumerate() {
        let dir = scratch(&format!("stop{n}"));
        let out = run(&dir, env, &["--quiet", "-c", "config"]);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{env:?}: {stderr}");
        assert!(
            stderr.starts_with("ikigai: no config home"),
            "{env:?}: {stderr}"
        );
        for word in ["XDG_CONFIG_HOME", "HOME", "--config-home"] {
            assert!(stderr.contains(word), "{env:?} misses {word}: {stderr}");
        }
        assert_eq!(left_in_cwd(&dir), Vec::<String>::new(), "{env:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A `--version` asks nothing of the home, so it answers even with none.
#[test]
fn version_needs_no_home() {
    let dir = scratch("version");
    let out = run(&dir, &[], &["--version"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A relative `XDG_CONFIG_HOME` is passed over for `HOME`, in the engine's reading of the
/// config home as well as the host's.
#[test]
fn a_relative_xdg_config_home_is_ignored() {
    let dir = scratch("xdg");
    let home = dir.join("home");
    let config = home.join(".config").join("ikigai");
    std::fs::create_dir_all(&config).expect("config home");
    let env = [
        ("XDG_CONFIG_HOME", "rel"),
        ("HOME", home.to_str().expect("utf-8 home")),
    ];
    let out = run(&dir, &env, &["--quiet", "-c", "config"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let want = format!("config file: {}", config.join("config.toml").display());
    assert!(stdout.contains(&want), "{stdout}");
    assert_eq!(left_in_cwd(&dir), Vec::<String>::new());
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--config-home` alone gives a config home but no home for the default workspace: the
/// host says so and names `--files`, and with `--files` it runs.
#[test]
fn a_config_home_with_no_home_needs_a_named_file_root() {
    let dir = scratch("files");
    let config = dir.join("config");
    let config_arg = config.to_str().expect("utf-8 path");
    std::fs::create_dir_all(&config).expect("config home");
    let out = run(
        &dir,
        &[],
        &["--config-home", config_arg, "--quiet", "-c", "config"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.starts_with("ikigai: no file root"), "{stderr}");
    assert!(stderr.contains("--files"), "{stderr}");
    assert_eq!(left_in_cwd(&dir), Vec::<String>::new());

    let files = dir.join("files");
    let args = [
        "--config-home",
        config_arg,
        "--files",
        files.to_str().expect("utf-8 path"),
        "--quiet",
        "-c",
        "config",
    ];
    let out = run(&dir, &[], &args);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(left_in_cwd(&dir), Vec::<String>::new());
    let _ = std::fs::remove_dir_all(&dir);
}

/// An empty or relative `XDG_RUNTIME_DIR` falls through to the absolute per-user default,
/// and the door binds there, not under the working directory.
#[test]
fn the_default_socket_is_never_under_the_working_directory() {
    for (n, runtime) in ["", "relrun"].into_iter().enumerate() {
        let dir = scratch(&format!("sock{n}"));
        let home = dir.join("home");
        let tmp = dir.join("tmp");
        std::fs::create_dir_all(&home).expect("home");
        std::fs::create_dir_all(&tmp).expect("tmp");
        let env = [
            ("HOME", home.to_str().expect("utf-8 home")),
            ("TMPDIR", tmp.to_str().expect("utf-8 tmp")),
            ("XDG_RUNTIME_DIR", runtime),
        ];
        let mut child = command(&dir, &env, &["serve"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the binary runs");
        let stderr = child.stderr.take().expect("piped stderr");
        let door = Door(child);
        let line = BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
            .find(|line| line.contains("serving on"))
            .expect("a serving banner");
        let path = line
            .split("serving on ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .expect("a path in the banner");
        assert!(Path::new(path).is_absolute(), "{line}");
        assert!(Path::new(path).starts_with(&tmp), "{line}");
        assert_eq!(left_in_cwd(&dir), Vec::<String>::new(), "{runtime:?}");
        drop(door);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A blank `files` line names no root, so the startup check refuses it as `file_root` would.
#[test]
fn a_blank_files_line_names_no_file_root() {
    let dir = scratch("blank");
    let config = dir.join("config");
    std::fs::create_dir_all(&config).expect("config home");
    std::fs::write(config.join("config.toml"), "files = \"\"\n").expect("config.toml");
    let config_arg = config.to_str().expect("utf-8 path");
    let out = run(
        &dir,
        &[],
        &["--config-home", config_arg, "--quiet", "-c", "config"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.starts_with("ikigai: no file root"), "{stderr}");
    assert_eq!(left_in_cwd(&dir), Vec::<String>::new());
    let _ = std::fs::remove_dir_all(&dir);
}
