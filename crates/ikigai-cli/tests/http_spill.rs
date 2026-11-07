//! Startup removes abandoned ephemeral HTTP spills without disturbing a live door.
#![cfg(all(feature = "embedded", feature = "web", unix))]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long a door gets to print its banner or exit. A watchdog, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

/// A child process that is killed when the test ends, whatever the test does.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch home whose config home's `config.toml` is `config`, and an owner-only workspace.
fn scratch(case: &str, config: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-http-spill-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let home = dir.join("config").join("ikigai");
    std::fs::create_dir_all(&home).expect("scratch config home");
    std::fs::write(home.join("config.toml"), config).expect("scratch config.toml");
    let files = dir.join("files");
    std::fs::create_dir_all(&files).expect("scratch workspace");
    std::fs::set_permissions(&files, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .expect("an owner-only workspace");
    dir
}

/// Start `serve --http 0` against `home` and report how it ENDED: `Ok((door, banner))` once it
/// printed `serving HTTP on`, `Err((code, stderr))` when it exited first.
fn start(home: &Path) -> Result<(Door, String), (i32, String)> {
    let mut child = Door(
        Command::new(env!("CARGO_BIN_EXE_ikigai"))
            // The ceiling grants the passkey challenge, as the edge's does: the endpoint declares
            // `urn:cap:passkey:challenge`, and a door without it refuses before any limit is counted.
            .args(["serve", "--http", "0", "--cap", "urn:cap:passkey:challenge"])
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("IKIGAI_FILES", home.join("files"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the binary under test starts"),
    );
    let stderr = child.0.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut seen = String::new();
        let mut served = false;
        let mut lines = BufReader::new(stderr).lines().map_while(Result::ok);
        for line in lines.by_ref() {
            seen.push_str(&line);
            seen.push('\n');
            if line.contains("serving HTTP on") {
                served = true;
                break;
            }
        }
        let _ = tx.send((served, seen));
        lines.for_each(drop);
    });
    let (served, seen) = rx
        .recv_timeout(PATIENCE)
        .unwrap_or_else(|e| panic!("the door neither served nor exited: {e}"));
    if served {
        return Ok((child, seen));
    }
    // EOF means the process is exiting; collect its status.
    let status = child.0.wait().expect("the door's exit status");
    Err((status.code().unwrap_or(-1), seen))
}

#[test]
fn startup_removes_stale_spills_and_preserves_a_live_door() {
    let home = scratch("sweep", "");
    let parent = home.join("config/ikigai/spill");
    let stale = parent.join("http-0-99999999");
    std::fs::create_dir_all(&stale).unwrap();
    let orphan = format!("{}0123", ikigai_fs::SPILL_PREFIX);
    std::fs::write(stale.join(&orphan), b"abandoned").unwrap();
    let (first, _) = start(&home).unwrap_or_else(|(code, err)| panic!("{code}: {err}"));
    assert!(
        !stale.exists(),
        "startup left a dead process's spill directory"
    );
    let live = parent.join(format!("http-0-{}", first.0.id()));
    std::fs::write(live.join(&orphan), b"still in use").unwrap();
    let (second, _) = start(&home).unwrap_or_else(|(code, err)| panic!("{code}: {err}"));
    assert_eq!(std::fs::read(live.join(&orphan)).unwrap(), b"still in use");
    drop(first);
    drop(second);
    let (_third, _) = start(&home).unwrap_or_else(|(code, err)| panic!("{code}: {err}"));
    assert!(
        !live.exists(),
        "restart left the previous door's spill directory"
    );
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn cleanup_preserves_unrelated_contents_and_never_follows_directory_symlinks() {
    let home = scratch("preserve", "");
    let parent = home.join("config/ikigai/spill");
    let orphan = format!("{}0123", ikigai_fs::SPILL_PREFIX);
    let empty = parent.join("http-0-99999998");
    std::fs::create_dir_all(&empty).unwrap();
    let kept = [
        "http-8080",
        "repl-99999999",
        "http-0-99999999-kept",
        "http-0-0",
        "http-0-2147483648",
        "http-0-",
        "http-0-+99999999",
    ];
    for name in kept {
        let dir = parent.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(&orphan), b"untouched").unwrap();
    }
    let mixed = parent.join("http-0-99999997");
    std::fs::create_dir_all(&mixed).unwrap();
    std::fs::write(mixed.join(&orphan), b"abandoned").unwrap();
    std::fs::write(mixed.join("keep.txt"), b"unrelated").unwrap();
    let target = home.join("target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join(&orphan), b"untouched").unwrap();
    std::os::unix::fs::symlink(&target, parent.join("http-0-99999996")).unwrap();
    let (_door, _) = start(&home).unwrap_or_else(|(code, err)| panic!("{code}: {err}"));
    assert!(!empty.exists(), "an empty stale directory stays");
    assert!(!mixed.join(&orphan).exists());
    assert_eq!(std::fs::read(mixed.join("keep.txt")).unwrap(), b"unrelated");
    for name in kept {
        assert_eq!(
            std::fs::read(parent.join(name).join(&orphan)).unwrap(),
            b"untouched"
        );
    }
    assert_eq!(std::fs::read(target.join(&orphan)).unwrap(), b"untouched");
    std::fs::remove_dir_all(home).unwrap();
}
