//! Terminal runbook reads choose the text face unless a caller names a type, and only when
//! stdout is a terminal: piped or redirected output keeps the runbook's own default face
//! (ledger #3838).
#![cfg(all(feature = "embedded", unix))]

use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Command, Stdio};
use std::sync::Mutex;

// Serialize pipe creation/spawning so a sibling child cannot inherit a pipe on macOS.
static SPAWN: Mutex<()> = Mutex::new(());

/// Where the child's stdout goes.
#[derive(Clone, Copy)]
enum Stdout {
    Pipe,
    Terminal,
}

/// A pseudo-terminal pair, both ends close-on-exec: the child gets the follower as its
/// stdout (which `dup2` makes inheritable) and nothing else.
fn pty() -> (std::fs::File, OwnedFd) {
    let (mut leader, mut follower) = (0, 0);
    // SAFETY: openpty writes two fresh descriptors into the out-parameters; the name,
    // termios and winsize pointers may be null.
    let made = unsafe {
        libc::openpty(
            &mut leader,
            &mut follower,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(made, 0, "openpty: {}", std::io::Error::last_os_error());
    for fd in [leader, follower] {
        // SAFETY: `fd` is a descriptor openpty just returned and nothing else owns yet.
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
    }
    // SAFETY: each descriptor is owned here and nowhere else.
    unsafe {
        (
            std::fs::File::from_raw_fd(leader),
            OwnedFd::from_raw_fd(follower),
        )
    }
}

fn read_to(command: &str, batch: bool, stdout: Stdout) -> String {
    let home = std::env::temp_dir().join(format!(
        "iki-runbook-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(home.join("config")).unwrap();
    std::fs::create_dir_all(home.join("files")).unwrap();
    let mut command_line = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command_line
        .args(["--demo", "--plain", "--quiet"])
        .current_dir(&home)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .stderr(Stdio::piped());
    if batch {
        command_line.args(["-c", command]).stdin(Stdio::null());
    } else {
        command_line.stdin(Stdio::piped());
    }
    let (mut child, terminal) = {
        let _lock = SPAWN.lock().unwrap_or_else(|error| error.into_inner());
        let terminal = match stdout {
            Stdout::Pipe => {
                command_line.stdout(Stdio::piped());
                None
            }
            Stdout::Terminal => {
                let (leader, follower) = pty();
                command_line.stdout(Stdio::from(follower));
                Some(leader)
            }
        };
        let child = command_line.spawn().unwrap();
        // The Command holds the follower; drop it so the leader reads to its end once
        // the child exits.
        drop(command_line);
        (child, terminal)
    };
    // Drain the terminal while the child writes, so a full buffer never stalls it. Linux
    // ends the read with EIO once the last follower closes.
    let reader = terminal.map(|mut leader| {
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let mut chunk = [0; 4096];
            loop {
                match leader.read(&mut chunk) {
                    Ok(0) | Err(_) => break out,
                    Ok(n) => out.extend_from_slice(&chunk[..n]),
                }
            }
        })
    });
    if !batch {
        writeln!(child.stdin.take().unwrap(), "{command}\nquit").unwrap();
    }
    let output = child.wait_with_output().unwrap();
    std::fs::remove_dir_all(home).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    match reader {
        // The terminal turns each newline into CRLF; undo it so faces compare as written.
        Some(reader) => String::from_utf8(reader.join().unwrap())
            .unwrap()
            .replace("\r\n", "\n"),
        None => String::from_utf8(output.stdout).unwrap(),
    }
}

fn read(command: &str, batch: bool) -> String {
    read_to(command, batch, Stdout::Pipe)
}

fn read_on_terminal(command: &str, batch: bool) -> String {
    read_to(command, batch, Stdout::Terminal)
}

/// The reproduction for ledger #3838: `ikigai -c 'source <iri>' | jq` got text/plain in
/// 0.5.2 and 0.5.3. Piped, an untyped read gets the runbook's own default (HTML).
#[test]
fn piped_batch_runbook_keeps_its_default_face() {
    let html = read("source urn:runbook:basics as=text/html", true);
    assert!(html.contains("hx-get="), "{html}");
    assert_eq!(read("source urn:runbook:basics", true), html);
}

#[test]
fn piped_line_repl_runbook_keeps_its_default_face() {
    let html = read("source urn:runbook:basics as=text/html", false);
    assert!(html.contains("hx-get="), "{html}");
    assert_eq!(read("source urn:runbook:basics", false), html);
}

#[test]
fn batch_runbook_on_a_terminal_defaults_to_its_text_face() {
    let plain = read_on_terminal("source urn:runbook:basics as=text/plain", true);
    assert!(plain.contains("Basics"), "{plain}");
    assert!(!plain.contains("<section"), "{plain}");
    assert_eq!(read_on_terminal("source urn:runbook:basics", true), plain);
}

#[test]
fn line_repl_runbook_on_a_terminal_defaults_to_its_text_face() {
    let plain = read_on_terminal("source urn:runbook:basics as=text/plain", false);
    assert!(plain.contains("Basics"), "{plain}");
    assert_eq!(read_on_terminal("source urn:runbook:basics", false), plain);
}

#[test]
fn explicit_runbook_faces_are_preserved() {
    for batch in [true, false] {
        let html = read("source urn:runbook:basics as=text/html", batch);
        assert!(html.contains("<"));
        assert!(html.contains("hx-get="));
        let json = read("source urn:runbook:basics as=application/json", batch);
        let page: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(page["id"], "basics");
    }
}

#[test]
fn quoted_runbook_names_and_pipeline_stages_choose_text_on_a_terminal() {
    let plain = read_on_terminal(
        "source urn:runbook:basics as=text/plain | urn:fn:toUpper",
        true,
    );
    assert_eq!(
        read_on_terminal("source \"urn:runbook:basics\" | urn:fn:toUpper", true),
        plain
    );
}

#[test]
fn explicit_runbook_faces_win_on_a_terminal() {
    let html = read_on_terminal("source urn:runbook:basics as=text/html", true);
    assert!(html.contains("hx-get="), "{html}");
    let json = read_on_terminal("source urn:runbook:basics as=application/json", true);
    let page: serde_json::Value = serde_json::from_str(json.trim()).unwrap();
    assert_eq!(page["id"], "basics");
}
