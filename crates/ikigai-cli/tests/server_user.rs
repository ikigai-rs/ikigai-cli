//! `ipc.server_user`: who a socket client accepts as its server (ledger #2966).
//!
//! That a server under another UID is refused, and that nothing reaches it, is pinned in
//! `ikigai-ipc`. A test cannot serve as another account without root, so what is pinned here is
//! the host's half: both ways of dialing read the setting, a bad one stops the dial, and a
//! client that names another account still reaches its own user's server.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use ikigai_core::{EndpointSpace, Exact, FnEndpoint, Kernel, ReprType, Representation};

/// A scratch home whose `config.toml` holds `config`.
fn home(name: &str, config: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iksu-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config_home = dir.join("config").join("ikigai");
    std::fs::create_dir_all(&config_home).expect("scratch config home");
    std::fs::write(config_home.join("config.toml"), config).expect("scratch config.toml");
    dir
}

fn ikigai(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .output()
        .expect("the binary under test runs")
}

/// A real server of this user's on `socket`, answering `urn:hello`.
fn serve(socket: &Path) {
    let hello = FnEndpoint::new("hello", |_inv| {
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"Hello, Ada".to_vec(),
        ))
    });
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:hello"), hello),
    ));
    let listener = ikigai_ipc::bind(socket).expect("the server binds");
    std::thread::spawn(move || {
        let _ = ikigai_ipc::serve_shared_on(Arc::new(kernel), listener);
    });
}

#[test]
fn an_unknown_server_user_stops_a_connect_and_a_mount() {
    let home = home("unknown", "ipc.server_user = \"no-such-account\"\n");
    let socket = home.join("k.sock");
    serve(&socket);
    let socket = socket.to_str().unwrap();
    let mount = format!("urn:peer:={socket}");

    for args in [
        vec!["--connect", socket, "--plain", "-c", "source urn:hello"],
        vec!["--mount", &mount, "--plain", "-c", "source urn:peer:hello"],
    ] {
        let out = ikigai(&home, &args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success()
                && stderr.contains("ipc.server_user: no user named `no-such-account`"),
            "{args:?}: {stderr}"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn naming_another_account_still_reaches_this_users_own_server() {
    // SAFETY: `getuid` reads a process attribute and cannot fail.
    let other = unsafe { libc::getuid() }.wrapping_add(1);
    let home = home("own", &format!("ipc.server_user = {other}\n"));
    let socket = home.join("k.sock");
    serve(&socket);

    let out = ikigai(
        &home,
        &[
            "--connect",
            socket.to_str().unwrap(),
            "--plain",
            "-c",
            "source urn:hello",
        ],
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("Hello, Ada"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&home);
}
