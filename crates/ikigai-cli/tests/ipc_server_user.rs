//! `ipc.server_user` through the real binary (ledger #2966): the account a socket client accepts
//! beside its own. The refusal of a server run by another account needs that account, so
//! `ikigai-ipc`'s unit tests pin it through a fake peer-credentials read; this pins the setting.
#![cfg(all(feature = "embedded", feature = "ipc", unix))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use ikigai_core::{EndpointSpace, Exact, FnEndpoint, Kernel, ReprType, Representation};

/// A scratch home holding `config` as its `config.toml`, kept SHORT because the socket lives in it.
fn scratch(case: &str, config: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("isu-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let home = dir.join("config").join("ikigai");
    std::fs::create_dir_all(&home).expect("scratch config home");
    std::fs::write(home.join("config.toml"), config).expect("scratch config");
    dir
}

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
    let listener = ikigai_ipc::bind(socket).expect("the door binds");
    std::thread::spawn(move || {
        let _ = ikigai_ipc::serve_shared_on(Arc::new(kernel), listener);
    });
}

fn attach(home: &Path, flags: &[&str], command: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args(flags)
        .args(["--quiet", "-c", command])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env_remove("IKIGAI_CONFIG_HOME")
        .output()
        .expect("the binary runs")
}

fn own_uid() -> u32 {
    // SAFETY: `getuid` reads a process attribute and cannot fail.
    unsafe { libc::getuid() }
}

#[test]
fn naming_another_account_still_reaches_this_users_own_door() {
    let home = scratch(
        "own",
        &format!("ipc.server_user = \"{}\"\n", own_uid().wrapping_add(1)),
    );
    let socket = home.join("k.sock");
    serve(&socket);
    let output = attach(
        &home,
        &["--connect", &socket.to_string_lossy()],
        "source urn:hello",
    );
    let (said, error) = (
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(output.status.success(), "{said}{error}");
    assert!(said.contains("Hello, Ada"), "{said}{error}");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn an_unknown_server_user_is_refused_by_name_on_both_dials() {
    let home = scratch(
        "typo",
        "ipc.server_user = \"no-such-ikigai-account-2966\"\n",
    );
    let socket = home.join("k.sock");
    serve(&socket);
    let path = socket.to_string_lossy().to_string();
    for flags in [
        vec!["--connect".to_string(), path.clone()],
        vec!["--mount".to_string(), format!("urn:hello={path}")],
    ] {
        let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
        let output = attach(&home, &flags, "source urn:hello");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{flags:?}: {error}");
        assert!(error.contains("ipc.server_user"), "{flags:?}: {error}");
        assert!(error.contains("no user named"), "{flags:?}: {error}");
    }
    let _ = std::fs::remove_dir_all(&home);
}
