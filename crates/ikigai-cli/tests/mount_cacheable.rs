//! A peer's `cacheable: true` through `--mount` (ledger #2613), through the real binary: a peer
//! kernel serves one endpoint that declares itself cacheable, and `ikigai --mount` reads it twice.
//!
//! The item reported every read `[uncacheable]` and `urn:kernel:uncached` naming the mounted
//! name `declared`, where cli 0.1.18 had printed `[computed]`. This pins WHICH side does that,
//! and that it is the rule rather than a loss:
//! - **The peer keeps its claim.** Its endpoint runs once for both reads (the peer's own cache
//!   answers the second), and a direct wire client is handed `Expiry::Never`, so the claim
//!   crosses the wire intact.
//! - **The mounting kernel holds every peer answer as uncacheable** (`ikigai-resolve`'s
//!   `as_held_here`, ledger #92): no cut on the peer can reach a copy stored here, so storing one
//!   would serve it stale for the life of the process. Each read through the mount is one round
//!   trip to the peer's cache, reported `uncacheable` here, and `urn:kernel:uncached` names the
//!   mounted read `declared` (the forwarding endpoint's answer is what declared it).
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT: HOME and the config home are a scratch directory, so
//! the binary reads none of this machine's mounts. The socket lives under `temp_dir()` with a
//! short name (`sun_path` is 104 bytes on macOS).
#![cfg(all(feature = "embedded", feature = "ipc", unix))]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ikigai_core::{
    Capability, EndpointSpace, Exact, Expiry, FnEndpoint, Iri, Kernel, ReprType, Representation,
    Request, Verb,
};
use ikigai_resolve::Resolver;

/// A scratch home, kept SHORT because the peer's socket lives in it.
fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("imc-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    dir
}

/// The peer: `urn:hello`, declared cacheable, counting how often it is entered.
fn peer(socket: &Path) -> Arc<AtomicUsize> {
    let entered = Arc::new(AtomicUsize::new(0));
    let hello = {
        let entered = Arc::clone(&entered);
        FnEndpoint::new("hello", move |_inv| {
            entered.fetch_add(1, Ordering::SeqCst);
            Ok(
                Representation::new(ReprType::new("text/plain"), b"Hello, Ada".to_vec())
                    .cacheable(),
            )
        })
    };
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:hello"), hello),
    ));
    let listener = ikigai_ipc::bind(socket).expect("the peer binds");
    std::thread::spawn(move || {
        let _ = ikigai_ipc::serve_shared_on(Arc::new(kernel), listener);
    });
    entered
}

#[test]
fn a_peers_cacheable_answer_is_uncacheable_through_the_mount_and_says_why() {
    let home = scratch("m");
    let socket = home.join("p.sock");
    let entered = peer(&socket);

    // The claim crosses the wire: a direct client is handed the peer's own expiry.
    let direct = ikigai_ipc::connect(&socket).expect("a direct client connects");
    let request = Request::new(Verb::Source, Iri::parse("urn:hello").unwrap());
    let (answer, _) = direct
        .issue_as(request, &Capability::root())
        .expect("the peer answers");
    assert_eq!(answer.expiry, Expiry::Never, "the peer sends `cacheable`");
    assert_eq!(entered.load(Ordering::SeqCst), 1);
    drop(direct);

    let mount = format!("urn:ts:={}", socket.display());
    let output = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args(["--plain", "--mount", &mount])
        .args(["-c", "source urn:ts:hello", "-c", "source urn:ts:hello"])
        .args(["-c", "source urn:kernel:uncached"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .env_remove("IKIGAI_CLIENTS")
        .env_remove("IKIGAI_GRANTS")
        .output()
        .expect("the binary runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let seen = format!("stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(output.status.success(), "{seen}");
    assert_eq!(
        stdout.matches("Hello, Ada").count(),
        2,
        "both reads answer: {seen}"
    );

    // The peer's cache answered the mounted reads: its endpoint was not entered again.
    assert_eq!(
        entered.load(Ordering::SeqCst),
        1,
        "the peer honors `cacheable` for reads through the mount: {seen}"
    );

    // The mounting kernel stores neither, and says so.
    // One cache note per command, in order; the third is `urn:kernel:uncached` itself.
    let notes: Vec<&str> = stderr
        .lines()
        .filter(|line| line.starts_with('[') && line.ends_with(']'))
        .collect();
    assert_eq!(
        notes.get(..2),
        Some(&["[uncacheable]", "[uncacheable]"][..]),
        "each read through the mount is uncacheable here: {seen}"
    );
    let row = stdout
        .lines()
        .find(|line| line.split_whitespace().next() == Some("urn:ts:hello"))
        .unwrap_or_else(|| panic!("no `urn:ts:hello` row in urn:kernel:uncached: {seen}"));
    assert!(row.contains("×2"), "computed on both reads: {row}");
    // Since resolve 0.2.12 (engine PR 25) the reason is the mount itself: the answer is a peer's.
    assert!(
        row.contains("mounted"),
        "named as an answer that came through the mount: {row}"
    );

    let _ = std::fs::remove_dir_all(&home);
}
