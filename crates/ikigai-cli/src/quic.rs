//! QUIC glue for the CLI: where the pinned certificates live, how `cert
//! generate` writes them, and how `serve`/`--connect` load them.
//!
//! Certificates sit in `<config>/ikigai-cli/quic/` as `server.{crt,key}` and
//! `client.{crt,key}`. By the role-naming convention, `--server-cert` always
//! names the *server's* certificate (the server presents it, the client pins
//! it) and `--client-cert` the *client's* (the client presents it, the server
//! pins it); `--server-key` / `--client-key` are the private halves.

#![cfg(feature = "quic")]

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use ikigai_quic::Identity;

use crate::Certs;

/// `<config>/ikigai-cli/quic/`.
fn dir() -> Result<PathBuf, String> {
    let config = ikigai_engine::config::path()
        .ok_or("no config directory (set $XDG_CONFIG_HOME, $HOME or $USERPROFILE)")?;
    let parent = config
        .parent()
        .ok_or("config path has no parent directory")?;
    Ok(parent.join("quic"))
}

/// The base certificate directory: an explicit `--cert-dir`, else the default
/// `<config>/ikigai-cli/quic/`. Relocating it moves the whole set — the four
/// default filenames and the `clients/` trust dir — so a dedicated identity lives
/// apart from the default pair.
fn base_dir(certs: &Certs) -> Result<PathBuf, String> {
    match &certs.cert_dir {
        Some(d) => Ok(PathBuf::from(d)),
        None => dir(),
    }
}

/// The default path for one of the four certificate/key files, under `certs`' dir.
fn default_path(name: &str, certs: &Certs) -> Result<PathBuf, String> {
    Ok(base_dir(certs)?.join(name))
}

/// Generate a server and a client identity into `dir_override` (else the default
/// quic directory), created `0700`, keys `0600`. Refuses to overwrite unless
/// `force`. Returns the directory.
pub fn generate(force: bool, dir_override: Option<PathBuf>) -> Result<PathBuf, String> {
    let dir = match dir_override {
        Some(d) => d,
        None => dir()?,
    };
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    restrict(&dir, 0o700)?;

    // Pre-flight: refuse if ANY target exists, before writing ANY of them.
    // Writing cert-then-key per identity and failing partway used to leave a
    // freshly generated `server.crt` beside a pre-existing `server.key` — a
    // mismatched pair, which is worse than either clobbering or refusing: the
    // server would present a certificate it has no key for, and every client
    // pinning the old cert would break.
    if !force {
        let existing: Vec<String> = ["server.crt", "server.key", "client.crt", "client.key"]
            .iter()
            .map(|name| dir.join(name))
            // `symlink_metadata`, not `exists()`: a dangling link is something at the path
            // too, and the exclusive create below would refuse it after half the set was
            // written.
            .filter(|path| std::fs::symlink_metadata(path).is_ok())
            .map(|path| path.display().to_string())
            .collect();
        if !existing.is_empty() {
            return Err(format!(
                "{} already exist(s) — nothing was written (use `--force` to replace the whole set)",
                existing.join(", ")
            ));
        }
    }

    for (name, identity) in [
        ("server", ikigai_quic::generate()),
        ("client", ikigai_quic::generate()),
    ] {
        write(
            &dir.join(format!("{name}.crt")),
            &identity.cert_pem,
            0o600,
            force,
        )?;
        write(
            &dir.join(format!("{name}.key")),
            &identity.key_pem,
            0o600,
            force,
        )?;
    }
    Ok(dir)
}

/// Write `contents` to `path` with `mode`, refusing to clobber unless `force`.
///
/// The file is created EXCLUSIVELY with `mode` at open (ledger #90): it is never on disk
/// with the umask's mode, waiting for a chmod, and an exclusive create refuses whatever is
/// already at the path, a symlink included, so the existence check and the write are one
/// step and a key never lands at a link's target. `force` writes a private temporary the
/// same way beside `path` and renames it over the path, which replaces a file (or a link)
/// there whole rather than writing through it.
fn write(path: &std::path::Path, contents: &str, mode: u32, force: bool) -> Result<(), String> {
    if !force {
        return write_new(path, contents, mode).map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => format!(
                "{} already exists (use `--force` to overwrite)",
                path.display()
            ),
            _ => format!("write {}: {e}", path.display()),
        });
    }
    let name = path
        .file_name()
        .ok_or_else(|| format!("write {}: no file name", path.display()))?;
    let partial = path.with_file_name(format!(
        ".{}.partial-{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    // A partial left by a crashed run of THIS pid cannot be told from ours; it is ours to
    // replace. Removing it removes a link too, never its target.
    let _ = std::fs::remove_file(&partial);
    write_new(&partial, contents, mode).map_err(|e| format!("write {}: {e}", partial.display()))?;
    std::fs::rename(&partial, path).map_err(|e| {
        let _ = std::fs::remove_file(&partial);
        format!("replace {}: {e}", path.display())
    })
}

/// Create `path` exclusively (`O_CREAT|O_EXCL`, which also refuses a symlink there) with
/// `mode` from the first byte, and write `contents`.
fn write_new(path: &std::path::Path, contents: &str, mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode; // Non-Unix: the user-private config directory's ACLs govern.
    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()
}

/// The server's identity (its cert + key).
pub fn server_identity(certs: &Certs) -> Result<Identity, String> {
    Ok(Identity {
        cert_pem: read(certs.server_cert.clone(), "server.crt", certs)?,
        key_pem: read(certs.server_key.clone(), "server.key", certs)?,
    })
}

/// The client's identity (its cert + key).
pub fn client_identity(certs: &Certs) -> Result<Identity, String> {
    Ok(Identity {
        cert_pem: read(certs.client_cert.clone(), "client.crt", certs)?,
        key_pem: read(certs.client_key.clone(), "client.key", certs)?,
    })
}

/// The client certificate the server pins.
pub fn trusted_client_cert(certs: &Certs) -> Result<String, String> {
    read(certs.client_cert.clone(), "client.crt", certs)
}

/// Mint an additional client identity into `<certdir>/clients/<name>.{crt,key}`.
/// The server trusts every `clients/*.crt` (see [`trusted_clients`]), so this
/// adds a principal without disturbing the existing certs. Returns the `.crt` path.
pub fn add_client(name: &str, certs: &Certs, force: bool) -> Result<PathBuf, String> {
    if name.is_empty() || name.contains('/') || name.contains("..") {
        return Err(format!("invalid client name: {name:?}"));
    }
    let clients = base_dir(certs)?.join("clients");
    std::fs::create_dir_all(&clients).map_err(|e| format!("create {}: {e}", clients.display()))?;
    restrict(&clients, 0o700)?;
    let identity = ikigai_quic::generate();
    let crt = clients.join(format!("{name}.crt"));
    write(&crt, &identity.cert_pem, 0o600, force)?;
    write(
        &clients.join(format!("{name}.key")),
        &identity.key_pem,
        0o600,
        force,
    )?;
    Ok(crt)
}

/// One certificate this server trusts: what it is CALLED, the file that made it true, and
/// the PEM itself.
///
/// The label and the path exist because a COUNT of these cannot answer the question an
/// operator asks of them. Two servers on one machine printed `1 trusted client cert(s)`
/// and meant opposite things (ledger #426): one had `clients/plasma.crt` enrolled, the
/// other had no `clients/` directory at all and was counting the base `client.crt` that
/// [`trusted_clients`] always includes. Same number, opposite fact.
pub struct TrustedClient {
    /// `base` for the configured `client.crt`, else the `clients/<name>.crt` stem.
    pub label: String,
    /// The file it was read from — the thing the operator adds or removes.
    pub path: PathBuf,
    pub pem: String,
}

/// Every client certificate the server accepts — the configured `client.crt` (labelled
/// `base`) plus any extra tenant certs dropped into `<certdir>/clients/*.crt`. Each
/// distinct cert is a distinct identity (its own `ws/<id>` workspace), so multi-tenant is
/// "add a cert".
///
/// Sorted by label after the base, so the banner a machine prints at startup is the same
/// every start — `read_dir` order is not.
pub fn trusted_clients(certs: &Certs) -> Result<Vec<TrustedClient>, String> {
    let base = match certs.client_cert.clone() {
        Some(path) => PathBuf::from(path),
        None => default_path("client.crt", certs)?,
    };
    let mut trusted = vec![TrustedClient {
        label: "base".to_string(),
        pem: trusted_client_cert(certs)?,
        path: base,
    }];
    let mut extra = Vec::new();
    if let Ok(entries) = base_dir(certs)
        .map(|d| d.join("clients"))
        .and_then(|clients| std::fs::read_dir(&clients).map_err(|e| e.to_string()))
    {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "crt") {
                if let Ok(pem) = std::fs::read_to_string(&path) {
                    extra.push(TrustedClient {
                        label: path
                            .file_stem()
                            .map_or_else(|| "?".to_string(), |s| s.to_string_lossy().into_owned()),
                        path,
                        pem,
                    });
                }
            }
        }
    }
    extra.sort_by(|a, b| a.label.cmp(&b.label));
    trusted.extend(extra);
    Ok(trusted)
}

/// The server certificate the client pins.
pub fn trusted_server_cert(certs: &Certs) -> Result<String, String> {
    read(certs.server_cert.clone(), "server.crt", certs)
}

/// Read a PEM file from an explicit path or the default for `default_name` (under
/// `certs`' base directory).
fn read(explicit: Option<String>, default_name: &str, certs: &Certs) -> Result<String, String> {
    let path = match explicit {
        Some(path) => PathBuf::from(path),
        None => default_path(default_name, certs)?,
    };
    std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "read {}: {e} — run `ikigai cert generate` first?",
            path.display()
        )
    })
}

/// Parse and resolve a `quic://host:port` target into a socket address.
pub fn parse_addr(target: &str) -> Result<SocketAddr, String> {
    let hostport = target
        .strip_prefix("quic://")
        .ok_or_else(|| format!("not a quic:// target: {target}"))?;
    let mut addrs: Vec<SocketAddr> = hostport
        .to_socket_addrs()
        .map_err(|e| format!("resolve {hostport}: {e}"))?
        .collect();
    // Prefer IPv4. A `serve` binds `0.0.0.0` (IPv4-only), but an mDNS `.local`
    // name often resolves to BOTH families and hands the IPv6 first — dialing
    // that, the IPv4-only server never answers and the connect times out. Sorting
    // IPv4 ahead (`is_ipv6()` false < true) picks a family the server is on.
    addrs.sort_by_key(|a| a.is_ipv6());
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| format!("{hostport} resolved to no address"))
}

#[cfg(unix)]
fn restrict(path: &std::path::Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("set permissions on {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn restrict(_path: &std::path::Path, _mode: u32) -> Result<(), String> {
    // Non-Unix: rely on the user-private config directory's ACLs.
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A fresh scratch directory for one test, removed when the guard drops.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("ikigai-cli-quic-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn mode(path: &std::path::Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    /// ledger #90: a key is written private from its first byte, `0600` at OPEN, never
    /// written world-readable and chmod-ed after.
    #[test]
    fn a_key_is_private_and_refuses_to_clobber() {
        let s = Scratch::new("private");
        let key = s.0.join("server.key");
        write(&key, "secret", 0o600, false).unwrap();
        assert_eq!(std::fs::read_to_string(&key).unwrap(), "secret");
        assert_eq!(mode(&key), 0o600);
        let err = write(&key, "other", 0o600, false).unwrap_err();
        assert!(err.contains("already exists"), "{err}");
        assert_eq!(std::fs::read_to_string(&key).unwrap(), "secret");
    }

    /// The existence check and the write were two steps, and the write FOLLOWED a symlink:
    /// a dangling link at the key's path passed `exists()` and the key landed wherever it
    /// pointed. Created exclusively at open, the link is refused and nothing is written.
    #[test]
    fn a_key_is_never_written_through_a_symlink() {
        let s = Scratch::new("symlink");
        let elsewhere = s.0.join("elsewhere");
        let key = s.0.join("client.key");
        std::os::unix::fs::symlink(&elsewhere, &key).unwrap();
        assert!(write(&key, "secret", 0o600, false).is_err());
        assert!(
            !elsewhere.exists(),
            "the key must not land at the link's target"
        );
    }

    /// `--force` REPLACES the file at the path: a world-readable file there is replaced by a
    /// private one, and a symlink there is replaced, not written through.
    #[test]
    fn force_replaces_the_path_and_never_writes_through_it() {
        let s = Scratch::new("force");
        let key = s.0.join("server.key");
        std::fs::write(&key, "old").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        write(&key, "new", 0o600, true).unwrap();
        assert_eq!(std::fs::read_to_string(&key).unwrap(), "new");
        assert_eq!(mode(&key), 0o600);

        let target = s.0.join("target");
        std::fs::write(&target, "untouched").unwrap();
        let link = s.0.join("client.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        write(&link, "secret", 0o600, true).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
        assert!(!std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "secret");
        assert_eq!(mode(&link), 0o600);
        // No temporary is left beside the key.
        let names: Vec<String> = std::fs::read_dir(&s.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 3, "{names:?}");
    }
}
