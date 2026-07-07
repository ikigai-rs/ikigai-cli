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
        .ok_or("no config directory (set $XDG_CONFIG_HOME or $HOME)")?;
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
fn write(path: &std::path::Path, contents: &str, mode: u32, force: bool) -> Result<(), String> {
    if path.exists() && !force {
        return Err(format!(
            "{} already exists (use `--force` to overwrite)",
            path.display()
        ));
    }
    std::fs::write(path, contents).map_err(|e| format!("write {}: {e}", path.display()))?;
    restrict(path, mode)?;
    Ok(())
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
/// The server trusts every `clients/*.crt` (see [`trusted_client_certs`]), so this
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

/// Every client certificate the server accepts — the configured `client.crt` plus any
/// extra tenant certs dropped into `<certdir>/clients/*.crt`. Each distinct cert is a
/// distinct identity (its own `ws/<id>` workspace), so multi-tenant is "add a cert".
pub fn trusted_client_certs(certs: &Certs) -> Result<Vec<String>, String> {
    let mut pems = vec![trusted_client_cert(certs)?];
    if let Ok(entries) = base_dir(certs)
        .map(|d| d.join("clients"))
        .and_then(|clients| std::fs::read_dir(&clients).map_err(|e| e.to_string()))
    {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "crt") {
                if let Ok(pem) = std::fs::read_to_string(&path) {
                    pems.push(pem);
                }
            }
        }
    }
    Ok(pems)
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
    hostport
        .to_socket_addrs()
        .map_err(|e| format!("resolve {hostport}: {e}"))?
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
