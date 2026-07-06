//! ikigai — resource-resolution REPL.
//!
//! Attaches to a kernel instance over a pluggable transport: `embedded` (the
//! kernel runs in this process), `ipc` (a kernel server over a Unix socket), or
//! `quic` (a remote kernel over QUIC with mutually-pinned TLS). `ikigai serve`
//! runs a server; `--connect` attaches to one, choosing the transport by the
//! target (a path → Unix socket, `quic://host:port` → QUIC). Each line is a
//! request issued against the kernel's address space; the response is its
//! representation's bytes.
//!
//! With `-c '<command>'` (repeatable) it runs the command(s) and exits. Otherwise,
//! on an interactive terminal it launches a full-screen [`tui`] REPL; piped or
//! with `--plain` it falls back to the line-oriented [`repl`]. All drive the same
//! renderer-agnostic [`engine`] over the chosen [`Resolver`](ikigai_resolve::Resolver).

#[cfg(not(target_family = "wasm"))]
mod clipboard;
#[cfg(feature = "quic")]
mod quic;
mod repl;
#[cfg(not(target_family = "wasm"))]
mod tui;

const USAGE: &str = "\
ikigai — resource-resolution REPL

usage:
  ikigai                       start the interactive REPL (full-screen on a terminal)
  ikigai --plain               force the line REPL (also used automatically when piped)
  ikigai --demo                mount the interactive runbook (urn:runbook:*); off by default
  ikigai --connect [<target>]  attach the REPL to a kernel server (a Unix path, or quic://host:port)
  ikigai serve [<target>]      run a kernel server (a Unix socket path, or quic://addr to bind)
  ikigai --daemon              headless: timers, the watcher, and the standing sync — for launchd
  ikigai --name <instance>     name this instance (scopes <name>.* config properties; defaults
                               repl / daemon / serve by mode)
  ikigai cert generate         create the pinned QUIC certificates in your config dir
  ikigai -c '<command>' ...    run command(s) non-interactively, then exit
  ikigai -h | --help           show this help

QUIC: --server-cert/--server-key name the server's identity, --client-cert/--client-key the client's
inside the REPL: source, describe, help, quit (type `help` for details)";

use ikigai_engine::Engine;

/// Per-role certificate-path overrides for QUIC, shared by `serve` and `--connect`.
#[derive(Default)]
struct Certs {
    server_cert: Option<String>,
    server_key: Option<String>,
    client_cert: Option<String>,
    client_key: Option<String>,
}

/// What the CLI was asked to do.
enum Mode {
    Repl(ReplArgs),
    /// Headless: build the watched kernel (timers, watcher, the standing sync)
    /// and park — the launchd-agent face of the desktop machine.
    Daemon,
    Serve {
        target: Option<String>,
        certs: Certs,
    },
    /// Serve the capability-scoped manifold as an MCP (Model Context Protocol)
    /// server over stdio. `grants`/`scopes` union into the session capability —
    /// the ceiling on the tools an MCP client sees and can call.
    Mcp {
        grants: Vec<String>,
        scopes: Vec<String>,
    },
    CertGenerate {
        force: bool,
    },
}

/// Options for the REPL mode.
#[derive(Default)]
struct ReplArgs {
    plain: bool,
    /// Mount the interactive runbook (`urn:runbook:*`); off by default so the CLI is
    /// a tool, not a demo. Only meaningful for the embedded (non-`--connect`) kernel.
    demo: bool,
    commands: Vec<String>,
    /// `None` = the embedded in-process kernel; `Some` = attach to a server, with
    /// `Some(None)` meaning the default Unix socket.
    connect: Option<Option<String>>,
    certs: Certs,
}

/// Whether a `serve`/`--connect` target names a QUIC endpoint.
fn is_quic(target: &str) -> bool {
    target.starts_with("quic://")
}

/// If `arg` is a `--{server,client}-{cert,key}` flag, consume its value into
/// `certs` and report that it was handled.
fn cert_flag(
    arg: &str,
    argv: &mut impl Iterator<Item = String>,
    certs: &mut Certs,
) -> Result<bool, String> {
    let slot = match arg {
        "--server-cert" => &mut certs.server_cert,
        "--server-key" => &mut certs.server_key,
        "--client-cert" => &mut certs.client_cert,
        "--client-key" => &mut certs.client_key,
        _ => return Ok(false),
    };
    *slot = Some(
        argv.next()
            .ok_or_else(|| format!("{arg} requires a path"))?,
    );
    Ok(true)
}

/// Parse argv. `Ok(None)` means a usage request was handled and we should exit 0.
fn parse_args() -> Result<Option<Mode>, String> {
    let mut argv = std::env::args().skip(1).peekable();

    if argv.peek().map(String::as_str) == Some("cert") {
        argv.next();
        return match argv.next().as_deref() {
            Some("generate") => {
                let mut force = false;
                for arg in argv {
                    match arg.as_str() {
                        "--force" => force = true,
                        other => {
                            return Err(format!("unknown argument after `cert generate`: {other}"))
                        }
                    }
                }
                Ok(Some(Mode::CertGenerate { force }))
            }
            Some(other) => Err(format!("unknown `cert` subcommand: {other}")),
            None => Err("usage: `ikigai cert generate`".to_string()),
        };
    }

    if argv.peek().map(String::as_str) == Some("serve") {
        argv.next();
        let mut target = None;
        let mut certs = Certs::default();
        while let Some(arg) = argv.next() {
            if cert_flag(&arg, &mut argv, &mut certs)? {
                continue;
            }
            if arg == "--name" {
                let name = argv
                    .next()
                    .ok_or_else(|| "--name needs a value".to_string())?;
                #[cfg(feature = "embedded")]
                ikigai_embedded::set_instance_name(name);
                continue;
            }
            if arg.starts_with('-') {
                return Err(format!("unknown argument: {arg}"));
            } else if target.is_none() {
                target = Some(arg);
            } else {
                return Err(format!("unexpected argument after `serve`: {arg}"));
            }
        }
        return Ok(Some(Mode::Serve { target, certs }));
    }

    if argv.peek().map(String::as_str) == Some("mcp") {
        argv.next();
        let mut grants = Vec::new();
        let mut scopes = Vec::new();
        while let Some(arg) = argv.next() {
            match arg.as_str() {
                "--grant" => grants.push(
                    argv.next()
                        .ok_or_else(|| "--grant needs a name".to_string())?,
                ),
                "--scope" => scopes.push(
                    argv.next()
                        .ok_or_else(|| "--scope needs a capability IRI".to_string())?,
                ),
                other => return Err(format!("unknown argument after `mcp`: {other}")),
            }
        }
        return Ok(Some(Mode::Mcp { grants, scopes }));
    }

    let mut repl = ReplArgs::default();
    let mut daemon = false;
    while let Some(arg) = argv.next() {
        if cert_flag(&arg, &mut argv, &mut repl.certs)? {
            continue;
        }
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--plain" => repl.plain = true,
            "--demo" => repl.demo = true,
            "--daemon" => daemon = true,
            "--name" => {
                let name = argv
                    .next()
                    .ok_or_else(|| "--name needs a value".to_string())?;
                ikigai_embedded::set_instance_name(name);
            }
            "--connect" => {
                // Optional target: take the next token unless it looks like a flag.
                let target = match argv.peek() {
                    Some(next) if !next.starts_with('-') => argv.next(),
                    _ => None,
                };
                repl.connect = Some(target);
            }
            "-c" | "--command" => {
                let command = argv
                    .next()
                    .ok_or_else(|| format!("{arg} requires a command argument"))?;
                repl.commands.push(command);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if daemon {
        return Ok(Some(Mode::Daemon));
    }
    Ok(Some(Mode::Repl(repl)))
}

#[cfg(feature = "embedded")]
fn main() {
    let mode = match parse_args() {
        Ok(Some(mode)) => mode,
        Ok(None) => {
            println!("{USAGE}");
            return;
        }
        Err(e) => {
            eprintln!("ikigai: {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    // The default instance name follows the mode; an explicit --name (already
    // set during parsing) wins because set_instance_name is first-write-wins.
    #[cfg(feature = "embedded")]
    ikigai_embedded::set_instance_name(match &mode {
        Mode::Daemon => "daemon",
        Mode::Serve { .. } => "serve",
        Mode::Mcp { .. } => "mcp",
        _ => "repl",
    });

    match mode {
        Mode::Daemon => daemon(),
        Mode::Mcp { grants, scopes } => mcp(grants, scopes),
        Mode::CertGenerate { force } => cert_generate(force),
        Mode::Serve { target, certs } => match target.as_deref() {
            Some(t) if is_quic(t) => serve_quic(t, &certs),
            _ => serve_ipc(target),
        },
        Mode::Repl(args) => {
            // `--demo` seeds the runtime demo flag; `demo on`/`off` (→ urn:host:demo)
            // toggles it thereafter. The runbook is gated on it, off by default.
            if args.demo {
                ikigai_embedded::demo_flag().store(true, std::sync::atomic::Ordering::SeqCst);
            }
            let engine = build_engine(args.connect, &args.certs).unwrap_or_else(|e| {
                eprintln!("ikigai: {e}");
                std::process::exit(1);
            });
            run_repl(engine, args.plain, &args.commands);
        }
    }
}

/// Headless mode: build the watched kernel — the filesystem watcher, the time
/// transport, and (via calendar.json's `derive_every`) the standing
/// consolidated-view sync all live in it — then park. This is what a
/// LaunchAgent runs: the desktop machine as a quiet, always-on resolver.
#[cfg(feature = "embedded")]
fn daemon() {
    // watched_kernel(), NOT kernel_for(): the watchers, the time transport's
    // kernel handle, and the standing-sync registration all live in the
    // watched constructor — a bare served-space kernel would park with the
    // banner up and nothing actually scheduled.
    let kernel = ikigai_embedded::watched_kernel();
    let name = ikigai_embedded::instance_name();
    match ikigai_embedded::standing_sync_interval() {
        Some(every) => eprintln!(
            "ikigai: daemon up — instance \"{name}\": standing sync every {}s + watchers (Ctrl-C to stop)",
            every.as_secs()
        ),
        None => eprintln!(
            "ikigai: daemon up — instance \"{name}\": no \"{name}.derive_every\" in calendar.json — IDLE (Ctrl-C to stop)"
        ),
    }
    // Catch up immediately: the interval timer waits a full period before its
    // first pass, and a daemon coming up after downtime is exactly when a
    // derive is most wanted (it also makes a fresh deploy verifiable now, not
    // in five minutes).
    ikigai_embedded::startup_derive(&kernel);
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

#[cfg(not(feature = "embedded"))]
fn daemon() {
    eprintln!("ikigai: --daemon requires the embedded feature");
    std::process::exit(2);
}

/// MCP stdio mode: project the composed manifold as MCP tools, scoped to the
/// session capability built from `--grant`/`--scope`. The grant is the ceiling.
#[cfg(feature = "embedded")]
fn mcp(grants: Vec<String>, scopes: Vec<String>) {
    use ikigai_core::Capability;
    let mut union = scopes;
    for name in &grants {
        let found = ikigai_embedded::grant_scopes(name);
        if found.is_empty() {
            eprintln!("ikigai mcp: grant \"{name}\" is empty or undefined in grants.json");
        }
        union.extend(found);
    }
    union.sort();
    union.dedup();
    let capability = if union.is_empty() {
        eprintln!(
            "ikigai mcp: no --grant/--scope given — running UNRESTRICTED (root). \
             Pass a grant to scope the tool list."
        );
        Capability::root()
    } else {
        eprintln!(
            "ikigai mcp: serving the manifold under {} scope(s)",
            union.len()
        );
        Capability::scoped(union)
    };
    let kernel = ikigai_embedded::watched_kernel();
    if let Err(e) = ikigai_mcp::server::serve(&kernel, &capability) {
        eprintln!("ikigai mcp: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "embedded"))]
fn mcp(_grants: Vec<String>, _scopes: Vec<String>) {
    eprintln!("ikigai: mcp requires the embedded feature");
    std::process::exit(2);
}

/// Register the demo capability profiles on an engine (so `cap freebusy` reads
/// friendlier than a scope list). Applied to every backend — embedded and, over
/// IPC, the capability is carried to the server so it takes effect there too.
#[cfg(feature = "embedded")]
fn with_profiles(engine: Engine) -> Engine {
    engine.define_cap_profile("freebusy", ["urn:cap:personal:calendar:read:freebusy"]);

    // File capability profiles, scoped to the local file module's jail root. Each
    // is a single-step narrowing from the owner's root authority — `cap write`
    // grants read+write within the root, `cap read-only` drops writes. `cap agent`
    // bundles the cross-cutting "what I'd hand an agent" set (free/busy + read).
    let root = ikigai_embedded::file_root();
    let root = root.display();
    let read = format!("urn:cap:fs:read:{root}");
    let write = format!("urn:cap:fs:write:{root}");
    let delete = format!("urn:cap:fs:delete:{root}");
    engine.define_cap_profile("read-only", [read.clone()]);
    engine.define_cap_profile("read", [read.clone()]);
    engine.define_cap_profile("write", [read.clone(), write.clone()]);
    engine.define_cap_profile("delete", [read.clone(), write, delete]);
    engine.define_cap_profile(
        "agent",
        ["urn:cap:personal:calendar:read:freebusy".to_string(), read],
    );
    engine
}

/// Build the engine over the chosen backend: the embedded kernel, or — with
/// `--connect` — an IPC or QUIC client, dispatched by the target.
#[cfg(feature = "embedded")]
fn build_engine(connect: Option<Option<String>>, certs: &Certs) -> Result<Engine, String> {
    match connect {
        // The watched kernel: cached workspace reads also invalidate on an
        // out-of-band file change (an editor), not just a `sink` through the REPL.
        // The same process scheduler drives both the kernel's fan-out and the
        // engine's `( a ; b )` / `..` parallelism, so `IKIGAI_SCHEDULER=pool:N`
        // governs all of it.
        None => Ok(with_profiles(
            Engine::new(ikigai_embedded::watched_kernel())
                .with_spawner(std::sync::Arc::new(ikigai_embedded::scheduler())),
        )),
        Some(target) => match target.as_deref() {
            Some(t) if is_quic(t) => connect_quic(t, certs),
            _ => connect_ipc(target),
        },
    }
}

/// Drive the engine: one-shot `-c`, else the full-screen TUI on a terminal, else
/// the line REPL.
#[cfg(feature = "embedded")]
fn run_repl(engine: Engine, plain: bool, commands: &[String]) {
    if !commands.is_empty() {
        std::process::exit(repl::run_commands(engine, commands));
    }
    #[cfg(not(target_family = "wasm"))]
    {
        use std::io::IsTerminal;
        if !plain && std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            // The keybinding scheme is read before entering the alternate screen
            // so an unsupported-value notice is visible.
            if let Err(e) = tui::run(engine, ikigai_engine::config::keybindings()) {
                eprintln!("ikigai: tui error: {e}");
                std::process::exit(1);
            }
            return;
        }
        repl::run(engine);
    }
    #[cfg(target_family = "wasm")]
    repl::run(engine);
}

// --- `cert generate` --------------------------------------------------------

#[cfg(all(feature = "embedded", feature = "quic"))]
fn cert_generate(force: bool) -> ! {
    match quic::generate(force) {
        Ok(dir) => {
            println!(
                "wrote server.{{crt,key}} and client.{{crt,key}} to {}",
                dir.display()
            );
            println!(
                "to attach a client on another machine, copy client.crt, client.key, and \
                 server.crt there."
            );
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("ikigai: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(all(feature = "embedded", not(feature = "quic")))]
fn cert_generate(_force: bool) -> ! {
    eprintln!("ikigai: `cert generate` needs the `quic` feature");
    std::process::exit(1);
}

// --- QUIC serve / connect ---------------------------------------------------

#[cfg(all(feature = "embedded", feature = "quic"))]
fn serve_quic(target: &str, certs: &Certs) -> ! {
    let result = (|| -> Result<(), String> {
        let addr = quic::parse_addr(target)?;
        let identity = quic::server_identity(certs)?;
        let trusted = quic::trusted_client_certs(certs)?;
        // Multi-tenant capability-on-the-wire: every connection is scoped to the
        // authenticated client's own workspace segment, minted per-connection from
        // *which* certificate authenticated. The cert IS the credential — the same
        // identity→capability move as the browser passkey, over mTLS. Each tenant
        // addresses files transparently under its own root (`urn:file:notes.txt`), and
        // `source urn:host:identity` reports its `<id>`.
        let root = ikigai_embedded::file_root();
        let minter: std::sync::Arc<dyn Fn(&str) -> ikigai_quic::Session + Send + Sync> =
            std::sync::Arc::new(move |id: &str| {
                let segment = root.join(id);
                let _ = std::fs::create_dir_all(&segment); // the tenant's private dir
                let seg = segment.display();
                ikigai_quic::Session {
                    capability: ikigai_core::Capability::root().attenuate([
                        format!("urn:cap:fs:read:{seg}"),
                        format!("urn:cap:fs:write:{seg}"),
                        format!("urn:cap:fs:delete:{seg}"),
                    ]),
                    file_segment: id.to_string(),
                }
            });
        eprintln!(
            "ikigai: serving on {target}  (per-client workspaces; {} trusted client cert(s))  (Ctrl-C to stop)",
            trusted.len()
        );
        ikigai_quic::serve(
            ikigai_embedded::kernel_for("Remote (QUIC)"),
            addr,
            &identity,
            &trusted,
            minter,
        )
        .map_err(|e| e.to_string())
    })();
    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("ikigai: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(all(feature = "embedded", feature = "quic"))]
fn connect_quic(target: &str, certs: &Certs) -> Result<Engine, String> {
    let addr = quic::parse_addr(target)?;
    let identity = quic::client_identity(certs)?;
    let trusted = quic::trusted_server_cert(certs)?;
    let resolver = ikigai_quic::connect(addr, &identity, &trusted)
        .map_err(|e| format!("connect {target}: {e}"))?;
    Ok(with_profiles(Engine::new(resolver)))
}

#[cfg(all(feature = "embedded", not(feature = "quic")))]
fn serve_quic(_target: &str, _certs: &Certs) -> ! {
    eprintln!("ikigai: `quic://` needs the `quic` feature");
    std::process::exit(1);
}

#[cfg(all(feature = "embedded", not(feature = "quic")))]
fn connect_quic(_target: &str, _certs: &Certs) -> Result<Engine, String> {
    Err("`quic://` needs the `quic` feature".to_string())
}

// --- IPC serve / connect ----------------------------------------------------

#[cfg(all(feature = "embedded", feature = "ipc", unix))]
fn serve_ipc(path: Option<String>) -> ! {
    let socket = ipc_socket(path);
    eprintln!("ikigai: serving on {}  (Ctrl-C to stop)", socket.display());
    match ikigai_ipc::serve(ikigai_embedded::trusted_kernel_for("Remote (IPC)"), &socket) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("ikigai: serve error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(all(feature = "embedded", feature = "ipc", unix))]
fn connect_ipc(path: Option<String>) -> Result<Engine, String> {
    let socket = ipc_socket(path);
    let resolver =
        ikigai_ipc::connect(&socket).map_err(|e| format!("connect {}: {e}", socket.display()))?;
    Ok(with_profiles(Engine::new(resolver)))
}

/// Resolve an explicit Unix socket path, or the secure default, exiting if
/// neither is available.
#[cfg(all(feature = "embedded", feature = "ipc", unix))]
fn ipc_socket(path: Option<String>) -> std::path::PathBuf {
    path.map(std::path::PathBuf::from)
        .or_else(ikigai_ipc::default_socket_path)
        .unwrap_or_else(|| {
            eprintln!("ikigai: no socket path given and no runtime directory to default to");
            std::process::exit(2);
        })
}

#[cfg(all(feature = "embedded", not(all(feature = "ipc", unix))))]
fn serve_ipc(_path: Option<String>) -> ! {
    eprintln!("ikigai: a Unix-socket server needs the `ipc` feature on a Unix platform");
    std::process::exit(1);
}

#[cfg(all(feature = "embedded", not(all(feature = "ipc", unix))))]
fn connect_ipc(_path: Option<String>) -> Result<Engine, String> {
    Err("attaching to a Unix socket needs the `ipc` feature on a Unix platform".to_string())
}

#[cfg(not(feature = "embedded"))]
fn main() {
    eprintln!(
        "ikigai {}: built without a transport. Rebuild with a transport feature, e.g. `--features embedded`.",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(1);
}
