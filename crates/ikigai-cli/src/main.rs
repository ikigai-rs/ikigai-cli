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
#[cfg(feature = "web")]
mod route_load;
#[cfg(not(target_family = "wasm"))]
mod tui;

const USAGE: &str = "\
ikigai — resource-resolution REPL

usage:
  ikigai                       start the interactive REPL (full-screen on a terminal)
  ikigai --plain               force the line REPL (also used automatically when piped)
  ikigai --demo                mount the interactive runbook (urn:runbook:*); off by default
  ikigai --connect [<target>]  attach the REPL to a kernel server (a Unix path, or quic://host:port)
  ikigai --mount <pfx>=<tgt>   compose a remote kernel at prefix <pfx> (<tgt> = Unix path or quic://host:port)
  ikigai serve [<target>]      run a kernel server (a Unix socket path, or quic://addr to bind)
  ikigai serve <q> --cap <s>   serve under a fixed capability ceiling <s> every client is clamped to
  ikigai serve <q> --announce  also advertise this kernel on the local network (mDNS), so clients
                               can mount it by name; `source urn:peer:list` shows who is out there
  ikigai serve <s> --prefer …  a served host may take --mount/--override/--prefer too, so IT owns
                               the topology: a local client reaches a peer through this socket
                               without holding its certs or finding it itself
  ikigai serve … --code-signer <k>  accept SIGNED programs (urn:lisp:run) vouched for by key
                               resource <k> (repeatable; --code-signers-dir sets where
                               urn:codekey:{file} reads from). Without it the door is unbound.
  ikigai serve … --eval-timeout <s>  wall-clock ceiling for a served eval (default 10s)
  ikigai serve --http <port>   serve the inbound HTTP face (loopback; front with TLS at your proxy)
                               [--trust-proxy: honor X-Forwarded-*; --cors-origin <o>: allow a CORS origin;
                                --routes <iri>: load routes from an RDF or plain-JSON resource
                                (a urn:file: route hot-reloads); --routes-only: un-routed → 404]
  ikigai --daemon              headless: timers, the watcher, and the standing sync — for launchd
  ikigai --name <instance>     name this instance (scopes <name>.* config properties; defaults
                               repl / daemon / serve by mode)
  ikigai --mount <p>=<t>       graft a remote namespace at prefix <p> (ALIAS: <p>rest → urn:rest
                               on the remote, tried after local; --cert-dir after it is ITS cert set)
  ikigai --override <p>=<t>    the SAME namespace, served remotely: IRIs forward unchanged and win
                               over local. <p> may be a whole IRI, so a single resource can be
                               rerouted; the most specific override wins
  ikigai --prefer <p>=<t>      like --override, but falls back to the LOCAL binding when the peer
                               is unreachable (transient failures only; denials still propagate)
  <t> = peer:<name>            find that peer on the local network (mDNS) instead of naming an
                               address; needs a pinned cert at <config>/ikigai/quic-<name>/
  ikigai --react               run the space reactor in this session — claims and executes tuples
                               dropped in the workspace. OFF by default; the daemon is the worker
  ikigai cert generate         create the pinned QUIC certificates (--dir <d> for a dedicated set)
  ikigai cert add-client <n>   mint an extra client identity into clients/<n>.{crt,key}
  ikigai -c '<command>' ...    run command(s) non-interactively, then exit
  ikigai -e '<sexpr>' ...       evaluate a Lisp s-expression (urn:lisp:eval), then exit
  ikigai --load <uri> [--cap <s>]  read a script resource and evaluate it as Lisp (--cap narrows first)
  ikigai -h | --help           show this help

QUIC: --server-cert/--server-key name the server's identity, --client-cert/--client-key the client's
inside the REPL: source, describe, help, quit (type `help` for details)";

use ikigai_engine::Engine;

/// Per-role certificate-path overrides for QUIC, shared by `serve` and `--connect`.
/// `cert_dir` relocates the whole set (the four default filenames + the `clients/`
/// trust dir) so a dedicated identity — e.g. a calendar-federation server — lives in
/// its own directory instead of the default `<config>/ikigai-cli/quic/`. The
/// per-file overrides still win over the directory default.
#[derive(Default, Clone)]
struct Certs {
    cert_dir: Option<String>,
    server_cert: Option<String>,
    server_key: Option<String>,
    client_cert: Option<String>,
    client_key: Option<String>,
}

/// What the CLI was asked to do.
enum Mode {
    Repl(ReplArgs),
    /// Headless: build the watched kernel (timers, watcher, the standing sync)
    /// and park — the launchd-agent face of the desktop machine. Carries any
    /// `--mount`s so the standing DRAIN has an edge to pull from — without them the
    /// drain job fires against a kernel that cannot resolve `urn:edge:` and pulls nothing.
    Daemon {
        /// Each mount carries its own certificates, so the daemon needs no
        /// default set of its own (it never `--connect`s).
        mounts: Vec<Mount>,
    },
    Serve {
        target: Option<String>,
        certs: Certs,
        /// `--cap <scope>` (repeatable): a fixed capability ceiling every
        /// authenticated client is clamped to, instead of the default per-tenant
        /// filesystem workspace. This is how a server shares exactly one narrow
        /// affordance — e.g. `--cap urn:cap:personal:calendar:read:freebusy` serves
        /// free/busy and nothing else, the clamp forbidding any client from widening.
        caps: Vec<String>,
        /// `--http <port|addr>`: serve the inbound HTTP face instead of IPC/QUIC.
        /// A bare port binds `127.0.0.1:<port>` (loopback — TLS terminates at the
        /// fronting proxy, e.g. Apache); a full `host:port` overrides the bind.
        http: Option<String>,
        /// `--trust-proxy`: honor `X-Forwarded-Proto`/`-For` from the upstream (enable
        /// ONLY behind a proxy you control, e.g. Apache). Drives HTTPS detection for HSTS.
        trust_proxy: bool,
        /// `--cors-origin <origin>` (repeatable): allow this cross-origin (exact, or `*`).
        /// Empty = CORS closed (the safe default).
        cors_origins: Vec<String>,
        /// `--routes <iri>`: load the route table from this RDF resource (`ik:Route` graph),
        /// e.g. `urn:web:routes` or a watched `urn:file:web/routes.ttl`.
        routes: Option<String>,
        /// `--routes-only`: an un-routed path 404s instead of falling through to the mechanical
        /// default — the route table becomes an exhaustive allow-list (the public-edge posture).
        routes_only: bool,
        /// `--announce`: advertise this kernel on the local network over mDNS, so clients
        /// can mount it by name instead of by an address that moves. Opt-in — broadcasting
        /// what a machine serves is a disclosure.
        announce: bool,
        /// Remote kernels composed into the served surface (`--mount`/`--override`/
        /// `--prefer`, same syntax as the REPL). THE HOST OWNS THE TOPOLOGY: a local client
        /// then reaches a peer through this socket without knowing where it is, holding its
        /// certificates, or needing the platform permission discovery requires.
        mounts: Vec<Mount>,
    },
    /// Serve the capability-scoped manifold as an MCP (Model Context Protocol)
    /// server over stdio. `grants`/`scopes` union into the session capability —
    /// the ceiling on the tools an MCP client sees and can call.
    Mcp {
        grants: Vec<String>,
        scopes: Vec<String>,
        /// Remote kernels composed into the projected manifold (`--mount`/`--override`/
        /// `--prefer`, same syntax as the REPL; no flags ⇒ the machine's own topology
        /// from the config home). A federated mount is most useful HERE: the MCP
        /// client gets tools that resolve on a peer without holding its certificates.
        mounts: Vec<Mount>,
    },
    CertGenerate {
        force: bool,
        /// `--dir <d>`: write the pair into `<d>` instead of the default quic dir, so a
        /// dedicated identity (a calendar server, say) doesn't clobber the default pair.
        dir: Option<String>,
    },
    /// `cert add-client <name>`: mint an ADDITIONAL client identity into
    /// `<certdir>/clients/<name>.{crt,key}`. The server already trusts every
    /// `clients/*.crt`, so this is how you add a second device/principal without
    /// touching the existing certs. (What AUTHORITY each gets is the identity→grant
    /// policy — a later step; today every trusted client shares the server's ceiling.)
    CertAddClient {
        name: String,
        cert_dir: Option<String>,
        force: bool,
    },
}

/// Options for the REPL mode.
#[derive(Default, Clone)]
struct ReplArgs {
    plain: bool,
    /// Mount the interactive runbook (`urn:runbook:*`); off by default so the CLI is
    /// a tool, not a demo. Only meaningful for the embedded (non-`--connect`) kernel.
    demo: bool,
    commands: Vec<String>,
    /// `None` = the embedded in-process kernel; `Some` = attach to a server, with
    /// `Some(None)` meaning the default Unix socket.
    connect: Option<Option<String>>,
    /// Remote kernels to compose into the local one, from `--mount <prefix>=<target>`
    /// (a Unix socket path or a `quic://host:port` URL). Each mounts a `RemoteSpace`
    /// so a resource under `prefix` resolves on the remote kernel. Embedded
    /// (non-`--connect`) only. Each carries its OWN certificates — distinct peers
    /// never share a cert set.
    mounts: Vec<Mount>,
    certs: Certs,
    /// Run the space reactor in this session (`--react`), claiming and executing tuples
    /// dropped into the workspace. OFF by default: reacting means competing with the
    /// writer daemon for the same queue, under whatever identity and grants this process
    /// happens to have. For demonstrating the tuplespace on a machine with no daemon —
    /// never alongside one.
    react: bool,
}

/// One `--mount`: where it binds, what it connects to, and the certificates for
/// THAT connection. Cert flags following a `--mount` attach to it; cert flags
/// before any mount form the default set (used by `--connect`, and by a mount
/// that declares none of its own).
#[derive(Clone)]
struct Mount {
    prefix: String,
    target: String,
    certs: Certs,
    kind: ikigai_embedded::MountKind,
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
        "--cert-dir" => &mut certs.cert_dir,
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
    parse_argv(std::env::args().skip(1))
}

/// The argument parser proper, over any argv — so it can be tested without a
/// process (which is how the per-mount certificate behaviour below is pinned).
fn parse_argv(args: impl Iterator<Item = String>) -> Result<Option<Mode>, String> {
    let mut argv = args.peekable();

    if argv.peek().map(String::as_str) == Some("cert") {
        argv.next();
        return match argv.next().as_deref() {
            Some("generate") => {
                let mut force = false;
                let mut dir = None;
                while let Some(arg) = argv.next() {
                    match arg.as_str() {
                        "--force" => force = true,
                        "--dir" => {
                            dir = Some(
                                argv.next()
                                    .ok_or_else(|| "--dir needs a path".to_string())?,
                            )
                        }
                        other => {
                            return Err(format!("unknown argument after `cert generate`: {other}"))
                        }
                    }
                }
                Ok(Some(Mode::CertGenerate { force, dir }))
            }
            Some("add-client") => {
                let mut name = None;
                let mut cert_dir = None;
                let mut force = false;
                while let Some(arg) = argv.next() {
                    match arg.as_str() {
                        "--force" => force = true,
                        "--cert-dir" => {
                            cert_dir = Some(
                                argv.next()
                                    .ok_or_else(|| "--cert-dir needs a path".to_string())?,
                            )
                        }
                        other if other.starts_with('-') => {
                            return Err(format!(
                                "unknown argument after `cert add-client`: {other}"
                            ))
                        }
                        _ if name.is_none() => name = Some(arg),
                        other => {
                            return Err(format!(
                                "unexpected argument after `cert add-client`: {other}"
                            ))
                        }
                    }
                }
                let name =
                    name.ok_or_else(|| "usage: `ikigai cert add-client <name>`".to_string())?;
                Ok(Some(Mode::CertAddClient {
                    name,
                    cert_dir,
                    force,
                }))
            }
            Some(other) => Err(format!("unknown `cert` subcommand: {other}")),
            None => {
                Err("usage: `ikigai cert generate` | `ikigai cert add-client <name>`".to_string())
            }
        };
    }

    if argv.peek().map(String::as_str) == Some("serve") {
        argv.next();
        let mut target = None;
        let mut certs = Certs::default();
        let mut caps = Vec::new();
        let mut code_signers: Vec<String> = Vec::new();
        let mut http = None;
        let mut trust_proxy = false;
        let mut cors_origins = Vec::new();
        let mut routes = None;
        let mut routes_only = false;
        let mut announce = false;
        let mut mounts: Vec<Mount> = Vec::new();
        while let Some(arg) = argv.next() {
            if cert_flag(&arg, &mut argv, &mut certs)? {
                // A cert flag FOLLOWING a mount belongs to that mount (the REPL's rule),
                // so two peers with different identities never share a set. Flags before
                // any mount are this server's own identity.
                if let Some(mount) = mounts.last_mut() {
                    mount.certs = certs.clone();
                }
                continue;
            }
            if arg == "--announce" {
                announce = true;
                continue;
            }
            if let Some(kind) = match arg.as_str() {
                "--mount" => Some(ikigai_embedded::MountKind::Alias),
                "--override" => Some(ikigai_embedded::MountKind::Override),
                "--prefer" => Some(ikigai_embedded::MountKind::Prefer),
                _ => None,
            } {
                let spec = argv
                    .next()
                    .ok_or_else(|| format!("{arg} needs <prefix>=<target>"))?;
                let (prefix, target) = spec
                    .split_once('=')
                    .ok_or_else(|| format!("{arg} expects <prefix>=<target>, got `{spec}`"))?;
                // Cert flags AFTER a mount attach to it (same rule as the REPL), so two
                // peers with different identities never share a cert set.
                mounts.push(Mount {
                    prefix: prefix.to_string(),
                    target: target.to_string(),
                    certs: certs.clone(),
                    kind,
                });
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
            if arg == "--cap" {
                caps.push(
                    argv.next()
                        .ok_or_else(|| "--cap needs a capability IRI".to_string())?,
                );
                continue;
            }
            // Wire-eval L1.5: whose signatures this host will run programs for.
            // Repeatable, like --cap. With none given, urn:lisp:run isn't bound.
            if arg == "--code-signer" {
                let signer = argv
                    .next()
                    .ok_or_else(|| "--code-signer needs a key resource IRI".to_string())?;
                code_signers.push(signer);
                continue;
            }
            if arg == "--code-signers-dir" {
                let dir = argv
                    .next()
                    .ok_or_else(|| "--code-signers-dir needs a path".to_string())?;
                #[cfg(feature = "embedded")]
                ikigai_embedded::set_code_signers_dir(std::path::PathBuf::from(dir));
                #[cfg(not(feature = "embedded"))]
                let _ = dir;
                continue;
            }
            if arg == "--eval-timeout" {
                let secs = argv
                    .next()
                    .ok_or_else(|| "--eval-timeout needs seconds".to_string())?
                    .parse::<u64>()
                    .map_err(|_| "--eval-timeout needs a whole number of seconds".to_string())?;
                #[cfg(feature = "embedded")]
                ikigai_embedded::set_eval_timeout_secs(secs);
                #[cfg(not(feature = "embedded"))]
                let _ = secs;
                continue;
            }
            if arg == "--http" {
                http = Some(
                    argv.next()
                        .ok_or_else(|| "--http needs a port or host:port".to_string())?,
                );
                continue;
            }
            if arg == "--trust-proxy" {
                trust_proxy = true;
                continue;
            }
            if arg == "--cors-origin" {
                cors_origins.push(
                    argv.next()
                        .ok_or_else(|| "--cors-origin needs an origin (or `*`)".to_string())?,
                );
                continue;
            }
            if arg == "--routes" {
                routes = Some(
                    argv.next()
                        .ok_or_else(|| "--routes needs a resource IRI".to_string())?,
                );
                continue;
            }
            if arg == "--routes-only" {
                routes_only = true;
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
        // Declare the code-signing trust set for whichever serve mode follows:
        // process-global, like the instance name, and read by the kernel
        // builders. Empty ⇒ urn:lisp:run is never bound.
        #[cfg(feature = "embedded")]
        ikigai_embedded::set_code_signers(code_signers);
        #[cfg(not(feature = "embedded"))]
        let _ = code_signers;
        return Ok(Some(Mode::Serve {
            target,
            certs,
            caps,
            http,
            trust_proxy,
            cors_origins,
            routes,
            routes_only,
            announce,
            mounts,
        }));
    }

    if argv.peek().map(String::as_str) == Some("mcp") {
        argv.next();
        let mut grants = Vec::new();
        let mut scopes = Vec::new();
        let mut certs = Certs::default();
        let mut mounts: Vec<Mount> = Vec::new();
        while let Some(arg) = argv.next() {
            // Cert flags AFTER a mount attach to it (the REPL's rule), so two peers
            // with different identities never share a set. mcp never `--connect`s,
            // so there is no default-set use for flags before any mount.
            if cert_flag(&arg, &mut argv, &mut certs)? {
                if let Some(mount) = mounts.last_mut() {
                    mount.certs = certs.clone();
                }
                continue;
            }
            if let Some(kind) = match arg.as_str() {
                "--mount" => Some(ikigai_embedded::MountKind::Alias),
                "--override" => Some(ikigai_embedded::MountKind::Override),
                "--prefer" => Some(ikigai_embedded::MountKind::Prefer),
                _ => None,
            } {
                let spec = argv
                    .next()
                    .ok_or_else(|| format!("{arg} needs <prefix>=<target>"))?;
                let (prefix, target) = spec
                    .split_once('=')
                    .ok_or_else(|| format!("{arg} expects <prefix>=<target>, got `{spec}`"))?;
                mounts.push(Mount {
                    prefix: prefix.to_string(),
                    target: target.to_string(),
                    certs: certs.clone(),
                    kind,
                });
                continue;
            }
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
        return Ok(Some(Mode::Mcp {
            grants,
            scopes,
            mounts,
        }));
    }

    let mut repl = ReplArgs::default();
    let mut daemon = false;
    while let Some(arg) = argv.next() {
        // Certificates attach to the mount they FOLLOW — `--mount a=X --cert-dir A
        // --mount b=Y --cert-dir B` gives each peer its own set (which is what
        // ikigai-emacs has always emitted). Before any mount, they form the
        // default set: what `--connect` uses, and what a later mount inherits.
        let cert_target = match repl.mounts.last_mut() {
            Some(mount) => &mut mount.certs,
            None => &mut repl.certs,
        };
        if cert_flag(&arg, &mut argv, cert_target)? {
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
            "--mount" => {
                // `--mount <prefix>=<socket>`: compose a remote kernel at `<prefix>`.
                let spec = argv
                    .next()
                    .ok_or_else(|| "--mount needs <prefix>=<socket>".to_string())?;
                let (prefix, socket) = spec
                    .split_once('=')
                    .ok_or_else(|| format!("--mount expects <prefix>=<socket>, got `{spec}`"))?;
                // Inherit whatever cert flags preceded this mount; any that FOLLOW
                // it refine this mount alone (see the cert_flag dispatch above).
                repl.mounts.push(Mount {
                    prefix: prefix.to_string(),
                    target: socket.to_string(),
                    certs: repl.certs.clone(),
                    kind: ikigai_embedded::MountKind::Alias,
                });
            }
            "--override" => {
                // `--override <prefix>=<target>`: the SAME namespace, served by the
                // remote. Unlike `--mount` the IRI is forwarded verbatim and the
                // mount is tried BEFORE local spaces, so `--override
                // urn:llm:=quic://peer:4433` sends `urn:llm:ask` to the peer even
                // though this kernel binds it too — no alias, nothing to rewrite at
                // the call site.
                let spec = argv
                    .next()
                    .ok_or_else(|| "--override needs <prefix>=<target>".to_string())?;
                let (prefix, target) = spec
                    .split_once('=')
                    .ok_or_else(|| format!("--override expects <prefix>=<target>, got `{spec}`"))?;
                repl.mounts.push(Mount {
                    prefix: prefix.to_string(),
                    target: target.to_string(),
                    certs: repl.certs.clone(),
                    kind: ikigai_embedded::MountKind::Override,
                });
            }
            "--react" => {
                repl.react = true;
            }
            "--prefer" => {
                // `--prefer <prefix>=<target>`: an override that DEGRADES. The
                // remote answers when it can; a transient failure (peer asleep,
                // network gone) falls through to this machine's own binding. A
                // capability denial is NOT transient and still propagates, and a
                // mutating verb is never replayed.
                let spec = argv
                    .next()
                    .ok_or_else(|| "--prefer needs <prefix>=<target>".to_string())?;
                let (prefix, target) = spec
                    .split_once('=')
                    .ok_or_else(|| format!("--prefer expects <prefix>=<target>, got `{spec}`"))?;
                repl.mounts.push(Mount {
                    prefix: prefix.to_string(),
                    target: target.to_string(),
                    certs: repl.certs.clone(),
                    kind: ikigai_embedded::MountKind::Prefer,
                });
            }
            "-c" | "--command" => {
                let command = argv
                    .next()
                    .ok_or_else(|| format!("{arg} requires a command argument"))?;
                repl.commands.push(command);
            }
            "-e" | "--eval" => {
                // Evaluate a Lisp s-expression: pushed verbatim into the command
                // stream, where the engine's paren-sniff routes it to urn:lisp:eval.
                // Runs in argv order alongside any `-c`/`--load`, then the process exits.
                let sexpr = argv
                    .next()
                    .ok_or_else(|| format!("{arg} requires an s-expression argument"))?;
                repl.commands.push(sexpr);
            }
            "--load" => {
                // `--load <uri> [--cap <scope>]`: read a script resource and evaluate
                // it as Lisp. Synthesized into the engine's `:load` command so the CLI
                // and REPL share one path; `--cap` becomes the `cap=<scope>` narrowing.
                let uri = argv
                    .next()
                    .ok_or_else(|| "--load requires a <uri> argument".to_string())?;
                let mut command = format!(":load {uri}");
                if argv.peek().map(String::as_str) == Some("--cap") {
                    argv.next();
                    let scope = argv
                        .next()
                        .ok_or_else(|| "--cap requires a capability scope".to_string())?;
                    command.push_str(&format!(" cap={scope}"));
                }
                repl.commands.push(command);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if daemon {
        return Ok(Some(Mode::Daemon {
            mounts: repl.mounts,
        }));
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
        Mode::Daemon { .. } => "daemon",
        Mode::Serve { .. } => "serve",
        Mode::Mcp { .. } => "mcp",
        _ => "repl",
    });

    match mode {
        Mode::Daemon { mounts } => daemon(mounts),
        Mode::Mcp {
            grants,
            scopes,
            mounts,
        } => mcp(grants, scopes, mounts),
        Mode::CertGenerate { force, dir } => cert_generate(force, dir),
        Mode::CertAddClient {
            name,
            cert_dir,
            force,
        } => cert_add_client(&name, cert_dir, force),
        Mode::Serve {
            target,
            certs,
            caps,
            announce,
            mounts,
            http,
            trust_proxy,
            cors_origins,
            routes,
            routes_only,
        } => match (http, target.as_deref()) {
            // The inbound HTTP face takes precedence over IPC/QUIC when `--http` is given.
            (Some(bind), _) => serve_http(
                &bind,
                &caps,
                trust_proxy,
                &cors_origins,
                routes.as_deref(),
                routes_only,
            ),
            (None, Some(t)) if is_quic(t) => serve_quic(t, &certs, &caps, announce),
            (None, _) if !caps.is_empty() => {
                eprintln!("ikigai: --cap sets a per-connection ceiling and needs a quic:// target");
                std::process::exit(2);
            }
            (None, _) => serve_ipc(target, mounts),
        },
        Mode::Repl(args) => {
            // `--demo` seeds the runtime demo flag; `demo on`/`off` (→ urn:host:demo)
            // toggles it thereafter. The runbook is gated on it, off by default.
            if args.demo {
                ikigai_embedded::demo_flag().store(true, std::sync::atomic::Ordering::SeqCst);
            }
            let engine = build_engine(args.connect, args.mounts, &args.certs, args.react)
                .unwrap_or_else(|e| {
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
fn daemon(mounts: Vec<Mount>) {
    // No mount flags -> the machine's own topology (config home), same rule as every
    // kernel-building mode. The booking picker asking urn:llm:ask in THIS process is
    // exactly who a `mount = "prefer urn:llm:=peer:plasma"` line is for.
    let mounts = match mounts_or_config(mounts) {
        Ok(mounts) => mounts,
        // A topology that does not parse must never look like no topology.
        Err(e) => {
            eprintln!("ikigai: {e}");
            std::process::exit(2);
        }
    };
    // watched_kernel(), NOT kernel_for(): the watchers, the time transport's
    // kernel handle, and the standing-sync registration all live in the
    // watched constructor — a bare served-space kernel would park with the
    // banner up and nothing actually scheduled.
    //
    // Compose any `--mount`s into that kernel, exactly as the REPL path does. This is what
    // the standing drain resolves `urn:edge:` through; a daemon that ignored its mounts
    // would schedule the drain and then pull nothing from a prefix it cannot resolve.
    // The daemon IS the worker: it holds the reactive kernel, so the workspace's tuples
    // are claimed and run here, under this signed job's identity and grants.
    let kernel = if mounts.is_empty() {
        ikigai_embedded::reactive_kernel_with_mounts(Vec::new())
    } else {
        let mut resolved = Vec::new();
        for mount in mounts {
            // Each mount connects with ITS OWN certificates.
            let target = mount.target.clone();
            match resolve_mount(mount) {
                Ok(spec) => resolved.push(spec),
                // A mount that will not connect is fatal here: the daemon's whole reason to
                // hold a mount is the drain, and a silent no-op is the failure mode this is
                // fixing. Say so and exit rather than park looking healthy. (A --prefer
                // mount never lands here — it connects on demand, by design.)
                Err(e) => {
                    eprintln!("ikigai: --mount {target}: {e}");
                    std::process::exit(2);
                }
            }
        }
        ikigai_embedded::reactive_kernel_with_mounts(resolved)
    };
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
fn daemon(_mounts: Vec<Mount>) {
    eprintln!("ikigai: --daemon requires the embedded feature");
    std::process::exit(2);
}

/// Build the session capability from the union of named grants + explicit
/// scopes. Empty ⇒ root (unrestricted). The grant is the ceiling.
#[cfg(feature = "embedded")]
fn mcp_capability(grants: &[String], scopes: &[String]) -> ikigai_core::Capability {
    let mut union: Vec<String> = scopes.to_vec();
    for name in grants {
        union.extend(ikigai_embedded::grant_scopes(name));
    }
    union.sort();
    union.dedup();
    if union.is_empty() {
        ikigai_core::Capability::root()
    } else {
        ikigai_core::Capability::scoped(union)
    }
}

/// Build the tool-visibility filter from the named grants — the union of their
/// `show`/`hide` globs. Distinct from [`mcp_capability`]: authority decides what
/// the session may call; this decides what the projected tool list bothers to
/// show. Empty ⇒ allow-all. `--scope` unions carry authority only, no visibility.
#[cfg(feature = "embedded")]
fn mcp_filter(grants: &[String]) -> ikigai_mcp::ToolFilter {
    let mut filter = ikigai_mcp::ToolFilter::default();
    for name in grants {
        let (show, hide) = ikigai_embedded::grant_visibility(name);
        filter.show.extend(show);
        filter.hide.extend(hide);
    }
    filter
}

/// MCP stdio mode: project the composed manifold as MCP tools, scoped to the
/// session capability built from `--grant`/`--scope` (the ceiling). A poller
/// watches the grants file; when the active grant's scopes change, it rebuilds
/// the capability and emits `notifications/tools/list_changed` so a connected
/// client's tool list morphs live — no restart. Broadening is safe here because
/// it is the HUMAN editing the grant (root re-granting), never the client.
#[cfg(feature = "embedded")]
fn mcp(grants: Vec<String>, scopes: Vec<String>, mounts: Vec<Mount>) {
    use ikigai_mcp::server::handle;
    use std::io::{BufRead, Write};
    use std::sync::{Arc, Mutex, RwLock};

    let capability = Arc::new(RwLock::new(mcp_capability(&grants, &scopes)));
    let filter = Arc::new(RwLock::new(mcp_filter(&grants)));
    match capability.read().expect("cap lock").scopes() {
        None => eprintln!("ikigai mcp: no --grant/--scope — running UNRESTRICTED (root)"),
        Some(s) => eprintln!(
            "ikigai mcp: serving the manifold under {} scope(s)",
            s.len()
        ),
    }
    {
        let f = filter.read().expect("filter lock");
        if !f.show.is_empty() || !f.hide.is_empty() {
            eprintln!(
                "ikigai mcp: tool visibility — {} shown, {} hidden pattern(s)",
                f.show.len(),
                f.hide.len()
            );
        }
    }
    // No mount flags -> the machine's own topology (config home), the same rule as
    // every kernel-building mode. This is where federation pays off for an agent:
    // `mount = "prefer urn:llm:=peer:plasma"` puts the peer's models behind the
    // SAME tool names the local kernel would project, no client-side config at all.
    let mounts = match mounts_or_config(mounts) {
        Ok(mounts) => mounts,
        // A topology that does not parse must never look like no topology.
        Err(e) => {
            eprintln!("ikigai: {e}");
            std::process::exit(2);
        }
    };
    let kernel = if mounts.is_empty() {
        ikigai_embedded::watched_kernel()
    } else {
        let mut resolved = Vec::new();
        for mount in mounts {
            let (target, prefix) = (mount.target.clone(), mount.prefix.clone());
            match resolve_mount(mount) {
                Ok(spec) => {
                    eprintln!("ikigai mcp: composing {prefix} via {target}");
                    resolved.push(spec);
                }
                // Fatal, like the daemon: an MCP server that silently dropped a mount
                // would project a manifold missing the tools the topology promised.
                // (A --prefer mount never lands here — it connects on demand.)
                Err(e) => {
                    eprintln!("ikigai: --mount {target}: {e}");
                    std::process::exit(2);
                }
            }
        }
        // Warm each prefer mount ONCE before projecting. A prefer-mount's catalog
        // only lists after its peer has been dialed (`entries()` deliberately never
        // dials, so the REPL's `list` cannot block on a sleeping peer) — but here
        // the manifold IS the interface: a tool that is not listed cannot be
        // called, so a namespace the local kernel does not also bind would NEVER
        // appear. One bounded probe (a UDS refusal is instant, QUIC has its dial
        // budget); the connection is cached by the dial regardless of the probe's
        // outcome, and an absent peer stays gracefully absent.
        for spec in resolved
            .iter()
            .filter(|s| s.kind == ikigai_embedded::MountKind::Prefer)
        {
            let _ = spec.resolver.issue(ikigai_core::Request::new(
                ikigai_core::Verb::Meta,
                ikigai_core::Iri::parse("urn:kernel:catalog").expect("static IRI"),
            ));
            let up = spec.resolver.entries().is_some();
            eprintln!(
                "ikigai mcp: {} peer is {}",
                spec.prefix,
                if up {
                    "up — its tools are projected"
                } else {
                    "absent — its tools are omitted (relaunch when it is up)"
                }
            );
        }
        ikigai_embedded::watched_kernel_with_mounts(resolved)
    };
    let stdout = Arc::new(Mutex::new(std::io::stdout()));

    // The live grant-swap watcher (poll the grants file's mtime). Only meaningful
    // when a named grant is in play; explicit --scope unions are fixed at launch.
    if !grants.is_empty() {
        if let Some(path) = ikigai_embedded::grants_path() {
            let capability = Arc::clone(&capability);
            let filter = Arc::clone(&filter);
            let stdout = Arc::clone(&stdout);
            std::thread::spawn(move || {
                let mtime = || std::fs::metadata(&path).and_then(|m| m.modified()).ok();
                let mut last = mtime();
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    let now = mtime();
                    if now == last {
                        continue;
                    }
                    last = now;
                    // A grant edit can change authority (scopes) and/or visibility
                    // (show/hide) — either reshapes the tool list, so re-emit on both.
                    let fresh_cap = mcp_capability(&grants, &scopes);
                    let fresh_filter = mcp_filter(&grants);
                    let cap_changed =
                        fresh_cap.scopes() != capability.read().expect("cap lock").scopes();
                    let filter_changed = fresh_filter != *filter.read().expect("filter lock");
                    if cap_changed {
                        *capability.write().expect("cap lock") = fresh_cap;
                    }
                    if filter_changed {
                        *filter.write().expect("filter lock") = fresh_filter;
                    }
                    if cap_changed || filter_changed {
                        let note =
                            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}";
                        let mut out = stdout.lock().expect("stdout lock");
                        let _ = writeln!(out, "{note}");
                        let _ = out.flush();
                        eprintln!("ikigai mcp: grant changed — tool list re-emitted");
                    }
                }
            });
        }
    }

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let response = {
            let cap = capability.read().expect("cap lock");
            let filt = filter.read().expect("filter lock");
            handle(&kernel, &cap, &filt, &msg)
        };
        if let Some(response) = response {
            let mut out = stdout.lock().expect("stdout lock");
            if writeln!(
                out,
                "{}",
                serde_json::to_string(&response).unwrap_or_default()
            )
            .is_err()
            {
                break;
            }
            let _ = out.flush();
        }
    }
}

#[cfg(not(feature = "embedded"))]
fn mcp(_grants: Vec<String>, _scopes: Vec<String>, _mounts: Vec<Mount>) {
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
    // The Lisp cap on its own — so `cap lisp` / `login lisp` reads friendlier than the
    // bare scope, and `:load … cap=lisp` narrows an untrusted script to "may eval, but
    // reaches no other authority." Additive; the embedded REPL's default root session
    // already covers `urn:cap:lisp`, so this is only needed after a narrowing.
    engine.define_cap_profile("lisp", ["urn:cap:lisp"]);
    engine
}

/// Build the engine over the chosen backend: the embedded kernel, or — with
/// `--connect` — an IPC or QUIC client, dispatched by the target.
#[cfg(feature = "embedded")]
fn build_engine(
    connect: Option<Option<String>>,
    mounts: Vec<Mount>,
    certs: &Certs,
    react: bool,
) -> Result<Engine, String> {
    match connect {
        // The watched kernel: cached workspace reads also invalidate on an
        // out-of-band file change (an editor), not just a `sink` through the REPL.
        // The same process scheduler drives both the kernel's fan-out and the
        // engine's `( a ; b )` / `..` parallelism, so `IKIGAI_SCHEDULER=pool:N`
        // governs all of it. Any `--mount`s compose remote kernels into it.
        None => {
            // No mount flags -> the machine's own topology (config home). Only here in
            // the EMBEDDED branch: a `--connect` client composes nothing — the host it
            // connects to owns the topology.
            let mounts = mounts_or_config(mounts)?;
            let kernel = if mounts.is_empty() {
                if react {
                    ikigai_embedded::reactive_kernel_with_mounts(Vec::new())
                } else {
                    ikigai_embedded::watched_kernel()
                }
            } else {
                let mut resolved = Vec::new();
                for mount in mounts {
                    // The target (socket path or quic:// URL) is the mount's origin
                    // label, surfaced in the catalog; each mount pins its OWN peer.
                    resolved.push(resolve_mount(mount)?);
                }
                if react {
                    ikigai_embedded::reactive_kernel_with_mounts(resolved)
                } else {
                    ikigai_embedded::watched_kernel_with_mounts(resolved)
                }
            };
            Ok(with_profiles(Engine::new(kernel).with_spawner(
                std::sync::Arc::new(ikigai_embedded::scheduler()),
            )))
        }
        Some(target) => {
            if !mounts.is_empty() {
                return Err("--mount composes into the embedded kernel; drop --connect".to_string());
            }
            match target.as_deref() {
                Some(t) if is_quic(t) => connect_quic(t, certs),
                _ => connect_ipc(target),
            }
        }
    }
}

/// The mounts a kernel-building mode composes: flags are POSTURE and win WHOLESALE
/// when given; otherwise the machine's own topology from the config home. Wholesale
/// rather than merged, because a half-and-half mount set is the kind of thing nobody
/// can debug at 2am. Every mode that builds a kernel from nothing routes through
/// this — the REPL/one-shot, the daemon, the IPC host — so `mount =` lines mean the
/// MACHINE composes that way, not one lucky process.
#[cfg(feature = "embedded")]
fn mounts_or_config(mounts: Vec<Mount>) -> Result<Vec<Mount>, String> {
    if mounts.is_empty() {
        config_mounts()
    } else {
        Ok(mounts)
    }
}

#[cfg(feature = "embedded")]
/// The machine's own topology, from `mount` lines in the host config.
///
/// Each line is `<mode> <prefix>=<target> [cert-dir]`, mirroring the CLI flags:
///
///     mount = "prefer urn:llm:=peer:plasma"
///     mount = "alias urn:cal:=quic://bug.local:4433 ~/.config/ikigai/quic-bug"
///
/// In the CONFIG HOME rather than in a launchd plist, because topology is a property of the
/// MACHINE: plasma is where inference lives, bug is where the calendar lives, and one copied
/// plist cannot say both. A plist is deployed from the repo and `git pull` would overwrite a
/// machine's identity with another's; a config file is that machine's own.
fn config_mounts() -> Result<Vec<Mount>, String> {
    ikigai_embedded::config::all("mount")
        .into_iter()
        .map(|line| {
            let mut parts = line.split_whitespace();
            let mode = parts
                .next()
                .ok_or_else(|| format!("mount `{line}`: expected <mode> <prefix>=<target>"))?;
            let kind = match mode {
                "alias" | "mount" => ikigai_embedded::MountKind::Alias,
                "override" => ikigai_embedded::MountKind::Override,
                "prefer" => ikigai_embedded::MountKind::Prefer,
                other => {
                    return Err(format!(
                        "mount `{line}`: unknown mode `{other}` (alias | override | prefer)"
                    ))
                }
            };
            let spec = parts
                .next()
                .ok_or_else(|| format!("mount `{line}`: expected <prefix>=<target>"))?;
            let (prefix, target) = spec.split_once('=').ok_or_else(|| {
                format!("mount `{line}`: expected <prefix>=<target>, got `{spec}`")
            })?;
            let mut certs = Certs::default();
            if let Some(dir) = parts.next() {
                certs.cert_dir = Some(shellexpand_home(dir));
            }
            Ok(Mount {
                prefix: prefix.to_string(),
                target: target.to_string(),
                certs,
                kind,
            })
        })
        .collect()
}

/// `~/x` → `$HOME/x`. A config file is hand-written, and `~` is what a person types.
fn shellexpand_home(path: &str) -> String {
    match path.strip_prefix("~/") {
        Some(rest) => std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
            .join(rest)
            .display()
            .to_string(),
        None => path.to_string(),
    }
}

/// Turn a parsed [`Mount`] into a [`MountSpec`], connecting eagerly or lazily
/// according to its kind. The target picks the transport the same way `--connect`
/// does: `quic://host:port` for a remote kernel over mutually-pinned TLS (federation
/// across machines), else a Unix socket path (a same-machine peer).
///
/// `--mount` and `--override` connect NOW: you named that peer because you want
/// its namespace, and a silent no-op is the failure mode worth being loud about.
/// `--prefer` connects on demand — its whole contract is that the peer may be
/// absent, so an absent peer at startup is normal operation, not an error.
fn resolve_mount(mount: Mount) -> Result<ikigai_embedded::MountSpec, String> {
    let Mount {
        prefix,
        target,
        certs,
        kind,
    } = mount;
    let resolver: std::sync::Arc<dyn ikigai_resolve::Resolver> =
        if kind == ikigai_embedded::MountKind::Prefer {
            std::sync::Arc::new(LazyResolver {
                target: target.clone(),
                certs,
                inner: std::sync::Mutex::new(None),
            })
        } else {
            connect_mount(&target, &certs, kind)?
        };
    Ok(ikigai_embedded::MountSpec {
        prefix,
        origin: target,
        resolver,
        kind,
    })
}

/// A mount that connects on FIRST USE, and re-tries on every use after a failure.
///
/// Why `--prefer` needs this: the eager path connects while the process starts, so
/// a peer that is merely asleep at boot — the normal case for a laptop preferring a
/// workstation — would be skipped for the life of the process, and never picked up
/// when it woke. Deferring the connect makes "when it's around" mean *now*, not
/// *at startup*.
///
/// A failure to connect is reported as the transient [`Error::Unavailable`] it is,
/// which is exactly what makes the `Failover` above it fall through to the local
/// binding.
///
/// Once connected, the resolver is KEPT even across failures — the transports
/// re-establish their own connections (`QuicResolver::round_trip` redials on any
/// transport error), so a peer that goes and returns is handled a layer down.
/// Dropping it here instead looks tempting and wedges the REPL: `QuicResolver`'s
/// `Drop` blocks on its runtime to flush the close frame, and doing that from
/// inside a resolution — which is already running under a runtime — is exactly
/// the context where blocking is not allowed.
struct LazyResolver {
    target: String,
    certs: Certs,
    inner: std::sync::Mutex<Option<std::sync::Arc<dyn ikigai_resolve::Resolver>>>,
}

impl LazyResolver {
    /// The live resolver, dialing the peer if this is the first call (or the first
    /// since a failure).
    fn get(&self) -> Result<std::sync::Arc<dyn ikigai_resolve::Resolver>, ikigai_core::Error> {
        if let Some(resolver) = self.inner.lock().unwrap().clone() {
            return Ok(resolver);
        }
        // A prefer mount forwards IRIs unchanged, so it speaks verbatim.
        let resolver = connect_mount(
            &self.target,
            &self.certs,
            ikigai_embedded::MountKind::Prefer,
        )
        .map_err(|e| ikigai_core::Error::Unavailable(format!("{}: {e}", self.target)))?;
        *self.inner.lock().unwrap() = Some(std::sync::Arc::clone(&resolver));
        Ok(resolver)
    }
}

#[async_trait::async_trait]
impl ikigai_resolve::Resolver for LazyResolver {
    fn issue(
        &self,
        request: ikigai_core::Request,
    ) -> Result<(ikigai_core::Representation, ikigai_resolve::CacheStatus), ikigai_core::Error>
    {
        self.get()?.issue(request)
    }

    fn issue_as(
        &self,
        request: ikigai_core::Request,
        capability: &ikigai_core::Capability,
    ) -> Result<(ikigai_core::Representation, ikigai_resolve::CacheStatus), ikigai_core::Error>
    {
        self.get()?.issue_as(request, capability)
    }

    async fn issue_as_async(
        &self,
        request: ikigai_core::Request,
        capability: &ikigai_core::Capability,
    ) -> Result<(ikigai_core::Representation, ikigai_resolve::CacheStatus), ikigai_core::Error>
    {
        let resolver = self.get()?;
        resolver.issue_as_async(request, capability).await
    }

    fn is_cached(
        &self,
        request: &ikigai_core::Request,
        capability: &ikigai_core::Capability,
    ) -> bool {
        // An unreachable peer has nothing cached, and probing must not dial.
        match self.inner.lock().unwrap().clone() {
            Some(resolver) => resolver.is_cached(request, capability),
            None => false,
        }
    }

    fn entries(&self) -> Option<Vec<ikigai_core::SpaceEntry>> {
        // Only if already connected: `catalog` must not block on dialing a peer
        // that may be asleep.
        self.inner.lock().unwrap().clone()?.entries()
    }

    fn transport(&self) -> String {
        match self.inner.lock().unwrap().clone() {
            Some(resolver) => resolver.transport(),
            None => format!("{} · not connected", self.target),
        }
    }
}

fn connect_mount(
    target: &str,
    certs: &Certs,
    kind: ikigai_embedded::MountKind,
) -> Result<std::sync::Arc<dyn ikigai_resolve::Resolver>, String> {
    // `peer:<name>` — mount by NAME, letting mDNS supply the address. Addresses move
    // (bug's `ipconfig getifaddr en0` came back empty during the mail work, because it was
    // on another interface); a name does not.
    if let Some(name) = target.strip_prefix("peer:") {
        let (resolved, certs) = resolve_peer(name, certs)?;
        return connect_mount_quic(&resolved, &certs);
    }
    if is_quic(target) {
        connect_mount_quic(target, certs)
    } else {
        connect_mount_ipc(target, kind)
    }
}

/// How long to listen before deciding a peer is not out there. Multicast replies are not
/// instant, so a browse started microseconds ago legitimately knows nothing.
#[cfg(all(feature = "embedded", feature = "quic"))]
const PEER_DISCOVERY_WAIT: std::time::Duration = std::time::Duration::from_millis(1500);

/// Turn `peer:<name>` into a dialable `quic://host:port` plus the certificates for it.
///
/// DISCOVERY SUPPLIES THE ADDRESS, NEVER THE TRUST. An announced name is
/// attacker-controlled — anything on the LAN can claim to be `plasma` — so a named mount
/// REQUIRES a pinned server certificate, by the deployed convention
/// `<config>/ikigai/quic-<name>/`. An impostor gets a failed handshake; an unenrolled peer
/// gets a refusal that says how to enrol it, rather than a connection.
///
/// That convention is also why this is ergonomic: the name determines both the address (by
/// announcement) and the identity (by directory), so `--prefer urn:llm:=peer:plasma` needs
/// no address and no `--cert-dir`.
#[cfg(all(feature = "embedded", feature = "quic"))]
fn resolve_peer(name: &str, certs: &Certs) -> Result<(String, Certs), String> {
    let browser = ikigai_discovery::Browser::start()
        .map_err(|e| format!("peer:{name}: could not browse this network: {e}"))?;
    std::thread::sleep(PEER_DISCOVERY_WAIT);
    let peer = browser.peer(name).ok_or_else(|| {
        format!(
            "peer:{name}: no peer is announcing under that name \
             (`source urn:peer:list` shows who is). The peer must serve with `--announce`."
        )
    })?;
    let addr = peer
        .socket_addr()
        .ok_or_else(|| format!("peer:{name}: announced no usable address"))?;

    let mut certs = certs.clone();
    if certs.cert_dir.is_none() && certs.server_cert.is_none() {
        let dir = peer_cert_dir(name);
        if !dir.join("server.crt").exists() {
            return Err(format!(
                "peer:{name}: found it at {addr}, but this machine holds no pinned \
                 certificate for it ({}/server.crt). Discovery supplies an address, never \
                 trust — enrol the peer first (on {name}: `ikigai cert add-client <this \
                 host>`, then copy its server.crt here), or pass --cert-dir.",
                dir.display()
            ));
        }
        certs.cert_dir = Some(dir.display().to_string());
    }
    Ok((format!("quic://{addr}"), certs))
}

/// The conventional per-peer certificate directory: `<config>/ikigai/quic-<name>/`.
/// plasma holds `quic-bug`, bug holds `quic-plasma`.
#[cfg(all(feature = "embedded", feature = "quic"))]
fn peer_cert_dir(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
        .join(".config/ikigai")
        .join(format!("quic-{name}"))
}

/// Without the `quic` feature there is nothing to dial a discovered peer with.
#[cfg(all(feature = "embedded", not(feature = "quic")))]
fn resolve_peer(name: &str, _certs: &Certs) -> Result<(String, Certs), String> {
    Err(format!(
        "peer:{name}: mounting a discovered peer needs the `quic` feature"
    ))
}

/// The QUIC idle timeout: `quic.timeout` (seconds) in the host config, else the
/// generous default. Like `ipc.timeout` (#259), what this bounds is SILENCE — and for
/// a long resolution the silence is the work.
#[cfg(all(feature = "embedded", feature = "quic"))]
fn quic_idle_timeout() -> std::time::Duration {
    ikigai_embedded::config::get("quic.timeout")
        .and_then(|s| s.parse::<u64>().ok())
        .map(std::time::Duration::from_secs)
        .unwrap_or(ikigai_quic::DEFAULT_IDLE_TIMEOUT)
}

#[cfg(all(feature = "embedded", feature = "quic"))]
fn connect_mount_quic(
    target: &str,
    certs: &Certs,
) -> Result<std::sync::Arc<dyn ikigai_resolve::Resolver>, String> {
    let addr = quic::parse_addr(target)?;
    let identity = quic::client_identity(certs)?;
    let trusted = quic::trusted_server_cert(certs)?;
    let resolver = ikigai_quic::connect_with(addr, &identity, &trusted, quic_idle_timeout())
        .map_err(|e| format!("--mount: connect {target}: {e}"))?;
    Ok(std::sync::Arc::new(resolver))
}

#[cfg(all(feature = "embedded", not(feature = "quic")))]
fn connect_mount_quic(
    _target: &str,
    _certs: &Certs,
) -> Result<std::sync::Arc<dyn ikigai_resolve::Resolver>, String> {
    Err("--mount of a quic:// target needs the `quic` feature".to_string())
}

#[cfg(all(feature = "embedded", feature = "ipc"))]
fn connect_mount_ipc(
    socket: &str,
    kind: ikigai_embedded::MountKind,
) -> Result<std::sync::Arc<dyn ikigai_resolve::Resolver>, String> {
    // The hello declares how this mount will address the peer, so a
    // prefix-canonical peer (ikigai-python) lists its entries in the form the
    // mount expects — alias mounts strip and re-prefix, the others forward
    // IRIs unchanged.
    let mode = match kind {
        ikigai_embedded::MountKind::Alias => ikigai_ipc::HelloMode::Alias,
        _ => ikigai_ipc::HelloMode::Verbatim,
    };
    let resolver = ikigai_ipc::connect_as(std::path::Path::new(socket), mode)
        .map_err(|e| format!("--mount: connect {socket}: {e}"))?;
    Ok(std::sync::Arc::new(resolver))
}

#[cfg(all(feature = "embedded", not(feature = "ipc")))]
fn connect_mount_ipc(
    _socket: &str,
    _kind: ikigai_embedded::MountKind,
) -> Result<std::sync::Arc<dyn ikigai_resolve::Resolver>, String> {
    Err("--mount of a Unix socket needs the `ipc` feature (Unix only)".to_string())
}

/// Drive the engine: one-shot `-c`, else the full-screen TUI on a terminal, else
/// the line REPL.
#[cfg(feature = "embedded")]
fn run_repl(engine: Engine, plain: bool, commands: &[String]) {
    if !commands.is_empty() {
        // A batch fed on a NON-TTY stdin (`printf %s "$v" | ikigai -c 'sink urn:secret:x'`)
        // routes that stdin to the first content-less `sink` — so a secret is piped in, never
        // placed on the command line. A TTY stdin is left alone (nothing to read, no block).
        #[cfg(not(target_family = "wasm"))]
        {
            use std::io::{IsTerminal, Read};
            if !std::io::stdin().is_terminal() {
                // LAZILY. Reading stdin to EOF here blocks whenever stdin is a non-TTY that
                // never closes — an inherited pipe from an editor, a harness, launchd — so
                // `ikigai -c 'source …' > file` hung waiting for input no command wanted.
                // `is_terminal()` cannot tell "a pipe with data" from "a pipe nobody will
                // write to"; the only safe moment to block is when a content-less `sink`
                // has actually asked for the content.
                engine.set_piped_input_with(|| {
                    let mut buf = Vec::new();
                    let _ = std::io::stdin().read_to_end(&mut buf);
                    buf
                });
            }
        }
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
fn cert_generate(force: bool, dir: Option<String>) -> ! {
    match quic::generate(force, dir.map(std::path::PathBuf::from)) {
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

#[cfg(all(feature = "embedded", feature = "quic"))]
fn cert_add_client(name: &str, cert_dir: Option<String>, force: bool) -> ! {
    let certs = Certs {
        cert_dir,
        ..Default::default()
    };
    match quic::add_client(name, &certs, force) {
        Ok(path) => {
            println!("wrote a new client identity to {}", path.display());
            println!(
                "the server trusts it on next start (it reads clients/*.crt); to use it, copy \
                 {name}.crt, {name}.key, and server.crt to the client machine."
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
fn cert_generate(_force: bool, _dir: Option<String>) -> ! {
    eprintln!("ikigai: `cert generate` needs the `quic` feature");
    std::process::exit(1);
}

#[cfg(all(feature = "embedded", not(feature = "quic")))]
fn cert_add_client(_name: &str, _cert_dir: Option<String>, _force: bool) -> ! {
    eprintln!("ikigai: `cert add-client` needs the `quic` feature");
    std::process::exit(1);
}

// --- QUIC serve / connect ---------------------------------------------------

#[cfg(all(feature = "embedded", feature = "quic"))]
fn serve_quic(target: &str, certs: &Certs, caps: &[String], announce: bool) -> ! {
    let caps = caps.to_vec();
    let result = (|| -> Result<(), String> {
        let addr = quic::parse_addr(target)?;
        let identity = quic::server_identity(certs)?;
        let trusted = quic::trusted_client_certs(certs)?;
        // Capability-on-the-wire: every connection's ceiling is minted per-connection
        // from *which* certificate authenticated. The cert IS the credential — the
        // same identity→capability move as the browser passkey, over mTLS — and the
        // server clamps any carried capability down to it (never widens).
        //
        // Two modes: with `--cap`, a FIXED ceiling shared by every authenticated
        // client (`--cap urn:cap:personal:calendar:read:freebusy` = a free/busy share
        // and nothing else). Without it, the default per-tenant filesystem workspace,
        // where each client transparently roots at its own segment (`urn:file:x`).
        let minter: std::sync::Arc<dyn Fn(&str) -> ikigai_quic::Session + Send + Sync> =
            if caps.is_empty() {
                let root = ikigai_embedded::file_root();
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
                })
            } else {
                let ceiling = ikigai_core::Capability::scoped(caps.clone());
                std::sync::Arc::new(move |id: &str| ikigai_quic::Session {
                    capability: ceiling.clone(),
                    file_segment: id.to_string(),
                })
            };
        let posture = if caps.is_empty() {
            "per-client workspaces".to_string()
        } else {
            format!("fixed ceiling: {}", caps.join(", "))
        };
        // A personal ceiling means this is a personal-resource server (the calendar
        // federation): serve the minimal calendar-only kernel — availability + calendar
        // and nothing else — instead of the default served kernel (host + fs). The clamp
        // still gates it (a freebusy ceiling → freebusy), but the manifold is also
        // minimal, so nothing but the calendar is even nameable over the wire.
        // THE GRANT DECIDES THE SURFACE. Each optional face is switched on by the
        // ceiling the operator set, so a capability that could never be exercised
        // never puts its endpoints on the wire.
        let surface = ikigai_embedded::ServedSurface {
            personal: caps.iter().any(|c| c.starts_with("urn:cap:personal:")),
            wire_eval: caps
                .iter()
                .any(|c| c == "urn:cap:lisp" || c == "urn:cap:lisp:run"),
            // A net grant means "you may spend my inference": urn:llm:* becomes
            // servable, still bounded by require_net to the granted provider hosts.
            llm: caps.iter().any(|c| c.starts_with("urn:cap:net:")),
        };
        let kernel = ikigai_embedded::served_kernel("Remote (QUIC)", surface);
        let signed_door = ikigai_embedded::code_signers_configured();
        let mut faces = vec![if surface.personal {
            "calendar-only"
        } else {
            "host + fs"
        }];
        if surface.llm {
            faces.push("llm");
        }
        if surface.wire_eval {
            faces.push("governed eval");
        }
        if surface.wire_eval && signed_door {
            faces.push("signed-run");
        }
        let surface = faces.join(" + ");
        eprintln!(
            "ikigai: serving on {target}  ({posture}; surface: {surface}; {} trusted client cert(s))  (Ctrl-C to stop)",
            trusted.len()
        );
        // Announce on the local network, so a client can mount this kernel by NAME rather
        // than by an address that moves. Opt-in: broadcasting what a machine serves is a
        // disclosure, and a server on an untrusted network may want to be found only by
        // those who were told where it is.
        //
        // What travels is what the banner already says — the name, the port, the surface,
        // the ceiling. It is ADVERTISEMENT, not authority: the ceiling is enforced here at
        // resolution time whatever the TXT record claims, and a listener still needs a
        // pinned certificate to get a connection at all.
        //
        // Held for the process lifetime: dropping it sends the mDNS goodbye, which is what
        // lets a peer distinguish "gone" from "never heard of".
        let _announcement = if announce {
            let name = ikigai_embedded::instance_name();
            let wire_version = ikigai_wire::PROTOCOL_VERSION.to_string();
            match ikigai_discovery::announce(
                name,
                addr.port(),
                &[
                    (ikigai_discovery::TXT_SURFACE, surface.as_str()),
                    (ikigai_discovery::TXT_CEILING, posture.as_str()),
                    (ikigai_discovery::TXT_VERSION, wire_version.as_str()),
                ],
            ) {
                Ok(handle) => {
                    eprintln!(
                        "ikigai: announcing as \"{name}\" on {}",
                        ikigai_discovery::SERVICE_TYPE
                    );
                    Some(handle)
                }
                // Not fatal: a kernel that cannot announce still serves everyone who knows
                // its address. Loud, though — silently not announcing would look like a
                // network with nobody on it.
                Err(e) => {
                    eprintln!("ikigai: warning: could not announce on this network: {e}");
                    None
                }
            }
        } else {
            None
        };
        ikigai_quic::serve_with(
            kernel,
            addr,
            &identity,
            &trusted,
            minter,
            quic_idle_timeout(),
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
    let resolver = ikigai_quic::connect_with(addr, &identity, &trusted, quic_idle_timeout())
        .map_err(|e| format!("connect {target}: {e}"))?;
    Ok(with_profiles(Engine::new(resolver)))
}

#[cfg(all(feature = "embedded", not(feature = "quic")))]
fn serve_quic(_target: &str, _certs: &Certs, _caps: &[String], _announce: bool) -> ! {
    eprintln!("ikigai: `quic://` needs the `quic` feature");
    std::process::exit(1);
}

#[cfg(all(feature = "embedded", not(feature = "quic")))]
fn connect_quic(_target: &str, _certs: &Certs) -> Result<Engine, String> {
    Err("`quic://` needs the `quic` feature".to_string())
}

// --- IPC serve / connect ----------------------------------------------------

#[cfg(all(feature = "embedded", feature = "ipc", unix))]
fn serve_ipc(path: Option<String>, mounts: Vec<Mount>) -> ! {
    let socket = ipc_socket(path);
    // Flags are POSTURE and win wholesale when given; otherwise the machine's own topology
    // from the config home. Wholesale rather than merged, because a half-and-half mount set
    // is the kind of thing nobody can debug at 2am.
    let mounts = match mounts_or_config(mounts) {
        Ok(mounts) => mounts,
        // A topology that does not parse must never look like no topology: this host
        // would come up serving purely local resources and answer every federated
        // request from the wrong machine, silently.
        Err(e) => {
            eprintln!("ikigai: {e}");
            std::process::exit(2);
        }
    };
    // Connect the mounts BEFORE announcing readiness: a host that says it is serving and
    // then cannot reach the peer it was told to compose is worse than one that refuses to
    // start. (A `--prefer` mount is exempt — its peer being absent is normal, and it dials
    // on demand.)
    let mut resolved = Vec::new();
    for mount in mounts {
        let target = mount.target.clone();
        match resolve_mount(mount) {
            Ok(spec) => resolved.push(spec),
            Err(e) => {
                eprintln!("ikigai: --mount {target}: {e}");
                std::process::exit(2);
            }
        }
    }
    let mounted = if resolved.is_empty() {
        String::new()
    } else {
        format!("; {} mount(s)", resolved.len())
    };
    eprintln!(
        "ikigai: serving on {}{mounted}  (Ctrl-C to stop)",
        socket.display()
    );
    let kernel = ikigai_embedded::trusted_kernel_with_mounts("Remote (IPC)", resolved);
    match ikigai_ipc::serve(kernel, &socket) {
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
    // `ipc.timeout` in the host config (seconds) overrides the default deadline. What it
    // bounds is SILENCE from the server, and a long resolution is silent while it works —
    // so a machine that routinely asks a 70B model a question wants a larger number than
    // one that does not. Config home, not an environment variable.
    let timeout = ikigai_embedded::config::get("ipc.timeout")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(std::time::Duration::from_secs)
        .unwrap_or(ikigai_ipc::DEFAULT_TIMEOUT);
    let resolver = ikigai_ipc::connect_with_timeout(&socket, Some(timeout))
        .map_err(|e| format!("connect {}: {e}", socket.display()))?;
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
fn serve_ipc(_path: Option<String>, _mounts: Vec<Mount>) -> ! {
    eprintln!("ikigai: a Unix-socket server needs the `ipc` feature on a Unix platform");
    std::process::exit(1);
}

/// The inbound HTTP face: serve the embedded kernel over HTTP. TLS is expected to
/// terminate at the fronting proxy (Apache holds the cert), so a bare `--http <port>`
/// binds loopback (`127.0.0.1`) — never a cleartext socket on the public interface.
/// A full `host:port` overrides the bind (e.g. `0.0.0.0:8080` behind a firewall).
/// S0 resolves every request under the public capability; the per-tenant door (the
/// identity→capability lookup) fills the same seam in a later slice.
#[cfg(all(feature = "embedded", feature = "web"))]
fn serve_http(
    bind: &str,
    caps: &[String],
    trust_proxy: bool,
    cors_origins: &[String],
    routes: Option<&str>,
    routes_only: bool,
) -> ! {
    use std::net::SocketAddr;
    let addr: SocketAddr = if let Ok(port) = bind.parse::<u16>() {
        SocketAddr::from(([127, 0, 0, 1], port))
    } else {
        match bind.parse() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("ikigai: --http wants a port or host:port ({bind}: {e})");
                std::process::exit(2);
            }
        }
    };
    let kernel = std::sync::Arc::new(ikigai_embedded::kernel_for("Remote (HTTP)"));
    // `--cap` clamps every request to a fixed ceiling — how the public HTTP face is
    // narrowed for the edge (a request can reach only what the ceiling grants). Without
    // it, the public (empty-scope) capability: only cap-free resources resolve.
    let (cap_fn, posture) = if caps.is_empty() {
        (ikigai_web::public_cap(), "public cap".to_string())
    } else {
        (
            ikigai_web::fixed_cap(caps.to_vec()),
            format!("ceiling: {}", caps.join(", ")),
        )
    };
    // The edge response policy: strict security headers by default; `--trust-proxy` honors
    // the fronting proxy's X-Forwarded-Proto (→ HSTS on HTTPS); `--cors-origin` opens CORS
    // to named origins (closed otherwise).
    let mut config = ikigai_web::EdgeConfig {
        trust_proxy,
        routes_only,
        ..Default::default()
    };
    config.cors.allowed_origins = cors_origins.to_vec();
    // Build the async runtime up front — route loading (a kernel SPARQL query) is async too.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ikigai: could not start the async runtime: {e}");
            std::process::exit(1);
        }
    };
    // `--routes <iri>`: load the route table from an RDF resource, queried through the
    // kernel's SPARQL on a plain (no-daemon) loader kernel. A load failure is fatal — a
    // misconfigured edge should not silently fall back to the bare default routing. When the
    // resource is a `urn:file:` route file, a poller hot-reloads it on change (no restart).
    let route_note = match routes {
        Some(iri) => {
            let loader = ikigai_embedded::kernel();
            let table = match runtime.block_on(route_load::load_route_table(
                &loader,
                iri,
                &ikigai_core::Capability::root(),
            )) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("ikigai: route load failed ({e})");
                    std::process::exit(1);
                }
            };
            let n = table.routes.len();
            let live = ikigai_web::live_routes(table);
            config.live_routes = Some(live.clone());

            // Hot-reload: poll the watched file's mtime; on change re-query on a FRESH kernel
            // (so no stale cache) and swap the live handle.
            if let Some(path) = route_load::watch_path(iri, &ikigai_embedded::file_root()) {
                let iri_owned = iri.to_string();
                runtime.spawn(async move {
                    let mtime =
                        |p: &std::path::Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
                    let mut last = mtime(&path);
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        let now = mtime(&path);
                        if now == last {
                            continue;
                        }
                        last = now;
                        let loader = ikigai_embedded::kernel();
                        match route_load::load_route_table(
                            &loader,
                            &iri_owned,
                            &ikigai_core::Capability::root(),
                        )
                        .await
                        {
                            Ok(t) => {
                                let m = t.routes.len();
                                ikigai_web::swap_routes(&live, t);
                                eprintln!("ikigai: reloaded {m} route(s) from {iri_owned}");
                            }
                            Err(e) => eprintln!(
                                "ikigai: route reload failed ({e}) — keeping the current table"
                            ),
                        }
                    }
                });
                format!("{n} route(s) from {iri}, watching")
            } else {
                format!("{n} route(s) from {iri}")
            }
        }
        None => "mechanical routing".to_string(),
    };
    let route_note = if routes_only {
        format!("{route_note}, routes-only (un-routed → 404)")
    } else {
        route_note
    };
    let cors_note = if cors_origins.is_empty() {
        "CORS closed".to_string()
    } else {
        format!("CORS: {}", cors_origins.join(", "))
    };
    let proxy_note = if trust_proxy {
        "trusting X-Forwarded-*"
    } else {
        "no proxy trust"
    };
    eprintln!(
        "ikigai: serving HTTP on {addr}  ({posture}; {route_note}; {cors_note}; {proxy_note}; terminate TLS at your proxy)  (Ctrl-C to stop)"
    );
    match runtime.block_on(ikigai_web::serve_with(kernel, cap_fn, addr, config)) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("ikigai: HTTP serve error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(all(feature = "embedded", feature = "web")))]
fn serve_http(
    _bind: &str,
    _caps: &[String],
    _trust_proxy: bool,
    _cors_origins: &[String],
    _routes: Option<&str>,
    _routes_only: bool,
) -> ! {
    eprintln!("ikigai: the inbound HTTP face needs the `web` feature (build with --features web)");
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

#[cfg(test)]
mod mount_cert_tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn mounts_of(args: &[&str]) -> Vec<Mount> {
        match parse_argv(argv(args).into_iter()) {
            Ok(Some(Mode::Repl(repl))) => repl.mounts,
            Ok(Some(_)) => panic!("expected a repl mode, got another mode"),
            Ok(None) => panic!("expected a repl mode, got no mode"),
            Err(e) => panic!("parse failed: {e}"),
        }
    }

    /// The bug this fixes: `--cert-dir` was a single global setting, so two mounts
    /// with different certificate sets silently shared the LAST one — the second
    /// peer's cert was pinned against the first peer's server, yielding
    /// "server certificate does not match the pinned certificate". Certificates
    /// now attach to the mount they follow.
    #[test]
    fn each_mount_keeps_its_own_certificates() {
        let mounts = mounts_of(&[
            "--mount",
            "urn:personal:=quic://localhost:4433",
            "--cert-dir",
            "/certs/peer",
            "--mount",
            "urn:edge:=quic://edge.example:4433",
            "--cert-dir",
            "/certs/edge",
        ]);
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].prefix, "urn:personal:");
        assert_eq!(mounts[0].certs.cert_dir.as_deref(), Some("/certs/peer"));
        assert_eq!(mounts[1].prefix, "urn:edge:");
        assert_eq!(
            mounts[1].certs.cert_dir.as_deref(),
            Some("/certs/edge"),
            "the second mount must NOT inherit the first mount's cert dir"
        );
    }

    /// Cert flags BEFORE any mount are the default set: later mounts inherit them
    /// (and `--connect` uses them), so the single-peer form keeps working.
    #[test]
    fn certs_before_a_mount_are_the_default_inherited_by_mounts() {
        let mounts = mounts_of(&[
            "--cert-dir",
            "/certs/default",
            "--mount",
            "urn:a:=quic://a.example:4433",
            "--mount",
            "urn:b:=quic://b.example:4433",
            "--cert-dir",
            "/certs/b",
        ]);
        assert_eq!(mounts[0].certs.cert_dir.as_deref(), Some("/certs/default"));
        assert_eq!(
            mounts[1].certs.cert_dir.as_deref(),
            Some("/certs/b"),
            "a mount's own cert flag overrides the inherited default"
        );
    }

    /// The three mount forms are distinct kinds, and each carries its own certs.
    #[test]
    fn mount_override_and_prefer_are_distinct_kinds() {
        let mounts = mounts_of(&[
            "--mount",
            "urn:cal:=quic://a.example:4433",
            "--override",
            "urn:personal:=quic://b.example:4433",
            "--prefer",
            "urn:llm:=quic://plasma.local:4433",
            "--cert-dir",
            "/certs/plasma",
        ]);
        assert_eq!(mounts[0].kind, ikigai_embedded::MountKind::Alias);
        assert_eq!(mounts[1].kind, ikigai_embedded::MountKind::Override);
        assert_eq!(mounts[2].kind, ikigai_embedded::MountKind::Prefer);
        assert_eq!(mounts[2].prefix, "urn:llm:");
        assert_eq!(mounts[2].target, "quic://plasma.local:4433");
        assert_eq!(mounts[2].certs.cert_dir.as_deref(), Some("/certs/plasma"));
    }

    /// `ikigai mcp` composes mounts like every other kernel-building mode — a
    /// federated manifold is where projection pays off (a peer's models and the
    /// remote calendar behind natural tool names, no client-side topology). Cert
    /// flags attach to the mount they follow, the REPL's rule.
    #[test]
    fn mcp_takes_mounts_with_their_own_certificates() {
        let parsed = parse_argv(
            argv(&[
                "mcp",
                "--grant",
                "cal",
                "--prefer",
                "urn:llm:=peer:plasma",
                "--mount",
                "urn:cal:=quic://bug.local:4433",
                "--cert-dir",
                "/certs/bug",
            ])
            .into_iter(),
        );
        let Ok(Some(Mode::Mcp { grants, mounts, .. })) = parsed else {
            panic!("expected mcp mode");
        };
        assert_eq!(grants, vec!["cal".to_string()]);
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].kind, ikigai_embedded::MountKind::Prefer);
        assert_eq!(mounts[0].target, "peer:plasma");
        assert!(
            mounts[0].certs.cert_dir.is_none(),
            "a cert flag after the SECOND mount must not leak onto the first"
        );
        assert_eq!(mounts[1].kind, ikigai_embedded::MountKind::Alias);
        assert_eq!(mounts[1].certs.cert_dir.as_deref(), Some("/certs/bug"));
    }

    /// A `--prefer` mount must NOT dial while the process starts: the peer being
    /// absent is its normal case, and an eager connect would both fail at boot and
    /// never pick the peer up when it woke.
    #[test]
    fn a_prefer_mount_does_not_connect_at_startup() {
        let mount = Mount {
            prefix: "urn:llm:".to_string(),
            // Nothing is listening here, and nothing should try.
            target: "quic://127.0.0.1:1".to_string(),
            certs: Certs::default(),
            kind: ikigai_embedded::MountKind::Prefer,
        };
        let spec = resolve_mount(mount).expect("a prefer mount must not fail at startup");
        assert!(
            spec.resolver.entries().is_none(),
            "an unconnected prefer mount has no catalog to report"
        );
        assert!(
            spec.resolver.transport().contains("not connected"),
            "transport should say the peer is not connected, got: {}",
            spec.resolver.transport()
        );
    }

    /// Per-file overrides ride along with the mount too, not just --cert-dir.
    #[test]
    fn per_file_cert_overrides_are_also_per_mount() {
        let mounts = mounts_of(&[
            "--mount",
            "urn:a:=quic://a.example:4433",
            "--server-cert",
            "/certs/a-server.crt",
            "--mount",
            "urn:b:=quic://b.example:4433",
            "--server-cert",
            "/certs/b-server.crt",
        ]);
        assert_eq!(
            mounts[0].certs.server_cert.as_deref(),
            Some("/certs/a-server.crt")
        );
        assert_eq!(
            mounts[1].certs.server_cert.as_deref(),
            Some("/certs/b-server.crt")
        );
    }
}
