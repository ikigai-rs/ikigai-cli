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
//! renderer-agnostic [`engine`](ikigai_engine) over the chosen [`Resolver`](ikigai_resolve::Resolver).

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
                               (with clients.json below, the OUTER bound each grant narrows within)
  ikigai serve <q>             per-identity authority when ~/.config/ikigai/clients.json enrols
                               certificates — it maps a client's SHA-256 fingerprint to a grant
                               named in grants.json, so each gets its own scopes, an unenrolled
                               one is REFUSED, and editing the file revokes on the next
                               connection. `cert add-client` prints the fingerprint to enrol.
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
                                (a urn:file: route hot-reloads); --routes-only: un-routed → 404;
                                --max-body <bytes>: largest accepted request body, default 1048576]
  ikigai --daemon              headless: timers, the watcher, and the standing sync — for launchd
  ikigai --name <instance>     name this instance (scopes <name>.* config properties; defaults
                               repl / daemon / serve by mode)
  ikigai --scheduler <spec>    fan-out width: single | pool | pool:N (any mode). Also
                               `scheduler = \"pool:N\"` in the config home (instance-scoped as
                               <name>.scheduler); IKIGAI_SCHEDULER still works, deprecated.
                               `source urn:kernel:scheduler` reports the width AND the channel
  ikigai --width-routing <on|off>
                               route a fan-out by the width it ACHIEVES: at 2+ concurrent
                               requests, append needs=batchAt<=W for targets that read it
                               (urn:llm:ask). OFF by default; also `width-routing = \"on\"`
                               in the config home (instance-scoped as <name>.width-routing).
                               An explicit provider= or needs= always wins
                               that set it — the DEFAULT `single` runs every fan-out serially
  ikigai --mount <p>=<t>       graft a remote namespace at prefix <p> (ALIAS: <p>rest → urn:rest
                               on the remote, tried after local; --cert-dir after it is ITS cert set)
  ikigai --override <p>=<t>    the SAME namespace, served remotely: IRIs forward unchanged and win
                               over local. <p> may be a whole IRI, so a single resource can be
                               rerouted; the most specific override wins
  ikigai --prefer <p>=<t>      like --override, but falls back to the LOCAL binding when the peer
                               is unreachable (transient failures only; denials still propagate)
  <t> = peer:<name>            find that peer on the local network (mDNS) instead of naming an
                               address; needs a pinned cert at <config>/ikigai/quic-<name>/
  ikigai --no-config-mounts    compose ZERO mounts: decline the machine's topology instead of
                               enumerating a replacement. Honoured by every mode that builds a
                               kernel (REPL, -c, --daemon, serve, mcp); refuses to start beside
                               --mount/--override/--prefer, which declare a topology of their own
  ikigai --react               run the space reactor in this session — claims and executes tuples
                               dropped in the workspace. OFF by default; the daemon is the worker
  ikigai cert generate         create the pinned QUIC certificates (--dir <d> for a dedicated set)
  ikigai cert add-client <n>   mint an extra client identity into clients/<n>.{crt,key}
  ikigai -c '<command>' ...    run command(s) non-interactively, then exit
  ikigai -e '<sexpr>' ...       evaluate a Lisp s-expression (urn:lisp:eval), then exit
  ikigai --load <uri> [--cap <s>]  read a script resource and evaluate it as Lisp (--cap narrows first)
  ikigai -h | --help           show this help
  ikigai -V | --version        print `ikigai <x.y.z>` on one line and exit — answered in
                               every mode, before anything is built or connected

QUIC: --server-cert/--server-key name the server's identity, --client-cert/--client-key the client's
inside the REPL: source, describe, help, quit (type `help` for details)";

/// The single line `-V`/`--version` prints. ONE version string for the whole binary:
/// the same spelling as the REPL banner (`repl.rs`), the no-transport message below,
/// and the MCP server's `version` field — so a script comparing a host against a
/// release does not have to know which face produced the number.
///
/// Deliberately undecorated. The caller is usually a script, not a human: `ikigai
/// 0.1.18`, nothing else on the line, exit 0.
const VERSION_LINE: &str = concat!("ikigai ", env!("CARGO_PKG_VERSION"));

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
    /// `-V` / `--version`: print `VERSION_LINE` to stdout and exit 0. A mode rather
    /// than an early `Ok(None)` because `Ok(None)` means "print the usage block",
    /// and burying a version behind a screen of help is the failure this fixes.
    Version,
    Repl(ReplArgs),
    /// Headless: build the watched kernel (timers, watcher, the standing sync)
    /// and park — the launchd-agent face of the desktop machine. Carries any
    /// `--mount`s so the standing DRAIN has an edge to pull from — without them the
    /// drain job fires against a kernel that cannot resolve `urn:edge:` and pulls nothing.
    Daemon {
        /// Each mount carries its own certificates, so the daemon needs no
        /// default set of its own (it never `--connect`s).
        mounts: Mounts,
    },
    Serve {
        target: Option<String>,
        certs: Certs,
        /// `--cap <scope>` (repeatable): a fixed capability ceiling every
        /// authenticated client is clamped to, instead of the default per-tenant
        /// filesystem workspace. This is how a server shares exactly one narrow
        /// affordance — e.g. `--cap urn:cap:personal:calendar:read:freebusy` serves
        /// free/busy and nothing else, the clamp forbidding any client from widening.
        /// Alongside a `clients.json` enrolment it is the OUTER bound instead: each
        /// client's own grant narrows within it and can never widen past it
        /// (see the `ikigai_embedded::clients` module).
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
        /// `--max-body <bytes>`: the largest request body this door accepts; a bigger one is
        /// refused with `413` before it is read. `None` → the transport's own default. Lower
        /// it for a door that only takes forms — the public intake edge has no use for a
        /// megabyte.
        max_body: Option<usize>,
        /// `--announce`: advertise this kernel on the local network over mDNS, so clients
        /// can mount it by name instead of by an address that moves. Opt-in — broadcasting
        /// what a machine serves is a disclosure.
        announce: bool,
        /// Remote kernels composed into the served surface (`--mount`/`--override`/
        /// `--prefer`, same syntax as the REPL). THE HOST OWNS THE TOPOLOGY: a local client
        /// then reaches a peer through this socket without knowing where it is, holding its
        /// certificates, or needing the platform permission discovery requires.
        mounts: Mounts,
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
        mounts: Mounts,
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
    /// never share a cert set. `--no-config-mounts` rides along as the DECLINE posture.
    mounts: Mounts,
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

/// What a kernel-building mode was TOLD about its mounts. THREE postures, not two:
///
/// - mount flags (`--mount`/`--override`/`--prefer`) are the WHOLE topology;
/// - `--no-config-mounts` composes ZERO, and does not read the config home at all;
/// - neither ⇒ the machine's own topology, from the config home's `mount` lines.
///
/// One value rather than a `Vec` plus a loose `bool`, so no door can plumb half of it: the
/// decline has to reach EVERY mode that builds a kernel, because the `mount` key is shared
/// by all of them — a decline honoured in one mode only would be the next version of the
/// bug it fixes (ledger #410).
#[derive(Default, Clone)]
struct Mounts {
    /// The mount flags, in argv order. Non-empty ⇒ the config home is not read.
    flags: Vec<Mount>,
    /// `--no-config-mounts`: compose nothing, and do not read the config home.
    declined: bool,
}

impl Mounts {
    /// The two postures are mutually exclusive, and that is a STARTUP ERROR rather than a
    /// precedence rule. A silent winner between "exactly these mounts" and "no mounts at
    /// all" is precisely the half-and-half mount set [`mounts_or_config`] exists to refuse
    /// to produce: from outside the process there is no way to tell which one took effect.
    fn refuse_conflict(&self) -> Result<(), String> {
        match self.flags.first() {
            Some(mount) if self.declined => Err(format!(
                "--no-config-mounts and {flag} cannot be combined: --no-config-mounts composes \
                 ZERO mounts and does not read the config home, while {flag} `{prefix}={target}` \
                 declares the whole topology. Pass one or the other.",
                flag = mount_flag(mount.kind),
                prefix = mount.prefix,
                target = mount.target,
            )),
            _ => Ok(()),
        }
    }
}

/// The mode word a `mount` line in the config home would use for this kind, so what the
/// banner prints is greppable in the file that produced it.
fn mount_mode(kind: ikigai_embedded::MountKind) -> &'static str {
    match kind {
        ikigai_embedded::MountKind::Alias => "alias",
        ikigai_embedded::MountKind::Override => "override",
        ikigai_embedded::MountKind::Prefer => "prefer",
    }
}

/// What this door composed, as the value `urn:host:posture` reports and both faces render
/// from — the facts of each mount, without the connected resolver or the private key
/// material behind its cert set.
///
/// ★ The banner and the resource render from ONE value through one renderer
/// ([`ikigai_embedded::posture::mount_lines`]). Two renderers over the same facts is how a
/// diagnostic and a resource end up as two spellings of one thing, which is the defect
/// class #418/#426 were about; this makes that impossible rather than merely discouraged.
fn mount_posture(mounts: &[Mount], declined: bool) -> ikigai_embedded::posture::MountPosture {
    if declined {
        return ikigai_embedded::posture::MountPosture::Declined;
    }
    ikigai_embedded::posture::MountPosture::Composed(
        mounts
            .iter()
            .map(|mount| ikigai_embedded::posture::ComposedMount {
                mode: mount_mode(mount.kind),
                prefix: mount.prefix.clone(),
                target: mount.target.clone(),
                cert_dir: mount.certs.cert_dir.clone(),
            })
            .collect(),
    )
}

/// The banner's mount block, in this crate's own terms — one line per mount, from
/// [`ikigai_embedded::posture::mount_lines`], which is where the reasoning lives (and which
/// `urn:host:posture` renders through too).
///
/// Printed BEFORE the mounts are resolved, so a door that hangs dialing a peer has already
/// named the peer it is hanging on. That was #410's actual failure mode.
fn mount_lines(mounts: &[Mount], declined: bool) -> Vec<String> {
    ikigai_embedded::posture::mount_lines(&mount_posture(mounts, declined))
}

/// Say what this door composed, on stderr, one line per mount. `who` prefixes every line
/// (`ikigai`, `ikigai mcp`) so a door's output stays attributable.
fn announce_mounts(who: &str, mounts: &[Mount], declined: bool) {
    for line in mount_lines(mounts, declined) {
        eprintln!("{who}: {line}");
    }
}

/// Everything `serve --http` was told, in one value.
///
/// A struct rather than eight positional arguments, and not to placate
/// `clippy::too_many_arguments`: the door had already reached the limit, so the next flag
/// was always going to be added either here or under an `#[allow]` — and an allow on this
/// function would then silently cover every flag after it too, which is the failure mode
/// the lint exists to prevent. Named fields also make the call site say which `bool` is
/// which.
///
/// ⚠ The `allow` is for the `web`-less build ONLY, where `serve_http` is the stub that
/// exits with "needs the `web` feature". The struct is still CONSTRUCTED there (the
/// dispatch arm is not feature-gated) and nothing reads it, so `-D dead-code` fires on
/// every field. Invisible to `cargo clippy --all-features`; CI's default-feature job is
/// what catches it.
#[cfg_attr(
    not(all(feature = "embedded", feature = "web")),
    allow(
        dead_code,
        reason = "the web-less build hands this to a stub that exits"
    )
)]
struct HttpDoor<'a> {
    /// `--http <port|host:port>`: a bare port binds loopback.
    bind: &'a str,
    /// `--cap`: the fixed ceiling every request resolves under. Empty ⇒ the public
    /// (empty-scope) capability.
    caps: &'a [String],
    trust_proxy: bool,
    cors_origins: &'a [String],
    routes: Option<&'a str>,
    routes_only: bool,
    max_body: Option<usize>,
    /// `--mount`/`--override`/`--prefer`, the machine's topology from the config home, or
    /// nothing at all under `--no-config-mounts`.
    mounts: Mounts,
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

/// If `arg` is `--scheduler`, consume its spec (`single` | `pool` | `pool:N`) and declare
/// it for this process. Accepted by every mode — a served kernel, the daemon, `mcp` and
/// the REPL all fan out on the same process scheduler.
///
/// **An invalid spec is an error here, not a fallback.** A typo'd `--scheduler pool:xyz`
/// quietly becoming `single` would leave the operator believing the host is N-wide while
/// it is one-wide — and a serialized fan-out is indistinguishable from a slow server from
/// outside the process. The deprecated `IKIGAI_SCHEDULER` keeps its lenient
/// warn-and-fall-back behaviour, because services in the field already set it.
fn scheduler_flag(arg: &str, argv: &mut impl Iterator<Item = String>) -> Result<bool, String> {
    if arg != "--scheduler" {
        return Ok(false);
    }
    let spec = argv
        .next()
        .ok_or_else(|| "--scheduler needs <single|pool|pool:N>".to_string())?;
    #[cfg(feature = "embedded")]
    ikigai_embedded::set_scheduler_spec(spec.as_str()).map_err(|e| format!("--scheduler: {e}"))?;
    #[cfg(not(feature = "embedded"))]
    let _ = spec;
    Ok(true)
}

/// If `arg` is `--width-routing`, consume its `on`/`off` value and declare it for this
/// process. Accepted by every mode, like `--scheduler` — the setting belongs to the host,
/// not to one command.
///
/// Off is the default, and deliberately: routing by width changes *which backend* answers,
/// and `ikigai-browse` folds model identity into a durable archive key — so the same file
/// explained twice would land under different entries depending on how many siblings its
/// request happened to have. An invalid value is an error rather than a fallback, for the
/// reason `--scheduler` gives: silently meaning "off" leaves nothing in the process to
/// contradict an operator who believes it is on.
fn width_routing_flag(arg: &str, argv: &mut impl Iterator<Item = String>) -> Result<bool, String> {
    if arg != "--width-routing" {
        return Ok(false);
    }
    let value = argv
        .next()
        .ok_or_else(|| "--width-routing needs <on|off>".to_string())?;
    #[cfg(feature = "embedded")]
    ikigai_embedded::set_width_routing(&value).map_err(|e| format!("--width-routing: {e}"))?;
    #[cfg(not(feature = "embedded"))]
    let _ = value;
    Ok(true)
}

/// `-V` / `--version` appearing anywhere in argv.
///
/// The scan is exact-token and unconditional — it does not know which flags take a
/// value, so a literal `--version` handed to one of them (`--name --version`) reads
/// as a version request. That is the deliberate price of not keeping a list of
/// value-taking flags here: such a list would rot silently the next time a flag is
/// added, and the failure would be a version flag that stops working in one arm.
fn version_requested<'a>(mut args: impl Iterator<Item = &'a str>) -> bool {
    args.any(|arg| arg == "-V" || arg == "--version")
}

/// Parse argv. `Ok(None)` means a usage request was handled and we should exit 0.
fn parse_args() -> Result<Option<Mode>, String> {
    parse_argv(std::env::args().skip(1))
}

/// The argument parser proper, over any argv — so it can be tested without a
/// process (which is how the per-mount certificate behaviour below is pinned).
fn parse_argv(args: impl Iterator<Item = String>) -> Result<Option<Mode>, String> {
    let args: Vec<String> = args.collect();
    // BEFORE any subcommand or mode parsing can consume it: `ikigai --version`,
    // `ikigai serve --version` and `ikigai --plain --version` must all answer the
    // same way. A version flag that works in only one arm is worse than none,
    // because it gets trusted.
    if version_requested(args.iter().map(String::as_str)) {
        return Ok(Some(Mode::Version));
    }
    let mut argv = args.into_iter().peekable();

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
        let mut max_body = None;
        let mut announce = false;
        let mut mounts = Mounts::default();
        while let Some(arg) = argv.next() {
            if cert_flag(&arg, &mut argv, &mut certs)? {
                // A cert flag FOLLOWING a mount belongs to that mount (the REPL's rule),
                // so two peers with different identities never share a set. Flags before
                // any mount are this server's own identity.
                if let Some(mount) = mounts.flags.last_mut() {
                    mount.certs = certs.clone();
                }
                continue;
            }
            if scheduler_flag(&arg, &mut argv)? || width_routing_flag(&arg, &mut argv)? {
                continue;
            }
            if arg == "--announce" {
                announce = true;
                continue;
            }
            if arg == "--no-config-mounts" {
                // DECLINE the machine's topology (see `Mounts`). The motivating case: an
                // inference peer that wants to be a LEAF, on a box whose shared config home
                // points every other process at IT.
                mounts.declined = true;
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
                mounts.flags.push(Mount {
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
            if arg == "--max-body" {
                let raw = argv
                    .next()
                    .ok_or_else(|| "--max-body needs a size in bytes".to_string())?;
                max_body = Some(
                    raw.parse::<usize>()
                        .map_err(|_| format!("--max-body wants a size in bytes ({raw})"))?,
                );
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
        // Both postures at once is a startup error, not a precedence rule (see `Mounts`).
        mounts.refuse_conflict()?;
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
            max_body,
            announce,
            mounts,
        }));
    }

    if argv.peek().map(String::as_str) == Some("mcp") {
        argv.next();
        let mut grants = Vec::new();
        let mut scopes = Vec::new();
        let mut certs = Certs::default();
        let mut mounts = Mounts::default();
        while let Some(arg) = argv.next() {
            // Cert flags AFTER a mount attach to it (the REPL's rule), so two peers
            // with different identities never share a set. mcp never `--connect`s,
            // so there is no default-set use for flags before any mount.
            if cert_flag(&arg, &mut argv, &mut certs)? {
                if let Some(mount) = mounts.flags.last_mut() {
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
                mounts.flags.push(Mount {
                    prefix: prefix.to_string(),
                    target: target.to_string(),
                    certs: certs.clone(),
                    kind,
                });
                continue;
            }
            if scheduler_flag(&arg, &mut argv)? || width_routing_flag(&arg, &mut argv)? {
                continue;
            }
            match arg.as_str() {
                // DECLINE the machine's topology (see `Mounts`).
                "--no-config-mounts" => mounts.declined = true,
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
        // Both postures at once is a startup error, not a precedence rule (see `Mounts`).
        mounts.refuse_conflict()?;
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
        let cert_target = match repl.mounts.flags.last_mut() {
            Some(mount) => &mut mount.certs,
            None => &mut repl.certs,
        };
        if cert_flag(&arg, &mut argv, cert_target)? {
            continue;
        }
        if scheduler_flag(&arg, &mut argv)? || width_routing_flag(&arg, &mut argv)? {
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
                repl.mounts.flags.push(Mount {
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
                repl.mounts.flags.push(Mount {
                    prefix: prefix.to_string(),
                    target: target.to_string(),
                    certs: repl.certs.clone(),
                    kind: ikigai_embedded::MountKind::Override,
                });
            }
            "--no-config-mounts" => {
                // DECLINE the machine's topology (see `Mounts`): compose ZERO mounts and do
                // not read the config home's `mount` lines.
                repl.mounts.declined = true;
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
                repl.mounts.flags.push(Mount {
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
    // Both postures at once is a startup error, not a precedence rule (see `Mounts`) — for
    // the REPL, the one-shot `-c`, and `--daemon`, which share this parse.
    repl.mounts.refuse_conflict()?;
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
        // One line, stdout, exit 0. Nothing is built, nothing is connected: the
        // question "which build am I on?" is asked precisely when the host is
        // suspect, so answering it must not depend on the host working.
        Mode::Version => println!("{VERSION_LINE}"),
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
            max_body,
        } => match (http, target.as_deref()) {
            // The inbound HTTP face takes precedence over IPC/QUIC when `--http` is given.
            (Some(bind), _) => serve_http(HttpDoor {
                bind: &bind,
                caps: &caps,
                trust_proxy,
                cors_origins: &cors_origins,
                routes: routes.as_deref(),
                routes_only,
                max_body,
                mounts,
            }),
            (None, Some(t)) if is_quic(t) => serve_quic(t, &certs, &caps, announce, mounts),
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
            let (engine, topology) =
                build_engine(args.connect, args.mounts, &args.certs, args.react).unwrap_or_else(
                    |e| {
                        eprintln!("ikigai: {e}");
                        std::process::exit(1);
                    },
                );
            run_repl(engine, args.plain, &args.commands, &topology);
        }
    }
}

/// Headless mode: build the watched kernel — the filesystem watcher, the time
/// transport, and (via calendar.json's `derive_every`) the standing
/// consolidated-view sync all live in it — then park. This is what a
/// LaunchAgent runs: the desktop machine as a quiet, always-on resolver.
#[cfg(feature = "embedded")]
fn daemon(mounts: Mounts) {
    // No mount flags -> the machine's own topology (config home), same rule as every
    // kernel-building mode. The booking picker asking urn:llm:ask in THIS process is
    // exactly who a `mount = "prefer urn:llm:=peer:plasma"` line is for.
    let declined = mounts.declined;
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
    announce_mounts("ikigai", &mounts, declined);
    // What this process composed, for `urn:host:posture`. Recorded by EVERY door that
    // builds a kernel, including the ones with no wire face: an unrecorded posture answers
    // "nobody told me", and a door that quietly skipped the call would make its own
    // topology unaskable while looking like a host that composed nothing.
    ikigai_embedded::posture::set_posture(ikigai_embedded::posture::Posture {
        door: "none — the writer daemon serves no transport; it holds the reactive kernel"
            .to_string(),
        mounts: mount_posture(&mounts, declined),
        clients: Vec::new(),
        surface: None,
        authority: Some("root — this process resolves under the identity it runs as".to_string()),
        reloads: Vec::new(),
    });
    let kernel = if mounts.is_empty() {
        ikigai_embedded::reactive_kernel_with_mounts(Vec::new())
    } else {
        let mut resolved = Vec::new();
        for mount in mounts {
            // Each mount connects with ITS OWN certificates.
            match resolve_mount(mount) {
                Ok(spec) => resolved.push(spec),
                // A mount that will not connect is fatal here: the daemon's whole reason to
                // hold a mount is the drain, and a silent no-op is the failure mode this is
                // fixing. Say so and exit rather than park looking healthy. (A --prefer
                // mount never lands here — it connects on demand, by design.)
                Err(e) => {
                    eprintln!("ikigai: {e}");
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
fn daemon(_mounts: Mounts) {
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
fn mcp(grants: Vec<String>, scopes: Vec<String>, mounts: Mounts) {
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
    let declined = mounts.declined;
    let mounts = match mounts_or_config(mounts) {
        Ok(mounts) => mounts,
        // A topology that does not parse must never look like no topology.
        Err(e) => {
            eprintln!("ikigai: {e}");
            std::process::exit(2);
        }
    };
    announce_mounts("ikigai mcp", &mounts, declined);
    ikigai_embedded::posture::set_posture(ikigai_embedded::posture::Posture {
        door: "stdio (MCP)".to_string(),
        mounts: mount_posture(&mounts, declined),
        clients: Vec::new(),
        surface: None,
        // The ceiling is `--grant`/`--scope`, which is also the tool list the client sees:
        // the manifold is projected under it, so an agent with no `urn:cap:host:posture`
        // in its grant is not even OFFERED this resource, let alone answered.
        authority: Some(match capability.read().expect("cap lock").scopes() {
            None => "root — no --grant/--scope was given (UNRESTRICTED)".to_string(),
            Some(s) => format!("{} scope(s) from --grant/--scope", s.len()),
        }),
        // The grants poller rebuilds the session capability when the file changes and emits
        // `tools/list_changed`, so the ceiling above is a startup READING of something this
        // door re-reads — exactly the over-claim `reloads` exists to prevent.
        reloads: vec![
            "grants.json — the active grant's scopes are re-read while running, and the \
             projected tool list is rebuilt live (no restart)"
                .to_string(),
        ],
    });
    let kernel = if mounts.is_empty() {
        ikigai_embedded::watched_kernel()
    } else {
        let mut resolved = Vec::new();
        for mount in mounts {
            match resolve_mount(mount) {
                Ok(spec) => resolved.push(spec),
                // Fatal, like the daemon: an MCP server that silently dropped a mount
                // would project a manifold missing the tools the topology promised.
                // (A --prefer mount never lands here — it connects on demand.)
                Err(e) => {
                    eprintln!("ikigai: {e}");
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
fn mcp(_grants: Vec<String>, _scopes: Vec<String>, _mounts: Mounts) {
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
///
/// Returns the engine and the TOPOLOGY LINES the interactive REPL should show — what this
/// kernel composed, in the same words the serving doors print. The REPL had no mount line
/// at ALL (ledger #418): every server said something about its topology and the one face a
/// human sits in front of said nothing, so an interactive session could not see what it was
/// resolving through. A `--connect` client composes nothing of its own and gets no lines;
/// the host it attaches to owns the topology and prints it.
#[cfg(feature = "embedded")]
fn build_engine(
    connect: Option<Option<String>>,
    mounts: Mounts,
    certs: &Certs,
    react: bool,
) -> Result<(Engine, Vec<String>), String> {
    match connect {
        // The watched kernel: cached workspace reads also invalidate on an
        // out-of-band file change (an editor), not just a `sink` through the REPL.
        // The same process scheduler drives both the kernel's fan-out and the
        // engine's `( a ; b )` / `..` parallelism, so `--scheduler pool:N` (or the
        // config home's `scheduler` key) governs all of it — and at the default
        // `single` all of it runs SEQUENTIALLY, because a Single scheduler polls its
        // tasks cooperatively on one thread and the HTTP transport blocks that thread.
        // Any `--mount`s compose remote kernels into it.
        None => {
            // No mount flags -> the machine's own topology (config home). Only here in
            // the EMBEDDED branch: a `--connect` client composes nothing — the host it
            // connects to owns the topology.
            let declined = mounts.declined;
            let mounts = mounts_or_config(mounts)?;
            let composed = mount_posture(&mounts, declined);
            let topology = ikigai_embedded::posture::mount_lines(&composed);
            // ⚠ This door's posture is the least interesting one there is, and saying so is
            // the point: a one-shot CLI or REPL composes the topology FROM THE CONFIG HOME
            // at the moment it starts, so asking it about its posture is nearly the same
            // question as reading the file. The answer worth having comes from a SERVING
            // process, whose composition happened at a startup you were not present for
            // (ledger #408/#428). Recorded anyway, because "unrecorded" must mean
            // unrecorded.
            ikigai_embedded::posture::set_posture(ikigai_embedded::posture::Posture {
                door: "none — in-process (this REPL/one-shot kernel)".to_string(),
                mounts: composed,
                clients: Vec::new(),
                surface: None,
                authority: Some(
                    "root — the running user IS the owner (`cap` attenuates it voluntarily)"
                        .to_string(),
                ),
                reloads: Vec::new(),
            });
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
            // The same process scheduler that decides how wide a fan-out RUNS also
            // decides what it may route on — so the engine reads its achievable width
            // from this spawner, and routes on it only if the host turned that on.
            Ok((
                with_profiles(
                    Engine::new(kernel)
                        .with_spawner(std::sync::Arc::new(ikigai_embedded::scheduler()))
                        .with_width_routing(ikigai_embedded::width_routing()),
                ),
                topology,
            ))
        }
        Some(target) => {
            if !mounts.flags.is_empty() {
                return Err("--mount composes into the embedded kernel; drop --connect".to_string());
            }
            // A `--connect` client composes nothing of its own, so declining the config home
            // would be INERT rather than wrong — and a flag that silently does nothing is how
            // an operator comes to believe a topology was declined when it was not.
            if mounts.declined {
                return Err(
                    "--no-config-mounts declines the config home for a kernel this process \
                     BUILDS; a --connect client composes no mounts anyway (the host it attaches \
                     to owns the topology) — drop one of the two"
                        .to_string(),
                );
            }
            match target.as_deref() {
                Some(t) if is_quic(t) => connect_quic(t, certs),
                _ => connect_ipc(target),
            }
            .map(|engine| (engine, Vec::new()))
        }
    }
}

/// The mounts a kernel-building mode composes. THREE postures: flags are POSTURE and win
/// WHOLESALE when given; `--no-config-mounts` composes ZERO and does not read the config
/// home at all; otherwise the machine's own topology from the config home. Wholesale rather
/// than merged, because a half-and-half mount set is the kind of thing nobody can debug at
/// 2am. Every mode that builds a kernel from nothing routes through this — the REPL/one-shot,
/// `serve` (all three doors), the daemon, mcp — so `mount =` lines mean the MACHINE composes
/// that way, not one lucky process, and DECLINING has to reach every one of them too.
///
/// ★ Why decline needed a posture of its own rather than an empty flag set: the config home
/// is SHARED by every process on the box, so a server given no mount flags inherits the
/// machine's whole topology — including the very lines that point the other processes at IT.
/// plasma's inference peer composed gonk, gonk mounts the peer for `urn:llm:`, and each
/// side's self-description then waited out its bound on the other (31s for `Call::Entries`,
/// ~109s for the HTTP index page that enumerates). Before this flag, declining the config
/// home meant enumerating a replacement topology the process did not want, because any flag
/// it was given became its whole topology (ledger #410).
#[cfg(feature = "embedded")]
fn mounts_or_config(mounts: Mounts) -> Result<Vec<Mount>, String> {
    resolve_mounts(mounts, config_mounts)
}

/// [`mounts_or_config`] with the config home's topology as a THUNK, so a test can assert what
/// the flag actually promises — that declining does not READ the file — instead of only that
/// the result came back empty, which an absent or unreadable config home produces too.
fn resolve_mounts(
    mounts: Mounts,
    config: impl FnOnce() -> Result<Vec<Mount>, String>,
) -> Result<Vec<Mount>, String> {
    // The backstop for the exclusion: each parse site refuses first (with the usage block),
    // but this is the one function every kernel-building door provably calls.
    mounts.refuse_conflict()?;
    if mounts.declined {
        Ok(Vec::new())
    } else if mounts.flags.is_empty() {
        config()
    } else {
        Ok(mounts.flags)
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
    mounts_from_config_lines(ikigai_embedded::config::all("mount"))
}

/// [`config_mounts`] over lines already read, so the line grammar is testable without a
/// config home: the environment is process-global, and mutating it races the test harness.
fn mounts_from_config_lines(lines: Vec<String>) -> Result<Vec<Mount>, String> {
    lines
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

/// Turn a parsed [`Mount`] into a [`MountSpec`](ikigai_embedded::MountSpec), connecting eagerly or lazily
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
                entries_failed: std::sync::Mutex::new(None),
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
/// A failure to connect is reported as the transient [`Error::Unavailable`](ikigai_core::Error::Unavailable) it is,
/// which is exactly what makes the `Failover` above it fall through to the local
/// binding.
///
/// Once connected, the resolver is KEPT even across failures — the transports
/// re-establish their own connections (`QuicResolver::round_trip` redials on any
/// transport error; `IpcResolver::round_trip` heals a dead connection on use),
/// so a peer that goes and returns is handled a layer down.
/// Dropping it here instead looks tempting and is still not what this does — but the
/// reason has changed. Until 2026-09-16 `QuicResolver::drop` called `block_on` on its own
/// runtime, so releasing a resolver from inside a resolution (which runs under a runtime)
/// was the context where blocking is not allowed. `ikigai-quic` now detects that and hands
/// the flush to a thread of its own, so a drop here would be SAFE; it is simply not needed,
/// because the transport heals its own connection a layer down.
struct LazyResolver {
    target: String,
    certs: Certs,
    inner: std::sync::Mutex<Option<std::sync::Arc<dyn ikigai_resolve::Resolver>>>,
    /// When the last `entries()` dial FAILED — the negative cache that keeps an
    /// enumeration-happy session from paying the connect bound on every `list`
    /// while the peer is asleep. Only `entries()` consults it: resolutions keep
    /// their retry-on-every-use behavior, which is what picks a woken peer up.
    entries_failed: std::sync::Mutex<Option<std::time::Instant>>,
}

/// How long `entries()` believes a failed dial before trying again.
const ENTRIES_REDIAL_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

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
        self.try_entries().ok().flatten()
    }

    /// The enumeration, keeping the failure — with ONE failure deliberately swallowed.
    ///
    /// ★ A `--prefer` mount's whole contract is that the peer may be absent, so a peer
    /// that will not DIAL is normal operation, not a degraded catalog: reporting it as an
    /// error would put a "mount unavailable" row in the manifold of every laptop whose
    /// workstation is asleep. A peer that is CONNECTED and then goes silent is the
    /// opposite — it was there, its resources are real, and the catalog is now missing
    /// them — so that error propagates.
    fn try_entries(&self) -> Result<Option<Vec<ikigai_core::SpaceEntry>>, ikigai_core::Error> {
        // An explicit enumeration deserves the truth: dial if we never have.
        // Without this, a prefer-mounted namespace the local kernel does not
        // also bind was INVISIBLE to `list` until something else used the peer
        // (mcp works around it with a startup warm, cli #270 — the REPL had
        // nothing). The cost is bounded (a UDS refusal is instant, QUIC by its
        // dial budget) and paid at most once per ENTRIES_REDIAL_AFTER while
        // the peer is asleep — resolutions keep their retry-on-every-use.
        if let Some(resolver) = self.inner.lock().unwrap().clone() {
            return resolver.try_entries();
        }
        {
            let failed = self.entries_failed.lock().unwrap();
            if let Some(at) = *failed {
                if at.elapsed() < ENTRIES_REDIAL_AFTER {
                    return Ok(None); // asleep a moment ago; don't stall every list
                }
            }
        }
        match self.get() {
            Ok(resolver) => {
                *self.entries_failed.lock().unwrap() = None;
                resolver.try_entries()
            }
            Err(_) => {
                // Native-only: `ikigai-cli` is the host BINARY — clap, the QUIC/IPC transports,
                // a terminal. It is never built for wasm. This stamps the negative cache for a
                // peer dial that failed, and the kernel Clock is not in scope on this path.
                // Bound to a `let` only so the attribute has a statement to sit on — an
                // attribute on an assignment expression is not stable (E0658) — which keeps
                // the opt-out on this one call instead of the whole method.
                #[allow(clippy::disallowed_methods)]
                let failed_at = std::time::Instant::now();
                *self.entries_failed.lock().unwrap() = Some(failed_at);
                Ok(None)
            }
        }
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
    // The connect error names the flag the operator actually wrote: a down
    // prefer-mount peer surfacing at first use as `--mount: connect …` sent the
    // reader hunting for a flag that was never typed.
    let flag = mount_flag(kind);
    // `peer:<name>` — mount by NAME, letting mDNS supply the address. Addresses move
    // (bug's `ipconfig getifaddr en0` came back empty during the mail work, because it was
    // on another interface); a name does not.
    if let Some(name) = target.strip_prefix("peer:") {
        let (resolved, certs) = resolve_peer(name, certs)?;
        return connect_mount_quic(&resolved, &certs, flag);
    }
    if is_quic(target) {
        connect_mount_quic(target, certs, flag)
    } else {
        connect_mount_ipc(target, kind, flag)
    }
}

/// The flag spelling of a mount kind (a `mount =` config line uses the same
/// word without the dashes).
fn mount_flag(kind: ikigai_embedded::MountKind) -> &'static str {
    match kind {
        ikigai_embedded::MountKind::Alias => "--mount",
        ikigai_embedded::MountKind::Override => "--override",
        ikigai_embedded::MountKind::Prefer => "--prefer",
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

/// The conventional per-peer certificate directory: `<config home>/quic-<name>/`.
/// plasma holds `quic-bug`, bug holds `quic-plasma`.
///
/// Resolved through the SAME config home as [`quic::dir`](crate::quic) and as
/// `holds_cert_for`'s oracle in the embedded host — this used to hardcode
/// `$HOME/.config/ikigai` while `quic::dir` honoured `XDG_CONFIG_HOME`, so setting that
/// variable pointed the dialer at one directory and the certificate writer at another.
#[cfg(all(feature = "embedded", feature = "quic"))]
fn peer_cert_dir(name: &str) -> std::path::PathBuf {
    ikigai_embedded::config::config_home()
        .unwrap_or_default()
        .join(format!("quic-{name}"))
}

/// Without the `quic` feature there is nothing to dial a discovered peer with.
#[cfg(all(feature = "embedded", not(feature = "quic")))]
fn resolve_peer(name: &str, _certs: &Certs) -> Result<(String, Certs), String> {
    Err(format!(
        "peer:{name}: mounting a discovered peer needs the `quic` feature"
    ))
}

/// The deadline a mounted peer's SELF-DESCRIPTION runs under: `describe.timeout`
/// (seconds) in the host config, else the transport default. `0` takes the bound off.
///
/// One key for both transports on purpose. What it bounds is a peer describing itself —
/// an enumeration, or one endpoint's contract — and that is the same act whether the peer
/// is behind a Unix socket or a QUIC connection. Two keys would make a federation's
/// legibility depend on which socket a peer happened to be reached through, which is not a
/// distinction an operator is thinking about when their catalog stops returning.
///
/// Config home, not an environment variable. ⚠ Raise it when the federation is DEEP:
/// enumeration is transitive and the bound is per hop, so three kernels deep the outermost
/// one needs headroom for both the hops below it.
#[cfg(feature = "embedded")]
fn describe_timeout(default: std::time::Duration) -> Option<std::time::Duration> {
    match ikigai_embedded::config::get("describe.timeout")
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(0) => None,
        Some(secs) => Some(std::time::Duration::from_secs(secs)),
        None => Some(default),
    }
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
    flag: &'static str,
) -> Result<std::sync::Arc<dyn ikigai_resolve::Resolver>, String> {
    let addr = quic::parse_addr(target)?;
    let identity = quic::client_identity(certs)?;
    let trusted = quic::trusted_server_cert(certs)?;
    let resolver = ikigai_quic::connect_with(addr, &identity, &trusted, quic_idle_timeout())
        .map_err(|e| format!("{flag}: connect {target}: {e}"))?
        .with_describe_timeout(describe_timeout(ikigai_quic::DEFAULT_DESCRIBE_TIMEOUT));
    Ok(std::sync::Arc::new(resolver))
}

#[cfg(all(feature = "embedded", not(feature = "quic")))]
fn connect_mount_quic(
    _target: &str,
    _certs: &Certs,
    flag: &'static str,
) -> Result<std::sync::Arc<dyn ikigai_resolve::Resolver>, String> {
    Err(format!(
        "{flag} of a quic:// target needs the `quic` feature"
    ))
}

#[cfg(all(feature = "embedded", feature = "ipc"))]
fn connect_mount_ipc(
    socket: &str,
    kind: ikigai_embedded::MountKind,
    flag: &'static str,
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
        .map_err(|e| format!("{flag}: connect {socket}: {e}"))?
        .with_describe_timeout(describe_timeout(ikigai_ipc::DEFAULT_DESCRIBE_TIMEOUT));
    Ok(std::sync::Arc::new(resolver))
}

#[cfg(all(feature = "embedded", not(feature = "ipc")))]
fn connect_mount_ipc(
    _socket: &str,
    _kind: ikigai_embedded::MountKind,
    flag: &'static str,
) -> Result<std::sync::Arc<dyn ikigai_resolve::Resolver>, String> {
    Err(format!(
        "{flag} of a Unix socket needs the `ipc` feature (Unix only)"
    ))
}

/// Drive the engine: one-shot `-c`, else the full-screen TUI on a terminal, else
/// the line REPL.
///
/// `topology` is what this kernel composed (see [`build_engine`]), shown to an INTERACTIVE
/// session only. A `-c` batch is a shell citizen — its stderr is somebody's script — and
/// the one-shot caller already chose its mounts on the command line or in the config home
/// it is reading. The human sitting at a prompt did not.
#[cfg(feature = "embedded")]
fn run_repl(engine: Engine, plain: bool, commands: &[String], topology: &[String]) {
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
            if let Err(e) = tui::run(engine, ikigai_engine::config::keybindings(), topology) {
                eprintln!("ikigai: tui error: {e}");
                std::process::exit(1);
            }
            return;
        }
        repl::run(engine, topology);
    }
    #[cfg(target_family = "wasm")]
    repl::run(engine, topology);
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
            // The id this cert will be KNOWN BY in clients.json. Printed here because
            // this is the moment the operator has the certificate in hand; otherwise
            // enrolling means going back for `openssl x509 -noout -fingerprint -sha256`.
            if let Ok(pem) = std::fs::read_to_string(&path) {
                if let Ok(fingerprint) = ikigai_quic::fingerprint_of_pem(&pem) {
                    println!(
                        "fingerprint: {fingerprint}\n  \
                         to give it its own authority, add it to the `clients` map in \
                         {}: \"{fingerprint}\": {{\"grant\": \"<grant>\", \"label\": \"{name}\"}}",
                        ikigai_embedded::clients::clients_path()
                            .map_or_else(|| "clients.json".into(), |p| p.display().to_string())
                    );
                }
            }
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

/// How much of a certificate fingerprint a diagnostic prints.
///
/// The full id is a 64-hex-character SHA-256, and that is what `cert add-client` prints and
/// what a `clients.json` key must be — a banner listing several of them in full is noise an
/// operator reads past. Sixteen is a PREFIX of exactly that string, in the same case, so
/// comparing by eye compares one fact rather than two spellings of it; it is also the
/// length the per-connection `client … → grant` line has always used, and one truncation
/// beats two.
#[cfg(all(feature = "embedded", feature = "quic"))]
const FINGERPRINT_SHOWN: usize = 16;

/// The leading [`FINGERPRINT_SHOWN`] characters of a fingerprint.
///
/// ⚠ A fingerprint is a hash of a PUBLIC certificate. It discloses no authority — holding
/// it does not let anyone connect, and a client is refused unless it presents the private
/// key. That is why it is safe on a banner even though these logs land world-readable under
/// `/tmp`; the certificate it names is already sent in the clear at every handshake.
#[cfg(all(feature = "embedded", feature = "quic"))]
fn short_fingerprint(full: &str) -> &str {
    &full[..full.len().min(FINGERPRINT_SHOWN)]
}

/// The trusted client certificates as identities: label, SHORT fingerprint, and the file
/// that put each one in the trusted set.
///
/// ★ **The fingerprint is truncated exactly once, here.** This is the only place in the
/// process that shortens one: the banner and `urn:host:posture` both render from the value
/// this returns, so a reader comparing the two is comparing one fact rather than two
/// spellings of it. `ikigai-embedded` could not do it anyway — `fingerprint_of_pem` lives
/// in `ikigai-quic`, which it does not depend on — and that accident happens to enforce
/// the rule.
///
/// An unparseable PEM becomes `unreadable` rather than vanishing: a certificate this server
/// has loaded and cannot describe is a fact the operator needs, not one to hide. The base
/// certificate is labelled `base` rather than listed as though it were a peer — it is the
/// one that made the old count lie (ledger #426), so it says what it is.
#[cfg(all(feature = "embedded", feature = "quic"))]
fn trusted_identities(
    trusted: &[quic::TrustedClient],
) -> Vec<ikigai_embedded::posture::TrustedIdentity> {
    trusted
        .iter()
        .map(|client| ikigai_embedded::posture::TrustedIdentity {
            label: client.label.clone(),
            fingerprint: ikigai_quic::fingerprint_of_pem(&client.pem).map_or_else(
                |_| "unreadable".to_string(),
                |f| short_fingerprint(&f).to_string(),
            ),
            path: client.path.display().to_string(),
        })
        .collect()
}

#[cfg(all(feature = "embedded", feature = "quic"))]
fn serve_quic(target: &str, certs: &Certs, caps: &[String], announce: bool, mounts: Mounts) -> ! {
    let caps = caps.to_vec();
    let result = (|| -> Result<(), String> {
        let addr = quic::parse_addr(target)?;
        let identity = quic::server_identity(certs)?;
        let trusted = quic::trusted_clients(certs)?;
        // Flags are POSTURE and win wholesale when given; `--no-config-mounts` composes
        // none; otherwise the machine's own topology from the config home — the same rule as
        // every kernel-building mode.
        let declined = mounts.declined;
        let mounts = mounts_or_config(mounts)?;
        // SELF-MOUNT GUARD, the QUIC face of serve_ipc's: the config home is shared by
        // every process on the machine, so the very lines that point OTHER processes at
        // this server (`mount = "prefer urn:repo:=quic://plasma:4433"`) are also read by
        // the serving process itself. A mount that dials our own bind address would
        // resolve through ourselves — skip it, one warning each, rather than dial.
        let announced = announce.then(ikigai_embedded::instance_name);
        let mounts: Vec<Mount> = mounts
            .into_iter()
            .filter(|mount| {
                let own = is_own_quic_addr(&mount.target, addr, announced);
                if own {
                    eprintln!(
                        "ikigai: mount `{}={}` targets this process's own serve address — \
                         skipped (this instance IS the server; that line is for the other \
                         processes on this machine)",
                        mount.prefix, mount.target
                    );
                }
                !own
            })
            .collect();
        // Connect the mounts BEFORE announcing readiness, exactly as serve_ipc does: a
        // host that says it is serving and then cannot reach the peer it was told to
        // compose is worse than one that refuses to start. (`--prefer` is exempt — its
        // peer being absent is normal, and it dials on demand.)
        announce_mounts("ikigai", &mounts, declined);
        // Held for the posture record below, which is built where the LAST of its facts
        // (the surface and the ceiling) becomes known — the resolve loop consumes `mounts`.
        let composed = mount_posture(&mounts, declined);
        let mut resolved = Vec::new();
        for mount in mounts {
            resolved.push(resolve_mount(mount)?);
        }
        // Capability-on-the-wire: every connection's ceiling is minted per-connection
        // from *which* certificate authenticated. The cert IS the credential — the
        // same identity→capability move as the browser passkey, over mTLS — and the
        // server clamps any carried capability down to it (never widens).
        //
        // THREE postures, most specific first.
        //
        // 1. PER-IDENTITY GRANTS, when a `clients.json` enrols certificates: the
        //    session capability is a function of *which* certificate authenticated,
        //    fingerprint → grant name → scopes, re-read per connection so editing the
        //    file revokes a client on its next call. Unenrolled ⇒ REFUSED, never the
        //    shared ceiling and never root.
        // 2. `--cap`: a FIXED ceiling shared by every authenticated client
        //    (`--cap urn:cap:personal:calendar:read:freebusy` = a free/busy share and
        //    nothing else). It also remains the OUTER bound under posture 1.
        // 3. Neither: the default per-tenant filesystem workspace, where each client
        //    transparently roots at its own segment (`urn:file:x`).
        //
        // A `clients.json` that exists but does not parse stops the server here: a
        // broken authority config must not degrade into serving everyone under 2 or 3.
        let enrolment = ikigai_embedded::clients::enrolment()?;
        // A served connection addresses files only inside `file_root/<segment>` — the
        // file module's jail refuses absolute IRI paths and anything outside its root
        // whatever the capability says, and the transport roots each tenant at its own
        // segment. So an fs scope naming an ABSOLUTE path outside the jail authorizes a
        // path no client can name: it looks like a narrow grant and grants nothing.
        // Refuse to start rather than run it — a silently inert authority config is the
        // failure this whole posture exists to avoid. (Relative fs scopes are the other
        // half, and are given a reachable meaning at mint time below.)
        let file_root = ikigai_embedded::file_root();
        let declared: Vec<String> = caps
            .iter()
            .cloned()
            .chain(
                enrolment
                    .iter()
                    .flat_map(|e| e.grant_names())
                    .flat_map(|name| ikigai_embedded::grant_scopes(&name)),
            )
            .collect();
        let unaddressable = ikigai_embedded::tenant::unaddressable_fs_scopes(&declared, &file_root);
        if !unaddressable.is_empty() {
            return Err(format!(
                "these file scopes name paths no client of this server can address:\n  \
                 {}\n  \
                 a served connection reaches only {}/<its segment>/… — the file module is \
                 jailed there and refuses everything outside it, capability or not.\n  \
                 write the path RELATIVE to the client's own workspace (`urn:cap:fs:read:notes` \
                 grants the `notes` it addresses as `urn:file:notes/…`), or point IKIGAI_FILES \
                 at the tree you meant to serve.",
                unaddressable.join("\n  "),
                file_root.display()
            ));
        }
        // The enrolment is re-read per connection inside the minter (that is what makes
        // an edit a revocation), so the startup read is used only to CHOOSE the posture
        // and to report it.
        let minter: ikigai_quic::Minter = if enrolment.is_some() {
            // `--cap` still bounds every grant; with no `--cap` the grant IS the authority.
            let ceiling = if caps.is_empty() {
                ikigai_core::Capability::root()
            } else {
                ikigai_core::Capability::scoped(caps.clone())
            };
            let path = ikigai_embedded::clients::clients_path()
                .map_or_else(|| "clients.json".into(), |p| p.display().to_string());
            let root = file_root.clone();
            std::sync::Arc::new(move |peer: &ikigai_quic::PeerIdentity| {
                match ikigai_embedded::clients::authority(&peer.fingerprint, &ceiling) {
                    Ok((grant, capability)) => {
                        // A grant's fs scopes are written the way the CLIENT addresses
                        // files (`urn:file:notes/…`), so resolve them against this
                        // connection's own workspace — the namespace its IRIs land in.
                        let capability = ikigai_embedded::tenant::root_fs_scopes(
                            &capability,
                            &ikigai_embedded::tenant::tenant_root(&root, &peer.segment_id),
                        );
                        eprintln!(
                            "ikigai: client {} → grant \"{grant}\" ({})",
                            short_fingerprint(&peer.fingerprint),
                            match capability.scopes() {
                                None => "unrestricted".to_string(),
                                Some(s) => format!("{} scope(s)", s.len()),
                            }
                        );
                        Some(ikigai_quic::Session {
                            capability,
                            file_segment: peer.segment_id.clone(),
                        })
                    }
                    // The FULL fingerprint, so debugging a denied client is a copy-paste
                    // rather than a packet capture.
                    Err(why) => {
                        eprintln!(
                            "ikigai: REFUSED a trusted client certificate — {why}\n  \
                             fingerprint: {}\n  \
                             to enrol it, add it to the `clients` map in {path}",
                            peer.fingerprint
                        );
                        None
                    }
                }
            })
        } else if caps.is_empty() {
            let root = file_root.clone();
            std::sync::Arc::new(move |peer: &ikigai_quic::PeerIdentity| {
                let segment = ikigai_embedded::tenant::tenant_root(&root, &peer.segment_id);
                let _ = std::fs::create_dir_all(&segment); // the tenant's private dir
                let seg = segment.display();
                Some(ikigai_quic::Session {
                    capability: ikigai_core::Capability::root().attenuate([
                        format!("urn:cap:fs:read:{seg}"),
                        format!("urn:cap:fs:write:{seg}"),
                        format!("urn:cap:fs:delete:{seg}"),
                    ]),
                    file_segment: peer.segment_id.clone(),
                })
            })
        } else {
            let ceiling = ikigai_core::Capability::scoped(caps.clone());
            let root = file_root.clone();
            std::sync::Arc::new(move |peer: &ikigai_quic::PeerIdentity| {
                Some(ikigai_quic::Session {
                    // The shared ceiling is shared, but each connection's file namespace
                    // is its own: a relative `--cap` fs scope means "this client's own
                    // `notes`", resolved per connection like a grant's.
                    capability: ikigai_embedded::tenant::root_fs_scopes(
                        &ceiling,
                        &ikigai_embedded::tenant::tenant_root(&root, &peer.segment_id),
                    ),
                    file_segment: peer.segment_id.clone(),
                })
            })
        };
        let posture = match (&enrolment, caps.is_empty()) {
            (Some(e), true) => format!("per-identity grants: {} enrolled", e.len()),
            (Some(e), false) => format!(
                "per-identity grants: {} enrolled, under ceiling: {}",
                e.len(),
                caps.join(", ")
            ),
            (None, true) => "per-client workspaces".to_string(),
            (None, false) => format!("fixed ceiling: {}", caps.join(", ")),
        };
        if let Some(default_grant) = enrolment.as_ref().and_then(|e| e.default_grant()) {
            eprintln!(
                "ikigai: warning: clients.json sets an explicit shared default grant \
                 \"{default_grant}\" — every trusted certificate that is not enrolled \
                 individually gets it"
            );
        }
        // A personal ceiling means this is a personal-resource server (the calendar
        // federation): serve the minimal calendar-only kernel — availability + calendar
        // and nothing else — instead of the default served kernel (host + fs). The clamp
        // still gates it (a freebusy ceiling → freebusy), but the manifold is also
        // minimal, so nothing but the calendar is even nameable over the wire.
        // THE GRANT DECIDES THE SURFACE. Each optional face is switched on by the
        // ceiling the operator set, so a capability that could never be exercised
        // never puts its endpoints on the wire.
        //
        // Under per-identity grants the operator's declared intent is `--cap` PLUS
        // every enrolled grant — otherwise `serve` with no `--cap` could only ever
        // offer the default surface, whatever the grants named. The surface is still
        // one startup-time decision (per-session surfaces are a much larger change),
        // so enrolling a grant that needs a new face takes a restart; the per-call
        // clamp is what makes serving one surface to differently-scoped clients safe.
        let surface_caps: Vec<String> = {
            let mut union = caps.clone();
            for grant in enrolment.iter().flat_map(|e| e.grant_names()) {
                union.extend(ikigai_embedded::grant_scopes(&grant));
            }
            union.sort();
            union.dedup();
            union
        };
        let surface = ikigai_embedded::ServedSurface {
            personal: surface_caps
                .iter()
                .any(|c| c.starts_with("urn:cap:personal:")),
            wire_eval: surface_caps
                .iter()
                .any(|c| c == "urn:cap:lisp" || c == "urn:cap:lisp:run"),
            // A net grant means "you may spend my inference": urn:llm:* becomes
            // servable, still bounded by require_net to the granted provider hosts.
            llm: surface_caps.iter().any(|c| c.starts_with("urn:cap:net:")),
        };
        let kernel = ikigai_embedded::served_kernel_with_mounts("Remote (QUIC)", surface, resolved);
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
        let identities = trusted_identities(&trusted);
        for line in ikigai_embedded::posture::client_lines(&identities) {
            eprintln!("ikigai: {line}");
        }
        eprintln!("ikigai: serving on {target}  ({posture}; surface: {surface})  (Ctrl-C to stop)");
        // ★ The same facts the four lines above just printed, recorded as a RESOURCE. This
        // is the door the whole item came from: the peer that cost plasma a ~120s manifold
        // (#408) had composed two mounts back at its own caller, and the only way to learn
        // that was to have been present at its startup. From here it is a question.
        //
        // Every value is the one that went to the banner — the mount facts, the SAME
        // truncated fingerprints, the surface and the ceiling strings — so the two cannot
        // read differently.
        ikigai_embedded::posture::set_posture(ikigai_embedded::posture::Posture {
            door: target.to_string(),
            mounts: composed,
            clients: identities,
            surface: Some(surface.clone()),
            authority: Some(posture.clone()),
            // ⚠ Under per-identity grants the ceiling above is a startup READING: the
            // minter re-reads clients.json (and grants.json through it) on EVERY
            // connection, which is what makes editing the file a revocation rather than a
            // TTL wait. The certificate SET is frozen — the PEMs were read once and handed
            // to the transport — so which certificates may connect cannot change while this
            // process runs, but WHICH AUTHORITY each gets can, and nothing here reports it.
            reloads: if enrolment.is_some() {
                vec![
                    "clients.json (and the grants it names) — re-read on EVERY connection, \
                     so which authority each certificate gets is decided then, not now; an \
                     edit revokes on the next call. The set of certificates that may \
                     connect at all is frozen at startup."
                        .to_string(),
                ]
            } else {
                Vec::new()
            },
        });
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
        //
        // Every line it logs names the ADDRESSES in the record — or says nothing is
        // announced because only loopback is up (an agent started at login, before DHCP) —
        // and it re-announces by itself when the addresses change. A bare "announcing as
        // plasma" once stayed true for an hour while the record held only 127.0.0.1.
        let _announcement = if announce {
            let name = ikigai_embedded::instance_name();
            let wire_version = ikigai_wire::PROTOCOL_VERSION.to_string();
            match ikigai_discovery::announce_with(
                name,
                addr.port(),
                &[
                    (ikigai_discovery::TXT_SURFACE, surface.as_str()),
                    (ikigai_discovery::TXT_CEILING, posture.as_str()),
                    (ikigai_discovery::TXT_VERSION, wire_version.as_str()),
                ],
                |event| eprintln!("ikigai: {event}"),
            ) {
                Ok(handle) => Some(handle),
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
        // The transport wants the PEMs; the banner wanted the identities. Same list.
        let pems: Vec<String> = trusted.into_iter().map(|client| client.pem).collect();
        ikigai_quic::serve_with(kernel, addr, &identity, &pems, minter, quic_idle_timeout())
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
        .map_err(|e| format!("connect {target}: {e}"))?
        .with_describe_timeout(describe_timeout(ikigai_quic::DEFAULT_DESCRIBE_TIMEOUT));
    Ok(with_profiles(Engine::new(resolver)))
}

#[cfg(all(feature = "embedded", not(feature = "quic")))]
fn serve_quic(
    _target: &str,
    _certs: &Certs,
    _caps: &[String],
    _announce: bool,
    _mounts: Mounts,
) -> ! {
    eprintln!("ikigai: `quic://` needs the `quic` feature");
    std::process::exit(1);
}

#[cfg(all(feature = "embedded", not(feature = "quic")))]
fn connect_quic(_target: &str, _certs: &Certs) -> Result<Engine, String> {
    Err("`quic://` needs the `quic` feature".to_string())
}

// --- IPC serve / connect ----------------------------------------------------

#[cfg(all(feature = "embedded", feature = "ipc", unix))]
fn serve_ipc(path: Option<String>, mounts: Mounts) -> ! {
    let socket = ipc_socket(path);
    // PRE-FLIGHT the sockaddr_un limit: the bind happens LAST — after the mounts
    // dial and after the kernel opens the browse store, taking its exclusive
    // lock — so without this check a too-long path surfaced the OS's
    // "path must be shorter than SUN_LEN" only after all of that work.
    if let Some(e) = socket_path_error(&socket) {
        eprintln!("ikigai: {e}");
        std::process::exit(2);
    }
    // Flags are POSTURE and win wholesale when given; otherwise the machine's own topology
    // from the config home. Wholesale rather than merged, because a half-and-half mount set
    // is the kind of thing nobody can debug at 2am.
    let declined = mounts.declined;
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
    // SELF-MOUNT GUARD: the config home is shared by every process on the machine, so
    // under the "the daemon serves, others mount" topology the very lines that point
    // OTHER processes at this socket (`mount = "prefer urn:repo:=<this socket>"`) are
    // also read by the serving process itself. A mount whose target is our own serve
    // socket would resolve through ourselves — at best a pointless hop, at worst a
    // recursive loop on every miss under the prefix — so it is skipped, with one
    // warning each, rather than dialed.
    let mounts: Vec<Mount> = mounts
        .into_iter()
        .filter(|mount| {
            let own = is_own_socket(&mount.target, &socket);
            if own {
                eprintln!(
                    "ikigai: mount `{}={}` targets this process's own serve socket — \
                     skipped (this instance IS the server; that line is for the other \
                     processes on this machine)",
                    mount.prefix, mount.target
                );
            }
            !own
        })
        .collect();
    // Connect the mounts BEFORE announcing readiness: a host that says it is serving and
    // then cannot reach the peer it was told to compose is worse than one that refuses to
    // start. (A `--prefer` mount is exempt — its peer being absent is normal, and it dials
    // on demand.)
    announce_mounts("ikigai", &mounts, declined);
    // ★ The posture of the door a local client (Emacs, the REPL, MCP) actually talks to.
    // THE HOST OWNS THE TOPOLOGY, so this socket's mounts are the ones a connected client
    // resolves through without knowing where the peers are — and until now the only way to
    // learn which they were was to have watched this process start.
    ikigai_embedded::posture::set_posture(ikigai_embedded::posture::Posture {
        door: socket.display().to_string(),
        mounts: mount_posture(&mounts, declined),
        // A Unix socket authenticates nobody by certificate: the socket's file permissions
        // are the boundary, which is exactly why the kernel behind it is the TRUSTED one.
        clients: Vec::new(),
        surface: None,
        authority: Some(
            "root — every request on this socket resolves as the owner; the socket's file \
             permissions are the boundary"
                .to_string(),
        ),
        reloads: Vec::new(),
    });
    let mut resolved = Vec::new();
    for mount in mounts {
        match resolve_mount(mount) {
            Ok(spec) => resolved.push(spec),
            Err(e) => {
                eprintln!("ikigai: {e}");
                std::process::exit(2);
            }
        }
    }
    eprintln!("ikigai: serving on {}  (Ctrl-C to stop)", socket.display());
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
        .map_err(|e| format!("connect {}: {e}", socket.display()))?
        .with_describe_timeout(describe_timeout(ikigai_ipc::DEFAULT_DESCRIBE_TIMEOUT));
    Ok(with_profiles(Engine::new(resolver)))
}

/// True when a mount target dials this process's own QUIC bind address — the
/// QUIC face of [`is_own_socket`].
///
/// Own means: a `quic://` target resolving to the bind address itself, or — when
/// the bind is a wildcard (`0.0.0.0`/`::`), which holds every address this
/// machine does — to a loopback or to an address this machine can BIND (the only
/// local-address oracle std offers). A `peer:` target is own only when this
/// server is itself announcing under that name. An unresolvable target is NOT
/// own — err on the side of mounting; the dial will say what is wrong.
#[cfg(all(feature = "embedded", feature = "quic"))]
fn is_own_quic_addr(target: &str, bind: std::net::SocketAddr, announced: Option<&str>) -> bool {
    if let Some(name) = target.strip_prefix("peer:") {
        return announced == Some(name);
    }
    if !is_quic(target) {
        return false; // a Unix-socket peer is never this QUIC server
    }
    let Ok(addr) = quic::parse_addr(target) else {
        return false;
    };
    if addr.port() != bind.port() {
        return false;
    }
    addr.ip() == bind.ip()
        || (bind.ip().is_unspecified()
            && (addr.ip().is_loopback() || std::net::UdpSocket::bind((addr.ip(), 0)).is_ok()))
}

/// True when an IPC mount target names this process's own serve socket.
///
/// A QUIC or mDNS target is never "own" here — this guard runs in the IPC
/// server, whose identity is exactly one Unix socket path. Comparison is on
/// `~`-expanded, lexically-absolute paths (the socket usually does not exist
/// yet — it is bound after the mounts compose — so canonicalizing would fail);
/// a symlinked spelling of the same socket is not caught, which errs on the
/// side of mounting.
#[cfg(all(feature = "embedded", feature = "ipc", unix))]
fn is_own_socket(target: &str, socket: &std::path::Path) -> bool {
    if is_quic(target) || target.starts_with("peer:") {
        return false;
    }
    let absolute = |p: std::path::PathBuf| std::path::absolute(&p).unwrap_or(p);
    absolute(std::path::PathBuf::from(shellexpand_home(target))) == absolute(socket.to_path_buf())
}

/// What `sockaddr_un`'s `sun_path` holds on this platform: 104 bytes on
/// macOS/the BSDs, 108 on Linux. The bind errors when the path's byte length
/// reaches it (one byte is the terminating NUL).
#[cfg(all(feature = "embedded", feature = "ipc", unix))]
const SUN_PATH_CAPACITY: usize = if cfg!(target_os = "linux") { 108 } else { 104 };

/// Why `socket` cannot be bound as a Unix socket, if it cannot be — the
/// pre-flight for a limit the OS would otherwise report only at bind time.
#[cfg(all(feature = "embedded", feature = "ipc", unix))]
fn socket_path_error(socket: &std::path::Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    let len = socket.as_os_str().as_bytes().len();
    (len >= SUN_PATH_CAPACITY).then(|| {
        format!(
            "socket path is {len} bytes, but a Unix socket path fits {} on this \
             platform — serve at a shorter path: {}",
            SUN_PATH_CAPACITY - 1,
            socket.display()
        )
    })
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
fn serve_ipc(_path: Option<String>, _mounts: Mounts) -> ! {
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
fn serve_http(door: HttpDoor<'_>) -> ! {
    let HttpDoor {
        bind,
        caps,
        trust_proxy,
        cors_origins,
        routes,
        routes_only,
        max_body,
        mounts,
    } = door;
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
    // Flags are POSTURE and win wholesale when given; otherwise the machine's own topology
    // from the config home — the same rule as serve_ipc and serve_quic. Until 2026-09-16
    // this door had none of it: `Mode::Serve` destructured `mounts`, handed them to the
    // other two doors, and dropped them here. No warning, no refusal, exit 0.
    let declined = mounts.declined;
    let mounts = match mounts_or_config(mounts) {
        Ok(mounts) => mounts,
        // A topology that does not parse must never look like no topology.
        Err(e) => {
            eprintln!("ikigai: {e}");
            std::process::exit(2);
        }
    };
    // ⚠ NO SELF-MOUNT GUARD HERE, and that is a decision rather than an omission. The
    // guard the other two doors run asks "does this mount target the address I am about to
    // serve on?" — answerable there because an IPC server IS a socket path and a QUIC
    // server IS a UDP address, which is exactly what a mount line names. This door serves
    // TCP HTTP, which is not a mountable target at all (`resolve_mount` takes `quic://`,
    // `peer:`, or a Unix socket path), so no config line can point at us. Copying the QUIC
    // guard would be worse than nothing: it compares host:port, so `serve --http 4433`
    // beside another process's QUIC server on UDP/4433 would silently SKIP a legitimate
    // mount.
    //
    // Connect the mounts BEFORE announcing readiness, exactly as the other two doors do: a
    // host that says it is serving and then cannot reach the peer it was told to compose is
    // worse than one that refuses to start. (`--prefer` is exempt — its peer being absent is
    // normal, and it dials on demand.)
    announce_mounts("ikigai", &mounts, declined);
    // Held for the posture record below: the route table (this door's surface) is not
    // loaded until further down, and the resolve loop consumes `mounts`.
    let composed = mount_posture(&mounts, declined);
    let mut resolved = Vec::new();
    for mount in mounts {
        match resolve_mount(mount) {
            Ok(spec) => resolved.push(spec),
            Err(e) => {
                eprintln!("ikigai: {e}");
                std::process::exit(2);
            }
        }
    }
    // `kernel_for_with_mounts`, NOT `served_kernel_with_mounts`: this door's kernel also
    // carries `urn:iki:foaf` and the transreption chain it issues through (the `/foaf`
    // face on the public edge), which the QUIC composer does not. And it stays the PUBLIC
    // kernel — a mount widens reach, never authority.
    let kernel = std::sync::Arc::new(ikigai_embedded::kernel_for_with_mounts(
        "Remote (HTTP)",
        resolved,
    ));
    // `--cap` clamps every request to a fixed ceiling — how the public HTTP face is
    // narrowed for the edge (a request can reach only what the ceiling grants). Without
    // it, the public (empty-scope) capability: only cap-free resources resolve.
    let (cap_fn, posture) = if caps.is_empty() {
        (ikigai_web::public_cap(), "public cap".to_string())
    } else {
        (
            ikigai_web::fixed_cap(caps.to_vec()),
            // `fixed ceiling:`, the same words serve_quic uses for the same posture — two
            // doors describing one concept in two spellings is the defect this arc is about.
            format!("fixed ceiling: {}", caps.join(", ")),
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
    // `--max-body` narrows the door; unset keeps the transport's own default.
    if let Some(max) = max_body {
        config.max_body_bytes = max;
    }
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
    // Set when a poller is watching the route file, so the posture record can NAME the
    // re-read instead of letting the "as of startup" line cover a table that hot-reloads.
    let mut routes_watched = false;
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
                routes_watched = true;
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
    // ★ The public door records its posture like any other — and `urn:host:posture` is
    // REACHABLE here (`GET /host/posture`) and REFUSED, because the public capability does
    // not hold `urn:cap:host:posture`. That is the intended shape: the resource is gated by
    // authority rather than withheld by composition, so an operator can put it on a
    // monitoring door by granting the one scope, and a stranger gets a 403 either way.
    // The paths are the sensitive part — a mount target names another machine and a cert
    // path describes this disk; a fingerprint is a hash of a public certificate and
    // discloses nothing.
    ikigai_embedded::posture::set_posture(ikigai_embedded::posture::Posture {
        door: format!("http://{addr}"),
        mounts: composed,
        // TLS terminates at the proxy and the door authenticates no client certificate;
        // per-request identity is the route table's `ik:bind` seam, not a cert.
        clients: Vec::new(),
        surface: Some(route_note.clone()),
        authority: Some(posture.clone()),
        reloads: if routes_watched {
            vec![
                "the route table — the watched route resource is re-queried when the file \
                 changes and swapped live, so the route count above is the startup reading"
                    .to_string(),
            ]
        } else {
            Vec::new()
        },
    });
    match runtime.block_on(ikigai_web::serve_with(kernel, cap_fn, addr, config)) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("ikigai: HTTP serve error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(all(feature = "embedded", feature = "web")))]
fn serve_http(_door: HttpDoor<'_>) -> ! {
    eprintln!("ikigai: the inbound HTTP face needs the `web` feature (build with --features web)");
    std::process::exit(1);
}

#[cfg(all(feature = "embedded", not(all(feature = "ipc", unix))))]
fn connect_ipc(_path: Option<String>) -> Result<Engine, String> {
    Err("attaching to a Unix socket needs the `ipc` feature on a Unix platform".to_string())
}

#[cfg(not(feature = "embedded"))]
fn main() {
    // A build with no transport still has to say what it is — that is exactly the
    // host someone is interrogating. Same parser, same line, exit 0; everything
    // else on this build is still the message below.
    if matches!(parse_args(), Ok(Some(Mode::Version))) {
        println!("{VERSION_LINE}");
        return;
    }
    eprintln!(
        "ikigai {}: built without a transport. Rebuild with a transport feature, e.g. `--features embedded`.",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(1);
}

#[cfg(test)]
mod mount_posture_tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn mount(kind: ikigai_embedded::MountKind) -> Mount {
        Mount {
            prefix: "urn:x:".to_string(),
            target: "/tmp/x.sock".to_string(),
            certs: Certs::default(),
            kind,
        }
    }

    /// The posture a mode ends up in, for each shape of command line. `None` = the parse
    /// refused; otherwise `(flag count, declined)`.
    fn posture(args: &[&str]) -> Result<(usize, bool), String> {
        let mounts = match parse_argv(argv(args).into_iter())? {
            Some(Mode::Repl(repl)) => repl.mounts,
            Some(Mode::Daemon { mounts }) => mounts,
            Some(Mode::Serve { mounts, .. }) => mounts,
            Some(Mode::Mcp { mounts, .. }) => mounts,
            _ => panic!("expected a kernel-building mode"),
        };
        Ok((mounts.flags.len(), mounts.declined))
    }

    /// The whole point of the flag: ZERO mounts, and the config home is not READ. Asserted
    /// against a thunk that panics rather than against an empty result — an empty result is
    /// also what an absent config home gives, so it would pass on a kernel that still paid
    /// for reading and parsing the machine's topology.
    #[test]
    fn declining_composes_zero_and_never_reads_the_config_home() {
        let declined = Mounts {
            flags: Vec::new(),
            declined: true,
        };
        let resolved = resolve_mounts(declined, || {
            panic!("--no-config-mounts must not read the config home")
        })
        .expect("declining is not an error");
        assert!(resolved.is_empty(), "declining composes nothing");
    }

    /// Unchanged behaviour, stated as a test because the flag is only safe if the DEFAULT
    /// still inherits the machine: no flags ⇒ the config home's `mount` lines.
    #[test]
    fn no_flags_still_compose_the_machines_topology() {
        let resolved = resolve_mounts(Mounts::default(), || {
            Ok(vec![mount(ikigai_embedded::MountKind::Prefer)])
        })
        .expect("a parsing config home is not an error");
        assert_eq!(resolved.len(), 1, "the config home is the default posture");
    }

    /// The other unchanged rule: flags win WHOLESALE, and the config home is not consulted
    /// to top them up.
    #[test]
    fn mount_flags_win_wholesale_over_the_config_home() {
        let flagged = Mounts {
            flags: vec![mount(ikigai_embedded::MountKind::Prefer)],
            declined: false,
        };
        let resolved = resolve_mounts(flagged, || panic!("flags win wholesale"))
            .expect("flags are not an error");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].prefix, "urn:x:");
    }

    /// Both postures at once is a STARTUP ERROR naming both flags — in EITHER order on the
    /// command line, for all three mount flags, in every mode that builds a kernel. A silent
    /// winner would be the half-and-half mount set nobody can debug at 2am.
    #[test]
    fn declining_beside_a_mount_flag_refuses_to_start() {
        let mount_flags = [
            ("--mount", "urn:a:=/tmp/a.sock"),
            ("--override", "urn:b:=/tmp/b.sock"),
            ("--prefer", "urn:c:=/tmp/c.sock"),
        ];
        let modes: [&[&str]; 4] = [&[], &["--daemon"], &["serve", "/tmp/s.sock"], &["mcp"]];
        for prefix in modes {
            for (flag, spec) in mount_flags {
                for order in [
                    vec!["--no-config-mounts", flag, spec],
                    vec![flag, spec, "--no-config-mounts"],
                ] {
                    let args: Vec<&str> = prefix.iter().copied().chain(order).collect();
                    let e = posture(&args).expect_err(&format!("{args:?} must refuse to start"));
                    assert!(
                        e.contains("--no-config-mounts") && e.contains(flag),
                        "the refusal must name BOTH flags, got: {e}"
                    );
                }
            }
        }
    }

    /// The flag has to be honoured by every door, because the `mount` key is shared by all
    /// of them: one that ignored it would be the next version of #410.
    #[test]
    fn every_kernel_building_mode_honours_the_flag() {
        for args in [
            vec!["--no-config-mounts"],
            vec!["--daemon", "--no-config-mounts"],
            vec!["serve", "/tmp/s.sock", "--no-config-mounts"],
            vec![
                "serve",
                "quic://0.0.0.0:4433",
                "--no-config-mounts",
                "--announce",
            ],
            vec!["serve", "--http", "8642", "--no-config-mounts"],
            vec!["mcp", "--no-config-mounts"],
        ] {
            assert_eq!(
                posture(&args).unwrap_or_else(|e| panic!("{args:?}: {e}")),
                (0, true),
                "{args:?} must reach its kernel builder as the DECLINE posture"
            );
        }
    }

    /// `--connect` composes nothing of its own, so the flag would be INERT there. An inert
    /// flag is how an operator comes to believe a topology was declined when it was not.
    #[test]
    fn declining_beside_connect_refuses_rather_than_doing_nothing() {
        let declined = Mounts {
            flags: Vec::new(),
            declined: true,
        };
        let e = match build_engine(
            Some(Some("/tmp/ikigai-no-such-socket".to_string())),
            declined,
            &Certs::default(),
            false,
        ) {
            Err(e) => e,
            // `Engine` is not `Debug`, so this cannot be an `expect_err`.
            Ok(_) => panic!("a flag with nothing to do must say so"),
        };
        assert!(
            e.contains("--no-config-mounts") && e.contains("--connect"),
            "the refusal must name both, got: {e}"
        );
    }

    /// A mount for the banner tests: the shape a `config.toml` line produces.
    fn a_mount(prefix: &str, target: &str) -> Mount {
        Mount {
            prefix: prefix.to_string(),
            target: target.to_string(),
            certs: Certs::default(),
            kind: ikigai_embedded::MountKind::Prefer,
        }
    }

    /// The banner is the deliverable as much as the flag is: an inherited topology was
    /// invisible because a decline and an empty config home printed the same nothing.
    #[test]
    fn the_banner_distinguishes_declined_from_simply_none() {
        let none = mount_lines(&[], false);
        assert_eq!(none.len(), 1);
        assert!(
            none[0].contains("none composed"),
            "an empty topology says so in words: {none:?}"
        );
        let declined = mount_lines(&[a_mount("urn:x:", "/tmp/x.sock")], true);
        assert_eq!(declined.len(), 1);
        assert!(
            declined[0].contains(ikigai_embedded::posture::MOUNTS_DECLINED),
            "the decline names itself: {declined:?}"
        );
        assert!(
            !declined[0].contains("urn:x:"),
            "a declined door composed NOTHING and must name no mount: {declined:?}"
        );
        assert_ne!(none[0], declined[0], "the two postures never read alike");
    }

    /// ★ The item itself (#418): the banner prints the mounts, not how many there are. Six
    /// was never the wrong number — it was never an answer to `which six`, and two of the
    /// six pointed back at the caller.
    #[test]
    fn the_banner_names_every_mount_rather_than_counting_them() {
        let lines = mount_lines(
            &[
                a_mount("urn:iki:store:", "/Users/x/.ikigai/gonk.sock"),
                a_mount("urn:llm:", "quic://plasma.local:4433"),
            ],
            false,
        );
        assert_eq!(
            lines.len(),
            2,
            "one line per mount, never a tally: {lines:?}"
        );
        assert_eq!(
            lines[0],
            "mount   prefer urn:iki:store: -> /Users/x/.ikigai/gonk.sock"
        );
        assert_eq!(
            lines[1],
            "mount   prefer urn:llm: -> quic://plasma.local:4433"
        );
        assert!(
            !lines.iter().any(|line| line.contains("2 mount")),
            "no count survives anywhere in the block: {lines:?}"
        );
    }

    /// A mount that authenticates as somebody else is a different mount, so the line says
    /// which certificates it carries. Two `prefer urn:llm:` lines to the same peer with
    /// different cert dirs are otherwise indistinguishable on the banner.
    #[test]
    fn a_mounts_own_certificates_are_named_on_its_line() {
        let mut mount = a_mount("urn:cal:", "quic://bug.local:4433");
        mount.certs.cert_dir = Some("/Users/x/.config/ikigai/quic-bug".to_string());
        assert_eq!(
            mount_lines(&[mount], false),
            vec!["mount   prefer urn:cal: -> quic://bug.local:4433  [certs /Users/x/.config/ikigai/quic-bug]"]
        );
    }

    /// ★ The other half of the item (#426): the banner names the certificates it trusts.
    /// Two servers printed `1 trusted client cert(s)` on one afternoon and meant opposite
    /// things — one with a peer enrolled in `clients/`, one with no `clients/` directory at
    /// all, counting the base cert that is ALWAYS trusted. The count could not express the
    /// fact the decision turned on.
    ///
    /// This also pins the SHAPE of what leaves the process: a 16-character prefix of the
    /// lowercase-hex SHA-256 that `cert add-client` prints in full and that a
    /// `clients.json` key must be. A prose comment could drift from that; this cannot.
    #[cfg(feature = "quic")]
    #[test]
    fn the_banner_names_each_trusted_certificate_and_labels_the_base() {
        let base = ikigai_quic::generate();
        let peer = ikigai_quic::generate();
        let full =
            ikigai_quic::fingerprint_of_pem(&peer.cert_pem).expect("a generated cert parses");
        let lines = ikigai_embedded::posture::client_lines(&trusted_identities(&[
            quic::TrustedClient {
                label: "base".to_string(),
                path: "/Users/x/.config/ikigai/quic/client.crt".into(),
                pem: base.cert_pem.clone(),
            },
            quic::TrustedClient {
                label: "plasma".to_string(),
                path: "/Users/x/.config/ikigai/quic/clients/plasma.crt".into(),
                pem: peer.cert_pem.clone(),
            },
        ]));
        assert_eq!(lines.len(), 2, "one line per certificate: {lines:?}");
        assert!(
            lines[0].starts_with("client  base  "),
            "the base cert is labelled as the base, not listed as a peer: {lines:?}"
        );
        assert_eq!(
            lines[1],
            format!(
                "client  plasma  {}  /Users/x/.config/ikigai/quic/clients/plasma.crt",
                &full[..16]
            )
        );
        assert_eq!(full.len(), 64, "the full id stays the SHA-256 hex");
        assert!(
            full.starts_with(short_fingerprint(&full)),
            "what the banner shows is a PREFIX of what `cert add-client` prints"
        );
        assert!(
            !lines.iter().any(|line| line.contains("cert(s)")),
            "no count survives anywhere in the block: {lines:?}"
        );
    }

    /// A certificate this server has loaded and cannot describe is a fact the operator
    /// needs. Dropping the row would put the banner back where it started — a list that
    /// silently disagrees with what is trusted.
    #[cfg(feature = "quic")]
    #[test]
    fn an_unparseable_certificate_still_gets_a_line() {
        let lines =
            ikigai_embedded::posture::client_lines(&trusted_identities(&[quic::TrustedClient {
                label: "junk".to_string(),
                path: "/tmp/junk.crt".into(),
                pem: "not a certificate".to_string(),
            }]));
        assert_eq!(lines, vec!["client  junk  unreadable  /tmp/junk.crt"]);
    }

    /// Each mode word is the one a `config.toml` `mount` line spells, so the banner is
    /// greppable in the file that produced it.
    #[test]
    fn the_mode_word_matches_the_config_lines_grammar() {
        for (kind, word) in [
            (ikigai_embedded::MountKind::Alias, "alias"),
            (ikigai_embedded::MountKind::Override, "override"),
            (ikigai_embedded::MountKind::Prefer, "prefer"),
        ] {
            assert_eq!(mount_mode(kind), word);
            // …and the grammar really parses it back.
            let parsed = mounts_from_config_lines(vec![format!("{word} urn:x:=/tmp/x.sock")])
                .expect("the mode word round-trips through the config grammar");
            assert_eq!(parsed[0].kind, kind);
        }
    }

    /// The config-home grammar, over lines rather than a file — proof that the default
    /// posture still parses what a machine's `config.toml` actually carries (the line here
    /// is the one on plasma that started #410).
    #[test]
    fn a_config_home_mount_line_still_parses() {
        let mounts = mounts_from_config_lines(vec![
            "prefer urn:iki:store:=/Users/x/.ikigai/gonk.sock".to_string(),
            "alias urn:cal:=quic://bug.local:4433 ~/.config/ikigai/quic-bug".to_string(),
        ])
        .expect("both lines parse");
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].kind, ikigai_embedded::MountKind::Prefer);
        assert_eq!(mounts[0].prefix, "urn:iki:store:");
        assert_eq!(mounts[1].kind, ikigai_embedded::MountKind::Alias);
        assert!(
            mounts[1]
                .certs
                .cert_dir
                .as_deref()
                .is_some_and(|dir| !dir.starts_with('~')),
            "a config line's `~` is expanded"
        );
    }
}

#[cfg(test)]
mod mount_cert_tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn mounts_of(args: &[&str]) -> Vec<Mount> {
        match parse_argv(argv(args).into_iter()) {
            Ok(Some(Mode::Repl(repl))) => repl.mounts.flags,
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

    /// The other half of prefer-mount catalog citizenship: `entries()` dials a
    /// peer that has never been used, so `list` shows a prefer-mounted
    /// namespace WITHOUT a prior resolution through it. (Before this, the
    /// REPL's list was blind to an undialed prefer mount — the same
    /// chicken-and-egg cli #270 fixed for mcp, which the ikigai-deno
    /// satellite then hit interactively.)
    #[test]
    fn a_prefer_mounts_entries_dial_a_live_peer() {
        use ikigai_core::{builtins, EndpointSpace, Exact, Kernel};
        let path =
            std::env::temp_dir().join(format!("ikigai-prefer-list-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let kernel = Kernel::new(std::sync::Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:upper"), builtins::to_upper()),
        ));
        let served = path.clone();
        std::thread::spawn(move || {
            let _ = ikigai_ipc::serve(kernel, &served);
        });
        // Give the listener a beat to bind.
        for _ in 0..50 {
            if path.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mount = Mount {
            prefix: "urn:test:".to_string(),
            target: path.display().to_string(),
            certs: Certs::default(),
            kind: ikigai_embedded::MountKind::Prefer,
        };
        let spec = resolve_mount(mount).expect("prefer resolves lazily");
        let entries = spec
            .resolver
            .entries()
            .expect("entries() dials the live peer");
        assert!(
            entries.iter().any(|e| e.endpoint == "toUpper"),
            "the peer's catalog is visible without any prior resolution: {entries:?}"
        );
        let _ = std::fs::remove_file(&path);
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
        let mounts = mounts.flags;
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
    // Native-only test in the host binary's own suite: it measures wall-clock elapsed
    // to assert a dead peer's `entries()` returns instead of stalling. Nothing here
    // is ever compiled for wasm.
    #[allow(clippy::disallowed_methods)]
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
            spec.resolver.transport().contains("not connected"),
            "transport should say the peer is not connected, got: {}",
            spec.resolver.transport()
        );
        // `entries()` DOES attempt a bounded dial now (an explicit enumeration
        // deserves the truth) — against a dead peer it yields no catalog, and
        // the failure is negative-cached so the next list doesn't stall again.
        let start = std::time::Instant::now();
        assert!(
            spec.resolver.entries().is_none(),
            "a dead peer yields no catalog"
        );
        assert!(
            spec.resolver.entries().is_none() && start.elapsed() < ENTRIES_REDIAL_AFTER,
            "the second probe rides the negative cache"
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

#[cfg(all(test, feature = "embedded", feature = "ipc", unix))]
mod own_socket_tests {
    use super::is_own_socket;
    use std::path::Path;

    /// The config home is shared machine-wide, so the serving process reads the very
    /// mount lines that point everyone ELSE at its socket — those must read as "own"
    /// however the path is spelled, while genuinely-remote targets must not.
    #[test]
    fn own_socket_is_detected_across_spellings() {
        let socket = Path::new("/tmp/ikigai-test/serve.sock");
        assert!(is_own_socket("/tmp/ikigai-test/serve.sock", socket));
        // A lexically-different spelling of the same path.
        assert!(is_own_socket("/tmp/ikigai-test/./serve.sock", socket));
        assert!(!is_own_socket("/tmp/ikigai-test/other.sock", socket));
        // Remote targets are never "own" — the IPC server's identity is a Unix path.
        assert!(!is_own_socket("quic://plasma.local:4433", socket));
        assert!(!is_own_socket("peer:plasma", socket));
    }

    /// `~` in a config line expands against $HOME before comparing.
    #[test]
    fn tilde_spelling_matches_the_expanded_socket() {
        let home = std::env::var("HOME").expect("HOME set in test env");
        let socket = std::path::PathBuf::from(home).join(".ikigai-test.sock");
        assert!(is_own_socket("~/.ikigai-test.sock", &socket));
    }
}

#[cfg(all(test, feature = "embedded", feature = "quic"))]
mod own_quic_addr_tests {
    use super::is_own_quic_addr;

    /// The QUIC face of the self-mount guard: the config home is machine-shared,
    /// so a QUIC-serving process reads the very lines that point everyone else
    /// at its own address — those must read as "own", while a different port, a
    /// Unix-socket peer, or another machine must not.
    #[test]
    fn own_quic_address_is_detected() {
        let wildcard: std::net::SocketAddr = "0.0.0.0:4433".parse().unwrap();
        // A wildcard bind holds every address this machine does, loopback included.
        assert!(is_own_quic_addr("quic://127.0.0.1:4433", wildcard, None));
        // Another port is another server, even on this machine.
        assert!(!is_own_quic_addr("quic://127.0.0.1:4434", wildcard, None));
        // A Unix-socket peer is never this QUIC server.
        assert!(!is_own_quic_addr("/tmp/ikigai.sock", wildcard, None));
        // A specific bind matches exactly itself.
        let specific: std::net::SocketAddr = "127.0.0.1:4433".parse().unwrap();
        assert!(is_own_quic_addr("quic://127.0.0.1:4433", specific, None));
    }

    /// A `peer:` target is own only when this server is itself announcing under
    /// that name — a non-announcing server is not discoverable, so the name
    /// cannot be it (err on the side of mounting).
    #[test]
    fn a_peer_target_is_own_only_under_our_announced_name() {
        let bind: std::net::SocketAddr = "0.0.0.0:4433".parse().unwrap();
        assert!(!is_own_quic_addr("peer:plasma", bind, None));
        assert!(is_own_quic_addr("peer:plasma", bind, Some("plasma")));
        assert!(!is_own_quic_addr("peer:bug", bind, Some("plasma")));
    }
}

#[cfg(all(test, feature = "embedded", feature = "ipc", unix))]
mod socket_preflight_tests {
    use super::{socket_path_error, SUN_PATH_CAPACITY};

    /// The bind used to be the LAST thing `serve_ipc` did — after the mounts
    /// dialed and the browse store took its exclusive lock — so a too-long path
    /// failed with the OS's "path must be shorter than SUN_LEN" only after all
    /// that work. The pre-flight mirrors the bind's exact boundary: a path of
    /// `sun_path`-capacity bytes fails (one byte is the NUL), one byte under fits.
    #[test]
    fn the_preflight_mirrors_the_binds_length_boundary() {
        let of_len = |n: usize| std::path::PathBuf::from(format!("/{}", "x".repeat(n - 1)));
        assert!(socket_path_error(&of_len(SUN_PATH_CAPACITY - 1)).is_none());
        let e = socket_path_error(&of_len(SUN_PATH_CAPACITY)).expect("over the sun_path capacity");
        assert!(e.contains("shorter path"), "{e}");
        assert!(socket_path_error(std::path::Path::new("/tmp/ikigai.sock")).is_none());
    }
}

#[cfg(all(test, feature = "embedded", feature = "ipc", unix))]
mod mount_flag_tests {
    use super::*;

    /// A down prefer-mount peer used to surface at first use as `--mount:
    /// connect …` — a flag the operator never typed. The connect error now names
    /// the mount's own spelling, through the lazy resolver and eagerly alike.
    #[test]
    fn a_down_prefer_peer_says_prefer_not_mount() {
        let absent = "/tmp/ikigai-test-absent-peer.sock";
        let spec = resolve_mount(Mount {
            prefix: "urn:repo:".to_string(),
            target: absent.to_string(),
            certs: Certs::default(),
            kind: ikigai_embedded::MountKind::Prefer,
        })
        .expect("a prefer mount resolves lazily");
        // First use dials — and the failure names --prefer.
        let err = spec
            .resolver
            .issue(ikigai_core::Request::new(
                ikigai_core::Verb::Source,
                ikigai_core::Iri::parse("urn:repo:x").expect("static IRI"),
            ))
            .expect_err("nothing listens at the absent socket")
            .to_string();
        assert!(err.contains("--prefer: connect"), "{err}");
        assert!(!err.contains("--mount:"), "{err}");
        // The eager kinds keep their own spellings.
        let Err(err) = connect_mount(absent, &Certs::default(), ikigai_embedded::MountKind::Alias)
        else {
            panic!("nothing listens at the absent socket");
        };
        assert!(err.contains("--mount: connect"), "{err}");
    }
}

/// `--scheduler`, the flag half of the fan-out width. The precedence ladder itself
/// (flag > config > env > `single`) is pinned in `ikigai_embedded::scheduling`, which can
/// test it as a pure function; what belongs here is that argv reaches that ladder from
/// every mode, and that a bad spec stops the process instead of silently narrowing it.
#[cfg(test)]
mod scheduler_flag_tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Option<Mode>, String> {
        parse_argv(args.iter().map(|s| s.to_string()))
    }

    /// The failure this exists to prevent: a typo'd width that becomes `single` and is
    /// invisible from outside the process — a serialized fan-out looks exactly like a
    /// slow server. Every mode fans out on the process scheduler, so every mode rejects.
    #[cfg(feature = "embedded")]
    #[test]
    fn an_invalid_scheduler_spec_stops_the_process_in_every_mode() {
        for args in [
            vec!["--scheduler", "pool:xyz"],
            vec!["--daemon", "--scheduler", "pool:xyz"],
            vec!["serve", "--scheduler", "pool:xyz"],
            vec!["mcp", "--scheduler", "pool:xyz"],
        ] {
            let Err(e) = parse(&args) else {
                panic!("a typo'd spec must not fall back to single: {args:?}")
            };
            assert!(
                e.contains("--scheduler") && e.contains("pool:xyz"),
                "the error must name the flag and the bad value, got: {e}"
            );
        }
        assert!(parse(&["--scheduler", "nonsense"]).is_err());
    }

    /// A flag that eats the next argument must say so when there is none, rather than
    /// treating the following flag as its value.
    #[test]
    fn the_scheduler_flag_requires_a_spec() {
        let Err(e) = parse(&["--scheduler"]) else {
            panic!("a flag with no value is an error")
        };
        assert!(e.contains("--scheduler"), "{e}");
    }

    /// Accepted in every mode: a served kernel, the daemon, `mcp` and the REPL all drive
    /// the same process scheduler. (This arms the process-global setting for the rest of
    /// this test binary — nothing else here builds a kernel.)
    #[test]
    fn a_valid_scheduler_spec_parses_in_every_mode() {
        assert!(matches!(
            parse(&["--scheduler", "pool:2"]),
            Ok(Some(Mode::Repl(_)))
        ));
        assert!(matches!(
            parse(&["--daemon", "--scheduler", "pool"]),
            Ok(Some(Mode::Daemon { .. }))
        ));
        assert!(matches!(
            parse(&["serve", "--scheduler", "single"]),
            Ok(Some(Mode::Serve { .. }))
        ));
        assert!(matches!(
            parse(&["mcp", "--scheduler", "single"]),
            Ok(Some(Mode::Mcp { .. }))
        ));
    }

    /// `--width-routing` rides the same three argv sites as `--scheduler`, so every mode
    /// that fans out can also say whether it routes on the width it reaches.
    #[test]
    fn the_width_routing_flag_parses_in_every_mode() {
        assert!(matches!(
            parse(&["--width-routing", "off"]),
            Ok(Some(Mode::Repl(_)))
        ));
        assert!(matches!(
            parse(&["--daemon", "--width-routing", "off"]),
            Ok(Some(Mode::Daemon { .. }))
        ));
        assert!(matches!(
            parse(&["serve", "--width-routing", "off"]),
            Ok(Some(Mode::Serve { .. }))
        ));
        assert!(matches!(
            parse(&["mcp", "--width-routing", "off"]),
            Ok(Some(Mode::Mcp { .. }))
        ));
    }

    /// A typo'd switch stops the process rather than silently meaning "off": the operator
    /// would otherwise believe the host routes by load shape when nothing in the process
    /// contradicts them. And a flag that eats its value must say so when there is none.
    #[cfg(feature = "embedded")]
    #[test]
    fn an_invalid_width_routing_value_stops_the_process() {
        let Err(e) = parse(&["--width-routing", "yes"]) else {
            panic!("`yes` is a typo, not a synonym for on")
        };
        assert!(e.contains("--width-routing") && e.contains("yes"), "{e}");

        let Err(e) = parse(&["--width-routing"]) else {
            panic!("a flag with no value is an error")
        };
        assert!(e.contains("--width-routing"), "{e}");
    }
}

/// `-V` / `--version`. This is the flag anyone debugging a client-library
/// integration reaches for first — three repos in one day worked around its absence
/// by resolving a known name and interpreting the failure — and it is exactly the
/// kind of flag that works the day it is written and breaks silently the next time
/// the argument parser is restructured. Nothing else in this suite would notice.
#[cfg(test)]
mod version_flag_tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Option<Mode>, String> {
        parse_argv(args.iter().map(|s| s.to_string()))
    }

    /// The OUTPUT contract, which is what a script actually depends on: `ikigai
    /// <version>` — one line, two tokens, no decoration — carrying the same number
    /// the REPL banner and the MCP server report.
    #[test]
    fn the_version_line_is_one_undecorated_line() {
        assert_eq!(
            VERSION_LINE,
            format!("ikigai {}", env!("CARGO_PKG_VERSION")),
            "one version string for the whole binary"
        );
        assert!(
            !VERSION_LINE.contains('\n'),
            "a script reads one line: {VERSION_LINE:?}"
        );
        assert_eq!(
            VERSION_LINE.split(' ').count(),
            2,
            "`ikigai <x.y.z>` and nothing else: {VERSION_LINE:?}"
        );
    }

    /// Every argument path answers it. The flag is consumed before any subcommand or
    /// mode parsing, so it cannot depend on which mode the REST of argv would have
    /// selected, and it never falls through to the usage printer (`Ok(None)`) — a
    /// version buried in a screen of help is the failure this replaces.
    #[test]
    fn every_argument_path_answers_the_version_flag() {
        for args in [
            vec!["--version"],
            vec!["-V"],
            vec!["serve", "--version"],
            vec!["serve", "-V"],
            vec!["serve", "quic://127.0.0.1:4433", "--version"],
            vec!["mcp", "--version"],
            vec!["cert", "--version"],
            vec!["cert", "generate", "--version"],
            vec!["--daemon", "--version"],
            vec!["--plain", "--version"],
            vec!["--demo", "--plain", "-V"],
            vec!["-c", "source urn:host:info", "--version"],
            vec!["--version", "-c", "source urn:host:info"],
            vec!["--connect", "--version"],
        ] {
            assert!(
                matches!(parse(&args), Ok(Some(Mode::Version))),
                "the version flag must be answered in every arm, not just one: {args:?}"
            );
        }
    }

    /// …and the scan changes nothing else: argv without the flag still parses to the
    /// mode it always did, including the arms whose own parsers would reject an
    /// unknown flag.
    #[test]
    fn argv_without_the_flag_is_untouched() {
        assert!(matches!(parse(&[]), Ok(Some(Mode::Repl(_)))));
        assert!(matches!(parse(&["--plain"]), Ok(Some(Mode::Repl(_)))));
        assert!(matches!(
            parse(&["--daemon"]),
            Ok(Some(Mode::Daemon { .. }))
        ));
        assert!(matches!(parse(&["serve"]), Ok(Some(Mode::Serve { .. }))));
        assert!(matches!(parse(&["mcp"]), Ok(Some(Mode::Mcp { .. }))));
        assert!(
            matches!(parse(&["-h"]), Ok(None)),
            "help still prints usage"
        );
        assert!(
            parse(&["--versionn"]).is_err(),
            "a near-miss is still an unknown argument, not a version request"
        );
    }
}

/// ★ **The command adapter's capability gate**, pinned where the composition lives.
///
/// A runbook step is TEXT. The runbook crate renders `hx-get="/k/<command>"` buttons and has
/// no Sink, no capability and nothing to gate (ikigai-cli PENDING §5) — the authority
/// decision belongs entirely to whatever turns that text into a request. In this workspace
/// that is [`Engine::eval`] over the embedded kernel under the session capability, driven by
/// the REPL, the TUI, and (in the browser host) the page's `/k/` bridge. `ikigai-web-demo`
/// #57 landed this check for its own `/k/` face; this is the native half.
///
/// ## Why the test is HERE, in the binary, rather than in `tests/`
///
/// The thing under test is not `Engine::eval` — it is the COMPOSITION: the embedded kernel's
/// spaces, plus [`with_profiles`], which decides what `cap read-only` actually grants by
/// reading [`ikigai_embedded::file_root`]. Both are private to this binary, and a `tests/`
/// binary could only re-create them — which is the arrangement that let `ikigai-web`'s HTTP
/// tests build kernels by hand while the one function with the defect went untested. So the
/// steps are the real runbook's, the profiles are the real `with_profiles`, and the kernel is
/// the real `ikigai_embedded::kernel()`.
///
/// ## Two gates, two witnesses, and neither is a status code
///
/// * **The kernel's floor** (declared = enforced). A session holding no grant under the
///   family the action declares is refused BEFORE dispatch, and core reports that as a
///   [`TraceEvent`] tagged [`DENIED_NOTE`] with `started == None` — the one event that names
///   something which never ran.
/// * **The module's ACL** (the parameterized rule). A session holding a grant under the
///   family but not for THIS path passes the floor and is refused inside `invoke`. That
///   refusal leaves NO trace event (core records an invocation only after `invoke` returns
///   `Ok` — reported for the hub), so the witness is the disk: no file, no directory.
///
/// In both the text the adapter shows begins `denied:`, which is prose — `Entry.result` is
/// `Result<String, String>`, so the taxonomy does not survive to the page. The TYPE is
/// asserted at the kernel, issued under the very capability the session holds.
///
/// ## What this test will not do
///
/// The ZeroTrust tab's steps 8 and 9 reach `httpbin.org` and `w3id.org`. A conformance-style
/// walk of a composing host is a remote-code-execution surface (conformance PENDING #139),
/// and the same is true of replaying a walkthrough: step 9 is a denial that is *supposed* to
/// happen before the request leaves, but a test whose failure mode is "we fetched a URL" is
/// not a test of the gate. They are asserted to be PRESENT and are not run.
#[cfg(all(test, feature = "embedded"))]
mod adapter_gate_tests {
    use super::*;
    use ikigai_core::{
        ArgRef, Capability, Error, Iri, Kernel, Request, TraceEvent, Tracer, Verb, DENIED_NOTE,
    };
    use ikigai_engine::Action;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex, MutexGuard};

    /// Every event the kernel reported: computed invocations and pre-dispatch denials.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<TraceEvent>>);

    impl Tracer for Recorder {
        fn record(&self, event: TraceEvent) {
            self.0.lock().expect("recorder").push(event);
        }
    }

    impl Recorder {
        fn events(&self) -> Vec<TraceEvent> {
            self.0.lock().expect("recorder").clone()
        }
    }

    /// `set_file_root` and the demo flag are process-global (their own docs say so), so the
    /// sessions here run one at a time rather than racing over one workspace root.
    static SESSION: Mutex<()> = Mutex::new(());

    struct Session {
        _lock: MutexGuard<'static, ()>,
        root: PathBuf,
        kernel: Arc<Kernel>,
        engine: Engine,
        trace: Arc<Recorder>,
    }

    /// The host as the REPL builds it, over a scratch workspace.
    ///
    /// `HOME`/`XDG_CONFIG_HOME` are redirected before the kernel is built because
    /// `root_space()` reads the config home (the `browse.root` lines); a test that reads the
    /// developer's real home and asserts only type-shape reads as clean while being about
    /// the machine it ran on (the hermetic-test rule). `set_file_root` is the typed channel
    /// `ikigai-embedded` documents for exactly this — `cfg(test)` does not reach a consumer.
    fn session(name: &str) -> Session {
        let lock = SESSION.lock().unwrap_or_else(|p| p.into_inner());
        let scratch =
            std::env::temp_dir().join(format!("ikigai-adapter-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(scratch.join("config")).expect("scratch config home");
        std::env::set_var("HOME", &scratch);
        std::env::set_var("XDG_CONFIG_HOME", scratch.join("config"));
        let root = scratch.join("workspace");
        std::fs::create_dir_all(&root).expect("scratch workspace");
        // Canonical: the file module compares canonical paths, so a capability scope naming
        // `/var/...` would not match a jail rooted at `/private/var/...` on macOS.
        let root = root.canonicalize().expect("canonical workspace");
        ikigai_embedded::set_file_root(root.clone());
        // The runbook is gated off by default (the CLI reads as a tool, not a demo).
        ikigai_embedded::demo_flag().store(true, Ordering::SeqCst);

        let kernel = Arc::new(ikigai_embedded::kernel());
        let trace = Arc::new(Recorder::default());
        kernel.set_tracer(trace.clone() as Arc<dyn Tracer>);
        let engine = with_profiles(Engine::new(Arc::clone(&kernel)));
        Session {
            _lock: lock,
            root,
            kernel,
            engine,
            trace,
        }
    }

    /// What the adapter does with a line — the same call the REPL, the TUI and the browser
    /// bridge all make.
    fn run(engine: &Engine, cmd: &str) -> Result<String, String> {
        match engine.eval(cmd) {
            Action::Output(entry) => entry.result,
            Action::Clear => Ok(String::new()),
            _ => panic!("`{cmd}` is not an output"),
        }
    }

    /// Reverse the runbook's attribute escaping (`esc` in ikigai-runbook).
    fn unescape(s: &str) -> String {
        s.replace("&quot;", "\"")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
    }

    /// Every `hx-get="/k/<command>"` the rendered tab carries, in order, minus the tab
    /// strip's own navigation and the `clear` button — the same slice the page's
    /// `htmx:beforeRequest` handler takes.
    fn steps(html: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = html;
        while let Some(at) = rest.find("hx-get=\"/k/") {
            rest = &rest[at + "hx-get=\"/k/".len()..];
            let end = rest.find('"').expect("a closed attribute");
            let cmd = unescape(&rest[..end]);
            rest = &rest[end..];
            if cmd == "clear" || cmd.starts_with("source urn:runbook:") {
                continue;
            }
            out.push(cmd);
        }
        out
    }

    /// The same Sink the step issues, at the kernel, under `capability` — the TYPED answer,
    /// which is the one thing the adapter's `Result<String, String>` cannot carry.
    fn typed_sink(kernel: &Kernel, target: &str, capability: &Capability) -> Error {
        let request = Request::new(Verb::Sink, Iri::parse(target.to_string()).expect("iri"))
            .with_arg("content", ArgRef::Inline(b"nope".to_vec()));
        futures::executor::block_on(kernel.issue(request, capability))
            .err()
            .unwrap_or_else(|| panic!("`{target}` resolved under {capability:?}"))
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// **The floor gate**: a step naming a gated resource, under a session that holds no
    /// grant under the declared family, is a typed `Denied` and the endpoint never runs.
    #[test]
    fn a_step_is_refused_before_dispatch_when_the_session_lacks_the_declared_family() {
        let s = session("floor");
        let tab = run(&s.engine, "source urn:runbook:zerotrust as=text/html")
            .expect("the demo flag is on, so the tab renders");
        let steps = steps(&tab);
        assert_eq!(steps.len(), 10, "{steps:?}");
        assert_eq!(steps[1], "cap read-only");
        assert_eq!(steps[2], "sink urn:file:note.txt nope");
        // Not run, and named so the omission is deliberate rather than forgotten.
        assert!(steps[7].contains("httpbin.org"), "{:?}", steps[7]);
        assert!(steps[8].contains("w3id.org"), "{:?}", steps[8]);

        run(&s.engine, &steps[0]).expect("1 · at root the write lands");
        let note = s.root.join("note.txt");
        assert_eq!(read(&note), "remember the milk");

        run(&s.engine, &steps[1]).expect("2 · cap read-only");
        assert_eq!(
            s.engine.capability(),
            Capability::root().attenuate([format!("urn:cap:fs:read:{}", s.root.display())]),
            "the profile `with_profiles` actually registers"
        );

        let before = s.trace.events().len();
        let refused = run(&s.engine, &steps[2]).expect_err("3 · write → denied");
        assert!(refused.starts_with("denied:"), "{refused}");
        assert_eq!(read(&note), "remember the milk", "the file is untouched");

        let events = s.trace.events();
        assert_eq!(
            events.len(),
            before + 1,
            "one event, the denial: {events:?}"
        );
        let denial = &events[before];
        assert_eq!(denial.target, "urn:file:note.txt");
        assert_eq!(
            denial.notes,
            vec![(DENIED_NOTE.to_string(), "urn:cap:fs:write:*".to_string())],
            "refused at the floor, for the scope the action declares"
        );
        assert!(
            denial.started.is_none() && denial.ended.is_none(),
            "nothing ran: {denial:?}"
        );
        assert!(
            matches!(
                typed_sink(&s.kernel, "urn:file:note.txt", &s.engine.capability()),
                Error::Denied(_)
            ),
            "typed at the kernel, under the session's own capability"
        );

        // Reads still resolve, and the jail holds even at full authority.
        assert_eq!(
            run(&s.engine, &steps[3]).expect("4 · read → ok"),
            "remember the milk"
        );
        run(&s.engine, &steps[4]).expect_err("5 · the jail refuses `..`");
        run(&s.engine, &steps[5]).expect("6 · cap reset");
        assert_eq!(s.engine.capability(), Capability::root());
        run(&s.engine, &steps[4]).expect_err("the jail holds at root too");
    }

    /// **The module's ACL gate**: a session that DOES hold a grant under the family, but for
    /// another path, clears the floor and is refused inside `invoke` — with no trace event
    /// at all, so the only witness is that nothing reached the disk.
    ///
    /// This is the half a status code cannot distinguish: both gates answer 403 through the
    /// HTTP face and `denied:` through this one, and only the absence of the file says the
    /// endpoint was not entered.
    #[test]
    fn a_step_outside_the_granted_segment_is_denied_and_never_reaches_the_disk() {
        let s = session("acl");
        let root = s.root.display();
        let login = run(
            &s.engine,
            &format!(
                "sink urn:host:login urn:cap:fs:read:{root}/mine urn:cap:fs:write:{root}/mine"
            ),
        )
        .expect("login is a session operation");
        assert!(login.starts_with("logged in"), "{login}");

        run(&s.engine, "sink urn:file:mine/secret.txt mine only")
            .expect("a write inside the segment lands");
        assert_eq!(read(&s.root.join("mine/secret.txt")), "mine only");

        let before = s.trace.events().len();
        let refused = run(&s.engine, "sink urn:file:someone-else/secret.txt nope")
            .expect_err("outside the segment is refused");
        assert!(refused.starts_with("denied:"), "{refused}");
        assert!(
            !s.root.join("someone-else").exists(),
            "nothing was written outside the granted segment"
        );
        let after = s.trace.events();
        assert_eq!(
            after.len(),
            before,
            "the module's ACL refused inside invoke, which core does not trace: {after:?}"
        );
        assert!(
            matches!(
                typed_sink(
                    &s.kernel,
                    "urn:file:someone-else/secret.txt",
                    &s.engine.capability()
                ),
                Error::Denied(_)
            ),
            "the floor passed (a write grant IS held) and the endpoint's own rule refused"
        );
    }
}
