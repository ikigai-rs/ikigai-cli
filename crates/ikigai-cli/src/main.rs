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
#[cfg(all(feature = "embedded", feature = "quic", feature = "web"))]
mod front;
#[cfg(feature = "embedded")]
mod layer;
#[cfg(feature = "quic")]
mod quic;
#[cfg(all(feature = "embedded", feature = "web"))]
mod rate_limits;
mod repl;
#[cfg(feature = "web")]
mod route_load;
#[cfg(all(feature = "embedded", not(target_family = "wasm")))]
mod show;
#[cfg(not(target_family = "wasm"))]
mod tui;
#[cfg(all(feature = "embedded", feature = "web"))]
mod uploads;

const USAGE: &str = "\
ikigai — resource-resolution REPL

usage:
  ikigai                       start the interactive REPL (full-screen on a terminal)
  ikigai --plain               force the line REPL (also used automatically when piped)
  ikigai --quiet               the line REPL with no greeting (no version banner, no topology
                               lines on stderr) and, when stdin is not a terminal, no prompt:
                               a piped session prints its answers and nothing else, so it
                               replays cleanly. Implies --plain; a -c batch is already quiet
                               The line REPL continues after errors; exits 1 if any line failed,
                               otherwise 0, at EOF or quit.
  ikigai --demo                mount the interactive runbook (urn:runbook:*); off by default
  ikigai --connect [<target>]  attach the REPL to a kernel server (a Unix path, or quic://host:port)
  ikigai --mount <pfx>=<tgt>   compose a remote kernel at prefix <pfx> (<tgt> = Unix path or quic://host:port)
  ikigai serve [<target>]      run a kernel server (a Unix socket path, or quic://addr to bind)
                               every door (socket, QUIC, --http) watches the file root, so a
                               file changed on disk is served fresh, no restart
  ikigai serve <q> --cap <s>   serve under a fixed capability ceiling <s> every client is clamped to
                               (with clients.json below, the OUTER bound each grant narrows within)
  ikigai serve <q>             per-identity authority when ~/.config/ikigai/clients.json enrolls
                               certificates — it maps a client's SHA-256 fingerprint to a grant
                               named in grants.json, so each gets its own scopes, an unenrolled
                               one is REFUSED, and editing the file revokes on the next
                               connection. `default` serves an enrolled entry that names no
                               grant, never a certificate with no entry. The trust list
                               (client.crt + clients/*.crt) is re-read at every handshake,
                               and a certificate past its notAfter (or before its notBefore) is
                               refused there.
                               `cert add-client` prints the fingerprint to enroll.
                               Each client is named urn:iki:host:<name>:client:<fingerprint>
                               (or its entry's `principal`), and a connection is closed once it
                               is quic.max_connection_age seconds old (default 600), so the
                               next call reconnects under the enrolment as it is then.
  ikigai serve <q> --require-enrollment
                               refuse to start without clients.json, so the door never falls
                               back to one shared --cap ceiling for every trusted certificate
                               (the booking airlock runs this way, its --cap the clamp)
  ikigai serve <q> --announce  also advertise this kernel on the local network (mDNS), so clients
                               can mount it by name; `source urn:peer:list` shows who is out there
  ikigai serve <q>             hosts LAYERS (ikigai-layers: urn:layer:*, urn:layers:*, urn:collab:*)
                               when the config home has a layers/ directory, on a kernel with a
                               clock; the host validates each write itself, so no validator is
                               bound. Participants are clients.json/grants.json as
                               `ikigai-layers grants <config home>` writes them. State lives in
                               --layers-state <dir>, else `layers.state` (instance-scoped as
                               <name>.layers.state; relative to the config home) in config.toml,
                               else ~/.ikigai/layers/<name>. No environment variable names it.
                               The state is SEALED AT REST (age): --layers-key <file> names the
                               host's age identity (`age-keygen -o <file>`), else `layers.key`
                               (<name>.layers.key) in config.toml. Required: without one the
                               door refuses to start, and a wrong key is refused at open
  ikigai serve <q> --layers-reseal  ONCE, over state an ikigai before 0.1.67 wrote (plaintext,
                               refused until then): seal every state file in place to the
                               --layers-key identity, then serve. Also rotates the key (new
                               identity first in the file, the old after it; drop the old line
                               after). Safe to rerun: it resumes a stopped run and changes
                               nothing over sealed state; later starts leave it off
                               A layer door serves ONLY its layers: none of the general served
                               surface (host, files, intake, links, passkey), and it refuses to
                               start with a mount or a ceiling that opens another face
  ikigai serve <s> --prefer …  a served host may take --mount/--override/--prefer too, so IT owns
                               the topology: a local client reaches a peer through this socket
                               without holding its certs or finding it itself. A v9 client's
                               deadline reaches the peer as time left; its retry count stops
                               here (serve sets no retry budget, so the peer uses its own), and
                               a spent deadline is answered, not refused
  ikigai serve … --code-signer <k>  accept SIGNED programs (urn:lisp:run) vouched for by key
                               resource <k> (repeatable; --code-signers-dir sets where
                               urn:codekey:{file} reads from). Without it the door is unbound.
  ikigai serve … --eval-timeout <s>  wall-clock ceiling for a served eval (default 10s)
  ikigai serve --http <port>   serve the inbound HTTP face (loopback; front with TLS at your proxy)
                               [--trust-proxy: honor X-Forwarded-*; --cors-origin <o>: allow a CORS origin;
                                --routes <iri>: load routes from an RDF or plain-JSON resource
                                (a urn:file: route hot-reloads; a route's {var} refuses a value
                                carrying : / ? # [ ] @ with a 400, {+var} passes it raw);
                                --routes-only: un-routed → 404;
                                --max-body <bytes>: largest accepted request body, default 1048576;
                                --push: serve cut notices as an event stream at /_ikigai/push —
                                needs --cap urn:cap:kernel:listen, or every stream is a 403;
                                --passkey-rp-id <domain> [--passkey-origin <url>]: the WebAuthn
                                relying party the passkey endpoints serve (origin defaults to
                                https://<domain>). No default: without it nothing can enroll, and
                                an edge with a passkey enrolled refuses every gated decision]
  ikigai --daemon              headless: timers, the watcher, and the standing sync — for launchd
  ikigai --name <instance>     name this instance (scopes <name>.* config properties; defaults
                               repl / daemon / serve by mode)
  ikigai --config-home <dir>   use <dir> as the config home (config.toml, grants.json, clients.json,
                               …) instead of $XDG_CONFIG_HOME/ikigai or ~/.config/ikigai. Any mode
                               (REPL, -c, serve, mcp, --daemon, --connect, cert). A relative <dir> is
                               made absolute against the working directory. The flag WINS: with it,
                               XDG_CONFIG_HOME is not read for the config home at all. It moves the
                               config home only; the data home (~/.ikigai) stays where it is
  ikigai --scheduler <spec>    fan-out width: single | pool | pool:N (any mode). Also
                               `scheduler = \"pool:N\"` in the config home (instance-scoped as
                               <name>.scheduler); IKIGAI_SCHEDULER still works, deprecated.
                               `source urn:kernel:scheduler` reports the width AND the channel
  ikigai --arrangement <file>  build the LOCAL kernel's root from a declared arrangement (Turtle in
                               the ik: vocabulary urn:kernel:topology writes) instead of the built-in
                               one. Also `arrangement = \"<file>\"` in the config home (relative to it;
                               instance-scoped as <name>.arrangement). `source urn:iki:host:arrangement`
                               dumps the running one to start from. REPL, -c, --daemon, mcp and
                               serve <socket>; refused by the served doors and --connect. A file that
                               is missing, malformed or does not build stops the start
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
  <p> = <p1>,<p2>,…            several prefixes, ONE connection and one cert set: `--override
                               urn:layer:,urn:layers:,urn:collab:=quic://door:4434 --cert-dir <d>`
                               follows a layer door (a comma cannot appear inside a prefix)
  ikigai mcp --grant <n> | --scope <s> | --principal <iri> | --root  [--grants <f>] [--show <p>] [mounts…]
                               serve the manifold as MCP tools over stdio, under the named
                               authority: --grant/--scope (repeatable, unioned); --principal, an
                               agent in the grants file's `principals` table, minted into every
                               call, its grant checked to be within its person's, read from a
                               grants file this user cannot write (--grants <f>, root-owned);
                               or --root, UNRESTRICTED, by request. Naming none refuses to start.
                               A grants-file edit narrows a running session live; a widening
                               waits for the next start. --show (repeatable)
                               lists only tools matching <p>: a tool name (`echo`, `repo-*`) or,
                               with a `:`, an IRI prefix they are bound under (`urn:layer:`), so
                               an entry for a mounted peer leaves the local tools out. It unions
                               with a --grant's `show` patterns; authority is unchanged
  ikigai --files <dir>         the local file module's root (urn:file:*), any mode. Else `files`
                               in config.toml (instance-scoped as <name>.files; relative to the
                               config home), else $IKIGAI_FILES, else ~/.ikigai/workspace
  ikigai --bayes-state <dir> --bayes-model <name>
                               bind the spam filter (ikigai-bayes: urn:bayes:<name>:score, :train,
                               :untrain, :stats, urn:bayes:models) in the LOCAL root, over a state
                               directory this process holds alone (a second process on it is
                               refused, naming the holder's pid). --bayes-model repeats. Else
                               `bayes.state` / `bayes.models` in config.toml (instance-scoped as
                               <name>.bayes.*; relative to the config home). Both halves or neither:
                               with no model named nothing is bound. A missing directory is created
                               at 0700. REPL, -c, --daemon, mcp and serve <socket>; refused by the
                               served doors and --connect. The doors need urn:cap:bayes:read:<name>
                               and urn:cap:bayes:train:<name>, which nothing grants by default
  ikigai --no-config-mounts    compose ZERO mounts: decline the machine's topology instead of
                               enumerating a replacement. Honoured by every mode that builds a
                               kernel (REPL, -c, --daemon, serve, mcp); refuses to start beside
                               --mount/--override/--prefer, which declare a topology of their own
  ikigai --react               run the space reactor in this session — claims and executes tuples
                               dropped in the workspace. OFF by default; the daemon is the worker
  ikigai cert generate         create the pinned QUIC certificates (--dir <d> for a dedicated set)
  ikigai cert add-client <n>   mint an extra client identity into clients/<n>.{crt,key}
  ikigai serve <q> --layers-https <addr>
                               a door hosting layers also serves participant verbs over HTTPS
                               at <addr> (or `layers.https`, instance-scoped as
                               <name>.layers.https, in the config home; off unless one names an
                               address), with the door's own server certificate, for a
                               participant that has only an HTTP client and a JSON parser.
                               Same kernel, grants, principals and refusals as the QUIC door;
                               needs the `web` feature beside `quic`
  ikigai layers-token mint <participant|fingerprint> [--label <l>]
                               mint a bearer token for the HTTPS front, bound to ONE enrolled
                               clients.json entry (a participant IRI that names exactly one, or
                               its fingerprint). Printed once; layer-tokens.json in the config
                               home stores its hash, re-read on every request
  ikigai layers-token list     the tokens: id, the client each is bound to, label, minted
  ikigai layers-token revoke <id>  remove one; its next request is refused (401)
  ikigai [flags] layers post brief|issue|file <layer> …
                               post an ik:Brief, ik:Issue or ik:File to a layer, the entry composed
                               for you (the Turtle escaped; a file's SHA-256, size, and text or
                               base64), through whatever routes urn:layer: (--override … --cert-dir,
                               --connect, a config-home mount): `ikigai --override
                               urn:layer:,urn:layers:,urn:collab:=quic://door:4434 --cert-dir <d>
                               layers post file talk ./trace.log`. Prints the entry's IRI
  ikigai [flags] layers save <entry> [<path>] [--as <name>] [--force]
                               write a posted file back to disk (no <path>: ~/Downloads) after
                               checking its size and SHA-256 against what the entry says; a name
                               that would arm something (CLAUDE.md, .envrc, CON) is refused, so
                               save it --as another; `ikigai layers --help` for all
  ikigai -c '<command>' ...    run command(s) non-interactively, then exit. Each -c is ONE
                               statement (a newline does not split it): repeat -c for more
  ikigai -e '<sexpr>' ...       evaluate a Lisp s-expression (urn:lisp:eval), then exit
  ikigai --load <uri> [--cap <s>]  read a script resource and evaluate it as Lisp (--cap narrows first)
  ikigai -h | --help           show this help
  ikigai -V | --version        print `ikigai <x.y.z>` on one line and exit — answered in
                               every mode, before anything is built or connected
  ikigai --version --verbose   that line, then one `<crate> <x.y.z>` line per ikigai-* crate
                               this binary links, read from the lock it was built from

QUIC: --server-cert/--server-key name the server's identity, --client-cert/--client-key the client's
inside the REPL: source, describe, help, quit (type `help` for details)";

/// The closing lines of `--help`: which transports THIS binary was built with and which it
/// lacks (ledger #109). [`USAGE`] describes every transport the source knows, so on a build
/// without `quic` it advertised `quic://` and the binary then refused it with "needs the
/// `quic` feature" (a store-only install on plasma silently dropped quic and web this way).
/// Read from `cfg!`, so the line is true of the binary that prints it.
#[cfg(feature = "embedded")]
fn build_transports() -> String {
    let mut has = Vec::new();
    let mut lacks = Vec::new();
    let mut note = |present: bool, what: &str, rebuild: &str| {
        if present {
            has.push(what.to_string());
        } else {
            lacks.push(format!("{what} ({rebuild})"));
        }
    };
    note(
        cfg!(all(feature = "ipc", unix)),
        "Unix socket",
        "needs the `ipc` feature on a Unix platform",
    );
    note(
        cfg!(feature = "quic"),
        "quic://",
        "needs the `quic` feature",
    );
    note(
        cfg!(feature = "web"),
        "serve --http",
        "needs the `web` feature",
    );
    note(
        cfg!(all(feature = "quic", feature = "web")),
        "--layers-https",
        "needs `quic` and `web`",
    );
    let list = |items: &[String]| {
        if items.is_empty() {
            "nothing".to_string()
        } else {
            items.join(", ")
        }
    };
    format!(
        "this build: has {}\n            lacks {}",
        list(&has),
        list(&lacks)
    )
}

/// The single line `-V`/`--version` prints. ONE version string for the whole binary:
/// the same spelling as the REPL banner (`repl.rs`), the no-transport message below,
/// and the MCP server's `version` field — so a script comparing a host against a
/// release does not have to know which face produced the number.
///
/// Deliberately undecorated. The caller is usually a script, not a human: `ikigai
/// 0.1.18`, nothing else on the line, exit 0.
const VERSION_LINE: &str = concat!("ikigai ", env!("CARGO_PKG_VERSION"));

/// What `--version --verbose` prints after [`VERSION_LINE`]: one `<crate> <x.y.z>` line per
/// `ikigai-*` crate this binary links, sorted, as `build.rs` read them from the lock this
/// build resolved against (ledger #1338) — or one line beginning `unknown:` saying why it
/// could not. `build.rs` states what the list can and cannot see.
///
/// A floor check reads it by contract instead of by the crates.io source paths that happen
/// to be compiled into panic locations, which is what it replaces.
const LINKED_CRATES: &str = include_str!(concat!(env!("OUT_DIR"), "/linked-ikigai.txt"));

/// The command that installs a newer build of THIS binary (ledger #288), with the features it
/// was built with, so following it does not silently drop `quic` or `web`. Named under an
/// unresolved name, the error people hit first on a host older than the docs they follow.
#[cfg(feature = "embedded")]
fn upgrade_command() -> String {
    let defaults = cfg!(feature = "embedded") && cfg!(feature = "ipc");
    let mut features: Vec<&str> = Vec::new();
    for (on, name) in [
        // Off the defaults, name what this build kept of them (`embedded` always: this
        // function is only built with it).
        (!defaults, "embedded"),
        (!defaults && cfg!(feature = "ipc"), "ipc"),
        (cfg!(feature = "quic"), "quic"),
        (cfg!(feature = "web"), "web"),
        (cfg!(feature = "store"), "store"),
    ] {
        if on {
            features.push(name);
        }
    }
    let mut command = "cargo install --locked ikigai-cli".to_string();
    if !defaults {
        command.push_str(" --no-default-features");
    }
    if !features.is_empty() {
        command.push_str(&format!(" --features {}", features.join(",")));
    }
    command
}

/// The build line under an unresolved name, said as this binary can justify it (ledger
/// #2481). ikigai-engine 0.2 words the line it hangs under an unresolved name (from
/// [`upgrade_command`], ledger #288) as if the name were NEWER than this build: "a name newer
/// than this build needs an upgrade". This build cannot know that. A name no release binds
/// (until 0.2.3 that was `urn:json:query`) sent the reader to reinstall the binary they
/// already had. So the faces replace the engine's sentence: this build binds no such name,
/// and an upgrade helps only if a newer release exists, which `cargo search` shows.
///
/// ```text
/// error: no endpoint resolved for urn:json:query
///        this host is ikigai 0.2.2, and it binds no such name
///        a newer release may bind it; if `cargo search ikigai-cli` names one past 0.2.2: cargo install --locked ikigai-cli
/// ```
///
/// Only the exact sentence the engine builds from [`VERSION_LINE`] and [`upgrade_command`]
/// is replaced, so a `--connect` engine (which names no build) and every other error pass
/// through untouched.
#[cfg(feature = "embedded")]
fn restate_build_line(err: &str) -> std::borrow::Cow<'_, str> {
    let upgrade = upgrade_command();
    let engine = format!(
        "this host is {VERSION_LINE}; a name newer than this build needs an upgrade: {upgrade}"
    );
    if !err.contains(&engine) {
        return std::borrow::Cow::Borrowed(err);
    }
    // The engine's continuation indent (`SUGGESTION_INDENT`), which clears `error: `.
    const INDENT: &str = "       ";
    let version = env!("CARGO_PKG_VERSION");
    std::borrow::Cow::Owned(err.replace(
        &engine,
        &format!(
            "this host is {VERSION_LINE}, and it binds no such name\n{INDENT}a newer release \
             may bind it; if `cargo search ikigai-cli` names one past {version}: {upgrade}"
        ),
    ))
}

/// Without `embedded` no engine names a build, so there is nothing to restate.
#[cfg(not(feature = "embedded"))]
fn restate_build_line(err: &str) -> std::borrow::Cow<'_, str> {
    std::borrow::Cow::Borrowed(err)
}

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
    /// and burying a version behind a screen of help is the failure this fixes. With
    /// `--verbose` (`verbose`), the linked `ikigai-*` crates follow, one per line.
    Version {
        verbose: bool,
    },
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
        /// fronting proxy, e.g. Apache); a full `host:port` overrides the bind. Port `0`
        /// takes a free port from the kernel, and the banner names the one bound.
        http: Option<String>,
        /// `--trust-proxy`: honor `X-Forwarded-Proto`/`-For` from the upstream (enable
        /// ONLY behind a proxy you control, e.g. Apache). Drives HTTPS detection for HSTS.
        trust_proxy: bool,
        /// `--cors-origin <origin>` (repeatable): allow this cross-origin (exact, or `*`).
        /// Empty = CORS closed (the safe default).
        cors_origins: Vec<String>,
        /// `--routes <iri>`: load the route table from this RDF resource (`ik:Route` graph),
        /// e.g. `urn:web:routes` or a watched `urn:file:web/routes.ttl`. A route's `{var}` is
        /// strict (a value carrying `:` `/` `?` `#` `[` `]` `@` is a `400`); `{+var}` is raw —
        /// see `ikigai_web::Route`.
        routes: Option<String>,
        /// `--routes-only`: an un-routed path 404s instead of falling through to the mechanical
        /// default — the route table becomes an exhaustive allow-list (the public-edge posture).
        routes_only: bool,
        /// `--max-body <bytes>`: the largest request body this door accepts; a bigger one is
        /// refused with `413` before it is read. `None` → the transport's own default. Lower
        /// it for a door that only takes forms — the public intake edge has no use for a
        /// megabyte.
        max_body: Option<usize>,
        /// `--push`: serve an event stream of cut notices at `ikigai_web::DEFAULT_PUSH_PATH`.
        /// A stream is heard under the door's capability, so it needs `--cap
        /// urn:cap:kernel:listen` too; without it every stream is answered 403.
        push: bool,
        /// `--announce`: advertise this kernel on the local network over mDNS, so clients
        /// can mount it by name instead of by an address that moves. Opt-in — broadcasting
        /// what a machine serves is a disclosure.
        announce: bool,
        /// Remote kernels composed into the served surface (`--mount`/`--override`/
        /// `--prefer`, same syntax as the REPL). THE HOST OWNS THE TOPOLOGY: a local client
        /// then reaches a peer through this socket without knowing where it is, holding its
        /// certificates, or needing the platform permission discovery requires.
        mounts: Mounts,
        /// `--layers-state <dir>` (absolute): where a QUIC door hosting layers keeps their
        /// entries, tuples, receipts and feeds (ledger #1188). Layers are hosted when the
        /// config home has a `layers/` directory; see `ikigai_embedded::layers`.
        layers_state: Option<std::path::PathBuf>,
        /// `--layers-key <path>` (absolute): the age identity file the layer host seals its
        /// state with (ikigai-layers 0.3.0, ledger #2011).
        layers_key: Option<std::path::PathBuf>,
        /// `--layers-reseal`: seal a plaintext state directory in place (and rotate the key)
        /// on this start, then serve (`ikigai_layers::Migration::Reseal`).
        layers_reseal: bool,
        /// `--layers-https <addr>`: also serve the layers' participant verbs over HTTPS there
        /// (ledger #1371). See `front.rs`.
        layers_https: Option<String>,
        /// `--require-enrollment`: a QUIC door that refuses to start without a `clients.json`,
        /// so it can never fall back to a shared `--cap` ceiling or to per-client workspaces
        /// because the file went missing (ledger #1826: the booking airlock).
        require_enrollment: bool,
    },
    /// Serve the capability-scoped manifold as an MCP (Model Context Protocol)
    /// server over stdio. `grants`/`scopes` union into the session capability —
    /// the ceiling on the tools an MCP client sees and can call.
    Mcp {
        grants: Vec<String>,
        scopes: Vec<String>,
        /// `--principal <agent IRI>` (ledger #1830): serve as that agent, minted into the
        /// session capability, its grant checked to be within its person's.
        principal: Option<String>,
        /// `--root`: serve UNRESTRICTED, by explicit request. Without it and without a grant,
        /// a scope or a principal, `ikigai mcp` refuses to start.
        root: bool,
        /// `--grants <file>`: read grants (and the principals table) from this file instead
        /// of the config home's `grants.json`.
        grants_file: Option<std::path::PathBuf>,
        /// `--show <pattern>` (repeatable): project only the tools matching one of these,
        /// unioned with the named grants' `show` lists (ledger #1284). An IRI prefix
        /// (`urn:layer:`) selects by where a tool is bound. Relevance, never authority.
        shows: Vec<String>,
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
    /// `layers-token mint|list|revoke`: the bearer tokens of a layer door's HTTPS front (see
    /// `ikigai_embedded::tokens`).
    LayersToken(TokenCommand),
}

/// What `layers-token` was asked to do.
enum TokenCommand {
    Mint {
        client: String,
        label: Option<String>,
    },
    List,
    Revoke {
        id: String,
    },
}

/// Options for the REPL mode.
#[derive(Default, Clone)]
struct ReplArgs {
    plain: bool,
    /// `--quiet` (ledger #1310): the line REPL without its greeting, and without a prompt
    /// when stdin is not a terminal. Implies `plain`.
    quiet: bool,
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
    /// `layers post|save …` (ledger #1629): run that against this engine instead of a REPL
    /// or a `-c` batch. Everything after `layers` on the command line is its own.
    #[cfg(feature = "embedded")]
    layers: Option<layer::Command>,
}

/// One `--mount`: where it binds, what it connects to, and the certificates for
/// THAT connection. Cert flags following a `--mount` attach to it; cert flags
/// before any mount form the default set (used by `--connect`, and by a mount
/// that declares none of its own).
///
/// `prefix` may name SEVERAL prefixes, comma-separated (`urn:layer:,urn:layers:=quic://…`):
/// one connection, one certificate set, every prefix served through it (ledger #1283). See
/// [`mount_prefixes`]. It is kept as typed so the banner and `urn:host:posture` show the
/// line the operator wrote.
#[derive(Clone)]
struct Mount {
    prefix: String,
    target: String,
    certs: Certs,
    kind: ikigai_embedded::MountKind,
}

/// The prefixes one mount flag (or `mount =` line) names. `urn:layer:,urn:layers:,urn:collab:`
/// is three prefixes served by ONE connection with ONE certificate set (ledger #1283): a layer
/// door's names live under three prefixes, and `urn:layers:` does not start with `urn:layer:`,
/// so following one took three `--override` flags, each followed by its own `--cert-dir` (the
/// cert flags attach to the mount they FOLLOW, so one trailing `--cert-dir` left the first two
/// on the default set, which a layer client does not have).
///
/// A comma therefore cannot appear INSIDE a prefix. An empty segment (`urn:a:,,urn:b:`, a
/// trailing comma) and the same prefix twice are refused rather than read as something: both
/// are typos, and an empty prefix would match every IRI. A single prefix is passed through
/// exactly as before, empty included, so no existing form changes meaning.
///
/// A prefix under the kernel's reserved namespace (`urn:kernel:`, or `urn:kernel` itself) is
/// refused too (ledger #1337): core answers those names itself, ahead of every mount, so such
/// a mount never applies, and an override that silently reads the LOCAL manifold is worse
/// than a refusal for an operator checking a door's. A prefix that merely CONTAINS the
/// namespace (`urn:`) still mounts everything else under it.
fn mount_prefixes(prefix: &str) -> Result<Vec<&str>, String> {
    if !prefix.contains(',') {
        refuse_kernel_prefix(prefix)?;
        return Ok(vec![prefix]);
    }
    let parts: Vec<&str> = prefix.split(',').collect();
    if parts.iter().any(|part| part.is_empty()) {
        return Err(format!(
            "`{prefix}` has an empty prefix (a comma separates prefixes; none may be empty)"
        ));
    }
    for (at, part) in parts.iter().enumerate() {
        if parts[..at].contains(part) {
            return Err(format!("`{prefix}` names `{part}` twice"));
        }
        refuse_kernel_prefix(part)?;
    }
    Ok(parts)
}

/// The namespace core answers itself, ahead of every mount (core's `CORE_SEAL`).
const KERNEL_NAMESPACE: &str = "urn:kernel:";

/// Refuse a mount prefix every name under which is the kernel's own (see [`mount_prefixes`]).
fn refuse_kernel_prefix(prefix: &str) -> Result<(), String> {
    if prefix.starts_with(KERNEL_NAMESPACE) || prefix == KERNEL_NAMESPACE.trim_end_matches(':') {
        return Err(format!(
            "`{prefix}` is under `{KERNEL_NAMESPACE}`, the namespace every kernel answers ITSELF \
             ahead of any mount, so this mount would never apply and the names would be read \
             from this kernel, not the target. To read another kernel's `{KERNEL_NAMESPACE}*`, \
             connect to it: `ikigai --connect <target> -c 'source urn:kernel:actions'`"
        ));
    }
    Ok(())
}

/// `<prefix>=<target>` split for the flag (or config line) `what`, with the prefixes checked
/// by [`mount_prefixes`] here, at parse time, so a bad list stops the start with the usage
/// block rather than at connect.
fn mount_spec<'a>(what: &str, spec: &'a str) -> Result<(&'a str, &'a str), String> {
    let (prefix, target) = spec
        .split_once('=')
        .ok_or_else(|| format!("{what} expects <prefix>=<target>, got `{spec}`"))?;
    mount_prefixes(prefix).map_err(|e| format!("{what}: {e}"))?;
    Ok((prefix, target))
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
    push: bool,
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

/// If `arg` is `--arrangement`, consume its path and declare it for this process: the local
/// kernel's root is then built from that declaration instead of the built-in arrangement
/// (ledger #637). The file is not read here — [`arm_local_root`] reads it once a mode that
/// builds a local root is known — so a door that builds none can refuse the flag by name
/// instead of silently ignoring it.
fn arrangement_flag(arg: &str, argv: &mut impl Iterator<Item = String>) -> Result<bool, String> {
    if arg != "--arrangement" {
        return Ok(false);
    }
    let path = argv
        .next()
        .ok_or_else(|| "--arrangement needs <path>".to_string())?;
    #[cfg(feature = "embedded")]
    ikigai_embedded::arrangement::set_arrangement_path(path);
    #[cfg(not(feature = "embedded"))]
    let _ = path;
    Ok(true)
}

/// Read the declared arrangement for the local root, if `--arrangement` or the config home's
/// `arrangement` key names one, before the first local kernel is built. **Fail loud**: a
/// declaration that is named and cannot be read or parsed stops the start with its message —
/// never a fall back to the built-in root, which an operator who asked for a declaration could
/// not tell apart from the one they asked for. (A declaration that parses and does not BUILD
/// stops the process where the root is built, with core's message naming the node.)
#[cfg(feature = "embedded")]
fn arm_local_root() {
    // Success says nothing here: the root is not built yet, and the line that says it was
    // arranged from the declaration is printed where it is (see `root_space_with_mounts`).
    match ikigai_embedded::arrangement::arm() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("ikigai: {e}");
            std::process::exit(2);
        }
    }
}

/// Refuse `--arrangement` on a door that builds no local root: the served postures are
/// minimal by design and a declaration must never widen one, and `--connect` resolves on
/// another kernel. Ignoring the flag there would be the silent fall back [`arm_local_root`]
/// exists to prevent. (The config home's `arrangement` key is simply not read by these doors:
/// it names the local root, and they do not build one.)
#[cfg(feature = "embedded")]
fn refuse_arrangement_flag(door: &str) {
    if let Some(path) = ikigai_embedded::arrangement::arrangement_flag() {
        eprintln!(
            "ikigai: --arrangement `{}` declares the LOCAL kernel's root, and {door} does not \
             build one",
            path.display()
        );
        std::process::exit(2);
    }
}

/// Open the spam filter's models for a mode that builds the local root, once, before the first
/// kernel is built (ledger #1512): `--bayes-state` + `--bayes-model`, else the config home's
/// `bayes.*` keys. **Fail loud**: half a setting, a state directory another process holds (the
/// refusal names its pid) or a model file that will not load stops the start, exit 2 — never a
/// host that runs without the filter it was told to bind. `announce` prints the one startup
/// line on stderr; a `-c` batch and `--quiet` stay quiet.
#[cfg(feature = "embedded")]
fn arm_bayes(announce: bool) {
    match ikigai_embedded::bayes::arm() {
        Ok(Some(line)) if announce => eprintln!("{line}"),
        Ok(_) => {}
        Err(e) => {
            eprintln!("ikigai: {e}");
            std::process::exit(2);
        }
    }
}

/// Refuse `--bayes-state` / `--bayes-model` on a door that builds no local root. The served
/// postures are minimal by design, and the public HTTP face in particular must never hold the
/// model: one writer per state directory, and the daemon is it.
#[cfg(feature = "embedded")]
fn refuse_bayes_flags(door: &str) {
    if ikigai_embedded::bayes::flags_given() {
        eprintln!(
            "ikigai: {} and {} bind the spam filter in the LOCAL root, and {door} does not build \
             one",
            ikigai_embedded::bayes::STATE_FLAG,
            ikigai_embedded::bayes::MODEL_FLAG
        );
        std::process::exit(2);
    }
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

/// `--version`: [`VERSION_LINE`], alone unless `verbose`, so a script reading one line is
/// unaffected; `--verbose` adds [`LINKED_CRATES`] under it.
fn print_version(verbose: bool) {
    println!("{VERSION_LINE}");
    if verbose {
        print!("{LINKED_CRATES}");
    }
}

/// Parse argv. `Ok(None)` means a usage request was handled and we should exit 0.
///
/// `--config-home` is taken out FIRST and applied before any mode is parsed, because every
/// mode reads the config home and some read it while parsing (a `--mount` line's peer cert
/// directory, the `arrangement` key) — the flag has to be in force before the first read.
/// `--files` is taken out the same way, for every mode at once.
fn parse_args() -> Result<Option<Mode>, String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // Read only to resolve a relative `--config-home`: a process whose working directory is
    // gone must still start when it was not given one.
    let cwd = std::env::current_dir().ok();
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    if let Some(dir) = take_config_home(&mut args, cwd.as_deref(), home.as_deref())? {
        apply_config_home(dir)?;
    }
    if let Some(dir) = take_files(&mut args, cwd.as_deref(), home.as_deref())? {
        #[cfg(feature = "embedded")]
        ikigai_embedded::set_file_root(dir);
        #[cfg(not(feature = "embedded"))]
        let _ = dir;
    }
    let (bayes_state, bayes_models) = take_bayes(&mut args, cwd.as_deref(), home.as_deref())?;
    #[cfg(feature = "embedded")]
    ikigai_embedded::bayes::set_flags(bayes_state, bayes_models);
    #[cfg(not(feature = "embedded"))]
    let _ = (bayes_state, bayes_models);
    parse_argv(args.into_iter())
}

/// Take every `--bayes-state <dir>` and `--bayes-model <name>` (either also as `--flag=value`)
/// out of `args`, in every mode at once like [`take_files`] (ledger #1512). The directory is made
/// ABSOLUTE by [`take_dir_flag`]'s rules; the model flag repeats, one name each, in the order
/// given. Nothing is opened here: the modes that build the local root ARM the model once the
/// instance name is known (`arm_bayes`), and the served doors refuse the flags by name.
///
/// A `--connect` client builds no kernel, so either flag beside it would do nothing, and is
/// refused rather than ignored.
fn take_bayes(
    args: &mut Vec<String>,
    cwd: Option<&std::path::Path>,
    home: Option<&std::path::Path>,
) -> Result<(Option<std::path::PathBuf>, Vec<String>), String> {
    let state = take_dir_flag(args, "--bayes-state", "bayes state directory", cwd, home)?;
    let mut models = Vec::new();
    let mut at = 0;
    while at < args.len() {
        let value = if args[at] == "--bayes-model" {
            args.remove(at);
            if at >= args.len() {
                return Err("--bayes-model needs <name>".to_string());
            }
            args.remove(at)
        } else if let Some(value) = args[at].strip_prefix("--bayes-model=") {
            let value = value.to_string();
            args.remove(at);
            value
        } else {
            at += 1;
            continue;
        };
        if value.is_empty() || value.starts_with('-') {
            return Err(format!(
                "--bayes-model needs <name>, and was given `{value}`"
            ));
        }
        models.push(value);
    }
    if (state.is_some() || !models.is_empty()) && args.iter().any(|arg| arg == "--connect") {
        return Err(
            "--bayes-state and --bayes-model bind the spam filter in a kernel this process \
             BUILDS; a --connect client resolves on another kernel: drop one of the two"
                .to_string(),
        );
    }
    Ok((state, models))
}

/// Take every `--config-home <dir>` (or `--config-home=<dir>`) out of `args` and return the
/// directory, ABSOLUTE (ledger #919): a relative `<dir>` is joined to `cwd`, and a leading
/// `~/` is expanded from `home`, because a config home that moves with the working directory
/// is the thing `config_home` exists to refuse (gonk's flag takes the path as typed; this one
/// does not, ledger #918). Given twice with two different directories is refused — a process
/// has one config home — and the same directory twice is one.
///
/// Like [`version_requested`], the scan is by exact token and does not know which flags take a
/// value, so `--config-home` as the literal VALUE of another flag reads as this flag. That
/// is the price of applying it before any mode is parsed, which every mode needs.
fn take_config_home(
    args: &mut Vec<String>,
    cwd: Option<&std::path::Path>,
    home: Option<&std::path::Path>,
) -> Result<Option<std::path::PathBuf>, String> {
    take_dir_flag(args, "--config-home", "config home", cwd, home)
}

/// Take every `--files <dir>` (or `--files=<dir>`) out of `args`: the root the local file
/// module is jailed to (`urn:file:*`), ABSOLUTE by [`take_config_home`]'s rules, in every mode
/// (ledger #1285). It wins over the config home's `files` key, which wins over the
/// `IKIGAI_FILES` variable, kept as the last fallback before `~/.ikigai/workspace` (see
/// `ikigai_embedded::file_root`). Configuration arrives by flag or config home; the variable
/// was the one channel a layer door's unit still needed an environment for.
///
/// A `--connect` client builds no kernel and has no file root of its own, so the flag beside
/// it would do nothing, and is refused rather than ignored.
fn take_files(
    args: &mut Vec<String>,
    cwd: Option<&std::path::Path>,
    home: Option<&std::path::Path>,
) -> Result<Option<std::path::PathBuf>, String> {
    let dir = take_dir_flag(args, "--files", "file root", cwd, home)?;
    if dir.is_some() && args.iter().any(|arg| arg == "--connect") {
        return Err(
            "--files names the file root of a kernel this process BUILDS; a --connect client \
             resolves on another kernel, whose root is its own: drop one of the two"
                .to_string(),
        );
    }
    Ok(dir)
}

/// Take every `<flag> <dir>` (or `<flag>=<dir>`) out of `args` and return the directory,
/// absolute. `what` names the one thing the directory is, for the refusal of two of them.
fn take_dir_flag(
    args: &mut Vec<String>,
    flag: &str,
    what: &str,
    cwd: Option<&std::path::Path>,
    home: Option<&std::path::Path>,
) -> Result<Option<std::path::PathBuf>, String> {
    let assigned = format!("{flag}=");
    let mut found: Option<std::path::PathBuf> = None;
    let mut at = 0;
    while at < args.len() {
        let value = if args[at] == flag {
            args.remove(at);
            if at >= args.len() {
                return Err(format!("{flag} needs <dir>"));
            }
            args.remove(at)
        } else if let Some(value) = args[at].strip_prefix(assigned.as_str()) {
            let value = value.to_string();
            args.remove(at);
            value
        } else {
            at += 1;
            continue;
        };
        if value.is_empty() || value.starts_with('-') {
            return Err(format!("{flag} needs <dir>, and was given `{value}`"));
        }
        // The workspace's one `~` rule, shared with every config-home key that names a path.
        let typed = ikigai_resolve::expand_home(&value, home).map_err(|e| format!("{flag} {e}"))?;
        let absolute: std::path::PathBuf = if typed.is_absolute() {
            typed
        } else {
            cwd.ok_or_else(|| {
                format!("{flag} `{value}` is relative and the working directory is unknown")
            })?
            .join(typed)
        }
        .components()
        .filter(|part| !matches!(part, std::path::Component::CurDir))
        .collect();
        match &found {
            Some(prior) if *prior != absolute => {
                return Err(format!(
                    "{flag} was given twice, as `{}` and `{}`; a process has one {what}",
                    prior.display(),
                    absolute.display()
                ))
            }
            _ => found = Some(absolute),
        }
    }
    Ok(found)
}

/// Put a `--config-home` in force for this process: both spellings of the config home read
/// it (the host's, and the engine's twin that `config` and the TUI's keybindings use).
fn apply_config_home(dir: std::path::PathBuf) -> Result<(), String> {
    #[cfg(feature = "embedded")]
    ikigai_embedded::config::set_config_home(dir.clone())
        .map_err(|e| format!("--config-home: {e}"))?;
    ikigai_engine::config::set_config_home(dir).map_err(|e| format!("--config-home: {e}"))
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
        return Ok(Some(Mode::Version {
            verbose: args.iter().any(|arg| arg == "--verbose"),
        }));
    }
    let mut argv = args.into_iter().peekable();

    if argv.peek().map(String::as_str) == Some("layers-token") {
        argv.next();
        let usage = "usage: `ikigai layers-token mint <participant|fingerprint> [--label <l>]` | \
                     `ikigai layers-token list` | `ikigai layers-token revoke <id>`";
        let command = match argv.next().as_deref() {
            Some("mint") => {
                let mut client = None;
                let mut label = None;
                while let Some(arg) = argv.next() {
                    match arg.as_str() {
                        "--label" => {
                            label = Some(
                                argv.next()
                                    .ok_or_else(|| "--label needs a value".to_string())?,
                            )
                        }
                        other if other.starts_with('-') => {
                            return Err(format!(
                                "unknown argument after `layers-token mint`: {other}"
                            ))
                        }
                        _ if client.is_none() => client = Some(arg),
                        other => {
                            return Err(format!(
                                "unexpected argument after `layers-token mint`: {other}"
                            ))
                        }
                    }
                }
                TokenCommand::Mint {
                    client: client.ok_or_else(|| usage.to_string())?,
                    label,
                }
            }
            Some("list") => match argv.next() {
                None => TokenCommand::List,
                Some(other) => {
                    return Err(format!(
                        "unexpected argument after `layers-token list`: {other}"
                    ))
                }
            },
            Some("revoke") => match (argv.next(), argv.next()) {
                (Some(id), None) => TokenCommand::Revoke { id },
                _ => return Err(usage.to_string()),
            },
            _ => return Err(usage.to_string()),
        };
        return Ok(Some(Mode::LayersToken(command)));
    }

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
        let mut push = false;
        let mut announce = false;
        let mut mounts = Mounts::default();
        let mut passkey_rp_id: Option<String> = None;
        let mut passkey_origin: Option<String> = None;
        let mut layers_state: Option<std::path::PathBuf> = None;
        let mut layers_key: Option<std::path::PathBuf> = None;
        let mut layers_reseal = false;
        let mut layers_https: Option<String> = None;
        let mut require_enrollment = false;
        while let Some(arg) = argv.next() {
            if arg == "--require-enrollment" {
                require_enrollment = true;
                continue;
            }
            if arg == "--layers-https" {
                let addr = argv.next().ok_or_else(|| {
                    "--layers-https needs an address (host:port; port 0 takes a free one)"
                        .to_string()
                })?;
                if layers_https.is_some() {
                    return Err("--layers-https given twice; a door has one front".to_string());
                }
                layers_https = Some(addr);
                continue;
            }
            if arg == "--layers-reseal" {
                layers_reseal = true;
                continue;
            }
            if arg == "--layers-key" {
                let file = argv.next().ok_or_else(|| {
                    "--layers-key needs a file (an age identity, as `age-keygen -o` writes one)"
                        .to_string()
                })?;
                if layers_key.is_some() {
                    return Err(
                        "--layers-key given twice; a layer host seals its state with one key \
                         file (it may hold several identities, the current one first)"
                            .to_string(),
                    );
                }
                // Absolute now, as `--layers-state` is: the key is read at open, against the
                // directory it was typed in.
                let file = std::path::PathBuf::from(file);
                layers_key = Some(if file.is_absolute() {
                    file
                } else {
                    std::env::current_dir()
                        .map_err(|e| format!("--layers-key: no working directory ({e})"))?
                        .join(file)
                });
                continue;
            }
            if arg == "--layers-state" {
                let dir = argv
                    .next()
                    .ok_or_else(|| "--layers-state needs a directory".to_string())?;
                if layers_state.is_some() {
                    return Err(
                        "--layers-state given twice; a door has one state directory".to_string()
                    );
                }
                // Absolute now, against the directory it was typed in: a state directory that
                // moved with the working directory would be a second host's.
                let dir = std::path::PathBuf::from(dir);
                layers_state = Some(if dir.is_absolute() {
                    dir
                } else {
                    std::env::current_dir()
                        .map_err(|e| format!("--layers-state: no working directory ({e})"))?
                        .join(dir)
                });
                continue;
            }
            if cert_flag(&arg, &mut argv, &mut certs)? {
                // A cert flag FOLLOWING a mount belongs to that mount (the REPL's rule),
                // so two peers with different identities never share a set. Flags before
                // any mount are this server's own identity.
                if let Some(mount) = mounts.flags.last_mut() {
                    mount.certs = certs.clone();
                }
                continue;
            }
            if scheduler_flag(&arg, &mut argv)?
                || width_routing_flag(&arg, &mut argv)?
                || arrangement_flag(&arg, &mut argv)?
            {
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
                let (prefix, target) = mount_spec(&arg, &spec)?;
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
            // The passkey relying party (see `ikigai_embedded::passkey::RelyingParty`). A flag,
            // not an environment variable: an env var leaks across every edge on a host, and a
            // forgotten one used to default silently to the production hostname.
            if arg == "--passkey-rp-id" {
                passkey_rp_id = Some(argv.next().ok_or_else(|| {
                    "--passkey-rp-id needs a domain (e.g. ikigai-rs.dev)".to_string()
                })?);
                continue;
            }
            if arg == "--passkey-origin" {
                passkey_origin = Some(argv.next().ok_or_else(|| {
                    "--passkey-origin needs an origin (e.g. https://ikigai-rs.dev)".to_string()
                })?);
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
            if arg == "--push" {
                push = true;
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
        // The passkey relying party, validated at startup so a typo is a refusal to start
        // rather than a page that fails at the first tap.
        match (passkey_rp_id, passkey_origin) {
            (Some(rp_id), origin) => {
                #[cfg(feature = "embedded")]
                ikigai_embedded::passkey::set_relying_party(
                    ikigai_embedded::passkey::RelyingParty::new(&rp_id, origin.as_deref())?,
                );
                #[cfg(not(feature = "embedded"))]
                let _ = (rp_id, origin);
            }
            (None, Some(_)) => {
                return Err("--passkey-origin needs --passkey-rp-id beside it".to_string());
            }
            (None, None) => {}
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
            max_body,
            push,
            announce,
            mounts,
            layers_state,
            layers_key,
            layers_reseal,
            layers_https,
            require_enrollment,
        }));
    }

    if argv.peek().map(String::as_str) == Some("mcp") {
        argv.next();
        let mut grants = Vec::new();
        let mut scopes = Vec::new();
        let mut principal = None;
        let mut root = false;
        let mut grants_file = None;
        let mut shows = Vec::new();
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
                let (prefix, target) = mount_spec(&arg, &spec)?;
                mounts.flags.push(Mount {
                    prefix: prefix.to_string(),
                    target: target.to_string(),
                    certs: certs.clone(),
                    kind,
                });
                continue;
            }
            if scheduler_flag(&arg, &mut argv)?
                || width_routing_flag(&arg, &mut argv)?
                || arrangement_flag(&arg, &mut argv)?
            {
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
                "--principal" => {
                    principal = Some(argv.next().ok_or_else(|| {
                        "--principal needs an agent IRI (an entry of the grants file's \
                         `principals` table)"
                            .to_string()
                    })?)
                }
                "--root" => root = true,
                "--grants" => {
                    grants_file = Some(std::path::PathBuf::from(
                        argv.next()
                            .ok_or_else(|| "--grants needs a file".to_string())?,
                    ))
                }
                "--show" => shows.push(argv.next().ok_or_else(|| {
                    "--show needs a pattern (a tool name, `repo-*`, or an IRI prefix such as \
                     `urn:layer:`)"
                        .to_string()
                })?),
                other => return Err(format!("unknown argument after `mcp`: {other}")),
            }
        }
        // Both postures at once is a startup error, not a precedence rule (see `Mounts`).
        mounts.refuse_conflict()?;
        if root && (!grants.is_empty() || !scopes.is_empty() || principal.is_some()) {
            return Err(
                "`mcp --root` serves UNRESTRICTED and cannot be combined with --grant, --scope \
                 or --principal, which bound the session; pass one or the other"
                    .to_string(),
            );
        }
        return Ok(Some(Mode::Mcp {
            grants,
            scopes,
            principal,
            root,
            grants_file,
            shows,
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
        if scheduler_flag(&arg, &mut argv)?
            || width_routing_flag(&arg, &mut argv)?
            || arrangement_flag(&arg, &mut argv)?
        {
            continue;
        }
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--plain" => repl.plain = true,
            "--quiet" => repl.quiet = true,
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
                let (prefix, socket) = mount_spec("--mount", &spec)?;
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
                let (prefix, target) = mount_spec("--override", &spec)?;
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
            #[cfg(feature = "embedded")]
            "layers" => {
                // Everything after it is the subcommand's; connection flags come before it.
                repl.layers = Some(layer::parse(argv.by_ref())?);
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
                let (prefix, target) = mount_spec("--prefer", &spec)?;
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
    #[cfg(feature = "embedded")]
    if repl.layers.is_some() && (daemon || repl.react || !repl.commands.is_empty()) {
        return Err(
            "`layers` runs one command and exits: drop -c/-e/--load, --daemon and --react"
                .to_string(),
        );
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
            println!("{USAGE}\n\n{}", build_transports());
            return;
        }
        Err(e) => {
            eprintln!("ikigai: {e}\n\n{USAGE}\n\n{}", build_transports());
            std::process::exit(2);
        }
    };

    // ikigai-lisp's bounds, from the config home's `lisp.*` keys, fixed once and before
    // anything can evaluate (ledger #920). A bad line stops every mode here rather than
    // reading as the default; `--version` alone answers whatever the config says.
    if !matches!(mode, Mode::Version { .. }) {
        if let Err(e) = ikigai_embedded::lisp::configure() {
            eprintln!("ikigai: {e}");
            std::process::exit(2);
        }
    }

    // The default instance name follows the mode; an explicit --name (already
    // set during parsing) wins because set_instance_name is first-write-wins.
    #[cfg(feature = "embedded")]
    ikigai_embedded::set_instance_name(match &mode {
        Mode::Daemon { .. } => "daemon",
        Mode::Serve { .. } => "serve",
        Mode::Mcp { .. } => "mcp",
        _ => "repl",
    });

    // Before any mount is resolved: a door's mounts describe under the INNER deadline.
    if matches!(mode, Mode::Serve { .. }) {
        SERVES_A_DOOR.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    match mode {
        // One line, stdout, exit 0. Nothing is built, nothing is connected: the
        // question "which build am I on?" is asked precisely when the host is
        // suspect, so answering it must not depend on the host working.
        Mode::Version { verbose } => print_version(verbose),
        Mode::Daemon { mounts } => {
            arm_local_root();
            arm_bayes(true);
            daemon(mounts)
        }
        Mode::Mcp {
            grants,
            scopes,
            principal,
            root,
            grants_file,
            shows,
            mounts,
        } => {
            arm_local_root();
            arm_bayes(true);
            mcp(
                McpAuthority {
                    grants,
                    scopes,
                    principal,
                    root,
                    grants_file,
                },
                shows,
                mounts,
            )
        }
        Mode::CertGenerate { force, dir } => cert_generate(force, dir),
        Mode::CertAddClient {
            name,
            cert_dir,
            force,
        } => cert_add_client(&name, cert_dir, force),
        Mode::LayersToken(command) => layers_token(command),
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
            push,
            layers_state,
            layers_key,
            layers_reseal,
            layers_https,
            require_enrollment,
        } => match (http, target.as_deref()) {
            // Enrollment is the QUIC door's (it is the door that authenticates certificates), so
            // the flag on any other door would require nothing.
            (http, target)
                if require_enrollment && (http.is_some() || !target.is_some_and(is_quic)) =>
            {
                eprintln!(
                    "ikigai: --require-enrollment applies to `serve quic://…`, the door that \
                     enrolls client certificates"
                );
                std::process::exit(2);
            }
            // Layers are hosted by the QUIC door only: it is the door that names each
            // participant from its certificate, and a layer refuses a write that names nobody.
            // A state directory for a door that hosts nothing is a flag that does nothing.
            (http, target)
                if (layers_state.is_some()
                    || layers_key.is_some()
                    || layers_reseal
                    || layers_https.is_some())
                    && (http.is_some() || !target.is_some_and(is_quic)) =>
            {
                eprintln!(
                    "ikigai: --layers-state, --layers-key, --layers-reseal and --layers-https \
                     apply to `serve quic://…`, the door that hosts layers"
                );
                std::process::exit(2);
            }
            // The inbound HTTP face takes precedence over IPC/QUIC when `--http` is given.
            (Some(bind), _) => {
                refuse_arrangement_flag("the HTTP door (`serve --http`), a served posture,");
                refuse_bayes_flags("the HTTP door (`serve --http`), a served posture,");
                serve_http(HttpDoor {
                    bind: &bind,
                    caps: &caps,
                    trust_proxy,
                    cors_origins: &cors_origins,
                    routes: routes.as_deref(),
                    routes_only,
                    max_body,
                    push,
                    mounts,
                })
            }
            (None, Some(t)) if is_quic(t) => {
                refuse_arrangement_flag("a QUIC door (`serve quic://…`), a served posture,");
                refuse_bayes_flags("a QUIC door (`serve quic://…`), a served posture,");
                serve_quic(
                    t,
                    &certs,
                    &caps,
                    announce,
                    mounts,
                    QuicDoorFlags {
                        layers_state,
                        layers_key,
                        layers_reseal,
                        layers_https,
                        require_enrollment,
                    },
                )
            }
            (None, _) if !caps.is_empty() => {
                eprintln!("ikigai: --cap sets a per-connection ceiling and needs a quic:// target");
                std::process::exit(2);
            }
            // The trusted IPC surface IS the local root (`trusted_kernel_with_mounts`), so a
            // declaration arranges it exactly as it arranges the REPL's.
            (None, _) => {
                arm_local_root();
                arm_bayes(true);
                serve_ipc(target, mounts)
            }
        },
        Mode::Repl(args) => {
            // `--demo` seeds the runtime demo flag; `demo on`/`off` (→ urn:host:demo)
            // toggles it thereafter. The runbook is gated on it, off by default.
            if args.demo {
                ikigai_embedded::demo_flag().store(true, std::sync::atomic::Ordering::SeqCst);
            }
            // `layers post|save` (ledger #1629): everything local first (a bad name, an
            // unreadable file, the entry composed), so a usage problem is refused before
            // anything is dialed; then the same engine a `-c` batch gets, and one command.
            let layers = match args.layers.clone().map(layer::prepare) {
                None => None,
                Some(Ok(layer::Prepared::Help)) => {
                    println!("{}", layer::USAGE);
                    return;
                }
                Some(Ok(prepared)) => Some(prepared),
                Some(Err(e)) => {
                    eprintln!("ikigai: {e}");
                    std::process::exit(layer::EXIT_USAGE);
                }
            };
            if args.connect.is_some() {
                refuse_arrangement_flag("`--connect`, which resolves on another kernel,");
            } else {
                arm_local_root();
                arm_bayes(!args.quiet && args.commands.is_empty() && layers.is_none());
            }
            let (engine, topology) =
                build_engine(args.connect, args.mounts, &args.certs, args.react).unwrap_or_else(
                    |e| {
                        eprintln!("ikigai: {e}");
                        std::process::exit(1);
                    },
                );
            if let Some(prepared) = layers {
                std::process::exit(layer::run(&engine, prepared));
            }
            run_repl(engine, args.plain, args.quiet, &args.commands, &topology);
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
                Ok(specs) => resolved.extend(specs),
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

/// What `ikigai mcp` was told its session may do: the flags that name its authority.
#[derive(Clone, Debug, Default)]
struct McpAuthority {
    grants: Vec<String>,
    scopes: Vec<String>,
    principal: Option<String>,
    root: bool,
    grants_file: Option<std::path::PathBuf>,
}

/// The refusal for an `ikigai mcp` that names no authority (ledger #1830). It used to serve
/// root; an agent's tool server that is root because nobody said otherwise is the default the
/// principal model removes.
#[cfg(feature = "embedded")]
const MCP_NO_AUTHORITY: &str = "no authority was named. Pass --grant <name> (a grant in \
     grants.json), --scope <capability IRI>, --principal <agent IRI> (an agent in grants.json's \
     `principals` table, checked against its person's grant), or --root to serve UNRESTRICTED";

/// An MCP session's authority, as resolved: the capability, the grant names whose `show`/`hide`
/// profiles shape its tool list, and the agent session when there is one.
#[cfg(feature = "embedded")]
struct McpSession {
    capability: ikigai_core::Capability,
    grants: Vec<String>,
    agent: Option<ikigai_embedded::agents::AgentSession>,
}

/// Resolve `authority` into the session it serves, or refuse with the reason.
///
/// - `--root`: root, by request.
/// - `--principal`: the agent session ([`ikigai_embedded::agents::agent_session`]) from a
///   grants file its user cannot write ([`ikigai_embedded::agents::check_protected`]).
/// - `--grant`/`--scope`: their union ([`mcp_capability`]).
/// - none of them: refused ([`MCP_NO_AUTHORITY`]).
#[cfg(feature = "embedded")]
fn mcp_session(authority: &McpAuthority) -> Result<McpSession, String> {
    if authority.root {
        return Ok(McpSession {
            capability: ikigai_core::Capability::root(),
            grants: Vec::new(),
            agent: None,
        });
    }
    if let Some(principal) = &authority.principal {
        let path = ikigai_embedded::grants_path()
            .ok_or_else(|| "no grants file: pass --grants <file>".to_string())?;
        ikigai_embedded::agents::check_protected(&path)?;
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let agent = ikigai_embedded::agents::agent_session(
            &text,
            principal,
            &authority.grants,
            &authority.scopes,
        )
        .map_err(|e| format!("{}: {e}", path.display()))?;
        return Ok(McpSession {
            capability: agent.capability.clone(),
            grants: agent.grants.clone(),
            agent: Some(agent),
        });
    }
    if authority.grants.is_empty() && authority.scopes.is_empty() {
        return Err(MCP_NO_AUTHORITY.to_string());
    }
    Ok(McpSession {
        capability: mcp_capability(&authority.grants, &authority.scopes)?,
        grants: authority.grants.clone(),
        agent: None,
    })
}

/// The capability a live reload may move a session to: `fresh` within `baseline`, the
/// authority the session STARTED with (ledger #1830). A reload narrows, and can restore what
/// an earlier reload narrowed, but never widens past the start, so an agent that can write the
/// grants file cannot widen a running session through it. Returns the capability and the
/// scopes `fresh` asked for that only a restart would grant.
#[cfg(feature = "embedded")]
fn mcp_reloaded(
    baseline: &ikigai_core::Capability,
    fresh: &ikigai_core::Capability,
) -> (ikigai_core::Capability, Vec<String>) {
    let Some(asked) = fresh.scopes() else {
        // A root reload (never produced: root sessions do not reload) keeps the baseline.
        return (baseline.clone(), Vec::new());
    };
    let kept = baseline.attenuate(asked.iter().cloned());
    let held = kept.scopes().cloned().unwrap_or_default();
    let waiting = asked
        .iter()
        .filter(|scope| !held.contains(*scope))
        .cloned()
        .collect();
    (kept, waiting)
}

/// Build the session capability from the union of named grants + explicit
/// scopes. The grant is the ceiling.
///
/// Called only with at least one `--grant` or `--scope` ([`mcp_session`] refuses neither). A
/// named grant that resolves to no scopes (misspelled, deleted, empty, or `grants.json` missing
/// or unparseable) is an `Err` naming it: an unknown grant is "undecided", never
/// "unrestricted", the same rule the served door's per-identity grants follow
/// (`clients::authority`).
#[cfg(feature = "embedded")]
fn mcp_capability(grants: &[String], scopes: &[String]) -> Result<ikigai_core::Capability, String> {
    mcp_capability_in(grants, scopes, ikigai_embedded::grant_scopes)
}

/// [`mcp_capability`] over an explicit grant lookup, so the policy is testable without
/// a grants file.
#[cfg(feature = "embedded")]
fn mcp_capability_in(
    grants: &[String],
    scopes: &[String],
    scopes_of: impl Fn(&str) -> Vec<String>,
) -> Result<ikigai_core::Capability, String> {
    if grants.is_empty() && scopes.is_empty() {
        return Err(MCP_NO_AUTHORITY.to_string());
    }
    let mut union: Vec<String> = scopes.to_vec();
    let mut undecided = Vec::new();
    for name in grants {
        let granted = scopes_of(name);
        if granted.is_empty() {
            undecided.push(format!("`{name}`"));
        }
        union.extend(granted);
    }
    if !undecided.is_empty() {
        return Err(format!(
            "grant {} is unknown or grants no scopes (check {})",
            undecided.join(", "),
            ikigai_embedded::grants_path()
                .map_or_else(|| "grants.json".to_string(), |p| p.display().to_string())
        ));
    }
    union.sort();
    union.dedup();
    Ok(ikigai_core::Capability::scoped(union))
}

/// Build the tool-visibility filter from the named grants — the union of their
/// `show`/`hide` globs — and the `--show` patterns. Distinct from [`mcp_capability`]:
/// authority decides what the session may call; this decides what the projected tool
/// list bothers to show. Empty ⇒ allow-all. `--scope` unions carry authority only, no
/// visibility; `--show` carries visibility only, no authority.
#[cfg(feature = "embedded")]
fn mcp_filter(grants: &[String], shows: &[String]) -> ikigai_mcp::ToolFilter {
    let mut filter = ikigai_mcp::ToolFilter {
        show: shows.to_vec(),
        hide: Vec::new(),
    };
    for name in grants {
        let (show, hide) = ikigai_embedded::grant_visibility(name);
        filter.show.extend(show);
        filter.hide.extend(hide);
    }
    filter
}

/// MCP stdio mode: project the composed manifold as MCP tools, scoped to the
/// session capability built from `--grant`/`--scope`/`--principal` (the ceiling), or root
/// under an explicit `--root`; with none of them it refuses to start (ledger #1830).
///
/// A poller watches the grants file; when the session's grants change it rebuilds the
/// capability and emits `notifications/tools/list_changed`, so a connected client's tool list
/// morphs live. A reload NARROWS live (and can restore what an earlier one narrowed), but never
/// widens past the authority the session started with: a widening is applied at the next
/// start ([`mcp_reloaded`]), so an agent that can write the grants file cannot widen a running
/// session through it. An agent session (`--principal`) additionally reads only a grants file
/// its user cannot write at all.
#[cfg(feature = "embedded")]
fn mcp(authority: McpAuthority, shows: Vec<String>, mounts: Mounts) {
    use ikigai_mcp::server::serve_concurrent;
    use std::io::Write;
    use std::sync::{Arc, Mutex, RwLock};

    if let Some(path) = &authority.grants_file {
        ikigai_embedded::set_grants_path(path.clone());
    }
    // An unnamed authority, a grant that names nothing, or an agent outside its person's
    // grant refuses to start: running would be root (the old fail-open) or a session with an
    // authority the operator did not ask for.
    let session = match mcp_session(&authority) {
        Ok(session) => session,
        Err(e) => {
            eprintln!("ikigai mcp: refusing to start: {e}");
            std::process::exit(2);
        }
    };
    let baseline = session.capability.clone();
    let grants = session.grants.clone();
    let capability = Arc::new(RwLock::new(session.capability));
    let filter = Arc::new(RwLock::new(mcp_filter(&grants, &shows)));
    match (
        &session.agent,
        capability.read().expect("cap lock").scopes(),
    ) {
        (_, None) => eprintln!("ikigai mcp: --root given — serving UNRESTRICTED (root)"),
        (Some(agent), Some(s)) => eprintln!(
            "ikigai mcp: serving as {} (acting for {}) under {} scope(s)",
            agent.principal,
            agent.person,
            s.len()
        ),
        (None, Some(s)) => eprintln!(
            "ikigai mcp: serving the manifold under {} scope(s)",
            s.len()
        ),
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
        authority: Some(
            match (
                &session.agent,
                capability.read().expect("cap lock").scopes(),
            ) {
                (_, None) => "root — --root was given (UNRESTRICTED)".to_string(),
                (Some(agent), Some(s)) => format!(
                    "{} scope(s), as {} acting for {}",
                    s.len(),
                    agent.principal,
                    agent.person
                ),
                (None, Some(s)) => format!("{} scope(s) from --grant/--scope", s.len()),
            },
        ),
        // The grants poller rebuilds the session capability when the file changes and emits
        // `tools/list_changed`, so the ceiling above is a startup READING of something this
        // door re-reads — exactly the over-claim `reloads` exists to prevent.
        reloads: vec![
            "grants.json — the active grant's scopes are re-read while running: a narrowing \
             rebuilds the projected tool list live, a widening waits for the next start"
                .to_string(),
        ],
    });
    let kernel = if mounts.is_empty() {
        ikigai_embedded::watched_kernel()
    } else {
        let mut resolved = Vec::new();
        for mount in mounts {
            match resolve_mount(mount) {
                Ok(specs) => resolved.extend(specs),
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
    // when a named grant or an agent is in play; explicit --scope unions are fixed at launch.
    if !grants.is_empty() || session.agent.is_some() {
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
                    // Fail CLOSED mid-session: a grant that stops resolving (deleted,
                    // renamed, or the file left unparseable) drops the session to NO
                    // authority until the file names it again. Keeping the last good grant
                    // instead would make deleting a grant a revocation that does not revoke.
                    let fresh_cap = match mcp_session(&authority) {
                        Ok(fresh) => {
                            let (kept, waiting) = mcp_reloaded(&baseline, &fresh.capability);
                            if !waiting.is_empty() {
                                eprintln!(
                                    "ikigai mcp: the grant now adds {} — a widening takes \
                                     effect at the next start, never in a running session",
                                    waiting.join(", ")
                                );
                            }
                            kept
                        }
                        Err(e) => {
                            eprintln!(
                                "ikigai mcp: {e} — the session now holds NO authority until \
                                 the grant resolves again"
                            );
                            ikigai_core::Capability::scoped(Vec::<String>::new())
                        }
                    };
                    let fresh_filter = mcp_filter(&grants, &shows);
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

    // The library's session loop (ledger #1695): each `tools/call` on its own thread, up to
    // `MAX_CONCURRENT_CALLS`, answered as it finishes, so a long poll holds no other tool
    // up; everything else answered in order on this thread. Raw bytes, not `lines()`: a
    // line that is not UTF-8 is a JSON-RPC Parse error to ANSWER, where `lines()` would end
    // the whole session on it (ledger #1309). The grant and filter are read per LINE, so
    // the poller's swap applies from the next message, exactly as before; a call keeps the
    // grant it was read under. Responses share the poller's stdout lock, one whole line each.
    let session = || {
        (
            capability.read().expect("cap lock").clone(),
            filter.read().expect("filter lock").clone(),
        )
    };
    if let Err(e) = serve_concurrent(
        &kernel,
        session,
        std::io::stdin().lock(),
        &stdout,
        ikigai_mcp::server::MAX_CONCURRENT_CALLS,
    ) {
        eprintln!("ikigai mcp: the session ended: {e}");
    }
}

#[cfg(not(feature = "embedded"))]
fn mcp(_authority: McpAuthority, _shows: Vec<String>, _mounts: Mounts) {
    eprintln!("ikigai: mcp requires the embedded feature");
    std::process::exit(2);
}

/// Register the demo capability profiles on an engine (so `cap freebusy` reads
/// friendlier than a scope list), and give `show` its file viewer. Applied to every backend — embedded and, over
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
    // `show <iri>`: a terminal cannot draw SVG, so the picture goes to a file and the
    // config home's `show.opener` (the platform's own by default). Every backend gets it —
    // over `--connect` the picture is fetched remotely and shown HERE.
    #[cfg(not(target_family = "wasm"))]
    let engine = engine.with_viewer(std::sync::Arc::new(show::FileViewer));
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
                    resolved.extend(resolve_mount(mount)?);
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
                        .with_width_routing(ikigai_embedded::width_routing())
                        // `as-of=<instant>`: this host's time doors, pinned per line (ledger
                        // #532). Only the in-process kernel gets them — a `--connect` engine
                        // has none and refuses `as-of=` rather than answering live.
                        .with_as_of_doors(ikigai_embedded::time_doors())
                        // This process IS the kernel answering, so its build is the one an
                        // unresolved name may predate (ledger #288). A `--connect` client
                        // names none: the host it attaches to is another build.
                        .with_host_build(VERSION_LINE, upgrade_command()),
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
    resolve_mounts(mounts, &home_dir(), config_mounts)
}

/// [`mounts_or_config`] with the config home's topology as a THUNK, so a test can assert what
/// the flag actually promises — that declining does not READ the file — instead of only that
/// the result came back empty, which an absent or unreadable config home produces too.
///
/// A mount FLAG's target takes the workspace's one `~` rule here, as a `mount` line's does in
/// [`mounts_from_config_lines`] (ledger #1381): no shell expands a `~` after `=`, so `--mount
/// 'urn:x:=~/x.sock'` reaches this process as written. Expanding it HERE, in the one function
/// every kernel-building door calls, means the self-mount guard, the banner and the dial all
/// see the same path; before, the guard expanded it and the dial did not. `home` is read once
/// by the caller, like the config lines' (see [`home_dir`]).
fn resolve_mounts(
    mounts: Mounts,
    home: &std::path::Path,
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
        mounts
            .flags
            .into_iter()
            .map(|mut mount| {
                mount.target =
                    ikigai_resolve::expand_home_str(&mount.target, Some(home)).map_err(|e| {
                        format!(
                            "{} `{}={}`: {e}",
                            mount_flag(mount.kind),
                            mount.prefix,
                            mount.target
                        )
                    })?;
                Ok(mount)
            })
            .collect()
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
    mounts_from_config_lines(ikigai_embedded::config::all("mount"), &home_dir())
}

/// [`config_mounts`] over lines already read and a home already resolved, so the line
/// grammar is testable without a config home OR a `$HOME`: the environment is
/// process-global, and both mutating it and reading it race the test harness.
fn mounts_from_config_lines(
    lines: Vec<String>,
    home: &std::path::Path,
) -> Result<Vec<Mount>, String> {
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
            let (prefix, target) = mount_spec(&format!("mount `{line}`"), spec)?;
            // A socket path and a certificate directory both take the workspace's one `~`
            // rule (ledger #1379); a `quic://` or `peer:` target never begins with `~`, so it
            // passes through unchanged.
            let expand = |value: &str| {
                ikigai_resolve::expand_home_str(value, Some(home))
                    .map_err(|e| format!("mount `{line}`: {e}"))
            };
            let target = expand(target)?;
            let mut certs = Certs::default();
            if let Some(dir) = parts.next() {
                certs.cert_dir = Some(expand(dir)?);
            }
            Ok(Mount {
                prefix: prefix.to_string(),
                target,
                certs,
                kind,
            })
        })
        .collect()
}

/// `$HOME`, read once at the top of a call chain and passed down: the environment is
/// process-global, and a test elsewhere in this binary redirects `HOME` to a scratch dir
/// under its own lock, so a helper that read it deeper down would race that test (and did:
/// `tilde_spelling_matches_the_expanded_socket` failed once on a branch that touched
/// neither). An unset `HOME` is the EMPTY path, which [`ikigai_resolve::expand_home`] treats
/// as no home: a leading `~` is then refused by name rather than expanded to a relative path,
/// as it was before ledger #1379.
#[cfg(feature = "embedded")]
fn home_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
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
///
/// One spec PER PREFIX, every one holding the SAME resolver: a mount that names several
/// prefixes ([`mount_prefixes`]) is one connection serving all of them, not one per prefix.
fn resolve_mount(mount: Mount) -> Result<Vec<ikigai_embedded::MountSpec>, String> {
    let Mount {
        prefix,
        target,
        certs,
        kind,
    } = mount;
    let prefixes = mount_prefixes(&prefix)?;
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
    Ok(prefixes
        .into_iter()
        .map(|prefix| ikigai_embedded::MountSpec {
            prefix: prefix.to_string(),
            origin: target.clone(),
            resolver: std::sync::Arc::clone(&resolver),
            kind,
        })
        .collect())
}

/// [`resolve_mount`] for a mount that names ONE prefix, the tests' common case.
#[cfg(test)]
fn resolve_one_mount(mount: Mount) -> Result<ikigai_embedded::MountSpec, String> {
    let mut specs = resolve_mount(mount)?;
    assert_eq!(specs.len(), 1, "one prefix, one spec");
    Ok(specs.remove(0))
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

    /// Forwarded, or the run is lost here (ledger #1942): the trait's default DROPS the
    /// context and resolves as `issue_as`, so a `--prefer` peer was sent a plain `IssueAs`
    /// and never saw the deadline of the run the door minted for a v9 client.
    fn issue_as_in_run(
        &self,
        request: ikigai_core::Request,
        capability: &ikigai_core::Capability,
        run: &ikigai_resolve::RunContext,
    ) -> Result<(ikigai_core::Representation, ikigai_resolve::CacheStatus), ikigai_core::Error>
    {
        self.get()?.issue_as_in_run(request, capability, run)
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
/// gets a refusal that says how to enroll it, rather than a connection.
///
/// That convention is also why this is ergonomic: the name determines both the address (by
/// announcement) and the identity (by directory), so `--prefer urn:llm:=peer:plasma` needs
/// no address and no `--cert-dir`.
#[cfg(all(feature = "embedded", feature = "quic"))]
fn resolve_peer(name: &str, certs: &Certs) -> Result<(String, Certs), String> {
    // Settled BEFORE the browse: a name that can name no certificate directory is refused
    // without making the operator wait out a discovery window first.
    let conventional = (certs.cert_dir.is_none() && certs.server_cert.is_none())
        .then(|| peer_cert_dir(name))
        .transpose()?;
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
    if let Some(dir) = conventional {
        if !dir.join("server.crt").exists() {
            return Err(format!(
                "peer:{name}: found it at {addr}, but this machine holds no pinned \
                 certificate for it ({}/server.crt). Discovery supplies an address, never \
                 trust — enroll the peer first (on {name}: `ikigai cert add-client <this \
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
/// Resolved through the SAME config home as [`quic::dir`](crate::quic) and through the same
/// spelling as `holds_cert_for`'s oracle in the embedded host
/// ([`ikigai_embedded::config::peer_cert_dir_in`]) — this used to hardcode
/// `$HOME/.config/ikigai` while `quic::dir` honoured `XDG_CONFIG_HOME`, so setting that
/// variable pointed the dialer at one directory and the certificate writer at another.
///
/// A name that is not one path segment is refused rather than joined (ledger #741): the
/// name is matched against what the LAN announced, and `plasma/../quic-plasma` must not
/// borrow plasma's pinned certificate directory.
#[cfg(all(feature = "embedded", feature = "quic"))]
fn peer_cert_dir(name: &str) -> Result<std::path::PathBuf, String> {
    let home = ikigai_embedded::config::config_home().unwrap_or_default();
    ikigai_embedded::config::peer_cert_dir_in(&home, name).ok_or_else(|| {
        format!(
            "peer:{name}: not a single path segment, so it names no certificate directory \
             (a peer name may not be empty, contain `/`, `\\`, `:` or NUL, or end in `.` or \
             a space)"
        )
    })
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
///
/// ★ **A process that SERVES a door gives its own mounts a SHORTER deadline** than the one
/// it is reached under ([`inner_describe_deadline`], ledger #1288). With one value at every
/// hop, a client asking a host about a silent peer hit ITS deadline first, because it started
/// first, and blamed the wrong process: "no response from the kernel server (it may be hung
/// or gone)" about a host that was healthy and waiting on its peer, and the race could cost
/// a second deadline. Inside the client's bound, the host's own deadline fires first and its
/// answer names the peer. The role, not the transport, decides: a gonk-shaped host is reached
/// over a socket and mounts over QUIC, an edge is reached over QUIC and may mount either.
#[cfg(feature = "embedded")]
fn describe_timeout(default: std::time::Duration) -> Option<std::time::Duration> {
    let outer = match ikigai_embedded::config::get("describe.timeout")
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(0) => return None,
        Some(secs) => std::time::Duration::from_secs(secs),
        None => default,
    };
    Some(if SERVES_A_DOOR.load(std::sync::atomic::Ordering::SeqCst) {
        inner_describe_deadline(outer)
    } else {
        outer
    })
}

/// Whether this process serves a door (`serve`, any of the three), set once in `main`
/// before any mount is resolved. What [`describe_timeout`] keys the inner deadline on.
#[cfg(feature = "embedded")]
static SERVES_A_DOOR: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The describe deadline a serving host gives its mounts, from the one its callers use:
/// two thirds of it (30 s becomes 20 s), so the host answers with the peer's name and a third
/// of the caller's bound to spare for the answer to travel back. A ratio rather than a fixed
/// margin so that a raised `describe.timeout`, read by host and client from one config home,
/// keeps the order. ⚠ Per hop, as the bound always was: three kernels deep, the middle and
/// the inner host both take two thirds of the same value. The real fix is a budget carried on
/// the wire and decremented per hop (the `ikigai_ipc::DEFAULT_DESCRIBE_TIMEOUT` note).
#[cfg(feature = "embedded")]
fn inner_describe_deadline(outer: std::time::Duration) -> std::time::Duration {
    outer * 2 / 3
}

/// The deadline a mounted peer's every OTHER call runs under, start to finish:
/// `call.timeout` (seconds) in the host config. `None` when the key is absent, which leaves
/// each transport's own default (its standing silence bound: `quic.timeout` for QUIC, the
/// socket timeout for IPC); `Some(None)` for `0`, which takes the bound off.
///
/// ★ Why it exists (ledger #1335): a peer that accepts a call and never answers it held the
/// caller until the connection's idle timeout, or for ever if the peer kept the connection
/// alive; an IPC peer trickling its reply was bounded by nothing. On expiry the transport
/// cancels the call on the wire and answers a typed `Timeout` naming the peer.
///
/// One key for both transports, for `describe.timeout`'s reason. Config home, not an
/// environment variable.
///
/// ★ **A process that SERVES a door gives its own mounts two thirds of a CONFIGURED value**
/// ([`inner_describe_deadline`]'s ratio and reason, ledger #1288): with `call.timeout` read
/// by host and client from one config home, the host's deadline fires first and its answer
/// names the silent peer, rather than the client's blaming the host. The UNSET default is
/// not shortened: there, every hop keeps the patience it always had, because an honest long
/// resolution (a 70B model's first token) is silent for its whole length and two thirds of
/// it would cut calls that used to succeed.
#[cfg(feature = "embedded")]
fn call_timeout() -> Option<Option<std::time::Duration>> {
    let outer = match ikigai_embedded::config::get("call.timeout")
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(0) => return Some(None),
        Some(secs) => std::time::Duration::from_secs(secs),
        None => return None,
    };
    Some(Some(
        if SERVES_A_DOOR.load(std::sync::atomic::Ordering::SeqCst) {
            inner_describe_deadline(outer)
        } else {
            outer
        },
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

/// How old a served QUIC connection may grow before the door closes it and the client's
/// next call reconnects, minted afresh (ledger #1179): `quic.max_connection_age` in the
/// config home, in seconds, default [`DEFAULT_MAX_CONNECTION_AGE`].
///
/// The door re-reads `clients.json` per CONNECTION, so this bound is what makes an edit a
/// revocation within a known time rather than "whenever the client next reconnects", which
/// for a standing mount may be never. An unusable value stops `serve` (a revocation bound
/// that silently became the default is a bound nobody chose).
#[cfg(all(feature = "embedded", feature = "quic"))]
fn quic_max_connection_age() -> Result<std::time::Duration, String> {
    match ikigai_embedded::config::get("quic.max_connection_age") {
        None => Ok(DEFAULT_MAX_CONNECTION_AGE),
        Some(raw) => match raw.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => Ok(std::time::Duration::from_secs(secs)),
            _ => Err(format!(
                "quic.max_connection_age = `{raw}` is not a positive number of seconds"
            )),
        },
    }
}

/// [`quic_max_connection_age`]'s default: ten minutes (design, ledger #1170 section 15).
#[cfg(all(feature = "embedded", feature = "quic"))]
const DEFAULT_MAX_CONNECTION_AGE: std::time::Duration = std::time::Duration::from_secs(600);

#[cfg(all(feature = "embedded", feature = "quic"))]
fn connect_mount_quic(
    target: &str,
    certs: &Certs,
    flag: &'static str,
) -> Result<std::sync::Arc<dyn ikigai_resolve::Resolver>, String> {
    let addr = quic::parse_addr(target)?;
    let identity = quic::client_identity(certs)?;
    let trusted = quic::trusted_server_cert(certs)?;
    let mut resolver = ikigai_quic::connect_with(addr, &identity, &trusted, quic_idle_timeout())
        .map_err(|e| format!("{flag}: connect {target}: {e}"))?
        .with_describe_timeout(describe_timeout(ikigai_quic::DEFAULT_DESCRIBE_TIMEOUT));
    if let Some(bound) = call_timeout() {
        resolver = resolver.with_call_timeout(bound);
    }
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

#[cfg(all(feature = "embedded", feature = "ipc", unix))]
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
    let mut resolver = ikigai_ipc::connect_as(std::path::Path::new(socket), mode)
        .map_err(|e| format!("{flag}: connect {socket}: {e}"))?
        .with_describe_timeout(describe_timeout(ikigai_ipc::DEFAULT_DESCRIBE_TIMEOUT));
    if let Some(bound) = call_timeout() {
        resolver = resolver.with_call_timeout(bound);
    }
    Ok(std::sync::Arc::new(resolver))
}

// `ikigai-ipc` is `#![cfg(unix)]` (empty elsewhere), so the `ipc` feature alone does not
// make the dial exist: a default Windows build has the feature and an empty crate.
#[cfg(all(feature = "embedded", not(all(feature = "ipc", unix))))]
fn connect_mount_ipc(
    _socket: &str,
    _kind: ikigai_embedded::MountKind,
    flag: &'static str,
) -> Result<std::sync::Arc<dyn ikigai_resolve::Resolver>, String> {
    Err(format!(
        "{flag} of a Unix socket needs the `ipc` feature on a Unix platform"
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
fn run_repl(engine: Engine, plain: bool, quiet: bool, commands: &[String], topology: &[String]) {
    // A picture answer is NAMED to a person at a terminal and written whole anywhere else
    // (ledger #983), so `ikigai -c 'source urn:diagram:kernel' > kernel.svg` keeps working.
    #[cfg(not(target_family = "wasm"))]
    {
        use std::io::IsTerminal;
        engine.set_picture_hint(std::io::stdout().is_terminal());
    }
    if !commands.is_empty() {
        // A batch fed on a NON-TTY stdin (`printf %s "$v" | ikigai -c 'sink urn:secret:x'`)
        // routes that stdin to the first content-less `sink` — so a secret is piped in, never
        // placed on the command line — or to the first `source` stage left with one REQUIRED
        // argument and no value for it (`cat q.rq | ikigai -c 'source …:graph-select graph=G'`,
        // ledger #1166), or to the first content-less `delete` whose contract declares
        // `content` (a claim's release note, ledger #1230). A TTY stdin is left alone (nothing
        // to read, no block).
        #[cfg(not(target_family = "wasm"))]
        {
            use std::io::IsTerminal;
            if !std::io::stdin().is_terminal() {
                // LAZILY. Reading stdin to EOF here blocks whenever stdin is a non-TTY that
                // never closes — an inherited pipe from an editor, a harness, launchd — so
                // `ikigai -c 'source …' > file` hung waiting for input no command wanted.
                // `is_terminal()` cannot tell "a pipe with data" from "a pipe nobody will
                // write to"; the only safe moment to block is when a content-less `sink`
                // has actually asked for the content.
                //
                // And even then, not forever (ledger #1088): an agent's backgrounded shell
                // hands a `sink urn:iki:ledger:close item=N` an inherited pipe nobody writes,
                // and the read waited on it for good. So the reader waits [`STDIN_GRACE`] for
                // the FIRST byte (or EOF); a stdin silent that long is idle, and the sink goes
                // without `content` rather than with an empty one.
                //
                // And the probe (ledger #1305): a `source` or `delete` fetches its target's
                // contract only to learn whether stdin should fill an argument, so a stdin
                // already at its end with nothing (`/dev/null`, as a harness or an agent's
                // shell hands it, or a closed empty pipe) is told apart WITHOUT reading it,
                // and no contract is fetched, or cached, for its sake.
                engine.set_piped_input_probed(
                    || read_stdin_unless_idle(STDIN_GRACE),
                    stdin_ended_empty,
                );
            }
        }
        std::process::exit(repl::run_commands(engine, commands));
    }
    #[cfg(not(target_family = "wasm"))]
    {
        use std::io::IsTerminal;
        if !plain && !quiet && std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            // The keybinding scheme is read before entering the alternate screen
            // so an unsupported-value notice is visible.
            if let Err(e) = tui::run(engine, ikigai_engine::config::keybindings(), topology) {
                eprintln!("ikigai: tui error: {e}");
                std::process::exit(1);
            }
            return;
        }
        std::process::exit(repl::run(engine, topology, quiet));
    }
    #[cfg(target_family = "wasm")]
    std::process::exit(repl::run(engine, topology, quiet));
}

/// How long a content-less `sink` waits for stdin's FIRST byte (or its end) before calling
/// it idle (ledger #1088). Data a producer has already written, a file, `/dev/null` and a
/// closed pipe all answer at once; only a descriptor nobody writes to waits the whole grace.
/// A producer slower than this to say anything (a long network fetch) loses the race: the
/// note on stderr says so, and a sink that requires `content` then refuses instead of
/// writing an empty body.
#[cfg(all(feature = "embedded", not(target_family = "wasm")))]
const STDIN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Read stdin to its end — unless nothing at all arrives within `grace`, which is `None`.
///
/// The read runs on a thread of its own because a blocking `read` cannot be given a
/// deadline portably. When stdin turns out idle that thread stays parked on it; a `-c`
/// batch ends in `process::exit`, which takes it down.
#[cfg(all(feature = "embedded", not(target_family = "wasm")))]
fn read_stdin_unless_idle(grace: std::time::Duration) -> Option<Vec<u8>> {
    use std::io::Read;
    let (started, first) = std::sync::mpsc::channel::<()>();
    let (finished, done) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = vec![0u8; 64 * 1024];
        let n = stdin.read(&mut buf).unwrap_or(0);
        buf.truncate(n);
        let _ = started.send(());
        if n > 0 {
            let _ = stdin.read_to_end(&mut buf);
        }
        let _ = finished.send(buf);
    });
    match first.recv_timeout(grace) {
        Ok(()) => done.recv().ok(),
        Err(_) => {
            eprintln!(
                "ikigai: nothing arrived on stdin within {}s, so the command that asked for it \
                 was sent without it (pipe the value in, or name it with content=…)",
                grace.as_secs()
            );
            None
        }
    }
}

/// Whether stdin is ALREADY at its end having offered nothing, answered without reading a
/// byte (ledger #1305): `/dev/null`, a regular file read to its end, a pipe or socket whose
/// writer closed with nothing left in it. `false` whenever that cannot be known: bytes are
/// waiting, a producer has not written yet, or the descriptor is of a kind this does not
/// recognize. A `false` costs only the contract fetch the batch made before the probe
/// existed, so every doubt resolves that way.
///
/// Why not read: a stage that turns out not to need stdin must leave it unread (a `-c` inside
/// a `while read` loop shares the loop's input), and an inherited pipe nobody writes would
/// cost the idle grace (ledger #1088) on every bare `source`.
#[cfg(all(feature = "embedded", unix))]
fn stdin_ended_empty() -> bool {
    use std::io::Seek;
    use std::os::fd::AsFd;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let stdin = std::io::stdin();
    // A duplicate of descriptor 0 to ask questions of: it shares the open file (and so the
    // offset), and dropping it closes only the duplicate.
    let Ok(fd) = stdin.as_fd().try_clone_to_owned() else {
        return false;
    };
    let mut file = std::fs::File::from(fd);
    let Ok(meta) = file.metadata() else {
        return false;
    };
    let kind = meta.file_type();
    if kind.is_file() {
        // Asking the offset does not move it.
        return file.stream_position().is_ok_and(|at| at >= meta.len());
    }
    if kind.is_char_device() {
        return std::fs::metadata("/dev/null").is_ok_and(|null| null.rdev() == meta.rdev());
    }
    if kind.is_fifo() || kind.is_socket() {
        use std::os::fd::AsRawFd;
        let raw = file.as_raw_fd();
        let mut poll = libc::pollfd {
            fd: raw,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid `pollfd` for a descriptor this function owns, a count of 1, and a
        // zero timeout: `poll` only writes `revents`, and returns at once.
        let ready = unsafe { libc::poll(&mut poll, 1, 0) };
        if ready != 1 || poll.revents & (libc::POLLIN | libc::POLLHUP) == 0 {
            return false; // nothing yet: a slow producer, or an idle pipe. Not known empty.
        }
        // Readable. Readable with nothing to read is the end; asked AFTER `poll`, so a byte
        // that arrives in between is counted rather than missed.
        let mut waiting: libc::c_int = 0;
        // SAFETY: `FIONREAD` writes one `c_int` through the pointer, which points at one.
        let asked = unsafe { libc::ioctl(raw, libc::FIONREAD, &mut waiting) };
        return asked == 0 && waiting == 0;
    }
    false
}

/// No probe off Unix: a stdin is never known empty, so the batch fetches as it always did.
#[cfg(all(feature = "embedded", not(unix), not(target_family = "wasm")))]
fn stdin_ended_empty() -> bool {
    false
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
                "a running server trusts it at its next connection (it reads clients/*.crt at \
                 every handshake); to use it, copy \
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

/// Write one diagnostic line to stderr, and DROP it if stderr cannot take it (ledger #1208).
///
/// For what a door says while it serves — per connection, per discovery event — never for
/// what it says before it serves or as it dies. `eprintln!` PANICS when the write fails, and
/// a door's stderr is whatever its supervisor handed it: under launchd a file, but under a
/// harness or supervisor that stops reading, a pipe whose read end has closed (EPIPE; Rust
/// ignores SIGPIPE, so the write returns the error). The panic then lands in the
/// CONNECTION'S task, and the client sees `connection lost` for a log line nobody was
/// reading. A diagnostic that cannot be written is lost; the connection it describes is not.
#[cfg(all(feature = "embedded", feature = "quic"))]
fn diagnose(line: std::fmt::Arguments<'_>) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr().lock(), "{line}");
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

/// The flags only a QUIC door takes, beside the ones every served door shares.
#[cfg(feature = "embedded")]
struct QuicDoorFlags {
    /// `--layers-state <dir>`.
    layers_state: Option<std::path::PathBuf>,
    /// `--layers-key <path>`.
    layers_key: Option<std::path::PathBuf>,
    /// `--layers-reseal`.
    layers_reseal: bool,
    /// `--layers-https <addr>`.
    layers_https: Option<String>,
    /// `--require-enrollment`.
    require_enrollment: bool,
}

#[cfg(all(feature = "embedded", feature = "quic"))]
fn serve_quic(
    target: &str,
    certs: &Certs,
    caps: &[String],
    announce: bool,
    mounts: Mounts,
    flags: QuicDoorFlags,
) -> ! {
    let QuicDoorFlags {
        layers_state,
        layers_key,
        layers_reseal,
        layers_https,
        require_enrollment,
    } = flags;
    let caps = caps.to_vec();
    let result = (|| -> Result<(), String> {
        let addr = quic::parse_addr(target)?;
        let identity = quic::server_identity(certs)?;
        let trusted = quic::trusted_clients(certs)?;
        let max_age = quic_max_connection_age()?;
        // THE LAYER HOST (ledger #1188), when the config home has a `layers/` directory:
        // opened before anything is served, so a configuration that does not check (a
        // manifest mounting another collaboration's layer, a shape that is not closed) stops
        // the door here rather than at its first write. `None` without `layers/`: the door is
        // built exactly as it always was.
        // Sealed at rest (ledger #2011): a missing or wrong key, or a plaintext state directory
        // without `--layers-reseal`, stops the door here too.
        let layers = ikigai_embedded::layers::open(ikigai_embedded::layers::Flags {
            state: layers_state.as_deref(),
            key: layers_key.as_deref(),
            reseal: layers_reseal,
        })?;
        // THE HTTPS FRONT (ledger #1371), when the flag or the config home names an address: a
        // second face onto THIS door's kernel and authority, for participants that speak only
        // HTTP. It fronts layers and nothing else, so it needs a door that hosts them.
        let https = layers_https_addr(layers_https)?;
        if let (Some(addr), None) = (&https, &layers) {
            return Err(format!(
                "the layers HTTPS front ({addr}) fronts layers, and this door hosts none: the \
                 config home has no `{}/` directory",
                ikigai_embedded::layers::DIR
            ));
        }
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
        // ★ A LAYER DOOR SERVES ONLY ITS LAYERS (`served_kernel_hosting`): no general served
        // surface, and no mount either, since a mount would re-serve a peer's surface to every
        // participant. Refused before anything dials, naming the mounts, rather than composed.
        if let (Some(hosted), false) = (&layers, mounts.is_empty()) {
            return Err(format!(
                "this door hosts layers (defined in {}), and a layer door serves only its \
                 layers: it composes no mount, and this start names {} ({}). Serve the mounted \
                 namespaces on a door of their own, or pass --no-config-mounts if the config \
                 home's `mount` lines are for the other processes on this machine.",
                hosted.config.join(ikigai_embedded::layers::DIR).display(),
                if mounts.len() == 1 { "one" } else { "several" },
                mounts
                    .iter()
                    .map(|m| format!("{}={}", m.prefix, m.target))
                    .collect::<Vec<_>>()
                    .join(", "),
            ));
        }
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
            resolved.extend(resolve_mount(mount)?);
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
        // ★ A door that HOSTS LAYERS needs posture 1, and refuses to start without it (ledger
        // #1281). Layers are for participants: each certificate is named by its enrollment and
        // granted exactly its layer actions. Without a `clients.json` the door fell to posture
        // 3 (or to a shared `--cap` ceiling), where no participant has a grant and every
        // trusted certificate got fs read, write and delete in its own segment: a door built
        // for layers serving a filesystem instead. The edge guarded it with an `ExecStartPre`
        // file test; the door should not need one. A door WITHOUT `layers/` is unchanged.
        if let (Some(hosted), None) = (&layers, &enrolment) {
            let clients = ikigai_embedded::clients::clients_path()
                .map_or_else(|| "clients.json".into(), |p| p.display().to_string());
            let grants = ikigai_embedded::grants_path()
                .map_or_else(|| "grants.json".into(), |p| p.display().to_string());
            return Err(format!(
                "this door hosts layers (defined in {}) but enrolls no certificates: there is \
                 no {clients}. A layer door serves only per-identity grants, so it will not \
                 start without them. Generate the enrollment with `ikigai-layers grants {}` \
                 (it writes {clients} and {grants}), or remove the `layers/` directory to \
                 serve without layers.",
                hosted.config.join("layers").display(),
                hosted.config.display(),
            ));
        }
        // ★ `--require-enrollment` (ledger #1826): the booking airlock serves per-drainer grants
        // under its `--cap` ceiling, and without a `clients.json` it would fall to posture 2,
        // the one shared ceiling for every trusted certificate. A missing file stops the door,
        // never opens it. (While serving, a file that goes away refuses every client: the
        // minter reads it per connection.)
        if require_enrollment && enrolment.is_none() {
            let clients = ikigai_embedded::clients::clients_path()
                .map_or_else(|| "clients.json".into(), |p| p.display().to_string());
            return Err(format!(
                "--require-enrollment: there is no {clients}, so this door would serve every \
                 trusted certificate under one shared authority. Enroll each client there \
                 (`\"<fingerprint>\": {{\"grant\": \"<grant in grants.json>\", \"label\": \"…\"}}`; \
                 `ikigai cert add-client` prints the fingerprint), or drop the flag."
            ));
        }
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
                 grants the `notes` it addresses as `urn:file:notes/…`), or point `--files` (or \
                 `files` in the config home) at the tree you meant to serve.",
                unaddressable.join("\n  "),
                file_root.display()
            ));
        }
        // WHO each connection is (ledger #1179): every posture names its client, so an
        // endpoint can ask who it serves (`inv.capability.principal()`) and a log can
        // attribute a call to a certificate. An enrolled client is named by its entry's
        // `principal` when it has one; every other client by Brian's convention,
        // `urn:iki:host:{name}:client:<fp>`, `{name}` being this instance's (`--name`, else
        // `serve`). Checked once here, against a placeholder fingerprint, because a name
        // core cannot carry as a principal would otherwise make every connection quietly
        // anonymous: `Session::authority` falls back to minting nothing.
        let host = ikigai_embedded::instance_name();
        ikigai_core::principal_scope(&ikigai_embedded::clients::default_principal(
            host,
            &"0".repeat(64),
        ))
        .map_err(|e| {
            format!(
                "this instance's name `{host}` cannot name its clients \
                 (urn:iki:host:{host}:client:<fingerprint>): {e} — pick another `--name`"
            )
        })?;
        let principal_of = move |fingerprint: &str, enrolled: Option<String>| {
            enrolled
                .unwrap_or_else(|| ikigai_embedded::clients::default_principal(host, fingerprint))
        };
        // The enrolment is re-read per connection inside the minter (that is what makes
        // an edit a revocation), so the startup read is used only to CHOOSE the posture
        // and to report it.
        // POSTURE 1's minter, as a builder: the QUIC door's logs each grant it mints (one line
        // per connection), and the layers HTTPS front's is the SAME code without that line,
        // because the front mints per REQUEST and a participant that long-polls would write a
        // line every few seconds. Refusals are logged by both.
        let enrolled_minter = |log_grants: bool| -> ikigai_quic::Minter {
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
                match ikigai_embedded::clients::authorize(&peer.fingerprint, &ceiling) {
                    Ok(authority) => {
                        let grant = authority.grant;
                        // A grant's fs scopes are written the way the CLIENT addresses
                        // files (`urn:file:notes/…`), so resolve them against this
                        // connection's own workspace — the namespace its IRIs land in.
                        let capability = ikigai_embedded::tenant::root_fs_scopes(
                            &authority.capability,
                            &ikigai_embedded::tenant::tenant_root(&root, &peer.segment_id),
                        );
                        let principal = principal_of(&peer.fingerprint, authority.principal);
                        if log_grants {
                            diagnose(format_args!(
                                "ikigai: client {} → grant \"{grant}\" ({}) as {principal}",
                                short_fingerprint(&peer.fingerprint),
                                match capability.scopes() {
                                    None => "unrestricted".to_string(),
                                    Some(s) => format!("{} scope(s)", s.len()),
                                }
                            ));
                        }
                        Some(ikigai_quic::Session {
                            capability,
                            file_segment: peer.segment_id.clone(),
                            principal: Some(principal),
                        })
                    }
                    // The FULL fingerprint, so debugging a denied client is a copy-paste
                    // rather than a packet capture.
                    Err(why) => {
                        diagnose(format_args!(
                            "ikigai: REFUSED a trusted client certificate — {why}\n  \
                             fingerprint: {}\n  \
                             to enroll it, add it to the `clients` map in {path}",
                            peer.fingerprint
                        ));
                        None
                    }
                }
            })
        };
        let front_minter = enrolment.is_some().then(|| enrolled_minter(false));
        let minter: ikigai_quic::Minter = if enrolment.is_some() {
            enrolled_minter(true)
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
                    principal: Some(principal_of(&peer.fingerprint, None)),
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
                    // Shared authority, but not a shared NAME: the bound is everyone's, the
                    // principal is still the certificate's own.
                    principal: Some(principal_of(&peer.fingerprint, None)),
                })
            })
        };
        // ★ A LOBBY (ledger #2009, #2104): when the layer host defines a `lobby = true` channel,
        // the door also admits a certificate its trust list does NOT name, and this minter, not
        // the one above, decides it. It mints exactly `Host::lobby_capability`: `say` on every
        // lobby and nothing else, under `urn:iki:host:{name}:client:<fp>`. Never through
        // `root_fs_scopes` and never combined with `--cap`: the lobby capability is the whole
        // authority, so neither can widen or reshape it. The host holds every lobby to its size
        // and rate bounds itself. Decided ONCE at startup, like the surface: a door with no
        // lobby (or no layers) serves through `serve_trusting_on` exactly as before.
        let lobby_minter: Option<ikigai_quic::Minter> = layers
            .as_ref()
            .filter(|hosted| !hosted.host.lobbies().is_empty())
            .map(|hosted| -> ikigai_quic::Minter {
                let layer_host = std::sync::Arc::clone(&hosted.host);
                std::sync::Arc::new(move |peer: &ikigai_quic::PeerIdentity| {
                    match layer_host.lobby_capability(host, &peer.fingerprint) {
                        Ok(Some(capability)) => {
                            let principal = capability.principal().map(str::to_string);
                            Some(ikigai_quic::Session {
                                capability,
                                file_segment: peer.segment_id.clone(),
                                principal,
                            })
                        }
                        Ok(None) => {
                            diagnose(format_args!(
                                "ikigai: REFUSED an unlisted client certificate: this door's \
                                 layer host has no lobby\n  fingerprint: {}",
                                peer.fingerprint
                            ));
                            None
                        }
                        Err(why) => {
                            diagnose(format_args!(
                                "ikigai: REFUSED an unlisted client certificate: no lobby \
                                 capability for it ({why})\n  fingerprint: {}",
                                peer.fingerprint
                            ));
                            None
                        }
                    }
                })
            });
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
        let posture = if require_enrollment {
            format!("{posture} (enrollment required)")
        } else {
            posture
        };
        // Not a warning since ledger #1825: `default` now serves only ENROLLED entries that
        // name no grant, never a trusted certificate with no entry, so it widens nothing.
        if let Some(default_grant) = enrolment.as_ref().and_then(|e| e.default_grant()) {
            eprintln!(
                "ikigai: clients.json sets a default grant \"{default_grant}\": an enrolled \
                 entry that names no grant is served under it (a certificate with no entry is \
                 still refused)"
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
        //
        // ★ And a grant scope the `--cap` ceiling does not allow is left out (ledger #1826):
        // the clamp takes it away from every connection, so it can never be exercised, and it
        // must not switch a face on either. Before, one stray personal scope in a drainer's
        // grant turned the booking airlock into the calendar-only kernel, with no spaces.
        let ceiling = (!caps.is_empty()).then(|| ikigai_core::Capability::scoped(caps.clone()));
        let surface_caps: Vec<String> = {
            let mut union = caps.clone();
            for grant in enrolment.iter().flat_map(|e| e.grant_names()) {
                let scopes = ikigai_embedded::grant_scopes(&grant);
                // Exactly what the minter clamps a connection under this grant to.
                match &ceiling {
                    Some(ceiling) => union.extend(
                        ceiling
                            .clamp(&ikigai_core::Capability::scoped(scopes))
                            .scopes()
                            .into_iter()
                            .flatten()
                            .cloned(),
                    ),
                    None => union.extend(scopes),
                }
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
        // ★ The same rule for a FACE: a ceiling (or an enrolled grant) that would open the
        // calendar, inference or the governed eval beside the layers is refused, not ignored.
        if let Some(hosted) = &layers {
            let opened: Vec<&str> = [
                (surface.personal, "the calendar (a urn:cap:personal: scope)"),
                (surface.llm, "inference (a urn:cap:net: scope)"),
                (
                    surface.wire_eval,
                    "the governed eval (urn:cap:lisp or urn:cap:lisp:run)",
                ),
            ]
            .into_iter()
            .filter_map(|(on, face)| on.then_some(face))
            .collect();
            if !opened.is_empty() {
                return Err(format!(
                    "this door hosts layers (defined in {}), and a layer door serves only its \
                     layers, but its ceiling or an enrolled grant would open {} beside them. \
                     Serve that face on a door of its own.",
                    hosted.config.join(ikigai_embedded::layers::DIR).display(),
                    opened.join(" and "),
                ));
            }
        }
        // ONE kernel for both faces (QUIC and the layers HTTPS front): a write through one
        // must cut the threads the other's readers hang from (`ikigai_quic::serve_shared_on`).
        let kernel = std::sync::Arc::new(ikigai_embedded::served_kernel_hosting(
            "Remote (QUIC)",
            surface,
            resolved,
            layers.as_ref().map(|hosted| &hosted.host),
        ));
        // And ONE workspace watch for that kernel, started before the banner, so a file
        // changed on disk is served fresh from the first request (ledger #246). Held to the end
        // of this closure, which is for as long as the door serves.
        let _workspace = watch_served_workspace(&kernel);
        let signed_door = ikigai_embedded::code_signers_configured();
        // A layer door's surface is its layers alone (refused above if anything else was asked).
        let mut faces = vec![if layers.is_some() {
            "layers"
        } else if surface.personal {
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
        if let Some(hosted) = &layers {
            eprintln!(
                "ikigai: layers: {} — defined in {}, state in {} ({})",
                match hosted.layer_lines() {
                    lines if lines.is_empty() => "none defined".to_string(),
                    lines => lines.join(", "),
                },
                hosted.config.join(ikigai_embedded::layers::DIR).display(),
                hosted.state.display(),
                hosted.source.as_str()
            );
            // The recipient is the PUBLIC half: what an operator checks against the key file.
            eprintln!(
                "ikigai: layers: state sealed at rest to {} (key {}, {})",
                hosted.recipient,
                hosted.key.display(),
                hosted.key_source.as_str()
            );
            if hosted.resealed {
                eprintln!(
                    "ikigai: layers: --layers-reseal: every state file is sealed to that \
                     recipient now; later starts leave the flag off (rerunning it is safe)"
                );
            }
            let lobbies = hosted.host.lobbies();
            if !lobbies.is_empty() {
                eprintln!(
                    "ikigai: layers: lobby open on {}: a client certificate this door does not \
                     trust may say there and nothing else",
                    lobbies.join(", ")
                );
            }
        }
        // The front binds before the banner too, and its line comes first, so the QUIC banner
        // stays the last line a harness waits for and both addresses are bound when it prints.
        let front = match &https {
            Some(addr) => Some(bind_layers_front(addr, &identity)?),
            None => None,
        };
        // BIND BEFORE THE BANNER (the QUIC face of ledger #1223): the banner is the readiness
        // signal every harness and supervisor waits for, so it must name a socket that is
        // already bound — and the BOUND one, so `quic://127.0.0.1:0` announces the port the
        // kernel chose rather than `:0`, and nobody has to pick a free port by binding one and
        // releasing it (which a child spawned in between can inherit and hold, on macOS).
        let socket = ikigai_quic::bind(addr).map_err(|e| format!("bind {target}: {e}"))?;
        let bound = socket
            .local_addr()
            .map_err(|e| format!("bind {target}: {e}"))?;
        let target = if addr.port() == 0 {
            format!(
                "quic://{}",
                std::net::SocketAddr::new(addr.ip(), bound.port())
            )
        } else {
            target.to_string()
        };
        let target = target.as_str();
        eprintln!(
            "ikigai: serving on {target}  ({posture}; surface: {surface}; connections \
             re-minted every {}s)  (Ctrl-C to stop)",
            max_age.as_secs()
        );
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
            // TTL wait. And since ledger #1825 the certificate SET is re-read at every
            // handshake too, so the client lines above are the startup reading of it.
            reloads: {
                let mut reloads = vec![
                    "the client trust list (the base client.crt and clients/*.crt) — re-read at \
                     EVERY handshake, so a certificate added is trusted at its next connection \
                     and one removed is refused at its next connection; the client lines \
                     above are the startup reading."
                        .to_string(),
                ];
                if enrolment.is_some() {
                    reloads.push(
                        "clients.json (and the grants it names) — re-read on EVERY connection, \
                         so which authority each certificate gets is decided then, not now; an \
                         edit revokes on the next call, and a certificate with no entry is \
                         refused whatever `default` says."
                            .to_string(),
                    );
                }
                if layers.is_some() {
                    reloads.push(
                        "layers/*.toml — read ONCE, at startup: each layer binds its own \
                         endpoints, so a new or changed layer takes a restart. \
                         participants.ttl and collabs/*.toml are re-read on every use."
                            .to_string(),
                    );
                }
                if front.is_some() {
                    reloads.push(
                        "layer-tokens.json — re-read on EVERY request to the HTTPS front, so a \
                         revoked token is refused on its next request; each token mints through \
                         clients.json as the certificate it is bound to would."
                            .to_string(),
                    );
                }
                reloads
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
                bound.port(),
                &[
                    (ikigai_discovery::TXT_SURFACE, surface.as_str()),
                    (ikigai_discovery::TXT_CEILING, posture.as_str()),
                    (ikigai_discovery::TXT_VERSION, wire_version.as_str()),
                ],
                // Fires on the announcer's own thread for as long as the door serves.
                |event| diagnose(format_args!("ikigai: {event}")),
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
        // ★ The trust list is re-read at EVERY handshake (ledger #1825): a certificate added to
        // `clients/` is trusted at its next connection and one removed is refused at its next
        // connection, no restart. The startup reading above is the banner's and the posture's.
        // A reading that fails trusts nobody until it reads again, and is logged once per new
        // reason rather than per handshake: anyone who can reach the port can start one.
        let trust: ikigai_quic::TrustList = {
            let certs = certs.clone();
            let last = std::sync::Mutex::new(None::<String>);
            std::sync::Arc::new(move || {
                let read = quic::trusted_clients(&certs);
                let mut last = last
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match read {
                    Ok(trusted) => {
                        if last.take().is_some() {
                            diagnose(format_args!("ikigai: the client trust list reads again"));
                        }
                        Ok(trusted.into_iter().map(|client| client.pem).collect())
                    }
                    Err(why) => {
                        if last.as_deref() != Some(why.as_str()) {
                            diagnose(format_args!(
                                "ikigai: REFUSING every client certificate: the trust list \
                                 does not read ({why})"
                            ));
                            *last = Some(why.clone());
                        }
                        Err(std::io::Error::other(why))
                    }
                }
            })
        };
        match (front, front_minter) {
            (Some(front), Some(front_minter)) => {
                spawn_layers_front(front, std::sync::Arc::clone(&kernel), front_minter)?
            }
            // Unreachable by the checks above (a layer door enrolls, and the front needs one),
            // and refused rather than served if it ever were: a front with no per-identity
            // minter would have no authority to give anyone.
            (Some(_), None) => {
                return Err(
                    "the layers HTTPS front needs per-identity grants (clients.json)".into(),
                )
            }
            (None, _) => {}
        }
        match lobby_minter {
            Some(lobby) => ikigai_quic::serve_lobby_on(
                kernel,
                socket,
                &identity,
                trust,
                minter,
                lobby,
                quic_idle_timeout(),
                Some(max_age),
            ),
            None => ikigai_quic::serve_trusting_on(
                kernel,
                socket,
                &identity,
                trust,
                minter,
                quic_idle_timeout(),
                Some(max_age),
            ),
        }
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

/// The config-home key naming the layers HTTPS front's address, instance-scoped as
/// `<instance>.layers.https`.
#[cfg(all(feature = "embedded", feature = "quic"))]
const LAYERS_HTTPS_KEY: &str = "layers.https";

/// Where the layers HTTPS front binds: `--layers-https`, else `<instance>.layers.https`, else
/// `layers.https` in the config home; `None` when nothing names one (the front is off). A bare
/// port binds loopback, as `serve --http <port>` does.
#[cfg(all(feature = "embedded", feature = "quic"))]
fn layers_https_addr(flag: Option<String>) -> Result<Option<String>, String> {
    let instance = ikigai_embedded::instance_name();
    let named = flag
        .or_else(|| ikigai_embedded::config::get(&format!("{instance}.{LAYERS_HTTPS_KEY}")))
        .or_else(|| ikigai_embedded::config::get(LAYERS_HTTPS_KEY))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let Some(named) = named else {
        return Ok(None);
    };
    if !cfg!(feature = "web") {
        return Err(format!(
            "the layers HTTPS front ({named}) needs the `web` feature beside `quic`: install \
             with `--features quic,web`"
        ));
    }
    Ok(Some(if named.parse::<u16>().is_ok() {
        format!("127.0.0.1:{named}")
    } else {
        named
    }))
}

/// The bound front, waiting for the kernel it will serve.
#[cfg(all(feature = "embedded", feature = "quic", feature = "web"))]
struct BoundFront {
    listener: std::net::TcpListener,
    tls: tokio_rustls::rustls::ServerConfig,
}

#[cfg(all(feature = "embedded", feature = "quic", not(feature = "web")))]
struct BoundFront;

/// Bind the front's socket and build its TLS (the QUIC door's own server certificate), and
/// print its banner line: it names the BOUND address, so port 0 announces the port taken.
#[cfg(all(feature = "embedded", feature = "quic", feature = "web"))]
fn bind_layers_front(addr: &str, identity: &ikigai_quic::Identity) -> Result<BoundFront, String> {
    let tls = ikigai_quic::https_server_tls(identity)
        .map_err(|e| format!("the layers HTTPS front's TLS: {e}"))?;
    let listener = std::net::TcpListener::bind(addr)
        .map_err(|e| format!("the layers HTTPS front could not bind {addr}: {e}"))?;
    let bound = listener
        .local_addr()
        .map_err(|e| format!("the layers HTTPS front's address: {e}"))?;
    let tokens = ikigai_embedded::tokens::tokens_path()
        .ok_or("the layers HTTPS front needs a config home to keep layer-tokens.json in")?;
    // Read once here so a broken file stops the start, as a broken clients.json does; the
    // front reads it again on every request.
    let held = ikigai_embedded::tokens::load_from(&tokens)?;
    eprintln!(
        "ikigai: layers https on https://{bound}  (bearer tokens: {} bound in {}, re-read on \
         every request; TLS with this door's server certificate)",
        held.len(),
        tokens.display()
    );
    Ok(BoundFront { listener, tls })
}

#[cfg(all(feature = "embedded", feature = "quic", not(feature = "web")))]
fn bind_layers_front(addr: &str, _identity: &ikigai_quic::Identity) -> Result<BoundFront, String> {
    Err(format!(
        "the layers HTTPS front ({addr}) needs the `web` feature beside `quic`"
    ))
}

/// Serve the front on a thread of its own, onto `kernel` (the QUIC door's) with `minter` (the
/// QUIC door's). If it ever stops, the door says so and goes on serving QUIC.
#[cfg(all(feature = "embedded", feature = "quic", feature = "web"))]
fn spawn_layers_front(
    bound: BoundFront,
    kernel: std::sync::Arc<ikigai_core::Kernel>,
    minter: ikigai_quic::Minter,
) -> Result<(), String> {
    let tokens = ikigai_embedded::tokens::tokens_path()
        .ok_or("the layers HTTPS front needs a config home to keep layer-tokens.json in")?;
    let front = front::Front {
        kernel,
        minter,
        tokens,
        edge: ikigai_web::EdgeConfig::default(),
    };
    std::thread::Builder::new()
        .name("layers-https".to_string())
        .spawn(move || {
            if let Err(e) = front::serve(front, bound.listener, bound.tls) {
                diagnose(format_args!("ikigai: layers https STOPPED: {e}"));
            }
        })
        .map(drop)
        .map_err(|e| format!("the layers HTTPS front's thread: {e}"))
}

#[cfg(all(feature = "embedded", feature = "quic", not(feature = "web")))]
fn spawn_layers_front(
    _bound: BoundFront,
    _kernel: std::sync::Arc<ikigai_core::Kernel>,
    _minter: ikigai_quic::Minter,
) -> Result<(), String> {
    Ok(())
}

/// `ikigai layers-token mint|list|revoke`: the bearer tokens of a layer door's HTTPS front,
/// kept hashed in `layer-tokens.json` beside `clients.json` (`ikigai_embedded::tokens`).
#[cfg(feature = "embedded")]
fn layers_token(command: TokenCommand) -> ! {
    use ikigai_embedded::tokens;
    let result = (|| -> Result<(), String> {
        let path = tokens::tokens_path()
            .ok_or("no config home to keep layer-tokens.json in (set HOME or --config-home)")?;
        let mut held = tokens::load_from(&path)?;
        match command {
            TokenCommand::Mint { client, label } => {
                let enrolment = ikigai_embedded::clients::enrolment()?.ok_or_else(|| {
                    format!(
                        "no clients.json ({}): a token is bound to an ENROLLED participant, so \
                         enroll it first (`ikigai-layers grants <config home>` writes \
                         clients.json from enrollment.toml)",
                        ikigai_embedded::clients::clients_path()
                            .map_or_else(|| "unset".into(), |p| p.display().to_string())
                    )
                })?;
                let key = tokens::resolve_client(&enrolment, &client)?;
                let token = tokens::generate()?;
                let created = tokens::now();
                let label = label.unwrap_or_else(|| client.clone());
                let binding = held.insert(&token, &key, &label, &created)?;
                tokens::save_to(&path, &held)?;
                // The token on stdout ALONE, so `$(ikigai layers-token mint …)` captures it;
                // everything else on stderr.
                println!("{token}");
                eprintln!(
                    "ikigai: minted token {} for {} (client {}), stored as its hash in {}. This \
                     is the only time it is shown.",
                    binding.id,
                    enrolment.principal_for(&key).unwrap_or(label.as_str()),
                    short_key(&key),
                    path.display()
                );
            }
            TokenCommand::List => {
                for b in held.bindings() {
                    println!("{}  {}  {}  {}", b.id, b.client, b.created, b.label);
                }
                if held.is_empty() {
                    eprintln!("ikigai: no tokens in {}", path.display());
                }
            }
            TokenCommand::Revoke { id } => {
                let gone = held.revoke(&id)?;
                tokens::save_to(&path, &held)?;
                eprintln!(
                    "ikigai: revoked token {} ({}); its next request is refused",
                    gone.id, gone.label
                );
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("ikigai: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(feature = "embedded"))]
fn layers_token(_command: TokenCommand) -> ! {
    eprintln!("ikigai: `layers-token` needs the `embedded` feature");
    std::process::exit(1);
}

/// A clients.json key for a log line: a fingerprint's leading characters, anything else whole.
#[cfg(feature = "embedded")]
fn short_key(key: &str) -> &str {
    if key.len() == 64 {
        &key[..16]
    } else {
        key
    }
}

#[cfg(all(feature = "embedded", feature = "quic"))]
fn connect_quic(target: &str, certs: &Certs) -> Result<Engine, String> {
    let addr = quic::parse_addr(target)?;
    let identity = quic::client_identity(certs)?;
    let trusted = quic::trusted_server_cert(certs)?;
    let mut resolver = ikigai_quic::connect_with(addr, &identity, &trusted, quic_idle_timeout())
        .map_err(|e| format!("connect {target}: {e}"))?
        .with_describe_timeout(describe_timeout(ikigai_quic::DEFAULT_DESCRIBE_TIMEOUT));
    if let Some(bound) = call_timeout() {
        resolver = resolver.with_call_timeout(bound);
    }
    Ok(with_profiles(Engine::new(resolver)))
}

#[cfg(all(feature = "embedded", not(feature = "quic")))]
fn serve_quic(
    _target: &str,
    _certs: &Certs,
    _caps: &[String],
    _announce: bool,
    _mounts: Mounts,
    flags: QuicDoorFlags,
) -> ! {
    // Read here so a build without `quic` does not call the fields dead; nothing uses them.
    let _ = (
        flags.layers_state,
        flags.layers_key,
        flags.layers_reseal,
        flags.layers_https,
        flags.require_enrollment,
    );
    eprintln!("ikigai: `quic://` needs the `quic` feature");
    std::process::exit(1);
}

#[cfg(all(feature = "embedded", not(feature = "quic")))]
fn connect_quic(_target: &str, _certs: &Certs) -> Result<Engine, String> {
    Err("`quic://` needs the `quic` feature".to_string())
}

/// Start a serving process's ONE workspace watch over its shared kernel, and say so on
/// stderr: which directory, or why there is none (ledger #246, #1425).
///
/// A served kernel binds the cacheable `urn:file:*`, so without a watch a file changed on disk
/// outside the kernel is served from the cached read until the process restarts. Called once
/// per door process, after the kernel is shared and before the banner, never per connection.
/// The returned handle stops the watch when dropped, so the caller holds it while it serves.
#[cfg(all(
    feature = "embedded",
    any(feature = "quic", feature = "web", all(feature = "ipc", unix))
))]
fn watch_served_workspace(
    kernel: &std::sync::Arc<ikigai_core::Kernel>,
) -> Option<ikigai_embedded::WorkspaceWatch> {
    match ikigai_embedded::watch_workspace(kernel) {
        Ok(Some(watch)) => {
            eprintln!(
                "ikigai: watching {} (a file changed on disk is served fresh)",
                watch.root().display()
            );
            Some(watch)
        }
        // The kernel binds no `urn:file:` (the calendar-only surface): nothing to watch.
        Ok(None) => None,
        Err(e) => {
            eprintln!(
                "ikigai: warning: workspace watcher not started ({e}); a file changed on disk \
                 outside ikigai is served stale until restart"
            );
            None
        }
    }
}

// --- IPC serve / connect ----------------------------------------------------

/// The other accounts a socket door admits (ledger #2139): the principals table's `uid`/`user`
/// entries ([`ikigai_embedded::agents::socket_peers`]), each a bounded, named admission, and
/// the group the socket is shared with (`ipc.group` in the config home's `config.toml`).
#[cfg(all(feature = "embedded", feature = "ipc", unix))]
struct SharedSocket {
    admissions: ikigai_ipc::Admissions,
    gid: u32,
    /// One line per admitted account: `uid 502 as urn:…`.
    accounts: Vec<String>,
}

/// Read [`SharedSocket`] from the grants file, or `None` when no principal names an account
/// (or there is no grants file): the door then admits only its own user, as before.
///
/// # Errors
///
/// Every reason the table cannot be honored, named: a grants file that does not parse or fails
/// a session check, an account that does not exist or is this user, a grants file the account
/// could write, and a missing or unknown `ipc.group`.
#[cfg(all(feature = "embedded", feature = "ipc", unix))]
fn shared_socket() -> Result<Option<SharedSocket>, String> {
    let Some(path) = ikigai_embedded::grants_path() else {
        return Ok(None);
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let peers = ikigai_embedded::agents::socket_peers(&text)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if peers.is_empty() {
        return Ok(None);
    }
    shared_socket_from(&path, peers, ikigai_embedded::config::get("ipc.group"))
}

/// [`shared_socket`] over the parsed accounts and the configured group, so the policy is
/// testable without a config home.
#[cfg(all(feature = "embedded", feature = "ipc", unix))]
fn shared_socket_from(
    path: &std::path::Path,
    peers: Vec<ikigai_embedded::agents::SocketPeer>,
    group: Option<String>,
) -> Result<Option<SharedSocket>, String> {
    use ikigai_embedded::agents::Account;
    // SAFETY: `getuid` reads a process attribute and cannot fail.
    let me = unsafe { libc::getuid() };
    let group = group
        .map(|g| g.trim().trim_matches('"').to_string())
        .ok_or_else(|| {
            format!(
                "{} admits other accounts to the socket, so it needs a group to share the socket \
             with: set `ipc.group = \"<group>\"` in {}, a group those accounts are in",
                path.display(),
                ikigai_embedded::config::config_path().display()
            )
        })?;
    let gid = match group.parse::<u32>() {
        Ok(gid) => gid,
        Err(_) => ikigai_ipc::gid_of_group(&group).map_err(|e| format!("ipc.group: {e}"))?,
    };
    let mut admissions = ikigai_ipc::Admissions::owner_only();
    let mut accounts = Vec::new();
    for peer in peers {
        let uid = match &peer.account {
            Account::Uid(uid) => *uid,
            Account::User(name) => ikigai_ipc::uid_of_user(name)
                .map_err(|e| format!("the account of `{}`: {e}", peer.session.principal))?,
        };
        if uid == me {
            return Err(format!(
                "the account of `{}` is this user (uid {uid}): a same-uid client is the owner \
                 to the operating system and cannot be bounded; run it as another account",
                peer.session.principal
            ));
        }
        ikigai_embedded::agents::check_protected_from(path, uid)?;
        let ceiling = ikigai_resolve::without_principals(&peer.session.capability);
        let admission =
            ikigai_ipc::Admission::bounded(ceiling, Some(peer.session.principal.clone()))
                .map_err(|e| format!("`{}`: {e}", peer.session.principal))?;
        if admissions
            .admit(me, Some(uid))
            .is_ok_and(|a| a.principal().is_some())
        {
            return Err(format!(
                "uid {uid} is named by two principals; an account is one principal"
            ));
        }
        admissions = admissions.with_uid(uid, admission);
        accounts.push(format!("uid {uid} as {}", peer.session.principal));
    }
    Ok(Some(SharedSocket {
        admissions,
        gid,
        accounts,
    }))
}

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
    let home = home_dir();
    let mounts: Vec<Mount> = mounts
        .into_iter()
        .filter(|mount| {
            let own = is_own_socket(&mount.target, &socket, &home);
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
    // Other accounts this socket admits, from the principals table (ledger #2139). A table
    // that names an account and cannot be honored stops the door: serving it owner-only would
    // look like the bound was applied.
    let shared = match shared_socket() {
        Ok(shared) => shared,
        Err(e) => {
            eprintln!("ikigai: serve error: {e}");
            std::process::exit(2);
        }
    };
    let authority = match &shared {
        None => "root, as the owner, naming no principal — only this user reaches the socket \
                 (its file permissions and the peer's UID are the boundary), and a principal a \
                 client supplies is removed"
            .to_string(),
        Some(shared) => format!(
            "root for this user, as the owner, naming no principal; and {}, each bounded by \
             its grant and named as its principal — the socket's group and mode and the peer's \
             UID are the boundary, any other UID is refused, and a principal a client supplies \
             is removed",
            shared.accounts.join(", ")
        ),
    };
    // ★ The posture of the door a local client (Emacs, the REPL, MCP) actually talks to.
    // THE HOST OWNS THE TOPOLOGY, so this socket's mounts are the ones a connected client
    // resolves through without knowing where the peers are — and until now the only way to
    // learn which they were was to have watched this process start.
    ikigai_embedded::posture::set_posture(ikigai_embedded::posture::Posture {
        door: socket.display().to_string(),
        mounts: mount_posture(&mounts, declined),
        // A Unix socket authenticates nobody by certificate: the socket's file permissions
        // and the peer's kernel-verified UID are the boundary.
        clients: Vec::new(),
        surface: None,
        authority: Some(authority),
        reloads: Vec::new(),
    });
    let mut resolved = Vec::new();
    for mount in mounts {
        match resolve_mount(mount) {
            Ok(specs) => resolved.extend(specs),
            Err(e) => {
                eprintln!("ikigai: {e}");
                std::process::exit(2);
            }
        }
    }
    // Shared, so the door and the workspace watch hold ONE kernel: the watch cuts the threads
    // this door's cached `urn:file:*` reads hang from (ledger #246).
    let kernel = std::sync::Arc::new(ikigai_embedded::trusted_kernel_with_mounts(
        "Remote (IPC)",
        resolved,
    ));
    let _workspace = watch_served_workspace(&kernel);
    // BIND BEFORE THE BANNER (ledger #430, #1224; the QUIC and HTTP doors already do): the
    // banner is the readiness signal every harness and supervisor waits for, and it printed
    // before the bind, so a client that dialed on it got `No such file or directory` about
    // half the time. The listener is listening once `bind` returns, so a client that connects
    // after the banner waits in the backlog until the accept loop takes it.
    let listener = match &shared {
        None => ikigai_ipc::bind(&socket),
        Some(shared) => ikigai_ipc::bind_shared(&socket, shared.gid),
    };
    let listener = match listener {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!(
                "ikigai: serve error: could not bind {}: {e}",
                socket.display()
            );
            std::process::exit(1);
        }
    };
    // ★ OWNER, explicitly (ledger #1830, row D12): this user's UID names the owner and no
    // party, so a principal is not meaningful for it. Root, and a `principal` argument or
    // carried principal scope a client supplies is removed. Another account is admitted only
    // as the principals table names it (ledger #2139), bounded and named.
    let admissions = match &shared {
        None => {
            eprintln!(
                "ikigai: the socket admits only this user, as the owner: root authority, no \
                 principal (a client-supplied one is removed)"
            );
            ikigai_ipc::Admissions::owner_only()
        }
        Some(shared) => {
            eprintln!(
                "ikigai: the socket admits this user as the owner (root authority, no \
                 principal), and {} other account(s), each bounded by its grant and named: {} \
                 (socket group gid {}, mode 0660; any other uid is refused)",
                shared.accounts.len(),
                shared.accounts.join(", "),
                shared.gid
            );
            shared.admissions.clone()
        }
    };
    // The banner stays LAST: it is the readiness signal, and a reader may stop at it.
    eprintln!("ikigai: serving on {}  (Ctrl-C to stop)", socket.display());
    match ikigai_ipc::serve_shared_on_admissions(
        kernel,
        listener,
        ikigai_ipc::Limits::default(),
        admissions,
    ) {
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
    let mut resolver = ikigai_ipc::connect_with_timeout(&socket, Some(timeout))
        .map_err(|e| format!("connect {}: {e}", socket.display()))?
        .with_describe_timeout(describe_timeout(ikigai_ipc::DEFAULT_DESCRIBE_TIMEOUT));
    if let Some(bound) = call_timeout() {
        resolver = resolver.with_call_timeout(bound);
    }
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
fn is_own_socket(target: &str, socket: &std::path::Path, home: &std::path::Path) -> bool {
    if is_quic(target) || target.starts_with("peer:") {
        return false;
    }
    let absolute = |p: std::path::PathBuf| std::path::absolute(&p).unwrap_or(p);
    // A target the rule refuses (`~bob/x.sock`) is compared as written: it names no socket
    // of this process either way.
    let target = ikigai_resolve::expand_home(target, Some(home))
        .unwrap_or_else(|_| std::path::PathBuf::from(target));
    absolute(target) == absolute(socket.to_path_buf())
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
/// The socket is bound BEFORE the banner prints, so the banner is a readiness signal and
/// names the address actually bound (port `0` → the kernel's choice).
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
        push,
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
    // The passkey store, checked the way the gate checks it (ledger #828): a file someone else
    // could have written refuses to start this door, naming the file and the `chmod`, rather
    // than serving pages whose every passkey-gated decision then refuses at the first tap. A
    // file others can only read is tightened to 0600 here. The workspace DIRECTORY is judged
    // first (ledger #850): one others can write refuses too, naming it and the `chmod go-w`,
    // because whoever can write it can plant an enrollment window or delete the store. This is
    // the door the browser ceremony runs through; the gate itself checks again on every load,
    // whatever the door.
    if let Err(detail) = ikigai_embedded::passkey::preflight() {
        eprintln!("ikigai: refusing to serve: the passkey store is not trusted: {detail}");
        std::process::exit(2);
    }
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
            Ok(specs) => resolved.extend(specs),
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
    let kernel = ikigai_embedded::kernel_for_with_mounts("Remote (HTTP)", resolved);
    // THE SPILL AND THE UPLOAD ROUTES (ledger #2244), from the config home: a file-backed spill
    // facility over a directory of this door's own, so an upload route takes a body larger than
    // memory. A line that does not parse stops the door, naming it.
    let upload_config = match uploads::uploads_from(
        &[
            ikigai_embedded::config::entries_under(uploads::ROUTE_KEY),
            ikigai_embedded::config::entries_under("http.spill"),
        ]
        .concat(),
    ) {
        Ok(config) => config,
        Err(e) => {
            eprintln!(
                "ikigai: {e} (in {})",
                ikigai_embedded::config::config_path().display()
            );
            std::process::exit(2);
        }
    };
    let (kernel, spill) = install_spill(kernel, &upload_config, addr.port());
    let upload_note =
        uploads::describe(&upload_config, spill.as_ref().map(|(dir, _)| dir.as_path()));
    let kernel = std::sync::Arc::new(kernel);
    // The door's ONE workspace watch: a stylesheet or context replaced on disk is served on
    // the next request, no unit restart (ledger #246: the edge kept rendering a replaced
    // `foaf.xsl` until `systemctl restart`). Held for as long as this function serves.
    let _workspace = watch_served_workspace(&kernel);
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
    // `--push` serves the event stream; what a stream hears is still the ceiling's business.
    if push {
        config.push = Some(ikigai_web::PushConfig::default());
    }
    // PER-CLIENT RATE LIMITS (ledger #1717), from the config home and on by default: the
    // public intake (every contact or booking submission is an email to a person) and the
    // passkey challenge. A line that does not parse stops the door, naming it; so does a bad
    // `passkey.max_challenges`, the bound on the challenge store the limit protects.
    let limits = match rate_limits::limits_from(&ikigai_embedded::config::entries_under(
        rate_limits::RULE_KEY,
    )) {
        Ok(limits) => limits,
        Err(e) => {
            eprintln!(
                "ikigai: {e} (in {})",
                ikigai_embedded::config::config_path().display()
            );
            std::process::exit(2);
        }
    };
    if let Err(e) = ikigai_embedded::passkey::check_config() {
        eprintln!("ikigai: {e}");
        std::process::exit(2);
    }
    let limits_note = rate_limits::describe(limits.as_ref());
    config.source_limits = limits;
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
    let push_note = if push {
        format!("push at {}; ", ikigai_web::DEFAULT_PUSH_PATH)
    } else {
        String::new()
    };
    let proxy_note = if trust_proxy {
        "trusting X-Forwarded-*"
    } else {
        "no proxy trust"
    };
    // ★ BIND BEFORE THE BANNER, and name the address that was BOUND (ledger #1223). The
    // banner used to print the configured address and `serve_with` bound it afterwards, so
    // the banner was not a readiness signal and `--http 0` announced port 0. That pushed
    // every harness into choosing a port itself — bind `:0`, read the port, release it, hand
    // it over — and on macOS a released port is not reliably free: `socket()` and
    // `FD_CLOEXEC` are two calls there, so a child spawned by another thread in between
    // inherits the listener and holds the port LISTENING after the harness dropped it. This
    // door then failed to bind (EADDRINUSE), and the harness's connect landed in the
    // inheritor's backlog and was reset. Binding here lets `--http 0` take a free port from
    // the kernel atomically, and makes the banner true the moment it prints.
    let listener = match runtime.block_on(tokio::net::TcpListener::bind(addr)) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("ikigai: HTTP serve error: could not bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    let addr = listener.local_addr().unwrap_or(addr);
    eprintln!(
        "ikigai: serving HTTP on {addr}  ({posture}; {route_note}; {cors_note}; {push_note}{proxy_note}; {limits_note}; {upload_note}; terminate TLS at your proxy)  (Ctrl-C to stop)"
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
    let served = match spill {
        Some((_, store)) if !upload_config.routes.is_empty() => {
            let uploads = upload_config.routes.iter().fold(
                ikigai_web::Uploads::new(store)
                    .min_rate(upload_config.min_rate, upload_config.grace),
                |uploads, (pattern, max)| uploads.route(pattern.clone(), *max),
            );
            runtime.block_on(ikigai_web::serve_with_uploads(
                kernel, cap_fn, listener, config, uploads,
            ))
        }
        _ => runtime.block_on(ikigai_web::serve_with_listener(
            kernel, cap_fn, listener, config,
        )),
    };
    match served {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("ikigai: HTTP serve error: {e}");
            std::process::exit(1);
        }
    }
}

/// The HTTP door's spill (ledger #2244): ikigai-fs's `FileSpill` over
/// `<config home>/spill/http-<port>` (`http-0-<pid>` for an ephemeral port), made `0700` if it is
/// missing, with `config`'s per-request ceiling, and the content store an upload is held in
/// while its Sink runs. A directory of this door's own, because a `FileSpill` removes the spill
/// files it finds in its directory when it opens it: two processes must never share one, and two
/// doors cannot both hold one port. Only under a config home that exists; never `TMPDIR`.
///
/// A door with no upload routes serves without a spill when the directory cannot be made (and
/// says why); one with upload routes refuses to start.
#[cfg(all(feature = "embedded", feature = "web", unix))]
fn install_spill(
    kernel: ikigai_core::Kernel,
    config: &uploads::UploadConfig,
    port: u16,
) -> (
    ikigai_core::Kernel,
    Option<(
        std::path::PathBuf,
        std::sync::Arc<ikigai_core::MemoryContentStore>,
    )>,
) {
    use std::os::unix::fs::DirBuilderExt;
    let Some(home) = ikigai_embedded::config::config_home().filter(|home| home.is_dir()) else {
        if !config.routes.is_empty() {
            eprintln!("ikigai: upload routes need a config home to spill under");
            std::process::exit(2);
        }
        return (kernel, None);
    };
    let name = match port {
        0 => format!("http-0-{}", std::process::id()),
        port => format!("http-{port}"),
    };
    let dir = home.join("spill").join(name);
    let spill = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| e.to_string())
        .and_then(|()| ikigai_fs::FileSpill::new(&dir).map_err(|e| e.to_string()));
    match spill {
        Ok(spill) => {
            let store = std::sync::Arc::new(ikigai_core::MemoryContentStore::new(config.total));
            let kernel = kernel
                .with_spill(std::sync::Arc::new(spill))
                .with_stream_spill(0, config.ceiling)
                .with_content_store(store.clone());
            (kernel, Some((dir, store)))
        }
        Err(e) if config.routes.is_empty() => {
            eprintln!("ikigai: serving without a spill ({}: {e})", dir.display());
            (kernel, None)
        }
        Err(e) => {
            eprintln!(
                "ikigai: upload routes need a spill directory ({}: {e})",
                dir.display()
            );
            std::process::exit(2);
        }
    }
}

/// Off Unix there is no file-backed spill facility, so there are no upload routes either.
#[cfg(all(feature = "embedded", feature = "web", not(unix)))]
fn install_spill(
    kernel: ikigai_core::Kernel,
    config: &uploads::UploadConfig,
    _port: u16,
) -> (
    ikigai_core::Kernel,
    Option<(
        std::path::PathBuf,
        std::sync::Arc<ikigai_core::MemoryContentStore>,
    )>,
) {
    if !config.routes.is_empty() {
        eprintln!("ikigai: upload routes need a spill facility, which is Unix only");
        std::process::exit(2);
    }
    (kernel, None)
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
    if let Ok(Some(Mode::Version { verbose })) = parse_args() {
        print_version(verbose);
        return;
    }
    eprintln!(
        "ikigai {}: built without a transport. Rebuild with a transport feature, e.g. `--features embedded`.",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(1);
}

/// `peer:<name>` is matched against what the LAN announced, and the conventional
/// certificate directory is built from it, so a name that is not one path segment is
/// refused BEFORE any browse (ledger #741). Hermetic for exactly that reason: the refusal
/// returns before a multicast socket exists.
#[cfg(all(test, feature = "embedded", feature = "quic"))]
mod peer_name_tests {
    use super::*;

    #[test]
    fn a_peer_name_with_path_segments_is_refused_before_browsing() {
        for bad in ["plasma/../quic-plasma", "a\\b", "", "C:x", "plasma."] {
            match resolve_peer(bad, &Certs::default()) {
                Err(err) => assert!(err.contains("not a single path segment"), "{bad:?}: {err}"),
                Ok((addr, _)) => panic!("{bad:?} resolved to {addr}"),
            }
        }
    }
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
        let resolved = resolve_mounts(declined, std::path::Path::new("/home/b"), || {
            panic!("--no-config-mounts must not read the config home")
        })
        .expect("declining is not an error");
        assert!(resolved.is_empty(), "declining composes nothing");
    }

    /// Unchanged behaviour, stated as a test because the flag is only safe if the DEFAULT
    /// still inherits the machine: no flags ⇒ the config home's `mount` lines.
    #[test]
    fn no_flags_still_compose_the_machines_topology() {
        let resolved = resolve_mounts(Mounts::default(), std::path::Path::new("/home/b"), || {
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
        let resolved = resolve_mounts(flagged, std::path::Path::new("/home/b"), || {
            panic!("flags win wholesale")
        })
        .expect("flags are not an error");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].prefix, "urn:x:");
    }

    /// The mount flags a kernel-building mode parsed, for the `~` tests below.
    fn flag_mounts(args: &[&str]) -> Mounts {
        match parse_argv(argv(args).into_iter()) {
            Ok(Some(Mode::Repl(repl))) => repl.mounts,
            Ok(Some(Mode::Daemon { mounts })) => mounts,
            Ok(Some(Mode::Serve { mounts, .. })) => mounts,
            Ok(Some(Mode::Mcp { mounts, .. })) => mounts,
            other => panic!(
                "expected a kernel-building mode from {args:?}: {:?}",
                other.is_ok()
            ),
        }
    }

    /// Ledger #1381: each mount FLAG's target takes the `~` rule a `mount` line takes. No shell
    /// expands a `~` after `=`, so before this the flag dialed the literal `~/x.sock`. Every
    /// mode that builds a kernel, all three flags; a target that does not begin with `~` is
    /// left as written.
    #[test]
    fn each_mount_flag_expands_a_leading_tilde() {
        let home = std::path::Path::new("/home/b");
        let modes: [&[&str]; 4] = [&[], &["--daemon"], &["serve", "/tmp/s.sock"], &["mcp"]];
        for mode in modes {
            for flag in ["--mount", "--override", "--prefer"] {
                let args: Vec<&str> = mode
                    .iter()
                    .copied()
                    .chain([flag, "urn:x:=~/x.sock", flag, "urn:y:=quic://plasma:4433"])
                    .collect();
                let resolved =
                    resolve_mounts(flag_mounts(&args), home, || panic!("flags win wholesale"))
                        .unwrap_or_else(|e| panic!("{args:?} must resolve: {e}"));
                // `home.join`, not a literal: on Windows the join's separator is `\`.
                let expanded = home.join("x.sock");
                assert_eq!(resolved[0].target, expanded.to_str().unwrap(), "{args:?}");
                assert_eq!(resolved[1].target, "quic://plasma:4433", "{args:?}");
            }
        }
    }

    /// The config lines' refusals, by name: another user's `~bob/…`, and a `~` with no home
    /// to expand it against (an unset HOME reaches here as the empty path, see `home_dir`).
    /// The refusal names the flag the operator typed, not a config line.
    #[test]
    fn a_mount_flag_refuses_another_users_home_and_a_missing_home() {
        for flag in ["--mount", "--override", "--prefer"] {
            let e = resolve_mounts(
                flag_mounts(&[flag, "urn:x:=~bob/x.sock"]),
                std::path::Path::new("/home/b"),
                || panic!("flags win wholesale"),
            )
            .err()
            .expect("`~bob` must be refused");
            assert!(
                e.starts_with(&format!("{flag} `urn:x:=~bob/x.sock`")),
                "{e}"
            );
            assert!(e.contains("another user's home (`~bob`)"), "{e}");

            let e = resolve_mounts(
                flag_mounts(&[flag, "urn:x:=~/x.sock"]),
                std::path::Path::new(""),
                || panic!("flags win wholesale"),
            )
            .err()
            .expect("a `~` with no home must be refused");
            assert!(e.starts_with(&format!("{flag} `urn:x:=~/x.sock`")), "{e}");
            assert!(e.contains("HOME is not set"), "{e}");
        }
    }

    /// The disagreement ledger #1381 named, closed: `serve`'s self-mount guard always expanded a `~`
    /// target, the dial did not, so a flag spelling this process's own socket with `~` was
    /// skipped as own while the same flag pointing elsewhere dialed a literal path. Now the
    /// target the guard judges IS the target the dial gets.
    #[cfg(all(feature = "embedded", feature = "ipc", unix))]
    #[test]
    fn the_self_mount_guard_and_the_dial_see_one_flag_target() {
        let home = std::path::Path::new("/home/b");
        let socket = std::path::Path::new("/home/b/.ikigai/s.sock");
        for flag in ["--mount", "--override", "--prefer"] {
            let resolved = resolve_mounts(
                flag_mounts(&[
                    "serve",
                    "/home/b/.ikigai/s.sock",
                    flag,
                    "urn:x:=~/.ikigai/s.sock",
                ]),
                home,
                || panic!("flags win wholesale"),
            )
            .expect("a `~` flag target resolves");
            assert_eq!(resolved[0].target, socket.to_str().unwrap(), "{flag}");
            assert!(is_own_socket(&resolved[0].target, socket, home), "{flag}");
        }
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
            let parsed = mounts_from_config_lines(
                vec![format!("{word} urn:x:=/tmp/x.sock")],
                std::path::Path::new("/tmp/ikigai-test-home"),
            )
            .expect("the mode word round-trips through the config grammar");
            assert_eq!(parsed[0].kind, kind);
        }
    }

    /// The config-home grammar, over lines rather than a file — proof that the default
    /// posture still parses what a machine's `config.toml` actually carries (the line here
    /// is the one on plasma that started #410).
    #[test]
    fn a_config_home_mount_line_still_parses() {
        let mounts = mounts_from_config_lines(
            vec![
                "prefer urn:iki:store:=/Users/x/.ikigai/gonk.sock".to_string(),
                "alias urn:cal:=quic://bug.local:4433 ~/.config/ikigai/quic-bug".to_string(),
            ],
            std::path::Path::new("/Users/x"),
        )
        .expect("both lines parse");
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].kind, ikigai_embedded::MountKind::Prefer);
        assert_eq!(mounts[0].prefix, "urn:iki:store:");
        assert_eq!(mounts[1].kind, ikigai_embedded::MountKind::Alias);
        let expanded = std::path::Path::new("/Users/x").join(".config/ikigai/quic-bug");
        assert_eq!(
            mounts[1].certs.cert_dir.as_deref(),
            expanded.to_str(),
            "a config line's `~` is expanded against the home it was handed"
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

    /// ledger #1283: a layer door's names live under three prefixes. One flag names all
    /// three, ONE `--cert-dir` after it covers them, and they resolve to one spec per prefix
    /// over ONE shared resolver, which is one connection.
    #[test]
    fn one_mount_flag_serves_several_prefixes_over_one_resolver() {
        let mounts = mounts_of(&[
            "--prefer",
            "urn:layer:,urn:layers:,urn:collab:=quic://127.0.0.1:1",
            "--cert-dir",
            "/certs/hub",
        ]);
        assert_eq!(mounts.len(), 1, "one flag is one mount");
        assert_eq!(mounts[0].certs.cert_dir.as_deref(), Some("/certs/hub"));
        // `--prefer`, so nothing dials: what is under test is the expansion, not a peer.
        let specs = resolve_mount(mounts[0].clone()).expect("a prefer mount resolves lazily");
        let prefixes: Vec<&str> = specs.iter().map(|spec| spec.prefix.as_str()).collect();
        assert_eq!(prefixes, ["urn:layer:", "urn:layers:", "urn:collab:"]);
        for spec in &specs[1..] {
            assert!(
                std::sync::Arc::ptr_eq(&specs[0].resolver, &spec.resolver),
                "{} shares the first prefix's resolver",
                spec.prefix
            );
            assert_eq!(spec.origin, "quic://127.0.0.1:1");
            assert_eq!(spec.kind, ikigai_embedded::MountKind::Prefer);
        }
    }

    /// A malformed prefix list stops the parse, in every flag and in a config line, rather
    /// than reading an empty prefix (which would match every IRI) or a doubled one.
    /// ledger #1337: core answers `urn:kernel:` itself, ahead of every mount, so a mount,
    /// override or prefer under it never applies, and `--override urn:kernel:=quic://door`
    /// read the LOCAL manifold as if it were the door's. Refused at parse time, naming the
    /// reserved prefix, in every flag, every mode and the config home's `mount` line.
    #[test]
    fn a_mount_under_the_kernels_reserved_prefix_is_refused() {
        for spec in [
            "urn:kernel:=quic://door:4433",
            "urn:kernel:actions=quic://door:4433",
            "urn:kernel=quic://door:4433",
            "urn:a:,urn:kernel:=quic://door:4433",
        ] {
            for flag in ["--mount", "--override", "--prefer"] {
                let err = match parse_argv(argv(&[flag, spec]).into_iter()) {
                    Err(e) => e,
                    Ok(_) => panic!("{flag} {spec} parsed"),
                };
                assert!(
                    err.contains(flag)
                        && err.contains("`urn:kernel:`")
                        && err.contains("--connect"),
                    "{flag} {spec}: {err}"
                );
            }
            for mode in [&["serve", "/tmp/x.sock"][..], &["mcp"][..]] {
                let mut args = mode.to_vec();
                args.extend(["--override", spec]);
                assert!(parse_argv(argv(&args).into_iter()).is_err(), "{args:?}");
            }
            let line = format!("override {spec} ~/certs");
            let err = mounts_from_config_lines(vec![line.clone()], std::path::Path::new("/h"))
                .map(|_| ())
                .expect_err(&line);
            assert!(err.contains("`urn:kernel:`"), "{line}: {err}");
        }
        // A prefix that merely CONTAINS the kernel's namespace still mounts: everything else
        // under it goes to the peer, and the kernel's own names stay the kernel's.
        assert_eq!(mount_prefixes("urn:"), Ok(vec!["urn:"]));
        assert_eq!(mount_prefixes("urn:kernels:"), Ok(vec!["urn:kernels:"]));
    }

    #[test]
    fn an_empty_or_doubled_prefix_in_a_list_is_refused() {
        for spec in [
            "urn:a:,,urn:b:=quic://h:1",
            "urn:a:,=quic://h:1",
            ",urn:a:=quic://h:1",
            "urn:a:,urn:a:=quic://h:1",
        ] {
            for flag in ["--mount", "--override", "--prefer"] {
                let err = match parse_argv(argv(&[flag, spec]).into_iter()) {
                    Err(e) => e,
                    Ok(_) => panic!("{flag} {spec} parsed"),
                };
                assert!(
                    err.contains(flag) && (err.contains("empty") || err.contains("twice")),
                    "{flag} {spec}: {err}"
                );
            }
            for mode in [&["serve", "/tmp/x.sock"][..], &["mcp"][..]] {
                let mut args = mode.to_vec();
                args.extend(["--override", spec]);
                assert!(parse_argv(argv(&args).into_iter()).is_err(), "{args:?}");
            }
            let line = format!("override {spec} ~/certs");
            assert!(
                mounts_from_config_lines(vec![line.clone()], std::path::Path::new("/h")).is_err(),
                "{line}"
            );
        }
        // A single prefix is passed through as before, an empty one included.
        assert_eq!(mount_prefixes("urn:a:"), Ok(vec!["urn:a:"]));
        assert_eq!(mount_prefixes(""), Ok(vec![""]));
    }

    /// The config home's `mount` line takes the same list, with its cert directory.
    #[test]
    fn a_config_mount_line_names_several_prefixes() {
        let mounts = mounts_from_config_lines(
            vec!["override urn:layer:,urn:layers:=quic://door:4434 ~/certs/hub".to_string()],
            std::path::Path::new("/home/b"),
        )
        .expect("the line parses");
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].prefix, "urn:layer:,urn:layers:");
        let expanded = std::path::Path::new("/home/b").join("certs/hub");
        assert_eq!(mounts[0].certs.cert_dir.as_deref(), expanded.to_str());
    }

    /// ledger #1379: a config-home `mount` line's SOCKET takes the `~` its cert directory
    /// always did, in every mode. It was dialed as the literal path `~/x.sock`.
    #[test]
    fn a_config_mount_lines_socket_expands_a_leading_tilde() {
        for mode in ["alias", "mount", "override", "prefer"] {
            let mounts = mounts_from_config_lines(
                vec![format!("{mode} urn:x:=~/.ikigai/gonk.sock ~/certs")],
                std::path::Path::new("/home/b"),
            )
            .expect("the line parses");
            let home = std::path::Path::new("/home/b");
            let socket = home.join(".ikigai/gonk.sock");
            assert_eq!(mounts[0].target, socket.to_str().unwrap(), "{mode}");
            assert_eq!(
                mounts[0].certs.cert_dir.as_deref(),
                home.join("certs").to_str()
            );
        }
        // A target that is not a path is never touched.
        for target in ["quic://bug.local:4433", "peer:plasma", "/abs/x.sock"] {
            let mounts = mounts_from_config_lines(
                vec![format!("prefer urn:x:={target}")],
                std::path::Path::new("/home/b"),
            )
            .expect("the line parses");
            assert_eq!(mounts[0].target, target);
        }
    }

    /// …and a `~` the rule cannot expand stops the start, naming the line, rather than
    /// dialing (or opening) a path nobody meant. An unset `HOME` reaches the parser as the
    /// empty path ([`home_dir`]).
    #[test]
    fn a_config_mount_lines_unexpandable_tilde_is_refused_by_line() {
        let refused = |line: &str, home: &str| match mounts_from_config_lines(
            vec![line.to_string()],
            std::path::Path::new(home),
        ) {
            Err(e) => e,
            Ok(_) => panic!("`{line}` with home `{home}` should be refused"),
        };
        let err = refused("prefer urn:x:=~bob/x.sock", "/home/b");
        assert!(err.contains("mount `prefer urn:x:=~bob/x.sock`"), "{err}");
        assert!(err.contains("another user's home"), "{err}");
        let err = refused("prefer urn:x:=~/x.sock", "");
        assert!(err.contains("HOME is not set"), "{err}");
        let err = refused("alias urn:x:=quic://bug.local:4433 ~/certs", "");
        assert!(
            err.contains("`~/certs`") && err.contains("HOME is not set"),
            "{err}"
        );
    }

    /// The end to end case the ledger item reported: a `~` socket in a config line DIALS the
    /// expanded path. The home is a scratch directory, never `$HOME`.
    #[cfg(all(feature = "ipc", unix))]
    #[test]
    fn a_config_mount_lines_tilde_socket_dials_the_peer() {
        use ikigai_core::{builtins, EndpointSpace, Exact, Kernel};
        let home = std::env::temp_dir();
        let name = format!("ikigai-tilde-{}.sock", std::process::id());
        let path = home.join(&name);
        let _ = std::fs::remove_file(&path);
        let kernel = Kernel::new(std::sync::Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:upper"), builtins::to_upper()),
        ));
        let served = path.clone();
        std::thread::spawn(move || {
            let _ = ikigai_ipc::serve(kernel, &served);
        });
        // Wait until the socket is CONNECTABLE, not merely present (see the test below).
        for _ in 0..250 {
            if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mut mounts = mounts_from_config_lines(vec![format!("alias urn:test:=~/{name}")], &home)
            .expect("the line parses");
        let spec = resolve_one_mount(mounts.remove(0)).expect("the expanded socket dials");
        let entries = spec.resolver.entries().expect("the peer lists its catalog");
        assert!(
            entries.iter().any(|e| e.endpoint == "to-upper"),
            "the mount reached the peer at the expanded path: {entries:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The other half of prefer-mount catalog citizenship: `entries()` dials a
    /// peer that has never been used, so `list` shows a prefer-mounted
    /// namespace WITHOUT a prior resolution through it. (Before this, the
    /// REPL's list was blind to an undialed prefer mount — the same
    /// chicken-and-egg cli #270 fixed for mcp, which the ikigai-deno
    /// satellite then hit interactively.)
    #[cfg(all(feature = "ipc", unix))]
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
        // Give the listener a beat to bind — and wait for it to be CONNECTABLE, not merely
        // for the path to exist: `bind(2)` creates the path before `listen(2)` runs, and a
        // dial in that window is refused. That window failed this test under a loaded
        // `--all-features` run (twice in a row, 2026-10-07), once a second test in this
        // binary started serving a socket alongside it.
        for _ in 0..250 {
            if std::os::unix::net::UnixStream::connect(&path).is_ok() {
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
        let spec = resolve_one_mount(mount).expect("prefer resolves lazily");
        let entries = spec
            .resolver
            .entries()
            .expect("entries() dials the live peer");
        assert!(
            entries.iter().any(|e| e.endpoint == "to-upper"),
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
        let spec = resolve_one_mount(mount).expect("a prefer mount must not fail at startup");
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

    /// A fixed home: the guard's `~` expansion is against whatever home it is HANDED,
    /// so the test needs no `$HOME` and cannot race the test that redirects it.
    const HOME: &str = "/tmp/ikigai-test-home";

    /// The config home is shared machine-wide, so the serving process reads the very
    /// mount lines that point everyone ELSE at its socket — those must read as "own"
    /// however the path is spelled, while genuinely-remote targets must not.
    #[test]
    fn own_socket_is_detected_across_spellings() {
        let home = Path::new(HOME);
        let socket = Path::new("/tmp/ikigai-test/serve.sock");
        assert!(is_own_socket("/tmp/ikigai-test/serve.sock", socket, home));
        // A lexically-different spelling of the same path.
        assert!(is_own_socket("/tmp/ikigai-test/./serve.sock", socket, home));
        assert!(!is_own_socket("/tmp/ikigai-test/other.sock", socket, home));
        // Remote targets are never "own" — the IPC server's identity is a Unix path.
        assert!(!is_own_socket("quic://plasma.local:4433", socket, home));
        assert!(!is_own_socket("peer:plasma", socket, home));
    }

    /// `~` in a config line expands against the home the guard is handed before comparing.
    #[test]
    fn tilde_spelling_matches_the_expanded_socket() {
        let home = Path::new(HOME);
        let socket = home.join(".ikigai-test.sock");
        assert!(is_own_socket("~/.ikigai-test.sock", &socket, home));
        // …and only against that home: a socket under another home is not this one.
        let elsewhere = Path::new("/tmp/ikigai-other-home").join(".ikigai-test.sock");
        assert!(!is_own_socket("~/.ikigai-test.sock", &elsewhere, home));
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
        let spec = resolve_one_mount(Mount {
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
mod config_home_flag_tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn take(args: &[&str]) -> (Result<Option<PathBuf>, String>, Vec<String>) {
        let mut args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let found = take_config_home(
            &mut args,
            Some(Path::new("/work/here")),
            Some(Path::new("/home/b")),
        );
        (found, args)
    }

    /// The flag leaves argv in either spelling, anywhere, so every mode's parser sees the rest
    /// unchanged — and the directory comes back absolute.
    #[test]
    fn the_flag_is_taken_out_of_every_position_and_made_absolute() {
        let (found, rest) = take(&["--config-home", "/abs/cfg", "-c", "list"]);
        assert_eq!(found, Ok(Some(PathBuf::from("/abs/cfg"))));
        assert_eq!(rest, ["-c", "list"]);

        let (found, rest) = take(&["serve", "/tmp/s.sock", "--config-home=./cfg"]);
        assert_eq!(found, Ok(Some(PathBuf::from("/work/here/cfg"))));
        assert_eq!(rest, ["serve", "/tmp/s.sock"]);

        let (found, _) = take(&["mcp", "--config-home", "~/scratch/cfg"]);
        assert_eq!(found, Ok(Some(PathBuf::from("/home/b/scratch/cfg"))));

        let (found, rest) = take(&["-c", "list"]);
        assert_eq!(found, Ok(None));
        assert_eq!(rest, ["-c", "list"]);
    }

    #[test]
    fn a_missing_or_doubled_directory_is_refused() {
        assert!(take(&["--config-home"])
            .0
            .unwrap_err()
            .contains("needs <dir>"));
        assert!(take(&["--config-home", "--plain"])
            .0
            .unwrap_err()
            .contains("--plain"));
        assert!(take(&["--config-home="])
            .0
            .unwrap_err()
            .contains("needs <dir>"));
        let twice = take(&["--config-home", "/a", "--config-home", "/b"])
            .0
            .unwrap_err();
        assert!(twice.contains("/a") && twice.contains("/b"), "{twice}");
        // The same directory twice, in two spellings, is one.
        assert_eq!(
            take(&["--config-home", "/work/here/cfg", "--config-home=cfg"]).0,
            Ok(Some(PathBuf::from("/work/here/cfg")))
        );
    }

    /// ledger #1379: the directory flags take the workspace's one `~` rule, the one every
    /// config-home path key takes: a bare `~` is the home, another user's `~name` and a `~`
    /// with no home are refused by name rather than resolved against the working directory.
    #[test]
    fn the_directory_flags_take_the_shared_tilde_rule() {
        let (found, _) = take(&["--config-home", "~"]);
        assert_eq!(found, Ok(Some(PathBuf::from("/home/b"))));
        let err = take(&["--config-home", "~bob/cfg"]).0.unwrap_err();
        assert!(err.starts_with("--config-home "), "{err}");
        assert!(err.contains("another user's home"), "{err}");
        let mut args = vec!["--files".to_string(), "~/ws".to_string()];
        let err = take_files(&mut args, Some(Path::new("/work/here")), None).unwrap_err();
        assert!(err.contains("HOME is not set"), "{err}");
    }

    fn take_files_from(args: &[&str]) -> (Result<Option<PathBuf>, String>, Vec<String>) {
        let mut args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let found = take_files(
            &mut args,
            Some(Path::new("/work/here")),
            Some(Path::new("/home/b")),
        );
        (found, args)
    }

    /// ledger #1285: `--files <dir>` in any mode, absolute, out of argv before the mode is
    /// parsed; twice with two directories is refused, and beside `--connect` (which builds
    /// no kernel, so has no file root) it is refused rather than ignored.
    #[test]
    fn files_is_taken_absolute_from_every_mode() {
        let (found, rest) = take_files_from(&["serve", "quic://0.0.0.0:4434", "--files", "ws"]);
        assert_eq!(found, Ok(Some(PathBuf::from("/work/here/ws"))));
        assert_eq!(rest, ["serve", "quic://0.0.0.0:4434"]);
        let (found, rest) = take_files_from(&["--files=~/door/ws", "-c", "list"]);
        assert_eq!(found, Ok(Some(PathBuf::from("/home/b/door/ws"))));
        assert_eq!(rest, ["-c", "list"]);
        let (found, _) = take_files_from(&["mcp", "--files", "/abs/ws"]);
        assert_eq!(found, Ok(Some(PathBuf::from("/abs/ws"))));
        assert_eq!(take_files_from(&["-c", "list"]).0, Ok(None));

        let twice = take_files_from(&["--files", "/a", "--files", "/b"])
            .0
            .unwrap_err();
        assert!(twice.contains("one file root"), "{twice}");
        assert!(take_files_from(&["--files"])
            .0
            .unwrap_err()
            .contains("--files needs <dir>"));
        let connect = take_files_from(&["--connect", "/tmp/s.sock", "--files", "/a"])
            .0
            .unwrap_err();
        assert!(connect.contains("--connect"), "{connect}");
    }
}

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
                matches!(parse(&args), Ok(Some(Mode::Version { .. }))),
                "the version flag must be answered in every arm, not just one: {args:?}"
            );
        }
    }

    /// `--verbose` beside the flag asks for the linked crates, in any order; the flag alone
    /// stays the one line a script reads (ledger #1338).
    #[test]
    fn verbose_asks_for_the_linked_crates() {
        for args in [
            vec!["--version", "--verbose"],
            vec!["--verbose", "-V"],
            vec!["serve", "--version", "--verbose"],
        ] {
            assert!(
                matches!(parse(&args), Ok(Some(Mode::Version { verbose: true }))),
                "{args:?}"
            );
        }
        assert!(matches!(
            parse(&["--version"]),
            Ok(Some(Mode::Version { verbose: false }))
        ));
    }

    /// The upgrade an unresolved name suggests installs THIS build's features (ledger #288):
    /// a `quic`/`web` host told to run a plain `cargo install` would lose its doors.
    #[cfg(feature = "embedded")]
    #[test]
    fn the_upgrade_command_keeps_this_builds_features() {
        let command = upgrade_command();
        assert!(
            command.starts_with("cargo install --locked ikigai-cli"),
            "{command}"
        );
        for (on, feature) in [
            (cfg!(feature = "quic"), "quic"),
            (cfg!(feature = "web"), "web"),
            (cfg!(feature = "store"), "store"),
        ] {
            let named = command
                .split_once(" --features ")
                .is_some_and(|(_, list)| list.split(',').any(|f| f == feature));
            assert_eq!(named, on, "`{feature}` in {command}");
        }
        assert_eq!(
            command.contains("--no-default-features"),
            !cfg!(feature = "ipc"),
            "{command}"
        );
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
///   family but not for THIS path passes the floor and is refused inside `invoke`. Since core
///   0.1.92 (ledger #20, #559) that is a TIMED event noted `(FAILED_NOTE, "denied")` and never
///   `DENIED_NOTE`: the endpoint was entered and returned `Err`. Through 0.1.91 it left no
///   event at all, so the only witness was the disk; the disk is still asserted (no file, no
///   directory), and now the trace says which gate refused by its key alone.
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
        ArgRef, Capability, Error, Iri, Kernel, Request, TraceEvent, Tracer, Verb, DEFAULTED_NOTE,
        DENIED_NOTE, FAILED_NOTE,
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
        let engine = with_profiles(
            Engine::new(Arc::clone(&kernel)).with_as_of_doors(ikigai_embedded::time_doors()),
        );
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
    /// another path, clears the floor and is refused inside `invoke` — one TIMED trace event
    /// noted `("failed", "denied")` (core 0.1.92), never the floor's `DENIED_NOTE`, and nothing
    /// on the disk.
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
            before + 1,
            "one event, the endpoint's own refusal: {after:?}"
        );
        let refusal = &after[before];
        assert_eq!(refusal.target, "urn:file:someone-else/secret.txt");
        // Since ikigai-fs 0.2 the file Sink declares an optional `encoding` with a default
        // (utf-8), and the kernel notes every declared default it fills (`DEFAULTED_NOTE`), so
        // the event carries that note beside the refusal. Which gate refused is still told by
        // `FAILED_NOTE` (never `DENIED_NOTE`) and by the timing asserted below.
        assert_eq!(
            refusal.notes,
            vec![
                (FAILED_NOTE.to_string(), "denied".to_string()),
                (DEFAULTED_NOTE.to_string(), "encoding".to_string()),
            ],
            "the module refused (it ran and failed), not the floor: {refusal:?}"
        );
        assert!(
            refusal.started.is_some() && refusal.ended.is_some(),
            "entered, so timed: {refusal:?}"
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

    /// ★ **`as-of=` over the real composition** (ledger #532): the host's own time doors,
    /// injected per line by the engine, pin BOTH clocks this host serves — `urn:tz:now` (which
    /// read `Utc::now()` directly until 0.1.29) and `urn:time:now` — and the next line is live
    /// again. The kernel here is `ikigai_embedded::kernel()`, which carries a `SystemClock`, so
    /// "live" is the machine's clock and the pin is the only way the digits could match.
    #[test]
    fn as_of_pins_the_hosts_clocks_for_one_line() {
        let s = session("as-of");
        assert_eq!(
            run(
                &s.engine,
                "source urn:tz:now zone=UTC as-of=2026-09-25T18:00Z"
            ),
            Ok("2026-09-25T18:00:00+00:00".to_string())
        );
        // Two different instants, two different corridors, two different answers — so the
        // HH:MM clock is pinned too, whatever zone the machine running this is in.
        let six = run(&s.engine, "source urn:time:now as-of=2026-09-25T18:00Z").unwrap();
        let seven = run(&s.engine, "source urn:time:now as-of=2026-09-25T19:00Z").unwrap();
        assert_ne!(six, seven);
        assert_eq!(
            run(&s.engine, "source urn:time:now as-of=2026-09-25T18:00Z"),
            Ok(six),
            "same instant, same corridor, same answer"
        );
        // The chain is per line: without `as-of=` the zoned clock is live again.
        let live = run(&s.engine, "source urn:tz:now zone=UTC").unwrap();
        assert!(!live.starts_with("2026-09-25T18:00:00"), "{live}");
        let _ = std::fs::remove_dir_all(s.root.parent().expect("scratch"));
    }
}

#[cfg(all(test, feature = "embedded"))]
mod passkey_flag_tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Option<Mode>, String> {
        parse_argv(args.iter().map(|s| s.to_string()))
    }

    /// The relying party is validated at startup: a malformed one refuses to serve rather than
    /// serving a page that fails at the first tap, and an origin with no id is refused.
    #[test]
    fn the_passkey_relying_party_flags_are_validated_at_startup() {
        assert!(parse(&["serve", "--http", "8099", "--passkey-rp-id", "edge.test"]).is_ok());
        assert!(parse(&[
            "serve",
            "--http",
            "8099",
            "--passkey-rp-id",
            "edge.test",
            "--passkey-origin",
            "https://login.edge.test",
        ])
        .is_ok());
        let err = parse(&["serve", "--passkey-rp-id", "https://edge.test"]).err();
        assert!(err.is_some_and(|e| e.contains("bare domain")));
        let err = parse(&["serve", "--passkey-origin", "https://edge.test"]).err();
        assert!(err.is_some_and(|e| e.contains("--passkey-rp-id")));
        assert!(
            parse(&["serve", "--passkey-rp-id"]).is_err(),
            "needs a value"
        );
    }
}

/// ★ Ledger #849, at the wrapper that is this binary's copy of the bug's shape: a `--prefer`
/// mount goes through [`LazyResolver`], which is exactly what `ikigai-web`'s `LazyIpcResolver`
/// was when it dropped every caller's capability at the wire. Driven over a REAL socket to a
/// peer that checks its scope at runtime, so what is asserted is what the PEER saw.
#[cfg(all(test, unix, feature = "embedded", feature = "ipc"))]
mod prefer_mount_capability_tests {
    use super::*;
    use ikigai_core::{
        Capability, Description, EndpointSpace, Error, Exact, FnEndpoint, Iri, Kernel, ReprType,
        Representation, Request, Verb,
    };
    use ikigai_resolve::Resolver;
    use std::sync::Arc;

    const SECRET: &str = "urn:cap:secret";

    /// A peer whose one endpoint declares nothing and checks `SECRET` itself, answering with
    /// the scopes it received.
    fn peer() -> Kernel {
        Kernel::new(Arc::new(
            EndpointSpace::new().bind(
                Exact::new("urn:peer:scoped"),
                FnEndpoint::new("scoped", |inv| {
                    if !inv.capability.allows(SECRET) {
                        return Err(Error::Denied(format!("the peer wants {SECRET}")));
                    }
                    let seen = inv.capability.scopes().map_or("root".to_string(), |s| {
                        s.iter().cloned().collect::<Vec<_>>().join(" ")
                    });
                    Ok(Representation::new(
                        ReprType::new("text/plain"),
                        seen.into_bytes(),
                    ))
                })
                .with_description(Description::new("scoped").verb(Verb::Source)),
            ),
        ))
    }

    #[test]
    fn a_prefer_mount_carries_a_narrowed_capability_to_its_peer() {
        let path = std::env::temp_dir().join(format!("ikc-{}-prefer.sock", std::process::id()));
        let served = path.clone();
        // The listener runs for the life of the test process; `serve` only returns on a dead
        // listener, and nothing here kills it.
        std::thread::spawn(move || ikigai_ipc::serve(peer(), &served));
        // Wait for a CONNECTABLE socket, not merely an existing path (up to 5s).
        let mut tries = 0;
        while std::os::unix::net::UnixStream::connect(&path).is_err() {
            tries += 1;
            assert!(tries < 500, "the peer never bound");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let spec = resolve_one_mount(Mount {
            prefix: "urn:peer:".to_string(),
            target: path.display().to_string(),
            certs: Certs::default(),
            kind: ikigai_embedded::MountKind::Prefer,
        })
        .expect("a prefer mount never dials at startup");
        let local = Kernel::new(Arc::new(ikigai_resolve::MountedRemote::overriding(
            spec.resolver,
            "urn:peer:",
            "test://prefer",
        )));
        let read = Request::new(Verb::Source, Iri::parse("urn:peer:scoped").unwrap());

        let (answer, _) = Resolver::issue_as(&local, read.clone(), &Capability::scoped([SECRET]))
            .expect("a sufficient narrowed capability crosses the prefer mount");
        assert_eq!(
            String::from_utf8_lossy(&answer.bytes),
            SECRET,
            "the peer saw the caller's capability, not root"
        );
        let refused = Resolver::issue_as(&local, read, &Capability::scoped(["urn:cap:other"]));
        assert!(
            matches!(&refused, Err(Error::Denied(m)) if m.contains("the peer wants")),
            "an insufficient capability is refused BY THE PEER: {refused:?}"
        );
        let _ = std::fs::remove_file(&path);
    }
}

/// `ikigai mcp`'s authority rules (ledger #1830): no root default, and a live reload that
/// never widens past the session's start. The binary's own tests are `tests/mcp_principals.rs`.
#[cfg(all(test, feature = "embedded"))]
mod mcp_authority_tests {
    use super::*;
    use ikigai_core::Capability;

    #[test]
    fn naming_no_grant_and_no_scope_is_refused_never_root() {
        let refused = mcp_capability_in(&[], &[], |_| Vec::new()).unwrap_err();
        assert!(refused.contains("--root"), "{refused}");
        let Err(refused) = mcp_session(&McpAuthority::default()) else {
            panic!("no authority named must not serve");
        };
        assert!(refused.contains("--principal"), "{refused}");
        let Ok(root) = mcp_session(&McpAuthority {
            root: true,
            ..McpAuthority::default()
        }) else {
            panic!("root by request");
        };
        assert!(root.capability.is_root());
    }

    #[test]
    fn a_reload_narrows_restores_and_never_widens_past_the_start() {
        let start = Capability::scoped(["urn:cap:a", "urn:cap:b"]);
        let (narrowed, waiting) = mcp_reloaded(&start, &Capability::scoped(["urn:cap:a"]));
        assert_eq!(narrowed, Capability::scoped(["urn:cap:a"]));
        assert!(waiting.is_empty());
        let (restored, _) = mcp_reloaded(&start, &start);
        assert_eq!(restored, start);
        let (kept, waiting) = mcp_reloaded(
            &start,
            &Capability::scoped(["urn:cap:a", "urn:cap:b", "urn:cap:c"]),
        );
        assert_eq!(kept, start);
        assert_eq!(waiting, vec!["urn:cap:c".to_string()]);
        // An agent session keeps its principal across a reload.
        let agent = start.with_principal("urn:example:agent").unwrap();
        let (reloaded, _) = mcp_reloaded(&agent, &agent);
        assert_eq!(reloaded.principal(), Some("urn:example:agent"));
    }
}

/// The socket door's reading of the principals table's accounts (ledger #2139).
#[cfg(all(test, feature = "embedded", feature = "ipc", unix))]
mod shared_socket_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn me() -> u32 {
        // SAFETY: `getuid` reads a process attribute and cannot fail.
        unsafe { libc::getuid() }
    }

    /// A grants file only its owner (this user) can write, holding `account` on a machine
    /// principal, and the parsed accounts.
    fn grants(
        name: &str,
        account: &str,
    ) -> (std::path::PathBuf, Vec<ikigai_embedded::agents::SocketPeer>) {
        let dir = std::env::temp_dir().join(format!("ikss-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.join("grants.json");
        let text = format!(
            r#"{{
              "brian": ["urn:cap:demo:read", "urn:cap:demo:write"],
              "node": ["urn:cap:demo:read"],
              "principals": {{
                "urn:example:brian": {{"kind": "person", "grant": "brian"}},
                "urn:example:node": {{
                  "kind": "machine", "acts_for": "urn:example:brian", "grant": "node", {account}
                }}
              }}
            }}"#
        );
        std::fs::write(&path, &text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let peers = ikigai_embedded::agents::socket_peers(&text).unwrap();
        (path, peers)
    }

    fn own_gid(path: &std::path::Path) -> String {
        std::fs::metadata(path).unwrap().gid().to_string()
    }

    #[test]
    fn another_account_is_admitted_bounded_and_named_and_nobody_else() {
        let other = me().wrapping_add(1);
        let (path, peers) = grants("ok", &format!(r#""uid": {other}"#));
        let shared = shared_socket_from(&path, peers, Some(own_gid(&path)))
            .unwrap()
            .expect("an account is named");
        assert_eq!(
            shared.accounts,
            [format!("uid {other} as urn:example:node")]
        );
        let node = shared.admissions.admit(me(), Some(other)).unwrap();
        assert_eq!(node.principal(), Some("urn:example:node"));
        assert!(!node.ceiling().allows("urn:cap:demo:write"));
        assert!(shared
            .admissions
            .admit(me(), Some(me()))
            .unwrap()
            .ceiling()
            .is_root());
        assert!(shared
            .admissions
            .admit(me(), Some(other.wrapping_add(1)))
            .is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn the_door_s_own_user_cannot_be_bounded_as_an_account() {
        let (path, peers) = grants("self", &format!(r#""uid": {}"#, me()));
        let refused = shared_socket_from(&path, peers, Some(own_gid(&path)))
            .err()
            .unwrap();
        assert!(
            refused.contains("same-uid client is the owner"),
            "{refused}"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn an_account_with_no_socket_group_or_no_such_user_stops_the_door() {
        let (path, peers) = grants("nogroup", &format!(r#""uid": {}"#, me().wrapping_add(1)));
        let refused = shared_socket_from(&path, peers, None).err().unwrap();
        assert!(refused.contains("ipc.group"), "{refused}");
        let (path2, peers) = grants("nouser", r#""user": "no-such-ikigai-account-2139""#);
        let refused = shared_socket_from(&path2, peers, Some(own_gid(&path2)))
            .err()
            .unwrap();
        assert!(refused.contains("no user named"), "{refused}");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(path2.parent().unwrap());
    }
}
