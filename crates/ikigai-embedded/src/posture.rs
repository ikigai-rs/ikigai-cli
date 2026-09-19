//! `urn:host:posture` — what THIS PROCESS composed at startup, and what it trusts.
//!
//! ## The gap this fills
//!
//! `urn:kernel:catalog` says what is BOUND. `urn:kernel:actions` says what may be INVOKED
//! under a capability. **Neither says "I composed these two mounts from the config home,
//! from these targets, and I loaded these two client certificates."** That configuration
//! fact is what five separate items turned on in one week (ledger #408 a 120s manifold
//! caused by a peer that had composed two mounts back at its own caller, #410 the fix,
//! #418 a banner printing `6 mount(s)` and answering nothing, #421 a retirement decision
//! hinging on whether a cert set had enrolled clients, #426 two doors printing `1 trusted
//! client cert(s)` with opposite meanings) — and in every one of them **the only way to
//! learn it was to be present at startup, grep a log, or restart the process.** A banner is
//! written once, to stderr, and cannot be asked. This is the one class of fact about a
//! running kernel that was not a resource, in a system whose thesis is that everything is.
//!
//! ## ★ It reports what the PROCESS composed, never what the disk now says
//!
//! Every fact here comes from the value the door built at startup and handed to
//! [`set_posture`]. Nothing in this module reads `config.toml`, a certificate directory, or
//! `clients.json`. That is the whole point: a resource that re-read the disk would disagree
//! with what the server actually trusts the moment anyone edited a file, and "the config
//! says X while the process does Y" is a worse lie than a count (ledger #428, and #416 on
//! the three config readers).
//!
//! So the freshness of each fact is part of the answer, and both faces say it:
//!
//! | fact | when it was decided | can it change without a restart? |
//! |---|---|---|
//! | the door, the surface, the authority | startup | no |
//! | the composed mounts | startup (`mounts_or_config` is wholesale) | no |
//! | the trusted certificate SET | startup (the PEMs are read once and handed to the transport) | no |
//! | **which authority each certificate gets** | **per connection** | **yes — `clients.json` is re-read on every connection** |
//!
//! The last row is the one a reader gets wrong, so the door NAMES it: every fact a door
//! re-reads while it runs goes in [`Posture::reloads`], and both faces print those beside
//! the startup facts rather than letting one "as of startup" line cover both. This module
//! reports the posture MODE (frozen: the process chose its minter once) and explicitly not
//! the live authority map — `enrolled: N` is the count as of the startup read, and the
//! authoritative answer to "who may connect, with what authority" is `clients.json` at
//! connection time, which is what makes editing it a revocation (see [`crate::clients`]).
//!
//! ## ★ Capability-gated, and the reasoning is the PATHS
//!
//! [`CAP_HOST_POSTURE`] gates every face. A fingerprint is **not** the sensitive part: it
//! is a hash of a public certificate, sent in the clear at every handshake and useless
//! without the private key. The sensitive part is the **paths** — `…/quic/calendar/clients/`,
//! `~/.ikigai/gonk.sock`, a mount target naming another machine — which describe the
//! operator's disk and the topology reachable from this process. A public HTTP face must not
//! hand a stranger that, so the door's public (empty-scope) capability is refused, and an
//! operator who wants posture on a monitoring door grants the scope deliberately.
//!
//! **Not `urn:cap:kernel:inspect`**, which gates the catalog, the manifold and health: that
//! is the grant every agent holds in order to have a tool list at all, and folding the disk
//! layout into it would hand the layout to every such agent. A separate scope is the only
//! way to hold one without the other.
//!
//! ## Why `urn:host:` and not `urn:kernel:`
//!
//! `urn:kernel:*` (catalog, actions, scheduler, cache, cut, validate, aliases) is
//! KERNEL-scoped — about the resolver. Posture is a fact about the PROCESS that configured
//! one: its door, its topology, its trust. `urn:host:*` is already exactly that family
//! (`info`, `identity`, `history`, `health`, `heartbeat`, `demo`), and `urn:kernel:*` is
//! intercepted by core as intrinsics before any space sees it, so a binding there would
//! never be reached at all.

use std::sync::Mutex;

use ikigai_core::{
    ActionSpec, ArgSpec, Description, FnEndpoint, Invocation, ReprType, Representation, Verb,
};

use crate::XSD_STRING;

/// The scope that reading this host's posture requires.
///
/// Deliberately its own scope rather than `urn:cap:kernel:inspect` — see the
/// module note: inspect is the manifold grant, and the paths in a posture report are a
/// strictly bigger disclosure than the tool list.
pub const CAP_HOST_POSTURE: &str = "urn:cap:host:posture";

/// What a door composed, as of startup. One value per process, recorded by
/// [`set_posture`].
///
/// Built by the door that composed the kernel, which is the only code that knows all of it
/// — and built from the SAME values the startup banner prints, so the banner and this
/// resource cannot drift into two spellings of one fact. (That drift is the defect this
/// whole family came out of: see [`mount_lines`].)
#[derive(Clone, Debug, Default)]
pub struct Posture {
    /// The door this process answers on, in the spelling an operator would type:
    /// `quic://0.0.0.0:4433`, a socket path, `http://127.0.0.1:8080` — or a plain phrase
    /// for the modes that have no door (`in-process`, `stdio (mcp)`).
    ///
    /// ★ **There is deliberately no `nature` field beside this.** `urn:host:info` reports
    /// the kernel's nature and this resource must not be a second answer to a question that
    /// already has one — a duplicated fact that CAN drift is the whole defect class this
    /// endpoint came out of. The door says more anyway: `quic://…` versus a socket path
    /// versus `http://…` distinguishes the transports more precisely than a label does, and
    /// it names the address as well as the kind.
    ///
    /// ⚠ And the two WOULD have disagreed. `serve_ipc` passes `"Remote (IPC)"` to
    /// [`trusted_kernel_with_mounts`](crate::trusted_kernel_with_mounts), which discards it
    /// (`let _ = nature;`) and composes `root_space`, whose nature is hard-coded
    /// `"Embedded (Native)"` — so an IPC door's `urn:host:info` says `Embedded (Native)`
    /// today while the door is IPC. Reported up rather than fixed here: threading the
    /// nature through `root_space` changes what the daemon Brian runs reports to every
    /// client that reads it, which deserves its own item rather than riding on a new
    /// resource.
    pub door: String,
    /// The topology, and which of the three mount postures produced it.
    pub mounts: MountPosture,
    /// The client certificates this process LOADED at startup, in load order. Empty for
    /// every door that does not authenticate clients by certificate.
    pub clients: Vec<TrustedIdentity>,
    /// The served surface, where the door has one (`host + fs`, `calendar-only + llm`).
    /// `None` on a door whose surface is not a startup decision.
    pub surface: Option<String>,
    /// What a caller resolves under, in one line — the `--cap` ceiling, the
    /// per-identity-grants mode, the per-client workspace default, or the public capability.
    /// `None` where the door has no answer to give.
    ///
    /// Named for the AUTHORITY rather than the ceiling because only two of the six doors
    /// have a ceiling at all: an owner-only socket resolves as the owner, and a workspace door
    /// derives each caller's authority from its own certificate.
    pub authority: Option<String>,
    /// ★ **Whatever this door RE-READS while it runs, named by the door itself.**
    ///
    /// Without this the report would over-claim: "composed at startup" is true of every
    /// other field, and saying it flatly would make the two files a QUIC door re-reads on
    /// every connection (`clients.json`, `grants.json`) look frozen — which is the opposite
    /// of the property that makes editing them a revocation. An HTTP door's watched route
    /// file is the other case.
    ///
    /// So each entry says what is re-read and when. Empty means the frozen claim holds
    /// whole, and that is then a fact rather than an omission. (Ledger #428's second
    /// caution, and #416 on not inventing a third algebra over the config readers.)
    pub reloads: Vec<String>,
}

/// The three relationships a door can have with the machine's topology. Three, not two:
/// "composed nothing" and "declined to look" are different facts, and printing nothing for
/// the second made them the same observation until ledger #418.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountPosture {
    /// `--no-config-mounts`: zero mounts, and the config home's `mount` lines were not read.
    Declined,
    /// What was composed, in composition order — which is semantic (a longer prefix fronts
    /// a shorter one), so the position is part of the fact.
    Composed(Vec<ComposedMount>),
}

impl Default for MountPosture {
    /// An empty COMPOSED set, never [`Declined`](MountPosture::Declined): a default must
    /// not claim a door declined to read the config home, which is a decision somebody
    /// made with a flag.
    fn default() -> Self {
        MountPosture::Composed(Vec::new())
    }
}

/// One composed mount: the mode a `mount` line in the config home would use, the prefix it
/// claims, the target it claims it from, and its own certificate directory when it has one
/// — a mount that authenticates as somebody else is a different mount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComposedMount {
    /// `alias` | `override` | `prefer` — the config file's own word, so what a face prints
    /// is greppable in the file that produced it.
    pub mode: &'static str,
    pub prefix: String,
    pub target: String,
    pub cert_dir: Option<String>,
}

/// One trusted client certificate, as the process holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedIdentity {
    /// `base` for the certificate that is always trusted, else the file stem of a
    /// `clients/*.crt`.
    pub label: String,
    /// The fingerprint **already truncated by the caller**, or `unreadable` for a PEM this
    /// process loaded and cannot describe.
    ///
    /// ⚠ Truncated by the caller ON PURPOSE. The full id is a 64-hex SHA-256 and the CLI
    /// owns the one helper that shortens it (16 characters, matching the per-connection
    /// `client … → grant` line); computing a second truncation here would put two spellings
    /// of one id in one process, which is the defect class this family exists to close
    /// (ledger #426). This crate cannot compute it anyway — `fingerprint_of_pem` lives in
    /// `ikigai-quic`, which is not a dependency.
    pub fingerprint: String,
    /// The file that put this certificate in the trusted set — the discriminator the
    /// fingerprint is not, and the thing an operator adds or removes.
    pub path: String,
}

/// The process's recorded posture. `None` until a door records one.
static POSTURE: Mutex<Option<Posture>> = Mutex::new(None);

/// Record what this process composed. Called once, by the door that built the kernel,
/// before it starts answering.
///
/// A `Mutex<Option<_>>` rather than a `OnceLock` so a test can record twice in one process;
/// nothing in production records twice.
pub fn set_posture(posture: Posture) {
    *POSTURE.lock().expect("posture lock") = Some(posture);
}

/// The recorded posture, or `None` if the door that built this kernel records none.
///
/// ★ `None` is REPORTED, never rendered as an empty topology. "This process composed no
/// mounts" and "nobody told me what this process composed" are different facts, and a
/// resource that answered the second with the first would be the count bug again with a
/// graph face on it.
pub fn posture() -> Option<Posture> {
    POSTURE.lock().expect("posture lock").clone()
}

/// The one spelling of the declined posture, so every face says it the same way.
pub const MOUNTS_DECLINED: &str =
    "declined (--no-config-mounts) — the config home's `mount` lines are not read";

/// One mount, named.
fn mount_line(mount: &ComposedMount) -> String {
    let certs = match &mount.cert_dir {
        Some(dir) => format!("  [certs {dir}]"),
        None => String::new(),
    };
    format!(
        "mount   {} {} -> {}{certs}",
        mount.mode, mount.prefix, mount.target
    )
}

/// The mount block — ONE LINE PER MOUNT, naming what was composed. Used by the startup
/// banner AND by the `text/plain` face of `urn:host:posture`, which is the point: one
/// spelling, two places to read it.
///
/// ★ This used to be `"; {n} mount(s)"`, and the count was always accurate and never an
/// answer. plasma's inference peer printed `6 mount(s)` at every startup while two of the
/// six pointed back at its own caller and cost the machine a ~120s `urn:kernel:actions`
/// (ledger #410/#418): six was not wrong, it just was not an answer to *which* six. A
/// diagnostic that prints a count instead of the items cannot answer the question that
/// makes it worth printing.
///
/// Three postures, and all three say what they mean in words: the mounts themselves, an
/// explicit decline, or an explicit nothing. The last used to print NOTHING at all, which
/// made "this machine composes no topology" and "this door forgot to say" one observation.
///
/// It does not elide. A cap would hide exactly the machine that most needs the list — the
/// hub with thirty mounts — and the banner prints once per process start, into a log.
pub fn mount_lines(mounts: &MountPosture) -> Vec<String> {
    match mounts {
        MountPosture::Declined => vec![format!("mount   {MOUNTS_DECLINED}")],
        MountPosture::Composed(mounts) if mounts.is_empty() => {
            vec!["mount   none composed — no `mount` lines in the config home".to_string()]
        }
        MountPosture::Composed(mounts) => mounts.iter().map(mount_line).collect(),
    }
}

/// The trusted-client block — ONE LINE PER CERTIFICATE: its label, its fingerprint, and the
/// file that put it there. The banner's and the posture face's, from one function.
///
/// ★ This used to be `"{n} trusted client cert(s)"`. Two servers on bug printed `1 trusted
/// client cert(s)` on the same afternoon and meant opposite things — one with
/// `clients/plasma.crt` enrolled, one with no `clients/` directory at all, counting the base
/// `client.crt` that is always trusted (ledger #426).
pub fn client_lines(clients: &[TrustedIdentity]) -> Vec<String> {
    let width = clients.iter().map(|c| c.label.len()).max().unwrap_or(0);
    clients
        .iter()
        .map(|client| {
            format!(
                "client  {label:width$}  {fingerprint}  {path}",
                label = client.label,
                fingerprint = client.fingerprint,
                path = client.path
            )
        })
        .collect()
}

/// What the `text/plain` face says about freshness. Prose, because the thing a reader gets
/// wrong is not a value but a relationship: the certificate SET is frozen while the
/// AUTHORITY each certificate gets is decided per connection.
/// The width of the key column in the `text/plain` face — `authority`, the longest key.
const KEY: usize = 9;

const FRESHNESS_NOTE: &str = concat!(
    "  as of      STARTUP — the door, the surface, the authority, the mounts (composed\n",
    "             wholesale) and the set of certificates that may connect at all were\n",
    "             decided once, when this process started, and cannot change while it\n",
    "             runs. Nothing here is a re-read of the config home: it is what THIS\n",
    "             PROCESS composed.\n",
);

/// The `text/plain` face.
///
/// The key column is [`KEY`] wide so the door's own facts line up; the mount and client
/// blocks keep the BANNER's spelling instead, because they are the banner's lines — that is
/// the whole point of rendering both from one value, and re-padding them here would make
/// the two disagree by two spaces.
fn posture_text(posture: Option<&Posture>) -> String {
    let Some(posture) = posture else {
        return UNRECORDED_TEXT.to_string();
    };
    let mut out = String::from("ikigai host posture\n");
    let mut row = |key: &str, value: &str| {
        out.push_str(&format!("  {key:KEY$}  {value}\n"));
    };
    row("door", &posture.door);
    if let Some(surface) = &posture.surface {
        row("surface", surface);
    }
    if let Some(authority) = &posture.authority {
        row("authority", authority);
    }
    for line in mount_lines(&posture.mounts) {
        out.push_str(&format!("  {line}\n"));
    }
    for line in client_lines(&posture.clients) {
        out.push_str(&format!("  {line}\n"));
    }
    if posture.clients.is_empty() {
        out.push_str("  client  none — this door does not authenticate clients by certificate\n");
    }
    out.push_str(FRESHNESS_NOTE);
    if posture.reloads.is_empty() {
        out.push_str(concat!(
            "  reloads    nothing — this door re-reads no file while it runs, so the\n",
            "             line above holds whole.\n",
        ));
    }
    for reload in &posture.reloads {
        out.push_str(&format!("  {:KEY$}  {reload}\n", "reloads"));
    }
    out
}

/// What both faces say when no door recorded a posture — a refusal to guess, not an empty
/// report. See [`posture`].
const UNRECORDED_TEXT: &str = "\
ikigai host posture
  unrecorded — the code that composed this kernel recorded no posture, so this process
  cannot say what it composed. This is NOT `nothing was composed`: a door that composes no
  mounts still records that. Reachable only from a kernel built outside the CLI's doors
  (an embedding host, or a test).
";

/// Turtle-escape a string literal. Paths and mount targets are operator-supplied, so a
/// quote or a backslash in one must not be able to produce a graph that does not parse.
fn literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// The `text/turtle` face.
///
/// ★ Skolemized, no blank nodes: every mount and every certificate gets a stable IRI under
/// `urn:ikigai:host:posture:` so the graph is diffable and SPARQL-able. Keyed by POSITION,
/// because position is part of the fact — mounts are composed in order and a longer prefix
/// fronts a shorter one — while the human key (`ik:mountPrefix`, `rdfs:label`) rides on the
/// node for a query to join on.
///
/// ⚠ The `ik:` terms here are NOT yet defined in `ikigai-vocab`; defining them needs a
/// `vocabulary.ttl` change in `ikigai-core` plus a manual deploy of
/// <https://ikigai-rs.dev/ns>, neither of which belongs to this repo. The conformance suite
/// pins the exact undefined set so the waiver cannot quietly grow (and fails the day the
/// terms land) — the same treatment `urn:host:health`'s graph face already gets.
fn posture_turtle(posture: Option<&Posture>) -> String {
    let mut out = String::from(
        "@prefix ik: <https://ikigai-rs.dev/ns#> .\n\
         @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n\n",
    );
    let Some(posture) = posture else {
        out.push_str(
            "<urn:host:posture> a ik:Posture ;\n    \
             rdfs:comment \"unrecorded: the code that composed this kernel recorded no \
             posture. NOT the same as composing nothing.\" .\n",
        );
        return out;
    };
    out.push_str(&format!(
        "<urn:host:posture> a ik:Posture ;\n    \
         ik:door \"{}\" ;\n    \
         ik:asOf \"startup\" ;\n    \
         rdfs:comment \"what THIS PROCESS composed when it started — not a re-read of the \
         config home. Anything the door re-reads while running is named by ik:reloads.\"",
        literal(&posture.door),
    ));
    if let Some(surface) = &posture.surface {
        out.push_str(&format!(" ;\n    ik:surface \"{}\"", literal(surface)));
    }
    if let Some(authority) = &posture.authority {
        out.push_str(&format!(" ;\n    ik:authority \"{}\"", literal(authority)));
    }
    for reload in &posture.reloads {
        out.push_str(&format!(" ;\n    ik:reloads \"{}\"", literal(reload)));
    }
    let composed = match &posture.mounts {
        MountPosture::Declined => {
            out.push_str(" ;\n    ik:mountPosture \"declined\"");
            &[][..]
        }
        MountPosture::Composed(mounts) if mounts.is_empty() => {
            out.push_str(" ;\n    ik:mountPosture \"none\"");
            &[][..]
        }
        MountPosture::Composed(mounts) => {
            out.push_str(" ;\n    ik:mountPosture \"composed\"");
            mounts
        }
    };
    for (n, _) in composed.iter().enumerate() {
        out.push_str(&format!(
            " ;\n    ik:mount <urn:ikigai:host:posture:mount:{n}>"
        ));
    }
    for (n, _) in posture.clients.iter().enumerate() {
        out.push_str(&format!(
            " ;\n    ik:trustedClient <urn:ikigai:host:posture:client:{n}>"
        ));
    }
    out.push_str(" .\n\n");
    for (n, mount) in composed.iter().enumerate() {
        out.push_str(&format!(
            "<urn:ikigai:host:posture:mount:{n}> a ik:Mount ;\n    \
             ik:mountMode \"{}\" ;\n    \
             ik:mountPrefix \"{}\" ;\n    \
             ik:mountTarget \"{}\"",
            literal(mount.mode),
            literal(&mount.prefix),
            literal(&mount.target),
        ));
        if let Some(dir) = &mount.cert_dir {
            out.push_str(&format!(" ;\n    ik:certDir \"{}\"", literal(dir)));
        }
        out.push_str(" .\n\n");
    }
    for (n, client) in posture.clients.iter().enumerate() {
        out.push_str(&format!(
            "<urn:ikigai:host:posture:client:{n}> a ik:TrustedClient ;\n    \
             rdfs:label \"{}\" ;\n    \
             ik:fingerprint \"{}\" ;\n    \
             ik:path \"{}\" .\n\n",
            literal(&client.label),
            literal(&client.fingerprint),
            literal(&client.path),
        ));
    }
    out
}

/// `urn:host:posture` — see the module note.
///
/// **Uncacheable, deliberately.** It is a fact about process state, not a pure function of
/// its inputs: `.cacheable()` with an empty thread set would be right once and stale
/// forever (ledger #92's shape). The value it reports is frozen for the process's life, so
/// caching would even be *correct* today — and would silently become a lie the first time a
/// door learned to recompose, with nothing to cut the thread. Reading it is a mutex lock and
/// a string format; there is nothing to buy.
pub(crate) fn host_posture() -> FnEndpoint {
    FnEndpoint::new("host-posture", |inv: &Invocation<'_>| {
        // Declared = enforced: the ActionSpec below requires exactly this.
        if !inv.capability.allows(CAP_HOST_POSTURE) {
            return Err(ikigai_core::Error::Denied(format!(
                "reading this host's posture requires `{CAP_HOST_POSTURE}` — it reports \
                 filesystem and socket paths, which describe the machine"
            )));
        }
        let turtle = inv
            .inline_str("as")
            .map(|v| v.contains("turtle"))
            .unwrap_or(false);
        let recorded = posture();
        let (body, repr) = if turtle {
            (posture_turtle(recorded.as_ref()), "text/turtle")
        } else {
            (posture_text(recorded.as_ref()), "text/plain")
        };
        Ok(Representation::new(ReprType::new(repr), body.into_bytes()))
    })
    .with_description(
        Description::new("host-posture")
            .title("Host posture")
            .summary(
                "what this process composed at startup: its mounts, the client certificates \
                 it trusts, its served surface and the authority a caller resolves under",
            )
            .verb(Verb::Source)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary(
                        "the startup-composed configuration of THIS process — never a \
                         re-read of the config home",
                    )
                    .input(
                        ArgSpec::new("as")
                            .optional()
                            .class(XSD_STRING)
                            .one_of(["text/plain", "text/turtle"])
                            .default_value("text/plain")
                            .summary("the representation to return (default text/plain)"),
                    )
                    // Both faces `as=` offers. ⚠ Declaring `text/turtle` brings the graph
                    // face under the conformance RDF checks, which is the point: an
                    // announced face is one somebody may rely on.
                    .output("text/plain")
                    .output("text/turtle")
                    .requires(CAP_HOST_POSTURE),
            ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::{Capability, Iri, Request};

    fn a_mount(mode: &'static str, prefix: &str, target: &str) -> ComposedMount {
        ComposedMount {
            mode,
            prefix: prefix.to_string(),
            target: target.to_string(),
            cert_dir: None,
        }
    }

    fn a_posture() -> Posture {
        Posture {
            door: "quic://0.0.0.0:4433".to_string(),
            mounts: MountPosture::Composed(vec![
                a_mount("prefer", "urn:iki:store:", "/tmp/gonk.sock"),
                ComposedMount {
                    cert_dir: Some("/tmp/quic-bug".to_string()),
                    ..a_mount("alias", "urn:cal:", "quic://bug.local:4433")
                },
            ]),
            clients: vec![
                TrustedIdentity {
                    label: "base".to_string(),
                    fingerprint: "bbaea49f3556e06f".to_string(),
                    path: "/tmp/quic/client.crt".to_string(),
                },
                TrustedIdentity {
                    label: "plasma".to_string(),
                    fingerprint: "afae4ee811856ef9".to_string(),
                    path: "/tmp/quic/clients/plasma.crt".to_string(),
                },
            ],
            surface: Some("host + fs".to_string()),
            authority: Some("per-client workspaces".to_string()),
            reloads: Vec::new(),
        }
    }

    /// The three mount postures are three DIFFERENT lines. `none` used to print nothing,
    /// which made it indistinguishable from a door that forgot to say (ledger #418).
    #[test]
    fn the_three_mount_postures_read_differently() {
        assert_eq!(
            mount_lines(&MountPosture::Composed(Vec::new())),
            vec!["mount   none composed — no `mount` lines in the config home"]
        );
        assert_eq!(
            mount_lines(&MountPosture::Declined),
            vec![format!("mount   {MOUNTS_DECLINED}")]
        );
        assert_eq!(
            mount_lines(&MountPosture::Composed(vec![a_mount(
                "prefer",
                "urn:x:",
                "/tmp/x.sock"
            )])),
            vec!["mount   prefer urn:x: -> /tmp/x.sock"]
        );
    }

    /// A mount with its own certificate directory says so: a mount that authenticates as
    /// somebody else is a different mount.
    #[test]
    fn a_mounts_own_cert_dir_is_on_its_line() {
        let lines = mount_lines(&a_posture().mounts);
        assert_eq!(
            lines[1],
            "mount   alias urn:cal: -> quic://bug.local:4433  [certs /tmp/quic-bug]"
        );
    }

    /// The text face names every mount and every certificate, and says WHEN the facts were
    /// decided — which is the half a count could never carry.
    #[test]
    fn the_text_face_names_the_items_and_dates_them() {
        let text = posture_text(Some(&a_posture()));
        assert!(text.contains("door       quic://0.0.0.0:4433"), "{text}");
        assert!(
            text.contains("mount   prefer urn:iki:store: -> /tmp/gonk.sock"),
            "{text}"
        );
        assert!(
            text.contains("client  base    bbaea49f3556e06f  /tmp/quic/client.crt"),
            "{text}"
        );
        assert!(text.contains("client  plasma  afae4ee811856ef9"), "{text}");
        assert!(text.contains("as of      STARTUP"), "{text}");
        assert!(
            text.contains("re-read of the config home"),
            "the report must say it is the PROCESS's composition, not the file's: {text}"
        );
    }

    /// ★ An unrecorded posture is REPORTED, not rendered as an empty one — in both faces.
    #[test]
    fn an_unrecorded_posture_refuses_to_guess() {
        let text = posture_text(None);
        assert!(text.contains("unrecorded"), "{text}");
        assert!(
            !text.contains("none composed"),
            "an unrecorded posture must not read as an empty topology: {text}"
        );
        let turtle = posture_turtle(None);
        assert!(turtle.contains("unrecorded"), "{turtle}");
        assert!(!turtle.contains("ik:mountPosture"), "{turtle}");
    }

    /// ★ A door that re-reads a file while it runs NAMES it, and a door that re-reads
    /// nothing says THAT — so the "as of startup" line can never quietly cover a live fact.
    #[test]
    fn a_live_fact_is_named_rather_than_covered_by_the_startup_line() {
        let frozen = posture_text(Some(&a_posture()));
        assert!(frozen.contains("reloads    nothing"), "{frozen}");
        let live = posture_text(Some(&Posture {
            reloads: vec!["clients.json — per connection".to_string()],
            ..a_posture()
        }));
        assert!(
            live.contains("reloads    clients.json — per connection"),
            "{live}"
        );
        assert!(
            !live.contains("reloads    nothing"),
            "a door with a live fact must not also claim it re-reads nothing: {live}"
        );
        let turtle = posture_turtle(Some(&Posture {
            reloads: vec!["clients.json — per connection".to_string()],
            ..a_posture()
        }));
        assert!(
            turtle.contains("ik:reloads \"clients.json — per connection\""),
            "{turtle}"
        );
    }

    /// A door with no certificate authentication says so rather than printing nothing —
    /// the #418 lesson applied to the other block.
    #[test]
    fn a_door_without_client_certs_says_so() {
        let text = posture_text(Some(&Posture {
            clients: Vec::new(),
            ..a_posture()
        }));
        assert!(
            text.contains("client  none — this door does not authenticate"),
            "{text}"
        );
    }

    /// The graph face parses, carries no blank node, and skolemizes every mount and
    /// certificate at a stable IRI.
    #[test]
    fn the_graph_face_is_skolemized_turtle() {
        let turtle = posture_turtle(Some(&a_posture()));
        assert!(
            turtle.contains("<urn:host:posture> a ik:Posture"),
            "{turtle}"
        );
        assert!(
            turtle.contains("<urn:ikigai:host:posture:mount:0> a ik:Mount"),
            "{turtle}"
        );
        assert!(
            turtle.contains("<urn:ikigai:host:posture:client:1> a ik:TrustedClient"),
            "{turtle}"
        );
        assert!(turtle.contains("ik:asOf \"startup\""), "{turtle}");
        assert!(!turtle.contains("_:"), "no blank nodes: {turtle}");
        assert!(turtle.contains("ik:certDir \"/tmp/quic-bug\""), "{turtle}");
    }

    /// The declined and empty mount postures are DISTINCT in the graph too, so a query can
    /// tell them apart without reading prose.
    #[test]
    fn the_graph_face_distinguishes_declined_from_empty() {
        let declined = posture_turtle(Some(&Posture {
            mounts: MountPosture::Declined,
            ..a_posture()
        }));
        assert!(
            declined.contains("ik:mountPosture \"declined\""),
            "{declined}"
        );
        assert!(!declined.contains("ik:mount <"), "{declined}");
        let empty = posture_turtle(Some(&Posture {
            mounts: MountPosture::Composed(Vec::new()),
            ..a_posture()
        }));
        assert!(empty.contains("ik:mountPosture \"none\""), "{empty}");
    }

    /// A path carrying a quote or a backslash must not produce a graph that does not parse.
    /// Operator-supplied strings reach the graph face verbatim, so the escape is the only
    /// thing between a mount line and an unparseable representation.
    #[test]
    fn operator_supplied_strings_are_escaped_into_the_graph() {
        let turtle = posture_turtle(Some(&Posture {
            mounts: MountPosture::Composed(vec![a_mount(
                "prefer",
                "urn:x:",
                "/tmp/he said \"hi\"\\here",
            )]),
            ..a_posture()
        }));
        assert!(
            turtle.contains("ik:mountTarget \"/tmp/he said \\\"hi\\\"\\\\here\""),
            "{turtle}"
        );
    }

    /// A kernel binding only this endpoint, for the two tests that need to go through the
    /// kernel's capability gate rather than call the renderer.
    fn posture_kernel() -> ikigai_core::Kernel {
        ikigai_core::Kernel::new(std::sync::Arc::new(
            crate::EndpointSpace::new().bind(crate::Exact::new("urn:host:posture"), host_posture()),
        ))
    }

    fn read(kernel: &ikigai_core::Kernel, cap: Capability) -> ikigai_core::Result<Representation> {
        futures::executor::block_on(kernel.issue(
            Request::new(
                Verb::Source,
                Iri::parse("urn:host:posture".to_string()).expect("iri"),
            ),
            &cap,
        ))
    }

    /// ★ **The gate, on the endpoint itself.** The public (empty-scope) capability the HTTP
    /// door hands every anonymous request is REFUSED, and the scope that opens it is not
    /// `urn:cap:kernel:inspect` — an agent holding a tool list must not thereby hold the
    /// operator's disk layout.
    #[test]
    fn the_public_capability_is_refused_and_inspect_is_not_enough() {
        set_posture(a_posture());
        let kernel = posture_kernel();
        let denied = read(&kernel, Capability::scoped(Vec::<String>::new()))
            .expect_err("the public capability must be refused");
        assert!(
            matches!(denied, ikigai_core::Error::Denied(_)),
            "a public read must be Denied, not something else: {denied:?}"
        );
        read(&kernel, Capability::scoped(["urn:cap:kernel:inspect"]))
            .expect_err("the manifold grant must not carry the disk layout");
        let allowed = read(&kernel, Capability::scoped([CAP_HOST_POSTURE]))
            .expect("the declared scope must be sufficient");
        assert!(String::from_utf8_lossy(&allowed.bytes).contains("ikigai host posture"));
    }

    /// Uncacheable, as the module note argues: process state, not a pure function.
    #[test]
    fn the_posture_representation_is_not_cacheable() {
        set_posture(a_posture());
        let repr = read(&posture_kernel(), Capability::scoped([CAP_HOST_POSTURE]))
            .expect("resolves under its declared scope");
        assert_eq!(
            repr.expiry,
            ikigai_core::Expiry::Always,
            "a process-state fact must expire immediately"
        );
    }
}
