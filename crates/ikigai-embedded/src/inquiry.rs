//! The contact-inquiry edge half (`ikigai-inquiry`'s [`edge_space`], ledger #3836), mounted from
//! the config home's `inquiry.json`, read once at startup like `intakes.json`.
//!
//! **No file, nothing bound**: without `inquiry.json` the host is exactly what it was. A file
//! that does not read, names a relative path, a key file that is not a key or is open to
//! others, a model or layer name the edge refuses, or a damaged block set, refuses the start,
//! naming the file and the problem.
//!
//! **One key, both sides.** The edge half hashes senders under `sender_key_file`; a configured
//! intake asks its `blocklist` under its `block_key_file`. When any intake row, or the booking
//! intake's `booking.json`, names a `block_key_file`, it must give the same keyed hashes as `sender_key_file`, or the start is
//! refused: a block written here would otherwise never be found there.
//!
//! **Where it is bound.** The local root binds the whole edge half. The served kernel binds
//! only what the intake and the airlock reach: the block set (`urn:iki:inquiry:block:key:{key}`)
//! and apply (`urn:iki:inquiry:apply`). Nothing here adds a route to the HTTP door. Each door
//! declares its own `urn:cap:inquiry:*` capability; nothing here grants one.
//!
//! The store keeps keys and numbers, never an address: the block set and the day counters.
//! A block written by another process over the same store (the import, say) is seen by a
//! running host after it restarts, since the block set is read when the edge opens.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use ikigai_core::{EndpointSpace, Request, Resolution, Scope, Space, SpaceEntry};
use ikigai_inquiry::{
    edge_space, Block, Config, DirStore, Edge, Key, Layers, RoutePolicy, SenderKeys,
    DEFAULT_BLOCK_DAYS,
};
use serde::Deserialize;

/// The file in the config home.
pub const FILE: &str = "inquiry.json";

/// The name the host gives the edge half's space (core's `SPACE-NAME` rule: the host names it).
pub const SPACE: &str = "urn:ikigai:space:inquiry";

/// The endpoint names the served kernel admits: the block set and apply.
const SERVED: [&str; 2] = ["inquiry-block", "inquiry-apply"];

static OPENED: OnceLock<Result<Option<Opened>, String>> = OnceLock::new();

/// The opened edge, and the file it came from.
#[derive(Debug)]
pub struct Opened {
    /// The edge half.
    pub edge: Arc<Edge>,
    /// The sender keys, for the import.
    pub keys: SenderKeys,
    /// How long an imported block holds unless told otherwise, in days.
    pub block_days: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    sender_key_file: PathBuf,
    store: PathBuf,
    model: String,
    owner: String,
    #[serde(default)]
    layers: Option<LayerNames>,
    #[serde(default)]
    block_days: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LayerNames {
    inquiry: String,
    spam: String,
    holding: String,
    examples: String,
    intents: String,
}

fn absolute<'a>(key: &str, path: &'a Path) -> Result<&'a Path, String> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(format!(
            "`{key}` must be an absolute path, not `{}`",
            path.display()
        ))
    }
}

/// Open the edge from `inquiry.json`'s text. `block_keys` are the configured intakes' block
/// keys, each named as an error sentence names it, each checked against the sender-key file.
fn open(text: &str, block_keys: &[(String, ikigai_intake::BlockKey)]) -> Result<Opened, String> {
    let file: File = serde_json::from_str(text).map_err(|e| format!("cannot be read: {e}"))?;
    let keys = SenderKeys::from_file(absolute("sender_key_file", &file.sender_key_file)?)?;
    for (intake, block_key) in block_keys {
        if !same_key(&keys, block_key) {
            return Err(format!(
                "`sender_key_file` and {intake}'s `block_key_file` hold different \
                 keys: a block written by the edge would never be found by the intake. Name \
                 one key file in both"
            ));
        }
    }
    let layers = match file.layers {
        Some(names) => Layers {
            inquiry: names.inquiry,
            spam: names.spam,
            holding: names.holding,
            examples: names.examples,
            intents: names.intents,
        }
        .checked(),
        None => Layers::for_owner(&file.owner),
    }
    .map_err(|e| format!("`owner` or `layers` is refused: {e}"))?;
    let block_days = file.block_days.unwrap_or(DEFAULT_BLOCK_DAYS);
    let config = Config {
        model: file.model,
        policy: RoutePolicy::for_layers(&layers)?,
        intents: layers.intents.clone(),
        block_days,
    };
    let store = DirStore::open(absolute("store", &file.store)?)
        .map_err(|e| format!("`store` cannot be opened: {e}"))?;
    let edge = Edge::new(config, keys.clone(), Arc::new(store))?;
    Ok(Opened {
        edge: Arc::new(edge),
        keys,
        block_days,
    })
}

/// Whether an intake's block key and the edge's sender keys hash a sender alike: the address
/// key and the domain key of the same probe address.
fn same_key(keys: &SenderKeys, block_key: &ikigai_intake::BlockKey) -> bool {
    let probe = "probe@inquiry.invalid";
    let ours = [keys.address(probe), keys.domain_of(probe)];
    let theirs = block_key.sender_keys(probe);
    ours.len() == theirs.len()
        && ours
            .iter()
            .zip(&theirs)
            .all(|(ours, theirs)| ours.as_ref().is_ok_and(|k| k.as_str() == theirs))
}

fn read() -> Result<Option<Opened>, String> {
    let Some(home) = crate::config::config_home() else {
        return Ok(None);
    };
    let path = home.join(FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let block_keys = crate::intakes::block_keys()?;
    open(&text, &block_keys)
        .map(Some)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// The edge, opened once per process: `Ok(None)` when the config home has no `inquiry.json`.
pub fn opened() -> Result<Option<&'static Opened>, String> {
    OPENED
        .get_or_init(read)
        .as_ref()
        .map(Option::as_ref)
        .map_err(Clone::clone)
}

pub(crate) fn check() -> Result<(), String> {
    opened().map(drop)
}

fn configured() -> Option<&'static Opened> {
    // The binary checks before constructing a kernel; a library constructor has no Result
    // channel and follows the host's fail-fast convention, as `intakes::bind` does.
    opened().unwrap_or_else(|e| panic!("{e}"))
}

/// The whole edge half, for the local root; `None` when nothing is configured.
pub(crate) fn local_space() -> Option<Arc<dyn Space>> {
    configured().map(|opened| Arc::new(named(edge_space(&opened.edge))) as Arc<dyn Space>)
}

/// What the served kernel binds: only the block set and apply; `None` when nothing is
/// configured.
pub(crate) fn served_space() -> Option<Arc<dyn Space>> {
    configured().map(|opened| Arc::new(Served(named(edge_space(&opened.edge)))) as Arc<dyn Space>)
}

fn named(space: EndpointSpace) -> EndpointSpace {
    space.named(ikigai_core::Iri::parse(SPACE).expect("a fixed IRI"))
}

/// The edge half narrowed to [`SERVED`], in resolution and in its entries.
struct Served(EndpointSpace);

impl Space for Served {
    fn resolve(&self, request: &Request, scope: &Scope) -> Resolution {
        match self.0.resolve(request, scope) {
            Resolution::Hit(hit) if SERVED.contains(&hit.endpoint.name()) => Resolution::Hit(hit),
            _ => Resolution::Miss,
        }
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        Some(
            self.0
                .entries()?
                .into_iter()
                .filter(|entry| SERVED.contains(&entry.endpoint.as_str()))
                .collect(),
        )
    }

    fn id(&self) -> Option<ikigai_core::Iri> {
        self.0.id()
    }
}

/// What one import did: counts only, never an address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImportCounts {
    /// Block lines read (every line that is a block record, or is not a record at all).
    pub read: usize,
    /// Blocks written.
    pub written: usize,
    /// Blocks that already held, so nothing was written.
    pub present: usize,
    /// Lines that could not be read as a block of an address or a domain.
    pub unreadable: usize,
}

impl std::fmt::Display for ImportCounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "read {}, written {}, already present {}, unreadable {}",
            self.read, self.written, self.present, self.unreadable
        )
    }
}

/// Import the legacy `block` lines of a contact host's decisions log (JSONL, one decision per
/// line, `{"action":"block","email":"<address or domain>",…}`) into the block set, each
/// holding `days` from `now`. A block already holding is left alone, so a second run writes
/// nothing. The log is only read. Lines whose action is anything else are skipped and not
/// counted; a line that is not a decision record at all is counted read and unreadable.
pub fn import_blocks(
    opened: &Opened,
    log: &str,
    days: u64,
    now: ikigai_core::Time,
) -> Result<ImportCounts, String> {
    if !(1..=ikigai_inquiry::MAX_BLOCK_DAYS).contains(&days) {
        return Err(format!(
            "--days is 1 to {}, not {days}",
            ikigai_inquiry::MAX_BLOCK_DAYS
        ));
    }
    let expires = now.plus_millis(days.saturating_mul(86_400_000));
    let mut counts = ImportCounts::default();
    for line in log.lines().filter(|line| !line.trim().is_empty()) {
        let record = serde_json::from_str::<serde_json::Value>(line).ok();
        let action = record
            .as_ref()
            .and_then(|r| r.get("action"))
            .and_then(serde_json::Value::as_str);
        match (&record, action) {
            (Some(_), Some(action)) if action.trim() != "block" => continue,
            _ => counts.read += 1,
        }
        let sender = record
            .as_ref()
            .and_then(|r| r.get("email"))
            .and_then(serde_json::Value::as_str);
        let Some((key, scope)) = sender.and_then(|sender| sender_key(&opened.keys, sender)) else {
            counts.unreadable += 1;
            continue;
        };
        if opened.edge.blocks().holding(&key, now).is_some() {
            counts.present += 1;
            continue;
        }
        opened.edge.blocks().put(
            Block {
                key,
                scope,
                label: Some("imported".into()),
                created: now,
                expires,
            },
            now,
        )?;
        counts.written += 1;
    }
    Ok(counts)
}

/// An address's key, or a domain's (a sender with no `@` that reads as a domain name).
fn sender_key(keys: &SenderKeys, sender: &str) -> Option<(Key, ikigai_inquiry::Scope)> {
    if sender.contains('@') {
        return keys
            .address(sender)
            .ok()
            .map(|key| (key, ikigai_inquiry::Scope::Address));
    }
    let domain = sender.trim().trim_start_matches('@');
    let labels_ok = domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !labels_ok {
        return None;
    }
    keys.domain(domain)
        .ok()
        .map(|key| (key, ikigai_inquiry::Scope::Domain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{
        ArgRef, Capability, Exact, FnEndpoint, Iri, Kernel, ReprType, Representation, Verb,
    };
    use std::sync::Mutex;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> TempDir {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("ikigai-inquiry-host-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
        fn key(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, contents).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            path
        }
        fn config(&self, key: &Path) -> String {
            serde_json::json!({
                "sender_key_file": key,
                "store": self.0.join("store"),
                "model": "contact",
                "owner": "brian",
            })
            .to_string()
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn now() -> ikigai_core::Time {
        ikigai_core::Time::from_millis(1_790_000_000_000)
    }

    #[allow(clippy::disallowed_methods)] // internal: a test fixture's kernel; it routes no user arguments
    fn kernel(space: impl Space + 'static) -> Kernel {
        Kernel::new(Arc::new(space)).with_clock(Arc::new(ikigai_core::SystemClock))
    }

    fn request(verb: Verb, iri: &str) -> Request {
        Request::new(verb, Iri::parse(iri).unwrap())
    }

    #[test]
    fn the_edge_names_resolve_under_their_capabilities_and_are_refused_without() {
        let dir = TempDir::new();
        let key = dir.key("sender.key", KEY);
        let opened = open(&dir.config(&key), &[]).unwrap();
        let blocked = opened.keys.address("spam@example.org").unwrap();
        opened
            .edge
            .blocks()
            .put(
                Block {
                    key: blocked.clone(),
                    scope: ikigai_inquiry::Scope::Address,
                    label: None,
                    created: now(),
                    expires: ikigai_core::Time::from_millis(u64::MAX / 2),
                },
                now(),
            )
            .unwrap();
        let local = kernel(named(edge_space(&opened.edge)));
        let member = format!("urn:iki:inquiry:block:key:{blocked}");
        let only = |cap: &str| Capability::scoped([cap.to_string()]);
        block_on(local.issue(
            request(Verb::Exists, &member),
            &only(ikigai_inquiry::CAP_BLOCK_CHECK),
        ))
        .unwrap();
        let refused = block_on(local.issue(request(Verb::Exists, &member), &only("urn:cap:other")));
        assert!(
            matches!(refused, Err(ikigai_core::Error::Denied(_))),
            "{refused:?}"
        );
        let sender_key = request(Verb::Source, ikigai_inquiry::SENDER_KEY)
            .with_arg("address", ArgRef::Inline(b"a@b.example".to_vec()));
        block_on(local.issue(sender_key.clone(), &only(ikigai_inquiry::CAP_SENDER_KEY))).unwrap();
        assert!(matches!(
            block_on(local.issue(sender_key.clone(), &only(ikigai_inquiry::CAP_BLOCK_CHECK))),
            Err(ikigai_core::Error::Denied(_))
        ));
        let apply = request(Verb::Sink, ikigai_inquiry::APPLY);
        assert!(matches!(
            block_on(local.issue(apply.clone(), &only(ikigai_inquiry::CAP_ROUTE))),
            Err(ikigai_core::Error::Denied(_))
        ));
        let route = request(Verb::Sink, ikigai_inquiry::ROUTE);
        assert!(matches!(
            block_on(local.issue(route, &only(ikigai_inquiry::CAP_APPLY))),
            Err(ikigai_core::Error::Denied(_))
        ));

        // The served narrowing: the block set and apply, nothing else.
        let served = kernel(Served(named(edge_space(&opened.edge))));
        block_on(served.issue(request(Verb::Exists, &member), &Capability::root())).unwrap();
        let missed = block_on(served.issue(sender_key, &Capability::root()));
        assert!(
            matches!(missed, Err(ikigai_core::Error::Unresolved(_))),
            "{missed:?}"
        );
        let mut patterns: Vec<String> = Served(named(edge_space(&opened.edge)))
            .entries()
            .unwrap()
            .into_iter()
            .map(|e| e.pattern)
            .collect();
        patterns.sort();
        assert_eq!(patterns, [ikigai_inquiry::APPLY, ikigai_inquiry::BLOCK]);
    }

    #[test]
    fn a_block_written_through_the_edge_is_found_by_a_configured_intakes_exists_check() {
        let dir = TempDir::new();
        let key = dir.key("block.key", KEY);
        let block_key = ikigai_intake::BlockKey::load(&key).unwrap();
        let opened = open(&dir.config(&key), &[("contact".into(), block_key.clone())]).unwrap();
        let edge = edge_space(&opened.edge);
        // Write the block through the edge half itself: apply's `block` intent lands here, so
        // the store is what both sides share.
        let blocked = opened.keys.address("Spam@Example.org").unwrap();
        opened
            .edge
            .blocks()
            .put(
                Block {
                    key: blocked,
                    scope: ikigai_inquiry::Scope::Address,
                    label: None,
                    created: now(),
                    expires: ikigai_core::Time::from_millis(u64::MAX / 2),
                },
                now(),
            )
            .unwrap();
        let landed = Arc::new(Mutex::new(Vec::new()));
        let seen = landed.clone();
        let intake = ikigai_intake::IntakeConfig {
            id: "contact".into(),
            space: "urn:space:contact".into(),
            fields: vec![ikigai_intake::IntakeField::required("email", "email")],
            fixed_fields: Default::default(),
            redirect: None,
            blocklist: Some("urn:iki:inquiry:block:key:{key}".into()),
            block_key: Some(block_key),
            email_field: Some("email".into()),
            honeypot: None,
            requires: "urn:cap:contact:submit".into(),
            clients: None,
            attests: Vec::new(),
            check_blocked: false,
        };
        let space = edge
            .bind(
                Exact::new("urn:intake:id:contact:submit"),
                ikigai_intake::submit(intake),
            )
            .bind(
                Exact::new("urn:space:contact"),
                FnEndpoint::new("record", move |inv| {
                    seen.lock()
                        .unwrap()
                        .push(inv.inline_str("content")?.to_string());
                    Ok(Representation::new(
                        ReprType::new("text/plain"),
                        b"ok".to_vec(),
                    ))
                }),
            );
        let kernel = kernel(space);
        let submit = |email: &str| {
            request(Verb::Sink, "urn:intake:id:contact:submit").with_arg(
                "content",
                ArgRef::Inline(
                    serde_json::json!({ "email": email })
                        .to_string()
                        .into_bytes(),
                ),
            )
        };
        let cap = Capability::scoped([
            "urn:cap:contact:submit".to_string(),
            ikigai_inquiry::CAP_BLOCK_CHECK.to_string(),
            "urn:cap:space:out".to_string(),
        ]);
        for email in [
            "  SPAM@example.ORG  ",
            "spam@example.org",
            "\tSpam@Example.Org",
        ] {
            block_on(kernel.issue(submit(email), &cap)).unwrap();
        }
        assert!(
            landed.lock().unwrap().is_empty(),
            "{:?}",
            landed.lock().unwrap()
        );
        block_on(kernel.issue(submit("friend@example.org"), &cap)).unwrap();
        assert_eq!(
            landed.lock().unwrap().len(),
            1,
            "an unblocked sender still lands"
        );
    }

    #[test]
    fn a_booking_key_file_unlike_the_sender_key_refuses_the_start() {
        let dir = TempDir::new();
        let key = dir.key("sender.key", KEY);
        let same = ikigai_intake::BlockKey::from_hex(KEY).unwrap();
        let other = ikigai_intake::BlockKey::from_hex(&"ab".repeat(32)).unwrap();
        let booking = "the booking intake (`booking.json`)".to_string();
        assert!(open(&dir.config(&key), &[(booking.clone(), same)]).is_ok());
        let error = open(&dir.config(&key), &[(booking, other)]).unwrap_err();
        assert!(
            error.contains("the booking intake (`booking.json`)'s"),
            "{error}"
        );
        assert!(error.contains("different keys"), "{error}");
    }

    #[test]
    fn different_key_files_refuse_the_start() {
        let dir = TempDir::new();
        let key = dir.key("sender.key", KEY);
        let other = ikigai_intake::BlockKey::from_hex(&"ab".repeat(32)).unwrap();
        let error = open(&dir.config(&key), &[("intake row `studio`".into(), other)]).unwrap_err();
        assert!(error.contains("intake row `studio`"), "{error}");
        assert!(error.contains("different keys"), "{error}");
    }

    #[test]
    fn a_malformed_config_is_refused_by_what_is_wrong() {
        let dir = TempDir::new();
        let key = dir.key("sender.key", KEY);
        let good: serde_json::Value = serde_json::from_str(&dir.config(&key)).unwrap();
        let with = |field: &str, value: serde_json::Value| {
            let mut config = good.clone();
            config[field] = value;
            config.to_string()
        };
        let without = |field: &str| {
            let mut config = good.clone();
            config.as_object_mut().unwrap().remove(field);
            config.to_string()
        };
        for (text, says) in [
            ("{".to_string(), "cannot be read"),
            (without("sender_key_file"), "sender_key_file"),
            (without("store"), "store"),
            (without("model"), "model"),
            (without("owner"), "owner"),
            (with("unexpected", true.into()), "unexpected"),
            (with("sender_key_file", "relative.key".into()), "absolute"),
            (with("store", "relative".into()), "absolute"),
            (with("model", "Not A Model".into()), "classifier model"),
            (with("owner", "Brian!".into()), "owner"),
            (with("block_days", 0.into()), "days"),
        ] {
            let error = open(&text, &[]).unwrap_err();
            assert!(error.contains(says), "{says}: {error}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(open(&good.to_string(), &[]).unwrap_err().contains("0600"));
        }
    }

    #[test]
    fn the_import_counts_and_a_rerun_writes_nothing() {
        let dir = TempDir::new();
        let key = dir.key("sender.key", KEY);
        let opened = open(&dir.config(&key), &[]).unwrap();
        let log = [
            r#"{"action":"approve","email":"friend@example.org","at":"2026-01-01"}"#,
            r#"{"action":"block","email":"Spam@Example.org","at":"2026-01-02"}"#,
            r#"{"action":"block","email":"seo@agency.example","at":"2026-01-03"}"#,
            r#"{"action":"block","email":"spam-domain.example","at":"2026-01-04"}"#,
            r#"{"action":"block","email":"not a sender","at":"2026-01-05"}"#,
        ]
        .join("\n");
        let first = import_blocks(&opened, &log, DEFAULT_BLOCK_DAYS, now()).unwrap();
        assert_eq!(
            first,
            ImportCounts {
                read: 4,
                written: 3,
                present: 0,
                unreadable: 1
            }
        );
        let printed = first.to_string();
        for address in ["spam@", "seo@", "spam-domain", "not a sender", "example"] {
            assert!(!printed.to_lowercase().contains(address), "{printed}");
        }
        let second = import_blocks(&opened, &log, DEFAULT_BLOCK_DAYS, now()).unwrap();
        assert_eq!(second.written, 0);
        assert_eq!(second.present, 3);
        let domain = opened.keys.domain("spam-domain.example").unwrap();
        let held = opened.edge.blocks().holding(&domain, now()).unwrap();
        assert_eq!(held.scope, ikigai_inquiry::Scope::Domain);
        assert_eq!(
            held.expires.as_millis() - now().as_millis(),
            DEFAULT_BLOCK_DAYS * 86_400_000
        );
        // Reopened from the store (another process, a restart): still held.
        let again = open(&dir.config(&key), &[]).unwrap();
        assert_eq!(import_blocks(&again, &log, 30, now()).unwrap().written, 0);
        assert!(import_blocks(&again, &log, 0, now()).is_err());
    }
}
