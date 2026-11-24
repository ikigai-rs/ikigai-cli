//! The booking intake's keyed block set, from the config home's `booking.json`, fixed for a
//! host's lifetime.
//!
//! Without the file the booking intake keeps the legacy check: it asks `urn:decisions`
//! whether the sender is `blocked`. With it, the intake asks the keyed block set instead,
//! exactly as a configured contact intake row does (`intakes.json`'s `blocklist` and
//! `block_key_file`).

use std::sync::OnceLock;

use serde::Deserialize;

/// The file in the config home.
pub(crate) const FILE: &str = "booking.json";

static CONFIG: OnceLock<Result<Option<Block>, String>> = OnceLock::new();

/// The block set a configured booking intake asks, and the key it hashes senders with.
#[derive(Clone)]
pub(crate) struct Block {
    /// The block set, as an IRI template naming each member once as `{key}`.
    pub(crate) blocklist: String,
    /// The key sender addresses are hashed with.
    pub(crate) key: ikigai_intake::BlockKey,
}

impl std::fmt::Debug for Block {
    /// The key is never shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Block")
            .field("blocklist", &self.blocklist)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    blocklist: String,
    /// An absolute path to the 64-hex-digit key sender addresses are hashed with.
    block_key_file: std::path::PathBuf,
}

/// The booking block from `booking.json`'s text, checked as the intake will use it.
fn parse(text: &str) -> Result<Block, String> {
    let file: File = serde_json::from_str(text).map_err(|e| format!("cannot be read: {e}"))?;
    if !file.block_key_file.is_absolute() {
        return Err(format!(
            "needs an absolute block_key_file, not `{}`",
            file.block_key_file.display()
        ));
    }
    let key = ikigai_intake::BlockKey::load(&file.block_key_file)
        .map_err(|e| format!("is refused: {e}"))?;
    let block = Block {
        blocklist: file.blocklist,
        key,
    };
    ikigai_intake::try_submit(crate::booking_intake_with(Some(&block)))
        .map_err(|e| format!("is refused: {e}"))?;
    Ok(block)
}

fn read() -> Result<Option<Block>, String> {
    let Some(home) = crate::config::config_home() else {
        return Ok(None);
    };
    let path = home.join(FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => parse(&text)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// The configured block, read once per process: `Ok(None)` when the config home has no
/// `booking.json`.
pub(crate) fn configured() -> Result<Option<&'static Block>, String> {
    CONFIG
        .get_or_init(read)
        .as_ref()
        .map(Option::as_ref)
        .map_err(Clone::clone)
}

pub(crate) fn check() -> Result<(), String> {
    configured().map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{
        ArgRef, Capability, EndpointSpace, Exact, FnEndpoint, Iri, Kernel, ReprType,
        Representation, Request, UriTemplate, Verb,
    };
    use std::sync::{Arc, Mutex};

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const BLOCKLIST: &str = "urn:iki:inquiry:block:key:{key}";

    /// A fresh directory, removed when dropped.
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new() -> TempDir {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("ikigai-booking-key-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }

        /// A key file, mode 600, in this directory.
        fn key(&self, contents: &str) -> std::path::PathBuf {
            let path = self.0.join("block.key");
            std::fs::write(&path, contents).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn file(blocklist: &str, key_file: &str) -> String {
        format!(
            r#"{{"blocklist":{},"block_key_file":{}}}"#,
            serde_json::to_string(blocklist).unwrap(),
            serde_json::to_string(key_file).unwrap()
        )
    }

    /// The booking intake as `parse` would configure it, in front of a recording bookings
    /// space, a block set holding `blocked` (keyed under [`KEY`]) and a legacy decisions log
    /// that answers `yes` for every sender. Returns the kernel, what landed, and what the
    /// block set and the decisions log were asked.
    struct Edge {
        kernel: Kernel,
        landed: Arc<Mutex<Vec<String>>>,
        asked: Arc<Mutex<Vec<(Verb, String, usize)>>>,
        decisions: Arc<Mutex<usize>>,
    }

    #[allow(clippy::disallowed_methods)] // internal: a test fixture's kernel; it routes no user arguments
    fn edge(block: Option<&Block>, blocked: &[&str]) -> Edge {
        let key = ikigai_intake::BlockKey::from_hex(KEY).unwrap();
        let members: Vec<String> = blocked
            .iter()
            .map(|member| BLOCKLIST.replace("{key}", &key.sender_keys(member)[0]))
            .collect();
        let landed = Arc::new(Mutex::new(Vec::new()));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let decisions = Arc::new(Mutex::new(0));
        let (land, ask, decide) = (landed.clone(), asked.clone(), decisions.clone());
        let space = EndpointSpace::new()
            .bind(
                Exact::new("urn:booking:submit"),
                ikigai_intake::try_submit(crate::booking_intake_with(block)).unwrap(),
            )
            .bind(
                Exact::new("urn:space:bookings"),
                FnEndpoint::new("bookings", move |inv| {
                    land.lock()
                        .unwrap()
                        .push(inv.inline_str("content").unwrap_or_default().to_string());
                    Ok(Representation::new(
                        ReprType::new("text/plain"),
                        b"ok".to_vec(),
                    ))
                }),
            )
            .bind(
                UriTemplate::parse(BLOCKLIST).unwrap(),
                FnEndpoint::new("block", move |inv| {
                    let iri = inv.request.target.to_string();
                    ask.lock().unwrap().push((
                        inv.request.verb,
                        iri.clone(),
                        inv.request.args.len(),
                    ));
                    if members.contains(&iri) {
                        Ok(Representation::new(ReprType::new("text/plain"), Vec::new()))
                    } else {
                        Err(ikigai_core::Error::NotFound(iri))
                    }
                }),
            )
            .bind(
                Exact::new("urn:decisions"),
                FnEndpoint::new("decisions", move |_| {
                    *decide.lock().unwrap() += 1;
                    Ok(Representation::new(
                        ReprType::new("text/plain"),
                        b"yes\n".to_vec(),
                    ))
                }),
            );
        Edge {
            kernel: Kernel::new(Arc::new(space)),
            landed,
            asked,
            decisions,
        }
    }

    fn book(edge: &Edge, email: &str) -> Vec<u8> {
        let body = format!(
            "name=Visitor&email={}&period=week&zone=Europe%2FLondon",
            email.replace('@', "%40")
        );
        let request = Request::new(Verb::Sink, Iri::parse("urn:booking:submit").unwrap())
            .with_arg("content", ArgRef::Inline(body.into_bytes()));
        let cap = Capability::scoped([
            "urn:cap:booking:submit",
            "urn:cap:inquiry:block:check",
            "urn:cap:decisions:read",
        ]);
        block_on(edge.kernel.issue(request, &cap)).unwrap().bytes
    }

    fn configured_block(dir: &TempDir) -> Block {
        let key = dir.key(KEY);
        parse(&file(BLOCKLIST, key.to_str().unwrap())).unwrap()
    }

    #[test]
    fn a_blocked_address_or_domain_is_dropped_with_the_answer_a_real_booking_gets() {
        let dir = TempDir::new();
        let block = configured_block(&dir);
        let edge = edge(
            Some(&block),
            &["blocked@example.org", "domain:spam.example"],
        );

        let real = book(&edge, "friend@example.org");
        assert_eq!(
            edge.landed.lock().unwrap().len(),
            1,
            "an unblocked booking lands"
        );

        for sender in [
            "blocked@example.org",
            "  Blocked@Example.ORG ",
            "anyone@spam.example",
        ] {
            assert_eq!(book(&edge, sender), real, "{sender:?} learns nothing");
        }
        assert_eq!(
            edge.landed.lock().unwrap().len(),
            1,
            "no blocked booking lands"
        );
        for (verb, iri, args) in edge.asked.lock().unwrap().iter() {
            assert_eq!(*verb, Verb::Exists);
            assert_eq!(*args, 0, "the question carries no arguments");
            let lower = iri.to_lowercase();
            assert!(!lower.contains("example") && !lower.contains('@'), "{iri}");
        }
        assert_eq!(
            *edge.decisions.lock().unwrap(),
            0,
            "a configured block set replaces the decisions log"
        );
    }

    #[test]
    fn an_unreachable_block_set_admits_the_booking() {
        let dir = TempDir::new();
        let mut block = configured_block(&dir);
        block.blocklist = "urn:nowhere:{key}".into();
        let edge = edge(Some(&block), &["friend@example.org"]);
        book(&edge, "friend@example.org");
        assert_eq!(edge.landed.lock().unwrap().len(), 1, "fail-open");
    }

    #[test]
    fn without_booking_json_the_decisions_log_still_decides() {
        let edge = edge(None, &["blocked@example.org"]);
        assert_eq!(book(&edge, "anyone@example.org"), b"received\n");
        assert_eq!(
            *edge.decisions.lock().unwrap(),
            1,
            "the legacy check is asked"
        );
        assert!(
            edge.asked.lock().unwrap().is_empty(),
            "the block set is not"
        );
        assert!(
            edge.landed.lock().unwrap().is_empty(),
            "a `yes` from urn:decisions drops the booking"
        );
        assert!(crate::booking_intake().blocklist.is_none());
        assert!(crate::booking_intake().check_blocked);
    }

    #[test]
    fn a_bad_booking_json_is_refused_by_what_is_wrong() {
        let dir = TempDir::new();
        let key = dir.key(KEY);
        let key = key.to_str().unwrap();
        let error = parse(&file(BLOCKLIST, "relative/block.key")).unwrap_err();
        assert!(
            error.contains("needs an absolute block_key_file"),
            "{error}"
        );
        for blocklist in ["not an iri", "urn:decisions", "urn:b:{key}:{key}"] {
            let error = parse(&file(blocklist, key)).unwrap_err();
            assert!(error.starts_with("is refused:"), "{blocklist}: {error}");
        }
        let error = parse(&format!(r#"{{"blocklist":"{BLOCKLIST}"}}"#)).unwrap_err();
        assert!(error.contains("block_key_file"), "{error}");
        let error = parse(&format!(
            r#"{{"blocklist":"{BLOCKLIST}","block_key_file":"{key}","fields":[]}}"#
        ))
        .unwrap_err();
        assert!(error.contains("unknown field"), "{error}");
        let bad = TempDir::new();
        let bad = bad.key("not a key");
        let error = parse(&file(BLOCKLIST, bad.to_str().unwrap())).unwrap_err();
        assert!(error.contains("is not 64 hexadecimal digits"), "{error}");
        assert!(
            !error.contains("not a key"),
            "contents are never echoed: {error}"
        );
    }
}
