//! Reactive spaces sealed at rest (ledger #3686).
//!
//! A space under `file_root/spaces` holds what a stranger submitted (a contact enquiry, a
//! booking request). With a space key configured, every tuple is stored as binary age
//! ciphertext sealed to that key, through `ikigai-intray`'s [`TupleCodec`], the way the layer
//! door seals its state: the public edge's `out` seals, the daemon's reactor and every `rd`,
//! `take` and `match=` open.
//!
//! The key is an age identity file (`age-keygen -o space.key`), found in this order:
//!
//! 1. `$CREDENTIALS_DIRECTORY/space.key`, when systemd passes it as a credential
//!    (`LoadCredential=space.key:/etc/ikigai/space.key`);
//! 2. `<config home>/space.key` (the key file on macOS, or anywhere without systemd).
//!
//! With neither, spaces are stored in the clear, as before. A key file that is present but
//! cannot be used never falls back to the clear: every drop and every read refuses, naming
//! the file.
//!
//! ⚠ The `.err` and `.out` NOTES a reactor writes beside a tuple are NOT sealed, even under a
//! key: they are the intray's sentence or what the handler answered. A handler must keep
//! visitor text out of what it answers.
//!
//! Tuples stored before the key was configured are plaintext, and a sealed space refuses them
//! until `ikigai space-reseal` seals them in place ([`reseal`]).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ikigai_encrypt::age::{Identity, Recipient};
use ikigai_intray::{SpaceEndpoint, TupleCodec};

/// The key's file name, in `$CREDENTIALS_DIRECTORY` and in the config home.
pub const SPACE_KEY_FILE: &str = "space.key";

/// The first bytes of every binary age file.
const MAGIC: &[u8] = b"age-encryption.org/v1";

/// Where the space key is, if one is configured: `$CREDENTIALS_DIRECTORY/space.key` when
/// that file exists, else `<config home>/space.key` when that one does.
pub fn space_key_path() -> Option<PathBuf> {
    space_key_path_from(
        std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from),
        crate::config::config_home(),
    )
}

fn space_key_path_from(credentials: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    credentials
        .map(|dir| dir.join(SPACE_KEY_FILE))
        .filter(|path| path.exists())
        .or_else(|| {
            home.map(|dir| dir.join(SPACE_KEY_FILE))
                .filter(|path| path.exists())
        })
}

/// The codec every space under this host stores through: `None` (the clear) with no key
/// configured, a [`SealCodec`] with one, and a codec that refuses everything when the key
/// file is present but unusable.
pub fn space_codec() -> Option<Arc<dyn TupleCodec>> {
    let path = space_key_path()?;
    Some(match SealCodec::load(&path) {
        Ok(codec) => Arc::new(codec) as Arc<dyn TupleCodec>,
        Err(why) => Arc::new(Refusing(why)) as Arc<dyn TupleCodec>,
    })
}

/// A space endpoint over `root`, sealed when a key is configured.
pub fn endpoint(root: PathBuf) -> SpaceEndpoint {
    let space = SpaceEndpoint::new(root);
    match space_codec() {
        Some(codec) => space.with_codec(codec),
        None => space,
    }
}

/// Seals tuples to an age identity's recipient and opens them with any identity in the file.
pub struct SealCodec {
    identities: Vec<Identity>,
    recipient: Recipient,
    /// Whether a read passes plaintext through (only while [`reseal`] seals old tuples).
    migrating: bool,
}

impl SealCodec {
    /// Read the age identity file at `path` (one `AGE-SECRET-KEY-1…` per line, `#` comments
    /// skipped; the first is the one tuples are sealed to). Refused, never echoing a line of
    /// it, when it cannot be read, holds no identity or, on unix, when group or others can
    /// reach it (a root-owned file may be group-readable, as systemd's credential store
    /// writes it).
    pub fn load(path: &Path) -> Result<SealCodec, String> {
        let refuse = |why: String| {
            format!(
                "the space key {}: {why}; every space is sealed to it and nothing is stored \
                 or read without it",
                path.display()
            )
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta =
                std::fs::metadata(path).map_err(|e| refuse(format!("cannot be read ({e})")))?;
            let mode = meta.mode() & 0o777;
            let allowed = if meta.uid() == 0 { 0o740 } else { 0o700 };
            if mode & !allowed != 0 {
                return Err(refuse(format!(
                    "is mode {mode:o}, so others can reach it (fix: chmod 600 {})",
                    path.display()
                )));
            }
        }
        let text =
            std::fs::read_to_string(path).map_err(|e| refuse(format!("cannot be read ({e})")))?;
        let identities = ikigai_encrypt::age::parse_identities(&text).map_err(|e| match e {
            ikigai_encrypt::age::Error::BadKey { line, .. } => {
                refuse(format!("line {line} is not an X25519 age identity"))
            }
            ikigai_encrypt::age::Error::NoKeys => {
                refuse("holds no age identity (expected a line AGE-SECRET-KEY-1…)".to_string())
            }
            other => refuse(other.to_string()),
        })?;
        let recipient = identities[0].to_public();
        Ok(SealCodec {
            identities,
            recipient,
            migrating: false,
        })
    }

    /// This codec, reading plaintext tuples too, so [`reseal`] can seal them.
    fn migrating(mut self) -> SealCodec {
        self.migrating = true;
        self
    }

    /// The recipient (`age1…`) tuples are sealed to.
    pub fn recipient(&self) -> String {
        self.recipient.to_string()
    }
}

impl TupleCodec for SealCodec {
    fn encode(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        ikigai_encrypt::age::seal(plain, std::slice::from_ref(&self.recipient))
            .map_err(|e| format!("seal: {e}"))
    }

    fn decode(&self, stored: &[u8]) -> Result<Vec<u8>, String> {
        if !stored.starts_with(MAGIC) {
            return if self.migrating {
                Ok(stored.to_vec())
            } else {
                Err("it is stored in the clear, and this space is sealed: run \
                     `ikigai space-reseal` to seal it"
                    .to_string())
            };
        }
        ikigai_encrypt::age::open(stored, &self.identities).map_err(|e| format!("open: {e}"))
    }

    fn is_current(&self, stored: &[u8]) -> bool {
        stored.starts_with(MAGIC)
            && ikigai_encrypt::age::open(stored, &self.identities[..1]).is_ok()
    }
}

/// A key file that is present but unusable: nothing is stored or read in the clear instead.
struct Refusing(String);

impl TupleCodec for Refusing {
    fn encode(&self, _: &[u8]) -> Result<Vec<u8>, String> {
        Err(self.0.clone())
    }
    fn decode(&self, _: &[u8]) -> Result<Vec<u8>, String> {
        Err(self.0.clone())
    }
}

/// What [`reseal`] did to one space.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Resealed {
    pub space: String,
    /// Pending tuples stored again, sealed (each under a new id).
    pub pending: usize,
    /// Settled tuples (`error/`, `outbox/`, `.processing/`) stored again, sealed.
    pub settled: usize,
}

/// Seal, in place, every tuple of every space under `root` that is not sealed to the current
/// identity in `key`: plaintext written before the key was configured, or tuples sealed to an
/// older key still listed in the file (a rotation puts the new identity first).
///
/// ⚠ Only while no reactor runs over `root` (stop the daemon first): a settled tuple moved
/// under a live pass is settled twice. The reactor's `.err`/`.out` notes are renamed with
/// their tuple; an `.out` note is sealed too.
pub fn reseal(root: &Path, key: &Path) -> Result<Vec<Resealed>, String> {
    let codec = SealCodec::load(key)?.migrating();
    let endpoint = SpaceEndpoint::new(root.to_path_buf()).with_codec(Arc::new(codec));
    let mut names: Vec<String> = match std::fs::read_dir(root) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| !name.starts_with('.'))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("{}: {e}", root.display())),
    };
    names.sort();
    let mut done = Vec::new();
    for name in names {
        let pending = endpoint
            .reencode(&name)
            .map_err(|e| format!("space `{name}`: {e}"))?
            .len();
        let settled = endpoint
            .reencode_settled(&name)
            .map_err(|e| format!("space `{name}`: {e}"))?
            .len();
        done.push(Resealed {
            space: name,
            pending,
            settled,
        });
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{ArgRef, Capability, EndpointSpace, Iri, Kernel, Request, UriTemplate, Verb};

    /// A fresh directory, removed when dropped.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> TempDir {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("ikigai-space-seal-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write_key(dir: &Path) -> PathBuf {
        use age::secrecy::ExposeSecret;
        let identity = age::x25519::Identity::generate();
        let path = dir.join(SPACE_KEY_FILE);
        std::fs::write(&path, format!("{}\n", identity.to_string().expose_secret())).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    fn kernel(space: SpaceEndpoint) -> Kernel {
        Kernel::new(Arc::new(EndpointSpace::new().bind(
            UriTemplate::parse(ikigai_intray::SPACE_TEMPLATE).unwrap(),
            space,
        )))
    }

    fn cap() -> Capability {
        Capability::scoped(vec![
            ikigai_intray::CAP_OUT.to_string(),
            ikigai_intray::CAP_READ.to_string(),
        ])
    }

    fn out(k: &Kernel, tuple: &[u8]) -> String {
        let id = block_on(
            k.issue(
                Request::new(Verb::Sink, Iri::parse("urn:space:contact").unwrap())
                    .with_arg("content", ArgRef::Inline(tuple.to_vec())),
                &cap(),
            ),
        )
        .unwrap();
        String::from_utf8(id.bytes).unwrap()
    }

    fn rd(k: &Kernel, id: &str) -> Result<Vec<u8>, ikigai_core::Error> {
        block_on(
            k.issue(
                Request::new(Verb::Source, Iri::parse("urn:space:contact").unwrap())
                    .with_arg("tuple", ArgRef::Inline(id.as_bytes().to_vec())),
                &cap(),
            ),
        )
        .map(|r| r.bytes)
    }

    fn files_under(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(files_under(&path));
            } else {
                out.push(path);
            }
        }
        out
    }

    fn assert_no_plaintext(root: &Path) {
        let files = files_under(root);
        assert!(
            !files.is_empty(),
            "nothing was stored under {}",
            root.display()
        );
        for file in files {
            let bytes = std::fs::read(&file).unwrap();
            assert!(
                !bytes.windows(SECRET.len()).any(|w| w == SECRET),
                "{} holds the tuple in the clear",
                file.display()
            );
        }
    }

    const SECRET: &[u8] = b"Elm Street";
    const ENQUIRY: &[u8] = b"((message \"please call me about the flat on Elm Street\"))";

    #[test]
    fn a_sealed_space_round_trips_and_its_files_carry_no_plaintext() {
        let dir = TempDir::new();
        let key = write_key(dir.path());
        let root = dir.path().join("spaces");
        let k = kernel(
            SpaceEndpoint::new(root.clone()).with_codec(Arc::new(SealCodec::load(&key).unwrap())),
        );
        let id = out(&k, ENQUIRY);
        assert_ne!(
            id,
            ikigai_intray::tuple_id(ENQUIRY),
            "the id is of the sealed bytes"
        );
        assert_no_plaintext(&root);
        assert_eq!(rd(&k, &id).unwrap(), ENQUIRY);
        // Another key cannot read it.
        let other = TempDir::new();
        let wrong = kernel(
            SpaceEndpoint::new(root.clone())
                .with_codec(Arc::new(SealCodec::load(&write_key(other.path())).unwrap())),
        );
        assert!(rd(&wrong, &id).is_err());
    }

    #[test]
    fn reseal_converts_plaintext_files() {
        let dir = TempDir::new();
        let key = write_key(dir.path());
        let root = dir.path().join("spaces");
        let old = out(&kernel(SpaceEndpoint::new(root.clone())), ENQUIRY);
        let sealed = || {
            kernel(
                SpaceEndpoint::new(root.clone())
                    .with_codec(Arc::new(SealCodec::load(&key).unwrap())),
            )
        };
        assert!(
            rd(&sealed(), &old).is_err(),
            "a sealed space refuses a plaintext tuple"
        );

        let done = reseal(&root, &key).unwrap();
        assert_eq!(
            done,
            vec![Resealed {
                space: "contact".into(),
                pending: 1,
                settled: 0
            }]
        );
        assert_no_plaintext(&root);
        let list = block_on(sealed().issue(
            Request::new(Verb::Source, Iri::parse("urn:space:contact").unwrap()),
            &cap(),
        ))
        .unwrap();
        let new = String::from_utf8(list.bytes).unwrap();
        assert_eq!(rd(&sealed(), new.trim()).unwrap(), ENQUIRY);
        assert_eq!(
            reseal(&root, &key).unwrap()[0].pending,
            0,
            "a second reseal moves nothing"
        );
    }

    #[test]
    fn an_unusable_key_refuses_rather_than_storing_in_the_clear() {
        let dir = TempDir::new();
        let path = dir.path().join(SPACE_KEY_FILE);
        std::fs::write(&path, "not a key\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let why = SealCodec::load(&path).err().unwrap();
        assert!(!why.contains("not a key"), "never echoes the file: {why}");
        let k = kernel(
            SpaceEndpoint::new(dir.path().join("spaces")).with_codec(Arc::new(Refusing(why))),
        );
        assert!(block_on(
            k.issue(
                Request::new(Verb::Sink, Iri::parse("urn:space:contact").unwrap())
                    .with_arg("content", ArgRef::Inline(ENQUIRY.to_vec())),
                &cap(),
            )
        )
        .is_err());
        assert!(files_under(&dir.path().join("spaces"))
            .iter()
            .all(|f| !std::fs::read(f)
                .unwrap()
                .windows(SECRET.len())
                .any(|w| w == SECRET)));
    }

    #[test]
    fn the_credential_directory_wins_over_the_config_home() {
        let creds = TempDir::new();
        let home = TempDir::new();
        assert_eq!(
            space_key_path_from(Some(creds.path().into()), Some(home.path().into())),
            None
        );
        let in_home = write_key(home.path());
        assert_eq!(
            space_key_path_from(Some(creds.path().into()), Some(home.path().into())),
            Some(in_home)
        );
        let in_creds = write_key(creds.path());
        assert_eq!(
            space_key_path_from(Some(creds.path().into()), Some(home.path().into())),
            Some(in_creds)
        );
    }
}
