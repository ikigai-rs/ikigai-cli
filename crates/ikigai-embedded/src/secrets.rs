//! The host's secret stores, from the config home's `[secret]` section (ledger #4487), and the
//! default store a host without one gets (ledger #4548).
//!
//! With no section, ikigai-secret's [`found_install`](ikigai_secret::found_install) says what is
//! already on this machine, without reading any secret, and
//! [`SecretConfig::for_host`] turns that into the store:
//!
//! - an install from before (Keychain items under `ikigai-secret`, a file store holding a secret,
//!   or `IKIGAI_SECRETS` set) keeps exactly the store it had (the Keychain on a Mac, the file
//!   store elsewhere), and the host says once at start that new installs get an `age-file` store
//!   and how to move to one ([`notice`]). No secret moves.
//! - the `age-file` store an earlier start of a new install made (its marker is in the data
//!   home's `secrets` directory) stays that store.
//! - a new install (nothing there) gets one `age-file` store, named `age-file`, in the data
//!   home's `secrets` directory, each secret encrypted at rest to the host's key (below). A
//!   host with no absolute home has no data home to make it in, and keeps today's store.
//!
//! Either way the plain `urn:secret:*` space is mounted over it, so every secret keeps its name,
//! `store` and `route` included. With a section, the host builds ikigai-secret's `RoutingBackend`
//! over the stores the section names and mounts the routed space, which adds the inspection
//! resources (`urn:secret:store`, `urn:secret:route`, `urn:secret:store:name:{store}`,
//! `urn:secret:route:secret:{name}`) ahead of `urn:secret:{name}`; the host says once at start
//! which names that reserves ([`announcement`]).
//!
//! The section is read once per process: a change needs a restart. A malformed section stops the
//! start with ikigai-secret's own sentence ([`configure`]); nothing in it is half-applied.
//!
//! ## The host's key
//!
//! An `age-file` store whose `identity` is `default` ([`HOST_DEFAULT_IDENTITY`], what the store a
//! new install gets names) is sealed to the host's key: an age identity file named
//! [`SECRET_KEY_FILE`], found as the space key is (`$CREDENTIALS_DIRECTORY/secret.key` when
//! systemd passes it as a credential, else `<config home>/secret.key`). For a new install's store
//! the host makes that file (`0600`) on the store's first write; every other store needs it to be
//! there already, so a lost key is never silently replaced by a new one that opens nothing. Any
//! other `identity` is refused at start: this host resolves only `default` so far.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use ikigai_secret::{
    AgeError, AgeKeys, Found, RoutingBackend, SecretConfig, SecretSection, StoreKind, X25519Keys,
    HOST_DEFAULT_IDENTITY,
};

/// The host key's file name, in `$CREDENTIALS_DIRECTORY` and in the config home.
pub const SECRET_KEY_FILE: &str = "secret.key";

/// The stores this host chose, and the start-up notice that goes with them.
struct Stores {
    routing: Arc<RoutingBackend>,
    /// ikigai-secret's line for an install from before that keeps its store ([`notice`]).
    notice: Option<String>,
}

/// The checked section and the backend built from it, or the sentence that refused it.
fn stores() -> &'static Result<Stores, String> {
    static STORES: OnceLock<Result<Stores, String>> = OnceLock::new();
    STORES.get_or_init(|| {
        let section = crate::config::secret_section()?;
        let home = crate::config::user_home();
        // With a section, `for_host` does not consult what is found, so nothing is probed.
        let found = match section {
            Some(_) => Found::Existing,
            None => ikigai_secret::found_install(home.as_deref()).map_err(|e| {
                format!("the secret store could not be chosen, because looking for one failed: {e}")
            })?,
        };
        let build_for = chosen(section.is_some(), home.as_deref(), found);
        let routing = routing_from(
            section.as_ref(),
            home.as_deref(),
            build_for,
            &host_key_place(),
            &crate::config::config_path_shown(),
        )?;
        let notice = notice_for(section.is_some(), found, routing.config());
        Ok(Stores { routing, notice })
    })
}

/// What to build for: `found`, except that with no section and no absolute `home` (no `HOME`,
/// so no data home to make an `age-file` store in) the host keeps today's store, as every host
/// did before ikigai-secret 0.5.4, rather than refusing to start.
pub(crate) fn chosen(section: bool, home: Option<&Path>, found: Found) -> Found {
    if section || found == Found::Existing || home.is_some_and(Path::is_absolute) {
        found
    } else {
        Found::Existing
    }
}

/// The notice for what was found: ikigai-secret's line only for an install from before with no
/// section. A host with no home keeps today's store too, but it is not an install from before,
/// so it is not told how to move.
pub(crate) fn notice_for(section: bool, found: Found, config: &SecretConfig) -> Option<String> {
    (!section && found == Found::Existing)
        .then(|| config.notice())
        .flatten()
}

/// Where the host key is, or would be made: `$CREDENTIALS_DIRECTORY/secret.key` when that file
/// exists, else `<config home>/secret.key`; `None` with neither a credential nor a config home.
fn host_key_place() -> KeyPlace {
    let credential = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(|dir| PathBuf::from(dir).join(SECRET_KEY_FILE))
        .filter(|path| path.exists());
    KeyPlace(credential.or_else(|| Some(crate::config::config_home()?.join(SECRET_KEY_FILE))))
}

/// Where the host key is ([`host_key_place`]), passed in so tests choose it.
#[derive(Clone, Debug)]
pub(crate) struct KeyPlace(pub(crate) Option<PathBuf>);

/// Choose the stores for `section` (read from `file`) and what `found` says is on this machine,
/// and build them, with the host key at `key` for each `age-file` store whose identity is
/// `default`. `home` is the directory a store `path` beginning with `~/` is read under, and the
/// one the data home is under. A refusal of the section is `file` followed by ikigai-secret's
/// sentence, which lists every problem.
pub(crate) fn routing_from(
    section: Option<&SecretSection>,
    home: Option<&Path>,
    found: Found,
    key: &KeyPlace,
    file: &str,
) -> Result<Arc<RoutingBackend>, String> {
    let named = |e: &dyn std::fmt::Display| match section {
        Some(_) => format!("{file}: {e}"),
        None => e.to_string(),
    };
    let config = SecretConfig::for_host(section, home, found).map_err(|e| named(&e))?;
    // Only the store a new install gets may make the key: any other store with no key file
    // would get a key that opens none of the secrets already in it.
    let may_make = section.is_none() && found == Found::Nothing;
    let mut keys: BTreeMap<String, Arc<dyn AgeKeys>> = BTreeMap::new();
    let mut refused = Vec::new();
    for store in config.stores() {
        if let StoreKind::AgeFile {
            identity,
            recipients,
            ..
        } = store.kind()
        {
            if identity == HOST_DEFAULT_IDENTITY {
                let host = HostKey::new(key.0.clone(), recipients.clone(), may_make);
                keys.insert(store.name().to_string(), Arc::new(host));
            } else {
                refused.push(format!(
                    "- `identity = {identity:?}` in [secret.store.{}] is not an identity this \
                     host can read: it reads only `identity = \"default\"`, its own key file \
                     ({SECRET_KEY_FILE} in the config home, or in $CREDENTIALS_DIRECTORY)",
                    store.name()
                ));
            }
        }
    }
    if !refused.is_empty() {
        return Err(format!(
            "{file}: The [secret] section was refused and nothing in it was applied ({}):\n{}",
            match refused.len() {
                1 => "1 problem".to_string(),
                n => format!("{n} problems"),
            },
            refused.join("\n")
        ));
    }
    config
        .build_with_keys(keys)
        .map(Arc::new)
        .map_err(|e| named(&e))
}

/// The host's age key for an `age-file` store whose identity is `default`: the age identity file
/// at its place ([`host_key_place`]), read on the store's first use, and made there on its first
/// write when the host may make it (the store a new install gets). Every item is sealed to the
/// key's own recipient and to the store's configured `recipients`. Nothing here ever names a key
/// or a value.
pub(crate) struct HostKey {
    path: Option<PathBuf>,
    recipients: Vec<String>,
    may_make: bool,
    keys: Mutex<Option<Arc<X25519Keys>>>,
}

impl HostKey {
    pub(crate) fn new(path: Option<PathBuf>, recipients: Vec<String>, may_make: bool) -> Self {
        HostKey {
            path,
            recipients,
            may_make,
            keys: Mutex::new(None),
        }
    }

    /// The keys, read once from the file; made first when `make` and the file is not there.
    fn keys(&self, make: bool) -> Result<Arc<X25519Keys>, AgeError> {
        let mut held = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(keys) = held.as_ref() {
            return Ok(Arc::clone(keys));
        }
        let Some(path) = self.path.as_deref() else {
            return Err(AgeError::Failed(
                "the host has no config home to keep its secret key in (secret.key); set HOME, \
                 or name the directory with --config-home <dir>"
                    .to_string(),
            ));
        };
        let text = match read_key(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && make && self.may_make => {
                make_key(path)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(AgeError::Failed(format!(
                    "the host's secret key {} is not there, so this store can neither read nor \
                     write a secret; put the age identity it was made with back in that file",
                    path.display()
                )))
            }
            Err(e) => {
                return Err(AgeError::Failed(format!(
                    "the host's secret key {} cannot be used: {e}",
                    path.display()
                )))
            }
        };
        let keys = X25519Keys::new(&text, &self.recipients).map_err(|e| {
            AgeError::Failed(format!(
                "the host's secret key {} cannot be used: {e}",
                path.display()
            ))
        })?;
        let keys = Arc::new(keys);
        *held = Some(Arc::clone(&keys));
        Ok(keys)
    }
}

impl AgeKeys for HostKey {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, AgeError> {
        self.keys(true)?.seal(plaintext)
    }

    fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, AgeError> {
        self.keys(false)?.open(ciphertext)
    }
}

/// The key file's text. Refused, never echoing a line of it, when group or others can reach it
/// (a root-owned file may be group-readable, as systemd's credential store writes it).
fn read_key(path: &Path) -> std::io::Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)?;
        let mode = meta.mode() & 0o777;
        let allowed = if meta.uid() == 0 { 0o740 } else { 0o700 };
        if mode & !allowed != 0 {
            return Err(std::io::Error::other(format!(
                "it is mode {mode:o}, so others can reach it (fix: chmod 600 {})",
                path.display()
            )));
        }
    }
    std::fs::read_to_string(path)
}

/// Make a new age identity in a new owner-only file at `path`, and answer its text. Another
/// process that made it first wins: its file is read instead.
fn make_key(path: &Path) -> Result<String, AgeError> {
    use ikigai_encrypt::age::{ExposeSecret, Identity};
    use std::io::Write;
    let failed = |e: std::io::Error| {
        AgeError::Failed(format!(
            "the host's secret key {} could not be made: {e}",
            path.display()
        ))
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(failed)?;
    }
    let identity = Identity::generate();
    let text = format!(
        "# The age identity ikigai seals its age-file secret store to. Keep a copy somewhere \
         safe: without it no secret in the store can be opened.\n# public key: {}\n{}\n",
        identity.to_public(),
        identity.to_string().expose_secret()
    );
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut out) => {
            out.write_all(text.as_bytes())
                .and_then(|()| out.sync_all())
                .map_err(failed)?;
            Ok(text)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read_key(path).map_err(failed),
        Err(e) => Err(failed(e)),
    }
}

/// Read and check the config home's `[secret]` section before any mode starts: `Err` is the
/// sentence the binary prints before it refuses to start. Embedded callers that skip it get the
/// same refusal as a panic when the first kernel is built.
pub fn configure() -> Result<(), String> {
    stores().as_ref().map(|_| ()).map_err(Clone::clone)
}

/// The routing backend every secret reader in this host shares: the `urn:secret:*` space, and
/// the LLM and meeting readers.
pub(crate) fn routing() -> Arc<RoutingBackend> {
    match stores() {
        Ok(stores) => Arc::clone(&stores.routing),
        Err(e) => panic!("{e}"),
    }
}

/// The `urn:secret:*` space over `routing`: the plain space when no `[secret]` section was
/// given (today's names, unchanged), the routed one with its inspection resources when one was.
pub(crate) fn space_over(routing: Arc<RoutingBackend>) -> ikigai_core::EndpointSpace {
    if routing.config().is_configured() {
        ikigai_secret::routed_space(routing)
    } else {
        ikigai_secret::space(routing)
    }
}

/// The `urn:secret:*` space for this host's local root. See [`space_over`].
pub(crate) fn space() -> ikigai_core::EndpointSpace {
    space_over(routing())
}

/// The one start-up line for a configured `[secret]` section, or `None` without one (or when it
/// was refused, which [`configure`] reports).
pub fn announcement() -> Option<String> {
    let stores = stores().as_ref().ok()?;
    announcement_for(stores.routing.config())
}

/// The one start-up line for an install from before that keeps its store (no `[secret]`
/// section): ikigai-secret's own sentence, that new installs now get an `age-file` store, how to
/// move to one, and that `IKIGAI_SECRETS` is deprecated. `None` for every other store.
pub fn notice() -> Option<String> {
    stores().as_ref().ok()?.notice.clone()
}

/// [`announcement`] for `config`.
pub(crate) fn announcement_for(config: &SecretConfig) -> Option<String> {
    if !config.is_configured() {
        return None;
    }
    let stores = config
        .stores()
        .iter()
        .map(|store| {
            let access = if store.writable() { "" } else { ", read-only" };
            format!("`{}` ({}{access})", store.name(), store.kind().name())
        })
        .collect::<Vec<_>>()
        .join(", ");
    let routes = match config.routes().len() {
        1 => "1 route".to_string(),
        n => format!("{n} routes"),
    };
    Some(format!(
        "ikigai: secrets: the [secret] section is in use: stores {stores}, default `{}`, {routes}. \
         These names are reserved for inspecting it and are never a secret's: urn:secret:store, \
         urn:secret:route, and every name beginning urn:secret:store:name: or \
         urn:secret:route:secret:. Reading them needs urn:cap:secret:inspect, except a name's \
         route, which needs that name's read scope.",
        config.default_store()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::{Capability, Iri, Kernel, Request, Verb};
    use ikigai_secret::Backend;

    fn section(text: &str) -> Option<SecretSection> {
        crate::config::secret_section_in(text).expect("section reads")
    }

    fn read(kernel: &Kernel, iri: &str, cap: &Capability) -> ikigai_core::Result<Vec<u8>> {
        let request = Request::new(Verb::Source, Iri::parse(iri).unwrap());
        futures::executor::block_on(kernel.issue(request, cap)).map(|r| r.bytes)
    }

    /// No section: the plain space, so a secret named `store` or `route` is still a secret, and
    /// no inspection name is bound.
    #[test]
    fn no_section_keeps_every_name_a_secret() {
        let routing =
            routing_from(None, None, Found::Existing, &KeyPlace(None), "config.toml").unwrap();
        assert!(!routing.config().is_configured());
        assert_eq!(announcement_for(routing.config()), None);
        #[allow(clippy::disallowed_methods)]
        // internal: a test kernel over the secret space alone; its requests name no arguments
        let kernel = Kernel::new(Arc::new(space_over(routing)));
        let inspect = Capability::scoped([ikigai_secret::INSPECT_SCOPE.to_string()]);
        let refused = read(&kernel, "urn:secret:store", &inspect).unwrap_err();
        assert!(
            refused.to_string().contains("urn:cap:secret:read:"),
            "`store` is a secret's name, under its read scope: {refused}"
        );
    }

    /// A section routing one name to a second file store reads that name from there, and every
    /// other name from the default.
    #[test]
    fn a_route_sends_a_name_to_its_store() {
        let dir = std::env::temp_dir().join(format!("iki-secret-routes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let main = dir.join("main");
        let team = dir.join("team");
        let text = format!(
            "files = \"/srv\"\n\n[secret]\ndefault = \"main\"\n\n[secret.store.main]\nkind = \
             \"file\"\npath = {main:?}\n\n[secret.store.team]\nkind = \"file\"\npath = \
             {team:?}\nwrite = false\n\n[[secret.route]]\nmatch = \"zoom.*\"\nstore = \"team\"\n"
        );
        ikigai_secret::FileBackend::new(&team)
            .set("zoom.token", b"from-team")
            .unwrap();
        ikigai_secret::FileBackend::new(&main)
            .set("other", b"from-main")
            .unwrap();
        let routing = routing_from(
            section(&text).as_ref(),
            None,
            Found::Existing,
            &KeyPlace(None),
            "config.toml",
        )
        .unwrap();
        let line = announcement_for(routing.config()).unwrap();
        assert!(line.contains("`team` (file, read-only)"), "{line}");
        assert!(line.contains("urn:secret:route:secret:"), "{line}");
        #[allow(clippy::disallowed_methods)]
        // internal: a test kernel over the secret space alone; its requests name no arguments
        let kernel = Kernel::new(Arc::new(space_over(routing)));
        let root = Capability::root();
        assert_eq!(
            read(&kernel, "urn:secret:zoom.token", &root).unwrap(),
            b"from-team"
        );
        assert_eq!(
            read(&kernel, "urn:secret:other", &root).unwrap(),
            b"from-main"
        );
        // No fallthrough: the default store does not answer for a routed name.
        assert!(read(&kernel, "urn:secret:zoom.other", &root).is_err());
        let inspect = Capability::scoped([ikigai_secret::INSPECT_SCOPE.to_string()]);
        let stores =
            String::from_utf8(read(&kernel, "urn:secret:store", &inspect).unwrap()).unwrap();
        assert!(stores.contains("team"), "{stores}");
        // A host flat key above the section is still the host's, and a route's `store` is not.
        assert_eq!(crate::config::host_part(&text), "files = \"/srv\"\n\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A section ikigai-secret refuses names the file and keeps ikigai-secret's sentence.
    #[test]
    fn a_malformed_section_is_refused_with_its_sentence() {
        let text = "[secret]\ndefault = \"nowhere\"\n\n[secret.store.main]\nkind = \"file\"\n";
        let refused = match routing_from(
            section(text).as_ref(),
            None,
            Found::Existing,
            &KeyPlace(None),
            "/home/x/config.toml",
        ) {
            Ok(_) => panic!("a default naming no store was accepted"),
            Err(e) => e,
        };
        assert!(
            refused.starts_with(
                "/home/x/config.toml: The [secret] section was refused and nothing in it was \
                 applied (1 problem):\n- `default = \"nowhere\"` in [secret] names no configured \
                 store"
            ),
            "{refused}"
        );
    }

    /// A scratch directory for one test, emptied first.
    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("iki-secret-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn source(routing: &RoutingBackend, name: &str) -> ikigai_core::Result<Vec<u8>> {
        Ok(routing.get(name)?.expect("the secret is there"))
    }

    /// An install from before (no section, `Found::Existing`) keeps today's store, unchanged,
    /// with the notice; no key is made.
    #[test]
    fn an_existing_install_keeps_its_store_and_gets_the_notice() {
        let home = scratch("existing");
        let key = home.join("config").join(SECRET_KEY_FILE);
        let routing = routing_from(
            None,
            Some(&home),
            Found::Existing,
            &KeyPlace(Some(key.clone())),
            "config.toml",
        )
        .unwrap();
        let today = SecretConfig::from_section(None, Some(&home)).unwrap();
        assert_eq!(routing.config(), &today);
        assert!(!routing.config().is_configured());
        let notice = routing
            .config()
            .notice()
            .expect("an existing install is told");
        assert!(notice.contains("age-file"), "{notice}");
        assert_eq!(announcement_for(routing.config()), None);
        assert!(!key.exists());
        let _ = std::fs::remove_dir_all(home);
    }

    /// A new install (`Found::Nothing`) gets the age-file store in the data home: its first
    /// write makes the host key (`0600`) and the store's marker, the item is age ciphertext, a
    /// second start (`Found::AgeFile`) reads it back, and there is no notice.
    #[test]
    #[cfg(unix)]
    fn a_new_install_gets_an_age_file_store_sealed_to_a_new_key() {
        use std::os::unix::fs::PermissionsExt;
        let home = scratch("new");
        let key = home.join("config").join(SECRET_KEY_FILE);
        let place = KeyPlace(Some(key.clone()));
        let routing =
            routing_from(None, Some(&home), Found::Nothing, &place, "config.toml").unwrap();
        assert_eq!(routing.config().default_store(), "age-file");
        assert_eq!(routing.config().notice(), None);
        assert!(!key.exists(), "nothing is made before the first write");
        routing.set("api-token", b"hunter2").unwrap();
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let item = std::fs::read(home.join(".ikigai/secrets/api-token")).unwrap();
        assert!(
            item.starts_with(ikigai_secret::AGE_HEADER),
            "sealed at rest"
        );
        assert_eq!(source(&routing, "api-token").unwrap(), b"hunter2");
        // The marker the first write left says so at the next start (`IKIGAI_SECRETS`, when the
        // test's own environment sets it, outranks the marker).
        if std::env::var_os("IKIGAI_SECRETS").is_none() {
            assert_eq!(
                ikigai_secret::found_install(Some(&home)).unwrap(),
                Found::AgeFile
            );
        }
        let again = routing_from(None, Some(&home), Found::AgeFile, &place, "config.toml").unwrap();
        assert_eq!(source(&again, "api-token").unwrap(), b"hunter2");
        let _ = std::fs::remove_dir_all(home);
    }

    /// A host with no section and no absolute home (no `HOME`) has no data home to make an
    /// age-file store in: it keeps today's store and starts, as before 0.5.4, with no notice.
    #[test]
    fn no_home_keeps_todays_store_without_the_notice() {
        for found in [Found::Nothing, Found::AgeFile] {
            let found = chosen(false, None, found);
            assert_eq!(found, Found::Existing);
            let routing = routing_from(None, None, found, &KeyPlace(None), "config.toml").unwrap();
            assert_eq!(
                routing.config(),
                &SecretConfig::from_section(None, None).unwrap()
            );
            // Not an install from before, so it is not told how to move.
            let notice = notice_for(false, Found::Nothing, routing.config());
            assert_eq!(notice, None);
        }
        // With a home, or with a section, what was found stands.
        let home = Path::new("/home/svc");
        assert_eq!(chosen(false, Some(home), Found::Nothing), Found::Nothing);
        assert_eq!(chosen(false, Some(home), Found::AgeFile), Found::AgeFile);
        assert_eq!(chosen(true, None, Found::Existing), Found::Existing);
        let existing = SecretConfig::from_section(None, Some(home)).unwrap();
        assert!(notice_for(false, Found::Existing, &existing).is_some());
        assert_eq!(notice_for(true, Found::Existing, &existing), None);
    }

    /// An age-file store from an earlier start whose key file is gone is never given a new key:
    /// a write is refused, naming the file, and no key file appears.
    #[test]
    fn a_lost_key_is_not_replaced() {
        let home = scratch("lost");
        let key = home.join("config").join(SECRET_KEY_FILE);
        let routing = routing_from(
            None,
            Some(&home),
            Found::AgeFile,
            &KeyPlace(Some(key.clone())),
            "config.toml",
        )
        .unwrap();
        let refused = routing
            .set("api-token", b"hunter2")
            .unwrap_err()
            .to_string();
        assert!(refused.contains(&key.display().to_string()), "{refused}");
        assert!(refused.contains("is not there"), "{refused}");
        assert!(!key.exists());
        let _ = std::fs::remove_dir_all(home);
    }

    /// A key file others can read is refused, naming its mode, and never echoed.
    #[test]
    #[cfg(unix)]
    fn a_reachable_key_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let home = scratch("reachable");
        let key = home.join(SECRET_KEY_FILE);
        let identity = ikigai_encrypt::age::Identity::generate();
        let text = {
            use ikigai_encrypt::age::ExposeSecret;
            identity.to_string().expose_secret().to_string()
        };
        std::fs::write(&key, format!("{text}\n")).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let host = HostKey::new(Some(key.clone()), Vec::new(), true);
        let refused = host.seal(b"x").unwrap_err().to_string();
        assert!(refused.contains("mode 644"), "{refused}");
        assert!(!refused.contains("AGE-SECRET-KEY"), "{refused}");
        let _ = std::fs::remove_dir_all(home);
    }

    /// A section's age-file store is sealed to the host key when its identity is `default`; any
    /// other identity is refused at start, naming the store.
    #[test]
    fn a_section_age_file_store_reads_only_the_default_identity() {
        let home = scratch("section-age");
        let text = "[secret]\ndefault = \"enc\"\n[secret.store.enc]\nkind = \"age-file\"\n\
                    path = \"~/enc\"\nidentity = \"file:/etc/ikigai/age\"\n";
        let refused = match routing_from(
            section(text).as_ref(),
            Some(&home),
            Found::Existing,
            &KeyPlace(None),
            "/home/x/config.toml",
        ) {
            Ok(_) => panic!("an identity this host cannot read was accepted"),
            Err(e) => e,
        };
        assert!(
            refused.starts_with(
                "/home/x/config.toml: The [secret] section was refused and nothing in it was \
                 applied (1 problem):\n- `identity = \"file:/etc/ikigai/age\"` in \
                 [secret.store.enc]"
            ),
            "{refused}"
        );
        let text = text.replace("file:/etc/ikigai/age", "default");
        let routing = routing_from(
            section(&text).as_ref(),
            Some(&home),
            Found::Existing,
            &KeyPlace(Some(home.join(SECRET_KEY_FILE))),
            "config.toml",
        )
        .unwrap();
        // The section's store did not make the key, so it refuses until one is put there.
        assert!(routing.set("x", b"y").is_err());
        assert!(!home.join(SECRET_KEY_FILE).exists());
        let _ = std::fs::remove_dir_all(home);
    }

    /// An unknown key is refused by the parser with the file's own line number.
    #[test]
    fn an_unknown_key_names_its_line() {
        let text = "files = \"/srv\"\n[secret]\ndefault = \"main\"\nkeybindings = \"vi\"\n";
        let refused = crate::config::secret_section_in(text).unwrap_err();
        assert!(refused.starts_with("line 4: "), "{refused}");
        assert!(refused.contains("keybindings"), "{refused}");
        assert!(refused.contains("goes above its first header"), "{refused}");
    }
}
