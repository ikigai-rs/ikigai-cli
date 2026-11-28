//! The host's secret stores, from the config home's `[secret]` section (ledger #4487).
//!
//! With no section, the host builds exactly what `ikigai_secret::default_backend()` builds (the
//! Keychain on a Mac, the file store elsewhere, `IKIGAI_SECRETS` still honored for its path) and
//! mounts the plain `urn:secret:*` space over it, so every secret keeps its name, `store` and
//! `route` included. With a section, it builds ikigai-secret's `RoutingBackend` over the stores
//! the section names and mounts the routed space, which adds the inspection resources
//! (`urn:secret:store`, `urn:secret:route`, `urn:secret:store:name:{store}`,
//! `urn:secret:route:secret:{name}`) ahead of `urn:secret:{name}`; the host says once at start
//! which names that reserves ([`announcement`]).
//!
//! The section is read once per process: a change needs a restart. A malformed section stops the
//! start with ikigai-secret's own sentence ([`configure`]); nothing in it is half-applied.

use std::path::Path;
use std::sync::{Arc, OnceLock};

use ikigai_secret::{RoutingBackend, SecretConfig, SecretSection};

/// The checked section and the backend built from it, or the sentence that refused it.
fn stores() -> &'static Result<Arc<RoutingBackend>, String> {
    static STORES: OnceLock<Result<Arc<RoutingBackend>, String>> = OnceLock::new();
    STORES.get_or_init(|| {
        let section = crate::config::secret_section()?;
        routing_from(
            section.as_ref(),
            crate::config::user_home().as_deref(),
            &crate::config::config_path_shown(),
        )
    })
}

/// Check `section` (read from `file`) for this platform and build its stores. `home` is the
/// directory a store `path` beginning with `~/` is read under. A refusal is `file` followed by
/// ikigai-secret's sentence, which lists every problem.
pub(crate) fn routing_from(
    section: Option<&SecretSection>,
    home: Option<&Path>,
    file: &str,
) -> Result<Arc<RoutingBackend>, String> {
    SecretConfig::from_section(section, home)
        .map(|config| Arc::new(config.build()))
        .map_err(|e| format!("{file}: {e}"))
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
        Ok(routing) => Arc::clone(routing),
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
    let routing = stores().as_ref().ok()?;
    announcement_for(routing.config())
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
        let routing = routing_from(None, None, "config.toml").unwrap();
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
        let routing = routing_from(section(&text).as_ref(), None, "config.toml").unwrap();
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
        let refused = match routing_from(section(text).as_ref(), None, "/home/x/config.toml") {
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
