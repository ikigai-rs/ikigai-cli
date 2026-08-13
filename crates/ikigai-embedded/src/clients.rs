//! Per-identity authority for served kernels: which authenticated client certificate
//! gets which named grant.
//!
//! A served kernel had exactly two postures, and neither could say "this client, these
//! scopes": `serve --cap …` sets one ceiling shared by every authenticated client, and
//! the default gives each client a filesystem workspace whose capability is *derived*
//! from its own directory. Reading personal data over the wire needs the third: the
//! authority is a function of WHICH certificate authenticated.
//!
//! The mapping lives in `clients.json`, beside `grants.json` in the ikigai config home
//! (env override `IKIGAI_CLIENTS`), and reuses the grants machinery rather than
//! inventing a parallel vocabulary of scopes — a *client* maps to a **grant name**, and
//! [`grant_scopes`](crate::grant_scopes) says what that name means:
//!
//! ```json
//! {
//!   "clients": {
//!     "6f1c…64 hex…": { "grant": "contacts-ro", "label": "linux-box" },
//!     "a920…64 hex…": "calendar-ro"
//!   },
//!   "default": "freebusy"
//! }
//! ```
//!
//! The key is the **stable** certificate fingerprint — lowercase hex SHA-256 of the
//! leaf DER, what `openssl x509 -noout -fingerprint -sha256` prints. Colons and case
//! are accepted and normalized away, so the tooling's own output pastes in unedited.
//!
//! Two properties are load-bearing:
//!
//! - **Live.** Both files are re-read on every connection, never cached. Editing
//!   `clients.json` revokes a client's authority on its next connection — revocation
//!   by editing a file, not by waiting out a TTL. Deleting the whole file revokes
//!   everyone.
//! - **Fail closed.** An enrolled certificate with no usable grant is REFUSED, never
//!   silently handed the shared ceiling or root. A shared default exists only when the
//!   operator writes `"default"` explicitly; absence never implies one. (The MCP grant
//!   path has the opposite footgun — an empty grant there yields root — which is
//!   exactly what is not reproduced here.)
//!
//! A grant's **file** scopes are the one kind that is not simply carried through: a
//! served client addresses files inside its own workspace, not by absolute host path,
//! so `urn:cap:fs:read:notes` is written the way the client names it and is resolved
//! against that workspace when the session is minted. See [`crate::tenant`] — which
//! also says why an absolute path outside the served jail stops `serve` at startup
//! instead of becoming a grant that quietly authorizes nothing.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ikigai_core::Capability;

/// Where the per-identity client map is read from: `$IKIGAI_CLIENTS` else
/// `clients.json` in the [config home](crate::config::config_home) — beside `grants.json`,
/// which it references by name. "Beside" is the whole point, so both resolve the config
/// home the same way; this file once spelled it `$HOME/.config/ikigai` directly, which put
/// it in a different directory than `config.toml` wherever `XDG_CONFIG_HOME` was set.
pub fn clients_path() -> Option<PathBuf> {
    std::env::var_os("IKIGAI_CLIENTS")
        .map(PathBuf::from)
        .or_else(|| crate::config::config_home().map(|dir| dir.join("clients.json")))
}

/// The parsed enrolment: fingerprint → grant name, plus the operator's *explicit*
/// shared default (`None` when they wrote none — absence is never a default).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Enrolment {
    clients: BTreeMap<String, String>,
    default_grant: Option<String>,
}

impl Enrolment {
    /// How many certificates are enrolled — for the serve banner.
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// The explicitly configured shared default grant, if any.
    pub fn default_grant(&self) -> Option<&str> {
        self.default_grant.as_deref()
    }

    /// The grant name for a fingerprint: its own entry, else the explicit default.
    pub fn grant_for(&self, fingerprint: &str) -> Option<&str> {
        self.clients
            .get(&normalize(fingerprint))
            .map(String::as_str)
            .or_else(|| self.default_grant())
    }

    /// Every enrolled grant name (plus the default), deduped — the operator's full
    /// declared intent, which is what decides the served SURFACE at startup.
    pub fn grant_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .clients
            .values()
            .cloned()
            .chain(self.default_grant.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

/// Read the enrolment from `clients_path()`.
///
/// `Ok(None)` means there is no such file — the server keeps its historical postures.
/// `Err` means the file EXISTS and is unusable: a broken authority config must stop the
/// server, not degrade it into serving everyone under the old shared ceiling.
pub fn enrolment() -> Result<Option<Enrolment>, String> {
    let Some(path) = clients_path() else {
        return Ok(None);
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    parse(&text)
        .map(Some)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Parse the `clients.json` shape. Both entry spellings are accepted: the object form
/// `{"grant": "…", "label": "…"}` (the label is for humans reading the file and the
/// server's logs) and the bare string form `"…"`.
fn parse(text: &str) -> Result<Enrolment, String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let mut clients = BTreeMap::new();
    // An absent `clients` object is legal — it is how an operator disables everyone
    // while keeping the file (and its default) around.
    if let Some(map) = v.get("clients") {
        let map = map
            .as_object()
            .ok_or("`clients` must be an object of fingerprint → grant")?;
        for (fingerprint, entry) in map {
            let grant = match entry {
                serde_json::Value::String(name) => name.clone(),
                serde_json::Value::Object(_) => entry
                    .get("grant")
                    .and_then(|g| g.as_str())
                    .ok_or_else(|| format!("client `{fingerprint}` has no `grant`"))?
                    .to_string(),
                _ => {
                    return Err(format!(
                        "client `{fingerprint}` must be a grant name or an object with one"
                    ))
                }
            };
            clients.insert(normalize(fingerprint), grant);
        }
    }
    let default_grant = match v.get("default") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(name)) => Some(name.clone()),
        Some(_) => return Err("`default` must be a grant name".to_string()),
    };
    Ok(Enrolment {
        clients,
        default_grant,
    })
}

/// Fold a fingerprint into its canonical form: lowercase, no colons or whitespace.
/// `openssl` prints `AB:CD:…`; this file may say `abcd…`; they are the same client.
fn normalize(fingerprint: &str) -> String {
    fingerprint
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .flat_map(char::to_lowercase)
        .collect()
}

/// Resolve an authenticated fingerprint to the authority its connection runs under,
/// bounded by `ceiling`. Returns `(grant name, capability)`; `Err(reason)` REFUSES the
/// connection, and the reason is written for a server log line.
///
/// Both config files are read here, on every call, so an edit takes effect on the next
/// connection. The ceiling is applied last and can only narrow: the order is
/// `operator ceiling (--cap) ∩ per-identity grant`, and the wire clamp then applies the
/// third term (`∩ carried capability`) per call.
pub fn authority(fingerprint: &str, ceiling: &Capability) -> Result<(String, Capability), String> {
    let enrolment = match enrolment()? {
        Some(enrolment) => enrolment,
        // The file went away while serving. That is a revocation, not a licence.
        None => {
            return Err(format!(
                "no client enrolment file ({})",
                clients_path().map_or_else(|| "unset".into(), |p| p.display().to_string())
            ))
        }
    };
    authority_in(&enrolment, fingerprint, ceiling, crate::grant_scopes)
}

/// [`authority`] over an already-parsed enrolment and an explicit grant lookup — the
/// whole policy, with the file reading factored out so it can be tested hermetically.
fn authority_in(
    enrolment: &Enrolment,
    fingerprint: &str,
    ceiling: &Capability,
    scopes_of: impl Fn(&str) -> Vec<String>,
) -> Result<(String, Capability), String> {
    let Some(grant) = enrolment.grant_for(fingerprint) else {
        return Err("no grant is configured for this certificate".to_string());
    };
    let scopes = scopes_of(grant);
    // The footgun, refused: an unknown or empty grant is not "unrestricted", it is
    // "undecided", and an undecided client gets nothing.
    if scopes.is_empty() {
        return Err(format!(
            "grant `{grant}` is unknown or grants no scopes (check grants.json)"
        ));
    }
    // `clamp` never widens: a scoped ceiling yields the intersection, and a root
    // ceiling (no `--cap`) yields exactly the grant's scopes.
    Ok((
        grant.to_string(),
        ceiling.clamp(&Capability::scoped(scopes)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The grants a test's `grants.json` would hold.
    fn grants(name: &str) -> Vec<String> {
        match name {
            "contacts-ro" => vec!["urn:cap:personal:contacts:read".to_string()],
            "everything" => vec![
                "urn:cap:personal:contacts:read".to_string(),
                "urn:cap:personal:calendar:read:detail".to_string(),
            ],
            // A grant NAMED in clients.json but absent from grants.json.
            _ => vec![],
        }
    }

    const FP: &str = "6f1c00000000000000000000000000000000000000000000000000000000abcd";

    fn enrolled(fingerprint: &str, grant: &str) -> Enrolment {
        parse(&format!(
            r#"{{"clients": {{"{fingerprint}": {{"grant": "{grant}", "label": "test"}}}}}}"#
        ))
        .unwrap()
    }

    /// What `openssl x509 -noout -fingerprint -sha256` prints — uppercase, colon
    /// separated — must enrol a client without hand-editing. Same client, either way.
    #[test]
    fn an_openssl_style_fingerprint_names_the_same_client() {
        let openssl = "6F:1C:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:AB:CD";
        let e = enrolled(openssl, "contacts-ro");
        assert_eq!(e.grant_for(FP), Some("contacts-ro"));
        assert_eq!(e.grant_for(openssl), Some("contacts-ro"));
    }

    /// The bare-string entry form is equivalent to the object form.
    #[test]
    fn both_entry_spellings_mean_the_same_grant() {
        let object = enrolled(FP, "contacts-ro");
        let bare = parse(&format!(r#"{{"clients": {{"{FP}": "contacts-ro"}}}}"#)).unwrap();
        assert_eq!(object, bare);
    }

    /// FAIL CLOSED. An unknown certificate must be refused — never quietly handed the
    /// shared `--cap` ceiling, and never root. This is the whole safety property: the
    /// server holds a real ceiling here, and the unknown client still gets nothing.
    #[test]
    fn an_unenrolled_certificate_is_refused_not_given_the_ceiling() {
        let enrolment = enrolled(FP, "contacts-ro");
        let ceiling = Capability::scoped(["urn:cap:personal:contacts:read".to_string()]);
        let stranger = "0000000000000000000000000000000000000000000000000000000000000000";
        let refused = authority_in(&enrolment, stranger, &ceiling, grants).unwrap_err();
        assert!(
            refused.contains("no grant is configured"),
            "unexpected reason: {refused}"
        );
    }

    /// The other half of the footgun: a certificate that IS enrolled, naming a grant
    /// that `grants.json` doesn't define (a typo, or a grant since deleted). Empty
    /// scopes must mean "refused", not "unrestricted".
    #[test]
    fn an_enrolled_certificate_naming_an_empty_grant_is_refused() {
        let enrolment = enrolled(FP, "typo-ro");
        let refused = authority_in(&enrolment, FP, &Capability::root(), grants).unwrap_err();
        assert!(refused.contains("typo-ro"), "unexpected reason: {refused}");
    }

    /// A shared default must be written, never implied. With one, the stranger gets the
    /// default's authority; the same file without it refuses them.
    #[test]
    fn a_shared_default_applies_only_when_explicitly_configured() {
        let stranger = "0000000000000000000000000000000000000000000000000000000000000000";
        let with = parse(&format!(
            r#"{{"clients": {{"{FP}": "everything"}}, "default": "contacts-ro"}}"#
        ))
        .unwrap();
        let (grant, capability) =
            authority_in(&with, stranger, &Capability::root(), grants).unwrap();
        assert_eq!(grant, "contacts-ro");
        assert!(capability.allows("urn:cap:personal:contacts:read"));
        // Their own entry still wins over the default.
        assert_eq!(with.grant_for(FP), Some("everything"));

        let without = parse(&format!(r#"{{"clients": {{"{FP}": "everything"}}}}"#)).unwrap();
        assert!(authority_in(&without, stranger, &Capability::root(), grants).is_err());
    }

    /// A grant NARROWER than `--cap` yields the narrow set — the point of the feature.
    #[test]
    fn a_narrower_grant_narrows_below_the_operator_ceiling() {
        let ceiling = Capability::scoped([
            "urn:cap:personal:contacts:read".to_string(),
            "urn:cap:personal:calendar:read:detail".to_string(),
        ]);
        let (_, capability) =
            authority_in(&enrolled(FP, "contacts-ro"), FP, &ceiling, grants).unwrap();
        assert!(capability.allows("urn:cap:personal:contacts:read"));
        assert!(
            !capability.allows("urn:cap:personal:calendar:read:detail"),
            "a narrow grant must not keep the ceiling's other scopes"
        );
    }

    /// A grant naming a scope OUTSIDE the operator's ceiling must not gain it: per
    /// identity grants attenuate, they never widen. `--cap` stays the outer bound.
    #[test]
    fn a_grant_cannot_widen_past_the_operator_ceiling() {
        let ceiling = Capability::scoped(["urn:cap:personal:contacts:read".to_string()]);
        let (_, capability) =
            authority_in(&enrolled(FP, "everything"), FP, &ceiling, grants).unwrap();
        assert!(capability.allows("urn:cap:personal:contacts:read"));
        assert!(
            !capability.allows("urn:cap:personal:calendar:read:detail"),
            "the grant named a scope the ceiling never granted — it must be clamped away"
        );
        // Without a ceiling (`serve` with no `--cap`), the grant IS the authority.
        let (_, unbounded) =
            authority_in(&enrolled(FP, "everything"), FP, &Capability::root(), grants).unwrap();
        assert!(unbounded.allows("urn:cap:personal:calendar:read:detail"));
    }

    /// Editing the file is the revocation mechanism, so re-reading must actually change
    /// the answer — including all the way to refusal when the entry is removed.
    #[test]
    fn editing_the_enrolment_changes_the_next_connections_authority() {
        let before = enrolled(FP, "everything");
        let (grant, capability) = authority_in(&before, FP, &Capability::root(), grants).unwrap();
        assert_eq!(grant, "everything");
        assert!(capability.allows("urn:cap:personal:calendar:read:detail"));

        // The operator narrows the client's grant.
        let after = enrolled(FP, "contacts-ro");
        let (grant, capability) = authority_in(&after, FP, &Capability::root(), grants).unwrap();
        assert_eq!(grant, "contacts-ro");
        assert!(!capability.allows("urn:cap:personal:calendar:read:detail"));

        // The operator deletes the entry: revoked outright, no fallback.
        let revoked = parse(r#"{"clients": {}}"#).unwrap();
        assert!(authority_in(&revoked, FP, &Capability::root(), grants).is_err());
    }

    /// A file that exists but doesn't parse must be an ERROR, not an empty enrolment:
    /// silently reading a broken authority config as "nobody is enrolled" would look
    /// identical to a server that had simply not been configured yet.
    #[test]
    fn a_malformed_enrolment_is_an_error_rather_than_an_empty_one() {
        assert!(parse("{ not json").is_err());
        assert!(parse(r#"{"clients": ["a", "b"]}"#).is_err());
        assert!(parse(&format!(r#"{{"clients": {{"{FP}": {{"label": "x"}}}}}}"#)).is_err());
        assert!(parse(r#"{"default": 7}"#).is_err());
        // Legal: no `clients` key at all — the file with everyone removed.
        assert!(parse("{}").unwrap().is_empty());
    }

    /// The served surface is chosen at startup from the operator's whole declared
    /// intent, so the grant names must come back deduped, default included.
    #[test]
    fn the_declared_grant_names_include_the_default_and_dedupe() {
        let e = parse(&format!(
            r#"{{"clients": {{"{FP}": "contacts-ro", "aa": "contacts-ro"}}, "default": "everything"}}"#
        ))
        .unwrap();
        assert_eq!(e.grant_names(), vec!["contacts-ro", "everything"]);
        assert_eq!(e.len(), 2);
    }
}
