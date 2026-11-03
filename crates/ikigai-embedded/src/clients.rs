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
//!     "a920…64 hex…": "calendar-ro",
//!     "07be…64 hex…": { "label": "spare laptop" }
//!   },
//!   "default": "freebusy"
//! }
//! ```
//!
//! **`default` is the grant for an ENROLLED client whose entry names none** (the spare laptop
//! above), and nothing else. It never admits a certificate the `clients` map has no entry for:
//! removing a client's entry refuses that client whatever `default` says, at the next
//! connection, and a bearer token bound to it with it (ledger #1825). Through cli 0.1.63 it was
//! the grant for every trusted certificate that had no entry, so a removal under a `default`
//! moved the client to the default grant instead of refusing it. An entry that names no grant
//! in a file with no `default` is an unusable entry, refused with the file like any other.
//!
//! An object entry may also carry a `principal`: the IRI the door names that client by
//! (`"principal": "urn:collab:participant:bobby"`). Without one the door names it
//! [`default_principal`]`(host, fingerprint)` = `urn:iki:host:{host}:client:<fingerprint>`,
//! the convention every host's door follows (ledger #1179). The principal is WHO, never
//! WHAT: it is minted into the connection's capability as core's principal scope and
//! stamped on every request, and grants nothing by itself.
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
//! - **Fail closed.** A certificate with no entry is REFUSED, and so is an enrolled one with
//!   no usable grant: never silently handed the shared ceiling, the default or root. A
//!   default exists only when the operator writes `"default"` explicitly; absence never
//!   implies one. (The MCP grant path has the opposite footgun — an empty grant there
//!   yields root — which is exactly what is not reproduced here.)
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

/// The IRI a host's door names an enrolled client by when its `clients.json` entry names
/// no `principal`: `urn:iki:host:{host}:client:<fingerprint>`, where `host` is the serving
/// instance's name (`--name`) and the fingerprint is folded the way enrolment keys are
/// (lowercase hex, colons dropped), so `openssl`'s spelling and ours name one client.
///
/// Brian's convention, 2026-10-10 (ledger #1170): one shape for every host's minted client
/// IRI, so a log or a ledger can attribute across hosts without a per-host rule.
///
/// ```
/// use ikigai_embedded::clients::default_principal;
///
/// let fp = "6F:1C:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:AB:CD";
/// assert_eq!(
///     default_principal("layers", fp),
///     "urn:iki:host:layers:client:6f1c00000000000000000000000000000000000000000000000000000000abcd"
/// );
/// ```
pub fn default_principal(host: &str, fingerprint: &str) -> String {
    format!("urn:iki:host:{host}:client:{}", normalize(fingerprint))
}

/// The authority one connection runs under, as [`authorize`] decides it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    /// The grant name the certificate's entry names, or the explicit default when its entry
    /// names none.
    pub grant: String,
    /// `operator ceiling ∩ grant`.
    pub capability: Capability,
    /// The `principal` the client's OWN entry names, if it names one. `None` means the
    /// door names it [`default_principal`]. A client served under the `default` grant has an
    /// entry of its own too (nothing else is admitted), so it may name one.
    pub principal: Option<String>,
}

/// One enrolled certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    /// `None`: the entry names no grant, so the file's `default` applies (the parser refuses
    /// such an entry in a file that sets none).
    grant: Option<String>,
    principal: Option<String>,
}

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
/// default for an enrolled entry that names no grant (`None` when they wrote none —
/// absence is never a default).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Enrolment {
    clients: BTreeMap<String, Entry>,
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

    /// The explicitly configured default grant, if any: the grant an enrolled entry that
    /// names none is served under.
    pub fn default_grant(&self) -> Option<&str> {
        self.default_grant.as_deref()
    }

    /// Whether `fingerprint` has an entry of its own, folded the way every key is.
    pub fn is_enrolled(&self, fingerprint: &str) -> bool {
        self.clients.contains_key(&normalize(fingerprint))
    }

    /// The grant name for a fingerprint: the one its own entry names, else the explicit
    /// default when its entry names none. `None` for a fingerprint with no entry, whatever
    /// the default says: `default` covers enrolled clients, never strangers (ledger #1825).
    ///
    /// ```
    /// # fn main() -> Result<(), String> {
    /// let fp = "6f1c00000000000000000000000000000000000000000000000000000000abcd";
    /// let stranger = "0".repeat(64);
    /// let e = ikigai_embedded::clients::parse_enrolment(&format!(
    ///     r#"{{"clients": {{"{fp}": {{"label": "spare laptop"}}}}, "default": "freebusy"}}"#
    /// ))?;
    /// assert_eq!(e.grant_for(fp), Some("freebusy"));
    /// assert_eq!(e.grant_for(&stranger), None);
    /// # Ok(())
    /// # }
    /// ```
    pub fn grant_for(&self, fingerprint: &str) -> Option<&str> {
        let entry = self.clients.get(&normalize(fingerprint))?;
        entry.grant.as_deref().or_else(|| self.default_grant())
    }

    /// The `principal` a fingerprint's OWN entry names, if any. Never the default's: a
    /// default is a grant, and no single IRI can name every client it covers.
    pub fn principal_for(&self, fingerprint: &str) -> Option<&str> {
        self.clients
            .get(&normalize(fingerprint))
            .and_then(|entry| entry.principal.as_deref())
    }

    /// The key `named` is enrolled under, folded the way every key is (an `openssl`
    /// fingerprint, colons and case, names the same client), when the file enrolls it.
    pub fn key_for(&self, named: &str) -> Option<String> {
        let key = normalize(named);
        self.clients.contains_key(&key).then_some(key)
    }

    /// Every enrolled key whose OWN entry names `principal`, sorted.
    pub fn keys_with_principal(&self, principal: &str) -> Vec<String> {
        self.clients
            .iter()
            .filter(|(_, entry)| entry.principal.as_deref() == Some(principal))
            .map(|(key, _)| key.clone())
            .collect()
    }

    /// Every enrolled grant name (plus the default), deduped — the operator's full
    /// declared intent, which is what decides the served SURFACE at startup.
    pub fn grant_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .clients
            .values()
            .filter_map(|entry| entry.grant.clone())
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
/// `{"grant": "…", "label": "…", "principal": "…"}` (the label is for humans reading the
/// file and the server's logs; the principal is optional, see the module docs) and the
/// bare string form `"…"`. The object form may leave `grant` out when the file sets a
/// `default`: that entry is served under the default.
///
/// A `principal` that core could not carry as a principal (not an absolute IRI, a `*`,
/// over 512 bytes) is an ERROR, like every other unusable entry: silently minting none
/// would serve that client under a name its operator never wrote. So is an entry that names
/// no grant in a file with no `default`: it would enroll a client with no authority to give.
pub fn parse_enrolment(text: &str) -> Result<Enrolment, String> {
    parse(text)
}

/// [`parse_enrolment`], under the name this crate has always called it by.
pub(crate) fn parse(text: &str) -> Result<Enrolment, String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let default_grant = match v.get("default") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(name)) => Some(name.clone()),
        Some(_) => return Err("`default` must be a grant name".to_string()),
    };
    let mut clients = BTreeMap::new();
    // An absent `clients` object is legal — it is how an operator disables everyone
    // while keeping the file (and its default) around.
    if let Some(map) = v.get("clients") {
        let map = map
            .as_object()
            .ok_or("`clients` must be an object of fingerprint → grant")?;
        for (fingerprint, entry) in map {
            let parsed = match entry {
                serde_json::Value::String(name) => Entry {
                    grant: Some(name.clone()),
                    principal: None,
                },
                serde_json::Value::Object(_) => Entry {
                    grant: match entry.get("grant") {
                        Some(serde_json::Value::String(name)) => Some(name.clone()),
                        None | Some(serde_json::Value::Null) if default_grant.is_some() => None,
                        None | Some(serde_json::Value::Null) => {
                            return Err(format!(
                                "client `{fingerprint}` has no `grant`, and the file sets no \
                                 `default` for it to be served under"
                            ))
                        }
                        Some(_) => {
                            return Err(format!(
                                "client `{fingerprint}`: `grant` must be a grant name"
                            ))
                        }
                    },
                    principal: match entry.get("principal") {
                        None | Some(serde_json::Value::Null) => None,
                        Some(serde_json::Value::String(iri)) => {
                            ikigai_core::principal_scope(iri).map_err(|e| {
                                format!("client `{fingerprint}` names an unusable principal: {e}")
                            })?;
                            Some(iri.clone())
                        }
                        Some(_) => {
                            return Err(format!(
                                "client `{fingerprint}`: `principal` must be an IRI string"
                            ))
                        }
                    },
                },
                _ => {
                    return Err(format!(
                        "client `{fingerprint}` must be a grant name or an object with one"
                    ))
                }
            };
            clients.insert(normalize(fingerprint), parsed);
        }
    }
    Ok(Enrolment {
        clients,
        default_grant,
    })
}

/// Fold an identity key into its canonical form.
///
/// A **certificate fingerprint** — 64 hex digits once colons and whitespace are gone —
/// folds to lowercase: `openssl` prints `AB:CD:…`, this file may say `abcd…`, and they are
/// the same client.
///
/// Anything else is kept **verbatim** (trimmed), because the same map also enrols a libp2p
/// **PeerId** (`12D3KooW…`, see `docs/design/p2p-mobility-design.md`), and a PeerId is
/// base58 — CASE-SENSITIVE. Folding it the way a fingerprint folds would turn every PeerId
/// entry into a key no connection can ever present: fail-closed, but silently inert, which
/// is the failure this file exists to refuse.
fn normalize(key: &str) -> String {
    let compact: String = key
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if compact.len() == 64 && compact.chars().all(|c| c.is_ascii_hexdigit()) {
        compact.to_ascii_lowercase()
    } else {
        key.trim().to_string()
    }
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
    authorize(fingerprint, ceiling).map(|authority| (authority.grant, authority.capability))
}

/// [`authority`], plus the `principal` the client's own entry names — read from the SAME
/// reading of the file, so a grant and a name can never come from two different edits.
pub fn authorize(fingerprint: &str, ceiling: &Capability) -> Result<Authority, String> {
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
    let (grant, capability) = authority_in(&enrolment, fingerprint, ceiling, crate::grant_scopes)?;
    Ok(Authority {
        grant,
        capability,
        principal: enrolment.principal_for(fingerprint).map(str::to_string),
    })
}

/// [`authority`] over an already-parsed enrolment and an explicit grant lookup — the
/// whole policy, with the file reading factored out so it can be tested hermetically.
fn authority_in(
    enrolment: &Enrolment,
    fingerprint: &str,
    ceiling: &Capability,
    scopes_of: impl Fn(&str) -> Result<Vec<String>, String>,
) -> Result<(String, Capability), String> {
    // ★ The order is the rule (ledger #1825): an entry of its own FIRST, and only then the
    // grant it names or the default. Asking for a grant first let the default answer for a
    // certificate whose entry had been removed, so removing a client moved it to the default
    // grant instead of refusing it, and a bearer token bound to it kept working.
    if !enrolment.is_enrolled(fingerprint) {
        return Err(
            "this certificate is not enrolled: the `clients` map has no entry for it (a \
             `default` grant serves only enrolled entries that name no grant)"
                .to_string(),
        );
    }
    let Some(grant) = enrolment.grant_for(fingerprint) else {
        return Err("no grant is configured for this certificate".to_string());
    };
    let scopes = scopes_of(grant)?;
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
    fn grants(name: &str) -> Result<Vec<String>, String> {
        Ok(match name {
            "contacts-ro" => vec!["urn:cap:personal:contacts:read".to_string()],
            "everything" => vec![
                "urn:cap:personal:contacts:read".to_string(),
                "urn:cap:personal:calendar:read:detail".to_string(),
            ],
            // A grant NAMED in clients.json but absent from grants.json.
            _ => vec![],
        })
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

    /// A libp2p PeerId enrols in the SAME map as a certificate fingerprint and names a grant
    /// the same way — one table for one concept. It is base58 and case-sensitive, so it must
    /// NOT fold the way a fingerprint folds: before this, `normalize` lowercased every key,
    /// and a PeerId entry became a key no connection could ever present.
    #[test]
    fn a_peer_id_enrols_beside_a_fingerprint_and_keeps_its_case() {
        let peer = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        let e = parse(&format!(
            r#"{{"clients": {{"{FP}": "everything", "{peer}": {{"grant": "contacts-ro", "label": "plasma over p2p"}}}}}}"#
        ))
        .unwrap();
        assert_eq!(e.grant_for(peer), Some("contacts-ro"));
        assert_eq!(e.grant_for(FP), Some("everything"));
        // One character's case is a DIFFERENT key — never a fuzzy match onto a grant.
        assert_eq!(e.grant_for(&peer.to_lowercase()), None);
        let (grant, capability) = authority_in(&e, peer, &Capability::root(), grants).unwrap();
        assert_eq!(grant, "contacts-ro");
        assert!(!capability.allows("urn:cap:personal:calendar:read:detail"));
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
            refused.contains("not enrolled"),
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

    /// A default must be written, never implied, and it serves ENROLLED entries that name no
    /// grant, never a stranger (ledger #1825). Until then the stranger got the default.
    #[test]
    fn a_default_serves_an_enrolled_entry_that_names_no_grant_and_never_a_stranger() {
        let stranger = "0000000000000000000000000000000000000000000000000000000000000000";
        let spare = "a".repeat(64);
        let with = parse(&format!(
            r#"{{"clients": {{"{FP}": "everything", "{spare}": {{"label": "spare"}}}}, "default": "contacts-ro"}}"#
        ))
        .unwrap();
        let (grant, capability) = authority_in(&with, &spare, &Capability::root(), grants).unwrap();
        assert_eq!(grant, "contacts-ro");
        assert!(capability.allows("urn:cap:personal:contacts:read"));
        // An entry's own grant still wins over the default.
        assert_eq!(with.grant_for(FP), Some("everything"));
        // A stranger is refused, default or not.
        assert_eq!(with.grant_for(stranger), None);
        let refused = authority_in(&with, stranger, &Capability::root(), grants).unwrap_err();
        assert!(refused.contains("not enrolled"), "{refused}");

        let without = parse(&format!(r#"{{"clients": {{"{FP}": "everything"}}}}"#)).unwrap();
        assert!(authority_in(&without, stranger, &Capability::root(), grants).is_err());
    }

    /// The case ledger #1825 names: an entry removed from a file that sets a `default`. The
    /// removed client is REFUSED, not moved to the default grant.
    #[test]
    fn removing_an_entry_refuses_it_even_under_a_default() {
        let before = parse(&format!(
            r#"{{"clients": {{"{FP}": "everything"}}, "default": "contacts-ro"}}"#
        ))
        .unwrap();
        assert!(authority_in(&before, FP, &Capability::root(), grants).is_ok());
        let after = parse(r#"{"clients": {}, "default": "contacts-ro"}"#).unwrap();
        let refused = authority_in(&after, FP, &Capability::root(), grants).unwrap_err();
        assert!(refused.contains("not enrolled"), "{refused}");
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
        // An entry with no grant is unusable when there is no default to serve it under...
        let bare = parse(&format!(r#"{{"clients": {{"{FP}": {{"label": "x"}}}}}}"#)).unwrap_err();
        assert!(bare.contains("no `default`"), "{bare}");
        // ...and legal beside one.
        assert!(parse(&format!(
            r#"{{"clients": {{"{FP}": {{"label": "x"}}}}, "default": "contacts-ro"}}"#
        ))
        .is_ok());
        assert!(parse(&format!(r#"{{"clients": {{"{FP}": {{"grant": 7}}}}}}"#)).is_err());
        assert!(parse(r#"{"default": 7}"#).is_err());
        // Legal: no `clients` key at all — the file with everyone removed.
        assert!(parse("{}").unwrap().is_empty());
    }

    /// An entry may name the principal its client is minted as; a bare-string entry and an
    /// object without one name none, so the door falls back to [`default_principal`] (ledger
    /// #1179). A stranger has no grant at all, default or not (ledger #1825).
    #[test]
    fn an_entry_may_name_its_principal_and_the_default_names_nobody() {
        let alice = "a".repeat(64);
        let stranger = "0".repeat(64);
        let e = parse(&format!(
            r#"{{"clients": {{
                "{FP}": {{"grant": "everything", "principal": "urn:collab:participant:bobby"}},
                "{alice}": {{"grant": "contacts-ro", "label": "alice"}}
            }}, "default": "contacts-ro"}}"#
        ))
        .unwrap();
        assert_eq!(e.principal_for(FP), Some("urn:collab:participant:bobby"));
        // The key folds the same way for the principal as for the grant.
        assert_eq!(
            e.principal_for(&FP.to_uppercase()),
            Some("urn:collab:participant:bobby")
        );
        assert_eq!(e.principal_for(&alice), None);
        assert_eq!(
            e.grant_for(&stranger),
            None,
            "the default serves no stranger"
        );
        assert_eq!(e.principal_for(&stranger), None, "the default names nobody");
    }

    /// A principal core could not carry is refused with the file, never minted as nothing.
    #[test]
    fn an_unusable_principal_is_an_error() {
        for bad in [r#""not an iri""#, r#""urn:x:*""#, "7"] {
            let text = format!(
                r#"{{"clients": {{"{FP}": {{"grant": "everything", "principal": {bad}}}}}}}"#
            );
            let refused = parse(&text).unwrap_err();
            assert!(refused.contains("principal"), "{bad}: {refused}");
        }
    }

    /// The default form is exact: the host's name and the folded fingerprint, nothing else.
    #[test]
    fn the_default_principal_is_exact() {
        assert_eq!(
            default_principal("serve", FP),
            format!("urn:iki:host:serve:client:{FP}")
        );
        let openssl = FP
            .to_uppercase()
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(
            default_principal("serve", &openssl),
            default_principal("serve", FP)
        );
        // And core can carry it as a principal.
        assert!(ikigai_core::principal_scope(&default_principal("layers", FP)).is_ok());
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
