//! Bearer tokens for the layer host's HTTPS front: a token is bound to ONE enrolled participant.
//!
//! A participant that speaks only HTTP (no QUIC, no client certificate it can present) takes
//! part in layers through the front `serve quic://… --layers-https <addr>` opens beside the
//! QUIC door. It authenticates with `Authorization: Bearer <token>`, and the token names
//! nothing by itself: it is bound to one ENROLLED client, the `clients.json` key (a
//! certificate fingerprint) the participant is enrolled under, and the front mints that
//! client's authority exactly as the QUIC door mints it for the certificate. Same grant, same
//! principal, same ceiling; a token is a second way to present an enrollment, never a second
//! authority.
//!
//! The binding lives in `layer-tokens.json`, beside `clients.json` in the config home:
//!
//! ```json
//! {
//!   "tokens": {
//!     "<lowercase hex SHA-256 of the token>": {
//!       "client": "<the clients.json key it is bound to>",
//!       "label": "relay host",
//!       "created": "2026-10-12T20:00:00Z",
//!       "expires": "2027-01-10T20:00:00Z",
//!       "require_cert": true
//!     }
//!   }
//! }
//! ```
//!
//! Three properties are load-bearing, and each is the same as `clients.json`'s:
//!
//! - **Stored hashed.** The file holds SHA-256 of each token, never the token: reading the
//!   file does not let anyone present one. The token is printed once, when it is minted.
//! - **Live.** The front reads the file on EVERY request, so removing an entry (or
//!   `ikigai layers-token revoke`) refuses the token's next request; removing the client's
//!   `clients.json` entry refuses it too, because the front mints through the same
//!   enrollment the QUIC door reads.
//! - **Fail closed.** A file that exists and does not parse refuses every token; an absent
//!   file is no tokens at all.
//!
//! Since ledger #4544 a token also has a **lifetime** and follows its **certificate**:
//!
//! - `expires` is when it stops working (`layers-token mint --lifetime`, default
//!   [`DEFAULT_LIFETIME_DAYS`] days, at most [`MAX_LIFETIME_DAYS`]). An entry with no
//!   `expires` was written by an older release: [`upgrade_file`] gives it one when the new
//!   release first starts, and the front refuses one it meets without.
//! - The front refuses a token whose bound certificate is no longer in the door's trust list,
//!   or is outside its validity window, as the QUIC door would refuse the certificate.
//! - A request that presents a client certificate must present the bound one; with
//!   `require_cert` (`mint --require-cert`) a request that presents none is refused.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The token file's name, in the config home beside `clients.json`.
pub const FILE: &str = "layer-tokens.json";

/// Every token starts with this, so one pasted into a log or a chat is recognizable for
/// what it is, and so a secret scanner can find it.
pub const PREFIX: &str = "iklt_";

/// `<config home>/layer-tokens.json`.
pub fn tokens_path() -> Option<PathBuf> {
    crate::config::config_home().map(|dir| dir.join(FILE))
}

/// One token's binding, as the file holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The token's id: the first 12 hex digits of its hash, what `list` shows and `revoke`
    /// takes. Not a secret: it cannot be presented.
    pub id: String,
    /// The `clients.json` key the token is bound to.
    pub client: String,
    /// For humans reading the file and the front's log.
    pub label: String,
    /// When it was minted (RFC 3339, UTC).
    pub created: String,
    /// When it stops working (RFC 3339, UTC). `None` only for an entry an older release
    /// wrote, which [`upgrade_file`] gives one and the front refuses until it has one.
    pub expires: Option<String>,
    /// Refuse a request that presents no client certificate (`mint --require-cert`).
    pub require_cert: bool,
}

/// A token's lifetime when `mint` is given none.
pub const DEFAULT_LIFETIME_DAYS: i64 = 90;

/// The longest lifetime `mint` grants.
pub const MAX_LIFETIME_DAYS: i64 = 365;

/// A lifetime as `mint --lifetime` takes it: a whole number of days (`90d`) or hours
/// (`12h`), more than zero and at most [`MAX_LIFETIME_DAYS`] days.
///
/// ```
/// use ikigai_embedded::tokens::parse_lifetime;
///
/// assert_eq!(parse_lifetime("90d").unwrap(), chrono::Duration::days(90));
/// assert_eq!(parse_lifetime("12h").unwrap(), chrono::Duration::hours(12));
/// assert!(parse_lifetime("0d").is_err());
/// assert!(parse_lifetime("366d").is_err());
/// assert!(parse_lifetime("soon").is_err());
/// ```
pub fn parse_lifetime(text: &str) -> Result<chrono::Duration, String> {
    let text = text.trim();
    let bad = || {
        format!(
            "`{text}` is not a lifetime: give a whole number of days or hours, such as `90d` or \
             `12h`, at most {MAX_LIFETIME_DAYS}d"
        )
    };
    let (number, unit) = text.split_at(text.len().saturating_sub(1));
    let n: i64 = number.parse().map_err(|_| bad())?;
    let lifetime = match unit {
        "d" => chrono::Duration::try_days(n),
        "h" => chrono::Duration::try_hours(n),
        _ => None,
    }
    .ok_or_else(bad)?;
    if lifetime <= chrono::Duration::zero() {
        return Err(bad());
    }
    if lifetime > chrono::Duration::days(MAX_LIFETIME_DAYS) {
        return Err(format!(
            "a token lives at most {MAX_LIFETIME_DAYS} days; `{text}` is longer: mint a new \
             token when this one expires instead"
        ));
    }
    Ok(lifetime)
}

/// [`DEFAULT_LIFETIME_DAYS`] as a duration: what `mint` grants when given no `--lifetime`.
pub fn default_lifetime() -> chrono::Duration {
    chrono::Duration::days(DEFAULT_LIFETIME_DAYS)
}

/// Now, in UTC: when a mint or an upgrade happens.
pub fn now_utc() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

/// Now, as seconds since the Unix epoch: the clock the front checks expiries by.
pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// `at`, as RFC 3339 UTC to the second.
pub fn rfc3339(at: chrono::DateTime<chrono::Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

impl Binding {
    /// Whether the token may still be presented at `now` (seconds since the Unix epoch).
    /// `Err` is the sentence the front answers with: when it expired and how to get a new one.
    pub fn check_expiry(&self, now: i64) -> Result<(), String> {
        let Some(expires) = &self.expires else {
            return Err(format!(
                "token {} has no expiry: an older release wrote it. Restart the layer door so \
                 it gives every token an expiry, or ask the operator to mint a new token \
                 (`ikigai layers-token mint`)",
                self.id
            ));
        };
        let at = chrono::DateTime::parse_from_rfc3339(expires)
            .map_err(|_| format!("token {} has an unreadable expiry `{expires}`", self.id))?;
        if now >= at.timestamp() {
            return Err(format!(
                "token {} expired at {expires}. Ask the operator to mint a new one with \
                 `ikigai layers-token mint`",
                self.id
            ));
        }
        Ok(())
    }
}

/// The parsed token file: token hash → binding.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tokens {
    by_hash: BTreeMap<String, Binding>,
}

/// How many hex digits of the hash name a token in `list` and `revoke`.
const ID_LEN: usize = 12;

/// Lowercase hex SHA-256 of `token`: what the file keys a token by.
///
/// ```
/// use ikigai_embedded::tokens::hash;
///
/// // SHA-256 of "abc" (FIPS 180-2's first example), as lowercase hex.
/// assert_eq!(hash("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
/// assert_ne!(hash("iklt_example"), hash("iklt_Example"));
/// ```
pub fn hash(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Now, as RFC 3339 UTC to the second: what a binding's `created` holds.
pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A fresh token: [`PREFIX`] and 32 random bytes as 64 lowercase hex digits.
pub fn generate() -> Result<String, String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|e| format!("no randomness for a token: {e}"))?;
    Ok(format!(
        "{PREFIX}{}",
        raw.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

impl Tokens {
    /// The binding a presented token resolves to, if the file holds its hash.
    pub fn binding_for(&self, token: &str) -> Option<&Binding> {
        self.by_hash.get(&hash(token.trim()))
    }

    /// Every binding, ordered by id.
    pub fn bindings(&self) -> Vec<&Binding> {
        let mut all: Vec<&Binding> = self.by_hash.values().collect();
        all.sort_by(|a, b| a.id.cmp(&b.id));
        all
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// Bind `token` to `client`. Refuses a token already in the file (a collision of 32
    /// random bytes is not going to happen, but a re-run of a scripted mint should not
    /// silently rebind one).
    pub fn insert(
        &mut self,
        token: &str,
        client: &str,
        label: &str,
        created: &str,
        expires: &str,
        require_cert: bool,
    ) -> Result<Binding, String> {
        let key = hash(token);
        if self.by_hash.contains_key(&key) {
            return Err("that token is already bound".to_string());
        }
        let binding = Binding {
            id: key[..ID_LEN].to_string(),
            client: client.to_string(),
            label: label.to_string(),
            created: created.to_string(),
            expires: Some(expires.to_string()),
            require_cert,
        };
        self.by_hash.insert(key, binding.clone());
        Ok(binding)
    }

    /// Remove the token whose id is `id` (or starts with it, at least 8 hex digits, when that
    /// names exactly one). Returns what was removed.
    pub fn revoke(&mut self, id: &str) -> Result<Binding, String> {
        let id = id.trim().to_ascii_lowercase();
        if id.len() < 8 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "`{id}` is not a token id (at least 8 hex digits, as `list` prints them)"
            ));
        }
        let matching: Vec<String> = self
            .by_hash
            .keys()
            .filter(|key| key.starts_with(&id))
            .cloned()
            .collect();
        match matching.as_slice() {
            [one] => Ok(self.by_hash.remove(one).expect("a key just read")),
            [] => Err(format!("no token has the id `{id}`")),
            _ => Err(format!(
                "`{id}` names {} tokens: give more of the id",
                matching.len()
            )),
        }
    }

    /// The file's JSON, pretty-printed and ending in a newline.
    pub fn to_json(&self) -> String {
        let tokens: serde_json::Map<String, serde_json::Value> = self
            .by_hash
            .iter()
            .map(|(key, b)| {
                let mut entry = serde_json::json!({
                    "client": b.client,
                    "label": b.label,
                    "created": b.created,
                });
                if let Some(expires) = &b.expires {
                    entry["expires"] = expires.clone().into();
                }
                if b.require_cert {
                    entry["require_cert"] = true.into();
                }
                (key.clone(), entry)
            })
            .collect();
        let mut text = serde_json::to_string_pretty(&serde_json::json!({ "tokens": tokens }))
            .expect("a JSON object serializes");
        text.push('\n');
        text
    }
}

/// Parse the token file's text. Every unusable entry is an ERROR, never skipped: a binding
/// silently dropped would refuse a participant for a reason nobody can see, and one silently
/// kept with a wrong shape could bind it to something its operator never wrote.
pub fn parse(text: &str) -> Result<Tokens, String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let mut by_hash = BTreeMap::new();
    if let Some(map) = v.get("tokens") {
        let map = map
            .as_object()
            .ok_or("`tokens` must be an object of token hash → binding")?;
        for (key, entry) in map {
            let key = key.to_ascii_lowercase();
            if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "`{key}` is not a token hash (64 hex digits): the file holds hashes, never \
                     tokens"
                ));
            }
            let field = |name: &str| entry.get(name).and_then(|v| v.as_str());
            let client = field("client")
                .filter(|c| !c.trim().is_empty())
                .ok_or_else(|| format!("token `{}` names no `client`", &key[..ID_LEN]))?;
            let expires = match entry.get("expires") {
                None => None,
                Some(v) => {
                    let text = v
                        .as_str()
                        .filter(|t| chrono::DateTime::parse_from_rfc3339(t).is_ok())
                        .ok_or_else(|| {
                            format!(
                                "token `{}` has an `expires` that is not an RFC 3339 time",
                                &key[..ID_LEN]
                            )
                        })?;
                    Some(text.to_string())
                }
            };
            let require_cert = match entry.get("require_cert") {
                None => false,
                Some(v) => v.as_bool().ok_or_else(|| {
                    format!(
                        "token `{}` has a `require_cert` that is not true or false",
                        &key[..ID_LEN]
                    )
                })?,
            };
            by_hash.insert(
                key.clone(),
                Binding {
                    id: key[..ID_LEN].to_string(),
                    client: client.trim().to_string(),
                    label: field("label").unwrap_or_default().to_string(),
                    created: field("created").unwrap_or_default().to_string(),
                    expires,
                    require_cert,
                },
            );
        }
    }
    Ok(Tokens { by_hash })
}

/// Read the token file at `path`. Absent is no tokens; present and unusable is an error.
pub fn load_from(path: &Path) -> Result<Tokens, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Tokens::default()),
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

/// Write `tokens` to `path`, owner read-write only, replacing the file whole (written beside
/// it and renamed, so a reader never sees half a file).
pub fn save_to(path: &Path, tokens: &Tokens) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    let partial = path.with_extension("json.partial");
    std::fs::write(&partial, tokens.to_json())
        .map_err(|e| format!("write {}: {e}", partial.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("restrict {}: {e}", partial.display()))?;
    }
    std::fs::rename(&partial, path).map_err(|e| format!("replace {}: {e}", path.display()))
}

/// Give every entry an older release wrote (one with no `expires`) an expiry
/// [`DEFAULT_LIFETIME_DAYS`] days from `now`, the new release's first start. Returns how many
/// got one; zero leaves the file untouched, so running it again changes nothing.
///
/// Before rewriting, the file as it was is copied to `<file>.bak-<now>` beside it, and the
/// rewrite is [`save_to`]'s (written beside and renamed), so a reader sees the old file or the
/// new one, never half of either. An absent file is zero entries.
pub fn upgrade_file(path: &Path, now: chrono::DateTime<chrono::Utc>) -> Result<usize, String> {
    let mut tokens = load_from(path)?;
    let expires = rfc3339(now + chrono::Duration::days(DEFAULT_LIFETIME_DAYS));
    let mut upgraded = 0;
    for binding in tokens.by_hash.values_mut() {
        if binding.expires.is_none() {
            binding.expires = Some(expires.clone());
            upgraded += 1;
        }
    }
    if upgraded == 0 {
        return Ok(0);
    }
    let backup = backup_path(path, now);
    std::fs::copy(path, &backup).map_err(|e| {
        format!(
            "back up {} to {} before giving its tokens an expiry: {e}",
            path.display(),
            backup.display()
        )
    })?;
    save_to(path, &tokens)?;
    Ok(upgraded)
}

/// Where [`upgrade_file`] keeps the file as it was: `<file>.bak-<now, compact UTC>`.
pub fn backup_path(path: &Path, now: chrono::DateTime<chrono::Utc>) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".bak-{}", now.format("%Y%m%dT%H%M%SZ")));
    path.with_file_name(name)
}

/// The `clients.json` key a mint binds to, from what the operator typed: a key the
/// enrollment holds (a fingerprint, colons and case as `openssl` prints them accepted), or a
/// participant's IRI that exactly ONE enrolled entry names as its `principal`.
pub fn resolve_client(
    enrolment: &crate::clients::Enrolment,
    named: &str,
) -> Result<String, String> {
    if let Some(key) = enrolment.key_for(named) {
        return Ok(key);
    }
    let keys = enrolment.keys_with_principal(named.trim());
    match keys.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(format!(
            "`{named}` is neither an enrolled fingerprint nor the principal of one: enroll the \
             participant first (`ikigai-layers grants` writes clients.json from enrollment.toml)"
        )),
        _ => Err(format!(
            "`{named}` is the principal of {} enrolled certificates: name the fingerprint the \
             token should present",
            keys.len()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "6f1c00000000000000000000000000000000000000000000000000000000abcd";

    #[test]
    fn a_token_is_stored_hashed_and_resolves_to_its_binding() {
        let token = generate().unwrap();
        assert!(token.starts_with(PREFIX) && token.len() == PREFIX.len() + 64);
        let mut tokens = Tokens::default();
        let bound = tokens
            .insert(
                &token,
                FP,
                "relay",
                "2026-10-12T00:00:00Z",
                "2027-01-10T00:00:00Z",
                false,
            )
            .unwrap();
        let text = tokens.to_json();
        assert!(!text.contains(&token), "the file never holds the token");
        assert!(text.contains(&hash(&token)));
        let read = parse(&text).unwrap();
        assert_eq!(read.binding_for(&token), Some(&bound));
        assert_eq!(read.binding_for(&generate().unwrap()), None);
        assert!(tokens
            .insert(&token, FP, "again", "x", "2027-01-10T00:00:00Z", false)
            .is_err());
    }

    #[test]
    fn revoking_by_id_removes_exactly_one() {
        let (a, b) = (generate().unwrap(), generate().unwrap());
        let mut tokens = Tokens::default();
        let first = tokens
            .insert(&a, FP, "a", "t", "2027-01-10T00:00:00Z", false)
            .unwrap();
        tokens
            .insert(&b, FP, "b", "t", "2027-01-10T00:00:00Z", true)
            .unwrap();
        assert!(tokens.revoke("abc").is_err(), "too short to be an id");
        assert!(tokens.revoke("not-hex!").is_err());
        assert_eq!(tokens.revoke(&first.id.to_uppercase()).unwrap(), first);
        assert_eq!(tokens.binding_for(&a), None);
        assert!(tokens.binding_for(&b).is_some());
        assert!(tokens.revoke(&first.id).is_err(), "already gone");
    }

    #[test]
    fn an_unusable_file_is_an_error_not_an_empty_one() {
        assert!(parse("{ not json").is_err());
        assert!(parse(r#"{"tokens": []}"#).is_err());
        assert!(
            parse(r#"{"tokens": {"iklt_raw": {"client": "x"}}}"#).is_err(),
            "a raw token in the file is refused: it holds hashes"
        );
        let key = "a".repeat(64);
        assert!(parse(&format!(r#"{{"tokens": {{"{key}": {{"label": "x"}}}}}}"#)).is_err());
        assert!(parse("{}").unwrap().is_empty());
    }

    #[test]
    fn a_mint_binds_by_fingerprint_or_by_a_unique_principal() {
        let other = "b".repeat(64);
        let twice = "c".repeat(64);
        let enrolment = crate::clients::parse(&format!(
            r#"{{"clients": {{
                "{FP}": {{"grant": "relay", "principal": "urn:collab:participant:relay"}},
                "{other}": {{"grant": "bob", "principal": "urn:collab:participant:bob"}},
                "{twice}": {{"grant": "bob", "principal": "urn:collab:participant:bob"}}
            }}}}"#
        ))
        .unwrap();
        assert_eq!(resolve_client(&enrolment, FP).unwrap(), FP);
        let openssl = FP
            .to_uppercase()
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(resolve_client(&enrolment, &openssl).unwrap(), FP);
        assert_eq!(
            resolve_client(&enrolment, "urn:collab:participant:relay").unwrap(),
            FP
        );
        let ambiguous = resolve_client(&enrolment, "urn:collab:participant:bob").unwrap_err();
        assert!(ambiguous.contains("2 enrolled"), "{ambiguous}");
        assert!(resolve_client(&enrolment, "urn:collab:participant:eve").is_err());
    }

    /// The token file as every release from cli v0.1.63 (where the front landed) through
    /// v0.6.2 wrote it: `tokens.rs` is byte-identical across those tags, so the two fixtures
    /// are the first and the last tag's shape. No entry carries `expires` or `require_cert`.
    const FIXTURES: [(&str, &str); 2] = [
        (
            "v0.1.63",
            include_str!("fixtures/layer-tokens-v0.1.63.json"),
        ),
        ("v0.6.2", include_str!("fixtures/layer-tokens-v0.6.2.json")),
    ];

    fn at(text: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("iki-tokens-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// What an older release does to the file when it mints or revokes: it rewrites every
    /// entry with `client`, `label` and `created` only (its `to_json`), dropping the rest.
    fn as_an_older_release_rewrites_it(text: &str) -> String {
        let mut v: serde_json::Value = serde_json::from_str(text).unwrap();
        for entry in v["tokens"].as_object_mut().unwrap().values_mut() {
            let e = entry.as_object_mut().unwrap();
            e.retain(|k, _| k == "client" || k == "label" || k == "created");
        }
        serde_json::to_string_pretty(&v).unwrap() + "\n"
    }

    #[test]
    fn a_token_expires_and_says_when_and_how_to_get_a_new_one() {
        let token = generate().unwrap();
        let mut tokens = Tokens::default();
        let b = tokens
            .insert(
                &token,
                FP,
                "relay",
                "2026-10-12T00:00:00Z",
                "2027-01-10T00:00:00Z",
                false,
            )
            .unwrap();
        assert!(b
            .check_expiry(at("2027-01-09T23:59:59Z").timestamp())
            .is_ok());
        let why = b
            .check_expiry(at("2027-01-10T00:00:00Z").timestamp())
            .unwrap_err();
        assert!(why.contains("expired at 2027-01-10T00:00:00Z"), "{why}");
        assert!(why.contains("ikigai layers-token mint"), "{why}");
        let legacy = Binding {
            expires: None,
            ..b.clone()
        };
        assert!(
            legacy
                .check_expiry(at("2026-10-13T00:00:00Z").timestamp())
                .is_err(),
            "no expiry, no entry"
        );
        let read = parse(&tokens.to_json()).unwrap();
        assert_eq!(
            read.binding_for(&token).unwrap().expires.as_deref(),
            Some("2027-01-10T00:00:00Z")
        );
        let key = "a".repeat(64);
        assert!(parse(&format!(
            r#"{{"tokens": {{"{key}": {{"client": "x", "expires": "soon"}}}}}}"#
        ))
        .is_err());
        assert!(parse(&format!(
            r#"{{"tokens": {{"{key}": {{"client": "x", "require_cert": "yes"}}}}}}"#
        ))
        .is_err());
    }

    #[test]
    fn upgrading_each_tags_file_gives_every_entry_an_expiry_once_with_a_backup() {
        for (tag, fixture) in FIXTURES {
            let dir = scratch(&format!("upgrade-{tag}"));
            let path = dir.join(FILE);
            std::fs::write(&path, fixture).unwrap();
            let first_start = at("2026-11-27T12:00:00Z");
            assert_eq!(upgrade_file(&path, first_start).unwrap(), 2, "{tag}");
            let backup = backup_path(&path, first_start);
            assert_eq!(
                std::fs::read_to_string(&backup).unwrap(),
                fixture,
                "{tag}: backup"
            );
            let upgraded = load_from(&path).unwrap();
            for b in upgraded.bindings() {
                assert_eq!(b.expires.as_deref(), Some("2027-02-25T12:00:00Z"), "{tag}");
                assert!(!b.require_cert);
                assert_eq!(b.client, FP);
            }
            assert!(
                !path.with_extension("json.partial").exists(),
                "{tag}: renamed into place"
            );
            // Idempotent: a second start finds nothing to do and touches nothing.
            let text = std::fs::read_to_string(&path).unwrap();
            assert_eq!(
                upgrade_file(&path, at("2026-12-01T00:00:00Z")).unwrap(),
                0,
                "{tag}"
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), text, "{tag}");
            assert!(
                !backup_path(&path, at("2026-12-01T00:00:00Z")).exists(),
                "{tag}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
        assert_eq!(
            upgrade_file(
                &std::env::temp_dir().join("iki-no-such-dir/x.json"),
                at("2026-11-27T12:00:00Z")
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn a_downgrade_then_a_re_upgrade_leaves_every_entry_with_an_expiry() {
        let dir = scratch("downgrade");
        let path = dir.join(FILE);
        std::fs::write(&path, FIXTURES[0].1).unwrap();
        assert_eq!(upgrade_file(&path, at("2026-11-27T12:00:00Z")).unwrap(), 2);
        let upgraded = std::fs::read_to_string(&path).unwrap();
        // An older release READS the upgraded file: its parser takes client, label and created
        // and ignores the rest, so every token still resolves to the same client under it.
        let old_view: serde_json::Value = serde_json::from_str(&upgraded).unwrap();
        for entry in old_view["tokens"].as_object().unwrap().values() {
            assert_eq!(entry["client"], FP);
        }
        // An older release that mints or revokes rewrites the file without the expiries; the
        // next start of this release gives them one again, counted from that start.
        std::fs::write(&path, as_an_older_release_rewrites_it(&upgraded)).unwrap();
        assert!(load_from(&path)
            .unwrap()
            .bindings()
            .iter()
            .all(|b| b.expires.is_none()));
        let restart = at("2026-12-10T00:00:00Z");
        assert_eq!(upgrade_file(&path, restart).unwrap(), 2);
        for b in load_from(&path).unwrap().bindings() {
            assert_eq!(b.expires.as_deref(), Some("2027-03-10T00:00:00Z"));
        }
        assert!(backup_path(&path, restart).exists());
        assert_eq!(upgrade_file(&path, restart).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_then_load_round_trips_owner_only() {
        let dir = std::env::temp_dir().join(format!("iki-tokens-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join(FILE);
        assert!(load_from(&path).unwrap().is_empty(), "absent is no tokens");
        let mut tokens = Tokens::default();
        tokens
            .insert(
                &generate().unwrap(),
                FP,
                "relay",
                "t",
                "2027-01-10T00:00:00Z",
                true,
            )
            .unwrap();
        save_to(&path, &tokens).unwrap();
        assert_eq!(load_from(&path).unwrap(), tokens);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
