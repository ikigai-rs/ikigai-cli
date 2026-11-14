//! Contact intake rows from the config home's `intakes.json`, fixed for a host's lifetime.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

use ikigai_core::{EndpointSpace, Exact};
use ikigai_intake::{BlocklistKey, IntakeConfig, IntakeField};
use serde::Deserialize;

static CONFIGS: OnceLock<Result<Vec<IntakeConfig>, String>> = OnceLock::new();

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    id: String,
    space: String,
    fields: Vec<Field>,
    #[serde(default)]
    fixed_fields: BTreeMap<String, String>,
    #[serde(default)]
    redirect: Option<String>,
    #[serde(default)]
    blocklist: Option<String>,
    /// A file holding the blocklist key, relative to the config home unless absolute.
    #[serde(default)]
    blocklist_key: Option<String>,
    #[serde(default)]
    email_field: Option<String>,
    #[serde(default)]
    honeypot: Option<String>,
    #[serde(default = "submit_cap")]
    requires: String,
}

fn submit_cap() -> String {
    "urn:cap:contact:submit".into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Field {
    name: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    one_of: Vec<String>,
    #[serde(default)]
    iana_zone: bool,
    #[serde(default = "max_len")]
    max_len: usize,
}

fn max_len() -> usize {
    ikigai_intake::DEFAULT_MAX_LEN
}

/// Read a row's blocklist key file. The error names the file, never its contents.
fn read_key(home: &Path, file: &str) -> Result<BlocklistKey, String> {
    let path = home.join(file);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read blocklist_key {}: {e}", path.display()))?;
    BlocklistKey::from_hex(&text).map_err(|e| format!("blocklist_key {}: {e}", path.display()))
}

fn parse(text: &str, home: &Path) -> Result<Vec<IntakeConfig>, String> {
    // Decode rows separately so even a schema error names the row's id when available.
    let rows: Vec<serde_json::Value> = serde_json::from_str(text)
        .map_err(|e| format!("the intake list is not a JSON array: {e}"))?;
    if rows.is_empty() {
        return Err("the intake list must have a first row for urn:contact:submit".into());
    }
    let mut ids = BTreeSet::new();
    rows.into_iter().enumerate().map(|(index, value)| {
        let name = value.get("id").and_then(|id| id.as_str()).unwrap_or("unnamed");
        let at = format!("intake row {} (`{}`)", index + 1, name.escape_debug());
        let row: Row = serde_json::from_value(value).map_err(|e| format!("{at} cannot be read: {e}"))?;
        if !ikigai_intake::field_name(&row.id) || !ids.insert(row.id.clone()) {
            return Err(format!("{at} needs a unique id made of letters, digits, underscores or hyphens, starting with a letter or underscore"));
        }
        let blocklist_key = row
            .blocklist_key
            .map(|file| read_key(home, &file))
            .transpose()
            .map_err(|e| format!("{at} is refused: {e}"))?;
        let config = IntakeConfig {
            id: row.id,
            space: row.space,
            fields: row.fields.into_iter().map(|field| {
                let summary = field.summary.unwrap_or_else(|| field.name.clone());
                let mut accepted = if field.required {
                    IntakeField::required(field.name, summary)
                } else {
                    IntakeField::optional(field.name, summary)
                };
                accepted.one_of = field.one_of;
                accepted.iana_zone = field.iana_zone;
                accepted.max_len = field.max_len;
                accepted
            }).collect(),
            fixed_fields: row.fixed_fields,
            blocklist: row.blocklist,
            blocklist_key,
            email_field: row.email_field,
            honeypot: row.honeypot,
            requires: row.requires,
            redirect: row.redirect,
            clients: None,
            attests: Vec::new(),
            check_blocked: false,
        };
        ikigai_intake::try_submit(config.clone()).map_err(|e| format!("{at} is refused: {e}"))?;
        Ok(config)
    }).collect()
}

fn compatibility_intake() -> Result<Vec<IntakeConfig>, String> {
    let config = crate::contact_intake();
    ikigai_intake::try_submit(config.clone()).map_err(|e| e.to_string())?;
    Ok(vec![config])
}

fn read() -> Result<Vec<IntakeConfig>, String> {
    let Some(home) = crate::config::config_home() else {
        return compatibility_intake();
    };
    let path = home.join("intakes.json");
    match std::fs::read_to_string(&path) {
        Ok(text) => parse(&text, &home).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => compatibility_intake(),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

fn configs() -> Result<&'static [IntakeConfig], String> {
    CONFIGS.get_or_init(read).as_deref().map_err(Clone::clone)
}

pub(crate) fn check() -> Result<(), String> {
    configs().map(|_| ())
}

fn bind_configs(mut space: EndpointSpace, configs: &[IntakeConfig]) -> EndpointSpace {
    for (index, config) in configs.iter().enumerate() {
        // Both doors share one endpoint identity, so arrangement dumps can be reloaded.
        let endpoint: std::sync::Arc<dyn ikigai_core::Endpoint> =
            std::sync::Arc::new(ikigai_intake::submit(config.clone()));
        if index == 0 {
            space = space.bind_arc(Exact::new("urn:contact:submit"), endpoint.clone());
        }
        space = space.bind_arc(
            Exact::new(format!("urn:intake:id:{}:submit", config.id)),
            endpoint,
        );
    }
    space
}

pub(crate) fn bind(space: EndpointSpace) -> EndpointSpace {
    // The CLI checks before constructing a kernel; library constructors have no Result
    // channel and follow the host's existing fail-fast configuration convention.
    bind_configs(space, configs().unwrap_or_else(|e| panic!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{
        ArgRef, Capability, Endpoint, FnEndpoint, Iri, Kernel, ReprType, Representation, Request,
        Verb,
    };
    use std::sync::{Arc, Mutex};

    const TWO: &str = r#"[
      {"id":"alpha","space":"urn:space:alpha","fields":[{"name":"message","required":true}],"fixed_fields":{"site":"alpha"}},
      {"id":"beta","space":"urn:space:beta","fields":[{"name":"message","required":true}],"fixed_fields":{"site":"beta"}}
    ]"#;

    fn post(endpoint: &str, body: &str) -> Request {
        Request::new(Verb::Sink, Iri::parse(endpoint).unwrap())
            .with_arg("content", ArgRef::Inline(body.as_bytes().to_vec()))
    }

    #[test]
    fn two_intakes_write_their_own_fixed_fields_and_the_alias_uses_the_first() {
        let configs = parse(TWO, Path::new("/nonexistent")).unwrap();
        let dropped = Arc::new(Mutex::new(Vec::new()));
        let mut space = bind_configs(EndpointSpace::new(), &configs);
        for config in &configs {
            let seen = dropped.clone();
            let target = config.space.clone();
            space = space.bind(
                Exact::new(&config.space),
                FnEndpoint::new("record", move |inv| {
                    seen.lock()
                        .unwrap()
                        .push((target.clone(), inv.inline_str("content")?.to_string()));
                    Ok(Representation::new(
                        ReprType::new("text/plain"),
                        b"ok".to_vec(),
                    ))
                }),
            );
        }
        let kernel = Kernel::new(Arc::new(space));
        for (endpoint, body) in [
            (
                "urn:intake:id:alpha:submit",
                "message=hello&site=forged&undeclared=evil",
            ),
            (
                "urn:intake:id:beta:submit",
                r#"{"message":"hello","site":"forged","undeclared":"evil"}"#,
            ),
            ("urn:contact:submit", "message=hello&site=forged"),
        ] {
            block_on(kernel.issue(post(endpoint, body), &Capability::root())).unwrap();
        }
        assert_eq!(
            *dropped.lock().unwrap(),
            [
                (
                    "urn:space:alpha".into(),
                    r#"((message "hello") (site "alpha"))"#.into()
                ),
                (
                    "urn:space:beta".into(),
                    r#"((message "hello") (site "beta"))"#.into()
                ),
                (
                    "urn:space:alpha".into(),
                    r#"((message "hello") (site "alpha"))"#.into()
                ),
            ]
        );
        assert!(block_on(kernel.issue(
            post("urn:intake:id:alpha:submit", "site=forged"),
            &Capability::root()
        ))
        .is_err());
        assert_eq!(
            dropped.lock().unwrap().len(),
            3,
            "validation precedes writing fixed values"
        );
    }

    #[test]
    fn a_fixed_field_is_not_an_input_even_if_also_declared() {
        let configs = parse(r#"[{"id":"a","space":"urn:space:a","fields":[{"name":"site","required":true}],"fixed_fields":{"site":"trusted"},"honeypot":"site"}]"#, Path::new("/nonexistent")).unwrap();
        let endpoint = ikigai_intake::try_submit(configs[0].clone()).unwrap();
        let action = endpoint.describe().action_specs().remove(0);
        assert!(!action.inputs.iter().any(|field| field.name == "site"));
        let seen = Arc::new(Mutex::new(String::new()));
        let recorded = seen.clone();
        let space = bind_configs(EndpointSpace::new(), &configs).bind(
            Exact::new("urn:space:a"),
            FnEndpoint::new("record", move |inv| {
                *recorded.lock().unwrap() = inv.inline_str("content")?.to_string();
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"ok".to_vec(),
                ))
            }),
        );
        let kernel = Kernel::new(Arc::new(space));
        for body in ["", "site=forged"] {
            seen.lock().unwrap().clear();
            block_on(kernel.issue(post("urn:intake:id:a:submit", body), &Capability::root()))
                .unwrap();
            assert_eq!(*seen.lock().unwrap(), r#"((site "trusted"))"#);
        }
    }

    /// A config home holding `blocklist.key`, removed when dropped.
    struct Home(std::path::PathBuf);
    impl Home {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("iki-intakes-{name}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("blocklist.key"), format!("{}\n", "07".repeat(32))).unwrap();
            std::fs::write(dir.join("bad.key"), "not a key\n").unwrap();
            Home(dir)
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_configured_blocklist_is_asked_exists_on_a_keyed_sender_hash() {
        let home = Home::new("keyed");
        let configs = parse(r#"[{"id":"a","space":"urn:space:a","fields":[{"name":"email","required":true}],"email_field":"email","blocklist":"urn:custom:blocklist:{key}","blocklist_key":"blocklist.key"}]"#, &home.0).unwrap();
        let [blocked, _] = BlocklistKey::new([7; 32])
            .sender_keys("blocked@example.org")
            .unwrap();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let seen = asked.clone();
        let space = bind_configs(EndpointSpace::new(), &configs).bind(
            ikigai_core::UriTemplate::parse("urn:custom:blocklist:{key}").unwrap(),
            FnEndpoint::new("block", move |inv| {
                assert_eq!(inv.request.verb, Verb::Exists);
                assert!(inv.request.args.is_empty());
                seen.lock()
                    .unwrap()
                    .push(inv.request.target.as_str().to_string());
                Ok(Representation::new(ReprType::new("text/plain"), Vec::new()))
            }),
        );
        // No destination exists: a write would fail, while a blocked submission is accepted-looking.
        let kernel = Kernel::new(Arc::new(space));
        let response = block_on(kernel.issue(
            post("urn:intake:id:a:submit", "email=Blocked%40example.org"),
            &Capability::root(),
        ))
        .unwrap();
        assert_eq!(response.bytes, b"received\n");
        assert_eq!(
            *asked.lock().unwrap(),
            [format!("urn:custom:blocklist:{blocked}")]
        );
    }

    #[test]
    fn bad_rows_are_refused_by_name() {
        let dir = Home::new("bad");
        let home = dir.0.as_path();
        for row in [
            r#"{"id":"broken","space":"urn:space:a","fields":[],"redirect":"javascript:alert(1)"}"#,
            r#"{"id":"broken","space":"not an iri","fields":[]}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[],"blocklist":"not an iri {key}"}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[],"fixed_fields":{"a) (evil":"x"}}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[],"fixed_fields":{"received":"x"}}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[{"name":"message","max_len":0}]}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[{"name":"message"},{"name":"message"}]}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[],"unexpected":true}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[{"name":"message","requird":true}]}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[],"email_field":"missing"}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[{"name":"email"}],"email_field":"email","blocklist":"urn:decisions","blocklist_key":"blocklist.key"}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[{"name":"email"}],"email_field":"email","blocklist":"urn:b:{key}"}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[{"name":"email"}],"email_field":"email","blocklist":"urn:b:{key}","blocklist_key":"missing.key"}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[{"name":"email"}],"email_field":"email","blocklist":"urn:b:{key}","blocklist_key":"bad.key"}"#,
        ] {
            let error = parse(&format!("[{row}]"), home).unwrap_err();
            assert!(error.contains("intake row 1 (`broken`)"), "{error}");
            assert!(
                !error.contains("not a key"),
                "a key file's contents are never repeated: {error}"
            );
        }
        assert!(parse("[]", home).unwrap_err().contains("first row"));
        let duplicate = TWO.replace("\"beta\"", "\"alpha\"");
        assert!(parse(&duplicate, home)
            .unwrap_err()
            .contains("intake row 2 (`alpha`)"));
        assert!(parse("{", home).is_err());
    }
}
