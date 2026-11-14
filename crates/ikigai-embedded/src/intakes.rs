//! Contact intake rows from the config home's `intakes.json`, fixed for a host's lifetime.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use ikigai_core::{EndpointSpace, Exact};
use ikigai_intake::{IntakeConfig, IntakeField};
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

fn parse(text: &str) -> Result<Vec<IntakeConfig>, String> {
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
        Ok(text) => parse(&text).map_err(|e| format!("{}: {e}", path.display())),
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
            Exact::new(format!("urn:intake:{}:submit", config.id)),
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
        let configs = parse(TWO).unwrap();
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
                "urn:intake:alpha:submit",
                "message=hello&site=forged&undeclared=evil",
            ),
            (
                "urn:intake:beta:submit",
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
            post("urn:intake:alpha:submit", "site=forged"),
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
        let configs = parse(r#"[{"id":"a","space":"urn:space:a","fields":[{"name":"site","required":true}],"fixed_fields":{"site":"trusted"},"honeypot":"site"}]"#).unwrap();
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
            block_on(kernel.issue(post("urn:intake:a:submit", body), &Capability::root())).unwrap();
            assert_eq!(*seen.lock().unwrap(), r#"((site "trusted"))"#);
        }
    }

    #[test]
    fn configured_blocklist_is_the_resource_queried() {
        let configs = parse(r#"[{"id":"a","space":"urn:space:a","fields":[{"name":"email","required":true}],"email_field":"email","blocklist":"urn:custom:blocklist"}]"#).unwrap();
        let queried = Arc::new(Mutex::new(false));
        let seen = queried.clone();
        let space = bind_configs(EndpointSpace::new(), &configs).bind(
            Exact::new("urn:custom:blocklist"),
            FnEndpoint::new("block", move |inv| {
                assert_eq!(inv.inline_str("blocked")?, "blocked@example.org");
                *seen.lock().unwrap() = true;
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"yes".to_vec(),
                ))
            }),
        );
        // No destination exists: a write would fail, while a blocked submission is accepted-looking.
        let kernel = Kernel::new(Arc::new(space));
        let response = block_on(kernel.issue(
            post("urn:intake:a:submit", "email=blocked%40example.org"),
            &Capability::root(),
        ))
        .unwrap();
        assert_eq!(response.bytes, b"received\n");
        assert!(*queried.lock().unwrap());
    }

    #[test]
    fn bad_rows_are_refused_by_name() {
        for row in [
            r#"{"id":"broken","space":"urn:space:a","fields":[],"redirect":"javascript:alert(1)"}"#,
            r#"{"id":"broken","space":"not an iri","fields":[]}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[],"blocklist":"not an iri"}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[],"fixed_fields":{"a) (evil":"x"}}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[],"fixed_fields":{"received":"x"}}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[{"name":"message","max_len":0}]}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[{"name":"message"},{"name":"message"}]}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[],"unexpected":true}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[{"name":"message","requird":true}]}"#,
            r#"{"id":"broken","space":"urn:space:a","fields":[],"email_field":"missing"}"#,
        ] {
            let error = parse(&format!("[{row}]")).unwrap_err();
            assert!(error.contains("intake row 1 (`broken`)"), "{error}");
        }
        assert!(parse("[]").unwrap_err().contains("first row"));
        let duplicate = TWO.replace("\"beta\"", "\"alpha\"");
        assert!(parse(&duplicate)
            .unwrap_err()
            .contains("intake row 2 (`alpha`)"));
        assert!(parse("{").is_err());
    }
}
