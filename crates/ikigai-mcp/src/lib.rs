//! Project the ikigai manifold as MCP tools.
//!
//! MCP (the Model Context Protocol) asks a server for three things: a list of
//! tools, a typed input schema per tool, and a way to call one. ikigai already
//! has all three under other names — `urn:kernel:actions` (the capability-scoped
//! manifold), [`ArgSpec`](ikigai_core::ArgSpec) contracts, and kernel invocation.
//! This crate is the *translation*: it turns an [`Action`](ikigai_core::ActionSpec)
//! on an endpoint's [`Description`](ikigai_core::Description) into an MCP tool
//! descriptor (name + description + JSON-Schema input), and maps the tool name
//! back to the `(endpoint, verb)` it came from so a `tools/call` can be routed.
//!
//! This module is pure — no kernel, no I/O — so the mapping is unit-testable on
//! its own. The stdio JSON-RPC server that drives a live kernel is layered on top.

pub mod server;

use ikigai_core::{ActionSpec, ArgSpec, Description, Verb};
use serde_json::{json, Map, Value};

/// The separator between an endpoint id and its verb in an MCP tool name. Double
/// underscore keeps the name inside the common MCP `[A-Za-z0-9_-]` constraint
/// (endpoint ids are lowerCamel/kebab, verbs are lowercase words) while staying
/// reversible: `personal-calendar__sink` → (`personal-calendar`, Sink).
const SEP: &str = "__";

/// The MCP tool name for an (endpoint id, verb) action — reversible via
/// [`parse_tool_name`]. Every verb is suffixed, including single-verb endpoints,
/// so the name always states which action it invokes.
pub fn tool_name(id: &str, verb: Verb) -> String {
    format!("{id}{SEP}{}", verb_token(verb))
}

/// Recover the `(endpoint id, verb)` an MCP tool name was built from. `None` for
/// a name that carries no known verb suffix.
pub fn parse_tool_name(name: &str) -> Option<(String, Verb)> {
    let (id, verb) = name.rsplit_once(SEP)?;
    if id.is_empty() {
        return None;
    }
    Some((id.to_string(), parse_verb_token(verb)?))
}

fn verb_token(verb: Verb) -> &'static str {
    match verb {
        Verb::Source => "source",
        Verb::Sink => "sink",
        Verb::Exists => "exists",
        Verb::Delete => "delete",
        Verb::Meta => "meta",
    }
}

fn parse_verb_token(token: &str) -> Option<Verb> {
    match token {
        "source" => Some(Verb::Source),
        "sink" => Some(Verb::Sink),
        "exists" => Some(Verb::Exists),
        "delete" => Some(Verb::Delete),
        "meta" => Some(Verb::Meta),
        _ => None,
    }
}

/// The JSON-Schema type for an `ik:class` IRI. Scalars map to their JSON type;
/// entity classes and unknown/absent classes fall back to `"string"` (the value
/// still travels as a string on the wire).
fn json_type(class: Option<&str>) -> &'static str {
    match class {
        Some("http://www.w3.org/2001/XMLSchema#integer") => "integer",
        Some("http://www.w3.org/2001/XMLSchema#boolean") => "boolean",
        Some("http://www.w3.org/2001/XMLSchema#decimal")
        | Some("http://www.w3.org/2001/XMLSchema#double") => "number",
        _ => "string",
    }
}

/// One input's JSON-Schema property node, from its [`ArgSpec`].
fn property(input: &ArgSpec) -> Value {
    let mut node = Map::new();
    node.insert("type".into(), json!(json_type(input.class.as_deref())));
    if !input.summary.is_empty() {
        node.insert("description".into(), json!(input.summary));
    }
    if !input.one_of.is_empty() {
        node.insert("enum".into(), json!(input.one_of));
    }
    if let Some(default) = &input.default {
        node.insert("default".into(), json!(default));
    }
    Value::Object(node)
}

/// The JSON-Schema `inputSchema` object for an action — one property per declared
/// input (binding-source inputs included: an MCP client has no IRI to template,
/// so it supplies them as arguments and the server routes them into the IRI).
/// `required` lists the required inputs.
pub fn input_schema(action: &ActionSpec) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for input in &action.inputs {
        properties.insert(input.name.clone(), property(input));
        if input.required {
            required.push(Value::String(input.name.clone()));
        }
    }
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "required": required,
    })
}

/// Project one action into an MCP tool descriptor: `{ name, description,
/// inputSchema }`. The description prefers the action's own summary, then the
/// endpoint's, so the model reads what the verb does on this endpoint.
pub fn action_to_tool(description: &Description, action: &ActionSpec) -> Value {
    let summary = if !action.summary.is_empty() {
        action.summary.clone()
    } else if !description.summary.is_empty() {
        description.summary.clone()
    } else {
        description.title.clone()
    };
    json!({
        "name": tool_name(&description.id, action.verb),
        "description": summary,
        "inputSchema": input_schema(action),
    })
}

/// Project every selectable action of an endpoint into MCP tools — the normalized
/// per-verb view ([`Description::action_specs`]), so flat and per-verb authoring
/// both project identically, and Meta is excluded (it is not a selectable action).
pub fn endpoint_tools(description: &Description) -> Vec<Value> {
    description
        .action_specs()
        .iter()
        .map(|action| action_to_tool(description, action))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::ArgSpec;

    #[test]
    fn tool_names_round_trip() {
        for (id, verb) in [
            ("personal-calendar", Verb::Sink),
            ("wc", Verb::Source),
            ("rdf-diff", Verb::Source),
        ] {
            let name = tool_name(id, verb);
            assert_eq!(parse_tool_name(&name), Some((id.to_string(), verb)));
        }
        assert!(parse_tool_name("no-verb-suffix").is_none());
        assert!(parse_tool_name("__source").is_none());
    }

    #[test]
    fn a_multi_verb_action_projects_a_typed_tool() {
        // The calendar Sink shape: typed dateTime, an enum, required vs optional.
        let d = Description::new("personal-calendar").action(
            ActionSpec::new(Verb::Sink)
                .summary("create an event")
                .input(
                    ArgSpec::new("start")
                        .summary("event start")
                        .class("http://www.w3.org/2001/XMLSchema#dateTime"),
                )
                .input(
                    ArgSpec::new("all_day")
                        .class("http://www.w3.org/2001/XMLSchema#boolean")
                        .optional(),
                )
                .input(ArgSpec::new("title").optional()),
        );
        let tools = endpoint_tools(&d);
        assert_eq!(tools.len(), 1);
        let tool = &tools[0];
        assert_eq!(tool["name"], "personal-calendar__sink");
        assert_eq!(tool["description"], "create an event");
        let schema = &tool["inputSchema"];
        assert_eq!(schema["properties"]["start"]["type"], "string"); // xsd:dateTime → string
        assert_eq!(schema["properties"]["all_day"]["type"], "boolean");
        assert_eq!(schema["required"], json!(["start"]));
    }

    #[test]
    fn enum_and_default_project_to_json_schema() {
        let d = Description::new("wc").verb(Verb::Source).input(
            ArgSpec::new("count")
                .one_of(["lines", "words", "bytes"])
                .default_value("lines"),
        );
        let tool = &endpoint_tools(&d)[0];
        let count = &tool["inputSchema"]["properties"]["count"];
        assert_eq!(count["enum"], json!(["lines", "words", "bytes"]));
        assert_eq!(count["default"], "lines");
        // a defaulted arg is optional → not in required
        assert_eq!(tool["inputSchema"]["required"], json!([]));
    }

    #[test]
    fn meta_is_not_a_tool() {
        let d = Description::new("wc").verb(Verb::Source).verb(Verb::Meta);
        let names: Vec<_> = endpoint_tools(&d)
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["wc__source"]);
    }
}
