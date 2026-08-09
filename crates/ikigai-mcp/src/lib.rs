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

use ikigai_core::{ActionSpec, ArgSpec, Description, InputSource, Verb};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// The separator between an endpoint id and its verb in an MCP tool name. Double
/// underscore keeps the name inside the MCP `[A-Za-z0-9_-]` constraint (verbs are
/// lowercase words) while staying reversible: `personal-calendar__sink` →
/// (`personal-calendar`, Sink).
const SEP: &str = "__";

/// Collapse an endpoint id into the MCP tool-name charset `[A-Za-z0-9_-]`.
/// Endpoint ids are conventionally kebab/lowerCamel, but an id may be a full URI
/// (`urn:llm:config`), and MCP names forbid `:` — so any character outside the
/// set becomes `_`. The map is lossy, but it is never inverted: [`tool_name`]
/// sanitizes when building a name and `tools/call` sanitizes each candidate id
/// the same way before matching, so both sides agree on the canonical form.
pub fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The MCP tool name for an (endpoint id, verb) action. The id is sanitized into
/// the legal charset (see [`sanitize_id`]); the verb is suffixed on every tool,
/// including single-verb endpoints, so the name always states which action it
/// invokes. Recover the parts with [`parse_tool_name`] — which yields the
/// *sanitized* id, the form `tools/call` matches on.
pub fn tool_name(id: &str, verb: Verb) -> String {
    format!("{}{SEP}{}", sanitize_id(id), verb_token(verb))
}

/// Recover the `(sanitized endpoint id, verb)` an MCP tool name was built from.
/// The id is in the [`sanitize_id`] canonical form — `tools/call` compares it
/// against `sanitize_id(candidate)`, so the lossy map is never inverted. `None`
/// for a name that carries no known verb suffix.
pub fn parse_tool_name(name: &str) -> Option<(String, Verb)> {
    let (id, verb) = name.rsplit_once(SEP)?;
    if id.is_empty() {
        return None;
    }
    Some((id.to_string(), parse_verb_token(verb)?))
}

/// A visibility profile for the projected tool list — *relevance*, distinct from
/// *authority*. The capability (grant) already decides which actions a client may
/// see and call; a `ToolFilter` narrows that authorized set to the ones worth
/// showing, so a focused agent isn't handed dozens of tools that duplicate its
/// built-ins (the `urn:text:*` Unix set beside a shell) or demo endpoints. It is
/// never a security boundary: a hidden tool the client somehow names is still
/// governed by the capability at `tools/call`; hiding only shapes the menu.
///
/// Both lists are glob patterns matched against a tool name by [`Self::allows`].
/// Semantics: allowlist-wins — a `hide` match is dropped; otherwise, if `show` is
/// non-empty the tool must match it; an empty filter allows everything (the
/// default, so an unconfigured grant behaves exactly as before).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolFilter {
    /// If non-empty, only tools matching one of these patterns are shown.
    pub show: Vec<String>,
    /// Tools matching any of these patterns are always hidden (wins over `show`).
    pub hide: Vec<String>,
}

impl ToolFilter {
    /// Whether `tool_name` (the sanitized `id__verb` form) survives the filter.
    pub fn allows(&self, tool_name: &str) -> bool {
        if self.hide.iter().any(|p| pattern_matches(p, tool_name)) {
            return false;
        }
        self.show.is_empty() || self.show.iter().any(|p| pattern_matches(p, tool_name))
    }
}

/// Match one visibility pattern against a tool name. Three human-friendly forms,
/// no regex: an exact name (`grep__source`); a trailing-`*` prefix (`repo-*`,
/// `http*`); or a bare endpoint id (`grep`) that matches every verb of that
/// endpoint (`grep__source`, `grep__sink`) by matching `id__`. `*` alone matches
/// all.
fn pattern_matches(pattern: &str, name: &str) -> bool {
    if pattern == name || pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return name.starts_with(prefix);
    }
    // A verb-less id matches any verb of that endpoint.
    !pattern.contains(SEP) && name.starts_with(&format!("{pattern}{SEP}"))
}

// --- row collapse: many bound rows, one tool name ---------------------------
//
// One endpoint bound many times projects ONE tool (MCP clients key on the
// name), but every bound row must stay reachable by call. Three row shapes
// exist in practice: identical patterns (a federated override/prefer mount
// lists a namespace twice — resolution serves the first, so the projection
// keeps exactly it); patterns differing by a literal segment (ikigai-browse
// binds `urn:repo:<root>:tree` once per configured root — the roots come back
// as a synthesized enum argument); and concrete-vs-templated pairs
// (`urn:repo:<root>:explain` beside `urn:repo:<root>:explain:{path}` — the
// supplied binding arguments select the row). [`collapse`] computes the shape
// once; `tools/list` projects the synthesized arguments into the input schema
// and `tools/call` routes through [`GroupShape::route`], where an argument
// that matches no row is a loud error, never a silent drop.

/// The `{var}` template-variable names of a bound pattern (empty for an exact IRI).
fn pattern_vars(pattern: &str) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();
    let mut rest = pattern;
    while let Some(open) = rest.find('{') {
        let Some(close) = rest[open..].find('}') else {
            break;
        };
        vars.insert(rest[open + 1..open + close].to_string());
        rest = &rest[open + close + 1..];
    }
    vars
}

/// One collapsed literal dimension of a subgroup: its patterns agree on every
/// `:`-separated segment except one, and that segment is a literal in each row
/// (`urn:repo:ikigai-cli:tree` / `urn:repo:ikigai-browse:tree`). The argument
/// is named after the segment *before* the varying one — the URN grammar's own
/// label for the axis (`urn:repo:…` varies by `repo`) — and a call's value for
/// it selects the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dimension {
    name: String,
    /// The varying segment's index in the `:`-split pattern.
    index: usize,
    /// The literal at that index, per pattern (row order — the enum values).
    values: Vec<String>,
}

/// The rows of one tool name that share a template-variable set — one *calling
/// shape*. A caller lands in the subgroup whose variables its binding
/// arguments fill, then the subgroup's [`Dimension`] (if any) picks the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Subgroup {
    vars: BTreeSet<String>,
    /// Distinct patterns, selection order.
    patterns: Vec<String>,
    dimension: Option<Dimension>,
}

/// A collapsed dimension as the input-schema argument it projects to: merged
/// across subgroups by name (the concrete and templated rows of a browse
/// family both vary by `repo` — one argument, values unioned).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SyntheticArg {
    pub(crate) name: String,
    pub(crate) values: Vec<String>,
    /// Required iff every subgroup carries the dimension — then no call can
    /// land on a row without answering it.
    pub(crate) required: bool,
}

/// Everything one tool name fronts: the calling shapes and the synthesized
/// selector arguments. Computed identically by `tools/list` (to project the
/// schema) and `tools/call` (to route), so what the model sees is what routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupShape {
    subgroups: Vec<Subgroup>,
    pub(crate) synthesized: Vec<SyntheticArg>,
}

/// Collapse the same-named rows' bound patterns into a [`GroupShape`].
/// `declared` is the action's declared input names: a dimension whose derived
/// name collides with a real argument is not synthesized (the declared
/// contract wins; those rows fall back to first-in-order routing).
pub(crate) fn collapse(patterns: &[String], declared: &[String]) -> GroupShape {
    // Distinct patterns, selection order: identical patterns are the federated
    // duplicate — resolution serves the first, the projection keeps exactly it.
    let mut distinct: Vec<String> = Vec::new();
    for p in patterns {
        if !distinct.contains(p) {
            distinct.push(p.clone());
        }
    }
    let mut subgroups: Vec<Subgroup> = Vec::new();
    for p in distinct {
        let vars = pattern_vars(&p);
        match subgroups.iter_mut().find(|s| s.vars == vars) {
            Some(s) => s.patterns.push(p),
            None => subgroups.push(Subgroup {
                vars,
                patterns: vec![p],
                dimension: None,
            }),
        }
    }
    for s in &mut subgroups {
        s.dimension = dimension(&s.patterns, declared);
    }
    let mut synthesized: Vec<SyntheticArg> = Vec::new();
    for s in &subgroups {
        let Some(d) = &s.dimension else { continue };
        match synthesized.iter_mut().find(|a| a.name == d.name) {
            Some(a) => {
                for v in &d.values {
                    if !a.values.contains(v) {
                        a.values.push(v.clone());
                    }
                }
            }
            None => synthesized.push(SyntheticArg {
                name: d.name.clone(),
                values: d.values.clone(),
                required: false,
            }),
        }
    }
    for a in &mut synthesized {
        a.required = subgroups
            .iter()
            .all(|s| s.dimension.as_ref().is_some_and(|d| d.name == a.name));
    }
    GroupShape {
        subgroups,
        synthesized,
    }
}

/// The literal dimension of one subgroup's patterns, if they align: same
/// `:`-segment count, exactly one differing index, all-literal values there,
/// and a usable non-colliding name derived from the preceding segment. `None`
/// means the rows don't collapse into an enum — routing falls back to the
/// first row in selection order (exactly the pre-collapse behavior, which is
/// also what resolution precedence serves for such shapes).
fn dimension(patterns: &[String], declared: &[String]) -> Option<Dimension> {
    if patterns.len() < 2 {
        return None;
    }
    let split: Vec<Vec<&str>> = patterns.iter().map(|p| p.split(':').collect()).collect();
    let len = split[0].len();
    if split.iter().any(|s| s.len() != len) {
        return None;
    }
    let differing: Vec<usize> = (0..len)
        .filter(|&i| split.iter().any(|s| s[i] != split[0][i]))
        .collect();
    let [index] = differing[..] else {
        return None;
    };
    if index == 0 || split.iter().any(|s| s[index].contains('{')) {
        return None;
    }
    let name = split[0][index - 1];
    let legal = name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !legal || declared.iter().any(|d| d == name) {
        return None;
    }
    let mut values = Vec::new();
    for s in &split {
        let v = s[index].to_string();
        if !values.contains(&v) {
            values.push(v);
        }
    }
    Some(Dimension {
        name: name.to_string(),
        index,
        values,
    })
}

impl GroupShape {
    /// Route one call to the single bound pattern its arguments select.
    /// `supplied_bindings` are the declared Binding-source inputs the caller
    /// actually passed. Every failure is a loud, repairable error — an
    /// argument that matches no row is never dropped.
    pub(crate) fn route<'a>(
        &'a self,
        tool: &str,
        supplied_bindings: &BTreeSet<String>,
        arguments: &Map<String, Value>,
    ) -> Result<&'a str, String> {
        // A supplied selector value must name a real row, whatever else holds.
        for arg in &self.synthesized {
            if let Some(value) = arguments.get(&arg.name).and_then(scalar) {
                if !arg.values.contains(&value) {
                    return Err(format!(
                        "`{value}` is not a bound `{}` (one of: {})",
                        arg.name,
                        arg.values.join(", ")
                    ));
                }
            }
        }
        // A candidate shape must have a `{var}` for every supplied binding
        // argument — a row that would drop one is not a match.
        let candidates: Vec<&Subgroup> = self
            .subgroups
            .iter()
            .filter(|s| supplied_bindings.is_subset(&s.vars))
            .collect();
        if candidates.is_empty() {
            let supplied = supplied_bindings
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let shapes = self
                .subgroups
                .iter()
                .map(|s| {
                    if s.vars.is_empty() {
                        "(no binding arguments)".to_string()
                    } else {
                        format!(
                            "({})",
                            s.vars.iter().cloned().collect::<Vec<_>>().join(", ")
                        )
                    }
                })
                .collect::<Vec<_>>()
                .join(" or ");
            return Err(format!(
                "no bound row of `{tool}` accepts binding arguments [{supplied}]; \
                 rows accept: {shapes}"
            ));
        }
        // Prefer a fully-answered shape (every variable supplied), the most
        // specific on a tie; otherwise the first candidate in selection order
        // (its unanswered variables are optional bindings the endpoint mints —
        // the annotation Sink's `{id}` — so partial substitution stands).
        let mut full: Vec<&Subgroup> = candidates
            .iter()
            .copied()
            .filter(|s| s.vars.is_subset(supplied_bindings))
            .collect();
        full.sort_by_key(|s| std::cmp::Reverse(s.vars.len()));
        let chosen = full.first().copied().unwrap_or(candidates[0]);

        if chosen.patterns.len() == 1 {
            return Ok(&chosen.patterns[0]);
        }
        let Some(d) = &chosen.dimension else {
            // Rows that don't align into an enum: first in selection order —
            // the pre-collapse behavior, matching resolution precedence.
            return Ok(&chosen.patterns[0]);
        };
        let Some(value) = arguments.get(&d.name).and_then(scalar) else {
            return Err(format!(
                "`{}` is required: `{tool}` fronts one row per {} (one of: {})",
                d.name,
                d.name,
                d.values.join(", ")
            ));
        };
        if !d.values.contains(&value) {
            return Err(format!(
                "`{value}` is not a bound `{}` (one of: {})",
                d.name,
                d.values.join(", ")
            ));
        }
        chosen
            .patterns
            .iter()
            .find(|p| p.split(':').nth(d.index) == Some(value.as_str()))
            .map(String::as_str)
            .ok_or_else(|| {
                format!("`{value}` selects no bound row of `{tool}` for this argument shape")
            })
    }
}

/// Splice a group's synthesized selector arguments into a projected tool's
/// `inputSchema`, so the collapsed dimensions stay visible and every row stays
/// reachable. A tool with no synthesized arguments is untouched — single-row
/// tools project byte-identically to [`action_to_tool`].
pub(crate) fn add_synthesized(tool: &mut Value, shape: &GroupShape) {
    for arg in &shape.synthesized {
        let schema = &mut tool["inputSchema"];
        schema["properties"][&arg.name] = json!({
            "type": "string",
            "enum": arg.values,
            "description": format!(
                "which {} this call addresses — one tool fronts every bound {}",
                arg.name, arg.name
            ),
        });
        if arg.required {
            if let Some(required) = schema["required"].as_array_mut() {
                required.push(Value::String(arg.name.clone()));
            }
        }
    }
}

/// A JSON scalar as the string the kernel expects (numbers/bools stringified;
/// objects/arrays/null are not scalars).
pub(crate) fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
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

/// Pre-flight a tool call's JSON `arguments` against an action's declared
/// contract — required present (Binding inputs ride the IRI, so exempt),
/// `one_of` honored, XSD scalars plausible, no unknown argument names. Returns
/// `None` when it conforms, or `Some(report)` — a SHACL `ValidationReport` whose
/// `sh:resultPath` joins each violation to the catalog's input node — when it
/// does not. Structured JSON in, so a value carrying a newline or `&` (a text
/// tool's `in`) validates correctly, unlike the kernel's flat `k=v` args face.
pub fn validate_arguments(
    description: &Description,
    action: &ActionSpec,
    arguments: &Value,
) -> Option<String> {
    let empty = Map::new();
    let args = arguments.as_object().unwrap_or(&empty);

    let verb = format!("{:?}", action.verb).to_lowercase();
    let action_iri = format!("urn:ikigai:endpoint:{}:action:{verb}", description.id);
    // Explicit actions own action-scoped input nodes; synthesized ones reference
    // the endpoint-level nodes — mirror the projection so resultPath joins.
    let explicit = description.actions.iter().any(|a| a.verb == action.verb);
    let input_ns = if explicit {
        format!("{action_iri}:input:")
    } else {
        format!("urn:ikigai:endpoint:{}:input:", description.id)
    };

    let mut violations: Vec<(String, Option<String>)> = Vec::new();
    for input in &action.inputs {
        let node = format!("{input_ns}{}", input.name);
        let value = args.get(&input.name).and_then(&scalar);
        if input.required && input.source != InputSource::Binding && value.is_none() {
            violations.push((
                format!("required input `{}` is missing", input.name),
                Some(node),
            ));
            continue;
        }
        let Some(value) = value else { continue };
        if !input.one_of.is_empty() && !input.one_of.iter().any(|v| v == &value) {
            violations.push((
                format!(
                    "`{value}` is not an accepted value of `{}` (one of: {})",
                    input.name,
                    input.one_of.join(", ")
                ),
                Some(node),
            ));
            continue;
        }
        if let Some(class) = &input.class {
            let ok = match class.as_str() {
                "http://www.w3.org/2001/XMLSchema#boolean" => value == "true" || value == "false",
                "http://www.w3.org/2001/XMLSchema#integer" => value.parse::<i64>().is_ok(),
                "http://www.w3.org/2001/XMLSchema#dateTime" => {
                    let b = value.as_bytes();
                    b.len() >= 10
                        && b[..4].iter().all(u8::is_ascii_digit)
                        && b[4] == b'-'
                        && b[5..7].iter().all(u8::is_ascii_digit)
                        && b[7] == b'-'
                        && b[8..10].iter().all(u8::is_ascii_digit)
                }
                _ => true,
            };
            if !ok {
                violations.push((
                    format!(
                        "`{value}` does not look like a {class} for `{}`",
                        input.name
                    ),
                    Some(node),
                ));
            }
        }
    }
    for key in args.keys() {
        if !action.inputs.iter().any(|i| &i.name == key) {
            violations.push((
                format!("unknown argument `{key}` — not in this action's contract"),
                None,
            ));
        }
    }

    if violations.is_empty() {
        return None;
    }
    let escape = |s: &str| {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', " ")
    };
    let mut ttl = String::from("@prefix sh: <http://www.w3.org/ns/shacl#> .\n\n");
    ttl.push_str("<urn:ikigai:validation:report> a sh:ValidationReport ;\n    sh:conforms false");
    for (message, path) in &violations {
        ttl.push_str(&format!(
            " ;\n    sh:result [ a sh:ValidationResult ;\n        sh:resultSeverity sh:Violation ;\n        sh:focusNode <{action_iri}>"
        ));
        if let Some(path) = path {
            ttl.push_str(&format!(" ;\n        sh:resultPath <{path}>"));
        }
        ttl.push_str(&format!(
            " ;\n        sh:resultMessage \"{}\" ]",
            escape(message)
        ));
    }
    ttl.push_str(" .\n");
    Some(ttl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::ArgSpec;

    #[test]
    fn validate_arguments_checks_the_contract() {
        use serde_json::json;
        let d = Description::new("wc").verb(Verb::Source).input(
            ArgSpec::new("count")
                .one_of(["lines", "words", "bytes"])
                .default_value("lines"),
        );
        let action = &d.action_specs()[0];

        // Conforms: a valid enum, and a value carrying newlines is fine.
        assert!(validate_arguments(&d, action, &json!({ "count": "lines" })).is_none());
        assert!(validate_arguments(&d, action, &json!({})).is_none());

        // Bad enum → a SHACL report joined to the input node.
        let report = validate_arguments(&d, action, &json!({ "count": "nope" })).unwrap();
        assert!(report.contains("sh:conforms false"), "{report}");
        assert!(
            report.contains("not an accepted value of `count`"),
            "{report}"
        );
        assert!(report.contains("wc:input:count"), "{report}");

        // Unknown argument.
        let report = validate_arguments(&d, action, &json!({ "bogus": "x" })).unwrap();
        assert!(report.contains("unknown argument `bogus`"), "{report}");
    }

    #[test]
    fn tool_filter_allows_by_relevance() {
        // Empty filter = allow-all (an unconfigured grant is unchanged).
        assert!(ToolFilter::default().allows("wc__source"));

        // Bare id matches every verb of that endpoint; a trailing-* is a prefix;
        // an exact name matches only itself.
        let f = ToolFilter {
            show: vec![],
            hide: vec![
                "wc".to_string(),     // id → wc__source, wc__sink, …
                "repo-*".to_string(), // prefix → repo-status__source, repo-log__source
                "greet__source".to_string(),
            ],
        };
        assert!(!f.allows("wc__source"));
        assert!(!f.allows("repo-status__source"));
        assert!(!f.allows("greet__source"));
        assert!(f.allows("greeter__source")); // "greet__source" is exact, not a prefix
        assert!(f.allows("sparql__source")); // unmatched → shown

        // Allowlist-wins: with a show list, only matches survive; hide still cuts.
        let g = ToolFilter {
            show: vec!["sparql".to_string(), "rdf-*".to_string()],
            hide: vec!["rdf-transrept".to_string()],
        };
        assert!(g.allows("sparql__source"));
        assert!(g.allows("rdf-union__source"));
        assert!(!g.allows("rdf-transrept__source")); // hidden despite matching show
        assert!(!g.allows("calendar__source")); // not in show → dropped
    }

    #[test]
    fn collapse_synthesizes_the_literal_dimension() {
        // The browse family shape: concrete + templated rows, one pair per root.
        let patterns: Vec<String> = [
            "urn:repo:alpha:tree",
            "urn:repo:alpha:tree:{path}",
            "urn:repo:beta:tree",
            "urn:repo:beta:tree:{path}",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let shape = collapse(&patterns, &["path".to_string(), "as".to_string()]);
        assert_eq!(shape.synthesized.len(), 1);
        let arg = &shape.synthesized[0];
        assert_eq!(arg.name, "repo"); // named by the segment before the varying one
        assert_eq!(arg.values, ["alpha", "beta"]);
        assert!(arg.required, "every calling shape needs the selector");
    }

    #[test]
    fn identical_patterns_collapse_by_precedence() {
        // The federated override/prefer duplicate: same pattern twice —
        // resolution serves the first, so routing keeps exactly it.
        let patterns = vec!["urn:demo:echo".to_string(), "urn:demo:echo".to_string()];
        let shape = collapse(&patterns, &[]);
        assert!(shape.synthesized.is_empty());
        assert_eq!(
            shape.route("echo__source", &BTreeSet::new(), &Map::new()),
            Ok("urn:demo:echo")
        );
    }

    #[test]
    fn misaligned_rows_fall_back_to_selection_order() {
        // Different segment counts — no enum to synthesize; the first row in
        // selection order wins, exactly the pre-collapse behavior.
        let patterns = vec!["urn:a:x:t".to_string(), "urn:b:t".to_string()];
        let shape = collapse(&patterns, &[]);
        assert!(shape.synthesized.is_empty());
        assert_eq!(
            shape.route("t__source", &BTreeSet::new(), &Map::new()),
            Ok("urn:a:x:t")
        );
        // Two differing indices likewise refuse to guess.
        let patterns = vec!["urn:a:x:t".to_string(), "urn:b:y:t".to_string()];
        assert!(collapse(&patterns, &[]).synthesized.is_empty());
    }

    #[test]
    fn a_dimension_colliding_with_a_declared_input_is_not_synthesized() {
        // The declared contract owns its names: a derived selector may not
        // shadow a real argument.
        let patterns = vec![
            "urn:repo:alpha:tree".to_string(),
            "urn:repo:beta:tree".to_string(),
        ];
        assert!(collapse(&patterns, &["repo".to_string()])
            .synthesized
            .is_empty());
    }

    #[test]
    fn route_requires_the_selector_when_rows_differ() {
        let patterns = vec![
            "urn:repo:alpha:tree".to_string(),
            "urn:repo:beta:tree".to_string(),
        ];
        let shape = collapse(&patterns, &[]);
        let err = shape
            .route("tree__source", &BTreeSet::new(), &Map::new())
            .unwrap_err();
        assert!(err.contains("`repo` is required"), "{err}");
        assert!(err.contains("alpha, beta"), "{err}");
        let mut args = Map::new();
        args.insert("repo".into(), json!("beta"));
        assert_eq!(
            shape.route("tree__source", &BTreeSet::new(), &args),
            Ok("urn:repo:beta:tree")
        );
    }

    #[test]
    fn route_rejects_arguments_no_row_absorbs() {
        // `path` is declared (optional binding) but no bound row carries a
        // `{path}` — supplying it must error, never silently drop.
        let patterns = vec![
            "urn:repo:alpha:state".to_string(),
            "urn:repo:beta:state".to_string(),
        ];
        let shape = collapse(&patterns, &["path".to_string()]);
        let supplied: BTreeSet<String> = ["path".to_string()].into();
        let err = shape
            .route("state__source", &supplied, &Map::new())
            .unwrap_err();
        assert!(err.contains("no bound row"), "{err}");
        assert!(err.contains("path"), "{err}");
    }

    #[test]
    fn a_single_partially_answerable_row_still_routes() {
        // The annotation-Sink shape: one row `urn:annotation:{id}` whose `id`
        // is optional (the endpoint mints one). Omitting it must keep routing
        // to the row — partial substitution stands, as before the collapse.
        let patterns = vec!["urn:annotation:{id}".to_string()];
        let shape = collapse(&patterns, &["id".to_string()]);
        assert_eq!(
            shape.route("annotation__sink", &BTreeSet::new(), &Map::new()),
            Ok("urn:annotation:{id}")
        );
    }

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
    fn uri_shaped_ids_project_legal_names() {
        // A colon-bearing id (`urn:llm:config`) must yield a name in the MCP
        // charset, and parse back to the sanitized form the server matches on.
        let name = tool_name("urn:llm:config", Verb::Source);
        assert_eq!(name, "urn_llm_config__source");
        assert!(name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'));
        assert_eq!(
            parse_tool_name(&name),
            Some(("urn_llm_config".to_string(), Verb::Source))
        );
        // The parsed id equals sanitize_id of the original — the server's match key.
        assert_eq!(
            parse_tool_name(&name).unwrap().0,
            sanitize_id("urn:llm:config")
        );
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
