//! Project the ikigai manifold as MCP tools.
//!
//! MCP (the Model Context Protocol) asks a server for three things: a list of
//! tools, a typed input schema per tool, and a way to call one. ikigai already
//! has all three under other names — `urn:kernel:actions` (the capability-scoped
//! manifold), [`ikigai_core::ArgSpec`] contracts, and kernel invocation.
//! This crate is the *translation*: it turns an [`Action`](ikigai_core::ActionSpec)
//! on an endpoint's [`ikigai_core::Description`] into an MCP tool
//! descriptor (name + description + JSON-Schema input), and maps the tool name
//! back to the `(endpoint, verb)` it came from so a `tools/call` can be routed.
//!
//! This module is pure — no kernel, no I/O — so the mapping is unit-testable on
//! its own. The stdio JSON-RPC server that drives a live kernel is layered on top.

pub mod server;

use ikigai_core::{ActionSpec, ArgSpec, Description, Verb};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// The separator between an endpoint id and its verb in an MCP tool name. Double
/// underscore keeps the name inside the MCP `[A-Za-z0-9_-]` constraint (verbs are
/// lowercase words) while staying reversible: `personal-calendar__sink` →
/// (`personal-calendar`, Sink).
const SEP: &str = "__";

/// The longest tool name this projection will emit.
///
/// Not an MCP rule — MCP itself does not bound the length — but the strictest bound
/// among the clients that consume it (the OpenAI-style function-name limit). It is
/// enforced anyway, and deliberately at the tighter end, because the failure is not
/// local: a client that rejects one over-long name rejects the whole `tools/list`
/// response, so an over-strict cap costs one shortcut and an over-loose one costs every
/// tool on the server. The live maximum across the ecosystem is about half of this.
pub const MAX_TOOL_NAME: usize = 64;

/// Collapse an endpoint id into the MCP tool-name charset `[A-Za-z0-9_-]`.
/// Endpoint ids are conventionally kebab/lowerCamel, but an id may be a full URI
/// (`urn:llm:config`), and MCP names forbid `:` — so any character outside the
/// set becomes `_`. The map is lossy, but it is never inverted: [`tool_name`]
/// sanitizes when building a name and `tools/call` sanitizes each candidate id
/// the same way before matching, so both sides agree on the canonical form.
///
/// ⚠ This is a filter over the INPUT and proves nothing on its own. It cannot see the
/// length of what it produced, and — being lossy — it cannot see that two DIFFERENT ids
/// arrived at one name. [`is_tool_name`] and [`distinct_ids`] are the two checks that
/// close those, and the projection runs both; see [`checked_tool_name`].
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

/// Whether `name` is a usable MCP tool name: `[A-Za-z0-9_-]`, non-empty, and within
/// [`MAX_TOOL_NAME`].
///
/// ★ This is the check that filtering characters does not give you. Escaping the input
/// makes a value *look* legal; only reading the result back in the target grammar proves
/// it. Core #99 paid for that lesson in the RDF projection — percent-encoding produced a
/// legal Turtle `IRIREF` that was not a legal IRI, and the parser then rejected the whole
/// document rather than the one triple. Same shape here: the unit of rejection is the
/// response, not the tool.
pub fn is_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TOOL_NAME
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// The MCP tool name for an action, or the reason it cannot be projected.
///
/// The failure is a *skip*, never a fallback name: a synthesized replacement would be a
/// name no `tools/call` could predict, and the endpoint stays reachable through every
/// other face of the kernel. What is not acceptable is emitting a name that takes the
/// whole tool list down with it.
pub fn checked_tool_name(id: &str, verb: Verb) -> Result<String, String> {
    let name = tool_name(id, verb);
    if name.len() > MAX_TOOL_NAME {
        return Err(format!(
            "`{id}` projects to a {}-character tool name, over the {MAX_TOOL_NAME}-character limit",
            name.len()
        ));
    }
    if !is_tool_name(&name) {
        return Err(format!("`{id}` projects to no usable tool name (`{name}`)"));
    }
    // ★ And then READ IT BACK with the parser `tools/call` routes by. The charset check
    // above is satisfied by `__source` — the projection of an EMPTY id — which
    // [`parse_tool_name`] refuses, so listing it would offer a tool that can never be
    // called. Nothing but the round trip catches that; a character-class test never can.
    if parse_tool_name(&name).map(|(parsed, v)| parsed == sanitize_id(id) && v == verb)
        != Some(true)
    {
        return Err(format!(
            "`{id}` projects to `{name}`, which does not read back as the action it names"
        ));
    }
    Ok(name)
}

/// The distinct endpoint ids behind one projected tool name, in sorted order.
///
/// ★★ [`sanitize_id`] is LOSSY, and its result is used as an IDENTITY KEY: `tools/list`
/// and `tools/call` both group rows by the tool name it builds (then by contract).
/// Collapsing many rows of ONE endpoint is deliberate and correct — a federated mount
/// lists a namespace twice, browse binds one endpoint per configured root. Collapsing two
/// DIFFERENT endpoints is not: `urn:llm:config` and `urn.llm.config` both sanitize to
/// `urn_llm_config`, and the caller's request would then be routed by selection
/// precedence rather than by what it asked for.
///
/// So the collapse is only allowed to be a collapse of *one* id. More than one is a
/// defect that must surface. Surveyed 2026-09-06: 285 endpoint ids across the ecosystem,
/// zero collisions — this costs nothing today and is a guard for the day someone adds an
/// id that differs from another only in punctuation.
pub fn distinct_ids<'a>(ids: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let set: BTreeSet<&str> = ids.into_iter().collect();
    set.into_iter().map(str::to_string).collect()
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
///
/// A pattern containing `:` is an **IRI prefix** instead (`urn:layer:`, `urn:layer:*`),
/// matched against the IRIs a tool is BOUND at rather than its name, by
/// [`Self::allows_tool`]: `show = ["urn:layer:", "urn:layers:"]` projects only what lives
/// under those prefixes, which is how an MCP entry for a mounted peer leaves out the local
/// kernel's own tools (ledger #1284). A tool name can never contain `:` ([`sanitize_id`]
/// maps it to `_`), so the two forms cannot be confused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolFilter {
    /// If non-empty, only tools matching one of these patterns are shown.
    pub show: Vec<String>,
    /// Tools matching any of these patterns are always hidden (wins over `show`).
    pub hide: Vec<String>,
}

impl ToolFilter {
    /// Whether `tool_name` (the sanitized `id__verb` form) survives the filter, by NAME
    /// alone: an IRI-prefix pattern matches no name, so a filter that shows only IRI
    /// prefixes allows nothing here. [`Self::allows_tool`] is the full test.
    pub fn allows(&self, tool_name: &str) -> bool {
        self.allows_tool(tool_name, &[])
    }

    /// Whether a tool survives the filter, given its name and the IRIs (or URI-template
    /// patterns) it is bound at. A name pattern is matched against `tool_name`; an
    /// IRI-prefix pattern (one containing `:`) against each bound IRI, and it matches when
    /// any of them starts with it.
    ///
    /// ```
    /// use ikigai_mcp::ToolFilter;
    ///
    /// let filter = ToolFilter { show: vec!["urn:layer:".into()], hide: vec![] };
    /// assert!(filter.allows_tool("layer-talk-say__sink", &["urn:layer:talk:say"]));
    /// assert!(!filter.allows_tool("echo__source", &["urn:demo:echo/{message}"]));
    /// // `urn:layers:` does not start with `urn:layer:`: a prefix is a string prefix.
    /// assert!(!filter.allows_tool("layers-feed__source", &["urn:layers:feed"]));
    /// ```
    pub fn allows_tool(&self, tool_name: &str, bound_at: &[&str]) -> bool {
        let hit = |pattern: &String| match iri_prefix(pattern) {
            Some(prefix) => bound_at.iter().any(|iri| iri.starts_with(prefix)),
            None => pattern_matches(pattern, tool_name),
        };
        if self.hide.iter().any(hit) {
            return false;
        }
        self.show.is_empty() || self.show.iter().any(hit)
    }
}

/// The IRI prefix an IRI-form visibility pattern names (a trailing `*` is allowed and
/// means the same), or `None` for a tool-name pattern. See [`ToolFilter`].
fn iri_prefix(pattern: &str) -> Option<&str> {
    pattern
        .contains(':')
        .then(|| pattern.strip_suffix('*').unwrap_or(pattern))
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

/// `target` with the template variable `{var}` removed together with ONE adjacent `:`
/// separator, or `None` when that is not a spelling the URN grammar can mean.
///
/// This is the bare-form convention two modules bind by (ledger #886): `ikigai-ledger`'s
/// `urn:iki:ledger:{ledger}:append` is also `urn:iki:ledger:append` (the `default` ledger),
/// and `ikigai-browse`'s `urn:iki:annotation:{id}` is also `urn:iki:annotation` (Sink mints
/// an id). Only a variable that is a WHOLE `:`-delimited segment, appearing once, can go;
/// one inside a segment (`urn:demo:echo/{message}`, `urn:x:pre{v}`) cannot. The caller must
/// still check that the shorter IRI reaches the same endpoint, since a grammar that does
/// not match the bare spelling leaves it free for another binding.
///
/// ```text
/// urn:iki:ledger:{ledger}:append  →  urn:iki:ledger:append
/// urn:iki:annotation:{id}         →  urn:iki:annotation
/// urn:demo:echo/{message}         →  (none)
/// ```
pub(crate) fn drop_segment(target: &str, var: &str) -> Option<String> {
    let token = format!("{{{var}}}");
    if target.matches(&token).count() != 1 {
        return None;
    }
    let at = target.find(&token)?;
    let after = at + token.len();
    if !target[..at].ends_with(':') {
        return None;
    }
    if after == target.len() {
        // The last segment: drop it and the separator before it.
        return Some(target[..at - 1].to_string());
    }
    if target[after..].starts_with(':') {
        // A middle segment: drop it and the separator after it.
        return Some(format!("{}{}", &target[..at], &target[after + 1..]));
    }
    None
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
        // the annotation Sink's `{id}` — so partial substitution stands here, and the
        // caller fills or drops each one from the contract before issuing: ledger #886).
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

/// A lexical form as the JSON value of type `ty` (ledger #19, Q11: a default is typed as
/// declared): `"50"` is `50` for an `integer`, `"true"` is `true` for a `boolean`. A form
/// that does not parse stays a string rather than being dropped, so the schema still shows
/// what the contract says.
fn typed(ty: &str, lexical: &str) -> Value {
    let parsed = match ty {
        "integer" => lexical.parse::<i64>().ok().map(Value::from),
        "number" => lexical
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number),
        "boolean" => match lexical {
            "true" => Some(Value::Bool(true)),
            "false" => Some(Value::Bool(false)),
            _ => None,
        },
        _ => None,
    };
    parsed.unwrap_or_else(|| Value::String(lexical.to_string()))
}

/// A whole value (a default, an example) as JSON: typed, and for a LIST argument an array
/// of typed items split on its separator.
fn json_value(input: &ArgSpec, ty: &str, lexical: &str) -> Value {
    match input.list {
        Some(separator) => Value::Array(
            separator
                .split(lexical)
                .into_iter()
                .map(|item| typed(ty, item))
                .collect(),
        ),
        None => typed(ty, lexical),
    }
}

/// One input's JSON-Schema property node, from its [`ArgSpec`]: its type, an `enum` from an
/// enumeration (`[]` for an empty one, which accepts nothing: ledger #41), a TYPED default,
/// its examples, and its summary with each value's meaning as `word: meaning` lines (MCP has
/// no per-enum description). A LIST argument is an array of such items (ledger #497); the
/// server joins it on the way in.
fn property(input: &ArgSpec) -> Value {
    let ty = json_type(input.class.as_deref());
    let mut item = Map::new();
    item.insert("type".into(), json!(ty));
    if input.is_enumerated() {
        let values: Vec<Value> = input.one_of.iter().map(|v| typed(ty, v)).collect();
        item.insert("enum".into(), Value::Array(values));
    }
    let mut node = match input.list {
        Some(_) => {
            let mut array = Map::new();
            array.insert("type".into(), json!("array"));
            array.insert("items".into(), Value::Object(item));
            array
        }
        None => item,
    };
    let mut description = input.summary.clone();
    for (value, note) in &input.values {
        if note.summary.is_empty() {
            continue;
        }
        if !description.is_empty() {
            description.push('\n');
        }
        description.push_str(&format!("{value}: {}", note.summary));
    }
    if !description.is_empty() {
        node.insert("description".into(), json!(description));
    }
    if let Some(default) = &input.default {
        node.insert("default".into(), json_value(input, ty, default));
    }
    if !input.examples.is_empty() {
        let examples: Vec<Value> = input
            .examples
            .iter()
            .map(|e| json_value(input, ty, e))
            .collect();
        node.insert("examples".into(), Value::Array(examples));
    }
    Value::Object(node)
}

/// The carrier of an [`Arguments::Envelope`](ikigai_core::Arguments::Envelope) action: the
/// input whose BODY the other by-value inputs are fields of (ledger #358).
pub fn envelope_carrier(action: &ActionSpec) -> Option<&str> {
    match &action.arguments {
        ikigai_core::Arguments::Envelope(carrier) => Some(carrier.as_str()),
        _ => None,
    }
}

/// Where each relation between inputs goes in a projected tool (ledger #1547, Q4).
///
/// A relation that a client accepts in a tool's `inputSchema` is projected as JSON Schema;
/// one it refuses is stated in the tool's description instead, never dropped, and the
/// server-side check ([`validate_arguments`]) refuses a call that breaks it either way.
///
/// ⚠ The Anthropic Messages API, which Claude Code hands every MCP tool to, refuses
/// `oneOf`, `anyOf` and `allOf` at the TOP level of a tool's `input_schema` with a 400 for
/// the WHOLE request (Claude Code's MCP reference, "Tools with invalid input schemas";
/// anthropics/claude-code#27337). Claude Code rewrites such a root when a remote feature
/// flag lets it (an `allOf` merged, a `oneOf`/`anyOf` branch's `required` moved into the
/// description) and otherwise skips the tool or, with the flags off, sends it and fails
/// every tool with it. An input group IS a top-level relation (exactly one of two
/// properties), and several value dependencies need an `allOf` to sit side by side, so
/// both fall back to the description here; a lone root `not` or `if`/`then` is not
/// documented either way, so it is not risked. `dependentRequired` and
/// `additionalProperties` are plain 2020-12 keywords the API takes, so input dependencies
/// and the argument set stay in the schema. Hermes is untested (no scratch Hermes exists to
/// try it against without touching the live one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// In the `inputSchema`.
    Schema,
    /// In the tool's description text.
    Description,
}

/// The placement of top-level combinators (`oneOf`, `anyOf`, `allOf`, `not`, `if`/`then`)
/// in the projected tools. See [`Placement`] for why it is the description.
pub const COMBINATORS: Placement = Placement::Description;

/// The relations between an action's inputs that its schema cannot carry as properties:
/// each as the JSON-Schema fragment that states it and the sentence that says it. Groups
/// (exactly-one as `oneOf`, at-least-one as `anyOf`, at-most-one as `not` over every pair)
/// and value dependencies (`if` the value, `then` its needs).
pub fn relations(action: &ActionSpec) -> Vec<(Value, String)> {
    let quoted = |names: &[String]| {
        names
            .iter()
            .map(|n| format!("`{n}`"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let requires = |names: &[&String]| json!({ "required": names });
    let mut out = Vec::new();
    for group in &action.groups {
        let members = &group.members;
        let each: Vec<Value> = members.iter().map(|m| requires(&[m])).collect();
        let (fragment, rule) = match group.kind {
            ikigai_core::GroupKind::ExactlyOne => (json!({ "oneOf": each }), "exactly one of"),
            ikigai_core::GroupKind::AtLeastOne => (json!({ "anyOf": each }), "at least one of"),
            ikigai_core::GroupKind::AtMostOne => {
                let mut pairs = Vec::new();
                for (i, a) in members.iter().enumerate() {
                    for b in &members[i + 1..] {
                        pairs.push(requires(&[a, b]));
                    }
                }
                (json!({ "not": { "anyOf": pairs } }), "at most one of")
            }
            _ => continue,
        };
        let mut sentence = format!("Give {rule} {}.", quoted(members));
        if let Some(pipe) = &group.pipe {
            sentence.push_str(&format!(" A piped value fills `{pipe}`."));
        }
        out.push((fragment, sentence));
    }
    for input in &action.inputs {
        for (value, note) in &input.values {
            if note.needs.is_empty() {
                continue;
            }
            let condition = match input.list {
                Some(_) => json!({ "contains": { "const": value } }),
                None => json!({ "const": value }),
            };
            out.push((
                json!({
                    "if": {
                        "properties": { input.name.clone(): condition },
                        "required": [input.name],
                    },
                    "then": { "required": note.needs },
                }),
                format!("`{}={value}` needs {}.", input.name, quoted(&note.needs)),
            ));
        }
    }
    out
}

/// The JSON-Schema `inputSchema` object for an action — one property per declared
/// input (binding-source inputs included: an MCP client has no IRI to template,
/// so it supplies them as arguments and the server routes them into the IRI).
/// `required` lists the required inputs.
///
/// Beside them (ledger #1547): `additionalProperties: false` on a CLOSED argument set, which
/// states what the server-side check already enforces (Q8), and a string-valued
/// `additionalProperties` described by the action's summary of what the extra names mean on
/// an OPEN one; `dependentRequired` for every input that `needs` others; and, under
/// [`COMBINATORS`], the [`relations`] folded under one `allOf`. On an ENVELOPE action the
/// properties are the FIELDS: the carrier is not one, and the server serializes the fields
/// into it.
pub fn input_schema(action: &ActionSpec) -> Value {
    let carrier = envelope_carrier(action);
    let mut properties = Map::new();
    let mut required = Vec::new();
    let mut dependent = Map::new();
    for input in &action.inputs {
        if Some(input.name.as_str()) == carrier {
            continue;
        }
        properties.insert(input.name.clone(), property(input));
        if input.required {
            required.push(Value::String(input.name.clone()));
        }
        if !input.needs.is_empty() {
            dependent.insert(input.name.clone(), json!(input.needs));
        }
    }
    let mut schema = Map::new();
    schema.insert("type".into(), json!("object"));
    schema.insert("properties".into(), Value::Object(properties));
    schema.insert("required".into(), Value::Array(required));
    let additional = match &action.arguments {
        ikigai_core::Arguments::Open(summary) => {
            json!({ "type": "string", "description": summary })
        }
        _ => json!(false),
    };
    schema.insert("additionalProperties".into(), additional);
    if !dependent.is_empty() {
        schema.insert("dependentRequired".into(), Value::Object(dependent));
    }
    if COMBINATORS == Placement::Schema {
        let fragments: Vec<Value> = relations(action).into_iter().map(|(f, _)| f).collect();
        if !fragments.is_empty() {
            schema.insert("allOf".into(), Value::Array(fragments));
        }
    }
    Value::Object(schema)
}

/// Project one action into an MCP tool descriptor: `{ name, description,
/// inputSchema }`. The description prefers the action's own summary, then the
/// endpoint's, so the model reads what the verb does on this endpoint; under
/// [`COMBINATORS`] it then states each of the action's [`relations`], so a group or a
/// value dependency the schema cannot carry is read, never dropped.
pub fn action_to_tool(description: &Description, action: &ActionSpec) -> Value {
    let mut summary = if !action.summary.is_empty() {
        action.summary.clone()
    } else if !description.summary.is_empty() {
        description.summary.clone()
    } else {
        description.title.clone()
    };
    if COMBINATORS == Placement::Description {
        for (_, sentence) in relations(action) {
            if !summary.is_empty() {
                summary.push('\n');
            }
            summary.push_str(&sentence);
        }
    }
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

/// A tool call's JSON `arguments` as the [`ProposedArgs`](ikigai_core::ProposedArgs) the one
/// checker reads: a scalar is one pair (numbers and booleans stringified), an ARRAY is one
/// pair per item (the repeats of a list argument, joined by
/// [`ActionSpec::join_repeats`]), and `null` is not given. An object, or an array item that
/// is not a scalar, has no lexical form; it is proposed EMPTY so the name is still checked
/// (an unknown name is still reported), and the server refuses it by name before it gets here.
pub fn proposed_args(arguments: &Value) -> ikigai_core::ProposedArgs {
    let mut pairs: Vec<(String, String)> = Vec::new();
    if let Some(map) = arguments.as_object() {
        for (name, value) in map {
            match value {
                Value::Null => {}
                Value::Array(items) => {
                    for item in items {
                        pairs.push((name.clone(), scalar(item).unwrap_or_default()));
                    }
                }
                other => pairs.push((name.clone(), scalar(other).unwrap_or_default())),
            }
        }
    }
    ikigai_core::ProposedArgs::from_pairs(pairs)
}

/// Pre-flight a tool call's JSON `arguments` against an action's declared contract with
/// core's one checker ([`ActionSpec::check`], ledger #1547): every rule `urn:kernel:validate`
/// applies (required inputs, groups, `needs`, `one_of` and class per list item, repeats, the
/// argument set). Returns `None` when it conforms, or `Some(report)` — a SHACL
/// `ValidationReport` whose `sh:resultPath` joins each violation to the catalog's node and
/// whose `sh:sourceConstraintComponent` names the rule, as `urn:kernel:validate` renders it
/// — when it does not. Structured JSON in, so a value carrying a newline or `&` (a text
/// tool's `in`) validates correctly, unlike the kernel's flat `k=v` args face.
///
/// It used to be a hand copy of the kernel's rules, and it had already drifted: it built
/// `sh:resultPath` from the raw input name where core encodes it (ledger #1352).
pub fn validate_arguments(
    description: &Description,
    action: &ActionSpec,
    arguments: &Value,
) -> Option<String> {
    let violations = action.check(&proposed_args(arguments));
    if violations.is_empty() {
        return None;
    }
    // The focus node is the CONTRACT checked — content-addressed, so a mounted copy with a
    // different contract is a different node — and every path hangs off it exactly as the
    // catalog and `urn:kernel:validate` mint it (core 0.1.91, ledger #948).
    let action_iri = action.contract_iri(&description.id);
    let escape = |s: &str| {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace(['\n', '\r'], " ")
    };
    let mut ttl = String::from("@prefix sh: <http://www.w3.org/ns/shacl#> .\n\n");
    ttl.push_str("<urn:ikigai:validation:report> a sh:ValidationReport ;\n    sh:conforms false");
    for violation in &violations {
        ttl.push_str(&format!(
            " ;\n    sh:result [ a sh:ValidationResult ;\n        sh:resultSeverity sh:Violation ;\n        sh:focusNode <{}>",
            ikigai_core::escape_iri_fragment(&action_iri)
        ));
        if let Some(path) = &violation.path {
            ttl.push_str(&format!(
                " ;\n        sh:resultPath <{}>",
                ikigai_core::escape_iri_fragment(&path.node_iri(&action_iri))
            ));
        }
        ttl.push_str(&format!(
            " ;\n        sh:sourceConstraintComponent <{}>",
            violation.kind.component()
        ));
        ttl.push_str(&format!(
            " ;\n        sh:resultMessage \"{}\" ]",
            escape(&violation.message)
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
        // Joined to the CONTRACT the catalog and `urn:kernel:validate` name (core 0.1.91):
        // the content-addressed node, and its own input node beneath it.
        let contract = action.contract_iri("wc");
        assert!(
            report.contains(&format!("sh:focusNode <{contract}>")),
            "{report}"
        );
        assert!(
            report.contains(&format!("sh:resultPath <{contract}:input:count>")),
            "{report}"
        );
        assert!(!report.contains("urn:ikigai:endpoint:"), "{report}");

        // Unknown argument.
        let report = validate_arguments(&d, action, &json!({ "bogus": "x" })).unwrap();
        assert!(report.contains("unknown argument `bogus`"), "{report}");
    }

    /// The report is Turtle, and Turtle's STRING_LITERAL_QUOTE forbids a raw CR as well as a
    /// raw LF. A value carrying one is echoed into `sh:resultMessage`, so it is flattened
    /// like the LF already was (ledger #733, finding P1).
    #[test]
    fn a_carriage_return_in_a_value_does_not_reach_the_report_raw() {
        use serde_json::json;
        let d = Description::new("counter")
            .verb(Verb::Source)
            .input(ArgSpec::new("n").class("http://www.w3.org/2001/XMLSchema#integer"));
        let action = &d.action_specs()[0];
        let report = validate_arguments(&d, action, &json!({ "n": "1\r2" })).expect("a violation");
        assert!(!report.contains('\r'), "raw CR in the report: {report:?}");
    }

    /// ledger #1547: the JSON face reaches core's one checker with the SAME proposal the
    /// shared validation vectors state. `tests/vectors/validation_vectors.json` is a copy of
    /// ikigai-vocab 0.1.106's (computed by `ActionSpec::check`, and pinned by Python's and
    /// Deno's `serve` too): each case's pairs become a JSON object (a name given several times
    /// becomes an array, which is how an MCP client sends a list), and the violations
    /// `validate_arguments` sees are the vector's, kind and path, in order. A core whose
    /// checker answers differently fails here until the copy is refreshed.
    #[test]
    fn the_shared_validation_vectors_hold_through_the_json_face() {
        let vectors: Value =
            serde_json::from_str(include_str!("../tests/vectors/validation_vectors.json"))
                .expect("the vectors parse");
        let cases = vectors["cases"].as_array().expect("cases");
        assert!(cases.len() > 30, "the whole table: {}", cases.len());
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let action: ActionSpec =
                serde_json::from_value(case["action"].clone()).expect("an ActionSpec");
            let mut object = Map::new();
            for pair in case["args"].as_array().unwrap() {
                let (k, v) = (pair[0].as_str().unwrap(), pair[1].clone());
                match object.get_mut(k) {
                    None => {
                        object.insert(k.to_string(), v);
                    }
                    Some(Value::Array(items)) => items.push(v),
                    Some(first) => *first = Value::Array(vec![first.clone(), v]),
                }
            }
            let arguments = Value::Object(object);
            let got: Vec<(String, Option<String>)> = action
                .check(&proposed_args(&arguments))
                .into_iter()
                .map(|v| (v.kind.word().to_string(), v.path.map(|p| p.word())))
                .collect();
            let want: Vec<(String, Option<String>)> = case["violations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    (
                        v["kind"].as_str().unwrap().to_string(),
                        v["path"].as_str().map(str::to_string),
                    )
                })
                .collect();
            assert_eq!(got, want, "{name}: {arguments}");
            let description = Description::new("vector");
            assert_eq!(
                validate_arguments(&description, &action, &arguments).is_none(),
                case["conforms"].as_bool().unwrap(),
                "{name}"
            );
        }
    }

    /// The report names the RULE as `urn:kernel:validate` does (`sh:sourceConstraintComponent`)
    /// and a group's node as its path, so a client repairs a group violation from the report.
    #[test]
    fn a_group_violation_is_reported_at_the_groups_node() {
        use ikigai_core::InputGroup;
        let d = Description::new("cut")
            .verb(Verb::Sink)
            .input(ArgSpec::new("thread").optional())
            .input(ArgSpec::new("content").optional())
            .group(InputGroup::exactly_one(["thread", "content"]).pipe("content"));
        let action = &d.action_specs()[0];
        assert!(validate_arguments(&d, action, &json!({"thread": "urn:x"})).is_none());
        let report = validate_arguments(&d, action, &json!({})).expect("none given");
        let contract = action.contract_iri("cut");
        assert!(
            report.contains(&format!(
                "sh:resultPath <{contract}:group:exactly-one:content,thread>"
            )),
            "{report}"
        );
        assert!(report.contains("shacl#XoneConstraintComponent"), "{report}");
        assert!(report.contains("got none"), "{report}");
    }

    /// ledger #1547's projection, construct by construct: a LIST is an array of its items'
    /// type and enumeration; an EMPTY enumeration is `"enum": []`; a default is TYPED as
    /// declared (`50` for an integer, `false` for a boolean, an array for a list); examples
    /// ride along; a value's meaning is a `word: meaning` line; `needs` is
    /// `dependentRequired`; a closed set is `additionalProperties: false`, an open one a
    /// described string; an envelope's carrier is not a property.
    #[test]
    fn the_schema_projects_the_argspec_shape() {
        use ikigai_core::{ListSeparator, ValueNote};
        const INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";
        let d = Description::new("review")
            .verb(Verb::Source)
            .input(
                ArgSpec::new("proposals")
                    .optional()
                    .list(ListSeparator::Comma)
                    .one_of(["minor", "major"])
                    .default_value("minor,major"),
            )
            .input(ArgSpec::new("limit").class(INTEGER).default_value("50"))
            .input(ArgSpec::new("strict").default_value(false))
            .input(ArgSpec::new("color").optional().example("#336699"))
            .input(
                ArgSpec::new("decision")
                    .optional()
                    .one_of(["publish", "retract"])
                    .value(
                        "retract",
                        ValueNote::new()
                            .summary("withdraw a published decision")
                            .needs(["revises"]),
                    ),
            )
            .input(ArgSpec::new("revises").optional())
            .input(ArgSpec::new("endpoint").optional().needs(["verb"]))
            .input(ArgSpec::new("verb").optional())
            .input(
                ArgSpec::new("provider")
                    .optional()
                    .one_of(Vec::<String>::new()),
            );
        let schema = input_schema(&d.action_specs()[0]);
        let p = &schema["properties"];
        assert_eq!(
            p["proposals"],
            json!({"type": "array", "items": {"type": "string", "enum": ["minor", "major"]},
                   "default": ["minor", "major"]})
        );
        assert_eq!(p["limit"]["default"], json!(50));
        assert_eq!(p["limit"]["type"], "integer");
        assert_eq!(p["strict"]["default"], json!(false));
        assert_eq!(p["strict"]["type"], "boolean");
        assert_eq!(p["color"]["examples"], json!(["#336699"]));
        assert_eq!(
            p["decision"]["description"],
            "retract: withdraw a published decision"
        );
        assert_eq!(p["provider"]["enum"], json!([]));
        assert_eq!(schema["dependentRequired"], json!({"endpoint": ["verb"]}));
        assert_eq!(schema["additionalProperties"], json!(false));
        // No top-level combinator: Claude Code's API refuses them (see `Placement`).
        for combinator in ["allOf", "oneOf", "anyOf", "not", "if"] {
            assert!(schema.get(combinator).is_none(), "{combinator}: {schema}");
        }

        let open = ActionSpec::new(Verb::Source)
            .input(ArgSpec::new("src"))
            .open_arguments("each fills a {name} marker in the body");
        assert_eq!(
            input_schema(&open)["additionalProperties"],
            json!({"type": "string", "description": "each fills a {name} marker in the body"})
        );

        let envelope = ActionSpec::new(Verb::Sink)
            .input(ArgSpec::new("email"))
            .input(ArgSpec::new("note").optional())
            .input(ArgSpec::new("content"))
            .envelope("content");
        let schema = input_schema(&envelope);
        assert!(schema["properties"].get("content").is_none(), "{schema}");
        assert_eq!(schema["required"], json!(["email"]));
    }

    /// ledger #1547, Q4: a relation the schema cannot carry at the top level (a group, a
    /// value's `needs`) is STATED in the tool's description, never dropped; the JSON-Schema
    /// fragment for each is still built, so a client that accepts combinators can be given
    /// them by flipping [`COMBINATORS`].
    #[test]
    fn relations_fall_back_to_the_tool_description() {
        use ikigai_core::{InputGroup, ValueNote};
        let d = Description::new("validate")
            .summary("pre-flight a call")
            .verb(Verb::Source)
            .input(ArgSpec::new("action").optional())
            .input(ArgSpec::new("endpoint").optional())
            .input(ArgSpec::new("a").optional())
            .input(ArgSpec::new("b").optional())
            .input(
                ArgSpec::new("decision")
                    .optional()
                    .one_of(["keep", "retract"])
                    .value("retract", ValueNote::new().needs(["action"])),
            )
            .group(InputGroup::exactly_one(["action", "endpoint"]))
            .group(InputGroup::at_most_one(["a", "b"]));
        let action = &d.action_specs()[0];
        let tool = action_to_tool(&d, action);
        let text = tool["description"].as_str().unwrap();
        assert!(text.starts_with("pre-flight a call\n"), "{text}");
        assert!(
            text.contains("Give exactly one of `action`, `endpoint`."),
            "{text}"
        );
        assert!(text.contains("Give at most one of `a`, `b`."), "{text}");
        assert!(
            text.contains("`decision=retract` needs `action`."),
            "{text}"
        );

        let fragments: Vec<Value> = relations(action).into_iter().map(|(f, _)| f).collect();
        assert_eq!(
            fragments[0],
            json!({"oneOf": [{"required": ["action"]}, {"required": ["endpoint"]}]})
        );
        assert_eq!(
            fragments[1],
            json!({"not": {"anyOf": [{"required": ["a", "b"]}]}})
        );
        assert_eq!(
            fragments[2],
            json!({"if": {"properties": {"decision": {"const": "retract"}},
                          "required": ["decision"]},
                   "then": {"required": ["action"]}})
        );
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

    /// ★ Filtering the input characters does not prove the output is a legal name.
    ///
    /// `sanitize_id` cannot see length, and length is exactly where the analogue of core
    /// #99 bites: a client that rejects one over-long name rejects the WHOLE `tools/list`
    /// response, so the failure escalates from one tool to every tool. The projection has
    /// to read its own result back in MCP's grammar.
    #[test]
    fn a_projected_tool_name_is_certified_in_mcps_own_grammar() {
        // The grammar, stated as a test rather than as a comment.
        assert!(is_tool_name("urn_llm_config__source"));
        assert!(is_tool_name("a"));
        assert!(!is_tool_name(""));
        assert!(
            !is_tool_name("urn:llm:config__source"),
            "`:` is not in the charset"
        );
        assert!(!is_tool_name("has space__source"));
        assert!(!is_tool_name(&"x".repeat(MAX_TOOL_NAME + 1)));
        assert!(is_tool_name(&"x".repeat(MAX_TOOL_NAME)));

        // Every id in the live shapes projects to a certified name that parses back.
        // These are ids the host really binds, read from the locked releases: `echo`
        // (core's builtins), `llm-config` (ikigai-llm 0.15), `meeting-schedule`
        // (ikigai-meeting 0.7) and `browse-explain-versions` (ikigai-browse 0.18.10). A URI-shaped id is
        // the next test's subject, not a live one.
        for id in [
            "echo",
            "llm-config",
            "meeting-schedule",
            "browse-explain-versions",
        ] {
            let name = checked_tool_name(id, Verb::Source).expect(id);
            assert!(is_tool_name(&name), "{name}");
            assert_eq!(parse_tool_name(&name).unwrap().0, sanitize_id(id));
        }

        // An id too long to project is REFUSED, with the reason — never emitted, and
        // never replaced by a synthesized name no `tools/call` could predict.
        let long = "urn:".to_string() + &"segment:".repeat(12);
        let err = checked_tool_name(&long, Verb::Source).unwrap_err();
        assert!(err.contains("over the"), "{err}");
        // An empty id would project to `__source`, which `parse_tool_name` already
        // refuses — so listing it would offer a tool that can never be called.
        assert!(checked_tool_name("", Verb::Source).is_err());
    }

    /// ★★ `sanitize_id` is lossy AND it is the identity key. Two ids differing only in
    /// punctuation become one tool name, and a call then lands wherever selection
    /// precedence puts it. Zero collisions exist today across 285 ecosystem ids, which is
    /// precisely why the guard is worth having now: it costs nothing and it will not be
    /// added on the day it is needed.
    #[test]
    fn two_ids_differing_only_in_punctuation_collide_on_one_tool_name() {
        assert_eq!(sanitize_id("urn:llm:config"), sanitize_id("urn.llm.config"));
        assert_eq!(
            tool_name("urn:llm:config", Verb::Source),
            tool_name("urn.llm.config", Verb::Source)
        );
        // Which is the defect the projection must SURFACE rather than merge.
        assert_eq!(
            distinct_ids(["urn:llm:config", "urn.llm.config"]).len(),
            2,
            "two endpoints, one name — an ambiguous tool"
        );
        // Many rows of ONE endpoint is the deliberate, correct collapse: a federated
        // mount lists a namespace twice, browse binds one endpoint per configured root.
        assert_eq!(
            distinct_ids(["browse-tree", "browse-tree", "browse-tree"]),
            vec!["browse-tree".to_string()]
        );
        assert!(distinct_ids(std::iter::empty()).is_empty());
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
        // The annotation-Sink shape: one row `urn:iki:annotation:{id}` whose `id`
        // is optional (the endpoint mints one). Omitting it must keep routing
        // to the row — partial substitution stands, as before the collapse.
        //
        // The IRI is written in the CANONICAL spelling on purpose: this fixture
        // mirrors what the browse catalog advertises, and the catalog lists the
        // BACKING name (an alias is never listed — ikigai-core's alias decision 4).
        // A projection tested against a spelling the catalog no longer emits is
        // testing a shape nothing produces. The tool NAME is unaffected: it comes
        // from `Description::id` ("annotation"), not from the IRI.
        let patterns = vec!["urn:iki:annotation:{id}".to_string()];
        let shape = collapse(&patterns, &["id".to_string()]);
        assert_eq!(
            shape.route("annotation__sink", &BTreeSet::new(), &Map::new()),
            Ok("urn:iki:annotation:{id}")
        );
    }

    #[test]
    fn only_a_whole_segment_variable_can_be_dropped() {
        assert_eq!(
            drop_segment("urn:iki:ledger:{ledger}:append", "ledger").as_deref(),
            Some("urn:iki:ledger:append")
        );
        assert_eq!(
            drop_segment("urn:iki:annotation:{id}", "id").as_deref(),
            Some("urn:iki:annotation")
        );
        assert_eq!(
            drop_segment("urn:iki:ledger:{ledger}:item:{id}", "ledger").as_deref(),
            Some("urn:iki:ledger:item:{id}")
        );
        for (pattern, var) in [
            ("urn:demo:echo/{message}", "message"),
            ("urn:x:pre{v}", "v"),
            ("urn:x:{v}suffix", "v"),
            ("{v}:x", "v"),
            ("urn:x:{v}:{v}", "v"),
            ("urn:x:{w}", "v"),
        ] {
            assert_eq!(drop_segment(pattern, var), None, "{pattern}");
        }
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
