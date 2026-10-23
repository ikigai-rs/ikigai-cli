//! A minimal, runtime-free MCP stdio server over a live kernel.
//!
//! MCP stdio speaks newline-delimited JSON-RPC 2.0. This server answers the
//! handful of methods a tool provider needs — `initialize`, `tools/list`,
//! `tools/call` — by driving the kernel it was handed under a fixed capability
//! (the session's grant). [`handle`] is the pure per-message dispatch (kernel +
//! capability + one request → one optional response), so it is unit-testable
//! without any I/O; [`serve`] is the stdin→stdout loop around it.
//!
//! The capability is the ceiling: `tools/list` shows only what the grant allows
//! (via [`Kernel::select_actions`]), and every `tools/call` re-checks it and
//! pre-flights the arguments through `urn:kernel:validate` before invoking — so
//! the manifold the model sees and the calls it can make never exceed the grant.

use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::{action_to_tool, parse_tool_name, ToolFilter};

/// The MCP protocol revision this server implements against.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// JSON-RPC 2.0 §5.1: the input is not JSON at all.
pub const PARSE_ERROR: i64 = -32700;
/// JSON-RPC 2.0 §5.1: the input is JSON but not a valid Request object.
pub const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC 2.0 §5.1: the method does not exist.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// Dispatch one parsed JSON-RPC message. Returns the response value to write back, or
/// `None` when JSON-RPC 2.0 says nothing is owed: a notification (a `method` and no
/// `id`), or a RESPONSE from the client (a `result` or an `error` and no `method`).
///
/// Anything else that is not a valid Request gets `-32600 Invalid Request`, under the
/// message's `id` when that is readable (a string, a number or null) and under `null`
/// otherwise — never silence, which a client cannot tell from a hang.
///
/// A JSON array is a batch, and batching is not part of the MCP revision this server
/// implements (2024-11-05: MCP added batches in 2025-03-26 and
/// removed them again in 2025-06-18), so every array, empty or not, is one
/// `-32600` under `null`.
///
/// ```
/// # use ikigai_core::{Capability, EndpointSpace, Kernel};
/// # use ikigai_mcp::{server::handle, ToolFilter};
/// # use serde_json::json;
/// # let kernel = Kernel::new(std::sync::Arc::new(EndpointSpace::new()));
/// # let (cap, filter) = (Capability::root(), ToolFilter::default());
/// // No `jsonrpc` member: invalid, answered under the id it carried.
/// let reply = handle(&kernel, &cap, &filter, &json!({"id": 7, "method": "ping"})).unwrap();
/// assert_eq!(reply["id"], 7);
/// assert_eq!(reply["error"]["code"], -32600);
/// assert_eq!(reply["error"]["message"], "Invalid Request");
///
/// // A response from the client to a server-initiated request: valid, never answered.
/// let response = json!({"jsonrpc": "2.0", "id": 3, "result": {}});
/// assert!(handle(&kernel, &cap, &filter, &response).is_none());
/// ```
pub fn handle(
    kernel: &Kernel,
    capability: &Capability,
    filter: &ToolFilter,
    msg: &Value,
) -> Option<Value> {
    let (id, method) = match shape(msg) {
        Shape::Request { id, method } => (id, method),
        Shape::Notification | Shape::Response => return None,
        Shape::Invalid { id, reason } => {
            return Some(err(id, INVALID_REQUEST, "Invalid Request", Some(&reason)))
        }
    };

    match method {
        "initialize" => Some(ok(id, initialize_result())),
        "ping" => Some(ok(id, json!({}))),
        "tools/list" => Some(ok(id, tools_list(kernel, capability, filter))),
        "tools/call" => Some(ok(id, tools_call(kernel, capability, msg.get("params")))),
        other => Some(err(
            id,
            METHOD_NOT_FOUND,
            &format!("method not found: {other}"),
            None,
        )),
    }
}

/// Dispatch one line of MCP stdio, as the raw bytes read (a trailing `\n` or `\r\n` is
/// ignored). A blank line is framing slack and gets no reply; a line that is not JSON —
/// invalid UTF-8 included — gets `-32700 Parse error` under `null`; anything else goes
/// to [`handle`].
///
/// ```
/// # use ikigai_core::{Capability, EndpointSpace, Kernel};
/// # use ikigai_mcp::{server::handle_line, ToolFilter};
/// # let kernel = Kernel::new(std::sync::Arc::new(EndpointSpace::new()));
/// # let (cap, filter) = (Capability::root(), ToolFilter::default());
/// let reply = handle_line(&kernel, &cap, &filter, b"not json\n").unwrap();
/// assert_eq!(reply["id"], serde_json::Value::Null);
/// assert_eq!(reply["error"]["code"], -32700);
/// assert_eq!(reply["error"]["message"], "Parse error");
/// assert!(handle_line(&kernel, &cap, &filter, b"  \r\n").is_none());
/// ```
pub fn handle_line(
    kernel: &Kernel,
    capability: &Capability,
    filter: &ToolFilter,
    line: &[u8],
) -> Option<Value> {
    match parse_line(line) {
        Parsed::Blank => None,
        Parsed::Unparsable(reply) => Some(reply),
        Parsed::Repeated(msg, path) => refuse_repeated(&msg, &path),
        Parsed::Message(msg) => handle(kernel, capability, filter, &msg),
    }
}

/// One line of MCP stdio, read.
enum Parsed {
    /// Framing slack: owed nothing.
    Blank,
    /// Not JSON (invalid UTF-8 included): the `-32700` reply it is owed.
    Unparsable(Value),
    /// A JSON value, to dispatch.
    Message(Value),
    /// A JSON value that names one member twice in one object, and the path to the repeat
    /// (ledger #387). Parsing keeps the LAST value, so dispatching it would act on a message
    /// the client did not unambiguously send: it is answered by [`refuse_repeated`] instead.
    Repeated(Value, Vec<String>),
}

fn parse_line(line: &[u8]) -> Parsed {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.iter().all(u8::is_ascii_whitespace) {
        return Parsed::Blank;
    }
    match serde_json::from_slice::<Value>(line) {
        Ok(msg) => match repeated_member(line) {
            Some(path) => Parsed::Repeated(msg, path),
            None => Parsed::Message(msg),
        },
        Err(e) => Parsed::Unparsable(err(
            Value::Null,
            PARSE_ERROR,
            "Parse error",
            Some(&e.to_string()),
        )),
    }
}

/// The detail of every refusal of a name given twice (ledger #387).
const GIVEN_TWICE: &str = "given twice; an argument takes one value, so name it once";

/// The answer to a message that names a member twice (ledger #387). `serde_json` keeps the
/// LAST of a repeated member, so `"arguments": {"graph": "A", "graph": "B"}` reached the
/// endpoint as `graph=B` and the call answered as if nothing were wrong.
///
/// A repeated tool ARGUMENT is the caller's mistake in a well-formed call, so it is a tool
/// result with `isError` naming the argument, the typed `InvalidArgument` form, which a
/// model reads and repairs from. Any other repeated member makes the message itself
/// ambiguous, so it is `-32600 Invalid Request` naming the member; a repeated `id` answers
/// under `null`, since which id was meant is the ambiguity. A notification or a response is
/// still never answered.
fn refuse_repeated(msg: &Value, path: &[String]) -> Option<Value> {
    let (id, method) = match shape(msg) {
        Shape::Request { id, method } => (id, method),
        Shape::Notification | Shape::Response => return None,
        Shape::Invalid { id, reason } => {
            return Some(err(id, INVALID_REQUEST, "Invalid Request", Some(&reason)))
        }
    };
    if let ("tools/call", [params, arguments, name]) = (method, path) {
        if params == "params" && arguments == "arguments" {
            let refused = ikigai_core::Error::InvalidArgument {
                name: name.clone(),
                detail: GIVEN_TWICE.to_string(),
            };
            return Some(ok(id, tool_error(refused.to_string())));
        }
    }
    let id = if path.first().map(String::as_str) == Some("id") {
        Value::Null
    } else {
        id
    };
    let detail = format!(
        "member `{}` is given twice; a message names each member of an object once",
        path.join(".")
    );
    Some(err(id, INVALID_REQUEST, "Invalid Request", Some(&detail)))
}

/// The path to the first member named twice in one JSON object, anywhere in `line`, in
/// document order (`["params", "arguments", "graph"]`; an array element is its index).
/// `None` when every object names each member once, or when `line` does not parse.
fn repeated_member(line: &[u8]) -> Option<Vec<String>> {
    use serde::de::DeserializeSeed;
    let mut path = Vec::new();
    let mut found = None;
    let mut de = serde_json::Deserializer::from_slice(line);
    Walk {
        path: &mut path,
        found: &mut found,
    }
    .deserialize(&mut de)
    .ok()?;
    found
}

/// A JSON walk that keeps nothing but the path to the first repeated member.
struct Walk<'a> {
    path: &'a mut Vec<String>,
    found: &'a mut Option<Vec<String>>,
}

impl Walk<'_> {
    fn child(&mut self) -> Walk<'_> {
        Walk {
            path: &mut *self.path,
            found: &mut *self.found,
        }
    }
}

impl<'de> serde::de::DeserializeSeed<'de> for Walk<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<(), D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de> serde::de::Visitor<'de> for Walk<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(mut self, mut seq: A) -> Result<(), A::Error> {
        let mut index = 0usize;
        loop {
            self.path.push(index.to_string());
            let more = seq.next_element_seed(self.child())?;
            self.path.pop();
            if more.is_none() {
                return Ok(());
            }
            index += 1;
        }
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(mut self, mut map: A) -> Result<(), A::Error> {
        let mut seen = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) && self.found.is_none() {
                let mut at = self.path.clone();
                at.push(key.clone());
                *self.found = Some(at);
            }
            self.path.push(key);
            map.next_value_seed(self.child())?;
            self.path.pop();
        }
        Ok(())
    }
}

/// What a parsed message IS, by JSON-RPC 2.0 §4 and §5.
enum Shape<'a> {
    /// A `method` and an `id`: owed exactly one response.
    Request { id: Value, method: &'a str },
    /// A `method` and no `id`: never answered, not even with an error (§4.1).
    Notification,
    /// A `result` or an `error` and no `method`: the client answering a request the
    /// server sent. Never answered — even when malformed, since replying to a reply is
    /// how two peers trade errors forever, and JSON-RPC gives a response no reply.
    Response,
    /// Anything else: `-32600`, under `id` (null when no id was readable).
    Invalid { id: Value, reason: String },
}

fn shape(msg: &Value) -> Shape<'_> {
    let Some(obj) = msg.as_object() else {
        let reason = match msg {
            Value::Array(batch) if batch.is_empty() => "an empty batch".to_string(),
            Value::Array(_) => format!(
                "a batch: JSON-RPC batching is not part of MCP {PROTOCOL_VERSION}; \
                 send each message on its own line"
            ),
            _ => "a JSON-RPC message is an object".to_string(),
        };
        return Shape::Invalid {
            id: Value::Null,
            reason,
        };
    };
    let method = obj.get("method");
    if method.is_none() && (obj.contains_key("result") || obj.contains_key("error")) {
        return Shape::Response;
    }
    if method.is_some() && !obj.contains_key("id") {
        return Shape::Notification;
    }
    let invalid = |id: &Value, reason: &str| Shape::Invalid {
        id: id.clone(),
        reason: reason.to_string(),
    };
    let id = match obj.get("id") {
        Some(id @ (Value::String(_) | Value::Number(_) | Value::Null)) => id.clone(),
        None => Value::Null,
        Some(_) => return invalid(&Value::Null, "`id` must be a string, a number or null"),
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return invalid(&id, "`jsonrpc` must be exactly \"2.0\"");
    }
    let Some(method) = method else {
        return invalid(&id, "no `method`, and no `result` or `error` either");
    };
    let Some(method) = method.as_str() else {
        return invalid(&id, "`method` must be a string");
    };
    if obj
        .get("params")
        .is_some_and(|p| !(p.is_object() || p.is_array()))
    {
        return invalid(&id, "`params` must be an object or an array");
    }
    Shape::Request { id, method }
}

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// A JSON-RPC error object; `data` carries the reason when the standard message is terse.
fn err(id: Value, code: i64, message: &str, data: Option<&str>) -> Value {
    let mut error = json!({ "code": code, "message": message });
    if let Some(data) = data {
        error["data"] = json!(data);
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": error })
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": { "listChanged": true } },
        "serverInfo": { "name": "ikigai", "version": env!("CARGO_PKG_VERSION") },
    })
}

/// Project the capability-scoped manifold as the MCP tool list. `select_actions`
/// with no present types returns every action the grant *authorizes*; each is
/// `describe`d for its typed contract and projected to a tool — then `filter`
/// drops the ones not worth showing (relevance, not authority; see [`ToolFilter`]).
fn tools_list(kernel: &Kernel, capability: &Capability, filter: &ToolFilter) -> Value {
    let query = ikigai_core::ActionQuery {
        capability: Some(capability),
        ..Default::default()
    };
    let mut tools = Vec::new();
    for group in tool_groups(kernel.select_actions(&query), true) {
        let bound_at: Vec<&str> = group.rows.iter().map(|m| m.endpoint.as_str()).collect();
        if !filter.allows_tool(&group.base, &bound_at) {
            continue;
        }
        let rows = &group.rows;
        // ★ The collapse is a collapse of ONE endpoint bound many ways. Two DIFFERENT ids
        // landing on one name is a different thing entirely: the name is the identity an
        // MCP client calls by, so serving it would route by selection precedence rather
        // than by what the caller asked for. Refuse instead — an ambiguous name is not a
        // usable tool, and a silent merge is the one outcome a caller cannot detect. See
        // [`crate::distinct_ids`].
        if let Some(ids) = &group.ambiguous {
            eprintln!(
                "ikigai-mcp: `{}` is claimed by {} endpoint ids that differ only in \
                 punctuation ({}) — not projected; rename one of them",
                group.name,
                ids.len(),
                ids.join(", ")
            );
            continue;
        }
        // `endpoint` may be an exact IRI or a URI-template pattern
        // (`urn:demo:echo/{message}`) — `describe_pattern` covers both, so
        // template-bound endpoints project as tools too.
        let Some(description) = kernel.describe_pattern(&rows[0].endpoint) else {
            continue;
        };
        let Some(action) = description
            .action_specs()
            .into_iter()
            .find(|a| a.verb == rows[0].verb)
        else {
            continue;
        };
        let mut tool = action_to_tool(&description, &action);
        let patterns: Vec<String> = rows.iter().map(|m| m.endpoint.clone()).collect();
        if group.name != group.base {
            // A second contract under one id: named apart, and SAID to be apart, so a model
            // choosing between the two reads why there are two.
            tool["name"] = json!(group.name);
            let summary = tool["description"].as_str().unwrap_or_default().to_string();
            tool["description"] = json!(format!(
                "{summary} [a different contract for `{}` than the tool `{}`; served at {}]",
                rows[0].id,
                group.base,
                patterns.join(", ")
            ));
        }
        let declared: Vec<String> = action.inputs.iter().map(|i| i.name.clone()).collect();
        crate::add_synthesized(&mut tool, &crate::collapse(&patterns, &declared));
        tools.push(tool);
    }
    json!({ "tools": tools })
}

/// One projected tool: the name a client calls, and the manifold rows behind it.
struct ToolGroup {
    /// The tool's name: `{id}__{verb}` for an id's first contract, `{id}-{digest}__{verb}`
    /// for every other contract under the same id and verb (see [`tool_groups`]).
    name: String,
    /// `{id}__{verb}` — what a [`ToolFilter`](crate::ToolFilter) is matched against, so
    /// hiding an endpoint hides every contract it is served under.
    base: String,
    /// The rows, all of ONE contract, in selection order.
    rows: Vec<ikigai_core::ActionMatch>,
    /// Set when two DIFFERENT ids sanitize to one base name: listed nowhere, routed nowhere.
    ambiguous: Option<Vec<String>>,
}

/// Group the manifold's rows into tools — ONE function, run by `tools/list` to project and by
/// `tools/call` to route, so what a client is shown is exactly what routes.
///
/// Rows group first by the projected name (`{id}__{verb}`): MCP clients key on the name, so
/// same-named rows — a namespace listed by both a fronted mount and the local space
/// (`--override`/`--prefer`), or one endpoint bound once per configured root (browse) —
/// collapse to ONE tool without losing reach. Identical patterns collapse by precedence
/// (resolution serves the first); patterns that differ come back as synthesized selector
/// arguments in the input schema (see [`crate::collapse`]), so every row stays addressable.
///
/// ★ Then by CONTRACT (ledger #948). An id is not unique in a kernel: a mounted peer's
/// `toUpper` can declare another capability or another input than the local one, and core
/// 0.1.91 content-addresses contracts so the two never merge. Grouping by name alone took
/// the schema from the first row, so the peer's copy was listed under the local contract and
/// a call using the peer's extra input was refused as an unknown argument — unreachable. So
/// the first contract (selection order) keeps the plain name, and each further contract gets
/// its own tool, `{id}-{first 8 hex of its digest}__{verb}`: stable while the contract is,
/// and different exactly when the contract is.
///
/// `report` sends the reason a row is not projected to stderr (the stdio server's log
/// channel); `tools/call` regroups silently.
fn tool_groups(matches: Vec<ikigai_core::ActionMatch>, report: bool) -> Vec<ToolGroup> {
    let skip = |reason: String| {
        if report {
            eprintln!("ikigai-mcp: not projected as a tool — {reason}");
        }
    };
    let mut by_base: Vec<(String, Vec<ikigai_core::ActionMatch>)> = Vec::new();
    for m in matches {
        // A name this projection cannot certify is not offered. Silence would be the
        // wrong answer twice over — the tool would be missing with no reason given, and
        // an over-long name reaching a client rejects the ENTIRE list, not the one tool.
        let base = match crate::checked_tool_name(&m.id, m.verb) {
            Ok(name) => name,
            Err(reason) => {
                skip(reason);
                continue;
            }
        };
        match by_base.iter_mut().find(|(b, _)| *b == base) {
            Some((_, rows)) => rows.push(m),
            None => by_base.push((base, vec![m])),
        }
    }
    let mut groups: Vec<ToolGroup> = Vec::new();
    for (base, rows) in by_base {
        let ids = crate::distinct_ids(rows.iter().map(|m| m.id.as_str()));
        if ids.len() > 1 {
            groups.push(ToolGroup {
                name: base.clone(),
                base,
                rows,
                ambiguous: Some(ids),
            });
            continue;
        }
        let mut by_contract: Vec<(String, Vec<ikigai_core::ActionMatch>)> = Vec::new();
        for m in rows {
            match by_contract.iter_mut().find(|(c, _)| *c == m.action) {
                Some((_, rows)) => rows.push(m),
                None => by_contract.push((m.action.clone(), vec![m])),
            }
        }
        for (i, (contract, rows)) in by_contract.into_iter().enumerate() {
            let name = if i == 0 {
                base.clone()
            } else {
                let Some(digest) = ikigai_core::parse_contract_iri(&contract)
                    .and_then(|_| contract.rsplit_once(":b3:"))
                    .and_then(|(_, hex)| hex.get(..8))
                else {
                    skip(format!(
                        "a second `{base}` contract `{contract}` is not content-addressed, so \
                         it has no name to be listed under"
                    ));
                    continue;
                };
                match crate::checked_tool_name(&format!("{}-{digest}", rows[0].id), rows[0].verb) {
                    Ok(name) => name,
                    Err(reason) => {
                        skip(reason);
                        continue;
                    }
                }
            };
            // A qualified name that some OTHER endpoint already projects to would make the
            // call route by list order; the later one is not offered.
            if groups.iter().any(|g| g.name == name) {
                skip(format!("`{name}` is already the name of another tool"));
                continue;
            }
            groups.push(ToolGroup {
                name,
                base: base.clone(),
                rows,
                ambiguous: None,
            });
        }
    }
    groups
}

/// Invoke one tool. Re-checks the grant (the tool must be in the manifold),
/// pre-flights the arguments through `urn:kernel:validate`, then issues the
/// request. Failures come back as an MCP tool result with `isError: true` and
/// the reason as text — data the model can read and repair from — never a
/// JSON-RPC protocol error.
fn tools_call(kernel: &Kernel, capability: &Capability, params: Option<&Value>) -> Value {
    let params = params.cloned().unwrap_or_else(|| json!({}));
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let Some((id, verb)) = parse_tool_name(name) else {
        return tool_error(format!("not a tool name: {name:?}"));
    };
    // Callable and listable must be the same set: `tools/list` refuses to project a name
    // it cannot certify, so `tools/call` refuses to route one. Without this, an over-long
    // name would fall through to the "not in the manifold" branch below and blame a
    // missing endpoint for what is a projection limit.
    if !crate::is_tool_name(name) {
        return tool_error(format!(
            "`{name}` is not a projectable tool name — it is never listed, so it cannot be called"
        ));
    }

    // Re-select under the grant: the tool must still be an allowed action, and
    // this yields its resolvable endpoint IRI + catalog action IRI.
    let query = ikigai_core::ActionQuery {
        capability: Some(capability),
        ..Default::default()
    };
    // Regroup exactly as `tools/list` projected (see [`tool_groups`]): the name picks ONE
    // group — one contract, all of its rows (one tool may front many bound rows, see
    // [`crate::collapse`]).
    let groups = tool_groups(kernel.select_actions(&query), false);
    let Some(group) = groups.into_iter().find(|g| g.name == name) else {
        // Absence has two causes and the distinction IS the diagnosis: re-select
        // without the capability filter to tell them apart. Rows that exist
        // unrestricted were withheld by the grant; rows gone even unrestricted
        // have left the manifold — an unbound endpoint or an unreachable mounted
        // peer — and blaming the capability there sends the caller debugging
        // grants while a peer is down (the 2026-08-09 incident: a dev-server
        // bounce read as a grant problem for a whole session).
        //
        // TRADE, MADE KNOWINGLY: a truthful message is necessarily an informative
        // one, so "denied" now confirms the tool EXISTS above the caller's grant —
        // an existence oracle the old always-blame-the-capability wording did not
        // give. Acceptable HERE because this face is the local stdio projection and
        // the caller already holds a named grant. It stops being acceptable the
        // moment this manifold is projected to a peer we would not tell what we
        // hold: then the denied branch must fall back to the absent wording, so
        // both answers reveal the same thing. Affordance = authorization means a
        // denial should ideally be unreachable; this is a diagnosis for a caller we
        // trust, not a hint for one we don't.
        let offered = tool_groups(
            kernel.select_actions(&ikigai_core::ActionQuery::default()),
            false,
        )
        .iter()
        .any(|g| g.name == name);
        return tool_error(if offered {
            format!("tool `{name}` is not available under this capability")
        } else {
            format!(
                "tool `{name}` is not in the manifold — no bound endpoint answers to it \
                 (a mounted peer may be unreachable, or the tool list is stale)"
            )
        });
    };

    // The same ambiguity `tools/list` refuses to project, refused again on the way in —
    // both sides compute it from the rows, so a name that is not offered is not routed
    // either. A loud error here is strictly better than a silent pick by precedence: the
    // caller named a tool, and two endpoints answer to that name.
    if let Some(ids) = &group.ambiguous {
        return tool_error(format!(
            "`{name}` is ambiguous — {} endpoint ids project to it ({}); it is not offered \
             in tools/list and cannot be routed. Rename one of them.",
            ids.len(),
            ids.join(", ")
        ));
    }
    let rows = group.rows;

    // Exact IRI or URI-template pattern alike — the contract comes back either
    // way; the substituted target is IRI-checked below, after binding args land.
    let Some(description) = kernel.describe_pattern(&rows[0].endpoint) else {
        return tool_error(format!(
            "endpoint `{}` no longer resolves",
            rows[0].endpoint
        ));
    };
    let Some(action) = description
        .action_specs()
        .into_iter()
        .find(|a| a.verb == verb)
    else {
        return tool_error(format!("`{id}` declares no {verb:?} action"));
    };

    // Collapse the same-named rows exactly as `tools/list` projected them, then
    // route this call to the single row its arguments select — the supplied
    // binding arguments pick the calling shape (path present → the templated
    // row, absent → the concrete one) and a synthesized selector value (`repo`)
    // picks the row within it. An argument no row can absorb, or a selector
    // value naming no row, is a loud error — never a silent drop.
    let patterns: Vec<String> = rows.iter().map(|m| m.endpoint.clone()).collect();
    let declared: Vec<String> = action.inputs.iter().map(|i| i.name.clone()).collect();
    let shape = crate::collapse(&patterns, &declared);
    let empty = serde_json::Map::new();
    let args_map = arguments.as_object().unwrap_or(&empty);
    // Every reader below takes an argument through `scalar`, which answers `None` for an
    // array or an object exactly as it does for an absent key. So refuse a non-scalar
    // value by name HERE, before anything reads it as missing: as a selector it was
    // misreported as "required", and as an optional binding it was dropped and the call
    // answered another resource. `null` stays what a JSON client means by it: not given.
    let named = action
        .inputs
        .iter()
        .map(|i| i.name.as_str())
        .chain(shape.synthesized.iter().map(|a| a.name.as_str()));
    //
    // A LIST argument (ledger #1547) is the one exception: it takes an ARRAY of scalars,
    // which is joined below with its separator's canonical character, exactly as the engine
    // joins `graph=A graph=B`.
    let is_list = |arg: &str| {
        action
            .inputs
            .iter()
            .any(|i| i.name == arg && i.list.is_some())
    };
    for arg in named {
        match args_map.get(arg) {
            Some(Value::Array(items)) if is_list(arg) => {
                if items
                    .iter()
                    .any(|item| matches!(item, Value::Array(_) | Value::Object(_)))
                {
                    return tool_error(format!(
                        "`{arg}` is a list of values (strings, numbers or booleans), and an \
                         item of it is not one"
                    ));
                }
            }
            Some(value @ (Value::Array(_) | Value::Object(_))) => {
                let kind = if value.is_array() {
                    "an array"
                } else {
                    "an object"
                };
                return tool_error(format!(
                    "`{arg}` takes one value (a string, number or boolean), not {kind}"
                ));
            }
            _ => {}
        }
    }
    let supplied: std::collections::BTreeSet<String> = action
        .inputs
        .iter()
        .filter(|i| i.source == ikigai_core::InputSource::Binding)
        .filter(|i| args_map.get(&i.name).and_then(crate::scalar).is_some())
        .map(|i| i.name.clone())
        .collect();
    let mut target = match shape.route(name, &supplied, args_map) {
        Ok(pattern) => pattern.to_string(),
        Err(reason) => return tool_error(reason),
    };
    // The synthesized selector arguments were consumed by routing; the action's
    // declared contract knows nothing of them, so validate the remainder.
    let mut endpoint_arguments = arguments.clone();
    if let Some(map) = endpoint_arguments.as_object_mut() {
        for arg in &shape.synthesized {
            map.remove(&arg.name);
        }
    }

    // Route each supplied argument: a Binding-source input substitutes into the
    // endpoint IRI template ({name} → value); an Argument-source input becomes a
    // request argument.
    //
    // Pre-flight the JSON arguments against the action's declared contract with core's one
    // checker (structured, so a value with a newline/& validates correctly). A
    // non-conforming call comes back as the SHACL report — data the model reads
    // and repairs from — without touching the endpoint.
    if let Some(report) = crate::validate_arguments(&description, &action, &endpoint_arguments) {
        return tool_error(format!("arguments failed validation:\n{report}"));
    }
    // One value per name: a list's array joined with its separator (ledger #1547). The
    // checker above has refused every other repeat, so this cannot fail on a call it passed.
    let joined = match action.join_repeats(&crate::proposed_args(&endpoint_arguments)) {
        Ok(joined) => joined,
        Err(e) => return tool_error(format!("{e}")),
    };
    let mut req_args: Vec<(String, String)> = Vec::new();
    // On an ENVELOPE action the fields a caller gave are serialized into the carrier, as
    // one JSON object: the body the endpoint reads (ledger #358). The checker has refused a
    // call that gives both the carrier and fields.
    let carrier = crate::envelope_carrier(&action);
    let mut fields = serde_json::Map::new();
    // Bindings whose value carries IRI structure (RFC 3986's gen-delims): such a value can
    // turn the row's template into ANOTHER endpoint's IRI, so the target is checked below to
    // still reach this tool's endpoint (ledger #86). Delimiters themselves are legitimate,
    // since `urn:file:{path}` and `urn:repo:{repo}:file:{path}` take `/` and `:`; what is
    // refused is a call answered by an endpoint the tool does not name.
    let mut structural: Vec<&str> = Vec::new();
    for (name, value) in joined.pairs() {
        let input = action.inputs.iter().find(|i| i.name == name);
        match input {
            Some(input) if input.source == ikigai_core::InputSource::Binding => {
                if value.contains([':', '/', '?', '#', '[', ']', '@']) {
                    structural.push(&input.name);
                }
                target = target.replace(&format!("{{{}}}", input.name), value);
            }
            Some(input) if carrier.is_some_and(|c| c != input.name) => {
                fields.insert(input.name.clone(), Value::String(value.to_string()));
            }
            // A declared argument, or (on an OPEN argument set, which the checker admitted)
            // any other name: a request argument either way.
            _ => req_args.push((name.to_string(), value.to_string())),
        }
    }
    if let (Some(carrier), false) = (carrier, fields.is_empty()) {
        req_args.push((carrier.to_string(), Value::Object(fields).to_string()));
    }

    // An OMITTED optional binding leaves its `{var}` in the row's pattern, and the literal
    // template is no IRI (ledger #886: `urn:iki:ledger:{ledger}:append` reached Hermes as "not
    // a valid IRI"). The contract says what omission means: a declared default is filled in;
    // without one, the variable's whole `:`-segment is dropped (the bare spelling a
    // ledger or an annotation binds by), and the shorter IRI must still reach THIS endpoint;
    // anything else is refused by name rather than issued.
    let pattern = target.clone();
    let mut dropped: Vec<&str> = Vec::new();
    for input in &action.inputs {
        let token = format!("{{{}}}", input.name);
        if input.source != ikigai_core::InputSource::Binding || !target.contains(&token) {
            continue;
        }
        if let Some(default) = &input.default {
            target = target.replace(&token, default);
        } else if let Some(shorter) = crate::drop_segment(&target, &input.name) {
            target = shorter;
            dropped.push(&input.name);
        } else {
            return tool_error(format!(
                "`{}` was omitted, and `{pattern}` has no spelling without it: give `{}`",
                input.name, input.name
            ));
        }
    }

    // Invoke.
    let Ok(target_iri) = Iri::parse(&target) else {
        return tool_error(format!("target `{target}` is not a valid IRI"));
    };
    if !dropped.is_empty() || !structural.is_empty() {
        let reached = kernel.describe(&target_iri).map(|d| d.id);
        if reached.as_deref() != Some(description.id.as_str()) {
            let names = |names: &[&str]| {
                names
                    .iter()
                    .map(|n| format!("`{n}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let which = match reached {
                Some(other) => format!("names a different endpoint (`{other}`)"),
                None => "names nothing".to_string(),
            };
            if !dropped.is_empty() {
                let names = names(&dropped);
                return tool_error(format!(
                    "{names} omitted: without it `{pattern}` becomes `{target}`, which {which}; give {names}"
                ));
            }
            return tool_error(format!(
                "{}: the value makes `{target}`, which {which}, not `{id}`'s; a value of this tool \
                 cannot address another endpoint",
                names(&structural)
            ));
        }
    }
    let mut request = Request::new(verb, target_iri);
    for (k, v) in req_args {
        request = request.with_arg(k, ArgRef::Inline(v.into_bytes()));
    }
    // `principal` is never the CLIENT's to name (ledger #1830): the door stamps the one its
    // session capability carries (minted by `ikigai mcp --principal`), or removes it, the rule
    // every door that builds a request applies.
    ikigai_resolve::stamp_principal(&mut request, capability.principal());
    match block_on(kernel.issue(request, capability)) {
        Ok(repr) => tool_text(String::from_utf8_lossy(&repr.bytes).into_owned()),
        Err(e) => tool_error(kernel_failure(&e)),
    }
}

/// The text a tool result carries for a kernel error (ledger #1546): core's own display,
/// then one line naming the `kind` and the failure `class`, and the delay in whole
/// milliseconds for a `RetryAfter`, so an agent reads "retry-after, 30000 ms" rather than
/// parsing prose. It rides in the text because the protocol version this server declares
/// (2024-11-05) gives a tool result no structured slot (`structuredContent` arrives with
/// 2025-06-18; adopting it is a protocol move, not this change).
///
/// ```
/// use std::time::Duration;
/// use ikigai_core::Error;
///
/// let limited = Error::RetryAfter { delay: Some(Duration::from_secs(30)), detail: "5 per minute".into() };
/// assert_eq!(
///     ikigai_mcp::server::kernel_failure(&limited),
///     "retry after 30000 ms: 5 per minute\nkind: retry-after; class: retry-after; retry-after-ms: 30000"
/// );
/// assert_eq!(
///     ikigai_mcp::server::kernel_failure(&Error::Denied("needs urn:cap:x".into())),
///     "denied: needs urn:cap:x\nkind: denied; class: denied"
/// );
/// ```
pub fn kernel_failure(e: &ikigai_core::Error) -> String {
    let mut text = format!("{e}\nkind: {}; class: {}", e.kind(), e.class().word());
    if let Some(millis) = e.retry_after_millis() {
        text.push_str(&format!("; retry-after-ms: {millis}"));
    }
    text
}

fn tool_text(text: String) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": false })
}

fn tool_error(message: String) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}

/// The stdin→stdout loop: read newline-delimited JSON-RPC, dispatch, write each
/// response as one line. Runs until stdin closes. See [`serve_io`].
pub fn serve(kernel: &Kernel, capability: &Capability) -> std::io::Result<()> {
    serve_io(
        kernel,
        capability,
        std::io::stdin().lock(),
        std::io::stdout(),
    )
}

/// [`serve`] over any line source and sink: [`serve_concurrent`] under one fixed capability,
/// with no tool filter and [`MAX_CONCURRENT_CALLS`]. Every line goes through the same dispatch
/// as [`handle_line`], so a line that is not JSON — invalid UTF-8 included — is answered with
/// `-32700` and the loop goes on; it neither ends the session nor passes in silence.
pub fn serve_io(
    kernel: &Kernel,
    capability: &Capability,
    input: impl std::io::BufRead,
    output: impl std::io::Write + Send,
) -> std::io::Result<()> {
    let filter = ToolFilter::default(); // allow-all: the plain server shows the full grant
    serve_concurrent(
        kernel,
        || (capability.clone(), filter.clone()),
        input,
        &Mutex::new(output),
        MAX_CONCURRENT_CALLS,
    )
}

/// The most `tools/call` requests one MCP session runs at once (ledger #1695), the bound a QUIC
/// door puts on one connection's calls. A call past it is refused at once with
/// [`SERVER_BUSY`] under its own `id`, never queued: a queued call would wait behind long polls
/// with nothing telling the client why, which is the stall the concurrency exists to end.
pub const MAX_CONCURRENT_CALLS: usize = 16;

/// JSON-RPC 2.0 §5.1 leaves -32000 to -32099 to the server: this one answers a `tools/call`
/// that arrives while the session's bound of calls is already running. Transient: the same
/// call is admitted once one of the running calls has answered.
pub const SERVER_BUSY: i64 = -32000;

/// JSON-RPC 2.0 §5.1: the server failed while handling a valid request. Here, a `tools/call`
/// whose thread could not start or panicked: answered, so its `id` is never left hanging.
pub const INTERNAL_ERROR: i64 = -32603;

/// **The loop of an MCP stdio session, with `tools/call`s run concurrently** (ledger #1695).
///
/// - Each `tools/call` runs on its own thread, under the capability `session` gave when its line
///   was READ, and its response is written when it finishes. Responses to calls therefore come
///   back in the order the calls finish, not the order they arrived, which JSON-RPC allows:
///   a client matches a response by `id`.
/// - Everything else (`initialize`, `ping`, `tools/list`, an invalid line, a notification) is
///   answered on the reading thread before the next line is read, so those keep their order
///   relative to each other and to what came before them.
/// - Every response is ONE line, written and flushed whole under `output`'s lock, which a host
///   shares with anything else that writes to the client (the grants poller's
///   `notifications/tools/list_changed`).
/// - At most `max_calls` calls run at once. Past that a call is refused AT ONCE with
///   [`SERVER_BUSY`] under its own `id`, `data` naming the bound; it is never queued.
/// - At the end of input the loop still waits for every running call and writes its answer.
///
/// `session` is asked once per line, on the reading thread, for the capability and tool filter
/// in force, so a host that swaps its grant while running is honored from the next line on.
///
/// ```
/// # use ikigai_core::{Capability, EndpointSpace, Kernel};
/// # use ikigai_mcp::{server::serve_concurrent, ToolFilter};
/// # let kernel = Kernel::new(std::sync::Arc::new(EndpointSpace::new()));
/// let session = || (Capability::root(), ToolFilter::default());
/// let call = br#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"x__source"}}"#;
/// let output = std::sync::Mutex::new(Vec::new());
/// // A bound of 0 refuses every call: the busy answer, under the call's id.
/// serve_concurrent(&kernel, session, &call[..], &output, 0).unwrap();
/// let reply: serde_json::Value = serde_json::from_slice(&output.into_inner().unwrap()).unwrap();
/// assert_eq!(reply["id"], 5);
/// assert_eq!(reply["error"]["code"], -32000);
/// assert_eq!(reply["error"]["message"], "Server busy");
/// assert!(reply["error"]["data"].as_str().unwrap().contains("0 tools/call"));
/// ```
pub fn serve_concurrent<W: std::io::Write + Send>(
    kernel: &Kernel,
    session: impl Fn() -> (Capability, ToolFilter),
    mut input: impl std::io::BufRead,
    output: &Mutex<W>,
    max_calls: usize,
) -> std::io::Result<()> {
    let running = AtomicUsize::new(0);
    // A call's thread that could not write: the client has gone. The reading thread stops at
    // the next line rather than serving nobody.
    let gone: Mutex<Option<std::io::Error>> = Mutex::new(None);
    std::thread::scope(|scope| {
        let mut line = Vec::new();
        loop {
            if let Some(e) = lock(&gone).take() {
                return Err(e);
            }
            line.clear();
            if input.read_until(b'\n', &mut line)? == 0 {
                // End of input: the scope joins every running call, which writes its answer.
                return Ok(());
            }
            let (capability, filter) = session();
            let msg = match parse_line(&line) {
                Parsed::Blank => continue,
                Parsed::Unparsable(reply) => {
                    write_line(output, &reply)?;
                    continue;
                }
                Parsed::Repeated(msg, path) => {
                    if let Some(reply) = refuse_repeated(&msg, &path) {
                        write_line(output, &reply)?;
                    }
                    continue;
                }
                Parsed::Message(msg) => msg,
            };
            let id = match shape(&msg) {
                Shape::Request {
                    id,
                    method: "tools/call",
                } => id,
                _ => {
                    if let Some(reply) = handle(kernel, &capability, &filter, &msg) {
                        write_line(output, &reply)?;
                    }
                    continue;
                }
            };
            if running.fetch_add(1, Ordering::AcqRel) >= max_calls {
                running.fetch_sub(1, Ordering::AcqRel);
                let detail = format!(
                    "{max_calls} tools/call requests are already running, the bound of one MCP \
                     session; this one was refused at once, not queued: send it again when one \
                     of them has answered"
                );
                write_line(output, &err(id, SERVER_BUSY, "Server busy", Some(&detail)))?;
                continue;
            }
            let slot = Slot(&running);
            let (gone, reply_id) = (&gone, id.clone());
            let spawned = std::thread::Builder::new()
                .name("ikigai-mcp-call".to_string())
                .spawn_scoped(scope, move || {
                    let _slot = slot; // freed after the answer is written, never before
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        tools_call(kernel, &capability, msg.get("params"))
                    }));
                    let reply = match result {
                        Ok(result) => ok(reply_id, result),
                        Err(panic) => {
                            let why = panic
                                .downcast_ref::<&str>()
                                .map(|s| s.to_string())
                                .or_else(|| panic.downcast_ref::<String>().cloned())
                                .unwrap_or_else(|| "a panic".to_string());
                            err(
                                reply_id,
                                INTERNAL_ERROR,
                                "Internal error",
                                Some(&format!("the call panicked: {why}")),
                            )
                        }
                    };
                    if let Err(e) = write_line(output, &reply) {
                        lock(gone).get_or_insert(e);
                    }
                });
            if let Err(e) = spawned {
                // The closure (and its slot) was dropped unrun: answer here instead.
                let detail = format!("the call's thread could not start: {e}");
                write_line(
                    output,
                    &err(id, INTERNAL_ERROR, "Internal error", Some(&detail)),
                )?;
            }
        }
    })
}

/// One running call's place under the bound, given back when it drops (after the answer is
/// written, or on unwind).
struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A poisoned lock still guards bytes that were written whole or not at all: carry on.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One response, one line, written and flushed whole under the output's lock.
fn write_line<W: std::io::Write>(output: &Mutex<W>, reply: &Value) -> std::io::Result<()> {
    let text = serde_json::to_string(reply)?;
    let mut out = lock(output);
    writeln!(out, "{text}")?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::{
        ArgSpec, Description, EndpointSpace, Exact, FnEndpoint, ReprType, Representation, Verb,
    };
    use std::sync::Arc;

    // A tiny echo-like endpoint: Source reads `in`, returns it wrapped, and
    // requires a capability so we can watch the manifold shrink.
    /// The tools that are the MODULE's, i.e. everything but the kernel's own operations.
    ///
    /// Since ikigai-core 0.1.67 the kernel projects `kernel-actions` and `kernel-validate`
    /// to an agent holding no inspect grant (the selection funnel's deterministic stages),
    /// and more of its operations to one that does. A test about what a MODULE offers
    /// therefore has to say so rather than count the whole list.
    fn module_tools(tools: &[serde_json::Value]) -> Vec<&serde_json::Value> {
        tools
            .iter()
            .filter(|t| {
                !t["name"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("kernel-")
            })
            .collect()
    }

    /// The kernel operations in a tool list, by name, in order.
    fn kernel_ops(tools: &[serde_json::Value]) -> Vec<String> {
        tools
            .iter()
            .filter_map(|t| t["name"].as_str())
            .filter(|n| n.starts_with("kernel-"))
            .map(str::to_string)
            .collect()
    }

    fn kernel() -> Kernel {
        let echo = FnEndpoint::new("echo", |inv| {
            let text = inv.inline_str("in").unwrap_or("");
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!("[{text}]").into_bytes(),
            ))
        })
        .with_description(
            Description::new("echo")
                .verb(Verb::Source)
                .requires("urn:cap:demo:echo")
                .input(ArgSpec::new("in").summary("the text")),
        );
        let space = EndpointSpace::new().bind(Exact::new("urn:demo:echo"), echo);
        Kernel::new(Arc::new(space))
    }

    /// An endpoint with an OPTIONAL by-value argument, echoing what reached it.
    fn pick_kernel() -> Kernel {
        let pick = FnEndpoint::new("pick", |inv| {
            let graph = inv.inline_str("graph").unwrap_or("-");
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!("graph={graph}").into_bytes(),
            ))
        })
        .with_description(
            Description::new("pick")
                .verb(Verb::Source)
                .input(ArgSpec::new("graph").optional().summary("one graph")),
        );
        Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:demo:pick"), pick),
        ))
    }

    /// An endpoint over the ArgSpec shape (ledger #1547) that echoes what it was handed: a
    /// LIST `graph` beside a plain `query` (Source), an OPEN `compose` whose extra names are
    /// template arguments (Source), and an ENVELOPE `submit` whose fields arrive inside
    /// `content` (Sink).
    fn shape_kernel() -> Kernel {
        use ikigai_core::ListSeparator;
        let arg = |inv: &ikigai_core::Invocation<'_>, name: &str| {
            inv.inline_str(name).unwrap_or("-").to_string()
        };
        let graphs = FnEndpoint::new("graphs", move |inv| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!("graph={} query={}", arg(inv, "graph"), arg(inv, "query")).into_bytes(),
            ))
        })
        .with_description(
            Description::new("graphs")
                .verb(Verb::Source)
                .input(
                    ArgSpec::new("graph")
                        .optional()
                        .list(ListSeparator::CommaOrWhitespace),
                )
                .input(ArgSpec::new("query").optional()),
        );
        let compose = FnEndpoint::new("compose", move |inv| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!("src={} title={}", arg(inv, "src"), arg(inv, "title")).into_bytes(),
            ))
        })
        .with_description(
            Description::new("compose")
                .verb(Verb::Source)
                .input(ArgSpec::new("src"))
                .open_arguments("each fills a {name} marker in the body"),
        );
        let submit = FnEndpoint::new("submit", move |inv| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!("content={}", arg(inv, "content")).into_bytes(),
            ))
        })
        .with_description(
            Description::new("submit")
                .verb(Verb::Sink)
                .input(ArgSpec::new("email"))
                .input(ArgSpec::new("note").optional())
                .input(ArgSpec::new("content"))
                .envelope("content"),
        );
        Kernel::new(Arc::new(
            EndpointSpace::new()
                .bind(Exact::new("urn:demo:graphs"), graphs)
                .bind(Exact::new("urn:demo:compose"), compose)
                .bind(Exact::new("urn:demo:submit"), submit),
        ))
    }

    fn call_text(k: &Kernel, tool: &str, arguments: Value) -> (bool, String) {
        let reply = handle(
            k,
            &Capability::root(),
            &ToolFilter::default(),
            &json!({"jsonrpc":"2.0","id":9,"method":"tools/call",
                    "params":{"name": tool, "arguments": arguments}}),
        )
        .unwrap();
        let result = &reply["result"];
        (
            result["isError"].as_bool().unwrap_or(false),
            result["content"][0]["text"]
                .as_str()
                .unwrap_or("")
                .to_string(),
        )
    }

    /// ledger #1547: a LIST argument takes a JSON array, joined on the way in with its
    /// separator's canonical character, so `["A","B"]` reaches the endpoint as the engine's
    /// `graph=A graph=B` does; an array for a non-list argument is still refused by name.
    #[test]
    fn a_list_argument_takes_an_array_and_joins_it() {
        let k = shape_kernel();
        assert_eq!(
            call_text(&k, "graphs__source", json!({"graph": ["urn:a", "urn:b"]})),
            (false, "graph=urn:a,urn:b query=-".to_string())
        );
        assert_eq!(
            call_text(&k, "graphs__source", json!({"graph": "urn:a urn:b"})),
            (false, "graph=urn:a urn:b query=-".to_string()),
            "the joined spelling is the caller's own"
        );
        let (error, text) = call_text(&k, "graphs__source", json!({"query": ["a", "b"]}));
        assert!(error && text.contains("`query` takes one value"), "{text}");
        let (error, text) = call_text(&k, "graphs__source", json!({"graph": [["urn:a"]]}));
        assert!(error && text.contains("an item of it is not one"), "{text}");
        // The schema says so.
        let list = handle(
            &k,
            &Capability::root(),
            &ToolFilter::default(),
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .unwrap();
        let tool = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "graphs__source")
            .unwrap()
            .clone();
        assert_eq!(tool["inputSchema"]["properties"]["graph"]["type"], "array");
        assert_eq!(tool["inputSchema"]["additionalProperties"], json!(false));
    }

    /// ledger #1547 (#607): an OPEN action passes the names it does not declare through as
    /// request arguments, where a closed one refuses them in the report.
    #[test]
    fn an_open_action_passes_unknown_names_through() {
        let k = shape_kernel();
        assert_eq!(
            call_text(
                &k,
                "compose__source",
                json!({"src": "urn:x", "title": "Hi"})
            ),
            (false, "src=urn:x title=Hi".to_string())
        );
        let (error, text) = call_text(&k, "graphs__source", json!({"title": "Hi"}));
        assert!(error && text.contains("unknown argument `title`"), "{text}");
    }

    /// ledger #1547 (#358): an ENVELOPE action's fields are serialized into its carrier, as
    /// one JSON object, so a client fills the form and the endpoint reads the body it reads;
    /// a required field missing is refused by the checker before anything runs.
    #[test]
    fn an_envelope_actions_fields_are_serialized_into_its_carrier() {
        let k = shape_kernel();
        assert_eq!(
            call_text(
                &k,
                "submit__sink",
                json!({"email": "a@example.org", "note": "hello"})
            ),
            (
                false,
                r#"content={"email":"a@example.org","note":"hello"}"#.to_string()
            )
        );
        let (error, text) = call_text(&k, "submit__sink", json!({"note": "hello"}));
        assert!(
            error && text.contains("required input `email` is missing"),
            "{text}"
        );
    }

    const GIVEN_TWICE_TEXT: &str =
        "invalid argument `graph`: given twice; an argument takes one value, so name it once";

    /// ledger #387, the MCP spelling of a repeat: a JSON object naming `graph` twice. It
    /// parsed LAST-WINS and the call answered `graph=B` as if nothing were wrong; now it is a
    /// tool error naming the argument, through `handle_line` and the stdio loop alike.
    #[test]
    fn a_tool_argument_given_twice_is_refused_by_name() {
        let line = br#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"pick__source","arguments":{"graph":"A","graph":"B"}}}"#;
        let (cap, filter) = (Capability::root(), ToolFilter::default());
        let reply = handle_line(&pick_kernel(), &cap, &filter, line).unwrap();
        assert_eq!(reply["id"], 4, "{reply}");
        assert_eq!(reply["result"]["isError"], true, "{reply}");
        assert_eq!(reply["result"]["content"][0]["text"], GIVEN_TWICE_TEXT);

        let mut out = Vec::new();
        let input = [&line[..], b"\n"].concat();
        serve_io(&pick_kernel(), &cap, &input[..], &mut out).unwrap();
        let reply: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(reply["result"]["content"][0]["text"], GIVEN_TWICE_TEXT);

        // Named once, the call is untouched.
        let once = br#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"pick__source","arguments":{"graph":"A"}}}"#;
        let reply = handle_line(&pick_kernel(), &cap, &filter, once).unwrap();
        assert_eq!(reply["result"]["content"][0]["text"], "graph=A", "{reply}");
    }

    /// ledger #387: a repeated member outside `arguments` makes the message itself ambiguous,
    /// so it is `-32600` naming the member; a repeated `id` answers under `null`.
    #[test]
    fn a_repeated_member_elsewhere_is_an_invalid_request() {
        let (cap, filter) = (Capability::root(), ToolFilter::default());
        let reply = handle_line(
            &pick_kernel(),
            &cap,
            &filter,
            br#"{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}"#,
        )
        .unwrap();
        assert_eq!(reply["id"], Value::Null, "{reply}");
        assert_eq!(reply["error"]["code"], INVALID_REQUEST, "{reply}");
        assert!(
            reply["error"]["data"]
                .as_str()
                .is_some_and(|d| d.contains("member `id` is given twice")),
            "{reply}"
        );
        let reply = handle_line(
            &pick_kernel(),
            &cap,
            &filter,
            br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"pick__source","name":"pick__source","arguments":{}}}"#,
        )
        .unwrap();
        assert_eq!(reply["id"], 3, "{reply}");
        assert_eq!(reply["error"]["code"], INVALID_REQUEST, "{reply}");
        assert!(
            reply["error"]["data"]
                .as_str()
                .is_some_and(|d| d.contains("member `params.name` is given twice")),
            "{reply}"
        );
        // A notification is never answered, a repeat or not.
        assert!(handle_line(
            &pick_kernel(),
            &cap,
            &filter,
            br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{"a":1,"a":2}}"#,
        )
        .is_none());
    }

    #[test]
    fn initialize_reports_tool_capability() {
        let k = kernel();
        let cap = Capability::root();
        let resp = handle(
            &k,
            &cap,
            &ToolFilter::default(),
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
        )
        .unwrap();
        assert_eq!(resp["result"]["serverInfo"]["name"], "ikigai");
        assert_eq!(resp["result"]["capabilities"]["tools"]["listChanged"], true);
    }

    #[test]
    fn notifications_get_no_reply() {
        let k = kernel();
        let cap = Capability::root();
        assert!(handle(
            &k,
            &cap,
            &ToolFilter::default(),
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .is_none());
    }

    #[test]
    fn tools_list_is_capability_scoped() {
        let k = kernel();
        // With the echo cap: the tool is present.
        let held = Capability::scoped(["urn:cap:demo:echo"]);
        let resp = handle(
            &k,
            &held,
            &ToolFilter::default(),
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        // ★ The kernel's OWN operations project too, and since `ikigai-core` 0.1.67 two of
        // them reach an agent holding no inspect grant at all: `kernel-actions` and
        // `kernel-validate`, the two deterministic stages of the selection funnel. That is
        // right — an agent that cannot see the narrowing step cannot narrow — but it means a
        // tool list is never only the module's, so every count here is over the module's own
        // rows. The funnel pair is PINNED rather than filtered away silently: if core stops
        // projecting it, an agent's menu quietly loses the thing that makes it navigable.
        assert_eq!(
            kernel_ops(tools),
            ["kernel-actions__source", "kernel-validate__source"],
            "the funnel projects to a scoped agent: {tools:?}"
        );
        let mine = module_tools(tools);
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0]["name"], "echo__source");
        assert_eq!(mine[0]["inputSchema"]["properties"]["in"]["type"], "string");

        // Without it: the manifold is empty — affordance equals authorization.
        let bare = Capability::scoped(["urn:cap:unrelated"]);
        let resp = handle(
            &k,
            &bare,
            &ToolFilter::default(),
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        )
        .unwrap();
        assert_eq!(
            module_tools(resp["result"]["tools"].as_array().unwrap()).len(),
            0
        );
    }

    /// ★★ The tool name is an IDENTITY KEY and `sanitize_id` is LOSSY. One endpoint bound
    /// many ways collapses to one tool on purpose; two DIFFERENT endpoints whose ids
    /// differ only in punctuation collapse the same way and must not — the caller named a
    /// tool and selection precedence would decide which endpoint it reached.
    ///
    /// Refusing costs both endpoints their MCP face, which is the right side to fail on:
    /// an ambiguous name is not a usable tool, the operator is told exactly which two ids
    /// to rename, and every other face of the kernel still reaches them. A silent merge is
    /// the one outcome the caller cannot detect.
    #[test]
    fn two_endpoints_colliding_on_one_tool_name_are_refused_by_both_sides() {
        let ep = |id: &'static str| {
            FnEndpoint::new(id, |_inv| {
                Ok(Representation::new(ReprType::new("text/plain"), Vec::new()))
            })
            .with_description(Description::new(id).verb(Verb::Source))
        };
        // `llm:config` and `llm.config` both sanitize to `llm_config`.
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:demo:one"), ep("llm:config"))
            .bind(Exact::new("urn:demo:two"), ep("llm.config"));
        let k = Kernel::new(Arc::new(space));
        let cap = Capability::root();

        let resp = handle(
            &k,
            &cap,
            &ToolFilter::default(),
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .unwrap();
        assert!(
            module_tools(resp["result"]["tools"].as_array().unwrap()).is_empty(),
            "an ambiguous name is not offered: {resp}"
        );

        // And the two sides agree: what is not listed is not routed either, with the
        // reason and both ids — never a pick by precedence.
        let resp = handle(
            &k,
            &cap,
            &ToolFilter::default(),
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
                    "params":{"name":"llm_config__source","arguments":{}}}),
        )
        .unwrap();
        assert_eq!(resp["result"]["isError"], true, "{resp}");
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("ambiguous"), "{text}");
        assert!(
            text.contains("llm.config") && text.contains("llm:config"),
            "{text}"
        );
    }

    /// A federated kernel lists a mounted namespace twice: under `--override`/
    /// `--prefer` the fronted mount's catalog AND the local space both carry the
    /// same endpoint. Resolution serves exactly one (the mount, by precedence),
    /// so the projection must offer exactly one tool — a duplicate name is at
    /// best confusing to an MCP client, at worst rejected outright.
    #[test]
    fn a_federated_duplicate_projects_one_tool() {
        let echo = |wrap: &'static str| {
            FnEndpoint::new("echo", move |inv| {
                let text = inv.inline_str("in").unwrap_or("");
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    format!("{wrap}{text}{wrap}").into_bytes(),
                ))
            })
            .with_description(
                Description::new("echo")
                    .verb(Verb::Source)
                    .input(ArgSpec::new("in").summary("the text")),
            )
        };
        // The same IRI bound in two composed spaces — the shape an override/prefer
        // mount produces (remote catalog fronted, local binding behind it).
        let root = ikigai_core::Fallback::new(vec![
            Arc::new(EndpointSpace::new().bind(Exact::new("urn:demo:echo"), echo("[")))
                as Arc<dyn ikigai_core::Space>,
            Arc::new(EndpointSpace::new().bind(Exact::new("urn:demo:echo"), echo("(")))
                as Arc<dyn ikigai_core::Space>,
        ]);
        let k = Kernel::new(Arc::new(root));
        let cap = Capability::root();
        let resp = handle(
            &k,
            &cap,
            &ToolFilter::default(),
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        let echoes: Vec<_> = tools
            .iter()
            .filter(|t| t["name"] == "echo__source")
            .collect();
        assert_eq!(
            echoes.len(),
            1,
            "one tool per name, not one per catalog row"
        );

        // And the call reaches the endpoint resolution serves: the FIRST space,
        // exactly as the fronted mount wins at resolution time.
        let resp = handle(
            &k,
            &cap,
            &ToolFilter::default(),
            &json!({
                "jsonrpc":"2.0","id":2,"method":"tools/call",
                "params": { "name": "echo__source", "arguments": { "in": "hi" } }
            }),
        )
        .unwrap();
        assert_eq!(resp["result"]["content"][0]["text"], "[hi[");
    }

    /// A template-bound endpoint (`urn:demo:echo/{message}`) has no exact IRI —
    /// its manifold row carries the pattern. `describe_pattern` still yields the
    /// contract, so it projects as a tool whose binding arg sits in the input
    /// schema; a call substitutes the arg into the IRI and resolves.
    #[test]
    fn a_template_bound_endpoint_projects_and_invokes() {
        use ikigai_core::{ActionSpec, UriTemplate};
        let echo = FnEndpoint::new("demo-echo", |inv| {
            let message = inv.bindings.get("message").unwrap_or("").to_string();
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!("echo: {message}").into_bytes(),
            ))
        })
        .with_description(
            Description::new("demo-echo").action(
                ActionSpec::new(Verb::Source)
                    .summary("echo the path segment back")
                    .input(ArgSpec::new("message").binding().summary("what to echo")),
            ),
        );
        let space =
            EndpointSpace::new().bind(UriTemplate::parse("urn:demo:echo/{message}").unwrap(), echo);
        let k = Kernel::new(Arc::new(space));
        let cap = Capability::root();

        // tools/list: the template action projects, binding arg in the schema.
        let resp = handle(
            &k,
            &cap,
            &ToolFilter::default(),
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        let tool = tools
            .iter()
            .find(|t| t["name"] == "demo-echo__source")
            .expect("a template-bound endpoint projects a tool");
        assert_eq!(
            tool["inputSchema"]["properties"]["message"]["type"],
            "string"
        );
        assert_eq!(tool["inputSchema"]["required"], json!(["message"]));

        // tools/call: the binding arg substitutes into the IRI and resolves.
        let resp = handle(
            &k,
            &cap,
            &ToolFilter::default(),
            &json!({
                "jsonrpc":"2.0","id":2,"method":"tools/call",
                "params": { "name": "demo-echo__source", "arguments": { "message": "hi" } }
            }),
        )
        .unwrap();
        assert_eq!(resp["result"]["isError"], false);
        assert_eq!(resp["result"]["content"][0]["text"], "echo: hi");
    }

    /// One endpoint bound once per configured root — the shape ikigai-browse's
    /// per-root manifold rows produce: `urn:repo:<root>:tree` (concrete) beside
    /// `urn:repo:<root>:tree:{path}` (templated), one pair per root. One tool
    /// must front all four rows and keep each reachable by call. The endpoint
    /// echoes its resolved target so a test can see which row a call reached.
    fn per_root_kernel() -> Kernel {
        use ikigai_core::{Endpoint, UriTemplate};
        let tree: Arc<dyn Endpoint> = Arc::new(
            FnEndpoint::new("tree", |inv| {
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    inv.request.target.as_str().as_bytes().to_vec(),
                ))
            })
            .with_description(
                Description::new("tree").verb(Verb::Source).input(
                    ArgSpec::new("path")
                        .binding()
                        .optional()
                        .summary("path within the root"),
                ),
            ),
        );
        let space = EndpointSpace::new()
            .bind_arc(Exact::new("urn:repo:alpha:tree"), Arc::clone(&tree))
            .bind_arc(
                UriTemplate::parse("urn:repo:alpha:tree:{path}").unwrap(),
                Arc::clone(&tree),
            )
            .bind_arc(Exact::new("urn:repo:beta:tree"), Arc::clone(&tree))
            .bind_arc(
                UriTemplate::parse("urn:repo:beta:tree:{path}").unwrap(),
                tree,
            );
        Kernel::new(Arc::new(space))
    }

    #[test]
    fn per_root_rows_collapse_to_one_tool_with_a_repo_enum() {
        let k = per_root_kernel();
        let cap = Capability::root();
        let resp = handle(
            &k,
            &cap,
            &ToolFilter::default(),
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        let trees: Vec<_> = tools
            .iter()
            .filter(|t| t["name"] == "tree__source")
            .collect();
        assert_eq!(trees.len(), 1, "one tool fronts every per-root row");
        let schema = &trees[0]["inputSchema"];
        // The collapsed root dimension comes back as a required enum argument…
        assert_eq!(
            schema["properties"]["repo"]["enum"],
            json!(["alpha", "beta"])
        );
        assert!(schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("repo")));
        // …beside the untouched declared contract.
        assert_eq!(schema["properties"]["path"]["type"], "string");
    }

    #[test]
    fn a_call_routes_to_the_row_its_arguments_select() {
        let k = per_root_kernel();
        let cap = Capability::root();
        let call = |args: Value| {
            handle(
                &k,
                &cap,
                &ToolFilter::default(),
                &json!({
                    "jsonrpc":"2.0","id":1,"method":"tools/call",
                    "params": { "name": "tree__source", "arguments": args }
                }),
            )
            .unwrap()["result"]
                .clone()
        };
        // repo alone → that root's concrete row.
        let resp = call(json!({ "repo": "beta" }));
        assert_eq!(resp["isError"], false);
        assert_eq!(resp["content"][0]["text"], "urn:repo:beta:tree");
        // repo + path → that root's templated row, path substituted.
        let resp = call(json!({ "repo": "alpha", "path": "src" }));
        assert_eq!(resp["isError"], false);
        assert_eq!(resp["content"][0]["text"], "urn:repo:alpha:tree:src");
        // An unknown repo is a loud error naming the bound values.
        let resp = call(json!({ "repo": "gamma", "path": "src" }));
        assert_eq!(resp["isError"], true);
        let text = resp["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("not a bound `repo`") && text.contains("alpha, beta"),
            "{text}"
        );
        // Omitting repo is a loud error too: several rows, no arbitrary winner.
        for args in [json!({}), json!({ "path": "src" })] {
            let resp = call(args);
            assert_eq!(resp["isError"], true);
            let text = resp["content"][0]["text"].as_str().unwrap();
            assert!(text.contains("`repo` is required"), "{text}");
        }
    }

    /// An argument the caller DID pass, as a JSON array or object, is refused by name —
    /// never read as absent. Read as absent, a non-scalar selector was reported as
    /// "`repo` is required" (a misdiagnosis: it was supplied), and a non-scalar optional
    /// binding was dropped, so the call answered a different resource than the one asked
    /// for (`urn:repo:alpha:tree` for a `path` the caller gave).
    #[test]
    fn a_non_scalar_argument_is_refused_by_name_not_read_as_absent() {
        let k = per_root_kernel();
        let cap = Capability::root();
        let call = |args: Value| {
            handle(
                &k,
                &cap,
                &ToolFilter::default(),
                &json!({
                    "jsonrpc":"2.0","id":1,"method":"tools/call",
                    "params": { "name": "tree__source", "arguments": args }
                }),
            )
            .unwrap()["result"]
                .clone()
        };
        for (args, name) in [
            (json!({ "repo": ["beta"] }), "repo"),
            (json!({ "repo": { "name": "beta" } }), "repo"),
            (json!({ "repo": "alpha", "path": ["src"] }), "path"),
        ] {
            let resp = call(args.clone());
            assert_eq!(resp["isError"], true, "{args}: {resp}");
            let text = resp["content"][0]["text"].as_str().unwrap();
            assert!(
                text.contains(&format!("`{name}` takes one value")),
                "{args}: {text}"
            );
            assert!(!text.contains("is required"), "{args}: {text}");
        }
        // `null` is how a JSON client says "not given": still absent, not refused.
        let resp = call(json!({ "repo": "beta", "path": null }));
        assert_eq!(resp["isError"], false, "{resp}");
        assert_eq!(resp["content"][0]["text"], "urn:repo:beta:tree");
    }

    /// A declared optional binding whose rows have no `{var}` for it (the
    /// browse state-family shape: concrete rows only) must error loudly when
    /// supplied — the pre-collapse projection silently dropped the argument
    /// and answered the wrong resource.
    #[test]
    fn a_binding_arg_no_row_absorbs_is_a_loud_error() {
        use ikigai_core::Endpoint;
        let state: Arc<dyn Endpoint> = Arc::new(
            FnEndpoint::new("state", |inv| {
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    inv.request.target.as_str().as_bytes().to_vec(),
                ))
            })
            .with_description(
                Description::new("state")
                    .verb(Verb::Source)
                    .input(ArgSpec::new("path").binding().optional()),
            ),
        );
        let space = EndpointSpace::new()
            .bind_arc(Exact::new("urn:repo:alpha:state"), Arc::clone(&state))
            .bind_arc(Exact::new("urn:repo:beta:state"), state);
        let k = Kernel::new(Arc::new(space));
        let cap = Capability::root();
        let resp = handle(
            &k,
            &cap,
            &ToolFilter::default(),
            &json!({
                "jsonrpc":"2.0","id":1,"method":"tools/call",
                "params": { "name": "state__source",
                            "arguments": { "repo": "alpha", "path": "src" } }
            }),
        )
        .unwrap();
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no bound row"), "{text}");
        assert!(text.contains("path"), "{text}");
    }

    /// A tool fronting exactly one row projects byte-identically to the plain
    /// per-action projection — the collapse machinery only shows where rows
    /// actually collapsed.
    #[test]
    fn a_single_row_tool_projects_byte_identically() {
        let k = kernel();
        let cap = Capability::scoped(["urn:cap:demo:echo"]);
        let resp = handle(
            &k,
            &cap,
            &ToolFilter::default(),
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .unwrap();
        let tool = &resp["result"]["tools"][0];
        let description = k.describe_pattern("urn:demo:echo").unwrap();
        let action = description
            .action_specs()
            .into_iter()
            .find(|a| a.verb == Verb::Source)
            .unwrap();
        assert_eq!(tool, &action_to_tool(&description, &action));
    }

    #[test]
    fn a_hide_filter_drops_an_authorized_tool_from_the_list() {
        let k = kernel();
        let held = Capability::scoped(["urn:cap:demo:echo"]);
        // The echo tool is authorized, but the visibility filter hides it by id —
        // authority unchanged, menu narrowed.
        let filter = ToolFilter {
            show: vec![],
            hide: vec!["echo".to_string()],
        };
        let resp = handle(
            &k,
            &held,
            &filter,
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .unwrap();
        assert_eq!(
            module_tools(resp["result"]["tools"].as_array().unwrap()).len(),
            0
        );

        // A show list that doesn't include echo hides it too; one that does keeps it.
        let only_other = ToolFilter {
            show: vec!["other".to_string()],
            hide: vec![],
        };
        let resp = handle(
            &k,
            &held,
            &only_other,
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        )
        .unwrap();
        assert_eq!(
            module_tools(resp["result"]["tools"].as_array().unwrap()).len(),
            0
        );
    }

    /// ledger #1284: an IRI-prefix `show` pattern projects only the tools bound under it,
    /// so an entry meant for a mounted namespace leaves out everything else the kernel
    /// offers, the kernel's own operations included. The authority is unchanged.
    #[test]
    fn an_iri_prefix_show_pattern_projects_only_the_tools_bound_under_it() {
        let k = kernel();
        let held = Capability::scoped(["urn:cap:demo:echo"]);
        let names = |filter: &ToolFilter| -> Vec<String> {
            let resp = handle(
                &k,
                &held,
                filter,
                &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            )
            .unwrap();
            resp["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|t| t["name"].as_str().map(str::to_string))
                .collect()
        };
        let all = names(&ToolFilter::default());
        assert!(
            all.iter().any(|n| n.starts_with("kernel-")),
            "unfiltered, the kernel's operations are listed beside echo: {all:?}"
        );
        for show in ["urn:demo:", "urn:demo:*", "urn:demo:echo"] {
            let only = ToolFilter {
                show: vec![show.to_string()],
                hide: vec![],
            };
            assert_eq!(names(&only), ["echo__source"], "show {show}");
        }
        let elsewhere = ToolFilter {
            show: vec!["urn:layer:".to_string()],
            hide: vec![],
        };
        assert!(names(&elsewhere).is_empty(), "nothing is bound there");
        // An IRI prefix in `hide` drops what is bound under it, and only that.
        let hidden = ToolFilter {
            show: vec![],
            hide: vec!["urn:demo:".to_string()],
        };
        let rest = names(&hidden);
        assert!(!rest.contains(&"echo__source".to_string()), "{rest:?}");
        assert_eq!(rest.len(), all.len() - 1, "{rest:?}");
    }

    #[test]
    fn tools_call_ignores_the_filter_authority_still_governs() {
        // A hidden tool is not a forbidden tool: the filter shapes the menu, not
        // the security boundary — a client that names it still invokes under cap.
        let k = kernel();
        let held = Capability::scoped(["urn:cap:demo:echo"]);
        let hide_all = ToolFilter {
            show: vec![],
            hide: vec!["*".to_string()],
        };
        let call = json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params": { "name": "echo__source", "arguments": { "in": "hi" } }
        });
        let resp = handle(&k, &held, &hide_all, &call).unwrap();
        assert_eq!(resp["result"]["isError"], false);
        assert_eq!(resp["result"]["content"][0]["text"], "[hi]");
    }

    #[test]
    fn tools_call_invokes_and_gates_on_capability() {
        let k = kernel();
        let held = Capability::scoped(["urn:cap:demo:echo"]);
        let call = json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params": { "name": "echo__source", "arguments": { "in": "hi" } }
        });
        let resp = handle(&k, &held, &ToolFilter::default(), &call).unwrap();
        assert_eq!(resp["result"]["isError"], false);
        assert_eq!(resp["result"]["content"][0]["text"], "[hi]");

        // The same call under a capability that doesn't hold the scope: the tool
        // is not in the manifold, so it can't be invoked.
        let bare = Capability::scoped(["urn:cap:unrelated"]);
        let resp = handle(&k, &bare, &ToolFilter::default(), &call).unwrap();
        assert_eq!(resp["result"]["isError"], true);
        assert!(resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("not available under this capability"));
    }

    /// A tool no manifold row backs at ALL — the shape a dead mounted peer
    /// leaves behind (its catalog vanishes, the client's tool roster doesn't) —
    /// must NOT be blamed on the capability: the caller holding the right grant
    /// would go debug grants while the peer is down. The message names absence.
    #[test]
    fn an_absent_tool_is_reported_as_absent_not_denied() {
        let k = kernel();
        let held = Capability::scoped(["urn:cap:demo:echo"]);
        let call = json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params": { "name": "ghost__source", "arguments": {} }
        });
        let resp = handle(&k, &held, &ToolFilter::default(), &call).unwrap();
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("not in the manifold"), "{text}");
        assert!(!text.contains("capability"), "{text}");
    }

    // ------------------------------------------------- ledger #886: omitted optional bindings

    /// A grammar for `{prefix}:{var}:{tail}` (or `{prefix}:{var}` when `tail` is empty) that
    /// ALSO matches the bare spelling with the variable's segment absent, the way
    /// `ikigai-ledger` (`urn:iki:ledger:append` = the `default` ledger) and `ikigai-browse`
    /// (`urn:iki:annotation` = mint an id) bind theirs. Advertises the template.
    struct BareOrNamed {
        prefix: &'static str,
        var: &'static str,
        tail: &'static str,
        bare_value: Option<&'static str>,
    }

    impl ikigai_core::Grammar for BareOrNamed {
        fn match_iri(&self, iri: &Iri) -> Option<ikigai_core::Bindings> {
            let rest = iri.as_str().strip_prefix(self.prefix)?;
            let mut bindings = ikigai_core::Bindings::new();
            let bare = if self.tail.is_empty() {
                rest.is_empty()
            } else {
                rest == format!(":{}", self.tail)
            };
            if bare {
                if let Some(value) = self.bare_value {
                    bindings.insert(self.var, value);
                }
                return Some(bindings);
            }
            let rest = rest.strip_prefix(':')?;
            let value = if self.tail.is_empty() {
                rest
            } else {
                rest.strip_suffix(&format!(":{}", self.tail))?
            };
            if value.is_empty() || value.contains(':') {
                return None;
            }
            bindings.insert(self.var, value);
            Some(bindings)
        }

        fn pattern(&self) -> String {
            if self.tail.is_empty() {
                format!("{}:{{{}}}", self.prefix, self.var)
            } else {
                format!("{}:{{{}}}:{}", self.prefix, self.var, self.tail)
            }
        }
    }

    /// An endpoint that answers with its target and the binding `var` it was handed.
    fn reporting(id: &str, var: &'static str, input: ArgSpec) -> FnEndpoint {
        FnEndpoint::new(id, move |inv| {
            let bound = inv.bindings.get(var).unwrap_or("-").to_string();
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!("{} {var}={bound}", inv.request.target.as_str()).into_bytes(),
            ))
        })
        .with_description(Description::new(id).verb(Verb::Sink).input(input))
    }

    fn call_tool(k: &Kernel, name: &str, arguments: serde_json::Value) -> serde_json::Value {
        handle(
            k,
            &Capability::root(),
            &ToolFilter::default(),
            &json!({
                "jsonrpc":"2.0","id":1,"method":"tools/call",
                "params": { "name": name, "arguments": arguments }
            }),
        )
        .unwrap()["result"]
            .clone()
    }

    /// ledger #886, the ledger shape: `{ledger}` is an optional binding with a DEFAULT, and
    /// the projection issued `urn:iki:ledger:{ledger}:append` literally when it was omitted
    /// ("not a valid IRI"). An omitted binding with a declared default is filled with it.
    #[test]
    fn an_omitted_binding_with_a_default_is_filled_with_it() {
        let ledger = ArgSpec::new("ledger")
            .binding()
            .optional()
            .default_value("default");
        let append = reporting("ledger-append", "ledger", ledger);
        let space = EndpointSpace::new().bind(
            BareOrNamed {
                prefix: "urn:demo:ledger",
                var: "ledger",
                tail: "append",
                bare_value: Some("default"),
            },
            append,
        );
        let k = Kernel::new(Arc::new(space));
        let omitted = call_tool(&k, "ledger-append__sink", json!({}));
        assert_eq!(omitted["isError"], false, "{omitted}");
        assert_eq!(
            omitted["content"][0]["text"],
            "urn:demo:ledger:default:append ledger=default"
        );
        let named = call_tool(&k, "ledger-append__sink", json!({ "ledger": "work" }));
        assert_eq!(
            named["content"][0]["text"],
            "urn:demo:ledger:work:append ledger=work"
        );
    }

    /// ledger #886, the annotation shape: `{id}` is optional with NO default, and the bare
    /// spelling (`urn:iki:annotation`) is what mints one. An omitted binding without a
    /// default drops its `:`-delimited segment, and the call reaches the same endpoint.
    #[test]
    fn an_omitted_binding_without_a_default_drops_its_segment() {
        let id = ArgSpec::new("id").binding().optional();
        let note = reporting("note", "id", id);
        let space = EndpointSpace::new().bind(
            BareOrNamed {
                prefix: "urn:demo:note",
                var: "id",
                tail: "",
                bare_value: None,
            },
            note,
        );
        let k = Kernel::new(Arc::new(space));
        let omitted = call_tool(&k, "note__sink", json!({}));
        assert_eq!(omitted["isError"], false, "{omitted}");
        assert_eq!(omitted["content"][0]["text"], "urn:demo:note id=-");
        let named = call_tool(&k, "note__sink", json!({ "id": "n1" }));
        assert_eq!(named["content"][0]["text"], "urn:demo:note:n1 id=n1");
    }

    /// The guard on dropping a segment: when the shorter IRI belongs to ANOTHER endpoint,
    /// the call is refused naming the variable, never answered by a resource the caller did
    /// not name.
    #[test]
    fn a_dropped_segment_that_reaches_another_endpoint_is_refused() {
        let v = ArgSpec::new("v").binding().optional();
        let named_only = reporting("named-only", "v", v);
        let other = reporting("other", "v", ArgSpec::new("unused").optional());
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:demo:x"), other)
            .bind(
                ikigai_core::UriTemplate::parse("urn:demo:x:{v}").unwrap(),
                named_only,
            );
        let k = Kernel::new(Arc::new(space));
        let resp = call_tool(&k, "named-only__sink", json!({}));
        assert_eq!(resp["isError"], true, "{resp}");
        let text = resp["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("`v`"), "{text}");
        assert!(
            !text.contains("v=-"),
            "never answered by another endpoint: {text}"
        );
    }

    /// ledger #86: a binding value is substituted into the row's template as it is, so a
    /// value carrying IRI structure (`alice:private`) can make the target a DIFFERENT
    /// endpoint's IRI, and a call to one tool was answered by another. Refused by name,
    /// exactly like a dropped segment that reaches another endpoint.
    #[test]
    fn a_binding_value_that_reaches_another_endpoint_is_refused() {
        let user = reporting("user", "name", ArgSpec::new("name").binding());
        let private = reporting("private", "name", ArgSpec::new("unused").optional());
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:demo:user:alice:private"), private)
            .bind(
                ikigai_core::UriTemplate::parse("urn:demo:user:{name}").unwrap(),
                user,
            );
        let k = Kernel::new(Arc::new(space));
        let resp = call_tool(&k, "user__sink", json!({ "name": "alice:private" }));
        assert_eq!(resp["isError"], true, "{resp}");
        let text = resp["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("`name`") && text.contains("`private`"),
            "{text}"
        );
        assert!(
            !text.contains("name=-"),
            "never answered by another endpoint: {text}"
        );
        // A plain value reaches the tool's own endpoint as before.
        let resp = call_tool(&k, "user__sink", json!({ "name": "alice" }));
        assert_eq!(resp["content"][0]["text"], "urn:demo:user:alice name=alice");
    }

    /// …and the guard is about WHICH endpoint answers, not about the characters: a value with
    /// `/` and `:` that the tool's own template carries (a file path, an IRI) still works,
    /// as `urn:file:{path}` and `urn:repo:{repo}:file:{path}` need it to.
    #[test]
    fn a_binding_value_with_delimiters_that_stays_on_its_endpoint_is_carried() {
        let file = reporting("file", "path", ArgSpec::new("path").binding());
        let space = EndpointSpace::new().bind(
            ikigai_core::UriTemplate::parse("urn:demo:file:{path}").unwrap(),
            file,
        );
        let k = Kernel::new(Arc::new(space));
        let resp = call_tool(&k, "file__sink", json!({ "path": "docs/a:b.md" }));
        assert_eq!(resp["isError"], false, "{resp}");
        assert_eq!(
            resp["content"][0]["text"],
            "urn:demo:file:docs/a:b.md path=docs/a:b.md"
        );
    }

    /// A variable that is not a whole `:`-segment cannot be dropped: refused by name.
    #[test]
    fn an_omitted_binding_inside_a_segment_is_refused_by_name() {
        let message = ArgSpec::new("message").binding().optional();
        let echo = reporting("slash-echo", "message", message);
        let space = EndpointSpace::new().bind(
            ikigai_core::UriTemplate::parse("urn:demo:echo/{message}").unwrap(),
            echo,
        );
        let k = Kernel::new(Arc::new(space));
        let resp = call_tool(&k, "slash-echo__sink", json!({}));
        assert_eq!(resp["isError"], true, "{resp}");
        let text = resp["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("`message`"), "{text}");
        assert!(!text.contains("not a valid IRI"), "{text}");
    }
}

/// Ledger #948 through the MCP face: a local `toUpper` and a peer's mounted at `urn:narrow:`
/// with a DIFFERENT contract (an extra optional `locale`). Ported from the hub's
/// reproduction, which showed ONE tool carrying the local schema, so the peer's copy was
/// unreachable: a call with `locale` was refused as an unknown argument.
#[cfg(test)]
mod manifold_identity_948 {
    use super::*;
    use ikigai_core::{
        ActionSpec, ArgSpec, Description, EndpointSpace, Exact, FnEndpoint, ReprType,
        Representation, Verb,
    };
    use std::sync::Arc;

    fn upper(tag: &'static str, extra: bool) -> FnEndpoint {
        let mut d = Description::new("toUpper")
            .verb(Verb::Source)
            .input(ArgSpec::new("in"));
        if extra {
            d = d.input(ArgSpec::new("locale").optional());
        }
        FnEndpoint::new("toUpper", move |_| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                tag.as_bytes().to_vec(),
            ))
        })
        .with_description(d)
    }

    fn call(k: &Kernel, tool: &str, args: Value) -> Value {
        let msg = json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":tool,"arguments":args}});
        handle(k, &Capability::root(), &ToolFilter::default(), &msg).unwrap()["result"].clone()
    }

    fn text(result: &Value) -> &str {
        result["content"][0]["text"].as_str().unwrap()
    }

    /// Ledger #1546: a kernel error's tool result names the kind and the failure class (and
    /// a RetryAfter's delay) on a line of its own, since the 2024-11-05 result has no
    /// structured slot. The display stays the first line.
    #[test]
    fn a_kernel_failure_names_its_kind_and_class_in_the_tool_result() {
        let limited = FnEndpoint::new("limited", |_| {
            Err(ikigai_core::Error::RetryAfter {
                delay: Some(std::time::Duration::from_millis(1_500)),
                detail: "5 per minute".into(),
            })
        })
        .with_description(Description::new("limited").verb(Verb::Source));
        let k = Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:limited"), limited),
        ));
        let resp = call(&k, "limited__source", json!({}));
        assert_eq!(resp["isError"], true, "{resp}");
        assert_eq!(
            text(&resp),
            "retry after 1500 ms: 5 per minute\nkind: retry-after; class: retry-after; retry-after-ms: 1500"
        );
    }

    #[test]
    fn each_contract_under_one_id_is_its_own_reachable_tool() {
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:iki:fn:toUpper"), upper("local", false))
            .bind(Exact::new("urn:narrow:iki:fn:toUpper"), upper("peer", true));
        let k = Kernel::new(Arc::new(space));
        let list = handle(
            &k,
            &Capability::root(),
            &ToolFilter::default(),
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .unwrap();
        let tools: Vec<&Value> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["name"].as_str().unwrap().starts_with("toUpper"))
            .collect();
        assert_eq!(tools.len(), 2, "one tool per contract: {tools:?}");

        // The first contract keeps the plain name and ITS schema.
        assert_eq!(tools[0]["name"], "toUpper__source");
        assert!(tools[0]["inputSchema"]["properties"]
            .get("locale")
            .is_none());
        // The peer's is named by its digest, and carries ITS schema.
        let peer_contract = ActionSpec::new(Verb::Source)
            .input(ArgSpec::new("in"))
            .input(ArgSpec::new("locale").optional())
            .contract_iri("toUpper");
        let digest = &peer_contract.rsplit_once(":b3:").unwrap().1[..8];
        let peer_name = format!("toUpper-{digest}__source");
        assert_eq!(tools[1]["name"], peer_name.as_str());
        assert!(tools[1]["inputSchema"]["properties"]
            .get("locale")
            .is_some());
        assert!(
            tools[1]["description"]
                .as_str()
                .unwrap()
                .contains("urn:narrow:iki:fn:toUpper"),
            "{}",
            tools[1]
        );

        // Both are reachable, each under its own contract.
        let local = call(&k, "toUpper__source", json!({"in":"x"}));
        assert_eq!(text(&local), "local", "{local}");
        let peer = call(&k, &peer_name, json!({"in":"x","locale":"tr"}));
        assert_eq!(text(&peer), "peer", "{peer}");

        // The local contract still refuses the peer's input, and the report names the
        // local CONTRACT, not the id both copies share.
        let refused = call(&k, "toUpper__source", json!({"in":"x","locale":"tr"}));
        assert_eq!(refused["isError"], true, "{refused}");
        let local_contract = ActionSpec::new(Verb::Source)
            .input(ArgSpec::new("in"))
            .contract_iri("toUpper");
        assert!(
            text(&refused).contains(&format!("sh:focusNode <{local_contract}>")),
            "{refused}"
        );
    }

    /// Identical contracts at two doors stay ONE tool, as before #948.
    #[test]
    fn identical_contracts_at_two_doors_stay_one_tool() {
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:iki:fn:toUpper"), upper("local", false))
            .bind(
                Exact::new("urn:narrow:iki:fn:toUpper"),
                upper("peer", false),
            );
        let k = Kernel::new(Arc::new(space));
        let list = handle(
            &k,
            &Capability::root(),
            &ToolFilter::default(),
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .unwrap();
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .filter(|n| n.starts_with("toUpper"))
            .collect();
        assert_eq!(names, ["toUpper__source"]);
    }
}

/// ledger #1309: JSON-RPC 2.0 §5.1 error replies, through the loop.
#[cfg(test)]
mod jsonrpc_1309 {
    use super::*;
    use ikigai_core::EndpointSpace;

    /// `ping` is all these tests call, and it needs no endpoint.
    fn kernel() -> Kernel {
        Kernel::new(std::sync::Arc::new(EndpointSpace::new()))
    }

    /// ledger #1309: every line through the real loop, one reply per line that is owed one,
    /// in order. Before, six of the invalid lines were skipped in silence (the first five and
    /// `"method":5`), three were answered as if valid (no `jsonrpc`, `"1.0"`, `params: 3`)
    /// and one under an object id, and the invalid UTF-8 line ENDED the session.
    #[test]
    fn the_stdio_loop_answers_every_invalid_line_per_json_rpc_5_1() {
        let input: Vec<u8> = [
            &b"not json\n"[..],
            b"[]\n",
            b"[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}]\n",
            b"42\n",
            b"{\"jsonrpc\":\"2.0\",\"id\":7}\n",
            b"{\"id\":8,\"method\":\"ping\"}\n",
            b"{\"jsonrpc\":\"1.0\",\"id\":9,\"method\":\"ping\"}\n",
            b"{\"jsonrpc\":\"2.0\",\"id\":{\"x\":1},\"method\":\"ping\"}\n",
            b"{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":5}\n",
            b"{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"ping\",\"params\":3}\n",
            b"\xff\xfe\n",
            // Owed nothing: a response from the client (result, then error), a notification,
            // and a notification that is not even valid. A blank line is framing slack.
            b"{\"jsonrpc\":\"2.0\",\"id\":12,\"result\":{}}\n",
            b"{\"jsonrpc\":\"2.0\",\"id\":13,\"error\":{\"code\":-1,\"message\":\"no\"}}\n",
            b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            b"{\"method\":\"bogus\",\"params\":3}\n",
            b"\r\n",
            // And the session is still alive at the end, CRLF framing included.
            b"{\"jsonrpc\":\"2.0\",\"id\":14,\"method\":\"ping\"}\r\n",
        ]
        .concat();
        let mut out = Vec::new();
        serve_io(&kernel(), &Capability::root(), &input[..], &mut out).expect("the loop runs");
        let replies: Vec<Value> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).expect("each reply is one JSON line"))
            .collect();
        let got: Vec<(Value, Option<i64>)> = replies
            .iter()
            .map(|r| (r["id"].clone(), r["error"]["code"].as_i64()))
            .collect();
        let null = Value::Null;
        assert_eq!(
            got,
            [
                (null.clone(), Some(PARSE_ERROR)),
                (null.clone(), Some(INVALID_REQUEST)),
                (null.clone(), Some(INVALID_REQUEST)),
                (null.clone(), Some(INVALID_REQUEST)),
                (json!(7), Some(INVALID_REQUEST)),
                (json!(8), Some(INVALID_REQUEST)),
                (json!(9), Some(INVALID_REQUEST)),
                (null.clone(), Some(INVALID_REQUEST)),
                (json!(10), Some(INVALID_REQUEST)),
                (json!(11), Some(INVALID_REQUEST)),
                (null.clone(), Some(PARSE_ERROR)),
                (json!(14), None),
            ]
        );
        for r in &replies {
            assert_eq!(r["jsonrpc"], "2.0", "{r}");
        }
        assert_eq!(replies[0]["error"]["message"], "Parse error");
        assert_eq!(replies[1]["error"]["message"], "Invalid Request");
        assert_eq!(replies[11]["result"], json!({}));
        // The reason rides in `data`, so a client can see WHY without the message drifting
        // from the standard's text.
        assert!(
            replies[2]["error"]["data"]
                .as_str()
                .unwrap()
                .contains("batching is not part of MCP 2024-11-05"),
            "{}",
            replies[2]
        );
    }

    /// The exact bytes JSON-RPC 2.0 §5.1 gives for a Parse error, `data` aside.
    #[test]
    fn a_parse_error_is_the_standard_reply_under_a_null_id() {
        let mut reply = handle_line(
            &kernel(),
            &Capability::root(),
            &ToolFilter::default(),
            b"{\"jsonrpc\": \"2.0\", \"method\": \"foobar, \"params\": \"bar\", \"baz]",
        )
        .expect("a parse error is answered");
        reply["error"]
            .as_object_mut()
            .unwrap()
            .remove("data")
            .expect("the parser's reason rides in data");
        assert_eq!(
            reply,
            json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}})
        );
    }
}

/// Ledger #1695: a `tools/call` runs on its own thread, so a slow one holds nothing else up.
#[cfg(test)]
mod concurrent_1695 {
    use super::*;
    use ikigai_core::{
        ArgSpec, Description, EndpointSpace, Exact, FnEndpoint, ReprType, Representation, Verb,
    };
    use std::sync::Arc;

    /// A writer the test and an endpoint can both read: the session's output so far.
    #[derive(Clone, Default)]
    struct Shared(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Shared {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
        fn replies(&self) -> Vec<Value> {
            self.text()
                .lines()
                .map(|l| serde_json::from_str(l).expect("each reply is one JSON line"))
                .collect()
        }
    }

    /// The echo kernel plus `urn:demo:slow`, a call that does not answer until `release` shows
    /// up in the session's output (or a minute passes, so a serial server fails the test
    /// rather than hang it). No sleep decides the order: the slow call answers only AFTER the
    /// output says the calls behind it were answered, which a server that runs one line at a
    /// time can never do.
    fn kernel_with_slow(output: &Shared, release: &'static str) -> Kernel {
        let seen = output.clone();
        let slow = FnEndpoint::new("slow", move |_inv| {
            let mut waited = 0;
            while !seen.text().contains(release) && waited < 6000 {
                std::thread::sleep(std::time::Duration::from_millis(10));
                waited += 1;
            }
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"slow".to_vec(),
            ))
        })
        .with_description(Description::new("slow").verb(Verb::Source));
        let echo = FnEndpoint::new("echo", |inv| {
            let text = inv.inline_str("in").unwrap_or("");
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!("[{text}]").into_bytes(),
            ))
        })
        .with_description(
            Description::new("echo")
                .verb(Verb::Source)
                .input(ArgSpec::new("in").summary("the text")),
        );
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:demo:slow"), slow)
            .bind(Exact::new("urn:demo:echo"), echo);
        Kernel::new(Arc::new(space))
    }

    fn call(id: u64, tool: &str, arguments: Value) -> String {
        json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
               "params":{"name":tool,"arguments":arguments}})
        .to_string()
            + "\n"
    }

    /// ★ **A slow `tools/call` holds nothing else up** (ledger #1695). The slow call answers
    /// only once the fast call behind it has, so the order of the replies IS the proof; the
    /// `ping` and `tools/list` between them are answered in arrival order while it runs, and
    /// the end of input still waits for the slow call's answer.
    #[test]
    fn a_fast_call_answers_while_a_slow_one_runs() {
        let out = Shared::default();
        let kernel = kernel_with_slow(&out, "\"id\":4");
        let input = [
            call(1, "slow__source", json!({})),
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n".to_string(),
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n".to_string(),
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}\n".to_string(),
            call(4, "echo__source", json!({"in": "fast"})),
        ]
        .concat();
        serve_io(&kernel, &Capability::root(), input.as_bytes(), out.clone())
            .expect("the loop runs");
        let replies = out.replies();
        let ids: Vec<Value> = replies.iter().map(|r| r["id"].clone()).collect();
        assert_eq!(
            ids,
            [json!(2), json!(3), json!(4), json!(1)],
            "{}",
            out.text()
        );
        assert_eq!(replies[2]["result"]["content"][0]["text"], "[fast]");
        assert_eq!(replies[3]["result"]["content"][0]["text"], "slow");
    }

    /// Past the bound a call is refused AT ONCE under its own id with [`SERVER_BUSY`], naming
    /// the bound, never queued behind the calls that are running; the running call still
    /// answers, and the bound frees when it does.
    #[test]
    fn a_call_past_the_bound_is_refused_at_once_never_queued() {
        let out = Shared::default();
        let kernel = kernel_with_slow(&out, "\"id\":2");
        let input = [
            call(1, "slow__source", json!({})),
            call(2, "echo__source", json!({"in": "over"})),
        ]
        .concat();
        let session = || (Capability::root(), ToolFilter::default());
        let output = std::sync::Mutex::new(out.clone());
        serve_concurrent(&kernel, session, input.as_bytes(), &output, 1).expect("the loop runs");
        let replies = out.replies();
        assert_eq!(replies.len(), 2, "{}", out.text());
        let busy = &replies[0];
        assert_eq!(busy["id"], 2, "{busy}");
        assert_eq!(busy["error"]["code"], SERVER_BUSY, "{busy}");
        assert_eq!(busy["error"]["message"], "Server busy", "{busy}");
        assert!(
            busy["error"]["data"]
                .as_str()
                .is_some_and(|d| d.contains("1 tools/call") && d.contains("not queued")),
            "{busy}"
        );
        assert_eq!(replies[1]["id"], 1, "{}", replies[1]);
        assert_eq!(replies[1]["result"]["content"][0]["text"], "slow");

        // Once the running call has answered, its slot is free again in the same session: the
        // second line is not even read until the first call's answer is out.
        let out = Shared::default();
        let kernel = kernel_with_slow(&out, "never");
        let input = Paced {
            lines: vec![
                call(1, "echo__source", json!({"in": "a"})),
                call(2, "echo__source", json!({"in": "b"})),
            ],
            next: 0,
            out: out.clone(),
        };
        let output = std::sync::Mutex::new(out.clone());
        serve_concurrent(&kernel, session, std::io::BufReader::new(input), &output, 1)
            .expect("the loop runs");
        let texts: Vec<Value> = out
            .replies()
            .iter()
            .map(|r| r["result"]["content"][0]["text"].clone())
            .collect();
        assert_eq!(texts, [json!("[a]"), json!("[b]")], "{}", out.text());
    }

    /// Input that hands over line `n` only once the output holds `n` replies, so a call is
    /// read only after every call before it has answered.
    struct Paced {
        lines: Vec<String>,
        next: usize,
        out: Shared,
    }

    impl std::io::Read for Paced {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let Some(line) = self.lines.get(self.next) else {
                return Ok(0);
            };
            let mut waited = 0;
            while self.out.text().lines().count() < self.next && waited < 6000 {
                std::thread::sleep(std::time::Duration::from_millis(10));
                waited += 1;
            }
            assert!(line.len() <= buf.len(), "a test line fits one read");
            buf[..line.len()].copy_from_slice(line.as_bytes());
            self.next += 1;
            Ok(line.len())
        }
    }
}

/// D11 of the principal model (ledger #1830): a `principal` the MCP CLIENT supplies never
/// reaches an endpoint. The door stamps the principal its capability carries, or none.
#[cfg(test)]
mod principal_tests {
    use super::*;
    use ikigai_core::{
        ArgSpec, Description, EndpointSpace, Exact, FnEndpoint, ReprType, Representation, Verb,
    };
    use serde_json::json;
    use std::sync::Arc;

    /// A Source that DECLARES a `principal` input (as a host reading the stamp might), and
    /// answers `<capability principal>|<principal argument>`, `-` for none.
    fn kernel() -> Kernel {
        let whoami = FnEndpoint::new("whoami", |inv: &ikigai_core::Invocation<'_>| {
            let held = inv.capability.principal().unwrap_or("-").to_string();
            let arg = inv.inline_str("principal").unwrap_or("-").to_string();
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!("{held}|{arg}").into_bytes(),
            ))
        })
        .with_description(
            Description::new("whoami")
                .verb(Verb::Source)
                .input(ArgSpec::new("principal").optional()),
        );
        Kernel::new(Arc::new(
            EndpointSpace::new().bind(Exact::new("urn:test:whoami"), whoami),
        ))
    }

    fn answer(capability: &Capability) -> String {
        let reply = handle(
            &kernel(),
            capability,
            &ToolFilter::default(),
            &json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {
                    "name": "whoami__source",
                    "arguments": { "principal": "urn:example:mallory" }
                }
            }),
        )
        .expect("a reply");
        reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("a text result: {reply}"))
            .to_string()
    }

    #[test]
    fn a_client_principal_argument_is_removed_when_the_session_names_nobody() {
        assert_eq!(answer(&Capability::root()), "-|-");
        assert_eq!(answer(&Capability::scoped(["urn:cap:demo:read"])), "-|-");
    }

    #[test]
    fn the_session_principal_is_stamped_over_a_client_supplied_one() {
        let agent = Capability::scoped(["urn:cap:demo:read"])
            .with_principal("urn:example:agent")
            .unwrap();
        assert_eq!(answer(&agent), "urn:example:agent|urn:example:agent");
    }
}
