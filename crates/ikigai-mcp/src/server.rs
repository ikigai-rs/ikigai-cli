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

use crate::{action_to_tool, parse_tool_name, ToolFilter};

/// The MCP protocol revision this server implements against.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// Dispatch one JSON-RPC message. Returns the response value to write back, or
/// `None` for a notification (no `id` ⇒ no reply).
pub fn handle(
    kernel: &Kernel,
    capability: &Capability,
    filter: &ToolFilter,
    msg: &Value,
) -> Option<Value> {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str)?;

    match method {
        // Notifications (no id): acknowledged by doing nothing.
        _ if id.is_none() => None,
        "initialize" => Some(ok(id?, initialize_result())),
        "ping" => Some(ok(id?, json!({}))),
        "tools/list" => Some(ok(id?, tools_list(kernel, capability, filter))),
        "tools/call" => Some(ok(id?, tools_call(kernel, capability, msg.get("params")))),
        other => Some(err(id?, -32601, &format!("method not found: {other}"))),
    }
}

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn err(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
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
    // Group the manifold rows by projected tool name: MCP clients key on the
    // name, so same-named rows — a namespace listed by both a fronted mount and
    // the local space (`--override`/`--prefer`), or one endpoint bound once per
    // configured root (browse) — must collapse to ONE tool without losing
    // reach. Identical patterns collapse by precedence (resolution serves the
    // first); patterns that differ come back as synthesized selector arguments
    // in the input schema (see [`crate::collapse`]), so every row stays
    // addressable by call.
    let mut order: Vec<String> = Vec::new();
    let mut groups: std::collections::BTreeMap<String, Vec<ikigai_core::ActionMatch>> =
        std::collections::BTreeMap::new();
    for m in kernel.select_actions(&query) {
        let name = crate::tool_name(&m.id, m.verb);
        if !groups.contains_key(&name) {
            order.push(name.clone());
        }
        groups.entry(name).or_default().push(m);
    }
    let mut tools = Vec::new();
    for name in order {
        if !filter.allows(&name) {
            continue;
        }
        let rows = &groups[&name];
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
        let declared: Vec<String> = action.inputs.iter().map(|i| i.name.clone()).collect();
        crate::add_synthesized(&mut tool, &crate::collapse(&patterns, &declared));
        tools.push(tool);
    }
    json!({ "tools": tools })
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

    // Re-select under the grant: the tool must still be an allowed action, and
    // this yields its resolvable endpoint IRI + catalog action IRI.
    let query = ikigai_core::ActionQuery {
        capability: Some(capability),
        ..Default::default()
    };
    // Match on the sanitized id: `id` from the tool name is already in
    // `sanitize_id` form, so sanitize each candidate the same way (a URI-shaped
    // id like `urn:llm:config` projects to `urn_llm_config`). ALL matching rows
    // are kept — one tool may front many bound rows (see [`crate::collapse`]).
    let rows: Vec<ikigai_core::ActionMatch> = kernel
        .select_actions(&query)
        .into_iter()
        .filter(|m| crate::sanitize_id(&m.id) == id && m.verb == verb)
        .collect();
    if rows.is_empty() {
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
        let offered = kernel
            .select_actions(&ikigai_core::ActionQuery::default())
            .into_iter()
            .any(|m| crate::sanitize_id(&m.id) == id && m.verb == verb);
        return tool_error(if offered {
            format!("tool `{name}` is not available under this capability")
        } else {
            format!(
                "tool `{name}` is not in the manifold — no bound endpoint answers to it \
                 (a mounted peer may be unreachable, or the tool list is stale)"
            )
        });
    }

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
    let mut req_args: Vec<(String, String)> = Vec::new();
    for input in &action.inputs {
        let Some(value) = arguments.get(&input.name).and_then(crate::scalar) else {
            continue;
        };
        if input.source == ikigai_core::InputSource::Binding {
            target = target.replace(&format!("{{{}}}", input.name), &value);
        } else {
            req_args.push((input.name.clone(), value));
        }
    }
    // Pre-flight the JSON arguments against the action's declared contract
    // (structured, so a value with a newline/& validates correctly). A
    // non-conforming call comes back as the SHACL report — data the model reads
    // and repairs from — without touching the endpoint.
    if let Some(report) = crate::validate_arguments(&description, &action, &endpoint_arguments) {
        return tool_error(format!("arguments failed validation:\n{report}"));
    }

    // Invoke.
    let Ok(target_iri) = Iri::parse(&target) else {
        return tool_error(format!("target `{target}` is not a valid IRI"));
    };
    let mut request = Request::new(verb, target_iri);
    for (k, v) in req_args {
        request = request.with_arg(k, ArgRef::Inline(v.into_bytes()));
    }
    match block_on(kernel.issue(request, capability)) {
        Ok(repr) => tool_text(String::from_utf8_lossy(&repr.bytes).into_owned()),
        Err(e) => tool_error(format!("{e}")),
    }
}

fn tool_text(text: String) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": false })
}

fn tool_error(message: String) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}

/// The stdin→stdout loop: read newline-delimited JSON-RPC, dispatch, write each
/// response as one line. Runs until stdin closes.
pub fn serve(kernel: &Kernel, capability: &Capability) -> std::io::Result<()> {
    use std::io::{BufRead, Write};
    let filter = ToolFilter::default(); // allow-all: the plain server shows the full grant
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue; // a malformed line is ignored, not fatal
        };
        if let Some(response) = handle(kernel, capability, &filter, &msg) {
            writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
            stdout.flush()?;
        }
    }
    Ok(())
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
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "echo__source");
        assert_eq!(
            tools[0]["inputSchema"]["properties"]["in"]["type"],
            "string"
        );

        // Without it: the manifold is empty — affordance equals authorization.
        let bare = Capability::scoped(["urn:cap:unrelated"]);
        let resp = handle(
            &k,
            &bare,
            &ToolFilter::default(),
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        )
        .unwrap();
        assert_eq!(resp["result"]["tools"].as_array().unwrap().len(), 0);
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
        assert_eq!(resp["result"]["tools"].as_array().unwrap().len(), 0);

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
        assert_eq!(resp["result"]["tools"].as_array().unwrap().len(), 0);
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
}
