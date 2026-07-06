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
use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request, Verb};
use serde_json::{json, Value};

use crate::{action_to_tool, parse_tool_name};

/// The MCP protocol revision this server implements against.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// Dispatch one JSON-RPC message. Returns the response value to write back, or
/// `None` for a notification (no `id` ⇒ no reply).
pub fn handle(kernel: &Kernel, capability: &Capability, msg: &Value) -> Option<Value> {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str)?;

    match method {
        // Notifications (no id): acknowledged by doing nothing.
        _ if id.is_none() => None,
        "initialize" => Some(ok(id?, initialize_result())),
        "ping" => Some(ok(id?, json!({}))),
        "tools/list" => Some(ok(id?, tools_list(kernel, capability))),
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
/// with no present types returns every action the grant allows; each is
/// `describe`d for its typed contract and projected to a tool.
fn tools_list(kernel: &Kernel, capability: &Capability) -> Value {
    let query = ikigai_core::ActionQuery {
        capability: Some(capability),
        ..Default::default()
    };
    let mut tools = Vec::new();
    for m in kernel.select_actions(&query) {
        let Ok(iri) = Iri::parse(&m.endpoint) else {
            continue;
        };
        let Some(description) = kernel.describe(&iri) else {
            continue;
        };
        if let Some(action) = description
            .action_specs()
            .into_iter()
            .find(|a| a.verb == m.verb)
        {
            tools.push(action_to_tool(&description, &action));
        }
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
    let Some(m) = kernel
        .select_actions(&query)
        .into_iter()
        .find(|m| m.id == id && m.verb == verb)
    else {
        return tool_error(format!(
            "tool `{name}` is not available under this capability"
        ));
    };

    let Ok(endpoint_iri) = Iri::parse(&m.endpoint) else {
        return tool_error(format!("endpoint `{}` is not a valid IRI", m.endpoint));
    };
    let Some(description) = kernel.describe(&endpoint_iri) else {
        return tool_error(format!("endpoint `{}` no longer resolves", m.endpoint));
    };
    let Some(action) = description
        .action_specs()
        .into_iter()
        .find(|a| a.verb == verb)
    else {
        return tool_error(format!("`{id}` declares no {verb:?} action"));
    };

    // Route each supplied argument: a Binding-source input substitutes into the
    // endpoint IRI template ({name} → value); an Argument-source input becomes a
    // request argument.
    let mut target = m.endpoint.clone();
    let mut req_args: Vec<(String, String)> = Vec::new();
    for input in &action.inputs {
        let Some(value) = arguments.get(&input.name).and_then(json_scalar) else {
            continue;
        };
        if input.source == ikigai_core::InputSource::Binding {
            target = target.replace(&format!("{{{}}}", input.name), &value);
        } else {
            req_args.push((input.name.clone(), value));
        }
    }

    // Pre-flight the argument values against the action's declared contract.
    let proposed = req_args
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let validate = Request::new(
        Verb::Source,
        Iri::parse("urn:kernel:validate").expect("valid IRI"),
    )
    .with_arg("action", ArgRef::Inline(m.action.clone().into_bytes()))
    .with_arg("args", ArgRef::Inline(proposed.into_bytes()));
    if let Ok(report) = block_on(kernel.issue(validate, capability)) {
        let report = String::from_utf8_lossy(&report.bytes);
        if report.contains("sh:conforms false") {
            return tool_error(format!("arguments failed validation:\n{report}"));
        }
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

/// A JSON scalar as the string the kernel expects (numbers/bools stringified;
/// objects/arrays/null skipped).
fn json_scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
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
        if let Some(response) = handle(kernel, capability, &msg) {
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
        ArgSpec, Description, EndpointSpace, Exact, FnEndpoint, ReprType, Representation,
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
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        )
        .unwrap();
        assert_eq!(resp["result"]["tools"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn tools_call_invokes_and_gates_on_capability() {
        let k = kernel();
        let held = Capability::scoped(["urn:cap:demo:echo"]);
        let call = json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params": { "name": "echo__source", "arguments": { "in": "hi" } }
        });
        let resp = handle(&k, &held, &call).unwrap();
        assert_eq!(resp["result"]["isError"], false);
        assert_eq!(resp["result"]["content"][0]["text"], "[hi]");

        // The same call under a capability that doesn't hold the scope: the tool
        // is not in the manifold, so it can't be invoked.
        let bare = Capability::scoped(["urn:cap:unrelated"]);
        let resp = handle(&k, &bare, &call).unwrap();
        assert_eq!(resp["result"]["isError"], true);
        assert!(resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("not available under this capability"));
    }
}
