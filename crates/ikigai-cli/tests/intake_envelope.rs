//! Ledger #1885: `ikigai-intake` declares its body as an argument ENVELOPE
//! (`ActionSpec::envelope("content")`, argspec design note 5.2), so the projections that came
//! with core 0.1.105 (ikigai-rs/ikigai-cli PR 548) apply to a real intake. Both live in other
//! crates than the declaration, which is why this file is here, where all three meet:
//!
//! - MCP's input schema and ikigai-web's OpenAPI request body show the form's FIELDS, and never
//!   `content` as a field of its own body;
//! - an MCP call that gives the fields as one JSON object reaches the intake as the body it
//!   parses, and the tuple it drops carries them.
//!
//! The edge's own forms (`urn:contact:submit`, `urn:booking:submit`) are pinned in
//! ikigai-embedded; a body-only submission (a form POST, a pipe) is pinned in ikigai-intake.
#![cfg(feature = "web")]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use ikigai_core::{
    Capability, EndpointSpace, Exact, FnEndpoint, Kernel, ReprType, Representation, Verb,
};
use ikigai_intake::IntakeField as F;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A small intake with a required, an optional and a constrained field, dropping into a
/// recording space. No redirect, so an accepted submission answers a plain `received`.
fn intake() -> ikigai_intake::IntakeConfig {
    ikigai_intake::IntakeConfig {
        id: "enquiry".to_string(),
        space: "urn:space:enquiries".to_string(),
        fields: vec![
            F::required("email", "Your email address"),
            F::optional("note", "Anything to add"),
            F::optional("topic", "What it is about").one_of(["talk", "book"]),
        ],
        email_field: Some("email".to_string()),
        honeypot: None,
        requires: "urn:cap:enquiry:submit".to_string(),
        clients: None,
        attests: Vec::new(),
        redirect: None,
        check_blocked: false,
        fixed_fields: Default::default(),
        blocklist: None,
        blocklist_key: None,
    }
}

/// The intake at `urn:enquiry:submit` in front of a space that records every tuple dropped.
fn kernel() -> (Arc<Kernel>, Arc<Mutex<Vec<String>>>) {
    let dropped = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&dropped);
    let space = FnEndpoint::new("enquiries", move |inv| {
        let tuple = inv.inline_str("content").unwrap_or_default().to_string();
        seen.lock().unwrap().push(tuple);
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"ok".to_vec(),
        ))
    });
    let space = EndpointSpace::new()
        .bind(
            Exact::new("urn:enquiry:submit"),
            ikigai_intake::submit(intake()),
        )
        .bind(Exact::new("urn:space:enquiries"), space);
    (Arc::new(Kernel::new(Arc::new(space))), dropped)
}

/// The intake's one action: its Sink.
fn action() -> ikigai_core::ActionSpec {
    use ikigai_core::Endpoint;
    let described = ikigai_intake::submit(intake()).describe();
    described
        .action_specs()
        .into_iter()
        .find(|a| a.verb == Verb::Sink)
        .expect("the intake declares its Sink")
}

/// The property names of a JSON-Schema object, in order.
fn property_names(schema: &Value) -> Vec<&str> {
    schema["properties"]
        .as_object()
        .unwrap_or_else(|| panic!("an object schema: {schema}"))
        .keys()
        .map(String::as_str)
        .collect()
}

#[test]
fn the_mcp_schema_shows_the_fields_and_not_the_carrier() {
    let schema = ikigai_mcp::input_schema(&action());
    assert_eq!(
        property_names(&schema),
        ["email", "note", "topic"],
        "{schema}"
    );
    assert_eq!(schema["required"], json!(["email"]), "{schema}");
    assert_eq!(
        schema["properties"]["topic"]["enum"],
        json!(["talk", "book"]),
        "{schema}"
    );
}

/// One MCP `tools/call` of the intake's Sink with `arguments`, under root. Returns whether
/// the tool answered an error, and its text.
fn call(kernel: &Kernel, arguments: Value) -> (bool, String) {
    let line = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "enquiry__sink", "arguments": arguments}})
    .to_string();
    let reply = ikigai_mcp::server::handle_line(
        kernel,
        &Capability::root(),
        &ikigai_mcp::ToolFilter::default(),
        line.as_bytes(),
    )
    .expect("a tools/call is answered");
    let result = &reply["result"];
    (
        result["isError"].as_bool().unwrap_or(false),
        result["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("a text answer: {reply}"))
            .to_string(),
    )
}

#[test]
fn an_mcp_call_with_the_fields_as_an_object_reaches_the_intake_as_its_body() {
    let (kernel, dropped) = kernel();
    let (error, text) = call(
        &kernel,
        json!({"email": "a@example.org", "note": "hello \"there\"", "topic": "talk"}),
    );
    assert!(!error, "{text}");
    assert_eq!(text, "received\n");
    assert_eq!(
        *dropped.lock().unwrap(),
        [r#"((email "a@example.org") (note "hello \"there\"") (topic "talk"))"#],
        "the fields were serialized into `content`, parsed and carried"
    );

    // The checker reads the FIELDS' rules on such a call: a required field missing and a
    // value outside its enumeration are refused before the intake runs.
    let (error, text) = call(&kernel, json!({"note": "hello"}));
    assert!(error && text.contains("`email`"), "{text}");
    let (error, text) = call(&kernel, json!({"email": "a@example.org", "topic": "spam"}));
    assert!(error && text.contains("`topic`"), "{text}");
    assert_eq!(
        dropped.lock().unwrap().len(),
        1,
        "neither refusal dropped a tuple"
    );

    // The body given whole still works, as a form POST or a pipe gives it.
    let (error, text) = call(&kernel, json!({"content": "email=b%40example.org"}));
    assert!(!error, "{text}");
    assert_eq!(
        dropped.lock().unwrap().last().map(String::as_str),
        Some(r#"((email "b@example.org"))"#)
    );
}

/// `GET path` against the door at `addr`, returning the whole response.
async fn get(addr: SocketAddr, path: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("the door accepts");
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("the request is written");
    let mut out = Vec::new();
    stream
        .read_to_end(&mut out)
        .await
        .expect("the response is read");
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn the_openapi_body_is_the_fields_and_not_the_carrier() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("a runtime");
    let resp = runtime.block_on(async {
        // Port 0, bound here and handed to the door, so the port is never raced.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let addr = listener.local_addr().expect("its address");
        let (kernel, _) = kernel();
        tokio::spawn(ikigai_web::serve_with_listener(
            kernel,
            ikigai_web::fixed_cap(vec!["urn:cap:enquiry:submit".to_string()]),
            listener,
            ikigai_web::EdgeConfig::default(),
        ));
        get(addr, "/enquiry/submit?description").await
    });
    let body = resp
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_else(|| panic!("a response: {resp}"));
    let v: Value = serde_json::from_str(body).unwrap_or_else(|e| panic!("OpenAPI ({e}): {resp}"));
    let content = &v["paths"]["/enquiry/submit"]["post"]["requestBody"]["content"];
    for media in ["application/json", "application/x-www-form-urlencoded"] {
        let schema = &content[media]["schema"];
        assert_eq!(
            property_names(schema),
            ["email", "note", "topic"],
            "{media}: {v}"
        );
        assert_eq!(schema["required"], json!(["email"]), "{media}: {v}");
    }
}
