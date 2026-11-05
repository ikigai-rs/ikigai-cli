//! The shared wire vectors (ledger #3165): the postcard bytes of every type that crosses the
//! wire, with representative values, the hello, and whole call and reply exchanges for the
//! hello and each verb.
//!
//! `tests/vectors/wire_vectors.json` is what the faces (ikigai-python, ikigai-deno,
//! ikigai-dotnet, ikigai-clojure, …) copy VERBATIM, instead of byte literals copied out of
//! another face's tests: vector-drift then compares files, not per-language extracts. This
//! test computes every vector from the codec and fails if the file differs, so the file cannot
//! drift from the code; it also decodes every vector back to the value it came from. To
//! regenerate after a deliberate wire change, run it with `IKIGAI_BLESS=1` and review the diff.
//!
//! The streamed frames of wire v10 are `tests/vectors/stream_frames.json`
//! (`tests/stream_vectors.rs`), which this file does not repeat.

use std::fmt::Debug;

use ikigai_core::{
    ArgRef, Capability, ContentId, Expiry, Iri, ReprType, Representation, Request, SpaceEntry,
    Time, TraceEvent, Verb,
};
use ikigai_resolve::CacheStatus;
use ikigai_wire::{
    decode, decode_hello, encode, encode_hello, Call, Hello, HelloMode, IssueWith, Reply,
    TraceContext, WireError, HELLO_MAGIC, MAX_FRAME, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

const VECTORS: &str = "tests/vectors/wire_vectors.json";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// `payload` as the IPC socket frames it: a `u32` big-endian length, then the payload.
fn framed(payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

/// One postcard vector: encodes `item`, checks it decodes back to `item`, and describes it.
fn vector<T>(name: &str, ty: &str, value: Value, item: &T) -> Value
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let bytes = encode(item).unwrap();
    assert_eq!(&decode::<T>(&bytes).unwrap(), item, "{name} round-trips");
    json!({"name": name, "type": ty, "value": value, "hex": hex(&bytes)})
}

/// Decode `bytes` as the wire type named `ty` and encode it again: what the second test
/// does with every postcard vector in the file.
fn reencode(ty: &str, bytes: &[u8]) -> Vec<u8> {
    fn again<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Vec<u8> {
        encode(&decode::<T>(bytes).unwrap()).unwrap()
    }
    match ty {
        "u8" => again::<u8>(bytes),
        "u32" => again::<u32>(bytes),
        "u64" => again::<u64>(bytes),
        "bool" => again::<bool>(bytes),
        "string" => again::<String>(bytes),
        "bytes" => again::<Vec<u8>>(bytes),
        "option<u32>" => again::<Option<u32>>(bytes),
        "Verb" => again::<Verb>(bytes),
        "Iri" => again::<Iri>(bytes),
        "ArgRef" => again::<ArgRef>(bytes),
        "Request" => again::<Request>(bytes),
        "Capability" => again::<Capability>(bytes),
        "ReprType" => again::<ReprType>(bytes),
        "Expiry" => again::<Expiry>(bytes),
        "Representation" => again::<Representation>(bytes),
        "CacheStatus" => again::<CacheStatus>(bytes),
        "SpaceEntry" => again::<SpaceEntry>(bytes),
        "TraceEvent" => again::<TraceEvent>(bytes),
        "TraceContext" => again::<TraceContext>(bytes),
        "IssueWith" => again::<IssueWith>(bytes),
        "WireError" => again::<WireError>(bytes),
        "Call" => again::<Call>(bytes),
        "Reply" => again::<Reply>(bytes),
        other => panic!("no decoder for the vector type {other}"),
    }
}

fn iri(text: &str) -> Iri {
    Iri::parse(text).unwrap()
}

fn read_request() -> Request {
    Request::new(Verb::Source, iri("urn:test:upper")).with_arg("in", ArgRef::Inline(b"hi".to_vec()))
}

fn request_for(verb: Verb) -> Request {
    Request::new(verb, iri("urn:example:note"))
}

fn text(body: &[u8]) -> Representation {
    Representation::new(ReprType::new("text/plain"), body.to_vec())
}

fn trace_event() -> TraceEvent {
    TraceEvent {
        target: "urn:test:upper".to_string(),
        thread: "ikigai-sched-0".to_string(),
        started: Some(Time::from_millis(1_000)),
        ended: Some(Time::from_millis(1_250)),
        cache_hit: false,
        span: 1,
        parent: None,
        capability: Some(vec!["urn:cap:demo".to_string()]),
        notes: vec![("model".to_string(), "llama3.2:3b".to_string())],
    }
}

fn trace_event_value() -> Value {
    json!({
        "target": "urn:test:upper", "thread": "ikigai-sched-0",
        "started": 1000, "ended": 1250, "cache_hit": false, "span": 1, "parent": null,
        "capability": ["urn:cap:demo"], "notes": [["model", "llama3.2:3b"]],
    })
}

fn verb_name(verb: Verb) -> &'static str {
    match verb {
        Verb::Source => "Source",
        Verb::Sink => "Sink",
        Verb::Exists => "Exists",
        Verb::Delete => "Delete",
        Verb::Meta => "Meta",
    }
}

const VERBS: [Verb; 5] = [
    Verb::Source,
    Verb::Sink,
    Verb::Exists,
    Verb::Delete,
    Verb::Meta,
];

/// One wire error per variant, in variant order, with its JSON description.
fn wire_errors() -> Vec<(&'static str, Value, WireError)> {
    vec![
        (
            "Unresolved",
            json!({"Unresolved": "urn:x"}),
            WireError::Unresolved("urn:x".into()),
        ),
        (
            "MissingArgument",
            json!({"MissingArgument": "in"}),
            WireError::MissingArgument("in".into()),
        ),
        (
            "InvalidArgument",
            json!({"InvalidArgument": {"name": "in", "detail": "not a number"}}),
            WireError::InvalidArgument {
                name: "in".into(),
                detail: "not a number".into(),
            },
        ),
        (
            "Endpoint",
            json!({"Endpoint": "boom"}),
            WireError::Endpoint("boom".into()),
        ),
        (
            "Denied",
            json!({"Denied": "x"}),
            WireError::Denied("x".into()),
        ),
        (
            "NotFound",
            json!({"NotFound": "no such note"}),
            WireError::NotFound("no such note".into()),
        ),
        (
            "Timeout",
            json!({"Timeout": "slow"}),
            WireError::Timeout("slow".into()),
        ),
        (
            "Unavailable",
            json!({"Unavailable": "the origin went away"}),
            WireError::Unavailable("the origin went away".into()),
        ),
        (
            "Conflict",
            json!({"Conflict": "x"}),
            WireError::Conflict("x".into()),
        ),
        (
            "DepthExceeded",
            json!({"DepthExceeded": {"depth": 64, "target": "urn:x"}}),
            WireError::DepthExceeded {
                depth: 64,
                target: "urn:x".into(),
            },
        ),
        (
            "RetryAfter",
            json!({"RetryAfter": {"delay_ms": 2000, "detail": "rate-limited"}}),
            WireError::RetryAfter {
                delay_ms: Some(2_000),
                detail: "rate-limited".into(),
            },
        ),
        (
            "RetryAfter/no-delay",
            json!({"RetryAfter": {"delay_ms": null, "detail": "rate-limited"}}),
            WireError::RetryAfter {
                delay_ms: None,
                detail: "rate-limited".into(),
            },
        ),
        (
            "OverBudget",
            json!({"OverBudget": "too big"}),
            WireError::OverBudget("too big".into()),
        ),
        (
            "Refused",
            json!({"Refused": "api.example.com answered 401"}),
            WireError::Refused("api.example.com answered 401".into()),
        ),
        (
            "Unsupported",
            json!({"Unsupported": {"verb": "Delete", "detail": "read-only"}}),
            WireError::Unsupported {
                verb: Some(Verb::Delete),
                detail: "read-only".into(),
            },
        ),
        (
            "Unsupported/no-verb",
            json!({"Unsupported": {"verb": null, "detail": "no clock"}}),
            WireError::Unsupported {
                verb: None,
                detail: "no clock".into(),
            },
        ),
    ]
}

/// The postcard encodings: the primitives every type is built from, then each wire type.
fn postcard() -> Vec<Value> {
    let mut out = Vec::new();

    // Unsigned integers are varints (LEB128). A `u64` past 2^53 is given as a decimal
    // string, so a JSON reader that holds numbers as doubles keeps it exact.
    for value in [0u32, 1, 127, 128, 300, 16_384, u32::MAX] {
        out.push(vector(&format!("u32/{value}"), "u32", json!(value), &value));
    }
    out.push(vector("u64/2^53", "u64", json!(1u64 << 53), &(1u64 << 53)));
    out.push(vector(
        "u64/max",
        "u64",
        json!(u64::MAX.to_string()),
        &u64::MAX,
    ));
    out.push(vector("u8/255", "u8", json!(255), &255u8));
    out.push(vector("bool/false", "bool", json!(false), &false));
    out.push(vector("bool/true", "bool", json!(true), &true));
    out.push(vector("string/empty", "string", json!(""), &String::new()));
    out.push(vector(
        "string/ascii",
        "string",
        json!("hi"),
        &"hi".to_string(),
    ));
    out.push(vector(
        "string/utf8",
        "string",
        json!("café ☕"),
        &"café ☕".to_string(),
    ));
    out.push(vector(
        "bytes",
        "bytes",
        json!({"hex": "00ff"}),
        &vec![0x00u8, 0xff],
    ));
    out.push(vector(
        "option/none",
        "option<u32>",
        json!(null),
        &None::<u32>,
    ));
    out.push(vector(
        "option/some",
        "option<u32>",
        json!(300),
        &Some(300u32),
    ));

    // Verb crosses as its VARIANT INDEX (Source 0 … Meta 4), not its `repr(u8)` value.
    for verb in VERBS {
        out.push(vector(
            &format!("Verb/{}", verb_name(verb)),
            "Verb",
            json!(verb_name(verb)),
            &verb,
        ));
    }
    out.push(vector(
        "Iri",
        "Iri",
        json!("urn:test:upper"),
        &iri("urn:test:upper"),
    ));
    out.push(vector(
        "ArgRef/Reference",
        "ArgRef",
        json!({"Reference": "urn:example:doc"}),
        &ArgRef::Reference(iri("urn:example:doc")),
    ));
    out.push(vector(
        "ArgRef/Inline",
        "ArgRef",
        json!({"Inline": {"hex": "6869"}}),
        &ArgRef::Inline(b"hi".to_vec()),
    ));
    let content = ContentId::of(b"hi");
    out.push(vector(
        "ArgRef/Content",
        "ArgRef",
        json!({"Content": content.to_string()}),
        &ArgRef::Content(content),
    ));
    out.push(vector(
        "Request/no-args",
        "Request",
        json!({"verb": "Source", "target": "urn:example:note", "args": {}}),
        &request_for(Verb::Source),
    ));
    out.push(vector(
        "Request/inline-arg",
        "Request",
        json!({"verb": "Source", "target": "urn:test:upper", "args": {"in": {"Inline": {"hex": "6869"}}}}),
        &read_request(),
    ));
    // Arguments are a map written in key order (a BTreeMap), whatever order they were added.
    out.push(vector(
        "Request/args-in-key-order",
        "Request",
        json!({"verb": "Sink", "target": "urn:example:note", "args": {
            "a": {"Reference": "urn:example:doc"},
            "b": {"Inline": {"hex": "00ff"}},
        }}),
        &request_for(Verb::Sink)
            .with_arg("b", ArgRef::Inline(vec![0x00, 0xff]))
            .with_arg("a", ArgRef::Reference(iri("urn:example:doc"))),
    ));
    out.push(vector(
        "Capability/root",
        "Capability",
        json!("root"),
        &Capability::root(),
    ));
    // A scoped capability is a set, written sorted.
    out.push(vector(
        "Capability/scoped",
        "Capability",
        json!({"scoped": ["urn:cap:a", "urn:cap:b"]}),
        &Capability::scoped(["urn:cap:b", "urn:cap:a"]),
    ));
    out.push(vector(
        "ReprType/no-params",
        "ReprType",
        json!({"media_type": "text/plain", "params": {}}),
        &ReprType::new("text/plain"),
    ));
    out.push(vector(
        "ReprType/params",
        "ReprType",
        json!({"media_type": "text/plain", "params": {"charset": "utf-8"}}),
        &ReprType::new("text/plain").with_param("charset", "utf-8"),
    ));
    out.push(vector(
        "Expiry/Always",
        "Expiry",
        json!("Always"),
        &Expiry::Always,
    ));
    out.push(vector(
        "Expiry/At",
        "Expiry",
        json!({"At": 1_700_000_000_000u64}),
        &Expiry::At(Time::from_millis(1_700_000_000_000)),
    ));
    out.push(vector(
        "Expiry/Never",
        "Expiry",
        json!("Never"),
        &Expiry::Never,
    ));
    out.push(vector(
        "Representation/uncacheable",
        "Representation",
        json!({"repr_type": {"media_type": "text/plain", "params": {}}, "bytes": {"utf8": "HI"}, "expiry": "Always"}),
        &text(b"HI"),
    ));
    out.push(vector(
        "Representation/cacheable",
        "Representation",
        json!({"repr_type": {"media_type": "application/json", "params": {}}, "bytes": {"utf8": "{}"}, "expiry": "Never"}),
        &Representation::new(ReprType::new("application/json"), b"{}".to_vec()).cacheable(),
    ));
    for (name, status) in [
        ("Hit", CacheStatus::Hit),
        ("Miss", CacheStatus::Miss),
        ("Uncacheable", CacheStatus::Uncacheable),
    ] {
        out.push(vector(
            &format!("CacheStatus/{name}"),
            "CacheStatus",
            json!(name),
            &status,
        ));
    }
    out.push(vector(
        "SpaceEntry/local",
        "SpaceEntry",
        json!({"pattern": "urn:test:upper", "endpoint": "upper", "origin": null}),
        &SpaceEntry {
            pattern: "urn:test:upper".into(),
            endpoint: "upper".into(),
            origin: None,
        },
    ));
    out.push(vector(
        "SpaceEntry/mounted",
        "SpaceEntry",
        json!({"pattern": "urn:example:note/{id}", "endpoint": "note", "origin": "beefybox"}),
        &SpaceEntry {
            pattern: "urn:example:note/{id}".into(),
            endpoint: "note".into(),
            origin: Some("beefybox".into()),
        },
    ));
    out.push(vector(
        "TraceEvent",
        "TraceEvent",
        trace_event_value(),
        &trace_event(),
    ));
    out.push(vector(
        "TraceContext/root",
        "TraceContext",
        json!({"trace_id": 7, "parent_span": null}),
        &TraceContext {
            trace_id: 7,
            parent_span: None,
        },
    ));
    out.push(vector(
        "TraceContext/parented",
        "TraceContext",
        json!({"trace_id": 7, "parent_span": 3}),
        &TraceContext {
            trace_id: 7,
            parent_span: Some(3),
        },
    ));
    out.push(vector(
        "IssueWith/empty",
        "IssueWith",
        json!({"trace": null, "retries": null, "time_left_ms": null}),
        &IssueWith::default(),
    ));
    out.push(vector(
        "IssueWith/full",
        "IssueWith",
        json!({"trace": {"trace_id": 7, "parent_span": null}, "retries": 2, "time_left_ms": 1500}),
        &IssueWith {
            trace: Some(TraceContext {
                trace_id: 7,
                parent_span: None,
            }),
            retries: Some(2),
            time_left_ms: Some(1_500),
        },
    ));
    for (name, value, error) in wire_errors() {
        out.push(vector(
            &format!("WireError/{name}"),
            "WireError",
            value,
            &error,
        ));
    }

    // Every Call variant, in variant order.
    let with = IssueWith {
        trace: None,
        retries: Some(1),
        time_left_ms: Some(1_500),
    };
    let ctx = TraceContext {
        trace_id: 7,
        parent_span: None,
    };
    let request_value = json!({"verb": "Source", "target": "urn:test:upper", "args": {"in": {"Inline": {"hex": "6869"}}}});
    let calls = vec![
        (
            "Issue",
            json!({"Issue": request_value}),
            Call::Issue(read_request()),
        ),
        (
            "IsCached",
            json!({"IsCached": request_value}),
            Call::IsCached(read_request()),
        ),
        ("Entries", json!("Entries"), Call::Entries),
        (
            "IssueAs",
            json!({"IssueAs": [request_value, "root"]}),
            Call::IssueAs(read_request(), Capability::root()),
        ),
        (
            "IssueTraced",
            json!({"IssueTraced": [request_value, "root", {"trace_id": 7, "parent_span": null}]}),
            Call::IssueTraced(read_request(), Capability::root(), ctx),
        ),
        (
            "IssueWith",
            json!({"IssueWith": [request_value, "root", {"trace": null, "retries": 1, "time_left_ms": 1500}]}),
            Call::IssueWith(read_request(), Capability::root(), with),
        ),
    ];
    for (name, value, call) in calls {
        out.push(vector(&format!("Call/{name}"), "Call", value, &call));
    }

    // Every Reply variant, in variant order.
    let hi = json!({"repr_type": {"media_type": "text/plain", "params": {}}, "bytes": {"utf8": "HI"}, "expiry": "Always"});
    let replies = vec![
        (
            "Resolved",
            json!({"Resolved": [hi, "Miss"]}),
            Reply::Resolved(text(b"HI"), CacheStatus::Miss),
        ),
        ("Cached/true", json!({"Cached": true}), Reply::Cached(true)),
        (
            "Entries/none",
            json!({"Entries": null}),
            Reply::Entries(None),
        ),
        (
            "Entries/some",
            json!({"Entries": [{"pattern": "urn:test:upper", "endpoint": "upper", "origin": null}]}),
            Reply::Entries(Some(vec![SpaceEntry {
                pattern: "urn:test:upper".into(),
                endpoint: "upper".into(),
                origin: None,
            }])),
        ),
        (
            "Error",
            json!({"Error": "boom"}),
            Reply::Error("boom".into()),
        ),
        (
            "ResolvedTraced",
            json!({"ResolvedTraced": [hi, "Miss", [trace_event_value()]]}),
            Reply::ResolvedTraced(text(b"HI"), CacheStatus::Miss, vec![trace_event()]),
        ),
        (
            "ErrorTyped",
            json!({"ErrorTyped": {"Denied": "x"}}),
            Reply::ErrorTyped(WireError::Denied("x".into())),
        ),
    ];
    for (name, value, reply) in replies {
        out.push(vector(&format!("Reply/{name}"), "Reply", value, &reply));
    }
    out
}

/// The hello payloads: NOT postcard, `"IKWH"` + u32 big-endian version + u8 mode.
fn hellos() -> Vec<Value> {
    let hello = |name: &str, about: &str, hello: Hello, payload: Vec<u8>| {
        assert_eq!(decode_hello(&payload), Some(hello), "{name} decodes");
        json!({
            "name": name,
            "about": about,
            "version": hello.version,
            "mode": match hello.mode {
                HelloMode::Verbatim => "Verbatim",
                HelloMode::Alias => "Alias",
            },
            "payload": hex(&payload),
            "framed": hex(&framed(&payload)),
        })
    };
    let current = Hello {
        version: PROTOCOL_VERSION,
        mode: HelloMode::Verbatim,
    };
    let alias = Hello {
        version: PROTOCOL_VERSION,
        mode: HelloMode::Alias,
    };
    let oldest = Hello {
        version: MIN_PROTOCOL_VERSION,
        mode: HelloMode::Verbatim,
    };
    let answer = encode_hello(&current)[..8].to_vec();
    vec![
        hello(
            "client/verbatim",
            "a plain client's hello",
            current,
            encode_hello(&current),
        ),
        hello(
            "client/alias",
            "an alias mount's hello",
            alias,
            encode_hello(&alias),
        ),
        hello(
            "client/oldest",
            "the oldest version a current peer speaks",
            oldest,
            encode_hello(&oldest),
        ),
        hello(
            "server/answer",
            "a server's answer omits the mode byte; a reader defaults it to Verbatim",
            current,
            answer,
        ),
    ]
}

fn hello_bytes(version: u32) -> Vec<u8> {
    framed(&encode_hello(&Hello {
        version,
        mode: HelloMode::Verbatim,
    }))
}

/// The server's answer to an accepted hello: the peer's version, no mode byte.
fn answer_bytes(version: u32) -> Vec<u8> {
    framed(
        &encode_hello(&Hello {
            version,
            mode: HelloMode::Verbatim,
        })[..8],
    )
}

fn exchange(
    name: &str,
    peer_version: u32,
    about: &str,
    call: &Call,
    reply: Reply,
    call_value: Value,
) -> Value {
    let call_payload = encode(&call.as_sent_to(peer_version)).unwrap();
    let reply_payload = encode(&reply.for_peer(peer_version)).unwrap();
    let mut client = hello_bytes(peer_version);
    client.extend(framed(&call_payload));
    let mut server = answer_bytes(peer_version);
    server.extend(framed(&reply_payload));
    json!({
        "name": name,
        "transport": "ipc",
        "peer_version": peer_version,
        "about": about,
        "call": call_value,
        "call_payload": hex(&call_payload),
        "reply_payload": hex(&reply_payload),
        "client_writes": hex(&client),
        "server_writes": hex(&server),
    })
}

/// Whole IPC exchanges: each side's hello, then one framed call and its framed reply.
fn exchanges() -> Vec<Value> {
    let mut out = Vec::new();
    for verb in VERBS {
        let name = verb_name(verb);
        let reply = match verb {
            Verb::Source => Reply::Resolved(text(b"hello").cacheable(), CacheStatus::Miss),
            Verb::Sink => Reply::Resolved(text(b"stored"), CacheStatus::Uncacheable),
            Verb::Exists => Reply::Resolved(text(b"").cacheable(), CacheStatus::Hit),
            Verb::Delete => Reply::Resolved(text(b""), CacheStatus::Uncacheable),
            Verb::Meta => Reply::Resolved(
                Representation::new(ReprType::new("application/json"), b"{}".to_vec()),
                CacheStatus::Uncacheable,
            ),
        };
        out.push(exchange(
            &format!("v{PROTOCOL_VERSION}/{name}"),
            PROTOCOL_VERSION,
            "a call under the root capability (Call::IssueAs) and a representative answer",
            &Call::IssueAs(request_for(verb), Capability::root()),
            reply,
            json!({"IssueAs": [{"verb": name, "target": "urn:example:note", "args": {}}, "root"]}),
        ));
    }
    out.push(exchange(
        &format!("v{PROTOCOL_VERSION}/Source/not-found"),
        PROTOCOL_VERSION,
        "a failure crosses as Reply::ErrorTyped with its taxonomy",
        &Call::IssueAs(request_for(Verb::Source), Capability::root()),
        Reply::ErrorTyped(WireError::NotFound("no such note".into())),
        json!({"IssueAs": [{"verb": "Source", "target": "urn:example:note", "args": {}}, "root"]}),
    ));
    out.push(exchange(
        &format!("v{PROTOCOL_VERSION}/IsCached"),
        PROTOCOL_VERSION,
        "whether the server's cache holds an answer",
        &Call::IsCached(request_for(Verb::Source)),
        Reply::Cached(false),
        json!({"IsCached": {"verb": "Source", "target": "urn:example:note", "args": {}}}),
    ));
    out.push(exchange(
        &format!("v{PROTOCOL_VERSION}/Entries"),
        PROTOCOL_VERSION,
        "the server's bindings",
        &Call::Entries,
        Reply::Entries(Some(vec![SpaceEntry {
            pattern: "urn:example:note".into(),
            endpoint: "note".into(),
            origin: None,
        }])),
        json!("Entries"),
    ));
    out.push(exchange(
        &format!("v{PROTOCOL_VERSION}/IssueTraced"),
        PROTOCOL_VERSION,
        "a recorded call, answered with the server's spans",
        &Call::IssueTraced(
            read_request(),
            Capability::root(),
            TraceContext {
                trace_id: 7,
                parent_span: None,
            },
        ),
        Reply::ResolvedTraced(text(b"HI"), CacheStatus::Miss, vec![trace_event()]),
        json!({"IssueTraced": [
            {"verb": "Source", "target": "urn:test:upper", "args": {"in": {"Inline": {"hex": "6869"}}}},
            "root",
            {"trace_id": 7, "parent_span": null},
        ]}),
    ));
    let with = Call::IssueWith(
        request_for(Verb::Source),
        Capability::scoped(["urn:cap:a"]),
        IssueWith {
            trace: None,
            retries: Some(1),
            time_left_ms: Some(1_500),
        },
    );
    let with_value = json!({"IssueWith": [
        {"verb": "Source", "target": "urn:example:note", "args": {}},
        {"scoped": ["urn:cap:a"]},
        {"trace": null, "retries": 1, "time_left_ms": 1500},
    ]});
    out.push(exchange(
        &format!("v{PROTOCOL_VERSION}/IssueWith"),
        PROTOCOL_VERSION,
        "a call carrying its run's context, answered with a typed RetryAfter",
        &with,
        Reply::ErrorTyped(WireError::RetryAfter {
            delay_ms: Some(2_000),
            detail: "rate-limited".into(),
        }),
        with_value.clone(),
    ));
    // The same exchange with a v8 peer: the call goes as the IssueAs it has always served,
    // the error as the Endpoint text it has always received.
    out.push(exchange(
        "v8/IssueWith",
        8,
        "to a v8 peer the run context is dropped (Call::for_peer) and a v9 error crosses as Endpoint(display) (Reply::for_peer)",
        &with,
        Reply::ErrorTyped(WireError::RetryAfter {
            delay_ms: Some(2_000),
            detail: "rate-limited".into(),
        }),
        with_value,
    ));
    out.push(exchange(
        "v7/Conflict",
        7,
        "to a v7 peer a Conflict crosses as Endpoint(\"conflict: …\")",
        &Call::IssueAs(request_for(Verb::Sink), Capability::root()),
        Reply::ErrorTyped(WireError::Conflict("x".into())),
        json!({"IssueAs": [{"verb": "Sink", "target": "urn:example:note", "args": {}}, "root"]}),
    ));
    out
}

fn computed() -> Value {
    json!({
        "about": "The ikigai wire's shared vectors (ikigai-wire, ledger #3165), computed by \
                  crates/ikigai-wire/tests/wire_vectors.rs, which fails if this file differs \
                  from what the codec writes. Faces copy this file verbatim. Hex is lowercase. \
                  `postcard` holds the postcard bytes of each type that crosses the wire, named \
                  by `type`; `value` describes the value in JSON (a u64 past 2^53 is a decimal \
                  string; bytes are {\"hex\": …} or {\"utf8\": …}; an enum is its variant name, \
                  or an object naming it; a Capability is \"root\" or {\"scoped\": [...]}). \
                  `hello` holds the hello payloads, which are NOT postcard: \"IKWH\", a u32 \
                  big-endian version, a u8 mode (0 Verbatim, 1 Alias), trailing bytes ignored. \
                  `exchanges` holds whole IPC exchanges: each side's framed hello, then one \
                  framed call and one framed reply; every frame is a u32 big-endian length, \
                  then the payload. The streamed frames of wire v10 are stream_frames.json.",
        "protocol_version": PROTOCOL_VERSION,
        "min_protocol_version": MIN_PROTOCOL_VERSION,
        "hello_magic": hex(&HELLO_MAGIC),
        "max_frame": MAX_FRAME,
        "postcard": postcard(),
        "hello": hellos(),
        "exchanges": exchanges(),
    })
}

#[test]
fn the_wire_vectors_file_is_what_the_codec_writes() {
    let computed = format!(
        "{}\n",
        serde_json::to_string_pretty(&computed()).expect("vectors render")
    );
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTORS);
    if std::env::var_os("IKIGAI_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &computed).unwrap();
        return;
    }
    let on_disk = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{VECTORS}: {e}; run with IKIGAI_BLESS=1 to write it"));
    assert!(
        on_disk == computed,
        "{VECTORS} differs from what the codec writes; if the wire change is deliberate, \
         rerun with IKIGAI_BLESS=1 and review the diff"
    );
}

/// The faces read the file, not this test: so every vector in it must decode as its type
/// and encode back to the same bytes, every hello must decode, and every exchange must be
/// the frames it names.
#[test]
fn every_vector_in_the_file_decodes_as_its_type() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTORS);
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for vector in file["postcard"].as_array().unwrap() {
        let bytes = unhex(vector["hex"].as_str().unwrap());
        let ty = vector["type"].as_str().unwrap();
        assert_eq!(reencode(ty, &bytes), bytes, "{}", vector["name"]);
    }
    for hello in file["hello"].as_array().unwrap() {
        let decoded = decode_hello(&unhex(hello["payload"].as_str().unwrap())).unwrap();
        assert_eq!(
            u64::from(decoded.version),
            hello["version"].as_u64().unwrap()
        );
    }
    for exchange in file["exchanges"].as_array().unwrap() {
        let version = exchange["peer_version"].as_u64().unwrap() as u32;
        let mut client = hello_bytes(version);
        let call = unhex(exchange["call_payload"].as_str().unwrap());
        decode::<Call>(&call).unwrap();
        client.extend(framed(&call));
        assert_eq!(
            hex(&client),
            exchange["client_writes"].as_str().unwrap(),
            "{}",
            exchange["name"]
        );
        let mut server = answer_bytes(version);
        let reply = unhex(exchange["reply_payload"].as_str().unwrap());
        decode::<Reply>(&reply).unwrap();
        server.extend(framed(&reply));
        assert_eq!(
            hex(&server),
            exchange["server_writes"].as_str().unwrap(),
            "{}",
            exchange["name"]
        );
    }
}

/// The file agrees with the byte literals the faces pinned before it existed (ikigai-python's
/// test_wire.py and test_hello.py), so a face that switches to the file changes no vector.
#[test]
fn the_file_agrees_with_the_faces_older_literals() {
    let by_name = |name: &str| -> String {
        postcard()
            .into_iter()
            .find(|v| v["name"] == name)
            .unwrap_or_else(|| panic!("no vector {name}"))["hex"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(by_name("Call/Entries"), "02");
    assert_eq!(
        by_name("Call/Issue"),
        hex(b"\x00\x00\x0eurn:test:upper\x01\x02in\x01\x02hi")
    );
    assert_eq!(
        by_name("Reply/Resolved"),
        hex(b"\x00\x0atext/plain\x00\x02HI\x00\x01")
    );
    assert_eq!(by_name("Reply/ErrorTyped"), hex(b"\x05\x04\x01x"));
    assert_eq!(by_name("WireError/Conflict"), "080178");
    assert_eq!(by_name("u32/300"), "ac02");
    assert_eq!(by_name("u64/max"), "ffffffffffffffffff01");
    let alias = encode_hello(&Hello {
        version: 7,
        mode: HelloMode::Alias,
    });
    assert_eq!(alias, b"IKWH\x00\x00\x00\x07\x01");
}
