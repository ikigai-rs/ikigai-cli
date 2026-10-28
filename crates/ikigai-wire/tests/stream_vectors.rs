//! The wire v10 stream vectors (ledger #2242): the bytes of a head, a chunk, END and an
//! ABORT for each failure class, in both directions, plus whole exchanges (a streamed
//! answer, a streamed call, and the collected answer a v9 and a v8 peer get instead).
//!
//! `tests/vectors/stream_frames.json` is what the faces (ikigai-python, ikigai-deno,
//! ikigai-dotnet, cms-web's WebTransport client) pin VERBATIM. This test computes every
//! vector from the codec and fails if the file differs, so the file cannot drift from the
//! code; it also decodes every payload back to the value it came from. To regenerate after
//! a deliberate wire change, run it with `IKIGAI_BLESS=1` and review the diff.

use ikigai_core::{Capability, Error, Expiry, Iri, ReprType, Representation, Request, Verb};
use ikigai_resolve::CacheStatus;
use ikigai_wire::{
    decode_call_frame, decode_reply_frame, encode, encode_call_frame, encode_reply_for_peer,
    encode_reply_frame, BodyFrame, BodyHead, Call, CallFrame, CallHead, IssueWith, Reply,
    ReplyFrame, ReplyHead, WireError, MAX_CHUNK, PROTOCOL_VERSION, STREAM_MAGIC,
};
use serde_json::{json, Value};

const VECTORS: &str = "tests/vectors/stream_frames.json";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `payload` as the IPC socket frames it: a `u32` big-endian length, then the payload.
fn framed(payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

fn upload_request() -> Request {
    Request::new(Verb::Sink, Iri::parse("urn:example:upload").unwrap())
}

fn read_request() -> Request {
    Request::new(Verb::Source, Iri::parse("urn:example:report").unwrap())
}

fn call_head(body: Option<BodyHead>, request: Request) -> CallHead {
    CallHead {
        request,
        capability: Capability::root(),
        with: IssueWith::default(),
        body,
    }
}

fn reply_head() -> ReplyHead {
    ReplyHead {
        representation: Representation::new(
            ReprType::new("text/plain").with_param("charset", "utf-8"),
            Vec::new(),
        )
        .cacheable()
        .map_body(|_| ()),
        status: CacheStatus::Miss,
        len: Some(11),
    }
}

/// One ABORT per failure class (core's `FailureClass`), with the error that carries it.
fn aborts() -> Vec<(&'static str, Error)> {
    use std::time::Duration;
    vec![
        (
            "transient/timeout",
            Error::Timeout("the producer stalled".into()),
        ),
        (
            "transient/unavailable",
            Error::Unavailable("the origin went away".into()),
        ),
        (
            "retry-after",
            Error::RetryAfter {
                delay: Some(Duration::from_secs(2)),
                detail: "rate-limited".into(),
            },
        ),
        (
            "over-budget",
            Error::OverBudget {
                detail: "the stream ran past its run's deadline (5000 ms)".into(),
            },
        ),
        ("denied", Error::Denied("needs urn:cap:example".into())),
        (
            "refused",
            Error::Refused("api.example.com answered 401".into()),
        ),
        ("permanent", Error::Conflict("changed while read".into())),
        ("unknown", Error::Endpoint("the producer failed".into())),
    ]
}

fn describe_error(error: &Error) -> Value {
    json!({
        "class": error.class().word(),
        "display": error.to_string(),
    })
}

/// Every frame vector: its name, direction, a description of the value, and the frame.
fn frames() -> Vec<(String, &'static str, Value, Payload)> {
    let mut out = Vec::new();
    out.push((
        "call/head/answer-only".to_string(),
        "call",
        json!({
            "kind": "head",
            "request": {"verb": "Source", "target": "urn:example:report", "args": {}},
            "capability": "root",
            "with": {"trace": null, "retries": null, "time_left_ms": null},
            "body": null,
        }),
        Payload::Call(CallFrame::Head(call_head(None, read_request()))),
    ));
    out.push((
        "call/head/with-body".to_string(),
        "call",
        json!({
            "kind": "head",
            "request": {"verb": "Sink", "target": "urn:example:upload", "args": {}},
            "capability": "root",
            "with": {"trace": null, "retries": 1, "time_left_ms": 1500},
            "body": {"arg": "content", "len": 5},
        }),
        Payload::Call(CallFrame::Head(CallHead {
            with: IssueWith {
                trace: None,
                retries: Some(1),
                time_left_ms: Some(1_500),
            },
            ..call_head(
                Some(BodyHead {
                    arg: "content".into(),
                    len: Some(5),
                }),
                upload_request(),
            )
        })),
    ));
    out.push((
        "reply/head".to_string(),
        "reply",
        json!({
            "kind": "head",
            "repr_type": "text/plain",
            "params": {"charset": "utf-8"},
            "expiry": "Never",
            "status": "Miss",
            "len": 11,
        }),
        Payload::Reply(ReplyFrame::Head(reply_head())),
    ));
    out.push((
        "reply/head/unknown-length".to_string(),
        "reply",
        json!({
            "kind": "head",
            "repr_type": "application/octet-stream",
            "params": {},
            "expiry": "Always",
            "status": "Uncacheable",
            "len": null,
        }),
        Payload::Reply(ReplyFrame::Head(ReplyHead {
            representation: Representation::new(
                ReprType::new("application/octet-stream"),
                Vec::new(),
            )
            .with_expiry(Expiry::Always)
            .map_body(|_| ()),
            status: CacheStatus::Uncacheable,
            len: None,
        })),
    ));
    for direction in ["call", "reply"] {
        let body = |frame: BodyFrame| match direction {
            "call" => Payload::Call(CallFrame::Body(frame)),
            _ => Payload::Reply(ReplyFrame::Body(frame)),
        };
        out.push((
            format!("{direction}/chunk"),
            direction,
            json!({"kind": "chunk", "utf8": "hello"}),
            body(BodyFrame::Chunk(b"hello"[..].into())),
        ));
        out.push((
            format!("{direction}/chunk/empty"),
            direction,
            json!({"kind": "chunk", "utf8": ""}),
            body(BodyFrame::Chunk(Default::default())),
        ));
        out.push((
            format!("{direction}/end"),
            direction,
            json!({"kind": "end"}),
            body(BodyFrame::End),
        ));
        for (class, error) in aborts() {
            out.push((
                format!("{direction}/abort/{class}"),
                direction,
                json!({"kind": "abort", "error": describe_error(&error)}),
                body(BodyFrame::Abort(WireError::from(&error))),
            ));
        }
    }
    out
}

enum Payload {
    Call(CallFrame),
    Reply(ReplyFrame),
}

impl Payload {
    fn encode(&self) -> Vec<u8> {
        match self {
            Payload::Call(frame) => encode_call_frame(frame).unwrap(),
            Payload::Reply(frame) => encode_reply_frame(frame).unwrap(),
        }
    }

    /// Decoding the payload gives back the value it was encoded from.
    fn round_trips(&self, bytes: &[u8]) -> bool {
        match self {
            Payload::Call(frame) => decode_call_frame(bytes).unwrap() == *frame,
            Payload::Reply(frame) => decode_reply_frame(bytes).unwrap() == *frame,
        }
    }
}

fn concat(frames: &[Vec<u8>]) -> Vec<u8> {
    frames.iter().flat_map(|f| framed(f)).collect()
}

/// Whole exchanges, as the bytes each side writes after the hello.
fn exchanges() -> Vec<Value> {
    let answer_head = encode_reply_frame(&ReplyFrame::Head(reply_head())).unwrap();
    let chunk = |text: &[u8]| {
        encode_reply_frame(&ReplyFrame::Body(BodyFrame::Chunk(text.to_vec().into()))).unwrap()
    };
    let end = encode_reply_frame(&ReplyFrame::Body(BodyFrame::End)).unwrap();
    let ask = encode_call_frame(&CallFrame::Head(call_head(None, read_request()))).unwrap();

    let upload = encode_call_frame(&CallFrame::Head(call_head(
        Some(BodyHead {
            arg: "content".into(),
            len: Some(5),
        }),
        upload_request(),
    )))
    .unwrap();
    let up_chunk =
        encode_call_frame(&CallFrame::Body(BodyFrame::Chunk(b"hello"[..].into()))).unwrap();
    let up_end = encode_call_frame(&CallFrame::Body(BodyFrame::End)).unwrap();
    let stored = encode_reply_frame(&ReplyFrame::Reply(Reply::Resolved(
        Representation::new(ReprType::new("text/plain"), b"stored".to_vec()),
        CacheStatus::Uncacheable,
    )))
    .unwrap();

    let aborted_detail = "the stream ran past its run's deadline (5000 ms)";
    let abort = encode_reply_frame(&ReplyFrame::Body(BodyFrame::Abort(WireError::OverBudget(
        aborted_detail.into(),
    ))))
    .unwrap();

    // The collected answer an older peer gets for a body past one frame: the server's
    // refusal, for a v9 peer typed, for a v8 peer the Endpoint text it has always received.
    let plain = encode(&Call::IssueAs(read_request(), Capability::root())).unwrap();
    let too_big = || {
        Reply::Resolved(
            Representation::new(
                ReprType::new("application/octet-stream"),
                vec![0u8; ikigai_wire::MAX_FRAME],
            ),
            CacheStatus::Uncacheable,
        )
    };
    let for_v9 = encode_reply_for_peer(too_big(), 9).unwrap();
    let for_v8 = encode_reply_for_peer(too_big(), 8).unwrap();

    let mut quic_call = STREAM_MAGIC.to_vec();
    quic_call.extend(concat(std::slice::from_ref(&ask)));

    vec![
        json!({
            "name": "v10/streamed-answer",
            "transport": "ipc",
            "peer_version": 10,
            "about": "a read asking for a streamed answer, answered with a head, two chunks and END",
            "client_writes": hex(&concat(std::slice::from_ref(&ask))),
            "server_writes": hex(&concat(&[answer_head.clone(), chunk(b"hello "), chunk(b"world"), end.clone()])),
        }),
        json!({
            "name": "v10/streamed-answer/quic",
            "transport": "quic",
            "peer_version": 10,
            "about": "the same exchange on one QUIC stream: the client's stream opens with the magic, then the same frames; each side then FINs its half",
            "client_writes": hex(&quic_call),
            "server_writes": hex(&concat(&[answer_head.clone(), chunk(b"hello "), chunk(b"world"), end])),
        }),
        json!({
            "name": "v10/streamed-answer/aborted",
            "transport": "ipc",
            "peer_version": 10,
            "about": "the producer fails part-way: the answer ends in an ABORT carrying OverBudget, and the chunk before it is not a body",
            "client_writes": hex(&concat(&[ask])),
            "server_writes": hex(&concat(&[answer_head, chunk(b"hello "), abort])),
        }),
        json!({
            "name": "v10/streamed-call",
            "transport": "ipc",
            "peer_version": 10,
            "about": "a Sink whose content is the caller's body: a head announcing 5 bytes, one chunk, END; answered with one plain Reply frame",
            "client_writes": hex(&concat(&[upload, up_chunk, up_end])),
            "server_writes": hex(&concat(&[stored])),
        }),
        json!({
            "name": "v9/collected-answer-over-budget",
            "transport": "ipc",
            "peer_version": 9,
            "about": "a v9 peer sends a plain call and gets the collected answer; past one frame, a typed OverBudget",
            "client_writes": hex(&framed(&plain)),
            "server_writes": hex(&framed(&for_v9)),
        }),
        json!({
            "name": "v8/collected-answer-over-budget",
            "transport": "ipc",
            "peer_version": 8,
            "about": "the same for a v8 peer: the refusal as the Endpoint text a v8 peer has always received",
            "client_writes": hex(&framed(&plain)),
            "server_writes": hex(&framed(&for_v8)),
        }),
    ]
}

fn computed() -> Value {
    let frames: Vec<Value> = frames()
        .into_iter()
        .map(|(name, direction, value, payload)| {
            let bytes = payload.encode();
            assert!(payload.round_trips(&bytes), "{name} round-trips");
            json!({
                "name": name,
                "direction": direction,
                "value": value,
                "payload": hex(&bytes),
                "framed": hex(&framed(&bytes)),
            })
        })
        .collect();
    json!({
        "about": "Wire v10 stream frames (ikigai-wire, ledger #2242), computed by \
                  crates/ikigai-wire/tests/stream_vectors.rs, which fails if this file differs \
                  from what the codec writes. Hex is lowercase. `payload` is a frame's bytes; \
                  `framed` adds the u32 big-endian length every frame carries on the IPC socket \
                  and on a QUIC stream of frames (which opens with `stream_magic`). Tags 6 to 9 \
                  are the same in both directions: head, chunk (a varint length, then the bytes, \
                  at most `max_chunk`), end, abort (a WireError). A body is whole only at END; \
                  a stream that stops without it is a failure, never a shorter body. Each abort \
                  is named by its error's failure class.",
        "protocol_version": PROTOCOL_VERSION,
        "max_chunk": MAX_CHUNK,
        "stream_magic": hex(&STREAM_MAGIC),
        "frames": frames,
        "exchanges": exchanges(),
    })
}

#[test]
fn the_stream_vectors_file_is_what_the_codec_writes() {
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

/// The faces read the file, not this test: so every payload in it must decode, in its
/// direction, to a frame of the kind its `value` names.
#[test]
fn every_vector_in_the_file_decodes_to_its_kind() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTORS);
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for frame in file["frames"].as_array().unwrap() {
        let bytes = unhex(frame["payload"].as_str().unwrap());
        let kind = frame["value"]["kind"].as_str().unwrap();
        let decoded = match frame["direction"].as_str().unwrap() {
            "call" => match decode_call_frame(&bytes).unwrap() {
                CallFrame::Head(_) => "head",
                CallFrame::Body(body) => body_kind(&body),
                _ => "plain",
            },
            _ => match decode_reply_frame(&bytes).unwrap() {
                ReplyFrame::Head(_) => "head",
                ReplyFrame::Body(body) => body_kind(&body),
                _ => "plain",
            },
        };
        assert_eq!(decoded, kind, "{}", frame["name"]);
    }
}

fn body_kind(frame: &BodyFrame) -> &'static str {
    match frame {
        BodyFrame::Chunk(_) => "chunk",
        BodyFrame::End => "end",
        BodyFrame::Abort(_) => "abort",
        _ => "unknown",
    }
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// A decoder that predates v10 (what a v9 server or client runs) refuses every new frame
/// as an unknown variant: a peer that negotiated v10 without the frames' code fails cleanly
/// and never reads a frame as some other call or reply.
#[test]
fn a_pre_v10_decoder_refuses_every_frame_cleanly() {
    for (name, _, _, payload) in frames() {
        let bytes = payload.encode();
        let refused = match payload {
            Payload::Call(_) => ikigai_wire::decode::<Call>(&bytes).is_err(),
            Payload::Reply(_) => ikigai_wire::decode::<Reply>(&bytes).is_err(),
        };
        assert!(refused, "{name} must not decode as a plain message");
    }
    // And no plain call starts with the QUIC stream magic's first byte.
    assert!(STREAM_MAGIC[0] > 9);
}
