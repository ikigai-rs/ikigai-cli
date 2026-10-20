//! The layers HTTPS front (ledger #1371), through the REAL binary: `serve quic://127.0.0.1:0
//! --layers-https 127.0.0.1:0` on one scratch host, participants over HTTPS (a bearer token
//! minted with `ikigai layers-token mint`) and over QUIC (a client certificate) at once.
//!
//! What is proved is that the two faces are one authority: the same layers, the same refusals,
//! the same receipts, one winner in a race between them, and the gateway protocol between
//! kernels end to end with one side speaking only HTTP and JSON.
//!
//! ★ Every door binds port 0 for both faces and the test reads the bound ports off its banner
//! (field guide 9h, ledger #1223). HERMETIC by the child's environment, as `layers_serve.rs`
//! is: `HOME`, `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set on each spawned process only.
#![cfg(all(feature = "embedded", feature = "quic", feature = "web", unix))]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{mpsc, Arc, Barrier};
use std::time::{Duration, Instant};

use ikigai_core::{ArgRef, Error, Iri, Representation, Request, Verb};
use ikigai_resolve::Resolver as _;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How long a door gets to print its banner. A watchdog, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

const ALICE: &str = "urn:collab:participant:alice";
const BOB: &str = "urn:collab:participant:bob";
const CAROL: &str = "urn:collab:participant:carol";

/// The wall clock, for this suite's deadlines and its one elapsed-time assertion. The workspace
/// bans `Instant::now` because it panics on wasm32; this suite runs a native binary over the
/// network and never builds for wasm.
#[allow(clippy::disallowed_methods)]
fn now() -> Instant {
    Instant::now()
}

/// A child killed when the test ends, whatever the test does.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn config_home(home: &Path) -> PathBuf {
    home.join("config").join("ikigai")
}

fn spawn(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .env_remove("IKIGAI_CLIENTS")
        .env_remove("IKIGAI_GRANTS");
    command
}

fn run(home: &Path, args: &[&str]) -> Output {
    spawn(home, args)
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs")
}

fn ok(out: Output, what: &str) -> String {
    assert!(
        out.status.success(),
        "{what} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// A throwaway age identity at `path`, as `age-keygen -o` writes one: the key the layer host
/// seals its state to (ikigai-layers 0.3.0, ledger #2011). Kept when it is already there, so a
/// restarted door opens what the first one sealed.
fn mint_key(path: &Path) {
    if !path.exists() {
        let identity = age::x25519::Identity::generate();
        std::fs::write(
            path,
            age::secrecy::ExposeSecret::expose_secret(&identity.to_string()),
        )
        .unwrap();
    }
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

const SHAPES: &str = r#"@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix ik: <https://ikigai-rs.dev/ns#> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix dcterms: <http://purl.org/dc/terms/> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

<urn:example:shape:message> a sh:NodeShape ;
  sh:targetClass ik:Message ;
  sh:closed true ;
  sh:ignoredProperties ( rdf:type ) ;
  sh:property [ sh:path ik:body ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:string ] ,
              [ sh:path prov:wasAttributedTo ; sh:minCount 1 ; sh:maxCount 1 ; sh:nodeKind sh:IRI ] ,
              [ sh:path dcterms:created ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:dateTime ] ,
              [ sh:path ik:seq ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:integer ] .

<urn:example:shape:offer> a sh:NodeShape ;
  sh:targetClass ik:Offer ;
  sh:closed true ;
  sh:ignoredProperties ( rdf:type ) ;
  sh:property [ sh:path dcterms:title ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:string ] ,
              [ sh:path ik:brief ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:string ] ,
              [ sh:path prov:wasAttributedTo ; sh:minCount 1 ; sh:maxCount 1 ; sh:nodeKind sh:IRI ] ,
              [ sh:path dcterms:created ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:dateTime ] ,
              [ sh:path ik:seq ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:integer ] .
"#;

/// The egress context: the shipped contexts' stamp terms, word for word as the host defines
/// them, beside the layer's own.
const CONTEXT: &str = r#"{ "@context": {
  "ik": "https://ikigai-rs.dev/ns#",
  "dcterms": "http://purl.org/dc/terms/",
  "prov": "http://www.w3.org/ns/prov#",
  "xsd": "http://www.w3.org/2001/XMLSchema#",
  "Message": "ik:Message", "Offer": "ik:Offer",
  "body": "ik:body", "title": "dcterms:title", "brief": "ik:brief",
  "attributedTo": { "@id": "prov:wasAttributedTo", "@type": "@id" },
  "created": { "@id": "dcterms:created", "@type": "xsd:dateTime" },
  "seq": { "@id": "ik:seq", "@type": "xsd:integer" }
} }
"#;

/// One scratch host: the door, both its addresses, and what a participant needs to reach it.
struct Host {
    home: PathBuf,
    certs: PathBuf,
    _door: Door,
    quic: SocketAddr,
    https: String,
    server_pem: String,
}

/// Configure and start a host. Layers:
///
/// - `talk` (a channel) and `tasks` (an addressed tuplespace), mounted by `pair`: alice, bob
///   and carol read, follow, say, drop and take;
/// - `side` (a channel), mounted by `solo`: alice alone;
/// - `gw` (an addressed tuplespace with the gateway's shapes and context), mounted by
///   `gateway`: alice and bob.
fn host(case: &str) -> Host {
    let home = std::env::temp_dir().join(format!("iki-lh-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let config = config_home(&home);
    std::fs::create_dir_all(&config).unwrap();
    let certs = home.join("certs");
    let d = certs.to_str().unwrap();
    ok(
        run(&home, &["cert", "generate", "--dir", d]),
        "cert generate",
    );
    for name in ["alice", "bob", "carol"] {
        ok(
            run(&home, &["cert", "add-client", name, "--cert-dir", d]),
            "cert add-client",
        );
    }
    write(config.join("layers/shapes.ttl"), SHAPES);
    write(config.join("layers/context.jsonld"), CONTEXT);
    write(
        config.join("layers/gateway.shapes.ttl"),
        ikigai_layers::gateway::SHAPES,
    );
    write(
        config.join("layers/gateway.context.jsonld"),
        ikigai_layers::gateway::CONTEXT,
    );
    let channel = "model = \"channel\"\nshapes = \"shapes.ttl\"\ncontext = \"context.jsonld\"\n";
    write(config.join("layers/talk.toml"), channel);
    write(config.join("layers/side.toml"), channel);
    write(
        config.join("layers/tasks.toml"),
        "model = \"tuplespace\"\nshapes = \"shapes.ttl\"\ncontext = \"context.jsonld\"\naddressed = true\n",
    );
    write(
        config.join("layers/gw.toml"),
        "model = \"tuplespace\"\nshapes = \"gateway.shapes.ttl\"\ncontext = \"gateway.context.jsonld\"\naddressed = true\n",
    );
    write(
        config.join("participants.ttl"),
        &format!(
            "@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n<{ALICE}> a foaf:Person .\n<{BOB}> a foaf:Person .\n<{CAROL}> a foaf:Person .\n"
        ),
    );
    let all = "[\"read\", \"feed\", \"say\"]";
    let work = "[\"read\", \"feed\", \"out\", \"take\"]";
    write(
        config.join("collabs/pair.toml"),
        &format!(
            "[[mount]]\nlayer = \"talk\"\nalice = {all}\nbob = {all}\ncarol = {all}\n\n\
             [[mount]]\nlayer = \"tasks\"\nalice = {work}\nbob = {work}\ncarol = {work}\n"
        ),
    );
    write(
        config.join("collabs/solo.toml"),
        &format!("[[mount]]\nlayer = \"side\"\nalice = {all}\n"),
    );
    write(
        config.join("collabs/gateway.toml"),
        &format!("[[mount]]\nlayer = \"gw\"\nalice = {work}\nbob = {work}\n"),
    );
    let fp = |name: &str| {
        let pem = std::fs::read_to_string(certs.join(format!("clients/{name}.crt"))).unwrap();
        ikigai_quic::fingerprint_of_pem(&pem).unwrap()
    };
    write(
        config.join("enrollment.toml"),
        &format!(
            "alice = \"{}\"\nbob = \"{}\"\ncarol = \"{}\"\n",
            fp("alice"),
            fp("bob"),
            fp("carol")
        ),
    );
    let loaded = ikigai_layers::Config::load(&config).expect("the configuration checks");
    let fingerprints: BTreeMap<String, BTreeSet<String>> =
        ikigai_layers::grants::load_fingerprints(&config, &loaded).expect("enrollment.toml");
    let enrollment =
        ikigai_layers::grants::generate(&loaded, &fingerprints).expect("an enrollment");
    enrollment
        .write(&config)
        .expect("grants.json and clients.json");

    let key = home.join("state.key");
    mint_key(&key);
    let args = [
        "serve",
        "quic://127.0.0.1:0",
        "--name",
        "layers",
        "--cert-dir",
        d,
        "--layers-key",
        key.to_str().unwrap(),
        "--layers-https",
        "127.0.0.1:0",
    ];
    let mut child = spawn(&home, &args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the door starts");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut seen = String::new();
        let mut lines = BufReader::new(stderr).lines().map_while(Result::ok);
        for line in lines.by_ref() {
            seen.push_str(&line);
            seen.push('\n');
            if line.contains("serving on") {
                break;
            }
        }
        let _ = tx.send(seen);
        lines.for_each(drop);
    });
    let door = Door(child);
    let seen = rx
        .recv_timeout(PATIENCE)
        .unwrap_or_else(|e| panic!("the door never printed its banner: {e}"));
    let after = |marker: &str| {
        seen.lines()
            .find_map(|line| line.split(marker).nth(1))
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or_else(|| panic!("no `{marker}` in the banner:\n{seen}"))
            .to_string()
    };
    let quic = after("serving on quic://");
    let https = after("layers https on https://");
    assert!(
        !quic.ends_with(":0") && !https.ends_with(":0"),
        "the banner names BOUND ports: {quic} {https}"
    );
    Host {
        server_pem: std::fs::read_to_string(certs.join("server.crt")).unwrap(),
        quic: quic.parse().unwrap(),
        https,
        home,
        certs,
        _door: door,
    }
}

impl Host {
    /// Mint a token for `participant` with the operator's own command.
    fn mint(&self, participant: &str) -> String {
        ok(
            run(&self.home, &["layers-token", "mint", participant]),
            "layers-token mint",
        )
        .trim()
        .to_string()
    }

    /// A QUIC participant: `name`'s certificate, the door's server certificate pinned.
    fn quic(&self, name: &str) -> ikigai_quic::QuicResolver {
        let read = |file: String| std::fs::read_to_string(self.certs.join(file)).unwrap();
        let identity = ikigai_quic::Identity {
            cert_pem: read(format!("clients/{name}.crt")),
            key_pem: read(format!("clients/{name}.key")),
        };
        ikigai_quic::connect(self.quic, &identity, &self.server_pem).expect("a QUIC participant")
    }

    /// One HTTPS request, the door's certificate pinned.
    fn https(&self, method: &str, path: &str, token: Option<&str>, body: &[u8]) -> Http {
        https(&self.https, &self.server_pem, method, path, token, body)
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// An HTTP answer.
#[derive(Debug)]
struct Http {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Http {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| {
            panic!(
                "not JSON ({e}): {} {}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_string())
        })
    }
}

fn https(
    addr: &str,
    server_pem: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &[u8],
) -> Http {
    https_full(addr, server_pem, method, path, token, &[], body)
}

fn https_full(
    addr: &str,
    server_pem: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Http {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let tls = ikigai_quic::pinned_https_client_tls(server_pem).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from("ikigai").unwrap();
        let mut stream = connector
            .connect(name, tcp)
            .await
            .expect("TLS with the pinned certificate");
        let mut request =
            format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
        if let Some(token) = token {
            request.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        for (name, value) in extra {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        stream.flush().await.unwrap();
        let mut out = Vec::new();
        let _ = stream.read_to_end(&mut out).await;
        let end = out
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap_or_else(|| panic!("no HTTP head in {:?}", String::from_utf8_lossy(&out)));
        let head = String::from_utf8_lossy(&out[..end]).to_string();
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("no status in {head}"));
        Http {
            status,
            head,
            body: out[end + 4..].to_vec(),
        }
    })
}

/// Percent-encode a query value (an IRI keeps its `:`).
fn enc(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// A request with inline arguments.
fn request(verb: Verb, iri: &str, args: &[(&str, &str)]) -> Request {
    let mut request = Request::new(verb, Iri::parse(iri).unwrap());
    for (name, value) in args {
        request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
    }
    request
}

fn issue(
    quic: &ikigai_quic::QuicResolver,
    verb: Verb,
    iri: &str,
    args: &[(&str, &str)],
) -> Result<Representation, Error> {
    quic.issue(request(verb, iri, args)).map(|(repr, _)| repr)
}

fn json_of(repr: &Representation) -> Value {
    serde_json::from_slice(&repr.bytes).unwrap()
}

/// An offer in `tasks`, as Turtle.
fn offer(id: &str, title: &str) -> String {
    format!(
        "@prefix ik: <https://ikigai-rs.dev/ns#> .\n@prefix dcterms: <http://purl.org/dc/terms/> .\n\
         <urn:layer:tasks:offer:{id}> a ik:Offer ; dcterms:title \"{title}\" ; ik:brief \"b\" ."
    )
}

#[test]
fn http_and_quic_participants_see_the_same_layers_refusals_and_receipts() {
    let host = host("same");
    let bob = host.mint(BOB);
    let alice = host.quic("alice");
    let bob_quic = host.quic("bob");

    // Who the door says the caller is: the same answer through either face.
    let me = host.https("GET", "/layers/me", Some(&bob), b"");
    assert_eq!(me.status, 200, "{}", String::from_utf8_lossy(&me.body));
    let over_quic = json_of(
        &issue(
            &bob_quic,
            Verb::Source,
            "urn:layers:me",
            &[("as", "application/json")],
        )
        .unwrap(),
    );
    assert_eq!(me.json(), over_quic);
    assert_eq!(me.json()["principal"], BOB);

    // A say over HTTP, as plain JSON under the layer's context; read back over QUIC.
    let said = host.https(
        "POST",
        "/layer/talk/say",
        Some(&bob),
        br#"{"@id": "urn:layer:new", "@type": "Message", "body": "from HTTP"}"#,
    );
    assert_eq!(said.status, 200, "{}", String::from_utf8_lossy(&said.body));
    let entry = said.json()["@id"].as_str().unwrap().to_string();
    assert!(entry.starts_with("urn:layer:talk:entry:"), "{entry}");
    issue(
        &alice,
        Verb::Sink,
        "urn:layer:talk:say",
        &[(
            "content",
            "@prefix ik: <https://ikigai-rs.dev/ns#> .\n<urn:layer:new> a ik:Message ; ik:body \"from QUIC\" .",
        )],
    )
    .unwrap();
    let over_http = host.https("GET", "/layer/talk/entries", Some(&bob), b"");
    assert_eq!(over_http.status, 200);
    assert_eq!(
        over_http.header("content-type").as_deref(),
        Some("application/ld+json")
    );
    let read_quic = json_of(
        &issue(
            &alice,
            Verb::Source,
            "urn:layer:talk:entries",
            &[("as", "application/ld+json")],
        )
        .unwrap(),
    );
    assert_eq!(
        over_http.json(),
        read_quic,
        "one layer, whichever face reads it"
    );
    let graph = over_http.json()["@graph"].as_array().unwrap().clone();
    assert_eq!(graph.len(), 2);
    assert_eq!(graph[0]["@id"], entry.as_str());
    assert_eq!(
        graph[0]["attributedTo"], BOB,
        "the token's participant is stamped"
    );
    assert_eq!(graph[0]["body"], "from HTTP");
    assert_eq!(graph[1]["attributedTo"], ALICE);

    // The same refusals, by kind. Bob holds nothing on `side`.
    let denied = host.https(
        "POST",
        "/layer/side/say",
        Some(&bob),
        br#"{"@id": "urn:layer:new", "@type": "Message", "body": "x"}"#,
    );
    assert_eq!(denied.status, 403);
    let quic_denied = issue(
        &bob_quic,
        Verb::Sink,
        "urn:layer:side:say",
        &[(
            "content",
            "@prefix ik: <https://ikigai-rs.dev/ns#> .\n<urn:layer:new> a ik:Message ; ik:body \"x\" .",
        )],
    )
    .unwrap_err();
    assert_eq!(denied.json()["kind"], quic_denied.kind());
    // A shape the layer refuses: a message with no body (the shape is closed and needs one).
    let refused = host.https(
        "POST",
        "/layer/talk/say",
        Some(&bob),
        br#"{"@id": "urn:layer:new", "@type": "Message", "title": "no body"}"#,
    );
    assert_eq!(
        refused.status,
        400,
        "{}",
        String::from_utf8_lossy(&refused.body)
    );
    assert_eq!(refused.json()["kind"], "invalid-argument");
    assert_eq!(refused.json()["name"], "content");
    let quic_refused = issue(
        &bob_quic,
        Verb::Sink,
        "urn:layer:talk:say",
        &[(
            "content",
            "@prefix ik: <https://ikigai-rs.dev/ns#> .\n@prefix dcterms: <http://purl.org/dc/terms/> .\n\
             <urn:layer:new> a ik:Message ; dcterms:title \"no body\" .",
        )],
    )
    .unwrap_err();
    assert_eq!(refused.json()["kind"], quic_refused.kind());

    // Work: alice drops over QUIC, bob takes over HTTP, and a retried take is a conflict the
    // taker recovers from the receipt.
    issue(
        &alice,
        Verb::Sink,
        "urn:layer:tasks:tuples",
        &[("content", &offer("1", "Front"))],
    )
    .unwrap();
    let pending = host.https("GET", "/layer/tasks/rd", Some(&bob), b"");
    assert_eq!(pending.status, 200);
    assert_eq!(
        pending.json()["tuples"][0]["subject"],
        "urn:layer:tasks:offer:1"
    );
    assert_eq!(pending.json()["tuples"][0]["dropper"], ALICE);
    let tuple = enc("urn:layer:tasks:offer:1");
    let take = format!("/layer/tasks/take?tuple={tuple}");
    let taken = host.https("POST", &take, Some(&bob), b"");
    assert_eq!(
        taken.status,
        200,
        "{}",
        String::from_utf8_lossy(&taken.body)
    );
    assert_eq!(taken.json()["@graph"][0]["title"], "Front");
    let again = host.https("POST", &take, Some(&bob), b"");
    assert_eq!(again.status, 409);
    assert_eq!(again.json()["kind"], "conflict");
    let receipt = host.https(
        "GET",
        &format!("/layer/tasks/rd?state=taken&tuple={tuple}"),
        Some(&bob),
        b"",
    );
    assert_eq!(receipt.status, 200);
    let nodes = receipt.json()["@graph"].as_array().unwrap().clone();
    let activity = nodes.iter().find(|n| n["@type"] == "Activity").unwrap();
    assert_eq!(activity["associatedWith"], BOB);
    assert_eq!(activity["used"], "urn:layer:tasks:offer:1");
    // The same receipt over QUIC, byte for byte as JSON.
    let quic_receipt = issue(
        &alice,
        Verb::Source,
        "urn:layer:tasks:tuples",
        &[
            ("state", "taken"),
            ("tuple", "urn:layer:tasks:offer:1"),
            ("as", "application/ld+json"),
        ],
    )
    .unwrap();
    assert_eq!(receipt.json(), json_of(&quic_receipt));
    // And its own resource, by id.
    let id = activity["@id"]
        .as_str()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .to_string();
    let by_id = host.https(
        "GET",
        &format!("/layer/tasks/receipt/{id}"),
        Some(&bob),
        b"",
    );
    assert_eq!(
        by_id.status,
        200,
        "{}",
        String::from_utf8_lossy(&by_id.body)
    );

    // A long poll: the feed waits, and a say over QUIC wakes it.
    let last = host
        .https("GET", "/layer/talk/feed?after=0", Some(&bob), b"")
        .json()["last"]
        .as_u64()
        .unwrap();
    let (addr, pem, token) = (host.https.clone(), host.server_pem.clone(), bob.clone());
    let started = now();
    let waiting = std::thread::spawn(move || {
        https(
            &addr,
            &pem,
            "GET",
            &format!("/layer/talk/feed?after={last}&wait=20"),
            Some(&token),
            b"",
        )
    });
    std::thread::sleep(Duration::from_millis(500));
    issue(
        &alice,
        Verb::Sink,
        "urn:layer:talk:say",
        &[(
            "content",
            "@prefix ik: <https://ikigai-rs.dev/ns#> .\n<urn:layer:new> a ik:Message ; ik:body \"wake\" .",
        )],
    )
    .unwrap();
    let woke = waiting.join().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "the say woke the wait"
    );
    assert_eq!(woke.status, 200);
    assert_eq!(woke.json()["events"][0]["by"], ALICE);
    // With nothing new, the front HOLDS the request for the whole wait, never answering early.
    let last = woke.json()["last"].as_u64().unwrap();
    let started = now();
    let held = host.https(
        "GET",
        &format!("/layer/talk/feed?after={last}&wait=2"),
        Some(&bob),
        b"",
    );
    assert!(
        started.elapsed() >= Duration::from_millis(1800),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(held.status, 200);
    assert_eq!(held.json()["events"].as_array().map(Vec::len), Some(0));

    // The tuples resource by its own name: out, rd and an overridden take.
    issue(
        &alice,
        Verb::Sink,
        "urn:layer:tasks:tuples",
        &[("content", &offer("2", "Named"))],
    )
    .unwrap();
    let listed = host.https("GET", "/layer/tasks/tuples", Some(&bob), b"");
    assert_eq!(
        listed.json()["tuples"][0]["subject"],
        "urn:layer:tasks:offer:2"
    );
    let taken = https_full(
        &host.https,
        &host.server_pem,
        "POST",
        &format!(
            "/layer/tasks/tuples?tuple={}",
            enc("urn:layer:tasks:offer:2")
        ),
        Some(&bob),
        &[("X-HTTP-Method-Override", "DELETE")],
        b"",
    );
    assert_eq!(
        taken.status,
        200,
        "{}",
        String::from_utf8_lossy(&taken.body)
    );
    assert_eq!(taken.json()["@graph"][0]["title"], "Named");
}

#[test]
fn no_token_a_revoked_token_and_an_unenrolled_client_are_refused() {
    let host = host("auth");
    let message = br#"{"@id": "urn:layer:new", "@type": "Message", "body": "nobody"}"#;
    let anonymous = host.https("POST", "/layer/talk/say", None, message);
    assert_eq!(anonymous.status, 401);
    assert_eq!(anonymous.json()["kind"], "denied");
    assert!(anonymous
        .header("www-authenticate")
        .is_some_and(|v| v.starts_with("Bearer")));
    let forged = host.https("POST", "/layer/talk/say", Some("iklt_00"), message);
    assert_eq!(forged.status, 401);
    // Nothing was admitted.
    let alice = host.quic("alice");
    let entries = json_of(
        &issue(
            &alice,
            Verb::Source,
            "urn:layer:talk:entries",
            &[("as", "application/ld+json")],
        )
        .unwrap(),
    );
    assert!(
        entries
            .get("@graph")
            .is_none_or(|g| g.as_array().is_none_or(Vec::is_empty)),
        "{entries}"
    );

    // A good token: a route the front does not know, and a method a route does not take.
    let bob = host.mint(BOB);
    assert_eq!(
        host.https("GET", "/layer/talk/nope", Some(&bob), b"")
            .status,
        404
    );
    let wrong = host.https("GET", "/layer/talk/say", Some(&bob), b"");
    assert_eq!(wrong.status, 405);
    assert_eq!(wrong.header("allow").as_deref(), Some("POST"));
    // The route answers authentication before it answers anything about routes.
    assert_eq!(host.https("GET", "/layer/talk/nope", None, b"").status, 401);

    // Revoked: its next request is refused.
    assert_eq!(host.https("GET", "/layers/me", Some(&bob), b"").status, 200);
    let listed = ok(
        run(&host.home, &["layers-token", "list"]),
        "layers-token list",
    );
    let id = listed.split_whitespace().next().unwrap().to_string();
    assert!(!listed.contains(&bob), "list never shows a token");
    ok(
        run(&host.home, &["layers-token", "revoke", &id]),
        "layers-token revoke",
    );
    assert_eq!(host.https("GET", "/layers/me", Some(&bob), b"").status, 401);

    // A token whose client the enrollment no longer holds mints nothing.
    let carol = host.mint(CAROL);
    assert_eq!(
        host.https("GET", "/layers/me", Some(&carol), b"").status,
        200
    );
    let clients = config_home(&host.home).join("clients.json");
    let mut enrolled: Value =
        serde_json::from_str(&std::fs::read_to_string(&clients).unwrap()).unwrap();
    let map = enrolled["clients"].as_object_mut().unwrap();
    let key = map
        .iter()
        .find(|(_, entry)| entry["principal"] == CAROL)
        .map(|(key, _)| key.clone())
        .unwrap();
    map.remove(&key);
    std::fs::write(&clients, serde_json::to_string_pretty(&enrolled).unwrap()).unwrap();
    assert_eq!(
        host.https("GET", "/layers/me", Some(&carol), b"").status,
        401
    );

    // A mint for someone the enrollment does not hold is refused at the command.
    let out = run(
        &host.home,
        &["layers-token", "mint", "urn:collab:participant:eve"],
    );
    assert!(!out.status.success());
}

/// ledger #1593: HEAD is answered the way ikigai-web's routed adapter answers it (cli PR 516):
/// a read route takes it as GET, with GET's status and headers and `Content-Length` GET's
/// length, and no content; every refusal to a HEAD (401, 404, 405) is a head alone too. A
/// read route's `Allow` names HEAD beside GET.
#[test]
fn head_is_answered_with_the_head_alone_on_every_path() {
    let host = host("head");
    let bob = host.mint(BOB);
    let get = host.https("GET", "/layers/me", Some(&bob), b"");
    assert_eq!(get.status, 200);
    assert!(!get.body.is_empty(), "GET has content");
    let head = host.https("HEAD", "/layers/me", Some(&bob), b"");
    assert_eq!(head.status, 200, "{}", head.head);
    assert!(
        head.body.is_empty(),
        "HEAD has no content: {:?}",
        String::from_utf8_lossy(&head.body)
    );
    assert_eq!(
        head.header("content-length"),
        Some(get.body.len().to_string()),
        "{}",
        head.head
    );
    assert_eq!(head.header("content-type"), get.header("content-type"));
    assert_eq!(head.header("cache-control").as_deref(), Some("no-store"));

    // The refusals: no token, no route, a route that takes POST only.
    for (path, token, status) in [
        ("/layers/me", None, 401),
        ("/layer/talk/nope", Some(bob.as_str()), 404),
        ("/layer/talk/say", Some(bob.as_str()), 405),
    ] {
        let refused = host.https("HEAD", path, token, b"");
        assert_eq!(refused.status, status, "HEAD {path}: {}", refused.head);
        assert!(
            refused.body.is_empty(),
            "HEAD {path} has no content: {:?}",
            String::from_utf8_lossy(&refused.body)
        );
    }
    let wrong = host.https("POST", "/layer/talk/entries", Some(&bob), b"");
    assert_eq!(wrong.status, 405);
    assert_eq!(wrong.header("allow").as_deref(), Some("GET, HEAD"));
    let wrong = host.https("PUT", "/layer/tasks/tuples", Some(&bob), b"");
    assert_eq!(wrong.header("allow").as_deref(), Some("GET, HEAD, POST"));
}

#[test]
fn a_race_between_an_http_taker_and_a_quic_taker_has_exactly_one_winner() {
    let host = host("race");
    let bob = host.mint(BOB);
    let alice = host.quic("alice");
    for round in 0..6 {
        let id = format!("race{round}");
        issue(
            &alice,
            Verb::Sink,
            "urn:layer:tasks:tuples",
            &[("content", &offer(&id, "race"))],
        )
        .unwrap();
        let subject = format!("urn:layer:tasks:offer:{id}");
        let barrier = Arc::new(Barrier::new(2));
        let carol = host.quic("carol");
        let quic_side = {
            let barrier = Arc::clone(&barrier);
            let subject = subject.clone();
            std::thread::spawn(move || {
                barrier.wait();
                issue(
                    &carol,
                    Verb::Delete,
                    "urn:layer:tasks:tuples",
                    &[("tuple", subject.as_str())],
                )
            })
        };
        let http_side = {
            let barrier = Arc::clone(&barrier);
            let (addr, pem, token) = (host.https.clone(), host.server_pem.clone(), bob.clone());
            let path = format!("/layer/tasks/take?tuple={}", enc(&subject));
            std::thread::spawn(move || {
                barrier.wait();
                https(&addr, &pem, "POST", &path, Some(&token), b"")
            })
        };
        let by_quic = quic_side.join().unwrap();
        let by_http = http_side.join().unwrap();
        let winner = match (&by_quic, by_http.status) {
            (Ok(_), 409) => CAROL,
            (Err(Error::Conflict(_)), 200) => BOB,
            other => panic!(
                "round {round}: not exactly one winner: {:?} / {}",
                other.0, other.1
            ),
        };
        let receipt = host.https(
            "GET",
            &format!("/layer/tasks/rd?state=taken&tuple={}", enc(&subject)),
            Some(&bob),
            b"",
        );
        let nodes = receipt.json()["@graph"].as_array().unwrap().clone();
        let activity = nodes.iter().find(|n| n["@type"] == "Activity").unwrap();
        assert_eq!(
            activity["associatedWith"], winner,
            "round {round}: the receipt names the winner"
        );
    }
}

/// A Door onto the layer host over QUIC, for the gateway's reference participant.
struct QuicDoor(ikigai_quic::QuicResolver);

#[async_trait::async_trait]
impl ikigai_layers::gateway::Door for QuicDoor {
    async fn call(&self, request: Request) -> Result<Representation, Error> {
        self.0.issue(request).map(|(repr, _)| repr)
    }
}

/// The resolving kernel: `urn:test:hello` answers `hello`.
fn hello_kernel() -> ikigai_core::Kernel {
    use ikigai_core::{Description, EndpointSpace, Exact, FnEndpoint, ReprType};
    let hello = FnEndpoint::new("hello", |_inv: &ikigai_core::Invocation<'_>| {
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"hello".to_vec(),
        ))
    })
    .with_description(Description::new("hello").verb(Verb::Source));
    ikigai_core::Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:test:hello"), hello),
    ))
}

#[test]
fn the_gateway_crosses_between_an_http_participant_and_a_quic_participant() {
    use ikigai_layers::gateway::{self, Ask, Asker, KernelDoor, Resolver};
    let host = host("gw");
    let bob = host.mint(BOB);

    // An asker over HTTP and JSON, a resolver over QUIC (the reference participant).
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let resolving = {
        let stop = Arc::clone(&stop);
        let door = QuicDoor(host.quic("alice"));
        std::thread::spawn(move || {
            let local = hello_kernel();
            let resolver = Resolver::new(KernelDoor::new(&local, ikigai_core::Capability::root()));
            let mut after = 0;
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                after = futures::executor::block_on(gateway::follow(
                    &door,
                    "gw",
                    &resolver,
                    after,
                    Duration::from_secs(1),
                ))
                .expect("the resolver follows");
            }
        })
    };
    let asked = host.https(
        "POST",
        "/layer/gw/out",
        Some(&bob),
        br#"{"@id": "urn:layer:gw:request:c1", "@type": "Request", "correlation": "c1", "resource": "urn:test:hello", "verb": "Source"}"#,
    );
    assert_eq!(
        asked.status,
        200,
        "{}",
        String::from_utf8_lossy(&asked.body)
    );
    assert_eq!(asked.json()["@id"], "urn:layer:gw:request:c1");
    let reply = enc("urn:layer:gw:reply:c1");
    let deadline = now() + Duration::from_secs(30);
    let answer = loop {
        let taken = host.https(
            "POST",
            &format!("/layer/gw/take?tuple={reply}"),
            Some(&bob),
            b"",
        );
        match taken.status {
            200 => break taken.json(),
            404 if now() < deadline => {
                assert_eq!(taken.json()["kind"], "not-found");
                std::thread::sleep(Duration::from_millis(200));
            }
            other => panic!(
                "the asker's take: {other} {}",
                String::from_utf8_lossy(&taken.body)
            ),
        }
    };
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    resolving.join().unwrap();
    let node = &answer["@graph"][0];
    assert_eq!(node["@type"], "Reply", "{answer}");
    assert_eq!(node["bytes"], "aGVsbG8=", "base64 of `hello`");
    assert!(node["mediaType"]
        .as_str()
        .unwrap()
        .starts_with("text/plain"));
    assert_eq!(node["addressedTo"], BOB);
    assert_eq!(node["attributedTo"], ALICE, "the resolver answered");

    // The reverse: an asker over QUIC (the reference participant), a resolver over HTTP and
    // JSON that takes the request, resolves it on its own side and drops the reply.
    let asking = {
        let door = QuicDoor(host.quic("alice"));
        std::thread::spawn(move || {
            let asker = Asker::new(door, "gw");
            let ask = Ask::new(Verb::Source, Iri::parse("urn:remote:hello").unwrap());
            futures::executor::block_on(asker.ask(&ask, Duration::from_secs(30)))
        })
    };
    let deadline = now() + Duration::from_secs(30);
    let request = loop {
        let pending = host.https("GET", "/layer/gw/rd", Some(&bob), b"").json();
        let found = pending["tuples"].as_array().unwrap().iter().find_map(|t| {
            t["subject"]
                .as_str()
                .filter(|s| s.starts_with("urn:layer:gw:request:"))
                .map(str::to_string)
        });
        match found {
            Some(subject) => break subject,
            None if now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            None => panic!("no request arrived"),
        }
    };
    let taken = host.https(
        "POST",
        &format!("/layer/gw/take?tuple={}", enc(&request)),
        Some(&bob),
        b"",
    );
    assert_eq!(
        taken.status,
        200,
        "{}",
        String::from_utf8_lossy(&taken.body)
    );
    let asked = taken.json()["@graph"][0].clone();
    assert_eq!(asked["resource"], "urn:remote:hello");
    assert_eq!(asked["verb"], "Source");
    assert_eq!(asked["attributedTo"], ALICE);
    let correlation = asked["correlation"].as_str().unwrap();
    let reply = json!({
        "@id": format!("urn:layer:gw:reply:{correlation}"),
        "@type": "Reply",
        "offer": request,
        "addressedTo": asked["attributedTo"],
        "correlation": correlation,
        "mediaType": "text/plain",
        "bytes": "aGVsbG8="
    });
    let dropped = host.https(
        "POST",
        "/layer/gw/out",
        Some(&bob),
        reply.to_string().as_bytes(),
    );
    assert_eq!(
        dropped.status,
        200,
        "{}",
        String::from_utf8_lossy(&dropped.body)
    );
    let answered = asking.join().unwrap().expect("the QUIC asker's answer");
    assert_eq!(answered.bytes, b"hello");
    assert_eq!(answered.repr_type.media_type, "text/plain");
}

/// What one `Expect: 100-continue` exchange on the front came to.
struct Expected {
    /// The head of the door's first answer: the interim `100`, or a final status it chose to
    /// answer at once.
    first: String,
    /// How long the door took to say it.
    waited: Duration,
    /// The final answer.
    last: Http,
}

/// Send a POST the way a client honoring `Expect: 100-continue` does (a JVM HTTP client sends
/// Expect on every POST with a body): the head alone, then wait for the door's first answer,
/// and send the body only once invited. The wait is bounded by `PATIENCE` so a door that never
/// answers fails the test rather than hanging it; the caller asserts how long it took.
fn expect_continue(host: &Host, path: &str, token: Option<&str>, body: &[u8]) -> Expected {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let tls = ikigai_quic::pinned_https_client_tls(&host.server_pem).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
        let tcp = tokio::net::TcpStream::connect(&host.https).await.unwrap();
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from("ikigai").unwrap();
        let mut stream = connector
            .connect(name, tcp)
            .await
            .expect("TLS with the pinned certificate");
        let mut head = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nExpect: 100-continue\r\n",
            host.https
        );
        if let Some(token) = token {
            head.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let started = now();
        let mut got = Vec::new();
        let mut tmp = [0u8; 1024];
        let end = tokio::time::timeout(PATIENCE, async {
            loop {
                if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                    return end + 4;
                }
                match stream.read(&mut tmp).await {
                    Ok(0) | Err(_) => return got.len(),
                    Ok(n) => got.extend_from_slice(&tmp[..n]),
                }
            }
        })
        .await
        .expect("the door answered the head at all");
        let waited = started.elapsed();
        let first = String::from_utf8_lossy(&got[..end]).to_string();
        let mut out = if first.starts_with("HTTP/1.1 100 ") {
            stream.write_all(body).await.unwrap();
            stream.flush().await.unwrap();
            got[end..].to_vec()
        } else {
            got
        };
        let _ = stream.read_to_end(&mut out).await;
        let split = out
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap_or_else(|| panic!("no final head in {:?}", String::from_utf8_lossy(&out)));
        let head = String::from_utf8_lossy(&out[..split]).to_string();
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("no status in {head}"));
        Expected {
            first,
            waited,
            last: Http {
                status,
                head,
                body: out[split + 4..].to_vec(),
            },
        }
    })
}

/// ledger #1408: a client that sends `Expect: 100-continue` (a JVM HTTP client does, on every
/// POST with a body) is never left waiting out its own expect timeout. A drop is invited at once
/// and lands; a POST without a token and a POST to a GET-only path are answered promptly too.
#[test]
fn an_expecting_client_is_answered_promptly_on_every_route() {
    let host = host("expect");
    let bob = host.mint(BOB);
    // Far under the 1 s curl waits and the 3 s a JVM client waits; a door that says nothing
    // costs the full timeout, so this is the line between the two, with room for a loaded CI.
    let prompt = Duration::from_millis(900);

    let dropped = expect_continue(
        &host,
        "/layer/tasks/tuples",
        Some(&bob),
        offer("e1", "Expect").as_bytes(),
    );
    assert_eq!(dropped.first, "HTTP/1.1 100 Continue\r\n\r\n");
    assert!(
        dropped.waited < prompt,
        "the drop waited {:?} for its invitation",
        dropped.waited
    );
    assert_eq!(
        dropped.last.status,
        200,
        "{}",
        String::from_utf8_lossy(&dropped.last.body)
    );
    let pending = host.https("GET", "/layer/tasks/rd", Some(&bob), b"");
    assert_eq!(
        pending.json()["tuples"][0]["subject"],
        "urn:layer:tasks:offer:e1"
    );

    let message = br#"{"@id": "urn:layer:new", "@type": "Message", "body": "nobody"}"#;
    let anonymous = expect_continue(&host, "/layer/talk/say", None, message);
    assert!(
        anonymous.waited < prompt,
        "the 401 waited {:?}",
        anonymous.waited
    );
    assert_eq!(anonymous.last.status, 401);

    let wrong = expect_continue(&host, "/layers/me", Some(&bob), message);
    assert!(wrong.waited < prompt, "the 405 waited {:?}", wrong.waited);
    assert_eq!(wrong.last.status, 405);
    assert_eq!(wrong.last.header("allow").as_deref(), Some("GET, HEAD"));
}
