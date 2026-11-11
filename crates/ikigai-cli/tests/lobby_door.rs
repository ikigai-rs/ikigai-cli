//! A door whose layer host defines a LOBBY admits a certificate it does not trust, and that
//! certificate may `say` on the lobby and nothing else (ledger #2009, #2104), through the REAL
//! binary and the real QUIC door.
//!
//! The wiring under test: `serve quic://` asks the layer host for its lobbies at startup; with
//! one, it serves through `ikigai_quic::serve_lobby_on`, whose TLS admits any client certificate
//! inside its validity window, and hands one its trust list does not name to a separate minter
//! that mints exactly `Host::door_capability` with the connection's address. Without one it serves through
//! `serve_trusting_on`, as it always did, and an untrusted certificate is refused at TLS.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `removal_beats_default.rs` is: `HOME`,
//! `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set on each spawned process only, and every door
//! binds port 0 and the test reads the bound port off its banner (field guide 9h).
#![cfg(all(feature = "embedded", feature = "quic", unix))]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long a door gets to print its banner. A watchdog, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

const ALICE: &str = "urn:collab:participant:alice";

/// A child killed when the test ends, whatever the test does.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch home unique to this case and process, with an empty config home.
fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-lob-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(config_home(&dir)).expect("scratch config home");
    dir
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
        // The developer's own overrides would point the child at real enrollment files.
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

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A certificate set in `<home>/<dir>`: the server pair, the base client, and `extra` added
/// clients under `clients/`.
fn certs(home: &Path, dir: &str, extra: &[&str]) -> PathBuf {
    let dir = home.join(dir);
    let d = dir.to_str().unwrap();
    ok(
        run(home, &["cert", "generate", "--dir", d]),
        "cert generate",
    );
    for name in extra {
        ok(
            run(home, &["cert", "add-client", name, "--cert-dir", d]),
            "cert add-client",
        );
    }
    dir
}

/// The fingerprint a door keys a client by.
fn fingerprint(cert: &Path) -> String {
    let pem = std::fs::read_to_string(cert).expect("the client certificate");
    ikigai_quic::fingerprint_of_pem(&pem).expect("a certificate")
}

/// `clients/<name>.{crt,key}` under `certs`.
fn pair(certs: &Path, name: &str) -> (PathBuf, PathBuf) {
    (
        certs.join(format!("clients/{name}.crt")),
        certs.join(format!("clients/{name}.key")),
    )
}

/// The `talk` layer's closed shape: a message with the host's three stamps.
const TALK_SHAPES: &str = r#"@prefix sh: <http://www.w3.org/ns/shacl#> .
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
"#;

const TALK_CONTEXT: &str = r#"{ "@context": {
  "ik": "https://ikigai-rs.dev/ns#",
  "Message": "ik:Message", "body": "ik:body"
} }
"#;

/// The lobby's closed shape, as ikigai-layers' `onboard/layers/enroll.shapes.ttl` writes it: one
/// `onb:EnrollmentRequest` an entry, with the host's three stamps.
const ENROLL_SHAPES: &str = r#"@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix ik: <https://ikigai-rs.dev/ns#> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix dcterms: <http://purl.org/dc/terms/> .
@prefix onb: <https://ikigai-rs.dev/ns/onboard#> .

<urn:iki:onboard:shape:request> a sh:NodeShape ;
  sh:targetClass onb:EnrollmentRequest ;
  sh:closed true ;
  sh:ignoredProperties ( rdf:type ) ;
  sh:property
    [ sh:path onb:invite ; sh:minCount 1 ; sh:maxCount 1 ; sh:nodeKind sh:IRI ;
      sh:pattern "^urn:iki:onboard:invite:[A-Za-z0-9._-]{1,64}$" ] ,
    [ sh:path onb:certificate ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:string ;
      sh:maxLength 8192 ] ,
    [ sh:path onb:fingerprint ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:string ;
      sh:pattern "^[0-9a-f]{64}$" ] ,
    [ sh:path onb:proof ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:string ;
      sh:pattern "^[0-9a-f]{64}$" ] ,
    [ sh:path prov:wasAttributedTo ; sh:minCount 1 ; sh:maxCount 1 ; sh:nodeKind sh:IRI ] ,
    [ sh:path dcterms:created ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:dateTime ] ,
    [ sh:path ik:seq ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:integer ] .
"#;

const ENROLL_CONTEXT: &str = r#"{ "@context": {
  "onb": "https://ikigai-rs.dev/ns/onboard#",
  "EnrollmentRequest": "onb:EnrollmentRequest"
} }
"#;

/// The configuration, in the config home: a `talk` channel alice mounts, and, when `lobby`, an
/// `enroll` lobby alice reads (nobody holds `say` on it: a door admits an unenrolled certificate
/// to it directly). Then the enrollment, generated by the layer host's own generator: alice only.
fn configure(home: &Path, certs: &Path, lobby: bool) {
    let config = config_home(home);
    write(config.join("layers/talk.shapes.ttl"), TALK_SHAPES);
    write(config.join("layers/talk.context.jsonld"), TALK_CONTEXT);
    write(
        config.join("layers/talk.toml"),
        "model = \"channel\"\nshapes = \"talk.shapes.ttl\"\ncontext = \"talk.context.jsonld\"\n",
    );
    let mut collab =
        "[[mount]]\nlayer = \"talk\"\nalice = [\"read\", \"feed\", \"say\"]\n".to_string();
    if lobby {
        write(config.join("layers/enroll.shapes.ttl"), ENROLL_SHAPES);
        write(config.join("layers/enroll.context.jsonld"), ENROLL_CONTEXT);
        write(
            config.join("layers/enroll.toml"),
            "model = \"channel\"\nshapes = \"enroll.shapes.ttl\"\n\
             context = \"enroll.context.jsonld\"\nlobby = true\n",
        );
        collab.push_str("\n[[mount]]\nlayer = \"enroll\"\nalice = [\"read\", \"feed\"]\n");
    }
    write(config.join("collabs/pair.toml"), &collab);
    write(
        config.join("participants.ttl"),
        &format!("@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n<{ALICE}> a foaf:Person .\n"),
    );
    // The host's key (ikigai-layers 0.3.0, ledger #2011): a throwaway age identity, named
    // through the config home's `layers.key`.
    let key = home.join("state.key");
    write(
        key.clone(),
        age::secrecy::ExposeSecret::expose_secret(&age::x25519::Identity::generate().to_string()),
    );
    #[cfg(unix)]
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    write(
        config.join("config.toml"),
        &format!("layers.key = \"{}\"\n", key.display()),
    );
    enroll(home, certs);
}

/// Generate the enrollment with the layer host's own generator: alice only.
fn enroll(home: &Path, certs: &Path) {
    let config = config_home(home);
    write(
        config.join("enrollment.toml"),
        &format!("alice = \"{}\"\n", fingerprint(&pair(certs, "alice").0)),
    );
    let loaded = ikigai_layers::Config::load(&config).expect("the configuration checks");
    let fingerprints: BTreeMap<String, BTreeSet<String>> =
        ikigai_layers::grants::load_fingerprints(&config, &loaded).expect("enrollment.toml");
    ikigai_layers::grants::generate(&loaded, &fingerprints)
        .expect("an enrollment")
        .write(&config)
        .expect("grants.json and clients.json");
}

/// A public feed's closed shape: one announcement with the host's three stamps.
const FEED_SHAPES: &str = r#"@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix ik: <https://ikigai-rs.dev/ns#> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix dcterms: <http://purl.org/dc/terms/> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

<urn:example:shape:announcement> a sh:NodeShape ;
  sh:targetClass ik:Message ;
  sh:closed true ;
  sh:ignoredProperties ( rdf:type ) ;
  sh:property [ sh:path dcterms:title ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:string ] ,
              [ sh:path prov:wasAttributedTo ; sh:minCount 1 ; sh:maxCount 1 ; sh:nodeKind sh:IRI ] ,
              [ sh:path dcterms:created ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:dateTime ] ,
              [ sh:path ik:seq ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:integer ] .
"#;

const FEED_CONTEXT: &str =
    r#"{ "@context": { "dcterms": "http://purl.org/dc/terms/", "title": "dcterms:title" } }"#;

const FEED_SCHEME: &str = r#"@prefix skos: <http://www.w3.org/2004/02/skos/core#> .
<urn:example:scheme:releases> a skos:ConceptScheme .
<urn:example:concept:release> a skos:Concept ; skos:prefLabel "Release" ; skos:notation "1" .
"#;

/// The join lobby's closed shape, as ikigai-layers' `onboard/layers/join.shapes.ttl` writes it: one
/// `onb:JoinRequest` an entry, with the host's three stamps.
const JOIN_SHAPES: &str = r#"@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix ik: <https://ikigai-rs.dev/ns#> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix dcterms: <http://purl.org/dc/terms/> .
@prefix onb: <https://ikigai-rs.dev/ns/onboard#> .

<urn:iki:onboard:shape:join> a sh:NodeShape ;
  sh:targetClass onb:JoinRequest ;
  sh:closed true ;
  sh:ignoredProperties ( rdf:type ) ;
  sh:property
    [ sh:path onb:certificate ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:string ;
      sh:maxLength 8192 ] ,
    [ sh:path onb:fingerprint ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:string ;
      sh:pattern "^[0-9a-f]{64}$" ] ,
    [ sh:path onb:layer ; sh:minCount 1 ; sh:nodeKind sh:IRI ;
      sh:pattern "^urn:layer:[a-z0-9-]+$" ] ,
    [ sh:path prov:wasAttributedTo ; sh:minCount 1 ; sh:maxCount 1 ; sh:nodeKind sh:IRI ] ,
    [ sh:path dcterms:created ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:dateTime ] ,
    [ sh:path ik:seq ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:integer ] .
"#;

const JOIN_CONTEXT: &str = r#"{ "@context": {
  "onb": "https://ikigai-rs.dev/ns/onboard#",
  "JoinRequest": "onb:JoinRequest"
} }
"#;

/// What [`configure`] writes with no lobby, plus a public `releases` feed alice publishes and a
/// `join` lobby answered by policy, taking `per_address` requests an hour from one source address
/// and enough from one certificate and from everyone that only the address can refuse.
fn configure_join(home: &Path, certs: &Path, per_address: usize) {
    configure(home, certs, false);
    let config = config_home(home);
    write(config.join("layers/feed.shapes.ttl"), FEED_SHAPES);
    write(config.join("layers/feed.context.jsonld"), FEED_CONTEXT);
    write(config.join("layers/feed.scheme.ttl"), FEED_SCHEME);
    write(
        config.join("layers/releases.toml"),
        "model = \"channel\"\nshapes = \"feed.shapes.ttl\"\ncontext = \"feed.context.jsonld\"\n\
         feed = true\npublishers = [\"alice\"]\nscheme = \"feed.scheme.ttl\"\npublic = true\n",
    );
    write(config.join("layers/join.shapes.ttl"), JOIN_SHAPES);
    write(config.join("layers/join.context.jsonld"), JOIN_CONTEXT);
    write(
        config.join("layers/join.toml"),
        "model = \"channel\"\nshapes = \"join.shapes.ttl\"\n\
         context = \"join.context.jsonld\"\nlobby = true\njoin = \"public\"\n",
    );
    let key = ed25519_dalek::pkcs8::EncodePrivateKey::to_pkcs8_pem(
        &ed25519_dalek::SigningKey::from_bytes(&[0x33; 32]),
        ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF,
    )
    .expect("a PKCS8 PEM");
    write(config.join("join.pem"), &key);
    write(
        config.join("layers.toml"),
        &format!(
            "[join]\nhost_key = \"join.pem\"\nper_certificate = 100\n\
             per_address = {per_address}\nper_hour = 100\n"
        ),
    );
    enroll(home, certs);
}

/// Start `serve quic://127.0.0.1:0 --name lobby --cert-dir <certs>` and wait for its banner;
/// returns the door, the bound address and the banner.
fn serve(home: &Path, certs: &Path) -> (Door, String, String) {
    let args = [
        "serve",
        "quic://127.0.0.1:0",
        "--name",
        "lobby",
        "--cert-dir",
        certs.to_str().unwrap(),
    ];
    let mut child = spawn(home, &args)
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
        .unwrap_or_else(|e| panic!("`{args:?}` never printed its banner: {e}"));
    let target = seen
        .lines()
        .find_map(|line| line.split("serving on ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no address in the banner:\n{seen}"))
        .to_string();
    (door, target, seen)
}

/// Ask the door `command` as the client `cert`/`key`, pinning the door's server certificate
/// from `certs`, writing `stdin` to the client when given.
fn ask(
    home: &Path,
    certs: &Path,
    (cert, key): &(PathBuf, PathBuf),
    target: &str,
    command: &str,
    stdin: Option<&str>,
) -> Output {
    let mut child = spawn(
        home,
        &[
            "--cert-dir",
            certs.to_str().unwrap(),
            "--client-cert",
            cert.to_str().unwrap(),
            "--client-key",
            key.to_str().unwrap(),
            "--connect",
            target,
            "--plain",
            "-c",
            command,
        ],
    )
    .stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("the client starts");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("piped stdin");
        pipe.write_all(text.as_bytes()).expect("write stdin");
    }
    child.wait_with_output().expect("the client ran")
}

fn describe(out: &Output) -> String {
    format!(
        "status {}: {}{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// An enrollment request as a node writes it: about `<urn:iki:onboard:request:{fp}>`, carrying
/// its own certificate, whose leaf DER the host checks hashes to `fp`.
fn request(cert: &Path) -> String {
    let pem = std::fs::read_to_string(cert).unwrap();
    let fp = fingerprint(cert);
    format!(
        "@prefix onb: <https://ikigai-rs.dev/ns/onboard#> .\n\
         <urn:iki:onboard:request:{fp}> a onb:EnrollmentRequest ;\n  \
         onb:invite <urn:iki:onboard:invite:mini-1> ;\n  \
         onb:certificate \"\"\"{pem}\"\"\" ;\n  \
         onb:fingerprint \"{fp}\" ;\n  \
         onb:proof \"{}\" .\n",
        "0".repeat(64)
    )
}

/// A join request for the public `releases` feed, carrying the certificate it was made with.
fn join_request(cert: &Path) -> String {
    let pem = std::fs::read_to_string(cert).unwrap();
    let fp = fingerprint(cert);
    format!(
        "@prefix onb: <https://ikigai-rs.dev/ns/onboard#> .\n\
         <urn:iki:onboard:join:{fp}> a onb:JoinRequest ;\n  \
         onb:certificate \"\"\"{pem}\"\"\" ;\n  \
         onb:fingerprint \"{fp}\" ;\n  \
         onb:layer <urn:layer:releases> .\n"
    )
}

/// The resource IRIs a manifold (`source urn:kernel:actions`) names, the kernel's own open
/// `urn:kernel:*` entries (every caller's) left out.
fn named(manifold: &str) -> BTreeSet<String> {
    manifold
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("urn:") && !line.starts_with("urn:kernel:"))
        .map(str::to_string)
        .collect()
}

/// An unenrolled certificate, one the door's trust list does not name, is admitted at TLS by a
/// door with a lobby, may `say` its enrollment request there, and is refused everything else:
/// the lobby's own reads, every other layer, the host-wide reads. Its manifold names the lobby's
/// `say` and nothing else. The enrolled path is untouched: alice still reads, and she reads the
/// request, attributed to the stranger's lobby principal.
#[test]
fn an_unenrolled_certificate_can_say_on_the_lobby_and_nothing_else() {
    let home = scratch("lobby");
    let certs = certs(&home, "certs", &["alice"]);
    // The stranger's identity is minted in another directory: the door does not trust it.
    let spare = self::certs(&home, "spare", &["mini"]);
    configure(&home, &certs, true);
    let (_door, target, banner) = serve(&home, &certs);
    assert!(
        banner.contains("lobby open on enroll"),
        "the banner says the lobby is open:\n{banner}"
    );
    let mini = pair(&spare, "mini");
    let alice = pair(&certs, "alice");
    let mini_fp = fingerprint(&mini.0);
    let mini_principal = format!("urn:iki:host:lobby:client:{mini_fp}");

    // Its whole manifold is the lobby's say.
    let manifold = ask(
        &home,
        &certs,
        &mini,
        &target,
        "source urn:kernel:actions",
        None,
    );
    assert_eq!(
        named(&ok(manifold, "the stranger's manifold")),
        BTreeSet::from(["urn:layer:enroll:say".to_string()]),
    );

    // It says its request on the lobby.
    let said = ok(
        ask(
            &home,
            &certs,
            &mini,
            &target,
            "sink urn:layer:enroll:say",
            Some(&request(&mini.0)),
        ),
        "the stranger's request",
    );
    assert!(
        said.trim().starts_with("urn:layer:enroll:entry:"),
        "the lobby admitted the request: {said}"
    );

    // Everything else is refused, as Denied.
    for (command, stdin) in [
        ("source urn:layer:enroll", None),
        ("source urn:layer:enroll:entries", None),
        ("source urn:layer:enroll:feed", None),
        ("source urn:layer:enroll:latest", None),
        ("source urn:layer:talk:entries", None),
        (
            "sink urn:layer:talk:say",
            Some("@prefix ik: <https://ikigai-rs.dev/ns#> .\n<urn:layer:new> a ik:Message ; ik:body \"hi\" .\n"),
        ),
        ("source urn:layers:feed", None),
        ("source urn:layers:participants", None),
        ("source urn:layers:me", None),
        ("source urn:collab:pair", None),
    ] {
        let out = ask(&home, &certs, &mini, &target, command, stdin);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && stderr.to_lowercase().contains("denied"),
            "the stranger must be Denied `{command}`: {}",
            describe(&out)
        );
    }

    // The enrolled path is unchanged: alice reads the lobby's entries, the request among them,
    // attributed to the principal the lobby minted for the stranger.
    let entries = ok(
        ask(
            &home,
            &certs,
            &alice,
            &target,
            "source urn:layer:enroll:entries",
            None,
        ),
        "alice reads the lobby",
    );
    assert!(
        entries.contains(&mini_principal) && entries.contains("onboard#EnrollmentRequest"),
        "alice reads the request, attributed to {mini_principal}:\n{entries}"
    );
    let me = ok(
        ask(
            &home,
            &certs,
            &alice,
            &target,
            "source urn:layers:me as=application/json",
            None,
        ),
        "alice's urn:layers:me",
    );
    assert!(me.contains(ALICE), "alice is still alice: {me}");
    let _ = std::fs::remove_dir_all(&home);
}

/// A door whose config home has a public feed and a join lobby opens, and a stranger who joins
/// reads the feed on its next connection and may do nothing else.
///
/// ★ THE SOURCE ADDRESS (ledger #3295): a second certificate from the same address is refused by
/// the join's per-address limit. Each client is its own process on its own ephemeral port, so
/// this also holds the door to counting the address and not the address and port.
#[test]
fn two_certificates_from_one_address_hit_the_joins_per_address_limit() {
    let home = scratch("join");
    let certs = certs(&home, "certs", &["alice"]);
    let spare = self::certs(&home, "spare", &["first", "second"]);
    configure_join(&home, &certs, 1);
    let (_door, target, banner) = serve(&home, &certs);
    assert!(
        banner.contains("lobby open on join"),
        "the door opens with its join lobby:\n{banner}"
    );
    let first = pair(&spare, "first");
    let second = pair(&spare, "second");

    ok(
        ask(
            &home,
            &certs,
            &first,
            &target,
            "sink urn:layer:join:say",
            Some(&join_request(&first.0)),
        ),
        "the first join",
    );
    ok(
        ask(
            &home,
            &certs,
            &first,
            &target,
            "source urn:layer:releases:entries",
            None,
        ),
        "the joined certificate reads the public feed",
    );
    let out = ask(
        &home,
        &certs,
        &first,
        &target,
        "source urn:layer:talk:entries",
        None,
    );
    assert!(
        !out.status.success()
            && String::from_utf8_lossy(&out.stderr)
                .to_lowercase()
                .contains("denied"),
        "a joined certificate reads public feeds and nothing else: {}",
        describe(&out)
    );

    let out = ask(
        &home,
        &certs,
        &second,
        &target,
        "sink urn:layer:join:say",
        Some(&join_request(&second.0)),
    );
    assert!(
        !out.status.success()
            && String::from_utf8_lossy(&out.stderr).contains("one source address"),
        "the second certificate from one address must hit the per-address limit: {}",
        describe(&out)
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// A layer door WITHOUT a lobby is the door it was: no lobby line in the banner, and a
/// certificate its trust list does not name is refused (at TLS, by the pinned verifier), while
/// the enrolled client is served.
#[test]
fn a_layer_door_without_a_lobby_refuses_an_unlisted_certificate() {
    let home = scratch("nolobby");
    let certs = certs(&home, "certs", &["alice"]);
    let spare = self::certs(&home, "spare", &["mini"]);
    configure(&home, &certs, false);
    let (_door, target, banner) = serve(&home, &certs);
    assert!(
        !banner.contains("lobby open"),
        "no lobby, no lobby line:\n{banner}"
    );
    let out = ask(
        &home,
        &certs,
        &pair(&spare, "mini"),
        &target,
        "source urn:kernel:actions",
        None,
    );
    assert!(
        !out.status.success(),
        "an unlisted certificate is refused: {}",
        describe(&out)
    );
    let me = ok(
        ask(
            &home,
            &certs,
            &pair(&certs, "alice"),
            &target,
            "source urn:layers:me as=application/json",
            None,
        ),
        "alice's urn:layers:me",
    );
    assert!(me.contains(ALICE), "alice is served: {me}");
    let _ = std::fs::remove_dir_all(&home);
}

/// A real layer host refuses a fingerprint in deny.txt after TLS. The client must report
/// admission, rather than diagnosing the first failed Meta request as a missing renderer.
#[test]
fn a_denied_certificate_is_reported_as_a_connection_refusal() {
    use ikigai_core::{
        Clock, EndpointSpace, Exact, FnEndpoint, Invocation, Kernel, ReprType, Representation,
        SystemClock,
    };
    use std::sync::Arc;

    let home = scratch("denied-certificate");
    let certs = certs(&home, "certs", &["alice", "stranger"]);
    configure(&home, &certs, true);
    let stranger = pair(&certs, "stranger");
    let denied = fingerprint(&stranger.0);
    write(config_home(&home).join("deny.txt"), &format!("{denied}\n"));
    let key = ikigai_layers::at_rest::StateKey::load(home.join("state.key")).unwrap();
    let host = ikigai_layers::Host::open(config_home(&home), home.join("state"), &key).unwrap();
    let server = ikigai_quic::Identity {
        cert_pem: std::fs::read_to_string(certs.join("server.crt")).unwrap(),
        key_pem: std::fs::read_to_string(certs.join("server.key")).unwrap(),
    };
    let socket = ikigai_quic::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let target = format!("quic://{}", socket.local_addr().unwrap());
    let minter: ikigai_quic::Minter = Arc::new(move |peer| {
        host.door_capability("test", &peer.fingerprint, None, SystemClock.now())
            .unwrap()
            .map(|_| ikigai_quic::Session {
                // Only admission is under test; the fixture endpoint needs no layer grant.
                capability: ikigai_core::Capability::root(),
                file_segment: String::new(),
                principal: None,
            })
    });
    std::thread::spawn(move || {
        // Deliberately no Meta renderer: an admitted connection must still get the
        // existing missing-contract diagnostic, distinct from a refused connection.
        let kernel = Kernel::new(Arc::new(EndpointSpace::new().bind(
            Exact::new("urn:test:ok"),
            FnEndpoint::new("ok", |_: &Invocation<'_>| {
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"ok".to_vec(),
                ))
            }),
        )));
        ikigai_quic::serve_lobby_on(
            Arc::new(kernel),
            socket,
            &server,
            Arc::new(|| Ok(Vec::new())),
            Arc::clone(&minter),
            minter,
            Duration::from_secs(30),
            None,
        )
        .unwrap();
    });
    let route = format!("urn:test:={target}");
    for (flag, address) in [
        ("--override", route.as_str()),
        ("--connect", target.as_str()),
    ] {
        let out = run(
            &home,
            &[
                "--cert-dir",
                certs.to_str().unwrap(),
                "--client-cert",
                stranger.0.to_str().unwrap(),
                "--client-key",
                stranger.1.to_str().unwrap(),
                flag,
                address,
                "-c",
                "source urn:test:ok",
            ],
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{}", describe(&out));
        assert!(stderr.contains(&format!("the door at {target} refused the connection: the client certificate is not admitted")), "{}", describe(&out));
        assert!(
            !stderr.contains("Meta renderer") && !stderr.contains("did not answer with a contract"),
            "{}",
            describe(&out)
        );
        assert!(
            !stderr.contains('\u{1b}'),
            "plain refusal: {}",
            describe(&out)
        );
    }

    // The same certificate is admitted on its next connection once deny.txt is cleared.
    // With no Meta renderer, the admitted peer still earns the existing contract warning.
    write(config_home(&home).join("deny.txt"), "");
    let out = run(
        &home,
        &[
            "--cert-dir",
            certs.to_str().unwrap(),
            "--client-cert",
            stranger.0.to_str().unwrap(),
            "--client-key",
            stranger.1.to_str().unwrap(),
            "--override",
            &route,
            "-c",
            "source urn:test:ok",
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{}", describe(&out));
    assert!(
        stderr.contains("did not answer with a contract") && stderr.contains("Meta renderer"),
        "{}",
        describe(&out)
    );
    assert!(
        !stderr.contains("certificate is not admitted"),
        "{}",
        describe(&out)
    );
    std::fs::remove_dir_all(home).unwrap();
}
