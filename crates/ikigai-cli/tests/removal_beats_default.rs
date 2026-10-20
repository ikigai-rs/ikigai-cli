//! Removing a client refuses it, whatever `default` says, and the trust list counts at the
//! next handshake (ledger #1825), through the REAL binary.
//!
//! Three things were wrong through cli 0.1.63, and each case below failed on that code:
//!
//! - `clients.json`'s `"default"` was the grant for every trusted certificate with NO entry, so
//!   removing a client's entry from a file that set one moved the client to the default grant
//!   instead of refusing it. Now `default` serves an ENROLLED entry that names no grant, and a
//!   certificate with no entry is refused.
//! - A bearer token on the layers HTTPS front mints through the same enrollment, so a token bound
//!   to a removed client kept working under the default too.
//! - The door read its trust list (`client.crt` and `clients/*.crt`) once at startup, so a
//!   removed certificate kept connecting until a restart, and a new one could not connect until
//!   one. It is read at every handshake now.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `quic_principals.rs` is: `HOME`,
//! `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set on each spawned process only, and every door
//! binds port 0 and the test reads the bound port off its banner (field guide 9h).
#![cfg(all(feature = "embedded", feature = "quic", unix))]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long a door gets to print its banner. A watchdog, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

const CAROL: &str = "urn:collab:participant:carol";

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
    let dir = std::env::temp_dir().join(format!("iki-rbd-{}-{case}", std::process::id()));
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

/// Start `ikigai serve quic://127.0.0.1:0 --cert-dir <certs> <extra…>` and wait for its
/// banner; returns the door and the whole banner (every line up to `serving on`).
fn serve(home: &Path, certs: &Path, extra: &[&str]) -> (Door, String) {
    let mut args = vec![
        "serve",
        "quic://127.0.0.1:0",
        "--cert-dir",
        certs.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
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
    (door, seen)
}

/// The value after `marker` on the first banner line that has it.
fn after(banner: &str, marker: &str) -> String {
    banner
        .lines()
        .find_map(|line| line.split(marker).nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no `{marker}` in the banner:\n{banner}"))
        .to_string()
}

/// `source urn:host:identity` over a NEW connection, as the client whose certificate and key
/// are `cert` and `key`, pinning the door's server certificate from `certs`.
fn identity_as(home: &Path, certs: &Path, cert: &Path, key: &Path, target: &str) -> Output {
    let dir = certs.to_str().unwrap();
    run(
        home,
        &[
            "--cert-dir",
            dir,
            "--client-cert",
            cert.to_str().unwrap(),
            "--client-key",
            key.to_str().unwrap(),
            "--connect",
            target,
            "--plain",
            "-c",
            "source urn:host:identity",
        ],
    )
}

/// The `principal` a served connection reports, or `None` when the door did not serve it.
fn served_as(out: &Output) -> Option<String> {
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("principal "))
        .map(str::to_string)
}

fn describe(out: &Output) -> String {
    format!(
        "status {}: {}{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// `clients/<name>.{crt,key}` under `certs`.
fn pair(certs: &Path, name: &str) -> (PathBuf, PathBuf) {
    (
        certs.join(format!("clients/{name}.crt")),
        certs.join(format!("clients/{name}.key")),
    )
}

/// A `default` never serves a certificate with no entry: a trusted certificate that was never
/// enrolled is refused, and so is a client whose entry is removed. On cli 0.1.63 both were
/// served under the default.
#[test]
fn a_default_never_serves_a_certificate_with_no_entry() {
    let home = scratch("stranger");
    let certs = certs(&home, "certs", &["alice", "bob"]);
    let alice = fingerprint(&pair(&certs, "alice").0);
    write(
        config_home(&home).join("grants.json"),
        r#"{"reader": ["urn:cap:space:read"], "taker": ["urn:cap:space:read", "urn:cap:space:take"]}"#,
    );
    let enroll = |clients: &str| {
        write(
            config_home(&home).join("clients.json"),
            &format!(r#"{{"clients": {{{clients}}}, "default": "reader"}}"#),
        );
    };
    enroll(&format!(
        r#""{alice}": {{"grant": "taker", "label": "alice"}}"#
    ));
    let (_door, banner) = serve(&home, &certs, &["--name", "rbd"]);
    let target = after(&banner, "serving on ");
    let ask = |name: &str| {
        let (cert, key) = pair(&certs, name);
        identity_as(&home, &certs, &cert, &key, &target)
    };

    let seen = ask("alice");
    assert_eq!(
        served_as(&seen),
        Some(format!("urn:iki:host:rbd:client:{alice}")),
        "alice's own entry: {}",
        describe(&seen)
    );
    // Bob's certificate is trusted (it is in clients/) and has no entry: refused.
    let seen = ask("bob");
    assert_eq!(
        served_as(&seen),
        None,
        "a certificate with no entry must be refused, default or not: {}",
        describe(&seen)
    );
    // Alice's entry is removed: her next connection is refused, not moved to the default.
    enroll("");
    let seen = ask("alice");
    assert_eq!(
        served_as(&seen),
        None,
        "a removed client must be refused, not served under the default: {}",
        describe(&seen)
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// What a `default` IS for: an enrolled entry that names no grant is served under it, as its
/// entry's own principal. On cli 0.1.63 such an entry made the whole file unusable, so the
/// door did not start.
#[test]
fn a_default_serves_an_enrolled_entry_that_names_no_grant() {
    let home = scratch("default");
    let certs = certs(&home, "certs", &["carol"]);
    let carol = fingerprint(&pair(&certs, "carol").0);
    write(
        config_home(&home).join("grants.json"),
        r#"{"reader": ["urn:cap:space:read"]}"#,
    );
    write(
        config_home(&home).join("clients.json"),
        &format!(
            r#"{{"clients": {{"{carol}": {{"label": "carol", "principal": "{CAROL}"}}}}, "default": "reader"}}"#
        ),
    );
    let (_door, banner) = serve(&home, &certs, &["--name", "rbd"]);
    assert!(
        banner.contains("default grant \"reader\""),
        "the banner says what the default serves: {banner}"
    );
    let target = after(&banner, "serving on ");
    let (cert, key) = pair(&certs, "carol");
    let seen = identity_as(&home, &certs, &cert, &key, &target);
    assert_eq!(
        served_as(&seen).as_deref(),
        Some(CAROL),
        "an enrolled entry with no grant is served under the default: {}",
        describe(&seen)
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// The trust list is read at EVERY handshake: a certificate dropped into `clients/` while the
/// door serves is trusted at its next connection, and one deleted from it is refused at its
/// next connection, both without a restart. On cli 0.1.63 neither counted until a restart.
#[test]
fn the_trust_list_counts_at_the_next_handshake() {
    let home = scratch("trust");
    let certs = certs(&home, "certs", &["alice"]);
    // Dave's identity is minted in another directory, so the door does not trust it at start.
    let spare = self::certs(&home, "spare", &["dave"]);
    let (alice, dave) = (
        fingerprint(&pair(&certs, "alice").0),
        fingerprint(&pair(&spare, "dave").0),
    );
    write(
        config_home(&home).join("grants.json"),
        r#"{"reader": ["urn:cap:space:read"]}"#,
    );
    write(
        config_home(&home).join("clients.json"),
        &format!(r#"{{"clients": {{"{alice}": "reader", "{dave}": "reader"}}}}"#),
    );
    let (_door, banner) = serve(&home, &certs, &["--name", "trust"]);
    let target = after(&banner, "serving on ");
    let (alice_crt, alice_key) = pair(&certs, "alice");
    let (dave_crt, dave_key) = pair(&spare, "dave");

    let seen = identity_as(&home, &certs, &alice_crt, &alice_key, &target);
    assert!(served_as(&seen).is_some(), "{}", describe(&seen));
    let seen = identity_as(&home, &certs, &dave_crt, &dave_key, &target);
    assert_eq!(
        served_as(&seen),
        None,
        "dave is enrolled but not yet trusted: {}",
        describe(&seen)
    );

    // Dave's certificate is added to the trust list while the door serves.
    std::fs::copy(&dave_crt, certs.join("clients/dave.crt")).unwrap();
    let seen = identity_as(&home, &certs, &dave_crt, &dave_key, &target);
    assert_eq!(
        served_as(&seen),
        Some(format!("urn:iki:host:trust:client:{dave}")),
        "a certificate added while the door serves is trusted at its next connection: {}",
        describe(&seen)
    );

    // Alice's certificate is removed from it; her clients.json entry stays, and she keeps a
    // copy of her certificate to present.
    let kept = home.join("alice-kept.crt");
    std::fs::copy(&alice_crt, &kept).unwrap();
    std::fs::remove_file(&alice_crt).unwrap();
    let seen = identity_as(&home, &certs, &kept, &alice_key, &target);
    assert_eq!(
        served_as(&seen),
        None,
        "a certificate removed from the trust list is refused at its next connection: {}",
        describe(&seen)
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// The closed shape of the one layer the token case hosts.
#[cfg(feature = "web")]
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
"#;

/// Its egress context.
#[cfg(feature = "web")]
const CONTEXT: &str = r#"{ "@context": {
  "ik": "https://ikigai-rs.dev/ns#",
  "dcterms": "http://purl.org/dc/terms/",
  "prov": "http://www.w3.org/ns/prov#",
  "xsd": "http://www.w3.org/2001/XMLSchema#",
  "Message": "ik:Message",
  "body": "ik:body",
  "attributedTo": { "@id": "prov:wasAttributedTo", "@type": "@id" },
  "created": { "@id": "dcterms:created", "@type": "xsd:dateTime" },
  "seq": { "@id": "ik:seq", "@type": "xsd:integer" }
} }
"#;

/// The status of `GET /layers/me` on the HTTPS front at `addr`, presenting `token`.
#[cfg(feature = "web")]
fn layers_me(addr: &str, server_pem: &str, token: &str) -> u16 {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        let request = format!(
            "GET /layers/me HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
             Authorization: Bearer {token}\r\nContent-Length: 0\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut out = Vec::new();
        let _ = stream.read_to_end(&mut out).await;
        let head = String::from_utf8_lossy(&out).to_string();
        head.split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("no HTTP status in {head}"))
    })
}

/// A bearer token is refused together with the client it is bound to, even when
/// `clients.json` sets a `default`. On cli 0.1.63 the front minted the removed client's token
/// under the default grant and answered it.
#[cfg(feature = "web")]
#[test]
fn a_token_bound_to_a_removed_client_is_refused_under_a_default() {
    let home = scratch("token");
    let config = config_home(&home);
    let certs = certs(&home, "certs", &["alice", "carol"]);
    write(config.join("layers/shapes.ttl"), SHAPES);
    write(config.join("layers/context.jsonld"), CONTEXT);
    write(
        config.join("layers/talk.toml"),
        "model = \"channel\"\nshapes = \"shapes.ttl\"\ncontext = \"context.jsonld\"\n",
    );
    write(
        config.join("participants.ttl"),
        "@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
         <urn:collab:participant:alice> a foaf:Person .\n\
         <urn:collab:participant:carol> a foaf:Person .\n",
    );
    write(
        config.join("collabs/pair.toml"),
        "[[mount]]\nlayer = \"talk\"\nalice = [\"read\", \"feed\", \"say\"]\n\
         carol = [\"read\", \"feed\", \"say\"]\n",
    );
    let fp = |name: &str| fingerprint(&pair(&certs, name).0);
    write(
        config.join("enrollment.toml"),
        &format!("alice = \"{}\"\ncarol = \"{}\"\n", fp("alice"), fp("carol")),
    );
    let loaded = ikigai_layers::Config::load(&config).expect("the configuration checks");
    let fingerprints =
        ikigai_layers::grants::load_fingerprints(&config, &loaded).expect("enrollment.toml");
    ikigai_layers::grants::generate(&loaded, &fingerprints)
        .expect("an enrollment")
        .write(&config)
        .expect("grants.json and clients.json");
    // The generator writes no default. Add one, naming a grant it did write (alice's), so the
    // old rule would have had a grant to hand a removed client.
    let clients = config.join("clients.json");
    let mut enrolled: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&clients).unwrap()).unwrap();
    let alice_grant = enrolled["clients"][fp("alice")]["grant"]
        .as_str()
        .expect("alice's generated grant")
        .to_string();
    enrolled["default"] = serde_json::Value::String(alice_grant);
    std::fs::write(&clients, serde_json::to_string_pretty(&enrolled).unwrap()).unwrap();

    // The layer host seals its state to an age identity (ikigai-layers 0.3.0, ledger #2011): a
    // throwaway one, as `age-keygen -o` would write it.
    let key = home.join("state.key");
    write(
        key.clone(),
        age::secrecy::ExposeSecret::expose_secret(&age::x25519::Identity::generate().to_string()),
    );
    let (_door, banner) = serve(
        &home,
        &certs,
        &[
            "--name",
            "layers",
            "--layers-key",
            key.to_str().unwrap(),
            "--layers-https",
            "127.0.0.1:0",
        ],
    );
    let https = after(&banner, "layers https on https://");
    let server_pem = std::fs::read_to_string(certs.join("server.crt")).unwrap();
    let token = ok(
        run(&home, &["layers-token", "mint", CAROL]),
        "layers-token mint",
    )
    .trim()
    .to_string();
    assert_eq!(layers_me(&https, &server_pem, &token), 200, "carol's token");

    // Carol's entry is removed. Her token is refused with her, default or not.
    enrolled["clients"]
        .as_object_mut()
        .unwrap()
        .remove(&fp("carol"));
    std::fs::write(&clients, serde_json::to_string_pretty(&enrolled).unwrap()).unwrap();
    assert_eq!(
        layers_me(&https, &server_pem, &token),
        401,
        "a token bound to a removed client must be refused, not minted under the default"
    );
    let _ = std::fs::remove_dir_all(&home);
}
