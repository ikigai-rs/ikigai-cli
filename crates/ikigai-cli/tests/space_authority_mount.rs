//! Does a reactive space's authority file narrow what its handler may call on a name mounted
//! through `--override` (a remote layer door), or does the door's grant for the host's one
//! certificate decide alone? (ledger #3688)
//!
//! Through the REAL binary on both sides: a scratch layer door (`serve quic://` over a config
//! home with `layers/`) whose generated grants give the `edge` client certificate
//! `urn:cap:layer:read:inquiry` (among others), and a writer daemon (`--daemon`, the reactive
//! kernel) in a second home that mounts the door with `--override urn:layer:=quic://…` under
//! that same certificate. Its `contact` space fires `urn:layer:inquiry` (the layer's definition,
//! a read that takes no argument), pinned by `space-handler/contact`, under whatever
//! `space-authority/contact` lists.
//!
//! The authority file is read fresh per tuple, so one daemon and one door serve both halves:
//! first the file OMITS the layer token, then it lists it.
//!
//! ★ Every door binds port 0 and the test reads the bound port off its banner, as
//! `layers_serve.rs` does. Hermetic by the child's environment: `HOME`, `XDG_CONFIG_HOME` and
//! `IKIGAI_FILES` are set on each spawned process only.
#![cfg(all(feature = "embedded", feature = "quic", unix))]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long a door or a daemon gets to come up, and a tuple to settle. A watchdog, not a
/// performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

const EDGE: &str = "urn:collab:participant:edge";

/// The token the door grants the edge certificate and the layer's definition read requires.
const READ_INQUIRY: &str = "urn:cap:layer:read:inquiry";

/// A child killed when the test ends, whatever the test does.
struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-sam-{}-{case}", std::process::id()));
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
        .env_remove("IKIGAI_CLIENTS")
        .env_remove("IKIGAI_GRANTS");
    command
}

fn run(home: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut child = spawn(home, args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("piped stdin");
        pipe.write_all(text.as_bytes()).expect("write stdin");
    }
    child.wait_with_output().expect("the binary ran")
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

/// A certificate set: the server pair, the base client, and `edge` (the host's one
/// certificate).
fn certs(home: &Path) -> PathBuf {
    let dir = home.join("certs");
    let d = dir.to_str().unwrap();
    ok(
        run(home, &["cert", "generate", "--dir", d], None),
        "cert generate",
    );
    ok(
        run(home, &["cert", "add-client", "edge", "--cert-dir", d], None),
        "cert add-client",
    );
    dir
}

const SHAPES: &str = r#"@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix ik: <https://ikigai-rs.dev/ns#> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix dcterms: <http://purl.org/dc/terms/> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

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

const CONTEXT: &str = r#"{ "@context": {
  "ik": "https://ikigai-rs.dev/ns#",
  "dcterms": "http://purl.org/dc/terms/",
  "Offer": "ik:Offer", "title": "dcterms:title", "brief": "ik:brief"
} }
"#;

/// The door's configuration: one tuplespace layer, `inquiry`, mounted by one collaboration in
/// which `edge` may read, follow, drop and take. Then the enrollment, generated by the layer
/// host's own generator (`ikigai-layers grants`, as a library call).
fn configure_door(home: &Path, certs: &Path) {
    let config = config_home(home);
    write(config.join("layers/shapes.ttl"), SHAPES);
    write(config.join("layers/context.jsonld"), CONTEXT);
    write(
        config.join("layers/inquiry.toml"),
        "model = \"tuplespace\"\nshapes = \"shapes.ttl\"\ncontext = \"context.jsonld\"\n",
    );
    write(
        config.join("participants.ttl"),
        &format!("@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n<{EDGE}> a foaf:Person .\n"),
    );
    write(
        config.join("collabs/hub.toml"),
        "[[mount]]\nlayer = \"inquiry\"\nedge = [\"read\", \"feed\", \"out\", \"take\"]\n",
    );
    let pem = std::fs::read_to_string(certs.join("clients/edge.crt")).expect("edge.crt");
    let fingerprint = ikigai_quic::fingerprint_of_pem(&pem).expect("a certificate");
    write(
        config.join("enrollment.toml"),
        &format!("edge = \"{fingerprint}\"\n"),
    );
    let key = home.join("state.key");
    let identity = age::x25519::Identity::generate();
    write(
        key.clone(),
        age::secrecy::ExposeSecret::expose_secret(&identity.to_string()),
    );
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    write(
        config.join("config.toml"),
        &format!("layers.key = \"{}\"\n", key.display()),
    );
    let loaded = ikigai_layers::Config::load(&config).expect("the configuration checks");
    let fingerprints: BTreeMap<String, BTreeSet<String>> =
        ikigai_layers::grants::load_fingerprints(&config, &loaded).expect("enrollment.toml");
    let enrollment =
        ikigai_layers::grants::generate(&loaded, &fingerprints).expect("an enrollment");
    let grants = format!("{:?}", enrollment.grants);
    assert!(
        grants.contains(READ_INQUIRY),
        "the door grants the edge certificate the token: {grants}"
    );
    enrollment
        .write(&config)
        .expect("grants.json and clients.json");
}

/// Start the child and wait for a stderr line containing `ready`; keep draining after it.
/// Answers the child and what it printed up to that line.
fn start(home: &Path, args: &[&str], ready: &str) -> (Killed, String) {
    let mut child = spawn(home, args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the child starts");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel();
    let ready = ready.to_string();
    std::thread::spawn(move || {
        let mut seen = String::new();
        let mut lines = BufReader::new(stderr).lines().map_while(Result::ok);
        for line in lines.by_ref() {
            seen.push_str(&line);
            seen.push('\n');
            if line.contains(&ready) {
                break;
            }
        }
        let _ = tx.send(seen);
        lines.for_each(drop);
    });
    let child = Killed(child);
    let seen = rx
        .recv_timeout(PATIENCE)
        .unwrap_or_else(|e| panic!("`{args:?}` never became ready: {e}"));
    (child, seen)
}

/// Where a dropped tuple settled: `Ok(note)` from `outbox/<id>.out`, `Err(note)` from
/// `error/<id>.err`. Panics when it settles nowhere within [`PATIENCE`].
#[allow(clippy::disallowed_methods)] // a native test's own deadline; never built for wasm
fn settled(space: &Path, id: &str) -> Result<String, String> {
    let deadline = Instant::now() + PATIENCE;
    loop {
        let out = space.join("outbox").join(format!("{id}.tuple"));
        let err = space.join("error").join(format!("{id}.tuple"));
        if out.is_file() {
            return Ok(
                std::fs::read_to_string(space.join("outbox").join(format!("{id}.out")))
                    .unwrap_or_default(),
            );
        }
        if err.is_file() {
            return Err(
                std::fs::read_to_string(space.join("error").join(format!("{id}.err")))
                    .unwrap_or_default(),
            );
        }
        assert!(
            Instant::now() < deadline,
            "tuple {id} settled nowhere under {}",
            space.display()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// ★ ledger #3688. The door grants the host's certificate `urn:cap:layer:read:inquiry`. A
/// reactor whose `space-authority` file omits that token is DENIED the layer read through the
/// `--override` mount, and the dead letter names the token: the handler runs under the
/// authority file's capability, the remote name's declared requirement is checked against it,
/// and a call that does cross the wire carries it (`IssueAs`) for the door to clamp to the
/// certificate's grant. Once the authority lists the token, the same handler reads the layer
/// through the same mount, so the denial was the authority file and not the door.
#[test]
fn a_space_authority_attenuates_a_handler_calling_an_override_mounted_layer() {
    let door_home = scratch("door");
    let certs = certs(&door_home);
    configure_door(&door_home, &certs);
    let (_door, banner) = start(
        &door_home,
        &[
            "serve",
            "quic://127.0.0.1:0",
            "--name",
            "layers",
            "--cert-dir",
            certs.to_str().unwrap(),
        ],
        "serving on",
    );
    let target = banner
        .lines()
        .find_map(|line| line.split("serving on ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no address in the banner:\n{banner}"))
        .to_string();
    let dir = certs.to_str().unwrap().to_string();
    let edge_cert = format!("{dir}/clients/edge.crt");
    let edge_key = format!("{dir}/clients/edge.key");
    let mount = [
        "--override".to_string(),
        format!("urn:layer:={target}"),
        "--cert-dir".to_string(),
        dir,
        "--client-cert".to_string(),
        edge_cert,
        "--client-key".to_string(),
        edge_key,
    ];

    // The reactor's home: a `contact` space pinned to the layer read, under an authority that
    // OMITS the layer token (it holds the tuplespace verbs, so it is a real grant, not none).
    let host = scratch("reactor");
    let host_config = config_home(&host);
    let space = host.join("files").join("spaces").join("contact");
    std::fs::create_dir_all(space.join("inbox")).unwrap();
    write(
        host_config.join("space-handler/contact"),
        "urn:layer:inquiry\n",
    );
    let authority = host_config.join("space-authority/contact");
    write(
        authority.clone(),
        "# the tuplespace verbs, and NOT the layer token\n\
         urn:cap:space:out\nurn:cap:space:read\nurn:cap:space:take\n",
    );

    let mut daemon_args: Vec<&str> = mount.iter().map(String::as_str).collect();
    daemon_args.push("--daemon");
    let (_daemon, up) = start(&host, &daemon_args, "daemon up");
    assert!(
        up.contains("override"),
        "the daemon announces its mount:\n{up}"
    );

    let drop_tuple = |text: &str| -> String {
        ok(
            run(
                &host,
                &["--plain", "-c", "sink urn:space:contact"],
                Some(text),
            ),
            "drop a tuple into the contact space",
        )
        .trim()
        .to_string()
    };

    // 1. The authority omits the token, the door grants it: denied, naming the token.
    let first = drop_tuple("first");
    match settled(&space, &first) {
        Err(note) => assert!(
            note.contains(READ_INQUIRY),
            "the denial names the layer token the authority omits: {note}"
        ),
        Ok(answer) => panic!(
            "the handler read the remote layer under an authority that omits {READ_INQUIRY}: \
             the door's grant decided alone. It answered: {answer}"
        ),
    }

    // 2. The control: the authority lists the token (read fresh, no restart). The same handler
    // reads the same layer through the same mount.
    write(
        authority,
        &format!("urn:cap:space:out\nurn:cap:space:read\nurn:cap:space:take\n{READ_INQUIRY}\n"),
    );
    let second = drop_tuple("second");
    match settled(&space, &second) {
        Ok(answer) => assert!(
            answer.contains("tuplespace"),
            "the handler's answer is the remote layer's definition: {answer}"
        ),
        Err(note) => panic!("with the token granted the handler must run: {note}"),
    }

    let _ = std::fs::remove_dir_all(&door_home);
    let _ = std::fs::remove_dir_all(&host);
}
