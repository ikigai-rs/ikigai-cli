//! `serve quic://` hosts LAYERS when the config home has a `layers/` directory (ledger #1188),
//! through the REAL binary and the real QUIC door, with two enrolled client certificates.
//!
//! The enrollment is the one `ikigai-layers grants <config dir>` writes: this suite calls the
//! same generator (`ikigai_layers::grants`) over the same configuration, so what is proved is
//! that the door serves the files the layer host's own tool produces. Each certificate's
//! entry names its participant as `principal`, the door mints it into the connection's
//! capability (ledger #1179), and the layer stamps it into every write.
//!
//! ★ Every door binds port 0 and the test reads the bound port off its banner. Picking a port
//! by binding one and releasing it races a child another test thread spawns, which can
//! inherit the socket on macOS and hold the port (field guide 9h, ledger #1223).
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `quic_principals.rs` is: `HOME`,
//! `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set on each spawned process only.
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
const BOB: &str = "urn:collab:participant:bob";

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
    let dir = std::env::temp_dir().join(format!("iki-ls-{}-{case}", std::process::id()));
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
        // The test harness may run with the developer's own overrides set; these would
        // point the child at real enrolment files.
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

/// A certificate set: the server pair, the base client, and `alice` and `bob`.
fn certs(home: &Path) -> PathBuf {
    let dir = home.join("certs");
    let d = dir.to_str().unwrap();
    ok(
        run(home, &["cert", "generate", "--dir", d]),
        "cert generate",
    );
    for name in ["alice", "bob"] {
        ok(
            run(home, &["cert", "add-client", name, "--cert-dir", d]),
            "cert add-client",
        );
    }
    dir
}

/// The fingerprint a door keys a client by: lowercase hex SHA-256 of its certificate DER.
fn fingerprint(cert: &Path) -> String {
    let pem = std::fs::read_to_string(cert).expect("the client certificate");
    ikigai_quic::fingerprint_of_pem(&pem).expect("a certificate")
}

/// A throwaway age identity at `path`, as `age-keygen -o` writes one: the key the layer host
/// seals its state to (ikigai-layers 0.3.0, ledger #2011).
fn mint_key(path: &Path) -> age::x25519::Identity {
    let identity = age::x25519::Identity::generate();
    write(
        path.to_path_buf(),
        age::secrecy::ExposeSecret::expose_secret(&identity.to_string()),
    );
    identity
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// The closed shapes every write is admitted against: a message, an offer, each allowing
/// the three stamps the host adds.
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

const CONTEXT: &str = r#"{ "@context": {
  "ik": "https://ikigai-rs.dev/ns#",
  "dcterms": "http://purl.org/dc/terms/",
  "Message": "ik:Message", "Offer": "ik:Offer",
  "body": "ik:body", "title": "dcterms:title", "brief": "ik:brief"
} }
"#;

/// The configuration, in the config home: three layers in two collaborations.
///
/// - `talk` (a channel) and `tasks` (an addressed tuplespace), mounted by `pair`: alice and
///   bob both read, follow, say, drop and take;
/// - `side` (a channel), mounted by `solo`: alice alone. Bob is in no collaboration that
///   mounts it, so nothing of it may reach his manifold.
///
/// Then the enrollment, generated by the layer host's own generator into the config home.
fn configure_layers(home: &Path, certs: &Path) {
    let config = config_home(home);
    write(config.join("layers/shapes.ttl"), SHAPES);
    write(config.join("layers/context.jsonld"), CONTEXT);
    let channel = "model = \"channel\"\nshapes = \"shapes.ttl\"\ncontext = \"context.jsonld\"\n";
    write(config.join("layers/talk.toml"), channel);
    write(config.join("layers/side.toml"), channel);
    write(
        config.join("layers/tasks.toml"),
        "model = \"tuplespace\"\nshapes = \"shapes.ttl\"\ncontext = \"context.jsonld\"\naddressed = true\n",
    );
    write(
        config.join("participants.ttl"),
        &format!(
            "@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n<{ALICE}> a foaf:Person .\n<{BOB}> a foaf:Person .\n"
        ),
    );
    write(
        config.join("collabs/pair.toml"),
        "[[mount]]\nlayer = \"talk\"\nalice = [\"read\", \"feed\", \"say\"]\nbob = [\"read\", \"feed\", \"say\"]\n\n\
         [[mount]]\nlayer = \"tasks\"\nalice = [\"read\", \"feed\", \"out\", \"take\"]\nbob = [\"read\", \"feed\", \"out\", \"take\"]\n",
    );
    write(
        config.join("collabs/solo.toml"),
        "[[mount]]\nlayer = \"side\"\nalice = [\"read\", \"feed\", \"say\"]\n",
    );
    write(
        config.join("enrollment.toml"),
        &format!(
            "alice = \"{}\"\nbob = \"{}\"\n",
            fingerprint(&certs.join("clients/alice.crt")),
            fingerprint(&certs.join("clients/bob.crt"))
        ),
    );
    // The host's key through the config home's channel (`layers.key`), so every door below
    // opens sealed without a flag; the sealed-state tests name theirs with `--layers-key`.
    mint_key(&home.join("state.key"));
    write(
        config.join("config.toml"),
        &format!("layers.key = \"{}\"\n", home.join("state.key").display()),
    );
    // `ikigai-layers grants <config home>`, as a library call.
    let loaded = ikigai_layers::Config::load(&config).expect("the configuration checks");
    let fingerprints: BTreeMap<String, BTreeSet<String>> =
        ikigai_layers::grants::load_fingerprints(&config, &loaded).expect("enrollment.toml");
    let enrollment =
        ikigai_layers::grants::generate(&loaded, &fingerprints).expect("an enrollment");
    assert_eq!(enrollment.clients.len(), 2, "both certificates enrolled");
    enrollment
        .write(&config)
        .expect("grants.json and clients.json");
}

/// Start `serve quic://127.0.0.1:0 --name layers` with `extra` flags. Returns the door, the
/// address its banner names (the BOUND port) and its stderr up to the banner.
fn serve(home: &Path, certs: &Path, extra: &[&str]) -> (Door, String, String) {
    let mut args = vec![
        "serve",
        "quic://127.0.0.1:0",
        "--name",
        "layers",
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
    // Keep draining after the banner, so the door's log is a pipe someone reads.
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
    assert!(
        !target.ends_with(":0"),
        "the banner names the BOUND port, not the one asked for: {target}"
    );
    (door, target, seen)
}

/// Ask the door `command` as `who` (`alice` or `bob`), writing `stdin` to the client when
/// given (the value a content-less `sink` reads).
fn ask(
    home: &Path,
    certs: &Path,
    who: &str,
    target: &str,
    command: &str,
    stdin: Option<&str>,
) -> Output {
    let dir = certs.to_str().unwrap();
    let cert = format!("{dir}/clients/{who}.crt");
    let key = format!("{dir}/clients/{who}.key");
    let mut child = spawn(
        home,
        &[
            "--cert-dir",
            dir,
            "--client-cert",
            &cert,
            "--client-key",
            &key,
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
        // Dropped here: EOF, so the client reads the whole value.
    }
    child.wait_with_output().expect("the client ran")
}

/// The first line of a successful answer: an IRI a write answered with.
fn first_line(out: Output, what: &str) -> String {
    ok(out, what)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

const IK: &str = "https://ikigai-rs.dev/ns#";

fn message(body: &str) -> String {
    format!("@prefix ik: <{IK}> .\n<urn:layer:new> a ik:Message ; ik:body \"{body}\" .\n")
}

/// A message in a channel layer is attributed to EACH sender's principal — the one the door
/// minted from that sender's certificate — and a sender that sends any of the three stamps
/// (attribution, time, sequence) is refused, so none can be forged.
#[test]
fn a_message_in_a_channel_layer_is_attributed_to_each_sender_and_a_sent_stamp_is_refused() {
    let home = scratch("chan");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    let state = home.join("layer-state");
    let (_door, target, banner) =
        serve(&home, &certs, &["--layers-state", state.to_str().unwrap()]);
    assert!(
        banner.contains("layers: side (channel), talk (channel), tasks (tuplespace)"),
        "the banner names what it hosts: {banner}"
    );
    assert!(
        banner.contains(&format!("state in {} (flag)", state.display())),
        "and where the state lives, by which channel: {banner}"
    );
    assert!(
        banner.contains("state sealed at rest to age1")
            && banner.contains(&format!(
                "(key {}, config)",
                home.join("state.key").display()
            )),
        "and the key it is sealed with, by which channel: {banner}"
    );

    let say = |who: &str, body: &str| {
        first_line(
            ask(
                &home,
                &certs,
                who,
                &target,
                "sink urn:layer:talk:say",
                Some(&message(body)),
            ),
            &format!("{who} says"),
        )
    };
    let from_alice = say("alice", "hello from alice");
    let from_bob = say("bob", "hello from bob");
    for (entry, author) in [(&from_alice, ALICE), (&from_bob, BOB)] {
        assert!(
            entry.starts_with("urn:layer:talk:entry:"),
            "an entry IRI: {entry}"
        );
        // Read back by the OTHER participant: what is stored, not what the writer saw.
        let reader = if author == ALICE { "bob" } else { "alice" };
        let stored = ok(
            ask(
                &home,
                &certs,
                reader,
                &target,
                &format!("source {entry}"),
                None,
            ),
            "read an entry",
        );
        assert!(
            stored.contains(&format!("prov:wasAttributedTo <{author}>")),
            "{entry} is attributed to {author}:\n{stored}"
        );
        assert!(stored.contains("dcterms:created") && stored.contains("ik:seq"));
    }
    let feed = ok(
        ask(
            &home,
            &certs,
            "bob",
            &target,
            "source urn:layer:talk:feed after=0",
            None,
        ),
        "the feed",
    );
    assert!(
        feed.contains(&format!(" say {from_alice} {ALICE}")),
        "{feed}"
    );
    assert!(feed.contains(&format!(" say {from_bob} {BOB}")), "{feed}");

    // Each stamp, sent by a writer, is refused, and nothing is stored or logged.
    for (prefix, stamp) in [
        (
            "@prefix prov: <http://www.w3.org/ns/prov#> .",
            format!("prov:wasAttributedTo <{ALICE}>"),
        ),
        (
            "@prefix dcterms: <http://purl.org/dc/terms/> .\n@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .",
            "dcterms:created \"2026-01-01T00:00:00Z\"^^xsd:dateTime".to_string(),
        ),
        ("", "ik:seq 99".to_string()),
    ] {
        let forged = format!(
            "@prefix ik: <{IK}> .\n{prefix}\n<urn:layer:new> a ik:Message ; ik:body \"forged\" ; {stamp} .\n"
        );
        let out = ask(
            &home,
            &certs,
            "bob",
            &target,
            "sink urn:layer:talk:say",
            Some(&forged),
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && stderr.contains("stamped by the host"),
            "a sent `{stamp}` is refused: {}{stderr}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
    let feed = ok(
        ask(
            &home,
            &certs,
            "alice",
            &target,
            "source urn:layer:talk:feed after=0",
            None,
        ),
        "the feed again",
    );
    assert_eq!(
        feed.lines().filter(|l| l.contains(" say ")).count(),
        2,
        "no refused write reached the feed: {feed}"
    );
    assert!(
        state.join("talk").join("feed.log").is_file(),
        "the state lives where --layers-state said"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// A take in a tuplespace layer names its TAKER — bob, from his certificate — in the feed and
/// in the receipt the host commits before replying; the dropper is named on the `out`; and a
/// second taker is refused with a Conflict that names the first.
#[test]
fn a_take_in_a_tuplespace_layer_names_its_taker_in_the_feed_and_a_receipt() {
    let home = scratch("take");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    let (_door, target, _banner) = serve(&home, &certs, &[]);

    let offer = "urn:layer:tasks:offer:01m4hhr0z8";
    let dropped = first_line(
        ask(
            &home,
            &certs,
            "alice",
            &target,
            "sink urn:layer:tasks:tuples",
            Some(&format!(
                "@prefix ik: <{IK}> .\n@prefix dcterms: <http://purl.org/dc/terms/> .\n\
                 <{offer}> a ik:Offer ; dcterms:title \"Host layers\" ; ik:brief \"Serve them.\" .\n"
            )),
        ),
        "alice drops an offer",
    );
    assert_eq!(dropped, offer, "out answers the tuple's subject");

    let taken = ok(
        ask(
            &home,
            &certs,
            "bob",
            &target,
            &format!("delete urn:layer:tasks:tuples {offer}"),
            None,
        ),
        "bob takes it",
    );
    assert!(
        taken.contains("Host layers"),
        "a take answers the tuple: {taken}"
    );

    let feed = ok(
        ask(
            &home,
            &certs,
            "alice",
            &target,
            "source urn:layer:tasks:feed after=0",
            None,
        ),
        "the task feed",
    );
    assert!(feed.contains(&format!(" out {offer} {ALICE}")), "{feed}");
    assert!(feed.contains(&format!(" taken {offer} {BOB}")), "{feed}");

    let receipt = ok(
        ask(
            &home,
            &certs,
            "alice",
            &target,
            &format!("source urn:layer:tasks:tuples state=taken tuple={offer}"),
            None,
        ),
        "the receipt",
    );
    assert!(
        receipt.contains(&format!("prov:wasAssociatedWith <{BOB}>")),
        "the receipt names the taker:\n{receipt}"
    );

    let again = ask(
        &home,
        &certs,
        "alice",
        &target,
        &format!("delete urn:layer:tasks:tuples {offer}"),
        None,
    );
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(
        !again.status.success() && stderr.contains(BOB),
        "a second taker is refused, told who won: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// The layer families a manifold names: `talk` from `urn:layer:talk:say`, and so on.
fn layers_in(manifold: &str) -> BTreeSet<String> {
    manifold
        .lines()
        .filter_map(|line| line.trim().strip_prefix("urn:layer:"))
        .map(|rest| rest.split(':').next().unwrap_or(rest).to_string())
        .collect()
}

/// A participant's manifold (`urn:kernel:actions` under the capability its certificate
/// earns) lists exactly its layers' actions: every action of every layer it holds, and
/// nothing of a layer it is not in.
#[test]
fn a_participants_manifold_lists_exactly_its_layers_actions() {
    let home = scratch("mani");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    let (_door, target, _banner) = serve(&home, &certs, &[]);
    let manifold = |who: &str| {
        ok(
            ask(
                &home,
                &certs,
                who,
                &target,
                "source urn:kernel:actions",
                None,
            ),
            &format!("{who}'s manifold"),
        )
    };
    let set = |names: &[&str]| names.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();

    let bob = manifold("bob");
    assert_eq!(layers_in(&bob), set(&["talk", "tasks"]), "bob:\n{bob}");
    assert!(
        !bob.contains("urn:layer:side"),
        "nothing of side reaches bob:\n{bob}"
    );
    let alice = manifold("alice");
    assert_eq!(
        layers_in(&alice),
        set(&["side", "talk", "tasks"]),
        "alice:\n{alice}"
    );

    // Every action each layer binds, by its model.
    for action in [
        "urn:layer:talk",
        "urn:layer:talk:say",
        "urn:layer:talk:entries",
        "urn:layer:talk:entry:{id}",
        "urn:layer:talk:latest",
        "urn:layer:talk:feed",
        "urn:layer:tasks:tuples",
        "urn:layer:tasks:receipt:{id}",
        "urn:layer:tasks:feed",
        "urn:layers:feed",
    ] {
        assert!(
            bob.lines().any(|line| line.trim() == action),
            "bob holds {action}:\n{bob}"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// Whether a catalog endpoint id is one a hosted layer brings: the layer actions
/// (`layer-{layer}-{action}`), the host-wide reads (`layers-feed`, `layers-participants`,
/// `layers-me`) and the collaboration reads (`collab`, `collab-participants`). Not the
/// validator: since ikigai-layers 0.2.1 admission validates inside the host, and the door
/// binds no `shacl-validate` (ledger #1295).
fn is_layer_endpoint(id: &str) -> bool {
    id.starts_with("layer-") || id.starts_with("layers-") || id.starts_with("collab")
}

/// Ledger #1295: a layer door offers NO participant a validator. Under ikigai-layers 0.2.0
/// admission composed `urn:shacl:validate`, so the door bound it beside the layers, and since
/// it declares no capability every participant's manifold listed it. Since 0.2.1 the host
/// validates each write itself: the door binds the layer space alone, admission still works
/// (a write is admitted), and `urn:layers:me` (0.2.2) tells each participant who the door
/// minted it as.
#[test]
fn a_layer_door_offers_no_validator_and_tells_each_participant_who_it_is() {
    let home = scratch("me");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    let (_door, target, _banner) = serve(&home, &certs, &[]);

    for (who, principal) in [("alice", ALICE), ("bob", BOB)] {
        let manifold = ok(
            ask(
                &home,
                &certs,
                who,
                &target,
                "source urn:kernel:actions",
                None,
            ),
            &format!("{who}'s manifold"),
        );
        assert!(
            manifold.contains("urn:layer:talk:say"),
            "{who}'s manifold was read:\n{manifold}"
        );
        assert!(
            !manifold.contains("urn:shacl:") && !manifold.contains("shacl-"),
            "no validator is offered to {who}:\n{manifold}"
        );

        let me = ok(
            ask(
                &home,
                &certs,
                who,
                &target,
                "source urn:layers:me as=application/json",
                None,
            ),
            &format!("{who}'s urn:layers:me"),
        );
        let me: serde_json::Value = serde_json::from_str(me.trim())
            .unwrap_or_else(|e| panic!("{who}: urn:layers:me is JSON ({e}): {me}"));
        assert_eq!(me["principal"], principal, "{who}: {me}");
    }

    // Admission still runs with no validator bound: a conforming message is admitted.
    let said = first_line(
        ask(
            &home,
            &certs,
            "bob",
            &target,
            "sink urn:layer:talk:say",
            Some(&message("validated in the host")),
        ),
        "bob says",
    );
    assert!(said.starts_with("urn:layer:talk:entry:"), "{said}");
    let _ = std::fs::remove_dir_all(&home);
}

/// With NO `layers/` directory the door is the door it always was: no layer, no banner line, and
/// the general served surface. With `layers/` the same config home serves the layers INSTEAD:
/// every endpoint it adds is a layer endpoint, and nothing of the general surface remains
/// (a layer door serves only its layers).
#[test]
fn without_a_layers_directory_serve_is_unchanged() {
    let home = scratch("none");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    // The catalog is the WHOLE surface (`urn:kernel:actions` is only what a grant reaches),
    // and reading it takes `urn:cap:kernel:inspect`: give alice's generated grant that too.
    let grants_path = config_home(&home).join("grants.json");
    let mut grants: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&grants_path).unwrap()).unwrap();
    grants["alice"]
        .as_array_mut()
        .expect("alice's grant is a list of scopes")
        .push("urn:cap:kernel:inspect".into());
    std::fs::write(&grants_path, grants.to_string()).unwrap();
    let (door, target, banner) = serve(&home, &certs, &[]);
    let with = ok(
        ask(
            &home,
            &certs,
            "alice",
            &target,
            "source urn:kernel:catalog",
            None,
        ),
        "the catalog with layers",
    );
    drop(door);

    // The same config home without `layers/`: the enrollment stays, so alice is still served.
    std::fs::remove_dir_all(config_home(&home).join("layers")).unwrap();
    let (_door, target, plain) = serve(&home, &certs, &[]);
    assert!(banner.contains("surface: layers;"), "{banner}");
    assert!(plain.contains("surface: host + fs;"), "{plain}");
    assert!(
        !plain.contains("ikigai: layers:"),
        "no layers line: {plain}"
    );
    let without = ok(
        ask(
            &home,
            &certs,
            "alice",
            &target,
            "source urn:kernel:catalog",
            None,
        ),
        "the catalog without layers",
    );
    // The catalog is Turtle, one `ik:Endpoint` per bound endpoint, each with its `ik:id`.
    let ids = |catalog: &str| -> BTreeSet<String> {
        catalog
            .lines()
            .filter_map(|line| line.trim().strip_prefix("ik:id \""))
            .filter_map(|rest| rest.split('"').next())
            .map(str::to_string)
            .collect()
    };
    let (with, without) = (ids(&with), ids(&without));
    assert!(
        without.contains("host-identity"),
        "the catalog was read: {without:?}"
    );
    for id in &without {
        assert!(
            !is_layer_endpoint(id),
            "no layer endpoint without layers/: {id}"
        );
    }
    let added: Vec<&String> = with.difference(&without).collect();
    assert!(
        added.contains(&&"layer-talk-say".to_string())
            && added.contains(&&"layer-tasks-tuples".to_string())
            && added.contains(&&"layers-me".to_string()),
        "hosting layers adds the layers: {added:?}"
    );
    assert!(
        !with.iter().any(|id| id.starts_with("shacl-")),
        "and no validator (ledger #1295): {with:?}"
    );
    for id in &added {
        assert!(
            is_layer_endpoint(id),
            "hosting layers adds ONLY layer endpoints, not {id}"
        );
    }
    // What both doors serve is only the kernel's own resources (the catalog, the manifold):
    // the general served surface is not on the layer door at all.
    let kept: Vec<&String> = with.intersection(&without).collect();
    for id in &kept {
        assert!(
            id.starts_with("kernel-"),
            "a layer door keeps nothing of the general surface, not {id}: {kept:?}"
        );
    }
    for gone in [
        "host-identity",
        "host-info",
        "passkey-challenge",
        "passkey-register",
    ] {
        assert!(
            without.contains(gone) && !with.contains(gone),
            "{gone} is on the general door and not on the layer door"
        );
    }

    // A state directory, a key or a reseal for a door that hosts no layer is a flag that does
    // nothing: refused. (The config home's `layers.key` stays: it is for whichever process
    // hosts layers, and this one hosts none.)
    let nowhere = home.join("nowhere");
    for flag in [
        &["--layers-state", nowhere.to_str().unwrap()][..],
        &["--layers-key", nowhere.to_str().unwrap()][..],
        &["--layers-reseal"][..],
    ] {
        let mut args = vec![
            "serve",
            "quic://127.0.0.1:0",
            "--cert-dir",
            certs.to_str().unwrap(),
        ];
        args.extend_from_slice(flag);
        let out = run(&home, &args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && stderr.contains(flag[0]),
            "{flag:?}: {stderr}"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// Start `serve quic://127.0.0.1:0 --name layers` with `extra` flags and report how it
/// ENDED: `Ok(banner)` when it printed `serving on` (the door is killed), `Err((code, stderr))`
/// when it exited first.
fn start_or_refuse(home: &Path, certs: &Path, extra: &[&str]) -> Result<String, (i32, String)> {
    let mut args = vec![
        "serve",
        "quic://127.0.0.1:0",
        "--name",
        "layers",
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
        let mut served = false;
        let mut lines = BufReader::new(stderr).lines().map_while(Result::ok);
        for line in lines.by_ref() {
            seen.push_str(&line);
            seen.push('\n');
            if line.contains("serving on") {
                served = true;
                break;
            }
        }
        let _ = tx.send((served, seen));
        lines.for_each(drop);
    });
    let (served, seen) = rx
        .recv_timeout(PATIENCE)
        .unwrap_or_else(|e| panic!("`{args:?}` neither served nor exited: {e}"));
    if served {
        let _ = child.kill();
        let _ = child.wait();
        return Ok(seen);
    }
    // stderr reached EOF: the process is exiting. `wait`, never `try_wait` (field guide 9h).
    let status = child.wait().expect("the door's exit status");
    Err((status.code().unwrap_or(-1), seen))
}

/// ledger #1281: a door whose config home has `layers/` but NO `clients.json` used to start in
/// the per-client-workspace posture, where every trusted certificate gets fs read, write and
/// delete in its own segment and no participant has a grant. A door that hosts layers is for
/// participants, so it refuses to start without per-identity grants, under `--cap` too, and
/// says which file is missing. Without `layers/`, the same config home still serves as before.
#[test]
fn a_layer_door_without_per_identity_grants_refuses_to_start() {
    let home = scratch("nogrants");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    std::fs::remove_file(config_home(&home).join("clients.json")).unwrap();

    for extra in [&[][..], &["--cap", "urn:cap:space:read"][..]] {
        let (code, stderr) = start_or_refuse(&home, &certs, extra)
            .expect_err("a layer door with no clients.json must not serve");
        assert_ne!(code, 0, "{extra:?}: a refusal exits non-zero: {stderr}");
        assert!(
            stderr.contains("clients.json") && stderr.contains("grants.json"),
            "{extra:?}: the refusal names the per-identity grants it needs: {stderr}"
        );
        assert!(!stderr.contains("serving on"), "{extra:?}: {stderr}");
    }

    // The same config home without `layers/` is the door it always was.
    std::fs::remove_dir_all(config_home(&home).join("layers")).unwrap();
    let banner = start_or_refuse(&home, &certs, &[]).expect("a door without layers/ serves");
    assert!(banner.contains("per-client workspaces"), "{banner}");
    let _ = std::fs::remove_dir_all(&home);
}

/// The connection flags a layer CLIENT passes to follow the door as `who`, with ONE mount
/// flag naming all three prefixes and ONE certificate set after it (ledger #1283). Before,
/// this took three `--override` flags, each followed by its own `--cert-dir`, since cert flags
/// attach to the mount they follow.
fn follow(certs: &Path, who: &str, target: &str) -> Vec<String> {
    let dir = certs.to_str().unwrap();
    vec![
        "--override".into(),
        format!("urn:layer:,urn:layers:,urn:collab:={target}"),
        "--cert-dir".into(),
        dir.into(),
        "--client-cert".into(),
        format!("{dir}/clients/{who}.crt"),
        "--client-key".into(),
        format!("{dir}/clients/{who}.key"),
    ]
}

/// Run the EMBEDDED client (no `--connect`: the door is mounted) with `connection` and one
/// command, writing `stdin` when given.
fn through(home: &Path, connection: &[String], command: &str, stdin: Option<&str>) -> Output {
    let mut args: Vec<&str> = connection.iter().map(String::as_str).collect();
    args.extend(["--plain", "-c", command]);
    let mut child = spawn(home, &args)
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

/// ledger #1283: one mount flag naming `urn:layer:,urn:layers:,urn:collab:` and one cert set
/// reach all three of the door's prefixes: a say under `urn:layer:`, the multiplexed feed
/// under `urn:layers:` (which `urn:layer:` does not reach) and the collaboration under
/// `urn:collab:`. The banner shows the line as written.
#[test]
fn one_mount_flag_with_one_cert_set_follows_all_three_layer_prefixes() {
    let home = scratch("follow");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    let (_door, target, _banner) = serve(&home, &certs, &[]);
    let alice = follow(&certs, "alice", &target);

    let said = through(
        &home,
        &alice,
        "sink urn:layer:talk:say",
        Some(&message("one connection")),
    );
    let entry = ok(said, "alice says, through the mount")
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    assert!(entry.starts_with("urn:layer:talk:entry:"), "{entry}");

    let feed = ok(
        through(&home, &alice, "source urn:layers:feed after=talk:0", None),
        "the multiplexed feed, under urn:layers:",
    );
    assert!(
        feed.contains("talk 1 ") && feed.contains(&format!(" say {entry} {ALICE}")),
        "the say is in the host-wide feed: {feed}"
    );
    let collab = ok(
        through(&home, &alice, "source urn:collab:pair", None),
        "the collaboration, under urn:collab:",
    );
    assert!(
        collab.contains("talk"),
        "the manifest names its layers: {collab}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// ledger #1284: `ikigai mcp` for a layer door lists ONLY the door's tools when told
/// `--show` the three prefixes. Without `--show` the local kernel's capability-free tools
/// (`about`, `echo`, `sparql-*`, …) are listed beside them.
#[test]
fn mcp_shows_only_the_layer_doors_tools_under_its_prefixes() {
    let home = scratch("mcp");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    let (_door, target, _banner) = serve(&home, &certs, &[]);

    let tools = |show: bool| -> Vec<String> {
        let mut args: Vec<String> = vec!["mcp".into()];
        for scope in [
            "urn:cap:layer:read:talk",
            "urn:cap:layer:feed:talk",
            "urn:cap:layer:say:talk",
            "urn:cap:collab:read:pair",
        ] {
            args.extend(["--scope".into(), scope.into()]);
        }
        args.extend(follow(&certs, "alice", &target));
        if show {
            for prefix in ["urn:layer:", "urn:layers:", "urn:collab:"] {
                args.extend(["--show".into(), prefix.into()]);
            }
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut child = spawn(&home, &args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("mcp starts");
        {
            let mut stdin = child.stdin.take().expect("piped stdin");
            writeln!(
                stdin,
                "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}"
            )
            .expect("write tools/list");
        }
        let out = ok(child.wait_with_output().expect("mcp ran"), "mcp tools/list");
        let line = out.lines().next().expect("one response");
        let v: serde_json::Value = serde_json::from_str(line).expect("a JSON-RPC line");
        v["result"]["tools"]
            .as_array()
            .expect("a tools/list result")
            .iter()
            .filter_map(|t| t["name"].as_str().map(str::to_string))
            .collect()
    };

    let shown = tools(true);
    assert!(
        shown.contains(&"layer-talk-say__sink".to_string())
            && shown.contains(&"layers-feed__source".to_string()),
        "the door's tools are listed: {shown:?}"
    );
    for name in &shown {
        assert!(
            name.starts_with("layer-") || name.starts_with("layers-") || name.starts_with("collab"),
            "only the door's tools, not {name}: {shown:?}"
        );
    }
    let everything = tools(false);
    assert!(
        everything.iter().any(|n| n == "echo__source"),
        "without --show the local capability-free tools are listed too: {everything:?}"
    );
    assert!(
        shown.iter().all(|n| everything.contains(n)),
        "--show only narrows"
    );
    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------------------------
// Ledger #1688 (threat model S4 gap 1, enforcement row L-18): the layer door used to bind the
// whole served surface BEHIND the layers, so every endpoint `served_space` binds was reachable by
// name from a participant's connection, and only the endpoints that declare a capability refused.
// A layer door now binds the layers alone (the section after this one); these probes are what a
// participant would have reached first, and the widened door below holds that putting the keys
// and a relying party on such a door still opens none of them.
// ---------------------------------------------------------------------------------------------

/// What a protected endpoint is asked, and how its refusal must read.
struct Probe {
    command: String,
    stdin: Option<String>,
    /// A piece of the refusal: the capability the floor names, or the missing key.
    refused_with: String,
}

fn probe(command: &str, stdin: Option<&str>, refused_with: &str) -> Probe {
    Probe {
        command: command.to_string(),
        stdin: stdin.map(str::to_string),
        refused_with: refused_with.to_string(),
    }
}

/// Every probe that does not depend on the decision-link keys: the public intake doors, the
/// spaces (the airlock), the blocklist, the client registry, the host's posture and switches,
/// the file module, the passkey enrollment (store and window opener) and the kernel's catalog.
fn protected_probes() -> Vec<Probe> {
    let enquiry = "name=Mallory&email=mallory%40example.org&message=hello";
    vec![
        probe(
            "sink urn:contact:submit",
            Some(enquiry),
            "urn:cap:contact:submit",
        ),
        probe(
            "sink urn:booking:submit",
            Some(enquiry),
            "urn:cap:booking:submit",
        ),
        probe("source urn:space:contact", None, "urn:cap:space:read"),
        probe(
            "sink urn:space:contact",
            Some("((contact \"x\"))"),
            "urn:cap:space:out",
        ),
        probe("delete urn:space:contact", None, "urn:cap:space:take"),
        probe("source urn:space:decisions", None, "urn:cap:space:read"),
        probe(
            "sink urn:space:decisions",
            Some("((decide \"approve\"))"),
            "urn:cap:space:out",
        ),
        probe("delete urn:space:decisions", None, "urn:cap:space:take"),
        probe("source urn:decisions", None, "urn:cap:decisions:read"),
        probe(
            "sink urn:decisions",
            Some("mallory@example.org"),
            "urn:cap:decisions:write",
        ),
        probe("source urn:client:anyone", None, "urn:cap:client:read"),
        probe("source urn:host:posture", None, "urn:cap:host:posture"),
        probe("sink urn:host:demo", Some("on"), "urn:cap:host:write:demo"),
        probe(
            "sink urn:host:history",
            Some("on"),
            "urn:cap:host:write:history",
        ),
        probe("source urn:file:decide.pub", None, "urn:cap:fs:read"),
        probe(
            "sink urn:file:passkey-enroll.open",
            Some("{}"),
            "urn:cap:fs:write",
        ),
        probe("delete urn:file:decide.pub", None, "urn:cap:fs:delete"),
        probe("source urn:kernel:catalog", None, "urn:cap:kernel:inspect"),
        // Not bound on any served surface: opening an enrollment window is the box's act.
        probe(
            "sink urn:passkey:enroll-open",
            Some(""),
            "no endpoint resolved",
        ),
    ]
}

/// Ask the door every probe as `who`; each must fail, naming its refusal.
fn assert_refused(home: &Path, certs: &Path, target: &str, who: &str, probes: &[Probe]) {
    for p in probes {
        let out = ask(home, certs, who, target, &p.command, p.stdin.as_deref());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "{who} must be refused `{}`, and was answered:\n{}",
            p.command,
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            stderr.contains(&p.refused_with),
            "{who}'s `{}` is refused naming `{}`:\n{stderr}",
            p.command,
            p.refused_with
        );
    }
}

/// Every file under `dir`, relative to it, so a test can say nothing was written.
fn files_under(dir: &Path) -> BTreeSet<String> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeSet<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.map_while(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(dir, dir, &mut out);
    out
}

/// Sign `payload` with `key`, as the Mac (decide) and the edge (block, label) mint a link.
fn signed(key: &ed25519_dalek::SigningKey, payload: &str) -> String {
    use base64::Engine;
    use ed25519_dalek::Signer;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.sign(payload.as_bytes()).to_bytes())
}

fn write_public_key(path: PathBuf, key: &ed25519_dalek::SigningKey) {
    use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePublicKey};
    let pem = key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("an SPKI PEM");
    write(path, &pem);
}

/// The same door WIDENED past what the edge deploys: the decision and block/label public keys
/// in its file root, a passkey relying party configured, and links that are VALIDLY signed (a
/// participant who has seen a leaked email link). None of it is reachable: a layer door binds
/// neither the links nor the passkey endpoints, so what lands in its file root or on its command
/// line cannot turn them into live gates on a door whose principals are outside collaborators.
/// Before, the links verified here and only the participant's missing `urn:cap:space:out` stood
/// between a leaked link and a recorded decision.
#[test]
fn a_widened_layer_door_still_binds_no_link_and_no_passkey_endpoint() {
    let home = scratch("widened");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    let files = home.join("files");
    let decide = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let block = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    write_public_key(files.join("decide.pub"), &decide);
    write_public_key(files.join("contact-block.pub"), &block);
    let before = files_under(&files);
    let (_door, target, _banner) = serve(&home, &certs, &["--passkey-rp-id", "edge.test"]);

    let exp = 99_999_999_999_i64;
    let booking = "abcdefgh12";
    let enquiry = "a".repeat(64);
    let approve_token = signed(&decide, &format!("{booking}|approve|{exp}"));
    let approve = format!("id={booking}&exp={exp}&t={approve_token}");
    let block_link = format!(
        "email=mallory%40example.org&id=&exp={exp}&t={}",
        signed(&block, &format!("contact-block|mallory@example.org||{exp}"))
    );
    let label_link = format!(
        "label=ham&id={enquiry}&exp={exp}&t={}",
        signed(&block, &format!("contact-label|ham|{enquiry}|{exp}"))
    );
    let unbound = "no endpoint resolved";
    let show =
        format!("source urn:calendar-request:approve id={booking} exp={exp} t={approve_token}");
    let mut probes = vec![
        probe(&show, None, unbound),
        probe("sink urn:calendar-request:approve", Some(&approve), unbound),
        probe("sink urn:contact-block", Some(&block_link), unbound),
        probe("sink urn:contact-label", Some(&label_link), unbound),
        probe("source urn:passkey:challenge", None, unbound),
        probe(
            "sink urn:passkey:register",
            Some("code=x&id=YWJj&spki=YWJj"),
            unbound,
        ),
    ];
    probes.extend(general_surface_probes());
    for who in ["alice", "bob"] {
        assert_refused(&home, &certs, &target, who, &probes);
    }
    assert_eq!(
        files_under(&files),
        before,
        "nothing was dropped, recorded or enrolled under the door's file root"
    );
    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------------------------
// A layer door serves the layer spaces and nothing else. Its principals are collaborators whose
// grants name layer verbs only, so the general served surface a public door carries (the intake
// doors, the airlock spaces, the decision and block/label links, the passkey endpoints, the
// host's own resources, the demo endpoints, the file module) is not bound on it at all: a name
// it does not serve resolves nowhere, under every grant.
// ---------------------------------------------------------------------------------------------

/// Whether a manifold line names something a layer door serves: the layer families, and the
/// kernel's own resources (the manifold itself), which every kernel answers under their own
/// capabilities.
fn on_a_layer_door(iri: &str) -> bool {
    ["urn:layer:", "urn:layers:", "urn:collab:", "urn:kernel:"]
        .iter()
        .any(|family| iri.starts_with(family))
}

/// Every endpoint the general served surface binds that a participant could name, the ones a
/// participant's grant would have reached first: each must resolve nowhere on a layer door.
fn general_surface_probes() -> Vec<Probe> {
    let link = "id=abcdefgh12&exp=99999999999&t=AAAA";
    let unbound = "no endpoint resolved";
    let mut probes = vec![
        probe("source urn:passkey:challenge", None, unbound),
        probe("source urn:passkey:register", None, unbound),
        probe(
            "sink urn:passkey:register",
            Some("code=x&id=YWJj&spki=YWJj"),
            unbound,
        ),
        probe("source urn:passkey:js", None, unbound),
        probe("source urn:decide:css", None, unbound),
        probe("sink urn:calendar-request:approve", Some(link), unbound),
        probe("sink urn:contact-block", Some(link), unbound),
        probe("sink urn:contact-label", Some(link), unbound),
        probe("source urn:host:identity", None, unbound),
        probe("source urn:host:info", None, unbound),
        probe("source urn:demo:greeter", None, unbound),
        probe("source urn:data:page", None, unbound),
        probe("source urn:time:now", None, unbound),
    ];
    // And every protected one, which no longer reaches its capability floor: it is not there.
    probes.extend(
        protected_probes()
            .into_iter()
            .filter(|p| !p.command.contains("urn:kernel:"))
            .map(|p| Probe {
                refused_with: unbound.to_string(),
                ..p
            }),
    );
    probes
}

/// A participant on a layer door reaches the layers and NOTHING else: every endpoint of the
/// general served surface resolves nowhere (the passkey challenge and page, the decision and
/// block/label links, the host's identity and info, the demo greeter among them), its manifold
/// names only the layer families, a missing key's path is never in an answer, and the layers
/// themselves still work. The banner says the door's surface is the layers.
#[test]
fn a_layer_door_serves_its_layers_and_nothing_else() {
    let home = scratch("only");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    let files = home.join("files");
    std::fs::create_dir_all(&files).unwrap();
    let (_door, target, banner) = serve(&home, &certs, &[]);

    let probes = general_surface_probes();
    for who in ["alice", "bob"] {
        assert_refused(&home, &certs, &target, who, &probes);
        for p in &probes {
            let out = ask(&home, &certs, who, &target, &p.command, p.stdin.as_deref());
            let said = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                !said.contains(home.to_str().unwrap()) && !said.contains("public key"),
                "{who}'s `{}` names no path and no key: {said}",
                p.command
            );
        }
        let manifold = ok(
            ask(
                &home,
                &certs,
                who,
                &target,
                "source urn:kernel:actions",
                None,
            ),
            &format!("{who}'s manifold"),
        );
        let named: Vec<&str> = manifold
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("urn:"))
            .collect();
        assert!(
            named.contains(&"urn:layer:talk:say"),
            "{who}'s manifold was read:\n{manifold}"
        );
        for iri in named {
            assert!(
                on_a_layer_door(iri),
                "{who}'s manifold names only the layer families, not {iri}:\n{manifold}"
            );
        }
    }

    // The layers themselves: a say is admitted and attributed, and each participant is told who
    // the door minted it as.
    let said = first_line(
        ask(
            &home,
            &certs,
            "bob",
            &target,
            "sink urn:layer:talk:say",
            Some(&message("still served")),
        ),
        "bob says",
    );
    assert!(said.starts_with("urn:layer:talk:entry:"), "{said}");
    let me = ok(
        ask(
            &home,
            &certs,
            "alice",
            &target,
            "source urn:layers:me as=application/json",
            None,
        ),
        "alice's urn:layers:me",
    );
    assert!(me.contains(ALICE), "{me}");
    assert_eq!(
        files_under(&files),
        BTreeSet::new(),
        "nothing was written under the door's file root"
    );
    assert!(banner.contains("surface: layers;"), "{banner}");
    let _ = std::fs::remove_dir_all(&home);
}

/// A layer door refuses to start with a ceiling that would open a face beside the layers
/// (inference, the calendar, the governed eval) or with a mount, which would re-serve a peer's
/// surface to every participant: either is a wider surface than the layers, and a layer door
/// serves only its layers. It says why, and the same flags on a door without `layers/` serve.
#[test]
fn a_layer_door_refuses_a_face_or_a_mount_beside_its_layers() {
    let home = scratch("faces");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    for extra in [
        &["--cap", "urn:cap:net:localhost"][..],
        &["--cap", "urn:cap:personal:calendar:read:freebusy"][..],
        &["--cap", "urn:cap:lisp"][..],
        &["--prefer", "urn:elsewhere:=quic://127.0.0.1:9"][..],
    ] {
        let (code, stderr) =
            start_or_refuse(&home, &certs, extra).expect_err("a layer door serves only its layers");
        assert_ne!(code, 0, "{extra:?}: {stderr}");
        assert!(
            stderr.contains("serves only its layers"),
            "{extra:?}: the refusal says why: {stderr}"
        );
        assert!(!stderr.contains("serving on"), "{extra:?}: {stderr}");
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// Every file under `dir`, recursively.
fn files_in(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

/// The files under `state` that hold `text` in the clear.
fn holding(state: &Path, text: &str) -> Vec<PathBuf> {
    files_in(state)
        .into_iter()
        .filter(|file| {
            let bytes = std::fs::read(file).unwrap();
            bytes.windows(text.len()).any(|w| w == text.as_bytes())
        })
        .collect()
}

/// What a host before ikigai-layers 0.3.0 left: open every sealed file under `state` with
/// `identity` and write it back in the clear (a feed line at a time), and no key check. Only
/// channel layers are used where this is called, so no tuple is renamed.
fn unseal_all(state: &Path, identity: &age::x25519::Identity) {
    use base64::Engine;
    const MAGIC: &[u8] = b"age-encryption.org/v1";
    std::fs::remove_file(state.join("key-check.age")).unwrap();
    for file in files_in(state) {
        let bytes = std::fs::read(&file).unwrap();
        if file.file_name().is_some_and(|n| n == "feed.log") {
            let text: String = String::from_utf8(bytes)
                .unwrap()
                .lines()
                .map(|line| {
                    let sealed = base64::engine::general_purpose::STANDARD
                        .decode(line)
                        .unwrap();
                    String::from_utf8(age::decrypt(identity, &sealed).unwrap()).unwrap() + "\n"
                })
                .collect();
            std::fs::write(&file, text).unwrap();
        } else if bytes.starts_with(MAGIC) {
            std::fs::write(&file, age::decrypt(identity, &bytes).unwrap()).unwrap();
        }
    }
}

/// The feed of `talk` and one entry, as bob reads them.
fn read_talk(home: &Path, certs: &Path, target: &str, entry: &str) -> (String, String) {
    let feed = ok(
        ask(
            home,
            certs,
            "bob",
            target,
            "source urn:layer:talk:feed after=0",
            None,
        ),
        "the feed",
    );
    let stored = ok(
        ask(home, certs, "bob", target, &format!("source {entry}"), None),
        "an entry",
    );
    (feed, stored)
}

/// ledger #2011: a layer door's state is sealed at rest with the key `--layers-key` names. The
/// door serves, nothing it wrote holds a message or a participant in the clear, and a restart
/// with the same key serves the same feed. No key, a key file that is not there and a key that
/// is not this state's are each refused at startup, naming the problem, and serve nothing.
#[test]
fn a_sealed_layer_door_restarts_with_its_feed_and_refuses_a_missing_or_wrong_key() {
    let home = scratch("sealed");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    // Only the flag names a key here.
    std::fs::remove_file(config_home(&home).join("config.toml")).unwrap();
    let state = home.join("layer-state");
    let key = home.join("flag.key");
    mint_key(&key);
    let (s, k) = (state.to_str().unwrap(), key.to_str().unwrap());

    // No key: refused before the host opens, so nothing is written.
    let (code, stderr) = start_or_refuse(&home, &certs, &["--layers-state", s])
        .expect_err("a layer door with no key must not serve");
    assert_ne!(code, 0, "{stderr}");
    assert!(
        stderr.contains("--layers-key") && stderr.contains("layers.key"),
        "the refusal names both channels: {stderr}"
    );
    assert!(!state.exists(), "nothing was written without a key");

    let (door, target, banner) = serve(&home, &certs, &["--layers-state", s, "--layers-key", k]);
    assert!(
        banner.contains("state sealed at rest to age1")
            && banner.contains(&format!("(key {}, flag)", key.display())),
        "{banner}"
    );
    let entry = first_line(
        ask(
            &home,
            &certs,
            "alice",
            &target,
            "sink urn:layer:talk:say",
            Some(&message("a sealed hello")),
        ),
        "alice says",
    );
    let before = read_talk(&home, &certs, &target, &entry);
    assert!(before.1.contains("a sealed hello"), "{}", before.1);
    drop(door);
    assert!(state.join("key-check.age").is_file());
    for text in ["a sealed hello", ALICE] {
        assert_eq!(
            holding(&state, text),
            Vec::<PathBuf>::new(),
            "no state file holds `{text}` in the clear"
        );
    }

    // The same key: the same feed and entry, after a restart.
    let (door, target, _) = serve(&home, &certs, &["--layers-state", s, "--layers-key", k]);
    assert_eq!(read_talk(&home, &certs, &target, &entry), before);
    drop(door);

    // A key file that is not there, and a key that is not this state's.
    let absent = home.join("absent.key");
    let other = home.join("other.key");
    mint_key(&other);
    for (path, says) in [
        (&absent, "does not exist"),
        (&other, "does not open this state directory"),
    ] {
        let (code, stderr) = start_or_refuse(
            &home,
            &certs,
            &["--layers-state", s, "--layers-key", path.to_str().unwrap()],
        )
        .expect_err("a wrong key must not serve");
        assert_ne!(code, 0, "{stderr}");
        assert!(
            stderr.contains(says) && stderr.contains(path.to_str().unwrap()),
            "{path:?}: {stderr}"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// ledger #2011: a state directory an ikigai before 0.1.67 wrote holds plaintext, and a door
/// refuses it, naming `--layers-reseal`. One start with that flag seals it in place and serves
/// the same feed; starting with it again is safe; later starts leave it off.
#[test]
fn a_plaintext_state_directory_is_refused_until_one_layers_reseal() {
    let home = scratch("reseal");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    std::fs::remove_file(config_home(&home).join("config.toml")).unwrap();
    let state = home.join("layer-state");
    let key = home.join("flag.key");
    let identity = mint_key(&key);
    let (s, k) = (state.to_str().unwrap(), key.to_str().unwrap());
    let flags = ["--layers-state", s, "--layers-key", k];

    let (door, target, _) = serve(&home, &certs, &flags);
    let entry = first_line(
        ask(
            &home,
            &certs,
            "alice",
            &target,
            "sink urn:layer:talk:say",
            Some(&message("a plain hello")),
        ),
        "alice says",
    );
    let before = read_talk(&home, &certs, &target, &entry);
    drop(door);
    unseal_all(&state, &identity);
    assert!(
        !holding(&state, "a plain hello").is_empty(),
        "the state is plaintext now, as a host before 0.3.0 left it"
    );

    let (code, stderr) =
        start_or_refuse(&home, &certs, &flags).expect_err("plaintext state must not serve");
    assert_ne!(code, 0, "{stderr}");
    assert!(
        stderr.contains("plaintext") && stderr.contains("--layers-reseal"),
        "the refusal names the flag that seals it: {stderr}"
    );

    let resealing = [&flags[..], &["--layers-reseal"][..]].concat();
    for pass in ["first", "again"] {
        let (door, target, banner) = serve(&home, &certs, &resealing);
        assert!(
            banner.contains("--layers-reseal: every state file is sealed"),
            "{pass}: {banner}"
        );
        assert_eq!(read_talk(&home, &certs, &target, &entry), before, "{pass}");
        drop(door);
        assert_eq!(
            holding(&state, "a plain hello"),
            Vec::<PathBuf>::new(),
            "{pass}: nothing is left in the clear"
        );
    }
    let (door, target, banner) = serve(&home, &certs, &flags);
    assert!(!banner.contains("--layers-reseal"), "{banner}");
    assert_eq!(read_talk(&home, &certs, &target, &entry), before);
    drop(door);
    let _ = std::fs::remove_dir_all(&home);
}
