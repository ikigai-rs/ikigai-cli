//! `ikigai layers post|save` (ledger #1629) through the REAL binary against a real layer door
//! on loopback: a scratch config home, scratch certificates, and a channel layer `work` whose
//! shapes are the Python participant client's copy of an edge layer that takes briefs, issues
//! and files (`tests/fixtures/layers/`). The poster reaches the door the way the hub does, with
//! `--override urn:layer:,urn:layers:,urn:collab:=quic://… --cert-dir …`, so what is proved is
//! the composed entry passing the door's own closed shapes and coming back byte for byte.
//!
//! ★ Every door binds port 0 and the test reads the bound port off its banner (field guide 9h,
//! ledger #1223). HERMETIC BY THE CHILD'S ENVIRONMENT, as `layers_serve.rs` is: `HOME`,
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
const IK: &str = "https://ikigai-rs.dev/ns#";

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
    let dir = std::env::temp_dir().join(format!("iki-lp-{}-{case}", std::process::id()));
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

/// The server pair and one client, `alice`, enrolled in a collaboration that mounts `work`
/// with read, feed and say: the enrollment `ikigai-layers grants <config home>` writes.
fn configure(home: &Path) -> PathBuf {
    let certs = home.join("certs");
    let d = certs.to_str().unwrap();
    ok(
        run(home, &["cert", "generate", "--dir", d]),
        "cert generate",
    );
    ok(
        run(home, &["cert", "add-client", "alice", "--cert-dir", d]),
        "cert add-client",
    );
    let config = config_home(home);
    write(
        config.join("layers/work.shapes.ttl"),
        include_str!("fixtures/layers/work.shapes.ttl"),
    );
    write(
        config.join("layers/work.context.jsonld"),
        include_str!("fixtures/layers/work.context.jsonld"),
    );
    write(
        config.join("layers/work.toml"),
        "model = \"channel\"\nshapes = \"work.shapes.ttl\"\ncontext = \"work.context.jsonld\"\n\
         entry_max = \"512KiB\"\n",
    );
    write(
        config.join("participants.ttl"),
        &format!("@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n<{ALICE}> a foaf:Person .\n"),
    );
    write(
        config.join("collabs/pair.toml"),
        "[[mount]]\nlayer = \"work\"\nalice = [\"read\", \"feed\", \"say\"]\n",
    );
    let pem = std::fs::read_to_string(certs.join("clients/alice.crt")).unwrap();
    let fingerprint = ikigai_quic::fingerprint_of_pem(&pem).expect("a certificate");
    write(
        config.join("enrollment.toml"),
        &format!("alice = \"{fingerprint}\"\n"),
    );
    let loaded = ikigai_layers::Config::load(&config).expect("the configuration checks");
    let fingerprints: BTreeMap<String, BTreeSet<String>> =
        ikigai_layers::grants::load_fingerprints(&config, &loaded).expect("enrollment.toml");
    ikigai_layers::grants::generate(&loaded, &fingerprints)
        .expect("an enrollment")
        .write(&config)
        .expect("grants.json and clients.json");
    certs
}

/// Start the door; returns it and the address its banner names (the BOUND port).
fn serve(home: &Path, certs: &Path) -> (Door, String) {
    let state = home.join("layer-state");
    let key = home.join("state.key");
    mint_key(&key);
    let args = [
        "serve",
        "quic://127.0.0.1:0",
        "--name",
        "layers",
        "--cert-dir",
        certs.to_str().unwrap(),
        "--layers-state",
        state.to_str().unwrap(),
        "--layers-key",
        key.to_str().unwrap(),
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
        .unwrap_or_else(|e| panic!("the door never printed its banner: {e}"));
    let target = seen
        .lines()
        .find_map(|line| line.split("serving on ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no address in the banner:\n{seen}"))
        .to_string();
    (door, target)
}

/// Run `ikigai <alice's route to the door> <args>` in `cwd`, with `stdin` when given.
fn as_alice(
    home: &Path,
    certs: &Path,
    target: &str,
    cwd: &Path,
    args: &[&str],
    stdin: Option<&str>,
) -> Output {
    let dir = certs.to_str().unwrap();
    let cert = format!("{dir}/clients/alice.crt");
    let key = format!("{dir}/clients/alice.key");
    let route = format!("urn:layer:,urn:layers:,urn:collab:={target}");
    let mut full = vec![
        "--cert-dir",
        dir,
        "--client-cert",
        &cert,
        "--client-key",
        &key,
        "--override",
        &route,
    ];
    full.extend_from_slice(args);
    let mut child = spawn(home, &full)
        .current_dir(cwd)
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

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

/// An entry IRI a post printed: its one line.
fn posted(out: Output, what: &str) -> String {
    let iri = ok(out, what).trim().to_string();
    assert!(
        iri.starts_with("urn:layer:work:entry:") && !iri.contains('\n'),
        "{what} printed the entry's IRI alone: {iri:?}"
    );
    iri
}

/// A brief (its title from its first heading, its repository from `owner/name`), an issue
/// (its body on stdin) and two files (text with quotes and newlines, and every byte value)
/// each pass the door's closed shapes; the door holds what was composed; reading ONE kind
/// already works through `entries type=`; and each file saves back byte for byte, refusing to
/// replace a file without `--force` and to save an entry that is not a file.
#[test]
fn briefs_issues_and_files_post_and_a_file_saves_back_byte_for_byte() {
    let home = scratch("post");
    let certs = configure(&home);
    let (_door, target) = serve(&home, &certs);
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let alice =
        |args: &[&str], stdin: Option<&str>| as_alice(&home, &certs, &target, &work, args, stdin);
    let read = |iri: &str| {
        ok(
            alice(&["-c", &format!("source {iri}")], None),
            "read an entry",
        )
    };

    // A brief from a file: the title is its first `# ` heading, and quotes, backslashes and
    // newlines in the body survive the Turtle.
    let body = "# Add a \"door\" check\n\n## Why\nA path like C:\\x\tmatters.\n";
    std::fs::write(work.join("brief.md"), body).unwrap();
    let brief = posted(
        alice(
            &[
                "layers",
                "post",
                "brief",
                "work",
                "brief.md",
                "--repo",
                "ikigai-rs/ikigai-core",
            ],
            None,
        ),
        "post brief",
    );
    let stored = read(&brief);
    assert!(stored.contains("ik:Brief"), "{stored}");
    assert!(
        stored.contains(r#"dcterms:title "Add a \"door\" check""#),
        "{stored}"
    );
    assert!(
        stored.contains("<https://github.com/ikigai-rs/ikigai-core>"),
        "{stored}"
    );
    assert!(
        stored.contains(&format!("prov:wasAttributedTo <{ALICE}>")),
        "stamped: {stored}"
    );

    // An issue from stdin, answering the brief; the trailing newline a pipe adds is dropped.
    let issue = posted(
        alice(
            &[
                "layers",
                "post",
                "issue",
                "work",
                "--title",
                "Crash on start",
                "--severity",
                "major",
                "--in-reply-to",
                &brief,
            ],
            Some("It crashes.\n"),
        ),
        "post issue",
    );
    let stored = read(&issue);
    assert!(stored.contains("<urn:iki:severity:major>"), "{stored}");
    assert!(
        stored.contains(&format!("<{brief}>")),
        "in reply to the brief: {stored}"
    );
    assert!(stored.contains("\"It crashes.\""), "{stored}");

    // Reading one kind needs nothing new: the door filters `entries` by class.
    let issues = ok(
        alice(
            &[
                "-c",
                &format!("source urn:layer:work:entries type={IK}Issue"),
            ],
            None,
        ),
        "entries of one kind",
    );
    assert!(
        // (The brief's IRI is there as the issue's ik:inReplyTo; the brief itself is not.)
        issues.contains(&format!("<{issue}> a ik:Issue")) && !issues.contains("ik:Brief"),
        "{issues}"
    );

    // Two files: text travels as text, the rest as base64; both save back exactly.
    let text = "line \"one\"\r\nline\ttwo\n".as_bytes().to_vec();
    let binary: Vec<u8> = (0u8..=255).collect();
    std::fs::write(work.join("trace.log"), &text).unwrap();
    std::fs::write(work.join("blob.bin"), &binary).unwrap();
    let text_entry = posted(
        alice(&["layers", "post", "file", "work", "trace.log"], None),
        "post a text file",
    );
    let binary_entry = posted(
        alice(
            &[
                "layers",
                "post",
                "file",
                "work",
                "blob.bin",
                "--file-name",
                "every-byte.bin",
            ],
            None,
        ),
        "post a binary file",
    );
    assert!(read(&text_entry).contains("ik:encoding \"text\""));
    let stored = read(&binary_entry);
    assert!(stored.contains("ik:encoding \"base64\""), "{stored}");
    assert!(stored.contains("\"application/octet-stream\""), "{stored}");

    let saved = home.join("saved");
    std::fs::create_dir_all(&saved).unwrap();
    let saved_arg = saved.to_str().unwrap();
    for (entry, name, bytes) in [
        (&text_entry, "trace.log", &text),
        (&binary_entry, "every-byte.bin", &binary),
    ] {
        let said = ok(alice(&["layers", "save", entry, saved_arg], None), "save");
        assert!(
            said.starts_with("saved ") && said.contains("sha256:"),
            "{said}"
        );
        assert_eq!(&std::fs::read(saved.join(name)).unwrap(), bytes, "{name}");
    }
    // With no PATH it lands in the downloads directory, never the working directory (often a
    // repository an agent works in), and with no downloads directory it asks for a PATH.
    std::fs::remove_file(work.join("trace.log")).unwrap();
    let nowhere = alice(&["layers", "save", &text_entry], None);
    assert_eq!(nowhere.status.code(), Some(2), "{}", stderr(&nowhere));
    assert!(
        stderr(&nowhere).contains("no downloads directory found")
            && stderr(&nowhere).contains("give a PATH"),
        "{}",
        stderr(&nowhere)
    );
    let downloads = home.join("Downloads");
    std::fs::create_dir_all(&downloads).unwrap();
    ok(
        alice(&["layers", "save", &text_entry], None),
        "save to Downloads",
    );
    assert_eq!(std::fs::read(downloads.join("trace.log")).unwrap(), text);
    assert!(
        !work.join("trace.log").exists(),
        "nothing in the working directory"
    );

    // An existing file is not replaced without --force.
    let again = alice(&["layers", "save", &text_entry, saved_arg], None);
    assert_eq!(again.status.code(), Some(2), "{}", stderr(&again));
    assert!(stderr(&again).contains("--force"), "{}", stderr(&again));
    ok(
        alice(&["layers", "save", &text_entry, saved_arg, "--force"], None),
        "save --force",
    );

    // A brief is not a file.
    let not_a_file = alice(&["layers", "save", &brief, saved_arg], None);
    assert_eq!(not_a_file.status.code(), Some(2), "{}", stderr(&not_a_file));
    assert!(
        stderr(&not_a_file).contains("is a Brief, not a file"),
        "{}",
        stderr(&not_a_file)
    );
}

/// What the door cannot check, `save` does: a file entry whose content does not hash to its
/// own digest passes the shapes, and is NOT saved (exit 1, nothing written). And what the door
/// would refuse anyway is refused here first: a file over the layer's content bound (exit 2,
/// naming how large a file the layer takes), and a bad layer name before anything is dialed.
#[test]
fn a_file_that_lies_about_its_digest_is_not_saved_and_an_oversized_one_is_not_sent() {
    let home = scratch("refuse");
    let certs = configure(&home);
    let (_door, target) = serve(&home, &certs);
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let alice =
        |args: &[&str], stdin: Option<&str>| as_alice(&home, &certs, &target, &work, args, stdin);

    // Posted by hand: well formed, a valid-looking digest, and the wrong one.
    let wrong = format!("sha256:{}", "0".repeat(64));
    let lying = format!(
        "@prefix ik: <{IK}> .\n<urn:layer:new> a ik:File ; ik:fileName \"lie.txt\" ; \
         ik:mediaType \"text/plain\" ; ik:contentHash \"{wrong}\" ; ik:byteSize 6 ; \
         ik:encoding \"text\" ; ik:content \"hello\\n\" .\n"
    );
    let entry = ok(
        alice(&["-c", "sink urn:layer:work:say"], Some(&lying)),
        "the door admits a well-formed file entry",
    )
    .trim()
    .to_string();
    let out = alice(&["layers", "save", &entry, work.to_str().unwrap()], None);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("not saved") && stderr(&out).contains("hashes to"),
        "{}",
        stderr(&out)
    );
    assert!(!work.join("lie.txt").exists(), "nothing was written");

    // One byte over the shapes' bound on ik:content (520192), refused before it is sent.
    std::fs::write(work.join("big.txt"), "a".repeat(520_193)).unwrap();
    let out = alice(&["layers", "post", "file", "work", "big.txt"], None);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("this layer takes at most 520192 bytes"),
        "{}",
        stderr(&out)
    );
    let feed = ok(
        alice(&["-c", "source urn:layer:work:feed after=0"], None),
        "the feed",
    );
    assert_eq!(
        feed.matches(" say ").count(),
        1,
        "only the hand-posted entry: {feed}"
    );

    // A bad layer name is refused before anything is dialed: no door is named at all.
    let out = run(
        &home,
        &["layers", "post", "brief", "Work", "--title", "t", "-"],
    );
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("is not a layer name"),
        "{}",
        stderr(&out)
    );
}

/// A file entry's name is the poster's choice, and the door's shapes admit a leading dot, so
/// `save` refuses every name that would arm something on the reader's machine (ledger #1748):
/// an agent's or a shell's configuration, a Windows device, drive or alternate data stream. It
/// writes nothing, exits 1, and says how to save it anyway: `--as NAME`. And `post file`
/// refuses to send a file a reader could not save, pointing at `--file-name`.
#[test]
fn a_file_named_as_configuration_is_not_saved_unless_renamed() {
    let home = scratch("names");
    let certs = configure(&home);
    let (_door, target) = serve(&home, &certs);
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let alice =
        |args: &[&str], stdin: Option<&str>| as_alice(&home, &certs, &target, &work, args, stdin);
    let saved = home.join("saved");
    std::fs::create_dir_all(&saved).unwrap();
    let saved_arg = saved.to_str().unwrap();

    // Posted by hand, as another client could: the shapes take each of these names.
    let digest = "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
    let posted_as = |name: &str| {
        let turtle = format!(
            "@prefix ik: <{IK}> .\n<urn:layer:new> a ik:File ; ik:fileName \"{name}\" ; \
             ik:mediaType \"text/plain\" ; ik:contentHash \"{digest}\" ; ik:byteSize 6 ; \
             ik:encoding \"text\" ; ik:content \"hello\\n\" .\n"
        );
        ok(
            alice(&["-c", "sink urn:layer:work:say"], Some(&turtle)),
            "the door admits the entry",
        )
        .trim()
        .to_string()
    };
    for name in [
        ".mcp.json",
        "CLAUDE.md",
        ".envrc",
        "AGENTS.md",
        "CON",
        "a.txt:ads",
    ] {
        let entry = posted_as(name);
        let out = alice(&["layers", "save", &entry, saved_arg], None);
        assert_eq!(out.status.code(), Some(1), "{name}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("not saved") && stderr(&out).contains("--as NAME"),
            "{name}: {}",
            stderr(&out)
        );
        assert_eq!(
            std::fs::read_dir(&saved).unwrap().count(),
            0,
            "{name}: nothing was written"
        );
    }

    // --as saves it under a name the reader chose, and a PATH naming the file does too.
    let mcp = posted_as(".mcp.json");
    ok(
        alice(
            &["layers", "save", &mcp, saved_arg, "--as", "mcp.json"],
            None,
        ),
        "save --as",
    );
    assert_eq!(std::fs::read(saved.join("mcp.json")).unwrap(), b"hello\n");
    assert!(!saved.join(".mcp.json").exists());
    let envrc = posted_as(".envrc");
    let named = saved.join("envrc.txt");
    ok(
        alice(&["layers", "save", &envrc, named.to_str().unwrap()], None),
        "save to a named file",
    );
    assert_eq!(std::fs::read(&named).unwrap(), b"hello\n");

    // --as and a PATH's own name are held to the same rules, before anything is dialed: these
    // run with no route to any door.
    let out = run(
        &home,
        &["layers", "save", &mcp, saved_arg, "--as", ".envrc"],
    );
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("choose another --as NAME"),
        "{}",
        stderr(&out)
    );
    let claude = saved.join("CLAUDE.md");
    let out = run(&home, &["layers", "save", &mcp, claude.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("give PATH another name"),
        "{}",
        stderr(&out)
    );
    assert!(!claude.exists());

    // A file a reader could not save is not posted, and the refusal names the way out.
    std::fs::write(work.join(".gitignore"), "target/\n").unwrap();
    let out = alice(&["layers", "post", "file", "work", ".gitignore"], None);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("loads as configuration")
            && stderr(&out).contains("--file-name NAME"),
        "{}",
        stderr(&out)
    );
    posted(
        alice(
            &[
                "layers",
                "post",
                "file",
                "work",
                ".gitignore",
                "--file-name",
                "gitignore.txt",
            ],
            None,
        ),
        "post under another name",
    );
}
