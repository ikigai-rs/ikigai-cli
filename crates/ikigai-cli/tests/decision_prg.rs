//! The emailed decision pages answer their POST with Post/Redirect/Get, through the REAL
//! binary (ledger #1879). A decision POST (`/calendar-request/{action}`, `/contact-block`,
//! `/contact-label`) answers `303 See Other` to `?outcome=<word>` on its own path, so a phone
//! that restores the tab restores a GET and never asks to post again; that GET renders the
//! outcome under the same CSP, `nosniff` and `no-store` as the form; the Location carries no
//! address, token or enquiry; and the same link POSTed twice records its intent once.
//!
//! The routes are the edge's for these pages (`edge-routes.json`), each with the HTML door's
//! CSP. The links are signed here with test keys whose public halves sit in the workspace, as
//! the Mac (decide) and the edge (block, label) mint them.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `html_door_pages.rs` is: `HOME`, `XDG_CONFIG_HOME`
//! and `IKIGAI_FILES` are set on the spawned process only, and the door binds port 0 and names
//! its port on its banner (field guide 9h).
#![cfg(all(feature = "embedded", feature = "web", unix))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use ikigai_web::HTML_DOOR_CSP;

/// How long a door gets to print its banner or exit. A watchdog, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

/// A booking id and a sender, in the shapes the links carry.
const BOOKING: &str = "abcdefgh12";
const SENDER: &str = "mallory@example.org";

/// A child process that is killed when the test ends, whatever the test does.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The signing keys the test mints links with: decide's (the Mac's) and the edge's block key.
struct Keys {
    decide: ed25519_dalek::SigningKey,
    block: ed25519_dalek::SigningKey,
}

/// A scratch home: an empty config home, and an owner-only workspace holding the edge's routes
/// for the decision pages and the public halves of both keys.
fn scratch(case: &str) -> (PathBuf, Keys) {
    let dir = std::env::temp_dir().join(format!("iki-prg-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let home = dir.join("config").join("ikigai");
    std::fs::create_dir_all(&home).expect("scratch config home");
    std::fs::write(home.join("config.toml"), "").expect("scratch config.toml");
    let files = dir.join("files");
    std::fs::create_dir_all(&files).expect("scratch workspace");
    std::fs::set_permissions(&files, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .expect("an owner-only workspace");
    let route = |id: &str, path: &str, target: &str| serde_json::json!({"id": id, "match": path, "target": target, "csp": HTML_DOOR_CSP});
    let routes = serde_json::json!({ "routes": [
        route("calendar-request", "/calendar-request/{action}", "urn:calendar-request:{action}"),
        route("contact-block", "/contact-block", "urn:contact-block"),
        route("contact-label", "/contact-label", "urn:contact-label"),
        route("decide-css", "/decide/css", "urn:decide:css"),
    ]});
    std::fs::write(files.join("routes.json"), routes.to_string()).expect("the route file");
    let keys = Keys {
        decide: ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
        block: ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]),
    };
    write_public_key(&files.join("decide.pub"), &keys.decide);
    write_public_key(&files.join("contact-block.pub"), &keys.block);
    (dir, keys)
}

fn write_public_key(path: &Path, key: &ed25519_dalek::SigningKey) {
    use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePublicKey};
    let pem = key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("an SPKI PEM");
    std::fs::write(path, pem).expect("the public key");
}

/// Sign `payload` with `key`, as a link is minted.
fn signed(key: &ed25519_dalek::SigningKey, payload: &str) -> String {
    use base64::Engine;
    use ed25519_dalek::Signer;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.sign(payload.as_bytes()).to_bytes())
}

/// One decision form: the path it posts to, the urlencoded body a browser sends, the outcome
/// word its POST redirects with, a phrase the outcome page shows, and the space it drops into.
struct Form {
    path: String,
    body: String,
    word: &'static str,
    shows: &'static str,
    space: &'static str,
    /// Values that must never reach a Location: the token, and any address or enquiry id.
    private: Vec<String>,
}

/// The three decision forms, each with a freshly signed link.
fn forms(keys: &Keys) -> Vec<Form> {
    let exp = 99_999_999_999_i64;
    let enquiry = "a".repeat(64);
    let decide = signed(&keys.decide, &format!("{BOOKING}|decline|{exp}"));
    let block = signed(&keys.block, &format!("contact-block|{SENDER}||{exp}"));
    let label = signed(&keys.block, &format!("contact-label|spam|{enquiry}||{exp}"));
    vec![
        Form {
            path: "/calendar-request/decline".to_string(),
            body: format!("id={BOOKING}&exp={exp}&t={decide}"),
            word: "recorded",
            shows: "Declined",
            space: "decisions",
            private: vec![decide, BOOKING.to_string()],
        },
        Form {
            path: "/contact-block".to_string(),
            body: format!("email=mallory%40example.org&id=&exp={exp}&t={block}"),
            word: "blocked",
            shows: "Enquiries from that sender will be dropped",
            space: "contact-blocks",
            private: vec![block, SENDER.to_string(), "mallory".to_string()],
        },
        Form {
            path: "/contact-label".to_string(),
            body: format!("label=spam&id={enquiry}&exp={exp}&t={label}"),
            word: "spam",
            shows: "Marked as spam",
            space: "contact-blocks",
            private: vec![label, enquiry[..12].to_string()],
        },
    ]
}

/// Start `serve --http 0` on the edge's decision routes; `(door, banner)` once it is serving.
fn start(home: &Path) -> (Door, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args([
            "serve",
            "--http",
            "0",
            "--routes",
            "urn:file:routes.json",
            "--routes-only",
            "--cap",
            "urn:cap:space:out",
        ])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary under test starts");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut seen = String::new();
        let mut served = false;
        let mut lines = BufReader::new(stderr).lines().map_while(Result::ok);
        for line in lines.by_ref() {
            seen.push_str(&line);
            seen.push('\n');
            if line.contains("serving HTTP on") {
                served = true;
                break;
            }
        }
        let _ = tx.send((served, seen));
        lines.for_each(drop);
    });
    let (served, seen) = rx
        .recv_timeout(PATIENCE)
        .unwrap_or_else(|e| panic!("the door neither served nor exited: {e}"));
    if !served {
        // stderr reached EOF: the process is exiting. `wait`, never `try_wait` (field guide 9h).
        let status = child.wait().expect("the door's exit status");
        panic!("the door exited ({status}): {seen}");
    }
    (Door(child), seen)
}

/// The port the door bound, off its banner (`serving HTTP on 127.0.0.1:<port>`).
fn bound_port(banner: &str) -> u16 {
    banner
        .lines()
        .find_map(|line| line.split("serving HTTP on ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|addr| addr.parse::<std::net::SocketAddr>().ok())
        .map(|addr| addr.port())
        .unwrap_or_else(|| panic!("no bound address on the banner: {banner}"))
}

/// One request: the status line, the header lines, and the body.
fn exchange(port: u16, request: &str) -> (String, Vec<String>, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("nothing accepted on {port}: {e}"));
    stream
        .write_all(request.as_bytes())
        .expect("the request is written");
    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .expect("the response is read");
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no header end: {raw}"));
    let mut lines = head.split("\r\n").map(str::to_string);
    let status = lines.next().unwrap_or_default();
    (status, lines.collect(), body.to_string())
}

fn get(port: u16, path: &str) -> (String, Vec<String>, String) {
    exchange(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"),
    )
}

/// POST `body` as a browser submits a form.
fn post(port: u16, path: &str, body: &str) -> (String, Vec<String>, String) {
    exchange(
        port,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
             Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
}

/// The value of header `name` (case-insensitive), if sent.
fn header<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// The tuples dropped into the space `name`, in whatever state they sit.
fn tuples_in(home: &Path, name: &str) -> usize {
    fn walk(dir: &Path) -> usize {
        std::fs::read_dir(dir).map_or(0, |entries| {
            entries
                .map_while(Result::ok)
                .map(|e| {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p)
                    } else {
                        usize::from(p.extension().is_some_and(|x| x == "tuple"))
                    }
                })
                .sum()
        })
    }
    walk(&home.join("files").join("spaces").join(name))
}

/// Settle every pending tuple in the space `name` as its reactor would: inbox to outbox. A
/// tuplespace drop is content-addressed, so the same bytes dropped while still PENDING are one
/// tuple anyway; once settled, the same bytes are a new request. Settling first is what makes a
/// replay observable here.
fn settle(home: &Path, name: &str) {
    let space = home.join("files").join("spaces").join(name);
    let outbox = space.join("outbox");
    std::fs::create_dir_all(&outbox).expect("an outbox");
    for entry in std::fs::read_dir(space.join("inbox")).expect("an inbox") {
        let from = entry.expect("an inbox entry").path();
        let to = outbox.join(from.file_name().expect("a tuple file name"));
        std::fs::rename(&from, &to).expect("settled");
    }
}

#[test]
fn every_decision_post_answers_303_to_an_outcome_page_that_names_no_one() {
    let (home, keys) = scratch("redirect");
    let (_door, banner) = start(&home);
    let port = bound_port(&banner);
    for form in forms(&keys) {
        let (status, headers, _) = post(port, &form.path, &form.body);
        assert_eq!(
            status, "HTTP/1.1 303 See Other",
            "{}: {headers:?}",
            form.path
        );
        let location = header(&headers, "location")
            .unwrap_or_else(|| panic!("{}: a Location: {headers:?}", form.path));
        assert_eq!(location, format!("?outcome={}", form.word), "{}", form.path);
        for private in &form.private {
            assert!(
                !location.contains(private.as_str()),
                "{}: `{private}` in the Location",
                form.path
            );
        }

        // The page the browser lands on: the outcome, as the form is served.
        let (form_status, form_headers, _) = get(port, &format!("{}?{}", form.path, form.body));
        assert_eq!(form_status, "HTTP/1.1 200 OK", "{}", form.path);
        let (status, headers, body) = get(port, &format!("{}{location}", form.path));
        assert_eq!(status, "HTTP/1.1 200 OK", "{}: {body}", form.path);
        assert!(body.contains(form.shows), "{}: {body}", form.path);
        for private in &form.private {
            assert!(
                !body.contains(private.as_str()),
                "{}: `{private}` on the outcome page",
                form.path
            );
        }
        for name in [
            "content-security-policy",
            "x-content-type-options",
            "cache-control",
        ] {
            assert_eq!(
                header(&headers, name),
                header(&form_headers, name),
                "{}: `{name}` as on the form",
                form.path
            );
        }
        assert_eq!(
            header(&headers, "content-security-policy"),
            Some(HTML_DOOR_CSP)
        );
        assert_eq!(header(&headers, "cache-control"), Some("no-store"));
        assert!(
            body.contains("<main>") && !body.contains("<script"),
            "{body}"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_decision_posted_twice_acts_once() {
    let (home, keys) = scratch("replay");
    let (_door, banner) = start(&home);
    let port = bound_port(&banner);
    for form in forms(&keys) {
        let before = tuples_in(&home, form.space);
        let (first, headers, _) = post(port, &form.path, &form.body);
        assert_eq!(first, "HTTP/1.1 303 See Other", "{}", form.path);
        assert_eq!(
            tuples_in(&home, form.space),
            before + 1,
            "{}: the first POST records the decision ({headers:?})",
            form.path
        );
        settle(&home, form.space);
        let (again, headers, _) = post(port, &form.path, &form.body);
        assert_eq!(again, "HTTP/1.1 303 See Other", "{}", form.path);
        assert_eq!(
            header(&headers, "location"),
            Some("?outcome=already"),
            "{}",
            form.path
        );
        assert_eq!(
            tuples_in(&home, form.space),
            before + 1,
            "{}: the second POST, after the first settled, records nothing",
            form.path
        );
        let (status, _, body) = get(port, &format!("{}?outcome=already", form.path));
        assert_eq!(status, "HTTP/1.1 200 OK", "{}", form.path);
        assert!(body.contains("Already recorded"), "{}: {body}", form.path);
    }
    let _ = std::fs::remove_dir_all(&home);
}
