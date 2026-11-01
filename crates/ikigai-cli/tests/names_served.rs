//! Names in a served surface, through the REAL binary (named requests C2, ledger #2516): `serve
//! --http … --names <file>` places the names layer LAST in the HTTP door's root, so a route
//! target such as `urn:quakes:page` resolves in that one process, with no second process and no
//! mount. Without the option the door serves no names, even with a `names` file in its config
//! home.
//!
//! The served layer is the bindings alone: the names atom and the status door are not on the
//! door's surface, a binding's fixed input cannot be given by the caller, and the forward runs
//! under the request's capability (the door's `--cap` ceiling grants the file reads here).
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `html_door_pages.rs` is: `HOME`, `XDG_CONFIG_HOME`
//! and `IKIGAI_FILES` are set on the spawned process only, and the door binds port 0 and names
//! its port on its banner.
#![cfg(all(feature = "embedded", feature = "web", unix))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long a door gets to print its banner or exit. A watchdog, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

/// How long an edit to the names file may take to rebind (a watch on its directory).
const REBOUND_WITHIN: Duration = Duration::from_secs(20);

/// The named request: compose a page template, fixed by reference.
const PAGE: &str = "urn:quakes:page = source urn:iki:fn:compose src=<urn:file:page.html>\n";

/// What `/quakes` answers: the template with the list spliced in.
const COMPOSED: &str = "<h1>Quakes</h1>\n<ul><li>north 4.5</li></ul>\n\n";

/// A child process that is killed when the test ends, whatever the test does.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch home: a config home holding `names`, and an owner-only workspace holding the page
/// template, the list it splices, and a route file mapping `/quakes` to `urn:quakes:page`.
fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-ns-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(config(&dir)).expect("scratch config home");
    std::fs::write(config(&dir).join("config.toml"), "").expect("scratch config.toml");
    std::fs::write(config(&dir).join("names"), PAGE).expect("a names file");
    let files = dir.join("files");
    std::fs::create_dir_all(&files).expect("scratch workspace");
    std::fs::set_permissions(&files, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .expect("an owner-only workspace");
    std::fs::write(
        files.join("page.html"),
        "<h1>Quakes</h1>\n$a{urn:file:list.html}\n",
    )
    .expect("the template");
    std::fs::write(files.join("list.html"), "<ul><li>north 4.5</li></ul>\n").expect("the list");
    std::fs::write(files.join("other.html"), "<p>other</p>\n").expect("another page");
    let routes = serde_json::json!({ "routes": [
        {"id": "quakes", "match": "/quakes", "target": "urn:quakes:page"},
    ]});
    std::fs::write(files.join("routes.json"), routes.to_string()).expect("the route file");
    dir
}

fn config(home: &Path) -> PathBuf {
    home.join("config").join("ikigai")
}

fn ikigai(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"));
    command
}

/// The door's arguments: `serve --http 0` over the route file, the workspace readable under
/// the door's ceiling, then `extra`.
fn door_args(home: &Path, extra: &[&str]) -> Vec<String> {
    let read = format!("urn:cap:fs:read:{}", home.join("files").display());
    let mut args: Vec<String> = [
        "serve",
        "--http",
        "0",
        "--routes",
        "urn:file:routes.json",
        "--cap",
        &read,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend(extra.iter().map(|s| s.to_string()));
    args
}

/// Start the door; `(door, banner)` once it is serving.
fn start(home: &Path, extra: &[&str]) -> (Door, String) {
    let args = door_args(home, extra);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut child = ikigai(home, &args)
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
        // stderr reached EOF: the process is exiting. `wait`, never `try_wait`.
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

/// `GET path` over plain HTTP/1.1: (status line, body).
fn get(port: u16, path: &str) -> (String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("nothing accepted on {port}: {e}"));
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .expect("the request is written");
    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .expect("the response is read");
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    (
        head.lines().next().unwrap_or_default().to_string(),
        body.to_string(),
    )
}

/// The item's test: `curl /quakes` answers the composed page from the names file.
#[test]
fn the_route_answers_the_composed_page_from_a_names_file() {
    let home = scratch("page");
    let names = config(&home).join("names");
    let (_door, banner) = start(&home, &["--names", names.to_str().expect("a UTF-8 path")]);
    assert!(banner.contains("names from "), "{banner}");
    let (status, body) = get(bound_port(&banner), "/quakes");
    assert!(status.contains(" 200 "), "{status}\n{body}");
    assert_eq!(body, COMPOSED);
}

/// Without the option the name is not served, though the config home holds a `names` file
/// binding it: a served door reads no names it was not told to.
#[test]
fn without_the_option_the_name_is_not_served() {
    let home = scratch("without");
    let (_door, banner) = start(&home, &[]);
    assert!(!banner.contains("names from "), "{banner}");
    let (status, body) = get(bound_port(&banner), "/quakes");
    assert!(status.contains(" 404 "), "{status}\n{body}");
    assert!(body.contains("urn:quakes:page"), "{body}");
}

/// The served layer is the bindings alone: the names atom and the status door are not on the
/// surface (a caller can neither read nor write the file, nor learn where it lives), and a
/// fixed input cannot be given by the caller.
#[test]
fn the_door_serves_the_bindings_alone() {
    let home = scratch("alone");
    let (_door, banner) = start(&home, &["--names", "config/ikigai/names"]);
    let port = bound_port(&banner);
    for path in ["/iki/host/names", "/iki/space/dynamic/names/status"] {
        let (status, body) = get(port, path);
        assert!(status.contains(" 404 "), "{path}: {status}\n{body}");
        assert!(!body.contains("config/ikigai"), "{path}: {body}");
    }
    let (status, body) = get(port, "/quakes?src=urn:file:other.html");
    assert!(!status.contains(" 200 "), "{status}\n{body}");
    assert!(
        body.contains("fixed by <urn:quakes:page>"),
        "{status}\n{body}"
    );
}

/// An edit to the names file rebinds on the running door, no restart.
#[test]
// A native test of a native binary: the deadline is the test's own wall clock.
#[allow(clippy::disallowed_methods)]
fn an_edit_to_the_names_file_rebinds() {
    let home = scratch("edit");
    let names = config(&home).join("names");
    let (_door, banner) = start(&home, &["--names", names.to_str().expect("a UTF-8 path")]);
    let port = bound_port(&banner);
    assert_eq!(get(port, "/quakes").1, COMPOSED);
    std::fs::write(
        &names,
        "urn:quakes:page = source urn:iki:fn:compose src=<urn:file:other.html>\n",
    )
    .expect("the edit");
    let deadline = Instant::now() + REBOUND_WITHIN;
    loop {
        let (_, body) = get(port, "/quakes");
        if body == "<p>other</p>\n" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "not rebound in {REBOUND_WITHIN:?}: {body}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// `--names` on `serve` is the HTTP door's: a socket door refuses it rather than ignoring it.
#[test]
fn another_door_refuses_the_option() {
    let home = scratch("refused");
    let socket = home.join("s.sock");
    let out = ikigai(
        &home,
        &[
            "serve",
            socket.to_str().expect("a UTF-8 path"),
            "--names",
            "config/ikigai/names",
        ],
    )
    .stdin(Stdio::null())
    .output()
    .expect("the binary under test runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("--names") && stderr.contains("is not the HTTP door"),
        "{stderr}"
    );
}

/// A reader supplies only named content; the shared shell supplies the landmarks and assets.
#[test]
fn a_named_page_composes_the_shared_ui_shell() {
    let home = scratch("ui-shell");
    std::fs::write(config(&home).join("names"), concat!(
        "urn:quakes:page = source urn:iki:fn:compose src=<urn:iki:ui:template:shell> family=quakes name=home theme=auto\n",
        "urn:iki:ui:title:quakes:home = source urn:file:title.txt\n",
        "urn:iki:ui:header:quakes = source urn:file:header.html\n",
        "urn:iki:ui:head:quakes = source urn:file:head.html\n",
        "urn:iki:ui:main:quakes:home = source urn:file:page.html\n",
    )).unwrap();
    std::fs::write(home.join("files/title.txt"), "Quakes & more").unwrap();
    std::fs::write(
        home.join("files/header.html"),
        "<nav aria-label=\"Site\"><a href=\"/quakes\">Quakes</a></nav>",
    )
    .unwrap();
    std::fs::write(home.join("files/head.html"), "").unwrap();
    std::fs::write(
        home.join("files/page.html"),
        "<h1>Quakes</h1><p>North: 4.5</p>",
    )
    .unwrap();
    let routes = serde_json::json!({"routes": [
        {"match": "/quakes", "target": "urn:quakes:page"},
        {"match": "/ui/{name}", "target": "urn:iki:ui:{name}"}
    ]});
    std::fs::write(home.join("files/routes.json"), routes.to_string()).unwrap();
    let (_door, banner) = start(&home, &["--names", "config/ikigai/names", "--routes-only"]);
    let port = bound_port(&banner);
    let (status, page) = get(port, "/quakes");
    assert!(status.contains(" 200 "), "{status}\n{page}");
    for expected in [
        "<html lang=\"en\"",
        "<title>Quakes &amp; more</title>",
        "Skip to content",
        "role=\"status\" aria-live=\"polite\"",
        "<main id=\"main\"",
        "<h1>Quakes</h1>",
        "integrity=\"sha384-HGfztofotfshcF7+8n44JQL2oJmowVChPTg48S+jvZoztPfvwD79OC/LTtG6dMp+\"",
    ] {
        assert!(page.contains(expected), "missing {expected}: {page}");
    }
    let mut assets = Vec::new();
    for asset in ["tokens.css", "shell.js", "htmx"] {
        let (status, bytes) = get(port, &format!("/ui/{asset}"));
        assert!(status.contains(" 200 "), "{asset}: {status}\n{bytes}");
        assert!(!bytes.is_empty());
        if asset == "htmx" {
            use base64::Engine;
            use sha2::Digest;
            let sri = format!(
                "sha384-{}",
                base64::engine::general_purpose::STANDARD
                    .encode(sha2::Sha384::digest(bytes.as_bytes()))
            );
            assert_eq!(
                sri,
                ikigai_ui::HTMX_INTEGRITY,
                "the served bytes match the shell's SRI"
            );
        }
        assets.push((format!("ui/{asset}"), bytes));
    }
    if let Some(dir) = std::env::var_os("IKIGAI_UI_AXE_SITE") {
        let mut files = vec![("quakes.html", "text/html", page.as_bytes())];
        for (path, bytes) in &assets {
            let kind = if path.ends_with(".css") {
                "text/css"
            } else {
                "text/javascript"
            };
            files.push((path.as_str(), kind, bytes.as_bytes()));
        }
        ikigai_ui::testkit::site::write(std::path::Path::new(&dir), &files).unwrap();
    }
}
