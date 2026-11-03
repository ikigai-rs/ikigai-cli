//! Keyed inference uses the host keystore without granting the caller raw-secret access.
#![cfg(all(feature = "embedded", unix))]

use std::path::Path;
use std::process::{Command, Output, Stdio};

fn command(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .arg("--quiet")
        .arg("--config-home")
        .arg(home.join("config"))
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .env("IKIGAI_SECRETS", home.join("secrets"))
        .env_remove("IKIGAI_LLM_CONFIG")
        .env_remove("IKIGAI_LLM_ANNOTATIONS")
        .env_remove("IKIGAI_GRANTS")
        .stdin(Stdio::null());
    command
}

fn configure(home: &Path, url: &str, secret: &str) {
    std::fs::create_dir_all(home.join("config")).unwrap();
    std::fs::create_dir_all(home.join("files")).unwrap();
    std::fs::write(
        home.join("config/llm.json"),
        format!(
            r#"{{"default":"test","providers":{{"test":{{"base_url":"{url}","model":"test-model","api_key_secret":"{secret}"}}}}}}"#
        ),
    )
    .unwrap();
}

fn diagnostic(out: &Output) -> String {
    format!(
        "status: {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_keyed_provider_reaches_the_host_reader() {
    let home = std::env::temp_dir().join(format!("iki-llm-reader-{}", std::process::id()));
    // No key is created, including on macOS: this must report an absent key, rather than
    // the plain-space mounting error, before any HTTP request can leave the process.
    let secret = format!("llm-absent-2714-{}", std::process::id());
    configure(&home, "http://127.0.0.1:1/v1", &secret);
    let out = command(&home)
        .args([
            "-c",
            "cap urn:cap:net:127.0.0.1 urn:cap:llm:use:test",
            "-c",
            "source urn:llm:test:ask prompt=hello",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{}", diagnostic(&out));
    assert!(stderr.contains(&secret), "{}", diagnostic(&out));
    assert!(stderr.contains("not found:"), "{}", diagnostic(&out));
    let _ = std::fs::remove_dir_all(home);
}

// The platform backend is a file store on Linux. A scratch HOME does not isolate macOS's
// Keychain, so the successful-key case runs on Linux CI only.
#[cfg(target_os = "linux")]
#[test]
fn net_and_provider_use_allow_inference_but_not_reading_the_key() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::time::Duration;

    let home = std::env::temp_dir().join(format!("iki-llm-key-{}", std::process::id()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    configure(&home, &format!("http://{address}/v1"), "llm-test-key");
    let stored = command(&home)
        .args([
            "-c",
            "sink urn:secret:llm-test-key content=synthetic-2714-token",
        ])
        .output()
        .unwrap();
    assert!(stored.status.success(), "{}", diagnostic(&stored));

    let (send, receive) = mpsc::channel();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut headers = String::new();
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse::<usize>().unwrap();
            }
            headers.push_str(&line);
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let response = r#"{"choices":[{"message":{"content":"keyed-answer-2714"}}]}"#;
        write!(reader.get_mut(), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
        send.send((headers, body)).unwrap();
    });

    // These are the caller's entire authority; in particular there is no secret-read scope.
    let caps = "cap urn:cap:net:127.0.0.1 urn:cap:llm:use:test";
    let out = command(&home)
        .args(["-c", caps, "-c", "source urn:llm:ask prompt=hello"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", diagnostic(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("keyed-answer-2714"),
        "{}",
        diagnostic(&out)
    );
    let (headers, body) = receive.recv_timeout(Duration::from_secs(30)).unwrap();
    assert!(
        headers.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"),
        "{headers}"
    );
    assert!(headers
        .to_ascii_lowercase()
        .contains("authorization: bearer synthetic-2714-token\r\n"));
    assert!(String::from_utf8_lossy(&body).contains("hello"));

    let denied = command(&home)
        .args(["-c", caps, "-c", "source urn:secret:llm-test-key"])
        .output()
        .unwrap();
    assert!(!denied.status.success(), "{}", diagnostic(&denied));
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("denied:"),
        "{}",
        diagnostic(&denied)
    );
    for result in [&out, &denied] {
        assert!(!diagnostic(result).contains("synthetic-2714-token"));
    }

    // A network grant, or the old raw-secret grant, cannot substitute for provider use.
    for caps in [
        "cap urn:cap:net:127.0.0.1",
        "cap urn:cap:net:127.0.0.1 urn:cap:secret:read:llm-test-key",
        "cap urn:cap:net:127.0.0.1 urn:cap:llm:use:other",
    ] {
        let denied = command(&home)
            .args(["-c", caps, "-c", "source urn:llm:test:ask prompt=hello"])
            .output()
            .unwrap();
        assert!(!denied.status.success(), "{}", diagnostic(&denied));
        assert!(
            String::from_utf8_lossy(&denied.stderr).contains("denied:"),
            "{}",
            diagnostic(&denied)
        );
        assert!(!diagnostic(&denied).contains("synthetic-2714-token"));
    }
    let _ = std::fs::remove_dir_all(home);
}
