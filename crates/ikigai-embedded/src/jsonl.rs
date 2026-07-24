//! Shared helpers for the small append-only JSONL logs (the decision log and the people
//! ledger). Each record is one line — appendable without parsing the whole file, and trivial
//! to read back. The readers here are deliberately small: the records are written by the
//! endpoints in this crate, so the shapes are known and flat.

/// A JSON string literal. The values are names, emails and RFC-3339 stamps, but a quote or
/// backslash must still not break the line, since each record is exactly one line.
pub fn json_str(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Pull a string field out of one JSONL record, or `None` if it is absent.
pub fn field(line: &str, name: &str) -> Option<String> {
    let key = format!("\"{name}\":\"");
    let start = line.find(&key)? + key.len();
    let mut out = String::new();
    let mut chars = line[start..].chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                other => out.push(other),
            },
            '"' => return Some(out),
            c => out.push(c),
        }
    }
    None
}

/// The current instant, RFC-3339 to the second, UTC.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Read the log at `path`, newest line first. An absent file is empty, not an error.
pub fn read_lines(path: &std::path::Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .rev()
        .map(str::to_string)
        .collect()
}

/// Append one record line to the log at `path`, creating the parent dir and file as needed.
/// `what` names the log for error messages (e.g. `"decisions"`, `"people"`).
pub fn append(path: &std::path::Path, record: &str, what: &str) -> ikigai_core::Result<()> {
    use ikigai_core::Error;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| Error::Endpoint(format!("{what} dir: {e}")))?;
    }
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| Error::Endpoint(format!("open {}: {e}", path.display())))?;
    file.write_all(record.as_bytes())
        .map_err(|e| Error::Endpoint(format!("append: {e}")))?;
    Ok(())
}
