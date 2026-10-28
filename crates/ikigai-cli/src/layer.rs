//! `ikigai layers post|save`: post a brief, an issue or a file to a layer, and save a posted
//! file back to disk with its size and digest checked (ledger #1629).
//!
//! **Nothing here is a new way to reach a door.** A post is the `sink urn:layer:{layer}:say`
//! a `-c` batch sends, with the entry composed here instead of by hand, and a save is a
//! `source` of the entry. Both run on the engine the REPL and `-c` build, so the door is
//! reached however this process routes `urn:layer:` (an `--override`, a `--connect`, a config
//! home `mount` line):
//!
//! ```text
//! ikigai --override urn:layer:,urn:layers:,urn:collab:=quic://door:4434 --cert-dir D \
//!        layers post file talk ./trace.log
//! ```
//!
//! What it saves the caller is the composition: a Turtle literal escaped for every character
//! it may not hold raw, a file's SHA-256 and size, text or base64, and on the way back the
//! check the door cannot make (a door validates an entry's SHAPE, never that its digest is
//! true of its content).
//!
//! The behavior and the names follow the Python participant client (`ikigai-layers post
//! brief|issue|file`, `ikigai-layers save`, in ikigai-rs/ikigai-layers-client), so a
//! collaborator moving between the two finds the same commands, flags and refusals. Reading
//! needs nothing new: `source urn:layer:{layer}:entries type=<class IRI>` already reads one
//! kind at the door.
//!
//! The entry kinds and their properties are the layer's closed shapes (the edge's
//! `talk.shapes.ttl`): `ik:Brief` (`dcterms:title`, `ik:body`, `ik:repository`), `ik:Issue`
//! (the same and `ik:severity`), and `ik:File` (`ik:fileName`, `ik:mediaType`,
//! `ik:contentHash`, `ik:byteSize`, `ik:encoding`, `ik:content`), each optionally
//! `ik:inReplyTo` or `ik:supersedes` an entry. The host stamps who, when and the sequence.

use crate::output::println;

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use icu_properties::props::GeneralCategory;
use ikigai_engine::{Action, Engine};
use sha2::{Digest, Sha256};

const IK: &str = "https://ikigai-rs.dev/ns#";
const DCTERMS: &str = "http://purl.org/dc/terms/";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const SH: &str = "http://www.w3.org/ns/shacl#";

/// The severities an issue may name, as `urn:iki:severity:{name}`: ikigai's review triage
/// list less `praise`, which is not an issue. Triage for a reader, never a gate.
const SEVERITIES: [&str; 4] = ["critical", "major", "minor", "info"];

/// Exit status: the door answered with an error, or a file entry failed its own check.
pub(crate) const EXIT_DOOR: i32 = 1;
/// Exit status: a usage problem, or a problem on this side (a file that cannot be read).
pub(crate) const EXIT_USAGE: i32 = 2;

pub(crate) const USAGE: &str = "\
usage (connection flags such as --override, --connect and --cert-dir go BEFORE `layers`):
  ikigai layers post brief LAYER [FILE|-] [--title T] [--repo owner/name|https://…]
  ikigai layers post issue LAYER [FILE|-] [--title T] [--repo …] [--severity critical|major|minor|info]
  ikigai layers post file LAYER PATH [--file-name N] [--media-type type/subtype]
      every post also takes --in-reply-to ENTRY and --supersedes ENTRY, and prints the entry's IRI;
      a brief or issue body is FILE, or stdin with - or no FILE; its title defaults to the
      body's first `# ` heading
  ikigai layers save ENTRY [PATH] [--as NAME] [--force]
      write a file entry's bytes to PATH (a directory: its own name in it, or NAME with --as;
      none: your downloads directory, ~/Downloads) after checking its size and SHA-256; nothing
      is written when either does not match. A name an agent or a shell loads as configuration
      (CLAUDE.md, AGENTS.md, .mcp.json, .envrc, any .git name), any name beginning with a dot,
      any ':', and a Windows device name (CON, NUL, COM1) are refused: save it under another
      name with --as NAME. --force replaces an existing file at the target; its old content is
      lost
exit: 0 done, 1 the door answered an error (or a file failed its check), 2 usage or local";

/// What `ikigai layers …` was asked to do, as parsed (nothing read or dialed yet).
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Command {
    /// `layers -h|--help`: the usage, exit 0.
    Help,
    Post {
        layer: String,
        kind: PostKind,
        in_reply_to: Option<String>,
        supersedes: Option<String>,
    },
    Save {
        entry: String,
        path: Option<PathBuf>,
        /// `--as NAME`: save under NAME instead of the entry's own file name.
        as_name: Option<String>,
        force: bool,
    },
}

/// The kind of entry a post writes, with its own options.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PostKind {
    Brief {
        source: String,
        title: Option<String>,
        repo: Option<String>,
    },
    Issue {
        source: String,
        title: Option<String>,
        repo: Option<String>,
        severity: Option<String>,
    },
    File {
        path: PathBuf,
        file_name: Option<String>,
        media_type: Option<String>,
    },
}

/// Parse what follows `layers` on the command line. Every argument after it belongs to it.
pub(crate) fn parse(argv: impl Iterator<Item = String>) -> Result<Command, String> {
    let mut argv = argv.peekable();
    let value = |argv: &mut std::iter::Peekable<_>, flag: &str| -> Result<String, String> {
        Iterator::next(argv).ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))
    };
    match argv.next().as_deref() {
        Some("-h" | "--help") => Ok(Command::Help),
        Some("post") => {
            let kind = argv.next().ok_or_else(|| {
                format!("`layers post` needs a kind: brief, issue or file\n{USAGE}")
            })?;
            if !matches!(kind.as_str(), "brief" | "issue" | "file") {
                return Err(format!(
                    "`layers post {kind}`: the kinds are brief, issue and file\n{USAGE}"
                ));
            }
            let mut positional = Vec::new();
            let (mut title, mut repo, mut severity) = (None, None, None);
            let (mut file_name, mut media_type) = (None, None);
            let (mut in_reply_to, mut supersedes) = (None, None);
            while let Some(arg) = argv.next() {
                let text = kind.as_str() != "file";
                match arg.as_str() {
                    "--in-reply-to" => in_reply_to = Some(value(&mut argv, &arg)?),
                    "--supersedes" => supersedes = Some(value(&mut argv, &arg)?),
                    "--title" if text => title = Some(value(&mut argv, &arg)?),
                    "--repo" if text => repo = Some(value(&mut argv, &arg)?),
                    "--severity" if kind == "issue" => severity = Some(value(&mut argv, &arg)?),
                    "--file-name" if !text => file_name = Some(value(&mut argv, &arg)?),
                    "--media-type" if !text => media_type = Some(value(&mut argv, &arg)?),
                    "-" => positional.push(arg),
                    other if other.starts_with('-') => {
                        return Err(format!(
                            "unknown argument after `layers post {kind}`: {other} (connection \
                             flags go before `layers`)\n{USAGE}"
                        ))
                    }
                    _ => positional.push(arg),
                }
            }
            let mut positional = positional.into_iter();
            let layer = positional
                .next()
                .ok_or_else(|| format!("`layers post {kind}` needs a LAYER\n{USAGE}"))?;
            let second = positional.next();
            if let Some(extra) = positional.next() {
                return Err(format!(
                    "unexpected argument after `layers post {kind}`: {extra}\n{USAGE}"
                ));
            }
            let kind = match kind.as_str() {
                "brief" => PostKind::Brief {
                    source: second.unwrap_or_else(|| "-".to_string()),
                    title,
                    repo,
                },
                "issue" => PostKind::Issue {
                    source: second.unwrap_or_else(|| "-".to_string()),
                    title,
                    repo,
                    severity,
                },
                _ => PostKind::File {
                    path: PathBuf::from(second.ok_or_else(|| {
                        format!("`layers post file` needs the PATH of the file to attach\n{USAGE}")
                    })?),
                    file_name,
                    media_type,
                },
            };
            Ok(Command::Post {
                layer,
                kind,
                in_reply_to,
                supersedes,
            })
        }
        Some("save") => {
            let mut positional = Vec::new();
            let mut force = false;
            let mut as_name = None;
            while let Some(arg) = argv.next() {
                match arg.as_str() {
                    "--force" => force = true,
                    "--as" => as_name = Some(value(&mut argv, &arg)?),
                    other if other.starts_with('-') => {
                        return Err(format!(
                            "unknown argument after `layers save`: {other} (connection flags \
                             go before `layers`)\n{USAGE}"
                        ))
                    }
                    _ => positional.push(arg),
                }
            }
            let mut positional = positional.into_iter();
            let entry = positional
                .next()
                .ok_or_else(|| format!("`layers save` needs the file entry's IRI\n{USAGE}"))?;
            let path = positional.next().map(PathBuf::from);
            if let Some(extra) = positional.next() {
                return Err(format!(
                    "unexpected argument after `layers save`: {extra}\n{USAGE}"
                ));
            }
            Ok(Command::Save {
                entry,
                path,
                as_name,
                force,
            })
        }
        Some(other) => Err(format!("unknown `layers` command: {other}\n{USAGE}")),
        None => Err(USAGE.to_string()),
    }
}

/// A command with everything local done: a post's entry composed (its files and stdin read),
/// a save's arguments checked. What [`run`] does next is only the door's part.
pub(crate) enum Prepared {
    Help,
    Post {
        layer: String,
        turtle: String,
        /// For a file: what the size bound is checked against before sending.
        file: Option<FileCheck>,
    },
    Save {
        entry: String,
        target: SaveTarget,
        force: bool,
    },
}

/// Where `save` writes, settled before anything is dialed.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SaveTarget {
    /// Into this directory (PATH named one, or the downloads directory when there was no
    /// PATH), under `as_name` or else the entry's own file name, which is checked when it
    /// arrives.
    Dir {
        dir: PathBuf,
        as_name: Option<String>,
    },
    /// To this file: PATH named it, and its name has been checked already, so the entry's
    /// own name does not matter.
    File(PathBuf),
}

/// What a file post checks against the layer's shapes before it is sent.
pub(crate) struct FileCheck {
    name: String,
    size: usize,
    encoding: &'static str,
    content: String,
}

/// Do everything that needs no door: refuse a bad name, entry, repository or severity, read
/// the body or file, and compose the entry. An error here is a usage or local problem.
pub(crate) fn prepare(command: Command) -> Result<Prepared, String> {
    match command {
        Command::Help => Ok(Prepared::Help),
        Command::Post {
            layer,
            kind,
            in_reply_to,
            supersedes,
        } => {
            layer_name(&layer)?;
            let thread = Thread {
                in_reply_to: in_reply_to.as_deref(),
                supersedes: supersedes.as_deref(),
            };
            let (turtle, file) = match kind {
                PostKind::Brief {
                    source,
                    title,
                    repo,
                } => {
                    let repo = repo.as_deref().map(repository).transpose()?;
                    let (title, body) = titled_body(&source, title, "brief")?;
                    (brief(&title, &body, repo.as_deref(), thread)?, None)
                }
                PostKind::Issue {
                    source,
                    title,
                    repo,
                    severity,
                } => {
                    let repo = repo.as_deref().map(repository).transpose()?;
                    let severity = severity.as_deref().map(severity_iri).transpose()?;
                    let (title, body) = titled_body(&source, title, "issue")?;
                    (
                        issue(&title, &body, repo.as_deref(), severity.as_deref(), thread)?,
                        None,
                    )
                }
                PostKind::File {
                    path,
                    file_name,
                    media_type,
                } => {
                    let data = std::fs::read(&path)
                        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                    let name = match file_name {
                        Some(name) => name,
                        None => path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .ok_or_else(|| {
                                format!(
                                    "{} has no file name to post it under: give --file-name",
                                    path.display()
                                )
                            })?
                            .to_string(),
                    };
                    safe_name(&name).map_err(|e| {
                        format!(
                            "{e}, and a reader cannot save it: post it under another name with \
                             --file-name NAME"
                        )
                    })?;
                    let entry = file_entry(&name, &data, media_type.as_deref(), thread)?;
                    (
                        entry.turtle,
                        Some(FileCheck {
                            name,
                            size: data.len(),
                            encoding: entry.encoding,
                            content: entry.content,
                        }),
                    )
                }
            };
            Ok(Prepared::Post {
                layer,
                turtle,
                file,
            })
        }
        Command::Save {
            entry,
            path,
            as_name,
            force,
        } => {
            entry_layer(&entry)?;
            if let Some(name) = &as_name {
                safe_name(name).map_err(|e| format!("not saved: {e}; choose another --as NAME"))?;
            }
            let target = save_target(path, as_name, downloads_dir)?;
            Ok(Prepared::Save {
                entry,
                target,
                force,
            })
        }
    }
}

/// Run a prepared command against `engine`; the process exit status.
pub(crate) fn run(engine: &Engine, prepared: Prepared) -> i32 {
    let outcome = match prepared {
        Prepared::Help => Ok(USAGE.to_string()),
        Prepared::Post {
            layer,
            turtle,
            file,
        } => post(engine, &layer, turtle, file),
        Prepared::Save {
            entry,
            target,
            force,
        } => save(engine, &entry, &target, force),
    };
    match outcome {
        Ok(line) => {
            println!("{line}");
            0
        }
        Err((code, message)) => {
            eprintln!("ikigai: {message}");
            code
        }
    }
}

type Outcome = Result<String, (i32, String)>;

/// One engine line's answer, or the door's error as exit 1.
fn ask(engine: &Engine, line: &str) -> Result<String, (i32, String)> {
    match engine.eval(line) {
        Action::Output(entry) => entry.result.map_err(|e| (EXIT_DOOR, e)),
        _ => Err((EXIT_DOOR, format!("`{line}` produced no answer"))),
    }
}

fn post(engine: &Engine, layer: &str, turtle: String, file: Option<FileCheck>) -> Outcome {
    if let Some(file) = file {
        let shapes = ask(engine, &format!("source urn:layer:{layer}:shapes"))?;
        let shapes = Shapes::parse(&shapes).map_err(|e| {
            (
                EXIT_DOOR,
                format!("the shapes of layer `{layer}` do not parse: {e}"),
            )
        })?;
        if !shapes.takes_files {
            return Err((
                EXIT_USAGE,
                format!("layer `{layer}` does not take files: its shapes admit no ik:File"),
            ));
        }
        if let Some(bound) = shapes.content_bound {
            if let Some(why) = too_large(&file, bound) {
                return Err((EXIT_USAGE, why));
            }
        }
    }
    engine.set_piped_input(turtle.into_bytes());
    let answer = ask(engine, &format!("sink urn:layer:{layer}:say"))?;
    Ok(answer.trim().to_string())
}

fn save(engine: &Engine, entry: &str, target: &SaveTarget, force: bool) -> Outcome {
    let turtle = ask(engine, &format!("source {entry} as=text/turtle"))?;
    let node = Node::of(&turtle, entry).map_err(|e| (EXIT_DOOR, format!("not saved: {e}")))?;
    if !node.types.iter().any(|t| t == &format!("{IK}File")) {
        let kind = node
            .types
            .iter()
            .map(|t| t.strip_prefix(IK).unwrap_or(t))
            .collect::<Vec<_>>()
            .join(",");
        return Err((
            EXIT_USAGE,
            format!(
                "{entry} is {}, not a file",
                if kind.is_empty() {
                    "an entry".to_string()
                } else {
                    format!("a {kind}")
                }
            ),
        ));
    }
    // The entry's own name matters only when it picks the file: not with --as, and not when
    // PATH names the file (both were checked before dialing).
    let target = match target {
        SaveTarget::Dir {
            dir,
            as_name: Some(name),
        } => dir.join(name),
        SaveTarget::Dir { dir, as_name: None } => {
            let name = node
                .one("fileName")
                .map_err(|e| (EXIT_DOOR, format!("not saved: {e}")))?;
            let name = safe_name(name).map_err(|e| {
                (
                    EXIT_DOOR,
                    format!("not saved: {e}; save it under another name with --as NAME"),
                )
            })?;
            dir.join(name)
        }
        SaveTarget::File(path) => path.clone(),
    };
    let data = node
        .bytes()
        .map_err(|e| (EXIT_DOOR, format!("not saved: {e}")))?;
    if target.exists() && !force {
        return Err((
            EXIT_USAGE,
            format!(
                "{} exists: give another PATH, --as NAME, or --force to replace it (its old \
                 content is lost)",
                target.display()
            ),
        ));
    }
    write_whole(&target, &data).map_err(|e| {
        (
            EXIT_USAGE,
            format!("cannot write {}: {e}", target.display()),
        )
    })?;
    Ok(format!(
        "saved {} ({} bytes, {})",
        target.display(),
        data.len(),
        digest(&data)
    ))
}

/// Where `save` writes, decided before dialing (the Python client's `_save_dir`): no PATH is
/// the downloads directory (`downloads`, refused when there is none, never the working
/// directory, which is often a repository an agent works in); a directory is that directory;
/// and a PATH naming the file has its own name held to [`safe_name`]. `--as` needs a directory.
fn save_target(
    path: Option<PathBuf>,
    as_name: Option<String>,
    downloads: impl FnOnce() -> Result<PathBuf, String>,
) -> Result<SaveTarget, String> {
    let Some(path) = path else {
        return Ok(SaveTarget::Dir {
            dir: downloads()?,
            as_name,
        });
    };
    if path.is_dir() {
        return Ok(SaveTarget::Dir { dir: path, as_name });
    }
    if as_name.is_some() {
        return Err(format!(
            "{} is not a directory: give --as NAME with a directory, or a PATH that names the file",
            path.display()
        ));
    }
    let name = match path.file_name() {
        None => String::new(),
        Some(name) => name.to_str().map(str::to_string).ok_or_else(|| {
            format!(
                "not saved: {} has a name that is not UTF-8; give PATH another name",
                path.display()
            )
        })?,
    };
    safe_name(&name).map_err(|e| format!("not saved: {e}; give PATH another name"))?;
    Ok(SaveTarget::File(path))
}

/// Write `data` to `target` whole or not at all: into a new file beside it, then renamed over
/// it, so a reader never sees half a file and a failed write leaves nothing behind.
fn write_whole(target: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = match target.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    std::fs::create_dir_all(&dir)?;
    // A name no other file has: this process's id, then the first free number. `create_new`
    // refuses an existing file, so a leftover from a crashed save is stepped over, never reused.
    let mut n = 0u32;
    let (temp, mut file) = loop {
        let temp = dir.join(format!(".ikigai-layers-{}-{n}", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
        {
            Ok(file) => break (temp, file),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 1000 => n += 1,
            Err(e) => return Err(e),
        }
    };
    let written = (|| {
        file.write_all(data)?;
        file.sync_all()?;
        std::fs::rename(&temp, target)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written
}

// ---- composing an entry --------------------------------------------------------------------

/// The entry an entry answers or replaces, both optional.
#[derive(Clone, Copy, Default)]
struct Thread<'a> {
    in_reply_to: Option<&'a str>,
    supersedes: Option<&'a str>,
}

/// `name` if it is a layer name (lowercase `[a-z0-9-]`, 1 to 24, no leading or trailing `-`).
fn layer_name(name: &str) -> Result<&str, String> {
    let ok = (1..=24).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if ok {
        Ok(name)
    } else {
        Err(format!(
            "`{name}` is not a layer name (lowercase a-z, 0-9 and -, 1 to 24)"
        ))
    }
}

/// The layer an entry IRI (`urn:layer:{layer}:entry:{id}`) belongs to.
fn entry_layer(entry: &str) -> Result<&str, String> {
    let refuse = || format!("`{entry}` is not an entry IRI (urn:layer:LAYER:entry:ID)");
    let rest = entry.strip_prefix("urn:layer:").ok_or_else(refuse)?;
    let (layer, id) = rest.split_once(":entry:").ok_or_else(refuse)?;
    layer_name(layer).map_err(|_| refuse())?;
    if id.is_empty()
        || id
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '<' | '>' | '"'))
    {
        return Err(refuse());
    }
    Ok(layer)
}

/// `text` as a Turtle double-quoted string literal, every character it may not hold raw
/// escaped (Turtle 1.1 `STRING_LITERAL_QUOTE`).
fn literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7F => {
                out.push_str(&format!("\\u{:04X}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `value` as a Turtle IRI reference `<…>`, refused when it cannot be one (Turtle 1.1 `IRIREF`
/// excludes these characters, and an IRI here is absolute).
fn iri(value: &str) -> Result<String, String> {
    let bad = value.is_empty()
        || !value.contains(':')
        || value
            .chars()
            .any(|c| (c as u32) <= 0x20 || "<>\"{}|^`\\".contains(c));
    if bad {
        Err(format!("{value:?} is not an absolute IRI"))
    } else {
        Ok(format!("<{value}>"))
    }
}

/// A repository's web IRI: `owner/name` is a GitHub repository, an `https://` IRI is taken as
/// given, and a bare name is refused (`ikigai-core` names a directory on one machine, and
/// means nothing to a reader on another).
fn repository(value: &str) -> Result<String, String> {
    if value.starts_with("https://") {
        iri(value)?;
        return Ok(value.to_string());
    }
    let part = |p: &str| {
        !p.is_empty()
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    };
    match value.split_once('/') {
        Some((owner, name)) if part(owner) && part(name) && !value.contains("..") => {
            Ok(format!("https://github.com/{value}"))
        }
        _ => Err(format!(
            "`{value}` is not a repository: give owner/name (on GitHub) or its https:// IRI"
        )),
    }
}

/// The IRI of one of [`SEVERITIES`].
fn severity_iri(name: &str) -> Result<String, String> {
    if SEVERITIES.contains(&name) {
        Ok(format!("urn:iki:severity:{name}"))
    } else {
        Err(format!(
            "`{name}` is not a severity ({})",
            SEVERITIES.join(", ")
        ))
    }
}

/// The Turtle for one entry of class `ik:{kind}` making `statements` (each `predicate
/// object`, already serialized), about `<urn:layer:new>`, which the host renames.
fn entry(kind: &str, statements: Vec<String>, thread: Thread<'_>) -> Result<String, String> {
    let mut said = vec![format!("a ik:{kind}")];
    said.extend(statements);
    if let Some(target) = thread.in_reply_to {
        said.push(format!("ik:inReplyTo {}", iri(target)?));
    }
    if let Some(target) = thread.supersedes {
        said.push(format!("ik:supersedes {}", iri(target)?));
    }
    let mut prefixes = format!("@prefix ik: <{IK}> .\n");
    if said.iter().any(|s| s.starts_with("dcterms:")) {
        prefixes.push_str(&format!("@prefix dcterms: <{DCTERMS}> .\n"));
    }
    Ok(format!(
        "{prefixes}<urn:layer:new> {} .\n",
        said.join(" ; ")
    ))
}

fn brief(
    title: &str,
    body: &str,
    repo: Option<&str>,
    thread: Thread<'_>,
) -> Result<String, String> {
    let mut said = vec![
        format!("dcterms:title {}", literal(title)),
        format!("ik:body {}", literal(body)),
    ];
    if let Some(repo) = repo {
        said.push(format!("ik:repository {}", iri(repo)?));
    }
    entry("Brief", said, thread)
}

fn issue(
    title: &str,
    body: &str,
    repo: Option<&str>,
    severity: Option<&str>,
    thread: Thread<'_>,
) -> Result<String, String> {
    let mut said = vec![
        format!("dcterms:title {}", literal(title)),
        format!("ik:body {}", literal(body)),
    ];
    if let Some(repo) = repo {
        said.push(format!("ik:repository {}", iri(repo)?));
    }
    if let Some(severity) = severity {
        said.push(format!("ik:severity {}", iri(severity)?));
    }
    entry("Issue", said, thread)
}

/// The first `# ` heading of a Markdown body (a level-one ATX heading), its closing `#`s
/// dropped.
fn first_heading(body: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let rest = line.strip_prefix('#')?;
        if !rest.starts_with([' ', '\t']) {
            return None;
        }
        let title = rest.trim().trim_end_matches('#').trim_end();
        (!title.is_empty()).then(|| title.to_string())
    })
}

/// The body (`source`: a file, or stdin with `-`) and the title: `title`, else the body's
/// first `# ` heading.
fn titled_body(
    source: &str,
    title: Option<String>,
    what: &str,
) -> Result<(String, String), String> {
    let body = if source == "-" {
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            return Err(format!(
                "the {what}: give it as a FILE argument, or pipe it in"
            ));
        }
        let mut text = String::new();
        stdin
            .lock()
            .read_to_string(&mut text)
            .map_err(|e| format!("cannot read the {what} from stdin: {e}"))?;
        // A piped body keeps the newline its producer ended it with; it is not the body's.
        text.trim_end_matches('\n').to_string()
    } else {
        std::fs::read_to_string(source).map_err(|e| format!("cannot read {source}: {e}"))?
    };
    if body.trim().is_empty() {
        return Err(format!("the {what} is empty"));
    }
    let title = match title {
        Some(t) => t,
        None => first_heading(&body).ok_or_else(|| {
            format!("give the {what} a --title, or start it with a `# Title` line")
        })?,
    };
    let title = title.trim().to_string();
    if title.is_empty() {
        return Err("the title is empty".to_string());
    }
    Ok((title, body))
}

/// The digest an `ik:File` names: `sha256:` and the lowercase hex of the bytes' SHA-256.
fn digest(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for byte in hash {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// `("text", the text)` when `data` is UTF-8 with no control character but tab, newline and
/// carriage return, else `("base64", its base64)`. Either way the digest and the size are of
/// the BYTES.
fn encode(data: &[u8]) -> (&'static str, String) {
    if let Ok(text) = std::str::from_utf8(data) {
        let plain = !text
            .chars()
            .any(|c| ((c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r')) || c as u32 == 0x7F);
        if plain {
            return ("text", text.to_string());
        }
    }
    ("base64", ikigai_http::base64::encode(data))
}

/// Names an agent, a shell or a tool loads as configuration, or as credentials, from the
/// directory it runs in or from home, compared case-insensitively (each written here in its
/// folded form). Most begin with a dot, and the leading-dot rule refuses every one of those
/// anyway; they are listed so the reason a reader sees is the specific one. Every name
/// beginning `.git` is refused too (`.gitconfig`, `.gitattributes`, `.git`).
///
/// The Python participant client's `CONFIG_NAMES` (`files.py` in ikigai-layers-client), the
/// source of truth for this rule (ledger #1748): a name added there is added here.
const CONFIG_NAMES: [&str; 24] = [
    // agent instructions and tool servers
    "claude.md",
    "claude.local.md",
    "agents.md",
    "agent.md",
    "gemini.md",
    ".mcp.json",
    // shells and direnv
    ".envrc",
    ".env",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    // credentials read by git, npm, pip and curl (`_netrc` is the Windows spelling)
    ".gitconfig",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "_netrc",
    // Python code that pytest and the interpreter import on their own
    "conftest.py",
    "sitecustomize.py",
    "usercustomize.py",
];

/// Windows device names, reserved with or without an extension (`CON`, `con.txt`), as
/// Microsoft's naming rules list them, with the ports below. The Python client's
/// `WINDOWS_DEVICES`.
const WINDOWS_DEVICES: [&str; 6] = ["con", "prn", "aux", "nul", "conin$", "conout$"];
/// `COM0`-`COM9` and `LPT0`-`LPT9`, and the superscript-digit ports (`COM¹`, `LPT³`).
const WINDOWS_PORTS: [&str; 2] = ["com", "lpt"];
const WINDOWS_PORT_DIGITS: &str = "0123456789\u{b9}\u{b2}\u{b3}";
/// The characters Windows does not allow in a name (besides `:`, `/` and `\`, refused
/// before), in code point order so the one a refusal names is the Python client's.
const WINDOWS_FORBIDDEN: [char; 6] = ['"', '*', '<', '>', '?', '|'];

/// Full Unicode case folding, as Python's `str.casefold` does it.
fn fold(text: &str) -> String {
    icu_casemap::CaseMapper::new()
        .fold_string(text)
        .into_owned()
}

/// Whether `stem` (a name before its first dot, trailing spaces dropped) is a Windows device.
fn is_windows_device(stem: &str) -> bool {
    let stem = fold(stem);
    WINDOWS_DEVICES.contains(&stem.as_str()) || WINDOWS_PORTS.iter().any(|port| {
        let mut digit = stem.strip_prefix(port).unwrap_or("").chars();
        matches!((digit.next(), digit.next()), (Some(d), None) if WINDOWS_PORT_DIGITS.contains(d))
    })
}

/// `name` if it is a bare file name a reader can save without leaving the directory it chose
/// and without arming anything there, else why not.
///
/// Refused, in this order (the Python participant client's `safe_name`, ledger #1748): a name
/// with a directory in it, or a control character; a name over 255 characters; an invisible
/// character (general category Cf, Zl or Zp: HFS+ ignored some of these when comparing names,
/// git's CVE-2014-9390); a name an agent or a shell loads as configuration ([`CONFIG_NAMES`],
/// and every `.git` name), compared after NFKC, with trailing dots and spaces dropped, and
/// case folded, as a case-insensitive file system and Windows would compare it; any name
/// beginning with a dot; a Windows drive (`C:x`) and any other `:` (an alternate data stream,
/// `a.txt:x`); a character Windows does not allow; a trailing dot or space (Windows drops it, so
/// `CLAUDE.md.` would land as `CLAUDE.md`); and a Windows device name with or without an
/// extension (`CON`, `nul.txt`).
fn safe_name(name: &str) -> Result<&str, String> {
    let bad = name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '\\'])
        || name.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7F);
    if bad {
        return Err(format!("{name:?} is not a bare file name"));
    }
    if name.chars().count() > 255 {
        let head: String = name.chars().take(40).collect();
        return Err(format!("{head:?}… is over 255 characters"));
    }
    let categories = icu_properties::CodePointMapData::<GeneralCategory>::new();
    if let Some(hidden) = name.chars().find(|&c| {
        matches!(
            categories.get(c),
            GeneralCategory::Format
                | GeneralCategory::LineSeparator
                | GeneralCategory::ParagraphSeparator
        )
    }) {
        return Err(format!(
            "{name:?} holds an invisible character (U+{:04X})",
            hidden as u32
        ));
    }
    // As a case-insensitive file system, and Windows, would compare it.
    let normalized = icu_normalizer::ComposingNormalizer::new_nfkc().normalize(name);
    let key = fold(normalized.trim_end_matches(['.', ' ']));
    if CONFIG_NAMES.contains(&key.as_str()) || key.starts_with(".git") {
        return Err(format!(
            "{name:?} is a name an agent or a shell loads as configuration"
        ));
    }
    if name.starts_with('.') {
        return Err(format!(
            "{name:?} begins with a dot: a hidden file, the form configuration takes"
        ));
    }
    let mut chars = name.chars();
    if let (Some(drive), Some(':')) = (chars.next(), chars.next()) {
        if drive.is_ascii_alphabetic() {
            return Err(format!("{name:?} begins with a Windows drive ({drive}:)"));
        }
    }
    if name.contains(':') {
        return Err(format!(
            "{name:?} holds ':', which Windows reads as an alternate data stream"
        ));
    }
    if let Some(c) = WINDOWS_FORBIDDEN.iter().find(|&&c| name.contains(c)) {
        return Err(format!(
            "{name:?} holds {c:?}, which Windows does not allow in a name"
        ));
    }
    if name.ends_with(['.', ' ']) {
        return Err(format!(
            "{name:?} ends in a dot or a space, which Windows drops from a name"
        ));
    }
    let stem = name.split('.').next().unwrap_or(name);
    if is_windows_device(stem.trim_end_matches(' ')) {
        return Err(format!("{name:?} is a Windows device name ({stem})"));
    }
    Ok(name)
}

/// Where `save` writes when it is given no PATH: `~/Downloads` when it is a directory, else
/// the platform's own downloads directory (on Windows the Downloads known folder; elsewhere the
/// `XDG_DOWNLOAD_DIR` of `~/.config/user-dirs.dirs`), else a refusal asking for a PATH. Never
/// home itself: a downloads directory set to home is the XDG spelling of "none".
fn downloads_dir() -> Result<PathBuf, String> {
    // $HOME, read once here (the environment is process-global); on Windows a native shell
    // sets USERPROFILE instead.
    let mut home = std::env::var_os("HOME").unwrap_or_default();
    if cfg!(windows) && home.is_empty() {
        home = std::env::var_os("USERPROFILE").unwrap_or_default();
    }
    let home = PathBuf::from(home);
    #[cfg(windows)]
    let known_folder: Option<&dyn Fn() -> Option<PathBuf>> = Some(&dirs::download_dir);
    #[cfg(not(windows))]
    let known_folder: Option<&dyn Fn() -> Option<PathBuf>> = None;
    downloads_dir_in(&home, known_folder).ok_or_else(|| {
        if home.as_os_str().is_empty() {
            "no downloads directory found (HOME is not set): give a PATH to save into".to_string()
        } else {
            format!(
                "no downloads directory found (no {}): give a PATH to save into",
                home.join("Downloads").display()
            )
        }
    })
}

/// [`downloads_dir`] for a given `home` (an empty one is no home). `known_folder` is the
/// Windows lookup, and its presence is the Windows branch, so a test takes either branch on
/// any platform (the Python client's `registry` parameter).
fn downloads_dir_in(
    home: &Path,
    known_folder: Option<&dyn Fn() -> Option<PathBuf>>,
) -> Option<PathBuf> {
    let has_home = !home.as_os_str().is_empty();
    let home_resolved = std::fs::canonicalize(home).ok();
    let usable = |candidate: PathBuf| -> Option<PathBuf> {
        if !candidate.is_dir() {
            return None;
        }
        let resolved = std::fs::canonicalize(&candidate).ok()?;
        (home_resolved.as_ref() != Some(&resolved)).then_some(candidate)
    };
    if has_home {
        if let Some(found) = usable(home.join("Downloads")) {
            return Some(found);
        }
    }
    if let Some(lookup) = known_folder {
        return lookup().and_then(usable);
    }
    if !has_home {
        return None;
    }
    let dirs = std::fs::read_to_string(home.join(".config").join("user-dirs.dirs")).ok()?;
    for line in dirs.lines() {
        let Some(value) = xdg_download_dir(line) else {
            continue;
        };
        if let Some(rest) = value.strip_prefix("$HOME/") {
            return usable(home.join(rest));
        }
        if value.starts_with('/') {
            return usable(PathBuf::from(value));
        }
        return None;
    }
    None
}

/// The value of a `XDG_DOWNLOAD_DIR="…"` line of `user-dirs.dirs`, `None` for any other line.
fn xdg_download_dir(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("XDG_DOWNLOAD_DIR")?;
    let rest = rest.trim_start().strip_prefix('=')?;
    let rest = rest.trim_start().strip_prefix('"')?;
    let value = rest.trim_end().strip_suffix('"')?;
    (!value.contains('"')).then_some(value)
}

/// Whether a layer's shapes take `value` as a media type: lowercase `type/subtype`, no
/// parameters, at most 127 bytes (the edge's `talk.shapes.ttl` pattern).
fn is_media_type(value: &str) -> bool {
    let token = |t: &str| {
        let mut bytes = t.bytes();
        matches!(bytes.next(), Some(b) if b.is_ascii_lowercase() || b.is_ascii_digit())
            && bytes
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!$&^_.+-".contains(&b))
    };
    value.len() <= 127 && matches!(value.split_once('/'), Some((t, s)) if token(t) && token(s))
}

/// The media type of `name` by its extension; when that says nothing a layer takes, `text/plain`
/// for text and `application/octet-stream` for anything else.
fn guess_media_type(name: &str, encoding: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let guessed = if lower.ends_with(".md") || lower.ends_with(".markdown") {
        // Not in every table.
        Some("text/markdown".to_string())
    } else {
        mime_guess::from_path(name)
            .first_raw()
            .map(str::to_ascii_lowercase)
    };
    match guessed {
        Some(m) if is_media_type(&m) => m,
        _ if encoding == "text" => "text/plain".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}

/// One `ik:File` entry, and what its size bound is checked against.
struct FileEntry {
    turtle: String,
    encoding: &'static str,
    content: String,
}

fn file_entry(
    name: &str,
    data: &[u8],
    media: Option<&str>,
    thread: Thread<'_>,
) -> Result<FileEntry, String> {
    safe_name(name)?;
    let (encoding, content) = encode(data);
    let media = match media {
        Some(m) => {
            let m = m.to_ascii_lowercase();
            if !is_media_type(&m) {
                return Err(format!(
                    "`{m}` is not a media type a layer takes (lowercase type/subtype)"
                ));
            }
            m
        }
        None => guess_media_type(name, encoding),
    };
    let said = vec![
        format!("ik:fileName {}", literal(name)),
        format!("ik:mediaType {}", literal(&media)),
        format!("ik:contentHash {}", literal(&digest(data))),
        format!("ik:byteSize {}", data.len()),
        format!("ik:encoding {}", literal(encoding)),
        format!("ik:content {}", literal(&content)),
    ];
    Ok(FileEntry {
        turtle: entry("File", said, thread)?,
        encoding,
        content,
    })
}

/// Why the encoded content is over `bound` (the shapes' `sh:maxLength` on `ik:content`),
/// naming the largest file the layer takes; `None` when it fits. Measured in UTF-8 bytes of
/// the escaped literal, never fewer than the characters `sh:maxLength` counts, so a file that
/// fits here fits the door's entry bound too.
fn too_large(file: &FileCheck, bound: u64) -> Option<String> {
    let encoded = (literal(&file.content).len() - 2) as u64;
    if encoded <= bound {
        return None;
    }
    let binary = bound / 4 * 3;
    Some(format!(
        "{} is {} bytes, {encoded} bytes as {}; this layer takes at most {bound} bytes of \
         content, which is a file of about {binary} bytes of binary or {bound} bytes of plain \
         text. Share a link to it instead.",
        file.name, file.size, file.encoding
    ))
}

// ---- reading what the door answers ----------------------------------------------------------

/// What `post file` reads of a layer's shapes (`urn:layer:{layer}:shapes`, Turtle).
#[derive(Debug, PartialEq)]
struct Shapes {
    /// Some shape targets `ik:File`.
    takes_files: bool,
    /// The least `sh:maxLength` any property shape on `ik:content` sets.
    content_bound: Option<u64>,
}

impl Shapes {
    fn parse(turtle: &str) -> Result<Shapes, String> {
        let triples = parse_turtle(turtle)?;
        let file = format!("{IK}File");
        let content = format!("{IK}content");
        let (target, path, max) = (
            format!("{SH}targetClass"),
            format!("{SH}path"),
            format!("{SH}maxLength"),
        );
        let takes_files = triples
            .iter()
            .any(|t| t.predicate.as_str() == target && iri_of(&t.object) == Some(file.as_str()));
        let on_content: Vec<&oxrdf::NamedOrBlankNode> = triples
            .iter()
            .filter(|t| t.predicate.as_str() == path && iri_of(&t.object) == Some(content.as_str()))
            .map(|t| &t.subject)
            .collect();
        let content_bound = triples
            .iter()
            .filter(|t| t.predicate.as_str() == max && on_content.contains(&&t.subject))
            .filter_map(|t| literal_of(&t.object)?.parse::<u64>().ok())
            .min();
        Ok(Shapes {
            takes_files,
            content_bound,
        })
    }
}

fn parse_turtle(text: &str) -> Result<Vec<oxrdf::Triple>, String> {
    oxttl::TurtleParser::new()
        .for_slice(text.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

fn iri_of(term: &oxrdf::Term) -> Option<&str> {
    match term {
        oxrdf::Term::NamedNode(n) => Some(n.as_str()),
        _ => None,
    }
}

fn literal_of(term: &oxrdf::Term) -> Option<&str> {
    match term {
        oxrdf::Term::Literal(l) => Some(l.value()),
        _ => None,
    }
}

/// One entry, as the statements about it in the door's Turtle.
struct Node {
    iri: String,
    types: Vec<String>,
    values: Vec<(String, String)>,
}

impl Node {
    fn of(turtle: &str, entry: &str) -> Result<Node, String> {
        let triples = parse_turtle(turtle)
            .map_err(|e| format!("the door's answer for {entry} does not parse: {e}"))?;
        let mut node = Node {
            iri: entry.to_string(),
            types: Vec::new(),
            values: Vec::new(),
        };
        let mut found = false;
        for t in triples {
            let about =
                matches!(&t.subject, oxrdf::NamedOrBlankNode::NamedNode(n) if n.as_str() == entry);
            if !about {
                continue;
            }
            found = true;
            if t.predicate.as_str() == RDF_TYPE {
                if let Some(class) = iri_of(&t.object) {
                    node.types.push(class.to_string());
                }
            } else if let Some(value) = literal_of(&t.object) {
                node.values
                    .push((t.predicate.as_str().to_string(), value.to_string()));
            }
        }
        if found {
            Ok(node)
        } else {
            Err(format!("the door's answer for {entry} holds no such entry"))
        }
    }

    /// The one literal value of `ik:{local}`; refused when there is none or several.
    fn one(&self, local: &str) -> Result<&str, String> {
        let predicate = format!("{IK}{local}");
        let mut values = self.values.iter().filter(|(p, _)| *p == predicate);
        match (values.next(), values.next()) {
            (Some((_, v)), None) => Ok(v),
            (None, _) => Err(format!("{} carries no ik:{local}", self.iri)),
            _ => Err(format!("{} carries more than one ik:{local}", self.iri)),
        }
    }

    /// A file entry's bytes, after checking its size and its digest against them: the check
    /// the door cannot make, so the one that matters. Its NAME is not checked here: whether it
    /// matters depends on where it is saved ([`SaveTarget`]), and `save` holds it to
    /// [`safe_name`] when it does.
    fn bytes(&self) -> Result<Vec<u8>, String> {
        let content = self.one("content")?;
        let data = match self.one("encoding")? {
            "text" => content.as_bytes().to_vec(),
            "base64" => ikigai_http::base64::decode(content)
                .map_err(|e| format!("{}: its base64 does not decode: {e}", self.iri))?,
            other => {
                return Err(format!(
                    "{} has encoding {other:?}, which is neither text nor base64",
                    self.iri
                ))
            }
        };
        let size = self.one("byteSize")?;
        if size.parse::<usize>().ok() != Some(data.len()) {
            return Err(format!(
                "{}: its content is {} bytes, and it says {size}",
                self.iri,
                data.len()
            ));
        }
        let expected = self.one("contentHash")?;
        let actual = digest(&data);
        if actual != expected {
            return Err(format!(
                "{}: its content hashes to {actual}, and it says {expected}",
                self.iri
            ));
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &[&str]) -> Result<Command, String> {
        parse(line.iter().map(|s| s.to_string()))
    }

    #[test]
    fn a_literal_escapes_every_character_turtle_may_not_hold_raw() {
        assert_eq!(literal("say \"hi\"\n"), r#""say \"hi\"\n""#);
        assert_eq!(literal("a\\b\tc\rd"), r#""a\\b\tc\rd""#);
        assert_eq!(literal("bell\u{7}del\u{7f}"), r#""bell\u0007del\u007F""#);
        assert_eq!(literal("ümlaut ✓"), "\"ümlaut ✓\"");
        // And what it escapes parses back to the same text.
        let text = "line one\n\"quoted\" \\ back\u{1}slash";
        let turtle = format!("<urn:s> <urn:p> {} .", literal(text));
        let triples = parse_turtle(&turtle).unwrap();
        assert_eq!(literal_of(&triples[0].object), Some(text));
    }

    #[test]
    fn a_brief_is_the_turtle_the_shapes_name() {
        let turtle = brief(
            "Add a door check",
            "## Why",
            Some("https://github.com/ikigai-rs/ikigai-devtools"),
            Thread::default(),
        )
        .unwrap();
        assert_eq!(
            turtle,
            "@prefix ik: <https://ikigai-rs.dev/ns#> .\n\
             @prefix dcterms: <http://purl.org/dc/terms/> .\n\
             <urn:layer:new> a ik:Brief ; dcterms:title \"Add a door check\" ; ik:body \"## Why\" ; \
             ik:repository <https://github.com/ikigai-rs/ikigai-devtools> .\n"
        );
    }

    #[test]
    fn an_issue_names_its_severity_and_its_thread() {
        let turtle = issue(
            "Typo",
            "In the README.",
            None,
            Some("urn:iki:severity:minor"),
            Thread {
                in_reply_to: Some("urn:layer:talk:entry:01a"),
                supersedes: Some("urn:layer:talk:entry:01b"),
            },
        )
        .unwrap();
        assert!(
            turtle.contains("ik:severity <urn:iki:severity:minor>"),
            "{turtle}"
        );
        assert!(turtle.contains("ik:inReplyTo <urn:layer:talk:entry:01a>"));
        assert!(turtle.contains("ik:supersedes <urn:layer:talk:entry:01b>"));
        assert!(parse_turtle(&turtle).is_ok(), "it parses: {turtle}");
        // A thread target that cannot be an IRI is refused, never written into the Turtle.
        let bad = Thread {
            in_reply_to: Some("urn:x> . <urn:evil"),
            supersedes: None,
        };
        assert!(issue("t", "b", None, None, bad).is_err());
    }

    #[test]
    fn a_repository_is_owner_slash_name_or_https_and_never_a_bare_name() {
        assert_eq!(
            repository("ikigai-rs/ikigai-core").unwrap(),
            "https://github.com/ikigai-rs/ikigai-core"
        );
        assert_eq!(
            repository("https://example.org/r").unwrap(),
            "https://example.org/r"
        );
        for bad in [
            "ikigai-core",
            "a/b/c",
            "../x",
            "a/..",
            "http://x/y",
            "a/b c",
        ] {
            assert!(repository(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_severity_is_one_of_four() {
        assert_eq!(severity_iri("major").unwrap(), "urn:iki:severity:major");
        assert!(severity_iri("praise").is_err());
    }

    #[test]
    fn the_title_defaults_to_the_first_level_one_heading() {
        assert_eq!(
            first_heading("intro\n## Not this\n# Crash on start ##\nbody"),
            Some("Crash on start".to_string())
        );
        assert_eq!(first_heading("#hashtag\n## two"), None);
    }

    #[test]
    fn a_digest_is_sha256_hex() {
        assert_eq!(
            digest(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn text_travels_as_itself_and_anything_else_as_base64() {
        assert_eq!(
            encode(b"two\nlines\r\n\t"),
            ("text", "two\nlines\r\n\t".to_string())
        );
        assert_eq!(encode(b"\x89PNG\r\n"), ("base64", "iVBORw0K".to_string()));
        // UTF-8 with a control character is not text.
        assert_eq!(encode(b"esc\x1b[0m").0, "base64");
    }

    // ---- what `save` will write, and where (ledger #1748) ------------------------------------
    // Mirrors the Python participant client's tests/test_save_names.py, case for case.

    /// `name` is refused, and the reason says `because`.
    fn refused(name: &str, because: &str) {
        let err = safe_name(name).expect_err(name);
        assert!(err.contains(because), "{name:?}: {err}");
    }

    #[test]
    fn a_name_an_agent_or_shell_loads_as_configuration_is_refused() {
        for name in [
            "CLAUDE.md",
            "CLAUDE.local.md",
            "AGENTS.md",
            ".mcp.json",
            ".envrc",
            ".env",
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
            ".zshenv",
            ".zprofile",
            ".gitconfig",
            ".npmrc",
            ".pypirc",
            ".netrc",
            "_netrc",
            "conftest.py",
        ] {
            assert!(CONFIG_NAMES.contains(&fold(name).as_str()), "{name}");
            refused(name, "loads as configuration");
        }
        // The list is written folded, so a lookup by a folded key can find every entry.
        for name in CONFIG_NAMES {
            assert_eq!(fold(name), name);
            refused(name, "loads as configuration");
        }
    }

    #[test]
    fn configuration_names_match_case_insensitively() {
        for name in [
            "claude.md",
            "Claude.MD",
            "agents.MD",
            ".MCP.JSON",
            ".EnvRC",
            "CONFTEST.PY",
        ] {
            refused(name, "loads as configuration");
        }
    }

    #[test]
    fn every_git_name_is_refused() {
        for name in [
            ".git",
            ".gitattributes",
            ".gitignore",
            ".git-credentials",
            ".GITMODULES",
        ] {
            refused(name, "loads as configuration");
        }
    }

    #[test]
    fn a_trailing_dot_or_space_or_a_lookalike_does_not_slip_past_the_list() {
        // Windows drops a trailing dot or space, so CLAUDE.md. lands as CLAUDE.md there; and
        // NFKC makes the fullwidth spelling the ASCII one.
        for name in [
            "CLAUDE.md.",
            "AGENTS.md ",
            "CLAUDE.md. .",
            "\u{FF23}\u{FF2C}\u{FF21}\u{FF35}\u{FF24}\u{FF25}.md",
        ] {
            refused(name, "loads as configuration");
        }
    }

    #[test]
    fn the_comparison_folds_case_as_python_casefold_does() {
        // Full case folding, not lowercasing: these differ only where a fold expands.
        assert_eq!(fold("Stra\u{DF}e"), "strasse");
        assert_eq!(fold("\u{1E9E}"), "ss");
        assert_eq!(fold("CLAUDE.MD"), "claude.md");
    }

    #[test]
    fn an_invisible_character_is_refused() {
        // HFS+ ignored some of these when comparing names (git's CVE-2014-9390).
        for name in [
            "CLAUDE\u{200C}.md",
            "notes\u{200B}.md",
            "a\u{2028}b",
            "\u{FEFF}x.txt",
        ] {
            refused(name, "invisible character");
        }
        refused("a\u{2029}b", "(U+2029)");
    }

    #[test]
    fn any_leading_dot_is_refused() {
        for name in [".hidden", ".claude", "..notes", "._x", ".cursorrules"] {
            refused(name, "begins with a dot");
        }
    }

    #[test]
    fn windows_device_names_are_refused_with_or_without_an_extension() {
        for name in [
            "CON", "con", "PRN", "AUX", "Nul.txt", "COM1", "com9.log", "LPT1", "lpt0",
        ] {
            refused(name, "Windows device name");
        }
        for name in [
            "COM\u{B9}",
            "LPT\u{B3}.txt",
            "CONIN$",
            "aux .txt",
            "nul.tar.gz",
        ] {
            refused(name, "Windows device name");
        }
        refused("Nul.txt", "(Nul)");
    }

    #[test]
    fn a_drive_letter_is_refused() {
        for name in ["C:x", "c:evil", "Z:"] {
            refused(name, "Windows drive");
        }
    }

    #[test]
    fn any_colon_is_refused_as_an_alternate_data_stream() {
        for name in [
            "a.txt:ads",
            "notes:Zone.Identifier",
            "10:30.txt",
            "a.txt::$DATA",
        ] {
            refused(name, "alternate data stream");
        }
    }

    #[test]
    fn a_character_windows_does_not_allow_is_refused() {
        for name in ["a?b", "a*b", "a\"b", "a|b", "a<b", "a>b"] {
            refused(name, "Windows does not allow");
        }
        // The one named is the first in code point order, as the Python client names it.
        refused("a|b?c", "holds '?'");
    }

    #[test]
    fn a_trailing_dot_or_space_is_refused() {
        for name in ["notes.", "notes ", "a.txt.."] {
            refused(name, "ends in a dot or a space");
        }
    }

    #[test]
    fn a_directory_or_control_character_is_still_refused() {
        for name in ["", ".", "..", "a/b", "a\\b", "x\ny", "\0"] {
            refused(name, "not a bare file name");
        }
        refused(&"x".repeat(256), "over 255 characters");
    }

    #[test]
    fn an_ordinary_name_is_allowed() {
        for name in [
            "notes.md",
            "trace.log",
            "README.md",
            "report 2026-10-16.pdf",
            "claude-notes.md",
            "my.CLAUDE.md",
            "agents.md.txt",
            "console.txt",
            "COM10",
            "conx.txt",
            "donn\u{E9}es.csv",
            "a.b.c",
            &"x".repeat(255),
            // 255 characters, 510 bytes: the bound counts characters, as the Python client does.
            &"\u{E9}".repeat(255),
        ] {
            assert_eq!(safe_name(name), Ok(name), "{name:?}");
        }
    }

    /// A scratch directory unique to this case and process, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(case: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!("iki-names-{}-{case}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn downloads_under_home_when_it_exists() {
        let home = Scratch::new("dl-home");
        let downloads = home.0.join("Downloads");
        std::fs::create_dir(&downloads).unwrap();
        assert_eq!(downloads_dir_in(&home.0, None), Some(downloads.clone()));
        // On Windows too: ~\Downloads before the known folder.
        let none = || None;
        assert_eq!(downloads_dir_in(&home.0, Some(&none)), Some(downloads));
    }

    #[test]
    fn the_xdg_download_dir_otherwise() {
        let home = Scratch::new("dl-xdg");
        std::fs::create_dir_all(home.0.join(".config")).unwrap();
        std::fs::create_dir(home.0.join("T\u{E9}l\u{E9}chargements")).unwrap();
        std::fs::write(
            home.0.join(".config").join("user-dirs.dirs"),
            "# written by xdg-user-dirs-update\nXDG_DESKTOP_DIR=\"$HOME/Desktop\"\n\
             XDG_DOWNLOAD_DIR=\"$HOME/T\u{E9}l\u{E9}chargements\"\n",
        )
        .unwrap();
        assert_eq!(
            downloads_dir_in(&home.0, None),
            Some(home.0.join("T\u{E9}l\u{E9}chargements"))
        );
    }

    #[test]
    fn an_xdg_download_dir_that_is_home_means_none() {
        let home = Scratch::new("dl-xdg-home");
        std::fs::create_dir_all(home.0.join(".config")).unwrap();
        std::fs::write(
            home.0.join(".config").join("user-dirs.dirs"),
            "XDG_DOWNLOAD_DIR=\"$HOME/\"\n",
        )
        .unwrap();
        assert_eq!(downloads_dir_in(&home.0, None), None);
    }

    #[test]
    fn the_windows_known_folder_otherwise() {
        let home = Scratch::new("dl-win");
        let elsewhere = home.0.join("D").join("Downloads2");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let found = || Some(elsewhere.clone());
        assert_eq!(
            downloads_dir_in(&home.0, Some(&found)),
            Some(elsewhere.clone())
        );
        let none = || None;
        assert_eq!(downloads_dir_in(&home.0, Some(&none)), None);
        // And the known folder is never home itself.
        let home_itself = || Some(home.0.clone());
        assert_eq!(downloads_dir_in(&home.0, Some(&home_itself)), None);
    }

    #[test]
    fn none_when_there_is_no_downloads_directory() {
        let home = Scratch::new("dl-none");
        assert_eq!(downloads_dir_in(&home.0, None), None);
        // No home at all is not the working directory's `Downloads`.
        assert_eq!(downloads_dir_in(Path::new(""), None), None);
    }

    #[test]
    fn with_no_path_it_saves_to_downloads_and_with_none_it_asks_for_a_path() {
        let downloads = PathBuf::from("/somewhere/Downloads");
        assert_eq!(
            save_target(None, None, || Ok(downloads.clone())),
            Ok(SaveTarget::Dir {
                dir: downloads.clone(),
                as_name: None
            })
        );
        let err = save_target(None, None, || Err("no downloads directory found".into()));
        assert!(err.unwrap_err().contains("no downloads directory found"));
    }

    #[test]
    fn a_path_naming_a_file_is_held_to_the_same_rules_before_dialing() {
        let dir = Scratch::new("target");
        let never = || -> Result<PathBuf, String> { panic!("downloads consulted") };
        for name in ["CLAUDE.md", ".zshenv", "AUX.txt"] {
            let err = save_target(Some(dir.0.join(name)), None, never).unwrap_err();
            assert!(err.contains("give PATH another name"), "{name}: {err}");
        }
        assert_eq!(
            save_target(Some(dir.0.join("envrc.txt")), None, never),
            Ok(SaveTarget::File(dir.0.join("envrc.txt")))
        );
        assert_eq!(
            save_target(Some(dir.0.clone()), Some("mcp.json".into()), never),
            Ok(SaveTarget::Dir {
                dir: dir.0.clone(),
                as_name: Some("mcp.json".into())
            })
        );
        // --as names the file, so PATH must be a directory.
        let err = save_target(Some(dir.0.join("x.txt")), Some("y".into()), never).unwrap_err();
        assert!(err.contains("not a directory"), "{err}");
    }

    #[test]
    fn as_is_held_to_the_same_rules_before_dialing() {
        let dir = Scratch::new("as");
        for name in [".envrc", "CLAUDE.md", "nul", "x:y"] {
            let command = Command::Save {
                entry: "urn:layer:work:entry:1".into(),
                path: Some(dir.0.clone()),
                as_name: Some(name.into()),
                force: false,
            };
            let err = prepare(command).err().expect(name);
            assert!(err.contains("choose another --as NAME"), "{name}: {err}");
        }
        assert_eq!(
            args(&["save", "urn:layer:talk:entry:1", "--as", "mcp.json"]).unwrap(),
            Command::Save {
                entry: "urn:layer:talk:entry:1".into(),
                path: None,
                as_name: Some("mcp.json".into()),
                force: false
            }
        );
        assert!(args(&["save", "urn:layer:talk:entry:1", "--as"]).is_err());
    }

    #[test]
    fn a_file_a_reader_could_not_save_is_not_posted_and_says_how() {
        let dir = Scratch::new("post");
        let dotfile = dir.0.join(".gitignore");
        std::fs::write(&dotfile, "target/\n").unwrap();
        let post = |file_name: Option<&str>| {
            prepare(Command::Post {
                layer: "work".into(),
                kind: PostKind::File {
                    path: dotfile.clone(),
                    file_name: file_name.map(str::to_string),
                    media_type: None,
                },
                in_reply_to: None,
                supersedes: None,
            })
        };
        let err = post(None).err().expect("refused");
        assert!(
            err.contains("loads as configuration") && err.contains("--file-name NAME"),
            "{err}"
        );
        assert!(post(Some("gitignore.txt")).is_ok());
        let err = post(Some("CON")).err().expect("refused");
        assert!(err.contains("Windows device name"), "{err}");
    }

    #[test]
    fn a_media_type_is_guessed_or_checked() {
        assert_eq!(guess_media_type("brief.md", "text"), "text/markdown");
        assert_eq!(guess_media_type("a.png", "base64"), "image/png");
        assert_eq!(guess_media_type("noext", "text"), "text/plain");
        assert_eq!(
            guess_media_type("noext", "base64"),
            "application/octet-stream"
        );
        assert!(is_media_type("application/vnd.ikigai+json"));
        assert!(!is_media_type("text/plain; charset=utf-8"));
        assert!(!is_media_type("Text/Plain"));
    }

    /// The file entry round-trips through what `save` reads: the Turtle the door would hold,
    /// parsed, checked and decoded back to the same bytes, text and binary alike.
    #[test]
    fn a_file_entry_saves_back_to_its_own_bytes() {
        for (name, data) in [
            ("trace.log", b"line \"one\"\nline two\n".to_vec()),
            ("blob.bin", (0u8..=255).collect::<Vec<u8>>()),
        ] {
            let entry = file_entry(name, &data, None, Thread::default()).unwrap();
            let stored = entry
                .turtle
                .replace("<urn:layer:new>", "<urn:layer:talk:entry:01x>");
            let node = Node::of(&stored, "urn:layer:talk:entry:01x").unwrap();
            assert!(node.types.contains(&format!("{IK}File")));
            assert_eq!(node.one("fileName").unwrap(), name);
            assert_eq!(node.bytes().unwrap(), data);
        }
    }

    /// A file whose content does not match its own digest or size is refused, naming which.
    #[test]
    fn a_file_entry_that_lies_about_its_bytes_is_refused() {
        let good = file_entry("a.txt", b"hello\n", None, Thread::default())
            .unwrap()
            .turtle
            .replace("<urn:layer:new>", "<urn:layer:t:entry:1>");
        let wrong_hash = good.replace(&digest(b"hello\n"), &digest(b"other"));
        let err = Node::of(&wrong_hash, "urn:layer:t:entry:1")
            .unwrap()
            .bytes()
            .unwrap_err();
        assert!(err.contains("hashes to"), "{err}");
        let wrong_size = good.replace("ik:byteSize 6", "ik:byteSize 7");
        let err = Node::of(&wrong_size, "urn:layer:t:entry:1")
            .unwrap()
            .bytes()
            .unwrap_err();
        assert!(err.contains("it says 7"), "{err}");
    }

    /// A file's base64 decodes by the ecosystem's one profile (`ikigai_http::base64`, ledger
    /// #1857 and #1866): canonical RFC 4648 §4, so nonzero pad bits are refused, and the
    /// refusal names the rule without echoing a byte or an offset of the content.
    #[test]
    fn a_file_entry_whose_base64_is_not_canonical_is_refused_by_the_shared_profile() {
        let data = [0x89u8, 0, 0, 1];
        let (encoding, b64) = encode(&data);
        assert_eq!((encoding, b64.as_str()), ("base64", "iQAAAQ=="));
        let good = file_entry("a.bin", &data, None, Thread::default())
            .unwrap()
            .turtle
            .replace("<urn:layer:new>", "<urn:layer:t:entry:1>");
        // `R` differs from `Q` only in the low bits that padding leaves unused.
        let bad = good.replace("\"iQAAAQ==\"", "\"iQAAAR==\"");
        assert_ne!(bad, good, "the fixture names the content literal");
        let err = Node::of(&bad, "urn:layer:t:entry:1")
            .unwrap()
            .bytes()
            .unwrap_err();
        assert!(err.contains("not canonical base64"), "{err}");
        assert!(!err.contains("offset"), "{err}");
    }

    #[test]
    fn the_shapes_say_whether_a_layer_takes_files_and_how_large() {
        // As a shapes FILE writes it (blank nodes) and as the door serves it (named nodes).
        let file = "@prefix sh: <http://www.w3.org/ns/shacl#> . @prefix ik: <https://ikigai-rs.dev/ns#> .\n\
                    <urn:s:file> sh:targetClass ik:File ; sh:property \
                    [ sh:path ik:content ; sh:maxLength 520192 ] , [ sh:path ik:body ; sh:maxLength 9 ] .";
        assert_eq!(
            Shapes::parse(file).unwrap(),
            Shapes {
                takes_files: true,
                content_bound: Some(520192)
            }
        );
        let served = "@prefix sh: <http://www.w3.org/ns/shacl#> .\n\
                      <urn:layer:t:shapes:n45> sh:path <https://ikigai-rs.dev/ns#content> .\n\
                      <urn:layer:t:shapes:n45> sh:maxLength \"100\"^^<http://www.w3.org/2001/XMLSchema#integer> .";
        assert_eq!(
            Shapes::parse(served).unwrap(),
            Shapes {
                takes_files: false,
                content_bound: Some(100)
            }
        );
    }

    #[test]
    fn a_file_over_the_bound_is_refused_naming_what_fits() {
        let check = |content: &str| FileCheck {
            name: "x.txt".into(),
            size: content.len(),
            encoding: "text",
            content: content.into(),
        };
        assert!(too_large(&check("12345"), 5).is_none());
        // An escaped quote is two bytes in the literal.
        let why = too_large(&check("1234\""), 5).unwrap();
        assert!(
            why.contains("6 bytes as text") && why.contains("about 3 bytes of binary"),
            "{why}"
        );
    }

    #[test]
    fn names_and_entries_are_checked_before_anything_is_dialed() {
        assert!(layer_name("talk-chris").is_ok());
        for bad in ["", "Talk", "-x", "x-", "a_b", &"a".repeat(25)] {
            assert!(layer_name(bad).is_err(), "{bad:?}");
        }
        assert_eq!(entry_layer("urn:layer:talk:entry:01m4").unwrap(), "talk");
        for bad in [
            "urn:layer:talk:01m4",
            "urn:layer:Talk:entry:1",
            "urn:layer:talk:entry:",
            "urn:layer:talk:entry:a b",
            "urn:layer:talk:entry:a> <b",
        ] {
            assert!(entry_layer(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_command_line_parses_as_the_python_client_spells_it() {
        assert_eq!(
            args(&["post", "brief", "talk", "brief.md", "--repo", "o/n"]).unwrap(),
            Command::Post {
                layer: "talk".into(),
                kind: PostKind::Brief {
                    source: "brief.md".into(),
                    title: None,
                    repo: Some("o/n".into())
                },
                in_reply_to: None,
                supersedes: None,
            }
        );
        assert_eq!(
            args(&[
                "post",
                "issue",
                "talk",
                "--title",
                "T",
                "--severity",
                "major"
            ])
            .unwrap(),
            Command::Post {
                layer: "talk".into(),
                kind: PostKind::Issue {
                    source: "-".into(),
                    title: Some("T".into()),
                    repo: None,
                    severity: Some("major".into())
                },
                in_reply_to: None,
                supersedes: None,
            }
        );
        assert_eq!(
            args(&[
                "post",
                "file",
                "talk",
                "./a.png",
                "--in-reply-to",
                "urn:layer:talk:entry:1"
            ])
            .unwrap(),
            Command::Post {
                layer: "talk".into(),
                kind: PostKind::File {
                    path: "./a.png".into(),
                    file_name: None,
                    media_type: None
                },
                in_reply_to: Some("urn:layer:talk:entry:1".into()),
                supersedes: None,
            }
        );
        assert_eq!(
            args(&["save", "urn:layer:talk:entry:1", "out/", "--force"]).unwrap(),
            Command::Save {
                entry: "urn:layer:talk:entry:1".into(),
                path: Some("out/".into()),
                as_name: None,
                force: true
            }
        );
        // A flag that belongs to another kind, or to the connection, is refused by name.
        let err = args(&["post", "file", "talk", "a", "--severity", "major"]).unwrap_err();
        assert!(err.contains("--severity"), "{err}");
        let err = args(&["post", "brief", "talk", "--override", "x=y"]).unwrap_err();
        assert!(err.contains("connection flags go before `layers`"), "{err}");
        assert!(args(&["post", "file", "talk"]).is_err());
        assert!(args(&["post", "note", "talk"]).is_err());
        assert!(args(&[]).is_err());
    }
}
