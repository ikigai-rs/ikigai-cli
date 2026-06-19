//! Renderer-agnostic REPL engine.
//!
//! Parses a command line, issues it against the kernel, and reports the result.
//! It knows nothing about terminals or rendering — the plain line REPL, the
//! `ratatui` TUI, and a future `ratzilla` browser frontend all drive this same
//! engine and present the [`Action`] it returns however suits their medium.
//!
//! `source` is self-description-driven: rather than assuming an `in` argument, it
//! asks the target endpoint for its parameter contract (a `Meta` request rendered
//! as `application/json`) and routes by it — so an endpoint that reads a
//! differently-named argument, several arguments, or only a grammar binding is
//! handled correctly. A `key=value` word names a declared argument; the
//! positional text or piped value fills the one argument left unnamed. The
//! contract is fetched through `issue`, so this works the same against a remote
//! kernel.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use ikigai_core::{ArgRef, Capability, Description, InputSource, Iri, Request, Verb};
use ikigai_resolve::{CacheStatus, Resolver};

use crate::config;

/// Help text shown by the `help` command (and the TUI's hint line links to it).
pub const HELP: &str = "\
commands:
  source <iri> [input]       SOURCE a resource; `input` is routed to its declared argument
  source <iri> key=value …   name arguments; positional/pipe fills the one left unnamed
  source a [input] | b | c   pipeline: `|` pipes the whole output into the next stage
  source a [input] .. b      map: run `b` per newline-item of `a`'s output, rejoin
  source a | ( b ; c )       fork: fan the input to each branch, join their outputs
  describe <iri> [type]      META a resource; `type` defaults to text/turtle
  cache <iri> [args]         report whether resolving it would hit the cache (no resolve)
  cap [scope…]               show the session capability, narrow it to `scope`s, or `cap reset`
  config [key=value]         show settings, or save one (e.g. config keybindings=emacs)
  list                       list the resources bound in the current space
  help                       show this help
  quit                       exit

arguments:
  `key=value` sets an argument by name (`key` must be a declared argument of the
  target); any other word is positional and fills the one argument left unnamed.

quoting:
  wrap a word in \"…\" to keep `|`, `..`, `(`, `)`, `;`, or spaces literal inside an
  IRI or input; \\\" is a literal quote and \\\\ a literal backslash.

try:
  source urn:fn:toUpper resource-oriented computing
  source urn:demo:echo/hello
  source urn:demo:greet greeting=Hello name=World
  source urn:demo:greet Hello name=World
  source urn:fn:toUpper hello | urn:fn:toUpper
  source urn:fn:toUpper \"a | b\"
  source urn:demo:split \"a,b,c\" .. urn:fn:toUpper
  source urn:demo:split \"a,b,c\" | ( urn:fn:toUpper ; urn:fn:reverseList )
  describe urn:fn:toUpper text/turtle";

/// One evaluated request: the line the user typed, what came back, and how the
/// kernel's cache served it.
pub struct Entry {
    pub input: String,
    pub result: Result<String, String>,
    pub cache: CacheStats,
}

/// A tally of the cache outcomes across the (possibly many) requests one input
/// line issues — a pipeline stage, a fork branch, and a mapped item each count.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct CacheStats {
    hits: u32,
    misses: u32,
    uncacheable: u32,
}

impl CacheStats {
    fn record(&mut self, status: CacheStatus) {
        match status {
            CacheStatus::Hit => self.hits += 1,
            CacheStatus::Miss => self.misses += 1,
            CacheStatus::Uncacheable => self.uncacheable += 1,
        }
    }

    /// Fold another tally into this one — used to summarise a `-c` batch.
    pub fn merge(&mut self, other: CacheStats) {
        self.hits += other.hits;
        self.misses += other.misses;
        self.uncacheable += other.uncacheable;
    }

    /// A compact label for the outcome — `None` when nothing was issued (e.g.
    /// `list`, `help`, or a command that errored before resolving). A single
    /// request reads as one word; several stages summarise their mix.
    pub fn label(&self) -> Option<String> {
        match (self.hits, self.misses, self.uncacheable) {
            (0, 0, 0) => None,
            (1, 0, 0) => Some("cached".to_string()),
            (0, 1, 0) => Some("computed".to_string()),
            (0, 0, 1) => Some("uncacheable".to_string()),
            _ => {
                let mut parts = Vec::new();
                let mut push = |n: u32, what: &str| {
                    if n > 0 {
                        parts.push(format!("{n} {what}"));
                    }
                };
                push(self.hits, "cached");
                push(self.misses, "computed");
                push(self.uncacheable, "uncacheable");
                Some(parts.join(" · "))
            }
        }
    }
}

/// What the frontend should do with an evaluated line.
pub enum Action {
    /// Display this request/response.
    Output(Entry),
    /// Show [`HELP`].
    Help,
    /// Leave the REPL.
    Quit,
    /// Empty line — do nothing.
    Noop,
}

/// Holds the resolver (a local or remote kernel) and turns input lines into
/// [`Action`]s.
pub struct Engine {
    resolver: Box<dyn Resolver>,
    /// Cache outcomes recorded by [`run`](Self::run) during the current `eval`.
    /// Interior-mutable so the `&self` resolution path can tally without
    /// threading an accumulator through every stage; the REPL is single-threaded.
    cache: Cell<CacheStats>,
    /// The session's current authority — every request resolves under it. It
    /// starts at `identity` and the `cap` command can only ever *narrow* it.
    capability: RefCell<Capability>,
    /// The authority this session was opened with (the host's identity). `cap
    /// reset` returns here — the owner-only move; a holder of a narrowed
    /// capability has no identity to widen back to.
    identity: Capability,
    /// Named capability profiles a host registers (e.g. `freebusy` → a set of
    /// `urn:cap:` scopes), so `cap <name>` reads friendlier than a scope list.
    profiles: RefCell<HashMap<String, Vec<String>>>,
}

impl Engine {
    /// An engine that resolves with full (root) authority — the trusted,
    /// same-process default.
    pub fn new(resolver: impl Resolver + 'static) -> Self {
        Self::with_identity(resolver, Capability::root())
    }

    /// An engine whose session authority is derived from a caller's identity.
    /// The session starts at `identity`, and `cap reset` returns to it.
    pub fn with_identity(resolver: impl Resolver + 'static, identity: Capability) -> Self {
        Self {
            resolver: Box::new(resolver),
            cache: Cell::new(CacheStats::default()),
            capability: RefCell::new(identity.clone()),
            identity,
            profiles: RefCell::new(HashMap::new()),
        }
    }

    /// The session's current capability.
    pub fn capability(&self) -> Capability {
        self.capability.borrow().clone()
    }

    /// Register a named capability profile — `cap <name>` then attenuates to its
    /// scopes (e.g. `freebusy`). A host sets these so the REPL reads friendlier
    /// than a bare scope list.
    pub fn define_cap_profile(
        &self,
        name: impl Into<String>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) {
        self.profiles
            .borrow_mut()
            .insert(name.into(), scopes.into_iter().map(Into::into).collect());
    }

    /// Evaluate one input line.
    pub fn eval(&self, line: &str) -> Action {
        let line = line.trim();
        if line.is_empty() {
            return Action::Noop;
        }
        // Each `run` during this line accumulates into `self.cache`; reset it
        // first, then read it back into the entry once the command has resolved.
        self.cache.set(CacheStats::default());
        let (cmd, rest) = split_first_word(line);
        let output = |this: &Self, result| {
            Action::Output(Entry {
                input: line.to_string(),
                result,
                cache: this.cache.get(),
            })
        };
        match cmd {
            "quit" | "exit" => Action::Quit,
            "help" | "?" => Action::Help,
            "list" | "ls" => output(self, self.run_list()),
            "config" => output(self, run_config(rest)),
            "cache" => output(self, self.run_cache(rest)),
            "cap" => output(self, self.run_cap(rest)),
            "source" | "src" => output(self, self.run_pipeline(rest)),
            "describe" | "desc" => {
                let (target, ty) = split_first_word(rest);
                let ty = if ty.is_empty() { "text/turtle" } else { ty };
                output(self, self.run_meta(target, ty))
            }
            other => output(self, Err(format!("unknown command `{other}` (try `help`)"))),
        }
    }

    /// Parse and run a pipeline. Stages are joined by connectors — `|` passes the
    /// whole output into the next stage, `..` maps the next stage over the
    /// output's newline-separated items — and a stage may be a `( a | b ; c )`
    /// fork that fans the same input to each branch and joins their outputs.
    ///
    /// The spec is parsed by [`parse_spec`], which honours `"…"` quoting so a
    /// literal operator can appear inside an IRI or input. Every leaf is just a
    /// `source`, so routing, the binding-only error, and caching all come from
    /// [`run_source`](Self::run_source).
    fn run_pipeline(&self, spec: &str) -> Result<String, String> {
        let pipeline = parse_spec(spec)?;
        self.run_pipeline_node(&pipeline, None)
    }

    /// Run a parsed pipeline. `incoming` is the value flowing in from an enclosing
    /// connector or fork — `None` at the top level, where the first stage takes
    /// its literal input from the command line instead.
    fn run_pipeline_node(
        &self,
        pipeline: &Pipeline,
        incoming: Option<&str>,
    ) -> Result<String, String> {
        let mut value = self.run_node(&pipeline.first, incoming)?;
        for step in &pipeline.rest {
            value = match step.connector {
                Connector::Pipe => self.run_node(&step.node, Some(&value))?,
                Connector::Map => self.run_map(&step.node, &value)?,
            };
        }
        Ok(value)
    }

    /// Run one stage. A `Source` is a `source` request; a `Fork` fans `incoming`
    /// to every branch and joins their outputs with newlines (the same list
    /// convention `..` reads).
    fn run_node(&self, node: &Node, incoming: Option<&str>) -> Result<String, String> {
        match node {
            Node::Source(words) => {
                let (target, args) = words.split_first().ok_or("expected an IRI")?;
                self.run_source(target, args, incoming)
            }
            Node::Fork(branches) => {
                let outputs = branches
                    .iter()
                    .map(|branch| self.run_pipeline_node(branch, incoming))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(outputs.join("\n"))
            }
        }
    }

    /// Map a stage over the newline-separated items of `value`: run the node once
    /// per item (feeding the item in) and rejoin the outputs with newlines. This
    /// is the list convention used across the kernel (e.g. `reverseList`), so `..`
    /// threads a list through a per-item transform. An error on any item aborts.
    fn run_map(&self, node: &Node, value: &str) -> Result<String, String> {
        let outputs = value
            .split('\n')
            .map(|item| self.run_node(node, Some(item)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(outputs.join("\n"))
    }

    /// `SOURCE` a resource and return its representation as text.
    fn run_source(
        &self,
        target: &str,
        args: &[String],
        incoming: Option<&str>,
    ) -> Result<String, String> {
        let request = self.source_request(target, args, incoming)?;
        self.run(request)
    }

    /// Build the `Source` [`Request`] for a stage without issuing it — shared by
    /// `source` (which then runs it) and `cache` (which probes it). `args` are
    /// the stage's words after the IRI; a word `key=value` is a named argument
    /// when `key` is a declared argument of the target (discovered from its
    /// self-description), otherwise it is positional text. The positional text —
    /// or `incoming`, the value flowing in from a connector/fork — is routed to
    /// the one declared argument left unnamed.
    fn source_request(
        &self,
        target: &str,
        args: &[String],
        incoming: Option<&str>,
    ) -> Result<Request, String> {
        let iri = parse_target(target)?;

        // The contract is only needed to recognise named arguments and route the
        // value; a bare `source <iri>` (no args, no pipe) skips the lookup.
        let description = (!args.is_empty() || incoming.is_some())
            .then(|| self.describe_struct(&iri))
            .flatten();
        let declared = declared_arguments(description.as_ref());

        // Split args into named (`key=value` with a declared key) and positional.
        let mut named: Vec<(&str, &str)> = Vec::new();
        let mut positional: Vec<&str> = Vec::new();
        for arg in args {
            match arg.split_once('=') {
                Some((key, value)) if declared.iter().any(|name| name == key) => {
                    named.push((key, value))
                }
                _ => positional.push(arg),
            }
        }
        let positional = positional.join(" ");

        // The value to route comes from the pipe xor the positional text — never
        // both (a piped stage's input is the pipe, so a literal has nowhere else
        // to go).
        let value = match (incoming, positional.is_empty()) {
            (Some(_), false) => {
                return Err(format!(
                    "`{}` takes its input from the pipe — drop the literal input",
                    iri.as_str()
                ))
            }
            (Some(value), true) => Some(value),
            (None, false) => Some(positional.as_str()),
            (None, true) => None,
        };

        let mut request = Request::new(Verb::Source, iri.clone());
        for (name, value) in &named {
            request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
        }

        if let Some(value) = value {
            let value = ArgRef::Inline(value.as_bytes().to_vec());
            match description {
                // No contract: assume the conventional `in`, as before.
                None => request = request.with_arg("in", value),
                Some(ref description) => {
                    let remaining: Vec<&str> = declared
                        .iter()
                        .map(String::as_str)
                        .filter(|name| !named.iter().any(|(named, _)| named == name))
                        .collect();
                    match remaining.as_slice() {
                        [name] => request = request.with_arg(*name, value),
                        [] if description.inputs.is_empty() => {
                            request = request.with_arg("in", value)
                        }
                        [] if declared.is_empty() => {
                            return Err(format!(
                                "`{}` takes no by-value argument — its parameter is captured \
                                 from the identifier, so put the value in the IRI",
                                iri.as_str()
                            ))
                        }
                        [] => {
                            return Err(format!(
                                "`{}` has no argument left for the value — every declared \
                                 argument is already set by name",
                                iri.as_str()
                            ))
                        }
                        many => {
                            return Err(format!(
                                "`{}` accepts multiple arguments ({}); name one with `key=value`",
                                iri.as_str(),
                                many.join(", ")
                            ))
                        }
                    }
                }
            }
        }
        Ok(request)
    }

    /// Report whether resolving `spec` would be served from the cache, without
    /// resolving it. `spec` is a single `<iri> [key=value …] [input]` — the same
    /// surface as one `source` stage, but no pipelines (there's nothing to thread
    /// through). Read-only except that naming arguments fetches the target's
    /// contract (a `Meta`), which is itself cacheable.
    fn run_cache(&self, spec: &str) -> Result<String, String> {
        let pipeline = parse_spec(spec)?;
        let words = match pipeline {
            Pipeline {
                first: Node::Source(words),
                rest,
            } if rest.is_empty() => words,
            _ => {
                return Err("`cache` checks a single resource — no `|`, `..`, or `( )`".to_string())
            }
        };
        let (target, args) = words.split_first().ok_or("expected an IRI")?;
        let request = self.source_request(target, args, None)?;
        Ok(if self.resolver.is_cached(&request) {
            "cached".to_string()
        } else {
            "not cached".to_string()
        })
    }

    /// `cap` command: show, narrow, or reset the session capability.
    ///
    /// `cap` shows the current authority; `cap <scope>…` narrows it to the given
    /// `urn:cap:` scopes (intersected with what's already held — it can only ever
    /// shrink); `cap reset` returns to the session's identity. This is how the
    /// owner voluntarily gives up authority before handing work to an agent.
    fn run_cap(&self, rest: &str) -> Result<String, String> {
        let rest = rest.trim();
        if rest.is_empty() {
            return Ok(self.describe_capability());
        }
        if rest == "reset" {
            *self.capability.borrow_mut() = self.identity.clone();
            return Ok(format!("reset to identity — {}", self.describe_capability()));
        }
        // A registered profile name expands to its scopes; otherwise each word is
        // taken as a `urn:cap:` scope directly.
        let scopes: Vec<String> = match self.profiles.borrow().get(rest) {
            Some(scopes) => scopes.clone(),
            None => rest.split_whitespace().map(str::to_string).collect(),
        };
        let narrowed = self.capability.borrow().attenuate(scopes);
        *self.capability.borrow_mut() = narrowed;
        Ok(format!("narrowed — {}", self.describe_capability()))
    }

    /// A one-line summary of the session capability.
    fn describe_capability(&self) -> String {
        match self.capability.borrow().scopes() {
            None => "capability: root (full authority)".to_string(),
            Some(scopes) if scopes.is_empty() => {
                "capability: empty (no scopes granted)".to_string()
            }
            Some(scopes) => format!(
                "capability: {}",
                scopes.iter().cloned().collect::<Vec<_>>().join(", ")
            ),
        }
    }

    /// List the bindings of the kernel's root space (pattern → endpoint), or an
    /// error if the space doesn't support enumeration.
    fn run_list(&self) -> Result<String, String> {
        let entries = self
            .resolver
            .entries()
            .ok_or_else(|| "the current space does not support listing".to_string())?;
        if entries.is_empty() {
            return Ok("(no bindings)".to_string());
        }
        let width = entries
            .iter()
            .map(|entry| entry.pattern.chars().count())
            .max()
            .unwrap_or(0);
        let lines: Vec<String> = entries
            .iter()
            .map(|entry| format!("{:<width$}  → {}", entry.pattern, entry.endpoint))
            .collect();
        Ok(lines.join("\n"))
    }

    /// `META` a resource, rendered to `ty`.
    fn run_meta(&self, target: &str, ty: &str) -> Result<String, String> {
        let iri = parse_target(target)?;
        let request =
            Request::new(Verb::Meta, iri).with_arg("as", ArgRef::Inline(ty.as_bytes().to_vec()));
        self.run(request)
    }

    /// Fetch a target's structured self-description via a `Meta` request rendered
    /// as `application/json`. `None` if it doesn't resolve or isn't JSON-renderable.
    fn describe_struct(&self, iri: &Iri) -> Option<Description> {
        let request = Request::new(Verb::Meta, iri.clone())
            .with_arg("as", ArgRef::Inline(b"application/json".to_vec()));
        // The contract fetch is internal plumbing — its cache outcome isn't part
        // of the user-facing tally, so the status is discarded. It resolves under
        // the session capability, like any request.
        let capability = self.capability.borrow();
        let (representation, _) = self.resolver.issue_as(request, &capability).ok()?;
        serde_json::from_slice(&representation.bytes).ok()
    }

    /// Issue a request, record how the resolver's cache served it, and decode the
    /// representation as UTF-8 text. The resolver reports the [`CacheStatus`]
    /// directly — for a remote kernel the server knows it without a probe.
    fn run(&self, request: Request) -> Result<String, String> {
        let capability = self.capability.borrow();
        let (representation, status) = self.resolver.issue_as(request, &capability)?;
        let mut stats = self.cache.get();
        stats.record(status);
        self.cache.set(stats);
        String::from_utf8(representation.bytes).map_err(|e| e.to_string())
    }
}

/// `config` command: with no argument, show the config file and current
/// properties; with `<key>=<value>`, validate and persist the property.
fn run_config(rest: &str) -> Result<String, String> {
    let rest = rest.trim();
    if rest.is_empty() {
        return Ok(config_summary());
    }
    let (key, value) = parse_config_assignment(rest)?;
    let path = config::set(key, &value).map_err(|e| format!("could not save config: {e}"))?;
    let mut message = format!("{key} = {value}  (saved to {})", path.display());
    if key == "keybindings" && !config::keybindings_supported(&value) {
        message.push_str(&format!(
            "\nnote: `{value}` keybindings aren't implemented yet — emacs is used until they are"
        ));
    }
    Ok(message)
}

/// Show the config file path and the current value of each known property.
fn config_summary() -> String {
    let location = config::path().map_or_else(
        || "(no config directory — set $XDG_CONFIG_HOME or $HOME)".to_string(),
        |path| path.display().to_string(),
    );
    let keybindings = config::get("keybindings").unwrap_or_else(|| "emacs (default)".to_string());
    format!("config file: {location}\nkeybindings = {keybindings}")
}

/// Parse and validate a `config` assignment into a `(property, value)`. Pure —
/// the write happens in [`run_config`].
fn parse_config_assignment(rest: &str) -> Result<(&'static str, String), String> {
    let (key, value) = rest.split_once('=').ok_or_else(|| {
        "usage: `config <key>=<value>` (e.g. `config keybindings=emacs`), or `config` to show \
         current settings"
            .to_string()
    })?;
    let key = match key.trim() {
        "keybindings" => "keybindings",
        other => return Err(format!("unknown property `{other}` (known: keybindings)")),
    };
    let value = value.trim().trim_matches(['"', '\'']).trim();
    if value.is_empty() {
        return Err(format!("`{key}` needs a value, e.g. `config {key}=emacs`"));
    }
    Ok((key, value.to_string()))
}

/// The names of a target's declared by-value arguments, in declaration order.
/// Binding inputs (captured from the IRI) and an absent contract yield none.
fn declared_arguments(description: Option<&Description>) -> Vec<String> {
    description
        .map(|description| {
            description
                .inputs
                .iter()
                .filter(|input| input.source == InputSource::Argument)
                .map(|input| input.name.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// How a stage's output feeds the next stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Connector {
    /// `|` — pass the whole output as the next stage's input.
    Pipe,
    /// `..` — map the next stage over the output's newline-separated items.
    Map,
}

/// One stage of a pipeline.
#[derive(Debug, PartialEq, Eq)]
enum Node {
    /// A `source` leaf: the first word is the IRI, the rest the literal input.
    Source(Vec<String>),
    /// A `( … ; … )` fork: each branch is run on the same input, outputs joined.
    Fork(Vec<Pipeline>),
}

/// A non-first stage and the connector that feeds it from the previous stage.
#[derive(Debug, PartialEq, Eq)]
struct Step {
    connector: Connector,
    node: Node,
}

/// A pipeline: a first stage followed by connector-fed stages. A branch of a
/// fork is itself a `Pipeline`, so forks nest.
#[derive(Debug, PartialEq, Eq)]
struct Pipeline {
    first: Node,
    rest: Vec<Step>,
}

/// A lexical token. `Word` carries already-unquoted text.
#[derive(Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    Pipe,  // |
    Map,   // ..  (only as a whole, unquoted word)
    Open,  // (
    Close, // )
    Semi,  // ;
}

/// Tokenise a pipeline spec.
///
/// `|`, `(`, `)`, and `;` are operators that split even mid-word; `..` is an
/// operator only as a whole, unquoted word (a `..` inside a word like
/// `urn:x/../y` stays literal), since dots are common in IRIs while the others
/// are not. A `"…"` span keeps any of them — and whitespace — literal and is
/// removed from the resulting word (`"a | b"` is one `Word`); inside it `\"` is
/// a literal quote and `\\` a literal backslash, any other `\x` left as-is.
/// Quote a word to use any operator character, or a bare `..`, as literal data.
fn tokenize(spec: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut in_word = false; // started a word? distinguishes "" (a quoted empty) from no word
    let mut quoted = false; // did the current word include a quoted span? (then `..` is literal)
    let mut chars = spec.chars().peekable();

    // Finish the current word: a standalone unquoted `..` is the map operator,
    // anything else is a `Word`.
    let flush =
        |tokens: &mut Vec<Token>, word: &mut String, in_word: &mut bool, quoted: &mut bool| {
            if *in_word {
                if !*quoted && word == ".." {
                    tokens.push(Token::Map);
                    word.clear();
                } else {
                    tokens.push(Token::Word(std::mem::take(word)));
                }
                *in_word = false;
                *quoted = false;
            }
        };

    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_word = true;
                quoted = true;
                loop {
                    match chars.next() {
                        Some('\\') => match chars.next() {
                            Some(e @ ('"' | '\\')) => word.push(e),
                            Some(other) => {
                                word.push('\\');
                                word.push(other);
                            }
                            None => return Err("unterminated `\\` escape in quoted text".into()),
                        },
                        Some('"') => break,
                        Some(ch) => word.push(ch),
                        None => return Err("unterminated `\"` quote".into()),
                    }
                }
            }
            '|' | '(' | ')' | ';' => {
                flush(&mut tokens, &mut word, &mut in_word, &mut quoted);
                tokens.push(match c {
                    '|' => Token::Pipe,
                    '(' => Token::Open,
                    ')' => Token::Close,
                    _ => Token::Semi,
                });
            }
            c if c.is_whitespace() => flush(&mut tokens, &mut word, &mut in_word, &mut quoted),
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    flush(&mut tokens, &mut word, &mut in_word, &mut quoted);
    Ok(tokens)
}

/// Parse a whole spec into a [`Pipeline`], rejecting trailing `)`/`;` that no
/// `(` opened.
fn parse_spec(spec: &str) -> Result<Pipeline, String> {
    let mut parser = Parser {
        tokens: tokenize(spec)?,
        pos: 0,
    };
    let pipeline = parser.parse_pipeline()?;
    match parser.peek() {
        None => Ok(pipeline),
        Some(Token::Close) => Err("unmatched `)`".to_string()),
        Some(Token::Semi) => Err("`;` outside a `( … )` fork".to_string()),
        Some(_) => Err("trailing input after the pipeline".to_string()),
    }
}

/// Recursive-descent parser over a [`tokenize`]d spec.
///
/// Grammar: `pipeline := stage ((`|` | `..`) stage)*`, `stage := `(` pipeline
/// (`;` pipeline)* `)` | word+`. A fork branch is a full pipeline, so forks and
/// connectors nest.
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn parse_pipeline(&mut self) -> Result<Pipeline, String> {
        let first = self.parse_stage()?;
        let mut rest = Vec::new();
        while let Some(connector) = match self.peek() {
            Some(Token::Pipe) => Some(Connector::Pipe),
            Some(Token::Map) => Some(Connector::Map),
            _ => None,
        } {
            self.pos += 1;
            if self.at_stage_boundary() {
                return Err("empty pipeline stage (a stray connector?)".to_string());
            }
            rest.push(Step {
                connector,
                node: self.parse_stage()?,
            });
        }
        Ok(Pipeline { first, rest })
    }

    fn parse_stage(&mut self) -> Result<Node, String> {
        match self.peek() {
            Some(Token::Open) => {
                self.pos += 1;
                let mut branches = vec![self.parse_pipeline()?];
                while matches!(self.peek(), Some(Token::Semi)) {
                    self.pos += 1;
                    if self.at_stage_boundary() {
                        return Err("empty fork branch (a stray `;`?)".to_string());
                    }
                    branches.push(self.parse_pipeline()?);
                }
                match self.peek() {
                    Some(Token::Close) => {
                        self.pos += 1;
                        Ok(Node::Fork(branches))
                    }
                    _ => Err("unclosed `(` in a fork".to_string()),
                }
            }
            Some(Token::Word(_)) => {
                let mut words = Vec::new();
                while let Some(Token::Word(w)) = self.peek() {
                    words.push(w.clone());
                    self.pos += 1;
                }
                Ok(Node::Source(words))
            }
            Some(Token::Close) => Err("empty fork branch or group `()`".to_string()),
            _ => Err("expected an IRI".to_string()),
        }
    }

    /// True when the next token can't begin a stage (end, a connector, or a fork
    /// delimiter) — used to catch a connector or `;` with nothing after it.
    fn at_stage_boundary(&self) -> bool {
        matches!(
            self.peek(),
            None | Some(Token::Pipe | Token::Map | Token::Semi | Token::Close)
        )
    }
}

fn parse_target(target: &str) -> Result<Iri, String> {
    if target.is_empty() {
        return Err("expected an IRI".to_string());
    }
    Iri::parse(target).map_err(|e| e.to_string())
}

/// Split off the first whitespace-delimited token; trim the remainder.
fn split_first_word(s: &str) -> (&str, &str) {
    match s.split_once(char::is_whitespace) {
        Some((head, tail)) => (head, tail.trim()),
        None => (s, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use ikigai_core::{
        builtins, ArgSpec, EndpointSpace, Exact, FnEndpoint, Invocation, Kernel, MetaRenderer,
        ReprType, Representation, Rewrite, UriTemplate,
    };

    /// A minimal renderer that emits the description as JSON — what the embedded
    /// transport's renderer does, isolated here so engine tests don't depend on it.
    struct JsonRenderer;
    impl MetaRenderer for JsonRenderer {
        fn render(
            &self,
            description: &Description,
            _target: &ReprType,
        ) -> ikigai_core::Result<Representation> {
            Ok(Representation::new(
                ReprType::new("application/json"),
                serde_json::to_vec(description).expect("serialize description"),
            ))
        }
    }

    fn builtin_engine() -> Engine {
        let echo = UriTemplate::parse("urn:demo:echo/{message}").expect("valid template");
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:fn:toUpper"), builtins::to_upper())
            .bind(echo, builtins::echo());
        Engine::new(Kernel::with_meta_renderer(
            Arc::new(space),
            Arc::new(JsonRenderer),
        ))
    }

    fn output(action: Action) -> Result<String, String> {
        match action {
            Action::Output(entry) => entry.result,
            _ => panic!("expected Action::Output"),
        }
    }

    fn entry(action: Action) -> Entry {
        match action {
            Action::Output(entry) => entry,
            _ => panic!("expected Action::Output"),
        }
    }

    #[test]
    fn cache_reports_computed_then_cached() {
        let engine = builtin_engine();
        let first = entry(engine.eval("source urn:fn:toUpper hi"));
        assert_eq!(first.cache.label().as_deref(), Some("computed"));
        // Same request again: served from the cache without recomputing.
        let second = entry(engine.eval("source urn:fn:toUpper hi"));
        assert_eq!(second.cache.label().as_deref(), Some("cached"));
        // A different input is a fresh computation.
        let other = entry(engine.eval("source urn:fn:toUpper bye"));
        assert_eq!(other.cache.label().as_deref(), Some("computed"));
    }

    #[test]
    fn cap_attenuates_the_session_and_endpoints_observe_it() {
        // An endpoint that projects on the session capability — full detail vs a
        // minimized view, exactly like urn:personal:calendar.
        let cal = FnEndpoint::new("cal", |inv: &Invocation<'_>| {
            let body = if inv.capability.allows("urn:cap:demo:cal:read:detail") {
                "DETAIL"
            } else {
                "freebusy"
            };
            Ok(Representation::new(
                ReprType::new("text/plain"),
                body.as_bytes().to_vec(),
            ))
        });
        let space = EndpointSpace::new().bind(Exact::new("urn:demo:cal"), cal);
        let engine = Engine::with_identity(
            Kernel::with_meta_renderer(Arc::new(space), Arc::new(JsonRenderer)),
            Capability::root(),
        );
        // Identity (root) sees detail.
        assert_eq!(output(engine.eval("source urn:demo:cal")).unwrap(), "DETAIL");
        // Give it up: narrow to the free/busy scope only.
        engine.eval("cap urn:cap:demo:cal:read:freebusy");
        assert_eq!(output(engine.eval("source urn:demo:cal")).unwrap(), "freebusy");
        // You cannot widen back by asking for detail — attenuation only narrows.
        engine.eval("cap urn:cap:demo:cal:read:detail");
        assert_eq!(output(engine.eval("source urn:demo:cal")).unwrap(), "freebusy");
        // Reset returns to identity (root) — the owner-only move.
        engine.eval("cap reset");
        assert_eq!(output(engine.eval("source urn:demo:cal")).unwrap(), "DETAIL");
    }

    #[test]
    fn config_assignment_parses_the_property() {
        assert_eq!(
            parse_config_assignment("keybindings=emacs").unwrap(),
            ("keybindings", "emacs".to_string())
        );
        // Quotes and surrounding whitespace are trimmed.
        assert_eq!(
            parse_config_assignment("  keybindings = \"vi\" ").unwrap(),
            ("keybindings", "vi".to_string())
        );
    }

    #[test]
    fn config_assignment_rejects_bad_input() {
        assert!(parse_config_assignment("keybindings")
            .unwrap_err()
            .contains("usage"));
        // An unknown key — including the `keybinds` misspelling — is rejected.
        assert!(parse_config_assignment("keybinds=emacs")
            .unwrap_err()
            .contains("unknown property"));
        assert!(parse_config_assignment("theme=dark")
            .unwrap_err()
            .contains("unknown property"));
        assert!(parse_config_assignment("keybindings=")
            .unwrap_err()
            .contains("needs a value"));
    }

    #[test]
    fn cache_command_probes_without_resolving() {
        let engine = builtin_engine();
        // Not cached — and probing must not resolve/cache the target itself.
        assert_eq!(
            output(engine.eval("cache urn:fn:toUpper hi")).unwrap(),
            "not cached"
        );
        assert_eq!(
            output(engine.eval("cache urn:fn:toUpper hi")).unwrap(),
            "not cached"
        );
        // After resolving, the same request is a hit.
        output(engine.eval("source urn:fn:toUpper hi")).unwrap();
        assert_eq!(
            output(engine.eval("cache urn:fn:toUpper hi")).unwrap(),
            "cached"
        );
        // A different argument identity is still a miss.
        assert_eq!(
            output(engine.eval("cache urn:fn:toUpper bye")).unwrap(),
            "not cached"
        );
    }

    #[test]
    fn cache_command_rejects_a_pipeline() {
        let err =
            output(builtin_engine().eval("cache urn:fn:toUpper hi | urn:fn:toUpper")).unwrap_err();
        assert!(err.contains("single resource"), "got: {err}");
    }

    #[test]
    fn cache_command_carries_no_cache_tag() {
        // The probe is not a resolution, so it reports no cache outcome of its own.
        assert_eq!(
            entry(builtin_engine().eval("cache urn:fn:toUpper hi"))
                .cache
                .label(),
            None
        );
    }

    #[test]
    fn cache_reports_an_uncacheable_result() {
        // No `.cacheable()` → `Expiry::Always` → never cached, recomputes each time.
        let now = FnEndpoint::new("now", |_inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                b"tick".to_vec(),
            ))
        });
        let space = EndpointSpace::new().bind(Exact::new("urn:fn:now"), now);
        let engine = Engine::new(Kernel::with_meta_renderer(
            Arc::new(space),
            Arc::new(JsonRenderer),
        ));
        assert_eq!(
            entry(engine.eval("source urn:fn:now"))
                .cache
                .label()
                .as_deref(),
            Some("uncacheable")
        );
        assert_eq!(
            entry(engine.eval("source urn:fn:now"))
                .cache
                .label()
                .as_deref(),
            Some("uncacheable")
        );
    }

    #[test]
    fn cache_summarises_a_multi_stage_pipeline() {
        let engine = list_engine();
        let first = entry(engine.eval("source urn:fn:toUpper hi | urn:fn:reverseList"));
        assert_eq!(first.cache.label().as_deref(), Some("2 computed"));
        let second = entry(engine.eval("source urn:fn:toUpper hi | urn:fn:reverseList"));
        assert_eq!(second.cache.label().as_deref(), Some("2 cached"));
    }

    #[test]
    fn non_resolving_commands_have_no_cache_label() {
        let engine = builtin_engine();
        assert_eq!(entry(engine.eval("list")).cache.label(), None);
        assert_eq!(entry(engine.eval("frobnicate")).cache.label(), None);
    }

    #[test]
    fn cache_label_formats_single_and_mixed_outcomes() {
        let mut stats = CacheStats::default();
        assert_eq!(stats.label(), None);
        stats.record(CacheStatus::Hit);
        assert_eq!(stats.label().as_deref(), Some("cached"));
        stats.record(CacheStatus::Miss);
        stats.record(CacheStatus::Uncacheable);
        assert_eq!(
            stats.label().as_deref(),
            Some("1 cached · 1 computed · 1 uncacheable")
        );
    }

    #[test]
    fn sources_an_inline_arg() {
        assert_eq!(
            output(builtin_engine().eval("source urn:fn:toUpper hi")).unwrap(),
            "HI"
        );
    }

    #[test]
    fn pipeline_chains_output_into_the_next_stage() {
        // `wrap` returns "[input]"; piping toUpper into it proves the value flows
        // and is routed to wrap's argument.
        let wrap = FnEndpoint::new("wrap", |inv: &Invocation<'_>| {
            let s = inv.inline_str("in")?;
            Ok(
                Representation::new(ReprType::new("text/plain"), format!("[{s}]").into_bytes())
                    .cacheable(),
            )
        });
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:fn:toUpper"), builtins::to_upper())
            .bind(Exact::new("urn:test:wrap"), wrap);
        let engine = Engine::new(Kernel::with_meta_renderer(
            Arc::new(space),
            Arc::new(JsonRenderer),
        ));
        assert_eq!(
            output(engine.eval("source urn:fn:toUpper hi | urn:test:wrap")).unwrap(),
            "[HI]"
        );
    }

    #[test]
    fn quotes_keep_a_pipe_literal_in_the_input() {
        // Without quoting this would split into two stages; the quotes make
        // `a | b` a single literal input to toUpper.
        assert_eq!(
            output(builtin_engine().eval("source urn:fn:toUpper \"a | b\"")).unwrap(),
            "A | B"
        );
    }

    #[test]
    fn quoted_input_preserves_internal_spacing() {
        // Bare words rejoin with single spaces; a quoted word keeps its own.
        assert_eq!(
            output(builtin_engine().eval("source urn:fn:toUpper \"a   b\"")).unwrap(),
            "A   B"
        );
    }

    #[test]
    fn piped_stage_with_a_literal_input_is_an_error() {
        let err = output(builtin_engine().eval("source urn:fn:toUpper hi | urn:fn:toUpper x"))
            .unwrap_err();
        assert!(err.contains("from the pipe"), "got: {err}");
    }

    #[test]
    fn a_stray_pipe_is_an_error() {
        let err = output(builtin_engine().eval("source urn:fn:toUpper hi | | urn:fn:toUpper"))
            .unwrap_err();
        assert!(err.contains("empty pipeline stage"), "got: {err}");
    }

    /// Shorthand for an expected `Word` token.
    fn w(s: &str) -> Token {
        Token::Word(s.to_string())
    }

    #[test]
    fn tokenize_splits_and_unquotes() {
        // The quoted span holds a literal pipe and collapses to one word.
        assert_eq!(
            tokenize("urn:fn:toUpper \"a | b\" | urn:demo:wrap").unwrap(),
            vec![
                w("urn:fn:toUpper"),
                w("a | b"),
                Token::Pipe,
                w("urn:demo:wrap"),
            ]
        );
    }

    #[test]
    fn tokenize_processes_escapes() {
        assert_eq!(
            tokenize(r#"x "say \"hi\" \\ ok""#).unwrap(),
            vec![w("x"), w(r#"say "hi" \ ok"#)]
        );
    }

    #[test]
    fn tokenize_rejects_an_unterminated_quote() {
        assert!(tokenize("x \"unclosed").is_err());
    }

    #[test]
    fn tokenize_recognises_a_standalone_map_operator() {
        assert_eq!(
            tokenize("urn:demo:split a | b .. urn:fn:toUpper").unwrap(),
            vec![
                w("urn:demo:split"),
                w("a"),
                Token::Pipe,
                w("b"),
                Token::Map,
                w("urn:fn:toUpper"),
            ]
        );
    }

    #[test]
    fn tokenize_keeps_dotdot_literal_inside_a_word_or_quotes() {
        // `..` only tokenises as Map when it's a whole, unquoted word.
        assert_eq!(
            tokenize(r#"urn:x/../y ".." z"#).unwrap(),
            vec![w("urn:x/../y"), w(".."), w("z")]
        );
    }

    #[test]
    fn tokenize_splits_fork_punctuation_even_without_spaces() {
        // `(`, `)`, `;` split mid-word like `|`, so spacing inside a fork is optional.
        assert_eq!(
            tokenize("(a|b;c)").unwrap(),
            vec![
                Token::Open,
                w("a"),
                Token::Pipe,
                w("b"),
                Token::Semi,
                w("c"),
                Token::Close,
            ]
        );
    }

    #[test]
    fn parse_spec_builds_a_nested_fork() {
        // `a | ( b ; c .. d )` — a fork whose second branch is itself a map pipeline.
        let pipeline = parse_spec("a | ( b ; c .. d )").unwrap();
        assert_eq!(
            pipeline,
            Pipeline {
                first: Node::Source(vec!["a".into()]),
                rest: vec![Step {
                    connector: Connector::Pipe,
                    node: Node::Fork(vec![
                        Pipeline {
                            first: Node::Source(vec!["b".into()]),
                            rest: vec![],
                        },
                        Pipeline {
                            first: Node::Source(vec!["c".into()]),
                            rest: vec![Step {
                                connector: Connector::Map,
                                node: Node::Source(vec!["d".into()]),
                            }],
                        },
                    ]),
                }],
            }
        );
    }

    #[test]
    fn parse_spec_rejects_malformed_forks() {
        assert!(parse_spec("( a ; b").unwrap_err().contains("unclosed"));
        assert!(parse_spec("a )").unwrap_err().contains("unmatched `)`"));
        assert!(parse_spec("a ; b").unwrap_err().contains("outside"));
        assert!(parse_spec("( )").unwrap_err().contains("empty"));
        assert!(parse_spec("( a ; )").unwrap_err().contains("stray `;`"));
    }

    /// An engine over the list-y builtins: `reverseList` (newline list in/out)
    /// and `toUpper`, for exercising `..` map.
    fn list_engine() -> Engine {
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:fn:reverseList"), builtins::reverse_list())
            .bind(Exact::new("urn:fn:toUpper"), builtins::to_upper());
        Engine::new(Kernel::with_meta_renderer(
            Arc::new(space),
            Arc::new(JsonRenderer),
        ))
    }

    /// An engine with a two-argument `greet` endpoint (`greeting` + `name`),
    /// plus `toUpper`/`reverseList`, for exercising `name=value` routing.
    fn greet_engine() -> Engine {
        let greet = FnEndpoint::new("greet", |inv: &Invocation<'_>| {
            let greeting = inv.inline_str("greeting")?;
            let name = inv.inline_str("name")?;
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!("{greeting}, {name}").into_bytes(),
            )
            .cacheable())
        })
        .with_description(
            Description::new("greet")
                .verb(Verb::Source)
                .verb(Verb::Meta)
                .input(ArgSpec::new("greeting"))
                .input(ArgSpec::new("name"))
                .output("text/plain"),
        );
        let space = EndpointSpace::new()
            .bind(Exact::new("urn:demo:greet"), greet)
            .bind(Exact::new("urn:fn:toUpper"), builtins::to_upper())
            .bind(Exact::new("urn:fn:reverseList"), builtins::reverse_list());
        Engine::new(Kernel::with_meta_renderer(
            Arc::new(space),
            Arc::new(JsonRenderer),
        ))
    }

    #[test]
    fn names_both_arguments() {
        assert_eq!(
            output(greet_engine().eval("source urn:demo:greet greeting=Hello name=World")).unwrap(),
            "Hello, World"
        );
    }

    #[test]
    fn named_arguments_are_order_independent() {
        assert_eq!(
            output(greet_engine().eval("source urn:demo:greet name=World greeting=Hi")).unwrap(),
            "Hi, World"
        );
    }

    #[test]
    fn positional_fills_the_one_unnamed_argument() {
        // `name` is named; the positional `Hello` lands in the remaining `greeting`.
        assert_eq!(
            output(greet_engine().eval("source urn:demo:greet Hello name=World")).unwrap(),
            "Hello, World"
        );
    }

    #[test]
    fn a_pipe_fills_the_one_unnamed_argument() {
        // `greeting` is named; the piped value lands in the remaining `name`.
        assert_eq!(
            output(greet_engine().eval("source urn:fn:toUpper world | urn:demo:greet greeting=Hi"))
                .unwrap(),
            "Hi, WORLD"
        );
    }

    #[test]
    fn map_threads_items_through_a_fixed_named_argument() {
        // `greeting` is pinned; `..` feeds each list item into the remaining `name`.
        let out = output(
            greet_engine().eval("source urn:fn:reverseList \"a\nb\" .. urn:demo:greet greeting=Hi"),
        )
        .unwrap();
        assert_eq!(out, "Hi, b\nHi, a");
    }

    #[test]
    fn equals_in_a_value_is_positional_when_the_key_is_not_declared() {
        // `a` is not a declared argument of toUpper, so `a=b` is positional input.
        assert_eq!(
            output(greet_engine().eval("source urn:fn:toUpper a=b")).unwrap(),
            "A=B"
        );
    }

    #[test]
    fn an_undeclared_key_is_treated_as_positional_text() {
        // `bogus` isn't declared, so `bogus=x` is positional and fills `greeting`.
        assert_eq!(
            output(greet_engine().eval("source urn:demo:greet bogus=x name=World")).unwrap(),
            "bogus=x, World"
        );
    }

    #[test]
    fn a_positional_value_with_two_unnamed_arguments_is_ambiguous() {
        let err = output(greet_engine().eval("source urn:demo:greet Hello")).unwrap_err();
        assert!(err.contains("name one with `key=value`"), "got: {err}");
    }

    #[test]
    fn an_extra_value_when_all_arguments_are_named_errors() {
        let err = output(greet_engine().eval("source urn:demo:greet greeting=Hi name=W extra"))
            .unwrap_err();
        assert!(err.contains("no argument left"), "got: {err}");
    }

    #[test]
    fn map_applies_the_next_stage_per_item() {
        // reverseList flips the three lines; `..` then uppercases each independently.
        let out =
            output(list_engine().eval("source urn:fn:reverseList \"a\nb\nc\" .. urn:fn:toUpper"))
                .unwrap();
        assert_eq!(out, "C\nB\nA");
    }

    #[test]
    fn map_and_pipe_compose() {
        // Whole-value pipe into reverseList, then map toUpper over its items.
        let out = output(
            list_engine()
                .eval("source urn:fn:toUpper \"x\ny\" | urn:fn:reverseList .. urn:fn:toUpper"),
        )
        .unwrap();
        assert_eq!(out, "Y\nX");
    }

    #[test]
    fn map_passes_blank_items_through_as_empty_input() {
        // A blank line in the list (here the reversed middle of `a\n\nb`) must
        // reach the stage as an empty input, not be dropped into a no-argument
        // request that errors with "missing required argument".
        let out = output(list_engine().eval("source urn:fn:toUpper \"a\n\nb\" .. urn:fn:toUpper"))
            .unwrap();
        assert_eq!(out, "A\n\nB");
    }

    #[test]
    fn map_propagates_a_stage_error() {
        let out = output(list_engine().eval("source urn:fn:toUpper \"a\nb\" .. urn:fn:nope"));
        assert!(out.is_err());
    }

    #[test]
    fn map_stage_with_a_literal_input_is_an_error() {
        let err =
            output(list_engine().eval("source urn:fn:toUpper hi .. urn:fn:toUpper x")).unwrap_err();
        assert!(err.contains("from the pipe"), "got: {err}");
    }

    #[test]
    fn fork_fans_the_input_to_each_branch_and_joins() {
        // `X\nY` reaches both branches: reverseList flips it, toUpper passes it
        // through; outputs join with a newline.
        let out = output(
            list_engine()
                .eval("source urn:fn:toUpper \"x\ny\" | ( urn:fn:reverseList ; urn:fn:toUpper )"),
        )
        .unwrap();
        assert_eq!(out, "Y\nX\nX\nY");
    }

    #[test]
    fn fork_branches_can_be_multi_stage_pipelines() {
        // First branch is a two-stage pipeline; second is a single stage.
        let out = output(list_engine().eval(
            "source urn:fn:reverseList \"x\ny\nz\" | ( urn:fn:toUpper | urn:fn:reverseList ; urn:fn:toUpper )",
        ))
        .unwrap();
        assert_eq!(out, "X\nY\nZ\nZ\nY\nX");
    }

    #[test]
    fn fork_at_the_top_level_runs_each_branch_with_its_own_literal() {
        // No incoming value, so each branch's first stage takes its own literal.
        let out =
            output(list_engine().eval("source ( urn:fn:toUpper a ; urn:fn:toUpper b )")).unwrap();
        assert_eq!(out, "A\nB");
    }

    #[test]
    fn map_into_a_fork_fans_each_item() {
        // reverseList → `b\na`; `..` runs the fork per item, each fanned to both.
        let out = output(
            list_engine()
                .eval("source urn:fn:reverseList \"a\nb\" .. ( urn:fn:toUpper ; urn:fn:toUpper )"),
        )
        .unwrap();
        assert_eq!(out, "B\nB\nA\nA");
    }

    #[test]
    fn fork_propagates_a_branch_error() {
        let out =
            list_engine().eval("source urn:fn:toUpper \"a\nb\" | ( urn:fn:toUpper ; urn:fn:nope )");
        assert!(output(out).is_err());
    }

    #[test]
    fn piped_fork_branch_with_a_literal_input_is_an_error() {
        let err = output(
            list_engine().eval("source urn:fn:toUpper hi | ( urn:fn:toUpper x ; urn:fn:toUpper )"),
        )
        .unwrap_err();
        assert!(err.contains("from the pipe"), "got: {err}");
    }

    #[test]
    fn pipeline_propagates_a_stage_error() {
        assert!(output(builtin_engine().eval("source urn:fn:toUpper hi | urn:fn:nope")).is_err());
    }

    #[test]
    fn pipeline_into_binding_only_endpoint_errors() {
        let err = output(builtin_engine().eval("source urn:fn:toUpper hi | urn:demo:echo/x"))
            .unwrap_err();
        assert!(err.contains("identifier"), "got: {err}");
    }

    #[test]
    fn lists_the_bound_resources() {
        let listing = output(builtin_engine().eval("list")).unwrap();
        assert!(listing.contains("urn:fn:toUpper"));
        assert!(listing.contains("toUpper"));
        assert!(listing.contains("urn:demo:echo/{message}"));
        assert!(listing.contains("echo"));
    }

    #[test]
    fn list_on_a_non_enumerable_space_errors() {
        let inner = Arc::new(EndpointSpace::new().bind(Exact::new("urn:x"), builtins::to_upper()));
        let engine = Engine::new(Kernel::new(Arc::new(Rewrite::new(inner, |_iri| None))));
        assert!(output(engine.eval("list")).is_err());
    }

    #[test]
    fn resolves_a_template_binding() {
        assert_eq!(
            output(builtin_engine().eval("source urn:demo:echo/hello")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn passing_a_value_to_a_binding_endpoint_is_a_helpful_error() {
        let err = output(builtin_engine().eval("source urn:demo:echo/hi extra")).unwrap_err();
        assert!(err.contains("identifier"), "got: {err}");
    }

    #[test]
    fn routes_input_to_the_declared_argument_name() {
        // `shout` reads a `text` argument, not `in`. Contract-driven routing must
        // send the input there; a hardcoded `in` would make this fail.
        let shout = FnEndpoint::new("shout", |inv: &Invocation<'_>| {
            let text = inv.inline_str("text")?;
            Ok(Representation::new(
                ReprType::new("text/plain"),
                text.to_uppercase().into_bytes(),
            )
            .cacheable())
        })
        .with_description(
            Description::new("shout")
                .verb(Verb::Source)
                .verb(Verb::Meta)
                .input(ArgSpec::new("text").summary("the text to shout"))
                .output("text/plain"),
        );
        let space = EndpointSpace::new().bind(Exact::new("urn:fn:shout"), shout);
        let engine = Engine::new(Kernel::with_meta_renderer(
            Arc::new(space),
            Arc::new(JsonRenderer),
        ));
        assert_eq!(output(engine.eval("source urn:fn:shout hi")).unwrap(), "HI");
    }

    #[test]
    fn unknown_command_is_an_error() {
        assert!(output(builtin_engine().eval("frobnicate x")).is_err());
    }

    #[test]
    fn unresolved_iri_is_an_error() {
        assert!(output(builtin_engine().eval("source urn:fn:nope x")).is_err());
    }

    #[test]
    fn control_words_map_to_actions() {
        assert!(matches!(builtin_engine().eval("quit"), Action::Quit));
        assert!(matches!(builtin_engine().eval("help"), Action::Help));
        assert!(matches!(builtin_engine().eval("   "), Action::Noop));
    }

    #[test]
    fn declared_arguments_lists_only_by_value_inputs() {
        // Only `Argument`-source inputs, in declaration order — bindings excluded.
        let description = Description::new("x")
            .input(ArgSpec::new("greeting"))
            .input(ArgSpec::new("who").binding())
            .input(ArgSpec::new("name"));
        assert_eq!(
            declared_arguments(Some(&description)),
            vec!["greeting", "name"]
        );

        // A binding-only contract and an absent contract both yield no arguments.
        let binding = Description::new("echo").input(ArgSpec::new("message").binding());
        assert!(declared_arguments(Some(&binding)).is_empty());
        assert!(declared_arguments(None).is_empty());
    }
}
