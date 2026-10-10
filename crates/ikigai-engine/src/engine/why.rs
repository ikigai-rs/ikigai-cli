//! The REPL's "why" views (ledger #908): `explain`, `why`, `dependents` and `show`.
//!
//! **Every one is a thin view over a resource**, so none has logic of its own and each works
//! the same against a local kernel and over `--connect` (the resources are remote-transparent):
//!
//! | command | sources |
//! | --- | --- |
//! | `explain <iri> [verb] [scopes=…]` | `urn:kernel:explain`, and BESIDE it `urn:kernel:cached` |
//! | `why <iri>` | `urn:kernel:uncached` (one name's rows) and `urn:kernel:cached` |
//! | `dependents <thread>` | `urn:kernel:dependents thread=` |
//! | `show <iri> [args]` | the resource itself, when it answers `image/svg+xml` |
//!
//! ⚠ **The cached probe is composed beside the explanation, never joined into it.** The
//! explanation is cacheable (derived from the bindings); `urn:kernel:cached` is live. Asking
//! core to join the two would make the explanation the least cacheable thing it read — the
//! cacheability rule — so the face asks twice and prints both.
//!
//! The first audience is the MODULE AUTHOR asking "why did my endpoint not get called?", so the
//! answers are core's own words: the engine passes them through rather than re-rendering them,
//! which keeps one spelling of each fact (the REPL, MCP and gonk show the same text).

use std::sync::Arc;

use ikigai_core::{ArgRef, Request, Verb};

use super::{parse_spec, parse_target, take_as_of, Engine, Node, Pipeline};

/// Every command word the engine dispatches, in the order `help` lists them — the table a
/// completing face (the TUI, Emacs) reads, and the one a test holds against
/// [`HELP`](super::HELP) and the dispatcher so the three cannot drift. Aliases (`src`, `desc`, `del`,
/// `ls`, `cls`, `exit`, `?`) are not listed: a completion offers the word `help` teaches.
pub const COMMANDS: &[&str] = &[
    "source",
    "plan",
    "run",
    "sink",
    "delete",
    "exists",
    "describe",
    ":lisp",
    ":load",
    "cache",
    "cap",
    "login",
    "logout",
    "trace",
    "explain",
    "why",
    "dependents",
    "show",
    "config",
    "list",
    "demo",
    "history",
    "clear",
    "help",
    "quit",
];

/// The verbs `urn:kernel:explain` explains, as its `verb` argument spells them.
const VERBS: [&str; 5] = ["source", "sink", "exists", "delete", "meta"];

/// The one media type `show` draws. A resource answering anything else is refused by name,
/// never guessed at: a picture face is something the resource declares by answering it.
const SVG: &str = "image/svg+xml";

/// What a face does with a picture `show` fetched.
///
/// Supplied by the host because it is a fact about the MEDIUM: the terminal CLI writes the
/// bytes to a file and opens it with the platform opener; a browser frontend would draw it
/// inline. The engine stays renderer-agnostic and wasm-clean either way.
pub trait Viewer {
    /// Show `bytes` (of media type `media`, fetched from `target`) and return the line to print
    /// — the path written, at least, so a face with no opener still says where the picture is.
    fn show(&self, target: &str, media: &str, bytes: &[u8]) -> Result<String, String>;
}

impl Engine {
    /// Give `show` somewhere to put a picture. Without a viewer `show` is refused, naming the
    /// pipe that stores the bytes instead.
    pub fn with_viewer(mut self, viewer: Arc<dyn Viewer>) -> Self {
        self.viewer = Some(viewer);
        self
    }

    /// The one stage a view command takes, and the chain its `as-of=` (if any) names. A view
    /// explains ONE name, so pipes, maps and forks are refused rather than read as one.
    pub(super) fn single_stage(
        &self,
        spec: &str,
        command: &str,
    ) -> Result<(Vec<String>, ikigai_core::Scope), String> {
        if spec.trim().is_empty() {
            return Err(format!("usage: {}", usage(command)));
        }
        let mut pipeline = parse_spec(spec)?;
        let scope = self.as_of_scope(take_as_of(&mut pipeline)?.as_ref())?;
        match pipeline {
            Pipeline {
                first: Node::Source(words),
                rest,
            } if rest.is_empty() && !words.is_empty() => Ok((words, scope)),
            _ => Err(format!(
                "`{command}` looks at a single resource — no `|`, `..`, or `( )`"
            )),
        }
    }

    /// `explain <iri> [verb] [scopes=…] [as=text/turtle]`.
    pub(super) async fn run_explain(&self, spec: &str) -> Result<String, String> {
        let (words, scope) = self.single_stage(spec, "explain")?;
        self.in_scope(scope, self.explain_line(words)).await
    }

    async fn explain_line(&self, words: Vec<String>) -> Result<String, String> {
        let (target, rest) = words.split_first().ok_or_else(|| usage("explain"))?;
        let target = parse_target(target)?;
        let mut verb: Option<String> = None;
        let mut scopes: Vec<String> = Vec::new();
        let mut face: Option<String> = None;
        for word in rest {
            match word.split_once('=') {
                Some(("scopes", value)) => scopes.push(value.to_string()),
                Some(("as", value)) => face = Some(value.to_string()),
                Some(("verb", value)) => set_verb(&mut verb, value)?,
                None if VERBS.contains(&word.as_str()) => set_verb(&mut verb, word)?,
                _ => {
                    return Err(format!(
                        "`explain` does not take `{word}` — usage: {}",
                        usage("explain")
                    ))
                }
            }
        }
        let mut request = Request::new(Verb::Source, parse_target("urn:kernel:explain")?)
            .with_arg("target", inline(target.as_str()));
        if let Some(verb) = &verb {
            request = request.with_arg("verb", inline(verb));
        }
        if !scopes.is_empty() {
            request = request.with_arg("scopes", inline(&scopes.join(",")));
        }
        let turtle = face.as_deref().is_some_and(|f| f.trim() == "text/turtle");
        if let Some(face) = &face {
            request = request.with_arg("as", inline(face));
        }
        let explanation = self.run(request).await?;
        // The graph face is for a machine: one parseable document, no line appended to it.
        if turtle {
            return Ok(explanation);
        }
        let verb = verb.as_deref().unwrap_or("source");
        let cached = if matches!(verb, "source" | "exists") {
            let probe = self.cached_now(target.as_str(), verb).await?;
            if scopes.is_empty() {
                probe
            } else {
                // The probe asks for THIS session's capability; a cache entry is keyed by
                // capability, so the narrower one `scopes=` names has entries of its own.
                format!("{probe} (for this session's capability, not the `scopes=` one)")
            }
        } else {
            format!("n/a: only a source or exists read is cached, and this explains {verb}")
        };
        Ok(format!(
            "{}\n  cached now  {cached}   (urn:kernel:cached, live)",
            explanation.trim_end()
        ))
    }

    /// `why <iri>` — the uncached log's rows for one name, and whether it is cached now.
    pub(super) async fn run_why(&self, spec: &str) -> Result<String, String> {
        let (words, scope) = self.single_stage(spec, "why")?;
        self.in_scope(scope, self.why_line(words)).await
    }

    async fn why_line(&self, words: Vec<String>) -> Result<String, String> {
        let [target] = words.as_slice() else {
            return Err(format!(
                "`why` takes one IRI (a read with arguments is its own log row; \
                 `source urn:kernel:uncached` lists them all) — usage: {}",
                usage("why")
            ));
        };
        let target = parse_target(target)?;
        let log = self
            .run(Request::new(
                Verb::Source,
                parse_target("urn:kernel:uncached")?,
            ))
            .await?;
        let cached = self.cached_now(target.as_str(), "source").await?;
        let rows = uncached_rows(&log, target.as_str());
        let mut out = vec![
            format!("why {}", target.as_str()),
            format!("  cached now  {cached}   (urn:kernel:cached, live)"),
        ];
        if rows.is_empty() {
            out.push(
                "  uncached    not in the kernel's uncached log (its last 64 computations that were \
                 not stored): it has not been computed uncached here, or it aged out. `trace` \
                 reads it once; an aliased name is logged under the name `explain` says it \
                 resolves as"
                    .to_string(),
            );
        } else {
            for row in &rows {
                out.push(format!("  uncached    {row}"));
            }
            out.push(
                "  reasons     declared = the endpoint answered uncacheable; dependency | denied | \
                 failed <iri> = a sub-request made it volatile; upstream = a volatile piped \
                 input; no-clock | expired | cut-in-flight | policy = the store declined. \
                 [the chain it was computed in]"
                    .to_string(),
            );
        }
        Ok(out.join("\n"))
    }

    /// `dependents <thread> [as=text/turtle]` — `urn:kernel:dependents`, passed through.
    pub(super) async fn run_dependents(&self, spec: &str) -> Result<String, String> {
        let (words, scope) = self.single_stage(spec, "dependents")?;
        self.in_scope(scope, self.dependents_line(words)).await
    }

    async fn dependents_line(&self, words: Vec<String>) -> Result<String, String> {
        let (thread, rest) = words.split_first().ok_or_else(|| usage("dependents"))?;
        let thread = parse_target(thread)?;
        let mut request = Request::new(Verb::Source, parse_target("urn:kernel:dependents")?)
            .with_arg("thread", inline(thread.as_str()));
        for word in rest {
            match word.split_once('=') {
                Some(("as", face)) => request = request.with_arg("as", inline(face)),
                _ => {
                    return Err(format!(
                        "`dependents` does not take `{word}` — usage: {}",
                        usage("dependents")
                    ))
                }
            }
        }
        Ok(self.run(request).await?.trim_end().to_string())
    }

    /// `show <iri> [args]` — fetch a picture face and hand it to the host's viewer.
    pub(super) async fn run_show(&self, spec: &str) -> Result<String, String> {
        let (words, scope) = self.single_stage(spec, "show")?;
        self.in_scope(scope, self.show_line(words)).await
    }

    async fn show_line(&self, words: Vec<String>) -> Result<String, String> {
        let (target, args) = words.split_first().ok_or_else(|| usage("show"))?;
        // Refused BEFORE the read, so a face that cannot show a picture never computes one.
        let viewer = self.viewer.clone().ok_or_else(|| {
            format!(
                "this face cannot show a picture (it was given no viewer); \
                 `source {target} | sink <file IRI>` stores the SVG instead"
            )
        })?;
        let request = self.source_request(target, args, None).await?;
        let representation = self.run_repr(request, None).await?;
        let media = representation.repr_type.media_type.as_str();
        if !media.eq_ignore_ascii_case(SVG) {
            return Err(format!(
                "`{target}` answered {media}, not {SVG}: it has no picture face. \
                 `urn:diagram:kernel` and `urn:diagram:arrangement of=<iri>` draw one"
            ));
        }
        viewer.show(target, media, &representation.bytes)
    }

    /// `yes` / `no` from `urn:kernel:cached` — whether a read of `target` by this session would
    /// be served from the cache right now, in the line's chain.
    async fn cached_now(&self, target: &str, verb: &str) -> Result<String, String> {
        let answer = self
            .run(
                Request::new(Verb::Source, parse_target("urn:kernel:cached")?)
                    .with_arg("target", inline(target))
                    .with_arg("verb", inline(verb)),
            )
            .await?;
        Ok(match answer.trim() {
            "true" => "yes".to_string(),
            "false" => "no".to_string(),
            other => format!("unknown (urn:kernel:cached answered `{other}`)"),
        })
    }
}

/// A verb given twice (positionally and by name, or two different ones) is refused: the
/// explanation is of ONE request.
fn set_verb(slot: &mut Option<String>, value: &str) -> Result<(), String> {
    let value = value.trim().to_ascii_lowercase();
    if !VERBS.contains(&value.as_str()) {
        return Err(format!(
            "`{value}` is not a verb `explain` knows ({})",
            VERBS.join(", ")
        ));
    }
    match slot {
        Some(prior) if *prior != value => Err(format!(
            "an explanation is of one request, and this names two verbs: {prior} and {value}"
        )),
        _ => {
            *slot = Some(value);
            Ok(())
        }
    }
}

/// The rows of `urn:kernel:uncached`'s readout that name `target` — each the text after the
/// target: `×count  reason  [chain]`. The readout's grammar is core's (`UncachedLog::render`):
/// a header line, then `  <target>  ×<n>  <reason>  [<chain>]` per row, and an IRI never holds
/// a space, so the first word IS the target.
fn uncached_rows(log: &str, target: &str) -> Vec<String> {
    log.lines()
        .skip(1)
        .filter_map(|line| {
            let line = line.trim_start();
            let rest = line.strip_prefix(target)?;
            // The whole first word, not a prefix of it: `urn:x` must not claim `urn:x:y`'s rows.
            rest.starts_with(' ').then(|| rest.trim().to_string())
        })
        .collect()
}

fn inline(value: &str) -> ArgRef {
    ArgRef::Inline(value.as_bytes().to_vec())
}

fn usage(command: &str) -> String {
    match command {
        "explain" => {
            "`explain <iri> [source|sink|exists|delete|meta] [scopes=<scope,…>] [as=text/turtle]`"
        }
        "why" => "`why <iri>`",
        "dependents" => "`dependents <thread> [as=text/turtle]`",
        "show" => "`show <iri> [key=value …]`",
        "exists" => "`exists <iri> [key=value …]`",
        _ => "see `help`",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use ikigai_core::{
        ArgSpec, Capability, Description, EndpointSpace, Exact, FnEndpoint, Invocation, Kernel,
        MetaRenderer, ReprType, Representation, UriTemplate, Verb,
    };

    use super::{uncached_rows, Viewer, COMMANDS};
    use crate::engine::{Action, Engine, HELP};

    const SECRET: &str = "urn:cap:test:secret";
    const INSPECT: &str = "urn:cap:kernel:inspect";
    const AS_OF: &str = "as-of=2026-09-25T18:00Z";

    /// The JSON Meta face the engine routes named arguments by (`describe_struct`). Without it
    /// the engine fails OPEN and every routing defect is invisible (field guide).
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

    fn answer(media: &str, body: &str) -> Representation {
        Representation::new(ReprType::new(media), body.as_bytes().to_vec())
    }

    /// `stable` caches, `volatile` never does, `guarded` declares a scope, `greet:{name}`
    /// binds a variable, `pic` answers a picture and `drawing of=` routes an argument to one.
    fn space() -> EndpointSpace {
        EndpointSpace::new()
            .bind(
                Exact::new("urn:test:stable"),
                FnEndpoint::new("stable", |_: &Invocation<'_>| {
                    Ok(answer("text/plain", "stable").cacheable())
                }),
            )
            .bind(
                Exact::new("urn:test:volatile"),
                FnEndpoint::new("volatile", |_: &Invocation<'_>| {
                    Ok(answer("text/plain", "volatile"))
                }),
            )
            .bind(
                Exact::new("urn:test:guarded"),
                FnEndpoint::new("guarded", |_: &Invocation<'_>| {
                    Ok(answer("text/plain", "guarded"))
                })
                .with_description(
                    Description::new("guarded")
                        .verb(Verb::Source)
                        .requires(SECRET),
                ),
            )
            .bind(
                UriTemplate::parse("urn:test:greet:{name}").expect("template"),
                FnEndpoint::new("greeter", |_: &Invocation<'_>| {
                    Ok(answer("text/plain", "hello"))
                }),
            )
            .bind(
                Exact::new("urn:test:pic"),
                FnEndpoint::new("pic", |_: &Invocation<'_>| {
                    Ok(answer("image/svg+xml", "<svg role=\"img\"/>").cacheable())
                }),
            )
            .bind(
                Exact::new("urn:test:drawing"),
                FnEndpoint::new("drawing", |inv: &Invocation<'_>| {
                    let of = inv.inline_str("of").unwrap_or("nothing");
                    Ok(answer(
                        "image/svg+xml",
                        &format!("<svg><title>{of}</title></svg>"),
                    ))
                })
                .with_description(
                    Description::new("drawing")
                        .verb(Verb::Source)
                        .input(ArgSpec::new("of").summary("what to draw")),
                ),
            )
    }

    fn kernel() -> Kernel {
        Kernel::with_meta_renderer(Arc::new(space()), Arc::new(JsonRenderer))
    }

    fn engine() -> Engine {
        // The as-of doors bind `urn:test:stable` again, so an `as-of=` line puts a corridor
        // AHEAD of the root that answers the same name: the root's door is shadowed.
        Engine::new(kernel()).with_as_of_doors(Arc::new(EndpointSpace::new().bind(
            Exact::new("urn:test:stable"),
            FnEndpoint::new("corridor-stable", |_: &Invocation<'_>| {
                Ok(answer("text/plain", "then").cacheable())
            }),
        )))
    }

    fn out(action: Action) -> Result<String, String> {
        match action {
            Action::Output(entry) => entry.result,
            _ => panic!("expected output"),
        }
    }

    fn ok(engine: &Engine, line: &str) -> String {
        out(engine.eval(line)).unwrap_or_else(|e| panic!("`{line}` failed: {e}"))
    }

    fn err(engine: &Engine, line: &str) -> String {
        match out(engine.eval(line)) {
            Ok(text) => panic!("`{line}` should have failed, and answered:\n{text}"),
            Err(e) => e,
        }
    }

    /// The line of `text` that starts (after indentation) with `prefix`.
    fn line<'a>(text: &'a str, prefix: &str) -> &'a str {
        text.lines()
            .find(|l| l.trim_start().starts_with(prefix))
            .unwrap_or_else(|| panic!("no `{prefix}` line in:\n{text}"))
    }

    /// Prints every transcript the report quotes: `cargo test -p ikigai-engine transcripts --
    /// --nocapture`. It asserts only that each line answered, so it never pins core's wording;
    /// the tests below pin what the REPL adds.
    #[test]
    fn transcripts() {
        let engine = engine();
        for command in [
            "explain urn:test:greet:ada",
            "explain urn:test:nothing",
            "source urn:test:stable",
            "explain urn:test:stable",
            "explain urn:test:stable as-of=2026-09-25T18:00Z",
            "explain urn:test:guarded scopes=urn:cap:kernel:inspect",
            "source urn:test:volatile",
            "source urn:test:volatile",
            "why urn:test:volatile",
            "why urn:test:stable",
            "dependents urn:test:stable",
        ] {
            println!("ikigai> {command}\n{}\n", ok(&engine, command));
        }
    }

    #[test]
    fn explain_a_grammar_miss_says_nothing_answers_and_nothing_is_cached() {
        let text = ok(&engine(), "explain urn:test:nothing");
        assert!(
            text.starts_with("explain source urn:test:nothing"),
            "{text}"
        );
        assert!(line(&text, "verdict").contains("unresolved"), "{text}");
        assert_eq!(
            line(&text, "cached now"),
            "  cached now  no   (urn:kernel:cached, live)"
        );
    }

    #[test]
    fn explain_names_the_door_and_the_grammar_bindings() {
        let text = ok(&engine(), "explain urn:test:greet:ada");
        assert!(text.contains("greeter"), "the answering endpoint: {text}");
        assert!(
            text.contains("name") && text.contains("ada"),
            "the binding: {text}"
        );
    }

    /// ★ A corridor ahead of the root answers the same name, so the root's door is SHADOWED —
    /// the module author's "why was my endpoint not called?" in its commonest form.
    #[test]
    fn explain_names_a_shadowed_door() {
        let text = ok(&engine(), &format!("explain urn:test:stable {AS_OF}"));
        let shadowed = text
            .lines()
            .find(|l| l.contains("shadowed"))
            .unwrap_or_else(|| panic!("no shadowed member:\n{text}"));
        assert!(shadowed.contains("`stable`"), "{shadowed}");
        assert!(
            text.contains("urn:ctx:time:"),
            "the corridor is a chain member: {text}"
        );
    }

    /// A capability that may ask (inspect) but lacks the endpoint's scope: explain names the
    /// scope a real request would be Denied for, through `scopes=` and through the identity.
    #[test]
    fn explain_names_the_missing_scopes_of_a_capability_refusal() {
        let engine = engine();
        let text = ok(
            &engine,
            &format!("explain urn:test:guarded scopes={INSPECT}"),
        );
        assert!(text.contains(SECRET), "names the lacking scope: {text}");
        assert!(text.contains("attenuated"), "{text}");
        assert!(
            line(&text, "cached now").contains("not the `scopes=` one"),
            "says whose cache it probed: {text}"
        );

        let engine = Engine::with_identity(kernel(), Capability::scoped([INSPECT]));
        let text = ok(&engine, "explain urn:test:guarded");
        assert!(text.contains(SECRET), "{text}");
        // ...and the real read is refused for exactly that scope.
        assert!(err(&engine, "source urn:test:guarded").contains(SECRET));
    }

    #[test]
    fn explain_itself_needs_inspect_and_refuses_a_wider_scope() {
        let engine = Engine::with_identity(kernel(), Capability::scoped([SECRET]));
        let refused = err(&engine, "explain urn:test:guarded");
        assert!(refused.contains(INSPECT), "{refused}");

        let engine = Engine::with_identity(kernel(), Capability::scoped([INSPECT]));
        let refused = err(
            &engine,
            &format!("explain urn:test:guarded scopes={SECRET}"),
        );
        assert!(
            refused.contains(SECRET) && refused.contains("never"),
            "{refused}"
        );
    }

    /// The cached-vs-uncached pair, through both views: a cacheable read is cached after it is
    /// read; an uncacheable one is in the uncached log, counted, with core's reason.
    #[test]
    fn why_and_explain_tell_a_cached_read_from_an_uncached_one() {
        let engine = engine();
        let before = ok(&engine, "explain urn:test:stable");
        assert!(line(&before, "cached now").contains(" no "), "{before}");
        ok(&engine, "source urn:test:stable");
        let after = ok(&engine, "explain urn:test:stable");
        assert!(line(&after, "cached now").contains(" yes "), "{after}");
        let stable = ok(&engine, "why urn:test:stable");
        assert!(line(&stable, "cached now").contains(" yes "), "{stable}");
        assert!(line(&stable, "uncached").contains("not in the kernel's uncached log"));

        ok(&engine, "source urn:test:volatile");
        ok(&engine, "source urn:test:volatile");
        let volatile = ok(&engine, "why urn:test:volatile");
        assert!(line(&volatile, "cached now").contains(" no "), "{volatile}");
        let row = line(&volatile, "uncached");
        assert!(row.contains("×2") && row.contains("declared"), "{volatile}");
    }

    #[test]
    fn dependents_lists_what_a_cut_would_recompute() {
        let engine = engine();
        ok(&engine, "source urn:test:stable");
        let text = ok(&engine, "dependents urn:test:stable");
        assert!(text.contains("urn:test:stable"), "{text}");
        ok(&engine, "sink urn:kernel:cut urn:test:stable");
        let after = ok(&engine, "dependents urn:test:stable");
        assert_ne!(text, after, "a cut entry is no longer a dependent: {after}");
    }

    #[test]
    fn the_graph_faces_pass_through_unchanged() {
        let engine = engine();
        let turtle = ok(&engine, "explain urn:test:stable as=text/turtle");
        assert!(
            !turtle.contains("cached now"),
            "nothing appended to a document: {turtle}"
        );
        assert!(turtle.contains("@prefix"), "{turtle}");
        ok(&engine, "source urn:test:stable");
        let turtle = ok(&engine, "dependents urn:test:stable as=text/turtle");
        assert!(turtle.contains("urn:test:stable"), "{turtle}");
    }

    #[test]
    fn the_grammar_misses_of_the_views_are_refused_by_name() {
        let engine = engine();
        assert!(err(&engine, "explain").contains("usage"));
        assert!(err(&engine, "explain urn:test:stable | urn:test:volatile").contains("single"));
        assert!(err(&engine, "explain urn:test:stable bogus").contains("`bogus`"));
        assert!(err(&engine, "explain urn:test:stable source verb=sink").contains("two verbs"));
        assert!(err(&engine, "explain urn:test:stable verb=fly").contains("`fly`"));
        assert!(err(&engine, "why urn:test:stable extra").contains("one IRI"));
        assert!(err(&engine, "why").contains("usage"));
        assert!(err(&engine, "dependents urn:test:stable x=y").contains("`x=y`"));
    }

    #[derive(Default)]
    struct Recorder(Mutex<Vec<(String, String, Vec<u8>)>>);
    impl Viewer for Recorder {
        fn show(&self, target: &str, media: &str, bytes: &[u8]) -> Result<String, String> {
            self.0
                .lock()
                .unwrap()
                .push((target.to_string(), media.to_string(), bytes.to_vec()));
            Ok(format!("shown {target}"))
        }
    }

    #[test]
    fn show_hands_a_picture_to_the_viewer_and_refuses_anything_else() {
        let recorder = Arc::new(Recorder::default());
        let engine = Engine::new(kernel()).with_viewer(recorder.clone());
        assert_eq!(ok(&engine, "show urn:test:pic"), "shown urn:test:pic");
        // Named arguments route by the contract, as `source` routes them.
        ok(&engine, "show urn:test:drawing of=urn:kernel:topology");
        {
            let seen = recorder.0.lock().unwrap();
            assert_eq!(seen[0].1, "image/svg+xml");
            assert_eq!(seen[0].2, b"<svg role=\"img\"/>");
            assert!(String::from_utf8_lossy(&seen[1].2).contains("urn:kernel:topology"));
        }
        let refused = err(&engine, "show urn:test:stable");
        assert!(
            refused.contains("text/plain") && refused.contains("no picture face"),
            "{refused}"
        );
        assert_eq!(
            recorder.0.lock().unwrap().len(),
            2,
            "nothing shown for a refusal"
        );
    }

    #[test]
    fn show_without_a_viewer_is_refused_before_anything_is_read() {
        let engine = Engine::new(kernel());
        let refused = err(&engine, "show urn:test:pic");
        assert!(refused.contains("no viewer"), "{refused}");
        let explained = ok(&engine, "explain urn:test:pic");
        assert!(
            line(&explained, "cached now").contains(" no "),
            "the picture was never computed: {explained}"
        );
    }

    /// `help`, the dispatcher and [`COMMANDS`] cannot drift: every listed word is taught by
    /// `help` and is a command the engine knows.
    #[test]
    fn every_command_is_in_help_and_dispatched() {
        for command in COMMANDS {
            assert!(
                HELP.lines().any(|l| {
                    let l = l.trim_start();
                    l.starts_with(&format!("{command} "))
                        || l.starts_with(&format!("{command}\t"))
                        || l == *command
                        || l.contains(&format!("/ {command} "))
                }),
                "`{command}` is not taught by help"
            );
            if let Action::Output(entry) = engine().eval(command) {
                if let Err(e) = entry.result {
                    assert!(!e.starts_with("unknown command"), "`{command}`: {e}");
                }
            }
        }
    }

    #[test]
    fn a_row_is_claimed_by_its_whole_first_word() {
        let log = "uncached (why …)\n  urn:x      ×2  declared  [root]\n  urn:x:y    ×1  declared  [root]\n";
        assert_eq!(uncached_rows(log, "urn:x"), vec!["×2  declared  [root]"]);
        assert_eq!(uncached_rows(log, "urn:x:y"), vec!["×1  declared  [root]"]);
        assert!(uncached_rows(log, "urn:z").is_empty());
    }
}
