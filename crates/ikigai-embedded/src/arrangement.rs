//! **The local root as a declared arrangement** — spaces as data, the host half (ledger #637).
//!
//! Core 0.1.83 turns a declaration into a live space: `Topology::from_turtle` reads the same
//! `ik:` graph `urn:kernel:topology` writes, and `build(&Topology, &Registry)` rebuilds it
//! from endpoints the host registered by name. This module is what makes the HOST run one:
//!
//! | name | kind | here |
//! |---|---|---|
//! | the host's endpoints | value | `harvest`: a [`Registry`] recovered from the SAME constructor list the built-in root is composed from, so there is one list, not two |
//! | a declaration | resource | `--arrangement <path>` or `arrangement = "<path>"` in the config home, read THROUGH a bootstrap kernel as `text/turtle` ([`arm`]) |
//! | the built root | value | `arrange`: core's `build` over the harvested registry |
//! | the root as a declaration | resource | [`RESOURCE`] (`urn:iki:host:arrangement`): the arrangement the root was built from, as Turtle or (`as=text/x-ikigai-arrangement`) as an s-expression, ready to save, edit and start from |
//!
//! ## Why the registry is HARVESTED, not registered
//!
//! The endpoints are not constructed here one by one. Most arrive inside a module's own
//! space (`ikigai_rdf::space()`, `ikigai_llm::space(…)`), and a core `EndpointSpace` does not
//! hand out the endpoints it binds. A second, hand-kept list of every endpoint would drift from
//! those spaces the first time a module added a door, and nothing would notice until a
//! declaration naming the new door was refused. So the constructor list stays the one list:
//! the built-in root is composed from it exactly as before, and the registry is recovered from
//! it by walking each space's topology and resolving every door's own pattern against the space
//! that holds it (the probe core's catalog uses). A door whose probe lands on a different
//! endpoint (shadowed inside its own space) is reported, never guessed at.
//!
//! ## ⚠ A name is not an identity, and this host proves it
//!
//! A door binds by [`Endpoint::name`], and names are not unique.
//! Where one name is bound at several doors to the SAME endpoint, that is one registration.
//! Where it is bound to DIFFERENT endpoints, no registry can say which one a door means, so the
//! name is left out and a declaration that uses it is refused naming every door it is bound at
//! (`Harvest::ambiguous`). Nothing is renamed: a name is on the wire. The built-in root has
//! three such names on every machine — `file` (the org-file jail and the workspace jail, two
//! different roots), `meeting` and `org-agenda` (each module binds two clones of one endpoint)
//! — and every `llm-*` backend name once `llm.json` declares a second provider.
//!
//! ## What stays around the arrangement
//!
//! A declaration names the local kernel's ROOT arrangement and nothing else. The host still
//! layers, exactly as before: the alias table (`with_aliases`), the clock, the subclass axioms,
//! config-home mounts (composed after it), the demo runbook (gated by `urn:host:demo`, a
//! runtime switch no declaration can state), and [`RESOURCE`] itself. The served postures
//! (`serve quic://…`, `serve --http`, the calendar server) never read a declaration: they are
//! minimal by design, and a declaration must never widen one.
//!
//! ## Build at start, fail loud
//!
//! The declaration is read and parsed once, at start ([`arm`]); each local root is built from it.
//! A missing file, a parse error or a build refusal stops the start with core's message, which
//! names the node. There is no fallback to the built-in root: an operator who asked for a
//! declaration and got the default would have no way to know. Hot reload is ledger #628.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use ikigai_core::{
    build, ArgRef, ArgSpec, Bindings, DeclarationError, Description, Door, Endpoint, EndpointSpace,
    Error, Exact, Fallback, Invocation, Iri, Kernel, MatchKind, Registry, ReprType, Representation,
    Request, Resolution, Result, Scope, Space, SpaceKind, Topology, UriTemplate, Verb,
};

/// The config-home key: `arrangement = "<path>"` in `config.toml`, instance-scoped as
/// `<instance>.arrangement` (a REPL and the daemon read the same file and may want different
/// roots). A relative path is resolved against the config home; `~/` against `$HOME`.
pub const CONFIG_KEY: &str = "arrangement";

/// The flag: `--arrangement <path>`, relative to the working directory.
pub const FLAG: &str = "--arrangement";

/// The host resource that answers the running root's arrangement as a declaration.
pub const RESOURCE: &str = "urn:iki:host:arrangement";

/// The value each `{var}` takes when a template door is probed. Arbitrary, and unusual on
/// purpose: a probe that happened to spell an exact door bound earlier in the same space would
/// land there and read as a shadowed door.
pub(crate) const PROBE: &str = "ikigai-arrangement-probe";

/// Which channel named the declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArrangementSource {
    /// `--arrangement <path>`.
    Flag,
    /// `arrangement` (or `<instance>.arrangement`) in the config home.
    Config,
}

impl ArrangementSource {
    /// `flag` / `config`, as the dump's header says it.
    pub fn as_str(self) -> &'static str {
        match self {
            ArrangementSource::Flag => "flag",
            ArrangementSource::Config => "config",
        }
    }
}

/// A declaration this process runs its local root from: where it came from and the tree it
/// parsed to.
#[derive(Clone, Debug)]
pub struct Declared {
    /// The file, as resolved (absolute for the flag, config-home-relative for the key).
    pub path: PathBuf,
    /// The channel that named it.
    pub source: ArrangementSource,
    /// The arrangement, parsed.
    pub topology: Topology,
}

/// The `--arrangement` path, declared while argv is read (first write wins, like
/// [`set_instance_name`](crate::set_instance_name)).
static FLAG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// The declaration this process armed — `None` until [`arm`] found one. Every local root built
/// afterwards is built from it.
static ACTIVE: OnceLock<Declared> = OnceLock::new();

/// Declare `--arrangement <path>` for this process. A relative path is taken against the
/// working directory NOW, so a later `cd` cannot move it.
pub fn set_arrangement_path(path: impl Into<PathBuf>) {
    let path = path.into();
    let path = if path.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(&path))
            .unwrap_or(path)
    } else {
        path
    };
    let _ = FLAG_PATH.set(path);
}

/// The `--arrangement` path, if the flag was given — so a door that never reads a declaration
/// (a served posture, `--connect`) can refuse the flag instead of ignoring it.
pub fn arrangement_flag() -> Option<&'static Path> {
    FLAG_PATH.get().map(PathBuf::as_path)
}

/// The declaration this process runs its local root from, once [`arm`] found one.
pub fn active() -> Option<&'static Declared> {
    ACTIVE.get()
}

/// **Read and parse the declaration for this process's local root**, if one is named: the
/// flag wins over the config home (`<instance>.arrangement`, then `arrangement`). Call once at
/// start, before the first local kernel is built; the kernels built afterwards run from it.
///
/// `Ok(None)`: nothing names a declaration, and the built-in root is used — the one case where
/// that is not a fallback. `Err`: a declaration IS named and cannot be read or parsed; the
/// caller stops the start with this message. Idempotent: a second call answers the first.
pub fn arm() -> std::result::Result<Option<&'static Declared>, String> {
    if let Some(declared) = ACTIVE.get() {
        return Ok(Some(declared));
    }
    let Some((path, source)) = named() else {
        return Ok(None);
    };
    let turtle = read_declaration(&path).map_err(|e| {
        format!(
            "the declared arrangement `{}` cannot be read: {e}",
            path.display()
        )
    })?;
    let topology = Topology::from_turtle(&turtle)
        .map_err(|e| format!("the declared arrangement `{}`: {e}", path.display()))?;
    let _ = ACTIVE.set(Declared {
        path,
        source,
        topology,
    });
    Ok(ACTIVE.get())
}

/// The declaration's path and the channel that named it: the flag, else the config home.
fn named() -> Option<(PathBuf, ArrangementSource)> {
    if let Some(path) = FLAG_PATH.get() {
        return Some((path.clone(), ArrangementSource::Flag));
    }
    let value = crate::config::get(&format!("{}.{CONFIG_KEY}", crate::instance_name()))
        .or_else(|| crate::config::get(CONFIG_KEY))?;
    Some((config_relative(&value), ArrangementSource::Config))
}

/// A config-home path value: `~/` against `$HOME`, a relative path against the config home.
fn config_relative(value: &str) -> PathBuf {
    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    let path = PathBuf::from(value);
    match crate::config::config_home() {
        Some(home) if path.is_relative() => home.join(path),
        _ => path,
    }
}

/// **Read a declaration THROUGH a kernel, as `text/turtle`.** A bootstrap kernel binds the
/// file's directory as `urn:file:{path}` beside the host's transreptors (RDF, JSON-LD,
/// s-expressions), so a declaration in another surface reaches core as Turtle by transreption
/// and this host changes nothing when a surface is added. Lossless plans only: a surface that
/// cannot carry the arrangement must say so, not drop part of it.
///
/// `ikigai-fs` decides the file's media type by extension: `.ttl`, `.nt`, `.jsonld`, and since
/// 0.1.7 `.arrangement` (`text/x-ikigai-arrangement`), which ikigai-sexpr 0.1.4's
/// `urn:sexpr:arrangement-to-rdf` transrepts to Turtle losslessly. That transreptor bounds
/// the tree before core reads it, and core bounds every declaration again as it reads it:
/// since 0.1.84 `Topology::from_turtle` refuses one past `MAX_DECLARATION_DEPTH`,
/// `MAX_DECLARATION_NODES` or `MAX_DECLARATION_TEXT` as `DeclarationError::TooLarge`, naming the
/// bound (ledger #643, and `docs/declared-arrangement.md`).
pub(crate) fn read_declaration(path: &Path) -> std::result::Result<String, String> {
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "the path names no file".to_string())?;
    let name = Iri::parse(format!("urn:file:{file}"))
        .map_err(|e| format!("the file name is not IRI-safe: {e}"))?;
    let root: Arc<dyn Space> = Arc::new(Fallback::new(vec![
        Arc::new(EndpointSpace::new().bind(
            UriTemplate::parse(ikigai_fs::FILE_TEMPLATE).expect("FILE_TEMPLATE is valid"),
            ikigai_fs::FileEndpoint::new(dir),
        )) as Arc<dyn Space>,
        Arc::new(ikigai_rdf::space()) as Arc<dyn Space>,
        Arc::new(ikigai_jsonld::space()) as Arc<dyn Space>,
        Arc::new(ikigai_sexpr::space()) as Arc<dyn Space>,
    ]));
    // The host's synchronous issuer (the one the REPL and the reactor drive), under root: the
    // host reading its own configuration.
    let kernel = Kernel::new(Arc::clone(&root));
    let issue = |request: Request| {
        ikigai_resolve::Resolver::issue(&kernel, request)
            .map(|(representation, _)| representation)
            .map_err(|e| e.to_string())
    };
    let read = issue(Request::new(Verb::Source, name))?;
    const TURTLE: &str = "text/turtle";
    let mut current = read;
    if current.repr_type.media_type != TURTLE {
        let from = current.repr_type.media_type.clone();
        let plan =
            ikigai_core::select_transreptor(root.as_ref(), &from, TURTLE).ok_or_else(|| {
                format!("it is `{from}`, and nothing here transrepts that to {TURTLE} losslessly")
            })?;
        for step in plan {
            let iri = Iri::parse(&step.endpoint).map_err(|e| e.to_string())?;
            let endpoint = step.endpoint.clone();
            let request = Request::new(Verb::Source, iri)
                .with_arg("content", ArgRef::Inline(current.bytes))
                .with_arg("as", ArgRef::Inline(step.to.into_bytes()));
            // The transreptor's refusal is the operator's answer — for an `.arrangement` file it
            // is ikigai-sexpr's, and it says where (`at root (endpoints) › door 1: …`) — so it
            // is passed through whole, after naming what refused.
            current = issue(request)
                .map_err(|e| format!("it is `{from}`, and <{endpoint}> refused it: {e}"))?;
        }
    }
    String::from_utf8(current.bytes).map_err(|_| format!("the {TURTLE} is not UTF-8"))
}

/// The registry recovered from a constructor list, and what could not go in it.
pub(crate) struct Harvest {
    /// Every endpoint bound under a name no other endpoint shares.
    pub registry: Registry,
    /// Names bound to two or more DIFFERENT endpoints, each with the patterns of the doors
    /// that bind it, in arrangement order. Left out of the registry: a door names one endpoint
    /// by name, and these names cannot say which.
    pub ambiguous: BTreeMap<String, Vec<String>>,
    /// Doors whose endpoint could not be recovered by resolving the door's own pattern in the
    /// space that holds it (shadowed there, or a pattern core cannot rebuild), as
    /// `(pattern, name)`.
    pub unreached: Vec<(String, String)>,
}

/// One door's pattern and the endpoint its probe found.
type Bound = (String, Arc<dyn Endpoint>);

/// **Recover the host's endpoints from the spaces it composes** — see the module note for why
/// this is a walk and not a list. Each member's topology names its doors; each door's pattern
/// (a template expanded with a probe value) is resolved in that member, and the endpoint that
/// answers is kept if it carries the door's name.
pub(crate) fn harvest(members: &[Arc<dyn Space>]) -> Harvest {
    let mut found: BTreeMap<String, Vec<Bound>> = BTreeMap::new();
    let mut unreached = Vec::new();
    for member in members {
        let mut doors = Vec::new();
        collect_doors(&member.topology(), &mut doors);
        for door in doors {
            match probe(member.as_ref(), &door) {
                Some(endpoint) => found
                    .entry(door.endpoint.clone())
                    .or_default()
                    .push((door.pattern.clone(), endpoint)),
                None => unreached.push((door.pattern.clone(), door.endpoint.clone())),
            }
        }
    }
    let mut registry = Registry::new();
    let mut ambiguous = BTreeMap::new();
    for (name, bound) in found {
        let first = Arc::clone(&bound[0].1);
        if bound
            .iter()
            .all(|(_, endpoint)| Arc::ptr_eq(endpoint, &first))
        {
            // One endpoint under its own name, however many doors bind it: `register` cannot
            // refuse it.
            let _ = registry.register(first);
        } else {
            ambiguous.insert(
                name,
                bound.into_iter().map(|(pattern, _)| pattern).collect(),
            );
        }
    }
    Harvest {
        registry,
        ambiguous,
        unreached,
    }
}

/// Every door in `node`'s tree, in pre-order.
fn collect_doors(node: &Topology, doors: &mut Vec<Door>) {
    if let SpaceKind::EndpointSpace { doors: here } = &node.kind {
        doors.extend(here.iter().cloned());
    }
    for child in &node.children {
        collect_doors(child, doors);
    }
}

/// The endpoint `door` binds, found by resolving its own pattern in `space` — `None` when the
/// probe lands on a differently named endpoint, misses, or the door is one core cannot rebuild
/// anyway. A confined door answers `None` too: its probe finds the confinement wrapper, and
/// registering that would wrap it twice when a declaration re-confines it.
fn probe(space: &dyn Space, door: &Door) -> Option<Arc<dyn Endpoint>> {
    if door.confined.is_some() {
        return None;
    }
    let name = match door.kind {
        MatchKind::Exact => door.pattern.clone(),
        MatchKind::Template => {
            let template = UriTemplate::parse(&door.pattern).ok()?;
            let mut bindings = Bindings::new();
            for var in template.variables() {
                bindings.insert(var, PROBE);
            }
            template.expand(&bindings)?
        }
        _ => return None,
    };
    let request = Request::new(Verb::Meta, Iri::parse(name).ok()?);
    match space.resolve(&request, &Scope::empty()) {
        Resolution::Hit(resolved) if resolved.endpoint.name() == door.endpoint => {
            Some(resolved.endpoint)
        }
        _ => None,
    }
}

/// **Build a declared arrangement** over the harvested registry. Core's refusal, which names
/// the node, is kept; a door that binds an ambiguous or unrecovered name gets the host's reason
/// instead of core's "not registered", which would be true and useless.
pub(crate) fn arrange(
    harvest: &Harvest,
    declaration: &Topology,
) -> std::result::Result<Arc<dyn Space>, String> {
    build(declaration, &harvest.registry).map_err(|e| explain(&e, harvest))
}

/// The message for a refusal: the host's when it knows more than core, else core's own.
fn explain(error: &DeclarationError, harvest: &Harvest) -> String {
    if let DeclarationError::UnknownEndpoint { door, id, .. } = error {
        if let Some(patterns) = harvest.ambiguous.get(id) {
            return format!(
                "<{door}> binds `{id}`, which names {} different endpoints in this host (bound \
                 at {}): a door binds by name, so the name cannot say which one. Declare the \
                 arrangement without it; the fix is for each endpoint to carry its own name",
                patterns.len(),
                quoted(patterns)
            );
        }
        let at: Vec<String> = harvest
            .unreached
            .iter()
            .filter(|(_, name)| name == id)
            .map(|(pattern, _)| pattern.clone())
            .collect();
        if !at.is_empty() {
            return format!(
                "<{door}> binds `{id}`, which this host binds (at {}) but could not recover from \
                 its own arrangement: that door's pattern resolves to another endpoint in its \
                 space, or is a kind core cannot rebuild",
                quoted(&at)
            );
        }
    }
    error.to_string()
}

/// `` `a`, `b` `` — patterns as a message lists them.
fn quoted(patterns: &[String]) -> String {
    patterns
        .iter()
        .map(|pattern| format!("`{pattern}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The media type of an arrangement written as an s-expression (an `*.arrangement` file), and
/// the second face [`RESOURCE`] answers.
pub const MEDIA_ARRANGEMENT: &str = ikigai_sexpr::arrangement::MEDIA_ARRANGEMENT;

/// The media type [`RESOURCE`] answers by default, and the one core's `Topology` reads.
const MEDIA_TURTLE: &str = "text/turtle";

/// The arrangement as [`RESOURCE`] answers it: the tree, and a header saying where it came
/// from, what the host layers around it, and — when it binds an ambiguous name — that it cannot
/// be declared back as it stands. The header is written as COMMENTS in either face (`#` in
/// Turtle, `;` in an s-expression): comments are not part of the arrangement, so the document
/// still reads back.
pub(crate) struct Dump {
    header: Vec<String>,
    topology: Topology,
}

impl Dump {
    /// The Turtle face: the header as `#` comments, then core's rendering. `Err` for a tree in
    /// which two DIFFERENT spaces claim one name: core's `to_turtle` renders a named node once,
    /// so it would write the first alone and the document would read back as another
    /// arrangement. `try_to_turtle` (core 0.1.84) refuses it with `build`'s own reason, which
    /// names the node — the same refusal `urn:kernel:topology` answers as a `Conflict`.
    pub(crate) fn turtle(&self) -> std::result::Result<String, String> {
        self.topology
            .try_to_turtle()
            .map(|body| self.with_header("#", &body))
            .map_err(|e| e.to_string())
    }

    /// The s-expression face (`text/x-ikigai-arrangement`): the header as `;` comments, then
    /// `ikigai-sexpr`'s canonical printing of the same tree. `Err` when the tree is one the
    /// s-expression grammar refuses (a kind core cannot build, or past its bounds), with
    /// ikigai-sexpr's reason, which says where.
    pub(crate) fn sexpr(&self) -> std::result::Result<String, String> {
        ikigai_sexpr::topology_to_arrangement(&self.topology)
            .map(|body| self.with_header(";;", &body))
            .map_err(|e| e.to_string())
    }

    fn with_header(&self, comment: &str, body: &str) -> String {
        let mut out = String::new();
        for line in &self.header {
            out.push_str(comment);
            out.push(' ');
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
        out.push_str(body);
        out
    }
}

/// The arrangement as [`RESOURCE`] answers it (see [`Dump`]).
pub(crate) fn dump(arrangement: &Topology, origin: &str, harvest: &Harvest) -> Dump {
    let mut header = vec![
        format!("The arrangement this host built its local root from: {origin}."),
        format!("Save it, edit it, and start from it: `ikigai {FLAG} <file>`, or"),
        format!("`{CONFIG_KEY} = \"<file>\"` in the config home's config.toml."),
        "Layered around it, and not part of it: the alias table, config-home mounts, the demo"
            .to_string(),
        format!("runbook (gated by urn:host:demo) and {RESOURCE} itself."),
    ];
    let mut used = Vec::new();
    collect_doors(arrangement, &mut used);
    let mut warned = std::collections::BTreeSet::new();
    for door in &used {
        if let Some(patterns) = harvest.ambiguous.get(&door.endpoint) {
            if warned.insert(door.endpoint.clone()) {
                header.push(format!(
                    "⚠ Not declarable as it stands: `{}` names {} different endpoints here ({}).",
                    door.endpoint,
                    patterns.len(),
                    quoted(patterns)
                ));
            }
        }
    }
    Dump {
        header,
        topology: arrangement.clone(),
    }
}

/// `urn:iki:host:arrangement` — the root's arrangement as a declaration (see [`Dump`]), as
/// Turtle by default and as an s-expression with `as=text/x-ikigai-arrangement`.
///
/// ★ The s-expression face is answered HERE, not by the kernel transrepting on `as`: core
/// transrepts on `as` for Meta only, and a Source endpoint serves its own faces. Nor does it
/// compose `urn:sexpr:arrangement-from-rdf` over the Turtle: that transreptor is bound in the
/// built-in root, and a DECLARED root need not bind it, so the face would work or fail by what
/// the operator happened to declare. The library call is the same code with no such dependency.
///
/// Both faces are computed from a tree fixed when the root is built (no hot reload, ledger
/// #628), so both are cacheable.
pub(crate) struct ArrangementEndpoint {
    dump: Dump,
}

impl ArrangementEndpoint {
    pub(crate) fn new(dump: Dump) -> Self {
        ArrangementEndpoint { dump }
    }
}

#[async_trait::async_trait]
impl Endpoint for ArrangementEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let face = match inv.request.args.get("as") {
            None => MEDIA_TURTLE.to_string(),
            Some(_) => inv.inline_str("as")?.trim().to_string(),
        };
        let bytes = match face.as_str() {
            MEDIA_TURTLE => self.dump.turtle().map_err(|detail| {
                Error::Conflict(format!(
                    "this host's arrangement cannot be written as a declaration: {detail}"
                ))
            })?,
            MEDIA_ARRANGEMENT => self.dump.sexpr().map_err(|detail| {
                Error::Endpoint(format!(
                    "this host's arrangement cannot be written as {MEDIA_ARRANGEMENT}: {detail}"
                ))
            })?,
            other => {
                return Err(Error::InvalidArgument {
                    name: "as".to_string(),
                    detail: format!(
                        "`{other}` is not a face of {RESOURCE}; it answers {MEDIA_TURTLE} \
                         (the default) or {MEDIA_ARRANGEMENT}"
                    ),
                })
            }
        };
        Ok(Representation::new(
            ReprType::new(face).with_param("charset", "utf-8"),
            bytes.into_bytes(),
        )
        .cacheable())
    }

    fn name(&self) -> &str {
        "host-arrangement"
    }

    fn describe(&self) -> Description {
        Description::new("host-arrangement")
            .title("The host's arrangement")
            .summary(
                "The arrangement this host built its local root from, as a declaration: the \
                 root node of urn:kernel:topology without the layers the host adds around it. \
                 Save it, edit it, and start a host from it with --arrangement <file>. Turtle \
                 by default; as=text/x-ikigai-arrangement writes it as an s-expression.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .input(
                ArgSpec::new("as")
                    .summary("the face to answer: Turtle, or the s-expression an `.arrangement` file holds")
                    .class(XSD_STRING)
                    .one_of([MEDIA_TURTLE, MEDIA_ARRANGEMENT])
                    .default_value(MEDIA_TURTLE)
                    .optional(),
            )
            .output("text/turtle;charset=utf-8")
            .output("text/x-ikigai-arrangement;charset=utf-8")
    }
}

/// The datatype of `as`.
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

/// The host layer that answers [`RESOURCE`].
pub(crate) fn dump_space(dump: Dump) -> EndpointSpace {
    EndpointSpace::new().bind(Exact::new(RESOURCE), ArrangementEndpoint::new(dump))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::FnEndpoint;

    fn endpoint(name: &'static str) -> Arc<dyn Endpoint> {
        Arc::new(FnEndpoint::new(name, move |_| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                name.as_bytes().to_vec(),
            ))
        }))
    }

    /// One endpoint bound at two doors is ONE registration; two different endpoints under one
    /// name are neither, and are reported with every door that binds the name.
    #[test]
    fn a_shared_endpoint_registers_once_and_a_shared_name_is_ambiguous() {
        let one = endpoint("one");
        let members: Vec<Arc<dyn Space>> = vec![
            Arc::new(
                EndpointSpace::new()
                    .bind_arc(Exact::new("urn:t:one"), Arc::clone(&one))
                    .bind_arc(UriTemplate::parse("urn:t:one:{x}").unwrap(), one)
                    .bind_arc(Exact::new("urn:t:a"), endpoint("same")),
            ),
            Arc::new(EndpointSpace::new().bind_arc(Exact::new("urn:t:b"), endpoint("same"))),
        ];
        let harvest = harvest(&members);
        assert_eq!(harvest.registry.ids().collect::<Vec<_>>(), vec!["one"]);
        assert_eq!(
            harvest.ambiguous.get("same"),
            Some(&vec!["urn:t:a".to_string(), "urn:t:b".to_string()])
        );
        assert!(harvest.unreached.is_empty());
    }

    /// A door shadowed inside its own space is reported, never guessed at: its probe finds the
    /// endpoint that shadows it.
    #[test]
    fn a_shadowed_door_is_unreached() {
        let members: Vec<Arc<dyn Space>> = vec![Arc::new(
            EndpointSpace::new()
                .bind_arc(UriTemplate::parse("urn:t:{x}").unwrap(), endpoint("wide"))
                .bind_arc(Exact::new("urn:t:narrow"), endpoint("narrow")),
        )];
        let harvest = harvest(&members);
        assert_eq!(
            harvest.unreached,
            vec![("urn:t:narrow".to_string(), "narrow".to_string())]
        );
        assert_eq!(harvest.registry.ids().collect::<Vec<_>>(), vec!["wide"]);
    }

    /// A declaration binding an ambiguous name is refused with the HOST's reason — which names
    /// every door the name is bound at — not core's bare "not registered".
    #[test]
    fn an_ambiguous_name_is_refused_with_the_doors_it_is_bound_at() {
        let members: Vec<Arc<dyn Space>> = vec![
            Arc::new(EndpointSpace::new().bind_arc(Exact::new("urn:t:a"), endpoint("same"))),
            Arc::new(EndpointSpace::new().bind_arc(Exact::new("urn:t:b"), endpoint("same"))),
        ];
        let harvest = harvest(&members);
        let declaration = Fallback::new(members).topology();
        let Err(refused) = arrange(&harvest, &declaration) else {
            panic!("an ambiguous name must not build")
        };
        assert!(
            refused.contains("`same`")
                && refused.contains("2 different endpoints")
                && refused.contains("`urn:t:a`, `urn:t:b`"),
            "{refused}"
        );
        assert!(
            refused.contains("<urn:ikigai:space:_:"),
            "names the door: {refused}"
        );
    }

    /// The dump reads back: its header is `#` comments, which are not triples.
    #[test]
    fn the_dump_parses_back_to_the_arrangement() {
        let members: Vec<Arc<dyn Space>> = vec![
            Arc::new(EndpointSpace::new().bind_arc(Exact::new("urn:t:a"), endpoint("same"))),
            Arc::new(EndpointSpace::new().bind_arc(Exact::new("urn:t:b"), endpoint("same"))),
        ];
        let harvest = harvest(&members);
        let arrangement = Fallback::new(members).topology();
        let turtle = dump(&arrangement, "the built-in default", &harvest)
            .turtle()
            .unwrap();
        assert!(
            turtle.contains("# ⚠ Not declarable as it stands: `same`"),
            "{turtle}"
        );
        assert_eq!(Topology::from_turtle(&turtle).unwrap(), arrangement);
    }

    /// The s-expression face is the same arrangement: its `;;` header is comments, and the body
    /// reads back through ikigai-sexpr to the tree the Turtle face carries.
    #[test]
    fn the_dump_has_an_s_expression_face_that_reads_back() {
        let members: Vec<Arc<dyn Space>> = vec![
            Arc::new(EndpointSpace::new().bind_arc(Exact::new("urn:t:a"), endpoint("a"))),
            Arc::new(EndpointSpace::new().bind_arc(Exact::new("urn:t:b"), endpoint("b"))),
        ];
        let harvest = harvest(&members);
        let arrangement = Fallback::new(members).topology();
        let dump = dump(&arrangement, "the built-in default", &harvest);
        let sexpr = dump.sexpr().unwrap();
        assert!(
            sexpr.starts_with(";; The arrangement this host built its local root from"),
            "{sexpr}"
        );
        assert!(sexpr.contains("(door \"urn:t:a\" a)"), "{sexpr}");
        assert_eq!(
            ikigai_sexpr::arrangement_to_topology(&sexpr).unwrap(),
            arrangement
        );
        assert_eq!(
            Topology::from_turtle(&dump.turtle().unwrap()).unwrap(),
            ikigai_sexpr::arrangement_to_topology(&sexpr).unwrap()
        );
    }

    /// A declaration is read through the bootstrap kernel: Turtle as it is, and a missing file
    /// as an error that says so.
    #[test]
    fn a_declaration_is_read_through_a_kernel() {
        let dir = std::env::temp_dir().join(format!("iki-arr-read-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("root.ttl");
        std::fs::write(&path, "@prefix ik: <https://ikigai-rs.dev/ns#> .\n").unwrap();
        assert!(read_declaration(&path).unwrap().contains("@prefix ik:"));
        assert!(read_declaration(&dir.join("absent.ttl")).is_err());
        // Another surface arrives as Turtle by transreption: N-Triples here, through the
        // host's own RDF transreptors — the path an s-expression surface will take.
        let leaf = Topology::new(SpaceKind::EndpointSpace {
            doors: vec![Door::new("urn:t:a", MatchKind::Exact, "a")],
        });
        let (rdf, ik) = (
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
            "https://ikigai-rs.dev/ns#",
        );
        let (s, list, door) = (
            "urn:ikigai:space:_:1",
            "urn:ikigai:space:_:1:doors:1",
            "urn:ikigai:space:_:1:door:1",
        );
        let triples = [
            format!("<{s}> <{rdf}type> <{ik}EndpointSpace> ."),
            format!("<{s}> <{ik}pattern> \"urn:t:a\" ."),
            format!("<{s}> <{ik}doors> <{list}> ."),
            format!("<{list}> <{rdf}first> <{door}> ."),
            format!("<{list}> <{rdf}rest> <{rdf}nil> ."),
            format!("<{door}> <{rdf}type> <{ik}Door> ."),
            format!("<{door}> <{ik}pattern> \"urn:t:a\" ."),
            format!("<{door}> <{ik}matchKind> \"exact\" ."),
            format!("<{door}> <{ik}endpointName> \"a\" ."),
        ];
        let nt = dir.join("root.nt");
        std::fs::write(&nt, triples.join("\n")).unwrap();
        let turtle = read_declaration(&nt).unwrap();
        assert_eq!(Topology::from_turtle(&turtle).unwrap(), leaf);
        // An `.arrangement` file — ikigai-fs 0.1.7 types it, ikigai-sexpr 0.1.4 transrepts it —
        // arrives as the Turtle of the same tree, comments and all dropped.
        let file = dir.join("root.arrangement");
        std::fs::write(&file, ";; one door\n(endpoints (door \"urn:t:a\" a))\n").unwrap();
        let turtle = read_declaration(&file).unwrap();
        assert_eq!(Topology::from_turtle(&turtle).unwrap(), leaf);
        // And a malformed one is refused with ikigai-sexpr's reason, naming the transreptor.
        std::fs::write(&file, "(endpoints (portal \"urn:t:a\" a))").unwrap();
        let refused = read_declaration(&file).unwrap_err();
        assert!(
            refused.contains("<urn:sexpr:arrangement-to-rdf> refused it")
                && refused.contains("door 1")
                && refused.contains("(portal …)"),
            "{refused}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
