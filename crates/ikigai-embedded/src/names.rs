//! **The names layer** (named requests C1, ledger #2515): the REPL's named requests, read from a
//! names file and served LAST in the local root.
//!
//! A request with arguments gets a NAME, bound in the host's names atom, instead of the kernel
//! parsing arguments out of IRIs (ledger #2447). This host's atom is a file:
//!
//! | what | where |
//! |---|---|
//! | the file | `--names <file>`, else the config home's `names` (the text form, [`MEDIA_NAMES`]) or `names.ttl` (the `ik:Alias` Turtle `urn:names:to-rdf` writes); both at once is refused. With neither, bindings are written to a new `names`. |
//! | the atom | [`RESOURCE`] (`urn:iki:host:names`): `Source` reads the file as names text, `Sink content=` writes it (in the file's own form, so a `names.ttl` stays Turtle). `bind` and `unbind` write it. |
//! | the bindings | a [`DynamicSpace`] (`urn:iki:space:dynamic:names`) holding an alias of the file's bindings, rebuilt on every write and every out-of-band edit of the file (a watch on its directory cuts the file's thread, [`RESOURCE`]). |
//! | the status door | `urn:iki:space:dynamic:names:status`: core's status of the dynamic space, then the file, the last refusal of the file and every binding SHADOWED by a name served ahead of the layer. |
//!
//! - **Last in the root.** A name the host already serves is answered by the host, so a
//!   binding can add names and never change one: a binding whose name is served ahead of the
//!   layer never answers, and the status door says which (`shadowed:`). A template name is
//!   not checked: what it shadows depends on the capture.
//! - **Authority is unchanged.** A binding declares and grants nothing; the forward a name
//!   performs carries the caller's capability. Writing the file is a host setting, so the
//!   `Sink` needs [`CAP_WRITE`] (the running user's root holds it; a `cap`-narrowed session
//!   does not).
//! - **A file that does not read keeps the names in force**, as a refused declaration does in
//!   a dynamic space, and the status door says why. A file that is removed binds nothing.
//!
//! Armed only by the processes that run the REPL (the REPL itself, `-c`): the served doors, the
//! daemon and MCP build their roots without it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock, Weak};

use async_trait::async_trait;
use ikigai_core::{
    ActionSpec, Alias, AliasTable, ArgSpec, ContentId, Description, DynamicSpace, Endpoint,
    EndpointSpace, Error, Exact, Fallback, Invocation, Iri, Kernel, Registry, ReprType,
    Representation, Request, Resolution, Result, Scope, Space, SpaceEntry, Thread, Topology,
    TopologyRule, Verb,
};
use ikigai_engine::names::{names_to_turtle, parse_names, turtle_to_names, MEDIA_NAMES};
use notify::{RecursiveMode, Watcher};

/// The names atom: `Source` reads the names file, `Sink content=` writes it.
pub const RESOURCE: &str = "urn:iki:host:names";

/// The capability a `Sink` to [`RESOURCE`] needs: it writes a file in the config home.
pub const CAP_WRITE: &str = "urn:cap:host:write:names";

/// The dynamic space's name: `urn:iki:space:dynamic:names`.
const SPACE_NAME: &str = "names";

/// The text file's name in the config home.
const TEXT_FILE: &str = "names";

/// The Turtle file's name in the config home.
const TURTLE_FILE: &str = "names.ttl";

const MEDIA_TURTLE: &str = "text/turtle";

/// The `--names` path, declared while argv is read (first write wins).
static FLAG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// The layer this process armed, once [`arm`] found a file to serve.
static ACTIVE: OnceLock<Arc<NamesLayer>> = OnceLock::new();

/// Declare `--names <file>` for this process. A relative path is taken against the working
/// directory NOW, so a later `cd` cannot move it.
pub fn set_names_path(path: impl Into<PathBuf>) {
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

/// The `--names` path, if the flag was given — so a door that serves no names layer can
/// refuse the flag instead of ignoring it.
pub fn names_flag() -> Option<&'static Path> {
    FLAG_PATH.get().map(PathBuf::as_path)
}

/// The layer this process serves, once [`arm`] armed one.
pub fn active() -> Option<Arc<NamesLayer>> {
    ACTIVE.get().cloned()
}

/// **Arm the names layer for this process's local root**: the flag's file, else the config
/// home's `names` or `names.ttl`, else a `names` there to be written by the first `bind`. Call
/// once at start, before the first local kernel is built.
///
/// `Ok(None)`: no flag and no config home, so there is nowhere to keep names. `Err`: the config
/// home holds both files, which could only mean two tables. Idempotent.
pub fn arm() -> std::result::Result<Option<Arc<NamesLayer>>, String> {
    if let Some(layer) = ACTIVE.get() {
        return Ok(Some(Arc::clone(layer)));
    }
    let path = match FLAG_PATH.get() {
        Some(path) => path.clone(),
        None => {
            let Some(home) = crate::config::config_home() else {
                return Ok(None);
            };
            config_home_file(&home)?
        }
    };
    let _ = ACTIVE.set(Arc::new(NamesLayer::new(path)));
    Ok(ACTIVE.get().cloned())
}

/// The names file in config home `home`: `names` or `names.ttl`, refused when both exist, and
/// `names` (to be created) when neither does.
fn config_home_file(home: &Path) -> std::result::Result<PathBuf, String> {
    let (text, turtle) = (home.join(TEXT_FILE), home.join(TURTLE_FILE));
    match (text.exists(), turtle.exists()) {
        (true, true) => Err(format!(
            "the config home holds both `{}` and `{}`, and a host has one names table: remove \
             one, or name the file with --names",
            text.display(),
            turtle.display()
        )),
        (false, true) => Ok(turtle),
        _ => Ok(text),
    }
}

/// **The names layer**: the atom's door, the dynamic space of bindings, and the status door
/// that reports what the bindings shadow. Placed last in the root ([`NamesLayer::over`]).
pub struct NamesLayer {
    shared: Arc<Shared>,
    /// The atom's door, then the bindings: what [`Space::entries`] and [`Space::topology`]
    /// report.
    spaces: Fallback,
    /// Held for the watch's lifetime.
    watch: OnceLock<notify::RecommendedWatcher>,
}

/// What the doors and the reload share.
struct Shared {
    /// The names file.
    path: PathBuf,
    /// The bindings.
    dynamic: Arc<DynamicSpace>,
    /// What is served ahead of the layer, for the shadow report: the root without it.
    ahead: RwLock<Option<Arc<dyn Space>>>,
    /// The kernel the layer serves in, once [`NamesLayer::attach`] named it.
    kernel: OnceLock<Weak<Kernel>>,
    /// The bindings in force that a name served ahead of the layer shadows.
    shadowed: RwLock<Vec<String>>,
    /// Why the file last failed to read, until it reads again.
    refusal: RwLock<Option<String>>,
}

impl NamesLayer {
    fn new(path: PathBuf) -> Self {
        let dynamic = Arc::new(DynamicSpace::new(
            SPACE_NAME,
            Iri::parse(RESOURCE).expect("a constant IRI"),
            Registry::new(),
        ));
        let shared = Arc::new(Shared {
            path,
            dynamic: Arc::clone(&dynamic),
            ahead: RwLock::new(None),
            kernel: OnceLock::new(),
            shadowed: RwLock::new(Vec::new()),
            refusal: RwLock::new(None),
        });
        let door = EndpointSpace::new().bind(
            Exact::new(RESOURCE),
            NamesFile {
                shared: Arc::clone(&shared),
            },
        );
        NamesLayer {
            spaces: Fallback::new(vec![Arc::new(door) as Arc<dyn Space>, dynamic]),
            shared,
            watch: OnceLock::new(),
        }
    }

    /// The names file this layer serves.
    pub fn path(&self) -> &Path {
        &self.shared.path
    }

    /// The root with this layer placed LAST: `ahead`, then the layer. `ahead` is also what
    /// the shadow report asks.
    pub fn over(self: &Arc<Self>, ahead: Arc<dyn Space>) -> Arc<dyn Space> {
        *self.shared.ahead.write().unwrap_or_else(|p| p.into_inner()) = Some(Arc::clone(&ahead));
        Arc::new(Fallback::new(vec![
            ahead,
            Arc::clone(self) as Arc<dyn Space>,
        ]))
    }

    /// Bind the file's names in `kernel` and watch the file. Once per process: the first
    /// kernel attached is the one the layer serves.
    pub fn attach(&self, kernel: &Arc<Kernel>) {
        if self.shared.kernel.set(Arc::downgrade(kernel)).is_err() {
            return;
        }
        futures::executor::block_on(self.shared.reload());
        if let Some(why) = self.shared.refusal() {
            eprintln!(
                "ikigai: {why}; no names are bound from it until it reads (`source \
                 {}` reports it)",
                self.status_iri().as_str()
            );
        }
        if let Some(watcher) = self.shared.watch() {
            let _ = self.watch.set(watcher);
        }
    }

    /// The status door: `urn:iki:space:dynamic:names:status`.
    pub fn status_iri(&self) -> &Iri {
        self.shared.dynamic.status_iri()
    }

    /// The bindings in force that a name served ahead of the layer shadows.
    pub fn shadowed(&self) -> Vec<String> {
        self.shared
            .shadowed
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl Space for NamesLayer {
    fn resolve(&self, request: &Request, scope: &Scope) -> Resolution {
        let resolution = self.spaces.resolve(request, scope);
        if &request.target != self.status_iri() {
            return resolution;
        }
        let shared = Arc::clone(&self.shared);
        resolution.map_endpoint(move |inner| Arc::new(Status { inner, shared }))
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        self.spaces.entries()
    }

    fn topology(&self) -> Topology {
        self.spaces.topology()
    }
}

/// How the file is written: the text form, or Turtle for a `.ttl` file.
fn is_turtle(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "ttl")
}

impl Shared {
    fn thread(&self) -> Thread {
        Thread::new(RESOURCE)
    }

    fn kernel(&self) -> Option<Arc<Kernel>> {
        self.kernel.get().and_then(Weak::upgrade)
    }

    fn refusal(&self) -> Option<String> {
        self.refusal
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// The file's bindings, as names text: `Ok(None)` when there is no file.
    fn read_text(&self) -> std::result::Result<Option<String>, String> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("the names file `{}`: {e}", self.path.display())),
        };
        let text = String::from_utf8(bytes)
            .map_err(|_| format!("the names file `{}` is not UTF-8 text", self.path.display()))?;
        if is_turtle(&self.path) {
            turtle_to_names(&text)
                .map(Some)
                .map_err(|e| format!("the names file `{}`: {e}", self.path.display()))
        } else {
            Ok(Some(text))
        }
    }

    /// Re-read the file and bind its names, when they changed. The file's thread is cut
    /// whatever happens, so the atom's next read is the file's. A file that does not read
    /// keeps the names in force and is recorded for the status door.
    async fn reload(&self) {
        let Some(kernel) = self.kernel() else {
            return;
        };
        kernel.cut(self.thread());
        let rules = match self.read_text().and_then(|text| {
            parse_names(text.as_deref().unwrap_or(""))
                .map_err(|e| format!("the names file `{}`: {e}", self.path.display()))
        }) {
            Ok(rules) => rules,
            Err(why) => {
                *self.refusal.write().unwrap_or_else(|p| p.into_inner()) = Some(why);
                return;
            }
        };
        let topology = match bindings(&rules) {
            Ok(topology) => topology,
            Err(why) => {
                *self.refusal.write().unwrap_or_else(|p| p.into_inner()) = Some(why);
                return;
            }
        };
        let digest = ContentId::of(topology.to_turtle().as_bytes());
        let result = if self.dynamic.status().in_force.as_ref() == Some(&digest) {
            Ok(())
        } else {
            self.dynamic
                .install_topology(&kernel, &topology)
                .await
                .map_err(|e| format!("the names file `{}`: {e}", self.path.display()))
        };
        match result {
            Ok(()) => {
                *self.refusal.write().unwrap_or_else(|p| p.into_inner()) = None;
                *self.shadowed.write().unwrap_or_else(|p| p.into_inner()) = self.shadows(&rules);
            }
            Err(why) => *self.refusal.write().unwrap_or_else(|p| p.into_inner()) = Some(why),
        }
    }

    /// The bindings whose name a space ahead of the layer answers, so the binding never does.
    fn shadows(&self, rules: &[TopologyRule]) -> Vec<String> {
        let ahead = self.ahead.read().unwrap_or_else(|p| p.into_inner());
        let Some(ahead) = ahead.as_ref() else {
            return Vec::new();
        };
        rules
            .iter()
            .filter(|rule| !rule.template)
            .filter(|rule| {
                let Ok(name) = Iri::parse(rule.from.as_str()) else {
                    return false;
                };
                let request = Request::new(rule.verb.unwrap_or(Verb::Source), name);
                matches!(ahead.resolve(&request, &Scope::empty()), Resolution::Hit(_))
            })
            .map(|rule| rule.from.clone())
            .collect()
    }

    /// Watch the file's directory, and reload on every change to the file.
    fn watch(self: &Arc<Self>) -> Option<notify::RecommendedWatcher> {
        let dir = self.path.parent()?.to_path_buf();
        let name = self.path.file_name()?.to_os_string();
        let shared = Arc::downgrade(self);
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let (Ok(event), Some(shared)) = (res, shared.upgrade()) else {
                return;
            };
            if event.paths.iter().any(|p| p.file_name() == Some(&name)) {
                futures::executor::block_on(shared.reload());
            }
        })
        .ok()?;
        watcher.watch(&dir, RecursiveMode::NonRecursive).ok()?;
        Some(watcher)
    }

    /// Write `text` (names text, already read) to the file in its own form.
    fn write(&self, text: &str) -> std::result::Result<(), String> {
        let bytes = if is_turtle(&self.path) {
            names_to_turtle(text).map_err(|e| e.to_string())?
        } else {
            text.to_string()
        };
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        std::fs::write(&self.path, bytes).map_err(|e| format!("{}: {e}", self.path.display()))
    }
}

/// The bindings as the arrangement the dynamic space binds: an alias over no doors, each
/// binding forwarding from the root.
fn bindings(rules: &[TopologyRule]) -> std::result::Result<Topology, String> {
    let mut table = AliasTable::new();
    for rule in rules {
        table = table.with_rule(rule.clone()).map_err(|e| e.to_string())?;
    }
    Ok(Alias::new(Arc::new(table), Arc::new(EndpointSpace::new())).topology())
}

/// [`RESOURCE`]: the names file, read and written.
struct NamesFile {
    shared: Arc<Shared>,
}

#[async_trait]
impl Endpoint for NamesFile {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        match inv.request.verb {
            Verb::Sink => {
                if !inv.capability.allows(CAP_WRITE) {
                    return Err(Error::Denied(format!(
                        "writing this host's names file requires `{CAP_WRITE}`"
                    )));
                }
                let text = inv.inline_str("content")?;
                parse_names(text).map_err(|e| Error::InvalidArgument {
                    name: "content".to_string(),
                    detail: e.to_string(),
                })?;
                self.shared.write(text).map_err(|e| {
                    Error::Endpoint(format!("the names file could not be written: {e}"))
                })?;
                self.shared.reload().await;
                if let Some(why) = self.shared.refusal() {
                    return Err(Error::Endpoint(why));
                }
                Ok(Representation::new(
                    ReprType::new("text/plain").with_param("charset", "utf-8"),
                    format!("wrote {}\n", self.shared.path.display()).into_bytes(),
                ))
            }
            _ => {
                let text = self.shared.read_text().map_err(Error::Endpoint)?;
                let Some(text) = text else {
                    return Err(Error::NotFound(format!(
                        "{RESOURCE}: no names file at `{}`",
                        self.shared.path.display()
                    )));
                };
                Ok(Representation::new(
                    ReprType::new(MEDIA_NAMES).with_param("charset", "utf-8"),
                    text.into_bytes(),
                )
                .cacheable()
                .depends_on(self.shared.thread()))
            }
        }
    }

    fn name(&self) -> &str {
        "host-names"
    }

    fn describe(&self) -> Description {
        Description::new("host-names")
            .title("The host's names")
            .summary(
                "This host's named requests, one binding per line (`<name> = <verb> <target> \
                 [key=value …]`), as the REPL's `bind` writes them. Source reads the names \
                 file; Sink content= replaces it (needs urn:cap:host:write:names), and the \
                 names layer, last in the root, binds what it holds. A name served ahead of \
                 the layer shadows a binding of it, and urn:iki:space:dynamic:names:status \
                 says which.",
            )
            // Per verb, so the Sink DECLARES the write capability it enforces: a flat
            // `.requires()` would also gate the read, and none at all left the manifold
            // offering the write to a narrowed session that is then refused.
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("read the names file")
                    .output(format!("{MEDIA_NAMES};charset=utf-8")),
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("replace the names file and rebind")
                    .requires(CAP_WRITE)
                    .input(
                        ArgSpec::new("content")
                            .summary("the whole names file")
                            .class("http://www.w3.org/2001/XMLSchema#string"),
                    )
                    .output("text/plain; charset=utf-8"),
            )
    }
}

/// The status door: the dynamic space's own status, then the file's.
struct Status {
    inner: Arc<dyn Endpoint>,
    shared: Arc<Shared>,
}

#[async_trait]
impl Endpoint for Status {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let core = self.inner.invoke(inv).await?;
        if core.repr_type.media_type != "text/plain" {
            return Ok(core);
        }
        let mut text = String::from_utf8_lossy(&core.bytes).trim_end().to_string();
        let path = &self.shared.path;
        text.push_str(&format!(
            "\nnames file: {} ({}{})",
            path.display(),
            if is_turtle(path) {
                MEDIA_TURTLE
            } else {
                MEDIA_NAMES
            },
            if path.exists() {
                ""
            } else {
                ", not yet written"
            }
        ));
        if let Some(why) = self.shared.refusal() {
            text.push_str(&format!(
                "\nnot read: {why}; the names in force are the last that read"
            ));
        }
        let shadowed = self
            .shared
            .shadowed
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        for name in shadowed {
            text.push_str(&format!(
                "\nshadowed: {name} is served ahead of the names layer, so its binding never \
                 answers"
            ));
        }
        text.push('\n');
        Ok(Representation::new(
            core.repr_type.clone(),
            text.into_bytes(),
        ))
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn describe(&self) -> Description {
        self.inner.describe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_config_home_names_one_file() {
        let dir = std::env::temp_dir().join(format!("iki-names-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(config_home_file(&dir), Ok(dir.join("names")));
        std::fs::write(dir.join("names.ttl"), "").unwrap();
        assert_eq!(config_home_file(&dir), Ok(dir.join("names.ttl")));
        std::fs::write(dir.join("names"), "").unwrap();
        let both = config_home_file(&dir).unwrap_err();
        assert!(both.contains("both"), "{both}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
