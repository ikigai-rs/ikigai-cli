//! Shared UI resources, with an optional published, read-only override directory.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};

use ikigai_core::{
    Capability, Description, Endpoint, EndpointSpace, Error, Fallback, Invocation, Kernel,
    Representation, Request, Resolution, Result, Scope, Space, SpaceEntry, UriTemplate, Verb,
};
use notify::{RecursiveMode, Watcher};

// External disk state has its own thread: this resource deliberately has no write verb.
const DISK: &str = "urn:iki:ui:disk:";

fn disk_thread(resource: &str) -> String {
    format!(
        "{DISK}{}",
        resource
            .strip_prefix(ikigai_ui::DIR)
            .expect("UI directory resource")
    )
}

fn directory() -> Option<PathBuf> {
    let path = crate::config::config_home()?.join("ui");
    path.is_dir().then_some(path)
}

pub(super) fn space() -> impl Space {
    let mut spaces: Vec<Arc<dyn Space>> = vec![Arc::new(Served(ikigai_ui::space()))];
    if let Some(root) = directory() {
        spaces.push(Arc::new(EndpointSpace::new().bind(
            UriTemplate::parse("urn:iki:ui:dir:{path}").expect("valid UI directory template"),
            PublishedDirectory {
                // Publishing this directory authorizes reads, never writes. This private
                // grant is used only by the jailed file reader, never by a sub-request.
                read: Capability::scoped([format!("urn:cap:fs:read:{}", root.display())]),
                files: ikigai_fs::FileEndpoint::new(root).cacheable(),
            },
        )));
    }
    ReadOnlyUi {
        inner: Fallback::new(spaces),
        endpoints: Mutex::new(HashMap::new()),
    }
}

/// The ikigai-ui resources this host serves, by endpoint name: the shell, its tokens and
/// template, htmx, and the theme and page choosers with their palettes. Everything the
/// cli served under ikigai-ui 0.5.0, and `tests/conformance.rs` pins the set.
pub(crate) const SERVED: [&str; 8] = [
    "ui-chooser",
    "ui-htmx",
    "ui-shell-js",
    "ui-template-shell",
    "ui-template-tokens",
    "ui-tokens-css",
    "ui-palette",
    "ui-theme-chooser",
];

/// `ikigai_ui::space()` narrowed to [`SERVED`] in all three of resolution, entries and
/// topology, so the catalog, the manifold and a dumped arrangement describe exactly what
/// resolves. ★ ikigai-ui 0.5.1 binds 58 more resources in the same space (screens, lenses,
/// forms, and the `outline`, `sexpr` and `lisp` compilers). A pin taken for the shell's
/// restart retry must not quietly add them to every cli kernel; which of them the REPL
/// should offer is its own decision. ikigai-gonk narrows the same space the same way
/// (its `doors.rs`, `UiShared`), and ikigai-ui offering this narrowed space itself would
/// retire both copies.
struct Served(ikigai_core::EndpointSpace);

impl Space for Served {
    fn resolve(&self, request: &Request, scope: &Scope) -> Resolution {
        match self.0.resolve(request, scope) {
            Resolution::Hit(hit) if SERVED.contains(&hit.endpoint.name()) => Resolution::Hit(hit),
            _ => Resolution::Miss,
        }
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        Some(
            self.0
                .entries()?
                .into_iter()
                .filter(|entry| SERVED.contains(&entry.endpoint.as_str()))
                .collect(),
        )
    }

    fn id(&self) -> Option<ikigai_core::Iri> {
        self.0.id()
    }

    fn topology(&self) -> ikigai_core::Topology {
        let mut topology = self.0.topology();
        if let ikigai_core::SpaceKind::EndpointSpace { doors } = &mut topology.kind {
            doors.retain(|door| SERVED.contains(&door.endpoint.as_str()));
        }
        topology
    }
}

struct ReadOnlyUi {
    inner: Fallback,
    // Keep one adapter per endpoint so harvesting and rebuilding a declared arrangement
    // preserve endpoint identity, just as resolving the built-in arrangement does.
    endpoints: Mutex<HashMap<usize, Arc<dyn Endpoint>>>,
}

impl Space for ReadOnlyUi {
    fn resolve(&self, request: &Request, scope: &Scope) -> Resolution {
        self.inner.resolve(request, scope).map_endpoint(|endpoint| {
            let key = Arc::as_ptr(&endpoint) as *const () as usize;
            let mut endpoints = self.endpoints.lock().unwrap_or_else(|e| e.into_inner());
            Arc::clone(
                endpoints
                    .entry(key)
                    .or_insert_with(|| Arc::new(ReadOnlyEndpoint(endpoint))),
            )
        })
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        self.inner.entries()
    }

    fn topology(&self) -> ikigai_core::Topology {
        self.inner.topology()
    }
}

struct ReadOnlyEndpoint(Arc<dyn Endpoint>);

#[async_trait::async_trait]
impl Endpoint for ReadOnlyEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if !matches!(inv.request.verb, Verb::Source | Verb::Meta) {
            return Err(Error::Denied("UI resources are read-only".to_string()));
        }
        self.0.invoke(inv).await
    }

    async fn invoke_body(&self, inv: &Invocation<'_>) -> Result<Representation<ikigai_core::Body>> {
        if !matches!(inv.request.verb, Verb::Source | Verb::Meta) {
            return Err(Error::Denied("UI resources are read-only".to_string()));
        }
        self.0.invoke_body(inv).await
    }

    fn name(&self) -> &str {
        self.0.name()
    }
    fn describe(&self) -> Description {
        self.0.describe()
    }
}

struct PublishedDirectory {
    files: ikigai_fs::FileEndpoint,
    read: Capability,
}

#[async_trait::async_trait]
impl Endpoint for PublishedDirectory {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if inv.request.verb != Verb::Source {
            return Err(Error::Denied("UI overrides are read-only".to_string()));
        }
        let mut published = inv.with_bindings(inv.bindings);
        published.capability = &self.read;
        self.files
            .invoke(&published)
            .await
            .map(|repr| repr.depends_on(disk_thread(inv.request.target.as_str())))
    }

    async fn invoke_body(&self, inv: &Invocation<'_>) -> Result<Representation<ikigai_core::Body>> {
        if inv.request.verb != Verb::Source {
            return Err(Error::Denied("UI overrides are read-only".to_string()));
        }
        let mut published = inv.with_bindings(inv.bindings);
        published.capability = &self.read;
        self.files
            .invoke_body(&published)
            .await
            .map(|repr| repr.depends_on(disk_thread(inv.request.target.as_str())))
    }

    fn name(&self) -> &str {
        "ui-directory"
    }

    fn describe(&self) -> Description {
        // Retain the file reader's path grammar, output and failure contracts, but expose
        // only the published read. A root caller cannot reach its Sink or Delete either.
        let mut description = self.files.describe();
        description.id = self.name().to_string();
        description.title = "Published UI overrides".to_string();
        description.summary =
            "Read-only files under the config home's ui directory, with the file jail's path and symlink checks.".to_string();
        description.verbs = vec![Verb::Source, Verb::Meta];
        description
            .inputs
            .retain(|a| a.name == "path" || a.name == "as");
        description.requires.clear();
        description.actions.retain(|a| a.verb == Verb::Source);
        for action in &mut description.actions {
            action.requires.clear();
        }
        description
    }
}

/// Held with the workspace watch, so both namespaces stay fresh for the same lifetime.
pub(super) fn watch(
    kernel: Weak<Kernel>,
) -> std::result::Result<Option<notify::RecommendedWatcher>, String> {
    let Some(root) = directory() else {
        return Ok(None);
    };
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let prefix = root.clone();
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        let (Ok(event), Some(kernel)) = (event, kernel.upgrade()) else {
            return;
        };
        if event.need_rescan() {
            for thread in crate::cached_threads(&kernel, ikigai_ui::DIR)
                .into_iter()
                .chain(crate::cached_threads(&kernel, DISK))
            {
                kernel.cut(thread);
            }
        } else if !event.kind.is_access() {
            for path in &event.paths {
                if let Some(thread) = crate::file_thread(&prefix, path) {
                    let resource = thread.replacen("urn:file:", ikigai_ui::DIR, 1);
                    kernel.cut(disk_thread(&resource));
                    kernel.cut(resource);
                }
            }
        }
    })
    .map_err(|e| e.to_string())?;
    watcher
        .watch(&root, RecursiveMode::Recursive)
        .map_err(|e| format!("{}: {e}", root.display()))?;
    Ok(Some(watcher))
}
