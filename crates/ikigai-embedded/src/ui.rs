//! Shared UI resources, with an optional published, read-only override directory.
use std::path::PathBuf;
use std::sync::{Arc, Weak};

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
    let mut spaces: Vec<Arc<dyn Space>> = vec![Arc::new(ikigai_ui::space())];
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
    ReadOnlyUi(Fallback::new(spaces))
}

struct ReadOnlyUi(Fallback);

impl Space for ReadOnlyUi {
    fn resolve(&self, request: &Request, scope: &Scope) -> Resolution {
        self.0
            .resolve(request, scope)
            .map_endpoint(|endpoint| Arc::new(ReadOnlyEndpoint(endpoint)))
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        self.0.entries()
    }

    fn topology(&self) -> ikigai_core::Topology {
        self.0.topology()
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
