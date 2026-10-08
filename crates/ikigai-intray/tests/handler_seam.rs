//! The Hermes audit's `handler-retarget` (ledger #877; the same class as ledger #445): the
//! `handler` file lives in the drop tree, so whoever can write the tree chose which IRI the
//! reactor fired every tuple at, under the reactor's host-granted authority.
//! `with_host_handler` lets the host decide.

mod common;

use common::{drop_tuple, scratch};
use ikigai_core::{Capability, Error, Kernel, ReprType, Representation, Request, SpaceEntry};
use ikigai_intray::{space, Outcome, SpaceReactor, CAP_OUT};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// A handler double that records the IRI each pass fired at.
#[derive(Default)]
struct Recording(Mutex<Vec<String>>);

impl Recording {
    fn fired(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

impl ikigai_resolve::Resolver for Recording {
    fn issue(
        &self,
        request: Request,
    ) -> Result<(Representation, ikigai_resolve::CacheStatus), Error> {
        self.issue_as(request, &Capability::root())
    }
    fn issue_as(
        &self,
        request: Request,
        _: &Capability,
    ) -> Result<(Representation, ikigai_resolve::CacheStatus), Error> {
        self.0
            .lock()
            .unwrap()
            .push(request.target.as_str().to_string());
        Ok((
            Representation::new(ReprType::new("text/plain"), Vec::new()),
            ikigai_resolve::CacheStatus::Uncacheable,
        ))
    }
    fn is_cached(&self, _: &Request, _: &Capability) -> bool {
        false
    }
    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        None
    }
}

const LEGIT: &str = "urn:legit:handler";

/// The Hermes probe's state: a reactive space whose `handler` file a dropper REWROTE.
fn retargeted(tag: &str) -> (std::path::PathBuf, String) {
    let root = scratch(tag);
    std::fs::create_dir_all(root.join("jobs")).unwrap();
    std::fs::write(root.join("jobs/handler"), LEGIT).unwrap();
    let k = Kernel::new(Arc::new(space(root.clone())));
    let id = drop_tuple(
        &k,
        &Capability::scoped([CAP_OUT]),
        "urn:space:jobs",
        b"work",
    )
    .unwrap();
    std::fs::write(root.join("jobs/handler"), "urn:evil:target").unwrap();
    (root, id)
}

fn reactor(root: &Path, handler: Arc<Recording>) -> SpaceReactor {
    SpaceReactor::new(
        root.to_path_buf(),
        handler,
        Capability::scoped(["urn:cap:mail:send"]),
    )
    .with_host_authority(|_| Some(Capability::scoped(["urn:cap:mail:send"])))
}

/// Without the seam the file decides — the hole the audit found, kept as the documented
/// default so no host changes behavior without choosing to.
#[test]
fn without_the_seam_the_file_decides() {
    let (root, _) = retargeted("seam-off");
    let handler = Arc::new(Recording::default());
    reactor(&root, Arc::clone(&handler)).drain("jobs");
    assert_eq!(handler.fired(), vec!["urn:evil:target"]);
}

/// An allow-list host: the retargeted file is refused, the tuple is dead-lettered with a
/// note naming the target, the dead-letter hook hears it, and nothing fires.
#[test]
fn a_host_allow_list_refuses_a_retargeted_handler_loudly() {
    let (root, id) = retargeted("seam-refuse");
    let handler = Arc::new(Recording::default());
    let heard = Arc::new(Mutex::new(Vec::new()));
    let h = Arc::clone(&heard);
    let outcomes = reactor(&root, Arc::clone(&handler))
        .with_host_handler(|_, file| file.filter(|f| *f == LEGIT).map(String::from))
        .on_dead_letter(move |space, tuple, why| {
            h.lock()
                .unwrap()
                .push((space.to_string(), tuple.to_string(), why.to_string()))
        })
        .drain("jobs");
    assert!(handler.fired().is_empty(), "fired at {:?}", handler.fired());
    assert!(
        matches!(&outcomes[..], [(i, Outcome::Errored(why))] if *i == id && why.contains("urn:evil:target")),
        "{outcomes:?}"
    );
    assert!(root.join("jobs/error").join(format!("{id}.tuple")).exists());
    assert_eq!(heard.lock().unwrap().len(), 1);
}

/// The allow-list passes the legitimate target through.
#[test]
fn a_host_allow_list_fires_an_allowed_handler() {
    let root = scratch("seam-allow");
    std::fs::create_dir_all(root.join("jobs")).unwrap();
    std::fs::write(root.join("jobs/handler"), LEGIT).unwrap();
    let k = Kernel::new(Arc::new(space(root.clone())));
    let id = drop_tuple(
        &k,
        &Capability::scoped([CAP_OUT]),
        "urn:space:jobs",
        b"work",
    )
    .unwrap();
    let handler = Arc::new(Recording::default());
    let outcomes = reactor(&root, Arc::clone(&handler))
        .with_host_handler(|_, file| file.filter(|f| *f == LEGIT).map(String::from))
        .drain("jobs");
    assert_eq!(outcomes, vec![(id, Outcome::Handled)]);
    assert_eq!(handler.fired(), vec![LEGIT]);
}

/// A host-config host: the host's own target fires whatever the file says, and a space the
/// host names needs no file at all.
#[test]
fn a_host_configured_handler_ignores_the_file() {
    let (root, _) = retargeted("seam-config");
    let handler = Arc::new(Recording::default());
    reactor(&root, Arc::clone(&handler))
        .with_host_handler(|space, _| (space == "jobs").then(|| LEGIT.to_string()))
        .drain("jobs");
    assert_eq!(handler.fired(), vec![LEGIT]);

    let root = scratch("seam-config-nofile");
    let k = Kernel::new(Arc::new(space(root.clone())));
    drop_tuple(
        &k,
        &Capability::scoped([CAP_OUT]),
        "urn:space:jobs",
        b"work",
    )
    .unwrap();
    let handler = Arc::new(Recording::default());
    reactor(&root, Arc::clone(&handler))
        .with_host_handler(|space, _| (space == "jobs").then(|| LEGIT.to_string()))
        .drain("jobs");
    assert_eq!(handler.fired(), vec![LEGIT]);
}
