//! Shared fixtures for the intray's integration tests (audit round 5, ledger #877).
#![allow(dead_code)] // each test binary uses a different subset of these helpers

use futures::executor::block_on;
use ikigai_core::{
    ArgRef, Capability, Error, Iri, Kernel, ReprType, Representation, Request, SpaceEntry, Verb,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

pub fn iri(s: &str) -> Iri {
    Iri::parse(s).unwrap()
}

/// A fresh, empty scratch root unique to this test and this process.
pub fn scratch(sub: &str) -> PathBuf {
    let root = std::env::temp_dir()
        .join("ikigai-intray-it")
        .join(format!("{sub}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    root
}

/// Drop `content` into the space at `target`, returning the tuple id.
pub fn drop_tuple(
    k: &Kernel,
    cap: &Capability,
    target: &str,
    content: &[u8],
) -> Result<String, Error> {
    block_on(k.issue(
        Request::new(Verb::Sink, iri(target)).with_arg("content", ArgRef::Inline(content.to_vec())),
        cap,
    ))
    .map(|r| String::from_utf8(r.bytes).unwrap())
}

/// A handler double that counts its calls and answers from a script (popped, so the LAST
/// element is the first answer); an exhausted script answers the empty string.
pub struct Counting {
    pub calls: AtomicUsize,
    pub answers: Mutex<Vec<&'static str>>,
}

impl Counting {
    pub fn new() -> Self {
        Counting {
            calls: AtomicUsize::new(0),
            answers: Mutex::new(Vec::new()),
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ikigai_resolve::Resolver for Counting {
    fn issue(
        &self,
        request: Request,
    ) -> Result<(Representation, ikigai_resolve::CacheStatus), Error> {
        self.issue_as(request, &Capability::root())
    }
    fn issue_as(
        &self,
        _request: Request,
        _capability: &Capability,
    ) -> Result<(Representation, ikigai_resolve::CacheStatus), Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let said = self.answers.lock().unwrap().pop().unwrap_or("");
        Ok((
            Representation::new(ReprType::new("text/plain"), said.as_bytes().to_vec()),
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
