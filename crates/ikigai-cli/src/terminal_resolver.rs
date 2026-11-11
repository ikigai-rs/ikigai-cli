//! Terminal face policy, applied only to the CLI engine's requests.
//!
//! Runbook pages default to HTML for browsers. A terminal asks for their text face
//! when the caller supplies no `as`, after parsing and before cache lookup/resolution.
//! The underlying kernel, HTTP door, and nested endpoint requests keep their defaults.

use std::sync::Arc;

use async_trait::async_trait;
use ikigai_core::{
    ArgRef, Body, Capability, Error, Provenance, Representation, Request, Scope, SpaceEntry,
    Tracer, Verb,
};
use ikigai_resolve::{CacheStatus, Resolver, RunContext};

pub struct TerminalResolver<R>(pub R);

fn terminal_request(mut request: Request) -> Request {
    if request.verb == Verb::Source
        && request.target.as_str().starts_with("urn:runbook:")
        && request.target.as_str() != "urn:runbook:script"
        && !request.args.contains_key("as")
    {
        request
            .args
            .insert("as".into(), ArgRef::Inline(b"text/plain".to_vec()));
    }
    request
}

#[async_trait]
impl<R: Resolver> Resolver for TerminalResolver<R> {
    fn issue(&self, request: Request) -> Result<(Representation, CacheStatus), Error> {
        self.0.issue(terminal_request(request))
    }

    fn issue_as(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.0.issue_as(terminal_request(request), capability)
    }

    fn issue_as_in_run(
        &self,
        request: Request,
        capability: &Capability,
        run: &RunContext,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.0
            .issue_as_in_run(terminal_request(request), capability, run)
    }

    async fn issue_as_async(
        &self,
        request: Request,
        capability: &Capability,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.0
            .issue_as_async(terminal_request(request), capability)
            .await
    }

    async fn issue_body_as_in_run(
        &self,
        request: Request,
        capability: &Capability,
        run: &RunContext,
    ) -> Result<(Representation<Body>, CacheStatus), Error> {
        self.0
            .issue_body_as_in_run(terminal_request(request), capability, run)
            .await
    }

    async fn issue_as_async_with_incoming(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Provenance,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.0
            .issue_as_async_with_incoming(terminal_request(request), capability, incoming)
            .await
    }

    async fn issue_as_async_in(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Option<Provenance>,
        scope: Scope,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.0
            .issue_as_async_in(terminal_request(request), capability, incoming, scope)
            .await
    }

    async fn issue_attached_in(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Option<Provenance>,
        scope: Scope,
        attach: Option<(String, Body)>,
    ) -> Result<(Representation, CacheStatus), Error> {
        self.0
            .issue_attached_in(
                terminal_request(request),
                capability,
                incoming,
                scope,
                attach,
            )
            .await
    }

    async fn issue_body_attached_in(
        &self,
        request: Request,
        capability: &Capability,
        incoming: Option<Provenance>,
        scope: Scope,
        attach: Option<(String, Body)>,
    ) -> Result<(Representation<Body>, CacheStatus), Error> {
        self.0
            .issue_body_attached_in(
                terminal_request(request),
                capability,
                incoming,
                scope,
                attach,
            )
            .await
    }

    fn set_tracer(&self, tracer: Arc<dyn Tracer>) {
        self.0.set_tracer(tracer);
    }

    fn clear_tracer(&self) {
        self.0.clear_tracer();
    }

    fn is_cached(&self, request: &Request, capability: &Capability) -> bool {
        self.0
            .is_cached(&terminal_request(request.clone()), capability)
    }

    fn is_cached_in(&self, request: &Request, capability: &Capability, scope: &Scope) -> bool {
        self.0
            .is_cached_in(&terminal_request(request.clone()), capability, scope)
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        self.0.entries()
    }

    fn try_entries(&self) -> Result<Option<Vec<SpaceEntry>>, Error> {
        self.0.try_entries()
    }

    fn transport(&self) -> String {
        self.0.transport()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::Iri;

    #[test]
    fn only_untyped_runbook_page_sources_get_a_default() {
        for (verb, target) in [
            (Verb::Meta, "urn:runbook:basics"),
            (Verb::Sink, "urn:runbook:basics"),
            (Verb::Source, "urn:runbook:script"),
            (Verb::Source, "urn:diagram:kernel"),
        ] {
            let request = Request::new(verb, Iri::parse(target).unwrap());
            assert_eq!(terminal_request(request.clone()), request);
        }
        for face in ["text/html", "application/json", "", "unsupported/type"] {
            let request = Request::new(Verb::Source, Iri::parse("urn:runbook:basics").unwrap())
                .with_arg("as", ArgRef::Inline(face.as_bytes().to_vec()));
            assert_eq!(terminal_request(request.clone()), request);
        }
    }

    #[test]
    fn cache_probes_use_the_same_face_as_resolution() {
        use ikigai_core::{EndpointSpace, Exact, FnEndpoint, Kernel, ReprType};

        let kernel = Kernel::new(Arc::new(EndpointSpace::new().bind(
            Exact::new("urn:runbook:basics"),
            FnEndpoint::new("page", |inv: &ikigai_core::Invocation<'_>| {
                assert_eq!(inv.inline_str("as").unwrap(), "text/plain");
                Ok(Representation::new(ReprType::new("text/plain"), b"page".to_vec()).cacheable())
            }),
        )));
        let resolver = TerminalResolver(kernel);
        let request = Request::new(Verb::Source, Iri::parse("urn:runbook:basics").unwrap());
        let cap = Capability::root();
        assert!(!resolver.is_cached(&request, &cap));
        resolver.issue_as(request.clone(), &cap).unwrap();
        assert!(resolver.is_cached(&request, &cap));
        assert!(resolver.is_cached_in(&request, &cap, &Scope::default()));
        assert!(!resolver.0.is_cached(&request, &cap));
    }
}
