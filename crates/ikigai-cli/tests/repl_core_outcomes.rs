//! The engine's REPL display of core's two resolution outcomes (ledger #3151): a `Gone` prints
//! as its error text and a redirect answer prints its JSON, the same text a face reads. Run
//! through the engine the binary links, not a copy of its rules.
use ikigai_core::{
    EndpointSpace, Error, Exact, FnEndpoint, Invocation, Kernel, Redirect, RedirectStatus,
    Representation,
};
use ikigai_engine::{Action, Engine};
use std::sync::Arc;

fn engine() -> Engine {
    let gone = FnEndpoint::new("gone", |_: &Invocation<'_>| {
        Err::<Representation, _>(Error::Gone("urn:t:gone was retired in 2024".into()))
    });
    let moved = FnEndpoint::new("moved", |_: &Invocation<'_>| {
        Ok(Representation::redirect(
            Redirect::new(RedirectStatus::SeeOther, "https://example.org/about").unwrap(),
        ))
    });
    let space = EndpointSpace::new()
        .bind(Exact::new("urn:t:gone"), gone)
        .bind(Exact::new("urn:t:moved"), moved);
    Engine::new(Arc::new(Kernel::new(Arc::new(space))))
}

fn result(action: Action) -> Result<String, String> {
    match action {
        Action::Output(entry) => entry.result,
        _ => panic!("expected output"),
    }
}

#[test]
fn a_gone_prints_as_its_error_text() {
    assert_eq!(
        result(engine().eval("source urn:t:gone")),
        Err("gone: urn:t:gone was retired in 2024".to_string())
    );
}

#[test]
fn a_redirect_answer_prints_its_json() {
    assert_eq!(
        result(engine().eval("source urn:t:moved")),
        Ok(r#"{"status":303,"location":"https://example.org/about"}"#.to_string())
    );
}
