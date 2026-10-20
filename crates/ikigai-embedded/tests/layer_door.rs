//! A kernel that hosts layers serves the layer spaces and nothing else.
//!
//! [`ikigai_embedded::served_kernel_hosting`] with a layer host builds the door a collaborator
//! connects to. Its principals are outside participants whose grants name layer verbs only, so
//! the door's surface is the layers (`urn:layer:*`), the host-wide reads (`urn:layers:*`, among
//! them `urn:layers:me`) and the collaborations (`urn:collab:*`): never the general served
//! surface a public door carries (the intake doors, the airlock spaces, the decision and
//! block/label links, the passkey endpoints, the host's own resources, the demo endpoints, the
//! file module). These tests hold the kernel to that by STRUCTURE, under the root capability:
//! a name the layer door does not bind cannot be reached by any grant at all.
//!
//! Own process (integration binary): the file root is a process global, set once, first.

use std::path::{Path, PathBuf};

use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Error, Iri, Kernel, Request, Verb};
use ikigai_embedded::{served_kernel, served_kernel_hosting, ServedSurface};

/// The families a layer door binds. `urn:kernel:` is the kernel's own (the manifold, the
/// catalog), answered by every kernel and gated by its own capabilities.
const LAYER_DOOR_FAMILIES: [&str; 4] = ["urn:layer:", "urn:layers:", "urn:collab:", "urn:kernel:"];

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

const SHAPES: &str = r#"@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix ik: <https://ikigai-rs.dev/ns#> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix dcterms: <http://purl.org/dc/terms/> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

<urn:example:shape:message> a sh:NodeShape ;
  sh:targetClass ik:Message ;
  sh:closed true ;
  sh:ignoredProperties ( rdf:type ) ;
  sh:property [ sh:path ik:body ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:string ] ,
              [ sh:path prov:wasAttributedTo ; sh:minCount 1 ; sh:maxCount 1 ; sh:nodeKind sh:IRI ] ,
              [ sh:path dcterms:created ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:dateTime ] ,
              [ sh:path ik:seq ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:integer ] .
"#;

const CONTEXT: &str = r#"{ "@context": {
  "ik": "https://ikigai-rs.dev/ns#",
  "Message": "ik:Message", "body": "ik:body"
} }
"#;

/// One channel layer, `talk`, mounted by one collaboration, `pair`, for one participant.
fn configure(config: &Path) {
    write(config.join("layers/shapes.ttl"), SHAPES);
    write(config.join("layers/context.jsonld"), CONTEXT);
    write(
        config.join("layers/talk.toml"),
        "model = \"channel\"\nshapes = \"shapes.ttl\"\ncontext = \"context.jsonld\"\n",
    );
    write(
        config.join("participants.ttl"),
        "@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
         <urn:collab:participant:alice> a foaf:Person .\n",
    );
    write(
        config.join("collabs/pair.toml"),
        "[[mount]]\nlayer = \"talk\"\nalice = [\"read\", \"feed\", \"say\"]\n",
    );
}

/// Every non-kernel pattern `kernel` binds.
fn patterns(kernel: &Kernel) -> Vec<String> {
    kernel
        .entries()
        .expect("an enumerable root")
        .into_iter()
        .map(|e| e.pattern)
        .collect()
}

/// Every path under `dir`, so a test can say nothing was written there.
fn listing(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(next) = todo.pop() {
        for entry in std::fs::read_dir(&next).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                todo.push(path.clone());
            }
            out.push(path);
        }
    }
    out.sort();
    out
}

/// Ask `iri` with `verb` under the ROOT capability, with a small form body for a Sink.
fn ask(kernel: &Kernel, verb: Verb, iri: &str) -> Result<(), Error> {
    let mut request = Request::new(verb, Iri::parse(iri).expect("a probe IRI"));
    if verb == Verb::Sink {
        request = request.with_arg(
            "content",
            ArgRef::Inline(b"id=abcdefgh12&exp=99999999999&t=AAAA".to_vec()),
        );
    }
    block_on(kernel.issue(request, &Capability::root())).map(drop)
}

/// What the general served surface answers and a layer door must not: every endpoint the
/// security review reached on a layer door, and the protected ones beside them.
const PROBES: [(Verb, &str); 21] = [
    (Verb::Source, "urn:passkey:challenge"),
    (Verb::Source, "urn:passkey:register"),
    (Verb::Sink, "urn:passkey:register"),
    (Verb::Source, "urn:passkey:js"),
    (Verb::Source, "urn:decide:css"),
    (Verb::Sink, "urn:calendar-request:approve"),
    (Verb::Sink, "urn:contact-block"),
    (Verb::Sink, "urn:contact-label"),
    (Verb::Sink, "urn:contact:submit"),
    (Verb::Sink, "urn:booking:submit"),
    (Verb::Source, "urn:space:contact"),
    (Verb::Source, "urn:decisions"),
    (Verb::Source, "urn:client:anyone"),
    (Verb::Source, "urn:host:info"),
    (Verb::Source, "urn:host:identity"),
    (Verb::Source, "urn:host:posture"),
    (Verb::Source, "urn:host:demo"),
    (Verb::Source, "urn:demo:greeter"),
    (Verb::Source, "urn:data:page"),
    (Verb::Source, "urn:time:now"),
    (Verb::Source, "urn:file:decide.pub"),
];

#[test]
fn a_layer_door_binds_the_layer_spaces_and_nothing_else() {
    // The file root FIRST, before any kernel: the general served surface below binds the file
    // module, the spaces and the client registry to it.
    let scratch = std::env::temp_dir().join(format!("iki-layer-door-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let files = scratch.join("files");
    std::fs::create_dir_all(&files).unwrap();
    ikigai_embedded::set_file_root(files.clone());
    let config = scratch.join("config");
    configure(&config);

    // The general served surface binds every probe: so a probe the layer door does not answer
    // is a probe of something real, never a typo that passes by resolving nowhere.
    let general = served_kernel("Test (QUIC)", ServedSurface::default());
    for (verb, iri) in PROBES {
        if let Err(Error::Unresolved(_)) = ask(&general, verb, iri) {
            panic!("the general served surface binds `{iri}`, or the probe is wrong")
        }
    }

    let before = listing(&files);
    // The state is sealed at rest (ikigai-layers 0.3.0): a throwaway key, as `age-keygen -o`.
    std::fs::write(
        scratch.join("state.key"),
        age::secrecy::ExposeSecret::expose_secret(&age::x25519::Identity::generate().to_string()),
    )
    .unwrap();
    let key = ikigai_layers::StateKey::load(scratch.join("state.key")).expect("an age identity");
    let host =
        ikigai_layers::Host::open(&config, scratch.join("state"), &key).expect("the host opens");
    let door = served_kernel_hosting(
        "Test (QUIC)",
        ServedSurface::default(),
        Vec::new(),
        Some(&host),
    );

    // By structure: every binding is a layer family.
    let bound = patterns(&door);
    assert!(
        bound.iter().any(|p| p == "urn:layer:talk:say")
            && bound.iter().any(|p| p == "urn:layers:me"),
        "the layers and the host-wide reads are bound: {bound:?}"
    );
    for pattern in &bound {
        assert!(
            LAYER_DOOR_FAMILIES.iter().any(|f| pattern.starts_with(f)),
            "a layer door binds only the layer families, not `{pattern}`: {bound:?}"
        );
    }
    // And by resolution, under ROOT: nothing a grant could ever open.
    for (verb, iri) in PROBES {
        match ask(&door, verb, iri) {
            Err(Error::Unresolved(_)) => {}
            other => panic!("a layer door resolves nothing at `{iri}` ({verb:?}), got {other:?}"),
        }
    }
    assert_eq!(
        listing(&files),
        before,
        "the layer door wrote nothing under the file root"
    );
    drop(door);
    drop(host);
    let _ = std::fs::remove_dir_all(&scratch);
}
