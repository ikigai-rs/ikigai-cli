//! The lockstep-pin invariant: every intra-workspace `path + version` dependency must name
//! the CURRENT `workspace.package.version`, not a floor.
//!
//! Why this is a test and not a convention. These crates are released together at one
//! version, so same-version-across-the-set is the only combination that has ever been
//! packaged, published or tested. A floor — the oldest published sibling whose API is
//! actually called — permits cargo to resolve `ikigai-cli 0.1.17` against `ikigai-ipc
//! 0.1.16`, which is not a weaker claim than the lockstep version but a DIFFERENT and
//! untested one. It is also unfalsifiable from inside the tree: the path dependency always
//! wins locally, so the version half is never exercised and every gate stays green over a
//! pin that no published version satisfies. The root manifest carries the full argument,
//! including why this is constitution rule 5 ("a pin states the true minimum API you use")
//! APPLIED to a lockstep set rather than broken by it.
//!
//! The pins drifted to eight versions behind over many releases and nothing noticed but a
//! comment — which had itself gone false, claiming they were "the matching lockstep
//! version" while they ranged 0.1.9 to 0.1.17. A comment cannot fail a build. This can.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use toml::Value;

/// Members deliberately OFF the lockstep, by name, each carrying the reason.
///
/// An entry here is not a licence to skip the check: an exempt member's pin is still checked,
/// against that member's OWN declared version, and the exemption is checked for staleness.
const EXEMPT: &[(&str, &str)] = &[(
    "ikigai-time",
    "the eighteenth member. `JobRegistry::new` taking the host's `Arc<dyn Clock>` was a \
     BREAKING change that earned a major bump the other members had no reason to take, so it \
     declares its own `version` and publishes on its own line. Pinning it at the workspace \
     version would name a release of ikigai-time that does not exist on crates.io.",
)];

/// The three dependency kinds a manifest can declare, in any of their table forms.
const KINDS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];

#[derive(Debug)]
struct Pin {
    manifest: String,
    table: String,
    dep: String,
    version: Option<String>,
}

impl Pin {
    fn site(&self) -> String {
        format!("{} [{}] {}", self.manifest, self.table, self.dep)
    }
}

fn workspace_root() -> PathBuf {
    // crates/ikigai-cli → crates → <workspace root>
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("ikigai-cli sits two levels below the workspace root")
        .to_path_buf()
}

fn parse(path: &Path) -> Value {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    text.parse::<Value>()
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Every dependency table in a manifest: the plain three, the workspace-inherited three, and
/// the target-gated ones. Written against the shapes rather than the names we happen to use
/// today, so a dependency moved into a `[dependencies.x]` table or behind a `cfg` is still seen.
fn dep_tables(doc: &Value) -> Vec<(String, &Value)> {
    let mut tables = Vec::new();
    for kind in KINDS {
        if let Some(t) = doc.get(kind) {
            tables.push((kind.to_string(), t));
        }
    }
    if let Some(ws) = doc.get("workspace") {
        for kind in KINDS {
            if let Some(t) = ws.get(kind) {
                tables.push((format!("workspace.{kind}"), t));
            }
        }
    }
    if let Some(Value::Table(targets)) = doc.get("target") {
        for (cfg, spec) in targets {
            for kind in KINDS {
                if let Some(t) = spec.get(kind) {
                    tables.push((format!("target.'{cfg}'.{kind}"), t));
                }
            }
        }
    }
    tables
}

/// Dependencies declared with a `path` — i.e. resolved from this tree, not the registry.
fn path_pins(manifest: &str, doc: &Value) -> Vec<Pin> {
    let mut pins = Vec::new();
    for (table, tbl) in dep_tables(doc) {
        let Some(map) = tbl.as_table() else { continue };
        for (dep, spec) in map {
            let Some(spec) = spec.as_table() else {
                continue;
            };
            if !spec.contains_key("path") {
                continue;
            }
            pins.push(Pin {
                manifest: manifest.to_string(),
                table: table.clone(),
                dep: dep.clone(),
                version: spec
                    .get("version")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            });
        }
    }
    pins
}

/// A member's own `version`: the literal it declares, or the workspace version it inherits.
fn declared_version(doc: &Value, workspace_version: &str) -> String {
    let pkg = doc.get("package").expect("member manifest has [package]");
    match pkg.get("version") {
        Some(Value::String(v)) => v.clone(),
        // `version.workspace = true` parses as a table.
        Some(Value::Table(_)) => workspace_version.to_string(),
        other => panic!("unreadable package.version: {other:?}"),
    }
}

#[test]
fn intra_workspace_pins_are_lockstep() {
    let root = workspace_root();
    let root_doc = parse(&root.join("Cargo.toml"));

    let workspace_version = root_doc["workspace"]["package"]["version"]
        .as_str()
        .expect("workspace.package.version is a string")
        .to_string();

    // Discovery below assumes the members glob. If that ever changes, this test would quietly
    // stop covering the members it missed, so make the assumption fail loudly instead.
    let members_glob = root_doc["workspace"]["members"]
        .as_array()
        .expect("workspace.members is an array");
    assert_eq!(
        members_glob.len(),
        1,
        "workspace.members is no longer the single `crates/*` glob this test walks; \
         teach `intra_workspace_pins_are_lockstep` the new layout before trusting it again"
    );
    assert_eq!(members_glob[0].as_str(), Some("crates/*"));

    // Every member: its own declared version, and every path pin it declares.
    let mut members: BTreeMap<String, String> = BTreeMap::new();
    let mut pins = path_pins("Cargo.toml", &root_doc);
    for entry in fs::read_dir(root.join("crates")).expect("crates/ is readable") {
        let dir = entry.expect("readable dir entry").path();
        let manifest = dir.join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let doc = parse(&manifest);
        let name = doc["package"]["name"]
            .as_str()
            .expect("package.name is a string")
            .to_string();
        members.insert(name, declared_version(&doc, &workspace_version));
        let label = format!(
            "crates/{}/Cargo.toml",
            dir.file_name().unwrap().to_string_lossy()
        );
        pins.extend(path_pins(&label, &doc));
    }

    // A parser that matches nothing passes every assertion below. Refuse to be that guard.
    assert!(
        pins.len() >= 10,
        "found only {} intra-workspace path dependencies — the manifests changed shape and \
         this test is no longer reading them",
        pins.len()
    );

    let exempt: BTreeMap<&str, &str> = EXEMPT.iter().copied().collect();
    let mut problems: Vec<String> = Vec::new();

    for pin in &pins {
        // A path dependency on something that is not a member of this workspace is either a
        // typo or a committed local path override, which the constitution forbids outright.
        let Some(member_version) = members.get(&pin.dep) else {
            problems.push(format!(
                "{}: path dependency on `{}`, which is not a member of this workspace. \
                 If this is a local cross-repo override it must live in .cargo/config.toml, \
                 never in a committed manifest.",
                pin.site(),
                pin.dep
            ));
            continue;
        };

        // A path-only sibling makes every crate above it unpublishable.
        let Some(version) = pin.version.as_deref() else {
            problems.push(format!(
                "{}: path dependency with no `version` — unpublishable.",
                pin.site()
            ));
            continue;
        };

        match exempt.get(pin.dep.as_str()) {
            Some(reason) => {
                if version != member_version {
                    problems.push(format!(
                        "{}: pinned at {version}, but `{}` declares {member_version}. \
                         It is exempt from the lockstep ({reason}) — which means its pin must \
                         track its OWN version, and this one no longer does.",
                        pin.site(),
                        pin.dep
                    ));
                }
            }
            None if version != workspace_version => problems.push(format!(
                "{}: pinned at {version}, workspace is {workspace_version}.",
                pin.site()
            )),
            None => {}
        }
    }

    // An exemption that has stopped being true is worse than no exemption: it reads as a
    // considered decision while covering nothing.
    for (name, reason) in EXEMPT {
        let Some(member_version) = members.get(*name) else {
            problems.push(format!(
                "EXEMPT lists `{name}`, which is not a member of this workspace — delete the entry."
            ));
            continue;
        };
        if member_version == &workspace_version {
            problems.push(format!(
                "EXEMPT lists `{name}` as off the lockstep ({reason}), but it now declares \
                 {member_version}, the same version as the workspace. It rejoined the lockstep: \
                 delete the exemption so the ordinary check covers it."
            ));
        }
        if !pins.iter().any(|p| p.dep.as_str() == *name) {
            problems.push(format!(
                "EXEMPT lists `{name}`, but nothing depends on it by path any more — delete the entry."
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "\n\nIntra-workspace sibling pins are out of lockstep:\n\n  {}\n\n\
         These crates are released together at one version, so a sibling pin states that \
         version — not a floor. A floor names a combination nothing has ever built, and no \
         local build can contradict it, because in-tree the path dependency always wins and \
         the version half is never exercised. See `[workspace.dependencies]` in the root \
         Cargo.toml for the full argument before \"fixing\" this by lowering a pin.\n\n\
         ⚠ RELEASE RITUAL: a lockstep bump edits {} sibling pins across Cargo.toml, \
         crates/ikigai-cli/Cargo.toml and crates/ikigai-embedded/Cargo.toml — not one \
         workspace.package.version line. This test is what makes those {} edits non-optional \
         rather than remembered; the last time they were merely remembered, they drifted \
         eight releases behind and only a (by then false) comment mentioned it.\n",
        problems.join("\n  "),
        pins.len() - EXEMPT.len(),
        pins.len() - EXEMPT.len(),
    );
}
