//! Re-encoding the settled stages, the file mode a space creates with, and the tuple id a
//! codec decodes with (ledger #2126).
//!
//! The codec is the same test double as `tests/codec.rs`: a one-byte key in front of a body
//! XORed with it, which decodes under ANY key and is current only under its own.

mod common;

use common::{drop_tuple, iri, scratch};
use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, EndpointSpace, Error, Kernel, Request, UriTemplate, Verb};
use ikigai_intray::{
    tuple_id, SpaceEndpoint, TupleCodec, CAP_OUT, CAP_READ, CAP_TAKE, ERROR_DIR, INBOX_DIR,
    OUTBOX_DIR, PROCESSING_DIR, SPACE_TEMPLATE,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MARK: &[u8] = b"XOR1";

struct Xor {
    key: u8,
}

impl TupleCodec for Xor {
    fn encode(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = MARK.to_vec();
        out.push(self.key);
        out.extend(plain.iter().map(|b| b ^ self.key));
        Ok(out)
    }
    fn decode(&self, stored: &[u8]) -> Result<Vec<u8>, String> {
        let rest = stored
            .strip_prefix(MARK)
            .ok_or("no XOR1 marker: not a sealed tuple")?;
        let (&key, body) = rest.split_first().ok_or("no key byte")?;
        Ok(body.iter().map(|b| b ^ key).collect())
    }
    fn is_current(&self, stored: &[u8]) -> bool {
        stored.strip_prefix(MARK).and_then(|r| r.first()) == Some(&self.key)
    }
}

fn sealed(key: u8, plain: &[u8]) -> Vec<u8> {
    Xor { key }.encode(plain).unwrap()
}

fn space(root: &Path, key: u8) -> SpaceEndpoint {
    SpaceEndpoint::new(root.to_path_buf()).with_codec(Arc::new(Xor { key }))
}

fn stage(root: &Path, stage: &str) -> PathBuf {
    root.join("jobs").join(stage)
}

/// Put `stored` in `stage` under its own hash, and answer the id.
fn plant(root: &Path, at: &str, stored: &[u8]) -> String {
    let id = tuple_id(stored);
    let dir = stage(root, at);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{id}.tuple")), stored).unwrap();
    id
}

/// Every file under `root`, by path relative to it, with its bytes.
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, into: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                walk(base, &p, into);
            } else {
                let rel = p.strip_prefix(base).unwrap().to_string_lossy().to_string();
                into.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    let mut files = BTreeMap::new();
    walk(root, root, &mut files);
    files
}

#[test]
fn settled_tuples_are_stored_again_under_new_ids_with_their_notes() {
    let root = scratch("settled-move");
    let dead = plant(&root, ERROR_DIR, &sealed(1, b"dead"));
    std::fs::write(stage(&root, ERROR_DIR).join(format!("{dead}.err")), "boom").unwrap();
    let done = plant(&root, OUTBOX_DIR, &sealed(1, b"done"));
    let said = sealed(1, b"the handler said done");
    std::fs::write(stage(&root, OUTBOX_DIR).join(format!("{done}.out")), &said).unwrap();
    let running = plant(&root, PROCESSING_DIR, &sealed(1, b"running"));

    let moved = space(&root, 2).reencode_settled("jobs").unwrap();

    let new_dead = tuple_id(&sealed(2, b"dead"));
    let new_done = tuple_id(&sealed(2, b"done"));
    let new_running = tuple_id(&sealed(2, b"running"));
    let names: Vec<_> = moved
        .iter()
        .map(|r| (r.stage, r.was.clone(), r.now.clone()))
        .collect();
    assert_eq!(
        names,
        vec![
            (
                ERROR_DIR,
                format!("{dead}.tuple"),
                format!("{new_dead}.tuple")
            ),
            (
                OUTBOX_DIR,
                format!("{done}.tuple"),
                format!("{new_done}.tuple")
            ),
            (
                PROCESSING_DIR,
                format!("{running}.tuple"),
                format!("{new_running}.tuple")
            ),
            // The `.out` note followed its tuple and was sealed again there.
            (OUTBOX_DIR, format!("{done}.out"), format!("{new_done}.out")),
        ]
    );

    let files = tree(&root);
    let rel = |at: &str, file: String| format!("jobs/{at}/{file}");
    assert_eq!(
        files.keys().cloned().collect::<Vec<_>>(),
        {
            let mut want = vec![
                rel(ERROR_DIR, format!("{new_dead}.tuple")),
                rel(ERROR_DIR, format!("{new_dead}.err")),
                rel(OUTBOX_DIR, format!("{new_done}.tuple")),
                rel(OUTBOX_DIR, format!("{new_done}.out")),
                rel(PROCESSING_DIR, format!("{new_running}.tuple")),
            ];
            want.sort();
            want
        },
        "the old files are gone, and no staging file is left behind"
    );
    assert_eq!(
        files[&rel(ERROR_DIR, format!("{new_dead}.err"))],
        b"boom",
        "an .err note is renamed, never re-encoded"
    );
    assert_eq!(
        files[&rel(OUTBOX_DIR, format!("{new_done}.out"))],
        sealed(2, b"the handler said done"),
        "an .out note is sealed again to the current key"
    );
    assert_eq!(
        files[&rel(PROCESSING_DIR, format!("{new_running}.tuple"))],
        sealed(2, b"running")
    );

    assert!(
        space(&root, 2).reencode_settled("jobs").unwrap().is_empty(),
        "once current, nothing moves"
    );
}

#[test]
fn a_corrupt_settled_tuple_keeps_its_name() {
    let root = scratch("settled-corrupt");
    let dir = stage(&root, ERROR_DIR);
    std::fs::create_dir_all(&dir).unwrap();
    // Named by a hash it does not have: a take or a reactor already holds it as corrupt.
    let name = tuple_id(b"something else");
    std::fs::write(dir.join(format!("{name}.tuple")), sealed(1, b"torn")).unwrap();
    std::fs::write(dir.join(format!("{name}.err")), "corrupt: ...").unwrap();

    let moved = space(&root, 2).reencode_settled("jobs").unwrap();

    assert_eq!(moved.len(), 1);
    assert_eq!(moved[0].was, format!("{name}.tuple"));
    assert_eq!(moved[0].now, moved[0].was, "the same name");
    assert_eq!(
        std::fs::read(dir.join(format!("{name}.tuple"))).unwrap(),
        sealed(2, b"torn"),
        "sealed again in place"
    );
    assert_eq!(tree(&root).len(), 2, "the tuple and its note, nothing else");
}

#[test]
fn a_settled_tuple_that_does_not_decode_refuses_with_nothing_changed() {
    let root = scratch("settled-undecodable");
    plant(&root, ERROR_DIR, &sealed(1, b"fine"));
    let bad = plant(&root, OUTBOX_DIR, b"never sealed");
    let before = tree(&root);

    let err = space(&root, 2).reencode_settled("jobs").unwrap_err();

    match &err {
        Error::Conflict(why) => assert!(why.contains(&bad), "names the tuple: {why}"),
        other => panic!("a typed Conflict, not {other:?}"),
    }
    assert_eq!(tree(&root), before, "nothing moved");
}

#[test]
fn a_plaintext_out_note_refuses_with_nothing_changed() {
    let root = scratch("settled-plain-note");
    let done = plant(&root, OUTBOX_DIR, &sealed(1, b"done"));
    // What a reactor writes: the handler's answer as it said it.
    std::fs::write(stage(&root, OUTBOX_DIR).join(format!("{done}.out")), "ok").unwrap();
    let before = tree(&root);

    let err = space(&root, 2).reencode_settled("jobs").unwrap_err();

    match &err {
        Error::Conflict(why) => {
            assert!(why.contains(&done) && why.contains(".out"), "{why}")
        }
        other => panic!("a typed Conflict, not {other:?}"),
    }
    assert_eq!(tree(&root), before, "nothing moved");
}

#[test]
fn a_rerun_after_a_stop_part_way_leaves_one_copy() {
    let root = scratch("settled-rerun");
    // A stop between writing the new file and removing the old: the tuple twice.
    let old = plant(&root, ERROR_DIR, &sealed(1, b"twice"));
    let new = plant(&root, ERROR_DIR, &sealed(2, b"twice"));
    std::fs::write(stage(&root, ERROR_DIR).join(format!("{new}.err")), "why").unwrap();
    assert_ne!(old, new);

    space(&root, 2).reencode_settled("jobs").unwrap();

    let files: Vec<_> = tree(&root).into_keys().collect();
    assert_eq!(
        files,
        vec![
            format!("jobs/{ERROR_DIR}/{new}.err"),
            format!("jobs/{ERROR_DIR}/{new}.tuple"),
        ]
    );
}

#[test]
fn the_inbox_is_left_to_reencode() {
    let root = scratch("settled-inbox");
    let pending = plant(&root, INBOX_DIR, &sealed(1, b"pending"));

    assert!(space(&root, 2).reencode_settled("jobs").unwrap().is_empty());
    assert!(stage(&root, INBOX_DIR)
        .join(format!("{pending}.tuple"))
        .is_file());
}

#[test]
fn a_space_name_must_be_one_segment() {
    let root = scratch("settled-name");
    assert!(matches!(
        space(&root, 2).reencode_settled("../x"),
        Err(Error::InvalidArgument { .. })
    ));
}

/// A codec that records the id it is asked to decode, and refuses one of them by name.
struct Named {
    seen: Mutex<Vec<String>>,
    refuse: String,
}

impl TupleCodec for Named {
    fn encode(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        Ok(plain.to_vec())
    }
    fn decode(&self, _stored: &[u8]) -> Result<Vec<u8>, String> {
        Err("decode without an id is never called".to_string())
    }
    fn decode_tuple(&self, id: &str, stored: &[u8]) -> Result<Vec<u8>, String> {
        self.seen.lock().unwrap().push(id.to_string());
        if id == self.refuse {
            return Err(format!("{id}.tuple was sealed to a key this host lost"));
        }
        Ok(stored.to_vec())
    }
}

fn all() -> Capability {
    Capability::scoped([CAP_OUT, CAP_READ, CAP_TAKE])
}

fn kernel_with(endpoint: SpaceEndpoint) -> Kernel {
    Kernel::new(Arc::new(
        EndpointSpace::new().bind(UriTemplate::parse(SPACE_TEMPLATE).unwrap(), endpoint),
    ))
}

#[test]
fn decode_is_given_the_tuple_id_and_the_reason_comes_last() {
    let root = scratch("settled-decode-id");
    let refuse = tuple_id(b"lost");
    let codec = Arc::new(Named {
        seen: Mutex::new(Vec::new()),
        refuse: refuse.clone(),
    });
    let k = kernel_with(SpaceEndpoint::new(root.clone()).with_codec(codec.clone()));
    let id = drop_tuple(&k, &all(), "urn:space:jobs", b"kept").unwrap();
    drop_tuple(&k, &all(), "urn:space:jobs", b"lost").unwrap();

    let rd = |tuple: &str| {
        block_on(
            k.issue(
                Request::new(Verb::Source, iri("urn:space:jobs"))
                    .with_arg("tuple", ArgRef::Inline(tuple.as_bytes().to_vec())),
                &all(),
            ),
        )
    };
    assert_eq!(rd(&id).unwrap().bytes, b"kept");
    assert_eq!(*codec.seen.lock().unwrap(), vec![id.clone()]);

    let err = rd(&refuse).unwrap_err();
    let Error::Conflict(why) = &err else {
        panic!("a typed Conflict, not {err:?}");
    };
    assert_eq!(
        why,
        &format!(
            "space `jobs`: tuple `{refuse}` does not decode with this space's codec, so it was \
             not read: {refuse}.tuple was sealed to a key this host lost"
        )
    );
}

/// A codec that implements only `decode` still works: the default `decode_tuple` calls it.
#[test]
fn a_codec_without_decode_tuple_is_unchanged() {
    struct Old;
    impl TupleCodec for Old {
        fn encode(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
            Ok([b"o:".as_slice(), plain].concat())
        }
        fn decode(&self, stored: &[u8]) -> Result<Vec<u8>, String> {
            stored
                .strip_prefix(b"o:")
                .map(<[u8]>::to_vec)
                .ok_or_else(|| "no o: prefix".to_string())
        }
    }
    assert_eq!(Old.decode_tuple("any", b"o:x").unwrap(), b"x");
    let root = scratch("settled-old-codec");
    let k = kernel_with(SpaceEndpoint::new(root).with_codec(Arc::new(Old)));
    let id = drop_tuple(&k, &all(), "urn:space:jobs", b"x").unwrap();
    let taken = block_on(
        k.issue(
            Request::new(Verb::Delete, iri("urn:space:jobs"))
                .with_arg("tuple", ArgRef::Inline(id.into_bytes())),
            &all(),
        ),
    )
    .unwrap();
    assert_eq!(taken.bytes, b"x");
}

#[cfg(unix)]
mod modes {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// Every entry under `root` (and `root` itself), with its mode.
    fn modes(root: &Path) -> Vec<(PathBuf, bool, u32)> {
        fn walk(dir: &Path, into: &mut Vec<(PathBuf, bool, u32)>) {
            into.push((dir.to_path_buf(), true, mode(dir)));
            for entry in std::fs::read_dir(dir).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() {
                    walk(&p, into);
                } else {
                    into.push((p.clone(), false, mode(&p)));
                }
            }
        }
        let mut all = Vec::new();
        walk(root, &mut all);
        all
    }

    // 0660/0770, not 0600/0700: a usual umask (022) would narrow these to 0640/0750, so the
    // test also shows the mode is set exactly rather than left to the umask.
    const FILE: u32 = 0o660;
    const DIR: u32 = 0o770;

    #[test]
    fn every_file_and_directory_a_space_creates_has_the_chosen_mode() {
        let root = scratch("settled-modes");
        let endpoint = |key| space(&root, key).with_modes(FILE, DIR);
        let k = kernel_with(endpoint(1));
        let first = drop_tuple(&k, &all(), "urn:space:jobs", b"one").unwrap();
        drop_tuple(&k, &all(), "urn:space:jobs", b"two").unwrap();
        // A take, which stages its claim in `.taking/`.
        block_on(
            k.issue(
                Request::new(Verb::Delete, iri("urn:space:jobs"))
                    .with_arg("tuple", ArgRef::Inline(first.into_bytes())),
                &all(),
            ),
        )
        .unwrap();
        // A take of a file that is not its tuple: quarantined to `error/` with an `.err` note.
        // The planted file is the test's, so it is given the mode itself.
        let corrupt = tuple_id(b"not this");
        let planted = stage(&root, INBOX_DIR).join(format!("{corrupt}.tuple"));
        std::fs::write(&planted, sealed(1, b"torn")).unwrap();
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(FILE)).unwrap();
        let _ = block_on(
            k.issue(
                Request::new(Verb::Delete, iri("urn:space:jobs"))
                    .with_arg("tuple", ArgRef::Inline(corrupt.clone().into_bytes())),
                &all(),
            ),
        );
        assert!(stage(&root, ERROR_DIR)
            .join(format!("{corrupt}.err"))
            .is_file());
        // Both re-encodings, under a new key.
        assert_eq!(endpoint(2).reencode("jobs").unwrap().len(), 1);
        assert_eq!(endpoint(2).reencode_settled("jobs").unwrap().len(), 1);

        let seen = modes(&root);
        assert!(seen.iter().any(|(_, dir, _)| !dir), "files were made");
        for (path, is_dir, got) in seen {
            let want = if is_dir { DIR } else { FILE };
            assert_eq!(got, want, "{} is {got:o}, not {want:o}", path.display());
        }
    }

    #[test]
    fn without_a_mode_the_umask_decides_as_before() {
        let root = scratch("settled-no-modes");
        let k = kernel_with(space(&root, 1));
        let id = drop_tuple(&k, &all(), "urn:space:jobs", b"one").unwrap();
        let inbox = stage(&root, INBOX_DIR);
        let witness = inbox.join("witness");
        std::fs::write(&witness, b"w").unwrap();
        std::fs::create_dir(inbox.join("witness-dir")).unwrap();
        assert_eq!(mode(&inbox.join(format!("{id}.tuple"))), mode(&witness));
        assert_eq!(mode(&inbox), mode(&inbox.join("witness-dir")));
    }
}
