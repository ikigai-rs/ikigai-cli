//! Where the trial binaries keep their libp2p identity: the secret `urn:secret:{--key}`, in the
//! file keystore at `--keystore` (default `$IKIGAI_SECRETS`, else `~/.ikigai/secrets`).
//!
//! The binaries are the HOST here: they bind `ikigai-secret`'s space in a kernel of their own and
//! hand `ikigai_p2p::load_or_generate_keypair` that kernel, so the library reaches no disk itself
//! (Hypothesis H, ledger #2419). Before that change `--key` named a key FILE; the stored bytes are
//! the same, so copying an old key file into the keystore under the name keeps its PeerId (see
//! `docs/design/p2p-mobility-design.md`).

use std::sync::Arc;

use ikigai_core::{Capability, Iri, Kernel};
use ikigai_secret::FileBackend;
use libp2p::identity::Keypair;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The keypair stored as `name` in the keystore at `keystore` (or the default store), minted
/// and stored on the first run.
pub fn keypair(name: &str, keystore: Option<String>) -> Result<Keypair, BoxError> {
    if name.contains('/') {
        return Err(format!(
            "--key is the NAME of a secret in the keystore, not a file path (`{name}`): to keep an \
             old key file's identity, copy it into the keystore directory under a name and pass \
             that name (with --keystore <dir> if it is not the default store)"
        )
        .into());
    }
    let backend = match keystore {
        Some(dir) => FileBackend::new(dir),
        None => FileBackend::in_data_dir()?,
    };
    let kernel = Kernel::new(Arc::new(ikigai_secret::space(Arc::new(backend))));
    // Exactly this one secret: read it, and write it on the run that mints it.
    let capability = Capability::scoped([
        format!("urn:cap:secret:read:{name}"),
        format!("urn:cap:secret:write:{name}"),
    ]);
    let secret = Iri::parse(format!("urn:secret:{name}"))?;
    Ok(ikigai_p2p::load_or_generate_keypair(
        &kernel,
        &capability,
        &secret,
    )?)
}
