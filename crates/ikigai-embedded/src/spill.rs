//! **The REPL's spill facility** (ledger #2724): what `urn:stream:spill` writes through on the
//! kernel a REPL, a `-c` batch or a `.iki` script builds, so a one-shot body can be answered as
//! one that can be read again. The HTTP door installs its own (`serve --http`, ledger #2244);
//! before this the local kernels installed none, and the step was refused as unsupported.
//!
//! ikigai-fs's `FileSpill`, over `<config home>/spill/repl-<pid>`: a directory of this process's
//! own, because a `FileSpill` removes the spill files it finds in its directory when it opens
//! it, and two processes must never share one. Only under a config home that exists; never
//! `TMPDIR`. The directory is made (`0700`) at the first spill, not at start, so a batch that
//! never spills leaves nothing behind; the same first spill removes the `repl-<pid>`
//! directories of processes that have gone (their spill files, then the directory if that
//! empties it), since a process that exits leaves its own behind.
//!
//! The bound is core's: a request may write at most [`ikigai_core::DEFAULT_STREAM_SPILL`]
//! (1 GiB), its own `max-bytes` lower.
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use ikigai_core::{ByteStream, Error, Replay, Result, Spill};

/// The prefix of a REPL's spill directory's name; the process id follows it.
const PREFIX: &str = "repl-";

static ARMED: OnceLock<Option<Arc<ReplSpill>>> = OnceLock::new();

/// **Arm the spill facility for this process's local kernels**: `<config home>/spill/repl-<pid>`,
/// made at the first spill. Call once at start, before the first local kernel is built.
/// Without a config home there is nowhere to spill, and `urn:stream:spill` stays unsupported.
/// Idempotent.
pub fn arm() -> Option<Arc<dyn Spill>> {
    ARMED
        .get_or_init(|| {
            let home = crate::config::config_home().filter(|home| home.is_dir())?;
            Some(Arc::new(ReplSpill::new(
                home.join("spill"),
                std::process::id(),
            )))
        })
        .clone()
        .map(|spill| spill as Arc<dyn Spill>)
}

/// The facility [`arm`] armed, if any.
pub fn active() -> Option<Arc<dyn Spill>> {
    ARMED
        .get()
        .cloned()
        .flatten()
        .map(|spill| spill as Arc<dyn Spill>)
}

/// A `FileSpill` over `<parent>/repl-<pid>`, opened at the first spill.
struct ReplSpill {
    parent: PathBuf,
    pid: u32,
    opened: OnceLock<std::result::Result<ikigai_fs::FileSpill, String>>,
}

impl ReplSpill {
    fn new(parent: PathBuf, pid: u32) -> Self {
        ReplSpill {
            parent,
            pid,
            opened: OnceLock::new(),
        }
    }

    fn dir(&self) -> PathBuf {
        self.parent.join(format!("{PREFIX}{}", self.pid))
    }

    fn open(&self) -> std::result::Result<&ikigai_fs::FileSpill, String> {
        self.opened
            .get_or_init(|| {
                use std::os::unix::fs::DirBuilderExt;
                let dir = self.dir();
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&dir)
                    .map_err(|e| format!("make the spill directory `{}`: {e}", dir.display()))?;
                remove_gone(&self.parent, self.pid);
                ikigai_fs::FileSpill::new(&dir).map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(Clone::clone)
    }
}

#[async_trait]
impl Spill for ReplSpill {
    async fn spill(&self, body: ByteStream, max_bytes: u64) -> Result<Arc<dyn Replay>> {
        self.open()
            .map_err(Error::Endpoint)?
            .spill(body, max_bytes)
            .await
    }
}

/// Remove the `repl-<pid>` directories under `parent` whose process has gone: their spill files
/// (`FileSpill::new` removes exactly those), then the directory, which stays if anything else
/// is in it. A directory whose process may still run is never opened. Best effort: what cannot
/// be removed is left for the next sweep.
fn remove_gone(parent: &Path, own: u32) {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|name| name.strip_prefix(PREFIX))
            .and_then(|pid| pid.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == own || !entry.file_type().is_ok_and(|kind| kind.is_dir()) || !gone(pid) {
            continue;
        }
        let dir = entry.path();
        if ikigai_fs::FileSpill::new(&dir).is_ok() {
            let _ = std::fs::remove_dir(&dir);
        }
    }
}

/// Whether no process `pid` exists: `kill(pid, 0)` answers `ESRCH`. A process this user may
/// not signal (`EPERM`) exists.
fn gone(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 sends nothing; it only asks whether `pid` names a process.
    let answer = unsafe { libc::kill(pid, 0) };
    answer == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory unique to this case and process, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(case: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("iki-repl-spill-{}-{case}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A process id no process has: past the largest a Linux or macOS kernel hands out.
    const GONE: u32 = 99_999_999;

    #[test]
    fn the_directory_is_made_at_the_first_spill() {
        let scratch = Scratch::new("first");
        let spill = ReplSpill::new(scratch.0.join("spill"), std::process::id());
        assert!(!spill.dir().exists());
        spill.open().unwrap();
        assert!(spill.dir().is_dir());
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(spill.dir()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    /// Every bytes a reader of `replay` yields, from the start.
    fn read(replay: &dyn Replay) -> Vec<u8> {
        use futures::StreamExt;
        futures::executor::block_on(replay.open().collect::<Vec<_>>())
            .into_iter()
            .flat_map(|chunk| chunk.unwrap().to_vec())
            .collect()
    }

    #[test]
    fn a_spilled_body_is_read_again_and_its_file_goes_with_it() {
        let scratch = Scratch::new("replay");
        let spill = ReplSpill::new(scratch.0.join("spill"), std::process::id());
        let body: ByteStream = Box::pin(futures::stream::iter([
            Ok(ikigai_core::Bytes::from_static(b"one-shot ")),
            Ok(ikigai_core::Bytes::from_static(b"body")),
        ]));
        let replay = futures::executor::block_on(spill.spill(body, 1024)).unwrap();
        assert_eq!(read(&*replay), b"one-shot body");
        assert_eq!(read(&*replay), b"one-shot body");
        assert_eq!(std::fs::read_dir(spill.dir()).unwrap().count(), 1);
        drop(replay);
        assert_eq!(std::fs::read_dir(spill.dir()).unwrap().count(), 0);
    }

    #[test]
    fn a_body_past_the_bound_is_refused() {
        let scratch = Scratch::new("bound");
        let spill = ReplSpill::new(scratch.0.join("spill"), std::process::id());
        let body: ByteStream = Box::pin(futures::stream::iter([Ok(
            ikigai_core::Bytes::from_static(b"twelve bytes"),
        )]));
        let refused = futures::executor::block_on(spill.spill(body, 4));
        assert!(
            matches!(refused, Err(Error::OverBudget { .. })),
            "{:?}",
            refused.err()
        );
    }

    #[test]
    fn a_gone_process_directory_is_removed_and_a_live_one_kept() {
        let scratch = Scratch::new("sweep");
        let parent = scratch.0.join("spill");
        let gone_dir = parent.join(format!("{PREFIX}{GONE}"));
        let kept = parent.join(format!("{PREFIX}{GONE}-kept"));
        let other = parent.join("http-8080");
        // pid 1 always runs (and this user may not signal it): its directory is never opened.
        let live = parent.join(format!("{PREFIX}1"));
        for dir in [&gone_dir, &kept, &other, &live] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let orphan = format!("{}0123", ikigai_fs::SPILL_PREFIX);
        std::fs::write(gone_dir.join(&orphan), b"left behind").unwrap();
        std::fs::write(live.join(&orphan), b"still running").unwrap();
        let spill = ReplSpill::new(parent.clone(), std::process::id());
        spill.open().unwrap();
        assert!(!gone_dir.exists(), "a gone process's directory stays");
        assert!(
            live.join(&orphan).exists(),
            "a live process's file was removed"
        );
        assert!(kept.is_dir() && other.is_dir());
    }

    #[test]
    fn a_gone_process_directory_holding_other_files_is_kept() {
        let scratch = Scratch::new("other-files");
        let parent = scratch.0.join("spill");
        let dir = parent.join(format!("{PREFIX}{GONE}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("notes"), b"not a spill file").unwrap();
        ReplSpill::new(parent, std::process::id()).open().unwrap();
        assert!(dir.join("notes").exists());
    }

    #[test]
    fn this_process_is_not_gone() {
        assert!(!gone(std::process::id()));
        assert!(gone(GONE));
    }
}
