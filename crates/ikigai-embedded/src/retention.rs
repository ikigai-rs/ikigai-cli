//! Outbox retention for reactive spaces (ledger #3687).
//!
//! A reactor moves a tuple its handler answered from `inbox/` to `<space>/outbox/<id>.tuple`,
//! with an `<id>.out` note of what the handler said beside it. Nothing ever removed either, so
//! every handled tuple and its note stayed on disk forever, and some of them hold a stranger's
//! text (a contact inquiry). This module is the host's retention for that outbox: per space,
//! OFF unless the operator turns it on.
//!
//! **Configuration.** One file per space, `<config home>/space-retention/<space>`, holding
//! one duration: `7d`, `36h`, `90m` (days, hours or minutes, a whole number above zero). It
//! lives in the CONFIG home, for the same reason as `space-authority/` and `space-handler/`:
//! the space's own directory sits beside the `inbox` a dropper writes into, and a dropper must
//! not be able to decide what the host deletes. Blank lines and `#` comments are ignored;
//! `off` (or a file with no duration in it, or no file) keeps everything. A file the host
//! cannot read as a duration keeps everything too, and is named on stderr once per sweep: a
//! typo must never delete more than the operator meant.
//!
//! **What is deleted.** Only a HANDLED tuple: a regular file `outbox/<id>.tuple` whose receipt
//! is older than the space's retention, and then its `outbox/<id>.out` note. Never anything in
//! `inbox/` (pending), `.processing/` (claimed, not settled) or `error/` (dead letters, which
//! the heartbeat reports and `retry=` re-runs). A space that needs its outbox (training reads
//! one today) simply has no retention file until that dependency is gone.
//!
//! **Receipt.** The reactor writes the note and THEN renames the tuple into `outbox/`, so the
//! receipt is the latest of: the note's modification time, the tuple's modification time, and
//! (on unix) the tuple's status-change time, which the rename into `outbox/` sets. Taking the
//! latest means an outbox entry is never judged older than it is.
//!
//! **Order.** The tuple goes first, then the note: a reader that finds the tuple still finds
//! its whole note beside it (the reactor's own invariant, ledger #1595). The note is removed
//! only if it is still the note that was judged old, so a re-handled tuple of the same id
//! (identical bytes dropped again) that lands between the two removals keeps its new answer.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The directory name under the config home that holds per-space outbox retention.
pub const SPACE_RETENTION_DIR: &str = "space-retention";

/// How often a reactive host sweeps its spaces' outboxes.
pub const SWEEP_EVERY: Duration = Duration::from_secs(3600);

/// The outbox stage a reactor settles a handled tuple into (`ikigai_intray::OUTBOX_DIR`).
const OUTBOX: &str = ikigai_intray::OUTBOX_DIR;

/// What one `space-retention/<space>` file says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retention {
    /// Keep every handled tuple (no file, `off`, or no duration in it).
    Off,
    /// Delete a handled tuple and its note this long after the handler's receipt.
    After(Duration),
    /// The file says something that is not a duration; everything is kept.
    Unreadable(String),
}

/// Read one retention file's text. See the module note for the grammar.
pub fn parse_retention(text: &str) -> Retention {
    let mut lines = text
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty());
    let Some(spec) = lines.next() else {
        return Retention::Off;
    };
    if lines.next().is_some() {
        return Retention::Unreadable("more than one duration".to_string());
    }
    if spec.eq_ignore_ascii_case("off") {
        return Retention::Off;
    }
    let (digits, unit) = spec.split_at(spec.len() - spec.chars().last().map_or(0, char::len_utf8));
    let seconds_per = match unit {
        "d" => 86_400,
        "h" => 3_600,
        "m" => 60,
        _ => {
            return Retention::Unreadable(format!(
                "`{spec}` is not a duration (a whole number with d, h or m, such as 7d)"
            ))
        }
    };
    match digits.parse::<u64>() {
        Ok(n) if n > 0 => match n.checked_mul(seconds_per) {
            Some(secs) => Retention::After(Duration::from_secs(secs)),
            None => Retention::Unreadable(format!("`{spec}` is too long")),
        },
        _ => Retention::Unreadable(format!(
            "`{spec}` is not a duration (a whole number above zero with d, h or m, such as 7d)"
        )),
    }
}

/// The retention configured for `space` in `retention_dir`; [`Retention::Off`] when there is
/// no file.
pub fn retention_for(retention_dir: &Path, space: &str) -> Retention {
    match std::fs::read_to_string(retention_dir.join(space)) {
        Ok(text) => parse_retention(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Retention::Off,
        Err(e) => Retention::Unreadable(format!("cannot be read: {e}")),
    }
}

/// What one sweep did, per space it looked at.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Swept {
    /// `(space, ids)` for each space at least one handled tuple was deleted from.
    pub expired: Vec<(String, Vec<String>)>,
    /// One line for each retention file the sweep did not act on, and each removal that failed.
    pub problems: Vec<String>,
}

/// Is `name` a space name this sweep will act on: one plain path component.
fn plain_name(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('.') && !name.contains(['/', '\\']) && name != ".."
}

/// A real directory, never a symbolic link: a dropper who can write the workspace must not be
/// able to point a space's `outbox` somewhere else and have the host delete there.
fn real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir())
}

/// When the handler's answer for this outbox entry was received: the latest of the times the
/// module note names. `None` when the tuple is not a regular file.
fn receipt(tuple: &Path, note: &Path) -> Option<SystemTime> {
    let meta = std::fs::symlink_metadata(tuple).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    let mut latest = meta.modified().ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let changed = SystemTime::UNIX_EPOCH
            + Duration::from_secs(u64::try_from(meta.ctime()).unwrap_or(0))
            + Duration::from_nanos(u64::try_from(meta.ctime_nsec()).unwrap_or(0));
        latest = latest.max(changed);
    }
    if let Some(noted) = note_time(note) {
        latest = latest.max(noted);
    }
    Some(latest)
}

/// The modification time of a regular-file note, if there is one.
fn note_time(note: &Path) -> Option<SystemTime> {
    std::fs::symlink_metadata(note)
        .ok()
        .filter(|m| m.file_type().is_file())
        .and_then(|m| m.modified().ok())
}

/// Sweep every space with a retention file in `retention_dir`, under the spaces root `root`,
/// as of `now`. Deletes each handled tuple older than its space's retention, and its note.
pub fn sweep(root: &Path, retention_dir: &Path, now: SystemTime) -> Swept {
    let mut swept = Swept::default();
    let Ok(entries) = std::fs::read_dir(retention_dir) else {
        return swept;
    };
    let mut spaces: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| plain_name(name))
        .collect();
    spaces.sort();
    for space in spaces {
        let keep = match retention_for(retention_dir, &space) {
            Retention::Off => continue,
            Retention::Unreadable(why) => {
                swept.problems.push(format!(
                    "ikigai: space `{space}`: {SPACE_RETENTION_DIR}/{space} {why}; keeping its \
                     whole outbox"
                ));
                continue;
            }
            Retention::After(keep) => keep,
        };
        let space_dir = root.join(&space);
        let outbox = space_dir.join(OUTBOX);
        if !real_dir(&space_dir) || !real_dir(&outbox) {
            continue;
        }
        let ids = expire_outbox(&outbox, keep, now, &space, &mut swept.problems);
        if !ids.is_empty() {
            swept.expired.push((space, ids));
        }
    }
    swept
}

/// Delete each handled tuple in `outbox` received more than `keep` before `now`, then its
/// note. Returns the ids deleted, in id order.
fn expire_outbox(
    outbox: &Path,
    keep: Duration,
    now: SystemTime,
    space: &str,
    problems: &mut Vec<String>,
) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(outbox) else {
        return Vec::new();
    };
    let mut ids: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|name| name.strip_suffix(".tuple").map(str::to_string))
        .filter(|id| plain_name(id))
        .collect();
    ids.sort();
    let mut expired = Vec::new();
    for id in ids {
        let tuple: PathBuf = outbox.join(format!("{id}.tuple"));
        let note: PathBuf = outbox.join(format!("{id}.out"));
        let Some(received) = receipt(&tuple, &note) else {
            continue;
        };
        // A receipt in the future (a clock stepped back) is not old.
        if now.duration_since(received).map_or(true, |age| age <= keep) {
            continue;
        }
        let judged = note_time(&note);
        if let Err(e) = std::fs::remove_file(&tuple) {
            if e.kind() != std::io::ErrorKind::NotFound {
                problems.push(format!(
                    "ikigai: space `{space}`: handled tuple {id} has expired but could not be \
                     deleted: {e}"
                ));
            }
            continue;
        }
        // Only the note that was judged old: a re-handled tuple's fresh note stays.
        if judged.is_some() && note_time(&note) == judged {
            if let Err(e) = std::fs::remove_file(&note) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    problems.push(format!(
                        "ikigai: space `{space}`: the note of expired tuple {id} could not be \
                         deleted: {e}"
                    ));
                }
            }
        }
        expired.push(id);
    }
    expired
}

/// The log lines for one sweep: one per space with expired tuples (a count, never the ids'
/// content), then each problem.
pub fn sweep_lines(swept: &Swept) -> Vec<String> {
    swept
        .expired
        .iter()
        .map(|(space, ids)| {
            let n = ids.len();
            let noun = if n == 1 { "tuple" } else { "tuples" };
            format!("ikigai: space `{space}`: deleted {n} handled {noun} past its outbox retention")
        })
        .chain(swept.problems.iter().cloned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Native-only, like the sweep: receipts are file times, so "now" is the wall clock.
    #[allow(clippy::disallowed_methods)]
    fn now() -> SystemTime {
        SystemTime::now()
    }

    const DAY: Duration = Duration::from_secs(86_400);

    /// A scratch spaces root and config retention dir, fresh per test.
    fn scratch(name: &str) -> (PathBuf, PathBuf) {
        let base =
            std::env::temp_dir().join(format!("ikigai-retention-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let spaces = base.join("spaces");
        let retention = base.join("config").join(SPACE_RETENTION_DIR);
        std::fs::create_dir_all(&spaces).unwrap();
        std::fs::create_dir_all(&retention).unwrap();
        (spaces, retention)
    }

    /// Leave a tuple in `space`'s `stage`, as a reactor (or a dropper) would, with a note
    /// beside it when `note` is given.
    fn put(spaces: &Path, space: &str, stage: &str, id: &str, note: Option<&str>) {
        let dir = spaces.join(space).join(stage);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(note) = note {
            std::fs::write(dir.join(format!("{id}.out")), note).unwrap();
        }
        std::fs::write(dir.join(format!("{id}.tuple")), format!("tuple {id}")).unwrap();
    }

    fn exists(spaces: &Path, space: &str, stage: &str, file: &str) -> bool {
        spaces.join(space).join(stage).join(file).exists()
    }

    #[test]
    fn an_old_handled_tuple_and_its_note_are_deleted() {
        let (spaces, retention) = scratch("old");
        std::fs::write(retention.join("contact"), "7d\n").unwrap();
        put(
            &spaces,
            "contact",
            "outbox",
            "a1",
            Some("routed to inquiry"),
        );
        put(&spaces, "contact", "outbox", "b2", None);
        // Eight days after the handler's receipt.
        let swept = sweep(&spaces, &retention, now() + 8 * DAY);
        assert_eq!(
            swept.expired,
            vec![(
                "contact".to_string(),
                vec!["a1".to_string(), "b2".to_string()]
            )]
        );
        assert!(swept.problems.is_empty(), "{:?}", swept.problems);
        for file in ["a1.tuple", "a1.out", "b2.tuple"] {
            assert!(
                !exists(&spaces, "contact", "outbox", file),
                "{file} was kept"
            );
        }
        assert_eq!(
            sweep_lines(&swept),
            vec!["ikigai: space `contact`: deleted 2 handled tuples past its outbox retention"]
        );
    }

    #[test]
    fn a_handled_tuple_inside_its_retention_is_kept() {
        let (spaces, retention) = scratch("young");
        std::fs::write(retention.join("contact"), "7d").unwrap();
        put(&spaces, "contact", "outbox", "a1", Some("routed"));
        let swept = sweep(&spaces, &retention, now() + 6 * DAY);
        assert_eq!(swept, Swept::default());
        assert!(exists(&spaces, "contact", "outbox", "a1.tuple"));
        assert!(exists(&spaces, "contact", "outbox", "a1.out"));
    }

    #[test]
    fn a_pending_tuple_is_never_deleted() {
        let (spaces, retention) = scratch("pending");
        std::fs::write(retention.join("contact"), "1m").unwrap();
        // Pending in the inbox, claimed mid-pass, and dead-lettered: none of them handled.
        put(&spaces, "contact", "inbox", "p1", None);
        put(&spaces, "contact", ".processing", "p2", None);
        put(&spaces, "contact", "error", "p3", None);
        std::fs::write(spaces.join("contact/error/p3.err"), "handler failed").unwrap();
        // The same bytes handled once and dropped again: the outbox copy goes, the new
        // request waiting in the inbox stays.
        put(&spaces, "contact", "outbox", "p1", Some("first answer"));
        let swept = sweep(&spaces, &retention, now() + 365 * DAY);
        assert_eq!(
            swept.expired,
            vec![("contact".to_string(), vec!["p1".to_string()])]
        );
        assert!(exists(&spaces, "contact", "inbox", "p1.tuple"));
        assert!(exists(&spaces, "contact", ".processing", "p2.tuple"));
        assert!(exists(&spaces, "contact", "error", "p3.tuple"));
        assert!(exists(&spaces, "contact", "error", "p3.err"));
    }

    #[test]
    fn retention_off_keeps_everything() {
        let (spaces, retention) = scratch("off");
        // No file for `jobs`; `off` for `training`; only comments for `contact`; and a typo
        // for `spam`, which must keep everything rather than guess.
        std::fs::write(retention.join("training"), "off\n").unwrap();
        std::fs::write(retention.join("contact"), "# 7d once training is gone\n").unwrap();
        std::fs::write(retention.join("spam"), "7 days").unwrap();
        for space in ["jobs", "training", "contact", "spam"] {
            put(&spaces, space, "outbox", "h1", Some("handled"));
        }
        let swept = sweep(&spaces, &retention, now() + 3650 * DAY);
        assert!(swept.expired.is_empty(), "{:?}", swept.expired);
        assert_eq!(swept.problems.len(), 1, "{:?}", swept.problems);
        assert!(
            swept.problems[0].contains("space `spam`"),
            "{:?}",
            swept.problems
        );
        for space in ["jobs", "training", "contact", "spam"] {
            assert!(
                exists(&spaces, space, "outbox", "h1.tuple"),
                "{space} lost its tuple"
            );
            assert!(
                exists(&spaces, space, "outbox", "h1.out"),
                "{space} lost its note"
            );
        }
        // And with no retention directory at all, nothing is swept.
        let none = sweep(&spaces, &retention.join("absent"), now() + 3650 * DAY);
        assert_eq!(none, Swept::default());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_outbox_is_not_followed() {
        let (spaces, retention) = scratch("symlink");
        std::fs::write(retention.join("contact"), "1m").unwrap();
        let elsewhere = spaces.parent().unwrap().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("keep.tuple"), "not an outbox").unwrap();
        std::fs::create_dir_all(spaces.join("contact")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, spaces.join("contact").join("outbox")).unwrap();
        let swept = sweep(&spaces, &retention, now() + 365 * DAY);
        assert_eq!(swept, Swept::default());
        assert!(elsewhere.join("keep.tuple").exists());
    }

    #[test]
    fn durations_parse() {
        assert_eq!(parse_retention("7d"), Retention::After(7 * DAY));
        assert_eq!(
            parse_retention(" 36h # a day and a half\n"),
            Retention::After(Duration::from_secs(36 * 3600))
        );
        assert_eq!(
            parse_retention("90m"),
            Retention::After(Duration::from_secs(90 * 60))
        );
        assert_eq!(parse_retention(""), Retention::Off);
        assert_eq!(parse_retention("OFF"), Retention::Off);
        for bad in ["0d", "7", "d", "7w", "-1d", "7d\n8d", "7é"] {
            assert!(
                matches!(parse_retention(bad), Retention::Unreadable(_)),
                "`{bad}` parsed"
            );
        }
    }
}
