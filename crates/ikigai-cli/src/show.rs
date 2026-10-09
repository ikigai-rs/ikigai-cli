//! The terminal's [`Viewer`] for `show <iri>` (ledger #908): a terminal cannot draw SVG, so the
//! picture is written to a file and handed to the platform's opener, and the path is printed so
//! a session with no opener (ssh, CI) still knows where the picture is.
//!
//! **The opener is the config home's `show.opener`**: absent means the platform's own (`open`
//! on macOS, `xdg-open` elsewhere on unix, `start` on Windows); `none` writes and prints the
//! path without opening anything; any other value is a command, split on whitespace, that is
//! run with the path appended (`show.opener = "open -a Safari"`). Config home, not an
//! environment variable.
//!
//! The file is named for what it shows and what it holds — `ikigai-show-<slug>-<hash>.svg` in
//! the system temporary directory — so showing the same picture twice reuses one file rather
//! than leaving a new one behind each time.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ikigai_engine::Viewer;

/// The config key naming the opener.
const OPENER_KEY: &str = "show.opener";

/// Writes the picture to the temporary directory and opens it with `show.opener`.
pub struct FileViewer;

impl Viewer for FileViewer {
    fn show(&self, target: &str, _media: &str, bytes: &[u8]) -> Result<String, String> {
        let path = picture_path(&std::env::temp_dir(), target, bytes);
        std::fs::write(&path, bytes)
            .map_err(|e| format!("could not write {}: {e}", path.display()))?;
        let wrote = format!("wrote {} ({} bytes)", path.display(), bytes.len());
        let opener = ikigai_embedded::config::get(OPENER_KEY);
        let Some(mut command) = opener_command(opener.as_deref()) else {
            return Ok(format!("{wrote} · not opened ({OPENER_KEY} = none)"));
        };
        let name = format!("{command:?}");
        let mut child = command
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                format!("{wrote}, and {name} could not open it: {e} (set {OPENER_KEY} in the config home)")
            })?;
        // Reaped off the REPL's thread: an opener that lingers (xdg-open can) must not hold the
        // prompt, and an unreaped child is a zombie until the session ends.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(format!("{wrote} · opened with {name}"))
    }
}

/// The opener for `configured`: the platform's own when unset, nothing for `none`/`off`, else
/// the configured command line.
fn opener_command(configured: Option<&str>) -> Option<Command> {
    match configured.map(str::trim) {
        Some("none" | "off" | "") => None,
        Some(line) => {
            let mut words = line.split_whitespace();
            let mut command = Command::new(words.next()?);
            command.args(words);
            Some(command)
        }
        None => Some(platform_opener()),
    }
}

#[cfg(target_os = "macos")]
fn platform_opener() -> Command {
    Command::new("open")
}

#[cfg(windows)]
fn platform_opener() -> Command {
    let mut command = Command::new("cmd");
    // `start` takes the first quoted argument as a window title, hence the empty one.
    command.args(["/C", "start", ""]);
    command
}

#[cfg(not(any(target_os = "macos", windows)))]
fn platform_opener() -> Command {
    Command::new("xdg-open")
}

/// `<dir>/ikigai-show-<slug>-<hash>.svg`: the slug is the target's last segments made
/// filename-safe (so a directory listing says what each picture is), the hash is of the bytes
/// (so one picture is one file, and a changed picture is a new one).
fn picture_path(dir: &Path, target: &str, bytes: &[u8]) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    let slug: String = target
        .trim_start_matches("urn:")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let slug = slug.trim_matches('-');
    let slug = &slug[slug.len().saturating_sub(40)..];
    dir.join(format!("ikigai-show-{slug}-{:016x}.svg", hasher.finish()))
}

#[cfg(test)]
mod tests {
    use super::{opener_command, picture_path};
    use std::path::Path;

    #[test]
    fn one_picture_is_one_file_named_for_what_it_shows() {
        let dir = Path::new("/tmp");
        let a = picture_path(dir, "urn:diagram:kernel", b"<svg/>");
        assert_eq!(a, picture_path(dir, "urn:diagram:kernel", b"<svg/>"));
        assert_ne!(a, picture_path(dir, "urn:diagram:kernel", b"<svg></svg>"));
        let name = a.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with("ikigai-show-diagram-kernel-") && name.ends_with(".svg"),
            "{name}"
        );
        // Nothing in a target can climb out of the directory.
        let hostile = picture_path(dir, "urn:x:../../etc/passwd", b"x");
        assert_eq!(hostile.parent(), Some(dir));
    }

    #[test]
    fn the_opener_is_the_platform_s_unless_the_config_home_names_one() {
        assert!(opener_command(None).is_some());
        assert!(opener_command(Some("none")).is_none());
        assert!(opener_command(Some(" off ")).is_none());
        let custom = opener_command(Some("open -a Safari")).unwrap();
        assert_eq!(custom.get_program(), "open");
        assert_eq!(custom.get_args().collect::<Vec<_>>(), vec!["-a", "Safari"]);
    }
}
