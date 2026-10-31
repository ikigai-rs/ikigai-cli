//! The REPL's kernel installs a spill facility (ledger #2724): `| urn:stream:spill` answers the
//! body again, as one that can be read again, instead of "this kernel has no spill facility".
#![cfg(all(feature = "embedded", unix))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const TURTLE: &str = "@prefix ex: <http://example.org/> .\nex:a ex:b ex:c .\n";
const TRIPLE: &str = "<http://example.org/a> <http://example.org/b> <http://example.org/c> .";
const TO_NTRIPLES: &str =
    "source urn:rdf:transrept content=<urn:file:x.ttl> as=application/n-triples";

/// A config home and a workspace holding `x.ttl`, unique to this case and process.
struct Home(PathBuf);

impl Home {
    fn new(case: &str) -> Self {
        let home = std::env::temp_dir().join(format!("iki-spill-{}-{case}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join("config")).unwrap();
        std::fs::create_dir_all(home.join("files")).unwrap();
        std::fs::write(home.join("files/x.ttl"), TURTLE).unwrap();
        Home(home)
    }

    fn spill(&self) -> PathBuf {
        self.0.join("config/spill")
    }

    fn run(&self, commands: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
        command
            .arg("--config-home")
            .arg(self.0.join("config"))
            .arg("--quiet");
        for line in commands {
            command.args(["-c", line]);
        }
        command
            .env("HOME", &self.0)
            .env("XDG_CONFIG_HOME", self.0.join("decoy"))
            .env("IKIGAI_FILES", self.0.join("files"))
            .env_remove("IKIGAI_GRANTS")
            .current_dir(&self.0)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn entries(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    entries
}

#[test]
fn the_spill_step_answers_a_body_read_again() {
    let home = Home::new("answers");
    let spilled = format!("{TO_NTRIPLES} | urn:stream:spill");
    // A fork hands the spilled body to two branches, so it is read twice.
    let forked =
        format!("{TO_NTRIPLES} | urn:stream:spill | ( urn:stream:text ; urn:stream:collect )");
    let out = home.run(&[&spilled, &forked]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(!text.contains("spill facility"), "{text}");
    assert_eq!(text.matches(TRIPLE).count(), 3, "{text}");

    // Under the config home, in a directory of this process's own, `0700`, and empty once the
    // process is done with its spilled bodies.
    let dirs = entries(&home.spill());
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    let name = dirs[0].file_name().unwrap().to_str().unwrap();
    assert!(
        name.strip_prefix("repl-")
            .is_some_and(|pid| pid.parse::<u32>().is_ok()),
        "{name}"
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&dirs[0]).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
    assert!(entries(&dirs[0]).is_empty(), "{:?}", entries(&dirs[0]));
}

#[test]
fn a_batch_that_never_spills_leaves_no_directory() {
    let home = Home::new("never");
    let out = home.run(&[TO_NTRIPLES]);
    assert!(out.status.success(), "{out:?}");
    assert!(!home.spill().exists());
}

#[test]
fn a_spill_removes_what_a_gone_process_left() {
    let home = Home::new("gone");
    // Past the largest process id a Linux or macOS kernel hands out: no process has it.
    let gone = home.spill().join("repl-99999999");
    std::fs::create_dir_all(&gone).unwrap();
    std::fs::write(gone.join(".ikigai-spill-0123"), "left behind").unwrap();
    let out = home.run(&[&format!("{TO_NTRIPLES} | urn:stream:spill")]);
    assert!(out.status.success(), "{out:?}");
    assert!(!gone.exists());
    assert_eq!(entries(&home.spill()).len(), 1);
}
