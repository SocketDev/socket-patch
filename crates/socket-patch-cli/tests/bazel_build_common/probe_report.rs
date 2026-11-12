//! Per-cell JSON reports: the evidence a claim rests on.
//!
//! A lane claims a (Bazel line, dependency system, OS) only with a report
//! of status `ran` for it. A test that skips, for any reason, writes a
//! report of status `skipped`, so a cell whose test printed SKIP can never
//! be mistaken for one that passed.
//!
//! A test that fails leaves no report. It writes none, and `Cell::open`
//! removes the one an earlier run of the same cell left
//! ([`Report::discard_earlier`]): the file name is fixed per cell and the
//! default directory persists, so a passing run followed by a failing one
//! would otherwise keep a `ran` report on disk. Two cases are out of that
//! reach, because the later run never learns the earlier file's name: a
//! test the later run does not run at all, and a later run that skips
//! before it finds a Bazel (no Bazel, or another `_GROUP` / `_SYSTEM`: its
//! report is `<test>.none...`). An audited run therefore starts with an
//! empty [`env::PROBE_DIR`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::{json, Value};

use super::env::{self, Group, System};
use super::fixture_server::FixtureServer;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ran,
    Skipped,
}

/// One test's report in one cell.
#[derive(Clone, Debug)]
pub struct Report {
    pub test: String,
    /// The Bazel version driven; `None` when the test skipped before it
    /// found one.
    pub bazel: Option<String>,
    pub group: Option<Group>,
    pub system: Option<System>,
    /// The lanes this test proves on its cell (`H-JS1`): what the claims
    /// audit matches a claim of `lanes::claims_json()` against. Empty for
    /// a test that proves no lane (the toy, a guard, a canary).
    pub lanes: Vec<String>,
    /// Every host the fixture server was asked for, from its request log.
    /// Private, with [`Report::hosts_logged`]: only
    /// [`Report::hosts_from_log`] and [`Report::hosts_from_renamed_log`],
    /// which read a server, can set it, so a report cannot name a host no
    /// server logged. The audit refuses a list with any other source.
    hosts: Vec<String>,
    /// [`Report::hosts`] was taken from a fixture server's log.
    hosts_logged: bool,
    /// A command of the test reached hosts directly, with no downloader
    /// rewrite, so `hosts` is not the whole list and the report proves
    /// nothing about hermeticity. Set only when such a command ran: by the
    /// record-only canaries, and by a toy cell that had to download Bazel's
    /// own module archives because the line does not commit them and no
    /// repository cache held them (`toy::open`; with the archives under
    /// [`env::CACHE_ROOT`] the same cell contacts no host and says `false`).
    pub direct_network: bool,
    /// Ruleset name to the version `bazel mod graph` resolved.
    pub resolved: BTreeMap<String, String>,
    /// Free-form measurements of the cell.
    pub details: serde_json::Map<String, Value>,
    pub started: Instant,
}

impl Report {
    pub fn new(test: &str) -> Report {
        Report {
            test: test.to_string(),
            bazel: None,
            group: None,
            system: None,
            lanes: Vec::new(),
            hosts: Vec::new(),
            hosts_logged: false,
            direct_network: false,
            resolved: BTreeMap::new(),
            details: serde_json::Map::new(),
            started: Instant::now(),
        }
    }

    pub fn detail(&mut self, key: &str, value: impl Into<Value>) -> &mut Report {
        self.details.insert(key.to_string(), value.into());
        self
    }

    /// This test is evidence for `lane` on its cell. A lane is claimed on
    /// a Bazel line, dependency system or OS only with a `ran` report that
    /// names it there (`scripts/bazel-matrix-audit.py --claims`).
    pub fn proves(&mut self, lane: &str) -> &mut Report {
        if !self.lanes.iter().any(|known| known == lane) {
            self.lanes.push(lane.to_string());
        }
        self
    }

    /// The hosts the report names: empty until one of the two functions
    /// below read a fixture server's log.
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// Take `hosts` from the request log of the test's fixture server.
    pub fn hosts_from_log(&mut self, server: &FixtureServer) {
        self.hosts_from_renamed_log(server, server.hosts());
    }

    /// [`Report::hosts_from_log`] for a test that renames what the log
    /// cannot name: a request a tool sent straight to the loopback origin
    /// has no host segment, and is reported as `127.0.0.1`. `hosts` is the
    /// server's own list after that renaming, which can merge two entries
    /// and never adds one.
    pub fn hosts_from_renamed_log(&mut self, server: &FixtureServer, mut hosts: Vec<String>) {
        hosts.sort();
        hosts.dedup();
        let logged = server.hosts().len();
        assert!(
            hosts.len() <= logged,
            "{}: {hosts:?} names more hosts than the fixture server logged ({logged})",
            self.test
        );
        self.hosts = hosts;
        self.hosts_logged = true;
    }

    pub fn to_json(&self, status: Status, reason: Option<&str>) -> Value {
        json!({
            "test": self.test,
            "status": match status { Status::Ran => "ran", Status::Skipped => "skipped" },
            "reason": reason,
            "bazel": self.bazel,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "group": self.group.map(Group::name),
            "system": self.system.map(System::name),
            "lanes": self.lanes,
            "hosts": self.hosts,
            // `none`: no fixture server's log was read. The audit accepts
            // that only beside an empty list (a test that served nothing).
            "hosts_source": if self.hosts_logged { "fixture_server_log" } else { "none" },
            "direct_network": self.direct_network,
            "wall_ms": u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "resolved": self.resolved,
            "details": self.details,
        })
    }

    /// The file this report is written to: one per (test, Bazel version,
    /// system, OS, architecture), so the cells of a matrix never collide.
    pub fn path(&self) -> PathBuf {
        self.path_in(&probe_dir())
    }

    /// [`Report::path`] under `dir` instead of the probe directory.
    pub fn path_in(&self, dir: &Path) -> PathBuf {
        let cell = format!(
            "{}.{}.{}.{}-{}",
            self.test,
            self.bazel.as_deref().unwrap_or("none"),
            self.system.map_or("any", System::name),
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        let name: String = cell
            .chars()
            .map(|c| match c {
                c if c.is_ascii_alphanumeric() => c,
                '.' | '_' | '-' => c,
                _ => '_',
            })
            .collect();
        dir.join(format!("{name}.json"))
    }

    /// The test ran to its end: write status `ran`. Call it last, after
    /// every assertion.
    pub fn ran(&self) -> PathBuf {
        self.write_in(&probe_dir(), Status::Ran, None)
    }

    /// Remove the report an earlier run of this cell left, so that only
    /// this run's own `ran`, `skip` or `skip_na` can leave one. Called
    /// once the cell is known (the Bazel version is part of the name) and
    /// before the test body runs: if the test then fails, no report says
    /// `ran`.
    pub fn discard_earlier(&self) {
        self.discard_in(&probe_dir());
    }

    /// [`Report::discard_earlier`] under `dir`. A file that cannot be
    /// removed is a failure: left in place it could still be read as this
    /// run's evidence.
    pub fn discard_in(&self, dir: &Path) {
        let path = self.path_in(dir);
        match std::fs::remove_file(&path) {
            Ok(()) => println!("removed the earlier probe report {}", path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("remove the earlier probe report {}: {e}", path.display()),
        }
    }

    /// Write this report under `dir` and return its path.
    pub fn write_in(&self, dir: &Path, status: Status, reason: Option<&str>) -> PathBuf {
        let path = self.path_in(dir);
        std::fs::create_dir_all(dir).expect("create the probe directory");
        let text = serde_json::to_vec_pretty(&self.to_json(status, reason)).unwrap();
        std::fs::write(&path, text).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        println!("probe report ({status:?}): {}", path.display());
        path
    }
}

/// Where reports go: [`env::PROBE_DIR`], else `<target tmp>/bazel-probe`.
pub fn probe_dir() -> PathBuf {
    env::var(env::PROBE_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("bazel-probe"))
}

/// Whether a test that cannot run here may skip: `Err` is the failure
/// message of a required cell, which never skips.
pub fn may_skip(test: &str, why: &str, required: bool) -> Result<(), String> {
    if required {
        return Err(format!(
            "{test}: {} is set but the test cannot run: {why}",
            env::REQUIRED
        ));
    }
    Ok(())
}

/// The test cannot run here (no Bazel, an unreachable origin, a fixture or
/// a registry mirror that is not committed for this Bazel version): a
/// failure on a required cell, else `SKIP` and a `skipped` report.
pub fn skip(report: &Report, why: &str) -> PathBuf {
    if let Err(failure) = may_skip(&report.test, why, env::required()) {
        panic!("{failure}");
    }
    println!("SKIP {}: {why}", report.test);
    report.write_in(&probe_dir(), Status::Skipped, Some(why))
}

/// The test does not apply to this cell (another fixture group, a
/// dependency system the Bazel line does not have, an OS the test has no
/// tool for): `SKIP (n/a)` and a `skipped` report, also on a required cell.
/// Never for something the cell is merely missing: a required cell whose
/// test ran nothing must fail, so that is [`skip`].
pub fn skip_na(report: &Report, why: &str) -> PathBuf {
    println!("SKIP (n/a) {}: {why}", report.test);
    report.write_in(&probe_dir(), Status::Skipped, Some(why))
}
