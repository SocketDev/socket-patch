//! The proof ladder: that Bazel consumes the patched bytes.
//!
//! The oracle is always something Bazel reports or builds, never a file
//! socket-patch wrote, and the harness never guesses an `external/<repo>`
//! path: the directory name differs per Bazel line and dependency system,
//! so it asks Bazel.
//!
//! - Tier 0, [`Cell::tier0`]: the source files Bazel lists for
//!   `//:socket_probe`, checked against the ruleset's [`Anchor`]. A fetch,
//!   no build.
//! - Tier 1, [`Cell::tier1_file`]: the bytes of a `socket_probe` output,
//!   on a warm server and (after [`Cell::shutdown`]) on a restarted one.
//! - Tier 2, [`Cell::tier2`]: `bazel run //:consumer` prints a marker from
//!   patched code, for rulesets whose install happens in a build action.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use sha2::{Digest, Sha256, Sha512};

use super::invoke::Run;
use super::server::Cell;

/// The tier-0 and tier-1 target every fixture defines.
pub const PROBE: &str = "//:socket_probe";
/// The tier-2 target: a program in the ruleset's language.
pub const CONSUMER: &str = "//:consumer";

const TIER0_QUERY: &str = r#"kind("source file", deps(//:socket_probe))"#;

/// One line of `bazel query --output=location`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFile {
    /// Where Bazel materialised the file.
    pub path: PathBuf,
    pub label: String,
}

/// The `<path>:<line>:<column>: source file <label>` lines of a query.
/// Read from the right: on Windows the path holds a drive colon.
pub fn parse_locations(stdout: &str) -> Vec<SourceFile> {
    let number = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    let parse = |line: &str| {
        let (location, label) = line.trim().split_once(": source file ")?;
        let (rest, column) = location.rsplit_once(':')?;
        let (path, row) = rest.rsplit_once(':')?;
        (number(column) && number(row) && !path.is_empty()).then(|| SourceFile {
            path: PathBuf::from(path),
            label: label.to_string(),
        })
    };
    stdout.lines().filter_map(parse).collect()
}

/// What tier 0 compares, per ruleset. Each names exactly one listed source
/// file; none or several is a failure, so a fixture that grew a second
/// copy cannot pass on the unpatched one.
#[derive(Clone, Copy, Debug)]
pub enum Anchor<'a> {
    /// The file whose label contains `label` has this hex sha256.
    Sha256 { label: &'a str, sha256: &'a str },
    /// rules_js: the only source file of an npm repository is the registry
    /// tarball `package.tgz` (extraction is a build action); its sha512
    /// must equal the lock's `integrity` (`sha512-<base64>`).
    Integrity { label: &'a str, integrity: &'a str },
    /// rules_jvm_external: the jar under the artifact repository's `file/`
    /// directory. Never the `processed_<jar>` a build through `@maven//`
    /// yields: a Java action stamps its manifest, so its hash is not the
    /// registry jar's.
    FileJar { jar: &'a str, sha256: &'a str },
}

impl Anchor<'_> {
    /// The path of the one source file this anchor names, once its digest
    /// matched.
    pub fn check(&self, sources: &[SourceFile]) -> Result<PathBuf, String> {
        let one = |what: &str, pick: &dyn Fn(&SourceFile) -> bool| {
            let hits: Vec<&SourceFile> = sources.iter().filter(|s| pick(s)).collect();
            match hits[..] {
                [hit] => Ok(hit.path.clone()),
                _ => Err(format!(
                    "expected exactly one source file for {what}, found {}: {sources:?}",
                    hits.len()
                )),
            }
        };
        let read =
            |path: &Path| std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()));
        let (path, got, want) = match *self {
            Anchor::Sha256 { label, sha256 } => {
                let path = one(label, &|s| s.label.contains(label))?;
                let got = hex::encode(Sha256::digest(read(&path)?));
                (path, got, sha256.to_string())
            }
            Anchor::Integrity { label, integrity } => {
                let tarball =
                    |s: &SourceFile| s.label.contains(label) && s.label.ends_with(":package.tgz");
                let path = one(label, &tarball)?;
                let digest = Sha512::digest(read(&path)?);
                let got = base64::engine::general_purpose::STANDARD.encode(digest);
                (path, format!("sha512-{got}"), integrity.to_string())
            }
            Anchor::FileJar { jar, sha256 } => {
                let registry_jar = |s: &SourceFile| {
                    s.path.file_name().is_some_and(|name| name == jar)
                        && s.path.components().any(|c| c.as_os_str() == "file")
                };
                let path = one(jar, &registry_jar)?;
                let got = hex::encode(Sha256::digest(read(&path)?));
                (path, got, sha256.to_string())
            }
        };
        if got == want {
            Ok(path)
        } else {
            Err(format!(
                "{} has digest {got}, expected {want}",
                path.display()
            ))
        }
    }
}

impl Cell {
    /// Tier 0: the source files Bazel materialised for `//:socket_probe`.
    pub fn tier0_sources(&self) -> Vec<SourceFile> {
        let args = [
            "--noimplicit_deps",
            "--notool_deps",
            "--output=location",
            TIER0_QUERY,
        ];
        parse_locations(&self.bazel_ok("query", &args).stdout())
    }

    /// Tier 0 against `anchor`: the repository Bazel materialised holds the
    /// expected bytes. Returns the file's path.
    pub fn tier0(&self, anchor: Anchor) -> PathBuf {
        let sources = self.tier0_sources();
        anchor
            .check(&sources)
            .unwrap_or_else(|why| panic!("{}: tier 0: {why}", self.test))
    }

    /// Tier 1: build `//:socket_probe` and return the absolute path of its
    /// output `socket_probe.out/<name>` (a directory for a tree-artifact
    /// input). An action input is then the file tier 0 listed.
    pub fn tier1_output(&self, name: &str) -> PathBuf {
        self.bazel_ok("build", &[PROBE]);
        let files = self.bazel_ok("cquery", &["--output=files", PROBE]).stdout();
        let suffix = format!("socket_probe.out/{name}");
        let hits: Vec<&str> = files
            .lines()
            .map(str::trim)
            .filter(|line| line.replace('\\', "/").ends_with(&suffix))
            .collect();
        let [hit] = hits[..] else {
            panic!(
                "{}: tier 1: no single output {suffix} in:\n{files}",
                self.test
            );
        };
        PathBuf::from(self.info("execution_root")).join(hit)
    }

    /// Tier 1 for a file input: the bytes of the probe output `name`. Run
    /// it once warm and once after [`Cell::shutdown`]: a restarted server
    /// rechecks external files.
    pub fn tier1_file(&self, name: &str) -> Vec<u8> {
        let path = self.tier1_output(name);
        std::fs::read(&path)
            .unwrap_or_else(|e| panic!("{}: tier 1: {}: {e}", self.test, path.display()))
    }

    /// Tier 2: `bazel run //:consumer` succeeds and prints `marker`.
    pub fn tier2(&self, marker: &str) -> Run {
        let run = self.bazel_ok("run", &[CONSUMER]);
        assert!(
            run.stdout().contains(marker),
            "{}: tier 2: {CONSUMER} did not print {marker:?}:\n{}",
            self.test,
            run.dump()
        );
        run
    }
}
