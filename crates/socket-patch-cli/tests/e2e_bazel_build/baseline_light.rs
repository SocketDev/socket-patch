//! Real-Bazel tests: `bazel_canary_baseline_*` for the light fixtures (rules_js,
//! rules_jvm_external, rules_ruby, rules_dotnet, rules_csharp).
//!
//! One canary per fixture workspace under `fixtures/bazel/light/<ruleset>/`. It
//! proves that the untouched fixture is a working build on the Bazel it is listed
//! for, which every later test of that fixture starts from: Bazel materialised
//! exactly the mirrored registry artifact (proof tier 0), `//:socket_probe` builds
//! where the cell's `proof` says so, `//:consumer` loads, the ruleset resolved to
//! the version `MATRIX.json` pins, a committed lock passes an `error`-mode build,
//! and Bazel wrote nothing into the workspace but its own files. The report it
//! writes carries the resolved versions and the hosts the fixture server was asked
//! for.
//!
//! Network. A canary fetches its ruleset (the registry, GitHub, toolchains) from
//! the real origins, so its report says `direct_network` and it is record-only:
//! an era whose pins stop fetching shows up here first. The fixture's own
//! packages do not come from the network. The downloader config written here
//! rewrites the URL scopes the registry modules own to the fixture server and
//! nothing else, so the committed locks keep their production URLs and a version
//! the mirror lacks is a fast 404, not a file from the real registry. That is a
//! different config from `Cell::use_fixture_server`, which rewrites every URL and
//! therefore needs a warm repository cache: with `SOCKET_PATCH_BAZEL_E2E_OFFLINE`
//! or `_REAL_REGISTRIES` set a baseline canary does not apply and skips.
//!
//! Credentials. A canary proves nothing about them. The package requests its
//! fixture server logs arrive through a downloader rewrite, and Bazel gives a
//! rewritten URL no header of the original one (only what the new URL's own
//! userinfo or a netrc entry says), so that log holds no `Authorization` header
//! whatever a fixture commits. "No credential left the machine" is a lane's
//! assertion, on a cold cell, through `FixtureServer::assert_no_header`.
//!
//! Other modules of the suite. A lane package owns `light/<ruleset>/` and its own
//! module here, not this file. It lists the cells of its tests under a fixture's
//! `lanes` key, which the checks below hold to a shape and no canary runs; for a
//! fixture it adds, it declares the canary in its own module as a plain
//! `fn bazel_canary_baseline_<ruleset>_<path>()` that calls [`baseline`]. The
//! schema, [`mount`] and [`downloader_rules`] are `pub(crate)` for those modules.
//!
//! The tests without `#[ignore]` need no Bazel: they hold `MATRIX.json`, the
//! fixture trees, the committed locks and the registry mirror to each other, and
//! exercise the four registry modules against a live fixture server.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use socket_patch_core::bazel::{java_hash, rje_lock};

use crate::bazel_build_common::env::{self, Group, System, Version};
use crate::bazel_build_common::fixture_server::FixtureServer;
use crate::bazel_build_common::invoke::{Options, Run};
use crate::bazel_build_common::probe_report;
use crate::bazel_build_common::proof::{parse_locations, Anchor, SourceFile, CONSUMER, PROBE};
use crate::bazel_build_common::registry::{gem, maven, npm, nuget};
use crate::bazel_build_common::server::Cell;
use crate::bazel_build_common::workspace::{fixtures_root, MODULE_LOCK, PROBE_BZL};
use crate::bazel_common::snapshot::{assert_same_tree_but_bazel_owned, snapshot, Entry};

/// The registry modules a matrix may name under `registries`: what [`mount`] serves.
pub(crate) const REGISTRIES: &[&str] = &["npm", "maven", "gem", "nuget"];

/// The CI tiers a cell may name.
const TIERS: &[&str] = &["nightly", "pr"];

/// The classes a cell's `outcome` may name.
const OUTCOMES: &[&str] = &["WORKS", "WORKS-AFTER"];

/// What a cell's `cache` may name: the restored repository cache.
const CACHES: &[&str] = &["restored"];

/// The tests whose CI cell never gets a restored repository cache (the
/// baselines and every other canary): on a warm cache a canary could not tell
/// when a pinned URL stops answering.
const COLD_PREFIX: &str = "bazel_canary_";

/// Who fetches a fixture's packages: Bazel's downloader, or a tool it runs.
const FETCHERS: &[&str] = &["downloader", "tool"];

/// The name every baseline canary starts with.
const CANARY_PREFIX: &str = "bazel_canary_baseline_";

/// The prefixes a test under a fixture's `lanes` key may have: the real-Bazel
/// tests of the lane packages.
const LANE_PREFIXES: &[&str] = &[
    "bazel_guard_",
    "bazel_agent_",
    "bazel_hosted_",
    "bazel_vendor_",
    "bazel_canary_",
];

/// The highest proof tier a baseline canary climbs: it builds the probe and
/// never runs the consumer.
const BASELINE_PROOF: u8 = 1;

/// The top of the proof ladder: 0 fetch, 1 build the probe, 2 run the consumer.
const TOP_PROOF: u8 = 2;

/// The one Bazel release no cell may name.
const NEVER_PINNED: &str = "7.7.0";

/// The key of a `moduleExtensions` entry that holds for every host system.
const GENERAL: &str = "general";

/// `fixtures/bazel/light`.
pub(crate) fn light() -> PathBuf {
    fixtures_root().join("light")
}

/// The mirror the registry modules serve: `<host>/<path>` for every artifact a
/// light fixture pins.
pub(crate) fn mirror() -> PathBuf {
    light().join("registry")
}

/// `light/<ruleset>/MATRIX.json`: the fixtures of one ruleset and the Bazel
/// versions each is claimed on. Unknown keys are refused, so a field this file
/// does not act on cannot sit in a matrix and look honoured.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Matrix {
    pub(crate) group: String,
    pub(crate) ruleset: String,
    /// The registry modules that serve this ruleset's packages.
    pub(crate) registries: Vec<String>,
    /// What tier 0 must find in every fixture of the ruleset.
    pub(crate) probe: Vec<ProbeFile>,
    pub(crate) fixtures: Vec<Fixture>,
}

/// One file the proof ladder anchors on, by the kind of
/// [`Anchor`](crate::bazel_build_common::proof::Anchor) that names it.
/// `artifact` is its path in the mirror, which is also its URL without the scheme.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "anchor", rename_all = "snake_case")]
pub(crate) enum ProbeFile {
    Integrity {
        label: String,
        artifact: String,
    },
    Sha256 {
        label: String,
        artifact: String,
        /// The probed file is this member of the artifact (a zip), for a ruleset
        /// that keeps only what it unpacked.
        #[serde(default)]
        member: Option<String>,
    },
    FileJar {
        jar: String,
        artifact: String,
    },
    /// rules_js before 1.40 unpacks the tarball while it fetches: the one
    /// source file of the npm repository is the directory `package`, and the
    /// probed file is `member` inside it (`package/<member>` of the tarball).
    Unpacked {
        label: String,
        artifact: String,
        member: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fixture {
    /// `<bzlmod|workspace>/<era>[-<variant>]`, under the ruleset's directory.
    pub(crate) path: String,
    /// The canary of this fixture.
    pub(crate) test: String,
    pub(crate) system: String,
    /// Ruleset module (or WORKSPACE repository) name to the version the fixture
    /// is written for.
    pub(crate) pins: BTreeMap<String, String>,
    /// What sets this fixture apart, for a reader of the matrix.
    pub(crate) shape: String,
    /// Who fetches the fixture's packages: `downloader` (Bazel's, which the
    /// rewrite reaches) or `tool` (a program Bazel runs, which needs a loopback
    /// origin of its own).
    #[serde(default = "downloader")]
    pub(crate) fetch: String,
    /// The Bazel versions the baseline canary built the fixture on.
    pub(crate) cells: Vec<CellSpec>,
    /// The labels tier 0 queries the dependencies of, where `//:socket_probe`
    /// is not the root: each must list every probed file.
    #[serde(default)]
    pub(crate) tier0_roots: Vec<String>,
    /// Labels in external repositories the canary also queries, so that a
    /// repository nothing else loads is fetched (and its pin checked) too.
    #[serde(default)]
    pub(crate) load: Vec<String>,
    /// A text the canary's build must print.
    #[serde(default)]
    pub(crate) build_stderr: Option<BuildStderr>,
    /// Bazel version to a committed `MODULE.bazel.lock`, relative to the
    /// fixture, for a fixture whose shape is a fact of that lock.
    #[serde(default)]
    pub(crate) module_lock: BTreeMap<String, String>,
    /// A `moduleExtensions` key the lock must hold after the build: the
    /// extension is recorded, so an edit of the file it reads stales the lock.
    #[serde(default)]
    pub(crate) recorded_extension: Option<String>,
    /// A `moduleExtensions` key the lock must not hold after the build: the
    /// extension is reproducible, so an edit of the file it reads stales nothing.
    #[serde(default)]
    pub(crate) not_recorded_extension: Option<String>,
    /// What tier 0 must find in this fixture, where it differs from the
    /// ruleset's.
    #[serde(default)]
    pub(crate) probe: Option<Vec<ProbeFile>>,
    /// The Maven repository URL the fixture commits for a client Bazel's
    /// downloader does not carry (Coursier, in an unpinned hub). It is loopback
    /// on a fixed port; the canary serves the mirror under its own port and
    /// writes that into its copy of `MODULE.bazel`.
    #[serde(default)]
    pub(crate) loopback_repository: Option<String>,
    /// The version-bearing names (`<group>_<artifact>_<version>`: an artifact
    /// repository, a hub's versioned alias) the workspace's own Starlark files
    /// use. A rewrite of the lock to another version renames them, so a fixture
    /// that lists one is the input of a refusal.
    #[serde(default)]
    pub(crate) versioned_names: Vec<String>,
    /// Each `maven_install.json`-format lock of the workspace, by its path, to
    /// the hash flavors that reproduce its stored `__RESOLVED_ARTIFACTS_HASH`
    /// (`v2`, `v3-sorted`, `v3-insertion`: the names of
    /// `socket_patch_core::bazel::rje_lock::Flavor`). The two v3 flavors differ
    /// only for a lock with two repositories; with one, both reproduce.
    #[serde(default)]
    pub(crate) lock_flavors: BTreeMap<String, Vec<String>>,
    /// The cells of the lane tests that run on this fixture. Checked for
    /// shape here; run by the lane's own module, never by the canary.
    #[serde(default)]
    pub(crate) lanes: Vec<Lane>,
}

fn downloader() -> String {
    "downloader".to_string()
}

/// One test of a lane package on a fixture, and where it is claimed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lane {
    /// A `bazel_guard_`, `bazel_agent_`, `bazel_hosted_`, `bazel_vendor_` or
    /// `bazel_canary_` test, declared in a module of this suite.
    pub(crate) test: String,
    /// A subset of the fixture's own Bazel versions: a lane runs where the
    /// baseline did.
    pub(crate) cells: Vec<CellSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CellSpec {
    pub(crate) bazel: String,
    /// The highest tier of the proof ladder the test climbs here: 0 fetch, 1
    /// build the probe, 2 run the consumer. A baseline canary stops at 1.
    pub(crate) proof: u8,
    /// `nightly` or `pr`: which CI tier runs the cell.
    pub(crate) tier: String,
    /// The class the ruleset's hosted lane must reach on this cell, where a
    /// probe fixed it (`WORKS`, `WORKS-AFTER`).
    #[serde(default)]
    pub(crate) outcome: Option<String>,
    /// `restored`, the one value: the cell runs on the restored repository
    /// cache. The CI plan demands the key of a Go or Rust cell of the `pr`
    /// tier and gives every guard, agent, hosted and vendor cell that cache
    /// anyway. Never on a canary's cell, which stays cold ([`COLD_PREFIX`]).
    #[serde(default)]
    pub(crate) cache: Option<String>,
}

/// What the stderr of a fixture's first build must hold: the evidence that a
/// ruleset took a path nothing else in the canary can tell apart.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BuildStderr {
    pub(crate) contains: String,
    /// The host systems (`std::env::consts::OS`) on which the ruleset does not
    /// print it.
    #[serde(default)]
    pub(crate) not_on: Vec<String>,
}

impl BuildStderr {
    fn applies_on(&self, os: &str) -> bool {
        !self.not_on.iter().any(|name| name == os)
    }
}

impl Matrix {
    pub(crate) fn parse(text: &str) -> Result<Matrix, String> {
        serde_json::from_str(text).map_err(|e| e.to_string())
    }

    pub(crate) fn load(ruleset: &str) -> Matrix {
        let path = light().join(ruleset).join("MATRIX.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let matrix = Matrix::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(matrix.ruleset, ruleset, "{}", path.display());
        assert_eq!(matrix.group, Group::Light.name(), "{}", path.display());
        matrix
    }

    pub(crate) fn fixture(&self, path: &str) -> &Fixture {
        let found = self.fixtures.iter().find(|fixture| fixture.path == path);
        found.unwrap_or_else(|| panic!("{}/MATRIX.json lists no fixture {path}", self.ruleset))
    }
}

impl Fixture {
    /// What tier 0 must find: the fixture's own list, or the ruleset's.
    pub(crate) fn probe<'a>(&'a self, matrix: &'a Matrix) -> &'a [ProbeFile] {
        self.probe.as_deref().unwrap_or(&matrix.probe)
    }

    /// The labels tier 0 queries the dependencies of.
    pub(crate) fn tier0_roots(&self) -> Vec<&str> {
        if self.tier0_roots.is_empty() {
            return vec![PROBE];
        }
        self.tier0_roots.iter().map(String::as_str).collect()
    }
}

impl ProbeFile {
    pub(crate) fn artifact(&self) -> &str {
        match self {
            ProbeFile::Integrity { artifact, .. }
            | ProbeFile::Sha256 { artifact, .. }
            | ProbeFile::FileJar { artifact, .. }
            | ProbeFile::Unpacked { artifact, .. } => artifact,
        }
    }

    /// The bytes Bazel must have materialised: the mirrored artifact, or the
    /// one member of it the ruleset keeps. `Err` when the mirror lacks either.
    pub(crate) fn expected(&self) -> Result<Vec<u8>, String> {
        let path = mirror().join(self.artifact());
        let at = |why: String| format!("{}: {why}", path.display());
        let bytes = std::fs::read(&path).map_err(|e| at(e.to_string()))?;
        let member = match self {
            ProbeFile::Unpacked { member, .. } => {
                return npm::member(&bytes, &format!("package/{member}")).map_err(at);
            }
            ProbeFile::Sha256 {
                member: Some(member),
                ..
            } => member,
            _ => return Ok(bytes),
        };
        let mut archive =
            zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|e| at(e.to_string()))?;
        let mut file = archive
            .by_name(member)
            .map_err(|e| at(format!("{member}: {e}")))?;
        let mut out = Vec::new();
        file.read_to_end(&mut out)
            .map_err(|e| at(format!("{member}: {e}")))?;
        Ok(out)
    }

    /// Tier 0 for this file: exactly one of the listed source files is it,
    /// with the expected bytes.
    pub(crate) fn check(&self, sources: &[SourceFile]) -> Result<PathBuf, String> {
        let bytes = self.expected()?;
        let sha256 = hex::encode(Sha256::digest(&bytes));
        match self {
            ProbeFile::Integrity { label, .. } => Anchor::Integrity {
                label,
                integrity: &npm::integrity(&bytes),
            }
            .check(sources),
            ProbeFile::Sha256 { label, .. } => Anchor::Sha256 {
                label,
                sha256: &sha256,
            }
            .check(sources),
            ProbeFile::FileJar { jar, .. } => Anchor::FileJar {
                jar,
                sha256: &sha256,
            }
            .check(sources),
            ProbeFile::Unpacked { label, member, .. } => {
                let unpacked = |source: &&SourceFile| {
                    source.label.contains(label.as_str()) && source.label.ends_with(":package")
                };
                let hits: Vec<&SourceFile> = sources.iter().filter(unpacked).collect();
                let [hit] = hits[..] else {
                    return Err(format!(
                        "expected exactly one unpacked package for {label}, found {}: {sources:?}",
                        hits.len()
                    ));
                };
                let file = hit.path.join(member);
                let got = std::fs::read(&file).map_err(|e| format!("{}: {e}", file.display()))?;
                if got == bytes {
                    Ok(file)
                } else {
                    let got = hex::encode(Sha256::digest(&got));
                    Err(format!(
                        "{} has digest {got}, expected {sha256}",
                        file.display()
                    ))
                }
            }
        }
    }
}

/// Mount the registry modules `names` on `server` and return every URL scope they
/// own. An unknown name is an error: a matrix that names a registry nobody
/// serves would have its packages fetched from the real one.
pub(crate) fn mount(server: &FixtureServer, names: &[String]) -> Vec<String> {
    let mirror = mirror();
    let mut scopes = Vec::new();
    for name in names {
        let mounted = match name.as_str() {
            "npm" => npm::mount(server, &mirror),
            "maven" => maven::mount(server, &mirror),
            "gem" => gem::mount(server, &mirror),
            "nuget" => nuget::mount(server, &mirror),
            other => Err(format!(
                "MATRIX.json names an unknown registry {other:?} (known: {REGISTRIES:?})"
            )),
        };
        scopes.extend(mounted.unwrap_or_else(|why| panic!("{why}")));
    }
    scopes
}

/// The pattern that matches the URLs of `scope` and no other. A scope is a URL
/// without its scheme; a trailing `*` makes it a prefix. Bazel matches a
/// `rewrite` pattern against the whole URL without its scheme.
fn scope_pattern(scope: &str) -> String {
    let (literal, tail) = match scope.strip_suffix('*') {
        Some(prefix) => (prefix, ".*"),
        None => (scope, ""),
    };
    format!("{}{tail}", regex::escape(literal))
}

/// The downloader config that sends `scopes`, and nothing else, to the fixture
/// server on `port`. Each line covers exactly its scope, and there is no
/// `block`: the ruleset itself still comes from its real origin.
pub(crate) fn downloader_rules(scopes: &[String], port: u16) -> String {
    let mut rules = String::new();
    for scope in scopes {
        let pattern = scope_pattern(scope);
        rules.push_str(&format!("rewrite ({pattern}) http://127.0.0.1:{port}/$1\n"));
    }
    rules
}

/// Name to version of the root module's direct dependencies, from
/// `bazel mod graph --output=json --depth=1`. Read from each dependency's `key`
/// (`<name>@<version>`): Bazel 7.0 and 7.1 print no separate `name` and `version`.
fn graph_versions(json: &str) -> Result<BTreeMap<String, String>, String> {
    let graph: Value = serde_json::from_str(json).map_err(|e| format!("mod graph: {e}"))?;
    let Some(dependencies) = graph["dependencies"].as_array() else {
        return Err(format!("mod graph: the root lists no dependencies: {json}"));
    };
    let pair = |dependency: &Value| {
        let key = dependency["key"]
            .as_str()
            .and_then(|key| key.split_once('@'));
        match key {
            Some((name, version)) if !name.is_empty() && !version.is_empty() => {
                Ok((name.to_string(), version.to_string()))
            }
            _ => Err(format!(
                "mod graph: a dependency without a <name>@<version> key: {dependency}"
            )),
        }
    };
    dependencies.iter().map(pair).collect()
}

/// The release an `http_archive` names, from `bazel query --output=build
/// //external:<name>`: the tag of its GitHub release URL without the leading `v`.
/// Every WORKSPACE fixture declares its ruleset that way; anything else is an
/// error, not a guess.
fn release_version(build: &str) -> Result<String, String> {
    const MARKER: &str = "/releases/download/";
    let Some(at) = build.find(MARKER) else {
        return Err(format!("no GitHub release URL in:\n{build}"));
    };
    let tag = build[at + MARKER.len()..].split('/').next().unwrap_or("");
    let version = tag.strip_prefix('v').unwrap_or(tag);
    if version.starts_with(|c: char| c.is_ascii_digit()) {
        Ok(version.to_string())
    } else {
        Err(format!("the release tag {tag:?} is not a version"))
    }
}

/// The version Bazel resolved for each pinned ruleset: from the module graph
/// under Bzlmod, from the repository's declaration under WORKSPACE.
fn resolved_versions(
    cell: &Cell,
    system: System,
    pins: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let test = &cell.test;
    if system == System::Workspace {
        let version = |name: &String| {
            let label = format!("//external:{name}");
            let build = cell.bazel_ok("query", &["--output=build", &label]).stdout();
            let version = release_version(&build);
            (
                name.clone(),
                version.unwrap_or_else(|why| panic!("{test}: {name}: {why}")),
            )
        };
        return pins.keys().map(version).collect();
    }
    let run = cell
        .mod_oracle(&["graph", "--output=json", "--depth=1"])
        .unwrap_or_else(|| panic!("{test}: this Bazel has no `mod` command"));
    assert!(run.ok(), "{test}: {}", run.dump());
    let graph = graph_versions(&run.stdout()).unwrap_or_else(|why| panic!("{test}: {why}"));
    let version = |name: &String| {
        let version = graph.get(name).cloned();
        (
            name.clone(),
            version.unwrap_or_else(|| {
                panic!("{test}: {name} is not a direct dependency of the root: {graph:?}")
            }),
        )
    };
    pins.keys().map(version).collect()
}

/// The `moduleExtensions` keys of a `MODULE.bazel.lock`: the extensions whose
/// result Bazel recorded. Empty for a lock that records none; `Err` for a file
/// that is not a lock, which would otherwise read as "nothing recorded".
fn recorded_extensions(lock: &[u8]) -> Result<Vec<String>, String> {
    let lock: Value =
        serde_json::from_slice(lock).map_err(|e| format!("{MODULE_LOCK} is not JSON: {e}"))?;
    if !lock.is_object() {
        return Err(format!("{MODULE_LOCK} is not a JSON object"));
    }
    let extensions = lock["moduleExtensions"].as_object();
    Ok(extensions.map_or_else(Vec::new, |map| map.keys().cloned().collect()))
}

/// Whether `keys` hold `extension`. The leading `@@` of the main repository
/// is not compared: the lock versions spell a root extension with and without it.
fn records(keys: &[String], extension: &str) -> bool {
    let bare = |key: &str| key.trim_start_matches('@').to_string();
    keys.iter().any(|key| bare(key) == bare(extension))
}

/// The tier-0 query over the dependencies of `root`. It is the query of
/// `Cell::tier0_sources` for a root other than `//:socket_probe`, kept here until
/// the harness takes one.
fn tier0_query(cell: &Cell, root: &str) -> Run {
    let query = format!(r#"kind("source file", deps({root}))"#);
    let args = [
        "--noimplicit_deps",
        "--notool_deps",
        "--output=location",
        query.as_str(),
    ];
    cell.bazel("query", &args)
}

/// Whether the top-level directory `name` of a fixture is data about the
/// fixture and no part of its workspace: the committed locks, and the goldens
/// a lane freezes (`expected-agent`, `expected-vendored`, `expected-hosted`).
/// A golden tree holds build files of its own, and a vendored one a tarball.
fn fixture_data_dir(name: &str) -> bool {
    name == "locks" || name.starts_with("expected-")
}

/// Remove the data directories of a fixture from the workspace copy Bazel
/// builds. `Cell::copy_fixture` copies the fixture whole.
pub(crate) fn strip_fixture_data(workspace: &Path) {
    let entries = std::fs::read_dir(workspace)
        .unwrap_or_else(|e| panic!("read {}: {e}", workspace.display()));
    for entry in entries {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if path.is_dir() && fixture_data_dir(&name) {
            std::fs::remove_dir_all(&path)
                .unwrap_or_else(|e| panic!("remove {}: {e}", path.display()));
        }
    }
}

/// The canary of the fixture `path` of `ruleset`. See the module documentation.
pub(crate) fn baseline(test: &str, ruleset: &str, path: &str) {
    let matrix = Matrix::load(ruleset);
    let fixture = matrix.fixture(path);
    assert_eq!(fixture.test, test, "{ruleset}/MATRIX.json, fixture {path}");
    let system = System::parse(&fixture.system)
        .unwrap_or_else(|| panic!("{test}: no dependency system {:?}", fixture.system));
    let Some(mut cell) = Cell::open(test, Group::Light, Some(system)) else {
        return;
    };
    let version = cell.bazel.version.text.clone();
    let Some(spec) = fixture.cells.iter().find(|spec| spec.bazel == version) else {
        let why = format!("{ruleset}/MATRIX.json has no cell for {path} on Bazel {version}");
        probe_report::skip_na(&cell.report, &why);
        return;
    };
    if env::offline() || env::real_registries() {
        let why = "a baseline canary fetches its ruleset from the real origins and its \
                   packages from the fixture server";
        probe_report::skip_na(&cell.report, why);
        return;
    }
    assert!(
        spec.proof <= BASELINE_PROOF,
        "{test}: a baseline canary climbs to proof {BASELINE_PROOF}, the cell says {}",
        spec.proof
    );

    let source = light().join(ruleset).join(path);
    cell.copy_fixture(&format!("light/{ruleset}/{path}"));
    strip_fixture_data(&cell.scratch.workspace);
    let committed = fixture.module_lock.get(&version).map(|rel| {
        let lock = source.join(rel);
        std::fs::read(&lock).unwrap_or_else(|e| panic!("{}: {e}", lock.display()))
    });
    if let Some(bytes) = &committed {
        cell.write_module_lock(bytes);
    }

    let server = FixtureServer::start();
    let scopes = mount(&server, &matrix.registries);
    let config = cell.scratch.root.join("downloader.cfg");
    std::fs::write(&config, downloader_rules(&scopes, server.port()))
        .unwrap_or_else(|e| panic!("write {}: {e}", config.display()));
    cell.options.downloader_config = Some(config);
    if let Some(committed) = &fixture.loopback_repository {
        let live = maven::mount_loopback(&server, &mirror()).unwrap_or_else(|why| panic!("{why}"));
        let module = std::fs::read_to_string(source.join("MODULE.bazel")).expect("MODULE.bazel");
        assert!(module.contains(committed.as_str()), "{test}: {committed}");
        cell.write("MODULE.bazel", module.replace(committed.as_str(), &live));
    }

    let untouched = snapshot(&cell.scratch.workspace);
    let roots = fixture.tier0_roots();
    // The first command fetches. With a committed lock it is the stale-lock
    // oracle: an `error`-mode build passes only on a lock that already holds
    // everything the build evaluates, so the committed file carries the proof
    // and not a lock Bazel would have written anyway.
    let first = match (&committed, spec.proof) {
        (Some(_), _) => cell.error_mode_build(&[PROBE]),
        (None, 0) => tier0_query(&cell, roots[0]),
        (None, _) => cell.bazel("build", &[PROBE]),
    };
    if first.origin_unreachable() {
        let why = format!("an origin is unreachable:\n{}", first.stderr());
        probe_report::skip(&cell.report, &why);
        return;
    }
    assert!(first.ok(), "{test}: {}", first.dump());
    if let Some(expected) = &fixture.build_stderr {
        if expected.applies_on(std::env::consts::OS) {
            assert!(
                first.stderr().contains(&expected.contains),
                "{test}: the build did not print {:?}:\n{}",
                expected.contains,
                first.dump()
            );
        }
    }
    // Whether `bazel mod deps` leaves the committed lock as it is. Recorded, not
    // asserted: the lock was made on one OS, and a cell on another may add keys.
    // (The `mod` command ran on 6.6.0 and later.)
    let reproduced = match &committed {
        Some(bytes) if cell.bazel.version.at_least(6, 6, 0) => {
            let options = Options {
                lockfile_mode: "update",
                ..cell.options.clone()
            };
            let run = cell.bazel_with(&options, "mod", &["deps"]);
            assert!(run.ok(), "{test}: {}", run.dump());
            Some(cell.module_lock().as_ref() == Some(bytes))
        }
        _ => None,
    };

    // Tier 0: the files Bazel materialised are the mirrored ones, from every root.
    let probe = fixture.probe(&matrix);
    for root in &roots {
        let listed = tier0_query(&cell, root);
        assert!(listed.ok(), "{test}: tier 0 from {root}: {}", listed.dump());
        let sources = parse_locations(&listed.stdout());
        for file in probe {
            if let Err(why) = file.check(&sources) {
                panic!("{test}: tier 0 from {root}: {why}");
            }
        }
    }
    // Tier 2 is not run here, but its target must exist and its rule must load.
    let consumer = cell.bazel_ok("query", &["--output=label_kind", CONSUMER]);
    let consumer = consumer.stdout().trim().to_string();
    assert!(consumer.ends_with(CONSUMER), "{test}: {consumer:?}");
    // A repository neither target loads is fetched here, and its pin checked.
    for label in &fixture.load {
        cell.bazel_ok("query", &["--output=label", label]);
    }

    let resolved = resolved_versions(&cell, system, &fixture.pins);
    assert_eq!(
        resolved, fixture.pins,
        "{test}: Bazel resolved other ruleset versions than {ruleset}/MATRIX.json pins"
    );

    let recorded = cell
        .module_lock()
        .map(|lock| recorded_extensions(&lock).unwrap_or_else(|why| panic!("{test}: {why}")));
    for (extension, expected) in [
        (&fixture.recorded_extension, true),
        (&fixture.not_recorded_extension, false),
    ] {
        let Some(extension) = extension else { continue };
        let Some(recorded) = &recorded else {
            panic!("{test}: Bazel left no {MODULE_LOCK} to look for {extension} in");
        };
        assert_eq!(
            records(recorded, extension),
            expected,
            "{test}: {MODULE_LOCK} records {extension}: expected {expected}, the lock has {recorded:?}"
        );
    }

    // Bazel wrote nothing but its own files: no ruleset tool rewrote a lock, a
    // hash file or a manifest of the fixture, so a later test's snapshot of this
    // state is stable. (For an `update_pnpm_lock` fixture this is also the proof
    // that the committed hash file matched and no pnpm ran.)
    assert_same_tree_but_bazel_owned(&untouched, &snapshot(&cell.scratch.workspace));

    // Every request the server saw was for a mirrored file: a miss means the
    // fixture pins something the mirror does not hold.
    let requests = server.requests();
    let misses: Vec<&str> = requests
        .iter()
        .filter(|request| request.status != 200)
        .map(|request| request.url.as_str())
        .collect();
    assert!(
        misses.is_empty(),
        "{test}: the fixture server could not answer {misses:?}"
    );
    // On an empty repository cache Bazel had to ask for each probed artifact, so
    // the rewrite is proven to reach this ruleset's fetch path. A shared cache
    // may answer a checksummed artifact with no request at all.
    let cold = env::var(env::CACHE_ROOT).is_none();
    if cold {
        for file in probe {
            // A loopback repository is asked for the path alone.
            let direct = file.artifact().strip_prefix(maven::HOST);
            let url = direct.filter(|_| fixture.loopback_repository.is_some());
            server.assert_requested(url.unwrap_or(file.artifact()), test);
        }
    }

    // A request to the loopback repository carries no host of its own.
    let host = |host: String| match host.as_str() {
        maven::ROOT => "127.0.0.1".to_string(),
        _ => host,
    };
    let hosts = server.hosts().into_iter().map(host).collect();
    cell.report.hosts_from_renamed_log(&server, hosts);
    cell.report.direct_network = true;
    cell.report.resolved = resolved;
    cell.report
        .detail("fixture", format!("light/{ruleset}/{path}"))
        .detail("tier", spec.tier.clone())
        .detail("proof", spec.proof)
        .detail("fetch", fixture.fetch.clone())
        .detail("outcome", spec.outcome.clone())
        .detail("tier0_roots", roots)
        .detail("loaded", fixture.load.clone())
        .detail("consumer", consumer)
        .detail("cold_repository_cache", cold)
        .detail("fixture_server_requests", requests.len())
        .detail("recorded_extensions", recorded)
        .detail("committed_lock_reproduced", reproduced);
    let report = cell.close();
    report.ran();
}

/// One `#[ignore]` test per fixture, named as `MATRIX.json` names it, and the
/// same list as data for the cross-check below.
macro_rules! canaries {
    ($($test:ident => ($ruleset:literal, $path:literal);)*) => {
        $(
            #[test]
            #[ignore = "real Bazel and the network; run with --ignored"]
            fn $test() {
                baseline(stringify!($test), $ruleset, $path);
            }
        )*

        /// `(test, ruleset, fixture path)` of every canary declared here.
        const CANARIES: &[(&str, &str, &str)] =
            &[$((stringify!($test), $ruleset, $path)),*];
    };
}

canaries! {
    bazel_canary_baseline_rules_js_bzlmod_e9 => ("rules_js", "bzlmod/e9");
    bazel_canary_baseline_rules_js_bzlmod_e9_sub => ("rules_js", "bzlmod/e9-sub");
    bazel_canary_baseline_rules_js_bzlmod_e9_npm_lock => ("rules_js", "bzlmod/e9-npm-lock");
    bazel_canary_baseline_rules_js_bzlmod_e9_upl_pnpm9 => ("rules_js", "bzlmod/e9-upl-pnpm9");
    bazel_canary_baseline_rules_js_bzlmod_e9_upl_pnpm10 => ("rules_js", "bzlmod/e9-upl-pnpm10");
    bazel_canary_baseline_rules_js_bzlmod_e9_upl_pnpm11 => ("rules_js", "bzlmod/e9-upl-pnpm11");
    bazel_canary_baseline_rules_js_bzlmod_e9_upl_pnpm12 => ("rules_js", "bzlmod/e9-upl-pnpm12");
    bazel_canary_baseline_rules_js_bzlmod_e7 => ("rules_js", "bzlmod/e7");
    bazel_canary_baseline_rules_js_bzlmod_e7_lock54 => ("rules_js", "bzlmod/e7-lock54");
    bazel_canary_baseline_rules_js_bzlmod_e7_npmrc => ("rules_js", "bzlmod/e7-npmrc");
    bazel_canary_baseline_rules_js_bzlmod_e7_upl => ("rules_js", "bzlmod/e7-upl");
    bazel_canary_baseline_rules_js_workspace_e7 => ("rules_js", "workspace/e7");
    bazel_canary_baseline_rules_js_bzlmod_e6 => ("rules_js", "bzlmod/e6");
    bazel_canary_baseline_rules_js_bzlmod_e6_floor => ("rules_js", "bzlmod/e6-floor");
    bazel_canary_baseline_rules_js_workspace_e6 => ("rules_js", "workspace/e6");
    bazel_canary_baseline_rules_jvm_external_bzlmod_e9 => ("rules_jvm_external", "bzlmod/e9");
    bazel_canary_baseline_rules_jvm_external_bzlmod_e9_two_hubs => ("rules_jvm_external", "bzlmod/e9-two-hubs");
    bazel_canary_baseline_rules_jvm_external_bzlmod_e9_spoke => ("rules_jvm_external", "bzlmod/e9-spoke");
    bazel_canary_baseline_rules_jvm_external_bzlmod_e8_insertion => ("rules_jvm_external", "bzlmod/e8-insertion");
    bazel_canary_baseline_rules_jvm_external_bzlmod_e7_v2 => ("rules_jvm_external", "bzlmod/e7-v2");
    bazel_canary_baseline_rules_jvm_external_bzlmod_e9_unpinned => ("rules_jvm_external", "bzlmod/e9-unpinned");
    bazel_canary_baseline_rules_ruby_bzlmod_e9 => ("rules_ruby", "bzlmod/e9");
    bazel_canary_baseline_rules_ruby_bzlmod_e9_nosums => ("rules_ruby", "bzlmod/e9-nosums");
    bazel_canary_baseline_rules_ruby_bzlmod_e9_transitive => ("rules_ruby", "bzlmod/e9-transitive");
    bazel_canary_baseline_rules_ruby_workspace_e7 => ("rules_ruby", "workspace/e7");
    bazel_canary_baseline_rules_dotnet_bzlmod_e9 => ("rules_dotnet", "bzlmod/e9");
    bazel_canary_baseline_rules_dotnet_bzlmod_e7 => ("rules_dotnet", "bzlmod/e7");
    bazel_canary_baseline_rules_csharp_bzlmod_e9 => ("rules_csharp", "bzlmod/e9");
}

// ---------------------------------------------------------------------------
// Hermetic checks of the fixtures, the matrices and the registry modules.

/// The ruleset directories under `root` (`fixtures/bazel/light`): every
/// directory but the registry mirror. `Err` for one without a `MATRIX.json`:
/// none of its fixtures would be checked, or run.
fn rulesets_in(root: &Path) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let entries = std::fs::read_dir(root).map_err(|e| format!("{}: {e}", root.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if !path.is_dir() || name == "registry" {
            continue;
        }
        if !path.join("MATRIX.json").is_file() {
            return Err(format!("{} has no MATRIX.json", path.display()));
        }
        names.push(name);
    }
    names.sort();
    Ok(names)
}

fn rulesets() -> Vec<String> {
    rulesets_in(&light()).unwrap_or_else(|why| panic!("{why}"))
}

/// The fixture workspaces on disk under one ruleset's directory, as matrix
/// paths: everything inside each of its sub-directories. `Err` for a
/// sub-directory that is no dependency system, whose workspaces no test opens.
fn fixture_dirs_in(ruleset: &Path) -> Result<BTreeSet<String>, String> {
    let mut paths = BTreeSet::new();
    let entries = std::fs::read_dir(ruleset).map_err(|e| format!("{}: {e}", ruleset.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.path().is_dir() {
            continue;
        }
        let system = entry.file_name().to_string_lossy().into_owned();
        if System::parse(&system).is_none() {
            return Err(format!(
                "{}: not a dependency system (bzlmod, workspace, hybrid)",
                entry.path().display()
            ));
        }
        let eras = std::fs::read_dir(entry.path()).map_err(|e| e.to_string())?;
        for era in eras {
            let era = era.map_err(|e| e.to_string())?;
            let era = era.file_name().to_string_lossy().into_owned();
            paths.insert(format!("{system}/{era}"));
        }
    }
    Ok(paths)
}

/// The text of every file of the fixture at `dir` that is part of its
/// workspace, as one string per file. A workspace holds no binary file; the
/// data directories ([`fixture_data_dir`]) may.
fn texts_of(dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut texts = BTreeMap::new();
    for (name, entry) in snapshot(dir) {
        let Entry::File { bytes, .. } = entry else {
            continue;
        };
        if name
            .split_once('/')
            .is_some_and(|(top, _)| fixture_data_dir(top))
        {
            continue;
        }
        let text = String::from_utf8(bytes)
            .map_err(|_| format!("{}/{name} is not UTF-8", dir.display()))?;
        texts.insert(name, text);
    }
    Ok(texts)
}

fn fixture_texts(ruleset: &str, path: &str) -> BTreeMap<String, String> {
    texts_of(&light().join(ruleset).join(path)).unwrap_or_else(|why| panic!("{why}"))
}

/// The Bazel versions `scripts/bazel-pins.txt` pins.
fn pinned_bazel_versions() -> BTreeSet<String> {
    let pins = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/bazel-pins.txt");
    let text = std::fs::read_to_string(&pins).expect("read scripts/bazel-pins.txt");
    let version = |line: &str| {
        let mut words = line.split_whitespace();
        (words.next() == Some("bazel")).then(|| words.next().unwrap_or_default().to_string())
    };
    text.lines().filter_map(version).collect()
}

/// Whether `text` can stand for a label inside a query expression.
fn is_label(text: &str) -> bool {
    let rooted = text.starts_with("//") || (text.starts_with('@') && text.contains("//"));
    rooted && !text.contains(|c: char| c.is_whitespace() || "\"'()".contains(c))
}

/// What is wrong with a list of cells: of a fixture's baseline (`top` is
/// [`BASELINE_PROOF`]) or of a lane test ([`TOP_PROOF`]).
fn cell_problems(
    cells: &[CellSpec],
    system: Option<System>,
    pinned: &BTreeSet<String>,
    top: u8,
    ruleset: &str,
) -> Vec<String> {
    let mut problems = Vec::new();
    if cells.is_empty() {
        problems.push("no cell claims it".to_string());
    }
    let mut seen = BTreeSet::new();
    for spec in cells {
        let bazel = &spec.bazel;
        if !seen.insert(bazel) {
            problems.push(format!("Bazel {bazel} is listed twice"));
        }
        if !pinned.contains(bazel) {
            problems.push(format!("Bazel {bazel} is not in scripts/bazel-pins.txt"));
        }
        // Whatever the pins file says: 7.7.0 alone writes absolute `file:///`
        // registry keys into `MODULE.bazel.lock`, so no fixture is claimed on it.
        if bazel == NEVER_PINNED {
            problems.push(format!(
                "Bazel {bazel} is never pinned: its locks record absolute file:/// registry keys"
            ));
        }
        if let (Some(version), Some(system)) = (Version::parse(bazel), system) {
            if version.system_flags(system).is_none() {
                problems.push(format!("Bazel {bazel} has no {} system", system.name()));
            }
        }
        if !TIERS.contains(&spec.tier.as_str()) {
            problems.push(format!(
                "Bazel {bazel}: tier {:?} is not one of {TIERS:?}",
                spec.tier
            ));
        }
        if spec.proof > top {
            problems.push(format!(
                "Bazel {bazel}: proof {} is above {top}, the highest tier this test climbs",
                spec.proof
            ));
        }
        if let Some(outcome) = spec.outcome.as_deref().filter(|o| !OUTCOMES.contains(o)) {
            problems.push(format!(
                "Bazel {bazel}: outcome {outcome:?} is not one of {OUTCOMES:?}"
            ));
        }
        if let Some(cache) = spec.cache.as_deref().filter(|c| !CACHES.contains(c)) {
            problems.push(format!(
                "Bazel {bazel}: cache {cache:?} is not one of {CACHES:?}"
            ));
        }
        // Any build through a rules_jvm_external hub pulls a JDK, up to 418 MB.
        if ruleset == "rules_jvm_external" && spec.tier == "pr" && spec.proof > 0 {
            problems.push(format!(
                "Bazel {bazel}: a rules_jvm_external cell of the PR tier stops at proof 0"
            ));
        }
    }
    problems
}

/// What is wrong with one fixture's entry, read without its tree.
fn fixture_problems(matrix: &Matrix, fixture: &Fixture, pinned: &BTreeSet<String>) -> Vec<String> {
    let ruleset = matrix.ruleset.as_str();
    let mut problems = Vec::new();

    let system = match fixture.path.split_once('/') {
        Some((system, era)) if system == fixture.system && !era.is_empty() => {
            System::parse(system).filter(|_| !era.contains('/'))
        }
        _ => None,
    };
    if system.is_none() {
        problems.push(format!(
            "the path is not <system>/<era> under the dependency system {:?}",
            fixture.system
        ));
    }
    let canary = format!(
        "{CANARY_PREFIX}{ruleset}_{}",
        fixture.path.replace(['/', '-'], "_")
    );
    if fixture.test != canary {
        problems.push(format!("its test is {}, not {canary}", fixture.test));
    }
    if fixture.shape.is_empty() || fixture.pins.is_empty() {
        problems.push("no shape, or no pins".to_string());
    }
    if fixture.probe(matrix).is_empty() {
        problems.push("nothing to probe: tier 0 would check no file".to_string());
    }
    if !FETCHERS.contains(&fixture.fetch.as_str()) {
        problems.push(format!(
            "fetch {:?} is not one of {FETCHERS:?}",
            fixture.fetch
        ));
    }
    if fixture.loopback_repository.is_some() && fixture.fetch != "tool" {
        problems.push(
            "a loopback repository serves a tool the downloader does not carry: fetch is \"tool\""
                .to_string(),
        );
    }
    problems.extend(cell_problems(
        &fixture.cells,
        system,
        pinned,
        BASELINE_PROOF,
        ruleset,
    ));
    // The CI plan restores no repository cache for a canary's cell, so a
    // `cache` there would state what no run does.
    let warm = |cells: &[CellSpec]| cells.iter().any(|spec| spec.cache.is_some());
    let cold = "a canary's cell runs on a cold repository cache and takes no `cache`";
    if warm(&fixture.cells) {
        problems.push(cold.to_string());
    }
    let cell = |bazel: &str| fixture.cells.iter().find(|spec| spec.bazel == bazel);
    for bazel in fixture.module_lock.keys() {
        match cell(bazel) {
            None => problems.push(format!("a lock for Bazel {bazel}, which no cell claims")),
            Some(spec) if spec.proof < 1 => problems.push(format!(
                "the lock for Bazel {bazel} is proven by an error-mode build: its cell needs proof 1"
            )),
            Some(_) => {}
        }
    }
    if let Some(expected) = &fixture.build_stderr {
        if expected.contains.is_empty() {
            problems.push("build_stderr.contains is empty".to_string());
        }
        for os in &expected.not_on {
            if !["linux", "macos", "windows"].contains(&os.as_str()) {
                problems.push(format!("build_stderr.not_on names no host system: {os:?}"));
            }
        }
        if fixture.cells.iter().any(|spec| spec.proof < 1) {
            problems
                .push("build_stderr is read from a build: every cell needs proof 1".to_string());
        }
    }
    let roots: BTreeSet<&String> = fixture.tier0_roots.iter().collect();
    if roots.len() != fixture.tier0_roots.len() {
        problems.push("a tier-0 root twice".to_string());
    }
    for root in &fixture.tier0_roots {
        if !is_label(root) {
            problems.push(format!("the tier-0 root {root:?} is not a label"));
        }
    }
    for label in &fixture.load {
        if !label.starts_with('@') || !is_label(label) {
            problems.push(format!(
                "load names {label:?}, not a label in an external repository"
            ));
        }
    }
    if fixture.recorded_extension.is_some()
        && fixture.recorded_extension == fixture.not_recorded_extension
    {
        problems.push("one extension is both recorded and not recorded".to_string());
    }
    for lane in &fixture.lanes {
        let test = &lane.test;
        let lane_test = LANE_PREFIXES.iter().any(|prefix| test.starts_with(prefix));
        if !lane_test || test.starts_with(CANARY_PREFIX) {
            problems.push(format!(
                "the lane test {test} has none of the prefixes {LANE_PREFIXES:?}, or is a baseline"
            ));
        }
        for why in cell_problems(&lane.cells, system, pinned, TOP_PROOF, ruleset) {
            problems.push(format!("{test}: {why}"));
        }
        if test.starts_with(COLD_PREFIX) && warm(&lane.cells) {
            problems.push(format!("{test}: {cold}"));
        }
        for spec in &lane.cells {
            if cell(&spec.bazel).is_none() {
                problems.push(format!(
                    "{test}: Bazel {} is no cell of the fixture's baseline",
                    spec.bazel
                ));
            }
        }
    }
    let what = format!("{ruleset}/{}", fixture.path);
    problems
        .into_iter()
        .map(|why| format!("{what}: {why}"))
        .collect()
}

/// What is wrong with a matrix, read without the fixture trees.
fn matrix_problems(matrix: &Matrix, pinned: &BTreeSet<String>) -> Vec<String> {
    let ruleset = &matrix.ruleset;
    let mut problems = Vec::new();
    if matrix.registries.is_empty() {
        problems.push(format!("{ruleset}: no registry serves its packages"));
    }
    for name in &matrix.registries {
        if !REGISTRIES.contains(&name.as_str()) {
            problems.push(format!(
                "{ruleset}: unknown registry {name:?} (known: {REGISTRIES:?})"
            ));
        }
    }
    let mut paths = BTreeSet::new();
    for fixture in &matrix.fixtures {
        if !paths.insert(&fixture.path) {
            problems.push(format!("{ruleset}: {} is listed twice", fixture.path));
        }
        problems.extend(fixture_problems(matrix, fixture, pinned));
    }
    problems
}

/// What is wrong with the committed lock `rel` of `fixture`: its place, its
/// version, where it was resolved, and the extension entries the fixture's
/// shape rests on.
fn lock_problems(fixture: &Fixture, rel: &str, bytes: &[u8]) -> Vec<String> {
    let mut problems = Vec::new();
    let place = regex::Regex::new(r"^locks/v(\d+)/(?:([^/]+)/)?MODULE\.bazel\.lock$").unwrap();
    let placed = place.captures(rel);
    let stated: Option<u64> = placed.as_ref().and_then(|hit| hit[1].parse().ok());
    let per_os = placed.as_ref().is_some_and(|hit| hit.get(2).is_some());
    if stated.is_none() {
        problems.push(format!("{rel} is not locks/v<N>[/<os>]/{MODULE_LOCK}"));
    }
    // A lock made against a `file://` or loopback registry records that
    // registry, and Bazel then reads it on every machine.
    let text = String::from_utf8_lossy(bytes);
    for host in ["127.0.0.1", "localhost", "file://", ".invalid"] {
        if text.contains(host) {
            problems.push(format!("{rel} names {host}"));
        }
    }
    let lock: Value = match serde_json::from_slice(bytes) {
        Ok(lock) => lock,
        Err(e) => {
            problems.push(format!("{rel} is not JSON: {e}"));
            return problems;
        }
    };
    let version = lock["lockFileVersion"].as_u64();
    if version.is_none() || version != stated {
        problems.push(format!(
            "{rel} has lockFileVersion {version:?}, its directory says {stated:?}"
        ));
    }
    let registry_files = lock["registryFileHashes"].as_object();
    for url in registry_files.into_iter().flat_map(|files| files.keys()) {
        if !url.starts_with("https://bcr.bazel.build/") {
            problems.push(format!(
                "{rel} resolved {url} outside https://bcr.bazel.build/"
            ));
        }
    }
    let recorded = match recorded_extensions(bytes) {
        Ok(recorded) => recorded,
        Err(why) => {
            problems.push(format!("{rel}: {why}"));
            return problems;
        }
    };
    // One lock serves every host only when no entry is keyed by a host system:
    // a lock made on macOS whose entry is keyed `os:osx,arch:aarch64` holds
    // nothing for a Linux host. Such a fixture carries one lock per OS the
    // matrix runs.
    let extensions = lock["moduleExtensions"].as_object();
    for (extension, entries) in extensions.into_iter().flatten() {
        let keys = entries.as_object().into_iter().flat_map(|map| map.keys());
        for key in keys.filter(|key| !per_os && key.as_str() != GENERAL) {
            problems.push(format!(
                "{rel} records {extension} under {key:?}: a lock with a host-keyed entry goes \
                 under locks/v<N>/<os>/, one per OS the matrix runs"
            ));
        }
    }
    if let Some(extension) = &fixture.recorded_extension {
        if !records(&recorded, extension) {
            problems.push(format!("{rel} does not record {extension}"));
        }
    }
    if let Some(extension) = &fixture.not_recorded_extension {
        if records(&recorded, extension) {
            problems.push(format!("{rel} records {extension}"));
        }
    }
    problems
}

/// The names of the functions a Rust source declares with a plain `fn`. A name
/// a macro builds is not seen.
fn declared_functions(source: &str) -> Vec<String> {
    let declaration =
        regex::Regex::new(r"(?m)^\s*(?:pub(?:\([a-z]+\))?\s+)?fn\s+([A-Za-z0-9_]+)\s*\(").unwrap();
    let names = declaration.captures_iter(source);
    names.map(|hit| hit[1].to_string()).collect()
}

/// Function name to the modules of this suite that declare it, this one
/// excepted: where a lane package declares the tests a matrix names.
fn suite_functions() -> BTreeMap<String, Vec<String>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/e2e_bazel_build");
    let mut functions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).expect("read e2e_bazel_build") {
        let entry = entry.expect("dir entry");
        let file = entry.file_name().to_string_lossy().into_owned();
        if !file.ends_with(".rs") || file == "baseline_light.rs" {
            continue;
        }
        let source = std::fs::read_to_string(entry.path()).expect("read a suite module");
        for name in declared_functions(&source) {
            functions.entry(name).or_default().push(file.clone());
        }
    }
    functions
}

/// What is wrong with how the tests the matrices name are declared. `fixtures`
/// is the `(test, ruleset, path)` of every listed fixture, `lanes` every lane
/// test, `canaries` the list of `canaries!`, and `declared` the result of
/// [`suite_functions`]. A fixture's canary is declared once: by `canaries!`
/// for that fixture, or by another module of the suite. A lane test is
/// declared once, by another module.
fn declaration_problems(
    fixtures: &[(String, String, String)],
    lanes: &[String],
    canaries: &[(&str, &str, &str)],
    declared: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let mut problems = Vec::new();
    let mut named = BTreeSet::new();
    for test in fixtures.iter().map(|(test, ..)| test).chain(lanes) {
        if !named.insert(test) {
            problems.push(format!("{test} is named twice in the matrices"));
        }
    }
    let elsewhere = |test: &str| declared.get(test).map(Vec::as_slice).unwrap_or(&[]);
    for (test, ruleset, path) in fixtures {
        let here: Vec<&(&str, &str, &str)> =
            canaries.iter().filter(|(name, ..)| name == test).collect();
        match (&here[..], elsewhere(test)) {
            ([(_, r, p)], []) if r == ruleset && p == path => {}
            ([(_, r, p)], []) => problems.push(format!(
                "canaries! declares {test} for {r}/{p}, MATRIX.json lists it for {ruleset}/{path}"
            )),
            ([], [_]) => {}
            ([], []) => problems.push(format!(
                "{ruleset}/{path} has no canary: add {test} to canaries!, or declare \
                 `fn {test}()` in the ruleset's module of the suite"
            )),
            (_, modules) => problems.push(format!(
                "{test} is declared more than once: {} time(s) by canaries! and in {modules:?}",
                here.len()
            )),
        }
    }
    for (test, ruleset, path) in canaries {
        if !fixtures.iter().any(|(name, ..)| name == test) {
            problems.push(format!(
                "canaries! declares {test} for {ruleset}/{path}, which no MATRIX.json lists"
            ));
        }
    }
    for test in lanes {
        match elsewhere(test) {
            [_] => {}
            [] => problems.push(format!(
                "the lane test {test} is declared in no module of the suite"
            )),
            modules => problems.push(format!(
                "the lane test {test} is declared more than once: {modules:?}"
            )),
        }
    }
    problems
}

/// rules_jvm_external's name for an artifact at a version: the repository
/// that holds its jar, and the hub's versioned alias
/// (`private/extensions/download_pinned_deps.bzl`, `escape`).
fn rje_versioned_name(coordinate: &str, version: &str) -> String {
    format!("{coordinate}:{version}").replace(['.', '-', ':', '/', '+'], "_")
}

/// The version-bearing rules_jvm_external names the Starlark files of a
/// fixture use outside comments: for every artifact a `maven_install.json`
/// lock (format v2 or v3) among `texts` pins, the name of
/// [`rje_versioned_name`] where a `MODULE.bazel`, `WORKSPACE`, `BUILD.bazel`
/// or `.bzl` file holds it.
fn versioned_names_used(texts: &BTreeMap<String, String>) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for text in texts.values() {
        let Ok(lock) = serde_json::from_str::<Value>(text) else {
            continue;
        };
        let artifacts = lock["artifacts"].as_object();
        for (coordinate, entry) in artifacts.into_iter().flatten() {
            if let Some(version) = entry["version"].as_str() {
                names.insert(rje_versioned_name(coordinate, version));
            }
        }
    }
    let starlark = |name: &&String| {
        let leaf = name.rsplit('/').next().unwrap_or(name);
        leaf.starts_with("MODULE.bazel")
            || leaf.starts_with("WORKSPACE")
            || leaf.starts_with("BUILD")
            || leaf.ends_with(".bzl")
    };
    let code: String = texts
        .iter()
        .filter(|(name, _)| starlark(name))
        .flat_map(|(_, text)| text.lines())
        .map(|line| line.split('#').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let used = |name: &String| {
        let token = regex::Regex::new(&format!(r"\b{}\b", regex::escape(name))).unwrap();
        token.is_match(&code)
    };
    names.into_iter().filter(used).collect()
}

/// Starlark source without its comments, for a check that reads what a file
/// declares. No fixture holds a `#` inside a string.
fn uncommented(source: &str) -> String {
    let code = source
        .lines()
        .map(|line| line.split('#').next().unwrap_or(""));
    code.collect::<Vec<_>>().join("\n")
}

/// The leading numbers of a ruleset release: `(3, 6, 0)` of `3.6.0`, `(7, 2, 0)`
/// of `7.2`, `(1, 0, 0)` of `1.0.0-rc2`.
fn release(version: &str) -> (u32, u32, u32) {
    let mut parts = version.split('.').map(|part| {
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().unwrap_or(0)
    });
    let mut next = || parts.next().unwrap_or(0);
    (next(), next(), next())
}

/// What is wrong with the `single_version_override` pins of a `MODULE.bazel`:
/// each comes with a `bazel_dep` of that module at the same version. Bazel 9.3.2
/// rejects an override below the declared version (`module 'bazel_skylib' is
/// overridden to use version '1.6.1', which is lower than the version '1.7.1'
/// requested by the root module`), and above it the `bazel_dep` line states a
/// version no build uses.
fn override_problems(module: &str) -> Vec<String> {
    let code = uncommented(module);
    let pairs = |call: &str, name: &str| -> Vec<(String, String)> {
        let pattern = format!(r#"\b{call}\(\s*{name} = "([^"]+)",\s*version = "([^"]*)""#);
        let found = regex::Regex::new(&pattern).unwrap();
        let hits = found.captures_iter(&code);
        hits.map(|hit| (hit[1].to_string(), hit[2].to_string()))
            .collect()
    };
    let declared: BTreeMap<String, String> = pairs("bazel_dep", "name").into_iter().collect();
    let mut problems = Vec::new();
    for (module, version) in pairs("single_version_override", "module_name") {
        match declared.get(&module) {
            Some(dep) if *dep == version => {}
            Some(dep) => problems.push(format!(
                "{module} is overridden to {version} and declared at {dep}"
            )),
            None => problems.push(format!(
                "{module} is overridden to {version} and no bazel_dep declares a version of it"
            )),
        }
    }
    problems
}

/// What a rules_js workspace declares about its hub.
struct NpmHub {
    /// The hub's name: `npm`.
    name: String,
    /// The pnpm lock as a label without its repository: `//app:pnpm-lock.yaml`.
    lock_label: String,
    update_pnpm_lock: bool,
    /// The managed pnpm the workspace names, where it names one.
    pnpm_version: Option<String>,
}

impl NpmHub {
    /// Read from `MODULE.bazel` or `WORKSPACE`: its one `npm_translate_lock` call.
    fn read(declaration: &str) -> Result<NpmHub, String> {
        let code = uncommented(declaration);
        let mut calls = code.split("npm_translate_lock(").skip(1);
        let (Some(call), None) = (calls.next(), calls.next()) else {
            return Err("not exactly one npm_translate_lock call".to_string());
        };
        let body = call.split(')').next().unwrap_or("");
        let text = |attribute: &str, within: &str| {
            let pattern = format!(r#"\b{attribute} = "([^"]*)""#);
            let found = regex::Regex::new(&pattern).unwrap().captures(within)?;
            Some(found[1].to_string())
        };
        let name = text("name", body).ok_or("the hub has no name")?;
        let lock_label = text("pnpm_lock", body).ok_or("the hub has no pnpm_lock")?;
        if !lock_label.starts_with("//") || !lock_label.contains(':') {
            return Err(format!(
                "pnpm_lock {lock_label:?} is not //<package>:<file>"
            ));
        }
        Ok(NpmHub {
            name,
            lock_label,
            update_pnpm_lock: body.contains("update_pnpm_lock = True"),
            pnpm_version: text("pnpm_version", &code),
        })
    }

    /// The workspace path of `file` in the lock's package.
    fn beside_lock(&self, file: &str) -> String {
        match self.lock_label[2..].split(':').next().unwrap_or("") {
            "" => file.to_string(),
            package => format!("{package}/{file}"),
        }
    }

    /// The lock's path in the workspace: `app/pnpm-lock.yaml`.
    fn lock_path(&self) -> String {
        let name = self.lock_label.rsplit(':').next().unwrap_or("");
        self.beside_lock(name)
    }

    /// Where rules_js keeps the hub's `update_pnpm_lock` hash file: the name ends
    /// in the base64 of the decimal Starlark `hash` of the hub name followed by
    /// the lock label (`npm_translate_lock_state.bzl`, `_init_update_labels`).
    fn hash_file(&self) -> String {
        let key = format!("{}{}", self.name, self.lock_label);
        let hash = java_hash::hash_bytes(key.as_bytes()).to_string();
        let suffix = base64::engine::general_purpose::STANDARD.encode(hash);
        format!(".aspect/rules/external_repository_action_cache/npm_translate_lock_{suffix}")
    }
}

/// `9.0` of `lockfileVersion: '9.0'`, the line that opens a pnpm lock.
fn lockfile_version(lock: &str) -> String {
    let line = lock
        .lines()
        .find_map(|line| line.strip_prefix("lockfileVersion:"));
    line.unwrap_or("").trim().trim_matches('\'').to_string()
}

/// Whether the workspace carries pnpm's lifecycle-hook allow list where rules_js
/// looks for it: `pnpm.onlyBuiltDependencies` in the `package.json` beside the
/// lock, or `onlyBuiltDependencies` / `allowBuilds` in a `pnpm-workspace.yaml`
/// there.
fn allows_builds(hub: &NpmHub, texts: &BTreeMap<String, String>) -> bool {
    let manifest = texts.get(&hub.beside_lock("package.json"));
    let manifest = manifest.and_then(|text| serde_json::from_str::<Value>(text).ok());
    let in_manifest = manifest.is_some_and(|m| m["pnpm"]["onlyBuiltDependencies"].is_array());
    let key =
        |line: &str| line.starts_with("onlyBuiltDependencies:") || line.starts_with("allowBuilds:");
    let workspace = texts.get(&hub.beside_lock("pnpm-workspace.yaml"));
    in_manifest || workspace.is_some_and(|text| text.lines().any(key))
}

/// What is wrong with the committed `update_pnpm_lock` hash file of `hub`. rules_js
/// compares each `<path>=<value>` line with the Starlark `hash` of that file; on a
/// difference it runs pnpm and rewrites the lock and this file. A fixture commits
/// the lines rules_js would write, so its baseline build runs no pnpm.
fn hash_file_problems(hub: &NpmHub, texts: &BTreeMap<String, String>) -> Vec<String> {
    let path = hub.hash_file();
    let Some(file) = texts.get(&path) else {
        return vec![format!("update_pnpm_lock without the hash file {path}")];
    };
    let mut problems = Vec::new();
    let mut recorded = BTreeSet::new();
    let lines = file.lines().filter(|line| !line.is_empty());
    for line in lines.filter(|line| !line.starts_with('#')) {
        let Some((input, value)) = line.split_once('=') else {
            problems.push(format!("{path}: {line:?} is not <path>=<hash>"));
            continue;
        };
        recorded.insert(input.to_string());
        let hash = texts
            .get(input)
            .map(|text| java_hash::hash_bytes(text.as_bytes()).to_string());
        match hash {
            Some(hash) if hash == value => {}
            Some(hash) => problems.push(format!(
                "{path} records {input} as {value}, the file hashes to {hash}: the first build \
                 would run pnpm"
            )),
            None => problems.push(format!("{path} records {input}, which the fixture lacks")),
        }
    }
    for input in [hub.lock_path(), hub.beside_lock("package.json")] {
        if !recorded.contains(&input) {
            problems.push(format!("{path} has no line for {input}"));
        }
    }
    problems
}

/// What is wrong with a rules_js fixture, read from the files of its workspace:
/// the facts the probes fixed that the matrix alone cannot show. `pin` is the
/// rules_js release the fixture is written for, `bazel` the versions of its cells.
fn rules_js_problems(pin: &str, bazel: &[&str], texts: &BTreeMap<String, String>) -> Vec<String> {
    let declaration = texts.get("MODULE.bazel").or_else(|| texts.get("WORKSPACE"));
    let Some(declaration) = declaration else {
        return vec!["neither MODULE.bazel nor WORKSPACE".to_string()];
    };
    let hub = match NpmHub::read(declaration) {
        Ok(hub) => hub,
        Err(why) => return vec![why],
    };
    let Some(lock) = texts.get(&hub.lock_path()) else {
        return vec![format!("no {}", hub.lock_path())];
    };
    let lock_version = lockfile_version(lock);
    let (major, ..) = release(pin);
    let mut problems = Vec::new();
    if major >= 2 && lock_version == "9.0" && !allows_builds(&hub, texts) {
        problems.push(
            "a 9.0 lock on rules_js 2.x or 3.x without the lifecycle-hook allow list: the build \
             fails with `pnpm 'allowBuilds' ... configuration required`"
                .to_string(),
        );
    }
    // Lock 6.0 belongs to rules_js 1.x on the 6.6.0, 7.0.2 and 7.1.2 lines.
    let late = |version: &str| Version::parse(version).is_some_and(|v| v.at_least(7, 7, 0));
    for version in bazel.iter().filter(|v| lock_version == "6.0" && late(v)) {
        problems.push(format!("a pnpm lock 6.0 has no cell on Bazel {version}"));
    }
    if hub.update_pnpm_lock {
        problems.extend(hash_file_problems(&hub, texts));
        // rules_js 2.x manages pnpm 8 unless told otherwise, and its version
        // table ends at 10.22.0; the hash-miss cells are proven on pnpm 9 and 10.
        let managed = hub.pnpm_version.as_deref().map(release);
        let in_table = |pnpm: (u32, u32, u32)| ((9, 0, 0)..=(10, 22, 0)).contains(&pnpm);
        match managed {
            _ if major != 2 => {}
            Some(pnpm) if in_table(pnpm) => {}
            Some(_) => problems.push(format!(
                "rules_js {pin} cannot manage pnpm {}: name a 9.x release, or 10.x up to 10.22.0",
                hub.pnpm_version.as_deref().unwrap_or_default()
            )),
            None => problems.push(format!(
                "rules_js {pin} manages pnpm 8 by default: name pnpm_version 9.x or 10.x"
            )),
        }
    }
    // A lock of another package manager beside the pnpm lock is one no hub reads,
    // and the input of the `.npmrc` creation hazard: the workspace has none yet.
    if texts.contains_key(&hub.beside_lock("package-lock.json")) {
        if uncommented(declaration).contains("package-lock.json") {
            problems.push("the hub names the sibling package-lock.json".to_string());
        }
        if texts.contains_key(&hub.beside_lock(".npmrc")) {
            problems.push("a sibling package-lock.json beside an .npmrc".to_string());
        }
    }
    problems
}

/// The files `paket2bazel` generated for a rules_dotnet fixture, as far as the
/// lock gate reads them.
#[derive(Debug, PartialEq)]
struct PaketFiles {
    /// The `moduleExtensions` key of the generated extension:
    /// `//deps:paket.main_extension.bzl%main_extension`.
    extension: String,
    /// Whether the extension file holds the literal `reproducible = True`. With
    /// it Bazel records nothing; without it the lock holds the extension's
    /// result, and an edit of the data file stales the lock.
    reproducible: bool,
    /// Every `sha512` value of the data file.
    sha512: Vec<String>,
}

/// The first line of both files `paket2bazel` of rules_dotnet 0.13.0 - 0.14.x
/// writes.
const LEGACY_PAKET_HEADER: &str = "\"Generated by paket2bazel\"";

/// Read the generated pair of a rules_dotnet fixture and hold it to one
/// generation. On 0.13.0 - 0.14.x the data file and the extension file both start
/// `"Generated by paket2bazel"` and an entry has no `"name"` key; from 0.15.0 the
/// data file starts `"GENERATED"`, the extension file `"Generated"`, and an entry
/// starts with `"name"`. A fixture pinned below 0.15.0 holds the first
/// generation: that release generates no other. (Files of the first generation
/// under a later pin are a shape a project can have, and are not refused here.)
fn paket_files(pin: &str, texts: &BTreeMap<String, String>) -> Result<PaketFiles, String> {
    let module = texts.get("MODULE.bazel").ok_or("no MODULE.bazel")?;
    let used = regex::Regex::new(
        r#"use_extension\(\s*"//([^:"]*):(paket\.[^"]+_extension\.bzl)",\s*"([^"]+)""#,
    )
    .unwrap();
    let code = uncommented(module);
    let used = used
        .captures(&code)
        .ok_or("MODULE.bazel uses no generated paket extension")?;
    let (package, file, name) = (&used[1], &used[2], &used[3]);
    let beside = |file: &str| match package {
        "" => file.to_string(),
        package => format!("{package}/{file}"),
    };
    let extension = texts
        .get(&beside(file))
        .ok_or_else(|| format!("no {}", beside(file)))?;
    let loaded = regex::Regex::new(r#"load\(":([^"]+)""#).unwrap();
    let data_file = loaded
        .captures(extension)
        .map(|hit| beside(&hit[1]))
        .ok_or("the extension file loads no data file")?;
    let data = texts
        .get(&data_file)
        .ok_or_else(|| format!("no {data_file}"))?;

    let first = |text: &str| text.lines().next().unwrap_or("").to_string();
    let legacy = match (first(data).as_str(), first(extension).as_str()) {
        (LEGACY_PAKET_HEADER, LEGACY_PAKET_HEADER) => true,
        ("\"GENERATED\"", "\"Generated\"") => false,
        (data, extension) => {
            return Err(format!(
                "{data_file} starts {data} and its extension file {extension}: the headers of \
                 no one generation"
            ))
        }
    };
    if data.contains("{\"name\": ") == legacy {
        let expected = if legacy { "no" } else { "a" };
        return Err(format!(
            "{data_file}: files with this header have entries with {expected} \"name\" key"
        ));
    }
    if release(pin) < (0, 15, 0) && !legacy {
        return Err(format!(
            "rules_dotnet {pin} generates files that start {LEGACY_PAKET_HEADER}, the fixture \
             holds the later generation"
        ));
    }
    let reproducible = uncommented(extension).contains("reproducible = True");
    let sha512 = regex::Regex::new(r#""sha512": "(sha512-[^"]+)""#).unwrap();
    let sha512: Vec<String> = sha512
        .captures_iter(data)
        .map(|hit| hit[1].to_string())
        .collect();
    if sha512.is_empty() {
        return Err(format!("{data_file} pins no package"));
    }
    Ok(PaketFiles {
        extension: format!("//{package}:{file}%{name}"),
        reproducible,
        sha512,
    })
}

/// What is wrong with the `.bazelrc` of a rules_ruby fixture whose cells are on
/// `bazel`. rules_ruby's rules resolve a Java runtime: without a remote one named
/// the build stops at `Cannot find Java binary` on a host that has no JDK. Bazel
/// 6 ships `remotejdk_11`, the later lines `remotejdk_21`.
fn ruby_runtime_problem(rc: Option<&str>, bazel: &[&str]) -> Option<String> {
    let on_six = |version: &&str| Version::parse(version).is_some_and(|v| v.major <= 6);
    let runtime = match bazel.iter().all(on_six) {
        true => "remotejdk_11",
        false => "remotejdk_21",
    };
    let flag = format!("build --java_runtime_version={runtime}");
    let named = rc.is_some_and(|rc| rc.lines().any(|line| line.trim() == flag));
    (!named).then(|| format!(".bazelrc has no `{flag}`"))
}

/// The hash flavors that reproduce the stored hash of a rules_jvm_external lock,
/// by the names `MATRIX.json` writes.
fn reproduced_flavors(lock: &str) -> Result<Vec<String>, String> {
    let lock = rje_lock::read(lock).map_err(|why| format!("{why:?}"))?;
    let flavors = lock.reproduced().map_err(|why| format!("{why:?}"))?;
    let names = flavors
        .into_iter()
        .map(|flavor| flavor.as_str().to_string());
    Ok(names.collect())
}

/// What is wrong with the locks and the probe of a rules_jvm_external fixture.
///
/// Locks: every lock of the workspace is listed under `lock_flavors` with the
/// flavors that reproduce its stored hash, and a v3 lock reproduces under the
/// flavor its pinned release checks (6.10 in file order, 7.0 and later sorted).
///
/// Probe: the registry jar is under the artifact repository's `file/` directory,
/// and a pinned fixture reaches it one of two ways. Through the versionless hub
/// label (`tier0_roots`): a query lists the jar with no build, and every baseline
/// cell stops at proof 0, because building that label analyses a `jvm_import` and
/// pulls a JDK. Or through the versioned artifact repository (`versioned_names`),
/// whose `file` target builds with no Java toolchain, in a fixture that a rewrite
/// of the lock breaks.
fn rje_problems(fixture: &Fixture, texts: &BTreeMap<String, String>) -> Vec<String> {
    let mut problems = Vec::new();
    let is_lock =
        |(name, text): &(&String, &String)| name.ends_with(".json") && rje_lock::read(text).is_ok();
    let found: BTreeSet<&String> = texts.iter().filter(is_lock).map(|(name, _)| name).collect();
    let listed: BTreeSet<&String> = fixture.lock_flavors.keys().collect();
    if found != listed {
        problems.push(format!(
            "lock_flavors lists {listed:?}, the workspace holds the locks {found:?}"
        ));
    }
    let pin = fixture
        .pins
        .get("rules_jvm_external")
        .map(|pin| release(pin));
    let checked = match pin {
        Some((6, 10, _)) => Some("v3-insertion"),
        Some((7.., _, _)) => Some("v3-sorted"),
        _ => None,
    };
    for (rel, stated) in &fixture.lock_flavors {
        match texts.get(rel).map(|text| reproduced_flavors(text)) {
            Some(Ok(reproduced)) if reproduced == *stated => {}
            Some(Ok(reproduced)) => problems.push(format!(
                "{rel} reproduces under {reproduced:?}, lock_flavors says {stated:?}"
            )),
            Some(Err(why)) => problems.push(format!("{rel}: {why}")),
            None => problems.push(format!("lock_flavors names {rel}, which is no file")),
        }
        let v3 = stated.iter().any(|flavor| flavor.starts_with("v3-"));
        let stated_as = |flavor: &str| stated.iter().any(|name| name == flavor);
        if let Some(checked) = checked.filter(|checked| v3 && !stated_as(checked)) {
            problems.push(format!(
                "{rel}: the pinned release checks the {checked} hash, which is not in {stated:?}"
            ));
        }
    }
    if fixture.lock_flavors.is_empty() {
        return problems;
    }
    if fixture.tier0_roots.is_empty() {
        if fixture.versioned_names.is_empty() {
            problems.push(
                "a pinned fixture whose probe is neither rooted at a hub label (tier0_roots) nor \
                 reads a versioned artifact repository (versioned_names)"
                    .to_string(),
            );
        }
    } else if fixture.cells.iter().any(|spec| spec.proof > 0) {
        problems.push(
            "a pinned fixture probed through its hub stops at proof 0: building the hub label \
             pulls a JDK"
                .to_string(),
        );
    }
    problems
}

/// The matrices, the fixture directories and the declared tests name the same
/// fixtures, every entry has the shape the canary and the CI plan read, and a
/// committed lock is the lock its fixture claims.
#[test]
fn every_light_fixture_has_a_matrix_entry_and_a_canary() {
    let pinned = pinned_bazel_versions();
    let mut problems = Vec::new();
    let mut fixtures = Vec::new();
    let mut lanes = Vec::new();
    for ruleset in rulesets() {
        let matrix = Matrix::load(&ruleset);
        problems.extend(matrix_problems(&matrix, &pinned));
        let listed: BTreeSet<String> = matrix.fixtures.iter().map(|f| f.path.clone()).collect();
        let on_disk =
            fixture_dirs_in(&light().join(&ruleset)).unwrap_or_else(|why| panic!("{why}"));
        if listed != on_disk {
            problems.push(format!(
                "{ruleset}: MATRIX.json lists {listed:?}, the directories are {on_disk:?}"
            ));
        }
        for fixture in &matrix.fixtures {
            let what = format!("{ruleset}/{}", fixture.path);
            for rel in fixture.module_lock.values() {
                let lock = light().join(&ruleset).join(&fixture.path).join(rel);
                match std::fs::read(&lock) {
                    Ok(bytes) => {
                        let found = lock_problems(fixture, rel, &bytes);
                        problems.extend(found.into_iter().map(|why| format!("{what}: {why}")));
                    }
                    Err(e) => problems.push(format!("{what}: {}: {e}", lock.display())),
                }
            }
            fixtures.push((fixture.test.clone(), ruleset.clone(), fixture.path.clone()));
            lanes.extend(fixture.lanes.iter().map(|lane| lane.test.clone()));
        }
    }
    problems.extend(declaration_problems(
        &fixtures,
        &lanes,
        CANARIES,
        &suite_functions(),
    ));
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Each fixture is a workspace the harness can run: the two proof targets, no
/// probe rule or root lock of its own, production host names only, and the
/// ruleset pinned to the version its matrix entry states (`bazel_dep` and
/// `single_version_override` agree, or the WORKSPACE names that release).
#[test]
fn every_light_fixture_pins_its_ruleset_and_keeps_production_hosts() {
    for ruleset in rulesets() {
        let matrix = Matrix::load(&ruleset);
        for fixture in &matrix.fixtures {
            let what = format!("light/{ruleset}/{}", fixture.path);
            let texts = fixture_texts(&ruleset, &fixture.path);
            let build = texts.get("BUILD.bazel").expect("a root BUILD.bazel");
            for target in ["socket_probe", "consumer"] {
                assert!(
                    build.contains(&format!("name = \"{target}\"")),
                    "{what}: no //:{target}"
                );
            }
            assert!(!texts.contains_key(PROBE_BZL), "{what} ships {PROBE_BZL}");
            assert!(
                !texts.contains_key(MODULE_LOCK),
                "{what}: a committed lock goes under locks/"
            );
            // The one loopback URL a fixture may commit is the repository of a
            // client the downloader rewrite cannot reach, declared in the matrix.
            let declared = fixture.loopback_repository.as_deref();
            if let Some(url) = declared {
                assert!(url.starts_with("http://127.0.0.1:"), "{what}: {url}");
                assert!(texts["MODULE.bazel"].contains(url), "{what}: {url}");
            }
            for (name, text) in &texts {
                let text = declared.map_or(text.clone(), |url| text.replace(url, ""));
                for host in ["127.0.0.1", "localhost", ".invalid"] {
                    assert!(!text.contains(host), "{what}/{name} names {host}");
                }
            }
            // A name that carries a version does not survive a rewrite of the
            // lock: only a fixture that says so may use one.
            let versioned: BTreeSet<String> = fixture.versioned_names.iter().cloned().collect();
            assert_eq!(
                versioned_names_used(&texts),
                versioned,
                "{what}: the versioned names its Starlark files use, and `versioned_names`"
            );
            for (module, version) in &fixture.pins {
                if fixture.system == System::Workspace.name() {
                    let workspace = texts.get("WORKSPACE").expect("a WORKSPACE");
                    assert!(workspace.contains(&format!("name = \"{module}\"")));
                    assert!(
                        workspace.contains(&format!("/releases/download/v{version}/")),
                        "{what}: WORKSPACE does not name {module} {version}"
                    );
                    continue;
                }
                let module_file = texts.get("MODULE.bazel").expect("a MODULE.bazel");
                let dep = format!("bazel_dep(name = \"{module}\", version = \"{version}\")");
                let pin = format!(
                    "single_version_override(\n    module_name = \"{module}\",\n    \
                     version = \"{version}\",\n)"
                );
                assert!(module_file.contains(&dep), "{what}: no {dep}");
                assert!(module_file.contains(&pin), "{what}: no {pin}");
            }
            // Every override, of the ruleset or of anything else the fixture pins.
            if let Some(module_file) = texts.get("MODULE.bazel") {
                let found = override_problems(module_file);
                assert!(found.is_empty(), "{what}: {}", found.join("; "));
            }
        }
    }
}

/// The mirror holds what the locks pin: each probed artifact's digest, in the
/// encoding its ecosystem uses, appears in the fixture, and its URL is inside a
/// scope the ruleset's registries own, so the canary's rewrite sends it to the
/// fixture server. A mirror file replaced without its locks (or the reverse)
/// fails here, not in a Bazel checksum error a day later. An unpinned hub is the
/// exception that proves the rule: it commits no digest at all.
#[test]
fn every_light_lock_pins_the_mirrored_artifact() {
    for ruleset in rulesets() {
        let matrix = Matrix::load(&ruleset);
        let server = FixtureServer::start();
        let owned: Vec<regex::Regex> = mount(&server, &matrix.registries)
            .iter()
            .map(|scope| regex::Regex::new(&format!("^(?:{})$", scope_pattern(scope))).unwrap())
            .collect();
        for fixture in &matrix.fixtures {
            let texts = fixture_texts(&ruleset, &fixture.path);
            for file in fixture.probe(&matrix) {
                let what = format!("light/{ruleset}/{}: {}", fixture.path, file.artifact());
                let path = mirror().join(file.artifact());
                let bytes =
                    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                let sri = npm::integrity(&bytes);
                let digests = [
                    sri.trim_start_matches("sha512-").to_string(),
                    hex::encode(Sha256::digest(&bytes)),
                ];
                let pinned = texts
                    .values()
                    .any(|text| digests.iter().any(|digest| text.contains(digest)));
                assert_eq!(
                    pinned,
                    fixture.loopback_repository.is_none(),
                    "{what}: a digest of it is pinned: {pinned}"
                );
                assert!(
                    owned.iter().any(|scope| scope.is_match(file.artifact())),
                    "{what}: no registry scope covers it"
                );
                if let Err(why) = file.expected() {
                    panic!("{what}: {why}");
                }
            }
        }
    }
}

/// A matrix built from `fixture`, the JSON of one fixture entry.
fn matrix_of(registries: &str, probe: &str, fixture: &str) -> Matrix {
    let text = format!(
        r#"{{"group": "light", "ruleset": "rules_x", "registries": {registries},
            "probe": {probe}, "fixtures": [{fixture}]}}"#
    );
    Matrix::parse(&text).unwrap_or_else(|why| panic!("{why}:\n{text}"))
}

const SOUND_PROBE: &str =
    r#"[{"anchor": "sha256", "label": "x.gem", "artifact": "rubygems.org/gems/x-1.0.0.gem"}]"#;

/// One fixture entry with `cells` and `extra` (further keys, each ending in a
/// comma) spliced in.
fn entry(cells: &str, extra: &str) -> String {
    format!(
        r#"{{"path": "bzlmod/e9", "test": "bazel_canary_baseline_rules_x_bzlmod_e9",
            "system": "bzlmod", "pins": {{"rules_x": "1.0.0"}}, "shape": "a shape", {extra}
            "cells": {cells}}}"#
    )
}

const SOUND_CELLS: &str = r#"[{"bazel": "9.3.2", "proof": 1, "tier": "nightly"}]"#;

#[test]
fn matrix_checks_refuse_what_a_canary_would_not_notice() {
    let pinned: BTreeSet<String> = ["9.3.2", "8.8.2", "7.7.2"].map(String::from).into();
    let problems = |registries: &str, probe: &str, fixture: &str| {
        matrix_problems(&matrix_of(registries, probe, fixture), &pinned).join("\n")
    };
    let of_cells = |cells: &str| problems(r#"["gem"]"#, SOUND_PROBE, &entry(cells, ""));
    let of_extra = |extra: &str| problems(r#"["gem"]"#, SOUND_PROBE, &entry(SOUND_CELLS, extra));
    assert_eq!(of_cells(SOUND_CELLS), "");

    // An empty probe list would let tier 0 and the lock check pass on nothing.
    let empty = problems(r#"["gem"]"#, "[]", &entry(SOUND_CELLS, ""));
    assert!(empty.contains("nothing to probe"), "{empty}");
    let emptied = of_extra(r#""probe": [],"#);
    assert!(emptied.contains("nothing to probe"), "{emptied}");
    // A registry nobody serves is refused here, not first in a real-Bazel run.
    let unknown = problems(r#"["gem", "cargo"]"#, SOUND_PROBE, &entry(SOUND_CELLS, ""));
    assert!(unknown.contains("unknown registry \"cargo\""), "{unknown}");
    let none = problems("[]", SOUND_PROBE, &entry(SOUND_CELLS, ""));
    assert!(none.contains("no registry serves"), "{none}");

    for (cells, why) in [
        ("[]", "no cell claims it"),
        (
            r#"[{"bazel": "9.3.2", "proof": 1, "tier": "nightly", "outcome": "WORKS_AFTER"}]"#,
            "outcome \"WORKS_AFTER\" is not one of",
        ),
        (
            r#"[{"bazel": "9.3.2", "proof": 2, "tier": "nightly"}]"#,
            "proof 2 is above 1",
        ),
        (
            r#"[{"bazel": "9.3.2", "proof": 1, "tier": "weekly"}]"#,
            "tier \"weekly\" is not one of",
        ),
        (
            r#"[{"bazel": "9.9.9", "proof": 1, "tier": "nightly"}]"#,
            "Bazel 9.9.9 is not in scripts/bazel-pins.txt",
        ),
        (
            r#"[{"bazel": "9.3.2", "proof": 1, "tier": "pr"}, {"bazel": "9.3.2", "proof": 0, "tier": "pr"}]"#,
            "Bazel 9.3.2 is listed twice",
        ),
        (
            r#"[{"bazel": "9.3.2", "proof": 1, "tier": "nightly", "cache": "restored"}]"#,
            "rules_x/bzlmod/e9: a canary's cell runs on a cold repository cache",
        ),
    ] {
        let found = of_cells(cells);
        assert!(found.contains(why), "{cells}: {found}");
    }
    // A cell without `proof`, and a key nothing reads, do not parse at all.
    let no_proof = entry(r#"[{"bazel": "9.3.2", "tier": "nightly"}]"#, "");
    let text = format!(
        r#"{{"group": "light", "ruleset": "rules_x", "registries": ["gem"],
            "probe": {SOUND_PROBE}, "fixtures": [{no_proof}]}}"#
    );
    assert!(Matrix::parse(&text).is_err_and(|why| why.contains("missing field `proof`")));
    let stray = text.replace(
        r#""tier": "nightly""#,
        r#""tier": "nightly", "proof": 1, "os": []"#,
    );
    assert!(Matrix::parse(&stray).is_err_and(|why| why.contains("unknown field `os`")));

    for (extra, why) in [
        (r#""fetch": "pip","#, "fetch \"pip\" is not one of"),
        (
            r#""loopback_repository": "http://127.0.0.1:1/maven2","#,
            "fetch is \"tool\"",
        ),
        (
            r#""module_lock": {"8.8.2": "locks/v24/MODULE.bazel.lock"},"#,
            "a lock for Bazel 8.8.2, which no cell claims",
        ),
        (
            r#""build_stderr": {"contains": "", "not_on": ["win32"]},"#,
            "build_stderr.contains is empty",
        ),
        (
            r#""build_stderr": {"contains": "x", "not_on": ["win32"]},"#,
            "names no host system: \"win32\"",
        ),
        (
            r#""tier0_roots": ["@maven//:a", "@maven//:a"],"#,
            "a tier-0 root twice",
        ),
        (
            r#""tier0_roots": ["maven//:a) + deps(//..."],"#,
            "is not a label",
        ),
        (
            r#""load": ["//:all"],"#,
            "not a label in an external repository",
        ),
        (
            r#""recorded_extension": "//:e.bzl%e", "not_recorded_extension": "//:e.bzl%e","#,
            "both recorded and not recorded",
        ),
        (
            r#""lanes": [{"test": "bazel_core_x", "cells": [{"bazel": "9.3.2", "proof": 2, "tier": "pr"}]}],"#,
            "the lane test bazel_core_x has none of the prefixes",
        ),
        (
            r#""lanes": [{"test": "bazel_canary_baseline_rules_x_other", "cells": []}],"#,
            "or is a baseline",
        ),
        (
            r#""lanes": [{"test": "bazel_hosted_rules_x_bzlmod", "cells": [{"bazel": "8.8.2", "proof": 3, "tier": "pr"}]}],"#,
            "bazel_hosted_rules_x_bzlmod: Bazel 8.8.2 is no cell of the fixture's baseline",
        ),
    ] {
        let found = of_extra(extra);
        assert!(found.contains(why), "{extra}: {found}");
    }
    // A lane cell climbs the whole ladder, and no further.
    let lane = of_extra(
        r#""lanes": [{"test": "bazel_hosted_rules_x_bzlmod", "cells": [{"bazel": "9.3.2", "proof": 2, "tier": "pr", "outcome": "WORKS-AFTER"}]}],"#,
    );
    assert_eq!(lane, "");
    let above = of_extra(
        r#""lanes": [{"test": "bazel_hosted_rules_x_bzlmod", "cells": [{"bazel": "9.3.2", "proof": 3, "tier": "pr"}]}],"#,
    );
    assert!(above.contains("proof 3 is above 2"), "{above}");
    // A lane cell may say that it runs on the restored repository cache, in
    // that one word, unless its test is a canary: a canary's cell stays cold.
    let lane_on = |test: &str, cache: &str| {
        of_extra(&format!(
            r#""lanes": [{{"test": "{test}", "cells": [{{"bazel": "9.3.2", "proof": 2, "tier": "pr", "cache": {cache}}}]}}],"#
        ))
    };
    assert_eq!(lane_on("bazel_hosted_rules_x_bzlmod", r#""restored""#), "");
    for cache in [r#""restore""#, r#""warm""#, r#""""#] {
        let found = lane_on("bazel_hosted_rules_x_bzlmod", cache);
        let why = format!("bazel_hosted_rules_x_bzlmod: Bazel 9.3.2: cache {cache} is not one of");
        assert!(found.contains(&why), "{cache}: {found}");
    }
    let canary = lane_on("bazel_canary_rules_x_drift", r#""restored""#);
    assert_eq!(
        canary,
        "rules_x/bzlmod/e9: bazel_canary_rules_x_drift: a canary's cell runs on a cold \
         repository cache and takes no `cache`"
    );
    // The key is a word, not a switch.
    let switch = entry(SOUND_CELLS, "").replace(
        r#""tier": "nightly""#,
        r#""tier": "nightly", "cache": true"#,
    );
    let text = format!(
        r#"{{"group": "light", "ruleset": "rules_x", "registries": ["gem"],
            "probe": {SOUND_PROBE}, "fixtures": [{switch}]}}"#
    );
    assert!(Matrix::parse(&text).is_err_and(|why| why.contains("expected a string")));

    // The path and the test name follow from each other and from the system.
    let misnamed = entry(SOUND_CELLS, "").replace("rules_x_bzlmod_e9", "rules_x_e9");
    let found = problems(r#"["gem"]"#, SOUND_PROBE, &misnamed);
    assert!(
        found.contains("its test is bazel_canary_baseline_rules_x_e9"),
        "{found}"
    );
    let elsewhere =
        entry(SOUND_CELLS, "").replace(r#""system": "bzlmod""#, r#""system": "hybrid""#);
    let found = problems(r#"["gem"]"#, SOUND_PROBE, &elsewhere);
    assert!(found.contains("the path is not <system>/<era>"), "{found}");
    // Bazel 9 has no WORKSPACE system.
    let workspace = entry(SOUND_CELLS, "")
        .replace("bzlmod/e9", "workspace/e9")
        .replace("rules_x_bzlmod_e9", "rules_x_workspace_e9")
        .replace(r#""system": "bzlmod""#, r#""system": "workspace""#);
    let found = problems(r#"["gem"]"#, SOUND_PROBE, &workspace);
    assert!(
        found.contains("Bazel 9.3.2 has no workspace system"),
        "{found}"
    );

    // A PR cell of rules_jvm_external stops at the fetch.
    let pr = [CellSpec {
        bazel: "9.3.2".to_string(),
        proof: 1,
        tier: "pr".to_string(),
        outcome: None,
        cache: None,
    }];
    let found = cell_problems(
        &pr,
        Some(System::Bzlmod),
        &pinned,
        TOP_PROOF,
        "rules_jvm_external",
    );
    assert!(found[0].contains("stops at proof 0"), "{found:?}");
    assert!(cell_problems(&pr, Some(System::Bzlmod), &pinned, TOP_PROOF, "rules_js").is_empty());

    // Bazel 7.7.0 is refused even where a pins file lists it.
    let mut with_770 = pinned.clone();
    with_770.insert(NEVER_PINNED.to_string());
    let on_770 = [CellSpec {
        bazel: NEVER_PINNED.to_string(),
        proof: 1,
        tier: "nightly".to_string(),
        outcome: None,
        cache: None,
    }];
    let found = cell_problems(
        &on_770,
        Some(System::Bzlmod),
        &with_770,
        TOP_PROOF,
        "rules_js",
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("Bazel 7.7.0 is never pinned"),
        "{found:?}"
    );
}

#[test]
fn fixture_directories_are_walked_whole() {
    let tree = tempfile::tempdir().unwrap();
    let dir = |rel: &str| std::fs::create_dir_all(tree.path().join(rel)).unwrap();
    let file = |rel: &str| std::fs::write(tree.path().join(rel), "{}").unwrap();
    dir("registry/rubygems.org");
    dir("rules_x/bzlmod/e9");
    dir("rules_x/workspace/e7-variant");
    dir("rules_x/hybrid/e8");
    file("rules_x/MATRIX.json");
    file("README.md");
    assert_eq!(rulesets_in(tree.path()).unwrap(), ["rules_x"]);
    let on_disk = fixture_dirs_in(&tree.path().join("rules_x")).unwrap();
    assert_eq!(
        on_disk.into_iter().collect::<Vec<_>>(),
        ["bzlmod/e9", "hybrid/e8", "workspace/e7-variant"]
    );

    // A workspace outside a dependency-system directory is in no matrix path.
    dir("rules_x/legacy/e5");
    let why = fixture_dirs_in(&tree.path().join("rules_x")).unwrap_err();
    assert!(
        why.contains("legacy") && why.contains("not a dependency system"),
        "{why}"
    );
    // A ruleset tree without a matrix is not skipped.
    dir("rules_new/bzlmod/e9");
    let why = rulesets_in(tree.path()).unwrap_err();
    assert!(
        why.contains("rules_new") && why.contains("has no MATRIX.json"),
        "{why}"
    );
}

#[test]
fn fixture_data_is_no_part_of_the_workspace() {
    for (name, data) in [
        ("locks", true),
        ("expected-hosted", true),
        ("expected-vendored", true),
        ("expected-agent", true),
        ("expected", false),
        ("deps", false),
        ("lockspace", false),
    ] {
        assert_eq!(fixture_data_dir(name), data, "{name}");
    }
    let fixture = tempfile::tempdir().unwrap();
    let write = |rel: &str, bytes: &[u8]| {
        let path = fixture.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    };
    write("BUILD.bazel", b"# root\n");
    write(
        "deps/expected-hosted/BUILD.bazel",
        b"# a package of the workspace\n",
    );
    write("locks/v13/MODULE.bazel.lock", b"{}");
    write("expected-hosted/BUILD.bazel", b"# a golden\n");
    write(
        "expected-vendored/.socket/vendor/npm/x.tgz",
        &[0x1f, 0x8b, 0xff, 0xfe],
    );
    write("expected-notes", b"a file, not a golden tree\n");

    // The hermetic checks read the workspace alone; a golden may be binary.
    let texts = texts_of(fixture.path()).unwrap();
    let names: Vec<&str> = texts.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            "BUILD.bazel",
            "deps/expected-hosted/BUILD.bazel",
            "expected-notes"
        ]
    );
    write("src/blob.bin", &[0xff, 0xfe]);
    let why = texts_of(fixture.path()).unwrap_err();
    assert!(why.contains("src/blob.bin is not UTF-8"), "{why}");

    // And the canary builds the workspace alone.
    strip_fixture_data(fixture.path());
    let left: Vec<String> = snapshot(fixture.path())
        .into_iter()
        .filter(|(_, entry)| matches!(entry, Entry::File { .. }))
        .map(|(name, _)| name)
        .collect();
    assert_eq!(
        left,
        [
            "BUILD.bazel",
            "deps/expected-hosted/BUILD.bazel",
            "expected-notes",
            "src/blob.bin"
        ]
    );
}

#[test]
fn a_committed_lock_is_held_to_its_fixture() {
    let fixture = |extra: &str| {
        let fixture = entry(
            r#"[{"bazel": "7.7.2", "proof": 1, "tier": "nightly"}]"#,
            extra,
        );
        matrix_of(r#"["gem"]"#, SOUND_PROBE, &fixture)
            .fixtures
            .remove(0)
    };
    let recorded = fixture(r#""recorded_extension": "//deps:e.bzl%e","#);
    let lock = br#"{"lockFileVersion": 13,
        "registryFileHashes": {"https://bcr.bazel.build/modules/x/1.0/MODULE.bazel": "abc"},
        "moduleExtensions": {"//deps:e.bzl%e": {"general": {}}}}"#;
    let rel = "locks/v13/MODULE.bazel.lock";
    assert_eq!(lock_problems(&recorded, rel, lock), Vec::<String>::new());
    assert_eq!(
        lock_problems(&recorded, "locks/v13/linux/MODULE.bazel.lock", lock),
        Vec::<String>::new()
    );
    let text = String::from_utf8_lossy(lock).into_owned();
    let found = |fixture: &Fixture, rel: &str, lock: &str| {
        lock_problems(fixture, rel, lock.as_bytes()).join("\n")
    };

    // The directory states the lock version, so a lock of another Bazel line
    // cannot sit under this one's key.
    let why = found(&recorded, "locks/v24/MODULE.bazel.lock", &text);
    assert!(
        why.contains("has lockFileVersion Some(13), its directory says Some(24)"),
        "{why}"
    );
    let why = found(&recorded, "locks/MODULE.bazel.lock", &text);
    assert!(
        why.contains("is not locks/v<N>[/<os>]/MODULE.bazel.lock"),
        "{why}"
    );
    // The extension entry the fixture's shape rests on is in the committed file.
    let why = found(
        &recorded,
        rel,
        &text.replace("//deps:e.bzl%e", "//deps:other.bzl%e"),
    );
    assert!(why.contains("does not record //deps:e.bzl%e"), "{why}");
    let unrecorded = fixture(r#""not_recorded_extension": "@@//deps:e.bzl%e","#);
    let why = found(&unrecorded, rel, &text);
    assert!(why.contains("records @@//deps:e.bzl%e"), "{why}");
    // Resolved against the central registry, and nothing else.
    for (registry, host) in [
        ("file:///tmp/registry/", "file://"),
        ("http://127.0.0.1:8080/", "127.0.0.1"),
        ("http://localhost:8080/", "localhost"),
        ("https://registry.invalid/", ".invalid"),
        (
            "https://mirror.example.com/",
            "outside https://bcr.bazel.build/",
        ),
    ] {
        let why = found(
            &recorded,
            rel,
            &text.replace("https://bcr.bazel.build/", registry),
        );
        assert!(why.contains(host), "{registry}: {why}");
    }
    let why = found(&recorded, rel, "not a lock");
    assert!(why.contains("is not JSON"), "{why}");
    // An entry keyed by a host system makes the lock that system's: it goes
    // under a directory that says so, beside the locks of the other systems.
    let keyed = text.replace("\"general\"", "\"os:osx,arch:aarch64\"");
    let why = found(&recorded, rel, &keyed);
    assert!(
        why.contains("records //deps:e.bzl%e under \"os:osx,arch:aarch64\""),
        "{why}"
    );
    assert_eq!(
        found(&recorded, "locks/v13/macos/MODULE.bazel.lock", &keyed),
        ""
    );
}

#[test]
fn the_tests_a_matrix_names_are_declared_once() {
    let source = "fn helper(x: u8) {}\n#[test]\n#[ignore]\nfn bazel_hosted_rules_x_bzlmod() {\n}\n\
                  \x20   pub(crate) fn shared() {}\npub fn open() {}\n// fn commented() {}\n\
                  let text = \"fn quoted()\";\n";
    assert_eq!(
        declared_functions(source),
        ["helper", "bazel_hosted_rules_x_bzlmod", "shared", "open"]
    );

    let fixture =
        |test: &str, path: &str| (test.to_string(), "rules_x".to_string(), path.to_string());
    let listed = [
        fixture("bazel_canary_baseline_rules_x_bzlmod_e9", "bzlmod/e9"),
        fixture(
            "bazel_canary_baseline_rules_x_bzlmod_e9_new",
            "bzlmod/e9-new",
        ),
    ];
    let lanes = ["bazel_hosted_rules_x_bzlmod".to_string()];
    let canaries = [(
        "bazel_canary_baseline_rules_x_bzlmod_e9",
        "rules_x",
        "bzlmod/e9",
    )];
    // Function name to the modules that declare it, space-separated.
    let modules = |pairs: &[(&str, &str)]| -> BTreeMap<String, Vec<String>> {
        let files = |at: &str| at.split(' ').map(str::to_string).collect();
        pairs
            .iter()
            .map(|(name, at)| (name.to_string(), files(at)))
            .collect()
    };
    // One canary from `canaries!`, one from the lane's module, and the lane test.
    let declared = modules(&[
        ("bazel_canary_baseline_rules_x_bzlmod_e9_new", "rules_x.rs"),
        ("bazel_hosted_rules_x_bzlmod", "rules_x.rs"),
    ]);
    let found = declaration_problems(&listed, &lanes, &canaries, &declared);
    assert_eq!(found, Vec::<String>::new());

    let found = declaration_problems(&listed, &lanes, &canaries, &BTreeMap::new()).join("\n");
    assert!(
        found.contains("rules_x/bzlmod/e9-new has no canary"),
        "{found}"
    );
    assert!(
        found.contains("bazel_hosted_rules_x_bzlmod is declared in no module"),
        "{found}"
    );
    let twice = modules(&[
        ("bazel_canary_baseline_rules_x_bzlmod_e9", "rules_x.rs"),
        (
            "bazel_canary_baseline_rules_x_bzlmod_e9_new",
            "rules_x.rs legacy.rs",
        ),
        ("bazel_hosted_rules_x_bzlmod", "rules_x.rs guard.rs"),
    ]);
    let found = declaration_problems(&listed, &lanes, &canaries, &twice).join("\n");
    assert_eq!(
        found.matches("is declared more than once").count(),
        3,
        "{found}"
    );
    // `canaries!` and the matrix must mean the same fixture, both ways.
    let moved = [(
        "bazel_canary_baseline_rules_x_bzlmod_e9",
        "rules_x",
        "bzlmod/e8",
    )];
    let found = declaration_problems(&listed[..1], &[], &moved, &declared).join("\n");
    assert!(
        found.contains("for rules_x/bzlmod/e8, MATRIX.json lists it for"),
        "{found}"
    );
    let found = declaration_problems(&[], &[], &canaries, &declared).join("\n");
    assert!(found.contains("which no MATRIX.json lists"), "{found}");
    let again = [listed[0].0.clone()];
    let found = declaration_problems(&listed, &again, &canaries, &declared).join("\n");
    assert!(found.contains("is named twice in the matrices"), "{found}");
}

#[test]
fn versioned_rje_names_are_found_in_code_and_not_in_comments() {
    assert_eq!(
        rje_versioned_name("org.slf4j:slf4j-api", "1.7.36"),
        "org_slf4j_slf4j_api_1_7_36"
    );
    let lock = r#"{"artifacts": {
        "org.slf4j:slf4j-api": {"shasums": {"jar": "d3"}, "version": "1.7.36"},
        "com.google.code.gson:gson": {"shasums": {"jar": "4e"}, "version": "2.10.1"}}}"#;
    let tree = |module: &str, build: &str| -> BTreeMap<String, String> {
        [
            ("maven_install.json", lock),
            ("MODULE.bazel", module),
            ("app/BUILD.bazel", build),
            (
                "README.md",
                "use_repo(maven, \"com_google_code_gson_gson_2_10_1\")",
            ),
        ]
        .map(|(name, text)| (name.to_string(), text.to_string()))
        .into()
    };
    let hub_only = tree(
        "# not `org_slf4j_slf4j_api_1_7_36`\nuse_repo(maven, \"maven\")\n",
        "srcs = [\"@maven//:org_slf4j_slf4j_api\"]  # org_slf4j_slf4j_api_1_7_36\n",
    );
    assert_eq!(versioned_names_used(&hub_only), BTreeSet::new());
    let spoke = tree(
        "use_repo(maven, \"maven\", \"org_slf4j_slf4j_api_1_7_36\")\n",
        "srcs = [\"@maven//:org_slf4j_slf4j_api\"]\n",
    );
    assert_eq!(
        versioned_names_used(&spoke).into_iter().collect::<Vec<_>>(),
        ["org_slf4j_slf4j_api_1_7_36"]
    );
    let alias = tree(
        "use_repo(maven, \"maven\")\n",
        "deps = [\"@maven//:com_google_code_gson_gson_2_10_1\"]\n",
    );
    assert_eq!(
        versioned_names_used(&alias).into_iter().collect::<Vec<_>>(),
        ["com_google_code_gson_gson_2_10_1"]
    );
    // A longer name that starts with a versioned one is another repository.
    let renamed = tree(
        "use_repo(maven, \"org_slf4j_slf4j_api_1_7_36_socket_0b5e1c1e\")\n",
        "",
    );
    assert_eq!(versioned_names_used(&renamed), BTreeSet::new());
}

/// The undeclared `.npmrc` fixture is the input of a credential refusal: its
/// token must be one rules_js sends to every registry, and its canary must
/// show that rules_js read the file.
#[test]
fn the_undeclared_npmrc_holds_an_unscoped_credential() {
    const CREDENTIALS: &[&str] = &["_authToken", "_auth", "username", "_password"];
    let matrix = Matrix::load("rules_js");
    let fixture = matrix.fixture("bzlmod/e7-npmrc");
    let texts = fixture_texts("rules_js", &fixture.path);
    // The keys of the file as rules_js reads them (`npm/private/npmrc.bzl`).
    let keys: Vec<&str> = texts[".npmrc"]
        .lines()
        .map(|line| line.split([';', '#']).next().unwrap_or("").trim())
        .filter(|line| !line.is_empty() && !line.starts_with('['))
        .map(|line| line.split('=').next().unwrap_or("").trim())
        .collect();
    // An un-scoped key is the whole key. A scoped one (`//host/:_authToken`)
    // goes to its own registry alone, which no refusal is about.
    assert!(
        keys.iter().any(|key| CREDENTIALS.contains(key)),
        "the .npmrc holds no un-scoped credential: {keys:?}"
    );
    let scoped = |key: &str| {
        CREDENTIALS
            .iter()
            .any(|name| key.ends_with(&format!(":{name}")))
    };
    assert!(!keys.iter().any(|key| scoped(key)), "{keys:?}");
    assert!(
        !texts["MODULE.bazel"].contains("npmrc"),
        "the file is declared"
    );

    // The tree is `e7` plus the file, so only the warning tells the two canaries apart.
    let mut twin = fixture_texts("rules_js", "bzlmod/e7");
    twin.insert(".npmrc".to_string(), texts[".npmrc"].clone());
    assert_eq!(texts, twin);
    let expected = fixture.build_stderr.as_ref().expect("build_stderr");
    assert_eq!(expected.contains, "Implicitly using .npmrc file");
    // rules_js 2.x does not look for the file on Windows.
    assert!(!expected.applies_on("windows") && expected.applies_on("linux"));
    assert!(expected.applies_on("macos"));
}

/// The rules_js facts the probes fixed: the lifecycle-hook allow list, the lines
/// a lock version belongs to, hash files that match, and the variants the later
/// rules_js packages start from.
#[test]
fn rules_js_fixtures_hold_what_the_probes_fixed() {
    let matrix = Matrix::load("rules_js");
    let mut shapes = BTreeSet::new();
    for fixture in &matrix.fixtures {
        let what = format!("light/rules_js/{}", fixture.path);
        let texts = fixture_texts("rules_js", &fixture.path);
        let pin = &fixture.pins["aspect_rules_js"];
        let bazel: Vec<&str> = fixture.cells.iter().map(|c| c.bazel.as_str()).collect();
        let found = rules_js_problems(pin, &bazel, &texts);
        assert!(found.is_empty(), "{what}: {}", found.join("; "));

        let declaration = texts.get("MODULE.bazel").or_else(|| texts.get("WORKSPACE"));
        let hub = NpmHub::read(declaration.expect("read above")).expect("read above");
        let line = format!("rules_js {}.x", release(pin).0);
        let lock = lockfile_version(&texts[&hub.lock_path()]);
        if hub.lock_label != "//:pnpm-lock.yaml" {
            shapes.insert(format!("{line}: lock {lock} in a sub-package"));
        }
        if let (true, Some(pnpm)) = (hub.update_pnpm_lock, &hub.pnpm_version) {
            shapes.insert(format!("{line}: update_pnpm_lock, managed pnpm {pnpm}"));
            // The managed pnpm is a dependency of neither proof target: the
            // canary loads it, so a version rules_js cannot fetch fails there.
            let loaded = fixture
                .load
                .iter()
                .any(|label| label.starts_with("@pnpm//"));
            assert!(loaded, "{what}: `load` names no @pnpm// label");
        }
        if texts.contains_key(&hub.beside_lock("package-lock.json")) {
            shapes.insert(format!("{line}: a package-lock.json beside lock {lock}"));
        }
    }
    for shape in [
        // The gate of the vendored lane: rules_js >= 2.1.1 joins a `file:` path
        // with the lock's package, older releases do not.
        "rules_js 3.x: lock 9.0 in a sub-package",
        // The managed pnpm majors as the probe ran them. On a hash miss 9 and 10
        // keep a hosted lock's pins; 11 and 12 fail the build.
        "rules_js 3.x: update_pnpm_lock, managed pnpm 9.15.9",
        "rules_js 3.x: update_pnpm_lock, managed pnpm 10.34.9",
        "rules_js 3.x: update_pnpm_lock, managed pnpm 11.28.10",
        "rules_js 3.x: update_pnpm_lock, managed pnpm 12.17.0",
        // rules_js 2.x only with a managed pnpm it is told to use.
        "rules_js 2.x: update_pnpm_lock, managed pnpm 9.15.9",
        // Where today's hosted run creates an `.npmrc`, which rules_js 3.x refuses.
        "rules_js 3.x: a package-lock.json beside lock 9.0",
    ] {
        assert!(
            shapes.contains(shape),
            "no fixture is {shape:?}: {shapes:?}"
        );
    }
}

#[test]
fn rules_js_checks_refuse_what_a_probe_refuted() {
    const NEW: &[&str] = &["9.3.2", "8.8.2"];
    let of = |path: &str| fixture_texts("rules_js", path);
    let found = |pin: &str, bazel: &[&str], texts: &BTreeMap<String, String>| {
        rules_js_problems(pin, bazel, texts).join("\n")
    };
    let edit = |texts: &mut BTreeMap<String, String>, file: &str, from: &str, to: &str| {
        let text = texts.get_mut(file).unwrap_or_else(|| panic!("no {file}"));
        assert!(text.contains(from), "{file} holds no {from:?}");
        *text = text.replace(from, to);
    };

    // The allow list, in the manifest or the workspace file of the lock's package.
    let mut bare = of("bzlmod/e9");
    assert_eq!(found("3.6.0", NEW, &bare), "");
    edit(
        &mut bare,
        "package.json",
        "onlyBuiltDependencies",
        "neverBuiltDependencies",
    );
    let why = found("3.6.0", NEW, &bare);
    assert!(why.contains("lifecycle-hook allow list"), "{why}");
    bare.insert(
        "pnpm-workspace.yaml".to_string(),
        "onlyBuiltDependencies: []\n".to_string(),
    );
    assert_eq!(found("3.6.0", NEW, &bare), "");
    let mut misplaced = of("bzlmod/e9-sub");
    let manifest = misplaced.remove("app/package.json").unwrap();
    misplaced.insert("package.json".to_string(), manifest);
    let why = found("3.6.0", NEW, &misplaced);
    assert!(why.contains("lifecycle-hook allow list"), "{why}");

    // Lock 6.0 stays on the lines before 7.7.
    let old = of("bzlmod/e6");
    assert_eq!(found("1.42.3", &["7.1.2", "7.0.2", "6.6.0"], &old), "");
    for late in ["7.7.2", "8.8.2", "9.3.2"] {
        let why = found("1.42.3", &["6.6.0", late], &old);
        assert_eq!(why, format!("a pnpm lock 6.0 has no cell on Bazel {late}"));
    }

    // The hash file is the one rules_js would write for these files.
    let upl = of("bzlmod/e9-upl-pnpm10");
    let hub = NpmHub::read(&upl["MODULE.bazel"]).unwrap();
    assert_eq!(
        hub.hash_file(),
        ".aspect/rules/external_repository_action_cache/npm_translate_lock_LTE4Nzc1MDcwNjU="
    );
    assert_eq!(found("3.6.0", NEW, &upl), "");
    let mut stale = upl.clone();
    stale.get_mut("pnpm-lock.yaml").unwrap().push('\n');
    let why = found("3.6.0", NEW, &stale);
    assert!(why.contains("records pnpm-lock.yaml as 734347507"), "{why}");
    assert!(why.contains("the first build would run pnpm"), "{why}");
    let mut renamed = upl.clone();
    edit(
        &mut renamed,
        "MODULE.bazel",
        "name = \"npm\",",
        "name = \"npm_other\",",
    );
    let why = found("3.6.0", NEW, &renamed);
    assert!(
        why.contains("update_pnpm_lock without the hash file"),
        "{why}"
    );
    let mut partial = upl.clone();
    edit(
        &mut partial,
        &hub.hash_file(),
        "package.json=",
        "other.json=",
    );
    let why = found("3.6.0", NEW, &partial);
    assert!(
        why.contains("records other.json, which the fixture lacks"),
        "{why}"
    );
    assert!(why.contains("has no line for package.json"), "{why}");
    // The lock label is part of the name, and its package of every path.
    let declared =
        "npm_translate_lock(\n    name = \"npm\",\n    pnpm_lock = \"//app:pnpm-lock.yaml\",\n)";
    let sub = NpmHub::read(declared).unwrap();
    assert_eq!(sub.lock_path(), "app/pnpm-lock.yaml");
    assert_eq!(sub.beside_lock("package.json"), "app/package.json");
    assert_ne!(sub.hash_file(), hub.hash_file());
    assert!(!sub.update_pnpm_lock && sub.pnpm_version.is_none());
    assert!(NpmHub::read("npm_translate_lock(name = \"npm\")").is_err());
    assert!(NpmHub::read(&format!("{declared}\n{declared}")).is_err());
    assert!(NpmHub::read("# npm_translate_lock(name = \"npm\")").is_err());

    // rules_js 2.x manages only a pnpm 9 or 10 it is told to use.
    let managed = of("bzlmod/e7-upl");
    assert_eq!(found("2.9.3", &["7.7.2"], &managed), "");
    for other in ["8.15.9", "10.34.9", "11.28.10"] {
        let mut texts = managed.clone();
        edit(&mut texts, "MODULE.bazel", "9.15.9", other);
        let why = found("2.9.3", &["7.7.2"], &texts);
        assert!(
            why.contains(&format!("cannot manage pnpm {other}")),
            "{why}"
        );
    }
    let mut default = managed.clone();
    edit(
        &mut default,
        "MODULE.bazel",
        "    pnpm_version = \"9.15.9\",\n",
        "",
    );
    let why = found("2.9.3", &["7.7.2"], &default);
    assert!(why.contains("manages pnpm 8 by default"), "{why}");
    // rules_js 3.x manages pnpm 10 by default, and its table holds 11 and 12.
    assert_eq!(found("3.6.0", NEW, &default), "");

    // A sibling lock is one no hub reads, in a workspace without an `.npmrc`.
    let mut sibling = of("bzlmod/e9-npm-lock");
    assert_eq!(found("3.6.0", NEW, &sibling), "");
    sibling.insert(
        ".npmrc".to_string(),
        "registry=https://registry.npmjs.org/\n".to_string(),
    );
    let why = found("3.6.0", NEW, &sibling);
    assert!(why.contains("beside an .npmrc"), "{why}");
    edit(
        &mut sibling,
        "MODULE.bazel",
        "    pnpm_lock = ",
        "    npm_package_lock = \"//:package-lock.json\",\n    pnpm_lock = ",
    );
    let why = found("3.6.0", NEW, &sibling);
    assert!(
        why.contains("the hub names the sibling package-lock.json"),
        "{why}"
    );
}

#[test]
fn an_override_is_held_to_the_declared_version() {
    let module = |dep: &str, pin: &str| {
        format!(
            "bazel_dep(name = \"bazel_skylib\", version = \"{dep}\")\n\
             # single_version_override(module_name = \"commented\", version = \"9\")\n\
             single_version_override(\n    module_name = \"bazel_skylib\",\n    version = \"{pin}\",\n)\n"
        )
    };
    assert_eq!(
        override_problems(&module("1.7.1", "1.7.1")),
        Vec::<String>::new()
    );
    // What Bazel 9.3.2 rejects, and its mirror image.
    for (dep, pin) in [("1.7.1", "1.6.1"), ("1.6.1", "1.7.1")] {
        let found = override_problems(&module(dep, pin)).join("\n");
        let why = format!("bazel_skylib is overridden to {pin} and declared at {dep}");
        assert_eq!(found, why);
    }
    let undeclared = "single_version_override(module_name = \"rules_x\", version = \"1.0\")";
    let found = override_problems(undeclared).join("\n");
    assert!(found.contains("no bazel_dep declares a version"), "{found}");
    // An override that pins no version is not one of these.
    let unversioned =
        "single_version_override(module_name = \"rules_x\", registry = \"https://bcr.bazel.build/\")";
    assert!(override_problems(unversioned).is_empty());

    assert_eq!(release("3.6.0"), (3, 6, 0));
    assert_eq!(release("7.2"), (7, 2, 0));
    assert_eq!(release("6.10"), (6, 10, 0));
    assert_eq!(release("1.0.0-rc2"), (1, 0, 0));
    assert_eq!(release("latest"), (0, 0, 0));
    assert!(release("0.14.0") < (0, 15, 0) && release("0.22.2") >= (0, 15, 0));
}

/// rules_dotnet: each fixture holds the files of one `paket2bazel` generation,
/// the 0.14.0 one the generation that release writes, and its matrix entry says
/// what follows for `MODULE.bazel.lock`. Without `reproducible = True` in the
/// generated extension Bazel records the extension's result: the fixture commits
/// that lock and its hosted outcome is WORKS-AFTER, because an edit of the data
/// file stales the entry. With it nothing is recorded and the outcome is WORKS.
#[test]
fn rules_dotnet_fixtures_are_of_one_generation_and_say_what_the_lock_records() {
    let matrix = Matrix::load("rules_dotnet");
    let mut kinds = BTreeSet::new();
    for fixture in &matrix.fixtures {
        let what = format!("light/rules_dotnet/{}", fixture.path);
        let texts = fixture_texts("rules_dotnet", &fixture.path);
        let pin = &fixture.pins["rules_dotnet"];
        let files = paket_files(pin, &texts).unwrap_or_else(|why| panic!("{what}: {why}"));
        let (recorded, unrecorded, outcome) = match files.reproducible {
            true => (None, Some(&files.extension), "WORKS"),
            false => (Some(&files.extension), None, "WORKS-AFTER"),
        };
        assert_eq!(fixture.recorded_extension.as_ref(), recorded, "{what}");
        assert_eq!(
            fixture.not_recorded_extension.as_ref(),
            unrecorded,
            "{what}"
        );
        for spec in &fixture.cells {
            let on = format!("{what} on Bazel {}", spec.bazel);
            assert_eq!(spec.outcome.as_deref(), Some(outcome), "{on}");
            let committed = fixture.module_lock.get(&spec.bazel);
            assert_eq!(committed.is_some(), !files.reproducible, "{on}: a lock");
            let Some(rel) = committed else { continue };
            // The recorded entry holds what the data file pins, so an edit of
            // the data file is an edit the lock disagrees with.
            let path = light().join("rules_dotnet").join(&fixture.path).join(rel);
            let lock = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let lock: Value = serde_json::from_slice(&lock).expect("a lock");
            let entries = lock["moduleExtensions"].as_object().expect("extensions");
            let entry = entries
                .iter()
                .find(|(key, _)| records(&[(*key).clone()], &files.extension))
                .map(|(_, entry)| entry.to_string())
                .unwrap_or_else(|| panic!("{on}: {rel} has no entry of {}", files.extension));
            for sha512 in &files.sha512 {
                assert!(
                    entry.contains(sha512.as_str()),
                    "{on}: {rel} lacks {sha512}"
                );
            }
        }
        kinds.insert((release(pin) < (0, 15, 0), files.reproducible));
    }
    // The 0.13 - 0.14 generation, recorded; and a reproducible extension.
    assert!(kinds.contains(&(true, false)), "{kinds:?}");
    assert!(
        kinds.iter().any(|(_, reproducible)| *reproducible),
        "{kinds:?}"
    );
}

#[test]
fn paket_files_of_two_generations_are_refused() {
    const EXTENSION: &str = "//deps:paket.main_extension.bzl%main_extension";
    const DATA: &str = "deps/paket.main.bzl";
    let legacy = fixture_texts("rules_dotnet", "bzlmod/e7");
    let current = fixture_texts("rules_dotnet", "bzlmod/e9");
    let old = paket_files("0.14.0", &legacy).unwrap();
    assert_eq!(
        (old.extension.as_str(), old.reproducible, old.sha512.len()),
        (EXTENSION, false, 2)
    );
    let new = paket_files("0.22.2", &current).unwrap();
    assert_eq!(
        (new.extension.as_str(), new.reproducible, new.sha512.len()),
        (EXTENSION, true, 2)
    );
    assert_eq!(old.sha512, new.sha512, "both pin the mirrored packages");

    // 0.14.0 generates the first generation alone. The reverse is a project that
    // kept its old files under a newer release: its extension is still recorded.
    let why = paket_files("0.14.0", &current).unwrap_err();
    assert!(
        why.contains("the fixture holds the later generation"),
        "{why}"
    );
    assert_eq!(paket_files("0.22.2", &legacy), Ok(old));

    // A data file under the extension file of the other generation.
    let mut mixed = legacy.clone();
    mixed.insert(DATA.to_string(), current[DATA].clone());
    let why = paket_files("0.14.0", &mixed).unwrap_err();
    assert!(why.contains("the headers of no one generation"), "{why}");
    // Entries of the other generation under a header.
    let mut named = legacy.clone();
    let data = named.get_mut(DATA).unwrap();
    *data = data.replace("{\"id\": ", "{\"name\": \"SP\", \"id\": ");
    let why = paket_files("0.14.0", &named).unwrap_err();
    assert!(why.contains("entries with no \"name\" key"), "{why}");
    let mut unnamed = current.clone();
    let data = unnamed.get_mut(DATA).unwrap();
    assert!(data.contains("{\"name\": \"SP.Victim\", "));
    *data = data
        .replace("{\"name\": \"SP.Victim\", ", "{")
        .replace("{\"name\": \"SP.Other\", ", "{");
    let why = paket_files("0.22.2", &unnamed).unwrap_err();
    assert!(why.contains("entries with a \"name\" key"), "{why}");

    let mut alone = legacy.clone();
    alone.remove("deps/paket.main_extension.bzl");
    let why = paket_files("0.14.0", &alone).unwrap_err();
    assert_eq!(why, "no deps/paket.main_extension.bzl");
    let mut unused = legacy.clone();
    unused.insert(
        "MODULE.bazel".to_string(),
        "module(name = \"x\")\n".to_string(),
    );
    let why = paket_files("0.14.0", &unused).unwrap_err();
    assert!(why.contains("uses no generated paket extension"), "{why}");
}

#[test]
fn rules_ruby_fixtures_name_the_remote_java_runtime_of_their_line() {
    let matrix = Matrix::load("rules_ruby");
    for fixture in &matrix.fixtures {
        let texts = fixture_texts("rules_ruby", &fixture.path);
        let bazel: Vec<&str> = fixture.cells.iter().map(|c| c.bazel.as_str()).collect();
        let found = ruby_runtime_problem(texts.get(".bazelrc").map(String::as_str), &bazel);
        assert_eq!(found, None, "light/rules_ruby/{}", fixture.path);
    }

    let rc = "# rules_ruby resolves a Java runtime.\nbuild --java_runtime_version=remotejdk_21\n";
    assert_eq!(ruby_runtime_problem(Some(rc), &["9.3.2", "8.8.2"]), None);
    assert_eq!(ruby_runtime_problem(Some(rc), &["7.7.2"]), None);
    // Bazel 6 has remotejdk_11.
    let why = ruby_runtime_problem(Some(rc), &["6.6.0"]).expect("refused");
    assert!(why.contains("--java_runtime_version=remotejdk_11"), "{why}");
    let eleven = rc.replace("remotejdk_21", "remotejdk_11");
    assert_eq!(ruby_runtime_problem(Some(&eleven), &["6.6.0"]), None);
    assert!(ruby_runtime_problem(Some(&eleven), &["7.7.2"]).is_some());
    assert!(ruby_runtime_problem(None, &["9.3.2"]).is_some());
    let commented = "# build --java_runtime_version=remotejdk_21\n";
    assert!(ruby_runtime_problem(Some(commented), &["9.3.2"]).is_some());
}

/// rules_jvm_external: every lock is of the flavor its fixture states, and the
/// registry jar is probed in one of the two ways [`rje_problems`] describes.
#[test]
fn rules_jvm_external_fixtures_state_their_lock_flavors_and_their_probe() {
    let matrix = Matrix::load("rules_jvm_external");
    let mut sole = BTreeSet::new();
    let mut hubs = 0;
    for fixture in &matrix.fixtures {
        let texts = fixture_texts("rules_jvm_external", &fixture.path);
        let found = rje_problems(fixture, &texts);
        let what = format!("light/rules_jvm_external/{}", fixture.path);
        assert!(found.is_empty(), "{what}: {}", found.join("; "));
        for stated in fixture.lock_flavors.values() {
            if let [flavor] = &stated[..] {
                sole.insert(flavor.as_str());
            }
        }
        hubs = hubs.max(fixture.lock_flavors.len());
    }
    // v2 and both v3 flavors each have a lock that no other flavor reproduces
    // (the v3 ones differ only for a lock with two repositories), and one
    // fixture pins two hubs.
    assert_eq!(sole, BTreeSet::from(["v2", "v3-insertion", "v3-sorted"]));
    assert_eq!(hubs, 2);

    // No other ruleset writes these locks, so nothing else may state a flavor.
    let others = rulesets();
    for ruleset in others
        .iter()
        .filter(|name| name.as_str() != "rules_jvm_external")
    {
        for fixture in &Matrix::load(ruleset).fixtures {
            let what = format!("light/{ruleset}/{}", fixture.path);
            assert!(fixture.lock_flavors.is_empty(), "{what}: lock_flavors");
        }
    }
}

#[test]
fn rje_checks_refuse_a_misstated_lock_and_a_probe_that_pulls_a_jdk() {
    const FETCHED: &str = r#"[{"bazel": "9.3.2", "proof": 0, "tier": "nightly"}]"#;
    const BUILT: &str = r#"[{"bazel": "9.3.2", "proof": 1, "tier": "nightly"}]"#;
    const HUB: &str = r#""tier0_roots": ["@maven//:org_slf4j_slf4j_api"],"#;
    let fixture = |cells: &str, extra: &str, pin: &str| {
        let pinned = format!(r#""rules_jvm_external": "{pin}""#);
        let entry = entry(cells, extra).replace(r#""rules_x": "1.0.0""#, &pinned);
        matrix_of(r#"["maven"]"#, SOUND_PROBE, &entry)
            .fixtures
            .remove(0)
    };
    let stated = |flavors: &str| format!(r#""lock_flavors": {{"maven_install.json": {flavors}}},"#);
    let found = |fixture: &Fixture, texts: &BTreeMap<String, String>| {
        rje_problems(fixture, texts).join("\n")
    };
    let sorted = fixture_texts("rules_jvm_external", "bzlmod/e9");
    let insertion = fixture_texts("rules_jvm_external", "bzlmod/e8-insertion");
    let hub_probed = |flavors: &str| format!("{} {HUB}", stated(flavors));
    let sound = fixture(FETCHED, &hub_probed(r#"["v3-sorted"]"#), "7.2");
    assert_eq!(found(&sound, &sorted), "");

    // The flavor is what reproduces the stored hash, not what the entry says.
    for wrong in [
        r#"["v3-insertion"]"#,
        r#"["v3-sorted", "v3-insertion"]"#,
        r#"["v2"]"#,
    ] {
        let why = found(&fixture(FETCHED, &hub_probed(wrong), "7.2"), &sorted);
        assert!(
            why.contains("maven_install.json reproduces under [\"v3-sorted\"]"),
            "{wrong}: {why}"
        );
    }
    // A lock in the flavor the pinned release does not check fails its build.
    let why = found(&sound, &insertion);
    assert!(why.contains("reproduces under [\"v3-insertion\"]"), "{why}");
    let on_610 = fixture(FETCHED, &hub_probed(r#"["v3-sorted"]"#), "6.10");
    let why = found(&on_610, &sorted);
    assert!(why.contains("checks the v3-insertion hash"), "{why}");
    let on_72 = fixture(FETCHED, &hub_probed(r#"["v3-insertion"]"#), "7.2");
    let why = found(&on_72, &insertion);
    assert!(why.contains("checks the v3-sorted hash"), "{why}");
    // A lock nothing states, a stated lock that is no file, an edited lock.
    let why = found(&fixture(FETCHED, HUB, "7.2"), &sorted);
    assert!(why.contains("the workspace holds the locks"), "{why}");
    let elsewhere = hub_probed(r#"["v3-sorted"]"#).replace("maven_install", "other_install");
    let why = found(&fixture(FETCHED, &elsewhere, "7.2"), &sorted);
    assert!(
        why.contains("names other_install.json, which is no file"),
        "{why}"
    );
    let mut edited = sorted.clone();
    let lock = edited.get_mut("maven_install.json").unwrap();
    assert!(lock.contains("\"1.7.36\""));
    *lock = lock.replace("\"1.7.36\"", "\"1.7.37\"");
    let why = found(&sound, &edited);
    assert!(why.contains("maven_install.json: Mismatch"), "{why}");

    // The probe: through the hub the baseline stops at the query.
    let built = fixture(BUILT, &hub_probed(r#"["v3-sorted"]"#), "7.2");
    let why = found(&built, &sorted);
    assert!(why.contains("stops at proof 0"), "{why}");
    let rootless = fixture(BUILT, &stated(r#"["v3-sorted"]"#), "7.2");
    let why = found(&rootless, &sorted);
    assert!(why.contains("neither rooted at a hub label"), "{why}");
    let spoke = format!(
        r#"{} "versioned_names": ["org_slf4j_slf4j_api_1_7_36"],"#,
        stated(r#"["v3-sorted"]"#)
    );
    assert_eq!(found(&fixture(BUILT, &spoke, "7.2"), &sorted), "");
    // An unpinned hub has no lock, and nothing here to answer for.
    assert_eq!(found(&fixture(BUILT, "", "7.2"), &BTreeMap::new()), "");
}

/// `registry/SHA256SUMS` lists every file of the mirror, so the files no lock
/// pins (the POMs and `.md5` files Coursier asks for, the NuGet service index)
/// are held to their bytes as well.
#[test]
fn the_registry_mirror_is_the_tree_its_checksums_list() {
    const SUMS: &str = "SHA256SUMS";
    let tree = snapshot(&mirror());
    let line = |(path, entry): (&String, &Entry)| match entry {
        Entry::File { bytes, .. } if path != SUMS => {
            Some(format!("{}  {path}", hex::encode(Sha256::digest(bytes))))
        }
        _ => None,
    };
    let expected: Vec<String> = tree.iter().filter_map(line).collect();
    let Some(Entry::File { bytes, .. }) = tree.get(SUMS) else {
        panic!("no registry/{SUMS}");
    };
    let listed = String::from_utf8(bytes.clone()).expect("UTF-8");
    assert_eq!(
        listed.lines().collect::<Vec<_>>(),
        expected,
        "registry/{SUMS} is stale: one `<sha256>  <path>` line per mirrored file, in path order"
    );
}

#[test]
fn downloader_rules_cover_a_scope_and_nothing_beside_it() {
    let scopes = [
        "registry.npmjs.org/@tootallnate/once/-/*".to_string(),
        "api.nuget.org/v3/index.json".to_string(),
    ];
    assert_eq!(
        downloader_rules(&scopes, 8080),
        "rewrite (registry\\.npmjs\\.org/@tootallnate/once/\\-/.*) http://127.0.0.1:8080/$1\n\
         rewrite (api\\.nuget\\.org/v3/index\\.json) http://127.0.0.1:8080/$1\n"
    );
    // Bazel matches a pattern against the whole URL without its scheme.
    let whole = |pattern: &str| regex::Regex::new(&format!("^(?:{pattern})$")).unwrap();
    let prefix = whole("registry\\.npmjs\\.org/@tootallnate/once/\\-/.*");
    assert!(prefix.is_match("registry.npmjs.org/@tootallnate/once/-/once-9.9.9.tgz"));
    assert!(!prefix.is_match("registry.npmjs.org/@tootallnate/once-more/-/x.tgz"));
    assert!(!prefix.is_match("registryXnpmjs.org/@tootallnate/once/-/once-2.0.0.tgz"));
    let exact = whole("api\\.nuget\\.org/v3/index\\.json");
    assert!(exact.is_match("api.nuget.org/v3/index.json"));
    assert!(!exact.is_match("api.nuget.org/v3/index.json.bak"));
}

#[test]
fn resolved_versions_are_read_from_the_graph_and_from_a_release_url() {
    let graph = r#"{"key": "<root>", "dependencies": [
        {"key": "aspect_rules_js@3.6.0", "name": "aspect_rules_js", "version": "3.6.0"},
        {"key": "rules_java@9.3.0", "name": "rules_java", "version": "9.3.0"}]}"#;
    let versions = graph_versions(graph).unwrap();
    assert_eq!(versions["aspect_rules_js"], "3.6.0");
    assert_eq!(versions.len(), 2);
    // Bazel 7.0 and 7.1 print the key alone.
    let keyed = r#"{"key": "<root>", "dependencies": [{"key": "aspect_rules_js@1.42.3"}]}"#;
    assert_eq!(graph_versions(keyed).unwrap()["aspect_rules_js"], "1.42.3");
    assert!(graph_versions(r#"{"key": "<root>"}"#).is_err());
    assert!(graph_versions(r#"{"dependencies": [{"name": "x", "version": "1"}]}"#).is_err());
    assert!(graph_versions(r#"{"dependencies": [{"key": "x@"}]}"#).is_err());
    assert!(graph_versions("WARNING: not json").is_err());

    let build = "http_archive(\n  name = \"aspect_rules_js\",\n  url = \
                 \"https://github.com/aspect-build/rules_js/releases/download/v2.9.3/rules_js-v2.9.3.tar.gz\",\n)";
    assert_eq!(release_version(build).unwrap(), "2.9.3");
    let untagged = "url = \"https://github.com/o/r/releases/download/1.0.0-rc2/r.tar.gz\"";
    assert_eq!(release_version(untagged).unwrap(), "1.0.0-rc2");
    assert!(release_version("url = \"https://example.com/r-1.0.tar.gz\"").is_err());
    assert!(
        release_version("url = \"https://github.com/o/r/releases/download/latest/r.tgz\"").is_err()
    );

    let lock = br#"{"lockFileVersion": 13, "moduleExtensions": {"//deps:e.bzl%e": {}}}"#;
    let recorded = recorded_extensions(lock).unwrap();
    assert_eq!(recorded, ["//deps:e.bzl%e"]);
    // Lock versions spell a root extension with and without `@@`.
    assert!(records(&recorded, "//deps:e.bzl%e") && records(&recorded, "@@//deps:e.bzl%e"));
    assert!(!records(&recorded, "//deps:e.bzl%other") && !records(&recorded, "deps:e.bzl%e"));
    assert_eq!(
        recorded_extensions(b"{\"lockFileVersion\": 13}").unwrap(),
        Vec::<String>::new()
    );
    // A file that is no lock is not "a lock that records nothing".
    assert!(recorded_extensions(b"not json").is_err());
    assert!(recorded_extensions(b"[]").is_err());
    assert!(recorded_extensions(b"").is_err());
}

/// The tier-0 primitives this file adds to the harness anchors fail closed:
/// none, several, a missing member and a changed byte are each an error.
#[test]
fn probe_files_name_exactly_one_file_and_compare_its_bytes() {
    const TARBALL: &str = "registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
    const NUPKG: &str = "api.nuget.org/v3-flatcontainer/sp.victim/1.0.0/sp.victim.1.0.0.nupkg";
    const DLL: &str = "lib/netstandard2.0/SP.Victim.dll";
    let tmp = tempfile::tempdir().unwrap();
    let write = |rel: &str, bytes: &[u8]| {
        let path = tmp.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let source = |path: &Path, label: &str| SourceFile {
        path: path.to_path_buf(),
        label: label.to_string(),
    };

    // rules_js before 1.40: the source file is the directory `package`.
    let index = npm::member(&mirrored(TARBALL), "package/index.js").unwrap();
    let unpacked = ProbeFile::Unpacked {
        label: "left-pad".to_string(),
        artifact: TARBALL.to_string(),
        member: "index.js".to_string(),
    };
    let good = write("npm__left-pad__1.3.0/package/index.js", &index);
    let package = source(good.parent().unwrap(), "@@npm__left-pad__1.3.0//:package");
    let other = source(tmp.path(), "@@npm__once__2.0.0//:package");
    assert_eq!(
        unpacked.check(&[package.clone(), other.clone()]),
        Ok(good.clone())
    );
    let why = unpacked.check(std::slice::from_ref(&other)).unwrap_err();
    assert!(why.contains("found 0"), "{why}");
    // A label that only contains the name, but is no unpacked package.
    let tarball = source(&good, "@@npm__left-pad__1.3.0//:package.tgz");
    let why = unpacked.check(&[tarball]).unwrap_err();
    assert!(why.contains("found 0"), "{why}");
    let second = write("npm__left-pad__1.3.0_copy/package/index.js", &index);
    let copy = source(
        second.parent().unwrap(),
        "@@npm__left-pad__1.3.0_copy//:package",
    );
    let why = unpacked.check(&[package.clone(), copy]).unwrap_err();
    assert!(why.contains("found 2"), "{why}");
    let empty = write(
        "npm__left-pad__empty/package/README.md",
        b"no index.js here",
    );
    let hollow = source(empty.parent().unwrap(), "@@npm__left-pad__empty//:package");
    let why = unpacked.check(&[hollow]).unwrap_err();
    assert!(why.contains("index.js"), "{why}");
    let mut changed = index.clone();
    changed[0] ^= 1;
    write("npm__left-pad__1.3.0/package/index.js", &changed);
    let why = unpacked.check(&[package]).unwrap_err();
    assert!(why.contains("has digest"), "{why}");
    // A member the mirrored tarball lacks is an error of the probe, not a panic.
    let absent = ProbeFile::Unpacked {
        label: "left-pad".to_string(),
        artifact: TARBALL.to_string(),
        member: "no-such-file.js".to_string(),
    };
    let why = absent.check(&[other]).unwrap_err();
    assert!(why.contains("no member package/no-such-file.js"), "{why}");

    // rules_csharp keeps one member of the package: the anchor is that member.
    let member = ProbeFile::Sha256 {
        label: "SP.Victim.dll".to_string(),
        artifact: NUPKG.to_string(),
        member: Some(DLL.to_string()),
    };
    let dll = member.expected().unwrap();
    assert_ne!(dll, mirrored(NUPKG), "the member, not the package");
    let kept = write("nuget_sp_victim/lib/SP.Victim.dll", &dll);
    let kept_source = source(&kept, "@@nuget_sp_victim//:lib/SP.Victim.dll");
    let unrelated = source(&good, "@@nuget_sp_other//:lib/SP.Other.dll");
    assert_eq!(
        member.check(&[kept_source.clone(), unrelated.clone()]),
        Ok(kept.clone())
    );
    let why = member.check(&[unrelated]).unwrap_err();
    assert!(why.contains("found 0"), "{why}");
    let twin = write("nuget_sp_victim_2/lib/SP.Victim.dll", &dll);
    let twin_source = source(&twin, "@@nuget_sp_victim_2//:lib/SP.Victim.dll");
    let why = member
        .check(&[kept_source.clone(), twin_source])
        .unwrap_err();
    assert!(why.contains("found 2"), "{why}");
    // The whole package where the member is expected does not pass.
    write("nuget_sp_victim/lib/SP.Victim.dll", &mirrored(NUPKG));
    let why = member
        .check(std::slice::from_ref(&kept_source))
        .unwrap_err();
    assert!(why.contains("has digest"), "{why}");
    let mut changed = dll.clone();
    *changed.last_mut().unwrap() ^= 1;
    write("nuget_sp_victim/lib/SP.Victim.dll", &changed);
    let why = member
        .check(std::slice::from_ref(&kept_source))
        .unwrap_err();
    assert!(why.contains("has digest"), "{why}");
    let absent = ProbeFile::Sha256 {
        label: "SP.Victim.dll".to_string(),
        artifact: NUPKG.to_string(),
        member: Some("lib/net48/SP.Victim.dll".to_string()),
    };
    let why = absent.check(&[kept_source]).unwrap_err();
    assert!(why.contains("lib/net48/SP.Victim.dll"), "{why}");
    let unmirrored = ProbeFile::Sha256 {
        label: "x".to_string(),
        artifact: "api.nuget.org/v3-flatcontainer/sp.none/1.0.0/sp.none.1.0.0.nupkg".to_string(),
        member: None,
    };
    assert!(unmirrored.expected().is_err());
}

#[test]
fn every_known_registry_mounts_and_each_scope_is_served() {
    let server = FixtureServer::start();
    for name in REGISTRIES {
        let scopes = mount(&server, &[name.to_string()]);
        assert!(!scopes.is_empty(), "{name} owns no scope");
    }
}

#[test]
#[should_panic(expected = "MATRIX.json names an unknown registry \"cargo\"")]
fn mounting_an_unknown_registry_is_refused() {
    let server = FixtureServer::start();
    mount(&server, &["npm".to_string(), "cargo".to_string()]);
}

/// `GET /<target>` on the fixture server: the status and the body.
fn get(server: &FixtureServer, target: &str) -> (u16, Vec<u8>) {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", server.port())).unwrap();
    write!(stream, "GET /{target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a response head");
    let head = String::from_utf8_lossy(&response[..head_end]).into_owned();
    let status = head.split(' ').nth(1).and_then(|code| code.parse().ok());
    (
        status.expect("a status code"),
        response[head_end + 4..].to_vec(),
    )
}

fn mirrored(path: &str) -> Vec<u8> {
    std::fs::read(mirror().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// A mirror directory of one file, for the refusals.
fn mirror_of(path: &str, bytes: &[u8]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(path);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, bytes).unwrap();
    dir
}

#[test]
fn npm_registry_serves_tarballs_and_package_documents() {
    const TARBALL: &str = "registry.npmjs.org/@tootallnate/once/-/once-2.0.0.tgz";
    let server = FixtureServer::start();
    let scopes = npm::mount(&server, &mirror()).unwrap();
    assert_eq!(
        scopes,
        [
            "registry.npmjs.org/@tootallnate/once/-/*",
            "registry.npmjs.org/left-pad/-/*"
        ]
    );
    assert_eq!(get(&server, TARBALL), (200, mirrored(TARBALL)));
    assert_eq!(
        get(&server, "registry.npmjs.org/left-pad/-/left-pad-9.9.9.tgz").0,
        404
    );

    // pnpm asks for a scoped document with the slash encoded.
    for spelling in [
        "@tootallnate%2Fonce",
        "@tootallnate%2fonce",
        "@tootallnate/once",
    ] {
        let (status, body) = get(&server, &format!("registry.npmjs.org/{spelling}"));
        assert_eq!(status, 200, "{spelling}");
        let document: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(document["name"], "@tootallnate/once");
        assert_eq!(document["dist-tags"]["latest"], "2.0.0");
        let version = &document["versions"]["2.0.0"];
        // The tarball's own manifest, so pnpm sees the real dependency lists.
        assert_eq!(version["engines"]["node"], ">= 10");
        assert_eq!(
            version["dist"]["integrity"],
            npm::integrity(&mirrored(TARBALL))
        );
        // Under the registry pnpm was pointed at, or pnpm would pin the URL.
        let tarball = format!(
            "{}@tootallnate/once/-/once-2.0.0.tgz",
            npm::loopback_registry(&server)
        );
        assert_eq!(version["dist"]["tarball"], tarball);
    }

    let stray = mirror_of("registry.npmjs.org/left-pad/left-pad-1.3.0.tgz", b"x");
    let why = npm::mount(&server, stray.path()).unwrap_err();
    assert!(
        why.contains("is not <name>/-/<leaf>-<version>.tgz"),
        "{why}"
    );
    let misnamed = mirror_of(
        "registry.npmjs.org/right-pad/-/right-pad-1.3.0.tgz",
        &mirrored("registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"),
    );
    let why = npm::mount(&server, misnamed.path()).unwrap_err();
    assert!(why.contains("holds \"left-pad\"@\"1.3.0\""), "{why}");
    // A tarball without a manifest cannot be given a package document.
    let mut hollow = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    let mut header = tar::Header::new_gnu();
    header.set_size(1);
    header.set_mode(0o644);
    header.set_cksum();
    hollow
        .append_data(&mut header, "package/index.js", &b"x"[..])
        .unwrap();
    let hollow = hollow.into_inner().unwrap().finish().unwrap();
    let unmanifested = mirror_of("registry.npmjs.org/hollow/-/hollow-1.0.0.tgz", &hollow);
    let why = npm::mount(&server, unmanifested.path()).unwrap_err();
    assert!(why.contains("no member package/package.json"), "{why}");
    assert!(npm::mount(&server, tempfile::tempdir().unwrap().path()).is_err());
}

#[test]
fn maven_registry_serves_sha1_sidecars_and_a_loopback_repository() {
    const JAR: &str = "org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar";
    let central = format!("repo1.maven.org/maven2/{JAR}");
    let server = FixtureServer::start();
    let scopes = maven::mount(&server, &mirror()).unwrap();
    assert_eq!(
        scopes,
        [
            "repo1.maven.org/maven2/org/slf4j/slf4j-api/1.7.36/*",
            "repo1.maven.org/maven2/org/slf4j/slf4j-parent/1.7.36/*"
        ]
    );
    assert_eq!(get(&server, &central), (200, mirrored(&central)));
    let sha1 = hex::encode(<sha1::Sha1 as sha1::Digest>::digest(mirrored(&central)));
    assert_eq!(
        get(&server, &format!("{central}.sha1")),
        (200, sha1.clone().into_bytes())
    );
    // Nothing is served without its host until the loopback repository is mounted.
    assert_eq!(get(&server, &format!("maven2/{JAR}")).0, 404);

    let repository = maven::mount_loopback(&server, &mirror()).unwrap();
    assert_eq!(
        repository,
        format!("http://127.0.0.1:{}/maven2", server.port())
    );
    assert_eq!(
        get(&server, &format!("maven2/{JAR}")),
        (200, mirrored(&central))
    );
    assert_eq!(
        get(&server, &format!("maven2/{JAR}.sha1")),
        (200, sha1.into_bytes())
    );
    // The mirrored `.md5` is served as it is and gets no sidecar of its own.
    assert_eq!(get(&server, &format!("maven2/{JAR}.md5")).0, 200);
    assert_eq!(get(&server, &format!("maven2/{JAR}.md5.sha1")).0, 404);
    let empty = tempfile::tempdir().unwrap();
    assert!(maven::mount(&server, empty.path()).is_err());
    assert!(maven::mount_loopback(&server, empty.path()).is_err());
}

#[test]
fn gem_registry_serves_gems_and_refuses_one_rules_ruby_would_skip() {
    const GEM: &str = "rubygems.org/gems/sp-victim-1.0.0.gem";
    let server = FixtureServer::start();
    let scopes = gem::mount(&server, &mirror()).unwrap();
    assert_eq!(
        scopes,
        [
            "rubygems.org/gems/sp-other-*",
            "rubygems.org/gems/sp-parent-*",
            "rubygems.org/gems/sp-victim-*"
        ]
    );
    assert_eq!(get(&server, GEM), (200, mirrored(GEM)));
    // The Bundler gem is not mirrored: it comes from the real host.
    assert_eq!(get(&server, "rubygems.org/gems/bundler-4.0.15.gem").0, 404);

    let skipped = mirror_of(
        "rubygems.org/gems/sp-empty-1.0.0.gem",
        &[0; gem::SKIPPED_GEM_SIZE],
    );
    let why = gem::mount(&server, skipped.path()).unwrap_err();
    assert!(why.contains("rules_ruby would skip it"), "{why}");
    let unnamed = mirror_of("rubygems.org/gems/sp-victim.gem", b"x");
    let why = gem::mount(&server, unnamed.path()).unwrap_err();
    assert!(why.contains("is not <name>-<version>.gem"), "{why}");
    // A platform gem keeps its name; an index file is its own exact scope.
    let platform = mirror_of("rubygems.org/gems/sp-victim-1.0.0-java.gem", b"x");
    std::fs::write(platform.path().join("rubygems.org/versions"), "---\n").unwrap();
    assert_eq!(
        gem::mount(&server, platform.path()).unwrap(),
        ["rubygems.org/gems/sp-victim-*", "rubygems.org/versions"]
    );
    let why = gem::mount(&server, tempfile::tempdir().unwrap().path()).unwrap_err();
    assert!(why.contains("no gem mirror"), "{why}");
}

#[test]
fn nuget_registry_serves_the_index_the_packages_and_a_refusal() {
    const NUPKG: &str = "api.nuget.org/v3-flatcontainer/sp.victim/1.0.0/sp.victim.1.0.0.nupkg";
    let server = FixtureServer::start();
    let scopes = nuget::mount(&server, &mirror()).unwrap();
    assert_eq!(
        scopes,
        [
            "api.nuget.org/v3/index.json",
            "api.nuget.org/v3-flatcontainer/sp.other/*",
            "api.nuget.org/v3-flatcontainer/sp.victim/*"
        ]
    );
    let (status, index) = get(&server, "api.nuget.org/v3/index.json");
    assert_eq!(status, 200);
    let index: Value = serde_json::from_slice(&index).unwrap();
    assert_eq!(index["resources"][0]["@id"], nuget::FLAT_CONTAINER_URL);
    let (status, list) = get(
        &server,
        "api.nuget.org/v3-flatcontainer/sp.victim/index.json",
    );
    assert_eq!(status, 200);
    let list: Value = serde_json::from_slice(&list).unwrap();
    assert_eq!(list["versions"], serde_json::json!(["1.0.0"]));
    assert_eq!(
        nuget::nupkg_url("SP.Victim", "1.0.0"),
        format!("https://{NUPKG}")
    );
    assert_eq!(get(&server, NUPKG), (200, mirrored(NUPKG)));

    // The mirrored feed refusing its own package: a withdrawal.
    nuget::refuse(
        &server,
        nuget::FLAT_CONTAINER_URL,
        "SP.Victim",
        "1.0.0",
        410,
    );
    assert_eq!(get(&server, NUPKG), (410, Vec::new()));
    // Another feed refusing a package it does not hold, at each of the three
    // URLs a client tries there before it moves to its next source. Unrefused,
    // each is a 404.
    const FEED: &str = "patch.socket.dev/patch-registry/nuget/token/uuid/flat";
    let spellings = [
        format!("{FEED}/sp.other/1.0.0/sp.other.1.0.0.nupkg"),
        format!("{FEED}/SP.Other/1.0.0/SP.Other.1.0.0.nupkg"),
        format!("{FEED}/Download/SP.Other/1.0.0"),
    ];
    let base = format!("https://{FEED}/");
    let asked = nuget::nupkg_spellings(&base, "SP.Other", "1.0.0");
    assert_eq!(asked, spellings.clone().map(|url| format!("https://{url}")));
    // The base is the same feed with or without its trailing slash.
    assert_eq!(
        nuget::nupkg_spellings(&format!("https://{FEED}"), "SP.Other", "1.0.0"),
        asked
    );
    for spelling in &spellings {
        assert_eq!(get(&server, spelling).0, 404, "{spelling}");
    }
    for status in [403, 503] {
        nuget::refuse(&server, &base, "SP.Other", "1.0.0", status);
        for spelling in &spellings {
            assert_eq!(get(&server, spelling), (status, Vec::new()), "{spelling}");
        }
    }
    // Another version, and the same package on the mirrored feed, are untouched.
    assert_eq!(
        get(
            &server,
            &format!("{FEED}/sp.other/2.0.0/sp.other.2.0.0.nupkg")
        )
        .0,
        404
    );
    let upstream = "api.nuget.org/v3-flatcontainer/sp.other/1.0.0/sp.other.1.0.0.nupkg";
    assert_eq!(get(&server, upstream), (200, mirrored(upstream)));

    let no_index = mirror_of(NUPKG, b"x");
    let why = nuget::mount(&server, no_index.path()).unwrap_err();
    assert!(why.contains("has no v3/index.json"), "{why}");
    let elsewhere = mirror_of(
        "api.nuget.org/v3/index.json",
        br#"{"resources": [{"@id": "http://127.0.0.1:1/flat/", "@type": "PackageBaseAddress/3.0.0"}]}"#,
    );
    let why = nuget::mount(&server, elsewhere.path()).unwrap_err();
    assert!(
        why.contains("names the flat container http://127.0.0.1:1/flat/"),
        "{why}"
    );
    let search_only = mirror_of(
        "api.nuget.org/v3/index.json",
        br#"{"resources": [{"@id": "https://api.nuget.org/query", "@type": "SearchQueryService"}]}"#,
    );
    let why = nuget::mount(&server, search_only.path()).unwrap_err();
    assert!(
        why.contains("names no PackageBaseAddress/3.0.0 resource"),
        "{why}"
    );
    let garbled = mirror_of("api.nuget.org/v3/index.json", b"<html>");
    let why = nuget::mount(&server, garbled.path()).unwrap_err();
    assert!(why.starts_with("v3/index.json: "), "{why}");
    let why = nuget::mount(&server, tempfile::tempdir().unwrap().path()).unwrap_err();
    assert!(why.contains("no NuGet mirror"), "{why}");
    let stray = mirror_of(
        "api.nuget.org/v3-flatcontainer/SP.Victim/1.0.0/SP.Victim.1.0.0.nupkg",
        b"x",
    );
    std::fs::create_dir_all(stray.path().join("api.nuget.org/v3")).unwrap();
    std::fs::write(
        stray.path().join("api.nuget.org/v3/index.json"),
        mirrored("api.nuget.org/v3/index.json"),
    )
    .unwrap();
    let why = nuget::mount(&server, stray.path()).unwrap_err();
    assert!(why.contains("in lower case"), "{why}");
}

/// What a tamper twin is served: at the URL the lock pins, bytes of the mirrored
/// length with one byte changed. Nothing is appended, and nothing else moves.
#[test]
fn a_tampered_artifact_keeps_its_url_and_length_and_changes_one_byte() {
    const TARBALL: &str = "registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
    const JAR: &str = "repo1.maven.org/maven2/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar";
    const GEM: &str = "rubygems.org/gems/sp-victim-1.0.0.gem";
    const NUPKG: &str = "api.nuget.org/v3-flatcontainer/sp.victim/1.0.0/sp.victim.1.0.0.nupkg";
    let server = FixtureServer::start();
    let every: Vec<String> = REGISTRIES.iter().map(|name| name.to_string()).collect();
    mount(&server, &every);

    let tarballs = npm::tarballs(&mirror()).unwrap();
    let left_pad = tarballs.iter().find(|tarball| tarball.name == "left-pad");
    npm::tamper(&server, left_pad.expect("left-pad"));
    let jar = JAR.trim_start_matches("repo1.maven.org/maven2/");
    maven::tamper(&server, &mirror(), jar).unwrap();
    gem::tamper(&server, &mirror(), "sp-victim-1.0.0.gem").unwrap();
    nuget::tamper(&server, &mirror(), "SP.Victim", "1.0.0").unwrap();
    for artifact in [TARBALL, JAR, GEM, NUPKG] {
        let (status, served) = get(&server, artifact);
        let upstream = mirrored(artifact);
        assert_eq!((status, served.len()), (200, upstream.len()), "{artifact}");
        let changed = served.iter().zip(&upstream).filter(|(a, b)| a != b);
        assert_eq!(changed.count(), 1, "{artifact}");
    }
    assert_eq!(npm::tampered(b"ab"), b"ac");
    // rules_ruby would skip a gem of this size and never look at its bytes.
    assert_ne!(get(&server, GEM).1.len(), gem::SKIPPED_GEM_SIZE);
    // The sidecar still states the mirrored jar's digest, which the served
    // bytes no longer have.
    let sha1 = hex::encode(<sha1::Sha1 as sha1::Digest>::digest(mirrored(JAR)));
    assert_eq!(
        get(&server, &format!("{JAR}.sha1")),
        (200, sha1.into_bytes())
    );
    // The other packages are served as mirrored.
    for neighbour in [
        "registry.npmjs.org/@tootallnate/once/-/once-2.0.0.tgz",
        "rubygems.org/gems/sp-other-1.0.0.gem",
        "api.nuget.org/v3-flatcontainer/sp.other/1.0.0/sp.other.1.0.0.nupkg",
    ] {
        assert_eq!(
            get(&server, neighbour),
            (200, mirrored(neighbour)),
            "{neighbour}"
        );
    }
    // A package the mirror lacks cannot be tampered with.
    assert!(maven::tamper(&server, &mirror(), "org/slf4j/none/1.0/none-1.0.jar").is_err());
    assert!(gem::tamper(&server, &mirror(), "sp-none-1.0.0.gem").is_err());
    assert!(nuget::tamper(&server, &mirror(), "SP.None", "1.0.0").is_err());

    // The declared `.npmrc` of a hash-miss cell: the registry and no credential.
    let npmrc = npm::loopback_npmrc(&server);
    let registry = format!("http://127.0.0.1:{}/registry.npmjs.org/", server.port());
    assert_eq!(npmrc, format!("registry={registry}\n"));
    assert_eq!(npm::loopback_registry(&server), registry);
}
