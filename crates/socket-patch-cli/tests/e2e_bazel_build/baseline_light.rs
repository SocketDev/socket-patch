//! Real-Bazel tests: `bazel_canary_baseline_*` for the light fixtures (rules_js,
//! rules_jvm_external, rules_ruby, rules_dotnet, rules_csharp).
//!
//! One canary per fixture workspace under `fixtures/bazel/light/<ruleset>/`. It
//! proves that the untouched fixture is a working build on the Bazel it is listed
//! for, which every later test of that fixture starts from: `//:socket_probe`
//! builds, Bazel materialised exactly the mirrored registry artifact (proof tier 0),
//! `//:consumer` loads, the ruleset resolved to the version `MATRIX.json` pins, and
//! the build wrote nothing into the workspace but Bazel's own files. The report it
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
//! The tests without `#[ignore]` need no Bazel: they hold `MATRIX.json`, the
//! fixture trees and the registry mirror to each other, and exercise the four
//! registry modules against a live fixture server.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::bazel_build_common::env::{self, Group, System};
use crate::bazel_build_common::fixture_server::FixtureServer;
use crate::bazel_build_common::probe_report;
use crate::bazel_build_common::proof::{Anchor, SourceFile, CONSUMER, PROBE};
use crate::bazel_build_common::registry::{gem, maven, npm, nuget};
use crate::bazel_build_common::server::Cell;
use crate::bazel_build_common::workspace::{fixtures_root, MODULE_LOCK, PROBE_BZL};
use crate::bazel_common::snapshot::{assert_same_tree_but_bazel_owned, snapshot, Entry};

/// `fixtures/bazel/light`.
fn light() -> PathBuf {
    fixtures_root().join("light")
}

/// The mirror the registry modules serve: `<host>/<path>` for every artifact a
/// light fixture pins.
fn mirror() -> PathBuf {
    light().join("registry")
}

/// `light/<ruleset>/MATRIX.json`: the fixtures of one ruleset and the Bazel
/// versions each is claimed on. Unknown keys are refused, so a field this file
/// does not act on cannot sit in a matrix and look honoured.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Matrix {
    group: String,
    ruleset: String,
    /// The registry modules that serve this ruleset's packages.
    registries: Vec<String>,
    /// What `//:socket_probe` of every fixture of the ruleset must hold.
    probe: Vec<ProbeFile>,
    fixtures: Vec<Fixture>,
}

/// One file the proof ladder anchors on, by the kind of
/// [`Anchor`](crate::bazel_build_common::proof::Anchor) that names it.
/// `artifact` is its path in the mirror, which is also its URL without the scheme.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "anchor", rename_all = "snake_case")]
enum ProbeFile {
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
struct Fixture {
    /// `<bzlmod|workspace>/<era>[-<variant>]`, under the ruleset's directory.
    path: String,
    /// The canary of this fixture.
    test: String,
    system: String,
    /// Ruleset module (or WORKSPACE repository) name to the version the fixture
    /// is written for.
    pins: BTreeMap<String, String>,
    /// What sets this fixture apart, for a reader of the matrix.
    shape: String,
    cells: Vec<CellSpec>,
    /// Bazel version to a committed `MODULE.bazel.lock`, relative to the
    /// fixture, for a fixture whose shape is a fact of that lock.
    #[serde(default)]
    module_lock: BTreeMap<String, String>,
    /// A `moduleExtensions` key the lock must hold after the build: the
    /// extension is recorded, so an edit of the file it reads stales the lock.
    #[serde(default)]
    recorded_extension: Option<String>,
    /// What `//:socket_probe` holds in this fixture, where it differs from the
    /// ruleset's.
    #[serde(default)]
    probe: Option<Vec<ProbeFile>>,
    /// The Maven repository URL the fixture commits for a client Bazel's
    /// downloader does not carry (Coursier, in an unpinned hub). It is loopback
    /// on a fixed port; the canary serves the mirror under its own port and
    /// writes that into its copy of `MODULE.bazel`.
    #[serde(default)]
    loopback_repository: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CellSpec {
    bazel: String,
    /// `nightly` or `pr`: which CI tier runs the cell.
    tier: String,
    /// The class the ruleset's hosted lane must reach on this cell, where a
    /// probe fixed it (`WORKS`, `WORKS-AFTER`).
    #[serde(default)]
    outcome: Option<String>,
}

impl Matrix {
    fn load(ruleset: &str) -> Matrix {
        let path = light().join(ruleset).join("MATRIX.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let matrix: Matrix =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(matrix.ruleset, ruleset, "{}", path.display());
        assert_eq!(matrix.group, Group::Light.name(), "{}", path.display());
        matrix
    }

    fn fixture(&self, path: &str) -> &Fixture {
        let found = self.fixtures.iter().find(|fixture| fixture.path == path);
        found.unwrap_or_else(|| panic!("{}/MATRIX.json lists no fixture {path}", self.ruleset))
    }
}

impl ProbeFile {
    fn artifact(&self) -> &str {
        match self {
            ProbeFile::Integrity { artifact, .. }
            | ProbeFile::Sha256 { artifact, .. }
            | ProbeFile::FileJar { artifact, .. }
            | ProbeFile::Unpacked { artifact, .. } => artifact,
        }
    }

    /// The bytes Bazel must have materialised: the mirrored artifact, or the
    /// one member of it the ruleset keeps.
    fn expected(&self) -> Vec<u8> {
        let path = mirror().join(self.artifact());
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let member = match self {
            ProbeFile::Unpacked { member, .. } => {
                let member = npm::member(&bytes, &format!("package/{member}"));
                return member.unwrap_or_else(|why| panic!("{}: {why}", path.display()));
            }
            ProbeFile::Sha256 {
                member: Some(member),
                ..
            } => member,
            _ => return bytes,
        };
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let mut file = archive
            .by_name(member)
            .unwrap_or_else(|e| panic!("{}: {member}: {e}", path.display()));
        let mut out = Vec::new();
        file.read_to_end(&mut out).expect("read a zip member");
        out
    }

    /// Tier 0 for this file: exactly one source file of `//:socket_probe` is it,
    /// with the expected bytes.
    fn check(&self, sources: &[SourceFile]) -> Result<PathBuf, String> {
        let bytes = self.expected();
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
fn mount(server: &FixtureServer, names: &[String]) -> Vec<String> {
    let mirror = mirror();
    let mut scopes = Vec::new();
    for name in names {
        let mounted = match name.as_str() {
            "npm" => npm::mount(server, &mirror),
            "maven" => maven::mount(server, &mirror),
            "gem" => gem::mount(server, &mirror),
            "nuget" => nuget::mount(server, &mirror),
            other => Err(format!("MATRIX.json names an unknown registry {other:?}")),
        };
        scopes.extend(mounted.unwrap_or_else(|why| panic!("{why}")));
    }
    scopes
}

/// The downloader config that sends `scopes`, and nothing else, to the fixture
/// server on `port`. A scope is a URL without its scheme; a trailing `*` makes it
/// a prefix. Bazel matches a `rewrite` pattern against the whole URL, so each
/// line covers exactly its scope, and there is no `block`: the ruleset itself
/// still comes from its real origin.
fn downloader_rules(scopes: &[String], port: u16) -> String {
    let mut rules = String::new();
    for scope in scopes {
        let (literal, tail) = match scope.strip_suffix('*') {
            Some(prefix) => (prefix, ".*"),
            None => (scope.as_str(), ""),
        };
        let pattern = regex::escape(literal);
        rules.push_str(&format!(
            "rewrite ({pattern}{tail}) http://127.0.0.1:{port}/$1\n"
        ));
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
/// result Bazel recorded. Empty for a lock that has none or is not JSON.
fn recorded_extensions(lock: &[u8]) -> Vec<String> {
    let lock: Value = serde_json::from_slice(lock).unwrap_or(Value::Null);
    let extensions = lock["moduleExtensions"].as_object();
    extensions.map_or_else(Vec::new, |map| map.keys().cloned().collect())
}

/// The canary of the fixture `path` of `ruleset`. See the module documentation.
fn baseline(test: &str, ruleset: &str, path: &str) {
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

    let source = light().join(ruleset).join(path);
    cell.copy_fixture(&format!("light/{ruleset}/{path}"));
    // The committed locks are fixture data, not part of the workspace.
    let _ = std::fs::remove_dir_all(cell.scratch.workspace.join("locks"));
    if let Some(lock) = fixture.module_lock.get(&version) {
        let lock = source.join(lock);
        let bytes = std::fs::read(&lock).unwrap_or_else(|e| panic!("{}: {e}", lock.display()));
        cell.write_module_lock(&bytes);
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
    let build = cell.bazel("build", &[PROBE]);
    if build.origin_unreachable() {
        let why = format!("an origin is unreachable:\n{}", build.stderr());
        probe_report::skip(&cell.report, &why);
        return;
    }
    assert!(build.ok(), "{test}: {}", build.dump());

    // Tier 0: the files Bazel materialised for the probe are the mirrored ones.
    let probe = fixture.probe.as_ref().unwrap_or(&matrix.probe);
    let sources = cell.tier0_sources();
    for file in probe {
        if let Err(why) = file.check(&sources) {
            panic!("{test}: tier 0: {why}");
        }
    }
    // Tier 2 is not run here, but its target must exist and its rule must load.
    let consumer = cell.bazel_ok("query", &["--output=label_kind", CONSUMER]);
    let consumer = consumer.stdout().trim().to_string();
    assert!(consumer.ends_with(CONSUMER), "{test}: {consumer:?}");

    let resolved = resolved_versions(&cell, system, &fixture.pins);
    assert_eq!(
        resolved, fixture.pins,
        "{test}: Bazel resolved other ruleset versions than {ruleset}/MATRIX.json pins"
    );

    let recorded = cell.module_lock().map(|lock| recorded_extensions(&lock));
    if let Some(extension) = &fixture.recorded_extension {
        let recorded = recorded.as_deref().unwrap_or_default();
        assert!(
            recorded.iter().any(|key| key == extension),
            "{test}: {MODULE_LOCK} does not record {extension}: {recorded:?}"
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
    let authorization = requests.iter().any(|request| {
        request
            .headers
            .iter()
            .any(|(name, _)| name == "authorization")
    });

    // A request to the loopback repository carries no host of its own.
    let host = |host: String| match host.as_str() {
        maven::ROOT => "127.0.0.1".to_string(),
        _ => host,
    };
    cell.report.hosts = server.hosts().into_iter().map(host).collect();
    cell.report.direct_network = true;
    cell.report.resolved = resolved;
    cell.report
        .detail("fixture", format!("light/{ruleset}/{path}"))
        .detail("tier", spec.tier.clone())
        .detail("outcome", spec.outcome.clone())
        .detail("consumer", consumer)
        .detail("cold_repository_cache", cold)
        .detail("fixture_server_requests", requests.len())
        .detail("authorization_header_sent", authorization)
        .detail("recorded_extensions", recorded);
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

        /// `(test, ruleset, fixture path)` of every canary.
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

/// The rulesets with a directory under `light/`.
fn rulesets() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(light())
        .expect("read fixtures/bazel/light")
        .map(|entry| entry.expect("dir entry"))
        .filter(|entry| entry.path().join("MATRIX.json").is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The fixture workspaces on disk under `light/<ruleset>/`, as matrix paths.
fn fixture_dirs(ruleset: &str) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for system in [System::Bzlmod, System::Workspace] {
        let dir = light().join(ruleset).join(system.name());
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let era = entry.file_name().to_string_lossy().into_owned();
            paths.insert(format!("{}/{era}", system.name()));
        }
    }
    paths
}

/// The text of every file of a fixture except its committed locks, as one
/// string per file. A fixture holds no binary file.
fn fixture_texts(ruleset: &str, path: &str) -> BTreeMap<String, String> {
    let tree = snapshot(&light().join(ruleset).join(path));
    let text = |(name, entry): (String, Entry)| match entry {
        Entry::File { bytes, .. } if !name.starts_with("locks/") => {
            let text = String::from_utf8(bytes);
            Some((
                name.clone(),
                text.unwrap_or_else(|_| panic!("{ruleset}/{path}/{name} is not UTF-8")),
            ))
        }
        _ => None,
    };
    tree.into_iter().filter_map(text).collect()
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

/// The matrices, the fixture directories and the canaries name the same
/// fixtures, each canary has the name its fixture's path gives it, and every
/// cell is on a Bazel the installer can provide.
#[test]
fn every_light_fixture_has_a_matrix_entry_and_a_canary() {
    let pinned = pinned_bazel_versions();
    let mut listed = BTreeSet::new();
    for ruleset in rulesets() {
        let matrix = Matrix::load(&ruleset);
        let paths: BTreeSet<String> = matrix.fixtures.iter().map(|f| f.path.clone()).collect();
        assert_eq!(
            paths.len(),
            matrix.fixtures.len(),
            "{ruleset}: a path twice"
        );
        assert_eq!(
            paths,
            fixture_dirs(&ruleset),
            "{ruleset}: MATRIX.json and the directories differ"
        );
        for fixture in &matrix.fixtures {
            let (system, _) = fixture.path.split_once('/').expect("<system>/<era>");
            assert_eq!(fixture.system, system, "{ruleset}/{}", fixture.path);
            let name = fixture.path.replace(['/', '-'], "_");
            assert_eq!(
                fixture.test,
                format!("bazel_canary_baseline_{ruleset}_{name}")
            );
            assert!(!fixture.shape.is_empty() && !fixture.pins.is_empty());
            assert!(
                !fixture.cells.is_empty(),
                "{}: no cell claims it",
                fixture.test
            );
            for spec in &fixture.cells {
                assert!(
                    pinned.contains(&spec.bazel),
                    "{}: Bazel {} is not in scripts/bazel-pins.txt",
                    fixture.test,
                    spec.bazel
                );
                assert!(["nightly", "pr"].contains(&spec.tier.as_str()));
            }
            for (bazel, lock) in &fixture.module_lock {
                assert!(fixture.cells.iter().any(|spec| &spec.bazel == bazel));
                let lock = light().join(&ruleset).join(&fixture.path).join(lock);
                assert!(lock.is_file(), "{} is missing", lock.display());
            }
            listed.insert((fixture.test.clone(), ruleset.clone(), fixture.path.clone()));
        }
    }
    let canaries: BTreeSet<(String, String, String)> = CANARIES
        .iter()
        .map(|(test, ruleset, path)| (test.to_string(), ruleset.to_string(), path.to_string()))
        .collect();
    assert_eq!(canaries.len(), CANARIES.len(), "a canary twice");
    assert_eq!(listed, canaries, "the matrices and the canaries differ");
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
        }
    }
}

/// The mirror holds what the locks pin: each probed artifact's digest, in the
/// encoding its ecosystem uses, appears in the fixture. A mirror file replaced
/// without its locks (or the reverse) fails here, not in a Bazel checksum error
/// a day later. An unpinned hub is the exception that proves the rule: it
/// commits no digest at all.
#[test]
fn every_light_lock_pins_the_mirrored_artifact() {
    for ruleset in rulesets() {
        let matrix = Matrix::load(&ruleset);
        for fixture in &matrix.fixtures {
            let texts = fixture_texts(&ruleset, &fixture.path);
            for file in fixture.probe.as_ref().unwrap_or(&matrix.probe) {
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
                    "light/{ruleset}/{}: a digest of {} is pinned: {pinned}",
                    fixture.path,
                    file.artifact()
                );
            }
        }
    }
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
    assert_eq!(recorded_extensions(lock), ["//deps:e.bzl%e"]);
    assert!(recorded_extensions(b"{\"lockFileVersion\": 13}").is_empty());
    assert!(recorded_extensions(b"not json").is_empty());
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
    assert!(maven::mount(&server, tempfile::tempdir().unwrap().path()).is_err());
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

    nuget::refuse(&server, "SP.Victim", "1.0.0", 403);
    assert_eq!(get(&server, NUPKG), (403, Vec::new()));

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
