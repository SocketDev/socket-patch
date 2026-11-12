//! Real-Bazel tests: `bazel_canary_baseline_*` for the heavy fixtures (the
//! Python family, gazelle, Rust). Each builds one fixture workspace of
//! `fixtures/bazel/heavy/` as committed, before socket-patch touches it,
//! and records what later tests and claims rest on: the ruleset versions
//! Bazel resolved, the toolchains the fetch needed, the hosts asked.
//!
//! The cells are data. `heavy/<ruleset>/MATRIX.json` lists every fixture
//! with its pins and the (fixture, Bazel) pairs that run; a test on a
//! Bazel release its fixture has no cell for prints `SKIP (n/a)`. The
//! tests here that need no Bazel check that those files, the fixture
//! trees and this file's test list agree.
//!
//! A baseline is a canary and reaches the real hosts (`direct_network` in
//! its report): the registry, the ruleset archives and the language
//! toolchains come from where a user gets them. Only the fixture's own
//! packages are synthetic. They are served by the fixture server under
//! their production URLs, through a downloader rewrite that names exactly
//! those URLs, or through the lever of the tool that fetches them
//! (`GOPROXY`, pip's `--index-url`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::bazel_build_common::env::{Group, System};
use crate::bazel_build_common::fixture_server::FixtureServer;
use crate::bazel_build_common::probe_report;
use crate::bazel_build_common::proof::{Anchor, PROBE};
use crate::bazel_build_common::registry::{goproxy, pypi_files, pypi_index};
use crate::bazel_build_common::server::Cell;
use crate::bazel_build_common::workspace::{fixtures_root, PROBE_BZL};

/// What a committed fixture file writes where a test needs the fixture
/// server's origin (pip's `--index-url`). The runner replaces it in the
/// workspace copy, in the files the fixture lists under `substitute`: a
/// loopback port never reaches a committed file.
const ORIGIN_PLACEHOLDER: &str = "http://socket-fixture.invalid";

/// One `heavy/<ruleset>/MATRIX.json`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Matrix {
    group: String,
    ruleset: String,
    fixtures: Vec<Fixture>,
}

/// One fixture workspace and the cells it runs in.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    /// The workspace, relative to `fixtures/bazel`.
    fixture: String,
    /// The test of this file that builds it.
    test: String,
    system: String,
    /// Ruleset to the version the build must resolve.
    pins: BTreeMap<String, String>,
    /// WORKSPACE fixtures: ruleset to the name of its repository rule,
    /// where the two differ (`rules_go` is `io_bazel_rules_go`).
    #[serde(default)]
    workspace_repos: BTreeMap<String, String>,
    /// The registry emulations the fixture's packages come from: `pypi`
    /// (Bazel's downloader), `pypi-pip` (pip itself), `goproxy`.
    registries: Vec<String>,
    /// Who fetches the packages: `downloader` or `tool`. A tool-fetched
    /// cell needs a loopback origin from the fake Socket API later.
    fetch: String,
    /// The hosts a cold run contacts directly, as far as a probe saw them.
    hosts: Vec<String>,
    probe: Probe,
    /// What `//:consumer` prints on the unpatched fixture.
    consumer: String,
    /// A substring of an external repository name per language toolchain
    /// the fetch itself needs (tier 0).
    toolchains: Vec<String>,
    #[serde(default)]
    substitute: Vec<String>,
    /// What the fixture is for.
    shape: String,
    cells: Vec<CellSpec>,
}

/// The one source file of the package among the sources of
/// `//:socket_probe`, and its upstream digest (tier 0).
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    label: String,
    sha256: String,
    /// The probe output with the same bytes (tier 1), where the probe's
    /// input is that file. Absent where it is a library rule: a source
    /// file of a Go or Rust repository is not visible to another
    /// repository on Bazel 9, so there the probe compiles the library and
    /// tier 0 alone carries the digest.
    output: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CellSpec {
    bazel: String,
    /// The highest tier of the proof ladder the baseline climbs here: 0
    /// fetch, 1 build the probe, 2 run the consumer.
    proof: u8,
    /// `nightly`, or `pr` for a cell cheap enough for the path-filtered run.
    tier: String,
    /// The probe cell that ran this pairing, or `unverified`: then this
    /// canary is the first evidence.
    evidence: String,
}

fn heavy_root() -> PathBuf {
    fixtures_root().join("heavy")
}

/// Every `MATRIX.json` directly under a ruleset directory of `heavy/`.
fn matrices() -> Vec<(PathBuf, Matrix)> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(heavy_root())
        .expect("read fixtures/bazel/heavy")
        .flatten()
    {
        let path = entry.path().join("MATRIX.json");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let matrix =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        found.push((path, matrix));
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

fn fixtures() -> Vec<Fixture> {
    let all = matrices()
        .into_iter()
        .flat_map(|(_, matrix)| matrix.fixtures);
    all.collect()
}

impl Fixture {
    fn dir(&self) -> PathBuf {
        fixtures_root().join(&self.fixture)
    }

    fn system(&self) -> System {
        System::parse(&self.system)
            .unwrap_or_else(|| panic!("{}: system {:?}", self.fixture, self.system))
    }
}

/// What mounting a fixture's registries yields for the Bazel commands.
#[derive(Default)]
struct Levers {
    /// URLs the downloader must fetch from the fixture server.
    rewrites: Vec<String>,
    repo_env: Vec<(String, String)>,
    /// The package files Bazel's downloader fetches, as (URL, sha256).
    packages: Vec<(String, String)>,
}

/// Start the emulations `fixture` names on `server`.
fn mount(fixture: &Fixture, server: &FixtureServer) -> Levers {
    let tree = heavy_root().join("registry");
    let mut levers = Levers::default();
    let distributions =
        || pypi_files::read_tree(&tree.join("pypi")).unwrap_or_else(|why| panic!("{why}"));
    for registry in &fixture.registries {
        match registry.as_str() {
            "pypi" => {
                let distributions = distributions();
                let package = |d: &pypi_files::Distribution| (d.url(), d.sha256.clone());
                levers.packages = distributions.iter().map(package).collect();
                levers
                    .rewrites
                    .extend(pypi_files::mount(server, &distributions));
                levers
                    .rewrites
                    .extend(pypi_index::mount(server, &distributions));
            }
            "pypi-pip" => {
                let distributions = distributions();
                pypi_files::mount(server, &distributions);
                let index = pypi_index::mount_pip_mode(server, &distributions);
                // For a fixture that reads the index through `envsubst`.
                levers.repo_env.push(("PIP_INDEX_URL".into(), index));
            }
            "goproxy" => {
                goproxy::mount(server, &tree.join("goproxy")).unwrap_or_else(|why| panic!("{why}"));
                // The fixture's module from the stub; gazelle's own tool
                // modules from the real proxy, which `go` tries after a 404.
                let list = format!("{},https://{}", goproxy::goproxy(server), goproxy::HOST);
                levers.repo_env.push(("GOPROXY".into(), list));
            }
            other => panic!("{}: unknown registry {other:?}", fixture.fixture),
        }
    }
    levers
}

/// Whether a cell of this process has already fetched the fixture
/// packages cold; held by that cell while it does.
static COLD_FETCH: Mutex<bool> = Mutex::new(false);

/// Make the first cell of this process that fetches `packages` through
/// Bazel's downloader fetch them from the fixture server. A persistent
/// repository cache answers a checksummed download with no request at
/// all, so on a warm cache no baseline would ever exercise the rewrite and
/// the stub, and a broken one would pass.
///
/// For that first cell the packages are removed from the cache and the
/// guard is returned: the caller holds it until its fetch is done and
/// asserted. Every other such cell waits here meanwhile, so none can read
/// a file while it is removed or put one back before the first cell asked
/// for it; they get `None` and may find the packages cached again.
fn cold_fetch(
    repository_cache: &Path,
    packages: &[(String, String)],
) -> Option<MutexGuard<'static, bool>> {
    if packages.is_empty() {
        return None;
    }
    let mut done = COLD_FETCH.lock().unwrap_or_else(PoisonError::into_inner);
    if *done {
        return None;
    }
    for (_, sha256) in packages {
        let blob = repository_cache
            .join("content_addressable/sha256")
            .join(sha256);
        match std::fs::remove_dir_all(&blob) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("evict {}: {e}", blob.display()),
        }
    }
    *done = true;
    Some(done)
}

/// A downloader config that sends exactly `urls` to the fixture server on
/// `port` and leaves every other download alone. The pattern is matched
/// against the whole URL without its scheme.
fn narrow_rewrite(urls: &[String], port: u16) -> String {
    let mut config = String::new();
    for url in urls {
        let rest = url.strip_prefix("https://").unwrap_or(url);
        config.push_str(&format!(
            "rewrite ({}) http://127.0.0.1:{port}/$1\n",
            regex::escape(rest)
        ));
    }
    config
}

/// Every `name@version` key of `bazel mod graph --output=json`, as
/// name to the versions seen.
fn graph_versions(node: &Value, out: &mut BTreeMap<String, BTreeSet<String>>) {
    match node {
        Value::Object(map) => {
            if let Some((name, version)) = map
                .get("key")
                .and_then(Value::as_str)
                .and_then(|key| key.split_once('@'))
            {
                out.entry(name.to_string())
                    .or_default()
                    .insert(version.to_string());
            }
            map.values().for_each(|child| graph_versions(child, out));
        }
        Value::Array(items) => items.iter().for_each(|child| graph_versions(child, out)),
        _ => {}
    }
}

/// Whether `rule` (the `--output=build` text of a WORKSPACE repository
/// rule) fetches release `version`: a `url`, `urls` or `strip_prefix`
/// line names it, and not as part of a longer version (`0.35.0` is not in
/// `10.35.0` or `0.35.01`, `0.35` is not in `0.35.0`).
fn rule_pins_version(rule: &str, version: &str) -> bool {
    let named = |line: &str| {
        line.match_indices(version).any(|(at, _)| {
            let before = line[..at].chars().next_back();
            let mut after = line[at + version.len()..].chars();
            let (next, then) = (after.next(), after.next());
            let digit = |c: Option<char>| c.is_some_and(|c| c.is_ascii_digit());
            let longer = digit(next) || (next == Some('.') && digit(then));
            !digit(before) && before != Some('.') && !longer
        })
    };
    let fetch_line = |line: &&str| line.contains("url") || line.contains("strip_prefix");
    rule.lines().filter(fetch_line).any(named)
}

/// The ruleset versions the build resolved, checked against the pins.
fn resolved(cell: &Cell, fixture: &Fixture) -> BTreeMap<String, String> {
    let mut resolved = BTreeMap::new();
    if fixture.system() == System::Workspace {
        // No module graph: the repository rule Bazel evaluated is the oracle.
        for (ruleset, version) in &fixture.pins {
            let repo = fixture.workspace_repos.get(ruleset).unwrap_or(ruleset);
            let rule = cell
                .bazel_ok("query", &["--output=build", &format!("//external:{repo}")])
                .stdout();
            assert!(
                rule_pins_version(&rule, version),
                "{}: @{repo} does not fetch {ruleset} {version}:\n{rule}",
                cell.test
            );
            resolved.insert(ruleset.clone(), version.clone());
        }
        return resolved;
    }
    let graph = cell
        .mod_oracle(&["graph", "--output=json"])
        .expect("a line with `bazel mod`");
    assert!(graph.ok(), "{}: {}", cell.test, graph.dump());
    let json: Value = serde_json::from_str(&graph.stdout())
        .unwrap_or_else(|e| panic!("{}: mod graph: {e}", cell.test));
    let mut versions = BTreeMap::new();
    graph_versions(&json, &mut versions);
    for (ruleset, pin) in &fixture.pins {
        let seen: Vec<&String> = versions.get(ruleset).into_iter().flatten().collect();
        assert_eq!(
            seen,
            [pin],
            "{}: {ruleset} resolved to {seen:?}, MATRIX.json pins {pin}",
            cell.test
        );
        resolved.insert(ruleset.clone(), pin.clone());
    }
    resolved
}

/// Substrings of the repository names of the language toolchains a heavy
/// fixture can pull in at fetch time: a Python interpreter, a Go SDK, the
/// host cargo and rustc of rules_rust, the cargo of rules_rs.
const LANGUAGE_TOOLCHAINS: &[&str] = &[
    "python_3_",
    "go_sdk",
    "rust_host_tools",
    "toolchains+cargo_",
];

/// The external repositories this run fetched that match each declared
/// toolchain. A toolchain the fixture says its fetch needs must be there:
/// the tier of a cell (PR or nightly) is decided on that list.
fn fetched_toolchains(cell: &Cell, fixture: &Fixture) -> BTreeMap<String, Vec<String>> {
    let external = PathBuf::from(cell.info("output_base")).join("external");
    let mut repos: Vec<String> = std::fs::read_dir(&external)
        .unwrap_or_else(|e| panic!("{}: {e}", external.display()))
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    repos.sort();
    let mut found = BTreeMap::new();
    if fixture.toolchains.is_empty() {
        // "The fetch needs no language toolchain" is a claim too: it is
        // what lets a cell into the PR tier.
        let stray: Vec<&String> = repos
            .iter()
            .filter(|repo| LANGUAGE_TOOLCHAINS.iter().any(|t| repo.contains(t)))
            .collect();
        assert!(
            stray.is_empty(),
            "{}: MATRIX.json lists no toolchain, but the fetch brought {stray:?}",
            cell.test
        );
    }
    for toolchain in &fixture.toolchains {
        let hits: Vec<String> = repos
            .iter()
            .filter(|repo| repo.contains(toolchain.as_str()))
            .cloned()
            .collect();
        assert!(
            !hits.is_empty(),
            "{}: no fetched repository matches the toolchain {toolchain:?}: {repos:?}",
            cell.test
        );
        found.insert(toolchain.clone(), hits);
    }
    found
}

/// The baseline of the fixture `test` builds.
fn baseline(test: &str) {
    let fixture = fixtures().into_iter().find(|f| f.test == test);
    let fixture = fixture.unwrap_or_else(|| panic!("{test} is in no heavy MATRIX.json"));
    let Some(mut cell) = Cell::open(test, Group::Heavy, Some(fixture.system())) else {
        return;
    };
    let version = cell.bazel.version.text.clone();
    let Some(spec) = fixture.cells.iter().find(|spec| spec.bazel == version) else {
        probe_report::skip_na(
            &cell.report,
            &format!("{} has no cell on Bazel {version}", fixture.fixture),
        );
        return;
    };
    cell.copy_fixture(&fixture.fixture);
    let server = FixtureServer::start();
    let levers = mount(&fixture, &server);
    for rel in &fixture.substitute {
        let path = cell.scratch.workspace.join(rel);
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(
            text.contains(ORIGIN_PLACEHOLDER),
            "{rel} of {} has no {ORIGIN_PLACEHOLDER}",
            fixture.fixture
        );
        cell.write(
            rel,
            text.replace(ORIGIN_PLACEHOLDER, &server.loopback_origin()),
        );
    }
    if !levers.rewrites.is_empty() {
        let config = cell.scratch.root.join("downloader.cfg");
        std::fs::write(&config, narrow_rewrite(&levers.rewrites, server.port()))
            .expect("write the downloader config");
        cell.options.downloader_config = Some(config);
    }
    cell.options.repo_env.extend(levers.repo_env);

    let cold = cold_fetch(&cell.scratch.repository_cache, &levers.packages);

    // The first command fetches everything tier 0 needs. A host that does
    // not answer is this machine's network, not the fixture.
    let fetch = cell.bazel("query", &["--output=label", &format!("deps({PROBE})")]);
    if fetch.origin_unreachable() {
        probe_report::skip(
            &cell.report,
            &format!("an origin is unreachable:\n{}", fetch.stderr()),
        );
        return;
    }
    assert!(fetch.ok(), "{test}: {}", fetch.dump());
    let anchor = Anchor::Sha256 {
        label: &fixture.probe.label,
        sha256: &fixture.probe.sha256,
    };
    cell.tier0(anchor);
    let fetched_cold = cold.is_some();
    if fetched_cold {
        // The cache held none of the packages: Bazel fetched the anchored
        // file through the rewrite, from the fixture server.
        let anchored = |(_, sha256): &&(String, String)| *sha256 == fixture.probe.sha256;
        let (url, _) = levers.packages.iter().find(anchored).expect("the anchor");
        server.assert_requested(url, test);
    }
    drop(cold);
    // Before any build: what is in `external/` now is what the fetch needed.
    let toolchains = fetched_toolchains(&cell, &fixture);
    if spec.proof >= 1 {
        match &fixture.probe.output {
            Some(name) => {
                let built = hex::encode(Sha256::digest(cell.tier1_file(name)));
                assert_eq!(
                    built, fixture.probe.sha256,
                    "{test}: tier 1: the probe output is not the upstream file"
                );
            }
            None => drop(cell.bazel_ok("build", &[PROBE])),
        }
    }
    if spec.proof >= 2 {
        cell.tier2(&fixture.consumer);
    }
    let resolved = resolved(&cell, &fixture);

    let requests = server.requests().len();
    cell.report.hosts = server.hosts();
    cell.report.direct_network = true;
    cell.report.resolved = resolved;
    cell.report
        .detail("fixture", fixture.fixture.as_str())
        .detail("proof", spec.proof)
        .detail("fetch", fixture.fetch.as_str())
        .detail("declared_hosts", fixture.hosts.clone())
        .detail("toolchains", serde_json::to_value(toolchains).unwrap())
        .detail("packages_fetched_cold", fetched_cold)
        .detail("fixture_server_requests", requests);
    cell.close().ran();
}

/// One `#[ignore]` test per fixture, and the list of their names for the
/// consistency check below.
macro_rules! baselines {
    ($($name:ident),* $(,)?) => {
        const TESTS: &[&str] = &[$(stringify!($name)),*];
        $(
            #[test]
            #[ignore = "real Bazel; run with --ignored"]
            fn $name() {
                baseline(stringify!($name));
            }
        )*
    };
}

baselines! {
    bazel_canary_baseline_aspect_rules_py_bzlmod_e9,
    bazel_canary_baseline_aspect_rules_py_bzlmod_e8_canary,
    bazel_canary_baseline_gazelle_bzlmod_e9,
    bazel_canary_baseline_gazelle_bzlmod_e9_nocheck,
    bazel_canary_baseline_gazelle_bzlmod_e9_beta,
    bazel_canary_baseline_gazelle_bzlmod_e7,
    bazel_canary_baseline_gazelle_bzlmod_e7_refusal,
    bazel_canary_baseline_gazelle_bzlmod_e7_sp_lock,
    bazel_canary_baseline_gazelle_directory_bzlmod_e9,
    bazel_canary_baseline_gazelle_directory_bzlmod_e7,
    bazel_canary_baseline_gazelle_workspace_workspace_e7,
    bazel_canary_baseline_gazelle_workspace_workspace_e7_macro,
    bazel_canary_baseline_gazelle_workspace_workspace_e7_keep,
    bazel_canary_baseline_gazelle_workspace_workspace_e7_seed,
    bazel_canary_baseline_rules_pycross_bzlmod_e9,
    bazel_canary_baseline_rules_pycross_bzlmod_e9_0_8_3,
    bazel_canary_baseline_rules_python_bzlmod_e9,
    bazel_canary_baseline_rules_python_bzlmod_e9_unhashed,
    bazel_canary_baseline_rules_python_bzlmod_e9_per_platform,
    bazel_canary_baseline_rules_python_bzlmod_e9_compile,
    bazel_canary_baseline_rules_python_bzlmod_e7_1_4_2,
    bazel_canary_baseline_rules_python_bzlmod_e7_1_3_0,
    bazel_canary_baseline_rules_python_workspace_e7,
    bazel_canary_baseline_rules_python_uv_bzlmod_e9,
    bazel_canary_baseline_rules_python_uv_bzlmod_e9_requirements,
    bazel_canary_baseline_rules_rs_bzlmod_e9,
    bazel_canary_baseline_rules_rs_bzlmod_e9_multi,
    bazel_canary_baseline_rules_rust_bzlmod_e9,
    bazel_canary_baseline_rules_rust_bzlmod_e9_nolock,
    bazel_canary_baseline_rules_rust_bzlmod_e7,
}

/// The workspaces under `dir`: every directory with a `MODULE.bazel` or a
/// `WORKSPACE`, relative to `fixtures/bazel`.
fn workspaces(dir: &Path, out: &mut BTreeSet<String>) {
    if dir.join("MODULE.bazel").is_file() || dir.join("WORKSPACE").is_file() {
        let rel = dir.strip_prefix(fixtures_root()).unwrap();
        out.insert(rel.to_string_lossy().replace('\\', "/"));
        return;
    }
    for entry in std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|entry| entry.path().is_dir())
    {
        workspaces(&entry.path(), out);
    }
}

/// Every file of a fixture workspace, as (relative path, bytes).
fn files(dir: &Path, rel: &str, out: &mut Vec<(String, Vec<u8>)>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let below = if rel.is_empty() {
            name
        } else {
            format!("{rel}/{name}")
        };
        if entry.path().is_dir() {
            files(&entry.path(), &below, out);
        } else {
            out.push((below, std::fs::read(entry.path()).unwrap()));
        }
    }
}

/// The Bazel releases `scripts/bazel-pins.txt` pins.
fn pinned_bazel_versions() -> BTreeSet<String> {
    let pins = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/bazel-pins.txt");
    let text = std::fs::read_to_string(&pins).unwrap_or_else(|e| panic!("{}: {e}", pins.display()));
    let rows = text
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>());
    rows.filter(|row| row.first() == Some(&"bazel"))
        .map(|row| row[1].to_string())
        .collect()
}

#[test]
fn heavy_matrix_lists_every_fixture_and_every_test() {
    let pinned = pinned_bazel_versions();
    let mut on_disk = BTreeSet::new();
    workspaces(&heavy_root(), &mut on_disk);
    let mut listed = BTreeSet::new();
    let mut tests = BTreeSet::new();
    for (path, matrix) in matrices() {
        let at = path.display();
        assert_eq!(matrix.group, "heavy", "{at}");
        let ruleset_dir = path
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(matrix.ruleset, ruleset_dir, "{at}");
        for fixture in &matrix.fixtures {
            let name = &fixture.fixture;
            // heavy/<ruleset>/<system>/<era>[-<variant>]
            let parts: Vec<&str> = name.split('/').collect();
            let system = fixture.system();
            assert!(
                matches!(parts[..], ["heavy", ruleset, sys, _] if ruleset == matrix.ruleset && sys == system.name()),
                "{at}: {name}"
            );
            assert!(listed.insert(name.clone()), "{at}: {name} is listed twice");
            assert!(
                tests.insert(fixture.test.clone()),
                "{at}: {} builds two fixtures",
                fixture.test
            );
            assert!(
                fixture.test.starts_with("bazel_canary_baseline_"),
                "{at}: {}",
                fixture.test
            );
            assert!(
                matches!(fixture.fetch.as_str(), "downloader" | "tool"),
                "{at}: {name}: fetch"
            );
            assert!(
                !fixture.cells.is_empty() && !fixture.pins.is_empty() && !fixture.shape.is_empty(),
                "{at}: {name}"
            );
            let mut lines = BTreeSet::new();
            for spec in &fixture.cells {
                assert!(
                    lines.insert(&spec.bazel),
                    "{at}: {name} lists Bazel {} twice",
                    spec.bazel
                );
                assert!(
                    pinned.contains(&spec.bazel),
                    "{at}: {name}: Bazel {} is not in bazel-pins.txt",
                    spec.bazel
                );
                // 7.7.0 alone writes absolute file:/// registry keys into a lock.
                assert_ne!(spec.bazel, "7.7.0", "{at}: {name}");
                assert!(spec.proof <= 2 && !spec.evidence.is_empty(), "{at}: {name}");
                let version = crate::bazel_build_common::env::Version::parse(&spec.bazel).unwrap();
                assert!(
                    version.system_flags(system).is_some(),
                    "{at}: {name}: Bazel {} has no {}",
                    spec.bazel,
                    system.name()
                );
                // Go and Rust need their toolchain (65 MB and 121 MB) just
                // to fetch: never a PR cell without a restored cache.
                let heavy_fetch = fixture
                    .toolchains
                    .iter()
                    .any(|t| t.contains("go_sdk") || t.contains("rust") || t.contains("cargo"));
                assert!(
                    spec.tier == "nightly" || (spec.tier == "pr" && !heavy_fetch),
                    "{at}: {name}: tier {}",
                    spec.tier
                );
            }
        }
    }
    assert_eq!(
        listed, on_disk,
        "MATRIX.json fixtures and the workspaces under heavy/ differ"
    );
    let declared: BTreeSet<String> = TESTS.iter().map(|test| test.to_string()).collect();
    assert_eq!(
        tests, declared,
        "MATRIX.json tests and the baselines! list differ"
    );
}

#[test]
fn heavy_fixtures_follow_the_fixture_conventions() {
    let dep =
        regex::Regex::new(r#"bazel_dep\(\s*name = "([^"]+)",\s*version = "([^"]+)""#).unwrap();
    let pin = regex::Regex::new(
        r#"single_version_override\(\s*module_name = "([^"]+)",\s*version = "([^"]+)""#,
    )
    .unwrap();
    for fixture in fixtures() {
        let name = &fixture.fixture;
        let mut tree = Vec::new();
        files(&fixture.dir(), "", &mut tree);
        let text = |rel: &str| {
            let hit = tree.iter().find(|(path, _)| path == rel);
            hit.map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
        };
        // The harness installs the shared probe rule; both ladder targets exist.
        assert!(
            text(PROBE_BZL).is_none(),
            "{name} ships its own {PROBE_BZL}"
        );
        let build = text("BUILD.bazel").unwrap_or_else(|| panic!("{name} has no BUILD.bazel"));
        assert!(
            build.contains("load(\"//:probe.bzl\", \"socket_probe\")"),
            "{name}: BUILD.bazel"
        );
        for target in ["name = \"socket_probe\"", "name = \"consumer\""] {
            assert!(
                build.contains(target),
                "{name}: BUILD.bazel has no {target}"
            );
        }
        // Bazel owns the lock and the convenience links.
        for (path, bytes) in &tree {
            let leaf = path.rsplit('/').next().unwrap();
            assert!(
                leaf != "MODULE.bazel.lock" || path.starts_with("locks/"),
                "{name}: {path}"
            );
            assert!(!path.starts_with("bazel-"), "{name}: {path}");
            let content = String::from_utf8_lossy(bytes);
            assert!(
                !content.contains("127.0.0.1") && !content.contains("localhost"),
                "{name}: {path} names a loopback host"
            );
            let substituted = fixture.substitute.iter().any(|rel| rel == path);
            assert_eq!(
                content.contains(ORIGIN_PLACEHOLDER),
                substituted,
                "{name}: {path} and `substitute` disagree"
            );
        }
        if fixture.system() == System::Workspace {
            assert!(
                text("WORKSPACE").is_some() && text("MODULE.bazel").is_none(),
                "{name}: a WORKSPACE-only fixture"
            );
            continue;
        }
        // A declared version can be lifted by another module, and 9.3.2
        // rejects an override below the declared one: both state the pin.
        let module = text("MODULE.bazel").unwrap();
        let pairs = |re: &regex::Regex| -> BTreeMap<String, String> {
            re.captures_iter(&module)
                .map(|c| (c[1].to_string(), c[2].to_string()))
                .collect()
        };
        let (deps, overrides) = (pairs(&dep), pairs(&pin));
        for (ruleset, version) in &fixture.pins {
            assert_eq!(
                deps.get(ruleset),
                Some(version),
                "{name}: bazel_dep of {ruleset}"
            );
            assert_eq!(
                overrides.get(ruleset),
                Some(version),
                "{name}: single_version_override of {ruleset}"
            );
        }
        // BCR lists no rules_python 2.5.0, only its release candidates.
        assert_ne!(
            fixture.pins.get("rules_python").map(String::as_str),
            Some("2.5.0"),
            "{name}"
        );
    }
}

#[test]
fn heavy_registry_tree_is_the_one_the_fixtures_pin() {
    let registry = heavy_root().join("registry");
    let mut tree = Vec::new();
    files(&registry, "", &mut tree);
    let sums = String::from_utf8(
        tree.iter()
            .find(|(path, _)| path == "SHA256SUMS")
            .expect("registry/SHA256SUMS")
            .1
            .clone(),
    )
    .unwrap();
    let mut expected: Vec<String> = tree
        .iter()
        .filter(|(path, _)| path != "SHA256SUMS")
        .map(|(path, bytes)| format!("{}  {path}", hex::encode(Sha256::digest(bytes))))
        .collect();
    expected.sort_by(|a, b| a[66..].cmp(&b[66..]));
    assert_eq!(
        sums.lines().collect::<Vec<_>>(),
        expected,
        "registry/SHA256SUMS is stale"
    );

    // Every digest a hashed Python lock states is a file of the tree, and
    // every probe anchor of a Python fixture is one too.
    let wheels = pypi_files::read_tree(&registry.join("pypi")).unwrap();
    let known: BTreeSet<&str> = wheels.iter().map(|d| d.sha256.as_str()).collect();
    let digest = regex::Regex::new(r"sha256[:=]([0-9a-f]{64})").unwrap();
    for fixture in fixtures()
        .into_iter()
        .filter(|f| f.registries.iter().any(|r| r.starts_with("pypi")))
    {
        assert!(
            known.contains(fixture.probe.sha256.as_str()),
            "{}: the probe anchor is no wheel of the tree",
            fixture.fixture
        );
        let mut tree = Vec::new();
        files(&fixture.dir(), "", &mut tree);
        for (path, bytes) in tree
            .iter()
            .filter(|(path, _)| path.ends_with(".txt") || path.ends_with(".lock"))
        {
            for hit in digest.captures_iter(&String::from_utf8_lossy(bytes)) {
                assert!(
                    known.contains(&hit[1]),
                    "{}: {path} pins {}, which the registry tree does not serve",
                    fixture.fixture,
                    &hit[1]
                );
            }
        }
    }
}

#[test]
fn the_narrow_rewrite_names_exact_urls_and_resolved_versions_are_read_strictly() {
    let config = narrow_rewrite(&["https://pypi.org/simple/spvictim/".to_string()], 4711);
    assert_eq!(
        config,
        "rewrite (pypi\\.org/simple/spvictim/) http://127.0.0.1:4711/$1\n"
    );
    let pattern = regex::Regex::new(&format!("^{}$", config.split(' ').nth(1).unwrap())).unwrap();
    assert!(pattern.is_match("pypi.org/simple/spvictim/"));
    // Neither another project nor a host that merely contains the name.
    assert!(!pattern.is_match("pypi.org/simple/spvictim-extra/"));
    assert!(!pattern.is_match("pypiXorg/simple/spvictim/"));

    let graph: Value = serde_json::from_str(
        r#"{"key": "<root>", "dependencies": [
            {"key": "rules_go@0.65.0", "dependencies": [{"key": "gazelle@0.54.0", "unexpanded": true}]},
            {"key": "gazelle@0.54.0", "dependencies": []}]}"#,
    )
    .unwrap();
    let mut versions = BTreeMap::new();
    graph_versions(&graph, &mut versions);
    let one = |v: &str| BTreeSet::from([v.to_string()]);
    assert_eq!(
        versions,
        BTreeMap::from([
            ("rules_go".to_string(), one("0.65.0")),
            ("gazelle".to_string(), one("0.54.0"))
        ])
    );

    let rule = "http_archive(\n  name = \"bazel_gazelle\",\n  urls = [\"https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.35.0/bazel-gazelle-v0.35.0.tar.gz\"],\n  sha256 = \"0.36.0\",\n)";
    assert!(rule_pins_version(rule, "0.35.0"));
    // Not a prefix of another release, and not from an attribute that fetches nothing.
    assert!(!rule_pins_version(rule, "0.35"));
    assert!(!rule_pins_version(rule, "0.36.0"));
    assert!(!rule_pins_version(
        &rule.replace("v0.35.0", "v10.35.0"),
        "0.35.0"
    ));
}
