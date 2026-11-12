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
//! (`GOPROXY`, pip's `--index-url`). A baseline therefore has no offline
//! phase and no real-registry variant: in either cell it prints
//! `SKIP (n/a)`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use socket_patch_core::bazel::module_lock::ModuleLock;

use crate::bazel_build_common::env::{self, Group, System};
use crate::bazel_build_common::fixture_server::FixtureServer;
use crate::bazel_build_common::probe_report;
use crate::bazel_build_common::proof::{Anchor, PROBE};
use crate::bazel_build_common::registry::{goproxy, pypi_files, pypi_index};
use crate::bazel_build_common::server::Cell;
use crate::bazel_build_common::workspace::{fixtures_root, MODULE_LOCK, PROBE_BZL};

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
    /// Who fetches the packages of the fixture as committed: Bazel's
    /// `downloader`, or a `tool` (pip, go, cargo).
    fetch: String,
    /// Who fetches a hosted reference once socket-patch has rewritten the
    /// fixture, where that is not who [`Fixture::fetch`] names: on
    /// rules_python 1.3.0 and 1.4.2 pip installs a registry requirement
    /// and Bazel's downloader fetches a hashed direct reference. Read it
    /// through [`Fixture::hosted_fetch`].
    #[serde(default)]
    hosted_fetch: Option<String>,
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
    /// The test targets that pass on the fixture as committed (the lock
    /// check of `compile_pip_requirements`). The baseline runs them, so a
    /// later test that expects one to turn red starts from a green one.
    #[serde(default)]
    test_targets: Vec<String>,
    /// What `MODULE.bazel.lock` says about the fixture's extension after
    /// the builds, for a fixture whose shape is a statement about the lock.
    #[serde(default)]
    lock: Option<LockSpec>,
    /// What the fixture is for.
    shape: String,
    cells: Vec<CellSpec>,
}

/// A claim about the lock Bazel writes. An extension is named as
/// `<label>%<name>` without its repository (`//:extensions.bzl%go_deps`):
/// the canonical repository name is spelled differently per Bazel line
/// (`gazelle~`, `gazelle+`).
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum LockSpec {
    /// The lock holds the extension's result, and every entry of it lists
    /// these files of the workspace as recorded inputs: an edit of one
    /// stales the lock.
    Records {
        extension: String,
        files: Vec<String>,
    },
    /// The lock holds neither an entry nor facts of the extension: no
    /// edit of a file it reads can stale the lock.
    NotRecorded(String),
}

impl LockSpec {
    fn extension(&self) -> &str {
        match self {
            LockSpec::Records { extension, .. } | LockSpec::NotRecorded(extension) => extension,
        }
    }

    /// `Err` says how `lock` differs from the claim. A lock the reader
    /// does not understand proves nothing and is an error too.
    fn check(&self, lock: &ModuleLock) -> Result<(), String> {
        let extensions = lock
            .extensions()
            .ok_or_else(|| format!("the lock cannot be read: {lock:?}"))?;
        let (label, name) = split_extension(self.extension())?;
        let entries = extensions.entries_of(label, name);
        match self {
            LockSpec::Records { extension, files } => {
                if entries.is_empty() {
                    let recorded = recorded_extensions(lock);
                    return Err(format!("no entry of {extension}; recorded: {recorded:?}"));
                }
                for entry in entries {
                    let listed: Vec<&str> = entry.inputs.iter().map(|i| i.path.as_str()).collect();
                    if let Some(file) = files.iter().find(|file| !listed.contains(&file.as_str())) {
                        return Err(format!(
                            "the {} entry of {extension} does not record {file}: {listed:?}",
                            entry.platform
                        ));
                    }
                }
                Ok(())
            }
            LockSpec::NotRecorded(extension) => {
                let facts = extensions.facts_of(label, name);
                if entries.is_empty() && facts.is_empty() {
                    return Ok(());
                }
                Err(format!(
                    "{extension} is recorded: {} entries, {} facts",
                    entries.len(),
                    facts.len()
                ))
            }
        }
    }
}

/// `//pkg:file.bzl%name` as (label, name).
fn split_extension(id: &str) -> Result<(&str, &str), String> {
    let split = id.split_once('%');
    split
        .filter(|(label, name)| label.starts_with("//") && label.contains(':') && !name.is_empty())
        .ok_or_else(|| format!("{id:?} is not `//<package>:<file>%<name>`"))
}

/// The ids of the extensions whose result `lock` holds, as the lock
/// spells them, sorted. Empty for a lock that could not be read.
fn recorded_extensions(lock: &ModuleLock) -> Vec<String> {
    let entries = lock.entries().unwrap_or_default();
    let ids: BTreeSet<String> = entries.iter().map(|entry| entry.id.raw.clone()).collect();
    ids.into_iter().collect()
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

    /// Who fetches a hosted reference: `downloader` or `tool`. A lane's
    /// fake Socket API hands out a loopback origin only where this says
    /// `tool`; a loopback URL must never reach a file Bazel's downloader
    /// reads or records.
    fn hosted_fetch(&self) -> &str {
        self.hosted_fetch.as_deref().unwrap_or(&self.fetch)
    }
}

/// What mounting a fixture's registries yields for the Bazel commands.
#[derive(Default)]
struct Levers {
    /// URLs the downloader must fetch from the fixture server.
    rewrites: Vec<String>,
    repo_env: Vec<(String, String)>,
    /// The URL of every package file the fixture server serves.
    packages: Vec<String>,
    /// The URL of the package file the probe anchors, where the fixture
    /// server serves that file itself (a wheel). The cell must ask for it.
    anchored: Option<String>,
    /// Bazel's downloader fetches the anchored file: a shared repository
    /// cache can answer for it with no request.
    downloader: bool,
}

/// Start the emulations `fixture` names on `server`.
fn mount(fixture: &Fixture, server: &FixtureServer) -> Levers {
    let tree = heavy_root().join("registry");
    let mut levers = Levers::default();
    // Both Python flavours serve the same files under the same routes.
    let wheels = |levers: &mut Levers| {
        let distributions =
            pypi_files::read_tree(&tree.join("pypi")).unwrap_or_else(|why| panic!("{why}"));
        let urls = pypi_files::mount(server, &distributions);
        let anchored = distributions
            .iter()
            .find(|d| d.sha256 == fixture.probe.sha256);
        let anchored = anchored.unwrap_or_else(|| {
            panic!(
                "{}: the probe anchors no wheel of the tree",
                fixture.fixture
            )
        });
        levers.anchored = Some(anchored.url());
        levers.packages.extend(urls.iter().cloned());
        (distributions, urls)
    };
    for registry in &fixture.registries {
        match registry.as_str() {
            "pypi" => {
                let (distributions, urls) = wheels(&mut levers);
                levers.downloader = true;
                levers.rewrites.extend(urls);
                levers
                    .rewrites
                    .extend(pypi_index::mount(server, &distributions));
            }
            "pypi-pip" => {
                let (distributions, _) = wheels(&mut levers);
                let index = pypi_index::mount_pip_mode(server, &distributions);
                // For a fixture that reads the index through `envsubst`.
                levers.repo_env.push(("PIP_INDEX_URL".into(), index));
            }
            "goproxy" => {
                let modules = goproxy::mount(server, &tree.join("goproxy"))
                    .unwrap_or_else(|why| panic!("{why}"));
                levers
                    .packages
                    .extend(modules.into_iter().map(|m| m.zip_url));
                // The fixture's module from the stub; gazelle's own tool
                // modules from the real proxy, which `go` tries after a 404.
                let list = format!("{},https://{}", goproxy::goproxy(server), goproxy::HOST);
                levers.repo_env.push(("GOPROXY".into(), list));
            }
            other => panic!("{}: unknown registry {other:?}", fixture.fixture),
        }
    }
    levers.packages.sort();
    levers.packages.dedup();
    levers
}

/// Where a Bazel repository cache keeps the download with this digest.
fn cache_entry(repository_cache: &Path, sha256: &str) -> PathBuf {
    repository_cache
        .join("content_addressable/sha256")
        .join(sha256)
}

/// One cell's hold on a shared repository cache, from the moment it
/// removed a download from it until its own fetch of that download is
/// done and asserted.
struct ColdFetch {
    /// The lock is the open file: closing it releases the cache.
    _lock: std::fs::File,
}

/// Make this cell fetch the download `sha256` from its origin. A
/// persistent repository cache answers a checksummed download with no
/// request at all, so on a warm cache a baseline would exercise neither
/// the rewrite nor the stub, and a broken one would pass. Every fixture
/// names its packages in a file of its own (a `uv.lock` states the URL of
/// each wheel), so every cell proves its own fetch: none rides on what
/// another one asked for.
///
/// A private cache (one under the cell's scratch root) is empty by
/// construction: `None`, and nothing is touched. On a shared cache the
/// one download is removed and the cache is held until the returned value
/// is dropped: another cell that wants to evict the same download waits
/// here, so it can neither remove the file while this cell's Bazel reads
/// it nor find it put back before it asked. The hold is a file lock
/// beside the cache, so it also covers a second test process on the same
/// cache root. Only a download that every cell fetches while it holds the
/// cache may be evicted: a cell that read it later, outside its hold,
/// would race with the next eviction. (That rules out `spdep`, which the
/// rules_python fixtures fetch only when the consumer is built.)
fn cold_fetch(scratch_root: &Path, repository_cache: &Path, sha256: &str) -> Option<ColdFetch> {
    if repository_cache.starts_with(scratch_root) {
        return None;
    }
    let mut name = repository_cache
        .file_name()
        .expect("a named repository cache")
        .to_os_string();
    name.push(".evict.lock");
    let path = repository_cache.with_file_name(name);
    // Never truncated: another cell may hold the lock on it right now.
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    lock.lock()
        .unwrap_or_else(|e| panic!("lock {}: {e}", path.display()));
    let entry = cache_entry(repository_cache, sha256);
    match std::fs::remove_dir_all(&entry) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("evict {}: {e}", entry.display()),
    }
    Some(ColdFetch { _lock: lock })
}

/// The `hosts` of a report from the fixture server's own list, which
/// takes the first path segment of each request for the host. A request
/// a tool sent straight to the loopback origin has no host segment (pip's
/// index is at `<origin>/pip-mode/simple/`): it was a request to
/// `127.0.0.1`, and is reported as that.
fn reported_hosts(server_hosts: Vec<String>) -> Vec<String> {
    let pip_root = pypi_index::PIP_MODE_PREFIX.split('/').next();
    let host = |host: String| {
        if Some(host.as_str()) == pip_root {
            LOOPBACK.to_string()
        } else {
            host
        }
    };
    let hosts: BTreeSet<String> = server_hosts.into_iter().map(host).collect();
    hosts.into_iter().collect()
}

/// How a report names the fixture server where a tool asked it directly.
const LOOPBACK: &str = "127.0.0.1";

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

/// Why a baseline does not run in the offline phase or in the
/// real-registry cell; `None` in an ordinary cell. Its narrow rewrite
/// leaves every real host reachable, which is what the offline phase
/// forbids, and its packages exist on no real registry. Without this a
/// baseline would run as usual there and leave a `ran` report under the
/// name of the ordinary cell.
fn no_baseline_cell(offline: bool, real_registries: bool) -> Option<&'static str> {
    (offline || real_registries).then_some(
        "a baseline canary fetches its ruleset from the real origins and its packages from \
         the fixture server",
    )
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
    if let Some(why) = no_baseline_cell(env::offline(), env::real_registries()) {
        probe_report::skip_na(&cell.report, why);
        return;
    }
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

    // Where Bazel's downloader fetches the anchored wheel, a shared
    // repository cache must not answer for it. Held until the fetch is
    // asserted; a cell that returns early releases it on the way out.
    let scratch = &cell.scratch;
    let evict = || {
        cold_fetch(
            &scratch.root,
            &scratch.repository_cache,
            &fixture.probe.sha256,
        )
    };
    let cold = levers.downloader.then(evict).flatten();

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
    if let Some(url) = &levers.anchored {
        // The wheel tier 0 just checked came from the fixture server:
        // through the rewrite, or because pip was pointed at the stub.
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
    if !fixture.test_targets.is_empty() {
        // The tests that must be green before socket-patch runs.
        let mut args = vec!["--test_output=errors"];
        args.extend(fixture.test_targets.iter().map(String::as_str));
        cell.bazel_ok("test", &args);
    }
    // The lock as the builds left it. The `mod` oracle below runs with
    // `--lockfile_mode=off` and does not write it.
    let lock = (fixture.system() == System::Bzlmod).then(|| {
        let bytes = cell.module_lock();
        let bytes = bytes.unwrap_or_else(|| panic!("{test}: Bazel wrote no {MODULE_LOCK}"));
        let lock = ModuleLock::parse(&bytes);
        // A lock the reader cannot read would be reported as recording
        // nothing.
        assert!(
            lock.extensions().is_some(),
            "{test}: {MODULE_LOCK} is not a lock the reader knows: {lock:?}"
        );
        lock
    });
    if let Some(claim) = &fixture.lock {
        let lock = lock.as_ref().expect("a lock claim is for a Bzlmod fixture");
        if let Err(why) = claim.check(lock) {
            panic!("{test}: {MODULE_LOCK}: {why}");
        }
    }
    let resolved = resolved(&cell, &fixture);

    let requests = server.requests().len();
    let asked = |url: &String| !server.requests_for(url).is_empty();
    let fetched_cold = levers.packages.iter().any(asked);
    cell.report.hosts = reported_hosts(server.hosts());
    cell.report.direct_network = true;
    cell.report.resolved = resolved;
    cell.report
        .detail("fixture", fixture.fixture.as_str())
        .detail("proof", spec.proof)
        .detail("fetch", fixture.fetch.as_str())
        .detail("hosted_fetch", fixture.hosted_fetch())
        .detail("declared_hosts", fixture.hosts.clone())
        .detail("toolchains", serde_json::to_value(toolchains).unwrap())
        .detail("test_targets", fixture.test_targets.clone())
        .detail("packages_fetched_cold", fetched_cold)
        .detail("fixture_server_requests", requests);
    if let Some(lock) = &lock {
        let facts = lock.facts().unwrap_or_default();
        let facts: BTreeSet<&str> = facts.iter().map(|facts| facts.id.raw.as_str()).collect();
        cell.report
            .detail("lock_file_version", lock.lock_file_version())
            .detail("recorded_extensions", recorded_extensions(lock))
            .detail("lock_facts", serde_json::to_value(facts).unwrap());
    }
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
            let fetcher = |who: &str| matches!(who, "downloader" | "tool");
            assert!(fetcher(&fixture.fetch), "{at}: {name}: fetch");
            assert!(
                fetcher(fixture.hosted_fetch()),
                "{at}: {name}: hosted_fetch"
            );
            // Stated only where it differs: one spelling per fact.
            assert_ne!(
                fixture.hosted_fetch.as_ref(),
                Some(&fixture.fetch),
                "{at}: {name}: hosted_fetch repeats fetch"
            );
            for target in &fixture.test_targets {
                assert!(
                    target.starts_with("//") && target.contains(':'),
                    "{at}: {name}: test target {target:?}"
                );
            }
            // A test target and a lock claim are about what a build does:
            // a cell that stops at the fetch could check neither.
            let builds = fixture.cells.iter().all(|spec| spec.proof >= 1);
            assert!(
                builds || (fixture.test_targets.is_empty() && fixture.lock.is_none()),
                "{at}: {name}: a fetch-only cell beside test_targets or lock"
            );
            if let Some(claim) = &fixture.lock {
                // Under WORKSPACE the lock is Bazel's placeholder.
                assert_eq!(system, System::Bzlmod, "{at}: {name}: lock");
                if let Err(why) = split_extension(claim.extension()) {
                    panic!("{at}: {name}: lock: {why}");
                }
                let files = match claim {
                    LockSpec::Records { files, .. } => files.as_slice(),
                    LockSpec::NotRecorded(_) => &[],
                };
                assert!(
                    files.iter().all(|file| fixture.dir().join(file).is_file()),
                    "{at}: {name}: lock: {files:?}"
                );
                assert_eq!(
                    files.is_empty(),
                    matches!(claim, LockSpec::NotRecorded(_)),
                    "{at}: {name}: a recorded extension names the files it records"
                );
            }
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

/// The Rust target triples of the platforms heavy cells run on: macOS
/// arm64, Linux x86_64 and Windows x86_64 in CI, and the Linux arm64
/// containers of a developer's machine.
const CELL_TRIPLES: &[&str] = &[
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
];

/// Whether a `bazel_dep` is a ruleset, whose version the fixture must pin
/// and the canary must report. `platforms` and the like carry no rules a
/// lane depends on.
fn is_ruleset(module: &str) -> bool {
    module.starts_with("rules_") || matches!(module, "gazelle" | "aspect_rules_py")
}

#[test]
fn heavy_fixtures_follow_the_fixture_conventions() {
    let dep =
        regex::Regex::new(r#"bazel_dep\(\s*name = "([^"]+)",\s*version = "([^"]+)""#).unwrap();
    let pin = regex::Regex::new(
        r#"single_version_override\(\s*module_name = "([^"]+)",\s*version = "([^"]+)""#,
    )
    .unwrap();
    // `use_extension("@<repo>//<label>", "<name>")`, as label and name.
    let extension =
        regex::Regex::new(r#"use_extension\(\s*"@[^/"]*(//[^"]+)",\s*"([^"]+)""#).unwrap();
    let compiled = regex::Regex::new(r#"compile_pip_requirements\(\s*name = "([^"]+)""#).unwrap();
    // Where a committed file points pip: the placeholder origin, then the
    // route of the pip-mode index.
    let pip_index = format!("{ORIGIN_PLACEHOLDER}/{}", pypi_index::PIP_MODE_PREFIX);
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
        // A test target is a rule of the root package, or the `.test` a
        // macro of that name declares (`compile_pip_requirements`).
        for target in &fixture.test_targets {
            let rule = target.strip_prefix("//:").unwrap_or_default();
            let stem = rule.rsplit_once('.').map_or(rule, |(stem, _)| stem);
            let declared = [rule, stem]
                .iter()
                .any(|rule| !rule.is_empty() && build.contains(&format!("name = \"{rule}\"")));
            assert!(declared, "{name}: BUILD.bazel declares no {target}");
        }
        // The lock check of `compile_pip_requirements` is what such a
        // fixture is for: the baseline runs it. It resolves with pip, which
        // no downloader rewrite reaches, so the rule names the pip index.
        for rule in compiled.captures_iter(&build) {
            let check = format!("//:{}.test", &rule[1]);
            assert!(
                fixture.test_targets.contains(&check),
                "{name}: `test_targets` lacks {check}"
            );
            assert!(
                build.contains(&format!("\"--index-url={pip_index}\"")),
                "{name}: compile_pip_requirements without the pip index would ask pypi.org"
            );
        }
        // pip is pointed at the index of the fixture server, or it would
        // look the synthetic packages up on the real one.
        if fixture.registries.iter().any(|r| r == "pypi-pip") {
            let indexed = |rel: &String| text(rel).is_some_and(|file| file.contains(&pip_index));
            assert!(
                fixture.substitute.iter().any(indexed),
                "{name}: no substituted file names {pip_index}"
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
        // Every ruleset the fixture depends on is pinned, not only the one
        // it is named for: Bazel 9.3.2 lifts a bare `rules_python` 1.0.0
        // to 1.7.0, and the canary checks and reports the pins alone.
        for ruleset in deps.keys().filter(|dep| is_ruleset(dep)) {
            assert!(
                fixture.pins.contains_key(ruleset),
                "{name}: bazel_dep {ruleset} has no `pins` entry"
            );
        }
        // rules_rs marks every crate incompatible with a target platform
        // that `platform_triples` does not list: the list covers every
        // platform a heavy cell runs on.
        if module.contains("platform_triples") {
            for triple in CELL_TRIPLES {
                assert!(
                    module.contains(&format!("\"{triple}\"")),
                    "{name}: platform_triples lacks {triple}"
                );
            }
        }
        // A lock claim names an extension the fixture uses.
        if let Some(claim) = &fixture.lock {
            let used: BTreeSet<String> = extension
                .captures_iter(&module)
                .map(|c| format!("{}%{}", &c[1], &c[2]))
                .collect();
            assert!(
                used.contains(claim.extension()),
                "{name}: lock: MODULE.bazel uses {used:?}, not {}",
                claim.extension()
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
    let served: BTreeSet<String> = wheels.iter().map(pypi_files::Distribution::url).collect();
    let digest = regex::Regex::new(r"sha256[:=]([0-9a-f]{64})").unwrap();
    let file_url = regex::Regex::new(&format!(
        r#"https://{}/[^\s"'#]*"#,
        regex::escape(pypi_files::HOST)
    ))
    .unwrap();
    let mut urls = 0;
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
        for (path, bytes) in &tree {
            let text = String::from_utf8_lossy(bytes);
            // A file URL a lock names (a `uv.lock` wheel) is one the
            // fixture server serves and the narrow rewrite lists: any
            // other would be fetched from the real host, or not at all.
            for url in file_url.find_iter(&text) {
                urls += 1;
                assert!(
                    served.contains(url.as_str()),
                    "{}: {path} names {}, which the registry tree does not serve",
                    fixture.fixture,
                    url.as_str()
                );
            }
            if !(path.ends_with(".txt") || path.ends_with(".lock")) {
                continue;
            }
            for hit in digest.captures_iter(&text) {
                assert!(
                    known.contains(&hit[1]),
                    "{}: {path} pins {}, which the registry tree does not serve",
                    fixture.fixture,
                    &hit[1]
                );
            }
        }
    }
    // The uv fixtures do name file URLs: the check above saw them.
    assert!(urls > 0, "no fixture names a {} URL", pypi_files::HOST);
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

#[test]
fn a_cold_fetch_evicts_one_download_of_a_shared_cache_and_holds_the_cache() {
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let scratch = dir.path().join("scratch");
    let private = scratch.join("cache");
    let shared = dir.path().join("shared/repos");
    let (anchored, other) = ("a".repeat(64), "b".repeat(64));
    let put = |cache: &Path, sha256: &str| {
        let entry = cache_entry(cache, sha256);
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("file"), b"wheel").unwrap();
    };
    let cached = |cache: &Path, sha256: &str| cache_entry(cache, sha256).join("file").is_file();
    for cache in [&private, &shared] {
        put(cache, &anchored);
        put(cache, &other);
    }

    // A cache under the scratch root is the cell's own: nothing is
    // removed and nothing is held.
    assert!(cold_fetch(&scratch, &private, &anchored).is_none());
    assert!(cached(&private, &anchored));

    // On a shared cache the one download goes, and no other.
    let first = cold_fetch(&scratch, &shared, &anchored).expect("a hold on the shared cache");
    assert!(!cached(&shared, &anchored) && cached(&shared, &other));
    // Its Bazel fetches the file and stores it again.
    put(&shared, &anchored);

    // A second cell waits for the first: it must not remove the file
    // while the first one's fetch may be reading it.
    let (taken, second) = mpsc::channel();
    let waiter = {
        let (scratch, shared, anchored) = (scratch.clone(), shared.clone(), anchored.clone());
        std::thread::spawn(move || {
            let held = cold_fetch(&scratch, &shared, &anchored);
            taken.send(held.is_some()).unwrap();
        })
    };
    let early = second.recv_timeout(Duration::from_millis(300));
    assert!(early.is_err(), "a second cell took the cache while held");
    assert!(cached(&shared, &anchored));
    drop(first);
    let held = second.recv_timeout(Duration::from_secs(60));
    assert_eq!(held, Ok(true), "the second cell never got the cache");
    waiter.join().unwrap();
    assert!(!cached(&shared, &anchored) && cached(&shared, &other));

    // A download that is not in the cache is nothing to evict.
    assert!(cold_fetch(&scratch, &shared, &anchored).is_some());
}

#[test]
fn a_report_lists_hosts_and_never_a_loopback_route_prefix() {
    use crate::bazel_build_common::registry::pypi_files::fetch;

    let tree = heavy_root().join("registry");
    let wheels = pypi_files::read_tree(&tree.join("pypi")).unwrap();
    let server = FixtureServer::start();
    pypi_files::mount(&server, &wheels);
    let index = pypi_index::mount(&server, &wheels);
    let pip_index = pypi_index::mount_pip_mode(&server, &wheels);
    let modules = goproxy::mount(&server, &tree.join("goproxy")).unwrap();
    // One request per kind of route a heavy baseline mounts: the two
    // index flavours, a wheel as pip is linked to it, a Go module, the
    // checksum database, and a miss.
    let wheel = wheels[0]
        .url()
        .replacen("https://", &format!("{}/", server.loopback_origin()), 1);
    let sumdb = format!(
        "{}/lookup/example.com/upstream@v1.0.0",
        goproxy::sumdb(&server)
    );
    let pip_page = format!("{pip_index}/{}/", wheels[0].project);
    let pip_miss = format!("{pip_index}/requests/");
    for (url, status) in [
        (index[0].as_str(), 200),
        (pip_page.as_str(), 200),
        (pip_miss.as_str(), 404),
        (wheel.as_str(), 200),
        (modules[0].zip_url.as_str(), 200),
        (sumdb.as_str(), 200),
    ] {
        assert_eq!(fetch(&server, url).0, status, "{url}");
    }

    let raw = server.hosts();
    let pip_root = pypi_index::PIP_MODE_PREFIX.split('/').next().unwrap();
    assert!(raw.iter().any(|host| host == pip_root), "{raw:?}");
    let hosts = reported_hosts(raw);
    let real = [
        pypi_index::HOST,
        pypi_files::HOST,
        goproxy::HOST,
        goproxy::SUMDB_HOST,
    ];
    let mut expected: Vec<&str> = real.to_vec();
    expected.push(LOOPBACK);
    expected.sort_unstable();
    assert_eq!(hosts, expected);
    // The mapping is by whole name, and it merges with a loopback host
    // that is already listed.
    assert_eq!(
        reported_hosts(vec![
            LOOPBACK.into(),
            pip_root.into(),
            format!("{pip_root}.example.org")
        ]),
        [LOOPBACK.to_string(), format!("{pip_root}.example.org")]
    );
}

#[test]
fn a_lock_claim_is_read_by_label_and_name_on_every_bazel_line() {
    let sha = "0".repeat(64);
    // What Bazel 7.7.2 writes (lock version 13) and what 8.x and 9.x
    // write (`+` names; version 28 keeps the inputs in one list).
    let v13 = format!(
        r#"{{"lockFileVersion": 13, "registryFileHashes": {{}}, "moduleExtensions": {{
            "@@gazelle~//:extensions.bzl%go_deps": {{"general": {{
                "bzlTransitiveDigest": "d", "usagesDigest": "u",
                "recordedFileInputs": {{"@@//go.mod": "{sha}", "@@//go.sum": "{sha}",
                                        "@@rules_go~//go.mod": "{sha}"}},
                "recordedDirentsInputs": {{}}, "envVariables": {{}},
                "generatedRepoSpecs": {{}}}}}},
            "@@rules_go~//go:extensions.bzl%go_sdk": {{"os:osx,arch:aarch64": {{
                "bzlTransitiveDigest": "d", "usagesDigest": "u",
                "recordedFileInputs": {{}}, "recordedDirentsInputs": {{}},
                "envVariables": {{}}, "generatedRepoSpecs": {{}}}}}}}}}}"#
    );
    let v28 = format!(
        r#"{{"lockFileVersion": 28, "registryFileHashes": {{}}, "moduleExtensions": {{
            "@@gazelle+//:extensions.bzl%go_deps": {{"general": {{
                "bzlTransitiveDigest": "d", "usagesDigest": "u",
                "recordedInputs": ["FILE:@@//go.mod {sha}", "FILE:@@//go.sum {sha}",
                                   "REPO_MAPPING:gazelle+,bazel_tools bazel_tools"],
                "generatedRepoSpecs": {{}}}}}}}},
            "facts": {{"@@rules_python+//python/extensions:pip.bzl%pip": {{"fact_version": "v2"}}}}}}"#
    );
    let records = |files: &[&str]| LockSpec::Records {
        extension: "//:extensions.bzl%go_deps".to_string(),
        files: files.iter().map(|file| file.to_string()).collect(),
    };
    let absent = |extension: &str| LockSpec::NotRecorded(extension.to_string());
    for text in [&v13, &v28] {
        let lock = ModuleLock::parse(text.as_bytes());
        assert!(lock.extensions().is_some(), "{lock:?}");
        records(&["go.mod", "go.sum"]).check(&lock).unwrap();
        // A file of another module is no record of the workspace's file,
        // and a file the extension never read is not recorded.
        let missing = records(&["go.mod", "go.work"]).check(&lock).unwrap_err();
        assert!(missing.contains("does not record go.work"), "{missing}");
        let recorded = absent("//:extensions.bzl%go_deps")
            .check(&lock)
            .unwrap_err();
        assert!(recorded.contains("is recorded: 1 entries"), "{recorded}");
        absent("//crate_universe:extension.bzl%crate")
            .check(&lock)
            .unwrap();
        // The label counts, not the name alone.
        let other = LockSpec::Records {
            extension: "//go:extensions.bzl%go_deps".to_string(),
            files: vec!["go.mod".to_string()],
        };
        assert!(other.check(&lock).unwrap_err().contains("no entry of"));
    }
    let v13_lock = ModuleLock::parse(v13.as_bytes());
    assert_eq!(
        recorded_extensions(&v13_lock),
        [
            "@@gazelle~//:extensions.bzl%go_deps",
            "@@rules_go~//go:extensions.bzl%go_sdk"
        ]
    );
    // Facts alone are a record too.
    let facts = absent("//python/extensions:pip.bzl%pip")
        .check(&ModuleLock::parse(v28.as_bytes()))
        .unwrap_err();
    assert!(facts.contains("0 entries, 1 facts"), "{facts}");
    // A lock that cannot be read proves no claim, in either direction.
    for claim in [records(&["go.mod"]), absent("//:extensions.bzl%go_deps")] {
        let unread = claim.check(&ModuleLock::parse(b"not json")).unwrap_err();
        assert!(unread.contains("cannot be read"), "{unread}");
    }
    assert!(split_extension("go_deps").is_err());
    assert!(split_extension("@gazelle//:extensions.bzl%go_deps").is_err());

    // The two spellings of a claim in a MATRIX.json.
    let parse = |text: &str| serde_json::from_str::<LockSpec>(text);
    let claim = parse(r#"{"records": {"extension": "//:e.bzl%e", "files": ["go.mod"]}}"#);
    assert_eq!(claim.unwrap().extension(), "//:e.bzl%e");
    let claim = parse(r#"{"not_recorded": "//:e.bzl%e"}"#).unwrap();
    assert!(matches!(claim, LockSpec::NotRecorded(_)));
    assert!(parse(r#"{"records": {"extension": "//:e.bzl%e"}}"#).is_err());
    assert!(parse(r#"{"recorded": "//:e.bzl%e"}"#).is_err());
}

#[test]
fn a_baseline_has_no_offline_and_no_real_registry_cell() {
    assert_eq!(no_baseline_cell(false, false), None);
    for (offline, real_registries) in [(true, false), (false, true), (true, true)] {
        let why = no_baseline_cell(offline, real_registries);
        assert!(why.is_some_and(|why| why.contains("fixture server")));
    }
}
