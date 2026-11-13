//! The toy core fixture (`fixtures/bazel/core`): the workspaces every
//! `bazel_core_` test runs in, the packages its registry serves, and the
//! committed files that let a cell on it resolve Bazel's own modules
//! without the network.
//!
//! A workspace with no ruleset still makes Bazel resolve the modules it
//! brings itself and fetch a few of their archives. Both are described
//! under `fixtures/bazel/registry` (see `scripts/bazel-fixture-registry.py`):
//!
//! - the registry files, read through `--registry=file://` on Unix. On
//!   Windows, where no cell has proved the `file://` path syntax, the
//!   fixture server plays `bcr.bazel.build` from the same files.
//! - the archives of a line whose build fetches few (one file of 6 to 8 KB
//!   on 6.6.0, 7.0.2, 7.1.2, 7.7.2 and 9.3.2), committed and passed as
//!   `--distdir`.
//! - for a line whose manifest entry says `"distdir": false`, only the
//!   sha256 of each archive (8.8.2 fetches 12.4 MB under Bzlmod and 12.4 MB
//!   under WORKSPACE, 11.5 MB of that in four archives the Bzlmod build
//!   does not fetch). The cell's repository cache must hold them: see
//!   [`module_archives`].
//!
//! [`gate`] decides from those files alone whether a test runs in a cell.
//! A WORKSPACE cell below Bazel 8 runs with Bzlmod off and needs none of
//! them. Any other cell on a Bazel version the manifest does not list
//! cannot run, which is a failure where the cell is required.
//!
//! Before that, `Cell::open` holds a test of the toy group to its row in
//! the group's `MATRIX.json` ([`unclaimed`]): on a Bazel release the group
//! has a cell for, a test runs only where its row lists the release, and
//! reports `SKIP (n/a)` elsewhere. A prefix run (`--ignored bazel_core_`)
//! therefore leaves a `ran` report for claimed (test, Bazel) pairs only;
//! to run a test on another release, add the release to its row first.
//!
//! No toy fixture has a `MODULE.bazel.lock` at its root: every cell makes
//! its lock in the test. For 6.6.0, 7.0.2 and 7.1.2 that is the only way.
//! Their locks name the registry they were made against
//! (`flags.cmdRegistries`, and under a `file://` registry absolute paths
//! in `repoSpec`), so one made against the Bazel Central Registry fails
//! `--lockfile_mode=error` here (`the value of --registry flag has been
//! modified`, exit 48) and one made here could not be committed. Their
//! manifest entries therefore name no lock (the registry file list comes
//! from a recorded run), and a test that builds on a committed lock is
//! not applicable on them.
//!
//! A toy cell never runs `bazel mod deps`: that command evaluates every
//! extension of Bazel's own modules and fetches their archives (39 MB on
//! 9.3.2), so a test passes `false` to `Cell::baseline` and refreshes a
//! lock with a build.
//!
//! Every toy lock keeps `https://registry.toy.invalid` URLs and a pin
//! points at [`HOSTED_ORIGIN`]: both reach the fixture server through the
//! downloader rewrite, so nothing a test writes carries a loopback URL.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use sha2::{Digest, Sha256};
use socket_patch_core::bazel::java_hash;

use super::env::{self, Group, System, Version};
use super::fixture_server::{FixtureServer, HOSTED_ORIGIN};
use super::invoke::{Bazel, Options, Run};
use super::isolation::{OutsideState, Scratch};
use super::probe_report;
use super::server::{self, Cell};
use super::workspace::{self, fixtures_root};
use crate::common::fs_tree;

/// The host every toy lock fetches from. `.invalid` never resolves, so a
/// fetch that got around the downloader rewrite fails instead of leaving
/// the machine.
pub const REGISTRY: &str = "https://registry.toy.invalid";

/// One package version of the toy registry. Its file is a POSIX shell
/// script that prints [`Package::marker`]; the bytes are committed under
/// `core/payloads/{upstream,patched}`.
#[derive(Clone, Copy, Debug)]
pub struct Package {
    pub name: &'static str,
    pub version: &'static str,
}

/// The package of the hub `toy`, in every fixture.
pub const DEP: Package = Package {
    name: "dep",
    version: "1.0.0",
};
/// The older pin of the hybrid fixture's WORKSPACE lock (`ws/toy.lock.json`).
pub const DEP_WS: Package = Package {
    name: "dep",
    version: "0.9.0",
};
/// The package of the facts hub (`facts/toy.lock.json`, eras 8 and 9).
pub const INDEXED: Package = Package {
    name: "indexed",
    version: "1.0.0",
};

impl Package {
    fn file(&self) -> String {
        format!("{}-{}.sh", self.name, self.version)
    }

    fn payload(&self, kind: &str) -> Vec<u8> {
        let path = fixtures_root()
            .join("core/payloads")
            .join(kind)
            .join(self.file());
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    /// The URL a committed toy lock pins.
    pub fn upstream_url(&self) -> String {
        format!("{REGISTRY}/{}/-/{}", self.name, self.file())
    }

    /// The URL a hosted pin points at, shaped like production's.
    pub fn hosted_url(&self) -> String {
        format!(
            "{HOSTED_ORIGIN}/patch/toy/{}/{}/9c1f4a52-7d3e-4b8a-a6f0-2e5d8c7b1a90/{}",
            self.name,
            self.version,
            self.file()
        )
    }

    pub fn upstream(&self) -> Vec<u8> {
        self.payload("upstream")
    }

    pub fn patched(&self) -> Vec<u8> {
        self.payload("patched")
    }

    /// The line the package prints when run (proof tier 2).
    pub fn marker(&self, patched: bool) -> String {
        let bytes = if patched {
            "PATCHED-BY-SOCKET"
        } else {
            "UPSTREAM"
        };
        format!("toy {} {}: {bytes}", self.name, self.version)
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The derived value of a toy lock: what `toy.bzl` compares `pinsHash`
/// with. Starlark `hash()` is Java's `String.hashCode`, so this is also a
/// check of the product's own implementation against every Bazel a toy
/// cell runs.
pub fn pins_hash(lock: &str) -> i32 {
    let json: serde_json::Value = serde_json::from_str(lock).expect("a toy lock is JSON");
    let packages = json["packages"].as_object().expect("packages");
    let mut pins: Vec<(&String, &str)> = packages
        .iter()
        .map(|(name, package)| (name, package["sha256"].as_str().expect("sha256")))
        .collect();
    pins.sort();
    let lines: String = pins
        .iter()
        .map(|(name, sha256)| format!("{name} {sha256}\n"))
        .collect();
    java_hash::hash_bytes(lines.as_bytes())
}

/// The toy lock `lock` with a hosted pin for `package` applied by hand,
/// as a lane will write one: the URL and the sha256 change in place, the
/// derived `pinsHash` follows, and every other byte stays. Panics when the
/// lock does not hold the package's upstream pin exactly once.
pub fn pin(lock: &str, package: Package) -> String {
    let once = |text: &str, from: &str, to: &str| {
        let found = text.matches(from).count();
        assert_eq!(found, 1, "{from:?} occurs {found} times in:\n{text}");
        text.replace(from, to)
    };
    let derived = |text: &str| format!("\"pinsHash\": {}", pins_hash(text));
    let (upstream, patched) = (package.upstream(), package.patched());
    let pinned = once(lock, &package.upstream_url(), &package.hosted_url());
    let pinned = once(&pinned, &sha256_hex(&upstream), &sha256_hex(&patched));
    once(&pinned, &derived(lock), &derived(&pinned))
}

/// `dir` as the URL `--registry` takes, where that form is known to work:
/// an absolute Unix path of characters a URL needs no escape for.
pub fn file_url(dir: &Path) -> Option<String> {
    let text = dir.to_str()?;
    let plain = |b: u8| b.is_ascii_alphanumeric() || b"/._-+".contains(&b);
    (cfg!(unix) && dir.is_absolute() && text.bytes().all(plain)).then(|| format!("file://{text}"))
}

/// The fixture workspace of a Bazel line: `core/<system>/e<major>`.
pub fn fixture_of(version: &Version, system: System) -> String {
    format!("core/{}/e{}", system.name(), version.major)
}

/// Every `MATRIX.json` of the toy group, by its path under
/// `fixtures/bazel` (with `/`), sorted: `core/MATRIX.json`, and each file
/// of its shape that lists other tests on the toy fixture
/// (`core/guard/MATRIX.json`).
pub fn matrices() -> Vec<(String, serde_json::Value)> {
    fn walk(dir: &Path, rel: &str, found: &mut Vec<(String, serde_json::Value)>) {
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
        for entry in entries {
            let entry = entry.expect("a fixture entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = format!("{rel}/{name}");
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                walk(&entry.path(), &rel, found);
            } else if name == "MATRIX.json" {
                let bytes =
                    std::fs::read(entry.path()).unwrap_or_else(|e| panic!("read {rel}: {e}"));
                let matrix =
                    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{rel}: {e}"));
                found.push((rel, matrix));
            }
        }
    }
    let mut found = Vec::new();
    walk(&fixtures_root().join("core"), "core", &mut found);
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// Why `test` does not run on the Bazel release `version`, going by its
/// row in the toy group's `matrices` ([`matrices`]): `Some` when a matrix
/// lists the test, no row of it names the release, and the group has a
/// cell on the release. Such a test is not applicable there (`SKIP (n/a)`,
/// also where the cell is required): the planner runs a test only where
/// its row claims it, and a prefix run must leave no `ran` report for a
/// pair nobody claims.
///
/// `None` = the claims do not decline the test: its row lists the release,
/// or no toy matrix lists the test (a canary, a test of another group), or
/// no toy matrix has a cell on the release. On such a release there is no
/// claim to hold a test to, and [`gate`] still fails a required cell that
/// cannot run instead of letting it pass having run nothing.
pub fn unclaimed(
    matrices: &[(String, serde_json::Value)],
    test: &str,
    version: &str,
) -> Option<String> {
    let rows: Vec<(&str, Vec<&str>)> = matrices
        .iter()
        .filter_map(|(name, matrix)| {
            let row = matrix["tests"].get(test)?;
            let releases = row["bazel"].as_array().into_iter().flatten();
            Some((name.as_str(), releases.filter_map(|r| r.as_str()).collect()))
        })
        .collect();
    let (name, claimed) = rows.first()?;
    if rows.iter().any(|(_, claimed)| claimed.contains(&version)) {
        return None;
    }
    let has_cell = |matrix: &serde_json::Value| {
        let mut cells = matrix["cells"].as_array().into_iter().flatten();
        cells.any(|cell| cell["bazel"].as_str() == Some(version))
    };
    if !matrices.iter().any(|(_, matrix)| has_cell(matrix)) {
        return None;
    }
    Some(format!(
        "{name} claims {test} on Bazel {} and not on {version}: a test of the toy group runs on \
         a release of its matrices only where its row lists the release",
        claimed.join(", ")
    ))
}

/// What a toy cell takes from the committed registry subset
/// (`fixtures/bazel/registry`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mirror {
    /// Nothing. The cell runs with Bzlmod off on a line below Bazel 8: it
    /// resolves no module and fetches no archive of Bazel's own.
    NotNeeded,
    /// The registry files, and the module archives as a `--distdir`.
    Committed,
    /// The registry files. The module archives are not committed: the
    /// cell's repository cache must hold the ones with these sha256
    /// digests ([`module_archives`]).
    Cached(Vec<String>),
}

/// Whether a toy test runs in a cell, decided from committed files alone
/// ([`gate`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gate {
    Run(Mirror),
    /// The test does not apply to the cell: `SKIP (n/a)`, also where the
    /// cell is required.
    NotApplicable(String),
    /// The cell is one the test is written for, and something it needs is
    /// not committed: `SKIP`, and a failure where the cell is required. A
    /// run that tested nothing must not pass a required cell.
    CannotRun(String),
}

impl Gate {
    /// How a test this gate keeps from running ends. `None` = it runs;
    /// `Ok` = it prints SKIP and writes a `skipped` report; `Err` = the
    /// failure message of a required cell.
    pub fn declined(&self, test: &str, required: bool) -> Option<Result<(), String>> {
        match self {
            Gate::Run(_) => None,
            Gate::NotApplicable(_) => Some(Ok(())),
            Gate::CannotRun(why) => Some(probe_report::may_skip(test, why, required)),
        }
    }
}

/// The gate of a toy test on Bazel `version` and `system`. `manifest` is
/// `registry/MANIFEST.json`, `fixture_present` whether [`fixture_of`]
/// exists, and `zero_network` whether the test claims that nothing leaves
/// the machine ([`open_offline`]).
///
/// Not applicable: the line lacks the dependency system, or the test
/// claims zero network (which it shows by building on the committed lock
/// in `error` mode) on a line that has no committed lock or whose module
/// archives are not committed.
/// Cannot run: there is no fixture for the line's major, or the cell needs
/// the registry mirror and the manifest does not list the version.
///
/// The mirror is asked for by need. A WORKSPACE cell below Bazel 8 needs
/// none (it ran on 7.0.2 and 7.1.2 with `--noenable_bzlmod`, no
/// `--registry` and no archive), so it runs on a version the manifest
/// does not list; on a listed one it is given the mirror all the same,
/// for the one command a test runs under the line's default flags. From
/// Bazel 8 the WORKSPACE suffix itself fetches archives.
pub fn gate(
    version: &Version,
    system: System,
    manifest: &serde_json::Value,
    fixture_present: bool,
    zero_network: bool,
) -> Gate {
    if version.system_flags(system).is_none() {
        let why = format!("Bazel {} has no {} system", version.text, system.name());
        return Gate::NotApplicable(why);
    }
    if !fixture_present {
        let why = format!("there is no fixture {}", fixture_of(version, system));
        return Gate::CannotRun(why);
    }
    let Some(entry) = manifest["versions"].get(&version.text) else {
        if system == System::Workspace && version.major < 8 {
            return Gate::Run(Mirror::NotNeeded);
        }
        let why = format!(
            "Bazel {} is not in fixtures/bazel/registry (scripts/bazel-fixture-registry.py add)",
            version.text
        );
        return Gate::CannotRun(why);
    };
    if zero_network && entry.get("lock").is_none() {
        let why = format!(
            "a Bazel {} lock names the registry it was made against, so none is committed: the \
             cell makes its lock in the test",
            version.text
        );
        return Gate::NotApplicable(why);
    }
    if entry["distdir"] == true {
        return Gate::Run(Mirror::Committed);
    }
    if zero_network {
        let why = format!(
            "the module archives of Bazel {} are not committed",
            version.text
        );
        return Gate::NotApplicable(why);
    }
    Gate::Run(Mirror::Cached(archive_digests(entry, system)))
}

/// The sha256 of every archive a cold build of the `system` fixture
/// fetches, from a manifest entry: `archives` are the module archives of a
/// Bzlmod build, `workspace_archives` what Bazel's own WORKSPACE suffix
/// fetches with Bzlmod off. A hybrid cell reads both files (and its test
/// also builds the tree as WORKSPACE only), so it needs both lists.
pub fn archive_digests(entry: &serde_json::Value, system: System) -> Vec<String> {
    let list = |key: &str| -> Vec<String> {
        let archives = entry[key].as_array().into_iter().flatten();
        archives
            .map(|archive| archive["sha256"].as_str().expect("sha256").to_string())
            .collect()
    };
    let mut digests = match system {
        System::Bzlmod => list("archives"),
        System::Workspace => list("workspace_archives"),
        System::Hybrid => [list("archives"), list("workspace_archives")].concat(),
    };
    digests.sort();
    digests.dedup();
    digests
}

/// Where a `--repository_cache` directory keeps the download with this
/// sha256: the file `file`, and beside it one empty `id-<hash>` marker per
/// canonical id it was fetched under (for the http rules, the URL list).
/// Bazel takes a hit only when the marker of the asking repository is
/// there too, so an entry is copied whole.
fn cache_entry(cache: &Path, sha256: &str) -> PathBuf {
    cache.join("content_addressable/sha256").join(sha256)
}

/// The digests of `digests` that `cache` does not hold. Held means the
/// file is there; the markers are not compared, because their names are
/// not committed. An entry that only another repository's fetch left (the
/// same archive under other URLs) therefore counts, and the cell's build
/// then asks the fixture server for the archive and fails on its 404,
/// naming it. [`seed_cache`] completes such an entry whenever the archives
/// are fetched or copied.
pub fn cache_lacks(cache: &Path, digests: &[String]) -> Vec<String> {
    let held = |digest: &&String| cache_entry(cache, digest).join("file").is_file();
    digests.iter().filter(|d| !held(d)).cloned().collect()
}

/// Copy the entries of `digests` from the repository cache `from` into
/// `to`, and nothing else `from` holds. What `to` already has of an entry
/// stays, and what it lacks is added: the file, or only a marker. Each
/// file arrives under a temporary name and is renamed, so a cell that
/// reads `to` at the same time never sees half of one.
pub fn seed_cache(from: &Path, to: &Path, digests: &[String]) {
    static COPIES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for digest in digests {
        let (source, dest) = (cache_entry(from, digest), cache_entry(to, digest));
        std::fs::create_dir_all(&dest).unwrap_or_else(|e| panic!("create {}: {e}", dest.display()));
        let entries = std::fs::read_dir(&source)
            .unwrap_or_else(|e| panic!("read the cache entry {}: {e}", source.display()));
        let mut names: Vec<_> = entries
            .map(|e| e.expect("cache entry").file_name())
            .collect();
        // The markers first: once `file` is there the entry counts as held.
        names.sort_by_key(|name| name == "file");
        for name in names {
            if dest.join(&name).exists() {
                continue;
            }
            let copy = COPIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let staged = dest.join(format!(".seed-{}-{copy}", std::process::id()));
            std::fs::copy(source.join(&name), &staged)
                .unwrap_or_else(|e| panic!("copy {}: {e}", source.join(&name).display()));
            std::fs::rename(&staged, dest.join(&name))
                .unwrap_or_else(|e| panic!("place {}: {e}", dest.join(&name).display()));
        }
    }
}

/// The sha256 of every committed toy package file, upstream and patched.
pub fn payload_digests() -> Vec<String> {
    let mut digests = Vec::new();
    for kind in ["upstream", "patched"] {
        let dir = fixtures_root().join("core/payloads").join(kind);
        for entry in std::fs::read_dir(&dir).expect("read the toy payloads") {
            let bytes = std::fs::read(entry.expect("payload").path()).expect("read a toy payload");
            digests.push(sha256_hex(&bytes));
        }
    }
    digests.sort();
    digests
}

/// A cell on a toy workspace, with the fixture server that plays the toy
/// registry and the Socket host.
pub struct Toy {
    pub cell: Cell,
    pub server: FixtureServer,
    outside: OutsideState,
}

/// Open a cell on `core/<system>/e<major>` with every upstream package
/// served. `cold` = an empty repository cache, for a twin. `None` = the
/// test does not run here; the reason is printed and reported ([`gate`]
/// says which reasons fail a required cell).
///
/// The cell is returned in the same state on every line: the fixture and
/// the probe rule copied in and nothing else. No Bazel command has run in
/// it, so there is no server, no output base, no `MODULE.bazel.lock` and
/// no convenience link, and the fixture server's log is empty. A cold
/// cell's repository cache holds no toy package, and nothing at all but
/// the module archives of a line that does not commit them.
pub fn open(test: &str, system: System, cold: bool) -> Option<Toy> {
    open_with(test, system, cold, false)
}

/// [`open`] on an empty repository cache with the proxies of every Bazel
/// command at a closed port: for a test that claims zero network. Not
/// applicable on a line that has no committed lock or whose module
/// archives are not committed.
pub fn open_offline(test: &str, system: System) -> Option<Toy> {
    open_with(test, system, true, true)
}

fn open_with(test: &str, system: System, cold: bool, zero_network: bool) -> Option<Toy> {
    let outside = OutsideState::capture();
    let opened = if cold {
        Cell::open_cold(test, Group::Core, Some(system))
    } else {
        Cell::open(test, Group::Core, Some(system))
    };
    let mut cell = opened?;
    let version = cell.bazel.version.clone();
    let fixture = fixture_of(&version, system);
    let registry = fixtures_root().join("registry");
    let manifest = std::fs::read(registry.join("MANIFEST.json")).expect("read MANIFEST.json");
    let manifest: serde_json::Value = serde_json::from_slice(&manifest).expect("MANIFEST.json");
    let present = fixtures_root().join(&fixture).is_dir();
    let mirror = match gate(&version, system, &manifest, present, zero_network) {
        Gate::Run(mirror) => mirror,
        Gate::NotApplicable(why) => {
            probe_report::skip_na(&cell.report, &why);
            return None;
        }
        Gate::CannotRun(why) => {
            probe_report::skip(&cell.report, &why);
            return None;
        }
    };
    cell.copy_fixture(&fixture);
    let server = FixtureServer::start();
    for package in [DEP, DEP_WS, INDEXED] {
        server.serve(&package.upstream_url(), package.upstream());
    }
    cell.use_fixture_server(&server);
    cell.options.closed_proxies |= zero_network;

    if mirror == Mirror::NotNeeded {
        cell.report.detail("registry", "not needed");
        cell.report.detail("module_archives", "not needed");
    } else {
        match file_url(&registry) {
            Some(url) => cell.options.registry = Some(url),
            None => serve_registry(&server, &registry),
        }
        let registry_read = if cell.options.registry.is_some() {
            "file"
        } else {
            "served"
        };
        cell.report.detail("registry", registry_read);
    }
    match mirror {
        Mirror::NotNeeded => {}
        Mirror::Committed => {
            cell.options.distdir = Some(registry.join("distdir").join(&version.text));
            cell.report.detail("module_archives", "committed");
        }
        Mirror::Cached(digests) => {
            if !module_archives(&mut cell, &fixture, &digests) {
                return None;
            }
        }
    }
    if cold {
        // Every package a cold cell builds is then a request in the log.
        let cache = &cell.scratch.repository_cache;
        let held: Vec<String> = payload_digests()
            .into_iter()
            .filter(|digest| cache_entry(cache, digest).exists())
            .collect();
        assert!(
            held.is_empty(),
            "{test}: a cold cell holds toy packages: {held:?}"
        );
    }
    Some(Toy {
        cell,
        server,
        outside,
    })
}

/// Play `bcr.bazel.build` from the committed registry files.
fn serve_registry(server: &FixtureServer, registry: &Path) {
    fn walk(server: &FixtureServer, dir: &Path, url: &str) {
        for entry in std::fs::read_dir(dir).expect("read the committed registry") {
            let entry = entry.expect("registry entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            let url = format!("{url}/{name}");
            if entry.path().is_dir() {
                walk(server, &entry.path(), &url);
            } else {
                server.serve(
                    &url,
                    std::fs::read(entry.path()).expect("read a registry file"),
                );
            }
        }
    }
    const HOST: &str = "https://bcr.bazel.build";
    let index = registry.join("bazel_registry.json");
    server.serve(
        &format!("{HOST}/bazel_registry.json"),
        std::fs::read(index).expect("read bazel_registry.json"),
    );
    walk(
        server,
        &registry.join("modules"),
        &format!("{HOST}/modules"),
    );
}

/// One fetch at a time into the shared repository cache: of two cells that
/// find it without the archives at once, the second waits and then finds
/// them there.
static FETCHING: Mutex<()> = Mutex::new(());

/// Give the cell's repository cache the module archives of a line that
/// does not commit them (`digests`, from the manifest), without running
/// anything in the cell itself. In order:
///
/// 1. The cell's cache already holds them (a warm cell on a restored
///    [`env::CACHE_ROOT`]): nothing to do.
/// 2. The shared cache under [`env::CACHE_ROOT`] holds them and the cell's
///    own is another directory (a cold cell): those entries are copied,
///    and no other, so the cold cell still holds no package.
/// 3. Neither does, and this is not the offline phase:
///    [`fetch_module_archives`] downloads them in a throwaway workspace,
///    they are copied from its cache into the shared one and the cell's,
///    and the report says `direct_network`.
///
/// Only case 3 leaves the machine. `false` = the test cannot run (the
/// offline phase without the archives, or an unreachable host): reported
/// with [`probe_report::skip`], a failure where the cell is required.
fn module_archives(cell: &mut Cell, fixture: &str, digests: &[String]) -> bool {
    let own = cell.scratch.repository_cache.clone();
    let shared = env::var(env::CACHE_ROOT).map(|root| PathBuf::from(root).join("repos"));
    let mut one_at_a_time = None;
    // Asked twice where the cache is shared: before waiting for another
    // cell's fetch, and after it, when that fetch may have filled it.
    for waited in [false, true] {
        if cache_lacks(&own, digests).is_empty() {
            cell.report.detail("module_archives", "repository cache");
            return true;
        }
        if waited || shared.is_none() {
            break;
        }
        one_at_a_time = Some(FETCHING.lock().unwrap_or_else(PoisonError::into_inner));
    }
    let warm = |shared: &&PathBuf| cache_lacks(shared, digests).is_empty();
    if let Some(shared) = shared.as_ref().filter(warm) {
        seed_cache(shared, &own, digests);
        cell.report
            .detail("module_archives", "seeded from the repository cache");
        return true;
    }
    if env::offline() {
        let why = format!(
            "the offline phase fetches nothing, and the module archives of Bazel {} are in no \
             repository cache (restore one under {})",
            cell.bazel.version.text,
            env::CACHE_ROOT
        );
        probe_report::skip(&cell.report, &why);
        return false;
    }
    let fetched = match fetch_module_archives(cell, fixture, digests) {
        Ok(fetched) => fetched,
        Err(why) => {
            probe_report::skip(&cell.report, &why);
            return false;
        }
    };
    for cache in shared.iter().chain([&own]) {
        seed_cache(&fetched.scratch.repository_cache, cache, digests);
    }
    // The throwaway root goes before the test's first command.
    drop(fetched);
    drop(one_at_a_time);
    cell.report.direct_network = true;
    cell.report.detail("module_archives", "fetched");
    true
}

/// A second scratch root for one helper build, with the guard a [`Cell`]
/// has: the server it started is shut down before the root is removed,
/// also when the build's own assertion fails.
struct Throwaway<'a> {
    bazel: &'a Bazel,
    scratch: Scratch,
}

impl Drop for Throwaway<'_> {
    fn drop(&mut self) {
        if let Err(why) = server::stop_server(self.bazel, &self.scratch) {
            eprintln!("leaving a Bazel server behind: {why}");
        }
    }
}

/// Download the module archives of the cell's line: one `build //...` of
/// `fixture` with the downloader config off, in a workspace copy, output
/// base and (empty) repository cache of its own, so that the test's cell
/// stays as [`open`] describes it. The toy packages come from the
/// committed payloads through `--distdir`; they land in the throwaway
/// cache and stay there. The server is shut down before this returns: the
/// test still runs one server at a time.
///
/// `Err` = a host was unreachable. A cold build that did not fetch every
/// archive of `digests` means the manifest is out of date, which fails.
fn fetch_module_archives<'a>(
    cell: &'a Cell,
    fixture: &str,
    digests: &[String],
) -> Result<Throwaway<'a>, String> {
    let fetch = Throwaway {
        bazel: &cell.bazel,
        scratch: Scratch::cold(),
    };
    let scratch = &fetch.scratch;
    scratch.assert_path_supported(&cell.bazel.version);
    fs_tree::copy_tree(&fixtures_root().join(fixture), &scratch.workspace);
    if let Err(why) = workspace::install_probe_rule(&scratch.workspace) {
        panic!("{}: {why}", cell.test);
    }
    let direct = Options {
        downloader_config: None,
        closed_proxies: false,
        distdir: Some(fixtures_root().join("core/payloads/upstream")),
        ..cell.options.clone()
    };
    let flags = direct
        .args(&cell.bazel, scratch)
        .unwrap_or_else(|why| panic!("{}: {why}", cell.test));
    let mut build = cell.bazel.command(scratch, "build");
    build.args(flags).arg("//...");
    direct.apply_env(&mut build);
    let run = Run::of(build);
    if run.origin_unreachable() {
        return Err(format!(
            "a module archive host is unreachable:\n{}",
            run.stderr()
        ));
    }
    assert!(run.ok(), "{}: {}", cell.test, run.dump());
    if let Err(why) = server::stop_server(&cell.bazel, scratch) {
        panic!("{}: {why}", cell.test);
    }
    let missing = cache_lacks(&scratch.repository_cache, digests);
    assert!(
        missing.is_empty(),
        "{}: registry/MANIFEST.json lists archives a cold build of {fixture} on Bazel {} did not \
         fetch: {missing:?} (scripts/bazel-fixture-registry.py add)",
        cell.test,
        cell.bazel.version.text
    );
    Ok(fetch)
}

impl Toy {
    /// The text of a workspace file.
    pub fn read(&self, rel: &str) -> String {
        let path = self.cell.scratch.workspace.join(rel);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    /// Hand-apply the hosted pin of `package` to the toy lock `lock` and
    /// serve `served` (the patched bytes, or a twin's) at the pinned URL.
    pub fn pin(&self, lock: &str, package: Package, served: Vec<u8>) {
        self.server.serve(&package.hosted_url(), served);
        self.cell.write(lock, pin(&self.read(lock), package));
    }

    /// End the test: the server log becomes the report's hosts, the cell
    /// is closed, nothing outside the scratch root was written, and the
    /// report is written with status `ran`.
    pub fn finish(mut self) {
        self.cell.report.hosts_from_log(&self.server);
        let report = self.cell.close();
        self.outside.assert_untouched("after the cell closed");
        report.ran();
    }
}
