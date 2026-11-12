//! The toy core fixture (`fixtures/bazel/core`): the workspaces every
//! `bazel_core_` test runs in, the packages its registry serves, and the
//! committed files that let a cell on it resolve Bazel's own modules
//! without the network.
//!
//! A workspace with no ruleset still makes Bazel resolve the modules it
//! brings itself and fetch a few of their archives. Both are committed
//! under `fixtures/bazel/registry` (see `scripts/bazel-fixture-registry.py`):
//!
//! - the registry files, read through `--registry=file://` on Unix. On
//!   Windows, where no cell has proved the `file://` path syntax, the
//!   fixture server plays `bcr.bazel.build` from the same files.
//! - the archives of a line whose build fetches few (7.7.2 and 9.3.2: one
//!   file of 8 KB), passed as `--distdir`. A line whose manifest entry
//!   says `"distdir": false` (8.8.2 fetches 12.4 MB) fetches them from
//!   their real hosts into the cell's repository cache before the
//!   downloader config is switched on, and its report says
//!   `direct_network`. In the offline phase (`SOCKET_PATCH_BAZEL_E2E_OFFLINE`)
//!   it fetches nothing and builds from the restored repository cache.
//!
//! Two limits follow. A toy cell never runs `bazel mod deps`: that command
//! evaluates every extension of Bazel's own modules and fetches their
//! archives (39 MB on 9.3.2), so a test passes `false` to `Cell::baseline`
//! and refreshes a lock with a build. And a Bazel version the registry
//! manifest does not list is skipped: 7.0.2, 7.1.2 and 6.6.0 write locks
//! without `registryFileHashes`, so their module list has to come from a
//! recorded run before `bazel-fixture-registry.py` can add them.
//!
//! Every toy lock keeps `https://registry.toy.invalid` URLs and a pin
//! points at [`HOSTED_ORIGIN`]: both reach the fixture server through the
//! downloader rewrite, so nothing a test writes carries a loopback URL.

use std::path::Path;

use sha2::{Digest, Sha256};
use socket_patch_core::bazel::java_hash;

use super::env::{self, Group, System};
use super::fixture_server::{FixtureServer, HOSTED_ORIGIN};
use super::invoke::Options;
use super::isolation::OutsideState;
use super::probe_report;
use super::server::Cell;
use super::workspace::fixtures_root;

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

/// A cell on a toy workspace, with the fixture server that plays the toy
/// registry and the Socket host.
pub struct Toy {
    pub cell: Cell,
    pub server: FixtureServer,
    outside: OutsideState,
}

/// Open a cell on `core/<system>/e<major>` with every upstream package
/// served. `cold` = an empty repository cache, for a twin. `None` = the
/// test does not run here; the reason is printed and reported.
pub fn open(test: &str, system: System, cold: bool) -> Option<Toy> {
    open_with(test, system, cold, false)
}

/// [`open`] on an empty repository cache with the proxies of every Bazel
/// command at a closed port: for a test that claims zero network. Skipped
/// on a line whose module archives are not committed.
pub fn open_offline(test: &str, system: System) -> Option<Toy> {
    open_with(test, system, true, true)
}

fn open_with(test: &str, system: System, cold: bool, offline: bool) -> Option<Toy> {
    let outside = OutsideState::capture();
    let opened = if cold {
        Cell::open_cold(test, Group::Core, Some(system))
    } else {
        Cell::open(test, Group::Core, Some(system))
    };
    let mut cell = opened?;
    let version = cell.bazel.version.clone();
    let fixture = format!("core/{}/e{}", system.name(), version.major);
    if !fixtures_root().join(&fixture).is_dir() {
        probe_report::skip_na(&cell.report, &format!("there is no fixture {fixture}"));
        return None;
    }
    cell.copy_fixture(&fixture);
    let server = FixtureServer::start();
    for package in [DEP, DEP_WS, INDEXED] {
        server.serve(&package.upstream_url(), package.upstream());
    }
    cell.use_fixture_server(&server);
    cell.options.closed_proxies |= offline;

    // The committed registry holds the modules of the Bazel versions its
    // manifest lists, and of no other: a line outside it would fail on the
    // first module the mirror lacks.
    let registry = fixtures_root().join("registry");
    let manifest = std::fs::read(registry.join("MANIFEST.json")).expect("read MANIFEST.json");
    let manifest: serde_json::Value = serde_json::from_slice(&manifest).expect("MANIFEST.json");
    let Some(entry) = manifest["versions"].get(&version.text) else {
        let why = format!(
            "Bazel {} is not in fixtures/bazel/registry (scripts/bazel-fixture-registry.py add)",
            version.text
        );
        probe_report::skip_na(&cell.report, &why);
        return None;
    };
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

    if entry["distdir"] == true {
        cell.options.distdir = Some(registry.join("distdir").join(&version.text));
        cell.report.detail("module_archives", "committed");
    } else if offline {
        let why = format!(
            "the module archives of Bazel {} are not committed",
            version.text
        );
        probe_report::skip_na(&cell.report, &why);
        return None;
    } else if env::offline() && cold {
        let why = "the offline phase fetches no module archives for an empty repository cache";
        probe_report::skip_na(&cell.report, why);
        return None;
    } else if env::offline() {
        // The offline phase never leaves the machine: the archives are in
        // the restored repository cache, or the first build fails on a 404.
        cell.report.detail("module_archives", "repository cache");
    } else if !fetch_module_archives(&mut cell) {
        return None;
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

/// A line with no committed archives: build the fixture once with the
/// downloader config off, so Bazel fetches the archives of its own modules
/// from their hosts into the cell's repository cache (a hit there when a
/// restored cache holds them). The toy packages come from the committed
/// payloads through `--distdir`, so the fixture server sees no request.
/// `false` = an origin was unreachable and the test was skipped.
fn fetch_module_archives(cell: &mut Cell) -> bool {
    let direct = Options {
        downloader_config: None,
        closed_proxies: false,
        distdir: Some(fixtures_root().join("core/payloads/upstream")),
        ..cell.options.clone()
    };
    let run = cell.bazel_with(&direct, "build", &["//..."]);
    if run.origin_unreachable() {
        let why = format!("a module archive host is unreachable:\n{}", run.stderr());
        probe_report::skip(&cell.report, &why);
        return false;
    }
    assert!(run.ok(), "{}: {}", cell.test, run.dump());
    cell.report.direct_network = true;
    cell.report.detail("module_archives", "fetched");
    true
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
        self.cell.report.hosts = self.server.hosts();
        let report = self.cell.close();
        self.outside.assert_untouched("after the cell closed");
        report.ran();
    }
}
