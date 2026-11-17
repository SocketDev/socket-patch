//! Hosted and vendored mode for an npm package that aspect_rules_js links
//! from a pnpm lock: `npm.npm_translate_lock(pnpm_lock = "//:pnpm-lock.yaml")`
//! under Bzlmod, with a lock of `lockfileVersion: '9.0'`.
//!
//! rules_js reads the lock itself. Every entry of `packages:` becomes one
//! repository, which Bazel's downloader fetches from the entry's `tarball`
//! (the registry's URL for the name and version when it has none, a path
//! beside the lock for a `file:` value) and holds to its `integrity`. No
//! pnpm runs, no `node_modules` of the checkout is read, and the machine
//! needs no Node: the ruleset downloads the one that runs the consumer.
//!
//! Two flows, one test each, on the Bazel the run is given ([`FIXTURE`]
//! says which ruleset goes with its release), each in a fresh output base:
//!
//! - (a) `bazel build` and `bazel run //:consumer` print the unpatched
//!   marker.
//! - (b) The one command of the mode writes its files and no other.
//!   `scan --mode hosted --yes` gives the package's entry of
//!   `pnpm-lock.yaml` the integrity of the patched tarball and its URL on
//!   the patch host, and creates `pnpm-workspace.yaml` with the
//!   `trustLockfile: true` that pnpm 11 and later ask for.
//!   `scan --mode vendored --yes` downloads the patched tarball to
//!   `.socket/vendor/npm/<uuid>/`, records it in the ledger
//!   `.socket/vendor/state.json`, and points the lock's entry and a pnpm
//!   override (in `package.json` and in a new `pnpm-workspace.yaml`) at the
//!   tarball.
//! - (c) The same two Bazel commands, with no step in between, print the
//!   patched marker; Bazel changed no file of the checkout, and a
//!   `--lockfile_mode=error` build passes. Hosted: Bazel fetched the
//!   tarball from the stand-in patch host. Vendored: the scan did, and
//!   Bazel read the committed file without a request to the stand-in.
//! - (d) The undo (`rollback --yes`, or `vendor --revert`): every file of
//!   the checkout is the one of before, byte for byte, and the build prints
//!   the unpatched marker again.
//! - (e) On a second machine (a new output base and, on Bazel 9, a new
//!   contents cache) the command runs against a second patch, whose tarball
//!   no cache can hold, and the pinned place holds other bytes: the patch
//!   host serves them (hosted), or they replace the committed file
//!   (vendored). The build fails on the checksum and does not take the
//!   registry's tarball in its place.
//!
//! What the checksum guards is a fetch, and an output base fetches a
//! repository once. The vendored flow holds that too, between (c) and (d):
//! with other bytes in the committed file, the output base that has fetched
//! it goes on building the patched tarball, with no error.
//!
//! The marker is read from what Bazel built, and the patched one holds an
//! id made for the run, so no cache of an earlier run can supply it.
//!
//! One loopback server per checkout (the second machine of (e) has its own)
//! stands in for three hosts, by route prefix: the Socket API (`/v0`), the
//! patch host (`/patch`) and `registry.npmjs.org` (the upstream tarball, and
//! the version document `rollback` reads through `SOCKET_NPM_REGISTRY`). The
//! package is the tests' own and no registry holds it. Its lock entry names
//! no URL, as pnpm writes one, so rules_js asks for it at the public
//! registry's URL; a downloader config in the checkout rewrites that URL to
//! the stand-in ([`route_registry`]), as a user behind a registry mirror has
//! it. The lock pins the sha512 of the tarball built here, so those bytes
//! come from a stand-in: this run's, or an earlier run's through the
//! repository cache the tests of a leg share, which is why no test counts
//! the requests for the upstream tarball in (a). It is also why a rewrite
//! that stopped applying would show on an empty cache only: Bazel then asks
//! the public registry for the name, and (a) fails on the answer or on the
//! lock's sha512.

use std::time::Instant;

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::envelope::event_for;
use crate::harness::{changed, fixture_path, Cell, Fixture, Ran, Run, Tree, CONSUMER};
use crate::hosted_memory_common::{self, mount_api, ORG};

/// The workspace the tests build, and the ruleset each Bazel release builds
/// it with.
const FIXTURE: Fixture = Fixture {
    name: "npm::FIXTURE",
    dir: "rules_js/bzlmod",
    eras: &[
        // aspect_rules_js 3.6.0, which asks for Bazel 7.6.0 or later.
        ((7, 6, 0)..(10, 0, 0), "e9"),
    ],
};

/// The package the fixture depends on, at the version its lock pins.
const NAME: &str = "fixture-upstream";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:npm/fixture-upstream@1.0.0";
/// The file name of its tarball: on the registry, on the patch host and
/// under `.socket/vendor`.
const TGZ: &str = "fixture-upstream-1.0.0.tgz";
/// Its two files. The fixture's lock holds the sha512 of the tarball of
/// these bytes ([`tarball`]).
const MANIFEST: &str =
    "{\"name\": \"fixture-upstream\", \"version\": \"1.0.0\", \"main\": \"index.js\"}\n";
const UPSTREAM_INDEX: &str = "module.exports = \"PRISTINE\";\n";
const UNPATCHED: &str = "OUT: PRISTINE";
/// The entry file of the other bytes a build finds at the pinned place.
const TAMPERED_INDEX: &str = "module.exports = \"TAMPERED\";\n";
/// The route prefix under which the stand-in plays the npm registry, and
/// the route of the upstream tarball there.
const REGISTRY: &str = "registry.npmjs.org";
const UPSTREAM_TGZ: &str = "/registry.npmjs.org/fixture-upstream/-/fixture-upstream-1.0.0.tgz";
/// The access-token level of a hosted tarball's URL, which `socket-patch`
/// writes as the API hands it out.
const TOKEN: &str = "22222222-2222-4222-8222-222222222222";
/// The `pnpm-workspace.yaml` hosted mode creates beside a 9.0 lock: the
/// root as the one package, and the setting without which pnpm 11 and later
/// reject a lock whose tarball URL is not the registry's.
const TRUSTING_WORKSPACE: &str = "packages:\n  - '.'\ntrustLockfile: true\n";
/// What [`changed`] gives for two equal trees.
const NOTHING: [&str; 0] = [];

/// The package with `index_js` as its entry file, as a registry tarball.
/// The gzip layer stores the archive without compressing it and no header
/// holds a time or an owner, so the bytes follow from the two files alone:
/// the fixture's lock pins the upstream tarball built here, and no binary
/// is committed.
fn tarball(index_js: &str) -> Vec<u8> {
    let stored = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none());
    let mut archive = tar::Builder::new(stored);
    for (name, text) in [
        ("package/package.json", MANIFEST),
        ("package/index.js", index_js),
    ] {
        let mut header = tar::Header::new_ustar();
        header.set_size(text.len() as u64);
        header.set_mode(0o644);
        archive
            .append_data(&mut header, name, text.as_bytes())
            .expect("tar");
    }
    let stored = archive.into_inner().expect("tar");
    stored.finish().expect("gzip")
}

/// The `integrity` of a tarball, as a pnpm lock and Bazel spell it.
fn integrity(tarball: &[u8]) -> String {
    let digest = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(tarball));
    format!("sha512-{digest}")
}

/// One patch of the package. Its id and its entry file are new for every
/// run, so no cache holds its tarball.
struct Patched {
    uuid: String,
    index_js: String,
    tarball: Vec<u8>,
    /// What the consumer prints once the tarball is built in.
    marker: String,
    /// The route of the tarball on the patch host.
    route: String,
}

impl Patched {
    fn new() -> Patched {
        let uuid = uuid::Uuid::new_v4().to_string();
        let index_js = format!("module.exports = \"PATCHED {uuid}\";\n");
        Patched {
            tarball: tarball(&index_js),
            marker: format!("OUT: PATCHED {uuid}"),
            route: format!("/patch/npm/{NAME}/{VERSION}/{TOKEN}/{uuid}/{TGZ}"),
            index_js,
            uuid,
        }
    }
}

/// The loopback server behind every host of one checkout.
struct StandIn {
    // Dropped before the runtime it runs on.
    server: MockServer,
    runtime: tokio::runtime::Runtime,
}

impl StandIn {
    /// A server that holds the upstream package as the registry does: the
    /// tarball, and the version document with its integrity and the URL the
    /// public registry would have it at.
    fn start() -> StandIn {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime for the stand-in");
        let server = runtime.block_on(MockServer::start());
        let standin = StandIn { server, runtime };
        let upstream = tarball(UPSTREAM_INDEX);
        let document = json!({
            "name": NAME,
            "version": VERSION,
            "dist": {
                "tarball": format!("https://{REGISTRY}/{NAME}/-/{TGZ}"),
                "integrity": integrity(&upstream),
            },
        });
        let document_route = format!("/{REGISTRY}/{NAME}/{VERSION}");
        let ok = || ResponseTemplate::new(200);
        standin.serve(&document_route, ok().set_body_json(document));
        standin.serve(UPSTREAM_TGZ, ok().set_body_bytes(upstream));
        standin
    }

    /// `http://127.0.0.1:<port>`.
    fn origin(&self) -> String {
        self.server.uri()
    }

    /// Answer `GET <route>` with `response`, ahead of the routes
    /// [`mount_api`] mounts: wiremock asks the mocks of the lowest priority
    /// number first. Any other route is a 404.
    fn serve(&self, route: &str, response: ResponseTemplate) {
        let mock = Mock::given(method("GET"))
            .and(path(route))
            .respond_with(response)
            .with_priority(1);
        self.runtime.block_on(mock.mount(&self.server));
    }

    /// The Socket API for `patch`, free for every caller, and the patch
    /// host with `served` at the URL the API hands out for its tarball. The
    /// API names the sha512 of the patch's own tarball, whatever is served.
    fn grant(&self, patch: &Patched, served: &[u8]) {
        let url = format!("{}{}", self.origin(), patch.route);
        let reference = json!({
            "status": "granted",
            "url": url,
            "purl": PURL,
            "artifacts": [{
                "kind": "tarball",
                "url": url,
                "integrity": { "sha512": integrity(&patch.tarball) },
            }],
            "registryOverride": null,
        });
        let granted = hosted_memory_common::Patch {
            purl: PURL.to_string(),
            uuid: patch.uuid.clone(),
            reference,
        };
        self.runtime.block_on(mount_api(&self.server, &[granted]));
        // The patch record, in place of the one `mount_api` serves: vendored
        // mode holds the entry file of the tarball it downloads to
        // `afterHash`.
        let record = json!({
            "uuid": patch.uuid,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": { "package/index.js": {
                "beforeHash": compute_git_sha256_from_bytes(UPSTREAM_INDEX.as_bytes()),
                "afterHash": compute_git_sha256_from_bytes(patch.index_js.as_bytes()),
            }},
            "vulnerabilities": { "GHSA-test-aaaa-bbbb": {
                "cves": ["CVE-2024-0001"], "summary": "s", "severity": "high", "description": "d",
            }},
            "description": "fixture",
            "license": "MIT",
            "tier": "free",
        });
        let record_route = format!("/v0/orgs/{ORG}/patches/view/{}", patch.uuid);
        let ok = || ResponseTemplate::new(200);
        self.serve(&record_route, ok().set_body_json(record));
        self.serve(&patch.route, ok().set_body_bytes(served));
    }

    /// The path of every request the server has received.
    fn requests(&self) -> Vec<String> {
        let received = self.runtime.block_on(self.server.received_requests());
        let received = received.expect("wiremock records requests");
        received.iter().map(|r| r.url.path().to_string()).collect()
    }

    /// How many requests for `route` the server has received.
    fn asked(&self, route: &str) -> usize {
        self.requests().iter().filter(|path| *path == route).count()
    }
}

/// The option that names a downloader config on `release`: Bazel 8.2.0
/// dropped the `experimental_` it had until then.
fn downloader_option(release: &str) -> &'static str {
    let mut numbers = release.split('.').map(|part| part.parse::<u32>().ok());
    let line = (numbers.next().flatten(), numbers.next().flatten());
    if line >= (Some(8), Some(2)) {
        "downloader_config"
    } else {
        "experimental_downloader_config"
    }
}

/// Send Bazel's downloader to `standin` for the registry's files of the
/// package: a `.bazelrc` of the checkout names a downloader config with the
/// one rewrite. Every other URL stays as it is, the patch host's included,
/// which a lock names at the stand-in's own origin.
fn route_registry(cell: &Cell, standin: &StandIn) {
    let origin = standin.origin();
    let rewrite =
        format!("rewrite registry\\.npmjs\\.org/{NAME}/(.*) {origin}/{REGISTRY}/{NAME}/$1\n");
    cell.write("downloader.cfg", rewrite);
    let option = downloader_option(cell.release());
    cell.write(".bazelrc", format!("common --{option}=downloader.cfg\n"));
}

/// The checkout of the fixture for `test`, and the stand-in its builds and
/// its commands talk to. `None` after a `SKIP` line when no Bazel runs here.
fn open(test: &str) -> Option<(Cell, StandIn)> {
    let cell = Cell::open(test, &FIXTURE)?;
    let standin = StandIn::start();
    route_registry(&cell, &standin);
    Some((cell, standin))
}

/// `socket-patch <args>` in `cell`, with `standin` as the Socket API, as
/// the patch server (a hosted pin is recognised by that origin) and as the
/// registry `rollback` reads the upstream entry from.
fn socket_patch(cell: &Cell, standin: &StandIn, args: &[&str]) -> Ran {
    let origin = standin.origin();
    let registry = format!("{origin}/{REGISTRY}");
    let env = [
        ("SOCKET_PATCH_SERVER_URL", origin.as_str()),
        ("SOCKET_NPM_REGISTRY", registry.as_str()),
    ];
    cell.socket_patch(&origin, args, &env)
}

/// A text file of a tree.
fn text(tree: &Tree, rel: &str) -> String {
    String::from_utf8(tree[rel].clone()).expect("a text file")
}

/// Step (a): the build of `cell` prints the unpatched marker. Gives the
/// files of the checkout, Bazel's own lock among them.
fn builds_unpatched(cell: &Cell) -> Tree {
    cell.builds(UNPATCHED);
    let before = cell.tree();
    let locked = before.contains_key("MODULE.bazel.lock");
    assert!(locked, "{}: Bazel wrote no lock", cell.test);
    before
}

/// Step (c): the build of `cell` prints `marker`, Bazel changed no file of
/// `pinned`, its own lock included, and that lock still stands when Bazel
/// may not update it.
fn builds_patched(cell: &Cell, pinned: &Tree, marker: &str) {
    cell.builds(marker);
    assert_eq!(changed(pinned, &cell.tree()), NOTHING, "{}", cell.test);
    let frozen = cell.frozen_build(&[CONSUMER]);
    assert!(frozen.ok(), "{}: {}", cell.test, frozen.dump());
}

/// Step (d): `socket-patch <undo>` counts one package under `counted` of
/// its summary, every file is the one of `before`, and so is the build.
fn undoes(cell: &Cell, standin: &StandIn, before: &Tree, undo: &[&str], counted: &str) {
    let test = &cell.test;
    let undone = socket_patch(cell, standin, undo);
    let said = &undone.dump;
    assert_eq!(undone.code, 0, "{test}: {said}");
    assert_eq!(undone.envelope["summary"][counted], 1, "{test}: {said}");
    assert_eq!(changed(before, &cell.tree()), NOTHING, "{test}: {said}");
    cell.builds(UNPATCHED);
    assert_eq!(changed(before, &cell.tree()), NOTHING, "{test}");
}

/// Step (e): the build of `twin` fails because Bazel finds the sha512 of
/// `found` where the lock pins that of `pinned`, and the registry is not
/// asked for the upstream tarball instead. Gives the build and the line it
/// failed with.
fn refuses(twin: &Cell, other: &StandIn, found: &[u8], pinned: &[u8]) -> (Run, String) {
    let test = &twin.test;
    let build = twin.bazel("build", &[CONSUMER]);
    assert!(!build.ok(), "{test}: other bytes built:\n{}", build.dump());
    let refusal = format!(
        "Checksum was {} but wanted {}",
        integrity(found),
        integrity(pinned)
    );
    assert!(
        build.stderr().contains(&refusal),
        "{test}: the build did not fail with {refusal:?}:\n{}",
        build.dump()
    );
    assert_eq!(
        other.asked(UPSTREAM_TGZ),
        0,
        "{test}: the build went to the upstream tarball"
    );
    (build, refusal)
}

/// The hosted flow of the module docs.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn hosted_npm_translate_lock() {
    let test = "npm::hosted_npm_translate_lock";
    let started = Instant::now();
    let Some((cell, standin)) = open(test) else {
        return;
    };
    let release = cell.release().to_string();
    let origin = standin.origin();
    let patch = Patched::new();
    standin.grant(&patch, &patch.tarball);

    // (a) The unpatched build.
    let before = builds_unpatched(&cell);

    // (b) The one command of hosted mode.
    let scan = socket_patch(&cell, &standin, &["scan", "--mode", "hosted", "--yes"]);
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    let event = event_for(&scan.envelope, PURL);
    assert_eq!(event["action"], "applied", "{test}: {said}");
    assert_eq!(event["uuid"], patch.uuid.as_str(), "{test}: {said}");
    // Those two files and no other: the entry of the package names the
    // patched tarball, by its sum and by its URL on the patch host.
    let written = ["pnpm-lock.yaml", "pnpm-workspace.yaml"];
    let rewritten = &scan.envelope["redirect"]["rewrittenFiles"];
    assert_eq!(*rewritten, json!(written), "{test}: {said}");
    let pinned = cell.tree();
    assert_eq!(changed(&before, &pinned), written, "{test}: {said}");
    let lock = text(&pinned, "pnpm-lock.yaml");
    let entry = format!(
        "  {NAME}@{VERSION}:\n    resolution: {{integrity: {}, tarball: {origin}{}}}\n",
        integrity(&patch.tarball),
        patch.route
    );
    assert!(lock.contains(&entry), "{test}: pnpm-lock.yaml:\n{lock}");
    let workspace = text(&pinned, "pnpm-workspace.yaml");
    assert_eq!(workspace, TRUSTING_WORKSPACE, "{test}");

    // (c) The same build, no step in between: patched, from the patch host.
    let (patched_fetches, upstream_fetches) =
        (standin.asked(&patch.route), standin.asked(UPSTREAM_TGZ));
    builds_patched(&cell, &pinned, &patch.marker);
    assert!(
        standin.asked(&patch.route) > patched_fetches,
        "{test}: the patched build did not fetch the tarball from the stand-in patch host"
    );
    assert_eq!(
        standin.asked(UPSTREAM_TGZ),
        upstream_fetches,
        "{test}: the patched build fetched the upstream tarball"
    );

    // (d) The undo: every file is the one of before, and so is the build.
    let undo = ["rollback", "--yes"];
    undoes(&cell, &standin, &before, &undo, "rolledBack");

    // (e) A second machine, a second patch, and a patch host that serves
    // other bytes at the URL the lock pins: still a tarball of the package,
    // with another sum.
    let twin = cell.twin();
    let other = StandIn::start();
    route_registry(&twin, &other);
    let second = Patched::new();
    let tampered = tarball(TAMPERED_INDEX);
    other.grant(&second, &tampered);
    let scan = socket_patch(&twin, &other, &["scan", "--mode", "hosted", "--yes"]);
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    let (_, refusal) = refuses(&twin, &other, &tampered, &second.tarball);
    assert!(
        other.asked(&second.route) > 0,
        "{test}: the patch host was not asked, so the failed build proves nothing"
    );

    println!(
        "{test}: Bazel {release} built {:?} from {origin}{} after `scan --mode hosted`; `rollback` \
         restored all {} files and the {UNPATCHED:?} build; other bytes at the patch host failed a \
         second machine's build ({refusal}); the stand-in answered {} requests for the upstream \
         tarball and {} for the patched one; {:?}",
        patch.marker,
        patch.route,
        before.len(),
        standin.asked(UPSTREAM_TGZ),
        standin.asked(&patch.route),
        started.elapsed()
    );
}

/// The vendored flow of the module docs.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn vendored_npm_translate_lock() {
    let test = "npm::vendored_npm_translate_lock";
    let started = Instant::now();
    let Some((cell, standin)) = open(test) else {
        return;
    };
    let release = cell.release().to_string();
    let patch = Patched::new();
    standin.grant(&patch, &patch.tarball);
    let tampered = tarball(TAMPERED_INDEX);

    // (a) The unpatched build.
    let before = builds_unpatched(&cell);

    // (b) The one command of vendored mode.
    let scan = socket_patch(&cell, &standin, &["scan", "--mode", "vendored", "--yes"]);
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["downloaded"], 1, "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    // The tarball and its ledger under `.socket/vendor`, the three files
    // that wire it in, and no other.
    let dir = format!(".socket/vendor/npm/{}", patch.uuid);
    let copy = format!("{dir}/{TGZ}");
    let written = [
        format!("{dir}/.gitattributes"),
        format!("{dir}/.gitignore"),
        copy.clone(),
        format!("{dir}/socket-patch.vendor.json"),
        ".socket/vendor/state.json".to_string(),
        "package.json".to_string(),
        "pnpm-lock.yaml".to_string(),
        "pnpm-workspace.yaml".to_string(),
    ];
    let vendored = cell.tree();
    assert_eq!(changed(&before, &vendored), written, "{test}: {said}");
    // The committed tarball is the one the patch host served; the lock
    // names it by path and by sum, and the override sends the package's one
    // version there.
    assert!(vendored[&copy] == patch.tarball, "{test}: {copy} differs");
    assert!(standin.asked(&patch.route) > 0, "{test}: {said}");
    let lock = text(&vendored, "pnpm-lock.yaml");
    let entry = format!(
        "  {NAME}@file:{copy}:\n    resolution: {{integrity: {}, tarball: file:{copy}}}\n",
        integrity(&patch.tarball)
    );
    assert!(lock.contains(&entry), "{test}: pnpm-lock.yaml:\n{lock}");
    let manifest: Value = serde_json::from_slice(&vendored["package.json"]).expect("package.json");
    let overridden = &manifest["pnpm"]["overrides"][format!("{NAME}@{VERSION}")];
    assert_eq!(*overridden, format!("file:{copy}"), "{test}: {manifest:#}");

    // (c) The same build, no step in between: patched, from the committed
    // file. Bazel asks the stand-in for nothing.
    let requests = standin.requests();
    builds_patched(&cell, &vendored, &patch.marker);
    assert_eq!(standin.requests(), requests, "{test}: Bazel asked a host");
    // What the checksum guards is the fetch, and this output base has
    // fetched: other bytes in the committed file are not read, so the build
    // neither fails nor changes. That is Bazel and the ruleset, not
    // `socket-patch`: a release that reads the file again fails here, and
    // then this step goes, and the caveat with it.
    cell.write(&copy, &tampered);
    cell.builds(&patch.marker);
    cell.write(&copy, &patch.tarball);

    // (d) The undo: every file is the one of before, and so is the build.
    let undo = ["vendor", "--revert"];
    undoes(&cell, &standin, &before, &undo, "removed");

    // (e) A second machine and a second patch, vendored there, and then
    // other bytes in the committed file: still a tarball of the package,
    // with another sum.
    let twin = cell.twin();
    let other = StandIn::start();
    route_registry(&twin, &other);
    let second = Patched::new();
    other.grant(&second, &second.tarball);
    let scan = socket_patch(&twin, &other, &["scan", "--mode", "vendored", "--yes"]);
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    let second_copy = format!(".socket/vendor/npm/{}/{TGZ}", second.uuid);
    let committed = twin.tree().contains_key(&second_copy);
    assert!(committed, "{test}: no {second_copy}: {said}");
    twin.write(&second_copy, &tampered);
    let (build, refusal) = refuses(&twin, &other, &tampered, &second.tarball);
    assert!(
        build.stderr().contains(&format!("file:{second_copy}")),
        "{test}: the build did not fail on the committed tarball:\n{}",
        build.dump()
    );

    println!(
        "{test}: Bazel {release} built {:?} from {copy} after `scan --mode vendored`, with no \
         request to the stand-in, and went on building it with other bytes in that file; `vendor \
         --revert` restored all {} files and the {UNPATCHED:?} build; other bytes in the committed \
         tarball failed a second machine's build ({refusal}); the stand-in answered {} requests \
         for the upstream tarball and {} for the patched one; {:?}",
        patch.marker,
        before.len(),
        standin.asked(UPSTREAM_TGZ),
        standin.asked(&patch.route),
        started.elapsed()
    );
}

/// Without a Bazel: the fixture's directories are those of its table, its
/// lock pins the upstream tarball the tests serve, and the names written
/// out above are those of the one package.
#[test]
fn the_fixture_pins_the_upstream_tarball_the_tests_serve() {
    FIXTURE.check();
    let path = fixture_path(FIXTURE.dir).join("common/pnpm-lock.yaml");
    let lock = std::fs::read_to_string(&path).expect("the fixture's pnpm-lock.yaml");
    let entry = format!(
        "  {NAME}@{VERSION}:\n    resolution: {{integrity: {}}}\n",
        integrity(&tarball(UPSTREAM_INDEX))
    );
    assert!(lock.contains(&entry), "{}: no\n{entry}", path.display());
    let manifest: Value = serde_json::from_str(MANIFEST).expect("the package's package.json");
    assert_eq!(manifest["name"], NAME);
    assert_eq!(manifest["version"], VERSION);
    assert_eq!(PURL, format!("pkg:npm/{NAME}@{VERSION}"));
    assert_eq!(TGZ, format!("{NAME}-{VERSION}.tgz"));
    assert_eq!(UPSTREAM_TGZ, format!("/{REGISTRY}/{NAME}/-/{TGZ}"));
}

#[test]
fn the_downloader_option_follows_the_release() {
    for (release, option) in [
        ("7.7.2", "experimental_downloader_config"),
        ("8.1.1", "experimental_downloader_config"),
        ("8.2.0", "downloader_config"),
        ("8.8.2", "downloader_config"),
        ("9.3.2-homebrew", "downloader_config"),
    ] {
        assert_eq!(downloader_option(release), option, "{release}");
    }
}
