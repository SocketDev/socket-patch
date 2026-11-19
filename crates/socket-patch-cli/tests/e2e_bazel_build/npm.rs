//! Hosted, vendored and agent mode for an npm package that aspect_rules_js
//! links from a pnpm lock:
//! `npm.npm_translate_lock(pnpm_lock = "//:pnpm-lock.yaml")` under Bzlmod,
//! with a lock of `lockfileVersion: '9.0'`.
//!
//! rules_js reads the lock itself. Every entry of `packages:` becomes one
//! repository, which Bazel's downloader fetches from the entry's `tarball`
//! (the registry's URL for the name and version when it has none, a path
//! beside the lock for a `file:` value) and holds to its `integrity`. No
//! pnpm runs, no `node_modules` of the checkout is read, and the machine
//! needs no Node: the ruleset downloads the one that runs the consumer.
//!
//! The hosted and the vendored flow, one test each, on the Bazel the run is
//! given ([`FIXTURE`] says which ruleset goes with its release), each in a
//! fresh output base:
//!
//! - (a) `bazel build` and `bazel run //:consumer` print the unpatched
//!   marker, and Bazel fetched the upstream tarball from the stand-in
//!   registry.
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
//!   Then the command of the mode runs a second time, as it does on every
//!   run of a pipeline, and `vex` is asked for its document. Bazel has built
//!   in the checkout by now and keeps its `bazel-*` links there, and the
//!   first run left a `pnpm-workspace.yaml` that lists the root as its one
//!   workspace package. That pattern names the root alone, so no link at
//!   the root is taken for a workspace member, the one to Bazel's execution
//!   root included, where the checkout's `package.json` shows up again:
//!   both commands see the package as they do in a checkout without the
//!   links. The hosted scan reports the patch applied again and the
//!   vendored one reports it `already_vendored`, each writes the VEX
//!   document of its run, `vex` attests the package, no file changes, and
//!   the build is still the patched one.
//! - (d) The undo (`rollback --yes`, or `vendor --revert`): every file of
//!   the checkout is the one of before, byte for byte, and the build prints
//!   the unpatched marker again.
//! - (e) On a second machine (a new output base and, on Bazel 9, a new
//!   contents cache) the command runs against a second patch, and the
//!   pinned place holds other bytes: the patch host serves them (hosted),
//!   or they replace the committed file (vendored). The build fails on the
//!   checksum and does not take the registry's tarball in its place.
//!
//! Both flows assert the VEX document of their patch as `main.rs` says.
//!
//! A third flow is agent mode ([`agent_npm_translate_lock`]), which patches
//! the copy of the package that the user's `pnpm install` left in
//! `node_modules`. rules_js does not read that directory, so the build is
//! the unpatched one before the command and after it. The flow asserts
//! that; that every form of `vex` writes a document that says the package
//! is affected, and names the call of `MODULE.bazel` that builds it from
//! the lock; that `vex --no-bazel`, for a repository that ships the
//! installed tree, says not affected of that tree while the build is still
//! the unpatched one; and that hosted mode, which the document names, then
//! ends in the patched build and in a document that says not affected.
//! Tests that need no Bazel run the same steps in a copy of the fixture,
//! and in workspaces where the statement must stay as it is without Bazel.
//!
//! A marker is read from what Bazel built. Bazel's downloader keeps every
//! file it fetches in the repository cache, under its checksum, and hands it
//! out again without a request; the tests of a leg share that cache, and CI
//! restores it from earlier runs. So every tarball of a run is new. The
//! entry file of the upstream package and of each patch holds an id made
//! for the run, which the marker shows, and the lock of the workspace copy
//! gets the upstream `integrity` from the bytes the run serves
//! ([`lock_pinning`]); the fixture's own lock holds a placeholder there.
//! Step (a) has to fetch the upstream tarball then, and counts the
//! requests: a downloader rewrite or a registry route that stopped working
//! fails it on every run, not on an empty cache alone.
//!
//! One loopback server per checkout (the second machine of (e) has its own)
//! stands in for three hosts, by route prefix: the Socket API (`/v0`), the
//! patch host (`/patch`) and `registry.npmjs.org` (the upstream tarball, and
//! the version document `rollback` reads through `SOCKET_NPM_REGISTRY`). The
//! package is the tests' own, under this organisation's scope ([`NAME`]).
//! Its lock entry names no URL, as pnpm writes one, so rules_js asks for it
//! at the public registry's URL; the downloader config of the cell rewrites
//! that URL to the stand-in ([`route_registry`]), as a user behind a registry
//! mirror has it.

use std::path::PathBuf;
use std::time::Instant;

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::utils::purl::canonical_purl;

use crate::envelope::{codes_in, event_triples};
use crate::harness::{
    cell_without_bazel, changed, fixture_path, rewrite, with_vex, Cell, Claim, Fixture, How, Ran,
    Run, StandIn, Tree, CONSUMER, NOTHING, NOT_IN_BUILD,
};
use crate::hosted_memory_common::{read_tree, Patch, ORG};

/// The workspace the tests build, and the ruleset each Bazel release builds
/// it with.
const FIXTURE: Fixture = Fixture {
    name: "npm::FIXTURE",
    dir: "rules_js/bzlmod",
    workflow: "bazel-npm.yml",
    eras: &[
        // aspect_rules_js 3.6.0, which asks for Bazel 7.6.0 or later.
        ((7, 6, 0)..(10, 0, 0), "e9"),
    ],
};

/// The package the fixture depends on, at the version its lock pins. The
/// scope is this organisation's on the public registry, so nobody else can
/// publish the name: a build or a pnpm that gets past the stand-in finds no
/// stranger's package there.
const NAME: &str = "@socketsecurity/bazel-fixture-upstream";
const VERSION: &str = "1.0.0";
/// With `%40` for the `@` of the scope, as this crate's tests spell the
/// Socket API's purl of a scoped package. `scan` takes either spelling and
/// names a patch in its events as the API did.
const PURL: &str = "pkg:npm/%40socketsecurity/bazel-fixture-upstream@1.0.0";
/// The product `vex` reads from the fixture's own `package.json`: its name
/// and its version.
const PRODUCT: &str = "pkg:npm/socket-fixture@0.0.0";
/// The file name of its tarball on the registry and on the patch host: the
/// name without its scope.
const TGZ: &str = "bazel-fixture-upstream-1.0.0.tgz";
/// Its `package.json`. The other file of a tarball is the entry file.
const MANIFEST: &str = "{\"name\": \"@socketsecurity/bazel-fixture-upstream\", \
    \"version\": \"1.0.0\", \"main\": \"index.js\"}\n";
/// The entry file of the other bytes a build finds at the pinned place.
const TAMPERED_INDEX: &str = "module.exports = \"TAMPERED\";\n";
/// The lock rules_js reads.
const LOCK: &str = "pnpm-lock.yaml";
/// The route prefix under which the stand-in plays the npm registry, and
/// the route of the upstream tarball there.
const REGISTRY: &str = "registry.npmjs.org";
const UPSTREAM_TGZ: &str =
    "/registry.npmjs.org/@socketsecurity/bazel-fixture-upstream/-/bazel-fixture-upstream-1.0.0.tgz";
/// The access-token level of a hosted tarball's URL, which `socket-patch`
/// writes as the API hands it out.
const TOKEN: &str = "22222222-2222-4222-8222-222222222222";
/// The `pnpm-workspace.yaml` hosted mode creates beside a 9.0 lock: the
/// root as the one package, and the setting without which pnpm 11 and later
/// reject a lock whose tarball URL is not the registry's.
const TRUSTING_WORKSPACE: &str = "packages:\n  - '.'\ntrustLockfile: true\n";

/// The `pnpm-workspace.yaml` vendored mode creates beside a 9.0 lock, which
/// rules_js reads: the root as the one package, and the override that sends
/// the package's one version to the committed tarball at `copy`.
fn overriding_workspace(copy: &str) -> String {
    format!("packages:\n  - '.'\noverrides:\n  '{NAME}@{VERSION}': file:{copy}\n")
}

/// The links Bazel keeps at the top of a checkout it has built in, beside
/// the one to its execution root, which is named for the checkout's
/// directory.
const BAZEL_LINKS: [&str; 3] = ["bazel-bin", "bazel-out", "bazel-testlogs"];

/// What a command reported: the events of its `envelope`, as
/// `event_triples` reads them, each purl in its canonical spelling.
/// `socket-patch` writes the `@` of an npm scope out in some of its events
/// and as `%40` in others. Both name the one package, so a test compares
/// events through this and holds none to either spelling.
fn reported(envelope: &Value) -> Vec<(String, String, String)> {
    let triples = event_triples(envelope).into_iter();
    let canonical = triples.map(|(purl, action, code)| (canonical_purl(&purl), action, code));
    canonical.collect()
}

/// The package with `index_js` as its entry file, as a registry tarball.
/// Every sum a test holds a build to is computed from the bytes it serves,
/// so nothing depends on the exact bytes the archive crates emit.
fn tarball(index_js: &str) -> Vec<u8> {
    let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut archive = tar::Builder::new(gzip);
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
    let gzip = archive.into_inner().expect("tar");
    gzip.finish().expect("gzip")
}

/// A sha512 as a pnpm lock and Bazel spell an `integrity`.
fn sri(sha512: &[u8]) -> String {
    let digest = base64::engine::general_purpose::STANDARD.encode(sha512);
    format!("sha512-{digest}")
}

/// The `integrity` of a tarball.
fn integrity(tarball: &[u8]) -> String {
    sri(&Sha512::digest(tarball))
}

/// One build of the package: an entry file that exports `<word> <id>`, the
/// tarball of it, and the line the consumer prints once Bazel built that
/// tarball in. The id is new for every run, so no cache holds the tarball.
struct Package {
    index_js: String,
    tarball: Vec<u8>,
    marker: String,
}

impl Package {
    fn new(word: &str, id: &str) -> Package {
        let index_js = format!("module.exports = \"{word} {id}\";\n");
        Package {
            tarball: tarball(&index_js),
            marker: format!("OUT: {word} {id}"),
            index_js,
        }
    }

    /// The package as the registry of one run has it.
    fn upstream() -> Package {
        Package::new("PRISTINE", &uuid::Uuid::new_v4().to_string())
    }
}

/// One patch of the package, under an id that is new for every run.
struct Patched {
    uuid: String,
    package: Package,
    /// The route of the tarball on the patch host.
    route: String,
}

impl Patched {
    fn new() -> Patched {
        let uuid = uuid::Uuid::new_v4().to_string();
        Patched {
            package: Package::new("PATCHED", &uuid),
            route: format!("/patch/npm/{NAME}/{VERSION}/{TOKEN}/{uuid}/{TGZ}"),
            uuid,
        }
    }

    /// Where vendored mode commits the tarball: in the patch's directory,
    /// under the scope of the name.
    fn vendored(&self) -> String {
        format!(".socket/vendor/npm/{}/{NAME}-{VERSION}.tgz", self.uuid)
    }
}

/// The entry of a lock that pins the package to the tarball of `integrity`
/// and names no URL, as pnpm writes the entry of a registry package (in
/// quotes: the key starts with `@`).
fn lock_entry(integrity: &str) -> String {
    format!("  '{NAME}@{VERSION}':\n    resolution: {{integrity: {integrity}}}\n")
}

/// The `integrity` of the package in the fixture's own lock, which is the
/// sum of no tarball: sixty-four zero bytes.
fn placeholder() -> String {
    sri(&[0; 64])
}

/// The fixture's lock with `upstream` in place of the placeholder: the lock
/// a test writes into its workspace copy before the first build.
fn lock_pinning(upstream: &Package) -> String {
    let path = fixture_path(FIXTURE.dir).join("common").join(LOCK);
    let lock = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let unpinned = lock_entry(&placeholder());
    let entries = lock.matches(&unpinned).count();
    assert_eq!(entries, 1, "{}: not one\n{unpinned}", path.display());
    lock.replace(&unpinned, &lock_entry(&integrity(&upstream.tarball)))
}

/// A stand-in that holds `upstream` as the registry does: the tarball, and
/// the version document with its integrity and the URL the public registry
/// would have it at.
fn registry(upstream: &Package) -> StandIn {
    let standin = StandIn::start();
    let document = json!({
        "name": NAME,
        "version": VERSION,
        "dist": {
            "tarball": format!("https://{REGISTRY}/{NAME}/-/{TGZ}"),
            "integrity": integrity(&upstream.tarball),
        },
    });
    let document = serde_json::to_vec(&document).expect("a JSON document");
    // `rollback` asks for the document of a scoped name with `%2f` for `/`.
    let named = NAME.replace('/', "%2f");
    standin.serve(5, &format!("/{REGISTRY}/{named}/{VERSION}"), &document);
    standin.serve(5, UPSTREAM_TGZ, &upstream.tarball);
    standin
}

/// The Socket API on `standin` for `patch` of `upstream`, free for every
/// caller, and the patch host with `served` at the URL the API hands out
/// for its tarball. The API names the sha512 of the patch's own tarball,
/// whatever is served.
fn grant(standin: &StandIn, upstream: &Package, patch: &Patched, served: &[u8]) {
    grant_recorded(standin, patch, served, &record(upstream, patch));
}

/// [`grant`] with `record` as the record of the patch.
fn grant_recorded(standin: &StandIn, patch: &Patched, served: &[u8], record: &Value) {
    let url = format!("{}{}", standin.origin(), patch.route);
    let reference = json!({
        "status": "granted",
        "url": url,
        "purl": PURL,
        "artifacts": [{
            "kind": "tarball",
            "url": url,
            "integrity": { "sha512": integrity(&patch.package.tarball) },
        }],
        "registryOverride": null,
    });
    let granted = Patch {
        purl: PURL.to_string(),
        uuid: patch.uuid.clone(),
        reference,
    };
    standin.api(&[granted]);
    // Priority 1: ahead of the shared API mock's patch record, whose hashes
    // are fixed, because vendored mode holds the downloaded file to `afterHash`.
    let record = serde_json::to_vec(record).expect("a JSON document");
    let record_route = format!("/v0/orgs/{ORG}/patches/view/{}", patch.uuid);
    standin.serve(1, &record_route, &record);
    standin.serve(5, &patch.route, served);
}

/// The record of `patch`: the entry file of `upstream` becomes the one of
/// the patch.
fn record(upstream: &Package, patch: &Patched) -> Value {
    json!({
        "uuid": patch.uuid,
        "purl": PURL,
        "publishedAt": "2026-01-01T00:00:00Z",
        "files": { "package/index.js": {
            "beforeHash": compute_git_sha256_from_bytes(upstream.index_js.as_bytes()),
            "afterHash": compute_git_sha256_from_bytes(patch.package.index_js.as_bytes()),
        }},
        "vulnerabilities": { "GHSA-test-aaaa-bbbb": {
            "cves": ["CVE-2024-0001"], "summary": "s", "severity": "high", "description": "d",
        }},
        "description": "fixture",
        "license": "MIT",
        "tier": "free",
    })
}

/// [`grant`] of the patch's own tarball, with a `record` that carries both
/// entry files: agent mode patches the installed copy from the record and
/// asks for no tarball, and hosted mode pins the tarball as in the hosted
/// flow.
fn grant_installed(standin: &StandIn, upstream: &Package, patch: &Patched) {
    let b64 = |text: &str| base64::engine::general_purpose::STANDARD.encode(text);
    let mut record = record(upstream, patch);
    let file = &mut record["files"]["package/index.js"];
    file["blobContent"] = b64(&patch.package.index_js).into();
    file["beforeBlobContent"] = b64(&upstream.index_js).into();
    grant_recorded(standin, patch, &patch.package.tarball, &record);
}

/// The directory of the package in pnpm's virtual store, from the checkout.
fn store() -> String {
    let entry = format!("{}@{VERSION}", NAME.replace('/', "+"));
    format!("node_modules/.pnpm/{entry}/node_modules/{NAME}")
}

/// What the user's `pnpm install` leaves for the package in the project
/// of `cell` (in its directory `project`: `""` for the checkout itself,
/// else with a `/` at its end): the two files of `upstream`'s tarball in
/// pnpm's virtual store, and the link to that directory which a `require`
/// of the project resolves. The store is the project's own, or with
/// `shared` the one at the root of the checkout, where pnpm keeps it for
/// the members of a workspace. No pnpm runs here, so the files pnpm keeps
/// for itself (`.modules.yaml`, the store's `lock.yaml`) are not there.
/// Gives the entry file, from the checkout.
fn install(cell: &Cell, project: &str, shared: bool, upstream: &Package) -> String {
    let store = match shared {
        true => store(),
        false => format!("{project}{}", store()),
    };
    cell.write(&format!("{store}/package.json"), MANIFEST);
    let entry = format!("{store}/index.js");
    cell.write(&entry, &upstream.index_js);
    let link = cell.path(&format!("{project}node_modules/{NAME}"));
    std::fs::create_dir_all(link.parent().expect("the scope")).expect("create the scope");
    // From the scope's directory in `node_modules`: to the store beside
    // it, or up to the root of the checkout and down into the store there.
    let target = match shared {
        true => "../".repeat(project.matches('/').count() + 2) + &store,
        false => self::store().replacen("node_modules/", "../", 1),
    };
    std::os::unix::fs::symlink(target, &link).expect("link the package");
    entry
}

/// Send Bazel's downloader to `standin` for the registry's files of the
/// package. Every other URL stays as it is, the patch host's included,
/// which a lock names at the stand-in's own origin.
fn route_registry(cell: &mut Cell, standin: &StandIn) {
    let files = format!("{REGISTRY}/{NAME}/");
    cell.route_downloads(&[rewrite(&files, &standin.origin())]);
}

/// The checkout of the fixture for `test`, the upstream package of this run,
/// which the lock of the checkout pins, and the stand-in that holds it,
/// which the builds and the commands of the checkout talk to. `None` after a
/// `SKIP` line when no Bazel runs here.
fn open(test: &str) -> Option<(Cell, StandIn, Package)> {
    let mut cell = Cell::open(test, &FIXTURE)?;
    let upstream = Package::upstream();
    cell.write(LOCK, lock_pinning(&upstream));
    let standin = registry(&upstream);
    route_registry(&mut cell, &standin);
    Some((cell, standin, upstream))
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

/// Step (a): the build of `cell` prints the marker of `upstream`, and Bazel
/// asked `standin` for that tarball, which no cache holds. Gives the files
/// of the checkout.
fn builds_upstream(cell: &Cell, standin: &StandIn, upstream: &Package) -> Tree {
    let before = cell.builds_unpatched(&upstream.marker);
    assert!(
        standin.asked(UPSTREAM_TGZ) > 0,
        "{}: the build did not fetch the upstream tarball from the stand-in registry",
        cell.test
    );
    before
}

/// Step (e), up to its build: a second machine with the checkout of `cell`
/// and a stand-in of its own, which its Bazel and its commands talk to; the
/// patch `second`, whose URL on that patch host answers with `served`; and
/// `scan --mode <mode> --yes` there, which applies it.
fn second_machine(
    cell: &Cell,
    upstream: &Package,
    mode: &str,
    second: &Patched,
    served: &[u8],
) -> (Cell, StandIn) {
    let mut twin = cell.twin();
    let other = registry(upstream);
    route_registry(&mut twin, &other);
    grant(&other, upstream, second, served);
    let scan = socket_patch(&twin, &other, &["scan", "--mode", mode, "--yes"]);
    let (test, said) = (&twin.test, &scan.dump);
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    (twin, other)
}

/// The second half of step (c), in the checkout of `cell` that Bazel has
/// built in and that holds the files of `patched`. Beside Bazel's links,
/// `scan --mode <mode> --yes` scans the package and reports the one event
/// `seen` for it (an action and an error code), which is what it reports in
/// a checkout without those links; the document of that run, and those of
/// `vex` and of `vex --no-verify`, attest `claim`; `vex` without a product
/// names the fixture's own; no file of the checkout changes; and the build
/// still prints `marker`.
fn runs_again(
    cell: &Cell,
    standin: &StandIn,
    mode: &str,
    seen: (&str, &str),
    patched: &Tree,
    claim: &Claim,
    marker: &str,
) {
    let test = &cell.test;
    // Bazel says where the checkout is, and its links are there.
    let info = cell.bazel("info", &["workspace"]);
    assert!(info.ok(), "{test}: {}", info.dump());
    let checkout = PathBuf::from(info.stdout().trim());
    let named = checkout.file_name().expect("the checkout's directory");
    let root_link = format!("bazel-{}", named.to_string_lossy());
    for link in BAZEL_LINKS.into_iter().chain([root_link.as_str()]) {
        let link = checkout.join(link);
        assert!(link.is_symlink(), "{test}: no link {}", link.display());
    }
    let one = |action: &str, code: &str| [(canonical_purl(PURL), action.into(), code.into())];

    let again = cell.document("again");
    let scan = ["scan", "--mode", mode, "--yes"];
    let scan = socket_patch(cell, standin, &[&scan[..], &with_vex(&again)].concat());
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    let seen = one(seen.0, seen.1);
    assert_eq!(reported(&scan.envelope), seen, "{test}: {said}");
    assert_eq!(scan.envelope["scannedPackages"], 1, "{test}: {said}");
    cell.wrote_in_run(&scan, &again, claim);

    // `vex` says the same of the build that printed the patched marker,
    // and with `--no-verify` that it checked no file.
    let run = |cell: &Cell, args: &[&str]| socket_patch(cell, standin, args);
    cell.stands_alone(run, claim, true);
    cell.stands_alone(run, claim, false);
    // Without a product, as a user types it: the same document for the
    // project of the checkout's own `package.json`, which Bazel's links
    // show a second time.
    cell.detects_product(run, Some(PRODUCT));

    assert_eq!(changed(patched, &cell.tree()), NOTHING, "{test}");
    cell.builds_patched(patched, marker);
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

/// The hosted flow of the module docs. Its second scan, beside the links of
/// the Bazel that built in the checkout, reports the patch applied again,
/// and `vex` writes a document that attests the package.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn hosted_npm_translate_lock() {
    let test = "npm::hosted_npm_translate_lock";
    let started = Instant::now();
    let Some((cell, standin, upstream)) = open(test) else {
        return;
    };
    let release = cell.release().to_string();
    let origin = standin.origin();
    let patch = Patched::new();
    grant(&standin, &upstream, &patch, &patch.package.tarball);

    // (a) The unpatched build, with the upstream tarball from the stand-in.
    let before = builds_upstream(&cell, &standin, &upstream);

    // (b) The one command of hosted mode. It rewrites those two files and
    // no other: the entry of the package names the patched tarball, by its
    // sum and by its URL on the patch host.
    let hosted = ["scan", "--mode", "hosted", "--yes"];
    let claim = Claim::new(PURL, &patch.uuid, How::Hosted);
    let run = |cell: &Cell, args: &[&str]| socket_patch(cell, &standin, args);
    let in_run = cell.document("in-run");
    let scan = run(&cell, &[&hosted[..], &with_vex(&in_run)].concat());
    let written = [LOCK, "pnpm-workspace.yaml"];
    let pinned = cell.pinned_by(&scan, PURL, &patch.uuid, &before, &written);
    let lock = text(&pinned, LOCK);
    let entry = format!(
        "  '{NAME}@{VERSION}':\n    resolution: {{integrity: {}, tarball: {origin}{}}}\n",
        integrity(&patch.package.tarball),
        patch.route
    );
    assert!(lock.contains(&entry), "{test}: {LOCK}:\n{lock}");
    let workspace = text(&pinned, "pnpm-workspace.yaml");
    assert_eq!(workspace, TRUSTING_WORKSPACE, "{test}");
    // The document of that run and the one of `vex` say so, in a checkout
    // Bazel has built in, before the patched build.
    cell.wrote_in_run(&scan, &in_run, &claim);
    cell.stands_alone(run, &claim, true);

    // (c) The same build, no step in between: patched, from the patch host.
    let patched_fetches = standin.asked(&patch.route);
    cell.builds_patched(&pinned, &patch.package.marker);
    assert!(
        standin.asked(&patch.route) > patched_fetches,
        "{test}: the patched build did not fetch the tarball from the stand-in patch host"
    );

    // The same command and `vex`, now that Bazel has built in the checkout.
    let (seen, marker) = (("applied", ""), &patch.package.marker);
    runs_again(&cell, &standin, "hosted", seen, &pinned, &claim, marker);

    // (d) The undo: every file is the one of before, and so is the build,
    // and `vex` has no document for it.
    let undo = socket_patch(&cell, &standin, &["rollback", "--yes"]);
    cell.undone(&undo, "rolledBack", &before, &upstream.marker);
    cell.attests_nothing(run, 2, "manifest_not_found");
    // The same two documents where no Bazel has built.
    cell.attests_unbuilt(run, &hosted, &before, &pinned, &claim);

    // (e) A second machine, a second patch, and a patch host that serves
    // other bytes at the URL the lock pins: still a tarball of the package,
    // with another sum.
    let second = Patched::new();
    let tampered = tarball(TAMPERED_INDEX);
    let (twin, other) = second_machine(&cell, &upstream, "hosted", &second, &tampered);
    let (_, refusal) = refuses(&twin, &other, &tampered, &second.package.tarball);
    assert!(
        other.asked(&second.route) > 0,
        "{test}: the patch host was not asked, so the failed build proves nothing"
    );

    println!(
        "{test}: Bazel {release} built {:?} from {origin}{} after `scan --mode hosted`; beside \
         Bazel's links a second scan reported the patch applied again, `vex` attested the \
         package and the build stayed patched; `rollback` restored all {} files and the {:?} \
         build; other bytes at the patch host failed a second machine's build ({refusal}); the \
         stand-in answered {} requests for the upstream tarball and {} for the patched one; {:?}",
        patch.package.marker,
        patch.route,
        before.len(),
        upstream.marker,
        standin.asked(UPSTREAM_TGZ),
        standin.asked(&patch.route),
        started.elapsed()
    );
}

/// The vendored flow of the module docs. Its second scan, beside the links
/// of the Bazel that built in the checkout, reports the package
/// `already_vendored`, and `vex` writes a document that attests it.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn vendored_npm_translate_lock() {
    let test = "npm::vendored_npm_translate_lock";
    let started = Instant::now();
    let Some((cell, standin, upstream)) = open(test) else {
        return;
    };
    let release = cell.release().to_string();
    let patch = Patched::new();
    grant(&standin, &upstream, &patch, &patch.package.tarball);

    // (a) The unpatched build, with the upstream tarball from the stand-in.
    let before = builds_upstream(&cell, &standin, &upstream);

    // (b) The one command of vendored mode.
    let vendoring = ["scan", "--mode", "vendored", "--yes"];
    let claim = Claim::new(PURL, &patch.uuid, How::Vendored);
    let run = |cell: &Cell, args: &[&str]| socket_patch(cell, &standin, args);
    let in_run = cell.document("in-run");
    let scan = run(&cell, &[&vendoring[..], &with_vex(&in_run)].concat());
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["downloaded"], 1, "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    // The tarball and its ledger under `.socket/vendor`, the three files
    // that wire it in, and no other.
    let dir = format!(".socket/vendor/npm/{}", patch.uuid);
    let copy = patch.vendored();
    let written = [
        format!("{dir}/.gitattributes"),
        format!("{dir}/.gitignore"),
        copy.clone(),
        format!("{dir}/socket-patch.vendor.json"),
        ".socket/vendor/state.json".to_string(),
        "package.json".to_string(),
        LOCK.to_string(),
        "pnpm-workspace.yaml".to_string(),
    ];
    let vendored = cell.tree();
    assert_eq!(changed(&before, &vendored), written, "{test}: {said}");
    // The committed tarball is the one the patch host served; the lock
    // names it by path and by sum, and the override sends the package's one
    // version there.
    let committed = vendored[&copy] == patch.package.tarball;
    assert!(committed, "{test}: {copy} differs");
    assert!(standin.asked(&patch.route) > 0, "{test}: {said}");
    let lock = text(&vendored, LOCK);
    let entry = format!(
        "  '{NAME}@file:{copy}':\n    resolution: {{integrity: {}, tarball: file:{copy}}}\n",
        integrity(&patch.package.tarball)
    );
    assert!(lock.contains(&entry), "{test}: {LOCK}:\n{lock}");
    let manifest: Value = serde_json::from_slice(&vendored["package.json"]).expect("package.json");
    let overridden = &manifest["pnpm"]["overrides"][format!("{NAME}@{VERSION}")];
    assert_eq!(*overridden, format!("file:{copy}"), "{test}: {manifest:#}");
    let workspace = text(&vendored, "pnpm-workspace.yaml");
    assert_eq!(workspace, overriding_workspace(&copy), "{test}");
    // The document of that run and the one of `vex` say so, in a checkout
    // Bazel has built in, before the patched build.
    cell.wrote_in_run(&scan, &in_run, &claim);
    cell.stands_alone(run, &claim, true);

    // (c) The same build, no step in between: patched, from the committed
    // file. Bazel asks the stand-in for nothing.
    let requests = standin.requests();
    cell.builds_patched(&vendored, &patch.package.marker);
    assert_eq!(standin.requests(), requests, "{test}: Bazel asked a host");

    // The same command and `vex`, now that Bazel has built in the checkout.
    let (seen, marker) = (("skipped", "already_vendored"), &patch.package.marker);
    runs_again(&cell, &standin, "vendored", seen, &vendored, &claim, marker);

    // (d) The undo: every file is the one of before, and so is the build,
    // and `vex` has no document for it.
    let undo = socket_patch(&cell, &standin, &["vendor", "--revert"]);
    cell.undone(&undo, "removed", &before, &upstream.marker);
    cell.attests_nothing(run, 2, "manifest_not_found");
    // The same two documents where no Bazel has built.
    cell.attests_unbuilt(run, &vendoring, &before, &vendored, &claim);

    // (e) A second machine and a second patch, vendored there, and then
    // other bytes in the committed file: still a tarball of the package,
    // with another sum.
    let second = Patched::new();
    let served = &second.package.tarball;
    let (twin, other) = second_machine(&cell, &upstream, "vendored", &second, served);
    let second_copy = second.vendored();
    let committed = twin.tree().contains_key(&second_copy);
    assert!(committed, "{test}: no {second_copy}");
    let tampered = tarball(TAMPERED_INDEX);
    twin.write(&second_copy, &tampered);
    let (build, refusal) = refuses(&twin, &other, &tampered, &second.package.tarball);
    assert!(
        build.stderr().contains(&format!("file:{second_copy}")),
        "{test}: the build did not fail on the committed tarball:\n{}",
        build.dump()
    );

    println!(
        "{test}: Bazel {release} built {:?} from {copy} after `scan --mode vendored`, with no \
         request to the stand-in; beside Bazel's links a second scan reported the package \
         already_vendored, `vex` attested it and the build stayed patched; `vendor --revert` \
         restored all {} files and the {:?} build; other bytes in the committed tarball failed \
         a second machine's build ({refusal}); the stand-in answered {} requests for the \
         upstream tarball and {} for the patched one; {:?}",
        patch.package.marker,
        before.len(),
        upstream.marker,
        standin.asked(UPSTREAM_TGZ),
        standin.asked(&patch.route),
        started.elapsed()
    );
}

/// The file that hands the lock to rules_js, and the call that does.
const MODULE: &str = "MODULE.bazel";
const HUB: &str = "npm.npm_translate_lock";

/// What `socket-patch` has to name when it says that the package is
/// affected: the lock `lock` that Bazel builds the package from, with the
/// hub's call and its line in the workspace file `file` of `cell`, and the
/// mode that patches that lock.
fn names(cell: &Cell, file: &str, lock: &str) -> Vec<String> {
    let workspace_file = text(&cell.tree(), file);
    let call = format!("{HUB}(");
    let above = workspace_file.lines().take_while(|line| *line != call);
    vec![
        format!("from {lock} (`{HUB}`, {file}:{})", above.count() + 1),
        "`socket-patch scan --mode hosted`".to_string(),
    ]
}

/// Agent mode in the project of `cell` (in its directory `project`, as
/// [`install`] takes it), where [`install`] left the package with the entry
/// file `entry`: `scan --mode agent --yes` patches the installed copy, from
/// the record of `patch`, and changes no other file of the project, and the
/// `apply` of a later install finds it patched. Then what the two say with
/// `--vex`, and what `vex` and
/// `vex --no-verify` say: all four pass and write one document. With
/// `unbuilt`, the [`names`] of the call that builds the package from the
/// lock, it says that the package is affected, and names them. Without, no
/// workspace file hands a lock of the project to Bazel, and it attests the
/// package through the patch, as in a checkout without Bazel. Gives the
/// files of the checkout.
fn patches_the_installed_copy(
    cell: &Cell,
    standin: &StandIn,
    project: &str,
    patch: &Patched,
    entry: &str,
    unbuilt: Option<&[String]>,
) -> Tree {
    let test = &cell.test;
    let before = cell.tree();
    let claim = match unbuilt {
        Some(names) => Claim::unbuilt(PURL, &patch.uuid, names),
        None => Claim::new(PURL, &patch.uuid, How::Agent),
    };
    let directory = ["--cwd", project.trim_end_matches('/')];
    let run = |cell: &Cell, args: &[&str]| {
        let at: &[&str] = if project.is_empty() { &[] } else { &directory };
        socket_patch(cell, standin, &[args, at].concat())
    };

    let in_run = cell.document("in-run");
    let agent = ["scan", "--mode", "agent", "--yes"];
    let scan = run(cell, &[&agent[..], &with_vex(&in_run)].concat());
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    let patched = cell.tree();
    let wrote = changed(&before, &patched);
    let outside: Vec<&String> = wrote
        .iter()
        .filter(|file| !file.starts_with(&format!("{project}.socket/")))
        .collect();
    assert_eq!(outside, [entry], "{test}: {said}");
    let installed = patched[entry] == patch.package.index_js.as_bytes();
    assert!(installed, "{test}: {entry} is not the patched file");

    let again = cell.document("apply");
    let apply = run(cell, &[&["apply"][..], &with_vex(&again)].concat());
    assert_eq!(
        apply.envelope["status"], "success",
        "{test}: {}",
        apply.dump
    );
    cell.wrote_in_run(&scan, &in_run, &claim);
    cell.wrote_in_run(&apply, &again, &claim);
    cell.stands_alone(run, &claim, true);
    cell.stands_alone(run, &claim, false);
    assert_eq!(changed(&patched, &cell.tree()), NOTHING, "{test}");
    patched
}

/// What the document of an affected package tells the user to do, in the
/// checkout of `cell` that agent mode patched: `scan --mode hosted --yes`
/// pins `patch` in the lock, which rules_js builds the package from. Its
/// document and the one of `vex` now attest the package, through the pin.
/// Gives the files of the checkout.
fn pins_the_lock(cell: &Cell, standin: &StandIn, patch: &Patched) -> Tree {
    let test = &cell.test;
    let claim = Claim::new(PURL, &patch.uuid, How::Hosted);
    let run = |cell: &Cell, args: &[&str]| socket_patch(cell, standin, args);
    let document = cell.document("hosted");
    let hosted = ["scan", "--mode", "hosted", "--yes"];
    let scan = run(cell, &[&hosted[..], &with_vex(&document)].concat());
    let applied = &scan.envelope["summary"]["applied"];
    assert_eq!(*applied, 1, "{test}: {}", scan.dump);
    cell.wrote_in_run(&scan, &document, &claim);
    cell.stands_alone(run, &claim, true);
    cell.tree()
}

/// Agent mode beside a hub that builds the package from the lock.
///
/// - (a) After the user's `pnpm install` ([`install`]), `bazel build` and
///   `bazel run //:consumer` print the unpatched marker: rules_js builds
///   the package from the tarball the lock names, and reads no
///   `node_modules` of the checkout, which `.bazelignore` names.
/// - (b) `scan --mode agent --yes` patches the copy in `node_modules`, and
///   `apply` finds it patched ([`patches_the_installed_copy`]). Both pass,
///   and they and `vex` write a document that says the package is
///   affected: it names `pnpm-lock.yaml`, which Bazel builds the package
///   from, the call of `MODULE.bazel` that reads it, and hosted mode,
///   which patches that lock.
/// - (c) The same two Bazel commands print the unpatched marker again, as
///   the document said, and `vex` says affected again. `vex --no-bazel`
///   says not affected ([`speaks_of_the_installed_tree`]): its document
///   then speaks of `node_modules`, which holds the patch, and not of the
///   Bazel build, which is still the unpatched one. It is for a repository
///   that ships what its package manager installed.
/// - (d) What the document says to do: `scan --mode hosted --yes` pins the
///   patch in the lock ([`pins_the_lock`]), the same two Bazel commands
///   print the patched marker, with the tarball from the stand-in patch
///   host, and `vex` attests the package as not affected.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn agent_npm_translate_lock() {
    let test = "npm::agent_npm_translate_lock";
    let started = Instant::now();
    let Some((cell, standin, upstream)) = open(test) else {
        return;
    };
    let release = cell.release().to_string();
    let patch = Patched::new();
    grant_installed(&standin, &upstream, &patch);

    // (a) The unpatched build, with the installed tree beside it.
    let entry = install(&cell, "", false, &upstream);
    builds_upstream(&cell, &standin, &upstream);

    // (b) Agent mode patches the installed copy, and says it is affected.
    let names = names(&cell, MODULE, LOCK);
    let patched = patches_the_installed_copy(&cell, &standin, "", &patch, &entry, Some(&names));

    // (c) The build is the one of (a): Bazel never reads the patched copy.
    cell.builds(&upstream.marker);
    assert_eq!(changed(&patched, &cell.tree()), NOTHING, "{test}");
    let run = |cell: &Cell, args: &[&str]| socket_patch(cell, &standin, args);
    cell.stands_alone(run, &Claim::unbuilt(PURL, &patch.uuid, &names), true);
    // Told that the installed tree is what ships, `vex` attests that tree.
    speaks_of_the_installed_tree(&cell, &standin, &patch);
    assert_eq!(changed(&patched, &cell.tree()), NOTHING, "{test}");

    // (d) Hosted mode patches what Bazel builds, and `vex` says so.
    let pinned = pins_the_lock(&cell, &standin, &patch);
    cell.builds_patched(&pinned, &patch.package.marker);
    assert!(
        standin.asked(&patch.route) > 0,
        "{test}: the patched build did not fetch the tarball from the stand-in patch host"
    );
    let claim = Claim::new(PURL, &patch.uuid, How::Hosted);
    cell.stands_alone(run, &claim, true);

    println!(
        "{test}: Bazel {release} built {:?} before and after `scan --mode agent` patched {}; \
         every form of `vex` said the package is affected, and named {names:?}, and \
         `vex --no-bazel` said it is not affected in the installed tree; after \
         `scan --mode hosted` it built {:?}, and `vex` said it is not affected; {:?}",
        upstream.marker,
        store(),
        patch.package.marker,
        started.elapsed()
    );
}

/// Without a Bazel: a checkout with the fixture's `MODULE.bazel` at its
/// root and the fixture's project in the directory `project` of it (as
/// [`install`] takes it), with the lock that pins the upstream package of
/// this run and the stand-in that holds it, as [`open`] makes them, the
/// package installed in the project, and a patch of the package granted to
/// agent mode. Gives the entry file of the installed copy last.
///
/// With `member`, the project is a member of a pnpm workspace at the root
/// of the checkout, laid out as `pnpm install` leaves one: the lock is the
/// workspace's, at the root, and names the project among its importers,
/// the project has no lock of its own, and the store is the root's.
fn checkout_of(project: &str, member: bool) -> (Cell, StandIn, Patched, String) {
    let cell = cell_without_bazel("9.3.2");
    for part in ["common", "e9"] {
        for (rel, bytes) in read_tree(&fixture_path(FIXTURE.dir).join(part)) {
            let at = if rel == MODULE { "" } else { project };
            cell.write(&format!("{at}{rel}"), bytes);
        }
    }
    cell.write(".git/HEAD", "ref: refs/heads/main\n");
    let upstream = Package::upstream();
    let lock = lock_pinning(&upstream);
    if member {
        let (own, named) = ("\n  .:\n", project.trim_end_matches('/'));
        assert_eq!(lock.matches(own).count(), 1, "{lock}");
        let shared = lock.replace(own, &format!("\n  .: {{}}\n\n  {named}:\n"));
        std::fs::remove_file(cell.path(&format!("{project}{LOCK}"))).expect("the member's lock");
        cell.write(LOCK, shared);
        cell.write("pnpm-workspace.yaml", format!("packages:\n  - {named}\n"));
        cell.write(
            "package.json",
            "{\"name\": \"workspace\", \"private\": true}\n",
        );
    } else {
        cell.write(&format!("{project}{LOCK}"), lock);
    }
    let standin = registry(&upstream);
    let patch = Patched::new();
    grant_installed(&standin, &upstream, &patch);
    let entry = install(&cell, project, member, &upstream);
    (cell, standin, patch, entry)
}

/// [`checkout_of`] a project with a lock and a store of its own.
fn checkout(project: &str) -> (Cell, StandIn, Patched, String) {
    checkout_of(project, false)
}

/// The action statement of a package of the fixture's checkout that is
/// affected because `patch` is in its installed copy alone: it names the
/// lock and its `call` as [`names`] gives them first, and ends with the
/// option for a repository that ships the installed tree.
fn action(patch: &Patched, call: &str) -> String {
    format!(
        "Bazel builds this package {call}, which does not name Socket patch {}: the patch is \
         only in the installed copy. Run `socket-patch scan --mode hosted` in the directory of \
         that lock to pin the patch there. If what you ship is the installed tree and not what \
         Bazel builds, pass `--no-bazel` (`--vex-no-bazel` on scan, apply and vendor).",
        patch.uuid
    )
}

/// The line a person reads on stderr when the document says that the
/// fixture's package is affected: the run warning, which says so and then
/// what the [`action`] statement says.
fn warns(patch: &Patched, call: &str) -> String {
    let action = action(patch, call);
    format!("Warning: {PURL}: the VEX document says affected. {action}")
}

/// Without a Bazel: step (b) of [`agent_npm_translate_lock`] in the
/// fixture's checkout, where `MODULE.bazel` hands the lock to rules_js.
/// Then `apply --vex` and `scan --mode agent --vex` as a person runs them:
/// each passes and writes the document, with the warning on stderr, the
/// line that it wrote a document on stdout, and no error; with `--silent`
/// each passes, writes the document and prints nothing.
#[test]
fn an_installed_patch_is_affected_beside_a_hub_that_reads_the_lock() {
    let (cell, standin, patch, entry) = checkout("");
    let names = names(&cell, MODULE, LOCK);
    let call = "from pnpm-lock.yaml (`npm.npm_translate_lock`, MODULE.bazel:7)";
    assert_eq!(names[0], call);
    patches_the_installed_copy(&cell, &standin, "", &patch, &entry, Some(&names));

    let origin = standin.origin();
    let registry = format!("{origin}/{REGISTRY}");
    let env = [
        ("SOCKET_PATCH_SERVER_URL", origin.as_str()),
        ("SOCKET_NPM_REGISTRY", registry.as_str()),
    ];
    let document = cell.document("person");
    let claim = Claim::unbuilt(PURL, &patch.uuid, &names);
    let warned = warns(&patch, &names[0]);
    let scan = ["scan", "--mode", "agent", "--yes"];
    for command in [&["apply"][..], &scan[..]] {
        let loud = [command, &with_vex(&document)].concat();
        cell.tells_a_person(&origin, &loud, &env, &document, &claim, &warned);
        let silent = [&loud[..], &["--silent"]].concat();
        cell.tells_a_person(&origin, &silent, &env, &document, &claim, &warned);
    }

    // What the document says to do ends in one that says not affected.
    pins_the_lock(&cell, &standin, &patch);
}

/// `vex --no-bazel` in the checkout of `cell`, where `patch` is in the
/// installed copy alone and a hub builds the package from the lock, so
/// that `vex` says affected: it exits 0, reports the package as verified
/// and warns of nothing, and its one statement says not affected, through
/// the patch. The document then speaks of `node_modules`, which a
/// repository that ships its installed tree puts in what it ships, and not
/// of what Bazel builds.
fn speaks_of_the_installed_tree(cell: &Cell, standin: &StandIn, patch: &Patched) {
    let path = cell.document("installed");
    let args = ["vex", "--no-bazel", "--output"];
    let vex = socket_patch(
        cell,
        standin,
        &[&args[..], &[path.to_str().expect("a path")]].concat(),
    );
    let (test, said) = (&cell.test, &vex.dump);
    assert_eq!(vex.code, 0, "{test}: {said}");
    assert_eq!(vex.envelope["status"], "success", "{test}: {said}");
    let verified = [(canonical_purl(PURL), "verified".into(), String::new())];
    assert_eq!(reported(&vex.envelope), verified, "{test}: {said}");
    let warned = codes_in(&vex.envelope["warnings"]);
    assert_eq!(warned, NOTHING, "{test}: {said}");
    let written = std::fs::read_to_string(&path).expect("a document");
    let document: Value = serde_json::from_str(&written).expect("a JSON document");
    let statements = document["statements"].as_array().map(Vec::as_slice);
    let Some([statement]) = statements else {
        panic!("{test}: not one statement:\n{written}");
    };
    let says = ["status", "impact_statement", "action_statement"].map(|key| &statement[key]);
    let impact = json!(format!("Patched via Socket patch {}", patch.uuid));
    let expected = [&json!("not_affected"), &impact, &Value::Null];
    assert_eq!(says, expected, "{test}: {written}");
}

/// Without a Bazel: a repository that ships what its package manager
/// installed, beside a hub that reads the same lock. Every form says
/// affected, as [`an_installed_patch_is_affected_beside_a_hub_that_reads_the_lock`]
/// holds. With `--no-bazel` on `vex`, `--vex-no-bazel` on `apply` and on
/// `scan --mode agent`, or `SOCKET_VEX_NO_BAZEL=1` on any of them, the
/// document attests the package through the patch, and the run is the one
/// of the same checkout without its `MODULE.bazel`, to a script and to a
/// person: the exit code, both streams byte for byte, and what the document
/// says. In that checkout, which is no Bazel workspace, the option changes
/// nothing and no run remarks on it.
#[test]
fn the_option_makes_the_run_the_one_of_a_checkout_without_bazel() {
    let (cell, standin, patch, entry) = checkout("");
    let names = names(&cell, MODULE, LOCK);
    patches_the_installed_copy(&cell, &standin, "", &patch, &entry, Some(&names));
    speaks_of_the_installed_tree(&cell, &standin, &patch);

    let origin = standin.origin();
    let registry = format!("{origin}/{REGISTRY}");
    let env = [
        ("SOCKET_PATCH_SERVER_URL", origin.as_str()),
        ("SOCKET_NPM_REGISTRY", registry.as_str()),
        ("SOCKET_VEX_NO_BAZEL", "1"),
    ];
    let document = cell.document("shipped");
    let scan = ["scan", "--mode", "agent", "--yes"];
    let forms = [
        (
            vec!["vex", "--output", document.to_str().expect("a path")],
            "--no-bazel",
        ),
        (
            [&["apply"][..], &with_vex(&document)].concat(),
            "--vex-no-bazel",
        ),
        ([&scan[..], &with_vex(&document)].concat(), "--vex-no-bazel"),
    ];
    let gives = |args: &[&str], env: &[(&str, &str)]| cell.gives(&origin, args, env, &document);
    let claim = Claim::new(PURL, &patch.uuid, How::Agent);
    let mut beside_the_hub = Vec::new();
    for (args, option) in &forms {
        let with_option = [&args[..], &[*option]].concat();
        if args[0] != "vex" {
            let ran = socket_patch(&cell, &standin, &with_option);
            cell.wrote_in_run(&ran, &document, &claim);
        }
        beside_the_hub.push([gives(&with_option, &env[..2]), gives(args, &env)]);
    }

    let patched = cell.tree();
    std::fs::remove_file(cell.path(MODULE)).expect(MODULE);
    for ((args, option), [by_option, by_variable]) in forms.iter().zip(&beside_the_hub) {
        let without_bazel = gives(args, &env[..2]);
        assert_eq!(*by_option, without_bazel, "{args:?} {option}");
        assert_eq!(
            *by_variable, without_bazel,
            "{args:?}, SOCKET_VEX_NO_BAZEL=1"
        );
        let outside = gives(&[&args[..], &[*option]].concat(), &env[..2]);
        assert_eq!(outside, without_bazel, "{args:?} {option}, no {MODULE}");
        for run in without_bazel.as_array().into_iter().flatten() {
            let says = [&run["code"], &run["document"]["statements"][0]["status"]];
            assert_eq!(
                says,
                [&json!(0), &json!("not_affected")],
                "{args:?}: {run:#}"
            );
        }
        println!("{args:?} with {option}, and without {MODULE}:\n{without_bazel:#}");
    }
    assert_eq!(changed(&patched, &cell.tree()), [MODULE], "{}", cell.test);
}

/// Without a Bazel: the installed patch is affected beside a second patch
/// of the manifest whose package this checkout does not have, as a
/// manifest shared by several projects holds one. Every form omits that
/// one with or without Bazel. `apply --vex` passes and writes the document
/// of the first, as it did when it attested it as patched. So does `vex`,
/// which reports both as skipped, each with its own code.
#[test]
fn an_installed_patch_is_affected_beside_a_patch_that_is_omitted_for_another_reason() {
    let (cell, standin, patch, entry) = checkout("");
    let names = names(&cell, MODULE, LOCK);
    patches_the_installed_copy(&cell, &standin, "", &patch, &entry, Some(&names));

    let manifest = ".socket/manifest.json";
    let mut recorded: Value = serde_json::from_str(&text(&cell.tree(), manifest)).expect(manifest);
    let patches = recorded["patches"].as_object_mut().expect("the patches");
    let [(_, record)] = &patches.iter().collect::<Vec<_>>()[..] else {
        panic!("not one patch: {patches:?}");
    };
    let mut absent = (*record).clone();
    absent["uuid"] = uuid::Uuid::new_v4().to_string().into();
    let other = "pkg:npm/%40socketsecurity/bazel-fixture-absent@1.0.0";
    patches.insert(other.to_string(), absent);
    cell.write(
        manifest,
        serde_json::to_vec_pretty(&recorded).expect(manifest),
    );

    let document = cell.document("beside");
    let apply = [&["apply"][..], &with_vex(&document)].concat();
    let apply = socket_patch(&cell, &standin, &apply);
    assert_eq!(apply.envelope["status"], "success", "{}", apply.dump);
    cell.wrote_in_run(
        &apply,
        &document,
        &Claim::unbuilt(PURL, &patch.uuid, &names),
    );

    let alone = cell.document("alone");
    let vex = ["vex", "--output", alone.to_str().expect("a path")];
    let vex = socket_patch(&cell, &standin, &vex);
    let (test, said) = (&cell.test, &vex.dump);
    assert_eq!(vex.code, 0, "{test}: {said}");
    assert_eq!(vex.envelope["status"], "partialFailure", "{test}: {said}");
    let ours = (canonical_purl(PURL), "skipped".into(), NOT_IN_BUILD.into());
    let absent = (
        canonical_purl(other),
        "skipped".into(),
        "package_not_found".into(),
    );
    assert_eq!(reported(&vex.envelope), [ours, absent], "{test}: {said}");
    let written: Value =
        serde_json::from_str(&std::fs::read_to_string(&alone).expect("a document"))
            .expect("a JSON document");
    let statuses: Vec<&Value> = (written["statements"].as_array().into_iter().flatten())
        .map(|statement| &statement["status"])
        .collect();
    assert_eq!(statuses, ["affected"], "{test}: {written:#}");
}

/// A second package in the checkout of `cell`, patched in its installed
/// copy alone, as agent mode leaves one: an entry of the lock as pnpm
/// writes one for a registry package, the patched files where
/// `pnpm install` puts them, and the patched file among the blobs. Gives
/// its patch, its purl and the record agent mode keeps in the manifest,
/// which names the advisory of the fixture's own patch.
fn second_installed_patch(cell: &Cell) -> (Patched, String, Value) {
    let second = Patched::new();
    let renamed = |text: &str| text.replace("upstream", "second");
    let (name, purl) = (renamed(NAME), renamed(PURL));
    let lock = text(&cell.tree(), LOCK);
    let snapshots = "\nsnapshots:\n";
    assert_eq!(lock.matches(snapshots).count(), 1, "{lock}");
    let entry = renamed(&lock_entry(&placeholder()));
    cell.write(
        LOCK,
        lock.replace(snapshots, &format!("\n{entry}{snapshots}")),
    );
    let store = renamed(&store());
    cell.write(&format!("{store}/package.json"), renamed(MANIFEST));
    cell.write(&format!("{store}/index.js"), &second.package.index_js);
    let link = cell.path(&format!("node_modules/{name}"));
    std::fs::create_dir_all(link.parent().expect("the scope")).expect("create the scope");
    std::os::unix::fs::symlink(store.replacen("node_modules/", "../", 1), &link)
        .expect("link the package");
    let mut record = record(&Package::upstream(), &second);
    record["purl"] = purl.as_str().into();
    record["exportedAt"] = record["publishedAt"].take();
    let patched = record["files"]["package/index.js"]["afterHash"].as_str();
    let blob = format!(".socket/blobs/{}", patched.expect("a hash"));
    cell.write(&blob, &second.package.index_js);
    (second, purl, record)
}

/// What `vex --output <path>` of `cell` says to a script and to a person,
/// in a checkout where it writes a document: it exits 0 both times. Gives
/// the envelope's status, its events (each as its purl, its action, its
/// code and the status of its details, in the order of the purls), the
/// verified and skipped counts of its summary, the codes of its warnings,
/// the statements of the document without their times, and the lines with
/// which it tells a person what it wrote: to the file, to the file had it
/// not been a dry run, and to stdout.
fn vex_says(cell: &Cell, standin: &StandIn, name: &str) -> (Value, Vec<Value>, [String; 3]) {
    let path = cell.document(name);
    let args = ["vex", "--output", path.to_str().expect("a path")];
    let vex = socket_patch(cell, standin, &args);
    let (test, said) = (&cell.test, &vex.dump);
    assert_eq!(vex.code, 0, "{test}: {said}");
    let events = vex.envelope["events"].as_array().into_iter().flatten();
    let mut events: Vec<Value> = events
        .map(|event| {
            let purl = canonical_purl(event["purl"].as_str().unwrap_or_default());
            let (code, status) = (&event["errorCode"], &event["details"]["status"]);
            json!([purl, event["action"], code, status])
        })
        .collect();
    events.sort_by_key(|event| event[0].as_str().map(str::to_string));
    let summary = &vex.envelope["summary"];
    let machine = json!({
        "status": vex.envelope["status"],
        "events": events,
        "verified": summary["verified"],
        "skipped": summary["skipped"],
        "warnings": codes_in(&vex.envelope["warnings"]),
    });
    let written = std::fs::read_to_string(&path).expect("a document");
    let mut document: Value = serde_json::from_str(&written).expect("a JSON document");
    let statements = document["statements"].as_array_mut().expect("statements");
    for statement in statements.iter_mut() {
        let object = statement.as_object_mut().expect("a statement");
        assert!(object.remove("timestamp").is_some(), "{written}");
    }
    let origin = standin.origin();
    let env = [("SOCKET_PATCH_SERVER_URL", origin.as_str())];
    let told = |args: &[&str], starts: &str| {
        let streams = cell.socket_patch_person(&origin, args, &env);
        assert!(!streams[1].contains("Error"), "{test}: {streams:?}");
        let mut lines = streams.iter().flat_map(|stream| stream.lines());
        let line = lines.find(|line| line.starts_with(starts));
        let line = line.unwrap_or_else(|| panic!("{test}: no {starts:?} line: {streams:?}"));
        line.replace(path.to_str().expect("a path"), "<path>")
    };
    let dry = [&args[..], &["--dry-run"]].concat();
    let wrote = [
        told(&args, "Wrote "),
        told(&dry, "[dry-run] "),
        told(&args[..1], "Emitted "),
    ];
    println!("{test}: the document of `vex`:\n{written}");
    (machine, std::mem::take(statements), wrote)
}

/// The statement of a document of the fixture's product about the package
/// `id` and the advisory of the fixture's patches, without its status.
fn about(id: &Value) -> Value {
    json!({
        "vulnerability": { "name": "GHSA-test-aaaa-bbbb", "aliases": ["CVE-2024-0001"] },
        "products": [{ "@id": PRODUCT, "subcomponents": [{ "@id": id }] }],
    })
}

/// Without a Bazel: a document says of each package what Bazel builds of
/// it. Hosted mode pinned the fixture's package in the lock, which rules_js
/// builds it from. The lock lists a second package, which is patched in its
/// installed copy alone, as agent mode leaves one, and both patches are for
/// the same advisory. `vex` and `apply --vex` exit 0, and their document
/// holds two statements for that advisory: the first package is not
/// affected, through its pin, and the second is affected, with what to do
/// about it. `vex` reports the first as verified and the second as
/// skipped, so the run is a partial failure, and tells a person how many
/// of the statements say affected; `apply --vex` counts them in its
/// envelope.
#[test]
fn a_document_says_of_each_package_what_bazel_builds_of_it() {
    let (cell, standin, patch, _) = checkout("");
    std::fs::remove_dir_all(cell.path("node_modules")).expect("remove the installed tree");
    pins_the_lock(&cell, &standin, &patch);
    let (second, purl, record) = second_installed_patch(&cell);
    let manifest = json!({ "patches": { purl.as_str(): record } });
    cell.write(".socket/manifest.json", manifest.to_string());

    let names = names(&cell, MODULE, LOCK);
    let (machine, statements, wrote) = vex_says(&cell, &standin, "each");
    let test = &cell.test;
    let (first, other) = (canonical_purl(PURL), canonical_purl(&purl));
    let expected = json!({
        "status": "partialFailure",
        "events": [
            [other, "skipped", NOT_IN_BUILD, "affected"],
            [first, "verified", null, "not_affected"],
        ],
        "verified": 1,
        "skipped": 1,
        "warnings": [NOT_IN_BUILD],
    });
    assert_eq!(machine, expected, "{test}");
    let told = [
        "Wrote OpenVEX document with 2 statements (1 affected) to <path>",
        "[dry-run] Would write OpenVEX document with 2 statements (1 affected) to <path>",
        "Emitted 2 VEX statements (1 affected)",
    ];
    assert_eq!(wrote, told, "{test}");

    let ids = statements
        .iter()
        .map(|statement| &statement["products"][0]["subcomponents"][0]["@id"]);
    let ids: Vec<&Value> = ids.collect();
    let mut expected = [about(ids[0]), about(ids[1])];
    expected[0]["status"] = "not_affected".into();
    expected[0]["justification"] = "inline_mitigations_already_exist".into();
    let impact = format!("Patched via Socket patch {} (redirected)", patch.uuid);
    expected[0]["impact_statement"] = impact.into();
    expected[1]["status"] = "affected".into();
    expected[1]["action_statement"] = action(&second, &names[0]).into();
    assert_eq!(statements, expected, "{test}");
    let named: Vec<String> = ids
        .iter()
        .map(|id| canonical_purl(id.as_str().unwrap_or_default()))
        .collect();
    assert_eq!(named, [first, other], "{test}");

    let in_run = cell.document("each-apply");
    let apply = [&["apply"][..], &with_vex(&in_run)].concat();
    let apply = socket_patch(&cell, &standin, &apply);
    let (summary, said) = (&apply.envelope["vex"], &apply.dump);
    assert_eq!(apply.code, 0, "{test}: {said}");
    let counted = [&summary["statements"], &summary["affected"]];
    assert_eq!(counted, [&json!(2), &json!(1)], "{test}: {said}");
    assert_eq!(
        codes_in(&summary["warnings"]),
        [NOT_IN_BUILD],
        "{test}: {said}"
    );
}

/// Without a Bazel: two packages that are patched in their installed
/// copies alone, by two patches for one advisory, while the hub reads the
/// lock that lists both. `vex` exits 0 with a document of two statements
/// for that advisory, one per package: each names its package alone, and
/// its action statement names the patch of that package. It reports both
/// as skipped and none as verified, warns of each, and tells a person that
/// both statements say affected.
#[test]
fn each_affected_package_of_an_advisory_has_a_statement_of_its_own() {
    let (cell, standin, patch, entry) = checkout("");
    let names = names(&cell, MODULE, LOCK);
    patches_the_installed_copy(&cell, &standin, "", &patch, &entry, Some(&names));
    let (second, purl, record) = second_installed_patch(&cell);
    let manifest = ".socket/manifest.json";
    let mut recorded: Value = serde_json::from_str(&text(&cell.tree(), manifest)).expect(manifest);
    recorded["patches"][purl.as_str()] = record;
    cell.write(manifest, recorded.to_string());

    let (machine, statements, wrote) = vex_says(&cell, &standin, "both");
    let test = &cell.test;
    let (first, other) = (canonical_purl(PURL), canonical_purl(&purl));
    let expected = json!({
        "status": "partialFailure",
        "events": [
            [other, "skipped", NOT_IN_BUILD, "affected"],
            [first, "skipped", NOT_IN_BUILD, "affected"],
        ],
        "verified": 0,
        "skipped": 2,
        "warnings": [NOT_IN_BUILD, NOT_IN_BUILD],
    });
    assert_eq!(machine, expected, "{test}");
    let told = [
        "Wrote OpenVEX document with 2 statements (2 affected) to <path>",
        "[dry-run] Would write OpenVEX document with 2 statements (2 affected) to <path>",
        "Emitted 2 VEX statements (2 affected)",
    ];
    assert_eq!(wrote, told, "{test}");

    let said: Vec<(String, Value)> = statements
        .iter()
        .map(|statement| {
            let id = &statement["products"][0]["subcomponents"][0]["@id"];
            let mut expected = about(id);
            expected["status"] = "affected".into();
            expected["action_statement"] = statement["action_statement"].clone();
            assert_eq!(*statement, expected, "{test}");
            let action = statement["action_statement"].clone();
            (canonical_purl(id.as_str().unwrap_or_default()), action)
        })
        .collect();
    let expected = [
        (other, json!(action(&second, &names[0]))),
        (first, json!(action(&patch, &names[0]))),
    ];
    assert_eq!(said, expected, "{test}");
}

/// Without a Bazel: a patch whose record names no advisory gets no
/// statement from any run, so the hub decides nothing for it. `apply --vex`
/// over that patch alone fails beside the hub as it fails in the same
/// checkout without a workspace file: the same exit code and envelope,
/// and the same lines for a person, none of them about Bazel.
#[test]
fn a_patch_without_an_advisory_fails_the_run_as_it_does_without_bazel() {
    let (cell, standin, patch, entry) = checkout("");
    let names = names(&cell, MODULE, LOCK);
    patches_the_installed_copy(&cell, &standin, "", &patch, &entry, Some(&names));

    let manifest = ".socket/manifest.json";
    let mut recorded: Value = serde_json::from_str(&text(&cell.tree(), manifest)).expect(manifest);
    let patches = recorded["patches"].as_object_mut().expect("the patches");
    for record in patches.values_mut() {
        record["vulnerabilities"] = json!({});
    }
    cell.write(
        manifest,
        serde_json::to_vec_pretty(&recorded).expect(manifest),
    );

    let document = cell.document("no-advisory");
    let apply = [&["apply"][..], &with_vex(&document)].concat();
    let origin = standin.origin();
    let env = [("SOCKET_PATCH_SERVER_URL", origin.as_str())];
    let run = || {
        let ran = socket_patch(&cell, &standin, &apply);
        let person = cell.socket_patch_person(&origin, &apply, &env);
        (ran.code, ran.envelope, person)
    };
    let beside = run();
    std::fs::remove_file(cell.path(MODULE)).expect(MODULE);
    assert_eq!(beside, run());

    let (code, envelope, [_, stderr]) = beside;
    let said = format!("{envelope:#}\n{stderr}");
    assert_eq!(code, 1, "{said}");
    let error = json!({
        "code": "no_applicable_patches",
        "message": "No applied patches with vulnerability metadata to attest.",
    });
    assert_eq!(envelope["error"], error, "{said}");
    assert!(!said.contains("Bazel"), "{said}");
    assert!(!document.exists(), "{said}");
}

/// What a case of a test below does to its checkout before the commands
/// run.
type Arrange = fn(&Cell);

/// The fixture's `MODULE.bazel` in `cell` with `label` as the lock its hub
/// reads.
fn reads(cell: &Cell, label: &str) {
    let module = text(&cell.tree(), MODULE);
    let own = format!("\"//:{LOCK}\"");
    assert!(module.contains(&own), "{module}");
    cell.write(MODULE, module.replace(&own, &format!("\"{label}\"")));
}

/// Without a Bazel: the package is affected wherever a workspace file
/// hands Bazel the lock of the project, which lists the package.
///
/// - The hub is in a file that `MODULE.bazel` includes, as a workspace
///   keeps the hubs of one language apart: the document names the call
///   in that file.
/// - The project is a directory of the workspace, and the hub reads the
///   project's lock.
/// - The project is a member of a pnpm workspace at the root, and the hub
///   reads the workspace's lock there, which names the project among its
///   importers. The patched copy is in the store at the root.
#[test]
fn an_installed_patch_is_affected_wherever_a_hub_reads_the_lock_of_the_project() {
    let included = "tools/npm.MODULE.bazel";
    let web = format!("web/{LOCK}");
    let cases: [(&str, bool, &str, &str, Arrange); 3] = [
        ("", false, included, LOCK, |cell| {
            let module = text(&cell.tree(), MODULE);
            let (head, hub) = module.split_once("npm = use_extension(").expect("the hub");
            let include = "include(\"//tools:npm.MODULE.bazel\")\n";
            cell.write(MODULE, format!("{head}{include}"));
            cell.write(
                "tools/npm.MODULE.bazel",
                format!("npm = use_extension({hub}"),
            );
        }),
        ("web/", false, MODULE, &web, |cell| {
            reads(cell, &format!("//web:{LOCK}"));
        }),
        ("web/", true, MODULE, LOCK, |_| ()),
    ];
    for (project, member, file, lock, arrange) in cases {
        let (mut cell, standin, patch, entry) = checkout_of(project, member);
        cell.test = format!("{project:?}, {member}, {file}, {lock}");
        arrange(&cell);
        let names = names(&cell, file, lock);
        patches_the_installed_copy(&cell, &standin, project, &patch, &entry, Some(&names));
    }
}

/// Without a Bazel: `scan --mode hosted --vex` over the patch that agent
/// mode left in the installed copy, at a patch service that has no hosted
/// artifact of it. The scan pins nothing, skips the package and passes, as
/// it does without `--vex`. Its document says the package is affected,
/// and names the call that builds it from the lock, in its envelope and as
/// a person runs it.
#[test]
fn an_installed_patch_is_affected_after_a_hosted_scan_that_pins_nothing() {
    let (cell, standin, patch, entry) = checkout("");
    let names = names(&cell, MODULE, LOCK);
    patches_the_installed_copy(&cell, &standin, "", &patch, &entry, Some(&names));
    let patched = cell.tree();
    drop(standin);
    let other = StandIn::start();
    let granted = Patch {
        purl: PURL.to_string(),
        uuid: patch.uuid.clone(),
        reference: json!({ "status": "granted", "purl": PURL }),
    };
    other.api(&[granted]);

    let document = cell.document("hosted");
    let hosted = ["scan", "--mode", "hosted", "--yes"];
    let hosted = [&hosted[..], &with_vex(&document)].concat();
    let scan = socket_patch(&cell, &other, &hosted);
    let (test, said) = (&cell.test, &scan.dump);
    let skipped = [(canonical_purl(PURL), "skipped".into(), "no_url".into())];
    assert_eq!(reported(&scan.envelope), skipped, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    // A hosted scan says of every document it writes that it hashed no
    // file for a hosted patch.
    let summary = &scan.envelope["vex"];
    let counted = [&summary["statements"], &summary["affected"]];
    assert_eq!(counted, [&json!(1), &json!(1)], "{test}: {said}");
    let warned = ["vex_hosted_unverified", NOT_IN_BUILD];
    assert_eq!(codes_in(&summary["warnings"]), warned, "{test}: {said}");
    let claim = Claim::unbuilt(PURL, &patch.uuid, &names);

    let origin = other.origin();
    let env = [("SOCKET_PATCH_SERVER_URL", origin.as_str())];
    let warned = warns(&patch, &names[0]);
    cell.tells_a_person(&origin, &hosted, &env, &document, &claim, &warned);
    let silent = [&hosted[..], &["--silent"]].concat();
    cell.tells_a_person(&origin, &silent, &env, &document, &claim, &warned);
    assert_eq!(changed(&patched, &cell.tree()), NOTHING, "{test}");
}

/// Without a Bazel: workspaces that give `socket-patch` no ground to say
/// that the package is affected, each made from the fixture's
/// `MODULE.bazel`. Every form says of the installed patch what it says in
/// a checkout without Bazel.
///
/// - The project is a directory of the workspace, and the hub reads the
///   lock of another directory beside it, which lists the package too:
///   Bazel builds nothing of this project.
/// - The project is a directory of the workspace with a lock of its own,
///   which no hub reads. The hub reads a lock at the root, above the
///   project, that lists the package too and does not name the project
///   among its importers: the lock of another project.
/// - The hub reads a lock below the project that lists the package too:
///   again the lock of another project.
/// - The hub's lines are a comment.
/// - The workspace cannot be read with certainty: it includes a file that
///   is not there, so calls may be missing from what was read.
/// - A `WORKSPACE` file defines repositories of its own, which the module
///   files do not show; Bazel 7 reads it beside them.
#[test]
fn an_installed_patch_is_attested_where_no_hub_is_shown_to_build_it() {
    let cases: [(&str, &str, Arrange); 6] = [
        ("the lock of another project", "web/", |cell| {
            let lock = text(&cell.tree(), &format!("web/{LOCK}"));
            cell.write(&format!("other/{LOCK}"), lock);
            reads(cell, &format!("//other:{LOCK}"));
        }),
        (
            "a lock above that does not name the project",
            "web/",
            |cell| {
                cell.write(LOCK, text(&cell.tree(), &format!("web/{LOCK}")));
            },
        ),
        ("a lock below the project", "", |cell| {
            cell.write(&format!("tools/{LOCK}"), text(&cell.tree(), LOCK));
            reads(cell, &format!("//tools:{LOCK}"));
        }),
        ("a hub in a comment", "", |cell| {
            let module = text(&cell.tree(), MODULE);
            let (head, hub) = module.split_once("npm = use_extension(").expect("the hub");
            let hub = format!("npm = use_extension({hub}");
            let comment: String = hub.lines().map(|line| format!("# {line}\n")).collect();
            cell.write(MODULE, format!("{head}{comment}"));
        }),
        ("an included file that is missing", "", |cell| {
            let module = text(&cell.tree(), MODULE);
            let include = "include(\"//tools:missing.MODULE.bazel\")\n";
            cell.write(MODULE, format!("{module}{include}"));
        }),
        ("a WORKSPACE file that defines repositories", "", |cell| {
            let rule = "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n";
            cell.write("WORKSPACE", rule);
        }),
    ];
    for (case, project, arrange) in cases {
        let (mut cell, standin, patch, entry) = checkout(project);
        cell.test = case.to_string();
        arrange(&cell);
        patches_the_installed_copy(&cell, &standin, project, &patch, &entry, None);
    }
}

/// Without a Bazel: what makes a package affected is a patch in a copy
/// Bazel does not build from, and a hosted pin is none. Here a second hub
/// reads a second lock in the project's directory, under a name of its
/// own, that lists the package without the patch, as the project's lock
/// did before hosted mode pinned it there. Hosted mode pins the project's
/// lock and no other, and its document and the one of `vex` attest the
/// package, as they do without the second hub. Whether Bazel links the
/// package from that other lock is not looked at yet. Nothing is installed
/// in this checkout: an installed copy without the patch leaves a hosted
/// pin out of the document with or without Bazel.
#[test]
fn a_hosted_pin_is_attested_beside_a_second_hub_that_lists_the_package() {
    let (cell, standin, patch, _) = checkout("");
    std::fs::remove_dir_all(cell.path("node_modules")).expect("remove the installed tree");
    let beside = format!("tools.{LOCK}");
    cell.write(&beside, text(&cell.tree(), LOCK));
    let module = text(&cell.tree(), MODULE);
    let second = format!(
        "npm.npm_translate_lock(\n    name = \"tools\",\n    pnpm_lock = \"//:{beside}\",\n)\n"
    );
    cell.write(
        MODULE,
        format!("{module}{second}use_repo(npm, \"tools\")\n"),
    );
    let pinned = pins_the_lock(&cell, &standin, &patch);
    assert!(text(&pinned, LOCK).contains(&patch.uuid), "{LOCK}");
    assert!(!text(&pinned, &beside).contains(&patch.uuid), "{beside}");
}

/// Without a Bazel, what stays fixed now that no sum is committed: the
/// fixture's directories and the legs of its workflow are those of its
/// table; the fixture's lock holds the one entry a test pins, with the
/// placeholder and no URL, and pinning changes nothing else; the fixture
/// depends on the package at the version of that entry and has the name
/// and the version of [`PRODUCT`]; two runs serve two upstream tarballs; and
/// the names written out above are those of the one package, under the
/// organisation's scope.
#[test]
fn a_test_pins_the_one_entry_of_the_fixture_lock() {
    FIXTURE.check();
    let common = fixture_path(FIXTURE.dir).join("common");
    let read = |rel: &str| std::fs::read_to_string(common.join(rel)).expect(rel);

    let upstream = Package::upstream();
    let pinned = lock_pinning(&upstream);
    let entry = lock_entry(&integrity(&upstream.tarball));
    assert!(pinned.contains(&entry), "no\n{entry}in\n{pinned}");
    let unpinned = pinned.replace(&entry, &lock_entry(&placeholder()));
    assert_eq!(unpinned, read(LOCK));
    assert_ne!(Package::upstream().tarball, upstream.tarball);

    let fixture: Value = serde_json::from_str(&read("package.json")).expect("package.json");
    assert_eq!(fixture["dependencies"][NAME], VERSION);
    let named = [&fixture["name"], &fixture["version"]].map(|field| field.as_str().expect("text"));
    assert_eq!(PRODUCT, format!("pkg:npm/{}@{}", named[0], named[1]));
    let manifest: Value = serde_json::from_str(MANIFEST).expect("the package's package.json");
    assert_eq!(manifest["name"], NAME);
    assert_eq!(manifest["version"], VERSION);
    let bare = NAME.strip_prefix("@socketsecurity/").expect("the scope");
    assert_eq!(PURL, format!("pkg:npm/%40socketsecurity/{bare}@{VERSION}"));
    assert_eq!(canonical_purl(PURL), format!("pkg:npm/{NAME}@{VERSION}"));
    assert_eq!(TGZ, format!("{bare}-{VERSION}.tgz"));
    assert_eq!(UPSTREAM_TGZ, format!("/{REGISTRY}/{NAME}/-/{TGZ}"));
}
