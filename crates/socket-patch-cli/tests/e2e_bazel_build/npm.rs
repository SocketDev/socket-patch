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
//!   vendored one reports it `already_vendored`, `vex` attests the package,
//!   no file changes, and the build is still the patched one.
//! - (d) The undo (`rollback --yes`, or `vendor --revert`): every file of
//!   the checkout is the one of before, byte for byte, and the build prints
//!   the unpatched marker again.
//! - (e) On a second machine (a new output base and, on Bazel 9, a new
//!   contents cache) the command runs against a second patch, and the
//!   pinned place holds other bytes: the patch host serves them (hosted),
//!   or they replace the committed file (vendored). The build fails on the
//!   checksum and does not take the registry's tarball in its place.
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

use crate::envelope::event_triples;
use crate::harness::{
    changed, fixture_path, rewrite, Cell, Fixture, Ran, Run, StandIn, Tree, CONSUMER, NOTHING,
};
use crate::hosted_memory_common::{Patch, ORG};

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
    let record = json!({
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
    });
    let record = serde_json::to_vec(&record).expect("a JSON document");
    let record_route = format!("/v0/orgs/{ORG}/patches/view/{}", patch.uuid);
    standin.serve(1, &record_route, &record);
    standin.serve(5, &patch.route, served);
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
/// a checkout without those links; `vex` attests the package in its
/// document; no file of the checkout changes; and the build still prints
/// `marker`.
fn runs_again(
    cell: &Cell,
    standin: &StandIn,
    mode: &str,
    seen: (&str, &str),
    patched: &Tree,
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

    let scan = socket_patch(cell, standin, &["scan", "--mode", mode, "--yes"]);
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    let seen = one(seen.0, seen.1);
    assert_eq!(reported(&scan.envelope), seen, "{test}: {said}");
    assert_eq!(scan.envelope["scannedPackages"], 1, "{test}: {said}");

    // The document goes beside the checkout, into the scratch root of the
    // cell, where nothing has that name: it is no file of the checkout, and
    // none of the machine's shared temp directory.
    let document = checkout.parent().expect("a scratch root").join("vex.json");
    assert!(!document.exists(), "{test}: {}", document.display());
    let output = document.to_string_lossy();
    let vex = socket_patch(cell, standin, &["vex", "--output", &output]);
    let said = &vex.dump;
    assert_eq!(vex.code, 0, "{test}: {said}");
    let attested = one("verified", "");
    assert_eq!(reported(&vex.envelope), attested, "{test}: {said}");
    let written = std::fs::read_to_string(&document).unwrap_or_default();
    // With its closing quote, as the document writes `"@id": "<purl>"`: a
    // longer version that only starts so is another package.
    let names = written.contains(&format!("\"{PURL}\""));
    assert!(names, "{test}: {said}\n{written}");

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
    let scan = socket_patch(&cell, &standin, &["scan", "--mode", "hosted", "--yes"]);
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

    // (c) The same build, no step in between: patched, from the patch host.
    let patched_fetches = standin.asked(&patch.route);
    cell.builds_patched(&pinned, &patch.package.marker);
    assert!(
        standin.asked(&patch.route) > patched_fetches,
        "{test}: the patched build did not fetch the tarball from the stand-in patch host"
    );

    // The same command and `vex`, now that Bazel has built in the checkout.
    let (seen, marker) = (("applied", ""), &patch.package.marker);
    runs_again(&cell, &standin, "hosted", seen, &pinned, marker);

    // (d) The undo: every file is the one of before, and so is the build.
    let undo = socket_patch(&cell, &standin, &["rollback", "--yes"]);
    cell.undone(&undo, "rolledBack", &before, &upstream.marker);

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
    let scan = socket_patch(&cell, &standin, &["scan", "--mode", "vendored", "--yes"]);
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

    // (c) The same build, no step in between: patched, from the committed
    // file. Bazel asks the stand-in for nothing.
    let requests = standin.requests();
    cell.builds_patched(&vendored, &patch.package.marker);
    assert_eq!(standin.requests(), requests, "{test}: Bazel asked a host");

    // The same command and `vex`, now that Bazel has built in the checkout.
    let (seen, marker) = (("skipped", "already_vendored"), &patch.package.marker);
    runs_again(&cell, &standin, "vendored", seen, &vendored, marker);

    // (d) The undo: every file is the one of before, and so is the build.
    let undo = socket_patch(&cell, &standin, &["vendor", "--revert"]);
    cell.undone(&undo, "removed", &before, &upstream.marker);

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

/// Without a Bazel, what stays fixed now that no sum is committed: the
/// fixture's directories and the legs of its workflow are those of its
/// table; the fixture's lock holds the one entry a test pins, with the
/// placeholder and no URL, and pinning changes nothing else; the fixture
/// depends on the package at the version of that entry; two runs serve two
/// upstream tarballs; and the names written out above are those of the one
/// package, under the organisation's scope.
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
    let manifest: Value = serde_json::from_str(MANIFEST).expect("the package's package.json");
    assert_eq!(manifest["name"], NAME);
    assert_eq!(manifest["version"], VERSION);
    let bare = NAME.strip_prefix("@socketsecurity/").expect("the scope");
    assert_eq!(PURL, format!("pkg:npm/%40socketsecurity/{bare}@{VERSION}"));
    assert_eq!(canonical_purl(PURL), format!("pkg:npm/{NAME}@{VERSION}"));
    assert_eq!(TGZ, format!("{bare}-{VERSION}.tgz"));
    assert_eq!(UPSTREAM_TGZ, format!("/{REGISTRY}/{NAME}/-/{TGZ}"));
}
