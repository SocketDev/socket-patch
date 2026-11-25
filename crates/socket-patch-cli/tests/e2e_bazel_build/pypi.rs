//! Hosted and vendored mode for a PyPI package that comes through
//! rules_python's `pip.parse(requirements_lock = "//:requirements.txt")`
//! under Bzlmod: a root `requirements.txt` in pip's hash-checking mode.
//!
//! The hosted flow, on the Bazel the run is given ([`FIXTURE`] says which
//! ruleset goes with its release), in a fresh output base:
//!
//! - (a) `bazel build` and `bazel run //:consumer` print the unpatched
//!   marker. The hub asked the index about the package, and Bazel fetched
//!   its wheel from there: the wheels of the index are built for the run,
//!   so no cache holds them.
//! - (b) `socket-patch scan --mode hosted --yes` rewrites
//!   `requirements.txt`, and nothing else: the pin of the package becomes a
//!   direct reference to the patched wheel, with its sha256. Where Bazel's
//!   lock records what the hub learned from the index (Bazel 8.5 and
//!   later), that leaves `MODULE.bazel.lock` stale: a build that may not
//!   update it (`--lockfile_mode=error`, as a CI with a frozen lock runs
//!   it) fails right after the scan, until a build that may update the
//!   lock, or `bazel mod deps --lockfile_mode=update`, has rewritten it
//!   and the user has committed that. On an older Bazel that build passes.
//! - (c) With no other step, the two Bazel commands of (a) print the
//!   patched marker. The wheel came from the stand-in patch host, and the
//!   hub did not ask the index about the package. Where Bazel's lock
//!   records what the hub learned from the index (Bazel 8.5 and later),
//!   that build rewrites `MODULE.bazel.lock`: the entry of the package
//!   goes, and nothing else changes. An older Bazel changes no file. The
//!   release decides which of the two the test expects. From then on the
//!   checkout stands: the next build changes no file, and a
//!   `--lockfile_mode=error` build passes.
//! - (d) `socket-patch rollback --yes` restores `requirements.txt` byte for
//!   byte, at once. Bazel's change to its own lock stays, so on Bazel 8.5
//!   and later the lock is stale again and a `--lockfile_mode=error` build
//!   fails right after the rollback as it did right after the scan. The
//!   next build that may update the lock asks the index about the package
//!   again, prints the unpatched marker and writes the lock of before:
//!   from then on every file of the checkout is the one of before.
//! - (e) On a second machine (a new output base), a patch service grants
//!   another patch of the package and its host serves other bytes than the
//!   grant pins: after the same `scan`, the build fails on the sha256.
//!
//! The marker is read from what Bazel built, and the patched one holds an
//! id made for the run, so no cache of an earlier run can supply it. The
//! flow asserts the VEX document of its patch as `main.rs` says.
//!
//! Vendored mode would commit the patched wheel and point the package's
//! line of `requirements.txt` at it, and rules_python builds no wheel from
//! such a line. So in this checkout, where the hub reads that file, the
//! command declines the package and writes nothing
//! ([`vendored_pip_parse`]): the build stays the unpatched one. With
//! `--allow-vendored-in-bazel` it does what it did before it declined, and
//! the build fails until `vendor --revert` has put the pin back. The flow
//! asserts that; that every form of `vex` meanwhile writes a document that
//! says the package is affected, and names the call of `MODULE.bazel` that
//! reads the file; that the revert brings the unpatched build back; and
//! that hosted mode, which the refusal and the document name, ends in the
//! patched build and in a document that says not affected.
//!
//! One loopback server stands in for four hosts. The Socket API and the
//! patch host answer at their own paths; `pypi.org` (the project pages of
//! the index, and the JSON document `rollback` reads through
//! `SOCKET_PYPI_JSON_API`) and `files.pythonhosted.org` (the two upstream
//! wheels) answer under a route prefix. rules_python fetches the index and
//! the wheels with Bazel's downloader, which takes a plain-http URL only
//! with a checksum, and an index page has none. So the hub keeps its
//! default index, `https://pypi.org/simple`, and a downloader config sends
//! Bazel to the stand-in, the way a mirror is configured ([`downloads`]).
//! It is there from the first build on, so step (c) changes no flag.
//!
//! No Bazel command of the flow reaches `pypi.org`. rules_python resolves
//! every hub of the build's modules when it resolves one, its own hub of
//! publishing tools among them, and an index page comes from no cache: on
//! the real index a run would ask for tens of pages, and for hundreds on
//! Bazel 7, whose lock records nothing of the index. The same downloader
//! config answers the page of every other project with one page of the
//! stand-in that lists no file, and blocks the host. A hub that finds no
//! file for a pin leaves the package to pip, and nothing starts that pip:
//! the build depends on no such package. What the rulesets download for
//! themselves still comes from the network: their archives and the Python
//! toolchain.
//!
//! The stand-in is not `patch.socket.dev`, so every `socket-patch` command
//! is told its origin (`SOCKET_PATCH_SERVER_URL`), as the operator of
//! another deployment does: `rollback` takes a URL on any other host for a
//! dependency of the user's own, not for a pin to undo.
//!
//! The fixture's `.bazelrc` selects rules_python's script bootstrap, so the
//! build and the run take no Python from the machine. (`scan` asks a
//! `python3` on `PATH` for its site-packages when there is one, and patches
//! the same without.)

use std::path::Path;
use std::time::Instant;

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha512};

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

use crate::harness::{
    cell_without_bazel, changed, fixture_path, rewrite, with_vex, Cell, Claim, Declined, Fixture,
    How, Ran, StandIn, Tree, ALLOW, CONSUMER, NOTHING, VENDORED,
};
use crate::hosted_memory_common::{read_tree, Patch, ORG};

// The wheel builder of the in-process Python suites. Its other helpers
// mount a grant on a server of those suites.
#[allow(dead_code)]
#[path = "../common/patched_wheel.rs"]
mod patched_wheel;

/// The workspace the test builds, and the ruleset each Bazel release
/// builds it with.
const FIXTURE: Fixture = Fixture {
    name: "pypi::FIXTURE",
    dir: "rules_python/bzlmod",
    workflow: "bazel-pypi.yml",
    eras: &[
        // rules_python 2.5.0-rc4, with the Python 3.11 of its toolchain.
        // It ran on Bazel 9.3.2, 8.8.2 and 7.7.2, the legs of the workflow:
        // every other release of the range is untested.
        ((7, 0, 0)..(10, 0, 0), "e9"),
    ],
};

/// The package the workspace requires, and the version `requirements.txt`
/// pins.
const NAME: &str = "spvictim";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:pypi/spvictim@1.0.0";
const UNPATCHED: &str = "OUT: PRISTINE";
/// The two hosts of the index, which are also the route prefixes of the
/// stand-in that plays them.
const INDEX: &str = "pypi.org";
const FILES: &str = "files.pythonhosted.org";
/// The route of the stand-in that answers for every project of the index
/// but the two of the test, with [`NO_FILES`].
const OTHER_PROJECTS: &str = "/pypi.org/simple/-/";
/// A project page that lists no file.
const NO_FILES: &str = "<!DOCTYPE html>\n<html><body>\n</body></html>\n";
const LOCK: &str = "MODULE.bazel.lock";
const REQUIREMENTS: &str = "requirements.txt";

/// A pure-Python wheel of one module.
struct Wheel {
    name: &'static str,
    version: &'static str,
    bytes: Vec<u8>,
    /// In hex, as `--hash=sha256:` and a grant spell it.
    sha256: String,
}

impl Wheel {
    /// `name` at `version`: `module` is its `__init__.py`, and `requires`
    /// are the distributions it depends on.
    fn new(name: &'static str, version: &'static str, requires: &[&str], module: &str) -> Wheel {
        let dist_info = format!("{name}-{version}.dist-info");
        let mut metadata = format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n");
        for distribution in requires {
            metadata.push_str(&format!("Requires-Dist: {distribution}\n"));
        }
        let (init, metadata_file) = (
            format!("{name}/__init__.py"),
            format!("{dist_info}/METADATA"),
        );
        let files = [
            (init.as_str(), module.as_bytes()),
            (metadata_file.as_str(), metadata.as_bytes()),
        ];
        let bytes = patched_wheel::build(&dist_info, &files);
        let sha256 = patched_wheel::sha256(&bytes);
        Wheel {
            name,
            version,
            bytes,
            sha256,
        }
    }

    /// Its file name, with the tags of [`patched_wheel::WHEEL`].
    fn filename(&self) -> String {
        format!("{}-{}-py2.py3-none-any.whl", self.name, self.version)
    }

    /// The entry of a hashed requirements file that pins this wheel, laid
    /// out as pip-compile writes it.
    fn requirement(&self) -> String {
        let (name, version) = (self.name, self.version);
        format!("{name}=={version} \\\n    --hash=sha256:{}\n", self.sha256)
    }

    /// Its project page on the index, as host and path.
    fn page(&self) -> String {
        format!("{INDEX}/simple/{}/", self.name)
    }

    /// Its file on the index, as host and path.
    fn file(&self) -> String {
        let (sha256, filename) = (&self.sha256, self.filename());
        let (first, second, rest) = (&sha256[..2], &sha256[2..4], &sha256[4..]);
        format!("{FILES}/packages/{first}/{second}/{rest}/{filename}")
    }
}

/// The package under test, built for the run `run`: its one function
/// returns `marker`. The id of the run is a comment of the module, so the
/// wheel has bytes, and a sha256, that no other run has: Bazel's repository
/// cache, which keeps every download that has a checksum, cannot hold it.
fn package(marker: &str, run: &str) -> Wheel {
    Wheel::new(NAME, VERSION, &["spdep"], &module(marker, run))
}

/// The one module of [`package`]: `spvictim/__init__.py`.
fn module(marker: &str, run: &str) -> String {
    format!("# Built for run {run}.\ndef value():\n    return \"{marker}\"\n")
}

/// The upstream wheels of the run `run`, as the index serves them: the
/// dependency of the package, which no patch touches, and the package.
fn upstream(run: &str) -> [Wheel; 2] {
    let module = format!("# Built for run {run}.\nNAME = \"spdep\"\n");
    let dependency = Wheel::new("spdep", "2.0.0", &[], &module);
    [dependency, package("PRISTINE", run)]
}

/// The `requirements.txt` that pins `wheels`: the test writes it into the
/// workspace copy, since the wheels of a run have a sha256 of their own.
fn requirements(wheels: &[Wheel]) -> String {
    wheels.iter().map(Wheel::requirement).collect()
}

/// Serve `wheel` on `standin` as the index does: its project page, which
/// links the file by its production URL and sha256, the file, and the JSON
/// document of the release. The page and the file are under
/// `/<host>/<path>`, where [`downloads`] sends Bazel.
fn publish(standin: &StandIn, wheel: &Wheel) {
    let (file, filename, sha256) = (wheel.file(), wheel.filename(), &wheel.sha256);
    let page = format!(
        "<!DOCTYPE html>\n<html><body>\n\
         <a href=\"https://{file}#sha256={sha256}\">{filename}</a><br />\n\
         </body></html>\n"
    );
    standin.serve(5, &format!("/{}", wheel.page()), page.as_bytes());
    standin.serve(5, &format!("/{file}"), &wheel.bytes);
    let release = json!({ "urls": [{
        "filename": filename,
        "url": format!("https://{file}"),
        "digests": { "sha256": sha256 },
    }] });
    let (name, version) = (wheel.name, wheel.version);
    let route = format!("/{INDEX}/pypi/{name}/{version}/json");
    let release = serde_json::to_vec(&release).expect("a JSON document");
    standin.serve(5, &route, &release);
}

/// The Socket API on `standin`: one free patch of the package, granted as a
/// wheel with the sha256 of `pinned` on the patch host this server plays.
/// Returns the route of that wheel, which is not served yet. The reference
/// is the one `patched_wheel::mount_grant` also writes, for a server of the
/// in-process suites: a change to the shape of a grant is a change to both.
fn grant(standin: &StandIn, uuid: &str, pinned: &Wheel) -> String {
    grant_by(standin, uuid, pinned, json!({ "sha256": pinned.sha256 }))
}

/// [`grant`] with `integrity` as the sums the grant names for the wheel.
fn grant_by(standin: &StandIn, uuid: &str, pinned: &Wheel, integrity: Value) -> String {
    let filename = pinned.filename();
    let route = format!("/patch/pypi/{NAME}/{VERSION}/grant-token/{uuid}/{filename}");
    let url = format!("{}{route}", standin.origin());
    let reference = json!({
        "status": "granted",
        "url": url,
        "purl": PURL,
        "artifacts": [{
            "kind": "tarball",
            "url": url,
            "integrity": integrity,
        }],
        "registryOverride": null,
    });
    let patch = Patch {
        purl: PURL.to_string(),
        uuid: uuid.to_string(),
        reference,
    };
    standin.api(&[patch]);
    route
}

/// The downloader config of the flow, for [`Cell::route_downloads`]: Bazel
/// fetches the project page and the file of each of `wheels` from the
/// stand-in at `origin`, and the page of any other project of the index
/// from [`OTHER_PROJECTS`] there. A URL on the index that no rule sends to
/// the stand-in is refused, so a build that would need the real index
/// fails instead of asking it. Every other download is left alone.
fn downloads(origin: &str, wheels: &[Wheel]) -> Vec<String> {
    let urls = wheels.iter().flat_map(|wheel| [wheel.page(), wheel.file()]);
    let mut rules: Vec<String> = urls.map(|url| rewrite(&url, origin)).collect();
    // Bazel tries every rule whose pattern matches a URL, as mirrors of one
    // another, so this one leaves out the projects that have a page. The
    // names are quoted like the prefix [`rewrite`] takes.
    let served: Vec<String> = wheels
        .iter()
        .map(|wheel| format!("\\Q{}\\E", wheel.name))
        .collect();
    rules.push(format!(
        "rewrite \\Q{INDEX}/simple/\\E(?!(?:{})/).* {origin}{OTHER_PROJECTS}",
        served.join("|")
    ));
    rules.push(format!("block {INDEX}"));
    rules
}

/// `lock` without what it files under the key `name`, at any depth.
fn forget(lock: &mut Value, name: &str) {
    match lock {
        Value::Object(entries) => {
            entries.remove(name);
            entries.values_mut().for_each(|entry| forget(entry, name));
        }
        Value::Array(items) => items.iter_mut().for_each(|item| forget(item, name)),
        _ => {}
    }
}

/// The build of a CI that holds Bazel's lock frozen, right after the
/// `socket-patch` command `after` and before any build that may update the
/// lock. `stale` says whether the command left the lock stale, which it
/// does exactly where the lock records what the hub learned from the index:
/// there Bazel must refuse the build over the facts the hub changed, and
/// elsewhere the build must pass.
fn frozen_build(cell: &Cell, after: &str, stale: bool) {
    let build = cell.bazel("build", &["--lockfile_mode=error", CONSUMER]);
    let refused = build.stderr().contains("has changed its facts");
    assert!(
        build.ok() != stale && refused == stale,
        "{}: right after `{after}`, a `--lockfile_mode=error` build on Bazel {} must {}. From \
         Bazel 8.5 on, {LOCK} is stale after the command: a user has to run a build that may \
         update it, or `bazel mod deps --lockfile_mode=update`, and commit the lock before a CI \
         with a frozen lock passes. An older Bazel keeps nothing of the index in its lock.\n{}",
        cell.test,
        cell.release(),
        if stale {
            "fail on the facts the hub changed"
        } else {
            "pass"
        },
        build.dump()
    );
}

/// The flow of the module docs.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn hosted_pip_parse() {
    let test = "pypi::hosted_pip_parse";
    let started = Instant::now();
    let Some(mut cell) = Cell::open(test, &FIXTURE) else {
        return;
    };
    let release = cell.release().to_string();

    // The wheels of this run. The patched one is the upstream package with
    // another `__init__.py`; all of them hold an id that is new for every
    // run.
    let uuid = uuid::Uuid::new_v4().to_string();
    let wheels = upstream(&uuid);
    let [dependency, pristine] = &wheels;
    let patched = package(&format!("PATCHED {uuid}"), &uuid);
    let marker = format!("OUT: PATCHED {uuid}");

    let standin = StandIn::start();
    let origin = standin.origin();
    wheels.iter().for_each(|wheel| publish(&standin, wheel));
    standin.serve(5, OTHER_PROJECTS, NO_FILES.as_bytes());
    let patched_route = grant(&standin, &uuid, &patched);
    standin.serve(5, &patched_route, &patched.bytes);
    let page = format!("/{}", pristine.page());
    let upstream_route = format!("/{}", pristine.file());
    let json_api = format!("{origin}/{INDEX}/pypi");
    let socket_patch = |cell: &Cell, api: &StandIn, args: &[&str]| -> Ran {
        let api = api.origin();
        let env = [
            ("SOCKET_PATCH_SERVER_URL", api.as_str()),
            ("SOCKET_PYPI_JSON_API", json_api.as_str()),
        ];
        cell.socket_patch(&api, args, &env)
    };
    cell.route_downloads(&downloads(&origin, &wheels));
    cell.write(REQUIREMENTS, requirements(&wheels));

    // (a) The unpatched build. The hub asked the stand-in index about the
    // package, and Bazel fetched the wheel of this run from it.
    let before = cell.builds_unpatched(UNPATCHED);
    assert!(
        standin.asked(&page) > 0,
        "{test}: the build did not ask the stand-in index about {NAME}"
    );
    assert!(
        standin.asked(&upstream_route) > 0,
        "{test}: the build did not fetch the upstream wheel from the stand-in"
    );
    // What the patched build has to make of Bazel's lock: the lock of
    // before without the index entry of the package. Bazel records such
    // entries from 8.5 on, so 9.3.2 and 8.8.2 have one to drop and 7.7.2
    // has none: each release is held to its case, and so to its undo.
    // 8.5.0 is read from Bazel's source: it is the first release whose
    // lock keeps the facts of a module extension (bazelbuild/bazel#27296;
    // `Facts.java` is in the tag 8.5.0 and not in 8.4.2), which is where
    // rules_python keeps what the index said. No release between 7.7.2
    // and 8.8.2 ran.
    let lock = |tree: &Tree| -> Value { serde_json::from_slice(&tree[LOCK]).expect("a JSON lock") };
    let mut patched_lock = lock(&before);
    forget(&mut patched_lock, NAME);
    let recorded = cell.numbers() >= (8, 5, 0);
    assert_eq!(
        patched_lock != lock(&before),
        recorded,
        "{test}: {LOCK} of Bazel {release} must hold an index entry of {NAME} from Bazel 8.5 on \
         and none before: the undo expected of a release follows from it"
    );
    let bazel_rewrites: &[&str] = if recorded { &[LOCK] } else { &[] };

    // (b) The one command of hosted mode. It rewrites that file and no
    // other: the pin of the dependency as it was, and the package as a
    // direct reference to the patched wheel with its sha256.
    let hosted = ["scan", "--mode", "hosted", "--yes"];
    let claim = Claim::new(PURL, &uuid, How::Hosted);
    let run = |cell: &Cell, args: &[&str]| socket_patch(cell, &standin, args);
    let in_run = cell.document("in-run");
    let scan = run(&cell, &[&hosted[..], &with_vex(&in_run)].concat());
    let said = &scan.dump;
    let pinned = cell.pinned_by(&scan, PURL, &uuid, &before, &[REQUIREMENTS]);
    let direct = format!("{NAME} @ {origin}{patched_route}");
    assert_eq!(
        String::from_utf8_lossy(&pinned[REQUIREMENTS]),
        format!(
            "{}{direct} --hash=sha256:{}\n",
            dependency.requirement(),
            patched.sha256
        ),
        "{test}"
    );
    // The document of that run and the one of `vex` say so, in a checkout
    // Bazel has built in, before anything has fetched the patched wheel.
    cell.wrote_in_run(&scan, &in_run, &claim);
    cell.stands_alone(run, &claim, true);
    assert_eq!(standin.asked(&patched_route), 0, "{test}: {said}");
    let index_requests = standin.asked(&page);
    // The scan left Bazel's lock as it was, so a frozen lock fails here
    // where that lock records the index.
    frozen_build(&cell, "scan --mode hosted", recorded);

    // (c) The build of (a) and no other step: patched, from the patch
    // host, and without a question to the index about the package.
    cell.builds(&marker);
    assert!(
        standin.asked(&patched_route) > 0,
        "{test}: the patched build did not fetch the wheel from the stand-in patch host"
    );
    assert_eq!(
        standin.asked(&page),
        index_requests,
        "{test}: the patched build asked the index about {NAME}"
    );
    // Bazel changed no file of the checkout but its own lock.
    let built = cell.tree();
    assert_eq!(changed(&pinned, &built), bazel_rewrites, "{test}");
    assert_eq!(lock(&built), patched_lock, "{test}: {LOCK}");
    // From here on the checkout stands: the next build changes no file,
    // and that lock holds when Bazel may not update it.
    cell.builds_patched(&built, &marker);
    // `vex` says the same of the build that printed the patched marker,
    // and with `--no-verify` that it checked no file.
    cell.stands_alone(run, &claim, true);
    cell.stands_alone(run, &claim, false);
    // Without a product, as a user types it, `vex` writes none: the
    // checkout has no file it reads a product from.
    cell.detects_product(run, None);

    // (d) The undo: `requirements.txt` is the one of before at once, and
    // the lock is still the one of the patched build, so a frozen lock
    // fails again where that lock records the index. The next build asks
    // the index about the package again, prints the unpatched marker and
    // puts the lock back. The step is written out and not `Cell::undone`,
    // which expects every file back before that build: here it is that
    // build which brings back Bazel's lock.
    let undo = socket_patch(&cell, &standin, &["rollback", "--yes"]);
    let said = &undo.dump;
    assert_eq!(undo.code, 0, "{test}: {said}");
    assert_eq!(undo.envelope["summary"]["rolledBack"], 1, "{test}: {said}");
    let restored = cell.tree();
    assert_eq!(changed(&built, &restored), [REQUIREMENTS], "{test}: {said}");
    assert_eq!(
        changed(&before, &restored),
        bazel_rewrites,
        "{test}: {said}"
    );
    frozen_build(&cell, "rollback", recorded);
    cell.builds(UNPATCHED);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}");
    assert!(
        standin.asked(&page) > index_requests,
        "{test}: the build after the undo did not ask the index about {NAME}"
    );
    // `vex` has no document for the checkout of before.
    cell.attests_nothing(run, 2, "manifest_not_found");
    // The same two documents where no Bazel has built.
    cell.attests_unbuilt(run, &hosted, &before, &pinned, &claim);

    // (e) A second machine. Bazel keeps a download that has a checksum in
    // the repository cache, which the two machines share, so this one gets
    // a patch whose wheel no machine has fetched: another service grants
    // it, and its host serves other bytes than the grant pins. The build
    // has to ask that host, and must fail on the sha256.
    let twin = cell.twin();
    let other = uuid::Uuid::new_v4().to_string();
    let granted = package(&format!("PATCHED {other}"), &other);
    let rogue = StandIn::start();
    let rogue_route = grant(&rogue, &other, &granted);
    rogue.serve(5, &rogue_route, &package("TAMPERED", &other).bytes);
    let scan = socket_patch(&twin, &rogue, &["scan", "--mode", "hosted", "--yes"]);
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    let build = twin.bazel("build", &[CONSUMER]);
    assert!(
        !build.ok(),
        "{test}: the tampered wheel built:\n{}",
        build.dump()
    );
    let digest = hex::decode(&granted.sha256).expect("a hex digest");
    let digest = base64::engine::general_purpose::STANDARD.encode(digest);
    let refusal = format!("but wanted sha256-{digest}");
    assert!(
        build.stderr().contains(&refusal),
        "{test}: the build did not fail on the sha256 of the granted wheel:\n{}",
        build.dump()
    );
    assert!(
        rogue.asked(&rogue_route) > 0,
        "{test}: the patch host was not asked, so the failed build proves nothing"
    );

    println!(
        "{test}: Bazel {release} built {marker:?} from `{direct}` after `scan --mode hosted`, and \
         rewrote {bazel_rewrites:?} itself; a `--lockfile_mode=error` build right after the scan, \
         and again right after `rollback`, {}; `rollback` restored {REQUIREMENTS} at once, and \
         the next build printed {UNPATCHED:?} and left all {} files as before; other bytes at the \
         patch host failed a second machine's build ({refusal}); the stand-in answered {} \
         requests for the project page, {} for the upstream wheel, {} for the patched wheel and \
         {} for the pages of other projects; {:?}",
        if recorded {
            "failed on the stale lock"
        } else {
            "passed"
        },
        before.len(),
        standin.asked(&page),
        standin.asked(&upstream_route),
        standin.asked(&patched_route),
        standin.asked(OTHER_PROJECTS),
        started.elapsed()
    );
}

/// What the vendored flow patches with: the upstream wheels of a run on a
/// stand-in index, and one patch of the package, which the Socket API on
/// the stand-in grants as a wheel on its patch host and records with the
/// hashes of the module it changes. Vendored mode holds the wheel it
/// downloads to that record.
struct Vendoring {
    standin: StandIn,
    /// The id of the run and of its patch.
    uuid: String,
    wheels: [Wheel; 2],
    patched: Wheel,
    /// The route of the patched wheel on the stand-in's patch host.
    route: String,
    /// The record of the patch, as the API serves it.
    record: Value,
}

/// The line of `requirements.txt` that vendored mode puts in the place of
/// the package's pin: the path of the committed wheel `copy`, its sha256,
/// and the pin it stands for.
fn vendored_line(copy: &str, wheel: &Wheel) -> String {
    let (sha256, name, version) = (&wheel.sha256, wheel.name, wheel.version);
    format!("./{copy} --hash=sha256:{sha256}  # socket-patch vendor: {name}=={version}\n")
}

impl Vendoring {
    fn new() -> Vendoring {
        let uuid = uuid::Uuid::new_v4().to_string();
        let wheels = upstream(&uuid);
        let marker = format!("PATCHED {uuid}");
        let patched = package(&marker, &uuid);
        let standin = StandIn::start();
        wheels.iter().for_each(|wheel| publish(&standin, wheel));
        standin.serve(5, OTHER_PROJECTS, NO_FILES.as_bytes());
        // Vendored mode downloads the wheel itself, and takes it only by
        // its sha512.
        let sha512 =
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&patched.bytes));
        let sums = json!({ "sha256": patched.sha256, "sha512": format!("sha512-{sha512}") });
        let route = grant_by(&standin, &uuid, &patched, sums);
        standin.serve(5, &route, &patched.bytes);
        let hash = |marker: &str| compute_git_sha256_from_bytes(module(marker, &uuid).as_bytes());
        let record = json!({
            "uuid": uuid,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": { "spvictim/__init__.py": {
                "beforeHash": hash("PRISTINE"),
                "afterHash": hash(&marker),
            }},
            "vulnerabilities": { "GHSA-test-aaaa-bbbb": {
                "cves": ["CVE-2024-0001"], "summary": "s", "severity": "high", "description": "d",
            }},
            "description": "fixture",
            "license": "MIT",
            "tier": "free",
        });
        let record_route = format!("/v0/orgs/{ORG}/patches/view/{uuid}");
        standin.serve(1, &record_route, record.to_string().as_bytes());
        Vendoring {
            standin,
            uuid,
            wheels,
            patched,
            route,
            record,
        }
    }

    /// `socket-patch <args>` in `cell`, with the stand-in as the Socket
    /// API, the patch server and the index's JSON API.
    fn run(&self, cell: &Cell, args: &[&str]) -> Ran {
        self.run_with(cell, args, &[])
    }

    /// [`Vendoring::run`] with the variables `more` as well.
    fn run_with(&self, cell: &Cell, args: &[&str], more: &[(&str, &str)]) -> Ran {
        let origin = self.standin.origin();
        let json_api = format!("{origin}/{INDEX}/pypi");
        let env = [
            ("SOCKET_PATCH_SERVER_URL", origin.as_str()),
            ("SOCKET_PYPI_JSON_API", json_api.as_str()),
        ];
        cell.socket_patch(&origin, args, &[&env[..], more].concat())
    }
}

/// The code under which vendored mode declines a package whose
/// requirements a hub of the workspace reads.
const DECLINED: &str = "vendor_pypi_bazel_hub";

/// The line of the `MODULE.bazel` of `cell` that calls the hub.
fn hub_line(cell: &Cell) -> usize {
    let module = String::from_utf8(cell.tree()["MODULE.bazel"].clone()).expect("a text file");
    let above = module.lines().take_while(|line| *line != "pip.parse(");
    above.count() + 1
}

/// What a refusal of vendored mode has to name in the checkout of `cell`:
/// the hub's call with its line in `MODULE.bazel`, and the file it reads.
fn refusal_names(cell: &Cell) -> [String; 2] {
    let call = format!("`pip.parse` (MODULE.bazel:{})", hub_line(cell));
    [call, format!("names {REQUIREMENTS}; ")]
}

/// What `socket-patch` has to name when it says that the package is
/// affected: the file that points at the committed wheel, the hub's call
/// with its line in the `MODULE.bazel` of `cell`, and the two commands
/// that patch what Bazel builds.
fn names(cell: &Cell) -> Vec<String> {
    vec![
        format!("the line of {REQUIREMENTS} that points at"),
        format!("(`pip.parse`, MODULE.bazel:{})", hub_line(cell)),
        "`socket-patch vendor --revert`, then `socket-patch scan --mode hosted`".to_string(),
    ]
}

/// Vendored mode on the user's word in the checkout of `cell`, whose
/// `requirements.txt` pins the wheels of `with` and is read by the hub:
/// `scan --mode vendored --yes --allow-vendored-in-bazel` commits the
/// patched wheel under `.socket/vendor/pypi` and points the package's line
/// of `requirements.txt` at it. The command passes, and with `--vex` it
/// writes a document that says the package is affected; so do
/// `apply --vex` and `vendor --vex`, and `vex` and `vex --no-verify`. Each
/// names the call of `MODULE.bazel` that hands `requirements.txt` to
/// rules_python, and the way out. Gives the files of the checkout.
fn vendors_the_wheel(cell: &Cell, with: &Vendoring) -> Tree {
    let test = &cell.test;
    let before = cell.tree();
    let run = |cell: &Cell, args: &[&str]| with.run(cell, args);

    let in_run = cell.document("in-run");
    let scan = run(
        cell,
        &[&VENDORED[..], &[ALLOW], &with_vex(&in_run)].concat(),
    );
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    // The wheel the patch host served, with its ledger under
    // `.socket/vendor`, and the one file that names it.
    let vendored = cell.tree();
    let dir = format!(".socket/vendor/pypi/{}", with.uuid);
    let copy = format!("{dir}/{}", with.patched.filename());
    let written = [
        format!("{dir}/.gitattributes"),
        format!("{dir}/.gitignore"),
        format!("{dir}/socket-patch.vendor.json"),
        copy.clone(),
        ".socket/vendor/state.json".to_string(),
        REQUIREMENTS.to_string(),
    ];
    assert_eq!(changed(&before, &vendored), written, "{test}: {said}");
    assert!(vendored[&copy] == with.patched.bytes, "{test}: {copy}");
    let [dependency, _] = &with.wheels;
    let rewritten = dependency.requirement() + &vendored_line(&copy, &with.patched);
    let requirements = String::from_utf8_lossy(&vendored[REQUIREMENTS]);
    assert_eq!(requirements, rewritten, "{test}: {said}");

    let names = names(cell);
    let claim = Claim::unbuilt(PURL, &with.uuid, &names);
    cell.wrote_in_run(&scan, &in_run, &claim);
    // A vendored checkout has no manifest: the two commands have nothing
    // to do, and write the document the scan wrote.
    for command in ["apply", "vendor"] {
        let document = cell.document(command);
        let ran = run(cell, &[&[command][..], &with_vex(&document)].concat());
        assert_eq!(ran.envelope["status"], "noManifest", "{test}: {}", ran.dump);
        cell.wrote_in_run(&ran, &document, &claim);
    }
    cell.stands_alone(run, &claim, true);
    cell.stands_alone(run, &claim, false);
    assert_eq!(changed(&vendored, &cell.tree()), NOTHING, "{test}");
    vendored
}

/// The second thing the document of an affected package tells the user to
/// do, in the checkout of `cell` whose files `vendor --revert` has put back
/// as they were in `before`: `scan --mode hosted --yes` pins the patch of
/// `with` in `requirements.txt`. Its document and the one of `vex` attest
/// the package, through the pin.
fn pins(cell: &Cell, with: &Vendoring, before: &Tree) {
    let run = |cell: &Cell, args: &[&str]| with.run(cell, args);
    let claim = Claim::new(PURL, &with.uuid, How::Hosted);
    let document = cell.document("hosted");
    let hosted = ["scan", "--mode", "hosted", "--yes"];
    let scan = run(cell, &[&hosted[..], &with_vex(&document)].concat());
    cell.pinned_by(&scan, PURL, &with.uuid, before, &[REQUIREMENTS]);
    cell.wrote_in_run(&scan, &document, &claim);
    cell.stands_alone(run, &claim, true);
}

/// Vendored mode where it declines: `socket-patch <args>` in `cell` ends
/// with `exit` and reports the package under [`DECLINED`], as the one event
/// `action`, in words that name the hub's call, the file it reads, hosted
/// mode and the switch. No file of the checkout differs from `before`.
fn declines(cell: &Cell, with: &Vendoring, args: &[&str], exit: i32, action: &str, before: &Tree) {
    let names = refusal_names(cell);
    let package = Declined {
        purl: PURL,
        code: DECLINED,
        names: &names.each_ref().map(String::as_str),
    };
    cell.declined(&with.run(cell, args), &package, exit, action, before);
}

/// Vendored mode beside a hub that reads `requirements.txt`.
///
/// - (a) `bazel build` and `bazel run //:consumer` print the unpatched
///   marker.
/// - (b) `scan --mode vendored --yes` declines the package: it exits 1,
///   names the call of `MODULE.bazel` that reads the file, hosted mode and
///   the switch, writes nothing and downloads no wheel. The same two Bazel
///   commands print the unpatched marker, and change no file.
/// - (c) With `--allow-vendored-in-bazel` the command does what it did
///   before it declined ([`vendors_the_wheel`]): it commits the patched
///   wheel and points the package's line of `requirements.txt` at it. It
///   passes, and it and every other form of `vex` write a document that
///   says the package is affected: each names the call of `MODULE.bazel`
///   that reads the file, and the way out. The same `bazel build` fails,
///   as the document said it may: rules_python takes the path of that
///   line for the name of a project and leaves the hub without a
///   repository it can name. No build holds the patched wheel, and `vex`
///   says affected again.
/// - (d) What the document says to do: `vendor --revert` puts every file
///   back, and the same two Bazel commands print the unpatched marker
///   again. `scan --mode hosted --yes` then pins the patch in
///   `requirements.txt` ([`pins`]), the two commands print the patched
///   marker, and `vex` attests the package as not affected.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn vendored_pip_parse() {
    let test = "pypi::vendored_pip_parse";
    let started = Instant::now();
    let Some(mut cell) = Cell::open(test, &FIXTURE) else {
        return;
    };
    let release = cell.release().to_string();
    let with = Vendoring::new();
    cell.route_downloads(&downloads(&with.standin.origin(), &with.wheels));
    cell.write(REQUIREMENTS, requirements(&with.wheels));

    // (a) The unpatched build.
    let before = cell.builds_unpatched(UNPATCHED);

    // (b) The one command of vendored mode: declined, with nothing written
    // and nothing of the patch fetched. The same build passes, on the
    // upstream package.
    declines(&cell, &with, &VENDORED, 1, "failed", &before);
    assert_eq!(with.standin.asked(&with.route), 0, "{test}");
    cell.builds_patched(&before, UNPATCHED);

    // (c) On the user's word vendored mode commits the wheel, and says it
    // is affected. The build fails on the line that names the committed
    // wheel, and changes no file of the checkout: rules_python makes the
    // name of a repository from the path, and Bazel takes no such name. A
    // console may break the message, so it is compared without white space.
    let vendored = vendors_the_wheel(&cell, &with);
    let build = cell.bazel("build", &[CONSUMER]);
    let named = format!(
        "invalid user-provided repo name 'pip_311__/_socket/vendor/pypi/{}/{}'",
        with.uuid.replace('-', "_"),
        with.patched.filename().replace(['-', '.'], "_")
    );
    let squeezed = |text: &str| text.split_whitespace().collect::<String>();
    assert!(
        !build.ok() && squeezed(&build.stderr()).contains(&squeezed(&named)),
        "{test}: the build did not fail on the vendored line ({named}):\n{}",
        build.dump()
    );
    assert_eq!(changed(&vendored, &cell.tree()), NOTHING, "{test}");
    let run = |cell: &Cell, args: &[&str]| with.run(cell, args);
    let names = names(&cell);
    cell.stands_alone(run, &Claim::unbuilt(PURL, &with.uuid, &names), true);

    // (d) The way out: the undo, which brings the files and the build
    // back, then hosted mode, whose pin Bazel builds.
    let undo = run(&cell, &["vendor", "--revert", "--yes"]);
    cell.undone(&undo, "removed", &before, UNPATCHED);
    pins(&cell, &with, &before);
    let marker = format!("OUT: PATCHED {}", with.uuid);
    cell.builds(&marker);
    let claim = Claim::new(PURL, &with.uuid, How::Hosted);
    cell.stands_alone(run, &claim, true);

    println!(
        "{test}: Bazel {release} built {UNPATCHED:?}; `scan --mode vendored` declined \
         ({DECLINED}), wrote nothing, and the build stayed {UNPATCHED:?}; with {ALLOW} it \
         vendored the wheel and the build failed ({named}), while every form of `vex` said the \
         package is affected; after `vendor --revert` it built {UNPATCHED:?} again, and after \
         `scan --mode hosted` {marker:?}, and `vex` said it is not affected; {:?}",
        started.elapsed()
    );
}

/// Without a Bazel: the fixture in a checkout of its own, with the
/// `requirements.txt` that pins the wheels of `with`.
fn checkout(with: &Vendoring) -> Cell {
    let cell = cell_without_bazel("9.3.2");
    for part in ["common", "e9"] {
        for (rel, bytes) in read_tree(&fixture_path(FIXTURE.dir).join(part)) {
            cell.write(&rel, bytes);
        }
    }
    cell.write(".git/HEAD", "ref: refs/heads/main\n");
    cell.write(REQUIREMENTS, requirements(&with.wheels));
    cell
}

/// Without a Bazel: steps (c) and (d) of [`vendored_pip_parse`] in the
/// fixture's checkout, where `MODULE.bazel` hands `requirements.txt` to
/// rules_python, so a vendored run that writes the line has the switch.
/// Between them, `scan --mode vendored --vex`, `vendor --vex` and
/// `apply --vex` as a person runs them, with no switch, since the file
/// already names the copy: each passes and writes the document, with the
/// warning on stderr, the line that it wrote a document on stdout, and no
/// error; with `--silent` each passes, writes the document and prints
/// nothing. After them, `vendor --vex` moves the hosted pin into a
/// committed copy again, and says affected again.
#[test]
fn a_vendored_wheel_is_affected_beside_a_hub_that_reads_the_requirements() {
    let with = Vendoring::new();
    let cell = checkout(&with);
    let before = cell.tree();
    let names = names(&cell);
    assert_eq!(names[1], "(`pip.parse`, MODULE.bazel:15)");
    let vendored = vendors_the_wheel(&cell, &with);

    let origin = with.standin.origin();
    let document = cell.document("person");
    let env = [("SOCKET_PATCH_SERVER_URL", origin.as_str())];
    let warned = format!(
        "Warning: {PURL}: the VEX document says affected. Bazel builds no package from {} the \
         copy of Socket patch {} under .socket/vendor {}: the build fails, or takes the \
         registry's package. Run {}.",
        names[0], with.uuid, names[1], names[2]
    );
    let claim = Claim::unbuilt(PURL, &with.uuid, &names);
    for command in [&VENDORED[..], &["vendor"], &["apply"]] {
        let loud = [command, &with_vex(&document)].concat();
        cell.tells_a_person(&origin, &loud, &env, &document, &claim, &warned);
        let silent = [&loud[..], &["--silent"]].concat();
        cell.tells_a_person(&origin, &silent, &env, &document, &claim, &warned);
    }
    assert_eq!(changed(&vendored, &cell.tree()), NOTHING);

    let undo = with.run(&cell, &["vendor", "--revert", "--yes"]);
    assert_eq!(undo.envelope["summary"]["removed"], 1, "{}", undo.dump);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{}", undo.dump);
    pins(&cell, &with, &before);

    // `vendor` in a checkout of hosted pins commits a copy of each: the
    // line of `requirements.txt` points at the wheel again.
    let ejected = cell.document("eject");
    let eject = [&["vendor", "--yes", ALLOW][..], &with_vex(&ejected)].concat();
    let eject = with.run(&cell, &eject);
    assert_eq!(eject.envelope["status"], "success", "{}", eject.dump);
    cell.wrote_in_run(&eject, &ejected, &claim);
    let line = String::from_utf8_lossy(&cell.tree()[REQUIREMENTS]).into_owned();
    assert!(line.contains(".socket/vendor/pypi/"), "{line}");
}

/// Without a Bazel: `vendor --vex` on the user's word in a checkout whose
/// manifest records the patch, as agent mode leaves one. It commits the
/// wheel, points `requirements.txt` at it, and passes; its document says
/// the package is affected and names the call that reads the file, as the
/// scan of [`vendors_the_wheel`] does.
#[test]
fn a_wheel_vendored_from_a_manifest_is_affected_beside_the_hub() {
    let with = Vendoring::new();
    let cell = checkout(&with);
    let mut record = with.record.clone();
    record["exportedAt"] = record["publishedAt"].take();
    let manifest = json!({ "patches": { PURL: record } });
    cell.write(".socket/manifest.json", manifest.to_string());

    let document = cell.document("vendor");
    let vendor = [&["vendor", "--yes", ALLOW][..], &with_vex(&document)].concat();
    let vendor = with.run(&cell, &vendor);
    let line = String::from_utf8_lossy(&cell.tree()[REQUIREMENTS]).into_owned();
    assert!(
        line.contains(".socket/vendor/pypi/"),
        "{line}\n{}",
        vendor.dump
    );
    assert_eq!(vendor.envelope["status"], "success", "{}", vendor.dump);
    let names = names(&cell);
    cell.wrote_in_run(
        &vendor,
        &document,
        &Claim::unbuilt(PURL, &with.uuid, &names),
    );
}

/// Without a Bazel: `vex` with a `--manifest-path` in another project
/// attests that project, and asks the workspace about the files of that
/// project. The checkout holds `svc`, where vendored mode pointed
/// `requirements.txt` at the wheel on the user's word, and `app`, where the
/// command is run.
/// While the hub reads the file of `svc`, the document says the package
/// is affected and names that file. While it reads the file of `app`,
/// which pins the same release, the wheel of `svc` is attested as
/// patched: no call hands Bazel the file that points at it.
#[test]
fn a_vendored_wheel_is_judged_by_the_files_of_the_manifest_s_project() {
    let with = Vendoring::new();
    let cell = checkout(&with);
    std::fs::remove_file(cell.path(REQUIREMENTS)).expect(REQUIREMENTS);
    for project in ["svc", "app"] {
        cell.write(
            &format!("{project}/{REQUIREMENTS}"),
            requirements(&with.wheels),
        );
    }
    let module = String::from_utf8(cell.tree()["MODULE.bazel"].clone()).expect("a text file");
    let own = format!("\"//:{REQUIREMENTS}\"");
    assert!(module.contains(&own), "{module}");
    let reads = |project: &str| {
        let label = format!("\"//{project}:{REQUIREMENTS}\"");
        cell.write("MODULE.bazel", module.replace(&own, &label));
    };
    reads("svc");
    let vendoring = [&VENDORED[..], &[ALLOW, "--cwd", "svc"]].concat();
    let scan = with.run(&cell, &vendoring);
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{}", scan.dump);

    let foreign = [
        "--cwd",
        "app",
        "--manifest-path",
        "../svc/.socket/manifest.json",
    ];
    let run = |cell: &Cell, args: &[&str]| with.run(cell, &[args, &foreign].concat());
    let mut names = names(&cell);
    names[0] = format!("the line of svc/{REQUIREMENTS} that points at");
    cell.stands_alone(run, &Claim::unbuilt(PURL, &with.uuid, &names), true);

    reads("app");
    let claim = Claim::new(PURL, &with.uuid, How::Vendored);
    cell.stands_alone(run, &claim, true);
}

/// Without a Bazel: in the fixture's checkout, where the hub reads
/// `requirements.txt`, every command that would vendor the package declines
/// it, writes nothing and fetches no wheel. On the user's word vendored
/// mode goes on, and a later run without it passes and writes nothing: the
/// file the hub reads already names the copy.
#[test]
fn every_command_that_would_vendor_declines_beside_a_hub_that_reads_the_requirements() {
    let with = Vendoring::new();
    let cell = checkout(&with);
    let names = refusal_names(&cell);
    let package = Declined {
        purl: PURL,
        code: DECLINED,
        names: &names.each_ref().map(String::as_str),
    };
    let run = |cell: &Cell, args: &[&str], env: &[(&str, &str)]| with.run_with(cell, args, env);
    let before = cell.tree();
    cell.declines_every_vendoring(run, &package);
    assert_eq!(with.standin.asked(&with.route), 0);
    let undo = with.run(&cell, &["rollback", "--yes"]);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{}", undo.dump);
    cell.vendors_on_the_users_word(run, &package);
}

/// Without a Bazel: the refusal is for a run that would write a file a hub
/// reads, and for no other. In a workspace whose hub reads another file, in
/// a project beside the one whose file it reads, and in no workspace at
/// all, vendored mode vendors the package as it did, with no switch. So it
/// does in a Poetry project beside a hub that reads the requirements file
/// exported from its lock: the lock is wired alone, the file the hub reads
/// stays as it is, and a later run passes. Where the file the hub is given
/// is not written out in `MODULE.bazel`, and where `MODULE.bazel` has a
/// byte that is not UTF-8 (Bazel takes such a file, and the call in it is
/// not seen here), the package is declined, and the refusal names the
/// place and the reason.
#[test]
fn vendored_mode_goes_on_where_no_hub_reads_the_requirements() {
    let with = Vendoring::new();
    let own = format!("\"//:{REQUIREMENTS}\"");
    let module = |cell: &Cell| String::from_utf8(cell.tree()["MODULE.bazel"].clone()).unwrap();
    let vendors = |cell: &Cell, args: &[&str]| {
        let scan = with.run(cell, &[&VENDORED[..], args].concat());
        assert_eq!(scan.code, 0, "{}", scan.dump);
        assert_eq!(scan.envelope["summary"]["applied"], 1, "{}", scan.dump);
    };
    // Another file of the same project.
    let cell = checkout(&with);
    cell.write(
        "MODULE.bazel",
        module(&cell).replace(&own, "\"//:requirements_lock.txt\""),
    );
    vendors(&cell, &[]);
    // The file of another project, and no workspace file at all.
    let cell = checkout(&with);
    cell.write(&format!("svc/{REQUIREMENTS}"), requirements(&with.wheels));
    vendors(&cell, &["--cwd", "svc"]);
    std::fs::remove_file(cell.path("MODULE.bazel")).expect("MODULE.bazel");
    let undo = with.run(&cell, &["vendor", "--revert", "--yes", "--cwd", "svc"]);
    assert_eq!(undo.code, 0, "{}", undo.dump);
    vendors(&cell, &[]);
    // A Poetry project, whose lock is the one file a run points at the
    // copy. The hub reads the requirements file exported from it.
    let cell = checkout(&with);
    let [_, upstream] = &with.wheels;
    let poetry = format!(
        "[[package]]\nname = \"{NAME}\"\nversion = \"{VERSION}\"\ndescription = \"\"\n\
         optional = false\npython-versions = \">=3.9\"\ngroups = [\"main\"]\nfiles = [\n    \
         {{file = \"{}\", hash = \"sha256:{}\"}},\n]\n\n[metadata]\nlock-version = \"2.1\"\n\
         python-versions = \">=3.9\"\ncontent-hash = \"{}\"\n",
        upstream.filename(),
        upstream.sha256,
        upstream.sha256
    );
    cell.write("poetry.lock", poetry);
    let project = format!(
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\ndescription = \"\"\n\
         authors = []\npackage-mode = false\n\n[tool.poetry.dependencies]\n\
         python = \">=3.9\"\n{NAME} = \"{VERSION}\"\n"
    );
    cell.write("pyproject.toml", project);
    let before = cell.tree();
    vendors(&cell, &[]);
    let vendored = cell.tree();
    assert!(vendored[REQUIREMENTS] == before[REQUIREMENTS]);
    let lock = String::from_utf8_lossy(&vendored["poetry.lock"]);
    assert!(lock.contains(".socket/vendor/pypi/"), "{lock}");
    for later in [&VENDORED[..], &["scan", "--yes"]] {
        let scan = with.run(&cell, later);
        assert_eq!(scan.code, 0, "{}", scan.dump);
        assert_eq!(changed(&vendored, &cell.tree()), NOTHING, "{}", scan.dump);
    }

    // A file that is not written out: the hub may read any.
    let cell = checkout(&with);
    cell.write("MODULE.bazel", module(&cell).replace(&own, "LOCK"));
    let unread = format!(
        "(MODULE.bazel:{}: the files `pip.parse` names",
        hub_line(&cell)
    );
    let package = Declined {
        purl: PURL,
        code: DECLINED,
        names: &[&unread, "cannot be read with certainty"],
    };
    let before = cell.tree();
    cell.declined(&with.run(&cell, &VENDORED), &package, 1, "failed", &before);

    // A file that cannot be read here: it may hold a call that reads any.
    let cell = checkout(&with);
    cell.write(
        "MODULE.bazel",
        [module(&cell).as_bytes(), b"# caf\xe9\n"].concat(),
    );
    let package = Declined {
        purl: PURL,
        code: DECLINED,
        names: &[
            "(MODULE.bazel: it cannot be read: it is not UTF-8)",
            "cannot be read with certainty",
        ],
    };
    let before = cell.tree();
    cell.declined(&with.run(&cell, &VENDORED), &package, 1, "failed", &before);
}

/// Without a Bazel: a `WORKSPACE` file that a migration left behind still
/// hands `requirements.txt` to the ruleset's older rule, beside a
/// `MODULE.bazel` whose hub reads another file. Bazel 9 never reads a
/// `WORKSPACE` file, so where the checkout names a release of 9 or later
/// the package is vendored as it is without that file. Where it names an
/// older release, none, or one that is no release, a Bazel that reads the
/// file may build the checkout: the package is declined, and the refusal
/// names the call of the `WORKSPACE` file.
#[test]
fn a_workspace_file_counts_unless_the_checkout_names_bazel_9_or_later() {
    let with = Vendoring::new();
    let own = format!("\"//:{REQUIREMENTS}\"");
    let legacy = format!("pip_parse(\n    name = \"pypi\",\n    requirements_lock = {own},\n)\n");
    // The fixture's checkout with a hub that reads another file, the
    // `WORKSPACE` file where it is `kept`, and what names the Bazel
    // release.
    let retained = |release: Option<&str>, kept: bool| {
        let cell = checkout(&with);
        let module = String::from_utf8(cell.tree()["MODULE.bazel"].clone()).expect("a text file");
        let other = module.replace(&own, "\"//:requirements_lock.txt\"");
        assert_ne!(other, module);
        cell.write("MODULE.bazel", other);
        if kept {
            cell.write("WORKSPACE", &legacy);
        }
        if let Some(release) = release {
            cell.write(".bazelversion", format!("{release}\n"));
        }
        cell
    };
    // A run that vendors the wheel: the files it writes, and the
    // requirements it leaves.
    let vendors = |cell: &Cell| {
        let before = cell.tree();
        let scan = with.run(cell, &VENDORED);
        assert_eq!(scan.code, 0, "{}", scan.dump);
        assert_eq!(scan.envelope["summary"]["applied"], 1, "{}", scan.dump);
        let after = cell.tree();
        (changed(&before, &after), after[REQUIREMENTS].clone())
    };
    let written = vendors(&retained(Some("9.3.2"), false));
    let line = String::from_utf8_lossy(&written.1);
    assert!(line.contains("./.socket/vendor/pypi/"), "{line}");
    for release in ["9.3.2", "9.0.0", "10.0.0"] {
        let kept = vendors(&retained(Some(release), true));
        assert!(kept == written, "{release}");
    }
    let names = format!("names {REQUIREMENTS}; ");
    let package = Declined {
        purl: PURL,
        code: DECLINED,
        names: &["`pip_parse` (WORKSPACE:1)", &names],
    };
    for release in [Some("7.7.2"), Some("8.8.2"), None, Some("latest")] {
        let cell = retained(release, true);
        let before = cell.tree();
        cell.declined(&with.run(&cell, &VENDORED), &package, 1, "failed", &before);
    }
}

/// Without a Bazel: with `SOCKET_NO_BAZEL=1` vendored mode vendors the
/// package whose requirements the hub reads, as it does in the same
/// checkout without its `MODULE.bazel`, to the byte. Without the variable
/// it declines the package there.
#[test]
fn the_switch_makes_vendored_mode_the_one_of_a_checkout_without_bazel() {
    let with = Vendoring::new();
    let cell = checkout(&with);
    let origin = with.standin.origin();
    let json_api = format!("{origin}/{INDEX}/pypi");
    let env = [
        ("SOCKET_PATCH_SERVER_URL", origin.as_str()),
        ("SOCKET_PYPI_JSON_API", json_api.as_str()),
    ];
    let declined = cell.off_is_without_bazel(&origin, &VENDORED, &env, &["MODULE.bazel"]);
    assert_eq!(declined[0]["code"], 1, "{declined:#}");
}

/// Without a Bazel: the fixture's directories are those of its table, and
/// the workflow runs each release on its era. The fixture holds no
/// `requirements.txt`: every era names the one the test writes, which pins
/// the wheels of the run by a sha256 no other run has.
#[test]
fn the_fixture_takes_its_requirements_from_the_run() {
    FIXTURE.check();
    let root = fixture_path(FIXTURE.dir);
    let committed = root.join("common").join(REQUIREMENTS);
    assert!(!committed.exists(), "{}", committed.display());
    for (_, era) in FIXTURE.eras {
        let path = root.join(era).join("MODULE.bazel");
        let module = std::fs::read_to_string(&path).expect("the era's MODULE.bazel");
        let named = format!("requirements_lock = \"//:{REQUIREMENTS}\"");
        assert!(module.contains(&named), "{}", path.display());
    }

    let [one, other] = ["one", "other"].map(upstream);
    for (wheel, again) in one.iter().zip(&other) {
        assert_eq!(wheel.filename(), again.filename());
        assert_ne!(wheel.sha256, again.sha256, "{}", wheel.filename());
    }
    let [dependency, pristine] = &one;
    assert_eq!(
        requirements(&one),
        format!(
            "spdep==2.0.0 \\\n    --hash=sha256:{}\nspvictim==1.0.0 \\\n    --hash=sha256:{}\n",
            dependency.sha256, pristine.sha256
        )
    );

    // The downloader config: a page and a file per wheel, then the two
    // rules that keep every other question to the index off the network.
    let rules = downloads("http://127.0.0.1:1", &one);
    assert_eq!(rules.len(), 6, "{rules:?}");
    assert_eq!(
        rules[0],
        r"rewrite (\Qpypi.org/simple/spdep/\E.*) http://127.0.0.1:1/$1"
    );
    assert_eq!(
        rules[4],
        r"rewrite \Qpypi.org/simple/\E(?!(?:\Qspdep\E|\Qspvictim\E)/).* http://127.0.0.1:1/pypi.org/simple/-/"
    );
    assert_eq!(rules[5], "block pypi.org");
}

/// Without a Bazel: the workflow names the product files of the flow one by
/// one, and a path that names no file would start no run.
#[test]
fn the_workflow_names_files_that_exist() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workflow = root.join(".github/workflows").join(FIXTURE.workflow);
    let text = std::fs::read_to_string(&workflow).expect("the workflow");
    let listed = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- '")?.strip_suffix('\''));
    let files: Vec<&str> = listed.filter(|path| !path.contains('*')).collect();
    assert!(!files.is_empty(), "{}", workflow.display());
    for path in files {
        assert!(root.join(path).is_file(), "{}: {path}", workflow.display());
    }
}
