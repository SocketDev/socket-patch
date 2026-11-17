//! Hosted mode for a PyPI package that comes through rules_python's
//! `pip.parse(requirements_lock = "//:requirements.txt")` under Bzlmod: a
//! root `requirements.txt` in pip's hash-checking mode.
//!
//! One flow, on the Bazel the run is given ([`FIXTURE`] says which ruleset
//! goes with its release), in a fresh output base:
//!
//! - (a) `bazel build` and `bazel run //:consumer` print the unpatched
//!   marker.
//! - (b) `socket-patch scan --mode hosted --yes` rewrites
//!   `requirements.txt`, and nothing else: the pin of the package becomes a
//!   direct reference to the patched wheel, with its sha256.
//! - (c) The same two Bazel commands, with no step in between, print the
//!   patched marker, and the wheel came from the stand-in patch host. Where
//!   Bazel's lock records what the hub learned from the index (Bazel 8.5
//!   and later), that build rewrites `MODULE.bazel.lock`: the hub no longer
//!   asks the index about the package, so its entry goes. An older Bazel
//!   changes no file. The release decides which of the two the test
//!   expects.
//! - (d) `socket-patch rollback --yes` restores `requirements.txt` byte for
//!   byte, at once. Bazel's change to its own lock stays until the next
//!   build, which prints the unpatched marker again and writes the lock of
//!   before: from then on every file of the checkout is the one of before.
//! - (e) On a second machine (a new output base), a patch service grants
//!   another patch of the package and its host serves other bytes than the
//!   grant pins: after the same `scan`, the build fails on the sha256.
//!
//! The marker is read from what Bazel built, and the patched one holds an
//! id made for the run, so no cache of an earlier run can supply it. No
//! step builds with `--lockfile_mode=error`: where the build of (c) has to
//! rewrite the lock, as it would after the same edit made by hand, a build
//! that may not rewrite it cannot pass.
//!
//! One loopback server stands in for four hosts. The Socket API and the
//! patch host answer at their own paths; `pypi.org` (the project pages of
//! the index, and the JSON document `rollback` reads through
//! `SOCKET_PYPI_JSON_API`) and `files.pythonhosted.org` (the two upstream
//! wheels) answer under a route prefix. rules_python fetches the index and
//! the wheels with Bazel's downloader, which takes a plain-http URL only
//! with a checksum, and an index page has none. So the hub keeps its
//! default index, `https://pypi.org/simple`, and a downloader config that
//! the workspace `.bazelrc` names sends the URLs of the two packages, and
//! no other, to the stand-in, the way a mirror is configured. It is there
//! from the first build on, so step (c) changes no flag. What the rulesets
//! download for themselves comes from the network: their archives, the
//! Python toolchain, and from the real `pypi.org` the index pages of the
//! packages they pin for their own tools.
//!
//! The stand-in is not `patch.socket.dev`, so every `socket-patch` command
//! is told its origin (`SOCKET_PATCH_SERVER_URL`), as the operator of
//! another deployment does: `rollback` takes a URL on any other host for a
//! dependency of the user's own, not for a pin to undo.
//!
//! The same `.bazelrc` selects rules_python's script bootstrap, so
//! `bazel run` starts the `py_binary` with the interpreter of the
//! toolchain. The default bootstrap is a Python program behind
//! `/usr/bin/env python3`: with it the flow would need a `python3` on the
//! machine's `PATH`. As it is, the build and the run take no Python from
//! the machine. (`scan` asks a `python3` on `PATH` for its site-packages
//! when there is one, and patches the same without.)

use std::io::Write as _;
use std::time::Instant;

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::envelope::event_for;
use crate::harness::{changed, fixture_path, Cell, Fixture, Tree, CONSUMER};
use crate::hosted_memory_common::{mount_api, Patch};

/// The workspace the test builds, and the ruleset each Bazel release
/// builds it with.
const FIXTURE: Fixture = Fixture {
    name: "pypi::FIXTURE",
    dir: "rules_python/bzlmod",
    eras: &[
        // rules_python 2.5.0-rc4, with the Python 3.11 of its toolchain.
        ((7, 0, 0)..(10, 0, 0), "e9"),
    ],
};

/// The package the fixture requires, and the version `requirements.txt`
/// pins.
const NAME: &str = "spvictim";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:pypi/spvictim@1.0.0";
const UNPATCHED: &str = "OUT: PRISTINE";
/// The two hosts of the index, which are also the route prefixes of the
/// stand-in that plays them.
const INDEX: &str = "pypi.org";
const FILES: &str = "files.pythonhosted.org";
const LOCK: &str = "MODULE.bazel.lock";
const REQUIREMENTS: &str = "requirements.txt";
/// What [`changed`] gives for two equal trees.
const NOTHING: [&str; 0] = [];

/// A pure-Python wheel of one module. The fixture's `requirements.txt`
/// pins the sha256 of the two upstream wheels, so the same files must give
/// the same bytes on every run: each member is stored, not compressed,
/// under one fixed time.
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
        let tags = "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n";
        let mut files = vec![
            (format!("{name}/__init__.py"), module.to_string()),
            (format!("{dist_info}/METADATA"), metadata),
            (format!("{dist_info}/WHEEL"), tags.to_string()),
        ];
        // RECORD lists every other file with its sha256 and its size.
        let mut record = String::new();
        for (file, text) in &files {
            let digest = Sha256::digest(text.as_bytes());
            let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
            record.push_str(&format!("{file},sha256={digest},{}\n", text.len()));
        }
        record.push_str(&format!("{dist_info}/RECORD,,\n"));
        files.push((format!("{dist_info}/RECORD"), record));

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::default())
            .unix_permissions(0o644);
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (file, text) in &files {
            archive.start_file(file.as_str(), options).expect("zip");
            archive.write_all(text.as_bytes()).expect("zip");
        }
        let bytes = archive.finish().expect("zip").into_inner();
        let sha256 = hex::encode(Sha256::digest(&bytes));
        Wheel {
            name,
            version,
            bytes,
            sha256,
        }
    }

    fn filename(&self) -> String {
        format!("{}-{}-py3-none-any.whl", self.name, self.version)
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

/// The package under test: its one function returns `marker`.
fn package(marker: &str) -> Wheel {
    let module = format!("def value():\n    return \"{marker}\"\n");
    Wheel::new(NAME, VERSION, &["spdep"], &module)
}

/// The upstream wheels, as the index serves them: the dependency of the
/// package, which no patch touches, and the package.
fn upstream() -> [Wheel; 2] {
    let dependency = Wheel::new("spdep", "2.0.0", &[], "NAME = \"spdep\"\n");
    [dependency, package("PRISTINE")]
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

/// The loopback server behind every host of the test.
struct StandIn {
    // Dropped before the runtime it runs on.
    server: MockServer,
    runtime: tokio::runtime::Runtime,
}

impl StandIn {
    fn start() -> StandIn {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime for the stand-in");
        let server = runtime.block_on(MockServer::start());
        StandIn { server, runtime }
    }

    /// `http://127.0.0.1:<port>`.
    fn origin(&self) -> String {
        self.server.uri()
    }

    /// Answer `GET <route>` with `body`. Any other route is a 404.
    fn serve(&self, route: &str, body: &[u8]) {
        let mock = Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body));
        self.runtime.block_on(mock.mount(&self.server));
    }

    /// Serve `wheel` as the index does: its project page, which links the
    /// file by its production URL and sha256, the file, and the JSON
    /// document of the release. The page and the file are under
    /// `/<host>/<path>`, where [`downloader_config`] sends Bazel.
    fn publish(&self, wheel: &Wheel) {
        let (file, filename, sha256) = (wheel.file(), wheel.filename(), &wheel.sha256);
        let page = format!(
            "<!DOCTYPE html>\n<html><body>\n\
             <a href=\"https://{file}#sha256={sha256}\">{filename}</a><br />\n\
             </body></html>\n"
        );
        self.serve(&format!("/{}", wheel.page()), page.as_bytes());
        self.serve(&format!("/{file}"), &wheel.bytes);
        let release = json!({ "urls": [{
            "filename": filename,
            "url": format!("https://{file}"),
            "digests": { "sha256": sha256 },
        }] });
        let (name, version) = (wheel.name, wheel.version);
        let route = format!("/{INDEX}/pypi/{name}/{version}/json");
        self.serve(&route, release.to_string().as_bytes());
    }

    /// The Socket API: one free patch of the package, granted as a wheel
    /// with the sha256 of `pinned` on the patch host this server plays.
    /// Returns the route of that wheel, which is not served yet.
    fn grant(&self, uuid: &str, pinned: &Wheel) -> String {
        let filename = pinned.filename();
        let route = format!("/patch/pypi/{NAME}/{VERSION}/grant-token/{uuid}/{filename}");
        let url = format!("{}{route}", self.origin());
        let reference = json!({
            "status": "granted",
            "url": url,
            "purl": PURL,
            "artifacts": [{
                "kind": "tarball",
                "url": url,
                "integrity": { "sha256": pinned.sha256 },
            }],
            "registryOverride": null,
        });
        let patch = Patch {
            purl: PURL.to_string(),
            uuid: uuid.to_string(),
            reference,
        };
        self.runtime.block_on(mount_api(&self.server, &[patch]));
        route
    }

    /// How many requests for `route` the server has received.
    fn asked(&self, route: &str) -> usize {
        let received = self.runtime.block_on(self.server.received_requests());
        let received = received.expect("wiremock records requests");
        received.iter().filter(|r| r.url.path() == route).count()
    }
}

/// The downloader config that sends Bazel to `origin` for the project page
/// and the file of each of `wheels`, and leaves every other download
/// alone. A rule matches a whole URL without its scheme.
fn downloader_config(origin: &str, wheels: &[Wheel]) -> String {
    let rule = |url: String| format!("rewrite ({}) {origin}/$1\n", url.replace('.', "\\."));
    let urls = wheels.iter().flat_map(|wheel| [wheel.page(), wheel.file()]);
    urls.map(rule).collect()
}

/// The flow of the module docs.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn hosted_pip_parse() {
    let test = "pypi::hosted_pip_parse";
    let started = Instant::now();
    let Some(cell) = Cell::open(test, &FIXTURE) else {
        return;
    };
    let release = cell.release().to_string();

    // The patched wheel: the upstream files with another `__init__.py`,
    // which holds an id that is new for every run.
    let uuid = uuid::Uuid::new_v4().to_string();
    let patched = package(&format!("PATCHED {uuid}"));
    let marker = format!("OUT: PATCHED {uuid}");
    let wheels = upstream();
    let [dependency, pristine] = &wheels;

    let standin = StandIn::start();
    let origin = standin.origin();
    wheels.iter().for_each(|wheel| standin.publish(wheel));
    let patched_route = standin.grant(&uuid, &patched);
    standin.serve(&patched_route, &patched.bytes);
    let page = format!("/{}", pristine.page());
    let upstream_route = format!("/{}", pristine.file());
    let json_api = format!("{origin}/{INDEX}/pypi");
    let socket_patch = |cell: &Cell, api: &StandIn, args: &[&str]| {
        let api = api.origin();
        let env = [
            ("SOCKET_PATCH_SERVER_URL", api.as_str()),
            ("SOCKET_PYPI_JSON_API", json_api.as_str()),
        ];
        cell.socket_patch(&api, args, &env)
    };
    // Bazel's line, as (major, minor): two things the flow meets changed
    // within 8.x.
    let line = {
        let mut numbers = release.split('.').map(|number| number.parse::<u32>().ok());
        (numbers.next().flatten(), numbers.next().flatten())
    };
    // The option lost its `experimental_` in Bazel 8.2.
    let option = if line < (Some(8), Some(2)) {
        "--experimental_downloader_config"
    } else {
        "--downloader_config"
    };
    // The script bootstrap starts what Bazel built with the interpreter of
    // the toolchain; the default one needs a `python3` on `PATH` for that.
    let bootstrap = "--@rules_python//python/config_settings:bootstrap_impl=script";
    cell.write("downloader.cfg", downloader_config(&origin, &wheels));
    cell.write(
        ".bazelrc",
        format!("common {option}=downloader.cfg\nbuild {bootstrap}\n"),
    );

    // (a) The unpatched build. The hub asked the stand-in about the
    // package; the wheel is one any run with the same repository cache may
    // have fetched before, and its sha256 is pinned.
    cell.builds(UNPATCHED);
    assert!(
        standin.asked(&page) > 0,
        "{test}: the build did not ask the stand-in index about {NAME}"
    );
    let before = cell.tree();
    assert!(before.contains_key(LOCK), "{test}: Bazel wrote no lock");
    let upstream_fetches = standin.asked(&upstream_route);
    // What the patched build has to make of Bazel's lock: the lock of
    // before without the index entry of the package. Bazel records such
    // entries from 8.5 on, so 9.3.2 and 8.8.2 have one to drop and 7.7.2
    // has none: each release is held to its case, and so to its undo.
    let lock = |tree: &Tree| -> Value { serde_json::from_slice(&tree[LOCK]).expect("a JSON lock") };
    let mut patched_lock = lock(&before);
    forget(&mut patched_lock, NAME);
    let recorded = line >= (Some(8), Some(5));
    assert_eq!(
        patched_lock != lock(&before),
        recorded,
        "{test}: {LOCK} of Bazel {release} must hold an index entry of {NAME} from Bazel 8.5 on \
         and none before: the undo expected of a release follows from it"
    );
    let bazel_rewrites: &[&str] = if recorded { &[LOCK] } else { &[] };

    // (b) The one command of hosted mode.
    let scan = socket_patch(&cell, &standin, &["scan", "--mode", "hosted", "--yes"]);
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    let event = event_for(&scan.envelope, PURL);
    assert_eq!(event["action"], "applied", "{test}: {said}");
    assert_eq!(event["uuid"], uuid.as_str(), "{test}: {said}");
    let rewritten = &scan.envelope["redirect"]["rewrittenFiles"];
    assert_eq!(*rewritten, json!([REQUIREMENTS]), "{test}: {said}");
    // That file and no other: the pin of the dependency as it was, and the
    // package as a direct reference to the patched wheel with its sha256.
    let pinned = cell.tree();
    assert_eq!(changed(&before, &pinned), [REQUIREMENTS], "{test}");
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
    assert_eq!(standin.asked(&patched_route), 0, "{test}: {said}");

    // (c) The same build, no step in between: patched, from the patch host.
    cell.builds(&marker);
    assert!(
        standin.asked(&patched_route) > 0,
        "{test}: the patched build did not fetch the wheel from the stand-in patch host"
    );
    assert_eq!(
        standin.asked(&upstream_route),
        upstream_fetches,
        "{test}: the patched build fetched the upstream wheel"
    );
    // Bazel changed no file of the checkout but its own lock.
    let built = cell.tree();
    assert_eq!(changed(&pinned, &built), bazel_rewrites, "{test}");
    assert_eq!(lock(&built), patched_lock, "{test}: {LOCK}");

    // (d) The undo: `requirements.txt` is the one of before at once, and
    // the lock is still the one of the patched build. The next build
    // prints the unpatched marker and puts the lock back.
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
    cell.builds(UNPATCHED);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}");

    // (e) A second machine. Bazel keeps a download that has a checksum in
    // the repository cache, which the two machines share, so this one gets
    // a patch whose wheel no machine has fetched: another service grants
    // it, and its host serves other bytes than the grant pins. The build
    // has to ask that host, and must fail on the sha256.
    let twin = cell.twin();
    let other = uuid::Uuid::new_v4().to_string();
    let granted = package(&format!("PATCHED {other}"));
    let rogue = StandIn::start();
    let rogue_route = rogue.grant(&other, &granted);
    rogue.serve(&rogue_route, &package("TAMPERED").bytes);
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
         rewrote {bazel_rewrites:?} itself; `rollback` restored {REQUIREMENTS} at once, and the \
         next build printed {UNPATCHED:?} and left all {} files as before; other bytes at the \
         patch host failed a second machine's build ({refusal}); the stand-in answered {} \
         requests for the project page, {} for the upstream wheel and {} for the patched wheel; \
         {:?}",
        before.len(),
        standin.asked(&page),
        standin.asked(&upstream_route),
        standin.asked(&patched_route),
        started.elapsed()
    );
}

/// Without a Bazel: the fixture's directories are those of its table, and
/// its `requirements.txt` pins the two wheels the test serves, byte for
/// byte. Should a release of the `zip` crate lay an archive out another
/// way, the failure shows the two entries the fixture needs.
#[test]
fn the_fixture_pins_the_upstream_wheels_the_test_serves() {
    FIXTURE.check();
    let path = fixture_path(FIXTURE.dir).join("common").join(REQUIREMENTS);
    let pinned = std::fs::read_to_string(&path).expect("the fixture's requirements.txt");
    let served: String = upstream().iter().map(Wheel::requirement).collect();
    assert_eq!(pinned, served, "{}", path.display());
}
