//! Hosted mode for a Go module that comes through gazelle's
//! `go_deps.from_file(go_mod = "//:go.mod")` under Bzlmod.
//!
//! One flow per Bazel release, in a fresh output base:
//!
//! - (a) `bazel build` and `bazel run //:consumer` print the unpatched
//!   marker.
//! - (b) `socket-patch scan --mode hosted --yes` rewrites `go.mod` and
//!   `go.sum`, and nothing else.
//! - (c) The same two Bazel commands, with no step in between, print the
//!   patched marker; the zip of the Socket module came from the stand-in
//!   patch host, Bazel changed no file of the checkout, and a
//!   `--lockfile_mode=error` build passes.
//! - (d) `socket-patch rollback --yes`: every file of the checkout is the
//!   one of before, byte for byte, and the build prints the unpatched
//!   marker again.
//! - (e) On a second machine (a new output base and, on Bazel 9, a new
//!   contents cache, so no module fetched before is there) with the
//!   rewritten `go.mod` and `go.sum`, a patch host that serves other bytes
//!   fails the build on the sum, and the upstream module is not fetched in
//!   its place.
//!
//! The marker is read from what Bazel built, and the patched one holds an
//! id made for the run, so no cache of an earlier run can supply it.
//!
//! One loopback server stands in for four hosts, by route prefix: the
//! Socket API, `proxy.golang.org` (the upstream module), `patch.socket.dev`
//! (the Socket module, in the GOPROXY layout) and `sum.golang.org` (the
//! lookup `rollback` reads through `SOCKET_GOSUMDB_URL`). gazelle fetches a
//! module with `go mod download`, which reads `GOPROXY`, so every Bazel
//! command gets
//! `--repo_env=GOPROXY=<upstream stand-in>,<patch-host stand-in>` from the
//! first build on and step (c) changes no flag. `go` asks the first entry
//! and goes on to the second after a 404, as it goes from the public proxy
//! to the real patch host in a build outside these tests. No public proxy
//! is in the list: on these gazelle releases the two modules of the test
//! are all that `go` asks a proxy for.

use std::io::Write as _;
use std::time::Instant;

use base64::Engine as _;
use serde_json::json;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::envelope::event_for;
use crate::harness::{changed, fixture_path, Cell, CONSUMER};
use crate::hosted_memory_common::{mount_api, Patch};

/// The module both fixtures require, and the version `go.sum` pins.
const MODULE: &str = "example.com/upstream";
const VERSION: &str = "v1.0.0";
const PURL: &str = "pkg:golang/example.com/upstream@v1.0.0";
/// Its two files. The fixtures' `go.sum` holds the `h1:` of these bytes.
const GO_MOD: &[u8] = b"module example.com/upstream\n\ngo 1.21\n";
const UPSTREAM_LIB: &[u8] = b"package upstream\n\nfunc Greeting() string { return \"PRISTINE\" }\n";
const UNPATCHED: &str = "OUT: PRISTINE";
/// The version of the Socket module that replaces it.
const SOCKET_VERSION: &str = "v1.0.0-socketpatch.1";
/// The route prefixes of the stand-in, one per host it plays.
const PROXY: &str = "proxy.golang.org";
const PATCH_HOST: &str = "patch.socket.dev";
const SUMDB: &str = "sum.golang.org";
/// What [`changed`] gives for two equal trees.
const NOTHING: [&str; 0] = [];

/// Go's `h1:` hash of a set of files: the sha256 of one
/// `<hex sha256>  <name>\n` line per file, in the order of the names.
fn h1(files: &[(String, &[u8])]) -> String {
    let mut files = files.to_vec();
    files.sort();
    let mut summary = String::new();
    for (name, bytes) in files {
        summary.push_str(&format!("{}  {name}\n", hex::encode(Sha256::digest(bytes))));
    }
    let digest = Sha256::digest(summary.as_bytes());
    let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
    format!("h1:{encoded}")
}

/// One version of a module holding [`GO_MOD`] and a `lib.go`, as a Go
/// module proxy serves it. An `h1:` covers the names and the contents of
/// the files, not the bytes of the zip, so the zip is built here and no
/// binary is committed.
struct Module {
    path: String,
    version: String,
    zip: Vec<u8>,
    /// The `<path> <version>` line of `go.sum`.
    zip_h1: String,
    /// The `<path> <version>/go.mod` line of `go.sum`.
    mod_h1: String,
}

impl Module {
    fn new(path: &str, version: &str, lib: &[u8]) -> Module {
        let name = |file: &str| format!("{path}@{version}/{file}");
        let files = [(name("go.mod"), GO_MOD), (name("lib.go"), lib)];
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, bytes) in &files {
            let options = zip::write::SimpleFileOptions::default();
            archive.start_file(name.as_str(), options).expect("zip");
            archive.write_all(bytes).expect("zip");
        }
        Module {
            path: path.to_string(),
            version: version.to_string(),
            zip: archive.finish().expect("zip").into_inner(),
            zip_h1: h1(&files),
            mod_h1: h1(&[("go.mod".to_string(), GO_MOD)]),
        }
    }

    /// The two lines a `go.sum` holds for this module version.
    fn go_sum(&self) -> [String; 2] {
        let (path, version) = (&self.path, &self.version);
        [
            format!("{path} {version} {}", self.zip_h1),
            format!("{path} {version}/go.mod {}", self.mod_h1),
        ]
    }

    /// The route of this version's `.info`, `.mod` or `.zip` on the proxy
    /// the stand-in plays under `/<host>`.
    fn route(&self, host: &str, extension: &str) -> String {
        format!("/{host}/{}/@v/{}.{extension}", self.path, self.version)
    }
}

/// The upstream module, as the public proxy would serve it.
fn upstream() -> Module {
    Module::new(MODULE, VERSION, UPSTREAM_LIB)
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

    /// Answer `GET <route>` with `body`. Any other route is a 404, which
    /// sends `go` to the next entry of its `GOPROXY` list. wiremock asks
    /// the mocks of the lowest `priority` number first.
    fn serve(&self, priority: u8, route: &str, body: &[u8]) {
        let mock = Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .with_priority(priority);
        self.runtime.block_on(mock.mount(&self.server));
    }

    /// Serve `module` in the GOPROXY layout under `/<host>`.
    fn serve_module(&self, host: &str, module: &Module) {
        let version = &module.version;
        let info = format!(r#"{{"Version": "{version}", "Time": "2026-01-01T00:00:00Z"}}"#);
        self.serve(5, &module.route(host, "info"), info.as_bytes());
        self.serve(5, &module.route(host, "mod"), GO_MOD);
        self.serve(5, &module.route(host, "zip"), &module.zip);
    }

    /// The Socket API: one free patch of the upstream module, granted as
    /// the module `socket` on the stand-in patch host. `go` fetches the
    /// module, not Bazel's downloader, so the grant may name the loopback
    /// origin.
    fn grant(&self, uuid: &str, socket: &Module) {
        let origin = self.origin();
        let url = format!("{origin}{}", socket.route(PATCH_HOST, "zip"));
        let reference = json!({
            "status": "granted",
            "url": url,
            "purl": PURL,
            "artifacts": [{ "kind": "tarball", "url": url, "integrity": {} }],
            "registryOverride": {
                "kind": "goproxy",
                "indexUrl": format!("{origin}/{PATCH_HOST}"),
                "identifiers": {
                    "name": MODULE,
                    "version": VERSION,
                    "goModulePath": socket.path,
                    "goModuleVersion": socket.version,
                    "goZipDirhashH1": socket.zip_h1,
                    "goModH1": socket.mod_h1,
                },
            },
        });
        let patch = Patch {
            purl: PURL.to_string(),
            uuid: uuid.to_string(),
            reference,
        };
        self.runtime.block_on(mount_api(&self.server, &[patch]));
    }

    /// How many requests for `route` the server has received.
    fn asked(&self, route: &str) -> usize {
        let received = self.runtime.block_on(self.server.received_requests());
        let received = received.expect("wiremock records requests");
        received.iter().filter(|r| r.url.path() == route).count()
    }
}

/// The flow of the module docs for `test`, on Bazel `release` and the
/// fixture workspace `fixture`.
fn hosted(test: &str, release: &str, fixture: &str) {
    let started = Instant::now();
    let Some(mut cell) = Cell::open(test, release, fixture) else {
        return;
    };

    // The Socket module: the upstream files with `lib.go` patched, under a
    // path that is new for every run.
    let uuid = uuid::Uuid::new_v4().to_string();
    let lib =
        format!("package upstream\n\nfunc Greeting() string {{ return \"PATCHED {uuid}\" }}\n");
    let patched = format!("OUT: PATCHED {uuid}");
    let socket_path = format!("{PATCH_HOST}/gopatch/{uuid}");
    let socket = Module::new(&socket_path, SOCKET_VERSION, lib.as_bytes());
    let upstream = upstream();

    let standin = StandIn::start();
    let origin = standin.origin();
    standin.serve_module(PROXY, &upstream);
    standin.serve_module(PATCH_HOST, &socket);
    // What `rollback` reads to restore the upstream `go.sum` lines, in the
    // form of the checksum database: a record number, the two lines, a
    // tree head.
    let lookup = format!(
        "1\n{}\n\ngo.sum database tree\n1\nAAAA\n",
        upstream.go_sum().join("\n")
    );
    let lookup_route = format!("/{SUMDB}/lookup/{MODULE}@{VERSION}");
    standin.serve(5, &lookup_route, lookup.as_bytes());
    standin.grant(&uuid, &socket);
    let sumdb = format!("{origin}/{SUMDB}");
    let socket_patch = |cell: &Cell, args: &[&str]| {
        cell.socket_patch(&origin, args, &[("SOCKET_GOSUMDB_URL", sumdb.as_str())])
    };
    let proxies = format!("{origin}/{PROXY},{origin}/{PATCH_HOST}");
    cell.repo_env.push(("GOPROXY".to_string(), proxies));
    let (upstream_zip, socket_zip) = (
        upstream.route(PROXY, "zip"),
        socket.route(PATCH_HOST, "zip"),
    );

    // (a) The unpatched build, with the upstream module from the stand-in.
    cell.builds(UNPATCHED);
    let upstream_fetches = standin.asked(&upstream_zip);
    assert!(
        upstream_fetches > 0,
        "{test}: the build did not fetch the upstream module from the stand-in"
    );
    let before = cell.tree();
    assert!(
        before.contains_key("MODULE.bazel.lock"),
        "{test}: Bazel wrote no lock"
    );

    // (b) The one command of hosted mode.
    let scan = socket_patch(&cell, &["scan", "--mode", "hosted", "--yes"]);
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    let event = event_for(&scan.envelope, PURL);
    assert_eq!(event["action"], "applied", "{test}: {said}");
    assert_eq!(event["uuid"], uuid.as_str(), "{test}: {said}");
    let rewritten = &scan.envelope["redirect"]["rewrittenFiles"];
    assert_eq!(*rewritten, json!(["go.mod", "go.sum"]), "{test}: {said}");
    // Those two files and no other: the one `replace` line, and the two
    // sums of the Socket module in place of the upstream module's.
    let pinned = cell.tree();
    assert_eq!(changed(&before, &pinned), ["go.mod", "go.sum"], "{test}");
    let text = |rel: &str| String::from_utf8(pinned[rel].clone()).expect("a text file");
    let (go_mod, go_sum) = (text("go.mod"), text("go.sum"));
    let replace = format!("replace {MODULE} {VERSION} => {socket_path} {SOCKET_VERSION}");
    let replaces = go_mod.lines().filter(|line| line.trim() == replace).count();
    assert_eq!(replaces, 1, "{test}: go.mod:\n{go_mod}");
    let mut sums: Vec<&str> = go_sum.lines().collect();
    sums.sort_unstable();
    assert_eq!(sums, socket.go_sum(), "{test}: go.sum:\n{go_sum}");
    assert_eq!(standin.asked(&socket_zip), 0, "{test}: {said}");

    // (c) The same build, no step in between: patched, from the patch host.
    cell.builds(&patched);
    assert!(
        standin.asked(&socket_zip) > 0,
        "{test}: the patched build did not fetch the Socket module from the stand-in"
    );
    assert_eq!(
        standin.asked(&upstream_zip),
        upstream_fetches,
        "{test}: the patched build fetched the upstream module"
    );
    // Bazel changed no file, its own lock included, and that lock still
    // stands when Bazel may not update it.
    assert_eq!(changed(&pinned, &cell.tree()), NOTHING, "{test}");
    let frozen = cell.frozen_build(&[CONSUMER]);
    assert!(frozen.ok(), "{test}: {}", frozen.dump());

    // (d) The undo: every file is the one of before, and so is the build.
    let undo = socket_patch(&cell, &["rollback", "--yes"]);
    let said = &undo.dump;
    assert_eq!(undo.code, 0, "{test}: {said}");
    assert_eq!(undo.envelope["summary"]["rolledBack"], 1, "{test}: {said}");
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}: {said}");
    cell.builds(UNPATCHED);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}");

    // (e) A second machine with the rewritten files, and a patch host that
    // serves other bytes at the pinned URL: still a module zip `go`
    // unpacks, with another `h1:`. The build must fail on the sum, and
    // must not go to the upstream module instead.
    let twin = cell.twin();
    twin.write("go.mod", &go_mod);
    twin.write("go.sum", &go_sum);
    let other = b"package upstream\n\nfunc Greeting() string { return \"TAMPERED\" }\n";
    let tampered = Module::new(&socket_path, SOCKET_VERSION, other);
    standin.serve(1, &socket_zip, &tampered.zip);
    // Counted here, so that only the twin's own requests are judged.
    let (socket_fetches, upstream_fetches) =
        (standin.asked(&socket_zip), standin.asked(&upstream_zip));
    let build = twin.bazel("build", &[CONSUMER]);
    assert!(
        !build.ok(),
        "{test}: the tampered module built:\n{}",
        build.dump()
    );
    // gazelle 0.54 fails with go's `checksum mismatch`, 0.45 with
    // `expected sum <the pinned one>`.
    let stderr = build.stderr();
    let pinned_sum = format!("expected sum {}", socket.zip_h1);
    let refusal = ["checksum mismatch", pinned_sum.as_str()]
        .into_iter()
        .find(|sign| stderr.contains(sign));
    let Some(refusal) = refusal else {
        panic!(
            "{test}: the build did not fail on the sum of the Socket module:\n{}",
            build.dump()
        );
    };
    assert!(
        standin.asked(&socket_zip) > socket_fetches,
        "{test}: the patch host was not asked, so the failed build proves nothing"
    );
    assert_eq!(
        standin.asked(&upstream_zip),
        upstream_fetches,
        "{test}: the build went to the upstream module"
    );

    println!(
        "{test}: Bazel {release} built {patched:?} from {socket_path}@{SOCKET_VERSION} after \
         `scan --mode hosted`; `rollback` restored all {} files and the {UNPATCHED:?} build; other \
         bytes at the patch host failed a second machine's build ({refusal}); {:?}",
        before.len(),
        started.elapsed()
    );
}

/// The fixtures pin the module these tests build: without a Bazel, this
/// holds the `h1:` arithmetic to sums that `go` computed.
#[test]
fn the_fixtures_pin_the_upstream_module_the_tests_serve() {
    for era in ["e9", "e7"] {
        let path = fixture_path(&format!("gazelle/bzlmod/{era}/go.sum"));
        let go_sum = std::fs::read_to_string(&path).expect("the fixture's go.sum");
        let lines: Vec<&str> = go_sum.lines().collect();
        assert_eq!(lines, upstream().go_sum(), "{}", path.display());
    }
}

#[test]
#[ignore = "real Bazel; run with --ignored"]
fn b9_hosted_go_deps() {
    hosted("b9_hosted_go_deps", "9.3.2", "gazelle/bzlmod/e9");
}

#[test]
#[ignore = "real Bazel; run with --ignored"]
fn b8_hosted_go_deps() {
    hosted("b8_hosted_go_deps", "8.8.2", "gazelle/bzlmod/e9");
}

// The fixture for Bazel 7 pins older rulesets: gazelle 0.45.0 and
// rules_go 0.53.0.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn b7_hosted_go_deps() {
    hosted("b7_hosted_go_deps", "7.7.2", "gazelle/bzlmod/e7");
}
