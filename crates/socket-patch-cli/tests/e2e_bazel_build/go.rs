//! A Go module that comes through gazelle's
//! `go_deps.from_file(go_mod = "//:go.mod")` under Bzlmod, in each mode.
//!
//! Hosted mode is one flow, on the Bazel the run is given ([`FIXTURE`] says
//! which rulesets go with its release), in a fresh output base:
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
//! Vendored and agent mode keep a patched copy of the module in the
//! checkout and point `go.mod` at it with a directory `replace`
//! ([`kept_copy_flow`]): the same steps (a) to (d), and between (c) and (d)
//! what the user does next in a gazelle workspace, `bazel run //:gazelle`
//! and a build, or `bazel build //...` when the module ships a BUILD file
//! of its own.
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
//! is in the hosted flow's list: on these gazelle releases the two modules
//! of the test are all that `go` asks a proxy for. The vendored and agent
//! flows have the public proxy last in their list, for the modules gazelle
//! itself is built from. The caller's other fetch settings are pinned
//! beside it ([`go_env`]), so a `GOPRIVATE` of the machine cannot send `go`
//! past the stand-ins.

use std::io::Write as _;
use std::time::Instant;

use base64::Engine as _;
use serde_json::json;
use sha2::{Digest, Sha256, Sha512};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

use crate::envelope::find_event;
use crate::harness::{changed, fixture_path, Cell, Fixture, Ran, StandIn, CONSUMER};
use crate::hosted_memory_common::{Patch, ORG};

/// The workspace the test builds, and the rulesets each Bazel release
/// builds it with.
const FIXTURE: Fixture = Fixture {
    name: "go::FIXTURE",
    dir: "gazelle/bzlmod",
    workflow: "bazel-go.yml",
    eras: &[
        // gazelle 0.45.0 and rules_go 0.53.0, with Go 1.23.4.
        ((7, 0, 0)..(8, 0, 0), "e7"),
        // gazelle 0.54.0 and rules_go 0.65.0, with Go 1.26.0.
        ((8, 0, 0)..(10, 0, 0), "e9"),
    ],
};

/// The module the fixture requires, and the version `go.sum` pins.
const MODULE: &str = "example.com/upstream";
const VERSION: &str = "v1.0.0";
const PURL: &str = "pkg:golang/example.com/upstream@v1.0.0";
/// Its two files. The fixture's `go.sum` holds the `h1:` of these bytes.
const GO_MOD: &[u8] = b"module example.com/upstream\n\ngo 1.21\n";
const UPSTREAM_LIB: &[u8] = b"package upstream\n\nfunc Greeting() string { return \"PRISTINE\" }\n";
const UNPATCHED: &str = "OUT: PRISTINE";
/// The version of the Socket module that replaces it.
const SOCKET_VERSION: &str = "v1.0.0-socketpatch.1";
/// The route prefixes of the stand-in, one per host it plays.
const PROXY: &str = "proxy.golang.org";
const PATCH_HOST: &str = "patch.socket.dev";
const SUMDB: &str = "sum.golang.org";

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

/// One version of a module holding [`GO_MOD`], a `lib.go` and whatever
/// else it ships, as a Go module proxy serves it. An `h1:` covers the names
/// and the contents of the files, not the bytes of the zip, so the zip is
/// built here and no binary is committed.
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
        Module::shipping(path, version, lib, &[])
    }

    /// The module with the files `shipped` beside its two.
    fn shipping(path: &str, version: &str, lib: &[u8], shipped: &[(&str, &[u8])]) -> Module {
        let name = |file: &str| format!("{path}@{version}/{file}");
        let own: [(&str, &[u8]); 2] = [("go.mod", GO_MOD), ("lib.go", lib)];
        let files: Vec<(String, &[u8])> = own
            .iter()
            .chain(shipped)
            .map(|(file, bytes)| (name(file), *bytes))
            .collect();
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

/// Serve `module` on `standin` in the GOPROXY layout under `/<host>`. A
/// route the stand-in does not serve is a 404, which sends `go` to the next
/// entry of its `GOPROXY` list.
fn serve_module(standin: &StandIn, host: &str, module: &Module) {
    let version = &module.version;
    let info = format!(r#"{{"Version": "{version}", "Time": "2026-01-01T00:00:00Z"}}"#);
    standin.serve(5, &module.route(host, "info"), info.as_bytes());
    standin.serve(5, &module.route(host, "mod"), GO_MOD);
    standin.serve(5, &module.route(host, "zip"), &module.zip);
}

/// The Socket API on `standin`: one free patch of the upstream module,
/// granted as the module `socket` on the stand-in patch host. `go` fetches
/// the module, not Bazel's downloader, so the grant may name the loopback
/// origin.
fn grant(standin: &StandIn, uuid: &str, socket: &Module) {
    let origin = standin.origin();
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
    standin.api(&[patch]);
}

/// What a `go` that Bazel starts reads in place of the caller's settings,
/// for [`Cell::repo_env`]: the proxy list, and every other setting that
/// decides where `go` fetches a module from and what it trusts. gazelle
/// hands `GOPROXY`, `GOPRIVATE`, `GONOPROXY`, `GONOSUMDB`, `GOSUMDB` and
/// (0.54) `GOAUTH` on to `go mod download` and clears the rest of the
/// environment, so a `GOPRIVATE=patch.socket.dev` of the machine would
/// send that fetch past the stand-ins to the real host.
fn go_env(proxies: &str) -> Vec<(String, String)> {
    let pins = [
        ("GOPROXY", proxies),
        ("GOPRIVATE", ""),
        ("GONOPROXY", ""),
        ("GONOSUMDB", ""),
        // No checksum database. gazelle turns it off for the fetch, which
        // it holds to `go.sum`; any other `go` that asked one would fail
        // on this name instead of asking sum.golang.org about a module of
        // the test.
        ("GOSUMDB", "sum.invalid.example"),
        // No credential helper of the machine.
        ("GOAUTH", "off"),
        // Not handed on by gazelle, but read by a `go` that a rule starts
        // with the environment it inherits.
        ("GOFLAGS", ""),
        ("GOINSECURE", ""),
    ];
    let owned = pins.map(|(name, value)| (name.to_string(), value.to_string()));
    owned.to_vec()
}

/// The flow of the module docs.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn hosted_go_deps() {
    let test = "go::hosted_go_deps";
    let started = Instant::now();
    let Some(mut cell) = Cell::open(test, &FIXTURE) else {
        return;
    };
    let release = cell.release().to_string();

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
    serve_module(&standin, PROXY, &upstream);
    serve_module(&standin, PATCH_HOST, &socket);
    // What `rollback` reads to restore the upstream `go.sum` lines, in the
    // form of the checksum database: a record number, the two lines, a
    // tree head.
    let lookup = format!(
        "1\n{}\n\ngo.sum database tree\n1\nAAAA\n",
        upstream.go_sum().join("\n")
    );
    let lookup_route = format!("/{SUMDB}/lookup/{MODULE}@{VERSION}");
    standin.serve(5, &lookup_route, lookup.as_bytes());
    grant(&standin, &uuid, &socket);
    let sumdb = format!("{origin}/{SUMDB}");
    let socket_patch = |cell: &Cell, args: &[&str]| {
        cell.socket_patch(&origin, args, &[("SOCKET_GOSUMDB_URL", sumdb.as_str())])
    };
    let proxies = format!("{origin}/{PROXY},{origin}/{PATCH_HOST}");
    cell.repo_env = go_env(&proxies);
    let (upstream_zip, socket_zip) = (
        upstream.route(PROXY, "zip"),
        socket.route(PATCH_HOST, "zip"),
    );

    // (a) The unpatched build, with the upstream module from the stand-in.
    let before = cell.builds_unpatched(UNPATCHED);
    let upstream_fetches = standin.asked(&upstream_zip);
    assert!(
        upstream_fetches > 0,
        "{test}: the build did not fetch the upstream module from the stand-in"
    );

    // (b) The one command of hosted mode. It rewrites those two files and
    // no other: the one `replace` line, and the two sums of the Socket
    // module in place of the upstream module's.
    let scan = socket_patch(&cell, &["scan", "--mode", "hosted", "--yes"]);
    let said = &scan.dump;
    let pinned = cell.pinned_by(&scan, PURL, &uuid, &before, &["go.mod", "go.sum"]);
    let text = |rel: &str| String::from_utf8(pinned[rel].clone()).expect("a text file");
    let (go_mod, go_sum) = (text("go.mod"), text("go.sum"));
    let replace = format!("replace {MODULE} {VERSION} => {socket_path} {SOCKET_VERSION}");
    let replaces = go_mod.lines().filter(|line| line.trim() == replace).count();
    assert_eq!(replaces, 1, "{test}: go.mod:\n{go_mod}");
    let mut sums: Vec<&str> = go_sum.lines().collect();
    sums.sort_unstable();
    assert_eq!(sums, socket.go_sum(), "{test}: go.sum:\n{go_sum}");
    assert_eq!(standin.asked(&socket_zip), 0, "{test}: {said}");

    // (c) The same build, no step in between: patched, from the patch
    // host. Bazel changed no file, its own lock included, and that lock
    // still stands when Bazel may not update it.
    cell.builds_patched(&pinned, &patched);
    assert!(
        standin.asked(&socket_zip) > 0,
        "{test}: the patched build did not fetch the Socket module from the stand-in"
    );
    assert_eq!(
        standin.asked(&upstream_zip),
        upstream_fetches,
        "{test}: the patched build fetched the upstream module"
    );

    // (d) The undo: every file is the one of before, and so is the build.
    let undo = socket_patch(&cell, &["rollback", "--yes"]);
    cell.undone(&undo, "rolledBack", &before, UNPATCHED);

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
         bytes at the patch host failed a second machine's build ({refusal}); {origin} answered \
         {} requests for the upstream zip and {} for the Socket zip; {:?}",
        before.len(),
        standin.asked(&upstream_zip),
        standin.asked(&socket_zip),
        started.elapsed()
    );
}

/// The BUILD file of a module that is itself built with Bazel, as such a
/// module ships it in its zip: it loads rules_go under the name rules_go
/// had before Bzlmod, which gazelle maps for the module's own repository
/// and nothing maps for a package of the checkout.
const SHIPPED_BUILD: &[u8] = b"load(\"@io_bazel_rules_go//go:def.bzl\", \"go_library\")

go_library(
    name = \"upstream\",
    srcs = [\"lib.go\"],
    importpath = \"example.com/upstream\",
    visibility = [\"//visibility:public\"],
)
";

/// A mode that keeps a patched copy of the module in the checkout and
/// points `go.mod` at it with a directory `replace`.
#[derive(Clone, Copy, PartialEq)]
enum Kept {
    /// `scan --mode vendored`: the copy is the archive the patch service
    /// serves, committed under `.socket/vendor/golang`.
    Vendored,
    /// `scan --mode agent`, then the `apply` of every later install: the
    /// copy is made from the module in the user's module cache, under
    /// `.socket/go-patches`.
    Agent,
}

impl Kept {
    /// The directory that holds every copy of the mode, from the project.
    fn copies(self) -> &'static str {
        match self {
            Kept::Vendored => ".socket/vendor/golang",
            Kept::Agent => ".socket/go-patches",
        }
    }

    /// The directory of the copy for the patch `uuid`, from the project.
    fn copy_dir(self, uuid: &str) -> String {
        match self {
            Kept::Vendored => format!("{}/{uuid}/{MODULE}@{VERSION}", self.copies()),
            Kept::Agent => format!("{}/{MODULE}@{VERSION}", self.copies()),
        }
    }

    /// The command of the mode.
    fn scan(self) -> [&'static str; 4] {
        let mode = match self {
            Kept::Vendored => "vendored",
            Kept::Agent => "agent",
        };
        ["scan", "--mode", mode, "--yes"]
    }
}

/// The Socket API on `standin` for a [`Kept`] mode: one free patch of the
/// upstream module, which changes its `lib.go` to `lib`. Vendored mode
/// downloads the whole patched module, `copy` (the upstream's names with
/// the patched file); agent mode patches the user's own copy from the
/// patch record, which replaces the record [`StandIn::api`] answers with.
fn grant_copy(standin: &StandIn, uuid: &str, copy: &Module, lib: &[u8]) {
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let archive = format!("/artifacts/{uuid}/upstream.zip");
    standin.serve(5, &archive, &copy.zip);
    let url = format!("{}{archive}", standin.origin());
    let integrity = json!({ "sha512": format!("sha512-{}", b64(&Sha512::digest(&copy.zip))) });
    let reference = json!({
        "status": "granted",
        "url": url,
        "purl": PURL,
        "artifacts": [{ "kind": "tarball", "url": url, "integrity": integrity }],
    });
    let patch = Patch {
        purl: PURL.to_string(),
        uuid: uuid.to_string(),
        reference,
    };
    standin.api(&[patch]);
    let record = json!({
        "uuid": uuid,
        "purl": PURL,
        "publishedAt": "2026-01-01T00:00:00Z",
        "files": { "lib.go": {
            "beforeHash": compute_git_sha256_from_bytes(UPSTREAM_LIB),
            "afterHash": compute_git_sha256_from_bytes(lib),
            "blobContent": b64(lib),
            "beforeBlobContent": b64(UPSTREAM_LIB),
        }},
        "vulnerabilities": { "GHSA-test-aaaa-bbbb": {
            "cves": ["CVE-2024-0001"], "summary": "s", "severity": "high", "description": "d",
        }},
        "description": "fixture",
        "license": "MIT",
        "tier": "free",
    });
    let route = format!("/v0/orgs/{ORG}/patches/view/{uuid}");
    standin.serve(1, &route, record.to_string().as_bytes());
}

/// What a [`Kept`] flow patches with: a stand-in that serves the upstream
/// module and grants one patch of it, and the module cache of the user.
struct Patching {
    standin: StandIn,
    /// The id of the patch, new for every run.
    uuid: String,
    /// The `lib.go` the patch makes, which holds the id.
    lib: String,
    upstream: Module,
    /// `GOMODCACHE`: the upstream module as `go mod download` leaves it,
    /// which agent mode copies.
    modcache: tempfile::TempDir,
}

impl Patching {
    /// For an upstream module that ships the files `shipped` beside its
    /// two.
    fn new(shipped: &[(&str, &[u8])]) -> Patching {
        let uuid = uuid::Uuid::new_v4().to_string();
        let lib =
            format!("package upstream\n\nfunc Greeting() string {{ return \"PATCHED {uuid}\" }}\n");
        let upstream = Module::shipping(MODULE, VERSION, UPSTREAM_LIB, shipped);
        let copy = Module::shipping(MODULE, VERSION, lib.as_bytes(), shipped);
        let standin = StandIn::start();
        serve_module(&standin, PROXY, &upstream);
        grant_copy(&standin, &uuid, &copy, lib.as_bytes());
        let modcache = tempfile::tempdir().expect("a module cache");
        let cached = modcache.path().join(format!("{MODULE}@{VERSION}"));
        std::fs::create_dir_all(&cached).expect("the cached module");
        let own: [(&str, &[u8]); 2] = [("go.mod", GO_MOD), ("lib.go", UPSTREAM_LIB)];
        for (file, bytes) in own.iter().chain(shipped) {
            std::fs::write(cached.join(file), bytes).expect("a file of the cached module");
        }
        Patching {
            standin,
            uuid,
            lib,
            upstream,
            modcache,
        }
    }

    /// `socket-patch <args>` in `cell`, which exits 0 with the status
    /// `success`.
    fn run(&self, cell: &Cell, args: &[&str]) -> Ran {
        let modcache = self.modcache.path().to_str().expect("a UTF-8 path");
        let env = [("GOMODCACHE", modcache)];
        let ran = cell.socket_patch(&self.standin.origin(), args, &env);
        assert_eq!(ran.code, 0, "{}: {}", cell.test, ran.dump);
        let status = &ran.envelope["status"];
        assert_eq!(*status, "success", "{}: {}", cell.test, ran.dump);
        ran
    }
}

/// The user's `bazel run //:gazelle`, which passes.
fn gazelle(cell: &Cell) {
    let ran = cell.bazel("run", &["//:gazelle"]);
    assert!(ran.ok(), "{}: {}", cell.test, ran.dump());
}

/// The flow of a [`Kept`] mode, for a module that ships `SHIPPED_BUILD`
/// (`ships_build`) or no BUILD file:
///
/// - (a) The unpatched build, and for a module without a BUILD file the
///   user's `bazel run //:gazelle`, which leaves the fixture as it is.
/// - (b) The command of the mode writes the copy and the one `replace` line
///   of `go.mod`.
/// - (c) `bazel build` and `bazel run //:consumer` print the patched marker,
///   Bazel changed no file, and a `--lockfile_mode=error` build passes.
/// - (d) What the user does next: `bazel run //:gazelle` and a build, or,
///   for a module that ships a BUILD file, `bazel build //...`. The build
///   breaks here: gazelle writes a BUILD file into the copy, or the copy
///   holds the one the module ships, `go_deps` copies the directory with
///   it, and Bazel reads the file as a package that cannot load rules_go.
/// - (e) The undo of the mode removes the copy and the `replace` line, and
///   the build prints the unpatched marker again.
fn kept_copy_flow(test: &str, mode: Kept, ships_build: bool) {
    let started = Instant::now();
    let Some(mut cell) = Cell::open(test, &FIXTURE) else {
        return;
    };
    let release = cell.release().to_string();
    let shipped: &[(&str, &[u8])] = if ships_build {
        &[("BUILD.bazel", SHIPPED_BUILD)]
    } else {
        &[]
    };
    let with = Patching::new(shipped);
    let patched = format!("OUT: PATCHED {}", with.uuid);
    let copy_dir = mode.copy_dir(&with.uuid);
    // The public proxy is last, for the modules gazelle is built from: the
    // stand-in has the module of the test, and no flow here has a Socket
    // module.
    let origin = with.standin.origin();
    cell.repo_env = go_env(&format!("{origin}/{PROXY},https://proxy.golang.org"));
    if ships_build {
        cell.write("go.sum", with.upstream.go_sum().join("\n") + "\n");
    }

    // (a) The unpatched build. The fixture's BUILD file is the one gazelle
    // writes, so whatever a later gazelle run changes comes from the patch.
    cell.builds_unpatched(UNPATCHED);
    if !ships_build {
        gazelle(&cell);
    }
    let before = cell.tree();
    let fixture = std::fs::read(fixture_path(FIXTURE.dir).join("common/BUILD.bazel"));
    assert_eq!(
        before["BUILD.bazel"],
        fixture.expect("the fixture"),
        "{test}"
    );

    // (b) The command of the mode: the copy, and the one `replace` line.
    let scan = with.run(&cell, &mode.scan());
    let event = find_event(&scan.envelope, "applied", None);
    assert_eq!(event["purl"], PURL, "{test}: {}", scan.dump);
    if mode == Kept::Agent {
        with.run(&cell, &["apply"]);
    }
    let pinned = cell.tree();
    let wrote = changed(&before, &pinned);
    let outside: Vec<&String> = wrote
        .iter()
        .filter(|f| !f.starts_with(".socket/"))
        .collect();
    assert_eq!(outside, ["go.mod"], "{test}: {wrote:?}");
    let lib = &pinned[&format!("{copy_dir}/lib.go")];
    assert_eq!(*lib, with.lib.as_bytes(), "{test}");
    let go_mod = String::from_utf8(pinned["go.mod"].clone()).expect("a text file");
    let replace = format!("replace {MODULE} {VERSION} => ./{copy_dir}");
    let replaces = go_mod.lines().filter(|line| line.trim() == replace).count();
    assert_eq!(replaces, 1, "{test}: go.mod:\n{go_mod}");

    // (c) The next build is patched, from the copy.
    cell.builds_patched(&pinned, &patched);

    // (d) The user's next step breaks the build.
    let (build, sign) = if ships_build {
        let sign = "No repository visible as '@io_bazel_rules_go'";
        (cell.bazel("build", &["//..."]), sign)
    } else {
        gazelle(&cell);
        let wrote = changed(&pinned, &cell.tree());
        assert_eq!(wrote, [format!("{copy_dir}/BUILD.bazel")], "{test}");
        let sign = "No repository visible as '@rules_go'";
        (cell.bazel("build", &[CONSUMER]), sign)
    };
    assert!(
        !build.ok() && build.stderr().contains(sign),
        "{test}: the build did not fail on {sign:?}:\n{}",
        build.dump()
    );

    // (e) The undo. An agent rollback keeps its emptied manifest.
    let (undo, counted, left): (&[&str], &str, &[&str]) = match mode {
        Kept::Vendored => (&["vendor", "--revert", "--yes"], "removed", &[]),
        Kept::Agent => (
            &["rollback", "--yes"],
            "rolledBack",
            &[".socket/manifest.json"],
        ),
    };
    let undo = with.run(&cell, undo);
    let count = &undo.envelope["summary"][counted];
    assert_eq!(*count, 1, "{test}: {}", undo.dump);
    assert_eq!(
        changed(&before, &cell.tree()),
        left,
        "{test}: {}",
        undo.dump
    );
    cell.builds(UNPATCHED);
    assert_eq!(changed(&before, &cell.tree()), left, "{test}");

    println!(
        "{test}: Bazel {release} built {patched:?} from {copy_dir} after the command of the mode; \
         then the build failed ({sign}); the undo left {left:?} and the {UNPATCHED:?} build; {:?}",
        started.elapsed()
    );
}

/// `scan --mode vendored` for a module without a BUILD file. What the code
/// does today: the build is patched after the command; the user's
/// `bazel run //:gazelle` then writes a BUILD.bazel into the copy, and the
/// next build fails to load the module
/// (`No repository visible as '@rules_go'`); `vendor --revert` leaves the
/// checkout as it was before the command.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn vendored_go_deps() {
    kept_copy_flow("go::vendored_go_deps", Kept::Vendored, false);
}

/// Agent mode (`scan --mode agent`, then `apply`) for a module without a
/// BUILD file. What the code does today: the build is patched after the
/// commands; the user's `bazel run //:gazelle` then writes a BUILD.bazel
/// into the copy, and the next build fails to load the module
/// (`No repository visible as '@rules_go'`); `rollback` leaves the checkout
/// as it was before, but for the emptied `.socket/manifest.json`.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn agent_go_deps() {
    kept_copy_flow("go::agent_go_deps", Kept::Agent, false);
}

/// `scan --mode vendored` for a module that ships a BUILD file of its own.
/// What the code does today: `//:consumer` builds patched after the
/// command, and `bazel build //...` fails right away on the BUILD file in
/// the copy (`No repository visible as '@io_bazel_rules_go'`);
/// `vendor --revert` leaves the checkout as it was before the command. This
/// test runs no gazelle.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn vendored_go_deps_module_with_a_build_file() {
    let test = "go::vendored_go_deps_module_with_a_build_file";
    kept_copy_flow(test, Kept::Vendored, true);
}

/// Without a Bazel: the fixture's directories are those of its table, and
/// its `go.sum` pins the module the test serves, which holds the `h1:`
/// arithmetic here to sums that `go` computed.
#[test]
fn the_fixture_pins_the_upstream_module_the_test_serves() {
    FIXTURE.check();
    let path = fixture_path(FIXTURE.dir).join("common/go.sum");
    let go_sum = std::fs::read_to_string(&path).expect("the fixture's go.sum");
    let lines: Vec<&str> = go_sum.lines().collect();
    assert_eq!(lines, upstream().go_sum(), "{}", path.display());
}
