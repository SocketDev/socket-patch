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
//! id made for the run, so no cache of an earlier run can supply it. Each
//! flow asserts the VEX document of its patch as `main.rs` says; agent mode
//! also has its `apply` write one.
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
use crate::harness::{
    cell_without_bazel, changed, fixture_path, with_vex, Cell, Claim, Fixture, How, Ran, StandIn,
    Tree, CONSUMER, NOTHING,
};
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
/// The product `vex` reads from the fixture's own `go.mod`, which records
/// a module and no version.
const PRODUCT: &str = "pkg:golang/example.com/consumer";
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

/// What the Socket API on `standin` grants for the one free patch of the
/// upstream module: the module `socket` on the stand-in patch host. `go`
/// fetches the module, not Bazel's downloader, so the grant may name the
/// loopback origin.
fn granted(standin: &StandIn, socket: &Module) -> serde_json::Value {
    let origin = standin.origin();
    let url = format!("{origin}{}", socket.route(PATCH_HOST, "zip"));
    json!({
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
    })
}

/// The Socket API on `standin`: one free patch of the upstream module,
/// granted as the module `socket`.
fn grant(standin: &StandIn, uuid: &str, socket: &Module) {
    let patch = Patch {
        purl: PURL.to_string(),
        uuid: uuid.to_string(),
        reference: granted(standin, socket),
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
    let hosted = ["scan", "--mode", "hosted", "--yes"];
    let claim = Claim::new(PURL, &uuid, How::Hosted);
    let in_run = cell.document("in-run");
    let scan = socket_patch(&cell, &[&hosted[..], &with_vex(&in_run)].concat());
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
    // The document of that run and the one of `vex` say so, in a checkout
    // Bazel has built in, before anything has fetched the Socket module.
    cell.wrote_in_run(&scan, &in_run, &claim);
    cell.stands_alone(socket_patch, &claim, true);
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
    // `vex` says the same of the build that printed the patched marker,
    // and with `--no-verify` that it checked no file.
    cell.stands_alone(socket_patch, &claim, true);
    cell.stands_alone(socket_patch, &claim, false);
    // Without a product, as a user types it: the same document for the
    // module of the checkout's own `go.mod`.
    cell.detects_product(socket_patch, Some(PRODUCT));

    // (d) The undo: every file is the one of before, and so is the build,
    // and `vex` has no document for it.
    let undo = socket_patch(&cell, &["rollback", "--yes"]);
    cell.undone(&undo, "rolledBack", &before, UNPATCHED);
    cell.attests_nothing(socket_patch, 2, "manifest_not_found");
    // The same two documents where no Bazel has built.
    cell.attests_unbuilt(socket_patch, &hosted, &before, &pinned, &claim);

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

/// The line `socket-patch` writes above each of its `.bazelignore` lines.
const IGNORE_COMMENT: &str =
    "# socket-patch: patched Go module copies, not Bazel packages (to opt out, comment out the next line)";

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

    /// What a VEX document says of a patch of the mode.
    fn how(self) -> How {
        match self {
            Kept::Vendored => How::Vendored,
            Kept::Agent => How::Agent,
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

    /// What `socket-patch` keeps in the `.bazelignore` at the root of a
    /// Bazel workspace while the project in its directory `project` (`""`:
    /// the root itself, else with a `/` at its end) has a copy of the mode.
    fn ignored(self, project: &str) -> String {
        format!("{IGNORE_COMMENT}\n{project}{}\n", self.copies())
    }
}

/// The Socket API on `standin` for a [`Kept`] mode: one free patch of the
/// upstream module, which changes its `lib.go` to `lib`. Vendored mode
/// downloads the whole patched module, `copy` (the upstream's names with
/// the patched file); agent mode patches the user's own copy from the
/// patch record, which replaces the record [`StandIn::api`] answers with;
/// and hosted mode is granted `socket`, as in [`grant`].
fn grant_copy(standin: &StandIn, uuid: &str, copy: &Module, socket: &Module, lib: &[u8]) {
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let archive = format!("/artifacts/{uuid}/upstream.zip");
    standin.serve(5, &archive, &copy.zip);
    let url = format!("{}{archive}", standin.origin());
    let integrity = json!({ "sha512": format!("sha512-{}", b64(&Sha512::digest(&copy.zip))) });
    let mut reference = granted(standin, socket);
    reference["artifacts"] = json!([{ "kind": "tarball", "url": url, "integrity": integrity }]);
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
        let socket_path = format!("{PATCH_HOST}/gopatch/{uuid}");
        let socket = Module::shipping(&socket_path, SOCKET_VERSION, lib.as_bytes(), shipped);
        let standin = StandIn::start();
        serve_module(&standin, PROXY, &upstream);
        serve_module(&standin, PATCH_HOST, &socket);
        grant_copy(&standin, &uuid, &copy, &socket, lib.as_bytes());
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

    /// `socket-patch <args>` in `cell`, with the module cache of the user.
    fn ran(&self, cell: &Cell, args: &[&str]) -> Ran {
        let modcache = self.modcache.path().to_str().expect("a UTF-8 path");
        let env = [("GOMODCACHE", modcache)];
        cell.socket_patch(&self.standin.origin(), args, &env)
    }

    /// [`Patching::ran`] as a person runs it, without `--json`: the lines
    /// of its stdout and of its stderr that name a `.bazelignore`.
    fn person(&self, cell: &Cell, args: &[&str]) -> [Vec<String>; 2] {
        let modcache = self.modcache.path().to_str().expect("a UTF-8 path");
        let env = [("GOMODCACHE", modcache)];
        naming_the_file(cell.socket_patch_person(&self.standin.origin(), args, &env))
    }

    /// [`Patching::ran`] for a command that exits 0 with the status
    /// `success`.
    fn run(&self, cell: &Cell, args: &[&str]) -> Ran {
        let ran = self.ran(cell, args);
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
/// - (b) The command of the mode writes the copy, the one `replace` line
///   of `go.mod`, and the line of `.bazelignore` that names the directory
///   of the copies. In the agent flow the user has a `.bazelignore` whose
///   last line has no line break, and the file then ends with that line of
///   `socket-patch`, without a line break as well.
/// - (c) `bazel build` and `bazel run //:consumer` print the patched marker,
///   Bazel changed no file, and a `--lockfile_mode=error` build passes.
/// - (d) What the user does next: for a module without a BUILD file
///   `bazel run //:gazelle`, which writes nothing, and the same build; then
///   `bazel build //...`. Without the line gazelle writes a BUILD file into
///   the copy, or the copy holds the one the module ships; `go_deps` copies
///   the directory with it, and Bazel reads the file as a package that
///   cannot load rules_go.
/// - (e) The undo of the mode removes the copy, the `replace` line and the
///   line of `.bazelignore`, which leaves the user's file as it was, and
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
    // The agent flow has a `.bazelignore` of the user's, whose last line
    // has no line break: Bazel and gazelle have to honour the line
    // `socket-patch` then ends the file with, and the undo has to leave the
    // user's file as it was.
    let (theirs, ignored) = match mode {
        Kept::Agent => (
            "node_modules\n# mine",
            mode.ignored("").trim_end().to_string(),
        ),
        Kept::Vendored => ("", mode.ignored("")),
    };
    if !theirs.is_empty() {
        cell.write(".bazelignore", theirs);
    }
    let ignored = [theirs, &ignored].join(if theirs.is_empty() { "" } else { "\n" });
    let before = cell.tree();
    let fixture = std::fs::read(fixture_path(FIXTURE.dir).join("common/BUILD.bazel"));
    assert_eq!(
        before["BUILD.bazel"],
        fixture.expect("the fixture"),
        "{test}"
    );

    // (b) The command of the mode: the copy, the one `replace` line, and
    // the line that keeps Bazel and gazelle out of the copies.
    let claim = Claim::new(PURL, &with.uuid, mode.how());
    let run = |cell: &Cell, args: &[&str]| with.ran(cell, args);
    let in_run = cell.document("in-run");
    let scan = with.run(&cell, &[&mode.scan()[..], &with_vex(&in_run)].concat());
    let event = find_event(&scan.envelope, "applied", None);
    assert_eq!(event["purl"], PURL, "{test}: {}", scan.dump);
    cell.wrote_in_run(&scan, &in_run, &claim);
    if mode == Kept::Agent {
        let again = cell.document("apply");
        let apply = with.run(&cell, &[&["apply"][..], &with_vex(&again)].concat());
        cell.wrote_in_run(&apply, &again, &claim);
    }
    let pinned = cell.tree();
    let wrote = changed(&before, &pinned);
    let outside: Vec<&String> = wrote
        .iter()
        .filter(|f| !f.starts_with(".socket/"))
        .collect();
    assert_eq!(outside, [".bazelignore", "go.mod"], "{test}: {wrote:?}");
    assert_eq!(pinned[".bazelignore"], ignored.as_bytes(), "{test}");
    let lib = &pinned[&format!("{copy_dir}/lib.go")];
    assert_eq!(*lib, with.lib.as_bytes(), "{test}");
    let go_mod = String::from_utf8(pinned["go.mod"].clone()).expect("a text file");
    let replace = format!("replace {MODULE} {VERSION} => ./{copy_dir}");
    let replaces = go_mod.lines().filter(|line| line.trim() == replace).count();
    assert_eq!(replaces, 1, "{test}: go.mod:\n{go_mod}");
    cell.stands_alone(run, &claim, true);

    // (c) The next build is patched, from the copy, and `vex` says so; with
    // `--no-verify` it says that it checked no file, and without a product
    // it says the same for the module of the checkout's own `go.mod`.
    cell.builds_patched(&pinned, &patched);
    cell.stands_alone(run, &claim, true);
    cell.stands_alone(run, &claim, false);
    cell.detects_product(run, Some(PRODUCT));

    // (d) The user's next step: gazelle writes nothing into the copy, the
    // build stays patched, and no package of the checkout is under
    // `.socket`.
    if !ships_build {
        gazelle(&cell);
        assert_eq!(changed(&pinned, &cell.tree()), NOTHING, "{test}");
        cell.builds_patched(&pinned, &patched);
    }
    let all = cell.bazel("build", &["//..."]);
    assert!(all.ok(), "{test}: {}", all.dump());

    // (e) The undo. An agent rollback keeps its emptied manifest, which
    // `vex` then finds empty, where the other undo leaves it none to find.
    let (undo, counted, left, nothing): (&[&str], &str, &[&str], (i32, &str)) = match mode {
        Kept::Vendored => (
            &["vendor", "--revert", "--yes"],
            "removed",
            &[],
            (2, "manifest_not_found"),
        ),
        Kept::Agent => (
            &["rollback", "--yes"],
            "rolledBack",
            &[".socket/manifest.json"],
            (1, "no_patches"),
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
    cell.attests_nothing(run, nothing.0, nothing.1);
    // The same two documents where no Bazel has built.
    cell.attests_unbuilt(run, &mode.scan(), &before, &pinned, &claim);

    let next = if ships_build {
        "`bazel build //...` passed"
    } else {
        "it built that again after `bazel run //:gazelle`, and `bazel build //...` passed"
    };
    println!(
        "{test}: Bazel {release} built {patched:?} from {copy_dir} after the command of the mode; \
         {next}; the undo left {left:?} and the {UNPATCHED:?} build; {:?}",
        started.elapsed()
    );
}

/// `scan --mode vendored` for a module without a BUILD file. The command
/// writes the copy, the `replace` and the `.bazelignore` line. The build is
/// patched, and stays patched after the user's `bazel run //:gazelle`,
/// which writes nothing into the copy; `bazel build //...` passes; and
/// `vendor --revert` leaves the checkout as it was before the command.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn vendored_go_deps() {
    kept_copy_flow("go::vendored_go_deps", Kept::Vendored, false);
}

/// Agent mode (`scan --mode agent`, then `apply`) for a module without a
/// BUILD file. The commands write the copy, the `replace` and the
/// `.bazelignore` line, here at the end of a file of the user's whose last
/// line has no line break. The build is patched, and stays patched after
/// the user's `bazel run //:gazelle`, which writes nothing into the copy;
/// `bazel build //...` passes; and `rollback` leaves the checkout as it was
/// before, that file included, but for the emptied `.socket/manifest.json`.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn agent_go_deps() {
    kept_copy_flow("go::agent_go_deps", Kept::Agent, false);
}

/// `scan --mode vendored` for a module that ships a BUILD file of its own.
/// The command writes the copy, the `replace` and the `.bazelignore` line.
/// The build is patched, `bazel build //...` passes although the copy holds
/// that BUILD file, and `vendor --revert` leaves the checkout as it was
/// before the command. This test runs no gazelle.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn vendored_go_deps_module_with_a_build_file() {
    let test = "go::vendored_go_deps_module_with_a_build_file";
    kept_copy_flow(test, Kept::Vendored, true);
}

/// Without a Bazel: the Go project of the fixture in a checkout of its
/// own, in the directory `project` of it (`""`: the root, else with a `/`
/// at its end), with the file `marks` at the root, which makes the
/// checkout a Bazel workspace when it is one of Bazel's names.
fn checkout(project: &str, marks: &str) -> Cell {
    let cell = cell_without_bazel("9.3.2");
    for file in ["go.mod", "go.sum"] {
        let bytes = std::fs::read(fixture_path(FIXTURE.dir).join("common").join(file));
        cell.write(&format!("{project}{file}"), bytes.expect("a fixture file"));
    }
    cell.write(".git/HEAD", "ref: refs/heads/main\n");
    cell.write(marks, "");
    cell
}

/// Without a Bazel: in a Bazel workspace the `.bazelignore` line follows
/// the directory of the copies, in vendored mode. A second run leaves one
/// pair. What an earlier release left after a gazelle run, a copy without
/// its line and with a BUILD file in it, is put right by the next run, which
/// makes the copy anew, but not by a dry run. A rollback that keeps the
/// copy keeps the line, since the files of the copy are still in the
/// workspace. The revert takes the pair, and the file it made, away, and
/// its dry run nothing.
#[test]
fn a_vendored_copy_has_its_bazelignore_line_while_it_is_on_disk() {
    let (cell, with) = (checkout("", "MODULE.bazel"), Patching::new(&[]));
    let (mode, before) = (Kept::Vendored, cell.tree());
    for _ in 0..2 {
        with.run(&cell, &mode.scan());
        assert_eq!(cell.tree()[".bazelignore"], mode.ignored("").as_bytes());
    }

    let stray = format!("{}/BUILD.bazel", mode.copy_dir(&with.uuid));
    std::fs::remove_file(cell.path(".bazelignore")).expect("remove the file");
    cell.write(&stray, "# what gazelle wrote\n");
    with.run(&cell, &["scan", "--mode", "vendored", "--yes", "--dry-run"]);
    assert!(!cell.tree().contains_key(".bazelignore"));
    with.run(&cell, &mode.scan());
    let tree = cell.tree();
    assert_eq!(tree[".bazelignore"], mode.ignored("").as_bytes());
    assert!(!tree.contains_key(&stray));

    // `repair` brings a lost copy back, and its line with it.
    let lib = format!("{}/lib.go", mode.copy_dir(&with.uuid));
    std::fs::remove_file(cell.path(".bazelignore")).expect("remove the file");
    std::fs::remove_dir_all(cell.path(mode.copies())).expect("remove the copies");
    with.run(&cell, &["repair"]);
    let tree = cell.tree();
    assert_eq!(tree[&lib], with.lib.as_bytes());
    assert_eq!(tree[".bazelignore"], mode.ignored("").as_bytes());

    with.run(&cell, &["rollback", "--yes", "--preserve-state"]);
    let kept = cell.tree();
    assert_eq!(kept["go.mod"], before["go.mod"]);
    assert!(kept.contains_key(&lib));
    assert_eq!(kept[".bazelignore"], mode.ignored("").as_bytes());

    with.run(&cell, &["vendor", "--revert", "--yes", "--dry-run"]);
    assert_eq!(changed(&kept, &cell.tree()), NOTHING);
    with.run(&cell, &["vendor", "--revert", "--yes"]);
    assert_eq!(changed(&before, &cell.tree()), NOTHING);
}

/// Without a Bazel: a dry run of any command writes nothing, also where
/// the run itself would write the file: a project that an earlier release
/// patched has a copy and no line for it. `repair` comes again for a copy
/// it would download anew, which is where its own run ends at the file.
#[test]
fn a_dry_run_leaves_a_copy_without_its_bazelignore_line() {
    let commands: [&[&str]; 10] = [
        &["scan", "--yes"],
        &["scan", "--mode", "hosted", "--yes"],
        &["get", PURL, "--yes"],
        &["apply"],
        &["vendor", "--yes"],
        &["vendor", "--revert", "--yes"],
        &["rollback", "--yes"],
        &["rollback", "--yes", "--preserve-state"],
        &["remove", PURL, "--yes"],
        &["repair"],
    ];
    for mode in [Kept::Vendored, Kept::Agent] {
        let (cell, with) = (checkout("", "MODULE.bazel"), Patching::new(&[]));
        with.run(&cell, &mode.scan());
        std::fs::remove_file(cell.path(".bazelignore")).expect("remove the file");
        let dry = |command: &[&str]| {
            let left = cell.tree();
            let ran = with.ran(&cell, &[command, &["--dry-run"]].concat());
            assert_eq!(ran.code, 0, "{}", ran.dump);
            assert_eq!(changed(&left, &cell.tree()), NOTHING, "{}", ran.dump);
            ran
        };
        dry(&mode.scan());
        commands.iter().for_each(|command| drop(dry(command)));
        if mode == Kept::Vendored {
            let lib = format!("{}/lib.go", mode.copy_dir(&with.uuid));
            std::fs::remove_file(cell.path(&lib)).expect("remove a file of the copy");
            let repair = dry(&["repair"]);
            let event = find_event(&repair.envelope, "verified", None);
            assert_eq!(event["details"]["wouldRedownload"], true, "{}", repair.dump);
        }
    }
}

/// Without a Bazel: two projects under one Bazel root share its
/// `.bazelignore`, and each run holds the lock of its own project only. A
/// scan in each, both started at the same moment, leaves the pair of both,
/// round after round.
#[test]
fn two_projects_patched_at_once_both_get_their_bazelignore_line() {
    let (cell, with) = (checkout("a/", "MODULE.bazel"), Patching::new(&[]));
    for file in ["go.mod", "go.sum"] {
        cell.write(&format!("b/{file}"), &cell.tree()[&format!("a/{file}")]);
    }
    let (a, b) = (Kept::Vendored.ignored("a/"), Kept::Vendored.ignored("b/"));
    for round in 0..8 {
        std::thread::scope(|runs| {
            for project in ["a", "b"] {
                let (cell, with) = (&cell, &with);
                let scan = ["scan", "--mode", "vendored", "--yes", "--cwd", project];
                runs.spawn(move || drop(with.run(cell, &scan)));
            }
        });
        let file = String::from_utf8_lossy(&cell.tree()[".bazelignore"]).into_owned();
        let either = [format!("{a}{b}"), format!("{b}{a}")];
        assert!(either.contains(&file), "round {round}: {file:?}");
        std::fs::remove_file(cell.path(".bazelignore")).expect("remove the file");
    }
}

/// Without a Bazel: a hosted scan that takes a vendored module over removes
/// the copy, and the line with it.
#[test]
fn a_hosted_takeover_of_a_vendored_copy_takes_its_line_away() {
    let (cell, with) = (checkout("", "MODULE.bazel"), Patching::new(&[]));
    with.run(&cell, &Kept::Vendored.scan());
    assert!(cell.tree().contains_key(".bazelignore"));
    with.run(&cell, &["scan", "--mode", "hosted", "--yes"]);
    let tree = cell.tree();
    let go_mod = String::from_utf8_lossy(&tree["go.mod"]);
    let hosted = format!("=> {PATCH_HOST}/gopatch/{} {SOCKET_VERSION}", with.uuid);
    assert!(go_mod.contains(&hosted), "{go_mod}");
    let left: Vec<&String> = tree
        .keys()
        .filter(|f| f.starts_with(".socket/vendor/"))
        .collect();
    assert_eq!(left, NOTHING);
    assert!(!tree.contains_key(".bazelignore"));
}

/// Without a Bazel: `vendor` in a hosted project ejects every hosted pin or
/// none. Here the eject vendors the Go module and then fails on a second
/// pin, whose patch the service does not hand out, so it is rolled back: the
/// project is hosted as before, file for file, and no `.bazelignore` names
/// the directory of a copy that is gone again. The group commit is switched
/// off, as it is for an eject whose restore it cannot hold (a Gradle pin
/// beside the Go one), so that the vendored module is on disk when the
/// second pin fails.
#[test]
fn an_eject_that_is_rolled_back_leaves_no_bazelignore_line() {
    let (cell, with) = (checkout("", "MODULE.bazel"), Patching::new(&[]));
    with.run(&cell, &["scan", "--mode", "hosted", "--yes"]);
    let (origin, other) = (with.standin.origin(), uuid::Uuid::new_v4().to_string());
    let pinned = cell.tree();
    let text = |file: &str| String::from_utf8_lossy(&pinned[file]).into_owned();
    let socket = format!("{PATCH_HOST}/gopatch/{other} {SOCKET_VERSION}");
    cell.write(
        "go.mod",
        format!(
            "{}\nrequire example.com/other {VERSION}\n\nreplace example.com/other {VERSION} => {socket}\n",
            text("go.mod")
        ),
    );
    // Any well-formed sums: nothing fetches these modules.
    let (zip_h1, mod_h1) = (&with.upstream.zip_h1, &with.upstream.mod_h1);
    let sums_of = |path: &str, version: &str| {
        format!("{path} {version} {zip_h1}\n{path} {version}/go.mod {mod_h1}")
    };
    let socket_sums = sums_of(&format!("{PATCH_HOST}/gopatch/{other}"), SOCKET_VERSION);
    cell.write("go.sum", text("go.sum") + &socket_sums + "\n");
    let record = json!({
        "uuid": other, "purl": format!("pkg:golang/example.com/other@{VERSION}"),
        "publishedAt": "2026-01-01T00:00:00Z", "files": {}, "vulnerabilities": {},
        "description": "fixture", "license": "MIT", "tier": "free",
    });
    let view = format!("/v0/orgs/{ORG}/patches/view/{other}");
    with.standin.serve(1, &view, record.to_string().as_bytes());
    for (module, sums) in [
        (MODULE, with.upstream.go_sum().join("\n")),
        ("example.com/other", sums_of("example.com/other", VERSION)),
    ] {
        let lookup = format!("1\n{sums}\n\ngo.sum database tree\n1\nAAAA\n");
        let route = format!("/{SUMDB}/lookup/{module}@{VERSION}");
        with.standin.serve(5, &route, lookup.as_bytes());
    }
    let hosted = cell.tree();
    let env = [
        ("SOCKET_GOSUMDB_URL", format!("{origin}/{SUMDB}")),
        ("SOCKET_PATCH_SWITCH_OFF", "group_commit".to_string()),
    ];
    let env = env.each_ref().map(|(name, value)| (*name, value.as_str()));
    let eject = cell.socket_patch(&origin, &["vendor", "--yes"], &env);
    assert_eq!(eject.code, 1, "{}", eject.dump);
    let warnings = eject.envelope["warnings"].as_array();
    let rolled_back = |w: &serde_json::Value| w["code"] == "eject_rolled_back";
    assert!(
        warnings.is_some_and(|w| w.iter().any(rolled_back)),
        "{}",
        eject.dump
    );
    assert_eq!(changed(&hosted, &cell.tree()), NOTHING, "{}", eject.dump);
}

/// Without a Bazel: the same in agent mode, where `apply` is what finds a
/// copy without its line, and `rollback` leaves its emptied manifest. A dry
/// run of either changes nothing.
#[test]
fn an_agent_copy_has_its_bazelignore_line_while_it_is_on_disk() {
    let (cell, with, mode) = (checkout("", "WORKSPACE"), Patching::new(&[]), Kept::Agent);
    let before = cell.tree();
    with.run(&cell, &mode.scan());
    assert_eq!(cell.tree()[".bazelignore"], mode.ignored("").as_bytes());

    std::fs::remove_file(cell.path(".bazelignore")).expect("remove the file");
    with.run(&cell, &["apply", "--dry-run"]);
    assert!(!cell.tree().contains_key(".bazelignore"));
    with.run(&cell, &["apply"]);
    let patched = cell.tree();
    assert_eq!(patched[".bazelignore"], mode.ignored("").as_bytes());

    with.run(&cell, &["rollback", "--yes", "--dry-run"]);
    assert_eq!(changed(&patched, &cell.tree()), NOTHING);
    with.run(&cell, &["rollback", "--yes"]);
    assert_eq!(changed(&before, &cell.tree()), [".socket/manifest.json"]);
}

/// Without a Bazel: Bazel reads `.bazelignore` at the root of the workspace
/// only, so a project below the root gets its line there, with its path
/// from the root, after the lines the user has, in their line breaks. A
/// file whose last line has no line break still has none at its end. The
/// revert leaves the file of before, byte for byte, a last byte that is a
/// carriage return on its own included.
#[test]
fn a_project_below_the_bazel_root_is_named_from_the_root() {
    let mode = Kept::Vendored;
    let pair = mode.ignored("svc/go/");
    let files = [
        ("node_modules\n", pair.clone()),
        (
            "node_modules\r\nthird_party\r\n",
            pair.replace('\n', "\r\n"),
        ),
        (
            "node_modules\r\nthird_party",
            format!("\r\n{}", pair.trim_end().replace('\n', "\r\n")),
        ),
        ("node_modules\r", format!("\n{}", pair.trim_end())),
    ];
    for (old, added) in files {
        let (cell, with) = (checkout("svc/go/", "WORKSPACE.bazel"), Patching::new(&[]));
        cell.write(".bazelignore", old);
        with.run(&cell, &[&mode.scan()[..], &["--cwd", "svc/go"]].concat());
        let tree = cell.tree();
        let file = String::from_utf8_lossy(&tree[".bazelignore"]);
        assert_eq!(file, format!("{old}{added}"));
        assert!(!tree.contains_key("svc/go/.bazelignore"));
        with.run(&cell, &["vendor", "--revert", "--yes", "--cwd", "svc/go"]);
        assert_eq!(cell.tree()[".bazelignore"], old.as_bytes());
    }
}

/// Without a Bazel: a project that is in no Bazel workspace gets what it
/// got before there was a line to write: every file the run writes in a
/// workspace, byte for byte, and no `.bazelignore`, the one file the two
/// checkouts then differ in. A directory named like a workspace file marks
/// no workspace.
#[test]
fn a_project_in_no_bazel_workspace_gets_no_bazelignore() {
    for mode in [Kept::Vendored, Kept::Agent] {
        let with = Patching::new(&[]);
        let (plain, marked) = (
            checkout("", "WORKSPACE/README"),
            checkout("", "MODULE.bazel"),
        );
        let trees = [&plain, &marked].map(|cell| {
            let before = cell.tree();
            let scan = with.run(cell, &mode.scan());
            let warnings = scan.envelope["warnings"].as_array();
            assert!(warnings.is_none_or(Vec::is_empty), "{}", scan.dump);
            let after = cell.tree();
            (changed(&before, &after), after)
        });
        let [(plain_wrote, plain), (_, marked)] = trees;
        assert!(
            plain_wrote.contains(&"go.mod".to_string()),
            "{plain_wrote:?}"
        );
        assert!(!plain.contains_key(".bazelignore"));
        // Apart from the file that marks each checkout, and the marker of a
        // vendored copy, which holds the second it was written in.
        let apart = |file: &String| {
            ["WORKSPACE/README", "MODULE.bazel"].contains(&file.as_str())
                || file.ends_with("/socket-patch.vendor.json")
        };
        let mut differ = changed(&plain, &marked);
        differ.retain(|file| !apart(file));
        assert_eq!(differ, [".bazelignore"]);
    }
}

/// Without a Bazel: with `SOCKET_NO_BAZEL=1` a run that keeps a copy of a
/// Go module in a Bazel workspace writes no `.bazelignore` and says
/// nothing of one: it is the run of the same checkout without its
/// `MODULE.bazel`, to the byte, in vendored and in agent mode. What an
/// earlier run wrote is still undone with the variable set: the revert of
/// a copy takes its pair, and the file that was made for it, away.
#[test]
fn the_switch_adds_no_bazelignore_line_and_still_takes_one_away() {
    let (cell, with) = (checkout("", "MODULE.bazel"), Patching::new(&[]));
    let modcache = with.modcache.path().to_str().expect("a UTF-8 path");
    let (origin, env) = (with.standin.origin(), [("GOMODCACHE", modcache)]);
    let before = cell.tree();
    for mode in [Kept::Vendored, Kept::Agent] {
        let beside = cell.off_is_without_bazel(&origin, &mode.scan(), &env, &["MODULE.bazel"]);
        let ignored = beside[0]["files"][".bazelignore"].as_str();
        assert_eq!(ignored, Some(mode.ignored("").as_str()), "{beside:#}");
    }

    with.run(&cell, &Kept::Vendored.scan());
    assert!(cell.tree().contains_key(".bazelignore"));
    let off = [env[0], ("SOCKET_NO_BAZEL", "1")];
    let undo = cell.socket_patch(&origin, &["vendor", "--revert", "--yes"], &off);
    assert_eq!(undo.code, 0, "{}", undo.dump);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{}", undo.dump);
}

/// Without a Bazel: a project that is in no git checkout looks no further
/// than its own directory. Below a Bazel root it is patched as anywhere
/// else, and gets no line and no warning: nothing above it is read, not
/// the `.bazelignore` of that root either, here a directory that no read
/// gets through. With a workspace file of its own it has its line in its
/// own directory. `GIT_CEILING_DIRECTORIES` ends the walk at the workspace
/// copy, so that a checkout above the temp directory changes nothing.
#[test]
fn a_project_in_no_git_checkout_looks_at_its_own_directory_only() {
    for mode in [Kept::Vendored, Kept::Agent] {
        let (cell, with) = (checkout("svc/", "MODULE.bazel"), Patching::new(&[]));
        std::fs::remove_dir_all(cell.path(".git")).expect("remove .git");
        cell.write(".bazelignore/README", "a directory in the file's place");
        let ceiling = cell.path("..");
        let env = [
            ("GOMODCACHE", with.modcache.path().to_str().expect("UTF-8")),
            ("GIT_CEILING_DIRECTORIES", ceiling.to_str().expect("UTF-8")),
        ];
        let scan = [&mode.scan()[..], &["--cwd", "svc"]].concat();
        let before = cell.tree();
        for own_root in [false, true] {
            if own_root {
                cell.write("svc/WORKSPACE", "");
            }
            let ran = cell.socket_patch(&with.standin.origin(), &scan, &env);
            assert_eq!(ran.code, 0, "{}", ran.dump);
            assert_eq!(not_updated(&ran), NOTHING, "{}", ran.dump);
            let wrote = changed(&before, &cell.tree());
            let ignores: Vec<_> = wrote
                .iter()
                .filter(|f| f.contains(".bazelignore"))
                .collect();
            let own: &[&str] = if own_root { &["svc/.bazelignore"] } else { &[] };
            assert_eq!(ignores, own, "{}", ran.dump);
            assert!(wrote.contains(&"svc/go.mod".to_string()), "{wrote:?}");
        }
        let file = String::from_utf8_lossy(&cell.tree()["svc/.bazelignore"]).into_owned();
        assert_eq!(file, mode.ignored(""));
    }
}

/// The `bazelignore_not_updated` warnings of a run.
fn not_updated(ran: &Ran) -> Vec<&str> {
    let warnings = ran.envelope["warnings"].as_array();
    let ours = |w: &&serde_json::Value| w["code"] == "bazelignore_not_updated";
    let details = warnings.into_iter().flatten().filter(ours);
    details
        .map(|w| w["detail"].as_str().expect("a detail"))
        .collect()
}

/// Make the `.bazelignore` of `cell` read-only. `false`: this user writes a
/// read-only file all the same (root).
fn read_only(cell: &Cell) -> bool {
    let file = cell.path(".bazelignore");
    let mut bits = std::fs::metadata(&file).expect("the file").permissions();
    bits.set_readonly(true);
    std::fs::set_permissions(&file, bits).expect("make the file read-only");
    std::fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .is_err()
}

/// Without a Bazel: a `.bazelignore` that socket-patch cannot write fails
/// no command: a directory in its place, and a read-only file. Each
/// command that ends with the copy on disk warns once, with the line
/// the user has to add, the patch stands, and the file stays as it is: a
/// scan whose prune pass comes to the file a second time included, in its
/// envelope and on the stderr a person reads. The undo, which leaves
/// nothing to add, warns of nothing.
#[test]
fn a_bazelignore_that_cannot_be_written_is_one_warning() {
    for (mode, obstacle) in [Kept::Vendored, Kept::Agent]
        .into_iter()
        .flat_map(|mode| ["a directory", "read-only"].map(|obstacle| (mode, obstacle)))
    {
        let (cell, with) = (checkout("", "MODULE.bazel"), Patching::new(&[]));
        if obstacle == "a directory" {
            cell.write(".bazelignore/README", "a directory in the file's place");
        } else {
            cell.write(".bazelignore", "node_modules\n");
            if !read_only(&cell) {
                continue;
            }
        }
        let before = cell.tree();
        let prune = ["scan", "--mode", "vendored", "--yes", "--prune"];
        let (keeping, undo): (&[&[&str]], &[&str]) = match mode {
            Kept::Vendored => (
                &[
                    &["repair"],
                    &["rollback", "--yes", "--preserve-state"],
                    &prune,
                ],
                &["vendor", "--revert", "--yes"],
            ),
            Kept::Agent => (&[&["apply"]], &["rollback", "--yes"]),
        };
        let scan = mode.scan();
        // A copy no ledger entry owns, which the prune pass sweeps: the scan
        // comes to the file a second time after that, and warns once.
        let orphan = format!("{}/{}", mode.copies(), uuid::Uuid::new_v4());
        for command in [&scan[..]].iter().chain(keeping) {
            if *command == prune {
                cell.write(
                    &format!("{orphan}/example.com/orphan@v1.0.0/go.mod"),
                    "module x\n",
                );
            }
            let ran = with.run(&cell, command);
            assert!(!cell.path(&orphan).exists(), "{obstacle}: {}", ran.dump);
            let [detail] = not_updated(&ran)[..] else {
                panic!("{obstacle}: {}", ran.dump);
            };
            let line = format!("add `{}` to it", mode.copies());
            assert!(detail.contains(&line), "{obstacle}: {detail}");
        }
        // The same scan as a person runs it: the pass that sweeps the copy
        // comes to the file after the scan has warned, and says no more.
        if mode == Kept::Vendored {
            let swept = format!("{orphan}/example.com/orphan@v1.0.0/go.mod");
            cell.write(&swept, "module x\n");
            let [_, stderr] = with.person(&cell, &prune);
            assert!(!cell.path(&swept).exists(), "{obstacle}");
            assert_eq!(stderr.len(), 1, "{obstacle}: {stderr:?}");
        }
        let tree = cell.tree();
        let lib = format!("{}/lib.go", mode.copy_dir(&with.uuid));
        assert!(tree.contains_key(&lib), "{obstacle}: {:?}", tree.keys());
        let ignore = |tree: &Tree| -> Vec<(String, Vec<u8>)> {
            let ours = tree
                .iter()
                .filter(|(file, _)| file.starts_with(".bazelignore"));
            ours.map(|(file, bytes)| (file.clone(), bytes.clone()))
                .collect()
        };
        assert_eq!(ignore(&tree), ignore(&before), "{obstacle}");
        let ran = with.run(&cell, undo);
        assert_eq!(not_updated(&ran), NOTHING, "{obstacle}: {}", ran.dump);
        assert_eq!(ignore(&cell.tree()), ignore(&before), "{obstacle}");
    }
}

/// Without a Bazel: a read-only `.bazelignore` that holds the pair of a
/// copy the undo removes is neither replaced nor deleted: the undo stands,
/// and warns once that the two lines can go.
#[test]
fn a_read_only_bazelignore_keeps_the_pair_of_a_copy_that_is_gone() {
    for (mode, old) in [Kept::Vendored, Kept::Agent]
        .into_iter()
        .flat_map(|mode| ["", "node_modules\n"].map(|old| (mode, old)))
    {
        let (cell, with) = (checkout("", "MODULE.bazel"), Patching::new(&[]));
        cell.write(".bazelignore", old);
        with.run(&cell, &mode.scan());
        let patched = cell.tree();
        assert_eq!(
            patched[".bazelignore"],
            format!("{old}{}", mode.ignored("")).as_bytes()
        );
        if !read_only(&cell) {
            return;
        }
        let undo: &[&str] = match mode {
            Kept::Vendored => &["vendor", "--revert", "--yes"],
            Kept::Agent => &["rollback", "--yes"],
        };
        let ran = with.run(&cell, undo);
        let [detail] = not_updated(&ran)[..] else {
            panic!("{}", ran.dump);
        };
        assert!(detail.contains("can be deleted"), "{detail}");
        let tree = cell.tree();
        assert_eq!(tree[".bazelignore"], patched[".bazelignore"]);
        let copies: Vec<&String> = tree
            .keys()
            .filter(|f| f.starts_with(mode.copies()))
            .collect();
        assert_eq!(copies, NOTHING, "{}", ran.dump);
        let bits = std::fs::metadata(cell.path(".bazelignore")).expect("the file");
        assert!(bits.permissions().readonly());
    }
}

/// Without a Bazel: the user's "no". With the path line commented out
/// under socket-patch's comment line, no command adds a line for that
/// directory, warns about it, or touches the two lines, whether the copy
/// is written, repaired, unwired or removed. The pair of the other
/// directory comes with that directory and goes with it.
#[test]
fn a_commented_out_bazelignore_line_stays_declined() {
    for mode in [Kept::Vendored, Kept::Agent] {
        let (cell, with) = (checkout("", "MODULE.bazel"), Patching::new(&[]));
        with.run(&cell, &mode.scan());
        let declined = mode.ignored("").replace("\n.socket", "\n# .socket");
        assert_ne!(declined, mode.ignored(""));
        cell.write(".bazelignore", &declined);
        let (other, scan) = match mode {
            Kept::Vendored => (Kept::Agent, mode.scan()),
            Kept::Agent => (Kept::Vendored, mode.scan()),
        };
        let unrelated = format!("{}/README", other.copies());
        cell.write(&unrelated, "a directory of the other mode");
        let commands: &[&[&str]] = match mode {
            Kept::Vendored => &[
                &scan,
                &["repair"],
                &["rollback", "--yes", "--preserve-state"],
                &scan,
                &["vendor", "--revert", "--yes"],
            ],
            Kept::Agent => &[&scan, &["apply"], &["rollback", "--yes"]],
        };
        for (n, command) in commands.iter().enumerate() {
            if n + 1 == commands.len() {
                let _ = std::fs::remove_dir_all(cell.path(other.copies()));
            }
            let ran = with.run(&cell, command);
            assert_eq!(not_updated(&ran), NOTHING, "{}", ran.dump);
            let mut file = declined.clone();
            if cell.path(other.copies()).is_dir() {
                file += &other.ignored("");
            }
            let tree = cell.tree();
            assert_eq!(
                String::from_utf8_lossy(&tree[".bazelignore"]),
                file,
                "{command:?}"
            );
        }
        let tree = cell.tree();
        assert_eq!(tree[".bazelignore"], declined.as_bytes());
        let copies: Vec<&String> = tree
            .keys()
            .filter(|f| f.starts_with(mode.copies()))
            .collect();
        assert_eq!(copies, NOTHING);
    }
}

/// Without a Bazel: `scan --prune` reverts a vendored module that the
/// project no longer uses: its lines are gone from `go.mod` and `go.sum`,
/// and the module from the module cache. That removes the last copy, and
/// the line goes with it.
#[test]
fn a_prune_that_removes_the_last_copy_takes_its_line_away() {
    let (cell, with) = (checkout("", "MODULE.bazel"), Patching::new(&[]));
    with.run(&cell, &Kept::Vendored.scan());
    let patched = cell.tree();
    assert!(patched.contains_key(".bazelignore"));
    let go_mod = String::from_utf8_lossy(&patched["go.mod"]);
    let unused: Vec<&str> = go_mod
        .lines()
        .filter(|line| !line.starts_with("require ") && !line.starts_with("replace "))
        .collect();
    assert_eq!(unused.len() + 2, go_mod.lines().count(), "{go_mod}");
    cell.write("go.mod", unused.join("\n") + "\n");
    cell.write("go.sum", "");
    let empty = with.modcache.path().join("empty");
    let env = [("GOMODCACHE", empty.to_str().expect("a UTF-8 path"))];
    let prune = ["scan", "--mode", "vendored", "--yes", "--prune"];
    let prune = cell.socket_patch(&with.standin.origin(), &prune, &env);
    assert_eq!(prune.code, 0, "{}", prune.dump);
    let tree = cell.tree();
    let copies: Vec<&String> = tree
        .keys()
        .filter(|f| f.starts_with(".socket/vendor/"))
        .collect();
    assert_eq!(copies, NOTHING, "{}", prune.dump);
    assert!(!tree.contains_key(".bazelignore"), "{}", prune.dump);
}

/// Without a Bazel: a command whose `--ecosystems` leaves Go out adds no
/// line for a Go copy; the same command without the option leaves the file
/// in line with the copy. `remove` of the Go patch and `vendor --revert`
/// remove the Go copy whatever the option says, and then its pair goes
/// with it, out of a file that keeps the user's line.
#[test]
fn a_run_that_leaves_go_out_adds_no_line_and_takes_the_pair_of_a_copy_it_removed_away() {
    let (cell, with) = (checkout("", "MODULE.bazel"), Patching::new(&[]));
    with.run(&cell, &Kept::Vendored.scan());
    std::fs::remove_file(cell.path(".bazelignore")).expect("remove the file");
    for command in [&["repair"][..], &["scan", "--mode", "vendored", "--yes"]] {
        with.run(&cell, &[command, &["--ecosystems", "npm"]].concat());
        assert!(!cell.tree().contains_key(".bazelignore"), "{command:?}");
    }
    with.run(&cell, &["repair"]);
    let pair = Kept::Vendored.ignored("");
    assert_eq!(cell.tree()[".bazelignore"], pair.as_bytes());

    let undos: [&[&str]; 2] = [&["remove", PURL, "--yes"], &["vendor", "--revert", "--yes"]];
    for undo in undos {
        with.run(&cell, &Kept::Vendored.scan());
        cell.write(".bazelignore", format!("node_modules\n{pair}"));
        let ran = with.run(&cell, &[undo, &["--ecosystems", "npm"]].concat());
        let tree = cell.tree();
        let copies: Vec<&String> = tree
            .keys()
            .filter(|f| f.starts_with(Kept::Vendored.copies()))
            .collect();
        assert_eq!(copies, NOTHING, "{}", ran.dump);
        assert_eq!(tree[".bazelignore"], b"node_modules\n", "{}", ran.dump);
        assert_eq!(not_updated(&ran), NOTHING, "{}", ran.dump);
    }
}

/// Without a Bazel: a scan that `socket.yml` lets write nothing
/// (`patches.enabled: false`: report only) leaves the file alone too, in
/// every mode, with a copy on disk that has no line. That is why the
/// hosted scan comes to the file only when it took the apply lock, which
/// it takes only when it has something to write.
#[test]
fn a_scan_that_may_write_nothing_leaves_the_file_alone() {
    let scans: [&[&str]; 6] = [
        &["scan", "--yes"],
        &["scan", "--mode", "hosted", "--yes"],
        &["scan", "--mode", "vendored", "--yes"],
        &["scan", "--mode", "agent", "--yes"],
        &["scan", "--mode", "vendored", "--yes", "--prune"],
        &["scan", "--sync", "--yes"],
    ];
    for mode in [Kept::Vendored, Kept::Agent] {
        let (cell, with) = (checkout("", "MODULE.bazel"), Patching::new(&[]));
        with.run(&cell, &mode.scan());
        std::fs::remove_file(cell.path(".bazelignore")).expect("remove the file");
        cell.write("socket.yml", "version: 2\npatches:\n  enabled: false\n");
        let before = cell.tree();
        for scan in scans {
            let ran = with.run(&cell, scan);
            let warnings = ran.envelope["warnings"].as_array();
            let disabled = |w: &serde_json::Value| w["code"] == "patches_disabled";
            assert!(
                warnings.is_some_and(|w| w.iter().any(disabled)),
                "{}",
                ran.dump
            );
            assert_eq!(changed(&before, &cell.tree()), NOTHING, "{}", ran.dump);
        }
    }
}

/// The lines of a run's stdout and of its stderr that name a `.bazelignore`.
fn naming_the_file(streams: [String; 2]) -> [Vec<String>; 2] {
    streams.map(|text| {
        let named = text.lines().filter(|line| line.contains(".bazelignore"));
        named.map(str::to_string).collect()
    })
}

/// What a person is told of a `.bazelignore` whose lines changed.
const UPDATED: &str =
    ".bazelignore: the lines that keep patched Go module copies under .socket out of \
     Bazel's packages";

/// Without a Bazel: what a person reads. A run that changes the file says
/// so on stdout, in words that hold for lines that came and for lines that
/// went; one that deletes the file says that; and one that cannot write it
/// warns on stderr.
#[test]
fn a_person_is_told_that_the_file_changed() {
    let (cell, with) = (checkout("", "MODULE.bazel"), Patching::new(&[]));
    let mode = Kept::Agent;
    with.run(&cell, &mode.scan());
    let person = |args: &[&str]| with.person(&cell, args);
    let told =
        |line: &String, start: &str, end: &str| line.starts_with(start) && line.ends_with(end);
    assert_eq!(person(&["apply"]), [NOTHING, NOTHING], "nothing changed");

    // A pair that came.
    std::fs::remove_file(cell.path(".bazelignore")).expect("remove the file");
    let [stdout, stderr] = person(&["apply"]);
    assert!(
        matches!(&stdout[..], [line] if told(line, "Updated ", UPDATED)),
        "{stdout:?}"
    );
    assert_eq!(stderr, NOTHING);

    // A pair that went, out of a file that keeps the user's line, and then
    // out of one that held nothing else.
    cell.write(
        ".bazelignore",
        format!("node_modules\n{}", mode.ignored("")),
    );
    let [stdout, stderr] = person(&["rollback", "--yes"]);
    assert!(
        matches!(&stdout[..], [line] if told(line, "Updated ", UPDATED)),
        "{stdout:?}"
    );
    assert_eq!(stderr, NOTHING);
    assert_eq!(cell.tree()[".bazelignore"], b"node_modules\n");
    with.run(&cell, &mode.scan());
    cell.write(".bazelignore", mode.ignored(""));
    let [stdout, stderr] = person(&["rollback", "--yes"]);
    let gone = ".bazelignore: no patched Go module copy is left under .socket";
    assert!(
        matches!(&stdout[..], [line] if told(line, "Removed ", gone)),
        "{stdout:?}"
    );
    assert_eq!(stderr, NOTHING);
    assert!(!cell.tree().contains_key(".bazelignore"));

    // A file that cannot be written.
    with.run(&cell, &mode.scan());
    std::fs::remove_file(cell.path(".bazelignore")).expect("remove the file");
    cell.write(".bazelignore/README", "a directory in the file's place");
    let [stdout, stderr] = person(&["apply"]);
    assert_eq!(stdout, NOTHING);
    let warned = |line: &String| line.starts_with("Warning: could not update ");
    assert!(matches!(&stderr[..], [line] if warned(line)), "{stderr:?}");
}

/// Without a Bazel: `--manifest-path` can name the manifest of another
/// project. The agent copies are those of `--cwd` and the vendored ones
/// those of the manifest's project, so one command brings the file of each
/// project's Bazel root in line: one file when both are under one root,
/// which a person is told of once, and two when the manifest's project is
/// in another checkout with a Bazel root of its own.
#[test]
fn a_manifest_in_another_project_brings_the_file_of_both_projects_in_line() {
    for (other, files) in [("b/", 1), ("other/c/", 2)] {
        let cell = checkout("a/", "MODULE.bazel");
        cell.write("a/.socket/go-patches/README", "the agent copies of `a`");
        cell.write(
            &format!("{other}.socket/manifest.json"),
            "{\"patches\":{}}\n",
        );
        cell.write(
            &format!("{other}.socket/vendor/golang/README"),
            "the vendored copies of the other project",
        );
        if files == 2 {
            cell.write("other/.git/HEAD", "ref: refs/heads/main\n");
            cell.write("other/WORKSPACE", "");
        }
        let manifest = format!("../{other}.socket/manifest.json");
        let apply = [
            "apply",
            "--offline",
            "--cwd",
            "a",
            "--manifest-path",
            &manifest,
        ];
        // No API: the run is offline.
        let ran = cell.socket_patch_person("http://127.0.0.1:9", &apply, &[]);
        let [stdout, stderr] = naming_the_file(ran);
        assert_eq!(stderr, NOTHING);
        assert_eq!(stdout.len(), files, "{stdout:?}");
        assert!(
            stdout.iter().all(|line| line.starts_with("Updated ")),
            "{stdout:?}"
        );
        let tree = cell.tree();
        let (agent, vendored) = (Kept::Agent.ignored("a/"), Kept::Vendored);
        let (root, others) = match files {
            1 => (format!("{agent}{}", vendored.ignored("b/")), None),
            _ => (agent, Some(vendored.ignored("c/"))),
        };
        assert_eq!(String::from_utf8_lossy(&tree[".bazelignore"]), root);
        let theirs = tree.get("other/.bazelignore");
        assert_eq!(
            theirs.map(|file| String::from_utf8_lossy(file).into_owned()),
            others
        );
    }
}

/// Without a Bazel: the fixture's directories are those of its table, its
/// `go.sum` pins the module the test serves, which holds the `h1:`
/// arithmetic here to sums that `go` computed, and its `go.mod` names the
/// module of [`PRODUCT`].
#[test]
fn the_fixture_pins_the_upstream_module_the_test_serves() {
    FIXTURE.check();
    let path = fixture_path(FIXTURE.dir).join("common/go.sum");
    let go_sum = std::fs::read_to_string(&path).expect("the fixture's go.sum");
    let lines: Vec<&str> = go_sum.lines().collect();
    assert_eq!(lines, upstream().go_sum(), "{}", path.display());
    let go_mod = std::fs::read_to_string(path.with_file_name("go.mod")).expect("go.mod");
    let module = PRODUCT.strip_prefix("pkg:golang/").expect("a Go module");
    let line = format!("module {module}");
    assert!(go_mod.lines().any(|named| named == line), "{go_mod}");
}
