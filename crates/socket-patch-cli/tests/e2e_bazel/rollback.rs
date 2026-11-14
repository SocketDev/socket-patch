//! Hermetic CLI tests: `rollback`, `remove`, `repair` and the
//! withdrawn-pin sweep under a Bazel root (design 7, hazards HZ-02 and
//! HZ-26; revision 4, architecture 4 and 8.6).
//!
//! A restoring edit is judged like a forward one. The built binary shows
//! what a command a person ran does (it restores, and names the command
//! that refreshes what Bazel derived) and what the automatic sweep does
//! (it keeps a pin whose restore would fail every build). Its lanes are
//! all disabled, so it can undo no row of the owned index: it keeps each,
//! with the record of its patch. What an undo does once a lane restores a
//! row is shown in process, over lane tables of the test's own.
//!
//! No Bazel and no network: a loopback server stands in for the Socket API
//! and for the package registries.

// The hosted toy lane of `hosted_engine`, for its workspace and its
// restore: each suite uses a part of it.
#[allow(dead_code)]
#[path = "hosted_engine/lane.rs"]
pub(crate) mod lane;

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use socket_patch_cli::args::GlobalArgs;
use socket_patch_cli::bazel_gate::commands::{self, undo_rows};
use socket_patch_cli::commands::remove::RemoveArgs;
use socket_patch_cli::commands::rollback::RollbackArgs;
use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::model::{
    Digest, Files, IndexRow, LaneCx, LaneOps, LaneSpec, LaneTable, Mode, RestoreOutcome, Ruleset,
};
use socket_patch_core::bazel::owned_index::{Index, IndexEdit, INDEX_PATH};
use socket_patch_core::patch::redirect::upstream::{HostedPin, PinStatus, RestoreOptions};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::bazel_common::{assert_restore_policy, assert_same_tree, changes, snapshot};
use crate::common::envelope::{all_codes, event_for, event_purls, has_event, parse_json_envelope};
use crate::common::{
    envelope_error_code, git_sha256, run_with_env, write_minimal_manifest, PatchEntry,
};

pub(crate) const ORG: &str = "test-org";
const MANIFEST: &str = ".socket/manifest.json";

/// A checkout with an npm project whose pnpm lock resolves `left-pad`, and
/// (`bazel`) the rules_js hub that makes Bazel build from that lock.
pub(crate) struct Checkout {
    _tmp: tempfile::TempDir,
    pub(crate) root: PathBuf,
}

impl Checkout {
    pub(crate) fn new(bazel: bool) -> Self {
        let tmp = tempfile::tempdir().expect("a temporary directory");
        let root = std::fs::canonicalize(tmp.path()).expect("its real path");
        let ws = Self { _tmp: tmp, root };
        // `.git` makes the directory the repository: nothing above is read.
        ws.put(".git/HEAD", "ref: refs/heads/main\n");
        ws.put(lane::LOCK, lane::LOCK_TEXT);
        let deps = r#"{"name": "p", "version": "0.0.0", "dependencies": {"left-pad": "1.3.0"}}"#;
        ws.put("package.json", deps);
        if bazel {
            ws.put(".bazelversion", lane::BAZELVERSION);
            let module = lane::MODULE.replace("LOCK_LABEL", "//:pnpm-lock.yaml");
            ws.put("MODULE.bazel", module);
        }
        ws
    }

    /// `rel` below the checkout, level by level.
    pub(crate) fn at(&self, rel: &str) -> PathBuf {
        let levels = rel.split('/').filter(|level| !level.is_empty());
        levels.fold(self.root.clone(), |at, level| at.join(level))
    }

    pub(crate) fn put(&self, rel: &str, bytes: impl AsRef<[u8]>) {
        let file = self.at(rel);
        std::fs::create_dir_all(file.parent().expect("a parent")).expect("mkdir");
        std::fs::write(file, bytes).expect("write");
    }

    pub(crate) fn get(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.at(rel)).ok()
    }

    /// The manifest record of the patch of `left-pad`, with its blobs.
    pub(crate) fn record(&self) {
        let (before, after) = (git_sha256(b"upstream\n"), git_sha256(b"patched\n"));
        let entry = PatchEntry {
            file_name: "package/index.js",
            before_hash: &before,
            after_hash: &after,
        };
        write_minimal_manifest(&self.at(".socket"), lane::PURL, lane::UUID, &[entry]);
        self.put(&format!(".socket/blobs/{before}"), "upstream\n");
        self.put(&format!(".socket/blobs/{after}"), "patched\n");
    }

    /// A `pins` row of the owned index, hand-written: `lane` replaced
    /// `original` by `new` in the lock.
    fn row(&self, index: &mut Index, lane: &str, key: &str, (original, new): (&str, &str)) {
        index.record_pin(IndexRow {
            uuid: lane::UUID.to_string(),
            purl: lane::PURL.to_string(),
            lane: lane.to_string(),
            file: lane::LOCK.to_string(),
            edits: vec![IndexEdit {
                key: key.to_string(),
                original: original.to_string(),
                new: new.to_string(),
            }],
            check: None,
        });
        self.put(INDEX_PATH, index.render().expect("an index that renders"));
    }

    fn records(&self) -> Vec<String> {
        let manifest = self.get(MANIFEST).expect("the manifest");
        let manifest: Value = serde_json::from_str(&manifest).expect("JSON");
        let patches = manifest["patches"].as_object().expect("patches");
        patches.keys().cloned().collect()
    }

    /// An installed copy of `left-pad` with the patch of [`Self::record`]
    /// applied: what an in-place restore would put back to upstream. A
    /// run that restores nothing leaves it patched, which a snapshot of
    /// the tree sees.
    pub(crate) fn install(&self) {
        let package = r#"{"name": "left-pad", "version": "1.3.0"}"#;
        self.put("node_modules/left-pad/package.json", package);
        self.put(INSTALLED, "patched\n");
    }
}

/// The patched file of the installed copy ([`Checkout::install`]).
const INSTALLED: &str = "node_modules/left-pad/index.js";

/// The lock as native hosted mode pins it: the hosted URL and its digest.
pub(crate) fn hosted_lock() -> String {
    lane::LOCK_TEXT.replace(lane::UPSTREAM, &lane::native_pin())
}

/// The lock as a lane over a generated value pins it: the digest alone,
/// which only a row of the owned index tells from the upstream one.
fn row_lock() -> String {
    lane::LOCK_TEXT.replace(lane::UPSTREAM, &lane::pinned())
}

/// The npm registry and the crates.io index, each with the one upstream
/// release a restore looks up.
pub(crate) async fn registries(server: &MockServer) {
    let tarball = format!(
        "{}/npm-registry/left-pad/-/left-pad-1.3.0.tgz",
        server.uri()
    );
    let dist = json!({ "tarball": tarball, "integrity": lane::UPSTREAM_SRI });
    let version = json!({ "name": "left-pad", "version": "1.3.0", "dist": dist });
    Mock::given(method("GET"))
        .and(path("/npm-registry/left-pad/1.3.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(version))
        .mount(server)
        .await;
    let serde = json!({
        "name": "serde", "vers": "1.0.190", "deps": [], "features": {}, "yanked": false,
        "cksum": "91d3c334ca1ee894a2c6f6ad7bf058a4d9a3b30e9e0d5a9d1f3e8f0c2c9c0000",
    });
    Mock::given(method("GET"))
        .and(path("/crates-index/se/rd/serde"))
        .respond_with(ResponseTemplate::new(200).set_body_string(serde.to_string()))
        .mount(server)
        .await;
}

/// The Socket API of a scan that is offered no patch, and is told that
/// the patch `withdrawn` is no longer published.
async fn api_without(server: &MockServer, withdrawn: &str) {
    let none = json!({ "packages": [], "canAccessPaidPatches": false });
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(none))
        .mount(server)
        .await;
    let gone = json!({ "results": { withdrawn: { "status": "withdrawn" } } });
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(gone))
        .mount(server)
        .await;
}

/// The binary in `cwd` with the registries at `server`: the exit code and
/// the envelope. It runs off the async threads, which serve meanwhile.
pub(crate) async fn run(cwd: &Path, args: &[&str], server: &MockServer) -> (i32, Value) {
    let (cwd, uri) = (cwd.to_path_buf(), server.uri());
    let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
    let ran = tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let (npm, crates) = (format!("{uri}/npm-registry"), format!("{uri}/crates-index"));
        // The patch service and Go's checksum database too: no run of
        // this suite reaches the real ones.
        let env = [
            ("SOCKET_NPM_REGISTRY", npm.as_str()),
            ("SOCKET_CRATES_INDEX", &crates),
            ("SOCKET_GOSUMDB_URL", &uri),
            ("SOCKET_VENDOR_URL", &uri),
        ];
        run_with_env(&cwd, &args, &env)
    });
    let (code, stdout, stderr) = ran.await.expect("the binary ran");
    assert!(!stdout.is_empty(), "no envelope (exit {code}):\n{stderr}");
    (code, parse_json_envelope(&stdout))
}

/// A hosted scan of `cwd` against the API at `server`.
async fn scan(cwd: &Path, server: &MockServer) -> (i32, Value) {
    let uri = server.uri();
    let args = ["scan", "--mode", "hosted", "--yes", "--json", "--org", ORG];
    let api = ["--api-token", "fake-token", "--api-url", uri.as_str()];
    run(cwd, &[&args[..], &api[..]].concat(), server).await
}

/// What a person reads on stderr from the same scan without `--json`.
async fn scan_as_a_person(cwd: &Path, server: &MockServer) -> String {
    let (cwd, uri) = (cwd.to_path_buf(), server.uri());
    let ran = tokio::task::spawn_blocking(move || {
        let args = ["scan", "--mode", "hosted", "--yes", "--org", ORG];
        let api = ["--api-token", "fake-token", "--api-url", uri.as_str()];
        let npm = format!("{uri}/npm-registry");
        let env = [
            ("SOCKET_NPM_REGISTRY", npm.as_str()),
            ("SOCKET_VENDOR_URL", uri.as_str()),
        ];
        run_with_env(&cwd, &[&args[..], &api[..]].concat(), &env)
    });
    let (_, _, stderr) = ran.await.expect("the binary ran");
    stderr
}

/// Every Bazel code an envelope carries.
pub(crate) fn bazel_codes(envelope: &Value) -> Vec<String> {
    let known = |code: &String| Code::ALL.iter().any(|c| c.as_str() == code);
    all_codes(envelope).into_iter().filter(known).collect()
}

/// The details of the warnings of `code`.
fn warnings(envelope: &Value, code: Code) -> Vec<String> {
    let warnings = envelope["warnings"].as_array().cloned().unwrap_or_default();
    let of_code = |w: &&Value| w["code"] == code.as_str();
    let detail = |w: &Value| w["detail"].as_str().expect("a detail").to_string();
    warnings.iter().filter(of_code).map(detail).collect()
}

/// The detail of the one warning of `code`.
fn warning(envelope: &Value, code: Code) -> String {
    let found = warnings(envelope, code);
    let [one] = found.as_slice() else {
        panic!("one `{code}` warning: {envelope:#}");
    };
    one.clone()
}

/// A `MODULE.bazel.lock` whose one extension records the pnpm lock as
/// `lock`: of family A (Bazel 6.2 to 7.1), or of family B (7.2 and later)
/// with a `facts` member. Both are lock vectors Bazel wrote.
fn module_lock(family_b: bool, lock: &str) -> String {
    module_lock_of(family_b, lane::LOCK, lock)
}

/// [`module_lock`] for the lock at the root-relative `path`.
fn module_lock_of(family_b: bool, path: &str, lock: &str) -> String {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../socket-patch-core/tests");
    let vector = match family_b {
        true => "module_lock/stale-repair/bazel-8.8.2/baseline",
        false => "probe_vectors/lockfile/recorded-inputs/bazel-6.6.0/fresh/root",
    };
    let vector = format!("fixtures/bazel/{vector}.MODULE.bazel.lock");
    let levels = vector.split('/');
    let file = levels.fold(fixtures, |at, level| at.join(level));
    let bytes = std::fs::read(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    let mut doc: Value = serde_json::from_slice(&bytes).expect("a lock vector");
    let digest = Digest::sha256_hex(lock.as_bytes());
    let entry = &mut doc["moduleExtensions"]["//:ext.bzl%toy"]["general"];
    assert!(entry.is_object(), "the vector has the toy extension");
    let (package, name) = path.rsplit_once('/').unwrap_or(("", path));
    match family_b {
        true => entry["recordedInputs"] = json!([format!("FILE:@@//{path} {digest}")]),
        false => {
            entry["accumulatedFileDigests"] = json!({ (format!("@@//{package}:{name}")): digest })
        }
    }
    assert_eq!(doc.get("facts").is_some(), family_b);
    serde_json::to_string_pretty(&doc).expect("JSON")
}

// ── The built binary: a restoring edit ───────────────────────────────

/// `rollback` of a hosted pin in the lock a hub reads restores it, in
/// either lock family, and names the one command that refreshes the
/// record Bazel keeps of the lock: at `warn` and with "builds fail" where
/// the lock is frozen, and with the `bazel clean --expunge` sentence, never
/// as a first step, where the lock stores facts on a line that includes
/// Bazel 8.5 to 9.2. `MODULE.bazel.lock` is never written. The same
/// project under no Bazel root is restored with no Bazel code at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restore_names_the_refresh_of_each_lock_family() {
    let server = MockServer::start().await;
    registries(&server).await;
    let frozen = "common --lockfile_mode=error\n";
    for (family_b, version, rc) in [
        (false, "7.1.2\n", ""),
        (true, "8.8.2\n", ""),
        (true, "8.8.2\n", frozen),
    ] {
        let ws = Checkout::new(true);
        ws.put(".bazelversion", version);
        ws.put(".bazelrc", rc);
        ws.put(lane::LOCK, hosted_lock());
        ws.put("MODULE.bazel.lock", module_lock(family_b, &hosted_lock()));
        let before = snapshot(&ws.root);
        let (code, envelope) = run(&ws.root, &["rollback", "--json", "--yes"], &server).await;
        assert_eq!(code, 0, "{version} {rc:?}: {envelope:#}");
        assert_eq!(ws.get(lane::LOCK).as_deref(), Some(lane::LOCK_TEXT));
        let after = snapshot(&ws.root);
        let changed: Vec<String> = changes(&before, &after).into_iter().map(|c| c.0).collect();
        assert_eq!(changed, [lane::LOCK], "{envelope:#}");
        assert_restore_policy(&before, &after);
        let said = warning(&envelope, Code::RedirectRunRequired);
        assert!(
            said.contains("`bazel mod deps --lockfile_mode=update`"),
            "{said}"
        );
        assert_eq!(said.contains("Builds fail"), rc == frozen, "{said}");
        let expunge = said.find("bazel clean --expunge");
        assert_eq!(expunge.is_some(), family_b, "{said}");
        assert!(expunge.is_none_or(|at| at > said.find("bazel mod deps").unwrap_or(0)));
    }

    let plain = Checkout::new(false);
    plain.put(lane::LOCK, hosted_lock());
    let (code, envelope) = run(&plain.root, &["rollback", "--json", "--yes"], &server).await;
    assert_eq!(code, 0, "{envelope:#}");
    assert_eq!(plain.get(lane::LOCK).as_deref(), Some(lane::LOCK_TEXT));
    assert_eq!(bazel_codes(&envelope), Vec::<String>::new(), "{envelope:#}");
}

/// The withdrawn-pin sweep is a restore nobody asked for by name. Where
/// the lock is frozen it keeps the pin and says so, naming `rollback` and
/// the command; where an ordinary build refreshes the lock it restores
/// and names the command.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sweep_keeps_a_withdrawn_pin_where_its_restore_fails_the_build() {
    let server = MockServer::start().await;
    registries(&server).await;
    api_without(&server, lane::UUID).await;
    for (rc, kept) in [
        ("common --lockfile_mode=error\n", true),
        ("common --lockfile_mode=update\n", false),
    ] {
        let ws = Checkout::new(true);
        ws.put(".bazelversion", "8.8.2\n");
        ws.put(".bazelrc", rc);
        ws.put(lane::LOCK, hosted_lock());
        ws.put("MODULE.bazel.lock", module_lock(true, &hosted_lock()));
        let before = snapshot(&ws.root);
        let (_, envelope) = scan(&ws.root, &server).await;
        let codes = bazel_codes(&envelope);
        let has = |code: Code| codes.iter().any(|c| c == code.as_str());
        assert_eq!(
            has(Code::RedirectWithdrawnPinKept),
            kept,
            "{rc:?}: {envelope:#}"
        );
        assert_eq!(
            has(Code::RedirectRunRequired),
            !kept,
            "{rc:?}: {envelope:#}"
        );
        if kept {
            assert_same_tree(&before, &snapshot(&ws.root));
            let said = warning(&envelope, Code::RedirectWithdrawnPinKept);
            let rollback = format!("`socket-patch rollback {}`", lane::PURL);
            assert!(
                said.contains(&rollback) && said.contains("bazel mod deps"),
                "{said}"
            );
        } else {
            assert_eq!(ws.get(lane::LOCK).as_deref(), Some(lane::LOCK_TEXT));
            assert_restore_policy(&before, &snapshot(&ws.root));
            let restored = event_for(&envelope, lane::PURL);
            assert_eq!(restored["action"], "rolledBack", "{envelope:#}");
        }

        // A person is told what happens to the pin, once: "restoring"
        // only for a pin that is restored, and for a kept one its
        // warning alone.
        let ws = Checkout::new(true);
        ws.put(".bazelversion", "8.8.2\n");
        ws.put(".bazelrc", rc);
        ws.put(lane::LOCK, hosted_lock());
        ws.put("MODULE.bazel.lock", module_lock(true, &hosted_lock()));
        let said = scan_as_a_person(&ws.root, &server).await;
        let restoring = said.contains("restoring its upstream registry entry");
        assert_eq!(restoring, !kept, "{rc:?}: {said}");
        assert_eq!(said.contains("the pin was kept"), kept, "{rc:?}: {said}");
    }
}

/// A hosted pin on a crate_universe hub with a `lockfile`, as release 5.1
/// writes one. The digest in `cargo-bazel-lock.json` covers the manifest,
/// so a restore fails every build until a repin, whatever the lockfile
/// mode: the sweep keeps the pin, and `rollback` restores the three files
/// and names the repin. The same holds for a hub whose `manifests` cannot
/// all be followed to a file (a concatenated list, a member of another
/// repository): which manifests the digest covers is then not known, so
/// the project's own count.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crate_universe_pin_is_kept_by_the_sweep_and_restored_by_rollback() {
    const SERDE: &str = "55555555-5555-5555-5555-555555555555";
    const WIRED: [&str; 3] = [".cargo/config.toml", "Cargo.lock", "Cargo.toml"];
    let server = MockServer::start().await;
    registries(&server).await;
    api_without(&server, SERDE).await;
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../socket-patch-core/tests/fixtures/redirect/cargo/cargo/basic");
    let of = |state: &str, rel: &str| {
        let levels = rel.split('/');
        let file = levels.fold(fixture.join(state), |at, level| at.join(level));
        std::fs::read_to_string(&file).ok()
    };
    let module = |manifests: &str| {
        format!(
            "bazel_dep(name = \"rules_rust\", version = \"0.75.0\")\n\
             crate = use_extension(\"@rules_rust//crate_universe:extensions.bzl\", \"crate\")\n\
             EXTRA = []\n\
             crate.from_cargo(\n    name = \"crates\",\n    cargo_lockfile = \"//:Cargo.lock\",\n    \
             lockfile = \"//:cargo-bazel-lock.json\",\n    manifests = {manifests},\n)\n\
             use_repo(crate, \"crates\")\n"
        )
    };
    let wired = |rc: &str, manifests: &str| {
        let ws = Checkout::new(true);
        std::fs::remove_file(ws.at(lane::LOCK)).expect("no npm project here");
        std::fs::remove_file(ws.at("package.json")).expect("no npm project here");
        ws.put("MODULE.bazel", module(manifests));
        ws.put(".bazelrc", rc);
        ws.put("cargo-bazel-lock.json", "{\"checksum\": \"0\"}\n");
        ws.put("src/main.rs", "fn main() {}\n");
        for rel in WIRED {
            ws.put(rel, of("expected", rel).expect("a wired file"));
        }
        ws
    };
    const LITERAL: &str = "[\"//:Cargo.toml\"]";
    let forms = [
        LITERAL,
        "[\"//:Cargo.toml\"] + EXTRA",
        "[\"@other//:Cargo.toml\"]",
    ];
    for manifests in forms {
        for rc in [
            "",
            "common --lockfile_mode=update\n",
            "common --lockfile_mode=off\n",
        ] {
            let ws = wired(rc, manifests);
            let before = snapshot(&ws.root);
            let (_, envelope) = scan(&ws.root, &server).await;
            // The pin stands, whichever guard speaks first: a hub that is
            // not literal is left alone before the sweep is reached.
            assert_same_tree(&before, &snapshot(&ws.root));
            if manifests == LITERAL {
                let said = warning(&envelope, Code::RedirectWithdrawnPinKept);
                assert!(
                    said.contains("CARGO_BAZEL_REPIN=1 bazel mod deps"),
                    "{rc:?}: {said}"
                );
            }
        }

        let ws = wired("", manifests);
        let before = snapshot(&ws.root);
        let (code, envelope) = run(&ws.root, &["rollback", "--json", "--yes"], &server).await;
        assert_eq!(code, 0, "{manifests}: {envelope:#}");
        for rel in WIRED {
            assert_eq!(ws.get(rel), of("input", rel), "{rel}: {envelope:#}");
        }
        let after = snapshot(&ws.root);
        let changed: Vec<String> = changes(&before, &after).into_iter().map(|c| c.0).collect();
        assert_eq!(changed, [".cargo", WIRED[0], WIRED[1], WIRED[2]]);
        // A hub that is not literal gets a second advisory: nobody could
        // judge the whole of what it reads.
        let said = warnings(&envelope, Code::RedirectRunRequired);
        assert_eq!(
            said.len(),
            1 + usize::from(manifests != LITERAL),
            "{said:?}"
        );
        let repin = |said: &&String| said.contains("`CARGO_BAZEL_REPIN=1 bazel mod deps`");
        let named = said.iter().find(repin);
        let named = named.unwrap_or_else(|| panic!("{manifests}: the repin is named: {said:?}"));
        assert!(named.contains("Builds fail"), "{named}");
    }
}

/// A hosted Go pin under a `go_deps` hub whose extension holds facts in
/// `MODULE.bazel.lock`, while no entry of the lock records `go.mod` (the
/// lock vector of probe L3): only the facts say that the restore stales
/// the lock. `rollback` restores `go.mod` and `go.sum` and names the
/// refresh, at `warn` and with "builds fail" where the lock is frozen.
/// `MODULE.bazel.lock` is never written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restore_of_a_go_pin_counts_the_facts_of_its_extension() {
    let server = MockServer::start().await;
    let fixtures =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../socket-patch-core/tests/fixtures");
    let read = |rel: &str| {
        let file = rel
            .split('/')
            .fold(fixtures.clone(), |at, level| at.join(level));
        let text = std::fs::read_to_string(&file);
        text.unwrap_or_else(|e| panic!("{}: {e}", file.display()))
    };
    let pin =
        |state: &str, file: &str| read(&format!("redirect/golang/gomod/basic/{state}/{file}"));
    let upstream = pin("input", "go.sum");
    Mock::given(method("GET"))
        .and(path("/lookup/github.com/foo/bar@v1.4.2"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "12345\n{}\ngo.sum database tree\n12345\nAAAA\n",
            upstream.trim_end()
        )))
        .mount(&server)
        .await;
    let facts = "bazel/module_lock/facts/go-deps";
    for (rc, frozen) in [("", false), ("common --lockfile_mode=error\n", true)] {
        let ws = Checkout::new(false);
        std::fs::remove_file(ws.at(lane::LOCK)).expect("no npm project here");
        std::fs::remove_file(ws.at("package.json")).expect("no npm project here");
        ws.put(".bazelversion", "9.3.2\n");
        ws.put(".bazelrc", rc);
        // The vectors as Bazel wrote them, whatever a checkout made of
        // their line ends.
        let vector = |name: &str| read(&format!("{facts}/{name}")).replace("\r\n", "\n");
        ws.put("MODULE.bazel", vector("root.MODULE.bazel"));
        let lock = vector("bazel-repaired.MODULE.bazel.lock");
        ws.put("MODULE.bazel.lock", &lock);
        for file in ["go.mod", "go.sum"] {
            ws.put(file, pin("expected", file));
        }
        let before = snapshot(&ws.root);
        let (code, envelope) = run(&ws.root, &["rollback", "--json", "--yes"], &server).await;
        assert_eq!(code, 0, "{rc:?}: {envelope:#}");
        for file in ["go.mod", "go.sum"] {
            assert_eq!(
                ws.get(file),
                Some(pin("input", file)),
                "{file}: {envelope:#}"
            );
        }
        assert_eq!(ws.get("MODULE.bazel.lock"), Some(lock), "{rc:?}");
        assert_restore_policy(&before, &snapshot(&ws.root));
        let said = warning(&envelope, Code::RedirectRunRequired);
        assert!(
            said.contains("`bazel mod deps --lockfile_mode=update`"),
            "{rc:?}: {said}"
        );
        assert_eq!(said.contains("Builds fail"), frozen, "{rc:?}: {said}");
    }
}

// ── The rows of the owned index ──────────────────────────────────────

/// The arguments of an in-process call for the project at the checkout.
pub(crate) fn common(ws: &Checkout, dry_run: bool) -> GlobalArgs {
    common_at(&ws.root, dry_run)
}

/// The arguments of an in-process call for the project at `cwd`.
fn common_at(cwd: &Path, dry_run: bool) -> GlobalArgs {
    GlobalArgs {
        cwd: cwd.to_path_buf(),
        json: true,
        silent: true,
        dry_run,
        ..GlobalArgs::default()
    }
}

const KEY: &str = "packages/left-pad@1.3.0/resolution";
const FROZEN: &str = "common --lockfile_mode=error\n";

/// A pin in a file only its row of the owned index tells from the
/// upstream one, built from a hand-written index, beside an installed
/// patched copy of the package. The built binary has no lane that
/// restores the row, so `rollback` (with and without `--preserve-state`)
/// and `remove` keep the row, the pin and the manifest record, name the
/// file and change nothing: the installed copy stays patched too, since
/// the rows are judged before anything is restored. Over a lane that
/// restores it, the undo returns the lock byte for byte, takes the last
/// row's index with it and names the refresh of the lock Bazel keeps,
/// which records the file and is frozen; a lock that drifted is refused
/// whole; a dry run writes nothing. With no row the record leaves as it
/// always did.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn governed_record_stays_with_a_kept_row() {
    let server = MockServer::start().await;
    let ws = Checkout::new(true);
    ws.put(".bazelversion", "8.8.2\n");
    ws.put(".bazelrc", FROZEN);
    ws.put(lane::LOCK, row_lock());
    ws.put("MODULE.bazel.lock", module_lock(true, &row_lock()));
    ws.record();
    ws.install();
    let edit = (lane::UPSTREAM_SRI, lane::PATCHED);
    ws.row(&mut Index::default(), "H-TOY1", KEY, edit);
    let wired = snapshot(&ws.root);
    let incomplete = Code::RedirectRevertIncomplete.as_str();

    for form in [&[][..], &["--preserve-state"]] {
        let args = [&["rollback", "--json", "--yes", "--offline"][..], form].concat();
        let (code, envelope) = run(&ws.root, &args, &server).await;
        assert_eq!(code, 1, "{args:?}: {envelope:#}");
        let said = warning(&envelope, Code::RedirectRevertIncomplete);
        assert!(
            said.contains(lane::LOCK) && said.contains("stays in the manifest"),
            "{said}"
        );
        // No lane of this release undoes the row: no checkout is named,
        // which would change nothing.
        assert!(
            said.contains("release") && !said.contains("git checkout"),
            "{said}"
        );
        // The record failed as itself: under its own code, and of no
        // mode's leg.
        assert!(
            has_event(&envelope, "failed", incomplete, lane::PURL),
            "{envelope:#}"
        );
        let kept = event_for(&envelope, lane::PURL);
        assert_eq!(kept["details"]["bazel"]["state"], "kept", "{envelope:#}");
        assert_eq!(kept["details"]["mode"], Value::Null, "{envelope:#}");
        assert_same_tree(&wired, &snapshot(&ws.root));
        assert_eq!(ws.records(), [lane::PURL]);
    }
    for form in [&[][..], &["--skip-rollback"]] {
        let args = [
            &["remove", lane::PURL, "--json", "--yes", "--offline"][..],
            form,
        ]
        .concat();
        let (code, envelope) = run(&ws.root, &args, &server).await;
        assert_eq!(code, 1, "{args:?}: {envelope:#}");
        assert_eq!(
            envelope_error_code(&envelope),
            Some(incomplete),
            "{envelope:#}"
        );
        let message = envelope["error"]["message"].as_str().unwrap_or_default();
        // Each cause names its own remedy.
        let remedy = match form.is_empty() {
            true => "release",
            false => "without `--skip-rollback`",
        };
        assert!(
            message.contains(remedy) && !message.contains("git checkout"),
            "{args:?}: {message}"
        );
        assert_same_tree(&wired, &snapshot(&ws.root));
    }

    // A lane that restores the row. The restoring edit is judged like a
    // forward one: the lock Bazel keeps records the file and is frozen.
    let records = [(lane::PURL.to_string(), lane::UUID.to_string())];
    let refresh = |undone: &commands::Undone| {
        let [(code, said)] = undone.warnings.as_slice() else {
            panic!("one advisory: {undone:?}");
        };
        assert_eq!(code, Code::RedirectRunRequired.as_str(), "{said}");
        assert!(
            said.contains("`bazel mod deps --lockfile_mode=update`")
                && said.contains("Builds fail"),
            "{said}"
        );
    };
    let dry = undo_rows(&common(&ws, true), &records, true, &lane::TABLE).await;
    assert_eq!((dry.kept.len(), dry.reverted.len()), (0, 1), "{dry:?}");
    refresh(&dry);
    assert_same_tree(&wired, &snapshot(&ws.root));

    ws.put(
        lane::LOCK,
        row_lock().replace(lane::PATCHED, "sha512-someone-elses"),
    );
    let drifted = snapshot(&ws.root);
    let kept = undo_rows(&common(&ws, false), &records, true, &lane::TABLE).await;
    assert!(
        kept.holds(lane::PURL) && kept.reverted.is_empty(),
        "{kept:?}"
    );
    assert_eq!(kept.kept[0].code, incomplete);
    assert_eq!(kept.warnings[0].0, incomplete);
    // A file that drifted is the one case a checkout lifts.
    let said = &kept.warnings[0].1;
    let checkout = format!("`git checkout -- {}`", lane::LOCK);
    assert!(
        said.contains(lane::LOCK) && said.contains(&checkout),
        "{said}"
    );
    assert_same_tree(&drifted, &snapshot(&ws.root));

    ws.put(lane::LOCK, row_lock());
    let undone = undo_rows(&common(&ws, false), &records, true, &lane::TABLE).await;
    assert!(undone.kept.is_empty(), "{undone:?}");
    refresh(&undone);
    assert_eq!(undone.reverted, [lane::PURL]);
    // The rows were the root's: the events of the run say which root.
    let root = undone.root.as_deref().map(std::fs::canonicalize);
    assert_eq!(root.and_then(Result::ok), Some(ws.root.clone()));
    assert_eq!(ws.get(lane::LOCK).as_deref(), Some(lane::LOCK_TEXT));
    assert!(
        !ws.at(".socket/bazel").exists(),
        "the last row takes the index"
    );
    // The undo wrote the lock and the index, and nothing Bazel owns.
    let after = snapshot(&ws.root);
    assert_restore_policy(&wired, &after);
    let changed: Vec<String> = changes(&wired, &after).into_iter().map(|c| c.0).collect();
    assert!(
        !changed.iter().any(|path| path == "MODULE.bazel.lock"),
        "{changed:?}"
    );

    // No row is left: the record leaves the manifest, as without Bazel,
    // and its installed copy goes back to upstream.
    let (code, envelope) = run(
        &ws.root,
        &["rollback", "--json", "--yes", "--offline"],
        &server,
    )
    .await;
    assert_eq!(code, 0, "{envelope:#}");
    assert_eq!(ws.records(), Vec::<String>::new(), "{envelope:#}");
    assert_eq!(ws.get(INSTALLED).as_deref(), Some("upstream\n"));
    let kept = Code::RedirectRevertIncomplete.as_str().to_string();
    assert!(!bazel_codes(&envelope).contains(&kept), "{envelope:#}");
}

/// A manifest record whose patch a hosted pin wires too is undone by the
/// hosted leg, rows included. Where that pin is not restored the record
/// stays: a pin with no record is one `apply` never looks at again. The
/// row no lane of this release undoes keeps the pin, and the record with
/// it; so does an index nobody can rely on; and `remove --skip-rollback`,
/// which leaves all wiring in place, is refused for a patch the index
/// records. Nothing is written in any of the three.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_stays_while_the_hosted_pin_of_its_patch_stands() {
    let server = MockServer::start().await;
    registries(&server).await;
    let incomplete = Code::RedirectRevertIncomplete.as_str();
    let pinned = || {
        let ws = Checkout::new(true);
        ws.put(lane::LOCK, hosted_lock());
        ws.record();
        ws
    };

    // A row of the patch that no lane undoes.
    let ws = pinned();
    ws.row(
        &mut Index::default(),
        "H-TOY1",
        KEY,
        (lane::UPSTREAM_SRI, lane::PATCHED),
    );
    let before = snapshot(&ws.root);
    let (code, envelope) = run(&ws.root, &["rollback", "--json", "--yes"], &server).await;
    assert_eq!(code, 1, "{envelope:#}");
    assert!(
        has_event(&envelope, "failed", "hosted_restore_refused", lane::PURL),
        "{envelope:#}"
    );
    assert!(
        has_event(&envelope, "failed", incomplete, lane::PURL),
        "{envelope:#}"
    );
    let removed = event_purls(&envelope, "removed");
    assert_eq!(removed, Vec::<String>::new(), "{envelope:#}");
    assert_same_tree(&before, &snapshot(&ws.root));
    assert_eq!(ws.records(), [lane::PURL]);

    // `remove --skip-rollback` would drop the record and leave the row.
    let args = ["remove", lane::PURL, "--json", "--yes", "--skip-rollback"];
    let (code, envelope) = run(&ws.root, &args, &server).await;
    assert_eq!(code, 1, "{envelope:#}");
    assert_eq!(
        envelope_error_code(&envelope),
        Some(incomplete),
        "{envelope:#}"
    );
    assert_same_tree(&before, &snapshot(&ws.root));

    // An index that is not the one socket-patch wrote, and no row.
    let ws = pinned();
    ws.put(
        INDEX_PATH,
        "{\"version\": 1, \"pins\": [], \"ignoreLines\": \"oops\"}\n",
    );
    let before = snapshot(&ws.root);
    let (code, envelope) = run(&ws.root, &["rollback", "--json", "--yes"], &server).await;
    assert_eq!(code, 1, "{envelope:#}");
    let refused = events_of(&envelope, "failed", "hosted_restore_refused");
    let [refused] = refused.as_slice() else {
        panic!("the pin is refused: {envelope:#}");
    };
    let why = refused.to_string();
    assert!(why.contains(INDEX_PATH), "the index is named: {refused:#}");
    assert!(
        has_event(&envelope, "failed", incomplete, lane::PURL),
        "{envelope:#}"
    );
    assert_same_tree(&before, &snapshot(&ws.root));
    assert_eq!(ws.records(), [lane::PURL]);

    // Beside the same index a pin of an ecosystem no hub builds is still
    // restored in the same run: what the index records is no part of it.
    let ws = pinned();
    ws.put(
        INDEX_PATH,
        "{\"version\": 1, \"pins\": [], \"ignoreLines\": \"oops\"}\n",
    );
    let cargo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../socket-patch-core/tests/fixtures/redirect/cargo/cargo/basic");
    let of = |state: &str, rel: &str| {
        let file = rel
            .split('/')
            .fold(cargo.join(state), |at, level| at.join(level));
        std::fs::read_to_string(&file).ok()
    };
    for rel in [".cargo/config.toml", "Cargo.lock", "Cargo.toml"] {
        ws.put(rel, of("expected", rel).expect("a wired file"));
    }
    ws.put("src/main.rs", "fn main() {}\n");
    let hosted = ws.get(lane::LOCK);
    let (code, envelope) = run(&ws.root, &["rollback", "--json", "--yes"], &server).await;
    assert_eq!(code, 1, "{envelope:#}");
    assert_eq!(ws.get(lane::LOCK), hosted, "the governed pin stands");
    assert_eq!(
        ws.get("Cargo.toml"),
        of("input", "Cargo.toml"),
        "{envelope:#}"
    );
    assert_eq!(
        ws.get("Cargo.lock"),
        of("input", "Cargo.lock"),
        "{envelope:#}"
    );
}

/// The `failed` events of `code` an envelope carries.
fn events_of(envelope: &Value, action: &str, code: &str) -> Vec<Value> {
    let events = envelope["events"].as_array().cloned().unwrap_or_default();
    let of = |event: &Value| event["action"] == action && event["errorCode"] == code;
    events.into_iter().filter(of).collect()
}

const ROW_LANES: &[LaneSpec] = &[
    LaneSpec::stub("V-TOYR", Mode::Vendored, &[]),
    LaneSpec::stub("A-TOYR", Mode::Agent, &[]),
];
const ROW_OPS: LaneOps = LaneOps {
    restore: put_back,
    ..LaneOps::disabled(ROW_LANES)
};
/// A vendored and an agent lane that each put a row's values back.
const ANY_MODE: LaneTable = LaneTable(&[(Ruleset::RulesJs, &ROW_OPS)]);

/// The undo of one row: each value goes back only from the value the row
/// wrote, and a file that holds it in any other form has drifted.
fn put_back(_: &LaneCx<'_>, files: &mut Files, row: &IndexRow) -> RestoreOutcome {
    let Some(mut text) = files.get(&row.file).cloned() else {
        return RestoreOutcome::Drifted(format!("{}: the file is gone", row.file));
    };
    for edit in row.edits.iter().rev() {
        if text.matches(&edit.new).count() != 1 {
            return RestoreOutcome::Drifted(format!("{}: `{}` was changed", row.file, edit.key));
        }
        text = text.replacen(&edit.new, &edit.original, 1);
    }
    files.insert(row.file.clone(), text);
    RestoreOutcome::Restored
}

/// Rows are selected by patch, whatever the mode of the lane that wrote
/// them: a hand-written index with a row under an agent lane and one
/// under a vendored lane, as a routed pin leaves them. The built binary
/// reports both and restores nothing, the installed copy included. Over
/// lanes that restore them, both are undone in one commit, or neither is:
/// one drifted value keeps the other row's as well, and the record is
/// reported under the code of the mode of its rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rows_of_any_lane_mode() {
    let server = MockServer::start().await;
    let ws = Checkout::new(true);
    let spec = ("specifier: 1.3.0", "specifier: 1.3.0+socket");
    let both = row_lock().replace(spec.0, spec.1);
    ws.put(lane::LOCK, &both);
    ws.record();
    ws.install();
    let mut index = Index::default();
    let digest = (lane::UPSTREAM_SRI, lane::PATCHED);
    ws.row(&mut index, "A-TOYR", KEY, digest);
    ws.row(&mut index, "V-TOYR", "importers/./left-pad/specifier", spec);
    let wired = snapshot(&ws.root);

    // The shipped table holds neither lane: the record is reported in
    // the hosted family, which is what an unknown lane falls back to.
    let incomplete = Code::RedirectRevertIncomplete.as_str();
    let args = ["rollback", lane::PURL, "--json", "--yes", "--offline"];
    let (code, envelope) = run(&ws.root, &args, &server).await;
    assert_eq!(code, 1, "{envelope:#}");
    let said = warning(&envelope, Code::RedirectRevertIncomplete);
    let named = format!("`{}`: ", lane::LOCK);
    assert_eq!(
        said.matches(&named).count(),
        2,
        "each row is reported: {said}"
    );
    assert!(
        has_event(&envelope, "failed", incomplete, lane::PURL),
        "{envelope:#}"
    );
    assert_same_tree(&wired, &snapshot(&ws.root));
    assert_eq!(ws.records(), [lane::PURL]);

    // One of the two values was changed by somebody else: neither goes.
    // The rows are a vendored lane's and an agent lane's, so the record
    // is reported in the vendored family.
    let records = [(lane::PURL.to_string(), lane::UUID.to_string())];
    ws.put(lane::LOCK, both.replace(spec.1, "specifier: 1.3.1"));
    let drifted = snapshot(&ws.root);
    let kept = undo_rows(&common(&ws, false), &records, true, &ANY_MODE).await;
    assert!(
        kept.holds(lane::PURL) && kept.reverted.is_empty(),
        "{kept:?}"
    );
    assert!(
        kept.kept[0].why.contains("importers/./left-pad/specifier"),
        "{kept:?}"
    );
    let vendored = Code::VendorRevertIncomplete.as_str();
    assert_eq!(
        (kept.kept[0].code, kept.warnings[0].0.as_str()),
        (vendored, vendored)
    );
    assert_same_tree(&drifted, &snapshot(&ws.root));

    ws.put(lane::LOCK, &both);
    let undone = undo_rows(&common(&ws, false), &records, true, &ANY_MODE).await;
    assert!(undone.kept.is_empty(), "{undone:?}");
    assert_eq!(undone.reverted, [lane::PURL]);
    assert_eq!(ws.get(lane::LOCK).as_deref(), Some(lane::LOCK_TEXT));
    assert!(!ws.at(INDEX_PATH).exists());
}

/// The arguments of an in-process `rollback` or `remove` of the checkout.
/// Telemetry is off: the run sends nothing anywhere.
fn in_process(ws: &Checkout) -> GlobalArgs {
    GlobalArgs {
        yes: true,
        no_telemetry: true,
        manifest_path: MANIFEST.to_string(),
        ..common(ws, false)
    }
}

/// `rollback`, `rollback --preserve-state` and `remove` over a lane that
/// restores the row (the commands of the built binary, run over a lane
/// table of the test's own). The row is undone with the record: the lock
/// goes back to upstream byte for byte, the last row takes the index with
/// it, and the installed copy is restored. The record leaves the
/// manifest, except under `--preserve-state`, which keeps it and still
/// reverts every row of its patch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_commands_undo_the_rows_of_a_record_over_a_lane_that_restores_them() {
    let wired = || {
        let ws = Checkout::new(true);
        ws.put(lane::LOCK, row_lock());
        ws.record();
        ws.install();
        ws.row(
            &mut Index::default(),
            "H-TOY1",
            KEY,
            (lane::UPSTREAM_SRI, lane::PATCHED),
        );
        ws
    };
    let unwired = |ws: &Checkout, what: &str| {
        assert_eq!(
            ws.get(lane::LOCK).as_deref(),
            Some(lane::LOCK_TEXT),
            "{what}"
        );
        assert!(!ws.at(".socket/bazel").exists(), "{what}: the index goes");
        assert_eq!(ws.get(INSTALLED).as_deref(), Some("upstream\n"), "{what}");
    };
    // The run writes the lock, its own state and the installed copy, and
    // no file of the user's Bazel workspace.
    let only_its_own = |before: &crate::bazel_common::Snapshot, ws: &Checkout| {
        let changed = changes(before, &snapshot(&ws.root));
        let own = |path: &String| {
            path == lane::LOCK || path.starts_with(".socket") || path.starts_with("node_modules")
        };
        let other: Vec<String> = changed
            .into_iter()
            .map(|c| c.0)
            .filter(|p| !own(p))
            .collect();
        assert_eq!(other, Vec::<String>::new());
    };
    for preserve_state in [false, true] {
        let ws = wired();
        let before = snapshot(&ws.root);
        let args = RollbackArgs {
            targets: Vec::new(),
            common: in_process(&ws),
            preserve_state,
        };
        let code = socket_patch_cli::commands::rollback::run_over(args, &lane::TABLE).await;
        assert_eq!(code, 0, "preserve_state={preserve_state}");
        unwired(&ws, "rollback");
        let kept: &[&str] = match preserve_state {
            true => &[lane::PURL],
            false => &[],
        };
        assert_eq!(ws.records(), kept, "preserve_state={preserve_state}");
        only_its_own(&before, &ws);
    }

    let ws = wired();
    let before = snapshot(&ws.root);
    let args = RemoveArgs {
        identifier: lane::PURL.to_string(),
        common: in_process(&ws),
        skip_rollback: false,
        preserve_state: false,
    };
    let code = socket_patch_cli::commands::remove::run_over(args, &lane::TABLE).await;
    assert_eq!(code, 0);
    unwired(&ws, "remove");
    assert_eq!(ws.records(), Vec::<String>::new());
    only_its_own(&before, &ws);

    // The same commands over the shipped table restore nothing of it.
    let ws = wired();
    let before = snapshot(&ws.root);
    let args = RollbackArgs {
        targets: Vec::new(),
        common: in_process(&ws),
        preserve_state: false,
    };
    let lanes = &commands::PRODUCTION;
    let code = socket_patch_cli::commands::rollback::run_over(args, lanes).await;
    assert_eq!(code, 1);
    assert_same_tree(&before, &snapshot(&ws.root));
}

// ── A pin with a native side and a row ───────────────────────────────

/// The registry of `server` as the project's own, in the `.npmrc` beside
/// its pnpm lock: the native restore reads it, and the test sets nothing
/// in the environment of its process.
fn npmrc(server: &MockServer) -> String {
    format!("registry={}/npm-registry/\n", server.uri())
}

/// A hosted pin with both sides: the pnpm lock of the project holds the
/// native pin, and a second lock, which the hub reads and only its row of
/// the owned index tells from upstream, holds the lane's. `native` and
/// `row` are their root-relative paths; the project is the directory of
/// `native`.
fn two_sided(server: &MockServer, native: &str, row: &str) -> (Checkout, PathBuf, HostedPin) {
    let ws = Checkout::new(false);
    std::fs::remove_file(ws.at(lane::LOCK)).expect("laid out below");
    std::fs::remove_file(ws.at("package.json")).expect("laid out below");
    let (package, name) = row.rsplit_once('/').unwrap_or(("", row));
    let label = format!("//{package}:{name}");
    ws.put(".bazelversion", "8.8.2\n");
    ws.put("MODULE.bazel", lane::MODULE.replace("LOCK_LABEL", &label));
    ws.put("MODULE.bazel.lock", module_lock_of(true, row, &row_lock()));
    let project = native.rsplit_once('/').map_or("", |(dir, _)| dir);
    let in_project = |file: &str| match project {
        "" => file.to_string(),
        dir => format!("{dir}/{file}"),
    };
    let deps = r#"{"name": "p", "version": "0.0.0", "dependencies": {"left-pad": "1.3.0"}}"#;
    ws.put(&in_project("package.json"), deps);
    ws.put(&in_project(".npmrc"), npmrc(server));
    ws.put(native, hosted_lock());
    ws.put(row, row_lock());
    let mut index = Index::default();
    index.record_pin(IndexRow {
        uuid: lane::UUID.to_string(),
        purl: lane::PURL.to_string(),
        lane: lane::LANE.0.to_string(),
        file: row.to_string(),
        edits: vec![IndexEdit {
            key: KEY.to_string(),
            original: lane::UPSTREAM_SRI.to_string(),
            new: lane::PATCHED.to_string(),
        }],
        check: None,
    });
    ws.put(INDEX_PATH, index.render().expect("an index that renders"));
    let pin = HostedPin {
        purl: lane::PURL.to_string(),
        uuid: lane::UUID.to_string(),
        files: vec![lane::LOCK.to_string()],
    };
    let cwd = ws.at(project);
    (ws, cwd, pin)
}

fn restore_options(dry_run: bool) -> RestoreOptions {
    RestoreOptions {
        dry_run,
        offline: false,
        patch_server_origins: Vec::new(),
        bun_lockb: false,
    }
}

/// A registry that answers like [`registries`] and, as it answers, lets
/// somebody else edit a file of the checkout: an edit that lands between
/// the restore's read of the file and its commit.
struct EditsWhileAsked {
    file: PathBuf,
    answer: Value,
}

impl wiremock::Respond for EditsWhileAsked {
    fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
        let mut text = std::fs::read_to_string(&self.file).expect("the lock");
        text.push_str("# an edit of somebody else's\n");
        std::fs::write(&self.file, text).expect("write");
        ResponseTemplate::new(200).set_body_json(self.answer.clone())
    }
}

/// `restore` for a pin with a native side and a row lands both in the
/// one commit anchored at the Bazel root, with the project at the root
/// and below it: the native lock goes back to the registry entry, the
/// row's lock to its recorded value, the index goes with its last row,
/// and `MODULE.bazel.lock` is never written. A row that drifted refuses
/// the pin with both files byte for byte; a dry run writes nothing; and
/// a native lock that somebody edits between the plan and the commit
/// leaves both files as they are, with the pin not written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restore_lands_the_native_lock_and_the_row_in_one_commit() {
    let server = MockServer::start().await;
    registries(&server).await;
    let layouts = [
        ("pnpm-lock.yaml", "bazel/pnpm-lock.yaml"),
        ("app/pnpm-lock.yaml", "pnpm-lock.yaml"),
    ];
    for (native, row) in layouts {
        // Both sides in one run.
        let (ws, cwd, pin) = two_sided(&server, native, row);
        let before = snapshot(&ws.root);
        let pins = std::slice::from_ref(&pin);
        let done = commands::restore(
            &common_at(&cwd, false),
            pins,
            &restore_options(false),
            &lane::TABLE,
        )
        .await;
        let statuses: Vec<&PinStatus> = done.pins.iter().map(|pin| &pin.status).collect();
        assert_eq!(
            statuses,
            [&PinStatus::Restored],
            "{native}: {:?}",
            done.flush_error
        );
        assert_eq!(ws.get(native).as_deref(), Some(lane::LOCK_TEXT), "{native}");
        assert_eq!(ws.get(row).as_deref(), Some(lane::LOCK_TEXT), "{row}");
        assert!(!ws.at(".socket/bazel").exists(), "{native}: the index goes");
        let after = snapshot(&ws.root);
        let changed: Vec<String> = changes(&before, &after).into_iter().map(|c| c.0).collect();
        assert!(
            !changed.iter().any(|path| path == "MODULE.bazel.lock"),
            "{changed:?}"
        );
        assert_restore_policy(&before, &after);
        // The lock Bazel keeps records the row's file: the refresh is named.
        let named = |(code, said): &(&'static str, String)| {
            *code == Code::RedirectRunRequired.as_str() && said.contains("bazel mod deps")
        };
        assert!(
            done.warnings.iter().any(named),
            "{native}: {:?}",
            done.warnings
        );

        // A dry run plans the same and writes nothing.
        let (ws, cwd, pin) = two_sided(&server, native, row);
        let before = snapshot(&ws.root);
        let pins = std::slice::from_ref(&pin);
        let dry = commands::restore(
            &common_at(&cwd, true),
            pins,
            &restore_options(true),
            &lane::TABLE,
        )
        .await;
        assert_eq!(dry.pins[0].status, PinStatus::Restored, "{native}");
        assert_same_tree(&before, &snapshot(&ws.root));

        // The row drifted: the pin is refused on both sides.
        let (ws, cwd, pin) = two_sided(&server, native, row);
        ws.put(
            row,
            row_lock().replace(lane::PATCHED, "sha512-someone-elses"),
        );
        let before = snapshot(&ws.root);
        let pins = std::slice::from_ref(&pin);
        let kept = commands::restore(
            &common_at(&cwd, false),
            pins,
            &restore_options(false),
            &lane::TABLE,
        )
        .await;
        assert!(
            matches!(kept.pins[0].status, PinStatus::Refused(_)),
            "{native}: {:?}",
            kept.pins
        );
        let incomplete = Code::RedirectRevertIncomplete.as_str();
        let said = kept.warnings.iter().find(|(code, _)| *code == incomplete);
        let said = said.unwrap_or_else(|| panic!("{native}: {:?}", kept.warnings));
        assert!(
            said.1.contains(row) && said.1.contains("git checkout"),
            "{said:?}"
        );
        assert_same_tree(&before, &snapshot(&ws.root));
    }

    // Somebody edits the native lock while the restore asks the registry
    // about it: what the restore read is no longer what the file holds,
    // and neither side is written.
    let edited = MockServer::start().await;
    let (ws, cwd, pin) = two_sided(&edited, "app/pnpm-lock.yaml", "pnpm-lock.yaml");
    let tarball = format!(
        "{}/npm-registry/left-pad/-/left-pad-1.3.0.tgz",
        edited.uri()
    );
    let dist = json!({ "tarball": tarball, "integrity": lane::UPSTREAM_SRI });
    let answer = json!({ "name": "left-pad", "version": "1.3.0", "dist": dist });
    Mock::given(method("GET"))
        .and(path("/npm-registry/left-pad/1.3.0"))
        .respond_with(EditsWhileAsked {
            file: ws.at("app/pnpm-lock.yaml"),
            answer,
        })
        .mount(&edited)
        .await;
    let pins = std::slice::from_ref(&pin);
    let raced = commands::restore(
        &common_at(&cwd, false),
        pins,
        &restore_options(false),
        &lane::TABLE,
    )
    .await;
    assert_eq!(
        raced.pins[0].status,
        PinStatus::Unwritten,
        "{:?}",
        raced.pins
    );
    assert!(raced.flush_error.is_some(), "the run says why");
    let native = ws.get("app/pnpm-lock.yaml").unwrap_or_default();
    assert!(
        native.starts_with(&hosted_lock()) && native.ends_with("somebody else's\n"),
        "the edited lock is left as it is: {native}"
    );
    assert_eq!(ws.get("pnpm-lock.yaml"), Some(row_lock()), "the row stands");
    assert!(ws.at(INDEX_PATH).exists(), "and so does its record");
}

// ── Every Bazel root above the project ───────────────────────────────

/// A restoring edit is judged by every Bazel root above the project, and
/// "no root to ask" is never "no Bazel".
///
/// - Nested roots: the project has a boundary file of its own, and the
///   frozen lock of the root above records the project's lock. The sweep
///   keeps the pin, as it does for the same files with one root, and a
///   `rollback` restores and says that builds fail until the refresh.
/// - A workspace above the repository, where nothing is read: nothing
///   can say what the restore stales, so the sweep keeps the pin, and a
///   `rollback` restores and says that nobody could judge it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restore_is_judged_by_every_bazel_root_above_the_project() {
    let server = MockServer::start().await;
    registries(&server).await;
    let deps = r#"{"name": "p", "version": "0.0.0", "dependencies": {"left-pad": "1.3.0"}}"#;
    let pin = HostedPin {
        purl: lane::PURL.to_string(),
        uuid: lane::UUID.to_string(),
        files: vec![lane::LOCK.to_string()],
    };
    let kept = Code::RedirectWithdrawnPinKept.as_str();
    let sweep = |cwd: PathBuf| {
        let pin = pin.clone();
        async move {
            let lanes = &commands::PRODUCTION;
            let (free, kept) = commands::automatic(&common_at(&cwd, false), vec![pin], lanes).await;
            let said: Vec<(&'static str, String)> = kept;
            (free.len(), said)
        }
    };

    // Nested roots, and the same files under one root.
    for nested in [true, false] {
        let ws = Checkout::new(false);
        std::fs::remove_file(ws.at(lane::LOCK)).expect("laid out below");
        std::fs::remove_file(ws.at("package.json")).expect("laid out below");
        ws.put(".bazelversion", "8.8.2\n");
        ws.put(".bazelrc", FROZEN);
        let module = lane::MODULE.replace("LOCK_LABEL", "//inner:pnpm-lock.yaml");
        ws.put("MODULE.bazel", module);
        let recorded = module_lock_of(true, "inner/pnpm-lock.yaml", &hosted_lock());
        ws.put("MODULE.bazel.lock", &recorded);
        if nested {
            ws.put("inner/MODULE.bazel", "module(name = \"inner\")\n");
        }
        ws.put("inner/pnpm-lock.yaml", hosted_lock());
        ws.put("inner/package.json", deps);
        ws.put("inner/.npmrc", npmrc(&server));
        let before = snapshot(&ws.root);
        let (free, said) = sweep(ws.at("inner")).await;
        assert_eq!(free, 0, "nested={nested}: {said:?}");
        let [(code, said)] = said.as_slice() else {
            panic!("nested={nested}: one pin is kept: {said:?}");
        };
        assert_eq!(*code, kept, "nested={nested}");
        assert!(
            said.contains("bazel mod deps") && said.contains("socket-patch rollback"),
            "nested={nested}: {said}"
        );
        assert_same_tree(&before, &snapshot(&ws.root));

        // A person asks: the pin is restored, and the root above says
        // what that costs.
        let cwd = ws.at("inner");
        let pins = std::slice::from_ref(&pin);
        let lanes = &commands::PRODUCTION;
        let done = commands::restore(
            &common_at(&cwd, false),
            pins,
            &restore_options(false),
            lanes,
        )
        .await;
        assert_eq!(done.pins[0].status, PinStatus::Restored, "nested={nested}");
        assert_eq!(
            ws.get("inner/pnpm-lock.yaml").as_deref(),
            Some(lane::LOCK_TEXT)
        );
        assert_eq!(
            ws.get("MODULE.bazel.lock"),
            Some(recorded),
            "nested={nested}"
        );
        let fails = |(code, said): &(&'static str, String)| {
            *code == Code::RedirectRunRequired.as_str() && said.contains("Builds fail")
        };
        assert!(
            done.warnings.iter().any(fails),
            "nested={nested}: {:?}",
            done.warnings
        );
    }

    // A workspace somebody builds, above the repository of the project.
    let ws = Checkout::new(false);
    std::fs::remove_file(ws.at(lane::LOCK)).expect("laid out below");
    std::fs::remove_file(ws.at("package.json")).expect("laid out below");
    std::fs::remove_dir_all(ws.at(".git")).expect("the repository is the project's");
    ws.put(".bazelversion", "8.8.2\n");
    ws.put(".bazelrc", FROZEN);
    ws.put("BUILD.bazel", "");
    let module = lane::MODULE.replace("LOCK_LABEL", "//repo:pnpm-lock.yaml");
    ws.put("MODULE.bazel", module);
    let recorded = module_lock_of(true, "repo/pnpm-lock.yaml", &hosted_lock());
    ws.put("MODULE.bazel.lock", recorded);
    ws.put("repo/.git/HEAD", "ref: refs/heads/main\n");
    ws.put("repo/pnpm-lock.yaml", hosted_lock());
    ws.put("repo/package.json", deps);
    ws.put("repo/.npmrc", npmrc(&server));
    let before = snapshot(&ws.root);
    let (free, said) = sweep(ws.at("repo")).await;
    assert_eq!(free, 0, "{said:?}");
    let [(code, said)] = said.as_slice() else {
        panic!("one pin is kept: {said:?}");
    };
    assert_eq!(*code, kept);
    assert!(
        said.contains("could not be judged") && said.contains("socket-patch rollback"),
        "{said}"
    );
    assert_same_tree(&before, &snapshot(&ws.root));

    let cwd = ws.at("repo");
    let pins = std::slice::from_ref(&pin);
    let lanes = &commands::PRODUCTION;
    let done = commands::restore(
        &common_at(&cwd, false),
        pins,
        &restore_options(false),
        lanes,
    )
    .await;
    assert_eq!(done.pins[0].status, PinStatus::Restored);
    assert_eq!(
        ws.get("repo/pnpm-lock.yaml").as_deref(),
        Some(lane::LOCK_TEXT)
    );
    let unjudged = |(code, said): &(&'static str, String)| {
        *code == Code::RedirectRunRequired.as_str() && said.contains("could not be judged")
    };
    assert!(done.warnings.iter().any(unjudged), "{:?}", done.warnings);

    // A root whose one boundary file cannot be read, with an owned index
    // that records a row of the pin's patch: the row cannot be undone
    // without a model, and a pin is restored on both sides or on
    // neither. The sweep keeps it, and a `rollback` refuses it and writes
    // nothing; a pin the index records nothing for is restored, with the
    // advisory that nobody could judge it.
    #[cfg(unix)]
    for recorded in [true, false] {
        use std::os::unix::fs::PermissionsExt;
        let ws = Checkout::new(true);
        ws.put(".npmrc", npmrc(&server));
        ws.put(lane::LOCK, hosted_lock());
        if recorded {
            ws.row(
                &mut Index::default(),
                "H-TOY1",
                KEY,
                (lane::UPSTREAM_SRI, lane::PATCHED),
            );
        }
        let module = ws.at("MODULE.bazel");
        let none = std::fs::Permissions::from_mode(0o000);
        std::fs::set_permissions(&module, none).expect("chmod");
        if std::fs::read(&module).is_ok() {
            // A user no permission stops (root) reads the file all the same.
            continue;
        }
        // (No snapshot here: it would read the file nobody can read.)
        let wired = |ws: &Checkout| (ws.get(lane::LOCK), ws.get(INDEX_PATH));
        let before = wired(&ws);
        let (free, said) = sweep(ws.root.clone()).await;
        assert_eq!((free, said.len()), (0, 1), "recorded={recorded}: {said:?}");
        assert_eq!(said[0].0, kept, "recorded={recorded}");
        assert_eq!(wired(&ws), before, "recorded={recorded}");

        let pins = std::slice::from_ref(&pin);
        let lanes = &lane::TABLE;
        let done =
            commands::restore(&common(&ws, false), pins, &restore_options(false), lanes).await;
        if recorded {
            assert!(
                matches!(done.pins[0].status, PinStatus::Refused(_)),
                "{:?}",
                done.pins
            );
            assert_eq!(wired(&ws), before, "nothing of the pin was changed");
        } else {
            assert_eq!(done.pins[0].status, PinStatus::Restored, "{:?}", done.pins);
            assert_eq!(ws.get(lane::LOCK).as_deref(), Some(lane::LOCK_TEXT));
            assert!(done.warnings.iter().any(unjudged), "{:?}", done.warnings);
        }
    }
}

// ── Scope, and repair ────────────────────────────────────────────────

/// Owner decision O16: `rollback`, `remove` and `repair` are refused when
/// their scope is inside a tree Bazel owns, whether `--cwd` named it, it
/// is the working directory, or `--manifest-path` names a manifest in it.
/// Nothing is read, restored, removed or repaired.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rollback_remove_and_repair_are_refused_in_a_tree_bazel_owns() {
    let server = MockServer::start().await;
    let ws = Checkout::new(true);
    // An output base of the workspace, as a build leaves it, with an
    // external repository in it that looks like a patched project.
    let marker = ws.root.to_string_lossy().into_owned();
    ws.put("out/DO_NOT_BUILD_HERE", &marker);
    ws.put("out/execroot/DO_NOT_BUILD_HERE", &marker);
    let inside = "out/external/npm__left-pad__1.3.0";
    ws.put(&format!("{inside}/{}", lane::LOCK), hosted_lock());
    let project = ws.at(inside);
    let entry = PatchEntry {
        file_name: "package/index.js",
        before_hash: &git_sha256(b"upstream\n"),
        after_hash: &git_sha256(b"patched\n"),
    };
    let manifest =
        write_minimal_manifest(&project.join(".socket"), lane::PURL, lane::UUID, &[entry]);
    let (named, manifest) = (project.to_string_lossy(), manifest.to_string_lossy());

    let before = snapshot(&ws.root);
    let refused = Code::AgentOutputTree.as_str();
    let commands = [&["rollback"][..], &["remove", lane::PURL], &["repair"]];
    for command in commands {
        let args = [command, &["--json", "--yes", "--offline"][..]].concat();
        let scopes = [
            (project.as_path(), &[][..], "the working directory"),
            (ws.root.as_path(), &["--cwd", &*named][..], "--cwd"),
            (
                ws.root.as_path(),
                &["--manifest-path", &*manifest][..],
                "(--manifest-path)",
            ),
        ];
        for (cwd, scope, said) in scopes {
            let args = [&args[..], scope].concat();
            let (code, envelope) = run(cwd, &args, &server).await;
            assert_eq!(code, 1, "{args:?}: {envelope:#}");
            assert_eq!(envelope_error_code(&envelope), Some(refused), "{args:?}");
            let message = envelope["error"]["message"].as_str().unwrap_or_default();
            assert!(message.contains(said), "{args:?}: {message}");
        }
    }
    assert_same_tree(&before, &snapshot(&ws.root));
}

/// `repair` brings the `.bazelignore` line back for a tree an older
/// release left with none, after the label scan, and takes a recorded
/// line out once its tree is gone, so the round trip leaves the root as
/// it was. Under no Bazel root it reports nothing and writes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repair_brings_the_ignore_line_back_in_step() {
    let server = MockServer::start().await;
    let copy = ".socket/go-patches/example.com/m@v1.0.0/go.mod";
    let args = ["repair", "--json", "--offline"];
    for bazel in [true, false] {
        let ws = Checkout::new(bazel);
        ws.record();
        let before = snapshot(&ws.root);
        ws.put(copy, "module example.com/m\n");
        let (code, envelope) = run(&ws.root, &args, &server).await;
        assert_eq!(code, 0, "{envelope:#}");
        // The line is reported, and after it what the run has to say
        // once about the workspace it read to audit the new record.
        let added = Code::WorkspaceIgnoreLineAdded.as_str();
        let said = bazel_codes(&envelope);
        let first: Vec<&str> = said.iter().take(1).map(String::as_str).collect();
        assert_eq!(first, [added][..usize::from(bazel)], "{envelope:#}");
        let notes = [Code::WorkspaceDetected, Code::WorkspaceOutOfScope].map(Code::as_str);
        let other = said
            .iter()
            .skip(1)
            .find(|code| !notes.contains(&code.as_str()));
        assert_eq!(other, None, "{envelope:#}");
        let line = ws.get(".bazelignore");
        assert_eq!(line.as_deref(), bazel.then_some(".socket/go-patches\n"));

        std::fs::remove_dir_all(ws.at(".socket/go-patches")).expect("remove the tree");
        // `--download-only` skips every cleanup: the line of the tree
        // that is gone stays, with its record.
        let lined = snapshot(&ws.root);
        let only = ["repair", "--json", "--download-only"];
        let (code, envelope) = run(&ws.root, &only, &server).await;
        assert_eq!(code, 0, "{envelope:#}");
        assert_same_tree(&lined, &snapshot(&ws.root));

        let (code, envelope) = run(&ws.root, &args, &server).await;
        assert_eq!(code, 0, "{envelope:#}");
        assert_eq!(bazel_codes(&envelope), Vec::<String>::new(), "{envelope:#}");
        assert_same_tree(&before, &snapshot(&ws.root));
    }
}

/// `repair` names a recorded pin that is gone from a lock which still
/// resolves the release (`redirect_bazel_pin_erased`): a ruleset's own
/// command, or an install, rewrote the file. It rebuilds nothing. A row
/// for a release the lock no longer resolves is what a bump left behind,
/// not a pin somebody erased, and neither is a row no lane of the run can
/// tell the pin of: the shipped lanes say nothing of either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repair_names_an_erased_pin_and_rebuilds_nothing() {
    let erased = Code::RedirectPinErased.as_str();
    let said = |found: Vec<socket_patch_cli::json_envelope::RunWarning>| -> Vec<String> {
        let of_code = found.into_iter().filter(|warning| warning.code == erased);
        of_code.map(|warning| warning.detail).collect()
    };
    // The lock holds the upstream digest again: the pin the row records
    // is gone, and the release is still resolved.
    let ws = Checkout::new(true);
    ws.row(
        &mut Index::default(),
        "H-TOY1",
        KEY,
        (lane::UPSTREAM_SRI, lane::PATCHED),
    );
    let before = snapshot(&ws.root);
    let found = said(commands::repair(&common(&ws, false), false, &lane::TABLE).await);
    let [detail] = found.as_slice() else {
        panic!("one erased pin: {found:?}");
    };
    assert!(
        detail.contains(lane::PURL) && detail.contains(lane::LOCK) && detail.contains("scan"),
        "{detail}"
    );
    assert_same_tree(&before, &snapshot(&ws.root));
    // The shipped lanes cannot tell their pins: cannot tell is not erased.
    let found = said(commands::repair(&common(&ws, false), false, &commands::PRODUCTION).await);
    assert_eq!(found, Vec::<String>::new());
    assert_same_tree(&before, &snapshot(&ws.root));

    // The pin stands: nothing to name.
    ws.put(lane::LOCK, row_lock());
    let found = said(commands::repair(&common(&ws, false), false, &lane::TABLE).await);
    assert_eq!(found, Vec::<String>::new());

    // The lock moved to another release: the row is a leftover, and the
    // pin was not erased.
    ws.put(lane::LOCK, lane::LOCK_TEXT.replace("1.3.0", "1.4.0"));
    let found = said(commands::repair(&common(&ws, false), false, &lane::TABLE).await);
    assert_eq!(found, Vec::<String>::new());
}
