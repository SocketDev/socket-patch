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
use socket_patch_cli::bazel_gate::commands::undo_rows;
use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::model::{
    Digest, Files, IndexRow, LaneCx, LaneOps, LaneSpec, LaneTable, Mode, RestoreOutcome, Ruleset,
};
use socket_patch_core::bazel::owned_index::{Index, IndexEdit, INDEX_PATH};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::bazel_common::{assert_restore_policy, assert_same_tree, changes, snapshot};
use crate::common::envelope::{all_codes, event_for, parse_json_envelope};
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
}

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
        // The patch service too: no run of this suite reaches the real one.
        let env = [
            ("SOCKET_NPM_REGISTRY", npm.as_str()),
            ("SOCKET_CRATES_INDEX", &crates),
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

/// Every Bazel code an envelope carries.
pub(crate) fn bazel_codes(envelope: &Value) -> Vec<String> {
    let known = |code: &String| Code::ALL.iter().any(|c| c.as_str() == code);
    all_codes(envelope).into_iter().filter(known).collect()
}

/// The detail of the one warning of `code`.
fn warning(envelope: &Value, code: Code) -> String {
    let warnings = envelope["warnings"].as_array().cloned().unwrap_or_default();
    let of_code = |w: &&Value| w["code"] == code.as_str();
    let found: Vec<&Value> = warnings.iter().filter(of_code).collect();
    let [one] = found.as_slice() else {
        panic!("one `{code}` warning: {envelope:#}");
    };
    one["detail"].as_str().expect("a detail").to_string()
}

/// A `MODULE.bazel.lock` whose one extension records the pnpm lock as
/// `lock`: of family A (Bazel 6.2 to 7.1), or of family B (7.2 and later)
/// with a `facts` member. Both are lock vectors Bazel wrote.
fn module_lock(family_b: bool, lock: &str) -> String {
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
    match family_b {
        true => entry["recordedInputs"] = json!([format!("FILE:@@//{} {digest}", lane::LOCK)]),
        false => {
            entry["accumulatedFileDigests"] = json!({ (format!("@@//:{}", lane::LOCK)): digest })
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
    }
}

/// A hosted pin on a crate_universe hub with a `lockfile`, as release 5.1
/// writes one. The digest in `cargo-bazel-lock.json` covers the manifest,
/// so a restore fails every build until a repin, whatever the lockfile
/// mode: the sweep keeps the pin, and `rollback` restores the three files
/// and names the repin.
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
    let module = "bazel_dep(name = \"rules_rust\", version = \"0.75.0\")\n\
        crate = use_extension(\"@rules_rust//crate_universe:extensions.bzl\", \"crate\")\n\
        crate.from_cargo(\n    name = \"crates\",\n    cargo_lockfile = \"//:Cargo.lock\",\n    \
        lockfile = \"//:cargo-bazel-lock.json\",\n    manifests = [\"//:Cargo.toml\"],\n)\n\
        use_repo(crate, \"crates\")\n";
    let wired = |rc: &str| {
        let ws = Checkout::new(true);
        std::fs::remove_file(ws.at(lane::LOCK)).expect("no npm project here");
        std::fs::remove_file(ws.at("package.json")).expect("no npm project here");
        ws.put("MODULE.bazel", module);
        ws.put(".bazelrc", rc);
        ws.put("cargo-bazel-lock.json", "{\"checksum\": \"0\"}\n");
        ws.put("src/main.rs", "fn main() {}\n");
        for rel in WIRED {
            ws.put(rel, of("expected", rel).expect("a wired file"));
        }
        ws
    };
    for rc in [
        "",
        "common --lockfile_mode=update\n",
        "common --lockfile_mode=off\n",
    ] {
        let ws = wired(rc);
        let before = snapshot(&ws.root);
        let (_, envelope) = scan(&ws.root, &server).await;
        let said = warning(&envelope, Code::RedirectWithdrawnPinKept);
        assert!(
            said.contains("CARGO_BAZEL_REPIN=1 bazel mod deps"),
            "{rc:?}: {said}"
        );
        assert_same_tree(&before, &snapshot(&ws.root));
    }

    let ws = wired("");
    let before = snapshot(&ws.root);
    let (code, envelope) = run(&ws.root, &["rollback", "--json", "--yes"], &server).await;
    assert_eq!(code, 0, "{envelope:#}");
    for rel in WIRED {
        assert_eq!(ws.get(rel), of("input", rel), "{rel}: {envelope:#}");
    }
    let after = snapshot(&ws.root);
    let changed: Vec<String> = changes(&before, &after).into_iter().map(|c| c.0).collect();
    assert_eq!(changed, [".cargo", WIRED[0], WIRED[1], WIRED[2]]);
    let said = warning(&envelope, Code::RedirectRunRequired);
    assert!(
        said.contains("`CARGO_BAZEL_REPIN=1 bazel mod deps`"),
        "{said}"
    );
    assert!(said.contains("Builds fail"), "{said}");
}

// ── The rows of the owned index ──────────────────────────────────────

/// The arguments of an in-process call for the project at the checkout.
pub(crate) fn common(ws: &Checkout, dry_run: bool) -> GlobalArgs {
    GlobalArgs {
        cwd: ws.root.clone(),
        json: true,
        silent: true,
        dry_run,
        ..GlobalArgs::default()
    }
}

/// A pin in a file only its row of the owned index tells from the
/// upstream one, built from a hand-written index. The built binary has no
/// lane that restores the row, so `rollback` (with and without
/// `--preserve-state`) and `remove` keep the row, the pin and the manifest
/// record, name the file and change nothing under the root. Over a lane
/// that restores it, the undo returns the lock byte for byte and takes the
/// last row's index with it; a lock that drifted is refused whole; a dry
/// run writes nothing. With no row the record leaves as it always did.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn governed_record_stays_with_a_kept_row() {
    let server = MockServer::start().await;
    let ws = Checkout::new(true);
    ws.put(lane::LOCK, row_lock());
    ws.record();
    let edit = (lane::UPSTREAM_SRI, lane::PATCHED);
    let key = "packages/left-pad@1.3.0/resolution";
    ws.row(&mut Index::default(), "H-TOY1", key, edit);
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
        let kept = event_for(&envelope, lane::PURL);
        assert_eq!(kept["details"]["bazel"]["state"], "kept", "{envelope:#}");
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
        assert_same_tree(&wired, &snapshot(&ws.root));
    }

    // A lane that restores the row.
    let records = [(lane::PURL.to_string(), lane::UUID.to_string())];
    let dry = undo_rows(&common(&ws, true), &records, true, &lane::TABLE).await;
    assert_eq!((dry.kept.len(), dry.reverted.len()), (0, 1), "{dry:?}");
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
    assert_eq!(kept.warnings[0].0, incomplete);
    assert!(kept.warnings[0].1.contains(lane::LOCK), "{kept:?}");
    assert_same_tree(&drifted, &snapshot(&ws.root));

    ws.put(lane::LOCK, row_lock());
    let undone = undo_rows(&common(&ws, false), &records, true, &lane::TABLE).await;
    assert!(
        undone.kept.is_empty() && undone.warnings.is_empty(),
        "{undone:?}"
    );
    assert_eq!(undone.reverted, [lane::PURL]);
    // The rows were the root's: the events of the run say which root.
    let root = undone.root.as_deref().map(std::fs::canonicalize);
    assert_eq!(root.and_then(Result::ok), Some(ws.root.clone()));
    assert_eq!(ws.get(lane::LOCK).as_deref(), Some(lane::LOCK_TEXT));
    assert!(
        !ws.at(".socket/bazel").exists(),
        "the last row takes the index"
    );
    assert_restore_policy(&wired, &snapshot(&ws.root));

    // No row is left: the record leaves the manifest, as without Bazel.
    let (code, envelope) = run(
        &ws.root,
        &["rollback", "--json", "--yes", "--offline"],
        &server,
    )
    .await;
    assert_eq!(code, 0, "{envelope:#}");
    assert_eq!(ws.records(), Vec::<String>::new(), "{envelope:#}");
    assert_eq!(bazel_codes(&envelope), Vec::<String>::new(), "{envelope:#}");
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
/// reports both and restores nothing. Over lanes that restore them, both
/// are undone in one commit, or neither is: one drifted value keeps the
/// other row's as well.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rows_of_any_lane_mode() {
    let server = MockServer::start().await;
    let ws = Checkout::new(true);
    let spec = ("specifier: 1.3.0", "specifier: 1.3.0+socket");
    let both = row_lock().replace(spec.0, spec.1);
    ws.put(lane::LOCK, &both);
    ws.record();
    let mut index = Index::default();
    let digest = (lane::UPSTREAM_SRI, lane::PATCHED);
    ws.row(
        &mut index,
        "A-TOYR",
        "packages/left-pad@1.3.0/resolution",
        digest,
    );
    ws.row(&mut index, "V-TOYR", "importers/./left-pad/specifier", spec);
    let wired = snapshot(&ws.root);

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
    assert_same_tree(&wired, &snapshot(&ws.root));
    assert_eq!(ws.records(), [lane::PURL]);

    // One of the two values was changed by somebody else: neither goes.
    let records = [(lane::PURL.to_string(), lane::UUID.to_string())];
    ws.put(lane::LOCK, both.replace(spec.1, "specifier: 1.3.1"));
    let drifted = snapshot(&ws.root);
    let kept = undo_rows(&common(&ws, false), &records, true, &ANY_MODE).await;
    assert!(
        kept.holds(lane::PURL) && kept.reverted.is_empty(),
        "{kept:?}"
    );
    assert!(
        kept.kept[0].1.contains("importers/./left-pad/specifier"),
        "{kept:?}"
    );
    assert_same_tree(&drifted, &snapshot(&ws.root));

    ws.put(lane::LOCK, &both);
    let undone = undo_rows(&common(&ws, false), &records, true, &ANY_MODE).await;
    assert!(undone.kept.is_empty(), "{undone:?}");
    assert_eq!(undone.reverted, [lane::PURL]);
    assert_eq!(ws.get(lane::LOCK).as_deref(), Some(lane::LOCK_TEXT));
    assert!(!ws.at(INDEX_PATH).exists());
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
        let added = Code::WorkspaceIgnoreLineAdded.as_str();
        let said = bazel_codes(&envelope);
        assert_eq!(
            said,
            [added].map(String::from)[..usize::from(bazel)],
            "{envelope:#}"
        );
        let line = ws.get(".bazelignore");
        assert_eq!(line.as_deref(), bazel.then_some(".socket/go-patches\n"));

        std::fs::remove_dir_all(ws.at(".socket/go-patches")).expect("remove the tree");
        let (code, envelope) = run(&ws.root, &args, &server).await;
        assert_eq!(code, 0, "{envelope:#}");
        assert_eq!(bazel_codes(&envelope), Vec::<String>::new(), "{envelope:#}");
        assert_same_tree(&before, &snapshot(&ws.root));
    }
}
