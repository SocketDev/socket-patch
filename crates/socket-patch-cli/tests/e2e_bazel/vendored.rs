//! Hermetic CLI tests: the vendored seam under a Bazel hub (design 5.4;
//! hazards HZ-02 and HZ-10; revision 4, 2.10).
//!
//! Bazel builds a governed ecosystem from the lock its ruleset reads, so a
//! vendored patch there is the gate's to decide before anything is fetched:
//! the built binary, whose lanes are all disabled, refuses with the code of
//! the reason, and its expectations are computed with `lanes::admits`. What
//! a lane's plan does once one is enabled (the artifact before the pin, the
//! undo that is whole or not at all) is shown in process, over the lane
//! table of `lane.rs`: the built binary has no lane to show it with.
//!
//! `scan --mode vendored` and `get --mode vendored` refuse a governed
//! package before they fetch its patch view, and their dry run shows the
//! same refusal: the loopback API records what it is asked.
//!
//! No Bazel and no network: a loopback server stands in for the patch
//! service and the API and records what it is asked.

// One lane file for this suite and for the unit tests of the seam: each
// uses a part of it.
#[allow(dead_code)]
mod lane;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use futures_util::future::BoxFuture;
use serde_json::Value;
use socket_patch_cli::args::GlobalArgs;
use socket_patch_cli::bazel_gate::vendored::{
    reader, revert_entry, vendor_one, ArtifactSource, Engine, RootCommit, RootTxn, Routed,
};
use socket_patch_cli::json_envelope::{Command, Envelope};
use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::lanes::{self, Cell, Decision};
use socket_patch_core::bazel::model::{Digest, HubId, LaneOps, LaneTable, Mode, Reason, RootRef};
use socket_patch_core::bazel::owned_index::{self, FileRow, Parsed, INDEX_PATH};
use socket_patch_core::crawlers::bazel_workspace::{read_workspace, DiskView};
use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::patch::apply::PatchSources;
use socket_patch_core::utils::group_commit::{CommittedFile, GroupCommit};
use socket_patch_core::vendor::{RevertOpts, VendorEntry, VendorState, VENDOR_STATE_REL};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::bazel_common::{assert_same_tree, snapshot};
use crate::common::envelope::{all_codes, event_for, parse_json_envelope};
use crate::common::{
    envelope_error_code, git_sha256, run_with_env, write_minimal_manifest, PatchEntry,
};

const UNIT: &str = ".socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const OTHER_UUID: &str = lane::OTHER_UUID;

/// A checkout with an npm project whose lock resolves `left-pad`, and
/// (`bazel`) the rules_js hub that makes Bazel build from that lock.
struct Workspace {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Workspace {
    fn new(bazel: bool) -> Self {
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
            ws.put("MODULE.bazel", lane::MODULE);
        }
        ws
    }

    /// `rel` below the checkout, level by level.
    fn at(&self, rel: &str) -> PathBuf {
        let levels = rel.split('/').filter(|level| !level.is_empty());
        levels.fold(self.root.clone(), |at, level| at.join(level))
    }

    fn put(&self, rel: &str, bytes: impl AsRef<[u8]>) {
        let path = self.at(rel);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(path, bytes).expect("write");
    }

    fn get(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.at(rel)).ok()
    }

    /// The patch of `left-pad` in the project's manifest: what the
    /// manifest-driven `vendor` vendors.
    fn stage_patch(&self) {
        let entry = PatchEntry {
            file_name: "package/index.js",
            before_hash: &git_sha256(b"upstream\n"),
            after_hash: &git_sha256(b"patched\n"),
        };
        write_minimal_manifest(&self.at(".socket"), lane::PURL, lane::UUID, &[entry]);
    }

    /// Whether the shipped lanes serve the hub in vendored mode, and the
    /// lane the design names for its cell: what every expectation of a
    /// refusal is computed from.
    fn cell(&self) -> (bool, Option<&'static str>) {
        let root = RootRef {
            root: self.root.clone(),
            project_rel: String::new(),
            boundary_levels: 0,
        };
        let ws = read_workspace(&root, &DiskView::new(&root)).expect("a workspace");
        let cell = Cell::of(&ws, HubId(0), Mode::Vendored).expect("the hub");
        let designed = match lanes::decision(cell.shape, Mode::Vendored) {
            Decision::Lane(lane) => Some(lane.0),
            Decision::Refused(_) => None,
        };
        (lanes::admits(&lanes::PRODUCTION, &cell), designed)
    }

    fn admitted(&self) -> bool {
        self.cell().0
    }

    fn entry(&self) -> VendorEntry {
        let ledger = self.get(VENDOR_STATE_REL).expect("the vendor ledger");
        let state: VendorState = serde_json::from_str(&ledger).expect("a ledger");
        state.entries[lane::PURL].clone()
    }
}

/// The binary in `cwd` with the patch service at `service`: the exit
/// code and the envelope. It runs off the async threads, which serve the
/// loopback service meanwhile.
async fn run(cwd: &Path, args: &[&str], service: &MockServer) -> (i32, Value) {
    let (cwd, uri) = (cwd.to_path_buf(), service.uri());
    let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
    let ran = tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        run_with_env(&cwd, &args, &[("SOCKET_VENDOR_URL", &uri)])
    });
    let (code, stdout, stderr) = ran.await.expect("the binary ran");
    assert!(!stdout.is_empty(), "no envelope (exit {code}):\n{stderr}");
    (code, parse_json_envelope(&stdout))
}

async fn asked(service: &MockServer) -> Vec<String> {
    let requests = service.received_requests().await.unwrap_or_default();
    requests.iter().map(|r| r.url.path().to_string()).collect()
}

/// Every Bazel code an envelope carries.
fn bazel_codes(envelope: &Value) -> Vec<String> {
    let known = |code: &String| Code::ALL.iter().any(|c| c.as_str() == code);
    all_codes(envelope).into_iter().filter(known).collect()
}

// ── The built binary: every production lane is disabled ──────────────

/// A package whose lock a hub reads is refused before the patch service
/// is asked for anything: the code is the mode's prefix plus the reason,
/// the event says which lane would lift it, and no file is written. The
/// same project with no Bazel file is vendored as it always was: the
/// native backend runs, and no Bazel code is reported.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_governed_package_is_refused_before_the_service_is_asked() {
    // The same project under no Bazel root, first: it needs no lane.
    let plain = Workspace::new(false);
    plain.stage_patch();
    let service = MockServer::start().await;
    let (_, envelope) = run(&plain.root, &["vendor", "--json"], &service).await;
    // The native backend asks the service for the artifact, which also
    // shows that the recorder below would see a request.
    let requests = asked(&service).await;
    assert!(
        requests.iter().any(|path| path.contains("/patch/")),
        "{requests:?}"
    );
    assert_eq!(bazel_codes(&envelope), Vec::<String>::new(), "{envelope:#}");
    let event = event_for(&envelope, lane::PURL);
    assert!(event["details"].get("bazel").is_none(), "{event:#}");
    assert!(event["details"].get("lift").is_none(), "{event:#}");

    let ws = Workspace::new(true);
    ws.stage_patch();
    let service = MockServer::start().await;
    let before = snapshot(&ws.root);
    let (code, envelope) = run(&ws.root, &["vendor", "--json"], &service).await;
    let refusal = Code::refusal(Mode::Vendored, Reason::RulesetUnsupported).expect("a code");
    let (admitted, designed) = ws.cell();
    // What holds whether or not a release enables the lane: the native
    // backend never wires a governed package. `package.json` is as it
    // was, and a ledger entry, where one was written, records that the
    // index of the root wires the artifact and nothing else.
    let after = snapshot(&ws.root);
    assert_eq!(before.get("package.json"), after.get("package.json"));
    if let Some(ledger) = ws.get(VENDOR_STATE_REL) {
        let state: VendorState = serde_json::from_str(&ledger).expect("a ledger");
        for entry in state.entries.values() {
            assert!(entry.bazel_index().is_some(), "native wiring: {entry:?}");
            assert_eq!(entry.wiring.len(), 1, "{entry:?}");
        }
    }
    if admitted {
        // A release that enables the lane vendors the package instead.
        let refused = bazel_codes(&envelope);
        assert!(
            !refused.iter().any(|c| c == refusal.as_str()),
            "{envelope:#}"
        );
        return;
    }
    assert_eq!(code, 1, "{envelope:#}");
    let event = event_for(&envelope, lane::PURL);
    assert_eq!(event["action"], "failed", "{envelope:#}");
    assert_eq!(event["errorCode"], refusal.as_str(), "{envelope:#}");
    let details = &event["details"];
    assert_eq!(details["token"], "lane_not_enabled", "{event:#}");
    assert_eq!(details["lift"]["kind"], "enable_lane", "{event:#}");
    // The lane the design names for the cell, from the lane table.
    let lane = designed.expect("a lane is designed for the cell");
    assert_eq!(details["lift"]["lane"], lane, "{event:#}");
    let bazel = serde_json::json!({
        "state": "refused", "ruleset": "rules_js", "lock": lane::LOCK, "lane": lane,
    });
    assert_eq!(details["bazel"], bazel, "{event:#}");
    assert_eq!(asked(&service).await, Vec::<String>::new());
    assert_same_tree(&before, &after);
    // The run says once what it found about the workspace above it.
    let said = all_codes(&envelope);
    let detected = Code::WorkspaceDetected.as_str();
    assert_eq!(
        said.iter().filter(|c| *c == detected).count(),
        1,
        "{envelope:#}"
    );
}

/// A governed package with several release variants in the manifest and
/// nothing installed gets the gate's refusal, with its token, for each
/// variant: the gate is asked before the variant probe, which would
/// otherwise call the two ambiguous and name no Bazel reason. Nothing is
/// asked of the patch service.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_governed_package_with_several_variants_gets_the_gates_refusal() {
    let tmp = tempfile::tempdir().expect("a temporary directory");
    let root = std::fs::canonicalize(tmp.path()).expect("its real path");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bazel/heavy/rules_python/bzlmod/e9-unhashed");
    for name in ["MODULE.bazel", "requirements.txt", "BUILD.bazel"] {
        std::fs::copy(fixture.join(name), root.join(name)).expect("copy the fixture");
    }
    std::fs::write(root.join(".bazelversion"), lane::BAZELVERSION).expect("write");
    std::fs::create_dir_all(root.join(".git")).expect("mkdir");
    std::fs::write(root.join(".git").join("HEAD"), "ref: refs/heads/main\n").expect("write");
    let variants = [
        (
            "pkg:pypi/spvictim@1.0.0?artifact_id=aaaa",
            "11111111-1111-4111-8111-111111111111",
        ),
        (
            "pkg:pypi/spvictim@1.0.0?artifact_id=bbbb",
            "22222222-2222-4222-8222-222222222222",
        ),
    ];
    let mut patches = serde_json::Map::new();
    for (purl, uuid) in variants {
        let hashes = serde_json::json!({
            "beforeHash": git_sha256(b"upstream\n"), "afterHash": git_sha256(b"patched\n"),
        });
        let record = serde_json::json!({
            "uuid": uuid, "exportedAt": "2026-01-01T00:00:00Z",
            "files": { "spvictim/__init__.py": hashes },
            "vulnerabilities": {}, "description": "x", "license": "MIT", "tier": "free",
        });
        patches.insert(purl.to_string(), record);
    }
    let manifest = serde_json::json!({ "patches": patches });
    std::fs::create_dir_all(root.join(".socket")).expect("mkdir");
    let manifest_path = root.join(".socket").join("manifest.json");
    std::fs::write(manifest_path, manifest.to_string()).expect("write");

    let service = MockServer::start().await;
    let before = snapshot(&root);
    let (code, envelope) = run(&root, &["vendor", "--json", "--offline"], &service).await;
    assert_eq!(code, 1, "{envelope:#}");
    let known: Vec<&str> = Code::ALL.iter().map(|code| code.as_str()).collect();
    for (purl, _) in variants {
        let event = event_for(&envelope, purl);
        assert_eq!(event["action"], "failed", "{envelope:#}");
        let said = event["errorCode"].as_str().expect("a code");
        assert!(known.contains(&said), "{purl}: no Bazel code: {event:#}");
        assert!(said.starts_with("vendor_bazel_"), "{event:#}");
        assert!(event["details"]["token"].is_string(), "{event:#}");
        assert!(event["details"]["lift"]["kind"].is_string(), "{event:#}");
    }
    assert_eq!(asked(&service).await, Vec::<String>::new());
    assert_same_tree(&before, &snapshot(&root));
}

const ORG: &str = "test-org";

/// A fake Socket API that knows one patch of `left-pad`: the batch and
/// by-package searches answer with it, and its view is served, so a view
/// request would succeed and is seen by the recorder.
async fn api_with_one_patch() -> MockServer {
    let api = MockServer::start().await;
    let found = serde_json::json!({
        "uuid": lane::UUID, "purl": lane::PURL, "tier": "free",
        "cveIds": ["CVE-2026-0001"], "ghsaIds": [], "severity": "high",
        "title": "vendor target",
    });
    let batch = serde_json::json!({
        "packages": [{ "purl": lane::PURL, "patches": [found] }],
        "canAccessPaidPatches": false,
    });
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(batch))
        .mount(&api)
        .await;
    let listed = serde_json::json!({
        "patches": [{
            "uuid": lane::UUID, "purl": lane::PURL,
            "publishedAt": "2026-01-01T00:00:00Z", "description": "Vendor patch",
            "license": "MIT", "tier": "free", "vulnerabilities": {},
        }],
        "canAccessPaidPatches": false,
    });
    let by_package = "/v0/orgs/test-org/patches/by-package/pkg%3Anpm%2Fleft-pad%401.3.0";
    Mock::given(method("GET"))
        .and(path(by_package))
        .respond_with(ResponseTemplate::new(200).set_body_json(listed))
        .mount(&api)
        .await;
    let view = serde_json::json!({
        "uuid": lane::UUID, "purl": lane::PURL, "publishedAt": "2026-01-01T00:00:00Z",
        "files": { "package/index.js": {
            "beforeHash": git_sha256(b"before\n"), "afterHash": git_sha256(b"after\n"),
            "blobContent": "YWZ0ZXIK",
        } },
        "vulnerabilities": {}, "description": "Vendor patch", "license": "MIT", "tier": "free",
    });
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{}", lane::UUID)))
        .respond_with(ResponseTemplate::new(200).set_body_json(view))
        .mount(&api)
        .await;
    api
}

/// `scan --mode vendored` and `get --mode vendored` ask the gate before
/// they fetch a patch view: under a hub whose lane is not enabled no view
/// and no artifact is requested and the tree is unchanged, with the
/// refusal's code, token and lift on the patch's event; and the dry run
/// shows the same refusal as a would-refuse row, not as a patch it would
/// vendor. The same project under no Bazel root is asked for its view.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_and_get_refuse_a_governed_package_before_its_view_is_fetched() {
    let refusal = Code::refusal(Mode::Vendored, Reason::RulesetUnsupported).expect("a code");
    let fetched = |requests: &[String]| -> Vec<String> {
        let asked = requests.iter();
        let costly = asked.filter(|p| p.contains("/patches/view/") || p.contains("/package"));
        costly.cloned().collect()
    };
    let commands: [&[&str]; 2] = [&["scan"], &["get", lane::PURL]];
    for (command, dry) in commands.into_iter().flat_map(|c| [(c, true), (c, false)]) {
        let ws = Workspace::new(true);
        ws.put(
            "node_modules/left-pad/package.json",
            r#"{"name":"left-pad","version":"1.3.0"}"#,
        );
        ws.put("node_modules/left-pad/index.js", "before\n");
        if ws.admitted() {
            // A release that enables the lane vendors the package.
            return;
        }
        let api = api_with_one_patch().await;
        let uri = api.uri();
        let mut args: Vec<&str> = command.to_vec();
        let flags = ["--json", "--mode", "vendored", "--yes", "--api-url", &uri];
        args.extend(flags);
        args.extend(["--api-token", "fake-token", "--org", ORG]);
        if dry {
            args.push("--dry-run");
        }
        let before = snapshot(&ws.root);
        let (code, envelope) = run(&ws.root, &args, &api).await;
        let said = format!("{args:?}: {envelope:#}");
        let requests = asked(&api).await;
        assert_eq!(fetched(&requests), Vec::<String>::new(), "{said}");
        assert_same_tree(&before, &snapshot(&ws.root));
        let event = event_for(&envelope, lane::PURL);
        assert_eq!(event["errorCode"], refusal.as_str(), "{said}");
        let details = &event["details"];
        assert_eq!(details["token"], "lane_not_enabled", "{said}");
        assert_eq!(details["lift"]["kind"], "enable_lane", "{said}");
        assert_eq!(details["bazel"]["lock"], lane::LOCK, "{said}");
        assert_eq!(details["mode"], "vendored", "{said}");
        match dry {
            // A would-refuse row: never a patch the run would vendor.
            true => assert_eq!((code, &event["action"]), (0, &"skipped".into()), "{said}"),
            false => assert_eq!((code, &event["action"]), (1, &"failed".into()), "{said}"),
        }
        // What a run says about the workspace it says once: a scan prints
        // its notes itself, and its vendor step does not repeat them.
        let codes = all_codes(&envelope);
        let detected = Code::WorkspaceDetected.as_str();
        let told = codes.iter().filter(|c| *c == detected).count();
        assert!(
            told <= 1,
            "the workspace was announced {told} times: {said}"
        );
    }

    // Under no Bazel root the view is fetched: the recorder sees it.
    let plain = Workspace::new(false);
    plain.put(
        "node_modules/left-pad/package.json",
        r#"{"name":"left-pad","version":"1.3.0"}"#,
    );
    plain.put("node_modules/left-pad/index.js", "before\n");
    let api = api_with_one_patch().await;
    let uri = api.uri();
    let args = [
        "scan",
        "--json",
        "--mode",
        "vendored",
        "--yes",
        "--api-url",
        &uri,
        "--api-token",
        "fake-token",
        "--org",
        ORG,
    ];
    let (_, envelope) = run(&plain.root, &args, &api).await;
    let requests = fetched(&asked(&api).await);
    let viewed = requests.iter().any(|p| p.contains("/patches/view/"));
    assert!(viewed, "{requests:?}: {envelope:#}");
    assert_eq!(bazel_codes(&envelope), Vec::<String>::new(), "{envelope:#}");
}

/// Owner decision O16: every form of `vendor` is refused when its scope
/// is inside a tree Bazel owns, whether `--cwd` named the scope or it is
/// the working directory. Nothing is read, fetched, written or reverted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vendor_is_refused_inside_a_bazel_output_tree() {
    let ws = Workspace::new(true);
    // An output base of the workspace, in the tree, as a build leaves it.
    let marker = ws.root.to_string_lossy().into_owned();
    ws.put("out/DO_NOT_BUILD_HERE", &marker);
    ws.put("out/execroot/DO_NOT_BUILD_HERE", &marker);
    ws.put("out/external/bazel_tools/WORKSPACE", "");
    // An external repository in it that looks like a vendored project.
    let inside = "out/external/npm__left-pad__1.3.0";
    ws.put(&format!("{inside}/{}", lane::LOCK), lane::LOCK_TEXT);
    ws.put(&format!("{inside}/{UNIT}/{}", lane::LEAF), lane::ARTIFACT);
    let ledger = serde_json::json!({ "version": 1, "entries": {} });
    ws.put(&format!("{inside}/{VENDOR_STATE_REL}"), ledger.to_string());
    let project = ws.at(inside);
    let entry = PatchEntry {
        file_name: "package/index.js",
        before_hash: &git_sha256(b"upstream\n"),
        after_hash: &git_sha256(b"patched\n"),
    };
    write_minimal_manifest(&project.join(".socket"), lane::PURL, lane::UUID, &[entry]);

    let service = MockServer::start().await;
    let before = snapshot(&ws.root);
    let refused = Code::AgentOutputTree.as_str();
    let named = project.to_string_lossy().into_owned();
    for form in [&[][..], &["--revert"], &["--check"]] {
        let mut args = vec!["vendor", "--json"];
        args.extend_from_slice(form);
        // The working directory nobody named, then a scope `--cwd` names.
        let (code, envelope) = run(&project, &args, &service).await;
        assert_eq!(code, 1, "{args:?}: {envelope:#}");
        assert_eq!(envelope_error_code(&envelope), Some(refused), "{args:?}");
        args.extend(["--cwd", &named]);
        let (code, envelope) = run(&ws.root, &args, &service).await;
        assert_eq!(code, 1, "{args:?}: {envelope:#}");
        assert_eq!(envelope_error_code(&envelope), Some(refused), "{args:?}");
    }
    assert_eq!(asked(&service).await, Vec::<String>::new());
    assert_same_tree(&before, &snapshot(&ws.root));
}

// ── In process: a lane that plans ────────────────────────────────────

/// A patch service that serves fixed bytes and notes, each time it is
/// asked, what the lock and the index held: an artifact is fetched
/// before any owned write.
struct Serves<'a> {
    bytes: Vec<u8>,
    ws: &'a Workspace,
    seen: Mutex<Vec<(Option<String>, bool)>>,
}

impl ArtifactSource for Serves<'_> {
    fn native_file<'a>(
        &'a self,
        _: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, (&'static str, String)>> {
        let state = (
            self.ws.get(lane::LOCK),
            self.ws.at(INDEX_PATH).exists() || self.ws.at(VENDOR_STATE_REL).exists(),
        );
        self.seen.lock().expect("the notes").push(state);
        Box::pin(async move { Ok(self.bytes.clone()) })
    }
}

/// The commit of a build that has one under a Bazel root. It counts the
/// commits whose staged pin found its artifact already on disk.
struct Lands<'a>(&'a Workspace, AtomicUsize);

impl RootCommit for Lands<'_> {
    fn commit<'a>(
        &'a self,
        group: Option<GroupCommit>,
        staged: &'a [RootTxn],
    ) -> BoxFuture<'a, std::io::Result<Vec<CommittedFile>>> {
        Box::pin(async move {
            let artifact = std::fs::read(self.0.at(&format!("{UNIT}/{}", lane::LEAF)));
            if artifact.is_ok_and(|bytes| lane::digest().holds(&bytes)) {
                self.1.fetch_add(1, Ordering::SeqCst);
            }
            for txn in staged {
                lane::land(&txn.root, &txn.changes)?;
            }
            match group {
                Some(group) => group.commit_changes().await,
                None => Ok(Vec::new()),
            }
        })
    }
}

/// The inner entry of the seam for `left-pad`, over the lane of
/// `lane.rs`, as the route of `apply` runs it.
async fn vendor(ws: &Workspace, source: &Serves<'_>, commit: &Lands<'_>) -> Routed {
    let record = PatchRecord {
        uuid: lane::UUID.to_string(),
        exported_at: String::new(),
        files: Default::default(),
        vulnerabilities: Default::default(),
        description: String::new(),
        license: String::new(),
        tier: String::new(),
    };
    vendor_over(ws, lane::TABLE, &record, source, commit).await
}

/// [`vendor`] over the lane table `lanes`, for the patch `record`.
async fn vendor_over(
    ws: &Workspace,
    lanes: LaneTable,
    record: &PatchRecord,
    source: &Serves<'_>,
    commit: &Lands<'_>,
) -> Routed {
    // The crawlers are aimed at an empty prefix: no installed tree of
    // this machine is read.
    let prefix = ws.at(".git/no-installed-tree");
    std::fs::create_dir_all(&prefix).expect("mkdir");
    let common = GlobalArgs {
        cwd: ws.root.clone(),
        global_prefix: Some(prefix),
        json: true,
        silent: true,
        ..GlobalArgs::default()
    };
    let engine = Engine {
        lanes,
        proofs: lane::PROOFS,
        source,
        commit,
        routed: false,
        close: false,
        notes: false,
    };
    let blobs = ws.at(".socket/blobs");
    let sources = PatchSources {
        blobs_path: &blobs,
        mem_blobs: None,
    };
    let ledger = socket_patch_core::vendor::load_state(&ws.root).await;
    let mut env = Envelope::new(Command::Vendor);
    let purl = lane::PURL;
    vendor_one(
        &common, purl, record, &sources, None, ledger, &engine, &mut env,
    )
    .await
}

fn serves<'a>(ws: &'a Workspace, bytes: &[u8]) -> Serves<'a> {
    Serves {
        bytes: bytes.to_vec(),
        ws,
        seen: Mutex::new(Vec::new()),
    }
}

/// The artifact a plan names is satisfied before the first owned write:
/// it is fetched while the lock and the index are as they were, it is on
/// disk with the pinned digest when the pin is committed, and bytes that
/// do not hash to the digest leave nothing written at all.
#[tokio::test]
async fn artifact_spec_precedes_apply() {
    let ws = Workspace::new(true);
    let before = snapshot(&ws.root);

    // A service that serves other bytes than the plan pins.
    let (tampered, commit) = (serves(&ws, b"tampered"), Lands(&ws, AtomicUsize::new(0)));
    let refused = vendor(&ws, &tampered, &commit).await;
    assert!(matches!(refused, Routed::Refused { .. }), "{refused:?}");
    let mut after = snapshot(&ws.root);
    after.retain(|path, _| !path.starts_with(".git/"));
    let mut untouched = before.clone();
    untouched.retain(|path, _| !path.starts_with(".git/"));
    assert_same_tree(&untouched, &after);
    assert_eq!(commit.1.load(Ordering::SeqCst), 0, "nothing was committed");

    let source = serves(&ws, lane::ARTIFACT);
    assert_eq!(vendor(&ws, &source, &commit).await, Routed::Vendored);
    // Asked once, with the lock as the user left it and no record yet.
    let seen = source.seen.lock().expect("the notes").clone();
    assert_eq!(seen, [(Some(lane::LOCK_TEXT.to_string()), false)]);
    // The provider was in place when the pin landed.
    assert_eq!(commit.1.load(Ordering::SeqCst), 1);
    let artifact = format!("{UNIT}/{}", lane::LEAF);
    let pin = lane::pinned(&artifact, &lane::digest());
    let pinned = lane::LOCK_TEXT.replace(lane::UPSTREAM, &pin);
    assert_eq!(ws.get(lane::LOCK).as_deref(), Some(pinned.as_str()));
    let entry = ws.entry();
    assert_eq!(entry.artifact.sha256, Digest::sha256_hex(lane::ARTIFACT));
    assert_eq!(
        entry.bazel_index().map(|record| record.uuid),
        Some(lane::UUID)
    );
}

/// An undo that cannot put a pin back undoes nothing of the patch and
/// keeps the artifact the pin names: the lock, the index and the artifact
/// are byte for byte what they were, and the outcome says
/// `vendor_bazel_revert_incomplete`. Once the file is restored the same
/// undo returns the tree to what it was before the patch was vendored.
#[tokio::test]
async fn revert_incomplete_keeps_artifact() {
    let ws = Workspace::new(true);
    let (source, commit) = (serves(&ws, lane::ARTIFACT), Lands(&ws, AtomicUsize::new(0)));
    assert_eq!(vendor(&ws, &source, &commit).await, Routed::Vendored);
    let entry = ws.entry();
    let wired = ws.get(lane::LOCK).expect("the lock");

    // The user reformats the pinned value: the record no longer matches.
    ws.put(lane::LOCK, wired.replace("{tarball: ", "{ tarball: "));
    let drifted = snapshot(&ws.root);
    let opts = RevertOpts::new(false);
    let loader = reader();
    let kept = revert_entry(&entry, &ws.root, opts, lane::TABLE, &commit, &loader).await;
    assert!(kept.success && kept.kept_artifact, "{kept:?}");
    let incomplete = Code::revert_incomplete(Mode::Vendored).expect("a code");
    let said: Vec<&str> = kept.warnings.iter().map(|w| w.code).collect();
    assert_eq!(said, [incomplete.as_str()]);
    // The file that drifted is named, with the command that restores it.
    let remedy = format!("`git checkout -- {}`", lane::LOCK);
    assert!(kept.warnings[0].detail.contains(&remedy), "{kept:?}");
    assert_same_tree(&drifted, &snapshot(&ws.root));
    assert!(ws.at(&format!("{UNIT}/{}", lane::LEAF)).exists());

    // A dry run of an undo that would land writes nothing either.
    ws.put(lane::LOCK, &wired);
    let restored = snapshot(&ws.root);
    let (loader, previewed) = (reader(), RevertOpts::new(true));
    let dry = revert_entry(&entry, &ws.root, previewed, lane::TABLE, &commit, &loader).await;
    assert!(dry.success && !dry.kept_artifact, "{dry:?}");
    assert_same_tree(&restored, &snapshot(&ws.root));

    let loader = reader();
    let undone = revert_entry(&entry, &ws.root, opts, lane::TABLE, &commit, &loader).await;
    assert!(undone.success && !undone.kept_artifact, "{undone:?}");
    assert_eq!(undone.warnings.len(), 0, "{undone:?}");
    assert_eq!(ws.get(lane::LOCK).as_deref(), Some(lane::LOCK_TEXT));
    assert!(!ws.at(INDEX_PATH).exists(), "the last row takes the index");
    assert!(!ws.at(".socket/vendor/npm").exists(), "and the artifact");
}

/// What the built binary does with a tree a lane wired (R-142 and the
/// undo). Its artifact verifies against the patch record, so `vendor
/// --check` gets past the artifact check and asks the Bazel build: with no
/// enabled lane nothing can prove that the build consumes the pin, and the
/// entry fails with that reason, never with one about a native lock.
/// `vendor --revert` keeps the pin, its artifact and an artifact that no
/// ledger entry owns: no enabled lane can say that the build reads none of
/// it. Nothing is deleted, and nothing is asked of the patch service.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_binary_keeps_what_the_index_wires() {
    let ws = Workspace::new(true);
    let archive = LaneOps {
        gate: lane::gate_archive,
        ..lane::ops()
    };
    let table = lane::table_with(archive, lane::ops().lanes[0].classes);
    let hashes = serde_json::json!({
        "beforeHash": git_sha256(lane::ARCHIVE_BEFORE),
        "afterHash": git_sha256(lane::ARCHIVE_AFTER),
    });
    let patch = serde_json::json!({
        "uuid": lane::UUID, "exportedAt": "2026-01-01T00:00:00Z",
        "files": { lane::ARCHIVE_FILE: hashes },
        "vulnerabilities": {}, "description": "x", "license": "MIT", "tier": "free",
    });
    let record: PatchRecord = serde_json::from_value(patch.clone()).expect("a record");
    let (source, commit) = (
        serves(&ws, lane::tarball()),
        Lands(&ws, AtomicUsize::new(0)),
    );
    let vendored = vendor_over(&ws, table, &record, &source, &commit).await;
    assert_eq!(vendored, Routed::Vendored);
    let manifest = serde_json::json!({ "patches": { lane::PURL: patch } });
    ws.put(".socket/manifest.json", manifest.to_string());
    // An artifact no ledger entry owns and no lockfile refers to.
    let orphan = format!(".socket/vendor/npm/{OTHER_UUID}/is-odd-3.0.1.bin");
    ws.put(&orphan, b"is-odd, patched\n");
    let admitted = ws.admitted();

    let service = MockServer::start().await;
    let before = snapshot(&ws.root);
    let (code, envelope) = run(&ws.root, &["vendor", "--check", "--json"], &service).await;
    let event = event_for(&envelope, lane::PURL);
    if !admitted {
        assert_eq!(code, 1, "{envelope:#}");
        assert_eq!(event["errorCode"], "vendor_check_failed", "{envelope:#}");
        // The Bazel check answered: the artifact check before it passed.
        let reason = event["reason"].as_str().expect("a reason");
        let missing = "wiring missing: no file the Bazel build reads pins the vendored artifact";
        assert!(reason.starts_with(missing), "{reason}");
    }
    assert_same_tree(&before, &snapshot(&ws.root));

    let (_, envelope) = run(&ws.root, &["vendor", "--revert", "--json"], &service).await;
    let after = snapshot(&ws.root);
    if !admitted {
        let codes = all_codes(&envelope);
        let incomplete = Code::revert_incomplete(Mode::Vendored).expect("a code");
        assert!(
            codes.iter().any(|c| c == incomplete.as_str()),
            "{envelope:#}"
        );
        let kept = "vendor_orphan_still_wired";
        let orphaned = |event: &&Value| event["errorCode"] == kept;
        let events = envelope["events"].as_array().expect("events");
        let event = events
            .iter()
            .find(orphaned)
            .expect("the orphan is reported");
        // One sentence, as it is written: no run of spaces from a string
        // literal that lost its line continuations.
        let reason = event["reason"].as_str().expect("a reason");
        assert!(!reason.contains("  "), "{reason:?}");
        assert!(reason.contains("no enabled lane can tell"), "{reason}");
        let artifact = format!("{UNIT}/left-pad-1.3.0.tgz");
        let kept: BTreeMap<_, _> = [
            lane::LOCK,
            INDEX_PATH,
            VENDOR_STATE_REL,
            orphan.as_str(),
            artifact.as_str(),
        ]
        .into_iter()
        .map(|path| (path, (before.get(path), after.get(path))))
        .collect();
        for (path, (was, is)) in kept {
            assert!(was.is_some() && was == is, "{path} changed: {envelope:#}");
        }
    }
    assert_eq!(asked(&service).await, Vec::<String>::new());
}

/// R-142 where a lane can tell: an artifact that no ledger entry owns is
/// in use exactly when a row of the root's owned index names its patch,
/// whatever kind of row. The orphan sweep's own cases (it deletes the
/// one no row names and keeps the other) run in process, in the unit
/// tests of the seam: the built binary has no lane that can tell.
#[tokio::test]
async fn an_index_row_keeps_an_artifact_in_use() {
    use socket_patch_cli::bazel_gate::vendored::in_use;
    use socket_patch_core::crawlers::types::Ecosystem;
    let ws = Workspace::new(true);
    let (source, commit) = (serves(&ws, lane::ARTIFACT), Lands(&ws, AtomicUsize::new(0)));
    assert_eq!(vendor(&ws, &source, &commit).await, Routed::Vendored);
    let npm = Some(Ecosystem::Npm);
    let asked = || in_use(&reader(), &ws.root, &lane::TABLE, npm, None, OTHER_UUID);
    assert_eq!(asked(), Some(false), "no row and no pin names the patch");

    let index = ws.get(INDEX_PATH).expect("the index");
    let Parsed::Ours(mut index) = owned_index::parse(index.as_bytes()) else {
        panic!("not the index socket-patch writes");
    };
    index.files.push(FileRow {
        path: format!(".socket/bazel/patches/{OTHER_UUID}/is-odd.patch"),
        sha256: Digest::sha256_hex(b"a patch file"),
        uuid: OTHER_UUID.to_string(),
        lane: lane::LANE.0.to_string(),
    });
    ws.put(INDEX_PATH, index.render().expect("an index that renders"));
    assert_eq!(asked(), Some(true), "a `files` row names the patch");
}
