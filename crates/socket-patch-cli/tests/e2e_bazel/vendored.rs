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
//! No Bazel and no network: a loopback server stands in for the patch
//! service and records what it is asked.

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
    revert_entry, vendor_one, ArtifactSource, Engine, RootCommit, RootTxn, Routed,
};
use socket_patch_cli::json_envelope::{Command, Envelope};
use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::lanes::{self, Cell};
use socket_patch_core::bazel::model::{Digest, HubId, Mode, Reason, RootRef};
use socket_patch_core::bazel::owned_index::{self, FileRow, Parsed, INDEX_PATH};
use socket_patch_core::crawlers::bazel_workspace::{read_workspace, DiskView};
use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::patch::apply::PatchSources;
use socket_patch_core::utils::group_commit::{CommittedFile, GroupCommit};
use socket_patch_core::vendor::{RevertOpts, VendorEntry, VendorState, VENDOR_STATE_REL};
use wiremock::MockServer;

use crate::bazel_common::{assert_same_tree, snapshot};
use crate::common::envelope::{all_codes, event_for, parse_json_envelope};
use crate::common::{
    envelope_error_code, git_sha256, run_with_env, write_minimal_manifest, PatchEntry,
};

const UNIT: &str = ".socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const OTHER_UUID: &str = "0a1b2c3d-0000-4000-8000-0000000000a1";

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

    /// Whether the shipped lanes serve the hub in vendored mode: what
    /// every expectation of a refusal is computed from.
    fn admitted(&self) -> bool {
        let root = RootRef {
            root: self.root.clone(),
            project_rel: String::new(),
            boundary_levels: 0,
        };
        let ws = read_workspace(&root, &DiskView::new(&root)).expect("a workspace");
        let cell = Cell::of(&ws, HubId(0), Mode::Vendored).expect("the hub");
        lanes::admits(&lanes::PRODUCTION, &cell)
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
    let ws = Workspace::new(true);
    ws.stage_patch();
    let service = MockServer::start().await;
    let before = snapshot(&ws.root);
    let (code, envelope) = run(&ws.root, &["vendor", "--json"], &service).await;
    if ws.admitted() {
        // A release that enables the lane vendors the package instead.
        return;
    }
    assert_eq!(code, 1, "{envelope:#}");
    let event = event_for(&envelope, lane::PURL);
    let refusal = Code::refusal(Mode::Vendored, Reason::RulesetUnsupported).expect("a code");
    assert_eq!(event["action"], "failed", "{envelope:#}");
    assert_eq!(event["errorCode"], refusal.as_str(), "{envelope:#}");
    let details = &event["details"];
    assert_eq!(details["token"], "lane_not_enabled", "{event:#}");
    assert_eq!(details["lift"]["kind"], "enable_lane", "{event:#}");
    assert_eq!(details["lift"]["lane"], "V-JS1", "{event:#}");
    let bazel = serde_json::json!({
        "state": "refused", "ruleset": "rules_js", "lock": lane::LOCK, "lane": "V-JS1",
    });
    assert_eq!(details["bazel"], bazel, "{event:#}");
    assert_eq!(asked(&service).await, Vec::<String>::new());
    assert_same_tree(&before, &snapshot(&ws.root));

    // The same project under no Bazel root.
    let plain = Workspace::new(false);
    plain.stage_patch();
    let (_, envelope) = run(&plain.root, &["vendor", "--json"], &service).await;
    // The native backend asks the service for the artifact, which also
    // shows that the recorder above would have seen a request.
    let requests = asked(&service).await;
    assert!(
        requests.iter().any(|path| path.contains("/patch/")),
        "{requests:?}"
    );
    assert_eq!(bazel_codes(&envelope), Vec::<String>::new(), "{envelope:#}");
    let event = event_for(&envelope, lane::PURL);
    assert!(event["details"].get("bazel").is_none(), "{event:#}");
    assert!(event["details"].get("lift").is_none(), "{event:#}");
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
        lanes: lane::TABLE,
        proofs: lane::PROOFS,
        source,
        commit,
        routed: false,
        close: false,
    };
    let record = PatchRecord {
        uuid: lane::UUID.to_string(),
        exported_at: String::new(),
        files: Default::default(),
        vulnerabilities: Default::default(),
        description: String::new(),
        license: String::new(),
        tier: String::new(),
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
        &common, purl, &record, &sources, None, ledger, &engine, &mut env,
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
    let kept = revert_entry(&entry, &ws.root, opts, lane::TABLE, &commit).await;
    assert!(kept.success && kept.kept_artifact, "{kept:?}");
    let incomplete = Code::revert_incomplete(Mode::Vendored).expect("a code");
    let said: Vec<&str> = kept.warnings.iter().map(|w| w.code).collect();
    assert_eq!(said, [incomplete.as_str()]);
    assert!(kept.warnings[0].detail.contains(lane::LOCK), "{kept:?}");
    assert_same_tree(&drifted, &snapshot(&ws.root));
    assert!(ws.at(&format!("{UNIT}/{}", lane::LEAF)).exists());

    // A dry run of an undo that would land writes nothing either.
    ws.put(lane::LOCK, &wired);
    let restored = snapshot(&ws.root);
    let dry = revert_entry(
        &entry,
        &ws.root,
        RevertOpts::new(true),
        lane::TABLE,
        &commit,
    )
    .await;
    assert!(dry.success && !dry.kept_artifact, "{dry:?}");
    assert_same_tree(&restored, &snapshot(&ws.root));

    let undone = revert_entry(&entry, &ws.root, opts, lane::TABLE, &commit).await;
    assert!(undone.success && !undone.kept_artifact, "{undone:?}");
    assert_eq!(undone.warnings.len(), 0, "{undone:?}");
    assert_eq!(ws.get(lane::LOCK).as_deref(), Some(lane::LOCK_TEXT));
    assert!(!ws.at(INDEX_PATH).exists(), "the last row takes the index");
    assert!(!ws.at(".socket/vendor/npm").exists(), "and the artifact");
}

/// What the built binary does with a tree a lane wired (R-142 and the
/// undo): with no enabled lane it can neither prove that the build
/// consumes the pin nor put it back, so `vendor --check` fails for the
/// entry, and `vendor --revert` keeps the pin, its artifact and an
/// artifact that only a row of the index names. Nothing is deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_binary_keeps_what_the_index_wires() {
    let ws = Workspace::new(true);
    if ws.admitted() {
        return;
    }
    let (source, commit) = (serves(&ws, lane::ARTIFACT), Lands(&ws, AtomicUsize::new(0)));
    assert_eq!(vendor(&ws, &source, &commit).await, Routed::Vendored);
    // An artifact no ledger entry owns, which a `files` row of the index
    // names: no lockfile refers to it, and the build may read it.
    let orphan = format!(".socket/vendor/npm/{OTHER_UUID}/is-odd-3.0.1.bin");
    ws.put(&orphan, b"is-odd, patched\n");
    let index = ws.get(INDEX_PATH).expect("the index");
    let Parsed::Ours(mut index) = owned_index::parse(index.as_bytes()) else {
        panic!("not the index socket-patch writes");
    };
    index.files.push(FileRow {
        path: ".socket/bazel/patches/0a1b2c3d-0000-4000-8000-0000000000a1/is-odd.patch".into(),
        sha256: Digest::sha256_hex(b"a patch file"),
        uuid: OTHER_UUID.to_string(),
        lane: "V-JS1".to_string(),
    });
    ws.put(INDEX_PATH, index.render().expect("an index that renders"));

    let service = MockServer::start().await;
    let before = snapshot(&ws.root);
    let (code, envelope) = run(&ws.root, &["vendor", "--check", "--json"], &service).await;
    assert_eq!(code, 1, "{envelope:#}");
    let event = event_for(&envelope, lane::PURL);
    assert_eq!(event["errorCode"], "vendor_check_failed", "{envelope:#}");
    assert_same_tree(&before, &snapshot(&ws.root));

    let (_, envelope) = run(&ws.root, &["vendor", "--revert", "--json"], &service).await;
    let codes = all_codes(&envelope);
    let incomplete = Code::revert_incomplete(Mode::Vendored).expect("a code");
    assert!(
        codes.iter().any(|c| c == incomplete.as_str()),
        "{envelope:#}"
    );
    assert!(
        codes.iter().any(|c| c == "vendor_orphan_still_wired"),
        "{envelope:#}"
    );
    let after = snapshot(&ws.root);
    let kept: BTreeMap<_, _> = [lane::LOCK, INDEX_PATH, VENDOR_STATE_REL, orphan.as_str()]
        .into_iter()
        .map(|path| (path, (before.get(path), after.get(path))))
        .collect();
    for (path, (was, is)) in kept {
        assert!(was.is_some() && was == is, "{path} changed: {envelope:#}");
    }
    assert!(after.contains_key(&format!("{UNIT}/{}", lane::LEAF)));
    assert_eq!(asked(&service).await, Vec::<String>::new());
}
