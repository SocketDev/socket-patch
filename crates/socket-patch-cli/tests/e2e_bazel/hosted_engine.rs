//! Hermetic CLI tests: the hosted seam under a Bazel hub (design 2.7 and
//! 7; hazards HZ-12, HZ-13 and HZ-15; revision 4, sections 4 and 5).
//!
//! Bazel builds a governed ecosystem from the lock its ruleset reads, so a
//! hosted pin there is the gate's to decide before a native rewriter sees
//! the patch. The built binary, whose lanes are all disabled, refuses each
//! governed patch with the code of the reason and writes nothing for it:
//! not the lock the hub reads, not the sibling lock nobody reads, and none
//! of the install-policy files native hosted mode creates. Its
//! expectations are computed with `lanes::admits`. What a lane's plan does
//! once one is enabled (the pin and its record in one commit anchored at
//! the Bazel root, no `.npmrc`, an undo of everything when the project's
//! own commit fails) is shown in process, over the lane table of
//! `lane.rs`: the built binary has no lane to show it with.
//!
//! No Bazel and no network: a loopback server stands in for the Socket
//! API.

// One file for this suite and for the unit tests of the seam, each of
// which uses a part of it.
#[allow(dead_code)]
mod lane;

#[path = "../hosted_memory_common/mod.rs"]
mod hosted_memory_common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use socket_patch_cli::args::GlobalArgs;
use socket_patch_cli::bazel_gate::hosted::{assumed, grants, run_command, staged, Hosted};
use socket_patch_cli::bazel_gate::run::{RunResult, ToolRunner};
use socket_patch_cli::commands::vex::VexEmbedArgs;
use socket_patch_cli::json_envelope::{Command, Envelope, PatchAction, PatchEvent};
use socket_patch_core::api::client::{ApiClient, ApiClientOptions, ApiRoute};
use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::lanes::{self, Cell};
use socket_patch_core::bazel::model::{
    Actor, GateOutcome, HubId, Interim, Mode, Reason, RootRef, RunKind, RunRequired,
};
use socket_patch_core::bazel::owned_index::{self, Parsed, INDEX_PATH};
use socket_patch_core::crawlers::bazel_workspace::{read_workspace, DiskView};
use socket_patch_core::formats::cargo::source_replacement::CratesIoSource;
use socket_patch_core::hosted::bazel_reads::BAZEL_WORKSPACE_KEY;
use socket_patch_core::hosted::engine::{self, Candidate, RewriteOptions, Rewritten};
use socket_patch_core::patch::apply_lock;
use socket_patch_core::patch::redirect::npmrc::OuterAllowRemote;
use socket_patch_core::patch::redirect::yarnrc::OuterYarnMirror;
use socket_patch_core::utils::group_commit::{GroupCommit, ROOT_JOURNAL_REL};
use socket_patch_core::vendor::lock_inventory::ProjectView;
use wiremock::MockServer;

use crate::bazel_common::{assert_same_tree, assert_write_policy, changes, snapshot};
use crate::common::envelope::{all_codes, event_for};
use hosted_memory_common::{mount_api, run_disk_in, Patch, ORG};

/// The files of a checkout whose project at `project` (`""`: the root) is
/// an npm project with a pnpm lock and an npm lock beside it, and
/// (`bazel`) the rules_js hub at the top that reads the pnpm lock.
fn files(project: &str, bazel: bool) -> BTreeMap<String, Vec<u8>> {
    let below = |name: &str| match project {
        "" => name.to_string(),
        project => format!("{project}/{name}"),
    };
    let label = match project {
        "" => "//:pnpm-lock.yaml".to_string(),
        project => format!("//{project}:pnpm-lock.yaml"),
    };
    let manifest = r#"{"name": "p", "version": "0.0.0", "dependencies": {"left-pad": "1.3.0"}}"#;
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut put = |rel: String, text: &str| drop(files.insert(rel, text.as_bytes().to_vec()));
    put(below(lane::LOCK), lane::LOCK_TEXT);
    put(below("package-lock.json"), lane::NPM_LOCK_TEXT);
    put(below("package.json"), manifest);
    if bazel {
        put(".bazelversion".to_string(), lane::BAZELVERSION);
        put(
            "MODULE.bazel".to_string(),
            &lane::MODULE.replace("LOCK_LABEL", &label),
        );
        if !project.is_empty() {
            put(below("BUILD.bazel"), "");
        }
    }
    files
}

/// The patch of `left-pad` as the fake Socket API grants it.
fn patch() -> Patch {
    let reference = json!({
        "status": "granted",
        "url": lane::URL,
        "purl": null,
        "artifacts": [{
            "kind": "tarball",
            "url": lane::URL,
            "integrity": { "sha512": lane::PATCHED },
        }],
        "registryOverride": null,
    });
    Patch {
        purl: lane::PURL.to_string(),
        uuid: lane::UUID.to_string(),
        reference,
    }
}

/// A checkout on disk, for the tests that run the seam in process.
struct Checkout {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    common: GlobalArgs,
}

impl Checkout {
    fn new(project: &str, bazel: bool) -> Self {
        let tmp = tempfile::tempdir().expect("a temporary directory");
        let root = std::fs::canonicalize(tmp.path()).expect("its real path");
        let common = GlobalArgs {
            cwd: below(&root, project),
            ..GlobalArgs::default()
        };
        let checkout = Self {
            _tmp: tmp,
            root,
            common,
        };
        // `.git` makes the directory the repository: nothing above is read.
        checkout.put(".git/HEAD", "ref: refs/heads/main\n");
        for (rel, bytes) in files(project, bazel) {
            checkout.put(&rel, bytes);
        }
        checkout
    }

    fn put(&self, rel: &str, bytes: impl AsRef<[u8]>) {
        let path = below(&self.root, rel);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(path, bytes).expect("write");
    }

    fn get(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(below(&self.root, rel)).ok()
    }
}

/// `rel` below `base`, level by level.
fn below(base: &Path, rel: &str) -> PathBuf {
    let levels = rel.split('/').filter(|level| !level.is_empty());
    levels.fold(base.to_path_buf(), |at, level| at.join(level))
}

/// Whether the shipped lanes serve the hub of `files` in hosted mode:
/// what every expectation of a refusal is computed from.
fn admitted(project: &str) -> bool {
    let checkout = Checkout::new(project, true);
    let root = RootRef {
        root: checkout.root.clone(),
        project_rel: project.to_string(),
        boundary_levels: 0,
    };
    let ws = read_workspace(&root, &DiskView::new(&root)).expect("a workspace");
    let cell = Cell::of(&ws, HubId(0), Mode::Hosted).expect("the hub");
    lanes::admits(&lanes::PRODUCTION, &cell)
}

/// Every Bazel code an envelope carries.
fn bazel_codes(envelope: &Value) -> Vec<String> {
    let known = |code: &String| Code::ALL.iter().any(|c| c.as_str() == code);
    all_codes(envelope).into_iter().filter(known).collect()
}

// ── The built binary: every production lane is disabled ──────────────

/// A package whose lock a hub reads is refused with the code of the mode
/// and reason, the event says which lane would lift it, and no file is
/// written: for a project at the Bazel root and for one below it, in a
/// run and in its dry run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_governed_dep_is_refused_with_a_named_code_and_zero_writes() {
    let api = MockServer::start().await;
    mount_api(&api, &[patch()]).await;
    for project in ["", "svc/app"] {
        if admitted(project) {
            // A release that enables the lane pins the package instead.
            continue;
        }
        let files = files(project, true);
        let refusal = Code::refusal(Mode::Hosted, Reason::RulesetUnsupported).expect("a code");
        for dry_run in [true, false] {
            let run = run_disk_in(&api, &files, project, dry_run);
            let envelope = &run.envelope;
            assert_eq!(envelope["status"], "success", "{project}: {envelope:#}");
            assert_eq!(run.changed, BTreeMap::new(), "{project} dry_run={dry_run}");

            let event = event_for(envelope, lane::PURL);
            assert_eq!(event["action"], "skipped", "{envelope:#}");
            assert_eq!(event["errorCode"], refusal.as_str(), "{envelope:#}");
            let reason = event["reason"].as_str().unwrap_or_default();
            assert!(reason.ends_with("nothing was written"), "{event:#}");
            let details = &event["details"];
            assert_eq!(details["mode"], "hosted", "{event:#}");
            assert_eq!(details["token"], "lane_not_enabled", "{event:#}");
            assert_eq!(details["lift"]["kind"], "enable_lane", "{event:#}");
            assert_eq!(details["lift"]["lane"], "H-JS1", "{event:#}");
            let lock = match project {
                "" => lane::LOCK.to_string(),
                project => format!("{project}/{}", lane::LOCK),
            };
            let bazel = json!({
                "state": "refused", "ruleset": "rules_js", "lock": lock, "lane": "H-JS1",
            });
            assert_eq!(details["bazel"], bazel, "{event:#}");

            // The run says the refusal once, and that the sibling lock
            // and the files its rewrite brings were left alone.
            let codes = bazel_codes(envelope);
            let skipped = Code::RedirectSideFileSkipped.as_str();
            assert!(codes.iter().any(|c| c == refusal.as_str()), "{codes:?}");
            assert!(codes.iter().any(|c| c == skipped), "{codes:?}");
            let rewritten = &envelope["redirect"]["rewrittenFiles"];
            assert_eq!(rewritten, &json!([]), "{envelope:#}");
        }
    }
}

/// A project that release 5.1 already rewrote: both npm locks carry the
/// hosted URL. The gate still refuses the patch, a lock line that names
/// the URL confirms nothing, and none of the install-policy files that
/// native hosted mode heals for such a lock is created.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lock_that_already_names_the_url_confirms_nothing_under_a_hub() {
    if admitted("") {
        return;
    }
    let api = MockServer::start().await;
    mount_api(&api, &[patch()]).await;
    let files = pinned_by_5_1("");

    let run = run_disk_in(&api, &files, "", false);
    assert_eq!(run.changed, BTreeMap::new(), "{:#}", run.envelope);
    let event = event_for(&run.envelope, lane::PURL);
    assert_eq!(event["action"], "skipped", "{:#}", run.envelope);
    assert_eq!(event["details"]["bazel"]["state"], "refused", "{event:#}");
    let codes = all_codes(&run.envelope);
    for healed in ["redirect_npm_allow_remote", "redirect_pnpm_trust_lockfile"] {
        assert!(!codes.iter().any(|c| c == healed), "{healed}: {codes:?}");
    }
}

/// The files of [`files`] as release 5.1 left them: both npm locks name
/// the hosted URL.
fn pinned_by_5_1(project: &str) -> BTreeMap<String, Vec<u8>> {
    let mut files = files(project, true);
    let pinned = lane::LOCK_TEXT.replace(lane::UPSTREAM, &lane::native_pin());
    files.insert(lane::LOCK.to_string(), pinned.into_bytes());
    let npm = lane::NPM_LOCK_TEXT
        .replace(
            "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            lane::URL,
        )
        .replace(lane::UPSTREAM_SRI, lane::PATCHED);
    files.insert("package-lock.json".to_string(), npm.into_bytes());
    files
}

/// A `bun.lockb` that cannot be parsed keeps the npm patches from the
/// native rewriters, and must not keep them from the Bazel gate: the
/// governed patch is refused with the code of its reason all the same, and
/// none of the install-policy files that the engine heals for a lock with
/// a hosted URL is created beside the lock the hub reads. The installed
/// copy is in the fixture because discovery finds no package through an
/// unreadable binary lock alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unparseable_bun_lock_does_not_take_a_governed_patch_from_the_gate() {
    if admitted("") {
        return;
    }
    let api = MockServer::start().await;
    mount_api(&api, &[patch()]).await;
    let mut files = pinned_by_5_1("");
    files.insert("bun.lockb".to_string(), b"not a bun lock".to_vec());
    let installed = r#"{"name": "left-pad", "version": "1.3.0"}"#;
    files.insert(
        "node_modules/left-pad/package.json".to_string(),
        installed.as_bytes().to_vec(),
    );
    let refusal = Code::refusal(Mode::Hosted, Reason::RulesetUnsupported).expect("a code");
    for dry_run in [true, false] {
        let run = run_disk_in(&api, &files, "", dry_run);
        let envelope = &run.envelope;
        assert_eq!(
            run.changed,
            BTreeMap::new(),
            "dry_run={dry_run}: {envelope:#}"
        );
        let event = event_for(envelope, lane::PURL);
        assert_eq!(event["action"], "skipped", "{envelope:#}");
        assert_eq!(event["errorCode"], refusal.as_str(), "{envelope:#}");
        assert_eq!(event["details"]["bazel"]["state"], "refused", "{event:#}");
        let codes = all_codes(envelope);
        for healed in ["redirect_npm_allow_remote", "redirect_pnpm_trust_lockfile"] {
            assert!(!codes.iter().any(|c| c == healed), "{healed}: {codes:?}");
        }
    }
}

/// The same project with no Bazel file: hosted mode pins both locks and
/// creates the two install-policy files, as release 5.1 does, and reports
/// no Bazel code and no Bazel detail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_same_project_under_no_bazel_root_is_rewritten_as_before() {
    let api = MockServer::start().await;
    mount_api(&api, &[patch()]).await;
    for project in ["", "svc/app"] {
        let run = run_disk_in(&api, &files(project, false), project, false);
        let envelope = &run.envelope;
        let below = |name: &str| match project {
            "" => name.to_string(),
            project => format!("{project}/{name}"),
        };
        let written: Vec<String> = [
            ".npmrc",
            "package-lock.json",
            lane::LOCK,
            "pnpm-workspace.yaml",
        ]
        .iter()
        .map(|name| below(name))
        .collect();
        let changed: Vec<&String> = run.changed.keys().collect();
        assert_eq!(changed, written.iter().collect::<Vec<_>>(), "{envelope:#}");
        assert_eq!(bazel_codes(envelope), Vec::<String>::new(), "{envelope:#}");
        let event = event_for(envelope, lane::PURL);
        assert_eq!(event["action"], "applied", "{envelope:#}");
        assert_eq!(event["details"], json!({ "mode": "hosted" }), "{event:#}");
    }
}

// ── In process: a lane that plans ────────────────────────────────────

fn candidates() -> Vec<Candidate> {
    vec![Candidate {
        purl: lane::PURL.to_string(),
        dep: lane::grant(),
    }]
}

/// One pass of the hosted engine over the project, as the command runs
/// it: the seam's reads, then the rewrite.
async fn rewrite(seam: &Hosted, common: &GlobalArgs, dry_run: bool) -> Rewritten {
    let view = ProjectView::Disk(&common.cwd);
    let candidates = candidates();
    let read = seam.read(&view, &candidates).await;
    let (npm_outer, yarn_outer) = (OuterAllowRemote::default, OuterYarnMirror::default);
    let options = RewriteOptions {
        dry_run,
        targets_pipenv_lock: false,
        pipenv_major: None,
        pipenv_unknown_detail: String::new(),
        trust_lockfile_config: true,
        npm_allow_remote_config: true,
        npm_outer: &npm_outer,
        yarn_classic_outer: &yarn_outer,
        cargo_outer: &|| CratesIoSource::Registry,
        pnpm_env: &|_| None,
        blocking: true,
        takeover_uuids: Default::default(),
        patch_server_origins: Vec::new(),
        prior_discovery: None,
    };
    engine::rewrite(&view, read, &candidates, BTreeMap::new(), options).await
}

/// The project's own commit, as the command makes it: each file the
/// native rewriters and the engine's own steps wrote, by its name in the
/// project.
async fn native(common: &GlobalArgs, done: &Rewritten) -> Result<(), String> {
    for (rel, text) in &done.rewrite.files {
        let path = below(&common.cwd, rel);
        std::fs::write(&path, text).map_err(|e| format!("failed to write {rel}: {e}"))?;
    }
    Ok(())
}

/// With a lane that plans, the pin and its record land in one commit
/// anchored at the Bazel root, `pnpm-workspace.yaml` is created as native
/// hosted mode creates it, and no `.npmrc` appears: the sibling lock that
/// would bring one is left as found. Every changed path is one
/// socket-patch may write in a Bazel repository. A second run finds the
/// pin in place and writes nothing; for a project at the root and below.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lane_pins_through_the_anchored_commit_and_no_npmrc_appears() {
    for project in ["", "svc/app"] {
        let checkout = Checkout::new(project, true);
        let common = &checkout.common;
        let at = |name: &str| match project {
            "" => name.to_string(),
            project => format!("{project}/{name}"),
        };
        let before = snapshot(&checkout.root);
        let seam = Hosted::new(common, lane::TABLE, lane::PROOFS);
        let done = rewrite(&seam, common, false).await;
        assert!(done.files.contains_key(BAZEL_WORKSPACE_KEY), "{project}");
        let pinned = [(lane::PURL.to_string(), lane::UUID.to_string())];
        assert_eq!(
            done.confirmed, pinned,
            "{project}: {:?}",
            done.rewrite.warnings
        );
        assert!(staged(&done) && assumed(&done, lane::UUID));
        assert_eq!(grants(&done).len(), 1);
        assert!(engine::guard(&ProjectView::Disk(&common.cwd), &done, &candidates()).is_none());
        // What the run writes, as the project spells it: the lock and the
        // policy file beside it, and the record at the Bazel root.
        let up = match project {
            "" => String::new(),
            project => project.split('/').map(|_| "../").collect(),
        };
        let mut rewritten = vec![
            format!("{up}{INDEX_PATH}"),
            lane::LOCK.to_string(),
            "pnpm-workspace.yaml".to_string(),
        ];
        rewritten.sort();
        assert_eq!(done.rewritten, rewritten, "{project}");
        // The rewrite itself lands nothing: the commit does.
        assert_same_tree(&before, &snapshot(&checkout.root));

        assert_eq!(seam.commit(&done, native(common, &done)).await, Ok(()));
        let after = snapshot(&checkout.root);
        let wrote: Vec<String> = changes(&before, &after)
            .into_iter()
            .map(|(path, _)| path)
            .filter(|path| below(&checkout.root, path).is_file())
            .collect();
        let expected = [
            INDEX_PATH.to_string(),
            at(lane::LOCK),
            at("pnpm-workspace.yaml"),
        ];
        let mut expected: Vec<String> = expected.into();
        expected.sort();
        assert_eq!(wrote, expected, "{project}");
        assert_write_policy(&before, &after);
        let lock = checkout.get(&at(lane::LOCK)).expect("the lock");
        assert_eq!(
            lock,
            lane::LOCK_TEXT.replace(lane::UPSTREAM, &lane::pinned())
        );
        assert_eq!(checkout.get(&at(".npmrc")), None, "{project}: no `.npmrc`");
        let sibling = checkout.get(&at("package-lock.json"));
        assert_eq!(sibling.as_deref(), Some(lane::NPM_LOCK_TEXT), "{project}");
        // The record names the pin, and no lock or journal is left.
        let index = checkout.get(INDEX_PATH).expect("the index");
        let Parsed::Ours(index) = owned_index::parse(index.as_bytes()) else {
            panic!("not the index socket-patch writes");
        };
        let rows: Vec<(&str, &str)> = index
            .pins
            .iter()
            .map(|row| (row.uuid.as_str(), row.file.as_str()))
            .collect();
        assert_eq!(rows, [(lane::UUID, at(lane::LOCK).as_str())], "{project}");
        let owned = below(&checkout.root, INDEX_PATH);
        let left: Vec<String> = std::fs::read_dir(owned.parent().expect("the owned directory"))
            .expect("the owned directory")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(left, ["index.json"], "{project}");

        // The event of the pin says how Bazel consumes it.
        let mut env = Envelope::new(Command::Scan);
        env.record(PatchEvent::new(PatchAction::Applied, lane::PURL).with_uuid(lane::UUID));
        seam.annotate(&mut env, &done);
        let bazel = json!({
            "state": "consumed", "ruleset": "rules_js", "lock": at(lane::LOCK),
            "lane": "H-TOY1", "anchor": "digest",
        });
        assert_eq!(env.events[0].details, Some(json!({ "bazel": bazel })));
        assert_eq!(seam.skipped(&done, &candidates()), Vec::new());

        // A second run: the pin is in place, confirmed, and nothing moves.
        let again = Hosted::new(common, lane::TABLE, lane::PROOFS);
        let done = rewrite(&again, common, false).await;
        assert_eq!(
            done.confirmed, pinned,
            "{project}: {:?}",
            done.rewrite.warnings
        );
        assert!(!staged(&done), "{project}: {:?}", done.bazel);
        assert_eq!(done.rewritten, Vec::<String>::new(), "{project}");
        assert_eq!(again.commit(&done, native(common, &done)).await, Ok(()));
        assert_same_tree(&after, &snapshot(&checkout.root));

        // The built binary's lanes cannot prove this pin, so they do not
        // confirm it either, and they leave it as they found it.
        if !admitted(project) {
            let shipped = Hosted::production(common);
            let done = rewrite(&shipped, common, false).await;
            assert_eq!(done.confirmed, Vec::new(), "{project}");
            assert!(!staged(&done) && !assumed(&done, lane::UUID));
            assert_eq!(done.rewritten, Vec::<String>::new(), "{project}");
        }
    }
}

/// The same project under no Bazel root, in process: the native rewriters
/// pin both locks and the engine creates `.npmrc`, which is what the lane
/// run above must not do.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_no_bazel_root_the_engine_creates_the_npmrc_as_before() {
    let checkout = Checkout::new("", false);
    let seam = Hosted::new(&checkout.common, lane::TABLE, lane::PROOFS);
    let done = rewrite(&seam, &checkout.common, false).await;
    assert!(done.bazel.is_none() && !done.files.contains_key(BAZEL_WORKSPACE_KEY));
    assert_eq!(
        done.rewritten,
        [
            ".npmrc",
            "package-lock.json",
            lane::LOCK,
            "pnpm-workspace.yaml"
        ]
    );
}

/// When the project's own commit fails behind the anchored one, the Bazel
/// root goes back to what it held: no pin, no index, no `.socket`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_project_commit_takes_the_bazel_commit_back() {
    for project in ["", "svc/app"] {
        let checkout = Checkout::new(project, true);
        let before = snapshot(&checkout.root);
        let seam = Hosted::new(&checkout.common, lane::TABLE, lane::PROOFS);
        let done = rewrite(&seam, &checkout.common, false).await;
        assert!(staged(&done), "{project}");
        let failing = async { Err("failed to write pnpm-workspace.yaml: disk full".to_string()) };
        let failed = seam.commit(&done, failing).await;
        let said = "failed to write pnpm-workspace.yaml: disk full".to_string();
        assert_eq!(failed, Err(said), "{project}");
        assert_same_tree(&before, &snapshot(&checkout.root));
    }
}

/// A file that changed between the decision and the commit refuses the
/// commit before anything is written: the user's edit stays, the project's
/// own commit is not run, and the run says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lock_edited_since_it_was_read_is_never_written_over() {
    let checkout = Checkout::new("", true);
    let seam = Hosted::new(&checkout.common, lane::TABLE, lane::PROOFS);
    let done = rewrite(&seam, &checkout.common, false).await;
    let edited = format!("{}# a line of the user's\n", lane::LOCK_TEXT);
    checkout.put(lane::LOCK, &edited);
    let before = snapshot(&checkout.root);
    let ran = std::cell::Cell::new(false);
    let project = async {
        ran.set(true);
        Ok(())
    };
    let refused = seam.commit(&done, project).await.unwrap_err();
    assert!(refused.contains("pnpm-lock.yaml changed"), "{refused}");
    assert!(refused.ends_with("(nothing was changed)"), "{refused}");
    assert!(!ran.get(), "the project's files were not written either");
    assert_same_tree(&before, &snapshot(&checkout.root));
}

/// An index at the root that socket-patch did not write cannot be relied
/// on: no lane writes beside it. Each governed patch is refused with the
/// code of that reason, in a run and in its dry run, and the file stays
/// as found.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_index_that_is_not_socket_patchs_refuses_every_governed_patch() {
    let checkout = Checkout::new("", true);
    checkout.put(INDEX_PATH, "not an index\n");
    let before = snapshot(&checkout.root);
    let seam = Hosted::new(&checkout.common, lane::TABLE, lane::PROOFS);
    let refusal = Code::refusal(Mode::Hosted, Reason::OwnedFileModified).expect("a code");
    for dry_run in [true, false] {
        let done = rewrite(&seam, &checkout.common, dry_run).await;
        assert_eq!(done.confirmed, Vec::new(), "dry_run={dry_run}");
        assert!(!staged(&done) && !assumed(&done, lane::UUID));
        let skipped = seam.skipped(&done, &candidates());
        let reasons: Vec<&str> = skipped.iter().map(|patch| patch.reason.as_str()).collect();
        assert_eq!(reasons, [refusal.as_str()], "{skipped:?}");
        let committed = seam.commit(&done, native(&checkout.common, &done)).await;
        assert_eq!(committed, Ok(()));
    }
    assert_same_tree(&before, &snapshot(&checkout.root));
}

/// A directory link, as each system makes one.
fn link_dir(target: &Path, link: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).expect("a link");
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(target, link).expect("a link");
}

/// A Bazel root whose `.socket` is a link belongs to another project. A
/// run that finds it so cannot rely on the index behind the link: it
/// refuses the patch and stages nothing, in a run and in its dry run. A
/// link that appears between the decision and the commit is refused by
/// the guard, and by the root's lock for a caller that committed all the
/// same. Nothing is created behind the link either way. On every system:
/// the link is a directory link as each one makes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_linked_socket_directory_at_the_root_gets_no_write() {
    let other = tempfile::tempdir().expect("another project");
    let link = |checkout: &Checkout| link_dir(other.path(), &checkout.root.join(".socket"));

    // Found linked.
    let checkout = Checkout::new("", true);
    link(&checkout);
    let before = snapshot(&checkout.root);
    let seam = Hosted::new(&checkout.common, lane::TABLE, lane::PROOFS);
    let refusal = Code::refusal(Mode::Hosted, Reason::OwnedFileModified).expect("a code");
    for dry_run in [true, false] {
        let done = rewrite(&seam, &checkout.common, dry_run).await;
        assert_eq!(done.confirmed, Vec::new(), "dry_run={dry_run}");
        assert!(!staged(&done) && !assumed(&done, lane::UUID));
        assert_eq!(done.rewritten, Vec::<String>::new(), "dry_run={dry_run}");
        let skipped = seam.skipped(&done, &candidates());
        let reasons: Vec<&str> = skipped.iter().map(|patch| patch.reason.as_str()).collect();
        assert_eq!(reasons, [refusal.as_str()], "{skipped:?}");
        let committed = seam.commit(&done, native(&checkout.common, &done)).await;
        assert_eq!(committed, Ok(()));
    }
    assert_same_tree(&before, &snapshot(&checkout.root));

    // Linked after the run decided.
    let checkout = Checkout::new("", true);
    let seam = Hosted::new(&checkout.common, lane::TABLE, lane::PROOFS);
    let done = rewrite(&seam, &checkout.common, false).await;
    assert!(staged(&done), "{:?}", done.rewrite.warnings);
    link(&checkout);
    let before = snapshot(&checkout.root);
    let view = ProjectView::Disk(&checkout.common.cwd);
    let Some(refusal) = engine::guard(&view, &done, &candidates()) else {
        panic!("not refused: {:?}", done.rewrite.warnings);
    };
    assert_eq!(refusal.code, engine::SYMLINK_REFUSAL, "{refusal:?}");
    assert!(refusal.message.contains(INDEX_PATH), "{refusal:?}");
    // A caller that committed all the same is refused by the lock, and
    // the project's own commit is never started.
    let ran = std::cell::Cell::new(false);
    let project = async {
        ran.set(true);
        Ok(())
    };
    let refused = seam.commit(&done, project).await;
    let said = refused.expect_err("no commit through a link");
    assert!(said.contains("is a symbolic link"), "{said}");
    assert!(said.ends_with("(nothing was changed)"), "{said}");
    assert!(!ran.get(), "the project's files were not written either");
    assert_same_tree(&before, &snapshot(&checkout.root));

    let behind = std::fs::read_dir(other.path()).expect("a directory");
    assert_eq!(behind.count(), 0, "nothing was created behind the link");
}

// ── One answer for a path two commits touch ──────────────────────────

/// A takeover staged its revert of the lock a hub reads in the project's
/// open group commit, and the lane then pins that lock: the run decides
/// from the staged bytes, the anchored commit lands the pin over what the
/// disk holds, and the group's own commit does not write its staged copy
/// over it. One run, no `changed while socket-patch was working on it`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lock_the_open_group_commit_holds_is_pinned_once() {
    for project in ["", "svc/app"] {
        let checkout = Checkout::new(project, true);
        let common = &checkout.common;
        let lock_path = below(&common.cwd, lane::LOCK);
        let group = GroupCommit::begin(&common.cwd);
        let reverted = format!("{}# as the takeover's revert left it\n", lane::LOCK_TEXT);
        socket_patch_core::utils::fs::atomic_write_bytes_preserving_mode(
            &lock_path,
            reverted.as_bytes(),
        )
        .await
        .expect("staged");
        assert_eq!(
            std::fs::read_to_string(&lock_path).expect("disk"),
            lane::LOCK_TEXT
        );

        let seam = Hosted::new(common, lane::TABLE, lane::PROOFS);
        let done = rewrite(&seam, common, false).await;
        let pinned = [(lane::PURL.to_string(), lane::UUID.to_string())];
        assert_eq!(
            done.confirmed, pinned,
            "{project}: {:?}",
            done.rewrite.warnings
        );
        assert!(engine::guard(&ProjectView::Disk(&common.cwd), &done, &candidates()).is_none());
        // The project's own commit, as the command makes it: the files
        // of the rewrite through the group, then the group.
        let project_commit = async {
            for (rel, text) in &done.rewrite.files {
                let path = below(&common.cwd, rel);
                socket_patch_core::utils::fs::atomic_write_bytes_preserving_mode(
                    &path,
                    text.as_bytes(),
                )
                .await
                .map_err(|e| format!("failed to write {rel}: {e}"))?;
            }
            group.commit().await.map(drop).map_err(|e| e.to_string())
        };
        assert_eq!(
            seam.commit(&done, project_commit).await,
            Ok(()),
            "{project}"
        );
        let landed = std::fs::read_to_string(&lock_path).expect("the lock");
        assert_eq!(
            landed,
            reverted.replace(lane::UPSTREAM, &lane::pinned()),
            "{project}"
        );
        let index = checkout.get(INDEX_PATH).expect("the index");
        assert!(matches!(
            owned_index::parse(index.as_bytes()),
            Parsed::Ours(_)
        ));
        assert!(
            below(&common.cwd, "pnpm-workspace.yaml").is_file(),
            "{project}"
        );
    }
}

// ── A command that has to run for a plan ─────────────────────────────

/// A tool runner that fails every command it is handed.
struct Fails;

impl ToolRunner for Fails {
    fn run(&self, _: &Path, _: &RunRequired) -> RunResult {
        RunResult::Failed("exit 2".to_string())
    }
}

/// The outcome of the gate for a plan whose command socket-patch runs
/// itself: what a run policy that allows tool runs makes of the plan in
/// `done`. No policy of this release does, so the tests of the unwind
/// write the outcome in.
fn needs_a_run(done: &mut Rewritten) {
    let bazel = done.bazel.as_mut().expect("the Bazel group ran");
    for patch in &mut bazel.group.decided {
        let GateOutcome::Proceed(plan) = &patch.outcome else {
            continue;
        };
        let run = RunRequired {
            kind: RunKind::ALL[0],
            command: "bazel mod deps --lockfile_mode=update".to_string(),
            argv: vec!["bazel".to_string(), "mod".to_string(), "deps".to_string()],
            env: Vec::new(),
            outputs: vec!["MODULE.bazel.lock".to_string()],
            interim: Interim::ALL[0],
            actor: Actor::SocketPatch,
            platforms: Vec::new(),
            gates_vex: true,
        };
        patch.outcome = GateOutcome::ProceedAfter(plan.clone(), run);
    }
}

/// A command that fails behind the pin unwinds the whole run: the pin,
/// its record and the install-policy file are taken back, the project's
/// own commit is never started, and the error says that nothing was
/// changed, which is then true. With the runner of this release the same
/// outcome lands: the command is left to the user.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_command_unwinds_the_whole_run() {
    for project in ["", "svc/app"] {
        let checkout = Checkout::new(project, true);
        let common = &checkout.common;
        let before = snapshot(&checkout.root);
        let seam = Hosted::new(common, lane::TABLE, lane::PROOFS).with_runner(Fails);
        let mut done = rewrite(&seam, common, false).await;
        assert!(staged(&done), "{project}");
        needs_a_run(&mut done);
        let ran = std::cell::Cell::new(false);
        let project_commit = async {
            ran.set(true);
            Ok(())
        };
        let failed = seam.commit(&done, project_commit).await.unwrap_err();
        assert!(failed.contains("`bazel mod deps --lockfile_mode=update` failed: exit 2"));
        assert!(failed.ends_with("(nothing was changed)"), "{failed}");
        assert!(
            !ran.get(),
            "{project}: the project's commit was never started"
        );
        assert_same_tree(&before, &snapshot(&checkout.root));

        let shipped = Hosted::new(common, lane::TABLE, lane::PROOFS);
        let mut done = rewrite(&shipped, common, false).await;
        needs_a_run(&mut done);
        assert_eq!(shipped.commit(&done, native(common, &done)).await, Ok(()));
        assert!(checkout.get(INDEX_PATH).is_some(), "{project}");
    }
}

// ── The command itself, over a lane that plans ───────────────────────

fn api_client(api: &MockServer) -> ApiClient {
    ApiClient::new(ApiClientOptions {
        api_url: api.uri(),
        api_token: Some("fake-token".to_string()),
        route: ApiRoute::org(ORG),
    })
}

/// The arguments of a hosted run of the command over `checkout`: quiet,
/// with no telemetry and no prompt.
fn command_args(checkout: &Checkout, api: &MockServer) -> GlobalArgs {
    GlobalArgs {
        silent: true,
        yes: true,
        no_telemetry: true,
        api_url: Some(api.uri()),
        api_token: Some("fake-token".to_string()),
        org: Some(ORG.to_string()),
        ..checkout.common.clone()
    }
}

/// `get --mode hosted` in process, through the command's own code, over
/// a lane that plans: its commit of a staged change set (the real project
/// commit, with its open group commit and the project lock), its report
/// and its in-run statement are lines that the built binary, whose lanes
/// are all disabled, never runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_command_lands_a_lanes_plan_through_its_own_commit() {
    let api = MockServer::start().await;
    mount_api(&api, &[patch()]).await;
    let selected = [(lane::PURL.to_string(), lane::UUID.to_string())];
    let no_vex = VexEmbedArgs::default();
    for project in ["", "svc/app"] {
        let at = |name: &str| match project {
            "" => name.to_string(),
            project => format!("{project}/{name}"),
        };
        let checkout = Checkout::new(project, true);
        let common = command_args(&checkout, &api);
        let client = api_client(&api);
        let before = snapshot(&checkout.root);
        let seam = Hosted::new(&common, lane::TABLE, lane::PROOFS);
        let code = run_command(&seam, &common, &no_vex, &client, &selected).await;
        assert_eq!(code, 0, "{project}");
        let after = snapshot(&checkout.root);
        let wrote: Vec<String> = changes(&before, &after)
            .into_iter()
            .map(|(path, _)| path)
            .filter(|path| below(&checkout.root, path).is_file())
            .collect();
        let mut expected = vec![
            INDEX_PATH.to_string(),
            at(lane::LOCK),
            at("pnpm-workspace.yaml"),
        ];
        expected.sort();
        assert_eq!(wrote, expected, "{project}");
        assert_write_policy(&before, &after);
        assert_eq!(checkout.get(&at(".npmrc")), None, "{project}: no `.npmrc`");
        let lock = checkout.get(&at(lane::LOCK)).expect("the lock");
        assert_eq!(
            lock,
            lane::LOCK_TEXT.replace(lane::UPSTREAM, &lane::pinned())
        );
        let index = checkout.get(INDEX_PATH).expect("the index");
        let Parsed::Ours(index) = owned_index::parse(index.as_bytes()) else {
            panic!("not the index socket-patch writes");
        };
        let rows: Vec<(&str, &str)> = index
            .pins
            .iter()
            .map(|row| (row.uuid.as_str(), row.file.as_str()))
            .collect();
        assert_eq!(rows, [(lane::UUID, at(lane::LOCK).as_str())], "{project}");
        // Neither lock file nor journal is left, at the root or in the
        // project.
        let owned = below(&checkout.root, INDEX_PATH);
        let owned = owned.parent().expect("the owned directory");
        let left: Vec<String> = std::fs::read_dir(owned)
            .expect("the owned directory")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(left, ["index.json"], "{project}");

        // A second run of the command finds the pin and writes nothing.
        let again = Hosted::new(&common, lane::TABLE, lane::PROOFS);
        let code = run_command(&again, &common, &no_vex, &client, &selected).await;
        assert_eq!(code, 0, "{project}");
        assert_same_tree(&after, &snapshot(&checkout.root));
    }
}

/// The command's commit when the Bazel root cannot be locked (another
/// run holds it past the wait): exit 1, and nothing of the run is on
/// disk, the project's own files included. The project's commit, with its
/// open group commit, was never started.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_command_writes_nothing_when_the_root_cannot_be_locked() {
    use socket_patch_core::utils::bazel_root_writes::lock_root_blocking;
    let api = MockServer::start().await;
    mount_api(&api, &[patch()]).await;
    let selected = [(lane::PURL.to_string(), lane::UUID.to_string())];
    let checkout = Checkout::new("svc/app", true);
    let common = command_args(&checkout, &api);
    let client = api_client(&api);
    let before = snapshot(&checkout.root);
    let held = lock_root_blocking(&checkout.root, std::time::Duration::ZERO).expect("free");
    let seam = Hosted::new(&common, lane::TABLE, lane::PROOFS);
    let code = run_command(&seam, &common, &VexEmbedArgs::default(), &client, &selected).await;
    assert_eq!(code, 1, "the pins were not written");
    drop(held);
    assert_same_tree(&before, &snapshot(&checkout.root));
}

/// The in-run statement of the command, through `--vex`: a lane that
/// leaves the pin to the native lock records no digest, so the statement
/// stands on the grant this run holds, which the command hands over with
/// the seam's part of its parameters. The same command with the seam's
/// statement judged over a table that does not know the lane has nothing
/// to hold the pin to, and says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_commands_in_run_statement_attests_a_pin_this_run_confirmed() {
    let api = MockServer::start().await;
    mount_api(&api, &[patch()]).await;
    let selected = [(lane::PURL.to_string(), lane::UUID.to_string())];
    for attested in [true, false] {
        let checkout = Checkout::new("", true);
        let common = command_args(&checkout, &api);
        let client = api_client(&api);
        let out = checkout.root.join("vex.json");
        let vex = VexEmbedArgs {
            vex: Some(out.clone()),
            vex_product: Some("pkg:generic/app@1.0.0".to_string()),
            ..VexEmbedArgs::default()
        };
        let seam = Hosted::new(&common, lane::NATIVE, lane::PROOFS);
        let seam = match attested {
            true => seam.attesting(&lane::NATIVE),
            false => seam,
        };
        let code = run_command(&seam, &common, &vex, &client, &selected).await;
        let lock = checkout.get(lane::LOCK).expect("the lock");
        assert!(lock.contains(lane::URL), "the native rewriter pinned it");
        assert_eq!(
            checkout.get(".npmrc"),
            None,
            "no `.npmrc` beside a governed lock"
        );
        let document = std::fs::read_to_string(&out).ok();
        match attested {
            true => {
                assert_eq!(code, 0, "the statement was made");
                let document: Value =
                    serde_json::from_str(&document.expect("the document")).expect("JSON");
                let statements = document["statements"].as_array().expect("statements");
                assert_eq!(statements.len(), 1, "{document:#}");
            }
            false => {
                assert_ne!(code, 0, "nothing holds the pin to a digest");
                assert_eq!(document, None, "no document was written");
            }
        }
    }
}

// ── Two projects of one root ─────────────────────────────────────────

/// ROUTED R-137: a second project of the root plans on the index as the
/// first project's commit left it. Each project's hub reads its own lock;
/// the first run pins its lock and records it, and the second, with a
/// seam of its own, adds its row beside the first, captures the first
/// project's recorded file without writing it, and leaves that lock byte
/// for byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_project_of_the_root_plans_on_the_index_the_first_left() {
    let tmp = tempfile::tempdir().expect("a temporary directory");
    let root = std::fs::canonicalize(tmp.path()).expect("its real path");
    let put = |rel: &str, text: &str| {
        let path = below(&root, rel);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(path, text).expect("write");
    };
    put(".git/HEAD", "ref: refs/heads/main\n");
    put(".bazelversion", lane::BAZELVERSION);
    put("MODULE.bazel", lane::TWO_HUBS);
    let manifest = r#"{"name": "p", "version": "0.0.0", "dependencies": {"left-pad": "1.3.0"}}"#;
    for project in ["svc/a", "svc/b"] {
        put(&format!("{project}/BUILD.bazel"), "");
        put(&format!("{project}/package.json"), manifest);
        put(&format!("{project}/{}", lane::LOCK), lane::LOCK_TEXT);
    }
    let common = |project: &str| GlobalArgs {
        cwd: below(&root, project),
        ..GlobalArgs::default()
    };
    let pinned = [(lane::PURL.to_string(), lane::UUID.to_string())];
    let lock_of = |project: &str| {
        std::fs::read_to_string(below(&root, &format!("{project}/{}", lane::LOCK))).expect("lock")
    };

    let first = common("svc/a");
    let seam = Hosted::new(&first, lane::TABLE, lane::PROOFS);
    let done = rewrite(&seam, &first, false).await;
    assert_eq!(done.confirmed, pinned, "{:?}", done.rewrite.warnings);
    assert_eq!(seam.commit(&done, native(&first, &done)).await, Ok(()));
    let a_pinned = lock_of("svc/a");
    assert_eq!(
        a_pinned,
        lane::LOCK_TEXT.replace(lane::UPSTREAM, &lane::pinned())
    );
    assert_eq!(
        lock_of("svc/b"),
        lane::LOCK_TEXT,
        "the other project is untouched"
    );

    // The second project, with a seam (and a loader) of its own.
    let second = common("svc/b");
    let seam = Hosted::new(&second, lane::TABLE, lane::PROOFS);
    let done = rewrite(&seam, &second, false).await;
    assert_eq!(done.confirmed, pinned, "{:?}", done.rewrite.warnings);
    let bazel = done.bazel.as_ref().expect("the Bazel group ran");
    let captured = |rel: &str| bazel.touched.iter().any(|path| path == rel);
    assert!(
        captured("svc/a/pnpm-lock.yaml"),
        "the first row's file: {:?}",
        bazel.touched
    );
    assert!(captured("svc/b/pnpm-lock.yaml") && captured(INDEX_PATH));
    let written: Vec<&str> = bazel
        .changes
        .iter()
        .map(|change| change.rel.as_str())
        .collect();
    assert!(!written.contains(&"svc/a/pnpm-lock.yaml"), "{written:?}");
    assert_eq!(seam.commit(&done, native(&second, &done)).await, Ok(()));
    assert_eq!(lock_of("svc/a"), a_pinned, "byte for byte");
    assert_eq!(lock_of("svc/b"), a_pinned);
    let index = std::fs::read(below(&root, INDEX_PATH)).expect("the index");
    let Parsed::Ours(index) = owned_index::parse(&index) else {
        panic!("not the index socket-patch writes");
    };
    let mut rows: Vec<&str> = index.pins.iter().map(|row| row.file.as_str()).collect();
    rows.sort();
    assert_eq!(rows, ["svc/a/pnpm-lock.yaml", "svc/b/pnpm-lock.yaml"]);

    // And the first project again: both pins are in place, nothing moves.
    let seam = Hosted::new(&first, lane::TABLE, lane::PROOFS);
    let done = rewrite(&seam, &first, false).await;
    assert_eq!(done.confirmed, pinned, "{:?}", done.rewrite.warnings);
    assert!(!staged(&done), "{:?}", done.bazel);
}

// ── A commit an interrupted run left at the root ─────────────────────

/// A dry run takes no lock, so nobody has finished a commit that an
/// interrupted run left journaled at the Bazel root: the files it names
/// may be half replaced. The dry run says so, with the journal and its
/// files, for each governed patch, and writes nothing; the run that
/// follows finishes the commit as it takes the project's lock, says what
/// it rolled forward, and decides from the finished files.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dry_run_reports_a_commit_an_interrupted_run_left_at_the_root() {
    let api = MockServer::start().await;
    mount_api(&api, &[patch()]).await;
    let project = "svc/app";
    let mut files = files(project, true);
    let journal = json!({
        "version": 1,
        "files": [{ "path": "svc/app/notes.lock", "before": null, "after": "bm90ZXMK" }],
    });
    files.insert(
        ROOT_JOURNAL_REL.to_string(),
        journal.to_string().into_bytes(),
    );

    let dry = run_disk_in(&api, &files, project, true);
    assert_eq!(dry.changed, BTreeMap::new(), "{:#}", dry.envelope);
    let event = event_for(&dry.envelope, lane::PURL);
    assert_eq!(event["action"], "skipped", "{:#}", dry.envelope);
    let reason = event["reason"].as_str().unwrap_or_default();
    assert!(reason.contains(".commit-journal.json"), "{event:#}");
    assert!(reason.contains("svc/app/notes.lock"), "{event:#}");
    assert!(reason.ends_with("nothing was written"), "{event:#}");

    if admitted(project) {
        return;
    }
    let wet = run_disk_in(&api, &files, project, false);
    let changed: Vec<&String> = wet.changed.keys().collect();
    assert_eq!(changed, ["svc/app/notes.lock"], "{:#}", wet.envelope);
    assert!(wet.stderr.contains("svc/app/notes.lock"), "{}", wet.stderr);
    let event = event_for(&wet.envelope, lane::PURL);
    let refusal = Code::refusal(Mode::Hosted, Reason::RulesetUnsupported).expect("a code");
    assert_eq!(event["errorCode"], refusal.as_str(), "{:#}", wet.envelope);
}

/// The same journal under the seam in process: once the project's lock
/// has finished the commit, the lane decides from the finished files and
/// pins.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finished_commit_is_decided_from_again() {
    let checkout = Checkout::new("svc/app", true);
    let journal = json!({
        "version": 1,
        "files": [{ "path": "svc/app/notes.lock", "before": null, "after": "bm90ZXMK" }],
    });
    checkout.put(ROOT_JOURNAL_REL, journal.to_string());
    let common = &checkout.common;
    let seam = Hosted::new(common, lane::TABLE, lane::PROOFS);
    let done = rewrite(&seam, common, true).await;
    assert_eq!(
        done.confirmed,
        Vec::new(),
        "nothing is decided over a pending commit"
    );
    assert!(!staged(&done));

    let socket_dir = common.cwd.join(".socket");
    let guard = apply_lock::acquire(&socket_dir, std::time::Duration::ZERO).expect("the lock");
    let replayed = guard.commit_recovery().expect("the replay is reported");
    assert!(
        replayed.detail.contains("svc/app/notes.lock"),
        "{}",
        replayed.detail
    );
    let seam = Hosted::new(common, lane::TABLE, lane::PROOFS);
    let done = rewrite(&seam, common, false).await;
    let pinned = [(lane::PURL.to_string(), lane::UUID.to_string())];
    assert_eq!(done.confirmed, pinned, "{:?}", done.rewrite.warnings);
    assert_eq!(seam.commit(&done, native(common, &done)).await, Ok(()));
    drop(guard);
    assert_eq!(
        checkout.get("svc/app/notes.lock").as_deref(),
        Some("notes\n")
    );
}

/// The project lock and a commit above it, through the binary's `apply`.
/// A journal that cannot be finished (a level of a path it names is a
/// file) stops the command of a project it names a file of, and of no
/// other: a sibling project's `apply` says it once and goes on, with the
/// exit code it would have had. And a journal that lies in a checkout with
/// no Bazel file is no commit of socket-patch's: it is neither replayed
/// nor mentioned, and no file it names is written.
#[test]
fn apply_goes_on_beside_a_commit_it_cannot_finish_and_replays_none_outside_a_bazel_root() {
    let manifest = r#"{"patches": {}}"#;
    let journal = |files: &[&str]| {
        let file = |path: &&str| json!({ "path": path, "before": null, "after": "bm90ZXMK" });
        let files: Vec<Value> = files.iter().map(file).collect();
        json!({ "version": 1, "files": files }).to_string()
    };
    let apply = |project: &Path| {
        let cwd = project.to_str().expect("a UTF-8 path");
        crate::common::run(project, &["apply", "--cwd", cwd])
    };

    // Under a Bazel root, a journal nobody can finish.
    let checkout = Checkout::new("svc/api", true);
    checkout.put("blocked", "a file where the journal names a directory");
    // The path that cannot be written comes first: where a system only
    // finds that out at the write, nothing was written before it.
    let named = ["blocked/notes.lock", "svc/api/notes.lock"];
    checkout.put(ROOT_JOURNAL_REL, journal(&named));
    for project in ["svc/api", "svc/other"] {
        checkout.put(&format!("{project}/.socket/manifest.json"), manifest);
    }
    let before = snapshot(&checkout.root);
    let (code, _, stderr) = apply(&below(&checkout.root, "svc/other"));
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.contains("is not finished"), "{stderr}");
    assert!(stderr.contains("blocked/notes.lock"), "{stderr}");
    assert_eq!(
        stderr.matches("Warning: an interrupted run").count(),
        1,
        "{stderr}"
    );
    assert_same_tree(&before, &snapshot(&checkout.root));
    // The project the journal names a file of does not go on over it.
    let (code, _, stderr) = apply(&below(&checkout.root, "svc/api"));
    assert_ne!(code, 0, "{stderr}");
    assert_same_tree(&before, &snapshot(&checkout.root));

    // The same journal in a checkout that is no Bazel workspace.
    let plain = Checkout::new("svc/app", false);
    plain.put(
        ROOT_JOURNAL_REL,
        journal(&["README.md", "svc/app/package.json"]),
    );
    plain.put("svc/app/.socket/manifest.json", manifest);
    let before = snapshot(&plain.root);
    let (code, _, stderr) = apply(&below(&plain.root, "svc/app"));
    assert_eq!(code, 0, "{stderr}");
    assert!(!stderr.contains("interrupted"), "{stderr}");
    assert_same_tree(&before, &snapshot(&plain.root));
    assert_eq!(plain.get("README.md"), None);
}
