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
use socket_patch_cli::bazel_gate::hosted::{assumed, grants, staged, Hosted};
use socket_patch_cli::json_envelope::{Command, Envelope, PatchAction, PatchEvent};
use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::lanes::{self, Cell};
use socket_patch_core::bazel::model::{HubId, Mode, Reason, RootRef};
use socket_patch_core::bazel::owned_index::{self, Parsed, INDEX_PATH};
use socket_patch_core::crawlers::bazel_workspace::{read_workspace, DiskView};
use socket_patch_core::formats::cargo::source_replacement::CratesIoSource;
use socket_patch_core::hosted::bazel_reads::BAZEL_WORKSPACE_KEY;
use socket_patch_core::hosted::engine::{self, Candidate, RewriteOptions, Rewritten};
use socket_patch_core::patch::redirect::npmrc::OuterAllowRemote;
use socket_patch_core::patch::redirect::yarnrc::OuterYarnMirror;
use socket_patch_core::vendor::lock_inventory::ProjectView;
use wiremock::MockServer;

use crate::bazel_common::{assert_same_tree, assert_write_policy, changes, snapshot};
use crate::common::envelope::{all_codes, event_for};
use hosted_memory_common::{mount_api, run_disk_in, Patch};

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
    let mut files = files("", true);
    let pinned = lane::LOCK_TEXT.replace(lane::UPSTREAM, &lane::native_pin());
    files.insert(lane::LOCK.to_string(), pinned.into_bytes());
    let npm = lane::NPM_LOCK_TEXT
        .replace(
            "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            lane::URL,
        )
        .replace(lane::UPSTREAM_SRI, lane::PATCHED);
    files.insert("package-lock.json".to_string(), npm.into_bytes());

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

/// A Bazel root whose `.socket` is a link belongs to another project. A
/// run that finds it so cannot rely on the index behind the link: it
/// refuses the patch and stages nothing, in a run and in its dry run. A
/// link that appears between the decision and the commit is refused by
/// the guard, and by the root's lock for a caller that committed all the
/// same. Nothing is created behind the link either way.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_linked_socket_directory_at_the_root_gets_no_write() {
    let other = tempfile::tempdir().expect("another project");
    let link = |checkout: &Checkout| {
        std::os::unix::fs::symlink(other.path(), checkout.root.join(".socket")).expect("a link");
    };

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
