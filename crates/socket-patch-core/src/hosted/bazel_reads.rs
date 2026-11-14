//! The hosted engine's Bazel reads (design 2.7 and 7, principle P7;
//! revision 4, sections 4 and 5): what the engine is handed about the
//! Bazel root above a project, and what it does with the answer.
//!
//! Where a Bazel ruleset governs an ecosystem of a project, the lock Bazel
//! builds from is the one a hub names: a label-addressed requirements file
//! in any package, a `maven_install.json`, the `pnpm-lock.yaml` beside a
//! `package-lock.json` nobody reads. The engine cannot know that file set
//! from names, so it does not try: it is handed the root ([`BazelReads`],
//! on [`CandidateFiles::bazel`](super::engine::CandidateFiles::bazel), the
//! way the sbt evidence rides the candidate files) and puts the Bazel
//! rewriter group in front of the native rewriters ([`rewrite`]). The
//! group reads the root through the view it is handed, lazily: every file
//! a hub names, the paired manifests, the Bazel-only locks, and the owned
//! directory `.socket/bazel/` beside them. No selection is made here that
//! a lane could outgrow.
//!
//! What the engine's own steps then leave alone ([`BazelDone`]):
//!
//! - **A decided patch is the Bazel group's.** Confirmed or refused, it is
//!   withheld from every step of the engine that writes for a patch: the
//!   binary Bun lock, the npm install-policy configs, the stale-install
//!   hints. Its confirmation is the group's report and nothing else.
//! - **No `.npmrc`.** A new `.npmrc` beside a lock a hub reads fails
//!   rules_js 3.x (`Undeclared .npmrc file`), so none is created or edited
//!   for a governed patch, whether the patch was written or refused.
//! - **`pnpm-workspace.yaml` as native hosted mode writes it**, for a
//!   patch the group confirmed and where no hub names the file (owner
//!   decision O14, [`creates_pnpm_workspace`]). A file a hub names is a
//!   recorded input of the build, and only the group's plan may write it.
//! - **No native write at an owned path, in a hook file, or in a file a
//!   hub names** ([`BazelDone::withhold_native_writes`]): no native
//!   rewriter is handed such a file's patch, and this is the tripwire
//!   behind that.
//!
//! # The view
//!
//! A [`Root`] hands the gate the files of the root as they are now. On
//! disk that is `crawlers::bazel_workspace::DiskView`, and three rules of
//! `FileView::list` matter to the recognizers that read through it (ROUTED
//! R-095). A directory that is not there lists as `Some` of an empty list:
//! `None` means "could not be listed", and an `update_pnpm_lock` hub
//! before its first build would read as one whose hash file cannot be
//! located. A link into a tree Bazel owns is a bare name, never a
//! directory, so no scan walks an output base. And the directory a lock
//! really lies in, where a label reaches it through a link, is known only
//! to a model read by `crawlers::bazel_workspace::read_workspace`
//! (`BazelWorkspace::lock_real_dirs`): a `Root` hands over such a model.
//!
//! A [`ProjectView::Memory`](crate::vendor::lock_inventory::ProjectView)
//! has no Bazel reads. The in-memory engine leaves every ecosystem a
//! ruleset governs, or may govern, alone before it gets here
//! (`hosted::memory`), because the files it is streamed cannot answer the
//! gate, and its own view lists no directory at all.
//!
//! Nothing here touches a disk: the caller makes the view and lands the
//! change set ([`BazelDone::changes`]) in a commit anchored at the root.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use crate::bazel::codes::Code;
use crate::bazel::exec;
use crate::bazel::inventory::may_build;
use crate::bazel::model::{FileText, GateOutcome, HookKind, Mode, Refusal};
use crate::bazel::owned_index::OWNED_DIR;
use crate::crawlers::types::Ecosystem;
use crate::patch::redirect::bazel::{BazelHost, BazelRewrite, Decided, Refused, Verdict};
use crate::patch::redirect::{full_name, DepOverride, RewriteResult, RewriteWarning};
use crate::utils::group_commit::AnchoredChange;

use super::guidance::PNPM_WORKSPACE_REL;

/// The synthetic candidate key a project under a Bazel root carries (see
/// [`BazelReads::marker`]). Like the sbt evidence key it is no path on any
/// system, so it never collides with a project file, and the engine keeps
/// it out of the symlink and unreadable refusals, the confirmation probe
/// and the writes (`patch::redirect::sbt::is_synthetic_key`).
pub const BAZEL_WORKSPACE_KEY: &str = "<socket-patch:bazel-workspace>";

/// Owner decision O14, defaulted: under a governed pnpm lock that a lane
/// pinned, `pnpm-workspace.yaml` is created or extended exactly as native
/// hosted mode does it (every executed probe cell had the created file,
/// rules_js 2.9.3 - 4.0.0-alpha.1 read and merge it, and without
/// `trustLockfile` a pnpm 11 outside Bazel rejects the lock). The one
/// place to flip: `false` leaves the file alone and says so
/// (`redirect_bazel_side_file_skipped`).
pub const fn creates_pnpm_workspace() -> bool {
    true
}

/// What can be asked about the Bazel root above a project.
pub enum Asked<'a> {
    /// The gate decides each patch: the question the rewriter group asks
    /// it with, over the files of the root as they are now.
    Gate(BazelHost<'a>),
    /// No gate can be asked: no boundary file of the root could be read,
    /// the root lies above the repository, or the owned index cannot be
    /// relied on. Each ecosystem that a ruleset governs or may govern
    /// there, with the refusal of its patches. An ecosystem that is not
    /// listed is one Bazel does not govern, and its patches are the
    /// native rewriters'.
    Unasked(Vec<(Ecosystem, Refusal)>),
}

/// The Bazel root above a project, as whoever read it hands it to the
/// engine (the CLI's loader; a test's fixture). `Send + Sync`: the engine
/// runs its rewriters on the blocking pool.
pub trait Root: Send + Sync {
    /// The question for the root as it is now. Called once per rewrite
    /// pass; the answers of one value must agree, since a later pass
    /// writes the earlier one's patches again from the start.
    fn ask(&self) -> Asked<'_>;

    /// The root, resolved, and the project's directory relative to it
    /// (forward slashes, `""` at the root). `None` where no root inside
    /// the repository was read.
    fn place(&self) -> Option<(PathBuf, String)>;
}

/// The Bazel reads of one project: `None` on
/// [`CandidateFiles::bazel`](super::engine::CandidateFiles::bazel) for a
/// project under no Bazel root, which is then rewritten exactly as it
/// always was.
#[derive(Clone)]
pub struct BazelReads(Arc<dyn Root>);

impl BazelReads {
    pub fn new(root: impl Root + 'static) -> Self {
        Self(Arc::new(root))
    }

    /// The value of [`BAZEL_WORKSPACE_KEY`] among the candidate texts: the
    /// root and the project's place under it, one per line. It is there
    /// for whoever reads the candidate texts of a rewrite (a test, a
    /// debug dump) to see that the Bazel group ran in front; no rewriter
    /// reads it.
    pub fn marker(&self) -> String {
        match self.0.place() {
            Some((root, project_rel)) => format!("{}\n{project_rel}", root.display()),
            None => String::new(),
        }
    }
}

impl std::fmt::Debug for BazelReads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BazelReads").field(&self.0.place()).finish()
    }
}

/// What the Bazel rewriter group decided and staged in one rewrite of a
/// project, for the engine's own steps and for the caller that commits.
#[derive(Debug, Clone, Default)]
pub struct BazelDone {
    /// The Bazel root, resolved. Empty where no root was read
    /// ([`Asked::Unasked`]): nothing is staged then.
    pub root: PathBuf,
    /// The project relative to [`Self::root`], `""` at the root.
    pub project_rel: String,
    /// The typed outcome of each patch the group decided, its plans and
    /// the owned index as the change set leaves it.
    pub group: BazelRewrite,
    /// The change set as `utils::group_commit::commit_anchored` lands it
    /// at [`Self::root`]: each path with the bytes the transaction read
    /// there. Empty when every lane is disabled.
    pub changes: Vec<AnchoredChange>,
    /// The paths that commit may write: `bazel::exec::touched` for the
    /// plans of the confirmed patches.
    pub touched: Vec<String>,
    /// A changed path whose bytes the root's view could not give: nothing
    /// can be compared at commit, so the run refuses before any write.
    pub unreadable: Vec<String>,
    /// The files a hub that Bazel may build from names, relative to the
    /// root: locks, derived values, configs.
    named: BTreeSet<String>,
    governed: BTreeSet<String>,
}

/// The ecosystem of a grant, as the rewriter group reads it.
fn ecosystem_of(dep: &DepOverride) -> Option<Ecosystem> {
    Ecosystem::from_purl(&format!("pkg:{}/", dep.ecosystem))
}

fn warning(code: Code, detail: String) -> RewriteWarning {
    let code = code.as_str().to_string();
    RewriteWarning { code, detail }
}

impl BazelDone {
    fn of(host: &BazelHost<'_>, group: BazelRewrite) -> Self {
        let (ws, base) = (host.cx.ws, host.cx.files);
        let (mut changes, mut unreadable) = (Vec::new(), Vec::new());
        for (rel, write) in &group.changes {
            let read = match base.read(rel) {
                FileText::Bytes(bytes) => Some(bytes),
                FileText::Absent => None,
                FileText::Unreadable => {
                    unreadable.push(rel.clone());
                    None
                }
            };
            changes.push(AnchoredChange {
                rel: rel.clone(),
                read,
                write: write.clone(),
            });
        }
        // The record lands before what it records where both are new: a
        // row without its edit is dropped by the next removal, and an
        // edit without its row would stay for good.
        changes.sort_by_key(|change| !change.rel.starts_with(OWNED_DIR));
        // The rows a sweep undid are in the index as it was read, the
        // rows of this run in the one the change set leaves.
        let mut touched = exec::touched(host.cx.index, &group.plans);
        touched.extend(exec::touched(&group.index, &group.plans));
        touched.sort();
        touched.dedup();
        let hubs = ws.hubs.iter().filter(|hub| may_build(hub));
        let named = hubs.flat_map(|hub| hub.locks.iter().filter_map(|lock| lock.path.clone()));
        Self {
            root: ws.root.root.clone(),
            project_rel: ws.root.project_rel.clone(),
            governed: group.governed(),
            named: named.collect(),
            group,
            changes,
            touched,
            unreadable,
        }
    }

    /// The patches the Bazel group decided, confirmed or refused: no step
    /// of the engine acts on one.
    pub fn governed(&self) -> &BTreeSet<String> {
        &self.governed
    }

    /// The decision of patch `uuid`, if the group made one.
    pub fn decided(&self, uuid: &str) -> Option<&Decided> {
        self.group.decided.iter().find(|patch| patch.uuid == uuid)
    }

    /// Whether the group pinned patch `uuid` (in this run or an earlier
    /// one) in every lock a governing hub reads for the package.
    pub fn confirmed(&self, uuid: &str) -> bool {
        self.decided(uuid)
            .is_some_and(|patch| patch.verdict == Verdict::Confirmed)
    }

    /// The overrides the engine's own steps may act on: every one the
    /// Bazel group left to the native rewriters.
    pub(crate) fn native(&self, overrides: &[DepOverride]) -> Vec<DepOverride> {
        let own = |dep: &&DepOverride| !self.governed.contains(&dep.patch_uuid);
        overrides.iter().filter(own).cloned().collect()
    }

    /// The overrides of the pnpm `trustLockfile` step: the native ones,
    /// and under decision O14 the npm patches the group confirmed, whose
    /// lock pnpm installs from with the same policy outside Bazel.
    pub(crate) fn trust_overrides(&self, overrides: &[DepOverride]) -> Vec<DepOverride> {
        let takes = |dep: &&DepOverride| {
            !self.governed.contains(&dep.patch_uuid)
                || (creates_pnpm_workspace()
                    && dep.ecosystem == "npm"
                    && self.confirmed(&dep.patch_uuid))
        };
        overrides.iter().filter(takes).cloned().collect()
    }

    fn below(&self) -> String {
        match self.project_rel.as_str() {
            "" => String::new(),
            project => format!("{project}/"),
        }
    }

    /// The root-relative path of the project file `rel`.
    fn rooted(&self, rel: &str) -> String {
        format!("{}{rel}", self.below())
    }

    /// A root-relative path as it is spelled from the project: a file of
    /// the project by its own name, a file above it with one `..` for
    /// each level the project lies below the root.
    fn spelled(&self, rel: &str) -> String {
        match rel.strip_prefix(&self.below()) {
            Some(own) if !self.project_rel.is_empty() => own.to_string(),
            _ if self.project_rel.is_empty() => rel.to_string(),
            _ => {
                let up = self.project_rel.split('/').map(|_| "..");
                let up: Vec<&str> = up.collect();
                format!("{}/{rel}", up.join("/"))
            }
        }
    }

    /// The text files the group wrote in the project, by their name in
    /// the project: what the pnpm `trustLockfile` step reads as locks
    /// spliced in this run.
    pub(crate) fn project_texts(&self) -> BTreeMap<String, String> {
        let below = self.below();
        let own = |change: &AnchoredChange| {
            let name = change.rel.strip_prefix(&below)?;
            let text = String::from_utf8(change.write.clone()?).ok()?;
            Some((name.to_string(), text))
        };
        self.changes.iter().filter_map(own).collect()
    }

    /// Every file the commit of the change set writes, as it is spelled
    /// from the project.
    pub fn rewritten(&self) -> Vec<String> {
        let spelled = |change: &AnchoredChange| self.spelled(&change.rel);
        self.changes.iter().map(spelled).collect()
    }

    /// Whether the engine's own writer has to leave the project file
    /// `rel` alone, and what the run says then: `rel` is one of the two
    /// install-policy files native hosted mode creates or extends,
    /// `.npmrc` and `pnpm-workspace.yaml` (the module docs).
    pub(crate) fn withholds(&self, rel: &str, npm_governed: bool) -> Option<RewriteWarning> {
        let named = self.named.contains(&self.rooted(rel));
        let kept = match rel {
            PNPM_WORKSPACE_REL => named || !creates_pnpm_workspace(),
            _ => named || npm_governed,
        };
        kept.then(|| {
            let why = match named {
                true => {
                    "a Bazel ruleset names it as an input of the build, so only a write the \
                         Bazel gate planned may change it"
                }
                false => {
                    "a new or changed file there can fail the Bazel build that reads the \
                          lock beside it"
                }
            };
            let detail = format!("`{rel}` was left as found: {why}");
            warning(Code::RedirectSideFileSkipped, detail)
        })
    }

    /// Whether a patch of the npm ecosystem was decided by the Bazel
    /// group: no `.npmrc` is then created or edited in the project.
    pub(crate) fn governs_npm(&self) -> bool {
        let npm = |patch: &Decided| patch.ecosystem == Ecosystem::Npm;
        self.group.decided.iter().any(npm)
    }

    /// Takes out of `result` every file a native rewriter wrote where
    /// only the Bazel layer may write: under the owned directory, in a
    /// hook file of the root, and in a file a hub names. No native
    /// rewriter is handed a patch of a governed ecosystem, so this finds
    /// nothing; it is what holds if one ever is. Returns the paths it
    /// withheld, as the project spells them.
    pub(crate) fn withhold_native_writes(&self, result: &mut RewriteResult) -> Vec<String> {
        let hook_files = HookKind::ALL.iter().flat_map(|kind| kind.files());
        let hook_files: Vec<&str> = hook_files.copied().collect();
        let owned = format!("{OWNED_DIR}/");
        let blocked = |rel: &String| {
            let path = self.rooted(rel);
            path.starts_with(&owned)
                || hook_files.contains(&path.as_str())
                || self.named.contains(&path)
        };
        let texts = result.files.keys().filter(|rel| blocked(rel));
        let binaries = result.binary_files.keys().filter(|rel| blocked(rel));
        let withheld: Vec<String> = texts.chain(binaries).cloned().collect();
        for rel in &withheld {
            result.files.remove(rel);
            result.binary_files.remove(rel);
            result.edits.retain(|edit| edit.path != *rel);
        }
        withheld
    }
}

/// The refusal of a patch for which no gate could be asked, as the
/// rewriter group reports one of the gate's.
fn unasked(refusal: &Refusal) -> Refused {
    // Every reason has a hosted code (`Code::refusal`); the fallback is
    // never taken.
    let code = Code::refusal(Mode::Hosted, refusal.reason);
    Refused {
        code: code.unwrap_or(Code::RedirectRulesetUnsupported),
        token: refusal.token,
        detail: refusal.detail.clone(),
        snippet: refusal.snippet.clone(),
        lift: refusal.lift.clone(),
    }
}

/// The rewriters of one pass as [`rewrite`] runs them: over `overrides`,
/// with the Bazel rewriter group in front when a host is given
/// (`rewrite_registry_redirect_with_host_under_bazel`), else the native
/// rewriters alone.
pub(crate) type Rewriters<'a> =
    dyn Fn(&[DepOverride], Option<&BazelHost<'_>>) -> (RewriteResult, BazelRewrite) + 'a;

/// One rewrite pass of a project under a Bazel root.
///
/// Where the gate can be asked, the Bazel rewriter group decides every
/// patch of a governed ecosystem and the native rewriters get the rest.
/// Where it cannot, the patches of every ecosystem a ruleset governs or
/// may govern are refused here, with the refusal the root gives for it,
/// and the native rewriters get the rest all the same: an unreadable
/// workspace is never a reason to write a lock Bazel may read.
pub(crate) fn rewrite(
    reads: &BazelReads,
    overrides: &[DepOverride],
    rewriters: &Rewriters<'_>,
) -> (RewriteResult, BazelDone) {
    let refusals = match reads.0.ask() {
        Asked::Gate(host) => {
            let (mut result, group) = rewriters(overrides, Some(&host));
            let done = BazelDone::of(&host, group);
            for rel in done.withhold_native_writes(&mut result) {
                let detail = format!(
                    "`{rel}` was left as found: only a write the Bazel gate planned may change \
                     a file the Bazel build reads"
                );
                result
                    .warnings
                    .push(warning(Code::RedirectSideFileSkipped, detail));
            }
            return (result, done);
        }
        Asked::Unasked(refusals) => refusals,
    };
    let mut group = BazelRewrite::default();
    let mut said: Vec<RewriteWarning> = Vec::new();
    let mut native: Vec<DepOverride> = Vec::new();
    for dep in overrides {
        let ecosystem = ecosystem_of(dep);
        let refusal = refusals.iter().find(|(of, _)| Some(*of) == ecosystem);
        let Some((ecosystem, refusal)) = refusal else {
            native.push(dep.clone());
            continue;
        };
        // One patch can be granted as several artifacts: one decision.
        if group
            .decided
            .iter()
            .any(|known| known.uuid == dep.patch_uuid)
        {
            continue;
        }
        let refused = unasked(refusal);
        let mut lines = vec![warning(refused.code, refused.detail.clone())];
        let snippet = refused.snippet.clone();
        lines.extend(snippet.map(|text| warning(Code::RedirectManualSnippet, text)));
        for line in lines {
            if !said.contains(&line) {
                said.push(line);
            }
        }
        group.decided.push(Decided {
            uuid: dep.patch_uuid.clone(),
            ecosystem: *ecosystem,
            name: full_name(dep),
            version: dep.version.clone(),
            outcome: GateOutcome::Refuse(refusal.clone()),
            verdict: Verdict::Refused(refused),
        });
    }
    let (mut result, _) = rewriters(&native, None);
    // The Bazel layer's lines come first, as the group puts its own.
    said.append(&mut result.warnings);
    result.warnings = said;
    let governed = group.governed();
    result.refused_bazel_uuids.extend(governed.iter().cloned());
    let (root, project_rel) = reads.0.place().unwrap_or_default();
    let done = BazelDone {
        root,
        project_rel,
        group,
        governed,
        ..BazelDone::default()
    };
    (result, done)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::bazel::gate::{self, GateCx, Roots};
    use crate::bazel::lanes::{self, Proofs};
    use crate::bazel::model::{
        BazelWorkspace, Gap, Index, LaneTable, Lift, Probe, Reason, RootRef, RulesetDetail,
    };
    use crate::bazel::rulesets::rules_js::ActionCache;
    use crate::crawlers::bazel_workspace::{read_workspace, DiskView};
    use crate::hosted::engine::{
        read_candidate_files, rewrite as engine_rewrite, Candidate, RewriteOptions,
    };
    use crate::patch::redirect::npmrc::OuterAllowRemote;
    use crate::patch::redirect::yarnrc::OuterYarnMirror;
    use crate::patch::redirect::{rewrite_registry_redirect, Integrity};
    use crate::vendor::lock_inventory::ProjectView;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const PY_UUID: &str = "0a1b2c3d-0000-4000-8000-0000000000a1";
    const URL: &str = "https://patch.socket.dev/patch/npm/tok_fixture_4f1c/left-pad-1.3.0.tgz";
    const MODULE: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"2.9.3\")\n\
        npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
        npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\"HUB)\n\
        use_repo(npm, \"npm\")\n";
    const PNPM_LOCK: &str = "lockfileVersion: '9.0'\n\npackages:\n\n  left-pad@1.3.0:\n    \
        resolution: {integrity: sha512-upstream}\n\nsnapshots:\n\n  left-pad@1.3.0: {}\n";
    const NPM_LOCK: &str =
        "{\n  \"name\": \"p\",\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \
        \"node_modules/left-pad\": {\n      \"version\": \"1.3.0\",\n      \
        \"resolved\": \"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz\",\n      \
        \"integrity\": \"sha512-upstream\"\n    }\n  }\n}\n";

    /// A checkout in a temporary directory: `.git` bounds every upward
    /// walk.
    struct Checkout {
        _tmp: tempfile::TempDir,
        top: PathBuf,
    }

    impl Checkout {
        fn new(files: &[(&str, &str)]) -> Self {
            let tmp = tempfile::tempdir().expect("a temporary directory");
            let top = std::fs::canonicalize(tmp.path()).expect("its real path");
            let checkout = Self { _tmp: tmp, top };
            checkout.put(".git/HEAD", "ref: refs/heads/main\n");
            for (rel, text) in files {
                checkout.put(rel, text);
            }
            checkout
        }

        fn at(&self, rel: &str) -> PathBuf {
            let levels = rel.split('/').filter(|level| !level.is_empty());
            levels.fold(self.top.clone(), |at, level| at.join(level))
        }

        fn put(&self, rel: &str, text: &str) {
            let path = self.at(rel);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(path, text).expect("write");
        }

        fn root(&self, project_rel: &str) -> RootRef {
            RootRef {
                root: self.top.clone(),
                project_rel: project_rel.to_string(),
                boundary_levels: 0,
            }
        }
    }

    /// One root read from disk, as the CLI's loader hands one over: the
    /// model, the view it was read through and the owned index.
    struct DiskRoot {
        probe: Probe,
        models: Vec<Result<BazelWorkspace, Gap>>,
        view: DiskView,
        index: Index,
        lanes: LaneTable,
        proofs: Proofs,
    }

    impl DiskRoot {
        fn read(root: &RootRef) -> Self {
            let view = DiskView::new(root);
            let model = read_workspace(root, &view);
            Self {
                probe: Probe::Workspace(root.clone()),
                models: vec![model],
                view,
                index: Index::default(),
                lanes: lanes::PRODUCTION,
                proofs: Proofs::PRODUCTION,
            }
        }
    }

    impl Root for DiskRoot {
        fn ask(&self) -> Asked<'_> {
            let Ok(ws) = &self.models[0] else {
                let why = gate::undetermined(&[]);
                return Asked::Unasked(vec![(Ecosystem::Npm, why)]);
            };
            let roots = Roots::Probed {
                probe: &self.probe,
                read: &self.models,
            };
            let cx = GateCx {
                roots,
                proofs: &self.proofs,
                ..GateCx::new(Mode::Hosted, ws, &self.view, &self.index)
            };
            let lanes = &self.lanes;
            Asked::Gate(BazelHost { cx, lanes })
        }

        fn place(&self) -> Option<(PathBuf, String)> {
            let ws = self.models[0].as_ref().ok()?;
            Some((ws.root.root.clone(), ws.root.project_rel.clone()))
        }
    }

    /// A root nobody could read: every npm patch is refused for it.
    struct Unread;

    impl Root for Unread {
        fn ask(&self) -> Asked<'_> {
            let lift = Lift::UserEdit {
                file: "MODULE.bazel".to_string(),
                what: "make the file readable".to_string(),
            };
            let refusal = Refusal::new(
                Reason::ConsumerUndetermined,
                crate::bazel::govern::WORKSPACE_UNREADABLE,
                "MODULE.bazel could not be read; nothing was written",
                lift,
            );
            Asked::Unasked(vec![(Ecosystem::Npm, refusal)])
        }

        fn place(&self) -> Option<(PathBuf, String)> {
            None
        }
    }

    fn grant(ecosystem: &str, name: &str, version: &str, uuid: &str, url: &str) -> DepOverride {
        DepOverride {
            ecosystem: ecosystem.to_string(),
            name: name.to_string(),
            namespace: None,
            version: version.to_string(),
            token: "tok_fixture_4f1c".to_string(),
            patch_uuid: uuid.to_string(),
            artifact_url: url.to_string(),
            registry_override: None,
            integrity: Integrity {
                sha512: Some("sha512-patched".to_string()),
                sha256: Some("ab".repeat(32)),
                ..Integrity::default()
            },
        }
    }

    fn left_pad() -> DepOverride {
        grant("npm", "left-pad", "1.3.0", UUID, URL)
    }

    fn requests() -> DepOverride {
        let url = "https://patch.socket.dev/patch/pypi/tok_fixture_4f1c/requests-2.31.0.tar.gz";
        grant("pypi", "requests", "2.31.0", PY_UUID, url)
    }

    fn module(hub: &str) -> String {
        MODULE.replace("HUB", hub)
    }

    /// The native rewriters over `files`, as [`rewrite`] is handed them.
    fn rewriters(
        files: &BTreeMap<String, String>,
    ) -> impl Fn(&[DepOverride], Option<&BazelHost<'_>>) -> (RewriteResult, BazelRewrite) + '_ {
        use crate::patch::redirect::rewrite_registry_redirect_under_bazel as under_bazel;
        move |overrides, host| match host {
            Some(host) => under_bazel(files, overrides, host),
            None => (
                rewrite_registry_redirect(files, overrides),
                BazelRewrite::default(),
            ),
        }
    }

    fn texts(files: &[(&str, &str)]) -> BTreeMap<String, String> {
        let text = |(path, text): &(&str, &str)| (path.to_string(), text.to_string());
        files.iter().map(text).collect()
    }

    /// ROUTED R-095: through the view the engine's Bazel reads use on
    /// disk, a directory that is not there lists as an empty one, and so
    /// an `update_pnpm_lock` hub that has not been built yet has a hash
    /// file that is absent, not one that cannot be located.
    #[test]
    fn a_missing_directory_lists_as_empty_and_the_hash_file_reads_absent() {
        let hub = module(", update_pnpm_lock = True");
        let checkout = Checkout::new(&[("MODULE.bazel", &hub), ("pnpm-lock.yaml", PNPM_LOCK)]);
        let root = DiskRoot::read(&checkout.root(""));
        let Asked::Gate(host) = root.ask() else {
            panic!("a readable root is asked");
        };
        let files = host.cx.files;
        assert_eq!(files.list(".aspect/rules"), Some(Vec::new()));
        assert_eq!(files.list("no/such/dir"), Some(Vec::new()));
        assert_eq!(files.read("no/such/file"), FileText::Absent);
        // Past the read boundary nothing is known, which is not "empty".
        assert_eq!(files.list(".."), None);

        let RulesetDetail::RulesJs(detail) = &host.cx.ws.hubs[0].detail else {
            panic!("a rules_js hub");
        };
        let cache = detail
            .action_cache
            .as_ref()
            .expect("update_pnpm_lock is on");
        assert!(matches!(cache, ActionCache::Absent { .. }), "{cache:?}");

        // Once the hub was built the file is found by what it lists.
        checkout.put(
            ".aspect/rules/external_repository_action_cache/npm_translate_lock_abc=",
            "pnpm-lock.yaml=1\n",
        );
        let built = DiskRoot::read(&checkout.root(""));
        let Asked::Gate(host) = built.ask() else {
            panic!("a readable root is asked");
        };
        let RulesetDetail::RulesJs(detail) = &host.cx.ws.hubs[0].detail else {
            panic!("a rules_js hub");
        };
        let cache = detail
            .action_cache
            .as_ref()
            .expect("update_pnpm_lock is on");
        assert!(matches!(cache, ActionCache::Lines { .. }), "{cache:?}");
    }

    /// A lock a label reaches through a linked directory lies in two
    /// directories, and only a model read from disk knows the real one.
    #[cfg(unix)]
    #[test]
    fn a_root_read_from_disk_knows_where_a_linked_lock_really_lies() {
        let hub = MODULE.replace("//:pnpm-lock.yaml\"HUB", "//app:pnpm-lock.yaml\"");
        let checkout = Checkout::new(&[("MODULE.bazel", &hub), ("real/pnpm-lock.yaml", PNPM_LOCK)]);
        checkout.put("real/BUILD.bazel", "");
        std::os::unix::fs::symlink(checkout.at("real"), checkout.at("app")).expect("a link");
        let root = DiskRoot::read(&checkout.root("real"));
        let ws = root.models[0].as_ref().expect("a workspace");
        let real = ws.lock_real_dirs.get("app/pnpm-lock.yaml");
        assert_eq!(real.map(String::as_str), Some("real"));
    }

    /// With every lane disabled the gate refuses each patch of a governed
    /// ecosystem with the code of its reason, nothing is staged for the
    /// Bazel root, and no native rewriter writes a file of the ecosystem:
    /// not the lock the hub reads, and not the sibling lock nobody reads.
    /// A patch of an ecosystem no ruleset governs is rewritten as ever.
    #[test]
    fn a_governed_patch_is_refused_and_the_native_rewriters_get_the_rest() {
        let checkout = Checkout::new(&[
            ("MODULE.bazel", &module("")),
            ("pnpm-lock.yaml", PNPM_LOCK),
            ("package-lock.json", NPM_LOCK),
            ("requirements.txt", "requests==2.31.0\n"),
        ]);
        let files = texts(&[
            ("pnpm-lock.yaml", PNPM_LOCK),
            ("package-lock.json", NPM_LOCK),
            ("requirements.txt", "requests==2.31.0\n"),
        ]);
        let reads = BazelReads::new(DiskRoot::read(&checkout.root("")));
        let overrides = [left_pad(), requests()];
        let (result, done) = rewrite(&reads, &overrides, &rewriters(&files));

        let expected: BTreeSet<String> = [UUID.to_string()].into();
        assert_eq!(done.governed(), &expected);
        assert_eq!(result.refused_bazel_uuids, expected);
        assert!(result.confirmed_bazel_uuids.is_empty());
        assert!(!done.confirmed(UUID));
        let Verdict::Refused(refused) = &done.decided(UUID).expect("decided").verdict else {
            panic!("refused");
        };
        assert_eq!(refused.code, Code::RedirectRulesetUnsupported);
        assert_eq!(refused.token, crate::bazel::model::LANE_NOT_ENABLED);
        assert!(
            refused.detail.ends_with("nothing was written"),
            "{refused:?}"
        );
        assert!(done.changes.is_empty() && done.touched.is_empty());
        assert_eq!(done.rewritten(), Vec::<String>::new());
        assert!(done.governs_npm());

        // The native result is the native result of the pypi patch alone.
        let alone = rewrite_registry_redirect(&files, &[requests()]);
        assert_eq!(result.files, alone.files);
        assert!(result.files.contains_key("requirements.txt"));
        assert!(!result.files.contains_key("package-lock.json"));
        assert!(!result.files.contains_key("pnpm-lock.yaml"));
        // What native hosted mode would have written beside the lock is
        // said once.
        let skipped = Code::RedirectSideFileSkipped.as_str();
        let said: Vec<&RewriteWarning> = result
            .warnings
            .iter()
            .filter(|warning| warning.code == skipped)
            .collect();
        assert_eq!(said.len(), 1, "{:?}", result.warnings);
        assert!(said[0].detail.contains("package-lock.json"), "{said:?}");
        assert_eq!(reads.marker(), format!("{}\n", checkout.top.display()));
    }

    /// Where no gate can be asked, the patches of every ecosystem the
    /// root names are refused with the root's own refusal, once however
    /// many artifacts a patch has, and the others are rewritten natively.
    #[test]
    fn a_root_that_cannot_be_asked_refuses_its_ecosystems_and_no_other() {
        let files = texts(&[
            ("package-lock.json", NPM_LOCK),
            ("requirements.txt", "requests==2.31.0\n"),
        ]);
        let reads = BazelReads::new(Unread);
        let second = grant(
            "npm",
            "left-pad",
            "1.3.0",
            UUID,
            "https://patch.socket.dev/other",
        );
        let overrides = [left_pad(), second, requests()];
        let (result, done) = rewrite(&reads, &overrides, &rewriters(&files));

        assert_eq!(done.group.decided.len(), 1, "{:?}", done.group.decided);
        let decided = &done.group.decided[0];
        assert_eq!(
            (decided.uuid.as_str(), decided.name.as_str()),
            (UUID, "left-pad")
        );
        let Verdict::Refused(refused) = &decided.verdict else {
            panic!("refused");
        };
        assert_eq!(refused.code, Code::RedirectConsumerUndetermined);
        assert_eq!(refused.lift.kind(), "user_edit");
        assert!(matches!(decided.outcome, GateOutcome::Refuse(_)));
        assert_eq!(result.refused_bazel_uuids.len(), 1);
        assert_eq!(
            result.warnings[0],
            warning(
                Code::RedirectConsumerUndetermined,
                "MODULE.bazel could not be read; nothing was written".to_string()
            )
        );
        let alone = rewrite_registry_redirect(&files, &[requests()]);
        assert_eq!(result.files, alone.files);
        assert!(!result.files.contains_key("package-lock.json"));
        assert_eq!(done.root, Path::new(""));
        assert!(done.changes.is_empty());
        assert_eq!(reads.marker(), "");
    }

    /// The paths of a Bazel change set are spelled from the project, and
    /// the two install-policy files are kept from the engine's own writer
    /// where a hub names them or a `.npmrc` could fail the build.
    #[test]
    fn a_change_set_is_spelled_from_the_project_and_side_files_are_withheld() {
        let change = |rel: &str| AnchoredChange {
            rel: rel.to_string(),
            read: None,
            write: Some(b"text\n".to_vec()),
        };
        let done = BazelDone {
            project_rel: "svc/api".to_string(),
            changes: vec![
                change(".socket/bazel/index.json"),
                change("svc/api/pnpm-lock.yaml"),
                change("svc/requirements_lock.txt"),
            ],
            named: ["svc/api/pnpm-workspace.yaml".to_string()].into(),
            ..BazelDone::default()
        };
        assert_eq!(
            done.rewritten(),
            [
                "../../.socket/bazel/index.json",
                "pnpm-lock.yaml",
                "../../svc/requirements_lock.txt"
            ]
        );
        let own: Vec<String> = done.project_texts().into_keys().collect();
        assert_eq!(own, ["pnpm-lock.yaml"]);
        // A file a hub names is the Bazel group's, whatever O14 says.
        let named = done.withholds(PNPM_WORKSPACE_REL, false).expect("withheld");
        assert_eq!(named.code, Code::RedirectSideFileSkipped.as_str());
        assert!(named.detail.contains("pnpm-workspace.yaml"), "{named:?}");
        assert!(done.withholds(".npmrc", true).is_some());
        assert!(done.withholds(".npmrc", false).is_none());

        let at_root = BazelDone {
            changes: vec![change(".socket/bazel/index.json"), change("pnpm-lock.yaml")],
            ..BazelDone::default()
        };
        assert_eq!(
            at_root.rewritten(),
            [".socket/bazel/index.json", "pnpm-lock.yaml"]
        );
        // O14: where no hub names it the file is native hosted mode's.
        assert!(creates_pnpm_workspace());
        assert!(at_root.withholds(PNPM_WORKSPACE_REL, true).is_none());
    }

    /// The tripwire behind principle P7: a native write at an owned path,
    /// in a hook file or in a file a hub names is taken out of the
    /// result, with its edits, and every other write stays.
    #[test]
    fn a_native_write_where_only_the_bazel_layer_writes_is_withheld() {
        let done = BazelDone {
            named: ["pnpm-lock.yaml".to_string()].into(),
            ..BazelDone::default()
        };
        let mut result = RewriteResult::default();
        for rel in [
            ".socket/bazel/index.json",
            ".bazelrc",
            "MODULE.bazel",
            "WORKSPACE.bzlmod",
            "pnpm-lock.yaml",
            "requirements.txt",
            "sub/.bazelrc",
        ] {
            result.files.insert(rel.to_string(), "text\n".to_string());
        }
        result
            .binary_files
            .insert(".socket/bazel/pins.bin".to_string(), vec![1]);
        result.edits.push(crate::patch::redirect::FileEdit {
            path: "pnpm-lock.yaml".to_string(),
            kind: "pnpm-lock".to_string(),
            action: "set".to_string(),
            key: None,
            original: None,
            new: None,
        });
        let mut withheld = done.withhold_native_writes(&mut result);
        withheld.sort();
        assert_eq!(
            withheld,
            [
                ".bazelrc",
                ".socket/bazel/index.json",
                ".socket/bazel/pins.bin",
                "MODULE.bazel",
                "WORKSPACE.bzlmod",
                "pnpm-lock.yaml"
            ]
        );
        let kept: Vec<&String> = result.files.keys().collect();
        assert_eq!(kept, ["requirements.txt", "sub/.bazelrc"]);
        assert!(result.binary_files.is_empty() && result.edits.is_empty());

        // A hook file of the root is no hook file of a project below it.
        let below = BazelDone {
            project_rel: "svc".to_string(),
            ..BazelDone::default()
        };
        let mut result = RewriteResult::default();
        result.files.insert(".bazelrc".to_string(), String::new());
        assert_eq!(
            below.withhold_native_writes(&mut result),
            Vec::<String>::new()
        );
    }

    fn options<'a>(
        npm_outer: &'a (dyn Fn() -> OuterAllowRemote + Send + Sync),
        yarn_outer: &'a (dyn Fn() -> OuterYarnMirror + Send + Sync),
    ) -> RewriteOptions<'a> {
        RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer,
            yarn_classic_outer: yarn_outer,
            cargo_outer: &|| crate::formats::cargo::source_replacement::CratesIoSource::Registry,
            pnpm_env: &|_| None,
            blocking: true,
            takeover_uuids: BTreeSet::new(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        }
    }

    /// The engine under a Bazel root, every lane disabled, in a project
    /// that release 5.1 already rewrote: both npm locks carry the hosted
    /// URL. The patch is refused, and nothing is written for it: not the
    /// locks, and none of the install-policy files native hosted mode
    /// would heal for a lock that carries a hosted URL. A native lock
    /// line that names the URL confirms nothing.
    #[tokio::test]
    async fn the_engine_writes_nothing_for_a_patch_the_bazel_gate_refuses() {
        let pinned = format!("{{integrity: sha512-patched, tarball: {URL}}}");
        let pnpm = PNPM_LOCK.replace("{integrity: sha512-upstream}", &pinned);
        let npm = NPM_LOCK
            .replace(
                "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                URL,
            )
            .replace("sha512-upstream", "sha512-patched");
        let checkout = Checkout::new(&[
            ("MODULE.bazel", &module("")),
            ("pnpm-lock.yaml", &pnpm),
            ("package-lock.json", &npm),
            (
                "package.json",
                "{\"name\": \"p\", \"version\": \"0.0.0\"}\n",
            ),
        ]);
        let view = ProjectView::Disk(&checkout.top);
        let candidates = [Candidate {
            purl: "pkg:npm/left-pad@1.3.0".to_string(),
            dep: left_pad(),
        }];
        let (npm_outer, yarn_outer) = (OuterAllowRemote::default, OuterYarnMirror::default);

        // Under no Bazel root this run heals both install-policy files.
        let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
        assert!(read.bazel.is_none());
        let native = engine_rewrite(
            &view,
            read,
            &candidates,
            BTreeMap::new(),
            options(&npm_outer, &yarn_outer),
        )
        .await;
        assert_eq!(native.confirmed.len(), 1, "the URL confirms it natively");
        assert!(native.bazel.is_none());
        for healed in [".npmrc", "pnpm-workspace.yaml"] {
            let wrote = native.rewritten.iter().any(|file| file == healed);
            assert!(wrote, "{healed}: {:?}", native.rewritten);
        }

        let mut read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
        read.attach(BazelReads::new(DiskRoot::read(&checkout.root(""))));
        assert!(read.files.contains_key(BAZEL_WORKSPACE_KEY));
        let done = engine_rewrite(
            &view,
            read,
            &candidates,
            BTreeMap::new(),
            options(&npm_outer, &yarn_outer),
        )
        .await;
        assert_eq!(
            done.confirmed,
            Vec::new(),
            "refused, whatever the locks say"
        );
        assert_eq!(done.rewritten, Vec::<String>::new());
        assert!(done.rewrite.files.is_empty() && done.rewrite.edits.is_empty());
        let bazel = done.bazel.as_ref().expect("the Bazel group ran");
        assert_eq!(bazel.governed().len(), 1);
        assert!(bazel.changes.is_empty());
        let codes: Vec<&str> = done
            .rewrite
            .warnings
            .iter()
            .map(|w| w.code.as_str())
            .collect();
        assert!(
            codes.contains(&Code::RedirectRulesetUnsupported.as_str()),
            "{codes:?}"
        );
        // No guidance for a pin the run did not make or confirm.
        assert!(done.pnpm_warnings.is_empty() && done.npm_warnings.is_empty());
        assert!(crate::hosted::engine::guard(&view, &done, &candidates).is_none());
    }
}
