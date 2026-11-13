//! CLI glue for Bazel builds: the one place the commands ask the pure layer
//! (`socket_patch_core::bazel`). It is not under `commands/`, so the command
//! layering allowlist does not grow.
//!
//! This file is the loader. A command makes one [`Loader`] per run and asks
//! it about each project directory it works on:
//!
//! - [`Loader::probe`] stats and reads nothing. Under no Bazel root that is
//!   the whole cost of this module, so a command that needs no governance
//!   answer (an `apply` run from a lifecycle hook) asks only this.
//! - [`Loader::load`] reads. Each Bazel root gets one `DiskView`, so each
//!   file of a root is opened once, whichever project asks. There is a
//!   model per root **and project**: its Bazel line spans the launcher
//!   files from the project up to the root, bazelisk takes the
//!   `.bazelversion` nearest the directory it is started in, and governance
//!   answers only for the project a model was read for. Projects with the
//!   same Bazel launcher files share what was read (`detect::rebase`). The
//!   root's owned index is read with its first model and handed out as
//!   [`IndexState`].
//! - [`Loader::committed`] is what a seam calls after it changed files
//!   under a Bazel root. What was read of the root is a cache from before
//!   the change, and the loader has no other way to learn of it: without
//!   the call the next project of the root is handed the files, the index
//!   and the model of before the write, and a transaction over them writes
//!   the first project's line and row away.
//!
//! What the run should say once about a workspace (it cannot be read, its
//! Bazel is too old, a workspace file lies above the repository) is queued
//! as it is found, each text once however many projects meet it, and a
//! command takes the queue with [`Loader::take_warnings`].
//!
//! The run policy of revision 4 is decided in [`run_policy`] and nowhere
//! else. It is `Never`: socket-patch runs no tool of the user's.
//!
//! The calls block (stats and reads): a command runs them where it runs
//! its other blocking walks. No command calls into this module yet: the
//! seams of the integration packages will, and the `mod` lines below name
//! their files. `run.rs` (`ToolRunner`, `NoRunner` and `finish`, revision 4
//! section 4) is not among them yet: its `finish` takes the captured
//! originals of the group commit, a type the hosted engine's package
//! defines, so the file and its `mod` line land in wave 5, before the
//! first seam that calls `finish`. `scope.rs` is the one check of a
//! command's scope root against Bazel's own trees.
//!
//! # Rules for a seam
//!
//! A seam is written once: a lane lands later by changing its lane file,
//! the lane table and the executor, and no file here. So a seam file of
//! this directory keeps to the following, and
//! `tests/command_module_layering.rs` scans every file here for the ones a
//! scan can see.
//!
//! - It asks the gate through a `GateCx` (`bazel::gate`) built as
//!   `GateCx { roots, .., ..GateCx::new(..) }`: the struct update keeps
//!   it compiling when the context gains a member, and `roots` is the root
//!   probe's answer, which `GateCx::new` cannot know and defaults to "one
//!   root". A context without it judges nested roots as one. So
//!   `GateCx::new` is written nowhere but as the base of that update (a
//!   call that is bound or passed on is the context with the default),
//!   and `Roots::One` is never written out: a seam passes what the probe
//!   found as `Roots::Probed`, which the gate reads as one root where the
//!   probe found one. Under `Probe::Nested` the models it passes are the
//!   ones read for the project of the request. The three other members
//!   `GateCx::new` defaults are as easy to forget and fail closed: with
//!   no `patch_url` every hosted request is refused (`fetch_blocked`),
//!   with no `host` a lane that wires a path refuses, and a default
//!   `allow_patch_conflicts` drops the user's flag. A seam sets what the
//!   run knows of each.
//! - It takes its [`LaneCx`] from [`LoadedRoot::lane_cx`] and its `RunCx`
//!   by struct update, never as a literal.
//! - It never matches on a write class, an owned write, a hook kind, a tag
//!   operation, a run kind, an anchor, an attest basis, a staleness
//!   behaviour or a withhold kind, and names no owned path as a literal,
//!   whole or level by level (`join(".socket").join("bazel")`): it hands
//!   plans to `exec::apply`, takes the paths of a commit from
//!   `exec::touched`, undoes through `exec::revert` and repairs through
//!   `exec::reconcile`. It names those types and the three contexts by
//!   their own names, with no `use .. as` and no `type` alias: the scan
//!   looks for the names.
//! - It maps a refusal the same way everywhere: the code is
//!   `Code::refusal(mode, reason)`, which is `Some` for every refusal the
//!   gate hands a hosted or vendored caller, a lane's own included;
//!   `details.token` and `details.lift` ride along; it never branches on a
//!   token. `not_resolved_by_hub` is a refusal like any other and never a
//!   reason to fall back to the native writer. A plan may carry the
//!   advisory `bazel_workspace_out_of_scope`: it is printed like any other.
//! - `lanes::discover` answers `Discovered { pins, cannot_tell }`: a
//!   reader keeps or withholds per ecosystem (`unknown_for`) and uses the
//!   pins of the others. It never treats "cannot tell" as "none".
//! - A write under a Bazel root goes `bazel_root_writes::before_*`,
//!   `exec::refresh`, `exec::touched`, `exec::apply`, and `exec::refresh`
//!   again after every root-channel call. `apply` inserts no `.bazelignore`
//!   line: `ExecError::LineNotHidden` maps to
//!   `bazel_workspace_ignore_line_needed`, and there is no conversion from
//!   `ExecError` to a refusal, so each seam maps the error to a code. After
//!   a failed commit the index is read again (`IndexFault::Stale` and
//!   `Missing` are answers, not bugs).
//! - After each commit, one that failed part-way included, it calls
//!   [`Loader::committed`], and builds no transaction on
//!   [`LoadedRoot::files`] or `LaneCx.files` from before it. It holds the
//!   `Arc<Loaded>` of the project it works on: the loader keeps only the
//!   last few.
//! - No seam lands a transaction or an overlay by itself. A commit
//!   under a Bazel root is the anchored group commit (the hosted engine's
//!   package lands it): under the root lock, staged and renamed, refused
//!   through a linked level. Until it exists a seam writes nothing under
//!   a root's owned directory, and no `.bazelignore`, except through
//!   `bazel_root_writes`.
//! - `exec::revert` answers `Reverted { written, dropped, kept }`. A
//!   `Kept::Pin` or `Kept::PinOfUnhandled` entry is a row that was not
//!   undone, with nothing of that row written; another row of the same
//!   patch may have been staged all the same. So a seam undoes one patch
//!   at a time, on an overlay of its own and over a copy of the index,
//!   and hands the overlay's changes to the commit only when `kept` is
//!   empty. Otherwise it drops both, deletes no artifact and reports
//!   `Code::revert_incomplete(mode)` with the file of each entry: a patch
//!   is undone whole or not at all. A pin's restore goes through
//!   `lanes::Restore`, on a copy of the row's files, written back only on
//!   `Restored`.
//! - `repair` reports what `exec::reconcile` reports and writes neither a
//!   missing index nor an absent ignore line: the root channel re-adds the
//!   line, and the index is never rebuilt from memory.
//! - A command that needs no governance answer asks [`Loader::probe`] or
//!   [`Loader::survey`] and never [`Loader::load`], which reads.
//! - Where a hub's lock lies is the disk's to say. A label is a spelling,
//!   and the lock behind it may be a link or lie behind a linked
//!   directory, in the directory of another project.
//!   `BazelWorkspace.lock_real_dirs` holds the real directories, and only
//!   `crawlers::bazel_workspace::read_workspace` fills it, which is what
//!   [`Loader::load`] calls. A seam that judges governance over a model
//!   `detect` built on any other view (an in-memory project, an overlay)
//!   has none: it treats a hub lock that it does not hold as content as
//!   undetermined, never as the lock of the directory the label spells.
//!   The same goes for which lock a run rewrites: a run started in one
//!   directory may pin a lock in another (a pnpm member's own, a Rush
//!   lock), and it is the lock's directory the gate is asked about.
//! - `crawlers::bazel_output::locate_output_base` also looks for a
//!   `_bazel_*` user root in the workspace root itself, beside the
//!   candidates it is handed. It has no product caller yet; a seam that
//!   becomes one hands it the run's candidates and does not look for a
//!   base on its own.

pub mod agent;
pub mod agent_go;
pub mod commands;
pub mod hosted;
pub mod scope;
pub mod vendored;
pub mod vex;

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};

use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::detect;
use socket_patch_core::bazel::exec::IndexFault;
use socket_patch_core::bazel::govern::{self, WORKSPACE_UNREADABLE};
use socket_patch_core::bazel::model::{
    BazelWorkspace, Completeness, DepSystem, FileText, FileView, Gap, Governance, Hub, HubId,
    Index, LaneCx, Liveness, LockRole, Mode, Probe, RootRef, Ruleset, RulesetDetail, RunPolicy,
    Tier,
};
use socket_patch_core::bazel::owned_index::{self, Parsed, INDEX_PATH};
use socket_patch_core::bazel::rulesets::report_only::ReportOnlyKind;
use socket_patch_core::bazel::version::{self, LineEvidence, TierRefusal};
use socket_patch_core::crawlers::bazel_root::{MarkerAbove, RootProbe, Survey};
use socket_patch_core::crawlers::bazel_workspace::{read_workspace, DiskView};
use socket_patch_core::crawlers::types::Ecosystem;
use socket_patch_core::utils::repo_root::{ReadBoundary, ReadScope};

use crate::json_envelope::RunWarning;

/// What a command knows about its run before it asks about any package:
/// everything the run policy may read. A command fills it in once, for
/// [`Loader::new`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunCx {
    /// The command writes nothing whatever it finds (`vex`, `list`,
    /// `apply --check`).
    pub read_only: bool,
    /// `--dry-run`.
    pub dry_run: bool,
    /// `SOCKET_OFFLINE`: a tool that needs the network cannot run.
    pub offline: bool,
}

/// Whether socket-patch may run a lane's tool in this run (revision 4,
/// 2.5; owner decision O17). `Never`, whatever the run: no tool runner
/// exists, and a lane whose build would fail between its write and the run
/// is refused with the command for the user to run. The loader hands the
/// answer to every [`LaneCx`], so the package that lands the runner changes
/// this function and no caller.
pub fn run_policy(_run: &RunCx) -> RunPolicy {
    RunPolicy::Never
}

/// One thing to say once in a run about a Bazel workspace. The code's
/// level (`Code::level`) is the prefix of its line for a human; the
/// `warnings[]` entry carries no level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub code: Code,
    pub detail: String,
}

impl Warning {
    /// The `warnings[]` entry of the envelope.
    pub fn entry(&self) -> RunWarning {
        RunWarning::new(self.code.as_str(), self.detail.clone())
    }
}

/// What the file at the owned index's path is. Read once per root, with
/// the root's first model, so it is as old as the files and the model it
/// is handed out with. A row that a writer of the same run records later
/// is not in it: the seam that wrote calls [`Loader::committed`], and the
/// next load reads the file again. `bazel::exec::refresh` catches up with
/// such a row only over a transaction that reads the disk, which one over
/// [`LoadedRoot::files`] does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexState {
    /// The index socket-patch wrote. A root with no index file has the
    /// empty one.
    Ours(Index),
    /// A file is there and its rows cannot be relied on: it could not be
    /// read, it was edited or mangled, or it is a file of the user's. No
    /// lane is asked, and nothing may be written over it.
    Faulty(IndexFault),
}

/// How many models a root keeps for the projects that come after
/// ([`RootState::model`]). A model holds the parsed `MODULE.bazel.lock`,
/// and a root whose sub-projects each pin their own Bazel (the nested
/// example workspaces of a ruleset repository) is read once for each of
/// them: without a bound every one of those reads would stay in memory
/// for the whole run.
const KEPT_MODELS: usize = 4;

/// The models of one root ([`RootState::model`]).
#[derive(Default)]
struct Models {
    /// How often the root was read.
    reads: usize,
    /// Copies of the last reads but the first, at most [`KEPT_MODELS`];
    /// the one a model was made from last is at the back.
    kept: VecDeque<BazelWorkspace>,
}

/// What is read once per Bazel root, whichever project asks, until the
/// run changes a file under the root ([`Loader::committed`]).
struct RootState {
    view: DiskView,
    index: OnceLock<IndexState>,
    models: Mutex<Models>,
}

impl RootState {
    fn new(root: &RootRef) -> Self {
        Self {
            view: DiskView::new(root),
            index: OnceLock::new(),
            models: Mutex::default(),
        }
    }

    /// The model of the root for the project of `root`.
    ///
    /// Projects from whose directories bazelisk starts the same Bazel have
    /// the same model but for the project it names (`detect::rebase`), so
    /// a root is read twice for them, not once per project: a read parses
    /// the whole `MODULE.bazel.lock` and, with rules_rust, opens every
    /// BUILD file. The first project owns what it read, so a run over one
    /// project holds one model; a later read leaves a copy from which the
    /// models of the projects after it are made. The copies are bounded
    /// ([`KEPT_MODELS`]), and the one that keeps being used is the one
    /// that stays.
    fn model(&self, root: &RootRef) -> Result<BazelWorkspace, Gap> {
        // Held across the read: a second project waits, then copies.
        let mut models = self.models.lock().unwrap_or_else(PoisonError::into_inner);
        // The index is read with the root's first model and never again,
        // so a lane is handed a model, files and an index of one read of
        // the root. It is read first: should another writer land a line
        // and its row in between, a line with no row is taken for the
        // user's and left alone, where a row with no line would record an
        // edit that the model says is not there.
        self.index();
        // The launcher files are read once, whatever the number of copies.
        let declared = version::read_declared(root, &self.view);
        let made = |known: &BazelWorkspace| detect::rebase_onto(known, root, &declared, &self.view);
        let mut kept = models.kept.iter().enumerate();
        if let Some((at, model)) = kept.find_map(|(at, known)| Some((at, made(known)?))) {
            if let Some(used) = models.kept.remove(at) {
                models.kept.push_back(used);
            }
            return Ok(model);
        }
        let model = read_workspace(root, &self.view);
        if let (Ok(ws), true) = (&model, models.reads > 0) {
            if models.kept.len() >= KEPT_MODELS {
                models.kept.pop_front();
            }
            models.kept.push_back(ws.clone());
        }
        models.reads += 1;
        model
    }

    fn index(&self) -> &IndexState {
        self.index.get_or_init(|| match self.view.read(INDEX_PATH) {
            FileText::Absent => IndexState::Ours(Index::default()),
            FileText::Unreadable => IndexState::Faulty(IndexFault::Unreadable),
            FileText::Bytes(bytes) => match owned_index::parse(&bytes) {
                Parsed::Ours(index) => IndexState::Ours(index),
                Parsed::Modified(what) => IndexState::Faulty(IndexFault::Modified(what)),
                Parsed::Foreign => IndexState::Faulty(IndexFault::Foreign),
            },
        })
    }
}

/// Why no lane can be asked about a hub. The caller refuses or withholds:
/// none of these is "Bazel does not govern here".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoLaneCx<'a> {
    /// The root has no model: none of its boundary files could be read.
    Workspace(&'a Gap),
    /// The owned index cannot be relied on, so no lane may write beside it.
    Index(&'a IndexFault),
    /// The model has no such hub.
    Hub(HubId),
}

/// One Bazel root as one project sees it.
#[derive(Clone, Copy)]
pub struct LoadedRoot<'a> {
    root: &'a RootRef,
    state: &'a RootState,
    model: &'a Result<BazelWorkspace, Gap>,
    run: RunPolicy,
}

impl<'a> LoadedRoot<'a> {
    /// The root, and where the project sits under it.
    pub fn root(&self) -> &'a RootRef {
        self.root
    }

    /// The files of the root, as every project of the run has read them
    /// since the last commit the loader was told of.
    ///
    /// It is a read cache: a file is read when it is first asked for and
    /// never again. Once the loader is told of a commit under the root
    /// the view is frozen (`DiskView::freeze`): it goes on answering what
    /// it had read, and a path nobody had asked for is `Unreadable`, never
    /// the bytes of after the commit and never `Absent`. So a load held
    /// across a commit is the root as it was, and it is not the base of a
    /// transaction. A seam reads what it is about to write over from a
    /// view made after the last commit of the run, and tells the loader
    /// once its own has landed ([`Loader::committed`]).
    pub fn files(&self) -> &'a DiskView {
        &self.state.view
    }

    /// The model read for this project. `Err` when no boundary file of the
    /// root could be read, which is never "no workspace".
    pub fn model(&self) -> Result<&'a BazelWorkspace, &'a Gap> {
        self.model.as_ref()
    }

    /// The root's owned index, as it was when the root's first model was
    /// read.
    pub fn index(&self) -> &'a IndexState {
        self.state.index()
    }

    /// What a lane function is handed for `hub` in `mode`: the model, the
    /// files and the index of one read of the root, and the run policy.
    /// They are what the root held before the run's last commit that the
    /// loader was not told of ([`Loader::committed`]): a lane decides from
    /// them, and no transaction is based on `files` ([`LoadedRoot::files`]).
    pub fn lane_cx(&self, mode: Mode, hub: HubId) -> Result<LaneCx<'a>, NoLaneCx<'a>> {
        let ws = self.model().map_err(NoLaneCx::Workspace)?;
        let index = match self.index() {
            IndexState::Ours(index) => index,
            IndexState::Faulty(fault) => return Err(NoLaneCx::Index(fault)),
        };
        if hub.0 >= ws.hubs.len() {
            return Err(NoLaneCx::Hub(hub));
        }
        Ok(LaneCx {
            mode,
            files: self.files(),
            ws,
            hub,
            index,
            run: self.run,
        })
    }
}

/// Everything read for one project: what the probe found and, for each
/// Bazel root at or below the read boundary, the model read for the
/// project.
pub struct Loaded {
    survey: Survey,
    states: Vec<Arc<RootState>>,
    /// One per root of `survey.roots`, in its order.
    models: Vec<Result<BazelWorkspace, Gap>>,
    run: RunPolicy,
}

impl Loaded {
    /// The one value the gate asks about (`Survey::probe`).
    pub fn probe(&self) -> Probe {
        self.survey.probe()
    }

    /// The Bazel workspace file above the read boundary, if any.
    pub fn above(&self) -> Option<&MarkerAbove> {
        self.survey.above.as_ref()
    }

    /// The roots inside the read boundary, nearest the project first.
    pub fn roots(&self) -> impl Iterator<Item = LoadedRoot<'_>> {
        let read = self.states.iter().zip(&self.models);
        let roots = self.survey.roots.iter().zip(read);
        roots.map(|(root, (state, model))| LoadedRoot {
            root,
            state,
            model,
            run: self.run,
        })
    }

    /// The models, one per root, in the order of [`Loaded::roots`].
    pub fn models(&self) -> &[Result<BazelWorkspace, Gap>] {
        &self.models
    }

    /// Which lock Bazel reads for `ecosystem` in this project, over every
    /// root that governs it (`govern::governance_over`).
    pub fn governance(&self, ecosystem: Ecosystem) -> Governance {
        govern::governance_over(&self.probe(), &self.models, ecosystem)
    }

    /// The governance of every ecosystem a Bazel ruleset can build. An
    /// ecosystem that is absent is one Bazel cannot govern.
    pub fn governed(&self) -> Vec<(Ecosystem, Governance)> {
        let mut out: Vec<(Ecosystem, Governance)> = Vec::new();
        for ecosystem in Ruleset::ALL.iter().filter_map(|r| r.ecosystem()) {
            if !out.iter().any(|(seen, _)| *seen == ecosystem) {
                out.push((ecosystem, self.governance(ecosystem)));
            }
        }
        out
    }
}

/// What decides everything a load reads: each root with the project's
/// place under it and its distance to the read boundary, and the marker
/// above the boundary. Two spellings of one project directory have one key.
type ProjectKey = (Vec<(PathBuf, String, usize)>, Option<(PathBuf, bool)>);

fn project_key(survey: &Survey) -> ProjectKey {
    let root = |r: &RootRef| (r.root.clone(), r.project_rel.clone(), r.boundary_levels);
    let above = survey.above.as_ref();
    let above = above.map(|above| (above.marker.clone(), above.confirmed));
    (survey.roots.iter().map(root).collect(), above)
}

/// How many loads the loader keeps alive by itself. A model holds the
/// parsed `MODULE.bazel.lock`, which runs to tens of megabytes in a large
/// workspace, and every project has its own: a run over hundreds of
/// projects must not keep them all. A caller keeps the load it works on.
const KEPT: usize = 8;

#[derive(Default)]
struct Memo {
    /// By project directory as given.
    surveys: HashMap<PathBuf, Survey>,
    /// By root and its distance to the read boundary, which bounds what a
    /// view reads.
    roots: HashMap<(PathBuf, usize), Arc<RootState>>,
    /// The loads somebody still holds, by project.
    projects: HashMap<ProjectKey, Weak<Loaded>>,
    /// The last [`KEPT`] loads.
    recent: VecDeque<Arc<Loaded>>,
    /// How many commits the loader was told of ([`Loader::committed`]).
    commits: u64,
    said: BTreeSet<(Code, String)>,
    pending: Vec<Warning>,
}

/// The loader of one run (module docs).
pub struct Loader {
    run: RunCx,
    probe: RootProbe,
    memo: Mutex<Memo>,
}

impl Loader {
    pub fn new(run: RunCx) -> Self {
        Self {
            run,
            probe: RootProbe::new(),
            memo: Mutex::default(),
        }
    }

    fn memo(&self) -> MutexGuard<'_, Memo> {
        self.memo.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues what nobody has been told yet in this run.
    fn say(&self, found: Vec<Warning>) {
        let mut memo = self.memo();
        for warning in found {
            if memo.said.insert((warning.code, warning.detail.clone())) {
                memo.pending.push(warning);
            }
        }
    }

    /// The run-level warnings found since the last call, in the order they
    /// were found. A text is queued once per run.
    pub fn take_warnings(&self) -> Vec<Warning> {
        std::mem::take(&mut self.memo().pending)
    }

    /// The Bazel roots that govern `project_dir` and the marker above its
    /// read boundary. Stats only, once per directory as given.
    pub fn survey(&self, project_dir: &Path) -> Survey {
        if let Some(known) = self.memo().surveys.get(project_dir) {
            return known.clone();
        }
        // The empty path is the working directory, as it is to the probe.
        let from = match project_dir.as_os_str().is_empty() {
            true => Path::new("."),
            false => project_dir,
        };
        let boundary = ReadBoundary::upward(ReadScope::Workspace, from);
        let survey = self.probe.survey(project_dir, &boundary);
        let above = survey.above.iter();
        self.say(
            above
                .map(|above| above_warning(above, is_outside(&boundary, &above.marker)))
                .collect(),
        );
        let known = survey.clone();
        self.memo().surveys.insert(project_dir.to_path_buf(), known);
        survey
    }

    /// What the stat-only probe found for `project_dir`. Reads nothing.
    pub fn probe(&self, project_dir: &Path) -> Probe {
        self.survey(project_dir).probe()
    }

    /// The models and the files of every Bazel root that governs
    /// `project_dir`. One project has one load for as long as somebody
    /// holds it, and the loader holds the last few itself. A load is what
    /// its roots held when it was read: after [`Loader::committed`] the
    /// project is read again, and a load somebody still holds stays as it
    /// was.
    pub fn load(&self, project_dir: &Path) -> Arc<Loaded> {
        let survey = self.survey(project_dir);
        let key = project_key(&survey);
        loop {
            let commits = match self.held(&key) {
                Ok(known) => return known,
                Err(commits) => commits,
            };
            let read = Arc::new(self.read(survey.clone()));
            if let Some(loaded) = self.keep(&key, read, commits) {
                return loaded;
            }
        }
    }

    /// The load of the project that somebody holds, else how many commits
    /// the loader was told of so far.
    fn held(&self, key: &ProjectKey) -> Result<Arc<Loaded>, u64> {
        let memo = self.memo();
        let held = memo.projects.get(key).and_then(Weak::upgrade);
        held.ok_or(memo.commits)
    }

    /// Makes `read` the project's load and returns the load everybody
    /// shares. `None` when the loader was told of a commit since it knew
    /// of `commits` of them, which is when the read began: the files may
    /// be from either side of the commit, so the caller reads again.
    fn keep(&self, key: &ProjectKey, read: Arc<Loaded>, commits: u64) -> Option<Arc<Loaded>> {
        let mut memo = self.memo();
        if memo.commits != commits {
            return None;
        }
        // Another task may have loaded the project meanwhile: its load is
        // the one everybody shares.
        if let Some(known) = memo.projects.get(key).and_then(Weak::upgrade) {
            return Some(known);
        }
        memo.projects.insert(key.clone(), Arc::downgrade(&read));
        memo.recent.push_back(Arc::clone(&read));
        if memo.recent.len() > KEPT {
            memo.recent.pop_front();
        }
        Some(read)
    }

    /// Tells the loader that this run changed files at or below `dir`: a
    /// Bazel root for a write anchored there (a `.bazelignore` line, the
    /// owned index and what it records), a project directory for a
    /// project's own (a lock file a hub reads, a vendored tree). A seam
    /// calls it after every commit that landed, and after one that failed
    /// part-way.
    ///
    /// Everything read of a root at, above or below `dir` is dropped: its
    /// files, its index and its models, and the loads built on them, so
    /// the next [`Loader::load`] reads the disk. A root above `dir` reads
    /// the files below it, and a view reads as far up as its read
    /// boundary, so both directions count. A load that a caller still
    /// holds keeps what it read: it is the root of before the commit, and
    /// nothing may be written from it. Its view is frozen, so what it had
    /// not read by now it cannot read any more: a lane or a gate that asks
    /// it for a file after the commit is told `Unreadable` and refuses,
    /// where it would have judged a model of before the commit by bytes
    /// of after it.
    ///
    /// Which directories are Bazel roots is not asked again: socket-patch
    /// creates no boundary file.
    pub fn committed(&self, dir: &Path) {
        // The empty path is the working directory, as it is to the probe.
        let from = match dir.as_os_str().is_empty() {
            true => Path::new("."),
            false => dir,
        };
        // The roots are resolved paths, and `dir` is as the caller spells
        // it. One that cannot be resolved could be anywhere, so every
        // root goes: reading one again costs time and nothing else.
        let real = std::fs::canonicalize(from).ok();
        let touched = |root: &Path| {
            let near = |dir: &Path| root.starts_with(dir) || dir.starts_with(root);
            real.as_deref().is_none_or(|real| near(real) || near(from))
        };
        let mut memo = self.memo();
        memo.commits += 1;
        memo.roots.retain(|(root, _), state| {
            let dropped = touched(root);
            if dropped {
                state.view.freeze();
            }
            !dropped
        });
        let built_on = |key: &ProjectKey| key.0.iter().any(|(root, _, _)| touched(root));
        memo.projects.retain(|key, _| !built_on(key));
        let built_on = |loaded: &Arc<Loaded>| loaded.survey.roots.iter().any(|r| touched(&r.root));
        memo.recent.retain(|loaded| !built_on(loaded));
    }

    fn root_state(&self, root: &RootRef) -> Arc<RootState> {
        let key = (root.root.clone(), root.boundary_levels);
        let mut memo = self.memo();
        let state = memo.roots.entry(key);
        Arc::clone(state.or_insert_with(|| Arc::new(RootState::new(root))))
    }

    fn read(&self, survey: Survey) -> Loaded {
        let state = |root: &RootRef| self.root_state(root);
        let states: Vec<Arc<RootState>> = survey.roots.iter().map(state).collect();
        let roots = survey.roots.iter().zip(&states);
        let models: Vec<Result<BazelWorkspace, Gap>> =
            roots.map(|(root, state)| state.model(root)).collect();
        let mut found = Vec::new();
        for (root, model) in survey.roots.iter().zip(&models) {
            model_warnings(root, model, &mut found);
        }
        self.say(found);
        Loaded {
            survey,
            states,
            models,
            run: run_policy(&self.run),
        }
    }
}

/// Whether the marker a survey reports is a file above the read boundary.
/// One the probe reports at or below it is its answer for a project it
/// could not place under the root there, and so is a relative one, which
/// it gives back when the working directory cannot be read.
///
/// Decided from the two paths as the probe built them, never by resolving
/// the file: the marker is a name joined to an ancestor of the resolved
/// project directory, and the boundary is such an ancestor. A boundary
/// file above the repository that is a link to a file inside it is above
/// the repository all the same, and `ReadBoundary::contains` would follow
/// the link and place it inside. An unbounded run has nothing above.
fn is_outside(boundary: &ReadBoundary, marker: &Path) -> bool {
    let above = |root: &Path| marker.is_absolute() && !marker.starts_with(root);
    boundary.root().is_some_and(above)
}

/// The warning for the marker a survey reports beside its roots. `outside`:
/// it is a Bazel workspace file above the read boundary (design 2.2).
/// Nothing is read there, so a workspace somebody builds there leaves
/// every ecosystem Bazel can build undetermined, and a stray file changes
/// nothing. Otherwise the probe could not place the project under the
/// root the marker makes, and answers as for a workspace it cannot read.
fn above_warning(above: &MarkerAbove, outside: bool) -> Warning {
    let marker = above.marker.display();
    let refused = "hosted and vendored patches are refused and VEX statements withheld for every \
                   ecosystem a Bazel ruleset can build";
    if !outside {
        let detail = format!(
            "The project directory cannot be named under the Bazel workspace of {marker}: a \
             directory name between them is not UTF-8, or the working directory could not be \
             read. The lock files Bazel builds the project from are not known, so {refused}"
        );
        let code = Code::WorkspaceUnreadable;
        return Warning { code, detail };
    }
    let detail = match above.confirmed {
        true => format!(
            "{marker} makes a directory above the repository a Bazel workspace, and socket-patch \
             does not read above the repository: the lock files that workspace builds from are \
             not known, so {refused}. Where nobody builds from that directory, remove the file \
             and any other Bazel workspace file beside it"
        ),
        false => format!(
            "{marker} is a Bazel workspace file above the repository, where socket-patch does \
             not read. Nothing beside it says that Bazel is run there, so it changes nothing; \
             where nobody builds from that directory, remove it"
        ),
    };
    Warning {
        code: Code::WorkspaceAboveRepo,
        detail,
    }
}

/// `count` of a thing, in words: `1 source archive`, `3 source archives`.
fn counted(count: usize, thing: &str) -> Option<String> {
    let plural = if count == 1 { "" } else { "s" };
    (count > 0).then(|| format!("{count} {thing}{plural}"))
}

/// The dependency system as the detection note names it.
///
/// A workspace that may run under more than one is named by each of them,
/// as a list no reader can group another way: the hybrid system is itself
/// "Bzlmod and WORKSPACE", and joined to its neighbours with "or" it read
/// as "WORKSPACE or Bzlmod and WORKSPACE or Bzlmod".
fn system_words(system: &DepSystem) -> String {
    match system {
        DepSystem::Bzlmod => "Bzlmod".to_string(),
        DepSystem::Workspace => "WORKSPACE".to_string(),
        DepSystem::Hybrid => "Bzlmod and WORKSPACE".to_string(),
        DepSystem::Neither => "no dependency system".to_string(),
        DepSystem::DualMode { systems, .. } => {
            let one = |system: &DepSystem| match system {
                DepSystem::Hybrid => "Bzlmod and WORKSPACE together".to_string(),
                other => system_words(other),
            };
            let each: Vec<String> = systems.iter().map(one).collect();
            let listed = match each.as_slice() {
                [] => "no system named".to_string(),
                [only] => only.clone(),
                [first, second] => format!("{first} or {second}"),
                [most @ .., last] => format!("{}, or {last}", most.join(", ")),
            };
            format!("dependency system not decided: {listed}")
        }
        DepSystem::Unknown { .. } => "dependency system unknown".to_string(),
    }
}

/// The name the detection note gives the ruleset of `hub`. A report-only
/// shape is named by its kind (`report_only` is nobody's ruleset) and
/// marked: socket-patch knows the shape and patches nothing for it.
fn hub_name(hub: &Hub) -> String {
    let RulesetDetail::ReportOnly(detail) = &hub.detail else {
        return hub.ruleset.name().to_string();
    };
    let kind = match detail.kind {
        ReportOnlyKind::RulesReqCompile => "rules_req_compile",
        ReportOnlyKind::RulesPoetry => "rules_poetry",
        ReportOnlyKind::BazelDeps => "bazel-deps",
        ReportOnlyKind::JvmImportExternal => "jvm_import_external",
        ReportOnlyKind::HttpJar => "http_jar",
        ReportOnlyKind::CargoRaze => "cargo-raze",
        ReportOnlyKind::NonRootModuleHub => "a module extension",
    };
    format!("{kind} (recognized, not patched)")
}

/// One hub as the detection note describes it, by what `govern::settle`
/// decided about its declaration. Bazel builds from a live one and may
/// build from an undecided one. Of any other the note says where it is
/// declared and why no build comes from it, and never that Bazel builds
/// from its lock: a `WORKSPACE` hub left beside `MODULE.bazel` on Bazel 9
/// names a lock that Bazel does not read.
fn hub_words(hub: &Hub) -> String {
    let locks = hub.locks.iter();
    let locks = locks.filter(|lock| lock.role == LockRole::PackageLock);
    let locks: Vec<&str> = locks
        .map(|lock| lock.path.as_deref().unwrap_or(&lock.label))
        .collect();
    let from = match locks.is_empty() {
        true => String::new(),
        false => format!(" from {}", locks.join(", ")),
    };
    let (name, packages) = (hub_name(hub), hub.ecosystem.display_name());
    let unused = |why: &str| {
        format!(
            "{name} is declared in {} for {packages} packages{from}, and Bazel does not build \
             from that declaration: {why}",
            hub.decl.site.file
        )
    };
    match &hub.liveness {
        Liveness::Live => format!("{name} builds {packages} packages{from}"),
        Liveness::Undecided { .. } => format!("{name} may build {packages} packages{from}"),
        // Bazel builds the packages, from locks of that module's own
        // repository, which are no files of this workspace.
        Liveness::NotRootModule => format!(
            "{name} builds {packages} packages for a module that is not the root module, from \
             that module's own lock files"
        ),
        Liveness::Dead { why } => unused(why),
        Liveness::Shadowed { by } => {
            unused(&format!("{} gives its name to another repository", by.file))
        }
        Liveness::NotImported => unused("no use_repo statement imports its repository"),
        Liveness::DevDependencyDropped => {
            unused("it is a dev dependency, and --ignore_dev_dependency drops it")
        }
    }
}

/// What the run says once about the root `root`, from the model read for
/// one project. Every text names the root and facts of the root, so the
/// projects of one root say it once between them.
fn model_warnings(root: &RootRef, model: &Result<BazelWorkspace, Gap>, out: &mut Vec<Warning>) {
    let at = root.root.display();
    let mut say = |code: Code, detail: String| out.push(Warning { code, detail });
    let ws = match model {
        Ok(ws) => ws,
        // The gap names the root: no boundary file there could be read.
        Err(gap) => return say(Code::WorkspaceUnreadable, gap.detail.clone()),
    };
    let gaps: &[Gap] = match &ws.completeness {
        Completeness::Exact => &[],
        Completeness::Incomplete(gaps) => gaps,
    };
    for gap in gaps.iter().filter(|gap| gap.token == WORKSPACE_UNREADABLE) {
        let detail = format!(
            "Bazel workspace {at}: {}. What it declares may decide which lock files Bazel reads, \
             so nothing is assumed about them until it can be read",
            gap.detail
        );
        say(Code::WorkspaceUnreadable, detail);
    }

    // Every hub is described, a report-only one too: it is no ruleset
    // socket-patch patches for, but governance answers for its ecosystem
    // and the locks it reads are refused, so the run says that it is
    // there. (Only its hand-written pins are counted below.)
    let mut rulesets: Vec<String> = ws.hubs.iter().map(hub_words).collect();
    rulesets.extend(ws.signals.iter().map(|signal| {
        let name = signal.ruleset.name();
        format!("{name} is declared, and the lock file it reads was not found")
    }));
    let mut seen = BTreeSet::new();
    rulesets.retain(|line| seen.insert(line.clone()));

    // The line, the rc files and the launcher matter where Bazel may
    // build registry packages; elsewhere nothing here depends on them.
    if !rulesets.is_empty() || !gaps.is_empty() {
        let line = &ws.line;
        let unsupported = match ws.tier {
            Tier::Refused(TierRefusal::TooOld) => Some("Bazel 4 and older are"),
            Tier::Refused(TierRefusal::ExperimentalBzlmod) => Some("Bzlmod on Bazel 5 is"),
            _ => None,
        };
        if let Some(what) = unsupported {
            let detail = format!(
                "Bazel workspace {at} runs Bazel {line}, and {what} not supported: no lock file \
                 Bazel reads there is patched. Upgrade Bazel, or patch outside Bazel"
            );
            say(Code::WorkspaceVersionUnsupported, detail);
        } else if line.untested() {
            // The Bazel half of the code. A ruleset release that no lane
            // cell ran is the gate's to name: the lane claims list them.
            let detail = format!(
                "Bazel workspace {at} may run a Bazel release socket-patch was not tested with \
                 (Bazel version: {line}); pin .bazelversion to a tested release"
            );
            say(Code::WorkspaceVersionUntested, detail);
        }
        for gap in ws.flags.gaps() {
            let detail = format!(
                "Bazel workspace {at}: an rc file was not read, so flags may apply that \
                 socket-patch does not see: {} {}",
                gap.file, gap.detail
            );
            say(Code::WorkspaceRcUnread, detail);
        }
        let wrappers = line.evidence.iter().filter_map(|evidence| match evidence {
            LineEvidence::Wrapper(path) => Some(path),
            _ => None,
        });
        for path in wrappers {
            let detail = format!(
                "Bazel workspace {at}: {path} is a launcher wrapper, which can start another \
                 Bazel release and pass flags that no committed rc file shows"
            );
            say(Code::WorkspaceRcUnread, detail);
        }
    }
    if !rulesets.is_empty() {
        let tier = match ws.tier {
            Tier::Supported => "supported",
            Tier::Beta => "beta",
            Tier::Legacy => "legacy",
            Tier::Refused(TierRefusal::TooOld | TierRefusal::ExperimentalBzlmod) => "not supported",
            // The release is not what is refused here: what the root
            // declares in a WORKSPACE file is.
            Tier::Refused(TierRefusal::WorkspaceRemoved) => {
                "WORKSPACE declarations refused, Bazel 9 and newer read none"
            }
            Tier::Refused(TierRefusal::LineUnknown) => {
                "WORKSPACE declarations refused, no Bazel release is pinned"
            }
        };
        // The launcher files the line was read from: a project that pins
        // its own Bazel has another line than the root, and says why.
        let pins = ws
            .line
            .evidence
            .iter()
            .filter_map(|evidence| match evidence {
                LineEvidence::Declared(pick) => pick.file.as_deref(),
                _ => None,
            });
        let pins: Vec<&str> = pins.collect();
        let from = match pins.is_empty() {
            true => String::new(),
            false => format!(" from {}", pins.join(" and ")),
        };
        let detail = format!(
            "Bazel workspace {at} (Bazel {}{from}, {tier}; {}): {}",
            ws.line,
            system_words(&ws.system),
            rulesets.join("; ")
        );
        say(Code::WorkspaceDetected, detail);
    }

    // Counts of declarations, in every file that was read: Bazel may
    // evaluate fewer (a WORKSPACE.bzlmod beside a WORKSPACE).
    let counts = [
        counted(ws.out_of_scope.bazel_modules, "Bazel module"),
        counted(ws.out_of_scope.source_archives, "source archive"),
        counted(ws.out_of_scope.report_only_pins, "hand-written pin"),
    ];
    let counts: Vec<String> = counts.into_iter().flatten().collect();
    if !counts.is_empty() {
        let detail = format!(
            "Bazel workspace {at} declares {}. Socket patches cover registry packages, so these \
             dependencies are not examined",
            counts.join(", ")
        );
        say(Code::WorkspaceOutOfScope, detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::bazel::exec::{self, Overlay, Txn};
    use socket_patch_core::bazel::ignore::BAZELIGNORE;
    use socket_patch_core::bazel::ignore::{self, IgnoreLine, IgnoreLineRow, SocketTree};
    use socket_patch_core::bazel::version::BazelVersion;
    use socket_patch_core::crawlers::bazel_root::boundary_file_in;

    const JS_MODULE: (&str, &str) = (
        "MODULE.bazel",
        "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
         npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
         npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
         use_repo(npm, \"npm\")\n",
    );
    const JS_WORKSPACE: (&str, &str) = (
        "WORKSPACE",
        "load(\"@aspect_rules_js//npm:repositories.bzl\", \"npm_translate_lock\")\n\
         npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n",
    );
    const PNPM_LOCK: (&str, &str) = ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
    const BAZEL_9: (&str, &str) = (".bazelversion", "9.3.2\n");

    /// A checkout in a temporary directory: `.git` bounds every upward
    /// read, so the roots of a test are the ones it writes.
    struct Repo {
        tmp: tempfile::TempDir,
        top: PathBuf,
    }

    impl Repo {
        fn new(files: &[(&str, &str)]) -> Self {
            let tmp = tempfile::tempdir().expect("a temporary directory");
            let top = std::fs::canonicalize(tmp.path()).expect("its real path");
            let repo = Self { tmp, top };
            repo.put(".git/HEAD", "ref: refs/heads/main\n");
            files.iter().for_each(|(rel, text)| repo.put(rel, text));
            repo
        }

        /// `rel` below the checkout, level by level.
        fn at(&self, rel: &str) -> PathBuf {
            let levels = rel.split('/').filter(|level| !level.is_empty());
            levels.fold(self.top.clone(), |at, level| at.join(level))
        }

        fn put(&self, rel: &str, text: &str) {
            let path = self.at(rel);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(path, text).expect("write");
        }

        fn get(&self, rel: &str) -> String {
            std::fs::read_to_string(self.at(rel)).expect("read")
        }

        /// Lands what a transaction staged, as the commit of a seam does.
        fn land(&self, txn: &Overlay<'_>) {
            for (rel, bytes) in txn.changes() {
                match bytes {
                    Some(bytes) => self.put(rel, std::str::from_utf8(bytes).expect("text")),
                    None => std::fs::remove_file(self.at(rel)).expect("remove"),
                }
            }
        }

        /// The codes of [`Repo::said`], in order.
        fn codes(said: &[(Code, String)]) -> Vec<&'static str> {
            said.iter().map(|(code, _)| code.as_str()).collect()
        }

        /// What the run says about this checkout. A workspace file above
        /// the temporary directory of this machine is not the test's.
        fn said(&self, loader: &Loader) -> Vec<(Code, String)> {
            let here = self.top.display().to_string();
            let said = loader.take_warnings().into_iter();
            let said = said.filter(|warning| warning.detail.contains(&here));
            said.map(|warning| (warning.code, warning.detail)).collect()
        }
    }

    /// The outermost root of a load: the one the test wrote.
    fn outer(loaded: &Loaded) -> LoadedRoot<'_> {
        loaded.roots().last().expect("a Bazel root")
    }

    #[test]
    fn under_no_bazel_root_nothing_is_loaded_and_nothing_is_said() {
        let repo = Repo::new(&[("app/package.json", "{}\n")]);
        let loader = Loader::new(RunCx::default());
        assert!(loader.survey(&repo.at("app")).roots.is_empty());
        let loaded = loader.load(&repo.at("app"));
        assert!(loaded.models().is_empty() && loaded.roots().next().is_none());
        // The seven ecosystems a ruleset can build, each as today.
        let governed = loaded.governed();
        assert_eq!(governed.len(), 7, "{governed:?}");
        assert_eq!(loaded.governance(Ecosystem::Npm), Governance::NotGoverned);
        assert_eq!(
            loaded.governance(Ecosystem::Composer),
            Governance::NotGoverned
        );
        assert_eq!(repo.said(&loader), []);
    }

    /// R-092: bazelisk takes the `.bazelversion` nearest the directory it
    /// is started in, so a model answers for the project it was read for.
    #[test]
    fn one_model_per_root_and_project_over_one_view_of_the_root() {
        let files = [JS_MODULE, PNPM_LOCK, (".bazelversion", "7.7.2\n")];
        let repo = Repo::new(&files);
        repo.put("sub/.bazelversion", "8.8.2\n");
        let loader = Loader::new(RunCx::default());
        let at_root = loader.load(&repo.top);
        // What a run has read of a root is what it keeps seeing until it
        // is told of a commit: the next project of the root opens no file
        // a second time.
        repo.put("MODULE.bazel", "module(name = \"changed\")\n");
        let at_sub = loader.load(&repo.at("sub"));
        let (root, sub) = (outer(&at_root), outer(&at_sub));
        assert!(std::ptr::eq(root.files(), sub.files()), "one view per root");
        assert_eq!(
            (&root.root().project_rel, &sub.root().project_rel),
            (&String::new(), &"sub".to_string())
        );
        let (root, sub) = (
            root.model().expect("a model"),
            sub.model().expect("a model"),
        );
        let (v7, v8) = (BazelVersion::new(7, 7, 2), BazelVersion::new(8, 8, 2));
        assert_eq!(root.line.exact(), Some(v7));
        assert_eq!((sub.line.lo, sub.line.hi), (Some(v7), Some(v8)));
        assert_eq!((sub.hubs.len(), &sub.module), (1, &root.module));
        // Each model answers for its own project.
        let governed = Governance::Governed(vec![HubId(0)]);
        assert_eq!(at_root.governance(Ecosystem::Npm), governed);
        assert_eq!(at_sub.governance(Ecosystem::Npm), Governance::NotGoverned);
        // One project is one load, however its directory is spelled.
        let spelled = repo.tmp.path().join("sub");
        assert!(Arc::ptr_eq(&at_sub, &loader.load(&spelled)));
        assert!(Arc::ptr_eq(&at_root, &loader.load(&repo.top)));
    }

    /// R-093: the loader is what says that a workspace file is unreadable.
    #[test]
    fn an_unreadable_workspace_file_is_said_once_per_run() {
        let workspace = ("WORKSPACE", "workspace(name = \"w\")\n\tx = 1\n");
        let repo = Repo::new(&[workspace, (".bazelversion", "7.7.2\n"), ("sub/BUILD", "")]);
        let loader = Loader::new(RunCx::default());
        let loaded = ["", "sub", ""].map(|project| loader.load(&repo.at(project)));
        let said = repo.said(&loader);
        let [(code, detail)] = said.as_slice() else {
            panic!("one warning, not {said:?}");
        };
        assert_eq!(code.as_str(), "bazel_workspace_unreadable");
        let named = format!("{}: WORKSPACE:2: a tab", repo.top.display());
        assert!(detail.contains(&named), "{detail}");
        // Unreadable is not absent: no ecosystem is taken for ungoverned.
        for (ecosystem, governance) in loaded[1].governed() {
            let undetermined = matches!(governance, Governance::Undetermined(_));
            assert!(undetermined, "{ecosystem:?}: {governance:?}");
        }
        loader.load(&repo.at("sub"));
        assert_eq!(loader.take_warnings(), []);
    }

    /// What a case of the index test puts at the index's path.
    enum Held<'a> {
        Nothing,
        Text(&'a str),
        Directory,
    }

    #[test]
    fn the_owned_index_is_read_once_per_root_and_a_faulty_one_yields_no_lane_context() {
        let line = IgnoreLine::new("", SocketTree::Vendor).expect("a line");
        let mut recorded = Index::default();
        recorded.record_lines(vec![IgnoreLineRow {
            line,
            created_file: true,
            added_final_newline: false,
        }]);
        let rendered = recorded.render().expect("a valid index");
        let cases: [(Held<'_>, Result<&Index, &str>); 5] = [
            (Held::Nothing, Ok(&Index::default())),
            (Held::Text(&rendered), Ok(&recorded)),
            (
                Held::Text("{\"ignoreLines\": [], \"pins\": []}\n"),
                Err("modified"),
            ),
            (Held::Text("{\"name\": \"mine\"}\n"), Err("foreign")),
            // Unreadable is not absent: a directory of the name is no
            // empty index, and nothing is written beside it.
            (Held::Directory, Err("unreadable")),
        ];
        for (at, (held, want)) in cases.into_iter().enumerate() {
            let repo = Repo::new(&[JS_MODULE, PNPM_LOCK, BAZEL_9, ("app/package.json", "{}")]);
            match held {
                Held::Nothing => {}
                Held::Text(text) => repo.put(INDEX_PATH, text),
                Held::Directory => std::fs::create_dir_all(repo.at(INDEX_PATH)).expect("mkdir"),
            }
            let loader = Loader::new(RunCx::default());
            let (at_root, at_app) = (loader.load(&repo.top), loader.load(&repo.at("app")));
            let root = outer(&at_root);
            let cx = root.lane_cx(Mode::Hosted, HubId(0));
            match (root.index(), want) {
                (IndexState::Ours(index), Ok(want)) => {
                    assert_eq!(index, want);
                    let Ok(cx) = cx else {
                        panic!("case {at}: no lane context");
                    };
                    let model = root.model().expect("a model");
                    assert!(std::ptr::eq(cx.index, index) && std::ptr::eq(cx.ws, model));
                    let asked = (cx.mode, cx.hub, cx.run);
                    assert_eq!(asked, (Mode::Hosted, HubId(0), RunPolicy::Never));
                    let no_hub = root.lane_cx(Mode::Vendored, HubId(1)).err();
                    assert_eq!(no_hub, Some(NoLaneCx::Hub(HubId(1))));
                }
                (IndexState::Faulty(fault), Err(want)) => {
                    let kind = match fault {
                        IndexFault::Unreadable => "unreadable",
                        IndexFault::Modified(_) => "modified",
                        IndexFault::Foreign => "foreign",
                        _ => "other",
                    };
                    assert_eq!(kind, want);
                    assert_eq!(cx.err(), Some(NoLaneCx::Index(fault)));
                }
                (found, want) => panic!("case {at}: {found:?}, not {want:?}"),
            }
            // Read once: a later write is not seen, by any project of the root.
            if !matches!(held, Held::Directory) {
                repo.put(INDEX_PATH, "{}");
            }
            assert!(std::ptr::eq(root.index(), outer(&at_app).index()));
        }
    }

    /// The index is read with the root's first model and not when a lane
    /// first asks: the root channel writes a line and its row straight to
    /// the disk, and a lane must not be handed a recorded line that its
    /// own model and files say is not there.
    #[test]
    fn a_lane_is_handed_an_index_as_old_as_its_model_and_files() {
        let repo = Repo::new(&[JS_MODULE, PNPM_LOCK, BAZEL_9]);
        let loader = Loader::new(RunCx::default());
        let loaded = loader.load(&repo.top);
        // Another writer of the run, after the load and before the lane.
        let line = IgnoreLine::new("app", SocketTree::Vendor).expect("a line");
        let added = ignore::insert(&FileText::Absent, std::slice::from_ref(&line));
        let added = added.expect("an edit").expect("a line to add");
        let mut index = Index::default();
        index.record_lines(added.rows);
        repo.put(
            BAZELIGNORE,
            std::str::from_utf8(&added.bytes).expect("text"),
        );
        repo.put(INDEX_PATH, &index.render().expect("a valid index"));

        let cx = outer(&loaded).lane_cx(Mode::Hosted, HubId(0));
        let cx = cx.expect("a lane context");
        assert_eq!(cx.index, &Index::default());
        assert!(!cx.ws.ignore.covers(line.as_str()));
        assert_eq!(cx.files.read(BAZELIGNORE), FileText::Absent);
        // Told of the write, the loader hands out all three as they are.
        loader.committed(&repo.top);
        let loaded = loader.load(&repo.top);
        let cx = outer(&loaded).lane_cx(Mode::Hosted, HubId(0));
        let cx = cx.expect("a lane context");
        assert_eq!(cx.index, &index);
        assert!(cx.ws.ignore.covers(line.as_str()));
        assert_eq!(cx.files.read(BAZELIGNORE), FileText::Bytes(added.bytes));
    }

    /// Wave 4 is inert: whatever a command says about its run, no tool is
    /// run, and that is what every lane is told.
    #[test]
    fn no_tool_run_is_allowed_whatever_the_run() {
        for bits in 0..8u8 {
            let [read_only, dry_run, offline] = [1, 2, 4].map(|bit| bits & bit != 0);
            let run = RunCx {
                read_only,
                dry_run,
                offline,
            };
            assert_eq!(run_policy(&run), RunPolicy::Never, "{run:?}");
        }
    }

    #[test]
    fn a_workspace_is_described_once_by_its_root_line_and_rulesets() {
        let repo = Repo::new(&[JS_MODULE, PNPM_LOCK, BAZEL_9, ("app/package.json", "{}")]);
        let loader = Loader::new(RunCx::default());
        for project in ["", "app", ""] {
            loader.load(&repo.at(project));
        }
        let at = repo.top.display();
        let out_of_scope = format!(
            "Bazel workspace {at} declares 1 Bazel module. Socket patches cover registry \
             packages, so these dependencies are not examined"
        );
        let want = [
            (
                Code::WorkspaceDetected,
                format!(
                    "Bazel workspace {at} (Bazel 9.3.2 from .bazelversion, supported; Bzlmod): \
                     rules_js builds npm packages from pnpm-lock.yaml"
                ),
            ),
            (Code::WorkspaceOutOfScope, out_of_scope),
        ];
        assert_eq!(repo.said(&loader), want);

        // No pinned Bazel, a launcher wrapper and an rc file nobody
        // committed: each is said, and none refuses anything by itself.
        let rc = (".bazelrc", "try-import %workspace%/user.bazelrc\n");
        let repo = Repo::new(&[JS_MODULE, PNPM_LOCK, rc, ("tools/bazel", "#!/bin/sh\n")]);
        let loader = Loader::new(RunCx::default());
        loader.load(&repo.top);
        let said = repo.said(&loader);
        let want = [
            "bazel_workspace_version_untested",
            "bazel_workspace_rc_unread",
            "bazel_workspace_rc_unread",
            "bazel_workspace_detected",
            "bazel_workspace_out_of_scope",
        ];
        assert_eq!(Repo::codes(&said), want, "{said:?}");
        assert!(said[1].1.contains("user.bazelrc") && said[2].1.contains("tools/bazel"));

        // An `import` of an rc file that is missing is an rc file that
        // was not read. It is no workspace file that cannot be read.
        let rc = (".bazelrc", "import %workspace%/missing.bazelrc\n");
        let repo = Repo::new(&[JS_MODULE, PNPM_LOCK, BAZEL_9, rc]);
        let loader = Loader::new(RunCx::default());
        loader.load(&repo.top);
        let said = repo.said(&loader);
        let want = [
            "bazel_workspace_rc_unread",
            "bazel_workspace_detected",
            "bazel_workspace_out_of_scope",
        ];
        assert_eq!(Repo::codes(&said), want, "{said:?}");
        assert!(said[0].1.contains("missing.bazelrc"), "{said:?}");

        // Bazel 4 is said once as unsupported, not also as untested.
        let repo = Repo::new(&[JS_WORKSPACE, PNPM_LOCK, (".bazelversion", "4.2.4\n")]);
        let loader = Loader::new(RunCx::default());
        loader.load(&repo.top);
        let said = repo.said(&loader);
        let want = [
            "bazel_workspace_version_unsupported",
            "bazel_workspace_detected",
        ];
        assert_eq!(Repo::codes(&said), want, "{said:?}");
        assert!(said[0].1.contains("Bazel 4 and older are"), "{said:?}");

        // So is Bzlmod on Bazel 5, where it is an experiment.
        let repo = Repo::new(&[JS_MODULE, PNPM_LOCK, (".bazelversion", "5.4.1\n")]);
        let loader = Loader::new(RunCx::default());
        loader.load(&repo.top);
        let said = repo.said(&loader);
        let want = [
            "bazel_workspace_version_unsupported",
            "bazel_workspace_detected",
            "bazel_workspace_out_of_scope",
        ];
        assert_eq!(Repo::codes(&said), want, "{said:?}");
        assert!(said[0].1.contains("Bzlmod on Bazel 5 is"), "{said:?}");

        // A root where Bazel builds no registry package says nothing of
        // its Bazel version, pinned or not.
        let repo = Repo::new(&[("MODULE.bazel", "module(name = \"plain\")\n")]);
        let loader = Loader::new(RunCx::default());
        loader.load(&repo.top);
        assert_eq!(repo.said(&loader), []);
    }

    /// The text of the one `bazel_workspace_detected` line of a load.
    fn detected(repo: &Repo, project: &str) -> String {
        let loader = Loader::new(RunCx::default());
        loader.load(&repo.at(project));
        let said = repo.said(&loader);
        let mut found = said
            .iter()
            .filter(|(code, _)| *code == Code::WorkspaceDetected);
        let (Some((_, detail)), None) = (found.next(), found.next()) else {
            panic!("one detected line, not {said:?}");
        };
        let at = format!("Bazel workspace {} ", repo.top.display());
        let detail = detail.strip_prefix(&at);
        detail.expect("the line names the root").to_string()
    }

    /// The note never says that Bazel builds from the lock of a hub it
    /// does not evaluate, and calls a Bazel release unsupported only when
    /// the release is what is refused.
    #[test]
    fn a_hub_bazel_does_not_evaluate_is_described_as_declared_and_unused() {
        let dead = "rules_js is declared in WORKSPACE for npm packages from";
        let no_workspace = "and Bazel does not build from that declaration: this Bazel \
                            configuration evaluates no WORKSPACE file";
        // A WORKSPACE hub left beside a MODULE.bazel that declares none,
        // on a Bazel that reads no WORKSPACE file.
        let plain = ("MODULE.bazel", "module(name = \"plain\")\n");
        let repo = Repo::new(&[plain, JS_WORKSPACE, PNPM_LOCK, BAZEL_9]);
        let want = format!(
            "(Bazel 9.3.2 from .bazelversion, WORKSPACE declarations refused, Bazel 9 and newer \
             read none; Bzlmod): {dead} pnpm-lock.yaml, {no_workspace}"
        );
        assert_eq!(detected(&repo, ""), want);

        // The same hub beside a live one: each is described as it stands.
        let legacy = JS_WORKSPACE.1.replace("//:pnpm", "//legacy:pnpm");
        let repo = Repo::new(&[JS_MODULE, ("WORKSPACE", &legacy), PNPM_LOCK, BAZEL_9]);
        repo.put("legacy/pnpm-lock.yaml", PNPM_LOCK.1);
        repo.put("legacy/BUILD.bazel", "");
        let want = format!(
            "(Bazel 9.3.2 from .bazelversion, supported; Bzlmod): rules_js builds npm packages \
             from pnpm-lock.yaml; {dead} legacy/pnpm-lock.yaml, {no_workspace}"
        );
        assert_eq!(detected(&repo, "legacy"), want);

        // A MODULE.bazel hub on Bazel 5, which reads no MODULE.bazel.
        let repo = Repo::new(&[JS_MODULE, PNPM_LOCK, (".bazelversion", "5.4.1\n")]);
        let want = "(Bazel 5.4.1 from .bazelversion, not supported; WORKSPACE): rules_js is \
                    declared in MODULE.bazel for npm packages from pnpm-lock.yaml, and Bazel does \
                    not build from that declaration: Bzlmod is off, so Bazel never reads \
                    MODULE.bazel";
        assert_eq!(detected(&repo, ""), want);

        // No pinned release: the WORKSPACE hub may be built from or not.
        let repo = Repo::new(&[JS_WORKSPACE, PNPM_LOCK]);
        let said = detected(&repo, "");
        let tier = "(Bazel unknown, WORKSPACE declarations refused, no Bazel release is pinned; ";
        assert!(said.starts_with(tier), "{said}");
        let hub = "): rules_js may build npm packages from pnpm-lock.yaml";
        assert!(said.ends_with(hub), "{said}");
    }

    /// A root whose only hub is a shape socket-patch reports and does not
    /// patch is a workspace all the same: governance answers for its
    /// ecosystem, so the run says what it found and what Bazel runs.
    #[test]
    fn a_report_only_hub_is_described_with_the_bazel_that_reads_it() {
        let poetry = (
            "WORKSPACE",
            "load(\"@com_sonia_rules_poetry//rules_poetry:poetry.bzl\", \"poetry\")\n\
             poetry(name = \"poetry\", lockfile = \"//:poetry.lock\", \
             pyproject = \"//:pyproject.toml\")\n",
        );
        let repo = Repo::new(&[
            poetry,
            ("poetry.lock", "# empty\n"),
            ("pyproject.toml", "[tool.poetry]\n"),
            (".bazelversion", "4.2.4\n"),
            ("tools/bazel", "#!/bin/sh\n"),
        ]);
        let loader = Loader::new(RunCx::default());
        let loaded = loader.load(&repo.top);
        let governed = Governance::Governed(vec![HubId(0)]);
        assert_eq!(loaded.governance(Ecosystem::Pypi), governed);
        let said = repo.said(&loader);
        let want = [
            "bazel_workspace_version_unsupported",
            "bazel_workspace_rc_unread",
            "bazel_workspace_detected",
        ];
        assert_eq!(Repo::codes(&said), want, "{said:?}");
        assert!(said[1].1.contains("tools/bazel"), "{said:?}");
        let want = format!(
            "Bazel workspace {} (Bazel 4.2.4 from .bazelversion, not supported; WORKSPACE): \
             rules_poetry (recognized, not patched) builds python packages from poetry.lock",
            repo.top.display()
        );
        assert_eq!(said[2].1, want);
    }

    #[test]
    fn a_workspace_file_above_the_repository_is_reported_and_never_read() {
        for confirmed in [true, false] {
            // The outer file would be unreadable, were it read.
            let outer = Repo::new(&[("WORKSPACE", "\tx = 1\n"), ("repo/app/package.json", "{}")]);
            outer.put("repo/.git/HEAD", "ref: refs/heads/main\n");
            if confirmed {
                outer.put(".bazelversion", "7.7.2\n");
            }
            let loader = Loader::new(RunCx::default());
            let marker = outer.at("WORKSPACE");
            let probe = Probe::RootOutsideBoundary {
                marker: marker.clone(),
                confirmed,
            };
            assert_eq!(loader.probe(&outer.at("repo/app")), probe);
            let loaded = loader.load(&outer.at("repo/app"));
            loader.load(&outer.at("repo"));
            assert!(loaded.models().is_empty());
            assert_eq!(loaded.above().map(|above| &above.marker), Some(&marker));
            let npm = loaded.governance(Ecosystem::Npm);
            match confirmed {
                true => assert!(matches!(npm, Governance::Undetermined(_)), "{npm:?}"),
                false => assert_eq!(npm, Governance::NotGoverned),
            }
            let said = outer.said(&loader);
            let [(Code::WorkspaceAboveRepo, detail)] = said.as_slice() else {
                panic!("one warning for the two projects, not {said:?}");
            };
            assert!(
                detail.starts_with(&marker.display().to_string()),
                "{detail}"
            );
            assert_eq!(detail.contains("refused"), confirmed, "{detail}");
        }
        // A marker inside the read boundary is the probe's answer for a
        // project it cannot place: no file above the repository to remove.
        let above = MarkerAbove {
            marker: PathBuf::from("MODULE.bazel"),
            confirmed: true,
        };
        let unplaced = above_warning(&above, false);
        assert_eq!(unplaced.code, Code::WorkspaceUnreadable);
        assert!(!unplaced.detail.contains("remove"), "{}", unplaced.detail);
        // Which of the two a marker is, by the paths alone: above the
        // boundary, or the probe's answer at a root inside it. A relative
        // one is what the probe gives back when it could not resolve the
        // project, and an unbounded run has nothing above.
        let repo = Repo::new(&[]);
        let boundary = ReadBoundary::Workspace {
            root: repo.at("repo"),
        };
        assert!(is_outside(&boundary, &repo.at("WORKSPACE")));
        assert!(!is_outside(&boundary, &repo.at("repo/MODULE.bazel")));
        assert!(!is_outside(&boundary, &repo.at("repo/ws/MODULE.bazel")));
        assert!(!is_outside(&boundary, Path::new("MODULE.bazel")));
        assert!(!is_outside(&ReadBoundary::Unbounded, &repo.at("WORKSPACE")));
    }

    /// A workspace file above the repository that is a link to a file
    /// inside it is above the repository all the same: where it lies is
    /// decided by its path, not by where the link leads. (Unix only:
    /// creating a link on Windows needs a privilege the test may not have.)
    #[cfg(unix)]
    #[test]
    fn a_linked_workspace_file_above_the_repository_is_still_above_it() {
        for confirmed in [true, false] {
            let target = "repo/tools/WORKSPACE.outer";
            let outer = Repo::new(&[(target, "\tx = 1\n"), ("repo/app/package.json", "{}")]);
            outer.put("repo/.git/HEAD", "ref: refs/heads/main\n");
            if confirmed {
                outer.put(".bazelversion", "7.7.2\n");
            }
            let marker = outer.at("WORKSPACE");
            std::os::unix::fs::symlink(outer.at(target), &marker).expect("a link");
            let loader = Loader::new(RunCx::default());
            let loaded = loader.load(&outer.at("repo/app"));
            let probe = Probe::RootOutsideBoundary {
                marker: marker.clone(),
                confirmed,
            };
            assert_eq!(loaded.probe(), probe);
            let npm = loaded.governance(Ecosystem::Npm);
            match confirmed {
                true => assert!(matches!(npm, Governance::Undetermined(_)), "{npm:?}"),
                false => assert_eq!(npm, Governance::NotGoverned),
            }
            // The warning says what governance does: a remedy where it
            // refuses, and "changes nothing" where it does not.
            let said = outer.said(&loader);
            let [(Code::WorkspaceAboveRepo, detail)] = said.as_slice() else {
                panic!("the file is above the repository, not {said:?}");
            };
            assert!(
                detail.starts_with(&marker.display().to_string()),
                "{detail}"
            );
            assert_eq!(detail.contains("refused"), confirmed, "{detail}");
        }
    }

    /// The other answer of the same probe value, end to end: a project the
    /// probe cannot place under a root inside the boundary. (Linux only:
    /// the disks of macOS and Windows refuse a name that is not Unicode.)
    #[cfg(target_os = "linux")]
    #[test]
    fn a_project_no_text_can_name_under_its_root_is_unreadable_and_not_above() {
        use std::os::unix::ffi::OsStrExt as _;
        let repo = Repo::new(&[JS_MODULE, PNPM_LOCK, BAZEL_9]);
        let odd = repo.top.join(std::ffi::OsStr::from_bytes(b"caf\xe9"));
        let project = odd.join("app");
        std::fs::create_dir_all(&project).expect("a directory whose name is not UTF-8");
        let loader = Loader::new(RunCx::default());
        let loaded = loader.load(&project);
        assert!(loaded.models().is_empty());
        let npm = loaded.governance(Ecosystem::Npm);
        assert!(matches!(npm, Governance::Undetermined(_)), "{npm:?}");
        let said = repo.said(&loader);
        let [(Code::WorkspaceUnreadable, detail)] = said.as_slice() else {
            panic!("the project cannot be placed, not {said:?}");
        };
        let named = repo.at("MODULE.bazel").display().to_string();
        assert!(detail.contains(&named), "{detail}");
        assert!(!detail.contains("remove"), "{detail}");
    }

    /// Every project with no root inside its read boundary has the same
    /// roots, none. What lies above the boundary tells them apart, so it
    /// is part of what a load is kept by: a project under a workspace
    /// somebody builds above its repository must not be handed the load
    /// of an unrelated checkout that was asked about first.
    #[test]
    fn projects_with_no_root_inside_are_told_apart_by_what_lies_above() {
        let checkout = |files: &[(&str, &str)]| {
            let repo = Repo::new(files);
            repo.put("repo/.git/HEAD", "ref: refs/heads/main\n");
            repo.put("repo/app/package.json", "{}");
            repo
        };
        let plain = checkout(&[]);
        let built = checkout(&[("WORKSPACE", "\tx = 1\n"), (".bazelversion", "7.7.2\n")]);
        for built_first in [true, false] {
            let loader = Loader::new(RunCx::default());
            let load = |repo: &Repo| loader.load(&repo.at("repo/app"));
            let (at_plain, at_built) = match built_first {
                true => {
                    let at_built = load(&built);
                    (load(&plain), at_built)
                }
                false => (load(&plain), load(&built)),
            };
            assert!(!Arc::ptr_eq(&at_plain, &at_built));
            // A stray workspace file above the temporary directory of
            // this machine may be reported for `plain`: it is never a
            // workspace somebody builds above `repo`, which is what makes
            // an ecosystem undetermined.
            let npm = |loaded: &Loaded| loaded.governance(Ecosystem::Npm);
            let (on_plain, on_built) = (npm(&at_plain), npm(&at_built));
            let undetermined = |found: &Governance| matches!(found, Governance::Undetermined(_));
            assert!(undetermined(&on_built), "{on_built:?}");
            assert!(!undetermined(&on_plain), "{on_plain:?}");
        }
    }

    /// A root with no model, over made-up values: `detect` gives none only
    /// when the view shows no boundary file where the probe saw one, and
    /// the two agree on every kind of file, so no disk produces the case
    /// short of a race. It is unreadable, and never "Bazel builds nothing
    /// here".
    #[test]
    fn a_root_with_no_model_is_unreadable_and_never_ungoverned() {
        let root = RootRef {
            root: PathBuf::from("nowhere"),
            project_rel: String::new(),
            boundary_levels: 0,
        };
        let gap = Gap {
            token: WORKSPACE_UNREADABLE,
            file: String::new(),
            detail: "the root holds no workspace file that can be read".to_string(),
        };
        let model: Result<BazelWorkspace, Gap> = Err(gap.clone());
        let mut said = Vec::new();
        model_warnings(&root, &model, &mut said);
        let want = Warning {
            code: Code::WorkspaceUnreadable,
            detail: gap.detail.clone(),
        };
        assert_eq!(said, [want]);

        let loaded = Loaded {
            survey: Survey {
                roots: vec![root.clone()],
                above: None,
            },
            states: vec![Arc::new(RootState::new(&root))],
            models: vec![model],
            run: RunPolicy::Never,
        };
        let no_cx = outer(&loaded).lane_cx(Mode::Hosted, HubId(0)).err();
        assert_eq!(no_cx, Some(NoLaneCx::Workspace(&gap)));
        for (ecosystem, governance) in loaded.governed() {
            let undetermined = matches!(governance, Governance::Undetermined(_));
            assert!(undetermined, "{ecosystem:?}: {governance:?}");
        }
    }

    #[test]
    fn every_nested_root_is_loaded_over_its_own_view() {
        let inner = JS_MODULE
            .1
            .replace("//:pnpm-lock.yaml", "//inner:pnpm-lock.yaml");
        let repo = Repo::new(&[
            ("MODULE.bazel", &inner),
            BAZEL_9,
            ("inner/pnpm-lock.yaml", PNPM_LOCK.1),
        ]);
        repo.put("inner/MODULE.bazel", "module(name = \"inner\")\n");
        repo.put("inner/BUILD.bazel", "");
        let loader = Loader::new(RunCx::default());
        let loaded = loader.load(&repo.at("inner"));
        assert!(matches!(loaded.probe(), Probe::Nested(_)));
        let roots: Vec<LoadedRoot<'_>> = loaded.roots().collect();
        let rels: Vec<&str> = roots
            .iter()
            .map(|r| r.root().project_rel.as_str())
            .collect();
        assert_eq!(rels, ["", "inner"]);
        assert!(!std::ptr::eq(roots[0].files(), roots[1].files()));
        assert_eq!(
            (roots[0].files().root(), roots[1].files().root()),
            (repo.at("inner").as_path(), repo.top.as_path())
        );
        let hubs = roots.iter().map(|r| r.model().map(|ws| ws.hubs.len()).ok());
        assert_eq!(hubs.collect::<Vec<_>>(), [Some(0), Some(1)]);
        // The outer root builds the project from a lock the inner root
        // does not name: the roots disagree, and neither is taken alone.
        let npm = loaded.governance(Ecosystem::Npm);
        assert!(matches!(npm, Governance::Ambiguous(_)), "{npm:?}");
        // The outer root is one view for both projects.
        let at_top = loader.load(&repo.top);
        assert!(std::ptr::eq(outer(&at_top).files(), roots[1].files()));
    }

    fn fixture_roots(dir: &Path, out: &mut Vec<PathBuf>) {
        if boundary_file_in(dir).is_some() {
            return out.push(dir.to_path_buf());
        }
        for entry in std::fs::read_dir(dir).expect("list fixtures").flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                fixture_roots(&entry.path(), out);
            }
        }
    }

    /// The loader changes nothing about what is read. Over the committed
    /// fixture workspaces, the model it hands out is the model a read of
    /// that root and project through another view gives: for a project it
    /// reads the root for, and for one whose model it makes from a copy.
    #[test]
    fn a_loaded_model_is_the_model_of_a_fresh_read() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let fixtures = fixtures.join("fixtures").join("bazel");
        let mut dirs = Vec::new();
        fixture_roots(&fixtures, &mut dirs);
        // One cell of each ruleset and dependency system. Its other cells
        // differ in versions, which nothing about a project depends on.
        dirs.sort();
        dirs.dedup_by(|cell, kept| cell.parent() == kept.parent());
        assert!(dirs.len() >= 15, "only {} fixture families", dirs.len());
        let loader = Loader::new(RunCx::default());
        for dir in &dirs {
            // Projects that need not exist: a load judges a directory by
            // where it would be created. The third is the first whose
            // model is a copy.
            let projects = [vec![], vec!["sp-a"], vec!["sp-b", "deep"]];
            let loads = projects.map(|levels| {
                let project = levels.iter().fold(dir.clone(), |at, level| at.join(level));
                (levels.join("/"), loader.load(&project))
            });
            let root = outer(&loads[0].1);
            let models = root.state.models.lock().expect("the models");
            let kept = (models.reads, models.kept.len());
            assert_eq!(kept, (2, 1), "{}: three projects, two reads", dir.display());
            let fresh = DiskView::new(root.root());
            for (project, loaded) in [&loads[0], &loads[2]] {
                let seen = outer(loaded);
                let shown = format!("`{project}` of {}", dir.display());
                assert!(std::ptr::eq(seen.files(), root.files()), "{shown}");
                assert_eq!(&seen.root().project_rel, project, "{shown}");
                let read = read_workspace(seen.root(), &fresh);
                assert_eq!(seen.model(), read.as_ref(), "{shown}");
            }
        }
    }

    /// A root whose sub-projects each pin their own Bazel is read once for
    /// each, and each read is a model as large as the lock it parsed: a
    /// root keeps a few of them, and the one that keeps being used.
    #[test]
    fn a_root_keeps_a_few_models_whatever_its_projects_pin() {
        let repo = Repo::new(&[JS_MODULE, PNPM_LOCK, BAZEL_9]);
        let pinned = KEPT_MODELS + 3;
        for project in 0..pinned {
            repo.put(&format!("pinned{project}/.bazelversion"), "9.3.2\n");
        }
        let loader = Loader::new(RunCx::default());
        let at_root = loader.load(&repo.top);
        let root = outer(&at_root);
        let fresh = DiskView::new(root.root());
        let load = |project: String| {
            let loaded = loader.load(&repo.at(&project));
            let seen = outer(&loaded);
            assert_eq!(seen.root().project_rel, project);
            let read = read_workspace(seen.root(), &fresh);
            assert_eq!(seen.model(), read.as_ref(), "`{project}`");
        };
        // The second project with the root's own launcher files is read,
        // and its read is the copy for the others.
        load("plain".to_string());
        for project in 0..pinned {
            // Its own `.bazelversion`: another launcher set, another read.
            load(format!("pinned{project}"));
            // The copy that was just used is not the one that goes.
            load(format!("plain{project}"));
        }
        let models = root.state.models.lock().expect("the models");
        let kept = (models.reads, models.kept.len());
        assert_eq!(kept, (pinned + 2, KEPT_MODELS));
    }

    /// The loader cannot see a commit of its own run, so the seam that
    /// commits tells it. Two projects of one root add their lines to the
    /// root's `.bazelignore` in turn, each through a transaction over the
    /// files the loader hands out: without the call the second reads the
    /// files of before the first commit and writes its line and row away.
    #[test]
    fn a_commit_is_followed_once_the_loader_is_told_of_it() {
        let apps = [("app1/package.json", "{}"), ("app2/package.json", "{}")];
        let repo = Repo::new(&[JS_MODULE, PNPM_LOCK, BAZEL_9, apps[0], apps[1]]);
        let loader = Loader::new(RunCx::default());
        // Held across both commits.
        let before = loader.load(&repo.at("app1"));
        let mut lines = Vec::new();
        for project in ["app1", "app2"] {
            let loaded = loader.load(&repo.at(project));
            let root = outer(&loaded);
            let IndexState::Ours(index) = root.index() else {
                panic!("{project}: a faulty index");
            };
            let mut index = index.clone();
            let mut txn = Overlay::new(root.files());
            let line = IgnoreLine::new(project, SocketTree::Vendor).expect("a line");
            let added = ignore::insert(&txn.read(BAZELIGNORE), std::slice::from_ref(&line));
            let added = added.expect("an edit").expect("a line to add");
            index.record_lines(added.rows);
            txn.write(BAZELIGNORE, added.bytes);
            txn.write(
                INDEX_PATH,
                index.render().expect("a valid index").into_bytes(),
            );
            repo.land(&txn);
            loader.committed(&root.root().root);
            lines.push(line);
        }
        let both = "app1/.socket/vendor\napp2/.socket/vendor\n";
        assert_eq!(repo.get(BAZELIGNORE), both);

        let after = loader.load(&repo.at("app1"));
        let root = outer(&after);
        let IndexState::Ours(index) = root.index() else {
            panic!("a faulty index");
        };
        let recorded: Vec<&IgnoreLine> = index.ignore_lines.iter().map(|row| &row.line).collect();
        assert_eq!(recorded, lines.iter().collect::<Vec<_>>());
        let model = root.model().expect("a model");
        assert!(lines.iter().all(|line| model.ignore.covers(line.as_str())));
        assert_eq!(
            root.files().read(BAZELIGNORE).as_bytes(),
            Some(both.as_bytes())
        );

        // The load held from before the commits is the root as it was:
        // no row, no line, and no base for a transaction.
        assert!(!Arc::ptr_eq(&before, &after));
        let old = outer(&before);
        assert_eq!(old.index(), &IndexState::Ours(Index::default()));
        assert_eq!(old.files().read(BAZELIGNORE), FileText::Absent);
        assert!(!old
            .model()
            .expect("a model")
            .ignore
            .covers(lines[0].as_str()));
        // `refresh` catches up with the rows of another writer only over
        // a transaction that reads the disk.
        let mut held = Index::default();
        exec::refresh(&mut held, &Overlay::new(old.files())).expect("an index");
        assert_eq!(held, Index::default());
        exec::refresh(&mut held, &Overlay::new(root.files())).expect("an index");
        assert_eq!(&held, index);

        // A commit under a project is a commit under every root above it,
        // however the directory is spelled.
        loader.committed(&repo.tmp.path().join("app2"));
        assert!(!Arc::ptr_eq(&after, &loader.load(&repo.at("app1"))));
        // Elsewhere, nothing that was read is dropped. What was read
        // here is let go, where no caller holds it.
        let other = Repo::new(&[JS_MODULE, PNPM_LOCK, BAZEL_9]);
        let at_other = loader.load(&other.top);
        let at_app1 = Arc::downgrade(&loader.load(&repo.at("app1")));
        assert!(
            at_app1.upgrade().is_some(),
            "the loader keeps the last loads"
        );
        loader.committed(&repo.top);
        assert!(Arc::ptr_eq(&at_other, &loader.load(&other.top)));
        assert!(at_app1.upgrade().is_none(), "a load of before the commit");
    }

    /// A load held across a commit is the root as it was, for every file
    /// (ROUTED R-136). What it had read it still answers; what it is
    /// asked for the first time after the commit it does not read, so no
    /// byte of after the commit is judged beside its model. Only the root
    /// the commit touched is closed.
    #[test]
    fn a_load_of_before_a_commit_reads_nothing_of_after_it() {
        let repo = Repo::new(&[JS_MODULE, PNPM_LOCK, BAZEL_9, ("late.bzl", "X = 0\n")]);
        let other = Repo::new(&[JS_MODULE, PNPM_LOCK, BAZEL_9, ("late.bzl", "X = 0\n")]);
        let loader = Loader::new(RunCx::default());
        let before = loader.load(&repo.top);
        let elsewhere = loader.load(&other.top);
        let old = outer(&before);
        let lock = old.files().read(PNPM_LOCK.0);
        assert_eq!(lock.as_bytes(), Some(PNPM_LOCK.1.as_bytes()));
        assert!(!old.files().is_frozen());

        // The commit of a seam: the lock, and two files nobody has read.
        repo.put(PNPM_LOCK.0, "lockfileVersion: 'after'\n");
        repo.put("late.bzl", "X = 1\n");
        repo.put("new.bzl", "Y = 1\n");
        loader.committed(&repo.top);

        assert!(old.files().is_frozen());
        assert_eq!(old.files().read(PNPM_LOCK.0), lock);
        for unread in ["late.bzl", "new.bzl", "never.bzl"] {
            assert_eq!(old.files().read(unread), FileText::Unreadable, "{unread}");
        }
        assert_eq!(old.files().list("never"), None);
        // The next load reads the disk.
        let after = loader.load(&repo.top);
        let new = outer(&after);
        assert!(!new.files().is_frozen());
        assert_eq!(
            new.files().read("late.bzl").as_bytes(),
            Some(&b"X = 1\n"[..])
        );
        assert_eq!(new.files().read("never.bzl"), FileText::Absent);
        // A root the commit did not touch is read as before.
        let untouched = outer(&elsewhere);
        assert!(!untouched.files().is_frozen());
        assert_eq!(
            untouched.files().read("late.bzl").as_bytes(),
            Some(&b"X = 0\n"[..])
        );
    }

    /// A load that was read while a commit landed is of neither side of
    /// it: it is not kept, and the project is read again.
    #[test]
    fn a_load_read_across_a_commit_is_not_kept() {
        let repo = Repo::new(&[JS_MODULE, PNPM_LOCK, BAZEL_9]);
        let loader = Loader::new(RunCx::default());
        let survey = loader.survey(&repo.top);
        let key = project_key(&survey);
        let Err(commits) = loader.held(&key) else {
            panic!("nothing is loaded yet");
        };
        let read = Arc::new(loader.read(survey.clone()));
        loader.committed(&repo.top);
        assert!(loader.keep(&key, Arc::clone(&read), commits).is_none());
        let loaded = loader.load(&repo.top);
        assert!(!Arc::ptr_eq(&read, &loaded));
        assert!(!std::ptr::eq(outer(&read).files(), outer(&loaded).files()));
        // With no commit in between, a read is what the project keeps.
        let survey = loader.survey(&repo.at("app"));
        let key = project_key(&survey);
        let Err(commits) = loader.held(&key) else {
            panic!("nothing is loaded for the project yet");
        };
        let read = Arc::new(loader.read(survey));
        let kept = loader.keep(&key, Arc::clone(&read), commits);
        assert!(kept.is_some_and(|kept| Arc::ptr_eq(&kept, &read)));
        assert!(Arc::ptr_eq(&read, &loader.load(&repo.at("app"))));
    }

    /// A model can be as large as the lock it parsed: the loader keeps the
    /// last few loads alive, and the rest only while a caller holds them.
    #[test]
    fn the_loader_keeps_the_last_loads_and_no_more() {
        let repo = Repo::new(&[JS_MODULE, PNPM_LOCK, BAZEL_9]);
        let loader = Loader::new(RunCx::default());
        let load = |project: usize| loader.load(&repo.at(&format!("p{project}")));
        let held = load(0);
        let dropped = Arc::downgrade(&load(1));
        let later = (2..KEPT + 3).map(|project| Arc::downgrade(&load(project)));
        let last = later.last().expect("a load");
        assert!(dropped.upgrade().is_none(), "kept past the last {KEPT}");
        assert!(last.upgrade().is_some(), "the last load is kept");
        assert!(Arc::ptr_eq(&held, &load(0)), "a held load is the one");
        // A project that was let go is loaded again, to the same model.
        let again = load(1);
        assert_eq!(outer(&again).root().project_rel, "p1");
        assert_eq!(
            outer(&again).model().map(|ws| &ws.hubs),
            outer(&held).model().map(|ws| &ws.hubs)
        );
    }

    /// The detection note names a workspace that may run under several
    /// dependency systems by each of them, in words that group one way.
    #[test]
    fn a_dual_mode_workspace_is_named_by_each_system_it_may_run() {
        let dual = |systems: &[DepSystem]| {
            system_words(&DepSystem::DualMode {
                systems: systems.to_vec(),
                why: String::new(),
            })
        };
        assert_eq!(system_words(&DepSystem::Hybrid), "Bzlmod and WORKSPACE");
        assert_eq!(
            dual(&[DepSystem::Workspace, DepSystem::Hybrid, DepSystem::Bzlmod]),
            "dependency system not decided: WORKSPACE, Bzlmod and WORKSPACE together, or Bzlmod"
        );
        assert_eq!(
            dual(&[DepSystem::Bzlmod, DepSystem::Hybrid]),
            "dependency system not decided: Bzlmod or Bzlmod and WORKSPACE together"
        );
        assert_eq!(
            dual(&[DepSystem::Neither]),
            "dependency system not decided: no dependency system"
        );
    }

    #[test]
    fn tasks_that_ask_about_one_project_share_one_load() {
        fn shared<T: Send + Sync>() {}
        shared::<Loader>();
        shared::<Arc<Loaded>>();
        let repo = Repo::new(&[JS_MODULE, PNPM_LOCK, BAZEL_9]);
        let loader = Loader::new(RunCx::default());
        let loads: Vec<Arc<Loaded>> = std::thread::scope(|scope| {
            let tasks: Vec<_> = (0..4)
                .map(|_| scope.spawn(|| loader.load(&repo.top)))
                .collect();
            tasks
                .into_iter()
                .map(|task| task.join().expect("a load"))
                .collect()
        });
        assert!(loads.iter().all(|loaded| Arc::ptr_eq(loaded, &loads[0])));
        assert_eq!(repo.said(&loader).len(), 2, "said once, not once per task");
    }
}
