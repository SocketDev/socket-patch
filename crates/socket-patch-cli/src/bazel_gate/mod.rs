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
//! - [`Loader::load`] reads. Each Bazel root gets one `DiskView` for the
//!   run, so each file of a root is opened once, whichever project asks.
//!   There is a model per root **and project**: its Bazel line spans the
//!   launcher files from the project up to the root, bazelisk takes the
//!   `.bazelversion` nearest the directory it is started in, and governance
//!   answers only for the project a model was read for. Projects with the
//!   same Bazel launcher files share what was read (`detect::rebase`). The
//!   root's owned index is read once and handed out as [`IndexState`].
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
//! their files.

pub mod agent;
pub mod agent_go;
pub mod commands;
pub mod hosted;
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
    BazelWorkspace, Completeness, DepSystem, FileText, FileView, Gap, Governance, HubId, Index,
    LaneCx, LockRole, Mode, Probe, RootRef, Ruleset, RunPolicy, Tier,
};
use socket_patch_core::bazel::owned_index::{self, Parsed, INDEX_PATH};
use socket_patch_core::bazel::version::{LineEvidence, TierRefusal};
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

/// What the file at the owned index's path is. Read once per root: a row
/// another writer of the same run records later is caught up with through
/// `bazel::exec::refresh`.
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

/// What is read once per Bazel root, whichever project asks.
struct RootState {
    view: DiskView,
    index: OnceLock<IndexState>,
    /// How often the root was read, and the models kept for the projects
    /// that come after ([`RootState::model`]).
    models: Mutex<(usize, Vec<BazelWorkspace>)>,
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
    /// project holds one model; every later read leaves a copy from which
    /// the models of the projects after it are made.
    fn model(&self, root: &RootRef) -> Result<BazelWorkspace, Gap> {
        // Held across the read: a second project waits, then copies.
        let mut kept = self.models.lock().unwrap_or_else(PoisonError::into_inner);
        let made = |known: &BazelWorkspace| detect::rebase(known, root, &self.view);
        if let Some(model) = kept.1.iter().find_map(made) {
            return Ok(model);
        }
        let model = read_workspace(root, &self.view);
        if let (Ok(ws), true) = (&model, kept.0 > 0) {
            kept.1.push(ws.clone());
        }
        kept.0 += 1;
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

    /// The files of the root, as every project of the run reads them.
    pub fn files(&self) -> &'a DiskView {
        &self.state.view
    }

    /// The model read for this project. `Err` when no boundary file of the
    /// root could be read, which is never "no workspace".
    pub fn model(&self) -> Result<&'a BazelWorkspace, &'a Gap> {
        self.model.as_ref()
    }

    /// The root's owned index, read on the first call.
    pub fn index(&self) -> &'a IndexState {
        self.state.index()
    }

    /// What a lane function is handed for `hub` in `mode`: the model, the
    /// files, the index as it was read, and the run policy.
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
        // A marker the probe reports inside the boundary is its answer for
        // a project it could not place under the root there.
        let above = survey.above.iter();
        self.say(
            above
                .map(|a| above_warning(a, !boundary.contains(&a.marker)))
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
    /// holds it, and the loader holds the last few itself.
    pub fn load(&self, project_dir: &Path) -> Arc<Loaded> {
        let survey = self.survey(project_dir);
        let key = project_key(&survey);
        let held = |memo: &Memo| memo.projects.get(&key).and_then(Weak::upgrade);
        if let Some(known) = held(&self.memo()) {
            return known;
        }
        let loaded = Arc::new(self.read(survey));
        let mut memo = self.memo();
        // Another task may have loaded the project meanwhile: its load is
        // the one everybody shares.
        if let Some(known) = held(&memo) {
            return known;
        }
        memo.projects.insert(key, Arc::downgrade(&loaded));
        memo.recent.push_back(Arc::clone(&loaded));
        if memo.recent.len() > KEPT {
            memo.recent.pop_front();
        }
        loaded
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
fn system_words(system: &DepSystem) -> String {
    match system {
        DepSystem::Bzlmod => "Bzlmod".to_string(),
        DepSystem::Workspace => "WORKSPACE".to_string(),
        DepSystem::Hybrid => "Bzlmod and WORKSPACE".to_string(),
        DepSystem::Neither => "no dependency system".to_string(),
        DepSystem::DualMode { systems, .. } => {
            let each: Vec<String> = systems.iter().map(system_words).collect();
            format!("{}, not decided", each.join(" or "))
        }
        DepSystem::Unknown { .. } => "dependency system unknown".to_string(),
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

    // A ruleset socket-patch patches for: a report-only shape is counted
    // below and governs nothing.
    let patched = |ruleset: Ruleset| ruleset.ecosystem().is_some();
    let mut rulesets: Vec<String> = Vec::new();
    for hub in ws.hubs.iter().filter(|hub| patched(hub.ruleset)) {
        let locks = hub.locks.iter();
        let locks = locks.filter(|lock| lock.role == LockRole::PackageLock);
        let locks: Vec<&str> = locks
            .map(|lock| lock.path.as_deref().unwrap_or(&lock.label))
            .collect();
        let (name, packages) = (hub.ruleset.name(), hub.ecosystem.display_name());
        rulesets.push(match locks.is_empty() {
            true => format!("{name} builds {packages} packages"),
            false => format!(
                "{name} builds {packages} packages from {}",
                locks.join(", ")
            ),
        });
    }
    let signals = ws.signals.iter().filter(|signal| patched(signal.ruleset));
    rulesets.extend(signals.map(|signal| {
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
            Tier::Refused(_) => "not supported",
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
    use socket_patch_core::bazel::ignore::{IgnoreLine, IgnoreLineRow, SocketTree};
    use socket_patch_core::bazel::version::BazelVersion;
    use socket_patch_core::crawlers::bazel_root::boundary_file_in;

    const JS_MODULE: (&str, &str) = (
        "MODULE.bazel",
        "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
         npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
         npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
         use_repo(npm, \"npm\")\n",
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
        // What a run has read of a root is what it keeps seeing: the next
        // project of the root opens no file a second time.
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
        let cases: [(Option<&str>, Result<&Index, &str>); 4] = [
            (None, Ok(&Index::default())),
            (Some(&rendered), Ok(&recorded)),
            (
                Some("{\"ignoreLines\": [], \"pins\": []}\n"),
                Err("modified"),
            ),
            (Some("{\"name\": \"mine\"}\n"), Err("foreign")),
        ];
        for (file, want) in cases {
            let repo = Repo::new(&[JS_MODULE, PNPM_LOCK, BAZEL_9, ("app/package.json", "{}")]);
            file.into_iter().for_each(|text| repo.put(INDEX_PATH, text));
            let loader = Loader::new(RunCx::default());
            let (at_root, at_app) = (loader.load(&repo.top), loader.load(&repo.at("app")));
            let root = outer(&at_root);
            let cx = root.lane_cx(Mode::Hosted, HubId(0));
            match (root.index(), want) {
                (IndexState::Ours(index), Ok(want)) => {
                    assert_eq!(index, want);
                    let Ok(cx) = cx else {
                        panic!("{file:?}: no lane context");
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
                        IndexFault::Modified(_) => "modified",
                        IndexFault::Foreign => "foreign",
                        _ => "other",
                    };
                    assert_eq!(kind, want);
                    assert_eq!(cx.err(), Some(NoLaneCx::Index(fault)));
                }
                (found, want) => panic!("{file:?}: {found:?}, not {want:?}"),
            }
            // Read once: a later write is not seen, by any project of the root.
            repo.put(INDEX_PATH, "{}");
            assert!(std::ptr::eq(root.index(), outer(&at_app).index()));
        }
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
        let codes: Vec<&str> = said.iter().map(|(code, _)| code.as_str()).collect();
        let want = [
            "bazel_workspace_version_untested",
            "bazel_workspace_rc_unread",
            "bazel_workspace_rc_unread",
            "bazel_workspace_detected",
            "bazel_workspace_out_of_scope",
        ];
        assert_eq!(codes, want, "{said:?}");
        assert!(said[1].1.contains("user.bazelrc") && said[2].1.contains("tools/bazel"));

        // Bazel 4 is said once as unsupported, not also as untested.
        let workspace = (
            "WORKSPACE",
            "load(\"@aspect_rules_js//npm:repositories.bzl\", \"npm_translate_lock\")\n\
             npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n",
        );
        let repo = Repo::new(&[workspace, PNPM_LOCK, (".bazelversion", "4.2.4\n")]);
        let loader = Loader::new(RunCx::default());
        loader.load(&repo.top);
        let said = repo.said(&loader);
        let codes: Vec<&str> = said.iter().map(|(code, _)| code.as_str()).collect();
        let want = [
            "bazel_workspace_version_unsupported",
            "bazel_workspace_detected",
        ];
        assert_eq!(codes, want, "{said:?}");

        // A root where Bazel builds no registry package says nothing of
        // its Bazel version, pinned or not.
        let repo = Repo::new(&[("MODULE.bazel", "module(name = \"plain\")\n")]);
        let loader = Loader::new(RunCx::default());
        loader.load(&repo.top);
        assert_eq!(repo.said(&loader), []);
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
            let kept = (models.0, models.1.len());
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
