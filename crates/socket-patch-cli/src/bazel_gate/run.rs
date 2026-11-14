//! What follows a commit whose plan names a command (revision 4, 2.5 and
//! section 4, contract item 3): the one place a seam asks whether the
//! write it just landed stands.
//!
//! A gate that answers `ProceedAfter` hands its plan a command. Either the
//! build passes until the user has run it (works-after: the advisory names
//! it), or it does not, and then the command is part of the transaction:
//! socket-patch runs it, checks what it wrote, and takes everything back
//! when that fails. Which of the two holds is the gate's decision, made
//! from the run policy (`bazel_gate::run_policy`); a seam never looks at
//! it.
//!
//! The commit itself is [`land`]: the change set a run staged under a
//! Bazel root and the project's own commit, as one. A seam hands it what
//! it staged, the gate's outcome of each plan it carries out and its own
//! commit, and gets back "landed" or why nothing stayed written. The order
//! inside is fixed here, for every seam:
//!
//! 1. **The root's lock.** A commit that an interrupted run left at the
//!    root is finished as the lock is taken; the run then decided from
//!    files that have changed since, so nothing of it is written and what
//!    the replay did is returned for the run to say
//!    ([`Unlanded::Recovered`]).
//! 2. **The inert files of the project** ([`Staged::ahead`]): what is
//!    harmless without the pin and needed with it (an install-policy file
//!    beside the lock). Landed first, so an interruption after this step
//!    leaves the inert file and never the pin without it.
//! 3. **The commit anchored at the root**, journaled.
//! 4. **Each outcome is settled** ([`finish`]) before anything else of the
//!    project is written. A command that fails unwinds the anchored commit
//!    and the inert files, and the project's own commit is never started:
//!    the run leaves nothing written, with no part of the project's commit
//!    to take back.
//! 5. **The project's own commit.** A failure takes steps 2 and 3 back.
//!
//! An interruption between steps 3 and 5 leaves the pin and its record
//! without the project's other files, which are the pins of ecosystems
//! Bazel does not govern and a takeover's ledger: each is whole without
//! the other, and the next run finds the pin in place and writes the rest.
//!
//! This release runs no tool. The run policy is `Never`, so the gate
//! refuses every plan whose build would fail before its command, and the
//! runner every seam passes is [`NoRunner`], which starts nothing: with it
//! [`finish`] never answers `Unwind`, and a works-after pin stands as the
//! commit left it. The package that lands the tool runner replaces what
//! [`runner`] returns and the body of [`finish`] (the snapshot of the
//! tool's outputs, the time budget, the lane's static post-check, the
//! `runs` row) and changes no seam: every seam takes its runner from
//! [`runner`], and the unwind of a failed run is step 4 above.

use std::future::Future;
use std::path::{Path, PathBuf};

use socket_patch_core::bazel::govern::BAZEL_ROOT_OUTSIDE_REPOSITORY;
use socket_patch_core::bazel::model::{Actor, GateOutcome, RunRequired};
use socket_patch_core::patch::apply_lock::CommitRecovery;
use socket_patch_core::utils::bazel_root_writes::{lock_root, RootLock, ROOT_LOCK_WAIT};
use socket_patch_core::utils::group_commit::{
    commit_anchored, is_pending, land_ahead, left_replaced, restore_anchored, take_back,
    AnchoredChange, CommittedFile,
};
use socket_patch_core::utils::repo_root::{ReadBoundary, ReadScope};

/// The originals a commit anchored at a Bazel root replaced, kept until
/// [`finish`] has spoken: each file the commit wrote with the bytes it
/// held before (`utils::group_commit::commit_anchored` returns them, and
/// `restore_anchored` puts them back).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    root: PathBuf,
    files: Vec<CommittedFile>,
}

impl Captured {
    /// The originals of a commit that landed under `root`.
    pub fn new(root: impl Into<PathBuf>, files: Vec<CommittedFile>) -> Self {
        let root = root.into();
        Self { root, files }
    }

    /// The Bazel root the commit was anchored at: where a tool runs.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The files to put back, in the order the commit wrote them.
    pub fn files(&self) -> &[CommittedFile] {
        &self.files
    }
}

/// How one run of a plan's command ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunResult {
    /// The runner starts no tool: the command is left to the user.
    Left,
    /// The tool ran and what it wrote passed the lane's check.
    Ran,
    /// The tool could not be started, failed, ran out of time, or left
    /// output the lane's check does not accept. The text is for the
    /// user: no token, no URL.
    Failed(String),
}

/// Runs the one command of a plan at a Bazel root. A seam holds its runner
/// across the awaits of its commit, on whichever thread that resumes.
pub trait ToolRunner: Send + Sync {
    fn run(&self, root: &Path, run: &RunRequired) -> RunResult;
}

/// The runner of a release that runs no tool (run policy `Never`): every
/// command is left to the user, and nothing is spawned.
pub struct NoRunner;

impl ToolRunner for NoRunner {
    fn run(&self, _: &Path, _: &RunRequired) -> RunResult {
        RunResult::Left
    }
}

/// The runner of this release, for every seam: [`NoRunner`]. Like
/// `bazel_gate::run_policy`, this is the one place that changes when
/// socket-patch starts to run a lane's tool, and no seam names a runner
/// of its own.
pub fn runner() -> Box<dyn ToolRunner> {
    Box::new(NoRunner)
}

/// What a seam does once [`finish`] has spoken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finish {
    /// The commit stands for this outcome. The originals come back for
    /// the next outcome of the same commit; the seam drops them after
    /// the last.
    Keep(Captured),
    /// The command failed, and the build does not pass without it: the
    /// seam puts every original back (the whole commit, since its plans
    /// landed as one), reports `why` and leaves nothing written.
    Unwind { captured: Captured, why: String },
}

/// Settles one gate outcome whose plan a commit has landed (revision 4,
/// 2.5, steps 2 to 6).
///
/// An outcome with no command stands. A command the gate left to the user
/// stands too: the pin is written, the advisory names the command, and
/// `vex` waits for its evidence. Only a command the gate gave to
/// socket-patch is handed to `runner`, and only its failure unwinds.
///
/// [`land`] calls this for each outcome of the change set it lands. A
/// seam that commits in another way (an undo whose reverse check names a
/// command) calls it itself, between its anchored commit and whatever it
/// writes after.
pub fn finish(outcome: &GateOutcome, captured: Captured, runner: &dyn ToolRunner) -> Finish {
    let GateOutcome::ProceedAfter(_, run) = outcome else {
        return Finish::Keep(captured);
    };
    if run.actor == Actor::User {
        return Finish::Keep(captured);
    }
    match runner.run(captured.root(), run) {
        RunResult::Left | RunResult::Ran => Finish::Keep(captured),
        RunResult::Failed(why) => {
            let why = format!("`{}` failed: {why}", run.command);
            Finish::Unwind { captured, why }
        }
    }
}

/// What one run staged under one Bazel root: the finished change set of a
/// transaction over the root (the `changes()` of a `bazel::exec::Overlay`,
/// each path with the bytes the transaction read there), the paths the
/// plans it carries out capture (`bazel::exec::touched`), and what [`land`]
/// needs beside them.
#[derive(Debug, Clone, Copy)]
pub struct Staged<'a> {
    pub root: &'a Path,
    /// The project of the run relative to `root`, forward-slashed, `""`
    /// at the root. The root has to lie inside the directory socket-patch
    /// writes in for that project, or nothing is landed.
    pub project_rel: &'a str,
    pub touched: &'a [String],
    pub changes: &'a [AnchoredChange],
    /// The gate's outcome of each plan the change set carries out, in the
    /// order staged: each is settled by [`finish`] once the change set
    /// has landed and before the project's own commit is started.
    pub outcomes: &'a [&'a GateOutcome],
    /// The files of the project that are inert until the change set
    /// lands, by path relative to the project, with their bytes: landed
    /// ahead of it, straight on disk, and taken back when the run does
    /// not land. The project's own commit may hold them too, and then
    /// finds them written.
    pub ahead: &'a [(String, Vec<u8>)],
}

/// A run that landed: the root's lock, still held, the originals the
/// commit anchored there replaced, and what the project's own commit
/// returned. Every outcome is settled. The seam tells its loader of the
/// commit, and then lets the lock go.
pub struct Landed<T> {
    pub lock: RootLock,
    pub captured: Captured,
    pub project: T,
}

/// Why nothing of a run stayed written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unlanded<E> {
    /// The root's lock was not taken, an inert file could not be landed,
    /// or the commit anchored at the root refused or failed. The project's
    /// own commit was not run. `pending`: a replace failed and could not
    /// be undone, so the commit's journal is kept and the next run that
    /// locks the root finishes it (the inert files stay for it). `left`
    /// holds one line per inert file that could not be put back. With
    /// neither, nothing was changed.
    Root {
        why: String,
        pending: bool,
        left: Vec<String>,
    },
    /// Taking the root's lock finished, or set aside, a commit that an
    /// interrupted run had left there: files under the root were
    /// rewritten, and this run decided from what they held before. Nothing
    /// of this run was written. The report names the files the replay
    /// rewrote and a journal it set aside; the seam says it, since a
    /// replay is never silent.
    Recovered(CommitRecovery),
    /// A command that socket-patch ran for a plan failed. The commit
    /// anchored at the root and the inert files were taken back, and the
    /// project's own commit was not run. `left` holds one line per file
    /// that could not be put back; empty when the tree is as it was.
    Run { why: String, left: Vec<String> },
    /// The project's own commit failed behind the anchored one, which was
    /// taken back with the inert files. `left` holds one line per file
    /// that could not be put back; empty when the root is as it was.
    Project { error: E, left: Vec<String> },
}

/// The directory of the project at `project_rel` under `root`.
fn project_dir(root: &Path, project_rel: &str) -> PathBuf {
    let levels = project_rel.split('/').filter(|level| !level.is_empty());
    levels.fold(root.to_path_buf(), |at, level| at.join(level))
}

/// Why no run of the project at `project` lands under `root`: the root
/// lies outside the directory socket-patch writes in for the project (the
/// repository around it, or the project itself where there is none). The
/// project lock looks for an interrupted commit no further than that
/// (`bazel_root_writes::recover_above`), so a commit anchored outside it
/// could be torn with nobody to finish it. A seam refuses such a root
/// when it decides; this is what holds if one does not.
pub fn outside(root: &Path, project: &Path) -> Option<String> {
    let writes = ReadBoundary::of(ReadScope::Workspace, project);
    (!writes.contains(root)).then(|| {
        format!(
            "the Bazel root {} is outside the project {}, and with no repository around the \
             project socket-patch writes nowhere else (`{BAZEL_ROOT_OUTSIDE_REPOSITORY}`)",
            root.display(),
            project.display()
        )
    })
}

/// Lands a run under a Bazel root (the module docs): what it staged
/// there, in the commit anchored at the root and under the root's lock
/// (`utils::group_commit::commit_anchored`), each outcome settled with
/// `runner`, and then the project's own commit `project`. All of it lands
/// or none of it does.
///
/// This is the one way a seam commits under a Bazel root. The anchored
/// commit comes before the project's because it is the one that can be
/// taken back from the originals it returns, and a command that has to
/// run for it runs before anything else of the project is written.
///
/// [`finish`] is called here, on the thread that polls this future: a
/// runner that starts a process blocks it. The package that lands such a
/// runner moves the call off the async threads in this function, which
/// no seam sees.
pub async fn land<F, T, E>(
    staged: Staged<'_>,
    runner: &dyn ToolRunner,
    project: F,
) -> Result<Landed<T>, Unlanded<E>>
where
    F: Future<Output = Result<T, E>>,
{
    let unchanged = |why: String| Unlanded::Root {
        why,
        pending: false,
        left: Vec::new(),
    };
    let dir = project_dir(staged.root, staged.project_rel);
    if let Some(why) = outside(staged.root, &dir) {
        return Err(unchanged(why));
    }
    let lock = lock_root(staged.root, ROOT_LOCK_WAIT).await;
    let lock = lock.map_err(|e| unchanged(e.to_string()))?;
    if let Some(replayed) = lock.recovered() {
        return Err(Unlanded::Recovered(replayed));
    }
    let ahead = match land_ahead(&dir, staged.ahead.to_vec()).await {
        Ok(ahead) => ahead,
        // The files already landed were put back, or the error names
        // the ones that could not be.
        Err(e) => {
            let (why, left) = match left_replaced(&e) {
                Some(kept) => (kept.cause.to_string(), kept.files.clone()),
                None => (e.to_string(), Vec::new()),
            };
            return Err(Unlanded::Root {
                why,
                pending: false,
                left,
            });
        }
    };
    // Everything this run put on disk so far, back to what it held.
    let undo = |committed: Vec<CommittedFile>| {
        let (lock, dir, ahead) = (&lock, &dir, &ahead);
        async move {
            let anchored = restore_anchored(lock, &committed).await;
            let mut left = anchored.err().unwrap_or_default();
            left.extend(take_back(dir, ahead).await.err().unwrap_or_default());
            left
        }
    };
    let committed = commit_anchored(&lock, staged.touched, staged.changes.to_vec()).await;
    let committed = match committed {
        Ok(committed) => committed,
        // A journal that stays is finished by the next run, which then
        // needs the inert files where they are.
        Err(e) if is_pending(&e) => {
            return Err(Unlanded::Root {
                why: e.to_string(),
                pending: true,
                left: Vec::new(),
            });
        }
        Err(e) => {
            return Err(Unlanded::Root {
                why: e.to_string(),
                pending: false,
                left: undo(Vec::new()).await,
            });
        }
    };
    let mut captured = Captured::new(staged.root, committed);
    for outcome in staged.outcomes {
        captured = match finish(outcome, captured, runner) {
            Finish::Keep(captured) => captured,
            Finish::Unwind { captured, why } => {
                let left = undo(captured.files).await;
                return Err(Unlanded::Run { why, left });
            }
        };
    }
    match project.await {
        Ok(project) => Ok(Landed {
            captured,
            lock,
            project,
        }),
        Err(error) => {
            let left = undo(captured.files).await;
            Err(Unlanded::Project { error, left })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::bazel::model::{
        Anchor, AttestBasis, Interim, LaneId, Plan, PlannedWrite, Refusal,
    };
    use socket_patch_core::bazel::owned_index::INDEX_PATH;
    use socket_patch_core::utils::group_commit::{pending_anchored, ROOT_JOURNAL_REL};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn plan() -> Plan {
        Plan {
            uuid: "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f".to_string(),
            lane: LaneId("H-TOY1"),
            writes: vec![PlannedWrite::NativeLock {
                path: "pnpm-lock.yaml".to_string(),
            }],
            repositories: Vec::new(),
            artifacts: Vec::new(),
            advisories: Vec::new(),
            attest: AttestBasis::LockUrl,
            anchor: Anchor::Digest,
        }
    }

    /// Every command the gate can hand a plan: each kind, for each actor
    /// and each interim state.
    fn commands() -> Vec<RunRequired> {
        use socket_patch_core::bazel::model::RunKind;
        let mut all = Vec::new();
        for kind in RunKind::ALL {
            for actor in Actor::ALL {
                for interim in Interim::ALL {
                    all.push(RunRequired {
                        kind: *kind,
                        command: "bazel mod deps --lockfile_mode=update".to_string(),
                        argv: vec!["bazel".to_string(), "mod".to_string(), "deps".to_string()],
                        env: Vec::new(),
                        outputs: vec!["MODULE.bazel.lock".to_string()],
                        interim: *interim,
                        actor: *actor,
                        platforms: Vec::new(),
                        gates_vex: true,
                    });
                }
            }
        }
        all
    }

    /// A plan whose command the gate gave to socket-patch.
    fn ours() -> GateOutcome {
        let run = commands()
            .into_iter()
            .find(|run| run.actor == Actor::SocketPatch);
        GateOutcome::ProceedAfter(plan(), run.expect("a command of socket-patch's"))
    }

    fn captured() -> Captured {
        let file = CommittedFile {
            rel: "pnpm-lock.yaml".to_string(),
            before: Some(b"lock-old\n".to_vec()),
        };
        Captured::new("/repo", vec![file])
    }

    /// A runner that counts its runs and answers as told.
    struct Told(RunResult, AtomicUsize);

    impl Told {
        fn new(answer: RunResult) -> Self {
            Self(answer, AtomicUsize::new(0))
        }

        fn runs(&self) -> usize {
            self.1.load(Ordering::SeqCst)
        }
    }

    impl ToolRunner for Told {
        fn run(&self, _: &Path, _: &RunRequired) -> RunResult {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.clone()
        }
    }

    /// A root on disk with one file, and what a run stages there: the
    /// change set that rewrites the file and records it, and an inert file
    /// of the project.
    struct Fixture {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        touched: Vec<String>,
        changes: Vec<AnchoredChange>,
        ahead: Vec<(String, Vec<u8>)>,
    }

    impl Fixture {
        /// `git`: the root is a checkout. Without it no repository bounds
        /// what socket-patch writes, and the bound is the project.
        fn new(git: bool) -> Self {
            let tmp = tempfile::tempdir().expect("a temporary directory");
            let root = std::fs::canonicalize(tmp.path()).expect("its real path");
            if git {
                std::fs::create_dir_all(root.join(".git")).expect("mkdir");
            }
            std::fs::create_dir_all(root.join("svc")).expect("mkdir");
            std::fs::write(root.join("MODULE.bazel"), b"module(name = \"ws\")\n").expect("write");
            std::fs::write(root.join("pnpm-lock.yaml"), b"lock-old\n").expect("write");
            let index = INDEX_PATH.to_string();
            let changes = vec![
                AnchoredChange {
                    rel: index.clone(),
                    read: None,
                    write: Some(b"{}\n".to_vec()),
                },
                AnchoredChange {
                    rel: "pnpm-lock.yaml".to_string(),
                    read: Some(b"lock-old\n".to_vec()),
                    write: Some(b"lock-new\n".to_vec()),
                },
            ];
            let touched = vec![index, "pnpm-lock.yaml".to_string()];
            let policy = b"trustLockfile: true\n".to_vec();
            let ahead = vec![("pnpm-workspace.yaml".to_string(), policy)];
            Self {
                _tmp: tmp,
                root,
                touched,
                changes,
                ahead,
            }
        }

        fn staged<'a>(&'a self, outcomes: &'a [&'a GateOutcome]) -> Staged<'a> {
            Staged {
                root: &self.root,
                project_rel: "",
                touched: &self.touched,
                changes: &self.changes,
                outcomes,
                ahead: &self.ahead,
            }
        }

        fn lock_text(&self) -> Vec<u8> {
            std::fs::read(self.root.join("pnpm-lock.yaml")).expect("the lock")
        }

        /// Every file and directory below the root but the git directory,
        /// by its path from there: a directory ends with `/`, so one that
        /// a commit left behind is a difference.
        fn tree(&self) -> Vec<String> {
            let mut found = Vec::new();
            let mut pending = vec![Vec::<String>::new()];
            while let Some(at) = pending.pop() {
                let dir = at
                    .iter()
                    .fold(self.root.clone(), |dir, level| dir.join(level));
                for entry in std::fs::read_dir(dir).expect("a directory") {
                    let entry = entry.expect("an entry");
                    let mut path = at.clone();
                    path.push(entry.file_name().to_string_lossy().into_owned());
                    if path == [".git"] {
                        continue;
                    }
                    match entry.file_type().expect("its kind").is_dir() {
                        true => {
                            found.push(format!("{}/", path.join("/")));
                            pending.push(path);
                        }
                        false => found.push(path.join("/")),
                    }
                }
            }
            found.sort();
            found
        }
    }

    /// The owned directory of a root: where its lock file and its journal
    /// lie, beside the index.
    fn owned(root: &Path) -> PathBuf {
        let index = project_dir(root, INDEX_PATH);
        index.parent().expect("the owned directory").to_path_buf()
    }

    /// The anchored commit and the project's commit land together, the
    /// inert file ahead of both, and the root stays locked until the seam
    /// lets go; a project commit that fails takes everything back, down to
    /// the directories it made; and a refused anchored commit never runs
    /// the project's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_run_lands_under_the_root_whole_or_not_at_all() {
        let fixture = Fixture::new(true);
        let root = &fixture.root;
        let before = fixture.tree();
        let proceed = GateOutcome::Proceed(plan());
        let outcomes = [&proceed];
        let staged = fixture.staged(&outcomes);

        // What the project's own commit finds on disk when it starts: the
        // inert file and the pin are there.
        let seen = std::cell::RefCell::new(Vec::new());
        let failing = async {
            *seen.borrow_mut() = fixture.tree();
            Err("disk full")
        };
        let failed: Result<Landed<()>, _> = land(staged, &NoRunner, failing).await;
        let Err(Unlanded::Project { error, left }) = failed else {
            panic!("the project's commit failed");
        };
        assert_eq!((error, left), ("disk full", Vec::new()));
        let seen = seen.into_inner();
        for landed in [INDEX_PATH, "pnpm-workspace.yaml"] {
            assert!(seen.iter().any(|path| path == landed), "{landed}: {seen:?}");
        }
        assert_eq!(
            fixture.tree(),
            before,
            "no index, no `.socket`, no policy file"
        );
        assert!(!root.join(".socket").exists());
        assert_eq!(fixture.lock_text(), b"lock-old\n");

        let landed = land::<_, _, &str>(staged, &NoRunner, async { Ok(7) }).await;
        let Ok(landed) = landed else {
            panic!("the run lands");
        };
        assert_eq!(landed.project, 7);
        assert_eq!(landed.captured.root(), root);
        let originals: Vec<&str> = landed
            .captured
            .files()
            .iter()
            .map(|f| f.rel.as_str())
            .collect();
        assert_eq!(originals, fixture.touched);
        assert_eq!(fixture.lock_text(), b"lock-new\n");
        let policy = std::fs::read(root.join("pnpm-workspace.yaml")).expect("the policy file");
        assert_eq!(policy, b"trustLockfile: true\n");
        // The root is locked until the seam is done with it.
        let lock = owned(root).join("apply.lock");
        assert!(lock.exists());
        drop(landed);
        assert!(!lock.exists());

        // The same change set again was read from a root that has moved
        // on: refused before the first replace, and the project's commit
        // is never started.
        let ran = std::cell::Cell::new(false);
        let project = async {
            ran.set(true);
            Ok::<(), &str>(())
        };
        let refused = land(staged, &NoRunner, project).await;
        let Err(Unlanded::Root { why, pending, left }) = refused else {
            panic!("the anchored commit refuses");
        };
        assert!(why.contains("changed while"), "{why}");
        assert!(!pending && !ran.get() && left.is_empty());
        // The inert file of the refused run went back to what it held.
        let policy = std::fs::read(root.join("pnpm-workspace.yaml")).expect("the policy file");
        assert_eq!(
            policy, b"trustLockfile: true\n",
            "as the run before left it"
        );
    }

    /// A command of socket-patch's that fails after the anchored commit
    /// unwinds the whole run before anything else of the project is
    /// written: the pin, its record, the inert file and every directory
    /// are as they were, and the project's own commit is never started.
    /// The command ran once, at the root, with the pin on disk.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_run_unwinds_everything_and_the_project_commit_never_starts() {
        struct Sees(PathBuf, AtomicUsize);
        impl ToolRunner for Sees {
            fn run(&self, root: &Path, _: &RunRequired) -> RunResult {
                assert_eq!(root, self.0, "the tool runs at the root");
                let pinned = std::fs::read(root.join("pnpm-lock.yaml")).expect("the lock");
                assert_eq!(pinned, b"lock-new\n", "the commit landed before the run");
                assert!(
                    root.join("pnpm-workspace.yaml").exists(),
                    "the inert file too"
                );
                self.1.fetch_add(1, Ordering::SeqCst);
                RunResult::Failed("exit 2".to_string())
            }
        }
        let fixture = Fixture::new(true);
        let before = fixture.tree();
        let (first, second) = (GateOutcome::Proceed(plan()), ours());
        let outcomes = [&first, &second];
        let runner = Sees(fixture.root.clone(), AtomicUsize::new(0));
        let ran = std::cell::Cell::new(false);
        let project = async {
            ran.set(true);
            Ok::<(), &str>(())
        };
        let Err(unlanded) = land(fixture.staged(&outcomes), &runner, project).await else {
            panic!("a failed run does not land");
        };
        let said = "`bazel mod deps --lockfile_mode=update` failed: exit 2".to_string();
        let whole = Unlanded::Run {
            why: said,
            left: Vec::new(),
        };
        assert_eq!(unlanded, whole);
        assert_eq!(runner.1.load(Ordering::SeqCst), 1);
        assert!(!ran.get(), "the project's commit was never started");
        assert_eq!(fixture.tree(), before);
        assert_eq!(fixture.lock_text(), b"lock-old\n");

        // The same run with a runner that passes lands, project and all.
        let passes = Told::new(RunResult::Ran);
        let landed = land::<_, _, &str>(fixture.staged(&outcomes), &passes, async { Ok(()) }).await;
        assert!(landed.is_ok());
        assert_eq!(passes.runs(), 1);
        assert_eq!(fixture.lock_text(), b"lock-new\n");
    }

    /// A commit that an interrupted run left at the root is finished as
    /// the lock is taken. The run decided from the files of before, so
    /// nothing of it is written, its project commit is not started, and it
    /// is told what the replay rewrote, by name.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_replay_under_the_lock_is_reported_and_nothing_of_the_run_is_written() {
        let fixture = Fixture::new(true);
        let root = &fixture.root;
        // The journal of an interrupted commit that rewrites the lock.
        let journal = project_dir(root, ROOT_JOURNAL_REL);
        std::fs::create_dir_all(journal.parent().expect("a parent")).expect("mkdir");
        let hash = "f0d5fb72d1b6ec8a8a2d03a50d7d3a79d4a7a6e36fc3c0d6c9b1b7e2c8a2c8d1";
        let interrupted = serde_json::json!({
            "version": 1,
            "files": [
                { "path": "pnpm-lock.yaml", "before": hash, "after": "bG9jay1yZXBsYXllZAo=" },
                { "path": "notes.lock", "before": null, "after": "bm90ZXMK" },
            ],
        });
        std::fs::write(&journal, interrupted.to_string()).expect("the journal");
        assert!(pending_anchored(root).expect("readable").is_some());

        let proceed = GateOutcome::Proceed(plan());
        let outcomes = [&proceed];
        let ran = std::cell::Cell::new(false);
        let project = async {
            ran.set(true);
            Ok::<(), &str>(())
        };
        let Err(unlanded) = land(fixture.staged(&outcomes), &NoRunner, project).await else {
            panic!("a run that decided before the replay does not land");
        };
        let Unlanded::Recovered(report) = unlanded else {
            panic!("the replay is reported: {unlanded:?}");
        };
        assert!(!ran.get(), "the project's commit was not started");
        // The lock no longer held the bytes the journal recorded, so the
        // commit could not be finished as written: the journal was set
        // aside, and the report names it and what was done.
        assert!(report.detail.contains("Bazel root"), "{}", report.detail);
        assert!(pending_anchored(root).expect("readable").is_none());
        assert!(
            !root.join("pnpm-workspace.yaml").exists(),
            "nothing of this run"
        );
        assert!(
            !project_dir(root, INDEX_PATH).exists(),
            "nothing of this run"
        );

        // A journal that replays as written: the files it rolled forward
        // are named.
        let fresh = Fixture::new(true);
        let root = &fresh.root;
        let journal = project_dir(root, ROOT_JOURNAL_REL);
        std::fs::create_dir_all(journal.parent().expect("a parent")).expect("mkdir");
        let interrupted = serde_json::json!({
            "version": 1,
            "files": [
                { "path": "notes.lock", "before": null, "after": "bm90ZXMK" },
                { "path": "svc/other.lock", "before": null, "after": "bm90ZXMK" },
            ],
        });
        std::fs::write(&journal, interrupted.to_string()).expect("the journal");
        let project = async {
            ran.set(true);
            Ok::<(), &str>(())
        };
        let unlanded = land(fresh.staged(&outcomes), &NoRunner, project)
            .await
            .err();
        let Some(Unlanded::Recovered(report)) = unlanded else {
            panic!("the replay is reported");
        };
        assert!(!ran.get());
        for rolled in ["notes.lock", "svc/other.lock"] {
            assert!(report.detail.contains(rolled), "{}", report.detail);
            assert_eq!(
                std::fs::read(project_dir(root, rolled)).expect("rolled"),
                b"notes\n"
            );
        }
        assert_eq!(fresh.lock_text(), b"lock-old\n", "nothing of this run");
        assert!(!root.join("pnpm-workspace.yaml").exists());
        // The next run finds a clean root and lands.
        let landed = land::<_, _, &str>(fresh.staged(&outcomes), &NoRunner, async { Ok(()) }).await;
        assert!(landed.is_ok());
    }

    /// With no repository around a project, a Bazel root above it is
    /// outside the directory socket-patch writes in: no run lands there,
    /// and nothing is locked or created for the answer. The root's own
    /// project lands as ever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_run_lands_at_a_root_outside_the_directory_it_writes_in() {
        let fixture = Fixture::new(false);
        let before = fixture.tree();
        let proceed = GateOutcome::Proceed(plan());
        let outcomes = [&proceed];
        let below = Staged {
            project_rel: "svc",
            ..fixture.staged(&outcomes)
        };
        let ran = std::cell::Cell::new(false);
        let project = async {
            ran.set(true);
            Ok::<(), &str>(())
        };
        let refused = land(below, &NoRunner, project).await;
        let Err(Unlanded::Root { why, pending, left }) = refused else {
            panic!("a root outside the project is not written");
        };
        assert!(why.contains(BAZEL_ROOT_OUTSIDE_REPOSITORY), "{why}");
        assert!(!pending && !ran.get() && left.is_empty());
        assert_eq!(fixture.tree(), before);
        assert_eq!(outside(&fixture.root, &fixture.root), None);

        let at_root = fixture.staged(&outcomes);
        let landed = land::<_, _, &str>(at_root, &NoRunner, async { Ok(()) }).await;
        assert!(
            landed.is_ok(),
            "the project at the root is inside its own bound"
        );

        // In a checkout the repository is the bound, and a project below
        // the root lands.
        let checkout = Fixture::new(true);
        let below = Staged {
            project_rel: "svc",
            ..checkout.staged(&outcomes)
        };
        let landed = land::<_, _, &str>(below, &NoRunner, async { Ok(()) }).await;
        assert!(landed.is_ok());
        let policy = checkout.root.join("svc").join("pnpm-workspace.yaml");
        assert!(policy.exists(), "the inert file lands in the project");
    }

    /// Inert first: when the anchored commit is torn (a replace failed,
    /// and what it had replaced could not be put back), its journal stays
    /// for the next run to finish, and the inert file of the project is
    /// already on disk and stays with it. The pin never stands without it.
    ///
    /// Unix only: what tears the commit here is the file-name limit of the
    /// unix file systems (a removal needs no stage file and its undo does),
    /// which is the one way to fail a replace and its undo from outside
    /// the commit without a hook in it.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_torn_commit_keeps_the_inert_file_it_was_landed_behind() {
        let fixture = Fixture::new(true);
        let root = &fixture.root;
        // A file whose removal succeeds and whose stage name is too long
        // to put it back, and a file whose stage name is too long to
        // write at all.
        let (old, new) = (
            format!("{}.old", "o".repeat(244)),
            format!("{}.new", "n".repeat(244)),
        );
        std::fs::write(root.join(&old), b"old\n").expect("write");
        let changes = vec![
            AnchoredChange {
                rel: old.clone(),
                read: Some(b"old\n".to_vec()),
                write: None,
            },
            AnchoredChange {
                rel: new.clone(),
                read: None,
                write: Some(b"new\n".to_vec()),
            },
        ];
        let touched = vec![old.clone(), new];
        let staged = Staged {
            touched: &touched,
            changes: &changes,
            ..fixture.staged(&[])
        };
        let ran = std::cell::Cell::new(false);
        let project = async {
            ran.set(true);
            Ok::<(), &str>(())
        };
        let torn = land(staged, &NoRunner, project).await;
        let Err(Unlanded::Root { pending, why, .. }) = torn else {
            panic!("a torn commit does not land");
        };
        assert!(pending, "the journal is kept: {why}");
        assert!(!ran.get(), "the project's commit was not started");
        assert!(pending_anchored(root).expect("readable").is_some());
        assert!(
            !root.join(&old).exists(),
            "the replace that could not be undone"
        );
        let policy = std::fs::read(root.join("pnpm-workspace.yaml")).expect("the inert file");
        assert_eq!(policy, b"trustLockfile: true\n", "landed ahead, and kept");
    }

    /// With the runner of this release nothing is ever unwound, whatever
    /// the gate answered: the originals come back untouched.
    #[test]
    fn finish_with_no_runner_never_unwinds() {
        let shipped = runner();
        for outcome in [GateOutcome::Proceed(plan()), ours()] {
            let finished = finish(&outcome, captured(), shipped.as_ref());
            assert_eq!(finished, Finish::Keep(captured()), "{outcome:?}");
        }
        let mut outcomes = vec![
            GateOutcome::NotBazel,
            GateOutcome::Proceed(plan()),
            GateOutcome::Refuse(Refusal::lane_not_enabled(LaneId("H-TOY1"))),
        ];
        let after = |run| GateOutcome::ProceedAfter(plan(), run);
        outcomes.extend(commands().into_iter().map(after));
        assert!(outcomes.len() > 3, "every command was listed");
        for outcome in &outcomes {
            let finished = finish(outcome, captured(), &NoRunner);
            assert_eq!(finished, Finish::Keep(captured()), "{outcome:?}");
        }
    }

    /// Only a command the gate gave to socket-patch reaches the runner,
    /// once, and only its failure unwinds: the originals are handed back
    /// with the command that failed.
    #[test]
    fn finish_runs_only_what_the_gate_gave_to_socket_patch() {
        for run in commands() {
            let outcome = GateOutcome::ProceedAfter(plan(), run.clone());
            let ours = run.actor == Actor::SocketPatch;

            let ran = Told::new(RunResult::Ran);
            assert_eq!(finish(&outcome, captured(), &ran), Finish::Keep(captured()));
            assert_eq!(ran.runs(), usize::from(ours), "{run:?}");

            let failed = Told::new(RunResult::Failed("exit 2".to_string()));
            let finished = finish(&outcome, captured(), &failed);
            assert_eq!(failed.runs(), usize::from(ours), "{run:?}");
            match (ours, finished) {
                (false, Finish::Keep(back)) => assert_eq!(back, captured()),
                (
                    true,
                    Finish::Unwind {
                        captured: back,
                        why,
                    },
                ) => {
                    assert_eq!(back, captured());
                    let said = "`bazel mod deps --lockfile_mode=update` failed: exit 2";
                    assert_eq!(why, said);
                }
                (_, other) => panic!("{run:?}: {other:?}"),
            }
        }
        // A plan with no command, or none at all, is never run.
        let never = Told::new(RunResult::Failed("ran".to_string()));
        for outcome in [GateOutcome::NotBazel, GateOutcome::Proceed(plan())] {
            assert_eq!(
                finish(&outcome, captured(), &never),
                Finish::Keep(captured())
            );
        }
        assert_eq!(never.runs(), 0);
    }
}
