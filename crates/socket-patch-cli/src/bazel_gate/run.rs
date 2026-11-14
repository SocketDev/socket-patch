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
//! it. A seam does three things: it keeps the originals its commit
//! replaced ([`Captured`]), hands each outcome it carried out to
//! [`finish`], and puts the originals back when the answer is
//! [`Finish::Unwind`]. The commit itself is [`land`]: the change set a run
//! staged under a Bazel root and the project's own commit, as one.
//!
//! This release runs no tool. The run policy is `Never`, so the gate
//! refuses every plan whose build would fail before its command, and the
//! runner every seam passes is [`NoRunner`], which starts nothing: with it
//! [`finish`] never answers `Unwind`, and a works-after pin stands as the
//! commit left it. The package that lands the tool runner replaces
//! `NoRunner` and the body of [`finish`] (the snapshot of the tool's
//! outputs, the time budget, the lane's static post-check, the `runs` row)
//! and changes no seam.

use std::future::Future;
use std::path::{Path, PathBuf};

use socket_patch_core::bazel::model::{Actor, GateOutcome, RunRequired};
use socket_patch_core::utils::bazel_root_writes::{lock_root, RootLock, ROOT_LOCK_WAIT};
use socket_patch_core::utils::group_commit::{
    commit_anchored, is_pending, restore_anchored, AnchoredChange, CommittedFile, Recovery,
};

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

/// Runs the one command of a plan at a Bazel root.
pub trait ToolRunner {
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
/// each path with the bytes the transaction read there), and the paths the
/// plans it carries out capture (`bazel::exec::touched`).
#[derive(Debug, Clone, Copy)]
pub struct Staged<'a> {
    pub root: &'a Path,
    pub touched: &'a [String],
    pub changes: &'a [AnchoredChange],
}

/// A run that landed: the root's lock, still held, the originals the
/// commit anchored there replaced, and what the project's own commit
/// returned. The seam settles each plan with [`finish`], tells its loader
/// of the commit, and then lets the lock go.
pub struct Landed<T> {
    pub lock: RootLock,
    pub captured: Captured,
    pub project: T,
}

/// Why nothing of a run stayed written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unlanded<E> {
    /// The root's lock was not taken, or the commit anchored at the root
    /// refused or failed. The project's own commit was not run. `pending`:
    /// a replace failed and could not be undone, so the commit's journal
    /// is kept and the next run that locks the root finishes it; in every
    /// other case nothing was changed.
    Root { why: String, pending: bool },
    /// The project's own commit failed behind the anchored one, which was
    /// taken back. `left` holds one line per file under the Bazel root
    /// that could not be put back; empty when the root is as it was.
    Project { error: E, left: Vec<String> },
}

/// Lands a run under a Bazel root: what it staged there, in the commit
/// anchored at the root and under the root's lock
/// (`utils::group_commit::commit_anchored`), and then the project's own
/// commit `project`. Both land or neither does: a failure of the project's
/// commit puts the root back to what it held.
///
/// This is the one way a seam commits under a Bazel root. The anchored
/// commit comes first because it is the one that can be taken back from
/// the originals it returns; the project's files are landed from what the
/// disk holds after it.
///
/// A commit that an interrupted run left at the root is finished as the
/// lock is taken. The run then decided from files that have changed since,
/// so nothing of it is written and the answer is [`Unlanded::Root`].
pub async fn land<F, T, E>(staged: Staged<'_>, project: F) -> Result<Landed<T>, Unlanded<E>>
where
    F: Future<Output = Result<T, E>>,
{
    let unchanged = |why: String| Unlanded::Root {
        why,
        pending: false,
    };
    let lock = lock_root(staged.root, ROOT_LOCK_WAIT).await;
    let lock = lock.map_err(|e| unchanged(e.to_string()))?;
    if *lock.recovery() != Recovery::Clean {
        let why = "the commit an interrupted run left there was finished first; run again";
        return Err(unchanged(why.to_string()));
    }
    let committed = commit_anchored(&lock, staged.touched, staged.changes.to_vec()).await;
    let committed = committed.map_err(|e| Unlanded::Root {
        why: e.to_string(),
        pending: is_pending(&e),
    })?;
    match project.await {
        Ok(project) => Ok(Landed {
            captured: Captured::new(staged.root, committed),
            lock,
            project,
        }),
        Err(error) => {
            let left = restore_anchored(&lock, &committed).await;
            let left = left.err().unwrap_or_default();
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

    fn captured() -> Captured {
        let file = CommittedFile {
            rel: "pnpm-lock.yaml".to_string(),
            before: Some(b"lock-old\n".to_vec()),
        };
        Captured::new("/repo", vec![file])
    }

    /// A runner that counts its runs and answers as told.
    struct Told(RunResult, std::cell::Cell<usize>);

    impl ToolRunner for Told {
        fn run(&self, root: &Path, _: &RunRequired) -> RunResult {
            assert_eq!(root, Path::new("/repo"), "the tool runs at the root");
            self.1.set(self.1.get() + 1);
            self.0.clone()
        }
    }

    /// A root on disk with one file, and the change set that rewrites it
    /// and records it.
    fn staged_root() -> (tempfile::TempDir, PathBuf, Vec<String>, Vec<AnchoredChange>) {
        let tmp = tempfile::tempdir().expect("a temporary directory");
        let root = std::fs::canonicalize(tmp.path()).expect("its real path");
        std::fs::write(root.join("MODULE.bazel"), b"module(name = \"ws\")\n").expect("write");
        std::fs::write(root.join("pnpm-lock.yaml"), b"lock-old\n").expect("write");
        let index = socket_patch_core::bazel::owned_index::INDEX_PATH.to_string();
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
        (tmp, root, touched, changes)
    }

    fn files(root: &Path) -> Vec<String> {
        let mut found = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(dir).expect("a directory") {
                let path = entry.expect("an entry").path();
                match path.is_dir() {
                    true => pending.push(path),
                    false => {
                        let rel = path.strip_prefix(root).expect("below the root");
                        let levels: Vec<String> = rel
                            .components()
                            .map(|c| c.as_os_str().to_string_lossy().into_owned())
                            .collect();
                        found.push(levels.join("/"));
                    }
                }
            }
        }
        found.sort();
        found
    }

    /// The anchored commit and the project's commit land together, and
    /// the root stays locked until the seam lets go; a project commit
    /// that fails takes the anchored one back, down to the directories it
    /// made; and a refused anchored commit never runs the project's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_run_lands_under_the_root_whole_or_not_at_all() {
        let (_tmp, root, touched, changes) = staged_root();
        let staged = Staged {
            root: &root,
            touched: &touched,
            changes: &changes,
        };
        let before = files(&root);

        let failed: Result<Landed<()>, _> = land(staged, async { Err("disk full") }).await;
        let Err(Unlanded::Project { error, left }) = failed else {
            panic!("the project's commit failed");
        };
        assert_eq!((error, left), ("disk full", Vec::new()));
        assert_eq!(files(&root), before, "no index, no `.socket`");
        assert_eq!(
            std::fs::read(root.join("pnpm-lock.yaml")).expect("read"),
            b"lock-old\n"
        );

        let landed = land::<_, _, &str>(staged, async { Ok(7) }).await;
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
        assert_eq!(originals, touched);
        assert_eq!(
            std::fs::read(root.join("pnpm-lock.yaml")).expect("read"),
            b"lock-new\n"
        );
        // The root is locked until the seam is done with it.
        let lock = root.join(socket_patch_core::bazel::owned_index::INDEX_PATH);
        assert!(lock.with_file_name("apply.lock").exists());
        drop(landed);
        assert!(!lock.with_file_name("apply.lock").exists());

        // The same change set again was read from a root that has moved
        // on: refused before the first replace, and the project's commit
        // is never started.
        let ran = std::cell::Cell::new(false);
        let project = async {
            ran.set(true);
            Ok::<(), &str>(())
        };
        let Err(Unlanded::Root { why, pending }) = land(staged, project).await else {
            panic!("the anchored commit refuses");
        };
        assert!(why.contains("changed while"), "{why}");
        assert!(!pending && !ran.get());
    }

    /// With the runner of this release nothing is ever unwound, whatever
    /// the gate answered: the originals come back untouched.
    #[test]
    fn finish_with_no_runner_never_unwinds() {
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

            let ran = Told(RunResult::Ran, Default::default());
            assert_eq!(finish(&outcome, captured(), &ran), Finish::Keep(captured()));
            assert_eq!(ran.1.get(), usize::from(ours), "{run:?}");

            let failed = Told(RunResult::Failed("exit 2".to_string()), Default::default());
            let finished = finish(&outcome, captured(), &failed);
            assert_eq!(failed.1.get(), usize::from(ours), "{run:?}");
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
        let never = Told(RunResult::Failed("ran".to_string()), Default::default());
        for outcome in [GateOutcome::NotBazel, GateOutcome::Proceed(plan())] {
            assert_eq!(
                finish(&outcome, captured(), &never),
                Finish::Keep(captured())
            );
        }
        assert_eq!(never.1.get(), 0);
    }
}
