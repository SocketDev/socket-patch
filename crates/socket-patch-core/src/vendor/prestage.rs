//! Service archives staged ahead of the serial vendor loop.
//!
//! The vendor loop wires one package at a time, and a directory-shaped
//! backend (cargo, composer, golang, gem) spends most of its local time on
//! one step it cannot overlap with anything: extracting the verified
//! prebuilt archive into its stage. The download plan
//! ([`crate::api::client::PlannedDownload`]) already fetches those archives
//! ahead of the loop; a [`PrestageRecipe`] lets it extract each one too, on
//! a small blocking pool, as the download lands — so when the loop reaches
//! the package its tree is already on disk and the backend only renames it
//! into place ([`PrestagedTree::claim_into`]). The single-file backends
//! (maven, nuget) and pypi's wheel get the one pure step they run on the
//! archive bytes instead: the afterHash check of the patched members.
//!
//! Nothing observable may change, so every decision stays the backend's:
//!
//! * A recipe only runs on an archive that passed the integrity checks
//!   `fetch_verified_archive` runs before handing it over — the backend
//!   never extracts anything else either.
//! * The tree lands in a sibling of the backend's stage
//!   (`<copy>.socket-prestage`), never in the stage itself: a backend that
//!   runs without it (its call skipped by the breaker, its plan position
//!   passed over) builds in its own stage undisturbed.
//! * Any failure — the extraction's own refusal included — just drops the
//!   pre-staged tree: the backend then extracts live, exactly as without it,
//!   and reports whatever that extraction reports, word for word.
//! * The swap, the wiring, the marker and the ledger stay in the loop, in
//!   record order; the backend claims the tree right where it would have
//!   extracted.
//! * A tree nobody claims is removed — but never while the loop runs: the
//!   loop's own failure unwinds prune empty vendor levels, and a concurrent
//!   removal could race one of its `create_dir_all`s. Unclaimed trees are
//!   queued and removed by [`settle`], which the loop's caller runs once
//!   the loop is done and its download plan detached.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::manifest::schema::PatchFileInfo;

/// Archives extracted at once, off the runtime's workers: enough to keep a
/// fast loop fed, few enough to leave the loop its own cores.
const PRESTAGE_CONCURRENCY: usize = 4;

static POOL: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(PRESTAGE_CONCURRENCY);

/// Pre-staged trees nobody claimed, awaiting [`settle`].
static ABANDONED: Mutex<Vec<(PathBuf, PathBuf)>> = Mutex::new(Vec::new());

/// Recipes whose output has not been received or dropped yet (see
/// [`settle`]).
static RUNNING: AtomicUsize = AtomicUsize::new(0);
static IDLE: tokio::sync::Notify = tokio::sync::Notify::const_new();

#[cfg(test)]
thread_local! {
    /// Trees claimed on this thread (a current-thread test runtime runs the
    /// backend's claim on the test's own thread).
    pub(crate) static CLAIMS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

type Extractor = Arc<dyn Fn(&[u8], &Path) -> Result<(), String> + Send + Sync>;

/// What to do with a planned download's archive once it has landed and
/// passed its integrity checks. Built by the backends' plan gates from the
/// same coordinates their own stage derives from.
#[derive(Clone)]
pub struct PrestageRecipe(Recipe);

#[derive(Clone)]
enum Recipe {
    /// Extract into `dir` (a sibling of the backend's stage) with the
    /// backend's own extractor. `socket_dir` bounds the pruning of the
    /// levels an unclaimed tree created.
    Extract {
        dir: PathBuf,
        socket_dir: PathBuf,
        extract: Extractor,
    },
    /// Check the archive's zip members against `files`' afterHashes (the
    /// backend's `zip_bytes_match_after_hashes`).
    VerifyZip {
        files: HashMap<String, PatchFileInfo>,
    },
}

impl std::fmt::Debug for PrestageRecipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Recipe::Extract { dir, .. } => write!(f, "PrestageRecipe::Extract({})", dir.display()),
            Recipe::VerifyZip { .. } => f.write_str("PrestageRecipe::VerifyZip"),
        }
    }
}

impl PartialEq for PrestageRecipe {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Recipe::Extract { dir: a, .. }, Recipe::Extract { dir: b, .. }) => a == b,
            (Recipe::VerifyZip { files: a }, Recipe::VerifyZip { files: b }) => a == b,
            _ => false,
        }
    }
}

impl Eq for PrestageRecipe {}

/// Where a copy dir's pre-staged tree is built: `<copy>.socket-prestage`.
pub(crate) fn prestage_dir_for(copy_dir: &Path) -> PathBuf {
    super::common::swap_sibling_for(copy_dir, ".socket-prestage")
}

impl PrestageRecipe {
    /// Extract into the pre-stage sibling of `copy_dir` with `extract`, the
    /// extractor the backend itself would run on its stage.
    pub(crate) fn extract(
        project_root: &Path,
        copy_dir: &Path,
        extract: impl Fn(&[u8], &Path) -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        Self(Recipe::Extract {
            dir: prestage_dir_for(copy_dir),
            socket_dir: project_root.join(crate::constants::SOCKET_DIR),
            extract: Arc::new(extract),
        })
    }

    /// Check the archive's zip members against `files`' afterHashes.
    pub(crate) fn verify_zip(files: &HashMap<String, PatchFileInfo>) -> Self {
        Self(Recipe::VerifyZip {
            files: files.clone(),
        })
    }
}

/// What a recipe produced, carried on the fetched archive to the backend.
#[derive(Debug, Clone, Default)]
pub(crate) struct Prestaged {
    /// The extracted tree, for the backend to claim.
    pub tree: Option<Arc<PrestagedTree>>,
    /// `zip_bytes_match_after_hashes(bytes, files)`, with the `files` it
    /// was computed against.
    pub zip_after_hashes: Option<(HashMap<String, PatchFileInfo>, bool)>,
}

impl Prestaged {
    /// The afterHash verdict for `files`, when it was computed for exactly
    /// those files.
    pub(crate) fn zip_verdict(&self, files: &HashMap<String, PatchFileInfo>) -> Option<bool> {
        self.zip_after_hashes
            .as_ref()
            .filter(|(computed_for, _)| computed_for == files)
            .map(|(_, verdict)| *verdict)
    }
}

/// A tree extracted ahead of the loop at `dir`. Removed when dropped
/// unclaimed (see the module docs for when).
#[derive(Debug)]
pub(crate) struct PrestagedTree {
    dir: PathBuf,
    socket_dir: PathBuf,
    claimed: AtomicBool,
}

impl PrestagedTree {
    /// Move the tree into `stage` — the backend's own stage, which it would
    /// otherwise have created and extracted into — replacing any litter
    /// there, as the backend's own `remove_tree(stage)` would. `false` (the
    /// tree left for cleanup) when it is not the pre-stage of `stage`'s
    /// copy dir or cannot be moved: the backend then extracts live.
    pub(crate) async fn claim_into(&self, stage: &Path, copy_dir: &Path) -> bool {
        if self.dir != prestage_dir_for(copy_dir) || self.claimed.load(Ordering::Relaxed) {
            return false;
        }
        if crate::patch::copy_tree::remove_tree(stage).await.is_err() {
            return false;
        }
        match tokio::fs::rename(&self.dir, stage).await {
            Ok(()) => {
                self.claimed.store(true, Ordering::Relaxed);
                crate::utils::durability::moved(&self.dir, stage);
                #[cfg(test)]
                CLAIMS.with(|claims| claims.set(claims.get() + 1));
                true
            }
            Err(_) => false,
        }
    }
}

impl Drop for PrestagedTree {
    fn drop(&mut self) {
        if self.claimed.load(Ordering::Relaxed) {
            return;
        }
        if let Ok(mut queue) = ABANDONED.lock() {
            queue.push((self.dir.clone(), self.socket_dir.clone()));
        }
    }
}

/// Remove an unclaimed tree and the vendor levels left empty above it,
/// stopping below `.socket` — the levels a failed backend's own unwind
/// prunes.
fn remove_abandoned(dir: &Path, socket_dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
    let mut level = dir.parent();
    while let Some(parent) = level {
        if parent == socket_dir || !parent.starts_with(socket_dir) {
            break;
        }
        if std::fs::remove_dir(parent).is_err() {
            break;
        }
        level = parent.parent();
    }
}

/// A recipe's output on its way back from the blocking pool. Counted in
/// [`RUNNING`] until received or dropped — dropped (its awaiting task
/// aborted), its tree is queued for cleanup BEFORE the count drops, so
/// [`settle`] never sweeps ahead of it.
struct Landing(Option<Prestaged>);

impl Landing {
    fn receive(mut self) -> Prestaged {
        self.0.take().unwrap_or_default()
    }
}

impl Drop for Landing {
    fn drop(&mut self) {
        drop(self.0.take());
        if RUNNING.fetch_sub(1, Ordering::SeqCst) == 1 {
            IDLE.notify_waiters();
        }
    }
}

/// Run `recipe` on a verified archive's `bytes`, which are handed back
/// untouched whatever happens (the backend may still need them). A failed
/// extraction leaves nothing claimable: its partial tree is removed at
/// once (only its own subtree) and the levels it created are queued for
/// [`settle`].
pub(crate) async fn run(recipe: &PrestageRecipe, bytes: Vec<u8>) -> (Vec<u8>, Prestaged) {
    let Ok(_permit) = POOL.acquire().await else {
        return (bytes, Prestaged::default());
    };
    let shared = Arc::new(bytes);
    let job = Arc::clone(&shared);
    let recipe = recipe.0.clone();
    RUNNING.fetch_add(1, Ordering::SeqCst);
    let landed = tokio::task::spawn_blocking(move || {
        let prestaged = match recipe {
            Recipe::Extract {
                dir,
                socket_dir,
                extract,
            } => {
                let _ = std::fs::remove_dir_all(&dir);
                let built = std::fs::create_dir_all(&dir)
                    .map_err(|e| e.to_string())
                    .and_then(|()| {
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            extract(&job, &dir)
                        }))
                        .unwrap_or_else(|_| Err("extraction panicked".to_string()))
                    });
                // Owned from here: dropped unclaimed, it is cleaned up.
                let tree = Arc::new(PrestagedTree {
                    dir,
                    socket_dir,
                    claimed: AtomicBool::new(false),
                });
                match built {
                    Ok(()) => Prestaged {
                        tree: Some(tree),
                        zip_after_hashes: None,
                    },
                    Err(_) => {
                        let _ = std::fs::remove_dir_all(&tree.dir);
                        drop(tree);
                        Prestaged::default()
                    }
                }
            }
            Recipe::VerifyZip { files } => {
                let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    super::common::zip_bytes_match_after_hashes(&job, &files)
                }));
                Prestaged {
                    tree: None,
                    zip_after_hashes: verdict.ok().map(|verdict| (files, verdict)),
                }
            }
        };
        drop(job);
        Landing(Some(prestaged))
    })
    .await;
    let prestaged = match landed {
        Ok(landing) => landing.receive(),
        // The blocking task never ran to completion (runtime shutting
        // down): nothing staged, and nothing will land.
        Err(_) => {
            if RUNNING.fetch_sub(1, Ordering::SeqCst) == 1 {
                IDLE.notify_waiters();
            }
            Prestaged::default()
        }
    };
    let bytes = Arc::try_unwrap(shared).unwrap_or_else(|still_shared| (*still_shared).clone());
    (bytes, prestaged)
}

/// Wait for every running recipe, then remove every tree nobody claimed
/// (and the empty vendor levels above it). Run once the vendor loop is
/// done and its download plan detached.
pub async fn settle() {
    loop {
        let idle = IDLE.notified();
        tokio::pin!(idle);
        idle.as_mut().enable();
        if RUNNING.load(Ordering::SeqCst) == 0 {
            break;
        }
        idle.await;
    }
    let queued: Vec<(PathBuf, PathBuf)> = ABANDONED
        .lock()
        .map(|mut queue| std::mem::take(&mut *queue))
        .unwrap_or_default();
    if queued.is_empty() {
        return;
    }
    let _ = tokio::task::spawn_blocking(move || {
        for (dir, socket_dir) in queued {
            remove_abandoned(&dir, &socket_dir);
        }
    })
    .await;
}

/// The backends whose copy dirs get pre-staged siblings, and how deep
/// below the uuid dir a copy dir can sit: cargo and gem copies are direct
/// children (`<name>-<version>`); composer (`<vendor>/<name>@<version>`)
/// and golang (`<module path>@<version>`) copies end in an `@` leaf under
/// any number of plain path levels.
const PRESTAGED_ECOSYSTEMS: [(&str, bool); 4] = [
    ("cargo", false),
    ("gem", false),
    ("composer", true),
    ("golang", true),
];

/// Deepest module-path nesting the sweep descends (a guard against a
/// pathological tree, far past any real module path).
const SWEEP_MAX_DEPTH: usize = 32;

/// Remove every `<copy>.socket-prestage` tree a previous run left under
/// `.socket/vendor/` — one that crashed or was interrupted between staging
/// an archive and [`settle`] — with the empty vendor levels above it.
/// [`settle`] only knows the current run's trees, and the backend only
/// replaces a pre-stage it stages again, so without this a leftover tree
/// whose package is never re-planned would stay forever. Run at the start
/// of a wet vendor loop, under its apply lock, before anything is staged:
/// every pre-stage tree on disk then is stale. Never descends into a copy
/// dir (an `@` leaf, or any child of a cargo / gem uuid dir), so a package
/// tree's own contents are never touched. Returns how many it removed.
pub async fn sweep_stale(project_root: &Path) -> usize {
    let socket_dir = project_root.join(crate::constants::SOCKET_DIR);
    let vendor_dir = socket_dir.join("vendor");
    tokio::task::spawn_blocking(move || {
        let mut removed = 0;
        for (eco, nested) in PRESTAGED_ECOSYSTEMS {
            for uuid_dir in plain_subdirs(&vendor_dir.join(eco)) {
                let depth = if nested { SWEEP_MAX_DEPTH } else { 1 };
                removed += sweep_level(&uuid_dir, depth, &socket_dir);
            }
        }
        removed
    })
    .await
    .unwrap_or(0)
}

/// The real (non-symlink) directories directly under `dir`, sorted.
fn plain_subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    dirs.sort();
    dirs
}

fn sweep_level(dir: &Path, depth: usize, socket_dir: &Path) -> usize {
    let mut removed = 0;
    for child in plain_subdirs(dir) {
        let name = child
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.ends_with(".socket-prestage") {
            remove_abandoned(&child, socket_dir);
            removed += 1;
        } else if depth > 1 && !name.contains('@') {
            removed += sweep_level(&child, depth - 1, socket_dir);
        }
    }
    removed
}

/// Serializes the tests that stage and settle: the abandoned queue and
/// the running count are process-wide, as one vendor loop per process is.
#[cfg(test)]
pub(crate) static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod sweep_tests {
    use super::*;

    /// Leftover pre-stage trees are removed wherever a copy dir's sibling
    /// can sit, with the vendor levels only they kept alive; copy dirs,
    /// their contents and everything else stay.
    #[tokio::test]
    async fn sweep_removes_only_stale_prestage_trees() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let v = root.join(".socket/vendor");
        let u = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let stale = [
            format!("cargo/{u}/foo-1.0.0.socket-prestage"),
            format!("gem/{u}/bar-2.0.0.socket-prestage"),
            format!("composer/{u}/psr/log@3.0.2.socket-prestage"),
            format!("golang/{u}/github.com/a/b@v1.0.0.socket-prestage"),
        ];
        for dir in &stale {
            std::fs::create_dir_all(v.join(dir).join("src")).unwrap();
            std::fs::write(v.join(dir).join("src/lib"), b"x").unwrap();
        }
        let kept = [
            format!("cargo/{u}/live-1.0.0/src/x.socket-prestage"),
            format!("cargo/{u}/live-1.0.0.socket-stage"),
            format!("composer/{u}/psr/cache@1.0.0/deep.socket-prestage"),
            format!("golang/{u}/github.com/a/c@v1.0.0"),
        ];
        for dir in &kept {
            std::fs::create_dir_all(v.join(dir)).unwrap();
        }
        std::fs::write(v.join("state.json"), b"{}").unwrap();

        assert_eq!(sweep_stale(root).await, stale.len());
        for dir in &stale {
            assert!(!v.join(dir).exists(), "{dir} swept");
        }
        for dir in &kept {
            assert!(v.join(dir).exists(), "{dir} kept");
        }
        assert!(
            !v.join("gem").exists(),
            "the levels only the tree kept alive are pruned"
        );
        assert!(!v.join(format!("composer/{u}/psr/log@3.0.2")).exists());
        assert!(v.join("state.json").exists());
        assert_eq!(sweep_stale(root).await, 0, "idempotent");
        assert_eq!(sweep_stale(&root.join("missing")).await, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_ok(bytes: &[u8], dest: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dest.join("src")).unwrap();
        std::fs::write(dest.join("src/lib.rs"), bytes).unwrap();
        Ok(())
    }

    fn extract_refused(bytes: &[u8], dest: &Path) -> Result<(), String> {
        std::fs::write(dest.join("partial"), bytes).unwrap();
        Err("corrupt archive".to_string())
    }

    /// The copy dir `.socket/vendor/cargo/<uuid>/c-1` of a fresh project.
    fn layout() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let copy_dir = tmp
            .path()
            .join(".socket/vendor/cargo/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/c-1");
        std::fs::create_dir_all(tmp.path().join(".socket")).unwrap();
        (tmp, copy_dir)
    }

    /// Every entry under `root`, dirs included (a husk shows up).
    fn listing(root: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap() {
                let p = e.unwrap().path();
                out.push(p.strip_prefix(root).unwrap().display().to_string());
                if p.is_dir() {
                    stack.push(p);
                }
            }
        }
        out.sort();
        out
    }

    /// A pre-staged tree lands beside the stage, the bytes come back
    /// untouched, and claiming moves it into the backend's stage.
    #[tokio::test]
    async fn an_extracted_tree_is_claimed_into_the_stage() {
        let _serial = TEST_LOCK.lock().await;
        let (tmp, copy_dir) = layout();
        let recipe = PrestageRecipe::extract(tmp.path(), &copy_dir, extract_ok);
        let (bytes, prestaged) = run(&recipe, b"patched".to_vec()).await;
        assert_eq!(bytes, b"patched");
        let tree = prestaged.tree.expect("a staged tree");
        assert!(prestage_dir_for(&copy_dir).join("src/lib.rs").is_file());
        let stage = super::super::common::stage_dir_for(&copy_dir);
        std::fs::create_dir_all(stage.join("litter")).unwrap();
        // Only the stage of THIS copy dir may claim it.
        assert!(
            !tree
                .claim_into(&stage, &copy_dir.with_file_name("other"))
                .await
        );
        assert!(tree.claim_into(&stage, &copy_dir).await);
        assert_eq!(std::fs::read(stage.join("src/lib.rs")).unwrap(), b"patched");
        assert!(
            !stage.join("litter").exists(),
            "litter replaced, as remove_tree would"
        );
        assert!(!prestage_dir_for(&copy_dir).exists());
        drop(tree);
        settle().await;
        assert!(
            stage.join("src/lib.rs").is_file(),
            "a claimed tree is never cleaned up"
        );
    }

    /// A refused extraction leaves nothing claimable and nothing behind
    /// once settled: not its partial tree, not the empty levels it made.
    #[tokio::test]
    async fn a_refused_extraction_stages_nothing() {
        let _serial = TEST_LOCK.lock().await;
        let (tmp, copy_dir) = layout();
        let recipe = PrestageRecipe::extract(tmp.path(), &copy_dir, extract_refused);
        let (bytes, prestaged) = run(&recipe, b"bytes".to_vec()).await;
        assert_eq!(bytes, b"bytes", "the backend still gets the bytes");
        assert!(prestaged.tree.is_none());
        assert!(!prestage_dir_for(&copy_dir).exists());
        settle().await;
        assert_eq!(listing(tmp.path()), vec![".socket".to_string()]);
    }

    /// A tree nobody claims is left alone until `settle`, which removes it
    /// and the vendor levels it created, stopping below `.socket`.
    #[tokio::test]
    async fn an_unclaimed_tree_is_removed_by_settle_only() {
        let _serial = TEST_LOCK.lock().await;
        let (tmp, copy_dir) = layout();
        let recipe = PrestageRecipe::extract(tmp.path(), &copy_dir, extract_ok);
        let (_, prestaged) = run(&recipe, b"patched".to_vec()).await;
        drop(prestaged);
        assert!(
            prestage_dir_for(&copy_dir).is_dir(),
            "never removed while the loop may still run"
        );
        settle().await;
        assert_eq!(listing(tmp.path()), vec![".socket".to_string()]);
    }

    /// The afterHash verdict answers only for the files it was computed
    /// against.
    #[tokio::test]
    async fn a_zip_verdict_answers_only_for_its_own_files() {
        let _serial = TEST_LOCK.lock().await;
        let files: HashMap<String, PatchFileInfo> = HashMap::from([(
            "a.txt".to_string(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash: "0".repeat(64),
            },
        )]);
        let (_, prestaged) = run(&PrestageRecipe::verify_zip(&files), b"not a zip".to_vec()).await;
        assert_eq!(
            prestaged.zip_verdict(&files),
            Some(super::super::common::zip_bytes_match_after_hashes(
                b"not a zip",
                &files
            ))
        );
        assert_eq!(prestaged.zip_verdict(&HashMap::new()), None);
    }
}
