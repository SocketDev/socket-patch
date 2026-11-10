//! The project directories of a checkout at and below `--cwd`.
//!
//! A bare hosted or vendored `scan` covers every one of them
//! ([`discovered`]), so what it patches is spread over several directories,
//! each with its own lockfiles and `.socket/`. Whatever `scan` does from a
//! directory must be visible and undoable from that directory, so the
//! commands that read or undo patches look for the same directories when
//! `--cwd` holds no patches of its own ([`patched`]): `list` and a bare
//! `rollback` cover each of them, and the commands that act on one project
//! name them and the run that reaches each ([`Advice`]).
//!
//! One search serves both, so no command sees a project another does not:
//! the in-memory engine's root detection over a walk of the checkout, less
//! what the socket.yml path policy (its built-in test and fixture ignores
//! included) leaves out of a discovered set.

use std::path::{Path, PathBuf};

use socket_patch_core::constants::DEFAULT_PATCH_MANIFEST_PATH;
use socket_patch_core::policy::{
    find_repo_root_with_warnings, repo_relative_checked, DiskPolicyFs, PolicyError,
    PolicyOverrides, PolicyWarning, Root, SelectionPolicy,
};
use socket_patch_core::utils::target::Target;

use crate::args::GlobalArgs;
use crate::hosted_memory::roots::{marker_ecosystem, roots_below, UNSUPPORTED_MARKERS};
use crate::json_envelope::RunWarning;
use crate::ui::{plural, shell_word};

/// A repository's socket.yml policy and the root it was read from.
pub(crate) struct RepoPolicy {
    pub policy: SelectionPolicy,
    pub repo_root: PathBuf,
    pub warnings: Vec<PolicyWarning>,
    /// Whether `repo_root` is a git checkout (rather than `--cwd` standing
    /// in for one). Project directories are searched for only inside a
    /// checkout: its root bounds the walk.
    pub in_git_repo: bool,
}

impl RepoPolicy {
    /// Read the policy of the repository holding `cwd` (canonical): the
    /// root socket.yml of the trusted git checkout around it, else of `cwd`.
    pub(crate) fn load(cwd: &Path, overrides: &PolicyOverrides) -> Result<Self, PolicyError> {
        let (repo_root, mut warnings) = find_repo_root_with_warnings(cwd);
        let in_git_repo = socket_patch_core::utils::repo_root::find_git_repo(cwd)
            .is_some_and(|repo| repo.trusted && repo.root == repo_root);
        let (policy, load_warnings) =
            SelectionPolicy::load(&DiskPolicyFs::new(&repo_root), overrides)?;
        warnings.extend(load_warnings);
        Ok(Self {
            policy,
            repo_root,
            warnings,
            in_git_repo,
        })
    }
}

/// The marker files of a disk project root: the same lock markers the
/// in-memory engine detects roots by, plus the maven/nuget markers disk
/// scans support. When a directory has none of those, its manifests
/// ([`MANIFEST_MARKERS`] and the JVM build files) are its markers instead;
/// the in-memory engine has no such fallback (manifests alone never make
/// a root there), so for a lockless directory the two engines disagree.
pub(crate) fn dir_markers(dir: &Path) -> Vec<String> {
    let mut markers = lock_markers(dir);
    if markers.is_empty() {
        // No lockfile: the manifests say what the project is. Every name
        // here, JVM build files included, must be a regular file: the
        // root-marker report lists files, so it deliberately keeps
        // `is_file` rather than `layout::marker_present` (which lets a
        // directory named like a build file mark a JVM build).
        markers = MANIFEST_MARKERS
            .iter()
            .chain(socket_patch_core::vendor::jvm::layout::JVM_PROJECT_MARKERS)
            .filter(|name| dir.join(name).is_file())
            .map(|name| name.to_string())
            .collect();
    }
    markers.sort();
    markers
}

/// The lockfile markers in `dir` (unsorted): what makes a directory a
/// project root of its own rather than a member of an enclosing one.
pub(crate) fn lock_markers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_ok_and(|t| t.is_file() || t.is_symlink()))
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|name| {
                    marker_ecosystem(name).is_some()
                        || UNSUPPORTED_MARKERS
                            .iter()
                            .any(|(_, names)| names.contains(&name.as_str()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Manifests that stand in as markers for a root with no lockfile (plus
/// every JVM build file, `layout::JVM_PROJECT_MARKERS`).
const MANIFEST_MARKERS: [&str; 6] = [
    "package.json",
    "pyproject.toml",
    "setup.py",
    "Cargo.toml",
    "composer.json",
    "Gemfile",
];

/// The project directories at and below `--cwd`, found by [`discovered`].
pub(crate) struct DiscoveredDirs {
    /// `--cwd` (when it is a project) and every project root below it,
    /// sorted; the flag says whether the user named the directory: only
    /// `--cwd` is explicit.
    pub dirs: Vec<(PathBuf, bool)>,
    /// Roots the socket.yml path policy (its built-in test and fixture
    /// ignores included) left out.
    pub ignored: usize,
    /// The walk gave up before it had seen the whole tree.
    pub truncated: bool,
}

/// The projects at and below `--cwd`: the roots the in-memory engine
/// detects for the same checkout (`roots_below`), less the ones the
/// socket.yml path `policy` (read from `repo_root`) leaves out of a
/// discovered set. `--cwd` itself is the user's choice, so it is explicit
/// and stays in whenever it is a project at all (a lockless one included).
pub(crate) async fn discovered(
    common: &GlobalArgs,
    policy: &SelectionPolicy,
    repo_root: &Path,
) -> DiscoveredDirs {
    let cwd = &common.cwd;
    // The socket.yml path policy's verdict on a root (`""` is `--cwd`,
    // which the user named).
    let admitted = |rel: &str| {
        let dir = if rel.is_empty() {
            cwd.clone()
        } else {
            cwd.join(rel)
        };
        let resolved = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
        let Some(project) = repo_relative_checked(repo_root, &resolved) else {
            return false;
        };
        policy
            .admits_root(&Root {
                rel_dir: &project,
                markers: &dir_markers(&dir),
                explicit: rel.is_empty(),
            })
            .is_ok()
    };
    let found = roots_below(cwd, common.ecosystems.as_deref(), admitted).await;
    let mut dirs = Vec::new();
    let mut ignored = 0;
    if found.governs_members || !dir_markers(cwd).is_empty() {
        dirs.push((cwd.clone(), true));
    }
    for rel in found.roots.iter().filter(|rel| !rel.is_empty()) {
        if admitted(rel) {
            dirs.push((cwd.join(rel), false));
        } else {
            ignored += 1;
        }
    }
    DiscoveredDirs {
        dirs,
        ignored,
        truncated: found.truncated,
    }
}

/// A discovered project directory as a run names it: relative to `--cwd`,
/// `/`-separated.
pub(crate) fn shown_project_dir(cwd: &Path, dir: &Path) -> String {
    dir.strip_prefix(cwd)
        .unwrap_or(dir)
        .to_string_lossy()
        .replace('\\', "/")
}

/// The name of `--cwd` itself among the project directories of a run.
pub(crate) const CWD_NAME: &str = ".";

/// The heading a run prints above one project directory's output. `shown`
/// is the directory relative to `--cwd`; `--cwd` itself, whose relative
/// path is empty, is headed [`CWD_NAME`].
pub(crate) fn heading(shown: &str) -> String {
    let shown = if shown.is_empty() { CWD_NAME } else { shown };
    format!("\n== {shown} ==")
}

/// The patch stores a command acts on. The project directories that hold
/// patches there are the ones a run of it has work in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Work {
    /// Every store: the manifest, the vendor ledger and the hosted pins in
    /// the lockfiles (`vex`, `remove`, `rollback`).
    Any,
    /// The manifest's records: what `apply` applies.
    Manifest,
    /// The manifest and the vendor ledger: what `repair` restores (hosted
    /// mode keeps nothing local).
    Local,
}

/// The patch state of one project, read without changing anything. A store
/// that cannot be read counts as holding patches: the project's own run
/// reports it, so it is state all the same.
#[derive(Default)]
struct PatchState {
    /// `(purl, uuid)` of each patch a store holds. A vendored entry is
    /// named by its ledger key and by its base purl.
    patches: Vec<(String, String)>,
    /// The manifest holds records.
    manifest: bool,
    /// The vendor ledger holds entries.
    vendored: bool,
    /// The lockfiles wire hosted patches (contested wiring included).
    hosted: bool,
}

impl PatchState {
    fn is_empty(&self) -> bool {
        !(self.manifest || self.vendored || self.hosted)
    }

    /// The local stores of the project at `common.cwd`: its manifest and
    /// its vendor ledger.
    async fn read_local(common: &GlobalArgs) -> Self {
        let mut state = Self::default();
        let manifest_path = common.resolved_manifest_path();
        match socket_patch_core::manifest::operations::read_manifest(&manifest_path).await {
            Ok(Some(manifest)) => {
                state.manifest = !manifest.patches.is_empty();
                state.patches.extend(
                    manifest
                        .patches
                        .iter()
                        .map(|(purl, record)| (purl.clone(), record.uuid.clone())),
                );
            }
            Ok(None) => {}
            Err(_) => state.manifest = true,
        }
        match socket_patch_core::vendor::load_state(&common.project_root()).await {
            Ok(ledger) => {
                state.vendored = !ledger.entries.is_empty();
                for (key, entry) in &ledger.entries {
                    state.patches.push((key.clone(), entry.uuid.clone()));
                    if entry.base_purl != *key {
                        state
                            .patches
                            .push((entry.base_purl.clone(), entry.uuid.clone()));
                    }
                }
            }
            Err(_) => state.vendored = true,
        }
        state
    }

    /// Every store of the project at `common.cwd`: [`Self::read_local`]
    /// and the hosted pins its lockfiles wire.
    async fn read(common: &GlobalArgs) -> Self {
        let mut state = Self::read_local(common).await;
        let inventory = crate::commands::hosted_inventory(common, &common.project_root()).await;
        state.hosted = !inventory.is_empty();
        state.patches.extend(
            inventory
                .unwindable()
                .into_iter()
                .map(|pin| (pin.purl, pin.uuid)),
        );
        state
    }
}

/// Whether the project at `--cwd` holds patch state in any store.
pub(crate) async fn cwd_is_patched(common: &GlobalArgs) -> bool {
    // The local stores first: a project with a manifest or a ledger is
    // settled without a read of its lockfiles.
    !PatchState::read_local(common).await.is_empty()
        || !crate::commands::hosted_inventory(common, &common.project_root())
            .await
            .is_empty()
}

/// A project directory below `--cwd` that holds patches.
pub(crate) struct PatchedProject {
    /// The directory: what a run of its own takes as `--cwd`.
    pub dir: PathBuf,
    /// Relative to `--cwd`: the name its heading and every message use.
    pub shown: String,
    state: PatchState,
}

impl PatchedProject {
    /// The run's flags, re-aimed at this project.
    pub(crate) fn common(&self, common: &GlobalArgs) -> GlobalArgs {
        let mut child = common.clone();
        child.cwd = self.dir.clone();
        child
    }

    /// The command line that runs `command` (the subcommand and its
    /// arguments, already shell-quoted) for this project, as the run
    /// `common` was asked to: a preview stays a preview.
    pub(crate) fn command(&self, common: &GlobalArgs, command: &str) -> String {
        // `--cwd .` joins to `./api`; the bare relative path names the same
        // directory.
        let dir = self.dir.strip_prefix(".").unwrap_or(&self.dir);
        let dry_run = if common.dry_run { " --dry-run" } else { "" };
        format!(
            "socket-patch {command}{dry_run} --cwd {}",
            shell_word(&dir.to_string_lossy())
        )
    }

    /// Whether a command acting on `work` has anything to do here.
    fn has(&self, work: Work) -> bool {
        match work {
            Work::Any => true,
            Work::Manifest => self.state.manifest,
            Work::Local => self.state.manifest || self.state.vendored,
        }
    }

    fn holds(&self, target: &Target) -> bool {
        self.state
            .patches
            .iter()
            .any(|(purl, uuid)| target.matches_patch(purl, uuid))
    }
}

/// What [`patched`] found.
#[derive(Default)]
pub(crate) struct Below {
    /// The patched projects below `--cwd`, sorted by directory.
    pub projects: Vec<PatchedProject>,
    /// What kept the search from being complete, one sentence each: a
    /// socket.yml that cannot be honored, a walk that gave up. A human run
    /// prints each as a `Warning:`; `list --json` carries them as
    /// [`PROJECTS_BELOW_NOT_SEARCHED`] warnings.
    pub notes: Vec<String>,
}

/// Warning code: the project directories below `--cwd` could not all be
/// searched for patches.
pub(crate) const PROJECTS_BELOW_NOT_SEARCHED: &str = "projects_below_not_searched";

/// The env binding of scan's `--no-socket-yml`: a run made under it reads
/// the same set of project directories that scan covered.
const NO_SOCKET_YML_ENV: &str = "SOCKET_NO_SOCKET_YML";

fn path_policy_overrides() -> PolicyOverrides {
    PolicyOverrides {
        bypass: std::env::var(NO_SOCKET_YML_ENV)
            .ok()
            .is_some_and(|value| crate::args::parse_bool_flag(&value).unwrap_or(false)),
        min_severity: None,
    }
}

/// Whether a run at `--cwd` looks for project directories below it at
/// all: the bounds a bare scan's search has. Only a project run (never the
/// global installs), over the default manifest (one the user pointed at
/// names the single project the run is about), inside a trusted git
/// checkout, whose root bounds the walk.
pub(crate) fn searches_below(common: &GlobalArgs) -> bool {
    if common.is_global() || common.manifest_path != DEFAULT_PATCH_MANIFEST_PATH {
        return false;
    }
    let cwd = std::fs::canonicalize(&common.cwd).unwrap_or_else(|_| common.cwd.clone());
    socket_patch_core::utils::repo_root::find_git_repo(&cwd).is_some_and(|repo| repo.trusted)
}

/// How much of each project directory [`patched`] reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Depth {
    /// The manifest and the vendor ledger: no lockfile is parsed. For
    /// `apply`, which works from the manifest alone and whose no-manifest
    /// exit is the cheap no-op CI steps and install hooks rely on.
    Local,
    /// Those and the hosted pins the lockfiles wire.
    All,
}

/// The project directories below `--cwd` that hold patches (in the stores
/// `depth` reads), for a run that found none at `--cwd` itself.
///
/// It never reaches a project a bare scan would not: nothing outside
/// [`searches_below`], and only the directories [`discovered`] returns
/// (the path policy and its built-in test and fixture ignores are applied
/// before any of a directory's files is read).
pub(crate) async fn patched(common: &GlobalArgs, depth: Depth) -> Below {
    let mut below = Below::default();
    if !searches_below(common) {
        return below;
    }
    let cwd = std::fs::canonicalize(&common.cwd).unwrap_or_else(|_| common.cwd.clone());
    let repo = match RepoPolicy::load(&cwd, &path_policy_overrides()) {
        Ok(repo) if repo.in_git_repo => repo,
        Ok(_) => return below,
        Err(err) => {
            below.notes.push(format!(
                "the project directories below this one were not searched for Socket \
                 patches: {err}"
            ));
            return below;
        }
    };
    let found = discovered(common, &repo.policy, &repo.repo_root).await;
    for (dir, explicit) in &found.dirs {
        // `--cwd` itself is the caller's to read.
        if *explicit {
            continue;
        }
        let mut project = PatchedProject {
            dir: dir.clone(),
            shown: shown_project_dir(&common.cwd, dir),
            state: PatchState::default(),
        };
        let child = project.common(common);
        project.state = match depth {
            Depth::Local => PatchState::read_local(&child).await,
            Depth::All => PatchState::read(&child).await,
        };
        if !project.state.is_empty() {
            below.projects.push(project);
        }
    }
    if found.truncated {
        below.notes.push(
            "this directory tree is too large to search for project directories; some that \
             hold Socket patches may have been missed"
                .to_string(),
        );
    }
    below
}

/// Warning code: a command that acts on one project found nothing at
/// `--cwd`, and project directories below it hold patches.
pub(crate) const PATCHED_PROJECTS_BELOW: &str = "patched_projects_below";

/// What such a command says: which project directories below `--cwd` hold
/// patches, and the run that reaches each. Empty when there are none.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Advice {
    /// The sentence naming the directories (no final period).
    headline: String,
    /// One command per directory to run instead; none when the command has
    /// no work in any of them.
    commands: Vec<String>,
}

/// How many directories (and commands) a message spells out before it
/// counts the rest: a checkout can hold hundreds of projects.
const SPELLED_OUT: usize = 10;

/// `a, b, c`, or the first [`SPELLED_OUT`] and `and N more`.
fn spelled_out(names: &[&str]) -> String {
    match names.len().checked_sub(SPELLED_OUT) {
        Some(more @ 1..) => format!("{}, and {more} more", names[..SPELLED_OUT].join(", ")),
        _ => names.join(", "),
    }
}

impl Advice {
    fn is_empty(&self) -> bool {
        self.headline.is_empty()
    }

    /// How many commands are left out of a message.
    fn more_commands(&self) -> usize {
        self.commands.len().saturating_sub(SPELLED_OUT)
    }

    /// The advice as one sentence: the detail of its `--json` warning.
    fn detail(&self) -> String {
        if self.commands.is_empty() {
            return format!(
                "{}; `socket-patch list` shows what each one holds",
                self.headline
            );
        }
        let mut commands: Vec<String> = self
            .commands
            .iter()
            .take(SPELLED_OUT)
            .map(|c| format!("`{c}`"))
            .collect();
        if self.more_commands() > 0 {
            commands.push(format!(
                "and the same for the other {} (`socket-patch list` names them)",
                self.more_commands()
            ));
        }
        format!("{}: run {}", self.headline, commands.join(", "))
    }

    /// The `warnings[]` entry of a `--json` run (none when empty).
    pub(crate) fn warnings(&self) -> Vec<RunWarning> {
        if self.is_empty() {
            return Vec::new();
        }
        vec![RunWarning::new(PATCHED_PROJECTS_BELOW, self.detail())]
    }

    /// The lines of a human run: the headline, then one command per line.
    fn lines(&self) -> Vec<String> {
        if self.is_empty() {
            return Vec::new();
        }
        if self.commands.is_empty() {
            return vec![format!("Note: {}.", self.detail())];
        }
        let mut lines = vec![format!("Note: {}. Run:", self.headline)];
        lines.extend(
            self.commands
                .iter()
                .take(SPELLED_OUT)
                .map(|c| format!("  {c}")),
        );
        if self.more_commands() > 0 {
            lines.push(format!(
                "  and the same for the other {} (`socket-patch list` names them)",
                self.more_commands()
            ));
        }
        lines
    }

    /// Print the advice on stderr, below the command's own message.
    pub(crate) fn print(&self) {
        for line in self.lines() {
            eprintln!("{line}");
        }
    }
}

impl Below {
    /// Print [`Below::notes`] on stderr (a human run).
    pub(crate) fn print_notes(&self) {
        for note in &self.notes {
            eprintln!("Warning: {note}.");
        }
    }

    /// The directories' names, for a message: `api, svc, web` (the first
    /// [`SPELLED_OUT`], then a count).
    pub(crate) fn names(&self) -> String {
        let names: Vec<&str> = self.projects.iter().map(|p| p.shown.as_str()).collect();
        spelled_out(&names)
    }

    /// `3 project directories below this one`.
    pub(crate) fn counted(&self) -> String {
        format!(
            "{} below this one",
            plural(
                self.projects.len(),
                "project directory",
                "project directories"
            )
        )
    }

    /// The advice of a run of `command` (the subcommand and its arguments,
    /// already shell-quoted) that found nothing at `--cwd`: the directories
    /// where it has `work`, each with its command. With `targets` (the
    /// identifiers of a `remove` or a `rollback`), only the directories
    /// holding a patch one of them names are worth a run.
    pub(crate) fn advice(
        &self,
        common: &GlobalArgs,
        command: &str,
        work: Work,
        targets: &[String],
    ) -> Advice {
        if self.projects.is_empty() {
            return Advice::default();
        }
        let hold = |n: usize| if n == 1 { "holds" } else { "hold" };
        let named = targets.join(", ");
        let targets: Vec<Target> = targets.iter().map(|t| Target::parse(t)).collect();
        let holders: Vec<&PatchedProject> = self
            .projects
            .iter()
            .filter(|project| project.has(work))
            .filter(|project| {
                targets.is_empty() || targets.iter().any(|target| project.holds(target))
            })
            .collect();
        if holders.is_empty() {
            // Patched all the same: say so, and why no run is named.
            let why = if !targets.is_empty() {
                format!("but none holds a patch matching {named}")
            } else if work == Work::Local {
                "all hosted: there is nothing local to repair".to_string()
            } else {
                // `apply` reads no lockfile, so it cannot tell what the
                // directories without a manifest hold: it says nothing.
                return Advice::default();
            };
            return Advice {
                headline: format!(
                    "{} {} Socket patches ({}), {why}",
                    self.counted(),
                    hold(self.projects.len()),
                    self.names()
                ),
                commands: Vec::new(),
            };
        }
        let count = plural(holders.len(), "project directory", "project directories");
        let names: Vec<&str> = holders.iter().map(|p| p.shown.as_str()).collect();
        let names = spelled_out(&names);
        let what = if !targets.is_empty() {
            format!("a patch matching {named}")
        } else {
            match work {
                Work::Any => "Socket patches",
                Work::Manifest => "a patch manifest",
                Work::Local => "local patch state",
            }
            .to_string()
        };
        Advice {
            headline: format!(
                "{count} below this one {} {what} ({names})",
                hold(holders.len())
            ),
            commands: holders.iter().map(|p| p.command(common, command)).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUESTS: (&str, &str) = (
        "pkg:pypi/requests@2.31.0",
        "11111111-1111-4111-8111-111111111111",
    );
    const MINIMIST: (&str, &str) = (
        "pkg:npm/minimist@1.2.2",
        "22222222-2222-4222-8222-222222222222",
    );

    /// A project in agent mode (a manifest) or hosted mode (lockfile pins).
    fn project(cwd: &str, shown: &str, patch: (&str, &str), manifest: bool) -> PatchedProject {
        PatchedProject {
            dir: Path::new(cwd).join(shown),
            shown: shown.to_string(),
            state: PatchState {
                patches: vec![(patch.0.to_string(), patch.1.to_string())],
                manifest,
                vendored: false,
                hosted: !manifest,
            },
        }
    }

    /// `api` in agent mode and `web` hosted, below `cwd`.
    fn below(cwd: &str) -> Below {
        Below {
            projects: vec![
                project(cwd, "api", REQUESTS, true),
                project(cwd, "web", MINIMIST, false),
            ],
            notes: Vec::new(),
        }
    }

    /// A run with the default flags.
    fn run() -> GlobalArgs {
        GlobalArgs::default()
    }

    #[test]
    fn advice_names_every_directory_and_its_command() {
        let advice = below(".").advice(&run(), "vex", Work::Any, &[]);
        assert_eq!(
            advice.lines(),
            [
                "Note: 2 project directories below this one hold Socket patches (api, web). Run:",
                "  socket-patch vex --cwd api",
                "  socket-patch vex --cwd web",
            ]
        );
        let warnings = advice.warnings();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, PATCHED_PROJECTS_BELOW);
        assert_eq!(
            warnings[0].detail,
            "2 project directories below this one hold Socket patches (api, web): run \
             `socket-patch vex --cwd api`, `socket-patch vex --cwd web`"
        );
    }

    /// The command must work as printed: `--cwd` is the directory the run
    /// was given joined with the project's, quoted when the shell needs it.
    #[cfg(unix)]
    #[test]
    fn the_command_carries_the_cwd_the_run_was_given() {
        let advice = below("/work/my repo").advice(&run(), "vex", Work::Any, &[]);
        assert_eq!(
            advice.lines()[1],
            "  socket-patch vex --cwd '/work/my repo/api'"
        );
        let advice = below("mono").advice(&run(), "apply --check", Work::Manifest, &[]);
        assert_eq!(
            advice.lines()[1],
            "  socket-patch apply --check --cwd mono/api"
        );
    }

    /// The command for a preview is a preview: pasting it must not do what
    /// the run it came from only described.
    #[test]
    fn a_dry_run_is_advised_a_dry_run() {
        let preview = GlobalArgs {
            dry_run: true,
            ..GlobalArgs::default()
        };
        let target = MINIMIST.0.to_string();
        let advice = below(".").advice(&preview, "rollback minimist", Work::Any, &[target]);
        assert_eq!(
            advice.commands,
            ["socket-patch rollback minimist --dry-run --cwd web"]
        );
    }

    /// A command is sent only where it has work: `apply` to a manifest,
    /// `repair` to local state.
    #[test]
    fn a_command_is_named_only_for_the_directories_it_has_work_in() {
        let below = below(".");
        assert_eq!(
            below.advice(&run(), "apply", Work::Manifest, &[]).lines(),
            [
                "Note: 1 project directory below this one holds a patch manifest (api). Run:",
                "  socket-patch apply --cwd api",
            ]
        );
        assert_eq!(
            below.advice(&run(), "repair", Work::Local, &[]).lines(),
            [
                "Note: 1 project directory below this one holds local patch state (api). Run:",
                "  socket-patch repair --cwd api",
            ]
        );
    }

    /// Hosted projects are still patched projects: a command with nothing
    /// to do in any of them says so instead of sending the user there.
    #[test]
    fn hosted_only_directories_are_named_without_a_command() {
        let hosted = Below {
            projects: vec![
                project(".", "svc", REQUESTS, false),
                project(".", "web", MINIMIST, false),
            ],
            notes: Vec::new(),
        };
        assert_eq!(
            hosted.advice(&run(), "repair", Work::Local, &[]).lines(),
            [
                "Note: 2 project directories below this one hold Socket patches (svc, web), \
                 all hosted: there is nothing local to repair; `socket-patch list` shows what \
                 each one holds."
            ]
        );
        // `apply` has no work without a manifest and nothing to say.
        assert!(hosted
            .advice(&run(), "apply", Work::Manifest, &[])
            .is_empty());
    }

    /// A checkout can hold hundreds of projects: a message spells out the
    /// first few directories and commands and counts the rest.
    #[test]
    fn a_long_list_of_directories_is_counted_not_spelled_out() {
        let shown: Vec<String> = (0..25).map(|n| format!("p{n:02}")).collect();
        let many = Below {
            projects: shown
                .iter()
                .map(|shown| project(".", shown, MINIMIST, false))
                .collect(),
            notes: Vec::new(),
        };
        assert_eq!(
            many.names(),
            "p00, p01, p02, p03, p04, p05, p06, p07, p08, p09, and 15 more"
        );
        let advice = many.advice(&run(), "vex", Work::Any, &[]);
        let lines = advice.lines();
        assert_eq!(lines.len(), 12, "{lines:?}");
        assert_eq!(lines[10], "  socket-patch vex --cwd p09");
        assert_eq!(
            lines[11],
            "  and the same for the other 15 (`socket-patch list` names them)"
        );
        assert!(advice.warnings()[0].detail.ends_with(
            "`socket-patch vex --cwd p09`, and the same for the other 15 (`socket-patch list` \
             names them)"
        ));
    }

    #[test]
    fn an_identifier_narrows_the_advice_to_the_directories_holding_it() {
        let below = below(".");
        let purl = MINIMIST.0.to_string();
        let advice = below.advice(&run(), &format!("remove {purl}"), Work::Any, &[purl]);
        assert_eq!(
            advice.lines(),
            [
                "Note: 1 project directory below this one holds a patch matching \
                 pkg:npm/minimist@1.2.2 (web). Run:",
                "  socket-patch remove pkg:npm/minimist@1.2.2 --cwd web",
            ]
        );
        // By uuid and by bare name too: the shared target grammar.
        for target in [REQUESTS.1, "requests"] {
            let advice = below.advice(
                &run(),
                &format!("remove {target}"),
                Work::Any,
                &[target.to_string()],
            );
            assert_eq!(
                advice.commands,
                [format!("socket-patch remove {target} --cwd api")]
            );
        }
    }

    #[test]
    fn an_identifier_no_directory_holds_gets_no_command() {
        let target = "pkg:npm/left-pad@1.3.0".to_string();
        let advice = below(".").advice(&run(), "remove x", Work::Any, &[target]);
        assert_eq!(
            advice.lines(),
            [
                "Note: 2 project directories below this one hold Socket patches (api, web), but \
                 none holds a patch matching pkg:npm/left-pad@1.3.0; `socket-patch list` shows \
                 what each one holds."
            ]
        );
        assert_eq!(advice.warnings().len(), 1);
    }

    /// `--cwd` has a name among a run's headings: its path relative to
    /// itself is empty, which reads as nothing at all.
    #[test]
    fn cwd_itself_is_named_among_the_directories() {
        assert_eq!(shown_project_dir(Path::new("mono"), Path::new("mono")), "");
        assert_eq!(heading(""), "\n== . ==");
        assert_eq!(heading(CWD_NAME), "\n== . ==");
        assert_eq!(heading("services/api"), "\n== services/api ==");
    }

    #[test]
    fn no_projects_no_advice() {
        let advice = Below::default().advice(&run(), "vex", Work::Any, &[]);
        assert!(advice.lines().is_empty());
        assert!(advice.warnings().is_empty());
    }

    fn write_hosted_lock(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("yarn.lock"),
            "# yarn lockfile v1\n\n\nleft-pad@1.2.3:\n  version \"1.2.3\"\n  resolved \
             \"https://patch.socket.dev/patch/npm/left-pad/1.2.3/\
             66666666-6666-4666-8666-666666666666/55555555-5555-4555-8555-555555555555/\
             left-pad-1.2.3.tgz\"\n  integrity sha512-PATCHEDpatched==\n",
        )
        .unwrap();
    }

    fn write_plain_lock(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
    }

    fn write_manifest(dir: &Path, patches: serde_json::Value) {
        std::fs::create_dir_all(dir.join(".socket")).unwrap();
        std::fs::write(
            dir.join(".socket/manifest.json"),
            serde_json::to_vec(&serde_json::json!({ "patches": patches })).unwrap(),
        )
        .unwrap();
    }

    fn names(below: &Below) -> Vec<&str> {
        below.projects.iter().map(|p| p.shown.as_str()).collect()
    }

    fn common_at(root: &Path) -> GlobalArgs {
        GlobalArgs {
            cwd: root.to_path_buf(),
            ..GlobalArgs::default()
        }
    }

    /// The search has scan's bounds: a checkout, project scope, the default
    /// manifest, and the path policy's built-in ignores.
    #[tokio::test]
    async fn the_search_is_bounded_like_a_scan() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_hosted_lock(&root.join("web"));
        write_hosted_lock(&root.join("tests/fixtures/app"));
        // A project with a lockfile and no patches is not a patched one.
        write_plain_lock(&root.join("plain"));
        let common = common_at(root);

        assert!(!searches_below(&common), "no checkout, no search");
        assert!(patched(&common, Depth::All).await.projects.is_empty());

        std::fs::create_dir_all(root.join(".git")).unwrap();
        assert!(searches_below(&common));
        let found = patched(&common, Depth::All).await;
        assert_eq!(names(&found), ["web"]);
        assert_eq!(found.projects[0].dir, root.join("web"));
        assert!(found.notes.is_empty());

        let global = GlobalArgs {
            global_prefix: Some(root.to_path_buf()),
            ..common.clone()
        };
        assert!(patched(&global, Depth::All).await.projects.is_empty());
        let pointed = GlobalArgs {
            manifest_path: "web/.socket/manifest.json".to_string(),
            ..common.clone()
        };
        assert!(patched(&pointed, Depth::All).await.projects.is_empty());
    }

    /// What a project holds decides which commands have work in it; an
    /// empty manifest is no patch, an unreadable one is state.
    #[tokio::test]
    async fn each_store_is_read_for_what_it_holds() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        write_hosted_lock(&root.join("web"));
        write_plain_lock(&root.join("api"));
        write_manifest(
            &root.join("api"),
            serde_json::json!({ "pkg:npm/is-odd@3.0.1": {
                "uuid": "99999999-9999-4999-8999-999999999999",
                "exportedAt": "2026-01-01T00:00:00Z", "files": {}, "vulnerabilities": {},
                "description": "", "license": "MIT", "tier": "free",
            } }),
        );
        write_plain_lock(&root.join("empty"));
        write_manifest(&root.join("empty"), serde_json::json!({}));
        let common = common_at(root);

        let found = patched(&common, Depth::All).await;
        assert_eq!(names(&found), ["api", "web"]);
        let (api, web) = (&found.projects[0], &found.projects[1]);
        assert!(api.has(Work::Manifest) && api.has(Work::Local));
        assert!(!web.has(Work::Manifest) && !web.has(Work::Local) && web.has(Work::Any));
        assert!(api.holds(&Target::parse("pkg:npm/is-odd@3.0.1")));
        assert!(web.holds(&Target::parse("55555555-5555-4555-8555-555555555555")));
        assert!(!web.holds(&Target::parse("is-odd")));

        // The local read parses no lockfile: hosted pins are not seen.
        assert_eq!(names(&patched(&common, Depth::Local).await), ["api"]);

        // A manifest that cannot be read is state its project reports.
        std::fs::write(root.join("empty/.socket/manifest.json"), b"{ not json").unwrap();
        assert_eq!(
            names(&patched(&common, Depth::All).await),
            ["api", "empty", "web"]
        );
    }

    /// A socket.yml that cannot be honored stops the search with a note
    /// instead of guessing which directories it would have left out.
    #[tokio::test]
    async fn an_invalid_socket_yml_stops_the_search_with_a_note() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        write_hosted_lock(&root.join("web"));
        std::fs::write(root.join("socket.yml"), "version: 2\npatches: [\n").unwrap();
        let found = patched(&common_at(root), Depth::All).await;
        assert!(found.projects.is_empty());
        assert_eq!(found.notes.len(), 1, "{:?}", found.notes);
        assert!(found.notes[0].starts_with("the project directories below this one were not"));
    }

    #[tokio::test]
    async fn cwd_is_patched_reads_every_store() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let common = common_at(root);
        assert!(!cwd_is_patched(&common).await);
        write_manifest(root, serde_json::json!({}));
        assert!(
            !cwd_is_patched(&common).await,
            "an empty manifest holds no patch"
        );
        write_hosted_lock(root);
        assert!(cwd_is_patched(&common).await);
    }
}
