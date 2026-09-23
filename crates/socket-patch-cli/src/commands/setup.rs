use clap::Args;
use socket_patch_core::crawlers::python_crawler::is_python_project;
use socket_patch_core::crawlers::Ecosystem;
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::{PatchManifest, SetupConfig};
use socket_patch_core::package_json::detect::{is_setup_configured_str, PackageManager};
use socket_patch_core::package_json::find::{
    detect_package_manager, find_package_json_files, PackageJsonFindResult, PackageJsonLocation,
    WorkspaceType,
};
use socket_patch_core::package_json::update::{
    remove_package_json, update_package_json, RemoveResult, RemoveStatus, UpdateResult,
    UpdateStatus,
};
use socket_patch_core::patch::apply_lock::acquire;
use socket_patch_core::setup::composer::{self, ComposerSetupStatus};
use socket_patch_core::setup::gem::{self, GemSetupStatus};
use socket_patch_core::setup::pypi::detect::{
    deps_contain_hook, detect_python_pm, PythonPackageManager,
};
use socket_patch_core::setup::pypi::edit::{
    add_hook_dependency, pyproject_contains_hook, remove_hook_dependency, ManifestKind,
    PthEditResult, PthStatus,
};
use socket_patch_core::telemetry::track_patch_setup;
use socket_patch_core::vex::applied_patches_with_vendor;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::ecosystem_dispatch::find_manifest_package_paths;
use crate::ui::plural;

/// Stringify the detected npm-family manager for telemetry.
fn manager_name(pm: PackageManager) -> &'static str {
    match pm {
        PackageManager::Npm => "npm",
        PackageManager::Pnpm => "pnpm",
    }
}

/// Compose the `+`-joined telemetry manager tag across the ecosystems in scope
/// (e.g. `npm+pypi+gem`), or `none`.
fn telemetry_manager_str(
    npm: bool,
    py: bool,
    gem: bool,
    composer: bool,
    npm_pm: PackageManager,
) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if npm {
        parts.push(manager_name(npm_pm));
    }
    if py {
        parts.push("pypi");
    }
    if gem {
        parts.push("gem");
    }
    if composer {
        parts.push("composer");
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join("+")
    }
}

#[derive(Args)]
pub struct SetupArgs {
    /// Verify the project is configured for socket-patch without changing
    /// anything. Exits non-zero if any manifest still needs setup.
    #[arg(
        long = "check",
        conflicts_with = "remove",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub check: bool,

    /// Revert the install hooks that `setup` added: npm `package.json` scripts,
    /// the Python `socket-patch[hook]` dependency, and the gem Bundler plugin
    /// wiring.
    #[arg(
        long = "remove",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub remove: bool,

    /// Workspace-member path(s) to exclude from setup (comma-separated, relative
    /// to the repo root). The exclusion is persisted in `.socket/manifest.json`
    /// so `setup --check` and a fresh clone honor it without re-passing the flag.
    // CLI_CONTRACT property 9.
    #[arg(long = "exclude", env = "SOCKET_SETUP_EXCLUDE", value_delimiter = ',')]
    pub exclude: Vec<String>,

    #[command(flatten)]
    pub common: GlobalArgs,
}

pub async fn run(args: SetupArgs) -> i32 {
    apply_env_toggles(&args.common);
    if args.check {
        run_check(&args).await
    } else if args.remove {
        run_remove(&args).await
    } else {
        run_setup(&args).await
    }
}

/// Discover the package.json files `setup`/`check`/`remove` should act on,
/// applying the pnpm "root-only" filtering. Returns an empty vec when none are
/// found (callers also consider Python before reporting `no_files`).
async fn discover(args: &SetupArgs, excludes: &[String]) -> Vec<PackageJsonLocation> {
    let Some(found) = find_members(args).await else {
        return Vec::new();
    };
    warn_unmatched_excludes(
        &args.common,
        &unmatched_excludes(&found, &args.common.cwd, excludes),
    );
    select_members(found, &args.common.cwd, excludes)
}

/// Walk for package.json files; `None` when npm is out of `--ecosystems` scope.
async fn find_members(args: &SetupArgs) -> Option<PackageJsonFindResult> {
    if !eco_in_scope(&args.common, Ecosystem::Npm) {
        return None;
    }
    Some(find_package_json_files(&args.common.cwd).await)
}

/// The exclude values (normalized) that cover no discovered member. Such a
/// value is almost always a typo. Checked against every member, before the
/// pnpm root-only filter.
fn unmatched_excludes(
    found: &PackageJsonFindResult,
    cwd: &Path,
    excludes: &[String],
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for e in excludes {
        let n = normalize_rel_path(e);
        if n.is_empty() || out.contains(&n) {
            continue;
        }
        let matched = found.files.iter().any(|loc| {
            !loc.is_root && is_member_excluded(&loc.path, cwd, std::slice::from_ref(&n))
        });
        if !matched {
            out.push(n);
        }
    }
    out
}

/// Say so (human mode only) rather than silently doing nothing.
fn warn_unmatched_excludes(common: &GlobalArgs, unmatched: &[String]) {
    if common.json || common.silent {
        return;
    }
    for e in unmatched {
        eprintln!("Warning: {}", format_unmatched_exclude(e));
    }
}

/// Apply the pnpm root-only rule and drop excluded members.
fn select_members(
    found: PackageJsonFindResult,
    cwd: &Path,
    excludes: &[String],
) -> Vec<PackageJsonLocation> {
    // For pnpm monorepos, only update root package.json. pnpm runs root
    // postinstall on `pnpm install`, so workspace-level postinstall scripts are
    // unnecessary and would fail under pnpm's strict module isolation.
    let files: Vec<PackageJsonLocation> = match found.workspace_type {
        WorkspaceType::Pnpm => found.files.into_iter().filter(|loc| loc.is_root).collect(),
        _ => found.files,
    };

    // Property 9: drop excluded workspace members (the root is never excludable).
    files
        .into_iter()
        .filter(|loc| loc.is_root || !is_member_excluded(&loc.path, cwd, excludes))
        .collect()
}

/// Emit the shared `no_files` result and exit code. `counts` carries the
/// per-command zero-valued summary fields (`setup` → updated/already/errors,
/// `check` → configured/needs/errors, `remove` → removed/notConfigured/errors)
/// so the `no_files` envelope keeps the documented shape (CLI_CONTRACT "Setup
/// command contract") instead of dropping them.
fn report_no_files(args: &SetupArgs, counts: &[(&str, i64)]) -> i32 {
    if args.common.json {
        // `serde_json::Map` preserves insertion order (the crate enables
        // `preserve_order`), so status → counts → files comes out in that order.
        let mut map = serde_json::Map::new();
        map.insert("status".to_string(), serde_json::json!("no_files"));
        for (key, value) in counts {
            map.insert((*key).to_string(), serde_json::json!(value));
        }
        map.insert("files".to_string(), serde_json::json!([]));
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Object(map))
                .expect("serializing an in-memory JSON value cannot fail")
        );
    } else if !args.common.silent {
        println!("{}", no_files_message(&args.common));
    }
    0
}

/// The setup-capable ecosystems (their `--ecosystems` tokens) and the name
/// of the project each one looks for, in discovery order.
const SETUP_ECOSYSTEMS: &[(Ecosystem, &str)] = &[
    (Ecosystem::Npm, "package.json"),
    (Ecosystem::Pypi, "Python"),
    (Ecosystem::Gem, "Bundler"),
    (Ecosystem::Composer, "Composer"),
];

/// The human `no_files` line for this run's `--ecosystems` scope.
fn no_files_message(common: &GlobalArgs) -> String {
    let in_scope: Vec<&str> = SETUP_ECOSYSTEMS
        .iter()
        .filter(|(eco, _)| eco_in_scope(common, *eco))
        .map(|(_, label)| *label)
        .collect();
    format_no_files(&in_scope, common.ecosystems.as_deref().unwrap_or(&[]))
}

/// `No package.json, Python, Bundler, or Composer project found`, narrowed
/// to the in-scope ecosystems. When `--ecosystems` names none that `setup`
/// can wire, "no project found" would be false (the project may well
/// exist), so say that setup has no hook for them instead.
fn format_no_files(in_scope: &[&str], requested: &[String]) -> String {
    if in_scope.is_empty() {
        return format!(
            "Setup has no install hook for: {} (supported: npm, pypi, gem, composer)",
            requested.join(", ")
        );
    }
    format!("No {} project found", join_or(in_scope))
}

/// `a`, `a or b`, `a, b, or c`.
fn join_or(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_string(),
        [a, b] => format!("{a} or {b}"),
        [init @ .., last] => format!("{}, or {last}", init.join(", ")),
    }
}

/// The warning for an `--exclude` value that matches no workspace member.
fn format_unmatched_exclude(value: &str) -> String {
    format!("--exclude {:?} matched no workspace member", value.trim())
}

fn pathdiff(path: &str, base: &Path) -> String {
    let p = Path::new(path);
    p.strip_prefix(base)
        .map(|r| r.display().to_string())
        .unwrap_or_else(|_| path.to_string())
}

/// Whether an ecosystem is in scope for this run, honoring the global
/// `--ecosystems` filter (`CLI_CONTRACT.md` → "Setup command contract",
/// property 2). With no filter (or an empty one) every ecosystem is in scope.
/// The exact `cli_name` match is the only one that can ever fire — clap's
/// value parser admits no alias or case variant — and it is the same rule
/// `partition_purls` applies, so setup's scope never diverges from apply's.
fn eco_in_scope(common: &GlobalArgs, eco: Ecosystem) -> bool {
    match &common.ecosystems {
        None => true,
        Some(list) if list.is_empty() => true,
        Some(list) => list.iter().any(|e| e == eco.cli_name()),
    }
}

/// Normalize a workspace-member / exclude path for comparison: trimmed,
/// forward slashes, no leading `./`, no trailing slash.
///
/// The trim is load-bearing for the CSV spellings of `--exclude`: clap splits
/// `--exclude "packages/a, packages/b"` (and `SOCKET_SETUP_EXCLUDE=a, b`, the
/// idiomatic CI-YAML form) on the comma only, so the second value arrives with
/// a leading space. Untrimmed it matches no member — the exclusion silently
/// does nothing — and the unmatchable spelling is then persisted into
/// `.socket/manifest.json`, where every later run and every clone inherits it.
fn normalize_rel_path(p: &str) -> String {
    let p = p.trim().replace('\\', "/");
    let p = p.strip_prefix("./").unwrap_or(&p);
    p.trim_end_matches('/').to_string()
}

/// Whether a discovered member manifest (`package.json` / `Cargo.toml`) lies in
/// an excluded workspace-member directory (relative to `cwd`). The repo root
/// (relative path `""`) is never excludable — `--exclude` targets members.
/// (CLI_CONTRACT property 9.)
fn is_member_excluded(manifest_path: &Path, cwd: &Path, excludes: &[String]) -> bool {
    if excludes.is_empty() {
        return false;
    }
    let dir = match manifest_path.parent() {
        Some(d) => d,
        None => return false,
    };
    let rel = match dir.strip_prefix(cwd) {
        Ok(r) => normalize_rel_path(&r.to_string_lossy()),
        Err(_) => return false, // outside cwd → not an excludable member
    };
    if rel.is_empty() {
        return false;
    }
    excludes.iter().any(|e| {
        let e = normalize_rel_path(e);
        // An exclusion covers the named directory AND everything below it. The
        // walk finds nested manifests (`tools/inner/package.json`, and members
        // of a member that is itself a workspace root), and those lie *inside*
        // the excluded member — an exact-match-only test wired install hooks
        // into a subtree the user asked setup to keep out of.
        !e.is_empty() && (rel == e || rel.starts_with(&format!("{e}/")))
    })
}

/// This run's ONE read of `.socket/manifest.json`, shared by the exclude
/// resolution, the `--exclude` persistence's already-persisted check and
/// `--check`'s patch-consistency pass (each used to parse the same bytes
/// again).
async fn read_setup_manifest(common: &GlobalArgs) -> io::Result<Option<PatchManifest>> {
    read_manifest(&common.resolved_manifest_path()).await
}

/// The manifest as the read-only consumers see it: absent OR unreadable
/// contribute nothing (the persistence step is what reports an unreadable
/// manifest).
fn manifest_view(existing: &io::Result<Option<PatchManifest>>) -> Option<&PatchManifest> {
    existing.as_ref().ok().and_then(Option::as_ref)
}

/// The exclude set in effect for this run: the persisted `setup.exclude` list
/// from the manifest (empty if no manifest / no setup state) union the
/// `--exclude` flag values (all normalized). This is what a clone inherits —
/// a clone with no flag still reads the persisted set.
fn effective_excludes(manifest: Option<&PatchManifest>, flag: &[String]) -> Vec<String> {
    let mut set: Vec<String> = manifest
        .and_then(|m| m.setup.as_ref())
        .map(|s| s.exclude.iter().map(|e| normalize_rel_path(e)).collect())
        .unwrap_or_default();
    for e in flag {
        let n = normalize_rel_path(e);
        if !n.is_empty() && !set.contains(&n) {
            set.push(n);
        }
    }
    set
}

/// Persist the effective exclude set into `.socket/manifest.json` (creating a
/// minimal manifest if none exists) so `--check` and a fresh clone honor it
/// without re-passing `--exclude`. No-op when the set is empty or `existing`
/// (this run's read) already carries it exactly — no lock, no rewrite, the
/// manifest stays byte-stable. Called only past the run's mutation gate
/// (discovery found work, the preview was confirmed or nothing needed
/// confirming) and never under `--dry-run`, so a no-project directory or an
/// aborted prompt leaves no `.socket/` behind.
///
/// The write is a read-modify-write of the file `apply`/`get`/`remove`/
/// `rollback` rewrite under `apply.lock`, so it takes the same lock and
/// re-reads under it; a missing `.socket/` is created by the acquire and
/// pruned again by the guard's drop if nothing gets written.
///
/// Returns a warning string when persistence was SKIPPED (fail-closed: the
/// lock is held elsewhere, the manifest cannot be read, or the write
/// failed) — the caller folds it into the run's warnings so it reaches the
/// human summary AND the `--json` envelope; a `--silent`/`--json`
/// automation run must not see a fully-successful setup whose excludes
/// silently evaporate on the next flag-less invocation.
async fn persist_setup_excludes(
    common: &GlobalArgs,
    existing: &io::Result<Option<PatchManifest>>,
    excludes: &[String],
) -> Option<String> {
    if excludes.is_empty() {
        return None;
    }
    let mut merged: Vec<String> = excludes.to_vec();
    merged.sort();
    merged.dedup();
    let persisted_exactly = |manifest: &Option<PatchManifest>| {
        manifest
            .as_ref()
            .and_then(|m| m.setup.as_ref())
            .map(|s| &s.exclude)
            == Some(&merged)
    };
    if matches!(existing, Ok(manifest) if persisted_exactly(manifest)) {
        return None; // already persisted exactly — don't lock, don't rewrite
    }

    let path = common.resolved_manifest_path();
    let timeout = Duration::from_secs(common.lock_timeout.unwrap_or(0));
    let _lock = match acquire(&common.socket_dir(), timeout) {
        Ok(guard) => guard,
        Err(err) => {
            let (code, message) = crate::commands::lock_cli::lock_failure(&err, timeout);
            let hint = if code == "lock_held" {
                "re-run `setup` (or pass --lock-timeout <secs>) to persist it"
            } else {
                "the exclude list will need re-passing"
            };
            return Some(format!("not persisting --exclude: {message} — {hint}"));
        }
    };
    // Fail closed on a manifest that exists but cannot be read or parsed: it
    // may still hold recoverable patch records, and flattening the error to
    // "no manifest yet" would rewrite the file down to a bare setup block —
    // destroying them for the sake of persisting an exclude list. Skip
    // persistence loudly instead; nothing else in this run needs the file.
    let existing = match read_manifest(&path).await {
        Ok(existing) => existing,
        Err(e) => {
            return Some(format!(
                "not persisting --exclude: cannot read {}: {e} — the exclude list will \
                 need re-passing until the manifest is repaired",
                path.display()
            ));
        }
    };
    if persisted_exactly(&existing) {
        return None; // a concurrent run persisted it meanwhile
    }
    // Preserve any existing `manual` declarations (property 7) when rewriting.
    let manual = existing
        .as_ref()
        .and_then(|m| m.setup.as_ref())
        .map(|s| s.manual.clone())
        .unwrap_or_default();
    let mut manifest = existing.unwrap_or_else(PatchManifest::new);
    manifest.setup = Some(SetupConfig {
        exclude: merged,
        manual,
    });
    // The acquire created the manifest's directory; a failed write is the
    // same fail-closed skip as an unreadable manifest, never a silent
    // "persisted".
    if let Err(e) = write_manifest(&path, &manifest).await {
        return Some(format!(
            "not persisting --exclude: cannot write {}: {e} — the exclude list will \
             need re-passing",
            path.display()
        ));
    }
    None
}

/// Which ecosystems are **actually set up** at `cwd` — i.e. their auto-repatch
/// hook is present on disk (the same presence checks `setup --check` runs). VEX
/// uses this (∪ the manifest's `manual` declarations) to attest patches only for
/// set-up-or-manual ecosystems (CLI_CONTRACT property 7). Read-only; ignores the
/// `--ecosystems` filter (it reports real on-disk state).
pub(crate) async fn configured_ecosystems(
    common: &GlobalArgs,
) -> std::collections::HashSet<Ecosystem> {
    let mut set = std::collections::HashSet::new();

    // npm: any discovered package.json whose hook scripts are present.
    let npm = find_package_json_files(&common.cwd).await;
    for loc in &npm.files {
        if let Ok(content) = tokio::fs::read_to_string(&loc.path).await {
            if !is_setup_configured_str(&content).needs_update {
                set.insert(Ecosystem::Npm);
                break;
            }
        }
    }

    // pypi: a chosen python manifest carries the `socket-patch[hook]` dep.
    // Detect on-disk state DIRECTLY — not via `plan_python`, which applies the
    // `--ecosystems` filter; this probe must report real state regardless of it
    // (e.g. `vex --ecosystems cargo` must still see a set-up python project).
    if is_python_project(&common.cwd).await {
        let pm = detect_python_pm(&common.cwd).await;
        for (path, kind) in choose_python_manifests(&common.cwd, pm).await {
            if let Ok(content) = tokio::fs::read_to_string(&path).await {
                if manifest_contains_hook(kind, &content) {
                    set.insert(Ecosystem::Pypi);
                    break;
                }
            }
        }
    }

    // gem: the managed plugin directive is present in the Gemfile.
    if let Some(project) = gem::discover_bundler_project(&common.cwd).await {
        if let Ok(content) = tokio::fs::read_to_string(&project.gemfile).await {
            if gem::is_plugin_directive_present(&content) {
                set.insert(Ecosystem::Gem);
            }
        }
    }

    if let Some(composer_json) = composer::discover_composer_project(&common.cwd).await {
        if let Ok(content) = tokio::fs::read_to_string(&composer_json).await {
            if composer::is_hook_present(&content) {
                set.insert(Ecosystem::Composer);
            }
        }
    }

    set
}

// ─────────────────────────────────────────────────────────────────────────
// Python (.pth hook) helpers
// ─────────────────────────────────────────────────────────────────────────

/// Is the hook dependency present in a Python manifest's content? Picks the
/// right detector for the manifest kind: `pyproject.toml` needs the *structural*
/// probe ([`pyproject_contains_hook`]) because the classic-Poetry form
/// (`socket-patch = { extras = ["hook"] }`) has no literal `socket-patch[hook]`
/// substring, so the textual probe would mis-report a configured project;
/// `requirements.txt` uses the textual line probe.
fn manifest_contains_hook(kind: ManifestKind, content: &str) -> bool {
    match kind {
        ManifestKind::Pyproject => pyproject_contains_hook(content),
        ManifestKind::Requirements => deps_contain_hook(content),
    }
}

/// A Python manifest `setup` will edit, plus the resolved package manager.
struct PythonPlan {
    pm: PythonPackageManager,
    manifests: Vec<(PathBuf, ManifestKind)>,
}

/// Decide which Python manifest(s) to edit for the detected package manager.
///
/// pyproject-based managers (uv/poetry/pdm/hatch) edit `pyproject.toml`; pip
/// prefers an existing `requirements.txt`, then a PEP 621 `pyproject.toml`, and
/// otherwise creates `requirements.txt`.
async fn choose_python_manifests(
    cwd: &Path,
    pm: PythonPackageManager,
) -> Vec<(PathBuf, ManifestKind)> {
    let pyproject = cwd.join("pyproject.toml");
    let requirements = cwd.join("requirements.txt");
    let pyproject_exists = tokio::fs::metadata(&pyproject).await.is_ok();
    let requirements_exists = tokio::fs::metadata(&requirements).await.is_ok();

    match pm {
        PythonPackageManager::Uv
        | PythonPackageManager::Poetry
        | PythonPackageManager::Pdm
        | PythonPackageManager::Hatch => {
            if pyproject_exists {
                vec![(pyproject, ManifestKind::Pyproject)]
            } else {
                vec![]
            }
        }
        PythonPackageManager::Pip => {
            if requirements_exists {
                vec![(requirements, ManifestKind::Requirements)]
            } else if pyproject_exists {
                vec![(pyproject, ManifestKind::Pyproject)]
            } else {
                // Nothing to edit yet: create requirements.txt so a CI
                // `pip install -r requirements.txt` installs the hook.
                vec![(requirements, ManifestKind::Requirements)]
            }
        }
    }
}

async fn plan_python(common: &GlobalArgs) -> Option<PythonPlan> {
    if !eco_in_scope(common, Ecosystem::Pypi) {
        return None;
    }
    if !is_python_project(&common.cwd).await {
        return None;
    }
    let pm = detect_python_pm(&common.cwd).await;
    let manifests = choose_python_manifests(&common.cwd, pm).await;
    if manifests.is_empty() {
        return None;
    }
    Some(PythonPlan { pm, manifests })
}

/// Run the hook-dependency edits for a plan (add or remove) at the given
/// dry-run setting. Returns per-manifest results.
async fn edit_python_manifests(
    plan: &PythonPlan,
    remove: bool,
    dry_run: bool,
) -> Vec<PthEditResult> {
    let mut out = Vec::new();
    for (path, kind) in &plan.manifests {
        let res = if remove {
            remove_hook_dependency(path, *kind, dry_run).await
        } else {
            add_hook_dependency(path, *kind, dry_run).await
        };
        out.push(res);
    }
    out
}

/// After a real (non-dry-run) edit that changed a manifest, refresh the
/// lockfile. Returns any warnings to surface. (There is no separate marker /
/// audit file: the committed dependency line is the source of truth.)
async fn finalize_python(plan: &PythonPlan, edits: &[PthEditResult], cwd: &Path) -> Vec<String> {
    let mut warnings = Vec::new();
    let any_changed = edits.iter().any(|e| e.status == PthStatus::Updated);
    if !any_changed {
        return warnings;
    }
    // Lockfile refresh (broad auto-edit): only when the manager uses a lockfile
    // that exists. Best-effort — never fatal. The spellings are tried in
    // order: pin-preserving first (`poetry lock --no-update`,
    // `pdm lock --update-reuse`), bare `lock` as the fallback for versions
    // that dropped the flag (Poetry 2.x, where bare `lock` is already
    // pin-preserving). A successful fallback is not a failure — only warn
    // when every spelling failed.
    if let Some((program, spellings)) = plan.pm.lock_commands() {
        let lockfile = match plan.pm {
            PythonPackageManager::Uv => Some("uv.lock"),
            PythonPackageManager::Poetry => Some("poetry.lock"),
            PythonPackageManager::Pdm => Some("pdm.lock"),
            _ => None,
        };
        let lock_present = match lockfile {
            Some(name) => tokio::fs::metadata(cwd.join(name)).await.is_ok(),
            None => false,
        };
        if lock_present {
            let mut failure: Option<String> = None;
            for args in spellings {
                match tokio::process::Command::new(program)
                    .args(*args)
                    .current_dir(cwd)
                    .output()
                    .await
                {
                    Ok(o) if o.status.success() => {
                        failure = None;
                        break;
                    }
                    Ok(o) => {
                        failure = Some(format!(
                            "`{program} {}` failed ({}); update the lockfile manually",
                            args.join(" "),
                            o.status
                        ));
                    }
                    Err(e) => {
                        // The program itself didn't spawn (not installed /
                        // not on PATH): retrying another spelling of the
                        // same program is pointless.
                        failure = Some(format!(
                            "could not run `{program} {}`: {e}; update the lockfile manually",
                            args.join(" ")
                        ));
                        break;
                    }
                }
            }
            if let Some(w) = failure {
                warnings.push(w);
            }
        }
    }
    warnings
}

// ─────────────────────────────────────────────────────────────────────────
// Shared per-ecosystem setup outcome
// ─────────────────────────────────────────────────────────────────────────

/// Summary of one ecosystem branch's contribution to a
/// setup/remove run. Each `build_*_outcome` returns one of these and the shared
/// reporting code merges + renders them without naming ecosystem-specific types.
#[derive(Default)]
struct SetupOutcome {
    /// A project for this ecosystem was discovered (gates the `no_files` decision).
    present: bool,
    /// Items changed (hook added/removed).
    changed: usize,
    already: usize,
    errors: usize,
    /// Envelope `files[]` entries (kind = `package_json` / `pth` / `gemfile` / …).
    json_files: Vec<serde_json::Value>,
    /// Human-readable preview lines (already formatted).
    preview: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────
// Gem (Bundler plugin) helpers
// ─────────────────────────────────────────────────────────────────────────

/// The Bundler project this run acts on, discovered ONCE per run (honoring
/// `--ecosystems`); `None` when gem is out of scope or no Gemfile is found.
async fn discover_gem_project(common: &GlobalArgs) -> Option<gem::BundlerProject> {
    if !eco_in_scope(common, Ecosystem::Gem) {
        return None;
    }
    gem::discover_bundler_project(&common.cwd).await
}

/// The gem project a setup run wires, paired with the run's ONE bundler
/// probe (a `Gemfile.lock` read, or a `bundle --version` spawn bounded by
/// its timeout): the preview and the real edit share both, so the probe
/// runs at most once per run.
async fn discover_gem_target(
    common: &GlobalArgs,
) -> Option<(gem::BundlerProject, gem::BundlerProbe)> {
    let project = discover_gem_project(common).await?;
    let probe = gem::probe_bundler(&project).await;
    Some((project, probe))
}

/// What the gem branch does to a project.
enum GemEdit<'a> {
    /// Wire the plugin; `add_plugin_directive_with` refuses below the
    /// bundler floor, judged from the run's probe.
    Add(&'a gem::BundlerProbe),
    /// Unwire. Deliberately ungated and never probes: it is the recovery
    /// path for an already-wired bundler-1.x project.
    Remove,
}

/// Build the gem branch's contribution to a setup/remove run: add (or remove)
/// the managed `plugin "socket-patch"` block in the Gemfile + the generated
/// `.socket/bundler-plugin/` plugin files. `target` is the discovered project
/// with the edit to make ([`discover_gem_target`] pairs the add path with the
/// run's one probe); `None` when the project has no Gemfile.
async fn build_gem_outcome(
    common: &GlobalArgs,
    target: Option<(&gem::BundlerProject, GemEdit<'_>)>,
    dry_run: bool,
) -> SetupOutcome {
    let Some((project, edit)) = target else {
        return SetupOutcome::default();
    };

    let mut out = SetupOutcome {
        present: true,
        ..Default::default()
    };

    let remove = matches!(edit, GemEdit::Remove);
    let results = match edit {
        GemEdit::Add(probe) => gem::add_plugin_directive_with(project, probe, dry_run).await,
        GemEdit::Remove => gem::remove_plugin_directive(project, dry_run).await,
    };

    let mut added_paths: Vec<String> = Vec::new();
    for r in &results {
        match r.status {
            GemSetupStatus::Updated => {
                out.changed += 1;
                added_paths.push(r.path.clone());
            }
            GemSetupStatus::AlreadyConfigured => out.already += 1,
            GemSetupStatus::Error => out.errors += 1,
        }
        out.json_files.push(serde_json::json!({
            "kind": r.kind,
            "path": r.path,
            "status": gem_status_str(&r.status, remove),
            "error": r.error,
        }));
    }

    if !added_paths.is_empty() {
        let header = if remove {
            "Gem: remove the socket-patch Bundler plugin wiring from:"
        } else {
            "Gem: add the socket-patch Bundler plugin wiring to:"
        };
        out.preview.push(header.to_string());
        let marker = if remove { "-" } else { "+" };
        for p in &added_paths {
            out.preview
                .push(format!("  {marker} {}", pathdiff(p, &common.cwd)));
        }
    }

    out
}

fn gem_status_str(s: &GemSetupStatus, for_remove: bool) -> &'static str {
    match (s, for_remove) {
        (GemSetupStatus::Updated, false) => "updated",
        (GemSetupStatus::Updated, true) => "removed",
        (GemSetupStatus::AlreadyConfigured, false) => "already_configured",
        (GemSetupStatus::AlreadyConfigured, true) => "not_configured",
        (GemSetupStatus::Error, _) => "error",
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Composer (composer.json scripts post-install/post-update hook) helpers
// ─────────────────────────────────────────────────────────────────────────

/// The `composer.json` this run acts on, discovered ONCE per run (honoring
/// `--ecosystems`).
async fn discover_composer_json(common: &GlobalArgs) -> Option<PathBuf> {
    if !eco_in_scope(common, Ecosystem::Composer) {
        return None;
    }
    composer::discover_composer_project(&common.cwd).await
}

/// Build the composer branch's contribution to a setup/remove run: add (or
/// remove) the `socket-patch apply` command in `composer.json`'s
/// `post-install-cmd` / `post-update-cmd` script events. `composer_json`
/// comes from [`discover_composer_json`], shared by the preview and the
/// real edit.
async fn build_composer_outcome(
    common: &GlobalArgs,
    composer_json: Option<&Path>,
    remove: bool,
    dry_run: bool,
) -> SetupOutcome {
    let Some(composer_json) = composer_json else {
        return SetupOutcome::default();
    };

    let mut out = SetupOutcome {
        present: true,
        ..Default::default()
    };

    let r = if remove {
        composer::remove_hook(composer_json, dry_run).await
    } else {
        composer::add_hook(composer_json, dry_run).await
    };

    let mut added_paths: Vec<String> = Vec::new();
    match r.status {
        ComposerSetupStatus::Updated => {
            out.changed += 1;
            added_paths.push(r.path.clone());
        }
        ComposerSetupStatus::AlreadyConfigured => out.already += 1,
        ComposerSetupStatus::Error => out.errors += 1,
    }
    out.json_files.push(serde_json::json!({
        "kind": r.kind,
        "path": r.path,
        "status": composer_status_str(&r.status, remove),
        "error": r.error,
    }));

    if !added_paths.is_empty() {
        let header = if remove {
            "Composer: remove the socket-patch re-apply hook from:"
        } else {
            "Composer: add the socket-patch re-apply hook to:"
        };
        out.preview.push(header.to_string());
        let marker = if remove { "-" } else { "+" };
        for p in &added_paths {
            out.preview
                .push(format!("  {marker} {}", pathdiff(p, &common.cwd)));
        }
    }

    out
}

fn composer_status_str(s: &ComposerSetupStatus, for_remove: bool) -> &'static str {
    match (s, for_remove) {
        (ComposerSetupStatus::Updated, false) => "updated",
        (ComposerSetupStatus::Updated, true) => "removed",
        (ComposerSetupStatus::AlreadyConfigured, false) => "already_configured",
        (ComposerSetupStatus::AlreadyConfigured, true) => "not_configured",
        (ComposerSetupStatus::Error, _) => "error",
    }
}

/// Append composer check entry (the `composer.json` hook presence) to the shared
/// `run_check` entries list. Returns whether a composer project was found.
/// Checks the SETUP wiring only — patch consistency is the shared
/// `append_patch_consistency_entries` pass.
async fn append_composer_check_entries(
    common: &GlobalArgs,
    entries: &mut Vec<(&'static str, String, CheckState, Option<String>)>,
) -> bool {
    if !eco_in_scope(common, Ecosystem::Composer) {
        return false;
    }
    let composer_json = match composer::discover_composer_project(&common.cwd).await {
        Some(p) => p,
        None => return false,
    };
    let (state, err) = match tokio::fs::read_to_string(&composer_json).await {
        Ok(content) => {
            if composer::is_hook_present(&content) {
                (CheckState::Configured, None)
            } else {
                (CheckState::NeedsConfiguration, None)
            }
        }
        Err(e) => (CheckState::Error, Some(e.to_string())),
    };
    entries.push(("composer", composer_json.display().to_string(), state, err));
    true
}

/// Materialise gem patches right after wiring the plugin (the "automatic" step)
/// so the first `bundle install` finds them already applied. Best-effort and
/// offline; a non-zero exit becomes a warning — the plugin heals on the next
/// `bundle install`.
async fn finalize_gem(common: &GlobalArgs) -> Vec<String> {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            return vec![format!(
                "could not locate socket-patch to materialize gem patches ({e}); \
                 run `socket-patch apply --ecosystems gem`"
            )]
        }
    };
    let root = common.cwd.display().to_string();
    // Forward the manifest location: the nested `apply` re-resolves a relative
    // `--manifest-path` against ITS OWN `--cwd`, so hand it the absolutized,
    // already-cwd-resolved path (the `get::run_nested_apply` rule). Dropping
    // the flag made this run read the default `.socket/manifest.json`, so a
    // project whose patches live anywhere else materialized nothing here —
    // silently, since a missing manifest is a clean exit-0 no-op for `apply`.
    let manifest = common.resolved_manifest_path();
    let manifest = std::path::absolute(&manifest).unwrap_or(manifest);
    let manifest = manifest.display().to_string();
    match tokio::process::Command::new(&exe)
        .args([
            "apply",
            "--offline",
            "--ecosystems",
            "gem",
            "--cwd",
            &root,
            "--manifest-path",
            &manifest,
            "--silent",
        ])
        .output()
        .await
    {
        Ok(o) if o.status.success() => Vec::new(),
        Ok(o) => vec![format!(
            "materializing gem patches exited with {}; the Bundler plugin will heal on next `bundle install`",
            o.status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into())
        )],
        Err(e) => vec![format!(
            "could not run apply to materialize gem patches ({e}); the Bundler plugin will heal on next `bundle install`"
        )],
    }
}

/// Append gem check entries (the Gemfile `plugin` directive + the generated
/// plugin dir) to the shared `run_check` entries list. Returns whether a
/// Bundler project was found. Checks the SETUP wiring only — patch consistency
/// is `apply --check`.
async fn append_gem_check_entries(
    common: &GlobalArgs,
    entries: &mut Vec<(&'static str, String, CheckState, Option<String>)>,
) -> bool {
    if !eco_in_scope(common, Ecosystem::Gem) {
        return false;
    }
    let project = match gem::discover_bundler_project(&common.cwd).await {
        Some(p) => p,
        None => return false,
    };
    // The bundler version floor (core `setup::gem::version`): bundler 1.x
    // cannot load the `plugin ... path:` directive, so a WIRED project fails
    // every `bundle install` (exit 7, an error that never names socket-patch)
    // — the campaign-confirmed state where `--check` kept saying "configured"
    // while the CI gate it exists to be went green over broken installs. Both
    // wired and unwired unsupported projects are red-flagged as errors: setup
    // itself refuses to wire below the floor, so "needs_configuration" (run
    // `setup` to fix) would point at a command that cannot help.
    let probe = gem::probe_bundler(&project).await;
    let (state, err) = match tokio::fs::read_to_string(&project.gemfile).await {
        Ok(content) => {
            let wired = gem::is_plugin_directive_present(&content);
            match (&probe, wired) {
                (gem::BundlerProbe::Unsupported { version, source }, true) => (
                    CheckState::Error,
                    Some(format!(
                        "the wired socket-patch plugin cannot load under bundler \
                         {version} (from {source}; needs >= {}.{}): every `bundle \
                         install` fails resolving 'socket-patch' as an ordinary gem \
                         (exit 7) before the plugin registers. Run `socket-patch \
                         setup --remove` to unwire, or upgrade bundler",
                        gem::MIN_BUNDLER.0,
                        gem::MIN_BUNDLER.1
                    )),
                ),
                (gem::BundlerProbe::Unsupported { version, source }, false) => (
                    CheckState::Error,
                    Some(gem::unsupported_bundler_message(version, source)),
                ),
                (_, true) => (CheckState::Configured, None),
                (_, false) => (CheckState::NeedsConfiguration, None),
            }
        }
        Err(e) => (CheckState::Error, Some(e.to_string())),
    };
    entries.push(("gemfile", project.gemfile.display().to_string(), state, err));
    let dir_state = if gem::plugin_files_present(&project.root).await {
        CheckState::Configured
    } else {
        CheckState::NeedsConfiguration
    };
    entries.push((
        "gem_plugin",
        gem::plugin_dir(&project.root).display().to_string(),
        dir_state,
        None,
    ));
    true
}

/// Append a `needs_configuration` entry for every in-scope manifest patch that
/// is installed but NOT correctly applied on disk (a file's hash != its
/// `afterHash`). This is the `apply --check` invariant that property 4 requires
/// `setup --check` to prove *in addition to* hook presence: a repo with hooks
/// wired but patches drifted/un-applied is not in a correctly-patched state.
///
/// Reuses the same machinery `vex` uses — the qualified-aware rollback resolver
/// (so release-variant PURLs resolve) honoring `--ecosystems`, the committed
/// vendor ledger ([`crate::commands::vex::vendor_context_from`]: a vendored
/// patch is judged by its `.socket/vendor/` artifact — the bytes the next
/// install consumes — never the expectedly-unpatched installed tree), then
/// [`applied_patches_with_vendor`]. An *uninstalled* package (`package_not_found`, also the
/// bucket for out-of-scope PURLs absent from the map) cannot be patched yet, and
/// a degenerate zero-file record (`no_files`) has nothing to hash — neither is
/// drift, so both are skipped. A missing/empty/unreadable manifest contributes
/// nothing of its own; the vendor ledger's detached records (vendored mode is
/// manifest-free) are folded in exactly as `vex` does, so a vendored-only
/// project is judged too. Read-only: it crawls but never writes.
async fn append_patch_consistency_entries(
    common: &GlobalArgs,
    manifest: Option<PatchManifest>,
    entries: &mut Vec<(&'static str, String, CheckState, Option<String>)>,
) {
    // ONE ledger read serves both the detached fold and the verifier's
    // VendorContext below. Without the fold a project whose committed
    // `.socket/vendor/**` artifact is missing or corrupt reported
    // `configured` — the exact hooks-present-but-state-drifted case
    // property 4 exists to catch. A ledger that cannot be read or parsed is
    // that case too (contract: "never as a `configured` verdict"): it is
    // surfaced BEFORE the emptiness return below — on a manifest-free
    // vendored project the fold is the only source of purls, so returning
    // early would report `configured` with no signal at all — as the shared
    // `unreadable vendor state` warning plus a `vendor_ledger` error entry
    // (verdict `error`, exit 1), and the verifier proceeds over an empty
    // ledger (already reported, so not warned twice).
    let mut manifest = manifest.unwrap_or_default();
    let ledger = match socket_patch_core::vendor::load_state(&common.cwd).await {
        Ok(state) => {
            crate::commands::fold_detached_records(&mut manifest, &state.entries);
            Ok(state)
        }
        Err(e) => {
            crate::commands::vex::warn_unreadable_vendor_state(common, &e);
            entries.push((
                "vendor_ledger",
                common
                    .cwd
                    .join(socket_patch_core::vendor::VENDOR_STATE_REL)
                    .display()
                    .to_string(),
                CheckState::Error,
                Some(format!("unreadable vendor state ({e})")),
            ));
            Ok(socket_patch_core::vendor::VendorState::new())
        }
    };
    if manifest.patches.is_empty() {
        return;
    }

    let purls: Vec<String> = manifest.patches.keys().cloned().collect();
    // `--json` reserves stdout for the check report: silence the dispatch's
    // human chrome ("Using <X> at: ...") like apply/rollback do.
    let package_paths =
        find_manifest_package_paths(&purls, common, common.silent || common.json).await;

    // The ledger passed here is always readable (an unreadable one was
    // reported above and replaced by an empty one), so there is no
    // degrade warning left to surface.
    let (vendor, _) = crate::commands::vex::vendor_context_from(common, &manifest, ledger).await;
    let outcome = applied_patches_with_vendor(&manifest, &package_paths, vendor.as_ref()).await;
    for failed in &outcome.failed {
        match failed.reason.as_str() {
            // Not installed (or out of scope) / nothing to hash → not drift.
            "package_not_found" | "no_files" => continue,
            // Installed but the on-disk file is not at its afterHash → drift.
            _ => entries.push((
                "patch",
                failed.purl.clone(),
                CheckState::NeedsConfiguration,
                Some(format!("patch not applied on disk ({})", failed.reason)),
            )),
        }
    }
}

/// Combine two ecosystem outcomes into one for the shared preview/envelope
/// printers, which take a single [`SetupOutcome`].
fn merge_outcomes(mut a: SetupOutcome, b: SetupOutcome) -> SetupOutcome {
    a.present |= b.present;
    a.changed += b.changed;
    a.already += b.already;
    a.errors += b.errors;
    a.json_files.extend(b.json_files);
    a.preview.extend(b.preview);
    a
}

// ─────────────────────────────────────────────────────────────────────────
// check
// ─────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Debug)]
enum CheckState {
    Configured,
    NeedsConfiguration,
    Error,
}

/// One `setup --check` status line. A drifted patch (`kind == "patch"`)
/// shows why it is not applied instead of "needs setup", which re-running
/// `setup` would not fix.
fn format_check_line(kind: &str, rel: &str, state: CheckState, err: Option<&str>) -> String {
    match (state, err) {
        (CheckState::Configured, _) => format!("  ✓ {rel} (configured)"),
        (CheckState::NeedsConfiguration, _) if kind == "patch" => {
            format!("  ✗ {rel}: {}", err.unwrap_or("patch not applied on disk"))
        }
        (CheckState::NeedsConfiguration, Some(e)) => format!("  ✗ {rel} (needs setup: {e})"),
        (CheckState::NeedsConfiguration, None) => format!("  ✗ {rel} (needs setup)"),
        (CheckState::Error, e) => format!("  ! {rel}: {}", e.unwrap_or("unknown error")),
    }
}

/// The `setup --check` verdict: what is wrong, then the command that fixes
/// each kind of problem (`setup` for missing hooks, `apply` for drifted
/// patches; invalid files need a hand edit).
fn format_check_footer(hooks: usize, drifted: usize, errors: usize) -> String {
    if hooks + drifted + errors == 0 {
        return "All manifests are configured with socket-patch.".to_string();
    }
    let mut problems = Vec::new();
    let mut advice = Vec::new();
    if hooks > 0 {
        problems.push(format!(
            "{} configuration",
            plural(hooks, "manifest needs", "manifests need")
        ));
        advice.push("Run `socket-patch setup` to add the missing install hooks.");
    }
    if drifted > 0 {
        problems.push(format!(
            "{} not applied on disk",
            plural(drifted, "patch is", "patches are")
        ));
        advice.push("Run `socket-patch apply` to re-apply the patches.");
    }
    if errors > 0 {
        problems.push(plural(errors, "error", "errors"));
        advice.push("Fix the errors above, then re-run `socket-patch setup --check`.");
    }
    format!("{}. {}", problems.join(", "), advice.join(" "))
}

/// Read-only verification that every discovered manifest (npm package.json and
/// the Python dependency manifest) is configured for socket-patch. Never writes
/// (so `--dry-run` is a harmless no-op here). Exits 0 only when all are
/// configured and none failed to parse.
async fn run_check(args: &SetupArgs) -> i32 {
    // `--silent` is "errors only" (CLI_CONTRACT.md): suppress the entire
    // human-readable report, mirroring `list`/`repair`/`get`/`remove`/`scan`.
    // The exit code still distinguishes the configuration states.
    if !args.common.json && !args.common.silent {
        eprintln!("Searching for package.json / Python / Bundler / Composer manifests...");
    }

    // Excluded members (persisted in the manifest + any passed via `--exclude`)
    // are skipped by discovery. Read-only: `--check` never persists.
    let existing = read_setup_manifest(&args.common).await;
    let excludes = effective_excludes(manifest_view(&existing), &args.exclude);
    let npm_files = discover(args, &excludes).await;
    let py_plan = plan_python(&args.common).await;

    // (kind, path, state, error)
    let mut entries: Vec<(&'static str, String, CheckState, Option<String>)> = Vec::new();

    for loc in &npm_files {
        let (state, err) = match tokio::fs::read_to_string(&loc.path).await {
            Ok(content) => {
                // npm and Node strip a leading UTF-8 BOM when reading
                // package.json (and `setup` itself tolerates one via
                // `is_setup_configured_str`); parse the same bytes they would,
                // or a BOM'd configured file fails `--check` as "Invalid
                // package.json" while `setup` calls it already_configured.
                let json = content.strip_prefix('\u{feff}').unwrap_or(&content);
                if let Err(e) = serde_json::from_str::<serde_json::Value>(json) {
                    // Keep the parser's detail (line/column): "Invalid
                    // package.json" alone leaves the user hunting.
                    (
                        CheckState::Error,
                        Some(format!("Invalid package.json: {e}")),
                    )
                } else if is_setup_configured_str(&content).needs_update {
                    (CheckState::NeedsConfiguration, None)
                } else {
                    (CheckState::Configured, None)
                }
            }
            Err(e) => (CheckState::Error, Some(e.to_string())),
        };
        entries.push(("package_json", loc.path.display().to_string(), state, err));
    }

    if let Some(plan) = &py_plan {
        for (path, kind) in &plan.manifests {
            let (state, err) = match tokio::fs::read_to_string(path).await {
                Ok(content) => {
                    if manifest_contains_hook(*kind, &content) {
                        (CheckState::Configured, None)
                    } else {
                        (CheckState::NeedsConfiguration, None)
                    }
                }
                // A not-yet-created requirements.txt simply needs setup; a
                // missing pyproject we'd have to edit is an error.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => match kind {
                    ManifestKind::Requirements => (CheckState::NeedsConfiguration, None),
                    ManifestKind::Pyproject => (CheckState::Error, Some(e.to_string())),
                },
                Err(e) => (CheckState::Error, Some(e.to_string())),
            };
            entries.push(("pth", path.display().to_string(), state, err));
        }
    }

    append_gem_check_entries(&args.common, &mut entries).await;
    append_composer_check_entries(&args.common, &mut entries).await;

    // Property 4: prove a correctly-patched state, not just hook presence —
    // every in-scope manifest patch must be applied on disk (`apply --check`
    // invariant). Drifted/un-applied patches add `needs_configuration` entries.
    append_patch_consistency_entries(&args.common, existing.ok().flatten(), &mut entries).await;

    if entries.is_empty() {
        return report_no_files(
            args,
            &[("configured", 0), ("needsConfiguration", 0), ("errors", 0)],
        );
    }

    let configured = entries
        .iter()
        .filter(|(_, _, s, _)| *s == CheckState::Configured)
        .count();
    let needs = entries
        .iter()
        .filter(|(_, _, s, _)| *s == CheckState::NeedsConfiguration)
        .count();
    // Drifted patches need `apply`, not `setup`: counted apart so the
    // footer can say which command fixes what.
    let drifted = entries
        .iter()
        .filter(|(k, _, s, _)| *k == "patch" && *s == CheckState::NeedsConfiguration)
        .count();
    let errs = entries
        .iter()
        .filter(|(_, _, s, _)| *s == CheckState::Error)
        .count();

    let all_ok = needs == 0 && errs == 0;
    let status = if errs > 0 {
        "error"
    } else if all_ok {
        "configured"
    } else {
        "needs_configuration"
    };

    if args.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": status,
                "configured": configured,
                "needsConfiguration": needs,
                "errors": errs,
                "files": entries.iter().map(|(kind, path, state, err)| {
                    serde_json::json!({
                        "kind": kind,
                        "path": path,
                        "status": match state {
                            CheckState::Configured => "configured",
                            CheckState::NeedsConfiguration => "needs_configuration",
                            CheckState::Error => "error",
                        },
                        "error": err,
                    })
                }).collect::<Vec<_>>(),
            }))
            .expect("serializing an in-memory JSON value cannot fail")
        );
    } else if !args.common.silent {
        println!("\nConfiguration status:\n");
        for (kind, path, state, err) in &entries {
            let rel = pathdiff(path, &args.common.cwd);
            println!("{}", format_check_line(kind, &rel, *state, err.as_deref()));
        }
        println!();
        println!("{}", format_check_footer(needs - drifted, drifted, errs));
    } else {
        // `--silent` is "errors only": the status report is muted, but
        // read/parse failures must still reach stderr. A plain
        // needs-configuration state is not an error — the exit code alone
        // carries it.
        for (_, path, state, err) in &entries {
            if *state == CheckState::Error {
                eprintln!(
                    "Error: {}: {}",
                    pathdiff(path, &args.common.cwd),
                    err.as_deref().unwrap_or("unknown error")
                );
            }
        }
    }

    if all_ok {
        0
    } else {
        1
    }
}

// ─────────────────────────────────────────────────────────────────────────
// remove
// ─────────────────────────────────────────────────────────────────────────

/// Render a removed script value: `None` means the key is being deleted.
fn render_removed(new: &Option<String>) -> String {
    match new {
        Some(s) if !s.is_empty() => format!("\"{s}\""),
        _ => "(removed)".to_string(),
    }
}

/// Revert the install hooks `setup` added (npm package.json scripts + the
/// Python `socket-patch-hook` dependency). Honors `--dry-run`, `--yes`, `--json`.
async fn run_remove(args: &SetupArgs) -> i32 {
    let common = &args.common;
    // `--silent` is "errors only" (CLI_CONTRACT.md): mute the human-readable
    // chatter just like `--json` does; the mutation and exit code are
    // unaffected, and prompting follows the shared `confirm()` semantics.
    let quiet = common.json || common.silent;
    if !quiet {
        eprintln!("Searching for package.json / Python / Bundler / Composer manifests...");
    }

    // Honor the persisted/`--exclude` member set so we never touch a member that
    // was deliberately excluded from setup. Remove does not change the set.
    let existing = read_setup_manifest(common).await;
    let excludes = effective_excludes(manifest_view(&existing), &args.exclude);
    let npm_files = discover(args, &excludes).await;
    let py_plan = plan_python(common).await;
    // Gem + Composer projects are discovered ONCE; the preview and the real
    // removal below share them.
    let gem_project = discover_gem_project(common).await;
    let composer_json = discover_composer_json(common).await;
    let gem_preview = build_gem_outcome(
        common,
        gem_project.as_ref().map(|p| (p, GemEdit::Remove)),
        true,
    )
    .await;
    let composer_preview =
        build_composer_outcome(common, composer_json.as_deref(), true, true).await;
    if npm_files.is_empty()
        && py_plan.is_none()
        && !gem_preview.present
        && !composer_preview.present
    {
        return report_no_files(args, &[("removed", 0), ("notConfigured", 0), ("errors", 0)]);
    }
    let gem_present = gem_preview.present;
    let extra_preview = merge_outcomes(gem_preview, composer_preview);

    // Preview (dry_run=true never writes).
    let mut npm_preview = Vec::new();
    for loc in &npm_files {
        npm_preview.push(remove_package_json(&loc.path, true).await);
    }
    let py_preview = match &py_plan {
        Some(p) => edit_python_manifests(p, true, true).await,
        None => Vec::new(),
    };

    if !quiet {
        print!(
            "{}",
            format_remove_preview(&npm_preview, &py_preview, &extra_preview, &common.cwd)
        );
    }

    let n_remove = npm_preview
        .iter()
        .filter(|r| r.status == RemoveStatus::Removed)
        .count()
        + py_preview
            .iter()
            .filter(|r| r.status == PthStatus::Updated)
            .count()
        + extra_preview.changed;
    let preview_errs = npm_preview
        .iter()
        .filter(|r| r.status == RemoveStatus::Error)
        .count()
        + py_preview
            .iter()
            .filter(|r| r.status == PthStatus::Error)
            .count()
        + extra_preview.errors;

    // Nothing to remove: clean (exit 0) or some file errored (exit 1).
    if n_remove == 0 {
        if common.json {
            print_remove_envelope(
                if preview_errs > 0 {
                    "error"
                } else {
                    "not_configured"
                },
                &npm_preview,
                &py_preview,
                &extra_preview,
                &[],
            );
        } else if !common.silent {
            if preview_errs > 0 {
                println!(
                    "\nNothing removed; {} (see errors above).",
                    plural(
                        preview_errs,
                        "item could not be processed",
                        "items could not be processed"
                    )
                );
            } else {
                println!("No socket-patch install hooks found to remove.");
            }
        }
        eprint_errors_when_silent(
            common,
            &remove_error_messages(&npm_preview, &py_preview, &extra_preview, &common.cwd),
        );
        return if preview_errs > 0 { 1 } else { 0 };
    }

    // Dry-run: preview already shown; report and exit without writing.
    if common.dry_run {
        if common.json {
            print_remove_envelope("dry_run", &npm_preview, &py_preview, &extra_preview, &[]);
        } else if !common.silent {
            println!("\nSummary (dry run):");
            println!(
                "  {}",
                plural(
                    n_remove,
                    "item would have socket-patch removed",
                    "items would have socket-patch removed"
                )
            );
        }
        eprint_errors_when_silent(
            common,
            &remove_error_messages(&npm_preview, &py_preview, &extra_preview, &common.cwd),
        );
        return if preview_errs > 0 { 1 } else { 0 };
    }

    // Confirm before mutating.
    // Default-no on a terminal; proceeds when stdin is not interactive.
    // Keep the prompt (or its non-interactive note) off the last preview
    // line. With --yes nothing is printed there, and the progress line below
    // already opens with its own blank line.
    if !quiet && !common.yes {
        eprintln!();
    }
    if !crate::ui::confirm_or_proceed("Remove these install hooks?", common) {
        if !common.silent {
            eprintln!("Aborted.");
        }
        return 0;
    }

    if !quiet {
        eprintln!("\nRemoving install hooks...");
    }
    let mut npm_results = Vec::new();
    for loc in &npm_files {
        npm_results.push(remove_package_json(&loc.path, false).await);
    }
    let mut py_results = Vec::new();
    let mut warnings = Vec::new();
    if let Some(plan) = &py_plan {
        py_results = edit_python_manifests(plan, true, false).await;
        warnings = finalize_python(plan, &py_results, &common.cwd).await;
    }
    // Real gem + composer removal (gem Gemfile `plugin` block + generated plugin
    // dir; composer.json script-event command).
    let extra_results = merge_outcomes(
        build_gem_outcome(
            common,
            gem_project.as_ref().map(|p| (p, GemEdit::Remove)),
            false,
        )
        .await,
        build_composer_outcome(common, composer_json.as_deref(), true, false).await,
    );

    let errs = npm_results
        .iter()
        .filter(|r| r.status == RemoveStatus::Error)
        .count()
        + py_results
            .iter()
            .filter(|r| r.status == PthStatus::Error)
            .count()
        + extra_results.errors;

    if common.json {
        print_remove_envelope(
            if errs > 0 {
                "partial_failure"
            } else {
                "success"
            },
            &npm_results,
            &py_results,
            &extra_results,
            &warnings,
        );
    } else if !common.silent {
        let removed = npm_results
            .iter()
            .filter(|r| r.status == RemoveStatus::Removed)
            .count()
            + py_results
                .iter()
                .filter(|r| r.status == PthStatus::Updated)
                .count()
            + extra_results.changed;
        println!("\nSummary:");
        println!(
            "  {}",
            plural(
                removed,
                "item had socket-patch removed",
                "items had socket-patch removed"
            )
        );
        if errs > 0 {
            println!("  {}", plural(errs, "error", "errors"));
        }
        if py_plan.is_some() {
            println!("\nAlso run `pip uninstall socket-patch-hook` to remove the installed .pth.");
        }
        if gem_present {
            println!(
                "\nNote: the Bundler plugin wiring was removed; already-patched gems on disk are \
                 reverted by a fresh `bundle install` (or `socket-patch rollback`)."
            );
        }
    }

    print_warnings(common, &warnings);
    eprint_errors_when_silent(
        common,
        &remove_error_messages(&npm_results, &py_results, &extra_results, &common.cwd),
    );

    if errs > 0 {
        1
    } else {
        0
    }
}

/// Error messages from a gem/composer [`SetupOutcome`]'s rendered `files[]`
/// entries — the only place per-edit errors for those ecosystems are retained.
/// The setup/remove previews use this so their human-mode "Errors:" sections
/// actually list gem/composer failures, honoring the "(see errors above)" line
/// both flows print when `preview_errors > 0`. Each message is prefixed with
/// the file's path (relative to `cwd`).
fn outcome_error_messages(o: &SetupOutcome, cwd: &Path) -> Vec<String> {
    o.json_files
        .iter()
        .filter(|f| f.get("status").and_then(|s| s.as_str()) == Some("error"))
        .filter_map(|f| {
            let err = f.get("error").and_then(|e| e.as_str())?;
            let path = f.get("path").and_then(|p| p.as_str()).unwrap_or("");
            Some(format_item_error(path, err, cwd))
        })
        .collect()
}

/// `packages/a/package.json: Invalid package.json: ...` — in a workspace
/// there can be dozens of manifests, so an error must say which one.
fn format_item_error(path: &str, err: &str, cwd: &Path) -> String {
    if path.is_empty() {
        err.to_string()
    } else {
        format!("{}: {err}", pathdiff(path, cwd))
    }
}

/// Print run warnings to stderr (`Warning: ...`) in human mode; `--json`
/// carries them in the envelope and `--silent` mutes them.
fn print_warnings(common: &GlobalArgs, warnings: &[String]) {
    if common.json || common.silent {
        return;
    }
    for w in warnings {
        eprintln!("{}", format_warning(w));
    }
}

/// `Warning: <Message>` — the warning texts start lowercase because they
/// double as JSON `warnings[]` strings; the human line capitalizes them.
fn format_warning(w: &str) -> String {
    let mut chars = w.chars();
    match chars.next() {
        Some(first) => format!("Warning: {}{}", first.to_uppercase(), chars.as_str()),
        None => "Warning:".to_string(),
    }
}

/// `--silent` is "errors only" (CLI_CONTRACT.md): the previews, summaries,
/// and status report that normally carry per-item failures are muted, so
/// before an error exit the failures themselves must still reach stderr —
/// mirroring `remove`/`scan`, whose error paths keep their stderr output.
/// JSON mode is exempt: its envelope already carries the errors.
fn eprint_errors_when_silent(common: &GlobalArgs, errs: &[String]) {
    if !common.silent || common.json {
        return;
    }
    for e in errs {
        eprintln!("Error: {e}");
    }
}

/// Per-item error messages across the three remove result families (npm +
/// Python + gem/composer) — the preview "Errors:" section and the
/// silent-mode stderr reporting share this.
fn remove_error_messages(
    npm: &[RemoveResult],
    py: &[PthEditResult],
    extra: &SetupOutcome,
    cwd: &Path,
) -> Vec<String> {
    let mut errs: Vec<String> = npm
        .iter()
        .filter(|r| r.status == RemoveStatus::Error)
        .filter_map(|r| Some(format_item_error(&r.path, r.error.as_deref()?, cwd)))
        .chain(
            py.iter()
                .filter(|r| r.status == PthStatus::Error)
                .filter_map(|r| Some(format_item_error(&r.path, r.error.as_deref()?, cwd))),
        )
        .collect();
    errs.extend(outcome_error_messages(extra, cwd));
    errs
}

/// Per-item error messages across the three setup result families (npm +
/// Python + gem/composer) — the preview "Errors:" section and the
/// silent-mode stderr reporting share this.
fn setup_error_messages(
    npm: &[UpdateResult],
    py: &[PthEditResult],
    extra: &SetupOutcome,
    cwd: &Path,
) -> Vec<String> {
    let mut errs: Vec<String> = npm
        .iter()
        .filter(|r| r.status == UpdateStatus::Error)
        .filter_map(|r| Some(format_item_error(&r.path, r.error.as_deref()?, cwd)))
        .chain(
            py.iter()
                .filter(|r| r.status == PthStatus::Error)
                .filter_map(|r| Some(format_item_error(&r.path, r.error.as_deref()?, cwd))),
        )
        .collect();
    errs.extend(outcome_error_messages(extra, cwd));
    errs
}

/// The `setup --remove` preview. Every section starts with a blank line (so
/// the block never ends in a stray one before the summary or prompt).
fn format_remove_preview(
    npm: &[RemoveResult],
    py: &[PthEditResult],
    extra: &SetupOutcome,
    cwd: &Path,
) -> String {
    let mut out = String::from("\nProposed changes:\n");
    let to_remove: Vec<_> = npm
        .iter()
        .filter(|r| r.status == RemoveStatus::Removed)
        .collect();
    if !to_remove.is_empty() {
        out.push_str("\nWill remove socket-patch from:\n");
        for r in &to_remove {
            out.push_str(&format!("  - {}\n", pathdiff(&r.path, cwd)));
            out.push_str(&format!("    postinstall:   \"{}\"\n", r.old_script));
            out.push_str(&format!(
                "    -> postinstall: {}\n",
                render_removed(&r.new_script)
            ));
            out.push_str(&format!(
                "    dependencies:  \"{}\"\n",
                r.old_dependencies_script
            ));
            out.push_str(&format!(
                "    -> dependencies: {}\n",
                render_removed(&r.new_dependencies_script)
            ));
        }
    }
    let py_remove: Vec<_> = py
        .iter()
        .filter(|r| r.status == PthStatus::Updated)
        .collect();
    if !py_remove.is_empty() {
        out.push_str("\nWill remove the socket-patch-hook dependency from:\n");
        for r in &py_remove {
            out.push_str(&format!("  - {}\n", pathdiff(&r.path, cwd)));
        }
    }
    push_extra_preview(&mut out, extra);
    // Surface failures so the "(see errors above)" line `run_remove` prints when
    // nothing could be removed actually points at something.
    push_errors(&mut out, &remove_error_messages(npm, py, extra, cwd));
    out
}

/// The gem/composer preview lines, as their own blank-line-led section.
fn push_extra_preview(out: &mut String, extra: &SetupOutcome) {
    if !extra.preview.is_empty() {
        out.push('\n');
        for line in &extra.preview {
            out.push_str(line);
            out.push('\n');
        }
    }
}

/// The preview's "Errors:" section (nothing when there are none).
fn push_errors(out: &mut String, errs: &[String]) {
    if !errs.is_empty() {
        out.push_str("\nErrors:\n");
        for e in errs {
            out.push_str(&format!("  ! {e}\n"));
        }
    }
}

fn print_remove_envelope(
    status: &str,
    npm: &[RemoveResult],
    py: &[PthEditResult],
    extra: &SetupOutcome,
    warnings: &[String],
) {
    let removed = npm
        .iter()
        .filter(|r| r.status == RemoveStatus::Removed)
        .count()
        + py.iter().filter(|r| r.status == PthStatus::Updated).count()
        + extra.changed;
    let not_cfg = npm
        .iter()
        .filter(|r| r.status == RemoveStatus::NotConfigured)
        .count()
        + py.iter()
            .filter(|r| r.status == PthStatus::AlreadyConfigured)
            .count()
        + extra.already;
    let errors = npm
        .iter()
        .filter(|r| r.status == RemoveStatus::Error)
        .count()
        + py.iter().filter(|r| r.status == PthStatus::Error).count()
        + extra.errors;

    let mut files: Vec<serde_json::Value> = npm
        .iter()
        .map(|r| {
            serde_json::json!({
                "kind": "package_json",
                "path": r.path,
                "status": match r.status {
                    RemoveStatus::Removed => "removed",
                    RemoveStatus::NotConfigured => "not_configured",
                    RemoveStatus::Error => "error",
                },
                "error": r.error,
            })
        })
        .collect();
    files.extend(py.iter().map(|r| {
        serde_json::json!({
            "kind": "pth",
            "path": r.path,
            "status": match r.status {
                PthStatus::Updated => "removed",
                PthStatus::AlreadyConfigured => "not_configured",
                PthStatus::Error => "error",
            },
            "error": r.error,
        })
    }));
    // extra.json_files already use the remove vocabulary
    // (removed/not_configured/error), built by the gem/composer outcomes.
    files.extend(extra.json_files.iter().cloned());

    let mut obj = serde_json::json!({
        "status": status,
        "removed": removed,
        "notConfigured": not_cfg,
        "errors": errors,
        "files": files,
    });
    if status == "dry_run" {
        obj["dryRun"] = serde_json::json!(true);
        obj["wouldRemove"] = serde_json::json!(removed);
    }
    if !warnings.is_empty() {
        obj["warnings"] = serde_json::json!(warnings);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&obj)
            .expect("serializing an in-memory JSON value cannot fail")
    );
}

// ─────────────────────────────────────────────────────────────────────────
// setup (npm package.json + Python .pth hook, combined)
// ─────────────────────────────────────────────────────────────────────────

async fn run_setup(args: &SetupArgs) -> i32 {
    let common = &args.common;
    // `--silent` is "errors only" (CLI_CONTRACT.md): mute the human-readable
    // chatter just like `--json` does; the mutation and exit code are
    // unaffected, and prompting follows the shared `confirm()` semantics.
    let quiet = common.json || common.silent;
    if !quiet {
        eprintln!("Configuring socket-patch install hooks...");
    }

    // Resolve the effective exclude set (persisted + `--exclude`); excluded
    // members are skipped by discovery. Persisting it waits for the mutation
    // gate below (past discovery and the confirm prompt) so a no-project
    // directory or an aborted run leaves no `.socket/` behind.
    let existing = read_setup_manifest(common).await;
    let excludes = effective_excludes(manifest_view(&existing), &args.exclude);
    let found = find_members(args).await;
    let unmatched = found
        .as_ref()
        .map(|f| unmatched_excludes(f, &common.cwd, &excludes))
        .unwrap_or_default();
    warn_unmatched_excludes(common, &unmatched);
    // A new `--exclude` value that matches no member is warned about above
    // and not persisted, so a typo does not ride into every later run and
    // clone. Values already persisted stay (they warn on every run instead
    // of being silently dropped from the user's manifest).
    let persisted = effective_excludes(manifest_view(&existing), &[]);
    let to_persist: Vec<String> = excludes
        .iter()
        .filter(|e| !unmatched.contains(e) || persisted.contains(e))
        .cloned()
        .collect();
    let npm_files = found
        .map(|f| select_members(f, &common.cwd, &excludes))
        .unwrap_or_default();
    let py_plan = plan_python(common).await;
    // Gem + Composer projects are discovered ONCE and bundler probed ONCE:
    // the preview and the real edit below share both.
    let gem = discover_gem_target(common).await;
    let gem_add = || {
        gem.as_ref()
            .map(|(project, probe)| (project, GemEdit::Add(probe)))
    };
    let composer_json = discover_composer_json(common).await;
    // Gem + Composer previews (dry-run); `.present` also tells us each project exists.
    let gem_preview = build_gem_outcome(common, gem_add(), true).await;
    let composer_preview =
        build_composer_outcome(common, composer_json.as_deref(), false, true).await;

    if npm_files.is_empty()
        && py_plan.is_none()
        && !gem_preview.present
        && !composer_preview.present
    {
        return report_no_files(
            args,
            &[("updated", 0), ("alreadyConfigured", 0), ("errors", 0)],
        );
    }

    let gem_present = gem_preview.present;
    let composer_present = composer_preview.present;
    let extra_preview = merge_outcomes(gem_preview, composer_preview);

    let npm_pm = detect_package_manager(&common.cwd).await;

    // `patch_setup` telemetry ("a successful setup") fires only on the two
    // exit-0, non-dry-run paths below — never for a dry run, an aborted
    // prompt, a no-project directory or an errored run.
    let track_setup = || {
        track_setup_success(
            common,
            !npm_files.is_empty(),
            py_plan.is_some(),
            gem_present,
            composer_present,
            npm_pm,
        )
    };

    // Preview (always dry-run first).
    let mut npm_preview = Vec::new();
    for loc in &npm_files {
        npm_preview.push(update_package_json(&loc.path, true, npm_pm).await);
    }
    let py_preview = match &py_plan {
        Some(plan) => edit_python_manifests(plan, false, true).await,
        None => Vec::new(),
    };

    let n_changes = npm_preview
        .iter()
        .filter(|r| r.status == UpdateStatus::Updated)
        .count()
        + py_preview
            .iter()
            .filter(|r| r.status == PthStatus::Updated)
            .count()
        + extra_preview.changed;
    if !quiet {
        print!(
            "{}",
            format_setup_preview(
                &npm_preview,
                &py_preview,
                &extra_preview,
                &common.cwd,
                n_changes
            )
        );
    }

    let preview_errors = npm_preview
        .iter()
        .filter(|r| r.status == UpdateStatus::Error)
        .count()
        + py_preview
            .iter()
            .filter(|r| r.status == PthStatus::Error)
            .count()
        + extra_preview.errors;

    if n_changes == 0 {
        // No hook needs editing, so there is no preview to confirm — but an
        // EXPLICIT new `--exclude` is the user's stated intent and is still
        // persisted (never under --dry-run, which returns below with the
        // preview). A skipped (fail-closed) persistence rides the warnings
        // channel exactly like on the mutating path.
        let warnings: Vec<String> = if !common.dry_run && !args.exclude.is_empty() {
            persist_setup_excludes(common, &existing, &to_persist)
                .await
                .into_iter()
                .collect()
        } else {
            Vec::new()
        };
        if common.json {
            print_setup_envelope(
                if preview_errors > 0 {
                    "error"
                } else {
                    "already_configured"
                },
                &npm_preview,
                &py_preview,
                &extra_preview,
                npm_pm,
                py_plan.as_ref(),
                &warnings,
            );
        } else if !common.silent {
            if preview_errors > 0 {
                println!(
                    "\nNo hooks were changed; {} (see errors above).",
                    plural(
                        preview_errors,
                        "item could not be processed",
                        "items could not be processed"
                    )
                );
            } else {
                println!("All install hooks are already configured with socket-patch!");
            }
        }
        print_warnings(common, &warnings);
        eprint_errors_when_silent(
            common,
            &setup_error_messages(&npm_preview, &py_preview, &extra_preview, &common.cwd),
        );
        if preview_errors > 0 {
            return 1;
        }
        if !common.dry_run {
            track_setup().await;
        }
        return 0;
    }

    if common.dry_run {
        if common.json {
            print_setup_envelope(
                "dry_run",
                &npm_preview,
                &py_preview,
                &extra_preview,
                npm_pm,
                py_plan.as_ref(),
                &[],
            );
        } else if !common.silent {
            println!("\nSummary (dry run):");
            println!(
                "  {}",
                plural(n_changes, "item would be updated", "items would be updated")
            );
        }
        eprint_errors_when_silent(
            common,
            &setup_error_messages(&npm_preview, &py_preview, &extra_preview, &common.cwd),
        );
        return if preview_errors > 0 { 1 } else { 0 };
    }

    // Default-no on a terminal; proceeds when stdin is not interactive.
    // Keep the prompt (or its non-interactive note) off the last preview
    // line. With --yes nothing is printed there, and the progress line below
    // already opens with its own blank line.
    if !quiet && !common.yes {
        eprintln!();
    }
    if !crate::ui::confirm_or_proceed("Proceed with these changes?", common) {
        if !common.silent {
            eprintln!("Aborted.");
        }
        return 0;
    }

    // Past the mutation gate: persist the exclude set now (a dry run
    // returned above; an aborted or no-project run never gets here).
    let persist_warning = persist_setup_excludes(common, &existing, &to_persist).await;

    if !quiet {
        eprintln!("\nApplying changes...");
    }

    let mut npm_results = Vec::new();
    for loc in &npm_files {
        npm_results.push(update_package_json(&loc.path, false, npm_pm).await);
    }
    let mut py_results = Vec::new();
    let mut warnings = Vec::new();
    if let Some(plan) = &py_plan {
        py_results = edit_python_manifests(plan, false, false).await;
        warnings = finalize_python(plan, &py_results, &common.cwd).await;
    }
    // A skipped (fail-closed) --exclude persistence rides the same warnings
    // channel: human summary line + `--json` envelope `warnings` array.
    warnings.extend(persist_warning);
    // Real gem + composer edits (gem Gemfile `plugin` block + generated plugin
    // dir; composer.json script-event command).
    let extra_results = merge_outcomes(
        build_gem_outcome(common, gem_add(), false).await,
        build_composer_outcome(common, composer_json.as_deref(), false, false).await,
    );

    // Materialise gem patches now so the first `bundle install` finds them
    // applied. Best-effort → warnings only.
    if gem_present {
        warnings.extend(finalize_gem(common).await);
    }

    let errors = npm_results
        .iter()
        .filter(|r| r.status == UpdateStatus::Error)
        .count()
        + py_results
            .iter()
            .filter(|r| r.status == PthStatus::Error)
            .count()
        + extra_results.errors;
    if errors == 0 {
        track_setup().await;
    }

    if common.json {
        print_setup_envelope(
            if errors > 0 {
                "partial_failure"
            } else {
                "success"
            },
            &npm_results,
            &py_results,
            &extra_results,
            npm_pm,
            py_plan.as_ref(),
            &warnings,
        );
    } else if !common.silent {
        let updated = npm_results
            .iter()
            .filter(|r| r.status == UpdateStatus::Updated)
            .count()
            + py_results
                .iter()
                .filter(|r| r.status == PthStatus::Updated)
                .count()
            + extra_results.changed;
        println!("\nSummary:");
        println!("  {}", plural(updated, "item updated", "items updated"));
        if errors > 0 {
            println!("  {}", plural(errors, "error", "errors"));
        }
        if let Some(plan) = &py_plan {
            println!(
                "\nCommit the {} dependency change (and your .socket/ patches) so \
                 the hook re-applies in CI after install.",
                plan.pm.as_str()
            );
        }
        if gem_present {
            println!(
                "\nCommit the Gemfile (the `plugin` block), .socket/bundler-plugin/, and your \
                 .socket/ patches so the Bundler plugin re-applies gem patches on every \
                 `bundle install` (including cached/no-op installs in CI). The socket-patch CLI \
                 must be on PATH wherever `bundle install` runs."
            );
        }
    }

    print_warnings(common, &warnings);
    eprint_errors_when_silent(
        common,
        &setup_error_messages(&npm_results, &py_results, &extra_results, &common.cwd),
    );

    if errors > 0 {
        1
    } else {
        0
    }
}

/// Fire `patch_setup` — "a successful `setup`". Attributed through the same
/// layered credential chain as every other command (flag / env / socket-cli
/// `config.json`), not the raw flag values: `setup` builds no API client (it
/// is a purely local edit), so the config layer is consulted explicitly,
/// exactly as `list` does — otherwise a caller authenticated by `socket
/// login` alone reports anonymously to the public patch proxy (and, with an
/// on-prem `apiBaseUrl`, to a different host than the client would use).
async fn track_setup_success(
    common: &GlobalArgs,
    npm: bool,
    py: bool,
    gem: bool,
    composer: bool,
    npm_pm: PackageManager,
) {
    let manager = telemetry_manager_str(npm, py, gem, composer, npm_pm);
    let (token, org) = common.telemetry_credentials();
    track_patch_setup(&manager, token.as_deref(), org.as_deref()).await;
}

/// The `setup` preview (same blank-line-led sections as
/// [`format_remove_preview`]). `n_changes == 0` leaves out the "already
/// configured" count: the caller then says everything is configured, and
/// the count would only repeat it.
fn format_setup_preview(
    npm: &[UpdateResult],
    py: &[PthEditResult],
    extra: &SetupOutcome,
    cwd: &Path,
    n_changes: usize,
) -> String {
    let mut out = String::new();
    let npm_changes: Vec<_> = npm
        .iter()
        .filter(|r| r.status == UpdateStatus::Updated)
        .collect();
    if !npm_changes.is_empty() {
        out.push_str("\npackage.json files to update:\n");
        for r in &npm_changes {
            out.push_str(&format!("  + {}\n", pathdiff(&r.path, cwd)));
            out.push_str(&format!("    -> postinstall: \"{}\"\n", r.new_script));
            // The run writes the `dependencies` hook too; show it when it
            // changes, so the preview matches what is written.
            if r.new_dependencies_script != r.old_dependencies_script {
                out.push_str(&format!(
                    "    -> dependencies: \"{}\"\n",
                    r.new_dependencies_script
                ));
            }
        }
    }
    let py_changes: Vec<_> = py
        .iter()
        .filter(|r| r.status == PthStatus::Updated)
        .collect();
    if !py_changes.is_empty() {
        out.push_str("\nPython manifests to update (socket-patch-hook):\n");
        for r in &py_changes {
            out.push_str(&format!("  + {}\n", pathdiff(&r.path, cwd)));
        }
    }
    push_extra_preview(&mut out, extra);

    let already = npm
        .iter()
        .filter(|r| r.status == UpdateStatus::AlreadyConfigured)
        .count()
        + py.iter()
            .filter(|r| r.status == PthStatus::AlreadyConfigured)
            .count()
        + extra.already;
    if already > 0 && n_changes > 0 {
        out.push_str(&format!("\nAlready configured (will skip): {already}\n"));
    }

    push_errors(&mut out, &setup_error_messages(npm, py, extra, cwd));
    out
}

#[allow(clippy::too_many_arguments)]
fn print_setup_envelope(
    status: &str,
    npm: &[UpdateResult],
    py: &[PthEditResult],
    extra: &SetupOutcome,
    npm_pm: PackageManager,
    py_plan: Option<&PythonPlan>,
    warnings: &[String],
) {
    let updated = npm
        .iter()
        .filter(|r| r.status == UpdateStatus::Updated)
        .count()
        + py.iter().filter(|r| r.status == PthStatus::Updated).count()
        + extra.changed;
    let already = npm
        .iter()
        .filter(|r| r.status == UpdateStatus::AlreadyConfigured)
        .count()
        + py.iter()
            .filter(|r| r.status == PthStatus::AlreadyConfigured)
            .count()
        + extra.already;
    let errors = npm
        .iter()
        .filter(|r| r.status == UpdateStatus::Error)
        .count()
        + py.iter().filter(|r| r.status == PthStatus::Error).count()
        + extra.errors;

    let mut files: Vec<serde_json::Value> = npm
        .iter()
        .map(|r| {
            serde_json::json!({
                "kind": "package_json",
                "path": r.path,
                "status": match r.status {
                    UpdateStatus::Updated => "updated",
                    UpdateStatus::AlreadyConfigured => "already_configured",
                    UpdateStatus::Error => "error",
                },
                "error": r.error,
            })
        })
        .collect();
    files.extend(py.iter().map(|r| {
        serde_json::json!({
            "kind": "pth",
            "path": r.path,
            "status": match r.status {
                PthStatus::Updated => "updated",
                PthStatus::AlreadyConfigured => "already_configured",
                PthStatus::Error => "error",
            },
            "error": r.error,
        })
    }));
    files.extend(extra.json_files.iter().cloned());

    let mut obj = serde_json::json!({
        "status": status,
        "updated": updated,
        "alreadyConfigured": already,
        "errors": errors,
        "packageManager": manager_name(npm_pm),
        "files": files,
    });
    if status == "dry_run" {
        obj["dryRun"] = serde_json::json!(true);
        obj["wouldUpdate"] = serde_json::json!(updated);
    }
    if let Some(plan) = py_plan {
        obj["pythonPackageManager"] = serde_json::json!(plan.pm.as_str());
    }
    if !warnings.is_empty() {
        obj["warnings"] = serde_json::json!(warnings);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&obj)
            .expect("serializing an in-memory JSON value cannot fail")
    );
}

#[cfg(test)]
mod tests {
    //! Exact-string tests for setup's human output builders.
    use super::*;

    fn cwd() -> PathBuf {
        PathBuf::from("/proj")
    }

    fn update(path: &str, status: UpdateStatus, err: Option<&str>) -> UpdateResult {
        UpdateResult {
            path: path.to_string(),
            status,
            old_script: String::new(),
            new_script: "npx @socketsecurity/socket-patch apply --silent".to_string(),
            old_dependencies_script: "npx @socketsecurity/socket-patch apply --silent".to_string(),
            new_dependencies_script: "npx @socketsecurity/socket-patch apply --silent".to_string(),
            error: err.map(str::to_string),
        }
    }

    fn remove(path: &str, status: RemoveStatus) -> RemoveResult {
        RemoveResult {
            path: path.to_string(),
            status,
            old_script: "socket-patch apply && echo hi".to_string(),
            new_script: Some("echo hi".to_string()),
            old_dependencies_script: "socket-patch apply".to_string(),
            new_dependencies_script: None,
            error: None,
        }
    }

    #[test]
    fn no_files_message_follows_scope() {
        let all = ["package.json", "Python", "Bundler", "Composer"];
        assert_eq!(
            format_no_files(&all, &[]),
            "No package.json, Python, Bundler, or Composer project found"
        );
        assert_eq!(
            format_no_files(&["package.json"], &["npm".to_string()]),
            "No package.json project found"
        );
        assert_eq!(
            format_no_files(&["Python", "Bundler"], &[]),
            "No Python or Bundler project found"
        );
        assert_eq!(
            format_no_files(&[], &["cargo".to_string(), "maven".to_string()]),
            "Setup has no install hook for: cargo, maven (supported: npm, pypi, gem, composer)"
        );
    }

    #[test]
    fn no_files_message_reads_the_ecosystems_filter() {
        let mut common = GlobalArgs::default();
        assert_eq!(
            no_files_message(&common),
            "No package.json, Python, Bundler, or Composer project found"
        );
        common.ecosystems = Some(vec!["cargo".to_string()]);
        assert!(no_files_message(&common).starts_with("Setup has no install hook for: cargo"));
        common.ecosystems = Some(vec!["cargo".to_string(), "pypi".to_string()]);
        assert_eq!(no_files_message(&common), "No Python project found");
    }

    #[test]
    fn warnings_are_capitalized_for_humans() {
        assert_eq!(
            format_warning("not persisting --exclude: x"),
            "Warning: Not persisting --exclude: x"
        );
        assert_eq!(
            format_warning("`uv lock` failed"),
            "Warning: `uv lock` failed"
        );
        assert_eq!(format_warning("écrit"), "Warning: Écrit");
        assert_eq!(format_warning(""), "Warning:");
    }

    #[test]
    fn unmatched_exclude_message_is_trimmed() {
        assert_eq!(
            format_unmatched_exclude(" nope"),
            "--exclude \"nope\" matched no workspace member"
        );
        assert_eq!(
            format_unmatched_exclude("pkgs/ü"),
            "--exclude \"pkgs/ü\" matched no workspace member"
        );
    }

    #[test]
    fn check_lines_render_each_state() {
        use CheckState::*;
        assert_eq!(
            format_check_line("package_json", "package.json", Configured, None),
            "  ✓ package.json (configured)"
        );
        assert_eq!(
            format_check_line("package_json", "package.json", NeedsConfiguration, None),
            "  ✗ package.json (needs setup)"
        );
        assert_eq!(
            format_check_line(
                "patch",
                "pkg:npm/minimist@1.2.5",
                NeedsConfiguration,
                Some("patch not applied on disk (hash_mismatch)")
            ),
            "  ✗ pkg:npm/minimist@1.2.5: patch not applied on disk (hash_mismatch)"
        );
        assert_eq!(
            format_check_line("gemfile", "Gemfile", NeedsConfiguration, Some("x")),
            "  ✗ Gemfile (needs setup: x)"
        );
        assert_eq!(
            format_check_line(
                "package_json",
                "a/package.json",
                Error,
                Some("Invalid package.json: EOF")
            ),
            "  ! a/package.json: Invalid package.json: EOF"
        );
        assert_eq!(
            format_check_line("pth", "req.txt", Error, None),
            "  ! req.txt: unknown error"
        );
    }

    #[test]
    fn check_footer_names_the_fixing_command() {
        assert_eq!(
            format_check_footer(0, 0, 0),
            "All manifests are configured with socket-patch."
        );
        assert_eq!(
            format_check_footer(1, 0, 0),
            "1 manifest needs configuration. Run `socket-patch setup` to add the missing \
             install hooks."
        );
        assert_eq!(
            format_check_footer(0, 1, 0),
            "1 patch is not applied on disk. Run `socket-patch apply` to re-apply the patches."
        );
        assert_eq!(
            format_check_footer(0, 0, 2),
            "2 errors. Fix the errors above, then re-run `socket-patch setup --check`."
        );
        assert_eq!(
            format_check_footer(3, 2, 1),
            "3 manifests need configuration, 2 patches are not applied on disk, 1 error. \
             Run `socket-patch setup` to add the missing install hooks. Run `socket-patch \
             apply` to re-apply the patches. Fix the errors above, then re-run `socket-patch \
             setup --check`."
        );
        for f in [format_check_footer(1, 1, 1), format_check_footer(2, 2, 2)] {
            assert!(!f.contains("(s)"), "{f}");
        }
    }

    #[test]
    fn item_errors_name_the_file() {
        assert_eq!(
            format_item_error(
                "/proj/packages/a/package.json",
                "Invalid package.json: x",
                &cwd()
            ),
            "packages/a/package.json: Invalid package.json: x"
        );
        assert_eq!(format_item_error("", "boom", &cwd()), "boom");
        assert_eq!(
            format_item_error("/elsewhere/p.json", "boom", &cwd()),
            "/elsewhere/p.json: boom"
        );
    }

    #[test]
    fn setup_preview_layout() {
        let npm = vec![
            update("/proj/package.json", UpdateStatus::Updated, None),
            update(
                "/proj/packages/b/package.json",
                UpdateStatus::AlreadyConfigured,
                None,
            ),
            update(
                "/proj/packages/bad/package.json",
                UpdateStatus::Error,
                Some("Invalid package.json: EOF"),
            ),
        ];
        let out = format_setup_preview(&npm, &[], &SetupOutcome::default(), &cwd(), 1);
        assert_eq!(
            out,
            "\npackage.json files to update:\n  + package.json\n    -> postinstall: \"npx \
             @socketsecurity/socket-patch apply --silent\"\n\nAlready configured (will skip): \
             1\n\nErrors:\n  ! packages/bad/package.json: Invalid package.json: EOF\n"
        );
        assert!(!out.contains("\n\n\n"), "{out:?}");
    }

    #[test]
    fn setup_preview_shows_a_changed_dependencies_script() {
        let mut r = update("/proj/package.json", UpdateStatus::Updated, None);
        r.old_dependencies_script = String::new();
        r.new_dependencies_script = "socket-patch apply --silent".to_string();
        assert_eq!(
            format_setup_preview(&[r], &[], &SetupOutcome::default(), &cwd(), 1),
            "\npackage.json files to update:\n  + package.json\n    -> postinstall: \"npx \
             @socketsecurity/socket-patch apply --silent\"\n    -> dependencies: \
             \"socket-patch apply --silent\"\n"
        );
    }

    #[test]
    fn setup_preview_skips_already_count_when_nothing_changes() {
        let npm = vec![update(
            "/proj/package.json",
            UpdateStatus::AlreadyConfigured,
            None,
        )];
        assert_eq!(
            format_setup_preview(&npm, &[], &SetupOutcome::default(), &cwd(), 0),
            ""
        );
    }

    #[test]
    fn setup_preview_lists_gem_and_composer_lines() {
        let extra = SetupOutcome {
            preview: vec![
                "Gem: add the socket-patch Bundler plugin wiring to:".to_string(),
                "  + Gemfile".to_string(),
            ],
            changed: 1,
            ..Default::default()
        };
        assert_eq!(
            format_setup_preview(&[], &[], &extra, &cwd(), 1),
            "\nGem: add the socket-patch Bundler plugin wiring to:\n  + Gemfile\n"
        );
    }

    #[test]
    fn remove_preview_layout_has_no_double_blank_lines() {
        let npm = vec![remove("/proj/package.json", RemoveStatus::Removed)];
        let py = vec![PthEditResult {
            path: "/proj/requirements.txt".to_string(),
            status: PthStatus::Updated,
            error: None,
        }];
        let extra = SetupOutcome {
            preview: vec![
                "Gem: remove the socket-patch Bundler plugin wiring from:".to_string(),
                "  - Gemfile".to_string(),
            ],
            ..Default::default()
        };
        let out = format_remove_preview(&npm, &py, &extra, &cwd());
        assert_eq!(
            out,
            "\nProposed changes:\n\nWill remove socket-patch from:\n  - package.json\n    \
             postinstall:   \"socket-patch apply && echo hi\"\n    -> postinstall: \"echo \
             hi\"\n    dependencies:  \"socket-patch apply\"\n    -> dependencies: \
             (removed)\n\nWill remove the socket-patch-hook dependency from:\n  - \
             requirements.txt\n\nGem: remove the socket-patch Bundler plugin wiring from:\n  \
             - Gemfile\n"
        );
        assert!(!out.contains("\n\n\n"), "{out:?}");
        assert!(
            out.ends_with("Gemfile\n"),
            "no trailing blank line: {out:?}"
        );
    }
}
