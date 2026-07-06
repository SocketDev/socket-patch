use clap::Args;
use socket_patch_core::composer_setup::{self, ComposerSetupStatus};
use socket_patch_core::crawlers::python_crawler::is_python_project;
use socket_patch_core::gem_setup::{self, GemSetupStatus};
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::{PatchManifest, SetupConfig};
use socket_patch_core::package_json::detect::{is_setup_configured_str, PackageManager};
use socket_patch_core::package_json::find::{
    detect_package_manager, find_package_json_files, PackageJsonLocation, WorkspaceType,
};
use socket_patch_core::package_json::update::{
    remove_package_json, update_package_json, RemoveResult, RemoveStatus, UpdateResult,
    UpdateStatus,
};
use socket_patch_core::pth_hook::detect::{
    deps_contain_hook, detect_python_pm, PythonPackageManager,
};
use socket_patch_core::pth_hook::edit::{
    add_hook_dependency, pyproject_contains_hook, remove_hook_dependency, ManifestKind,
    PthEditResult, PthStatus,
};
use socket_patch_core::utils::telemetry::track_patch_setup;
use socket_patch_core::vex::applied_patches_with_vendor;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::ecosystem_dispatch::find_manifest_package_paths;
use crate::output::stdin_is_tty;

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
    /// so `setup --check` and a fresh clone honor it without re-passing the flag
    /// (CLI_CONTRACT property 9).
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
    if !eco_in_scope(&args.common, ECO_NPM) {
        return Vec::new();
    }
    let find_result = find_package_json_files(&args.common.cwd).await;

    // For pnpm monorepos, only update root package.json. pnpm runs root
    // postinstall on `pnpm install`, so workspace-level postinstall scripts are
    // unnecessary and would fail under pnpm's strict module isolation.
    let files: Vec<PackageJsonLocation> = match find_result.workspace_type {
        WorkspaceType::Pnpm => find_result
            .files
            .into_iter()
            .filter(|loc| loc.is_root)
            .collect(),
        _ => find_result.files,
    };

    // Property 9: drop excluded workspace members (the root is never excludable).
    files
        .into_iter()
        .filter(|loc| loc.is_root || !is_member_excluded(&loc.path, &args.common.cwd, excludes))
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
            serde_json::to_string_pretty(&serde_json::Value::Object(map)).unwrap()
        );
    } else if !args.common.silent {
        println!("No package.json, Python, Bundler, or Composer project found");
    }
    0
}

fn pathdiff(path: &str, base: &Path) -> String {
    let p = Path::new(path);
    p.strip_prefix(base)
        .map(|r| r.display().to_string())
        .unwrap_or_else(|_| path.to_string())
}

/// The setup/remove mutation gate (shared verbatim by both flows): default-no
/// prompt on a TTY, auto-proceed with a stderr note when stdin is not
/// interactive. Returns whether to go ahead. (Deliberately NOT
/// `output::confirm`, whose semantics differ: stderr prompt, `default_yes`
/// honored on non-TTY and empty input.)
fn confirm_proceed(prompt: &str) -> bool {
    if !stdin_is_tty() {
        eprintln!("Non-interactive mode detected, proceeding automatically.");
        return true;
    }
    print!("{prompt}");
    io::stdout().flush().unwrap();
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() {
        // Terminals can deliver non-UTF-8 bytes (e.g. a Latin-1 paste);
        // `read_line` reports those as InvalidData. Treat any read
        // failure like an unrecognized answer (abort), not a panic.
        return false;
    }
    let answer = answer.trim().to_lowercase();
    answer == "y" || answer == "yes"
}

/// Whether an ecosystem is in scope for this run, honoring the global
/// `--ecosystems` filter (`CLI_CONTRACT.md` → "Setup command contract",
/// property 2). With no filter (or an empty one) every ecosystem is in scope.
/// `names` lists the accepted tokens for the ecosystem — its canonical
/// `Ecosystem::cli_name()` plus any friendly alias (e.g. `pypi`/`python`,
/// `gem`/`ruby`) — matched case-insensitively, mirroring the scoping semantics
/// `apply` uses for the in-place ecosystems.
fn eco_in_scope(common: &GlobalArgs, names: &[&str]) -> bool {
    match &common.ecosystems {
        None => true,
        Some(list) if list.is_empty() => true,
        Some(list) => list
            .iter()
            .any(|e| names.iter().any(|n| e.eq_ignore_ascii_case(n))),
    }
}

/// Normalize a workspace-member / exclude path for comparison: forward slashes,
/// no leading `./`, no trailing slash.
fn normalize_rel_path(p: &str) -> String {
    let p = p.replace('\\', "/");
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
    excludes.iter().any(|e| normalize_rel_path(e) == rel)
}

/// The exclude set in effect for this run: the persisted `setup.exclude` list
/// from `.socket/manifest.json` (empty if no manifest / no setup state) union
/// the `--exclude` flag values (all normalized). This is what a clone inherits
/// — a clone with no flag still reads the persisted set. Read-only.
async fn effective_excludes(common: &GlobalArgs, flag: &[String]) -> Vec<String> {
    let mut set: Vec<String> = match read_manifest(&common.resolved_manifest_path()).await {
        Ok(Some(m)) => m
            .setup
            .map(|s| s.exclude)
            .unwrap_or_default()
            .iter()
            .map(|e| normalize_rel_path(e))
            .collect(),
        _ => Vec::new(),
    };
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
/// without re-passing `--exclude`. No-op when the set is empty or already
/// exactly persisted (keeps the manifest byte-stable). Never called under
/// `--dry-run`.
async fn persist_setup_excludes(common: &GlobalArgs, excludes: &[String]) {
    if excludes.is_empty() {
        return;
    }
    let path = common.resolved_manifest_path();
    let existing = read_manifest(&path).await.ok().flatten();
    let mut merged: Vec<String> = excludes.to_vec();
    merged.sort();
    merged.dedup();
    if existing
        .as_ref()
        .and_then(|m| m.setup.as_ref())
        .map(|s| &s.exclude)
        == Some(&merged)
    {
        return; // already persisted exactly — don't rewrite
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
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let _ = write_manifest(&path, &manifest).await;
}

/// Which ecosystems are **actually set up** at `cwd` — i.e. their auto-repatch
/// hook is present on disk (the same presence checks `setup --check` runs). VEX
/// uses this (∪ the manifest's `manual` declarations) to attest patches only for
/// set-up-or-manual ecosystems (CLI_CONTRACT property 7). Read-only; ignores the
/// `--ecosystems` filter (it reports real on-disk state).
pub(crate) async fn configured_ecosystems(
    common: &GlobalArgs,
) -> std::collections::HashSet<socket_patch_core::crawlers::Ecosystem> {
    use socket_patch_core::crawlers::Ecosystem;
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
    if let Some(project) = gem_setup::discover_bundler_project(&common.cwd).await {
        if let Ok(content) = tokio::fs::read_to_string(&project.gemfile).await {
            if gem_setup::is_plugin_directive_present(&content) {
                set.insert(Ecosystem::Gem);
            }
        }
    }

    if let Some(composer_json) = composer_setup::discover_composer_project(&common.cwd).await {
        if let Ok(content) = tokio::fs::read_to_string(&composer_json).await {
            if composer_setup::is_hook_present(&content) {
                set.insert(Ecosystem::Composer);
            }
        }
    }

    set
}

// Canonical `--ecosystems` token sets per setup branch (see `eco_in_scope`).
const ECO_NPM: &[&str] = &["npm"];
const ECO_PYPI: &[&str] = &["pypi", "python"];
const ECO_GEM: &[&str] = &["gem", "ruby"];
const ECO_COMPOSER: &[&str] = &["composer", "php"];

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
    if !eco_in_scope(common, ECO_PYPI) {
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
    // that exists. Best-effort — never fatal.
    if let Some((program, args)) = plan.pm.lock_command() {
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
            match tokio::process::Command::new(program)
                .args(args)
                .current_dir(cwd)
                .output()
                .await
            {
                Ok(o) if o.status.success() => {}
                Ok(o) => warnings.push(format!(
                    "`{program} {}` failed ({}); update the lockfile manually",
                    args.join(" "),
                    o.status
                )),
                Err(e) => warnings.push(format!(
                    "could not run `{program} {}`: {e}; update the lockfile manually",
                    args.join(" ")
                )),
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

/// Build the gem branch's contribution to a setup/remove run: add (or remove)
/// the managed `plugin "socket-patch"` block in the Gemfile + the generated
/// `.socket/bundler-plugin/` plugin files.
async fn build_gem_outcome(common: &GlobalArgs, remove: bool, dry_run: bool) -> SetupOutcome {
    if !eco_in_scope(common, ECO_GEM) {
        return SetupOutcome::default();
    }
    let project = match gem_setup::discover_bundler_project(&common.cwd).await {
        Some(p) => p,
        None => return SetupOutcome::default(),
    };

    let mut out = SetupOutcome {
        present: true,
        ..Default::default()
    };

    let results = if remove {
        gem_setup::remove_plugin_directive(&project, dry_run).await
    } else {
        gem_setup::add_plugin_directive(&project, dry_run).await
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
        for p in &added_paths {
            out.preview
                .push(format!("  + {}", pathdiff(p, &common.cwd)));
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

/// Build the composer branch's contribution to a setup/remove run: add (or
/// remove) the `socket-patch apply` command in `composer.json`'s
/// `post-install-cmd` / `post-update-cmd` script events.
async fn build_composer_outcome(common: &GlobalArgs, remove: bool, dry_run: bool) -> SetupOutcome {
    if !eco_in_scope(common, ECO_COMPOSER) {
        return SetupOutcome::default();
    }
    let composer_json = match composer_setup::discover_composer_project(&common.cwd).await {
        Some(p) => p,
        None => return SetupOutcome::default(),
    };

    let mut out = SetupOutcome {
        present: true,
        ..Default::default()
    };

    let r = if remove {
        composer_setup::remove_hook(&composer_json, dry_run).await
    } else {
        composer_setup::add_hook(&composer_json, dry_run).await
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
        for p in &added_paths {
            out.preview
                .push(format!("  + {}", pathdiff(p, &common.cwd)));
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
    if !eco_in_scope(common, ECO_COMPOSER) {
        return false;
    }
    let composer_json = match composer_setup::discover_composer_project(&common.cwd).await {
        Some(p) => p,
        None => return false,
    };
    let (state, err) = match tokio::fs::read_to_string(&composer_json).await {
        Ok(content) => {
            if composer_setup::is_hook_present(&content) {
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
    match tokio::process::Command::new(&exe)
        .args(["apply", "--offline", "--ecosystems", "gem", "--cwd", &root, "--silent"])
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
    if !eco_in_scope(common, ECO_GEM) {
        return false;
    }
    let project = match gem_setup::discover_bundler_project(&common.cwd).await {
        Some(p) => p,
        None => return false,
    };
    let (state, err) = match tokio::fs::read_to_string(&project.gemfile).await {
        Ok(content) => {
            if gem_setup::is_plugin_directive_present(&content) {
                (CheckState::Configured, None)
            } else {
                (CheckState::NeedsConfiguration, None)
            }
        }
        Err(e) => (CheckState::Error, Some(e.to_string())),
    };
    entries.push(("gemfile", project.gemfile.display().to_string(), state, err));
    let dir_state = if gem_setup::plugin_files_present(&project.root).await {
        CheckState::Configured
    } else {
        CheckState::NeedsConfiguration
    };
    entries.push((
        "gem_plugin",
        gem_setup::plugin_dir(&project.root).display().to_string(),
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
/// vendor ledger ([`crate::commands::vex::load_vendor_context`]: a vendored
/// patch is judged by its `.socket/vendor/` artifact — the bytes the next
/// install consumes — never the expectedly-unpatched installed tree), then
/// [`applied_patches_with_vendor`]. An *uninstalled* package (`package_not_found`, also the
/// bucket for out-of-scope PURLs absent from the map) cannot be patched yet, and
/// a degenerate zero-file record (`no_files`) has nothing to hash — neither is
/// drift, so both are skipped. A missing/empty/unreadable manifest contributes
/// nothing (hook presence alone decides). Read-only: it crawls but never writes.
async fn append_patch_consistency_entries(
    common: &GlobalArgs,
    entries: &mut Vec<(&'static str, String, CheckState, Option<String>)>,
) {
    let manifest_path = common.resolved_manifest_path();
    let manifest = match read_manifest(&manifest_path).await {
        Ok(Some(m)) if !m.patches.is_empty() => m,
        _ => return,
    };

    let purls: Vec<String> = manifest.patches.keys().cloned().collect();
    // `--json` reserves stdout for the check report: silence the dispatch's
    // human chrome ("Using <X> at: ...") like apply/rollback do.
    let package_paths =
        find_manifest_package_paths(&purls, common, common.silent || common.json).await;

    let vendor = crate::commands::vex::load_vendor_context(common, &manifest).await;
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

#[derive(Clone, Copy, PartialEq)]
enum CheckState {
    Configured,
    NeedsConfiguration,
    Error,
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
        println!("Searching for package.json / Python / Bundler / Composer manifests...");
    }

    // Excluded members (persisted in the manifest + any passed via `--exclude`)
    // are skipped by discovery. Read-only: `--check` never persists.
    let excludes = effective_excludes(&args.common, &args.exclude).await;
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
                if serde_json::from_str::<serde_json::Value>(json).is_err() {
                    (CheckState::Error, Some("Invalid package.json".to_string()))
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
    append_patch_consistency_entries(&args.common, &mut entries).await;

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
            .unwrap()
        );
    } else if !args.common.silent {
        println!("\nConfiguration status:\n");
        for (_, path, state, err) in &entries {
            let rel = pathdiff(path, &args.common.cwd);
            match state {
                CheckState::Configured => println!("  ✓ {rel} (configured)"),
                CheckState::NeedsConfiguration => println!("  ✗ {rel} (needs setup)"),
                CheckState::Error => {
                    println!("  ! {rel}: {}", err.as_deref().unwrap_or("unknown error"))
                }
            }
        }
        println!();
        if all_ok {
            println!("All manifests are configured with socket-patch.");
        } else {
            println!(
                "{needs} manifest(s) need configuration, {errs} error(s). Run `socket-patch setup` to fix."
            );
        }
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
        println!("Searching for package.json / Python / Bundler / Composer manifests...");
    }

    // Honor the persisted/`--exclude` member set so we never touch a member that
    // was deliberately excluded from setup. Remove does not change the set.
    let excludes = effective_excludes(common, &args.exclude).await;
    let npm_files = discover(args, &excludes).await;
    let py_plan = plan_python(common).await;
    let gem_preview = build_gem_outcome(common, true, true).await;
    let composer_preview = build_composer_outcome(common, true, true).await;
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
        print_remove_preview(&npm_preview, &py_preview, &extra_preview, common);
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
                println!("Nothing removed; {preview_errs} item(s) could not be processed (see errors above).");
            } else {
                println!("No socket-patch install hooks found to remove.");
            }
        }
        eprint_errors_when_silent(
            common,
            &remove_error_messages(&npm_preview, &py_preview, &extra_preview),
        );
        return if preview_errs > 0 { 1 } else { 0 };
    }

    // Dry-run: preview already shown; report and exit without writing.
    if common.dry_run {
        if common.json {
            print_remove_envelope("dry_run", &npm_preview, &py_preview, &extra_preview, &[]);
        } else if !common.silent {
            println!("\nSummary:");
            println!("  {n_remove} item(s) would have socket-patch removed");
        }
        eprint_errors_when_silent(
            common,
            &remove_error_messages(&npm_preview, &py_preview, &extra_preview),
        );
        return if preview_errs > 0 { 1 } else { 0 };
    }

    // Confirm before mutating.
    if !common.yes && !common.json && !confirm_proceed("Remove these install hooks? (y/N): ") {
        println!("Aborted");
        return 0;
    }

    if !quiet {
        println!("\nRemoving changes...");
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
        build_gem_outcome(common, true, false).await,
        build_composer_outcome(common, true, false).await,
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
        println!("  {removed} item(s) had socket-patch removed");
        if errs > 0 {
            println!("  {errs} error(s)");
        }
        for w in &warnings {
            println!("  warning: {w}");
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

    eprint_errors_when_silent(
        common,
        &remove_error_messages(&npm_results, &py_results, &extra_results),
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
/// both flows print when `preview_errors > 0`.
fn outcome_error_messages(o: &SetupOutcome) -> Vec<String> {
    o.json_files
        .iter()
        .filter(|f| f.get("status").and_then(|s| s.as_str()) == Some("error"))
        .filter_map(|f| f.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .collect()
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
) -> Vec<String> {
    let mut errs: Vec<String> = npm
        .iter()
        .filter(|r| r.status == RemoveStatus::Error)
        .filter_map(|r| r.error.clone())
        .chain(
            py.iter()
                .filter(|r| r.status == PthStatus::Error)
                .filter_map(|r| r.error.clone()),
        )
        .collect();
    errs.extend(outcome_error_messages(extra));
    errs
}

/// Per-item error messages across the three setup result families (npm +
/// Python + gem/composer) — the preview "Errors:" section and the
/// silent-mode stderr reporting share this.
fn setup_error_messages(
    npm: &[UpdateResult],
    py: &[PthEditResult],
    extra: &SetupOutcome,
) -> Vec<String> {
    let mut errs: Vec<String> = npm
        .iter()
        .filter(|r| r.status == UpdateStatus::Error)
        .filter_map(|r| r.error.clone())
        .chain(
            py.iter()
                .filter(|r| r.status == PthStatus::Error)
                .filter_map(|r| r.error.clone()),
        )
        .collect();
    errs.extend(outcome_error_messages(extra));
    errs
}

fn print_remove_preview(
    npm: &[RemoveResult],
    py: &[PthEditResult],
    extra: &SetupOutcome,
    common: &GlobalArgs,
) {
    let to_remove: Vec<_> = npm
        .iter()
        .filter(|r| r.status == RemoveStatus::Removed)
        .collect();
    let py_remove: Vec<_> = py
        .iter()
        .filter(|r| r.status == PthStatus::Updated)
        .collect();
    println!("\nProposed changes:\n");
    if !to_remove.is_empty() {
        println!("Will remove socket-patch from:");
        for r in &to_remove {
            let rel = pathdiff(&r.path, &common.cwd);
            println!("  - {rel}");
            println!("    postinstall:   \"{}\"", r.old_script);
            println!("    -> postinstall: {}", render_removed(&r.new_script));
            println!("    dependencies:  \"{}\"", r.old_dependencies_script);
            println!(
                "    -> dependencies: {}",
                render_removed(&r.new_dependencies_script)
            );
        }
        println!();
    }
    if !py_remove.is_empty() {
        println!("Will remove the socket-patch-hook dependency from:");
        for r in &py_remove {
            println!("  - {}", pathdiff(&r.path, &common.cwd));
        }
        println!();
    }
    if !extra.preview.is_empty() {
        for line in &extra.preview {
            println!("{line}");
        }
        println!();
    }

    // Surface failures so the "(see errors above)" line `run_remove` prints when
    // nothing could be removed actually points at something.
    let errs = remove_error_messages(npm, py, extra);
    if !errs.is_empty() {
        println!("Errors:");
        for e in &errs {
            println!("  ! {e}");
        }
        println!();
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
    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
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
        println!("Configuring socket-patch install hooks...");
    }

    // Resolve the effective exclude set (persisted + `--exclude`) and, on a real
    // run, persist it so `--check` and a fresh clone honor it without the flag.
    // Dry-run never writes the manifest. Excluded members are then skipped by
    // discovery.
    let excludes = effective_excludes(common, &args.exclude).await;
    if !common.dry_run {
        persist_setup_excludes(common, &excludes).await;
    }
    let npm_files = discover(args, &excludes).await;
    let py_plan = plan_python(common).await;
    // Gem + Composer previews (dry-run); `.present` also tells us each project exists.
    let gem_preview = build_gem_outcome(common, false, true).await;
    let composer_preview = build_composer_outcome(common, false, true).await;

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

    let telemetry_manager = telemetry_manager_str(
        !npm_files.is_empty(),
        py_plan.is_some(),
        gem_present,
        composer_present,
        npm_pm,
    );
    track_patch_setup(
        &telemetry_manager,
        common.api_token.as_deref(),
        common.org.as_deref(),
    )
    .await;

    // Preview (always dry-run first).
    let mut npm_preview = Vec::new();
    for loc in &npm_files {
        npm_preview.push(update_package_json(&loc.path, true, npm_pm).await);
    }
    let py_preview = match &py_plan {
        Some(plan) => edit_python_manifests(plan, false, true).await,
        None => Vec::new(),
    };

    if !quiet {
        print_setup_preview(&npm_preview, &py_preview, &extra_preview, common);
    }

    let n_changes = npm_preview
        .iter()
        .filter(|r| r.status == UpdateStatus::Updated)
        .count()
        + py_preview
            .iter()
            .filter(|r| r.status == PthStatus::Updated)
            .count()
        + extra_preview.changed;
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
                &[],
            );
        } else if !common.silent {
            if preview_errors > 0 {
                println!("No hooks were changed; {preview_errors} item(s) could not be processed (see errors above).");
            } else {
                println!("All install hooks are already configured with socket-patch!");
            }
        }
        eprint_errors_when_silent(
            common,
            &setup_error_messages(&npm_preview, &py_preview, &extra_preview),
        );
        return if preview_errors > 0 { 1 } else { 0 };
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
            println!("  {n_changes} item(s) would be updated");
        }
        eprint_errors_when_silent(
            common,
            &setup_error_messages(&npm_preview, &py_preview, &extra_preview),
        );
        return if preview_errors > 0 { 1 } else { 0 };
    }

    if !common.yes && !common.json && !confirm_proceed("Proceed with these changes? (y/N): ") {
        println!("Aborted");
        return 0;
    }

    if !quiet {
        println!("\nApplying changes...");
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
    // Real gem + composer edits (gem Gemfile `plugin` block + generated plugin
    // dir; composer.json script-event command).
    let extra_results = merge_outcomes(
        build_gem_outcome(common, false, false).await,
        build_composer_outcome(common, false, false).await,
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
        println!("  {updated} item(s) updated");
        if errors > 0 {
            println!("  {errors} error(s)");
        }
        for w in &warnings {
            println!("  warning: {w}");
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

    eprint_errors_when_silent(
        common,
        &setup_error_messages(&npm_results, &py_results, &extra_results),
    );

    if errors > 0 {
        1
    } else {
        0
    }
}

fn print_setup_preview(
    npm: &[UpdateResult],
    py: &[PthEditResult],
    extra: &SetupOutcome,
    common: &GlobalArgs,
) {
    let npm_changes: Vec<_> = npm
        .iter()
        .filter(|r| r.status == UpdateStatus::Updated)
        .collect();
    let py_changes: Vec<_> = py
        .iter()
        .filter(|r| r.status == PthStatus::Updated)
        .collect();

    if !npm_changes.is_empty() {
        println!("\npackage.json files to update:");
        for r in &npm_changes {
            println!("  + {}", pathdiff(&r.path, &common.cwd));
            println!("    -> postinstall: \"{}\"", r.new_script);
        }
    }
    if !py_changes.is_empty() {
        println!("\nPython manifests to update (socket-patch-hook):");
        for r in &py_changes {
            println!("  + {}", pathdiff(&r.path, &common.cwd));
        }
    }
    if !extra.preview.is_empty() {
        println!();
        for line in &extra.preview {
            println!("{line}");
        }
    }

    let npm_already = npm
        .iter()
        .filter(|r| r.status == UpdateStatus::AlreadyConfigured)
        .count();
    let py_already = py
        .iter()
        .filter(|r| r.status == PthStatus::AlreadyConfigured)
        .count();
    if npm_already + py_already + extra.already > 0 {
        println!(
            "\nAlready configured (will skip): {}",
            npm_already + py_already + extra.already
        );
    }

    let errs = setup_error_messages(npm, py, extra);
    if !errs.is_empty() {
        println!("\nErrors:");
        for e in &errs {
            println!("  ! {e}");
        }
    }
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
    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}
