use clap::Args;
#[cfg(feature = "cargo")]
use socket_patch_core::cargo_setup::{
    add_guard_dep, discover_cargo_project, is_guard_dep_present, remove_guard_dep, CargoEditResult,
    CargoSetupStatus,
};
#[cfg(feature = "golang")]
use socket_patch_core::go_setup::{self, GoSetupStatus};
use socket_patch_core::gem_setup::{self, GemSetupStatus};
#[cfg(feature = "composer")]
use socket_patch_core::composer_setup::{self, ComposerSetupStatus};
use socket_patch_core::crawlers::python_crawler::is_python_project;
use socket_patch_core::package_json::detect::{is_setup_configured_str, PackageManager};
use socket_patch_core::package_json::find::{
    detect_package_manager, find_package_json_files, PackageJsonLocation, WorkspaceType,
};
use socket_patch_core::package_json::update::{
    remove_package_json, update_package_json, RemoveResult, RemoveStatus, UpdateResult,
    UpdateStatus,
};
use socket_patch_core::pth_hook::{
    add_hook_dependency, deps_contain_hook, detect_python_pm, remove_hook_dependency, ManifestKind,
    PthEditResult, PthStatus, PythonPackageManager,
};
use socket_patch_core::crawlers::CrawlerOptions;
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::utils::telemetry::track_patch_setup;
use socket_patch_core::vex::applied_patches;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::args::GlobalArgs;
use crate::ecosystem_dispatch::{find_packages_for_rollback, partition_purls};
use crate::output::stdin_is_tty;

/// Stringify the detected npm-family manager for telemetry.
fn manager_name(pm: PackageManager) -> &'static str {
    match pm {
        PackageManager::Npm => "npm",
        PackageManager::Pnpm => "pnpm",
    }
}

/// Compose the `+`-joined telemetry manager tag across the ecosystems in scope
/// (e.g. `npm+pypi+cargo`), or `none`.
#[allow(clippy::too_many_arguments)]
fn telemetry_manager_str(
    npm: bool,
    py: bool,
    cargo: bool,
    go: bool,
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
    if cargo {
        parts.push("cargo");
    }
    if go {
        parts.push("golang");
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
        value_parser = clap::builder::BoolishValueParser::new(),
    )]
    pub check: bool,

    /// Revert the install hooks that `setup` added: npm `package.json` scripts,
    /// the Python `socket-patch[hook]` dependency, the cargo `socket-patch-guard`
    /// dependency + `[env]`, the Go guard package + blank imports, and the gem
    /// Bundler plugin wiring.
    #[arg(
        long = "remove",
        default_value_t = false,
        value_parser = clap::builder::BoolishValueParser::new(),
    )]
    pub remove: bool,

    #[command(flatten)]
    pub common: GlobalArgs,
}

pub async fn run(args: SetupArgs) -> i32 {
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
async fn discover(args: &SetupArgs) -> Vec<PackageJsonLocation> {
    if !eco_in_scope(&args.common, ECO_NPM) {
        return Vec::new();
    }
    let find_result = find_package_json_files(&args.common.cwd).await;

    // For pnpm monorepos, only update root package.json. pnpm runs root
    // postinstall on `pnpm install`, so workspace-level postinstall scripts are
    // unnecessary and would fail under pnpm's strict module isolation.
    match find_result.workspace_type {
        WorkspaceType::Pnpm => find_result
            .files
            .into_iter()
            .filter(|loc| loc.is_root)
            .collect(),
        _ => find_result.files,
    }
}

/// Emit the shared "nothing found" result and exit code.
fn report_no_files(args: &SetupArgs, status: &str) -> i32 {
    if args.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": status,
                "files": [],
            }))
            .unwrap()
        );
    } else {
        println!("No package.json or Python project found");
    }
    0
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
/// `names` lists the accepted tokens for the ecosystem — its canonical
/// `Ecosystem::cli_name()` plus any friendly alias (e.g. `golang`/`go`,
/// `pypi`/`python`, `gem`/`ruby`) — matched case-insensitively, mirroring the
/// semantics `apply` already uses (`cargo_in_local_scope`/`go_in_local_scope`).
fn eco_in_scope(common: &GlobalArgs, names: &[&str]) -> bool {
    match &common.ecosystems {
        None => true,
        Some(list) if list.is_empty() => true,
        Some(list) => list
            .iter()
            .any(|e| names.iter().any(|n| e.eq_ignore_ascii_case(n))),
    }
}

// Canonical `--ecosystems` token sets per setup branch (see `eco_in_scope`).
const ECO_NPM: &[&str] = &["npm"];
const ECO_PYPI: &[&str] = &["pypi", "python"];
const ECO_CARGO: &[&str] = &["cargo"];
const ECO_GOLANG: &[&str] = &["golang", "go"];
const ECO_GEM: &[&str] = &["gem", "ruby"];
#[cfg(feature = "composer")]
const ECO_COMPOSER: &[&str] = &["composer", "php"];

// ─────────────────────────────────────────────────────────────────────────
// Python (.pth hook) helpers
// ─────────────────────────────────────────────────────────────────────────

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

fn pth_status_str(s: &PthStatus) -> &'static str {
    match s {
        PthStatus::Updated => "updated",
        PthStatus::AlreadyConfigured => "already_configured",
        PthStatus::Error => "error",
    }
}

fn update_status_str(s: &UpdateStatus) -> &'static str {
    match s {
        UpdateStatus::Updated => "updated",
        UpdateStatus::AlreadyConfigured => "already_configured",
        UpdateStatus::Error => "error",
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Cargo (project-local [patch]-redirect guard) helpers
// ─────────────────────────────────────────────────────────────────────────

/// Feature-agnostic summary of the cargo branch's contribution to a
/// setup/remove run. Built by [`build_cargo_outcome`] (a no-op `Default` when
/// the `cargo` feature is off), so the shared reporting code never has to name
/// the cargo-only types.
#[derive(Default)]
struct SetupOutcome {
    /// A cargo project was discovered (gates the `no_files` decision).
    present: bool,
    /// Items changed (guard dep added/removed + `[env]` written/removed).
    changed: usize,
    already: usize,
    errors: usize,
    /// Envelope `files[]` entries (kind = `cargo` / `cargo_env`).
    json_files: Vec<serde_json::Value>,
    /// Human-readable preview lines (already formatted).
    preview: Vec<String>,
}

/// Build the cargo outcome for a setup (`remove=false`) or remove
/// (`remove=true`) run at the given `dry_run` setting.
#[cfg(feature = "cargo")]
async fn build_cargo_outcome(common: &GlobalArgs, remove: bool, dry_run: bool) -> SetupOutcome {
    use socket_patch_core::patch::cargo_config;

    if !eco_in_scope(common, ECO_CARGO) {
        return SetupOutcome::default();
    }
    let project = match discover_cargo_project(&common.cwd).await {
        Some(p) => p,
        None => return SetupOutcome::default(),
    };

    let mut out = SetupOutcome {
        present: true,
        ..Default::default()
    };

    // Per-member guard dependency edits.
    let version = guard_version();
    let mut results: Vec<(String, CargoEditResult)> = Vec::new();
    for member in &project.members {
        let res = if remove {
            remove_guard_dep(member, dry_run).await
        } else {
            add_guard_dep(member, &version, dry_run).await
        };
        results.push(("cargo".to_string(), res));
    }

    // The shared `[env] SOCKET_PATCH_ROOT` at the workspace root.
    let config_path = project.root.join(".cargo/config.toml");
    let env_change = if remove {
        cargo_config::drop_env_root(&project.root, dry_run).await
    } else {
        cargo_config::ensure_env_root(&project.root, dry_run).await
    };
    results.push(("cargo_env".to_string(), env_result(&config_path, env_change)));

    // Aggregate counts + render envelope entries / preview lines.
    let mut added_paths: Vec<String> = Vec::new();
    for (kind, r) in &results {
        match r.status {
            CargoSetupStatus::Updated => {
                out.changed += 1;
                added_paths.push(r.path.clone());
            }
            CargoSetupStatus::AlreadyConfigured => out.already += 1,
            CargoSetupStatus::Error => out.errors += 1,
        }
        out.json_files.push(serde_json::json!({
            "kind": kind,
            "path": r.path,
            "status": cargo_status_str(&r.status, remove),
            "error": r.error,
        }));
    }

    if !added_paths.is_empty() {
        let header = if remove {
            "Cargo: remove socket-patch-guard + [env] SOCKET_PATCH_ROOT from:"
        } else {
            "Cargo: add socket-patch-guard + [env] SOCKET_PATCH_ROOT to:"
        };
        out.preview.push(header.to_string());
        for p in &added_paths {
            out.preview.push(format!("  + {}", pathdiff(p, &common.cwd)));
        }
    }

    out
}

#[cfg(not(feature = "cargo"))]
async fn build_cargo_outcome(_common: &GlobalArgs, _remove: bool, _dry_run: bool) -> SetupOutcome {
    SetupOutcome::default()
}

// ─────────────────────────────────────────────────────────────────────────
// Go (project-local go.mod `replace`-redirect guard) helpers
// ─────────────────────────────────────────────────────────────────────────

/// Build the Go branch's contribution to a setup/remove run: write (or remove)
/// the `internal/socketpatchguard` package + the per-`main` blank-import files.
/// A no-op `Default` when the `golang` feature is off.
#[cfg(feature = "golang")]
async fn build_go_outcome(common: &GlobalArgs, remove: bool, dry_run: bool) -> SetupOutcome {
    if !eco_in_scope(common, ECO_GOLANG) {
        return SetupOutcome::default();
    }
    let module = match go_setup::discover_go_module(&common.cwd).await {
        Some(m) => m,
        None => return SetupOutcome::default(),
    };

    let mut out = SetupOutcome {
        present: true,
        ..Default::default()
    };

    let mut results: Vec<go_setup::GoEditResult> = Vec::new();
    if remove {
        results.push(go_setup::remove_guard(&module.root, dry_run).await);
        results.extend(go_setup::remove_main_imports(&module.root, dry_run).await);
    } else {
        results.push(go_setup::add_guard(&module.root, dry_run).await);
        results.extend(
            go_setup::add_main_imports(&module.root, &module.module_path, dry_run).await,
        );
    }

    let mut added_paths: Vec<String> = Vec::new();
    for r in &results {
        match r.status {
            GoSetupStatus::Updated => {
                out.changed += 1;
                added_paths.push(r.path.clone());
            }
            GoSetupStatus::AlreadyConfigured => out.already += 1,
            GoSetupStatus::Error => out.errors += 1,
        }
        out.json_files.push(serde_json::json!({
            "kind": r.kind,
            "path": r.path,
            "status": go_status_str(&r.status, remove),
            "error": r.error,
        }));
    }

    if !added_paths.is_empty() {
        let header = if remove {
            "Go: remove socket-patch guard wiring from:"
        } else {
            "Go: add socket-patch guard wiring to:"
        };
        out.preview.push(header.to_string());
        for p in &added_paths {
            out.preview.push(format!("  + {}", pathdiff(p, &common.cwd)));
        }
    }

    out
}

#[cfg(not(feature = "golang"))]
async fn build_go_outcome(_common: &GlobalArgs, _remove: bool, _dry_run: bool) -> SetupOutcome {
    SetupOutcome::default()
}

#[cfg(feature = "golang")]
fn go_status_str(s: &GoSetupStatus, for_remove: bool) -> &'static str {
    match (s, for_remove) {
        (GoSetupStatus::Updated, false) => "updated",
        (GoSetupStatus::Updated, true) => "removed",
        (GoSetupStatus::AlreadyConfigured, false) => "already_configured",
        (GoSetupStatus::AlreadyConfigured, true) => "not_configured",
        (GoSetupStatus::Error, _) => "error",
    }
}

/// Materialise the Go `replace` redirects right after wiring the guard (the
/// "automatic" step) so the first `go test`/`go run` finds patches already in
/// sync instead of self-healing on first run. Best-effort and offline: runs the
/// same `apply` the guard would, capturing output so it never corrupts setup's
/// (possibly JSON) stdout. A non-zero exit becomes a warning — the guard heals
/// it on first run. No-op without the `golang` feature.
#[cfg(feature = "golang")]
async fn finalize_go(common: &GlobalArgs) -> Vec<String> {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            return vec![format!(
                "could not locate socket-patch to materialize go patches ({e}); \
                 run `socket-patch apply --ecosystems golang`"
            )]
        }
    };
    let root = common.cwd.display().to_string();
    match tokio::process::Command::new(&exe)
        .args(["apply", "--offline", "--ecosystems", "golang", "--cwd", &root, "--silent"])
        .output()
        .await
    {
        Ok(o) if o.status.success() => Vec::new(),
        Ok(o) => vec![format!(
            "materializing go patches exited with {}; the guard will heal on first `go test`/run",
            o.status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into())
        )],
        Err(e) => vec![format!(
            "could not run apply to materialize go patches ({e}); the guard will heal on first run"
        )],
    }
}

#[cfg(not(feature = "golang"))]
async fn finalize_go(_common: &GlobalArgs) -> Vec<String> {
    Vec::new()
}

// ─────────────────────────────────────────────────────────────────────────
// Gem (Bundler plugin) helpers
// ─────────────────────────────────────────────────────────────────────────

/// Build the gem branch's contribution to a setup/remove run: add (or remove)
/// the managed `plugin "socket-patch"` block in the Gemfile + the generated
/// `.socket/bundler-plugin/` plugin files. Gem is an unconditional ecosystem,
/// so (unlike cargo/go) this is never feature-gated.
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
            out.preview.push(format!("  + {}", pathdiff(p, &common.cwd)));
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
/// `post-install-cmd` / `post-update-cmd` script events. Feature-gated behind
/// `composer` (a no-op `Default` when off), exactly like the cargo/go branches —
/// composer apply itself only exists with the feature, so wiring a hook without
/// it would be incoherent.
#[cfg(feature = "composer")]
async fn build_composer_outcome(common: &GlobalArgs, remove: bool, dry_run: bool) -> SetupOutcome {
    if !eco_in_scope(common, ECO_COMPOSER) {
        return SetupOutcome::default();
    }
    let project = match composer_setup::discover_composer_project(&common.cwd).await {
        Some(p) => p,
        None => return SetupOutcome::default(),
    };

    let mut out = SetupOutcome {
        present: true,
        ..Default::default()
    };

    let r = if remove {
        composer_setup::remove_hook(&project, dry_run).await
    } else {
        composer_setup::add_hook(&project, dry_run).await
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
            out.preview.push(format!("  + {}", pathdiff(p, &common.cwd)));
        }
    }

    out
}

#[cfg(not(feature = "composer"))]
async fn build_composer_outcome(_common: &GlobalArgs, _remove: bool, _dry_run: bool) -> SetupOutcome {
    SetupOutcome::default()
}

#[cfg(feature = "composer")]
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
#[cfg(feature = "composer")]
async fn append_composer_check_entries(
    common: &GlobalArgs,
    entries: &mut Vec<(&'static str, String, CheckState, Option<String>)>,
) -> bool {
    if !eco_in_scope(common, ECO_COMPOSER) {
        return false;
    }
    let project = match composer_setup::discover_composer_project(&common.cwd).await {
        Some(p) => p,
        None => return false,
    };
    let (state, err) = match tokio::fs::read_to_string(&project.composer_json).await {
        Ok(content) => {
            if composer_setup::is_hook_present(&content) {
                (CheckState::Configured, None)
            } else {
                (CheckState::NeedsConfiguration, None)
            }
        }
        Err(e) => (CheckState::Error, Some(e.to_string())),
    };
    entries.push((
        "composer",
        project.composer_json.display().to_string(),
        state,
        err,
    ));
    true
}

#[cfg(not(feature = "composer"))]
async fn append_composer_check_entries(
    _common: &GlobalArgs,
    _entries: &mut Vec<(&'static str, String, CheckState, Option<String>)>,
) -> bool {
    false
}

/// Materialise gem patches right after wiring the plugin (the "automatic" step)
/// so the first `bundle install` finds them already applied. Best-effort and
/// offline; a non-zero exit becomes a warning — the plugin heals on the next
/// `bundle install`. Mirrors [`finalize_go`].
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
/// (so release-variant PURLs resolve) honoring `--ecosystems`, then
/// [`applied_patches`]. An *uninstalled* package (`package_not_found`, also the
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
    let partitioned = partition_purls(&purls, common.ecosystems.as_deref());
    let crawler_options = CrawlerOptions {
        cwd: common.cwd.clone(),
        global: common.global,
        global_prefix: common.global_prefix.clone(),
        batch_size: 0, // unused for find_packages_for_rollback
    };
    let package_paths =
        find_packages_for_rollback(&partitioned, &crawler_options, common.silent).await;

    let outcome = applied_patches(&manifest, &package_paths).await;
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

/// The guard version string `setup` writes — major.minor of this CLI, so the
/// committed dep tracks the installed `socket-patch`.
#[cfg(feature = "cargo")]
fn guard_version() -> String {
    let v = env!("CARGO_PKG_VERSION");
    let mut parts = v.split('.');
    match (parts.next(), parts.next()) {
        (Some(major), Some(minor)) => format!("{major}.{minor}"),
        _ => v.to_string(),
    }
}

#[cfg(feature = "cargo")]
fn cargo_status_str(s: &CargoSetupStatus, for_remove: bool) -> &'static str {
    match (s, for_remove) {
        (CargoSetupStatus::Updated, false) => "updated",
        (CargoSetupStatus::Updated, true) => "removed",
        (CargoSetupStatus::AlreadyConfigured, false) => "already_configured",
        (CargoSetupStatus::AlreadyConfigured, true) => "not_configured",
        (CargoSetupStatus::Error, _) => "error",
    }
}

#[cfg(feature = "cargo")]
fn env_result(config_path: &Path, change: Result<bool, String>) -> CargoEditResult {
    match change {
        Ok(true) => CargoEditResult {
            path: config_path.display().to_string(),
            status: CargoSetupStatus::Updated,
            error: None,
        },
        Ok(false) => CargoEditResult {
            path: config_path.display().to_string(),
            status: CargoSetupStatus::AlreadyConfigured,
            error: None,
        },
        Err(e) => CargoEditResult {
            path: config_path.display().to_string(),
            status: CargoSetupStatus::Error,
            error: Some(e),
        },
    }
}

/// Append cargo check entries (one per member + one for `[env]`) to the shared
/// `run_check` entries list. Returns whether a cargo project was found.
#[cfg(feature = "cargo")]
async fn append_cargo_check_entries(
    common: &GlobalArgs,
    entries: &mut Vec<(&'static str, String, CheckState, Option<String>)>,
) -> bool {
    use socket_patch_core::patch::cargo_config;

    if !eco_in_scope(common, ECO_CARGO) {
        return false;
    }
    let project = match discover_cargo_project(&common.cwd).await {
        Some(p) => p,
        None => return false,
    };
    for member in &project.members {
        let (state, err) = match tokio::fs::read_to_string(member).await {
            Ok(content) => {
                if is_guard_dep_present(&content) {
                    (CheckState::Configured, None)
                } else {
                    (CheckState::NeedsConfiguration, None)
                }
            }
            Err(e) => (CheckState::Error, Some(e.to_string())),
        };
        entries.push(("cargo", member.display().to_string(), state, err));
    }
    let env_ok = cargo_config::env_root_present(&project.root).await;
    entries.push((
        "cargo_env",
        project.root.join(".cargo/config.toml").display().to_string(),
        if env_ok {
            CheckState::Configured
        } else {
            CheckState::NeedsConfiguration
        },
        None,
    ));
    true
}

#[cfg(not(feature = "cargo"))]
async fn append_cargo_check_entries(
    _common: &GlobalArgs,
    _entries: &mut Vec<(&'static str, String, CheckState, Option<String>)>,
) -> bool {
    false
}

/// Append Go check entries (the guard package + one per `package main` blank
/// import) to the shared `run_check` entries list. Returns whether a Go module
/// was found. Checks the SETUP wiring only — redirect sync is `apply --check`.
#[cfg(feature = "golang")]
async fn append_go_check_entries(
    common: &GlobalArgs,
    entries: &mut Vec<(&'static str, String, CheckState, Option<String>)>,
) -> bool {
    if !eco_in_scope(common, ECO_GOLANG) {
        return false;
    }
    let module = match go_setup::discover_go_module(&common.cwd).await {
        Some(m) => m,
        None => return false,
    };
    let guard_state = if go_setup::guard_files_present(&module.root).await {
        CheckState::Configured
    } else {
        CheckState::NeedsConfiguration
    };
    entries.push((
        "go_guard",
        module.root.join(go_setup::GUARD_DIR).display().to_string(),
        guard_state,
        None,
    ));
    for dir in go_setup::find_main_package_dirs(&module.root).await {
        let path = go_setup::import_file_path(&dir);
        let state = if tokio::fs::metadata(&path).await.is_ok() {
            CheckState::Configured
        } else {
            CheckState::NeedsConfiguration
        };
        entries.push(("go_import", path.display().to_string(), state, None));
    }
    true
}

#[cfg(not(feature = "golang"))]
async fn append_go_check_entries(
    _common: &GlobalArgs,
    _entries: &mut Vec<(&'static str, String, CheckState, Option<String>)>,
) -> bool {
    false
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
    if !args.common.json {
        println!("Searching for package.json / Python / Cargo / Go / Bundler / Composer manifests...");
    }

    let npm_files = discover(args).await;
    let py_plan = plan_python(&args.common).await;

    // (kind, path, state, error)
    let mut entries: Vec<(&'static str, String, CheckState, Option<String>)> = Vec::new();

    for loc in &npm_files {
        let (state, err) = match tokio::fs::read_to_string(&loc.path).await {
            Ok(content) => {
                if serde_json::from_str::<serde_json::Value>(&content).is_err() {
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
                    if deps_contain_hook(&content) {
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

    append_cargo_check_entries(&args.common, &mut entries).await;
    append_go_check_entries(&args.common, &mut entries).await;
    append_gem_check_entries(&args.common, &mut entries).await;
    append_composer_check_entries(&args.common, &mut entries).await;

    // Property 4: prove a correctly-patched state, not just hook presence —
    // every in-scope manifest patch must be applied on disk (`apply --check`
    // invariant). Drifted/un-applied patches add `needs_configuration` entries.
    append_patch_consistency_entries(&args.common, &mut entries).await;

    if entries.is_empty() {
        return report_no_files(args, "no_files");
    }

    let configured = entries.iter().filter(|(_, _, s, _)| *s == CheckState::Configured).count();
    let needs = entries.iter().filter(|(_, _, s, _)| *s == CheckState::NeedsConfiguration).count();
    let errs = entries.iter().filter(|(_, _, s, _)| *s == CheckState::Error).count();

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
    } else {
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
    if !common.json {
        println!("Searching for package.json / Python / Cargo / Go / Bundler / Composer manifests...");
    }

    let npm_files = discover(args).await;
    let py_plan = plan_python(common).await;
    let cargo_preview = build_cargo_outcome(common, true, true).await;
    let go_preview = build_go_outcome(common, true, true).await;
    let gem_preview = build_gem_outcome(common, true, true).await;
    let composer_preview = build_composer_outcome(common, true, true).await;
    if npm_files.is_empty()
        && py_plan.is_none()
        && !cargo_preview.present
        && !go_preview.present
        && !gem_preview.present
        && !composer_preview.present
    {
        return report_no_files(args, "no_files");
    }
    let cargo_present = cargo_preview.present;
    let go_present = go_preview.present;
    let gem_present = gem_preview.present;
    let cargo_preview = merge_outcomes(
        merge_outcomes(merge_outcomes(cargo_preview, go_preview), gem_preview),
        composer_preview,
    );

    // Preview (dry_run=true never writes).
    let mut npm_preview = Vec::new();
    for loc in &npm_files {
        npm_preview.push(remove_package_json(&loc.path, true).await);
    }
    let py_preview = match &py_plan {
        Some(p) => edit_python_manifests(p, true, true).await,
        None => Vec::new(),
    };

    if !common.json {
        print_remove_preview(&npm_preview, &py_preview, &cargo_preview, common);
    }

    let n_remove = npm_preview.iter().filter(|r| r.status == RemoveStatus::Removed).count()
        + py_preview.iter().filter(|r| r.status == PthStatus::Updated).count()
        + cargo_preview.changed;
    let preview_errs = npm_preview.iter().filter(|r| r.status == RemoveStatus::Error).count()
        + py_preview.iter().filter(|r| r.status == PthStatus::Error).count()
        + cargo_preview.errors;

    // Nothing to remove: clean (exit 0) or some file errored (exit 1).
    if n_remove == 0 {
        if common.json {
            print_remove_envelope(
                if preview_errs > 0 { "error" } else { "not_configured" },
                &npm_preview,
                &py_preview,
                &cargo_preview,
                &[],
            );
        } else if preview_errs > 0 {
            println!("Nothing removed; {preview_errs} item(s) could not be processed (see errors above).");
        } else {
            println!("No socket-patch install hooks found to remove.");
        }
        return if preview_errs > 0 { 1 } else { 0 };
    }

    // Dry-run: preview already shown; report and exit without writing.
    if common.dry_run {
        if common.json {
            print_remove_envelope("dry_run", &npm_preview, &py_preview, &cargo_preview, &[]);
        } else {
            println!("\nSummary:");
            println!("  {n_remove} item(s) would have socket-patch removed");
        }
        return if preview_errs > 0 { 1 } else { 0 };
    }

    // Confirm before mutating.
    if !common.yes && !common.json {
        if !stdin_is_tty() {
            eprintln!("Non-interactive mode detected, proceeding automatically.");
        } else {
            print!("Remove these install hooks? (y/N): ");
            io::stdout().flush().unwrap();
            let mut answer = String::new();
            io::stdin().read_line(&mut answer).unwrap();
            let answer = answer.trim().to_lowercase();
            if answer != "y" && answer != "yes" {
                println!("Aborted");
                return 0;
            }
        }
    }

    if !common.json {
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
    // Real cargo + go + gem + composer removal (guard dep/[env] root; go guard
    // package + imports; gem Gemfile `plugin` block + generated plugin dir;
    // composer.json script-event command).
    let cargo_results = merge_outcomes(
        merge_outcomes(
            merge_outcomes(
                build_cargo_outcome(common, true, false).await,
                build_go_outcome(common, true, false).await,
            ),
            build_gem_outcome(common, true, false).await,
        ),
        build_composer_outcome(common, true, false).await,
    );

    let errs = npm_results.iter().filter(|r| r.status == RemoveStatus::Error).count()
        + py_results.iter().filter(|r| r.status == PthStatus::Error).count()
        + cargo_results.errors;

    if common.json {
        print_remove_envelope(
            if errs > 0 { "partial_failure" } else { "success" },
            &npm_results,
            &py_results,
            &cargo_results,
            &warnings,
        );
    } else {
        let removed = npm_results.iter().filter(|r| r.status == RemoveStatus::Removed).count()
            + py_results.iter().filter(|r| r.status == PthStatus::Updated).count()
            + cargo_results.changed;
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
        if cargo_present {
            println!(
                "\nNote: existing patched-crate copies under .socket/cargo-patches/ and any \
                 managed [patch.crates-io] entries are removed on `socket-patch rollback`."
            );
        }
        if go_present {
            println!(
                "\nNote: the Go guard wiring was removed; existing patched-module copies under \
                 .socket/go-patches/ and managed go.mod `replace` directives are removed on \
                 `socket-patch rollback`."
            );
        }
        if gem_present {
            println!(
                "\nNote: the Bundler plugin wiring was removed; already-patched gems on disk are \
                 reverted by a fresh `bundle install` (or `socket-patch rollback`)."
            );
        }
    }

    if errs > 0 {
        1
    } else {
        0
    }
}

/// Error messages from a cargo/go/gem [`SetupOutcome`]'s rendered `files[]`
/// entries — the only place per-edit errors for those ecosystems are retained.
/// The setup/remove previews use this so their human-mode "Errors:" sections
/// actually list cargo/go/gem failures, honoring the "(see errors above)" line
/// both flows print when `preview_errors > 0`.
fn outcome_error_messages(o: &SetupOutcome) -> Vec<String> {
    o.json_files
        .iter()
        .filter(|f| f.get("status").and_then(|s| s.as_str()) == Some("error"))
        .filter_map(|f| f.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .collect()
}

fn print_remove_preview(
    npm: &[RemoveResult],
    py: &[PthEditResult],
    cargo: &SetupOutcome,
    common: &GlobalArgs,
) {
    let to_remove: Vec<_> = npm.iter().filter(|r| r.status == RemoveStatus::Removed).collect();
    let py_remove: Vec<_> = py.iter().filter(|r| r.status == PthStatus::Updated).collect();
    println!("\nProposed changes:\n");
    if !to_remove.is_empty() {
        println!("Will remove socket-patch from:");
        for r in &to_remove {
            let rel = pathdiff(&r.path, &common.cwd);
            println!("  - {rel}");
            println!("    postinstall:   \"{}\"", r.old_script);
            println!("    -> postinstall: {}", render_removed(&r.new_script));
            println!("    dependencies:  \"{}\"", r.old_dependencies_script);
            println!("    -> dependencies: {}", render_removed(&r.new_dependencies_script));
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
    if !cargo.preview.is_empty() {
        for line in &cargo.preview {
            println!("{line}");
        }
        println!();
    }

    // Surface failures so the "(see errors above)" line `run_remove` prints when
    // nothing could be removed actually points at something.
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
    errs.extend(outcome_error_messages(cargo));
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
    cargo: &SetupOutcome,
    warnings: &[String],
) {
    let removed = npm.iter().filter(|r| r.status == RemoveStatus::Removed).count()
        + py.iter().filter(|r| r.status == PthStatus::Updated).count()
        + cargo.changed;
    let not_cfg = npm.iter().filter(|r| r.status == RemoveStatus::NotConfigured).count()
        + py.iter().filter(|r| r.status == PthStatus::AlreadyConfigured).count()
        + cargo.already;
    let errors = npm.iter().filter(|r| r.status == RemoveStatus::Error).count()
        + py.iter().filter(|r| r.status == PthStatus::Error).count()
        + cargo.errors;

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
    // cargo.json_files already use the remove vocabulary
    // (removed/not_configured/error), built by `build_cargo_outcome`.
    files.extend(cargo.json_files.iter().cloned());

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
    if !common.json {
        println!("Configuring socket-patch install hooks...");
    }

    let npm_files = discover(args).await;
    let py_plan = plan_python(common).await;
    // Cargo + Go + Gem + Composer previews (dry-run); `.present` also tells us each project exists.
    let cargo_preview = build_cargo_outcome(common, false, true).await;
    let go_preview = build_go_outcome(common, false, true).await;
    let gem_preview = build_gem_outcome(common, false, true).await;
    let composer_preview = build_composer_outcome(common, false, true).await;

    if npm_files.is_empty()
        && py_plan.is_none()
        && !cargo_preview.present
        && !go_preview.present
        && !gem_preview.present
        && !composer_preview.present
    {
        if common.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "no_files",
                    "updated": 0,
                    "alreadyConfigured": 0,
                    "errors": 0,
                    "files": [],
                }))
                .unwrap()
            );
        } else {
            println!("No package.json, Python, Cargo, Go, Bundler, or Composer project found");
        }
        return 0;
    }

    let cargo_present = cargo_preview.present;
    let go_present = go_preview.present;
    let gem_present = gem_preview.present;
    let composer_present = composer_preview.present;
    let cargo_preview = merge_outcomes(
        merge_outcomes(merge_outcomes(cargo_preview, go_preview), gem_preview),
        composer_preview,
    );

    let npm_pm = detect_package_manager(&common.cwd).await;

    let telemetry_manager = telemetry_manager_str(
        !npm_files.is_empty(),
        py_plan.is_some(),
        cargo_present,
        go_present,
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

    if !common.json {
        print_setup_preview(&npm_preview, &py_preview, &cargo_preview, common);
    }

    let n_changes = npm_preview.iter().filter(|r| r.status == UpdateStatus::Updated).count()
        + py_preview.iter().filter(|r| r.status == PthStatus::Updated).count()
        + cargo_preview.changed;
    let preview_errors = npm_preview.iter().filter(|r| r.status == UpdateStatus::Error).count()
        + py_preview.iter().filter(|r| r.status == PthStatus::Error).count()
        + cargo_preview.errors;

    if n_changes == 0 {
        if common.json {
            print_setup_envelope(
                if preview_errors > 0 { "error" } else { "already_configured" },
                &npm_preview,
                &py_preview,
                &cargo_preview,
                npm_pm,
                py_plan.as_ref(),
                &[],
            );
        } else if preview_errors > 0 {
            println!("No hooks were changed; {preview_errors} item(s) could not be processed (see errors above).");
        } else {
            println!("All install hooks are already configured with socket-patch!");
        }
        return if preview_errors > 0 { 1 } else { 0 };
    }

    if common.dry_run {
        if common.json {
            print_setup_envelope(
                "dry_run",
                &npm_preview,
                &py_preview,
                &cargo_preview,
                npm_pm,
                py_plan.as_ref(),
                &[],
            );
        } else {
            println!("\nSummary (dry run):");
            println!("  {n_changes} item(s) would be updated");
        }
        return if preview_errors > 0 { 1 } else { 0 };
    }

    if !common.yes && !common.json {
        if !stdin_is_tty() {
            eprintln!("Non-interactive mode detected, proceeding automatically.");
        } else {
            print!("Proceed with these changes? (y/N): ");
            io::stdout().flush().unwrap();
            let mut answer = String::new();
            io::stdin().read_line(&mut answer).unwrap();
            let answer = answer.trim().to_lowercase();
            if answer != "y" && answer != "yes" {
                println!("Aborted");
                return 0;
            }
        }
    }

    if !common.json {
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
    // Real cargo + go + gem + composer edits (cargo guard dep/[env] root; go guard
    // package + per-main blank imports; gem Gemfile `plugin` block + generated
    // plugin dir; composer.json script-event command).
    let cargo_results = merge_outcomes(
        merge_outcomes(
            merge_outcomes(
                build_cargo_outcome(common, false, false).await,
                build_go_outcome(common, false, false).await,
            ),
            build_gem_outcome(common, false, false).await,
        ),
        build_composer_outcome(common, false, false).await,
    );

    // Materialise the go.mod `replace` redirects now so the first `go test`/run
    // is already in sync (the "automatic" step). Best-effort → warnings only.
    if go_present {
        warnings.extend(finalize_go(common).await);
    }
    // Materialise gem patches now so the first `bundle install` finds them
    // applied. Best-effort → warnings only.
    if gem_present {
        warnings.extend(finalize_gem(common).await);
    }

    let errors = npm_results.iter().filter(|r| r.status == UpdateStatus::Error).count()
        + py_results.iter().filter(|r| r.status == PthStatus::Error).count()
        + cargo_results.errors;

    if common.json {
        print_setup_envelope(
            if errors > 0 { "partial_failure" } else { "success" },
            &npm_results,
            &py_results,
            &cargo_results,
            npm_pm,
            py_plan.as_ref(),
            &warnings,
        );
    } else {
        let updated = npm_results.iter().filter(|r| r.status == UpdateStatus::Updated).count()
            + py_results.iter().filter(|r| r.status == PthStatus::Updated).count()
            + cargo_results.changed;
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
        if cargo_present {
            println!(
                "\nCommit Cargo.toml (socket-patch-guard), .cargo/config.toml, and your \
                 .socket/ patches so the guard re-applies cargo patches in CI."
            );
        }
        if go_present {
            println!(
                "\nCommit go.mod (the `replace` directives), internal/socketpatchguard/, the \
                 generated socket_patch_guard_import.go files, .socket/go-patches/, and your \
                 .socket/ patches. Enforcement: `go test ./...` gates at CI time (the guard \
                 reads the patch state in-process, so the test cache re-runs it on any drift), \
                 and the init() guard gates every `go run`/binary launch."
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

    if errors > 0 {
        1
    } else {
        0
    }
}

fn print_setup_preview(
    npm: &[UpdateResult],
    py: &[PthEditResult],
    cargo: &SetupOutcome,
    common: &GlobalArgs,
) {
    let npm_changes: Vec<_> = npm.iter().filter(|r| r.status == UpdateStatus::Updated).collect();
    let py_changes: Vec<_> = py.iter().filter(|r| r.status == PthStatus::Updated).collect();

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
    if !cargo.preview.is_empty() {
        println!();
        for line in &cargo.preview {
            println!("{line}");
        }
    }

    let npm_already = npm.iter().filter(|r| r.status == UpdateStatus::AlreadyConfigured).count();
    let py_already = py.iter().filter(|r| r.status == PthStatus::AlreadyConfigured).count();
    if npm_already + py_already + cargo.already > 0 {
        println!(
            "\nAlready configured (will skip): {}",
            npm_already + py_already + cargo.already
        );
    }

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
    errs.extend(outcome_error_messages(cargo));
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
    cargo: &SetupOutcome,
    npm_pm: PackageManager,
    py_plan: Option<&PythonPlan>,
    warnings: &[String],
) {
    let updated = npm.iter().filter(|r| r.status == UpdateStatus::Updated).count()
        + py.iter().filter(|r| r.status == PthStatus::Updated).count()
        + cargo.changed;
    let already = npm.iter().filter(|r| r.status == UpdateStatus::AlreadyConfigured).count()
        + py.iter().filter(|r| r.status == PthStatus::AlreadyConfigured).count()
        + cargo.already;
    let errors = npm.iter().filter(|r| r.status == UpdateStatus::Error).count()
        + py.iter().filter(|r| r.status == PthStatus::Error).count()
        + cargo.errors;

    let mut files: Vec<serde_json::Value> = npm
        .iter()
        .map(|r| {
            serde_json::json!({
                "kind": "package_json",
                "path": r.path,
                "status": update_status_str(&r.status),
                "error": r.error,
            })
        })
        .collect();
    files.extend(py.iter().map(|r| {
        serde_json::json!({
            "kind": "pth",
            "path": r.path,
            "status": pth_status_str(&r.status),
            "error": r.error,
        })
    }));
    files.extend(cargo.json_files.iter().cloned());

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
