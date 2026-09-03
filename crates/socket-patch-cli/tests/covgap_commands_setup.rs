//! Coverage-gap tests for `commands/setup.rs` (audit at d5e1815; the file is
//! unchanged since). Each section names the uncovered line ranges it drives.
//!
//! Everything here runs on the host with no Docker and no ecosystem
//! toolchain: `setup` edits package.json / requirements.txt / pyproject.toml /
//! Gemfile / composer.json directly. The gem/composer round trips mirror the
//! feature-gated `setup_matrix_{gem,composer}.rs` host guards, which the
//! default (non-`setup-e2e`) test configuration never compiles — these
//! always-on ports are what actually count for coverage.

use std::path::Path;

#[path = "common/mod.rs"]
mod common;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const UNWIRED_PACKAGE_JSON: &str = "{ \"name\": \"covgap\", \"version\": \"1.0.0\" }\n";

/// A package.json `setup` reports `already_configured` (the same wired form
/// `setup_check_tolerates_bom_like_npm` pins, minus the BOM).
const WIRED_SCRIPTS_FRAGMENT: &str = "\"scripts\":{\"postinstall\":\"npx @socketsecurity/socket-patch apply --silent --ecosystems npm\",\"dependencies\":\"npx @socketsecurity/socket-patch apply --silent --ecosystems npm\"}";

const GEMFILE_FIXTURE: &str = "source 'https://rubygems.org'\ngem 'colorize', '1.1.0'\n";

/// Same shape as the feature-gated composer matrix fixture: 4-space indented,
/// so the byte-for-byte restore assertion has real formatting to preserve.
const COMPOSER_JSON: &str =
    "{\n    \"name\": \"acme/widget\",\n    \"require\": {\n        \"monolog/monolog\": \"3.5.0\"\n    }\n}\n";

/// A Gemfile.lock as `bundle install` under bundler 1.17.3 writes it — the
/// deterministic lock-probe input for the bundler version floor (the probe
/// classifies from `BUNDLED WITH` before ever spawning `bundle`).
const LOCK_1X: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    \
                       colorize (1.1.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  \
                       colorize (= 1.1.0)\n\nBUNDLED WITH\n   1.17.3\n";

/// The supported-floor twin of [`LOCK_1X`]. Every fixture that wires (or
/// checks) a Gemfile pins the probe through this lock: without one on disk
/// the floor probe falls through to the host's real `bundle --version`, and
/// a machine whose first-on-PATH bundler is below the 2.2 floor (stock macOS
/// ships /usr/bin/bundle = 1.17.2) would make `setup` refuse to wire.
const LOCK_2X: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    \
                       colorize (1.1.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  \
                       colorize (= 1.1.0)\n\nBUNDLED WITH\n   2.5.22\n";

/// Classic-Poetry pyproject (no `[project]` table) — `detect_python_pm`
/// classifies `[tool.poetry]` as Poetry with no poetry.lock on disk, and
/// `add_hook_dependency` edits `[tool.poetry.dependencies]` (the same fixture
/// `setup_pth_invariants.rs` wires through its shims).
const POETRY_PYPROJECT: &str = "[tool.poetry]\nname = \"x\"\nversion = \"0.1.0\"\ndescription = \"\"\nauthors = []\n\n[tool.poetry.dependencies]\npython = \"^3.9\"\n";

const REQUIREMENTS_NO_HOOK: &str = "requests==2.31.0\n";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, content).expect("write file");
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read file")
}

/// Run the binary through the shared hermetic runner (`SOCKET_*` scrubbed,
/// telemetry disabled). Returns `(code, stdout, stderr)`.
fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    common::run_with_env(cwd, args, &[("SOCKET_TELEMETRY_DISABLED", "1")])
}

/// [`run`] + extra child-only env (e.g. a PATH override for the lockfile
/// refresh spawn). The parent process env is never mutated, so no
/// serialization is needed.
fn run_env(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut merged: Vec<(&str, &str)> = vec![("SOCKET_TELEMETRY_DISABLED", "1")];
    merged.extend_from_slice(env);
    common::run_with_env(cwd, args, &merged)
}

/// [`run`], asserting stdout is one JSON document.
fn run_json(cwd: &Path, args: &[&str]) -> (i32, serde_json::Value) {
    let (code, stdout, stderr) = run(cwd, args);
    let v = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout must be JSON ({e}); stdout=\n{stdout}\nstderr=\n{stderr}")
    });
    (code, v)
}

/// All `files[]` entries with the given `kind`.
fn entries_of<'a>(v: &'a serde_json::Value, kind: &str) -> Vec<&'a serde_json::Value> {
    v["files"]
        .as_array()
        .unwrap_or_else(|| panic!("files must be an array: {v}"))
        .iter()
        .filter(|f| f["kind"] == kind)
        .collect()
}

/// The single `files[]` entry with the given `kind` (panics on 0 or >1).
fn entry_of<'a>(v: &'a serde_json::Value, kind: &str) -> &'a serde_json::Value {
    let matches = entries_of(v, kind);
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one `{kind}` entry, got {}: {v}",
        matches.len()
    );
    matches[0]
}

/// Wire a fixture with `setup --yes --json`, asserting it succeeded.
fn wire(cwd: &Path) {
    let (code, v) = run_json(cwd, &["setup", "--yes", "--json"]);
    assert_eq!(code, 0, "fixture wiring must succeed: {v}");
    assert_eq!(v["status"], "success", "fixture wiring must succeed: {v}");
}

#[cfg(unix)]
fn running_as_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
}

#[cfg(unix)]
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

// ---------------------------------------------------------------------------
// Composer setup/check/remove round trip — always-on port of the
// feature-gated setup_matrix_composer host guard.
// Covers 59 (composer telemetry tag), 674, 678-702, 705-718, 721-729
// (build_composer_outcome add+remove, status vocabulary), 743, 746-757
// (append_composer_check_entries probe arms).
// ---------------------------------------------------------------------------

#[test]
fn composer_setup_check_remove_round_trip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("composer.json"), COMPOSER_JSON);

    // check (pristine): the composer entry needs configuration, exit 1.
    let (code, v) = run_json(cwd, &["setup", "--check", "--json"]);
    assert_eq!(code, 1, "pre-setup check must fail: {v}");
    assert_eq!(v["status"], "needs_configuration", "{v}");
    assert_eq!(entry_of(&v, "composer")["status"], "needs_configuration");

    // setup: wires the hook into both script events.
    let (code, v) = run_json(cwd, &["setup", "--yes", "--json"]);
    assert_eq!(code, 0, "composer setup must succeed: {v}");
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(v["updated"], 1, "{v}");
    assert_eq!(entry_of(&v, "composer")["status"], "updated");
    let wired: serde_json::Value =
        serde_json::from_str(&read(&cwd.join("composer.json"))).expect("valid composer.json");
    for event in ["post-install-cmd", "post-update-cmd"] {
        assert!(
            wired["scripts"][event]
                .as_array()
                .unwrap_or_else(|| panic!("{event} missing: {wired}"))
                .iter()
                .any(|c| c.as_str().is_some_and(|s| s.contains("socket-patch apply"))),
            "{event} must carry the re-apply command: {wired}"
        );
    }

    // idempotent second setup: already_configured.
    let (code, v) = run_json(cwd, &["setup", "--yes", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(v["status"], "already_configured", "{v}");
    assert_eq!(entry_of(&v, "composer")["status"], "already_configured");

    // check (wired): configured, exit 0.
    let (code, v) = run_json(cwd, &["setup", "--check", "--json"]);
    assert_eq!(code, 0, "post-setup check must pass: {v}");
    assert_eq!(entry_of(&v, "composer")["status"], "configured");

    // remove: strips the hook and restores composer.json byte-for-byte.
    let (code, v) = run_json(cwd, &["setup", "--remove", "--yes", "--json"]);
    assert_eq!(code, 0, "composer remove must succeed: {v}");
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(v["removed"], 1, "{v}");
    assert_eq!(entry_of(&v, "composer")["status"], "removed");
    assert_eq!(
        read(&cwd.join("composer.json")),
        COMPOSER_JSON,
        "remove must restore composer.json byte-for-byte"
    );

    // second remove: nothing left to unwire → not_configured.
    let (code, v) = run_json(cwd, &["setup", "--remove", "--yes", "--json"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["status"], "not_configured", "{v}");
    assert_eq!(entry_of(&v, "composer")["status"], "not_configured");

    // check (post-remove): needs configuration again.
    let (code, v) = run_json(cwd, &["setup", "--check", "--json"]);
    assert_eq!(code, 1, "post-remove check must fail again: {v}");
    assert_eq!(entry_of(&v, "composer")["status"], "needs_configuration");
}

// ---------------------------------------------------------------------------
// `--ecosystems` scope-outs.
// Covers 740 (composer scoped out of check), 822 (gem scoped out of check),
// and 117 (npm scoped out of discover).
// ---------------------------------------------------------------------------

#[test]
fn check_ecosystems_scopes_gem_and_composer_out() {
    // A gem+composer project checked with npm-only scope: both branches
    // return before probing, so no manifest at all is in scope → no_files.
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("Gemfile"), GEMFILE_FIXTURE);
    write(&cwd.join("composer.json"), COMPOSER_JSON);

    let (code, v) = run_json(cwd, &["setup", "--check", "--json", "--ecosystems", "npm"]);
    assert_eq!(code, 0, "nothing in scope must exit 0: {v}");
    assert_eq!(v["status"], "no_files", "{v}");
    assert!(
        v["files"].as_array().is_some_and(|a| a.is_empty()),
        "no entry may leak past the scope filter: {v}"
    );
}

#[test]
fn check_ecosystems_scopes_npm_out() {
    // npm OUT of scope (the reverse of setup_contract_gaps'
    // `setup_ecosystems_filter_scopes_work_to_named_ecosystem`): discover()
    // must return empty without walking, leaving only the pth entry.
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("package.json"), UNWIRED_PACKAGE_JSON);
    write(&cwd.join("requirements.txt"), REQUIREMENTS_NO_HOOK);

    let (code, v) = run_json(cwd, &["setup", "--check", "--json", "--ecosystems", "pypi"]);
    assert_eq!(code, 1, "the unwired pth entry must fail the check: {v}");
    let files = v["files"].as_array().expect("files[]");
    assert_eq!(files.len(), 1, "only the pth entry may appear: {v}");
    assert_eq!(files[0]["kind"], "pth", "{v}");

    // And a real scoped run must leave the out-of-scope package.json alone.
    let (code, v) = run_json(cwd, &["setup", "--yes", "--json", "--ecosystems", "pypi"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(
        read(&cwd.join("package.json")),
        UNWIRED_PACKAGE_JSON,
        "`--ecosystems pypi` must not touch package.json"
    );
    assert!(
        read(&cwd.join("requirements.txt")).contains("socket-patch[hook]"),
        "the in-scope python manifest must be wired"
    );
}

// ---------------------------------------------------------------------------
// Gem check + remove round trip and the bundler version floor — always-on
// port of the feature-gated setup_matrix_gem host guards.
// Covers 613, 625-626, 647, 655-658 (remove path + gem_status_str), 825,
// 836-858 (probe arms incl. the Unsupported wired/unwired errors), 863-875
// (gemfile + gem_plugin check entries).
// ---------------------------------------------------------------------------

#[test]
fn gem_check_setup_remove_round_trip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("Gemfile"), GEMFILE_FIXTURE);
    write(&cwd.join("Gemfile.lock"), LOCK_2X);

    // check (pristine): Gemfile + plugin dir both need configuration.
    let (code, v) = run_json(cwd, &["setup", "--check", "--json"]);
    assert_eq!(code, 1, "pre-setup gem check must fail: {v}");
    assert_eq!(entry_of(&v, "gemfile")["status"], "needs_configuration");
    assert_eq!(entry_of(&v, "gem_plugin")["status"], "needs_configuration");
    assert_eq!(v["needsConfiguration"], 2, "{v}");

    wire(cwd);
    assert!(
        read(&cwd.join("Gemfile")).contains("plugin 'socket-patch'"),
        "setup must wire the plugin directive"
    );

    // check (wired): both entries configured, exit 0.
    let (code, v) = run_json(cwd, &["setup", "--check", "--json"]);
    assert_eq!(code, 0, "post-setup gem check must pass: {v}");
    assert_eq!(entry_of(&v, "gemfile")["status"], "configured");
    assert_eq!(entry_of(&v, "gem_plugin")["status"], "configured");

    // remove: Gemfile restored byte-for-byte, plugin dir deleted.
    let (code, v) = run_json(cwd, &["setup", "--remove", "--yes", "--json"]);
    assert_eq!(code, 0, "gem remove must succeed: {v}");
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(entry_of(&v, "gemfile")["status"], "removed");
    assert_eq!(entry_of(&v, "gem_plugin")["status"], "removed");
    assert_eq!(
        read(&cwd.join("Gemfile")),
        GEMFILE_FIXTURE,
        "remove must restore the Gemfile byte-for-byte"
    );
    assert!(
        !cwd.join(".socket/bundler-plugin").exists(),
        "remove must delete the generated plugin dir"
    );

    // second remove: nothing wired → not_configured vocabulary.
    let (code, v) = run_json(cwd, &["setup", "--remove", "--yes", "--json"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["status"], "not_configured", "{v}");
    assert_eq!(entry_of(&v, "gemfile")["status"], "not_configured");
    assert_eq!(entry_of(&v, "gem_plugin")["status"], "not_configured");
}

#[test]
fn gem_check_bundler_1x_lock_unwired_reports_error() {
    // The lock probe (`BUNDLED WITH 1.17.3`) classifies without spawning
    // bundler, so this is deterministic on every host. An UNWIRED project
    // below the floor is an error (running `setup` cannot help — it refuses
    // to wire), not needs_configuration.
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("Gemfile"), GEMFILE_FIXTURE);
    write(&cwd.join("Gemfile.lock"), LOCK_1X);

    let (code, v) = run_json(cwd, &["setup", "--check", "--json"]);
    assert_eq!(code, 1, "an unsupported bundler must fail the check: {v}");
    assert_eq!(v["status"], "error", "{v}");
    let gemfile = entry_of(&v, "gemfile");
    assert_eq!(gemfile["status"], "error", "{v}");
    let err = gemfile["error"].as_str().expect("gemfile error message");
    assert!(
        err.contains("1.17.3") && err.contains(">= 2.2"),
        "the error must name the detected bundler and the floor: {err}"
    );
    assert!(
        err.contains("cannot load the socket-patch Bundler plugin"),
        "the error must explain WHY the floor exists: {err}"
    );
}

#[test]
fn gem_check_bundler_1x_lock_wired_points_at_remove() {
    // Wire under a supported 2.x lock, then downgrade the lock to bundler
    // 1.x: `--check` must red-flag the WIRED project and point at
    // `setup --remove` as the way out.
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("Gemfile"), GEMFILE_FIXTURE);
    write(&cwd.join("Gemfile.lock"), LOCK_2X);
    wire(cwd);
    write(&cwd.join("Gemfile.lock"), LOCK_1X);

    let (code, v) = run_json(cwd, &["setup", "--check", "--json"]);
    assert_eq!(code, 1, "wired-below-floor must fail the check: {v}");
    let gemfile = entry_of(&v, "gemfile");
    assert_eq!(gemfile["status"], "error", "{v}");
    let err = gemfile["error"].as_str().expect("gemfile error message");
    assert!(
        err.contains("setup --remove") && err.contains("unwire"),
        "the wired-project error must name the unwire recovery: {err}"
    );
    assert!(err.contains("1.17.3"), "must name the detected version: {err}");
    // The plugin dir was still generated by the wiring; its entry stays
    // independent of the version gate.
    assert_eq!(entry_of(&v, "gem_plugin")["status"], "configured");
}

#[cfg(unix)]
#[test]
fn gem_check_unreadable_gemfile_reports_error() {
    // Covers 861: the Gemfile read error arm of append_gem_check_entries.
    if running_as_root() {
        eprintln!("SKIP: root bypasses file permission checks");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("Gemfile"), GEMFILE_FIXTURE);
    write(&cwd.join("Gemfile.lock"), LOCK_2X);
    wire(cwd);
    chmod(&cwd.join("Gemfile"), 0o000);

    let (code, v) = run_json(cwd, &["setup", "--check", "--json"]);
    chmod(&cwd.join("Gemfile"), 0o644);

    assert_eq!(code, 1, "an unreadable Gemfile must fail the check: {v}");
    let gemfile = entry_of(&v, "gemfile");
    assert_eq!(gemfile["status"], "error", "{v}");
    assert!(
        gemfile["error"].as_str().is_some_and(|e| !e.is_empty()),
        "the io error must be carried on the entry: {v}"
    );
}

// ---------------------------------------------------------------------------
// Property 7 — the on-disk hook probe (`configured_ecosystems`) positive
// inserts. Every e2e_vex fixture opts in via `setup.manual`; here the
// manifest declares NO manual ecosystems, so a statement can only exist
// because the probe found the hook wired on disk.
// Covers 359-362 (npm), 374-377 (pypi), 385-387 (gem), 391-395 (composer).
// ---------------------------------------------------------------------------

/// One patch record per ecosystem, mirroring e2e_vex's `make_record`.
fn covgap_patch_manifest() -> socket_patch_core::manifest::schema::PatchManifest {
    use socket_patch_core::manifest::schema::{
        PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo,
    };
    use std::collections::HashMap;

    let cases: &[(&str, &str, &str)] = &[
        ("pkg:npm/left-pad@1.3.0", "GHSA-cov-npm", "11111111-1111-4111-8111-111111111111"),
        ("pkg:pypi/six@1.16.0", "GHSA-cov-pypi", "22222222-2222-4222-8222-222222222222"),
        ("pkg:gem/rack@2.2.3", "GHSA-cov-gem", "33333333-3333-4333-8333-333333333333"),
        (
            "pkg:composer/monolog/monolog@2.0.0",
            "GHSA-cov-composer",
            "44444444-4444-4444-8444-444444444444",
        ),
    ];
    let mut manifest = PatchManifest::new();
    for (purl, ghsa, uuid) in cases {
        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: "a".repeat(64),
                after_hash: "b".repeat(64),
            },
        );
        let mut vulns = HashMap::new();
        vulns.insert(
            (*ghsa).to_string(),
            VulnerabilityInfo {
                cves: vec!["CVE-2024-1".to_string()],
                summary: "s".to_string(),
                severity: "high".to_string(),
                description: "d".to_string(),
            },
        );
        manifest.patches.insert(
            (*purl).to_string(),
            PatchRecord {
                uuid: (*uuid).to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files,
                vulnerabilities: vulns,
                description: format!("Patch {uuid}"),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            },
        );
    }
    manifest
}

/// Write the 4-ecosystem patch manifest with NO `setup` block — i.e. zero
/// `manual` declarations, so only the on-disk probe can admit a patch.
fn write_covgap_manifest(cwd: &Path) {
    let manifest = covgap_patch_manifest();
    write(
        &cwd.join(".socket/manifest.json"),
        &serde_json::to_string_pretty(&manifest).expect("serialize manifest"),
    );
}

#[test]
fn vex_attests_ecosystems_wired_on_disk_without_manual() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("package.json"), UNWIRED_PACKAGE_JSON);
    write(&cwd.join("requirements.txt"), REQUIREMENTS_NO_HOOK);
    write(&cwd.join("Gemfile"), GEMFILE_FIXTURE);
    write(&cwd.join("Gemfile.lock"), LOCK_2X);
    write(&cwd.join("composer.json"), COMPOSER_JSON);
    // Wire all four hooks on disk with a real setup run.
    wire(cwd);
    write_covgap_manifest(cwd);

    let (code, stdout, stderr) = run(
        cwd,
        &["vex", "--no-verify", "--product", "pkg:npm/app@1.0.0"],
    );
    assert_eq!(
        code, 0,
        "all four wired ecosystems must attest; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let doc: serde_json::Value = serde_json::from_str(&stdout).expect("VEX JSON on stdout");
    let stmts = doc["statements"].as_array().expect("statements[]");
    assert_eq!(
        stmts.len(),
        4,
        "one statement per wired ecosystem (npm/pypi/gem/composer): {doc}"
    );
    for purl in [
        "pkg:npm/left-pad@1.3.0",
        "pkg:pypi/six@1.16.0",
        "pkg:gem/rack@2.2.3",
        "pkg:composer/monolog/monolog@2.0.0",
    ] {
        assert!(
            stmts
                .iter()
                .any(|s| s["products"][0]["subcomponents"][0]["@id"] == purl),
            "missing statement for {purl}: {doc}"
        );
    }
}

#[test]
fn vex_drops_all_patches_when_projects_present_but_unwired() {
    // Negative control for the probe: the SAME four project manifests exist
    // but no hook is wired and no `manual` is declared, so every patch must
    // be filtered — proving the positive test's statements came from the
    // probe, not from project presence.
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("package.json"), UNWIRED_PACKAGE_JSON);
    write(&cwd.join("requirements.txt"), REQUIREMENTS_NO_HOOK);
    write(&cwd.join("Gemfile"), GEMFILE_FIXTURE);
    write(&cwd.join("composer.json"), COMPOSER_JSON);
    write_covgap_manifest(cwd);

    let out = cwd.join("out.json");
    let (code, stdout, _stderr) = run(
        cwd,
        &[
            "vex",
            "--no-verify",
            "--product",
            "pkg:npm/app@1.0.0",
            "--output",
            out.to_str().unwrap(),
        ],
    );
    let statements = std::fs::read_to_string(&out)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v["statements"].as_array().map(|a| a.len()))
        .unwrap_or(0);
    assert_eq!(
        statements, 0,
        "unwired ecosystems must not attest (property 7); stdout=\n{stdout}"
    );
    assert_eq!(
        code, 1,
        "with every patch filtered, vex must report no-applicable-patches; stdout=\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// confirm_proceed's non-TTY branch (180-181): piped stdin, no --yes, no
// --json — the normal CI shape. Auto-proceeds with a stderr note.
// ---------------------------------------------------------------------------

#[test]
fn setup_non_tty_auto_proceeds_without_yes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("package.json"), UNWIRED_PACKAGE_JSON);

    // `Command::output()` (inside the shared runner) closes the child's
    // stdin, so stdin_is_tty() is false.
    let (code, stdout, stderr) = run(cwd, &["setup"]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("Non-interactive mode detected, proceeding automatically."),
        "the auto-proceed note must reach stderr; stderr=\n{stderr}"
    );
    assert!(
        stdout.contains("Summary:"),
        "the run must have proceeded to the summary; stdout=\n{stdout}"
    );
    assert!(
        read(&cwd.join("package.json")).contains("socket-patch"),
        "the non-TTY run must actually wire the hook"
    );
}

#[test]
fn setup_non_tty_auto_proceed_note_prints_under_silent() {
    // Documents the CURRENT contract: `--silent` mutes the human report but
    // prompting (and therefore the non-TTY auto-proceed note) follows the
    // shared confirm semantics unchanged — the note still reaches stderr.
    // If the contract is later tightened to mute it, flip this assertion.
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("package.json"), UNWIRED_PACKAGE_JSON);

    let (code, stdout, stderr) = run(cwd, &["setup", "--silent"]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.trim().is_empty(),
        "--silent must mute stdout; got: {stdout:?}"
    );
    assert!(
        stderr.contains("Non-interactive mode detected"),
        "current contract: the auto-proceed note is confirm-flow output, not \
         muted by --silent; stderr=\n{stderr}"
    );
    assert!(
        read(&cwd.join("package.json")).contains("socket-patch"),
        "the silent non-TTY run must still wire the hook"
    );
}

// ---------------------------------------------------------------------------
// `setup --remove` interactive decline (1237-1238) — the remove twin of
// interactive_prompts_e2e's setup abort, driven through a PTY.
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod pty {
    use std::io::{Read, Write};
    use std::path::Path;
    use std::time::Duration;

    use portable_pty::{native_pty_system, CommandBuilder, PtySize};

    /// Trimmed copy of interactive_prompts_e2e's PTY runner (that file is a
    /// separate test binary, so its helper cannot be imported): spawn the
    /// binary in a PTY with the SOCKET_* env scrubbed, send `input`, collect
    /// output until exit. A watchdog kills the child after `timeout`.
    pub fn run_in_pty(args: &[&str], cwd: &Path, input: &str, timeout: Duration) -> (i32, String) {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("openpty");

        let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_socket-patch"));
        for a in args {
            cmd.arg(a);
        }
        cmd.cwd(cwd);
        for (key, _) in std::env::vars_os() {
            let name = key.to_string_lossy();
            if name.starts_with("SOCKET_")
                && !name.contains("TELEMETRY")
                && name != "SOCKET_NO_CONFIG"
                && name != "SOCKET_NO_UPDATE_CHECK"
            {
                cmd.env_remove(&key);
            }
        }
        // PTY children have a real terminal on stderr; force the notifier
        // kill-switch like the sibling suite does.
        cmd.env("SOCKET_NO_UPDATE_CHECK", "1");

        let mut child = pair.slave.spawn_command(cmd).expect("spawn in PTY");
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().expect("clone reader");
        let reader_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = reader.read_to_end(&mut buf);
            buf
        });

        let mut killer = child.clone_killer();
        std::thread::spawn(move || {
            std::thread::sleep(timeout);
            let _ = killer.kill();
        });

        let mut writer = pair.master.take_writer().expect("take writer");
        let _ = writer.write_all(input.as_bytes());
        let _ = writer.flush();
        drop(writer);

        let status = child.wait().expect("child.wait");
        drop(pair.master);
        let output = reader_handle.join().expect("reader join");
        (
            status.exit_code() as i32,
            String::from_utf8_lossy(&output).to_string(),
        )
    }
}

#[cfg(unix)]
#[test]
fn remove_interactive_decline_aborts_without_change() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("package.json"), UNWIRED_PACKAGE_JSON);
    wire(cwd);
    let wired = read(&cwd.join("package.json"));

    let (code, output) = pty::run_in_pty(
        &["setup", "--remove"],
        cwd,
        "n\n",
        std::time::Duration::from_secs(15),
    );
    assert_eq!(code, 0, "declining the remove must exit cleanly; got: {output}");
    assert!(
        output.contains("Remove these install hooks? (y/N):"),
        "the interactive remove confirm must have been shown; got: {output}"
    );
    assert!(
        !output.contains("Non-interactive mode detected"),
        "a PTY child must take the interactive branch; got: {output}"
    );
    assert!(
        output.contains("Aborted"),
        "declining must print the abort message; got: {output}"
    );
    assert!(
        !output.contains("Removing changes..."),
        "declining must abort before mutating; got: {output}"
    );
    assert_eq!(
        read(&cwd.join("package.json")),
        wired,
        "the wired package.json must be untouched after the decline"
    );
}

// ---------------------------------------------------------------------------
// persist_setup_excludes' already-persisted no-rewrite branch (323): a
// flag-less rerun whose effective excludes equal the persisted set must not
// rewrite .socket/manifest.json (the byte-stability the doc comment
// promises). Detected via a cosmetic (JSON-equivalent) formatting marker
// that any rewrite would normalize away.
// ---------------------------------------------------------------------------

#[test]
fn exclude_already_persisted_skips_manifest_rewrite() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(
        &cwd.join("package.json"),
        r#"{ "name": "root", "workspaces": ["packages/*"] }"#,
    );
    write(&cwd.join("packages/a/package.json"), UNWIRED_PACKAGE_JSON);
    write(&cwd.join("packages/b/package.json"), UNWIRED_PACKAGE_JSON);

    let (code, v) = run_json(cwd, &["setup", "--yes", "--json", "--exclude", "packages/a"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["status"], "success", "{v}");
    let manifest_path = cwd.join(".socket/manifest.json");
    let persisted = read(&manifest_path);
    assert!(
        persisted.contains("packages/a"),
        "the exclude must be persisted: {persisted}"
    );

    // Cosmetic marker: trailing whitespace is JSON-equivalent, so a re-read
    // still parses the same set — but a rewrite (serde pretty-print) would
    // drop it. If the no-rewrite branch regresses, the marker vanishes.
    let marked = format!("{persisted}\n \n");
    write(&manifest_path, &marked);

    let (code, v) = run_json(cwd, &["setup", "--yes", "--json"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(
        read(&manifest_path),
        marked,
        "a rerun whose excludes are already persisted exactly must not \
         rewrite the manifest"
    );
    // The persisted exclusion still holds without the flag.
    let files = v["files"].as_array().expect("files[]");
    assert!(
        !files
            .iter()
            .any(|f| f["path"].as_str().is_some_and(|p| p.contains("packages/a"))),
        "the persisted exclude must keep packages/a out of the run: {v}"
    );
}

// ---------------------------------------------------------------------------
// Python edge matrix.
// ---------------------------------------------------------------------------

/// Covers 463: pip project with neither requirements.txt nor pyproject —
/// setup creates requirements.txt carrying the hook.
#[test]
fn setup_pip_from_scratch_creates_requirements() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("setup.py"), "from setuptools import setup\nsetup()\n");

    let (code, v) = run_json(cwd, &["setup", "--yes", "--json"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(v["pythonPackageManager"], "pip", "{v}");
    let pth = entry_of(&v, "pth");
    assert_eq!(pth["status"], "updated", "{v}");
    assert!(
        pth["path"]
            .as_str()
            .is_some_and(|p| p.ends_with("requirements.txt")),
        "{v}"
    );
    let created = read(&cwd.join("requirements.txt"));
    assert!(
        created.contains("socket-patch[hook]"),
        "the created requirements.txt must carry the hook dep; got:\n{created}"
    );
    // The user's own file is untouched.
    assert!(
        read(&cwd.join("setup.py")).starts_with("from setuptools"),
        "setup.py must not be modified"
    );
}

/// Covers 452 + 479: a pyproject-based manager (uv, detected from a bare
/// uv.lock) with no pyproject.toml has nothing to edit → the whole run is
/// `no_files` (the partial-checkout shape).
#[test]
fn setup_uv_lock_without_pyproject_reports_no_files() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("uv.lock"), "version = 1\n");

    let (code, v) = run_json(cwd, &["setup", "--yes", "--json"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["status"], "no_files", "{v}");
    assert_eq!(v["updated"], 0, "{v}");
    assert_eq!(v["alreadyConfigured"], 0, "{v}");
    assert_eq!(v["errors"], 0, "{v}");
    assert!(v["files"].as_array().is_some_and(|a| a.is_empty()), "{v}");
    // Nothing conjured on disk either.
    assert!(!cwd.join("pyproject.toml").exists());
    assert!(!cwd.join("requirements.txt").exists());
}

/// Covers 510: when the python manifest is already configured and only
/// ANOTHER ecosystem changed, finalize_python must return before the lock
/// refresh. The empty PATH makes the guard sharp: a regression that reaches
/// the refresh spawns `poetry`, fails to find it, and surfaces a warning.
#[test]
fn setup_python_already_configured_skips_lock_refresh() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("pyproject.toml"), POETRY_PYPROJECT);
    wire(cwd); // wires the poetry hook (no poetry.lock yet → no refresh)

    // Now a lockfile exists and an npm manifest still needs wiring.
    write(&cwd.join("poetry.lock"), "# stub lock\n");
    write(&cwd.join("package.json"), UNWIRED_PACKAGE_JSON);
    let empty = tempfile::tempdir().expect("empty PATH dir");
    let (code, stdout, stderr) = run_env(
        cwd,
        &["setup", "--yes", "--json"],
        &[("PATH", empty.path().to_str().unwrap())],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(entry_of(&v, "package_json")["status"], "updated", "{v}");
    assert_eq!(entry_of(&v, "pth")["status"], "already_configured", "{v}");
    assert!(
        v.get("warnings").is_none(),
        "an unchanged python manifest must skip the lock refresh entirely \
         (no `poetry` spawn, no warning): {v}"
    );
}

/// Covers 565: a Poetry project (detected via [tool.poetry]) with NO
/// poetry.lock — setup edits the manifest and must not attempt (or warn
/// about) a lock refresh. Empty PATH again makes a regression observable.
#[test]
fn setup_poetry_without_lock_skips_refresh() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("pyproject.toml"), POETRY_PYPROJECT);

    let empty = tempfile::tempdir().expect("empty PATH dir");
    let (code, stdout, stderr) = run_env(
        cwd,
        &["setup", "--yes", "--json"],
        &[("PATH", empty.path().to_str().unwrap())],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(v["pythonPackageManager"], "poetry", "{v}");
    assert_eq!(entry_of(&v, "pth")["status"], "updated", "{v}");
    assert!(
        v.get("warnings").is_none(),
        "no poetry.lock on disk → no refresh attempt, no warning: {v}"
    );
    assert!(
        read(&cwd.join("pyproject.toml")).contains("socket-patch"),
        "the manifest edit itself must still happen"
    );
}

/// Covers 1000 (manifest present without the hook → needs_configuration) and
/// 1005-1006 (pip with no requirements.txt yet → NotFound → needs_configuration).
#[test]
fn check_python_states_without_hook_and_missing_requirements() {
    // (i) requirements.txt present, hook absent.
    let a = tempfile::tempdir().expect("tempdir");
    write(&a.path().join("requirements.txt"), REQUIREMENTS_NO_HOOK);
    let (code, v) = run_json(a.path(), &["setup", "--check", "--json"]);
    assert_eq!(code, 1, "{v}");
    assert_eq!(v["status"], "needs_configuration", "{v}");
    assert_eq!(entry_of(&v, "pth")["status"], "needs_configuration", "{v}");

    // (ii) python project (setup.py) whose requirements.txt does not exist
    // yet: the NotFound arm for Requirements is "simply needs setup".
    let b = tempfile::tempdir().expect("tempdir");
    write(&b.path().join("setup.py"), "from setuptools import setup\nsetup()\n");
    let (code, v) = run_json(b.path(), &["setup", "--check", "--json"]);
    assert_eq!(code, 1, "{v}");
    let pth = entry_of(&v, "pth");
    assert_eq!(pth["status"], "needs_configuration", "{v}");
    assert!(
        pth["path"]
            .as_str()
            .is_some_and(|p| p.ends_with("requirements.txt")),
        "the not-yet-created requirements.txt is the manifest to create: {v}"
    );
    assert!(pth["error"].is_null(), "NotFound-for-Requirements is not an error: {v}");
}

/// Covers 1009: an unreadable python manifest is a check ERROR (distinct from
/// the NotFound arm above).
#[cfg(unix)]
#[test]
fn check_unreadable_python_manifest_reports_error() {
    if running_as_root() {
        eprintln!("SKIP: root bypasses file permission checks");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("requirements.txt"), REQUIREMENTS_NO_HOOK);
    chmod(&cwd.join("requirements.txt"), 0o000);

    let (code, v) = run_json(cwd, &["setup", "--check", "--json"]);
    chmod(&cwd.join("requirements.txt"), 0o644);

    assert_eq!(code, 1, "{v}");
    assert_eq!(v["status"], "error", "{v}");
    let pth = entry_of(&v, "pth");
    assert_eq!(pth["status"], "error", "{v}");
    assert!(
        pth["error"].as_str().is_some_and(|e| !e.is_empty()),
        "the io error must be carried on the entry: {v}"
    );
}

/// Covers 1903: setup --json on an unreadable python manifest — the pth
/// files[] entry carries status "error" inside the error envelope.
#[cfg(unix)]
#[test]
fn setup_json_unreadable_python_manifest_error_envelope() {
    if running_as_root() {
        eprintln!("SKIP: root bypasses file permission checks");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("requirements.txt"), REQUIREMENTS_NO_HOOK);
    chmod(&cwd.join("requirements.txt"), 0o000);

    let (code, v) = run_json(cwd, &["setup", "--yes", "--json"]);
    chmod(&cwd.join("requirements.txt"), 0o644);

    assert_eq!(code, 1, "an unprocessable manifest must exit 1: {v}");
    assert_eq!(v["status"], "error", "{v}");
    assert_eq!(v["errors"], 1, "{v}");
    let pth = entry_of(&v, "pth");
    assert_eq!(pth["status"], "error", "{v}");
    assert!(pth["error"].is_string(), "{v}");
}

// ---------------------------------------------------------------------------
// `--check` needs/error rendering (1067, 1081, 1083, 1091-1094, 988).
// ---------------------------------------------------------------------------

fn mixed_needs_error_fixture() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(
        &tmp.path().join("package.json"),
        r#"{ "name": "root", "workspaces": ["packages/*"] }"#,
    );
    write(&tmp.path().join("packages/bad/package.json"), "{");
    tmp
}

#[test]
fn check_human_report_renders_needs_and_error_lines() {
    let tmp = mixed_needs_error_fixture();
    let (code, stdout, _stderr) = run(tmp.path(), &["setup", "--check"]);
    assert_eq!(code, 1, "stdout=\n{stdout}");
    assert!(
        stdout.contains("✗ package.json (needs setup)"),
        "the unconfigured root must render as ✗ needs-setup; stdout=\n{stdout}"
    );
    // The relative path renders via Path::display(), which uses `\` on
    // Windows — normalize so the assertion is separator-agnostic.
    let stdout_norm = stdout.replace('\\', "/");
    assert!(
        stdout_norm.contains("! packages/bad/package.json: Invalid package.json"),
        "the unparseable member must render its error; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains(
            "1 manifest(s) need configuration, 1 error(s). Run `socket-patch setup` to fix."
        ),
        "the summary must count needs and errors; stdout=\n{stdout}"
    );
}

#[test]
fn check_json_mixed_needs_and_error_status() {
    let tmp = mixed_needs_error_fixture();
    let (code, v) = run_json(tmp.path(), &["setup", "--check", "--json"]);
    assert_eq!(code, 1, "{v}");
    assert_eq!(v["status"], "error", "errors dominate the status: {v}");
    assert_eq!(v["needsConfiguration"], 1, "{v}");
    assert_eq!(v["errors"], 1, "{v}");
    let statuses: Vec<&str> = entries_of(&v, "package_json")
        .iter()
        .filter_map(|f| f["status"].as_str())
        .collect();
    assert!(
        statuses.contains(&"needs_configuration") && statuses.contains(&"error"),
        "both per-file states must be rendered: {v}"
    );
}

/// Covers 988: an unreadable package.json in `--check` carries the io error
/// (PermissionDenied — distinct from the invalid-JSON arm above).
#[cfg(unix)]
#[test]
fn check_json_unreadable_package_json_reports_io_error() {
    if running_as_root() {
        eprintln!("SKIP: root bypasses file permission checks");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    write(
        &tmp.path().join("package.json"),
        r#"{ "name": "root", "workspaces": ["packages/*"] }"#,
    );
    let locked = tmp.path().join("packages/locked/package.json");
    write(&locked, UNWIRED_PACKAGE_JSON);
    chmod(&locked, 0o000);

    let (code, v) = run_json(tmp.path(), &["setup", "--check", "--json"]);
    chmod(&locked, 0o644);

    assert_eq!(code, 1, "{v}");
    assert_eq!(v["status"], "error", "{v}");
    let entry = entries_of(&v, "package_json")
        .into_iter()
        .find(|f| f["path"].as_str().is_some_and(|p| p.contains("locked")))
        .unwrap_or_else(|| panic!("no entry for the locked member: {v}"));
    assert_eq!(entry["status"], "error", "{v}");
    assert!(
        entry["error"].as_str().is_some_and(|e| e.contains("denied")),
        "the entry must carry the read error, not the JSON-parse one: {v}"
    );
}

// ---------------------------------------------------------------------------
// `setup --remove` human/json outcome matrix.
// ---------------------------------------------------------------------------

/// Covers 1210-1211: the most common interactive remove outcome — nothing
/// wired, human mode.
#[test]
fn remove_human_nothing_wired_message() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(&tmp.path().join("package.json"), UNWIRED_PACKAGE_JSON);

    let (code, stdout, _stderr) = run(tmp.path(), &["setup", "--remove", "--yes"]);
    assert_eq!(code, 0, "stdout=\n{stdout}");
    assert!(
        stdout.contains("No socket-patch install hooks found to remove."),
        "human mode must say nothing was wired; stdout=\n{stdout}"
    );
}

/// Covers 1225-1227 (human dry-run remove summary) and 1124-1125 (BOTH
/// render_removed arms: a restored pre-existing script renders quoted, a
/// deleted key renders `(removed)`).
#[test]
fn remove_human_dry_run_summary_renders_both_removed_forms() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    // A pre-existing postinstall so removal RESTORES it (Some arm); the
    // dependencies script is setup's own, so removal DELETES it (None arm).
    write(
        &cwd.join("package.json"),
        r#"{ "name": "x", "scripts": { "postinstall": "echo hi" } }"#,
    );
    wire(cwd);
    let wired = read(&cwd.join("package.json"));

    let (code, stdout, _stderr) = run(cwd, &["setup", "--remove", "--dry-run"]);
    assert_eq!(code, 0, "stdout=\n{stdout}");
    assert!(
        stdout.contains("Will remove socket-patch from:"),
        "the remove preview header must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("-> postinstall: \"echo hi\""),
        "a restored user script must render quoted; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("-> dependencies: (removed)"),
        "a deleted lifecycle key must render as (removed); stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("1 item(s) would have socket-patch removed"),
        "the human dry-run summary must count the pending removals; stdout=\n{stdout}"
    );
    assert_eq!(
        read(&cwd.join("package.json")),
        wired,
        "--dry-run must not modify the file"
    );
}

/// Covers the human remove preview sections for python (1426-1430) and
/// gem/composer (1432-1436), the pip uninstall hint (1302), and the Bundler
/// reversal note (1305-1308) — a real (non-dry-run) human remove across
/// npm + python + gem + composer.
#[test]
fn remove_human_real_run_prints_python_gem_composer_sections() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("package.json"), UNWIRED_PACKAGE_JSON);
    write(&cwd.join("requirements.txt"), REQUIREMENTS_NO_HOOK);
    write(&cwd.join("Gemfile"), GEMFILE_FIXTURE);
    write(&cwd.join("Gemfile.lock"), LOCK_2X);
    write(&cwd.join("composer.json"), COMPOSER_JSON);
    wire(cwd);

    let (code, stdout, stderr) = run(cwd, &["setup", "--remove", "--yes"]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains("Will remove the socket-patch-hook dependency from:"),
        "the python remove preview section must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Gem: remove the socket-patch Bundler plugin wiring from:"),
        "the gem remove preview lines must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Composer: remove the socket-patch re-apply hook from:"),
        "the composer remove preview lines must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Also run `pip uninstall socket-patch-hook`"),
        "the post-remove pip hint must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("the Bundler plugin wiring was removed"),
        "the Bundler reversal note must print; stdout=\n{stdout}"
    );
    // The removal really happened on every manifest.
    assert_eq!(read(&cwd.join("Gemfile")), GEMFILE_FIXTURE);
    assert_eq!(read(&cwd.join("composer.json")), COMPOSER_JSON);
    assert!(!read(&cwd.join("package.json")).contains("socket-patch"));
    assert!(!read(&cwd.join("requirements.txt")).contains("socket-patch"));
}

/// Covers 1197: remove --json when nothing is removable AND the preview
/// errored → status "error", exit 1.
#[cfg(unix)]
#[test]
fn remove_json_preview_stage_unreadable_reports_error_status() {
    if running_as_root() {
        eprintln!("SKIP: root bypasses file permission checks");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("package.json"), UNWIRED_PACKAGE_JSON);
    chmod(&cwd.join("package.json"), 0o000);

    let (code, v) = run_json(cwd, &["setup", "--remove", "--yes", "--json"]);
    chmod(&cwd.join("package.json"), 0o644);

    assert_eq!(code, 1, "{v}");
    assert_eq!(v["status"], "error", "{v}");
    assert_eq!(v["removed"], 0, "{v}");
    assert_eq!(v["errors"], 1, "{v}");
    assert_eq!(entry_of(&v, "package_json")["status"], "error", "{v}");
}

/// Covers 1296 + 1318: human remove whose write stage fails (clean preview,
/// unwritable directory) → "N error(s)" and exit 1.
#[cfg(unix)]
#[test]
fn remove_human_write_stage_error_counts_and_exits_nonzero() {
    if running_as_root() {
        eprintln!("SKIP: root bypasses directory permission checks");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("package.json"), UNWIRED_PACKAGE_JSON);
    wire(cwd);
    chmod(cwd, 0o555);

    let (code, stdout, _stderr) = run(cwd, &["setup", "--remove", "--yes"]);
    chmod(cwd, 0o755);

    assert_eq!(code, 1, "a failed write must exit 1; stdout=\n{stdout}");
    assert!(
        stdout.contains("1 error(s)"),
        "the human summary must count the write failure; stdout=\n{stdout}"
    );
    assert!(
        read(&cwd.join("package.json")).contains("socket-patch"),
        "the hook must still be wired after the failed write"
    );
}

/// Covers 1274 + 1488: the --json twin — status partial_failure with the
/// npm files[] entry carrying status "error".
#[cfg(unix)]
#[test]
fn remove_json_write_stage_error_reports_partial_failure() {
    if running_as_root() {
        eprintln!("SKIP: root bypasses directory permission checks");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("package.json"), UNWIRED_PACKAGE_JSON);
    wire(cwd);
    chmod(cwd, 0o555);

    let (code, v) = run_json(cwd, &["setup", "--remove", "--yes", "--json"]);
    chmod(cwd, 0o755);

    assert_eq!(code, 1, "{v}");
    assert_eq!(v["status"], "partial_failure", "{v}");
    assert_eq!(v["removed"], 0, "{v}");
    assert_eq!(v["errors"], 1, "{v}");
    let entry = entry_of(&v, "package_json");
    assert_eq!(entry["status"], "error", "{v}");
    assert!(entry["error"].is_string(), "{v}");
}

/// Covers 1500: remove --json python status "not_configured" (the hook was
/// never in the python manifest while npm had something to remove).
#[test]
fn remove_json_python_not_configured_status() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("package.json"), UNWIRED_PACKAGE_JSON);
    wire(cwd);
    // The python manifest appears AFTER wiring, so it never got the hook.
    write(&cwd.join("requirements.txt"), REQUIREMENTS_NO_HOOK);

    let (code, v) = run_json(cwd, &["setup", "--remove", "--yes", "--json"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(entry_of(&v, "package_json")["status"], "removed", "{v}");
    assert_eq!(entry_of(&v, "pth")["status"], "not_configured", "{v}");
    assert_eq!(
        read(&cwd.join("requirements.txt")),
        REQUIREMENTS_NO_HOOK,
        "a not-configured python manifest must be untouched"
    );
}

/// Covers 1501: remove --json python status "error" (unreadable manifest)
/// riding a partial_failure envelope next to a successful npm removal.
#[cfg(unix)]
#[test]
fn remove_json_python_error_status() {
    if running_as_root() {
        eprintln!("SKIP: root bypasses file permission checks");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("package.json"), UNWIRED_PACKAGE_JSON);
    wire(cwd);
    write(&cwd.join("requirements.txt"), REQUIREMENTS_NO_HOOK);
    chmod(&cwd.join("requirements.txt"), 0o000);

    let (code, v) = run_json(cwd, &["setup", "--remove", "--yes", "--json"]);
    chmod(&cwd.join("requirements.txt"), 0o644);

    assert_eq!(code, 1, "{v}");
    assert_eq!(v["status"], "partial_failure", "{v}");
    assert_eq!(entry_of(&v, "package_json")["status"], "removed", "{v}");
    let pth = entry_of(&v, "pth");
    assert_eq!(pth["status"], "error", "{v}");
    assert!(pth["error"].is_string(), "{v}");
}

// ---------------------------------------------------------------------------
// setup human-mode output: idempotent message, previews, commit notes,
// warnings, error counts.
// ---------------------------------------------------------------------------

/// Covers 1653-1654: the idempotent second human run.
#[test]
fn setup_human_second_run_reports_all_configured() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(&tmp.path().join("package.json"), UNWIRED_PACKAGE_JSON);
    wire(tmp.path());

    let (code, stdout, _stderr) = run(tmp.path(), &["setup", "--yes"]);
    assert_eq!(code, 0, "stdout=\n{stdout}");
    assert!(
        stdout.contains("All install hooks are already configured with socket-patch!"),
        "the idempotent second run must say so; stdout=\n{stdout}"
    );
}

/// Covers 1814-1817 (python preview section), 1820-1823 (gem preview lines),
/// 1763-1767 (python commit note naming the detected manager), and
/// 1770-1775 (Gemfile commit note) in one real human setup run.
#[test]
fn setup_human_preview_and_commit_notes_for_python_and_gem() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("package.json"), UNWIRED_PACKAGE_JSON);
    write(&cwd.join("requirements.txt"), REQUIREMENTS_NO_HOOK);
    write(&cwd.join("Gemfile"), GEMFILE_FIXTURE);
    write(&cwd.join("Gemfile.lock"), LOCK_2X);

    let (code, stdout, stderr) = run(cwd, &["setup", "--yes"]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains("Python manifests to update (socket-patch-hook):"),
        "the python preview section must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Gem: add the socket-patch Bundler plugin wiring to:"),
        "the gem preview lines must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Commit the pip dependency change"),
        "the python commit note must name the detected manager; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Commit the Gemfile"),
        "the Gemfile commit note must print; stdout=\n{stdout}"
    );
}

/// Covers 1835-1838: the "Already configured (will skip)" preview count —
/// needs a mixed tree with one wired and one unwired manifest.
#[test]
fn setup_human_preview_counts_already_configured() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(
        &cwd.join("package.json"),
        &format!("{{\"name\":\"root\",\"workspaces\":[\"packages/*\"],{WIRED_SCRIPTS_FRAGMENT}}}"),
    );
    write(&cwd.join("packages/a/package.json"), UNWIRED_PACKAGE_JSON);

    let (code, stdout, _stderr) = run(cwd, &["setup", "--yes"]);
    assert_eq!(code, 0, "stdout=\n{stdout}");
    assert!(
        stdout.contains("Already configured (will skip): 1"),
        "the wired root must be counted as a skip; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("1 item(s) updated"),
        "the unwired member must still be updated; stdout=\n{stdout}"
    );
    assert!(
        read(&cwd.join("packages/a/package.json")).contains("socket-patch"),
        "the unwired member must gain the hook"
    );
}

/// Covers 1760-1761: the human summary warning line, driven hermetically by
/// the fail-closed --exclude persistence over a corrupt manifest (the JSON
/// twin lives in setup_contract_gaps.rs).
#[test]
fn setup_human_summary_surfaces_persist_warning() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("package.json"), UNWIRED_PACKAGE_JSON);
    let corrupt = "not json {{{";
    write(&cwd.join(".socket/manifest.json"), corrupt);

    let (code, stdout, _stderr) = run(cwd, &["setup", "--yes", "--exclude", "packages/b"]);
    assert_eq!(code, 0, "the skip is a warning, not an error; stdout=\n{stdout}");
    assert!(
        stdout.contains("warning: not persisting --exclude"),
        "the human summary must surface the fail-closed persistence skip; stdout=\n{stdout}"
    );
    assert_eq!(
        read(&cwd.join(".socket/manifest.json")),
        corrupt,
        "the corrupt manifest must survive byte-identical"
    );
}

/// Covers 1757: the human summary "N error(s)" line on a partial failure.
#[cfg(unix)]
#[test]
fn setup_human_summary_counts_errors() {
    if running_as_root() {
        eprintln!("SKIP: root bypasses file permission checks");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(
        &cwd.join("package.json"),
        r#"{ "name": "root", "workspaces": ["packages/*"] }"#,
    );
    let locked = cwd.join("packages/locked/package.json");
    write(&locked, UNWIRED_PACKAGE_JSON);
    chmod(&locked, 0o000);

    let (code, stdout, _stderr) = run(cwd, &["setup", "--yes"]);
    chmod(&locked, 0o644);

    assert_eq!(code, 1, "a partial failure must exit 1; stdout=\n{stdout}");
    assert!(
        stdout.contains("1 item(s) updated"),
        "the readable root must still be updated; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("1 error(s)"),
        "the human summary must count the unreadable member; stdout=\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// Remove-mode lockfile-refresh warnings (1299-1300 human, 1522 --json):
// a Poetry project whose lock refresh cannot spawn `poetry` (empty PATH).
// ---------------------------------------------------------------------------

/// Wire the poetry hook (no lock → no refresh during wiring), then plant an
/// empty poetry.lock so the REMOVE run attempts the refresh.
fn poetry_remove_warning_fixture() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(&tmp.path().join("pyproject.toml"), POETRY_PYPROJECT);
    wire(tmp.path());
    assert!(
        read(&tmp.path().join("pyproject.toml")).contains("socket-patch"),
        "fixture: the hook must be wired before the remove run"
    );
    write(&tmp.path().join("poetry.lock"), "# stub lock\n");
    tmp
}

#[test]
fn remove_human_surfaces_poetry_lock_refresh_warning() {
    let tmp = poetry_remove_warning_fixture();
    let empty = tempfile::tempdir().expect("empty PATH dir");

    let (code, stdout, stderr) = run_env(
        tmp.path(),
        &["setup", "--remove", "--yes"],
        &[("PATH", empty.path().to_str().unwrap())],
    );
    assert_eq!(
        code, 0,
        "a failed lock refresh is a warning, not an error; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("warning: could not run `poetry"),
        "the human summary must warn that the refresh could not run; stdout=\n{stdout}"
    );
    // The edit itself must still have happened: the hook extra is gone. (For
    // the classic-Poetry inline-table form, current remove semantics strip
    // `extras = ["hook"]` but keep a bare `socket-patch = { version = "*" }`
    // dependency line — asserting on the extra, not the whole line, pins the
    // part that defines "hook removed".)
    let pyproject = read(&tmp.path().join("pyproject.toml"));
    assert!(
        !pyproject.contains("hook"),
        "the hook extra must be stripped by the remove; got:\n{pyproject}"
    );
}

#[test]
fn remove_json_surfaces_poetry_lock_refresh_warning() {
    let tmp = poetry_remove_warning_fixture();
    let empty = tempfile::tempdir().expect("empty PATH dir");

    let (code, stdout, stderr) = run_env(
        tmp.path(),
        &["setup", "--remove", "--yes", "--json"],
        &[("PATH", empty.path().to_str().unwrap())],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(entry_of(&v, "pth")["status"], "removed", "{v}");
    let warnings = v["warnings"]
        .as_array()
        .unwrap_or_else(|| panic!("the envelope must carry a warnings array: {v}"));
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().is_some_and(|w| w.contains("could not run `poetry"))),
        "the refresh failure must ride the --json warnings: {v}"
    );
}
