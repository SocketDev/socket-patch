//! `apply`'s render suite (#1089): the human-mode (no `--json`, no
//! `--silent`) output of `commands/apply.rs`. Behavior is asserted
//! through `--json` codes in `apply_failure_paths.rs`; the sentence
//! checks here are the render checks, one per message family.
//!
//! Lines pinned: the go drift report, the stale-redirect `Removed` /
//! `Would remove` announcement, "No patches to apply.", the
//! no-matching-package error block, the dry-run summary counts,
//! `--verbose` per-file labels, the pnpm/bun/vlt layout notes, the
//! yarn-PnP refusal, the gem fallback-home skip warning and the
//! `--dry-run --vex` skip line.

use serde_json::json;

use crate::apply_fixture::*;

// ═══════════ go drift and reconcile reports ═══════════

/// `--check` drift prints the out-of-sync report with each drift's detail.
#[test]
fn check_drift_prints_out_of_sync_report() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), json!({}));
    std::fs::write(
        tmp.path().join("go.mod"),
        "module example.com/app\n\ngo 1.21\n\n\
         replace example.com/other v1.2.3 => ./.socket/go-patches/example.com/other@v1.2.3\n",
    )
    .unwrap();

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--check"], &[]);
    assert_eq!(code, 1, "an orphan replace is drift; stderr={stderr}");
    assert!(
        stderr.contains("Patches are OUT OF SYNC:"),
        "drift must print the out-of-sync report; stderr={stderr}"
    );
    assert!(
        stderr.contains("orphan go.mod `replace` for `example.com/other`"),
        "the report must carry each drift's detail; stderr={stderr}"
    );
}

/// A wet apply announces the pruned redirect with its purl; `--dry-run`
/// uses the conditional verb.
#[test]
fn reconcile_announces_removed_and_would_remove() {
    let tmp = tempfile::tempdir().unwrap();
    write_stale_go_redirect(tmp.path());

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline", "--dry-run"], &[]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(
        stdout.contains("Would remove 1 stale Go patch redirect:"),
        "dry-run must use the conditional verb; stdout={stdout}"
    );
    assert!(stdout.contains(GO_PURL), "stdout={stdout}");

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(
        stdout.contains("Removed 1 stale Go patch redirect:"),
        "the removal must be announced; stdout={stdout}"
    );
    assert!(
        stdout.contains(GO_PURL),
        "the announcement must name the pruned purl; stdout={stdout}"
    );
}

// ═══════════ apply output block ═══════════

/// The empty-scope clean success prints "No patches to apply.": the
/// postinstall-hook UX for fresh projects.
#[test]
fn empty_manifest_prints_no_patches_to_apply() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), json!({}));

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(
        stdout.contains("No patches to apply."),
        "the human no-op line must print; stdout={stdout}"
    );
}

/// Zero packages match an in-scope patch: the error block lists the
/// unmatched purls and carries the check-your-cwd hint.
#[test]
fn no_matching_packages_prints_error_block() {
    let tmp = tempfile::tempdir().unwrap();
    write_npm_patch(tmp.path(), "ghost", "63636363-6363-4363-8363-636363636363");

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 1, "stderr={stderr}");
    assert!(
        stderr.contains("Error: The targeted manifest patch matched no installed package:"),
        "a failing run labels its cause an error; stderr={stderr}"
    );
    assert!(
        stderr.contains("  - pkg:npm/ghost@1.0.0"),
        "the error must list the unmatched purls; stderr={stderr}"
    );
    assert!(
        stderr.contains("--cwd points to the right directory"),
        "the error must carry the remediation hint; stderr={stderr}"
    );
}

/// The dry-run summary counts an already-patched package under "already
/// patched", not "can be patched".
#[test]
fn dry_run_summary_counts_already_patched() {
    let tmp = tempfile::tempdir().unwrap();
    write_npm_patch(tmp.path(), "twice", "64646464-6464-4464-8464-646464646464");
    install_npm_pkg(tmp.path(), "twice", "1.0.0", Some(MM_AFTER));

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline", "--dry-run"], &[]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(
        stdout.contains("Patch verification complete:"),
        "stdout={stdout}"
    );
    assert!(
        stdout.contains("1 package already patched"),
        "stdout={stdout}"
    );
    assert!(
        stdout.contains("0 packages can be patched"),
        "stdout={stdout}"
    );
}

/// `--verbose` detailed verification: the already-patched / hash-mismatch /
/// not-found labels, the per-file `message:` line, the `expected:` hash
/// line and the per-package failure lines.
#[test]
fn verbose_dry_run_prints_per_file_labels_and_hashes() {
    let tmp = tempfile::tempdir().unwrap();
    write_three_state_npm_project(tmp.path());

    let (code, stdout, stderr) = run_apply(
        tmp.path(),
        &["--offline", "--dry-run", "--verbose", "--strict"],
        &[],
    );
    assert_eq!(code, 1, "stderr={stderr}");
    assert!(stdout.contains("Detailed verification:"), "stdout={stdout}");
    for label in ["[already patched]", "[hash mismatch]", "[not found]"] {
        assert!(
            stdout.contains(&format!("package/index.js {label}")),
            "the {label} label must render; stdout={stdout}"
        );
    }
    assert!(
        stdout.contains("message: File hash does not match expected value"),
        "stdout={stdout}"
    );
    assert!(
        stdout.contains("message: File not found"),
        "stdout={stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "expected: {}",
            crate::common::git_sha256(MM_BEFORE)
        )),
        "the expected-hash line must render for the mismatch; stdout={stdout}"
    );
    for purl in ["pkg:npm/vmismatch@1.0.0", "pkg:npm/vmissing@1.0.0"] {
        assert!(
            stderr.contains(&format!("Failed to patch {purl}")),
            "stderr={stderr}"
        );
    }
}

// ═══════════ layout notes and refusals ═══════════

/// A pnpm store layout gets the informational stderr note.
#[test]
fn pnpm_layout_prints_informational_note() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), json!({}));
    std::fs::create_dir_all(tmp.path().join("node_modules").join(".pnpm")).unwrap();

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(
        stderr.contains(
            "Note: pnpm layout detected. Copy-on-write will keep the global store untouched."
        ),
        "stderr={stderr}"
    );
    assert!(stdout.contains("No patches to apply."), "stdout={stdout}");
}

/// A `bun.lock` + `node_modules/` tree routes to the Bun arm and prints
/// its informational note (non-fatal, exit 0).
#[test]
fn bun_layout_prints_informational_note() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), json!({}));
    std::fs::create_dir_all(tmp.path().join("node_modules")).unwrap();
    std::fs::write(tmp.path().join("bun.lock"), "{}\n").unwrap();

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(
        code, 0,
        "the bun note is informational only; stderr={stderr}"
    );
    assert!(
        stderr.contains(
            "Note: bun layout detected. Copy-on-write will keep ~/.bun/install/cache/ untouched."
        ),
        "stderr={stderr}"
    );
}

/// A vlt install (the `node_modules/.vlt` store) prints its note and never
/// refuses. vlt install state outranks a sibling `bun.lock`, so the bun
/// note does not print.
#[test]
fn vlt_layout_prints_informational_note_in_human_mode() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), json!({}));
    std::fs::create_dir_all(tmp.path().join("node_modules").join(".vlt")).unwrap();
    std::fs::write(tmp.path().join("bun.lock"), "{}\n").unwrap();

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(
        code, 0,
        "the vlt note is informational only; stderr={stderr}"
    );
    assert!(
        stderr.contains(
            "Note: vlt layout detected. Copy-on-write keeps vlt's shared package store \
             (<vlt cache>/store/v1) untouched."
        ),
        "stderr={stderr}"
    );
    assert!(!stderr.contains("bun layout detected"), "stderr={stderr}");
}

/// The layout notes are human-only: `--json` and `--silent` runs (the
/// install hook runs `apply --silent`) stay quiet. The hidden lock alone
/// is vlt install state too.
#[test]
fn vlt_layout_note_is_muted_under_json_and_silent() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), json!({}));
    std::fs::create_dir_all(tmp.path().join("node_modules")).unwrap();
    std::fs::write(tmp.path().join("node_modules/.vlt-lock.json"), "{}").unwrap();

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(stderr.contains("vlt layout detected"), "stderr={stderr}");
    for flag in ["--json", "--silent"] {
        let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline", flag], &[]);
        assert_eq!(code, 0, "{flag}: stderr={stderr}");
        assert!(
            !stderr.contains("layout detected"),
            "{flag}: stderr={stderr}"
        );
    }
}

/// The yarn-PnP refusal names the layout on human stderr; a corrupt
/// manifest under the same layout prints the manifest error instead.
#[test]
fn pnp_refusal_names_the_layout_and_corrupt_manifest_does_not() {
    let tmp = tempfile::tempdir().unwrap();
    write_pnp_npm_project(tmp.path());
    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 1, "stderr={stderr}");
    assert!(
        stderr.contains("Plug'n'Play layout is not supported"),
        "stderr={stderr}"
    );

    std::fs::write(tmp.path().join(".socket/manifest.json"), "{ not json").unwrap();
    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 1, "stderr={stderr}");
    assert!(
        stderr.contains("Failed to parse manifest JSON"),
        "stderr={stderr}"
    );
    assert!(!stderr.contains("Plug'n'Play"), "stderr={stderr}");
}

// ═══════════ gem fallback-home skip warning ═══════════

/// Unix-only: the fallback home comes from a fake `gem` binary on PATH
/// (the `in_process_gem_fallback_home.rs` fixture shape, which pins the
/// `--json` warning code; this is its human render).
#[cfg(unix)]
mod gem_fallback_home_human {
    use std::path::{Path, PathBuf};

    use serde_json::json;

    use crate::apply_fixture::*;
    use crate::common;

    const ORIGINAL: &[u8] = b"module Rack\n  VERSION = 'VULNERABLE'\nend\n";
    const MARKER: &[u8] = b"# SOCKET-PATCHED-FALLBACK\n";

    /// Fake `gem` answering `env gemdir` with `home`, so the crawler's
    /// fallback resolves to exactly one gem home.
    fn install_fake_gem(bin_dir: &Path, home: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = env ] && [ \"$2\" = gemdir ]; then\n  printf '%s\\n' \"{}\"\n  exit 0\nfi\nexit 1\n",
            home.display()
        );
        let bin = bin_dir.join("gem");
        std::fs::write(&bin, script).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Stage a gem copy (`<root>/gems/rack-3.1.0/lib/rack.rb` = `bytes`)
    /// plus the `specifications/` marker; returns the staged file path.
    fn stage_copy(root: &Path, bytes: &[u8]) -> PathBuf {
        let file = root.join("gems/rack-3.1.0/lib/rack.rb");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, bytes).unwrap();
        std::fs::create_dir_all(root.join("specifications")).unwrap();
        file
    }

    /// Human-mode apply with the hermetic SOCKET_* env and BUNDLE_*
    /// scrubbed, PATH = the fake-gem bin dir only, BUNDLE_PATH = the store
    /// root.
    fn run_apply_human(project: &Path, bin_dir: &Path, store_root: &Path) -> (i32, String, String) {
        let mut cmd = common::hermetic_command(&common::binary());
        cmd.args(["apply", "--offline", "--ecosystems", "gem", "--cwd"])
            .arg(project);
        common::hermetic::scrub_extra(&mut cmd, &[common::hermetic::Extra::Bundle]);
        cmd.env("PATH", bin_dir);
        cmd.env("BUNDLE_PATH", store_root);
        let out = cmd.output().expect("run socket-patch apply");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    /// Store copy patched + home copy matching NO variant: the per-copy
    /// warning names the skipped copy's path and says why the skip is
    /// safe. Non-fatal; the store copy is patched, the home copy untouched.
    #[test]
    fn mismatched_fallback_home_copy_warns_on_human_stderr() {
        let foreign = b"totally different bytes\n";
        let project = tempfile::tempdir().unwrap();
        let root = project.path();
        std::fs::write(root.join("Gemfile"), b"source 'https://rubygems.org'\n").unwrap();

        let store_root = root.join("bundle-store");
        let store_file = stage_copy(&store_root, ORIGINAL);
        let home = root.join("gem-home");
        let home_file = stage_copy(&home, foreign);
        let bin_dir = root.join("fake-bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        install_fake_gem(&bin_dir, &home);

        let patched = [ORIGINAL, MARKER].concat();
        write_manifest(
            root,
            json!({
                GEM_QUALIFIED_PURL: patch_record(
                    "69696969-6969-4969-8969-696969696969",
                    one_file("lib/rack.rb", ORIGINAL, &patched),
                )
            }),
        );
        stage_blob(root, &common::git_sha256(&patched), &patched);

        let (code, _stdout, stderr) = run_apply_human(root, &bin_dir, &store_root);
        assert_eq!(code, 0, "stderr={stderr}");
        assert!(
            stderr.contains("Warning: ") && stderr.contains("was not patched"),
            "the best-effort skip must print its human warning; stderr={stderr}"
        );
        assert!(
            stderr.contains(&format!("gem-env home copy at {}", home.display())),
            "the warning must name the fallback-home copy; stderr={stderr}"
        );
        assert!(
            stderr.contains("bundle-path copy — the one bundler loads — is patched"),
            "the warning must explain why the skip is safe; stderr={stderr}"
        );
        assert_eq!(std::fs::read(&store_file).unwrap(), patched);
        assert_eq!(std::fs::read(&home_file).unwrap(), foreign);
    }
}

// ═══════════ dry-run --vex ═══════════

/// `apply --dry-run --vex <path>` announces that VEX generation is skipped.
#[test]
fn dry_run_with_vex_announces_the_skip() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_gem_patch(
        root,
        "72727272-7272-4272-8272-727272727272",
        b"# SOCKET-VEX-PATCH\n",
    );
    let vex_path = root.join("out.vex.json");

    let (code, stdout, stderr) = run_apply(
        root,
        &[
            "--offline",
            "--ecosystems",
            "gem",
            "--dry-run",
            "--vex",
            vex_path.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(
        stdout.contains("Skipping VEX generation (--dry-run: nothing was applied)."),
        "stdout={stdout}"
    );
}
