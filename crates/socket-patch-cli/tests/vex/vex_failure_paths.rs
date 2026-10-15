//! `vex`'s `--json` contracts for its failure and advisory paths (#1089):
//! exit code, `status`, `error.code`, skipped events and their
//! `errorCode`s, `warnings[]` codes and the bytes on disk. A message is read
//! only for what it must name (a file). The human output of the same paths
//! is pinned in `vex_render.rs`.
//!
//!   1. a corrupt manifest (`manifest_invalid`), including the stale-doc
//!      cleanup and a FIFO at `--output`;
//!   2. a malformed pre-v5 redirect ledger (`redirect_ledger_corrupt`, an
//!      advisory);
//!   3. a corrupt vendor ledger (`vendor_ledger_corrupt`, a hard error),
//!      with and without a manifest;
//!   4. the multi-manifest product auto-detect warning;
//!   5. dry runs, `-O -`, stale-document removal and omission order.

use crate::vex_fixture::*;

// ───────────────────── corrupt manifest ─────────────────────

/// A present-but-corrupt manifest is the hard exit-2 `manifest_invalid`
/// (distinct from the missing-manifest `manifest_not_found`), and a run that
/// ends in error leaves no OpenVEX document at `--output`, not even a
/// previous run's.
#[test]
fn corrupt_manifest_is_manifest_invalid_and_removes_the_stale_doc() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_corrupt_manifest(cwd);
    let out = cwd.join("out.vex.json");
    std::fs::write(&out, STALE_OPENVEX_DOC).unwrap();

    let (o, env) = vex_json(cwd, &[]);
    assert_eq!(o.status.code(), Some(2), "{env}");
    assert_eq!(env["status"], "error", "{env}");
    assert_eq!(envelope_error_code(&env), Some("manifest_invalid"), "{env}");
    assert!(
        envelope_error_message(&env).is_some_and(|m| m.contains("manifest.json")),
        "the error names the unreadable file: {env}"
    );
    assert!(!out.exists(), "a failed run leaves no document at --output");
}

/// A failed run's stale-doc cleanup reads `--output` to check it is
/// OpenVEX before deleting it. A FIFO there must not block that read: the
/// run still fails promptly with its own error and leaves the FIFO alone.
#[cfg(unix)]
#[test]
fn failed_run_does_not_block_on_a_fifo_at_output() {
    use std::os::unix::fs::FileTypeExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_corrupt_manifest(cwd);
    let fifo = cwd.join("out.vex.json");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());

    let mut child = vex_command(cwd, Some(PRODUCT))
        .args(["--json", "--output", fifo.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("invoke vex");
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            panic!("vex blocked reading the FIFO at --output");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let o = child.wait_with_output().unwrap();
    let env = parse_json_envelope(&stdout(&o));
    assert_eq!(o.status.code(), Some(2), "{env}");
    assert_eq!(envelope_error_code(&env), Some("manifest_invalid"), "{env}");
    assert!(
        std::fs::symlink_metadata(&fifo)
            .unwrap()
            .file_type()
            .is_fifo(),
        "a FIFO is not an OpenVEX document and must not be removed"
    );
}

// ───────────────────── pre-v5 redirect ledger ─────────────────────

/// v5 hosted mode keeps no ledger, so a malformed pre-v5
/// `.socket/vendor/redirect-state.json` is only an advisory: its records are
/// not consulted and the run reaches its own outcome. With a manifest whose
/// package is not installed that is `no_applicable_patches` (exit 1); with
/// nothing else on disk it is `manifest_not_found` (exit 2). Either way the
/// warning travels in the envelope and the file is left alone.
#[test]
fn corrupt_redirect_ledger_is_an_advisory_and_the_run_reaches_its_own_outcome() {
    let purl = "pkg:npm/leftpad@1.0.0";
    for (with_manifest, exit, code) in [
        (true, 1, "no_applicable_patches"),
        (false, 2, "manifest_not_found"),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        if with_manifest {
            write_npm_manifest(cwd, &[purl]);
        }
        write_corrupt_redirect_ledger(cwd);

        let (o, env) = vex_json(cwd, &[]);
        assert_eq!(o.status.code(), Some(exit), "{env}");
        assert_eq!(envelope_error_code(&env), Some(code), "{env}");
        if with_manifest {
            assert!(
                has_event(&env, "skipped", "package_not_found", purl),
                "the manifest patch was evaluated: {env}"
            );
        }
        let warning = env["warnings"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|w| w["code"] == "redirect_ledger_corrupt")
            .unwrap_or_else(|| panic!("redirect_ledger_corrupt expected: {env}"));
        assert!(
            warning["detail"]
                .as_str()
                .is_some_and(|d| d.contains("redirect-state.json")),
            "the warning names the ledger: {env}"
        );
        assert!(
            !stderr(&o).contains("redirect-state.json"),
            "--json keeps the warning off stderr: {}",
            stderr(&o)
        );
        assert_redirect_ledger_untouched(cwd);
        assert!(!cwd.join("out.vex.json").exists());
    }
}

// ───────────────────── corrupt vendor ledger ─────────────────────

/// Unlike the pre-v5 redirect ledger, the vendor ledger is an attestation
/// input (embedded records, and the wiring that gates them), so a corrupt
/// one fails closed with `vendor_ledger_corrupt` before any verification,
/// whether or not a manifest exists, instead of attesting from the rest or
/// blaming a manifest the project never had.
#[test]
fn corrupt_vendor_ledger_fails_closed_before_verification() {
    for with_manifest in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        if with_manifest {
            write_npm_manifest(cwd, &["pkg:npm/leftpad@1.0.0"]);
        }
        write_corrupt_vendor_ledger(cwd);

        let (o, env) = vex_json(cwd, &[]);
        assert_eq!(o.status.code(), Some(2), "{env}");
        assert_eq!(env["status"], "error", "{env}");
        assert_eq!(
            envelope_error_code(&env),
            Some("vendor_ledger_corrupt"),
            "{env}"
        );
        assert!(
            envelope_error_message(&env)
                .is_some_and(|m| m.contains("state.json") && m.contains("corrupt")),
            "the error names the unreadable ledger and why: {env}"
        );
        assert!(
            env["events"].as_array().is_none_or(|e| e.is_empty()),
            "no per-patch events on a pre-verification hard error: {env}"
        );
        assert_vendor_ledger_untouched(cwd);
        assert!(!cwd.join("out.vex.json").exists(), "no document");
    }
}

// ───────────────────── product auto-detect ─────────────────────

/// With package.json and Cargo.toml side by side, auto-detect picks
/// package.json and says so as a `product_multiple_manifests` warning, in
/// the envelope only.
#[test]
fn multi_manifest_auto_detect_warns_in_the_envelope() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_multi_manifest_project(cwd);
    let out = cwd.join("out.vex.json");

    let mut cmd = vex_command(cwd, None);
    cmd.arg("--no-verify");
    let (o, env) = run_json(cmd, &out);
    assert_eq!(o.status.code(), Some(0), "{env}");
    assert_eq!(warning_codes(&env), ["product_multiple_manifests"], "{env}");
    assert!(
        env["warnings"][0]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("package.json")),
        "the warning names the manifest used: {env}"
    );
    assert!(stderr(&o).is_empty(), "{}", stderr(&o));
    assert_eq!(
        read_doc(&out)["statements"][0]["products"][0]["@id"],
        PRODUCT
    );
}

// ───────────────────── output contract ─────────────────────

#[test]
fn json_dry_run_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_npm_manifest(cwd, &["pkg:npm/a@1.0.0"]);

    let (o, env) = vex_json(cwd, &["--no-verify", "--dry-run"]);
    assert_eq!(o.status.code(), Some(0), "{env}");
    assert_eq!(env["dryRun"], true, "{env}");
    assert!(!cwd.join("out.vex.json").exists());
}

/// Under `--json` the envelope owns stdout, so `-O -` is refused.
#[test]
fn json_with_output_dash_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_npm_manifest(cwd, &["pkg:npm/a@1.0.0"]);

    let o = vex(cwd, &["--no-verify", "--json", "-O", "-"]);
    let env = parse_json_envelope(&stdout(&o));
    assert_eq!(o.status.code(), Some(2), "{env}");
    assert_eq!(
        envelope_error_code(&env),
        Some("json_requires_output"),
        "{env}"
    );
    assert!(!cwd.join("-").exists());
}

#[test]
fn failed_run_reports_stale_doc_removal_as_a_warning_code() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_npm_manifest(cwd, &["pkg:npm/a@1.0.0"]);
    let out = cwd.join("out.vex.json");
    std::fs::write(&out, STALE_OPENVEX_DOC).unwrap();

    let (o, env) = vex_json(cwd, &[]);
    assert_eq!(o.status.code(), Some(1), "{env}");
    assert!(
        warning_codes(&env).contains(&"vex_stale_doc_removed".to_string()),
        "{env}"
    );
    assert!(!out.exists());
    assert!(stderr(&o).is_empty(), "{}", stderr(&o));
}

/// Omitted patches come out as `skipped` events sorted by purl, whatever
/// the manifest order.
#[test]
fn omitted_patches_are_sorted_skipped_events() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_npm_manifest(
        cwd,
        &[
            "pkg:npm/zeta@1.0.0",
            "pkg:npm/alpha@1.0.0",
            "pkg:npm/mid@1.0.0",
        ],
    );

    let (o, env) = vex_json(cwd, &[]);
    assert_eq!(o.status.code(), Some(1), "{env}");
    assert_eq!(
        envelope_error_code(&env),
        Some("no_applicable_patches"),
        "{env}"
    );
    assert_eq!(
        event_purls(&env, "skipped"),
        [
            "pkg:npm/alpha@1.0.0",
            "pkg:npm/mid@1.0.0",
            "pkg:npm/zeta@1.0.0"
        ],
        "{env}"
    );
    assert!(
        events(&env)
            .iter()
            .all(|e| e["errorCode"] == "package_not_found"
                && e["reason"].as_str().is_some_and(|r| !r.is_empty())),
        "{env}"
    );
}
