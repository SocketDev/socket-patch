//! How `apply` and `apply --check` report an INSTALLED gem whose files
//! match no release variant of the manifest (#2231).
//!
//! A gem edited in place (`bundle open`, a debug line) or rebuilt by a
//! private gem server holds bytes the patch was not made for. A qualified
//! record (`?platform=ruby`) names one distribution, so `apply` leaves
//! such a copy untouched and fails (`cli_gem_variant_mismatch_policy.rs`
//! pins that). This suite pins what the run SAYS about it:
//!
//!   * the copy is installed: never "not installed on this host", "not
//!     found on disk" or a `package_not_installed` event, even when the
//!     project's `Gemfile.lock` resolves the gem (which made the old
//!     report read as a calm lockfile-only skip);
//!   * the failure names the copy, the file that differs and the way
//!     back to the published gem (`bundle pristine <gem>`);
//!   * `--json` carries one `failed` / `no_matching_variant` event keyed
//!     by the base purl, the code `apply --check` already gives the copy;
//!   * `apply --check` does not offer `socket-patch apply` as the remedy,
//!     since `apply` leaves the copy as it is.
//!
//! All offline: the real binary over a synthetic `vendor/bundle` tree.

use std::path::{Path, PathBuf};

use serde_json::json;

use crate::apply_fixture::{
    install_gem, one_file, patch_record, run_gem, run_gem_apply, stage_blob, write_manifest,
    GEM_BASE_PURL, GEM_LOCAL, GEM_PRISTINE, GEM_QUALIFIED_PURL,
};
use crate::common::envelope::{
    assert_envelope_invariants, event_codes, events, parse_json_envelope,
};
use crate::common::git_sha256;

const NO_VARIANT: &str = "no_matching_variant";

/// The `error` text of the base's `failed` / `no_matching_variant` event.
fn no_variant_error(v: &serde_json::Value) -> String {
    let event = events(v)
        .iter()
        .find(|e| {
            e["action"] == "failed" && e["errorCode"] == NO_VARIANT && e["purl"] == GEM_BASE_PURL
        })
        .unwrap_or_else(|| panic!("no failed/{NO_VARIANT} event for the base: {v:#}"));
    // `apply` words a failure as `error`, `apply --check` as `reason`.
    event["error"]
        .as_str()
        .or(event["reason"].as_str())
        .unwrap_or_default()
        .to_string()
}

/// The issue's project: `rack 3.1.0` in the project's own `vendor/bundle`
/// with a debug edit, a `?platform=ruby` record for it, and a
/// `Gemfile.lock` that resolves it. Returns the edited file.
fn edited_gem_project(root: &Path) -> PathBuf {
    let patched = [GEM_PRISTINE, b"\n# SOCKET-PATCH\n"].concat();
    let file = install_gem(root, "rack-3.1.0", "lib/rack.rb", GEM_LOCAL);
    write_manifest(
        root,
        json!({
            GEM_QUALIFIED_PURL: patch_record(
                "22312231-2231-4231-8231-223122312231",
                one_file("lib/rack.rb", GEM_PRISTINE, &patched),
            )
        }),
    );
    stage_blob(root, &git_sha256(&patched), &patched);
    std::fs::write(
        root.join("Gemfile"),
        "source \"https://rubygems.org\"\n\ngem \"rack\", \"3.1.0\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("Gemfile.lock"),
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.1.0)\n\n\
         PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack (= 3.1.0)\n\nBUNDLED WITH\n   2.5.22\n",
    )
    .unwrap();
    assert_ne!(git_sha256(GEM_LOCAL), git_sha256(GEM_PRISTINE));
    assert_ne!(git_sha256(GEM_LOCAL), git_sha256(&patched));
    file
}

/// The human run: one error that says the copy's content is not a
/// release the patch was made for, names the file and `bundle pristine`,
/// and nothing that says the gem is absent.
#[test]
fn edited_gem_is_reported_as_installed_with_other_content() {
    let tmp = tempfile::tempdir().unwrap();
    let file = edited_gem_project(tmp.path());

    let (code, stdout, stderr) = run_gem_apply(tmp.path(), &[]);
    let out = format!("{stdout}{stderr}");
    assert_eq!(code, 1, "{out}");
    assert_eq!(
        std::fs::read(&file).unwrap(),
        GEM_LOCAL,
        "the copy must be left as it is"
    );
    assert!(
        stderr.contains(&format!(
            "Failed to patch {GEM_BASE_PURL}: no matching variant found"
        )),
        "{out}"
    );
    assert!(
        stderr.contains("lib/rack.rb"),
        "the file must be named: {out}"
    );
    assert!(
        stderr.contains("rack-3.1.0"),
        "the copy must be named: {out}"
    );
    assert!(
        stderr.contains("`bundle pristine rack`"),
        "the way back to the published gem must be named: {out}"
    );
    for wrong in [
        "not installed on this host",
        "not found on disk",
        "no matching installed package",
        "lockfile",
    ] {
        assert!(!out.contains(wrong), "must not say {wrong:?}: {out}");
    }
    assert!(out.contains("1 failed"), "{out}");
}

/// `--json`: the copy is one `failed` / `no_matching_variant` event keyed
/// by the base purl, with the same text; no `package_not_installed`.
#[test]
fn edited_gem_is_a_failed_event_not_a_not_installed_skip() {
    let tmp = tempfile::tempdir().unwrap();
    edited_gem_project(tmp.path());

    let (code, stdout, stderr) = run_gem_apply(tmp.path(), &["--json"]);
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_json_envelope(&stdout);
    assert_envelope_invariants(&v, "apply");
    assert_eq!(v["status"], "partialFailure", "{v:#}");
    let error = no_variant_error(&v);
    assert!(error.contains("lib/rack.rb"), "{v:#}");
    assert!(error.contains("`bundle pristine rack`"), "{v:#}");
    assert!(
        !event_codes(&v).iter().any(|c| c == "package_not_installed"),
        "an installed copy is never `package_not_installed`: {v:#}"
    );
    assert_eq!(v["summary"]["failed"], 1, "{v:#}");
}

/// `apply --check`: the drift names `bundle pristine`, and the report
/// does not end by sending the user to an `apply` that changes nothing.
#[test]
fn check_does_not_offer_apply_for_a_copy_apply_leaves() {
    let tmp = tempfile::tempdir().unwrap();
    edited_gem_project(tmp.path());

    let (code, stdout, stderr) = run_gem(
        tmp.path(),
        &["apply", "--offline", "--ecosystems", "gem", "--check"],
        &[],
    );
    let out = format!("{stdout}{stderr}");
    assert_eq!(code, 1, "{out}");
    assert!(stderr.contains("no matching variant found"), "{out}");
    assert!(stderr.contains("`bundle pristine rack`"), "{out}");
    assert!(
        !stderr.contains("to regenerate them"),
        "`apply` cannot regenerate a copy it leaves untouched: {out}"
    );

    let (code, stdout, _) = run_gem(
        tmp.path(),
        &[
            "apply",
            "--offline",
            "--ecosystems",
            "gem",
            "--check",
            "--json",
        ],
        &[],
    );
    assert_eq!(code, 1, "{stdout}");
    let v = parse_json_envelope(&stdout);
    let detail = no_variant_error(&v);
    assert!(detail.contains("`bundle pristine rack`"), "{v:#}");
}

/// A drift `apply` does heal beside one it does not: the `apply` remedy
/// is still printed for the first.
#[test]
fn check_keeps_the_apply_remedy_for_a_drift_apply_heals() {
    let tmp = tempfile::tempdir().unwrap();
    edited_gem_project(tmp.path());
    // A second, unpatched gem with a bare record: plain drift.
    let pristine = b"module Rake\nend\n";
    let patched = [&pristine[..], b"# SOCKET-PATCH\n"].concat();
    install_gem(tmp.path(), "rake-13.0.0", "lib/rake.rb", pristine);
    let manifest_path = tmp.path().join(".socket/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    manifest["patches"]["pkg:gem/rake@13.0.0"] = patch_record(
        "22312231-2231-4231-8231-223122312232",
        one_file("lib/rake.rb", pristine, &patched),
    );
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    stage_blob(tmp.path(), &git_sha256(&patched), &patched);

    let (code, _stdout, stderr) = run_gem(
        tmp.path(),
        &["apply", "--offline", "--ecosystems", "gem", "--check"],
        &[],
    );
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("pkg:gem/rake@13.0.0"), "{stderr}");
    assert!(stderr.contains("to regenerate them"), "{stderr}");
    assert!(stderr.contains("`bundle pristine rack`"), "{stderr}");
}
