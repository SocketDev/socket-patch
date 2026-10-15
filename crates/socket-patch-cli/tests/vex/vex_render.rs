//! What a human sees from the standalone `vex` command (#1089): dry runs,
//! `-O -`, the written-document summary, stale-document cleanup, omission
//! reporting, flag typos and the error and warning lines of the failure
//! paths whose `--json` contracts live in `vex_failure_paths.rs`. One check
//! per message family.

use crate::vex_fixture::*;

#[test]
fn dry_run_with_output_writes_nothing_and_says_so() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_npm_manifest(cwd, &["pkg:npm/a@1.0.0"]);
    let out_path = cwd.join("d.json");

    let o = vex(
        cwd,
        &["--no-verify", "--dry-run", "-O", out_path.to_str().unwrap()],
    );
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(!out_path.exists(), "--dry-run must not write the document");
    assert_eq!(
        stdout(&o).trim_end(),
        format!(
            "[dry-run] Would write OpenVEX document with 1 statement to {}",
            out_path.display()
        )
    );
}

#[test]
fn dry_run_failure_keeps_previous_document() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    // Verify mode with nothing installed: nothing attests.
    write_npm_manifest(cwd, &["pkg:npm/a@1.0.0"]);
    let out_path = cwd.join("keep.json");
    std::fs::write(&out_path, STALE_OPENVEX_DOC).unwrap();

    let o = vex(cwd, &["--dry-run", "-O", out_path.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(out_path.exists(), "a dry run deletes nothing");
    assert!(!stderr(&o).contains("Removed the previous VEX document"));
}

#[test]
fn output_dash_means_stdout() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_npm_manifest(cwd, &["pkg:npm/a@1.0.0"]);

    let o = vex(cwd, &["--no-verify", "-O", "-"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let doc: Value = serde_json::from_slice(&o.stdout).expect("document on stdout");
    assert_eq!(doc["statements"].as_array().unwrap().len(), 1);
    assert!(!cwd.join("-").exists(), "no file literally named `-`");
    assert_eq!(stderr(&o).trim_end(), "Emitted 1 VEX statement");
}

#[test]
fn written_document_ends_with_newline_and_summary_is_singular() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_npm_manifest(cwd, &["pkg:npm/a@1.0.0"]);
    let out_path = cwd.join("out.json");

    let o = vex(cwd, &["--no-verify", "-O", out_path.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let body = std::fs::read_to_string(&out_path).unwrap();
    assert!(
        body.ends_with("}\n"),
        "file must end with a newline: {body:?}"
    );
    assert!(!body.ends_with("\n\n"));
    assert_eq!(
        stdout(&o).trim_end(),
        format!(
            "Wrote OpenVEX document with 1 statement to {}",
            out_path.display()
        )
    );
}

#[test]
fn failed_run_reports_stale_document_removal() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_npm_manifest(cwd, &["pkg:npm/a@1.0.0"]);
    let out_path = cwd.join("keep.json");
    std::fs::write(&out_path, STALE_OPENVEX_DOC).unwrap();

    let o = vex(cwd, &["-O", out_path.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(!out_path.exists(), "failure contract: stale doc removed");
    let err = stderr(&o);
    assert!(
        err.contains(&format!(
            "Warning: Removed the previous VEX document at {} (this run could not attest it).",
            out_path.display()
        )),
        "{err}"
    );
    // The error line is last.
    assert!(
        err.trim_end()
            .ends_with("Error: No applied patches with vulnerability metadata to attest."),
        "{err}"
    );
}

#[test]
fn omissions_are_sorted_and_listed_once() {
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

    let o = vex(cwd, &[]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    let lines: Vec<String> = stderr(&o).lines().map(str::to_string).collect();
    assert_eq!(
        lines,
        vec![
            "Warning: omitting pkg:npm/alpha@1.0.0 from VEX: the package is not installed (package_not_found)",
            "Warning: omitting pkg:npm/mid@1.0.0 from VEX: the package is not installed (package_not_found)",
            "Warning: omitting pkg:npm/zeta@1.0.0 from VEX: the package is not installed (package_not_found)",
            "Error: No applied patches with vulnerability metadata to attest.",
        ]
    );

    // --silent mutes the warnings, so the error lists the omissions itself.
    let o = vex(cwd, &["--silent"]);
    assert_eq!(o.status.code(), Some(1));
    let lines: Vec<String> = stderr(&o).lines().map(str::to_string).collect();
    assert_eq!(
        lines,
        vec![
            "Error: No applied patches with vulnerability metadata to attest.",
            "  omitted: pkg:npm/alpha@1.0.0 (package_not_found)",
            "  omitted: pkg:npm/mid@1.0.0 (package_not_found)",
            "  omitted: pkg:npm/zeta@1.0.0 (package_not_found)",
        ]
    );
}

#[test]
fn trusted_patch_attests_without_setup_config() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    // No manifest `setup` section and no install hook: the trusted patch
    // still attests, with no omission warning.
    write_npm_manifest(cwd, &["pkg:npm/a@1.0.0"]);

    let o = vex(cwd, &["--no-verify"]);
    let err = stderr(&o);
    assert_eq!(o.status.code(), Some(0), "{err}");
    assert!(!err.contains("omitting"), "{err}");
    let doc: Value = serde_json::from_slice(&o.stdout).expect("OpenVEX doc on stdout");
    assert_eq!(doc["statements"].as_array().unwrap().len(), 1, "{doc}");
}

#[test]
fn org_that_looks_like_a_file_warns() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_npm_manifest(cwd, &["pkg:npm/a@1.0.0"]);

    let o = vex(cwd, &["--no-verify", "-o", "out.json"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(
        stderr(&o).contains(
            "Warning: --org \"out.json\" looks like a file path; did you mean -O/--output?"
        ),
        "{}",
        stderr(&o)
    );
    let o = vex(cwd, &["--no-verify", "-o", "out.json", "--silent"]);
    assert!(stderr(&o).is_empty(), "{}", stderr(&o));
}

#[test]
fn missing_manifest_suggests_next_step() {
    let tmp = tempfile::tempdir().unwrap();
    let o = vex(tmp.path(), &[]);
    assert_eq!(o.status.code(), Some(2));
    // Manifest-less VEX: the error also says the lockfiles and ledgers
    // wired nothing, since those alone could have supplied patches.
    let expected = format!(
        "Error: Manifest not found at {}, and no hosted or vendored patch references were \
         found in the project's lockfiles or .socket/vendor ledgers — nothing to attest. Run \
         `socket-patch scan` or `socket-patch get` first, or pass --manifest-path.\n",
        tmp.path().join(".socket/manifest.json").display()
    );
    assert_eq!(stderr(&o), expected);
}

/// A user who already passed `--manifest-path` is not told to pass it.
#[test]
fn missing_custom_manifest_does_not_suggest_manifest_path() {
    let tmp = tempfile::tempdir().unwrap();
    let o = vex(tmp.path(), &["--manifest-path", "nope.json"]);
    assert_eq!(o.status.code(), Some(2));
    let expected = format!(
        "Error: Manifest not found at {}, and no hosted or vendored patch references were \
         found in the project's lockfiles or .socket/vendor ledgers — nothing to attest. Run \
         `socket-patch scan` or `socket-patch get` first.\n",
        tmp.path().join("nope.json").display()
    );
    assert_eq!(stderr(&o), expected);
}

/// A corrupt manifest is not a missing one: the error names the parse
/// failure and the file, and no document reaches stdout.
#[test]
fn corrupt_manifest_error_names_the_file() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_corrupt_manifest(cwd);
    let o = vex(cwd, &[]);
    assert_eq!(o.status.code(), Some(2));
    assert!(o.stdout.is_empty(), "{}", stdout(&o));
    let err = stderr(&o);
    assert!(
        err.starts_with("Error: Failed to parse manifest JSON: "),
        "{err}"
    );
    assert!(err.contains(".socket/manifest.json)"), "{err}");
}

#[test]
fn product_undetected_names_the_unusable_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_npm_manifest(cwd, &["pkg:npm/a@1.0.0"]);
    std::fs::write(cwd.join("package.json"), r#"{"name":"app"}"#).unwrap();
    let o = vex_command(cwd, None).arg("--no-verify").output().unwrap();
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("(package.json was found but has no usable name and version)"),
        "{}",
        stderr(&o)
    );
}

/// The `redirect_ledger_corrupt` advisory is a stderr warning line, ahead
/// of the run's own outcome.
#[test]
fn corrupt_redirect_ledger_prints_a_warning_line() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_npm_manifest(cwd, &["pkg:npm/leftpad@1.0.0"]);
    write_corrupt_redirect_ledger(cwd);

    let o = vex(cwd, &[]);
    let err = stderr(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(
        err.lines().any(|l| l.starts_with("Warning:")
            && l.contains("pre-v5 redirect ledger")
            && l.contains("redirect-state.json")),
        "{err}"
    );
    assert!(err.contains("(package_not_found)"), "{err}");
    assert_redirect_ledger_untouched(cwd);
}

/// The `vendor_ledger_corrupt` error names the ledger, with or without a
/// manifest (never "Manifest not found"), and `--silent` never mutes it.
#[test]
fn corrupt_vendor_ledger_error_names_the_ledger() {
    for (with_manifest, silent) in [(true, false), (false, false), (false, true)] {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        if with_manifest {
            write_npm_manifest(cwd, &["pkg:npm/leftpad@1.0.0"]);
        }
        write_corrupt_vendor_ledger(cwd);

        let o = vex(cwd, if silent { &["--silent"] } else { &[] });
        let err = stderr(&o);
        assert_eq!(o.status.code(), Some(2), "{err}");
        assert!(o.stdout.is_empty(), "no document: {}", stdout(&o));
        assert!(
            err.lines().any(|l| l.starts_with("Error:")
                && l.contains("vendor ledger")
                && l.contains("state.json")),
            "with_manifest={with_manifest} silent={silent}: {err}"
        );
        assert!(!err.contains("Manifest not found"), "{err}");
        assert!(
            !err.contains("omitting"),
            "the ledger error fires before verification: {err}"
        );
        assert_vendor_ledger_untouched(cwd);
    }
}

/// The multi-manifest auto-detect warning names the manifest it used, and
/// `--silent` suppresses it without changing the document.
#[test]
fn multi_manifest_auto_detect_warning_and_silent() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_multi_manifest_project(cwd);
    let out_path = cwd.join("out.vex.json");

    for silent in [false, true] {
        let mut cmd = vex_command(cwd, None);
        cmd.args(["--no-verify", "--output", out_path.to_str().unwrap()]);
        if silent {
            cmd.arg("--silent");
        }
        let o = cmd.output().expect("invoke vex");
        let err = stderr(&o);
        assert_eq!(o.status.code(), Some(0), "{err}");
        let warned = err
            .lines()
            .any(|l| l.contains("Multiple project manifests") && l.contains("using package.json"));
        assert_eq!(warned, !silent, "silent={silent}: {err}");
        if silent {
            assert!(o.stdout.is_empty(), "{}", stdout(&o));
        }
        assert_eq!(
            read_doc(&out_path)["statements"][0]["products"][0]["@id"],
            PRODUCT
        );
    }
}
