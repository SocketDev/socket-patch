//! Terminal-output contract for the standalone `vex` command: what a human
//! (and a `--json` consumer) sees for dry runs, `-O -`, stale-document
//! cleanup, omission reporting and flag typos. Fixtures are self-contained
//! tempdir projects driven through the built binary with a scrubbed
//! `SOCKET_*` environment (the parent env is never mutated).

use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, SetupConfig, VulnerabilityInfo,
};

const STALE_OPENVEX_DOC: &str = r#"{"@context":"https://openvex.dev/ns/v0.2.0","@id":"urn:uuid:stale","author":"Socket","timestamp":"2020-01-01T00:00:00Z","version":1,"statements":[]}"#;

fn cli() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    cmd
}

fn record(uuid: &str, ghsa: &str) -> PatchRecord {
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
        ghsa.to_string(),
        VulnerabilityInfo {
            cves: vec!["CVE-2026-0001".to_string()],
            summary: "s".to_string(),
            severity: "high".to_string(),
            description: "d".to_string(),
        },
    );
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: "2024-01-01T00:00:00Z".to_string(),
        files,
        vulnerabilities: vulns,
        description: "p".to_string(),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

/// A manifest with `purls` (each with a distinct GHSA). `manual` declares
/// npm so the property-7 setup filter keeps the patches; `None` leaves the
/// ecosystem un-set-up.
fn write_manifest(cwd: &Path, purls: &[&str], manual: bool) {
    let mut m = PatchManifest::new();
    for (i, purl) in purls.iter().enumerate() {
        m.patches.insert(
            purl.to_string(),
            record(
                &format!("{:08}-1111-4111-8111-111111111111", i + 1),
                &format!("GHSA-test-{i}"),
            ),
        );
    }
    if manual {
        m.setup = Some(SetupConfig {
            exclude: Vec::new(),
            manual: vec!["npm".to_string()],
        });
    }
    let dir = cwd.join(".socket");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&m).unwrap(),
    )
    .unwrap();
}

fn vex(cwd: &Path, extra: &[&str]) -> Output {
    cli()
        .current_dir(cwd)
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .args(extra)
        .output()
        .expect("invoke vex")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn dry_run_with_output_writes_nothing_and_says_so() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_manifest(cwd, &["pkg:npm/a@1.0.0"], true);
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

    let o = vex(
        cwd,
        &[
            "--no-verify",
            "--dry-run",
            "--json",
            "-O",
            out_path.to_str().unwrap(),
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let env: Value = serde_json::from_slice(&o.stdout).expect("envelope");
    assert_eq!(env["dryRun"], true, "{env}");
    assert!(!out_path.exists());
}

#[test]
fn dry_run_failure_keeps_previous_document() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    // Verify mode with nothing installed: nothing attests.
    write_manifest(cwd, &["pkg:npm/a@1.0.0"], true);
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
    write_manifest(cwd, &["pkg:npm/a@1.0.0"], true);

    let o = vex(cwd, &["--no-verify", "-O", "-"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let doc: Value = serde_json::from_slice(&o.stdout).expect("document on stdout");
    assert_eq!(doc["statements"].as_array().unwrap().len(), 1);
    assert!(!cwd.join("-").exists(), "no file literally named `-`");
    assert_eq!(stderr(&o).trim_end(), "Emitted 1 VEX statement");

    // --json still needs a real file: the envelope owns stdout.
    let o = vex(cwd, &["--no-verify", "--json", "-O", "-"]);
    assert_eq!(o.status.code(), Some(2));
    let env: Value = serde_json::from_slice(&o.stdout).expect("envelope");
    assert_eq!(env["error"]["code"], "json_requires_output", "{env}");
}

#[test]
fn written_document_ends_with_newline_and_summary_is_singular() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_manifest(cwd, &["pkg:npm/a@1.0.0"], true);
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
    write_manifest(cwd, &["pkg:npm/a@1.0.0"], true);
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

    std::fs::write(&out_path, STALE_OPENVEX_DOC).unwrap();
    let o = vex(cwd, &["--json", "-O", out_path.to_str().unwrap()]);
    let env: Value = serde_json::from_slice(&o.stdout).expect("envelope");
    assert!(
        env["warnings"]
            .as_array()
            .is_some_and(|w| w.iter().any(|w| w["code"] == "vex_stale_doc_removed")),
        "{env}"
    );
    assert!(
        !stderr(&o).contains("Removed the previous"),
        "--json keeps stderr clean"
    );
}

#[test]
fn omissions_are_sorted_and_listed_once() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purls = [
        "pkg:npm/zeta@1.0.0",
        "pkg:npm/alpha@1.0.0",
        "pkg:npm/mid@1.0.0",
    ];
    write_manifest(cwd, &purls, true);

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

    // The JSON skipped events come out in the same order.
    let out_path = cwd.join("o.json");
    let o = vex(cwd, &["--json", "-O", out_path.to_str().unwrap()]);
    let env: Value = serde_json::from_slice(&o.stdout).expect("envelope");
    let order: Vec<&str> = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["purl"].as_str().unwrap())
        .collect();
    assert_eq!(
        order,
        vec![
            "pkg:npm/alpha@1.0.0",
            "pkg:npm/mid@1.0.0",
            "pkg:npm/zeta@1.0.0"
        ]
    );
    assert_eq!(
        env["events"][0]["reason"],
        "patch omitted from VEX: the package is not installed"
    );
}

#[test]
fn all_setup_drops_skip_the_generic_note() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    // No `manual`, no hook: property 7 drops the (trusted) patch.
    write_manifest(cwd, &["pkg:npm/a@1.0.0"], false);

    let o = vex(cwd, &["--no-verify"]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    let err = stderr(&o);
    assert!(!err.contains("Note:"), "{err}");
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(lines.len(), 2, "{err}");
    assert!(lines[0].starts_with("Warning: omitting pkg:npm/a@1.0.0 from VEX: applied, but"));
    assert!(lines[0].ends_with("(ecosystem_not_setup)"), "{err}");
    assert!(
        lines[1].starts_with(
            "Error: 1 applied patch with vulnerability metadata was omitted from VEX because \
             its ecosystem is not set up"
        ),
        "{err}"
    );
}

#[test]
fn org_that_looks_like_a_file_warns() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_manifest(cwd, &["pkg:npm/a@1.0.0"], true);

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

#[test]
fn corrupt_manifest_error_names_the_file() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    std::fs::create_dir_all(cwd.join(".socket")).unwrap();
    std::fs::write(cwd.join(".socket/manifest.json"), "{not json").unwrap();
    let o = vex(cwd, &[]);
    assert_eq!(o.status.code(), Some(2));
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
    write_manifest(cwd, &["pkg:npm/a@1.0.0"], true);
    std::fs::write(cwd.join("package.json"), r#"{"name":"app"}"#).unwrap();
    let o = cli()
        .args(["vex", "--no-verify", "--cwd", cwd.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("(package.json was found but has no usable name and version)"),
        "{}",
        stderr(&o)
    );
}
