//! End-to-end tests for redirect-patch awareness in `socket-patch vex`.
//!
//! `socket-patch scan --redirect` rewrites lockfiles so a patched dependency
//! resolves from Socket's HOSTED vendored patch, and records the patch (file
//! hashes + vulnerabilities) in `.socket/vendor/redirect-state.json`. After the
//! package manager installs, the patched bytes land in the installed tree, so
//! `vex` attests those patches against the installed tree exactly as it does
//! for `apply` — with a `(redirected)` provenance marker. Coverage:
//!
//!   1. redirected PURL attested against the installed tree, `(redirected)`
//!      marker (the post-install verified path)
//!   2. property-7 exemption: a redirected patch bypasses the configured/manual
//!      ecosystem filter (the lockfile rewrite is the persistence), while a
//!      plain unconfigured control is dropped
//!   3. tampered installed file → omitted with skip reason `hash_mismatch`
//!      (fail-closed)
//!   4. `--no-verify` attests from the ledger records with NO installed tree
//!      (the same shape as the in-run `scan --redirect --vex` attestation)

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use serde_json::Value;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo,
};
use socket_patch_core::patch::redirect::RedirectState;

const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const PRODUCT: &str = "pkg:npm/app@1.0.0";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_socket-patch")
}

/// CLI invocation with the ambient `SOCKET_*` environment scrubbed (explicit
/// flags must be the sole source of truth).
fn cli() -> Command {
    let mut cmd = Command::new(binary());
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") {
            cmd.env_remove(key);
        }
    }
    cmd
}

/// Patch record with one npm-shaped file (`package/…`) and one vulnerability.
fn make_record(uuid: &str, after_hash: &str, vuln_id: &str, cves: &[&str]) -> PatchRecord {
    let mut files = HashMap::new();
    files.insert(
        "package/index.js".to_string(),
        PatchFileInfo {
            before_hash: "a".repeat(64),
            after_hash: after_hash.to_string(),
        },
    );
    let mut vulns = HashMap::new();
    vulns.insert(
        vuln_id.to_string(),
        VulnerabilityInfo {
            cves: cves.iter().map(|s| s.to_string()).collect(),
            summary: "test summary".to_string(),
            severity: "high".to_string(),
            description: "test description".to_string(),
        },
    );
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: "2024-01-01T00:00:00Z".to_string(),
        files,
        vulnerabilities: vulns,
        description: format!("Patch {uuid}"),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

/// Write a `.socket/vendor/redirect-state.json` ledger embedding `record` for
/// `purl` (the shape `scan --redirect` persists for VEX).
fn write_redirect_state(cwd: &Path, purl: &str, record: PatchRecord) {
    let mut state = RedirectState::new();
    state.records.insert(purl.to_string(), record);
    let dir = cwd.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("redirect-state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();
}

/// Lay down an installed npm package `node_modules/<name>/index.js` with
/// `installed` bytes + a root package.json so the crawler resolves it to the
/// PURL. Returns the PURL.
fn scaffold_npm(cwd: &Path, name: &str, version: &str, installed: &[u8]) -> String {
    std::fs::write(
        cwd.join("package.json"),
        format!(
            r#"{{ "name": "app", "version": "1.0.0", "dependencies": {{ "{name}": "{version}" }} }}"#
        ),
    )
    .unwrap();
    let pkg = cwd.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), installed).unwrap();
    format!("pkg:npm/{name}@{version}")
}

// ──────────────────────────────────────────────────────────────────────
// 1. redirected PURL attested against the installed tree (verified path)
// ──────────────────────────────────────────────────────────────────────

#[test]
fn redirected_purl_attested_against_installed_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    // Post-install: the installed tree holds the patched bytes (the redirect
    // pulled them from the hosted patch server), matching the record's hash.
    let patched = b"redirected patched index\n";
    let after = compute_git_sha256_from_bytes(patched);
    let purl = scaffold_npm(cwd, "left-pad", "1.3.0", patched);
    write_redirect_state(cwd, &purl, make_record(UUID, &after, "GHSA-rdir-1111", &["CVE-2024-1"]));
    assert!(
        !cwd.join(".socket/manifest.json").exists(),
        "fixture sanity: a redirect project has no manifest"
    );

    let out = cli()
        .args(["vex", "--cwd", cwd.to_str().unwrap(), "--product", PRODUCT])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "redirected patch must verify against the installed tree. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let doc: Value = serde_json::from_slice(&out.stdout).expect("VEX JSON on stdout");
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "the redirected patch must be attested: {doc}");
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-rdir-1111");
    assert_eq!(stmts[0]["status"], "not_affected");
    assert_eq!(stmts[0]["products"][0]["subcomponents"][0]["@id"], purl);
    assert_eq!(
        stmts[0]["impact_statement"].as_str().unwrap(),
        format!("Patched via Socket patch {UUID} (redirected)"),
        "redirected attestation must carry the (redirected) marker"
    );
}

// ──────────────────────────────────────────────────────────────────────
// 2. property-7 exemption — a redirected patch bypasses the filter
// ──────────────────────────────────────────────────────────────────────

#[test]
fn redirected_purl_bypasses_property7_filter() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    // Redirected npm patch: verifies + bypasses property 7.
    let patched = b"redirected patched index\n";
    let after = compute_git_sha256_from_bytes(patched);
    let purl = scaffold_npm(cwd, "left-pad", "1.3.0", patched);
    write_redirect_state(cwd, &purl, make_record(UUID, &after, "GHSA-rdir-keep", &["CVE-2024-2"]));

    // Control: a plain manifest npm patch that VERIFIES against node_modules
    // but is neither redirected nor set up / manual — property 7 must drop it,
    // proving the filter ran while the redirected patch sailed through.
    let ctrl_patched = b"control patched index\n";
    let ctrl_after = compute_git_sha256_from_bytes(ctrl_patched);
    let ctrl_pkg = cwd.join("node_modules/control-pkg");
    std::fs::create_dir_all(&ctrl_pkg).unwrap();
    std::fs::write(
        ctrl_pkg.join("package.json"),
        r#"{"name":"control-pkg","version":"2.0.0"}"#,
    )
    .unwrap();
    std::fs::write(ctrl_pkg.join("index.js"), ctrl_patched).unwrap();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/control-pkg@2.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            &ctrl_after,
            "GHSA-npm-control",
            &["CVE-2024-3"],
        ),
    );
    // NO setup section: nothing configured, nothing manual.
    let dir = cwd.join(".socket");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let out = cli()
        .args(["vex", "--cwd", cwd.to_str().unwrap(), "--product", PRODUCT])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "the redirected patch must be attested without setup/manual. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).unwrap();
    let doc: Value = serde_json::from_str(&stdout).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "only the redirected patch bypasses property 7; the unconfigured npm \
         control must be dropped. doc:\n{stdout}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-rdir-keep");
    assert!(
        !stdout.contains("GHSA-npm-control"),
        "the non-redirected, non-configured control must be filtered:\n{stdout}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// 3. fail-closed — a tampered installed file omits the redirected patch
// ──────────────────────────────────────────────────────────────────────

#[test]
fn tampered_installed_file_omits_redirected_patch() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    // The installed file does NOT hash to the record's afterHash.
    let after = compute_git_sha256_from_bytes(b"what the patch should contain\n");
    let purl = scaffold_npm(cwd, "left-pad", "1.3.0", b"tampered installed bytes\n");
    write_redirect_state(cwd, &purl, make_record(UUID, &after, "GHSA-rdir-bad", &["CVE-2024-4"]));

    let vex_path = cwd.join("out.vex.json");
    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--json",
            "--output",
            vex_path.to_str().unwrap(),
            "--product",
            PRODUCT,
        ])
        .output()
        .expect("invoke vex");

    // The only patch failed verification → soft "nothing to attest".
    assert_eq!(
        out.status.code(),
        Some(1),
        "tampered installed file must not be attested. stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let env: Value = serde_json::from_slice(&out.stdout).expect("envelope JSON on stdout");
    assert_eq!(env["status"], "error");
    assert_eq!(env["error"]["code"], "no_applicable_patches");
    let events = env["events"].as_array().unwrap();
    let skipped = events
        .iter()
        .find(|e| e["action"] == "skipped" && e["purl"] == purl)
        .unwrap_or_else(|| panic!("expected a skipped event for the tampered purl: {env}"));
    assert_eq!(
        skipped["errorCode"], "hash_mismatch",
        "a redirected patch verifies against the installed tree, so the reason \
         is the installed-tree hash_mismatch: {skipped}"
    );
    assert!(
        !vex_path.exists(),
        "no VEX doc may be written when nothing attests"
    );
}

// ──────────────────────────────────────────────────────────────────────
// 4. --no-verify attests from the ledger with NO installed tree — the same
// shape as the in-run `scan --redirect --vex` attestation (bytes are remote,
// fetched at install time, so there is nothing to hash yet).
// ──────────────────────────────────────────────────────────────────────

#[test]
fn redirected_no_verify_attests_without_installed_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purl = "pkg:npm/left-pad@1.3.0";

    // No node_modules, no manifest — the redirect ledger is the only source.
    write_redirect_state(
        cwd,
        purl,
        make_record(UUID, &"b".repeat(64), "GHSA-rdir-nv", &["CVE-2024-5"]),
    );

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--product",
            PRODUCT,
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "--no-verify must attest the redirected patch with no installed tree. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let doc: Value = serde_json::from_slice(&out.stdout).expect("VEX JSON on stdout");
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "the redirected patch must be attested: {doc}");
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-rdir-nv");
    assert_eq!(
        stmts[0]["impact_statement"].as_str().unwrap(),
        format!("Patched via Socket patch {UUID} (redirected)"),
    );
}

// ──────────────────────────────────────────────────────────────────────
// 5. every ecosystem attests through the redirect ledger, including the
// ones whose crawler/feature isn't compiled by default (maven/nuget/
// composer) and the qualified-PURL variants (pypi `?artifact_id=`, gem
// `?platform=`, maven `?classifier=&ext=`). The redirect bypass means these
// need neither the ecosystem's cargo feature nor a real toolchain, and the
// qualified PURL must survive verbatim as the subcomponent id.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn no_verify_attests_redirected_patches_across_ecosystems() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    let cases: &[(&str, &str)] = &[
        ("pkg:npm/left-pad@1.3.0", "GHSA-eco-npm"),
        ("pkg:pypi/six@1.16.0?artifact_id=sdist", "GHSA-eco-pypi"),
        ("pkg:cargo/serde@1.0.0", "GHSA-eco-cargo"),
        ("pkg:gem/rack@2.2.3?platform=ruby", "GHSA-eco-gem"),
        ("pkg:golang/github.com/foo/bar@v1.4.2", "GHSA-eco-golang"),
        (
            "pkg:maven/org.example/lib@1.0.0?classifier=native&ext=jar",
            "GHSA-eco-maven",
        ),
        ("pkg:nuget/Newtonsoft.Json@13.0.1", "GHSA-eco-nuget"),
        ("pkg:composer/monolog/monolog@2.0.0", "GHSA-eco-composer"),
    ];

    let mut state = RedirectState::new();
    for (purl, ghsa) in cases {
        state
            .records
            .insert(purl.to_string(), make_record(UUID, &"b".repeat(64), ghsa, &["CVE-2024-1"]));
    }
    let dir = cwd.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("redirect-state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--product",
            PRODUCT,
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "every ecosystem's redirected patch must attest. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let doc: Value = serde_json::from_slice(&out.stdout).expect("VEX JSON on stdout");
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        cases.len(),
        "every ecosystem's redirected patch must be attested: {doc}"
    );
    for (purl, ghsa) in cases {
        let st = stmts
            .iter()
            .find(|s| s["vulnerability"]["name"] == *ghsa)
            .unwrap_or_else(|| panic!("missing statement for {ghsa}: {doc}"));
        assert_eq!(st["status"], "not_affected");
        assert!(
            st["impact_statement"]
                .as_str()
                .unwrap()
                .contains("(redirected)"),
            "{ghsa} must carry the (redirected) marker"
        );
        assert_eq!(
            st["products"][0]["subcomponents"][0]["@id"], *purl,
            "the (possibly qualified) PURL must survive verbatim as the subcomponent id"
        );
    }
}
