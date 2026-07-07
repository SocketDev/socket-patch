//! End-to-end tests for the `socket-patch vex` subcommand.
//!
//! Validates the OpenVEX document shape produced by a real invocation
//! of the compiled binary. When `vexctl` is on `PATH` the test also
//! pipes the output through `vexctl validate` to confirm spec
//! conformance — the CI workflow installs vexctl before the test
//! step, so this branch is exercised in CI.
//!
//! Layered tests (no-network, no-disk-state required):
//!   1. `--no-verify` against a fixture manifest with multi-CVE vulns
//!   2. `--no-verify` with two patches sharing a GHSA (alias-merge path)
//!   3. error path: empty manifest exits non-zero with no doc
//!   4. verify-mode against patched files laid on disk
//!   5. verify-mode where one patch file is missing → omitted + warning

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use serde_json::Value;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, SetupConfig, VulnerabilityInfo,
};

/// Setup-supported ecosystems, declared `manual` in test fixtures so the
/// property-7 setup-state filter (`commands/setup::configured_ecosystems`)
/// does not drop these patches — these tests exercise VEX document
/// GENERATION, not setup state, so they opt every patch in via the `manual`
/// escape hatch. The apply-only ecosystems (maven/nuget) are appended by
/// [`all_manual`].
const ALL_MANUAL: &[&str] = &["npm", "pypi", "cargo", "golang", "gem", "composer"];

/// [`ALL_MANUAL`] plus the apply-only ecosystems (maven/nuget), so the
/// all-ecosystem agent matrix below can declare every one of the 8.
fn all_manual() -> Vec<String> {
    let mut names: Vec<String> = ALL_MANUAL.iter().map(|s| (*s).to_string()).collect();
    names.push("maven".to_string());
    names.push("nuget".to_string());
    names
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_socket-patch")
}

/// Build a `Command` for the CLI with the entire `SOCKET_*` environment
/// scrubbed from the child process.
///
/// Every flag these tests rely on has an env fallback: `--product`/
/// `SOCKET_VEX_PRODUCT`, `--no-verify`/`SOCKET_VEX_NO_VERIFY`, `--doc-id`/
/// `SOCKET_VEX_DOC_ID`, `--output`/`SOCKET_VEX_OUTPUT`, `--compact`/
/// `SOCKET_VEX_COMPACT`, plus the `GlobalArgs` set (`SOCKET_JSON`,
/// `SOCKET_OFFLINE`, `SOCKET_ECOSYSTEMS`, `SOCKET_GLOBAL_PREFIX`,
/// `SOCKET_CWD`, `SOCKET_MANIFEST_PATH`, `SOCKET_API_TOKEN`, …). If the
/// ambient environment leaks any of these into the child, a test silently
/// stops exercising the path it names — an exported `SOCKET_VEX_NO_VERIFY`
/// would route the verify-mode tests through the no-verify path (so the
/// on-disk hash check is never run), and an exported `SOCKET_VEX_PRODUCT`
/// would defeat both auto-detect tests by supplying the product the test
/// claims the binary inferred. Removing the whole prefix from the child
/// (the parent env is never mutated, so tests stay independent and need no
/// serialization) makes the explicit CLI flags the sole source of truth.
fn cli() -> Command {
    let mut cmd = Command::new(binary());
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") {
            cmd.env_remove(key);
        }
    }
    cmd
}

/// Write `manifest` to `<cwd>/.socket/manifest.json`.
fn write_manifest(cwd: &Path, manifest: &PatchManifest) {
    let dir = cwd.join(".socket");
    std::fs::create_dir_all(&dir).unwrap();
    let mut m = manifest.clone();
    m.setup = Some(SetupConfig {
        exclude: Vec::new(),
        manual: all_manual(),
    });
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&m).unwrap(),
    )
    .unwrap();
}

/// Patch record with one file (whose hashes you choose) and one
/// vulnerability.
fn make_record(
    uuid: &str,
    file_name: &str,
    before_hash: &str,
    after_hash: &str,
    vuln_id: &str,
    cves: &[&str],
) -> PatchRecord {
    let mut files = HashMap::new();
    files.insert(
        file_name.to_string(),
        PatchFileInfo {
            before_hash: before_hash.to_string(),
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

// ──────────────────────────────────────────────────────────────────────
// no-verify path
// ──────────────────────────────────────────────────────────────────────

#[test]
fn no_verify_emits_valid_openvex() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/lodash@4.17.20".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            "GHSA-aaaa-bbbb-cccc",
            &["CVE-2024-1111", "CVE-2024-1112"],
        ),
    );
    manifest.patches.insert(
        "pkg:npm/minimist@1.2.0".to_string(),
        make_record(
            "22222222-2222-4222-8222-222222222222",
            "package/index.js",
            "c".repeat(64).as_str(),
            "d".repeat(64).as_str(),
            "GHSA-dddd-eeee-ffff",
            &["CVE-2024-2222"],
        ),
    );
    write_manifest(cwd, &manifest);

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--product",
            "pkg:npm/test-app@1.0.0",
            "--doc-id",
            "urn:uuid:fixed-test-id",
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "vex exited non-zero. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).unwrap();
    let doc: Value = serde_json::from_str(&stdout).expect("vex stdout must be valid JSON");

    assert_eq!(doc["@context"], "https://openvex.dev/ns/v0.2.0");
    assert_eq!(doc["@id"], "urn:uuid:fixed-test-id");
    assert_eq!(doc["author"], "Socket");
    assert_eq!(doc["version"], 1);
    assert!(doc["tooling"]
        .as_str()
        .unwrap()
        .starts_with("socket-patch "));

    let statements = doc["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 2, "one statement per GHSA");

    // Statements are sorted by vuln id (BTreeMap order).
    let s0 = &statements[0];
    assert_eq!(s0["vulnerability"]["name"], "GHSA-aaaa-bbbb-cccc");
    let aliases = s0["vulnerability"]["aliases"].as_array().unwrap();
    assert_eq!(aliases.len(), 2);
    assert_eq!(aliases[0], "CVE-2024-1111");
    assert_eq!(aliases[1], "CVE-2024-1112");
    assert_eq!(s0["status"], "not_affected");
    assert_eq!(s0["justification"], "inline_mitigations_already_exist");

    let products = s0["products"].as_array().unwrap();
    assert_eq!(products.len(), 1);
    assert_eq!(products[0]["@id"], "pkg:npm/test-app@1.0.0");
    let subs = products[0]["subcomponents"].as_array().unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0]["@id"], "pkg:npm/lodash@4.17.20");

    maybe_validate_with_vexctl(&stdout);
}

#[test]
fn two_patches_sharing_ghsa_merge_subcomponents() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/foo@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/a.js",
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            "GHSA-shared",
            &["CVE-SHARED"],
        ),
    );
    manifest.patches.insert(
        "pkg:npm/bar@2.0.0".to_string(),
        make_record(
            "22222222-2222-4222-8222-222222222222",
            "package/b.js",
            "c".repeat(64).as_str(),
            "d".repeat(64).as_str(),
            "GHSA-shared",
            &["CVE-SHARED"],
        ),
    );
    write_manifest(cwd, &manifest);

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(out.status.success());

    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "shared GHSA collapses into one statement");

    let subs = stmts[0]["products"][0]["subcomponents"].as_array().unwrap();
    assert_eq!(subs.len(), 2);
    let ids: Vec<&str> = subs.iter().map(|s| s["@id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"pkg:npm/foo@1.0.0"));
    assert!(ids.contains(&"pkg:npm/bar@2.0.0"));
}

// ──────────────────────────────────────────────────────────────────────
// Cross-ecosystem AGENT matrix — the agent-mode twin of
// `e2e_vex_redirect::no_verify_attests_redirected_patches_across_ecosystems`.
// One manifest patch per official ecosystem (qualified PURLs for the
// release-variant ones: pypi `?artifact_id=`, gem `?platform=`, maven
// `?classifier=&ext=`), `setup.manual` declaring every ecosystem (via
// `all_manual`) so property 7 keeps them all, and `--no-verify` attests
// straight from the manifest with no installed tree.
//
// Unlike the redirect matrix — whose patches bypass BOTH property 7 and
// `Ecosystem::from_purl` via the `redirected` set — an agent patch routes
// through `Ecosystem::from_purl` + the `manual` allowlist. Each statement must
// carry a PLAIN impact statement (NO `(vendored)`/`(redirected)` marker — that
// is what distinguishes agent provenance) and preserve the (possibly
// qualified) PURL verbatim as the subcomponent id.
#[test]
fn no_verify_attests_agent_patches_across_ecosystems() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    // (manifest purl, GHSA id, patch uuid). Distinct uuids so each statement's
    // plain impact string is uniquely pinned to its patch.
    let cases: &[(&str, &str, &str)] = &[
        (
            "pkg:npm/left-pad@1.3.0",
            "GHSA-eco-npm",
            "11111111-1111-4111-8111-111111111111",
        ),
        (
            "pkg:pypi/six@1.16.0?artifact_id=sdist",
            "GHSA-eco-pypi",
            "22222222-2222-4222-8222-222222222222",
        ),
        (
            "pkg:cargo/serde@1.0.0",
            "GHSA-eco-cargo",
            "33333333-3333-4333-8333-333333333333",
        ),
        (
            "pkg:gem/rack@2.2.3?platform=ruby",
            "GHSA-eco-gem",
            "44444444-4444-4444-8444-444444444444",
        ),
        (
            "pkg:golang/github.com/foo/bar@v1.4.2",
            "GHSA-eco-golang",
            "55555555-5555-4555-8555-555555555555",
        ),
        (
            "pkg:maven/org.example/lib@1.0.0?classifier=native&ext=jar",
            "GHSA-eco-maven",
            "66666666-6666-4666-8666-666666666666",
        ),
        (
            "pkg:nuget/Newtonsoft.Json@13.0.1",
            "GHSA-eco-nuget",
            "77777777-7777-4777-8777-777777777777",
        ),
        (
            "pkg:composer/monolog/monolog@2.0.0",
            "GHSA-eco-composer",
            "88888888-8888-4888-8888-888888888888",
        ),
    ];

    let mut manifest = PatchManifest::new();
    for (purl, ghsa, uuid) in cases {
        manifest.patches.insert(
            purl.to_string(),
            make_record(
                uuid,
                "package/index.js",
                "a".repeat(64).as_str(),
                "b".repeat(64).as_str(),
                ghsa,
                &["CVE-2024-1"],
            ),
        );
    }
    // write_manifest stamps setup.manual = all_manual(), which declares
    // every one of the 8 ecosystems.
    write_manifest(cwd, &manifest);

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "every ecosystem's agent patch must attest. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let doc: Value = serde_json::from_slice(&out.stdout).expect("VEX JSON on stdout");
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        cases.len(),
        "every ecosystem's agent patch must be attested (one statement each): {doc}"
    );
    for (purl, ghsa, uuid) in cases {
        let st = stmts
            .iter()
            .find(|s| s["vulnerability"]["name"] == *ghsa)
            .unwrap_or_else(|| panic!("missing statement for {ghsa}: {doc}"));
        assert_eq!(st["status"], "not_affected");
        let impact = st["impact_statement"]
            .as_str()
            .unwrap_or_else(|| panic!("impact_statement missing for {ghsa}: {doc}"));
        // Plain agent phrasing — the exact-equality check simultaneously proves
        // there is NO `(vendored)`/`(redirected)` provenance marker appended.
        assert_eq!(
            impact,
            format!("Patched via Socket patch {uuid}"),
            "{ghsa} must carry the PLAIN agent impact statement (no provenance marker)"
        );
        assert!(
            !impact.contains("(vendored)") && !impact.contains("(redirected)"),
            "{ghsa} agent attestation must have no provenance marker: {impact}"
        );
        assert_eq!(
            st["products"][0]["subcomponents"][0]["@id"], *purl,
            "the (possibly qualified) PURL must survive verbatim as the subcomponent id"
        );
    }

    maybe_validate_with_vexctl(&String::from_utf8_lossy(&out.stdout));
}

#[test]
fn empty_manifest_exits_non_zero_with_no_doc() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_manifest(cwd, &PatchManifest::new());

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    // Empty manifest is the soft "nothing to attest" case → exit 1
    // (distinct from a missing/unreadable manifest, which is exit 2).
    assert_eq!(
        out.status.code(),
        Some(1),
        "empty manifest must exit 1 (no_patches). stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Nothing on stdout — the VEX itself isn't written.
    assert!(
        out.stdout.is_empty(),
        "stdout should be empty when no doc is produced. got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Error"), "got: {stderr}");
    assert!(
        stderr.contains("Manifest is empty"),
        "stderr must explain the manifest is empty, not some other error. got: {stderr}"
    );
}

#[test]
fn missing_manifest_exits_non_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let out = cli()
        .args([
            "vex",
            "--cwd",
            tmp.path().to_str().unwrap(),
            "--no-verify",
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    // Missing manifest is a hard failure → exit 2 (not the soft exit-1
    // "empty manifest" case).
    assert_eq!(
        out.status.code(),
        Some(2),
        "missing manifest must exit 2 (manifest_not_found). stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty(), "no doc when manifest is missing");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Manifest not found"), "got: {stderr}");
}

#[test]
fn json_envelope_requires_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), &PatchManifest::new());

    let out = cli()
        .args([
            "vex",
            "--cwd",
            tmp.path().to_str().unwrap(),
            "--no-verify",
            "--json",
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(!out.status.success());
    // --json forces envelope-on-stdout, which we then assert lives in stdout.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let env: Value = serde_json::from_str(&stdout).expect("envelope JSON");
    assert_eq!(env["status"], "error");
    assert_eq!(env["error"]["code"], "json_requires_output");
}

#[test]
fn json_envelope_with_output_emits_both() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/x@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            "GHSA-zzzz",
            &["CVE-9999"],
        ),
    );
    write_manifest(cwd, &manifest);
    let vex_path = cwd.join("out.vex.json");

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--json",
            "--output",
            vex_path.to_str().unwrap(),
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(out.status.success());

    // Envelope on stdout.
    let env: Value = serde_json::from_slice(&out.stdout).expect("envelope JSON");
    assert_eq!(env["command"], "vex");
    assert_eq!(env["status"], "success");
    assert_eq!(env["summary"]["verified"], 1);

    // VEX doc at --output.
    let vex_text = std::fs::read_to_string(&vex_path).unwrap();
    let doc: Value = serde_json::from_str(&vex_text).unwrap();
    assert_eq!(doc["@context"], "https://openvex.dev/ns/v0.2.0");
    assert_eq!(doc["statements"].as_array().unwrap().len(), 1);

    maybe_validate_with_vexctl(&vex_text);
}

#[test]
fn auto_detect_prefers_git_remote_over_package_json() {
    // Both signals present; the binary must surface the git-remote PURL.
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    std::fs::write(
        cwd.join("package.json"),
        r#"{"name":"from-pkg","version":"1.0.0"}"#,
    )
    .unwrap();
    let git_dir = cwd.join(".git");
    std::fs::create_dir_all(&git_dir).unwrap();
    std::fs::write(
        git_dir.join("config"),
        "[remote \"origin\"]\n\turl = git@github.com:SocketDev/socket-patch.git\n",
    )
    .unwrap();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/x@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            "GHSA-zz",
            &["CVE-ZZ"],
        ),
    );
    write_manifest(cwd, &manifest);

    let out = cli()
        .args(["vex", "--cwd", cwd.to_str().unwrap(), "--no-verify"])
        .output()
        .expect("invoke vex");
    assert!(out.status.success());
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        doc["statements"][0]["products"][0]["@id"],
        "pkg:github/SocketDev/socket-patch"
    );
}

#[test]
fn auto_detect_uses_package_json() {
    // When --product is omitted the binary reads `package.json` for the
    // product PURL. We don't lay down node_modules so we pair this with
    // --no-verify.
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    std::fs::write(
        cwd.join("package.json"),
        r#"{"name":"my-app","version":"7.7.7"}"#,
    )
    .unwrap();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/x@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            "GHSA-z",
            &["CVE-Z"],
        ),
    );
    write_manifest(cwd, &manifest);

    let out = cli()
        .args(["vex", "--cwd", cwd.to_str().unwrap(), "--no-verify"])
        .output()
        .expect("invoke vex");
    assert!(out.status.success());
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        doc["statements"][0]["products"][0]["@id"],
        "pkg:npm/my-app@7.7.7"
    );
}

// ──────────────────────────────────────────────────────────────────────
// verify-mode tests — lay down patched files on disk and exercise the
// hash-check pipeline. We bypass ecosystem-crawler resolution by writing
// the manifest with PURLs whose npm package layout we control, then
// pointing --cwd at the synthetic node_modules.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn verify_mode_includes_applied_omits_unapplied() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    // Two npm packages — one we'll lay down "patched", one we won't.
    let nm = cwd.join("node_modules");
    let applied_pkg = nm.join("applied-pkg");
    std::fs::create_dir_all(&applied_pkg).unwrap();
    std::fs::write(
        applied_pkg.join("package.json"),
        r#"{"name":"applied-pkg","version":"1.0.0"}"#,
    )
    .unwrap();
    let patched_content = b"patched index";
    let after_hash = compute_git_sha256_from_bytes(patched_content);
    std::fs::write(applied_pkg.join("index.js"), patched_content).unwrap();

    let unapplied_pkg = nm.join("unapplied-pkg");
    std::fs::create_dir_all(&unapplied_pkg).unwrap();
    std::fs::write(
        unapplied_pkg.join("package.json"),
        r#"{"name":"unapplied-pkg","version":"2.0.0"}"#,
    )
    .unwrap();
    // No matching file on disk → verify reports file_not_found.

    // Third package: the file IS present, but it still holds the
    // ORIGINAL (un-patched) content — i.e. the patch was never applied.
    // This is the case that distinguishes a real hash check from a
    // presence-only check: an implementation that emitted a statement
    // for any package whose file merely exists would wrongly include
    // this one. Verify-mode must hash the file, see it equals
    // `beforeHash` (not `afterHash`), and omit it as `not_applied`.
    let tampered_pkg = nm.join("tampered-pkg");
    std::fs::create_dir_all(&tampered_pkg).unwrap();
    std::fs::write(
        tampered_pkg.join("package.json"),
        r#"{"name":"tampered-pkg","version":"3.0.0"}"#,
    )
    .unwrap();
    let original_content = b"original un-patched index";
    let before_hash_tampered = compute_git_sha256_from_bytes(original_content);
    // The "patched" content we claim the patch produces, but never write.
    let after_hash_tampered = compute_git_sha256_from_bytes(b"what the patch would write");
    assert_ne!(
        before_hash_tampered, after_hash_tampered,
        "before/after hashes must differ or the scenario is degenerate"
    );
    std::fs::write(tampered_pkg.join("index.js"), original_content).unwrap();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/applied-pkg@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            "a".repeat(64).as_str(),
            after_hash.as_str(),
            "GHSA-applied",
            &["CVE-APPLIED"],
        ),
    );
    manifest.patches.insert(
        "pkg:npm/unapplied-pkg@2.0.0".to_string(),
        make_record(
            "22222222-2222-4222-8222-222222222222",
            "package/missing.js",
            "c".repeat(64).as_str(),
            "d".repeat(64).as_str(),
            "GHSA-unapplied",
            &["CVE-UNAPPLIED"],
        ),
    );
    manifest.patches.insert(
        "pkg:npm/tampered-pkg@3.0.0".to_string(),
        make_record(
            "33333333-3333-4333-8333-333333333333",
            "package/index.js",
            before_hash_tampered.as_str(),
            after_hash_tampered.as_str(),
            "GHSA-tampered",
            &["CVE-TAMPERED"],
        ),
    );
    write_manifest(cwd, &manifest);

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--product",
            "pkg:npm/test-app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "verify mode should succeed when at least one patch verifies. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout.clone()).unwrap();
    let doc: Value = serde_json::from_str(&stdout).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "only the patch whose on-disk file hashes to afterHash should appear; \
         the un-applied (file missing) and tampered (file at beforeHash) \
         patches must both be omitted. doc:\n{stdout}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-applied");
    // The lone statement's subcomponent must be the genuinely-applied pkg.
    let subs = stmts[0]["products"][0]["subcomponents"].as_array().unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0]["@id"], "pkg:npm/applied-pkg@1.0.0");
    // Neither omitted vuln may leak anywhere into the emitted document.
    assert!(
        !stdout.contains("GHSA-unapplied"),
        "the unapplied patch's vuln must not appear in the VEX doc:\n{stdout}"
    );
    assert!(
        !stdout.contains("GHSA-tampered"),
        "the tampered (file-present-but-unpatched) patch's vuln must not \
         appear in the VEX doc — a presence-only check would wrongly emit \
         it:\n{stdout}"
    );

    // Both omissions must surface on stderr, each routed with its own
    // verification reason (the warning format is
    // "omitting patch for <purl> from VEX (<reason>)").
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unapplied-pkg") && stderr.contains("file_not_found"),
        "stderr should warn that unapplied-pkg was omitted as file_not_found. \
         got: {stderr}"
    );
    assert!(
        stderr.contains("tampered-pkg") && stderr.contains("not_applied"),
        "stderr should warn that tampered-pkg was omitted as not_applied — \
         this is what proves the on-disk hash was actually checked. \
         got: {stderr}"
    );

    maybe_validate_with_vexctl(&stdout);
}

#[test]
fn verify_mode_all_failed_exits_non_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/ghost@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            "GHSA-ghost",
            &["CVE-GHOST"],
        ),
    );
    write_manifest(cwd, &manifest);

    // No node_modules, no package directory — ecosystem dispatch returns
    // empty map, every patch lands in `failed` → no statements → exit 1.
    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    // All patches failed verification → soft "nothing to attest" → exit 1.
    assert_eq!(
        out.status.code(),
        Some(1),
        "all-failed verify must exit 1 (no_applicable_patches). stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("No applied patches"), "got: {stderr}");
    // The single ghost patch must be reported as omitted (it was found
    // in neither node_modules nor a package dir → package_not_found).
    assert!(
        stderr.contains("ghost") && stderr.contains("package_not_found"),
        "stderr should name the omitted ghost patch and its reason. got: {stderr}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Release-variant verify-mode regression — PyPI manifests key patches by
// *qualified* PURLs (`?artifact_id=`), but the crawler only knows the base
// PURL. `vex` must resolve package paths with the qualified-aware
// (rollback) dispatcher, exactly like `get`/`rollback` do; otherwise every
// PyPI/Gem/Maven patch is silently dropped from the VEX doc as
// `package_not_found`. We drive the PyPI crawler at a synthetic
// `site-packages` via `--global-prefix` to keep the test offline.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn verify_mode_resolves_qualified_pypi_purl() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    // Synthetic site-packages with a dist-info the crawler can read.
    let site_packages = cwd.join("site-packages");
    let dist_info = site_packages.join("examplepkg-1.2.3.dist-info");
    std::fs::create_dir_all(&dist_info).unwrap();
    std::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: examplepkg\nVersion: 1.2.3\n\n",
    )
    .unwrap();

    // Lay the patched file at the package root (file_name strips the
    // leading `package/` segment, so this lands at site-packages/mod.py).
    let patched = b"patched python module";
    let after_hash = compute_git_sha256_from_bytes(patched);
    std::fs::write(site_packages.join("mod.py"), patched).unwrap();

    // Manifest keyed by a *qualified* PyPI PURL, as `get --sync` writes
    // for release-variant ecosystems.
    let qualified_purl = "pkg:pypi/examplepkg@1.2.3?artifact_id=sdist";
    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        qualified_purl.to_string(),
        make_record(
            "33333333-3333-4333-8333-333333333333",
            "package/mod.py",
            "a".repeat(64).as_str(),
            after_hash.as_str(),
            "GHSA-pypi-variant",
            &["CVE-2024-PYPI"],
        ),
    );
    write_manifest(cwd, &manifest);

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--global-prefix",
            site_packages.to_str().unwrap(),
            "--ecosystems",
            "pypi",
            "--product",
            "pkg:pypi/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "qualified PyPI patch must verify and emit a statement. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "the qualified PyPI patch must not be dropped as package_not_found"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-pypi-variant");
    // The subcomponent retains the fully-qualified manifest PURL.
    let subs = stmts[0]["products"][0]["subcomponents"].as_array().unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0]["@id"], qualified_purl);

    maybe_validate_with_vexctl(&String::from_utf8_lossy(&out.stdout));
}

// ──────────────────────────────────────────────────────────────────────
// JSON-envelope partial-failure regression — verify mode where SOME
// patches verify and some don't. The doc is still generated (so the run
// succeeds, exit 0), but the envelope must report `partialFailure` and
// carry one `verified` event per applied subcomponent plus one `skipped`
// event (with the routing reason in `errorCode`) per omitted patch. This
// is the `--json` twin of `verify_mode_includes_applied_omits_unapplied`,
// which only exercised the human/stdout-doc path.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn json_envelope_partial_failure_on_mixed_verify() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    // One npm package laid down "patched" (file hashes to afterHash) and
    // one whose file is absent (verify reports file_not_found).
    let nm = cwd.join("node_modules");
    let applied_pkg = nm.join("applied-pkg");
    std::fs::create_dir_all(&applied_pkg).unwrap();
    std::fs::write(
        applied_pkg.join("package.json"),
        r#"{"name":"applied-pkg","version":"1.0.0"}"#,
    )
    .unwrap();
    let patched_content = b"patched index";
    let after_hash = compute_git_sha256_from_bytes(patched_content);
    std::fs::write(applied_pkg.join("index.js"), patched_content).unwrap();

    let unapplied_pkg = nm.join("unapplied-pkg");
    std::fs::create_dir_all(&unapplied_pkg).unwrap();
    std::fs::write(
        unapplied_pkg.join("package.json"),
        r#"{"name":"unapplied-pkg","version":"2.0.0"}"#,
    )
    .unwrap();
    // No matching file on disk → verify reports file_not_found.

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/applied-pkg@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            "a".repeat(64).as_str(),
            after_hash.as_str(),
            "GHSA-applied",
            &["CVE-APPLIED"],
        ),
    );
    manifest.patches.insert(
        "pkg:npm/unapplied-pkg@2.0.0".to_string(),
        make_record(
            "22222222-2222-4222-8222-222222222222",
            "package/missing.js",
            "c".repeat(64).as_str(),
            "d".repeat(64).as_str(),
            "GHSA-unapplied",
            &["CVE-UNAPPLIED"],
        ),
    );
    write_manifest(cwd, &manifest);

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
            "pkg:npm/test-app@1.0.0",
        ])
        .output()
        .expect("invoke vex");

    // The document was generated (one patch verified), so the run is a
    // success at the process level — exit 0 — even though one patch was
    // omitted. The omission surfaces in the envelope, not the exit code.
    assert_eq!(
        out.status.code(),
        Some(0),
        "a partial verify (≥1 applied) must still exit 0. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let env: Value = serde_json::from_slice(&out.stdout).expect("envelope JSON on stdout");
    assert_eq!(env["command"], "vex");
    assert_eq!(
        env["status"], "partialFailure",
        "mixed verify must report partialFailure, not success. env:\n{env}"
    );
    assert_eq!(env["summary"]["verified"], 1, "one applied subcomponent");
    assert_eq!(env["summary"]["skipped"], 1, "one omitted patch");

    let events = env["events"].as_array().unwrap();
    // The applied patch surfaces as a `verified` event keyed by its PURL.
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "verified" && e["purl"] == "pkg:npm/applied-pkg@1.0.0"),
        "expected a verified event for the applied package. events:\n{events:#?}"
    );
    // The omitted patch surfaces as a `skipped` event whose `errorCode`
    // carries the verification reason tag (NOT the human message — the
    // tag is what programmatic consumers route on).
    let skipped = events
        .iter()
        .find(|e| e["action"] == "skipped" && e["purl"] == "pkg:npm/unapplied-pkg@2.0.0")
        .expect("expected a skipped event for the unapplied package");
    assert_eq!(
        skipped["errorCode"], "file_not_found",
        "the skip reason tag must land in errorCode for routing. event:\n{skipped}"
    );

    // The VEX document at --output carries only the applied patch.
    let vex_text = std::fs::read_to_string(&vex_path).unwrap();
    let doc: Value = serde_json::from_str(&vex_text).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "only the applied patch is attested. doc:\n{vex_text}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-applied");
    assert!(
        !vex_text.contains("GHSA-unapplied"),
        "the omitted patch's vuln must not leak into the doc:\n{vex_text}"
    );
    maybe_validate_with_vexctl(&vex_text);
}

// ──────────────────────────────────────────────────────────────────────
// `--compact` output shape — the flag selects `serde_json::to_string`
// (single line, no inter-token whitespace) over `to_string_pretty`. Pin
// the actual on-the-wire shape so a flipped branch (compact ⇄ pretty) is
// caught; no other test exercises `--compact`.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn compact_flag_emits_single_line_json() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/lodash@4.17.20".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            "GHSA-aaaa-bbbb-cccc",
            &["CVE-2024-1111"],
        ),
    );
    write_manifest(cwd, &manifest);

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--compact",
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "compact vex must succeed. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).unwrap();
    // The document is the only thing on stdout. Compact serialization is
    // a single line: after trimming the trailing newline from `println!`,
    // there must be no interior newline and no `": "`/`",\n"` pretty
    // spacing. A pretty (default) doc would span many lines.
    let trimmed = stdout.trim_end_matches('\n');
    assert!(
        !trimmed.contains('\n'),
        "compact output must be a single line, got multi-line:\n{stdout}"
    );
    assert!(
        !trimmed.contains("\n  "),
        "compact output must not carry pretty-print indentation"
    );
    // It must still be valid OpenVEX with the expected statement.
    let doc: Value = serde_json::from_str(trimmed).expect("compact output must be valid JSON");
    assert_eq!(doc["@context"], "https://openvex.dev/ns/v0.2.0");
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1);
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-aaaa-bbbb-cccc");

    // Control: the SAME inputs without --compact span multiple lines, so
    // the single-line assertion above is discriminating (not vacuous).
    let pretty = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    let pretty_stdout = String::from_utf8(pretty.stdout).unwrap();
    assert!(
        pretty_stdout.trim_end_matches('\n').contains('\n'),
        "pretty (default) output should be multi-line — control for the compact assertion"
    );
}

// ──────────────────────────────────────────────────────────────────────
// vexctl integration (run only when the binary is on PATH)
// ──────────────────────────────────────────────────────────────────────

/// Pipe the VEX text through `vexctl` if it's on `PATH`. CI installs
/// vexctl before the test step so the validation actually runs there;
/// local devs without Go see a skip message instead of a failure.
///
/// `vexctl merge --files=<path>` loads, parses, and re-emits the
/// document. vexctl does not yet expose a dedicated `validate`
/// subcommand at v0.3.x, but a successful merge of a single file is
/// the canonical proof that the input parses cleanly against the
/// OpenVEX schema (`list` requires a selector argument, `filter`
/// requires a query expression — merge is the only no-arg parse gate).
fn maybe_validate_with_vexctl(vex_text: &str) {
    let Some(vexctl) = find_vexctl_on_path() else {
        eprintln!("(skipping vexctl validation — binary not on PATH)");
        return;
    };
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), vex_text).unwrap();

    let out = Command::new(&vexctl)
        .args(["merge", tmp.path().to_str().unwrap()])
        .output()
        .expect("spawn vexctl");
    assert!(
        out.status.success(),
        "vexctl rejected the document.\nstderr:\n{}\nstdout:\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    // Sanity: the merge output must itself be valid OpenVEX JSON.
    let _: Value =
        serde_json::from_slice(&out.stdout).expect("vexctl merge output must be valid JSON");
}

/// Stdlib-only `PATH` lookup for `vexctl`. Returns `None` if missing.
fn find_vexctl_on_path() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for entry in std::env::split_paths(&path) {
        let candidate = entry.join("vexctl");
        if candidate.is_file() {
            return Some(candidate);
        }
        let with_exe = entry.join("vexctl.exe");
        if with_exe.is_file() {
            return Some(with_exe);
        }
    }
    None
}
