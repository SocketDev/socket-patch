//! In-process test for `socket-patch scan --redirect`: mocks the API
//! (discovery + the `patches/package` reference endpoint) via wiremock, lays
//! down an npm project with a lockfile, runs `scan --redirect`, and asserts the
//! lockfile's patched-dependency entry was repointed at the hosted vendored
//! patch (resolved URL + sha512 integrity) and a revert ledger was written.
//! This is the CLI counterpart of the depscan-side install-verify e2e; the
//! rewriter bytes themselves are pinned by the shared golden fixtures.

use std::collections::HashMap;
use std::path::Path;

use serial_test::serial;
use socket_patch_cli::commands::scan::{run, ScanArgs};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, SetupConfig, VulnerabilityInfo,
};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const NAME: &str = "in-proc-redirect";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:npm/in-proc-redirect@1.0.0";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const HOSTED_URL: &str = "http://patch.test/patch/npm/in-proc-redirect/1.0.0/22222222-2222-4222-8222-222222222222/11111111-1111-4111-8111-111111111111/in-proc-redirect-1.0.0.tgz";
const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
const GHSA: &str = "GHSA-rdir-aaaa-bbbb";

fn redirect_args(cwd: &Path, api_url: String) -> ScanArgs {
    ScanArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            org: Some(ORG.to_string()),
            api_token: Some("fake".to_string()),
            api_url,
            json: true,
            yes: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: 100,
        apply: false,
        prune: false,
        sync: false,
        vendor: false,
        detached: false,
        redirect: true,
        mode: None,
        all_releases: false,
        vex: Default::default(),
    }
}

async fn mock_discovery(server: &MockServer) {
    // Batch discovery: the installed package has a patch.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "redirect fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    // Per-package search used by the redirect selection.
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

async fn mock_reference(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": HOSTED_URL,
                    "purl": PURL,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": HOSTED_URL,
                        "integrity": { "sha512": PATCHED_SHA512 }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(server)
        .await;
}

/// The `view/{uuid}` endpoint `run_redirect` calls to build the patch record
/// (file hashes + vulnerabilities) it persists into the redirect ledger for VEX.
async fn mock_view(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": "a".repeat(64),
                    "afterHash": "b".repeat(64),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2024-9"],
                    "summary": "redirect vex fixture",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
}

fn write_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "{VERSION}" }} }}"#
        ),
    )
    .unwrap();
    // Installed package so the npm crawler discovers it.
    let pkg = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    // Lockfile the redirect rewriter edits.
    std::fs::write(
        root.join("package-lock.json"),
        format!(
            r#"{{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {{
    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "{VERSION}" }} }},
    "node_modules/{NAME}": {{
      "version": "{VERSION}",
      "resolved": "https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz",
      "integrity": "sha512-UPSTREAMupstream=="
    }}
  }}
}}
"#
        ),
    )
    .unwrap();
}

#[tokio::test]
#[serial]
async fn scan_redirect_rewrites_lockfile_to_hosted_patch() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "scan --redirect should succeed");

    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        lock.contains(HOSTED_URL),
        "lockfile resolved must point at the hosted patch; got:\n{lock}"
    );
    assert!(
        lock.contains(PATCHED_SHA512),
        "lockfile integrity must be the patched sha512; got:\n{lock}"
    );
    assert!(
        !lock.contains("UPSTREAMupstream"),
        "the upstream resolved/integrity must be replaced; got:\n{lock}"
    );
    // Revert ledger written.
    assert!(
        tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .is_file(),
        "a redirect ledger should be written for revert"
    );
}

/// `scan --redirect --vex` must emit a valid OpenVEX doc for the redirected
/// patch. The redirected bytes aren't installed in-run, so this is a NO-VERIFY
/// attestation built from the patch records the redirect run persists into the
/// ledger; the statement carries the `(redirected)` provenance marker.
#[tokio::test]
#[serial]
async fn scan_redirect_vex_emits_redirected_attestation() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let vex_path = tmp.path().join("out.vex.json");
    let mut args = redirect_args(tmp.path(), server.uri());
    args.vex = socket_patch_cli::commands::vex::VexEmbedArgs {
        vex: Some(vex_path.clone()),
        vex_product: Some("pkg:npm/consumer@0.0.0".to_string()),
        ..Default::default()
    };

    let code = run(args).await;
    assert_eq!(code, 0, "scan --redirect --vex should succeed");

    // The ledger embeds the patch record (so a post-install `vex` can verify).
    let ledger =
        std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger.contains("\"records\"") && ledger.contains(GHSA) && ledger.contains(PURL),
        "ledger must embed the patch record + vulnerability: {ledger}"
    );

    // The VEX document attests the redirected patch with the (redirected) marker.
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&vex_path).unwrap()).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "the redirected patch must be attested: {doc}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA);
    assert_eq!(stmts[0]["status"], "not_affected");
    assert_eq!(stmts[0]["products"][0]["subcomponents"][0]["@id"], PURL);
    let impact = stmts[0]["impact_statement"].as_str().unwrap();
    assert!(
        impact.contains("(redirected)"),
        "the attestation must carry the (redirected) marker: {impact}"
    );
}

/// A patch record with one npm-shaped file and one vulnerability, for the
/// manifest-side fixtures below.
fn npm_record(uuid: &str, before: &str, after: &str, ghsa: &str) -> PatchRecord {
    let mut files = HashMap::new();
    files.insert(
        "package/index.js".to_string(),
        PatchFileInfo {
            before_hash: before.to_string(),
            after_hash: after.to_string(),
        },
    );
    let mut vulns = HashMap::new();
    vulns.insert(
        ghsa.to_string(),
        VulnerabilityInfo {
            cves: vec!["CVE-2024-1".to_string()],
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
        description: "x".to_string(),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

/// Write an installed npm package with `index.js` = `bytes`.
fn write_installed(root: &Path, name: &str, version: &str, bytes: &[u8]) {
    let pkg = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), bytes).unwrap();
}

/// Idempotency guard for the revert ledger: a second `scan --redirect` run
/// (whose rewrite matches the already-redirected entries) must MERGE into
/// `redirect-state.json`, preserving the first run's edits — the entries whose
/// `original` values a future revert needs — rather than clobbering the file.
#[tokio::test]
#[serial]
async fn second_redirect_run_preserves_revert_edits() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "first scan --redirect should succeed");
    let ledger_path = tmp.path().join(".socket/vendor/redirect-state.json");
    let first = std::fs::read_to_string(&ledger_path).unwrap();
    assert!(
        first.contains("registry.npmjs.org"),
        "first run's edits must record the ORIGINAL upstream URL: {first}"
    );

    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "second scan --redirect should succeed");
    let second = std::fs::read_to_string(&ledger_path).unwrap();
    assert!(
        second.contains("registry.npmjs.org"),
        "the second run must PRESERVE the original-upstream edit needed for \
         revert (merge, not overwrite): {second}"
    );
    assert!(
        second.contains(GHSA),
        "records must survive the merge: {second}"
    );
    // Idempotency: the rewriters see an already-redirected lockfile, record
    // no new edits, and the edit list stays the same length — unbounded edit
    // growth across CI re-runs would poison a future revert.
    let first_json: serde_json::Value = serde_json::from_str(&first).unwrap();
    let second_json: serde_json::Value = serde_json::from_str(&second).unwrap();
    assert_eq!(
        first_json["edits"].as_array().unwrap().len(),
        second_json["edits"].as_array().unwrap().len(),
        "a re-run must not append duplicate edits: {second}"
    );
}

/// A granted patch whose rewriter finds NOTHING to edit (no lockfile at all)
/// must not be recorded or attested: nothing in the project pins the hosted
/// patch, so a `not_affected` statement would suppress a live CVE. The
/// requested attestation therefore fails (exit 1) with no document and no
/// ledger.
#[tokio::test]
#[serial]
async fn no_lockfile_redirect_is_not_attested() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    // Project WITHOUT a lockfile: installed tree + package.json only.
    std::fs::write(
        tmp.path().join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "{VERSION}" }} }}"#
        ),
    )
    .unwrap();
    let pkg = tmp.path().join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), b"unpatched installed bytes\n").unwrap();

    let vex_path = tmp.path().join("out.vex.json");
    let mut args = redirect_args(tmp.path(), server.uri());
    args.vex = socket_patch_cli::commands::vex::VexEmbedArgs {
        vex: Some(vex_path.clone()),
        vex_product: Some("pkg:npm/consumer@0.0.0".to_string()),
        ..Default::default()
    };
    let code = run(args).await;
    assert_eq!(
        code, 1,
        "nothing was redirected, so a requested attestation must fail"
    );
    assert!(
        !vex_path.exists(),
        "NO OpenVEX document may exist for a tree where nothing pins the patch"
    );
    assert!(
        !tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .exists(),
        "no ledger may be written when no file was rewritten"
    );
}

/// In-run `--vex` semantics: redirected PURLs are exempt from verification
/// (their bytes are remote until install), but OTHER manifest patches still
/// verify normally — an applied one attests plain, a not-applied one is
/// omitted. This pins that `scan --redirect --vex` does NOT silently attest
/// the whole manifest unverified.
#[tokio::test]
#[serial]
async fn redirect_vex_verifies_manifest_patches_normally() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    // Manifest patch A: APPLIED on disk (installed bytes hash to afterHash).
    let good = b"patched control bytes\n";
    let good_after = compute_git_sha256_from_bytes(good);
    write_installed(tmp.path(), "control-good", "1.0.0", good);
    // Manifest patch B: NOT applied (installed bytes == beforeHash).
    let bad = b"unpatched control bytes\n";
    let bad_before = compute_git_sha256_from_bytes(bad);
    write_installed(tmp.path(), "control-bad", "1.0.0", bad);

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/control-good@1.0.0".to_string(),
        npm_record(
            "33333333-3333-4333-8333-333333333333",
            &"a".repeat(64),
            &good_after,
            "GHSA-ctrl-good",
        ),
    );
    manifest.patches.insert(
        "pkg:npm/control-bad@1.0.0".to_string(),
        npm_record(
            "44444444-4444-4444-8444-444444444444",
            &bad_before,
            &"b".repeat(64),
            "GHSA-ctrl-bad",
        ),
    );
    // npm declared `manual` so property-7 admits the controls — what drops
    // GHSA-ctrl-bad must be VERIFICATION, not the ecosystem filter.
    manifest.setup = Some(SetupConfig {
        exclude: Vec::new(),
        manual: vec!["npm".to_string()],
    });
    let socket_dir = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();
    std::fs::write(
        socket_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let vex_path = tmp.path().join("out.vex.json");
    let mut args = redirect_args(tmp.path(), server.uri());
    args.vex = socket_patch_cli::commands::vex::VexEmbedArgs {
        vex: Some(vex_path.clone()),
        vex_product: Some("pkg:npm/consumer@0.0.0".to_string()),
        ..Default::default()
    };
    let code = run(args).await;
    assert_eq!(code, 0, "scan --redirect --vex should succeed");

    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&vex_path).unwrap()).unwrap();
    let text = doc.to_string();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        2,
        "redirected + applied-control attest; not-applied control is omitted: {doc}"
    );
    assert!(text.contains(GHSA), "redirected patch attested: {doc}");
    assert!(
        text.contains("GHSA-ctrl-good"),
        "verified manifest patch attested: {doc}"
    );
    assert!(
        !text.contains("GHSA-ctrl-bad"),
        "unapplied manifest patch must be verification-omitted in-run: {doc}"
    );
    // Provenance: the redirected statement carries the marker, the plain
    // manifest one does not.
    for st in stmts {
        let impact = st["impact_statement"].as_str().unwrap();
        if st["vulnerability"]["name"] == GHSA {
            assert!(impact.contains("(redirected)"), "{impact}");
        } else {
            assert!(!impact.contains("(redirected)"), "{impact}");
        }
    }
}

/// `--vex` with nothing to attest is an ERROR, not a silent no-op: the
/// reference endpoint denies the patch (forbidden), no manifest exists, so a
/// requested attestation has no subject — exit 1, no document written.
#[tokio::test]
#[serial]
async fn redirect_vex_errors_when_nothing_to_attest() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    // Reference endpoint: the patch exists but this org may not download it.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": { UUID: { "status": "forbidden", "url": null, "purl": PURL, "artifacts": [], "registryOverride": null } }
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let vex_path = tmp.path().join("out.vex.json");
    let mut args = redirect_args(tmp.path(), server.uri());
    args.vex = socket_patch_cli::commands::vex::VexEmbedArgs {
        vex: Some(vex_path.clone()),
        vex_product: Some("pkg:npm/consumer@0.0.0".to_string()),
        ..Default::default()
    };
    let code = run(args).await;
    assert_eq!(
        code, 1,
        "a requested-but-unfulfillable VEX must flip the exit code"
    );
    assert!(
        !vex_path.exists(),
        "no document may be written when nothing attests"
    );
    // Pin the failure family: NOTHING was redirected (the reference was
    // forbidden), so no ledger exists and the lockfile is untouched —
    // excluding the "redirect succeeded but VEX write failed" family.
    assert!(
        !tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .exists(),
        "a forbidden reference must not produce a ledger"
    );
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        lock.contains("registry.npmjs.org"),
        "the lockfile must be untouched when the reference is denied: {lock}"
    );
}

/// Flag composition on the redirect path: `--vex-doc-id` pins the document
/// `@id` and `--vex-compact` writes single-line JSON.
#[tokio::test]
#[serial]
async fn redirect_vex_doc_id_and_compact_flags() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let vex_path = tmp.path().join("out.vex.json");
    let mut args = redirect_args(tmp.path(), server.uri());
    args.vex = socket_patch_cli::commands::vex::VexEmbedArgs {
        vex: Some(vex_path.clone()),
        vex_product: Some("pkg:npm/consumer@0.0.0".to_string()),
        vex_doc_id: Some("urn:uuid:00000000-0000-4000-8000-000000000000".to_string()),
        vex_compact: true,
        ..Default::default()
    };
    let code = run(args).await;
    assert_eq!(code, 0, "scan --redirect --vex should succeed");

    let raw = std::fs::read_to_string(&vex_path).unwrap();
    assert_eq!(
        raw.trim_end().lines().count(),
        1,
        "--vex-compact must write single-line JSON: {raw}"
    );
    let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        doc["@id"], "urn:uuid:00000000-0000-4000-8000-000000000000",
        "--vex-doc-id must pin the document id"
    );
}

/// `--dry-run` composes: no file writes, no ledger, and VEX generation is
/// skipped (nothing was redirected on disk to attest) with exit 0.
#[tokio::test]
#[serial]
async fn redirect_dry_run_skips_vex() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_before = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();

    let vex_path = tmp.path().join("out.vex.json");
    let mut args = redirect_args(tmp.path(), server.uri());
    args.common.dry_run = true;
    args.vex = socket_patch_cli::commands::vex::VexEmbedArgs {
        vex: Some(vex_path.clone()),
        vex_product: Some("pkg:npm/consumer@0.0.0".to_string()),
        ..Default::default()
    };
    let code = run(args).await;
    assert_eq!(code, 0, "dry-run redirect should succeed");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap(),
        lock_before,
        "dry-run must not touch the lockfile"
    );
    assert!(
        !tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .exists(),
        "dry-run must not write the ledger"
    );
    assert!(!vex_path.exists(), "dry-run must not write a VEX document");
}

const BERRY_CHECKSUM: &str = "10c0/7785879d9a7dc9bee6730ec55926a0ab9ed6bfe0eaee0cbcbcf00841d42488fddda51265c73eeddd54c5deca87d131e846ff66d27d890ef73f12720b458d7ca3";

/// Reference mock whose granted patch carries BOTH a tarball (sha512) and a
/// yarn-berry-zip artifact (yarnBerry10c0) — the berry rewriter pins the zip
/// checksum, not the tarball's.
async fn mock_reference_with_berry(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": HOSTED_URL,
                    "purl": PURL,
                    "artifacts": [
                        { "kind": "tarball", "url": HOSTED_URL,
                          "integrity": { "sha512": PATCHED_SHA512 } },
                        { "kind": "yarn-berry-zip", "url": "http://patch.test/berry.zip",
                          "integrity": { "yarnBerry10c0": BERRY_CHECKSUM } }
                    ],
                    "registryOverride": null
                }
            }
        })))
        .mount(server)
        .await;
}

/// Write a project whose only lockfile is a yarn-berry `yarn.lock` resolving
/// `<NAME>@npm:<VERSION>` (spike B3 shape, cacheKey 10c0).
fn write_berry_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "^{VERSION}" }} }}"#
        ),
    )
    .unwrap();
    let pkg = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    std::fs::write(
        root.join("yarn.lock"),
        format!(
            "# This file is generated by running \"yarn install\" inside your project.\n\
             # Manual changes might be lost - proceed with caution!\n\n\
             __metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
             \"{NAME}@npm:^{VERSION}\":\n  version: {VERSION}\n  \
             resolution: \"{NAME}@npm:{VERSION}\"\n  checksum: 10c0/{}\n  \
             languageName: node\n  linkType: hard\n\n\
             \"consumer@workspace:.\":\n  version: 0.0.0-use.local\n  \
             resolution: \"consumer@workspace:.\"\n  dependencies:\n    \
             {NAME}: \"npm:^{VERSION}\"\n  languageName: unknown\n  linkType: soft\n",
            "3".repeat(128)
        ),
    )
    .unwrap();
}

/// The berry leg: the yarn.lock entry is repointed via `::__archiveUrl=` (the
/// URL percent-encoded) and its `checksum:` becomes the yarnBerry10c0. The
/// descriptor KEY is preserved (so `--immutable` still passes), a ledger is
/// written, and a second run is a no-op.
#[tokio::test]
#[serial]
async fn scan_redirect_rewrites_yarn_berry_lock() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference_with_berry(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_berry_project(tmp.path());

    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "scan --redirect (berry) should succeed");

    let lock = std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap();
    // yarn writes `__archiveUrl=<encodeURIComponent(url)>`; assert both the
    // binding marker and the encoded URL landed.
    let encoded = socket_patch_core::utils::uri::encode_uri_component(HOSTED_URL);
    assert!(
        lock.contains("::__archiveUrl=") && lock.contains(&encoded),
        "resolution must carry the encoded __archiveUrl; got:\n{lock}"
    );
    assert!(
        lock.contains(BERRY_CHECKSUM),
        "checksum must be the yarnBerry10c0"
    );
    assert!(
        lock.contains(&format!("\"{NAME}@npm:^{VERSION}\":")),
        "the descriptor key must be preserved verbatim; got:\n{lock}"
    );
    assert!(
        tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .is_file(),
        "a redirect ledger should be written"
    );

    // Idempotent: a second run rewrites nothing new (no ledger edit growth).
    let ledger_path = tmp.path().join(".socket/vendor/redirect-state.json");
    let first: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger_path).unwrap()).unwrap();
    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "second berry run should succeed");
    let second: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger_path).unwrap()).unwrap();
    assert_eq!(
        first["edits"].as_array().unwrap().len(),
        second["edits"].as_array().unwrap().len(),
        "a berry re-run must not append duplicate edits"
    );
}

/// Write a project whose only lockfile is a text `bun.lock` (registry 4-tuple).
fn write_bun_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "^{VERSION}" }} }}"#
        ),
    )
    .unwrap();
    let pkg = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    std::fs::write(
        root.join("bun.lock"),
        format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"packages\": {{\n    \
             \"{NAME}\": [\"{NAME}@{VERSION}\", \"\", {{}}, \"sha512-UPSTREAMupstream==\"],\n  \
             }}\n}}\n"
        ),
    )
    .unwrap();
}

/// The bun leg: the registry 4-tuple is rewritten to a URL 3-tuple carrying the
/// hosted URL + patched sha512; the upstream integrity is gone.
#[tokio::test]
#[serial]
async fn scan_redirect_rewrites_bun_lock() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path());

    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "scan --redirect (bun) should succeed");

    let lock = std::fs::read_to_string(tmp.path().join("bun.lock")).unwrap();
    assert!(
        lock.contains(&format!("\"{NAME}@{HOSTED_URL}\"")),
        "the tuple's spec must be name@<hosted url>; got:\n{lock}"
    );
    assert!(
        lock.contains(PATCHED_SHA512),
        "integrity must be the patched sha512"
    );
    assert!(
        !lock.contains("UPSTREAMupstream"),
        "upstream integrity must be replaced; got:\n{lock}"
    );
    assert!(
        tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .is_file(),
        "a redirect ledger should be written"
    );
}

/// The bun.lockb auto-migration leg: a fake `bun` shim prepended to PATH writes
/// a canned text bun.lock and deletes bun.lockb, exercising the migration
/// branch of `run_redirect` without a real bun. The migration removal is
/// recorded in the ledger, and the freshly-written bun.lock is then redirected.
///
/// unix-only: the shim is a `#!/bin/sh` script (Windows would need a .cmd
/// twin and `;` PATH joining). The migration path itself is OS-agnostic
/// (`Command::new("bun")` resolves bun.exe on Windows) and gets real-bun
/// coverage in the toolchain-gated e2e_redirect_bun_build capstone.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn scan_redirect_migrates_bun_lockb_then_redirects() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    // Project locked to a BINARY bun.lockb (placeholder bytes — never parsed).
    std::fs::write(
        tmp.path().join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "^{VERSION}" }} }}"#
        ),
    )
    .unwrap();
    let pkg = tmp.path().join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    std::fs::write(tmp.path().join("bun.lockb"), b"BUN-BINARY-PLACEHOLDER").unwrap();

    // A fake `bun` on PATH: `bun install …` writes bun.lock and deletes lockb.
    let bin_dir = tmp.path().join("fakebin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let shim = bin_dir.join("bun");
    let bun_lock_body = format!(
        "{{\n  \"lockfileVersion\": 1,\n  \"packages\": {{\n    \
         \"{NAME}\": [\"{NAME}@{VERSION}\", \"\", {{}}, \"sha512-UPSTREAMupstream==\"],\n  \
         }}\n}}\n"
    );
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\n\
             # emulate `bun install --save-text-lockfile`: write bun.lock, drop bun.lockb\n\
             cat > bun.lock <<'LOCK'\n{bun_lock_body}LOCK\n\
             rm -f bun.lockb\n\
             exit 0\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: single-threaded #[serial] test; PATH restored below.
    unsafe {
        std::env::set_var("PATH", format!("{}:{orig_path}", bin_dir.display()));
    }

    let code = run(redirect_args(tmp.path(), server.uri())).await;

    unsafe {
        std::env::set_var("PATH", orig_path);
    }
    assert_eq!(code, 0, "scan --redirect (lockb migration) should succeed");

    assert!(
        !tmp.path().join("bun.lockb").exists(),
        "the shim must have deleted bun.lockb"
    );
    let lock = std::fs::read_to_string(tmp.path().join("bun.lock")).unwrap();
    assert!(
        lock.contains(HOSTED_URL) && lock.contains(PATCHED_SHA512),
        "the migrated bun.lock must be redirected; got:\n{lock}"
    );
    // The migration removal is recorded (action "removed") for revert.
    let ledger =
        std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger.contains("redirect_bun_lockb_migrated") && ledger.contains("\"removed\""),
        "the ledger must record the bun.lockb removal: {ledger}"
    );
}

// ── Rush monorepo ────────────────────────────────────────────────────────

/// A Rush pnpm lock (v9) resolving the patched package under `packages:`, so
/// the pnpm redirect rewriter has a `NAME@VERSION` block to repoint. `extra`
/// lets a subspace lock resolve a DIFFERENT package name so the two locks are
/// distinguishable in assertions.
fn rush_pnpm_lock(pkg_name: &str) -> String {
    format!(
        "lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      {pkg_name}:
        specifier: {VERSION}
        version: {VERSION}

packages:
  {pkg_name}@{VERSION}:
    resolution: {{integrity: sha512-UPSTREAMupstream==}}

snapshots:
  {pkg_name}@{VERSION}: {{}}
"
    )
}

/// Lay down a Rush monorepo: rush.json, the single source-of-truth lock at
/// common/config/rush/pnpm-lock.yaml resolving the patched package, and one
/// subspace lock. NO root package.json / package-lock.json pair. When
/// `with_repo_state` is set, also drop common/config/rush/repo-state.json (the
/// file that carries pnpmShrinkwrapHash).
fn write_rush_project(root: &Path, with_repo_state: bool) {
    std::fs::write(root.join("rush.json"), r#"{ "rushVersion": "5.100.0" }"#).unwrap();
    let common = root.join("common/config/rush");
    std::fs::create_dir_all(&common).unwrap();
    // The common lock resolves the patched package (matches mock_reference PURL).
    std::fs::write(common.join("pnpm-lock.yaml"), rush_pnpm_lock(NAME)).unwrap();
    // A subspace lock ALSO resolves the patched package, so both nested locks
    // get rewritten in place under their own repo-relative keys.
    let subspace = root.join("common/config/subspaces/frontend");
    std::fs::create_dir_all(&subspace).unwrap();
    std::fs::write(subspace.join("pnpm-lock.yaml"), rush_pnpm_lock(NAME)).unwrap();
    if with_repo_state {
        std::fs::write(
            common.join("repo-state.json"),
            "{\n  \"pnpmShrinkwrapHash\": \"deadbeef\",\n  \"preventManualShrinkwrapChanges\": true\n}\n",
        )
        .unwrap();
    }
}

/// `scan --redirect` in a Rush monorepo rewrites BOTH the common
/// source-of-truth lock and every subspace lock in place (nested FileEdit
/// paths), even though there is no root package.json/lock pair — the package
/// is discovered from the Rush locks (lockfile supplement) and the pnpm
/// rewriter is basename-generalized. With repo-state.json present, the run
/// warns that the lock was edited outside `rush update`.
#[tokio::test]
#[serial]
async fn scan_redirect_rewrites_rush_common_and_subspace_locks() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_rush_project(tmp.path(), true);

    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "scan --redirect should succeed in a Rush repo");

    // Both nested locks are rewritten in place (not a new root lock).
    for rel in [
        "common/config/rush/pnpm-lock.yaml",
        "common/config/subspaces/frontend/pnpm-lock.yaml",
    ] {
        let lock = std::fs::read_to_string(tmp.path().join(rel)).unwrap();
        assert!(
            lock.contains(HOSTED_URL),
            "{rel} must be repointed at the hosted patch; got:\n{lock}"
        );
        assert!(
            lock.contains(PATCHED_SHA512),
            "{rel} integrity must be the patched sha512; got:\n{lock}"
        );
    }
    // No stray root lock was created.
    assert!(
        !tmp.path().join("pnpm-lock.yaml").exists(),
        "the rewrite must edit nested locks in place, not create a root lock"
    );

    // repo-state.json present → the stale-hash warning fires.
    let out = std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json"))
        .expect("a redirect ledger should be written");
    assert!(
        out.contains(HOSTED_URL),
        "the ledger records the redirect for revert: {out}"
    );
}

/// Run the built `socket-patch` binary as a subprocess against `api_url`
/// (a wiremock server) so we can parse the `--json` envelope's `warnings`
/// array — the in-process `run` writes JSON to the process stdout, which a
/// hosting test can't read back. No package-manager binary is needed: the
/// rewrite is pure text over the fixture locks.
fn run_redirect_subprocess(cwd: &Path, api_url: &str) -> serde_json::Value {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_socket-patch"))
        .args([
            "scan",
            "--redirect",
            "--json",
            "--yes",
            "--cwd",
            cwd.to_str().unwrap(),
            "--api-url",
            api_url,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ])
        .output()
        .expect("run socket-patch");
    assert_eq!(
        out.status.code(),
        Some(0),
        "scan --redirect must succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "scan --redirect --json output is not JSON: {e}\nstdout:\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

/// Collect the `code` field of every warning in the redirect envelope.
fn warning_codes(env: &serde_json::Value) -> Vec<String> {
    env["redirect"]["warnings"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|w| w["code"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The `redirect_rush_repo_state_stale` warning fires exactly when a Rush lock
/// was rewritten AND common/config/rush/repo-state.json is present (the file
/// that carries pnpmShrinkwrapHash, which an out-of-band lock edit desyncs).
/// The twin fixture without repo-state.json rewrites identically but emits no
/// such warning. repo-state.json itself is never edited by the redirect — the
/// customer refreshes it with `rush update`, which the redirect survives.
#[tokio::test]
#[serial]
async fn rush_repo_state_stale_warning_is_gated_on_repo_state_presence() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    // With repo-state.json: the stale-hash warning is present.
    let with_state = tempfile::tempdir().unwrap();
    write_rush_project(with_state.path(), true);
    let repo_state_before =
        std::fs::read_to_string(with_state.path().join("common/config/rush/repo-state.json"))
            .unwrap();
    let env = run_redirect_subprocess(with_state.path(), &server.uri());
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert!(
        warning_codes(&env).contains(&"redirect_rush_repo_state_stale".to_string()),
        "repo-state.json present → stale-hash warning must fire; got warnings {:?}",
        warning_codes(&env)
    );
    // repo-state.json is Rush's business — the redirect must not touch it.
    let repo_state_after =
        std::fs::read_to_string(with_state.path().join("common/config/rush/repo-state.json"))
            .unwrap();
    assert_eq!(
        repo_state_before, repo_state_after,
        "the redirect must not rewrite repo-state.json"
    );

    // Twin without repo-state.json: rewrites identically, no warning.
    let no_state = tempfile::tempdir().unwrap();
    write_rush_project(no_state.path(), false);
    let env = run_redirect_subprocess(no_state.path(), &server.uri());
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert!(
        !warning_codes(&env).contains(&"redirect_rush_repo_state_stale".to_string()),
        "no repo-state.json → no stale-hash warning; got warnings {:?}",
        warning_codes(&env)
    );
    // The rewrite still landed in the common lock.
    let lock =
        std::fs::read_to_string(no_state.path().join("common/config/rush/pnpm-lock.yaml")).unwrap();
    assert!(
        lock.contains(HOSTED_URL),
        "the common lock must still be redirected without repo-state.json; got:\n{lock}"
    );
}
