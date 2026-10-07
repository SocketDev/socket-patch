//! In-process test for `socket-patch scan --mode hosted`: mocks the API
//! (discovery + the `patches/package` reference endpoint) via wiremock, lays
//! down an npm project with a lockfile, runs `scan --mode hosted`, and asserts the
//! lockfile's patched-dependency entry was repointed at the hosted vendored
//! patch (resolved URL + sha512 integrity) — and (v5) that NO redirect
//! ledger was written: the lockfile pin is the whole hosted state, and
//! `rollback` restores the default upstream registry entry.
//! This is the CLI counterpart of the depscan-side install-verify e2e; the
//! rewriter bytes themselves are pinned by the shared golden fixtures.

use std::collections::HashMap;
use std::path::Path;

use serial_test::serial;
use socket_patch_cli::commands::scan::{run, ScanArgs};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo,
};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "npm_e2e_common/manifestless.rs"]
mod npm_e2e_common;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;
// `bun_vex` re-exports its own copy of `vex_e2e_common` for the bun cells;
// the npm cells use the top-level one above.
#[allow(clippy::duplicate_mod)]
#[path = "vex_e2e_common/bun.rs"]
mod bun_vex;
#[path = "in_process_redirect/vlt.rs"]
mod vlt;
#[path = "vlt_hosted_common/mod.rs"]
mod vlt_hosted_common;

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
        socket_yml: Default::default(),
        paths: Vec::new(),
        packages: Vec::new(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            org: Some(ORG.to_string()),
            api_token: Some("fake".to_string()),
            api_url: Some(api_url),
            json: true,
            yes: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: Some(100),
        apply: false,
        prune: false,
        sync: false,
        vendor: false,
        mode: Some(socket_patch_cli::commands::scan::ScanMode::Hosted),
        all_releases: false,
        vex: Default::default(),
        rollout: Default::default(),
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
/// (file hashes + vulnerabilities) the in-run VEX attests from.
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
    assert_eq!(code, 0, "scan --mode hosted should succeed");

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
    // v5: no revert ledger — the lock pin is the whole record.
    vlt_hosted_common::assert_no_ledger(tmp.path());
}

/// `scan --mode hosted --vex` must emit a valid OpenVEX doc for the redirected
/// patch. The redirected bytes aren't installed in-run, so this is a NO-VERIFY
/// attestation built from the patch records this run fetched (held in memory
/// — v5 writes no ledger); the statement carries the `(redirected)`
/// provenance marker.
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
    assert_eq!(code, 0, "scan --mode hosted --vex should succeed");

    // The record reached the attestation in memory: nothing persisted.
    vlt_hosted_common::assert_no_ledger(tmp.path());

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

/// Idempotency: a second `scan --mode hosted` run over the already-redirected
/// lock plans from the current lock text (v5 keeps no ledger chain), so it
/// succeeds, leaves the lock byte-identical and still writes no ledger.
#[tokio::test]
#[serial]
async fn second_redirect_run_is_idempotent() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "first scan --mode hosted should succeed");
    let first = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(first.contains(HOSTED_URL), "{first}");

    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "second scan --mode hosted should succeed");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap(),
        first,
        "a re-run must leave the redirected lock byte-identical"
    );
    vlt_hosted_common::assert_no_ledger(tmp.path());
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
/// omitted. This pins that `scan --mode hosted --vex` does NOT silently attest
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
    // What drops GHSA-ctrl-bad must be VERIFICATION.
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
    assert_eq!(code, 0, "scan --mode hosted --vex should succeed");

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
    assert_eq!(code, 0, "scan --mode hosted --vex should succeed");

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
    mock_reference_with_berry_url(server, HOSTED_URL).await;
}

async fn mock_reference_with_berry_url(server: &MockServer, hosted_url: &str) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": hosted_url,
                    "purl": PURL,
                    "artifacts": [
                        { "kind": "tarball", "url": hosted_url,
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
    write_berry_project_spelled(root, str::to_string);
}

/// [`write_berry_project`] with the lock's bytes passed through `spell` —
/// the Windows shapes (yarn writes a new lockfile with CRLF there; a
/// `core.autocrlf` checkout does the same on any OS; editors add a BOM).
fn write_berry_project_spelled(root: &Path, spell: impl Fn(&str) -> String) {
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
        spell(&format!(
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
        )),
    )
    .unwrap();
}

/// The berry leg: the yarn.lock entry's resolution becomes the hosted
/// tarball-URL locator (never an `npm:` one, whose fetcher sends npm
/// registry auth to the patch host — #404) and its `checksum:` becomes the
/// yarnBerry10c0. The
/// descriptor KEY is preserved (so `--immutable` still passes), no ledger is
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
    assert_eq!(code, 0, "scan --mode hosted (berry) should succeed");

    let lock = std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap();
    assert!(
        lock.contains(&format!("\n  resolution: \"{NAME}@{HOSTED_URL}\"\n")),
        "resolution must be the hosted tarball locator; got:\n{lock}"
    );
    assert!(
        !lock.contains("__archiveUrl") && !lock.contains(&format!("resolution: \"{NAME}@npm:")),
        "the hosted pin must not be an npm: locator; got:\n{lock}"
    );
    assert!(
        lock.contains(BERRY_CHECKSUM),
        "checksum must be the yarnBerry10c0"
    );
    // Option C (#404): the entry is re-keyed by the tarball descriptor, and
    // the root package.json routes the original descriptor there.
    assert!(
        lock.contains(&format!("\"{NAME}@{HOSTED_URL}\":")),
        "the entry is keyed by the tarball descriptor; got:\n{lock}"
    );
    let pkg = std::fs::read_to_string(tmp.path().join("package.json")).unwrap();
    let pkg: serde_json::Value = serde_json::from_str(&pkg).unwrap();
    assert_eq!(
        pkg["resolutions"],
        serde_json::json!({ format!("{NAME}@npm:^{VERSION}"): HOSTED_URL }),
        "{pkg}"
    );
    vlt_hosted_common::assert_no_ledger(tmp.path());

    // Idempotent: a second run rewrites nothing (the lock is byte-stable).
    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "second berry run should succeed");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        lock,
        "a berry re-run must leave the lock byte-identical"
    );
    vlt_hosted_common::assert_no_ledger(tmp.path());
}

/// The berry leg on the Windows lock shapes: yarn berry writes a NEW
/// `yarn.lock` with `os.EOL` (CRLF on Windows), a `core.autocrlf` checkout
/// produces the same on any OS, and editors add a BOM. The hosted chain
/// must redirect the dep (never `redirected: 0` with a line-ending
/// refusal), keep every line CRLF and the BOM, write no ledger, stay a
/// no-op on re-run, and `rollback` must restore the upstream registry entry
/// (re-resolved from the mocked npm registry: the berry checksum is
/// recomputed from the upstream tarball) — the pristine lock byte-for-byte
/// but for that checksum value, CRLF and BOM kept.
#[tokio::test]
#[serial]
async fn scan_redirect_rewrites_crlf_and_bom_yarn_berry_locks_and_rollback_restores_them() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference_with_berry_url(
        &server,
        &HOSTED_URL.replace("http://patch.test", &server.uri()),
    )
    .await;
    mock_view(&server).await;
    let tarball = upstream_tarball();
    mock_npm_registry(
        &server,
        &vlt_hosted_common::sha512_sri(&tarball),
        Some(tarball),
    )
    .await;
    let hosted_url = HOSTED_URL.replace("http://patch.test", &server.uri());

    for (label, bom) in [("crlf", ""), ("bom+crlf", "\u{feff}")] {
        let tmp = tempfile::tempdir().unwrap();
        write_berry_project_spelled(tmp.path(), |t| format!("{bom}{}", t.replace('\n', "\r\n")));
        let lock_path = tmp.path().join("yarn.lock");
        let pristine = std::fs::read(&lock_path).unwrap();

        let env = run_redirect_subprocess_with(
            tmp.path(),
            &server.uri(),
            &["--patch-server-url", &server.uri()],
        );
        assert_eq!(env["redirect"]["redirected"], 1, "{label}: {env:#}");
        assert!(
            warning_codes(&env).is_empty(),
            "{label}: no line-ending refusal (or any other warning): {env:#}"
        );
        let lock = std::fs::read_to_string(&lock_path).unwrap();
        assert!(
            lock.contains(&format!("  resolution: \"{NAME}@{hosted_url}\"\r\n"))
                && lock.contains(&format!("  checksum: {BERRY_CHECKSUM}\r\n")),
            "{label}: the entry is redirected in CRLF: {lock:?}"
        );
        assert_eq!(
            lock.matches('\n').count(),
            lock.matches("\r\n").count(),
            "{label}: every line keeps CRLF"
        );
        assert_eq!(lock.starts_with('\u{feff}'), !bom.is_empty(), "{label}");

        vlt_hosted_common::assert_no_ledger(tmp.path());

        // Re-run: in sync, byte-stable.
        let env = run_redirect_subprocess_with(
            tmp.path(),
            &server.uri(),
            &["--patch-server-url", &server.uri()],
        );
        assert_eq!(env["redirect"]["redirected"], 1, "{label}: {env:#}");
        assert_eq!(
            std::fs::read_to_string(&lock_path).unwrap(),
            lock,
            "{label}"
        );
        vlt_hosted_common::assert_no_ledger(tmp.path());

        let (code, env) = rollback_json_with_origin(tmp.path(), &server, &server.uri());
        assert_eq!(code, Some(0), "{label}: rollback: {env:#}");
        assert_eq!(
            env["hosted"]["reverted"],
            serde_json::json!([PURL]),
            "{label}: {env:#}"
        );
        let restored = std::fs::read_to_string(&lock_path).unwrap();
        let checksum = berry_checksum_of(&restored);
        assert_ne!(
            checksum, BERRY_CHECKSUM,
            "{label}: the patched checksum is gone"
        );
        assert_eq!(
            restored,
            String::from_utf8(pristine.clone()).unwrap().replace(
                &format!("10c0/{}", "3".repeat(128)),
                &format!("10c0/{checksum}")
            ),
            "{label}: rollback restores the pristine CRLF lock (upstream checksum \
             re-derived from the registry tarball)"
        );
        let pkg: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(tmp.path().join("package.json")).unwrap())
                .unwrap();
        assert!(
            pkg.get("resolutions").is_none(),
            "{label}: rollback drops the resolutions pin: {pkg}"
        );
        vlt_hosted_common::assert_no_ledger(tmp.path());
    }
}

/// #632: a dependency declared through a yarn catalog (`"catalog:"`) is
/// matched by yarn's `resolutions` before the catalog is expanded, so the
/// hosted pin must also route `<name>@catalog:`; `rollback` must drop every
/// selector it wrote and restore the lock's expanded `npm:` key, leaving
/// package.json byte-identical to the pristine one.
#[tokio::test]
#[serial]
async fn yarn_berry_catalog_dependency_is_pinned_and_rolled_back() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    let hosted_url = HOSTED_URL.replace("http://patch.test", &server.uri());
    mock_reference_with_berry_url(&server, &hosted_url).await;
    mock_view(&server).await;
    let tarball = upstream_tarball();
    mock_npm_registry(
        &server,
        &vlt_hosted_common::sha512_sri(&tarball),
        Some(tarball),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    write_berry_project(tmp.path());
    let pkg_path = tmp.path().join("package.json");
    std::fs::write(
        &pkg_path,
        format!(
            "{{\n  \"name\": \"consumer\",\n  \"version\": \"0.0.0\",\n  \
             \"dependencies\": {{\n    \"{NAME}\": \"catalog:\"\n  }}\n}}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        tmp.path().join(".yarnrc.yml"),
        format!("nodeLinker: node-modules\ncatalog:\n  {NAME}: ^{VERSION}\n"),
    )
    .unwrap();
    let pristine_pkg = std::fs::read_to_string(&pkg_path).unwrap();
    let lock_path = tmp.path().join("yarn.lock");
    let pristine_lock = std::fs::read_to_string(&lock_path).unwrap();

    let env = run_redirect_subprocess_with(
        tmp.path(),
        &server.uri(),
        &["--patch-server-url", &server.uri()],
    );
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    assert!(warning_codes(&env).is_empty(), "{env:#}");
    let pkg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&pkg_path).unwrap()).unwrap();
    assert_eq!(
        pkg["resolutions"],
        serde_json::json!({
            format!("{NAME}@npm:^{VERSION}"): hosted_url,
            format!("{NAME}@catalog:"): hosted_url,
        }),
        "{pkg}"
    );
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock.contains(&format!("\"{NAME}@{hosted_url}\":")),
        "the entry is keyed by the tarball descriptor: {lock}"
    );

    let (code, env) = rollback_json_with_origin(tmp.path(), &server, &server.uri());
    assert_eq!(code, Some(0), "rollback: {env:#}");
    assert_eq!(
        env["hosted"]["reverted"],
        serde_json::json!([PURL]),
        "{env:#}"
    );
    assert_eq!(
        std::fs::read_to_string(&pkg_path).unwrap(),
        pristine_pkg,
        "rollback drops both selectors"
    );
    let restored = std::fs::read_to_string(&lock_path).unwrap();
    let checksum = berry_checksum_of(&restored);
    assert_eq!(
        restored,
        pristine_lock.replace(
            &format!("10c0/{}", "3".repeat(128)),
            &format!("10c0/{checksum}")
        ),
        "rollback restores the expanded npm: key"
    );
}

/// #404 upgrade path: a lock pinned by an earlier release carries the old
/// `npm:<v>::__archiveUrl=<url>` resolution, which makes yarn's npm fetcher
/// send registry auth to the patch host. `rollback` must still recognize and
/// restore that legacy pin, and a repeat hosted `scan` must re-pin it to the
/// tarball-URL locator.
#[tokio::test]
#[serial]
async fn yarn_berry_legacy_archive_url_pin_is_rolled_back_and_repinned() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    let hosted_url = HOSTED_URL.replace("http://patch.test", &server.uri());
    mock_reference_with_berry_url(&server, &hosted_url).await;
    mock_view(&server).await;
    let tarball = upstream_tarball();
    mock_npm_registry(
        &server,
        &vlt_hosted_common::sha512_sri(&tarball),
        Some(tarball),
    )
    .await;
    let legacy = |t: &str| {
        t.replace(
            &format!("resolution: \"{NAME}@npm:{VERSION}\""),
            &format!(
                "resolution: \"{NAME}@npm:{VERSION}::__archiveUrl={}\"",
                socket_patch_core::utils::uri::encode_uri_component(&hosted_url)
            ),
        )
        .replace(&format!("10c0/{}", "3".repeat(128)), BERRY_CHECKSUM)
    };

    // Rollback of the legacy pin restores the registry entry.
    let tmp = tempfile::tempdir().unwrap();
    write_berry_project_spelled(tmp.path(), legacy);
    let lock_path = tmp.path().join("yarn.lock");
    assert!(std::fs::read_to_string(&lock_path)
        .unwrap()
        .contains("::__archiveUrl="));
    let (code, env) = rollback_json_with_origin(tmp.path(), &server, &server.uri());
    assert_eq!(code, Some(0), "rollback: {env:#}");
    assert_eq!(
        env["hosted"]["reverted"],
        serde_json::json!([PURL]),
        "{env:#}"
    );
    let restored = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        restored.contains(&format!("\n  resolution: \"{NAME}@npm:{VERSION}\"\n"))
            && !restored.contains("__archiveUrl")
            && !restored.contains(BERRY_CHECKSUM),
        "the registry entry is restored: {restored}"
    );

    // A repeat hosted scan re-pins the legacy entry as a tarball locator.
    let tmp = tempfile::tempdir().unwrap();
    write_berry_project_spelled(tmp.path(), legacy);
    let lock_path = tmp.path().join("yarn.lock");
    let env = run_redirect_subprocess_with(
        tmp.path(),
        &server.uri(),
        &["--patch-server-url", &server.uri()],
    );
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock.contains(&format!("\n  resolution: \"{NAME}@{hosted_url}\"\n"))
            && !lock.contains("__archiveUrl"),
        "the legacy pin is migrated: {lock}"
    );
    vlt_hosted_common::assert_no_ledger(tmp.path());
}

/// A berry lock whose line endings are MIXED (CRLF and LF, or a bare CR)
/// cannot be kept in one style — and yarn itself rejects it under
/// `--immutable` — so the hosted run refuses it untouched with a code that
/// names the line endings and the `yarn install` remedy, redirecting
/// nothing and writing nothing.
#[tokio::test]
#[serial]
async fn scan_redirect_refuses_a_mixed_line_ending_yarn_berry_lock() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference_with_berry(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_berry_project_spelled(tmp.path(), |t| {
        t.replace('\n', "\r\n")
            .replacen("proceed with caution!\r\n", "proceed with caution!\n", 1)
    });
    let lock_path = tmp.path().join("yarn.lock");
    let before = std::fs::read(&lock_path).unwrap();

    let env = run_redirect_subprocess(tmp.path(), &server.uri());
    assert_eq!(env["redirect"]["redirected"], 0, "{env:#}");
    assert!(
        warning_codes(&env).contains(&"redirect_yarn_berry_mixed_line_endings".to_string()),
        "{env:#}"
    );
    let detail = redirect_warning_detail(&env, "redirect_yarn_berry_mixed_line_endings");
    assert!(detail.contains("yarn install"), "remedy named: {detail}");
    assert_eq!(std::fs::read(&lock_path).unwrap(), before, "untouched");
    assert!(
        !tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .exists(),
        "no ledger for a refused rewrite"
    );
}

/// Classic (v1) yarn.lock with CRLF line endings (Windows `core.autocrlf`
/// checkout): the full hosted chain must repoint the TARGET entry — not
/// whichever entry sorts first — and keep every untouched line CRLF
/// byte-identical. Regression: `split("\n\n")` never split a CRLF lock, so
/// the whole file was one block and the leftmost `resolved`/`integrity` (the
/// decoy's) were rewritten, then confirmed and ledgered as the target's.
#[tokio::test]
#[serial]
async fn scan_redirect_rewrites_correct_entry_in_crlf_classic_lock() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
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
    let decoy_resolved = "https://registry.yarnpkg.com/aaa-decoy/-/aaa-decoy-1.0.0.tgz#aaaa";
    let lock_lf = format!(
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
         # yarn lockfile v1\n\n\n\
         aaa-decoy@^1.0.0:\n  version \"1.0.0\"\n  resolved \"{decoy_resolved}\"\n  \
         integrity sha512-DECOYdecoy==\n\n\
         {NAME}@{VERSION}:\n  version \"{VERSION}\"\n  \
         resolved \"https://registry.yarnpkg.com/{NAME}/-/{NAME}-{VERSION}.tgz#bbbb\"\n  \
         integrity sha512-UPSTREAMupstream==\n"
    );
    std::fs::write(tmp.path().join("yarn.lock"), lock_lf.replace('\n', "\r\n")).unwrap();

    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "scan --mode hosted (classic CRLF) should succeed");

    let lock = std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap();
    assert!(
        lock.contains(&format!("resolved \"{decoy_resolved}\"\r\n"))
            && lock.contains("integrity sha512-DECOYdecoy==\r\n"),
        "the decoy entry must stay byte-identical: {lock}"
    );
    assert!(
        lock.contains(&format!("resolved \"{HOSTED_URL}\"\r\n"))
            && lock.contains(&format!("integrity {PATCHED_SHA512}\r\n")),
        "the target entry must pin the hosted patch: {lock}"
    );
    assert!(
        !lock.contains("integrity sha512-UPSTREAMupstream=="),
        "the target's upstream integrity must be gone: {lock}"
    );
    assert_eq!(
        lock.matches('\n').count(),
        lock.matches("\r\n").count(),
        "every line must keep its CRLF ending: {lock}"
    );
    vlt_hosted_common::assert_no_ledger(tmp.path());
}

/// Write a project whose only lockfile is a text `bun.lock` (registry
/// 4-tuple) at the given `lockfileVersion` (bun 1.3 emits 1, bun 1.4 emits 2
/// — same grammar either way).
fn write_bun_project(root: &Path, lock_version: u64) {
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
            "{{\n  \"lockfileVersion\": {lock_version},\n  \"packages\": {{\n    \
             \"{NAME}\": [\"{NAME}@{VERSION}\", \"\", {{}}, \"sha512-UPSTREAMupstream==\"],\n  \
             }}\n}}\n"
        ),
    )
    .unwrap();
}

/// Manifest-less VEX over a bun leg's hosted state ([`bun_vex`]): a
/// lockfile-only checkout (nothing installed, so the lock's sha512 pin is
/// the evidence) is attested `(redirected)` from the ledger and — ledgers
/// deleted — from the lock + patch API; offline → `record_unavailable`;
/// the registry lock back → NOT attested.
fn bun_manifestless_vex(root: &Path, registry_lock: &[u8], tag: &str) {
    let scratch = tempfile::tempdir().unwrap();
    let case = bun_vex::BunVexCase {
        tag,
        mode: bun_vex::BunMode::Hosted,
        purl: PURL,
        uuid: UUID,
        files: vec![("package/index.js".to_string(), "b".repeat(64))],
        vulns: &[(GHSA, &["CVE-2024-9"])],
        lock: "bun.lock",
        registry_lock: registry_lock.to_vec(),
        patch_server_url: Some("http://patch.test".to_string()),
    };
    bun_vex::run_bun_vex_matrix(root, scratch.path(), &case, |_| {});
}

/// The bun leg: the registry 4-tuple is rewritten to a URL 3-tuple carrying the
/// hosted URL + patched sha512; the upstream integrity is gone.
#[tokio::test]
#[serial]
async fn scan_redirect_rewrites_bun_lock() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), 1);
    let lock_before = std::fs::read(tmp.path().join("bun.lock")).unwrap();

    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "scan --mode hosted (bun) should succeed");

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
    vlt_hosted_common::assert_no_ledger(tmp.path());
    bun_manifestless_vex(tmp.path(), &lock_before, "bun-v1");
}

/// REGRESSION (#469): the project also gets a BUNDLED copy of the patched
/// `name@version` (`parent` bundles it; Bun unpacks it from parent's
/// tarball, so no rewire reaches it). The regular entry is redirected, but
/// the in-run `--vex` must not attest the purl while that copy stays
/// unpatched, exactly like a standalone `vex` run.
#[tokio::test]
#[serial]
async fn scan_redirect_bun_bundled_copy_is_not_attested_in_run() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), 1);
    let lock = std::fs::read_to_string(tmp.path().join("bun.lock")).unwrap();
    let bundled = format!(
        "    \"parent/{NAME}\": [\"{NAME}@{VERSION}\", \"\", {{ \"bundled\": true }},          \"sha512-UPSTREAMupstream==\"],\n  }}\n}}\n"
    );
    let lock = lock.replacen("  }\n}\n", &bundled, 1);
    std::fs::write(tmp.path().join("bun.lock"), &lock).unwrap();
    let copy = tmp
        .path()
        .join("node_modules/parent/node_modules")
        .join(NAME);
    std::fs::create_dir_all(&copy).unwrap();
    std::fs::write(
        copy.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();

    let out = tmp.path().join("out.vex.json");
    let mut args = redirect_args(tmp.path(), server.uri());
    args.vex.vex = Some(out.clone());
    args.vex.vex_product = Some("pkg:npm/consumer@0.0.0".into());
    let _ = run(args).await;

    let rewritten = std::fs::read_to_string(tmp.path().join("bun.lock")).unwrap();
    assert!(
        rewritten.contains(&format!("\"{NAME}@{HOSTED_URL}\"")),
        "the regular entry is redirected"
    );
    assert!(
        rewritten.contains(&format!("\"parent/{NAME}\": [\"{NAME}@{VERSION}\"")),
        "the bundled entry keeps its registry spec"
    );
    let attested = std::fs::read_to_string(&out)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .is_some_and(|doc| doc.to_string().contains(PURL));
    assert!(
        !attested,
        "in-run VEX must not attest a purl whose bundled copy stays unpatched"
    );
}

/// REGRESSION (#325): npm's half of #469. The hoisted entry is redirected,
/// but a parent also bundles the same `name@version` (`inBundle: true` in
/// `packages`, or the legacy `bundled: true` spelling in a v1
/// `dependencies` tree). npm unpacks that copy from the parent's tarball,
/// so it stays unpatched; the run warns
/// `redirect_npm_bundled_instance_skipped`, and its in-run `--vex` must
/// not attest the purl either.
#[tokio::test]
#[serial]
async fn scan_redirect_npm_bundled_copy_is_not_attested_in_run() {
    let packages_lock = format!(
        r#"{{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {{
    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "{VERSION}", "parent": "2.0.0" }} }},
    "node_modules/{NAME}": {{
      "version": "{VERSION}",
      "resolved": "https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz",
      "integrity": "sha512-UPSTREAMupstream=="
    }},
    "node_modules/parent": {{
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/parent/-/parent-2.0.0.tgz",
      "integrity": "sha512-PARENT=="
    }},
    "node_modules/parent/node_modules/{NAME}": {{
      "version": "{VERSION}",
      "inBundle": true,
      "integrity": "sha512-UPSTREAMupstream=="
    }}
  }}
}}
"#
    );
    let legacy_lock = format!(
        r#"{{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {{
    "{NAME}": {{
      "version": "{VERSION}",
      "resolved": "https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz",
      "integrity": "sha512-UPSTREAMupstream=="
    }},
    "parent": {{
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/parent/-/parent-2.0.0.tgz",
      "integrity": "sha512-PARENT==",
      "dependencies": {{
        "{NAME}": {{
          "version": "{VERSION}",
          "bundled": true
        }}
      }}
    }}
  }}
}}
"#
    );
    for (shape, lock) in [("inBundle", packages_lock), ("legacy bundled", legacy_lock)] {
        let server = MockServer::start().await;
        mock_discovery(&server).await;
        mock_reference(&server).await;
        mock_view(&server).await;

        let tmp = tempfile::tempdir().unwrap();
        write_project(tmp.path());
        std::fs::write(tmp.path().join("package-lock.json"), &lock).unwrap();
        let copy = tmp
            .path()
            .join("node_modules/parent/node_modules")
            .join(NAME);
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::write(
            copy.join("package.json"),
            format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("node_modules/parent/package.json"),
            format!(
                r#"{{ "name": "parent", "version": "2.0.0", "bundleDependencies": ["{NAME}"] }}"#
            ),
        )
        .unwrap();

        let out = tmp.path().join("out.vex.json");
        let mut args = redirect_args(tmp.path(), server.uri());
        args.vex.vex = Some(out.clone());
        args.vex.vex_product = Some("pkg:npm/consumer@0.0.0".into());
        let _ = run(args).await;

        let rewritten = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
        assert!(
            rewritten.contains(HOSTED_URL),
            "{shape}: the regular entry is redirected:\n{rewritten}"
        );
        let attested = std::fs::read_to_string(&out)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .is_some_and(|doc| doc.to_string().contains(PURL));
        assert!(
            !attested,
            "{shape}: in-run VEX must not attest a purl whose bundled copy stays unpatched"
        );
    }
}

/// npm 7+ installs from the v2 `packages` map. An ignored legacy bundled
/// flag must not block the hosted in-run attestation before that install.
#[tokio::test]
#[serial]
async fn scan_redirect_npm_stale_legacy_bundle_mirror_still_attests() {
    for lockfile in ["package-lock.json", "npm-shrinkwrap.json"] {
        let server = MockServer::start().await;
        mock_discovery(&server).await;
        mock_reference(&server).await;
        mock_view(&server).await;
        let tmp = tempfile::tempdir().unwrap();
        write_project(tmp.path());
        std::fs::write(
            tmp.path().join("node_modules").join(NAME).join("index.js"),
            b"upstream bytes before the next install\n",
        )
        .unwrap();
        let original = tmp.path().join("package-lock.json");
        let mut lock: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&original).unwrap()).unwrap();
        lock["lockfileVersion"] = serde_json::json!(2);
        lock["dependencies"] = serde_json::json!({
            NAME: {
                "version": VERSION,
                "resolved": format!("https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz"),
                "integrity": "sha512-UPSTREAMupstream==",
                "bundled": true
            }
        });
        std::fs::write(&original, serde_json::to_vec_pretty(&lock).unwrap()).unwrap();
        if lockfile != "package-lock.json" {
            std::fs::rename(&original, tmp.path().join(lockfile)).unwrap();
        }
        let out = tmp.path().join("out.vex.json");
        let mut args = redirect_args(tmp.path(), server.uri());
        args.vex.vex = Some(out.clone());
        args.vex.vex_product = Some("pkg:npm/consumer@0.0.0".into());
        let exit = run(args).await;
        assert_eq!(
            exit, 0,
            "{lockfile}: npm consumes the normal packages entry"
        );
        let document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        assert!(
            document.to_string().contains(PURL),
            "{lockfile}: {document:#}"
        );
        assert_eq!(document["statements"][0]["status"], "not_affected");
        let rewritten: serde_json::Value =
            serde_json::from_slice(&std::fs::read(tmp.path().join(lockfile)).unwrap()).unwrap();
        assert_eq!(
            rewritten["packages"][format!("node_modules/{NAME}")]["resolved"],
            HOSTED_URL
        );
        assert_eq!(rewritten["dependencies"][NAME]["bundled"], true);
    }
}

/// The bun 1.4 leg: `"lockfileVersion": 2` is the SAME emitted grammar as 1
/// (bun 1.4 bumped the integer to gate stricter parse checks — oven-sh/bun
/// PR #31539 — same-fixture locks are byte-identical except the integer), so
/// the rewrite must proceed exactly like v1 and preserve the version line.
#[tokio::test]
#[serial]
async fn scan_redirect_rewrites_bun_lock_v2() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), 2);
    let lock_before = std::fs::read(tmp.path().join("bun.lock")).unwrap();

    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "scan --mode hosted (bun, lock v2) should succeed");

    let lock = std::fs::read_to_string(tmp.path().join("bun.lock")).unwrap();
    assert!(
        lock.contains("\"lockfileVersion\": 2,"),
        "the version line must be preserved verbatim; got:\n{lock}"
    );
    assert!(
        lock.contains(&format!("\"{NAME}@{HOSTED_URL}\"")),
        "the tuple's spec must be name@<hosted url>; got:\n{lock}"
    );
    assert!(
        lock.contains(PATCHED_SHA512),
        "integrity must be the patched sha512"
    );
    vlt_hosted_common::assert_no_ledger(tmp.path());
    bun_manifestless_vex(tmp.path(), &lock_before, "bun-v2");
}

/// A future `lockfileVersion` (3) has no byte-exact fixtures: the rewrite
/// must refuse whole (fail closed), leave the lock byte-identical, count
/// nothing redirected, and surface `redirect_bun_lock_unsupported` in the
/// `--json` envelope. Subprocess so `redirected` and `warnings[]` can be
/// read back.
#[tokio::test]
#[serial]
async fn scan_redirect_refuses_bun_lock_v3() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), 3);
    let before = std::fs::read_to_string(tmp.path().join("bun.lock")).unwrap();

    let env = run_redirect_subprocess(tmp.path(), &server.uri());
    assert_eq!(
        env["redirect"]["redirected"], 0,
        "an unsupported lock version must redirect nothing: {env}"
    );
    assert!(
        warning_codes(&env).contains(&"redirect_bun_lock_unsupported".to_string()),
        "the refusal must reach the envelope: {env}"
    );
    let after = std::fs::read_to_string(tmp.path().join("bun.lock")).unwrap();
    assert_eq!(
        after, before,
        "fail-closed: the lock must be byte-untouched"
    );
    assert!(
        !after.contains(HOSTED_URL),
        "the hosted URL must never appear in a refused lock: {after}"
    );
}

/// The packages-entry line keyed `key` in a bun.lock (verbatim, no line
/// terminator).
fn bun_packages_line(lock: &str, key: &str) -> String {
    let prefix = format!("    \"{key}\": [");
    lock.split('\n')
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no `{key}` packages entry in:\n{lock}"))
        .trim_end_matches('\r')
        .to_string()
}

/// Re-spell a URL 3-tuple line the way Bun 1.1.39–1.3.9 re-save it on any
/// later lock re-save (`bun add <pkg>`, `bun install` after a package.json
/// change): the trailing `"sha512-…"` element dropped, everything else
/// verbatim (measured on real 1.1.45, 1.2.23 and 1.3.9; 1.3.10+ keep it).
fn drop_bun_digest(line: &str) -> String {
    let cut = line
        .rfind(", \"sha512-")
        .unwrap_or_else(|| panic!("no sha512 element in {line}"));
    let tail = if line.ends_with("],") { "]," } else { "]" };
    format!("{}{tail}", &line[..cut])
}

/// Bun 1.1.39–1.3.9 re-save our URL 3-tuple WITHOUT its sha512 whenever the
/// lock is re-saved for another reason. The digest-less 2-tuple is still
/// our wiring (the spec bun installs from is intact): a repeat `scan
/// --mode hosted` must report a CONSISTENT envelope — `redirected: 1` with
/// no `redirect_bun_entry_not_found` — and heal the line back to the
/// 3-tuple; a third run is a no-op; no run writes a ledger; and `rollback`
/// must restore the pristine registry line (re-resolved from the mocked npm
/// registry) whether the lock is the healed 3-tuple or Bun has since
/// dropped the digest again.
#[tokio::test]
#[serial]
async fn scan_redirect_heals_digestless_bun_tuple_and_rollback_restores_the_registry_line() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    // The record fetch too, so the "no warnings at all" assertion below is
    // exact (without it every run carries a `record_fetch_failed` advisory).
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), 1);
    let lock_path = tmp.path().join("bun.lock");
    let pristine = std::fs::read_to_string(&lock_path).unwrap();
    mock_npm_registry(&server, "sha512-UPSTREAMupstream==", None).await;

    for drop_again_before_rollback in [false, true] {
        let env = run_redirect_subprocess(tmp.path(), &server.uri());
        assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
        let wired = std::fs::read_to_string(&lock_path).unwrap();
        let wired_line = bun_packages_line(&wired, NAME);
        assert!(
            wired_line.contains(HOSTED_URL) && wired_line.contains(PATCHED_SHA512),
            "{wired_line}"
        );
        let digestless = drop_bun_digest(&wired_line);
        assert!(
            digestless.ends_with("{}],") && !digestless.contains("sha512"),
            "{digestless}"
        );
        std::fs::write(&lock_path, wired.replace(&wired_line, &digestless)).unwrap();

        // Repeat hosted run over the digest-less lock.
        let env = run_redirect_subprocess(tmp.path(), &server.uri());
        assert_eq!(env["status"], "success", "{env:#}");
        assert_eq!(
            env["redirect"]["redirected"], 1,
            "the wired dep still counts as redirected: {env:#}"
        );
        let codes = warning_codes(&env);
        assert!(
            !codes.contains(&"redirect_bun_entry_not_found".to_string()),
            "a digest-less instance of our own wiring is not `entry_not_found`: {env:#}"
        );
        assert_eq!(
            std::fs::read_to_string(&lock_path).unwrap(),
            wired,
            "the digest is healed back — lock byte-identical to the first run's"
        );
        vlt_hosted_common::assert_no_ledger(tmp.path());

        // A third run over the healed lock is a no-op.
        let env = run_redirect_subprocess(tmp.path(), &server.uri());
        assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
        assert!(warning_codes(&env).is_empty(), "{env:#}");
        assert_eq!(std::fs::read_to_string(&lock_path).unwrap(), wired);

        if drop_again_before_rollback {
            // Another `bun add` on Bun < 1.3.10: the digest is gone again.
            std::fs::write(&lock_path, wired.replace(&wired_line, &digestless)).unwrap();
        }
        let (code, env) = rollback_json(tmp.path(), &server);
        assert_eq!(
            code,
            Some(0),
            "rollback (digest dropped again: {drop_again_before_rollback}) must succeed: {env:#}"
        );
        assert_eq!(env["status"], "success", "{env:#}");
        assert_eq!(
            std::fs::read_to_string(&lock_path).unwrap(),
            pristine,
            "rollback lands on the pristine registry line (digest dropped again: \
             {drop_again_before_rollback})"
        );
        vlt_hosted_common::assert_no_ledger(tmp.path());
    }
}

// Native binary lockfiles are parsed and patched without invoking Bun.
const INVALID_LOCKB_BYTES: &[u8] = b"\x00BUN-BINARY\xff\xfe\x00LOCK";

/// `rollback --json --yes` as a subprocess, with the mock patch host
/// recognized (`--patch-server-url http://patch.test`, so lockfile
/// discovery finds the hosted pins) and the upstream restore's npm registry
/// pointed at `registry` (`SOCKET_NPM_REGISTRY`, see [`mock_npm_registry`]);
/// returns (exit code, parsed envelope).
fn rollback_json(cwd: &Path, registry: &MockServer) -> (Option<i32>, serde_json::Value) {
    rollback_json_with_origin(cwd, registry, "http://patch.test")
}

fn rollback_json_with_origin(
    cwd: &Path,
    registry: &MockServer,
    origin: &str,
) -> (Option<i32>, serde_json::Value) {
    hosted_unwind_json(cwd, registry, origin, &["rollback"])
}

/// `<command…> --json --yes` as a subprocess against the hosted pins of
/// `origin`, the upstream restore reading `registry` — the shared runner
/// behind [`rollback_json`] and [`remove_json`].
fn hosted_unwind_json(
    cwd: &Path,
    registry: &MockServer,
    origin: &str,
    command: &[&str],
) -> (Option<i32>, serde_json::Value) {
    let out = scrubbed_cli()
        .args(command)
        .args([
            "--json",
            "--yes",
            "--patch-server-url",
            origin,
            "--cwd",
            cwd.to_str().unwrap(),
        ])
        .env(
            "SOCKET_NPM_REGISTRY",
            format!("{}/npm-registry", registry.uri()),
        )
        .output()
        .unwrap_or_else(|e| panic!("run socket-patch {}: {e}", command[0]));
    let env_json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{} --json stdout must be JSON: {e}\nstdout:\n{}\nstderr:\n{}",
            command[0],
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code(), env_json)
}

/// The npm registry's version document for `NAME@VERSION` under
/// `<server>/npm-registry` — what rollback's upstream restore re-resolves a
/// hosted pin from — carrying `integrity`, plus (when given) the upstream
/// `tarball` served at the document's `dist.tarball` (a yarn berry restore
/// downloads it to recompute the zip checksum).
async fn mock_npm_registry(server: &MockServer, integrity: &str, tarball: Option<Vec<u8>>) {
    let tarball_path = format!("/npm-registry/{NAME}/-/{NAME}-{VERSION}.tgz");
    Mock::given(method("GET"))
        .and(path(format!("/npm-registry/{NAME}/{VERSION}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": NAME,
            "version": VERSION,
            "dist": {
                "tarball": format!("{}{tarball_path}", server.uri()),
                "integrity": integrity,
                "shasum": "0".repeat(40),
            }
        })))
        .mount(server)
        .await;
    if let Some(bytes) = tarball {
        let checksum =
            socket_patch_core::vendor::test_support::service_fixture::berry_checksum(&bytes, NAME)
                .unwrap();
        Mock::given(method("GET"))
            .and(path(format!("/upstream/npm/{UUID}.json")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": NAME, "version": VERSION, "integrity": integrity, "yarnBerry10c0": checksum
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(tarball_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
            .mount(server)
            .await;
    }
}

/// A small upstream npm tarball for `NAME@VERSION`.
fn upstream_tarball() -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(gz);
    let package_json = format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#);
    for (name, data) in [
        ("package/package.json", package_json.as_bytes()),
        (
            "package/index.js",
            b"module.exports = 'upstream'\n".as_slice(),
        ),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, data).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// The `checksum: 10c0/<hex>` value of the target entry in a berry lock.
fn berry_checksum_of(lock: &str) -> String {
    let at = lock
        .find(&format!("\"{NAME}@npm:^{VERSION}\":"))
        .unwrap_or_else(|| panic!("no target entry in {lock:?}"));
    let rest = &lock[at..];
    let line = rest
        .split('\n')
        .find_map(|l| {
            l.trim_end_matches('\r')
                .trim()
                .strip_prefix("checksum: 10c0/")
        })
        .unwrap_or_else(|| panic!("no checksum in {rest:?}"));
    line.to_string()
}

/// A child-only PATH with `bin_dir` first, joined with the OS separator.
fn path_with_first(bin_dir: &Path) -> std::ffi::OsString {
    let mut entries = vec![bin_dir.to_path_buf()];
    entries.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    std::env::join_paths(entries).expect("PATH entries join")
}

/// `scan --mode hosted --json --yes` as a subprocess with the given child PATH;
/// returns (exit code, parsed envelope, stderr). Asserts stdout IS JSON so a
/// leaking shim (bun chatter on stdout) fails loudly.
fn scan_redirect_json_with_path(
    cwd: &Path,
    api_url: &str,
    path: &std::ffi::OsStr,
) -> (Option<i32>, serde_json::Value, String) {
    let out = scrubbed_cli()
        .args([
            "scan",
            "--mode=hosted",
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
        .env("PATH", path)
        .output()
        .expect("run socket-patch");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let env_json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "--json stdout must be a pure JSON envelope: {e}\nstdout:\n{}\nstderr:\n{stderr}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    (out.status.code(), env_json, stderr)
}

/// The `detail` of the first redirect warning carrying `code`.
fn redirect_warning_detail(env: &serde_json::Value, code: &str) -> String {
    env["redirect"]["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|w| w["code"] == code)
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_else(|| panic!("expected a `{code}` redirect warning: {env:#}"))
        .to_string()
}

/// package.json + installed copy + a binary lockfile.
fn write_bun_lockb_project(root: &Path, lockb: &[u8]) {
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
    std::fs::write(root.join("bun.lockb"), lockb).unwrap();
}

#[cfg(unix)]
fn install_bun_shim(root: &Path, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin = root.join("fakebin");
    std::fs::create_dir_all(&bin).unwrap();
    let shim = bin.join("bun");
    std::fs::write(&shim, body).unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_bun_lockb_refuses_before_editing_including_dry_run() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    for dry_run in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_bun_lockb_project(root, INVALID_LOCKB_BYTES);
        std::fs::rename(root.join("bun.lockb"), root.join("shared.lockb")).unwrap();
        std::os::unix::fs::symlink("shared.lockb", root.join("bun.lockb")).unwrap();
        let bin = install_bun_shim(root, "#!/bin/sh\ntouch bun-was-spawned\nexit 1\n");
        let mut cmd = scrubbed_cli();
        cmd.args([
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            root.to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ])
        .env("PATH", path_with_first(&bin));
        if dry_run {
            cmd.arg("--dry-run");
        }
        let output = cmd.output().unwrap();
        let env: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(1), "{env:#}");
        assert_eq!(
            env["errorCode"], "redirect_symlinked_file_unsupported",
            "{env:#}"
        );
        assert_eq!(
            std::fs::read_link(root.join("bun.lockb")).unwrap(),
            std::path::Path::new("shared.lockb")
        );
        assert_eq!(
            std::fs::read(root.join("shared.lockb")).unwrap(),
            INVALID_LOCKB_BYTES
        );
        assert!(!root.join("bun-was-spawned").exists());
        assert!(!root.join("bun.lock").exists());
        assert!(!root.join(".socket/vendor/redirect-state.json").exists());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn malformed_binary_lock_never_spawns_bun_or_changes_format() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    for bytes in [
        INVALID_LOCKB_BYTES.to_vec(),
        vec![0xAB; 8 * 1024 * 1024 + 1],
    ] {
        let tmp = tempfile::tempdir().unwrap();
        write_bun_lockb_project(tmp.path(), &bytes);
        let bin = install_bun_shim(
            tmp.path(),
            "#!/bin/sh\necho SHOULD-NOT-RUN\ntouch bun-was-spawned\nexit 1\n",
        );
        let (code, env, stderr) =
            scan_redirect_json_with_path(tmp.path(), &server.uri(), &path_with_first(&bin));
        assert_eq!(code, Some(0), "{env:#}\n{stderr}");
        assert_eq!(env["redirect"]["redirected"], 0, "{env:#}");
        assert!(!redirect_warning_detail(&env, "redirect_bun_lockb_invalid").is_empty());
        assert!(!warning_codes(&env).contains(&"redirect_npm_no_lockfile".to_string()));
        assert_eq!(std::fs::read(tmp.path().join("bun.lockb")).unwrap(), bytes);
        assert!(!tmp.path().join("bun.lock").exists());
        assert!(!tmp.path().join("bun-was-spawned").exists());
        assert!(!tmp
            .path()
            .join(".socket/vendor/redirect-state.json")
            .exists());
    }
}

#[tokio::test]
async fn native_binary_no_matching_version_preserves_exact_bytes() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    // This real Bun lock resolves minimist/is-number; the grant targets a
    // different installed package, so no binary record may be rewritten.
    let bytes = include_bytes!("../../socket-patch-core/tests/fixtures/bun-lockb/1.1.45/bun.lockb");
    write_bun_lockb_project(tmp.path(), bytes);
    let (code, env, stderr) =
        scan_redirect_json_with_path(tmp.path(), &server.uri(), std::ffi::OsStr::new(""));
    assert_eq!(code, Some(0), "{env:#}\n{stderr}");
    assert_eq!(env["redirect"]["redirected"], 0, "{env:#}");
    assert_eq!(std::fs::read(tmp.path().join("bun.lockb")).unwrap(), bytes);
    assert!(!tmp.path().join("bun.lock").exists());
    assert!(!tmp
        .path()
        .join(".socket/vendor/redirect-state.json")
        .exists());
}

/// A `socket-patch` Command with the ambient `SOCKET_*` env surface scrubbed,
/// for the subprocess tests below: the binary binds a wide clap env surface
/// (SOCKET_DRY_RUN, SOCKET_OFFLINE, SOCKET_ECOSYSTEMS, SOCKET_PROXY_URL, ...),
/// and an ambient value silently changes what these tests exercise — ambient
/// `SOCKET_DRY_RUN=true` turns the rewrite into a no-op and every on-disk
/// oracle red. Seed-then-scrub (the `common/mod.rs` pattern): the hostile
/// seeds never reach the child because `env_remove` clears them too, but if a
/// scrub line is ever dropped the seed turns the suite red immediately.
/// Telemetry opt-outs are deliberately kept so an opted-out dev stays opted
/// out. The in-process tests above don't need this — their literal `ScanArgs`
/// bypass clap's env bindings entirely.
fn scrubbed_cli() -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.env("SOCKET_DRY_RUN", "true")
        .env("SOCKET_OFFLINE", "true")
        .env("SOCKET_ECOSYSTEMS", "cargo")
        .env("SOCKET_MANIFEST_PATH", "/nonexistent/manifest.json")
        .env_remove("SOCKET_DRY_RUN")
        .env_remove("SOCKET_OFFLINE")
        .env_remove("SOCKET_ECOSYSTEMS")
        .env_remove("SOCKET_MANIFEST_PATH");
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_") && !name.contains("TELEMETRY") && name != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&key);
        }
    }
    // In-process tests in this binary `std::env::set_var` these via
    // `apply_env_toggles`; one set by a parallel test between the scan
    // above and the spawn would be inherited, so remove them
    // unconditionally (see in_process_vendor.rs `run_cli`).
    for key in [
        "SOCKET_OFFLINE",
        "SOCKET_DEBUG",
        "SOCKET_API_URL",
        "SOCKET_PROXY_URL",
    ] {
        cmd.env_remove(key);
    }
    cmd
}

/// A denied patch reference never changes the project's binary lockfile
/// or invokes an installer, even when a Bun shim is available on PATH.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn no_redirectable_patch_leaves_bun_lockb_alone() {
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

    let bin_dir = install_bun_shim(
        tmp.path(),
        "#!/bin/sh\n: > \"${0%/*}/bun-was-spawned\"\nexit 97\n",
    );
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: single-threaded #[serial] test; PATH restored below.
    unsafe {
        std::env::set_var("PATH", format!("{}:{orig_path}", bin_dir.display()));
    }

    let code = run(redirect_args(tmp.path(), server.uri())).await;

    unsafe {
        std::env::set_var("PATH", orig_path);
    }
    assert_eq!(code, 0, "a fully-skipped redirect still exits 0");
    assert!(!bin_dir.join("bun-was-spawned").exists());
    assert!(
        tmp.path().join("bun.lockb").exists(),
        "bun.lockb must survive a scan that redirected nothing"
    );
    assert!(
        !tmp.path().join("bun.lock").exists(),
        "no text lock may be created when nothing is redirectable"
    );
    assert!(
        !tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .exists(),
        "no ledger may be written when nothing was redirected"
    );
}

/// A corrupt pre-v5 redirect ledger is IGNORED (v5 never reads it): the
/// binary-lockfile path runs exactly as without it — here a placeholder
/// `bun.lockb` the native codec rejects (exit 0, nothing redirected) — no
/// Bun process starts, no text lock appears, and the torn ledger is left
/// byte-identical in place (never quarantined).
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn corrupt_pre_v5_ledger_is_ignored_beside_a_bun_lockb() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
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

    let ledger_path = tmp.path().join(".socket/vendor/redirect-state.json");
    std::fs::create_dir_all(ledger_path.parent().unwrap()).unwrap();
    let corrupt_bytes = b"{\"mode\":\"hosted\",\"edits\":[{\"path\":\"bun.lo";
    std::fs::write(&ledger_path, corrupt_bytes).unwrap();

    let bin_dir = install_bun_shim(
        tmp.path(),
        "#!/bin/sh\n: > \"${0%/*}/bun-was-spawned\"\nexit 97\n",
    );
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: single-threaded #[serial] test; PATH restored below.
    unsafe {
        std::env::set_var("PATH", format!("{}:{orig_path}", bin_dir.display()));
    }

    let code = run(redirect_args(tmp.path(), server.uri())).await;

    unsafe {
        std::env::set_var("PATH", orig_path);
    }
    assert_eq!(code, 0, "a pre-v5 ledger never fails a hosted run");
    assert!(!bin_dir.join("bun-was-spawned").exists());
    assert_eq!(
        std::fs::read(tmp.path().join("bun.lockb")).ok().as_deref(),
        Some(b"BUN-BINARY-PLACEHOLDER".as_slice()),
        "the unparseable binary lock stays byte-untouched"
    );
    assert!(!tmp.path().join("bun.lock").exists());
    assert_eq!(
        std::fs::read(&ledger_path).unwrap(),
        corrupt_bytes,
        "the pre-v5 ledger is left byte-identical in place"
    );
    assert!(!tmp
        .path()
        .join(".socket/vendor/redirect-state.json.corrupt")
        .exists());
}

/// A DIRECTORY squatting on the pre-v5 ledger path used to make the run
/// fail closed (the ledger was the revert path). v5 hosted mode never reads
/// or writes that path, so the run succeeds, the lock is redirected, and
/// the squatting directory is left alone.
#[tokio::test]
#[serial]
async fn directory_at_the_legacy_ledger_path_does_not_block_the_run() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let squatter = tmp.path().join(".socket/vendor/redirect-state.json");
    std::fs::create_dir_all(&squatter).unwrap();

    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "the legacy ledger path is not consulted");
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        lock.contains(HOSTED_URL),
        "the lock is redirected; got:\n{lock}"
    );
    assert!(squatter.is_dir(), "the squatting directory is untouched");
}

/// A MID-RUN lockfile write failure (second of two locks unwritable) exits
/// 1; the first lock landed, the failed lock stays byte-untouched (atomic
/// stage+rename, no truncation), and no ledger is written (v5: a landed
/// hosted pin is undone by `rollback`'s upstream restore, which needs no
/// recorded originals).
///
/// unix-only: a read-only directory does not block file creation on Windows.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn partial_lockfile_write_failure_exits_1_and_writes_no_ledger() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    // Rush repo: two pnpm locks, both resolving the patched package. The
    // rewriter output map is a BTreeMap, so the common lock
    // (common/config/rush/…) is written before the subspace lock
    // (common/config/subspaces/…).
    write_rush_project(tmp.path(), false);
    let subspace_dir = tmp.path().join("common/config/subspaces/frontend");
    let before_subspace = std::fs::read_to_string(subspace_dir.join("pnpm-lock.yaml")).unwrap();
    std::fs::set_permissions(&subspace_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

    let code = run(redirect_args(tmp.path(), server.uri())).await;

    std::fs::set_permissions(&subspace_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(code, 1, "a mid-run lockfile write failure must exit 1");

    // The first lock landed before the failure…
    let common =
        std::fs::read_to_string(tmp.path().join("common/config/rush/pnpm-lock.yaml")).unwrap();
    assert!(
        common.contains(HOSTED_URL),
        "the common lock was written before the subspace failure; got:\n{common}"
    );
    vlt_hosted_common::assert_no_ledger(tmp.path());

    // The failed lock is byte-untouched — no partial/truncated write.
    assert_eq!(
        std::fs::read_to_string(subspace_dir.join("pnpm-lock.yaml")).unwrap(),
        before_subspace,
        "the unwritable lock must stay byte-identical (atomic writes)"
    );
}

// ── Rush monorepo ────────────────────────────────────────────────────────

/// A Rush pnpm lock (v9) resolving the patched package under `packages:`, so
/// the pnpm redirect rewriter has a `NAME@VERSION` block to repoint.
/// `pkg_name` is the package the lock resolves (both the common and the
/// subspace lock pass `NAME`).
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

/// `scan --mode hosted` in a Rush monorepo rewrites BOTH the common
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
    assert_eq!(code, 0, "scan --mode hosted should succeed in a Rush repo");

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
    // And no root pnpm-workspace.yaml either: rush runs pnpm in common/temp,
    // which never reads the repo root, so the trustLockfile auto-config
    // (root-lock-gated) must stay hands-off here — writing it would be
    // config theater.
    assert!(
        !tmp.path().join("pnpm-workspace.yaml").exists(),
        "rush nested-lock redirects must not create a root pnpm-workspace.yaml"
    );

    vlt_hosted_common::assert_no_ledger(tmp.path());
}

/// Run the built `socket-patch` binary as a subprocess against `api_url`
/// (a wiremock server) so we can parse the `--json` envelope's `warnings`
/// array — the in-process `run` writes JSON to the process stdout, which a
/// hosting test can't read back. No package-manager binary is needed: the
/// rewrite is pure text over the fixture locks.
fn run_redirect_subprocess(cwd: &Path, api_url: &str) -> serde_json::Value {
    run_redirect_subprocess_with(cwd, api_url, &[])
}

/// [`run_redirect_subprocess`] with extra CLI flags appended (e.g. the
/// `--no-trust-lockfile-config` opt-out), so flag-dependent envelope shapes
/// are exercised through the real clap parse.
fn run_redirect_subprocess_with(cwd: &Path, api_url: &str, extra: &[&str]) -> serde_json::Value {
    let out = scrubbed_cli()
        .args([
            "scan",
            "--mode=hosted",
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
        .args(extra)
        .output()
        .expect("run socket-patch");
    assert_eq!(
        out.status.code(),
        Some(0),
        "scan --mode hosted must succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "scan --mode hosted --json output is not JSON: {e}\nstdout:\n{}",
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

/// A patched dep whose ONLY lock instance is bundled (`inBundle: true`)
/// must not be redirected: npm extracts that copy from its parent's tarball
/// and ignores the entry's resolved/integrity, so a rewrite would confirm —
/// and VEX-attest — a patch whose bytes never install. The run must report
/// `redirected: 0`, leave the lockfile byte-identical, and carry the loud
/// stays-UNPATCHED warning. Subprocess so the `--json` envelope's
/// `redirected` count and `warnings[]` can be read back.
#[tokio::test]
#[serial]
async fn redirect_inbundle_only_dep_is_skipped_not_confirmed() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().expect("create the fixture tempdir");
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "consumer", "version": "0.0.0", "dependencies": { "parent": "2.0.0" } }"#,
    )
    .expect("write the consumer package.json");
    // Installed tree: the patched package exists only as parent's bundled
    // nested copy — the crawler still discovers it there.
    let parent = tmp.path().join("node_modules").join("parent");
    std::fs::create_dir_all(&parent).expect("create node_modules/parent");
    std::fs::write(
        parent.join("package.json"),
        r#"{ "name": "parent", "version": "2.0.0", "bundleDependencies": ["in-proc-redirect"] }"#,
    )
    .expect("write the bundling parent's package.json");
    let nested = parent.join("node_modules").join(NAME);
    std::fs::create_dir_all(&nested).expect("create the bundled nested copy's dir");
    std::fs::write(
        nested.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .expect("write the bundled nested copy's package.json");
    let lock = format!(
        r#"{{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {{
    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "parent": "2.0.0" }} }},
    "node_modules/parent": {{
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/parent/-/parent-2.0.0.tgz",
      "integrity": "sha512-PARENT=="
    }},
    "node_modules/parent/node_modules/{NAME}": {{
      "version": "{VERSION}",
      "inBundle": true,
      "integrity": "sha512-UPSTREAMupstream=="
    }}
  }}
}}
"#
    );
    std::fs::write(tmp.path().join("package-lock.json"), &lock)
        .expect("write the bundled-instance package-lock.json");

    let env = run_redirect_subprocess(tmp.path(), &server.uri());
    assert_eq!(
        env["redirect"]["redirected"], 0,
        "a bundled-only dep must NOT be counted redirected: {env}"
    );
    let codes = warning_codes(&env);
    assert!(
        codes.contains(&"redirect_npm_bundled_instance_skipped".to_string()),
        "the stays-UNPATCHED warning must reach the envelope: {env}"
    );
    let after = std::fs::read_to_string(tmp.path().join("package-lock.json"))
        .expect("read back the package-lock.json the run must have left alone");
    assert_eq!(after, lock, "the lockfile must be byte-untouched");
    assert!(
        !after.contains(HOSTED_URL),
        "the hosted URL must never appear (it would confirm + attest): {after}"
    );
}

/// A pnpm v6 lock resolving the patched dep through BOTH a plain key and a
/// malformed peer key with an unclosed parenthesis must be refused whole:
/// `redirected: 0`, the lock byte-untouched, the hosted URL nowhere (a
/// partial splice would have landed it in the lock, and the confirmation
/// probe would then confirm + VEX-attest the dep while dependents through
/// the unsupported instance keep installing the unpatched upstream tarball),
/// a `redirect_pnpm_unsupported_lock_key` warning naming the residual key,
/// and no redirect-ledger record claiming the purl. Subprocess so the
/// `--json` envelope's `redirected` count and `warnings[]` can be read back.
#[tokio::test]
#[serial]
async fn redirect_pnpm_malformed_peer_residual_refuses_dep_not_confirmed() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().expect("create the fixture tempdir");
    std::fs::write(
        tmp.path().join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "{VERSION}" }} }}"#
        ),
    )
    .expect("write the consumer package.json");
    let pkg = tmp.path().join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).expect("create the installed package dir");
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .expect("write the installed package.json");
    let lock = format!(
        "lockfileVersion: '6.0'

dependencies:
  {NAME}:
    specifier: {VERSION}
    version: {VERSION}

packages:

  /{NAME}@{VERSION}:
    resolution: {{integrity: sha512-UPSTREAMupstream==}}
    dev: false

  /{NAME}@{VERSION}(react@18.2.0(scheduler@0.23.2):
    resolution: {{integrity: sha512-UPSTREAMupstream==}}
    dev: false
"
    );
    std::fs::write(tmp.path().join("pnpm-lock.yaml"), &lock)
        .expect("write the mixed plain + malformed-peer pnpm lock");

    let env = run_redirect_subprocess(tmp.path(), &server.uri());
    assert_eq!(
        env["redirect"]["redirected"], 0,
        "a residual-instance dep must NOT be counted redirected: {env}"
    );
    let codes = warning_codes(&env);
    assert!(
        codes.contains(&"redirect_pnpm_unsupported_lock_key".to_string()),
        "the residual refusal warning must reach the envelope: {env}"
    );
    let after = std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml"))
        .expect("read back the pnpm-lock.yaml the run must have left alone");
    assert_eq!(after, lock, "the lockfile must be byte-untouched");
    assert!(
        !after.contains(HOSTED_URL),
        "the hosted URL must never appear (it would confirm + attest): {after}"
    );
    // And nothing else half-claims the purl (v5 writes no ledger at all).
    vlt_hosted_common::assert_no_ledger(tmp.path());
}

/// The rewriters' own warnings must reach HUMAN mode too, not just the
/// `--json` envelope: they carry the load-bearing "why nothing happened /
/// what you must do" guidance (`redirect_npm_no_lockfile`, the hosted
/// Gradle planner's refusal codes and its `redirect_gradle_manual_snippet`
/// fallback, the missing-integrity family).
/// Regression guard: the human branch printed skipped/record/rush warnings
/// but dropped `rewrite.warnings` entirely, so a default-mode
/// `scan --mode hosted` in a lockfile-less project reported "Redirected 0
/// package(s)" with no explanation at all. Subprocess (not in-process) so
/// stderr can be read back.
#[tokio::test]
#[serial]
async fn redirect_human_mode_prints_rewriter_warnings() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    // Installed tree + package.json only — NO lockfile, so the npm rewriter
    // emits `redirect_npm_no_lockfile` for the granted override.
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

    let out = scrubbed_cli()
        .args([
            "scan",
            "--mode=hosted",
            "--yes",
            "--cwd",
            tmp.path().to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ])
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a no-op redirect still exits 0; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("Switched 0 packages to hosted patches; rewrote 0 files."),
        "anchor: the run must have taken the human-mode redirect branch; \
         stdout=\n{stdout}"
    );
    assert!(
        stderr.contains("Warning: No package-lock.json"),
        "human mode must print the rewriter's no-lockfile warning (JSON mode \
         already carries it); stderr=\n{stderr}"
    );
}

/// Human-mode `skipped` lines and the record/rush warnings are built
/// as `serde_json::Value`s and were printed with `{}` — `Display` for `Value`
/// emits JSON, so every one of them reached the terminal wrapped in literal
/// double quotes (`skipped "pkg:npm/x@1.0.0" ("forbidden")`, `warning: "…"`),
/// unlike the adjacent `rewrite.warnings` line which prints the bare `String`.
/// Both legs run as subprocesses so stderr can be read back.
#[tokio::test]
#[serial]
async fn redirect_human_mode_warnings_are_not_json_quoted() {
    // Leg 1 — a DENIED reference produces a `skipped` line.
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": { UUID: { "status": "forbidden", "url": null, "purl": PURL, "artifacts": [], "registryOverride": null } }
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let out = scrubbed_cli()
        .args([
            "scan",
            "--mode=hosted",
            "--yes",
            "--cwd",
            tmp.path().to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ])
        .output()
        .expect("run socket-patch");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!(
            "{PURL}: not entitled to this patch (paid plan or no org access)"
        )),
        "the skipped line must print the bare purl/reason, not JSON-quoted \
         values; stderr=\n{stderr}"
    );

    // Leg 2 — a GRANTED reference whose patch record cannot be fetched (no
    // `view/{uuid}` mock → 404) produces a `record_fetch_failed` warning.
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let out = scrubbed_cli()
        .args([
            "scan",
            "--mode=hosted",
            "--yes",
            "--cwd",
            tmp.path().to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ])
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("Switched 1 package to hosted patches; rewrote"),
        "anchor: the dep must have been redirected so the record fetch runs; \
         stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "Warning: {PURL} was switched to hosted, but its patch record could not \
             be fetched"
        )),
        "the record-fetch warning must print the bare detail string, not a \
         JSON-quoted one; stderr=\n{stderr}"
    );
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

/// With Rush subspaces enabled, the pnpmShrinkwrapHash carrier lives next to
/// each subspace lock, at common/config/subspaces/<name>/repo-state.json, and
/// there is no common/config/rush/repo-state.json (#714). A rewrite that
/// landed in a subspace lock must still warn, keyed on that sibling file, and
/// must leave it byte-identical.
#[tokio::test]
#[serial]
async fn rush_subspace_repo_state_stale_warning_fires_for_subspace_repo_state() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("rush.json"),
        r#"{ "rushVersion": "5.100.0" }"#,
    )
    .unwrap();
    for name in ["default", "tools"] {
        let dir = tmp.path().join("common/config/subspaces").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pnpm-lock.yaml"), rush_pnpm_lock(NAME)).unwrap();
    }
    let state_rel = "common/config/subspaces/default/repo-state.json";
    let state = "{\n  \"pnpmShrinkwrapHash\": \"deadbeef\"\n}\n";
    std::fs::write(tmp.path().join(state_rel), state).unwrap();

    let env = run_redirect_subprocess(tmp.path(), &server.uri());
    assert_eq!(env["status"], "success", "envelope: {env}");
    for name in ["default", "tools"] {
        let lock = std::fs::read_to_string(
            tmp.path()
                .join(format!("common/config/subspaces/{name}/pnpm-lock.yaml")),
        )
        .unwrap();
        assert!(
            lock.contains(HOSTED_URL),
            "the {name} subspace lock must be redirected; got:\n{lock}"
        );
    }
    assert!(
        warning_codes(&env).contains(&"redirect_rush_repo_state_stale".to_string()),
        "a subspace repo-state.json beside a rewritten subspace lock must trigger \
         the stale-hash warning; got warnings {:?}",
        warning_codes(&env)
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join(state_rel)).unwrap(),
        state,
        "the redirect must not rewrite the subspace repo-state.json"
    );
}

/// The stale-hash warning pairs each rewritten lock with the repo-state.json
/// in its own directory: a subspace repo-state.json says nothing about a
/// rewrite that landed only in the common lock (that subspace's lock, and so
/// its hash, is untouched).
#[tokio::test]
#[serial]
async fn rush_subspace_repo_state_does_not_flag_a_common_only_rewrite() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("rush.json"),
        r#"{ "rushVersion": "5.100.0" }"#,
    )
    .unwrap();
    let common = tmp.path().join("common/config/rush");
    std::fs::create_dir_all(&common).unwrap();
    std::fs::write(common.join("pnpm-lock.yaml"), rush_pnpm_lock(NAME)).unwrap();
    let subspace = tmp.path().join("common/config/subspaces/tools");
    std::fs::create_dir_all(&subspace).unwrap();
    let sub_lock = rush_pnpm_lock("unrelated-pkg");
    std::fs::write(subspace.join("pnpm-lock.yaml"), &sub_lock).unwrap();
    std::fs::write(subspace.join("repo-state.json"), "{}\n").unwrap();

    let env = run_redirect_subprocess(tmp.path(), &server.uri());
    assert_eq!(env["status"], "success", "envelope: {env}");
    let lock = std::fs::read_to_string(common.join("pnpm-lock.yaml")).unwrap();
    assert!(
        lock.contains(HOSTED_URL),
        "common lock must be redirected; got:\n{lock}"
    );
    assert_eq!(
        std::fs::read_to_string(subspace.join("pnpm-lock.yaml")).unwrap(),
        sub_lock,
        "the subspace lock resolves nothing patched and must be untouched"
    );
    assert!(
        !warning_codes(&env).contains(&"redirect_rush_repo_state_stale".to_string()),
        "only the common lock changed and it has no repo-state.json beside it; got \
         warnings {:?}",
        warning_codes(&env)
    );
}

/// pnpm >=11 rejects (or, under Rush's `--no-prefer-frozen-lockfile`
/// install, silently re-resolves) a hosted-redirected lock unless the
/// lockfile is trusted — but the generic `redirect_pnpm_trust_lockfile`
/// remedies (`pnpm install --trust-lockfile`, a repo-root
/// pnpm-workspace.yaml `trustLockfile` key, a `--store-dir` reinstall) do
/// nothing in a Rush repo: rush runs pnpm in common/temp with a workspace
/// file it generates itself (#713). A run that spliced only Rush locks must
/// carry the Rush remedy instead: the `pnpm_config_trust_lockfile=true rush
/// install` env var, the pnpm 11 `usePnpmFrozenLockfileForRushInstall`
/// experiment, and a `rush purge` clean reinstall.
#[tokio::test]
#[serial]
async fn rush_pnpm_trust_warning_gives_rush_remedy() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_rush_project(tmp.path(), false);
    let env = run_redirect_subprocess(tmp.path(), &server.uri());
    assert_eq!(env["status"], "success", "envelope: {env}");
    let detail = env["redirect"]["warnings"]
        .as_array()
        .and_then(|arr| {
            arr.iter()
                .find(|w| w["code"] == "redirect_pnpm_trust_lockfile")
                .and_then(|w| w["detail"].as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| panic!("redirect_pnpm_trust_lockfile must fire; envelope: {env}"));
    for needle in [
        "pnpm_config_trust_lockfile=true rush install",
        "usePnpmFrozenLockfileForRushInstall",
        "common/config/rush/experiments.json",
        "rush purge",
        "socket-patch vex",
    ] {
        assert!(
            detail.contains(needle),
            "the Rush trust detail must name `{needle}`; got:\n{detail}"
        );
    }
    for needle in ["pnpm install --trust-lockfile", "--store-dir", "pnpm clean --lockfile"] {
        assert!(
            !detail.contains(needle),
            "the Rush trust detail must not offer the pnpm-only `{needle}`; got:\n{detail}"
        );
    }
    assert!(
        !tmp.path().join("pnpm-workspace.yaml").exists(),
        "rush nested-lock redirects must not create a root pnpm-workspace.yaml"
    );
}

/// HEAL-ON-RERUN for #713: a Rush repo whose locks an earlier run (any
/// release) already redirected splices nothing on a re-scan, yet its `rush
/// install` still needs the Rush trust remedy — so the re-run re-issues it
/// instead of going silent, and still writes no root pnpm-workspace.yaml.
#[tokio::test]
#[serial]
async fn rush_rerun_on_redirected_locks_reissues_the_rush_remedy() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_rush_project(tmp.path(), false);
    run_redirect_subprocess(tmp.path(), &server.uri());
    let common_rel = "common/config/rush/pnpm-lock.yaml";
    let redirected = std::fs::read_to_string(tmp.path().join(common_rel)).unwrap();
    assert!(
        redirected.contains(HOSTED_URL),
        "first run must redirect:\n{redirected}"
    );

    let env = run_redirect_subprocess(tmp.path(), &server.uri());
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join(common_rel)).unwrap(),
        redirected,
        "the re-run must leave the redirected Rush lock byte-identical"
    );
    let detail = env["redirect"]["warnings"]
        .as_array()
        .and_then(|arr| {
            arr.iter()
                .find(|w| w["code"] == "redirect_pnpm_trust_lockfile")
                .and_then(|w| w["detail"].as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| panic!("the re-run must re-issue the Rush remedy; envelope: {env}"));
    assert!(
        detail.contains("pnpm_config_trust_lockfile=true rush install"),
        "{detail}"
    );
    assert!(!detail.contains("pnpm install --trust-lockfile"), "{detail}");
    assert!(
        !tmp.path().join("pnpm-workspace.yaml").exists(),
        "a Rush re-run must not create a root pnpm-workspace.yaml"
    );
}

/// The `redirect_rush_repo_state_stale` warning claims a Rush lock "was edited
/// outside `rush update`" — so it must fire only when the rewrite actually
/// landed in a Rush lock. A Rush repo whose locks resolve only an UNRELATED
/// package (the granted patch's dep is installed but absent from every lock)
/// gets no lock edit and therefore no stale-hash warning, even with
/// repo-state.json present.
#[tokio::test]
#[serial]
async fn rush_stale_warning_requires_an_actual_lock_edit() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("rush.json"),
        r#"{ "rushVersion": "5.100.0" }"#,
    )
    .unwrap();
    let common = tmp.path().join("common/config/rush");
    std::fs::create_dir_all(&common).unwrap();
    // The lock resolves a package the granted patch does NOT cover.
    std::fs::write(
        common.join("pnpm-lock.yaml"),
        rush_pnpm_lock("unrelated-pkg"),
    )
    .unwrap();
    std::fs::write(
        common.join("repo-state.json"),
        "{\n  \"pnpmShrinkwrapHash\": \"deadbeef\",\n  \"preventManualShrinkwrapChanges\": true\n}\n",
    )
    .unwrap();
    // Installed copy so discovery still selects the patch.
    write_installed(tmp.path(), NAME, VERSION, b"unpatched installed bytes\n");
    let lock_before =
        std::fs::read_to_string(tmp.path().join("common/config/rush/pnpm-lock.yaml")).unwrap();

    let env = run_redirect_subprocess(tmp.path(), &server.uri());
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["redirect"]["redirected"], 0,
        "nothing pins the patch, so nothing may count as redirected: {env}"
    );
    assert!(
        !warning_codes(&env).contains(&"redirect_rush_repo_state_stale".to_string()),
        "no lock was edited, so the stale-hash warning must not fire; got warnings {:?}",
        warning_codes(&env)
    );
    let lock_after =
        std::fs::read_to_string(tmp.path().join("common/config/rush/pnpm-lock.yaml")).unwrap();
    assert_eq!(
        lock_before, lock_after,
        "the unrelated lock must be untouched"
    );
}

/// A plain (non-Rush) pnpm project whose only lockfile is a root
/// `pnpm-lock.yaml` (lockfileVersion 9.0) resolving the patched package, plus
/// the installed `node_modules/<NAME>` copy the crawler discovers.
fn write_pnpm_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "{VERSION}" }} }}"#
        ),
    )
    .unwrap();
    write_installed(root, NAME, VERSION, b"unpatched installed bytes\n");
    std::fs::write(root.join("pnpm-lock.yaml"), rush_pnpm_lock(NAME)).unwrap();
}

/// A hosted redirect that rewrites the root v9 `pnpm-lock.yaml` AUTO-CONFIGURES
/// `trustLockfile: true` in pnpm-workspace.yaml (zero-touch: pnpm >=11's
/// lockfile supply-chain policy rejects the rewritten lock otherwise, and the
/// committable workspace key is the verified recovery both majors honor while
/// pnpm 9/10 silently ignore it), and the `redirect_pnpm_trust_lockfile`
/// warning must say so: trust is configured, commit the file alongside the
/// lock, installs need no flags — naming BOTH failure spellings (pnpm 11:
/// `ERR_PNPM_TARBALL_URL_MISMATCH`, pnpm 12:
/// `ERR_PNPM_LOCKFILE_RESOLUTION_VERIFICATION`), disclosing the whole-lock
/// tradeoff (trustLockfile skips pnpm's re-verification for ALL entries), and
/// pre-empting pnpm 12's own rebuild-the-lock advice, which silently
/// reinstates the vulnerable upstream. The named host must be the SPLICED
/// artifact host (here the fixture's `patch.test`), never a hardcoded
/// `patch.socket.dev` — the hosted host follows `--api-url`. The npm twin
/// (package-lock.json, no pnpm lock) rewrites identically but emits no such
/// warning and no workspace file. Subprocess so the `--json` `warnings[]`
/// array can be read back.
#[tokio::test]
#[serial]
async fn pnpm_lock_redirect_autoconfigures_trust_lockfile_and_says_so() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    // pnpm project: the root pnpm-lock.yaml is rewritten → the warning fires.
    let pnpm = tempfile::tempdir().unwrap();
    write_pnpm_project(pnpm.path());
    let env = run_redirect_subprocess(pnpm.path(), &server.uri());
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["redirect"]["redirected"], 1,
        "anchor: the pnpm lock must have been redirected: {env}"
    );
    // The zero-touch write itself: a fresh pnpm-workspace.yaml with the
    // root-only scaffold + the trust key, and it counts as a rewritten file
    // (a CI consumer committing rewrittenFiles must not miss it).
    let ws = std::fs::read_to_string(pnpm.path().join("pnpm-workspace.yaml"))
        .expect("the run must create pnpm-workspace.yaml");
    assert_eq!(
        ws, "packages:\n  - '.'\ntrustLockfile: true\n",
        "created workspace file must be the scaffold + trust key"
    );
    assert!(
        env["redirect"]["rewrittenFiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "pnpm-workspace.yaml"),
        "pnpm-workspace.yaml must be listed in rewrittenFiles: {env}"
    );
    assert!(
        warning_codes(&env).contains(&"redirect_pnpm_trust_lockfile".to_string()),
        "a rewritten pnpm-lock.yaml must warn about the pnpm >=11 policy; got warnings {:?}",
        warning_codes(&env)
    );
    let detail = env["redirect"]["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["code"] == "redirect_pnpm_trust_lockfile")
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_default();
    // The new reality: trust is configured; commit it; no flags needed.
    assert!(
        detail.contains("trustLockfile: true") && detail.contains("pnpm-workspace.yaml"),
        "the warning must name the configured pnpm-workspace.yaml \
         `trustLockfile: true` key; got: {detail}"
    );
    assert!(
        detail.contains("commit it alongside the lock") && detail.contains("no extra flags"),
        "the warning must say trust is configured and installs need no flags; got: {detail}"
    );
    // The security tradeoff, stated honestly: the skip covers the WHOLE lock.
    assert!(
        detail.contains("ALL lockfile entries") && detail.contains("minimumReleaseAge"),
        "the warning must disclose the whole-lock re-verification skip; got: {detail}"
    );
    // The `.npmrc` `trust-lockfile=true` spelling is IGNORED by pnpm and
    // must never be recommended.
    assert!(
        !detail.contains(".npmrc"),
        "the warning must not point at .npmrc (pnpm ignores that spelling); got: {detail}"
    );
    // Both major-specific failure spellings.
    assert!(
        detail.contains("ERR_PNPM_TARBALL_URL_MISMATCH")
            && detail.contains("ERR_PNPM_LOCKFILE_RESOLUTION_VERIFICATION"),
        "the warning must name the pnpm 11 AND pnpm 12 error codes; got: {detail}"
    );
    // pnpm 12's error text steers users to rebuild the lock, which discards
    // the redirect — the warning must pre-empt it and scope the blast radius.
    assert!(
        detail.contains("pnpm clean --lockfile"),
        "the warning must pre-empt pnpm's rebuild-the-lock advice; got: {detail}"
    );
    assert!(
        detail.contains("pnpm <=10"),
        "the warning must scope the failure to pnpm >=11; got: {detail}"
    );
    // The host is derived from the spliced tarball URL (the fixture's
    // HOSTED_URL host), never hardcoded.
    assert!(
        detail.contains("patch.test") && !detail.contains("patch.socket.dev"),
        "the warning must name the actual spliced host, not patch.socket.dev; \
         got: {detail}"
    );

    // v5: the created workspace file is the record (no ledger edit).
    vlt_hosted_common::assert_no_ledger(pnpm.path());

    // npm twin: only a package-lock.json is rewritten → no pnpm warning and
    // no workspace file materializes.
    let npm = tempfile::tempdir().unwrap();
    write_project(npm.path());
    let env = run_redirect_subprocess(npm.path(), &server.uri());
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert!(
        !warning_codes(&env).contains(&"redirect_pnpm_trust_lockfile".to_string()),
        "an npm-only redirect must not emit the pnpm trust-lockfile warning; got warnings {:?}",
        warning_codes(&env)
    );
    assert!(
        !npm.path().join("pnpm-workspace.yaml").exists(),
        "an npm-only redirect must not create pnpm-workspace.yaml"
    );
}

/// `--no-trust-lockfile-config` (the opt-out for users who refuse the
/// whole-lock trust tradeoff): the redirect still lands, but nothing touches
/// pnpm-workspace.yaml, the ledger records no workspace-trust edit, and the
/// warning falls back to the OLD two-recovery guidance (per-run
/// `pnpm install --trust-lockfile`; committable `trustLockfile: true`).
#[tokio::test]
#[serial]
async fn pnpm_trust_opt_out_writes_nothing_and_keeps_manual_guidance() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    let env =
        run_redirect_subprocess_with(tmp.path(), &server.uri(), &["--no-trust-lockfile-config"]);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["redirect"]["redirected"], 1,
        "the opt-out must not stop the redirect itself: {env}"
    );
    assert!(
        !tmp.path().join("pnpm-workspace.yaml").exists(),
        "the opt-out must not create pnpm-workspace.yaml"
    );
    assert_eq!(
        env["redirect"]["rewrittenFiles"],
        serde_json::json!(["pnpm-lock.yaml"]),
        "only the lock may be rewritten under the opt-out: {env}"
    );
    vlt_hosted_common::assert_no_ledger(tmp.path());
    let detail = env["redirect"]["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["code"] == "redirect_pnpm_trust_lockfile")
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_default();
    assert!(
        detail.contains("--trust-lockfile")
            && detail.contains("trustLockfile: true")
            && detail.contains("pnpm-workspace.yaml"),
        "the opt-out warning must keep BOTH manual recoveries; got: {detail}"
    );
    assert!(
        detail.contains("pnpm clean --lockfile") && detail.contains("pnpm <=10"),
        "the opt-out warning keeps the rebuild caution and version scoping; got: {detail}"
    );
    assert!(
        !detail.contains("no extra flags"),
        "the opt-out warning must not claim trust was configured; got: {detail}"
    );
}

/// An EXPLICIT user `trustLockfile: <non-true>` in pnpm-workspace.yaml is a
/// security decision the auto-config must never flip: the file stays
/// byte-identical, no workspace-trust edit is recorded, and the warning says
/// the setting was respected while spelling out the manual recoveries.
#[tokio::test]
#[serial]
async fn pnpm_trust_respects_an_explicit_user_false() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    let user_ws = "packages:\n  - '.'\ntrustLockfile: false\n";
    std::fs::write(tmp.path().join("pnpm-workspace.yaml"), user_ws).unwrap();

    let env = run_redirect_subprocess(tmp.path(), &server.uri());
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["redirect"]["redirected"], 1,
        "the redirect itself must still land: {env}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("pnpm-workspace.yaml")).unwrap(),
        user_ws,
        "an explicit trustLockfile: false must be left byte-identical"
    );
    let detail = env["redirect"]["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["code"] == "redirect_pnpm_trust_lockfile")
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_default();
    assert!(
        detail.contains("respected") && detail.contains("trustLockfile: false"),
        "the warning must say the explicit user setting was respected; got: {detail}"
    );
    assert!(
        detail.contains("--trust-lockfile"),
        "the warning must fall back to the per-run flag recovery; got: {detail}"
    );
    vlt_hosted_common::assert_no_ledger(tmp.path());
}

/// Two hardening pins on the trust-lockfile warning's host list, which lands
/// in CI logs via both stderr and the persisted `--json` envelope:
///
/// 1. USERINFO NEVER LEAKS. A credentialed artifact URL
///    (`http://alice:s3cret@patch.test/…`) is spliced into the lock verbatim,
///    but the warning must name `host[:port]` only — printing the URL
///    authority wholesale leaked `alice:s3cret` into CI logs.
/// 2. ONLY SPLICED HOSTS ARE NAMED. The host list must come from the URLs
///    actually present in a REWRITTEN pnpm-lock.yaml's final text, not from
///    every npm override: a sibling override that landed solely in
///    package-lock.json (here `other-host.test`) must not be named, or the
///    warning points users at a server the pnpm lock never references.
///
/// Fixture: two granted npm patches — the credentialed one resolved ONLY by
/// the root pnpm-lock.yaml, the sibling resolved ONLY by package-lock.json.
#[tokio::test]
#[serial]
async fn pnpm_warning_strips_userinfo_and_names_only_spliced_hosts() {
    const SIBLING_NAME: &str = "sibling-npm-only";
    const SIBLING_VERSION: &str = "2.0.0";
    const SIBLING_PURL: &str = "pkg:npm/sibling-npm-only@2.0.0";
    const SIBLING_UUID: &str = "33333333-3333-4333-8333-333333333333";
    const SIBLING_URL: &str = "http://other-host.test/patch/npm/sibling-npm-only/2.0.0/44444444-4444-4444-8444-444444444444/33333333-3333-4333-8333-333333333333/sibling-npm-only-2.0.0.tgz";
    const CRED_URL: &str = "http://alice:s3cret@patch.test/patch/npm/in-proc-redirect/1.0.0/22222222-2222-4222-8222-222222222222/11111111-1111-4111-8111-111111111111/in-proc-redirect-1.0.0.tgz";

    let server = MockServer::start().await;
    // Discovery: BOTH installed packages have a granted patch.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [
                {
                    "purl": PURL,
                    "patches": [{
                        "uuid": UUID, "purl": PURL, "tier": "free",
                        "cveIds": [], "ghsaIds": [], "severity": "high",
                        "title": "credentialed redirect fixture"
                    }]
                },
                {
                    "purl": SIBLING_PURL,
                    "patches": [{
                        "uuid": SIBLING_UUID, "purl": SIBLING_PURL, "tier": "free",
                        "cveIds": [], "ghsaIds": [], "severity": "high",
                        "title": "sibling redirect fixture"
                    }]
                }
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    // Per-package search, one mock per package name (the names share no
    // substring, so the regexes cannot cross-match).
    for (pkg_name, uuid, purl) in [
        (NAME, UUID, PURL),
        (SIBLING_NAME, SIBLING_UUID, SIBLING_PURL),
    ] {
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/v0/orgs/{ORG}/patches/by-package/.*{pkg_name}.*$"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "patches": [{
                    "uuid": uuid, "purl": purl,
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "x", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                }],
                "canAccessPaidPatches": false,
            })))
            .mount(&server)
            .await;
    }
    // Grants: the pnpm-locked package's tarball URL carries userinfo; the
    // sibling's points at a DIFFERENT host that must never reach the warning.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": CRED_URL,
                    "purl": PURL,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": CRED_URL,
                        "integrity": { "sha512": PATCHED_SHA512 }
                    }],
                    "registryOverride": null
                },
                SIBLING_UUID: {
                    "status": "granted",
                    "url": SIBLING_URL,
                    "purl": SIBLING_PURL,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": SIBLING_URL,
                        "integrity": { "sha512": PATCHED_SHA512 }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(&server)
        .await;
    // Patch views for BOTH confirmed redirects (ledger records for VEX).
    for (uuid, purl) in [(UUID, PURL), (SIBLING_UUID, SIBLING_PURL)] {
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": uuid,
                "purl": purl,
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
            .mount(&server)
            .await;
    }

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "{VERSION}", "{SIBLING_NAME}": "{SIBLING_VERSION}" }} }}"#
        ),
    )
    .unwrap();
    write_installed(tmp.path(), NAME, VERSION, b"unpatched installed bytes\n");
    write_installed(
        tmp.path(),
        SIBLING_NAME,
        SIBLING_VERSION,
        b"unpatched sibling bytes\n",
    );
    // pnpm-lock.yaml resolves ONLY the credentialed package…
    std::fs::write(tmp.path().join("pnpm-lock.yaml"), rush_pnpm_lock(NAME)).unwrap();
    // …while package-lock.json resolves ONLY the sibling.
    std::fs::write(
        tmp.path().join("package-lock.json"),
        format!(
            r#"{{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {{
    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{SIBLING_NAME}": "{SIBLING_VERSION}" }} }},
    "node_modules/{SIBLING_NAME}": {{
      "version": "{SIBLING_VERSION}",
      "resolved": "https://registry.npmjs.org/{SIBLING_NAME}/-/{SIBLING_NAME}-{SIBLING_VERSION}.tgz",
      "integrity": "sha512-UPSTREAMupstream=="
    }}
  }}
}}
"#
        ),
    )
    .unwrap();

    let env = run_redirect_subprocess(tmp.path(), &server.uri());
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["redirect"]["redirected"], 2,
        "anchor: both locks must have been redirected: {env}"
    );
    // Anchors: the credentialed URL really was spliced into the pnpm lock
    // (so the no-leak assertion below is exercising a real splice), and the
    // sibling's URL landed only in package-lock.json.
    let pnpm_lock = std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap();
    assert!(
        pnpm_lock.contains(CRED_URL) && !pnpm_lock.contains("other-host.test"),
        "pnpm-lock.yaml must carry the credentialed URL and nothing from the \
         sibling host; got:\n{pnpm_lock}"
    );
    let npm_lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        npm_lock.contains(SIBLING_URL),
        "package-lock.json must carry the sibling URL; got:\n{npm_lock}"
    );

    let detail = env["redirect"]["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["code"] == "redirect_pnpm_trust_lockfile")
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_default()
        .to_string();
    // (1) Host only, never userinfo. The `@` check pins the whole authority
    // form: no spelling of `user:pass@host` can survive it.
    assert!(
        detail.contains("patch.test"),
        "the warning must name the spliced host; got: {detail}"
    );
    assert!(
        !detail.contains("alice") && !detail.contains("s3cret") && !detail.contains('@'),
        "the warning must never leak URL userinfo (credentials) into CI logs; \
         got: {detail}"
    );
    // (2) Only hosts spliced into a rewritten pnpm lock — the sibling landed
    // solely in package-lock.json, so its host must not be named.
    assert!(
        !detail.contains("other-host.test"),
        "the warning must name only hosts the pnpm lock actually points at; \
         got: {detail}"
    );
}

/// A clean, fully-successful hosted run must carry an EXACT warning set — not
/// merely "contains X". Presence-only assertions let spurious warnings ride
/// along unnoticed: every pnpm/yarn/bun/Rush run shipped a bogus
/// `redirect_npm_no_lockfile` ("no package-lock.json present") because the
/// npm rewriter warned whenever ITS lock was absent, with no regard for the
/// sibling lock that was successfully rewritten. npm success = exactly the
/// npm >= 12 `allow-remote` caveat (the run auto-configures `.npmrc` and
/// says so), and still exactly that one caveat once the project `.npmrc`
/// already allows it; pnpm success = exactly the trust-lockfile install
/// caveat.
#[tokio::test]
#[serial]
async fn clean_success_warning_set_is_exact_for_npm_and_pnpm() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    // npm project (package-lock.json): EXACTLY the npm >= 12 allow-remote
    // install caveat...
    let npm = tempfile::tempdir().unwrap();
    write_project(npm.path());
    let env = run_redirect_subprocess(npm.path(), &server.uri());
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["redirect"]["redirected"], 1,
        "anchor: the npm lock must have been redirected: {env}"
    );
    assert_eq!(
        warning_codes(&env),
        vec!["redirect_npm_allow_remote".to_string()],
        "a clean npm success must emit EXACTLY the allow-remote caveat: {env}"
    );
    assert_eq!(
        std::fs::read_to_string(npm.path().join(".npmrc")).unwrap(),
        "allow-remote=all\n",
        "the npm hosted run auto-configures allow-remote: {env}"
    );
    // ...and still EXACTLY that caveat (the already-set variant, carrying
    // the whole-tree tradeoff) once `.npmrc` already allows it.
    let npm = tempfile::tempdir().unwrap();
    write_project(npm.path());
    std::fs::write(npm.path().join(".npmrc"), "allow-remote=all\n").unwrap();
    let env = run_redirect_subprocess(npm.path(), &server.uri());
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["redirect"]["redirected"], 1, "anchor: {env}");
    assert_eq!(
        warning_codes(&env),
        vec!["redirect_npm_allow_remote".to_string()],
        "a clean npm success with allow-remote=all still carries the caveat: {env}"
    );

    // pnpm project (pnpm-lock.yaml only — no package-lock.json, by design):
    // EXACTLY the pnpm >=11 trust-lockfile caveat, nothing else.
    let pnpm = tempfile::tempdir().unwrap();
    write_pnpm_project(pnpm.path());
    let env = run_redirect_subprocess(pnpm.path(), &server.uri());
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["redirect"]["redirected"], 1,
        "anchor: the pnpm lock must have been redirected: {env}"
    );
    assert_eq!(
        warning_codes(&env),
        vec!["redirect_pnpm_trust_lockfile".to_string()],
        "a clean pnpm success must emit EXACTLY the trust-lockfile caveat \
         (regression: spurious redirect_npm_no_lockfile): {env}"
    );
}

/// Cargo's hosted redirect wires the managed sparse registry into
/// `.cargo/config.toml` — but a project carrying the LEGACY extensionless
/// `.cargo/config` is one cargo READS INSTEAD (it warns about the duplicate
/// and ignores `config.toml`). The redirect never even read that spelling, so
/// the `[registries.socket-patch-<uuid>]` definition landed in an ignored file
/// while `Cargo.toml` gained `registry = "socket-patch-<uuid>"` naming it:
/// cargo then fails with "no index found for registry", and the run still
/// reported the dep redirected (its index URL "landed in a file") and attested
/// it to VEX. Same invariant `vendor::cargo_config::config_path` already
/// enforces on the vendor path.
#[tokio::test]
#[serial]
async fn cargo_redirect_writes_the_legacy_dot_cargo_config() {
    const CARGO_PURL: &str = "pkg:cargo/serde@1.0.190";
    const CARGO_UUID: &str = "55555555-5555-4555-8555-555555555555";
    const CKSUM: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    let index_url = "sparse+http://patch.test/cargo/idx/";

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": CARGO_PURL,
                "patches": [{
                    "uuid": CARGO_UUID, "purl": CARGO_PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "cargo legacy-config fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": CARGO_UUID, "purl": CARGO_PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                CARGO_UUID: {
                    "status": "granted",
                    "url": "http://patch.test/serde-1.0.190.crate",
                    "purl": CARGO_PURL,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": "http://patch.test/serde-1.0.190.crate",
                        "integrity": { "sha256": CKSUM }
                    }],
                    "registryOverride": {
                        "kind": "cargo-sparse",
                        "indexUrl": index_url,
                        "identifiers": {
                            "name": "serde",
                            "version": "1.0.190",
                            "cargoCksumSha256": CKSUM,
                        }
                    }
                }
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{CARGO_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": CARGO_UUID,
            "purl": CARGO_PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n",
    )
    .unwrap();
    // Lockfile-only discovery: the Cargo.lock inventory supplies the purl.
    std::fs::write(
        tmp.path().join("Cargo.lock"),
        "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.190\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"91f70896d6720bc714a4a57d22fc91f1db634680e65c8efe13323f1fa38d53f5\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(tmp.path().join(".cargo")).unwrap();
    std::fs::write(tmp.path().join(".cargo/config"), "[net]\nretry = 3\n").unwrap();

    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "scan --mode hosted should succeed");

    let legacy = std::fs::read_to_string(tmp.path().join(".cargo/config")).unwrap();
    assert!(
        legacy.contains(&format!("[registries.socket-patch-{CARGO_UUID}]")),
        "the registry definition must land in the legacy `.cargo/config` — the \
         file cargo actually reads; got:\n{legacy}"
    );
    assert!(
        legacy.contains("retry = 3"),
        "the user's existing config must be preserved: {legacy}"
    );
    assert!(
        !tmp.path().join(".cargo/config.toml").exists(),
        "no shadowed `.cargo/config.toml` may be created beside the legacy file"
    );
    let manifest = std::fs::read_to_string(tmp.path().join("Cargo.toml")).unwrap();
    assert!(
        manifest.contains(&format!("registry = \"socket-patch-{CARGO_UUID}\"")),
        "anchor: the Cargo.toml dep must name the managed registry: {manifest}"
    );
}

/// `scan --mode hosted --json` must emit a machine-readable error envelope on
/// stdout for EVERY failure exit, never empty stdout plus an exit code.
///
/// Regression pin for the long-open hosted-mode JSON gap: the early
/// bail-outs (discovery-detail failure, reference-resolve failure) returned
/// with the message on stderr only, so a `--json` consumer saw exit 1 with
/// nothing to parse. Two legs, one per bail-out.
#[tokio::test]
#[serial]
async fn redirect_json_mode_failures_emit_error_envelope() {
    let assert_error_envelope = |out: &std::process::Output, leg: &str| {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{leg}: failure exit; stdout=\n{stdout}\nstderr=\n{stderr}"
        );
        let v: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!("{leg}: --json stdout must be a parseable envelope even on failure ({e}); stdout=\n{stdout}")
        });
        assert_eq!(
            v["status"], "error",
            "{leg}: envelope status; stdout=\n{stdout}"
        );
        assert!(
            v["error"].as_str().is_some_and(|m| !m.is_empty()),
            "{leg}: envelope must carry the error message; stdout=\n{stdout}"
        );
        assert_eq!(
            v["redirect"]["mode"], "hosted",
            "{leg}: envelope must identify the mode; stdout=\n{stdout}"
        );
    };

    // Leg 1 — batch discovery succeeds, every patch-detail query fails →
    // `discover_selected` bails with (1, message).
    let server = MockServer::start().await;
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
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let out = scrubbed_cli()
        .args([
            "scan",
            "--mode=hosted",
            "--yes",
            "--json",
            "--cwd",
            tmp.path().to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ])
        .output()
        .expect("run socket-patch");
    assert_error_envelope(&out, "discovery-detail failure");

    // Leg 2 — discovery + selection succeed, the reference resolve fails.
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let out = scrubbed_cli()
        .args([
            "scan",
            "--mode=hosted",
            "--yes",
            "--json",
            "--cwd",
            tmp.path().to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ])
        .output()
        .expect("run socket-patch");
    assert_error_envelope(&out, "reference-resolve failure");
}

/// Shared by the write-failure envelope tests below: even a run that dies on
/// a filesystem obstruction must exit 1 with a machine-readable `--json`
/// error envelope on stdout.
fn assert_write_failure_envelope(out: &std::process::Output, leg: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "{leg}: failure exit; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "{leg}: --json stdout must be a parseable envelope even on failure ({e}); \
             stdout=\n{stdout}"
        )
    });
    assert_eq!(v["status"], "error", "{leg}: status; stdout=\n{stdout}");
    assert!(
        v["error"].as_str().is_some_and(|m| !m.is_empty()),
        "{leg}: envelope must carry the error message; stdout=\n{stdout}"
    );
    assert_eq!(
        v["redirect"]["mode"], "hosted",
        "{leg}: envelope must identify the mode; stdout=\n{stdout}"
    );
}

/// Shared driver for the write-failure legs: a hosted `scan --mode hosted --json`
/// subprocess against the obstructed project in `tmp`.
async fn run_hosted_json_scan(tmp: &std::path::Path, server: &MockServer) -> std::process::Output {
    scrubbed_cli()
        .args([
            "scan",
            "--mode=hosted",
            "--yes",
            "--json",
            "--cwd",
            tmp.to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ])
        .output()
        .expect("run socket-patch")
}

/// Leg 3 of the four `--json` failure exits: the rewritten lockfile cannot
/// be written back — its DIRECTORY is read-only, so the atomic stage file
/// cannot be created (the rewriter read the lock fine moments earlier). A
/// read-only lock FILE no longer fails this leg: the atomic stage+rename
/// replaces it mode-preserved, like the vendored backend's writer. (Legs 1-2
/// — the discovery-detail and reference-resolve failures — are pinned by
/// `redirect_json_mode_failures_emit_error_envelope` above. The former leg 4
/// — the ledger write — has no subject in v5: hosted mode writes no ledger,
/// see `readonly_socket_vendor_does_not_block_a_hosted_run` below.)
///
/// unix-only: a read-only directory does not block file creation on Windows.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn redirect_json_mode_write_failures_emit_error_envelope() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    // Rush project: the lock lives in a subdirectory.
    write_rush_project(tmp.path(), false);
    let lock_dir = tmp.path().join("common/config/rush");
    std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let out = run_hosted_json_scan(tmp.path(), &server).await;
    std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_write_failure_envelope(&out, "lockfile-write failure");
}

/// v5 hosted mode writes nothing under `.socket/`, so a read-only
/// `.socket/vendor` (which used to fail the run at the ledger write) no
/// longer matters: the run succeeds and the lockfile is redirected.
///
/// unix-only: the obstruction is a read-only DIRECTORY (Windows ignores
/// FILE_ATTRIBUTE_READONLY on directories for file creation).
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn readonly_socket_vendor_does_not_block_a_hosted_run() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    let mut perms = std::fs::metadata(&vendor_dir).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&vendor_dir, perms.clone()).unwrap();
    let out = run_hosted_json_scan(tmp.path(), &server).await;
    // Restore writability so the tempdir can be cleaned up. The blanket
    // group-write concern behind the lint doesn't apply: this un-readonlies a
    // private tempdir moments before its deletion.
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(&vendor_dir, perms).unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout=\n{stdout}\nstderr=\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("parseable envelope");
    assert_eq!(v["redirect"]["redirected"], 1, "{v:#}");
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(lock.contains(HOSTED_URL), "{lock}");
    vlt_hosted_common::assert_no_ledger(tmp.path());
}

/// A MALFORMED pre-v5 redirect ledger (torn write, truncation, bad
/// hand-edit) is IGNORED by v5 hosted scan: never read for planning, never
/// quarantined, never an error. The run succeeds and redirects, the torn
/// bytes are left in place verbatim, and nothing about them is printed.
#[tokio::test]
#[serial]
async fn corrupt_pre_v5_ledger_is_ignored_and_left_untouched() {
    const TORN: &[u8] = b"{ \"version\": 1, \"mode\": \"hosted\", \"edits\": [ { \"path\": \"packa";

    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(vendor_dir.join("redirect-state.json"), TORN).unwrap();

    let out = run_hosted_json_scan(tmp.path(), &server).await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("parseable envelope");
    assert_eq!(v["status"], "success", "{v:#}");
    assert_eq!(v["redirect"]["redirected"], 1, "{v:#}");
    assert!(
        !stdout.contains("redirect-state.json") && !stderr.contains("malformed"),
        "the legacy ledger is never mentioned; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(lock.contains(HOSTED_URL), "{lock}");
    assert_eq!(
        std::fs::read(vendor_dir.join("redirect-state.json")).unwrap(),
        TORN,
        "the pre-v5 ledger bytes are left in place verbatim"
    );
    assert!(!vendor_dir.join("redirect-state.json.corrupt").exists());
}

/// `--dry-run` over a corrupt pre-v5 ledger: the preview succeeds, and
/// neither the ledger nor the lock is touched.
#[tokio::test]
#[serial]
async fn corrupt_pre_v5_ledger_dry_run_succeeds_without_touching_it() {
    const TORN: &[u8] = b"{ not json";

    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(vendor_dir.join("redirect-state.json"), TORN).unwrap();

    let out = scrubbed_cli()
        .args([
            "scan",
            "--mode=hosted",
            "--yes",
            "--json",
            "--dry-run",
            "--cwd",
            tmp.path().to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ])
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout=\n{stdout}");
    assert_eq!(
        std::fs::read(vendor_dir.join("redirect-state.json")).unwrap(),
        TORN,
        "dry-run must not move or rewrite the pre-v5 ledger"
    );
    assert!(!vendor_dir.join("redirect-state.json.corrupt").exists());
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_before,
        "dry-run leaves the lock untouched"
    );
}

/// Hosted mode records patches ONLY in the lockfile pins — it never writes
/// `.socket/manifest.json` (nor, in v5, a ledger) — so `updates[]` (the
/// documented CI signal) must consult the hosted pins, or a pure hosted
/// project whose redirected patch has been superseded reports
/// `updates: []` forever.
#[tokio::test]
#[serial]
async fn scan_updates_reports_superseding_patch_for_a_lock_pinned_project() {
    const OLD_UUID: &str = "99999999-9999-4999-8999-999999999999";

    let server = MockServer::start().await;
    // Discovery offers ONLY the new uuid; the lock pins the old one.
    mock_discovery(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    // The lock as a previous hosted run left it: pinned to OLD_UUID's
    // hosted artifact (the only v5 hosted persistence).
    let old_url = HOSTED_URL.replace(UUID, OLD_UUID);
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    std::fs::write(
        tmp.path().join("package-lock.json"),
        lock.replace(
            &format!("https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz"),
            &old_url,
        ),
    )
    .unwrap();

    // Bare `scan --json` (hosted by default) — the nightly CI shape; the
    // mock host counts as the patch server via `--patch-server-url`.
    let out = scrubbed_cli()
        .args([
            "scan",
            "--json",
            "--patch-server-url",
            "http://patch.test",
            "--cwd",
            tmp.path().to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ])
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("parseable envelope");
    let updates = v["updates"].as_array().expect("updates array");
    assert_eq!(
        updates.len(),
        1,
        "the lock-pinned patch was superseded — updates[] must say so; \
         stdout=\n{stdout}"
    );
    assert_eq!(updates[0]["purl"], PURL);
    assert_eq!(updates[0]["oldUuid"], OLD_UUID);
    assert_eq!(updates[0]["newUuid"], UUID);
}

/// `scan --mode hosted --prune` must not silently drop `--prune`: both
/// hosted terminals return before the GC blocks, so a bot migrating its sync
/// job from `--mode agent --prune` would otherwise stop pruning forever with
/// exit 0 and no signal. The envelope must carry an explicit
/// `redirect_prune_ignored` warning (and, unchanged, no `gc` object —
/// hosted mode runs no GC).
#[tokio::test]
#[serial]
async fn hosted_prune_emits_explicit_ignored_warning() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let out = scrubbed_cli()
        .args([
            "scan",
            "--mode",
            "hosted",
            "--prune",
            "--json",
            "--yes",
            "--cwd",
            tmp.path().to_str().unwrap(),
            "--api-url",
            &server.uri(),
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
        "scan --mode hosted --prune must still succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let env_json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "--json stdout must be a JSON envelope: {e}\nstdout:\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert!(
        warning_codes(&env_json)
            .iter()
            .any(|c| c == "redirect_prune_ignored"),
        "hosted --prune must warn that the flag is ignored; envelope: {env_json}"
    );
    assert!(
        env_json.get("gc").is_none(),
        "hosted mode must not run (or claim to run) GC: {env_json}"
    );
    // The redirect itself is unaffected by the ignored flag.
    assert_eq!(env_json["redirect"]["redirected"], 1, "{env_json}");
}

// ── composer ─────────────────────────────────────────────────────────────

const COMPOSER_PURL: &str = "pkg:composer/monolog/monolog@2.0.0";
const COMPOSER_UUID: &str = "66666666-6666-4666-8666-666666666666";
const COMPOSER_URL: &str = "http://patch.test/patch/composer/monolog/monolog/2.0.0/\
                            77777777-7777-4777-8777-777777777777/\
                            66666666-6666-4666-8666-666666666666/monolog-2.0.0.zip";
const COMPOSER_SHA1: &str = "abcdef0123456789abcdef0123456789abcdef01";

/// A composer project discovered through `vendor/composer/installed.json`,
/// with the lock the redirect rewriter edits. The lock is composer-native:
/// `JSON_UNESCAPED_SLASHES`, 4-space indent.
fn write_composer_project(root: &Path) {
    std::fs::write(
        root.join("composer.json"),
        "{ \"require\": { \"monolog/monolog\": \"2.0.0\" } }\n",
    )
    .unwrap();
    let installed = root.join("vendor").join("composer");
    std::fs::create_dir_all(&installed).unwrap();
    std::fs::write(
        installed.join("installed.json"),
        r#"{ "packages": [ { "name": "monolog/monolog", "version": "2.0.0" } ] }
"#,
    )
    .unwrap();
    std::fs::create_dir_all(root.join("vendor/monolog/monolog")).unwrap();
    std::fs::write(
        root.join("composer.lock"),
        r#"{
    "content-hash": "abc123def456abc123def456abc1",
    "packages": [
        {
            "name": "monolog/monolog",
            "version": "2.0.0",
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/Seldaek/monolog/zipball/abc123",
                "reference": "abc123def456",
                "shasum": ""
            }
        }
    ],
    "packages-dev": []
}
"#,
    )
    .unwrap();
}

async fn mock_composer_api(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": COMPOSER_PURL,
                "patches": [{
                    "uuid": COMPOSER_UUID, "purl": COMPOSER_PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "composer redirect fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": COMPOSER_UUID, "purl": COMPOSER_PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    // composer pins `dist.shasum` — a sha1, not npm's sha512.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                COMPOSER_UUID: {
                    "status": "granted",
                    "url": COMPOSER_URL,
                    "purl": COMPOSER_PURL,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": COMPOSER_URL,
                        "integrity": { "sha1": COMPOSER_SHA1 }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{COMPOSER_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": COMPOSER_UUID,
            "purl": COMPOSER_PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "src/Logger.php": {
                    "beforeHash": "a".repeat(64),
                    "afterHash": "b".repeat(64),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2024-9"],
                    "summary": "composer redirect fixture",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
}

/// End-to-end regression for the composer redirect that reported itself as
/// having done nothing: the rewriter wrote the hosted url with `\/`-escaped
/// slashes while the post-rewrite confirmation probe searched only the raw and
/// percent-encoded spellings, so a fully successful rewrite yielded
/// `redirected: 0`, no patch record fetched, and nothing for `vex` to
/// attest. The rewriter now emits composer-native raw slashes and the probe
/// asks the rewriter's own predicate, so the lock edit and the confirmation
/// cannot disagree. Subprocess so the `--json` envelope can be read back.
#[tokio::test]
#[serial]
async fn composer_redirect_is_confirmed_and_recorded() {
    let server = MockServer::start().await;
    mock_composer_api(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_composer_project(tmp.path());

    let env = run_redirect_subprocess(tmp.path(), &server.uri());
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["redirect"]["redirected"], 1,
        "the composer redirect must be CONFIRMED, not silently unconfirmed: {env}"
    );
    assert_eq!(
        env["redirect"]["rewrittenFiles"][0], "composer.lock",
        "composer.lock must be the rewritten file: {env}"
    );
    assert!(
        warning_codes(&env).is_empty(),
        "a clean composer redirect emits no warnings; got {:?}",
        warning_codes(&env)
    );

    let lock = std::fs::read_to_string(tmp.path().join("composer.lock")).unwrap();
    assert!(
        lock.contains(&format!("\"url\": \"{COMPOSER_URL}\"")),
        "dist.url must be the hosted patch with composer-native raw slashes; got:\n{lock}"
    );
    assert!(
        !lock.contains("\\/"),
        "composer writes lock JSON with JSON_UNESCAPED_SLASHES — no escaped slashes may \
         be introduced; got:\n{lock}"
    );
    assert!(
        lock.contains(&format!("\"shasum\": \"{COMPOSER_SHA1}\"")),
        "dist.shasum must pin the patched artifact's sha1; got:\n{lock}"
    );

    // The confirmation is what drives the record fetch (held in memory for
    // the in-run VEX — v5 persists no ledger): no confirmation, no record.
    let views = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().contains("/patches/view/"))
        .count();
    assert_eq!(views, 1, "the confirmed redirect fetched its patch record");
    vlt_hosted_common::assert_no_ledger(tmp.path());
}

/// Mount the full cargo hosted-mock set (discovery + reference + view) for
/// one patch over `purl`. Eight positional fixture knobs beat a one-off
/// params struct for a test-local mock helper.
#[allow(clippy::too_many_arguments)]
async fn mock_cargo_patch(
    server: &MockServer,
    purl: &str,
    uuid: &str,
    name: &str,
    version: &str,
    index_url: &str,
    cksum: &str,
    ghsa: &str,
) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": uuid, "purl": purl, "tier": "free",
                    "cveIds": [], "ghsaIds": [ghsa], "severity": "high",
                    "title": "cargo redirect fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": uuid, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                uuid: {
                    "status": "granted",
                    "url": format!("http://patch.test/{name}-{version}.crate"),
                    "purl": purl,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": format!("http://patch.test/{name}-{version}.crate"),
                        "integrity": { "sha256": cksum }
                    }],
                    "registryOverride": {
                        "kind": "cargo-sparse",
                        "indexUrl": index_url,
                        "identifiers": {
                            "name": name,
                            "version": version,
                            "cargoCksumSha256": cksum,
                        }
                    }
                }
            }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "src/lib.rs": {
                    "beforeHash": "a".repeat(64),
                    "afterHash": "b".repeat(64),
                }
            },
            "vulnerabilities": {
                ghsa: {
                    "cves": ["CVE-2024-99999"],
                    "summary": "cargo redirect vex fixture",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
}

/// Write a vendored crate dir so the cargo crawler discovers `name@version`
/// without the project's manifest/lock referencing it.
fn write_vendored_crate(root: &Path, name: &str, version: &str) {
    let dir = root.join("vendor").join(name);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n"),
    )
    .unwrap();
    std::fs::write(dir.join("src/lib.rs"), b"// unpatched\n").unwrap();
}

/// AUDIT A3/A3b — the cargo analogue of `no_lockfile_redirect_is_not_attested`:
/// a granted cargo patch whose crate the project does not declare (surfaced by
/// the crawler from a vendor dir) must confirm NOTHING. The old behavior wrote
/// an inert `[registries.…]` block to `.cargo/config.toml`, whose index URL
/// then satisfied the substring confirmed check: the run reported
/// `redirected: 1`, persisted a ledger record, and emitted an `assume_applied`
/// VEX statement while no build anywhere used the patched bytes.
#[tokio::test]
#[serial]
async fn cargo_granted_but_nothing_pinned_is_not_confirmed_or_attested() {
    const CARGO_PURL: &str = "pkg:cargo/cfg-if@1.0.0";
    const CARGO_UUID: &str = "11111111-1111-4111-8111-111111111111";
    let cksum = "cd".repeat(32);
    let index_url = format!("sparse+http://patch.test/registry/cargo/{CARGO_UUID}/index/");

    let server = MockServer::start().await;
    mock_cargo_patch(
        &server,
        CARGO_PURL,
        CARGO_UUID,
        "cfg-if",
        "1.0.0",
        &index_url,
        &cksum,
        "GHSA-carg-aaaa-bbbb",
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    // Manifest + lock reference ONLY serde; cfg-if exists solely in vendor/.
    std::fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"consumer\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\nserde = \"1.0\"\n",
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("Cargo.lock"),
        "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"ee\"\n",
    )
    .unwrap();
    write_vendored_crate(tmp.path(), "cfg-if", "1.0.0");
    let toml_before = std::fs::read_to_string(tmp.path().join("Cargo.toml")).unwrap();
    let lock_before = std::fs::read_to_string(tmp.path().join("Cargo.lock")).unwrap();

    let vex_path = tmp.path().join("out.vex.json");
    let mut args = redirect_args(tmp.path(), server.uri());
    args.vex = socket_patch_cli::commands::vex::VexEmbedArgs {
        vex: Some(vex_path.clone()),
        vex_product: Some("pkg:cargo/consumer@0.0.0".to_string()),
        ..Default::default()
    };
    let code = run(args).await;

    assert_eq!(
        std::fs::read_to_string(tmp.path().join("Cargo.toml")).unwrap(),
        toml_before,
        "Cargo.toml must be untouched (no dep entry for cfg-if)"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("Cargo.lock")).unwrap(),
        lock_before,
        "Cargo.lock must be untouched (no [[package]] for cfg-if)"
    );
    assert!(
        !tmp.path().join(".cargo/config.toml").exists()
            && !tmp.path().join(".cargo/config").exists(),
        "NO inert [registries] block may be written when nothing pins the patch"
    );
    assert!(
        !tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .exists(),
        "no ledger may be written when nothing was redirected"
    );
    assert!(
        !vex_path.exists(),
        "NO OpenVEX document may exist for a tree where nothing pins the patch"
    );
    assert_eq!(
        code, 1,
        "nothing was redirected, so the requested attestation must fail"
    );
}

/// A granted cargo patch for a crate the project reaches only
/// TRANSITIVELY (in Cargo.lock, declared by no manifest) stays a refusal —
/// a manifest `registry` pin cannot reach it — but a loud one: nothing is
/// written, recorded or attested, the requested VEX fails the run, and the
/// warning names the crate transitive-only and points at vendored mode.
#[tokio::test]
#[serial]
async fn cargo_transitive_only_crate_is_refused_loudly_and_not_attested() {
    const CARGO_PURL: &str = "pkg:cargo/cfg-if@1.0.0";
    const CARGO_UUID: &str = "22222222-2222-4222-8222-222222222222";
    let cksum = "cd".repeat(32);
    let index_url = format!("sparse+http://patch.test/registry/cargo/{CARGO_UUID}/index/");
    let server = MockServer::start().await;
    mock_cargo_patch(
        &server,
        CARGO_PURL,
        CARGO_UUID,
        "cfg-if",
        "1.0.0",
        &index_url,
        &cksum,
        "GHSA-carg-tttt-tttt",
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"consumer\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\nlog = \"0.4\"\n",
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("Cargo.lock"),
        "version = 3\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"ee\"\n\n[[package]]\nname = \"log\"\nversion = \"0.4.20\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"ff\"\ndependencies = [\n \"cfg-if\",\n]\n",
    )
    .unwrap();
    write_vendored_crate(tmp.path(), "cfg-if", "1.0.0");
    let toml_before = std::fs::read(tmp.path().join("Cargo.toml")).unwrap();
    let lock_before = std::fs::read(tmp.path().join("Cargo.lock")).unwrap();

    let vex_path = tmp.path().join("out.vex.json");
    let mut args = redirect_args(tmp.path(), server.uri());
    args.vex = socket_patch_cli::commands::vex::VexEmbedArgs {
        vex: Some(vex_path.clone()),
        vex_product: Some("pkg:cargo/consumer@0.0.0".to_string()),
        ..Default::default()
    };
    let code = run(args).await;

    assert_eq!(
        std::fs::read(tmp.path().join("Cargo.toml")).unwrap(),
        toml_before
    );
    assert_eq!(
        std::fs::read(tmp.path().join("Cargo.lock")).unwrap(),
        lock_before
    );
    assert!(
        !tmp.path().join(".cargo").exists(),
        "no registry block may be written for an unpinnable crate"
    );
    assert!(
        !tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .exists(),
        "nothing redirected, nothing recorded"
    );
    assert!(
        !vex_path.exists(),
        "a transitive-only crate is never attested"
    );
    assert_eq!(code, 1, "the requested attestation must fail the run");

    // Without --vex the run succeeds, reporting nothing redirected and the
    // transitive-only warning in the envelope.
    let env = run_redirect_subprocess(tmp.path(), &server.uri());
    assert_eq!(env["redirect"]["redirected"], 0, "{env}");
    let warning = env["redirect"]["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["code"] == "redirect_cargo_toml_dep_not_found")
        .unwrap_or_else(|| panic!("{env}"));
    let detail = warning["detail"].as_str().unwrap();
    assert!(
        detail.contains("cfg-if@1.0.0 is a transitive-only dependency")
            && detail.contains("--mode vendored"),
        "{detail}"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("Cargo.lock")).unwrap(),
        lock_before
    );
}

/// A workspace member or path dependency the rewriter must not write —
/// outside the project root, or reached through a symbolic link — still
/// declares the patched crate to cargo. Pinning only the root would leave
/// that package resolving crates.io (`--locked` fails, the unpatched copy is
/// compiled) while the crate is reported redirected. REGRESSION: the root
/// was pinned and the dep confirmed; a literal symlinked member was even
/// written through the link, outside the project. Now the Cargo.lock
/// dependents check refuses the crate and nothing is written anywhere.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn cargo_member_outside_the_project_or_behind_a_symlink_refuses_the_crate() {
    const CARGO_PURL: &str = "pkg:cargo/cfg-if@1.0.0";
    const CARGO_UUID: &str = "33333333-3333-4333-8333-333333333333";
    let cksum = "cd".repeat(32);
    let index_url = format!("sparse+http://patch.test/registry/cargo/{CARGO_UUID}/index/");
    let server = MockServer::start().await;
    mock_cargo_patch(
        &server,
        CARGO_PURL,
        CARGO_UUID,
        "cfg-if",
        "1.0.0",
        &index_url,
        &cksum,
        "GHSA-carg-ssss-ssss",
    )
    .await;

    let lib_manifest =
        "[package]\nname = \"lib\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ncfg-if = \"1\"\n";
    let lock = "version = 3\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"ee\"\n\n[[package]]\nname = \"consumer\"\nversion = \"0.0.0\"\ndependencies = [\n \"cfg-if\",\n \"lib\",\n]\n\n[[package]]\nname = \"lib\"\nversion = \"0.1.0\"\ndependencies = [\n \"cfg-if\",\n]\n";
    for (shape, root_manifest, link) in [
        (
            "out-of-root path dependency",
            "[package]\nname = \"consumer\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\ncfg-if = \"1.0.0\"\nlib = { path = \"../lib\" }\n",
            None,
        ),
        (
            "glob-matched symlinked member",
            "[workspace]\nmembers = [\"crates/*\"]\n\n[package]\nname = \"consumer\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\ncfg-if = \"1.0.0\"\n",
            Some("crates/lib"),
        ),
        (
            "literal symlinked member",
            "[workspace]\nmembers = [\"lib\"]\n\n[package]\nname = \"consumer\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\ncfg-if = \"1.0.0\"\n",
            Some("lib"),
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("lib");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("Cargo.toml"), lib_manifest).unwrap();
        let app = tmp.path().join("app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("Cargo.toml"), root_manifest).unwrap();
        std::fs::write(app.join("Cargo.lock"), lock).unwrap();
        if let Some(link) = link {
            let at = app.join(link);
            std::fs::create_dir_all(at.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&outside, at).unwrap();
        }
        write_vendored_crate(&app, "cfg-if", "1.0.0");

        let env = run_redirect_subprocess(&app, &server.uri());
        assert_eq!(env["redirect"]["redirected"], 0, "{shape}: {env}");
        let warning = env["redirect"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["code"] == "redirect_cargo_transitive_dependents")
            .unwrap_or_else(|| panic!("{shape}: {env}"));
        let detail = warning["detail"].as_str().unwrap();
        assert!(
            detail.contains("lib 0.1.0 (a path package") && detail.contains("--mode vendored"),
            "{shape}: {detail}"
        );
        assert_eq!(
            std::fs::read_to_string(outside.join("Cargo.toml")).unwrap(),
            lib_manifest,
            "{shape}: a manifest outside the project is never written"
        );
        assert_eq!(
            std::fs::read_to_string(app.join("Cargo.toml")).unwrap(),
            root_manifest,
            "{shape}"
        );
        assert_eq!(std::fs::read_to_string(app.join("Cargo.lock")).unwrap(), lock, "{shape}");
        assert!(!app.join(".cargo").exists(), "{shape}");
    }
}

/// AUDIT A2 (green side): the multi-line `[dependencies.<name>]` table form —
/// with NO Cargo.lock — is fully pinned: the manifest entry gains a registry
/// line, the managed registry block is wired in, and the patch is recorded +
/// attested (the manifest pin forces the next resolution through the managed
/// registry, which serves the patched checksum).
#[tokio::test]
#[serial]
async fn cargo_table_form_without_lock_is_pinned_and_attested() {
    const CARGO_PURL: &str = "pkg:cargo/serde@1.0.190";
    const CARGO_UUID: &str = "55555555-5555-4555-8555-555555555555";
    let cksum = "11".repeat(32);
    let index_url = format!("sparse+http://patch.test/registry/cargo/{CARGO_UUID}/index/");

    let server = MockServer::start().await;
    mock_cargo_patch(
        &server,
        CARGO_PURL,
        CARGO_UUID,
        "serde",
        "1.0.190",
        &index_url,
        &cksum,
        "GHSA-carg-cccc-dddd",
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    // Table-form dependency; NO Cargo.lock. The crawler discovers the version
    // from the vendored crate dir.
    std::fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies.serde]\nversion = \"1.0.190\"\n",
    )
    .unwrap();
    write_vendored_crate(tmp.path(), "serde", "1.0.190");

    let vex_path = tmp.path().join("out.vex.json");
    let mut args = redirect_args(tmp.path(), server.uri());
    args.vex = socket_patch_cli::commands::vex::VexEmbedArgs {
        vex: Some(vex_path.clone()),
        vex_product: Some("pkg:cargo/app@0.1.0".to_string()),
        ..Default::default()
    };
    let code = run(args).await;
    assert_eq!(code, 0, "the table-form pin must land and attest");

    let manifest = std::fs::read_to_string(tmp.path().join("Cargo.toml")).unwrap();
    assert!(
        manifest.contains(&format!(
            "[dependencies.serde]\nregistry = \"socket-patch-{CARGO_UUID}\"\nversion = \"1.0.190\""
        )),
        "the table entry must gain the registry line: {manifest}"
    );
    let cfg = std::fs::read_to_string(tmp.path().join(".cargo/config.toml")).unwrap();
    assert!(
        cfg.contains(&index_url),
        "the managed registry block must be wired in: {cfg}"
    );
    assert!(
        !tmp.path().join("Cargo.lock").exists(),
        "no lockfile may be invented"
    );
    vlt_hosted_common::assert_no_ledger(tmp.path());
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&vex_path).unwrap()).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "the landed redirect is attested: {doc}");
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-carg-cccc-dddd");
}

/// Manifest-less VEX over the committed state of an in-process npm
/// `scan --mode hosted` (the in-process twin of `e2e_redirect_npm_build`'s
/// tail): a checkout carrying only package.json, the redirected
/// package-lock.json and `.socket/` — nothing installed (the hosted host is
/// fictional), so the lockfile pin is the basis — attests with the ledger,
/// without it (lockfile discovery + patch API), not `--offline`
/// (`record_unavailable`, zero requests) and not once the lock is reverted
/// (`redirect_unwired`, `--no-verify` too); `apply --vex` agrees.
#[tokio::test]
#[serial]
async fn in_process_hosted_scan_state_attests_manifest_less() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let pristine = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    assert_eq!(run(redirect_args(tmp.path(), server.uri())).await, 0);

    let checkout = tmp.path().join("checkout");
    npm_e2e_common::fresh_checkout(tmp.path(), &checkout, &["package-lock.json"]);
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let api = vex_e2e_common::PatchApi::start(vec![(
                    UUID.to_string(),
                    vex_e2e_common::patch_view(
                        UUID,
                        PURL,
                        &[("package/index.js", &"b".repeat(64))],
                        &[(GHSA, &["CVE-2024-9"])],
                    ),
                )]);
                npm_e2e_common::manifestless_vex_matrix(&npm_e2e_common::ManifestlessCase {
                    label: "in-process hosted scan".to_string(),
                    project: &checkout,
                    purl: PURL,
                    uuid: UUID,
                    marker: vex_e2e_common::Marker::Redirected,
                    vulns: &[(GHSA, &["CVE-2024-9"])],
                    api: &api,
                    patch_server_url: Some("http://patch.test".to_string()),
                    registry_locks: vec![("package-lock.json", pristine.clone())],
                    embedded: &[vex_e2e_common::VexVia::Apply],
                });
            })
            .join()
            .expect("manifest-less VEX tail panicked");
    });
}

// ── #557 / #817: restore keeps the registry tarball URL its PM records ──────

/// [`mock_npm_registry`] for a registry whose version document advertises
/// `tarball_url` as `dist.tarball` — a proxy or GitHub Packages-style
/// registry whose URLs are not at the conventional
/// `<registry>/<name>/-/<name>-<version>.tgz` path. Also mounts the
/// `/upstream/npm/<uuid>.json` record a berry restore reads its checksum
/// from.
async fn mock_npm_registry_advertising(server: &MockServer, integrity: &str, tarball_url: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/npm-registry/{NAME}/{VERSION}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": NAME,
            "version": VERSION,
            "dist": {
                "tarball": tarball_url,
                "integrity": integrity,
                "shasum": "0".repeat(40),
            }
        })))
        .mount(server)
        .await;
    let checksum = socket_patch_core::vendor::test_support::service_fixture::berry_checksum(
        &upstream_tarball(),
        NAME,
    )
    .unwrap();
    Mock::given(method("GET"))
        .and(path(format!("/upstream/npm/{UUID}.json")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": NAME, "version": VERSION, "integrity": integrity, "yarnBerry10c0": checksum
        })))
        .mount(server)
        .await;
}

/// #817: on a registry whose `dist.tarball` is not at yarn's conventional
/// path, yarn locks the entry as `name@npm:<v>::__archiveUrl=<encoded url>`
/// and fetches from that URL. A hosted pin then `rollback` must give the
/// binding back (the restored locator is the one yarn wrote), not a bare
/// `name@npm:<v>` that yarn would fetch from a path the registry never
/// advertised.
#[tokio::test]
#[serial]
async fn yarn_berry_rollback_restores_the_registry_archive_url_binding() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    let hosted_url = HOSTED_URL.replace("http://patch.test", &server.uri());
    mock_reference_with_berry_url(&server, &hosted_url).await;
    mock_view(&server).await;
    let advertised = format!(
        "{}/files/{}",
        server.uri(),
        socket_patch_core::utils::uri::encode_uri_component(&format!(
            "https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz"
        ))
    );
    mock_npm_registry_advertising(
        &server,
        &vlt_hosted_common::sha512_sri(&upstream_tarball()),
        &advertised,
    )
    .await;
    let binding = |t: &str| {
        t.replace(
            &format!("resolution: \"{NAME}@npm:{VERSION}\""),
            &format!(
                "resolution: \"{NAME}@npm:{VERSION}::__archiveUrl={}\"",
                socket_patch_core::utils::uri::encode_uri_component(&advertised)
            ),
        )
    };

    let tmp = tempfile::tempdir().unwrap();
    write_berry_project_spelled(tmp.path(), binding);
    let lock_path = tmp.path().join("yarn.lock");
    let pristine = std::fs::read_to_string(&lock_path).unwrap();
    assert!(pristine.contains("::__archiveUrl="), "{pristine}");

    let env = run_redirect_subprocess_with(
        tmp.path(),
        &server.uri(),
        &["--patch-server-url", &server.uri()],
    );
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    let pinned = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        pinned.contains(&format!("\n  resolution: \"{NAME}@{hosted_url}\"\n")),
        "{pinned}"
    );

    let (code, env) = rollback_json_with_origin(tmp.path(), &server, &server.uri());
    assert_eq!(code, Some(0), "rollback: {env:#}");
    assert_eq!(
        env["hosted"]["reverted"],
        serde_json::json!([PURL]),
        "{env:#}"
    );
    let restored = std::fs::read_to_string(&lock_path).unwrap();
    let checksum = berry_checksum_of(&restored);
    assert_eq!(
        restored,
        pristine.replace(
            &format!("10c0/{}", "3".repeat(128)),
            &format!("10c0/{checksum}")
        ),
        "rollback restores the locator with its __archiveUrl binding"
    );
}

/// #817 control: a registry serving conventional tarball URLs keeps the
/// bare `name@npm:<v>` locator yarn writes for it (no binding invented).
#[tokio::test]
#[serial]
async fn yarn_berry_rollback_keeps_a_bare_locator_for_conventional_urls() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    let hosted_url = HOSTED_URL.replace("http://patch.test", &server.uri());
    mock_reference_with_berry_url(&server, &hosted_url).await;
    mock_view(&server).await;
    let conventional = format!(
        "{}/npm-registry/{NAME}/-/{NAME}-{VERSION}.tgz",
        server.uri()
    );
    mock_npm_registry_advertising(
        &server,
        &vlt_hosted_common::sha512_sri(&upstream_tarball()),
        &conventional,
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    write_berry_project(tmp.path());
    let lock_path = tmp.path().join("yarn.lock");
    let pristine = std::fs::read_to_string(&lock_path).unwrap();
    let env = run_redirect_subprocess_with(
        tmp.path(),
        &server.uri(),
        &["--patch-server-url", &server.uri()],
    );
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    let (code, env) = rollback_json_with_origin(tmp.path(), &server, &server.uri());
    assert_eq!(code, Some(0), "rollback: {env:#}");
    let restored = std::fs::read_to_string(&lock_path).unwrap();
    let checksum = berry_checksum_of(&restored);
    assert_eq!(
        restored,
        pristine.replace(
            &format!("10c0/{}", "3".repeat(128)),
            &format!("10c0/{checksum}")
        )
    );
    assert!(!restored.contains("__archiveUrl"), "{restored}");
}

/// #908: the restore reads `dist.tarball` from the registry the project
/// resolves against (`.yarnrc.yml` `npmRegistryServer`), not from the
/// default registry. A mirror whose tarball URLs are off the conventional
/// path keeps its `::__archiveUrl=` binding, even though the default
/// registry (`SOCKET_NPM_REGISTRY` here, npmjs normally) serves the
/// conventional URL yarn would derive — and the mirror would 404.
#[tokio::test]
#[serial]
async fn yarn_berry_rollback_reads_the_tarball_from_the_project_registry() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    let hosted_url = HOSTED_URL.replace("http://patch.test", &server.uri());
    mock_reference_with_berry_url(&server, &hosted_url).await;
    mock_view(&server).await;
    let integrity = vlt_hosted_common::sha512_sri(&upstream_tarball());
    // The default registry: conventional URLs, as npmjs serves them.
    mock_npm_registry_advertising(
        &server,
        &integrity,
        &format!(
            "{}/npm-registry/{NAME}/-/{NAME}-{VERSION}.tgz",
            server.uri()
        ),
    )
    .await;
    // The project's mirror: Artifactory/CDN-style tarball URLs.
    let mirror = format!("{}/mirror", server.uri());
    let advertised = format!("{}/cdn/files/{NAME}-{VERSION}.tgz", server.uri());
    Mock::given(method("GET"))
        .and(path(format!("/mirror/{NAME}/{VERSION}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": NAME,
            "version": VERSION,
            "dist": { "tarball": advertised, "integrity": integrity },
        })))
        .mount(&server)
        .await;
    let binding = |t: &str| {
        t.replace(
            &format!("resolution: \"{NAME}@npm:{VERSION}\""),
            &format!(
                "resolution: \"{NAME}@npm:{VERSION}::__archiveUrl={}\"",
                socket_patch_core::utils::uri::encode_uri_component(&advertised)
            ),
        )
    };

    let tmp = tempfile::tempdir().unwrap();
    write_berry_project_spelled(tmp.path(), binding);
    std::fs::write(
        tmp.path().join(".yarnrc.yml"),
        format!("nodeLinker: node-modules\nnpmRegistryServer: \"{mirror}\"\n"),
    )
    .unwrap();
    let lock_path = tmp.path().join("yarn.lock");
    let pristine = std::fs::read_to_string(&lock_path).unwrap();

    let env = run_redirect_subprocess_with(
        tmp.path(),
        &server.uri(),
        &["--patch-server-url", &server.uri()],
    );
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");

    let (code, env) = rollback_json_with_origin(tmp.path(), &server, &server.uri());
    assert_eq!(code, Some(0), "rollback: {env:#}");
    assert_eq!(
        env["hosted"]["reverted"],
        serde_json::json!([PURL]),
        "{env:#}"
    );
    let restored = std::fs::read_to_string(&lock_path).unwrap();
    let checksum = berry_checksum_of(&restored);
    assert_eq!(
        restored,
        pristine.replace(
            &format!("10c0/{}", "3".repeat(128)),
            &format!("10c0/{checksum}")
        ),
        "rollback keeps the mirror's __archiveUrl binding"
    );
}

/// A pnpm project whose lock records the patched entry as
/// `{integrity, tarball: <tarball>}` — what pnpm writes under
/// `lockfile-include-tarball-url`, or for a tarball URL the registry
/// serves off the conventional path.
fn write_pnpm_tarball_project(root: &Path, tarball: &str) -> String {
    write_pnpm_project(root);
    let lock = rush_pnpm_lock(NAME).replace(
        "resolution: {integrity: sha512-UPSTREAMupstream==}",
        &format!("resolution: {{integrity: sha512-UPSTREAMupstream==, tarball: {tarball}}}"),
    );
    std::fs::write(root.join("pnpm-lock.yaml"), &lock).unwrap();
    lock
}

/// Scan hosted, then roll back, and return the restored pnpm-lock.yaml.
fn pnpm_pin_and_rollback(root: &Path, server: &MockServer) -> String {
    let env = run_redirect_subprocess(root, &server.uri());
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    let pinned = std::fs::read_to_string(root.join("pnpm-lock.yaml")).unwrap();
    assert!(pinned.contains("patch.test"), "{pinned}");
    let (code, env) = rollback_json(root, server);
    assert_eq!(code, Some(0), "rollback: {env:#}");
    assert_eq!(
        env["hosted"]["reverted"],
        serde_json::json!([PURL]),
        "{env:#}"
    );
    std::fs::read_to_string(root.join("pnpm-lock.yaml")).unwrap()
}

/// #557: under `.npmrc` `lockfile-include-tarball-url=true` (pnpm 9/10),
/// pnpm records every resolution with its `tarball:` URL, so `rollback`
/// must write the registry's `dist.tarball` back — byte-exact.
#[tokio::test]
#[serial]
async fn pnpm_rollback_keeps_tarball_under_npmrc_include_tarball_url() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    mock_npm_registry(&server, "sha512-UPSTREAMupstream==", None).await;
    let tarball = format!(
        "{}/npm-registry/{NAME}/-/{NAME}-{VERSION}.tgz",
        server.uri()
    );

    let tmp = tempfile::tempdir().unwrap();
    let pristine = write_pnpm_tarball_project(tmp.path(), &tarball);
    std::fs::write(
        tmp.path().join(".npmrc"),
        "lockfile-include-tarball-url=true\n",
    )
    .unwrap();
    assert_eq!(pnpm_pin_and_rollback(tmp.path(), &server), pristine);
}

/// #557, the pnpm 10+ spelling: `lockfileIncludeTarballUrl: true` in
/// pnpm-workspace.yaml.
#[tokio::test]
#[serial]
async fn pnpm_rollback_keeps_tarball_under_workspace_include_tarball_url() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    mock_npm_registry(&server, "sha512-UPSTREAMupstream==", None).await;
    let tarball = format!(
        "{}/npm-registry/{NAME}/-/{NAME}-{VERSION}.tgz",
        server.uri()
    );

    let tmp = tempfile::tempdir().unwrap();
    let pristine = write_pnpm_tarball_project(tmp.path(), &tarball);
    std::fs::write(
        tmp.path().join("pnpm-workspace.yaml"),
        "packages:\n  - '.'\nlockfileIncludeTarballUrl: true\n",
    )
    .unwrap();
    assert_eq!(pnpm_pin_and_rollback(tmp.path(), &server), pristine);
}

/// #557, the other case pnpm records `tarball:` in: the registry's
/// `dist.tarball` is not the conventional URL pnpm would derive, so pnpm
/// keeps it even without the setting.
#[tokio::test]
#[serial]
async fn pnpm_rollback_keeps_an_unconventional_registry_tarball() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    let advertised = format!("{}/files/{NAME}/{VERSION}/download.tgz", server.uri());
    mock_npm_registry_advertising(&server, "sha512-UPSTREAMupstream==", &advertised).await;

    let tmp = tempfile::tempdir().unwrap();
    let pristine = write_pnpm_tarball_project(tmp.path(), &advertised);
    assert_eq!(pnpm_pin_and_rollback(tmp.path(), &server), pristine);
}

/// Mount the version document of the project's `.npmrc` mirror at
/// `<server>/mirror`, advertising `tarball` as `dist.tarball`, and return
/// the mirror's base URL.
async fn mock_pnpm_mirror(server: &MockServer, tarball: &str) -> String {
    Mock::given(method("GET"))
        .and(path(format!("/mirror/{NAME}/{VERSION}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": NAME,
            "version": VERSION,
            "dist": { "tarball": tarball, "integrity": "sha512-UPSTREAMupstream==" },
        })))
        .mount(server)
        .await;
    format!("{}/mirror/", server.uri())
}

/// #919: pnpm's restore reads `dist.tarball` from the registry the
/// project's `.npmrc` names, not from the default registry. A CDN-style
/// mirror tarball pnpm recorded as `tarball:` stays, even though the
/// default registry (`SOCKET_NPM_REGISTRY` here, npmjs normally) serves a
/// conventional URL pnpm would derive — and the mirror would 404 on.
#[tokio::test]
#[serial]
async fn pnpm_rollback_reads_the_npmrc_mirror_document_for_an_offpath_tarball() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    mock_npm_registry(&server, "sha512-UPSTREAMupstream==", None).await;
    let advertised = format!("{}/cdn/files/{NAME}-{VERSION}.tgz", server.uri());
    let mirror = mock_pnpm_mirror(&server, &advertised).await;

    let tmp = tempfile::tempdir().unwrap();
    let pristine = write_pnpm_tarball_project(tmp.path(), &advertised);
    std::fs::write(tmp.path().join(".npmrc"), format!("registry={mirror}\n")).unwrap();
    assert_eq!(pnpm_pin_and_rollback(tmp.path(), &server), pristine);
}

/// #919, under `lockfile-include-tarball-url=true`: the restored `tarball:`
/// is the mirror's URL pnpm wrote, not the default registry's.
#[tokio::test]
#[serial]
async fn pnpm_rollback_keeps_the_mirror_tarball_under_include_tarball_url() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    mock_npm_registry(&server, "sha512-UPSTREAMupstream==", None).await;
    let advertised = format!("{}/mirror/{NAME}/-/{NAME}-{VERSION}.tgz", server.uri());
    let mirror = mock_pnpm_mirror(&server, &advertised).await;

    let tmp = tempfile::tempdir().unwrap();
    let pristine = write_pnpm_tarball_project(tmp.path(), &advertised);
    std::fs::write(
        tmp.path().join(".npmrc"),
        format!("registry={mirror}\nlockfile-include-tarball-url=true\n"),
    )
    .unwrap();
    assert_eq!(pnpm_pin_and_rollback(tmp.path(), &server), pristine);
}

/// #919 on pnpm 11+: the mirror is named by pnpm-workspace.yaml's
/// `registry:` (which pnpm 11 reads ahead of `.npmrc`), not `.npmrc`.
#[tokio::test]
#[serial]
async fn pnpm_rollback_reads_the_workspace_mirror_on_pnpm_11() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    mock_npm_registry(&server, "sha512-UPSTREAMupstream==", None).await;
    let advertised = format!("{}/cdn/files/{NAME}-{VERSION}.tgz", server.uri());
    let mirror = mock_pnpm_mirror(&server, &advertised).await;

    let tmp = tempfile::tempdir().unwrap();
    let pristine = write_pnpm_tarball_project(tmp.path(), &advertised);
    write_pnpm_modules_json(tmp.path(), "11.27.0");
    std::fs::write(
        tmp.path().join("pnpm-workspace.yaml"),
        format!("packages:\n  - '.'\nregistry: {mirror}\n"),
    )
    .unwrap();
    assert_eq!(pnpm_pin_and_rollback(tmp.path(), &server), pristine);
}

/// The scoped package and hosted URL of the #919 scope-registry case.
const SCOPED_NAME: &str = "@socktest/scoped-pkg";
const SCOPED_HOSTED_URL: &str = "http://patch.test/patch/npm/%40socktest/scoped-pkg/1.0.0/22222222-2222-4222-8222-222222222222/11111111-1111-4111-8111-111111111111/scoped-pkg-1.0.0.tgz";

/// A v9 pnpm lock resolving `SCOPED_NAME@VERSION` with `resolution`.
fn scoped_pnpm_lock(resolution: &str) -> String {
    format!(
        "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      \
         '{SCOPED_NAME}':\n        specifier: {VERSION}\n        version: {VERSION}\n\n\
         packages:\n\n  '{SCOPED_NAME}@{VERSION}':\n    resolution: {resolution}\n\n\
         snapshots:\n\n  '{SCOPED_NAME}@{VERSION}': {{}}\n"
    )
}

/// #919, scoped: a scoped name resolves against `.npmrc`'s
/// `@scope:registry`, not `registry`. Its version document is read from
/// there (an off-path CDN tarball stays recorded), and a URL conventional
/// under it stays derived (the bare `{integrity}` stays bare). `registry`
/// names a mirror that 404s and the default registry advertises the other
/// shape each time, so reading either one changes the restored lock.
#[tokio::test]
#[serial]
async fn pnpm_rollback_reads_the_scope_registry_for_a_scoped_name() {
    let server = MockServer::start().await;
    let scope_registry = format!("{}/scoped/", server.uri());
    let cdn = format!("{}/cdn/scoped-pkg-{VERSION}.tgz", server.uri());
    let conventional = format!("{scope_registry}{SCOPED_NAME}/-/scoped-pkg-{VERSION}.tgz");
    for (advertised, default_advertises, recorded) in [
        (&cdn, &conventional, Some(&cdn)),
        (&conventional, &cdn, None),
    ] {
        server.reset().await;
        for (prefix, tarball) in [("scoped", advertised), ("npm-registry", default_advertises)] {
            Mock::given(method("GET"))
                .and(path_regex(format!(
                    "^/{prefix}/@socktest%2[fF]scoped-pkg/{VERSION}$"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "name": SCOPED_NAME,
                    "version": VERSION,
                    "dist": { "tarball": tarball, "integrity": "sha512-UPSTREAMupstream==" },
                })))
                .mount(&server)
                .await;
        }

        let tmp = tempfile::tempdir().unwrap();
        let pristine = scoped_pnpm_lock(&match recorded {
            Some(tarball) => {
                format!("{{integrity: sha512-UPSTREAMupstream==, tarball: {tarball}}}")
            }
            None => "{integrity: sha512-UPSTREAMupstream==}".to_string(),
        });
        let pinned = scoped_pnpm_lock(&format!(
            "{{integrity: {PATCHED_SHA512}, tarball: {SCOPED_HOSTED_URL}}}"
        ));
        std::fs::write(tmp.path().join("pnpm-lock.yaml"), &pinned).unwrap();
        std::fs::write(
            tmp.path().join(".npmrc"),
            format!(
                "registry={}/unscoped/\n@socktest:registry={scope_registry}\n",
                server.uri()
            ),
        )
        .unwrap();

        let (code, env) = rollback_json(tmp.path(), &server);
        assert_eq!(code, Some(0), "rollback: {env:#}");
        assert_eq!(
            env["hosted"]["reverted"],
            serde_json::json!(["pkg:npm/@socktest/scoped-pkg@1.0.0"]),
            "{env:#}"
        );
        assert!(
            !env["warnings"]
                .to_string()
                .contains("upstream_registry_fallback"),
            "{env:#}"
        );
        let restored = std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap();
        assert_eq!(restored, pristine, "advertised {advertised}");
    }
}

/// #919: when the `.npmrc` mirror cannot be read (here it answers 401),
/// pnpm's restore falls back to the default registry's document, exits 0,
/// and says so with `upstream_registry_fallback`.
#[tokio::test]
#[serial]
async fn pnpm_rollback_falls_back_from_an_unreadable_mirror_and_warns() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    mock_npm_registry(&server, "sha512-UPSTREAMupstream==", None).await;
    Mock::given(method("GET"))
        .and(path_regex("^/private/"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    let pristine = std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap();
    std::fs::write(
        tmp.path().join(".npmrc"),
        format!("registry={}/private/\n", server.uri()),
    )
    .unwrap();

    let env = run_redirect_subprocess(tmp.path(), &server.uri());
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    let (code, env) = rollback_json(tmp.path(), &server);
    assert_eq!(code, Some(0), "rollback: {env:#}");
    assert_eq!(
        env["hosted"]["reverted"],
        serde_json::json!([PURL]),
        "{env:#}"
    );
    let codes: Vec<_> = env["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"upstream_registry_fallback"), "{env:#}");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap(),
        pristine
    );
}

/// `remove <PURL>` as a subprocess, like [`rollback_json`].
fn remove_json(cwd: &Path, registry: &MockServer) -> (Option<i32>, serde_json::Value) {
    hosted_unwind_json(cwd, registry, "http://patch.test", &["remove", PURL])
}

/// The `node_modules/.modules.yaml` install record pnpm 10+ writes (JSON),
/// naming `pnpm@{version}` as the pnpm that installed the project.
fn write_pnpm_modules_json(root: &Path, version: &str) {
    std::fs::write(
        root.join("node_modules/.modules.yaml"),
        format!(
            "{{\n  \"layoutVersion\": 5,\n  \"nodeLinker\": \"isolated\",\n  \
             \"packageManager\": \"pnpm@{version}\",\n  \"pendingBuilds\": []\n}}\n"
        ),
    )
    .unwrap();
}

/// #902: pnpm 11/12 ignore `lockfile-include-tarball-url` in `.npmrc`, so
/// the lock they wrote has no `tarball:` and `rollback` must keep it that
/// way, byte-exact.
#[tokio::test]
#[serial]
async fn pnpm_rollback_stays_bare_when_pnpm11_ignores_npmrc_include_tarball_url() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    mock_npm_registry(&server, "sha512-UPSTREAMupstream==", None).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    write_pnpm_modules_json(tmp.path(), "11.28.3");
    std::fs::write(
        tmp.path().join(".npmrc"),
        "lockfile-include-tarball-url=true\n",
    )
    .unwrap();
    let pristine = std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap();
    assert_eq!(pnpm_pin_and_rollback(tmp.path(), &server), pristine);
}

/// #902, `remove` shares the restore: same project as above.
#[tokio::test]
#[serial]
async fn pnpm_remove_stays_bare_when_pnpm12_ignores_npmrc_include_tarball_url() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    mock_npm_registry(&server, "sha512-UPSTREAMupstream==", None).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    write_pnpm_modules_json(tmp.path(), "12.8.1");
    std::fs::write(
        tmp.path().join(".npmrc"),
        "lockfile-include-tarball-url=true\n",
    )
    .unwrap();
    let lock_path = tmp.path().join("pnpm-lock.yaml");
    let pristine = std::fs::read_to_string(&lock_path).unwrap();
    let env = run_redirect_subprocess(tmp.path(), &server.uri());
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    assert!(std::fs::read_to_string(&lock_path)
        .unwrap()
        .contains("patch.test"));
    let (code, env) = remove_json(tmp.path(), &server);
    assert_eq!(code, Some(0), "remove: {env:#}");
    assert_eq!(std::fs::read_to_string(&lock_path).unwrap(), pristine);
}

/// #902: pnpm <= 9 ignores pnpm-workspace.yaml settings, so a
/// `lockfileIncludeTarballUrl: true` there left the lock bare. The pnpm 9
/// install record is YAML.
#[tokio::test]
#[serial]
async fn pnpm_rollback_stays_bare_when_pnpm9_ignores_workspace_include_tarball_url() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    mock_npm_registry(&server, "sha512-UPSTREAMupstream==", None).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    std::fs::write(
        tmp.path().join("node_modules/.modules.yaml"),
        "hoistPattern:\n  - '*'\nlayoutVersion: 5\nnodeLinker: isolated\n\
         packageManager: pnpm@9.15.9\npendingBuilds: []\n",
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("pnpm-workspace.yaml"),
        "packages:\n  - '.'\nlockfileIncludeTarballUrl: true\n",
    )
    .unwrap();
    let pristine = std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap();
    assert_eq!(pnpm_pin_and_rollback(tmp.path(), &server), pristine);
}

/// #902: with no install record, package.json's corepack `packageManager`
/// pin names the pnpm major.
#[tokio::test]
#[serial]
async fn pnpm_rollback_reads_the_pnpm_major_from_package_json_package_manager() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    mock_npm_registry(&server, "sha512-UPSTREAMupstream==", None).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    std::fs::write(
        tmp.path().join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "packageManager": "pnpm@9.15.9+sha512.abc", "dependencies": {{ "{NAME}": "{VERSION}" }} }}"#
        ),
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("pnpm-workspace.yaml"),
        "packages:\n  - '.'\nlockfileIncludeTarballUrl: true\n",
    )
    .unwrap();
    let pristine = std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap();
    assert_eq!(pnpm_pin_and_rollback(tmp.path(), &server), pristine);
}

/// #902: the lock itself is the best witness. An unpinned registry entry
/// pnpm wrote without `tarball:` proves the setting was not in effect,
/// whatever the settings files say.
#[tokio::test]
#[serial]
async fn pnpm_rollback_follows_lock_evidence_over_an_ignored_setting() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    mock_npm_registry(&server, "sha512-UPSTREAMupstream==", None).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    let lock = rush_pnpm_lock(NAME).replace(
        "\nsnapshots:\n",
        "  other-dep@2.0.0:\n    resolution: {integrity: sha512-OTHERother==}\n\n\
             snapshots:\n",
    ) + "  other-dep@2.0.0: {}\n";
    std::fs::write(tmp.path().join("pnpm-lock.yaml"), &lock).unwrap();
    std::fs::write(
        tmp.path().join(".npmrc"),
        "lockfile-include-tarball-url=true\n",
    )
    .unwrap();
    assert_eq!(pnpm_pin_and_rollback(tmp.path(), &server), lock);
}

/// #417: hosted `scan` from a cargo workspace MEMBER treated it as a
/// lockless project, wrote `registry = …` into the member's Cargo.toml and
/// a `[registries]` block into the member's `.cargo/config.toml`, left the
/// root Cargo.lock alone, and exited 0, breaking every build of the
/// workspace. It now refuses with vendored mode's
/// `cargo_manifest_not_workspace_root` and writes nothing.
#[tokio::test]
#[serial]
async fn cargo_hosted_scan_from_workspace_member_refuses() {
    const CARGO_PURL: &str = "pkg:cargo/cfg-if@1.0.4";
    const CARGO_UUID: &str = "33333333-3333-4333-8333-333333333333";
    let cksum = "cd".repeat(32);
    let index_url = format!("sparse+http://patch.test/registry/cargo/{CARGO_UUID}/index/");
    let server = MockServer::start().await;
    mock_cargo_patch(
        &server,
        CARGO_PURL,
        CARGO_UUID,
        "cfg-if",
        "1.0.4",
        &index_url,
        &cksum,
        "GHSA-carg-wsmb-wsmb",
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"inherits\", \"direct\"]\n\n\
         [workspace.dependencies]\ncfg-if = \"1.0.4\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
         checksum = \"ee\"\n\n[[package]]\nname = \"direct\"\nversion = \"0.1.0\"\n\
         dependencies = [\n \"cfg-if\",\n]\n\n[[package]]\nname = \"inherits\"\n\
         version = \"0.1.0\"\ndependencies = [\n \"cfg-if\",\n]\n",
    )
    .unwrap();
    for (member, dep) in [
        ("inherits", "cfg-if = { workspace = true }"),
        ("direct", "cfg-if = \"1.0.4\""),
    ] {
        std::fs::create_dir_all(root.join(member).join("src")).unwrap();
        std::fs::write(
            root.join(member).join("Cargo.toml"),
            format!(
                "[package]\nname = \"{member}\"\nversion = \"0.1.0\"\nedition = \"2018\"\n\n\
                 [dependencies]\n{dep}\n"
            ),
        )
        .unwrap();
        std::fs::write(root.join(member).join("src/lib.rs"), "").unwrap();
    }
    let member = root.join("direct");
    write_vendored_crate(&member, "cfg-if", "1.0.4");
    let manifest_before = std::fs::read(member.join("Cargo.toml")).unwrap();
    let lock_before = std::fs::read(root.join("Cargo.lock")).unwrap();

    let out = scrubbed_cli()
        .args([
            "scan",
            "--mode=hosted",
            "--json",
            "--yes",
            "--cwd",
            member.to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ])
        .output()
        .expect("run socket-patch");
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "scan --json output is not JSON ({e}):\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    assert_eq!(out.status.code(), Some(1), "{doc}");
    assert_eq!(doc["status"], "error", "{doc}");
    assert_eq!(
        doc["errorCode"], "cargo_manifest_not_workspace_root",
        "{doc}"
    );
    assert!(
        doc["error"]
            .as_str()
            .is_some_and(|m| m.contains("workspace root") && m.contains("nothing was written")),
        "{doc}"
    );
    assert_eq!(
        std::fs::read(member.join("Cargo.toml")).unwrap(),
        manifest_before
    );
    assert_eq!(std::fs::read(root.join("Cargo.lock")).unwrap(), lock_before);
    assert!(!member.join(".cargo").exists(), "no member registry block");
    assert!(!member.join(".socket").exists());
}
