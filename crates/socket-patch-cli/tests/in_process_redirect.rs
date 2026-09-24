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

#[path = "npm_e2e_common/manifestless.rs"]
mod npm_e2e_common;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;
// `bun_vex` re-exports its own copy of `vex_e2e_common` for the bun cells;
// the npm cells use the top-level one above.
#[allow(clippy::duplicate_mod)]
#[path = "vex_e2e_common/bun.rs"]
mod bun_vex;

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
        paths: Vec::new(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            org: Some(ORG.to_string()),
            api_token: Some("fake".to_string()),
            api_url: Some(api_url),
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

/// The berry leg on the Windows lock shapes: yarn berry writes a NEW
/// `yarn.lock` with `os.EOL` (CRLF on Windows), a `core.autocrlf` checkout
/// produces the same on any OS, and editors add a BOM. The hosted chain
/// must redirect the dep (never `redirected: 0` with a line-ending
/// refusal), keep every line CRLF and the BOM, record the lock's on-disk
/// CRLF fragments in the ledger, stay a no-op on re-run, and `rollback`
/// must restore the pristine lock byte-for-byte.
#[tokio::test]
#[serial]
async fn scan_redirect_rewrites_crlf_and_bom_yarn_berry_locks_and_rollback_restores_them() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference_with_berry(&server).await;
    mock_view(&server).await;
    let encoded = socket_patch_core::utils::uri::encode_uri_component(HOSTED_URL);

    for (label, bom) in [("crlf", ""), ("bom+crlf", "\u{feff}")] {
        let tmp = tempfile::tempdir().unwrap();
        write_berry_project_spelled(tmp.path(), |t| format!("{bom}{}", t.replace('\n', "\r\n")));
        let lock_path = tmp.path().join("yarn.lock");
        let pristine = std::fs::read(&lock_path).unwrap();

        let env = run_redirect_subprocess(tmp.path(), &server.uri());
        assert_eq!(env["redirect"]["redirected"], 1, "{label}: {env:#}");
        assert!(
            warning_codes(&env).is_empty(),
            "{label}: no line-ending refusal (or any other warning): {env:#}"
        );
        let lock = std::fs::read_to_string(&lock_path).unwrap();
        assert!(
            lock.contains(&format!("::__archiveUrl={encoded}\"\r\n"))
                && lock.contains(&format!("  checksum: {BERRY_CHECKSUM}\r\n")),
            "{label}: the entry is redirected in CRLF: {lock:?}"
        );
        assert_eq!(
            lock.matches('\n').count(),
            lock.matches("\r\n").count(),
            "{label}: every line keeps CRLF"
        );
        assert_eq!(lock.starts_with('\u{feff}'), !bom.is_empty(), "{label}");

        let ledger = read_ledger(tmp.path());
        let edit = ledger["edits"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["kind"] == "redirect_yarn_berry_entry")
            .unwrap_or_else(|| panic!("{label}: a berry ledger edit: {ledger:#}"));
        for side in ["original", "new"] {
            let fragment = edit[side].as_str().unwrap();
            assert!(
                fragment.contains("\r\n") && !fragment.replace("\r\n", "").contains('\n'),
                "{label}: the ledger's {side} is the on-disk CRLF fragment: {fragment:?}"
            );
            assert!(
                String::from_utf8_lossy(if side == "original" {
                    &pristine
                } else {
                    lock.as_bytes()
                })
                .contains(fragment),
                "{label}: {side} is a verbatim slice of the file"
            );
        }

        // Re-run: in sync, byte-stable, no new ledger edit.
        let env = run_redirect_subprocess(tmp.path(), &server.uri());
        assert_eq!(env["redirect"]["redirected"], 1, "{label}: {env:#}");
        assert_eq!(
            std::fs::read_to_string(&lock_path).unwrap(),
            lock,
            "{label}"
        );
        assert_eq!(
            read_ledger(tmp.path())["edits"].as_array().unwrap().len(),
            ledger["edits"].as_array().unwrap().len(),
            "{label}: a re-run appends nothing"
        );

        let (code, env) = rollback_json(tmp.path());
        assert_eq!(code, Some(0), "{label}: rollback: {env:#}");
        assert_eq!(
            std::fs::read(&lock_path).unwrap(),
            pristine,
            "{label}: rollback restores the pristine CRLF lock byte-for-byte"
        );
        assert!(
            !tmp.path()
                .join(".socket/vendor/redirect-state.json")
                .exists(),
            "{label}: the emptied ledger is removed"
        );
    }
}

/// A berry lock whose line endings are MIXED (CRLF and LF, or a bare CR)
/// cannot be kept in one style — and yarn itself rejects it under
/// `--immutable` — so the hosted run refuses it untouched with a code that
/// names the line endings and the `yarn install` remedy, redirecting
/// nothing and writing no ledger.
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
    assert_eq!(code, 0, "scan --redirect (classic CRLF) should succeed");

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
    assert!(
        tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .is_file(),
        "a redirect ledger should be written"
    );
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
    bun_manifestless_vex(tmp.path(), &lock_before, "bun-v1");
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
    assert_eq!(code, 0, "scan --redirect (bun, lock v2) should succeed");

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
    assert!(
        tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .is_file(),
        "a redirect ledger should be written"
    );
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
/// no `redirect_bun_entry_not_found` — heal the line back to the 3-tuple
/// and record the heal as a second ledger edit for the key (`original` =
/// the 2-tuple); a third run appends nothing; and `rollback` must unwind
/// the chain to the pristine registry line whether the lock is the healed
/// 3-tuple or Bun has since dropped the digest again. Before the fix the
/// repeat scan warned `entry_not_found` beside `redirected: 1` and
/// rollback refused `partial_failure` ("matches neither the redirected nor
/// the original fragment"), stranding every user on those releases.
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
    let ledger_path = tmp.path().join(".socket/vendor/redirect-state.json");

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
        let ledger = read_ledger(tmp.path());
        let edits = ledger["edits"].as_array().unwrap();
        assert_eq!(edits.len(), 2, "first edit + the heal: {ledger:#}");
        assert_eq!(
            edits[0]["original"],
            serde_json::json!(bun_packages_line(&pristine, NAME)),
            "{ledger:#}"
        );
        assert_eq!(edits[1]["key"], NAME, "{ledger:#}");
        assert_eq!(
            edits[1]["original"],
            serde_json::json!(digestless),
            "{ledger:#}"
        );
        assert_eq!(edits[1]["new"], serde_json::json!(wired_line), "{ledger:#}");

        // A third run over the healed lock is a no-op for the ledger.
        let env = run_redirect_subprocess(tmp.path(), &server.uri());
        assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
        assert!(warning_codes(&env).is_empty(), "{env:#}");
        assert_eq!(
            read_ledger(tmp.path())["edits"].as_array().unwrap().len(),
            2,
            "a re-run over the healed lock must not append edits"
        );

        if drop_again_before_rollback {
            // Another `bun add` on Bun < 1.3.10: the digest is gone again.
            std::fs::write(&lock_path, wired.replace(&wired_line, &digestless)).unwrap();
        }
        let (code, env) = rollback_json(tmp.path());
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
        assert!(
            !ledger_path.exists(),
            "the emptied ledger is deleted after a full unwind"
        );
    }
}

// Native binary lockfiles are parsed and patched without invoking Bun.
const INVALID_LOCKB_BYTES: &[u8] = b"\x00BUN-BINARY\xff\xfe\x00LOCK";

/// `rollback --json --yes --offline` as a subprocess; returns (exit code,
/// parsed envelope).
fn rollback_json(cwd: &Path) -> (Option<i32>, serde_json::Value) {
    let out = scrubbed_cli()
        .args([
            "rollback",
            "--json",
            "--yes",
            "--offline",
            "--cwd",
            cwd.to_str().unwrap(),
        ])
        .output()
        .expect("run socket-patch rollback");
    let env_json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "rollback --json stdout must be JSON: {e}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code(), env_json)
}

fn read_ledger(root: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(root.join(".socket/vendor/redirect-state.json")).unwrap();
    serde_json::from_str(&text).expect("the ledger is JSON")
}

/// A child-only PATH with `bin_dir` first, joined with the OS separator.
fn path_with_first(bin_dir: &Path) -> std::ffi::OsString {
    let mut entries = vec![bin_dir.to_path_buf()];
    entries.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    std::env::join_paths(entries).expect("PATH entries join")
}

/// `scan --redirect --json --yes` as a subprocess with the given child PATH;
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

/// A corrupt redirect ledger refuses before any binary-lockfile edits.
/// The existing binary remains byte-identical and no Bun process starts.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn corrupt_ledger_refuses_before_the_bun_lockb_edit() {
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

    // A torn ledger: parseable as neither the vendor nor the redirect shape.
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
    assert_eq!(code, 1, "a corrupt ledger must flip the exit code");
    assert!(!bin_dir.join("bun-was-spawned").exists());
    assert_eq!(
        std::fs::read(tmp.path().join("bun.lockb")).ok().as_deref(),
        Some(b"BUN-BINARY-PLACEHOLDER".as_slice()),
        "the binary lock must be byte-untouched: the refusal precedes the rewrite"
    );
    assert!(
        !tmp.path().join("bun.lock").exists(),
        "no text lock may be created by a run that refused before redirecting"
    );
    // The malformed ledger is quarantined (never deleted), so recovery of the
    // pre-redirect originals it may still hold stays possible.
    let quarantined = tmp
        .path()
        .join(".socket/vendor/redirect-state.json.corrupt");
    assert_eq!(
        std::fs::read(&quarantined).unwrap(),
        corrupt_bytes,
        "the malformed ledger is moved aside verbatim"
    );
}

/// An unusable ledger is an ERROR, not a silent success:
/// `.socket/vendor/redirect-state.json` is the only revert path (and the VEX
/// record store). A DIRECTORY squatting on the ledger path makes it
/// unloadable, so the run must fail closed BEFORE rewriting anything — the
/// old flow rewrote the lockfile first and only then discovered the ledger
/// could not be persisted, leaving the repo redirected with no way back.
#[tokio::test]
#[serial]
async fn unwritable_ledger_fails_the_run() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    // Occupy the ledger path with a DIRECTORY so the ledger cannot be loaded
    // (or written).
    std::fs::create_dir_all(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap();

    let code = run(redirect_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 1, "an unusable ledger must flip the exit code");
    // Fail-closed ordering: the ledger problem surfaces before any project
    // file is touched, so the lockfile still points at the upstream registry.
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        !lock.contains(HOSTED_URL),
        "an unusable ledger must abort before the lockfile rewrite; got:\n{lock}"
    );
}

/// Findings hosted-atomicity 1+2: a MID-RUN lockfile write failure (second of
/// two locks unwritable) must never leave the successfully-written first lock
/// redirected with no ledger record of its pre-redirect originals. The ledger
/// is persisted BEFORE the lockfile loop, so every planned edit's original is
/// durable even when a later write fails; the failed lock itself stays
/// byte-untouched (atomic stage+rename, no truncation).
///
/// unix-only: a read-only directory does not block file creation on Windows.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn partial_lockfile_write_failure_persists_ledger_originals() {
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
    // …so its pre-redirect originals MUST already be in the ledger: without
    // them a revert is impossible, and a re-run cannot recapture them (the
    // entry is already redirected and produces no new edit).
    let ledger = std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json"))
        .expect("the ledger must be persisted before any lockfile is mutated");
    assert!(
        ledger.contains("UPSTREAMupstream"),
        "the ledger must record the pre-redirect original integrity: {ledger}"
    );
    assert!(
        ledger.contains("common/config/rush/pnpm-lock.yaml"),
        "the ledger must record the edit for the lock that WAS written: {ledger}"
    );

    // The failed lock is byte-untouched — no partial/truncated write.
    assert_eq!(
        std::fs::read_to_string(subspace_dir.join("pnpm-lock.yaml")).unwrap(),
        before_subspace,
        "the unwritable lock must stay byte-identical (atomic writes)"
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
    // And no root pnpm-workspace.yaml either: rush runs pnpm in common/temp,
    // which never reads the repo root, so the trustLockfile auto-config
    // (root-lock-gated) must stay hands-off here — writing it would be
    // config theater.
    assert!(
        !tmp.path().join("pnpm-workspace.yaml").exists(),
        "rush nested-lock redirects must not create a root pnpm-workspace.yaml"
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
    run_redirect_subprocess_with(cwd, api_url, &[])
}

/// [`run_redirect_subprocess`] with extra CLI flags appended (e.g. the
/// `--no-trust-lockfile-config` opt-out), so flag-dependent envelope shapes
/// are exercised through the real clap parse.
fn run_redirect_subprocess_with(cwd: &Path, api_url: &str, extra: &[&str]) -> serde_json::Value {
    let out = scrubbed_cli()
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
        .args(extra)
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
    // No ledger half-claims the purl either: an unconfirmed dep must fetch
    // no record and record no edits.
    let ledger_path = tmp.path().join(".socket/vendor/redirect-state.json");
    if let Ok(text) = std::fs::read_to_string(&ledger_path) {
        let ledger: serde_json::Value =
            serde_json::from_str(&text).expect("the redirect ledger must be valid JSON");
        assert!(
            ledger["records"].get(PURL).is_none(),
            "an unconfirmed dep must not be recorded: {ledger}"
        );
        let claimed = ledger["edits"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|e| e["key"].as_str().is_some_and(|k| k.contains(NAME)));
        assert!(!claimed, "no edit may claim the refused dep: {ledger}");
    }
}

/// The rewriters' own warnings must reach HUMAN mode too, not just the
/// `--json` envelope: they carry the load-bearing "why nothing happened /
/// what you must do" guidance (`redirect_npm_no_lockfile`,
/// `redirect_gradle_manual_snippet`, the missing-integrity family).
/// Regression guard: the human branch printed skipped/record/rush warnings
/// but dropped `rewrite.warnings` entirely, so a default-mode
/// `scan --redirect` in a lockfile-less project reported "Redirected 0
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
            "--redirect",
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
        stdout.contains("Redirected 0 packages; rewrote 0 files."),
        "anchor: the run must have taken the human-mode redirect branch; \
         stdout=\n{stdout}"
    );
    assert!(
        stderr.contains("Warning (redirect_npm_no_lockfile): No package-lock.json"),
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
            "--redirect",
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
            "--redirect",
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
        stdout.contains("Redirected 1 package; rewrote"),
        "anchor: the dep must have been redirected so the record fetch runs; \
         stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "Warning (record_fetch_failed): {PURL} redirected, but its patch record could not \
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

    // The ledger records the workspace-trust edit (created ⇒ revert deletes).
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(pnpm.path().join(".socket/vendor/redirect-state.json")).unwrap(),
    )
    .unwrap();
    assert!(
        ledger["edits"].as_array().unwrap().iter().any(|e| {
            e["kind"] == "redirect_pnpm_workspace_trust"
                && e["action"] == "created"
                && e["path"] == "pnpm-workspace.yaml"
                && e["key"] == "trustLockfile"
        }),
        "the ledger must record the created workspace-trust edit: {ledger}"
    );

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
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap(),
    )
    .unwrap();
    assert!(
        !ledger.to_string().contains("redirect_pnpm_workspace_trust"),
        "the opt-out must record no workspace-trust edit: {ledger}"
    );
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
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap(),
    )
    .unwrap();
    assert!(
        !ledger.to_string().contains("redirect_pnpm_workspace_trust"),
        "no workspace-trust edit may be recorded for a respected user setting: {ledger}"
    );
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
    assert_eq!(code, 0, "scan --redirect should succeed");

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

/// `scan --redirect --json` must emit a machine-readable error envelope on
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
            "--redirect",
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
            "--redirect",
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

/// Shared driver for the write-failure legs: a hosted `scan --redirect --json`
/// subprocess against the obstructed project in `tmp`.
async fn run_hosted_json_scan(tmp: &std::path::Path, server: &MockServer) -> std::process::Output {
    scrubbed_cli()
        .args([
            "scan",
            "--redirect",
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
/// `redirect_json_mode_failures_emit_error_envelope` above; leg 4 — the
/// ledger write — is pinned by the unix-only
/// `redirect_ledger_write_failure_leaves_project_files_untouched` below.)
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
    // Rush project: the lock lives in a subdirectory, so obstructing it does
    // not also block the (earlier) `.socket/vendor` ledger write at the root.
    write_rush_project(tmp.path(), false);
    let lock_dir = tmp.path().join("common/config/rush");
    std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let out = run_hosted_json_scan(tmp.path(), &server).await;
    std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_write_failure_envelope(&out, "lockfile-write failure");
}

/// Leg 4 of the four `--json` failure exits: the revert ledger cannot be
/// persisted — `.socket/vendor` is read-only, so the atomic writer's stage
/// file cannot be created. The ledger is written BEFORE the project files
/// (its recorded originals are the only revert path), so the failure must
/// also leave the lockfile untouched — not rewritten-but-unrevertable.
///
/// unix-only: the obstruction is a read-only DIRECTORY, and Windows ignores
/// FILE_ATTRIBUTE_READONLY on directories for file creation, so the stage
/// file would be created fine there.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn redirect_ledger_write_failure_leaves_project_files_untouched() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_before = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
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
    assert_write_failure_envelope(&out, "ledger-write failure");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap(),
        lock_before,
        "a failed ledger write must leave the project files untouched \
         (ledger-before-files ordering)"
    );
}

/// A MALFORMED redirect ledger (torn write, truncation, bad hand-edit) must
/// abort a hosted run before anything is written. The old tolerant load
/// returned `None` for it, so `run_redirect` started a FRESH ledger and
/// overwrote the corrupt file — permanently destroying every previously
/// recorded pre-redirect original (the only revert path) with exit 0.
#[tokio::test]
#[serial]
async fn corrupt_ledger_fails_closed_and_preserves_the_bytes() {
    const TORN: &[u8] = b"{ \"version\": 1, \"mode\": \"hosted\", \"edits\": [ { \"path\": \"packa";

    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_before = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(vendor_dir.join("redirect-state.json"), TORN).unwrap();

    let out = scrubbed_cli()
        .args([
            "scan",
            "--redirect",
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
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a corrupt ledger must be a hard error, not a silent fresh start; \
         stdout=\n{stdout}"
    );
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("--json stdout must stay parseable on failure");
    assert_eq!(v["status"], "error");
    let message = v["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("redirect-state.json"),
        "error must name the ledger file: {message}"
    );
    assert!(
        message.contains("redirect-state.json.corrupt"),
        "error must point at the moved-aside file: {message}"
    );
    // The corruption is reported ONCE, as the engine's hard error: the
    // read-only `updates[]` consult of the same file must not also print
    // its advisory warning for a hosted run.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr.matches("is malformed").count(),
        1,
        "the corrupt-ledger message must print exactly once; stderr=\n{stderr}"
    );

    // Nothing was rewritten, and the corrupt bytes survived verbatim in the
    // quarantine file — never overwritten by a fresh ledger.
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap(),
        lock_before,
        "the project must be untouched"
    );
    assert_eq!(
        std::fs::read(vendor_dir.join("redirect-state.json.corrupt")).unwrap(),
        TORN,
        "the corrupt ledger bytes must be preserved for recovery"
    );
    assert!(
        !vendor_dir.join("redirect-state.json").exists(),
        "no fresh ledger may be written over the failure"
    );
}

/// `--dry-run` over a corrupt ledger reports the same hard error but moves
/// nothing: a dry run must not mutate the project, quarantine included.
#[tokio::test]
#[serial]
async fn corrupt_ledger_dry_run_errors_without_moving_the_file() {
    const TORN: &[u8] = b"{ not json";

    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(vendor_dir.join("redirect-state.json"), TORN).unwrap();

    let out = scrubbed_cli()
        .args([
            "scan",
            "--redirect",
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
    assert_eq!(
        out.status.code(),
        Some(1),
        "dry-run must report the corruption a real run would refuse on; \
         stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read(vendor_dir.join("redirect-state.json")).unwrap(),
        TORN,
        "dry-run must not move or rewrite the malformed ledger"
    );
    assert!(
        !vendor_dir.join("redirect-state.json.corrupt").exists(),
        "dry-run must not quarantine"
    );
}

/// D2 regression: hosted mode records patches ONLY in the redirect ledger —
/// it never writes `.socket/manifest.json` — so `updates[]` (the documented
/// read-only CI signal) must consult the ledger too. A pure hosted project
/// whose redirected patch has been superseded used to report `updates: []`
/// forever.
#[tokio::test]
#[serial]
async fn scan_updates_reports_superseding_patch_for_ledger_only_project() {
    const OLD_UUID: &str = "99999999-9999-4999-8999-999999999999";

    let server = MockServer::start().await;
    // Discovery offers ONLY the new uuid; the ledger records the old one.
    mock_discovery(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    // Ledger-only persistence, exactly as a previous hosted run left it.
    let mut ledger = socket_patch_core::patch::redirect::RedirectState::new();
    ledger.records.insert(
        PURL.to_string(),
        PatchRecord {
            uuid: OLD_UUID.to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        },
    );
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(
        vendor_dir.join("redirect-state.json"),
        format!("{}\n", serde_json::to_string_pretty(&ledger).unwrap()),
    )
    .unwrap();

    // Plain read-only `scan --json` — the nightly CI shape from the finding.
    let out = scrubbed_cli()
        .args([
            "scan",
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
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("parseable envelope");
    let updates = v["updates"].as_array().expect("updates array");
    assert_eq!(
        updates.len(),
        1,
        "the ledger-recorded patch was superseded — updates[] must say so; \
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
/// `redirected: 0`, no patch record in the ledger, and nothing for `vex` to
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

    // The confirmation is what drives the record fetch: no confirmation, no
    // record, and `socket-patch vex` can never attest the patch.
    let ledger =
        std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger.contains(COMPOSER_PURL) && ledger.contains(GHSA),
        "the ledger must carry the fetched patch record for the redirected purl: {ledger}"
    );
    assert!(
        ledger.contains("redirect_composer_dist"),
        "the ledger must carry the revert edit for the lock rewrite: {ledger}"
    );
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
    let ledger =
        std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger.contains(CARGO_UUID) && ledger.contains("GHSA-carg-cccc-dddd"),
        "the ledger must record the landed redirect: {ledger}"
    );
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
