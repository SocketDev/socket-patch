//! In-process test for `socket-patch scan --redirect`: mocks the API
//! (discovery + the `patches/package` reference endpoint) via wiremock, lays
//! down an npm project with a lockfile, runs `scan --redirect`, and asserts the
//! lockfile's patched-dependency entry was repointed at the hosted vendored
//! patch (resolved URL + sha512 integrity) and a revert ledger was written.
//! This is the CLI counterpart of the depscan-side install-verify e2e; the
//! rewriter bytes themselves are pinned by the shared golden fixtures.

use std::path::Path;

use serial_test::serial;
use socket_patch_cli::commands::scan::{run, ScanArgs};
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
    assert_eq!(stmts.len(), 1, "the redirected patch must be attested: {doc}");
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA);
    assert_eq!(stmts[0]["status"], "not_affected");
    assert_eq!(stmts[0]["products"][0]["subcomponents"][0]["@id"], PURL);
    let impact = stmts[0]["impact_statement"].as_str().unwrap();
    assert!(
        impact.contains("(redirected)"),
        "the attestation must carry the (redirected) marker: {impact}"
    );
}
