//! In-process full-apply tests for ecosystems whose toolchains may
//! not be on the developer's host (golang, maven, composer, nuget).
//!
//! Instead of running real installers, we **handcraft the on-disk
//! directory layout each crawler expects**, then run the full
//! `socket-patch scan --sync` chain against a wiremock-served patch
//! whose hashes match the bytes we wrote. This is a true install-and-
//! patch e2e for the CLI — only the upstream install step is mimicked
//! (legitimately, since the crawler only sees on-disk state).
//!
//! The handcrafted layouts match exactly what `go mod download`, `mvn
//! dependency:get`, `composer require`, and `dotnet add package`
//! produce. The Docker e2e tests verify that real installers produce
//! the same layouts.

// Each test is feature-gated on its ecosystem (e.g. `cfg(feature =
// "golang")` for the gin tests). With default features (no ecosystems
// enabled) every test and helper compiles out — quiet the resulting
// dead-code/unused-import noise so non-feature builds stay warning-
// clean.
#![allow(dead_code, unused_imports)]

use std::path::{Path, PathBuf};

use base64::Engine;
use serial_test::serial;
use sha2::{Digest, Sha256};
use socket_patch_cli::commands::scan::{run as scan_run, ScanArgs};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

// --- Request introspection helpers -----------------------------------------
// The discovery-only tests below previously asserted *only* `scan_run == 0`.
// Exit 0 is also what a crawler that discovered nothing (or short-circuited
// the API entirely) returns, so the old assertion was vacuous. These helpers
// let us assert on the real code path: that the batch endpoint was actually
// hit and that it carried the PURL the crawler was supposed to discover.
async fn recorded(server: &MockServer) -> Vec<wiremock::Request> {
    server.received_requests().await.unwrap_or_default()
}

fn batch_posts(reqs: &[wiremock::Request]) -> Vec<&wiremock::Request> {
    reqs.iter()
        .filter(|r| format!("{}", r.method) == "POST" && r.url.path().ends_with("/patches/batch"))
        .collect()
}

fn req_body(req: &wiremock::Request) -> String {
    String::from_utf8_lossy(&req.body).into_owned()
}

/// Assert the scan crawled the package and sent exactly that PURL to the
/// batch endpoint — proving discovery actually ran rather than no-opping.
async fn assert_discovered_purl(server: &MockServer, expected_purl: &str) {
    let reqs = recorded(server).await;
    let posts = batch_posts(&reqs);
    assert_eq!(
        posts.len(),
        1,
        "exactly one batch query expected (a crawler that found nothing sends none); got {}",
        posts.len()
    );
    let body = req_body(posts[0]);
    assert!(
        body.contains(expected_purl),
        "batch request must carry the discovered purl {expected_purl}; body was: {body}"
    );
}

fn default_scan_args(cwd: &Path, eco: &str, api_url: String) -> ScanArgs {
    ScanArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: true,
            // bypass per-ecosystem project-marker check
            global_prefix: None,
            api_url,
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec![eco.to_string()]),
            download_mode: "diff".to_string(),
            dry_run: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: 100,
        apply: false,
        prune: false,
        sync: true,
        all_releases: false,
        vex: Default::default(),
    }
}

async fn setup_apply_mock(
    server: &MockServer,
    purl: &str,
    uuid: &str,
    file_in_patch: &str,
    before_hash: &str,
    after_hash: &str,
    patched_bytes: &[u8],
) {
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(patched_bytes);

    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": uuid, "purl": purl,
                    "tier": "free", "cveIds": [], "ghsaIds": [],
                    "severity": "medium", "title": "handcrafted fixture"
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

    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                file_in_patch: {
                    "beforeHash": before_hash,
                    "afterHash":  after_hash,
                    "blobContent": blob_b64,
                }
            },
            "vulnerabilities": {},
            "description": "fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(server)
        .await;
}

// ---------------------------------------------------------------------------
// golang
// ---------------------------------------------------------------------------

#[cfg(feature = "golang")]
#[tokio::test]
#[serial]
async fn golang_handcrafted_install_apply_patches_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // GOMODCACHE layout: <encoded-module-path>@<version>/<files>.
    // For `github.com/gin-gonic/gin@v1.9.1`, the encoded module path is
    // the same string (no uppercase letters to escape).
    let module_dir = tmp.path().join("github.com/gin-gonic/gin@v1.9.1");
    std::fs::create_dir_all(&module_dir).unwrap();
    let gin_file = module_dir.join("gin.go");
    let original = b"package gin\n\nfunc Version() string { return \"1.9.1\" }\n";
    std::fs::write(&gin_file, original).unwrap();
    let before_hash = git_sha256(original);
    let mut patched = original.to_vec();
    patched.extend_from_slice(b"\n// SOCKET-PATCH-E2E-MARKER\n");
    let after_hash = git_sha256(&patched);

    std::env::set_var("GOMODCACHE", tmp.path());

    let server = MockServer::start().await;
    setup_apply_mock(
        &server,
        "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
        "15151515-1515-4151-8151-151515151515",
        "package/gin.go",
        &before_hash,
        &after_hash,
        &patched,
    )
    .await;

    let args = default_scan_args(tmp.path(), "golang", server.uri());
    let code = scan_run(args).await;
    // A single free patch that downloads + applies cleanly must exit 0.
    // `download_and_apply_patches` only returns 1 when a patch fails to
    // download or apply, so 1 here means the apply path silently broke.
    assert_eq!(
        code, 0,
        "scan --sync should fully apply the golang patch (exit 0)"
    );

    // Golden check: the file must equal the EXACT patched bytes the mock
    // served, not merely contain the marker substring (a corrupting apply
    // could append the marker while mangling the rest).
    let after = std::fs::read(&gin_file).expect("read after");
    assert_eq!(
        after,
        patched,
        "patched {} bytes do not match the served blob exactly",
        gin_file.display()
    );

    std::env::remove_var("GOMODCACHE");
}

// ---------------------------------------------------------------------------
// maven
// ---------------------------------------------------------------------------

#[cfg(feature = "maven")]
#[tokio::test]
#[serial]
async fn maven_handcrafted_install_apply_patches_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // m2 layout: $repo/org/apache/commons/commons-lang3/3.12.0/<files>
    let repo = tmp.path().join("m2-repo");
    let version_dir = repo.join("org/apache/commons/commons-lang3/3.12.0");
    std::fs::create_dir_all(&version_dir).unwrap();
    // The maven crawler verifies presence of a .pom file. Without it,
    // the version dir is ignored.
    std::fs::write(
        version_dir.join("commons-lang3-3.12.0.pom"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.12.0</version></project>",
    )
    .unwrap();
    // The patchable file: any text file under the version dir.
    let payload_file = version_dir.join("LICENSE.txt");
    let original = b"Apache License 2.0\nThis is the LICENSE.\n";
    std::fs::write(&payload_file, original).unwrap();
    let before_hash = git_sha256(original);
    let mut patched = original.to_vec();
    patched.extend_from_slice(b"\n# SOCKET-PATCH-E2E-MARKER\n");
    let after_hash = git_sha256(&patched);

    std::env::set_var("MAVEN_REPO_LOCAL", &repo);
    // Maven crawler is runtime-gated behind this env var (see
    // `ecosystem_dispatch::maven_runtime_enabled`). The test
    // deliberately exercises the Maven apply path, so opt in.
    std::env::set_var("SOCKET_EXPERIMENTAL_MAVEN", "1");

    let server = MockServer::start().await;
    setup_apply_mock(
        &server,
        "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
        "16161616-1616-4161-8161-161616161616",
        "package/LICENSE.txt",
        &before_hash,
        &after_hash,
        &patched,
    )
    .await;

    let args = default_scan_args(tmp.path(), "maven", server.uri());
    let code = scan_run(args).await;
    assert_eq!(
        code, 0,
        "scan --sync should fully apply the maven patch (exit 0)"
    );

    let after = std::fs::read(&payload_file).expect("read after");
    assert_eq!(
        after,
        patched,
        "patched {} bytes do not match the served blob exactly",
        payload_file.display()
    );

    std::env::remove_var("MAVEN_REPO_LOCAL");
    std::env::remove_var("SOCKET_EXPERIMENTAL_MAVEN");
}

/// Maven is the one release-variant ecosystem where multiple variants
/// COEXIST on disk: a version dir can hold several classifier jars at
/// once (e.g. native `-linux-x86_64` / `-osx-x86_64`). This pins that
/// the (default, narrow) apply path keeps and patches *every* present
/// classifier variant — exercising the plural `select_installed_variants`
/// selector — rather than just the first.
#[cfg(feature = "maven")]
#[tokio::test]
#[serial]
async fn maven_multi_classifier_patches_every_present_jar() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("m2-repo");
    let version_dir = repo.join("org/example/native-lib/1.0.0");
    std::fs::create_dir_all(&version_dir).unwrap();
    std::fs::write(
        version_dir.join("native-lib-1.0.0.pom"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>native-lib</artifactId><version>1.0.0</version></project>",
    )
    .unwrap();

    // Two classifier jars coexist in the same version directory.
    let jar_a = "native-lib-1.0.0-linux-x86_64.jar";
    let jar_b = "native-lib-1.0.0-osx-x86_64.jar";
    let orig_a = b"JAR-A original bytes\n";
    let orig_b = b"JAR-B original bytes\n";
    std::fs::write(version_dir.join(jar_a), orig_a).unwrap();
    std::fs::write(version_dir.join(jar_b), orig_b).unwrap();
    let mut patched_a = orig_a.to_vec();
    patched_a.extend_from_slice(b"\n# MARKER-A\n");
    let mut patched_b = orig_b.to_vec();
    patched_b.extend_from_slice(b"\n# MARKER-B\n");

    std::env::set_var("MAVEN_REPO_LOCAL", &repo);
    std::env::set_var("SOCKET_EXPERIMENTAL_MAVEN", "1");

    let base = "pkg:maven/org.example/native-lib@1.0.0";
    let purl_a = format!("{base}?classifier=linux-x86_64&ext=jar");
    let purl_b = format!("{base}?classifier=osx-x86_64&ext=jar");
    let uuid_a = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let uuid_b = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    let server = MockServer::start().await;
    // Batch + by-package advertise both classifier variants for the base.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": base,
                "patches": [
                    { "uuid": uuid_a, "purl": purl_a, "tier": "free", "cveIds": [],
                      "ghsaIds": [], "severity": "medium", "title": "linux jar" },
                    { "uuid": uuid_b, "purl": purl_b, "tier": "free", "cveIds": [],
                      "ghsaIds": [], "severity": "medium", "title": "osx jar" },
                ]
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
            "patches": [
                { "uuid": uuid_a, "purl": purl_a, "publishedAt": "2024-01-01T00:00:00Z",
                  "description": "linux", "license": "MIT", "tier": "free", "vulnerabilities": {} },
                { "uuid": uuid_b, "purl": purl_b, "publishedAt": "2024-01-01T00:00:00Z",
                  "description": "osx", "license": "MIT", "tier": "free", "vulnerabilities": {} },
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    for (uuid, purl, jar, before, after) in [
        (uuid_a, &purl_a, jar_a, orig_a.to_vec(), patched_a.clone()),
        (uuid_b, &purl_b, jar_b, orig_b.to_vec(), patched_b.clone()),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": uuid,
                "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": {
                    jar: {
                        "beforeHash": git_sha256(&before),
                        "afterHash": git_sha256(&after),
                        "blobContent": base64::engine::general_purpose::STANDARD.encode(&after),
                    }
                },
                "vulnerabilities": {},
                "description": "fixture", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;
    }

    let args = default_scan_args(tmp.path(), "maven", server.uri());
    let code = scan_run(args).await;
    assert_eq!(
        code, 0,
        "scan --sync should fully apply BOTH classifier patches (exit 0)"
    );

    // BOTH coexisting classifier jars must be patched — and to the EXACT
    // served bytes, so a selector that patches one jar with the other's
    // blob (or only the first) is caught.
    let after_a = std::fs::read(version_dir.join(jar_a)).expect("read jar a");
    let after_b = std::fs::read(version_dir.join(jar_b)).expect("read jar b");
    assert_eq!(
        after_a, patched_a,
        "linux-x86_64 classifier jar bytes do not match its served blob"
    );
    assert_eq!(
        after_b, patched_b,
        "osx-x86_64 classifier jar bytes do not match its served blob (plural selector must keep both)"
    );

    std::env::remove_var("MAVEN_REPO_LOCAL");
    std::env::remove_var("SOCKET_EXPERIMENTAL_MAVEN");
}

// ---------------------------------------------------------------------------
// composer
// ---------------------------------------------------------------------------

#[cfg(feature = "composer")]
#[tokio::test]
#[serial]
async fn composer_handcrafted_install_apply_patches_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // composer layout: vendor/<vendor>/<name>/<files> + vendor/composer/installed.json
    let vendor = tmp.path().join("vendor");
    let pkg_dir = vendor.join("monolog/monolog");
    std::fs::create_dir_all(pkg_dir.join("src/Monolog")).unwrap();
    let payload = pkg_dir.join("src/Monolog/Logger.php");
    let original = b"<?php\nnamespace Monolog;\nclass Logger {}\n";
    std::fs::write(&payload, original).unwrap();
    let before_hash = git_sha256(original);
    let mut patched = original.to_vec();
    patched.extend_from_slice(b"\n// SOCKET-PATCH-E2E-MARKER\n");
    let after_hash = git_sha256(&patched);

    // installed.json — composer's manifest of vendored packages.
    let installed_dir = vendor.join("composer");
    std::fs::create_dir_all(&installed_dir).unwrap();
    std::fs::write(
        installed_dir.join("installed.json"),
        r#"{ "packages": [
            { "name": "monolog/monolog", "version": "3.5.0", "version_normalized": "3.5.0.0" }
        ] }"#,
    )
    .unwrap();
    // composer.json in cwd so the crawler considers it a PHP project.
    std::fs::write(
        tmp.path().join("composer.json"),
        r#"{ "name": "test/proj", "require": {} }"#,
    )
    .unwrap();

    let server = MockServer::start().await;
    setup_apply_mock(
        &server,
        "pkg:composer/monolog/monolog@3.5.0",
        "17171717-1717-4171-8171-171717171717",
        "package/src/Monolog/Logger.php",
        &before_hash,
        &after_hash,
        &patched,
    )
    .await;

    // composer doesn't need --global; the composer.json marker + vendor/
    // is enough. Use the default args but flip global=false.
    let mut args = default_scan_args(tmp.path(), "composer", server.uri());
    args.common.global = false;
    let code = scan_run(args).await;
    assert_eq!(
        code, 0,
        "scan --sync should fully apply the composer patch (exit 0)"
    );

    let after = std::fs::read(&payload).expect("read after");
    assert_eq!(
        after,
        patched,
        "patched {} bytes do not match the served blob exactly",
        payload.display()
    );
}

// ---------------------------------------------------------------------------
// nuget
// ---------------------------------------------------------------------------

#[cfg(feature = "nuget")]
#[tokio::test]
#[serial]
async fn nuget_handcrafted_install_apply_patches_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // nuget layout: $packages/<lowercase-name>/<version>/<files>
    let packages = tmp.path().join("nuget-packages");
    let pkg_dir = packages.join("newtonsoft.json").join("13.0.3");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    // nuget crawler verifies the directory has a `.nuspec` file or `lib/` dir.
    std::fs::write(
        pkg_dir.join("newtonsoft.json.nuspec"),
        r#"<?xml version="1.0"?><package><metadata>
            <id>Newtonsoft.Json</id><version>13.0.3</version></metadata></package>"#,
    )
    .unwrap();
    let payload = pkg_dir.join("LICENSE.md");
    let original = b"MIT License\nCopyright (c) 2007 James Newton-King\n";
    std::fs::write(&payload, original).unwrap();
    let before_hash = git_sha256(original);
    let mut patched = original.to_vec();
    patched.extend_from_slice(b"\n# SOCKET-PATCH-E2E-MARKER\n");
    let after_hash = git_sha256(&patched);

    std::env::set_var("NUGET_PACKAGES", &packages);
    // NuGet crawler is runtime-gated behind this env var (see
    // `ecosystem_dispatch::nuget_runtime_enabled`). The test
    // deliberately exercises the NuGet apply path, so opt in.
    std::env::set_var("SOCKET_EXPERIMENTAL_NUGET", "1");

    let server = MockServer::start().await;
    setup_apply_mock(
        &server,
        "pkg:nuget/Newtonsoft.Json@13.0.3",
        "18181818-1818-4181-8181-181818181818",
        "package/LICENSE.md",
        &before_hash,
        &after_hash,
        &patched,
    )
    .await;

    let args = default_scan_args(tmp.path(), "nuget", server.uri());
    let code = scan_run(args).await;
    assert_eq!(
        code, 0,
        "scan --sync should fully apply the nuget patch (exit 0)"
    );

    let after = std::fs::read(&payload).expect("read after");
    assert_eq!(
        after,
        patched,
        "patched {} bytes do not match the served blob exactly",
        payload.display()
    );

    std::env::remove_var("NUGET_PACKAGES");
    std::env::remove_var("SOCKET_EXPERIMENTAL_NUGET");
}

// ---------------------------------------------------------------------------
// Discovery-only tests for each handcrafted layout
// ---------------------------------------------------------------------------

#[cfg(feature = "golang")]
#[tokio::test]
#[serial]
async fn golang_handcrafted_discovery() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(tmp.path().join("github.com/gin-gonic/gin@v1.9.1")).unwrap();
    std::env::set_var("GOMODCACHE", tmp.path());

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                "patches": [{
                    "uuid": "x", "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                    "tier": "free", "cveIds": [], "ghsaIds": [], "severity": "low",
                    "title": "discovery"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let mut args = default_scan_args(tmp.path(), "golang", server.uri());
    args.sync = false;
    assert_eq!(scan_run(args).await, 0);
    // Exit 0 alone is vacuous (an empty crawler also exits 0). Prove the
    // handcrafted GOMODCACHE layout was actually crawled and its PURL sent.
    assert_discovered_purl(&server, "pkg:golang/github.com/gin-gonic/gin@v1.9.1").await;
    std::env::remove_var("GOMODCACHE");
}

#[cfg(feature = "maven")]
#[tokio::test]
#[serial]
async fn maven_handcrafted_discovery() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("m2");
    let version_dir = repo.join("org/example/foo/1.0.0");
    std::fs::create_dir_all(&version_dir).unwrap();
    std::fs::write(version_dir.join("foo-1.0.0.pom"), "<project/>").unwrap();
    std::env::set_var("MAVEN_REPO_LOCAL", &repo);
    std::env::set_var("SOCKET_EXPERIMENTAL_MAVEN", "1");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [], "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let mut args = default_scan_args(tmp.path(), "maven", server.uri());
    args.sync = false;
    assert_eq!(scan_run(args).await, 0);
    // Prove the m2 layout (version dir gated on a .pom) was crawled and its
    // PURL queried — not that the crawler silently found nothing.
    assert_discovered_purl(&server, "pkg:maven/org.example/foo@1.0.0").await;
    std::env::remove_var("MAVEN_REPO_LOCAL");
    std::env::remove_var("SOCKET_EXPERIMENTAL_MAVEN");
}

#[cfg(feature = "nuget")]
#[tokio::test]
#[serial]
async fn nuget_handcrafted_discovery() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pkgs = tmp.path().join("pkgs");
    let dir = pkgs.join("foo").join("1.0.0");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("foo.nuspec"), "<package/>").unwrap();
    std::env::set_var("NUGET_PACKAGES", &pkgs);
    std::env::set_var("SOCKET_EXPERIMENTAL_NUGET", "1");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [], "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let mut args = default_scan_args(tmp.path(), "nuget", server.uri());
    args.sync = false;
    assert_eq!(scan_run(args).await, 0);
    // Prove the nuget packages layout (gated on a .nuspec) was crawled and
    // its PURL queried — exit 0 alone would also pass an empty crawl.
    assert_discovered_purl(&server, "pkg:nuget/foo@1.0.0").await;
    std::env::remove_var("NUGET_PACKAGES");
    std::env::remove_var("SOCKET_EXPERIMENTAL_NUGET");
}

// Helper kept around so `PathBuf` import is used in case of future tests.
#[allow(dead_code)]
fn _path_helper() -> PathBuf {
    PathBuf::new()
}
