//! In-process `get <uuid> --mode hosted` coverage for the ecosystems that
//! have NO hermetic hosted e2e today: pypi (requirements.txt), maven
//! (pom.xml — fail-closed suffixed-version pin), nuget (nuget.config +
//! packages.lock.json), composer (composer.lock), plus the deno negative
//! (no redirect rewriter exists for deno — a granted reference must land
//! NOTHING).
//!
//! Modeled on `in_process_get_modes.rs` (view + patches/package reference
//! mocks; disk-state assertions only — in-process `run()` prints its JSON
//! envelope to the real stdout, which these tests cannot capture) and on
//! `in_process_remote_ecosystems_apply.rs` (handcrafted no-toolchain project
//! layouts). The UUID identifier path is used throughout: it is EXEMPT from
//! installed narrowing, so no search endpoints and no installed packages are
//! needed — only the candidate lockfile(s) each core rewriter dispatches on
//! (`socket-patch-core/src/patch/redirect/mod.rs`). Reference-response
//! shapes are copied from the shared golden fixtures under
//! `socket-patch-core/tests/fixtures/redirect/` (the same camelCase
//! `registryOverride`/`identifiers` the API serves and `scan/hosted.rs`
//! deserializes into `DepOverride`).
//!
//! `#[serial]`: `get::run` mirrors env toggles into process-global env vars.

use std::path::Path;

use serial_test::serial;
use socket_patch_cli::commands::get::GetArgs;
use socket_patch_cli::commands::scan::ScanMode;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
/// The grant-token path level that precedes the patch uuid in hosted URLs.
const TOKEN: &str = "11111111-1111-4111-8111-111111111111";

const BEFORE_BYTES: &[u8] = b"vulnerable\n";
const AFTER_BYTES: &[u8] = b"patched\n";

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn get_hosted_args(identifier: &str, cwd: &Path, api_url: String) -> GetArgs {
    GetArgs {
        common: socket_patch_cli::args::GlobalArgs {
            org: Some(ORG.to_string()),
            cwd: cwd.to_path_buf(),
            yes: true,
            api_token: Some("fake-token-for-tests".to_string()),
            api_url: Some(api_url),
            json: true,
            download_mode: "diff".to_string(),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: identifier.to_string(),
        id: false,
        cve: false,
        ghsa: false,
        package: false,
        save_only: false,
        one_off: false,
        all_releases: false,
        mode: Some(ScanMode::Hosted),
    }
}

/// `view/{uuid}` with real git-blob hashes + inline blob content — the shape
/// the UUID resolution AND the post-confirmation record fetch both read.
async fn mock_view(server: &MockServer, uuid: &str, purl: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/payload.txt": {
                    "beforeHash": compute_git_sha256_from_bytes(BEFORE_BYTES),
                    "afterHash": compute_git_sha256_from_bytes(AFTER_BYTES),
                    "blobContent": b64(AFTER_BYTES),
                }
            },
            "vulnerabilities": {
                "GHSA-hhhh-eeee-xxxx": {
                    "cves": ["CVE-2024-4321"],
                    "summary": "get hosted ecosystems fixture",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "get hosted ecosystems fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(server)
        .await;
}

/// The hosted reference grant for one uuid. `integrity` is the tarball
/// artifact's integrity object; `registry_override` is the camelCase
/// `registryOverride` (or `null` for URL-pinning ecosystems like pypi and
/// composer) — shapes copied from the redirect golden fixtures.
async fn mock_reference(
    server: &MockServer,
    uuid: &str,
    purl: &str,
    url: &str,
    integrity: serde_json::Value,
    registry_override: serde_json::Value,
) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                uuid: {
                    "status": "granted",
                    "url": url,
                    "purl": purl,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": url,
                        "integrity": integrity,
                    }],
                    "registryOverride": registry_override,
                }
            }
        })))
        .mount(server)
        .await;
}

/// Bodies of every reference request the mock saw — the anti-vacuity oracle
/// proving the grant flow actually ran (and ran once) for the right uuid.
async fn reference_bodies(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().ends_with("/patches/package"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect()
}

fn read_ledger(cwd: &Path) -> serde_json::Value {
    let ledger_path = cwd.join(".socket/vendor/redirect-state.json");
    assert!(
        ledger_path.is_file(),
        "redirect ledger must be written at {}",
        ledger_path.display()
    );
    serde_json::from_str(&std::fs::read_to_string(&ledger_path).unwrap())
        .expect("redirect-state.json parses")
}

/// Hosted mode's persistence contract: the ledger IS the store — never the
/// manifest, never blobs (parity with `scan --mode hosted`).
fn assert_no_manifest_no_blobs(cwd: &Path) {
    assert!(
        !cwd.join(".socket/manifest.json").exists(),
        "hosted mode must NOT write the manifest"
    );
    assert!(
        !cwd.join(".socket/blobs").exists(),
        "hosted mode must NOT persist blobs"
    );
}

// ---------------------------------------------------------------------------
// pypi — requirements.txt (rewrite_pypi_requirements)
// ---------------------------------------------------------------------------

/// A pip project pinning `requests==2.31.0`: the hosted grant must rewrite
/// that one line to `requests @ <hosted-url> --hash=sha256:<hex>` (the
/// integrity pin fails closed on tampered bytes), leave the bystander line
/// byte-identical, record the ledger — and write no manifest.
#[tokio::test]
#[serial]
async fn pypi_requirements_hosted_rewrites_pinned_line() {
    const UUID: &str = "a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1";
    const PURL: &str = "pkg:pypi/requests@2.31.0";
    const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let url = format!(
        "http://patch.test/patch/pypi/requests/2.31.0/{TOKEN}/{UUID}/requests-2.31.0-py3-none-any.whl"
    );

    let server = MockServer::start().await;
    mock_view(&server, UUID, PURL).await;
    mock_reference(
        &server,
        UUID,
        PURL,
        &url,
        serde_json::json!({ "sha256": SHA256 }),
        serde_json::Value::Null,
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("requirements.txt"),
        "flask==2.0.1\nrequests==2.31.0\n",
    )
    .unwrap();

    let code =
        socket_patch_cli::commands::get::run(get_hosted_args(UUID, tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "get <uuid> --mode hosted (pypi) should succeed");

    let reqs = std::fs::read_to_string(tmp.path().join("requirements.txt")).unwrap();
    let expected_line = format!("requests @ {url} --hash=sha256:{SHA256}");
    assert!(
        reqs.lines().any(|l| l == expected_line),
        "requirements.txt must pin the hosted wheel URL + sha256; got:\n{reqs}"
    );
    assert!(
        !reqs.contains("requests==2.31.0"),
        "the upstream version pin must be replaced; got:\n{reqs}"
    );
    assert!(
        reqs.lines().any(|l| l == "flask==2.0.1"),
        "the bystander line must survive byte-identical; got:\n{reqs}"
    );

    let ledger = read_ledger(tmp.path());
    assert_eq!(ledger["mode"], "hosted");
    assert_eq!(
        ledger["records"][PURL]["uuid"], UUID,
        "the ledger must record the redirected patch for VEX; got:\n{ledger}"
    );
    assert!(
        ledger["edits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["path"] == "requirements.txt" && e["kind"] == "redirect_requirements_line"),
        "the ledger must carry the requirements.txt edit (revert data); got:\n{ledger}"
    );
    assert_no_manifest_no_blobs(tmp.path());

    let bodies = reference_bodies(&server).await;
    assert_eq!(bodies.len(), 1, "exactly one reference request");
    assert!(bodies[0].contains(UUID));
}

// ---------------------------------------------------------------------------
// maven — pom.xml fail-closed suffixed-version pin (rewrite_maven_pom)
// ---------------------------------------------------------------------------

/// A pom pinning `commons-lang3@3.12.0`: a fail-closed grant (registryOverride
/// carrying `identifiers.mavenSuffixedVersion` + `mavenPomSha256`) must pin
/// the `-socket.<hex8>` SUFFIXED version — served ONLY by the injected Socket
/// `<repository>` (checksumPolicy fail), so a repo failure can never fall
/// back to the unpatched upstream jar — and merge the jar+pom sha256 pair
/// into the Maven trusted-checksums summary file.
#[tokio::test]
#[serial]
async fn maven_pom_hosted_pins_suffixed_version_fail_closed() {
    const UUID: &str = "b2b2b2b2-b2b2-4b2b-8b2b-b2b2b2b2b2b2";
    const PURL: &str = "pkg:maven/org.apache.commons/commons-lang3@3.12.0";
    const SUFFIXED: &str = "3.12.0-socket.b2b2b2b2";
    const JAR_SHA256: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const POM_SHA256: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let index_url = format!("http://patch.test/patch-registry/maven/{TOKEN}/{UUID}/maven2");
    let url = format!(
        "http://patch.test/patch/maven/org.apache.commons/commons-lang3/3.12.0/{TOKEN}/{UUID}/commons-lang3-{SUFFIXED}.jar"
    );

    let server = MockServer::start().await;
    mock_view(&server, UUID, PURL).await;
    // Reference-response shape: the maven arm of the shared redirect golden
    // fixtures (socket-patch-core/tests/fixtures/redirect/maven/pom/basic).
    mock_reference(
        &server,
        UUID,
        PURL,
        &url,
        serde_json::json!({ "sha256": JAR_SHA256 }),
        serde_json::json!({
            "kind": "maven2",
            "indexUrl": index_url,
            "identifiers": {
                "name": "org.apache.commons/commons-lang3",
                "version": "3.12.0",
                "mavenGroupId": "org.apache.commons",
                "mavenArtifactId": "commons-lang3",
                "mavenSuffixedVersion": SUFFIXED,
                "mavenPomSha256": POM_SHA256,
            }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("pom.xml"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>dev.socket.test</groupId>
  <artifactId>consumer</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
  </dependencies>
</project>
"#,
    )
    .unwrap();

    let code =
        socket_patch_cli::commands::get::run(get_hosted_args(UUID, tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "get <uuid> --mode hosted (maven) should succeed");

    let pom = std::fs::read_to_string(tmp.path().join("pom.xml")).unwrap();
    assert!(
        pom.contains(&format!("<version>{SUFFIXED}</version>")),
        "the dependency must pin the suffixed version; got:\n{pom}"
    );
    assert!(
        !pom.contains("<version>3.12.0</version>"),
        "the bare upstream version must be gone (fail-closed); got:\n{pom}"
    );
    assert!(
        pom.contains(&format!("<id>socket-patch-{UUID}</id>")) && pom.contains(&index_url),
        "the Socket repository (id + index url) must be injected; got:\n{pom}"
    );
    assert!(
        pom.contains("<checksumPolicy>fail</checksumPolicy>"),
        "the injected repository must carry the fail transport checksum policy; got:\n{pom}"
    );

    // Trusted checksums: the jar AND the served pom, under the SUFFIXED
    // version's local-repo paths.
    let checksums =
        std::fs::read_to_string(tmp.path().join(".mvn/checksums/checksums.sha256")).unwrap();
    let repo_dir = format!("org/apache/commons/commons-lang3/{SUFFIXED}");
    assert!(
        checksums.contains(&format!(
            "{JAR_SHA256}  {repo_dir}/commons-lang3-{SUFFIXED}.jar"
        )),
        "trusted-checksums must pin the patched jar; got:\n{checksums}"
    );
    assert!(
        checksums.contains(&format!(
            "{POM_SHA256}  {repo_dir}/commons-lang3-{SUFFIXED}.pom"
        )),
        "trusted-checksums must pin the served pom; got:\n{checksums}"
    );
    let mvn_config = std::fs::read_to_string(tmp.path().join(".mvn/maven.config")).unwrap();
    assert!(
        mvn_config.contains("trustedChecksums"),
        "maven.config must enable the trusted-checksums post-processor; got:\n{mvn_config}"
    );

    let ledger = read_ledger(tmp.path());
    assert_eq!(ledger["records"][PURL]["uuid"], UUID);
    assert_no_manifest_no_blobs(tmp.path());

    let bodies = reference_bodies(&server).await;
    assert_eq!(bodies.len(), 1, "exactly one reference request");
    assert!(bodies[0].contains(UUID));
}

// ---------------------------------------------------------------------------
// nuget — nuget.config + packages.lock.json (rewrite_nuget)
// ---------------------------------------------------------------------------

/// A .NET project with a nuget.config (one nuget.org source) and a
/// packages.lock.json pinning Newtonsoft.Json: the grant must add the
/// per-patch Socket source + an EXCLUSIVE packageSourceMapping routing only
/// the patched id there (with a `*` fallback to nuget.org so every other
/// restore keeps resolving), and swap the lock's contentHash for the patched
/// artifact's sha512 (prefix-stripped).
#[tokio::test]
#[serial]
async fn nuget_hosted_wires_source_mapping_and_lock_hash() {
    const UUID: &str = "c3c3c3c3-c3c3-4c3c-8c3c-c3c3c3c3c3c3";
    const PURL: &str = "pkg:nuget/Newtonsoft.Json@13.0.3";
    const PATCHED_SHA512_SRI: &str =
        "sha512-NUGETPATCHEDcontenthashbase64NUGETPATCHEDcontenthashAA==";
    const PATCHED_CONTENT_HASH: &str = "NUGETPATCHEDcontenthashbase64NUGETPATCHEDcontenthashAA==";
    const UPSTREAM_CONTENT_HASH: &str = "UPSTREAMnugetHASHupstream==";
    let index_url = format!("http://patch.test/patch-registry/nuget/{TOKEN}/{UUID}/index.json");
    let url = format!(
        "http://patch.test/patch-registry/nuget/{TOKEN}/{UUID}/flat/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
    );

    let server = MockServer::start().await;
    mock_view(&server, UUID, PURL).await;
    // Reference-response shape: the nuget packages-lock golden fixture
    // (socket-patch-core/tests/fixtures/redirect/nuget/packages-lock/basic).
    mock_reference(
        &server,
        UUID,
        PURL,
        &url,
        serde_json::json!({ "sha512": PATCHED_SHA512_SRI }),
        serde_json::json!({
            "kind": "nuget-v3",
            "indexUrl": index_url,
            "identifiers": {
                "name": "Newtonsoft.Json",
                "version": "13.0.3",
                "nugetIdLower": "newtonsoft.json",
                "nugetVersionNorm": "13.0.3",
            }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("nuget.config"),
        r#"<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
"#,
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("packages.lock.json"),
        format!(
            r#"{{
  "version": 1,
  "dependencies": {{
    "net6.0": {{
      "Newtonsoft.Json": {{
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "{UPSTREAM_CONTENT_HASH}"
      }}
    }}
  }}
}}
"#
        ),
    )
    .unwrap();

    let code =
        socket_patch_cli::commands::get::run(get_hosted_args(UUID, tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "get <uuid> --mode hosted (nuget) should succeed");

    let config = std::fs::read_to_string(tmp.path().join("nuget.config")).unwrap();
    assert!(
        config.contains(&format!(
            r#"<add key="socket-patch-{UUID}" value="{index_url}" />"#
        )),
        "the Socket package source must be added; got:\n{config}"
    );
    assert!(
        config.contains(&format!(r#"<packageSource key="socket-patch-{UUID}">"#))
            && config.contains(r#"<package pattern="Newtonsoft.Json" />"#),
        "the mapping must route ONLY the patched id to the Socket source; got:\n{config}"
    );
    assert!(
        config.contains(r#"<packageSource key="nuget.org">"#)
            && config.contains(r#"<package pattern="*" />"#),
        "the pre-existing source needs a `*` fallback mapping or every other \
         package NU1100s; got:\n{config}"
    );

    let lock = std::fs::read_to_string(tmp.path().join("packages.lock.json")).unwrap();
    assert!(
        lock.contains(PATCHED_CONTENT_HASH),
        "contentHash must be the patched sha512 (SRI prefix stripped); got:\n{lock}"
    );
    assert!(
        !lock.contains(UPSTREAM_CONTENT_HASH),
        "the upstream contentHash must be replaced; got:\n{lock}"
    );
    assert!(
        lock.contains(r#""resolved": "13.0.3""#),
        "the resolved version stays the normalized 13.0.3; got:\n{lock}"
    );

    let ledger = read_ledger(tmp.path());
    assert_eq!(ledger["records"][PURL]["uuid"], UUID);
    assert_no_manifest_no_blobs(tmp.path());

    let bodies = reference_bodies(&server).await;
    assert_eq!(bodies.len(), 1, "exactly one reference request");
    assert!(bodies[0].contains(UUID));
}

// ---------------------------------------------------------------------------
// composer — composer.lock (rewrite_composer_lock)
// ---------------------------------------------------------------------------

/// A PHP project whose composer.lock spells URLs with the `\/`-escaped
/// slashes older composer wrote: the grant must repoint the target entry's
/// dist block at the hosted zip (written raw — `artifact_url_present` accepts
/// either spelling, so the confirmation probe still counts it) and pin the
/// patched sha1 shasum, leaving the bystander package's escaped dist intact.
#[tokio::test]
#[serial]
async fn composer_lock_hosted_repoints_dist_minding_escaped_slashes() {
    const UUID: &str = "d4d4d4d4-d4d4-4d4d-8d4d-d4d4d4d4d4d4";
    const PURL: &str = "pkg:composer/monolog/monolog@3.5.0";
    const SHA1: &str = "abcdef0123456789abcdef0123456789abcdef01";
    let url = format!(
        "http://patch.test/patch/composer/monolog/monolog/3.5.0/{TOKEN}/{UUID}/monolog-3.5.0.zip"
    );

    let server = MockServer::start().await;
    mock_view(&server, UUID, PURL).await;
    // Reference-response shape: the composer golden fixture (dist.shasum
    // rides integrity.sha1; no registryOverride for composer).
    mock_reference(
        &server,
        UUID,
        PURL,
        &url,
        serde_json::json!({ "sha1": SHA1 }),
        serde_json::Value::Null,
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    // `\/`-escaped dist URLs, 4-space indent, `"key": "value"` spacing — the
    // exact shape composer writes (mirrors the escaped-slash-lock golden
    // fixture).
    std::fs::write(
        tmp.path().join("composer.lock"),
        r#"{
    "_readme": [
        "This file locks the dependencies of your project to a known state"
    ],
    "content-hash": "abc123def456abc123def456abc1",
    "packages": [
        {
            "name": "monolog/monolog",
            "version": "3.5.0",
            "dist": {
                "type": "zip",
                "url": "https:\/\/api.github.com\/repos\/Seldaek\/monolog\/zipball\/abc123",
                "reference": "abc123def456",
                "shasum": ""
            }
        },
        {
            "name": "psr/log",
            "version": "1.1.4",
            "dist": {
                "type": "zip",
                "url": "https:\/\/api.github.com\/repos\/php-fig\/log\/zipball\/d49695b909c3b7628b6289db5479a1c204601f11",
                "reference": "d49695b909c3b7628b6289db5479a1c204601f11",
                "shasum": ""
            }
        }
    ],
    "packages-dev": []
}
"#,
    )
    .unwrap();

    let code =
        socket_patch_cli::commands::get::run(get_hosted_args(UUID, tmp.path(), server.uri())).await;
    assert_eq!(
        code, 0,
        "get <uuid> --mode hosted (composer) should succeed"
    );

    let lock = std::fs::read_to_string(tmp.path().join("composer.lock")).unwrap();
    assert!(
        lock.contains(&format!(r#""url": "{url}""#)),
        "the dist url must point at the hosted zip (raw slashes); got:\n{lock}"
    );
    assert!(
        lock.contains(&format!(r#""shasum": "{SHA1}""#)),
        "the dist shasum must pin the patched artifact; got:\n{lock}"
    );
    assert!(
        !lock.contains("Seldaek"),
        "the upstream zipball url must be replaced (either slash spelling); got:\n{lock}"
    );
    assert!(
        lock.contains(r"https:\/\/api.github.com\/repos\/php-fig\/log\/zipball\/"),
        "the bystander package's escaped dist must stay byte-identical; got:\n{lock}"
    );

    let ledger = read_ledger(tmp.path());
    assert_eq!(ledger["records"][PURL]["uuid"], UUID);
    assert_no_manifest_no_blobs(tmp.path());

    let bodies = reference_bodies(&server).await;
    assert_eq!(bodies.len(), 1, "exactly one reference request");
    assert!(bodies[0].contains(UUID));
}

// ---------------------------------------------------------------------------
// deno — negative: no rewriter, a grant must land NOTHING
// ---------------------------------------------------------------------------

/// No redirect rewriter edits deno's integrity entries today, and deno.lock
/// is deliberately absent from scan/hosted.rs's REDIRECT_CANDIDATE_FILES. A
/// GRANTED reference for a deno-ecosystem purl must therefore land nothing:
/// deno.lock byte-identical, no ledger (no record to attest — the patch is
/// NOT pinned anywhere), no manifest, and a calm exit 0 (skipped grants and
/// rewriter no-ops never flip the hosted exit). Covered for both purl
/// spellings: `pkg:jsr/` (deno's real purl type — see
/// crawlers/types.rs::test_from_purl_deno_jsr) and a defensive `pkg:deno/`.
#[tokio::test]
#[serial]
async fn deno_hosted_grant_lands_nothing() {
    const DENO_LOCK: &str = r#"{
  "version": "4",
  "specifiers": {
    "jsr:@std/path@0.220.0": "0.220.0"
  }
}
"#;
    for (uuid, purl) in [
        (
            "e5e5e5e5-e5e5-4e5e-8e5e-e5e5e5e5e5e5",
            "pkg:jsr/@std/path@0.220.0",
        ),
        (
            "f6f6f6f6-f6f6-4f6f-8f6f-f6f6f6f6f6f6",
            "pkg:deno/std-path@0.220.0",
        ),
    ] {
        let server = MockServer::start().await;
        mock_view(&server, uuid, purl).await;
        let url = format!(
            "http://patch.test/patch/deno/std-path/0.220.0/{TOKEN}/{uuid}/std-path-0.220.0.tgz"
        );
        mock_reference(
            &server,
            uuid,
            purl,
            &url,
            serde_json::json!({ "sha512": "sha512-DENOpatchedDENOpatched==" }),
            serde_json::Value::Null,
        )
        .await;

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("deno.lock"), DENO_LOCK).unwrap();

        let code =
            socket_patch_cli::commands::get::run(get_hosted_args(uuid, tmp.path(), server.uri()))
                .await;
        assert_eq!(code, 0, "{purl}: an unredirectable grant is a calm exit 0");

        assert_eq!(
            std::fs::read_to_string(tmp.path().join("deno.lock")).unwrap(),
            DENO_LOCK,
            "{purl}: deno.lock must stay byte-identical"
        );
        assert!(
            !tmp.path().join(".socket").exists(),
            "{purl}: nothing may be persisted — no ledger record (the patch \
             is not pinned anywhere, so recording it would attest a no-op), \
             no manifest, no blobs"
        );

        // Anti-vacuity: the engine really ran the grant flow — the reference
        // endpoint was asked for exactly this uuid; it just had nothing to
        // rewrite.
        let bodies = reference_bodies(&server).await;
        assert_eq!(bodies.len(), 1, "{purl}: exactly one reference request");
        assert!(bodies[0].contains(uuid), "{purl}: grant asked for the uuid");
    }
}
