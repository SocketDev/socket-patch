//! `get` must forward its API-client flags into the nested `apply` step.
//!
//! `get` drives `apply` in-process (`get.rs::run_nested_apply`). That step
//! builds its OWN `ApiClient` from the `GlobalArgs` it is handed
//! (`apply.rs` → `fetch_stage::stage_patch_sources` →
//! `get_api_client_with_overrides(common.api_client_overrides())`), so any
//! `--api-url` / `--api-token` / `--org` / `--proxy-url` the caller passed on
//! the COMMAND LINE has to be threaded through. Regression guard: the nested
//! `ApplyArgs` was built from `GlobalArgs::default()`, whose api fields are
//! all `None` — the nested apply silently fell back to env-var / config /
//! built-in-default resolution and never saw the user's flags.
//!
//! Reachable whenever the patch view does not embed `blobContent` for every
//! file (the manifest records the hashes; the bytes are fetched on demand):
//! `get` writes no blob, and the nested apply has to download it. Both `get`
//! call sites are covered — the direct-UUID path (`save_and_apply_patch`) and
//! the search path (`download_and_apply_patches`).
//!
//! Hermetic by construction: the *env* API/proxy URLs point at a dead local
//! port, so a run that ignores the flags fails on a refused connection rather
//! than reaching the real socket.dev.

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/mod.rs"]
mod common;

const ORG: &str = "test-org";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const PKG: &str = "nested-api-pkg";
const PURL: &str = "pkg:npm/nested-api-pkg@1.0.0";
const PURL_ENCODED: &str = "pkg%3Anpm%2Fnested-api-pkg%401.0.0";
const BEFORE: &[u8] = b"before\n";
const AFTER: &[u8] = b"patched\n";

/// A dead local port. Whatever the nested apply resolves from the ENV must
/// not be reachable — that is what makes "the flags were ignored" show up as
/// a failure instead of a silent success against the same mock.
const DEAD_URL: &str = "http://127.0.0.1:1";

fn install_npm_package(root: &std::path::Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"nested-apply-root","version":"0.0.0","private":true}"#,
    )
    .expect("write root package.json");
    let pkg_dir = root.join("node_modules").join(PKG);
    std::fs::create_dir_all(&pkg_dir).expect("create pkg dir");
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(r#"{{"name":"{PKG}","version":"1.0.0"}}"#),
    )
    .expect("write pkg package.json");
    std::fs::write(pkg_dir.join("index.js"), BEFORE).expect("write pkg file");
}

/// Mount the patch view WITHOUT `blobContent`: the manifest gets the
/// before/after hashes, but the patched bytes are only obtainable from the
/// blob endpoint — i.e. by the nested apply's own API client.
async fn mount_view_without_blob(mock: &MockServer, before_hash: &str, after_hash: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash,
                    "afterHash": after_hash,
                }
            },
            "vulnerabilities": {},
            "description": "nested-apply api-flag fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(mock)
        .await;
}

async fn mount_blob(mock: &MockServer, after_hash: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/blob/{after_hash}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(AFTER.to_vec()))
        .mount(mock)
        .await;
}

async fn mount_search(mock: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG}/patches/by-package/{PURL_ENCODED}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID,
                "purl": PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "nested-apply api-flag fixture",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {},
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
}

/// Env that pins every ambient API source at a dead port, so the ONLY
/// working route to the mock is the flags the test passes on the argv.
///
/// `SOCKET_API_TOKEN` is deliberately ABSENT (`common::run_with_env` scrubs
/// the whole `SOCKET_*` surface first, and this list does not add it back):
/// the token is the discriminator. A nested client that never sees
/// `--api-token` takes the token-less public-proxy branch and resolves its
/// base from `SOCKET_PROXY_URL` — the dead port — no matter what any other
/// layer does with the URL.
fn dead_env<'a>() -> Vec<(&'a str, &'a str)> {
    vec![
        ("SOCKET_API_URL", DEAD_URL),
        ("SOCKET_PROXY_URL", DEAD_URL),
        // Pin the slug: an unset one triggers an org auto-resolve
        // round-trip, which is not what this test is about.
        ("SOCKET_ORG_SLUG", ORG),
    ]
}

async fn assert_blob_was_fetched(mock: &MockServer, after_hash: &str) {
    let requests = mock
        .received_requests()
        .await
        .expect("wiremock records requests");
    let want = format!("/v0/orgs/{ORG}/patches/blob/{after_hash}");
    assert!(
        requests.iter().any(|r| r.url.path() == want),
        "the nested apply must fetch the missing blob through the CLI-flag API client; \
         got requests={:?}",
        requests
            .iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn get_by_uuid_nested_apply_uses_api_flags_not_env() {
    let before_hash = common::git_sha256(BEFORE);
    let after_hash = common::git_sha256(AFTER);

    let mock = MockServer::start().await;
    mount_view_without_blob(&mock, &before_hash, &after_hash).await;
    mount_blob(&mock, &after_hash).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    install_npm_package(tmp.path());

    let uri = mock.uri();
    let (code, stdout, stderr) = common::run_with_env(
        tmp.path(),
        &[
            "get",
            UUID,
            "--yes",
            "--json",
            // `file` mode goes straight for the per-file blob endpoint; the
            // point here is which CLIENT does the fetch, not which artifact.
            "--download-mode",
            "file",
            "--api-url",
            &uri,
            "--api-token",
            "flag-token",
            "--org",
            ORG,
        ],
        &dead_env(),
    );

    assert_eq!(
        code, 0,
        "get must apply the patch through the flag-configured client; \
         stdout={stdout}\nstderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("valid JSON expected: {e}\nstdout={stdout}"));
    assert_eq!(v["status"], "success", "stdout={stdout}");
    assert_eq!(v["applied"], 1, "stdout={stdout}");

    let patched = tmp.path().join("node_modules").join(PKG).join("index.js");
    assert_eq!(
        std::fs::read(&patched).expect("read patched file"),
        AFTER,
        "the installed file must carry the patched bytes"
    );
    assert_blob_was_fetched(&mock, &after_hash).await;
}

#[tokio::test]
async fn get_by_purl_nested_apply_uses_api_flags_not_env() {
    let before_hash = common::git_sha256(BEFORE);
    let after_hash = common::git_sha256(AFTER);

    let mock = MockServer::start().await;
    mount_search(&mock).await;
    mount_view_without_blob(&mock, &before_hash, &after_hash).await;
    mount_blob(&mock, &after_hash).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    install_npm_package(tmp.path());

    let uri = mock.uri();
    let (code, stdout, stderr) = common::run_with_env(
        tmp.path(),
        &[
            "get",
            PURL,
            "--yes",
            "--json",
            "--download-mode",
            "file",
            "--api-url",
            &uri,
            "--api-token",
            "flag-token",
            "--org",
            ORG,
        ],
        &dead_env(),
    );

    assert_eq!(
        code, 0,
        "the search path's nested apply must also use the flag-configured client; \
         stdout={stdout}\nstderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("valid JSON expected: {e}\nstdout={stdout}"));
    assert_eq!(v["status"], "success", "stdout={stdout}");
    assert_eq!(v["applied"], 1, "stdout={stdout}");

    let patched = tmp.path().join("node_modules").join(PKG).join("index.js");
    assert_eq!(
        std::fs::read(&patched).expect("read patched file"),
        AFTER,
        "the installed file must carry the patched bytes"
    );
    assert_blob_was_fetched(&mock, &after_hash).await;
}

/// Token-less public-proxy leg: with no `--api-token` anywhere, a flag-only
/// `--proxy-url` is the ONLY route to patches — the client consults
/// `proxy_url` exclusively on its token-less branch, so the two
/// authenticated legs above stay green even if `run_nested_apply` drops the
/// `proxy_url` field. This leg goes red for exactly that regression: the
/// nested apply's blob fetch must hit the flag proxy, not the dead env one.
#[tokio::test]
async fn get_by_uuid_nested_apply_uses_proxy_url_flag_when_tokenless() {
    let before_hash = common::git_sha256(BEFORE);
    let after_hash = common::git_sha256(AFTER);

    let mock = MockServer::start().await;
    // Proxy-shaped endpoints: no org scope.
    Mock::given(method("GET"))
        .and(path(format!("/patch/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash,
                    "afterHash": after_hash,
                }
            },
            "vulnerabilities": {},
            "description": "nested-apply proxy-flag fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/patch/blob/{after_hash}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(AFTER.to_vec()))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    install_npm_package(tmp.path());

    let uri = mock.uri();
    let (code, stdout, stderr) = common::run_with_env(
        tmp.path(),
        &[
            "get",
            UUID,
            "--yes",
            "--json",
            "--download-mode",
            "file",
            "--proxy-url",
            &uri,
        ],
        &dead_env(),
    );

    assert_eq!(
        code, 0,
        "token-less get must reach the flag proxy end to end; \
         stdout={stdout}\nstderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("valid JSON expected: {e}\nstdout={stdout}"));
    assert_eq!(v["status"], "success", "stdout={stdout}");

    let requests = mock
        .received_requests()
        .await
        .expect("wiremock records requests");
    let want = format!("/patch/blob/{after_hash}");
    assert!(
        requests.iter().any(|r| r.url.path() == want),
        "the nested apply's blob fetch must ride the --proxy-url flag \
         (token-less branch); got requests={:?}",
        requests
            .iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
}
