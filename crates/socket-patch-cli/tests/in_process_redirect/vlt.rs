//! Hosted vlt legs (DESIGN §3, §8.2): the rewrite through the CLI, the
//! artifact preflight, the warm-tree heal with its advisory, and the in-run
//! VEX exclusion. Every run is the scrubbed subprocess binary, so the
//! `--json` envelope is read back and no parent env is mutated.

use std::path::Path;

use serde_json::Value;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::vlt_hosted_common::*;

fn ledger(root: &Path) -> Value {
    serde_json::from_str(&read(root, ".socket/vendor/redirect-state.json")).unwrap()
}

fn vlt_edit_keys(root: &Path) -> Vec<String> {
    ledger(root)["edits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["kind"] == "redirect_vlt_lock_node")
        .map(|e| e["key"].as_str().unwrap().to_string())
        .collect()
}

fn skipped_reasons(doc: &Value) -> Vec<String> {
    doc["redirect"]["skipped"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["reason"].as_str().map(str::to_string))
        .collect()
}

fn lock_with(era: Era, nodes: &[String]) -> String {
    vlt_lock(era, nodes)
}

async fn assert_rewrites(era: Era, expected_warnings: &[&str]) {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), era);

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert_eq!(redirected(&doc), 1, "{doc:#}");
    assert_eq!(
        read(tmp.path(), "vlt-lock.json"),
        lock_with(era, &[pinned_node(era.dep_id(), &server)])
    );
    assert_eq!(
        doc["redirect"]["rewrittenFiles"],
        serde_json::json!(["vlt-lock.json"])
    );
    assert_eq!(warning_codes(&doc), expected_warnings, "{doc:#}");
    assert_eq!(warning_detail(&doc, ADVISORY), ADVISORY_NOTHING_STALE);
    assert_eq!(vlt_edit_keys(tmp.path()), ["left-pad@1.3.0"]);
    assert!(ledger(tmp.path())["records"][PURL].is_object());
    assert_eq!(artifact_requests(&server).await, 1);
}

#[tokio::test]
async fn scan_redirect_rewrites_vlt_lock_v1() {
    assert_rewrites(Era::V1, &[ADVISORY]).await;
}

#[tokio::test]
async fn scan_redirect_rewrites_vlt_lock_v0() {
    assert_rewrites(Era::V0, &[ADVISORY]).await;
}

#[tokio::test]
async fn scan_redirect_rewrites_vlt_lock_a0() {
    assert_rewrites(
        Era::A0,
        &[
            "redirect_vlt_lockfile_version_missing",
            "redirect_vlt_old_lockfile_ignored",
            ADVISORY,
        ],
    )
    .await;
}

#[tokio::test]
async fn scan_redirect_refuses_vlt_lock_v2() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    let v2 = read(tmp.path(), "vlt-lock.json")
        .replace("\"lockfileVersion\": 1", "\"lockfileVersion\": 2");
    std::fs::write(tmp.path().join("vlt-lock.json"), &v2).unwrap();

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert_eq!(redirected(&doc), 0);
    assert_eq!(warning_codes(&doc), ["redirect_vlt_lock_unsupported"]);
    assert_eq!(read(tmp.path(), "vlt-lock.json"), v2);
    assert_eq!(artifact_requests(&server).await, 0);
    assert!(!ledger_path(tmp.path()).exists());
}

#[tokio::test]
async fn scan_redirect_vlt_rerun_noop_keeps_ledger() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    scan_hosted(tmp.path(), &server, &[], &[]);
    let lock = read(tmp.path(), "vlt-lock.json");
    let ledger_bytes = read(tmp.path(), ".socket/vendor/redirect-state.json");

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert_eq!(
        redirected(&doc),
        1,
        "a pinned lock stays confirmed: {doc:#}"
    );
    assert_eq!(read(tmp.path(), "vlt-lock.json"), lock);
    assert_eq!(
        read(tmp.path(), ".socket/vendor/redirect-state.json"),
        ledger_bytes
    );
    assert_eq!(vlt_edit_keys(tmp.path()), ["left-pad@1.3.0"]);
}

#[tokio::test]
async fn scan_redirect_vlt_crlf() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    let other = "\"~npm~ms@2.1.3\": [0,\"ms\"]".to_string();
    let crlf = lock_with(Era::V1, &[registry_node(TILDE_ID), other.clone()]).replace('\n', "\r\n");
    std::fs::write(tmp.path().join("vlt-lock.json"), &crlf).unwrap();

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert_eq!(redirected(&doc), 1);
    assert_eq!(
        read(tmp.path(), "vlt-lock.json"),
        lock_with(Era::V1, &[pinned_node(TILDE_ID, &server), other]).replace('\n', "\r\n")
    );
    let original = ledger(tmp.path())["edits"][0]["original"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        !original.contains('\r') && !original.ends_with(','),
        "{original:?}"
    );
}

#[tokio::test]
async fn scan_redirect_vlt_peer_instances() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    let peer = "~npm~left-pad@1.3.0~peer.2";
    std::fs::write(
        tmp.path().join("vlt-lock.json"),
        lock_with(Era::V1, &[registry_node(TILDE_ID), registry_node(peer)]),
    )
    .unwrap();

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert_eq!(redirected(&doc), 1);
    assert_eq!(
        read(tmp.path(), "vlt-lock.json"),
        lock_with(
            Era::V1,
            &[pinned_node(TILDE_ID, &server), pinned_node(peer, &server)]
        )
    );
    assert_eq!(
        vlt_edit_keys(tmp.path()),
        ["left-pad@1.3.0", "left-pad@1.3.0~peer.2"]
    );
    assert_eq!(
        artifact_requests(&server).await,
        1,
        "one GET per distinct artifact URL"
    );
}

#[tokio::test]
async fn scan_redirect_vlt_sibling_package_lock_ambiguous() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    std::fs::write(tmp.path().join("package-lock.json"), package_lock()).unwrap();

    let (_, doc) = scan_hosted(tmp.path(), &server, &["--no-npm-allow-remote-config"], &[]);

    assert_eq!(redirected(&doc), 1);
    assert!(warning_codes(&doc).contains(&"redirect_vlt_sibling_lockfiles".to_string()));
    assert!(read(tmp.path(), "package-lock.json").contains(&artifact_url(&server)));
    assert_eq!(
        read(tmp.path(), "vlt-lock.json"),
        lock_with(Era::V1, &[pinned_node(TILDE_ID, &server)])
    );
}

#[tokio::test]
async fn scan_redirect_vlt_sibling_package_lock_vlt_installed_does_not_confirm_refused() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    std::fs::write(tmp.path().join("package-lock.json"), package_lock()).unwrap();
    let off_grammar =
        format!("\"{TILDE_ID}\": [0, \"{NAME}\", \"{UPSTREAM_SHA512}\", \"{REGISTRY_URL}\"]");
    let lock = lock_with(
        Era::V1,
        &["\"~npm~ms@2.1.3\": [0,\"ms\"]".to_string(), off_grammar],
    );
    std::fs::write(tmp.path().join("vlt-lock.json"), &lock).unwrap();
    write_hidden_lock(tmp.path(), &[]);

    let (_, doc) = scan_hosted(tmp.path(), &server, &["--no-npm-allow-remote-config"], &[]);

    assert_eq!(
        redirected(&doc),
        0,
        "vlt drives and refused the dep: the package-lock rewrite confirms nothing: {doc:#}"
    );
    assert!(warning_codes(&doc).contains(&"redirect_vlt_unsupported_lock_key".to_string()));
    assert_eq!(read(tmp.path(), "vlt-lock.json"), lock);
    assert!(!ledger_path(tmp.path()).exists() || ledger(tmp.path())["records"][PURL].is_null());
}

// ── artifact preflight ───────────────────────────────────────────────────

async fn assert_preflight_refuses(response: ResponseTemplate, reason: &str) {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    mock_artifact_with(&server, response).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    let lock = read(tmp.path(), "vlt-lock.json");

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert_eq!(redirected(&doc), 0, "{doc:#}");
    assert_eq!(read(tmp.path(), "vlt-lock.json"), lock);
    assert!(!ledger_path(tmp.path()).exists(), "nothing is written");
    assert_eq!(
        warning_detail(&doc, UNVERIFIABLE),
        format!(
            "vlt would fail to verify {}: {reason}; nothing was written for {PURL}",
            artifact_url(&server)
        )
    );
    assert_eq!(skipped_reasons(&doc), [UNVERIFIABLE]);
    assert!(!warning_codes(&doc).contains(&ADVISORY.to_string()));
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_content_encoding_refused() {
    assert_preflight_refuses(
        ResponseTemplate::new(200)
            .insert_header("content-encoding", "gzip")
            .set_body_bytes(gzip(&patched_tarball())),
        "content-encoding gzip",
    )
    .await;
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_identity_passes() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    mock_artifact_with(
        &server,
        ResponseTemplate::new(200)
            .insert_header("content-encoding", "identity")
            .set_body_bytes(patched_tarball()),
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert_eq!(redirected(&doc), 1);
    assert!(!warning_codes(&doc).contains(&UNVERIFIABLE.to_string()));
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_sha512_mismatch() {
    assert_preflight_refuses(
        ResponseTemplate::new(200).set_body_bytes(b"other bytes".to_vec()),
        "sha512 mismatch",
    )
    .await;
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_http_404() {
    assert_preflight_refuses(ResponseTemplate::new(404), "http 404").await;
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_http_500() {
    assert_preflight_refuses(ResponseTemplate::new(500), "http 500").await;
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_fetch_error() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    let url = format!("http://127.0.0.1:9{}", artifact_path());
    mock_reference_at(&server, &url, &sha512_sri(&patched_tarball())).await;
    mock_view(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    let lock = read(tmp.path(), "vlt-lock.json");

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert_eq!(redirected(&doc), 0);
    assert_eq!(read(tmp.path(), "vlt-lock.json"), lock);
    let detail = warning_detail(&doc, UNVERIFIABLE);
    assert!(
        detail.starts_with(&format!("vlt would fail to verify {url}: fetch error "))
            && detail.ends_with(&format!("; nothing was written for {PURL}")),
        "{detail}"
    );
}

async fn redirect_chain(hops: usize) -> (Value, tempfile::TempDir) {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_view(&server).await;
    for hop in 0..hops {
        Mock::given(method("GET"))
            .and(path(format!("/hop/{hop}")))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/hop/{}", server.uri(), hop + 1)),
            )
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(format!("/hop/{hops}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(patched_tarball()))
        .mount(&server)
        .await;
    mock_reference_at(
        &server,
        &format!("{}/hop/0", server.uri()),
        &sha512_sri(&patched_tarball()),
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);
    (doc, tmp)
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_redirect_chain_10_passes() {
    let (doc, _tmp) = redirect_chain(10).await;
    assert_eq!(redirected(&doc), 1, "{doc:#}");
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_redirect_chain_11_fails() {
    let (doc, _tmp) = redirect_chain(11).await;
    assert_eq!(redirected(&doc), 0);
    assert!(warning_detail(&doc, UNVERIFIABLE).contains(": fetch error "));
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_one_get_per_distinct_url() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    let ids = [
        TILDE_ID,
        "~npm~left-pad@1.3.0~peer.2",
        "~npm~left-pad@1.3.0~peer.3",
    ];
    let nodes: Vec<String> = ids.iter().map(|id| registry_node(id)).collect();
    std::fs::write(tmp.path().join("vlt-lock.json"), lock_with(Era::V1, &nodes)).unwrap();

    let (_, doc) = scan_hosted(tmp.path(), &server, &["--dry-run"], &[]);
    assert_eq!(redirected(&doc), 1);
    assert_eq!(artifact_requests(&server).await, 1);
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_dry_run_still_preflights_writes_nothing() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_artifact_with(
        &server,
        ResponseTemplate::new(200)
            .insert_header("content-encoding", "gzip")
            .set_body_bytes(gzip(&patched_tarball())),
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    let lock = read(tmp.path(), "vlt-lock.json");

    let (_, doc) = scan_hosted(tmp.path(), &server, &["--dry-run"], &[]);

    assert_eq!(artifact_requests(&server).await, 1);
    assert_eq!(redirected(&doc), 0);
    assert!(warning_codes(&doc).contains(&UNVERIFIABLE.to_string()));
    assert_eq!(read(tmp.path(), "vlt-lock.json"), lock);
    assert!(!tmp.path().join(".socket").exists());
}

async fn gzip_artifact_server() -> MockServer {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    mock_artifact_with(
        &server,
        ResponseTemplate::new(200)
            .insert_header("content-encoding", "gzip")
            .set_body_bytes(gzip(&patched_tarball())),
    )
    .await;
    server
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_failed_dep_withheld_from_every_rewriter() {
    let server = gzip_artifact_server().await;
    let tmp = tempfile::tempdir().unwrap();
    write_installed_vlt_project(tmp.path(), PRISTINE);
    std::fs::write(tmp.path().join("package-lock.json"), package_lock()).unwrap();

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert_eq!(redirected(&doc), 0);
    assert_eq!(read(tmp.path(), "package-lock.json"), package_lock());
    assert_eq!(
        read(tmp.path(), "vlt-lock.json"),
        lock_with(Era::V1, &[registry_node(TILDE_ID)])
    );
    assert!(store_dir(tmp.path(), TILDE_ID).exists());
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_ambiguous_withholds_vlt_only() {
    let server = gzip_artifact_server().await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    std::fs::write(tmp.path().join("package-lock.json"), package_lock()).unwrap();

    let (_, doc) = scan_hosted(tmp.path(), &server, &["--no-npm-allow-remote-config"], &[]);

    assert_eq!(
        redirected(&doc),
        1,
        "package-lock.json still confirms: {doc:#}"
    );
    assert!(read(tmp.path(), "package-lock.json").contains(&artifact_url(&server)));
    assert_eq!(
        read(tmp.path(), "vlt-lock.json"),
        lock_with(Era::V1, &[registry_node(TILDE_ID)])
    );
    assert_eq!(
        warning_detail(&doc, UNVERIFIABLE),
        format!(
            "vlt would fail to verify {}: content-encoding gzip; vlt-lock.json was not changed \
             for {PURL}",
            artifact_url(&server)
        )
    );
    assert!(skipped_reasons(&doc).is_empty(), "{doc:#}");
}

/// A package-lock.json that lists only the root: the npm rewriter has
/// nothing to pin.
fn package_lock_without_dep() -> String {
    r#"{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "consumer", "version": "0.0.0" }
  }
}
"#
    .to_string()
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_ambiguous_earlier_pin_is_not_confirmed() {
    let server = gzip_artifact_server().await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    let pinned = lock_with(Era::V1, &[pinned_node(TILDE_ID, &server)]);
    std::fs::write(tmp.path().join("vlt-lock.json"), &pinned).unwrap();
    std::fs::write(
        tmp.path().join("package-lock.json"),
        package_lock_without_dep(),
    )
    .unwrap();

    let (_, doc) = scan_hosted(tmp.path(), &server, &["--no-npm-allow-remote-config"], &[]);

    assert_eq!(
        redirected(&doc),
        0,
        "the earlier run's vlt pin alone confirms nothing: {doc:#}"
    );
    assert_eq!(read(tmp.path(), "vlt-lock.json"), pinned);
    assert_eq!(
        warning_detail(&doc, UNVERIFIABLE),
        format!(
            "vlt would fail to verify {}: content-encoding gzip; {PURL} was left pinned by an \
             earlier run and `vlt ci` will fail until the artifact verifies",
            artifact_url(&server)
        )
    );
}

/// A real `node_modules/.vlt` store with no hidden lock (0.0.0-1 and
/// 0.0.0-32 write none) is vlt's install state too: vlt drives beside a
/// package-lock.json, so there is no sibling warning and a failed preflight
/// withholds the dep from every rewriter.
#[tokio::test]
async fn scan_redirect_vlt_store_dir_without_hidden_lock_drives() {
    let server = gzip_artifact_server().await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    install_store(tmp.path(), TILDE_ID, PRISTINE);
    std::fs::write(tmp.path().join("package-lock.json"), package_lock()).unwrap();

    let (_, doc) = scan_hosted(tmp.path(), &server, &["--no-npm-allow-remote-config"], &[]);

    assert_eq!(redirected(&doc), 0, "{doc:#}");
    assert!(
        !warning_codes(&doc).contains(&"redirect_vlt_sibling_lockfiles".to_string()),
        "{doc:#}"
    );
    assert_eq!(skipped_reasons(&doc), [UNVERIFIABLE]);
    assert_eq!(read(tmp.path(), "package-lock.json"), package_lock());
    assert_eq!(
        warning_detail(&doc, UNVERIFIABLE),
        format!(
            "vlt would fail to verify {}: content-encoding gzip; nothing was written for {PURL}",
            artifact_url(&server)
        )
    );
}

/// When vlt drives, only the vlt rewriter confirms an npm purl: a
/// package-lock.json rewrite that carries the hosted URL does not, when
/// vlt-lock.json has no default-registry node for the dep.
#[tokio::test]
async fn scan_redirect_vlt_drives_entry_not_found_sibling_rewrite_does_not_confirm() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_package_json(tmp.path());
    install_importer(tmp.path(), PRISTINE);
    std::fs::write(
        tmp.path().join("vlt-lock.json"),
        lock_with(Era::V1, &["\"~npm~ms@2.1.3\": [0,\"ms\"]".to_string()]),
    )
    .unwrap();
    write_hidden_lock(tmp.path(), &[]);
    std::fs::write(tmp.path().join("package-lock.json"), package_lock()).unwrap();

    let (_, doc, attested) = scan_with_vex(tmp.path(), &server, &["--no-npm-allow-remote-config"]);

    assert!(
        warning_codes(&doc).contains(&"redirect_vlt_entry_not_found".to_string()),
        "{doc:#}"
    );
    assert!(read(tmp.path(), "package-lock.json").contains(&artifact_url(&server)));
    assert_eq!(redirected(&doc), 0, "{doc:#}");
    assert!(!attested, "{doc:#}");
    assert_eq!(artifact_requests(&server).await, 0);
}

const VENDORED_UUID: &str = "11111111-2222-4333-8444-555555555555";

/// A vlt project whose left-pad is vendored (§3.4 D19 dir node) and
/// claimed by a `flavor: "vlt"` vendored ledger entry.
fn write_vlt_vendored_project(root: &Path) -> (String, Vec<u8>) {
    write_package_json(root);
    install_importer(root, PATCHED);
    let dir = format!(".socket/vendor/npm/{VENDORED_UUID}/{NAME}-{VERSION}/node_modules/{NAME}");
    let lock = lock_with(
        Era::V1,
        &[format!(
            "\"file~.socket+vendor+npm+{VENDORED_UUID}+{NAME}-{VERSION}+node__modules+{NAME}\": \
             [0,\"{NAME}\",null,\"{dir}\"]"
        )],
    );
    std::fs::write(root.join("vlt-lock.json"), &lock).unwrap();
    let state = serde_json::json!({
        "version": 1,
        "entries": { PURL: {
            "ecosystem": "npm",
            "basePurl": PURL,
            "uuid": VENDORED_UUID,
            "artifact": { "path": format!(".socket/vendor/npm/{VENDORED_UUID}/{NAME}-{VERSION}") },
            "wiring": [],
            "flavor": "vlt"
        }}
    });
    std::fs::create_dir_all(root.join(".socket/vendor")).unwrap();
    let state = serde_json::to_vec_pretty(&state).unwrap();
    std::fs::write(root.join(".socket/vendor/state.json"), &state).unwrap();
    (lock, state)
}

/// Vendored → hosted (§4.10): the takeover restores the registry node this
/// run pins, so the artifact is probed through the vendored node BEFORE the
/// revert; a failure keeps the package vendored (never reverted), with or
/// without another npm-family lock, wet or dry.
#[tokio::test]
async fn scan_redirect_vlt_vendored_takeover_preflights_before_the_revert() {
    for (sibling, dry_run) in [(false, false), (false, true), (true, false)] {
        let server = gzip_artifact_server().await;
        let tmp = tempfile::tempdir().unwrap();
        let (lock, state) = write_vlt_vendored_project(tmp.path());
        if sibling {
            std::fs::write(tmp.path().join("package-lock.json"), package_lock()).unwrap();
        }
        let mut extra = vec!["--no-npm-allow-remote-config"];
        if dry_run {
            extra.push("--dry-run");
        }

        let (_, doc) = scan_hosted(tmp.path(), &server, &extra, &[]);

        let leg = format!("sibling={sibling} dry_run={dry_run}: {doc:#}");
        assert_eq!(artifact_requests(&server).await, 1, "{leg}");
        assert_eq!(redirected(&doc), 0, "{leg}");
        assert_eq!(skipped_reasons(&doc), [UNVERIFIABLE], "{leg}");
        assert!(
            !warning_codes(&doc)
                .iter()
                .any(|c| c.contains("revert") || c.contains("takeover")),
            "no takeover is attempted: {leg}"
        );
        assert_eq!(read(tmp.path(), "vlt-lock.json"), lock, "{leg}");
        assert_eq!(
            std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap(),
            state,
            "{leg}"
        );
        if sibling {
            assert_eq!(
                read(tmp.path(), "package-lock.json"),
                package_lock(),
                "{leg}"
            );
        }
    }

    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_vendored_project(tmp.path());
    let (_, doc) = scan_hosted(tmp.path(), &server, &["--dry-run"], &[]);
    assert_eq!(
        artifact_requests(&server).await,
        1,
        "a verifying artifact is probed too: {doc:#}"
    );
    assert!(
        !warning_codes(&doc).contains(&UNVERIFIABLE.to_string()),
        "{doc:#}"
    );
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_get_uuid_driver() {
    let server = gzip_artifact_server().await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    let lock = read(tmp.path(), "vlt-lock.json");
    let cwd = tmp.path().to_str().unwrap().to_string();
    let uri = server.uri();

    let (code, doc, stderr) = run_json(
        tmp.path(),
        &[
            "get",
            UUID,
            "--mode",
            "hosted",
            "--yes",
            "--cwd",
            &cwd,
            "--api-url",
            &uri,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        &[],
    );

    assert_eq!(code, 0, "{doc:#}\n{stderr}");
    assert_eq!(artifact_requests(&server).await, 1);
    assert_eq!(redirected(&doc), 0);
    assert!(warning_codes(&doc).contains(&UNVERIFIABLE.to_string()));
    assert_eq!(read(tmp.path(), "vlt-lock.json"), lock);
}

fn pnpm_lock() -> String {
    format!(
        "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      {NAME}:\n        \
         specifier: {VERSION}\n        version: {VERSION}\n\npackages:\n  {NAME}@{VERSION}:\n    \
         resolution: {{integrity: {UPSTREAM_SHA512}}}\n\nsnapshots:\n  {NAME}@{VERSION}: {{}}\n"
    )
}

fn bun_lock() -> String {
    format!(
        "{{\n  \"lockfileVersion\": 1,\n  \"packages\": {{\n    \"{NAME}\": [\"{NAME}@{VERSION}\", \
         \"\", {{}}, \"{UPSTREAM_SHA512}\"],\n  }}\n}}\n"
    )
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_no_preflight_without_vlt_lock() {
    for (lock, text) in [
        ("package-lock.json", package_lock()),
        ("pnpm-lock.yaml", pnpm_lock()),
        ("bun.lock", bun_lock()),
    ] {
        let server = MockServer::start().await;
        mock_all(&server).await;
        let tmp = tempfile::tempdir().unwrap();
        write_package_json(tmp.path());
        install_importer(tmp.path(), PRISTINE);
        std::fs::write(tmp.path().join(lock), text).unwrap();

        let (_, doc) = scan_hosted(tmp.path(), &server, &["--no-npm-allow-remote-config"], &[]);

        assert_eq!(redirected(&doc), 1, "{lock}: {doc:#}");
        assert!(
            read(tmp.path(), lock).contains(&artifact_url(&server)),
            "{lock}"
        );
        assert_eq!(artifact_requests(&server).await, 0, "{lock}");
        assert!(
            !warning_codes(&doc)
                .iter()
                .any(|c| c.starts_with("redirect_vlt_")),
            "{lock}: {doc:#}"
        );
    }
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_proxy_honored() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_view(&server).await;
    mock_artifact(&server).await;
    let url = format!("http://vlt-artifact.invalid{}", artifact_path());
    mock_reference_at(&server, &url, &sha512_sri(&patched_tarball())).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    let proxy = server.uri();

    let (_, doc) = scan_hosted(
        tmp.path(),
        &server,
        &[],
        &[
            ("HTTP_PROXY", proxy.as_str()),
            ("http_proxy", proxy.as_str()),
            ("NO_PROXY", "127.0.0.1,localhost"),
            ("no_proxy", "127.0.0.1,localhost"),
        ],
    );

    assert_eq!(redirected(&doc), 1, "{doc:#}");
    assert_eq!(artifact_requests(&server).await, 1);
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_already_pinned_failure_left_pinned() {
    let server = gzip_artifact_server().await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    let pinned = lock_with(Era::V1, &[pinned_node(TILDE_ID, &server)]);
    std::fs::write(tmp.path().join("vlt-lock.json"), &pinned).unwrap();

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert_eq!(redirected(&doc), 0, "neither confirmed nor attested");
    assert_eq!(
        read(tmp.path(), "vlt-lock.json"),
        pinned,
        "nothing is reverted"
    );
    assert_eq!(
        warning_detail(&doc, UNVERIFIABLE),
        format!(
            "vlt would fail to verify {}: content-encoding gzip; {PURL} was left pinned by an \
             earlier run and `vlt ci` will fail until the artifact verifies",
            artifact_url(&server)
        )
    );
}

#[tokio::test]
async fn scan_redirect_vlt_artifact_no_bearer_on_artifact_request() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);

    scan_hosted(tmp.path(), &server, &[], &[]);

    let requests = server.received_requests().await.unwrap();
    let (artifact, api): (Vec<_>, Vec<_>) = requests
        .iter()
        .partition(|r| r.url.path() == artifact_path());
    assert_eq!(artifact.len(), 1);
    assert!(artifact[0].headers.get("authorization").is_none());
    assert!(api.iter().any(|r| r.headers.get("authorization").is_some()));
}

// ── warm-tree heal ───────────────────────────────────────────────────────

#[tokio::test]
async fn scan_redirect_vlt_warm_tree_invalidates_stale_store() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_installed_vlt_project(tmp.path(), PATCHED);

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert_eq!(redirected(&doc), 1);
    assert!(!store_dir(tmp.path(), TILDE_ID).exists());
    assert!(!tmp.path().join("node_modules/.vlt").join(TILDE_ID).exists());
    assert!(!tmp.path().join("node_modules/.vlt-lock.json").exists());
    assert!(tmp.path().join("node_modules/.vlt").is_dir());
    assert_eq!(warning_detail(&doc, ADVISORY), advisory_invalidated(1));
}

#[tokio::test]
async fn scan_redirect_vlt_heal_rule_b_hidden_lock_without_node() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_installed_vlt_project(tmp.path(), PATCHED);
    write_hidden_lock(tmp.path(), &["\"~npm~ms@2.1.3\": [0,\"ms\"]".to_string()]);

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert!(!store_dir(tmp.path(), TILDE_ID).exists());
    assert_eq!(warning_detail(&doc, ADVISORY), advisory_invalidated(1));
}

#[tokio::test]
async fn scan_redirect_vlt_heal_rule_c_no_hidden_lock_with_record() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_installed_vlt_project(tmp.path(), PRISTINE);
    std::fs::remove_file(tmp.path().join("node_modules/.vlt-lock.json")).unwrap();

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert!(!store_dir(tmp.path(), TILDE_ID).exists());
    assert_eq!(warning_detail(&doc, ADVISORY), advisory_invalidated(1));
}

#[tokio::test]
async fn scan_redirect_vlt_heal_rule_c_no_record_uses_artifact_bytes() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_artifact(&server).await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    write_installed_vlt_project(tmp.path(), PRISTINE);
    std::fs::remove_file(tmp.path().join("node_modules/.vlt-lock.json")).unwrap();
    let healthy = tempfile::tempdir().unwrap();
    write_installed_vlt_project(healthy.path(), PATCHED);
    std::fs::remove_file(healthy.path().join("node_modules/.vlt-lock.json")).unwrap();

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);
    let (_, healthy_doc) = scan_hosted(healthy.path(), &server, &[], &[]);

    assert!(warning_codes(&doc).contains(&"record_fetch_failed".to_string()));
    assert!(!store_dir(tmp.path(), TILDE_ID).exists());
    assert_eq!(warning_detail(&doc, ADVISORY), advisory_invalidated(1));
    assert!(store_dir(healthy.path(), TILDE_ID).exists());
    assert_eq!(
        warning_detail(&healthy_doc, ADVISORY),
        ADVISORY_NOTHING_STALE
    );
}

/// A warm install of `nodes` (each `(DepID, flags)`) holding `index`, with
/// a hidden lock recording their registry integrity.
fn write_installed_flagged(root: &Path, nodes: &[(&str, u8)], index: &[u8]) {
    write_vlt_project(root, Era::V1);
    let lines: Vec<String> = nodes
        .iter()
        .map(|(id, flags)| with_flags(&registry_node(id), *flags))
        .collect();
    std::fs::write(root.join("vlt-lock.json"), lock_with(Era::V1, &lines)).unwrap();
    for (id, _) in nodes {
        install_store(root, id, index);
    }
    write_hidden_lock(root, &lines);
}

#[tokio::test]
async fn scan_redirect_vlt_heal_keeps_stale_optional_instance() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    for flags in [1, 3] {
        for extra in [&[][..], &["--no-vlt-install-cleanup"][..]] {
            let tmp = tempfile::tempdir().unwrap();
            write_installed_flagged(tmp.path(), &[(TILDE_ID, flags)], PRISTINE);

            let (_, doc) = scan_hosted(tmp.path(), &server, extra, &[]);

            assert_eq!(
                read(tmp.path(), "vlt-lock.json"),
                lock_with(
                    Era::V1,
                    &[with_flags(&pinned_node(TILDE_ID, &server), flags)]
                ),
                "flags={flags} {extra:?}"
            );
            assert_eq!(
                std::fs::read(store_dir(tmp.path(), TILDE_ID).join("index.js")).unwrap(),
                PRISTINE,
                "an optional store entry is never removed: flags={flags} {extra:?}"
            );
            assert!(tmp.path().join("node_modules/.vlt-lock.json").exists());
            assert_eq!(
                warning_detail(&doc, ADVISORY),
                advisory_optional_kept(1),
                "flags={flags} {extra:?}"
            );
        }
    }
}

#[tokio::test]
async fn scan_redirect_vlt_heal_removes_the_prod_instance_keeps_the_optional_one() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let optional = "~npm~left-pad@1.3.0~peer.2";
    write_installed_flagged(tmp.path(), &[(TILDE_ID, 0), (optional, 1)], PRISTINE);

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert!(!tmp.path().join("node_modules/.vlt").join(TILDE_ID).exists());
    assert!(!tmp.path().join("node_modules/.vlt-lock.json").exists());
    assert_eq!(
        std::fs::read(store_dir(tmp.path(), optional).join("index.js")).unwrap(),
        PRISTINE
    );
    let also = also_optional_kept(1, "unpatched copies of optional dependencies");
    assert_eq!(
        warning_detail(&doc, ADVISORY),
        advisory_invalidated(1).replace(" Note:", &format!(" {also} Note:")),
        "the removal and the kept optional copy are both reported"
    );

    let (_, skipped) = {
        let tmp = tempfile::tempdir().unwrap();
        write_installed_flagged(tmp.path(), &[(TILDE_ID, 0), (optional, 1)], PRISTINE);
        scan_hosted(tmp.path(), &server, &["--dry-run"], &[])
    };
    assert_eq!(
        warning_detail(&skipped, ADVISORY),
        format!("{} {also}", advisory_cleanup_skipped(1)),
        "a skipped cleanup counts the removable copy and reports the optional one"
    );
}

#[cfg(unix)]
fn link_node_modules_outside(root: &Path, outside: &Path) {
    let real = outside.join("node_modules");
    std::fs::rename(root.join("node_modules"), &real).unwrap();
    std::os::unix::fs::symlink(&real, root.join("node_modules")).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn scan_redirect_vlt_heal_undeterminable_node_modules_symlink_not_deleted() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    write_installed_vlt_project(tmp.path(), PRISTINE);
    link_node_modules_outside(tmp.path(), outside.path());

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert_eq!(warning_detail(&doc, ADVISORY), advisory_undeterminable(1));
    assert!(store_dir(outside.path(), TILDE_ID)
        .join("index.js")
        .exists());
    assert!(outside.path().join("node_modules/.vlt-lock.json").exists());
}

#[tokio::test]
async fn scan_redirect_vlt_heal_advisory_texts_exact() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let fresh = tempfile::tempdir().unwrap();
    write_vlt_project(fresh.path(), Era::V1);
    let warm = tempfile::tempdir().unwrap();
    write_installed_vlt_project(warm.path(), PRISTINE);
    let skipped = tempfile::tempdir().unwrap();
    write_installed_vlt_project(skipped.path(), PRISTINE);

    let (_, fresh_doc) = scan_hosted(fresh.path(), &server, &[], &[]);
    let (_, warm_doc) = scan_hosted(warm.path(), &server, &[], &[]);
    let (_, skipped_doc) = scan_hosted(skipped.path(), &server, &["--no-vlt-install-cleanup"], &[]);

    assert_eq!(warning_detail(&fresh_doc, ADVISORY), ADVISORY_NOTHING_STALE);
    assert_eq!(warning_detail(&warm_doc, ADVISORY), advisory_invalidated(1));
    assert_eq!(
        warning_detail(&skipped_doc, ADVISORY),
        advisory_cleanup_skipped(1)
    );
    for doc in [&fresh_doc, &warm_doc, &skipped_doc] {
        assert_eq!(
            warning_codes(doc).iter().filter(|c| *c == ADVISORY).count(),
            1,
            "{doc:#}"
        );
    }
}

#[tokio::test]
async fn scan_redirect_vlt_heal_dry_run_deletes_nothing_emits_iii() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_installed_vlt_project(tmp.path(), PRISTINE);
    let lock = read(tmp.path(), "vlt-lock.json");

    let (_, doc) = scan_hosted(tmp.path(), &server, &["--dry-run"], &[]);

    assert_eq!(warning_detail(&doc, ADVISORY), advisory_cleanup_skipped(1));
    assert!(store_dir(tmp.path(), TILDE_ID).join("index.js").exists());
    assert!(tmp.path().join("node_modules/.vlt-lock.json").exists());
    assert_eq!(read(tmp.path(), "vlt-lock.json"), lock);
}

#[cfg(unix)]
fn mkfifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(unix)]
#[tokio::test]
async fn scan_redirect_vlt_heal_hidden_lock_fifo_or_symlink() {
    let server = MockServer::start().await;
    mock_all(&server).await;

    let fifo = tempfile::tempdir().unwrap();
    write_installed_vlt_project(fifo.path(), PRISTINE);
    let hidden = fifo.path().join("node_modules/.vlt-lock.json");
    std::fs::remove_file(&hidden).unwrap();
    mkfifo(&hidden);
    let (_, doc) = scan_hosted(fifo.path(), &server, &[], &[]);
    assert_eq!(warning_detail(&doc, ADVISORY), advisory_invalidated(1));
    assert!(std::fs::symlink_metadata(&hidden).is_err());
    assert!(!store_dir(fifo.path(), TILDE_ID).exists());

    let linked = tempfile::tempdir().unwrap();
    write_installed_vlt_project(linked.path(), PRISTINE);
    let hidden = linked.path().join("node_modules/.vlt-lock.json");
    let target = linked.path().join("hidden-target.json");
    std::fs::rename(&hidden, &target).unwrap();
    std::os::unix::fs::symlink(&target, &hidden).unwrap();
    let (_, doc) = scan_hosted(linked.path(), &server, &[], &[]);
    assert_eq!(warning_detail(&doc, ADVISORY), advisory_invalidated(1));
    assert!(std::fs::symlink_metadata(&hidden).is_err());
    assert!(target.exists(), "only the link is removed");
}

#[cfg(unix)]
#[tokio::test]
async fn scan_redirect_vlt_heal_invalidation_failure_warns() {
    use std::os::unix::fs::PermissionsExt as _;
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_installed_vlt_project(tmp.path(), PRISTINE);
    let store = tmp.path().join("node_modules/.vlt");
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o555)).unwrap();

    let (code, doc) = scan_hosted(tmp.path(), &server, &[], &[]);
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(code, 0);
    assert_eq!(redirected(&doc), 1);
    assert_eq!(warning_detail(&doc, ADVISORY), advisory_cleanup_skipped(1));
    assert!(store.join(TILDE_ID).exists());
}

#[tokio::test]
async fn scan_redirect_vlt_no_install_cleanup_flag_keeps_tree() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_installed_vlt_project(tmp.path(), PRISTINE);

    let (_, doc) = scan_hosted(tmp.path(), &server, &["--no-vlt-install-cleanup"], &[]);

    assert_eq!(redirected(&doc), 1);
    assert_eq!(
        read(tmp.path(), "vlt-lock.json"),
        lock_with(Era::V1, &[pinned_node(TILDE_ID, &server)])
    );
    assert!(store_dir(tmp.path(), TILDE_ID).join("index.js").exists());
    assert!(tmp.path().join("node_modules/.vlt-lock.json").exists());
    assert_eq!(warning_detail(&doc, ADVISORY), advisory_cleanup_skipped(1));
}

#[tokio::test]
async fn scan_redirect_vlt_env_socket_no_vlt_install_cleanup() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_installed_vlt_project(tmp.path(), PRISTINE);

    let (_, doc) = scan_hosted(
        tmp.path(),
        &server,
        &[],
        &[("SOCKET_NO_VLT_INSTALL_CLEANUP", "1")],
    );

    assert!(store_dir(tmp.path(), TILDE_ID).join("index.js").exists());
    assert_eq!(warning_detail(&doc, ADVISORY), advisory_cleanup_skipped(1));
}

#[tokio::test]
async fn scan_redirect_vlt_rerun_does_not_invalidate_healthy_tree() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    std::fs::write(
        tmp.path().join("vlt-lock.json"),
        lock_with(Era::V1, &[pinned_node(TILDE_ID, &server)]),
    )
    .unwrap();
    install_store(tmp.path(), TILDE_ID, PATCHED);
    write_hidden_lock(tmp.path(), &[pinned_node(TILDE_ID, &server)]);

    let (_, doc) = scan_hosted(tmp.path(), &server, &[], &[]);

    assert_eq!(redirected(&doc), 1);
    assert!(store_dir(tmp.path(), TILDE_ID).join("index.js").exists());
    assert!(tmp.path().join("node_modules/.vlt-lock.json").exists());
    assert_eq!(warning_detail(&doc, ADVISORY), ADVISORY_NOTHING_STALE);
}

#[tokio::test]
async fn scan_redirect_vlt_heal_custom_patch_server_origin_heals() {
    let server = MockServer::start().await;
    let artifacts = MockServer::start().await;
    mock_discovery(&server).await;
    mock_view(&server).await;
    mock_artifact(&artifacts).await;
    mock_reference_at(
        &server,
        &artifact_url(&artifacts),
        &sha512_sri(&patched_tarball()),
    )
    .await;
    let configured = tempfile::tempdir().unwrap();
    write_installed_vlt_project(configured.path(), PRISTINE);
    let unconfigured = tempfile::tempdir().unwrap();
    write_installed_vlt_project(unconfigured.path(), PRISTINE);
    let origin = artifacts.uri();

    let (_, doc) = scan_hosted(
        configured.path(),
        &server,
        &["--patch-server-url", &origin],
        &[],
    );
    let (_, plain) = scan_hosted(unconfigured.path(), &server, &[], &[]);

    assert_eq!(warning_detail(&doc, ADVISORY), advisory_invalidated(1));
    assert!(!store_dir(configured.path(), TILDE_ID).exists());
    assert!(
        !warning_codes(&plain).contains(&ADVISORY.to_string()),
        "a URL on an unconfigured host is not Socket-owned: {plain:#}"
    );
    assert!(store_dir(unconfigured.path(), TILDE_ID).exists());
}

// ── in-run VEX exclusion ─────────────────────────────────────────────────

/// A confirmed vlt pin on a host that is neither patch.socket.dev nor a
/// configured origin is never healed, so the same run must not attest the
/// installed (pristine) copy; with the origin configured the heal proves it.
#[tokio::test]
async fn scan_redirect_vlt_unconfigured_origin_vex_not_attested() {
    let server = MockServer::start().await;
    let artifacts = MockServer::start().await;
    mock_discovery(&server).await;
    mock_view(&server).await;
    mock_artifact(&artifacts).await;
    mock_reference_at(
        &server,
        &artifact_url(&artifacts),
        &sha512_sri(&patched_tarball()),
    )
    .await;
    let unconfigured = tempfile::tempdir().unwrap();
    write_installed_vlt_project(unconfigured.path(), PRISTINE);
    let configured = tempfile::tempdir().unwrap();
    write_installed_vlt_project(configured.path(), PRISTINE);
    let origin = artifacts.uri();

    let (_, doc, attested) = scan_with_vex(unconfigured.path(), &server, &[]);
    let (_, healed, healed_attested) =
        scan_with_vex(configured.path(), &server, &["--patch-server-url", &origin]);

    assert_eq!(redirected(&doc), 1, "{doc:#}");
    assert!(!warning_codes(&doc).contains(&ADVISORY.to_string()));
    assert!(store_dir(unconfigured.path(), TILDE_ID).exists());
    assert!(!attested, "an unhealed pin is not attested: {doc:#}");
    assert_eq!(warning_detail(&healed, ADVISORY), advisory_invalidated(1));
    assert!(healed_attested, "{healed:#}");
}

fn vex_args(out: &Path) -> Vec<String> {
    vec![
        "--vex".into(),
        out.to_str().unwrap().into(),
        "--vex-product".into(),
        "pkg:npm/consumer@0.0.0".into(),
    ]
}

fn scan_with_vex(root: &Path, server: &MockServer, extra: &[&str]) -> (i32, Value, bool) {
    let out = root.join("out.vex.json");
    let vex = vex_args(&out);
    let mut args: Vec<&str> = vex.iter().map(String::as_str).collect();
    args.extend_from_slice(extra);
    let (code, doc) = scan_hosted(root, server, &args, &[]);
    (code, doc, vex_attests(&out))
}

#[tokio::test]
async fn scan_redirect_vlt_no_cleanup_vex_not_attested() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_installed_vlt_project(tmp.path(), PRISTINE);
    let healed = tempfile::tempdir().unwrap();
    write_installed_vlt_project(healed.path(), PRISTINE);

    let (_, doc, attested) = scan_with_vex(tmp.path(), &server, &["--no-vlt-install-cleanup"]);
    let (code, _, healed_attested) = scan_with_vex(healed.path(), &server, &[]);

    assert_eq!(redirected(&doc), 1);
    assert!(
        !attested,
        "stale installed copies are not attested: {doc:#}"
    );
    assert_eq!(code, 0);
    assert!(
        healed_attested,
        "the invalidated tree attests from the ledger"
    );
}

#[tokio::test]
async fn scan_redirect_vlt_kept_optional_instance_vex_not_attested() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let stale = tempfile::tempdir().unwrap();
    write_installed_flagged(stale.path(), &[(TILDE_ID, 1)], PRISTINE);
    let healthy = tempfile::tempdir().unwrap();
    write_installed_flagged(healthy.path(), &[(TILDE_ID, 1)], PATCHED);
    write_hidden_lock(
        healthy.path(),
        &[with_flags(&pinned_node(TILDE_ID, &server), 1)],
    );

    let (_, doc, attested) = scan_with_vex(stale.path(), &server, &[]);
    let (_, healthy_doc, healthy_attested) = scan_with_vex(healthy.path(), &server, &[]);

    assert_eq!(redirected(&doc), 1);
    assert!(
        !attested,
        "a kept stale optional copy is not attested: {doc:#}"
    );
    assert_eq!(
        warning_detail(&healthy_doc, ADVISORY),
        ADVISORY_NOTHING_STALE
    );
    assert!(
        healthy_attested,
        "a patched optional copy attests: {healthy_doc:#}"
    );
}

#[tokio::test]
async fn scan_redirect_vlt_foreign_instance_vex_not_attested() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    std::fs::write(
        tmp.path().join("vlt-lock.json"),
        lock_with(
            Era::V1,
            &[
                registry_node("~custom~left-pad@1.3.0"),
                registry_node(TILDE_ID),
            ],
        ),
    )
    .unwrap();

    let (_, doc, attested) = scan_with_vex(tmp.path(), &server, &[]);

    assert_eq!(redirected(&doc), 1);
    assert!(warning_codes(&doc).contains(&"redirect_vlt_custom_registry_skipped".to_string()));
    assert!(!attested, "{doc:#}");
}

#[tokio::test]
async fn scan_redirect_vlt_old_lockfile_vex_not_attested() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V0);
    std::fs::write(
        tmp.path().join("vlt-lock.json"),
        lock_with(Era::V0, &[registry_node(EMPTY_SEGMENT_ID)]),
    )
    .unwrap();

    let (_, doc, attested) = scan_with_vex(tmp.path(), &server, &[]);

    assert_eq!(redirected(&doc), 1);
    assert!(warning_codes(&doc).contains(&"redirect_vlt_old_lockfile_ignored".to_string()));
    assert!(!attested, "{doc:#}");
}

#[tokio::test]
async fn scan_redirect_vlt_a0_vex_not_attested() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::A0);
    let control = tempfile::tempdir().unwrap();
    write_vlt_project(control.path(), Era::V1);

    let (_, doc, attested) = scan_with_vex(tmp.path(), &server, &[]);
    let (_, _, control_attested) = scan_with_vex(control.path(), &server, &[]);

    assert!(warning_codes(&doc).contains(&"redirect_vlt_lockfile_version_missing".to_string()));
    assert!(!attested, "{doc:#}");
    assert!(control_attested);
}

#[cfg(unix)]
#[tokio::test]
async fn scan_redirect_vlt_undeterminable_vex_not_attested() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    write_installed_vlt_project(tmp.path(), PRISTINE);
    link_node_modules_outside(tmp.path(), outside.path());

    let (_, doc, attested) = scan_with_vex(tmp.path(), &server, &[]);

    assert_eq!(warning_detail(&doc, ADVISORY), advisory_undeterminable(1));
    assert!(!attested, "{doc:#}");
}

#[tokio::test]
async fn scan_redirect_vlt_workspace_member_cwd_sees_no_root_lock() {
    let server = MockServer::start().await;
    mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_project(tmp.path(), Era::V1);
    let root_lock = read(tmp.path(), "vlt-lock.json");
    let member = tmp.path().join("packages/a");
    std::fs::create_dir_all(&member).unwrap();
    write_package_json(&member);
    install_importer(&member, PRISTINE);

    let (_, doc) = scan_hosted(&member, &server, &[], &[]);

    assert_eq!(redirected(&doc), 0, "{doc:#}");
    assert!(!member.join("package-lock.json").exists());
    assert!(!member.join("vlt-lock.json").exists());
    assert_eq!(read(tmp.path(), "vlt-lock.json"), root_lock);
    assert!(!warning_codes(&doc)
        .iter()
        .any(|c| c.starts_with("redirect_vlt_")));
    assert_eq!(artifact_requests(&server).await, 0);
}
