//! Self-test for the shared manifest-less VEX e2e helpers in
//! `tests/vex_e2e_common/mod.rs`: the patch-API stand-in's routes and
//! request accounting, the project-shaping helpers, `run_vex` across the
//! standalone and embedded commands, and the assertion helpers' own
//! failure modes. Uses the synthetic lockfile-only hosted npm shape, so it
//! needs no package manager.

use crate::vex_e2e_common;

use vex_e2e_common::*;

const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const GHSA: &str = "GHSA-selt-test-0001";
const CVE: &str = "CVE-2026-4242";

fn left_pad_view() -> serde_json::Value {
    patch_view(
        UUID,
        "pkg:npm/left-pad@1.3.0",
        &[("package/index.js", &git_sha256(b"patched\n"))],
        &[(GHSA, &[CVE])],
    )
}

#[test]
fn patch_api_serves_both_view_routes_and_counts_requests() {
    let api = PatchApi::start(vec![(UUID.to_string(), left_pad_view())]);
    api.assert_no_requests();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let get = |path: &str| {
        let url = format!("{}{path}", api.uri());
        rt.block_on(async { reqwest::get(url).await.unwrap().status().as_u16() })
    };
    assert_eq!(get(&format!("/patch/view/{UUID}")), 200);
    assert_eq!(get(&format!("/v0/orgs/acme/patches/view/{UUID}")), 200);
    assert_eq!(get("/patch/view/00000000-0000-4000-8000-000000000000"), 404);
    assert_eq!(get(&format!("/v0/orgs/a/b/patches/view/{UUID}")), 404);
    assert_eq!(api.request_count(), 4);
    assert_eq!(api.view_requests(UUID), 2);

    let failing = PatchApi::empty();
    failing.fail_view(UUID, 403);
    let url = format!("{}/patch/view/{UUID}", failing.uri());
    let status = rt.block_on(async { reqwest::get(url).await.unwrap().status().as_u16() });
    assert_eq!(status, 403);
}

#[test]
fn strip_helpers_remove_only_manifest_and_ledgers() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let artifact = p.join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"));
    std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
    for f in [
        ".socket/manifest.json",
        ".socket/vendor/state.json",
        ".socket/vendor/redirect-state.json",
    ] {
        std::fs::write(p.join(f), "{}").unwrap();
    }
    std::fs::write(&artifact, b"tgz").unwrap();
    strip_manifest(p);
    assert!(!p.join(".socket/manifest.json").exists());
    assert!(p.join(".socket/vendor/state.json").exists());
    strip_ledgers(p);
    assert!(!p.join(".socket/vendor/state.json").exists());
    assert!(!p.join(".socket/vendor/redirect-state.json").exists());
    assert!(artifact.exists(), "artifacts are kept");
    // Idempotent on an already-stripped project.
    strip_manifest(p);
    strip_ledgers(p);
}

/// The module-doc flow: offline (zero network, record unavailable), then
/// online through the public-proxy route, standalone and embedded.
#[test]
fn run_vex_hosted_lockfile_only_offline_then_online() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let purl = write_hosted_npm_lock(p, "left-pad", "1.3.0", UUID);
    let api = PatchApi::start(vec![(UUID.to_string(), left_pad_view())]);

    let out = run_vex(&binary(), p, &VexRun::offline());
    assert_eq!(out.code, Some(1), "{out}");
    assert_eq!(
        out.envelope["error"]["code"], "no_applicable_patches",
        "{out}"
    );
    assert_not_attested(&out.envelope, &purl, "record_unavailable");
    assert!(out.doc.is_none(), "{out}");
    api.assert_no_requests();

    let out = run_vex(&binary(), p, &VexRun::online(&api));
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(
        out.doc(),
        &purl,
        UUID,
        Marker::Redirected,
        &[(GHSA, &[CVE])],
    );
    assert_absent(out.doc.as_ref(), "pkg:npm/other@1.0.0");
    assert!(api.view_requests(UUID) >= 1, "{:?}", api.requests());

    for via in [VexVia::Apply, VexVia::Vendor] {
        std::fs::remove_file(p.join(DEFAULT_OUTPUT)).unwrap();
        let out = run_vex(&binary(), p, &VexRun::online(&api).via(via));
        assert_eq!(out.code, Some(0), "{via:?}: {out}");
        assert_eq!(out.envelope["vex"]["statements"], 1, "{via:?}: {out}");
        assert_attested(
            out.doc(),
            &purl,
            UUID,
            Marker::Redirected,
            &[(GHSA, &[CVE])],
        );
    }
}

/// With a token the CLI uses the org-scoped route, which the stand-in
/// serves too.
#[test]
fn run_vex_org_scoped_route() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let purl = write_hosted_npm_lock(p, "left-pad", "1.3.0", UUID);
    let api = PatchApi::start(vec![(UUID.to_string(), left_pad_view())]);
    let out = run_vex(&binary(), p, &VexRun::org_scoped(&api, "acme"));
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(
        out.doc(),
        &purl,
        UUID,
        Marker::Redirected,
        &[(GHSA, &[CVE])],
    );
    let requests = api.requests();
    assert!(
        requests.contains(&format!("/v0/orgs/acme/patches/view/{UUID}")),
        "{requests:?}"
    );
    assert!(
        !requests.iter().any(|r| r.starts_with("/patch/view/")),
        "{requests:?}"
    );
}

/// `--no-verify`, a custom output path/product, and human mode.
#[test]
fn run_vex_options_reach_the_command() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let purl = write_hosted_npm_lock(p, "left-pad", "1.3.0", UUID);
    let api = PatchApi::start(vec![(UUID.to_string(), left_pad_view())]);
    let run = VexRun {
        no_verify: true,
        human: true,
        product: Some("pkg:npm/custom-product@2.0.0".to_string()),
        output: Some("nested-out.json".into()),
        ..VexRun::online(&api)
    };
    let out = run_vex(&binary(), p, &run);
    assert_eq!(out.code, Some(0), "{out}");
    assert!(out.envelope.is_null());
    assert_eq!(out.output, p.join("nested-out.json"));
    let doc = out.doc();
    assert_eq!(
        doc["statements"][0]["products"][0]["@id"], "pkg:npm/custom-product@2.0.0",
        "{out}"
    );
    assert_attested(doc, &purl, UUID, Marker::Redirected, &[(GHSA, &[CVE])]);
}

// ── assertion helpers fail when they should ──────────────────────────

fn doc_with(purl: &str, impact: &str) -> serde_json::Value {
    serde_json::json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "statements": [{
            "vulnerability": { "name": GHSA, "aliases": [CVE] },
            "products": [{ "@id": DEFAULT_PRODUCT, "subcomponents": [{ "@id": purl }] }],
            "status": "not_affected",
            "justification": "inline_mitigations_already_exist",
            "impact_statement": impact,
        }]
    })
}

#[test]
fn assert_attested_accepts_qualified_purls_and_joined_impacts() {
    let doc = doc_with(
        "pkg:pypi/foo@1.0?artifact_id=foo-1.0-py3-none-any.whl",
        &format!("Patched via Socket patch other; Patched via Socket patch {UUID} (vendored)"),
    );
    assert_attested(
        &doc,
        "pkg:pypi/foo@1.0",
        UUID,
        Marker::Vendored,
        &[(GHSA, &[CVE])],
    );
    assert!(purl_matches("pkg:npm/a@1?x=y", "pkg:npm/a@1"));
    assert!(!purl_matches("pkg:npm/a@10", "pkg:npm/a@1"));
}

#[test]
#[should_panic(expected = "lacks")]
fn assert_attested_rejects_wrong_marker() {
    let doc = doc_with(
        "pkg:npm/a@1",
        &format!("Patched via Socket patch {UUID} (vendored)"),
    );
    assert_attested(
        &doc,
        "pkg:npm/a@1",
        UUID,
        Marker::Redirected,
        &[(GHSA, &[CVE])],
    );
}

#[test]
#[should_panic(expected = "vulnerabilities attested")]
fn assert_attested_rejects_missing_vuln() {
    let doc = doc_with("pkg:npm/a@1", &format!("Patched via Socket patch {UUID}"));
    assert_attested(
        &doc,
        "pkg:npm/a@1",
        UUID,
        Marker::Applied,
        &[(GHSA, &[CVE]), ("GHSA-miss-ing0-0000", &[])],
    );
}

#[test]
#[should_panic(expected = "was attested")]
fn assert_not_attested_rejects_a_verified_purl() {
    let env = serde_json::json!({ "events": [
        { "action": "verified", "purl": "pkg:npm/a@1" },
        { "action": "skipped", "purl": "pkg:npm/a@1", "errorCode": "hash_mismatch" },
    ]});
    assert_not_attested(&env, "pkg:npm/a@1", "hash_mismatch");
}

#[test]
#[should_panic(expected = "must not be attested")]
fn assert_absent_rejects_a_present_purl() {
    let doc = doc_with("pkg:npm/a@1", "x");
    assert_absent(Some(&doc), "pkg:npm/a@1");
}
