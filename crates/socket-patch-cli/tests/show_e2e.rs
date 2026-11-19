//! `socket-patch show` end to end, against a mock patch service.
//!
//! The run is piped (not a terminal), so nothing is paged and no menu
//! opens: the summary and every selected diff print at once, in ASCII and
//! without color. Covers the view carrying both sides of each file, the
//! blob endpoint filling in a side the view lacks, `--stat`, `--file`,
//! `--json`, `--silent`, a search that finds several patches, and the
//! failures.

#[path = "common/mod.rs"]
mod common;
use common::{binary, hermetic_command};

use base64::Engine as _;
use std::path::Path;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "8be53d06-7bd4-40cc-ab8f-36dc6248985a";
const OTHER: &str = "1d90158a-fffb-47ee-a84f-b210a3f7ae65";
const PURL: &str = "pkg:npm/undici@8.10.0";

const BEFORE_A: &str = "one\ntwo\nthree\n";
const AFTER_A: &str = "one\nTWO\nthree\nfour\n";
const AFTER_NEW: &str = "added\n";

fn b64(text: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(text)
}

/// A 64-hex blob hash that is `c` repeated.
fn hash(c: char) -> String {
    c.to_string().repeat(64)
}

fn run_show(cwd: &Path, mock: &MockServer, args: &[&str]) -> (i32, String, String) {
    let mut cmd = hermetic_command(&binary());
    cmd.arg("show")
        .args(args)
        .args([
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG,
        ])
        .current_dir(cwd);
    let out = cmd.output().expect("run socket-patch show");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// The patch view: `lib/a.js` changed (its content before the patch inline
/// when `inline_before`), `lib/new.js` added.
fn view(inline_before: bool) -> serde_json::Value {
    let mut a = serde_json::json!({
        "beforeHash": hash('b'),
        "afterHash": hash('a'),
        "blobContent": b64(AFTER_A),
    });
    if inline_before {
        a["beforeBlobContent"] = serde_json::json!(b64(BEFORE_A));
    }
    serde_json::json!({
        "uuid": UUID,
        "purl": PURL,
        "publishedAt": "Mon, 03 Aug 2026 19:12:42 GMT",
        "description": "",
        "license": "MIT",
        "tier": "free",
        "files": {
            "lib/a.js": a,
            "lib/new.js": {"afterHash": hash('c'), "blobContent": b64(AFTER_NEW)},
        },
        "vulnerabilities": {
            "GHSA-aaaa-bbbb-cccc": {
                "cves": ["CVE-2026-84961"],
                "summary": "TLS validation bypass",
                "severity": "HIGH",
                "description": "d"
            }
        },
        "statistics": {
            "diff": {"linesAdded": 3, "linesRemoved": 1, "filesChanged": 2},
            "functionsChanged": 1,
            "tests": {"before": {"count": 35, "total": 35}, "after": {"count": 35, "total": 35}},
            "pocs": {"reproducedBefore": {"count": 1, "total": 1},
                     "blockedAfter": {"count": 1, "total": 1}},
            "performance": {"generalWallChange": null, "hotWallChange": 0.0356,
                            "peakMemChange": null}
        }
    })
}

async fn mount_view(mock: &MockServer, body: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .and(query_param("include_before_blobs", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(mock)
        .await;
}

const SUMMARY: &str = "\
pkg:npm/undici@8.10.0  HIGH  [FREE]
Patch 8be53d06-7bd4-40cc-ab8f-36dc6248985a, published 03 Aug 2026, MIT

Fixes:
  HIGH  CVE-2026-84961  TLS validation bypass

Measured by Socket:
  Verified: 1 of 1 exploit blocked (1 of 1 worked before the patch), 35 of 35 tests passing \
(35 of 35 before the patch)
  Change: +3 -1 lines in 2 files, 1 function
  Performance: patched code +3.6%

2 files changed: +3 -1
  lib/a.js    +2 -1
  lib/new.js  +1 -0
";

const DIFF_A: &str = "\
--- a/lib/a.js
+++ b/lib/a.js
@@ -1,3 +1,4 @@
 one
-two
+TWO
 three
+four
";

const DIFF_NEW: &str = "\
--- /dev/null
+++ b/lib/new.js
@@ -0,0 +1,1 @@
+added
";

#[tokio::test(flavor = "multi_thread")]
async fn show_prints_the_summary_and_every_diff_when_piped() {
    let mock = MockServer::start().await;
    mount_view(&mock, view(true)).await;
    let tmp = tempfile::tempdir().unwrap();

    let (code, stdout, stderr) = run_show(tmp.path(), &mock, &[UUID]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert_eq!(stdout, format!("{SUMMARY}\n{DIFF_A}{DIFF_NEW}"));
    assert!(
        !stdout.contains('\x1b') && stdout.is_ascii(),
        "a pipe gets neither color nor glyphs: {stdout:?}"
    );
    // The project is untouched.
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

/// A view without the content before the patch (the public proxy's): that
/// side is read from the blob endpoint by its hash.
#[tokio::test(flavor = "multi_thread")]
async fn show_reads_a_missing_side_from_the_blob_endpoint() {
    let mock = MockServer::start().await;
    mount_view(&mock, view(false)).await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/blob/{}", hash('b'))))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(BEFORE_A.as_bytes()))
        .expect(1)
        .mount(&mock)
        .await;
    let tmp = tempfile::tempdir().unwrap();

    let (code, stdout, stderr) = run_show(tmp.path(), &mock, &[UUID, "--no-pager"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert_eq!(stdout, format!("{SUMMARY}\n{DIFF_A}{DIFF_NEW}"));
}

#[tokio::test(flavor = "multi_thread")]
async fn show_stat_and_file_narrow_what_is_printed() {
    let mock = MockServer::start().await;
    mount_view(&mock, view(true)).await;
    let tmp = tempfile::tempdir().unwrap();

    let (code, stdout, _) = run_show(tmp.path(), &mock, &[UUID, "--stat"]);
    assert_eq!(code, 0);
    assert_eq!(stdout, SUMMARY);

    // The end of a path selects the file; the summary still lists both.
    let (code, stdout, _) = run_show(tmp.path(), &mock, &[UUID, "--file", "new.js"]);
    assert_eq!(code, 0);
    assert_eq!(stdout, format!("{SUMMARY}\n{DIFF_NEW}"));

    let (code, stdout, stderr) = run_show(tmp.path(), &mock, &[UUID, "--file", "nope.js"]);
    assert_eq!(code, 1, "stdout={stdout}");
    assert_eq!(
        stderr.lines().last().unwrap_or_default(),
        "Error: `nope.js` is not a file of this patch; it changes: lib/a.js, lib/new.js"
    );
    assert!(stdout.is_empty(), "{stdout:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn show_json_is_one_document_without_file_content() {
    let mock = MockServer::start().await;
    mount_view(&mock, view(true)).await;
    let tmp = tempfile::tempdir().unwrap();

    let (code, stdout, stderr) = run_show(tmp.path(), &mock, &[UUID, "--json"]);
    assert_eq!(code, 0, "stderr={stderr}");
    let doc: serde_json::Value = serde_json::from_str(&stdout).expect("one JSON document");
    assert_eq!(doc["command"], "show");
    assert_eq!(doc["status"], "success");
    let patch = &doc["patch"];
    assert_eq!(patch["uuid"], UUID);
    assert_eq!(patch["purl"], PURL);
    assert_eq!(patch["tier"], "free");
    assert_eq!(patch["statistics"]["pocs"]["blockedAfter"]["count"], 1);
    assert_eq!(
        patch["files"],
        serde_json::json!([
            {"path": "lib/a.js", "beforeHash": hash('b'), "afterHash": hash('a'),
             "added": 2, "removed": 1, "binary": false},
            {"path": "lib/new.js", "beforeHash": "", "afterHash": hash('c'),
             "added": 1, "removed": 0, "binary": false},
        ])
    );
    assert!(!stdout.contains(&b64(AFTER_A)), "no file content: {stdout}");

    // `--silent`: nothing on success.
    let (code, stdout, _) = run_show(tmp.path(), &mock, &[UUID, "--silent"]);
    assert_eq!((code, stdout.as_str()), (0, ""));
}

/// A purl with several patches: piped, the best ranked is shown and the
/// others are named on stderr.
#[tokio::test(flavor = "multi_thread")]
async fn show_resolves_a_purl_to_its_best_ranked_patch() {
    let mock = MockServer::start().await;
    mount_view(&mock, view(true)).await;
    let found = |uuid: &str, severity: &str, cve: &str| {
        serde_json::json!({
            "uuid": uuid, "purl": PURL, "publishedAt": "2026-08-03T00:00:00Z",
            "description": "", "license": "MIT", "tier": "free",
            "vulnerabilities": {
                format!("GHSA-{cve}"): {"cves": [cve], "summary": "s", "severity": severity,
                                         "description": "d"}
            }
        })
    };
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG}/patches/by-package/{}",
            PURL.replace(':', "%3A")
                .replace('/', "%2F")
                .replace('@', "%40")
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                found(OTHER, "MODERATE", "CVE-2026-85014"),
                found(UUID, "HIGH", "CVE-2026-84961"),
            ],
            "canAccessPaidPatches": true
        })))
        .mount(&mock)
        .await;
    let tmp = tempfile::tempdir().unwrap();

    let (code, stdout, stderr) = run_show(tmp.path(), &mock, &[PURL, "--stat"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert_eq!(stdout, SUMMARY);
    assert!(
        stderr.contains(&format!(
            "2 patches match {PURL}; showing the best ranked. The others:\n  1d90158a  {PURL}  \
             MODERATE  CVE-2026-85014"
        )),
        "{stderr}"
    );
}

/// A token the patch service refuses is not the end of it: the public
/// service, which has the free patches, is asked for the patch. When it
/// has none either, the refusal is what is reported: it is the cause, and
/// the public service's "no such patch" would hide it.
#[tokio::test(flavor = "multi_thread")]
async fn show_reads_from_the_public_service_when_the_token_is_refused() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{OTHER}")))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/patch/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(view(true)))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/patch/view/{OTHER}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let public = mock.uri();

    let (code, stdout, stderr) = run_show(tmp.path(), &mock, &[UUID, "--proxy-url", &public]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert_eq!(stdout, format!("{SUMMARY}\n{DIFF_A}{DIFF_NEW}"));

    let (code, stdout, stderr) = run_show(tmp.path(), &mock, &[OTHER, "--proxy-url", &public]);
    assert_eq!(code, 1, "stdout={stdout}; stderr={stderr}");
    assert!(stdout.is_empty(), "{stdout:?}");
    assert!(
        stderr.contains("Error: Unauthorized: Invalid API token"),
        "{stderr}"
    );
    assert!(!stderr.contains("no patch found"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn show_failures_are_coded_and_exit_one() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "error": {"message": "Patch not found"}
        })))
        .mount(&mock)
        .await;
    let tmp = tempfile::tempdir().unwrap();

    let (code, stdout, stderr) = run_show(tmp.path(), &mock, &[UUID]);
    assert_eq!(code, 1, "stdout={stdout}; stderr={stderr}");
    assert!(stdout.is_empty(), "{stdout:?}");
    assert!(
        stderr.contains(&format!("Error: no patch found with UUID {UUID}")),
        "{stderr}"
    );

    let (code, stdout, _) = run_show(tmp.path(), &mock, &[UUID, "--json"]);
    assert_eq!(code, 1);
    let doc: serde_json::Value = serde_json::from_str(&stdout).expect("one JSON document");
    assert_eq!(doc["status"], "error");
    assert_eq!(doc["error"]["code"], "patch_not_found");

    // No network, no patch: refused before any request.
    let (code, _, stderr) = run_show(tmp.path(), &mock, &[UUID, "--offline"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("cannot run with --offline"), "{stderr}");
}
