//! End-to-end tests for `apply`'s online code paths against a
//! wiremock-driven mock API. These complement `apply_invariants.rs`
//! (which only exercises offline paths).
//!
//! Verifies:
//!   - `apply` (default, online) fetches missing blobs from the API
//!     and writes them to an OS tempdir (NOT `.socket/`).
//!   - a cold-cache apply fetches only per-file blobs, never a diff
//!     archive (v5 removed the diff download path).
//!   - `apply` against installed packages writes patched content to
//!     node_modules and leaves `.socket/` byte-identical.

use std::path::Path;

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::apply_fixture::{
    install_npm_pkg, one_file, patch_record, stage_blob, write_manifest, write_root_package_json,
};
use crate::common::{binary, git_sha256, hermetic};

const ORG_SLUG: &str = "test-org";

fn run_apply(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, String, String) {
    // Pass the API URL/token/org via env vars (equivalent to the global
    // --api-url/--api-token/--org flags).
    let mut argv: Vec<&str> = vec!["apply", "--json"];
    argv.extend_from_slice(extra);
    let out = hermetic::command(&binary())
        .args(&argv)
        .current_dir(cwd)
        .env("SOCKET_API_URL", api_url)
        .env("SOCKET_API_TOKEN", "fake-token-for-test")
        .env("SOCKET_ORG_SLUG", ORG_SLUG)
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

// ---------------------------------------------------------------------------
// Online fetch path — apply downloads a missing blob and applies it.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_online_fetches_missing_blob_and_patches_file() {
    let before = b"before\n";
    let after = b"after\n";
    let after_hash = git_sha256(after);

    let mock = MockServer::start().await;
    let purl = "pkg:npm/apply-network-test@1.0.0";
    let uuid = "11111111-1111-4111-8111-111111111111";

    // The fetcher hits /v0/orgs/{slug}/patches/blob/{hash}. Return the
    // patched bytes so the binary's content-hash check passes.
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(after.to_vec()))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    install_npm_pkg(tmp.path(), "apply-network-test", "1.0.0", Some(before));
    let socket = tmp.path().join(".socket");
    write_manifest(
        tmp.path(),
        json!({ purl: patch_record(uuid, one_file("package/index.js", before, after)) }),
    );

    let (code, stdout, stderr) = run_apply(tmp.path(), &mock.uri(), &[]);
    assert_eq!(
        code, 0,
        "apply must succeed; stdout={stdout}; stderr={stderr}"
    );

    // The whole point of this test is the ONLINE fetch path: the blob was
    // neither pre-staged in `.socket/blobs/` nor present anywhere on disk,
    // so the only way the file can end up with after-content is by the
    // binary actually GETting it from the blob endpoint. Assert the mock
    // recorded that request — otherwise a future regression that resolved
    // the content some other way (or short-circuited) would stay green.
    let requests = mock
        .received_requests()
        .await
        .expect("wiremock records requests");
    let blob_path = format!("/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}");
    assert!(
        requests.iter().any(|r| r.url.path() == blob_path),
        "apply must fetch the missing blob from the API; \
         got requests={:?}",
        requests
            .iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
    // Per-file blobs are the only download: a cold cache must never
    // request a diff (or legacy package) archive.
    assert!(
        requests
            .iter()
            .all(|r| !r.url.path().contains("/diff") && !r.url.path().contains("/package/")),
        "apply must request only blobs; got requests={:?}",
        requests
            .iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
    assert!(
        !socket.join("diffs").exists(),
        "apply must not create .socket/diffs/"
    );
    // The fetch path must have actually applied the patch (not silently
    // no-op'd to a green exit). Assert the JSON summary, not just exit code.
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["command"], "apply");
    assert_eq!(
        v["summary"]["applied"], 1,
        "online fetch must apply exactly one patch; stdout={stdout}"
    );
    assert_eq!(
        v["summary"]["failed"], 0,
        "online fetch must not record any failures; stdout={stdout}"
    );
    let events = v["events"].as_array().expect("events array");
    assert!(
        events
            .iter()
            .any(|e| e["purl"] == purl && e["action"] != "failed"),
        "must emit a non-failed event for the patched purl; events={events:?}"
    );

    // The file under node_modules should now contain the patched bytes.
    let patched_path = tmp.path().join("node_modules/apply-network-test/index.js");
    let patched_content = std::fs::read(&patched_path).expect("read patched file");
    assert_eq!(
        patched_content, after,
        "node_modules file must contain after-content; got: {patched_content:?}"
    );

    // `.socket/blobs/` must remain empty — apply staged the fetched blob
    // into a tempdir, NOT into the persistent cache.
    let blobs_dir = socket.join("blobs");
    if blobs_dir.exists() {
        let entries: Vec<_> = std::fs::read_dir(&blobs_dir).unwrap().collect();
        assert!(
            entries.is_empty(),
            "apply must not write blobs to .socket/blobs/; found: {entries:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// --ecosystems filter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_with_ecosystem_filter_excluding_npm_skips_all_npm_patches() {
    let before = b"before\n";
    let after = b"after\n";

    let mock = MockServer::start().await;
    let purl = "pkg:npm/skipped@1.0.0";
    let uuid = "11111111-1111-4111-8111-111111111111";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    install_npm_pkg(tmp.path(), "skipped", "1.0.0", Some(before));
    write_manifest(
        tmp.path(),
        json!({ purl: patch_record(uuid, one_file("package/index.js", before, after)) }),
    );

    let (code, stdout, stderr) = run_apply(tmp.path(), &mock.uri(), &["--ecosystems", "pypi"]);
    // Filtering out npm leaves nothing in scope: there is genuinely no
    // work this run can do, so apply is a clean no-op SUCCESS (exit 0) —
    // the same documented contract as an empty manifest (npm `postinstall`
    // runs `apply` on every install). The `--ecosystems` filter scopes the
    // source probes and download planner up front, so the excluded npm
    // patch's missing artifacts are never fetched against this route-less
    // mock.
    assert_eq!(
        code, 0,
        "ecosystem filter with nothing in scope is a clean no-op success; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["command"], "apply");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["applied"], 0);
    // Nothing in the npm ecosystem may even be discovered/downloaded once
    // it's filtered out — guards against the filter being applied only at
    // the write step while still crawling/fetching the excluded packages.
    assert_eq!(
        v["summary"]["discovered"], 0,
        "filtered npm must not be discovered"
    );
    assert_eq!(
        v["summary"]["downloaded"], 0,
        "filtered npm must not be downloaded"
    );
    assert_eq!(
        v["summary"]["failed"], 0,
        "skipping out-of-scope is not a failure"
    );
    // The excluded patch's artifacts must not be fetched AT ALL — the
    // filter scopes the download planner itself, not just the write step.
    // (Only artifact endpoints are checked; telemetry may ping the API.)
    let requests = mock.received_requests().await.unwrap_or_default();
    let artifact_requests: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path().contains("/patches/"))
        .collect();
    assert!(
        artifact_requests.is_empty(),
        "no patch artifacts may be fetched for a filtered-out ecosystem; got {artifact_requests:?}"
    );
    // The excluded npm patch must not appear as an applied/patched event —
    // an empty `events` array or one without our purl is fine, but a
    // "patched" event for the skipped purl would mean the filter leaked.
    if let Some(events) = v["events"].as_array() {
        assert!(
            !events
                .iter()
                .any(|e| e["purl"] == purl && e["action"] == "patched"),
            "ecosystem filter must not patch the excluded npm purl; events={events:?}"
        );
    }

    // Node_modules file must be UNCHANGED.
    let content = std::fs::read(tmp.path().join("node_modules/skipped/index.js")).unwrap();
    assert_eq!(content, before, "non-matching ecosystem must skip apply");
}

// ---------------------------------------------------------------------------
// Dry-run with installed package — verified action, no disk write
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_dry_run_emits_verified_event_without_writing() {
    let before = b"before\n";
    let after = b"after\n";
    let after_hash = git_sha256(after);

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    install_npm_pkg(tmp.path(), "dryrun-target", "1.0.0", Some(before));
    write_manifest(
        tmp.path(),
        json!({ "pkg:npm/dryrun-target@1.0.0": patch_record("11111111-1111-4111-8111-111111111111", one_file("package/index.js", before, after)) }),
    );
    // Pre-stage the after blob so we don't need to mock the network
    // path; we just want to verify dry-run reports the action correctly.
    stage_blob(tmp.path(), &after_hash, after);

    // No mock needed — apply finds everything locally.
    let out = hermetic::command(&binary())
        .args(["apply", "--json", "--dry-run", "--offline"])
        .current_dir(tmp.path())
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(code, 0, "dry-run must succeed; stdout={stdout}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["dryRun"], true);
    // Dry-run must report it would patch but never actually applies.
    assert_eq!(
        v["summary"]["applied"], 0,
        "dry-run must not count any applied patch; stdout={stdout}"
    );
    let events = v["events"].as_array().expect("events array");
    // The verified event must be for OUR purl, not some unrelated event;
    // and dry-run must NOT emit a real "patched"/"applied" action.
    assert!(
        events
            .iter()
            .any(|e| e["purl"] == "pkg:npm/dryrun-target@1.0.0" && e["action"] == "verified"),
        "dry-run must emit a verified event for the target purl; events={events:?}"
    );
    assert!(
        events
            .iter()
            .all(|e| e["action"] != "patched" && e["action"] != "applied"),
        "dry-run must not emit a patched/applied action; events={events:?}"
    );

    // File content must be UNCHANGED.
    let content = std::fs::read(tmp.path().join("node_modules/dryrun-target/index.js")).unwrap();
    assert_eq!(
        content, before,
        "dry-run must not modify node_modules files"
    );
}

// ---------------------------------------------------------------------------
// Apply when blob is already in `.socket/blobs/` (no fetch needed)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// `--force` accepts hash-mismatched files
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_with_force_overrides_hash_mismatch() {
    let after = b"after\n";
    let after_hash = git_sha256(after);
    let expected_before = b"expected-before\n";
    let actual_before = b"DIFFERENT-CONTENT\n"; // wrong before content

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    install_npm_pkg(tmp.path(), "force-target", "1.0.0", Some(actual_before));
    write_manifest(
        tmp.path(),
        json!({ "pkg:npm/force-target@1.0.0": patch_record("11111111-1111-4111-8111-111111111111", one_file("package/index.js", expected_before, after)) }),
    );
    // Pre-stage the after blob so we don't need the network.
    stage_blob(tmp.path(), &after_hash, after);

    // Without --force apply should fail (hash mismatch). With --force it
    // should bypass the verification and write the patched content.
    let out = hermetic::command(&binary())
        .args(["apply", "--json", "--offline", "--force"])
        .current_dir(tmp.path())
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        code, 0,
        "--force must succeed past hash mismatch; stdout={stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    // With force on a HashMismatch, the diff path bails because the
    // on-disk hash still doesn't match `before_hash`, but the blob
    // fallback should kick in and overwrite the file with the
    // afterHash content. Assert the run reports a real success — a
    // green exit with applied==0 would mean --force silently skipped.
    assert_eq!(v["command"], "apply");
    assert_eq!(
        v["summary"]["applied"], 1,
        "--force must apply the patch past the hash mismatch; stdout={stdout}"
    );
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().all(|e| e["action"] != "failed"),
        "--force run must not emit a failed event; events={events:?}"
    );
    let content = std::fs::read(tmp.path().join("node_modules/force-target/index.js")).unwrap();
    assert_eq!(
        content, after,
        "--force must overwrite file with afterHash content"
    );
}

#[tokio::test]
async fn apply_hash_mismatch_opt_in_warns_and_applies_strict_fails() {
    let after = b"after\n";
    let after_hash = git_sha256(after);
    let expected_before = b"expected-before\n";
    let actual_before = b"DIFFERENT-CONTENT\n";

    let fixture = || {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_root_package_json(tmp.path());
        install_npm_pkg(tmp.path(), "mismatch", "1.0.0", Some(actual_before));
        write_manifest(
            tmp.path(),
            json!({ "pkg:npm/mismatch@1.0.0": patch_record("11111111-1111-4111-8111-111111111111", one_file("package/index.js", expected_before, after)) }),
        );
        stage_blob(tmp.path(), &after_hash, after);
        tmp
    };

    // OPT-IN: the mismatch is overwritten with the full verified patched
    // content (the blob is hash-gated to afterHash) and surfaced as a warning event — exit 0.
    let tmp = fixture();
    let out = hermetic::command(&binary())
        .args(["apply", "--allow-patch-conflicts", "--json", "--offline"])
        .current_dir(tmp.path())
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "opted-in mismatch is a warning, not an error: {v:#}"
    );
    assert_eq!(v["status"], "success", "{v:#}");
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["action"] == "applied"),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e["errorCode"] == "content_mismatch_overwritten"),
        "the overwrite is surfaced as a warning event: {events:?}"
    );
    let content = std::fs::read(tmp.path().join("node_modules/mismatch/index.js")).unwrap();
    assert_eq!(
        content, after,
        "the file carries the verified patched bytes"
    );

    // The human run logs the warning to stderr.
    let tmp = fixture();
    let out = hermetic::command(&binary())
        .args(["apply", "--allow-patch-conflicts", "--offline", "--yes"])
        .current_dir(tmp.path())
        .output()
        .expect("run socket-patch");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code().unwrap_or(-1), 0, "stderr={stderr}");
    assert!(
        stderr.contains("did not match the patch's expected original content"),
        "stderr warning present: {stderr}"
    );

    // --strict: fail closed — exit 1, failed event, file untouched.
    let tmp = fixture();
    let out = hermetic::command(&binary())
        .args([
            "apply",
            "--allow-patch-conflicts",
            "--json",
            "--offline",
            "--strict",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(out.status.code().unwrap_or(-1), 1, "{v:#}");
    assert_eq!(v["status"], "partialFailure", "{v:#}");
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["action"] == "failed"),
        "strict emits a failed event: {events:?}"
    );
    let content = std::fs::read(tmp.path().join("node_modules/mismatch/index.js")).unwrap();
    assert_eq!(content, actual_before, "strict must not modify the file");
}

// ---------------------------------------------------------------------------
// Pypi ecosystem — covers the python crawler branch in ecosystem_dispatch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_pypi_package_uses_python_crawler() {
    let before = b"def hello():\n    return 'before'\n";
    let after = b"def hello():\n    return 'after'\n";
    let after_hash = git_sha256(after);

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());

    // Pypi crawler discovers a project-local venv via filesystem probing
    // (`find_local_venv_site_packages` → `find_site_packages_under`), so this is
    // fully deterministic and does NOT depend on a real Python on PATH. The
    // probed layout is platform-specific: `.venv/Lib/site-packages` on Windows,
    // `.venv/lib/python3.*/site-packages` on Unix — stage whichever this runner
    // will actually look in. The crawler returns the *site-packages* dir as the
    // package path, and apply joins it with the patch file key after stripping
    // the `package/` prefix — so the patch key `package/index.js` resolves to
    // `<site-packages>/index.js`. Write the source there so apply can patch it.
    let site_packages = if cfg!(windows) {
        tmp.path().join(".venv").join("Lib").join("site-packages")
    } else {
        tmp.path()
            .join(".venv")
            .join("lib")
            .join("python3.12")
            .join("site-packages")
    };
    std::fs::create_dir_all(&site_packages).expect("create site-packages");
    std::fs::write(site_packages.join("index.js"), before).expect("write source");
    let dist_info = site_packages.join("pypi_target-1.0.0.dist-info");
    std::fs::create_dir_all(&dist_info).unwrap();
    std::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: pypi_target\nVersion: 1.0.0\n",
    )
    .unwrap();

    write_manifest(
        tmp.path(),
        json!({ "pkg:pypi/pypi_target@1.0.0": patch_record("11111111-1111-4111-8111-111111111111", one_file("package/index.js", before, after)) }),
    );
    stage_blob(tmp.path(), &after_hash, after);

    // Run apply restricted to pypi. With the venv staged on disk and the
    // after-blob pre-cached, this must locate the package via the python
    // crawler and patch it — exercising the pypi dispatch branch end to
    // end, not just "without panicking". An ambient venv is scrubbed so CI
    // can't redirect discovery away from our `.venv`.
    let mut cmd = hermetic::command(&binary());
    cmd.args(["apply", "--json", "--offline", "--ecosystems", "pypi"])
        .current_dir(tmp.path());
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv]);
    let out = cmd.output().expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        code, 0,
        "pypi apply must find + patch the package; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["command"], "apply");
    assert_eq!(
        v["summary"]["applied"], 1,
        "exactly one pypi patch must be applied; stdout={stdout}"
    );
    // The pypi crawler must have been the one to resolve the package: the
    // patched event carries the pypi PURL.
    let events = v["events"].as_array().expect("events array");
    assert!(
        events
            .iter()
            .any(|e| e["purl"] == "pkg:pypi/pypi_target@1.0.0" && e["action"] != "failed"),
        "must emit a non-failed event for the pypi purl; got events={events:?}"
    );

    // The on-disk source file under site-packages must now hold after-content.
    let patched = std::fs::read(site_packages.join("index.js")).expect("read patched");
    assert_eq!(
        patched, after,
        "pypi apply must overwrite site-packages file with after-content"
    );
}

#[tokio::test]
async fn apply_uses_locally_cached_blob_without_fetching() {
    let before = b"before\n";
    let after = b"after\n";
    let after_hash = git_sha256(after);

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    install_npm_pkg(tmp.path(), "cached", "1.0.0", Some(before));
    let socket = tmp.path().join(".socket");
    write_manifest(
        tmp.path(),
        json!({ "pkg:npm/cached@1.0.0": patch_record("22222222-2222-4222-8222-222222222222", one_file("package/index.js", before, after)) }),
    );
    stage_blob(tmp.path(), &after_hash, after);

    // No mock server. If apply tries to hit the network, the test will
    // fail (connection refused) — proving the local-blob fast path is
    // taken when sources are already on disk. Both URLs are pinned: with
    // no token the child takes the public-proxy path.
    let out = hermetic::command(&binary())
        .args(["apply", "--json"])
        .current_dir(tmp.path())
        // Unreachable port: should never be contacted.
        .env("SOCKET_API_URL", "http://127.0.0.1:1")
        .env("SOCKET_PROXY_URL", "http://127.0.0.1:1")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        code, 0,
        "apply with cached blob must succeed without network; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        v["summary"]["applied"], 1,
        "cached-blob apply must apply exactly one patch; stdout={stdout}"
    );

    // File was patched.
    let content = std::fs::read(tmp.path().join("node_modules/cached/index.js")).unwrap();
    assert_eq!(content, after);

    // `.socket/blobs/` must still contain the cached blob (apply is
    // read-only against the persistent cache).
    assert!(
        socket.join("blobs").join(&after_hash).exists(),
        "cached blob must survive apply"
    );
}

// ---------------------------------------------------------------------------
// Mismatch: the full blob is downloaded and applied.
// ---------------------------------------------------------------------------

/// The explicitly approved mismatch policy applies the FULL afterHash blob to a
/// mismatched file. A leftover legacy package archive is not a source, so
/// the stage step still downloads the blob.
#[tokio::test]
async fn apply_mismatch_redownloads_full_blob_and_applies() {
    let after = b"after\n";
    let after_hash = git_sha256(after);

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(after.to_vec()))
        .mount(&mock)
        .await;

    let uuid = "11111111-1111-4111-8111-111111111111";
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    install_npm_pkg(
        tmp.path(),
        "mismatch",
        "1.0.0",
        Some(b"DIFFERENT-CONTENT\n"),
    );
    let socket = tmp.path().join(".socket");
    write_manifest(
        tmp.path(),
        json!({ "pkg:npm/mismatch@1.0.0": patch_record(
            uuid,
            one_file("package/index.js", b"expected-before\n", after),
        )}),
    );
    // A leftover LOCAL package archive exists, but nothing reads it: only
    // the blob can produce the patched bytes, and no blob is cached.
    let packages = socket.join("packages");
    std::fs::create_dir_all(&packages).unwrap();
    {
        use std::io::Write as _;
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            std::fs::File::create(packages.join(format!("{uuid}.tar.gz"))).unwrap(),
            flate2::Compression::default(),
        ));
        let mut header = tar::Header::new_gnu();
        let bytes = b"unrelated";
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "other.js", &bytes[..])
            .unwrap();
        builder
            .into_inner()
            .unwrap()
            .finish()
            .unwrap()
            .flush()
            .unwrap();
    }

    let (code, stdout, stderr) = run_apply(tmp.path(), &mock.uri(), &["--allow-patch-conflicts"]);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(code, 0, "stdout={v:#}\nstderr={stderr}");
    let events = v["events"].as_array().expect("events array");
    assert!(
        events
            .iter()
            .any(|e| e["errorCode"] == "content_mismatch_overwritten"),
        "{events:?}"
    );

    // The blob was fetched on demand…
    let requests = mock.received_requests().await.unwrap();
    let blob_path = format!("/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}");
    assert!(
        requests.iter().any(|r| r.url.path() == blob_path),
        "the full blob must be redownloaded for the mismatched file"
    );
    // …and the file carries the verified patched bytes.
    let content = std::fs::read(tmp.path().join("node_modules/mismatch/index.js")).unwrap();
    assert_eq!(content, after);
}

// ---------------------------------------------------------------------------
// --offline is a strict airgap: ZERO network requests, including the
// telemetry-labeling client's org-slug auto-resolution at command start.
// ---------------------------------------------------------------------------

/// `run()` builds an API client up front purely to label telemetry with the
/// token/org. When `SOCKET_API_TOKEN` is set but no org is configured, that
/// client construction auto-resolves the org slug via `GET
/// /v0/organizations` — a live network round-trip that must not happen under
/// `--offline` (the same strict-airgap contract that already disables
/// telemetry and blob fetching). The apply itself is fully satisfiable
/// offline here (blob staged locally), so the ONLY traffic the mock could
/// ever see is contract-violating.
#[tokio::test]
async fn offline_apply_with_token_makes_zero_network_requests() {
    let before = b"offline airgap before\n";
    let after = b"offline airgap after\n";
    let after_hash = git_sha256(after);

    // No mocks mounted: every request is a violation, and all are recorded.
    let mock = MockServer::start().await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    install_npm_pkg(tmp.path(), "airgap-test", "1.0.0", Some(before));
    write_manifest(
        tmp.path(),
        json!({ "pkg:npm/airgap-test@1.0.0": patch_record("33333333-3333-4333-8333-333333333333", one_file("package/index.js", before, after)) }),
    );
    stage_blob(tmp.path(), &after_hash, after);

    let mut cmd = hermetic::command(&binary());
    cmd.args(["apply", "--json", "--offline"])
        .current_dir(tmp.path());
    // The builder scrubs ambient SOCKET_* (an ambient SOCKET_ORG_SLUG would
    // skip the auto-resolution and make this test vacuously green) and
    // keeps the config layer off; seed only what the scenario needs: token
    // set, org absent, both URLs pinned to the mock so any traffic — API or
    // proxy path — is captured. Telemetry is switched back on (the builder
    // forces it off) so only `--offline` can keep the telemetry POST away
    // from the mock.
    cmd.env("SOCKET_TELEMETRY_DISABLED", "0")
        .env("SOCKET_API_URL", mock.uri())
        .env("SOCKET_PROXY_URL", mock.uri())
        .env("SOCKET_API_TOKEN", "fake-token-for-test");
    let out = cmd.output().expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(
        code, 0,
        "offline apply with a locally staged blob must succeed; \
         stdout={stdout}\nstderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json envelope");
    assert_eq!(
        v["summary"]["applied"], 1,
        "the staged patch must actually apply offline; stdout={stdout}"
    );

    let requests = mock.received_requests().await.unwrap_or_default();
    let hits: Vec<String> = requests
        .iter()
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect();
    assert!(
        hits.is_empty(),
        "--offline must make ZERO network requests (strict airgap), but the \
         mock server saw: {hits:?}"
    );
}

// ---------------------------------------------------------------------------
// Failed downloads must not condemn patches that already have a local source.
// ---------------------------------------------------------------------------

/// Write a `.socket/packages/<uuid>.tar.gz` carrying `entries`.
fn write_package_archive(packages: &Path, uuid: &str, entries: &[(&str, &[u8])]) {
    use std::io::Write as _;
    std::fs::create_dir_all(packages).expect("create packages dir");
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        std::fs::File::create(packages.join(format!("{uuid}.tar.gz"))).unwrap(),
        flate2::Compression::default(),
    ));
    for (name, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, *bytes).unwrap();
    }
    builder
        .into_inner()
        .unwrap()
        .finish()
        .unwrap()
        .flush()
        .unwrap();
}

/// A leftover `.socket/packages/<uuid>.tar.gz` (v5.0 no longer reads package
/// archives) is not a patch source: when the diff fetch and the blob
/// fallback both fail, apply must report the patch as unavailable instead of
/// silently patching from the stale archive.
#[tokio::test]
async fn apply_online_ignores_legacy_package_archive_when_downloads_fail() {
    let before = b"pkgcache before\n";
    let after = b"pkgcache after\n";
    let after_hash = git_sha256(after);
    let uuid = "44444444-4444-4444-8444-444444444444";

    // Nothing is served: diff and blob endpoints 404 (wiremock default for
    // unmounted routes), i.e. every download attempt fails.
    let mock = MockServer::start().await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    install_npm_pkg(tmp.path(), "pkgcache", "1.0.0", Some(before));
    let socket = tmp.path().join(".socket");
    write_manifest(
        tmp.path(),
        json!({ "pkg:npm/pkgcache@1.0.0": patch_record(uuid, one_file("package/index.js", before, after)) }),
    );
    write_package_archive(
        &socket.join("packages"),
        uuid,
        &[("package/index.js", after)],
    );

    let (code, stdout, stderr) = run_apply(tmp.path(), &mock.uri(), &[]);
    assert_ne!(
        code, 0,
        "a legacy package archive must not cover the patch; stdout={stdout}\nstderr={stderr}"
    );
    let content = std::fs::read(tmp.path().join("node_modules/pkgcache/index.js")).unwrap();
    assert_eq!(
        content, before,
        "the file must not be patched from the legacy archive"
    );

    let requests = mock.received_requests().await.unwrap_or_default();
    let blob_path = format!("/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}");
    assert!(
        requests.iter().any(|r| r.url.path() == blob_path),
        "the (404ing) blob fetch must have been attempted; got {:?}",
        requests
            .iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Multi-copy mismatch top-up: every physical copy is probed, not just the
// first.
// ---------------------------------------------------------------------------

/// Two physical copies of one PURL (a root copy plus a nested duplicate):
/// the root copy already carries the afterHash bytes, the nested one was
/// locally modified (matches NEITHER hash). The stage step fetches the full
/// afterHash blob, and the explicitly approved warn-and-overwrite policy must apply it
/// to EVERY copy, not just the first (clean, root) one.
#[tokio::test]
async fn mismatch_overwrites_every_copy_of_a_duplicated_package() {
    let before = b"before\n";
    let after = b"after\n";
    let after_hash = git_sha256(after);

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(after.to_vec()))
        .mount(&mock)
        .await;

    let uuid = "44444444-4444-4444-8444-444444444444";
    let purl = "pkg:npm/dupcopy@1.0.0";
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    // Root copy: already patched (afterHash bytes) — the probe finds no
    // mismatch here.
    install_npm_pkg(tmp.path(), "dupcopy", "1.0.0", Some(after));
    // Nested duplicate under a real intermediate package: locally modified,
    // matching neither hash.
    install_npm_pkg(tmp.path(), "parent", "1.0.0", Some(b"parent\n"));
    install_npm_pkg(
        &tmp.path().join("node_modules").join("parent"),
        "dupcopy",
        "1.0.0",
        Some(b"locally modified\n"),
    );

    let socket = tmp.path().join(".socket");
    write_manifest(
        tmp.path(),
        json!({ purl: patch_record(uuid, one_file("package/index.js", before, after)) }),
    );
    let (code, stdout, stderr) = run_apply(tmp.path(), &mock.uri(), &["--allow-patch-conflicts"]);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        code, 0,
        "both copies must apply cleanly.\nstdout={v:#}\nstderr={stderr}"
    );
    assert_eq!(
        v["summary"]["applied"], 1,
        "the drifted nested copy must be warn-overwritten.\nstdout={v:#}"
    );
    assert_eq!(v["summary"]["failed"], 0, "no copy may fail.\nstdout={v:#}");

    // The blob was fetched…
    let requests = mock.received_requests().await.unwrap();
    let blob_path = format!("/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}");
    assert!(
        requests.iter().any(|r| r.url.path() == blob_path),
        "the stage step must fetch the blob the nested copy needs; got {:?}",
        requests
            .iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
    // …and BOTH copies carry the patched bytes.
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/dupcopy/index.js")).unwrap(),
        after,
        "root copy must keep the patched bytes"
    );
    assert_eq!(
        std::fs::read(
            tmp.path()
                .join("node_modules/parent/node_modules/dupcopy/index.js")
        )
        .unwrap(),
        after,
        "the nested copy must be overwritten with the verified patched bytes"
    );

    // Apply stays read-only against the persistent cache: the fetched
    // blob lands in a transient overlay, never `.socket/blobs/`.
    let blobs_dir = socket.join("blobs");
    if blobs_dir.exists() {
        let entries: Vec<_> = std::fs::read_dir(&blobs_dir).unwrap().collect();
        assert!(
            entries.is_empty(),
            "apply must not write to .socket/blobs/; found {entries:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The API client is built on first need: an apply that fetches nothing asks
// the API nothing and prints no API advisory.
// ---------------------------------------------------------------------------

/// A token of the real shape, so the client's token-shape warning (printed
/// when a client is built) never explains a stderr difference.
const WELL_SHAPED_TOKEN: &str = "sktsec_00000000000000000000000000000000000000000000_api";

/// A project whose one patch is already applied and whose patched blob is
/// cached: `apply` has nothing to fetch and nothing to write.
fn write_already_patched_project(root: &Path) {
    let before = b"lazy client before\n";
    let after = b"lazy client after\n";
    write_root_package_json(root);
    install_npm_pkg(root, "lazy-client", "1.0.0", Some(after));
    write_manifest(
        root,
        json!({ "pkg:npm/lazy-client@1.0.0": patch_record(
            "55555555-5555-4555-8555-555555555555",
            one_file("package/index.js", before, after),
        )}),
    );
    stage_blob(root, &git_sha256(after), after);
}

/// `METHOD /path` for every request `mock` saw.
async fn request_log(mock: &MockServer) -> Vec<String> {
    mock.received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect()
}

/// CA-P01: with a token and no org, building the client asks the API for
/// the org (`GET /v0/organizations`). A no-op apply — the run CI makes
/// after every install — needs no client, so it must not ask: its only
/// request is its own telemetry event, sent on the route the credentials
/// alone select (no org is known, so the anonymous proxy).
#[tokio::test]
async fn noop_apply_with_a_token_and_no_org_never_asks_for_the_org() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v0/organizations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "organizations": { "org-1": {
                "id": "org-1", "name": "Lazy", "image": null, "plan": "free", "slug": "lazy-org"
            }}
        })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_already_patched_project(tmp.path());

    let mut cmd = hermetic::command(&binary());
    cmd.args(["apply", "--json"]).current_dir(tmp.path());
    // Telemetry on (the builder forces it off), token set, org absent, and
    // both hosts pinned to the mock so every request is seen.
    cmd.env("SOCKET_TELEMETRY_DISABLED", "0")
        .env("SOCKET_API_URL", mock.uri())
        .env("SOCKET_PROXY_URL", mock.uri())
        .env("SOCKET_API_TOKEN", WELL_SHAPED_TOKEN);
    let out = cmd.output().expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout={stdout}\nstderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json envelope");
    assert_eq!(v["events"][0]["errorCode"], "already_patched", "{v}");

    assert_eq!(
        request_log(&mock).await,
        ["POST /patch/telemetry"],
        "a no-op apply's only request is its telemetry event"
    );
    assert!(
        mock.received_requests().await.unwrap()[0]
            .headers
            .get("authorization")
            .is_none(),
        "the anonymous route never carries the bearer"
    );
}

/// CA-U07: the "No SOCKET_API_TOKEN set — using the public patch API
/// proxy" advisory describes where a fetch goes. A tokenless apply that
/// fetches nothing must not print it; one that has a blob to download
/// still does (the anti-vacuous half; its proxy is a closed loopback port).
#[test]
fn tokenless_apply_prints_the_proxy_advisory_only_when_it_fetches() {
    let run = |root: &Path| {
        let out = hermetic::command(&binary())
            .args(["apply", "--proxy-url", "http://127.0.0.1:1/"])
            .current_dir(root)
            .output()
            .expect("run socket-patch");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    write_already_patched_project(tmp.path());
    let (code, stderr) = run(tmp.path());
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        !stderr.contains("public patch API proxy"),
        "nothing was fetched, so no proxy is in use; stderr={stderr}"
    );

    // Same project with the cached blob gone and the package unpatched:
    // now the run must download, and says where from.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_already_patched_project(tmp.path());
    std::fs::remove_dir_all(tmp.path().join(".socket/blobs")).unwrap();
    std::fs::write(
        tmp.path().join("node_modules/lazy-client/index.js"),
        b"lazy client before\n",
    )
    .unwrap();
    let (code, stderr) = run(tmp.path());
    assert_eq!(code, Some(1), "the download fails; stderr={stderr}");
    assert_eq!(
        stderr.matches("public patch API proxy").count(),
        1,
        "a run that fetches says which API it uses, once; stderr={stderr}"
    );
}
