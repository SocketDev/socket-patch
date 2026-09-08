//! Coverage-gap tests for `repair`'s vendored-artifact phase
//! (`commands/repair_vendor.rs`): the record-resolution edges of pass 1
//! (corrupt ledger, dropped/moved-on manifest records, API-recovered
//! records), the tampered-state health arms (StaleUuid / Unverifiable),
//! dry-run previews of ledger/wiring reconstruction, the pristine ladder's
//! ledger-recovered registry rung (Fetched and Failed), the rebuild loop's
//! Refused/rebuild-failed arms, soft-restore fallbacks, `--ecosystems`
//! scoping, and the human (non-`--json`) output lines.
//!
//! Fixtures and helpers mirror `repair_vendor_e2e.rs` (this suite owns its
//! own copies; that file is owned by another agent).

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const ENCODED: &str = "pkg%3Anpm%2Fleft-pad%401.3.0";
const BEFORE: &[u8] = b"before\n";
const AFTER: &[u8] = b"after\n";
const AFTER_B64: &str = "YWZ0ZXIK";

const GEM_UUID: &str = "22222222-2222-4222-8222-222222222222";
const GEM_NAME: &str = "padlock";
const GEM_VERSION: &str = "1.2.0";
const GEM_PURL: &str = "pkg:gem/padlock@1.2.0";
const GEM_ENCODED: &str = "pkg%3Agem%2Fpadlock%401.2.0";
const GEMSPEC_STUB: &[u8] = b"Gem::Specification.new do |s|\n  s.name = \"padlock\"\n  s.version = \"1.2.0\"\n  s.summary = \"repair fixture\"\n  s.authors = [\"socket-patch e2e\"]\n  s.require_paths = [\"lib\"]\nend\n";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn sri_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::Sha512;
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A pristine registry tarball for left-pad@1.3.0 (BEFORE bytes).
fn pristine_tgz() -> Vec<u8> {
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (path, bytes) in [
        (
            "package/package.json",
            br#"{"name":"left-pad","version":"1.3.0"}"#.as_slice(),
        ),
        ("package/index.js", BEFORE),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// Vendorable npm project: package.json, a v3 lock whose left-pad entry
/// resolves to `resolved_url`/`integrity`, and the installed package.
fn write_fixture(root: &Path, resolved_url: &str, integrity: &str) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "covgap-repair-vendor", "version": "0.0.0" }"#,
    )
    .unwrap();
    let lock = serde_json::json!({
        "name": "covgap-repair-vendor",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "covgap-repair-vendor",
                "version": "0.0.0",
                "dependencies": { "left-pad": "^1.3.0" }
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": resolved_url,
                "integrity": integrity,
                "license": "WTFPL"
            }
        }
    });
    let mut lock_bytes = serde_json::to_vec_pretty(&lock).unwrap();
    lock_bytes.push(b'\n');
    std::fs::write(root.join("package-lock.json"), lock_bytes).unwrap();

    let pkg = root.join("node_modules/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE).unwrap();
}

fn gem_copy_rel() -> String {
    format!(".socket/vendor/gem/{GEM_UUID}/{GEM_NAME}-{GEM_VERSION}")
}

/// Hermetic bundler project (modeled on repair_vendor_e2e's): exact-pin
/// Gemfile, a bundler-4.0.15-shaped lock (`with_checksums` adds the ≥ 2.6
/// CHECKSUMS section), and the installed gem + stub gemspec under the
/// project-local `vendor/bundle` layout the ruby crawler discovers.
fn write_gem_fixture(root: &Path, with_checksums: bool) {
    std::fs::write(
        root.join("Gemfile"),
        format!("source \"https://rubygems.org\"\n\ngem \"{GEM_NAME}\", \"{GEM_VERSION}\"\n"),
    )
    .unwrap();
    let checksums = if with_checksums {
        format!(
            "CHECKSUMS\n  {GEM_NAME} ({GEM_VERSION}) sha256={}\n\n",
            "e".repeat(64)
        )
    } else {
        String::new()
    };
    std::fs::write(
        root.join("Gemfile.lock"),
        format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    {GEM_NAME} ({GEM_VERSION})\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  {GEM_NAME} (= {GEM_VERSION})\n\n\
             {checksums}BUNDLED WITH\n   4.0.15\n"
        ),
    )
    .unwrap();

    let home = root.join("vendor/bundle/ruby/3.4.0");
    let gem_dir = home.join(format!("gems/{GEM_NAME}-{GEM_VERSION}"));
    std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
    std::fs::write(gem_dir.join("lib/padlock.rb"), BEFORE).unwrap();
    std::fs::create_dir_all(home.join("specifications")).unwrap();
    std::fs::write(
        home.join(format!("specifications/{GEM_NAME}-{GEM_VERSION}.gemspec")),
        GEMSPEC_STUB,
    )
    .unwrap();
}

/// Discovery batch for any subset of the two fixtures (one mock per server:
/// wiremock's first-match-wins would otherwise hide the second batch mock).
async fn mount_batch(mock: &MockServer, include_npm: bool, include_gem: bool) {
    let mut packages = Vec::new();
    if include_npm {
        packages.push(serde_json::json!({
            "purl": PURL,
            "patches": [{
                "uuid": UUID,
                "purl": PURL,
                "tier": "free",
                "cveIds": ["CVE-2026-0001"],
                "ghsaIds": [],
                "severity": "high",
                "title": "vendor target"
            }]
        }));
    }
    if include_gem {
        packages.push(serde_json::json!({
            "purl": GEM_PURL,
            "patches": [{
                "uuid": GEM_UUID,
                "purl": GEM_PURL,
                "tier": "free",
                "cveIds": ["CVE-2026-0002"],
                "ghsaIds": [],
                "severity": "high",
                "title": "gem vendor target"
            }]
        }));
    }
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": packages,
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
}

/// by-package + view routes for `UUID` (same shapes as repair_vendor_e2e).
async fn mount_npm_routes(mock: &MockServer) {
    let before_hash = git_sha256(BEFORE);
    let after_hash = git_sha256(AFTER);
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{ENCODED}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID,
                "purl": PURL,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "Vendor patch",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash,
                    "afterHash":  after_hash,
                    "blobContent": AFTER_B64,
                }
            },
            "vulnerabilities": {
                "GHSA-aaaa-bbbb-cccc": {
                    "cves": ["CVE-2026-0001"],
                    "summary": "test vuln",
                    "severity": "high",
                    "description": "details"
                }
            },
            "description": "Vendor patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(mock)
        .await;
}

/// by-package + view routes for `GEM_UUID` with a configurable after-blob
/// (the combined-fixture test needs gem patch content that npm's cannot
/// satisfy by hash collision — both defaults share the AFTER bytes).
async fn mount_gem_routes(mock: &MockServer, after: &[u8]) {
    let before_hash = git_sha256(BEFORE);
    let after_hash = git_sha256(after);
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{GEM_ENCODED}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": GEM_UUID,
                "purl": GEM_PURL,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "Gem vendor patch",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{GEM_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": GEM_UUID,
            "purl": GEM_PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "lib/padlock.rb": {
                    "beforeHash": before_hash,
                    "afterHash":  after_hash,
                    "blobContent": b64(after),
                }
            },
            "vulnerabilities": {
                "GHSA-dddd-eeee-ffff": {
                    "cves": ["CVE-2026-0002"],
                    "summary": "gem test vuln",
                    "severity": "high",
                    "description": "details"
                }
            },
            "description": "Gem vendor patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(mock)
        .await;
}

/// Discovery + view for `UUID` (npm fixture only).
async fn mount_patch_api(mock: &MockServer) {
    mount_batch(mock, true, false).await;
    mount_npm_routes(mock).await;
}

/// Discovery + view for `GEM_UUID` (gem fixture only).
async fn mount_gem_patch_api(mock: &MockServer) {
    mount_batch(mock, false, true).await;
    mount_gem_routes(mock, AFTER).await;
}

/// Serve an after-blob for `--download-mode file` repairs.
async fn mount_blob_of(mock: &MockServer, content: &'static [u8]) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/blob/{}",
            git_sha256(content)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(content))
        .mount(mock)
        .await;
}

async fn mount_blob(mock: &MockServer) {
    mount_blob_of(mock, AFTER).await;
}

fn run_cli_with(
    root: &Path,
    mock_uri: &str,
    argv: &[&str],
    json: bool,
    envs: &[(&str, &str)],
) -> (i32, String, String) {
    let mut full = argv.to_vec();
    if json {
        full.push("--json");
    }
    full.extend_from_slice(&[
        "--api-url",
        mock_uri,
        "--api-token",
        "fake-token",
        "--org",
        ORG_SLUG,
    ]);
    let mut cmd = Command::new(binary());
    cmd.args(&full).current_dir(root);
    // Scrub every ambient `SOCKET_*` var (same rationale as
    // `covgap_commands_repair.rs::socket_cmd`: an ambient
    // `SOCKET_JSON`/`SOCKET_SILENT`/`SOCKET_OFFLINE` would flip the very
    // loud-vs-quiet and online-rebuild branches this suite pins). Tests
    // re-seed only what they deliberately control via `envs`.
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SOCKET_")
            && name.to_string_lossy() != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(name);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn run_cli(root: &Path, mock_uri: &str, argv: &[&str]) -> (i32, String, String) {
    run_cli_with(root, mock_uri, argv, true, &[])
}

/// The human-output twin of [`run_cli`]: identical flags minus `--json`
/// (every `!quiet` println/eprintln in repair_vendor.rs is dead under
/// `--json`, so these lines are only reachable here).
fn run_cli_human(root: &Path, mock_uri: &str, argv: &[&str]) -> (i32, String, String) {
    run_cli_with(root, mock_uri, argv, false, &[])
}

/// `scan --vendor --yes` to establish a vendored npm project; returns the
/// vendored tarball path.
fn vendor_project(root: &Path, mock_uri: &str) -> PathBuf {
    let (code, stdout, stderr) = run_cli(root, mock_uri, &["scan", "--vendor", "--yes"]);
    assert_eq!(code, 0, "vendor setup failed: {stdout} {stderr}");
    let tgz = root.join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"));
    assert!(tgz.is_file(), "setup must vendor the tarball");
    tgz
}

/// `scan --vendor --yes` the gem fixture; returns the vendored copy dir.
fn vendor_gem_project(root: &Path, mock_uri: &str, expected_after: &[u8]) -> PathBuf {
    let (code, stdout, stderr) = run_cli(root, mock_uri, &["scan", "--vendor", "--yes"]);
    assert_eq!(code, 0, "gem vendor setup failed: {stdout} {stderr}");
    let copy = root.join(gem_copy_rel());
    assert_eq!(
        std::fs::read(copy.join("lib/padlock.rb")).expect("vendored lib"),
        expected_after,
        "setup must vendor the patched copy"
    );
    copy
}

fn parse_env(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("bad JSON ({e}): {stdout}"))
}

fn events_of(v: &serde_json::Value) -> Vec<serde_json::Value> {
    v["events"].as_array().cloned().unwrap_or_default()
}

/// Run-level `warnings[]` (`{code, detail}`); empty when omitted.
fn warnings_of(v: &serde_json::Value) -> Vec<serde_json::Value> {
    v["warnings"].as_array().cloned().unwrap_or_default()
}

fn read_state(root: &Path) -> serde_json::Value {
    serde_json::from_str(
        &std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap()
}

fn write_state(root: &Path, state: &serde_json::Value) {
    std::fs::write(
        root.join(".socket/vendor/state.json"),
        serde_json::to_vec_pretty(state).unwrap(),
    )
    .unwrap();
}

// ───────────────────────── pass-1 record resolution ─────────────────────────

/// Corrupt `.socket/vendor/state.json` (unparseable JSON) → the vendored
/// phase surfaces `vendor_state_unreadable` as a partial failure instead of
/// silently treating the ledger as empty (repair.rs's own earlier load uses
/// `unwrap_or_default`, so this is the only place the corruption reaches
/// the user). The artifact is untouched.
#[tokio::test]
async fn repair_fails_loudly_on_corrupt_vendor_state() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());
    let tgz_bytes = std::fs::read(&tgz).unwrap();

    std::fs::write(tmp.path().join(".socket/vendor/state.json"), b"{ not json").unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert_eq!(v["status"], "partialFailure", "envelope={v}");
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["errorCode"] == "vendor_state_unreadable"
            && e["error"].as_str().unwrap_or("").contains("corrupt")),
        "envelope={v}"
    );
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        tgz_bytes,
        "an unreadable ledger must not touch the artifact"
    );
}

/// A ledger entry whose record was DROPPED from the manifest is silently
/// skipped — the vendor reconcile owns reverting it, so repair must neither
/// fail nor rebuild the disowned artifact.
#[tokio::test]
async fn repair_skips_entry_dropped_from_manifest() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());

    let manifest_path = tmp.path().join(".socket/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["patches"]
        .as_object_mut()
        .unwrap()
        .remove(PURL)
        .expect("the vendored patch must be in the manifest");
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    std::fs::remove_file(&tgz).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        !events_of(&v).iter().any(|e| e["purl"] == PURL),
        "a manifest-dropped entry is the reconcile's call, not repair's: {v}"
    );
    assert!(
        !tgz.exists(),
        "repair must not rebuild an artifact the manifest disowned"
    );
}

/// The manifest record's uuid MOVED ON (a patch update is pending): repair
/// skips with `vendor_uuid_mismatch` instead of rebuilding a stale-uuid
/// artifact.
#[tokio::test]
async fn repair_skips_when_manifest_uuid_moved_on() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    mount_blob(&mock).await; // the moved-on record is no longer vendored-in-sync: step 1 downloads its blob
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());
    let tgz_bytes = std::fs::read(&tgz).unwrap();

    let manifest_path = tmp.path().join(".socket/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["patches"][PURL]["uuid"] =
        serde_json::json!("99999999-9999-4999-8999-999999999999");
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();

    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &mock.uri(),
        &["repair", "--download-mode", "file"],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "skipped"
            && e["purl"] == PURL
            && e["errorCode"] == "vendor_uuid_mismatch"
            && e["reason"].as_str().unwrap_or("").contains("moved on")),
        "envelope={v}"
    );
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        tgz_bytes,
        "a pending re-vendor must leave the old-uuid artifact alone"
    );
}

/// Non-detached ledger entry with NO manifest at all: the record is
/// recovered from the patch API by uuid (rebuild succeeds), and the same
/// shape under `--offline` fails loudly with `vendor_artifact_unrepairable`
/// naming the missing record (covers `fetch_record_by_uuid`'s offline
/// early-return too).
#[tokio::test]
async fn repair_recovers_record_by_uuid_without_manifest_then_fails_offline() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());
    let tgz_bytes = std::fs::read(&tgz).unwrap();

    std::fs::remove_file(tmp.path().join(".socket/manifest.json")).unwrap();
    std::fs::remove_file(&tgz).unwrap();

    // Online: the (None, None) arm fetches the record by uuid and rebuilds.
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["purl"] == PURL),
        "envelope={v}"
    );
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        tgz_bytes,
        "the API-recovered record drives a byte-identical rebuild"
    );

    // Offline: the record cannot be recovered — fail closed, artifact-less.
    std::fs::remove_file(&tgz).unwrap();
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--offline"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == PURL
            && e["errorCode"] == "vendor_artifact_unrepairable"
            && e["error"]
                .as_str()
                .unwrap_or("")
                .contains("no manifest record for patch")),
        "envelope={v}"
    );
}

// ───────────────────── tampered-state health arms ─────────────────────

/// `state.json`'s artifact.path edited to a DIFFERENT (valid) uuid dir
/// while entry.uuid still matches the record: the health check reports
/// StaleUuid and repair skips with "a re-vendor is pending" — never
/// rebuilds at the stale path.
#[tokio::test]
async fn repair_skips_stale_uuid_artifact_path() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());
    let tgz_bytes = std::fs::read(&tgz).unwrap();

    let mut state = read_state(tmp.path());
    state["entries"][PURL]["artifact"]["path"] = serde_json::json!(format!(
        ".socket/vendor/npm/99999999-9999-4999-8999-999999999999/left-pad-1.3.0.tgz"
    ));
    write_state(tmp.path(), &state);

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "skipped"
            && e["purl"] == PURL
            && e["errorCode"] == "vendor_uuid_mismatch"
            && e["reason"]
                .as_str()
                .unwrap_or("")
                .contains("re-vendor is pending")),
        "envelope={v}"
    );
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        tgz_bytes,
        "the real artifact is untouched"
    );
    assert!(
        !tmp.path()
            .join(".socket/vendor/npm/99999999-9999-4999-8999-999999999999")
            .exists(),
        "nothing is built at the stale path"
    );
}

/// `state.json`'s artifact.path tampered to a NON-vendor path: the health
/// check fails closed (Unverifiable / vendor_path_unsafe) and repair
/// surfaces `vendor_artifact_unrepairable` telling the user to fix
/// state.json — it must never read, rebuild, or delete through the
/// poisoned path.
#[tokio::test]
async fn repair_fails_closed_on_unsafe_ledger_artifact_path() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());
    let tgz_bytes = std::fs::read(&tgz).unwrap();

    let mut state = read_state(tmp.path());
    state["entries"][PURL]["artifact"]["path"] = serde_json::json!("left-pad.tgz");
    write_state(tmp.path(), &state);

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == PURL
            && e["errorCode"] == "vendor_artifact_unrepairable"
            && e["error"].as_str().unwrap_or("").contains("fix state.json")),
        "envelope={v}"
    );
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        tgz_bytes,
        "the real artifact survives the fail-closed refusal"
    );
}

// ───────────── pass 2: reference with no ledger, no manifest, offline ─────────────

/// Lockfile reference with the ledger AND manifest both gone, `--offline`:
/// the failure is attributed to a SYNTHETIC purl carrying the recovered
/// uuid (`pkg:npm/unknown@<uuid>`) and advises restoring state.json or
/// re-running online. Nothing on disk is touched.
#[tokio::test]
async fn repair_no_ledger_no_manifest_offline_fails_with_synthetic_purl() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());
    let tgz_bytes = std::fs::read(&tgz).unwrap();
    let lock_bytes = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
    std::fs::remove_file(tmp.path().join(".socket/manifest.json")).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--offline"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == format!("pkg:npm/unknown@{UUID}")
            && e["errorCode"] == "vendor_artifact_missing"
            && e["error"]
                .as_str()
                .unwrap_or("")
                .contains("restore .socket/vendor/state.json or re-run online")),
        "envelope={v}"
    );
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        tgz_bytes,
        "the surviving artifact is untouched"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_bytes,
        "the lock is untouched"
    );
}

// ─────────────────────── dry-run previews ───────────────────────

/// Dry-run preview of an ANCHORED ledger reconstruction (artifact intact,
/// wired lock integrity vouches): `wouldRestoreLedgerEntry` with NO
/// `wouldRebuild`, and state.json is not recreated.
#[tokio::test]
async fn repair_dry_run_previews_anchored_ledger_restore() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    vendor_project(tmp.path(), &mock.uri());
    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    let preview = events_of(&v)
        .into_iter()
        .find(|e| e["action"] == "verified" && e["purl"] == PURL)
        .unwrap_or_else(|| panic!("expected a verified preview: {v}"));
    assert_eq!(
        preview["details"]["wouldRestoreLedgerEntry"], true,
        "envelope={v}"
    );
    assert!(
        preview["details"].get("wouldRebuild").is_none(),
        "an anchored surviving artifact previews restore-only: {preview}"
    );
    assert!(
        !tmp.path().join(".socket/vendor/state.json").exists(),
        "dry run writes no ledger"
    );
}

/// Dry-run preview of an UNANCHORED reconstruction (gem dir — no lockfile
/// integrity can vouch): `wouldRestoreLedgerEntry` AND `wouldRebuild`
/// (the fingerprint would come from a rebuild, never the live tree), and
/// neither the ledger nor the copy dir is touched.
#[tokio::test]
async fn repair_dry_run_previews_unanchored_reconstruction_rebuild() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    let copy = vendor_gem_project(tmp.path(), &mock.uri(), AFTER);
    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    let preview = events_of(&v)
        .into_iter()
        .find(|e| e["action"] == "verified" && e["purl"] == GEM_PURL)
        .unwrap_or_else(|| panic!("expected a verified preview: {v}"));
    assert_eq!(
        preview["details"]["wouldRestoreLedgerEntry"], true,
        "envelope={v}"
    );
    assert_eq!(
        preview["details"]["wouldRebuild"], true,
        "an unanchored survivor previews a trust-restoring rebuild: {preview}"
    );
    assert!(
        !tmp.path().join(".socket/vendor/state.json").exists(),
        "dry run writes no ledger"
    );
    assert_eq!(
        std::fs::read(copy.join("lib/padlock.rb")).unwrap(),
        AFTER,
        "dry run touches no artifact bytes"
    );
}

// ─────────────────── pass-1 gem wiring backfill edges ───────────────────

/// Dry-run preview of the pass-1 empty-wiring gem backfill:
/// `wouldRestoreWiring` — and the persisted wiring stays empty.
#[tokio::test]
async fn repair_dry_run_previews_gem_wiring_backfill() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    vendor_gem_project(tmp.path(), &mock.uri(), AFTER);

    let mut state = read_state(tmp.path());
    state["entries"][GEM_PURL]["wiring"] = serde_json::json!([]);
    write_state(tmp.path(), &state);

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "verified"
            && e["purl"] == GEM_PURL
            && e["details"]["wouldRestoreWiring"] == true),
        "envelope={v}"
    );
    let state = read_state(tmp.path());
    assert_eq!(
        state["entries"][GEM_PURL]["wiring"].as_array().map(Vec::len),
        Some(0),
        "dry run must not persist the backfilled wiring: {state}"
    );
}

/// The pass-1 backfill's degradation-notes loop: on a CHECKSUMS lock the
/// reconstruction succeeds with the unrecoverable-sha256 note, which must
/// ride the envelope as a skipped advisory NEXT TO the wiringRestored
/// rebuilt event.
#[tokio::test]
async fn repair_backfill_surfaces_unrecoverable_checksum_note() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), true);
    vendor_gem_project(tmp.path(), &mock.uri(), AFTER);

    let mut state = read_state(tmp.path());
    state["entries"][GEM_PURL]["wiring"] = serde_json::json!([]);
    write_state(tmp.path(), &state);

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "rebuilt"
            && e["purl"] == GEM_PURL
            && e["details"]["wiringRestored"] == true
            && e["details"]["artifactRebuilt"] == false),
        "envelope={v}"
    );
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "skipped"
            && e["purl"] == GEM_PURL
            && e["errorCode"] == "vendor_checksum_unrecoverable"),
        "the degradation note rides the envelope: {v}"
    );
    let state = read_state(tmp.path());
    assert!(
        !state["entries"][GEM_PURL]["wiring"]
            .as_array()
            .unwrap_or(&Vec::new())
            .is_empty(),
        "the backfilled wiring is persisted: {state}"
    );
}

/// Pass-1 backfill reconstruction FAILURE (Gemfile deleted while the
/// artifact stays healthy): the gap rides the run-level `warnings[]` as
/// `vendor_wiring_unknown` naming the purl — never a skipped event — the
/// run stays exit 0, and the wiring stays empty.
#[tokio::test]
async fn repair_backfill_failure_warns_wiring_unknown() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    vendor_gem_project(tmp.path(), &mock.uri(), AFTER);

    let mut state = read_state(tmp.path());
    state["entries"][GEM_PURL]["wiring"] = serde_json::json!([]);
    write_state(tmp.path(), &state);
    std::fs::remove_file(tmp.path().join("Gemfile")).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        warnings_of(&v)
            .iter()
            .any(|w| w["code"] == "vendor_wiring_unknown"
                && w["detail"].as_str().unwrap_or("").contains(GEM_PURL)
                && w["detail"]
                    .as_str()
                    .unwrap_or("")
                    .contains("cannot be reconstructed")),
        "the backfill failure rides run-level warnings[]: {v}"
    );
    assert!(
        !events_of(&v)
            .iter()
            .any(|e| e["errorCode"] == "vendor_wiring_unknown"),
        "no skipped event for the run-level advisory: {v}"
    );
    let state = read_state(tmp.path());
    assert_eq!(
        state["entries"][GEM_PURL]["wiring"].as_array().map(Vec::len),
        Some(0),
        "an unreconstructable wiring stays empty: {state}"
    );
}

/// The pass-2 twin: a NO-LEDGER gem reconstruction whose Gemfile is gone
/// maps the reconstruction error to WiringReconstruction::Unknown — the
/// run-level warning says the entry "was reconstructed without pre-vendor
/// wiring originals", the re-synthesized entry persists with empty wiring,
/// and when the soft rebuild's dispatch then REFUSES (`gemfile_missing`)
/// the healthy set-aside artifact bytes are restored, not destroyed.
#[tokio::test]
async fn repair_reconstruction_without_gemfile_warns_wiring_unknown() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    let copy = vendor_gem_project(tmp.path(), &mock.uri(), AFTER);

    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
    std::fs::remove_file(tmp.path().join("Gemfile")).unwrap();

    mount_blob(&mock).await;
    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &mock.uri(),
        &["repair", "--download-mode", "file"],
    );
    let v = parse_env(&stdout);
    assert!(
        warnings_of(&v)
            .iter()
            .any(|w| w["code"] == "vendor_wiring_unknown"
                && w["detail"].as_str().unwrap_or("").contains(GEM_PURL)
                && w["detail"]
                    .as_str()
                    .unwrap_or("")
                    .contains("was reconstructed without pre-vendor wiring originals")),
        "the pass-2 reconstruction gap rides run-level warnings[]: {v}"
    );
    // The soft rebuild's gem dispatch REFUSES without a Gemfile
    // (`gemfile_missing`), staying loud — and the refused dispatch replaced
    // nothing, so the healthy set-aside artifact is restored below.
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == GEM_PURL
            && e["errorCode"] == "gemfile_missing"),
        "envelope={v}"
    );
    let state = read_state(tmp.path());
    assert_eq!(
        state["entries"][GEM_PURL]["wiring"].as_array().map(Vec::len),
        Some(0),
        "no guessed wiring on the re-synthesized entry: {state}"
    );
    assert_eq!(
        std::fs::read(copy.join("lib/padlock.rb")).unwrap(),
        AFTER,
        "the healthy artifact bytes survive the reconstruction"
    );
}

// ────────────── pristine ladder: ledger-recovered registry rung ──────────────

/// The PristineFetch::Fetched rung under repair: artifact AND node_modules
/// gone, but the ledger's preserved pre-vendor lock fragment names a
/// fetchable, integrity-verified registry URL — the rebuild reproduces the
/// recorded bytes end-to-end.
#[tokio::test]
async fn repair_rebuilds_via_ledger_recovered_registry_fetch() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tgz_bytes = pristine_tgz();
    let integrity = sri_of(&tgz_bytes);
    Mock::given(method("GET"))
        .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz_bytes))
        .mount(&mock)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    // The PRE-VENDOR lock resolves to the mock registry with the real
    // integrity — exactly what the ledger preserves as the wiring original.
    write_fixture(
        tmp.path(),
        &format!("{}/left-pad/-/left-pad-1.3.0.tgz", mock.uri()),
        &integrity,
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());
    let vendored_bytes = std::fs::read(&tgz).unwrap();

    std::fs::remove_file(&tgz).unwrap();
    std::fs::remove_dir_all(tmp.path().join("node_modules")).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["purl"] == PURL),
        "envelope={v}"
    );
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        vendored_bytes,
        "the verified registry fetch drives a byte-identical rebuild"
    );
}

/// The same recovered-URL rung when the fetch FAILS (registry 500): a
/// non-soft candidate fails with `vendor_fetch_failed` and nothing is
/// invented on disk.
#[tokio::test]
async fn repair_fails_when_ledger_recovered_fetch_fails() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let integrity = sri_of(&pristine_tgz());
    Mock::given(method("GET"))
        .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        &format!("{}/left-pad/-/left-pad-1.3.0.tgz", mock.uri()),
        &integrity,
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());

    std::fs::remove_file(&tgz).unwrap();
    std::fs::remove_dir_all(tmp.path().join("node_modules")).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == PURL
            && e["errorCode"] == "vendor_fetch_failed"),
        "envelope={v}"
    );
    assert!(!tgz.exists(), "a failed fetch must not invent an artifact");
}

/// The UNVERIFIED-registry reconstruction rung when the conventional fetch
/// fails: `fetch_npm_unverified`'s error maps to `vendor_fetch_failed`, the
/// candidate goes unrebuildable, and the rewired lock stays byte-identical.
#[tokio::test]
async fn repair_reconstruction_unverified_fetch_failure() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    Mock::given(method("GET"))
        .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());
    let lock_bytes = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    // Fresh-clone hole: vendor tree gone AND nothing installed — only the
    // rewired lock (whose recorded integrity is the trust anchor) is left.
    std::fs::remove_dir_all(tmp.path().join(".socket/vendor")).unwrap();
    std::fs::remove_dir_all(tmp.path().join("node_modules")).unwrap();

    mount_blob(&mock).await;
    let (code, stdout, stderr) = run_cli_with(
        tmp.path(),
        &mock.uri(),
        &["repair", "--download-mode", "file"],
        true,
        &[("SOCKET_NPM_REGISTRY", &mock.uri())],
    );
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == PURL
            && e["errorCode"] == "vendor_fetch_failed"),
        "envelope={v}"
    );
    assert!(!tgz.exists(), "nothing rebuilt from the failed fetch");
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_bytes,
        "the trust-anchor lock is untouched"
    );
}

// ─────────────────── rebuild-loop failure arms ───────────────────

/// The rebuild dispatch REFUSES (package-lock.json deleted along with the
/// tarball): the backend's refusal code (`vendor_lockfile_missing`)
/// surfaces verbatim as the per-entry failure.
#[tokio::test]
async fn repair_rebuild_refused_when_lockfile_missing() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());

    std::fs::remove_file(&tgz).unwrap();
    std::fs::remove_file(tmp.path().join("package-lock.json")).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == PURL
            && e["errorCode"] == "vendor_lockfile_missing"),
        "the backend refusal code surfaces verbatim: {v}"
    );
    assert!(!tgz.exists(), "a refused dispatch replaced nothing");
}

/// The dispatch RUNS but fails (`result.success == false`): the installed
/// copy's patched file is gone, so the backend's fail-closed
/// missing-patch-file pre-check fails the rebuild —
/// `vendor_artifact_rebuild_failed` with the underlying cause.
#[tokio::test]
async fn repair_rebuild_fails_when_installed_patch_file_missing() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());

    std::fs::remove_file(&tgz).unwrap();
    // Keep package.json so the crawler still resolves the install.
    std::fs::remove_file(tmp.path().join("node_modules/left-pad/index.js")).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == PURL
            && e["errorCode"] == "vendor_artifact_rebuild_failed"
            && e["error"].as_str().unwrap_or("").contains("File not found")),
        "envelope={v}"
    );
    assert!(!tgz.exists(), "a failed dispatch replaced nothing");
}

// ─────────────────── soft-restore fallbacks ───────────────────

/// Staging itself is Unavailable (offline, one candidate's patch content
/// has no local source): the SOFT candidate is restored fingerprint-less
/// and counted rebuilt, while the non-soft sibling fails — one run, both
/// arms. The gem's content IS harvestable from its healthy artifact, but
/// staging is all-or-nothing across the candidate set, exactly the shape
/// this fallback exists for.
#[tokio::test]
async fn repair_soft_restore_when_staging_unavailable() {
    const AFTER_GEM: &[u8] = b"gem after\n";
    let mock = MockServer::start().await;
    mount_batch(&mock, true, true).await;
    mount_npm_routes(&mock).await;
    mount_gem_routes(&mock, AFTER_GEM).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    write_gem_fixture(tmp.path(), false);
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["scan", "--vendor", "--yes"]);
    assert_eq!(code, 0, "combined vendor setup failed: {stdout} {stderr}");
    let tgz = tmp
        .path()
        .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"));
    assert!(tgz.is_file(), "setup must vendor the npm tarball");
    let copy = tmp.path().join(gem_copy_rel());
    assert_eq!(
        std::fs::read(copy.join("lib/padlock.rb")).expect("vendored gem lib"),
        AFTER_GEM,
        "setup must vendor the patched gem copy"
    );

    // Ledger gone; npm artifact broken (non-soft), gem artifact healthy
    // (soft). Offline: the npm after-blob has no local source, so the
    // in-memory staging is Unavailable for the whole candidate set.
    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
    std::fs::remove_file(&tgz).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--offline"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    // The soft gem candidate: fingerprint-less restore, counted rebuilt.
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "rebuilt"
            && e["purl"] == GEM_PURL
            && e["details"]["ledgerRestored"] == true
            && e["details"]["artifactRebuilt"] == false),
        "envelope={v}"
    );
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "skipped"
            && e["purl"] == GEM_PURL
            && e["errorCode"] == "vendor_inventory_unverified"
            && e["reason"]
                .as_str()
                .unwrap_or("")
                .contains("no local source to rebuild from")),
        "the fingerprint gap is surfaced: {v}"
    );
    // The non-soft npm candidate stays a loud failure.
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == PURL
            && e["error"].as_str().unwrap_or("").contains("--offline")),
        "envelope={v}"
    );
    let state = read_state(tmp.path());
    assert!(
        state["entries"][GEM_PURL]["artifact"]["fileInventory"].is_null(),
        "no fingerprint was invented for the soft restore: {state}"
    );
    assert_eq!(
        std::fs::read(copy.join("lib/padlock.rb")).unwrap(),
        AFTER_GEM,
        "the soft-restored artifact bytes are untouched"
    );
}

/// `--offline` + soft candidate + package NOT installed: staging succeeds
/// (the healthy artifact's own blobs are harvested), but the pristine
/// ladder cannot fetch — the entry is soft-restored fingerprint-less with
/// the offline cause named.
#[tokio::test]
async fn repair_offline_soft_restore_without_installed_copy() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    let copy = vendor_gem_project(tmp.path(), &mock.uri(), AFTER);

    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
    std::fs::remove_dir_all(tmp.path().join("vendor/bundle")).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--offline"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "rebuilt"
            && e["purl"] == GEM_PURL
            && e["details"]["ledgerRestored"] == true
            && e["details"]["artifactRebuilt"] == false),
        "envelope={v}"
    );
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "skipped"
            && e["purl"] == GEM_PURL
            && e["errorCode"] == "vendor_inventory_unverified"
            && e["reason"]
                .as_str()
                .unwrap_or("")
                .contains("--offline prevents fetching")),
        "the offline cause is named: {v}"
    );
    let state = read_state(tmp.path());
    assert!(
        state["entries"][GEM_PURL]["artifact"]["fileInventory"].is_null(),
        "the live tree must not be fingerprinted in: {state}"
    );
    assert!(
        !state["entries"][GEM_PURL]["wiring"]
            .as_array()
            .unwrap_or(&Vec::new())
            .is_empty(),
        "the reconstructed wiring is persisted: {state}"
    );
    assert_eq!(
        std::fs::read(copy.join("lib/padlock.rb")).unwrap(),
        AFTER,
        "the artifact bytes are untouched"
    );
}

// ─────────────── precise unrepairable detail selection ───────────────

/// A non-soft pass-1 gem candidate with a precise Unverifiable cause
/// (artifact gone, installed copy gone, no CHECKSUMS sha recorded): the
/// recover-error detail is surfaced VERBATIM in
/// `vendor_artifact_unrepairable` — not the blanket "no verifiable pristine
/// source" text, which falsely implies the ledger recorded nothing.
#[tokio::test]
async fn repair_gem_unverifiable_reason_is_surfaced() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    let copy = vendor_gem_project(tmp.path(), &mock.uri(), AFTER);

    std::fs::remove_dir_all(&copy).unwrap();
    std::fs::remove_dir_all(tmp.path().join("vendor/bundle")).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    let failed = events_of(&v)
        .into_iter()
        .find(|e| e["action"] == "failed" && e["purl"] == GEM_PURL)
        .unwrap_or_else(|| panic!("expected a failed event: {v}"));
    assert_eq!(
        failed["errorCode"], "vendor_artifact_unrepairable",
        "{failed}"
    );
    let detail = failed["error"].as_str().unwrap_or("");
    assert!(
        detail.contains("the ledger cannot recover")
            && detail.contains("no pre-vendor Gemfile.lock checksum recorded"),
        "the precise recover-error must be surfaced verbatim: {failed}"
    );
    assert!(
        !detail.contains("no verifiable pristine source"),
        "the blanket text must not mask the precise cause: {failed}"
    );
}

// ─────────────── backend warning forwarding during rebuilds ───────────────

/// Non-`vendor_artifact_rebuilt` backend warnings surface during a repair
/// rebuild: a drifted installed copy is force-applied and its
/// `vendor_content_mismatch_overwritten` advisory rides the envelope next
/// to the rebuilt event.
#[tokio::test]
async fn repair_forwards_backend_content_mismatch_warning() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    let copy = vendor_gem_project(tmp.path(), &mock.uri(), AFTER);

    std::fs::remove_dir_all(&copy).unwrap();
    // The INSTALLED copy drifted: matches neither BEFORE nor AFTER.
    std::fs::write(
        tmp.path().join(format!(
            "vendor/bundle/ruby/3.4.0/gems/{GEM_NAME}-{GEM_VERSION}/lib/padlock.rb"
        )),
        b"drifted\n",
    )
    .unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "skipped"
            && e["purl"] == GEM_PURL
            && e["errorCode"] == "vendor_content_mismatch_overwritten"),
        "the backend advisory is forwarded: {v}"
    );
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["purl"] == GEM_PURL),
        "envelope={v}"
    );
    assert_eq!(
        std::fs::read(copy.join("lib/padlock.rb")).unwrap(),
        AFTER,
        "the rebuild force-applied the patched content"
    );
}

// ─────────────────────── --ecosystems scoping ───────────────────────

/// `repair --ecosystems <other>` must not touch out-of-scope ledger
/// entries — and the same broken entry is repaired once its ecosystem is
/// in scope.
#[tokio::test]
async fn repair_ecosystems_scope_skips_out_of_scope_entries() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());
    std::fs::remove_file(&tgz).unwrap();

    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &mock.uri(),
        &["repair", "--ecosystems", "gem"],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        !events_of(&v).iter().any(|e| e["purl"] == PURL),
        "an out-of-scope entry produces no events: {v}"
    );
    assert!(
        !tgz.exists(),
        "repair --ecosystems gem must not touch the npm artifact"
    );

    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &mock.uri(),
        &["repair", "--ecosystems", "npm"],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["purl"] == PURL),
        "envelope={v}"
    );
    assert!(tgz.is_file(), "in-scope repair rebuilds the artifact");
}

// ───────────────────────── human output ─────────────────────────

/// The human (non-`--json`) output lines: the "Rebuilding N…" header and
/// per-purl "Rebuilt …" line on stdout for a successful rebuild, and the
/// "Cannot repair vendored artifact for …" stderr line for a failure.
#[tokio::test]
async fn repair_human_output_lines() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());
    std::fs::remove_file(&tgz).unwrap();

    let (code, stdout, stderr) = run_cli_human(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(
        stdout.contains("Rebuilding 1 broken vendored artifact(s)"),
        "the rebuild header is printed: {stdout}"
    );
    assert!(
        stdout.contains(&format!("Rebuilt {PURL}")),
        "the per-purl rebuilt line is printed: {stdout}"
    );
    assert!(tgz.is_file(), "the human-mode repair still rebuilds");

    // Failure line: poison the ledger path (fail-closed Unverifiable arm).
    let mut state = read_state(tmp.path());
    state["entries"][PURL]["artifact"]["path"] = serde_json::json!("left-pad.tgz");
    write_state(tmp.path(), &state);
    let (code, stdout, stderr) = run_cli_human(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    assert!(
        stderr.contains(&format!("Cannot repair vendored artifact for {PURL}")),
        "the failure line is printed to stderr: {stderr}"
    );
}

/// The human-mode `vendor_wiring_unknown` warning line (the run-level
/// advisory's stderr twin).
#[tokio::test]
async fn repair_human_warns_wiring_unknown() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    vendor_gem_project(tmp.path(), &mock.uri(), AFTER);

    let mut state = read_state(tmp.path());
    state["entries"][GEM_PURL]["wiring"] = serde_json::json!([]);
    write_state(tmp.path(), &state);
    std::fs::remove_file(tmp.path().join("Gemfile")).unwrap();

    let (code, stdout, stderr) = run_cli_human(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(
        stderr.contains("Warning (vendor_wiring_unknown):"),
        "the run-level advisory is printed to stderr: {stderr}"
    );
}

// ────────────── unrepairable-detail selection: remaining arms ──────────────

/// A broken PLATFORM-LOCKED artifact with no pristine source anywhere (not
/// installed, no lockfile at all, ledger wiring gone): the failure detail is
/// the platform-locked advice — "reinstall the package on this platform" —
/// not the generic no-source text. `platform_locked` is a plain ledger
/// field read by repair's detail selection (eco-agnostic), so a tampered
/// npm ledger drives the branch without any pypi machinery. Deleting every
/// npm lock also exercises the wired-integrity probe's None fall-through
/// (the unverified-registry rung must NOT fire without a trust anchor).
#[tokio::test]
async fn repair_platform_locked_detail_when_no_pristine_source() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());

    std::fs::remove_file(&tgz).unwrap();
    std::fs::remove_dir_all(tmp.path().join("node_modules")).unwrap();
    std::fs::remove_file(tmp.path().join("package-lock.json")).unwrap();
    let mut state = read_state(tmp.path());
    state["entries"][PURL]["wiring"] = serde_json::json!([]);
    state["entries"][PURL]["artifact"]["platformLocked"] = serde_json::json!(true);
    write_state(tmp.path(), &state);

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    let failed = events_of(&v)
        .into_iter()
        .find(|e| {
            e["action"] == "failed"
                && e["purl"] == PURL
                && e["errorCode"] == "vendor_artifact_unrepairable"
        })
        .unwrap_or_else(|| panic!("expected an unrepairable failure: {v}"));
    assert!(
        failed["error"]
            .as_str()
            .unwrap_or("")
            .contains("platform-locked (compiled)"),
        "the platform-locked advice must win the detail selection: {failed}"
    );
    assert!(
        !tgz.exists(),
        "no artifact is invented without a pristine source"
    );
}

/// A tampered `base_purl` (version lost) inside a ledger entry whose lock
/// still records the wired trust anchor: the unverified-registry rung must
/// fail CLOSED on the unparsable coordinates (never fetch garbage), falling
/// through to the precise ledger-recovery error instead.
#[tokio::test]
async fn repair_tampered_base_purl_surfaces_precise_unverifiable_detail() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());

    std::fs::remove_file(&tgz).unwrap();
    std::fs::remove_dir_all(tmp.path().join("node_modules")).unwrap();
    let mut state = read_state(tmp.path());
    state["entries"][PURL]["wiring"] = serde_json::json!([]);
    state["entries"][PURL]["basePurl"] = serde_json::json!("pkg:npm/left-pad");
    write_state(tmp.path(), &state);

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    let failed = events_of(&v)
        .into_iter()
        .find(|e| {
            e["action"] == "failed"
                && e["purl"] == PURL
                && e["errorCode"] == "vendor_artifact_unrepairable"
        })
        .unwrap_or_else(|| panic!("expected an unrepairable failure: {v}"));
    assert!(
        failed["error"]
            .as_str()
            .unwrap_or("")
            .contains("the ledger cannot recover one"),
        "the precise recovery error must surface: {failed}"
    );
    assert!(
        !tgz.exists(),
        "unparsable coordinates must never drive a registry fetch"
    );
}

// ────────────── soft reconstruction + pristine fetch FAILURE ──────────────

/// A SOFT reconstruction (healthy-by-members, no lock integrity anchors the
/// vendored tarball) whose pristine registry fetch then FAILS (500): the
/// entry stays restored fingerprint-less with the fetch failure named —
/// never a hard failure, never a live-tree fingerprint. The lock shape: the
/// registry resolution survived for left-pad while a second spec references
/// the vendored tarball WITHOUT integrity (a hand-migrated lock), so the
/// reference is found but nothing anchors the artifact bytes.
#[tokio::test]
async fn repair_soft_restore_when_pristine_fetch_fails() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    Mock::given(method("GET"))
        .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());
    let tgz_bytes = std::fs::read(&tgz).unwrap();

    // Ledger gone, package not installed; the hand-shaped lock keeps the
    // fetchable registry resolution AND an unanchored vendored reference.
    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
    std::fs::remove_dir_all(tmp.path().join("node_modules")).unwrap();
    let lock = serde_json::json!({
        "name": "covgap-repair-vendor",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "covgap-repair-vendor",
                "version": "0.0.0",
                "dependencies": { "left-pad": "^1.3.0" }
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": format!("{}/left-pad/-/left-pad-1.3.0.tgz", mock.uri()),
                "integrity": sri_of(&pristine_tgz())
            },
            "node_modules/left-pad-vendored": {
                "version": "1.3.0",
                "resolved": format!("file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")
            }
        }
    });
    std::fs::write(
        tmp.path().join("package-lock.json"),
        serde_json::to_vec_pretty(&lock).unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "rebuilt"
            && e["purl"] == PURL
            && e["details"]["ledgerRestored"] == true
            && e["details"]["artifactRebuilt"] == false),
        "the soft candidate is restored, not failed: {v}"
    );
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "skipped"
            && e["purl"] == PURL
            && e["errorCode"] == "vendor_inventory_unverified"
            && e["reason"]
                .as_str()
                .unwrap_or("")
                .contains("the pristine fetch failed")),
        "the fetch failure is named in the fingerprint-gap advisory: {v}"
    );
    let state = read_state(tmp.path());
    assert!(
        state["entries"][PURL]["artifact"]["sha256"]
            .as_str()
            .unwrap_or("")
            .is_empty(),
        "the live tarball must never be fingerprinted in: {state}"
    );
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        tgz_bytes,
        "the healthy artifact bytes are untouched"
    );
}

// ────────────── record recovery shares ONE api client per run ──────────────

/// TWO manifest-less ledger entries recovered by uuid in one run: the
/// second lookup must reuse the cached API client (constructing per-lookup
/// would re-print the token-shape advisory N times) and still resolve its
/// record — both artifacts rebuild.
#[tokio::test]
async fn repair_recovers_multiple_records_by_uuid_sharing_one_client() {
    let mock = MockServer::start().await;
    mount_batch(&mock, true, true).await;
    mount_npm_routes(&mock).await;
    mount_gem_routes(&mock, AFTER).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    write_gem_fixture(tmp.path(), false);
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["scan", "--vendor", "--yes"]);
    assert_eq!(code, 0, "combined vendor setup failed: {stdout} {stderr}");
    let tgz = tmp
        .path()
        .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"));
    let copy = tmp.path().join(gem_copy_rel());
    assert!(tgz.is_file() && copy.is_dir(), "setup must vendor both");

    std::fs::remove_file(tmp.path().join(".socket/manifest.json")).unwrap();
    std::fs::remove_file(&tgz).unwrap();
    std::fs::remove_dir_all(&copy).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    for purl in [PURL, GEM_PURL] {
        assert!(
            events_of(&v)
                .iter()
                .any(|e| e["action"] == "rebuilt" && e["purl"] == purl),
            "both records must be recovered by uuid and rebuilt: {v}"
        );
    }
    assert!(tgz.is_file(), "the npm artifact is rebuilt");
    assert_eq!(
        std::fs::read(copy.join("lib/padlock.rb")).unwrap(),
        AFTER,
        "the gem artifact is rebuilt"
    );
}

// ────────────── purls with no vendor backend (jsr) ──────────────

/// A (tampered/hand-migrated) ledger entry keyed by a purl whose ecosystem
/// has NO vendor backend (`pkg:jsr/…`), its artifact corrupt and its
/// package "installed" (JSR cache staged via `DENO_DIR`): the dispatch
/// returns no backend, repair fails with `vendor_artifact_unrepairable`
/// naming the missing backend — and the set-aside corrupt bytes are put
/// BACK (the failed dispatch replaced nothing; forensic evidence survives).
#[tokio::test]
async fn repair_no_backend_for_purl_restores_set_aside_bytes() {
    const JSR_PURL: &str = "pkg:jsr/@std/path@0.220.0";
    const JSR_UUID: &str = "44444444-4444-4444-8444-444444444444";
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    mount_blob(&mock).await;
    // The in-memory stager recovers the jsr record's content through the
    // patch view endpoint (the corrupt artifact yields no harvest).
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{JSR_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": JSR_UUID,
            "purl": JSR_PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": git_sha256(BEFORE),
                    "afterHash":  git_sha256(AFTER),
                    "blobContent": AFTER_B64,
                }
            },
            "vulnerabilities": {},
            "description": "jsr vendor patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(&mock)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    vendor_project(tmp.path(), &mock.uri());

    // Manifest record for the jsr purl (same patch content, its own uuid).
    let manifest_path = tmp.path().join(".socket/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let mut jsr_record = manifest["patches"][PURL].clone();
    jsr_record["uuid"] = serde_json::json!(JSR_UUID);
    manifest["patches"][JSR_PURL] = jsr_record;
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();

    // Ledger entry for the jsr purl with a CORRUPT committed artifact.
    let corrupt_rel = format!(".socket/vendor/npm/{JSR_UUID}/left-pad-1.3.0.tgz");
    let mut state = read_state(tmp.path());
    let mut jsr_entry = state["entries"][PURL].clone();
    jsr_entry["uuid"] = serde_json::json!(JSR_UUID);
    jsr_entry["basePurl"] = serde_json::json!(JSR_PURL);
    jsr_entry["artifact"]["path"] = serde_json::json!(corrupt_rel);
    jsr_entry["wiring"] = serde_json::json!([]);
    state["entries"][JSR_PURL] = jsr_entry;
    write_state(tmp.path(), &state);
    let corrupt_abs = tmp.path().join(&corrupt_rel);
    std::fs::create_dir_all(corrupt_abs.parent().unwrap()).unwrap();
    std::fs::write(&corrupt_abs, b"not a tarball").unwrap();

    // "Installed" JSR copy: the staged cache layout the deno crawler walks
    // (`$DENO_DIR/npm/jsr.io/@<scope>/<name>/<version>/`), gated on a
    // deno.json project marker.
    std::fs::write(tmp.path().join("deno.json"), b"{}\n").unwrap();
    let deno_home = tempfile::tempdir().unwrap();
    let jsr_pkg = deno_home
        .path()
        .join("npm/jsr.io/@std/path/0.220.0");
    std::fs::create_dir_all(&jsr_pkg).unwrap();
    std::fs::write(jsr_pkg.join("index.js"), AFTER).unwrap();

    let (code, stdout, stderr) = run_cli_with(
        tmp.path(),
        &mock.uri(),
        &["repair", "--download-mode", "file"],
        true,
        &[("DENO_DIR", deno_home.path().to_str().unwrap())],
    );
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == JSR_PURL
            && e["errorCode"] == "vendor_artifact_unrepairable"
            && e["error"]
                .as_str()
                .unwrap_or("")
                .contains("no vendor backend for this ecosystem")),
        "envelope={v}"
    );
    assert_eq!(
        std::fs::read(&corrupt_abs).unwrap(),
        b"not a tarball",
        "the set-aside corrupt bytes must be restored after the no-backend dispatch"
    );
    assert!(
        !tmp.path()
            .join(format!(".socket/vendor/npm/{JSR_UUID}.pre-rebuild"))
            .exists(),
        "no .pre-rebuild leftover survives the restore"
    );

    // Second run, artifact now MISSING (not corrupt): no set-aside is taken
    // — there are no bytes worth keeping — and the no-backend dispatch
    // still fails loudly without inventing a .pre-rebuild dir.
    std::fs::remove_file(&corrupt_abs).unwrap();
    let (code, stdout, stderr) = run_cli_with(
        tmp.path(),
        &mock.uri(),
        &["repair", "--download-mode", "file"],
        true,
        &[("DENO_DIR", deno_home.path().to_str().unwrap())],
    );
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == JSR_PURL
            && e["errorCode"] == "vendor_artifact_unrepairable"
            && e["error"]
                .as_str()
                .unwrap_or("")
                .contains("no vendor backend for this ecosystem")),
        "envelope={v}"
    );
    assert!(
        !corrupt_abs.exists() && !tmp
            .path()
            .join(format!(".socket/vendor/npm/{JSR_UUID}.pre-rebuild"))
            .exists(),
        "a missing artifact stays missing: nothing is invented or set aside"
    );
}

// ────────── must-verify rebuild at a renamed lock reference ──────────

/// The lock's vendored reference was hand-RENAMED (leaf drift) and the
/// ledger is gone: the reconstruction records the renamed path, the rebuild
/// dispatch rebuilds/wires the CANONICAL leaf, and the trust-anchor verify
/// then cannot read the artifact at the reconstructed path — fail closed:
/// uuid dir removed ("nothing was kept") and the snapshotted trust-anchor
/// lock restored byte-for-byte (the backend's re-wire must not survive).
#[tokio::test]
async fn repair_reconstruction_renamed_leaf_fails_closed_and_restores_lock() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    vendor_project(tmp.path(), &mock.uri());

    // Rename the leaf inside the rewired lock, then lose the whole vendor
    // tree (ledger + artifact) — the fresh-clone hole plus leaf drift.
    let lock_path = tmp.path().join("package-lock.json");
    let renamed = std::fs::read_to_string(&lock_path)
        .unwrap()
        .replace("left-pad-1.3.0.tgz", "custom-left-pad.tgz");
    std::fs::write(&lock_path, &renamed).unwrap();
    std::fs::remove_dir_all(tmp.path().join(".socket/vendor")).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    let failed = events_of(&v)
        .into_iter()
        .find(|e| {
            e["action"] == "failed"
                && e["purl"] == PURL
                && e["errorCode"] == "vendor_artifact_rebuild_failed"
        })
        .unwrap_or_else(|| panic!("expected a rebuild failure: {v}"));
    assert!(
        failed["error"]
            .as_str()
            .unwrap_or("")
            .contains("cannot read the rebuilt artifact"),
        "the unreadable reconstructed path is the named cause: {failed}"
    );
    assert!(
        !tmp.path().join(format!(".socket/vendor/npm/{UUID}")).exists(),
        "nothing is kept from the rejected rebuild"
    );
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        renamed,
        "the trust-anchor lock is restored byte-for-byte from the snapshot"
    );
}

// ────────── set-aside degrades to removal when the rename is blocked ──────────

/// The eco level (`.socket/vendor/npm/`) is read-only, so the set-aside
/// rename cannot create `<uuid>.pre-rebuild`: it degrades to plain removal
/// (best-effort — the uuid dir itself survives empty, its unlink needs the
/// same read-only parent) and the rebuild trigger still fires — the corrupt
/// artifact is replaced, not wedged.
#[cfg(unix)]
#[tokio::test]
async fn repair_set_aside_blocked_rename_degrades_to_removal() {
    use std::os::unix::fs::PermissionsExt;
    if is_root() {
        eprintln!("skipped: read-only-dir contraption is inert as root");
        return;
    }
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());
    let vendored_bytes = std::fs::read(&tgz).unwrap();
    std::fs::write(&tgz, b"corrupt bytes").unwrap();

    let eco_dir = tmp.path().join(".socket/vendor/npm");
    std::fs::set_permissions(&eco_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    // Restore perms first so the tempdir always cleans up.
    std::fs::set_permissions(&eco_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["purl"] == PURL),
        "the blocked set-aside must not block the rebuild: {v}"
    );
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        vendored_bytes,
        "the rebuild replaces the corrupt bytes"
    );
    assert!(
        !eco_dir.join(format!("{UUID}.pre-rebuild")).exists(),
        "no set-aside dir can exist under the read-only eco level"
    );
}

/// Is the test process running as root? (Read-only-directory contraptions
/// are inert under euid 0, so those tests skip themselves.)
#[cfg(unix)]
fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

/// Make `.socket/vendor` read-only so `save_state`'s atomic stage-file
/// create fails (EACCES) while every read — state.json, the artifacts in
/// the writable eco subdirs — still works. Callers restore via
/// [`writable_vendor_dir`] before asserting so the tempdir always cleans up.
#[cfg(unix)]
fn readonly_vendor_dir(root: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        root.join(".socket/vendor"),
        std::fs::Permissions::from_mode(0o555),
    )
    .unwrap();
}

#[cfg(unix)]
fn writable_vendor_dir(root: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        root.join(".socket/vendor"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
}

// ────────────── ledger-write failures stay loud, everywhere ──────────────

/// Pass-1 gem wiring BACKFILL whose ledger write fails: the
/// `vendor_state_write_failed` failure is the outcome — no `wiringRestored`
/// rebuilt event may claim the backfill happened.
#[cfg(unix)]
#[tokio::test]
async fn repair_backfill_persist_failure_stays_loud() {
    if is_root() {
        eprintln!("skipped: read-only-dir contraption is inert as root");
        return;
    }
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    vendor_gem_project(tmp.path(), &mock.uri(), AFTER);

    let mut state = read_state(tmp.path());
    state["entries"][GEM_PURL]["wiring"] = serde_json::json!([]);
    write_state(tmp.path(), &state);
    readonly_vendor_dir(tmp.path());

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    writable_vendor_dir(tmp.path());
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == GEM_PURL
            && e["errorCode"] == "vendor_state_write_failed"),
        "envelope={v}"
    );
    assert!(
        !events_of(&v)
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["details"]["wiringRestored"] == true),
        "an unpersisted backfill must not claim wiringRestored: {v}"
    );
    let state = read_state(tmp.path());
    assert_eq!(
        state["entries"][GEM_PURL]["wiring"].as_array().map(Vec::len),
        Some(0),
        "the committed ledger still has the empty wiring: {state}"
    );
}

/// Pass-2 ANCHORED ledger restore whose state write fails: the failure is
/// surfaced per purl, no `ledgerRestored` event is emitted, and the intact
/// artifact is untouched.
#[cfg(unix)]
#[tokio::test]
async fn repair_anchored_restore_persist_failure_stays_loud() {
    if is_root() {
        eprintln!("skipped: read-only-dir contraption is inert as root");
        return;
    }
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());
    let tgz_bytes = std::fs::read(&tgz).unwrap();

    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
    readonly_vendor_dir(tmp.path());

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    writable_vendor_dir(tmp.path());
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == PURL
            && e["errorCode"] == "vendor_state_write_failed"),
        "envelope={v}"
    );
    assert!(
        !events_of(&v)
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["purl"] == PURL),
        "an unpersisted anchored restore must not claim ledgerRestored: {v}"
    );
    assert!(
        !tmp.path().join(".socket/vendor/state.json").exists(),
        "no ledger could be written"
    );
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        tgz_bytes,
        "the anchored artifact is untouched"
    );
}

/// The SOFT-reconstruction early persist fails: the candidate goes
/// unrebuildable up front, so the later ladder must not double-report it —
/// staging proceeds (harvest from the healthy artifact) but the pristine
/// loop and rebuild loop both skip the purl: exactly one failed event, no
/// soft-restore advisory, no rebuilt event.
#[cfg(unix)]
#[tokio::test]
async fn repair_soft_persist_failure_skips_downstream_ladder() {
    if is_root() {
        eprintln!("skipped: read-only-dir contraption is inert as root");
        return;
    }
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    let copy = vendor_gem_project(tmp.path(), &mock.uri(), AFTER);

    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
    readonly_vendor_dir(tmp.path());

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    writable_vendor_dir(tmp.path());
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    let failed: Vec<serde_json::Value> = events_of(&v)
        .into_iter()
        .filter(|e| e["action"] == "failed" && e["purl"] == GEM_PURL)
        .collect();
    assert_eq!(
        failed.len(),
        1,
        "exactly one failure for the unpersistable soft candidate: {v}"
    );
    assert_eq!(failed[0]["errorCode"], "vendor_state_write_failed", "{v}");
    assert!(
        !events_of(&v).iter().any(|e| e["purl"] == GEM_PURL
            && (e["action"] == "rebuilt"
                || e["errorCode"] == "vendor_inventory_unverified")),
        "no restore is claimed and no fingerprint advisory rides a dead restore: {v}"
    );
    assert_eq!(
        std::fs::read(copy.join("lib/padlock.rb")).unwrap(),
        AFTER,
        "the healthy artifact bytes are untouched"
    );
}

/// The Unavailable-staging fallback must ALSO skip a purl the early soft
/// persist already failed: one combined run — the gem soft candidate's
/// state write fails, the npm blob has no offline source — yields the state
/// failure for the gem (no soft-restore advisory) and the offline failure
/// for the npm candidate.
#[cfg(unix)]
#[tokio::test]
async fn repair_unavailable_staging_skips_unpersistable_soft_candidate() {
    if is_root() {
        eprintln!("skipped: read-only-dir contraption is inert as root");
        return;
    }
    const AFTER_GEM: &[u8] = b"gem after\n";
    let mock = MockServer::start().await;
    mount_batch(&mock, true, true).await;
    mount_npm_routes(&mock).await;
    mount_gem_routes(&mock, AFTER_GEM).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    write_gem_fixture(tmp.path(), false);
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["scan", "--vendor", "--yes"]);
    assert_eq!(code, 0, "combined vendor setup failed: {stdout} {stderr}");
    let tgz = tmp
        .path()
        .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"));

    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
    std::fs::remove_file(&tgz).unwrap();
    readonly_vendor_dir(tmp.path());

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--offline"]);
    writable_vendor_dir(tmp.path());
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == GEM_PURL
            && e["errorCode"] == "vendor_state_write_failed"),
        "envelope={v}"
    );
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == PURL
            && e["error"].as_str().unwrap_or("").contains("--offline")),
        "the non-soft candidate still fails on the missing source: {v}"
    );
    assert!(
        !events_of(&v).iter().any(|e| e["action"] == "rebuilt"
            || e["errorCode"] == "vendor_inventory_unverified"),
        "no restore is claimed for the unpersistable candidate: {v}"
    );
}

/// A SUCCESSFUL rebuild of a RECONSTRUCTED entry whose ledger write then
/// fails: the artifact is legitimately rebuilt on disk (and trust-anchor
/// verified), but the run reports the state failure and never claims
/// `rebuilt` (the post-verify is skipped — an unpersisted entry must not be
/// attested). A plain pass-1 rebuild never persists (nothing about the
/// entry changed), so the persist-after-rebuild step is only reachable via
/// a reconstruction (or a backend-returned entry).
#[cfg(unix)]
#[tokio::test]
async fn repair_rebuild_persist_failure_stays_loud() {
    if is_root() {
        eprintln!("skipped: read-only-dir contraption is inert as root");
        return;
    }
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri());

    // Ledger gone + artifact gone, installed copy kept: pass 2 reconstructs
    // the entry, the rebuild dispatch succeeds from the installed copy, and
    // ONLY the ledger write fails (the eco subdir stays writable).
    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
    std::fs::remove_file(&tgz).unwrap();
    readonly_vendor_dir(tmp.path());

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    writable_vendor_dir(tmp.path());
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == PURL
            && e["errorCode"] == "vendor_state_write_failed"),
        "envelope={v}"
    );
    assert!(
        !events_of(&v)
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["purl"] == PURL),
        "an unpersisted rebuild must not be claimed: {v}"
    );
    assert!(
        tgz.is_file(),
        "the rebuild itself succeeded before the ledger write failed"
    );
}

/// The INVENTORY-REFRESH persist failing: the refreshed entry cannot be
/// recorded, so the run surfaces `vendor_state_write_failed` next to the
/// `vendor_inventory_refreshed` advisory and never claims `rebuilt`.
#[cfg(unix)]
#[tokio::test]
async fn repair_inventory_refresh_persist_failure_stays_loud() {
    if is_root() {
        eprintln!("skipped: read-only-dir contraption is inert as root");
        return;
    }
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    let copy = vendor_gem_project(tmp.path(), &mock.uri(), AFTER);

    // A recorded inventory the LOCAL rebuild cannot reproduce (a phantom
    // member), plus a missing artifact: the rebuild verifies member-wise,
    // trips the inventory cross-check, and takes the refresh path.
    let mut state = read_state(tmp.path());
    state["entries"][GEM_PURL]["artifact"]["fileInventory"]["phantom.txt"] =
        serde_json::json!("0".repeat(64));
    write_state(tmp.path(), &state);
    std::fs::remove_dir_all(&copy).unwrap();
    readonly_vendor_dir(tmp.path());

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    writable_vendor_dir(tmp.path());
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "skipped"
            && e["purl"] == GEM_PURL
            && e["errorCode"] == "vendor_inventory_refreshed"),
        "the refresh advisory still rides the envelope: {v}"
    );
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == GEM_PURL
            && e["errorCode"] == "vendor_state_write_failed"),
        "envelope={v}"
    );
    assert!(
        !events_of(&v)
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["purl"] == GEM_PURL),
        "an unpersisted refresh must not be claimed rebuilt: {v}"
    );
    assert_eq!(
        std::fs::read(copy.join("lib/padlock.rb")).unwrap(),
        AFTER,
        "the member-verified rebuild is kept on disk"
    );
}
