//! Repair's pre-rebuild uuid-dir clearing must never DESTROY an artifact
//! the dispatch then fails to replace. The rebuild loop clears the live
//! dir right before `dispatch_vendor_one` (the backends rebuild on
//! MISSING), but the dispatch itself can still refuse or fail — e.g. the
//! in-hand installed copy is broken in a way no pre-rebuild rung probes —
//! and a failed dispatch replaces nothing: the wired lockfiles are left
//! pointing at a bare ENOENT, and (for pass-1 corrupt candidates) the
//! forensic bytes the NOTE above repair's staging step promises to keep
//! are gone. Gem fixtures modeled on repair_vendor_e2e's.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
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

fn gem_copy_rel() -> String {
    format!(".socket/vendor/gem/{GEM_UUID}/{GEM_NAME}-{GEM_VERSION}")
}

/// Hermetic bundler project: exact-pin Gemfile, a lock modeled on real
/// bundler 4.0.15 output, and the installed gem + stub gemspec under the
/// project-local `vendor/bundle` layout the ruby crawler discovers.
fn write_gem_fixture(root: &Path) {
    std::fs::write(
        root.join("Gemfile"),
        format!("source \"https://rubygems.org\"\n\ngem \"{GEM_NAME}\", \"{GEM_VERSION}\"\n"),
    )
    .unwrap();
    std::fs::write(
        root.join("Gemfile.lock"),
        format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    {GEM_NAME} ({GEM_VERSION})\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  {GEM_NAME} (= {GEM_VERSION})\n\n\
             BUNDLED WITH\n   4.0.15\n"
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

/// Mount discovery + view for `GEM_UUID` (same shapes as repair_vendor_e2e).
async fn mount_gem_patch_api(mock: &MockServer) {
    let before_hash = git_sha256(BEFORE);
    let after_hash = git_sha256(AFTER);
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
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
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
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
                    "blobContent": AFTER_B64,
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

/// Serve the after-blob (no-ledger repairs re-download in step 1).
async fn mount_blob(mock: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/blob/{}",
            git_sha256(AFTER)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(AFTER))
        .mount(mock)
        .await;
}

fn run_cli(root: &Path, mock_uri: &str, argv: &[&str]) -> (i32, String, String) {
    let mut full = argv.to_vec();
    full.extend_from_slice(&[
        "--json",
        "--api-url",
        mock_uri,
        "--api-token",
        "fake-token",
        "--org",
        ORG_SLUG,
    ]);
    let out = Command::new(binary())
        .args(&full)
        .current_dir(root)
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .output()
        .expect("run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn parse_env(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("bad JSON ({e}): {stdout}"))
}

fn events_of(v: &serde_json::Value) -> Vec<serde_json::Value> {
    v["events"].as_array().cloned().unwrap_or_default()
}

/// `scan --vendor --yes` the gem fixture; returns the vendored copy dir.
fn vendor_gem_project(root: &Path, mock_uri: &str) -> PathBuf {
    let (code, stdout, stderr) = run_cli(root, mock_uri, &["scan", "--vendor", "--yes"]);
    assert_eq!(code, 0, "gem vendor setup failed: {stdout} {stderr}");
    let copy = root.join(gem_copy_rel());
    assert_eq!(
        std::fs::read(copy.join("lib/padlock.rb")).expect("vendored lib"),
        AFTER,
        "setup must vendor the patched copy"
    );
    copy
}

/// Ledger loss + member-healthy vendored dir → SOFT candidate; the
/// installed copy is still DISCOVERABLE (the crawler only needs the gem
/// dir with `lib/`) but its patched file is gone, so every pre-rebuild
/// soft fallback is bypassed (a rebuild source is "in hand") and the
/// dispatch itself fails the gem backend's fail-closed
/// missing_existing_patch_files pre-check. The failed dispatch replaced
/// nothing: the member-healthy artifact the wired Gemfile/Gemfile.lock
/// still resolve through must SURVIVE — a broken installed copy must
/// never be more destructive than an absent one (which keeps the tree,
/// see repair_vendor_e2e's G1d). RED before the move-aside fix: the uuid
/// dir was deleted up front and `bundle install` ENOENTs on the wired
/// path.
#[tokio::test]
async fn repair_keeps_healthy_soft_artifact_when_rebuild_dispatch_fails() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path());
    let copy = vendor_gem_project(tmp.path(), &mock.uri());
    let gemfile_wired = std::fs::read(tmp.path().join("Gemfile")).unwrap();

    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
    std::fs::remove_file(
        tmp.path()
            .join(format!(
                "vendor/bundle/ruby/3.4.0/gems/{GEM_NAME}-{GEM_VERSION}/lib/padlock.rb"
            )),
    )
    .unwrap();

    mount_blob(&mock).await;
    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &mock.uri(),
        &["repair", "--download-mode", "file"],
    );
    // The rebuild failure stays loud...
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "failed" && e["purl"] == GEM_PURL),
        "envelope={v}"
    );
    // ...but the healthy artifact must not have been destroyed.
    assert_eq!(
        std::fs::read(copy.join("lib/padlock.rb"))
            .expect("the vendored artifact must survive the failed rebuild"),
        AFTER,
        "member-healthy vendored copy intact"
    );
    assert_eq!(
        std::fs::read(copy.join("padlock.gemspec")).unwrap(),
        GEMSPEC_STUB
    );
    assert!(
        !tmp.path()
            .join(format!(".socket/vendor/gem/{GEM_UUID}.pre-rebuild"))
            .exists(),
        "no set-aside residue after the restore"
    );
    // The pre-persisted fingerprint-less entry points at real bytes, and
    // the pair is still wired to them.
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(state["entries"][GEM_PURL]["uuid"], GEM_UUID, "state={state}");
    assert_eq!(
        std::fs::read(tmp.path().join("Gemfile")).unwrap(),
        gemfile_wired,
        "the wired Gemfile is untouched"
    );
}

/// The pass-1 corrupt twin of the same root: a ledgered artifact whose
/// unpatched member was tampered (Corrupt via inventory mismatch) queues
/// a rebuild, but the dispatch REFUSES (the installed stub gemspec the
/// gem backend requires is gone). The NOTE above repair's staging step
/// promises the corrupt-but-diagnosable bytes survive every no-rebuild
/// outcome — a refusing dispatch replaced nothing, so deleting the dir
/// up front converts the forensic tamper evidence into a bare ENOENT.
/// RED before the move-aside fix.
#[tokio::test]
async fn repair_keeps_corrupt_forensic_bytes_when_rebuild_dispatch_refuses() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path());
    let copy = vendor_gem_project(tmp.path(), &mock.uri());

    // Tamper an UNPATCHED member: pass 1 flags the dir Corrupt (the
    // recorded fileInventory knows), the patched member still verifies.
    const TAMPERED: &[u8] = b"tampered stub\n";
    std::fs::write(copy.join("padlock.gemspec"), TAMPERED).unwrap();
    // The pristine ladder still finds the installed copy (rebuild source
    // "in hand"), but the dispatch refuses: the specifications stub the
    // gem backend rebuilds the gemspec from is gone.
    std::fs::remove_file(tmp.path().join(format!(
        "vendor/bundle/ruby/3.4.0/specifications/{GEM_NAME}-{GEM_VERSION}.gemspec"
    )))
    .unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "failed" && e["purl"] == GEM_PURL),
        "envelope={v}"
    );
    // The corrupt-but-diagnosable bytes survive the refusal.
    assert_eq!(
        std::fs::read(copy.join("padlock.gemspec"))
            .expect("the corrupt artifact must survive a refused rebuild"),
        TAMPERED,
        "forensic evidence of the tamper preserved"
    );
    assert_eq!(
        std::fs::read(copy.join("lib/padlock.rb")).unwrap(),
        AFTER,
        "patched member intact"
    );
    assert!(
        !tmp.path()
            .join(format!(".socket/vendor/gem/{GEM_UUID}.pre-rebuild"))
            .exists(),
        "no set-aside residue after the restore"
    );
}
