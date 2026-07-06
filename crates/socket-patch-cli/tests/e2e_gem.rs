//! End-to-end tests for the RubyGems patch lifecycle.
//!
//! Non-ignored tests exercise crawling against a temporary directory with fake
//! gem layouts.  They do **not** require network access or a real Ruby
//! installation.
//!
//! Ignored tests exercise the full CLI against the real Socket API, using the
//! **activestorage@5.2.0** patch (UUID `4bf7fe0b-dc57-4ea8-945f-bc4a04c47a15`),
//! which fixes CVE-2022-21831 (code injection).
//!
//! # Running
//! ```sh
//! # Scan tests (no network needed)
//! cargo test -p socket-patch-cli --test e2e_gem
//!
//! # Full lifecycle (needs bundler + network)
//! cargo test -p socket-patch-cli --test e2e_gem -- --ignored
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GEM_UUID: &str = "4bf7fe0b-dc57-4ea8-945f-bc4a04c47a15";
const GEM_PURL: &str = "pkg:gem/activestorage@5.2.0";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn has_command(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Compute Git SHA-256: `SHA256("blob <len>\0" ++ content)`.
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn git_sha256_file(path: &Path) -> String {
    let content = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    git_sha256(&content)
}

fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let out: Output = Command::new(binary())
        .args(args)
        .current_dir(cwd)
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("failed to execute socket-patch binary");

    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (code, stdout, stderr)
}

fn assert_run_ok(cwd: &Path, args: &[&str], context: &str) -> (String, String) {
    let (code, stdout, stderr) = run(cwd, args);
    assert_eq!(
        code, 0,
        "{context} failed (exit {code}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    (stdout, stderr)
}

fn bundle_run(cwd: &Path, args: &[&str]) {
    let out = Command::new("bundle")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("failed to run bundle");
    assert!(
        out.status.success(),
        "bundle {args:?} failed (exit {:?}).\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Write a minimal Gemfile that installs activestorage 5.2.0.
fn write_gemfile(cwd: &Path) {
    std::fs::write(
        cwd.join("Gemfile"),
        "source 'https://rubygems.org'\ngem 'activestorage', '5.2.0'\n",
    )
    .expect("write Gemfile");
}

/// Locate the gem install directory under vendor/bundle/ruby/*/gems/activestorage-5.2.0.
fn find_gem_dir(cwd: &Path) -> PathBuf {
    let ruby_dir = cwd.join("vendor/bundle/ruby");
    for entry in std::fs::read_dir(&ruby_dir).expect("read vendor/bundle/ruby") {
        let entry = entry.unwrap();
        let gem_dir = entry.path().join("gems").join("activestorage-5.2.0");
        if gem_dir.exists() {
            return gem_dir;
        }
    }
    panic!(
        "could not find activestorage-5.2.0 gem dir under {}",
        ruby_dir.display()
    );
}

/// Read the manifest and return the files map for the gem patch.
fn read_patch_files(manifest_path: &Path) -> serde_json::Value {
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(manifest_path).unwrap()).unwrap();
    let patch = &manifest["patches"][GEM_PURL];
    assert!(patch.is_object(), "manifest should contain {GEM_PURL}");
    patch["files"].clone()
}

/// Verify all patched files match their afterHash from the manifest.
fn assert_after_hashes(gem_dir: &Path, files: &serde_json::Value) {
    for (rel_path, info) in files.as_object().expect("files object") {
        let after_hash = info["afterHash"]
            .as_str()
            .expect("afterHash should be a string");
        let full_path = gem_dir.join(rel_path);
        assert!(
            full_path.exists(),
            "patched file should exist: {}",
            full_path.display()
        );
        assert_eq!(
            git_sha256_file(&full_path),
            after_hash,
            "hash mismatch for {rel_path} after patching"
        );
    }
}

/// Verify all patched files match their beforeHash (or are removed if new).
fn assert_before_hashes(gem_dir: &Path, files: &serde_json::Value) {
    for (rel_path, info) in files.as_object().expect("files object") {
        let before_hash = info["beforeHash"].as_str().unwrap_or("");
        let full_path = gem_dir.join(rel_path);
        if before_hash.is_empty() {
            assert!(
                !full_path.exists(),
                "new file {rel_path} should be removed after rollback"
            );
        } else {
            assert_eq!(
                git_sha256_file(&full_path),
                before_hash,
                "{rel_path} should match beforeHash"
            );
        }
    }
}

/// The "files are not patched" oracle used by `test_gem_dry_run` /
/// `test_gem_save_only` (after `get --no-apply` / `get --save-only`) must
/// FAIL when the gem is actually in the applied state — otherwise a `get`
/// that wrongly applies sails through the whole test. Hermetic stand-in for
/// that masked regression: a gem dir whose files carry afterHash content
/// plus a patch-created file, checked with the exact oracle those tests run.
#[test]
fn not_patched_oracle_catches_applied_state() {
    let dir = tempfile::tempdir().unwrap();
    let gem_dir = dir.path().to_path_buf();

    let files = serde_json::json!({
        "lib/modified.rb": {
            "beforeHash": git_sha256(b"original content\n"),
            "afterHash": git_sha256(b"patched content\n"),
        },
        "lib/created.rb": {
            "beforeHash": "",
            "afterHash": git_sha256(b"new file\n"),
        },
    });

    // Applied state: modified file has afterHash content, created file exists.
    std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
    std::fs::write(gem_dir.join("lib/modified.rb"), b"patched content\n").unwrap();
    std::fs::write(gem_dir.join("lib/created.rb"), b"new file\n").unwrap();

    let oracle = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // The exact not-patched oracle the lifecycle tests run. It must be
        // anchored to the manifest's beforeHash, not a snapshot taken after
        // the command under test (which is vacuously self-consistent).
        assert_before_hashes(&gem_dir, &files);
    }));
    assert!(
        oracle.is_err(),
        "the not-patched oracle passed on a fully applied gem — it cannot \
         catch a `get --no-apply`/`--save-only` that wrongly applies"
    );

    // And it must PASS on the pristine state (no false failures).
    std::fs::write(gem_dir.join("lib/modified.rb"), b"original content\n").unwrap();
    std::fs::remove_file(gem_dir.join("lib/created.rb")).unwrap();
    assert_before_hashes(&gem_dir, &files);
}

// ---------------------------------------------------------------------------
// Scan tests (no network needed)
// ---------------------------------------------------------------------------

/// Parse `scan --json` stdout into a Value, with diagnostics on failure.
fn parse_scan_json(stdout: &str, stderr: &str) -> serde_json::Value {
    serde_json::from_str(stdout).unwrap_or_else(|e| {
        panic!("scan --json must emit valid JSON ({e}).\nstdout:\n{stdout}\nstderr:\n{stderr}")
    })
}

/// Minimal, dependency-free percent-decoder for `%XX`-escaped path segments.
/// Independent of the production encoder so it cannot rubber-stamp a buggy one.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Start a mock Socket *public proxy* that answers every per-package lookup
/// with an empty (no-patch) result. Returns the running server.
///
/// In proxy mode (no API token — `run()` strips `SOCKET_API_TOKEN`) the scan
/// issues one `GET /patch/by-package/<percent-encoded-purl>` per discovered
/// package. Capturing those requests lets us assert the *exact* PURLs the
/// gem crawler synthesized — name, version, and `pkg:gem/` ecosystem — rather
/// than trusting a self-reported count.
async fn start_proxy() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("^/patch/by-package/.+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    server
}

/// Decoded set of PURLs the scan requested from the proxy's by-package route.
async fn requested_purls(server: &MockServer) -> Vec<String> {
    let reqs = server.received_requests().await.unwrap_or_default();
    reqs.iter()
        .filter(|r| format!("{}", r.method) == "GET")
        .filter_map(|r| {
            let p = r.url.path();
            p.strip_prefix("/patch/by-package/").map(percent_decode)
        })
        .collect()
}

/// Run `scan --json` against a freshly-started mock proxy and return both the
/// parsed JSON envelope and the exact set of PURLs the crawler sent upstream.
///
/// The blocking subprocess is offloaded so the in-process mock server (running
/// on the same runtime) can service the scan's HTTP requests concurrently.
async fn scan_via_proxy(project_dir: &Path) -> (serde_json::Value, Vec<String>) {
    let server = start_proxy().await;
    let proxy_uri = server.uri();
    let dir = project_dir.to_path_buf();
    let (code, stdout, stderr) = tokio::task::spawn_blocking(move || {
        let cwd = dir.to_str().unwrap().to_string();
        run(
            &dir,
            &["scan", "--json", "--cwd", &cwd, "--proxy-url", &proxy_uri],
        )
    })
    .await
    .expect("scan task panicked");

    assert_eq!(
        code, 0,
        "scan --json should exit 0.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let json = parse_scan_json(&stdout, &stderr);
    assert_eq!(
        json["status"], "success",
        "scan status should be success.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let purls = requested_purls(&server).await;
    (json, purls)
}

/// Verify that `socket-patch scan` discovers gems in a vendor/bundle layout
/// AND parses each one into the correct `pkg:gem/<name>@<version>` PURL.
///
/// The crawl is offline (no real Ruby/network), but a mock public proxy
/// captures the per-package lookups the scan fires, so we assert the *exact*
/// PURLs the crawler synthesized — not merely a self-reported count. A
/// regression that mis-parses `rails-7.1.0` (wrong name/version split),
/// mis-classifies the ecosystem, double-counts, or lets another crawler leak
/// in now fails loudly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_discovers_vendored_gems() {
    let dir = tempfile::tempdir().unwrap();
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();

    // Create Gemfile so local mode activates
    std::fs::write(
        project_dir.join("Gemfile"),
        "source 'https://rubygems.org'\n",
    )
    .unwrap();

    // Set up vendor/bundle/ruby/<version>/gems/ layout
    let gems_dir = project_dir
        .join("vendor")
        .join("bundle")
        .join("ruby")
        .join("3.2.0")
        .join("gems");

    // Create rails-7.1.0 with lib/ marker
    let rails_dir = gems_dir.join("rails-7.1.0");
    std::fs::create_dir_all(rails_dir.join("lib")).unwrap();

    // Create nokogiri-1.15.4 with lib/ marker
    let nokogiri_dir = gems_dir.join("nokogiri-1.15.4");
    std::fs::create_dir_all(nokogiri_dir.join("lib")).unwrap();

    let (json, mut purls) = scan_via_proxy(&project_dir).await;

    // Exactly the two vendored gems — not zero (crawler regression) and not a
    // larger number (ambient discovery leaking in).
    assert_eq!(
        json["scannedPackages"].as_u64(),
        Some(2),
        "scan should discover exactly the two vendored gems (rails, nokogiri)"
    );
    // Shape invariants the contract guarantees.
    assert!(json["packages"].is_array(), "packages must be an array");
    assert!(json["updates"].is_array(), "updates must be an array");

    // The crawler must have produced EXACTLY these two PURLs and queried the
    // proxy for each — proving correct name/version split and `pkg:gem/`
    // ecosystem tagging, not just a count of two unknown things.
    purls.sort();
    assert_eq!(
        purls,
        vec![
            "pkg:gem/nokogiri@1.15.4".to_string(),
            "pkg:gem/rails@7.1.0".to_string(),
        ],
        "scan must look up the two gems by their exact PURLs"
    );
}

/// Verify that `socket-patch scan` discovers gems with gemspec markers
/// (the `.gemspec`-without-`lib/` discovery path, distinct from the lib/ path)
/// and parses the gemspec-only gem into the correct PURL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_discovers_gems_with_gemspec() {
    let dir = tempfile::tempdir().unwrap();
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();

    // Create Gemfile.lock so local mode activates
    std::fs::write(project_dir.join("Gemfile.lock"), "GEM\n  specs:\n").unwrap();

    // Set up vendor/bundle/ruby/<version>/gems/ layout
    let gems_dir = project_dir
        .join("vendor")
        .join("bundle")
        .join("ruby")
        .join("3.1.0")
        .join("gems");

    // Create net-http-0.4.1 with .gemspec marker (no lib/)
    let net_http_dir = gems_dir.join("net-http-0.4.1");
    std::fs::create_dir_all(&net_http_dir).unwrap();
    std::fs::write(net_http_dir.join("net-http.gemspec"), "# gemspec\n").unwrap();

    let (json, purls) = scan_via_proxy(&project_dir).await;

    // The single gemspec-only gem must be discovered — exactly one, proving the
    // .gemspec marker path works (a regression there would yield zero).
    assert_eq!(
        json["scannedPackages"].as_u64(),
        Some(1),
        "scan should discover exactly the one gemspec-marked gem (net-http)"
    );
    // ...and it must be parsed into the right PURL. `net-http-0.4.1` is a
    // hyphenated name immediately before the version, so a sloppy
    // last-hyphen split could mangle it — pin the exact result.
    assert_eq!(
        purls,
        vec!["pkg:gem/net-http@0.4.1".to_string()],
        "scan must look up the gemspec-only gem by its exact PURL"
    );
}

// ---------------------------------------------------------------------------
// Lifecycle tests (need bundler + network)
// ---------------------------------------------------------------------------

/// Full lifecycle: get -> list (verify CVE-2022-21831) -> rollback -> apply -> remove.
#[test]
#[ignore]
fn test_gem_full_lifecycle() {
    if !has_command("bundle") {
        eprintln!("SKIP: bundle not found on PATH");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();

    // -- Setup: create project and install activestorage@5.2.0 ----------------
    write_gemfile(cwd);
    bundle_run(cwd, &["install", "--path", "vendor/bundle"]);

    let gem_dir = find_gem_dir(cwd);

    // -- GET: download + apply patch ------------------------------------------
    assert_run_ok(cwd, &["get", GEM_UUID], "get");

    let manifest_path = cwd.join(".socket/manifest.json");
    assert!(
        manifest_path.exists(),
        ".socket/manifest.json should exist after get"
    );

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let patch = &manifest["patches"][GEM_PURL];
    assert!(patch.is_object(), "manifest should contain {GEM_PURL}");
    assert_eq!(patch["uuid"].as_str().unwrap(), GEM_UUID);

    let files = &patch["files"];
    assert!(
        files.as_object().is_some_and(|f| !f.is_empty()),
        "patch should modify at least one file"
    );

    // Files should now be patched — verify against afterHash from manifest.
    assert_after_hashes(&gem_dir, files);

    // -- LIST: verify JSON output ---------------------------------------------
    // v3.0 envelope: `list --json` emits {command,status,events,summary}
    // with one `discovered` event per manifest entry. Vulnerabilities
    // live under `details.vulnerabilities[]`.
    let (stdout, _) = assert_run_ok(cwd, &["list", "--json"], "list --json");
    let list: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let events = list["events"].as_array().expect("envelope events array");
    let patches: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["action"] == "discovered")
        .collect();
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0]["uuid"].as_str().unwrap(), GEM_UUID);
    assert_eq!(patches[0]["purl"].as_str().unwrap(), GEM_PURL);

    let vulns = patches[0]["details"]["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities array");
    assert!(
        !vulns.is_empty(),
        "patch should report at least one vulnerability"
    );

    let has_cve = vulns.iter().any(|v| {
        v["cves"]
            .as_array()
            .is_some_and(|cves| cves.iter().any(|c| c == "CVE-2022-21831"))
    });
    assert!(has_cve, "vulnerability list should include CVE-2022-21831");

    // -- ROLLBACK: restore original files -------------------------------------
    assert_run_ok(cwd, &["rollback"], "rollback");
    assert_before_hashes(&gem_dir, files);

    // -- APPLY: re-apply from manifest ----------------------------------------
    assert_run_ok(cwd, &["apply"], "apply");
    assert_after_hashes(&gem_dir, files);

    // -- REMOVE: rollback + remove from manifest ------------------------------
    assert_run_ok(cwd, &["remove", GEM_UUID], "remove");
    assert_before_hashes(&gem_dir, files);

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    assert!(
        manifest["patches"].as_object().unwrap().is_empty(),
        "manifest should be empty after remove"
    );
}

/// `get --no-apply` + `apply --dry-run` should not modify files.
#[test]
#[ignore]
fn test_gem_dry_run() {
    if !has_command("bundle") {
        eprintln!("SKIP: bundle not found on PATH");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();

    write_gemfile(cwd);
    bundle_run(cwd, &["install", "--path", "vendor/bundle"]);

    let gem_dir = find_gem_dir(cwd);

    // Download without applying.
    assert_run_ok(cwd, &["get", GEM_UUID, "--no-apply"], "get --no-apply");

    // Read manifest to get file list and expected hashes.
    let manifest_path = cwd.join(".socket/manifest.json");
    let files = read_patch_files(&manifest_path);

    // Files should still be original (not patched) — checked against the
    // manifest's beforeHash, an oracle independent of the current disk
    // state (a snapshot taken after `get --no-apply` would pass even if
    // the flag regressed and applied).
    assert_before_hashes(&gem_dir, &files);

    // Dry-run should succeed but leave files untouched.
    assert_run_ok(cwd, &["apply", "--dry-run"], "apply --dry-run");
    assert_before_hashes(&gem_dir, &files);

    // Real apply should work.
    assert_run_ok(cwd, &["apply"], "apply");
    assert_after_hashes(&gem_dir, &files);
}

/// `get --save-only` should save the patch to the manifest without applying.
#[test]
#[ignore]
fn test_gem_save_only() {
    if !has_command("bundle") {
        eprintln!("SKIP: bundle not found on PATH");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();

    write_gemfile(cwd);
    bundle_run(cwd, &["install", "--path", "vendor/bundle"]);

    let gem_dir = find_gem_dir(cwd);

    // Download with --save-only.
    assert_run_ok(cwd, &["get", GEM_UUID, "--save-only"], "get --save-only");

    // Read manifest to get file list and expected hashes.
    let manifest_path = cwd.join(".socket/manifest.json");
    let files = read_patch_files(&manifest_path);

    // Files should still be original (not patched) — checked against the
    // manifest's beforeHash, independent of the current disk state.
    assert_before_hashes(&gem_dir, &files);

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let patch = &manifest["patches"][GEM_PURL];
    assert!(patch.is_object(), "manifest should contain {GEM_PURL}");
    assert_eq!(patch["uuid"].as_str().unwrap(), GEM_UUID);

    // Real apply should work.
    assert_run_ok(cwd, &["apply"], "apply");
    assert_after_hashes(&gem_dir, &files);
}
