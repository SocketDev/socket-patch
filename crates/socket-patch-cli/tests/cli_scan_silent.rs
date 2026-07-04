//! `scan --silent` contract tests.
//!
//! CLI_CONTRACT.md defines `--silent` as "Errors only". Regression
//! guard: `scan` gated all of its human-readable output on `!json`
//! alone — the "No packages found" hint, the "Found N packages" /
//! "Found N patches" stderr chatter, the results table, the summary,
//! the "Patches to apply" listing, and the post-apply GC line all
//! printed under `--silent` — and the human download path hardcoded
//! `silent: false` into `DownloadParams`, so the nested apply step's
//! progress printed too. Same bug class previously fixed in `list`,
//! `repair`, `get`, and `remove`.
//!
//! The apply-flow test runs against a wiremock API (same fixture shape
//! as `scan_sync_e2e.rs`) so the full human-mode scan→select→download→
//! apply pipeline is exercised without the network.
//!
//! Stderr assertions ignore the "No SOCKET_API_TOKEN set" client
//! warning: it's printed unconditionally by
//! `get_api_client_with_overrides` in core for every command and is
//! out of scope for `scan`'s `--silent` gating.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use socket_patch_cli::args::GLOBAL_ARG_ENV_VARS;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
const UUID: &str = "11111111-1111-4111-8111-111111111111";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn write_root(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "scan-silent-test", "version": "0.0.0" }"#,
    )
    .unwrap();
}

fn write_npm_package(root: &Path, name: &str, version: &str, content: &[u8]) {
    let pkg_dir = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
    std::fs::write(pkg_dir.join("index.js"), content).unwrap();
}

/// Run `socket-patch scan` in `cwd` with a scrubbed SOCKET_* environment
/// so ambient developer/CI configuration (tokens, silent toggles) can't
/// change the branch under test.
fn run_scan(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("scan").args(args).current_dir(cwd);
    for var in GLOBAL_ARG_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd.env_remove("SOCKET_BATCH_SIZE");
    cmd.env_remove("SOCKET_ALL_RELEASES");
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch scan");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Non-error stderr lines: drop the unconditional core API-token warning
/// (both its lead line and its "Got: ... Continuing anyway" continuation)
/// and blank lines, keep everything else.
fn stderr_chatter(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter(|l| {
            !l.contains("SOCKET_API_TOKEN")
                && !l.contains("Continuing anyway")
                && !l.trim().is_empty()
        })
        .map(|l| l.to_string())
        .collect()
}

/// Mount the three endpoints the human-mode apply flow hits: batch
/// discovery, per-package search, and the full patch view (inline blob).
/// Fixture shape mirrors `scan_sync_e2e.rs`.
async fn mount_one_patch_api(mock: &MockServer, purl: &str, before: &[u8]) {
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(b"after\n");
    let encoded = purl
        .replace(':', "%3A")
        .replace('/', "%2F")
        .replace('@', "%40");

    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": UUID,
                    "purl": purl,
                    "tier": "free",
                    "cveIds": [],
                    "ghsaIds": [],
                    "severity": "high",
                    "title": "silent test patch"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID,
                "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "Silent test patch",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;

    // base64 of "after\n" — inline so the apply step needs no blob endpoint.
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash,
                    "afterHash": after_hash,
                    "blobContent": "YWZ0ZXIK",
                }
            },
            "vulnerabilities": {},
            "description": "Silent test patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(mock)
        .await;
}

/// `scan --silent` in a project with no installed packages must produce
/// no output at all (the "No packages found. Run ... install first."
/// hint is informational, not an error — the scan itself succeeded).
/// Fully offline: the crawl finds nothing, so the API is never queried.
#[test]
fn scan_silent_no_packages_produces_no_output() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root(tmp.path());

    let (code, stdout, stderr) = run_scan(tmp.path(), &["--silent"]);
    assert_eq!(
        code, 0,
        "empty scan must succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "--silent must produce no stdout; got {stdout:?}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter.is_empty(),
        "--silent must produce no stderr chatter on success; got {chatter:?}"
    );

    // Control run: the same scenario WITHOUT --silent must print the
    // hint — otherwise the assertions above pass vacuously.
    let (loud_code, loud_stdout, _) = run_scan(tmp.path(), &[]);
    assert_eq!(loud_code, 0);
    assert!(
        loud_stdout.contains("No packages found"),
        "non-silent empty scan must print the install hint; got {loud_stdout:?}"
    );
}

/// The full human-mode apply flow under `--silent --yes` must stay
/// quiet end to end: no "Found N packages" / "Found N patches" stderr
/// chatter, no results table, no "Patches to apply" listing, and no
/// download/apply progress from the nested `download_and_apply_patches`
/// call (which `scan` configured with a hardcoded `silent: false`).
/// The mutation itself must still happen.
#[tokio::test]
async fn scan_silent_apply_flow_produces_no_output_but_still_applies() {
    let purl = "pkg:npm/silent-target@1.0.0";
    let before = b"before\n";

    let mock = MockServer::start().await;
    mount_one_patch_api(&mock, purl, before).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root(tmp.path());
    write_npm_package(tmp.path(), "silent-target", "1.0.0", before);

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &[
            "--silent",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ],
    );
    assert_eq!(
        code, 0,
        "scan apply must succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "--silent must produce no stdout; got {stdout:?}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter.is_empty(),
        "--silent must produce no stderr chatter on success; got {chatter:?}"
    );

    // Silent suppresses output, not the mutation: the patch must have
    // been applied to disk and recorded in the manifest.
    let patched =
        std::fs::read(tmp.path().join("node_modules/silent-target/index.js")).expect("read file");
    assert_eq!(
        patched, b"after\n",
        "the patch must still be applied under --silent"
    );
    let manifest =
        std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).expect("read manifest");
    let v: serde_json::Value = serde_json::from_str(&manifest).expect("parse manifest");
    assert_eq!(
        v["patches"][purl]["uuid"], UUID,
        "the manifest must still record the patch under --silent"
    );

    // Control run: the same flow WITHOUT --silent must print the table
    // and the pre-apply listing — otherwise the assertions above pass
    // vacuously.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    write_root(tmp2.path());
    write_npm_package(tmp2.path(), "silent-target", "1.0.0", before);
    let (loud_code, loud_stdout, loud_stderr) = run_scan(
        tmp2.path(),
        &[
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ],
    );
    assert_eq!(
        loud_code, 0,
        "control run must succeed; stderr={loud_stderr:?}"
    );
    assert!(
        loud_stdout.contains("PACKAGE"),
        "non-silent scan must print the results table; got {loud_stdout:?}"
    );
    assert!(
        loud_stdout.contains("Patches to apply:"),
        "non-silent scan must print the pre-apply listing; got {loud_stdout:?}"
    );
    assert!(
        loud_stderr.contains("Found 1 packages"),
        "non-silent scan must print the crawl summary on stderr; got {loud_stderr:?}"
    );
}

/// A v3 package-lock with a single registry-resolved dependency, so the
/// `--vendor` flow can rewire it to the vendored artifact (the npm vendor
/// backend keys off lock entries).
fn write_npm_lock(root: &Path) {
    let lock = serde_json::json!({
        "name": "scan-silent-test",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "scan-silent-test",
                "version": "0.0.0",
                "dependencies": { "silent-target": "^1.0.0" }
            },
            "node_modules/silent-target": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/silent-target/-/silent-target-1.0.0.tgz",
                "integrity": "sha512-orig==",
                "license": "MIT"
            }
        }
    });
    let mut bytes = serde_json::to_vec_pretty(&lock).unwrap();
    bytes.push(b'\n');
    std::fs::write(root.join("package-lock.json"), bytes).unwrap();
}

/// Seed `.socket/manifest.json` with an entry for a package that is NOT
/// installed, so a `--prune` pass has something to prune.
fn seed_manifest_with_gone_entry(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let manifest = serde_json::json!({
        "patches": {
            "pkg:npm/gone@1.0.0": {
                "uuid": "99999999-9999-4999-8999-999999999999",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": {
                    "package/index.js": {
                        "beforeHash": "0".repeat(64),
                        "afterHash": "a".repeat(64),
                    }
                },
                "vulnerabilities": {},
                "description": "seed",
                "license": "MIT",
                "tier": "free",
            }
        }
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

/// The vendored-mode GC line must honor `--silent` like the apply-mode one
/// does: `scan --vendor --prune --silent --yes` prints nothing when it
/// succeeds. Regression guard: `run_vendor_interactive_path` printed
/// "GC: pruned N manifest entries." (and the vendored-revert GC line)
/// unconditionally.
#[tokio::test]
async fn scan_vendor_silent_gc_prints_nothing() {
    let purl = "pkg:npm/silent-target@1.0.0";
    let before = b"before\n";

    let mock = MockServer::start().await;
    mount_one_patch_api(&mock, purl, before).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root(tmp.path());
    write_npm_lock(tmp.path());
    write_npm_package(tmp.path(), "silent-target", "1.0.0", before);
    seed_manifest_with_gone_entry(tmp.path());

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &[
            "--vendor",
            "--prune",
            "--silent",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ],
    );
    assert_eq!(
        code, 0,
        "scan --vendor --prune must succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "--silent must produce no stdout (regression: the vendor path's \
         GC line printed unconditionally); got {stdout:?}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter.is_empty(),
        "--silent must produce no stderr chatter on success; got {chatter:?}"
    );

    // Silent suppresses output, not the work: the prune and the vendoring
    // both still happened.
    let manifest =
        std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).expect("read manifest");
    let v: serde_json::Value = serde_json::from_str(&manifest).expect("parse manifest");
    assert!(
        v["patches"]["pkg:npm/gone@1.0.0"].is_null(),
        "the uninstalled entry must still be pruned under --silent: {v}"
    );
    assert_eq!(v["patches"][purl]["uuid"], UUID, "manifest={v}");
    assert!(
        tmp.path()
            .join(format!(".socket/vendor/npm/{UUID}/silent-target-1.0.0.tgz"))
            .is_file(),
        "the package must still be vendored under --silent"
    );

    // Control run: the same scenario WITHOUT --silent must print the GC
    // line — otherwise the assertions above pass vacuously.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    write_root(tmp2.path());
    write_npm_lock(tmp2.path());
    write_npm_package(tmp2.path(), "silent-target", "1.0.0", before);
    seed_manifest_with_gone_entry(tmp2.path());
    let (loud_code, loud_stdout, loud_stderr) = run_scan(
        tmp2.path(),
        &[
            "--vendor",
            "--prune",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ],
    );
    assert_eq!(
        loud_code, 0,
        "control run must succeed; stderr={loud_stderr:?}"
    );
    assert!(
        loud_stdout.contains("GC: pruned 1 manifest entry."),
        "non-silent vendor scan must print the GC line; got {loud_stdout:?}"
    );
}

/// Errors must still print under `--silent` ("errors only", not
/// "nothing"): when every API batch fails, the failure message keeps
/// its stderr output and exit 1 — but the informational "Found N
/// packages" line that precedes it must still be suppressed.
#[tokio::test]
async fn scan_silent_keeps_error_output() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root(tmp.path());
    write_npm_package(tmp.path(), "silent-target", "1.0.0", b"before\n");

    let (code, _stdout, stderr) = run_scan(
        tmp.path(),
        &[
            "--silent",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ],
    );
    assert_eq!(
        code, 1,
        "all-batches-failed scan must exit 1; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("API batch queries failed"),
        "--silent must NOT suppress error output; got {stderr:?}"
    );
    assert!(
        !stderr.contains("Found 1 packages"),
        "--silent must suppress the informational crawl summary even on \
         the error path; got {stderr:?}"
    );
}
