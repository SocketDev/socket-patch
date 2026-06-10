//! Multi-release (multi-`artifact_id`) PyPI patching coverage.
//!
//! A PyPI `package@version` can resolve to several patch variants — one
//! per release/distribution (`?artifact_id=...`, e.g. different wheels +
//! an sdist). Only the distribution actually installed in the venv can
//! apply. These tests install a real `six==1.16.0`, then drive the CLI
//! against a wiremock that advertises three release variants where only
//! one carries the on-disk file's real `beforeHash`.
//!
//! Behaviors pinned:
//!   * `scan` (narrow, default) stores only the installed-dist variant.
//!   * `scan --all-releases` (broad) stores every variant; apply still
//!     patches with the installed one.
//!   * `remove <base PURL>` over a broad manifest removes ALL variants
//!     and rolls back the file without spurious failure.
//!   * `rollback` (no id) over a broad manifest exits 0 and restores the
//!     file (non-installed variants are skipped, not failed).
//!
//! Requires `python3` with `venv` + `pip`; skipped (visibly) otherwise.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use serial_test::serial;
use sha2::{Digest, Sha256};
use socket_patch_cli::commands::remove::{run as remove_run, RemoveArgs};
use socket_patch_cli::commands::rollback::{run as rollback_run, RollbackArgs};
use socket_patch_cli::commands::scan::{run as scan_run, ScanArgs};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const PYPI_PACKAGE: &str = "six";
const PYPI_VERSION: &str = "1.16.0";

// One UUID per release variant. The "installed" wheel is the only one
// whose beforeHash matches the real on-disk six.py.
const UUID_INSTALLED: &str = "11111111-1111-4111-8111-111111111111";
const UUID_OTHER_WHEEL: &str = "22222222-2222-4222-8222-222222222222";
const UUID_SDIST: &str = "33333333-3333-4333-8333-333333333333";

const ARTIFACT_INSTALLED: &str = "wheel-cp-installed";
const ARTIFACT_OTHER_WHEEL: &str = "wheel-cp-other";
const ARTIFACT_SDIST: &str = "sdist";

const MARKER_INSTALLED: &[u8] = b"\n# SOCKET-MULTIRELEASE-INSTALLED\n";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn find_python() -> Option<&'static str> {
    for cmd in ["python3", "python", "py"] {
        let ok = Command::new(cmd)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Some(cmd);
        }
    }
    None
}

fn has_python3() -> bool {
    find_python().is_some()
}

fn venv_pip(venv: &Path) -> PathBuf {
    if cfg!(windows) {
        venv.join("Scripts").join("pip.exe")
    } else {
        venv.join("bin").join("pip")
    }
}

fn find_site_packages(venv: &Path) -> PathBuf {
    if cfg!(windows) {
        venv.join("Lib").join("site-packages")
    } else {
        let lib = venv.join("lib");
        for entry in std::fs::read_dir(&lib).expect("lib dir").flatten() {
            let sp = entry.path().join("site-packages");
            if sp.exists() {
                return sp;
            }
        }
        panic!("site-packages not found under {}", lib.display());
    }
}

/// Install `six==1.16.0` into a venv under `tmp`; return the path to the
/// installed `six.py`.
fn install_six(tmp: &Path) -> PathBuf {
    let venv = tmp.join(".venv");
    let python = find_python().expect("python interpreter not on PATH");
    let status = Command::new(python)
        .args(["-m", "venv", venv.to_str().unwrap()])
        .status()
        .expect("python venv");
    assert!(status.success(), "failed to create venv");

    let pip = venv_pip(&venv);
    let status = Command::new(&pip)
        .args([
            "install",
            "--disable-pip-version-check",
            "--quiet",
            "--no-cache-dir",
            &format!("{PYPI_PACKAGE}=={PYPI_VERSION}"),
        ])
        .status()
        .expect("pip install");
    assert!(status.success(), "failed to install {PYPI_PACKAGE}");

    let candidate = find_site_packages(&venv).join("six.py");
    assert!(candidate.exists(), "six.py not found after pip install");
    candidate
}

fn base_purl() -> String {
    format!("pkg:pypi/{PYPI_PACKAGE}@{PYPI_VERSION}")
}

fn qualified(artifact_id: &str) -> String {
    format!("{}?artifact_id={artifact_id}", base_purl())
}

/// Stand up a wiremock advertising three release variants for the base
/// PURL. Only the `installed` variant's `beforeHash` matches the real
/// on-disk six.py; the other two describe different distributions.
async fn setup_multi_release_mock(server: &MockServer, installed_before_hash: &str) {
    let base = base_purl();

    // --- batch: report the base package has patches -----------------------
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": base,
                // Ordering is deliberate: the INSTALLED variant is listed
                // LAST, never first. Selection must be driven by an on-disk
                // `beforeHash` match (`select_installed_variants`), not by
                // "keep/apply the first variant in the list". If a regression
                // ever falls back to positional selection it would pick
                // other-wheel here and the byte/marker asserts below fail.
                "patches": [
                    { "uuid": UUID_OTHER_WHEEL, "purl": qualified(ARTIFACT_OTHER_WHEEL),
                      "tier": "free", "cveIds": [], "ghsaIds": [],
                      "severity": "high", "title": "other wheel" },
                    { "uuid": UUID_SDIST, "purl": qualified(ARTIFACT_SDIST),
                      "tier": "free", "cveIds": [], "ghsaIds": [],
                      "severity": "high", "title": "sdist" },
                    { "uuid": UUID_INSTALLED, "purl": qualified(ARTIFACT_INSTALLED),
                      "tier": "free", "cveIds": [], "ghsaIds": [],
                      "severity": "high", "title": "installed wheel" },
                ]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;

    // --- by-package: all three qualified variants -------------------------
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            // Same deliberate ordering: installed variant LAST (see batch).
            "patches": [
                { "uuid": UUID_OTHER_WHEEL, "purl": qualified(ARTIFACT_OTHER_WHEEL),
                  "publishedAt": "2024-01-01T00:00:00Z", "description": "other wheel",
                  "license": "MIT", "tier": "free", "vulnerabilities": {} },
                { "uuid": UUID_SDIST, "purl": qualified(ARTIFACT_SDIST),
                  "publishedAt": "2024-01-01T00:00:00Z", "description": "sdist",
                  "license": "MIT", "tier": "free", "vulnerabilities": {} },
                { "uuid": UUID_INSTALLED, "purl": qualified(ARTIFACT_INSTALLED),
                  "publishedAt": "2024-01-01T00:00:00Z", "description": "installed wheel",
                  "license": "MIT", "tier": "free", "vulnerabilities": {} },
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;

    // --- view: per-UUID full patch with file hashes + inline blobs --------
    // Installed variant: beforeHash == real on-disk hash, so it applies.
    // Its beforeBlobContent is left as a placeholder set by the caller's
    // real bytes below (filled via mount_installed_view).
    // The two non-installed variants carry bogus distribution bytes so
    // their beforeHash never matches the on-disk file.
    let other_before = b"# six.py from a DIFFERENT wheel distribution\n";
    let mut other_after = other_before.to_vec();
    other_after.extend_from_slice(b"\n# OTHER-WHEEL-MARKER\n");
    mount_view(
        server,
        UUID_OTHER_WHEEL,
        &qualified(ARTIFACT_OTHER_WHEEL),
        &git_sha256(other_before),
        &git_sha256(&other_after),
        other_before,
        &other_after,
    )
    .await;

    let sdist_before = b"# six.py from the sdist distribution\n";
    let mut sdist_after = sdist_before.to_vec();
    sdist_after.extend_from_slice(b"\n# SDIST-MARKER\n");
    mount_view(
        server,
        UUID_SDIST,
        &qualified(ARTIFACT_SDIST),
        &git_sha256(sdist_before),
        &git_sha256(&sdist_after),
        sdist_before,
        &sdist_after,
    )
    .await;

    // Sanity: the installed variant's before hash is the real file hash.
    let _ = installed_before_hash;
}

/// Mount the view for the installed variant. Separated because it needs
/// the real on-disk `before` bytes (for rollback) and the marker-patched
/// `after` bytes computed by the test.
async fn mount_installed_view(
    server: &MockServer,
    before_hash: &str,
    after_hash: &str,
    before_bytes: &[u8],
    after_bytes: &[u8],
) {
    mount_view(
        server,
        UUID_INSTALLED,
        &qualified(ARTIFACT_INSTALLED),
        before_hash,
        after_hash,
        before_bytes,
        after_bytes,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn mount_view(
    server: &MockServer,
    uuid: &str,
    purl: &str,
    before_hash: &str,
    after_hash: &str,
    before_bytes: &[u8],
    after_bytes: &[u8],
) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "six.py": {
                    "beforeHash": before_hash,
                    "afterHash": after_hash,
                    "blobContent": b64(after_bytes),
                    "beforeBlobContent": b64(before_bytes),
                }
            },
            "vulnerabilities": {},
            "description": "multi-release fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(server)
        .await;
}

fn scan_args(tmp: &Path, api_url: String, all_releases: bool) -> ScanArgs {
    ScanArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: false,
            global_prefix: None,
            api_url,
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["pypi".to_string()]),
            download_mode: "diff".to_string(),
            dry_run: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: 100,
        // Download + apply but DON'T prune/GC: the post-sync GC sweeps
        // `beforeHash` blobs (only `afterHash` blobs are kept for apply),
        // which would force the later rollback/remove to re-fetch them
        // from the API. Keeping GC off leaves the before-blobs on disk so
        // rollback restores offline. (Prune's base-vs-qualified handling
        // is covered by `detect_prunable` unit tests.)
        apply: true,
        prune: false,
        sync: false,
        all_releases,
        vex: Default::default(),
    }
}

fn manifest_keys(tmp: &Path) -> Vec<String> {
    let path = tmp.join(".socket").join("manifest.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("manifest not found at {}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&raw).expect("manifest json");
    v["patches"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn file_has_marker(file: &Path, marker: &[u8]) -> bool {
    let bytes = std::fs::read(file).expect("read file");
    bytes.windows(marker.len()).any(|w| w == marker)
}

/// Markers that belong ONLY to the non-installed variants. They must NEVER
/// appear in the on-disk six.py: those variants' `beforeHash` does not match
/// the real file, so a correct apply leaves them untouched. If one shows up,
/// apply patched the wrong distribution into the file.
const MARKER_OTHER_WHEEL: &[u8] = b"# OTHER-WHEEL-MARKER\n";
const MARKER_SDIST: &[u8] = b"# SDIST-MARKER\n";

/// Bytes the installed `six.py` must contain after the installed variant is
/// applied (original file + the installed marker, exactly).
struct Fixture {
    six_path: PathBuf,
    server: MockServer,
    /// Original on-disk bytes (rollback/remove must restore these exactly).
    original: Vec<u8>,
    /// Expected post-apply bytes (original + installed marker, exactly).
    patched: Vec<u8>,
}

/// Common setup: install six, compute the installed variant's hashes,
/// stand up the mock.
async fn fixture(tmp: &Path) -> Fixture {
    let six_path = install_six(tmp);
    let original = std::fs::read(&six_path).expect("read six.py");
    let before_hash = git_sha256(&original);
    let mut patched = original.clone();
    patched.extend_from_slice(MARKER_INSTALLED);
    let after_hash = git_sha256(&patched);

    let server = MockServer::start().await;
    setup_multi_release_mock(&server, &before_hash).await;
    mount_installed_view(&server, &before_hash, &after_hash, &original, &patched).await;
    Fixture {
        six_path,
        server,
        original,
        patched,
    }
}

// ---------------------------------------------------------------------------
// Narrow (default): only the installed-dist variant lands in the manifest.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn narrow_scan_keeps_only_installed_release() {
    if !has_python3() {
        println!("SKIP: python3 not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let fx = fixture(tmp.path()).await;
    let six_path = &fx.six_path;

    let code = scan_run(scan_args(tmp.path(), fx.server.uri(), false)).await;
    assert_eq!(
        code, 0,
        "narrow scan (download+apply of the installed variant) must succeed"
    );

    // Manifest holds exactly the installed wheel variant.
    let keys = manifest_keys(tmp.path());
    assert_eq!(
        keys,
        vec![qualified(ARTIFACT_INSTALLED)],
        "narrow scan must store only the installed-dist variant; got {keys:?}"
    );

    // The on-disk file is EXACTLY original + installed marker — not merely
    // "contains the marker somewhere". Bit-for-bit equality also proves the
    // non-installed variants did not leak any bytes into the file.
    let on_disk = std::fs::read(six_path).expect("read six.py");
    assert_eq!(
        on_disk, fx.patched,
        "narrow apply must produce exactly original+installed-marker bytes"
    );
    assert!(
        !file_has_marker(six_path, MARKER_OTHER_WHEEL),
        "other-wheel content must never reach the file"
    );
    assert!(
        !file_has_marker(six_path, MARKER_SDIST),
        "sdist content must never reach the file"
    );
}

// ---------------------------------------------------------------------------
// Broad: every variant is downloaded; apply still picks the installed one.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn broad_scan_keeps_all_releases() {
    if !has_python3() {
        println!("SKIP: python3 not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let fx = fixture(tmp.path()).await;
    let six_path = &fx.six_path;

    let code = scan_run(scan_args(tmp.path(), fx.server.uri(), true)).await;
    assert_eq!(
        code, 0,
        "broad scan must succeed: only the installed variant applies, the \
         two non-installed variants must be skipped (hash mismatch), not failed"
    );

    // Manifest holds all three release variants.
    let mut keys = manifest_keys(tmp.path());
    keys.sort();
    let mut expected = vec![
        qualified(ARTIFACT_INSTALLED),
        qualified(ARTIFACT_OTHER_WHEEL),
        qualified(ARTIFACT_SDIST),
    ];
    expected.sort();
    assert_eq!(keys, expected, "broad scan must store every variant");

    // Apply still patches with the installed distribution's variant ONLY:
    // the file must be exactly original+installed-marker, with no bytes from
    // the other-wheel or sdist variants leaking in.
    let on_disk = std::fs::read(six_path).expect("read six.py");
    assert_eq!(
        on_disk, fx.patched,
        "broad apply must patch with the installed variant exactly, nothing else"
    );
    assert!(
        !file_has_marker(six_path, MARKER_OTHER_WHEEL),
        "other-wheel content must never reach the file"
    );
    assert!(
        !file_has_marker(six_path, MARKER_SDIST),
        "sdist content must never reach the file"
    );
}

// ---------------------------------------------------------------------------
// Remove <base PURL> over a broad manifest: removes ALL variants and
// rolls back the file with no spurious failure.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn remove_base_purl_clears_all_variants_and_rolls_back() {
    if !has_python3() {
        println!("SKIP: python3 not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let fx = fixture(tmp.path()).await;
    let six_path = &fx.six_path;

    // Broad scan to seed all three variants + apply the installed one.
    let scan_code = scan_run(scan_args(tmp.path(), fx.server.uri(), true)).await;
    assert_eq!(scan_code, 0, "seed scan must succeed");
    assert_eq!(manifest_keys(tmp.path()).len(), 3);
    assert_eq!(
        std::fs::read(six_path).expect("read six.py"),
        fx.patched,
        "precondition: installed variant should be applied before remove"
    );

    // Remove by base PURL — must match every variant and roll back.
    let remove_args = RemoveArgs {
        identifier: base_purl(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            org: Some(ORG.to_string()),
            api_url: fx.server.uri(),
            api_token: Some("fake".to_string()),
            json: true,
            yes: true,
            ecosystems: Some(vec!["pypi".to_string()]),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        skip_rollback: false,
    };
    let code = remove_run(remove_args).await;
    assert_eq!(code, 0, "remove base PURL should succeed (exit 0)");

    // Manifest emptied of the six variants.
    assert!(
        manifest_keys(tmp.path()).is_empty(),
        "all release variants should be removed from the manifest"
    );
    // File rolled back to its EXACT original bytes — not merely "marker gone"
    // (a corrupt/truncated restore would also lack the marker but be wrong).
    assert_eq!(
        std::fs::read(six_path).expect("read six.py"),
        fx.original,
        "remove should roll the on-disk file back to its original bytes exactly"
    );
}

// ---------------------------------------------------------------------------
// Rollback (no identifier) over a broad manifest: exit 0, file restored,
// non-installed variants skipped rather than failed.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn rollback_all_over_broad_manifest_succeeds() {
    if !has_python3() {
        println!("SKIP: python3 not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let fx = fixture(tmp.path()).await;
    let six_path = &fx.six_path;

    let scan_code = scan_run(scan_args(tmp.path(), fx.server.uri(), true)).await;
    assert_eq!(scan_code, 0, "seed scan must succeed");
    assert_eq!(manifest_keys(tmp.path()).len(), 3);
    assert_eq!(
        std::fs::read(six_path).expect("read six.py"),
        fx.patched,
        "precondition: installed variant should be applied before rollback"
    );

    // Rollback everything in the manifest. Before the variant-dedupe fix
    // this exited non-zero (HashMismatch on the two non-installed
    // variants against the single on-disk file).
    let rollback_args = RollbackArgs {
        identifier: None,
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            org: Some(ORG.to_string()),
            api_url: fx.server.uri(),
            api_token: Some("fake".to_string()),
            json: true,
            ecosystems: Some(vec!["pypi".to_string()]),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        one_off: false,
    };
    let code = rollback_run(rollback_args).await;
    assert_eq!(code, 0, "rollback-all over broad manifest should exit 0");

    // File restored to its EXACT original bytes.
    assert_eq!(
        std::fs::read(six_path).expect("read six.py"),
        fx.original,
        "rollback should restore the original file bytes exactly"
    );
}
