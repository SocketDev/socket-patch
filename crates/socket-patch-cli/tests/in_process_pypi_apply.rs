//! In-process full-apply test for the pypi ecosystem.
//!
//! Real install → real on-disk hash computation → wiremock with
//! matching hashes → in-process `socket-patch apply` → assert file is
//! patched on disk. This is the canonical "install + patch" flow the
//! user expects in production.
//!
//! Requires: `python3` with `venv` and `pip` on PATH. Skipped (with a
//! `println!` to make the skip visible) when python3 is missing.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use serial_test::serial;
use sha2::{Digest, Sha256};
use socket_patch_cli::commands::apply::{run as apply_run, ApplyArgs};
use socket_patch_cli::commands::scan::{run as scan_run, ScanArgs};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "12121212-1212-4121-8121-121212121212";
const PYPI_PACKAGE: &str = "six";
const PYPI_VERSION: &str = "1.16.0";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Resolve an available Python executable. Tries `python3` (Unix
/// convention) first, then `python` (the canonical Windows name —
/// `python3` is uncommon on Windows installs) and finally `py` (the
/// Windows launcher). Mirrors `find_python_command` in the core
/// crawler so the test environment matches what the crawler probes.
fn find_python() -> Option<&'static str> {
    for cmd in ["python3", "python", "py"] {
        let ok = python_cmd(cmd)
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

/// Build a `Command` for a python/pip spawn with the hostile ambient env
/// scrubbed. Any `PIP_*` var silently reconfigures every pip invocation:
/// `PIP_DRY_RUN=1` turns `pip install` into an exit-0 no-op and
/// `PIP_TARGET` diverts the install outside the venv — both verified to
/// leave the venv without `six.py`, stranding all four tests at the
/// "six.py not found" assert. `PYTHONHOME`/`PYTHONPATH` reshape the
/// interpreter the venv is built from, so they're cleared too. The two
/// verified hostile values are seeded and then scrubbed — `env_remove`
/// clears the seed as well, so the child never sees it, but if the scrub
/// is ever dropped the seeds (not a developer's ambient shell) turn the
/// suite red immediately.
fn python_cmd(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut cmd = Command::new(program);
    cmd.env("PIP_DRY_RUN", "1")
        .env("PIP_TARGET", "/nonexistent")
        .env_remove("PIP_DRY_RUN")
        .env_remove("PIP_TARGET")
        .env_remove("PYTHONHOME")
        .env_remove("PYTHONPATH");
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("PIP_") {
            cmd.env_remove(&k);
        }
    }
    cmd
}

/// Path to `pip` inside the given venv. PEP-405 mandates a different
/// layout per platform: `Scripts\pip.exe` on Windows,
/// `bin/pip` on Unix.
fn venv_pip(venv: &Path) -> PathBuf {
    if cfg!(windows) {
        venv.join("Scripts").join("pip.exe")
    } else {
        venv.join("bin").join("pip")
    }
}

/// Install the test package in a venv inside `tmp`. Returns the path
/// to the installed `six.py` file.
fn install_six(tmp: &Path) -> PathBuf {
    let venv = tmp.join(".venv");
    let python = find_python().expect("python interpreter not on PATH");
    let status = python_cmd(python)
        .args(["-m", "venv", venv.to_str().unwrap()])
        .status()
        .expect("python venv");
    assert!(status.success(), "failed to create venv");

    let pip = venv_pip(&venv);
    let status = python_cmd(&pip)
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
    assert!(
        candidate.exists(),
        "six.py not found at {} after pip install",
        candidate.display()
    );
    candidate
}

/// Locate the venv's `site-packages` directory. The layout depends on
/// platform per PEP-405:
///  * Unix: `<venv>/lib/python<MAJOR>.<MINOR>/site-packages/` — the
///    interpreter version is part of the path so we glob it.
///  * Windows: `<venv>\Lib\site-packages\` — no version subdirectory.
fn find_site_packages(venv: &Path) -> PathBuf {
    if cfg!(windows) {
        let sp = venv.join("Lib").join("site-packages");
        assert!(
            sp.exists(),
            "Windows venv site-packages not found at {}",
            sp.display()
        );
        sp
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

async fn setup_pypi_apply_mock(
    server: &MockServer,
    before_hash: &str,
    after_hash: &str,
    patched_bytes: &[u8],
) {
    let purl = format!("pkg:pypi/{PYPI_PACKAGE}@{PYPI_VERSION}");
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(patched_bytes);

    // Batch search: report the patch for the installed PURL.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": UUID, "purl": purl,
                    "tier": "free", "cveIds": [], "ghsaIds": [],
                    "severity": "high", "title": "pypi e2e fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;

    // The full patch view: file path "six.py" (pypi convention — no
    // `package/` prefix; path is relative to site-packages).
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "six.py": {
                    "beforeHash": before_hash,
                    "afterHash":  after_hash,
                    "blobContent": blob_b64,
                }
            },
            "vulnerabilities": {},
            "description": "pypi e2e fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(server)
        .await;
}

// ---------------------------------------------------------------------------
// Full install → scan --sync (download + apply) → verify file patched
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_install_scan_sync_patches_real_file() {
    if !has_python3() {
        println!("SKIP: python3 not on PATH");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let six_path = install_six(tmp.path());

    // Read the real installed bytes + compute the real before-hash.
    let original = std::fs::read(&six_path).expect("read six.py");
    let before_hash = git_sha256(&original);

    // Synthesize patched content with a recognizable marker.
    let mut patched = original.clone();
    patched.extend_from_slice(b"\n# SOCKET-PATCH-E2E-MARKER\n");
    let after_hash = git_sha256(&patched);

    let server = MockServer::start().await;
    setup_pypi_apply_mock(&server, &before_hash, &after_hash, &patched).await;

    let mut args = ScanArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: false,
            global_prefix: None,
            api_url: server.uri(),
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["pypi".to_string()]),
            download_mode: "diff".to_string(),
            dry_run: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: 100,
        apply: false,
        prune: false,
        sync: true,
        vendor: false,
        detached: false,
        redirect: false,
        mode: None,
        all_releases: false,
        vex: Default::default(),
    };
    // Avoid borrow problem with into_iter
    let _ = &mut args;
    let code = scan_run(args).await;
    // A successful scan --sync that discovers + applies the patch must
    // exit 0. Accepting `|| code == 1` would let a failed apply (which
    // also exits 1) pass, so we require the success code.
    assert_eq!(code, 0, "scan --sync should succeed (exit 0)");

    // The on-disk file must be byte-for-byte the patched content the
    // mock served — not merely "contains the marker somewhere", which
    // would also pass if apply corrupted/truncated the rest of the file.
    let after = std::fs::read(&six_path).expect("read patched six.py");
    assert_ne!(after, original, "file was not modified by scan --sync");
    assert_eq!(
        after, patched,
        "patched file does not match the served blob byte-for-byte"
    );
    // And its real on-disk hash must equal the served afterHash, proving
    // the apply landed exactly the content keyed by the manifest.
    assert_eq!(
        git_sha256(&after),
        after_hash,
        "on-disk hash does not match served afterHash"
    );
}

/// As above, but uses `apply --force` instead of `scan --sync`. This
/// exercises the read-only apply path (no online fetch needed since
/// scan --sync writes the manifest + blob).
#[tokio::test]
#[serial]
async fn pypi_scan_then_apply_force_patches_real_file() {
    if !has_python3() {
        println!("SKIP: python3 not on PATH");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let six_path = install_six(tmp.path());
    let original = std::fs::read(&six_path).expect("read six.py");
    let before_hash = git_sha256(&original);
    let mut patched = original.clone();
    patched.extend_from_slice(b"\n# SOCKET-PATCH-MARKER-APPLY-FORCE\n");
    let after_hash = git_sha256(&patched);

    let server = MockServer::start().await;
    setup_pypi_apply_mock(&server, &before_hash, &after_hash, &patched).await;

    // 1. scan --sync to write the manifest + blob.
    let scan_args = ScanArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: false,
            global_prefix: None,
            api_url: server.uri(),
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["pypi".to_string()]),
            download_mode: "diff".to_string(),
            dry_run: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: 100,
        apply: false,
        prune: false,
        sync: true,
        vendor: false,
        detached: false,
        redirect: false,
        mode: None,
        all_releases: false,
        vex: Default::default(),
    };
    let scan_code = scan_run(scan_args).await;
    assert_eq!(scan_code, 0, "scan --sync should succeed (exit 0)");

    // scan --sync itself applies the patch, so the marker is already on
    // disk here. If we asserted the marker now, the subsequent apply
    // --force would be a no-op the test could never detect. Revert the
    // file to its pristine bytes so the apply step has real work to do —
    // this is what makes the apply path actually under test.
    std::fs::write(&six_path, &original).expect("revert six.py");
    let reverted = std::fs::read(&six_path).expect("read reverted six.py");
    assert_eq!(reverted, original, "failed to revert file before apply");
    assert_eq!(
        git_sha256(&reverted),
        before_hash,
        "reverted file must match the served beforeHash"
    );

    // 2. Now run apply --offline --force separately. Exercises the
    // read-only-cache path in apply.rs.
    let apply_args = ApplyArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            dry_run: false,
            silent: true,
            manifest_path: ".socket/manifest.json".to_string(),
            offline: true,
            global: false,
            global_prefix: None,
            ecosystems: Some(vec!["pypi".to_string()]),
            json: true,
            verbose: false,
            download_mode: "diff".to_string(),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        force: true,
        check: false,
        vex: Default::default(),
    };
    let apply_code = apply_run(apply_args).await;
    assert_eq!(
        apply_code, 0,
        "apply --offline --force should succeed (exit 0)"
    );

    // The apply step (not scan) must have re-patched the reverted file
    // to exactly the served blob.
    let after = std::fs::read(&six_path).expect("read after apply");
    assert_eq!(
        after, patched,
        "apply --force did not produce the served blob byte-for-byte"
    );
    assert_eq!(
        git_sha256(&after),
        after_hash,
        "on-disk hash after apply does not match served afterHash"
    );
}

// ---------------------------------------------------------------------------
// Dry-run preserves the file
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_apply_dry_run_does_not_modify_file() {
    if !has_python3() {
        println!("SKIP: python3 not on PATH");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let six_path = install_six(tmp.path());
    let original = std::fs::read(&six_path).expect("read six.py");
    let before_hash = git_sha256(&original);
    let mut patched = original.clone();
    patched.extend_from_slice(b"\n# DRY-RUN-MARKER\n");
    let after_hash = git_sha256(&patched);

    let server = MockServer::start().await;
    setup_pypi_apply_mock(&server, &before_hash, &after_hash, &patched).await;

    let scan_args = ScanArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: false,
            global_prefix: None,
            api_url: server.uri(),
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["pypi".to_string()]),
            download_mode: "diff".to_string(),
            dry_run: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: 100,
        apply: true,
        prune: false,
        sync: false,
        vendor: false,
        detached: false,
        redirect: false,
        mode: None,
        all_releases: false,
        vex: Default::default(),
    };
    // Require success: otherwise an early crash (before the apply path
    // is ever reached) would leave the file untouched and let this test
    // pass without ever exercising the dry-run apply logic it guards.
    let dry_code = scan_run(scan_args).await;
    assert_eq!(
        dry_code, 0,
        "scan --apply --dry-run should succeed (exit 0)"
    );

    let after = std::fs::read(&six_path).expect("read after dry-run");
    assert_eq!(
        after, original,
        "dry-run must not modify the installed file"
    );
    assert_eq!(
        git_sha256(&after),
        before_hash,
        "dry-run changed the file hash"
    );

    // "File unchanged" alone is a vacuous oracle: it is satisfied just as
    // well by a crawler that discovered nothing or a scan that no-op'd
    // before ever reaching the apply path. To prove the dry-run path
    // actually had real work to *decline*, assert the crawler discovered
    // six and queried the batch endpoint with its PURL — the same
    // observable proof of discovery used by the crawler sanity test.
    let purl = format!("pkg:pypi/{PYPI_PACKAGE}@{PYPI_VERSION}");
    let requests = server.received_requests().await.expect("recording enabled");
    let batch_bodies: Vec<String> = requests
        .iter()
        .filter(|r| r.url.path() == format!("/v0/orgs/{ORG}/patches/batch"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect();
    assert!(
        !batch_bodies.is_empty(),
        "dry-run never queried the batch endpoint — discovery did not run, \
         so the file being unmodified proves nothing about dry-run apply"
    );
    assert!(
        batch_bodies.iter().any(|b| b.contains(&purl)),
        "dry-run batch request did not include the discovered six PURL {purl}; \
         the unchanged file does not prove dry-run suppressed a real patch; \
         bodies: {batch_bodies:?}"
    );
    // Discovery alone still doesn't pin the APPLY path: a scan that
    // degraded to plain listing (e.g. a broken `--apply` → agent-mode
    // fold in `resolve_mode_flags`) also queries batch with the purl,
    // exits 0, and leaves the file untouched — vacuously green. In JSON
    // mode only the agent-mode apply branch fetches per-package patch
    // details (`discover_selected`, which runs before the dry-run gate),
    // so requiring that fetch proves dry-run reached the apply path with
    // a real patch selected and then declined to write. Mutation-verified:
    // dropping the `--apply` fold passes every assert above but fails here.
    assert!(
        requests.iter().any(|r| r
            .url
            .path()
            .starts_with(&format!("/v0/orgs/{ORG}/patches/by-package/"))),
        "dry-run never fetched per-package patch details — the agent-mode \
         apply branch did not run, so the unchanged file proves nothing \
         about dry-run apply"
    );
}

// ---------------------------------------------------------------------------
// Discovery sanity check — the crawler finds six in the venv
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_crawler_finds_real_installed_six() {
    if !has_python3() {
        println!("SKIP: python3 not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let _ = install_six(tmp.path());

    // Sanity: site-packages should contain a six dist-info dir.
    let site_packages = find_site_packages(&tmp.path().join(".venv"));
    let has_dist_info = std::fs::read_dir(&site_packages)
        .expect("site-packages")
        .flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with("six-1.16.0"));
    assert!(has_dist_info, "six-1.16.0.dist-info should be present");

    // Now run scan and assert discovery via mock.
    let server = MockServer::start().await;
    let purl = format!("pkg:pypi/{PYPI_PACKAGE}@{PYPI_VERSION}");
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": UUID, "purl": purl, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "low",
                    "title": "discovery sanity"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let args = ScanArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: false,
            global_prefix: None,
            api_url: server.uri(),
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["pypi".to_string()]),
            download_mode: "diff".to_string(),
            dry_run: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: 100,
        apply: false,
        prune: false,
        sync: false,
        vendor: false,
        detached: false,
        redirect: false,
        mode: None,
        all_releases: false,
        vex: Default::default(),
    };
    assert_eq!(scan_run(args).await, 0);

    // scan exits 0 even when it discovers nothing, so the exit code
    // alone does not prove the crawler found six. Verify the crawler
    // actually sent six's PURL to the batch endpoint — that is the
    // observable proof of discovery.
    let requests = server.received_requests().await.expect("recording enabled");
    let batch_bodies: Vec<String> = requests
        .iter()
        .filter(|r| r.url.path() == format!("/v0/orgs/{ORG}/patches/batch"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect();
    assert!(
        !batch_bodies.is_empty(),
        "crawler never queried the batch endpoint"
    );
    assert!(
        batch_bodies.iter().any(|b| b.contains(&purl)),
        "batch request did not include the discovered six PURL {purl}; bodies: {batch_bodies:?}"
    );
}
