//! End-to-end tests for the PyPI patch lifecycle.
//!
//! These tests exercise the full CLI against the real Socket API, using the
//! **pydantic-ai@0.0.36** patch (UUID `725a5343-52ec-4290-b7ce-e1cec55878e1`),
//! which fixes CVE-2026-25580 (SSRF in URL Download Handling).
//!
//! # Prerequisites
//! - `python3` on PATH (with `venv` and `pip` modules)
//! - Network access to `patches-api.socket.dev` and `pypi.org`
//!
//! # Running
//! ```sh
//! cargo test -p socket-patch-cli --test e2e_pypi -- --ignored
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PYPI_UUID: &str = "725a5343-52ec-4290-b7ce-e1cec55878e1";
const PYPI_PURL_PREFIX: &str = "pkg:pypi/pydantic-ai@0.0.36";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn has_python3() -> bool {
    Command::new("python3")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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

/// Run the CLI binary with the given args, setting `cwd` as the working dir.
fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let out: Output = Command::new(binary())
        .args(args)
        .current_dir(cwd)
        .env_remove("SOCKET_API_TOKEN") // force public proxy (free-tier)
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

/// Find the `site-packages` directory inside a venv.
///
/// On Unix: `.venv/lib/python3.X/site-packages`
/// On Windows: `.venv/Lib/site-packages`
fn find_site_packages(cwd: &Path) -> PathBuf {
    let venv = cwd.join(".venv");
    if cfg!(windows) {
        let sp = venv.join("Lib").join("site-packages");
        assert!(sp.exists(), "site-packages not found at {}", sp.display());
        return sp;
    }
    // Unix: glob for python3.* directory
    let lib = venv.join("lib");
    for entry in std::fs::read_dir(&lib).expect("read .venv/lib") {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("python3.") {
            let sp = entry.path().join("site-packages");
            if sp.exists() {
                return sp;
            }
        }
    }
    panic!("site-packages not found under {}", lib.display());
}

/// Create a venv and install pydantic-ai (without transitive deps for speed).
fn setup_venv(cwd: &Path) {
    let status = Command::new("python3")
        .args(["-m", "venv", ".venv"])
        .current_dir(cwd)
        .status()
        .expect("failed to create venv");
    assert!(status.success(), "python3 -m venv failed");

    let pip = if cfg!(windows) {
        cwd.join(".venv/Scripts/pip")
    } else {
        cwd.join(".venv/bin/pip")
    };

    // Install both the meta-package (for dist-info that matches the PURL)
    // and the slim package (for the actual Python source files).
    // --no-deps keeps the install fast by skipping transitive dependencies.
    let out = Command::new(&pip)
        .args([
            "install",
            "--no-deps",
            "--disable-pip-version-check",
            "pydantic-ai==0.0.36",
            "pydantic-ai-slim==0.0.36",
        ])
        .current_dir(cwd)
        .output()
        .expect("failed to run pip install");
    assert!(
        out.status.success(),
        "pip install failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Read the manifest and return the files map for the pydantic-ai patch.
/// Returns `(purl, files)` where files is `{ relative_path: { beforeHash, afterHash } }`.
fn read_patch_files(manifest_path: &Path) -> (String, serde_json::Value) {
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(manifest_path).unwrap()).unwrap();

    let patches = manifest["patches"].as_object().expect("patches object");
    let (purl, patch) = patches
        .iter()
        .find(|(k, _)| k.starts_with(PYPI_PURL_PREFIX))
        .unwrap_or_else(|| panic!("no patch matching {PYPI_PURL_PREFIX} in manifest"));

    (purl.clone(), patch["files"].clone())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Full lifecycle: get → verify hashes → list → rollback → apply → remove.
#[test]
#[ignore]
fn test_pypi_full_lifecycle() {
    if !has_python3() {
        eprintln!("SKIP: python3 not found on PATH");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();

    // -- Setup: create venv and install pydantic-ai@0.0.36 ----------------
    setup_venv(cwd);

    let site_packages = find_site_packages(cwd);
    assert!(
        site_packages.join("pydantic_ai").exists(),
        "pydantic_ai package should be installed in site-packages"
    );

    // Record original hashes of all files that will be patched.
    // We'll compare against these after rollback.
    let files_to_check = [
        "pydantic_ai/messages.py",
        "pydantic_ai/models/__init__.py",
        "pydantic_ai/models/anthropic.py",
        "pydantic_ai/models/gemini.py",
        "pydantic_ai/models/openai.py",
    ];
    let original_hashes: Vec<(String, String)> = files_to_check
        .iter()
        .map(|f| {
            let path = site_packages.join(f);
            let hash = if path.exists() {
                git_sha256_file(&path)
            } else {
                String::new() // file doesn't exist yet (e.g., _ssrf.py)
            };
            (f.to_string(), hash)
        })
        .collect();

    // -- GET: download + apply patch ---------------------------------------
    assert_run_ok(cwd, &["get", PYPI_UUID], "get");

    let manifest_path = cwd.join(".socket/manifest.json");
    assert!(manifest_path.exists(), ".socket/manifest.json should exist after get");

    // Parse the manifest to get file hashes from the API.
    let (purl, files_value) = read_patch_files(&manifest_path);
    assert!(
        purl.starts_with(PYPI_PURL_PREFIX),
        "purl should start with {PYPI_PURL_PREFIX}, got {purl}"
    );

    let files = files_value.as_object().expect("files should be an object");
    assert!(!files.is_empty(), "patch should modify at least one file");

    // The patch must genuinely change content: at least one file's beforeHash
    // must differ from its afterHash (a brand-new file with an empty beforeHash
    // also counts). Without this, every "applied"/"restored"/"unchanged"
    // assertion below is vacuous — a no-op implementation would stay green.
    let nontrivial = files.iter().any(|(_, info)| {
        info["beforeHash"].as_str().unwrap_or("") != info["afterHash"].as_str().unwrap_or("")
    });
    assert!(
        nontrivial,
        "patch must change at least one file (some beforeHash != afterHash)"
    );

    // Verify every file's hash matches the afterHash from the manifest.
    for (rel_path, info) in files {
        let after_hash = info["afterHash"]
            .as_str()
            .expect("afterHash should be a string");
        let full_path = site_packages.join(rel_path);
        assert!(
            full_path.exists(),
            "patched file should exist: {}",
            full_path.display()
        );
        assert_eq!(
            git_sha256_file(&full_path),
            after_hash,
            "hash mismatch for {rel_path} after get"
        );
    }

    // Independent oracle: at least one file recorded BEFORE any CLI ran must
    // have actually changed on disk. This catches a `get` that writes nothing
    // (or whose manifest afterHash was copied from the pristine file).
    let disk_changed = original_hashes.iter().any(|(rel, orig)| {
        let p = site_packages.join(rel);
        !orig.is_empty() && p.exists() && git_sha256_file(&p) != *orig
    });
    assert!(
        disk_changed,
        "get should have modified at least one already-existing file on disk"
    );

    // -- LIST: verify JSON output ------------------------------------------
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
    assert_eq!(patches.len(), 1, "should have exactly one patch");
    assert_eq!(patches[0]["uuid"].as_str().unwrap(), PYPI_UUID);

    // Verify vulnerability
    let vulns = patches[0]["details"]["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities array");
    assert!(!vulns.is_empty(), "should have vulnerability info");
    let has_cve = vulns.iter().any(|v| {
        v["cves"]
            .as_array()
            .map_or(false, |cves| cves.iter().any(|c| c == "CVE-2026-25580"))
    });
    assert!(has_cve, "vulnerability list should include CVE-2026-25580");

    // -- ROLLBACK: restore original files ----------------------------------
    assert_run_ok(cwd, &["rollback"], "rollback");

    // Verify files are restored to their original state.
    for (rel_path, info) in files {
        let before_hash = info["beforeHash"].as_str().unwrap_or("");
        let full_path = site_packages.join(rel_path);

        if before_hash.is_empty() {
            // New file — should be deleted after rollback.
            assert!(
                !full_path.exists(),
                "new file {rel_path} should be removed after rollback"
            );
        } else {
            // Existing file — hash should match beforeHash.
            assert_eq!(
                git_sha256_file(&full_path),
                before_hash,
                "{rel_path} should match beforeHash after rollback"
            );
        }
    }

    // Also verify against our originally recorded hashes.
    for (rel_path, orig_hash) in &original_hashes {
        if orig_hash.is_empty() {
            continue; // file didn't exist before
        }
        let full_path = site_packages.join(rel_path);
        if full_path.exists() {
            assert_eq!(
                git_sha256_file(&full_path),
                *orig_hash,
                "{rel_path} should match original hash after rollback"
            );
        }
    }

    // -- APPLY: re-apply from manifest ------------------------------------
    assert_run_ok(cwd, &["apply"], "apply");

    for (rel_path, info) in files {
        let after_hash = info["afterHash"]
            .as_str()
            .expect("afterHash should be a string");
        let full_path = site_packages.join(rel_path);
        assert_eq!(
            git_sha256_file(&full_path),
            after_hash,
            "{rel_path} should match afterHash after re-apply"
        );
    }

    // -- REMOVE: rollback + remove from manifest ---------------------------
    assert_run_ok(cwd, &["remove", PYPI_UUID], "remove");

    // `remove` is rollback + manifest removal, so the files must be restored,
    // not just the manifest cleared. Verify both against the manifest's
    // beforeHash (new files removed, existing files reverted).
    for (rel_path, info) in files {
        let before_hash = info["beforeHash"].as_str().unwrap_or("");
        let full_path = site_packages.join(rel_path);
        if before_hash.is_empty() {
            assert!(
                !full_path.exists(),
                "new file {rel_path} should be removed after remove"
            );
        } else {
            assert_eq!(
                git_sha256_file(&full_path),
                before_hash,
                "{rel_path} should be restored to beforeHash after remove"
            );
        }
    }

    // Manifest should be empty.
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    assert!(
        manifest["patches"].as_object().unwrap().is_empty(),
        "manifest should be empty after remove"
    );
}

/// `apply --dry-run` should not modify files on disk.
#[test]
#[ignore]
fn test_pypi_dry_run() {
    if !has_python3() {
        eprintln!("SKIP: python3 not found on PATH");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();

    setup_venv(cwd);

    let site_packages = find_site_packages(cwd);

    // Record original hashes.
    let messages_py = site_packages.join("pydantic_ai/messages.py");
    assert!(messages_py.exists());
    let original_hash = git_sha256_file(&messages_py);

    // Download without applying.
    assert_run_ok(cwd, &["get", PYPI_UUID, "--no-apply"], "get --no-apply");

    // File should be unchanged.
    assert_eq!(
        git_sha256_file(&messages_py),
        original_hash,
        "file should not change after get --no-apply"
    );

    // Read the manifest and snapshot the pre-apply on-disk state of EVERY
    // patched file, so we can prove dry-run touched none of them.
    let manifest_path = cwd.join(".socket/manifest.json");
    let (_, files_value) = read_patch_files(&manifest_path);
    let files = files_value.as_object().unwrap();
    assert!(!files.is_empty(), "manifest should record patched files");

    // The patch must be non-trivial; otherwise "unchanged after dry-run" is
    // vacuously true even for a completely broken apply.
    let nontrivial = files.iter().any(|(_, info)| {
        info["beforeHash"].as_str().unwrap_or("") != info["afterHash"].as_str().unwrap_or("")
    });
    assert!(nontrivial, "patch must change at least one file");

    let pre_state: Vec<(String, Option<String>)> = files
        .keys()
        .map(|rel| {
            let p = site_packages.join(rel);
            let h = if p.exists() { Some(git_sha256_file(&p)) } else { None };
            (rel.clone(), h)
        })
        .collect();

    // Dry-run should leave EVERY patched file untouched (no edits, no new files).
    assert_run_ok(cwd, &["apply", "--dry-run"], "apply --dry-run");
    for (rel, before) in &pre_state {
        let p = site_packages.join(rel);
        match before {
            Some(h) => assert_eq!(
                &git_sha256_file(&p),
                h,
                "{rel} must be unchanged after apply --dry-run"
            ),
            None => assert!(
                !p.exists(),
                "{rel} must not be created by apply --dry-run"
            ),
        }
    }

    // Real apply should bring every file to afterHash, and must actually move
    // at least one file off its pre-apply state.
    assert_run_ok(cwd, &["apply"], "apply");
    let mut any_changed = false;
    for (rel, info) in files {
        let after_hash = info["afterHash"].as_str().expect("afterHash");
        let p = site_packages.join(rel);
        assert_eq!(
            git_sha256_file(&p),
            after_hash,
            "{rel} should match afterHash after real apply"
        );
        let pre = pre_state
            .iter()
            .find(|(r, _)| r == rel)
            .and_then(|(_, h)| h.clone());
        if pre.as_deref() != Some(after_hash) {
            any_changed = true;
        }
    }
    assert!(
        any_changed,
        "real apply must modify at least one file relative to its pre-apply state"
    );
}

/// Global lifecycle: scan → get → rollback → apply → remove using `-g --global-prefix`.
#[test]
#[ignore]
fn test_pypi_global_lifecycle() {
    if !has_python3() {
        eprintln!("SKIP: python3 not found on PATH");
        return;
    }

    let global_dir = tempfile::tempdir().unwrap();
    let cwd_dir = tempfile::tempdir().unwrap();
    let cwd = cwd_dir.path();

    // -- Setup: pip install --target into global_dir -------------------------
    let out = Command::new("python3")
        .args([
            "-m",
            "pip",
            "install",
            "--target",
            global_dir.path().to_str().unwrap(),
            "--no-deps",
            "--disable-pip-version-check",
            "pydantic-ai==0.0.36",
            "pydantic-ai-slim==0.0.36",
        ])
        .output()
        .expect("failed to run pip install --target");
    assert!(
        out.status.success(),
        "pip install --target failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert!(
        global_dir.path().join("pydantic_ai").exists(),
        "pydantic_ai package should be installed in global_dir"
    );

    let gp_str = global_dir.path().to_str().unwrap();

    // -- SCAN: verify scan -g finds the package ------------------------------
    let (stdout, _) = assert_run_ok(
        cwd,
        &["scan", "-g", "--global-prefix", gp_str, "--json"],
        "scan -g --json",
    );
    let scan: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let scanned = scan["scannedPackages"]
        .as_u64()
        .expect("scannedPackages should be a number");
    assert!(scanned >= 1, "scan should find at least 1 package, got {scanned}");

    // -- GET: download + apply patch globally --------------------------------
    assert_run_ok(
        cwd,
        &["get", PYPI_UUID, "-g", "--global-prefix", gp_str],
        "get -g",
    );

    let manifest_path = cwd.join(".socket/manifest.json");
    assert!(manifest_path.exists(), "manifest should exist after get");

    let (_, files_value) = read_patch_files(&manifest_path);
    let files = files_value.as_object().expect("files object");
    assert!(!files.is_empty(), "manifest should record patched files");

    // Patch must be non-trivial, else the rollback/apply round-trip below is
    // vacuous (rolling back to beforeHash == afterHash proves nothing).
    let nontrivial = files.iter().any(|(_, info)| {
        info["beforeHash"].as_str().unwrap_or("") != info["afterHash"].as_str().unwrap_or("")
    });
    assert!(nontrivial, "patch must change at least one file");

    // Verify every patched file matches afterHash.
    for (rel_path, info) in files {
        let after_hash = info["afterHash"].as_str().expect("afterHash");
        let full_path = global_dir.path().join(rel_path);
        assert!(full_path.exists(), "patched file should exist: {}", full_path.display());
        assert_eq!(
            git_sha256_file(&full_path),
            after_hash,
            "{rel_path} should match afterHash after global get"
        );
    }

    // -- ROLLBACK: restore original files globally ---------------------------
    assert_run_ok(
        cwd,
        &["rollback", "-g", "--global-prefix", gp_str],
        "rollback -g",
    );

    for (rel_path, info) in files {
        let before_hash = info["beforeHash"].as_str().unwrap_or("");
        let full_path = global_dir.path().join(rel_path);
        if before_hash.is_empty() {
            assert!(
                !full_path.exists(),
                "new file {rel_path} should be removed after global rollback"
            );
        } else {
            assert_eq!(
                git_sha256_file(&full_path),
                before_hash,
                "{rel_path} should match beforeHash after global rollback"
            );
        }
    }

    // -- APPLY: re-apply from manifest globally ------------------------------
    assert_run_ok(
        cwd,
        &["apply", "-g", "--global-prefix", gp_str],
        "apply -g",
    );

    for (rel_path, info) in files {
        let after_hash = info["afterHash"].as_str().expect("afterHash");
        let full_path = global_dir.path().join(rel_path);
        assert_eq!(
            git_sha256_file(&full_path),
            after_hash,
            "{rel_path} should match afterHash after global apply"
        );
    }

    // -- REMOVE: rollback + remove from manifest globally --------------------
    assert_run_ok(
        cwd,
        &["remove", PYPI_UUID, "-g", "--global-prefix", gp_str],
        "remove -g",
    );

    // Files must be restored by the global remove, not just the manifest cleared.
    for (rel_path, info) in files {
        let before_hash = info["beforeHash"].as_str().unwrap_or("");
        let full_path = global_dir.path().join(rel_path);
        if before_hash.is_empty() {
            assert!(
                !full_path.exists(),
                "new file {rel_path} should be removed after global remove"
            );
        } else {
            assert_eq!(
                git_sha256_file(&full_path),
                before_hash,
                "{rel_path} should be restored to beforeHash after global remove"
            );
        }
    }

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    assert!(
        manifest["patches"].as_object().unwrap().is_empty(),
        "manifest should be empty after global remove"
    );
}

/// `get --save-only` should save the patch to the manifest without applying.
#[test]
#[ignore]
fn test_pypi_save_only() {
    if !has_python3() {
        eprintln!("SKIP: python3 not found on PATH");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();

    setup_venv(cwd);

    let site_packages = find_site_packages(cwd);
    let messages_py = site_packages.join("pydantic_ai/messages.py");
    assert!(messages_py.exists());
    let original_hash = git_sha256_file(&messages_py);

    // Download with --save-only.
    assert_run_ok(cwd, &["get", PYPI_UUID, "--save-only"], "get --save-only");

    // File should be unchanged.
    assert_eq!(
        git_sha256_file(&messages_py),
        original_hash,
        "file should not change after get --save-only"
    );

    // Manifest should exist with the patch.
    let manifest_path = cwd.join(".socket/manifest.json");
    assert!(manifest_path.exists(), "manifest should exist after get --save-only");

    let (purl, files_value) = read_patch_files(&manifest_path);
    assert!(
        purl.starts_with(PYPI_PURL_PREFIX),
        "manifest should contain a pydantic-ai patch"
    );

    let files = files_value.as_object().unwrap();
    assert!(!files.is_empty(), "manifest should record patched files");

    // Patch must be non-trivial, else "unchanged after save-only" is vacuous.
    let nontrivial = files.iter().any(|(_, info)| {
        info["beforeHash"].as_str().unwrap_or("") != info["afterHash"].as_str().unwrap_or("")
    });
    assert!(nontrivial, "patch must change at least one file");

    // --save-only must NOT apply the patch. For every file the patch genuinely
    // modifies (beforeHash != afterHash), the on-disk content must therefore
    // not match afterHash. (Note: an empty beforeHash does not imply the file
    // is absent on disk — the package install may already ship it.)
    let mut checked_modified = 0;
    for (rel, info) in files {
        let before_hash = info["beforeHash"].as_str().unwrap_or("");
        let after_hash = info["afterHash"].as_str().expect("afterHash");
        if before_hash == after_hash {
            continue; // file not actually changed by the patch
        }
        let p = site_packages.join(rel);
        if p.exists() {
            assert_ne!(
                git_sha256_file(&p),
                after_hash,
                "{rel} must NOT be at afterHash after get --save-only (apply must not have run)"
            );
        }
        checked_modified += 1;
    }
    assert!(
        checked_modified > 0,
        "expected at least one patch-modified file to verify against save-only"
    );

    // Real apply should work, and bring every file to its afterHash.
    assert_run_ok(cwd, &["apply"], "apply");

    let after_hash = files["pydantic_ai/messages.py"]["afterHash"]
        .as_str()
        .unwrap();
    assert_eq!(
        git_sha256_file(&messages_py),
        after_hash,
        "file should match afterHash after apply"
    );
    for (rel, info) in files {
        let after = info["afterHash"].as_str().expect("afterHash");
        assert_eq!(
            git_sha256_file(&site_packages.join(rel)),
            after,
            "{rel} should match afterHash after apply"
        );
    }
}

/// macOS auto-discovery: `scan -g --json` without `--global-prefix` uses real path probing.
#[cfg(target_os = "macos")]
#[test]
#[ignore]
fn test_pypi_macos_global_auto_discovery() {
    if !has_python3() {
        eprintln!("SKIP: python3 not found on PATH");
        return;
    }

    let cwd_dir = tempfile::tempdir().unwrap();
    let cwd = cwd_dir.path();

    // Run scan -g without --global-prefix to exercise macOS auto-discovery
    let (code, stdout, stderr) = run(cwd, &["scan", "-g", "--json"]);

    // Should complete without error (exit 0)
    assert_eq!(
        code, 0,
        "scan -g --json failed (exit {code}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Output should be valid JSON with the full scan envelope.
    let scan: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON from scan -g: {e}\nstdout:\n{stdout}"));

    // The scan must report success, not just exit 0 with an error payload.
    assert_eq!(
        scan["status"].as_str(),
        Some("success"),
        "scan -g envelope should report status=success, got: {}",
        scan["status"]
    );

    let scanned = scan["scannedPackages"]
        .as_u64()
        .unwrap_or_else(|| panic!("scannedPackages should be a number, got: {}", scan["scannedPackages"]));

    // The whole point of this test is that auto-discovery (no --global-prefix)
    // actually probes the real macOS framework/global site-packages. A working
    // python3 host (required above) always ships a populated site-packages
    // (pip/setuptools at minimum), so a correct probe finds >= 1 package. A
    // broken probe that locates nothing would report 0 — assert against it so
    // the "real path probing" claim cannot silently regress to a no-op.
    assert!(
        scanned >= 1,
        "auto-discovery should crawl the real global site-packages and find \
         at least 1 package, got {scanned}.\nstdout:\n{stdout}"
    );

    // Structural envelope invariants: every count field must be present and
    // numeric, the packages array must be well-formed, and the patched-subset
    // count cannot exceed the total scanned. These hold regardless of host and
    // reject a malformed/partial envelope that happens to carry a number.
    for field in [
        "packagesWithPatches",
        "totalPatches",
        "freePatches",
        "paidPatches",
    ] {
        assert!(
            scan[field].is_u64(),
            "{field} should be a number, got: {}",
            scan[field]
        );
    }
    let packages = scan["packages"]
        .as_array()
        .expect("packages should be an array");
    let with_patches = scan["packagesWithPatches"].as_u64().unwrap();
    assert_eq!(
        packages.len() as u64,
        with_patches,
        "packages array length must equal packagesWithPatches"
    );
    assert!(
        with_patches <= scanned,
        "packagesWithPatches ({with_patches}) cannot exceed scannedPackages ({scanned})"
    );
}

/// UUID shortcut: `socket-patch <UUID>` should behave like `socket-patch get <UUID>`.
#[test]
#[ignore]
fn test_pypi_uuid_shortcut() {
    if !has_python3() {
        eprintln!("SKIP: python3 not found on PATH");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();

    setup_venv(cwd);

    let site_packages = find_site_packages(cwd);
    assert!(site_packages.join("pydantic_ai").exists());

    // Snapshot a known-patched file BEFORE the shortcut runs, so we have an
    // oracle that is independent of the command under test.
    let messages_py = site_packages.join("pydantic_ai/messages.py");
    let messages_before = messages_py.exists().then(|| git_sha256_file(&messages_py));

    // Run with bare UUID (no "get" subcommand).
    assert_run_ok(cwd, &[PYPI_UUID], "uuid shortcut");

    let manifest_path = cwd.join(".socket/manifest.json");
    assert!(manifest_path.exists(), "manifest should exist after UUID shortcut");

    let (purl, files_value) = read_patch_files(&manifest_path);
    assert!(
        purl.starts_with(PYPI_PURL_PREFIX),
        "manifest should contain a pydantic-ai patch, got {purl}"
    );
    let files = files_value.as_object().expect("files object");
    assert!(!files.is_empty(), "manifest should record patched files");

    // Patch must be non-trivial; combined with the afterHash checks below this
    // proves the shortcut actually applied (not a no-op that happens to match).
    let nontrivial = files.iter().any(|(_, info)| {
        info["beforeHash"].as_str().unwrap_or("") != info["afterHash"].as_str().unwrap_or("")
    });
    assert!(nontrivial, "patch must change at least one file");

    for (rel_path, info) in files {
        let after_hash = info["afterHash"].as_str().expect("afterHash");
        let full_path = site_packages.join(rel_path);
        assert_eq!(
            git_sha256_file(&full_path),
            after_hash,
            "{rel_path} should match afterHash after UUID shortcut"
        );
    }

    // Independent oracle: the bare-UUID shortcut must behave like `get` and
    // actually modify the file we snapshotted before it ran. If messages.py is
    // part of this patch, its on-disk content must have moved off the original.
    if let Some(before) = messages_before {
        if files.contains_key("pydantic_ai/messages.py") {
            assert_ne!(
                git_sha256_file(&messages_py),
                before,
                "UUID shortcut should have modified messages.py (behave like `get`)"
            );
        }
    }
}
