//! Regression test for the release-variant apply branch in
//! `apply_patches_inner`.
//!
//! When an installed release-variant package (PyPI / RubyGems / Maven)
//! is found on disk and its patch *matches* the installed distribution
//! (its first file verifies Ready) but then *fails to apply* (e.g. a
//! file's served blob does not hash to its declared `afterHash`), the
//! package was unambiguously found on disk. It must be reported with a
//! single `failed` event — NOT additionally reported as a
//! `package_not_installed` `skipped` event.
//!
//! Before the fix the variant branch only recorded a PURL as "matched"
//! on a *successful* apply, so a matched-but-failed variant fell through
//! to `unmatched` and the run loop emitted a contradictory second event
//! (`skipped` / `package_not_installed`) for the very same PURL. The npm
//! branch never had this bug because it always marks an attempted PURL
//! matched.
//!
//! Requires: `python3` with `venv` and `pip` on PATH. Skipped (visibly)
//! when python3 is missing — same contract as `in_process_pypi_apply`.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

const PYPI_PACKAGE: &str = "six";
const PYPI_VERSION: &str = "1.16.0";
const UUID: &str = "12121212-1212-4121-8121-121212121212";

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
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

/// An installed PyPI variant whose first file verifies `Ready` but whose
/// blob does not hash to its declared `afterHash` (so apply fails) must
/// produce exactly one `failed` event and NO `package_not_installed`
/// `skipped` event for the same PURL.
#[test]
fn failed_installed_variant_is_not_also_reported_not_installed() {
    if find_python().is_none() {
        println!("SKIP: python3 not on PATH");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let six_path = install_six(tmp.path());
    let original = std::fs::read(&six_path).expect("read six.py");
    let before_hash = git_sha256(&original);

    // Declare an `afterHash` for content the blob will NOT actually
    // contain, so the on-disk file verifies `Ready` (its bytes hash to
    // `beforeHash`) — making this the matched installed distribution —
    // but the apply step fails the post-write hash check.
    let mut intended_patched = original.clone();
    intended_patched.extend_from_slice(b"\n# INTENDED-PATCH\n");
    let after_hash = git_sha256(&intended_patched);

    // Stage `.socket/` by hand: a manifest with one pypi patch and a blob
    // keyed by `afterHash` whose *content* is the unpatched original
    // (hash == beforeHash != afterHash). `get_missing_blobs` only checks
    // that the blob file exists, so offline apply does not short-circuit;
    // the content mismatch is caught later, inside `apply_file_patch`.
    let socket_dir = tmp.path().join(".socket");
    std::fs::create_dir_all(socket_dir.join("blobs")).expect("mk .socket/blobs");
    std::fs::write(socket_dir.join("blobs").join(&after_hash), &original)
        .expect("write decoy blob");

    let purl = format!("pkg:pypi/{PYPI_PACKAGE}@{PYPI_VERSION}");
    // `serde_json::json!` consumes the key expression, so clone for the key and
    // keep `purl` itself for the assertions further down.
    let manifest_key = purl.clone();
    let manifest = serde_json::json!({
        "patches": {
            manifest_key: {
                "uuid": UUID,
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": {
                    "six.py": { "beforeHash": before_hash, "afterHash": after_hash }
                },
                "vulnerabilities": {},
                "description": "variant apply-failure fixture",
                "license": "MIT",
                "tier": "free"
            }
        }
    });
    std::fs::write(
        socket_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .expect("write manifest");

    // Run the real binary as a subprocess and capture its JSON envelope from the
    // child's stdout. This is reliable under cargo's test-output capture, unlike
    // an in-process `gag`-based stdout redirect (which races libtest's own
    // capture). NOT `--force`: exercises the variant-matches-installed path,
    // exactly where the misreport happened. SOCKET_* are scrubbed so the flags
    // decide behaviour.
    let output = Command::new(binary())
        .args([
            "apply",
            "--offline",
            "--ecosystems",
            "pypi",
            "--json",
            "--cwd",
            tmp.path().to_str().unwrap(),
        ])
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_OFFLINE")
        .env_remove("SOCKET_ECOSYSTEMS")
        .env_remove("SOCKET_JSON")
        .env_remove("SOCKET_FORCE")
        .env_remove("SOCKET_CWD")
        .env_remove("SOCKET_MANIFEST_PATH")
        .output()
        .expect("run socket-patch apply");
    let code = output.status.code().unwrap_or(-1);
    let out = String::from_utf8_lossy(&output.stdout).to_string();

    // The apply failed, so the command exits non-zero (partial failure).
    assert_eq!(code, 1, "a failed apply must exit 1; stdout: {out}");

    let env: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("envelope not JSON ({e}): {out}"));
    let events = env["events"]
        .as_array()
        .unwrap_or_else(|| panic!("no events array in envelope: {out}"));

    // Gather every event referring to our PURL.
    let for_purl: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["purl"] == serde_json::Value::String(purl.clone()))
        .collect();

    // The on-disk file was genuinely found, so it must be reported as a
    // single failure — never duplicated, never "package_not_installed".
    assert_eq!(
        for_purl.len(),
        1,
        "expected exactly one event for {purl}, got {}: {out}",
        for_purl.len()
    );
    assert_eq!(
        for_purl[0]["action"], "failed",
        "the installed-but-unpatchable variant must be `failed`: {out}"
    );

    // The specific regression: no `skipped` / `package_not_installed`
    // event for a package that was actually installed and attempted.
    let bogus_skip = events.iter().any(|e| {
        e["purl"] == serde_json::Value::String(purl.clone())
            && e["action"] == "skipped"
            && e["errorCode"] == "package_not_installed"
    });
    assert!(
        !bogus_skip,
        "found a contradictory `package_not_installed` skip for the installed \
         variant {purl}; the failed-apply variant was misreported as not installed: {out}"
    );
}
