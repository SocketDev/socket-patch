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

/// Spawn the CLI with the ambient environment scrubbed, so the flags each
/// test passes are the only thing deciding behaviour.
///
/// The binary binds a wide `SOCKET_*` env surface: an ambient
/// `SOCKET_DRY_RUN=true` turns both real applies here into no-op dry runs
/// (every variant `verified`, exit 0 — both tests red), and
/// `SOCKET_GLOBAL` / `SOCKET_GLOBAL_PREFIX` aim the crawl — and the patch
/// WRITES — at the host's real site-packages. Seed-then-scrub (mirrors
/// `common::run_with_env`): the highest-risk vars are seeded with hostile
/// values so a dropped scrub line turns the tests red immediately;
/// telemetry opt-outs are deliberately kept.
///
/// `VIRTUAL_ENV` must go too: the PyPI crawler early-returns on it, so an
/// activated ambient venv hijacks discovery away from the tmp venv (six is
/// "not installed" — both tests red) or, if that venv holds six@1.16.0,
/// aims the patch at the developer's own environment. A hostile seed is
/// impossible here (only a *real* venv path triggers the early return), so
/// it is plain-removed.
fn run_apply_scrubbed(args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(binary());
    cmd.args(args)
        .env("SOCKET_DRY_RUN", "true")
        .env("SOCKET_GLOBAL", "true")
        .env("SOCKET_GLOBAL_PREFIX", "/nonexistent")
        .env("SOCKET_MANIFEST_PATH", "/nonexistent/manifest.json")
        .env_remove("SOCKET_DRY_RUN")
        .env_remove("SOCKET_GLOBAL")
        .env_remove("SOCKET_GLOBAL_PREFIX")
        .env_remove("SOCKET_MANIFEST_PATH")
        .env_remove("VIRTUAL_ENV");
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_") && !name.contains("TELEMETRY") {
            cmd.env_remove(&key);
        }
    }
    cmd.output().expect("run socket-patch apply")
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
    // exactly where the misreport happened. SOCKET_* and VIRTUAL_ENV are
    // scrubbed so the flags decide behaviour.
    let output = run_apply_scrubbed(&[
        "apply",
        "--offline",
        "--ecosystems",
        "pypi",
        "--json",
        "--cwd",
        tmp.path().to_str().unwrap(),
    ]);
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

/// Regression: a multi-variant base PURL where ONE variant applies cleanly
/// but a SIBLING variant fails must flip the command to a non-zero exit /
/// `partialFailure` — not silently report success because one variant
/// happened to apply.
///
/// The apply variant branch tracks an `applied` flag and only flagged
/// `has_errors` when *no* variant applied. A successful sibling therefore
/// masked a failed variant: the JSON envelope carried a `failed` event yet
/// the command exited 0 with `status: success`. The npm branch and the
/// rollback loop both set `has_errors` on *every* failed result; this pins
/// the variant branch to the same contract.
///
/// `--force` is the lever that makes every variant of the base get
/// attempted (it bypasses the per-variant first-file installed-distribution
/// check), so both variants reach `apply_package_patch`: one with a valid
/// `afterHash` blob (applies), one with a decoy blob that does not hash to
/// its `afterHash` (fails the pre-write hash check).
#[test]
fn partial_multi_variant_failure_fails_the_command() {
    if find_python().is_none() {
        println!("SKIP: python3 not on PATH");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let six_path = install_six(tmp.path());
    let original = std::fs::read(&six_path).expect("read six.py");
    let before_hash = git_sha256(&original);

    // Variant A: a genuine patch whose blob hashes to its declared
    // `afterHash` → applies cleanly.
    let mut patched_a = original.clone();
    patched_a.extend_from_slice(b"\n# PATCH-A\n");
    let after_hash_a = git_sha256(&patched_a);

    // Variant B: declares an `afterHash` for content the blob will NOT
    // contain (the blob holds the unpatched original), so the pre-write
    // hash check inside `apply_file_patch` fails → this variant fails.
    let mut intended_b = original.clone();
    intended_b.extend_from_slice(b"\n# PATCH-B\n");
    let after_hash_b = git_sha256(&intended_b);

    let socket_dir = tmp.path().join(".socket");
    std::fs::create_dir_all(socket_dir.join("blobs")).expect("mk .socket/blobs");
    // A's blob is valid; B's blob is a decoy (original bytes under B's hash).
    std::fs::write(socket_dir.join("blobs").join(&after_hash_a), &patched_a)
        .expect("write valid blob A");
    std::fs::write(socket_dir.join("blobs").join(&after_hash_b), &original)
        .expect("write decoy blob B");

    let base = format!("pkg:pypi/{PYPI_PACKAGE}@{PYPI_VERSION}");
    let variant_a = format!("{base}?artifact_id=six-{PYPI_VERSION}-py2.py3-none-any.whl");
    let variant_b = format!("{base}?artifact_id=six-{PYPI_VERSION}.tar.gz");
    let key_a = variant_a.clone();
    let key_b = variant_b.clone();
    let manifest = serde_json::json!({
        "patches": {
            key_a: {
                "uuid": UUID,
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": { "six.py": { "beforeHash": before_hash, "afterHash": after_hash_a } },
                "vulnerabilities": {},
                "description": "variant A (applies)",
                "license": "MIT",
                "tier": "free"
            },
            key_b: {
                "uuid": UUID,
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": { "six.py": { "beforeHash": before_hash, "afterHash": after_hash_b } },
                "vulnerabilities": {},
                "description": "variant B (fails)",
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

    let output = run_apply_scrubbed(&[
        "apply",
        "--force",
        "--offline",
        "--ecosystems",
        "pypi",
        "--json",
        "--cwd",
        tmp.path().to_str().unwrap(),
    ]);
    let code = output.status.code().unwrap_or(-1);
    let out = String::from_utf8_lossy(&output.stdout).to_string();

    // The core regression: a failed sibling variant must fail the command.
    assert_eq!(
        code, 1,
        "a partial multi-variant failure must exit 1, not be masked by the \
         successful sibling; stdout: {out}"
    );

    let env: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("envelope not JSON ({e}): {out}"));
    let events = env["events"]
        .as_array()
        .unwrap_or_else(|| panic!("no events array in envelope: {out}"));

    // Prove the scenario was genuinely exercised: exactly one variant
    // applied and exactly one failed (not a total failure).
    let applied: Vec<&serde_json::Value> =
        events.iter().filter(|e| e["action"] == "applied").collect();
    let failed: Vec<&serde_json::Value> =
        events.iter().filter(|e| e["action"] == "failed").collect();
    assert_eq!(
        applied.len(),
        1,
        "expected exactly one applied variant: {out}"
    );
    assert_eq!(
        failed.len(),
        1,
        "expected exactly one failed variant: {out}"
    );
    assert_eq!(applied[0]["purl"], serde_json::Value::String(variant_a));
    assert_eq!(failed[0]["purl"], serde_json::Value::String(variant_b));

    // And the envelope itself must signal the partial failure.
    assert_eq!(
        env["status"], "partialFailure",
        "envelope status must reflect the partial failure: {out}"
    );
}
