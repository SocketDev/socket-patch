//! End-to-end: assert the typed JSON envelope `sidecars[]` shape
//! for every ecosystem's post-apply advisory path.
//!
//! These tests drive the `socket-patch apply` binary as a subprocess
//! against handcrafted package layouts (the same layouts the crawlers
//! find on real installs). For each ecosystem we:
//!
//!   1. Stage the package directory the crawler expects.
//!   2. Write `.socket/manifest.json` referencing a synthetic PURL.
//!   3. Drop the `after_hash` blob under `.socket/blobs/<hash>` so
//!      apply runs fully offline.
//!   4. Invoke `socket-patch apply --json` with `--global-prefix`
//!      pointed at the package root, plus any per-ecosystem env
//!      gates (e.g. `SOCKET_EXPERIMENTAL_NUGET=1`,
//!      `NUGET_PACKAGES=<path>`, `GOMODCACHE=<path>`).
//!   5. Parse the JSON envelope and assert the structured
//!      `envelope.sidecars[]` record matches the ecosystem's
//!      expected `code` / `severity` / `files[]` contract.
//!
//! These are the load-bearing tests that lock the **typed** sidecar
//! JSON contract (codes are stable snake_case enum tags, severity is
//! a stable bucket) that downstream consumers — CI bots, the Socket
//! dashboard, jq pipelines, telemetry — branch on. A future refactor
//! that renames a code, flips a severity, or moves the data
//! elsewhere fires here loudly.
//!
//! Network: no. Toolchain: none. These run on every PR.

use std::path::Path;

#[path = "common/mod.rs"]
mod common;

use common::{
    git_sha256, parse_json_envelope, run_with_env, write_blob, write_minimal_manifest,
    PatchEntry,
};

/// Helper: stage a package layout + manifest + blob, run apply, and
/// return the parsed JSON envelope.
///
/// `package_root` is the directory the crawler will be pointed at via
/// `--global-prefix`; the manifest lives in `cwd/.socket/`. The two
/// are separated because `--global-prefix` semantics expect the
/// ecosystem's root (e.g. `$GOMODCACHE`, `$NUGET_PACKAGES`, site-
/// packages) which is not the same as the `--cwd` where `.socket/`
/// lives.
///
/// `extra_env` adds env vars only to the child process (the parent's
/// env is untouched so tests stay parallel-safe).
fn apply_and_parse(
    cwd: &Path,
    package_root: &Path,
    extra_env: &[(&str, &str)],
) -> serde_json::Value {
    let (_code, stdout, stderr) = run_with_env(
        cwd,
        &[
            "apply",
            "--json",
            "--cwd",
            cwd.to_str().unwrap(),
            "--global-prefix",
            package_root.to_str().unwrap(),
        ],
        extra_env,
    );
    if stdout.trim().is_empty() {
        panic!(
            "socket-patch apply emitted no JSON.\nstderr:\n{stderr}"
        );
    }
    parse_json_envelope(&stdout)
}

/// Locate the first `envelope.sidecars[]` record matching the given
/// ecosystem tag, or panic with the full envelope on miss. Tests use
/// this to drill into the per-ecosystem record without re-implementing
/// the lookup five times.
fn find_sidecar_record<'a>(
    env: &'a serde_json::Value,
    ecosystem: &str,
) -> &'a serde_json::Value {
    let sidecars = env["sidecars"]
        .as_array()
        .unwrap_or_else(|| panic!("envelope.sidecars must be an array.\nenv: {env}"));
    sidecars
        .iter()
        .find(|s| s["ecosystem"] == ecosystem)
        .unwrap_or_else(|| {
            panic!(
                "envelope.sidecars must contain a record with ecosystem={ecosystem}.\nenv: {env}"
            )
        })
}

// ─────────────────────────────────────────────────────────────────────
// PyPI — advisory-only, code = pypi_record_stale
// ─────────────────────────────────────────────────────────────────────

/// PyPI: patching a file inside a `dist-info`-discovered package
/// emits a `pypi_record_stale` advisory at severity `warning`.
///
/// Locks in the contract: PyPI's sidecar path is advisory-only (no
/// file rewrites yet — `.dist-info/RECORD` rewriter is a follow-up),
/// `files[]` is present but empty, and the advisory carries the
/// stable `pypi_record_stale` enum tag.
#[test]
fn pypi_apply_emits_pypi_record_stale_advisory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let site_packages = cwd.join("site-packages");

    // Stage a synthetic dist-info that the python crawler will
    // recognize (`Name:` + `Version:` headers in METADATA).
    let dist_info = site_packages.join("requests-2.28.0.dist-info");
    std::fs::create_dir_all(&dist_info).unwrap();
    std::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: requests\nVersion: 2.28.0\n",
    )
    .unwrap();

    // The file we'll "patch". The Python crawler returns the
    // site-packages dir itself as `pkg_path`, so the manifest
    // file_name is resolved relative to site-packages.
    let target = site_packages.join("payload.py");
    let original = b"# original\n";
    std::fs::write(&target, original).unwrap();

    let patched = b"# patched\n";
    let before = git_sha256(original);
    let after = git_sha256(patched);

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        "pkg:pypi/requests@2.28.0",
        "20000001-0000-4001-8001-000000000001",
        &[PatchEntry {
            file_name: "package/payload.py",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket_dir, &after, patched);

    let env = apply_and_parse(cwd, &site_packages, &[]);

    // The patch landed on disk before the sidecar fired.
    assert_eq!(std::fs::read(&target).unwrap(), patched);

    let record = find_sidecar_record(&env, "pypi");
    assert_eq!(
        record["purl"], "pkg:pypi/requests@2.28.0",
        "record must denormalize the PURL.\nrecord: {record}"
    );
    // Advisory-only: files[] is present but empty.
    let files = record["files"].as_array().expect("files array");
    assert!(
        files.is_empty(),
        "pypi advisory-only path must report no files[]; got {record}"
    );
    let advisory = record
        .get("advisory")
        .unwrap_or_else(|| panic!("advisory missing.\nrecord: {record}"));
    assert_eq!(
        advisory["code"], "pypi_record_stale",
        "code contract: pypi must emit pypi_record_stale"
    );
    assert_eq!(
        advisory["severity"], "warning",
        "severity contract: pypi advisory is severity=warning"
    );
    assert!(
        advisory["message"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "advisory.message must be non-empty"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Gem — advisory-only, code = gem_bundle_install_reverts
// ─────────────────────────────────────────────────────────────────────

/// Gem: patching a file inside a `<name>-<version>` gem directory
/// emits a `gem_bundle_install_reverts` advisory at severity `warning`.
///
/// The Ruby crawler treats `<gem_path>/<name>-<version>/` with a
/// `lib/` subdirectory as a valid gem (no `.gemspec` required for
/// the lib-only case).
#[test]
fn gem_apply_emits_gem_bundle_install_reverts_advisory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let gem_root = cwd.join("gems");
    let gem_dir = gem_root.join("rails-7.1.0");
    std::fs::create_dir_all(gem_dir.join("lib")).unwrap();

    let target = gem_dir.join("lib").join("rails.rb");
    let original = b"module Rails; end\n";
    std::fs::write(&target, original).unwrap();

    let patched = b"module Rails; VERSION = '7.1.0-patched'.freeze; end\n";
    let before = git_sha256(original);
    let after = git_sha256(patched);

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        "pkg:gem/rails@7.1.0",
        "20000002-0000-4002-8002-000000000002",
        &[PatchEntry {
            file_name: "package/lib/rails.rb",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket_dir, &after, patched);

    let env = apply_and_parse(cwd, &gem_root, &[]);

    assert_eq!(std::fs::read(&target).unwrap(), patched);

    let record = find_sidecar_record(&env, "gem");
    assert_eq!(record["purl"], "pkg:gem/rails@7.1.0");
    let files = record["files"].as_array().expect("files array");
    assert!(
        files.is_empty(),
        "gem advisory-only path must report no files[]; got {record}"
    );
    let advisory = record.get("advisory").expect("advisory missing");
    assert_eq!(
        advisory["code"], "gem_bundle_install_reverts",
        "code contract: gem must emit gem_bundle_install_reverts"
    );
    assert_eq!(advisory["severity"], "warning");
}

// ─────────────────────────────────────────────────────────────────────
// Go — advisory-only, code = go_mod_verify_fails
// ─────────────────────────────────────────────────────────────────────

/// Go: patching a file inside a `$GOMODCACHE/<encoded-module>@<ver>/`
/// directory emits a `go_mod_verify_fails` advisory at severity
/// `warning`.
///
/// The Go crawler expects the GOMODCACHE layout: an encoded module
/// path followed by `@<version>/`. We pass both `--global-prefix` and
/// `GOMODCACHE` for redundancy (the apply CLI consumes the former,
/// some downstream code paths read the latter).
#[cfg(feature = "golang")]
#[test]
fn golang_apply_emits_go_mod_verify_fails_advisory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let cache = cwd.join("gomodcache");
    // GOMODCACHE layout: <encoded-module>@<version>/. For
    // `github.com/gin-gonic/gin` there are no uppercase letters,
    // so the encoded form equals the path verbatim.
    let module_dir = cache.join("github.com").join("gin-gonic").join("gin@v1.9.1");
    std::fs::create_dir_all(&module_dir).unwrap();

    let target = module_dir.join("gin.go");
    let original = b"package gin\n";
    std::fs::write(&target, original).unwrap();

    let patched = b"package gin\n// patched\n";
    let before = git_sha256(original);
    let after = git_sha256(patched);

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
        "20000003-0000-4003-8003-000000000003",
        &[PatchEntry {
            file_name: "package/gin.go",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket_dir, &after, patched);

    let env = apply_and_parse(
        cwd,
        &cache,
        &[("GOMODCACHE", cache.to_str().unwrap())],
    );

    assert_eq!(std::fs::read(&target).unwrap(), patched);

    let record = find_sidecar_record(&env, "golang");
    assert_eq!(
        record["purl"],
        "pkg:golang/github.com/gin-gonic/gin@v1.9.1"
    );
    let files = record["files"].as_array().expect("files array");
    assert!(
        files.is_empty(),
        "golang advisory-only path must report no files[]; got {record}"
    );
    let advisory = record.get("advisory").expect("advisory missing");
    assert_eq!(
        advisory["code"], "go_mod_verify_fails",
        "code contract: golang must emit go_mod_verify_fails"
    );
    assert_eq!(advisory["severity"], "warning");
}

// ─────────────────────────────────────────────────────────────────────
// NuGet — file deletion (no advisory), code path proves
// `.nupkg.metadata` is removed and recorded as `Deleted`
// ─────────────────────────────────────────────────────────────────────

/// NuGet (unsigned): patching a file inside a `<lowercase-name>/<ver>/`
/// global-cache layout deletes `.nupkg.metadata` (the on-disk content
/// hash sidecar) and records the deletion under
/// `envelope.sidecars[].files[]`. No advisory is emitted for the
/// unsigned case — the deletion alone is the operator surface.
#[cfg(feature = "nuget")]
#[test]
fn nuget_apply_deletes_metadata_and_records_files() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let packages = cwd.join("nuget-packages");
    // Global cache layout: <lowercase-name>/<version>/
    let pkg_dir = packages.join("newtonsoft.json").join("13.0.3");
    std::fs::create_dir_all(pkg_dir.join("lib")).unwrap();

    // The on-disk metadata sidecar the NuGet fixup will remove.
    std::fs::write(
        pkg_dir.join(".nupkg.metadata"),
        r#"{"contentHash":"deadbeef"}"#,
    )
    .unwrap();

    let target = pkg_dir.join("payload.txt");
    let original = b"hello\n";
    std::fs::write(&target, original).unwrap();
    let patched = b"hello patched\n";
    let before = git_sha256(original);
    let after = git_sha256(patched);

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        "pkg:nuget/Newtonsoft.Json@13.0.3",
        "20000004-0000-4004-8004-000000000004",
        &[PatchEntry {
            file_name: "package/payload.txt",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket_dir, &after, patched);

    let env = apply_and_parse(
        cwd,
        &packages,
        &[
            ("NUGET_PACKAGES", packages.to_str().unwrap()),
            ("SOCKET_EXPERIMENTAL_NUGET", "1"),
        ],
    );

    // Patch landed.
    assert_eq!(std::fs::read(&target).unwrap(), patched);
    // Sidecar deleted the metadata file.
    assert!(
        !pkg_dir.join(".nupkg.metadata").exists(),
        "nuget fixup must delete .nupkg.metadata"
    );

    let record = find_sidecar_record(&env, "nuget");
    let files = record["files"].as_array().expect("files array");
    assert_eq!(
        files.len(),
        1,
        "expected one file entry for .nupkg.metadata deletion; got {record}"
    );
    assert_eq!(files[0]["path"], ".nupkg.metadata");
    assert_eq!(
        files[0]["action"], "deleted",
        "action contract: .nupkg.metadata is `deleted`, not `rewritten`"
    );
    // No advisory on the unsigned path — the sidecar emits files
    // only. Either `advisory` is absent from JSON or `null`.
    assert!(
        record.get("advisory").is_none() || record["advisory"].is_null(),
        "unsigned nuget path must not emit an advisory; got {record}"
    );
}

/// NuGet (signed): when the package also carries a `.nupkg.sha512`
/// signature sidecar, the typed payload surfaces BOTH the metadata-
/// deleted file entry AND a `nuget_signed_package_tampered` advisory
/// at severity `warning`. The old single-variant `SidecarOutcome`
/// design lost the advisory in this case; the typed schema keeps
/// both visible.
#[cfg(feature = "nuget")]
#[test]
fn nuget_apply_signed_package_emits_files_and_advisory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let packages = cwd.join("nuget-packages");
    let pkg_dir = packages.join("newtonsoft.json").join("13.0.3");
    std::fs::create_dir_all(pkg_dir.join("lib")).unwrap();

    // Both the content-hash sidecar AND the signed-package marker.
    std::fs::write(
        pkg_dir.join(".nupkg.metadata"),
        r#"{"contentHash":"deadbeef"}"#,
    )
    .unwrap();
    std::fs::write(
        pkg_dir.join("newtonsoft.json.13.0.3.nupkg.sha512"),
        "abc123",
    )
    .unwrap();

    let target = pkg_dir.join("payload.txt");
    let original = b"hello\n";
    std::fs::write(&target, original).unwrap();
    let patched = b"hello patched\n";
    let before = git_sha256(original);
    let after = git_sha256(patched);

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        "pkg:nuget/Newtonsoft.Json@13.0.3",
        "20000005-0000-4005-8005-000000000005",
        &[PatchEntry {
            file_name: "package/payload.txt",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket_dir, &after, patched);

    let env = apply_and_parse(
        cwd,
        &packages,
        &[
            ("NUGET_PACKAGES", packages.to_str().unwrap()),
            ("SOCKET_EXPERIMENTAL_NUGET", "1"),
        ],
    );

    let record = find_sidecar_record(&env, "nuget");

    // Files[] still carries the metadata deletion — even in the
    // signed-package case the new schema does NOT collapse this
    // away (old design's bug).
    let files = record["files"].as_array().expect("files array");
    assert_eq!(files.len(), 1, "metadata deletion must still be reported");
    assert_eq!(files[0]["path"], ".nupkg.metadata");
    assert_eq!(files[0]["action"], "deleted");

    // AND the signed-package advisory rides alongside.
    let advisory = record.get("advisory").unwrap_or_else(|| {
        panic!(
            "signed package must emit an advisory alongside files[].\nrecord: {record}"
        )
    });
    assert_eq!(
        advisory["code"], "nuget_signed_package_tampered",
        "code contract: signed-package case emits nuget_signed_package_tampered"
    );
    assert_eq!(advisory["severity"], "warning");
    assert!(advisory["message"]
        .as_str()
        .map(|s| !s.is_empty())
        .unwrap_or(false));
}
