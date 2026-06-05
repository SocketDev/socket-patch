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
// Only the cargo sidecar test needs the bare (un-framed) digest used in
// `.cargo-checksum.json`; gate the import so a `--no-default-features`
// (no `cargo`) build doesn't trip the unused-import lint under `-D warnings`.
#[cfg(feature = "cargo")]
use common::sha256_hex;

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
    let (code, stdout, stderr) = run_with_env(
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
    let env = parse_json_envelope(&stdout);

    // Run-level contract: a sidecar record is meaningless unless the
    // underlying patch actually landed *and the run reported success*.
    // Every test in this file stages exactly one offline patch that
    // must apply cleanly, so lock the whole-run shape here once. This
    // closes the loophole where a regression that flips the run to
    // partialFailure / non-zero exit, mis-records the patch event, or
    // drops the summary count would still slip past the per-ecosystem
    // `sidecars[]` assertions below.
    assert_eq!(
        code, 0,
        "apply must exit 0 on a clean offline apply.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        env["command"], "apply",
        "envelope.command must be `apply`.\nenv: {env}"
    );
    assert_eq!(
        env["status"], "success",
        "apply must report status=success (not partialFailure/error).\nenv: {env}"
    );
    assert_eq!(
        env["dryRun"], false,
        "these applies are NOT dry runs — bytes must hit disk.\nenv: {env}"
    );
    assert_eq!(
        env.get("error"),
        None,
        "a successful apply must carry no top-level error.\nenv: {env}"
    );
    let summary = &env["summary"];
    assert_eq!(
        summary["applied"], 1,
        "exactly one package must be applied.\nenv: {env}"
    );
    assert_eq!(
        summary["failed"], 0,
        "no patch event may be `failed`.\nenv: {env}"
    );
    // The real apply path must have recorded an `applied` patch event —
    // proves the sidecar rode on an actual on-disk patch rather than a
    // fabricated / short-circuited record.
    let events = env["events"]
        .as_array()
        .unwrap_or_else(|| panic!("envelope.events must be an array.\nenv: {env}"));
    assert!(
        events.iter().any(|e| e["action"] == "applied"),
        "apply must record at least one `applied` event.\nenv: {env}"
    );

    env
}

/// Assert the per-ecosystem contract that a `sidecars[]` record JOINs
/// to an `applied` `events[]` record by `purl` (the documented schema
/// invariant downstream consumers rely on), and that the run produced
/// exactly the one sidecar record this test staged. Both the sidecar
/// `purl` and the event `purl` derive from the same `package_key`, so a
/// mismatch here means the wiring between the apply loop and the
/// sidecar emitter regressed.
fn assert_sidecar_joins_applied_event(env: &serde_json::Value, record: &serde_json::Value) {
    let sidecars = env["sidecars"].as_array().expect("sidecars array");
    assert_eq!(
        sidecars.len(),
        1,
        "exactly one sidecar record expected for a single staged package.\nenv: {env}"
    );
    let purl = record["purl"]
        .as_str()
        .unwrap_or_else(|| panic!("sidecar record.purl must be a string.\nrecord: {record}"));
    assert!(!purl.is_empty(), "sidecar record.purl must be non-empty");
    let events = env["events"].as_array().expect("events array");
    assert!(
        events
            .iter()
            .any(|e| e["purl"] == record["purl"] && e["action"] == "applied"),
        "sidecar record (purl={purl}) must JOIN to an `applied` event of the same purl.\nenv: {env}"
    );
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
    assert_sidecar_joins_applied_event(&env, record);
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
    // The advisory message is the operator-facing remediation guidance —
    // a bare non-empty check would accept any garbage string. Pin the
    // stable, load-bearing tokens the production constant carries: the
    // `pip check` instruction and the `.dist-info/RECORD` it points at.
    let msg = advisory["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("pip check") && msg.contains("RECORD"),
        "pypi advisory.message must guide the operator to `pip check` the .dist-info/RECORD; got {msg:?}"
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
    assert_sidecar_joins_applied_event(&env, record);
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
    // Pin the stable operator-guidance token rather than just non-empty:
    // the gem advisory tells the operator that `bundle install` reverts.
    let msg = advisory["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("bundle install"),
        "gem advisory.message must warn that `bundle install` reverts the patch; got {msg:?}"
    );
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
    assert_sidecar_joins_applied_event(&env, record);
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
    // Pin the stable operator-guidance token rather than just non-empty:
    // the Go advisory points at `go mod verify`.
    let msg = advisory["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("go mod verify"),
        "golang advisory.message must point the operator at `go mod verify`; got {msg:?}"
    );
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
    assert_sidecar_joins_applied_event(&env, record);
    assert_eq!(
        record["purl"].as_str().map(|s| s.to_lowercase()),
        Some("pkg:nuget/newtonsoft.json@13.0.3".to_string()),
        "record must carry the package PURL.\nrecord: {record}"
    );
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

/// NuGet `has_signed_marker` non-UTF8 filename skip: dropping a
/// file with a non-UTF8 name into the package directory exercises
/// the `entry.file_name().to_str()` None arm of
/// `has_signed_marker`'s iteration (line 93). The fixup then
/// continues — the sha512 marker isn't present, no advisory; the
/// `.nupkg.metadata` deletion still fires because we stage it too.
///
/// Linux-only (`OsStr::from_bytes` is Unix-gated; macOS HFS+/APFS
/// also accept arbitrary byte sequences in filenames). Falls back
/// to a portable shape on other Unices where the filesystem
/// rejects non-UTF8 names.
#[cfg(all(unix, feature = "nuget"))]
#[test]
fn nuget_apply_with_non_utf8_filename_in_pkg_dir() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let packages = cwd.join("nuget-packages");
    let pkg_dir = packages.join("newtonsoft.json").join("13.0.3");
    std::fs::create_dir_all(pkg_dir.join("lib")).unwrap();
    std::fs::write(
        pkg_dir.join(".nupkg.metadata"),
        r#"{"contentHash":"deadbeef"}"#,
    )
    .unwrap();
    // Drop a file with a non-UTF8 name into the package dir. The
    // sidecar's `has_signed_marker` iteration calls
    // `entry.file_name().to_str()` on each entry; this one returns
    // None and the iteration skips past it (covering line 93 of
    // nuget.rs).
    //
    // APFS/HFS+/ext4 all accept arbitrary byte sequences in
    // filenames; some networked filesystems may reject. If the
    // filesystem rejects, skip — the iteration arm is exercised on
    // the runners where it can run.
    let bad_name = OsStr::from_bytes(&[0xff, 0xfe, b'-', b'b', b'a', b'd']);
    let bad_path = pkg_dir.join(bad_name);
    if std::fs::write(&bad_path, b"binary").is_err() {
        eprintln!("SKIP: filesystem rejects non-UTF8 filenames");
        return;
    }
    // Precondition must be genuinely established — otherwise the rest of
    // this test would pass as a plain `.nupkg.metadata` deletion without
    // ever exercising the non-UTF8 `to_str() == None` skip arm it exists
    // to lock. A silent no-op here would mean the test guards nothing.
    assert!(
        bad_path.exists(),
        "non-UTF8 fixture file must exist so has_signed_marker's None arm is reached"
    );

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
        "20000007-0000-4007-8007-000000000007",
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

    // Patch landed and .nupkg.metadata removal succeeded; the
    // non-UTF8 file didn't trip the sidecar (the implicit-skip arm
    // is what we're locking in).
    assert_eq!(std::fs::read(&target).unwrap(), patched);
    assert!(!pkg_dir.join(".nupkg.metadata").exists());
    // The non-UTF8 file must be untouched — the fixup skips it (it is not
    // a `.nupkg.sha512` marker) rather than deleting or mangling it. Proves
    // the skip arm ran and left the directory otherwise intact.
    assert!(
        bad_path.exists(),
        "non-UTF8 file must survive the fixup (skipped, not deleted)"
    );

    let record = find_sidecar_record(&env, "nuget");
    assert_sidecar_joins_applied_event(&env, record);
    let files = record["files"].as_array().expect("files array");
    assert_eq!(files.len(), 1, "metadata deletion expected");
    assert_eq!(files[0]["path"], ".nupkg.metadata");
    assert_eq!(files[0]["action"], "deleted");
    // No advisory — the non-UTF8 file is NOT a `.nupkg.sha512`
    // marker (its name isn't even valid UTF-8), so the signed-
    // package branch stays cold.
    assert!(
        record.get("advisory").is_none() || record["advisory"].is_null(),
        "non-UTF8 file must not trigger the signed-marker advisory; got {record}"
    );
}

/// NuGet sidecar I/O-error boundary: when `.nupkg.metadata` exists
/// as a *directory* (not a file), `tokio::fs::remove_file` fails
/// with a non-NotFound error and `nuget::fixup` returns
/// `SidecarError::Io`. The boundary in `apply_package_patch`
/// converts that into a `sidecar_fixup_failed` advisory.
///
/// Covers the non-NotFound arm of the remove_file match in
/// `sidecars/nuget.rs` (lines 50-54) — the path the existing
/// success and signed-package tests can't reach. As with the
/// cargo equivalent, the directory-as-file ruse beats chmod
/// because it fails uniformly across uids and platforms.
#[cfg(feature = "nuget")]
#[test]
fn nuget_apply_with_metadata_directory_reports_sidecar_fixup_failed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let packages = cwd.join("nuget-packages");
    let pkg_dir = packages.join("newtonsoft.json").join("13.0.3");
    std::fs::create_dir_all(pkg_dir.join("lib")).unwrap();
    // `.nupkg.metadata` as a non-empty directory. remove_file
    // refuses to unlink a directory; that's an EISDIR-class I/O
    // error, not NotFound.
    std::fs::create_dir(pkg_dir.join(".nupkg.metadata")).unwrap();
    std::fs::write(
        pkg_dir.join(".nupkg.metadata").join("placeholder"),
        b"non-empty so the dir can't be remove_file-removed even on permissive platforms",
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
        "20000006-0000-4006-8006-000000000006",
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

    // Patch landed (atomic write commits before the sidecar runs).
    assert_eq!(std::fs::read(&target).unwrap(), patched);

    let record = find_sidecar_record(&env, "nuget");
    assert_sidecar_joins_applied_event(&env, record);
    let advisory = record.get("advisory").expect("advisory");
    assert_eq!(advisory["code"], "sidecar_fixup_failed");
    assert_eq!(advisory["severity"], "error");
    let msg = advisory["message"].as_str().unwrap_or("");
    assert!(
        msg.contains(".nupkg.metadata"),
        "advisory message must reference the metadata path; got {msg:?}"
    );
    // The boundary wraps the SidecarError with a stable, recognizable
    // prefix consumers key on; a bare "contains the path" check would
    // pass on an unrelated message that merely mentions the file.
    assert!(
        msg.contains("sidecar fixup failed"),
        "fixup-failed advisory must carry the stable `sidecar fixup failed` prefix; got {msg:?}"
    );
    // Boundary contract: failure path emits NO files[] entries.
    let files = record["files"].as_array().expect("files array");
    assert!(
        files.is_empty(),
        "failed fixup must not report any deleted files; got {record}"
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

    // Patch landed and the signature marker did NOT get clobbered.
    assert_eq!(std::fs::read(&target).unwrap(), patched);
    assert!(
        pkg_dir.join("newtonsoft.json.13.0.3.nupkg.sha512").exists(),
        "signed-package fixup must leave the .nupkg.sha512 marker in place"
    );
    assert!(
        !pkg_dir.join(".nupkg.metadata").exists(),
        "signed-package fixup must still delete .nupkg.metadata"
    );

    let record = find_sidecar_record(&env, "nuget");
    assert_sidecar_joins_applied_event(&env, record);

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
    // Pin the stable token: the signed-package advisory names the
    // `.nupkg.sha512` signature sidecar it cannot honestly recompute.
    let msg = advisory["message"].as_str().unwrap_or("");
    assert!(
        msg.contains(".nupkg.sha512"),
        "signed-package advisory.message must reference the .nupkg.sha512 signature sidecar; got {msg:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Cargo — file rewrite (no advisory), code path proves
// `.cargo-checksum.json` is rewritten to the on-disk hash and recorded
// as `Rewritten`. This is the DEFAULT-feature sidecar and the only one
// in the shipped binary that *rewrites* a file, so it must have an
// end-to-end guard that runs under `--features cargo` (the recommended
// command) — not just core-crate unit tests on `cargo::fixup`.
// ─────────────────────────────────────────────────────────────────────

/// Cargo: patching a file inside a `<name>-<version>/` registry-cache
/// crate rewrites `<crate>/.cargo-checksum.json` so the patched file's
/// entry reflects its new on-disk SHA-256, records the rewrite under
/// `envelope.sidecars[].files[]` with action `rewritten`, and emits NO
/// advisory (the rewrite keeps `cargo build` happy — there is nothing
/// to warn the operator about).
///
/// Independently derives the expected post-patch digest with the bare
/// (un-Git-framed) `sha256_hex` cargo uses, then reads the rewritten
/// checksum file back off disk and pins it — so a regression that
/// stops rewriting, rewrites the wrong value, clobbers the untouched
/// sibling / `package` tarball hash, or mislabels the action fires loudly.
#[cfg(feature = "cargo")]
#[test]
fn cargo_apply_rewrites_checksum_and_records_files() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let registry = cwd.join("registry-src");
    // Registry layout: <name>-<version>/ with a Cargo.toml the crawler
    // verifies against the PURL (name=mycrate, version=1.0.0).
    let crate_dir = registry.join("mycrate-1.0.0");
    std::fs::create_dir_all(crate_dir.join("src")).unwrap();
    std::fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname = \"mycrate\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();

    let target = crate_dir.join("src").join("lib.rs");
    let original = b"// original lib\n";
    std::fs::write(&target, original).unwrap();
    let patched = b"// patched lib\n";
    let before = git_sha256(original);
    let after = git_sha256(patched);

    // Pre-existing `.cargo-checksum.json` with a STALE hash for the file
    // we patch, an UNTOUCHED sibling entry, and the `package` tarball
    // hash. The fixup must rewrite ONLY the patched entry and preserve
    // the rest verbatim.
    let stale_lib = "00".repeat(32);
    let untouched_sibling = "11".repeat(32);
    let package_hash = "deadbeefpackagehash";
    let checksum_path = crate_dir.join(".cargo-checksum.json");
    std::fs::write(
        &checksum_path,
        format!(
            r#"{{"files":{{"src/lib.rs":"{stale_lib}","Cargo.toml":"{untouched_sibling}"}},"package":"{package_hash}"}}"#
        ),
    )
    .unwrap();

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        "pkg:cargo/mycrate@1.0.0",
        "20000008-0000-4008-8008-000000000008",
        &[PatchEntry {
            file_name: "package/src/lib.rs",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket_dir, &after, patched);

    let env = apply_and_parse(cwd, &registry, &[]);

    // Patch landed on disk before the sidecar fired.
    assert_eq!(std::fs::read(&target).unwrap(), patched);

    // The checksum file was rewritten on disk: the patched entry now
    // carries the REAL post-patch bare-sha256 (derived independently here,
    // NOT read back from the same value we'd be checking), the stale value
    // is gone, and the untouched sibling + `package` tarball hash survive.
    let post: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&checksum_path).unwrap())
            .expect(".cargo-checksum.json must stay valid JSON after rewrite");
    let expected = sha256_hex(patched);
    assert_eq!(
        post["files"]["src/lib.rs"].as_str(),
        Some(expected.as_str()),
        "patched-file checksum must be rewritten to the on-disk sha256; got {post}"
    );
    assert_ne!(
        post["files"]["src/lib.rs"].as_str(),
        Some(stale_lib.as_str()),
        "stale pre-patch checksum must NOT survive the rewrite; got {post}"
    );
    assert_eq!(
        post["files"]["Cargo.toml"].as_str(),
        Some(untouched_sibling.as_str()),
        "an unpatched sibling's checksum must be preserved verbatim; got {post}"
    );
    assert_eq!(
        post["package"].as_str(),
        Some(package_hash),
        "the `package` tarball hash must be preserved verbatim; got {post}"
    );

    let record = find_sidecar_record(&env, "cargo");
    assert_sidecar_joins_applied_event(&env, record);
    assert_eq!(record["purl"], "pkg:cargo/mycrate@1.0.0");
    let files = record["files"].as_array().expect("files array");
    assert_eq!(
        files.len(),
        1,
        "cargo fixup rewrites exactly one file (.cargo-checksum.json); got {record}"
    );
    assert_eq!(files[0]["path"], ".cargo-checksum.json");
    assert_eq!(
        files[0]["action"], "rewritten",
        "action contract: .cargo-checksum.json is `rewritten`, not `deleted`"
    );
    // The success path emits files only — no advisory rides along.
    assert!(
        record.get("advisory").is_none() || record["advisory"].is_null(),
        "cargo checksum rewrite must not emit an advisory; got {record}"
    );
}
