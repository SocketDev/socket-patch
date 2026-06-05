//! End-to-end tests for human-readable (non-JSON) output paths and
//! `--verbose` modes. The previous coverage push focused on `--json`
//! output; these tests exercise the table printers, verbose
//! verification details, and `--silent` short-circuits that the JSON
//! tests don't reach.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

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

fn write_root(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "output-test", "version": "0.0.0" }"#,
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

fn write_manifest(root: &Path, purl: &str, before: &[u8], after: &[u8]) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let bh = git_sha256(before);
    let ah = git_sha256(after);
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{
          "beforeHash": "{bh}",
          "afterHash":  "{ah}"
        }}
      }},
      "vulnerabilities": {{
        "CVE-2024-12345": {{
          "cves": ["CVE-2024-12345"],
          "summary": "Test",
          "severity": "high",
          "description": "Test vulnerability"
        }}
      }},
      "description": "Test patch",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
        ),
    )
    .unwrap();
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&ah), after).unwrap();
    std::fs::write(blobs.join(&bh), before).unwrap();
}

// ---------------------------------------------------------------------------
// apply — non-JSON / verbose / silent paths
// ---------------------------------------------------------------------------

#[test]
fn apply_non_json_prints_human_readable_summary() {
    let before = b"before\n";
    let after = b"after\n";
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "non-json-target", "1.0.0", before);
    write_manifest(tmp.path(), "pkg:npm/non-json-target@1.0.0", before, after);

    let out = Command::new(binary())
        .args(["apply", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The human-readable summary must report the count *and* name the
    // patched package — not merely print one of two loosely-OR'd words.
    assert!(
        stdout.contains("Summary:") && stdout.contains("1/1 targeted patches applied"),
        "non-JSON apply should print the patch-count summary; got: {stdout}"
    );
    assert!(
        stdout.contains("Patched packages:")
            && stdout.contains("pkg:npm/non-json-target@1.0.0"),
        "non-JSON apply should list the patched PURL; got: {stdout}"
    );
    // The summary is only honest if the file was actually rewritten.
    let patched = std::fs::read(
        tmp.path()
            .join("node_modules/non-json-target/index.js"),
    )
    .unwrap();
    assert_eq!(
        patched, after,
        "apply must rewrite the target file to the patched content"
    );
}

#[test]
fn apply_verbose_prints_per_file_details() {
    let before = b"before\n";
    let after = b"after\n";
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "verbose-target", "1.0.0", before);
    write_manifest(tmp.path(), "pkg:npm/verbose-target@1.0.0", before, after);

    let out = Command::new(binary())
        .args(["apply", "--offline", "--verbose"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // `--verbose` is the whole point of this test: it MUST emit the
    // per-file "Detailed verification" block. The old `|| "Summary"`
    // escape made this vacuous because the non-verbose path also prints
    // "Summary", so a broken --verbose would still pass.
    assert!(
        stdout.contains("Detailed verification:"),
        "--verbose apply must print the detailed-verification block; got: {stdout}"
    );
    assert!(
        stdout.contains("package/index.js"),
        "--verbose apply must name the per-file path; got: {stdout}"
    );
    // The verbose block shows current/target hashes; assert the patched
    // target hash is actually surfaced.
    assert!(
        stdout.contains(&git_sha256(after)),
        "--verbose apply must print the per-file target hash; got: {stdout}"
    );
}

#[test]
fn apply_silent_emits_no_stdout() {
    let before = b"before\n";
    let after = b"after\n";
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "silent-target", "1.0.0", before);
    write_manifest(tmp.path(), "pkg:npm/silent-target@1.0.0", before, after);

    let out = Command::new(binary())
        .args(["apply", "--offline", "--silent"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    assert!(
        out.stdout.is_empty(),
        "--silent must suppress stdout; got: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    // Silence must mean "quiet", not "skip the work": the patch must
    // still be applied to disk. A no-op apply that prints nothing would
    // otherwise pass this test.
    let patched = std::fs::read(tmp.path().join("node_modules/silent-target/index.js")).unwrap();
    assert_eq!(
        patched, after,
        "--silent apply must still patch the target file"
    );
}

#[test]
fn apply_no_manifest_non_json_prints_message() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args(["apply"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No .socket folder found, skipping patch application"),
        "non-JSON no-manifest must print friendly message; got: {stdout}"
    );
}

#[test]
fn apply_dry_run_non_json_prints_verification_summary() {
    let before = b"before\n";
    let after = b"after\n";
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "dry-target", "1.0.0", before);
    write_manifest(tmp.path(), "pkg:npm/dry-target@1.0.0", before, after);

    let out = Command::new(binary())
        .args(["apply", "--offline", "--dry-run"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Patch verification complete") && stdout.contains("can be patched"),
        "dry-run non-JSON should print the verification summary; got: {stdout}"
    );
    // Dry-run reports 0 patches *applied* and, critically, must NOT touch
    // the file on disk. The old test never checked this, so a dry-run
    // that actually mutated files would have passed.
    assert!(
        stdout.contains("0/1 targeted patches applied"),
        "dry-run must report nothing applied; got: {stdout}"
    );
    let on_disk = std::fs::read(tmp.path().join("node_modules/dry-target/index.js")).unwrap();
    assert_eq!(
        on_disk, before,
        "dry-run must leave the target file unmodified"
    );
}

// ---------------------------------------------------------------------------
// list — non-JSON paths
// ---------------------------------------------------------------------------

#[test]
fn list_non_json_prints_table() {
    let before = b"before\n";
    let after = b"after\n";
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), "pkg:npm/list-target@1.0.0", before, after);

    let out = Command::new(binary())
        .args(["list"])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Require BOTH the PURL and the concrete CVE id (not the weaker
    // "Vulnerabilities" header alternative), so a table that drops the
    // vuln detail can't pass.
    assert!(
        stdout.contains("pkg:npm/list-target@1.0.0"),
        "list non-JSON must print the PURL; got: {stdout}"
    );
    assert!(
        stdout.contains("CVE-2024-12345"),
        "list non-JSON must print the CVE id; got: {stdout}"
    );
    assert!(
        stdout.contains("Found 1 patch(es)"),
        "list non-JSON must report the patch count; got: {stdout}"
    );
}

#[test]
fn list_empty_manifest_non_json() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{"patches":{}}"#,
    )
    .unwrap();

    let out = Command::new(binary())
        .args(["list"])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No patches found"),
        "empty manifest non-JSON message; got: {stdout}"
    );
}

#[test]
fn list_no_manifest_non_json_prints_error_to_stderr() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args(["list"])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Manifest not found") || stderr.contains("not found"),
        "non-JSON list-without-manifest must print to stderr; got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// scan — non-JSON paths
// ---------------------------------------------------------------------------

#[test]
fn scan_non_json_no_packages_prints_friendly_message() {
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    // Scan needs network normally, but with no packages crawled it
    // short-circuits before the network call.
    let out = Command::new(binary())
        .args(["scan"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        // Point SOCKET_API_URL at a closed port so any accidental
        // network call fails fast.
        .env("SOCKET_API_URL", "http://127.0.0.1:1")
        .output()
        .expect("run");
    // With no installed packages, scan short-circuits BEFORE the network
    // call (we point SOCKET_API_URL at a dead port to prove no request is
    // made) and exits cleanly with the friendly message. The old test
    // accepted literally any non-empty output on either stream, which a
    // crash or a network-error spew would also satisfy.
    assert_eq!(
        out.status.code(),
        Some(0),
        "scan with no packages must short-circuit to a clean exit; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No packages found"),
        "scan non-JSON must print the no-packages message; got: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// repair — non-JSON paths
// ---------------------------------------------------------------------------

#[test]
fn repair_non_json_no_orphans_prints_summary() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), "pkg:npm/repair-target@1.0.0", b"a", b"b");

    let out = Command::new(binary())
        .args(["repair", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Repair complete."),
        "non-JSON repair should print the completion summary; got: {stdout}"
    );
}

#[test]
fn repair_non_json_with_orphans_prints_cleanup_summary() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), "pkg:npm/repair-target@1.0.0", b"a", b"b");
    // Add an orphan blob (not referenced by manifest).
    let blobs = tmp.path().join(".socket/blobs");
    let orphan = blobs.join("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    std::fs::write(&orphan, b"orphan").unwrap();

    let out = Command::new(binary())
        .args(["repair", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The test name promises a *cleanup* summary, so assert the cleanup
    // actually happened — both in the printed summary and on disk. The
    // old `!stdout.is_empty()` check would pass even if no blob was ever
    // removed.
    assert!(
        stdout.contains("Removed") && stdout.contains("unused blob"),
        "repair with orphans must report removed unused blobs; got: {stdout}"
    );
    assert!(
        !orphan.exists(),
        "repair must actually delete the orphan blob from disk"
    );
    assert!(
        stdout.contains("Repair complete."),
        "repair with orphans must still print the completion tail; got: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// remove — non-JSON paths
// ---------------------------------------------------------------------------

#[test]
fn remove_non_json_prints_what_will_be_removed() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), "pkg:npm/remove-target@1.0.0", b"a", b"b");

    let out = Command::new(binary())
        .args(["remove", "pkg:npm/remove-target@1.0.0", "--yes", "--skip-rollback"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Removed 1 patch(es) from manifest")
            && stdout.contains("pkg:npm/remove-target@1.0.0"),
        "non-JSON remove must print confirmation naming the PURL; stdout={stdout}"
    );
    // The confirmation is only meaningful if the manifest was actually
    // rewritten to drop the patch.
    let manifest =
        std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    assert!(
        !manifest.contains("pkg:npm/remove-target@1.0.0"),
        "remove must delete the patch from the manifest; got: {manifest}"
    );
}

// ---------------------------------------------------------------------------
// rollback — non-JSON paths
// ---------------------------------------------------------------------------

#[test]
fn rollback_non_json_prints_summary() {
    let before = b"original\n";
    let after = b"patched\n";
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "rb-non-json", "1.0.0", after);
    write_manifest(tmp.path(), "pkg:npm/rb-non-json@1.0.0", before, after);

    let out = Command::new(binary())
        .args(["rollback", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Rolled back packages:") && stdout.contains("pkg:npm/rb-non-json@1.0.0"),
        "non-JSON rollback should print summary naming the PURL; got: {stdout}"
    );
    // The summary must reflect reality: the file should be restored to the
    // pre-patch ("before") content. The old test's `|| "original"` even
    // matched the literal package content, masking a no-op rollback.
    let restored = std::fs::read(tmp.path().join("node_modules/rb-non-json/index.js")).unwrap();
    assert_eq!(
        restored, before,
        "rollback must restore the file to its pre-patch content"
    );
}

#[test]
fn rollback_verbose_prints_per_file_details() {
    let before = b"original\n";
    let after = b"patched\n";
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "rb-verbose", "1.0.0", after);
    write_manifest(tmp.path(), "pkg:npm/rb-verbose@1.0.0", before, after);

    let out = Command::new(binary())
        .args(["rollback", "--offline", "--verbose"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // `--verbose` must add the per-file "Detailed verification" block.
    // The old `|| "Rolled"` alternative matched the non-verbose summary,
    // making the verbose-specific assertion vacuous.
    assert!(
        stdout.contains("Detailed verification:") && stdout.contains("package/index.js"),
        "verbose rollback must print the per-file detail block; got: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// get — non-JSON identifier-not-found
// ---------------------------------------------------------------------------

#[test]
fn get_non_json_invalid_uuid_falls_through_to_package_search() {
    let tmp = tempfile::tempdir().unwrap();
    // Invalid identifier without --cve/--ghsa/--package etc. The binary
    // should fall through to package-name search and either succeed or
    // exit 1 cleanly. We're exercising the type-detection branch.
    let out = Command::new(binary())
        .args([
            "get",
            "not-a-real-package",
            "--save-only",
            "--yes",
            "--api-url",
            "http://127.0.0.1:1",
            "--api-token",
            "fake",
            "--org",
            "test-org",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The point of the test is the type-detection branch: an identifier
    // that is neither CVE/GHSA/UUID nor an explicit flag must fall through
    // to a *package-name search*. The old `0 || 1` accepted any outcome —
    // including the binary mis-routing to a vuln lookup. Assert the
    // fall-through actually happened: with no installed packages it
    // short-circuits cleanly (exit 0) after announcing the search.
    assert_eq!(code, 0, "package-name fall-through should exit cleanly; stdout={stdout}");
    assert!(
        stdout.contains("as a package name search"),
        "get with a bare identifier must fall through to package-name search; got: {stdout}"
    );
}

#[test]
fn get_with_explicit_cve_flag_works() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            "CVE-2099-99999",
            "--cve",
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            "http://127.0.0.1:1",
            "--api-token",
            "fake",
            "--org",
            "test-org",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    // The API is unreachable (dead port), so this must surface a network
    // error — exit 1 with a structured JSON error payload whose URL proves
    // the `--cve` flag routed to the by-cve endpoint. The old test accepted
    // exit 0-or-1 and only parsed JSON "if non-empty", so an empty stdout
    // or a wrong endpoint would have passed.
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(code, 1, "unreachable API must yield a failure exit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("must emit parseable JSON");
    assert_eq!(v["status"], "error", "must report a structured error; got: {stdout}");
    let err = v["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("by-cve/CVE-2099-99999"),
        "--cve must route to the by-cve endpoint; got error: {err}"
    );
}

#[test]
fn get_with_explicit_ghsa_flag_works() {
    let tmp = tempfile::tempdir().unwrap();
    // Non-JSON so we can assert the human-readable routing line on stdout
    // and the network error (with the by-ghsa endpoint) on stderr.
    let out = Command::new(binary())
        .args([
            "get",
            "GHSA-1111-2222-3333",
            "--ghsa",
            "--save-only",
            "--yes",
            "--api-url",
            "http://127.0.0.1:1",
            "--api-token",
            "fake",
            "--org",
            "test-org",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(code, 1, "unreachable API must yield a failure exit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("Searching patches for GHSA: GHSA-1111-2222-3333"),
        "--ghsa must announce a GHSA search; got: {stdout}"
    );
    assert!(
        stderr.contains("by-ghsa/GHSA-1111-2222-3333"),
        "--ghsa must route to the by-ghsa endpoint; got: {stderr}"
    );
}

#[test]
fn get_with_explicit_package_flag_works() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            "some-package",
            "--package",
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            "http://127.0.0.1:1",
            "--api-token",
            "fake",
            "--org",
            "test-org",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    // `--package` forces a package-name search. With no installed packages
    // it short-circuits locally (never reaching the dead API), exits 0, and
    // emits the structured "no_packages" JSON. The old `0 || 1` would have
    // accepted a crash or a misrouted vuln lookup.
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(code, 0, "package search with no packages should exit cleanly");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("must emit parseable JSON");
    assert_eq!(v["status"], "no_packages", "got: {stdout}");
    assert_eq!(v["found"], 0, "got: {stdout}");
}

// ---------------------------------------------------------------------------
// setup — non-JSON paths
// ---------------------------------------------------------------------------

#[test]
fn setup_no_files_non_json_prints_friendly_message() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args(["setup"])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No package.json"),
        "non-JSON setup must report missing package.json; got: {stdout}"
    );
}

#[test]
fn setup_dry_run_non_json_prints_preview() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "p", "version": "1.0.0" }"#,
    )
    .unwrap();
    let before = std::fs::read_to_string(tmp.path().join("package.json")).unwrap();
    let out = Command::new(binary())
        .args(["setup", "--dry-run", "--yes"])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("would be updated") && stdout.contains("postinstall"),
        "non-JSON setup dry-run should preview the postinstall hook; got: {stdout}"
    );
    // Dry-run must NOT actually write the postinstall hook into the file.
    let after = std::fs::read_to_string(tmp.path().join("package.json")).unwrap();
    assert_eq!(
        before, after,
        "setup --dry-run must leave package.json untouched"
    );
    assert!(
        !after.contains("postinstall"),
        "setup --dry-run must not write a postinstall hook; got: {after}"
    );
}

// ---------------------------------------------------------------------------
// Bare-UUID fallback — `socket-patch <UUID>` rewrites to `get <UUID>`
// ---------------------------------------------------------------------------

#[test]
fn bare_uuid_fallback_treats_uuid_as_get_identifier() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "11111111-1111-4111-8111-111111111111",
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            "http://127.0.0.1:1",
            "--api-token",
            "fake",
            "--org",
            "test-org",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    // The bare UUID must be rewritten to `get <UUID>` and routed to the
    // patch-view endpoint. We prove the rewrite happened by inspecting the
    // failed-request URL in the JSON error: it must hit
    // `patches/view/<uuid>`. The old `0 || 1` would have passed even if the
    // UUID were treated as an unknown command or misrouted.
    assert_eq!(code, 1, "unreachable API must yield a failure exit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("must emit parseable JSON");
    assert_eq!(v["status"], "error", "got: {stdout}");
    let err = v["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("patches/view/11111111-1111-4111-8111-111111111111"),
        "bare-UUID fallback must route to the patch-view endpoint; got error: {err}"
    );
}

// ---------------------------------------------------------------------------
// --help on each subcommand
// ---------------------------------------------------------------------------

#[test]
fn each_subcommand_help_prints_usage() {
    let subcommands = [
        "apply", "rollback", "get", "scan", "list", "remove", "setup", "repair", "gc",
    ];
    for sub in subcommands {
        let out = Command::new(binary())
            .args([sub, "--help"])
            .output()
            .expect("run");
        assert_eq!(out.status.code(), Some(0), "subcommand {sub} --help failed");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("Usage:") || stdout.contains("USAGE"),
            "{sub} --help must print usage; got: {stdout}"
        );
    }
}

#[test]
fn top_level_help_prints_all_subcommands() {
    let out = Command::new(binary()).args(["--help"]).output().expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for sub in ["apply", "rollback", "get", "scan", "list", "remove", "setup", "repair"] {
        assert!(stdout.contains(sub), "top-level help missing {sub}; got: {stdout}");
    }
    // `gc` is the visible alias.
    assert!(stdout.contains("gc"), "top-level help missing `gc` alias");
}

#[test]
fn version_flag_prints_version() {
    let out = Command::new(binary()).args(["--version"]).output().expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Derive the expected version from the crate metadata at compile time
    // rather than a hardcoded literal. The old test OR'd in a stale
    // "3.0.0", so a binary reporting any (even wrong) version still passed.
    let expected = env!("CARGO_PKG_VERSION");
    assert!(
        stdout.contains("socket-patch") && stdout.contains(expected),
        "--version must print `socket-patch {expected}`; got: {stdout}"
    );
}
