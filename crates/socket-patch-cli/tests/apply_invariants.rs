//! Integration tests for `apply`'s state invariants.
//!
//! These lock down two contracts that make `apply` safe to run from
//! deploy hooks and CI pipelines:
//!
//! 1. `apply` is read-only against `.socket/`. Even when fetching missing
//!    sources over the network, downloaded bytes go to an OS tempdir and
//!    `.socket/` itself is byte-identical before and after the run.
//! 2. `apply --offline` against a manifest with no usable local source
//!    surfaces a `partial_failure` JSON envelope and exits non-zero —
//!    the documented airgap behavior.
//!
//! Both tests run fully offline: no network calls, no real package
//! installs. The manifest references a synthetic PURL that the npm
//! crawler won't match, which trips the "no packages found / offline"
//! branches and exercises the invariants without needing a real fixture.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Minimal manifest with one synthetic patch entry. The PURL points at a
/// package that won't be found on disk; the `afterHash` blob is missing
/// from `.socket/blobs/`. This forces every branch we want to test —
/// `--offline` bails out, and the no-mutation invariant holds because
/// nothing actually runs.
const MANIFEST_JSON: &str = r#"{
  "patches": {
    "pkg:npm/__invariant_test_pkg__@9.9.9": {
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {
        "package/index.js": {
          "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
          "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111"
        }
      },
      "vulnerabilities": {},
      "description": "synthetic invariant test patch",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#;

fn write_project(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), MANIFEST_JSON).expect("write manifest");
    // Pre-create the blobs dir with a sentinel file so the recursive
    // hash has something stable to chew on. Apply must not delete or
    // alter this file.
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).expect("create blobs dir");
    std::fs::write(blobs.join("sentinel"), b"do not modify me").expect("write sentinel");
    // Empty node_modules so the npm crawler returns nothing.
    std::fs::create_dir_all(root.join("node_modules")).expect("create node_modules");
    // A package.json so the crawler considers this a project root.
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"invariant-test","version":"0.0.0"}"#,
    )
    .expect("write package.json");
}

/// Recursive, stable hash of every regular file under `dir`. Combines
/// each file's relative path and bytes into a single SHA-256 so any
/// change — adding, removing, or rewriting a file — flips the digest.
///
/// Excludes `apply.lock` (advisory lock file created by `apply` /
/// `rollback` / `repair` / `remove`). That file is deliberate
/// ephemeral session state — not patch content — and persists by
/// design so subsequent runs can re-flock the same inode without a
/// create race. The "apply is read-only against .socket/" invariant
/// is about the patch payload (manifest, blobs, diffs, packages),
/// not session metadata.
fn dir_hash(dir: &Path) -> String {
    let mut files: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    collect_files(dir, dir, &mut files);
    files.retain(|(rel, _)| rel.file_name().and_then(|n| n.to_str()) != Some("apply.lock"));
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    for (rel, bytes) in files {
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(b"\0");
        hasher.update(&bytes);
        hasher.update(b"\0");
    }
    hex::encode(hasher.finalize())
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            collect_files(root, &path, out);
        } else if file_type.is_file() {
            let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            if let Ok(bytes) = std::fs::read(&path) {
                out.push((rel, bytes));
            }
        }
    }
}

fn run_apply(cwd: &Path, extra: &[&str]) -> (i32, String) {
    let mut args = vec!["apply", "--json"];
    args.extend_from_slice(extra);
    let out = Command::new(binary())
        .args(&args)
        .current_dir(cwd)
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_CLI_API_TOKEN")
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

/// Every counter in the envelope's `summary` block must be exactly 0.
/// We enumerate the keys explicitly (rather than "applied == 0") so a
/// regression that started reporting work on these no-op paths — e.g. a
/// phantom `downloaded`, `verified`, or `skipped` — trips the test
/// instead of slipping through an unchecked field.
fn assert_summary_all_zero(summary: &serde_json::Value) {
    let obj = summary
        .as_object()
        .unwrap_or_else(|| panic!("summary must be a JSON object, got {summary}"));
    assert!(!obj.is_empty(), "summary object must not be empty");
    for (key, val) in obj {
        assert_eq!(
            val.as_u64(),
            Some(0),
            "summary.{key} must be 0 on this no-op path, got {val}"
        );
    }
}

const SCOPED_NPM_PURL: &str = "pkg:npm/scopedpkg@1.0.0";
const SCOPED_ORIGINAL: &[u8] = b"module.exports = function vulnerable() { return 'pwn'; };\n";
const SCOPED_PATCHED: &[u8] = b"module.exports = function safe() { return 'ok'; };\n";

/// Git SHA-256: `SHA256("blob <len>\0" ++ content)`. Computed
/// independently here so the manifest hashes are NOT derived from the
/// code under test (no circular oracle).
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Lay down a project with TWO manifest patches:
///   - an npm patch that is fully applicable offline (package installed,
///     patched blob present in `.socket/blobs/`), and
///   - a pypi patch whose blob is missing from `.socket/` entirely.
///
/// Used to prove the offline no-local-source guard is scoped to the
/// patches the run can actually apply (`--ecosystems` filter).
fn write_mixed_scope_project(root: &Path) {
    let before = git_sha256(SCOPED_ORIGINAL);
    let after = git_sha256(SCOPED_PATCHED);

    std::fs::write(
        root.join("package.json"),
        r#"{"name":"scope-test","version":"0.0.0"}"#,
    )
    .expect("write package.json");

    let pkg = root.join("node_modules").join("scopedpkg");
    std::fs::create_dir_all(&pkg).expect("create package dir");
    std::fs::write(
        pkg.join("package.json"),
        r#"{"name":"scopedpkg","version":"1.0.0"}"#,
    )
    .expect("write pkg package.json");
    std::fs::write(pkg.join("index.js"), SCOPED_ORIGINAL).expect("write index.js");

    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).expect("create blobs");
    std::fs::write(socket.join("blobs").join(&after), SCOPED_PATCHED).expect("write blob");
    let manifest = format!(
        r#"{{
  "patches": {{
    "{SCOPED_NPM_PURL}": {{
      "uuid": "33333333-3333-4333-8333-333333333333",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{ "beforeHash": "{before}", "afterHash": "{after}" }}
      }},
      "vulnerabilities": {{}},
      "description": "in-scope npm patch with local sources",
      "license": "MIT",
      "tier": "free"
    }},
    "pkg:pypi/__ghost_pkg__@9.9.9": {{
      "uuid": "44444444-4444-4444-8444-444444444444",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "ghost.py": {{
          "beforeHash": "2222222222222222222222222222222222222222222222222222222222222222",
          "afterHash":  "3333333333333333333333333333333333333333333333333333333333333333"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "out-of-scope pypi patch with NO local source",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).expect("write manifest");
}

/// Regression: the `--offline` no-local-source guard (and the download
/// planner feeding it) must only consider patches that are in scope for
/// THIS run. A patch filtered out by `--ecosystems` — or belonging to an
/// ecosystem this build can't apply at all — will never be applied, so
/// its missing `.socket/` sources must not fail a run whose in-scope
/// patches are all locally applicable.
///
/// Before the fix, the guard scanned the WHOLE manifest: here the
/// out-of-scope pypi patch (no blob on disk) tripped the offline bail and
/// the fully-applicable npm patch was never applied (exit 1, no events).
#[test]
fn offline_ecosystems_filter_ignores_out_of_scope_missing_source() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_mixed_scope_project(tmp.path());

    let (code, stdout) = run_apply(
        tmp.path(),
        &["--offline", "--silent", "--ecosystems", "npm"],
    );
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("apply --json must emit valid JSON");
    assert_eq!(
        code, 0,
        "all in-scope (npm) patches have local sources; the out-of-scope pypi \
         patch must not trip the offline bail. envelope:\n{v}"
    );
    assert_eq!(v["status"], "success", "expected a clean apply, got {v}");
    let events = v["events"].as_array().expect("events array");
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "applied" && e["purl"] == SCOPED_NPM_PURL),
        "the in-scope npm patch must actually be applied; got {events:?}"
    );
    // The patched bytes really landed on disk.
    assert_eq!(
        std::fs::read(
            tmp.path()
                .join("node_modules")
                .join("scopedpkg")
                .join("index.js")
        )
        .expect("read patched file"),
        SCOPED_PATCHED,
        "in-scope npm patch must be written to disk"
    );

    // CONTROL: the same fixture WITHOUT the `--ecosystems` filter puts the
    // sourceless pypi patch in scope, so the documented offline bail must
    // still fire — the fix scopes the guard, it does not disable it.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    write_mixed_scope_project(tmp2.path());
    let (code2, stdout2) = run_apply(tmp2.path(), &["--offline", "--silent"]);
    assert_eq!(
        code2, 1,
        "with no ecosystem filter the sourceless pypi patch is in scope and \
         must still trip the offline bail; stdout=\n{stdout2}"
    );
    let v2: serde_json::Value =
        serde_json::from_str(&stdout2).expect("apply --json must emit valid JSON");
    assert_eq!(v2["status"], "partialFailure", "{v2}");
}

#[test]
fn offline_with_missing_source_emits_partial_failure() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_project(tmp.path());

    let (code, stdout) = run_apply(tmp.path(), &["--offline", "--silent"]);

    // Exit code 1 is contract: any patch without a usable source under
    // `--offline` flips the run to partialFailure.
    assert_eq!(code, 1, "unexpected exit code; stdout=\n{stdout}");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("apply --json must emit valid JSON");
    assert_eq!(v["command"], "apply");
    assert_eq!(
        v["status"], "partialFailure",
        "expected status=partialFailure, got {v}"
    );
    // `partialFailure` is distinct from a hard `error` envelope: the
    // command ran to completion and decided nothing was applicable. A
    // top-level `error` payload here would mean a different failure mode
    // slipped through wearing the partialFailure label.
    assert!(
        v.get("error").is_none(),
        "partialFailure must not carry a top-level error payload; got {v}"
    );
    // Nothing was applied, downloaded, skipped, or otherwise touched —
    // the offline guard bails before any work. Every summary counter
    // must be 0 (not just `applied`/`failed`), and no per-patch events
    // should be emitted on this short-circuit path.
    assert_summary_all_zero(&v["summary"]);
    let events = v["events"]
        .as_array()
        .expect("envelope must carry an events array");
    assert!(
        events.is_empty(),
        "offline bail emits no per-patch events; got {events:?}"
    );
}

#[test]
fn apply_does_not_mutate_socket_dir_offline() {
    // Even on the failure path (offline + missing source), apply must
    // not touch `.socket/`. The directory hash should match exactly.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_project(tmp.path());

    let socket = tmp.path().join(".socket");
    let before = dir_hash(&socket);
    let (code, stdout) = run_apply(tmp.path(), &["--offline", "--silent"]);
    let after = dir_hash(&socket);

    // The run must have actually taken the failure path we care about —
    // otherwise an apply that errored out *before* reaching any write
    // would also leave `.socket/` pristine and the hash check would pass
    // vacuously. Pin the exit code AND the envelope status so the
    // no-mutation guarantee is anchored to the documented offline bail.
    assert_eq!(code, 1, "offline+missing should exit 1; stdout=\n{stdout}");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("apply --json must emit valid JSON");
    assert_eq!(
        v["status"], "partialFailure",
        "expected the offline partialFailure path, got {v}"
    );
    assert_eq!(
        before, after,
        "apply --offline must not mutate .socket/; hash changed"
    );
    // Belt-and-suspenders against a dir_hash blind spot: read the two
    // payload files back and confirm they are byte-identical to what
    // `write_project` laid down.
    assert_eq!(
        std::fs::read(socket.join("blobs").join("sentinel")).expect("sentinel survives"),
        b"do not modify me",
        "apply must not rewrite the blobs sentinel"
    );
    assert_eq!(
        std::fs::read_to_string(socket.join("manifest.json")).expect("manifest survives"),
        MANIFEST_JSON,
        "apply must not rewrite manifest.json"
    );
}

#[test]
fn apply_does_not_mutate_socket_dir_when_no_packages_match() {
    // Same hash invariant when not offline. With no packages installed
    // and a synthetic PURL, apply's "no packages found" branch fires
    // before any fetch is attempted. `.socket/` must remain pristine.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_project(tmp.path());

    let socket = tmp.path().join(".socket");
    let before = dir_hash(&socket);
    let (code, stdout) = run_apply(tmp.path(), &["--silent"]);
    let after = dir_hash(&socket);

    // Previously this test discarded the result entirely (`let _ = ...`),
    // so a build that crashed, hung, exited 0, or wrote garbage to stdout
    // would still "pass" as long as it happened not to touch `.socket/`.
    // Pin the contract: the no-usable-source run reports partialFailure
    // and exits non-zero, AND leaves `.socket/` untouched.
    assert_eq!(
        code, 1,
        "no-match / unfetchable run must exit 1; stdout=\n{stdout}"
    );
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("apply --json must emit valid JSON");
    assert_eq!(v["command"], "apply");
    assert_eq!(
        v["status"], "partialFailure",
        "expected partialFailure on the no-match path, got {v}"
    );
    assert!(
        v.get("error").is_none(),
        "no-match path is a partialFailure, not a hard error; got {v}"
    );
    // Parity with the offline test: this bail path does no work either, so
    // every summary counter must be 0 and no per-patch events should be
    // emitted. Without these a regression that started reporting phantom
    // work (a spurious `failed`/`discovered`/`downloaded`, or fabricated
    // events) on the no-match branch would pass unnoticed.
    assert_summary_all_zero(&v["summary"]);
    let events = v["events"]
        .as_array()
        .expect("envelope must carry an events array");
    assert!(
        events.is_empty(),
        "no-match bail emits no per-patch events; got {events:?}"
    );
    assert_eq!(
        before, after,
        "apply must not mutate .socket/ on the no-match path; hash changed"
    );
    assert_eq!(
        std::fs::read(socket.join("blobs").join("sentinel")).expect("sentinel survives"),
        b"do not modify me",
        "apply must not rewrite the blobs sentinel on the no-match path"
    );
    // Belt-and-suspenders against a dir_hash blind spot (same as the
    // offline test): the manifest must be byte-identical to what
    // `write_project` laid down.
    assert_eq!(
        std::fs::read_to_string(socket.join("manifest.json")).expect("manifest survives"),
        MANIFEST_JSON,
        "apply must not rewrite manifest.json on the no-match path"
    );
}

/// Apply against a directory with NO `.socket/` folder at all
/// emits a `status: "noManifest"` envelope in JSON mode and exits
/// 0 (not an error — there's just nothing to do). Covers the
/// early-return branch at the top of `commands::apply::run`.
#[test]
fn apply_with_no_socket_dir_emits_no_manifest_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Note: NO .socket/ directory at all — completely fresh tree.
    let (code, stdout) = run_apply(tmp.path(), &[]);
    assert_eq!(code, 0, "no-manifest is not an error; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("envelope must be valid JSON");
    assert_eq!(v["command"], "apply");
    assert_eq!(v["status"], "noManifest");
    // noManifest is a clean no-op, not a partial failure dressed up: no
    // error payload, no events, and every summary counter at 0.
    assert!(
        v.get("error").is_none(),
        "noManifest must not carry an error payload; got {v}"
    );
    assert!(
        v["events"]
            .as_array()
            .expect("envelope must carry an events array")
            .is_empty(),
        "noManifest emits no events; got {}",
        v["events"]
    );
    assert_summary_all_zero(&v["summary"]);
}

/// Non-JSON / silent flag: same no-manifest case but in human
/// (non-JSON) mode with `--silent` suppresses the friendly
/// message. Exit still 0. Locks the silent-mode short-circuit.
#[test]
fn apply_with_no_socket_dir_silent_emits_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = Command::new(binary())
        .args(["apply", "--silent"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_CLI_API_TOKEN")
        .output()
        .expect("run socket-patch");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim().is_empty(),
        "silent must produce no stdout; got {stdout:?}"
    );

    // Control run: the same no-manifest scenario WITHOUT `--silent` must
    // print the friendly skip message to stdout. Without this control the
    // test above would pass vacuously even if `--silent` did nothing and
    // the message simply never existed — i.e. it would not actually prove
    // the silent-mode short-circuit suppresses anything.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    let loud = Command::new(binary())
        .args(["apply"])
        .current_dir(tmp2.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_CLI_API_TOKEN")
        .output()
        .expect("run socket-patch");
    assert_eq!(loud.status.code(), Some(0));
    let loud_stdout = String::from_utf8_lossy(&loud.stdout);
    assert!(
        loud_stdout.contains("No .socket folder found"),
        "non-silent no-manifest run must print the skip message; got {loud_stdout:?}"
    );
}
