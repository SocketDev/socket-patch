//! Mismatch-policy contract for release-variant (gem) packages.
//!
//! For npm, a locally-modified file is handled by the documented default
//! mismatch policy: warn + apply the full verified patched content,
//! `--strict` refuses, `--force` also skips missing files (see
//! `apply_network.rs::apply_hash_mismatch_default_warns_and_applies_strict_fails`).
//! Release-variant ecosystems (gem/pypi/maven) route through the variant
//! loop instead, whose installed-distribution gate used to skip ANY
//! variant whose representative file mismatched — making the default
//! policy unreachable for them: a SINGLETON base (one manifest record for
//! the `package@version`, the common case) with a locally-modified file
//! failed with "no matching variant found" instead of warn-overwriting.
//!
//! Behaviors pinned (all offline, real binary, synthetic gem trees):
//!   * singleton + locally-modified file: default apply warns
//!     (`content_mismatch_overwritten`) AND applies the full afterHash
//!     bytes; `--strict` refuses (file untouched, exit 1); `--force`
//!     keeps applying as before.
//!   * multi-variant base: UNCHANGED — only the installed variant is
//!     applied; the mismatched sibling is skipped, never warn-overwritten
//!     (a sibling mismatch means "different distribution", not "locally
//!     modified"). When NO variant matches, the base still fails with
//!     "no matching variant found" and the file stays untouched.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

const SINGLETON_PURL: &str = "pkg:gem/rack@3.1.0";
const UUID_SINGLETON: &str = "31313131-3131-4131-8131-313131313131";

const PRISTINE: &[u8] = b"module Rack\n  VERSION = '3.1.0'\nend\n";
const LOCAL: &[u8] = b"module Rack\n  VERSION = '3.1.0'\nend\n# local tweak\n";
const PATCH_MARKER: &[u8] = b"\n# SOCKET-SINGLETON-PATCH\n";

const MULTI_NAME: &str = "nokogiri";
const MULTI_VERSION: &str = "1.16.5";
const UUID_LINUX: &str = "41414141-4141-4141-8141-414141414141";
const UUID_DARWIN: &str = "42424242-4242-4242-8242-424242424242";

const LINUX_PRISTINE: &[u8] = b"module Nokogiri\n  VERSION = '1.16.5'\nend\n";
const LINUX_MARKER: &[u8] = b"\n# SOCKET-LINUX-PATCH\n";
const DARWIN_BEFORE: &[u8] = b"# nokogiri.rb from the arm64-darwin gem\n";
const DARWIN_MARKER: &[u8] = b"\n# DARWIN-MARKER\n";

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Git-SHA256: SHA256("blob <len>\0" ++ content).
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn with_marker(base: &[u8], marker: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    v.extend_from_slice(marker);
    v
}

/// Run `socket-patch apply --offline --ecosystems gem <extra>` in `cwd`
/// with the ambient `SOCKET_*` environment scrubbed (prefix scrub, keeping
/// `SOCKET_NO_CONFIG`) so only the argv decides behavior, and telemetry
/// disabled.
fn run_apply(cwd: &Path, extra: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("apply")
        .args(["--offline", "--ecosystems", "gem"])
        .args(extra)
        .current_dir(cwd);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_")
            && key.to_string_lossy() != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch apply");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Synthesize an installed gem under the cwd's vendor/bundle tree (what
/// the ruby crawler scans in local mode; a real `gem install` produces
/// exactly this `gems/<name>-<version>[-<platform>]` leaf — verified
/// against RubyGems on ruby 3.4). Returns the patchable file path.
fn install_gem(cwd: &Path, leaf: &str, file_rel: &str, contents: &[u8]) -> PathBuf {
    let gem_dir = cwd
        .join("vendor")
        .join("bundle")
        .join("ruby")
        .join("3.4.0")
        .join("gems")
        .join(leaf);
    let file = gem_dir.join(file_rel);
    std::fs::create_dir_all(file.parent().unwrap()).expect("create gem dir");
    std::fs::write(&file, contents).expect("write gem file");
    file
}

fn patch_record(uuid: &str, file: &str, before_hash: &str, after_hash: &str) -> serde_json::Value {
    serde_json::json!({
        "uuid": uuid,
        "exportedAt": "2024-01-01T00:00:00Z",
        "files": { file: { "beforeHash": before_hash, "afterHash": after_hash } },
        "vulnerabilities": {},
        "description": "gem variant mismatch fixture",
        "license": "MIT",
        "tier": "free"
    })
}

fn write_socket_dir(cwd: &Path, patches: serde_json::Value, blobs: &[(&str, &[u8])]) {
    let socket = cwd.join(".socket");
    let blobs_dir = socket.join("blobs");
    std::fs::create_dir_all(&blobs_dir).expect("create .socket/blobs");
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({ "patches": patches })).unwrap(),
    )
    .expect("write manifest");
    for (hash, content) in blobs {
        std::fs::write(blobs_dir.join(hash), content).expect("write blob");
    }
}

/// Singleton fixture: one bare-PURL gem record whose only file was
/// locally modified on disk (matches NEITHER beforeHash nor afterHash);
/// the afterHash blob is staged so the offline apply has the full
/// patched bytes available. Returns the on-disk file path and the exact
/// patched bytes a correct warn-overwrite must produce.
fn singleton_fixture(cwd: &Path) -> (PathBuf, Vec<u8>) {
    let patched = with_marker(PRISTINE, PATCH_MARKER);
    let file = install_gem(cwd, "rack-3.1.0", "lib/rack.rb", LOCAL);
    write_socket_dir(
        cwd,
        serde_json::json!({
            SINGLETON_PURL: patch_record(
                UUID_SINGLETON,
                "lib/rack.rb",
                &git_sha256(PRISTINE),
                &git_sha256(&patched),
            )
        }),
        &[(&git_sha256(&patched), patched.as_slice())],
    );
    // Fixture sanity: the on-disk bytes must match neither hash, or the
    // mismatch path under test is never taken.
    assert_ne!(git_sha256(LOCAL), git_sha256(PRISTINE));
    assert_ne!(git_sha256(LOCAL), git_sha256(&patched));
    (file, patched)
}

/// Default policy: the singleton's local modification is overwritten with
/// the full verified patched content and surfaced as a warning — the same
/// npm contract, previously unreachable for gem (the run failed with
/// "no matching variant found" and left the file untouched).
#[test]
fn singleton_mismatch_default_warns_and_applies() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (file, patched) = singleton_fixture(tmp.path());

    let (code, _stdout, stderr) = run_apply(tmp.path(), &[]);
    assert_eq!(
        code, 0,
        "default mismatch on a singleton variant is a warning, not an error; stderr={stderr}"
    );
    assert_eq!(
        std::fs::read(&file).expect("read patched file"),
        patched,
        "the file must carry exactly the verified patched bytes"
    );
    assert!(
        stderr.contains("content_mismatch_overwritten"),
        "the overwrite must be surfaced as the npm-family mismatch warning; stderr={stderr}"
    );
    assert!(
        stderr.contains(SINGLETON_PURL),
        "the warning must name the package; stderr={stderr}"
    );
    assert!(
        stderr.contains("applied the full verified patched content"),
        "the warning must say what happened to the file; stderr={stderr}"
    );

    // JSON envelope twin: `applied` event for the purl plus the per-file
    // warning event — the same shape apply_network pins for npm.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (file, patched) = singleton_fixture(tmp.path());
    let (code, stdout, _stderr) = run_apply(tmp.path(), &["--json"]);
    assert_eq!(code, 0, "json run must also succeed; stdout={stdout}");
    assert_eq!(std::fs::read(&file).expect("read patched file"), patched);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON envelope");
    assert_eq!(v["status"], "success", "{v:#}");
    let events = v["events"].as_array().expect("events array");
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "applied" && e["purl"] == SINGLETON_PURL),
        "singleton must be reported applied: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e["errorCode"] == "content_mismatch_overwritten"),
        "the overwrite must ride as a warning event: {events:?}"
    );
}

/// `--strict` restores the fail-closed contract for the singleton: exit 1
/// with the per-file hash-mismatch error and the file byte-identical.
#[test]
fn singleton_mismatch_strict_refuses() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (file, _patched) = singleton_fixture(tmp.path());

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--strict"]);
    assert_eq!(
        code, 1,
        "--strict must refuse the mismatch; stderr={stderr}"
    );
    assert_eq!(
        std::fs::read(&file).expect("read file"),
        LOCAL,
        "--strict must not modify the file"
    );
    assert!(
        stderr.contains(&format!("Failed to patch {SINGLETON_PURL}")),
        "--strict must fail the package with a per-package error; stderr={stderr}"
    );
    assert!(
        stderr.contains("File hash does not match expected value"),
        "--strict must name the actual refusal (the hash mismatch), not a \
         generic no-matching-variant miss; stderr={stderr}"
    );
    assert!(
        !stderr.contains("content_mismatch_overwritten"),
        "--strict must not claim an overwrite happened; stderr={stderr}"
    );
}

/// `--force` behavior is unchanged by the singleton fall-through: it
/// bypassed the gate before and still applies the full patched bytes.
#[test]
fn singleton_mismatch_force_still_applies() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (file, patched) = singleton_fixture(tmp.path());

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--force"]);
    assert_eq!(code, 0, "--force must keep applying; stderr={stderr}");
    assert_eq!(
        std::fs::read(&file).expect("read patched file"),
        patched,
        "--force must overwrite with the verified patched bytes"
    );
}

fn multi_purl(platform: &str) -> String {
    format!("pkg:gem/{MULTI_NAME}@{MULTI_VERSION}?platform={platform}")
}

/// Multi-variant fixture: the x86_64-linux variant is installed (its
/// beforeHash matches the on-disk bytes unless `local_bytes` overrides
/// them); the arm64-darwin sibling describes a DIFFERENT distribution
/// whose beforeHash can never match. Both afterHash blobs are staged.
fn multi_variant_fixture(cwd: &Path, on_disk: &[u8]) -> (PathBuf, Vec<u8>, Vec<u8>) {
    let linux_patched = with_marker(LINUX_PRISTINE, LINUX_MARKER);
    let darwin_patched = with_marker(DARWIN_BEFORE, DARWIN_MARKER);
    let file = install_gem(
        cwd,
        &format!("{MULTI_NAME}-{MULTI_VERSION}-x86_64-linux"),
        &format!("lib/{MULTI_NAME}.rb"),
        on_disk,
    );
    write_socket_dir(
        cwd,
        serde_json::json!({
            multi_purl("x86_64-linux"): patch_record(
                UUID_LINUX,
                "lib/nokogiri.rb",
                &git_sha256(LINUX_PRISTINE),
                &git_sha256(&linux_patched),
            ),
            multi_purl("arm64-darwin"): patch_record(
                UUID_DARWIN,
                "lib/nokogiri.rb",
                &git_sha256(DARWIN_BEFORE),
                &git_sha256(&darwin_patched),
            ),
        }),
        &[
            (&git_sha256(&linux_patched), linux_patched.as_slice()),
            (&git_sha256(&darwin_patched), darwin_patched.as_slice()),
        ],
    );
    (file, linux_patched, darwin_patched)
}

/// Over-broadening guard: a MULTI-variant base keeps the current
/// behavior. The installed variant applies; the mismatched sibling means
/// "different distribution" and is skipped — its bytes must never be
/// warn-overwritten onto the installed gem, and no mismatch warning may
/// fire.
#[test]
fn multi_variant_mismatched_sibling_is_skipped_not_overwritten() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (file, linux_patched, _darwin_patched) = multi_variant_fixture(tmp.path(), LINUX_PRISTINE);

    let (code, _stdout, stderr) = run_apply(tmp.path(), &[]);
    assert_eq!(
        code, 0,
        "the installed variant must apply cleanly; stderr={stderr}"
    );
    let after = std::fs::read(&file).expect("read patched file");
    assert_eq!(
        after, linux_patched,
        "the file must carry exactly the installed platform's patched bytes"
    );
    assert!(
        !after
            .windows(DARWIN_MARKER.len())
            .any(|w| w == DARWIN_MARKER),
        "the sibling distribution's bytes must never be written"
    );
    assert!(
        !stderr.contains("content_mismatch_overwritten"),
        "a sibling-variant mismatch is a skip, not an overwrite warning; stderr={stderr}"
    );
}

/// Second guard: when NO variant of a multi-variant base matches the
/// on-disk bytes (locally-modified file), the base still fails with the
/// no-matching-variant error and the file stays untouched — the
/// mismatch-policy fall-through is singleton-only.
#[test]
fn multi_variant_none_matching_still_fails_closed() {
    let local = with_marker(LINUX_PRISTINE, b"# local tweak\n");
    let tmp = tempfile::tempdir().expect("tempdir");
    let (file, linux_patched, darwin_patched) = multi_variant_fixture(tmp.path(), &local);
    assert_ne!(git_sha256(&local), git_sha256(LINUX_PRISTINE));
    assert_ne!(git_sha256(&local), git_sha256(DARWIN_BEFORE));

    let (code, _stdout, stderr) = run_apply(tmp.path(), &[]);
    assert_eq!(
        code, 1,
        "a multi-variant base with no matching variant must keep failing; stderr={stderr}"
    );
    assert!(
        stderr.contains("no matching variant found"),
        "the failure must stay the no-matching-variant error; stderr={stderr}"
    );
    let after = std::fs::read(&file).expect("read file");
    assert_eq!(
        after, local,
        "no variant matched, so nothing may be written"
    );
    assert_ne!(after, linux_patched);
    assert_ne!(after, darwin_patched);
}
