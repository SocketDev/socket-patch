//! End-to-end: `socket-patch apply` against a Cargo vendor source
//! followed by `cargo check` succeeds.
//!
//! This is the load-bearing integration test for the
//! `crates/socket-patch-core/src/patch/sidecars/cargo.rs` fixup.
//! Patching a vendored crate's source file without updating
//! `.cargo-checksum.json` causes cargo to refuse the build with
//! "the listed checksum has changed". The sidecar rewrite makes
//! the build pass — and this test proves it end to end, not just
//! at the unit level.
//!
//! ## Setup
//!
//! - `<tmp>/consumer/`: a tiny binary crate that depends on
//!   `safety-fixture = "1.0.0"`.
//! - `<tmp>/consumer/vendor/safety-fixture/`: hand-crafted vendored
//!   crate with a valid `.cargo-checksum.json`.
//! - `<tmp>/consumer/.cargo/config.toml`: routes `crates-io` to the
//!   local `vendor/` directory source.
//! - `cargo generate-lockfile --offline` produces the consumer's
//!   Cargo.lock pointing at the vendored entry — no network.
//!
//! ## Tests
//!
//! 1. **Smoke**: `cargo check --offline --frozen` succeeds against
//!    the un-patched fixture. Establishes the baseline.
//! 2. **Negative control**: mutate the source file without running
//!    apply, run `cargo check` — fails with "checksum changed".
//!    Proves cargo actually verifies.
//! 3. **Sidecar round trip**: synthesize a `.socket/manifest.json` plus an
//!    after-hash blob, run `socket-patch apply`, run `cargo check` — it
//!    succeeds. The sidecar fixup is the load-bearing piece.
//! 4. **`package` field preserved**: assert
//!    `.cargo-checksum.json`'s `"package"` key survives the rewrite
//!    unchanged (cargo doesn't verify it at build time, but we
//!    don't want to silently regress).
//!
//! Network: no. Toolchain: cargo (already on every e2e CI runner).
//! `#[ignore]` gated because it shells out to `cargo`.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

#[path = "common/mod.rs"]
mod common;

use common::{
    assert_run_ok, cargo_run, has_command, parse_json_envelope, run, sha256_hex, write_blob,
    write_minimal_manifest, PatchEntry,
};

const ORIGINAL_LIB_RS: &str = "pub fn hello() -> &'static str { \"world\" }\n";
const PATCHED_LIB_RS: &str = "pub fn hello() -> &'static str { \"PATCHED\" }\n";
const FIXTURE_TOML: &str =
    "[package]\nname = \"safety-fixture\"\nversion = \"1.0.0\"\nedition = \"2021\"\n";

/// PURL the synthetic manifest points at. The cargo crawler resolves
/// `pkg:cargo/<name>@<version>` against the consumer's `vendor/`
/// directory (vendor layout: `<name>/` bare, no version suffix).
const FIXTURE_PURL: &str = "pkg:cargo/safety-fixture@1.0.0";
const FIXTURE_UUID: &str = "11111111-2222-4111-8111-111111111111";

// ── Setup helpers ─────────────────────────────────────────────────────

/// Build the consumer + vendor directory tree under `root`.
/// Returns the consumer dir (the working directory for cargo + apply
/// invocations).
fn stage_consumer(root: &Path) -> PathBuf {
    let consumer = root.join("consumer");
    let vendor_fixture = consumer.join("vendor").join("safety-fixture");
    std::fs::create_dir_all(consumer.join("src")).unwrap();
    std::fs::create_dir_all(consumer.join(".cargo")).unwrap();
    std::fs::create_dir_all(vendor_fixture.join("src")).unwrap();

    // Consumer manifest + entry point.
    std::fs::write(
        consumer.join("Cargo.toml"),
        r#"[package]
name = "consumer"
version = "0.1.0"
edition = "2021"

[dependencies]
safety-fixture = "1.0.0"
"#,
    )
    .unwrap();
    std::fs::write(
        consumer.join("src/main.rs"),
        "fn main() { println!(\"{}\", safety_fixture::hello()); }\n",
    )
    .unwrap();

    // Route crates-io to the local vendor directory. The directory
    // source verifies per-file SHA256 against .cargo-checksum.json
    // at build time — exactly the verification we want to exercise.
    std::fs::write(
        consumer.join(".cargo/config.toml"),
        r#"[source.crates-io]
replace-with = "vendored-test"

[source.vendored-test]
directory = "vendor"
"#,
    )
    .unwrap();

    // Vendored crate sources.
    std::fs::write(vendor_fixture.join("Cargo.toml"), FIXTURE_TOML).unwrap();
    std::fs::write(vendor_fixture.join("src/lib.rs"), ORIGINAL_LIB_RS).unwrap();

    // Initial .cargo-checksum.json matching the on-disk sources.
    write_checksum_json(&vendor_fixture);

    consumer
}

/// Recompute `.cargo-checksum.json` from the current on-disk source
/// files. Mirrors what `cargo vendor` produces: raw SHA256 of file
/// bytes (not the Git-blob framing socket-patch uses for its own
/// hashes). The `package` field can be any 64-hex string —
/// directory sources don't verify it.
fn write_checksum_json(vendor_fixture: &Path) {
    let toml_hash = sha256_hex(&std::fs::read(vendor_fixture.join("Cargo.toml")).unwrap());
    let lib_hash = sha256_hex(&std::fs::read(vendor_fixture.join("src/lib.rs")).unwrap());
    let json = serde_json::json!({
        "files": {
            "Cargo.toml": toml_hash,
            "src/lib.rs": lib_hash,
        },
        // Sentinel package hash — directory sources don't validate
        // this field. We assert it survives the apply rewrite
        // unchanged so we can spot a regression that starts
        // touching it.
        "package": "0".repeat(64),
    });
    std::fs::write(
        vendor_fixture.join(".cargo-checksum.json"),
        serde_json::to_string_pretty(&json).unwrap(),
    )
    .unwrap();
}

/// Use cargo to generate the consumer's Cargo.lock against the
/// directory source. Runs `--offline`; the source is local so no
/// network access is needed. Sets a sandboxed CARGO_HOME so the
/// test never touches the user's real cargo cache.
fn generate_lockfile(consumer: &Path, cargo_home: &Path) {
    let out = Command::new("cargo")
        .args(["generate-lockfile", "--offline"])
        .current_dir(consumer)
        .env("CARGO_HOME", cargo_home)
        .output()
        .expect("cargo generate-lockfile");
    assert!(
        out.status.success(),
        "cargo generate-lockfile failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Run `cargo check --offline --frozen` against the consumer.
/// Returns the cargo Output so the caller can inspect both pass and
/// failure modes.
fn cargo_check(consumer: &Path, cargo_home: &Path) -> std::process::Output {
    // Wipe target/ so cargo re-resolves the directory source. The
    // checksum verification happens at *unpack/copy* time, and once
    // a build has consumed the source cargo will short-circuit on
    // subsequent runs even if the underlying files changed.
    let _ = std::fs::remove_dir_all(consumer.join("target"));
    cargo_run(
        consumer,
        &["check", "--offline", "--frozen"],
        &[("CARGO_HOME", cargo_home.to_str().unwrap())],
    )
}

/// Compute the apply manifest entries for "patch lib.rs from
/// ORIGINAL → PATCHED". Returns `(before_hash, after_hash)` as
/// Git-SHA-256 hex (the hash format socket-patch records).
fn git_hashes() -> (String, String) {
    (
        git_sha256(ORIGINAL_LIB_RS.as_bytes()),
        git_sha256(PATCHED_LIB_RS.as_bytes()),
    )
}

/// Local Git-SHA-256 helper (sha2 + the "blob N\0" framing). We have
/// one in `common` but keep an inline copy to keep the test self-
/// readable.
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Stage `.socket/manifest.json` + `.socket/blobs/<after_hash>` so
/// the apply pipeline can run fully offline against the synthetic
/// vendored crate.
fn stage_socket_manifest(consumer: &Path) -> (String, String) {
    let (before, after) = git_hashes();
    let socket_dir = consumer.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        FIXTURE_PURL,
        FIXTURE_UUID,
        &[PatchEntry {
            file_name: "src/lib.rs",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    // Stage the after-hash blob — apply's offline path reads the
    // bytes from `.socket/blobs/<hash>` and writes them on top of
    // the on-disk file.
    write_blob(&socket_dir, &after, PATCHED_LIB_RS.as_bytes());
    (before, after)
}

// ── Tests ─────────────────────────────────────────────────────────────

/// Smoke: the un-patched fixture builds. If this fails the whole
/// fixture is broken and the other tests are noise.
#[test]
#[ignore]
fn cargo_check_succeeds_against_unpatched_fixture() {
    if !has_command("cargo") {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let consumer = stage_consumer(root.path());
    let cargo_home = root.path().join(".cargo-home");

    generate_lockfile(&consumer, &cargo_home);
    let out = cargo_check(&consumer, &cargo_home);
    assert!(
        out.status.success(),
        "baseline cargo check should succeed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Negative control: mutate the source file WITHOUT running apply,
/// build — cargo must reject with "checksum changed". This proves
/// that cargo's directory-source verification is actually firing,
/// which means the *positive* test below is meaningful.
#[test]
#[ignore]
fn cargo_check_fails_without_sidecar_fixup() {
    if !has_command("cargo") {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let consumer = stage_consumer(root.path());
    let cargo_home = root.path().join(".cargo-home");
    generate_lockfile(&consumer, &cargo_home);

    // Sanity: baseline builds.
    assert!(cargo_check(&consumer, &cargo_home).status.success());

    // Mutate the source file in place, keep the OLD checksum file —
    // this is "what a naive patch tool (without the sidecar fixup)
    // would do."
    std::fs::write(
        consumer.join("vendor/safety-fixture/src/lib.rs"),
        PATCHED_LIB_RS,
    )
    .unwrap();

    let out = cargo_check(&consumer, &cargo_home);
    assert!(
        !out.status.success(),
        "cargo check should refuse mismatched checksum"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("checksum") && stderr.contains("changed"),
        "expected 'checksum...changed' error from cargo, got:\nstderr:\n{stderr}"
    );
}

/// The headline test: socket-patch apply rewrites both the source
/// file and `.cargo-checksum.json`, and cargo accepts the result.
#[test]
#[ignore]
fn apply_then_cargo_check_succeeds() {
    if !has_command("cargo") {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let consumer = stage_consumer(root.path());
    let cargo_home = root.path().join(".cargo-home");
    generate_lockfile(&consumer, &cargo_home);

    // Baseline must build.
    assert!(cargo_check(&consumer, &cargo_home).status.success());

    // Stage manifest + blob, then run apply.
    let (_before, after) = stage_socket_manifest(&consumer);

    // Snapshot the original `.cargo-checksum.json` so we can assert
    // the apply both rewrote the per-file hash AND preserved the
    // `package` field.
    let pre_checksum: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(consumer.join("vendor/safety-fixture/.cargo-checksum.json"))
            .unwrap(),
    )
    .unwrap();

    let (_stdout, _stderr) = assert_run_ok(
        &consumer,
        &["apply", "--cwd", consumer.to_str().unwrap()],
        "socket-patch apply",
    );

    // On-disk file is patched.
    assert_eq!(
        std::fs::read_to_string(consumer.join("vendor/safety-fixture/src/lib.rs")).unwrap(),
        PATCHED_LIB_RS,
        "source file should reflect the patched content"
    );

    // The sidecar rewrote `.cargo-checksum.json`. The "src/lib.rs"
    // entry must now be the raw SHA256 of the patched bytes; the
    // `package` field must be unchanged.
    let post_checksum: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(consumer.join("vendor/safety-fixture/.cargo-checksum.json"))
            .unwrap(),
    )
    .unwrap();
    let expected_lib_hash = sha256_hex(PATCHED_LIB_RS.as_bytes());
    assert_eq!(
        post_checksum["files"]["src/lib.rs"].as_str(),
        Some(expected_lib_hash.as_str()),
        "sidecar should rewrite src/lib.rs entry to the new SHA256.\npost: {post_checksum}"
    );
    assert_eq!(
        post_checksum["package"], pre_checksum["package"],
        "`package` field must survive the rewrite unchanged"
    );
    // Other entries (Cargo.toml) are NOT patched and stay the same.
    assert_eq!(
        post_checksum["files"]["Cargo.toml"], pre_checksum["files"]["Cargo.toml"],
        "unpatched entries must keep their original hash"
    );

    // The whole point: cargo now accepts the patched sources.
    let out = cargo_check(&consumer, &cargo_home);
    assert!(
        out.status.success(),
        "cargo check should succeed after sidecar fixup.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // Touch `after` to silence unused-warnings; it's the
    // ground-truth hash the manifest pinned.
    let _ = after;
}

/// Rollback twin of the headline test: after apply rewrote both the
/// source and `.cargo-checksum.json`, `socket-patch rollback` must
/// restore BOTH — the original bytes AND the original checksum entry.
/// Before the rollback-side sidecar resync, rollback restored only the
/// bytes, leaving the patched hash in the checksum file — and the
/// negative control above proves cargo then refuses to build the
/// rolled-back crate ("checksum ... has changed").
#[test]
#[ignore]
fn rollback_after_apply_then_cargo_check_succeeds() {
    if !has_command("cargo") {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let consumer = stage_consumer(root.path());
    let cargo_home = root.path().join(".cargo-home");
    generate_lockfile(&consumer, &cargo_home);

    // Baseline must build.
    assert!(cargo_check(&consumer, &cargo_home).status.success());

    let (before, _after) = stage_socket_manifest(&consumer);
    // Rollback restores from the before-hash blob; stage it alongside
    // the after-blob exactly as apply's snapshot would have left it.
    write_blob(
        &consumer.join(".socket"),
        &before,
        ORIGINAL_LIB_RS.as_bytes(),
    );

    let (_stdout, _stderr) = assert_run_ok(
        &consumer,
        &["apply", "--cwd", consumer.to_str().unwrap()],
        "socket-patch apply",
    );
    assert_eq!(
        std::fs::read_to_string(consumer.join("vendor/safety-fixture/src/lib.rs")).unwrap(),
        PATCHED_LIB_RS,
        "apply must land the patched content first"
    );

    let (_stdout, _stderr) = assert_run_ok(
        &consumer,
        &["rollback", "--cwd", consumer.to_str().unwrap()],
        "socket-patch rollback",
    );

    // Bytes are back to the original...
    assert_eq!(
        std::fs::read_to_string(consumer.join("vendor/safety-fixture/src/lib.rs")).unwrap(),
        ORIGINAL_LIB_RS,
        "rollback must restore the original source"
    );
    // ...and the checksum entry was resynced to the original hash.
    let post_checksum: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(consumer.join("vendor/safety-fixture/.cargo-checksum.json"))
            .unwrap(),
    )
    .unwrap();
    let expected_lib_hash = sha256_hex(ORIGINAL_LIB_RS.as_bytes());
    assert_eq!(
        post_checksum["files"]["src/lib.rs"].as_str(),
        Some(expected_lib_hash.as_str()),
        "rollback must resync .cargo-checksum.json to the original SHA256.\npost: {post_checksum}"
    );

    // The whole point: the rolled-back vendored crate still builds.
    let out = cargo_check(&consumer, &cargo_home);
    assert!(
        out.status.success(),
        "cargo check should succeed after rollback resynced the sidecar.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// JSON envelope sanity check on the same scenario: assert apply
/// reports the cargo sidecar in the new top-level `envelope.sidecars[]`
/// list with the structured shape.
///
/// Locks in the typed JSON contract that downstream consumers
/// (jq pipelines, dashboards, telemetry) rely on:
///   envelope.sidecars[].ecosystem == "cargo"
///   envelope.sidecars[].files[i].path == ".cargo-checksum.json"
///   envelope.sidecars[].files[i].action == "rewritten"
///
/// If a refactor flips key names or moves the data elsewhere, this
/// test fires loudly.
#[test]
#[ignore]
fn apply_reports_cargo_checksum_in_sidecars_updated() {
    if !has_command("cargo") {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let consumer = stage_consumer(root.path());
    let cargo_home = root.path().join(".cargo-home");
    generate_lockfile(&consumer, &cargo_home);
    stage_socket_manifest(&consumer);

    let (_code, stdout, stderr) = run(
        &consumer,
        &["apply", "--json", "--cwd", consumer.to_str().unwrap()],
    );

    let env = parse_json_envelope(&stdout);
    let sidecars = env["sidecars"].as_array().unwrap_or_else(|| {
        panic!("envelope must carry `sidecars` array.\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    let cargo_record = sidecars
        .iter()
        .find(|s| s["ecosystem"] == "cargo")
        .unwrap_or_else(|| {
            panic!(
                "envelope.sidecars must contain a record with ecosystem=cargo.\nstdout:\n{stdout}"
            )
        });
    let files = cargo_record["files"].as_array().expect("files array");
    assert!(
        files.iter().any(|f| {
            f["path"] == ".cargo-checksum.json" && f["action"] == "rewritten"
        }),
        "expected files[] to contain {{path:.cargo-checksum.json, action:rewritten}}; got {cargo_record}"
    );
    // No advisory expected for the cargo success path.
    assert!(
        cargo_record.get("advisory").is_none() || cargo_record["advisory"].is_null(),
        "cargo success path should not carry an advisory; got {cargo_record}"
    );
    // PURL is denormalized into the record for jq filtering.
    assert!(
        cargo_record["purl"]
            .as_str()
            .map(|p| p.starts_with("pkg:cargo/"))
            .unwrap_or(false),
        "sidecar record must carry the PURL; got {cargo_record}"
    );
}

/// Sidecar-fixup-failure boundary: when `.cargo-checksum.json` is
/// malformed, `sidecars::cargo::fixup` returns `Err(SidecarError)`.
/// The boundary in `apply_package_patch` converts that into a
/// `SidecarRecord` carrying `advisory.code = "sidecar_fixup_failed"`
/// + `severity = "error"`.
///
/// The patch itself MUST still apply (the bytes were committed
/// atomically before the sidecar runs). The envelope must surface
/// the structured error so downstream consumers can branch on
/// `advisory.code == "sidecar_fixup_failed"` rather than parsing
/// free-form text.
#[test]
fn apply_with_malformed_checksum_reports_sidecar_fixup_failed() {
    let root = tempfile::tempdir().unwrap();
    let consumer = stage_consumer(root.path());
    let cargo_home = root.path().join(".cargo-home");
    let _ = cargo_home; // unused here; lockfile + cargo check not needed
    stage_socket_manifest(&consumer);

    // Corrupt the checksum file so cargo::fixup hits the
    // `serde_json::from_str` Malformed error path. The fixup runs
    // AFTER the patch is committed atomically, so the patch itself
    // succeeds; only the sidecar emits an Error-severity advisory.
    let checksum = consumer.join("vendor/safety-fixture/.cargo-checksum.json");
    std::fs::write(&checksum, b"{this is not valid json").unwrap();

    let (code, stdout, stderr) = run(
        &consumer,
        &["apply", "--json", "--cwd", consumer.to_str().unwrap()],
    );

    // The patched bytes are on disk — atomic write committed before
    // the sidecar's failure.
    assert_eq!(
        std::fs::read_to_string(consumer.join("vendor/safety-fixture/src/lib.rs")).unwrap(),
        PATCHED_LIB_RS,
        "patch must apply even when sidecar fixup fails"
    );

    let env = parse_json_envelope(&stdout);
    // Contract: a best-effort sidecar failure does NOT fail the command.
    // The patch applied atomically, so apply exits 0 and reports the
    // top-level status as `success`; the error-severity advisory in
    // `sidecars[]` is the ONLY failure signal. Pin both so a regression
    // that bubbled the sidecar error up to a non-zero exit / a
    // `partialFailure`/`error` status (or, conversely, dropped the
    // advisory because it "looked successful") fails loudly.
    assert_eq!(
        code, 0,
        "best-effort sidecar failure must not fail the command (exit).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        env["status"], "success",
        "sidecar fixup failure must not flip the top-level status; got {env}"
    );
    let sidecars = env["sidecars"].as_array().unwrap_or_else(|| {
        panic!("envelope must carry `sidecars` array.\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    let cargo_record = sidecars
        .iter()
        .find(|s| s["ecosystem"] == "cargo")
        .unwrap_or_else(|| {
            panic!("envelope.sidecars must contain a cargo record.\nstdout:\n{stdout}")
        });
    let advisory = cargo_record.get("advisory").unwrap_or_else(|| {
        panic!("malformed checksum should produce an advisory.\nrecord: {cargo_record}")
    });
    assert_eq!(
        advisory["code"], "sidecar_fixup_failed",
        "advisory.code must be sidecar_fixup_failed; got {advisory}"
    );
    assert_eq!(
        advisory["severity"], "error",
        "boundary-converted sidecar errors are severity=error"
    );
    // Message must carry enough to diagnose: the on-disk path of the
    // file that failed to parse. `!is_empty()` was vacuous — the
    // boundary prefixes a fixed "sidecar fixup failed (patch still
    // applied): " string, so it can never be empty regardless of
    // whether the underlying detail survived. Pin the path instead so
    // a regression that swallowed the source error (generic message)
    // is caught.
    let msg = advisory["message"].as_str().unwrap_or("");
    assert!(
        msg.contains(".cargo-checksum.json"),
        "advisory.message must reference the checksum path that failed to parse; got {msg:?}"
    );
    // No `files[]` entries on the failure path — the rewriter
    // didn't get far enough to touch anything.
    let files = cargo_record["files"].as_array().expect("files array");
    assert!(
        files.is_empty(),
        "failed fixup must not report any rewritten files; got {cargo_record}"
    );
}

/// Second branch of the cargo sidecar Malformed path: the JSON
/// parses but lacks a top-level `files` object. The cargo fixup
/// surfaces this as `SidecarError::Malformed { detail: "missing or
/// non-object `files` field" }` which the apply boundary converts
/// to a `sidecar_fixup_failed` advisory at severity `error`.
///
/// Distinct from the parse-error case (above) — exercises the
/// shape-check after deserialization, which the prior test can't
/// reach. Together they cover both `Malformed` arms of cargo::fixup.
#[test]
fn apply_with_missing_files_field_reports_sidecar_fixup_failed() {
    let root = tempfile::tempdir().unwrap();
    let consumer = stage_consumer(root.path());
    stage_socket_manifest(&consumer);

    // Parseable JSON, no `files` field. Triggers the `.ok_or_else`
    // arm in cargo::fixup that returns Malformed with a different
    // detail string than the serde parse path.
    let checksum = consumer.join("vendor/safety-fixture/.cargo-checksum.json");
    std::fs::write(
        &checksum,
        br#"{"package":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run(
        &consumer,
        &["apply", "--json", "--cwd", consumer.to_str().unwrap()],
    );

    // Patch still committed atomically.
    assert_eq!(
        std::fs::read_to_string(consumer.join("vendor/safety-fixture/src/lib.rs")).unwrap(),
        PATCHED_LIB_RS,
    );

    let env = parse_json_envelope(&stdout);
    // Same best-effort contract as the parse-error arm: exit 0, status
    // success, advisory is the only failure signal.
    assert_eq!(
        code, 0,
        "best-effort sidecar failure must not fail the command.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(env["status"], "success", "got {env}");
    let sidecars = env["sidecars"].as_array().expect("sidecars array");
    let cargo = sidecars
        .iter()
        .find(|s| s["ecosystem"] == "cargo")
        .expect("cargo record");
    let advisory = cargo.get("advisory").expect("advisory");
    assert_eq!(advisory["code"], "sidecar_fixup_failed");
    assert_eq!(advisory["severity"], "error");
    // Message must mention the `files` field to be diagnostically
    // useful — distinguishes this Malformed arm from the parse arm.
    let message = advisory["message"].as_str().unwrap_or("");
    assert!(
        message.contains("files"),
        "advisory message must mention the missing `files` field; got {message:?}"
    );
    // Failed fixup reports no rewritten files (matches the parse-error
    // arm) — proves the rewriter aborted before touching anything.
    assert!(
        cargo["files"].as_array().expect("files array").is_empty(),
        "failed fixup must not report any rewritten files; got {cargo}"
    );
}

/// Regression (read-only checksum file): a real Cargo registry/vendor
/// tree marks `.cargo-checksum.json` read-only (`0o444`) for tamper
/// detection. The sidecar must STILL rewrite it — the hardened
/// stage+rename write path relaxes the file's mode, swaps a fresh
/// inode in atomically, and restores `0o444` afterward.
///
/// Before the fix the bare in-place `tokio::fs::write` failed `EACCES`
/// here and surfaced a `sidecar_fixup_failed` error, leaving the
/// checksum stale-patched and the crate unbuildable in exactly the
/// real-world (read-only-registry) case the fixup exists to handle.
///
/// Runs under any uid: even where the kernel grants root implicit
/// write, the success assertions (content rewritten, mode restored)
/// hold, so there is no root-skip false-negative to dodge.
#[cfg(unix)]
#[test]
fn apply_with_readonly_checksum_still_rewrites_it() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let consumer = stage_consumer(root.path());
    stage_socket_manifest(&consumer);

    // Lock the checksum file down exactly as Cargo would for a
    // registry/vendor source.
    let checksum = consumer.join("vendor/safety-fixture/.cargo-checksum.json");
    std::fs::set_permissions(&checksum, std::fs::Permissions::from_mode(0o444)).unwrap();

    let (code, stdout, stderr) = run(
        &consumer,
        &["apply", "--json", "--cwd", consumer.to_str().unwrap()],
    );

    // Success path: read-only checksum is rewritten cleanly, so apply
    // exits 0 with a top-level `success` status (the rewrite succeeded,
    // no advisory). Pin it so a regression that surfaced the old
    // EACCES failure can't hide behind the (separately-asserted)
    // on-disk checks.
    assert_eq!(
        code, 0,
        "read-only checksum rewrite must succeed (exit 0).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Patch landed — source file is in a writable subdir.
    assert_eq!(
        std::fs::read_to_string(consumer.join("vendor/safety-fixture/src/lib.rs")).unwrap(),
        PATCHED_LIB_RS,
    );

    // The read-only checksum was rewritten to match the patched
    // source (raw SHA256, the cargo format).
    let post: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&checksum).unwrap()).unwrap();
    assert_eq!(
        post["files"]["src/lib.rs"].as_str().unwrap(),
        sha256_hex(PATCHED_LIB_RS.as_bytes()),
        "checksum entry must reflect the patched source"
    );

    // The original `0o444` mode was restored bit-for-bit.
    let mode = std::fs::metadata(&checksum).unwrap().permissions().mode() & 0o7777;
    // Re-grant write so tempdir cleanup can unlink.
    let _ = std::fs::set_permissions(&checksum, std::fs::Permissions::from_mode(0o644));
    assert_eq!(
        mode, 0o444,
        "checksum file must stay read-only after rewrite"
    );

    // The sidecar reports a successful rewrite — not a failure advisory.
    let env = parse_json_envelope(&stdout);
    assert_eq!(
        env["status"], "success",
        "clean read-only rewrite must report top-level success; got {env}"
    );
    let cargo = env["sidecars"]
        .as_array()
        .expect("sidecars array")
        .iter()
        .find(|s| s["ecosystem"] == "cargo")
        .expect("cargo record");
    let rewrote = cargo["files"].as_array().is_some_and(|files| {
        files
            .iter()
            .any(|f| f["path"] == ".cargo-checksum.json" && f["action"] == "rewritten")
    });
    assert!(
        rewrote,
        "expected a rewritten .cargo-checksum.json file entry; got {cargo}"
    );
    assert!(
        cargo.get("advisory").map(|a| a.is_null()).unwrap_or(true),
        "successful rewrite must not carry a failure advisory; got {cargo}"
    );
}

/// Third Malformed branch: when `.cargo-checksum.json` exists but
/// is a *directory* rather than a file. `tokio::fs::read_to_string`
/// returns an I/O error with kind `IsADirectory` (Linux) /
/// `InvalidInput` (macOS) — NOT `NotFound` — so the fixup hits the
/// generic `Err(source)` arm in cargo.rs (lines 61-65) and returns
/// `SidecarError::Io`. The boundary converts that to a
/// `sidecar_fixup_failed` advisory.
///
/// Picks the "directory in place of file" route over chmod tricks
/// because chmod-based negative tests silently no-op when run as
/// root (CI containers, dev sandboxes), while a directory-as-file
/// race fails the same way for every uid.
#[test]
fn apply_with_checksum_directory_reports_sidecar_fixup_failed() {
    let root = tempfile::tempdir().unwrap();
    let consumer = stage_consumer(root.path());
    stage_socket_manifest(&consumer);

    // Replace the regular `.cargo-checksum.json` file with a
    // directory of the same name. `read_to_string` will refuse to
    // treat it as a string.
    let checksum = consumer.join("vendor/safety-fixture/.cargo-checksum.json");
    std::fs::remove_file(&checksum).unwrap();
    std::fs::create_dir(&checksum).unwrap();

    let (code, stdout, stderr) = run(
        &consumer,
        &["apply", "--json", "--cwd", consumer.to_str().unwrap()],
    );

    // Source write still succeeded — the directory-as-file ruse
    // only affects the sidecar's read step.
    assert_eq!(
        std::fs::read_to_string(consumer.join("vendor/safety-fixture/src/lib.rs")).unwrap(),
        PATCHED_LIB_RS,
    );

    let env = parse_json_envelope(&stdout);
    // Best-effort contract: exit 0, status success, advisory only.
    assert_eq!(
        code, 0,
        "best-effort sidecar failure must not fail the command.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(env["status"], "success", "got {env}");
    let cargo = env["sidecars"]
        .as_array()
        .expect("sidecars array")
        .iter()
        .find(|s| s["ecosystem"] == "cargo")
        .expect("cargo record");
    let advisory = cargo.get("advisory").expect("advisory");
    assert_eq!(advisory["code"], "sidecar_fixup_failed");
    assert_eq!(advisory["severity"], "error");
    // Message must reference the checksum path so operators can
    // locate the problem on disk.
    let msg = advisory["message"].as_str().unwrap_or("");
    assert!(
        msg.contains(".cargo-checksum.json"),
        "advisory message must reference the checksum path; got {msg:?}"
    );
    // Failed fixup reports no rewritten files.
    assert!(
        cargo["files"].as_array().expect("files array").is_empty(),
        "failed fixup must not report any rewritten files; got {cargo}"
    );
}

/// Cargo sidecar no-op: no `.cargo-checksum.json` present at all.
/// The fixup returns `Ok(None)` (lines 56-60 of cargo.rs) and the
/// envelope carries no cargo record at all — apply still succeeds
/// because the sidecar contract treats "no checksum file" as
/// "nothing to do, package isn't from a directory source".
#[test]
fn apply_without_cargo_checksum_emits_no_sidecar_record() {
    let root = tempfile::tempdir().unwrap();
    let consumer = stage_consumer(root.path());
    stage_socket_manifest(&consumer);

    // Remove the checksum entirely so the fixup hits the
    // `NotFound -> Ok(None)` early return.
    std::fs::remove_file(consumer.join("vendor/safety-fixture/.cargo-checksum.json")).unwrap();

    let (code, stdout, stderr) = run(
        &consumer,
        &["apply", "--json", "--cwd", consumer.to_str().unwrap()],
    );

    // Patch still applied.
    assert_eq!(
        std::fs::read_to_string(consumer.join("vendor/safety-fixture/src/lib.rs")).unwrap(),
        PATCHED_LIB_RS,
    );

    // Positive signal: "no checksum file => nothing to fix up" is a
    // clean success, not an error. Without this a regression that made
    // a missing checksum file FAIL the apply (exit 1 / error status)
    // would still pass the negative `!has_cargo_record` check below
    // (the patch lands atomically and no cargo record is emitted on the
    // error path either). Pin the success outcome.
    let env = parse_json_envelope(&stdout);
    assert_eq!(
        code, 0,
        "missing checksum file is a no-op success, must exit 0.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        env["status"], "success",
        "missing checksum file must report success; got {env}"
    );

    // No cargo sidecar record emitted — the fixup returned None, so
    // the apply loop never calls `record_sidecar`. The envelope's
    // `sidecars` array is either absent or empty.
    let has_cargo_record = env
        .get("sidecars")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().any(|s| s["ecosystem"] == "cargo"))
        .unwrap_or(false);
    assert!(
        !has_cargo_record,
        "no checksum file => no sidecar record; got envelope:\n{env}"
    );
}

/// The "package/" API-side prefix in a manifest entry must
/// normalize to the cargo-checksum-relative path (`src/lib.rs`,
/// not `package/src/lib.rs`). The unit test pins this at the
/// `cargo::fixup` level; this e2e proves the full pipeline
/// (apply → sidecar dispatch → cargo fixup → checksum rewrite)
/// honors it.
#[test]
fn apply_normalizes_package_prefix_in_cargo_checksum() {
    let root = tempfile::tempdir().unwrap();
    let consumer = stage_consumer(root.path());
    let socket_dir = consumer.join(".socket");
    let (before, after) = git_hashes();
    // Manifest uses the "package/" prefix that the API emits.
    write_minimal_manifest(
        &socket_dir,
        FIXTURE_PURL,
        FIXTURE_UUID,
        &[PatchEntry {
            file_name: "package/src/lib.rs",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket_dir, &after, PATCHED_LIB_RS.as_bytes());

    let (code, stdout, stderr) = run(
        &consumer,
        &["apply", "--json", "--cwd", consumer.to_str().unwrap()],
    );

    // Success path: a clean prefix-normalized rewrite must exit 0.
    assert_eq!(
        code, 0,
        "apply (prefix-normalized, no fixup error) must exit 0.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Patch landed despite the prefixed key.
    assert_eq!(
        std::fs::read_to_string(consumer.join("vendor/safety-fixture/src/lib.rs")).unwrap(),
        PATCHED_LIB_RS,
    );

    // `.cargo-checksum.json` was rewritten with the normalized key
    // `src/lib.rs` — NOT `package/src/lib.rs`. Cargo would reject
    // the latter at next build.
    //
    // NOTE: the fixture's *initial* checksum already carries a
    // `src/lib.rs` key (sha256 of ORIGINAL). So `is_string()` alone is
    // vacuous — it stays true even if the rewriter never touched the
    // value, used the wrong framing, or wrote a stale/garbage hash.
    // The only honest oracle is the independently-computed raw SHA256
    // of the PATCHED bytes (cargo's directory source verifies exactly
    // this). Compare against that, not just "a string exists".
    let checksum: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(consumer.join("vendor/safety-fixture/.cargo-checksum.json"))
            .unwrap(),
    )
    .unwrap();
    let expected_patched_hash = sha256_hex(PATCHED_LIB_RS.as_bytes());
    // Sanity: the expected value must DIFFER from the original hash,
    // otherwise this assertion couldn't distinguish "rewritten" from
    // "left stale".
    assert_ne!(
        expected_patched_hash,
        sha256_hex(ORIGINAL_LIB_RS.as_bytes()),
        "test bug: patched and original hashes collide"
    );
    assert_eq!(
        checksum["files"]["src/lib.rs"].as_str(),
        Some(expected_patched_hash.as_str()),
        "rewriter must normalize `package/src/lib.rs` -> `src/lib.rs` AND write \
         the raw SHA256 of the patched bytes; got {checksum}"
    );
    assert!(
        checksum["files"].get("package/src/lib.rs").is_none(),
        "rewriter must NOT create a `package/`-prefixed key"
    );
    // The unpatched Cargo.toml entry must survive untouched — proves
    // the rewriter only rehashed the patched file, not the whole map.
    assert_eq!(
        checksum["files"]["Cargo.toml"].as_str(),
        Some(sha256_hex(FIXTURE_TOML.as_bytes()).as_str()),
        "unpatched Cargo.toml entry must keep its original hash; got {checksum}"
    );

    // The envelope still reports the rewritten sidecar file by its
    // package-relative path (the file we changed on disk).
    let env = parse_json_envelope(&stdout);
    let sidecars = env["sidecars"].as_array().unwrap();
    let cargo = sidecars.iter().find(|s| s["ecosystem"] == "cargo").unwrap();
    let files = cargo["files"].as_array().unwrap();
    assert!(
        files
            .iter()
            .any(|f| f["path"] == ".cargo-checksum.json" && f["action"] == "rewritten"),
        "sidecar record must still report .cargo-checksum.json:rewritten; got {cargo}"
    );
}

/// Headline real-world round trip: fetch the actual `traitobject@0.0.1`
/// crate from crates.io, apply the real Socket patch
/// `b15f2b7f-d5cb-43c9-b793-80f71682188f` from the public proxy, then
/// run `cargo check` against a consumer that depends on it.
///
/// This is the cargo "layer 2 + layer 3" combined test (per the
/// PR #80 plan): a real published crate plus the real Socket patch,
/// no synthetic fixtures. Proves the sidecar fixup composes with
/// cargo's actual on-disk verification of crates.io sources.
///
/// Network deps:
///   - crates.io (cargo fetch traitobject@0.0.1)
///   - patches-api.socket.dev (socket-patch get, public proxy)
///
/// The traitobject 0.0.1 patch adds a `compile_error!` to `src/lib.rs`
/// guarded by the `allow-unmaintained` feature — so the consumer
/// declares the dep with `features = ["allow-unmaintained"]` to keep
/// the build green and let us assert "cargo check succeeded after the
/// real patch was applied."
#[test]
#[ignore]
fn traitobject_real_socket_patch_round_trip() {
    if !has_command("cargo") {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let consumer = root.path().join("consumer");
    let cargo_home = root.path().join(".cargo-home");
    std::fs::create_dir_all(consumer.join("src")).unwrap();

    // Consumer crate that uses traitobject. The `allow-unmaintained`
    // feature opts past the post-patch `compile_error!` guard so the
    // build can actually link.
    std::fs::write(
        consumer.join("Cargo.toml"),
        r#"[package]
name = "traitobject-consumer"
version = "0.0.1"
edition = "2021"

[dependencies]
traitobject = { version = "0.0.1", features = ["allow-unmaintained"] }
"#,
    )
    .unwrap();
    std::fs::write(consumer.join("src/main.rs"), "fn main() {}\n").unwrap();

    // 1. Fetch traitobject@0.0.1 from crates.io (real network).
    //    Hermetic CARGO_HOME means we never touch the user's cache.
    let cargo_home_str = cargo_home.to_str().unwrap();
    let fetch = Command::new("cargo")
        .args(["fetch"])
        .current_dir(&consumer)
        .env("CARGO_HOME", cargo_home_str)
        .output()
        .expect("cargo fetch");
    if !fetch.status.success() {
        // Network unavailable, crates.io down, etc. — skip rather
        // than fail. The ignore gate already keeps us out of the
        // default test run; this is a defensive second skip path.
        eprintln!(
            "SKIP: cargo fetch traitobject failed (likely network):\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&fetch.stdout),
            String::from_utf8_lossy(&fetch.stderr),
        );
        return;
    }

    // 2. Confirm the unpacked source landed under the registry path.
    //    Shape: `<cargo_home>/registry/src/index.crates.io-*/traitobject-0.0.1/`.
    let registry_src = cargo_home.join("registry/src");
    let mut traitobject_dir: Option<std::path::PathBuf> = None;
    for entry in std::fs::read_dir(&registry_src).unwrap() {
        let entry = entry.unwrap();
        let candidate = entry.path().join("traitobject-0.0.1");
        if candidate.is_dir() {
            traitobject_dir = Some(candidate);
            break;
        }
    }
    let traitobject_dir = traitobject_dir
        .expect("traitobject-0.0.1 should be unpacked under cargo registry/src after cargo fetch");
    let checksum_path = traitobject_dir.join(".cargo-checksum.json");
    let pre_apply_checksum: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&checksum_path)
            .expect("traitobject-0.0.1 must ship .cargo-checksum.json"),
    )
    .unwrap();

    // 3. Run `socket-patch get` against the public proxy. This
    //    downloads + applies the real patch in one shot.
    let socket_patch_run = Command::new(env!("CARGO_BIN_EXE_socket-patch"))
        .args([
            "get",
            "b15f2b7f-d5cb-43c9-b793-80f71682188f",
            "--cwd",
            consumer.to_str().unwrap(),
        ])
        .env("CARGO_HOME", cargo_home_str)
        .env_remove("SOCKET_API_TOKEN") // force public proxy
        .output()
        .expect("socket-patch get");
    if !socket_patch_run.status.success() {
        eprintln!(
            "SKIP: socket-patch get failed (likely network):\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&socket_patch_run.stdout),
            String::from_utf8_lossy(&socket_patch_run.stderr),
        );
        return;
    }

    // 4. Manifest should now record the patch.
    let manifest_path = consumer.join(".socket/manifest.json");
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path).expect("manifest.json must exist after get"),
    )
    .unwrap();
    let patch = &manifest["patches"]["pkg:cargo/traitobject@0.0.1"];
    assert!(
        patch.is_object(),
        "manifest should contain the traitobject patch: {manifest}"
    );

    // 5. The sidecar fixup must have rewritten .cargo-checksum.json.
    //    The patch covers src/lib.rs (and Cargo.toml, Cargo.lock,
    //    README.md), so those entries should have NEW SHA256 values
    //    while every unpatched-file entry stays put.
    let post_apply_checksum: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&checksum_path).unwrap()).unwrap();
    let pre_files = pre_apply_checksum["files"].as_object().unwrap();
    let post_files = post_apply_checksum["files"].as_object().unwrap();
    let patched_paths = ["Cargo.toml", "Cargo.lock", "README.md", "src/lib.rs"];
    for f in patched_paths {
        if let (Some(pre), Some(post)) = (pre_files.get(f), post_files.get(f)) {
            assert_ne!(
                pre, post,
                ".cargo-checksum.json entry for {f} should change after apply"
            );
            assert_eq!(
                post.as_str().unwrap().len(),
                64,
                "post-apply hash for {f} should be 64-hex SHA256"
            );
        }
    }
    // `package` field is preserved (the .crate tarball hash didn't
    // become honestly recomputable without the original .crate).
    assert_eq!(
        pre_apply_checksum["package"], post_apply_checksum["package"],
        ".cargo-checksum.json `package` field must survive the rewrite unchanged"
    );

    // 6. The whole point: cargo accepts the patched sources.
    let check = cargo_check(&consumer, &cargo_home);
    assert!(
        check.status.success(),
        "cargo check should succeed against patched traitobject.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr),
    );
}
