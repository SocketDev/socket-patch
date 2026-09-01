//! Coverage-gap tests for `commands/vex.rs` (2026-09 coverage audit): the
//! corrupt-ledger/corrupt-manifest hard-error family, the multi-manifest
//! product auto-detect warning echo, and the four skip guards in the
//! go-patches `replace` synthesis (including the SECURITY fail-closed
//! coordinate guard on tamper-able `go.mod` lines).
//!
//! Fixture + runner shapes mirror `e2e_vex.rs` / `e2e_vex_vendor.rs` /
//! `e2e_vex_redirect.rs` (which this suite deliberately does not touch): a
//! self-contained tempdir project driven through the built binary with a
//! scrubbed child environment. No test mutates this process's environment.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use serde_json::Value;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, SetupConfig, VulnerabilityInfo,
};
use socket_patch_core::vendor::state::{VendorArtifact, VendorEntry, VendorState};

/// Canonical-grammar patch UUID (the vendored-artifact verifier validates
/// the uuid path level, so fixtures must use the real shape).
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

/// Every setup-supported ecosystem, declared `manual` so the property-7
/// setup-state filter doesn't interfere with tests that aren't about it.
const ALL_MANUAL: &[&str] = &["npm", "pypi", "cargo", "golang", "gem", "composer"];

/// A prior successful run's minimal-but-recognizable OpenVEX document (the
/// `@context` names openvex.dev, which is what `remove_stale_vex_doc` keys
/// its deletion guard on). Mirrors the stale-doc fixture in
/// `e2e_vex_vendor.rs`.
const STALE_OPENVEX_DOC: &str = r#"{"@context":"https://openvex.dev/ns/v0.2.0","@id":"urn:uuid:stale","author":"Socket","timestamp":"2020-01-01T00:00:00Z","version":1,"statements":[]}"#;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_socket-patch")
}

/// CLI invocation with the ambient `SOCKET_*` environment scrubbed (same
/// rationale as `e2e_vex.rs`: explicit flags must be the sole source of
/// truth; the parent env is never mutated so tests need no serialization).
fn cli() -> Command {
    let mut cmd = Command::new(binary());
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    // Keep telemetry off: `vex` failures otherwise POST a real event to the
    // production proxy endpoint on every run.
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    cmd
}

/// Write `manifest` to `<cwd>/.socket/manifest.json`, declaring every
/// setup-supported ecosystem `manual` so property 7 keeps the patches.
fn write_manifest(cwd: &Path, manifest: &PatchManifest) {
    let dir = cwd.join(".socket");
    std::fs::create_dir_all(&dir).unwrap();
    let mut m = manifest.clone();
    m.setup = Some(SetupConfig {
        exclude: Vec::new(),
        manual: ALL_MANUAL.iter().map(|s| s.to_string()).collect(),
    });
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&m).unwrap(),
    )
    .unwrap();
}

/// Patch record with one file (whose hashes you choose) and one
/// vulnerability.
fn make_record(
    uuid: &str,
    file_name: &str,
    before_hash: &str,
    after_hash: &str,
    vuln_id: &str,
    cves: &[&str],
) -> PatchRecord {
    let mut files = HashMap::new();
    files.insert(
        file_name.to_string(),
        PatchFileInfo {
            before_hash: before_hash.to_string(),
            after_hash: after_hash.to_string(),
        },
    );
    let mut vulns = HashMap::new();
    vulns.insert(
        vuln_id.to_string(),
        VulnerabilityInfo {
            cves: cves.iter().map(|s| s.to_string()).collect(),
            summary: "test summary".to_string(),
            severity: "high".to_string(),
            description: "test description".to_string(),
        },
    );
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: "2024-01-01T00:00:00Z".to_string(),
        files,
        vulnerabilities: vulns,
        description: format!("Patch {uuid}"),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

/// One-npm-patch manifest whose package is nowhere on disk — verify mode
/// then omits it as `package_not_found` and, with nothing else to attest,
/// the run ends `no_applicable_patches`.
fn write_ghost_npm_manifest(cwd: &Path, purl: &str) {
    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        purl.to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            "GHSA-cg-ghost",
            &["CVE-2026-100"],
        ),
    );
    write_manifest(cwd, &manifest);
}

// ──────────────────────────────────────────────────────────────────────
// corrupt manifest → `manifest_unreadable`, exit 2 (line 682)
//
// A PRESENT-but-corrupt `.socket/manifest.json` is the hard exit-2 error
// (`read_manifest` → Err), distinct from the missing-manifest exit-2
// (`manifest_not_found`, already covered in `e2e_vex.rs`) and the soft
// empty-manifest exit 1.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn corrupt_manifest_exits_2_with_parse_error_on_stderr() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let dir = cwd.join(".socket");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("manifest.json"), "{not json").unwrap();

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert_eq!(
        out.status.code(),
        Some(2),
        "a present-but-corrupt manifest is a hard error. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.is_empty(),
        "no document may be emitted for an unreadable manifest. got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Error:"), "got: {stderr}");
    assert!(
        stderr.contains("Failed to parse manifest JSON"),
        "the error must name the manifest parse failure, not some other \
         cause (a missing manifest says 'Manifest not found'). got: {stderr}"
    );
    assert!(
        !stderr.contains("Manifest not found"),
        "corrupt must not be conflated with missing. got: {stderr}"
    );
}

#[test]
fn corrupt_manifest_json_envelope_carries_code_and_removes_stale_doc() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let dir = cwd.join(".socket");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("manifest.json"), "{not json").unwrap();

    // A previous successful run's doc sits at --output; the failure
    // contract says a run that ends in error leaves NO OpenVEX document
    // there — including this stale one.
    let vex_path = cwd.join("out.vex.json");
    std::fs::write(&vex_path, STALE_OPENVEX_DOC).unwrap();

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--json",
            "--output",
            vex_path.to_str().unwrap(),
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert_eq!(
        out.status.code(),
        Some(2),
        "manifest_unreadable is a hard error in --json mode too. stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let env: Value = serde_json::from_slice(&out.stdout).expect("envelope JSON on stdout");
    assert_eq!(env["command"], "vex", "{env}");
    assert_eq!(env["status"], "error", "{env}");
    assert_eq!(env["error"]["code"], "manifest_unreadable", "{env}");
    assert!(
        env["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Failed to parse manifest JSON"),
        "the envelope message must carry the parse failure: {env}"
    );
    assert!(
        !vex_path.exists(),
        "a failed run must not leave a previous run's attestation at --output"
    );
}

// ──────────────────────────────────────────────────────────────────────
// corrupt redirect ledger → `redirect_ledger_corrupt`, exit 2 (692-693)
//
// The module doc promises a HARD error for a present-but-malformed
// `.socket/vendor/redirect-state.json`: attesting with its records
// silently dropped would produce a false document. No manifest is laid
// down — `augment_with_redirect` must error BEFORE the empty-manifest /
// manifest_not_found check, which is itself an ordering assertion.
// ──────────────────────────────────────────────────────────────────────

/// Plant a malformed redirect ledger at its canonical path.
fn write_corrupt_redirect_ledger(cwd: &Path) {
    let dir = cwd.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("redirect-state.json"), "{{{").unwrap();
}

#[test]
fn corrupt_redirect_ledger_hard_errors_in_human_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_corrupt_redirect_ledger(cwd);

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert_eq!(
        out.status.code(),
        Some(2),
        "a malformed redirect ledger is a hard error, never a degrade. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty(), "no document on a hard error");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("redirect ledger") && stderr.contains("malformed"),
        "the CorruptRedirectState message must reach stderr. got: {stderr}"
    );
    // Ordering: the ledger error fires before the missing-manifest check —
    // the (absent) manifest must not be what gets reported.
    assert!(
        !stderr.contains("Manifest not found"),
        "the redirect-ledger error must win over manifest_not_found. got: {stderr}"
    );
}

#[test]
fn corrupt_redirect_ledger_json_envelope_carries_code_and_preserves_ledger() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_corrupt_redirect_ledger(cwd);
    let ledger_path = cwd.join(".socket/vendor/redirect-state.json");

    let vex_path = cwd.join("out.vex.json");
    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--json",
            "--output",
            vex_path.to_str().unwrap(),
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert_eq!(
        out.status.code(),
        Some(2),
        "redirect_ledger_corrupt is a hard error in --json mode too. stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let env: Value = serde_json::from_slice(&out.stdout).expect("envelope JSON on stdout");
    assert_eq!(env["status"], "error", "{env}");
    assert_eq!(env["error"]["code"], "redirect_ledger_corrupt", "{env}");
    assert!(
        env["error"]["message"].as_str().unwrap().contains("malformed"),
        "the envelope must carry the CorruptRedirectState detail: {env}"
    );
    // vex is a READ-ONLY ledger consumer: the malformed file may still hold
    // the only pre-redirect revert data, so it must be left exactly where it
    // was — neither deleted nor quarantined by this run.
    assert_eq!(
        std::fs::read_to_string(&ledger_path).unwrap(),
        "{{{",
        "vex must not touch the malformed redirect ledger"
    );
    assert!(
        !cwd.join(".socket/vendor/redirect-state.json.corrupt").exists(),
        "vex must not quarantine the ledger (that is the writer's recovery flow)"
    );
    assert!(!vex_path.exists(), "no document on a hard error");
}

// ──────────────────────────────────────────────────────────────────────
// corrupt vendor ledger → warn + fail-closed degrade (732, 829-836)
//
// Unlike the redirect ledger, a present-but-corrupt
// `.socket/vendor/state.json` DEGRADES: `load_vendor_context` warns on
// stderr and proceeds with no vendor entries, so vendored purls fall
// through to the installed tree, fail verification there, and are omitted
// — fail-closed, never falsely attested. The same run drives
// `augment_with_detached`'s Err-skip (its `if let Ok(state)` guard).
// ──────────────────────────────────────────────────────────────────────

#[test]
fn corrupt_vendor_ledger_warns_and_fails_closed_in_human_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purl = "pkg:npm/leftpad@1.0.0";
    write_ghost_npm_manifest(cwd, purl);
    // AFTER write_manifest (which creates .socket/): plant the corrupt ledger.
    let dir = cwd.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("state.json"), "not json").unwrap();

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    // The sole patch fails verification against the (absent) installed tree
    // → soft "nothing to attest", exit 1 — NOT a false attestation and NOT
    // a hard ledger error (the vendor ledger, unlike the redirect ledger,
    // is a degrade).
    assert_eq!(
        out.status.code(),
        Some(1),
        "corrupt vendor ledger must degrade to no_applicable_patches. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty(), "no document when nothing attests");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unreadable vendor state"),
        "the degrade must be disclosed on stderr. got: {stderr}"
    );
    assert!(
        stderr.contains("corrupt"),
        "the warning must carry load_state's detail (corrupt <path>). got: {stderr}"
    );
    // Fail-closed surfacing: the omitted patch is named with its reason.
    assert!(
        stderr.contains(purl) && stderr.contains("package_not_found"),
        "the un-verifiable patch must be reported omitted. got: {stderr}"
    );
    assert!(
        stderr.contains("No applied patches"),
        "the generic nothing-to-attest message applies (the omission was \
         verification, not the setup filter). got: {stderr}"
    );
}

#[test]
fn corrupt_vendor_ledger_json_mode_pins_channel_behavior() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purl = "pkg:npm/leftpad@1.0.0";
    write_ghost_npm_manifest(cwd, purl);
    let dir = cwd.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("state.json"), "not json").unwrap();

    let vex_path = cwd.join("out.vex.json");
    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--json",
            "--output",
            vex_path.to_str().unwrap(),
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert_eq!(
        out.status.code(),
        Some(1),
        "same fail-closed degrade under --json. stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let env: Value = serde_json::from_slice(&out.stdout).expect("envelope JSON on stdout");
    assert_eq!(env["status"], "error", "{env}");
    assert_eq!(env["error"]["code"], "no_applicable_patches", "{env}");
    // The un-verifiable patch surfaces as a machine-readable skipped event.
    let events = env["events"].as_array().unwrap();
    let skipped = events
        .iter()
        .find(|e| e["action"] == "skipped" && e["purl"] == purl)
        .unwrap_or_else(|| panic!("expected a skipped event for the ghost purl: {env}"));
    assert_eq!(skipped["errorCode"], "package_not_found", "{skipped}");
    assert!(!vex_path.exists(), "no document when nothing attests");

    // Channel pin (current behavior): `load_vendor_context`'s unreadable-
    // vendor-state warning is gated only on --silent, so in --json mode it
    // still lands on stderr rather than in the envelope's warnings[] (the
    // error envelope carries no warnings at all). If the gating is ever
    // reworked to fold this into warnings[] like note_warning does, update
    // this pin alongside.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unreadable vendor state"),
        "current contract: the degrade warning goes to stderr even under \
         --json. got: {stderr}"
    );
    assert!(
        env["warnings"].is_null(),
        "current contract: the error envelope carries no warnings[]: {env}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// multi-manifest auto-detect warning echo (792-794)
//
// `detect_product` warns when multiple project manifests coexist (e.g.
// package.json + Cargo.toml, no .git) and `resolve_product_id` must echo
// that warning to stderr in human mode — and suppress it under --silent.
// ──────────────────────────────────────────────────────────────────────

/// Tempdir with package.json AND Cargo.toml (no .git), plus a one-patch
/// manifest. Auto-detect must pick package.json → `pkg:npm/app@1.0.0`.
fn scaffold_multi_manifest_project(cwd: &Path) {
    std::fs::write(cwd.join("package.json"), r#"{"name":"app","version":"1.0.0"}"#).unwrap();
    std::fs::write(
        cwd.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();
    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/x@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            "GHSA-cg-multi",
            &["CVE-2026-200"],
        ),
    );
    write_manifest(cwd, &manifest);
}

#[test]
fn auto_detect_multi_manifest_warns_on_stderr() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    scaffold_multi_manifest_project(cwd);

    let out_path = cwd.join("out.vex.json");
    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--output",
            out_path.to_str().unwrap(),
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "multi-manifest detect is a warning, not a failure. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Multiple project manifests detected"),
        "detect_product's warning must be echoed to stderr. got: {stderr}"
    );
    assert!(
        stderr.contains("using package.json"),
        "the warning must name the manifest actually used. got: {stderr}"
    );
    // The detection itself resolved via package.json.
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    assert_eq!(
        doc["statements"][0]["products"][0]["@id"], "pkg:npm/app@1.0.0",
        "package.json wins the multi-manifest priority: {doc}"
    );
}

#[test]
fn auto_detect_multi_manifest_warning_suppressed_by_silent() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    scaffold_multi_manifest_project(cwd);

    let out_path = cwd.join("out.vex.json");
    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--silent",
            "--output",
            out_path.to_str().unwrap(),
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "--silent must not change the outcome. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("Multiple project manifests"),
        "--silent must suppress the detect warning echo. got: {stderr}"
    );
    assert!(
        out.stdout.is_empty(),
        "--silent with --output prints nothing to stdout. got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    // The document is still produced with the auto-detected product.
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    assert_eq!(doc["statements"][0]["products"][0]["@id"], "pkg:npm/app@1.0.0");
}

// ──────────────────────────────────────────────────────────────────────
// go-patches synthesis skip guards (875, 879, 884, 891)
//
// `synthesize_go_patches` walks the tamper-able `go.mod` replace set;
// owner classification is by target-path prefix (`.socket/go-patches/`),
// so hand-written lines reach every guard:
//   (a) version-less directory replace          → skipped (875)
//   (b) go-patches replace with no manifest purl → skipped (879)
//   (c) explicit vendor entry takes precedence   → skipped (884)
//   (d) SECURITY: unsafe module coordinates      → skipped (891) — the
//       only end-to-end proof that a tampered go.mod cannot key an
//       out-of-tree path into VEX verification (the inline unit test only
//       pins the predicate, not that the synthesis consults it).
// ──────────────────────────────────────────────────────────────────────

const GOOD_UUID: &str = "22222222-2222-4222-8222-222222222222";
const EVIL_UUID: &str = "33333333-3333-4333-8333-333333333333";

/// Non-detached golang vendor-ledger entry (the manifest record is the
/// verification oracle) whose dir-shaped artifact lives at `rel_path`.
fn write_golang_vendor_state(cwd: &Path, purl: &str, rel_path: &str) {
    let mut state = VendorState::new();
    state.entries.insert(
        purl.to_string(),
        VendorEntry {
            ecosystem: "golang".to_string(),
            base_purl: purl.to_string(),
            uuid: UUID.to_string(),
            artifact: VendorArtifact {
                path: rel_path.to_string(),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: None,
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        },
    );
    let dir = cwd.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();
}

#[test]
fn go_patches_synthesis_skips_tampered_and_stale_replaces() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    // ── GOOD module: exactly the fixture shape of
    // e2e_vex_vendor::golang_go_patches_redirect_attested_without_module_cache
    // — the control proving the synthesis DID run on this go.mod.
    let good_module = "github.com/foo/bar";
    let good_version = "v1.4.2";
    let good_purl = format!("pkg:golang/{good_module}@{good_version}");
    std::fs::write(
        cwd.join("go.mod"),
        format!("module example.com/app\n\ngo 1.21\n\nrequire {good_module} {good_version}\n"),
    )
    .unwrap();
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(
            socket_patch_core::vendor::go_mod_edit::ensure_replace_entry(
                cwd,
                good_module,
                good_version,
                socket_patch_core::vendor::go_mod_edit::GO_PATCHES_DIR,
                false,
            ),
        )
        .expect("write go.mod replace");
    let good_patched = b"package bar // patched\n";
    let good_after = compute_git_sha256_from_bytes(good_patched);
    let good_copy = cwd.join(format!(".socket/go-patches/{good_module}@{good_version}"));
    std::fs::create_dir_all(&good_copy).unwrap();
    std::fs::write(good_copy.join("bar.go"), good_patched).unwrap();

    // ── (c) VENDORED module: manifest purl with BOTH a go-patches replace
    // line AND an explicit vendor entry. The vendor artifact holds the
    // hash-matching bytes; the go-patches copy dir holds DIFFERENT bytes —
    // so if the vendor-entry precedence guard were dropped (synthesis wins),
    // verification would hash the wrong bytes and the purl would vanish
    // from the doc. The "(vendored)" marker pins the winning provenance.
    let vend_module = "github.com/vendored/mod";
    let vend_version = "v1.0.0";
    let vend_purl = format!("pkg:golang/{vend_module}@{vend_version}");
    let vend_patched = b"package mod // vendored patched\n";
    let vend_after = compute_git_sha256_from_bytes(vend_patched);
    let vend_rel = format!(".socket/vendor/golang/{UUID}/{vend_module}@{vend_version}");
    let vend_dir = cwd.join(&vend_rel);
    std::fs::create_dir_all(&vend_dir).unwrap();
    std::fs::write(vend_dir.join("mod.go"), vend_patched).unwrap();
    write_golang_vendor_state(cwd, &vend_purl, &vend_rel);
    let vend_decoy = cwd.join(format!(".socket/go-patches/{vend_module}@{vend_version}"));
    std::fs::create_dir_all(&vend_decoy).unwrap();
    std::fs::write(vend_decoy.join("mod.go"), b"stale go-patches copy\n").unwrap();

    // ── (d) TAMPERED module: unsafe traversal coordinates in a hand-written
    // socket-owned replace, plus a manifest record. A hash-MATCHING decoy is
    // planted at the location the traversal resolves to
    // (.socket/go-patches/github.com/foo/../../../etc@v1.0.0 → .socket/etc@v1.0.0),
    // so an implementation missing the are_safe_redirect_coords guard would
    // byte-verify the decoy and falsely attest.
    let evil_module = "github.com/foo/../../../etc";
    let evil_version = "v1.0.0";
    let evil_purl = format!("pkg:golang/{evil_module}@{evil_version}");
    let evil_patched = b"package etc // evil decoy\n";
    let evil_after = compute_git_sha256_from_bytes(evil_patched);
    let evil_decoy_dir = cwd.join(".socket").join(format!("etc@{evil_version}"));
    std::fs::create_dir_all(&evil_decoy_dir).unwrap();
    std::fs::write(evil_decoy_dir.join("evil.go"), evil_patched).unwrap();

    // Hand-append the tampered/stale replace lines exactly as an attacker
    // (or a stale tool) could commit them; the `.socket/go-patches/` target
    // prefix classifies every one of them as socket-owned.
    let mut go_mod = std::fs::read_to_string(cwd.join("go.mod")).unwrap();
    go_mod.push_str(&format!(
        "\nreplace github.com/noversion => ./.socket/go-patches/x\n\
         replace github.com/stale v1.0.0 => ./.socket/go-patches/github.com/stale@v1.0.0\n\
         replace {vend_module} {vend_version} => ./.socket/go-patches/{vend_module}@{vend_version}\n\
         replace {evil_module} {evil_version} => ./.socket/go-patches/{evil_module}@{evil_version}\n"
    ));
    std::fs::write(cwd.join("go.mod"), go_mod).unwrap();
    // (b)'s stale copy dir exists with plausible bytes so only the missing
    // manifest entry (not a missing dir) can explain its absence downstream.
    let stale_copy = cwd.join(".socket/go-patches/github.com/stale@v1.0.0");
    std::fs::create_dir_all(&stale_copy).unwrap();
    std::fs::write(stale_copy.join("stale.go"), b"package stale\n").unwrap();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        good_purl.clone(),
        make_record(
            GOOD_UUID,
            "bar.go",
            "a".repeat(64).as_str(),
            &good_after,
            "GHSA-cg-go-good",
            &["CVE-2026-301"],
        ),
    );
    manifest.patches.insert(
        vend_purl.clone(),
        make_record(
            UUID,
            "mod.go",
            "a".repeat(64).as_str(),
            &vend_after,
            "GHSA-cg-go-vend",
            &["CVE-2026-302"],
        ),
    );
    manifest.patches.insert(
        evil_purl.clone(),
        make_record(
            EVIL_UUID,
            "evil.go",
            "a".repeat(64).as_str(),
            &evil_after,
            "GHSA-cg-go-evil",
            &["CVE-2026-303"],
        ),
    );
    write_manifest(cwd, &manifest);

    // Hermetic, EMPTY module cache: with the go-patches synthesis refusing
    // the tampered coordinates there is nowhere left for that purl to
    // verify — fail-closed omission is the only acceptable outcome.
    let empty_cache = tmp.path().join("empty-gomodcache");
    std::fs::create_dir_all(&empty_cache).unwrap();

    let out = cli()
        .env("GOMODCACHE", &empty_cache)
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--product",
            "pkg:golang/example.com/app@v0.0.1",
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "the good + vendored purls must still attest. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).unwrap();
    let doc: Value = serde_json::from_str(&stdout).expect("VEX JSON on stdout");
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        2,
        "exactly the good redirect + the vendored purl attest; the \
         version-less, stale, and tampered replaces are all skipped. \
         doc:\n{stdout}"
    );

    // Control (the synthesis ran): the good module attests from the
    // go-patches copy dir with the PLAIN (non-vendored) impact statement.
    let good = stmts
        .iter()
        .find(|s| s["vulnerability"]["name"] == "GHSA-cg-go-good")
        .unwrap_or_else(|| panic!("good redirect purl missing: {stdout}"));
    assert_eq!(good["products"][0]["subcomponents"][0]["@id"], good_purl);
    assert_eq!(
        good["impact_statement"].as_str().unwrap(),
        format!("Patched via Socket patch {GOOD_UUID}"),
        "a go-patches redirect is applied, not vendored"
    );

    // (c) precedence: the vendored purl attests FROM THE VENDOR ARTIFACT —
    // the (vendored) marker plus the deliberately-wrong go-patches decoy
    // bytes make a flipped precedence fail this test in two ways.
    let vend = stmts
        .iter()
        .find(|s| s["vulnerability"]["name"] == "GHSA-cg-go-vend")
        .unwrap_or_else(|| panic!("vendored purl missing: {stdout}"));
    assert_eq!(vend["products"][0]["subcomponents"][0]["@id"], vend_purl);
    assert_eq!(
        vend["impact_statement"].as_str().unwrap(),
        format!("Patched via Socket patch {UUID} (vendored)"),
        "the explicit vendor entry must win over the go-patches synthesis"
    );

    // (d) SECURITY: the tampered purl is omitted even though a decoy at the
    // traversal target byte-matches its record — the coordinates guard must
    // keep the out-of-tree path out of the verification map entirely.
    assert!(
        !stdout.contains("GHSA-cg-go-evil"),
        "a tampered go.mod replace must never key an attestation:\n{stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&evil_purl),
        "the tampered purl must surface as an omission on stderr. got: {stderr}"
    );

    // (b) the stale replace (no manifest purl) leaks into nothing.
    assert!(
        !stdout.contains("github.com/stale"),
        "a go-patches replace without a manifest record attests nothing:\n{stdout}"
    );
    // (a) the version-less replace likewise attests nothing.
    assert!(
        !stdout.contains("github.com/noversion"),
        "a version-less replace attests nothing:\n{stdout}"
    );
}
