//! End-to-end tests for vendored-patch awareness in `socket-patch vex`.
//!
//! A `socket-patch vendor` run ejects the patched package into a committed
//! `.socket/vendor/<eco>/<uuid>/<artifact>` recorded in
//! `.socket/vendor/state.json` — after which the installed tree is expected
//! to be UN-patched (the lockfile consumes the vendored copy). `vex` must
//! attest those patches from the committed artifact:
//!
//!   1. vendored PURL attested with NO installed tree, impact statement
//!      carries the "(vendored)" marker
//!   2. tampered vendored artifact → omitted, envelope skip reason
//!      `vendor_hash_mismatch`
//!   3. Property-7 exemption: a vendored patch needs no install hook by
//!      construction, so it bypasses the configured/manual ecosystem filter
//!   4. legacy `.socket/go-patches/` redirect regression: an apply-redirected
//!      Go patch verifies against the redirect copy dir, not the (pristine)
//!      module cache

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use serde_json::Value;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, SetupConfig, VulnerabilityInfo,
};
use socket_patch_core::patch::vendor::state::{VendorArtifact, VendorEntry, VendorState};

/// Canonical-grammar patch UUID — the vendored-artifact verifier validates
/// the uuid path level, so fixtures must use the real shape.
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

/// Every setup-supported ecosystem, declared `manual` so the property-7
/// filter doesn't interfere with the tests that aren't about it.
const ALL_MANUAL: &[&str] = &["npm", "pypi", "cargo", "golang", "gem", "composer"];

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_socket-patch")
}

/// CLI invocation with the ambient `SOCKET_*` environment scrubbed (same
/// rationale as `e2e_vex.rs`: explicit flags must be the sole source of
/// truth).
fn cli() -> Command {
    let mut cmd = Command::new(binary());
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") {
            cmd.env_remove(key);
        }
    }
    cmd
}

/// Write `manifest` to `<cwd>/.socket/manifest.json`, optionally declaring
/// every ecosystem `manual` (tests of the property-7 exemption pass `false`).
fn write_manifest(cwd: &Path, manifest: &PatchManifest, declare_manual: bool) {
    let dir = cwd.join(".socket");
    std::fs::create_dir_all(&dir).unwrap();
    let mut m = manifest.clone();
    if declare_manual {
        m.setup = Some(SetupConfig {
            exclude: Vec::new(),
            manual: ALL_MANUAL.iter().map(|s| s.to_string()).collect(),
        });
    }
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&m).unwrap(),
    )
    .unwrap();
}

/// Patch record with one file and one vulnerability.
fn make_record(
    uuid: &str,
    file_name: &str,
    after_hash: &str,
    vuln_id: &str,
    cves: &[&str],
) -> PatchRecord {
    let mut files = HashMap::new();
    files.insert(
        file_name.to_string(),
        PatchFileInfo {
            before_hash: "a".repeat(64),
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

/// Write a `.socket/vendor/state.json` ledger with one cargo-style
/// (dir-shaped) entry for `purl` whose artifact lives at `rel_path`.
fn write_vendor_state(cwd: &Path, purl: &str, rel_path: &str) {
    let mut state = VendorState::new();
    state.entries.insert(
        purl.to_string(),
        VendorEntry {
            ecosystem: "cargo".to_string(),
            base_purl: purl.to_string(),
            uuid: UUID.to_string(),
            artifact: VendorArtifact {
                path: rel_path.to_string(),
                sha256: String::new(),
                size: None,
                platform_locked: None,
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

/// Lay down a vendored cargo-style dir artifact containing `src/lib.rs`
/// with `content`; returns the project-relative artifact path.
fn write_vendored_dir(cwd: &Path, content: &[u8]) -> String {
    let rel = format!(".socket/vendor/cargo/{UUID}/serde-1.0.0");
    let dir = cwd.join(&rel).join("src");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("lib.rs"), content).unwrap();
    rel
}

// ──────────────────────────────────────────────────────────────────────
// 1. vendored attestation with NO installed tree
// ──────────────────────────────────────────────────────────────────────

#[test]
fn vendored_purl_attested_with_no_installed_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purl = "pkg:cargo/serde@1.0.0";

    let patched = b"patched vendored source\n";
    let after_hash = compute_git_sha256_from_bytes(patched);
    let rel = write_vendored_dir(cwd, patched);
    write_vendor_state(cwd, purl, &rel);

    // No Cargo.toml, no target/, no registry copy — the vendored artifact
    // is the ONLY evidence on disk.
    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        purl.to_string(),
        make_record(
            UUID,
            "src/lib.rs",
            &after_hash,
            "GHSA-vend-aaaa",
            &["CVE-2024-1"],
        ),
    );
    write_manifest(cwd, &manifest, true);

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--product",
            "pkg:cargo/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "vendored patch must verify with no installed tree. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let doc: Value = serde_json::from_slice(&out.stdout).expect("VEX JSON on stdout");
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "the vendored patch must be attested");
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-vend-aaaa");
    assert_eq!(stmts[0]["status"], "not_affected");
    let subs = stmts[0]["products"][0]["subcomponents"].as_array().unwrap();
    assert_eq!(subs[0]["@id"], purl);
    let impact = stmts[0]["impact_statement"].as_str().unwrap();
    assert_eq!(
        impact,
        format!("Patched via Socket patch {UUID} (vendored)"),
        "vendored attestation must carry the (vendored) marker"
    );
}

// ──────────────────────────────────────────────────────────────────────
// 2. tampered vendored artifact → omitted with vendor_hash_mismatch
// ──────────────────────────────────────────────────────────────────────

#[test]
fn tampered_vendored_artifact_omitted_with_vendor_hash_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purl = "pkg:cargo/serde@1.0.0";

    // The artifact on disk does NOT hash to the manifest's afterHash.
    let after_hash = compute_git_sha256_from_bytes(b"what the patch should contain\n");
    let rel = write_vendored_dir(cwd, b"tampered bytes\n");
    write_vendor_state(cwd, purl, &rel);

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        purl.to_string(),
        make_record(
            UUID,
            "src/lib.rs",
            &after_hash,
            "GHSA-vend-bbbb",
            &["CVE-2024-2"],
        ),
    );
    write_manifest(cwd, &manifest, true);

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
            "pkg:cargo/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");

    // The only patch failed verification → soft "nothing to attest".
    assert_eq!(
        out.status.code(),
        Some(1),
        "tampered vendored artifact must not be attested. stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let env: Value = serde_json::from_slice(&out.stdout).expect("envelope JSON on stdout");
    assert_eq!(env["status"], "error");
    assert_eq!(env["error"]["code"], "no_applicable_patches");
    // The omission surfaces as a skipped event whose errorCode carries the
    // vendor routing tag (same surfacing shape as installed-tree failures).
    let events = env["events"].as_array().unwrap();
    let skipped = events
        .iter()
        .find(|e| e["action"] == "skipped" && e["purl"] == purl)
        .expect("expected a skipped event for the tampered vendored patch");
    assert_eq!(
        skipped["errorCode"], "vendor_hash_mismatch",
        "the vendor verification reason must land in errorCode. event:\n{skipped}"
    );
    assert!(
        !vex_path.exists(),
        "no VEX doc may be written when nothing attests"
    );
}

// ──────────────────────────────────────────────────────────────────────
// 3. Property-7 exemption — vendored patches need no install hook
// ──────────────────────────────────────────────────────────────────────

#[test]
fn property7_vendored_purl_bypasses_setup_manual_filter() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let vendored_purl = "pkg:cargo/serde@1.0.0";

    let patched = b"patched vendored source\n";
    let after_hash = compute_git_sha256_from_bytes(patched);
    let rel = write_vendored_dir(cwd, patched);
    write_vendor_state(cwd, vendored_purl, &rel);

    // Control: an npm patch that VERIFIES against node_modules but whose
    // ecosystem is neither set up (no postinstall hook anywhere) nor manual
    // — property 7 must drop it, proving the filter ran while the vendored
    // patch sailed through.
    let nm_pkg = cwd.join("node_modules/applied-pkg");
    std::fs::create_dir_all(&nm_pkg).unwrap();
    std::fs::write(
        nm_pkg.join("package.json"),
        r#"{"name":"applied-pkg","version":"1.0.0"}"#,
    )
    .unwrap();
    let npm_patched = b"patched npm index";
    let npm_after = compute_git_sha256_from_bytes(npm_patched);
    std::fs::write(nm_pkg.join("index.js"), npm_patched).unwrap();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        vendored_purl.to_string(),
        make_record(
            UUID,
            "src/lib.rs",
            &after_hash,
            "GHSA-vend-cccc",
            &["CVE-2024-3"],
        ),
    );
    manifest.patches.insert(
        "pkg:npm/applied-pkg@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            &npm_after,
            "GHSA-npm-control",
            &["CVE-2024-4"],
        ),
    );
    // NO setup section: nothing configured, nothing manual.
    write_manifest(cwd, &manifest, false);

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--product",
            "pkg:cargo/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "the vendored patch must be attested without any setup/manual config. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).unwrap();
    let doc: Value = serde_json::from_str(&stdout).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "only the vendored patch bypasses property 7; the unconfigured npm \
         control must be dropped. doc:\n{stdout}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-vend-cccc");
    assert!(
        !stdout.contains("GHSA-npm-control"),
        "the non-vendored, non-configured npm patch must be filtered:\n{stdout}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// 4. legacy go-patches redirect regression — an apply-redirected Go patch
// must verify against the `.socket/go-patches/` copy dir (the bytes the
// build consumes), not the pristine module cache. Without the redirect
// synthesis the crawler resolves nothing here (empty GOMODCACHE) and the
// patch is silently dropped as package_not_found → exit 1.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn golang_go_patches_redirect_attested_without_module_cache() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let module = "github.com/foo/bar";
    let version = "v1.4.2";
    let purl = format!("pkg:golang/{module}@{version}");

    // A real go.mod (required by ensure_replace_entry) + the socket-owned
    // replace directive exactly as `apply`'s redirect backend writes it.
    std::fs::write(
        cwd.join("go.mod"),
        format!("module example.com/app\n\ngo 1.21\n\nrequire {module} {version}\n"),
    )
    .unwrap();
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(socket_patch_core::patch::go_mod_edit::ensure_replace_entry(
            cwd,
            module,
            version,
            socket_patch_core::patch::go_mod_edit::GO_PATCHES_DIR,
            false,
        ))
        .expect("write go.mod replace");

    // The patched copy dir the redirect points at.
    let patched = b"package bar // patched\n";
    let after_hash = compute_git_sha256_from_bytes(patched);
    let copy_dir = cwd.join(format!(".socket/go-patches/{module}@{version}"));
    std::fs::create_dir_all(&copy_dir).unwrap();
    std::fs::write(copy_dir.join("bar.go"), patched).unwrap();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        purl.clone(),
        make_record(
            "22222222-2222-4222-8222-222222222222",
            "bar.go",
            &after_hash,
            "GHSA-go-redirect",
            &["CVE-2024-5"],
        ),
    );
    write_manifest(cwd, &manifest, true);

    // Hermetic, EMPTY module cache: the pristine module is nowhere on disk,
    // exactly like a fresh checkout that only ran the redirect apply.
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
        "an apply-redirected go patch must be attested from the go-patches \
         copy dir even with no module cache. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "the redirected go patch must be attested");
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-go-redirect");
    let subs = stmts[0]["products"][0]["subcomponents"].as_array().unwrap();
    assert_eq!(subs[0]["@id"], purl);
    // Redirect copies are applied (machine-local), NOT vendored — the
    // phrasing must stay the plain form.
    let impact = stmts[0]["impact_statement"].as_str().unwrap();
    assert!(
        !impact.contains("(vendored)"),
        "a go-patches redirect is not a vendored artifact: {impact}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// 5. detached entries (scan --vendor --detached): no manifest at all
// ──────────────────────────────────────────────────────────────────────

/// Ledger writer for the detached shape: `detached: true` plus the
/// embedded record that replaces the manifest as verification source.
fn write_detached_vendor_state(cwd: &Path, purl: &str, rel_path: &str, record: PatchRecord) {
    let mut state = VendorState::new();
    state.entries.insert(
        purl.to_string(),
        VendorEntry {
            ecosystem: "cargo".to_string(),
            base_purl: purl.to_string(),
            uuid: UUID.to_string(),
            artifact: VendorArtifact {
                path: rel_path.to_string(),
                sha256: String::new(),
                size: None,
                platform_locked: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            detached: true,
            record: Some(record),
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

/// A detached vendored patch has NO manifest record — `vex` must attest it
/// from the ledger's embedded record + the committed artifact, even when
/// `.socket/manifest.json` does not exist at all. The vendored property-7
/// exemption applies (no setup/manual declaration anywhere).
#[test]
fn detached_entry_attested_without_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purl = "pkg:cargo/serde@1.0.0";

    let patched = b"patched detached source\n";
    let after_hash = compute_git_sha256_from_bytes(patched);
    let rel = write_vendored_dir(cwd, patched);
    let record = make_record(
        UUID,
        "src/lib.rs",
        &after_hash,
        "GHSA-deta-aaaa",
        &["CVE-2026-3"],
    );
    write_detached_vendor_state(cwd, purl, &rel, record);
    assert!(
        !cwd.join(".socket/manifest.json").exists(),
        "fixture sanity: detached-only project has no manifest"
    );

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--product",
            "pkg:cargo/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "detached vendored patch must attest with no manifest. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: Value = serde_json::from_slice(&out.stdout).expect("VEX JSON on stdout");
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "the detached patch must be attested: {doc}");
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-deta-aaaa");
    assert_eq!(stmts[0]["status"], "not_affected");
    let subs = stmts[0]["products"][0]["subcomponents"].as_array().unwrap();
    assert_eq!(subs[0]["@id"], purl);
    assert_eq!(
        stmts[0]["impact_statement"].as_str().unwrap(),
        format!("Patched via Socket patch {UUID} (vendored)"),
        "detached attestation carries the (vendored) marker"
    );
}

/// Fail-closed parity with the manifest-tracked flow: a tampered detached
/// artifact is OMITTED (the embedded record's afterHashes are the oracle),
/// and with nothing else to attest the command reports
/// no_applicable_patches.
#[test]
fn tampered_detached_artifact_omitted() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purl = "pkg:cargo/serde@1.0.0";

    let after_hash = compute_git_sha256_from_bytes(b"what the patch should contain\n");
    let rel = write_vendored_dir(cwd, b"tampered detached bytes\n");
    let record = make_record(
        UUID,
        "src/lib.rs",
        &after_hash,
        "GHSA-deta-bbbb",
        &["CVE-2026-4"],
    );
    write_detached_vendor_state(cwd, purl, &rel, record);

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
            "pkg:cargo/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert_eq!(
        out.status.code(),
        Some(1),
        "tampered-only ⇒ no_applicable_patches (exit 1). stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let env: Value = serde_json::from_slice(&out.stdout).expect("vex --json emits an envelope");
    assert_eq!(env["status"], "error", "{env}");
    assert_eq!(env["error"]["code"], "no_applicable_patches", "{env}");
    // Same surfacing shape as the manifest-tracked tamper test: a skipped
    // event whose errorCode carries the vendor verification reason.
    let events = env["events"].as_array().unwrap();
    let skipped = events
        .iter()
        .find(|e| e["action"] == "skipped" && e["purl"] == purl)
        .unwrap_or_else(|| panic!("expected a skipped event for the tampered purl: {env}"));
    assert_eq!(
        skipped["errorCode"], "vendor_hash_mismatch",
        "tamper must surface as vendor_hash_mismatch: {skipped}"
    );
    assert!(!vex_path.exists(), "no document for an all-failed run");
}
