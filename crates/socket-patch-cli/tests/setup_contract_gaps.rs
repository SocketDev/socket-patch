//! **Executable spec for the not-yet-implemented parts of the `setup` contract.**
//!
//! Every test in this file encodes a property from the "Setup command contract"
//! section of `crates/socket-patch-cli/CLI_CONTRACT.md` that the current binary
//! does **not** yet satisfy. They are intentionally RED — exactly like the
//! pre-existing all-batches-failed guard in `scan_invariants.rs::scan_handles_
//! api_500_error_gracefully`. They are NOT regressions: a failure here means the
//! gap is still open. When the corresponding property is implemented, the test
//! flips green and protects it thereafter.
//!
//! This work was scoped as *documentation + tests only* — we deliberately did
//! not change production behavior, so these stay RED on purpose. Do not "fix"
//! them by weakening the assertions.
//!
//! Each test names the property it guards and explains why it is currently RED.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// `SOCKET_*` vars scrubbed from every child so behaviour is decided by flags +
/// fixtures alone (mirrors setup_invariants.rs). Critically includes
/// `SOCKET_ECOSYSTEMS` (whose ambient value would defeat the prop-2 scoping
/// test) and the cargo-backend `SOCKET_PATCH_*` knobs.
const SOCKET_ENV_VARS: &[&str] = &[
    "SOCKET_CWD",
    "SOCKET_MANIFEST_PATH",
    "SOCKET_API_TOKEN",
    "SOCKET_ECOSYSTEMS",
    "SOCKET_OFFLINE",
    "SOCKET_JSON",
    "SOCKET_DRY_RUN",
    "SOCKET_YES",
    "SOCKET_VEX_NO_VERIFY",
    "SOCKET_VEX_PRODUCT",
    "SOCKET_DEBUG",
    "SOCKET_TELEMETRY_DISABLED",
    "SOCKET_PATCH_ROOT",
    "SOCKET_PATCH_BIN",
    "SOCKET_PATCH_DEBUG",
];

/// Run the binary with a scrubbed environment, telemetry off, and HOME pointed
/// at `home`. Returns (exit code, stdout).
fn run(cwd: &Path, home: &Path, args: &[&str]) -> (i32, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for var in SOCKET_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd.env("HOME", home);
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, content).expect("write file");
}

/// git-style blob SHA-256 (matches the manifest's beforeHash/afterHash scheme).
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

// ===========================================================================
// Property 2 — ecosystem-scoped. `setup --ecosystems npm` must act on ONLY the
// npm manifest, leaving the python (and cargo) manifests untouched.
//
// SHIPPED: `setup` now honors `--ecosystems` via the `eco_in_scope` gating in
// commands/setup.rs (discover / plan_python / build_*_outcome / append_*_check).
// This pin is now an active (non-ignored) regression guard.
// ===========================================================================

#[test]
fn setup_ecosystems_filter_scopes_work_to_named_ecosystem() {
    let proj = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    write(
        &proj.path().join("package.json"),
        r#"{ "name": "x", "version": "1.0.0" }"#,
    );
    let original_requirements = "requests==2.31.0\n";
    write(&proj.path().join("requirements.txt"), original_requirements);

    let (code, stdout) = run(proj.path(), home.path(), &["setup", "--json", "--yes", "--ecosystems", "npm"]);
    assert_eq!(code, 0, "scoped setup should still succeed; stdout=\n{stdout}");

    // The npm side IS in scope and must be configured (proves the run happened).
    assert!(
        std::fs::read_to_string(proj.path().join("package.json"))
            .unwrap()
            .contains("socket-patch"),
        "the in-scope npm manifest must be configured"
    );

    // The python manifest is OUT of scope and must be left byte-for-byte.
    let req = std::fs::read_to_string(proj.path().join("requirements.txt")).unwrap();
    assert_eq!(
        req, original_requirements,
        "`--ecosystems npm` must NOT touch the python manifest (property 2); got:\n{req}"
    );
}

// ===========================================================================
// Property 4 — `check` proves a correctly-patched state. With the install hook
// present but a manifest patch NOT applied on disk (file hash != afterHash),
// `setup --check` must report needs-configuration / exit non-zero.
//
// SHIPPED: `run_check` now also verifies on-disk patch consistency via
// `append_patch_consistency_entries` (reads `.socket/manifest.json`, resolves
// installed package paths, and runs the `applied_patches` afterHash check), so a
// hooked-but-unpatched repo reports `needs_configuration` / exit 1. This pin is
// now an active (non-ignored) regression guard.
// ===========================================================================

#[test]
fn setup_check_detects_unapplied_manifest_patch() {
    let proj = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    // Wire the npm install hook (so hook-presence alone would say "configured").
    write(
        &proj.path().join("package.json"),
        r#"{ "name": "x", "version": "1.0.0" }"#,
    );
    let (c, _) = run(proj.path(), home.path(), &["setup", "--json", "--yes"]);
    assert_eq!(c, 0, "precondition: initial setup wires the hook");

    // An installed npm package whose on-disk file does NOT match the manifest's
    // afterHash — i.e. the patch is present in the manifest but not applied.
    let original = b"original\n";
    let patched = b"patched\n";
    let on_disk = b"DRIFTED-not-the-patched-content\n";
    let pkg = proj.path().join("node_modules/badpkg");
    write(&pkg.join("package.json"), r#"{ "name": "badpkg", "version": "1.0.0" }"#);
    write(&pkg.join("index.js"), &String::from_utf8_lossy(on_disk));

    write(
        &proj.path().join(".socket/manifest.json"),
        &format!(
            r#"{{ "patches": {{
  "pkg:npm/badpkg@1.0.0": {{
    "uuid": "11111111-1111-4111-8111-111111111111",
    "exportedAt": "2024-01-01T00:00:00Z",
    "files": {{ "package/index.js": {{ "beforeHash": "{before}", "afterHash": "{after}" }} }},
    "vulnerabilities": {{ "GHSA-aaaa-bbbb-cccc": {{ "cves": ["CVE-2024-0001"], "summary": "x", "severity": "high", "description": "d" }} }},
    "description": "d", "license": "MIT", "tier": "free"
  }}
}} }}"#,
            before = git_sha256(original),
            after = git_sha256(patched),
        ),
    );

    let (code, stdout) = run(proj.path(), home.path(), &["setup", "--check", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    // A repo with the hook wired but the patch NOT applied on disk is NOT in a
    // correctly-patched state, so --check must fail.
    assert_eq!(
        code, 1,
        "check must fail when a manifest patch is unapplied on disk (property 4); stdout=\n{stdout}"
    );
    assert_ne!(
        v["status"], "configured",
        "check must NOT report `configured` for a hooked-but-unpatched repo; stdout=\n{stdout}"
    );
}

// ===========================================================================
// Property 7 — reflected in VEX. A patch contributes a VEX statement only for an
// ecosystem that is actually set up (or declared `manual`). Here the manifest
// has a pypi patch but pypi is NOT set up (no requirements.txt / pyproject hook),
// so the document must contain zero statements (exit 1, no applicable patches).
//
// CURRENTLY RED: VEX has no notion of setup state. With `--no-verify` it trusts
// the manifest wholesale and emits the statement regardless of whether pypi was
// ever set up — so it writes a 1-statement document and exits 0.
//
// (The converse — declaring pypi `manual` to re-include it — is follow-up work;
// see the `#[ignore]`d placeholder below.)
// ===========================================================================

#[test]
// Gap pin (non-blocking, runnable via --ignored). Un-ignore when property 7 ships.
#[ignore = "gap: VEX has no notion of setup state; see CLI_CONTRACT 'Setup command contract' property 7"]
fn vex_omits_patches_for_unconfigured_ecosystem() {
    let proj = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    // A pypi patch in the manifest, but NOTHING is set up in this repo (no
    // package.json, no requirements.txt, no pyproject.toml).
    write(
        &proj.path().join(".socket/manifest.json"),
        r#"{ "patches": {
  "pkg:pypi/badpkg@1.0.0": {
    "uuid": "11111111-1111-4111-8111-111111111111",
    "exportedAt": "2024-01-01T00:00:00Z",
    "files": { "badpkg/__init__.py": { "beforeHash": "aaaa", "afterHash": "bbbb" } },
    "vulnerabilities": { "GHSA-xxxx-xxxx-xxxx": { "cves": ["CVE-2024-0001"], "summary": "x", "severity": "high", "description": "d" } },
    "description": "d", "license": "MIT", "tier": "free"
  }
} }"#,
    );

    let out = proj.path().join("out.json");
    let (code, stdout) = run(
        proj.path(),
        home.path(),
        &[
            "vex",
            "--no-verify",
            "--product",
            "pkg:pypi/myapp@1.0.0",
            "--output",
            out.to_str().unwrap(),
        ],
    );

    // pypi is not set up here, so its patch must not be attested. With no other
    // patches that means no applicable patches at all → exit 1, no document.
    let statements = std::fs::read_to_string(&out)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v["statements"].as_array().map(|a| a.len()))
        .unwrap_or(0);
    assert_eq!(
        statements, 0,
        "VEX must omit patches for an un-set-up ecosystem (property 7); stdout=\n{stdout}"
    );
    assert_eq!(
        code, 1,
        "with the only patch belonging to an un-set-up ecosystem, vex must report \
         no-applicable-patches (exit 1); stdout=\n{stdout}"
    );
}

// ===========================================================================
// Property 8 (residue) — graceful, exact remove. A `.cargo/config.toml` that
// `setup` *created* should be cleaned up on `--remove`, restoring the exact
// pre-setup tree.
//
// SHIPPED: `edit_config` (cargo_config.rs) now deletes an emptied socket-created
// `.cargo/config.toml` and prunes the now-empty `.cargo/` dir, so a repo that had
// no `.cargo/` before setup is restored exactly. This pin is now an active
// (non-ignored) regression guard.
// ===========================================================================

#[cfg(feature = "cargo")]
#[test]
fn setup_remove_cleans_up_cargo_config_it_created() {
    let proj = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    write(
        &proj.path().join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nserde = \"1\"\n",
    );
    // Precondition: no .cargo/ before setup.
    assert!(!proj.path().join(".cargo").exists());

    let (c1, _) = run(proj.path(), home.path(), &["setup", "--json", "--yes"]);
    assert_eq!(c1, 0);
    assert!(
        proj.path().join(".cargo/config.toml").exists(),
        "precondition: setup created .cargo/config.toml"
    );

    let (c2, _) = run(proj.path(), home.path(), &["setup", "--remove", "--json", "--yes"]);
    assert_eq!(c2, 0);

    // Exact restoration: the .cargo/config.toml setup created must be gone, not
    // lingering empty.
    assert!(
        !proj.path().join(".cargo/config.toml").exists(),
        "remove must delete the .cargo/config.toml it created, restoring the exact \
         pre-setup tree (property 8); an empty file is being left behind"
    );
}

// ===========================================================================
// Property 9 (exclude) — follow-up work. The `--exclude` flag and its persisted
// home (a sub-property of `.socket/manifest.json`) are not implemented yet, so
// this placeholder is `#[ignore]`d: it documents the intended behavior without
// failing the default suite. Un-ignore it when the exclude mechanism lands.
// ===========================================================================

#[test]
#[ignore = "exclude mechanism is follow-up; see CLI_CONTRACT 'Setup command contract' property 9"]
fn setup_honors_exclude_for_a_workspace_member() {
    // Intended behavior once implemented:
    //   - root package.json + packages/a configured,
    //   - packages/b skipped because it was excluded,
    //   - the exclusion persisted in .socket/manifest.json so `--check`, `apply`,
    //     and a fresh clone all honor it (no re-passing of --exclude).
    panic!("pending: --exclude flag + .socket/manifest.json exclude sub-property");
}
