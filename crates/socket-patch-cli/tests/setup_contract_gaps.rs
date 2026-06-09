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
    "SOCKET_SETUP_EXCLUDE",
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
// SHIPPED: VEX now filters by setup state — `generate_vex` drops patches whose
// ecosystem is neither set up (`commands/setup::configured_ecosystems`) nor
// declared `manual` in the manifest's `setup.manual`. With pypi un-set-up and
// not manual, the only patch is dropped → no applicable patches → exit 1. This
// pin is now an active (non-ignored) regression guard.
//
// (The converse — declaring pypi `manual` to re-include it — is exercised by the
// `manual` escape hatch the e2e_vex / e2e_embedded_vex fixtures rely on.)
// ===========================================================================

#[test]
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
// Property 9 (exclude) — SHIPPED. `setup --exclude <member>` skips that member
// and PERSISTS the exclusion under `.socket/manifest.json`'s `setup.exclude`, so
// a later `--check` (and a fresh clone) honor it without re-passing the flag.
// This pin is now an active (non-ignored) regression guard.
// ===========================================================================

#[test]
fn setup_honors_exclude_for_a_workspace_member() {
    let proj = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    // npm workspace: root + two members.
    write(
        &proj.path().join("package.json"),
        r#"{ "name": "root", "workspaces": ["packages/*"] }"#,
    );
    write(
        &proj.path().join("packages/a/package.json"),
        r#"{ "name": "a", "version": "1.0.0" }"#,
    );
    write(
        &proj.path().join("packages/b/package.json"),
        r#"{ "name": "b", "version": "1.0.0" }"#,
    );

    let read = |p: PathBuf| std::fs::read_to_string(p).unwrap();

    // Setup, excluding packages/b.
    let (code, stdout) = run(
        proj.path(),
        home.path(),
        &["setup", "--json", "--yes", "--exclude", "packages/b"],
    );
    assert_eq!(code, 0, "scoped setup should succeed:\n{stdout}");

    // Root + packages/a configured; packages/b left untouched.
    assert!(
        read(proj.path().join("package.json")).contains("socket-patch"),
        "the root must be configured (never excludable)"
    );
    assert!(
        read(proj.path().join("packages/a/package.json")).contains("socket-patch"),
        "the included member packages/a must be configured"
    );
    assert!(
        !read(proj.path().join("packages/b/package.json")).contains("socket-patch"),
        "the EXCLUDED member packages/b must NOT be configured"
    );

    // The exclusion is persisted under `setup.exclude` in the manifest.
    let manifest = read(proj.path().join(".socket/manifest.json"));
    let mv: serde_json::Value = serde_json::from_str(&manifest).expect("manifest is JSON");
    let excl = mv["setup"]["exclude"]
        .as_array()
        .unwrap_or_else(|| panic!("manifest must carry setup.exclude:\n{manifest}"));
    assert!(
        excl.iter().any(|v| v == "packages/b"),
        "the exclusion must persist in the manifest:\n{manifest}"
    );

    // A fresh `--check` WITHOUT re-passing --exclude honors the persisted set:
    // the excluded member must not count as needing configuration → `configured`.
    let (code, stdout) = run(proj.path(), home.path(), &["setup", "--check", "--json"]);
    assert_eq!(
        code, 0,
        "check must pass — the excluded member must not be flagged as needing setup:\n{stdout}"
    );
    let cv: serde_json::Value = serde_json::from_str(&stdout).expect("check JSON");
    assert_eq!(
        cv["status"], "configured",
        "check must report `configured`, honoring the persisted exclude:\n{stdout}"
    );
    assert!(
        !cv["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["path"].as_str().is_some_and(|p| p.contains("packages/b"))),
        "the excluded member must not appear among the checked files:\n{stdout}"
    );
}
