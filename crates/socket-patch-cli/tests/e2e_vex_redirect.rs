//! End-to-end tests for redirect-patch awareness in `socket-patch vex`.
//!
//! `socket-patch scan --redirect` rewrites lockfiles so a patched dependency
//! resolves from Socket's HOSTED vendored patch, and records the patch (file
//! hashes + vulnerabilities) in `.socket/vendor/redirect-state.json`. After the
//! package manager installs, the patched bytes land in the installed tree, so
//! `vex` attests those patches against the installed tree exactly as it does
//! for `apply` — with a `(redirected)` provenance marker. Coverage:
//!
//!   1. redirected PURL attested against the installed tree, `(redirected)`
//!      marker (the post-install verified path)
//!   2. property-7 exemption: a redirected patch bypasses the configured/manual
//!      ecosystem filter (the lockfile rewrite is the persistence), while a
//!      plain unconfigured control is dropped
//!   3. tampered installed file → omitted with skip reason `hash_mismatch`
//!      (fail-closed)
//!   4. `--no-verify` attests from the ledger records with NO installed tree
//!      (the same shape as the in-run `scan --redirect --vex` attestation) —
//!      but only while the lockfile still wires the hosted patch: a stale
//!      ledger is `redirect_unwired` even under `--no-verify`
//!   5. every ecosystem attests through the ledger with its real hosted
//!      wiring
//!   6. manifest-less, LEDGER-less hosted VEX from the lockfile alone: the
//!      record comes from the patch API, the pinned hosted wiring is the
//!      evidence until install, an installed tree that does not verify wins,
//!      foreign hosts and pin-less entries are refused
//!
//! Every ledger fixture carries the lockfile wiring `scan --redirect` wrote
//! next to it: `vex` only attests a redirect-ledger record while some
//! lockfile still resolves the dependency from its hosted patch (a reverted
//! lockfile with the ledger left behind must not keep attesting).

#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use serde_json::Value;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo,
};
use socket_patch_core::patch::redirect::{FileEdit, RedirectState};
use vex_e2e_common::skipped_reason;

const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const PRODUCT: &str = "pkg:npm/app@1.0.0";
/// A uuid-SHAPED grant token (production tokens may be uuid-shaped; the
/// patch uuid is the LAST uuid segment of a hosted URL).
const TOKEN: &str = "11111111-2222-4333-8444-555555555555";
/// The patched tarball pin the hosted npm rewriter always writes.
const SRI: &str = "sha512-UEFUQ0hFRHBhdGNoZWRQQVRDSEVEcGF0Y2hlZA==";

/// Production hosted artifact URL for an npm package.
fn hosted_npm_url(name: &str, version: &str, uuid: &str) -> String {
    format!(
        "https://patch.socket.dev/patch/npm/{name}/{version}/{TOKEN}/{uuid}/{name}-{version}.tgz"
    )
}

/// `package-lock.json` resolving each `(name, version, uuid)` from its
/// hosted Socket patch (what `scan --mode hosted` writes), pinned with the
/// patched tarball's integrity unless `pinned` is false.
fn write_hosted_package_lock(cwd: &Path, deps: &[(&str, &str, &str)], pinned: bool) {
    let mut packages = serde_json::Map::new();
    packages.insert(
        String::new(),
        serde_json::json!({ "name": "app", "version": "1.0.0" }),
    );
    for (name, version, uuid) in deps {
        let mut entry = serde_json::json!({
            "version": version,
            "resolved": hosted_npm_url(name, version, uuid),
        });
        if pinned {
            entry["integrity"] = Value::String(SRI.to_string());
        }
        packages.insert(format!("node_modules/{name}"), entry);
    }
    std::fs::write(
        cwd.join("package-lock.json"),
        serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": packages,
        })
        .to_string(),
    )
    .unwrap();
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_socket-patch")
}

/// CLI invocation with the ambient `SOCKET_*` environment scrubbed (explicit
/// flags must be the sole source of truth).
fn cli() -> Command {
    let mut cmd = Command::new(binary());
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd
}

/// Patch record with one npm-shaped file (`package/…`) and one vulnerability.
fn make_record(uuid: &str, after_hash: &str, vuln_id: &str, cves: &[&str]) -> PatchRecord {
    let mut files = HashMap::new();
    files.insert(
        "package/index.js".to_string(),
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

/// Write a `.socket/vendor/redirect-state.json` ledger embedding `record` for
/// `purl` (the shape `scan --redirect` persists for VEX).
fn write_redirect_state(cwd: &Path, purl: &str, record: PatchRecord) {
    let mut state = RedirectState::new();
    state.records.insert(purl.to_string(), record);
    let dir = cwd.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("redirect-state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();
}

/// Lay down an installed npm package `node_modules/<name>/index.js` with
/// `installed` bytes + a root package.json so the crawler resolves it to the
/// PURL. Returns the PURL.
fn scaffold_npm(cwd: &Path, name: &str, version: &str, installed: &[u8]) -> String {
    std::fs::write(
        cwd.join("package.json"),
        format!(
            r#"{{ "name": "app", "version": "1.0.0", "dependencies": {{ "{name}": "{version}" }} }}"#
        ),
    )
    .unwrap();
    let pkg = cwd.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), installed).unwrap();
    format!("pkg:npm/{name}@{version}")
}

// ──────────────────────────────────────────────────────────────────────
// 1. redirected PURL attested against the installed tree (verified path)
// ──────────────────────────────────────────────────────────────────────

#[test]
fn redirected_purl_attested_against_installed_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    // Post-install: the installed tree holds the patched bytes (the redirect
    // pulled them from the hosted patch server), matching the record's hash.
    let patched = b"redirected patched index\n";
    let after = compute_git_sha256_from_bytes(patched);
    let purl = scaffold_npm(cwd, "left-pad", "1.3.0", patched);
    write_redirect_state(
        cwd,
        &purl,
        make_record(UUID, &after, "GHSA-rdir-1111", &["CVE-2024-1"]),
    );
    // The lockfile rewrite the ledger records (the redirect is LIVE).
    write_hosted_package_lock(cwd, &[("left-pad", "1.3.0", UUID)], true);
    assert!(
        !cwd.join(".socket/manifest.json").exists(),
        "fixture sanity: a redirect project has no manifest"
    );

    let out = cli()
        .args(["vex", "--cwd", cwd.to_str().unwrap(), "--product", PRODUCT])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "redirected patch must verify against the installed tree. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let doc: Value = serde_json::from_slice(&out.stdout).expect("VEX JSON on stdout");
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "the redirected patch must be attested: {doc}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-rdir-1111");
    assert_eq!(stmts[0]["status"], "not_affected");
    assert_eq!(stmts[0]["products"][0]["subcomponents"][0]["@id"], purl);
    assert_eq!(
        stmts[0]["impact_statement"].as_str().unwrap(),
        format!("Patched via Socket patch {UUID} (redirected)"),
        "redirected attestation must carry the (redirected) marker"
    );
}

// ──────────────────────────────────────────────────────────────────────
// 2. property-7 exemption — a redirected patch bypasses the filter
// ──────────────────────────────────────────────────────────────────────

#[test]
fn redirected_purl_bypasses_property7_filter() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    // Redirected npm patch: verifies + bypasses property 7.
    let patched = b"redirected patched index\n";
    let after = compute_git_sha256_from_bytes(patched);
    let purl = scaffold_npm(cwd, "left-pad", "1.3.0", patched);
    write_redirect_state(
        cwd,
        &purl,
        make_record(UUID, &after, "GHSA-rdir-keep", &["CVE-2024-2"]),
    );
    write_hosted_package_lock(cwd, &[("left-pad", "1.3.0", UUID)], true);

    // Control: a plain manifest npm patch that VERIFIES against node_modules
    // but is neither redirected nor set up / manual — property 7 must drop it,
    // proving the filter ran while the redirected patch sailed through.
    let ctrl_patched = b"control patched index\n";
    let ctrl_after = compute_git_sha256_from_bytes(ctrl_patched);
    let ctrl_pkg = cwd.join("node_modules/control-pkg");
    std::fs::create_dir_all(&ctrl_pkg).unwrap();
    std::fs::write(
        ctrl_pkg.join("package.json"),
        r#"{"name":"control-pkg","version":"2.0.0"}"#,
    )
    .unwrap();
    std::fs::write(ctrl_pkg.join("index.js"), ctrl_patched).unwrap();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/control-pkg@2.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            &ctrl_after,
            "GHSA-npm-control",
            &["CVE-2024-3"],
        ),
    );
    // NO setup section: nothing configured, nothing manual.
    let dir = cwd.join(".socket");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let out = cli()
        .args(["vex", "--cwd", cwd.to_str().unwrap(), "--product", PRODUCT])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "the redirected patch must be attested without setup/manual. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).unwrap();
    let doc: Value = serde_json::from_str(&stdout).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "only the redirected patch bypasses property 7; the unconfigured npm \
         control must be dropped. doc:\n{stdout}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-rdir-keep");
    assert!(
        !stdout.contains("GHSA-npm-control"),
        "the non-redirected, non-configured control must be filtered:\n{stdout}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// 3. fail-closed — a tampered installed file omits the redirected patch
// ──────────────────────────────────────────────────────────────────────

#[test]
fn tampered_installed_file_omits_redirected_patch() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    // The installed file does NOT hash to the record's afterHash.
    let after = compute_git_sha256_from_bytes(b"what the patch should contain\n");
    let purl = scaffold_npm(cwd, "left-pad", "1.3.0", b"tampered installed bytes\n");
    write_redirect_state(
        cwd,
        &purl,
        make_record(UUID, &after, "GHSA-rdir-bad", &["CVE-2024-4"]),
    );
    // Live, PINNED hosted wiring: the not-installed lockfile basis would
    // attest this purl — but an installed tree exists and does not verify,
    // and installed evidence wins.
    write_hosted_package_lock(cwd, &[("left-pad", "1.3.0", UUID)], true);

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
            PRODUCT,
        ])
        .output()
        .expect("invoke vex");

    // The only patch failed verification → soft "nothing to attest".
    assert_eq!(
        out.status.code(),
        Some(1),
        "tampered installed file must not be attested. stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let env: Value = serde_json::from_slice(&out.stdout).expect("envelope JSON on stdout");
    assert_eq!(env["status"], "error");
    assert_eq!(env["error"]["code"], "no_applicable_patches");
    let events = env["events"].as_array().unwrap();
    let skipped = events
        .iter()
        .find(|e| e["action"] == "skipped" && e["purl"] == purl)
        .unwrap_or_else(|| panic!("expected a skipped event for the tampered purl: {env}"));
    assert_eq!(
        skipped["errorCode"], "hash_mismatch",
        "a redirected patch verifies against the installed tree, so the reason \
         is the installed-tree hash_mismatch: {skipped}"
    );
    assert!(
        !vex_path.exists(),
        "no VEX doc may be written when nothing attests"
    );
}

// ──────────────────────────────────────────────────────────────────────
// 4. --no-verify attests from the ledger with NO installed tree — the same
// shape as the in-run `scan --redirect --vex` attestation (bytes are remote,
// fetched at install time, so there is nothing to hash yet).
// ──────────────────────────────────────────────────────────────────────

#[test]
fn redirected_no_verify_attests_without_installed_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purl = "pkg:npm/left-pad@1.3.0";

    // No node_modules, no manifest — the redirect ledger is the only record
    // source. DELIBERATE CHANGE: the ledger alone no longer attests; the
    // lockfile must still wire the hosted patch (see the gated twin below),
    // so the fixture carries the rewrite `scan --redirect` recorded.
    write_redirect_state(
        cwd,
        purl,
        make_record(UUID, &"b".repeat(64), "GHSA-rdir-nv", &["CVE-2024-5"]),
    );
    write_hosted_package_lock(cwd, &[("left-pad", "1.3.0", UUID)], true);

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--product",
            PRODUCT,
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "--no-verify must attest the redirected patch with no installed tree. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let doc: Value = serde_json::from_slice(&out.stdout).expect("VEX JSON on stdout");
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "the redirected patch must be attested: {doc}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-rdir-nv");
    assert_eq!(
        stmts[0]["impact_statement"].as_str().unwrap(),
        format!("Patched via Socket patch {UUID} (redirected)"),
    );
}

// ──────────────────────────────────────────────────────────────────────
// 5. every ecosystem attests through the redirect ledger, including the
// qualified-PURL variants (pypi `?artifact_id=`, gem `?platform=`, maven
// `?classifier=&ext=`). The redirect bypass means these need no real
// toolchain, and the qualified PURL must survive verbatim as the
// subcomponent id.
// ──────────────────────────────────────────────────────────────────────

/// One ecosystem's hosted wiring for the cross-ecosystem test: the project
/// file(s) `scan --mode hosted` rewrites for it, in the golden fixtures'
/// shapes (`crates/socket-patch-core/tests/fixtures/redirect/**/expected/`),
/// carrying that patch's uuid.
fn write_hosted_wiring(cwd: &Path, eco: &str, uuid: &str) -> Vec<&'static str> {
    let registry =
        |kind: &str| format!("https://patch.socket.dev/patch-registry/{kind}/{TOKEN}/{uuid}");
    let write = |file: &str, text: String| {
        let path = cwd.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    match eco {
        "npm" => {
            write_hosted_package_lock(cwd, &[("left-pad", "1.3.0", uuid)], true);
            vec!["package-lock.json"]
        }
        "pypi" => {
            write(
                "requirements.txt",
                format!(
                    "six @ https://patch.socket.dev/patch/pypi/six/1.16.0/{TOKEN}/{uuid}/\
                     six-1.16.0.tar.gz --hash=sha256:{}\n",
                    "d".repeat(64)
                ),
            );
            vec!["requirements.txt"]
        }
        "cargo" => {
            write(
                "Cargo.lock",
                format!(
                    "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\
                     source = \"sparse+{}/index/\"\nchecksum = \"{}\"\n",
                    registry("cargo"),
                    "e".repeat(64)
                ),
            );
            vec!["Cargo.lock"]
        }
        "gem" => {
            write(
                "Gemfile.lock",
                format!(
                    "GEM\n  remote: {}/\n  specs:\n    rack (2.2.3)\n\nPLATFORMS\n  ruby\n\n\
                     DEPENDENCIES\n  rack (= 2.2.3)!\n",
                    registry("gem")
                ),
            );
            vec!["Gemfile.lock"]
        }
        "golang" => {
            write(
                "go.mod",
                format!(
                    "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n\n\
                     replace github.com/foo/bar v1.4.2 => patch.socket.dev/gopatch/{uuid} \
                     v1.4.2-socketpatch.1\n"
                ),
            );
            write(
                "go.sum",
                format!(
                    "patch.socket.dev/gopatch/{uuid} v1.4.2-socketpatch.1 h1:aGFzaA==\n\
                     patch.socket.dev/gopatch/{uuid} v1.4.2-socketpatch.1/go.mod h1:bW9k\n"
                ),
            );
            vec!["go.mod", "go.sum"]
        }
        "maven" => {
            write(
                "pom.xml",
                format!(
                    "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>app</groupId>\n  \
                     <artifactId>app</artifactId>\n  <version>1.0.0</version>\n  <dependencies>\n    \
                     <dependency>\n      <groupId>org.example</groupId>\n      \
                     <artifactId>lib</artifactId>\n      <version>1.0.0-socket.{}</version>\n    \
                     </dependency>\n  </dependencies>\n  <repositories>\n    <repository>\n      \
                     <id>socket-patch-{uuid}</id>\n      <url>{}/maven2</url>\n    </repository>\n  \
                     </repositories>\n</project>\n",
                    &uuid[..8],
                    registry("maven")
                ),
            );
            vec!["pom.xml"]
        }
        "nuget" => {
            write(
                "nuget.config",
                format!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  \
                     <packageSources>\n    <add key=\"socket-patch-{uuid}\" \
                     value=\"{}/index.json\" />\n  </packageSources>\n  <packageSourceMapping>\n    \
                     <packageSource key=\"socket-patch-{uuid}\">\n      \
                     <package pattern=\"Newtonsoft.Json\" />\n    </packageSource>\n  \
                     </packageSourceMapping>\n</configuration>\n",
                    registry("nuget")
                ),
            );
            // The lock records no source url — only the resolved version.
            write(
                "packages.lock.json",
                serde_json::json!({
                    "version": 1,
                    "dependencies": { "net8.0": { "Newtonsoft.Json": {
                        "type": "Direct",
                        "requested": "[13.0.1, )",
                        "resolved": "13.0.1",
                        "contentHash": "UEFUQ0hFRA=="
                    } } }
                })
                .to_string(),
            );
            vec!["nuget.config", "packages.lock.json"]
        }
        "composer" => {
            write(
                "composer.lock",
                serde_json::json!({
                    "packages": [{
                        "name": "monolog/monolog",
                        "version": "2.0.0",
                        "dist": {
                            "type": "zip",
                            "url": format!(
                                "https://patch.socket.dev/patch/composer/monolog/monolog/2.0.0/{TOKEN}/{uuid}/monolog-2.0.0.zip"
                            ),
                            "reference": "abc123",
                            "shasum": "f".repeat(40)
                        }
                    }],
                    "packages-dev": []
                })
                .to_string(),
            );
            vec!["composer.lock"]
        }
        other => panic!("no hosted wiring shape for {other}"),
    }
}

#[test]
fn no_verify_attests_redirected_patches_across_ecosystems() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    // (purl, ghsa, eco, patch uuid). Each ecosystem gets its OWN patch uuid:
    // a ledger record attests only while the lockfile wires THAT uuid to
    // THAT package, so one uuid shared by eight packages (the original
    // fixture) would be — correctly — unattributable.
    let cases: &[(&str, &str, &str, &str)] = &[
        (
            "pkg:npm/left-pad@1.3.0",
            "GHSA-eco-npm",
            "npm",
            "a1a1a1a1-1111-4111-8111-a1a1a1a1a1a1",
        ),
        (
            "pkg:pypi/six@1.16.0?artifact_id=sdist",
            "GHSA-eco-pypi",
            "pypi",
            "b2b2b2b2-1111-4111-8111-b2b2b2b2b2b2",
        ),
        (
            "pkg:cargo/serde@1.0.0",
            "GHSA-eco-cargo",
            "cargo",
            "c3c3c3c3-1111-4111-8111-c3c3c3c3c3c3",
        ),
        (
            "pkg:gem/rack@2.2.3?platform=ruby",
            "GHSA-eco-gem",
            "gem",
            "d4d4d4d4-1111-4111-8111-d4d4d4d4d4d4",
        ),
        (
            "pkg:golang/github.com/foo/bar@v1.4.2",
            "GHSA-eco-golang",
            "golang",
            "e5e5e5e5-1111-4111-8111-e5e5e5e5e5e5",
        ),
        (
            "pkg:maven/org.example/lib@1.0.0?classifier=native&ext=jar",
            "GHSA-eco-maven",
            "maven",
            "f6f6f6f6-1111-4111-8111-f6f6f6f6f6f6",
        ),
        (
            "pkg:nuget/Newtonsoft.Json@13.0.1",
            "GHSA-eco-nuget",
            "nuget",
            "0707a7a7-1111-4111-8111-0707a7a7a7a7",
        ),
        (
            "pkg:composer/monolog/monolog@2.0.0",
            "GHSA-eco-composer",
            "composer",
            "08b8b8b8-1111-4111-8111-08b8b8b8b8b8",
        ),
    ];

    // The ledger records both halves `scan --redirect` persists: the
    // records AND the file edits (whose files still carry each patch's
    // hosted wiring — the liveness proof for formats lockfile discovery
    // does not read yet).
    let mut state = RedirectState::new();
    for (purl, ghsa, eco, uuid) in cases {
        state.records.insert(
            purl.to_string(),
            make_record(uuid, &"b".repeat(64), ghsa, &["CVE-2024-1"]),
        );
        for file in write_hosted_wiring(cwd, eco, uuid) {
            state.edits.push(FileEdit {
                path: file.to_string(),
                kind: format!("redirect_{eco}"),
                action: "rewritten".to_string(),
                key: Some(purl.to_string()),
                original: None,
                new: None,
            });
        }
    }
    let dir = cwd.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("redirect-state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();

    let out = cli()
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--product",
            PRODUCT,
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "every ecosystem's redirected patch must attest. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let doc: Value = serde_json::from_slice(&out.stdout).expect("VEX JSON on stdout");
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        cases.len(),
        "every ecosystem's redirected patch must be attested: {doc}"
    );
    for (purl, ghsa, _, uuid) in cases {
        let st = stmts
            .iter()
            .find(|s| s["vulnerability"]["name"] == *ghsa)
            .unwrap_or_else(|| panic!("missing statement for {ghsa}: {doc}"));
        assert_eq!(st["status"], "not_affected");
        assert_eq!(
            st["impact_statement"].as_str().unwrap(),
            format!("Patched via Socket patch {uuid} (redirected)"),
            "{ghsa} must carry the (redirected) marker"
        );
        assert_eq!(
            st["products"][0]["subcomponents"][0]["@id"], *purl,
            "the (possibly qualified) PURL must survive verbatim as the subcomponent id"
        );
    }
}

// ──────────────────────────────────────────────────────────────────────
// 4b. DELIBERATE CHANGE — the redirect ledger alone no longer attests.
// A record whose hosted wiring the lockfile no longer carries (no lockfile,
// or one reverted to the registry) is `redirect_unwired`, INCLUDING under
// `--no-verify`: the gate is about what the build consumes, not hashing.
// Before, both shapes attested `(redirected)` — a false `not_affected`.
// ──────────────────────────────────────────────────────────────────────

/// `vex --json --output` in `cwd` (hermetic: no ambient token or socket-cli
/// config, telemetry off); returns (exit, envelope).
fn vex_json(cwd: &Path, extra: &[&str]) -> (Option<i32>, Value) {
    vex_json_env(cwd, extra, &[])
}

/// [`vex_json`] with extra child environment (a fabricated module cache /
/// cargo home / maven repository for the installed-tree lookups).
fn vex_json_env(cwd: &Path, extra: &[&str], envs: &[(&str, &Path)]) -> (Option<i32>, Value) {
    let vex_path = cwd.join("out.vex.json");
    let mut args = vec![
        "vex".to_string(),
        "--cwd".to_string(),
        cwd.to_str().unwrap().to_string(),
        "--json".to_string(),
        "--output".to_string(),
        vex_path.to_str().unwrap().to_string(),
        "--product".to_string(),
        PRODUCT.to_string(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    let mut cmd = cli();
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("SOCKET_NO_API_TOKEN", "1")
        .env_remove("VIRTUAL_ENV");
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let out = cmd.args(&args).output().expect("invoke vex");
    let env: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "envelope JSON on stdout ({e}). stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code(), env)
}

#[test]
fn stale_redirect_ledger_is_not_attested_even_with_no_verify() {
    let purl = "pkg:npm/left-pad@1.3.0";
    let registry_lock = serde_json::json!({
        "lockfileVersion": 3,
        "packages": { "node_modules/left-pad": {
            "version": "1.3.0",
            "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "integrity": SRI
        } }
    })
    .to_string();
    for reverted in [None, Some(registry_lock.as_str())] {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        write_redirect_state(
            cwd,
            purl,
            make_record(UUID, &"b".repeat(64), "GHSA-rdir-stale", &["CVE-2024-9"]),
        );
        if let Some(lock) = reverted {
            std::fs::write(cwd.join("package-lock.json"), lock).unwrap();
        }
        for extra in [&[][..], &["--no-verify"][..]] {
            let (code, env) = vex_json(cwd, extra);
            assert_eq!(code, Some(1), "{reverted:?} {extra:?}: {env}");
            assert_eq!(env["error"]["code"], "no_applicable_patches", "{env}");
            assert_eq!(skipped_reason(&env, purl), "redirect_unwired", "{env}");
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// 6. manifest-less, LEDGER-less hosted VEX (a depscan-opened PR, or a
// checkout whose `.socket/` was never committed): the lockfile's Socket-host
// reference is the only input; the record comes from the patch API.
// ──────────────────────────────────────────────────────────────────────

/// A patch-API stand-in serving `GET /patch/view/<uuid>` (the public-proxy
/// route an unauthenticated `vex` fetches from). Keep the runtime alive for
/// the CLI invocation.
fn serve_patch_views(
    views: Vec<(String, Value)>,
) -> (tokio::runtime::Runtime, wiremock::MockServer) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let server = rt.block_on(async {
        let server = MockServer::start().await;
        for (uuid, body) in views {
            Mock::given(method("GET"))
                .and(path(format!("/patch/view/{uuid}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&server)
                .await;
        }
        server
    });
    (rt, server)
}

/// The view the API returns for the left-pad patch.
fn left_pad_view(after_hash: &str) -> Value {
    serde_json::json!({
        "uuid": UUID,
        "purl": "pkg:npm/left-pad@1.3.0",
        "publishedAt": "Fri, 27 Mar 2026 00:00:00 GMT",
        "files": { "package/index.js": { "beforeHash": "a".repeat(64), "afterHash": after_hash } },
        "vulnerabilities": {
            "GHSA-lock-host": {
                "cves": ["CVE-2026-40"], "summary": "s", "severity": "high", "description": "d"
            }
        },
        "description": "hosted patch",
        "license": "MIT",
        "tier": "free",
    })
}

#[test]
fn lockfile_hosted_ref_attests_without_manifest_or_ledger() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purl = "pkg:npm/left-pad@1.3.0";
    // Lockfile-only checkout: nothing installed, no `.socket/` at all.
    write_hosted_package_lock(cwd, &[("left-pad", "1.3.0", UUID)], true);
    assert!(!cwd.join(".socket").exists());

    // Offline: the wiring is found, but no record is available.
    let (code, env) = vex_json(cwd, &["--offline"]);
    assert_eq!(code, Some(1), "{env}");
    assert_eq!(skipped_reason(&env, purl), "record_unavailable");

    // Online: the record is fetched, and the PINNED hosted wiring attests
    // until install (the in-run `scan --redirect --vex` evidence).
    let (_rt, server) = serve_patch_views(vec![(UUID.to_string(), left_pad_view(&"b".repeat(64)))]);
    let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
    assert_eq!(code, Some(0), "{env}");
    let doc: Value =
        serde_json::from_slice(&std::fs::read(cwd.join("out.vex.json")).unwrap()).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "{doc}");
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-lock-host");
    assert_eq!(stmts[0]["vulnerability"]["aliases"][0], "CVE-2026-40");
    assert_eq!(stmts[0]["products"][0]["subcomponents"][0]["@id"], purl);
    assert_eq!(
        stmts[0]["impact_statement"],
        format!("Patched via Socket patch {UUID} (redirected)")
    );
    assert!(
        !cwd.join(".socket/manifest.json").exists(),
        "vex never writes the manifest"
    );
}

/// Once installed, the installed tree is the evidence: a verifying tree
/// attests, a tampered one is omitted even though the pinned wiring alone
/// would have attested a not-yet-installed checkout.
#[test]
fn lockfile_hosted_ref_is_hash_verified_once_installed() {
    let patched = b"hosted patched index\n";
    let after = compute_git_sha256_from_bytes(patched);
    for (installed, expect_ok) in [(&patched[..], true), (&b"tampered bytes\n"[..], false)] {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let purl = scaffold_npm(cwd, "left-pad", "1.3.0", installed);
        write_hosted_package_lock(cwd, &[("left-pad", "1.3.0", UUID)], true);
        let (_rt, server) = serve_patch_views(vec![(UUID.to_string(), left_pad_view(&after))]);
        let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
        if expect_ok {
            assert_eq!(code, Some(0), "{env}");
        } else {
            assert_eq!(code, Some(1), "{env}");
            assert_eq!(skipped_reason(&env, &purl), "hash_mismatch", "{env}");
        }
    }
}

/// The hosted npm rewriter ALWAYS pins the patched tarball's integrity; an
/// entry without one is not Socket-written, so it cannot attest from the
/// lockfile alone — only a verifying installed tree can.
#[test]
fn pinless_hosted_ref_needs_an_installed_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purl = "pkg:npm/left-pad@1.3.0";
    write_hosted_package_lock(cwd, &[("left-pad", "1.3.0", UUID)], false);
    let patched = b"hosted patched index\n";
    let (_rt, server) = serve_patch_views(vec![(
        UUID.to_string(),
        left_pad_view(&compute_git_sha256_from_bytes(patched)),
    )]);
    let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
    assert_eq!(code, Some(1), "{env}");
    assert_eq!(skipped_reason(&env, purl), "package_not_found", "{env}");

    scaffold_npm(cwd, "left-pad", "1.3.0", patched);
    write_hosted_package_lock(cwd, &[("left-pad", "1.3.0", UUID)], false);
    let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
    assert_eq!(
        code,
        Some(0),
        "an installed tree that verifies attests: {env}"
    );
}

/// A uuid in a NON-Socket host's URL is the user's own dependency source,
/// never a patch reference: nothing is discovered, so with no manifest and
/// no ledgers the run is `manifest_not_found` (exit 2), and its message
/// says no hosted/vendored references were found either.
#[test]
fn uuid_on_a_foreign_host_is_not_a_patch_reference() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    std::fs::write(
        cwd.join("package-lock.json"),
        serde_json::json!({
            "lockfileVersion": 3,
            "packages": { "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": format!("https://evil.example/patch/npm/{TOKEN}/{UUID}/left-pad-1.3.0.tgz"),
                "integrity": SRI
            } }
        })
        .to_string(),
    )
    .unwrap();
    let (code, env) = vex_json(cwd, &[]);
    assert_eq!(code, Some(2), "{env}");
    assert_eq!(env["error"]["code"], "manifest_not_found", "{env}");
    let message = env["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("Manifest not found") && message.contains("no hosted or vendored"),
        "{message}"
    );
}

/// `--patch-server-url` (staging / self-hosted / test servers): hosted
/// references on the operator's configured patch-server origin count.
#[test]
fn configured_patch_server_origin_counts_as_hosted() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let (_rt, server) = serve_patch_views(vec![(UUID.to_string(), left_pad_view(&"b".repeat(64)))]);
    std::fs::write(
        cwd.join("package-lock.json"),
        serde_json::json!({
            "lockfileVersion": 3,
            "packages": { "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": format!("{}/patch/npm/{TOKEN}/{UUID}/left-pad-1.3.0.tgz", server.uri()),
                "integrity": SRI
            } }
        })
        .to_string(),
    )
    .unwrap();
    let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
    assert_eq!(
        code,
        Some(2),
        "not a Socket host without the override: {env}"
    );
    let (code, env) = vex_json(
        cwd,
        &[
            "--proxy-url",
            &server.uri(),
            "--patch-server-url",
            &server.uri(),
        ],
    );
    assert_eq!(code, Some(0), "{env}");
}

// ──────────────────────────────────────────────────────────────────────
// 7. review regressions: the gates that keep a stale or ambiguous wiring
// from attesting.
// ──────────────────────────────────────────────────────────────────────

/// REGRESSION: `--ecosystems` / `SOCKET_ECOSYSTEMS` keeps out-of-scope
/// purls from being crawled at all, so they come back `package_not_found`.
/// The not-installed lockfile basis must not excuse THAT: the installed
/// tree was never inspected (here it is present and UNPATCHED), so an
/// out-of-scope pinned hosted ref stays omitted instead of attesting.
#[test]
fn ecosystems_filter_never_turns_an_uninspected_install_into_a_lockfile_attestation() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purl = scaffold_npm(cwd, "left-pad", "1.3.0", b"unpatched upstream bytes\n");
    write_hosted_package_lock(cwd, &[("left-pad", "1.3.0", UUID)], true);
    write_redirect_state(
        cwd,
        &purl,
        make_record(UUID, &"b".repeat(64), "GHSA-eco-scope", &["CVE-2026-41"]),
    );

    // In scope, the installed tree is inspected and does not verify.
    let (code, env) = vex_json(cwd, &["--offline"]);
    assert_eq!(code, Some(1), "{env}");
    assert_eq!(skipped_reason(&env, &purl), "hash_mismatch", "{env}");

    let (code, env) = vex_json(cwd, &["--offline", "--ecosystems", "pypi"]);
    assert_eq!(code, Some(1), "an out-of-scope purl must not attest: {env}");
    assert_eq!(skipped_reason(&env, &purl), "package_not_found", "{env}");
    assert!(
        !env["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "verified"),
        "{env}"
    );

    // The same run with NOTHING installed still attests from the pinned
    // wiring when npm is in scope (the basis itself is unchanged).
    std::fs::remove_dir_all(cwd.join("node_modules")).unwrap();
    let (code, env) = vex_json(cwd, &["--offline", "--ecosystems", "npm"]);
    assert_eq!(code, Some(0), "{env}");
}

/// Write a redirect ledger with `records` and real-kind `edits`.
fn write_redirect_ledger(cwd: &Path, records: &[(&str, PatchRecord)], edits: &[(&str, &str)]) {
    let mut state = RedirectState::new();
    for (purl, record) in records {
        state.records.insert(purl.to_string(), record.clone());
    }
    for (path, kind) in edits {
        state.edits.push(FileEdit {
            path: path.to_string(),
            kind: kind.to_string(),
            action: "rewritten".to_string(),
            key: None,
            original: None,
            new: None,
        });
    }
    let dir = cwd.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("redirect-state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();
}

/// REGRESSION: after the cargo dependency pin was reverted (Cargo.toml has
/// no `registry = "socket-patch-<U>"`, Cargo.lock sources the crate from
/// crates.io), the leftover `.cargo/config.toml` `[registries]` block still
/// names the uuid — but it routes nothing, so the hosted ledger record is
/// `redirect_unwired`, INCLUDING under `--no-verify`. With the pin in place
/// the same ledger attests.
#[test]
fn leftover_registry_definition_does_not_keep_a_hosted_ledger_alive() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purl = "pkg:cargo/smallvec@1.6.0";
    let index = format!("https://patch.socket.dev/patch-registry/cargo/{TOKEN}/{UUID}/index/");
    std::fs::create_dir_all(cwd.join(".cargo")).unwrap();
    std::fs::write(
        cwd.join(".cargo/config.toml"),
        format!("[registries.socket-patch-{UUID}]\nindex = \"sparse+{index}\"\n"),
    )
    .unwrap();
    std::fs::write(
        cwd.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nsmallvec = \"1.6.0\"\n",
    )
    .unwrap();
    std::fs::write(
        cwd.join("Cargo.lock"),
        format!(
            "version = 3\n\n[[package]]\nname = \"smallvec\"\nversion = \"1.6.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{}\"\n",
            "c".repeat(64)
        ),
    )
    .unwrap();
    write_redirect_ledger(
        cwd,
        &[(
            purl,
            make_record(UUID, &"b".repeat(64), "GHSA-cargo-left", &["CVE-2026-42"]),
        )],
        &[
            ("Cargo.toml", "redirect_cargo_toml_dep"),
            (".cargo/config.toml", "redirect_cargo_registry"),
            ("Cargo.lock", "redirect_cargo_lock_entry"),
        ],
    );
    for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
        let (code, env) = vex_json(cwd, extra);
        assert_eq!(code, Some(1), "{extra:?}: {env}");
        assert_eq!(
            skipped_reason(&env, purl),
            "redirect_unwired",
            "{extra:?}: {env}"
        );
    }

    // The pin restored (the shape `scan --mode hosted` writes): live.
    std::fs::write(
        cwd.join("Cargo.toml"),
        format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
             smallvec = {{ version = \"1.6.0\", registry = \"socket-patch-{UUID}\" }}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        cwd.join("Cargo.lock"),
        format!(
            "version = 3\n\n[[package]]\nname = \"smallvec\"\nversion = \"1.6.0\"\n\
             source = \"sparse+{index}\"\nchecksum = \"{}\"\n",
            "e".repeat(64)
        ),
    )
    .unwrap();
    let (code, env) = vex_json(cwd, &["--offline", "--no-verify"]);
    assert_eq!(code, Some(0), "{env}");
}

/// REGRESSION: two npm locks wiring ONE package to DIFFERENT patches (a
/// stale package-lock.json beside the npm-shrinkwrap.json) — which one the
/// build installs is not decidable from the files, so NEITHER attests, and
/// the purl gets exactly one `wiring_conflict` skip (never a statement plus
/// a skip). Covers both record shapes: manifest U1 + ledger U2, and a
/// ledger record for only one of them.
#[test]
fn conflicting_lockfiles_attest_neither_patch() {
    const U1: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    const U2: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
    let purl = "pkg:npm/left-pad@1.3.0";
    for with_manifest in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        write_hosted_package_lock(cwd, &[("left-pad", "1.3.0", U1)], true);
        std::fs::rename(
            cwd.join("package-lock.json"),
            cwd.join("npm-shrinkwrap.json"),
        )
        .unwrap();
        write_hosted_package_lock(cwd, &[("left-pad", "1.3.0", U2)], true);
        write_redirect_state(
            cwd,
            purl,
            make_record(U2, &"b".repeat(64), "GHSA-only-u2", &["CVE-2026-43"]),
        );
        if with_manifest {
            let mut manifest = PatchManifest::new();
            manifest.patches.insert(
                purl.to_string(),
                make_record(U1, &"b".repeat(64), "GHSA-only-u1", &["CVE-2026-44"]),
            );
            std::fs::create_dir_all(cwd.join(".socket")).unwrap();
            std::fs::write(
                cwd.join(".socket/manifest.json"),
                serde_json::to_string_pretty(&manifest).unwrap(),
            )
            .unwrap();
        }
        for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
            let (code, env) = vex_json(cwd, extra);
            assert_eq!(code, Some(1), "{with_manifest} {extra:?}: {env}");
            let events = env["events"].as_array().unwrap();
            assert!(
                !events.iter().any(|e| e["action"] == "verified"),
                "{with_manifest} {extra:?}: {env}"
            );
            let skips: Vec<&Value> = events
                .iter()
                .filter(|e| e["action"] == "skipped" && e["purl"] == purl)
                .collect();
            assert_eq!(skips.len(), 1, "{with_manifest} {extra:?}: {env}");
            assert_eq!(skips[0]["errorCode"], "wiring_conflict", "{env}");
        }
    }
}

/// REGRESSION: `scan --mode hosted` over a vendored package leaves the
/// vendor-ledger entry (U1) in place and records the hosted patch (U2) in
/// the redirect ledger; the (yarn classic) lockfile wires U2 — discovered
/// both as a lockfile ref and through the ledger's recorded wiring file.
/// The dead vendor claim must fall through to the live
/// hosted claim and attest U2 `(redirected)`, not drop the patch as
/// `vendor_unwired`. With the hosted wiring gone too, it is unwired.
#[test]
fn hosted_takeover_of_a_vendored_package_attests_the_hosted_patch() {
    const U1: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    const U2: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purl = "pkg:npm/left-pad@1.3.0";
    std::fs::write(
        cwd.join("yarn.lock"),
        format!(
            "# yarn lockfile v1\n\nleft-pad@1.3.0:\n  version \"1.3.0\"\n  resolved \"{}#abc\"\n  \
             integrity {SRI}\n",
            hosted_npm_url("left-pad", "1.3.0", U2)
        ),
    )
    .unwrap();
    let u1_record = make_record(U1, &"b".repeat(64), "GHSA-vend-u1", &["CVE-2026-45"]);
    let vendor_state = serde_json::json!({
        "version": 1,
        "entries": { purl: {
            "ecosystem": "npm",
            "basePurl": purl,
            "uuid": U1,
            "artifact": {
                "path": format!(".socket/vendor/npm/{U1}/left-pad-1.3.0.tgz"),
                "sha256": ""
            },
            "wiring": [{ "file": "yarn.lock", "kind": "yarn_resolved", "action": "rewritten" }],
            "flavor": "yarn-classic",
            "detached": true,
            "record": u1_record,
        } }
    });
    std::fs::create_dir_all(cwd.join(".socket/vendor")).unwrap();
    std::fs::write(
        cwd.join(".socket/vendor/state.json"),
        serde_json::to_string_pretty(&vendor_state).unwrap(),
    )
    .unwrap();
    write_redirect_ledger(
        cwd,
        &[(
            purl,
            make_record(U2, &"b".repeat(64), "GHSA-host-u2", &["CVE-2026-46"]),
        )],
        &[("yarn.lock", "redirect_yarn_classic_entry")],
    );

    let (code, env) = vex_json(cwd, &["--offline", "--no-verify"]);
    assert_eq!(code, Some(0), "{env}");
    let doc: Value =
        serde_json::from_slice(&std::fs::read(cwd.join("out.vex.json")).unwrap()).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "{doc}");
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-host-u2");
    assert_eq!(
        stmts[0]["impact_statement"],
        format!("Patched via Socket patch {U2} (redirected)")
    );

    // Hosted wiring reverted as well: nothing is wired any more.
    std::fs::write(
        cwd.join("yarn.lock"),
        "# yarn lockfile v1\n\nleft-pad@1.3.0:\n  version \"1.3.0\"\n  \
         resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#abc\"\n",
    )
    .unwrap();
    let (code, env) = vex_json(cwd, &["--offline", "--no-verify"]);
    assert_eq!(code, Some(1), "{env}");
    assert_eq!(skipped_reason(&env, purl), "vendor_unwired", "{env}");
}

// ──────────────────────────────────────────────────────────────────────
// 8. REGRESSION (core discover rule 11): a redirect ledger record whose
// patch the lockfiles still MENTION, but only in a shape the package
// manager does not consume, is dead — the ledger fallback no longer
// re-derives "live" from the raw text the extractor already rejected.
// ──────────────────────────────────────────────────────────────────────

/// A committed hosted-rewriter golden (`crates/socket-patch-core/tests/
/// fixtures/redirect/<rel>`).
fn redirect_fixture(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../socket-patch-core/tests/fixtures/redirect")
        .join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Every case pairs the rewriter's own golden output (LIVE — it attests)
/// with the stale shape an extractor REJECTS with a diagnostic or skips as
/// unread (the file text still names the patch uuid in pin position, so
/// before rule 11 the ledger fallback found it and attested
/// `(redirected)`, `--no-verify` or not):
///
/// * go: a `require` bump leaves the hosted replace inert;
/// * cargo: the Cargo.toml pin was reverted, the lock entry is stale;
/// * uv: a `pyproject.toml` that does not confirm the lock's hosted source
///   (uv re-resolves it);
/// * maven: the managed `-socket.<hex8>` pin is shadowed by a direct plain
///   version;
/// * nuget: a source + mapping whose lock no longer restores the id (the
///   dependency was dropped and the lock regenerated);
/// * pnpm: only the `shrinkwrap.yaml` debris pnpm never reads names it.
#[test]
fn rejected_hosted_wiring_never_keeps_a_redirect_ledger_alive() {
    let go_mod = redirect_fixture("golang/gomod/basic/expected/go.mod");
    let go_sum = redirect_fixture("golang/gomod/basic/expected/go.sum");
    let cargo_toml = redirect_fixture("cargo/cargo/basic/expected/Cargo.toml");
    let cargo_lock = redirect_fixture("cargo/cargo/basic/expected/Cargo.lock");
    let uv_lock = redirect_fixture("pypi/uv/basic/expected/uv.lock");
    let pom = redirect_fixture("maven/pom/existing-depmgmt/expected/pom.xml");
    let nuget_config = redirect_fixture("nuget/packages-lock/basic/expected/nuget.config");
    let nuget_lock = redirect_fixture("nuget/packages-lock/basic/expected/packages.lock.json");
    let pnpm_hosted = redirect_fixture("npm/pnpm/basic/expected/pnpm-lock.yaml");
    let pnpm_registry = redirect_fixture("npm/pnpm/basic/input/pnpm-lock.yaml");

    let bumped = go_mod.replace(
        "require github.com/foo/bar v1.4.2",
        "require github.com/foo/bar v1.5.0",
    );
    assert_ne!(bumped, go_mod);
    let reverted_toml = cargo_toml.replace(
        "serde = { version = \"1.0.190\", registry = \"socket-patch-55555555-5555-5555-5555-555555555555\" }",
        "serde = \"1.0.190\"",
    );
    assert_ne!(reverted_toml, cargo_toml);
    let unconfirming_pyproject =
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"click==8.1.7\"]\n"
            .to_string();
    let shadowed_pom = pom.replace(
        "      <artifactId>slf4j-api</artifactId>\n    </dependency>\n  </dependencies>",
        "      <artifactId>slf4j-api</artifactId>\n      <version>1.7.36</version>\n    </dependency>\n  </dependencies>",
    );
    assert_ne!(shadowed_pom, pom);

    type Files = Vec<(&'static str, String)>;
    let cases: Vec<(&str, &str, &str, Files, Files)> = vec![
        (
            "go require bump",
            "pkg:golang/github.com/foo/bar@v1.4.2",
            "55555555-5555-5555-5555-555555555555",
            vec![("go.mod", bumped), ("go.sum", go_sum.clone())],
            vec![("go.mod", go_mod.clone()), ("go.sum", go_sum.clone())],
        ),
        (
            "cargo reverted pin",
            "pkg:cargo/serde@1.0.190",
            "55555555-5555-5555-5555-555555555555",
            vec![
                ("Cargo.toml", reverted_toml),
                ("Cargo.lock", cargo_lock.clone()),
            ],
            vec![
                ("Cargo.toml", cargo_toml.clone()),
                ("Cargo.lock", cargo_lock.clone()),
            ],
        ),
        (
            "uv lock its pyproject does not confirm",
            "pkg:pypi/click@8.1.7",
            "88888888-8888-8888-8888-888888888888",
            vec![
                ("uv.lock", uv_lock.clone()),
                ("pyproject.toml", unconfirming_pyproject),
            ],
            vec![("uv.lock", uv_lock.clone())],
        ),
        (
            "maven managed pin shadowed",
            "pkg:maven/org.slf4j/slf4j-api@1.7.36",
            "77777777-7777-7777-7777-777777777777",
            vec![("pom.xml", shadowed_pom)],
            vec![("pom.xml", pom.clone())],
        ),
        (
            "nuget source whose lock no longer restores the id",
            "pkg:nuget/Newtonsoft.Json@13.0.3",
            "66666666-6666-6666-6666-666666666666",
            vec![
                ("nuget.config", nuget_config.clone()),
                (
                    "packages.lock.json",
                    nuget_lock.replace("Newtonsoft.Json", "Serilog"),
                ),
            ],
            vec![
                ("nuget.config", nuget_config.clone()),
                ("packages.lock.json", nuget_lock.clone()),
            ],
        ),
        (
            "pnpm shrinkwrap debris",
            "pkg:npm/left-pad@1.3.0",
            "22222222-2222-2222-2222-222222222222",
            vec![
                ("pnpm-lock.yaml", pnpm_registry.clone()),
                ("shrinkwrap.yaml", pnpm_hosted.clone()),
            ],
            vec![("pnpm-lock.yaml", pnpm_hosted.clone())],
        ),
    ];

    for (name, purl, uuid, stale, live) in cases {
        for (is_live, files) in [(false, &stale), (true, &live)] {
            let tmp = tempfile::tempdir().unwrap();
            let cwd = tmp.path();
            let mut edits = Vec::new();
            for (file, text) in files {
                std::fs::write(cwd.join(file), text).unwrap();
                edits.push((*file, "rewritten"));
            }
            // The ledger recorded editing every wiring file of the pair.
            for (file, _) in &live {
                if !edits.iter().any(|(f, _)| f == file) {
                    edits.push((*file, "rewritten"));
                }
            }
            write_redirect_ledger(
                cwd,
                &[(
                    purl,
                    make_record(uuid, &"b".repeat(64), "GHSA-rjct-host", &["CVE-2026-51"]),
                )],
                &edits,
            );
            // `--global-prefix` must not switch discovery's authority off:
            // the ledger is still read from `--cwd`, so its liveness must
            // still be judged by the lockfiles there.
            let prefix = tempfile::tempdir().unwrap();
            let global = ["--offline", "--no-verify", "--global-prefix"];
            let global: Vec<&str> = global
                .into_iter()
                .chain([prefix.path().to_str().unwrap()])
                .collect();
            let (code, env) = vex_json(cwd, &global);
            if is_live {
                assert_eq!(code, Some(0), "{name} (live, --global-prefix): {env}");
            } else {
                assert_eq!(code, Some(1), "{name} (--global-prefix): {env}");
                assert_eq!(
                    skipped_reason(&env, purl),
                    "redirect_unwired",
                    "{name} (--global-prefix): {env}"
                );
            }
            let (code, env) = vex_json(cwd, &["--offline", "--no-verify"]);
            if is_live {
                assert_eq!(code, Some(0), "{name} (live): {env}");
                continue;
            }
            assert_eq!(code, Some(1), "{name}: {env}");
            assert_eq!(
                env["error"]["code"], "no_applicable_patches",
                "{name}: {env}"
            );
            assert_eq!(
                skipped_reason(&env, purl),
                "redirect_unwired",
                "{name}: {env}"
            );
            // Without --no-verify too: the gate is about wiring.
            let (code, env) = vex_json(cwd, &["--offline"]);
            assert_eq!(code, Some(1), "{name}: {env}");
            assert_eq!(
                skipped_reason(&env, purl),
                "redirect_unwired",
                "{name}: {env}"
            );
        }
    }
}

/// REGRESSION (false attestation): the ledger's hosted wiring lives in one
/// lock while a SIBLING lock resolves the same version from the registry —
/// a stale `yarn.lock` beside the hosted `package-lock.json`, a registry
/// `uv.lock` (what `uv sync --frozen` installs) beside a hosted
/// `requirements.txt`. Which one the build installs from depends on the
/// package manager that runs, so the record is not attested
/// (`redirect_unwired`, with a note naming the contesting lock) where it
/// used to be `not_affected (redirected)`. Without the stale lock it attests.
#[test]
fn a_sibling_lock_resolving_the_registry_contests_a_ledger_record() {
    const U: &str = "5e1f0a3c-2b4d-4c6e-8f10-123456789abc";
    let npm_url = format!("https://patch.socket.dev/patch/npm/foo/1.0.0/{TOKEN}/{U}/foo-1.0.0.tgz");
    let pypi_url = format!(
        "https://patch.socket.dev/patch/pypi/vexdemo/1.2.3/{TOKEN}/{U}/vexdemo-1.2.3-py3-none-any.whl"
    );
    let sha = "a".repeat(64);
    type Files = Vec<(&'static str, String)>;
    let cases: Vec<(&str, &str, Files, (&'static str, String))> = vec![
        (
            "npm + stale yarn",
            "pkg:npm/foo@1.0.0",
            vec![(
                "package-lock.json",
                serde_json::json!({
                    "name": "app", "lockfileVersion": 3, "requires": true,
                    "packages": {
                        "": {"name": "app", "dependencies": {"foo": "1.0.0"}},
                        "node_modules/foo": {"version": "1.0.0", "resolved": npm_url, "integrity": SRI},
                    }
                })
                .to_string(),
            )],
            (
                "yarn.lock",
                format!(
                    "# yarn lockfile v1\n\n\nfoo@1.0.0:\n  version \"1.0.0\"\n  resolved \
                     \"https://registry.yarnpkg.com/foo/-/foo-1.0.0.tgz#{}\"\n  integrity {SRI}\n",
                    "0".repeat(40)
                ),
            ),
        ),
        (
            "requirements + registry uv.lock",
            "pkg:pypi/vexdemo@1.2.3",
            vec![(
                "requirements.txt",
                format!("vexdemo @ {pypi_url} --hash=sha256:{sha}\n"),
            )],
            (
                "uv.lock",
                format!(
                    "version = 1\nrequires-python = \">=3.8\"\n\n[[package]]\nname = \"vexdemo\"\n\
                     version = \"1.2.3\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\n\
                     wheels = [{{ url = \"https://files.pythonhosted.org/packages/vexdemo-1.2.3-py3-none-any.whl\", \
                     hash = \"sha256:{sha}\" }}]\n"
                ),
            ),
        ),
    ];
    for (name, purl, wired, stale) in cases {
        for contested in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            let cwd = tmp.path();
            let mut edits = Vec::new();
            for (file, text) in &wired {
                std::fs::write(cwd.join(file), text).unwrap();
                edits.push((*file, "rewritten"));
            }
            if contested {
                std::fs::write(cwd.join(stale.0), &stale.1).unwrap();
            }
            write_redirect_ledger(
                cwd,
                &[(
                    purl,
                    make_record(U, &"b".repeat(64), "GHSA-sibl-lock", &["CVE-2026-53"]),
                )],
                &edits,
            );
            let (code, env) = vex_json(cwd, &["--offline", "--no-verify"]);
            if !contested {
                assert_eq!(code, Some(0), "{name} (no stale lock): {env}");
                continue;
            }
            assert_eq!(code, Some(1), "{name}: {env}");
            assert_eq!(
                skipped_reason(&env, purl),
                "redirect_unwired",
                "{name}: {env}"
            );
            assert!(
                env.to_string().contains(stale.0),
                "{name}: the contesting lock is named: {env}"
            );
        }
    }
}

/// REGRESSION: a hosted pin with NO lock at all is the rewriters' ordinary
/// output, not a stale shape — `rewrite_nuget` edits only nuget.config for a
/// project without RestorePackagesWithLockFile, `rewrite_cargo` only
/// Cargo.toml + `.cargo/config.toml` for a crate whose Cargo.lock is
/// gitignored. The exclusive Socket route (which serves only the patched
/// version) plus the ledger's exact purl is live wiring; before, discovery
/// recognized the uuid, made no ref, and killed the record as
/// `redirect_unwired`. A ledger version outside cargo's requirement stays
/// dead.
#[test]
fn lockless_hosted_pins_keep_their_redirect_ledger_record_alive() {
    let nuget_config = redirect_fixture("nuget/packages-lock/basic/expected/nuget.config");
    let cargo_toml = redirect_fixture("cargo/cargo/basic/expected/Cargo.toml");
    let cargo_config = redirect_fixture("cargo/cargo/basic/expected/.cargo/config.toml");
    type Files = Vec<(&'static str, String)>;
    let cases: Vec<(&str, &str, &str, Files, bool)> = vec![
        (
            "nuget lockless",
            "pkg:nuget/Newtonsoft.Json@13.0.3",
            "66666666-6666-6666-6666-666666666666",
            vec![("nuget.config", nuget_config.clone())],
            true,
        ),
        (
            "cargo lockless",
            "pkg:cargo/serde@1.0.190",
            "55555555-5555-5555-5555-555555555555",
            vec![
                ("Cargo.toml", cargo_toml.clone()),
                (".cargo/config.toml", cargo_config.clone()),
            ],
            true,
        ),
        (
            "cargo lockless, ledger version outside the requirement",
            "pkg:cargo/serde@2.0.0",
            "55555555-5555-5555-5555-555555555555",
            vec![
                ("Cargo.toml", cargo_toml.clone()),
                (".cargo/config.toml", cargo_config.clone()),
            ],
            false,
        ),
    ];
    for (name, purl, uuid, files, live) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let mut edits = Vec::new();
        for (file, text) in &files {
            let path = cwd.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
            edits.push((*file, "rewritten"));
        }
        write_redirect_ledger(
            cwd,
            &[(
                purl,
                make_record(uuid, &"b".repeat(64), "GHSA-lock-less", &["CVE-2026-52"]),
            )],
            &edits,
        );
        let (code, env) = vex_json(cwd, &["--offline", "--no-verify"]);
        if live {
            assert_eq!(code, Some(0), "{name}: {env}");
            let doc: Value =
                serde_json::from_slice(&std::fs::read(cwd.join("out.vex.json")).unwrap()).unwrap();
            assert_eq!(
                doc["statements"][0]["impact_statement"],
                format!("Patched via Socket patch {uuid} (redirected)"),
                "{name}: {doc}"
            );
        } else {
            assert_eq!(code, Some(1), "{name}: {env}");
            assert_eq!(
                skipped_reason(&env, purl),
                "redirect_unwired",
                "{name}: {env}"
            );
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// 9. Installed-tree evidence is the copy the hosted BUILD consumes
// (`commands/vex_consumed.rs`): a distinct store's pristine sibling is
// never judged (not installed ⇒ the pinned lockfile wiring attests), and
// where hosted and registry bytes share a location every copy must verify.
// ──────────────────────────────────────────────────────────────────────

/// The patch view for `uuid` → `purl` with one file `(key, before, after)`.
fn one_file_view(uuid: &str, purl: &str, file: &str, before: &[u8], after: &[u8]) -> Value {
    serde_json::json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "Fri, 27 Mar 2026 00:00:00 GMT",
        "files": { file: {
            "beforeHash": compute_git_sha256_from_bytes(before),
            "afterHash": compute_git_sha256_from_bytes(after),
        } },
        "vulnerabilities": {
            "GHSA-cons-umed": {
                "cves": ["CVE-2026-60"], "summary": "s", "severity": "high", "description": "d"
            }
        },
        "description": "hosted patch",
        "license": "MIT",
        "tier": "free",
    })
}

fn put(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// Assert `vex` attested exactly `uuid`'s patch, `(redirected)`.
fn assert_attested(cwd: &Path, code: Option<i32>, env: &Value, uuid: &str, what: &str) {
    assert_eq!(code, Some(0), "{what}: {env}");
    let doc: Value =
        serde_json::from_slice(&std::fs::read(cwd.join("out.vex.json")).unwrap()).unwrap();
    assert_eq!(
        doc["statements"][0]["impact_statement"],
        format!("Patched via Socket patch {uuid} (redirected)"),
        "{what}: {doc}"
    );
}

/// Go: under `replace M v => patch.socket.dev/gopatch/<U> <sver>` the build
/// compiles the REPLACEMENT module. A pristine `M@v` in the module cache
/// (cached before the redirect) is never read: with only it present the
/// pinned wiring attests — before, it was hashed and the patch omitted as
/// `not_applied` — while the replacement, once downloaded, is the evidence.
#[test]
fn go_hosted_ref_is_judged_by_its_replacement_module_never_the_pristine_original() {
    const U: &str = "55555555-5555-5555-5555-555555555555";
    let purl = "pkg:golang/github.com/foo/bar@v1.4.2";
    let (pristine, patched) = (
        &b"package bar // pristine\n"[..],
        &b"package bar // patched\n"[..],
    );
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().join("app");
    let modcache = tmp.path().join("modcache");
    std::fs::create_dir_all(&cwd).unwrap();
    for file in ["go.mod", "go.sum"] {
        let text = redirect_fixture(&format!("golang/gomod/basic/expected/{file}"));
        std::fs::write(cwd.join(file), text).unwrap();
    }
    put(&modcache, "github.com/foo/bar@v1.4.2/lib.go", pristine);
    let (_rt, server) = serve_patch_views(vec![(
        U.to_string(),
        one_file_view(U, purl, "lib.go", pristine, patched),
    )]);
    let envs = [("GOMODCACHE", modcache.as_path())];
    let args = ["--proxy-url", &server.uri()];

    let (code, env) = vex_json_env(&cwd, &args, &envs);
    assert_attested(&cwd, code, &env, U, "only the pristine original is cached");

    let replacement = format!("patch.socket.dev/gopatch/{U}@v1.4.2-socketpatch.1/lib.go");
    put(&modcache, &replacement, patched);
    let (code, env) = vex_json_env(&cwd, &args, &envs);
    assert_attested(&cwd, code, &env, U, "the consumed replacement verifies");

    put(&modcache, &replacement, b"tampered\n");
    let (code, env) = vex_json_env(&cwd, &args, &envs);
    assert_eq!(code, Some(1), "{env}");
    assert_eq!(skipped_reason(&env, purl), "hash_mismatch", "{env}");
}

/// Cargo: a hosted lock entry builds from its Socket registry's own
/// `registry/src/<host>-<hash>/` extraction; crates.io's copy of the same
/// `name-version` is a pristine sibling (before: hashed, `not_applied`).
/// Two Socket registries holding the crate (a superseded patch built on
/// this machine) are told apart by the cached `.crate` matching the lock's
/// pinned checksum; the consumed copy tampered is omitted.
#[test]
fn cargo_hosted_ref_is_judged_by_its_socket_registry_copy_never_crates_io() {
    use sha2::{Digest, Sha256};
    const U: &str = "55555555-5555-5555-5555-555555555555";
    let purl = "pkg:cargo/serde@1.0.190";
    let (pristine, patched) = (&b"// serde pristine\n"[..], &b"// serde patched\n"[..]);
    let crate_bytes = b"the patched serde-1.0.190.crate";
    let checksum = hex::encode(Sha256::digest(crate_bytes));
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().join("app");
    let cargo_home = tmp.path().join("cargo");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::write(
        cwd.join("Cargo.toml"),
        redirect_fixture("cargo/cargo/basic/expected/Cargo.toml"),
    )
    .unwrap();
    let lock = redirect_fixture("cargo/cargo/basic/expected/Cargo.lock").replace(
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        &checksum,
    );
    std::fs::write(cwd.join("Cargo.lock"), lock).unwrap();
    let manifest = b"[package]\nname = \"serde\"\nversion = \"1.0.190\"\n";
    let crate_dir = |registry: &str, lib: &[u8]| {
        let dir = format!("registry/src/{registry}/serde-1.0.190");
        put(&cargo_home, &format!("{dir}/Cargo.toml"), manifest);
        put(&cargo_home, &format!("{dir}/src/lib.rs"), lib);
    };
    crate_dir("index.crates.io-1949cf8c6b5b557f", pristine);
    let (_rt, server) = serve_patch_views(vec![(
        U.to_string(),
        one_file_view(U, purl, "src/lib.rs", pristine, patched),
    )]);
    let envs = [("CARGO_HOME", cargo_home.as_path())];
    let args = ["--proxy-url", &server.uri()];

    let (code, env) = vex_json_env(&cwd, &args, &envs);
    assert_attested(
        &cwd,
        code,
        &env,
        U,
        "only crates.io's pristine copy is extracted",
    );

    // This patch's registry (its cached .crate is the pinned artifact) and
    // an older patch's registry holding the same crate version.
    crate_dir("patch.socket.dev-bbbbbbbbbbbbbbbb", patched);
    put(
        &cargo_home,
        "registry/cache/patch.socket.dev-bbbbbbbbbbbbbbbb/serde-1.0.190.crate",
        crate_bytes,
    );
    crate_dir("patch.socket.dev-aaaaaaaaaaaaaaaa", b"// an older patch\n");
    put(
        &cargo_home,
        "registry/cache/patch.socket.dev-aaaaaaaaaaaaaaaa/serde-1.0.190.crate",
        b"an older patch's crate",
    );
    let (code, env) = vex_json_env(&cwd, &args, &envs);
    assert_attested(&cwd, code, &env, U, "the pinned registry's copy verifies");

    crate_dir("patch.socket.dev-bbbbbbbbbbbbbbbb", b"// tampered\n");
    let (code, env) = vex_json_env(&cwd, &args, &envs);
    assert_eq!(code, Some(1), "{env}");
    assert_eq!(skipped_reason(&env, purl), "hash_mismatch", "{env}");
}

/// Maven: the fail-closed hosted pom pins `<base>-socket.<hex8>`, so maven
/// resolves the suffixed version dir and never the `<base>` one (before:
/// the pristine `<base>` jar was hashed and the patch omitted). The served
/// files carry the suffixed name; the record's `<a>-<base>.jar` is matched
/// as `<a>-<suffixed>.jar`.
#[test]
fn maven_hosted_ref_is_judged_by_its_suffixed_version_never_the_base_version() {
    const U: &str = "77777777-7777-7777-7777-777777777777";
    let purl = "pkg:maven/org.slf4j/slf4j-api@1.7.36";
    let (pristine, patched) = (&b"PK pristine jar"[..], &b"PK patched jar"[..]);
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().join("app");
    let m2 = tmp.path().join("m2");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::write(
        cwd.join("pom.xml"),
        redirect_fixture("maven/pom/basic/expected/pom.xml"),
    )
    .unwrap();
    let base = "org/slf4j/slf4j-api/1.7.36";
    put(&m2, &format!("{base}/slf4j-api-1.7.36.pom"), b"<project/>");
    put(&m2, &format!("{base}/slf4j-api-1.7.36.jar"), pristine);
    let (_rt, server) = serve_patch_views(vec![(
        U.to_string(),
        one_file_view(U, purl, "slf4j-api-1.7.36.jar", pristine, patched),
    )]);
    let envs = [("MAVEN_REPO_LOCAL", m2.as_path())];
    let args = ["--proxy-url", &server.uri()];

    let (code, env) = vex_json_env(&cwd, &args, &envs);
    assert_attested(
        &cwd,
        code,
        &env,
        U,
        "only the pristine base version is cached",
    );

    let suffixed = "org/slf4j/slf4j-api/1.7.36-socket.77777777";
    put(
        &m2,
        &format!("{suffixed}/slf4j-api-1.7.36-socket.77777777.pom"),
        b"<project/>",
    );
    let jar = format!("{suffixed}/slf4j-api-1.7.36-socket.77777777.jar");
    put(&m2, &jar, patched);
    let (code, env) = vex_json_env(&cwd, &args, &envs);
    assert_attested(&cwd, code, &env, U, "the consumed suffixed jar verifies");

    put(&m2, &jar, b"PK tampered jar");
    let (code, env) = vex_json_env(&cwd, &args, &envs);
    assert_eq!(code, Some(1), "{env}");
    assert_eq!(skipped_reason(&env, purl), "hash_mismatch", "{env}");
}

/// npm installs hosted and registry bytes at the same `node_modules` paths,
/// and every physical copy serves some dependent: a patched root copy must
/// not attest a pristine NESTED copy of the same version (before: only the
/// root copy was hashed — a false `not_affected`).
#[test]
fn every_installed_npm_copy_of_a_hosted_ref_must_verify() {
    let (pristine, patched) = (
        &b"module.exports = 'pristine'\n"[..],
        &b"module.exports = 'patched'\n"[..],
    );
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purl = scaffold_npm(cwd, "left-pad", "1.3.0", patched);
    write_hosted_package_lock(cwd, &[("left-pad", "1.3.0", UUID)], true);
    put(
        cwd,
        "node_modules/dep/package.json",
        br#"{ "name": "dep", "version": "1.0.0" }"#,
    );
    put(
        cwd,
        "node_modules/dep/node_modules/left-pad/package.json",
        br#"{ "name": "left-pad", "version": "1.3.0" }"#,
    );
    put(
        cwd,
        "node_modules/dep/node_modules/left-pad/index.js",
        pristine,
    );
    let (_rt, server) = serve_patch_views(vec![(
        UUID.to_string(),
        one_file_view(UUID, &purl, "package/index.js", pristine, patched),
    )]);
    let args = ["--proxy-url", &server.uri()];

    let (code, env) = vex_json(cwd, &args);
    assert_eq!(
        code,
        Some(1),
        "a pristine nested copy is unpatched code: {env}"
    );
    assert_eq!(skipped_reason(&env, &purl), "not_applied", "{env}");

    put(
        cwd,
        "node_modules/dep/node_modules/left-pad/index.js",
        patched,
    );
    let (code, env) = vex_json(cwd, &args);
    assert_attested(cwd, code, &env, UUID, "every copy verifies");
}

/// pypi: every copy in the project's environments counts — any of them may
/// be the interpreter that runs the project — so a pristine copy in a
/// second project venv blocks the attestation a patched `.venv` would
/// otherwise earn alone (before: only the first environment was hashed).
#[test]
fn every_project_environment_copy_of_a_hosted_ref_must_verify() {
    let (pristine, patched) = (&b"# six pristine\n"[..], &b"# six patched\n"[..]);
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let purl = "pkg:pypi/six@1.16.0";
    std::fs::write(
        cwd.join("requirements.txt"),
        format!(
            "six @ https://patch.socket.dev/patch/pypi/six/1.16.0/{TOKEN}/{UUID}/\
             six-1.16.0-py2.py3-none-any.whl --hash=sha256:{}\n",
            "d".repeat(64)
        ),
    )
    .unwrap();
    let site = |venv: &str, py: &str| {
        if cfg!(windows) {
            format!("{venv}/Lib/site-packages")
        } else {
            format!("{venv}/lib/{py}/site-packages")
        }
    };
    let install = |venv: &str, py: &str, bytes: &[u8]| {
        let site = site(venv, py);
        put(
            cwd,
            &format!("{site}/six-1.16.0.dist-info/METADATA"),
            b"Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n",
        );
        put(cwd, &format!("{site}/six.py"), bytes);
    };
    install(".venv", "python3.12", patched);
    install("venv", "python3.11", pristine);
    let (_rt, server) = serve_patch_views(vec![(
        UUID.to_string(),
        one_file_view(UUID, purl, "six.py", pristine, patched),
    )]);
    let args = ["--proxy-url", &server.uri()];

    let (code, env) = vex_json(cwd, &args);
    assert_eq!(code, Some(1), "a pristine copy in a project venv: {env}");
    assert_eq!(skipped_reason(&env, purl), "not_applied", "{env}");

    install("venv", "python3.11", patched);
    let (code, env) = vex_json(cwd, &args);
    assert_attested(cwd, code, &env, UUID, "every environment's copy verifies");
}
