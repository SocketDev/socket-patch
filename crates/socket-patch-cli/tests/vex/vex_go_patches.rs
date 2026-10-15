//! The guards `synthesize_go_patches` applies to the tamper-able `go.mod`
//! replace set, read through `vex --json` (#1089): which purls attest in the
//! document at `--output`, and which come out as `skipped` events with which
//! `errorCode`.
//!
//! Owner classification is by target-path prefix (`.socket/go-patches/`),
//! so hand-written lines reach every guard:
//!   (a) version-less directory replace          → skipped
//!   (b) go-patches replace with no manifest purl → skipped
//!   (c) explicit (LIVE) vendor entry takes precedence → skipped
//!   (d) SECURITY: unsafe module coordinates      → skipped — the
//!       only end-to-end proof that a tampered go.mod cannot key an
//!       out-of-tree path into VEX verification (the inline unit test only
//!       pins the predicate, not that the synthesis consults it).

use std::ffi::OsStr;
use std::path::Path;

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::vendor::state::{
    VendorArtifact, VendorEntry, VendorState, WiringAction, WiringRecord,
};

use crate::vex_fixture::*;

/// Canonical-grammar patch UUID (the vendored-artifact verifier validates
/// the uuid path level, so fixtures must use the real shape).
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const GOOD_UUID: &str = "22222222-2222-4222-8222-222222222222";
const EVIL_UUID: &str = "33333333-3333-4333-8333-333333333333";
const GO_PRODUCT: &str = "pkg:golang/example.com/app@v0.0.1";

/// Non-detached golang vendor-ledger entry (the manifest record is the
/// verification oracle) whose dir-shaped artifact lives at `rel_path`,
/// recording its `go.mod` replace wiring — vex only honors a vendor entry
/// whose artifact some lockfile/config still references, and the ledger's
/// recorded wiring files are that proof for formats lockfile discovery does
/// not read.
fn write_golang_vendor_state(cwd: &Path, purl: &str, rel_path: &str) {
    let mut state = VendorState::new();
    state.entries.insert(
        purl.to_string(),
        VendorEntry::new(
            "golang".to_string(),
            purl.to_string(),
            UUID.to_string(),
            VendorArtifact {
                yarn_berry10c0: None,
                path: rel_path.to_string(),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            vec![WiringRecord {
                file: "go.mod".to_string(),
                kind: "go_replace".to_string(),
                action: WiringAction::Added,
                key: None,
                original: None,
                new: None,
            }],
        ),
    );
    let dir = cwd.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();
}

/// `vex --json` for the Go product against an EMPTY module cache (so a purl
/// the synthesis refuses has nowhere else to verify), with extra env.
fn vex_go(cwd: &Path, env: &[(&str, &OsStr)]) -> (std::process::Output, Value) {
    let cache = cwd.join("empty-gomodcache");
    std::fs::create_dir_all(&cache).unwrap();
    let mut cmd = vex_command(cwd, Some(GO_PRODUCT));
    cmd.env("GOMODCACHE", &cache);
    for (k, v) in env {
        cmd.env(k, v);
    }
    run_json(cmd, &cwd.join("out.vex.json"))
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
    // prefix classifies every one of them as socket-owned. (c) also keeps
    // its LIVE vendor wiring — the vendor-over-go-patches takeover shape
    // with the stale go-patches line left behind: without it the vendor
    // entry wires nothing, and vex now omits such a leftover entry as
    // `vendor_unwired` instead of letting it route verification at all.
    let mut go_mod = std::fs::read_to_string(cwd.join("go.mod")).unwrap();
    go_mod.push_str(&format!(
        "\nreplace github.com/noversion => ./.socket/go-patches/x\n\
         replace github.com/stale v1.0.0 => ./.socket/go-patches/github.com/stale@v1.0.0\n\
         replace {vend_module} {vend_version} => ./{vend_rel}\n\
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
    for (purl, uuid, file, after, ghsa, cve) in [
        (
            &good_purl,
            GOOD_UUID,
            "bar.go",
            &good_after,
            "GHSA-cg-go-good",
            "CVE-2026-301",
        ),
        (
            &vend_purl,
            UUID,
            "mod.go",
            &vend_after,
            "GHSA-cg-go-vend",
            "CVE-2026-302",
        ),
        (
            &evil_purl,
            EVIL_UUID,
            "evil.go",
            &evil_after,
            "GHSA-cg-go-evil",
            "CVE-2026-303",
        ),
    ] {
        manifest.patches.insert(
            purl.clone(),
            make_record(uuid, file, &"a".repeat(64), after, ghsa, &[cve]),
        );
    }
    write_manifest(cwd, &manifest);

    let (o, env) = vex_go(cwd, &[]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "the good + vendored purls must still attest: {env}"
    );
    let doc = read_doc(&cwd.join("out.vex.json"));
    let text = doc.to_string();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        2,
        "exactly the good redirect + the vendored purl attest; the \
         version-less, stale, and tampered replaces are all skipped. doc: {doc:#}"
    );

    // Control (the synthesis ran): the good module attests from the
    // go-patches copy dir with the PLAIN (non-vendored) impact statement.
    let good = stmts
        .iter()
        .find(|s| s["vulnerability"]["name"] == "GHSA-cg-go-good")
        .unwrap_or_else(|| panic!("good redirect purl missing: {doc:#}"));
    assert_eq!(good["products"][0]["subcomponents"][0]["@id"], good_purl);
    assert_eq!(
        good["impact_statement"],
        format!("Patched via Socket patch {GOOD_UUID}"),
        "a go-patches redirect is applied, not vendored"
    );

    // (c) precedence: the vendored purl attests FROM THE VENDOR ARTIFACT —
    // the (vendored) marker plus the deliberately-wrong go-patches decoy
    // bytes make a flipped precedence fail this test in two ways.
    let vend = stmts
        .iter()
        .find(|s| s["vulnerability"]["name"] == "GHSA-cg-go-vend")
        .unwrap_or_else(|| panic!("vendored purl missing: {doc:#}"));
    assert_eq!(vend["products"][0]["subcomponents"][0]["@id"], vend_purl);
    assert_eq!(
        vend["impact_statement"],
        format!("Patched via Socket patch {UUID} (vendored)"),
        "the explicit vendor entry must win over the go-patches synthesis"
    );

    // (d) SECURITY: the tampered purl is omitted even though a decoy at the
    // traversal target byte-matches its record — the coordinates guard must
    // keep the out-of-tree path out of the verification map entirely.
    assert!(
        !text.contains("GHSA-cg-go-evil"),
        "a tampered go.mod replace must never key an attestation: {doc:#}"
    );
    assert_eq!(
        event_purls(&env, "skipped"),
        [evil_purl.as_str()],
        "the tampered purl is the one omission: {env}"
    );

    // (a) and (b): the version-less replace and the stale replace (no
    // manifest purl) leak into nothing.
    for leaked in ["github.com/stale", "github.com/noversion"] {
        assert!(!text.contains(leaked), "{leaked} attests nothing: {doc:#}");
        assert!(!env.to_string().contains(leaked), "{leaked}: {env}");
    }
}

/// #391 / #392: a go-patches replace pinned to a version the build list no
/// longer selects is inert — after `go get M@v1.4.3` (go >= 1.17 require),
/// or in a go 1.16 graph where go.sum shows the build selects another
/// version — so vex must omit the patch however intact its copy is.
#[test]
fn go_patches_replace_for_an_unselected_version_is_not_attested() {
    let module = "github.com/foo/bar";
    let version = "v1.4.2";
    let purl = format!("pkg:golang/{module}@{version}");
    let replace =
        format!("replace {module} {version} => ./.socket/go-patches/{module}@{version}\n");
    let selected_v117 =
        format!("module example.com/app\n\ngo 1.21\n\nrequire {module} {version}\n\n{replace}");
    let bumped_v117 =
        format!("module example.com/app\n\ngo 1.21\n\nrequire {module} v1.4.3\n\n{replace}");
    let go116 =
        format!("module example.com/app\n\ngo 1.16\n\nrequire example.com/mid v1.0.0\n\n{replace}");
    let go116_sum = format!(
        "{module} {version}/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
         {module} v1.5.0 h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n"
    );
    for (go_mod, go_sum, attests) in [
        (&selected_v117, None, true),
        (&bumped_v117, None, false),
        (&go116, Some(go116_sum.as_str()), false),
        (&go116, None, true),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        std::fs::write(cwd.join("go.mod"), go_mod).unwrap();
        if let Some(sum) = go_sum {
            std::fs::write(cwd.join("go.sum"), sum).unwrap();
        }
        let patched = b"package bar // patched\n";
        let copy = cwd.join(format!(".socket/go-patches/{module}@{version}"));
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::write(copy.join("bar.go"), patched).unwrap();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            purl.clone(),
            make_record(
                GOOD_UUID,
                "bar.go",
                &"a".repeat(64),
                &compute_git_sha256_from_bytes(patched),
                "GHSA-go-unselected",
                &["CVE-2026-391"],
            ),
        );
        write_manifest(cwd, &manifest);

        let (o, env) = vex_go(cwd, &[]);
        if attests {
            assert_eq!(o.status.code(), Some(0), "{go_mod}\n{env}");
            let doc = read_doc(&cwd.join("out.vex.json"));
            assert_eq!(
                doc["statements"][0]["vulnerability"]["name"], "GHSA-go-unselected",
                "{go_mod}\n{doc:#}"
            );
        } else {
            assert_eq!(o.status.code(), Some(1), "{go_mod}\n{env}");
            assert!(
                has_event(&env, "skipped", "go_version_not_selected", &purl),
                "{go_mod}\n{env}"
            );
            assert!(!cwd.join("out.vex.json").exists(), "{go_mod}");
        }
    }
}

/// #484: the patch API keys a `+incompatible` Go module as
/// `@v2.0.0%2Bincompatible`, while go.mod spells the replace's version with
/// a literal `+`. vex must match the two spellings: an applied go-patches
/// redirect attests (it used to be omitted as `not_applied`, exit 1), while
/// a go.work replace that overrides it, or a require that selects another
/// version, is still caught, never attested, and reported under the
/// record's own `%2B` spelling.
#[test]
fn go_patches_replace_of_an_incompatible_module_matches_the_encoded_key() {
    let module = "example.com/legacy";
    let version = "v2.0.0+incompatible";
    let encoded = "pkg:golang/example.com/legacy@v2.0.0%2Bincompatible";
    // (omission reason, if any)
    for omitted in [
        None,
        Some("go_workspace_override"),
        Some("go_version_not_selected"),
    ] {
        let overridden = omitted == Some("go_workspace_override");
        let required = if omitted == Some("go_version_not_selected") {
            "v2.1.0+incompatible"
        } else {
            version
        };
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        std::fs::write(
            cwd.join("go.mod"),
            format!(
                "module example.com/app\n\ngo 1.21\n\nrequire {module} {required}\n\n\
                 replace {module} {version} => ./.socket/go-patches/{module}@{version}\n"
            ),
        )
        .unwrap();
        let go_work = cwd.join("go.work");
        if overridden {
            std::fs::write(
                &go_work,
                format!("go 1.21\n\nuse .\n\nreplace {module} {version} => ./fork\n"),
            )
            .unwrap();
        }
        let patched = b"package legacy // patched\n";
        let copy = cwd.join(format!(".socket/go-patches/{module}@{version}"));
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::write(copy.join("lib.go"), patched).unwrap();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            encoded.to_string(),
            make_record(
                GOOD_UUID,
                "lib.go",
                &"a".repeat(64),
                &compute_git_sha256_from_bytes(patched),
                "GHSA-go-incompatible",
                &["CVE-2026-484"],
            ),
        );
        write_manifest(cwd, &manifest);

        let gowork: &OsStr = if overridden {
            go_work.as_os_str()
        } else {
            OsStr::new("off")
        };
        let (o, env) = vex_go(cwd, &[("GOWORK", gowork)]);
        if let Some(reason) = omitted {
            assert_eq!(o.status.code(), Some(1), "{env}");
            assert!(has_event(&env, "skipped", reason, encoded), "{env}");
            assert!(!cwd.join("out.vex.json").exists());
        } else {
            assert_eq!(o.status.code(), Some(0), "{env}");
            let doc = read_doc(&cwd.join("out.vex.json"));
            let stmts = doc["statements"].as_array().unwrap();
            assert_eq!(stmts.len(), 1, "{doc:#}");
            assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-go-incompatible");
            assert_eq!(stmts[0]["status"], "not_affected");
            assert_eq!(stmts[0]["products"][0]["subcomponents"][0]["@id"], encoded);
        }
    }
}
