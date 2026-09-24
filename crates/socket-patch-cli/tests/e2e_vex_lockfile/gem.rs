//! Manifest-less VEX for bundler (gem), hermetic and on every OS: the lock
//! shapes each bundler ERA actually writes (captured from the real bundler
//! 1.17.3 → 4.0.21 runs of `e2e_redirect_gem_build` / `e2e_vendor_gem_build`)
//! with NO `.socket/manifest.json` and NO ledgers — the lockfile wiring, the
//! committed `.socket/vendor/` artifact and the patch API are the only
//! evidence — against the attestation contract:
//!
//! * hosted, not installed: attests from the lock alone — from the patched
//!   gem's `CHECKSUMS` pin in the CHECKSUMS era (a pin-less Socket entry
//!   there was not Socket-written, so it does NOT attest), and from the
//!   patch-registry wiring alone before it (bundler < 2.6 never pins);
//! * hosted, installed: the installed tree decides — patched attests,
//!   pristine is `not_applied`, tampered is `hash_mismatch`;
//! * vendored: the committed artifact decides — a tampered member is
//!   `vendor_hash_mismatch` whatever is installed;
//! * a uuid-shaped segment on a non-Socket (or lookalike) host, or a
//!   vendored-looking path outside `.socket/vendor/`, is not a reference:
//!   nothing is discovered and the API is never asked;
//! * an API record naming another package or another patch is
//!   `record_mismatch`; `--offline` is `record_unavailable` with zero
//!   requests.
//!
//! Eras (see the gem extractor's module docs):
//!
//! | flavor | bundler | lock | hosted wiring |
//! |---|---|---|---|
//! | `Merged117` | 1.17 / 2.0 / 2.1 | `Gemfile.lock` | ONE `GEM` section, both remotes; source pin via DEPENDENCIES `!` + Gemfile block |
//! | `MergedGemsRb` | same | `gems.locked` + `gems.rb` | same |
//! | `Separate25` | 2.2 – 2.5 | `Gemfile.lock` | its own `GEM` section, sorted first, no pin |
//! | `Checksums27` | 2.6 / 2.7 | `Gemfile.lock` | own section + `CHECKSUMS` sha256 pin |
//! | `GemsLocked4` | 4.x | `gems.locked` | own section + pin |
//!
//! Vendored wiring is the same `PATH` section in every era (plus a BARE
//! `CHECKSUMS` entry once the lock has the section).
//!
//! The fixture gem (`vexgem`) is made up so no ambient gem home can hold a
//! same-named copy.

use crate::vex_e2e_common;

use std::path::Path;

use serde_json::Value;
use vex_e2e_common::*;

const UUID: &str = "5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b";
const OTHER_UUID: &str = "0d0d0d0d-2222-4222-8222-0d0d0d0d0d0d";
/// Uuid-shaped grant token (production tokens may be); the patch uuid is the
/// LAST uuid segment of the index URL.
const TOKEN: &str = "44444444-5555-4666-8777-888888888888";
const PURL: &str = "pkg:gem/vexgem@2.3.4";
const PRODUCT: &str = "pkg:gem/app@1.0.0";
const GHSA: &str = "GHSA-vexg-gem0-0001";
const CVE: &str = "CVE-2026-8181";
const FILE: &str = "lib/vexgem.rb";
const BEFORE: &[u8] = b"module Vexgem\n  STATUS = \"VULNERABLE\"\nend\n";
const AFTER: &[u8] = b"module Vexgem\n  STATUS = \"PATCHED\"\nend\n";
const TAMPERED: &[u8] = b"module Vexgem\n  STATUS = \"hand-edited\"\nend\n";
const VULNS: &[(&str, &[&str])] = &[(GHSA, &[CVE])];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Era {
    Merged117,
    MergedGemsRb,
    Separate25,
    Checksums27,
    GemsLocked4,
}

const ERAS: [Era; 5] = [
    Era::Merged117,
    Era::MergedGemsRb,
    Era::Separate25,
    Era::Checksums27,
    Era::GemsLocked4,
];

impl Era {
    fn lock(self) -> &'static str {
        match self {
            Era::MergedGemsRb | Era::GemsLocked4 => "gems.locked",
            _ => "Gemfile.lock",
        }
    }

    fn manifest(self) -> &'static str {
        match self {
            Era::MergedGemsRb | Era::GemsLocked4 => "gems.rb",
            _ => "Gemfile",
        }
    }

    fn checksums(self) -> bool {
        matches!(self, Era::Checksums27 | Era::GemsLocked4)
    }

    fn bundled_with(self) -> &'static str {
        match self {
            Era::Merged117 => "1.17.3",
            Era::MergedGemsRb => "2.1.4",
            Era::Separate25 => "2.5.23",
            Era::Checksums27 => "2.7.2",
            Era::GemsLocked4 => "4.0.21",
        }
    }
}

fn index(origin: &str, uuid: &str) -> String {
    format!("{origin}/patch-registry/gem/{TOKEN}/{uuid}/")
}

fn artifact_rel(uuid: &str) -> String {
    format!(".socket/vendor/gem/{uuid}/vexgem-2.3.4")
}

/// Write the hosted Gemfile / lock pair for `era` wiring `vexgem` to the
/// patch-registry index `remote` (`pin`: the `CHECKSUMS` sha256 of the
/// patched `.gem`, CHECKSUMS eras only).
fn write_hosted(dir: &Path, era: Era, remote: &str, pin: bool) {
    let upstream = "https://rubygems.org/";
    let sources = match era {
        Era::Merged117 | Era::MergedGemsRb => format!(
            "GEM\n  remote: {upstream}\n  remote: {remote}\n  specs:\n    rake (13.2.1)\n    \
             vexgem (2.3.4)\n\n"
        ),
        // bundler >= 2.2: one section per source, sorted by remote.
        _ => format!(
            "GEM\n  remote: {remote}\n  specs:\n    vexgem (2.3.4)\n\n\
             GEM\n  remote: {upstream}\n  specs:\n    rake (13.2.1)\n\n"
        ),
    };
    let mut lock =
        format!("{sources}PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake\n  vexgem (= 2.3.4)!\n");
    if era.checksums() {
        let sha = if pin {
            format!(" sha256={}", "e".repeat(64))
        } else {
            String::new()
        };
        lock.push_str(&format!(
            "\nCHECKSUMS\n  rake (13.2.1) sha256={}\n  vexgem (2.3.4){sha}\n",
            "1".repeat(64)
        ));
    }
    lock.push_str(&format!("\nBUNDLED WITH\n   {}\n", era.bundled_with()));
    std::fs::write(dir.join(era.lock()), lock).unwrap();
    std::fs::write(
        dir.join(era.manifest()),
        format!(
            "source \"https://rubygems.org\"\n\ngem \"rake\"\n\nsource \"{remote}\" do\n  \
             gem \"vexgem\", \"2.3.4\"\nend\n"
        ),
    )
    .unwrap();
}

/// The vendored pair (`vendor::gem`'s PATH-section edit) wiring `rel`, plus
/// the committed artifact holding `content`.
fn write_vendored(dir: &Path, era: Era, rel: &str, content: &[u8]) {
    let mut lock = format!(
        "PATH\n  remote: {rel}\n  specs:\n    vexgem (2.3.4)\n\n\
         GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.2.1)\n\n\
         PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake\n  vexgem (= 2.3.4)!\n"
    );
    if era.checksums() {
        lock.push_str(&format!(
            "\nCHECKSUMS\n  rake (13.2.1) sha256={}\n  vexgem (2.3.4)\n",
            "1".repeat(64)
        ));
    }
    lock.push_str(&format!("\nBUNDLED WITH\n   {}\n", era.bundled_with()));
    std::fs::write(dir.join(era.lock()), lock).unwrap();
    std::fs::write(
        dir.join(era.manifest()),
        format!(
            "source \"https://rubygems.org\"\n\ngem \"rake\"\ngem \"vexgem\", \"2.3.4\", path: \
             \"{rel}\"\n"
        ),
    )
    .unwrap();
    let art = dir.join(rel);
    std::fs::create_dir_all(art.join("lib")).unwrap();
    std::fs::write(art.join(FILE), content).unwrap();
    std::fs::write(
        art.join("vexgem.gemspec"),
        "Gem::Specification.new do |s|\n  s.name = \"vexgem\"\n  s.version = \"2.3.4\"\nend\n",
    )
    .unwrap();
}

/// Bundler's deployment layout (`vendor/bundle/ruby/<abi>/gems/…`), the
/// first place the ruby crawler looks.
fn install(dir: &Path, content: &[u8]) {
    let gem = dir.join("vendor/bundle/ruby/3.3.0/gems/vexgem-2.3.4");
    std::fs::create_dir_all(gem.join("lib")).unwrap();
    std::fs::write(gem.join(FILE), content).unwrap();
}

/// The patch view with the REAL before/after hashes (so a pristine install
/// reads as `not_applied`, not as a mismatch).
fn view(uuid: &str, purl: &str) -> Value {
    let mut v = patch_view(uuid, purl, &[(FILE, &git_sha256(AFTER))], VULNS);
    v["files"][FILE]["beforeHash"] = Value::String(git_sha256(BEFORE));
    v
}

fn api() -> PatchApi {
    PatchApi::start(vec![(UUID.into(), view(UUID, PURL))])
}

/// Standalone `vex` against `api`, with the mock's origin configured as a
/// patch server (the hosted fixtures use `origin`).
fn online(api: &PatchApi) -> VexRun {
    VexRun {
        product: Some(PRODUCT.into()),
        patch_server_url: Some(api.uri()),
        ..VexRun::online(api)
    }
}

fn attested(dir: &Path, run: &VexRun, marker: Marker, cell: &str) {
    let out = run_vex(&binary(), dir, run);
    assert_eq!(out.code, Some(0), "{cell}: {out}");
    assert_attested(out.doc(), PURL, UUID, marker, VULNS);
    assert!(
        !dir.join(".socket/manifest.json").exists(),
        "{cell}: vex wrote a manifest"
    );
}

fn omitted(dir: &Path, run: &VexRun, reason: &str, cell: &str) -> VexOutcome {
    let out = run_vex(&binary(), dir, run);
    assert_eq!(out.code, Some(1), "{cell}: {out}");
    assert_not_attested(&out.envelope, PURL, reason);
    assert_absent(out.doc.as_ref(), PURL);
    out
}

// ── hosted ────────────────────────────────────────────────────────────

/// Not installed: the lock alone. CHECKSUMS eras need the patched gem's pin
/// (the rewriter always writes it there); earlier eras never pin, so the
/// patch-registry wiring is the whole basis.
#[test]
fn hosted_not_installed_attests_from_the_era_lock() {
    for era in ERAS {
        let api = api();
        let tmp = tempfile::tempdir().unwrap();
        write_hosted(tmp.path(), era, &index(&api.uri(), UUID), true);
        attested(
            tmp.path(),
            &online(&api),
            Marker::Redirected,
            &format!("{era:?}"),
        );
        assert!(
            api.view_requests(UUID) >= 1,
            "{era:?}: {:?}",
            api.requests()
        );

        if era.checksums() {
            let tmp = tempfile::tempdir().unwrap();
            write_hosted(tmp.path(), era, &index(&api.uri(), UUID), false);
            omitted(
                tmp.path(),
                &online(&api),
                "package_not_found",
                &format!("{era:?} pin-less"),
            );
        }
    }
}

#[test]
fn hosted_installed_tree_decides() {
    for era in ERAS {
        let api = api();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write_hosted(dir, era, &index(&api.uri(), UUID), true);
        install(dir, AFTER);
        attested(
            dir,
            &online(&api),
            Marker::Redirected,
            &format!("{era:?} patched"),
        );
        install(dir, BEFORE);
        omitted(
            dir,
            &online(&api),
            "not_applied",
            &format!("{era:?} pristine"),
        );
        install(dir, TAMPERED);
        omitted(
            dir,
            &online(&api),
            "hash_mismatch",
            &format!("{era:?} tampered"),
        );
    }
}

#[test]
fn hosted_offline_without_a_ledger_is_record_unavailable_and_silent() {
    for era in ERAS {
        let api = api();
        let tmp = tempfile::tempdir().unwrap();
        write_hosted(tmp.path(), era, &index(&api.uri(), UUID), true);
        let run = VexRun {
            offline: true,
            ..online(&api)
        };
        omitted(
            tmp.path(),
            &run,
            "record_unavailable",
            &format!("{era:?} offline"),
        );
        api.assert_no_requests();
    }
}

/// A uuid-shaped segment on a host that is not the Socket patch server (nor
/// the configured origin) — including a lookalike — is not a reference.
#[test]
fn hosted_spoofed_hosts_are_not_references() {
    for era in ERAS {
        for host in [
            "https://gems.evil.example",
            "https://patch.socket.dev.evil.example",
            "https://evil.example/https://patch.socket.dev",
        ] {
            let api = api();
            let tmp = tempfile::tempdir().unwrap();
            write_hosted(tmp.path(), era, &index(host, UUID), true);
            let out = run_vex(&binary(), tmp.path(), &online(&api));
            let cell = format!("{era:?} {host}");
            assert_eq!(out.code, Some(2), "{cell}: {out}");
            assert_eq!(
                out.envelope["error"]["code"], "manifest_not_found",
                "{cell}: {out}"
            );
            assert_absent(out.doc.as_ref(), PURL);
            api.assert_no_requests();
        }
    }
}

#[test]
fn hosted_record_for_another_package_or_patch_is_a_mismatch() {
    for era in ERAS {
        for (label, body) in [
            ("other package", view(UUID, "pkg:gem/othergem@9.9.9")),
            ("other patch", view(OTHER_UUID, PURL)),
        ] {
            let api = PatchApi::start(vec![(UUID.into(), body)]);
            let tmp = tempfile::tempdir().unwrap();
            write_hosted(tmp.path(), era, &index(&api.uri(), UUID), true);
            omitted(
                tmp.path(),
                &online(&api),
                "record_mismatch",
                &format!("{era:?} {label}"),
            );
        }
    }
}

// ── vendored ──────────────────────────────────────────────────────────

#[test]
fn vendored_artifact_decides() {
    for era in ERAS {
        let api = api();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write_vendored(dir, era, &artifact_rel(UUID), AFTER);
        // A stale pristine install does not un-attest a verifying artifact.
        install(dir, BEFORE);
        attested(dir, &online(&api), Marker::Vendored, &format!("{era:?}"));
        std::fs::write(dir.join(artifact_rel(UUID)).join(FILE), TAMPERED).unwrap();
        omitted(
            dir,
            &online(&api),
            "vendor_hash_mismatch",
            &format!("{era:?} tampered artifact"),
        );
    }
}

#[test]
fn vendored_offline_and_mismatch() {
    for era in ERAS {
        let api = api();
        let tmp = tempfile::tempdir().unwrap();
        write_vendored(tmp.path(), era, &artifact_rel(UUID), AFTER);
        let run = VexRun {
            offline: true,
            ..online(&api)
        };
        omitted(tmp.path(), &run, "record_unavailable", &format!("{era:?}"));
        api.assert_no_requests();

        let api = PatchApi::start(vec![(UUID.into(), view(UUID, "pkg:gem/othergem@9.9.9"))]);
        omitted(
            tmp.path(),
            &online(&api),
            "record_mismatch",
            &format!("{era:?} other package"),
        );
    }
}

/// A vendored-looking path outside the project's `.socket/vendor/gem/` is
/// not a reference (and never fetches the uuid's record).
#[test]
fn vendored_spoofed_paths_are_not_references() {
    for era in ERAS {
        for rel in [
            format!("../.socket/vendor/gem/{UUID}/vexgem-2.3.4"),
            format!("vendor/.socket-vendor/gem/{UUID}/vexgem-2.3.4"),
            format!("gems/{UUID}/vexgem-2.3.4"),
        ] {
            let api = api();
            let tmp = tempfile::tempdir().unwrap();
            let proj = tmp.path().join("proj");
            std::fs::create_dir_all(&proj).unwrap();
            // The artifact exists (so only the location is wrong).
            let target = proj.join(&rel);
            std::fs::create_dir_all(target.join("lib")).unwrap();
            std::fs::write(target.join(FILE), AFTER).unwrap();
            write_vendored(&proj, era, &rel, AFTER);
            let out = run_vex(&binary(), &proj, &online(&api));
            let cell = format!("{era:?} {rel}");
            assert_ne!(out.code, Some(0), "{cell}: {out}");
            assert_absent(out.doc.as_ref(), PURL);
            api.assert_no_requests();
        }
    }
}

// ── embedded ──────────────────────────────────────────────────────────

/// The embedded `apply --vex` / `vendor --vex` of a manifest-less checkout
/// attest exactly what standalone `vex` does, in every era.
#[test]
fn embedded_vex_agrees_in_every_era() {
    for era in ERAS {
        for (mode, marker) in [
            ("hosted", Marker::Redirected),
            ("vendored", Marker::Vendored),
        ] {
            for via in [VexVia::Apply, VexVia::Vendor] {
                let api = api();
                let tmp = tempfile::tempdir().unwrap();
                let dir = tmp.path();
                if mode == "hosted" {
                    write_hosted(dir, era, &index(&api.uri(), UUID), true);
                    install(dir, AFTER);
                } else {
                    write_vendored(dir, era, &artifact_rel(UUID), AFTER);
                }
                let out = run_vex(&binary(), dir, &online(&api).via(via));
                let cell = format!("{era:?} {mode} {via:?}");
                assert_eq!(out.code, Some(0), "{cell}: {out}");
                assert_eq!(out.envelope["status"], "noManifest", "{cell}: {out}");
                assert_eq!(out.envelope["vex"]["statements"], 1, "{cell}: {out}");
                assert_attested(out.doc(), PURL, UUID, marker, VULNS);
            }
        }
    }
}
