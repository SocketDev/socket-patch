//! Embedded `--vex` on a checkout with NO `.socket/manifest.json`.
//!
//! Hosted (`scan --mode hosted`) and vendored (`scan --mode vendored`,
//! depscan) checkouts carry their patches in the lockfiles and
//! `.socket/vendor`, not the manifest. `apply --vex` / `vendor --vex` used
//! to take the no-manifest early return and exit 0 WITHOUT a
//! document — a silently missed attestation (and a previous run's document
//! left at the path). Contract pinned here, for both commands:
//!
//! - wiring found and attestable => the document is written, exit 0, the
//!   `--json` envelope keeps `status: noManifest` and carries the `vex`
//!   summary;
//! - nothing referenced anywhere => the historical calm exit 0, no `vex`
//!   key, no error, and a stale OpenVEX document at the path is removed;
//!   discovery diagnostics still reach `warnings[]`;
//! - any other VEX failure => non-zero, `error.code` in the envelope, the
//!   stale document removed (the with-manifest fail-the-command contract);
//! - `--dry-run` => no generation, no document, no network;
//! - `apply --check` => no generation, the output path untouched, no
//!   network (read-only, like the with-manifest `--check`).

use crate::vex_e2e_common;

use vex_e2e_common::*;

const UUID: &str = "3c1e9a52-7b4d-4e8f-9a0b-1c2d3e4f5a6b";
const GHSA: &str = "GHSA-mfls-embd-0001";
const CVE: &str = "CVE-2026-5151";

const EMBEDDED: [VexVia; 2] = [VexVia::Apply, VexVia::Vendor];

fn api() -> PatchApi {
    PatchApi::start(vec![(
        UUID.to_string(),
        patch_view(
            UUID,
            "pkg:npm/left-pad@1.3.0",
            &[("package/index.js", &git_sha256(b"patched\n"))],
            &[(GHSA, &[CVE])],
        ),
    )])
}

/// A previous run's OpenVEX document at the default output path.
fn write_stale_doc(project: &std::path::Path) {
    std::fs::write(
        project.join(DEFAULT_OUTPUT),
        serde_json::json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [{ "vulnerability": { "name": "GHSA-stale" } }]
        })
        .to_string(),
    )
    .unwrap();
}

#[test]
fn manifest_less_embedded_vex_attests_hosted_wiring() {
    for via in EMBEDDED {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path();
        let purl = write_hosted_npm_lock(p, "left-pad", "1.3.0", UUID);
        let api = api();
        let out = run_vex(&binary(), p, &VexRun::online(&api).via(via));
        assert_eq!(out.code, Some(0), "{via:?}: {out}");
        assert_eq!(out.envelope["status"], "noManifest", "{via:?}: {out}");
        assert!(out.envelope.get("error").is_none(), "{via:?}: {out}");
        let vex = &out.envelope["vex"];
        assert_eq!(vex["statements"], 1, "{via:?}: {out}");
        assert_eq!(vex["format"], "openvex-0.2.0");
        assert_eq!(vex["path"], out.output.display().to_string());
        assert_attested(
            out.doc(),
            &purl,
            UUID,
            Marker::Redirected,
            &[(GHSA, &[CVE])],
        );
        assert!(api.view_requests(UUID) >= 1, "{:?}", api.requests());
        assert!(
            !p.join(".socket/manifest.json").exists(),
            "never writes one"
        );

        // Human mode: both the calm no-manifest line and the VEX line.
        std::fs::remove_file(&out.output).unwrap();
        let human = VexRun {
            human: true,
            ..VexRun::online(&api).via(via)
        };
        let out = run_vex(&binary(), p, &human);
        assert_eq!(out.code, Some(0), "{via:?}: {out}");
        let calm = match via {
            VexVia::Apply => "No patch manifest found; nothing to apply.",
            _ => "No manifest found, nothing to vendor.",
        };
        assert!(out.stdout.contains(calm), "{via:?}: {out}");
        assert!(
            out.stdout
                .contains("Wrote OpenVEX document with 1 statement to"),
            "{out}"
        );
        out.doc();
    }
}

#[test]
fn nothing_discovered_keeps_calm_exit_and_removes_stale_doc() {
    for via in EMBEDDED {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path();
        write_stale_doc(p);
        let api = PatchApi::empty();
        let out = run_vex(&binary(), p, &VexRun::online(&api).via(via));
        assert_eq!(out.code, Some(0), "{via:?}: {out}");
        assert_eq!(out.envelope["status"], "noManifest", "{via:?}: {out}");
        assert!(out.envelope.get("vex").is_none(), "{via:?}: {out}");
        assert!(out.envelope.get("error").is_none(), "{via:?}: {out}");
        assert!(out.doc.is_none(), "stale document must be removed: {out}");
        api.assert_no_requests();

        // Human + --silent: still calm, still quiet.
        write_stale_doc(p);
        let silent = VexRun {
            human: true,
            ..VexRun::online(&api).via(via).arg("--silent")
        };
        let out = run_vex(&binary(), p, &silent);
        assert_eq!(out.code, Some(0), "{via:?}: {out}");
        assert!(out.stdout.is_empty(), "{via:?}: {out}");
        assert!(!out.stderr.contains("Error"), "{via:?}: {out}");
        assert!(out.doc.is_none(), "{out}");
    }
}

/// An unparseable lockfile may be WHY nothing was found: the diagnostic
/// rides the calm envelope's `warnings[]` (stderr is silenced by --json).
#[test]
fn nothing_discovered_still_reports_discovery_diagnostics() {
    for via in EMBEDDED {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path();
        std::fs::write(p.join("package-lock.json"), "{ not json").unwrap();
        let out = run_vex(&binary(), p, &VexRun::offline().via(via));
        assert_eq!(out.code, Some(0), "{via:?}: {out}");
        assert_eq!(out.envelope["status"], "noManifest", "{via:?}: {out}");
        let codes: Vec<&str> = out.envelope["warnings"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|w| w["code"].as_str())
            .collect();
        assert!(codes.contains(&"lockfile_unparseable"), "{via:?}: {out}");
    }
}

#[test]
fn vex_failure_without_manifest_fails_the_command() {
    for via in EMBEDDED {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path();
        write_hosted_npm_lock(p, "left-pad", "1.3.0", UUID);
        write_stale_doc(p);
        let api = api();
        // Offline: the wiring is found, but no record is available.
        let out = run_vex(&binary(), p, &VexRun::offline().via(via));
        assert_eq!(out.code, Some(1), "{via:?}: {out}");
        assert_eq!(out.envelope["status"], "error", "{via:?}: {out}");
        assert_eq!(
            out.envelope["error"]["code"], "no_applicable_patches",
            "{via:?}: {out}"
        );
        assert!(out.envelope.get("vex").is_none(), "{via:?}: {out}");
        assert!(out.doc.is_none(), "stale document must be removed: {out}");
        api.assert_no_requests();

        // Human mode: the error prints even under --silent.
        let silent = VexRun {
            human: true,
            ..VexRun::offline().via(via).arg("--silent")
        };
        let out = run_vex(&binary(), p, &silent);
        assert_eq!(out.code, Some(1), "{via:?}: {out}");
        assert!(out.stdout.is_empty(), "{via:?}: {out}");
        assert!(
            out.stderr.contains("Error: VEX generation failed"),
            "{via:?}: {out}"
        );
    }
}

/// REGRESSION: `apply --check` is read-only, lock-free and offline-safe (it
/// never crawls, fetches or writes), and with a manifest it returns before
/// any VEX work. Manifest-less, `--vex` (or an ambient `SOCKET_VEX`) used to
/// run full generation first — crawling, fetching patch views, rewriting
/// the output path and flipping the exit to 1. It now keeps the calm
/// `noManifest` exit 0 and touches nothing.
#[test]
fn check_skips_manifest_less_vex() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    write_hosted_npm_lock(p, "left-pad", "1.3.0", UUID);
    let api = api();
    for (label, run) in [
        (
            "--vex",
            VexRun::online(&api).via(VexVia::Apply).arg("--check"),
        ),
        (
            "--vex, offline (would fail generation)",
            VexRun {
                offline: true,
                ..VexRun::online(&api).via(VexVia::Apply).arg("--check")
            },
        ),
    ] {
        write_stale_doc(p);
        let before = std::fs::read(p.join(DEFAULT_OUTPUT)).unwrap();
        let out = run_vex(&binary(), p, &run);
        assert_eq!(out.code, Some(0), "{label}: {out}");
        assert_eq!(out.envelope["status"], "noManifest", "{label}: {out}");
        assert!(out.envelope.get("vex").is_none(), "{label}: {out}");
        assert!(out.envelope.get("error").is_none(), "{label}: {out}");
        assert_eq!(
            std::fs::read(p.join(DEFAULT_OUTPUT)).unwrap(),
            before,
            "{label}: --check must not touch the output path"
        );
        api.assert_no_requests();
    }
}

#[test]
fn dry_run_skips_manifest_less_vex() {
    for via in EMBEDDED {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path();
        write_hosted_npm_lock(p, "left-pad", "1.3.0", UUID);
        let api = api();
        let run = VexRun {
            dry_run: true,
            ..VexRun::online(&api).via(via)
        };
        let out = run_vex(&binary(), p, &run);
        assert_eq!(out.code, Some(0), "{via:?}: {out}");
        assert_eq!(out.envelope["status"], "noManifest", "{via:?}: {out}");
        assert_eq!(out.envelope["dryRun"], true, "{via:?}: {out}");
        assert!(out.envelope.get("vex").is_none(), "{via:?}: {out}");
        assert!(out.doc.is_none(), "{out}");
        api.assert_no_requests();

        let human = VexRun { human: true, ..run };
        let out = run_vex(&binary(), p, &human);
        assert_eq!(out.code, Some(0), "{via:?}: {out}");
        // The shared embedded-VEX dry-run line (`vex::format_vex_dry_run_skip`).
        let done = if via == VexVia::Vendor {
            "vendored"
        } else {
            "applied"
        };
        assert!(
            out.stdout
                .lines()
                .any(|l| l == format!("Skipping VEX generation (--dry-run: nothing was {done}).")),
            "{out}"
        );
        assert!(out.doc.is_none(), "{out}");
        api.assert_no_requests();
    }
}
