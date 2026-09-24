//! Hermetic manifest-less VEX cells for every npm lock SHAPE the npm majors
//! commit — no npm binary, runs on every OS in the standard test job.
//!
//! The real-npm capstones (`e2e_redirect_npm_build`, `e2e_vendor_npm_build`,
//! driven per major by the npm compatibility matrix) prove the happy path
//! end to end. This suite pins the adversarial cells on each shape a
//! checkout can carry, with NO `.socket/manifest.json` and NO ledgers — the
//! lockfile wiring plus a mock patch API are the only inputs:
//!
//! | shape            | written by                                   |
//! |------------------|----------------------------------------------|
//! | `v1`             | npm 6 (`dependencies` tree only)             |
//! | `v2`             | npm 7 / 8 (`packages` + legacy mirror)       |
//! | `v3`             | npm 9 – 12                                   |
//! | `shrinkwrap`     | `npm shrinkwrap` (npm <= 11), v3 content     |
//! | `dual`           | npm 12 shrinkwrap repo: both locks, identical |
//!
//! Cells: hosted not-installed attests from the integrity pin; hosted
//! installed + patched attests (hash-verified); hosted installed pristine /
//! tampered is omitted (`hash_mismatch` — installed evidence wins over the
//! pin); a uuid-shaped segment on a NON-Socket host is nothing at all (no
//! ref, zero API requests); a record naming another package or another
//! uuid is `record_mismatch`; a vendored artifact attests, and a tampered
//! member is `vendor_hash_mismatch`; and the npm 12 dual-lock hazard — one
//! lock wired, the other still on the registry — attests nothing.

use crate::vex_e2e_common;

use std::path::Path;

use serde_json::{json, Value};
use vex_e2e_common::*;

const NAME: &str = "left-pad";
const VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const UUID: &str = "3f2a1b0c-9d8e-4f7a-8b6c-5d4e3f2a1b0c";
const OTHER_UUID: &str = "4a3b2c1d-0e9f-4a8b-9c7d-6e5f4a3b2c1d";
const TOKEN: &str = "11111111-2222-4333-8444-555555555555";
const GHSA: &str = "GHSA-lock-npm-shape";
const CVE: &str = "CVE-2026-4242";
const PIN: &str = "sha512-UEFUQ0hFRHBhdGNoZWRQQVRDSEVEcGF0Y2hlZA==";
const REGISTRY_SRI: &str = "sha512-UkVHSVNUUllyZWdpc3RyeVJFR0lTVFJZ";
const PATCHED: &[u8] = b"/* SOCKET-PATCHED */\nmodule.exports = leftPad;\n";
const PRISTINE: &[u8] = b"module.exports = leftPad;\n";

#[derive(Clone, Copy, Debug)]
enum Shape {
    V1,
    V2,
    V3,
    Shrinkwrap,
    Dual,
}

const SHAPES: [Shape; 5] = [
    Shape::V1,
    Shape::V2,
    Shape::V3,
    Shape::Shrinkwrap,
    Shape::Dual,
];

fn hosted_url(host: &str, uuid: &str) -> String {
    format!("https://{host}/patch/npm/{NAME}/{VERSION}/{TOKEN}/{uuid}/{NAME}-{VERSION}.tgz")
}

fn vendored_rel(uuid: &str) -> String {
    format!(".socket/vendor/npm/{uuid}/{NAME}-{VERSION}.tgz")
}

/// The lock document for `shape` with `left-pad` resolving to `resolved`.
fn lock_doc(shape: Shape, resolved: &str, integrity: &str) -> Value {
    let entry = json!({ "version": VERSION, "resolved": resolved, "integrity": integrity });
    let root = json!({ "name": "app", "version": "1.0.0", "dependencies": { NAME: "^1.3.0" } });
    match shape {
        Shape::V1 => json!({
            "name": "app", "version": "1.0.0", "lockfileVersion": 1, "requires": true,
            "dependencies": { NAME: entry },
        }),
        Shape::V2 => json!({
            "name": "app", "version": "1.0.0", "lockfileVersion": 2, "requires": true,
            "packages": { "": root, format!("node_modules/{NAME}"): entry.clone() },
            "dependencies": { NAME: entry },
        }),
        Shape::V3 | Shape::Shrinkwrap | Shape::Dual => json!({
            "name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
            "packages": { "": root, format!("node_modules/{NAME}"): entry },
        }),
    }
}

/// Commit `shape`'s lock file(s) wiring left-pad to `resolved`.
fn write_locks(project: &Path, shape: Shape, resolved: &str, integrity: &str) {
    let doc = serde_json::to_string_pretty(&lock_doc(shape, resolved, integrity)).unwrap();
    std::fs::write(
        project.join("package.json"),
        r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}"#,
    )
    .unwrap();
    let files: &[&str] = match shape {
        Shape::Shrinkwrap => &["npm-shrinkwrap.json"],
        Shape::Dual => &["npm-shrinkwrap.json", "package-lock.json"],
        _ => &["package-lock.json"],
    };
    for f in files {
        std::fs::write(project.join(f), &doc).unwrap();
    }
}

fn install(project: &Path, index_js: &[u8]) {
    let dir = project.join("node_modules").join(NAME);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        format!(r#"{{"name":"{NAME}","version":"{VERSION}"}}"#),
    )
    .unwrap();
    std::fs::write(dir.join("index.js"), index_js).unwrap();
}

/// A deterministic single-member npm artifact (`package/index.js`).
fn write_artifact(project: &Path, uuid: &str, index_js: &[u8]) {
    let dest = project.join(vendored_rel(uuid));
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    let mut out = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut out, flate2::Compression::new(6));
        let mut builder = tar::Builder::new(enc);
        for (member, bytes) in [
            (
                "package/package.json",
                format!(r#"{{"name":"{NAME}","version":"{VERSION}"}}"#).into_bytes(),
            ),
            ("package/index.js", index_js.to_vec()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, member, &bytes[..])
                .unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
    }
    std::fs::write(dest, out).unwrap();
}

fn api_for(uuid: &str, purl: &str) -> PatchApi {
    PatchApi::start(vec![(
        uuid.to_string(),
        patch_view(
            uuid,
            purl,
            &[("package/index.js", &git_sha256(PATCHED))],
            &[(GHSA, &[CVE])],
        ),
    )])
}

fn assert_no_manifest_or_ledgers(p: &Path) {
    for rel in [
        ".socket/manifest.json",
        ".socket/vendor/state.json",
        ".socket/vendor/redirect-state.json",
    ] {
        assert!(!p.join(rel).exists(), "{rel} must not exist");
    }
}

/// Hosted, nothing installed: every shape attests `(redirected)` from the
/// patched sha512 pin (the in-run `scan --mode hosted --vex` basis) with
/// the API's record; `--offline` is `record_unavailable` with zero requests.
#[test]
fn hosted_uninstalled_attests_from_the_integrity_pin_in_every_shape() {
    let api = api_for(UUID, PURL);
    for shape in SHAPES {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path();
        write_locks(p, shape, &hosted_url("patch.socket.dev", UUID), PIN);
        assert_no_manifest_or_ledgers(p);

        let before = api.request_count();
        let out = run_vex(&binary(), p, &VexRun::offline());
        assert_eq!(out.code, Some(1), "{shape:?} offline:\n{out}");
        assert_not_attested(&out.envelope, PURL, "record_unavailable");
        assert_eq!(
            api.request_count(),
            before,
            "{shape:?}: --offline made requests"
        );

        let out = run_vex(&binary(), p, &VexRun::online(&api));
        assert_eq!(out.code, Some(0), "{shape:?}:\n{out}");
        assert_attested(out.doc(), PURL, UUID, Marker::Redirected, &[(GHSA, &[CVE])]);
    }
}

/// Hosted, installed: the patched tree attests (hash-verified); a PRISTINE
/// or TAMPERED installed tree is omitted `hash_mismatch` even though the
/// lockfile pin is intact — installed evidence wins.
#[test]
fn hosted_installed_tree_is_the_evidence_in_every_shape() {
    let api = api_for(UUID, PURL);
    for shape in SHAPES {
        for (label, bytes, attested) in [
            ("patched", PATCHED, true),
            ("pristine", PRISTINE, false),
            ("tampered", &b"module.exports = evil;\n"[..], false),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let p = tmp.path();
            write_locks(p, shape, &hosted_url("patch.socket.dev", UUID), PIN);
            install(p, bytes);
            let out = run_vex(&binary(), p, &VexRun::online(&api));
            if attested {
                assert_eq!(out.code, Some(0), "{shape:?} {label}:\n{out}");
                assert_attested(out.doc(), PURL, UUID, Marker::Redirected, &[(GHSA, &[CVE])]);
            } else {
                assert_eq!(out.code, Some(1), "{shape:?} {label}:\n{out}");
                assert_not_attested(&out.envelope, PURL, "hash_mismatch");
                assert_absent(out.doc.as_ref(), PURL);
            }
        }
    }
}

/// A uuid-shaped segment on a host that is not a Socket patch server is not
/// a patch reference: nothing is discovered (`manifest_not_found`), the API
/// is never asked, and `--no-verify` changes nothing.
#[test]
fn spoofed_non_socket_host_with_a_uuid_segment_is_nothing() {
    let api = api_for(UUID, PURL);
    for shape in SHAPES {
        for no_verify in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let p = tmp.path();
            write_locks(
                p,
                shape,
                &hosted_url("patch.socket.dev.evil.example", UUID),
                PIN,
            );
            install(p, PATCHED);
            let mut run = VexRun::online(&api);
            run.no_verify = no_verify;
            let out = run_vex(&binary(), p, &run);
            assert_eq!(out.code, Some(2), "{shape:?}:\n{out}");
            assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");
            assert_absent(out.doc.as_ref(), PURL);
        }
    }
    api.assert_no_requests();
}

/// The API's record for the wired uuid names ANOTHER package, or carries
/// another uuid: `record_mismatch`, never attested — a hand-edited lock
/// cannot borrow another patch's record. Hosted and vendored.
#[test]
fn record_purl_or_uuid_mismatch_is_record_mismatch() {
    let wrong_purl = PatchApi::start(vec![(
        UUID.to_string(),
        patch_view(
            UUID,
            "pkg:npm/minimist@1.2.5",
            &[("package/index.js", &git_sha256(PATCHED))],
            &[(GHSA, &[CVE])],
        ),
    )]);
    let wrong_uuid = PatchApi::start(vec![(
        UUID.to_string(),
        patch_view(
            OTHER_UUID,
            PURL,
            &[("package/index.js", &git_sha256(PATCHED))],
            &[(GHSA, &[CVE])],
        ),
    )]);
    for shape in [Shape::V1, Shape::V3, Shape::Dual] {
        for api in [&wrong_purl, &wrong_uuid] {
            let tmp = tempfile::tempdir().unwrap();
            let p = tmp.path();
            write_locks(p, shape, &hosted_url("patch.socket.dev", UUID), PIN);
            let out = run_vex(&binary(), p, &VexRun::online(api));
            assert_eq!(out.code, Some(1), "{shape:?} hosted:\n{out}");
            assert_not_attested(&out.envelope, PURL, "record_mismatch");

            if matches!(shape, Shape::V1) {
                continue; // vendoring refuses v1 locks; no vendored v1 shape exists
            }
            let tmp = tempfile::tempdir().unwrap();
            let p = tmp.path();
            write_locks(p, shape, &format!("file:{}", vendored_rel(UUID)), PIN);
            write_artifact(p, UUID, PATCHED);
            let out = run_vex(&binary(), p, &VexRun::online(api));
            assert_eq!(out.code, Some(1), "{shape:?} vendored:\n{out}");
            assert_not_attested(&out.envelope, PURL, "record_mismatch");
        }
    }
}

/// Vendored (v2 / v3 / shrinkwrap / dual — vendoring refuses v1): the
/// committed artifact is the evidence, nothing need be installed; a tampered
/// artifact MEMBER is `vendor_hash_mismatch` even with a patched install.
#[test]
fn vendored_artifact_is_the_evidence_and_a_tampered_member_is_omitted() {
    let api = api_for(UUID, PURL);
    for shape in [Shape::V2, Shape::V3, Shape::Shrinkwrap, Shape::Dual] {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path();
        write_locks(p, shape, &format!("file:{}", vendored_rel(UUID)), PIN);
        write_artifact(p, UUID, PATCHED);
        assert_no_manifest_or_ledgers(p);
        let out = run_vex(&binary(), p, &VexRun::online(&api));
        assert_eq!(out.code, Some(0), "{shape:?}:\n{out}");
        assert_attested(out.doc(), PURL, UUID, Marker::Vendored, &[(GHSA, &[CVE])]);

        write_artifact(p, UUID, b"/* tampered */\n");
        install(p, PATCHED);
        let out = run_vex(&binary(), p, &VexRun::online(&api));
        assert_eq!(out.code, Some(1), "{shape:?} tampered:\n{out}");
        assert_not_attested(&out.envelope, PURL, "vendor_hash_mismatch");
        assert_absent(out.doc.as_ref(), PURL);
    }
}

/// REGRESSION (npm 12 dual-lock): npm <= 11 installs from the shrinkwrap,
/// npm 12 from the package-lock.json beside it. One lock wired to a Socket
/// patch while the other still resolves the package from the registry is
/// patched under some majors only — nothing attests (hosted or vendored, in
/// either direction, `--no-verify` too), and the run says why.
#[test]
fn dual_lock_with_one_lock_on_the_registry_attests_nothing() {
    let api = api_for(UUID, PURL);
    let registry = format!("https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz");
    for wired in [
        hosted_url("patch.socket.dev", UUID),
        format!("file:{}", vendored_rel(UUID)),
    ] {
        for wired_file in ["npm-shrinkwrap.json", "package-lock.json"] {
            for no_verify in [false, true] {
                let tmp = tempfile::tempdir().unwrap();
                let p = tmp.path();
                write_locks(p, Shape::Dual, &registry, REGISTRY_SRI);
                let doc = lock_doc(Shape::Dual, &wired, PIN);
                std::fs::write(p.join(wired_file), doc.to_string()).unwrap();
                write_artifact(p, UUID, PATCHED);
                let mut run = VexRun::online(&api);
                run.no_verify = no_verify;
                let out = run_vex(&binary(), p, &run);
                assert_ne!(out.code, Some(0), "{wired_file} {wired}:\n{out}");
                assert_absent(out.doc.as_ref(), PURL);
                let text = out.stdout.clone() + &out.stderr;
                assert!(
                    text.contains("patched_ref_unattributable") && text.contains("npm >= 12"),
                    "the contested wiring must be explained:\n{out}"
                );
            }
        }
    }
}

/// Standalone `vex` over a manifest-less checkout honors the output
/// conventions every `vex` run does: `-O -` prints the document to stdout
/// (never a file named `-`) with the summary on stderr, and `--dry-run`
/// builds and verifies — fetching the record, attesting from the pin — but
/// writes nothing and leaves a previous document at the path alone, saying
/// what it would have written (`dryRun: true` under `--json`).
#[test]
fn standalone_vex_dry_run_and_stdout_output_work_without_a_manifest() {
    let api = api_for(UUID, PURL);
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    write_locks(p, Shape::V3, &hosted_url("patch.socket.dev", UUID), PIN);
    assert_no_manifest_or_ledgers(p);

    // `-O -`: the document is stdout.
    let mut cmd = std::process::Command::new(binary());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(key);
        }
    }
    let out = cmd
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("SOCKET_NO_API_TOKEN", "1")
        .current_dir(p)
        .args(["vex", "--cwd"])
        .arg(p)
        .args(["-O", "-", "--product", DEFAULT_PRODUCT, "--proxy-url"])
        .arg(api.uri())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let doc: Value = serde_json::from_str(&stdout).expect("the document is stdout");
    assert_attested(&doc, PURL, UUID, Marker::Redirected, &[(GHSA, &[CVE])]);
    assert!(stderr.contains("Emitted 1 VEX statement"), "{stderr}");
    assert!(
        !p.join("-").exists(),
        "`-O -` is stdout, not a file named `-`"
    );

    // `--dry-run` (human): nothing written, the stale document kept.
    let stale = r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}"#;
    std::fs::write(p.join(DEFAULT_OUTPUT), stale).unwrap();
    let run = VexRun {
        dry_run: true,
        human: true,
        ..VexRun::online(&api)
    };
    let out = run_vex(&binary(), p, &run);
    assert_eq!(out.code, Some(0), "{out}");
    assert_eq!(
        out.stdout.trim_end(),
        format!(
            "[dry-run] Would write OpenVEX document with 1 statement to {}",
            p.join(DEFAULT_OUTPUT).display()
        ),
        "{out}"
    );
    assert_eq!(
        std::fs::read_to_string(p.join(DEFAULT_OUTPUT)).unwrap(),
        stale
    );

    // `--dry-run --json`: the envelope says so and still verifies.
    let run = VexRun {
        dry_run: true,
        ..VexRun::online(&api)
    };
    let out = run_vex(&binary(), p, &run);
    assert_eq!(out.code, Some(0), "{out}");
    assert_eq!(out.envelope["dryRun"], true, "{out}");
    assert!(
        out.envelope["events"]
            .as_array()
            .is_some_and(|events| events
                .iter()
                .any(|e| e["action"] == "verified" && e["purl"] == PURL)),
        "{out}"
    );
    assert_eq!(
        std::fs::read_to_string(p.join(DEFAULT_OUTPUT)).unwrap(),
        stale
    );
    assert_no_manifest_or_ledgers(p);
}

/// The `(code, detail)` of every `warnings[]` entry of `envelope`.
fn warnings_of(envelope: &Value) -> Vec<(String, String)> {
    envelope["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|w| {
            (
                w["code"].as_str().unwrap_or_default().to_string(),
                w["detail"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// `--json` keeps WHY a patch was gated (it used to reach only human
/// stderr as `Note:` lines, leaving the envelope with a bare
/// `record_unavailable` / `wiring_conflict`): the record-fetch error and
/// the wiring conflict's files ride `warnings[]`, standalone and embedded,
/// and a failed embedded `--vex` lists each omitted patch as `vex_omitted`
/// (`--silent`: `omitted:` lines under the error).
#[test]
fn json_envelopes_carry_why_a_patch_was_gated() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    write_locks(p, Shape::V3, &hosted_url("patch.socket.dev", UUID), PIN);
    let unreachable = VexRun {
        proxy_url: Some("http://127.0.0.1:1".to_string()),
        ..VexRun::default()
    };
    let out = run_vex(&binary(), p, &unreachable);
    assert_eq!(out.code, Some(1), "{out}");
    assert_not_attested(&out.envelope, PURL, "record_unavailable");
    assert!(
        warnings_of(&out.envelope)
            .iter()
            .any(|(code, detail)| code == "vex_record_fetch_failed"
                && detail.contains(&format!("Could not fetch patch {UUID}"))),
        "{out}"
    );

    for via in [VexVia::Apply, VexVia::Vendor] {
        let out = run_vex(&binary(), p, &unreachable.clone().via(via));
        assert_eq!(out.code, Some(1), "{via:?}:\n{out}");
        let warnings = warnings_of(&out.envelope);
        assert!(
            warnings
                .iter()
                .any(|(code, _)| code == "vex_record_fetch_failed"),
            "{via:?}:\n{out}"
        );
        assert!(
            warnings.iter().any(|(code, detail)| code == "vex_omitted"
                && detail.starts_with(&format!("{PURL}: "))
                && detail.ends_with("(record_unavailable)")),
            "{via:?}:\n{out}"
        );
        let silent = VexRun {
            human: true,
            ..unreachable.clone().via(via).arg("--silent")
        };
        let out = run_vex(&binary(), p, &silent);
        assert_eq!(out.code, Some(1), "{via:?} --silent:\n{out}");
        assert!(
            out.stderr.contains("Error: VEX generation failed")
                && out
                    .stderr
                    .contains(&format!("  omitted: {PURL} (record_unavailable)")),
            "{via:?} --silent:\n{out}"
        );
    }

    // Two locks wiring different patches: the conflict names both files.
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    write_locks(p, Shape::Dual, &hosted_url("patch.socket.dev", UUID), PIN);
    let other = lock_doc(
        Shape::Dual,
        &hosted_url("patch.socket.dev", OTHER_UUID),
        PIN,
    );
    std::fs::write(p.join("npm-shrinkwrap.json"), other.to_string()).unwrap();
    let out = run_vex(&binary(), p, &VexRun::offline());
    assert_eq!(out.code, Some(1), "{out}");
    assert_not_attested(&out.envelope, PURL, "wiring_conflict");
    assert!(
        warnings_of(&out.envelope)
            .iter()
            .any(|(code, detail)| code == "vex_wiring_conflict"
                && detail.contains("npm-shrinkwrap.json")
                && detail.contains("package-lock.json")),
        "{out}"
    );
}

/// A stale org token: the authenticated API answers 401, the run retries
/// the public proxy (free patches only) — and says so in `warnings[]` with
/// `get` / `scan`'s warning text, instead of a `Note:` `--json` dropped.
#[test]
fn stale_credentials_fall_back_to_the_public_proxy_with_a_warning() {
    let org = PatchApi::empty();
    org.fail_view(UUID, 401);
    let proxy = api_for(UUID, PURL);
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    write_locks(p, Shape::V3, &hosted_url("patch.socket.dev", UUID), PIN);
    let run = VexRun {
        proxy_url: Some(proxy.uri()),
        ..VexRun::org_scoped(&org, "acme")
    };
    let out = run_vex(&binary(), p, &run);
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, &[(GHSA, &[CVE])]);
    assert!(org.view_requests(UUID) >= 1 && proxy.view_requests(UUID) >= 1);
    assert!(
        warnings_of(&out.envelope)
            .iter()
            .any(|(code, detail)| code == "api_auth_fallback"
                && detail.starts_with("authenticated API returned")
                && detail.contains("falling back to public patch API proxy (free patches only)")),
        "{out}"
    );
}

/// ONE installed-tree lookup per run: the record check and the hosted
/// consumed-copy check share it, so a `--global-prefix` run prints its
/// `Using global npm packages at:` banner once (it printed twice).
#[test]
fn global_prefix_run_crawls_the_installed_tree_once() {
    let api = api_for(UUID, PURL);
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    write_locks(p, Shape::V3, &hosted_url("patch.socket.dev", UUID), PIN);
    install(p, PATCHED);
    let run = VexRun {
        human: true,
        ..VexRun::online(&api)
    }
    .arg("--global-prefix")
    .arg(p.join("node_modules").to_string_lossy().into_owned());
    let out = run_vex(&binary(), p, &run);
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, &[(GHSA, &[CVE])]);
    assert_eq!(
        out.stderr.matches("Using global npm packages at:").count(),
        1,
        "{out}"
    );
}

/// `apply --vex` with no manifest says what the command did BEFORE the VEX
/// run's own warnings, and says when nothing referenced a patch so no
/// document was written. Both streams share one pipe here, so the order is
/// the order a terminal shows.
#[test]
fn manifestless_apply_prints_its_summary_before_vex_warnings() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    std::fs::write(
        p.join("package.json"),
        r#"{"name":"app","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(p.join("package-lock.json"), "not json").unwrap();
    let log = p.join("combined.log");
    let file = std::fs::File::create(&log).unwrap();
    let mut cmd = std::process::Command::new(binary());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(key);
        }
    }
    let status = cmd
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("SOCKET_NO_API_TOKEN", "1")
        .current_dir(p)
        .args(["apply", "--offline", "--cwd"])
        .arg(p)
        .args(["--vex", "o.json", "--vex-product", DEFAULT_PRODUCT])
        .stdout(file.try_clone().unwrap())
        .stderr(file)
        .status()
        .unwrap();
    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(status.code(), Some(0), "{text}");
    let summary = text
        .find("No patch manifest found; nothing to apply.")
        .unwrap_or_else(|| panic!("{text}"));
    let warning = text
        .find("package-lock.json is not valid JSON")
        .unwrap_or_else(|| panic!("{text}"));
    assert!(summary < warning, "{text}");
    assert!(text.contains("No VEX document written"), "{text}");
    assert!(!p.join("o.json").exists());
}

/// Commit an npm-workspaces v3 lock: the root depends on left-pad (hoisted
/// to `node_modules/left-pad`) and member `packages/a` on the alias
/// `"lp": "npm:left-pad@1.3.0"` (`packages/a/node_modules/lp`), both
/// wired to the same hosted tarball.
fn write_workspace_with_member_alias(project: &Path) {
    let entry = json!({
        "version": VERSION,
        "resolved": hosted_url("patch.socket.dev", UUID),
        "integrity": PIN,
    });
    let mut alias = entry.clone();
    alias["name"] = json!(NAME);
    let lock = json!({
        "name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
        "packages": {
            "": {
                "name": "app", "version": "1.0.0", "workspaces": ["packages/a"],
                "dependencies": { NAME: "^1.3.0" },
            },
            format!("node_modules/{NAME}"): entry,
            "node_modules/a": { "resolved": "packages/a", "link": true },
            "packages/a": {
                "name": "a", "version": "1.0.0",
                "dependencies": { "lp": format!("npm:{NAME}@{VERSION}") },
            },
            "packages/a/node_modules/lp": alias,
        },
    });
    std::fs::write(
        project.join("package.json"),
        r#"{"name":"app","version":"1.0.0","workspaces":["packages/a"],"dependencies":{"left-pad":"^1.3.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        project.join("package-lock.json"),
        serde_json::to_string_pretty(&lock).unwrap(),
    )
    .unwrap();
    let member = project.join("packages/a");
    std::fs::create_dir_all(&member).unwrap();
    std::fs::write(
        member.join("package.json"),
        format!(
            r#"{{"name":"a","version":"1.0.0","dependencies":{{"lp":"npm:{NAME}@{VERSION}"}}}}"#
        ),
    )
    .unwrap();
}

/// REGRESSION (Bugbot): every consumed copy of a hosted npm purl is hashed,
/// including a workspace member's ALIAS install beside a good root copy.
/// The alias walk used to start at the root `node_modules` only, and the
/// identity fallback runs only when no copy was found at all — so with the
/// root (hoisted) copy patched, a tampered or stale member alias went
/// unhashed and the document attested from the good root copy.
#[test]
fn workspace_member_alias_beside_a_patched_root_copy_is_evidence() {
    let api = api_for(UUID, PURL);
    for (label, member_bytes, attested) in [
        ("patched", PATCHED, true),
        ("pristine", PRISTINE, false),
        ("tampered", &b"module.exports = evil;\n"[..], false),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path();
        write_workspace_with_member_alias(p);
        install(p, PATCHED);
        let alias_dir = p.join("packages/a/node_modules/lp");
        std::fs::create_dir_all(&alias_dir).unwrap();
        std::fs::write(
            alias_dir.join("package.json"),
            format!(r#"{{"name":"{NAME}","version":"{VERSION}"}}"#),
        )
        .unwrap();
        std::fs::write(alias_dir.join("index.js"), member_bytes).unwrap();
        assert_no_manifest_or_ledgers(p);

        let out = run_vex(&binary(), p, &VexRun::online(&api));
        if attested {
            assert_eq!(out.code, Some(0), "{label}:\n{out}");
            assert_attested(out.doc(), PURL, UUID, Marker::Redirected, &[(GHSA, &[CVE])]);
        } else {
            assert_eq!(out.code, Some(1), "{label}:\n{out}");
            assert_not_attested(&out.envelope, PURL, "hash_mismatch");
            assert_absent(out.doc.as_ref(), PURL);
        }
    }
}
