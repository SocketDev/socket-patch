//! Manifest-less `socket-patch vex` for DENO — the NEGATIVE ecosystem:
//! there is no hosted rewriter (`scan --mode hosted` refuses deno, and no
//! rewriter edits `deno.lock`) and no vendored backend (no
//! `.socket/vendor/jsr/`), so nothing a Deno project commits is ever a patch
//! reference. Without the manifest, `vex` must never attest a Deno-resolved
//! package — not from `deno.lock` / `deno.json` text that names a Socket
//! patch-server url, not from a ledger claiming such wiring (forged or
//! foreign), with or without `--no-verify` — while agent-mode (manifest)
//! Deno patches keep attesting exactly as before.
//!
//! Hermetic on every OS (the patch API is the shared `vex_e2e_common`
//! stand-in; the JSR cache is a per-test `DENO_DIR`); the real-deno
//! (1.x + 2.x) capstone lives in `e2e_vex_build/deno.rs`.

use crate::vex_e2e_common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::Value;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
use socket_patch_core::patch::redirect::{FileEdit, RedirectState};
use socket_patch_core::vendor::state::{
    VendorArtifact, VendorEntry, VendorState, WiringAction, WiringRecord,
};
use vex_e2e_common::{
    assert_absent, assert_attested, binary, run_vex, Marker, PatchApi, VexOutcome, VexRun, VexVia,
    HOSTED_TOKEN,
};

const PRODUCT: &str = "pkg:npm/deno-app@1.0.0";
const GHSA: &str = "GHSA-deno-lock-vex0";
const CVE: &str = "CVE-2026-7330";
const UUID: &str = "3c3c3c3c-1111-4111-8111-3c3c3c3c3c3c";
const JSR_PURL: &str = "pkg:jsr/@std/path@1.0.0";
const NPM_PURL: &str = "pkg:npm/left-pad@1.3.0";

/// One project: `<tmp>/app` + a private `DENO_DIR` at `<tmp>/deno`.
struct Fx {
    tmp: tempfile::TempDir,
    cwd: PathBuf,
}

impl Fx {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("app");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(tmp.path().join("deno")).unwrap();
        Fx { tmp, cwd }
    }

    fn deno_dir(&self) -> PathBuf {
        self.tmp.path().join("deno")
    }

    fn put(&self, rel: &str, bytes: impl AsRef<[u8]>) {
        put(&self.cwd, rel, bytes.as_ref());
    }

    fn run(&self, run: VexRun) -> VexOutcome {
        let run = VexRun {
            product: Some(PRODUCT.to_string()),
            ..run
        }
        .env("DENO_DIR", self.deno_dir());
        run_vex(&binary(), &self.cwd, &run)
    }

    /// Standalone `vex --json` + `extra` args.
    fn vex(&self, extra: &[&str]) -> VexOutcome {
        self.run(VexRun {
            extra_args: extra.iter().map(|s| s.to_string()).collect(),
            ..VexRun::default()
        })
    }
}

fn put(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// Nothing discovered and nothing recorded: exit 2 `manifest_not_found`,
/// no document statement for `purls`.
fn assert_nothing_to_attest(out: &VexOutcome, purls: &[&str], what: &str) {
    assert_eq!(out.code, Some(2), "{what}: {out}");
    assert_eq!(
        out.envelope["error"]["code"], "manifest_not_found",
        "{what}: {out}"
    );
    for purl in purls {
        assert_absent(out.doc.as_ref(), purl);
    }
}

/// Omitted `purl` with `reason` (exit 1 `no_applicable_patches`).
fn assert_omitted(out: &VexOutcome, purl: &str, reason: &str, what: &str) {
    vex_e2e_common::assert_omitted(out, purl, reason, what);
}

fn files() -> Vec<(&'static str, &'static [u8], &'static [u8])> {
    vec![(
        "package/mod.ts",
        b"export const x = 1;\n",
        b"export const x = 2;\n",
    )]
}

fn view(uuid: &str, purl: &str) -> Value {
    let files: serde_json::Map<String, Value> = files()
        .iter()
        .map(|(key, before, after)| {
            (
                key.to_string(),
                serde_json::json!({
                    "beforeHash": compute_git_sha256_from_bytes(before),
                    "afterHash": compute_git_sha256_from_bytes(after),
                }),
            )
        })
        .collect();
    serde_json::json!({
        "uuid": uuid, "purl": purl, "publishedAt": "Fri, 27 Mar 2026 00:00:00 GMT",
        "files": files,
        "vulnerabilities": { GHSA: {
            "cves": [CVE], "summary": "s", "severity": "high", "description": "d"
        } },
        "description": "deno patch", "license": "MIT", "tier": "free",
    })
}

fn record(uuid: &str) -> PatchRecord {
    let files: HashMap<String, PatchFileInfo> = files()
        .iter()
        .map(|(key, before, after)| {
            (
                key.to_string(),
                PatchFileInfo {
                    before_hash: compute_git_sha256_from_bytes(before),
                    after_hash: compute_git_sha256_from_bytes(after),
                },
            )
        })
        .collect();
    let mut vulnerabilities = HashMap::new();
    vulnerabilities.insert(
        GHSA.to_string(),
        VulnerabilityInfo {
            cves: vec![CVE.to_string()],
            summary: "s".to_string(),
            severity: "high".to_string(),
            description: "d".to_string(),
        },
    );
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: "2026-01-01T00:00:00Z".to_string(),
        files,
        vulnerabilities,
        description: "ledger record".to_string(),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

/// A redirect ledger recording `purl` and an edit of each `(file, kind)`.
fn write_redirect_ledger(fx: &Fx, purl: &str, edited: &[(&str, &str)]) {
    let mut state = RedirectState::new();
    state.records.insert(purl.to_string(), record(UUID));
    for (file, kind) in edited {
        state.edits.push(FileEdit {
            path: file.to_string(),
            kind: kind.to_string(),
            action: "rewritten".to_string(),
            key: Some(purl.to_string()),
            original: None,
            new: None,
        });
    }
    fx.put(
        ".socket/vendor/redirect-state.json",
        serde_json::to_string_pretty(&state).unwrap(),
    );
}

/// A Deno project whose `deno.json` imports and `deno.lock` `npm` /
/// `remote` entries name a Socket patch-server url (a user's own import of
/// one, or hand-copied text).
fn deno_project_naming_socket_urls(fx: &Fx) -> String {
    let npm_url = format!(
        "https://patch.socket.dev/patch/npm/left-pad/1.3.0/{HOSTED_TOKEN}/{UUID}/left-pad-1.3.0.tgz"
    );
    fx.put(
        "deno.json",
        serde_json::json!({
            "name": "@acme/app", "version": "1.0.0",
            "imports": { "left-pad": "npm:left-pad@1.3.0", "lp": npm_url }
        })
        .to_string(),
    );
    fx.put(
        "deno.lock",
        serde_json::json!({
            "version": "5",
            "specifiers": { "npm:left-pad@1.3.0": "1.3.0", "jsr:@std/path@1.0.0": "1.0.0" },
            "npm": { "left-pad@1.3.0": { "integrity": "sha512-UEFUQ0hFRA==", "tarball": npm_url } },
            "jsr": { "@std/path@1.0.0": { "integrity": "a".repeat(64) } },
            "remote": { (npm_url.clone()): "b".repeat(64) }
        })
        .to_string(),
    );
    npm_url
}

/// A `deno.lock` / `deno.json` naming a Socket patch-server url is never a
/// patch reference: with no manifest and no ledger `vex` has nothing to
/// attest (exit 2) and fetches nothing — with `--no-verify` and with the
/// url's host configured as `--patch-server-url` too.
#[test]
fn deno_files_naming_socket_urls_never_attest() {
    let fx = Fx::new();
    deno_project_naming_socket_urls(&fx);
    let api = PatchApi::start(vec![
        (UUID.to_string(), view(UUID, NPM_PURL)),
        (
            "11111111-2222-4333-8444-555555555555".to_string(),
            view(UUID, NPM_PURL),
        ),
    ]);
    for no_verify in [false, true] {
        let mut run = VexRun::online(&api);
        run.no_verify = no_verify;
        run.patch_server_url = Some("https://patch.socket.dev".to_string());
        let out = fx.run(run);
        assert_nothing_to_attest(&out, &[NPM_PURL, JSR_PURL], "deno files only");
    }
    api.assert_no_requests();
}

/// Ledgers claiming wiring through Deno's files are dead, with and without
/// `--no-verify`:
/// * a redirect ledger recording the lockfile a hosted rewriter WOULD have
///   edited (package-lock.json, absent here) — `redirect_unwired`;
/// * REGRESSION: a (forged / foreign) redirect ledger naming `deno.lock` /
///   `deno.json` ITSELF — no writer records those, and the Socket url in
///   them is the user's own import; the liveness fallback used to read any
///   unknown file as a pin, so `--no-verify` attested it;
/// * a vendor ledger entry for a jsr package: there is no jsr backend, so
///   no committed artifact can be wired — `vendor_unwired`.
#[test]
fn deno_ledger_claims_are_dead() {
    let fx = Fx::new();
    deno_project_naming_socket_urls(&fx);
    let ledgers: [(&str, &[(&str, &str)]); 4] = [
        (NPM_PURL, &[("package-lock.json", "redirect_npm_lock")]),
        (JSR_PURL, &[("package-lock.json", "redirect_npm_lock")]),
        (NPM_PURL, &[("deno.lock", "redirect_deno_lock")]),
        (NPM_PURL, &[("deno.json", "redirect_deno_json")]),
    ];
    for (purl, edited) in ledgers {
        write_redirect_ledger(&fx, purl, edited);
        for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
            let out = fx.vex(extra);
            assert_omitted(
                &out,
                purl,
                "redirect_unwired",
                &format!("{purl} {edited:?} {extra:?}"),
            );
        }
    }
    std::fs::remove_dir_all(fx.cwd.join(".socket")).unwrap();

    let rel = format!(".socket/vendor/jsr/{UUID}/std-path-1.0.0.tgz");
    fx.put(&rel, b"not an artifact");
    let mut state = VendorState::new();
    state.entries.insert(
        JSR_PURL.to_string(),
        VendorEntry {
            ecosystem: "jsr".to_string(),
            base_purl: JSR_PURL.to_string(),
            uuid: UUID.to_string(),
            artifact: VendorArtifact {
                path: rel.clone(),
                sha256: "0".repeat(64),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring: vec![WiringRecord {
                file: "deno.lock".to_string(),
                kind: "deno_lock_entry".to_string(),
                action: WiringAction::Rewritten,
                key: None,
                original: None,
                new: None,
            }],
            lock: None,
            took_over_go_patches: false,
            detached: true,
            record: Some(record(UUID)),
            flavor: None,
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        },
    );
    fx.put(
        ".socket/vendor/state.json",
        serde_json::to_string_pretty(&state).unwrap(),
    );
    for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
        let out = fx.vex(extra);
        assert_omitted(&out, JSR_PURL, "vendor_unwired", &format!("jsr {extra:?}"));
    }
}

/// Agent mode, unchanged: a JSR package in the (staged) Deno cache layout
/// the crawler walks (`$DENO_DIR/npm/jsr.io/@<scope>/<name>/<version>/`)
/// patched by `apply --vex` attests with the plain provenance; the
/// standalone `vex` with the manifest attests the same (and the tampered
/// tree does not); with the manifest gone nothing names the patch — the
/// jsr `deno.lock` entry is not wiring — so there is nothing to attest.
#[test]
fn deno_jsr_agent_patch_attests_only_with_the_manifest() {
    let fx = Fx::new();
    fx.put(
        "deno.json",
        r#"{ "imports": { "@std/path": "jsr:@std/path@1.0.0" } }"#,
    );
    fx.put(
        "deno.lock",
        serde_json::json!({
            "version": "4",
            "specifiers": { "jsr:@std/path@1.0.0": "1.0.0" },
            "jsr": { "@std/path@1.0.0": { "integrity": "a".repeat(64) } }
        })
        .to_string(),
    );
    let pkg = fx.deno_dir().join("npm/jsr.io/@std/path/1.0.0");
    let (key, before, after) = files()[0];
    put(&pkg, key.strip_prefix("package/").unwrap(), before);
    let rec = record(UUID);
    let mut manifest = serde_json::json!({
        "patches": { JSR_PURL: serde_json::to_value(&rec).unwrap() },
        // Deno has no install hook: declare it manual (property 7).
        "setup": { "manual": ["deno"] },
    });
    fx.put(".socket/manifest.json", manifest.to_string());
    fx.put(
        &format!(".socket/blobs/{}", compute_git_sha256_from_bytes(after)),
        after,
    );

    let quiet = PatchApi::empty();
    let out = fx.run(
        VexRun {
            proxy_url: Some(quiet.uri()),
            offline: true,
            ..VexRun::default()
        }
        .via(VexVia::Apply),
    );
    assert_eq!(out.code, Some(0), "apply --vex: {out}");
    assert_attested(
        out.doc(),
        JSR_PURL,
        UUID,
        Marker::Applied,
        &[(GHSA, &[CVE])],
    );
    assert_eq!(
        std::fs::read(pkg.join("mod.ts")).unwrap(),
        after,
        "patched in the cache"
    );

    let out = fx.vex(&["--offline"]);
    assert_eq!(out.code, Some(0), "with the manifest: {out}");
    assert_attested(
        out.doc(),
        JSR_PURL,
        UUID,
        Marker::Applied,
        &[(GHSA, &[CVE])],
    );

    put(&pkg, "mod.ts", b"export const x = 3;\n");
    let out = fx.vex(&["--offline"]);
    assert_eq!(out.code, Some(1), "tampered cache copy: {out}");
    assert_absent(out.doc.as_ref(), JSR_PURL);
    put(&pkg, "mod.ts", after);

    // Manifest gone (no ledger, a jsr lock entry, the patched cache copy
    // still there): nothing names the patch.
    std::fs::remove_file(fx.cwd.join(".socket/manifest.json")).unwrap();
    for extra in [&["--offline"][..], &["--no-verify"][..]] {
        let out = fx.vex(extra);
        assert_nothing_to_attest(&out, &[JSR_PURL], &format!("no manifest {extra:?}"));
    }
    quiet.assert_no_requests();

    // And a manifest WITHOUT the `setup.manual` declaration keeps the
    // pre-existing property-7 omission (unchanged by manifest-less VEX:
    // the Deno patch is not lockfile-persisted, so it does not bypass it).
    manifest["setup"] = serde_json::json!({});
    fx.put(".socket/manifest.json", manifest.to_string());
    let out = fx.vex(&["--offline"]);
    assert_eq!(out.code, Some(1), "undeclared deno ecosystem: {out}");
    assert_absent(out.doc.as_ref(), JSR_PURL);
}
