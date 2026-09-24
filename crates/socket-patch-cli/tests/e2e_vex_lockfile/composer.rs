//! Manifest-less VEX for composer (PHP): `socket-patch vex` must attest
//! HOSTED and VENDORED composer patches from `composer.lock` alone — no
//! `.socket/manifest.json` and (unless a cell says otherwise) no
//! `.socket/vendor/state.json` / `.socket/vendor/redirect-state.json` — and
//! must never attest a patch the install does not consume.
//!
//! Hermetic on every OS: no PHP / composer toolchain, no network beyond a
//! loopback wiremock ([`PatchApi`]). Installed trees are fabricated in the
//! layout the composer crawler reads (`vendor/<vendor>/<name>/` +
//! `vendor/composer/installed.json`, in both the composer 2 `{"packages":
//! [...]}` and the composer 1 bare-array shape). The real-composer twins are
//! `e2e_vendor_composer_build.rs` (vendored) and
//! `e2e_redirect_composer_build.rs` (hosted), which end in the same
//! manifest-less VEX legs against lockfiles the real composer 1 / 2 wrote.
//!
//! Every cell runs over the lock-spelling matrix ([`Flavor`] × [`Mode`]):
//!
//! | flavor | lock | hosted wiring | vendored wiring |
//! |---|---|---|---|
//! | `Lock` | `packages[]`, raw slashes (composer 2 `JSON_UNESCAPED_SLASHES`) | `dist.url` on the patch server + sha1 `shasum` | `dist {type: path, url: .socket/vendor/composer/<U>/<v>/<n>@<ver>, reference: <U>}` |
//! | `LockEscaped` | same, every `/` written `\/` (older writers) | same | same |
//! | `LockDev` | `packages-dev[]`, pretty `v1.2.3` version | same | same |
//!
//! Cells:
//!
//! * a) no manifest, no ledgers, online → attested (right subcomponent purl,
//!   vulnerability id + CVE alias, `(redirected)` / `(vendored)` marker),
//!   through both the public-proxy and the org-scoped view routes;
//! * b) `--offline` / API 404 / API 403 with no local record →
//!   `record_unavailable`, and `--offline` makes NO request;
//! * c) ledger present, manifest absent → attested offline from the ledger;
//! * d) lock reverted to the registry while the ledger / artifact remain →
//!   `redirect_unwired` / `vendor_unwired`, with and without `--no-verify`;
//!   a leftover artifact with no ledger and no wiring → nothing at all;
//! * e) tampered installed tree (hosted) / artifact member (vendored) →
//!   omitted;
//! * f) spoofed references (a uuid-shaped segment on a non-Socket host, a
//!   vendored-looking path outside `.socket/vendor`, a leaf / `reference`
//!   naming another package or patch, an API / ledger record for another
//!   package or patch) → never attested (`record_mismatch` where a record
//!   exists);
//! * g) hosted: not installed → attests from the lock's sha1 pin only;
//!   installed + patched → attests after hash verification (composer 1 and
//!   composer 2 `installed.json`); installed pristine → omitted;
//! * h) a lock wiring one package to two patches → `wiring_conflict`;
//!   a `--patch-server-url` deployment's origin counts only when configured.

use crate::vex_e2e_common;

use std::path::Path;

use serde_json::Value;
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
use socket_patch_core::patch::redirect::{FileEdit, RedirectState};
use socket_patch_core::vendor::state::{
    VendorArtifact, VendorEntry, VendorState, WiringAction, WiringRecord,
};
use vex_e2e_common::*;

/// The patch uuid every cell wires (canonical lowercase v4 shape).
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
/// A second, unrelated patch uuid (spoof / superseded cells).
const OTHER_UUID: &str = "0c0c0c0c-1111-4111-8111-0c0c0c0c0c0c";
/// A uuid-SHAPED grant token: production tokens may be uuid-shaped, and the
/// patch uuid is the LAST uuid segment of a hosted URL.
const TOKEN: &str = "11111111-2222-4333-8444-555555555555";
const SOCKET: &str = "https://patch.socket.dev";
const PRODUCT: &str = "pkg:composer/acme/app@1.0.0";
const GHSA: &str = "GHSA-cmpx-7777-0001";
const CVE: &str = "CVE-2026-7778";
/// The patched composer archive's sha1 the hosted rewriter pins.
const SHA1: &str = "abcdef0123456789abcdef0123456789abcdef01";

const PURL: &str = "pkg:composer/acme/vexprobe@1.2.3";
const OTHER_PURL: &str = "pkg:composer/acme/otherprobe@9.9.9";
/// The record's file key: relative to the composer package dir (the
/// vendored artifact dir has the same layout).
const FILE_KEY: &str = "src/Probe.php";

const BEFORE: &[u8] = b"<?php\n// vexprobe 1.2.3\nconst VULNERABLE = true;\n";
const AFTER: &[u8] = b"<?php\n// vexprobe 1.2.3 (patched by socket)\nconst VULNERABLE = false;\n";
const TAMPERED: &[u8] = b"<?php\n// vexprobe 1.2.3 (hand-edited)\nconst VULNERABLE = null;\n";

/// A loopback port nothing listens on: runs that pass no [`PatchApi`] are
/// pointed here (on top of `--offline`) so no cell can ever reach the real
/// public proxy.
const DEAD_API: &str = "http://127.0.0.1:9";

// ── the flavor matrix ─────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flavor {
    Lock,
    LockEscaped,
    LockDev,
}

const ALL_FLAVORS: [Flavor; 3] = [Flavor::Lock, Flavor::LockEscaped, Flavor::LockDev];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Hosted,
    Vendored,
}

const ALL_MODES: [Mode; 2] = [Mode::Hosted, Mode::Vendored];

impl Mode {
    fn marker(self) -> Marker {
        match self {
            Mode::Hosted => Marker::Redirected,
            Mode::Vendored => Marker::Vendored,
        }
    }

    fn marker_text(self) -> &'static str {
        match self {
            Mode::Hosted => "(redirected)",
            Mode::Vendored => "(vendored)",
        }
    }

    fn unwired(self) -> &'static str {
        match self {
            Mode::Hosted => "redirect_unwired",
            Mode::Vendored => "vendor_unwired",
        }
    }
}

impl Flavor {
    /// The version string the lock (and installed.json) spell.
    fn locked_version(self) -> &'static str {
        if self == Flavor::LockDev {
            "v1.2.3"
        } else {
            "1.2.3"
        }
    }
}

fn artifact_rel(uuid: &str) -> String {
    format!(".socket/vendor/composer/{uuid}/acme/vexprobe@1.2.3")
}

/// The hosted URL the rewriter writes, on `origin`.
fn hosted_url(origin: &str, uuid: &str) -> String {
    format!("{origin}/patch/composer/acme/vexprobe/1.2.3/{TOKEN}/{uuid}/vexprobe-1.2.3.zip")
}

/// What the lock resolves the patched package from.
#[derive(Clone, Debug)]
enum Wire {
    /// The hosted patch at `url`; `pinned` writes the patched archive's
    /// sha1 into `dist.shasum`.
    Hosted { url: String, pinned: bool },
    /// A vendored artifact dir at `rel`; `reference` is `dist.reference`
    /// (the patch uuid the backend writes).
    Vendored { rel: String, reference: String },
    /// The upstream registry (a reverted / never-patched lock).
    Registry,
}

impl Wire {
    fn socket(mode: Mode) -> Wire {
        match mode {
            Mode::Hosted => Wire::Hosted {
                url: hosted_url(SOCKET, UUID),
                pinned: true,
            },
            Mode::Vendored => Wire::Vendored {
                rel: artifact_rel(UUID),
                reference: UUID.to_string(),
            },
        }
    }
}

/// The `acme/vexprobe` lock entry for `wire`, in the shapes the rewriters'
/// golden fixtures pin.
fn lock_entry(flavor: Flavor, wire: &Wire) -> Value {
    let mut entry = serde_json::json!({
        "name": "acme/vexprobe",
        "version": flavor.locked_version(),
    });
    match wire {
        Wire::Hosted { url, pinned } => {
            entry["dist"] = serde_json::json!({
                "type": "zip",
                "url": url,
                "reference": "0123456789abcdef0123456789abcdef01234567",
                "shasum": if *pinned { SHA1 } else { "" },
            });
        }
        Wire::Vendored { rel, reference } => {
            entry["dist"] =
                serde_json::json!({ "type": "path", "url": rel, "reference": reference });
            entry["transport-options"] = serde_json::json!({ "symlink": false });
        }
        Wire::Registry => {
            entry["source"] = serde_json::json!({
                "type": "git",
                "url": "https://github.com/acme/vexprobe.git",
                "reference": "0123456789abcdef0123456789abcdef01234567",
            });
            entry["dist"] = serde_json::json!({
                "type": "zip",
                "url": "https://api.github.com/repos/acme/vexprobe/zipball/0123456789abcdef0123456789abcdef01234567",
                "reference": "0123456789abcdef0123456789abcdef01234567",
                "shasum": "",
            });
        }
    }
    entry
}

/// Write `composer.lock` (+ `composer.json`) holding `entries` for the
/// patched package next to an untouched registry bystander.
fn write_lock_entries(cwd: &Path, flavor: Flavor, entries: Vec<Value>) {
    let bystander = serde_json::json!({
        "name": "psr/log",
        "version": "1.1.4",
        "dist": {
            "type": "zip",
            "url": "https://api.github.com/repos/php-fig/log/zipball/d49695b909c3b7628b6289db5479a1c204601f11",
            "reference": "d49695b909c3b7628b6289db5479a1c204601f11",
            "shasum": ""
        }
    });
    let (packages, dev) = if flavor == Flavor::LockDev {
        (vec![bystander], entries)
    } else {
        let mut packages = entries;
        packages.push(bystander);
        (packages, vec![])
    };
    let lock = serde_json::json!({
        "_readme": ["This file locks the dependencies of your project to a known state"],
        "content-hash": "abc123def456abc123def456abc123de",
        "packages": packages,
        "packages-dev": dev,
    });
    let mut text = serde_json::to_string_pretty(&lock).unwrap();
    if flavor == Flavor::LockEscaped {
        // Writers without `JSON_UNESCAPED_SLASHES` escape every slash; the
        // lock must be read through the JSON decoder.
        text = text.replace('/', "\\/");
    }
    std::fs::write(cwd.join("composer.lock"), text).unwrap();
    let require_key = if flavor == Flavor::LockDev {
        "require-dev"
    } else {
        "require"
    };
    std::fs::write(
        cwd.join("composer.json"),
        serde_json::json!({
            "name": "acme/app",
            require_key: { "acme/vexprobe": "^1.2" },
        })
        .to_string(),
    )
    .unwrap();
}

fn write_wiring(cwd: &Path, flavor: Flavor, wire: &Wire) {
    write_lock_entries(cwd, flavor, vec![lock_entry(flavor, wire)]);
}

/// The committed vendored artifact dir holding `content` at [`FILE_KEY`]
/// (plus the package's own composer.json, as the backend copies it).
fn write_artifact(cwd: &Path, uuid: &str, content: &[u8]) -> String {
    let rel = artifact_rel(uuid);
    let dir = cwd.join(&rel);
    let file = dir.join(FILE_KEY);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, content).unwrap();
    std::fs::write(
        dir.join("composer.json"),
        r#"{"name":"acme/vexprobe","version":"1.2.3"}"#,
    )
    .unwrap();
    rel
}

/// Which `vendor/composer/installed.json` shape an install wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Installed {
    /// composer 2: `{"packages": [...], "dev": …}` with `install-path`.
    V2,
    /// composer 1: a bare array, no `install-path`.
    V1,
}

/// The installed copy the crawler finds: `vendor/acme/vexprobe` + the
/// `installed.json` naming it.
fn install(cwd: &Path, flavor: Flavor, content: &[u8]) {
    install_as(cwd, flavor, Installed::V2, content);
}

fn install_as(cwd: &Path, flavor: Flavor, shape: Installed, content: &[u8]) {
    let file = cwd.join("vendor/acme/vexprobe").join(FILE_KEY);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, content).unwrap();
    std::fs::create_dir_all(cwd.join("vendor/composer")).unwrap();
    let pkg = serde_json::json!({
        "name": "acme/vexprobe",
        "version": flavor.locked_version(),
        "install-path": "../acme/vexprobe",
    });
    let body = match shape {
        Installed::V2 => serde_json::json!({ "packages": [pkg], "dev": true }),
        Installed::V1 => {
            let mut pkg = pkg;
            pkg.as_object_mut().unwrap().remove("install-path");
            serde_json::json!([pkg])
        }
    };
    std::fs::write(cwd.join("vendor/composer/installed.json"), body.to_string()).unwrap();
}

// ── records, views, ledgers ───────────────────────────────────────────

fn record(uuid: &str) -> PatchRecord {
    let mut files = std::collections::HashMap::new();
    files.insert(
        FILE_KEY.to_string(),
        PatchFileInfo {
            before_hash: git_sha256(BEFORE),
            after_hash: git_sha256(AFTER),
        },
    );
    let mut vulns = std::collections::HashMap::new();
    vulns.insert(
        GHSA.to_string(),
        VulnerabilityInfo {
            cves: vec![CVE.to_string()],
            summary: "composer lockfile vex fixture".to_string(),
            severity: "high".to_string(),
            description: "d".to_string(),
        },
    );
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: "2026-01-01T00:00:00Z".to_string(),
        files,
        vulnerabilities: vulns,
        description: "lockfile vex fixture".to_string(),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

/// The patch-API view of `uuid` claiming `purl` — with the REAL before hash
/// (the shared `patch_view` stubs it), so a pristine install is recognized
/// as `not_applied` rather than an unknown tree.
fn view(uuid: &str, purl: &str) -> Value {
    serde_json::json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "Fri, 27 Mar 2026 00:00:00 GMT",
        "files": { FILE_KEY: {
            "beforeHash": git_sha256(BEFORE),
            "afterHash": git_sha256(AFTER),
        } },
        "vulnerabilities": { GHSA: {
            "cves": [CVE], "summary": "s", "severity": "high", "description": "d"
        } },
        "description": "lockfile vex fixture",
        "license": "MIT",
        "tier": "free",
    })
}

/// The API serving the honest record for [`UUID`].
fn honest_api() -> PatchApi {
    PatchApi::start(vec![(UUID.into(), view(UUID, PURL))])
}

/// `.socket/vendor/redirect-state.json` as `scan --redirect` writes it for a
/// composer redirect: the record plus the lock edit.
fn write_redirect_ledger(cwd: &Path, key: &str, rec: PatchRecord) {
    let mut state = RedirectState::new();
    state.records.insert(key.to_string(), rec);
    state.edits.push(FileEdit {
        path: "composer.lock".to_string(),
        kind: "redirect_composer_dist".to_string(),
        action: "rewritten".to_string(),
        key: Some(key.to_string()),
        original: None,
        new: None,
    });
    let dir = cwd.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("redirect-state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();
}

/// `.socket/vendor/state.json` as `vendor` writes it (non-detached, record
/// embedded), with the composer backend's lock wiring record.
fn write_vendor_ledger(cwd: &Path, key: &str, rec: PatchRecord) {
    let mut state = VendorState::new();
    state.entries.insert(
        key.to_string(),
        VendorEntry {
            ecosystem: "composer".to_string(),
            base_purl: key.to_string(),
            uuid: rec.uuid.clone(),
            artifact: VendorArtifact {
                path: artifact_rel(&rec.uuid),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring: vec![WiringRecord {
                file: "composer.lock".to_string(),
                kind: "composer_lock_package".to_string(),
                action: WiringAction::Rewritten,
                key: Some("acme/vexprobe".to_string()),
                original: None,
                new: None,
            }],
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: Some(rec),
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

fn write_ledger(cwd: &Path, mode: Mode, key: &str, rec: PatchRecord) {
    match mode {
        Mode::Hosted => write_redirect_ledger(cwd, key, rec),
        Mode::Vendored => write_vendor_ledger(cwd, key, rec),
    }
}

/// A lockfile-only checkout wired to [`UUID`] for `mode`, and (vendored)
/// the committed artifact holding `artifact`.
fn project(flavor: Flavor, mode: Mode, artifact: &[u8]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    write_wiring(tmp.path(), flavor, &Wire::socket(mode));
    if mode == Mode::Vendored {
        write_artifact(tmp.path(), UUID, artifact);
    }
    tmp
}

// ── running vex ───────────────────────────────────────────────────────

/// Standalone `vex --json` in `cwd` for [`PRODUCT`], its public-proxy
/// traffic pointed at `api` (or at a dead port when `None`), plus `extra`.
fn vex(cwd: &Path, api: Option<&PatchApi>, extra: &[&str]) -> VexOutcome {
    let mut run = match api {
        Some(api) => VexRun::online(api),
        None => VexRun {
            proxy_url: Some(DEAD_API.to_string()),
            api_url: Some(DEAD_API.to_string()),
            ..VexRun::default()
        },
    };
    run.product = Some(PRODUCT.to_string());
    for arg in extra {
        run = run.arg(*arg);
    }
    // A failed run must not leave a previous cell's document behind.
    let _ = std::fs::remove_file(cwd.join(DEFAULT_OUTPUT));
    run_vex(&binary(), cwd, &run)
}

/// Exit 0, one `verified` event for `purl`, and the document's statement:
/// exactly [`GHSA`] (+ [`CVE`]) via `uuid` with `mode`'s marker.
fn assert_attests(out: &VexOutcome, purl: &str, uuid: &str, mode: Mode, cell: &str) {
    assert_eq!(out.code, Some(0), "{cell}: must attest:\n{out}");
    assert_eq!(out.envelope["status"], "success", "{cell}:\n{out}");
    let verified: Vec<&Value> = out.envelope["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "verified")
        .collect();
    assert_eq!(verified.len(), 1, "{cell}: one verified event:\n{out}");
    assert_eq!(verified[0]["purl"], purl, "{cell}:\n{out}");
    assert_eq!(verified[0]["details"]["vulnerability"], GHSA, "{cell}");
    let doc = out.doc();
    let stmts = assert_attested(doc, purl, uuid, mode.marker(), &[(GHSA, &[CVE])]);
    assert_eq!(stmts.len(), 1, "{cell}: {doc}");
    assert_eq!(
        doc["statements"].as_array().map(Vec::len),
        Some(1),
        "{cell}: nothing but the one patch is attested: {doc}"
    );
    assert_eq!(stmts[0]["products"][0]["@id"], PRODUCT, "{cell}");
    assert_eq!(
        stmts[0]["impact_statement"],
        format!("Patched via Socket patch {uuid} {}", mode.marker_text()),
        "{cell}"
    );
}

/// Exit 1 (`no_applicable_patches`), `purl` skipped with `reason`, and no
/// document on disk.
fn assert_omits(out: &VexOutcome, purl: &str, reason: &str, cell: &str) {
    assert_eq!(out.code, Some(1), "{cell}: nothing may attest:\n{out}");
    assert_eq!(
        out.envelope["error"]["code"], "no_applicable_patches",
        "{cell}:\n{out}"
    );
    assert_not_attested(&out.envelope, purl, reason);
    assert!(
        out.doc.is_none(),
        "{cell}: no VEX doc may be written:\n{out}"
    );
}

/// Nothing Socket-shaped is discovered, so a manifest-less, ledger-less run
/// is `manifest_not_found` (exit 2) — and the API holding a genuine record
/// for the uuid is never even asked.
fn assert_nothing_discovered(cwd: &Path, api: &PatchApi, cell: &str) -> VexOutcome {
    let out = vex(cwd, Some(api), &[]);
    assert_eq!(out.code, Some(2), "{cell}:\n{out}");
    assert_eq!(
        out.envelope["error"]["code"], "manifest_not_found",
        "{cell}:\n{out}"
    );
    assert_eq!(
        api.request_count(),
        0,
        "{cell}: a non-reference is never fetched"
    );
    assert!(out.doc.is_none(), "{cell}");
    out
}

fn assert_no_socket_state_written(cwd: &Path, cell: &str) {
    for rel in [
        ".socket/manifest.json",
        ".socket/vendor/state.json",
        ".socket/vendor/redirect-state.json",
    ] {
        assert!(
            !cwd.join(rel).exists(),
            "{cell}: vex must never write {rel}"
        );
    }
}

fn cells() -> impl Iterator<Item = (Flavor, Mode)> {
    ALL_FLAVORS
        .into_iter()
        .flat_map(|f| ALL_MODES.into_iter().map(move |m| (f, m)))
}

// ──────────────────────────────────────────────────────────────────────
// a) no manifest, no ledgers, online → attested
// ──────────────────────────────────────────────────────────────────────

/// A depscan-opened PR / a checkout whose `.socket/` ledgers were never
/// committed: the lock wiring is the only input, the record comes from the
/// patch API (exactly one fetch), hosted refs attest from the pinned wiring
/// (nothing installed), vendored refs from the hashed artifact.
#[test]
fn a_lockfile_only_checkout_attests_online() {
    for (flavor, mode) in cells() {
        let cell = format!("{flavor:?}/{mode:?}");
        let tmp = project(flavor, mode, AFTER);
        let cwd = tmp.path();
        let api = honest_api();
        let out = vex(cwd, Some(&api), &[]);
        assert_attests(&out, PURL, UUID, mode, &cell);
        assert_eq!(
            api.view_requests(UUID),
            1,
            "{cell}: exactly one record fetch"
        );
        assert_eq!(api.request_count(), 1, "{cell}: {:?}", api.requests());
        assert_no_socket_state_written(cwd, &cell);
    }
}

/// With a token the record comes from the org-scoped view route instead of
/// the public proxy — same attestation.
#[test]
fn a_org_scoped_record_fetch_attests() {
    for mode in ALL_MODES {
        let cell = format!("{mode:?}");
        let tmp = project(Flavor::Lock, mode, AFTER);
        let api = honest_api();
        let mut run = VexRun::org_scoped(&api, "acme-org");
        run.product = Some(PRODUCT.into());
        let out = run_vex(&binary(), tmp.path(), &run);
        assert_attests(&out, PURL, UUID, mode, &cell);
        assert!(
            api.requests()
                .iter()
                .any(|p| p == &format!("/v0/orgs/acme-org/patches/view/{UUID}")),
            "{cell}: the org-scoped route served the record: {:?}",
            api.requests()
        );
    }
}

// ──────────────────────────────────────────────────────────────────────
// b) no local record and no way to fetch one → record_unavailable
// ──────────────────────────────────────────────────────────────────────

#[test]
fn b_offline_or_unfetchable_record_is_record_unavailable() {
    for (flavor, mode) in cells() {
        let cell = format!("{flavor:?}/{mode:?}");
        let tmp = project(flavor, mode, AFTER);
        let cwd = tmp.path();

        // --offline: the API (which WOULD answer) is never contacted, with
        // or without --no-verify (it skips hashing, never the record gate).
        let api = honest_api();
        for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
            let out = vex(cwd, Some(&api), extra);
            assert_omits(
                &out,
                PURL,
                "record_unavailable",
                &format!("{cell} {extra:?}"),
            );
        }
        api.assert_no_requests();

        // Online, but the API has no record (404) or refuses it (403 — a
        // paid patch on the public proxy): omitted, never attested from the
        // lock's own claims.
        let missing = PatchApi::empty();
        let out = vex(cwd, Some(&missing), &[]);
        assert_omits(&out, PURL, "record_unavailable", &format!("{cell} 404"));
        assert!(
            missing.request_count() >= 1,
            "{cell}: the record was asked for"
        );

        let refused = PatchApi::empty();
        refused.fail_view(UUID, 403);
        let out = vex(cwd, Some(&refused), &[]);
        assert_omits(&out, PURL, "record_unavailable", &format!("{cell} 403"));
        assert!(refused.view_requests(UUID) >= 1, "{cell}");
        assert_no_socket_state_written(cwd, &cell);
    }
}

// ──────────────────────────────────────────────────────────────────────
// c) ledger present, manifest absent → attested offline
// ──────────────────────────────────────────────────────────────────────

#[test]
fn c_ledger_without_manifest_attests_offline() {
    for (flavor, mode) in cells() {
        let cell = format!("{flavor:?}/{mode:?}");
        let tmp = project(flavor, mode, AFTER);
        let cwd = tmp.path();
        write_ledger(cwd, mode, PURL, record(UUID));
        let api = honest_api();
        let out = vex(cwd, Some(&api), &["--offline"]);
        assert_attests(&out, PURL, UUID, mode, &cell);
        api.assert_no_requests();

        if mode == Mode::Hosted {
            // Post-install: the installed tree is hash-verified against the
            // ledger record.
            install(cwd, flavor, AFTER);
            let out = vex(cwd, None, &["--offline"]);
            assert_attests(&out, PURL, UUID, mode, &format!("{cell}+installed"));
        }
        assert!(!cwd.join(".socket/manifest.json").exists(), "{cell}");
    }
}

// ──────────────────────────────────────────────────────────────────────
// d) lock reverted while the ledger / artifact remain → unwired
// ──────────────────────────────────────────────────────────────────────

/// `composer.lock` is reverted to the registry (a manual revert, `git
/// checkout composer.lock`, or a `composer update` that re-resolved from
/// packagist); the ledger, the committed artifact and even a still-patched
/// installed tree stay behind. The next install consumes the registry
/// package, so nothing may attest — with or without `--no-verify`, online or
/// offline.
#[test]
fn d_reverted_lock_with_leftover_ledger_is_unwired() {
    for (flavor, mode) in cells() {
        let cell = format!("{flavor:?}/{mode:?}");
        let tmp = project(flavor, mode, AFTER);
        let cwd = tmp.path();
        write_ledger(cwd, mode, PURL, record(UUID));
        if mode == Mode::Hosted {
            install(cwd, flavor, AFTER);
        }
        write_wiring(cwd, flavor, &Wire::Registry);
        let api = honest_api();
        for extra in [
            &[][..],
            &["--no-verify"][..],
            &["--offline"][..],
            &["--offline", "--no-verify"][..],
        ] {
            let out = vex(cwd, Some(&api), extra);
            assert_omits(&out, PURL, mode.unwired(), &format!("{cell} {extra:?}"));
        }
    }
}

/// A leftover vendored artifact with NO ledger and a registry lock is not a
/// reference at all: nothing is discovered, nothing is fetched.
#[test]
fn d_leftover_artifact_without_ledger_or_wiring_is_nothing() {
    for flavor in ALL_FLAVORS {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        write_wiring(cwd, flavor, &Wire::Registry);
        write_artifact(cwd, UUID, AFTER);
        for extra in [&[][..], &["--no-verify"][..]] {
            let api = honest_api();
            let out = vex(cwd, Some(&api), extra);
            assert_eq!(out.code, Some(2), "{flavor:?} {extra:?}:\n{out}");
            assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");
            api.assert_no_requests();
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// e) tampered evidence → omitted
// ──────────────────────────────────────────────────────────────────────

#[test]
fn e_tampered_evidence_is_omitted() {
    for (flavor, mode) in cells() {
        let cell = format!("{flavor:?}/{mode:?}");
        // Vendored: a hand-edited member of the committed artifact.
        // Hosted: an installed tree matching neither side of the patch
        // (installed evidence wins over the pinned wiring).
        let tmp = project(flavor, mode, TAMPERED);
        let cwd = tmp.path();
        if mode == Mode::Hosted {
            install(cwd, flavor, TAMPERED);
        }
        let reason = match mode {
            Mode::Hosted => "hash_mismatch",
            Mode::Vendored => "vendor_hash_mismatch",
        };
        let api = honest_api();
        let out = vex(cwd, Some(&api), &[]);
        assert_omits(&out, PURL, reason, &format!("{cell} online"));
        write_ledger(cwd, mode, PURL, record(UUID));
        let out = vex(cwd, None, &["--offline"]);
        assert_omits(&out, PURL, reason, &format!("{cell} ledger"));
    }
}

/// A vendored artifact whose patched member was deleted cannot verify.
#[test]
fn e_vendored_artifact_missing_its_member_is_omitted() {
    for flavor in ALL_FLAVORS {
        let tmp = project(flavor, Mode::Vendored, AFTER);
        let cwd = tmp.path();
        std::fs::remove_file(cwd.join(artifact_rel(UUID)).join(FILE_KEY)).unwrap();
        let api = honest_api();
        let out = vex(cwd, Some(&api), &[]);
        assert_omits(&out, PURL, "file_not_found", &format!("{flavor:?}"));
    }
}

// ──────────────────────────────────────────────────────────────────────
// f) spoofed references → never attested
// ──────────────────────────────────────────────────────────────────────

#[test]
fn f_uuid_on_a_foreign_host_is_not_a_patch_reference() {
    for flavor in ALL_FLAVORS {
        // The exact Socket path shape (uuid-shaped token + uuid segments) on
        // someone else's host, a Socket-lookalike suffix host, a userinfo
        // trick, and plain http to the real host.
        for origin in [
            "https://patch.evil.example",
            "https://patch.socket.dev.evil.example",
            "https://patch.socket.dev@evil.example",
            "http://patch.socket.dev",
        ] {
            let cell = format!("{flavor:?} {origin}");
            let tmp = tempfile::tempdir().unwrap();
            let cwd = tmp.path();
            write_wiring(
                cwd,
                flavor,
                &Wire::Hosted {
                    url: hosted_url(origin, UUID),
                    pinned: true,
                },
            );
            assert_nothing_discovered(cwd, &honest_api(), &cell);
            // Even an installed tree carrying the patched bytes cannot turn a
            // foreign-host dist into a Socket patch.
            install(cwd, flavor, AFTER);
            assert_nothing_discovered(cwd, &honest_api(), &format!("{cell} installed"));
        }
    }
}

#[test]
fn f_vendored_looking_paths_outside_the_project_vendor_dir_are_not_references() {
    for flavor in ALL_FLAVORS {
        for rel in [
            // An ordinary local path repository that happens to carry a uuid.
            format!("packages/composer/{UUID}/acme/vexprobe@1.2.3"),
            // Escaping the project root to someone else's `.socket/vendor`.
            format!("../.socket/vendor/composer/{UUID}/acme/vexprobe@1.2.3"),
            // Absolute.
            format!("/tmp/.socket/vendor/composer/{UUID}/acme/vexprobe@1.2.3"),
            // Another ecosystem's vendor dir.
            format!(".socket/vendor/gem/{UUID}/acme/vexprobe@1.2.3"),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let cwd = tmp.path();
            write_wiring(
                cwd,
                flavor,
                &Wire::Vendored {
                    rel: rel.clone(),
                    reference: UUID.to_string(),
                },
            );
            // A genuine artifact at the in-project location does not help.
            write_artifact(cwd, UUID, AFTER);
            assert_nothing_discovered(cwd, &honest_api(), &format!("{flavor:?} {rel}"));
        }
    }
}

/// A vendored path whose leaf names ANOTHER package (a lock entry borrowing
/// some other patch's committed artifact) is not a reference for this one.
#[test]
fn f_vendored_leaf_naming_another_package_is_not_a_reference() {
    for flavor in ALL_FLAVORS {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        write_wiring(
            cwd,
            flavor,
            &Wire::Vendored {
                rel: format!(".socket/vendor/composer/{UUID}/acme/otherprobe@9.9.9"),
                reference: UUID.to_string(),
            },
        );
        let out = assert_nothing_discovered(cwd, &honest_api(), &format!("{flavor:?}"));
        assert!(
            out.envelope["warnings"].to_string().contains("ref_invalid"),
            "{flavor:?}: the rejected wiring must be diagnosed:\n{out}"
        );
    }
}

/// The vendor backend writes the patch uuid into `dist.reference`; a
/// vendored path dist whose reference names another patch (or is missing)
/// is a hand edit the backend never produces.
#[test]
fn f_vendored_reference_must_carry_the_path_uuid() {
    for flavor in ALL_FLAVORS {
        for reference in [OTHER_UUID, ""] {
            let tmp = tempfile::tempdir().unwrap();
            let cwd = tmp.path();
            write_artifact(cwd, UUID, AFTER);
            write_wiring(
                cwd,
                flavor,
                &Wire::Vendored {
                    rel: artifact_rel(UUID),
                    reference: reference.to_string(),
                },
            );
            assert_nothing_discovered(cwd, &honest_api(), &format!("{flavor:?} {reference:?}"));
        }
    }
}

/// The API's record for the wired uuid names ANOTHER package, or is another
/// patch altogether: the lock and the record disagree about what was
/// patched → `record_mismatch`.
#[test]
fn f_api_record_for_another_package_or_patch_is_a_mismatch() {
    for (flavor, mode) in cells() {
        let cell = format!("{flavor:?}/{mode:?}");
        let tmp = project(flavor, mode, AFTER);
        let cwd = tmp.path();
        let other_pkg = PatchApi::start(vec![(UUID.into(), view(UUID, OTHER_PURL))]);
        let out = vex(cwd, Some(&other_pkg), &[]);
        assert_omits(&out, PURL, "record_mismatch", &format!("{cell} purl"));
        let out = vex(cwd, Some(&other_pkg), &["--no-verify"]);
        assert_omits(
            &out,
            PURL,
            "record_mismatch",
            &format!("{cell} purl --no-verify"),
        );

        let other_patch = PatchApi::start(vec![(UUID.into(), view(OTHER_UUID, PURL))]);
        let out = vex(cwd, Some(&other_patch), &[]);
        assert_omits(&out, PURL, "record_mismatch", &format!("{cell} uuid"));
    }
}

/// A LOCAL ledger record carrying the wired uuid but filed under another
/// package is never borrowed (offline — the ledger is the only record).
#[test]
fn f_ledger_record_for_another_package_is_a_mismatch() {
    for (flavor, mode) in cells() {
        let cell = format!("{flavor:?}/{mode:?}");
        let tmp = project(flavor, mode, AFTER);
        let cwd = tmp.path();
        write_ledger(cwd, mode, OTHER_PURL, record(UUID));
        let out = vex(cwd, None, &["--offline"]);
        assert_omits(&out, PURL, "record_mismatch", &cell);
    }
}

/// The lock wires the package to patch U while the ledger records patch U'
/// for it: only what the lock wires may attest (the record for U comes from
/// the API; the stale U' record is superseded, never attested).
#[test]
fn f_ledger_record_for_a_superseded_patch_is_not_attested() {
    for (flavor, mode) in cells() {
        let cell = format!("{flavor:?}/{mode:?}");
        let tmp = project(flavor, mode, AFTER);
        let cwd = tmp.path();
        write_ledger(cwd, mode, PURL, record(OTHER_UUID));
        let out = vex(cwd, None, &["--offline"]);
        assert_omits(&out, PURL, "record_unavailable", &format!("{cell} offline"));
        let api = honest_api();
        let out = vex(cwd, Some(&api), &[]);
        assert_attests(&out, PURL, UUID, mode, &format!("{cell} online"));
        assert!(
            !out.doc().to_string().contains(OTHER_UUID),
            "{cell}: the superseded patch must not be attested"
        );
    }
}

/// A hosted URL whose only uuid-shaped segment is the grant token names no
/// patch: never attested, and the real patch's record is not reachable
/// through it.
#[test]
fn f_grant_token_alone_is_not_a_patch() {
    for flavor in ALL_FLAVORS {
        let cell = format!("{flavor:?}");
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let url = format!("{SOCKET}/patch/composer/acme/vexprobe/1.2.3/{TOKEN}/vexprobe-1.2.3.zip");
        write_wiring(cwd, flavor, &Wire::Hosted { url, pinned: true });
        let api = honest_api();
        let out = vex(cwd, Some(&api), &[]);
        assert_ne!(out.code, Some(0), "{cell}:\n{out}");
        assert!(out.doc.is_none(), "{cell}:\n{out}");
        assert!(!out.envelope.to_string().contains(GHSA), "{cell}:\n{out}");
        assert_eq!(api.view_requests(UUID), 0, "{cell}");
    }
}

// ──────────────────────────────────────────────────────────────────────
// g) hosted: the installed tree decides once it exists
// ──────────────────────────────────────────────────────────────────────

#[test]
fn g_hosted_not_installed_attests_only_from_a_pinned_lock() {
    for flavor in ALL_FLAVORS {
        let cell = format!("{flavor:?}");
        // Pinned (the rewriter's output): attests with nothing installed.
        let tmp = project(flavor, Mode::Hosted, AFTER);
        let api = honest_api();
        let out = vex(tmp.path(), Some(&api), &[]);
        assert_attests(&out, PURL, UUID, Mode::Hosted, &cell);

        // Pin-less (empty / short / missing sha1): the composer rewriter
        // ALWAYS pins, so a pin-less Socket entry was not Socket-written —
        // only a verifying installed tree can attest it.
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        write_wiring(
            cwd,
            flavor,
            &Wire::Hosted {
                url: hosted_url(SOCKET, UUID),
                pinned: false,
            },
        );
        let out = vex(cwd, Some(&api), &[]);
        assert_omits(&out, PURL, "package_not_found", &format!("{cell} pinless"));
        install(cwd, flavor, AFTER);
        let out = vex(cwd, Some(&api), &[]);
        assert_attests(
            &out,
            PURL,
            UUID,
            Mode::Hosted,
            &format!("{cell} pinless+installed"),
        );
    }
}

#[test]
fn g_hosted_installed_tree_is_hash_verified() {
    for flavor in ALL_FLAVORS {
        for shape in [Installed::V2, Installed::V1] {
            let cell = format!("{flavor:?} {shape:?}");
            // Installed and patched: attested after hashing.
            let tmp = project(flavor, Mode::Hosted, AFTER);
            let cwd = tmp.path();
            install_as(cwd, flavor, shape, AFTER);
            let api = honest_api();
            let out = vex(cwd, Some(&api), &[]);
            assert_attests(&out, PURL, UUID, Mode::Hosted, &format!("{cell} patched"));

            // Installed but pristine (installed before the lock was
            // redirected, never reinstalled): the pinned wiring would attest
            // a fresh checkout, but installed evidence wins.
            install_as(cwd, flavor, shape, BEFORE);
            let out = vex(cwd, Some(&api), &[]);
            assert_omits(&out, PURL, "not_applied", &format!("{cell} pristine"));

            // `--no-verify` skips the hash, so it attests from the wiring.
            let out = vex(cwd, Some(&api), &["--no-verify"]);
            assert_attests(
                &out,
                PURL,
                UUID,
                Mode::Hosted,
                &format!("{cell} pristine --no-verify"),
            );
        }
    }
}

/// Vendored patches are judged by the committed artifact, never the
/// installed tree: a stale pristine `vendor/` copy (composer mirrors the
/// path dist at the next install) does not un-attest a verifying artifact.
#[test]
fn g_vendored_is_judged_by_the_artifact_not_the_installed_tree() {
    for flavor in ALL_FLAVORS {
        let tmp = project(flavor, Mode::Vendored, AFTER);
        let cwd = tmp.path();
        install(cwd, flavor, BEFORE);
        let api = honest_api();
        let out = vex(cwd, Some(&api), &[]);
        assert_attests(&out, PURL, UUID, Mode::Vendored, &format!("{flavor:?}"));
    }
}

// ──────────────────────────────────────────────────────────────────────
// h) conflicts and configured origins
// ──────────────────────────────────────────────────────────────────────

/// One lock wiring the same package to a hosted patch AND a vendored one
/// (a botched merge of two branches) attests neither.
#[test]
fn h_one_package_wired_to_two_patches_is_a_conflict() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let hosted = lock_entry(
        Flavor::Lock,
        &Wire::Hosted {
            url: hosted_url(SOCKET, UUID),
            pinned: true,
        },
    );
    let vendored = lock_entry(
        Flavor::Lock,
        &Wire::Vendored {
            rel: artifact_rel(OTHER_UUID),
            reference: OTHER_UUID.to_string(),
        },
    );
    write_lock_entries(cwd, Flavor::Lock, vec![hosted, vendored]);
    write_artifact(cwd, OTHER_UUID, AFTER);
    let api = PatchApi::start(vec![
        (UUID.into(), view(UUID, PURL)),
        (OTHER_UUID.into(), view(OTHER_UUID, PURL)),
    ]);
    let out = vex(cwd, Some(&api), &[]);
    assert_omits(&out, PURL, "wiring_conflict", "conflict");
}

/// A `--patch-server-url` deployment: its origin's hosted dists are patch
/// references only when the run names that origin (port included).
#[test]
fn h_configured_patch_server_origin_counts_only_when_configured() {
    for flavor in ALL_FLAVORS {
        let cell = format!("{flavor:?}");
        let origin = "https://patches.internal.example:8443";
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        write_wiring(
            cwd,
            flavor,
            &Wire::Hosted {
                url: hosted_url(origin, UUID),
                pinned: true,
            },
        );
        assert_nothing_discovered(cwd, &honest_api(), &format!("{cell} unconfigured"));
        let api = honest_api();
        let other_port = vex(
            cwd,
            Some(&api),
            &["--patch-server-url", "https://patches.internal.example"],
        );
        assert_eq!(other_port.code, Some(2), "{cell} wrong port:\n{other_port}");
        api.assert_no_requests();
        let out = vex(cwd, Some(&api), &["--patch-server-url", origin]);
        assert_attests(
            &out,
            PURL,
            UUID,
            Mode::Hosted,
            &format!("{cell} configured"),
        );
    }
}
