//! Manifest-less VEX for Poetry (`poetry.lock`) — HOSTED and VENDORED
//! patches, with NO `.socket/manifest.json` and (unless a cell says
//! otherwise) NO `.socket/vendor/{state,redirect-state}.json` ledgers.
//!
//! Hermetic: no Poetry, no Python, no network beyond a loopback wiremock
//! patch API, so it runs on every OS in the plain `test` job. The real-Poetry
//! twin (every major release, real `poetry install`) is
//! `e2e_vex_build/poetry.rs`.
//!
//! Every wiring file is produced by the SAME writers the product uses: the
//! fixture cells run the core `rewrite_poetry_lock` over the committed native
//! locks of every Poetry release (`socket-patch-core/tests/fixtures/poetry/
//! <0.12.17..2.4.3>/`: lock formats "0" / "1.0" / "1.1" / "2.0" / "2.1"), and
//! the writer-driven cells run the real `scan --redirect --vex` / `scan
//! --vendor --vex` / `apply --vex` / `vendor --vex` binaries against a
//! wiremock patch API. The package is renamed to a made-up `vexfixture`, so
//! no interpreter's global site-packages on the test host can hold a copy.
//!
//! The matrix, per release × {hosted, vendored}:
//!
//!   a. no manifest / no ledgers, online → attested with the right
//!      subcomponent purl, vulnerability id + CVE alias, `(redirected)` /
//!      `(vendored)` marker, exit 0, one `verified` event;
//!   b. `--offline` (and an API that 404s) → `record_unavailable`, exit 1,
//!      and under `--offline` NO request reaches the API;
//!   c. ledger present, manifest absent → attests offline from the ledger's
//!      record (no API request);
//!   d. lockfile reverted to the registry while the ledger (+ artifact)
//!      remain → `redirect_unwired` / `vendor_unwired`, `--no-verify` too;
//!   e. tampered installed tree (hosted) → `hash_mismatch`; tampered
//!      vendored wheel member → `vendor_hash_mismatch`;
//!   f. spoofs: a uuid on a non-Socket host is no reference; a Socket url
//!      under a source type Poetry would not install it from is no reference;
//!      a record whose purl or uuid differs from the lock → `record_mismatch`;
//!   g. hosted not installed → attests from the lock's sha256 pin (every
//!      pin spelling: package `files`, `[metadata.files]`, the lock-1.0
//!      `#sha256=` fragment); installed + patched → attests after hashing;
//!      installed pristine → `not_applied`; a pin-less entry needs an
//!      installed tree.

use crate::vex_e2e_common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
use socket_patch_core::patch::redirect::{FileEdit, RedirectState};
use socket_patch_core::utils::poetry_lock::rewrite_poetry_lock;
use socket_patch_core::vendor::state::{
    VendorArtifact, VendorEntry, VendorState, WiringAction, WiringRecord,
};
use vex_e2e_common::{
    assert_absent, binary, run_vex, statements_for, Marker, PatchApi, VexOutcome, VexRun, VexVia,
    DEFAULT_OUTPUT,
};

// ── fixture identity ────────────────────────────────────────────────────

const PKG: &str = "vexfixture";
/// The committed Poetry fixtures lock `urllib3==1.26.18` (renamed).
const VER: &str = "1.26.18";
const WHEEL: &str = "vexfixture-1.26.18-py2.py3-none-any.whl";
const HOSTED_UUID: &str = "9a1c3e5b-7d9f-4b1d-8f3a-5c7e9b1d3f5a";
const VENDORED_UUID: &str = "8b2d4f6a-8c0e-4a2c-9e4b-6d8f0a2c4e6b";
/// A uuid-SHAPED grant token: hosted urls carry it BEFORE the patch uuid.
const TOKEN: &str = "11111111-2222-4333-8444-555555555555";
const PRODUCT: &str = "pkg:pypi/app@0.1.0";
const GHSA: &str = "GHSA-poet-ryve-x001";
const CVE: &str = "CVE-2026-7101";
/// The patched module, site-packages relative (pypi record keys are).
const MODULE: &str = "vexfixture/__init__.py";
const PRISTINE: &[u8] = b"# vexfixture pristine\n";
const PATCHED: &[u8] = b"# vexfixture pristine\nSOCKET_PATCHED = 1\n";
const TAMPERED: &[u8] = b"# vexfixture tampered\n";
/// Org slug for the writer-driven (`scan`) cells.
const ORG: &str = "test-org";

fn purl() -> String {
    format!("pkg:pypi/{PKG}@{VER}")
}

/// The artifact-qualified purl the patch API files pypi patches under.
fn api_purl() -> String {
    format!("pkg:pypi/{PKG}@{VER}?artifact_id=py2-py3-none-any-whl")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// ── the committed Poetry locks ──────────────────────────────────────────

/// Every committed Poetry fixture, oldest first: lock format "0" (0.12),
/// "1.0" (1.0), "1.1" (1.1/1.2), "2.0" (1.3–1.8) and "2.1" (2.x).
const RELEASES: &[&str] = &[
    "0.12.17", "1.0.10", "1.1.15", "1.2.2", "1.3.2", "1.4.2", "1.5.1", "1.6.1", "1.7.1", "1.8.5",
    "2.0.1", "2.1.4", "2.2.1", "2.3.4", "2.4.3",
];

/// One release per lock format / major, for the heavier cells.
const REPRESENTATIVE: &[&str] = &[
    "0.12.17", "1.0.10", "1.1.15", "1.2.2", "1.8.5", "2.0.1", "2.4.3",
];

fn fixture(release: &str, file: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../socket-patch-core/tests/fixtures/poetry")
        .join(release)
        .join(file);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("urllib3", PKG)
}

/// Poetry lock format "0" (0.12) ignores url sources: the hosted rewriter
/// refuses it and so does discovery (asserted below).
fn supports_hosted(release: &str) -> bool {
    release != "0.12.17"
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Hosted,
    Vendored,
}

impl Mode {
    fn uuid(self) -> &'static str {
        match self {
            Mode::Hosted => HOSTED_UUID,
            Mode::Vendored => VENDORED_UUID,
        }
    }

    fn marker(self) -> Marker {
        match self {
            Mode::Hosted => Marker::Redirected,
            Mode::Vendored => Marker::Vendored,
        }
    }

    fn unwired(self) -> &'static str {
        match self {
            Mode::Hosted => "redirect_unwired",
            Mode::Vendored => "vendor_unwired",
        }
    }

    fn releases(self) -> Vec<&'static str> {
        RELEASES
            .iter()
            .copied()
            .filter(|r| self == Mode::Vendored || supports_hosted(r))
            .collect()
    }

    fn representative(self) -> Vec<&'static str> {
        REPRESENTATIVE
            .iter()
            .copied()
            .filter(|r| self == Mode::Vendored || supports_hosted(r))
            .collect()
    }
}

fn hosted_url_on(origin: &str, uuid: &str) -> String {
    format!("{origin}/patch/pypi/{PKG}/{VER}/{TOKEN}/{uuid}/{WHEEL}")
}

fn hosted_url(uuid: &str) -> String {
    hosted_url_on("https://patch.socket.dev", uuid)
}

fn vendored_rel(uuid: &str) -> String {
    format!(".socket/vendor/pypi/{uuid}/{WHEEL}")
}

/// The registry (pre-patch / reverted) project files of `release`.
fn native_files(release: &str) -> Vec<(&'static str, String)> {
    vec![
        ("pyproject.toml", fixture(release, "pyproject.toml")),
        ("poetry.lock", fixture(release, "poetry.lock")),
    ]
}

/// `release`'s lock after the writer wired `location` (a hosted url or a
/// `.socket/vendor/...` path) pinned to `sha256`.
fn wired_lock(release: &str, mode: Mode, location: &str, sha256: &str) -> String {
    rewrite_poetry_lock(
        &fixture(release, "poetry.lock"),
        PKG,
        VER,
        match mode {
            Mode::Hosted => "url",
            Mode::Vendored => "file",
        },
        location,
        WHEEL,
        sha256,
    )
    .unwrap_or_else(|e| panic!("poetry {release} {mode:?}: {e}"))
    .expect("lock has the entry")
}

// ── project scaffolding ─────────────────────────────────────────────────

/// A temp dir holding the project (`proj/`) and an isolated home for
/// Poetry's out-of-tree virtualenv lookups (`home/`).
struct Proj {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
}

impl Proj {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("proj");
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        Proj {
            _tmp: tmp,
            root,
            home,
        }
    }

    fn write(&self, rel: &str, bytes: impl AsRef<[u8]>) {
        let path = self.root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn write_files(&self, files: &[(&str, String)]) {
        for (name, text) in files {
            self.write(name, text);
        }
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.root.join(rel)).unwrap()
    }

    fn exists(&self, rel: &str) -> bool {
        self.root.join(rel).exists()
    }

    fn remove(&self, rel: &str) {
        match std::fs::remove_file(self.root.join(rel)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("{rel}: {e}"),
        }
    }

    /// Site-packages of the in-project `.venv` (PEP 405 layout per OS).
    fn site(&self) -> PathBuf {
        if cfg!(windows) {
            self.root.join(".venv/Lib/site-packages")
        } else {
            self.root.join(".venv/lib/python3.12/site-packages")
        }
    }

    /// An EMPTY in-project venv: keeps the crawl off the host interpreters
    /// (a project with no venv falls back to the global site-packages).
    fn empty_venv(&self) {
        std::fs::create_dir_all(self.site()).unwrap();
    }

    /// Install `vexfixture==1.26.18` into `.venv` with `module` bytes.
    fn install(&self, module: &[u8]) {
        let site = self.site();
        let dist = site.join(format!("{PKG}-{VER}.dist-info"));
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::create_dir_all(site.join(PKG)).unwrap();
        std::fs::write(site.join(MODULE), module).unwrap();
        std::fs::write(
            dist.join("METADATA"),
            format!("Metadata-Version: 2.1\nName: {PKG}\nVersion: {VER}\n"),
        )
        .unwrap();
        std::fs::write(
            dist.join("WHEEL"),
            "Wheel-Version: 1.0\nGenerator: socket-patch-tests\nRoot-Is-Purelib: true\n\
             Tag: py2-none-any\nTag: py3-none-any\n",
        )
        .unwrap();
        let rec = |rel: &str, bytes: &[u8]| {
            use base64::Engine as _;
            let digest =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes));
            format!("{rel},sha256={digest},{}\n", bytes.len())
        };
        let metadata = std::fs::read(dist.join("METADATA")).unwrap();
        let wheel = std::fs::read(dist.join("WHEEL")).unwrap();
        let record = format!(
            "{}{}{}{PKG}-{VER}.dist-info/RECORD,,\n",
            rec(MODULE, module),
            rec(&format!("{PKG}-{VER}.dist-info/METADATA"), &metadata),
            rec(&format!("{PKG}-{VER}.dist-info/WHEEL"), &wheel),
        );
        std::fs::write(dist.join("RECORD"), record).unwrap();
    }
}

/// A wheel (zip) holding `vexfixture/__init__.py` = `module` plus its
/// dist-info.
fn build_wheel(module: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        let dist = format!("{PKG}-{VER}.dist-info");
        let members: Vec<(String, Vec<u8>)> = vec![
            (MODULE.to_string(), module.to_vec()),
            (
                format!("{dist}/METADATA"),
                format!("Metadata-Version: 2.1\nName: {PKG}\nVersion: {VER}\n\n").into_bytes(),
            ),
            (
                format!("{dist}/WHEEL"),
                b"Wheel-Version: 1.0\nGenerator: socket-patch-tests\nRoot-Is-Purelib: true\n\
                  Tag: py2-none-any\nTag: py3-none-any\n"
                    .to_vec(),
            ),
            (format!("{dist}/RECORD"), Vec::new()),
        ];
        for (name, bytes) in members {
            writer.start_file(name, opts).unwrap();
            writer.write_all(&bytes).unwrap();
        }
        writer.finish().unwrap();
    }
    buf.into_inner()
}

/// Wire `release` in `mode` into `p` exactly as the writers leave it:
/// hosted → the Socket url pinned to the patched wheel's sha256; vendored →
/// the committed `.socket/vendor/pypi/<uuid>/<wheel>` (holding `artifact`
/// module bytes) pinned to its sha256. Returns the pin.
fn wire(p: &Proj, release: &str, mode: Mode, artifact: &[u8]) -> String {
    let wheel = build_wheel(artifact);
    let sha = sha256_hex(&wheel);
    let location = match mode {
        Mode::Hosted => hosted_url(HOSTED_UUID),
        Mode::Vendored => {
            let rel = vendored_rel(VENDORED_UUID);
            p.write(&rel, &wheel);
            rel
        }
    };
    p.write("pyproject.toml", fixture(release, "pyproject.toml"));
    p.write("poetry.lock", wired_lock(release, mode, &location, &sha));
    sha
}

// ── records, views, ledgers ─────────────────────────────────────────────

fn record(uuid: &str) -> PatchRecord {
    let mut files = HashMap::new();
    files.insert(
        MODULE.to_string(),
        PatchFileInfo {
            before_hash: compute_git_sha256_from_bytes(PRISTINE),
            after_hash: compute_git_sha256_from_bytes(PATCHED),
        },
    );
    let mut vulnerabilities = HashMap::new();
    vulnerabilities.insert(
        GHSA.to_string(),
        VulnerabilityInfo {
            cves: vec![CVE.to_string()],
            summary: "vexfixture advisory".to_string(),
            severity: "high".to_string(),
            description: "d".to_string(),
        },
    );
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: "2026-09-01T00:00:00Z".to_string(),
        files,
        vulnerabilities,
        description: "vexfixture patch".to_string(),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

/// The patch API's view of `uuid` (the `GET …/view/<uuid>` body).
fn view(uuid: &str, purl: &str) -> Value {
    json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "Tue, 01 Sep 2026 00:00:00 GMT",
        "files": { MODULE: {
            "beforeHash": compute_git_sha256_from_bytes(PRISTINE),
            "afterHash": compute_git_sha256_from_bytes(PATCHED),
        } },
        "vulnerabilities": { GHSA: {
            "cves": [CVE], "summary": "vexfixture advisory", "severity": "high",
            "description": "d"
        } },
        "description": "vexfixture patch",
        "license": "MIT",
        "tier": "free",
    })
}

/// A patch API serving the wired patch's view (both view routes).
fn api_for(mode: Mode) -> PatchApi {
    PatchApi::start(vec![(mode.uuid().into(), view(mode.uuid(), &api_purl()))])
}

/// `.socket/vendor/redirect-state.json` with `record` filed under
/// `ledger_purl` and the poetry-lock edit the hosted writer records.
fn write_redirect_ledger(p: &Proj, ledger_purl: &str, record: PatchRecord) {
    let mut state = RedirectState::new();
    state.records.insert(ledger_purl.to_string(), record);
    state.edits.push(FileEdit {
        path: "poetry.lock".to_string(),
        kind: "redirect_poetry_lock_package".to_string(),
        action: "rewritten".to_string(),
        key: Some(format!("{PKG}@{VER}")),
        original: None,
        new: None,
    });
    p.write(
        ".socket/vendor/redirect-state.json",
        serde_json::to_string_pretty(&state).unwrap(),
    );
}

/// `.socket/vendor/state.json` with one poetry entry embedding `record`
/// (the shape every current vendor writer persists).
fn write_vendor_ledger(p: &Proj, sha: &str, record: PatchRecord) {
    let mut state = VendorState::new();
    state.entries.insert(
        api_purl(),
        VendorEntry {
            ecosystem: "pypi".to_string(),
            base_purl: purl(),
            uuid: record.uuid.clone(),
            artifact: VendorArtifact {
                path: vendored_rel(&record.uuid),
                sha256: sha.to_string(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring: vec![WiringRecord {
                file: "poetry.lock".to_string(),
                kind: "poetry_lock_package".to_string(),
                action: WiringAction::Rewritten,
                key: None,
                original: None,
                new: None,
            }],
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: Some(record),
            flavor: Some("poetry".to_string()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        },
    );
    p.write(
        ".socket/vendor/state.json",
        serde_json::to_string_pretty(&state).unwrap(),
    );
}

/// The ledger `mode`'s writer persists next to the wiring `wire` left.
fn write_ledger(p: &Proj, mode: Mode, sha: &str, record: PatchRecord) {
    match mode {
        Mode::Hosted => write_redirect_ledger(p, &api_purl(), record),
        Mode::Vendored => write_vendor_ledger(p, sha, record),
    }
}

fn strip_ledgers(p: &Proj) {
    vex_e2e_common::strip_ledgers(&p.root);
}

// ── running the CLI ─────────────────────────────────────────────────────

/// Poetry's out-of-tree virtualenv / config lookups, pointed into `p.home`
/// so the developer's own Poetry setup can never feed the crawl.
fn poetry_envs(p: &Proj) -> Vec<(String, std::ffi::OsString)> {
    vec![
        (
            "POETRY_CACHE_DIR".into(),
            p.home.join("poetry-cache").into(),
        ),
        (
            "POETRY_VIRTUALENVS_PATH".into(),
            p.home.join("poetry-venvs").into(),
        ),
        (
            "POETRY_CONFIG_DIR".into(),
            p.home.join("poetry-config").into(),
        ),
    ]
}

/// Standalone `vex --json` over `p` (no stale document left from a prior
/// run): online against `api` (public proxy) unless `offline`, where `api`
/// is still configured so a stray request would be observed.
fn vex(p: &Proj, api: &PatchApi, offline: bool, extra: &[&str]) -> VexOutcome {
    let _ = std::fs::remove_file(p.root.join(DEFAULT_OUTPUT));
    let mut run = VexRun {
        offline,
        proxy_url: Some(api.uri()),
        product: Some(PRODUCT.to_string()),
        envs: poetry_envs(p),
        ..VexRun::default()
    };
    for arg in extra {
        run = run.arg(*arg);
    }
    run_vex(&binary(), &p.root, &run)
}

/// Exactly one statement for `api_purl()` from `uuid` with `mode`'s marker
/// and the fixture advisory, plus the one matching `verified` event.
fn assert_attested(what: &str, out: &VexOutcome, mode: Mode, uuid: &str) {
    assert_eq!(out.code, Some(0), "{what}: {out}");
    assert_eq!(out.envelope["status"], "success", "{what}: {out}");
    let doc = out.doc();
    vex_e2e_common::assert_attested(doc, &purl(), uuid, mode.marker(), &[(GHSA, &[CVE])]);
    let stmts = doc["statements"].as_array().expect("statements");
    assert_eq!(stmts.len(), 1, "{what}: {doc}");
    assert_eq!(stmts[0]["products"][0]["@id"], PRODUCT, "{what}");
    let subs = stmts[0]["products"][0]["subcomponents"].as_array().unwrap();
    assert_eq!(subs.len(), 1, "{what}: {doc}");
    assert_eq!(subs[0]["@id"], api_purl(), "{what}: {doc}");
    let events = out.envelope["events"].as_array().unwrap();
    assert_eq!(events.len(), 1, "{what}: {out}");
    assert_eq!(events[0]["action"], "verified", "{what}: {out}");
    assert_eq!(events[0]["purl"], api_purl(), "{what}: {out}");
}

/// Nothing attested: exit 1 `no_applicable_patches`, the purl skipped with
/// `reason`, and no document written.
fn assert_omitted(what: &str, out: &VexOutcome, reason: &str) {
    vex_e2e_common::assert_omitted(out, &purl(), reason, what);
}

/// No manifest, no ledger and no reference: exit 2 `manifest_not_found`.
fn assert_nothing_found(what: &str, out: &VexOutcome) {
    assert_eq!(out.code, Some(2), "{what}: {out}");
    assert_eq!(
        out.envelope["error"]["code"], "manifest_not_found",
        "{what}: {out}"
    );
    assert!(out.doc.is_none(), "{what}");
}

fn assert_no_manifest_written(p: &Proj, what: &str) {
    assert!(
        !p.exists(".socket/manifest.json"),
        "{what}: vex must never write the manifest"
    );
}

// ════════════════════════════════════════════════════════════════════════
// a + b + g(not installed): lockfile alone, no manifest, no ledgers
// ════════════════════════════════════════════════════════════════════════

/// (a) online → attested from the API record; (b) `--offline` →
/// `record_unavailable` with zero requests; (b') an API with no view for
/// the uuid (404) → `record_unavailable`. Nothing is installed, so hosted
/// attests from the lock's sha256 pin (g). Every release, both modes.
#[test]
fn lockfile_only_attests_online_and_is_unavailable_offline() {
    for mode in [Mode::Hosted, Mode::Vendored] {
        for release in mode.releases() {
            let what = format!("poetry {release} {mode:?}");
            let p = Proj::new();
            wire(&p, release, mode, PATCHED);
            p.empty_venv();
            assert!(!p.exists(".socket/manifest.json"));
            assert!(!p.exists(".socket/vendor/state.json"));
            assert!(!p.exists(".socket/vendor/redirect-state.json"));

            let api = api_for(mode);
            let out = vex(&p, &api, true, &[]);
            assert_omitted(&format!("{what} offline"), &out, "record_unavailable");
            api.assert_no_requests();

            let empty = PatchApi::empty();
            let out = vex(&p, &empty, false, &[]);
            assert_omitted(&format!("{what} 404"), &out, "record_unavailable");
            assert!(empty.view_requests(mode.uuid()) >= 1, "{what}");

            let out = vex(&p, &api, false, &[]);
            assert_attested(&what, &out, mode, mode.uuid());
            assert!(
                api.view_requests(mode.uuid()) >= 1,
                "{what}: record from API"
            );
            // --no-verify skips hashing, never the record / wiring gates.
            let out = vex(&p, &api, false, &["--no-verify"]);
            assert_attested(&format!("{what} --no-verify"), &out, mode, mode.uuid());
            assert_no_manifest_written(&p, &what);
        }
    }
}

/// Git checkouts on Windows (autocrlf) hand Poetry — and `vex` — a CRLF
/// lock; the wiring reads the same.
#[test]
fn crlf_lock_attests_like_lf() {
    for mode in [Mode::Hosted, Mode::Vendored] {
        for release in ["1.1.15", "1.8.5", "2.4.3"] {
            let what = format!("poetry {release} {mode:?} CRLF");
            let p = Proj::new();
            wire(&p, release, mode, PATCHED);
            p.empty_venv();
            let crlf = p
                .read("poetry.lock")
                .replace("\r\n", "\n")
                .replace('\n', "\r\n");
            p.write("poetry.lock", &crlf);
            let api = api_for(mode);
            let out = vex(&p, &api, false, &[]);
            assert_attested(&what, &out, mode, mode.uuid());
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// c: ledger present, manifest absent → offline attestation from the ledger
// ════════════════════════════════════════════════════════════════════════

#[test]
fn ledger_without_manifest_attests_offline() {
    for mode in [Mode::Hosted, Mode::Vendored] {
        for release in mode.representative() {
            let what = format!("poetry {release} {mode:?} ledger");
            let p = Proj::new();
            let sha = wire(&p, release, mode, PATCHED);
            p.empty_venv();
            write_ledger(&p, mode, &sha, record(mode.uuid()));
            let api = PatchApi::empty();
            for extra in [&[][..], &["--no-verify"][..]] {
                let out = vex(&p, &api, true, extra);
                assert_attested(&format!("{what} {extra:?}"), &out, mode, mode.uuid());
            }
            api.assert_no_requests();
            assert_no_manifest_written(&p, &what);
        }
    }
}

/// The lock wires a NEWER patch than the ledger records for the same
/// package: the wired uuid wins, so the stale ledger record cannot stand in
/// for it — offline there is no record for the wired patch.
#[test]
fn ledger_record_for_a_superseded_patch_does_not_attest_the_wired_one() {
    const OLD: &str = "6c9e3a4d-5f6b-4c7d-8e8f-9a0b1c2d3e4f";
    for mode in [Mode::Hosted, Mode::Vendored] {
        for release in mode.representative() {
            let what = format!("poetry {release} {mode:?} superseded");
            let p = Proj::new();
            let sha = wire(&p, release, mode, PATCHED);
            p.empty_venv();
            write_ledger(&p, mode, &sha, record(OLD));
            let api = api_for(mode);
            let out = vex(&p, &api, true, &[]);
            assert_omitted(&what, &out, "record_unavailable");
            let out = vex(&p, &api, false, &[]);
            assert_attested(&what, &out, mode, mode.uuid());
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// d: lockfile reverted while the ledger (and artifact) remain
// ════════════════════════════════════════════════════════════════════════

/// After the wiring is reverted to the registry lock (the committed
/// artifact and the ledger left behind), the ledger record must not attest
/// — with or without `--no-verify`, offline or online. Without the ledger,
/// the leftover artifact alone names nothing: `manifest_not_found`.
#[test]
fn reverted_lockfile_never_attests_a_leftover_ledger() {
    for mode in [Mode::Hosted, Mode::Vendored] {
        for release in mode.releases() {
            let what = format!("poetry {release} {mode:?} reverted");
            let p = Proj::new();
            let sha = wire(&p, release, mode, PATCHED);
            p.empty_venv();
            write_ledger(&p, mode, &sha, record(mode.uuid()));
            let api = api_for(mode);
            let out = vex(&p, &api, true, &[]);
            assert_eq!(out.code, Some(0), "{what} (live): {out}");

            p.write_files(&native_files(release));
            for extra in [&[][..], &["--no-verify"][..]] {
                let out = vex(&p, &api, true, extra);
                assert_omitted(&format!("{what} {extra:?}"), &out, mode.unwired());
                let out = vex(&p, &api, false, extra);
                assert_omitted(&format!("{what} online {extra:?}"), &out, mode.unwired());
            }

            strip_ledgers(&p);
            if mode == Mode::Vendored {
                assert!(p.exists(&vendored_rel(VENDORED_UUID)), "{what}");
            }
            let out = vex(&p, &api, false, &[]);
            assert_nothing_found(&format!("{what} (no ledger)"), &out);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// e: tampered installed tree (hosted) / tampered vendored wheel member
// ════════════════════════════════════════════════════════════════════════

#[test]
fn tampered_evidence_is_omitted() {
    for release in Mode::Hosted.representative() {
        let what = format!("poetry {release} hosted tampered install");
        let p = Proj::new();
        let sha = wire(&p, release, Mode::Hosted, PATCHED);
        p.install(TAMPERED);
        let api = api_for(Mode::Hosted);
        let out = vex(&p, &api, false, &[]);
        assert_omitted(&what, &out, "hash_mismatch");
        write_ledger(&p, Mode::Hosted, &sha, record(HOSTED_UUID));
        let out = vex(&p, &api, true, &[]);
        assert_omitted(&format!("{what} + ledger"), &out, "hash_mismatch");
    }
    for release in Mode::Vendored.representative() {
        let what = format!("poetry {release} vendored tampered wheel");
        let p = Proj::new();
        // The committed wheel's member does not hash to the record's
        // afterHash (the lock pin matches the tampered wheel — a hand-edit
        // that re-pinned it).
        let sha = wire(&p, release, Mode::Vendored, TAMPERED);
        p.empty_venv();
        let api = api_for(Mode::Vendored);
        let out = vex(&p, &api, false, &[]);
        assert_omitted(&what, &out, "vendor_hash_mismatch");
        write_ledger(&p, Mode::Vendored, &sha, record(VENDORED_UUID));
        let out = vex(&p, &api, true, &[]);
        assert_omitted(&format!("{what} + ledger"), &out, "vendor_hash_mismatch");

        // A committed wheel swapped AFTER the lock was pinned: the lock's
        // sha256 no longer names the artifact on disk.
        let p = Proj::new();
        wire(&p, release, Mode::Vendored, PATCHED);
        p.empty_venv();
        p.write(&vendored_rel(VENDORED_UUID), build_wheel(TAMPERED));
        let out = vex(&p, &api, false, &[]);
        assert_eq!(out.code, Some(1), "{what} (swapped wheel): {out}");
        assert!(out.doc.is_none(), "{what} (swapped wheel)");

        // A deleted artifact is no evidence either.
        p.remove(&vendored_rel(VENDORED_UUID));
        let out = vex(&p, &api, false, &[]);
        assert_eq!(out.code, Some(1), "{what} (artifact deleted): {out}");
        assert!(out.doc.is_none(), "{what} (artifact deleted)");
    }
}

// ════════════════════════════════════════════════════════════════════════
// f: spoofed references and mismatched records
// ════════════════════════════════════════════════════════════════════════

/// A patch uuid in a url on a host that is not Socket's patch server —
/// including look-alike hosts — is the user's own dependency source, never
/// a patch reference: nothing is found and nothing is fetched. The
/// operator's `--patch-server-url` origin counts only when configured.
#[test]
fn uuid_on_a_non_socket_host_is_not_a_reference() {
    for release in Mode::Hosted.representative() {
        for origin in [
            "https://evil.example",
            "https://patch.socket.dev.evil.example",
            "https://patch.socket.dev@evil.example",
            "https://evil.example/https://patch.socket.dev",
            "http://patch.socket.dev",
            "https://patch.socket.dev:8443",
        ] {
            let what = format!("poetry {release} {origin}");
            let p = Proj::new();
            p.empty_venv();
            let wheel = build_wheel(PATCHED);
            p.write("pyproject.toml", fixture(release, "pyproject.toml"));
            p.write(
                "poetry.lock",
                wired_lock(
                    release,
                    Mode::Hosted,
                    &hosted_url_on(origin, HOSTED_UUID),
                    &sha256_hex(&wheel),
                ),
            );
            let api = api_for(Mode::Hosted);
            let out = vex(&p, &api, false, &[]);
            assert_nothing_found(&what, &out);
            api.assert_no_requests();
        }
    }

    // A self-hosted patch server's origin is a reference only when named.
    let p = Proj::new();
    p.empty_venv();
    let api = api_for(Mode::Hosted);
    let wheel = build_wheel(PATCHED);
    p.write("pyproject.toml", fixture("2.4.3", "pyproject.toml"));
    p.write(
        "poetry.lock",
        wired_lock(
            "2.4.3",
            Mode::Hosted,
            &hosted_url_on(&api.uri(), HOSTED_UUID),
            &sha256_hex(&wheel),
        ),
    );
    assert_nothing_found("unconfigured origin", &vex(&p, &api, false, &[]));
    api.assert_no_requests();
    let out = vex(&p, &api, false, &["--patch-server-url", &api.uri()]);
    assert_attested("configured origin", &out, Mode::Hosted, HOSTED_UUID);
}

/// A Socket artifact under a `[package.source]` type Poetry would not
/// install it from (`legacy` index, a vendored wheel as `url`, a hosted
/// url as `file`), and a hosted url in a format-"0" lock (Poetry 0.12
/// ignores url sources), wire nothing.
#[test]
fn socket_artifact_poetry_would_not_install_is_not_a_reference() {
    let url = hosted_url(HOSTED_UUID);
    let rel = vendored_rel(VENDORED_UUID);
    let sha = sha256_hex(&build_wheel(PATCHED));
    let cases = [
        (
            "legacy index",
            "2.4.3",
            wired_lock("2.4.3", Mode::Hosted, &url, &sha)
                .replace("type = \"url\"", "type = \"legacy\""),
        ),
        (
            "vendored wheel as url",
            "2.4.3",
            wired_lock("2.4.3", Mode::Vendored, &rel, &sha)
                .replace("type = \"file\"", "type = \"url\""),
        ),
        (
            "hosted url as file",
            "1.8.5",
            wired_lock("1.8.5", Mode::Hosted, &url, &sha)
                .replace("type = \"url\"", "type = \"file\""),
        ),
        (
            "format 0 url",
            "0.12.17",
            wired_lock("0.12.17", Mode::Vendored, &rel, &sha)
                .replace("type = \"file\"", "type = \"url\"")
                .replace(&rel, &url),
        ),
    ];
    for (label, release, lock) in cases {
        let p = Proj::new();
        p.empty_venv();
        p.write("pyproject.toml", fixture(release, "pyproject.toml"));
        p.write(&rel, build_wheel(PATCHED));
        p.write("poetry.lock", &lock);
        let api = PatchApi::start(vec![
            (HOSTED_UUID.into(), view(HOSTED_UUID, &api_purl())),
            (VENDORED_UUID.into(), view(VENDORED_UUID, &api_purl())),
        ]);
        let out = vex(&p, &api, false, &[]);
        assert_nothing_found(label, &out);
        api.assert_no_requests();
        assert!(
            out.envelope["warnings"].to_string().contains("poetry.lock"),
            "{label}: the refused reference is diagnosed: {out}"
        );
    }
}

/// A `.socket/vendor`-LOOKING path that is not this project's committed
/// artifact dir is no vendored reference.
#[test]
fn vendor_shaped_path_outside_the_project_vendor_dir_is_not_a_reference() {
    for release in Mode::Vendored.representative() {
        for rel in [
            format!("vendor/pypi/{VENDORED_UUID}/{WHEEL}"),
            format!("wheels/.socket/vendor/pypi/{VENDORED_UUID}/{WHEEL}"),
            format!("../.socket/vendor/pypi/{VENDORED_UUID}/{WHEEL}"),
        ] {
            let what = format!("poetry {release} {rel}");
            let p = Proj::new();
            p.empty_venv();
            let wheel = build_wheel(PATCHED);
            if !rel.starts_with("..") {
                p.write(&rel, &wheel);
            }
            p.write("pyproject.toml", fixture(release, "pyproject.toml"));
            p.write(
                "poetry.lock",
                wired_lock(release, Mode::Vendored, &rel, &sha256_hex(&wheel)),
            );
            let api = api_for(Mode::Vendored);
            let out = vex(&p, &api, false, &[]);
            assert_ne!(out.code, Some(0), "{what}: {out}");
            assert!(out.doc.is_none(), "{what}: {out}");
            api.assert_no_requests();
        }
    }
}

/// The record fetched for the WIRED uuid must name the lock's package AND
/// carry that uuid; otherwise → `record_mismatch`, never attested.
#[test]
fn record_naming_another_package_or_patch_is_a_mismatch() {
    const OTHER_UUID: &str = "7d0f4b5e-6a7c-4d8e-9f0a-1b2c3d4e5f60";
    for mode in [Mode::Hosted, Mode::Vendored] {
        for release in mode.representative() {
            let uuid = mode.uuid();
            let bodies = [
                ("other package", view(uuid, "pkg:pypi/other-package@1.0.0")),
                (
                    "other version",
                    view(uuid, &format!("pkg:pypi/{PKG}@9.9.9")),
                ),
                ("other uuid", view(OTHER_UUID, &api_purl())),
            ];
            for (label, body) in bodies {
                let what = format!("poetry {release} {mode:?} {label}");
                let p = Proj::new();
                wire(&p, release, mode, PATCHED);
                p.empty_venv();
                let api = PatchApi::start(vec![(uuid.into(), body)]);
                let out = vex(&p, &api, false, &[]);
                assert_omitted(&what, &out, "record_mismatch");
            }

            // A LOCAL record for the wired uuid filed under another package
            // (a hand-edited ledger) is a mismatch too.
            let what = format!("poetry {release} {mode:?} ledger names another package");
            let p = Proj::new();
            wire(&p, release, mode, PATCHED);
            p.empty_venv();
            write_redirect_ledger(&p, "pkg:pypi/other-package@1.0.0", record(uuid));
            let api = PatchApi::empty();
            let out = vex(&p, &api, true, &[]);
            assert_omitted(&what, &out, "record_mismatch");
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// g: hosted evidence — the lock pin before install, the installed tree after
// ════════════════════════════════════════════════════════════════════════

/// Once installed, the installed tree is the evidence: patched attests
/// after hashing (online and from the ledger offline), pristine is
/// `not_applied` even though the pinned wiring alone would have attested.
#[test]
fn hosted_installed_tree_is_hash_verified() {
    for release in Mode::Hosted.representative() {
        let what = format!("poetry {release} hosted installed");
        let p = Proj::new();
        let sha = wire(&p, release, Mode::Hosted, PATCHED);
        let api = api_for(Mode::Hosted);

        p.install(PATCHED);
        let out = vex(&p, &api, false, &[]);
        assert_attested(&what, &out, Mode::Hosted, HOSTED_UUID);

        p.install(PRISTINE);
        let out = vex(&p, &api, false, &[]);
        assert_omitted(&format!("{what} pristine"), &out, "not_applied");

        write_ledger(&p, Mode::Hosted, &sha, record(HOSTED_UUID));
        let out = vex(&p, &api, true, &[]);
        assert_omitted(&format!("{what} pristine + ledger"), &out, "not_applied");
        p.install(PATCHED);
        let out = vex(&p, &api, true, &[]);
        assert_attested(&format!("{what} + ledger"), &out, Mode::Hosted, HOSTED_UUID);
    }
}

/// Every pin spelling the hosted writer leaves across lock formats counts
/// on its own: the package-level `files` list (all formats ≥ 1.0), the
/// `[metadata.files]` table (1.0 / 1.1) and the lock-1.0 `#sha256=<hex>&`
/// url fragment. With EVERY pin stripped the entry was not written by
/// socket-patch, so it cannot attest from the lock alone
/// (`package_not_found` until installed) — only a verifying installed tree
/// can.
#[test]
fn every_hosted_pin_spelling_attests_and_a_pinless_entry_needs_an_install() {
    for release in ["1.0.10", "1.1.15", "1.2.2", "1.8.5", "2.4.3"] {
        let what = format!("poetry {release} pins");
        let p = Proj::new();
        let sha = wire(&p, release, Mode::Hosted, PATCHED);
        p.empty_venv();
        let lock = p.read("poetry.lock");
        let api = api_for(Mode::Hosted);
        let files_line = format!("files = [{{ file = \"{WHEEL}\", hash = \"sha256:{sha}\" }}]");
        let metadata_entry = format!("{PKG} = [{{ file = \"{WHEEL}\", hash = \"sha256:{sha}\" }}]");
        let fragment = format!("#sha256={sha}&");
        let spellings: Vec<(&str, &str)> = [
            ("package files", files_line.as_str()),
            ("metadata.files", metadata_entry.as_str()),
            ("url fragment", fragment.as_str()),
        ]
        .into_iter()
        .filter(|(_, s)| lock.contains(*s))
        .collect();
        assert!(!spellings.is_empty(), "{what}: no pin found:\n{lock}");
        if release.starts_with("1.0") {
            assert_eq!(spellings.len(), 3, "{what}: 1.0 writes all three:\n{lock}");
        }
        // Each spelling alone.
        for (keep, _) in &spellings {
            let mut only = lock.clone();
            for (label, text) in &spellings {
                if label != keep {
                    only = strip_pin(&only, text);
                }
            }
            p.write("poetry.lock", &only);
            let out = vex(&p, &api, false, &[]);
            assert_attested(
                &format!("{what} only {keep}"),
                &out,
                Mode::Hosted,
                HOSTED_UUID,
            );
        }
        // None.
        let mut stripped = lock.clone();
        for (_, text) in &spellings {
            stripped = strip_pin(&stripped, text);
        }
        assert!(!stripped.contains(&sha), "{what}: {stripped}");
        p.write("poetry.lock", &stripped);
        let out = vex(&p, &api, false, &[]);
        assert_omitted(&format!("{what} pin-less"), &out, "package_not_found");
        p.install(PATCHED);
        let out = vex(&p, &api, false, &[]);
        assert_attested(
            &format!("{what} pin-less installed"),
            &out,
            Mode::Hosted,
            HOSTED_UUID,
        );
    }
}

/// What `poetry lock --no-update` on Poetry 1.1 / 1.2 does to a redirected
/// lock-1.1 unit (measured, see `in_process_redirect_poetry.rs`): keeps
/// `[package.source]`, drops the inserted package-level `files` line and
/// re-lays the `[metadata.files]` entry into Poetry's multi-line array. The
/// relocked lock still pins the patched wheel, so it still attests — and
/// a ledger left from before the relock stays live.
#[test]
fn poetry_1x_relock_of_a_hosted_lock_still_attests() {
    for release in ["1.1.15", "1.2.2"] {
        let what = format!("poetry {release} relocked");
        let p = Proj::new();
        let sha = wire(&p, release, Mode::Hosted, PATCHED);
        p.empty_venv();
        let lock = p.read("poetry.lock");
        let entry = format!("{PKG} = [{{ file = ");
        let mut relocked = String::new();
        for line in lock.lines() {
            if line.starts_with("files = [{ file = ") {
                continue;
            }
            if let Some(rest) = line.strip_prefix(&entry) {
                let inner = rest.trim_end_matches(" }]");
                relocked.push_str(&format!("{PKG} = [\n    {{file = {inner}}},\n]\n"));
                continue;
            }
            relocked.push_str(line);
            relocked.push('\n');
        }
        assert_ne!(relocked, lock, "{what}: the relock re-laid the unit");
        assert!(
            !relocked.contains("files = [{ file = "),
            "{what}:\n{relocked}"
        );
        assert!(
            relocked.contains(&sha),
            "{what}: metadata pin kept:\n{relocked}"
        );
        p.write("poetry.lock", &relocked);
        let api = api_for(Mode::Hosted);
        let out = vex(&p, &api, false, &[]);
        assert_attested(&what, &out, Mode::Hosted, HOSTED_UUID);
        write_ledger(&p, Mode::Hosted, &sha, record(HOSTED_UUID));
        let out = vex(&p, &api, true, &["--no-verify"]);
        assert_attested(&format!("{what} + ledger"), &out, Mode::Hosted, HOSTED_UUID);
    }
}

/// Poetry records a package under its own spelling (`zope.interface`,
/// `ruamel.yaml`, a 1.x lock's display case) while the patch API names it by
/// a PURL; wheel files and dist-info dirs use yet another (`zope_interface`).
/// Every spelling of one project is the same package: the lock entry
/// attests under the API record's purl whichever way either side spells it,
/// hosted before and after install, and vendored.
#[test]
fn non_canonical_package_spellings_attest() {
    const DIST: &str = "vex_fixture";
    let wheel_name = format!("{DIST}-{VER}-py2.py3-none-any.whl");
    let module = format!("{DIST}/__init__.py");
    let build = |bytes: &[u8]| {
        use std::io::Write as _;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            let dist = format!("{DIST}-{VER}.dist-info");
            for (name, data) in [
                (module.clone(), bytes.to_vec()),
                (
                    format!("{dist}/METADATA"),
                    format!("Metadata-Version: 2.1\nName: vex.fixture\nVersion: {VER}\n\n")
                        .into_bytes(),
                ),
                (
                    format!("{dist}/WHEEL"),
                    b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n".to_vec(),
                ),
                (format!("{dist}/RECORD"), Vec::new()),
            ] {
                w.start_file(name, opts).unwrap();
                w.write_all(&data).unwrap();
            }
            w.finish().unwrap();
        }
        buf.into_inner()
    };
    for (lock_name, api_name) in [
        ("vex.fixture", "vex.fixture"),
        ("vex.fixture", "vex-fixture"),
        ("Vex_Fixture", "vex-fixture"),
    ] {
        for mode in [Mode::Hosted, Mode::Vendored] {
            let what = format!("lock {lock_name:?} / API {api_name:?} {mode:?}");
            let p = Proj::new();
            let wheel = build(PATCHED);
            let sha = sha256_hex(&wheel);
            let uuid = mode.uuid();
            let location = match mode {
                Mode::Hosted => format!(
                    "https://patch.socket.dev/patch/pypi/{lock_name}/{VER}/{TOKEN}/{uuid}/{wheel_name}"
                ),
                Mode::Vendored => {
                    let rel = format!(".socket/vendor/pypi/{uuid}/{wheel_name}");
                    p.write(&rel, &wheel);
                    rel
                }
            };
            let native = fixture("2.4.3", "poetry.lock").replace(PKG, lock_name);
            let lock = rewrite_poetry_lock(
                &native,
                lock_name,
                VER,
                if mode == Mode::Hosted { "url" } else { "file" },
                &location,
                &wheel_name,
                &sha,
            )
            .unwrap_or_else(|e| panic!("{what}: {e}"))
            .expect("entry");
            p.write(
                "pyproject.toml",
                fixture("2.4.3", "pyproject.toml").replace(PKG, lock_name),
            );
            p.write("poetry.lock", &lock);
            p.empty_venv();
            let api_purl = format!("pkg:pypi/{api_name}@{VER}");
            let mut body = view(uuid, &api_purl);
            let files = body["files"][MODULE].clone();
            body["files"] = json!({ module.clone(): files });
            let api = PatchApi::start(vec![(uuid.into(), body)]);
            let out = vex(&p, &api, false, &[]);
            assert_eq!(out.code, Some(0), "{what}: {out}");
            let stmts = statements_for(out.doc(), &api_purl);
            assert_eq!(stmts.len(), 1, "{what}: {out}");
            if mode == Mode::Hosted {
                // Installed (dist-info under the wheel spelling): verified.
                let site = p.site();
                let dist = site.join(format!("{DIST}-{VER}.dist-info"));
                std::fs::create_dir_all(&dist).unwrap();
                std::fs::create_dir_all(site.join(DIST)).unwrap();
                std::fs::write(site.join(&module), PATCHED).unwrap();
                std::fs::write(
                    dist.join("METADATA"),
                    format!("Metadata-Version: 2.1\nName: vex.fixture\nVersion: {VER}\n"),
                )
                .unwrap();
                std::fs::write(dist.join("RECORD"), "").unwrap();
                let out = vex(&p, &api, false, &[]);
                assert_eq!(out.code, Some(0), "{what} installed: {out}");
                std::fs::write(site.join(&module), TAMPERED).unwrap();
                let out = vex(&p, &api, false, &[]);
                assert_eq!(out.code, Some(1), "{what} tampered install: {out}");
                assert!(out.doc.is_none(), "{what}");
            }
        }
    }
}

/// Remove one pin spelling from a lock: a whole `files = [...]` /
/// `[metadata.files]` line becomes an empty list, the url fragment is cut.
fn strip_pin(lock: &str, pin: &str) -> String {
    if pin.starts_with('#') {
        return lock.replace(pin, "");
    }
    let key = pin.split(" = ").next().unwrap();
    lock.replace(pin, &format!("{key} = []"))
}

// ════════════════════════════════════════════════════════════════════════
// Writer-driven: the REAL `scan --redirect --vex` / `scan --vendor --vex`
// write the wiring and the ledgers; then the manifest (and the ledgers) are
// deleted and standalone + embedded VEX must still attest — and stop
// attesting once the real revert unwinds the wiring with the ledger left
// behind.
// ════════════════════════════════════════════════════════════════════════

/// Poetry releases the writer-driven cells run (one per lock format the
/// hosted AND vendored writers support).
const WRITER_RELEASES: &[&str] = &["1.0.10", "1.1.15", "1.8.5", "2.4.3"];

/// The authenticated discovery + fetch routes `scan` uses for the fixture
/// patch (a separate server from the [`PatchApi`] `vex` reads records from,
/// so the `vex` runs' request counts are theirs alone): batch discovery
/// (base purl → the qualified record purl), the per-package search, the
/// hosted grant (`artifact_url` pinned to the wheel's sha256), the
/// authenticated view with inline blob content, and the wheel itself.
struct ScanApi {
    rt: tokio::runtime::Runtime,
    server: wiremock::MockServer,
}

impl ScanApi {
    fn start(uuid: &str, artifact_url: Option<&str>, wheel: &[u8]) -> Self {
        use base64::Engine as _;
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, ResponseTemplate};
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(wiremock::MockServer::start());
        let artifact_url = artifact_url
            .map(str::to_string)
            .unwrap_or_else(|| hosted_url_on(&server.uri(), uuid));
        let sha = sha256_hex(wheel);
        let mut full_view = view(uuid, &api_purl());
        full_view["files"][MODULE]["blobContent"] =
            Value::String(base64::engine::general_purpose::STANDARD.encode(PATCHED));
        let artifact_path = artifact_url.strip_prefix(&server.uri()).map(str::to_string);
        rt.block_on(async {
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "packages": [{
                        "purl": purl(),
                        "patches": [{
                            "uuid": uuid, "purl": api_purl(), "tier": "free",
                            "cveIds": [CVE], "ghsaIds": [GHSA], "severity": "HIGH",
                            "title": "vexfixture patch"
                        }]
                    }],
                    "canAccessPaidPatches": false,
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path_regex(format!(
                    "^/v0/orgs/{ORG}/patches/by-package/.+$"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "patches": [{
                        "uuid": uuid, "purl": api_purl(),
                        "publishedAt": "2026-09-01T00:00:00Z",
                        "description": "vexfixture patch", "license": "MIT", "tier": "free",
                        "vulnerabilities": {}
                    }],
                    "canAccessPaidPatches": false,
                })))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/package")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "results": { uuid: {
                        "status": "granted",
                        "url": artifact_url,
                        "purl": purl(),
                        "artifacts": [{
                            "kind": "tarball",
                            "url": artifact_url,
                            "integrity": { "sha256": sha }
                        }],
                        "registryOverride": null
                    } }
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(full_view))
                .mount(&server)
                .await;
            if let Some(artifact_path) = artifact_path {
                Mock::given(method("GET"))
                    .and(path(artifact_path))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(wheel.to_vec()))
                    .mount(&server)
                    .await;
            }
        });
        ScanApi { rt, server }
    }

    fn uri(&self) -> String {
        self.server.uri()
    }

    fn requests(&self) -> usize {
        self.rt
            .block_on(self.server.received_requests())
            .map(|r| r.len())
            .unwrap_or(0)
    }
}

/// An authenticated `socket-patch <args> --json --yes` in `p` against
/// `api` → (exit, envelope).
fn run_authed(p: &Proj, api: &ScanApi, args: &[&str]) -> (Option<i32>, Value) {
    let mut cmd = Command::new(binary());
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") || key.starts_with("POETRY_") {
            cmd.env_remove(key);
        }
    }
    for (key, value) in poetry_envs(p) {
        cmd.env(key, value);
    }
    let out = cmd
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env_remove("VIRTUAL_ENV")
        .current_dir(&p.root)
        .args(args)
        .args([
            "--json",
            "--yes",
            "--cwd",
            p.root.to_str().unwrap(),
            "--api-url",
            &api.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG,
        ])
        .output()
        .expect("invoke socket-patch");
    let env: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{args:?}: envelope JSON on stdout ({e}). stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code(), env)
}

/// The embedded `--vex` document at `path`, with its one statement
/// asserted.
fn assert_embedded_doc(what: &str, path: &Path, mode: Mode) {
    let doc: Value = serde_json::from_slice(
        &std::fs::read(path).unwrap_or_else(|e| panic!("{what}: embedded VEX doc: {e}")),
    )
    .unwrap();
    vex_e2e_common::assert_attested(&doc, &purl(), mode.uuid(), mode.marker(), &[(GHSA, &[CVE])]);
    assert_eq!(statements_for(&doc, &purl()).len(), 1, "{what}: {doc}");
}

/// An embedded (`apply --vex` / `vendor --vex`) run over the manifest-less
/// checkout, records fetched from `api` unless `offline`.
fn embedded(p: &Proj, api: &PatchApi, via: VexVia, offline: bool, extra: &[&str]) -> VexOutcome {
    let _ = std::fs::remove_file(p.root.join(DEFAULT_OUTPUT));
    let mut run = VexRun {
        offline,
        proxy_url: Some(api.uri()),
        product: Some(PRODUCT.to_string()),
        envs: poetry_envs(p),
        ..VexRun::default()
    }
    .via(via);
    for arg in extra {
        run = run.arg(*arg);
    }
    run_vex(&binary(), &p.root, &run)
}

/// `scan --redirect --vex` on a lock-only checkout (nothing installed)
/// writes the hosted wiring + the redirect ledger and attests in-run; then,
/// with no manifest:
///   c. the ledger alone attests offline (standalone and `apply --vex`);
///   b. without the ledger, offline is `record_unavailable` with no request;
///   a. without the ledger, online attests (standalone and `apply --vex`);
///   d. `rollback` unwinds the wiring; with the ledger put back it is dead.
///
/// Both a production `patch.socket.dev` artifact url (nothing is fetched
/// from it) and a self-hosted patch server (the mock's own origin, which
/// `vex` must be told about with `--patch-server-url`).
#[test]
fn scan_redirect_wiring_attests_without_manifest_or_ledger() {
    for release in WRITER_RELEASES {
        for self_hosted in [false, true] {
            let what = format!("poetry {release} scan --redirect self_hosted={self_hosted}");
            let p = Proj::new();
            p.write_files(&native_files(release));
            p.empty_venv();
            let wheel = build_wheel(PATCHED);
            let production = hosted_url(HOSTED_UUID);
            let scan = ScanApi::start(
                HOSTED_UUID,
                (!self_hosted).then_some(production.as_str()),
                &wheel,
            );
            let artifact_url = if self_hosted {
                hosted_url_on(&scan.uri(), HOSTED_UUID)
            } else {
                production.clone()
            };
            let embedded_doc = p.root.join("embedded.vex.json");
            let (code, env) = run_authed(
                &p,
                &scan,
                &[
                    "scan",
                    "--redirect",
                    "--vex",
                    embedded_doc.to_str().unwrap(),
                    "--vex-product",
                    PRODUCT,
                ],
            );
            assert_eq!(code, Some(0), "{what}: {env}");
            let lock = p.read("poetry.lock");
            assert!(
                lock.contains(&artifact_url),
                "{what}: lock not wired:\n{lock}"
            );
            assert!(lock.contains("type = \"url\""), "{what}:\n{lock}");
            assert!(p.exists(".socket/vendor/redirect-state.json"), "{what}");
            assert!(
                !p.exists(".socket/manifest.json"),
                "{what}: hosted writes no manifest"
            );
            assert_embedded_doc(&what, &embedded_doc, Mode::Hosted);

            let origin_flag: Vec<String> = if self_hosted {
                vec!["--patch-server-url".into(), scan.uri()]
            } else {
                Vec::new()
            };
            let origin: Vec<&str> = origin_flag.iter().map(String::as_str).collect();
            let api = api_for(Mode::Hosted);

            // c. the writer's ledger attests offline.
            let out = vex(&p, &api, true, &origin);
            assert_attested(&format!("{what} ledger"), &out, Mode::Hosted, HOSTED_UUID);
            let out = embedded(&p, &api, VexVia::Apply, true, &origin);
            assert_eq!(out.code, Some(0), "{what} apply --vex ledger: {out}");
            assert_eq!(out.envelope["status"], "noManifest", "{what}: {out}");
            assert_eq!(out.envelope["vex"]["statements"], 1, "{what}: {out}");
            api.assert_no_requests();

            // b / a. no ledger.
            let ledger_path = p.root.join(".socket/vendor/redirect-state.json");
            let ledger = std::fs::read(&ledger_path).unwrap();
            strip_ledgers(&p);
            let out = vex(&p, &api, true, &origin);
            assert_omitted(
                &format!("{what} no ledger offline"),
                &out,
                "record_unavailable",
            );
            let out = embedded(&p, &api, VexVia::Apply, true, &origin);
            assert_eq!(out.code, Some(1), "{what} apply --vex offline: {out}");
            assert_absent(out.doc.as_ref(), &purl());
            api.assert_no_requests();
            let out = vex(&p, &api, false, &origin);
            assert_attested(
                &format!("{what} no ledger online"),
                &out,
                Mode::Hosted,
                HOSTED_UUID,
            );
            let out = embedded(&p, &api, VexVia::Apply, false, &origin);
            assert_eq!(out.code, Some(0), "{what} apply --vex online: {out}");
            vex_e2e_common::assert_attested(
                out.doc(),
                &purl(),
                HOSTED_UUID,
                Marker::Redirected,
                &[(GHSA, &[CVE])],
            );
            assert_no_manifest_written(&p, &what);

            // d. the real revert, then the ledger restored behind its back.
            std::fs::write(&ledger_path, &ledger).unwrap();
            let (code, env) = run_authed(&p, &scan, &["rollback"]);
            assert_eq!(code, Some(0), "{what} rollback: {env}");
            for (name, text) in native_files(release) {
                assert_eq!(p.read(name), text, "{what}: rollback restores {name}");
            }
            // A fully reverted project keeps no `.socket/` at all: recreate
            // the directory the stale ledger is planted back into.
            std::fs::create_dir_all(ledger_path.parent().unwrap()).unwrap();
            std::fs::write(&ledger_path, &ledger).unwrap();
            for extra in [&[][..], &["--no-verify"][..]] {
                let mut args = origin.clone();
                args.extend_from_slice(extra);
                let out = vex(&p, &api, true, &args);
                assert_omitted(
                    &format!("{what} reverted {extra:?}"),
                    &out,
                    "redirect_unwired",
                );
                let out = vex(&p, &api, false, &args);
                assert_omitted(
                    &format!("{what} reverted online {extra:?}"),
                    &out,
                    "redirect_unwired",
                );
            }
            let _ = scan.requests();
        }
    }
}

/// `scan --vendor --vex --vendor-source build` over the installed (pristine)
/// dist rebuilds the patched wheel into `.socket/vendor/pypi/<uuid>/`, wires
/// the lock, writes the ledger (never a manifest: vendored mode is
/// manifest-free) and attests in-run. A legacy manifest seeded beside the
/// ledger attests the same way; then, with no manifest:
///   c. the vendor ledger alone attests offline (standalone and `vendor
///      --vex` / `apply --vex`);
///   b. without the ledger, offline is `record_unavailable`, no request;
///   a. without the ledger, online attests (the committed wheel is hashed);
///   d. `vendor --revert` unwinds the wiring; with the ledger put back (and
///      the artifact re-committed) it is `vendor_unwired`, `--no-verify` too.
/// The `--detached` twin (a hidden compatibility no-op) behaves the same.
#[test]
fn scan_vendor_wiring_attests_without_manifest_or_ledger() {
    for detached in [false, true] {
        for release in WRITER_RELEASES {
            let what = format!("poetry {release} scan --vendor detached={detached}");
            let p = Proj::new();
            p.write_files(&native_files(release));
            p.install(PRISTINE);
            let scan = ScanApi::start(
                VENDORED_UUID,
                Some(&hosted_url(VENDORED_UUID)),
                &build_wheel(PATCHED),
            );
            let embedded_doc = p.root.join("embedded.vex.json");
            let mut args = vec![
                "scan",
                "--vendor",
                "--vendor-source",
                "build",
                "--vex",
                embedded_doc.to_str().unwrap(),
                "--vex-product",
                PRODUCT,
            ];
            if detached {
                args.push("--detached");
            }
            let (code, env) = run_authed(&p, &scan, &args);
            assert_eq!(code, Some(0), "{what}: {env}");
            assert_embedded_doc(&what, &embedded_doc, Mode::Vendored);
            let lock = p.read("poetry.lock");
            assert!(
                lock.contains(&format!("url = \"{}\"", vendored_rel(VENDORED_UUID))),
                "{what}: lock not wired:\n{lock}"
            );
            assert!(lock.contains("type = \"file\""), "{what}:\n{lock}");
            assert!(
                !p.exists(".socket/manifest.json"),
                "{what}: vendored mode is manifest-free (--detached is a no-op)"
            );
            // Vendoring never patches the installed tree.
            assert_eq!(std::fs::read(p.site().join(MODULE)).unwrap(), PRISTINE);

            let api = api_for(Mode::Vendored);
            // A legacy (pre-5.0) checkout also carries the manifest record
            // beside the ledger: same uuid, so it attests the same way.
            assert!(vex_e2e_common::seed_legacy_manifest(&p.root) > 0, "{what}");
            let out = vex(&p, &api, true, &[]);
            assert_attested(
                &format!("{what} legacy manifest"),
                &out,
                Mode::Vendored,
                VENDORED_UUID,
            );
            vex_e2e_common::strip_manifest(&p.root);
            // c. the ledger alone — standalone and both embedded commands.
            let out = vex(&p, &api, true, &[]);
            assert_attested(
                &format!("{what} ledger"),
                &out,
                Mode::Vendored,
                VENDORED_UUID,
            );
            for via in [VexVia::Vendor, VexVia::Apply] {
                let out = embedded(&p, &api, via, true, &[]);
                assert_eq!(out.code, Some(0), "{what} {via:?} --vex ledger: {out}");
                assert_eq!(out.envelope["status"], "noManifest", "{what}: {out}");
                vex_e2e_common::assert_attested(
                    out.doc(),
                    &purl(),
                    VENDORED_UUID,
                    Marker::Vendored,
                    &[(GHSA, &[CVE])],
                );
            }
            api.assert_no_requests();

            // b / a. no ledger.
            let ledger_path = p.root.join(".socket/vendor/state.json");
            let ledger = std::fs::read(&ledger_path).unwrap();
            strip_ledgers(&p);
            let out = vex(&p, &api, true, &[]);
            assert_omitted(
                &format!("{what} no ledger offline"),
                &out,
                "record_unavailable",
            );
            api.assert_no_requests();
            let out = vex(&p, &api, false, &[]);
            assert_attested(
                &format!("{what} no ledger online"),
                &out,
                Mode::Vendored,
                VENDORED_UUID,
            );
            let out = embedded(&p, &api, VexVia::Vendor, false, &[]);
            assert_eq!(out.code, Some(0), "{what} vendor --vex online: {out}");
            vex_e2e_common::assert_attested(
                out.doc(),
                &purl(),
                VENDORED_UUID,
                Marker::Vendored,
                &[(GHSA, &[CVE])],
            );
            assert_no_manifest_written(&p, &what);

            // d. the real revert, then the ledger + artifact put back.
            std::fs::write(&ledger_path, &ledger).unwrap();
            let artifact_dir = p.root.join(format!(".socket/vendor/pypi/{VENDORED_UUID}"));
            let artifacts: Vec<(PathBuf, Vec<u8>)> = std::fs::read_dir(&artifact_dir)
                .unwrap()
                .flatten()
                .map(|e| (e.path(), std::fs::read(e.path()).unwrap()))
                .collect();
            let (code, env) = run_authed(&p, &scan, &["vendor", "--revert"]);
            assert_eq!(code, Some(0), "{what} revert: {env}");
            for (name, text) in native_files(release) {
                assert_eq!(p.read(name), text, "{what}: revert restores {name}");
            }
            std::fs::create_dir_all(&artifact_dir).unwrap();
            for (path, bytes) in &artifacts {
                std::fs::write(path, bytes).unwrap();
            }
            std::fs::write(&ledger_path, &ledger).unwrap();
            for extra in [&[][..], &["--no-verify"][..]] {
                let out = vex(&p, &api, true, extra);
                assert_omitted(
                    &format!("{what} reverted {extra:?}"),
                    &out,
                    "vendor_unwired",
                );
                let out = vex(&p, &api, false, extra);
                assert_omitted(
                    &format!("{what} reverted online {extra:?}"),
                    &out,
                    "vendor_unwired",
                );
            }
            let _ = scan.requests();
        }
    }
}
