//! Shared hermetic cells for manifest-less `socket-patch vex` over the PDM
//! (`pdm.lock`) and Hatch (PEP 508 direct references in `pyproject.toml` /
//! `hatch.toml`) wirings, in BOTH patch modes: HOSTED (the wiring points at
//! Socket's patch server) and VENDORED (the wiring points at a committed
//! `.socket/vendor/pypi/<uuid>/<wheel>`).
//!
//! Used by `e2e_vex_lockfile/pdm.rs` and `e2e_vex_lockfile/hatch.rs`, which
//! only declare their [`Flavor`]s and call the cell functions below. Pull it
//! in (after `vex_e2e_common`, whose runner and assertions every cell uses)
//! with
//!
//! ```ignore
//! #[path = "vex_e2e_common/mod.rs"]
//! mod vex_e2e_common;
//! #[path = "vex_pdm_hatch_common/mod.rs"]
//! mod vex_pdm_hatch_common;
//! ```
//!
//! Every project is wired by the REAL CLI, not by hand: `scan --redirect`
//! (hosted) or `scan --vendor --vendor-source build` (vendored) runs against
//! a wiremock stand-in for the Socket API, with the package's pristine
//! install in a fabricated `.venv` for the vendored build. The wired tree is
//! snapshotted once per (flavor, mode) and every cell restores the snapshot
//! into its own temp dir, then DELETES what the cell says to delete
//! (`.socket/manifest.json`, the ledgers `.socket/vendor/state.json` /
//! `.socket/vendor/redirect-state.json`, the venv) before running VEX.
//!
//! Hermetic: no network (the API is wiremock; `--offline` runs assert zero
//! requests), no real Python / PDM / Hatch needed. The package is a
//! fictitious `vexdemo` so no interpreter on the machine can hold a copy the
//! crawler would find.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::Value;

use crate::vex_e2e_common::{
    assert_attested, binary, git_sha256, run_vex, statements_for, Marker, PatchApi, VexOutcome,
    VexRun, VexVia,
};

pub const ORG: &str = "test-org";
pub const NAME: &str = "vexdemo";
pub const VERSION: &str = "1.2.3";
pub const PURL: &str = "pkg:pypi/vexdemo@1.2.3";
pub const PRODUCT: &str = "pkg:pypi/app@0.1.0";
/// The patch uuid the hosted wiring carries.
pub const HOSTED_UUID: &str = "3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f";
/// The patch uuid the vendored wiring carries (distinct, so a hosted
/// fixture can never satisfy a vendored assertion by accident).
pub const VENDORED_UUID: &str = "6f5e4d3c-2b1a-4f0e-9d8c-7b6a5f4e3d2c";
/// A uuid-SHAPED grant token: the patch uuid is the LAST uuid segment.
pub const TOKEN: &str = "11111111-2222-4333-8444-555555555555";
pub const GHSA: &str = "GHSA-pdmh-lock-0001";
pub const CVE: &str = "CVE-2026-7101";
/// The record's one file, site-packages relative (the pypi file-key
/// convention, which is also the wheel member name).
pub const MODULE: &str = "vexdemo/__init__.py";
pub const PRISTINE: &[u8] = b"def run():\n    return 'vulnerable'\n";
pub const PATCHED: &[u8] = b"def run():\n    return 'fixed'\n";
pub const TAMPERED: &[u8] = b"def run():\n    return 'tampered'\n";
pub const WHEEL: &str = "vexdemo-1.2.3-py3-none-any.whl";
const VULNS: &[(&str, &[&str])] = &[(GHSA, &[CVE])];

pub fn hosted_url() -> String {
    format!("https://patch.socket.dev/patch/pypi/{NAME}/{VERSION}/{TOKEN}/{HOSTED_UUID}/{WHEEL}")
}

/// The patched wheel's sha256 the grant pins (never downloaded here).
pub fn hosted_sha256() -> String {
    "c".repeat(64)
}

pub fn vendored_wheel_rel() -> String {
    format!(".socket/vendor/pypi/{VENDORED_UUID}/{WHEEL}")
}

// ── flavors + modes ───────────────────────────────────────────────────

/// One project shape of the package manager under test.
#[derive(Clone, Debug)]
pub struct Flavor {
    /// Unique label (cache key + assertion context).
    pub label: String,
    /// The project files BEFORE Socket touched them (what a "revert"
    /// restores), root-relative.
    pub native: Vec<(String, String)>,
    /// The HOSTED rewriter wires this shape.
    pub hosted: bool,
    /// The VENDORED backend wires this shape.
    pub vendored: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    Hosted,
    Vendored,
}

impl Mode {
    pub fn uuid(self) -> &'static str {
        match self {
            Mode::Hosted => HOSTED_UUID,
            Mode::Vendored => VENDORED_UUID,
        }
    }

    pub fn marker(self) -> Marker {
        match self {
            Mode::Hosted => Marker::Redirected,
            Mode::Vendored => Marker::Vendored,
        }
    }

    /// The skip reason a stale ledger record of this mode earns.
    pub fn unwired(self) -> &'static str {
        match self {
            Mode::Hosted => "redirect_unwired",
            Mode::Vendored => "vendor_unwired",
        }
    }

    /// The ledger file this mode's wiring run writes.
    pub fn ledger(self) -> &'static str {
        match self {
            Mode::Hosted => ".socket/vendor/redirect-state.json",
            Mode::Vendored => ".socket/vendor/state.json",
        }
    }
}

/// Every (flavor, mode) the backends wire.
pub fn cells(flavors: &[Flavor]) -> Vec<(Flavor, Mode)> {
    let mut out: Vec<(Flavor, Mode)> = flavors
        .iter()
        .filter(|f| f.hosted)
        .map(|f| (f.clone(), Mode::Hosted))
        .collect();
    out.extend(
        flavors
            .iter()
            .filter(|f| f.vendored)
            .map(|f| (f.clone(), Mode::Vendored)),
    );
    out
}

// ── process + fs helpers ──────────────────────────────────────────────

/// The CLI with the ambient environment neutralized: every `SOCKET_*`
/// scrubbed, telemetry and socket-cli config off, no `VIRTUAL_ENV` (a
/// python-crawler input).
pub fn cli() -> Command {
    let mut cmd = Command::new(binary());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env_remove("VIRTUAL_ENV");
    cmd
}

pub fn put(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn site_packages_rel(venv: &str) -> String {
    if cfg!(windows) {
        format!("{venv}/Lib/site-packages")
    } else {
        format!("{venv}/lib/python3.12/site-packages")
    }
}

/// Install `vexdemo 1.2.3` into `<root>/<venv>` with `module` as its one
/// source file — a real-shaped dist (METADATA, WHEEL, RECORD, INSTALLER) the
/// python crawler resolves and the vendored wheel builder can rebuild from.
pub fn install(root: &Path, venv: &str, module: &[u8]) {
    let site = site_packages_rel(venv);
    let dist = format!("{site}/vexdemo-1.2.3.dist-info");
    put(root, &format!("{site}/{MODULE}"), module);
    put(
        root,
        &format!("{dist}/METADATA"),
        b"Metadata-Version: 2.1\nName: vexdemo\nVersion: 1.2.3\nSummary: demo\n",
    );
    put(
        root,
        &format!("{dist}/WHEEL"),
        b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    );
    put(root, &format!("{dist}/INSTALLER"), b"pip\n");
    put(
        root,
        &format!("{dist}/RECORD"),
        format!(
            "{MODULE},,\nvexdemo-1.2.3.dist-info/METADATA,,\nvexdemo-1.2.3.dist-info/WHEEL,,\n\
             vexdemo-1.2.3.dist-info/INSTALLER,,\nvexdemo-1.2.3.dist-info/RECORD,,\n"
        )
        .as_bytes(),
    );
}

/// Every regular file under `root`, keyed by `/`-joined relative path.
fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

pub fn fresh() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    (tmp, cwd)
}

// ── the mock Socket API ───────────────────────────────────────────────

/// The patch view (`GET …/view/<uuid>`) for `uuid` naming `purl`: one file
/// (`MODULE`, pristine → patched, with the inline blob the vendored build
/// consumes) and one GHSA with a CVE alias.
pub fn view(uuid: &str, purl: &str) -> Value {
    use base64::Engine as _;
    serde_json::json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "Fri, 27 Mar 2026 00:00:00 GMT",
        "files": { MODULE: {
            "beforeHash": git_sha256(PRISTINE),
            "afterHash": git_sha256(PATCHED),
            "blobContent": base64::engine::general_purpose::STANDARD.encode(PATCHED),
        } },
        "vulnerabilities": { GHSA: {
            "cves": [CVE], "summary": "pdm/hatch fixture", "severity": "high", "description": "d"
        } },
        "description": "pdm/hatch lockfile patch",
        "license": "MIT",
        "tier": "free",
    })
}

/// A patch API holding exactly `uuid`'s view (naming `purl`).
pub fn api_with(uuid: &str, purl: &str) -> PatchApi {
    PatchApi::start(vec![(uuid.to_string(), view(uuid, purl))])
}

/// The wiremock stand-in `scan` talks to: discovery (batch +
/// by-package), the hosted grant for `uuid`, and the org view route.
pub struct ScanApi {
    rt: tokio::runtime::Runtime,
    server: wiremock::MockServer,
}

impl ScanApi {
    pub fn start(uuid: &str) -> Self {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, ResponseTemplate};
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(wiremock::MockServer::start());
        let api = ScanApi { rt, server };
        api.mount(
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "packages": [{
                        "purl": PURL,
                        "patches": [{
                            "uuid": uuid, "purl": PURL, "tier": "free",
                            "cveIds": [CVE], "ghsaIds": [GHSA], "severity": "high",
                            "title": "pdm/hatch fixture"
                        }]
                    }],
                    "canAccessPaidPatches": false,
                }))),
        );
        api.mount(
            Mock::given(method("GET"))
                .and(path_regex(format!(
                    "^/v0/orgs/{ORG}/patches/by-package/.+$"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "patches": [{
                        "uuid": uuid, "purl": PURL,
                        "publishedAt": "2026-03-27T00:00:00Z",
                        "description": "x", "license": "MIT", "tier": "free",
                        "vulnerabilities": {}
                    }],
                    "canAccessPaidPatches": false,
                }))),
        );
        api.mount(
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/package")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "results": { uuid: {
                        "status": "granted",
                        "url": hosted_url(),
                        "purl": PURL,
                        "artifacts": [{
                            "kind": "tarball",
                            "url": hosted_url(),
                            "integrity": { "sha256": hosted_sha256() }
                        }],
                        "registryOverride": null
                    } }
                }))),
        );
        for route in [
            format!("/patch/view/{uuid}"),
            format!("/v0/orgs/{ORG}/patches/view/{uuid}"),
        ] {
            api.mount(
                Mock::given(method("GET"))
                    .and(path(route))
                    .respond_with(ResponseTemplate::new(200).set_body_json(view(uuid, PURL))),
            );
        }
        api
    }

    fn mount(&self, mock: wiremock::Mock) {
        self.rt.block_on(mock.mount(&self.server));
    }

    pub fn uri(&self) -> String {
        self.server.uri()
    }
}

// ── wiring: the real CLI writes every project edit ────────────────────

/// `PATH` with a stand-in `hatch` first. The vendored Hatch ENVIRONMENT
/// wiring (`{root:uri}` in `[envs.*]`) refuses unless `hatch --version`
/// reports >= 1.2 (older Hatch does not expand the context field there), and
/// no real Hatch is assumed on the machine. Unix: a script printing a Hatch
/// version line. Windows (the probe resolves `hatch.exe` only): a hard link
/// to — or copy of — this very CLI binary, whose `--version` prints
/// `socket-patch <semver>`, which satisfies the same probe.
pub fn path_with_fake_hatch(scratch: &Path) -> std::ffi::OsString {
    let dir = scratch.join("fake-hatch-bin");
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let script = dir.join("hatch");
        std::fs::write(&script, "#!/bin/sh\necho 'Hatch, version 1.16.0'\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    #[cfg(windows)]
    {
        let exe = dir.join("hatch.exe");
        if !exe.exists() && std::fs::hard_link(binary(), &exe).is_err() {
            std::fs::copy(binary(), &exe).unwrap();
        }
    }
    let mut paths = vec![dir];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    std::env::join_paths(paths).unwrap()
}

/// `scan --json` (hosted: `--redirect`; vendored: `--vendor --vendor-source
/// build`) in `cwd` against `api`.
pub fn run_scan(
    cwd: &Path,
    api: &ScanApi,
    mode: Mode,
    extra: &[&str],
) -> (Option<i32>, Value, String) {
    let mut args: Vec<String> = [
        "scan",
        "--json",
        "--yes",
        "--api-url",
        &api.uri(),
        "--api-token",
        "fake",
        "--org",
        ORG,
        "--cwd",
        cwd.to_str().unwrap(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    match mode {
        Mode::Hosted => args.push("--redirect".into()),
        Mode::Vendored => args.extend(["--vendor", "--vendor-source", "build"].map(String::from)),
    }
    args.extend(extra.iter().map(|s| s.to_string()));
    let out = cli()
        .env("PATH", path_with_fake_hatch(cwd.parent().unwrap()))
        .args(&args)
        .current_dir(cwd)
        .output()
        .expect("invoke scan");
    let stderr = text(&out.stderr);
    let env: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "scan envelope ({e}). stdout:\n{}\nstderr:\n{stderr}",
            text(&out.stdout)
        )
    });
    (out.status.code(), env, stderr)
}

/// `doc` holds exactly one statement: `vexdemo` not_affected by [`GHSA`]
/// (alias [`CVE`]) via `mode`'s patch, with its provenance marker, for
/// [`PRODUCT`].
pub fn assert_statement(doc: &Value, mode: Mode, what: &str) {
    let all = doc["statements"]
        .as_array()
        .unwrap_or_else(|| panic!("{what}: {doc}"));
    assert_eq!(all.len(), 1, "{what}: {doc}");
    assert_attested(doc, PURL, mode.uuid(), mode.marker(), VULNS);
    let stmt = &all[0];
    assert_eq!(stmt["products"][0]["@id"], PRODUCT, "{what}: {stmt}");
    let subs = stmt["products"][0]["subcomponents"].as_array().unwrap();
    assert_eq!(subs.len(), 1, "{what}: {stmt}");
    assert_eq!(subs[0]["@id"], PURL, "{what}: {stmt}");
}

/// Run the real wiring for (`flavor`, `mode`) in `proj` (a fresh dir),
/// asserting the SAME-RUN embedded `--vex` attests it.
pub fn wire_into(proj: &Path, flavor: &Flavor, mode: Mode, extra: &[&str]) -> Value {
    for (rel, native) in &flavor.native {
        put(proj, rel, native.as_bytes());
    }
    if mode == Mode::Vendored {
        // The vendored build rebuilds the wheel from the pristine install.
        install(proj, ".venv", PRISTINE);
    }
    let api = ScanApi::start(mode.uuid());
    let vex_out = proj.join("scan.vex.json");
    let mut args = vec!["--vex", vex_out.to_str().unwrap(), "--vex-product", PRODUCT];
    args.extend_from_slice(extra);
    let (code, env, stderr) = run_scan(proj, &api, mode, &args);
    let what = format!("{}/{mode:?} {extra:?}", flavor.label);
    assert_eq!(
        code,
        Some(0),
        "{what}: scan failed: {env}\nstderr:\n{stderr}"
    );
    let doc: Value = serde_json::from_slice(
        &std::fs::read(&vex_out)
            .unwrap_or_else(|e| panic!("{what}: embedded vex doc missing ({e}): {env}\n{stderr}")),
    )
    .unwrap();
    assert_statement(&doc, mode, &what);
    assert_eq!(env["vex"]["statements"], 1, "{what}: {env}");
    std::fs::remove_file(&vex_out).unwrap();
    let _ = std::fs::remove_dir_all(proj.join(".venv"));
    env
}

/// One (flavor, mode) project as the real CLI left it.
pub struct Wired {
    pub flavor: Flavor,
    pub mode: Mode,
    /// Every file after the wiring run (the venv and VEX output excluded):
    /// wired project files, `.socket/manifest.json` (vendored non-detached),
    /// the mode's ledger, the committed wheel (vendored).
    pub files: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Copy, Debug)]
pub struct Keep {
    pub manifest: bool,
    pub ledgers: bool,
}

pub const NOTHING: Keep = Keep {
    manifest: false,
    ledgers: false,
};
pub const LEDGERS_ONLY: Keep = Keep {
    manifest: false,
    ledgers: true,
};
pub const EVERYTHING: Keep = Keep {
    manifest: true,
    ledgers: true,
};

impl Wired {
    /// Lay the wired tree down in `cwd`, then drop the manifest and/or the
    /// ledgers as the cell requires.
    pub fn restore(&self, cwd: &Path, keep: Keep) {
        for (rel, bytes) in &self.files {
            let is_manifest = rel == ".socket/manifest.json";
            let is_ledger =
                rel == ".socket/vendor/state.json" || rel == ".socket/vendor/redirect-state.json";
            if (is_manifest && !keep.manifest) || (is_ledger && !keep.ledgers) {
                continue;
            }
            put(cwd, rel, bytes);
        }
        if !keep.manifest {
            assert!(!cwd.join(".socket/manifest.json").exists());
        }
        if !keep.ledgers {
            assert!(!cwd.join(".socket/vendor/state.json").exists());
            assert!(!cwd.join(".socket/vendor/redirect-state.json").exists());
        }
    }

    /// Put every Socket-edited project file back to its native bytes (the
    /// user reverted the wiring by hand, or re-locked).
    pub fn revert_wiring(&self, cwd: &Path) {
        for (rel, native) in &self.flavor.native {
            put(cwd, rel, native.as_bytes());
        }
    }

    /// The project files the wiring run actually changed.
    pub fn changed_files(&self) -> Vec<&str> {
        self.flavor
            .native
            .iter()
            .filter(|(rel, native)| {
                self.files.get(rel).map(Vec::as_slice) != Some(native.as_bytes())
            })
            .map(|(rel, _)| rel.as_str())
            .collect()
    }

    pub fn what(&self) -> String {
        format!("{}/{:?}", self.flavor.label, self.mode)
    }
}

/// The wired snapshot for (`flavor`, `mode`), built once per test binary.
pub fn wired(flavor: &Flavor, mode: Mode) -> Arc<Wired> {
    type Cache = Mutex<HashMap<(String, Mode), Arc<Wired>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(hit) = cache.get(&(flavor.label.clone(), mode)) {
        return hit.clone();
    }
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    wire_into(&proj, flavor, mode, &[]);
    let wired = Arc::new(Wired {
        flavor: flavor.clone(),
        mode,
        files: snapshot(&proj),
    });
    let what = wired.what();
    // Anti-vacuity: the run really rewired a project file, into the
    // mode's reference shape, and left its ledger + artifact behind.
    let changed = wired.changed_files();
    assert!(!changed.is_empty(), "{what}: nothing was rewired");
    let wiring_text: String = changed.iter().map(|rel| text(&wired.files[*rel])).collect();
    match mode {
        Mode::Hosted => assert!(
            wiring_text.contains(&hosted_url()),
            "{what}: the hosted url must be wired: {wiring_text}"
        ),
        Mode::Vendored => {
            assert!(
                wiring_text.contains(&vendored_wheel_rel()),
                "{what}: the vendored wheel must be wired: {wiring_text}"
            );
            assert!(
                wired.files.contains_key(&vendored_wheel_rel()),
                "{what}: the wheel must be committed: {:?}",
                wired.files.keys().collect::<Vec<_>>()
            );
        }
    }
    assert!(
        wired.files.contains_key(mode.ledger()),
        "{what}: the {} ledger must be written: {:?}",
        mode.ledger(),
        wired.files.keys().collect::<Vec<_>>()
    );
    cache.insert((flavor.label.clone(), mode), wired.clone());
    wired
}

// ── vex runner + assertions ───────────────────────────────────────────

/// A standalone `vex --json` run for [`PRODUCT`] (unauthenticated: records
/// come from `api`'s public-proxy route when one is given).
pub fn vex_run(api: Option<&PatchApi>) -> VexRun {
    let mut run = match api {
        Some(api) => VexRun::online(api),
        None => VexRun::default(),
    };
    run.product = Some(PRODUCT.to_string());
    run
}

pub fn vex(cwd: &Path, run: &VexRun) -> VexOutcome {
    run_vex(&binary(), cwd, run)
}

pub fn assert_ok_attested(out: &VexOutcome, mode: Mode, what: &str) {
    assert_eq!(out.code, Some(0), "{what}: {out}");
    assert_eq!(out.envelope["status"], "success", "{what}: {out}");
    assert_statement(out.doc(), mode, what);
    let verified: Vec<&Value> = out.envelope["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "verified")
        .collect();
    assert_eq!(verified.len(), 1, "{what}: {out}");
    assert_eq!(verified[0]["purl"], PURL, "{what}: {out}");
}

/// Exit 1 `no_applicable_patches`, no document, and `vexdemo` omitted with
/// `reason`.
pub fn assert_omitted(out: &VexOutcome, reason: &str, what: &str) {
    crate::vex_e2e_common::assert_omitted(out, PURL, reason, what);
}

/// Nothing Socket-wired was found at all: exit 2 `manifest_not_found`.
pub fn assert_nothing_discovered(out: &VexOutcome, what: &str) {
    assert_eq!(out.code, Some(2), "{what}: {out}");
    assert_eq!(
        out.envelope["error"]["code"], "manifest_not_found",
        "{what}: {out}"
    );
    assert!(out.doc.is_none(), "{what}: {out}");
}

// ──────────────────────────────────────────────────────────────────────
// cells
// ──────────────────────────────────────────────────────────────────────

/// a) no manifest, no ledgers, online → attested from the wiring alone
/// (hosted: the lock's sha256 pin, nothing installed; vendored: the
/// committed wheel), the record fetched from the API, nothing written.
pub fn a_wiring_only_checkout_attests_online(flavors: &[Flavor]) {
    for (flavor, mode) in cells(flavors) {
        let wired = wired(&flavor, mode);
        let what = wired.what();
        let (_tmp, cwd) = fresh();
        wired.restore(&cwd, NOTHING);
        let api = api_with(mode.uuid(), PURL);
        let out = vex(&cwd, &vex_run(Some(&api)));
        assert_ok_attested(&out, mode, &what);
        assert!(
            api.view_requests(mode.uuid()) >= 1,
            "{what}: {:?}",
            api.requests()
        );
        assert!(
            !cwd.join(".socket/manifest.json").exists(),
            "{what}: vex never writes the manifest"
        );
        assert!(
            !cwd.join(mode.ledger()).exists(),
            "{what}: vex never writes a ledger"
        );
    }
}

/// b) `--offline` (with and without `--no-verify`), an unreachable API and
/// an API without the patch (404), no local record → `record_unavailable`;
/// `--offline` never contacts the API.
pub fn b_no_local_record_is_record_unavailable(flavors: &[Flavor]) {
    for (flavor, mode) in cells(flavors) {
        let wired = wired(&flavor, mode);
        let what = wired.what();
        let (_tmp, cwd) = fresh();
        wired.restore(&cwd, NOTHING);
        // The API WOULD answer — `--offline` must not ask it.
        let api = api_with(mode.uuid(), PURL);
        for no_verify in [false, true] {
            let run = VexRun {
                offline: true,
                no_verify,
                ..vex_run(Some(&api))
            };
            assert_omitted(
                &vex(&cwd, &run),
                "record_unavailable",
                &format!("{what} offline nv={no_verify}"),
            );
        }
        api.assert_no_requests();
        let dead = VexRun {
            proxy_url: Some("http://127.0.0.1:9".into()),
            ..vex_run(None)
        };
        assert_omitted(
            &vex(&cwd, &dead),
            "record_unavailable",
            &format!("{what} unreachable"),
        );
        let empty = PatchApi::empty();
        assert_omitted(
            &vex(&cwd, &vex_run(Some(&empty))),
            "record_unavailable",
            &format!("{what} 404"),
        );
    }
}

/// c) ledger kept, manifest gone → attested OFFLINE from the ledger record
/// (both `--offline` and `--offline --no-verify`); the committed `.socket/`
/// exactly as the wiring run left it attests too.
pub fn c_ledger_without_manifest_attests_offline(flavors: &[Flavor]) {
    for (flavor, mode) in cells(flavors) {
        let wired = wired(&flavor, mode);
        let what = wired.what();
        for keep in [LEDGERS_ONLY, EVERYTHING] {
            let (_tmp, cwd) = fresh();
            wired.restore(&cwd, keep);
            let api = PatchApi::empty();
            for no_verify in [false, true] {
                let run = VexRun {
                    offline: true,
                    no_verify,
                    ..vex_run(Some(&api))
                };
                assert_ok_attested(
                    &vex(&cwd, &run),
                    mode,
                    &format!("{what} {keep:?} nv={no_verify}"),
                );
            }
            api.assert_no_requests();
        }
    }
}

/// d) wiring reverted to the registry while ledger + artifact remain →
/// `redirect_unwired` / `vendor_unwired`, `--no-verify` included; the
/// manifest back as well still attests nothing; with the ledger gone too
/// nothing is discovered at all (the orphaned wheel is never evidence).
pub fn d_reverted_wiring_is_unwired_even_with_no_verify(flavors: &[Flavor]) {
    for (flavor, mode) in cells(flavors) {
        let wired = wired(&flavor, mode);
        let what = wired.what();
        let (_tmp, cwd) = fresh();
        wired.restore(&cwd, LEDGERS_ONLY);
        wired.revert_wiring(&cwd);
        if mode == Mode::Vendored {
            assert!(
                cwd.join(vendored_wheel_rel()).is_file(),
                "{what}: artifact stays"
            );
        }
        for no_verify in [false, true] {
            let run = VexRun {
                offline: true,
                no_verify,
                ..vex_run(None)
            };
            assert_omitted(
                &vex(&cwd, &run),
                mode.unwired(),
                &format!("{what} nv={no_verify}"),
            );
        }
        // Online too: the API cannot revive a dead ledger claim.
        let api = api_with(mode.uuid(), PURL);
        let run = VexRun {
            no_verify: true,
            ..vex_run(Some(&api))
        };
        assert_omitted(
            &vex(&cwd, &run),
            mode.unwired(),
            &format!("{what} online nv"),
        );

        if let Some(manifest) = wired.files.get(".socket/manifest.json") {
            put(&cwd, ".socket/manifest.json", manifest);
            for no_verify in [false, true] {
                let run = VexRun {
                    offline: true,
                    no_verify,
                    ..vex_run(None)
                };
                let out = vex(&cwd, &run);
                assert_ne!(out.code, Some(0), "{what} manifest nv={no_verify}: {out}");
                assert!(out.doc.is_none(), "{what} manifest nv={no_verify}: {out}");
            }
        }

        let (_tmp2, cwd2) = fresh();
        wired.restore(&cwd2, NOTHING);
        wired.revert_wiring(&cwd2);
        let out = vex(&cwd2, &vex_run(Some(&api)));
        assert_nothing_discovered(&out, &format!("{what} no ledger"));
    }
}

/// Rewrite the committed wheel with `MODULE`'s bytes replaced (every other
/// member kept byte-identical).
pub fn tamper_wheel(cwd: &Path) {
    use std::io::{Read as _, Write as _};
    let path = cwd.join(vendored_wheel_rel());
    let original = std::fs::read(&path).unwrap();
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(original)).unwrap();
    let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let mut saw_module = false;
    for i in 0..archive.len() {
        let mut member = archive.by_index(i).unwrap();
        let name = member.name().to_string();
        let mut bytes = Vec::new();
        member.read_to_end(&mut bytes).unwrap();
        if name == MODULE {
            assert_eq!(
                bytes, PATCHED,
                "the vendored wheel carries the patched bytes"
            );
            bytes = TAMPERED.to_vec();
            saw_module = true;
        }
        out.start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        out.write_all(&bytes).unwrap();
    }
    assert!(saw_module, "the wheel must hold {MODULE}");
    std::fs::write(&path, out.finish().unwrap().into_inner()).unwrap();
}

/// e) tampered installed tree (hosted) / tampered wheel member (vendored)
/// → omitted, with or without the ledgers; `--no-verify` is the documented
/// opt-out of hashing (the wiring/record gates still run).
pub fn e_tampered_evidence_is_omitted(flavors: &[Flavor]) {
    for (flavor, mode) in cells(flavors) {
        let wired = wired(&flavor, mode);
        for keep in [NOTHING, LEDGERS_ONLY] {
            let what = format!("{} ledgers={}", wired.what(), keep.ledgers);
            let (_tmp, cwd) = fresh();
            wired.restore(&cwd, keep);
            let reason = match mode {
                Mode::Hosted => {
                    install(&cwd, ".venv", TAMPERED);
                    "hash_mismatch"
                }
                Mode::Vendored => {
                    tamper_wheel(&cwd);
                    "vendor_hash_mismatch"
                }
            };
            let api = api_with(mode.uuid(), PURL);
            assert_omitted(&vex(&cwd, &vex_run(Some(&api))), reason, &what);
            let run = VexRun {
                no_verify: true,
                ..vex_run(Some(&api))
            };
            assert_ok_attested(&vex(&cwd, &run), mode, &format!("{what} --no-verify"));
        }
    }
}

/// f1) the Socket patch host swapped for a look-alike in every wired file:
/// the uuid-shaped segments (grant token + patch uuid) are all still there.
/// Without a ledger that is not a patch reference at all (nothing is looked
/// up). With the redirect ledger kept, a uuid no allowlisted reference
/// mentions falls back to the LEDGER's own recorded wiring (vex_sources.rs
/// "liveness": self-hosted patch servers outside the allowlist) — which the
/// unchanged sha256 pin still names — so it is NOT unwired, but nothing is
/// installed and the lock is no longer a discovered Socket reference, so no
/// lockfile-pin basis exists either: verification omits it
/// (`package_not_found`).
pub fn f_hosted_uuid_on_a_foreign_host_is_not_a_reference(flavors: &[Flavor]) {
    for flavor in flavors.iter().filter(|f| f.hosted) {
        let wired = wired(flavor, Mode::Hosted);
        for keep in [NOTHING, LEDGERS_ONLY] {
            let what = format!("{} ledgers={}", wired.what(), keep.ledgers);
            let (_tmp, cwd) = fresh();
            wired.restore(&cwd, keep);
            for rel in wired.changed_files() {
                let spoofed = text(&wired.files[rel]).replace(
                    "https://patch.socket.dev/",
                    "https://patch.socket.dev.evil.example/",
                );
                assert!(spoofed.contains(HOSTED_UUID), "{what}: {spoofed}");
                assert!(!spoofed.contains("https://patch.socket.dev/"), "{what}");
                put(&cwd, rel, spoofed.as_bytes());
            }
            let api = api_with(HOSTED_UUID, PURL);
            let out = vex(&cwd, &vex_run(Some(&api)));
            if keep.ledgers {
                assert_omitted(&out, "package_not_found", &what);
            } else {
                assert_nothing_discovered(&out, &what);
                api.assert_no_requests();
            }
        }
    }
}

/// f2) a vendored reference that escapes the project root (`../.socket/…`),
/// with a verifying copy of the wheel planted exactly where it points: a
/// path outside the committed tree is never a vendored patch.
pub fn f_vendored_path_escaping_the_root_is_not_a_reference(flavors: &[Flavor]) {
    for flavor in flavors.iter().filter(|f| f.vendored) {
        let wired = wired(flavor, Mode::Vendored);
        let what = wired.what();
        let (tmp, cwd) = fresh();
        wired.restore(&cwd, NOTHING);
        put(
            tmp.path(),
            &vendored_wheel_rel(),
            &wired.files[&vendored_wheel_rel()],
        );
        std::fs::remove_dir_all(cwd.join(".socket")).unwrap();
        let mut spoofed_any = false;
        for rel in wired.changed_files() {
            let original = text(&wired.files[rel]);
            let spoofed = original
                .replace("./.socket/vendor/", "../.socket/vendor/")
                .replace(
                    "{root:uri}/.socket/vendor/",
                    "{root:uri}/../.socket/vendor/",
                );
            let spoofed = if spoofed == original {
                original.replace(".socket/vendor/", "../.socket/vendor/")
            } else {
                spoofed
            };
            spoofed_any |= spoofed != original;
            put(&cwd, rel, spoofed.as_bytes());
        }
        assert!(spoofed_any, "{what}: nothing to spoof");
        let api = api_with(VENDORED_UUID, PURL);
        let out = vex(&cwd, &vex_run(Some(&api)));
        assert_ne!(out.code, Some(0), "{what}: {out}");
        assert!(out.doc.is_none(), "{what}: {out}");
        let events = out.envelope["events"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            !events.iter().any(|e| e["action"] == "verified"),
            "{what}: {out}"
        );
    }
}

/// f3) the API's record for the wired uuid disagrees with the wiring:
/// another package, version, ecosystem, or uuid → `record_mismatch` (with
/// and without `--no-verify`). The artifact-QUALIFIED spelling of the same
/// purl is the same package and attests.
pub fn f_record_disagreeing_with_the_wiring_is_a_mismatch(flavors: &[Flavor]) {
    for (flavor, mode) in cells(flavors) {
        let wired = wired(&flavor, mode);
        let what = wired.what();
        let (_tmp, cwd) = fresh();
        wired.restore(&cwd, NOTHING);
        let other_uuid = "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b";
        for (label, body) in [
            (
                "other package",
                view(mode.uuid(), "pkg:pypi/otherpkg@1.2.3"),
            ),
            ("other version", view(mode.uuid(), "pkg:pypi/vexdemo@9.9.9")),
            (
                "other ecosystem",
                view(mode.uuid(), "pkg:npm/vexdemo@1.2.3"),
            ),
            ("other uuid", view(other_uuid, PURL)),
        ] {
            let api = PatchApi::start(vec![(mode.uuid().to_string(), body)]);
            for no_verify in [false, true] {
                let run = VexRun {
                    no_verify,
                    ..vex_run(Some(&api))
                };
                assert_omitted(
                    &vex(&cwd, &run),
                    "record_mismatch",
                    &format!("{what} {label} nv={no_verify}"),
                );
            }
        }
        let api = api_with(
            mode.uuid(),
            "pkg:pypi/vexdemo@1.2.3?artifact_id=py3-none-any-whl",
        );
        let out = vex(&cwd, &vex_run(Some(&api)));
        assert_eq!(out.code, Some(0), "{what} qualified: {out}");
    }
}

/// g1) hosted: the installed copy is the evidence once present. Patched →
/// hashed and attested. Pristine (a venv synced before the redirect, or a
/// stale install) → `not_applied`, the pin notwithstanding.
pub fn g_hosted_installed_tree_states(flavors: &[Flavor]) {
    for flavor in flavors.iter().filter(|f| f.hosted) {
        let wired = wired(flavor, Mode::Hosted);
        for (bytes, expect) in [(PATCHED, None), (PRISTINE, Some("not_applied"))] {
            for keep in [NOTHING, LEDGERS_ONLY] {
                let what = format!(
                    "{} installed={expect:?} ledgers={}",
                    wired.what(),
                    keep.ledgers
                );
                let (_tmp, cwd) = fresh();
                wired.restore(&cwd, keep);
                install(&cwd, ".venv", bytes);
                let api = api_with(HOSTED_UUID, PURL);
                let out = vex(&cwd, &vex_run(Some(&api)));
                match expect {
                    None => assert_ok_attested(&out, Mode::Hosted, &what),
                    Some(reason) => assert_omitted(&out, reason, &what),
                }
            }
        }
    }
}

/// Remove every spelling of the `sha` pin the pdm / hatch hosted writers
/// use (`#sha256=` url fragment, pdm `files` rows carrying `sha256:`).
fn strip_sha256_pins(text: &str, sha: &str) -> String {
    let mut out = text.replace(&format!("#sha256={sha}"), "");
    if out.contains("[[package]]") {
        out = out
            .lines()
            .filter(|line| !line.contains(&format!("sha256:{sha}")))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
    }
    out
}

/// g2) hosted with the sha256 pin stripped: the rewriters ALWAYS write one,
/// so the wiring alone is no evidence — only a verifying installed tree is.
pub fn g_hosted_pinless_reference_needs_an_installed_tree(flavors: &[Flavor]) {
    for flavor in flavors.iter().filter(|f| f.hosted) {
        let wired = wired(flavor, Mode::Hosted);
        let what = wired.what();
        let (_tmp, cwd) = fresh();
        wired.restore(&cwd, NOTHING);
        let sha = hosted_sha256();
        let mut stripped_any = false;
        for rel in wired.changed_files() {
            let original = text(&wired.files[rel]);
            let stripped = strip_sha256_pins(&original, &sha);
            stripped_any |= stripped != original;
            put(&cwd, rel, stripped.as_bytes());
        }
        assert!(stripped_any, "{what}: no pin found to strip");
        let api = api_with(HOSTED_UUID, PURL);
        let out = vex(&cwd, &vex_run(Some(&api)));
        assert_eq!(out.code, Some(1), "{what}: {out}");
        assert!(out.doc.is_none(), "{what}: {out}");
        install(&cwd, ".venv", PATCHED);
        let out = vex(&cwd, &vex_run(Some(&api)));
        assert_ok_attested(&out, Mode::Hosted, &format!("{what} installed"));
    }
}

/// g3) vendored: the committed wheel is the evidence, NOT the venv. A venv
/// still holding the pristine release does not unseat the attestation, but
/// it is disclosed as `vendored_tree_out_of_sync`; a patched venv is not.
pub fn g_vendored_attests_over_a_pristine_venv_with_a_warning(flavors: &[Flavor]) {
    let out_of_sync = |out: &VexOutcome| {
        out.envelope["warnings"]
            .as_array()
            .is_some_and(|w| w.iter().any(|w| w["code"] == "vendored_tree_out_of_sync"))
    };
    for flavor in flavors.iter().filter(|f| f.vendored) {
        let wired = wired(flavor, Mode::Vendored);
        let what = wired.what();
        let (_tmp, cwd) = fresh();
        wired.restore(&cwd, NOTHING);
        install(&cwd, ".venv", PRISTINE);
        let api = api_with(VENDORED_UUID, PURL);
        let out = vex(&cwd, &vex_run(Some(&api)));
        assert_ok_attested(&out, Mode::Vendored, &what);
        assert!(out_of_sync(&out), "{what}: {out}");
        install(&cwd, ".venv", PATCHED);
        let out = vex(&cwd, &vex_run(Some(&api)));
        assert_ok_attested(&out, Mode::Vendored, &format!("{what} patched venv"));
        assert!(!out_of_sync(&out), "{what}: {out}");
    }
}

/// `scan --vendor --detached --vex` never writes a manifest; its own VEX
/// and a later standalone `vex` both attest (ledger present, then gone).
pub fn embedded_detached_vendor_scan_attests_without_a_manifest(flavors: &[Flavor]) {
    for flavor in flavors.iter().filter(|f| f.vendored) {
        let (_tmp, cwd) = fresh();
        wire_into(&cwd, flavor, Mode::Vendored, &["--detached"]);
        let what = format!("{} detached", flavor.label);
        assert!(
            !cwd.join(".socket/manifest.json").exists(),
            "{what}: detached writes no manifest"
        );
        let run = VexRun {
            offline: true,
            ..vex_run(None)
        };
        assert_ok_attested(&vex(&cwd, &run), Mode::Vendored, &what);
        std::fs::remove_file(cwd.join(".socket/vendor/state.json")).unwrap();
        let api = api_with(VENDORED_UUID, PURL);
        assert_ok_attested(
            &vex(&cwd, &vex_run(Some(&api))),
            Mode::Vendored,
            &format!("{what} no ledger"),
        );
    }
}

/// A CI re-run of `scan --redirect --vex` / `scan --vendor --vex` on a
/// checkout whose `.socket/` was never committed (the wiring is already
/// there): the embedded document still attests. `expect_refusal` names the
/// flavors whose vendored backend documents a refusal for a ledgerless
/// direct reference (Hatch: "Ledgerless direct references and drifted
/// sources are refused", docs/testing/hatch.md) — scan then exits 1 with the
/// backend's error code and, by contract, generates no VEX (embedded VEX
/// runs only on a zero exit); standalone `vex` still attests that checkout.
pub fn embedded_rescan_of_a_manifest_less_checkout(
    flavors: &[Flavor],
    expect_refusal: Option<&str>,
) {
    for (flavor, mode) in cells(flavors) {
        let wired = wired(&flavor, mode);
        let what = format!("{} re-scan", wired.what());
        let (_tmp, cwd) = fresh();
        wired.restore(&cwd, NOTHING);
        if mode == Mode::Vendored {
            install(&cwd, ".venv", PRISTINE);
        }
        let api = ScanApi::start(mode.uuid());
        let vex_out = cwd.join("scan.vex.json");
        let (code, env, stderr) = run_scan(
            &cwd,
            &api,
            mode,
            &["--vex", vex_out.to_str().unwrap(), "--vex-product", PRODUCT],
        );
        match (mode, expect_refusal) {
            (Mode::Vendored, Some(refusal)) => {
                assert_eq!(code, Some(1), "{what}: {env}\n{stderr}");
                assert_eq!(
                    env["vendor"]["events"][0]["errorCode"], refusal,
                    "{what}: {env}"
                );
                assert!(!vex_out.exists(), "{what}: no VEX on a failed scan");
                let _ = std::fs::remove_dir_all(cwd.join(".venv"));
                let patch_api = api_with(mode.uuid(), PURL);
                assert_ok_attested(
                    &vex(&cwd, &vex_run(Some(&patch_api))),
                    mode,
                    &format!("{what} standalone"),
                );
            }
            _ => {
                assert_eq!(code, Some(0), "{what}: {env}\n{stderr}");
                let doc: Value = serde_json::from_slice(
                    &std::fs::read(&vex_out)
                        .unwrap_or_else(|e| panic!("{what}: ({e}) {env}\n{stderr}")),
                )
                .unwrap();
                assert_statement(&doc, mode, &what);
            }
        }
    }
}

/// `apply --vex` and `vendor --vex` on a manifest-less wired checkout (CI:
/// install, then `socket-patch apply --vex out.json`): the patches the
/// wiring names are attested although there is no manifest to apply —
/// offline from the ledgers, and online from the API with no ledger.
pub fn embedded_apply_and_vendor_vex_attest_a_manifest_less_checkout(flavors: &[Flavor]) {
    for (flavor, mode) in cells(flavors) {
        let wired = wired(&flavor, mode);
        for via in [VexVia::Apply, VexVia::Vendor] {
            for keep in [LEDGERS_ONLY, NOTHING] {
                let what = format!("{} {via:?} ledgers={}", wired.what(), keep.ledgers);
                let (_tmp, cwd) = fresh();
                wired.restore(&cwd, keep);
                let api = api_with(mode.uuid(), PURL);
                let run = VexRun {
                    offline: keep.ledgers,
                    ..vex_run(Some(&api))
                }
                .via(via);
                let out = vex(&cwd, &run);
                assert_eq!(out.code, Some(0), "{what}: {out}");
                assert_eq!(out.envelope["vex"]["statements"], 1, "{what}: {out}");
                assert_statement(out.doc(), mode, &what);
                assert!(!cwd.join(".socket/manifest.json").exists(), "{what}");
                if keep.ledgers {
                    api.assert_no_requests();
                }
            }
        }
    }
}

/// The purl is not attested anywhere in `out`'s document (if any).
pub fn assert_no_statement(out: &VexOutcome, what: &str) {
    if let Some(doc) = &out.doc {
        assert!(statements_for(doc, PURL).is_empty(), "{what}: {out}");
    }
}
