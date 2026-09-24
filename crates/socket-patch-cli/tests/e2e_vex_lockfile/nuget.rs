//! Manifest-less `socket-patch vex` for NUGET: the hosted
//! (`scan --mode hosted` → `rewrite_nuget`: a `socket-patch-<uuid>` source,
//! an exact-id `packageSourceMapping` and the lock's re-pinned
//! `contentHash`) and vendored (`vendor` → `vendor::nuget_feed`: a local
//! `.socket/vendor/nuget/<uuid>` feed + mapping + re-pin) wirings are
//! attested from the project files alone — no `.socket/manifest.json`, and
//! (except where a cell says otherwise) no `.socket/vendor/state.json` or
//! `redirect-state.json` ledger — and never falsely.
//!
//! Hermetic on every OS: the patch API is the shared `vex_e2e_common`
//! stand-in (public-proxy `GET /patch/view/<uuid>` via `--proxy-url`), the
//! global packages folder is a per-test temp dir (`NUGET_PACKAGES`), and no
//! real `dotnet` runs (the real-SDK capstones, one per SDK major, live in
//! `e2e_nuget_dotnet_build.rs`).
//!
//! Matrix (per flavor × {hosted, vendored}):
//!
//! | cell | shape | expectation |
//! |---|---|---|
//! | a | no manifest, no ledgers, online | attested `(redirected)` / `(vendored)` with the record's purl, the record's vuln id + CVE alias, exit 0, a `verified` envelope event |
//! | b | `--offline` (and an unreachable API) with no local record | `record_unavailable`, exit 1, ZERO requests reach the API under `--offline` |
//! | c | ledger present, manifest absent, `--offline` | attested from the ledger's embedded record |
//! | d | wiring reverted to the registry, ledger (+ artifact) left behind | `redirect_unwired` / `vendor_unwired`, with and without `--no-verify` |
//! | e | tampered installed tree (hosted) / tampered artifact member (vendored) | omitted `hash_mismatch` / `vendor_hash_mismatch` |
//! | f | uuid-shaped segment on a non-Socket host / outside the vendor tree; a record naming another package, version or patch | not a reference (exit 2, nothing to attest, no fetch) / `record_mismatch` |
//! | g | hosted not installed / installed + patched / installed pristine | attests from the lock's `contentHash` pin (D5) / attests after hashing / omitted `not_applied` |
//!
//! Flavors: every hosted golden (`packages.lock.json` + `nuget.config`,
//! incl. empty / self-closing `<packageSources>` and no pre-existing
//! mapping), the three config spellings NuGet reads, and vendored with and
//! without a lock. Embedded: the REAL writers (`vendor --vex`,
//! `scan --mode hosted --vex`, `apply --vex`) produce the state, then the
//! manifest and ledgers are deleted and the standalone `vex` re-attests.
//!
//! Documented limitations are asserted explicitly (never skipped): a
//! hosted source with no lock (no version to attribute), a lock entry
//! without a `contentHash` pin, and agent-mode (`apply`) patches, which
//! have no lockfile wiring to discover.

use crate::vex_e2e_common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
use socket_patch_core::patch::redirect::{FileEdit, RedirectState};
use socket_patch_core::vendor::state::{
    VendorArtifact, VendorEntry, VendorState, WiringAction, WiringRecord,
};
use vex_e2e_common::{assert_omitted_parts, binary, run_vex, PatchApi, VexRun};

const PRODUCT: &str = "pkg:nuget/app@1.0.0";

/// The committed hosted goldens' patch identity.
const NUGET_HOSTED_UUID: &str = "66666666-6666-6666-6666-666666666666";
/// The purl the patch API names for the nuget patch (NuGet ids are
/// case-insensitive; the API keeps the gallery casing).
const NUGET_PURL: &str = "pkg:nuget/Newtonsoft.Json@13.0.3";
const NUGET_VENDOR_UUID: &str = "6a6a6a6a-1111-4111-8111-6a6a6a6a6a6a";

const GHSA: &str = "GHSA-nuget-lock-vex0";
const CVE: &str = "CVE-2026-7100";

// ── process plumbing ─────────────────────────────────────────────────────

/// The CLI for the embedded writers (`vendor` / `scan` / `apply`), with
/// every ambient `SOCKET_*` variable scrubbed, telemetry/config off, and the
/// global packages folder pinned to `store` — an ambient `~/.nuget/packages`
/// must never become installed evidence.
fn cli(store: &Path) -> Command {
    let mut cmd = Command::new(binary());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("NUGET_PACKAGES", store.join("nuget"))
        .env_remove("VIRTUAL_ENV");
    cmd
}

/// One hermetic project: `<tmp>/app` is the checkout, `<tmp>/store/nuget`
/// the global packages folder.
struct Fx {
    tmp: tempfile::TempDir,
    cwd: PathBuf,
}

impl Fx {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("app");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(tmp.path().join("store/nuget")).unwrap();
        Fx { tmp, cwd }
    }

    fn store(&self) -> PathBuf {
        self.tmp.path().join("store")
    }

    fn nuget(&self) -> PathBuf {
        self.store().join("nuget")
    }

    fn put(&self, rel: &str, bytes: impl AsRef<[u8]>) {
        put(&self.cwd, rel, bytes.as_ref());
    }

    fn rm(&self, rel: &str) {
        let p = self.cwd.join(rel);
        if p.is_dir() {
            std::fs::remove_dir_all(&p).unwrap();
        } else if p.exists() {
            std::fs::remove_file(&p).unwrap();
        }
    }

    fn assert_no_manifest(&self) {
        assert!(
            !self.cwd.join(".socket/manifest.json").exists(),
            "fixture sanity: no manifest"
        );
    }

    /// `socket-patch vex --json --output out.vex.json` (the shared
    /// `run_vex`, hermetic) + `extra` → (exit, envelope).
    fn vex(&self, extra: &[&str]) -> (Option<i32>, Value) {
        let _ = std::fs::remove_file(self.cwd.join("out.vex.json"));
        let run = VexRun {
            product: Some(PRODUCT.to_string()),
            extra_args: extra.iter().map(|s| s.to_string()).collect(),
            ..VexRun::default()
        }
        .env("NUGET_PACKAGES", self.nuget());
        let out = run_vex(&binary(), &self.cwd, &run);
        (out.code, out.envelope)
    }

    /// The OpenVEX document the last successful [`Fx::vex`] wrote.
    fn doc(&self) -> Value {
        doc_at(&self.cwd.join("out.vex.json"))
    }
}

/// The shared patch-API stand-in serving `(uuid, view)` pairs.
struct Api(PatchApi);

impl Api {
    fn serve(views: Vec<(&str, Value)>) -> Self {
        Api(PatchApi::start(
            views
                .into_iter()
                .map(|(uuid, body)| (uuid.to_string(), body))
                .collect(),
        ))
    }

    fn uri(&self) -> String {
        self.0.uri()
    }

    fn requests(&self) -> usize {
        self.0.request_count()
    }
}

/// The authenticated API + feed stand-in `scan --mode hosted` drives
/// (built in [`serve_hosted_api`]). Keep it alive for the invocation.
struct HostedApi {
    rt: tokio::runtime::Runtime,
    server: wiremock::MockServer,
}

impl HostedApi {
    fn uri(&self) -> String {
        self.server.uri()
    }

    fn requests(&self) -> usize {
        self.rt
            .block_on(self.server.received_requests())
            .map_or(0, |r| r.len())
    }
}

fn put(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn doc_at(path: &Path) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap()
}

/// Cell (a)'s full oracle: exit 0, exactly one `not_affected` statement for
/// `uuid` with the `marker` provenance, `purl` (the record's purl, which
/// keeps the API's casing for case-insensitive nuget ids) as the
/// subcomponent, the
/// record's vuln id + CVE alias, and a `verified` envelope event.
fn assert_attested(fx: &Fx, code: Option<i32>, env: &Value, uuid: &str, purl: &str, marker: &str) {
    assert_eq!(code, Some(0), "{purl} ({marker}) must attest: {env}");
    let doc = fx.doc();
    let stmts = doc["statements"].as_array().expect("statements");
    assert_eq!(stmts.len(), 1, "exactly one statement: {doc}");
    let st = &stmts[0];
    assert_eq!(st["status"], "not_affected", "{doc}");
    assert_eq!(st["vulnerability"]["name"], GHSA, "{doc}");
    assert_eq!(st["vulnerability"]["aliases"][0], CVE, "{doc}");
    assert_eq!(
        st["impact_statement"],
        format!("Patched via Socket patch {uuid} ({marker})"),
        "{doc}"
    );
    let sub = st["products"][0]["subcomponents"][0]["@id"]
        .as_str()
        .expect("subcomponent id");
    assert_eq!(
        sub, purl,
        "the subcomponent must be the record's (API-cased) purl of the wired package: {doc}"
    );
    assert_eq!(st["products"][0]["@id"], PRODUCT, "{doc}");
    let verified = env["events"]
        .as_array()
        .expect("events")
        .iter()
        .filter(|e| e["action"] == "verified")
        .count();
    assert_eq!(verified, 1, "one verified event: {env}");
    assert!(
        !fx.cwd.join(".socket/manifest.json").exists(),
        "vex never writes the manifest"
    );
}

/// The omission oracle: exit 1 `no_applicable_patches`, `purl` skipped with
/// `reason`, no statement.
fn assert_omitted(code: Option<i32>, env: &Value, purl: &str, reason: &str, what: &str) {
    // `Fx::vex` deletes the output before every run, and a failed run
    // writes none: the shared oracle's document check has nothing to read.
    assert_omitted_parts(code, env, None, purl, reason, what);
}

/// Nothing discovered and nothing recorded: `manifest_not_found`, exit 2.
fn assert_nothing_to_attest(code: Option<i32>, env: &Value, what: &str) {
    assert_eq!(code, Some(2), "{what}: {env}");
    assert_eq!(env["error"]["code"], "manifest_not_found", "{what}: {env}");
}

// ── the patch API stand-in ───────────────────────────────────────────────

/// The patch view for `uuid` → `purl`: `(file key, before, after)` files,
/// one GHSA with a CVE alias.
fn view(uuid: &str, purl: &str, files: &[(&str, &[u8], &[u8])]) -> Value {
    let files: serde_json::Map<String, Value> = files
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
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "Fri, 27 Mar 2026 00:00:00 GMT",
        "files": files,
        "vulnerabilities": {
            GHSA: { "cves": [CVE], "summary": "s", "severity": "high", "description": "d" }
        },
        "description": "lockfile-discovered patch",
        "license": "MIT",
        "tier": "free",
    })
}

/// The ledger's embedded record for the same patch [`view`] serves.
fn record(uuid: &str, files: &[(&str, &[u8], &[u8])]) -> PatchRecord {
    let files: HashMap<String, PatchFileInfo> = files
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
    let mut vulns = HashMap::new();
    vulns.insert(
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
        vulnerabilities: vulns,
        description: "ledger record".to_string(),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

/// `.socket/vendor/redirect-state.json` recording `purl` → `record` and a
/// rewrite of every file in `edited` (what `scan --mode hosted` persists).
fn write_redirect_ledger(fx: &Fx, purl: &str, rec: PatchRecord, edited: &[(&str, &str)]) {
    let mut state = RedirectState::new();
    state.records.insert(purl.to_string(), rec);
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

/// `.socket/vendor/state.json` with one entry (embedded record, the
/// backend's wiring record) — what `vendor` persists.
#[allow(clippy::too_many_arguments)]
fn write_vendor_ledger(
    fx: &Fx,
    eco: &str,
    purl: &str,
    uuid: &str,
    artifact_rel: &str,
    rec: PatchRecord,
    wiring: (&str, &str),
) {
    let sha256 = sha256_hex(&std::fs::read(fx.cwd.join(artifact_rel)).unwrap());
    let mut state = VendorState::new();
    state.entries.insert(
        purl.to_string(),
        VendorEntry {
            ecosystem: eco.to_string(),
            base_purl: purl.to_string(),
            uuid: uuid.to_string(),
            artifact: VendorArtifact {
                path: artifact_rel.to_string(),
                sha256,
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring: vec![WiringRecord {
                file: wiring.0.to_string(),
                kind: wiring.1.to_string(),
                action: WiringAction::Rewritten,
                key: None,
                original: None,
                new: None,
            }],
            lock: None,
            took_over_go_patches: false,
            detached: true,
            record: Some(rec),
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
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// A zip-family artifact (`.nupkg`) holding `members`.
fn zip_bytes(members: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, bytes) in members {
            writer.start_file(*name, opts).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
    }
    buf.into_inner()
}

/// A committed hosted-rewriter golden (`socket-patch-core/tests/fixtures/
/// redirect/<rel>`).
fn fixture_dir(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../socket-patch-core/tests/fixtures/redirect")
        .join(rel)
}

/// Copy every file of a golden dir into `fx`'s checkout, returning the
/// root-relative paths copied.
fn copy_golden(fx: &Fx, rel: &str) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                out.push(
                    path.strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    let base = fixture_dir(rel);
    let mut files = Vec::new();
    walk(&base, &base, &mut files);
    files.sort();
    for file in &files {
        fx.put(file, std::fs::read(base.join(file)).unwrap());
    }
    files
}

// ══════════════════════════════════════════════════════════════════════════
// NUGET — hosted (`rewrite_nuget`: source + exact-id mapping + lock re-pin)
// ══════════════════════════════════════════════════════════════════════════

/// The nuget patch's single file, keyed relative to the global packages
/// folder's `<idLower>/<version>/` dir (the crawler's package dir).
const NUGET_FILE_KEY: &str = "lib/net6.0/Newtonsoft.Json.dll";
const NUGET_PRISTINE: &[u8] = b"MZ newtonsoft pristine dll";
const NUGET_PATCHED: &[u8] = b"MZ newtonsoft patched dll";

fn nuget_files() -> Vec<(&'static str, &'static [u8], &'static [u8])> {
    vec![(NUGET_FILE_KEY, NUGET_PRISTINE, NUGET_PATCHED)]
}

fn nuget_hosted_view() -> Value {
    view(NUGET_HOSTED_UUID, NUGET_PURL, &nuget_files())
}

const NUGET_HOSTED_GOLDENS: &[&str] = &[
    "nuget/packages-lock/basic",
    "nuget/packages-lock/empty-sources",
    "nuget/packages-lock/empty-sources-selfclosing",
    "nuget/packages-lock/no-preexisting-mapping",
];

/// Cells a, b, c, d and f (record mismatch) for one hosted nuget wiring laid
/// down by `setup`; `revert` puts the registry-only shape back.
fn nuget_hosted_cells(what: &str, setup: &dyn Fn(&Fx), revert: &dyn Fn(&Fx)) {
    // (a) online, nothing installed: the lock's re-pinned contentHash is
    // the evidence (nuget's hosted `integrity_required` is true).
    let fx = Fx::new();
    setup(&fx);
    fx.assert_no_manifest();
    let api = Api::serve(vec![(NUGET_HOSTED_UUID, nuget_hosted_view())]);
    let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(&fx, code, &env, NUGET_HOSTED_UUID, NUGET_PURL, "redirected");

    // (b) offline / unreachable API with no local record.
    let before = api.requests();
    let (code, env) = fx.vex(&["--offline", "--proxy-url", &api.uri()]);
    assert_omitted(code, &env, NUGET_PURL, "record_unavailable", what);
    assert_eq!(api.requests(), before, "{what}: --offline made a request");
    let (code, env) = fx.vex(&["--proxy-url", "http://127.0.0.1:9"]);
    assert_omitted(code, &env, NUGET_PURL, "record_unavailable", what);

    // (f) the record names another package / version / patch.
    for (label, bad) in [
        (
            "other package",
            view(
                NUGET_HOSTED_UUID,
                "pkg:nuget/Newtonsoft.Json.Bson@13.0.3",
                &nuget_files(),
            ),
        ),
        (
            "other version",
            view(
                NUGET_HOSTED_UUID,
                "pkg:nuget/Newtonsoft.Json@13.0.1",
                &nuget_files(),
            ),
        ),
        (
            "other uuid",
            view(
                "12121212-3434-4565-8787-909090909090",
                NUGET_PURL,
                &nuget_files(),
            ),
        ),
    ] {
        let bad_api = Api::serve(vec![(NUGET_HOSTED_UUID, bad)]);
        let (code, env) = fx.vex(&["--proxy-url", &bad_api.uri()]);
        assert_omitted(
            code,
            &env,
            NUGET_PURL,
            "record_mismatch",
            &format!("{what}: {label}"),
        );
    }

    // (c) the redirect ledger's record, offline, no manifest.
    write_redirect_ledger(
        &fx,
        NUGET_PURL,
        record(NUGET_HOSTED_UUID, &nuget_files()),
        &[
            ("nuget.config", "redirect_nuget_config"),
            ("packages.lock.json", "redirect_nuget_lock"),
        ],
    );
    let (code, env) = fx.vex(&["--offline"]);
    assert_attested(&fx, code, &env, NUGET_HOSTED_UUID, NUGET_PURL, "redirected");

    // (d) reverted to the registry, ledger left behind: dead.
    revert(&fx);
    for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
        let (code, env) = fx.vex(extra);
        assert_omitted(
            code,
            &env,
            NUGET_PURL,
            "redirect_unwired",
            &format!("{what} reverted {extra:?}"),
        );
    }
}

#[test]
fn nuget_hosted_goldens_attest_without_manifest_or_ledgers() {
    for golden in NUGET_HOSTED_GOLDENS {
        nuget_hosted_cells(
            golden,
            &|fx| {
                copy_golden(fx, &format!("{golden}/expected"));
            },
            &|fx| {
                fx.rm("nuget.config");
                copy_golden(fx, &format!("{golden}/input"));
            },
        );
    }
}

/// NuGet reads the first of `nuget.config`, `NuGet.config`, `NuGet.Config`
/// (case-insensitive filesystems make them one file). Each spelling alone
/// carries the wiring. Reverting only the mapping (the pin) — the source
/// definition left behind — is dead too (rule 10).
#[test]
fn nuget_hosted_config_spellings_and_a_mapping_only_revert() {
    let golden = "nuget/packages-lock/basic/expected";
    let config = std::fs::read_to_string(fixture_dir(golden).join("nuget.config")).unwrap();
    let lock = std::fs::read_to_string(fixture_dir(golden).join("packages.lock.json")).unwrap();
    let unmapped = config.replace(
        &format!(
            "    <packageSource key=\"socket-patch-{NUGET_HOSTED_UUID}\">\n      \
             <package pattern=\"Newtonsoft.Json\" />\n    </packageSource>\n"
        ),
        "",
    );
    assert_ne!(unmapped, config);
    for name in ["nuget.config", "NuGet.config", "NuGet.Config"] {
        nuget_hosted_cells(
            name,
            &|fx| {
                fx.put(name, &config);
                fx.put("packages.lock.json", &lock);
            },
            &|fx| fx.put(name, &unmapped),
        );
    }
}

/// Cells e and g. NuGet restores into ONE global packages folder shared by
/// every source (`<NUGET_PACKAGES>/<idLower>/<version>/`), so the copy
/// there is the one the build consumes, whichever source it came from.
#[test]
fn nuget_hosted_installed_tree_is_the_evidence_once_present() {
    let fx = Fx::new();
    copy_golden(&fx, "nuget/packages-lock/basic/expected");
    fx.put(
        "app.csproj",
        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>\
         <TargetFramework>net6.0</TargetFramework></PropertyGroup></Project>",
    );
    let api = Api::serve(vec![(NUGET_HOSTED_UUID, nuget_hosted_view())]);
    let args = ["--proxy-url", &api.uri()];
    let pkg = fx.nuget().join("newtonsoft.json/13.0.3");

    // (g) not installed: attests from the contentHash pin.
    let (code, env) = fx.vex(&args);
    assert_attested(&fx, code, &env, NUGET_HOSTED_UUID, NUGET_PURL, "redirected");

    // (g) installed and patched.
    put(&pkg, "newtonsoft.json.nuspec", b"<package/>");
    put(&pkg, NUGET_FILE_KEY, NUGET_PATCHED);
    let (code, env) = fx.vex(&args);
    assert_attested(&fx, code, &env, NUGET_HOSTED_UUID, NUGET_PURL, "redirected");

    // (e) tampered installed file.
    put(&pkg, NUGET_FILE_KEY, b"MZ tampered");
    let (code, env) = fx.vex(&args);
    assert_omitted(code, &env, NUGET_PURL, "hash_mismatch", "tampered dll");
    // --no-verify skips the hash, not the wiring gate.
    let (code, env) = fx.vex(&["--proxy-url", &api.uri(), "--no-verify"]);
    assert_attested(&fx, code, &env, NUGET_HOSTED_UUID, NUGET_PURL, "redirected");

    // (g) installed PRISTINE (a same-version copy restored from nuget.org
    // before the redirect is what the shared folder serves): omitted.
    put(&pkg, NUGET_FILE_KEY, NUGET_PRISTINE);
    let (code, env) = fx.vex(&args);
    assert_omitted(code, &env, NUGET_PURL, "not_applied", "pristine dll");
}

/// A lock entry WITHOUT a contentHash was not written by `rewrite_nuget`
/// (it always re-pins): it may not attest from the lock alone — only a
/// verifying installed tree can.
#[test]
fn nuget_hosted_pinless_lock_entry_needs_an_installed_tree() {
    let fx = Fx::new();
    copy_golden(&fx, "nuget/packages-lock/basic/expected");
    let mut lock: Value =
        serde_json::from_slice(&std::fs::read(fx.cwd.join("packages.lock.json")).unwrap()).unwrap();
    lock["dependencies"]["net6.0"]["Newtonsoft.Json"]
        .as_object_mut()
        .unwrap()
        .remove("contentHash");
    fx.put("packages.lock.json", lock.to_string());
    fx.put("app.csproj", "<Project/>");
    let api = Api::serve(vec![(NUGET_HOSTED_UUID, nuget_hosted_view())]);
    let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
    assert_omitted(code, &env, NUGET_PURL, "package_not_found", "pin-less");
    put(
        &fx.nuget().join("newtonsoft.json/13.0.3"),
        NUGET_FILE_KEY,
        NUGET_PATCHED,
    );
    let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(&fx, code, &env, NUGET_HOSTED_UUID, NUGET_PURL, "redirected");
}

/// Cell f: a `socket-patch-<uuid>` source on a non-Socket host, and a
/// Socket url naming another patch than its key, wire nothing — with no
/// manifest/ledger there is nothing to attest and no record is fetched.
/// A ledger for the uuid stays dead for the rejected Socket-host shape.
#[test]
fn nuget_hosted_spoofed_sources_never_attest() {
    let golden = "nuget/packages-lock/basic/expected";
    let config = std::fs::read_to_string(fixture_dir(golden).join("nuget.config")).unwrap();
    let lock = std::fs::read_to_string(fixture_dir(golden).join("packages.lock.json")).unwrap();
    let foreign = config.replace("https://patch.socket.dev", "https://evil.example");
    let other_uuid = config.replace(
        &format!("/{NUGET_HOSTED_UUID}/index.json"),
        "/12121212-3434-4565-8787-909090909090/index.json",
    );
    let plain_http = config.replace("https://patch.socket.dev", "http://patch.socket.dev");
    for (label, cfg) in [
        ("foreign host", &foreign),
        ("key/url uuid mismatch", &other_uuid),
        ("plain http", &plain_http),
    ] {
        assert_ne!(cfg, &config, "{label}");
        let fx = Fx::new();
        fx.put("nuget.config", cfg);
        fx.put("packages.lock.json", &lock);
        let api = Api::serve(vec![(NUGET_HOSTED_UUID, nuget_hosted_view())]);
        let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
        assert_nothing_to_attest(code, &env, label);
        assert_eq!(api.requests(), 0, "{label}: no record fetch for a non-ref");
    }
}

/// A hosted source + mapping with NO `packages.lock.json` names no version
/// (a csproj `Version` is a minimum), so it is no reference — nothing to
/// attest from the lockfiles alone. But it is `rewrite_nuget`'s ordinary
/// output for a project without RestorePackagesWithLockFile: the exclusive
/// exact-id mapping routes every restore of the id to the Socket source,
/// which serves only the patched version, so the redirect ledger's record
/// (which supplies the exact version) is live and attests `(redirected)`.
/// REGRESSION: it used to be `redirect_unwired`.
#[test]
fn nuget_hosted_source_without_a_lock_attests_through_its_ledger() {
    let fx = Fx::new();
    let golden = "nuget/packages-lock/basic/expected";
    fx.put(
        "nuget.config",
        std::fs::read(fixture_dir(golden).join("nuget.config")).unwrap(),
    );
    let api = Api::serve(vec![(NUGET_HOSTED_UUID, nuget_hosted_view())]);
    let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
    assert_nothing_to_attest(code, &env, "no lock");
    write_redirect_ledger(
        &fx,
        NUGET_PURL,
        record(NUGET_HOSTED_UUID, &nuget_files()),
        &[("nuget.config", "redirect_nuget_config")],
    );
    let (code, env) = fx.vex(&["--offline", "--no-verify"]);
    assert_attested(&fx, code, &env, NUGET_HOSTED_UUID, NUGET_PURL, "redirected");
}

// ══════════════════════════════════════════════════════════════════════════
// VENDORED — `vendor::nuget_feed` (local feed + exact-id mapping + re-pin)
// ══════════════════════════════════════════════════════════════════════════

/// One vendored package: how to wire it, where its artifact lives, what its
/// record hashes (zip MEMBERS of the committed `.nupkg`).
struct Vendored {
    eco: &'static str,
    /// The purl the lock/config wires (discovery's canonical form).
    purl: &'static str,
    /// The purl the API / ledger names.
    record_purl: &'static str,
    uuid: &'static str,
    artifact_rel: String,
    member: &'static str,
    wiring_file: &'static str,
    wiring_kind: &'static str,
}

const MEMBER_PRISTINE: &[u8] = b"upstream NOTICE\n";
const MEMBER_PATCHED: &[u8] = b"upstream NOTICE\nSOCKET-PATCHED\n";

impl Vendored {
    fn nuget() -> Self {
        Vendored {
            eco: "nuget",
            purl: "pkg:nuget/newtonsoft.json@13.0.3",
            record_purl: NUGET_PURL,
            uuid: NUGET_VENDOR_UUID,
            artifact_rel: format!(
                ".socket/vendor/nuget/{NUGET_VENDOR_UUID}/newtonsoft.json.13.0.3.nupkg"
            ),
            member: "LICENSE.md",
            wiring_file: "nuget.config",
            wiring_kind: "nuget_config_source",
        }
    }

    fn files(&self) -> Vec<(&'static str, &'static [u8], &'static [u8])> {
        vec![(self.member, MEMBER_PRISTINE, MEMBER_PATCHED)]
    }

    fn view(&self) -> Value {
        view(self.uuid, self.record_purl, &self.files())
    }

    /// Commit the artifact (member bytes `content`) and return its bytes.
    fn write_artifact(&self, fx: &Fx, content: &[u8]) -> Vec<u8> {
        let bytes = zip_bytes(&[(self.member, content), ("extra/unpatched.txt", b"x")]);
        fx.put(&self.artifact_rel, &bytes);
        bytes
    }

    fn ledger(&self, fx: &Fx) {
        write_vendor_ledger(
            fx,
            self.eco,
            self.record_purl,
            self.uuid,
            &self.artifact_rel,
            record(self.uuid, &self.files()),
            (self.wiring_file, self.wiring_kind),
        );
    }
}

/// `vendor_nuget`'s config: the relative feed source + its exact-id mapping
/// (+ the `*` catch-all to nuget.org the writer fans out).
fn vendored_nuget_config(value: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    \
         <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n    \
         <add key=\"socket-patch-{NUGET_VENDOR_UUID}\" value=\"{value}\" />\n  \
         </packageSources>\n  <packageSourceMapping>\n    \
         <packageSource key=\"nuget.org\">\n      <package pattern=\"*\" />\n    \
         </packageSource>\n    <packageSource key=\"socket-patch-{NUGET_VENDOR_UUID}\">\n      \
         <package pattern=\"Newtonsoft.Json\" />\n    </packageSource>\n  \
         </packageSourceMapping>\n</configuration>\n"
    )
}

fn registry_nuget_config() -> String {
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    \
     <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n  \
     </packageSources>\n</configuration>\n"
        .to_string()
}

/// `packages.lock.json` pinning the vendored nupkg's contentHash (what
/// `vendor_nuget` re-pins).
fn nuget_lock(content_hash: &str) -> String {
    serde_json::json!({
        "version": 1,
        "dependencies": { "net8.0": { "Newtonsoft.Json": {
            "type": "Direct",
            "requested": "[13.0.3, )",
            "resolved": "13.0.3",
            "contentHash": content_hash
        } } }
    })
    .to_string()
}

fn nupkg_content_hash(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha512};
    base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
}

/// Cells a–f for one vendored wiring. `wire` writes the project files for
/// the committed artifact bytes; `unwire` reverts them to the registry.
fn vendored_cells(v: &Vendored, what: &str, wire: &dyn Fn(&Fx, &[u8]), unwire: &dyn Fn(&Fx)) {
    let fx = Fx::new();
    let bytes = v.write_artifact(&fx, MEMBER_PATCHED);
    wire(&fx, &bytes);
    fx.assert_no_manifest();
    assert!(!fx.cwd.join(".socket/vendor/state.json").exists());
    let api = Api::serve(vec![(v.uuid, v.view())]);

    // (a) online, no manifest, no ledger: the committed artifact's members
    // are hashed against the fetched record.
    let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(&fx, code, &env, v.uuid, v.record_purl, "vendored");

    // (b) offline / unreachable with no local record.
    let before = api.requests();
    let (code, env) = fx.vex(&["--offline", "--proxy-url", &api.uri()]);
    assert_omitted(code, &env, v.purl, "record_unavailable", what);
    assert_eq!(api.requests(), before, "{what}: --offline made a request");
    let (code, env) = fx.vex(&["--proxy-url", "http://127.0.0.1:9"]);
    assert_omitted(code, &env, v.purl, "record_unavailable", what);

    // (f) the record names another package / patch.
    let other_purl = "pkg:nuget/Newtonsoft.Json.Bson@13.0.3";
    for (label, bad) in [
        ("other package", view(v.uuid, other_purl, &v.files())),
        (
            "other uuid",
            view(
                "12121212-3434-4565-8787-909090909090",
                v.record_purl,
                &v.files(),
            ),
        ),
    ] {
        let bad_api = Api::serve(vec![(v.uuid, bad)]);
        let (code, env) = fx.vex(&["--proxy-url", &bad_api.uri()]);
        assert_omitted(
            code,
            &env,
            v.purl,
            "record_mismatch",
            &format!("{what}: {label}"),
        );
    }

    // (e) a tampered artifact member (no ledger): the fetched record's
    // afterHash no longer matches.
    let tampered = v.write_artifact(&fx, b"tampered NOTICE\n");
    wire(&fx, &tampered);
    let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
    assert_omitted(code, &env, v.purl, "vendor_hash_mismatch", what);

    // (c) the vendor ledger's embedded record, offline, no manifest.
    let bytes = v.write_artifact(&fx, MEMBER_PATCHED);
    wire(&fx, &bytes);
    v.ledger(&fx);
    let (code, env) = fx.vex(&["--offline"]);
    assert_attested(&fx, code, &env, v.uuid, v.record_purl, "vendored");

    // (e) with the ledger: a tampered member is caught too.
    let good = std::fs::read(fx.cwd.join(&v.artifact_rel)).unwrap();
    let tampered = zip_bytes(&[
        (v.member, b"tampered NOTICE\n"),
        ("extra/unpatched.txt", b"x"),
    ]);
    fx.put(&v.artifact_rel, &tampered);
    let (code, env) = fx.vex(&["--offline"]);
    assert_omitted(code, &env, v.purl, "vendor_hash_mismatch", what);
    fx.put(&v.artifact_rel, &good);

    // (d) the wiring reverted, ledger + artifact left behind: dead, even
    // under --no-verify.
    unwire(&fx);
    for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
        let (code, env) = fx.vex(extra);
        assert_omitted(
            code,
            &env,
            v.purl,
            "vendor_unwired",
            &format!("{what} reverted {extra:?}"),
        );
    }
}

#[test]
fn nuget_vendored_attests_with_and_without_a_lock_in_every_config_spelling() {
    let v = Vendored::nuget();
    let value = format!(".socket/vendor/nuget/{NUGET_VENDOR_UUID}");
    for name in ["nuget.config", "NuGet.config", "NuGet.Config"] {
        for locked in [true, false] {
            vendored_cells(
                &v,
                &format!("{name} locked={locked}"),
                &|fx, bytes| {
                    fx.put(name, vendored_nuget_config(&value));
                    if locked {
                        fx.put("packages.lock.json", nuget_lock(&nupkg_content_hash(bytes)));
                    }
                },
                &|fx| fx.put(name, registry_nuget_config()),
            );
        }
    }
}

/// The vendored tree is the product the build consumes — an installed
/// store copy (pristine, e.g. from before vendoring) does not block the
/// attestation (it is disclosed as out of sync, never judged).
#[test]
fn vendored_attestation_ignores_a_pristine_store_copy() {
    let v = Vendored::nuget();
    {
        let fx = Fx::new();
        let bytes = v.write_artifact(&fx, MEMBER_PATCHED);
        fx.put(
            "nuget.config",
            vendored_nuget_config(&format!(".socket/vendor/nuget/{NUGET_VENDOR_UUID}")),
        );
        fx.put(
            "packages.lock.json",
            nuget_lock(&nupkg_content_hash(&bytes)),
        );
        fx.put("app.csproj", "<Project/>");
        put(
            &fx.nuget().join("newtonsoft.json/13.0.3"),
            v.member,
            MEMBER_PRISTINE,
        );
        let api = Api::serve(vec![(v.uuid, v.view())]);
        let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
        assert_attested(&fx, code, &env, v.uuid, v.record_purl, "vendored");
    }
}

/// Cell f (vendored): a `socket-patch-vendor-<uuid>` repository / nuget
/// source whose url leaves the project's `.socket/vendor/<eco>/<uuid>` tree
/// (absolute, `../`, another ecosystem's dir, another uuid's dir) is not
/// this project's committed artifact — not a reference; with a ledger for
/// the uuid the claim is dead.
#[test]
fn vendored_spoofed_locations_never_attest() {
    let nug = Vendored::nuget();
    let other = "12121212-3434-4565-8787-909090909090";
    let cases: Vec<(&Vendored, &str, &str, String)> = vec![
        (
            &nug,
            "nuget traversal",
            "nuget.config",
            vendored_nuget_config(&format!("../.socket/vendor/nuget/{NUGET_VENDOR_UUID}")),
        ),
        (
            &nug,
            "nuget absolute",
            "nuget.config",
            vendored_nuget_config(&format!("/tmp/.socket/vendor/nuget/{NUGET_VENDOR_UUID}")),
        ),
        (
            &nug,
            "nuget other uuid",
            "nuget.config",
            vendored_nuget_config(&format!(".socket/vendor/nuget/{other}")),
        ),
        (
            &nug,
            "nuget other ecosystem",
            "nuget.config",
            vendored_nuget_config(&format!(".socket/vendor/maven/{NUGET_VENDOR_UUID}")),
        ),
        (
            &nug,
            "nuget windows absolute",
            "nuget.config",
            vendored_nuget_config(&format!(
                "C:\\tmp\\.socket\\vendor\\nuget\\{NUGET_VENDOR_UUID}"
            )),
        ),
    ];
    for (v, label, file, text) in cases {
        let fx = Fx::new();
        v.write_artifact(&fx, MEMBER_PATCHED);
        fx.put(file, &text);
        let api = Api::serve(vec![(v.uuid, v.view())]);
        let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
        assert_nothing_to_attest(code, &env, label);
        assert_eq!(api.requests(), 0, "{label}: no record fetch for a non-ref");
        v.ledger(&fx);
        for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
            let (code, env) = fx.vex(extra);
            assert_omitted(code, &env, v.purl, "vendor_unwired", label);
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════
// EMBEDDED — the REAL writers lay the wiring down (`vendor --vex`,
// `scan --mode hosted --vex`, `apply --vex`); then the manifest and the
// ledgers are deleted and the standalone `vex` must re-attest from the
// project files alone.
// ══════════════════════════════════════════════════════════════════════════

const ORG: &str = "test-org";

impl Fx {
    /// Run the real binary with `args` (hermetic stores, no ambient token).
    fn run(&self, args: &[&str]) -> (Option<i32>, Value, String) {
        let mut cmd = cli(&self.store());
        cmd.args(args).current_dir(&self.cwd);
        let out = cmd.output().expect("invoke socket-patch");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let env = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "{args:?}: envelope JSON on stdout ({e}). stdout:\n{}\nstderr:\n{stderr}",
                String::from_utf8_lossy(&out.stdout)
            )
        });
        (out.status.code(), env, stderr)
    }

    /// Stage an agent-mode manifest + after-hash blob (what `get` saves)
    /// so `vendor` / `apply` run fully offline.
    fn stage_manifest(&self, purl: &str, uuid: &str, files: &[(&str, &[u8], &[u8])]) {
        let rec = record(uuid, files);
        let mut patches = serde_json::Map::new();
        patches.insert(purl.to_string(), serde_json::to_value(&rec).unwrap());
        self.put(
            ".socket/manifest.json",
            serde_json::to_string_pretty(&serde_json::json!({ "patches": patches })).unwrap(),
        );
        for (_, _, after) in files {
            self.put(
                &format!(".socket/blobs/{}", compute_git_sha256_from_bytes(after)),
                after,
            );
        }
    }

    fn embedded_doc(&self) -> Value {
        doc_at(&self.cwd.join("embedded.vex.json"))
    }
}

/// Assert an OpenVEX doc attests exactly `uuid` with `marker` for `purl`.
fn assert_doc_attests(doc: &Value, uuid: &str, purl: &str, marker: &str) {
    let stmts = doc["statements"].as_array().expect("statements");
    assert_eq!(stmts.len(), 1, "{doc}");
    assert_eq!(stmts[0]["status"], "not_affected", "{doc}");
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA, "{doc}");
    assert_eq!(
        stmts[0]["impact_statement"],
        format!("Patched via Socket patch {uuid} ({marker})"),
        "{doc}"
    );
    assert_eq!(
        stmts[0]["products"][0]["subcomponents"][0]["@id"], purl,
        "{doc}"
    );
}

/// After a real writer ran: the three standalone shapes — manifest gone
/// (ledger record, offline), manifest AND ledger gone (API record online;
/// `record_unavailable` offline), then the wiring reverted with the ledger
/// restored (`*_unwired`).
#[allow(clippy::too_many_arguments)]
fn standalone_after_writer(
    fx: &Fx,
    ledger: &str,
    uuid: &str,
    record_purl: &str,
    marker: &str,
    api_view: Value,
    revert: &dyn Fn(&Fx),
    dead_reason: &str,
) {
    fx.rm(".socket/manifest.json");
    fx.rm(".socket/blobs");
    assert!(
        fx.cwd.join(ledger).exists(),
        "the writer persisted {ledger}"
    );
    let (code, env) = fx.vex(&["--offline"]);
    assert_attested(fx, code, &env, uuid, record_purl, marker);

    let saved = std::fs::read(fx.cwd.join(ledger)).unwrap();
    fx.rm(ledger);
    let api = Api::serve(vec![(uuid, api_view)]);
    let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(fx, code, &env, uuid, record_purl, marker);
    let before = api.requests();
    let (code, env) = fx.vex(&["--offline", "--proxy-url", &api.uri()]);
    assert_omitted(
        code,
        &env,
        record_purl,
        "record_unavailable",
        "writer, no ledger",
    );
    assert_eq!(api.requests(), before);

    fx.put(ledger, &saved);
    revert(fx);
    for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
        let (code, env) = fx.vex(extra);
        assert_omitted(code, &env, record_purl, dead_reason, "writer, reverted");
    }
}

#[test]
fn nuget_vendor_command_wiring_reattests_without_manifest_or_ledger() {
    let fx = Fx::new();
    let v = Vendored::nuget();
    let cached = fx.nuget().join("newtonsoft.json/13.0.3");
    let nuspec = b"<?xml version=\"1.0\"?><package><metadata><id>Newtonsoft.Json</id>\
                   <version>13.0.3</version></metadata></package>";
    let nupkg = zip_bytes(&[
        ("Newtonsoft.Json.nuspec", nuspec),
        (v.member, MEMBER_PRISTINE),
        ("lib/net6.0/Newtonsoft.Json.dll", b"MZ dll"),
    ]);
    put(&cached, "newtonsoft.json.13.0.3.nupkg", &nupkg);
    put(
        &cached,
        "newtonsoft.json.13.0.3.nupkg.sha512",
        nupkg_content_hash(&nupkg).as_bytes(),
    );
    put(&cached, "newtonsoft.json.nuspec", nuspec);
    put(&cached, v.member, MEMBER_PRISTINE);
    put(&cached, "lib/net6.0/Newtonsoft.Json.dll", b"MZ dll");
    fx.put(
        "app.csproj",
        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net8.0\
         </TargetFramework><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>\
         </PropertyGroup><ItemGroup><PackageReference Include=\"Newtonsoft.Json\" \
         Version=\"13.0.3\" /></ItemGroup></Project>",
    );
    let upstream_lock = nuget_lock(&nupkg_content_hash(&nupkg));
    fx.put("packages.lock.json", &upstream_lock);
    fx.stage_manifest(NUGET_PURL, NUGET_VENDOR_UUID, &v.files());

    let embedded = fx.cwd.join("embedded.vex.json");
    let (code, env, stderr) = fx.run(&[
        "vendor",
        "--json",
        "--offline",
        "--cwd",
        fx.cwd.to_str().unwrap(),
        "--vex",
        embedded.to_str().unwrap(),
        "--vex-product",
        PRODUCT,
    ]);
    assert_eq!(code, Some(0), "vendor --vex: {env}\n{stderr}");
    assert_doc_attests(
        &fx.embedded_doc(),
        NUGET_VENDOR_UUID,
        NUGET_PURL,
        "vendored",
    );
    assert!(fx.cwd.join(&v.artifact_rel).is_file(), "{}", v.artifact_rel);
    let lock = std::fs::read_to_string(fx.cwd.join("packages.lock.json")).unwrap();
    let vendored = std::fs::read(fx.cwd.join(&v.artifact_rel)).unwrap();
    assert!(
        lock.contains(&nupkg_content_hash(&vendored)),
        "the lock is re-pinned to the vendored nupkg: {lock}"
    );

    standalone_after_writer(
        &fx,
        ".socket/vendor/state.json",
        NUGET_VENDOR_UUID,
        NUGET_PURL,
        "vendored",
        v.view(),
        &|fx| {
            fx.rm("nuget.config");
            fx.put("packages.lock.json", &upstream_lock);
        },
        "vendor_unwired",
    );
}

/// The authenticated API `scan --mode hosted` drives: batch discovery, the
/// by-package listing, the hosted reference grant (from the committed
/// rewriter golden's `overrides.json`), and the patch view.
fn serve_hosted_api(golden: &str, purl: &str, uuid: &str, view_body: Value) -> HostedApi {
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let overrides: Value =
        serde_json::from_slice(&std::fs::read(fixture_dir(golden).join("overrides.json")).unwrap())
            .unwrap();
    let o = &overrides[0];
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let server = rt.block_on(async {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "packages": [{ "purl": purl, "patches": [{
                    "uuid": uuid, "purl": purl, "tier": "free", "cveIds": [CVE],
                    "ghsaIds": [GHSA], "severity": "high", "title": "t"
                }] }],
                "canAccessPaidPatches": false,
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/v0/orgs/{ORG}/patches/by-package/.+$"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "patches": [{
                    "uuid": uuid, "purl": purl, "publishedAt": "2026-01-01T00:00:00Z",
                    "description": "d", "license": "MIT", "tier": "free",
                    "vulnerabilities": view_body["vulnerabilities"].clone()
                }],
                "canAccessPaidPatches": false,
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{ORG}/patches/package")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { uuid: {
                    "status": "granted",
                    "url": o["artifactUrl"],
                    "purl": purl,
                    "artifacts": [{
                        "kind": "tarball", "url": o["artifactUrl"], "integrity": o["integrity"]
                    }],
                    "registryOverride": o["registryOverride"],
                } }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(view_body.clone()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/patch/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(view_body))
            .mount(&server)
            .await;
        server
    });
    HostedApi { rt, server }
}

fn scan_hosted_vex(fx: &Fx, api: &HostedApi) -> (Option<i32>, Value, String) {
    let embedded = fx.cwd.join("embedded.vex.json");
    fx.run(&[
        "scan",
        "--mode",
        "hosted",
        "--json",
        "--yes",
        "--cwd",
        fx.cwd.to_str().unwrap(),
        "--api-url",
        &api.uri(),
        "--org",
        ORG,
        "--api-token",
        "fake",
        "--vex",
        embedded.to_str().unwrap(),
        "--vex-product",
        PRODUCT,
    ])
}

/// `scan --mode hosted --vex` for nuget: the rewriter adds the Socket
/// source + mapping and re-pins the lock's contentHash. The global packages
/// folder is SHARED by every source, so a pristine same-version copy there
/// is what an unlocked restore reuses — the standalone vex omits it
/// (`not_applied`) and attests from the pin once it is gone.
#[test]
fn nuget_scan_hosted_wiring_reattests_without_manifest_or_ledger() {
    let golden = "nuget/packages-lock/basic";
    let fx = Fx::new();
    copy_golden(&fx, &format!("{golden}/input"));
    fx.put("app.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\"/>");
    let pkg = fx.nuget().join("newtonsoft.json/13.0.3");
    put(&pkg, "newtonsoft.json.nuspec", b"<package/>");
    put(&pkg, NUGET_FILE_KEY, NUGET_PRISTINE);
    let api = serve_hosted_api(golden, NUGET_PURL, NUGET_HOSTED_UUID, nuget_hosted_view());
    let (code, env, stderr) = scan_hosted_vex(&fx, &api);
    assert_eq!(code, Some(0), "scan --mode hosted --vex: {env}\n{stderr}");
    assert_eq!(env["redirect"]["redirected"], 1, "{env}");
    // The in-run VEX attests on the fresh pin (`assume_applied`: the
    // restore that consumes it has not run yet), never on the pristine
    // shared-folder copy.
    assert_doc_attests(
        &fx.embedded_doc(),
        NUGET_HOSTED_UUID,
        NUGET_PURL,
        "redirected",
    );
    assert!(
        api.requests() >= 3,
        "batch + reference + view reached the stand-in"
    );
    let config = std::fs::read_to_string(fx.cwd.join("nuget.config")).unwrap();
    assert!(
        config.contains(&format!("socket-patch-{NUGET_HOSTED_UUID}")),
        "{config}"
    );

    // The pristine shared-folder copy is installed evidence: omitted.
    fx.rm(".socket/manifest.json");
    let (code, env) = fx.vex(&["--offline"]);
    assert_omitted(
        code,
        &env,
        NUGET_PURL,
        "not_applied",
        "pristine global copy",
    );
    // Cleared (a fresh CI restore would fetch the patched nupkg): the pin.
    std::fs::remove_dir_all(fx.nuget().join("newtonsoft.json")).unwrap();
    let inputs = copy_golden_to_vec(&format!("{golden}/input"));
    standalone_after_writer(
        &fx,
        ".socket/vendor/redirect-state.json",
        NUGET_HOSTED_UUID,
        NUGET_PURL,
        "redirected",
        nuget_hosted_view(),
        &|fx| {
            for (file, bytes) in &inputs {
                fx.put(file, bytes);
            }
        },
        "redirect_unwired",
    );
}

fn copy_golden_to_vec(rel: &str) -> Vec<(String, Vec<u8>)> {
    let fx = Fx::new();
    copy_golden(&fx, rel)
        .into_iter()
        .map(|f| {
            let bytes = std::fs::read(fx.cwd.join(&f)).unwrap();
            (f, bytes)
        })
        .collect()
}

/// DOCUMENTED LIMITATION (design scope): an AGENT-mode nuget patch
/// (`apply` rewrites the extracted package in the global packages folder)
/// has no lockfile wiring — only the manifest records it. `apply --vex`
/// attests it (plain provenance); with the manifest gone nothing names the
/// patch, so the standalone vex has nothing to attest.
#[test]
fn nuget_apply_vex_attests_but_agent_mode_needs_the_manifest() {
    let fx = Fx::new();
    fx.put(
        "app.csproj",
        "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><PackageReference \
         Include=\"Newtonsoft.Json\" Version=\"13.0.3\" /></ItemGroup></Project>",
    );
    let pkg = fx.nuget().join("newtonsoft.json/13.0.3");
    put(&pkg, "newtonsoft.json.nuspec", b"<package/>");
    put(&pkg, NUGET_FILE_KEY, NUGET_PRISTINE);
    fx.stage_manifest(NUGET_PURL, NUGET_HOSTED_UUID, &nuget_files());
    // nuget has no install hook: agent-mode statements need the ecosystem
    // declared `setup.manual` (property 7) — the hosted/vendored cells
    // above never do, their wiring IS the persistence.
    let manifest = fx.cwd.join(".socket/manifest.json");
    let mut m: Value = serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    m["setup"] = serde_json::json!({ "manual": ["nuget"] });
    fx.put(".socket/manifest.json", m.to_string());
    let embedded = fx.cwd.join("embedded.vex.json");
    let (code, env, stderr) = fx.run(&[
        "apply",
        "--json",
        "--offline",
        "--cwd",
        fx.cwd.to_str().unwrap(),
        "--vex",
        embedded.to_str().unwrap(),
        "--vex-product",
        PRODUCT,
    ]);
    assert_eq!(code, Some(0), "apply --vex: {env}\n{stderr}");
    let doc = fx.embedded_doc();
    assert_eq!(
        doc["statements"][0]["impact_statement"],
        format!("Patched via Socket patch {NUGET_HOSTED_UUID}"),
        "agent mode carries no provenance marker: {doc}"
    );
    assert_eq!(
        std::fs::read(pkg.join(NUGET_FILE_KEY)).unwrap(),
        NUGET_PATCHED
    );
    let (code, env) = fx.vex(&["--offline"]);
    assert_eq!(code, Some(0), "with the manifest: {env}");
    fx.rm(".socket/manifest.json");
    let (code, env) = fx.vex(&["--offline"]);
    assert_nothing_to_attest(code, &env, "agent mode without the manifest");
    // And no lockfile/config wiring appeared from `apply`.
    assert!(!fx.cwd.join("nuget.config").exists());
    assert!(!fx.cwd.join("packages.lock.json").exists());
}
