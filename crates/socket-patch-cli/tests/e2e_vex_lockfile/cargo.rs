//! Manifest-less `socket-patch vex` for cargo: hosted (`scan --mode
//! hosted`) and vendored (`vendor`) patches must attest from `Cargo.lock`,
//! `Cargo.toml` and the project cargo config alone, with NO
//! `.socket/manifest.json` and (unless a cell says otherwise) NO
//! `.socket/vendor/state.json` or `.socket/vendor/redirect-state.json` — and
//! must never attest falsely.
//!
//! Hermetic: every run gets a private, EMPTY `CARGO_HOME` (an ambient
//! crates.io copy must not decide a verdict), the patch API is a wiremock
//! stand-in serving `GET /patch/view/<uuid>` (the unauthenticated
//! public-proxy route), and no `cargo` toolchain is needed. Runs on every OS
//! in the default `test` job; the real-toolchain flows (every Cargo.lock
//! version, fresh-checkout installs, then the same manifest-less steps) live
//! in `e2e_redirect_cargo_build.rs`, `e2e_vendor_cargo_build.rs` and
//! `mode_migration_cargo.rs`.
//!
//! Cells, per the manifest-less VEX design:
//!
//! * **a** no manifest, no ledgers, online → one statement for the replaced
//!   crate's purl with the record's vuln id + CVE alias and the
//!   `(redirected)` / `(vendored)` marker; exit 0; `verified` envelope events.
//! * **b** `--offline` (or an API that cannot serve the record) with no local
//!   record → `record_unavailable`, exit 1, and ZERO requests reach the API
//!   under `--offline`.
//! * **c** ledger present, manifest absent → attests offline from the
//!   ledger's embedded record.
//! * **d** wiring reverted to the registry while the ledger / artifact stay
//!   → `redirect_unwired` / `vendor_unwired`, with and without `--no-verify`.
//! * **e** tampered installed tree (hosted) / tampered committed artifact
//!   member (vendored) → omitted (`hash_mismatch` / `vendor_hash_mismatch`).
//! * **f** spoofing: a uuid-shaped segment on a non-Socket host (hosted) or a
//!   non-root-anchored vendor path (vendored) is not a reference; a record
//!   whose purl or uuid differs from the wiring is `record_mismatch`.
//! * **g** (hosted) not installed → attests from the lockfile's checksum pin
//!   (design D5); installed-and-patched → attests after hashing the copy the
//!   build CONSUMES; that copy pristine → omitted; a pin-less reference
//!   needs a verifying installed copy.
//!
//! Flavors: hosted — `Cargo.lock` `[[package]] source =
//! "sparse+…/patch-registry/cargo/<token>/<uuid>/index/"` + checksum,
//! `Cargo.toml` `registry = "socket-patch-<uuid>"` (inline / table form),
//! `.cargo/config.toml` / legacy `.cargo/config` / no project config; lock
//! v1 (`[metadata]` checksums) / v2 (no `version` key) / v3 / v4;
//! `registry+` source kind; the committed rewriter golden. Vendored — the
//! root `Cargo.toml`'s `[patch.crates-io]` (what v5 `vendor` writes: inline,
//! the Socket-owned `<name>-socket-<uuid8>` key with `package =`, sub-table,
//! `./`-prefixed), and the pre-v5 wiring in `.cargo/config.toml` / legacy
//! `.cargo/config`; the lock entry sourceless (v1 / v2 / v3 / v4, and no
//! lock yet). Embedded: `scan --vex`, `apply --vex` and `vendor --vex` on a
//! manifest-less lockfile-wired project.

//! manifest-less lockfile-wired project.

use crate::vex_e2e_common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
use socket_patch_core::patch::redirect::{FileEdit, RedirectState};

/// The patch uuid every fixture wires (canonical lowercase).
const U: &str = "6b7c8d9e-0f1a-4a1b-8c2d-3e4f5a6b7c8d";
/// A second, unrelated patch uuid.
const OTHER_U: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
/// A uuid-SHAPED grant token (production tokens may be): the patch uuid is
/// the LAST canonical-uuid segment of a hosted URL, never the token.
const TOKEN: &str = "11111111-2222-4333-8444-555555555555";
const PRODUCT: &str = "pkg:github/acme/app@1.0.0";
const GHSA: &str = "GHSA-lkcg-0001-aaaa";
const CVE: &str = "CVE-2026-7001";

const CRATE: &str = "serde";
const CRATE_VERSION: &str = "1.0.190";
const CARGO_PURL: &str = "pkg:cargo/serde@1.0.190";
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

const PRISTINE_RS: &[u8] = b"// serde pristine\npub fn f() {}\n";
const PATCHED_RS: &[u8] = b"// serde patched\npub fn f() {}\n";

// ── harness ───────────────────────────────────────────────────────────

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_socket-patch")
}

/// A project under `<tmp>/app` plus a private (empty unless a test fills
/// it) cargo home.
struct Fx {
    _tmp: tempfile::TempDir,
    cwd: PathBuf,
    cargo_home: PathBuf,
}

/// One `vex --json` run: exit code, envelope, and the written document (only
/// on exit 0).
struct Run {
    code: Option<i32>,
    env: Value,
    doc: Option<Value>,
}

impl Fx {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("app");
        let cargo_home = tmp.path().join("cargo-home");
        for dir in [&cwd, &cargo_home] {
            std::fs::create_dir_all(dir).unwrap();
        }
        Fx {
            _tmp: tmp,
            cwd,
            cargo_home,
        }
    }

    /// Write `bytes` at project-relative `rel`.
    fn put(&self, rel: &str, bytes: impl AsRef<[u8]>) {
        put(&self.cwd, rel, bytes.as_ref());
    }

    fn rm(&self, rel: &str) {
        let path = self.cwd.join(rel);
        if path.is_dir() {
            std::fs::remove_dir_all(path).unwrap();
        } else {
            std::fs::remove_file(path).unwrap();
        }
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.cwd.join(rel)).unwrap()
    }

    /// Hermetic child: ambient `SOCKET_*` scrubbed, no token / config /
    /// telemetry, the fixture's private caches.
    fn command(&self) -> Command {
        let mut cmd = Command::new(binary());
        for (key, _) in std::env::vars() {
            if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
                cmd.env_remove(key);
            }
        }
        cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
            .env("SOCKET_NO_CONFIG", "1")
            .env("SOCKET_NO_API_TOKEN", "1")
            .env("CARGO_HOME", &self.cargo_home)
            .env_remove("VIRTUAL_ENV");
        cmd
    }

    /// `vex --cwd <app> --json --output <app>/out.vex.json --product …`.
    fn vex(&self, extra: &[&str]) -> Run {
        let out_path = self.cwd.join("out.vex.json");
        let _ = std::fs::remove_file(&out_path);
        let mut args: Vec<String> = [
            "vex",
            "--cwd",
            self.cwd.to_str().unwrap(),
            "--json",
            "--output",
            out_path.to_str().unwrap(),
            "--product",
            PRODUCT,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        args.extend(extra.iter().map(|s| s.to_string()));
        let out = self.command().args(&args).output().expect("invoke vex");
        let env: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "envelope JSON on stdout ({e}). stdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        let doc = (out.status.code() == Some(0)).then(|| {
            serde_json::from_slice(&std::fs::read(&out_path).expect("exit 0 writes the document"))
                .unwrap()
        });
        Run {
            code: out.status.code(),
            env,
            doc,
        }
    }

    /// Install the hosted cargo copy the build consumes:
    /// `$CARGO_HOME/registry/src/<host>-<hash>/serde-1.0.190/`.
    fn install_crate(&self, registry_dir: &str, lib: &[u8]) {
        let dir = format!("registry/src/{registry_dir}/{CRATE}-{CRATE_VERSION}");
        put(
            &self.cargo_home,
            &format!("{dir}/Cargo.toml"),
            format!("[package]\nname = \"{CRATE}\"\nversion = \"{CRATE_VERSION}\"\n").as_bytes(),
        );
        put(&self.cargo_home, &format!("{dir}/src/lib.rs"), lib);
    }
}

fn put(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// The wiremock patch API. The runtime must outlive every CLI invocation.
struct Api {
    rt: tokio::runtime::Runtime,
    server: wiremock::MockServer,
}

impl Api {
    /// Serve each `(uuid, view)` on the public-proxy route (the one an
    /// unauthenticated `vex` fetches from). Any other request 404s.
    fn start(views: Vec<(&str, Value)>) -> Self {
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
        Api { rt, server }
    }

    fn uri(&self) -> String {
        self.server.uri()
    }

    /// Requests the API received so far.
    fn hits(&self) -> usize {
        self.rt
            .block_on(self.server.received_requests())
            .map_or(0, |r| r.len())
    }
}

/// The API's view of patch `uuid` for `purl`: one file `(key, before, after)`
/// and one GHSA with a CVE alias.
fn view(uuid: &str, purl: &str, file: &str, before: &[u8], after: &[u8]) -> Value {
    serde_json::json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "Fri, 27 Mar 2026 00:00:00 GMT",
        "files": { file: {
            "beforeHash": compute_git_sha256_from_bytes(before),
            "afterHash": compute_git_sha256_from_bytes(after),
        } },
        "vulnerabilities": {
            GHSA: { "cves": [CVE], "summary": "s", "severity": "high", "description": "d" }
        },
        "description": "lockfile-discovered patch",
        "license": "MIT",
        "tier": "free",
    })
}

fn cargo_view(uuid: &str) -> Value {
    view(uuid, CARGO_PURL, "src/lib.rs", PRISTINE_RS, PATCHED_RS)
}

/// The same patch as a ledger-embedded [`PatchRecord`].
fn record(uuid: &str, file: &str, before: &[u8], after: &[u8]) -> PatchRecord {
    let mut files = HashMap::new();
    files.insert(
        file.to_string(),
        PatchFileInfo {
            before_hash: compute_git_sha256_from_bytes(before),
            after_hash: compute_git_sha256_from_bytes(after),
        },
    );
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
        exported_at: "2026-03-27T00:00:00Z".to_string(),
        files,
        vulnerabilities,
        description: "ledger patch".to_string(),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

fn cargo_record(uuid: &str) -> PatchRecord {
    record(uuid, "src/lib.rs", PRISTINE_RS, PATCHED_RS)
}

/// `.socket/vendor/redirect-state.json` recording `purl → record` and the
/// real-kind edits `scan --mode hosted` logs.
fn write_redirect_ledger(fx: &Fx, purl: &str, rec: PatchRecord, edits: &[(&str, &str)]) {
    let mut state = RedirectState::new();
    state.records.insert(purl.to_string(), rec);
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
    fx.put(
        ".socket/vendor/redirect-state.json",
        serde_json::to_string_pretty(&state).unwrap(),
    );
}

const CARGO_HOSTED_EDITS: &[(&str, &str)] = &[
    ("Cargo.toml", "redirect_cargo_toml_dep"),
    (".cargo/config.toml", "redirect_cargo_registry"),
    ("Cargo.lock", "redirect_cargo_lock_entry"),
];

/// `.socket/vendor/state.json` with ONE entry in the shape current writers
/// persist (non-detached, record embedded). JSON rather than the struct so
/// additive ledger fields never break this suite.
fn write_vendor_ledger(
    fx: &Fx,
    eco: &str,
    purl: &str,
    uuid: &str,
    artifact: &str,
    rec: Option<PatchRecord>,
    wiring: &[(&str, &str)],
) {
    let mut entry = serde_json::json!({
        "ecosystem": eco,
        "basePurl": purl,
        "uuid": uuid,
        "artifact": { "path": artifact },
        "wiring": wiring
            .iter()
            .map(|(file, kind)| serde_json::json!({ "file": file, "kind": kind, "action": "rewritten" }))
            .collect::<Vec<_>>(),
    });
    if let Some(rec) = rec {
        entry["record"] = serde_json::to_value(rec).unwrap();
    }
    let state = serde_json::json!({ "version": 1, "entries": { purl: entry } });
    fx.put(
        ".socket/vendor/state.json",
        serde_json::to_string_pretty(&state).unwrap(),
    );
}

/// A named fixture mutation (a revert shape).
type Shape = dyn Fn(&Fx);

// ── assertions ───────────────────────────────────────────────────────

/// Exactly one statement: `purl` fixed by `uuid`'s GHSA (CVE alias), with the
/// provenance `marker`; exit 0; a `verified` event carrying the vuln; the
/// manifest is never written.
fn assert_attested(fx: &Fx, run: &Run, purl: &str, uuid: &str, marker: &str, what: &str) {
    assert_eq!(run.code, Some(0), "{what}: {}", run.env);
    assert_eq!(run.env["status"], "success", "{what}: {}", run.env);
    let doc = run.doc.as_ref().unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "{what}: {doc}");
    let st = &stmts[0];
    assert_eq!(st["status"], "not_affected", "{what}: {st}");
    assert_eq!(st["vulnerability"]["name"], GHSA, "{what}: {st}");
    assert_eq!(st["vulnerability"]["aliases"][0], CVE, "{what}: {st}");
    assert_eq!(st["products"][0]["@id"], PRODUCT, "{what}: {st}");
    assert_eq!(
        st["products"][0]["subcomponents"][0]["@id"], purl,
        "{what}: {st}"
    );
    assert_eq!(
        st["impact_statement"],
        format!("Patched via Socket patch {uuid} ({marker})"),
        "{what}: {st}"
    );
    let verified: Vec<&Value> = run.env["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "verified")
        .collect();
    assert_eq!(verified.len(), 1, "{what}: {}", run.env);
    assert_eq!(verified[0]["purl"], purl, "{what}: {}", run.env);
    assert_eq!(verified[0]["details"]["vulnerability"], GHSA, "{what}");
    assert_eq!(verified[0]["details"]["aliases"][0], CVE, "{what}");
    assert!(
        !fx.cwd.join(".socket/manifest.json").exists(),
        "{what}: vex never writes the manifest"
    );
}

/// Nothing attested: exit 1 `no_applicable_patches`, no document, no
/// `verified` event, and `purl`'s single skip carries `reason`.
fn assert_omitted(run: &Run, purl: &str, reason: &str, what: &str) {
    vex_e2e_common::assert_omitted_parts(run.code, &run.env, run.doc.as_ref(), purl, reason, what);
}

/// Nothing referenced a patch at all: exit 2 `manifest_not_found`.
fn assert_nothing_discovered(run: &Run, what: &str) {
    assert_eq!(run.code, Some(2), "{what}: {}", run.env);
    assert_eq!(
        run.env["error"]["code"], "manifest_not_found",
        "{what}: {}",
        run.env
    );
    assert!(run.doc.is_none(), "{what}");
}

/// Every statement's subcomponent purls, sorted.
fn subcomponents(doc: &Value) -> Vec<String> {
    let mut purls: Vec<String> = doc["statements"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|s| {
            s["products"][0]["subcomponents"]
                .as_array()
                .unwrap()
                .clone()
        })
        .filter_map(|s| s["@id"].as_str().map(str::to_string))
        .collect();
    purls.sort();
    purls
}

fn warning_codes(run: &Run) -> Vec<String> {
    run.env["warnings"]
        .as_array()
        .map(|w| {
            w.iter()
                .filter_map(|w| w["code"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// ── cargo fixtures ────────────────────────────────────────────────────

/// Production hosted cargo index for `uuid` on `origin`.
fn cargo_index(origin: &str, uuid: &str) -> String {
    format!("{origin}/patch-registry/cargo/{TOKEN}/{uuid}/index/")
}

#[derive(Clone, Copy, Debug)]
enum CargoConfig {
    /// `.cargo/config.toml` (what the rewriter writes).
    Toml,
    /// Legacy extensionless `.cargo/config` (cargo reads it INSTEAD).
    Legacy,
    /// No project config: the definition lives in `$CARGO_HOME`.
    None,
}

#[derive(Clone, Copy, Debug)]
struct CargoHosted {
    lock_version: u8,
    /// `sparse+` (what the rewriter writes) or `registry+` (a git index).
    kind: &'static str,
    /// `[dependencies.serde]` table form instead of the inline table.
    table_form: bool,
    config: CargoConfig,
    /// Write the lock's checksum pin.
    pinned: bool,
}

const CARGO_HOSTED: CargoHosted = CargoHosted {
    lock_version: 3,
    kind: "sparse",
    table_form: false,
    config: CargoConfig::Toml,
    pinned: true,
};

/// A two-package `Cargo.lock` (the `app` root depending on `serde`) in lock
/// format `version`, with `serde_block_tail` (`source = "…"` /
/// `checksum = "…"` lines, or empty for a detached entry) as serde's pins:
///
/// * v4 / v3 — the `version = N` header, inline `checksum`;
/// * v2 — the same body with NO `version` key (cargo 1.41–1.52's default);
/// * v1 — no `version` key, dependency references spelled
///   `"name version (source)"`, and the checksum moved to the trailing
///   `[metadata]` table (cargo < 1.41).
fn cargo_lock(version: u8, serde_block_tail: &str) -> String {
    cargo_lock_at(version, CRATE_VERSION, serde_block_tail)
}

/// [`cargo_lock`] with serde locked at `crate_version` (a vendored copy's
/// tagged version).
fn cargo_lock_at(version: u8, crate_version: &str, serde_block_tail: &str) -> String {
    const HEADER: &str =
        "# This file is automatically @generated by Cargo.\n# It is not intended for manual \
         editing.\n";
    let value = |key: &str| {
        serde_block_tail.lines().find_map(|l| {
            l.strip_prefix(&format!("{key} = \""))
                .and_then(|v| v.strip_suffix('"'))
                .map(str::to_string)
        })
    };
    if version == 1 {
        let source = value("source");
        let dep_ref = match &source {
            Some(src) => format!("{CRATE} {crate_version} ({src})"),
            None => format!("{CRATE} {crate_version}"),
        };
        let source_line = source
            .as_ref()
            .map(|src| format!("source = \"{src}\"\n"))
            .unwrap_or_default();
        let metadata = match (&source, value("checksum")) {
            (Some(src), Some(sum)) => {
                format!("\n[metadata]\n\"checksum {CRATE} {crate_version} ({src})\" = \"{sum}\"\n")
            }
            _ => String::new(),
        };
        return format!(
            "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"{dep_ref}\",\n]\n\n\
             [[package]]\nname = \"{CRATE}\"\nversion = \"{crate_version}\"\n{source_line}{metadata}"
        );
    }
    let version_line = if version >= 3 {
        format!("version = {version}\n\n")
    } else {
        String::new()
    };
    format!(
        "{HEADER}{version_line}[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
         dependencies = [\n \"serde\",\n]\n\n[[package]]\nname = \"{CRATE}\"\nversion = \
         \"{crate_version}\"\n{serde_block_tail}"
    )
}

fn cargo_toml(dep: &str) -> String {
    format!("[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n{dep}")
}

/// The three-file hosted rewrite (`patch::redirect::rewrite_cargo`) for
/// `uuid` on `origin`.
fn write_cargo_hosted(fx: &Fx, uuid: &str, origin: &str, h: CargoHosted) {
    let index = cargo_index(origin, uuid);
    let registry = format!("socket-patch-{uuid}");
    let dep = if h.table_form {
        format!(
            "[dependencies.{CRATE}]\nversion = \"{CRATE_VERSION}\"\nregistry = \"{registry}\"\n"
        )
    } else {
        format!(
            "[dependencies]\n{CRATE} = {{ version = \"{CRATE_VERSION}\", registry = \
             \"{registry}\" }}\n"
        )
    };
    fx.put("Cargo.toml", cargo_toml(&dep));
    let checksum = if h.pinned {
        format!("checksum = \"{}\"\n", "e".repeat(64))
    } else {
        String::new()
    };
    fx.put(
        "Cargo.lock",
        cargo_lock(
            h.lock_version,
            &format!("source = \"{}+{index}\"\n{checksum}", h.kind),
        ),
    );
    let definition = format!("[registries.{registry}]\nindex = \"{}+{index}\"\n", h.kind);
    match h.config {
        CargoConfig::Toml => fx.put(".cargo/config.toml", definition),
        CargoConfig::Legacy => fx.put(".cargo/config", definition),
        CargoConfig::None => {}
    }
}

/// The crates.io state the hosted rewrite replaced (a full revert).
fn write_cargo_registry(fx: &Fx) {
    fx.put(
        "Cargo.toml",
        cargo_toml(&format!("[dependencies]\n{CRATE} = \"{CRATE_VERSION}\"\n")),
    );
    fx.put(
        "Cargo.lock",
        cargo_lock(
            3,
            &format!(
                "source = \"{CRATES_IO}\"\nchecksum = \"{}\"\n",
                "c".repeat(64)
            ),
        ),
    );
}

/// Cargo's registry src dir name for the Socket patch host.
const SOCKET_CARGO_SRC: &str = "patch.socket.dev-0123456789abcdef";
const CRATES_IO_SRC: &str = "index.crates.io-1949cf8c6b5b557f";

fn cargo_artifact(uuid: &str) -> String {
    format!(".socket/vendor/cargo/{uuid}/{CRATE}-{CRATE_VERSION}")
}

#[derive(Clone, Copy, Debug)]
enum CargoVendored {
    /// What v5 `vendor` writes: the root `Cargo.toml`'s
    /// `[patch.crates-io] serde = { path = "…" }`.
    Inline,
    /// The Socket-owned fallback key (a second vendored version of the
    /// crate): `serde-socket-<uuid8> = { package = "serde", path = "…" }`.
    SocketKey,
    /// `[patch.crates-io.serde] path = "…"` in the manifest.
    SubTable,
    /// `./`-prefixed path spelling in the manifest.
    DotSlash,
    /// Pre-v5 wiring: `.cargo/config.toml` `[patch.crates-io]`.
    LegacyConfigToml,
    /// Pre-v5 wiring in the legacy extensionless `.cargo/config`.
    LegacyConfig,
}

/// The copy's (and the detached lock entry's) tagged version for `uuid`.
fn tagged_version(uuid: &str) -> String {
    socket_patch_core::vendor::cargo_tag::tag_version(CRATE_VERSION, uuid)
}

/// The `vendor` cargo backend's committed state: the patched copy dir, the
/// `[patch.crates-io]` path entry, and the lock entry detached from crates.io
/// (source + checksum dropped). The v5 manifest flavors carry the tagged
/// version `<version>+socket.<uuid>` in the copy's `Cargo.toml` and the lock
/// entry; the pre-v5 config flavors are untagged, as those releases wrote.
fn write_cargo_vendored(fx: &Fx, uuid: &str, flavor: CargoVendored, lib: &[u8]) {
    let rel = cargo_artifact(uuid);
    let legacy = matches!(
        flavor,
        CargoVendored::LegacyConfigToml | CargoVendored::LegacyConfig
    );
    let copy_version = if legacy {
        CRATE_VERSION.to_string()
    } else {
        tagged_version(uuid)
    };
    fx.put(
        &format!("{rel}/Cargo.toml"),
        format!("[package]\nname = \"{CRATE}\"\nversion = \"{copy_version}\"\n"),
    );
    fx.put(&format!("{rel}/src/lib.rs"), lib);
    let dep = format!("[dependencies]\n{CRATE} = \"{CRATE_VERSION}\"\n");
    let inline = format!("[patch.crates-io]\n{CRATE} = {{ path = \"{rel}\" }}\n");
    let manifest = |patch: String| fx.put("Cargo.toml", cargo_toml(&format!("{dep}\n{patch}")));
    match flavor {
        CargoVendored::Inline => manifest(inline),
        CargoVendored::SocketKey => manifest(format!(
            "[patch.crates-io]\n{CRATE}-socket-{} = {{ package = \"{CRATE}\", path = \"{rel}\" }}\n",
            &uuid[..8]
        )),
        CargoVendored::SubTable => {
            manifest(format!("[patch.crates-io.{CRATE}]\npath = \"{rel}\"\n"))
        }
        CargoVendored::DotSlash => manifest(format!(
            "[patch.crates-io]\n{CRATE} = {{ path = \"./{rel}\" }}\n"
        )),
        CargoVendored::LegacyConfigToml => {
            fx.put("Cargo.toml", cargo_toml(&dep));
            fx.put(".cargo/config.toml", inline);
        }
        CargoVendored::LegacyConfig => {
            fx.put("Cargo.toml", cargo_toml(&dep));
            fx.put(".cargo/config", inline);
        }
    }
    fx.put("Cargo.lock", cargo_lock_at(4, &copy_version, ""));
}

/// The manifest `write_cargo_vendored` writes, minus the `[patch]` wiring.
fn cargo_toml_unwired() -> String {
    cargo_toml(&format!("[dependencies]\n{CRATE} = \"{CRATE_VERSION}\"\n"))
}

const CARGO_VENDORED_FLAVORS: [CargoVendored; 6] = [
    CargoVendored::Inline,
    CargoVendored::SocketKey,
    CargoVendored::SubTable,
    CargoVendored::DotSlash,
    CargoVendored::LegacyConfigToml,
    CargoVendored::LegacyConfig,
];

fn redirect_fixture(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../socket-patch-core/tests/fixtures/redirect")
        .join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// ══════════════════════════════════════════════════════════════════════
// cargo × hosted
// ══════════════════════════════════════════════════════════════════════

/// a + g(not installed): every hosted flavor attests `(redirected)` from the
/// lockfile alone (record from the API, pinned wiring as the evidence).
#[test]
fn cargo_hosted_a_attests_every_flavor_without_manifest_or_ledgers() {
    let flavors = [
        CARGO_HOSTED,
        CargoHosted {
            lock_version: 4,
            ..CARGO_HOSTED
        },
        CargoHosted {
            lock_version: 2,
            ..CARGO_HOSTED
        },
        CargoHosted {
            lock_version: 1,
            ..CARGO_HOSTED
        },
        CargoHosted {
            table_form: true,
            config: CargoConfig::Legacy,
            ..CARGO_HOSTED
        },
        CargoHosted {
            config: CargoConfig::None,
            ..CARGO_HOSTED
        },
        CargoHosted {
            kind: "registry",
            ..CARGO_HOSTED
        },
    ];
    let api = Api::start(vec![(U, cargo_view(U))]);
    for flavor in flavors {
        let fx = Fx::new();
        write_cargo_hosted(&fx, U, "https://patch.socket.dev", flavor);
        assert!(!fx.cwd.join(".socket").exists());
        let run = fx.vex(&["--proxy-url", &api.uri()]);
        assert_attested(
            &fx,
            &run,
            CARGO_PURL,
            U,
            "redirected",
            &format!("{flavor:?}"),
        );
        assert!(
            warning_codes(&run).is_empty(),
            "{flavor:?}: a clean rewrite raises no discovery warning: {}",
            run.env
        );
    }
}

/// a: the rewriter's own committed golden (`cargo/cargo/basic/expected`,
/// uuid `5555…`, uuid-shaped token `1111…` before it) attests that uuid.
#[test]
fn cargo_hosted_a_rewriter_golden_attests_its_uuid() {
    const GOLDEN_U: &str = "55555555-5555-5555-5555-555555555555";
    let fx = Fx::new();
    for file in ["Cargo.toml", "Cargo.lock", ".cargo/config.toml"] {
        fx.put(
            file,
            redirect_fixture(&format!("cargo/cargo/basic/expected/{file}")),
        );
    }
    let api = Api::start(vec![(GOLDEN_U, cargo_view(GOLDEN_U))]);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(&fx, &run, CARGO_PURL, GOLDEN_U, "redirected", "golden");
}

/// b: no local record — `--offline` never touches the API; an API that
/// 404s the view, or is unreachable, is `record_unavailable` too.
#[test]
fn cargo_hosted_b_without_a_record_is_record_unavailable() {
    let fx = Fx::new();
    write_cargo_hosted(&fx, U, "https://patch.socket.dev", CARGO_HOSTED);
    let api = Api::start(vec![(U, cargo_view(U))]);
    let run = fx.vex(&["--offline", "--proxy-url", &api.uri()]);
    assert_omitted(&run, CARGO_PURL, "record_unavailable", "offline");
    assert_eq!(api.hits(), 0, "--offline must make no network call");

    let empty = Api::start(vec![]);
    let run = fx.vex(&["--proxy-url", &empty.uri()]);
    assert_omitted(&run, CARGO_PURL, "record_unavailable", "API 404");
    assert!(empty.hits() >= 1, "the online run did ask the API");

    let run = fx.vex(&["--proxy-url", "http://127.0.0.1:9"]);
    assert_omitted(&run, CARGO_PURL, "record_unavailable", "API unreachable");
}

/// c: the redirect ledger's embedded record attests offline with the
/// manifest absent — with and without `--no-verify`, installed or not.
#[test]
fn cargo_hosted_c_ledger_record_attests_offline() {
    let fx = Fx::new();
    write_cargo_hosted(&fx, U, "https://patch.socket.dev", CARGO_HOSTED);
    write_redirect_ledger(&fx, CARGO_PURL, cargo_record(U), CARGO_HOSTED_EDITS);
    for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
        let run = fx.vex(extra);
        assert_attested(
            &fx,
            &run,
            CARGO_PURL,
            U,
            "redirected",
            &format!("{extra:?}"),
        );
    }
    fx.install_crate(SOCKET_CARGO_SRC, PATCHED_RS);
    let run = fx.vex(&["--offline"]);
    assert_attested(&fx, &run, CARGO_PURL, U, "redirected", "installed");
}

/// d: every revert shape with the ledger left behind is `redirect_unwired`,
/// `--no-verify` or not — the full revert, a reverted `Cargo.toml` pin over a
/// stale lock, a lock re-resolved from crates.io under a surviving pin, and a
/// leftover registry definition alone.
#[test]
fn cargo_hosted_d_reverted_wiring_never_keeps_the_ledger_alive() {
    let stale_lock = |fx: &Fx| {
        write_cargo_hosted(fx, U, "https://patch.socket.dev", CARGO_HOSTED);
        fx.put(
            "Cargo.toml",
            cargo_toml(&format!("[dependencies]\n{CRATE} = \"{CRATE_VERSION}\"\n")),
        );
    };
    let relocked = |fx: &Fx| {
        write_cargo_hosted(fx, U, "https://patch.socket.dev", CARGO_HOSTED);
        fx.put(
            "Cargo.lock",
            cargo_lock(
                3,
                &format!(
                    "source = \"{CRATES_IO}\"\nchecksum = \"{}\"\n",
                    "c".repeat(64)
                ),
            ),
        );
    };
    let full_revert_with_definition = |fx: &Fx| {
        write_cargo_hosted(fx, U, "https://patch.socket.dev", CARGO_HOSTED);
        write_cargo_registry(fx);
    };
    let full_revert = |fx: &Fx| {
        write_cargo_registry(fx);
    };
    let shapes: [(&str, &Shape); 4] = [
        ("Cargo.toml pin reverted, lock stale", &stale_lock),
        ("lock re-resolved from crates.io", &relocked),
        (
            "only the registry definition left",
            &full_revert_with_definition,
        ),
        ("full revert", &full_revert),
    ];
    for (name, shape) in shapes {
        let fx = Fx::new();
        shape(&fx);
        write_redirect_ledger(&fx, CARGO_PURL, cargo_record(U), CARGO_HOSTED_EDITS);
        // The consumed copy is even installed and patched: wiring decides.
        fx.install_crate(SOCKET_CARGO_SRC, PATCHED_RS);
        for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
            let run = fx.vex(extra);
            assert_omitted(
                &run,
                CARGO_PURL,
                "redirect_unwired",
                &format!("{name} {extra:?}"),
            );
        }
    }
}

/// e: the Socket registry's extracted copy tampered → `hash_mismatch`, even
/// though the pinned wiring alone would attest a not-installed checkout.
#[test]
fn cargo_hosted_e_tampered_installed_copy_is_omitted() {
    let fx = Fx::new();
    write_cargo_hosted(&fx, U, "https://patch.socket.dev", CARGO_HOSTED);
    fx.install_crate(SOCKET_CARGO_SRC, b"// tampered\n");
    let api = Api::start(vec![(U, cargo_view(U))]);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_omitted(&run, CARGO_PURL, "hash_mismatch", "tampered");
    // The ledger's record is judged by the same copy.
    write_redirect_ledger(&fx, CARGO_PURL, cargo_record(U), CARGO_HOSTED_EDITS);
    let run = fx.vex(&["--offline"]);
    assert_omitted(&run, CARGO_PURL, "hash_mismatch", "tampered, ledger");
}

/// f: a uuid-shaped segment on a non-Socket host is the user's own registry
/// (no reference — and a leftover ledger record for that uuid is unwired);
/// `--patch-server-url` admits exactly the configured origin; a record
/// naming another package or another patch is `record_mismatch`.
#[test]
fn cargo_hosted_f_spoofed_references_never_attest() {
    let api = Api::start(vec![(U, cargo_view(U))]);

    // Foreign host, lock + pin + definition all in place.
    let fx = Fx::new();
    write_cargo_hosted(&fx, U, "https://evil.example", CARGO_HOSTED);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_nothing_discovered(&run, "foreign host");
    assert_eq!(api.hits(), 0, "a foreign-host uuid is never even fetched");
    // DELIBERATE (the staging fallback): a uuid on a host outside the
    // allowlist is not a lockfile reference, but it is not "recognized"
    // either, so a redirect-ledger record for it falls back to the ledger's
    // own recorded wiring files — which still name it — so that a staging
    // `scan --mode hosted` run without `--patch-server-url` keeps
    // attesting. Hash verification still judges the copy the build
    // consumes (the foreign registry's): nothing is installed here, so the
    // default run omits it; only `--no-verify`, which trusts the ledger's
    // record by definition, attests.
    write_redirect_ledger(&fx, CARGO_PURL, cargo_record(U), CARGO_HOSTED_EDITS);
    let run = fx.vex(&["--offline"]);
    assert_omitted(
        &run,
        CARGO_PURL,
        "package_not_found",
        "foreign host + ledger",
    );
    fx.install_crate(SOCKET_CARGO_SRC, PATCHED_RS);
    let run = fx.vex(&["--offline"]);
    assert_omitted(
        &run,
        CARGO_PURL,
        "package_not_found",
        "foreign host + ledger: Socket's copy is not what this lock builds",
    );
    fx.install_crate("evil.example-0123456789abcdef", PRISTINE_RS);
    let run = fx.vex(&["--offline"]);
    assert_eq!(
        run.code,
        Some(1),
        "foreign registry's pristine copy: {}",
        run.env
    );
    let run = fx.vex(&["--offline", "--no-verify"]);
    assert_attested(
        &fx,
        &run,
        CARGO_PURL,
        U,
        "redirected",
        "staging fallback, --no-verify",
    );

    // The same foreign origin configured as the operator's patch server.
    let fx = Fx::new();
    write_cargo_hosted(&fx, U, &api.uri(), CARGO_HOSTED);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_nothing_discovered(&run, "unconfigured test origin");
    let run = fx.vex(&["--proxy-url", &api.uri(), "--patch-server-url", &api.uri()]);
    assert_attested(&fx, &run, CARGO_PURL, U, "redirected", "--patch-server-url");

    // Records that disagree with the wiring.
    let other_pkg = view(
        U,
        "pkg:cargo/libc@0.2.150",
        "src/lib.rs",
        PRISTINE_RS,
        PATCHED_RS,
    );
    let other_uuid = cargo_view(OTHER_U);
    for (name, body) in [("other package", other_pkg), ("other uuid", other_uuid)] {
        let fx = Fx::new();
        write_cargo_hosted(&fx, U, "https://patch.socket.dev", CARGO_HOSTED);
        let api = Api::start(vec![(U, body)]);
        let run = fx.vex(&["--proxy-url", &api.uri()]);
        assert_omitted(&run, CARGO_PURL, "record_mismatch", name);
    }
}

/// f: a ledger record for a DIFFERENT patch of the same crate never attests
/// the wired one — the wired uuid wins (the ledger record is superseded),
/// and with no record for the wired uuid it is `record_unavailable`.
#[test]
fn cargo_hosted_f_ledger_record_for_another_uuid_is_superseded() {
    let fx = Fx::new();
    write_cargo_hosted(&fx, U, "https://patch.socket.dev", CARGO_HOSTED);
    write_redirect_ledger(&fx, CARGO_PURL, cargo_record(OTHER_U), CARGO_HOSTED_EDITS);
    for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
        let run = fx.vex(extra);
        assert_eq!(run.code, Some(1), "{extra:?}: {}", run.env);
        assert!(
            !run.env
                .to_string()
                .contains(&format!("Patched via Socket patch {OTHER_U}")),
            "{extra:?}: {}",
            run.env
        );
        assert!(run.doc.is_none());
    }
    // Online, the wired uuid's own record attests.
    let api = Api::start(vec![(U, cargo_view(U))]);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(&fx, &run, CARGO_PURL, U, "redirected", "wired uuid online");
}

/// g: the installed-copy basis. Only crates.io's pristine copy extracted →
/// not installed → the pin attests; the Socket registry's copy patched →
/// verified; that copy pristine → omitted; a pin-less lock needs a
/// verifying copy.
#[test]
fn cargo_hosted_g_installed_copy_basis() {
    let api = Api::start(vec![(U, cargo_view(U))]);
    let uri = api.uri();
    let args = ["--proxy-url", uri.as_str()];

    let fx = Fx::new();
    write_cargo_hosted(&fx, U, "https://patch.socket.dev", CARGO_HOSTED);
    fx.install_crate(CRATES_IO_SRC, PRISTINE_RS);
    let run = fx.vex(&args);
    assert_attested(
        &fx,
        &run,
        CARGO_PURL,
        U,
        "redirected",
        "crates.io sibling only",
    );

    fx.install_crate(SOCKET_CARGO_SRC, PATCHED_RS);
    let run = fx.vex(&args);
    assert_attested(
        &fx,
        &run,
        CARGO_PURL,
        U,
        "redirected",
        "consumed copy patched",
    );

    fx.install_crate(SOCKET_CARGO_SRC, PRISTINE_RS);
    let run = fx.vex(&args);
    assert_eq!(run.code, Some(1), "consumed copy pristine: {}", run.env);
    assert!(run.doc.is_none());
    let reason = run.env["events"][0]["errorCode"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        reason == "not_applied" || reason == "hash_mismatch",
        "consumed copy pristine: {}",
        run.env
    );

    // No checksum pin: the lockfile alone is not Socket-written evidence.
    let fx = Fx::new();
    write_cargo_hosted(
        &fx,
        U,
        "https://patch.socket.dev",
        CargoHosted {
            pinned: false,
            ..CARGO_HOSTED
        },
    );
    let run = fx.vex(&args);
    assert_omitted(
        &run,
        CARGO_PURL,
        "package_not_found",
        "pin-less, not installed",
    );
    fx.install_crate(SOCKET_CARGO_SRC, PATCHED_RS);
    let run = fx.vex(&args);
    assert_attested(
        &fx,
        &run,
        CARGO_PURL,
        U,
        "redirected",
        "pin-less, verified copy",
    );
}

/// Lock v1 (cargo < 1.41): the pin lives in `[metadata]` under
/// `"checksum <name> <version> (<source>)"` (where the hosted rewriter
/// writes it for a v1 lock) and is the lockfile basis like v2+'s inline
/// checksum — a not-installed v1 checkout attests; an installed copy is
/// still hash-verified (patched → attests, pristine → omitted).
#[test]
fn cargo_hosted_lock_v1_metadata_checksum_is_the_pin() {
    let fx = Fx::new();
    write_cargo_hosted(
        &fx,
        U,
        "https://patch.socket.dev",
        CargoHosted {
            lock_version: 1,
            ..CARGO_HOSTED
        },
    );
    let lock = fx.read("Cargo.lock");
    assert!(
        lock.contains("\n[metadata]\n") && !lock.contains("\nchecksum = "),
        "{lock}"
    );
    let api = Api::start(vec![(U, cargo_view(U))]);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(
        &fx,
        &run,
        CARGO_PURL,
        U,
        "redirected",
        "v1 lock, not installed",
    );
    assert!(warning_codes(&run).is_empty(), "{}", run.env);
    fx.install_crate(SOCKET_CARGO_SRC, PATCHED_RS);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(
        &fx,
        &run,
        CARGO_PURL,
        U,
        "redirected",
        "v1 lock, verified copy",
    );
    fx.install_crate(SOCKET_CARGO_SRC, PRISTINE_RS);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_eq!(run.code, Some(1), "v1 lock, pristine copy: {}", run.env);
    assert!(run.doc.is_none());
}

// ══════════════════════════════════════════════════════════════════════
// cargo × vendored
// ══════════════════════════════════════════════════════════════════════

/// a: every `[patch]` spelling attests `(vendored)` from the committed copy.
#[test]
fn cargo_vendored_a_attests_every_flavor_without_manifest_or_ledgers() {
    let api = Api::start(vec![(U, cargo_view(U))]);
    for flavor in CARGO_VENDORED_FLAVORS {
        let fx = Fx::new();
        write_cargo_vendored(&fx, U, flavor, PATCHED_RS);
        assert!(!fx.cwd.join(".socket/manifest.json").exists());
        assert!(!fx.cwd.join(".socket/vendor/state.json").exists());
        let run = fx.vex(&["--proxy-url", &api.uri()]);
        assert_attested(&fx, &run, CARGO_PURL, U, "vendored", &format!("{flavor:?}"));
        assert!(warning_codes(&run).is_empty(), "{flavor:?}: {}", run.env);
    }
}

/// a: the detached (sourceless) lock entry in every Cargo.lock format —
/// v1's `"name version"` references and `[metadata]` table, v2's missing
/// `version` key, v3 — is the same live `[patch]`, whether it carries the
/// copy's tagged version (v5) or the untagged one (vendored before tagged
/// versions); a v1–v4 lock that re-resolved the crate from crates.io is not.
#[test]
fn cargo_vendored_a_attests_in_every_lock_version() {
    let api = Api::start(vec![(U, cargo_view(U))]);
    for version in 1..=4u8 {
        let fx = Fx::new();
        write_cargo_vendored(&fx, U, CargoVendored::Inline, PATCHED_RS);
        for locked in [tagged_version(U), CRATE_VERSION.to_string()] {
            fx.put("Cargo.lock", cargo_lock_at(version, &locked, ""));
            let run = fx.vex(&["--proxy-url", &api.uri()]);
            assert_attested(
                &fx,
                &run,
                CARGO_PURL,
                U,
                "vendored",
                &format!("lock v{version} at {locked}"),
            );
            assert!(warning_codes(&run).is_empty(), "v{version}: {}", run.env);
        }

        fx.put(
            "Cargo.lock",
            cargo_lock(
                version,
                &format!(
                    "source = \"{CRATES_IO}\"\nchecksum = \"{}\"\n",
                    "c".repeat(64)
                ),
            ),
        );
        let run = fx.vex(&["--proxy-url", &api.uri()]);
        assert_nothing_discovered(&run, &format!("lock v{version} re-resolved"));
    }
}

/// f: a detached lock entry tagged for ANOTHER patch uuid names a copy
/// other than the one the `[patch]` points at (a config override elsewhere,
/// or a stale wiring): never attested — in any lock format, with or
/// without the ledger.
#[test]
fn cargo_vendored_f_lock_tag_for_another_uuid_never_attests() {
    let api = Api::start(vec![(U, cargo_view(U)), (OTHER_U, cargo_view(OTHER_U))]);
    for version in 1..=4u8 {
        let fx = Fx::new();
        write_cargo_vendored(&fx, U, CargoVendored::Inline, PATCHED_RS);
        fx.put(
            "Cargo.lock",
            cargo_lock_at(version, &tagged_version(OTHER_U), ""),
        );
        let run = fx.vex(&["--proxy-url", &api.uri()]);
        assert_nothing_discovered(&run, &format!("lock v{version} tagged for another uuid"));
    }
}

/// a (first build pending): no Cargo.lock yet — the `[patch]` wiring is
/// what cargo will build, so it attests (the `vendored_entry_in_use` rule).
#[test]
fn cargo_vendored_a_attests_before_the_first_lock() {
    let fx = Fx::new();
    write_cargo_vendored(&fx, U, CargoVendored::Inline, PATCHED_RS);
    fx.rm("Cargo.lock");
    let api = Api::start(vec![(U, cargo_view(U))]);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(&fx, &run, CARGO_PURL, U, "vendored", "no lock");
}

#[test]
fn cargo_vendored_b_without_a_record_is_record_unavailable() {
    let fx = Fx::new();
    write_cargo_vendored(&fx, U, CargoVendored::Inline, PATCHED_RS);
    let api = Api::start(vec![(U, cargo_view(U))]);
    let run = fx.vex(&["--offline", "--proxy-url", &api.uri()]);
    assert_omitted(&run, CARGO_PURL, "record_unavailable", "offline");
    assert_eq!(api.hits(), 0, "--offline must make no network call");
    let empty = Api::start(vec![]);
    let run = fx.vex(&["--proxy-url", &empty.uri()]);
    assert_omitted(&run, CARGO_PURL, "record_unavailable", "API 404");
}

/// c: the vendor ledger's embedded record attests offline (manifest gone);
/// an older ledger with NO embedded record needs the API.
#[test]
fn cargo_vendored_c_ledger_record_attests_offline() {
    let fx = Fx::new();
    write_cargo_vendored(&fx, U, CargoVendored::Inline, PATCHED_RS);
    let wiring = [
        ("Cargo.toml", "cargo_patch_entry"),
        ("Cargo.lock", "cargo_lock_entry"),
    ];
    write_vendor_ledger(
        &fx,
        "cargo",
        CARGO_PURL,
        U,
        &cargo_artifact(U),
        Some(cargo_record(U)),
        &wiring,
    );
    for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
        let run = fx.vex(extra);
        assert_attested(&fx, &run, CARGO_PURL, U, "vendored", &format!("{extra:?}"));
    }
    write_vendor_ledger(
        &fx,
        "cargo",
        CARGO_PURL,
        U,
        &cargo_artifact(U),
        None,
        &wiring,
    );
    let run = fx.vex(&["--offline"]);
    assert_omitted(
        &run,
        CARGO_PURL,
        "record_unavailable",
        "record-less ledger, offline",
    );
    let api = Api::start(vec![(U, cargo_view(U))]);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(
        &fx,
        &run,
        CARGO_PURL,
        U,
        "vendored",
        "record-less ledger, online",
    );
}

/// d: the manifest `[patch]` entry removed, a pre-v5 project's whole
/// config deleted, or the lock re-resolved from crates.io (an unused patch)
/// — artifact + ledger left behind → `vendor_unwired`, `--no-verify` or not.
#[test]
fn cargo_vendored_d_reverted_wiring_never_keeps_the_ledger_alive() {
    let shapes: [(&str, CargoVendored, &str, &Shape); 3] = [
        (
            "[patch] entry removed",
            CargoVendored::Inline,
            "Cargo.toml",
            &|fx: &Fx| fx.put("Cargo.toml", cargo_toml_unwired()),
        ),
        (
            "legacy config deleted",
            CargoVendored::LegacyConfigToml,
            ".cargo/config.toml",
            &|fx: &Fx| fx.rm(".cargo/config.toml"),
        ),
        (
            "lock re-resolved from crates.io",
            CargoVendored::Inline,
            "Cargo.toml",
            &|fx: &Fx| {
                fx.put(
                    "Cargo.lock",
                    cargo_lock(
                        4,
                        &format!(
                            "source = \"{CRATES_IO}\"\nchecksum = \"{}\"\n",
                            "c".repeat(64)
                        ),
                    ),
                )
            },
        ),
    ];
    for (name, flavor, wiring_file, revert) in shapes {
        let fx = Fx::new();
        write_cargo_vendored(&fx, U, flavor, PATCHED_RS);
        write_vendor_ledger(
            &fx,
            "cargo",
            CARGO_PURL,
            U,
            &cargo_artifact(U),
            Some(cargo_record(U)),
            &[
                (wiring_file, "cargo_patch_entry"),
                ("Cargo.lock", "cargo_lock_entry"),
            ],
        );
        revert(&fx);
        for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
            let run = fx.vex(extra);
            assert_omitted(
                &run,
                CARGO_PURL,
                "vendor_unwired",
                &format!("{name} {extra:?}"),
            );
        }
        // Ledger-less, the same leftover artifact is simply not referenced.
        fx.rm(".socket/vendor/state.json");
        let api = Api::start(vec![(U, cargo_view(U))]);
        let run = fx.vex(&["--proxy-url", &api.uri()]);
        assert_ne!(run.code, Some(0), "{name}, ledger-less: {}", run.env);
        assert!(run.doc.is_none(), "{name}, ledger-less");
    }
}

/// d (REGRESSION, real-cargo lock shape): the user replaced the crate with
/// their own path dependency and left the vendored `[patch]` behind. The
/// lock still has a SOURCELESS `serde 1.0.190` (the path dep's) — what cargo
/// 1.97 writes, verified with the real toolchain — plus `[[patch.unused]]
/// serde 1.0.190`: the vendored copy is NOT in the graph. Before the fix
/// the sourceless entry alone made it a live reference and `vex` attested
/// `(vendored)` for a copy the build never compiles — ledger or not.
#[test]
fn cargo_vendored_d_patch_shadowed_by_a_path_dependency_is_unwired() {
    let fx = Fx::new();
    write_cargo_vendored(&fx, U, CargoVendored::Inline, PATCHED_RS);
    fx.put(
        "my-serde/Cargo.toml",
        format!("[package]\nname = \"{CRATE}\"\nversion = \"{CRATE_VERSION}\"\n"),
    );
    fx.put("my-serde/src/lib.rs", PRISTINE_RS);
    fx.put(
        "Cargo.toml",
        cargo_toml(&format!(
            "[dependencies]\n{CRATE} = {{ path = \"my-serde\" }}\n\n\
             [patch.crates-io]\n{CRATE} = {{ path = \"{}\" }}\n",
            cargo_artifact(U)
        )),
    );
    fx.put(
        "Cargo.lock",
        format!(
            "{}\n[[patch.unused]]\nname = \"{CRATE}\"\nversion = \"{CRATE_VERSION}\"\n",
            cargo_lock(4, "")
        ),
    );
    let api = Api::start(vec![(U, cargo_view(U))]);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_nothing_discovered(&run, "ledger-less");
    assert!(
        warning_codes(&run)
            .iter()
            .any(|c| c == "patched_ref_invalid"),
        "the rejection is explained: {}",
        run.env
    );
    write_vendor_ledger(
        &fx,
        "cargo",
        CARGO_PURL,
        U,
        &cargo_artifact(U),
        Some(cargo_record(U)),
        &[
            ("Cargo.toml", "cargo_patch_entry"),
            ("Cargo.lock", "cargo_lock_entry"),
        ],
    );
    for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
        let run = fx.vex(extra);
        assert_omitted(
            &run,
            CARGO_PURL,
            "vendor_unwired",
            &format!("ledger {extra:?}"),
        );
    }
}

/// e: a tampered member of the committed copy → `vendor_hash_mismatch`,
/// ledger-less or ledger-backed.
#[test]
fn cargo_vendored_e_tampered_artifact_member_is_omitted() {
    let fx = Fx::new();
    write_cargo_vendored(&fx, U, CargoVendored::Inline, b"// tampered\n");
    let api = Api::start(vec![(U, cargo_view(U))]);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_omitted(&run, CARGO_PURL, "vendor_hash_mismatch", "ledger-less");
    write_vendor_ledger(
        &fx,
        "cargo",
        CARGO_PURL,
        U,
        &cargo_artifact(U),
        Some(cargo_record(U)),
        &[("Cargo.toml", "cargo_patch_entry")],
    );
    let run = fx.vex(&["--offline"]);
    assert_omitted(&run, CARGO_PURL, "vendor_hash_mismatch", "ledger");
}

/// f: a `[patch]` path that is not root-anchored (another checkout's copy)
/// or whose leaf names another crate is no reference; a record naming
/// another package or patch is `record_mismatch`.
#[test]
fn cargo_vendored_f_spoofed_references_never_attest() {
    let api = Api::start(vec![(U, cargo_view(U))]);
    for (name, path) in [
        ("parent-relative", format!("../other/{}", cargo_artifact(U))),
        (
            "leaf names another crate",
            format!(".socket/vendor/cargo/{U}/libc-0.2.150"),
        ),
    ] {
        let fx = Fx::new();
        write_cargo_vendored(&fx, U, CargoVendored::Inline, PATCHED_RS);
        fx.put(
            "Cargo.toml",
            format!(
                "{}\n[patch.crates-io]\n{CRATE} = {{ path = \"{path}\" }}\n",
                cargo_toml_unwired()
            ),
        );
        let run = fx.vex(&["--proxy-url", &api.uri()]);
        assert_ne!(run.code, Some(0), "{name}: {}", run.env);
        assert!(run.doc.is_none(), "{name}");
    }

    let other_pkg = view(
        U,
        "pkg:cargo/libc@0.2.150",
        "src/lib.rs",
        PRISTINE_RS,
        PATCHED_RS,
    );
    for (name, body) in [
        ("other package", other_pkg),
        ("other uuid", cargo_view(OTHER_U)),
    ] {
        let fx = Fx::new();
        write_cargo_vendored(&fx, U, CargoVendored::Inline, PATCHED_RS);
        let api = Api::start(vec![(U, body)]);
        let run = fx.vex(&["--proxy-url", &api.uri()]);
        assert_omitted(&run, CARGO_PURL, "record_mismatch", name);
    }
}

/// LIMITATION (design R5): a ledger-LESS vendored dir artifact is verified
/// against the record's files only — there is no recorded file inventory,
/// so an EXTRA file injected into the committed copy goes unnoticed. A
/// ledger entry carrying `fileInventory` catches it (the vendor writers
/// record one for dir artifacts).
#[test]
fn cargo_vendored_injected_file_needs_the_ledger_inventory() {
    let fx = Fx::new();
    write_cargo_vendored(&fx, U, CargoVendored::Inline, PATCHED_RS);
    let rel = cargo_artifact(U);
    let api = Api::start(vec![(U, cargo_view(U))]);
    // The inventory the vendor writer records for the pristine commit.
    let inventory: serde_json::Map<String, Value> = [
        (
            "Cargo.toml",
            fx.read(&format!("{rel}/Cargo.toml")).into_bytes(),
        ),
        ("src/lib.rs", PATCHED_RS.to_vec()),
    ]
    .into_iter()
    .map(|(k, v)| {
        (
            k.to_string(),
            Value::String(compute_git_sha256_from_bytes(&v)),
        )
    })
    .collect();
    fx.put(&format!("{rel}/build.rs"), "fn main() {}\n");

    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(
        &fx,
        &run,
        CARGO_PURL,
        U,
        "vendored",
        "ledger-less: injection unseen",
    );

    write_vendor_ledger(
        &fx,
        "cargo",
        CARGO_PURL,
        U,
        &rel,
        Some(cargo_record(U)),
        &[("Cargo.toml", "cargo_patch_entry")],
    );
    let state_path = ".socket/vendor/state.json";
    let mut state: Value = serde_json::from_str(&fx.read(state_path)).unwrap();
    state["entries"][CARGO_PURL]["artifact"]["fileInventory"] = Value::Object(inventory);
    fx.put(state_path, serde_json::to_string_pretty(&state).unwrap());
    let run = fx.vex(&["--offline"]);
    assert_eq!(
        run.code,
        Some(1),
        "ledger inventory catches the injection: {}",
        run.env
    );
    assert!(run.doc.is_none());
}

// ══════════════════════════════════════════════════════════════════════
// hosted + vendored together, and embedded VEX
// ══════════════════════════════════════════════════════════════════════

/// The second crate of the mixed-mode project (vendored while serde is
/// hosted).
const CRATE2: &str = "cfg-if";
const CRATE2_VERSION: &str = "1.0.0";
const CARGO_PURL2: &str = "pkg:cargo/cfg-if@1.0.0";
const U2: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";

/// One project: serde hosted (three-file rewrite) AND cfg-if vendored
/// (`[patch.crates-io]` + detached entry) — the state a `scan --mode hosted`
/// followed by `vendor` of another crate leaves. Both attest, each with its
/// own marker; `U2`'s record is served for cfg-if.
fn write_cargo_mixed(fx: &Fx) {
    write_cargo_hosted(fx, U, "https://patch.socket.dev", CARGO_HOSTED);
    let rel = format!(".socket/vendor/cargo/{U2}/{CRATE2}-{CRATE2_VERSION}");
    fx.put(
        &format!("{rel}/Cargo.toml"),
        format!("[package]\nname = \"{CRATE2}\"\nversion = \"{CRATE2_VERSION}\"\n"),
    );
    fx.put(&format!("{rel}/src/lib.rs"), PATCHED_RS);
    let toml = fx.read("Cargo.toml");
    fx.put(
        "Cargo.toml",
        format!(
            "{toml}{CRATE2} = \"{CRATE2_VERSION}\"\n\n[patch.crates-io]\n\
             {CRATE2} = {{ path = \"{rel}\" }}\n"
        ),
    );
    let lock = fx.read("Cargo.lock").replace(
        "dependencies = [\n \"serde\",\n]",
        &format!("dependencies = [\n \"{CRATE2}\",\n \"serde\",\n]"),
    );
    fx.put(
        "Cargo.lock",
        format!("{lock}\n[[package]]\nname = \"{CRATE2}\"\nversion = \"{CRATE2_VERSION}\"\n"),
    );
}

fn mixed_api() -> Api {
    Api::start(vec![
        (U, cargo_view(U)),
        (
            U2,
            view(U2, CARGO_PURL2, "src/lib.rs", PRISTINE_RS, PATCHED_RS),
        ),
    ])
}

/// Both statements' subcomponents + the per-patch marker in the impact.
fn assert_mixed(doc: &Value) {
    assert_eq!(
        subcomponents(doc),
        vec![CARGO_PURL2.to_string(), CARGO_PURL.to_string()],
        "{doc}"
    );
    let impact = doc["statements"][0]["impact_statement"].as_str().unwrap();
    assert!(
        impact.contains(&format!("Patched via Socket patch {U} (redirected)"))
            && impact.contains(&format!("Patched via Socket patch {U2} (vendored)")),
        "{impact}"
    );
}

#[test]
fn cargo_hosted_and_vendored_in_one_project_attest_together() {
    let api = mixed_api();
    let fx = Fx::new();
    write_cargo_mixed(&fx);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_eq!(run.code, Some(0), "{}", run.env);
    assert!(warning_codes(&run).is_empty(), "{}", run.env);
    // Both patches fix the same GHSA, so the builder emits ONE statement
    // naming both subcomponents, each patch's provenance in the impact.
    assert_mixed(run.doc.as_ref().unwrap());

    // Offline, neither record is available: both omitted, no network.
    let run = fx.vex(&["--offline", "--proxy-url", &api.uri()]);
    assert_eq!(run.code, Some(1), "{}", run.env);
    let skipped: Vec<&str> = run.env["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "skipped")
        .filter_map(|e| e["errorCode"].as_str())
        .collect();
    assert_eq!(
        skipped,
        ["record_unavailable", "record_unavailable"],
        "{}",
        run.env
    );
    assert_eq!(
        api.hits(),
        2,
        "only the online run fetched (one view per uuid)"
    );
}

/// Embedded `scan --vex` (read-only scan) on the manifest-less, ledger-less
/// mixed project: the scan attests the same patches standalone `vex` does
/// and folds the summary into its envelope; an API that serves no view
/// fails the requested VEX (and removes a stale document).
#[test]
fn embedded_scan_vex_attests_lockfile_wired_patches() {
    let api = mixed_api();
    let fx = Fx::new();
    write_cargo_mixed(&fx);
    let out_path = fx.cwd.join("scan.vex.json");
    let scan = |proxy: &str| {
        let out = fx
            .command()
            .args([
                "scan",
                "--cwd",
                fx.cwd.to_str().unwrap(),
                "--json",
                "--proxy-url",
                proxy,
                "--vex",
                out_path.to_str().unwrap(),
                "--vex-product",
                PRODUCT,
            ])
            .output()
            .expect("invoke scan");
        let env: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "scan JSON ({e}). stdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code(), env)
    };
    let (code, env) = scan(&api.uri());
    assert_eq!(code, Some(0), "{env}");
    assert_eq!(env["status"], "success", "{env}");
    assert_eq!(env["vex"]["statements"], 1, "one GHSA statement: {env}");
    let doc: Value = serde_json::from_slice(&std::fs::read(&out_path).unwrap()).unwrap();
    assert_mixed(&doc);
    assert!(!fx.cwd.join(".socket/manifest.json").exists());

    let empty = Api::start(vec![]);
    let (code, env) = scan(&empty.uri());
    assert_eq!(code, Some(1), "{env}");
    assert_eq!(env["error"]["code"], "no_applicable_patches", "{env}");
    assert!(!out_path.exists(), "the stale document is removed");
}

/// Embedded `apply --vex` / `vendor --vex` on the manifest-less mixed
/// project: neither command has anything of its own to do, but the
/// requested document must still be produced (`status: noManifest` + a
/// `vex` summary) — and offline, with no record anywhere, the requested VEX
/// fails the command rather than exiting 0 without it.
#[test]
fn embedded_apply_and_vendor_vex_attest_lockfile_wired_patches_without_manifest() {
    let api = mixed_api();
    let fx = Fx::new();
    write_cargo_mixed(&fx);
    let before: Vec<String> = ["Cargo.toml", "Cargo.lock", ".cargo/config.toml"]
        .iter()
        .map(|f| fx.read(f))
        .collect();
    let out_path = fx.cwd.join("embedded.vex.json");
    for command in ["apply", "vendor"] {
        let run = |extra: &[&str]| {
            let _ = std::fs::remove_file(&out_path);
            let mut args = vec![
                command.to_string(),
                "--cwd".to_string(),
                fx.cwd.to_str().unwrap().to_string(),
                "--json".to_string(),
                "--vex".to_string(),
                out_path.to_str().unwrap().to_string(),
                "--vex-product".to_string(),
                PRODUCT.to_string(),
            ];
            args.extend(extra.iter().map(|s| s.to_string()));
            let out = fx.command().args(&args).output().expect("invoke");
            let env: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
                panic!(
                    "{command} JSON ({e}). stdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                )
            });
            (out.status.code(), env)
        };

        let (code, env) = run(&["--proxy-url", &api.uri()]);
        assert_eq!(code, Some(0), "{command}: {env}");
        assert_eq!(env["status"], "noManifest", "{command}: {env}");
        assert_eq!(env["vex"]["statements"], 1, "{command}: {env}");
        let doc: Value = serde_json::from_slice(&std::fs::read(&out_path).unwrap()).unwrap();
        assert_mixed(&doc);
        assert!(!fx.cwd.join(".socket/manifest.json").exists(), "{command}");

        let (code, env) = run(&["--offline"]);
        assert_eq!(code, Some(1), "{command}: {env}");
        assert_eq!(
            env["error"]["code"], "no_applicable_patches",
            "{command}: {env}"
        );
        assert!(!out_path.exists(), "{command}");
    }
    // Neither command touched the committed wiring.
    let after: Vec<String> = ["Cargo.toml", "Cargo.lock", ".cargo/config.toml"]
        .iter()
        .map(|f| fx.read(f))
        .collect();
    assert_eq!(before, after);
}
