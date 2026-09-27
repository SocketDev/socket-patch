//! Manifest-less VEX for yarn — the hermetic test matrix for yarn classic
//! (v1 lockfile) and yarn berry 2 / 3 / 4 (node-modules linker), hosted AND
//! vendored, with NO `.socket/manifest.json` and (unless a cell says
//! otherwise) NO `.socket/vendor/state.json` / `redirect-state.json` ledgers.
//!
//! The only input is what a depscan-opened PR (or a checkout whose `.socket/`
//! was never committed) carries: `package.json`, `yarn.lock`, `.yarnrc.yml`
//! and — vendored — the committed `.socket/vendor/npm/<uuid>/<leaf>.tgz`.
//! The patch record comes from a wiremock stand-in for the public patch
//! proxy (`GET /patch/view/<uuid>`); nothing touches the network.
//!
//! Cells, for EVERY flavor × {hosted, vendored} (see the table in each
//! test's doc comment):
//!
//!   a) online, nothing but the lockfile → attested with the right
//!      subcomponent purl, vuln id + CVE alias and `(redirected)` /
//!      `(vendored)` marker; exit 0; a `verified` envelope event.
//!   b) `--offline` with no local record → `record_unavailable`, exit 1, and
//!      the mock API receives ZERO requests.
//!   c) ledger present, manifest absent → attests `--offline` from the
//!      ledger's record.
//!   d) lockfile reverted to the registry while the ledger (and vendored
//!      artifact) remain → `redirect_unwired` / `vendor_unwired`, with and
//!      without `--no-verify`.
//!   e) tampered installed tree (hosted) → `hash_mismatch`; tampered
//!      vendored tarball member → `vendor_hash_mismatch`.
//!   f) spoofing: a uuid-shaped segment on a non-Socket host / outside
//!      `.socket/vendor/` is no reference at all; a record whose purl or uuid
//!      differs from the lock → `record_mismatch`.
//!   g) hosted not installed → attests on the lock's integrity pin (design
//!      D5); installed + patched → attests after hashing; installed pristine
//!      → omitted.
//!
//! Plus the documented limitations, asserted explicitly:
//!   * yarn berry 2/3 locks (cacheKey 7 / 8) carry a BARE-hex `checksum:`
//!     that the extractor does not accept as a pin (only `<cacheKey>/<hex>`
//!     is read as [`LockIntegrity::BerryChecksum`]); Socket's hosted rewriter
//!     refuses those locks outright (`redirect_yarn_berry_cache_unsupported`),
//!     so such an entry is hand-made and attests only from an installed tree
//!     that verifies — never from the lock alone (a missed attestation, never
//!     a false one).
//!   * Plug'n'Play: see [`pnp_layout_contract`].
//!
//! Runs on every OS; no toolchain, no network.

use crate::vex_e2e_common;

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use serde_json::Value;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
use socket_patch_core::patch::redirect::{FileEdit, RedirectState};
use socket_patch_core::vendor::state::{
    VendorArtifact, VendorEntry, VendorState, WiringAction, WiringRecord,
};
use vex_e2e_common::{assert_omitted_parts, read_doc};

const UUID: &str = "4d5e6f70-8192-4a3b-9c4d-5e6f70819243";
/// Another canonical uuid (a different patch).
const OTHER_UUID: &str = "5e6f7081-92a3-4b4c-8d5e-6f7081920354";
/// A uuid-SHAPED grant token: the patch uuid is the LAST uuid segment.
const TOKEN: &str = "11111111-2222-4333-8444-555555555555";
const NAME: &str = "left-pad";
const VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const PRODUCT: &str = "pkg:npm/app@1.0.0";
const GHSA: &str = "GHSA-yarn-lock-vex1";
const CVE: &str = "CVE-2026-7001";
const MEMBER: &str = "package/index.js";
const PRISTINE: &[u8] = b"module.exports = function leftPad() {};\n";
const PATCHED: &[u8] = b"/* SOCKET-PATCHED */\nmodule.exports = function leftPad() {};\n";
/// The berry workspace locator of the `app` root (`app@workspace:.`,
/// percent-encoded the way yarn writes it into `::locator=`).
const LOCATOR: &str = "app%40workspace%3A.";

// ── flavors ──────────────────────────────────────────────────────────────

/// Every yarn lockfile grammar/version in scope. The berry `__metadata`
/// headers and checksum spellings are the ones the REAL `corepack yarn@X`
/// writes for a left-pad@1.3.0 project (captured 2026-09-22 with
/// yarn 2.4.3 / 3.8.7 / 4.12.0, node-modules linker).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flavor {
    /// yarn 1.x — `# yarn lockfile v1`.
    Classic,
    /// yarn 2.4 — `__metadata: version: 4, cacheKey: 7`, bare-hex checksum.
    Berry2,
    /// yarn 3.x — `__metadata: version: 6, cacheKey: 8`, bare-hex checksum.
    Berry3,
    /// yarn 4.x — `__metadata: version: 8, cacheKey: 10c0`, `10c0/<hex>`.
    Berry4,
}

const FLAVORS: [Flavor; 4] = [
    Flavor::Classic,
    Flavor::Berry2,
    Flavor::Berry3,
    Flavor::Berry4,
];

impl Flavor {
    fn is_berry(self) -> bool {
        self != Flavor::Classic
    }

    /// `(lockfile version, cacheKey)` of the berry `__metadata` block.
    fn berry_meta(self) -> (u32, &'static str) {
        match self {
            Flavor::Berry2 => (4, "7"),
            Flavor::Berry3 => (6, "8"),
            Flavor::Berry4 => (8, "10c0"),
            Flavor::Classic => unreachable!("classic has no __metadata"),
        }
    }

    /// The `checksum:` value this yarn writes (yarn 4 prefixes the cacheKey;
    /// yarn 2/3 write the bare hex).
    fn berry_checksum(self, hex_char: char) -> String {
        let hex: String = std::iter::repeat_n(hex_char, 128).collect();
        match self {
            Flavor::Berry4 => format!("10c0/{hex}"),
            _ => hex,
        }
    }

    /// Whether the lock carries an integrity pin the extractor accepts for a
    /// hosted entry (see the module doc's berry 2/3 limitation).
    fn hosted_pin_is_read(self) -> bool {
        matches!(self, Flavor::Classic | Flavor::Berry4)
    }

    /// The vendor-ledger `flavor` the npm-family vendor backends record.
    fn ledger_flavor(self) -> &'static str {
        if self.is_berry() {
            "yarn-berry"
        } else {
            "yarn-classic"
        }
    }
}

// ── lockfile writers ─────────────────────────────────────────────────────

fn berry_header(flavor: Flavor) -> String {
    let (version, cache_key) = flavor.berry_meta();
    format!(
        "# This file is generated by running \"yarn install\" inside your project.\n\
         # Manual changes might be lost - proceed with caution!\n\n__metadata:\n  \
         version: {version}\n  cacheKey: {cache_key}\n\n"
    )
}

/// The berry root-workspace block (yarn 4 quotes the `npm:` range).
fn berry_workspace_block(flavor: Flavor) -> String {
    let dep = if flavor == Flavor::Berry4 {
        "\"npm:1.3.0\""
    } else {
        "1.3.0"
    };
    format!(
        "\"app@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"app@workspace:.\"\n  \
         dependencies:\n    left-pad: {dep}\n  languageName: unknown\n  linkType: soft\n"
    )
}

const CLASSIC_HEADER: &str =
    "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n";

/// A classic hosted artifact URL (the shape `rewrite_yarn_classic`'s goldens
/// carry) on `origin`, for patch `uuid`.
fn classic_hosted_url(origin: &str, uuid: &str) -> String {
    format!("{origin}/patch/npm/{NAME}/{VERSION}/{TOKEN}/{uuid}/{NAME}-{VERSION}.tgz")
}

/// A berry hosted artifact URL (the shorter shape the berry goldens carry).
fn berry_hosted_url(origin: &str, uuid: &str) -> String {
    format!("{origin}/patch/npm/{TOKEN}/{uuid}/{NAME}-{VERSION}.tgz")
}

/// JavaScript's `encodeURIComponent` — how both yarn berry and Socket's
/// rewriter spell the `__archiveUrl=` binding.
fn encode_uri_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `yarn.lock` resolving left-pad from the hosted Socket patch `uuid` on
/// `origin` — exactly what `scan --mode hosted` writes for each grammar.
fn hosted_lock(flavor: Flavor, origin: &str, uuid: &str) -> String {
    if flavor.is_berry() {
        let url = berry_hosted_url(origin, uuid);
        format!(
            "{}\"left-pad@npm:1.3.0\":\n  version: 1.3.0\n  resolution: \
             \"left-pad@npm:1.3.0::__archiveUrl={}\"\n  checksum: {}\n  languageName: node\n  \
             linkType: hard\n\n{}",
            berry_header(flavor),
            encode_uri_component(&url),
            flavor.berry_checksum('7'),
            berry_workspace_block(flavor),
        )
    } else {
        format!(
            "{CLASSIC_HEADER}left-pad@1.3.0:\n  version \"1.3.0\"\n  resolved \"{}#{}\"\n  \
             integrity sha512-UEFUQ0hFRHBhdGNoZWRQQVRDSEVEcGF0Y2hlZA==\n",
            classic_hosted_url(origin, uuid),
            "abcdef0123456789abcdef0123456789abcdef01",
        )
    }
}

/// The registry lock the real yarn of each flavor writes for left-pad —
/// the state after a user reverts Socket's rewrite.
fn registry_lock(flavor: Flavor) -> String {
    if flavor.is_berry() {
        format!(
            "{}{}\n\"left-pad@npm:1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  \
             checksum: {}\n  languageName: node\n  linkType: hard\n",
            berry_header(flavor),
            berry_workspace_block(flavor),
            flavor.berry_checksum('3'),
        )
    } else {
        format!(
            "{CLASSIC_HEADER}left-pad@1.3.0:\n  version \"1.3.0\"\n  resolved \
             \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e\"\n  \
             integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==\n"
        )
    }
}

fn vendored_rel(uuid: &str) -> String {
    format!(".socket/vendor/npm/{uuid}/{NAME}-{VERSION}.tgz")
}

/// `yarn.lock` wiring left-pad to the committed tarball `rel` — the shapes
/// `vendor_yarn_classic` / `vendor_yarn_berry` write.
fn vendored_lock(flavor: Flavor, rel: &str) -> String {
    if flavor.is_berry() {
        format!(
            "{}{}\n\"left-pad@file:./{rel}::locator={LOCATOR}\":\n  version: 1.3.0\n  \
             resolution: \"left-pad@file:./{rel}#./{rel}::hash=39ea9b&locator={LOCATOR}\"\n  \
             checksum: {}\n  languageName: node\n  linkType: hard\n",
            berry_header(flavor),
            berry_workspace_block(flavor),
            flavor.berry_checksum('9'),
        )
    } else {
        format!(
            "{CLASSIC_HEADER}left-pad@1.3.0:\n  version \"1.3.0\"\n  resolved \"file:./{rel}#{}\"\n  \
             integrity sha512-VkVORE9SRURyZW5kZXJlZFZFTkRPUkVE==\n",
            "0123456789abcdef0123456789abcdef01234567",
        )
    }
}

/// Root `package.json`; a berry vendored project also maps the package onto
/// the committed tarball via `resolutions` (the dependency range itself
/// stays `1.3.0` — that is the shape `vendor_yarn_berry` writes).
fn package_json(resolution: Option<&str>) -> String {
    let mut doc = serde_json::json!({
        "name": "app",
        "version": "1.0.0",
        "dependencies": { NAME: VERSION },
    });
    if let Some(rel) = resolution {
        doc["resolutions"] = serde_json::json!({ NAME: format!("file:./{rel}") });
    }
    doc.to_string()
}

fn put(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// `package.json` + `.yarnrc.yml` (node-modules linker for berry) — the
/// project files every cell shares.
fn write_project(cwd: &Path, flavor: Flavor, resolution: Option<&str>) {
    put(cwd, "package.json", package_json(resolution).as_bytes());
    if flavor.is_berry() {
        put(
            cwd,
            ".yarnrc.yml",
            b"nodeLinker: node-modules\nenableGlobalCache: false\n",
        );
    }
}

/// A hosted lockfile-only checkout for `flavor`: nothing installed, no
/// `.socket/` at all.
fn hosted_checkout(cwd: &Path, flavor: Flavor) {
    write_project(cwd, flavor, None);
    put(
        cwd,
        "yarn.lock",
        hosted_lock(flavor, "https://patch.socket.dev", UUID).as_bytes(),
    );
}

/// Single-member `.tgz` at `dest`.
fn write_member_tgz(dest: &Path, member: &str, bytes: &[u8]) {
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    let mut out = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut out, flate2::Compression::new(6));
        let mut builder = tar::Builder::new(enc);
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, member, bytes).unwrap();
        builder.into_inner().unwrap().finish().unwrap();
    }
    std::fs::write(dest, &out).unwrap();
}

/// A vendored lockfile-only checkout for `flavor`: the lock (and, berry,
/// the `resolutions` mapping) wire left-pad to the committed tarball whose
/// `package/index.js` holds `artifact_bytes`. Returns the artifact path.
fn vendored_checkout(cwd: &Path, flavor: Flavor, artifact_bytes: &[u8]) -> String {
    let rel = vendored_rel(UUID);
    write_member_tgz(&cwd.join(&rel), MEMBER, artifact_bytes);
    write_project(cwd, flavor, flavor.is_berry().then_some(rel.as_str()));
    put(cwd, "yarn.lock", vendored_lock(flavor, &rel).as_bytes());
    rel
}

/// An installed `node_modules/left-pad` whose `index.js` holds `bytes`.
fn install(cwd: &Path, bytes: &[u8]) {
    put(
        cwd,
        "node_modules/left-pad/package.json",
        format!(r#"{{"name":"{NAME}","version":"{VERSION}"}}"#).as_bytes(),
    );
    put(cwd, "node_modules/left-pad/index.js", bytes);
}

// ── records, API, ledgers ────────────────────────────────────────────────

/// The API patch view for `uuid` → `purl` (one file, one GHSA + CVE).
fn patch_view(uuid: &str, purl: &str) -> Value {
    serde_json::json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "Fri, 27 Mar 2026 00:00:00 GMT",
        "files": { MEMBER: {
            "beforeHash": compute_git_sha256_from_bytes(PRISTINE),
            "afterHash": compute_git_sha256_from_bytes(PATCHED),
        } },
        "vulnerabilities": {
            GHSA: { "cves": [CVE], "summary": "s", "severity": "high", "description": "d" }
        },
        "description": "yarn lockfile patch",
        "license": "MIT",
        "tier": "free",
    })
}

/// The same patch as an embedded ledger record.
fn record(uuid: &str) -> PatchRecord {
    let mut files = HashMap::new();
    files.insert(
        MEMBER.to_string(),
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
        description: "yarn lockfile patch".to_string(),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

/// A patch-API stand-in serving `GET /patch/view/<uuid>` for each view; the
/// runtime must outlive the CLI invocation.
fn serve_patch_views(views: Vec<(&str, Value)>) -> (tokio::runtime::Runtime, wiremock::MockServer) {
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
    (rt, server)
}

/// The API serving the genuine left-pad patch view.
fn serve_left_pad() -> (tokio::runtime::Runtime, wiremock::MockServer) {
    serve_patch_views(vec![(UUID, patch_view(UUID, PURL))])
}

fn request_count(rt: &tokio::runtime::Runtime, server: &wiremock::MockServer) -> usize {
    rt.block_on(server.received_requests())
        .map(|r| r.len())
        .unwrap_or(0)
}

/// The redirect ledger `scan --mode hosted` persists: the embedded record
/// plus the yarn.lock edit.
fn write_redirect_ledger(cwd: &Path, flavor: Flavor, rec: PatchRecord) {
    let mut state = RedirectState::new();
    state.records.insert(PURL.to_string(), rec);
    state.edits.push(FileEdit {
        path: "yarn.lock".to_string(),
        kind: if flavor.is_berry() {
            "redirect_yarn_berry_entry"
        } else {
            "redirect_yarn_classic_entry"
        }
        .to_string(),
        action: "rewritten".to_string(),
        key: None,
        original: None,
        new: None,
    });
    put(
        cwd,
        ".socket/vendor/redirect-state.json",
        serde_json::to_string_pretty(&state).unwrap().as_bytes(),
    );
}

/// The vendor ledger `scan --vendor` persists for a yarn project: embedded
/// record (D9) and the backend's own wiring records.
fn write_vendor_ledger(cwd: &Path, flavor: Flavor, rel: &str, rec: PatchRecord) {
    let wiring_record = |file: &str, kind: &str| WiringRecord {
        file: file.to_string(),
        kind: kind.to_string(),
        action: WiringAction::Rewritten,
        key: Some(NAME.to_string()),
        original: None,
        new: None,
    };
    let wiring = if flavor.is_berry() {
        vec![
            wiring_record("package.json", "yarn_berry_resolution"),
            wiring_record("yarn.lock", "yarn_berry_lock_entry"),
        ]
    } else {
        vec![wiring_record("yarn.lock", "yarn_lock_block")]
    };
    let mut state = VendorState::new();
    state.entries.insert(
        PURL.to_string(),
        VendorEntry {
            ecosystem: "npm".to_string(),
            base_purl: PURL.to_string(),
            uuid: rec.uuid.clone(),
            artifact: VendorArtifact {
                path: rel.to_string(),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring,
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: Some(rec),
            flavor: Some(flavor.ledger_flavor().to_string()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        },
    );
    put(
        cwd,
        ".socket/vendor/state.json",
        serde_json::to_string_pretty(&state).unwrap().as_bytes(),
    );
}

// ── CLI ──────────────────────────────────────────────────────────────────

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_socket-patch")
}

/// The CLI with the ambient `SOCKET_*` environment scrubbed (explicit flags
/// are the sole source of truth), no token, no socket-cli config, telemetry
/// off.
fn cli() -> Command {
    let mut cmd = Command::new(binary());
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("SOCKET_NO_API_TOKEN", "1")
        .env_remove("VIRTUAL_ENV");
    cmd
}

/// Parse a JSON envelope from stdout, or panic with both streams.
fn envelope(out: &std::process::Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "envelope JSON on stdout ({e}). stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// `vex --json --output out.vex.json` in `cwd`; returns (exit, envelope).
fn vex_json(cwd: &Path, extra: &[&str]) -> (Option<i32>, Value) {
    let _ = std::fs::remove_file(cwd.join("out.vex.json"));
    let vex_path = cwd.join("out.vex.json");
    let mut args = vec![
        "vex",
        "--cwd",
        cwd.to_str().unwrap(),
        "--json",
        "--output",
        vex_path.to_str().unwrap(),
        "--product",
        PRODUCT,
    ];
    args.extend_from_slice(extra);
    let out = cli().args(&args).output().expect("invoke vex");
    (out.status.code(), envelope(&out))
}

/// Assert a run attested exactly the left-pad patch `uuid` with `marker`
/// (`redirected` / `vendored`): exit 0, one `verified` event, and one
/// OpenVEX statement with the right subcomponent, vulnerability, alias and
/// impact statement. The manifest is never written.
fn assert_attested(
    cwd: &Path,
    code: Option<i32>,
    env: &Value,
    uuid: &str,
    marker: &str,
    cell: &str,
) {
    assert_eq!(code, Some(0), "{cell}: {env}");
    let verified: Vec<&Value> = env["events"]
        .as_array()
        .unwrap_or_else(|| panic!("{cell}: no events: {env}"))
        .iter()
        .filter(|e| e["action"] == "verified")
        .collect();
    assert_eq!(verified.len(), 1, "{cell}: {env}");
    assert_eq!(verified[0]["purl"], PURL, "{cell}: {env}");
    let doc: Value = serde_json::from_slice(
        &std::fs::read(cwd.join("out.vex.json"))
            .unwrap_or_else(|e| panic!("{cell}: no VEX document ({e}): {env}")),
    )
    .unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "{cell}: {doc}");
    let s = &stmts[0];
    assert_eq!(s["status"], "not_affected", "{cell}: {doc}");
    assert_eq!(s["vulnerability"]["name"], GHSA, "{cell}: {doc}");
    assert_eq!(s["vulnerability"]["aliases"][0], CVE, "{cell}: {doc}");
    assert_eq!(s["products"][0]["@id"], PRODUCT, "{cell}: {doc}");
    assert_eq!(
        s["products"][0]["subcomponents"][0]["@id"], PURL,
        "{cell}: {doc}"
    );
    assert_eq!(
        s["impact_statement"],
        format!("Patched via Socket patch {uuid} ({marker})"),
        "{cell}: {doc}"
    );
    assert!(
        !cwd.join(".socket/manifest.json").exists(),
        "{cell}: vex never writes the manifest"
    );
}

/// Assert a run attested NOTHING and skipped left-pad with `reason`; no
/// OpenVEX document is left behind.
fn assert_omitted(cwd: &Path, code: Option<i32>, env: &Value, reason: &str, cell: &str) {
    let doc = read_doc(&cwd.join("out.vex.json"));
    assert_omitted_parts(code, env, doc.as_ref(), PURL, reason, cell);
}

// ──────────────────────────────────────────────────────────────────────
// HOSTED — lockfile only (cells a, b, e, g)
// ──────────────────────────────────────────────────────────────────────

/// | cell | classic | berry 2 | berry 3 | berry 4 |
/// |---|---|---|---|---|
/// | b offline, no record | record_unavailable, 0 requests | same | same | same |
/// | g not installed (lock pin) | attests | package_not_found (limitation) | same | attests |
/// | g installed patched | attests | attests | attests | attests |
/// | e installed tampered | hash_mismatch | same | same | same |
/// | g installed pristine | omitted | same | same | same |
#[test]
fn hosted_lockfile_only_matrix() {
    for flavor in FLAVORS {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        hosted_checkout(cwd, flavor);
        assert!(!cwd.join(".socket").exists());

        // b) offline: the wiring is found, but no record is available — and
        // the mock API (reachable via --proxy-url) is never contacted.
        let (rt, server) = serve_left_pad();
        let (code, env) = vex_json(cwd, &["--offline", "--proxy-url", &server.uri()]);
        let cell = format!("{flavor:?} hosted b) offline");
        assert_omitted(cwd, code, &env, "record_unavailable", &cell);
        assert_eq!(request_count(&rt, &server), 0, "{cell}: network call made");

        // a/g) online, nothing installed: the PINNED hosted wiring is the
        // evidence (design D5). yarn 2/3's bare-hex checksum is not read as
        // a pin (module doc), so those need an installed tree.
        let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
        let cell = format!("{flavor:?} hosted a) online, not installed");
        if flavor.hosted_pin_is_read() {
            assert_attested(cwd, code, &env, UUID, "redirected", &cell);
            assert!(request_count(&rt, &server) >= 1, "{cell}: record fetched");
        } else {
            assert_omitted(cwd, code, &env, "package_not_found", &cell);
        }

        // g) installed + patched: hash-verified, attests.
        install(cwd, PATCHED);
        let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
        let cell = format!("{flavor:?} hosted g) installed patched");
        assert_attested(cwd, code, &env, UUID, "redirected", &cell);

        // e) installed but tampered: the installed evidence wins over the
        // lock pin — omitted.
        install(cwd, b"tampered bytes\n");
        let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
        let cell = format!("{flavor:?} hosted e) installed tampered");
        assert_omitted(cwd, code, &env, "hash_mismatch", &cell);

        // g) installed pristine (the registry bytes — the hosted tarball was
        // never installed): omitted.
        install(cwd, PRISTINE);
        let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
        let cell = format!("{flavor:?} hosted g) installed pristine");
        assert_omitted(cwd, code, &env, "not_applied", &cell);
        drop(rt);
    }
}

// ──────────────────────────────────────────────────────────────────────
// VENDORED — lockfile only (cells a, b, e)
// ──────────────────────────────────────────────────────────────────────

/// | cell | classic | berry 2 | berry 3 | berry 4 |
/// |---|---|---|---|---|
/// | b offline, no record | record_unavailable, 0 requests | same | same | same |
/// | a online | attests (vendored) | same | same | same |
/// | a + pristine node_modules copy | attests (the artifact is the evidence) | same | same | same |
/// | e tampered artifact member | vendor_hash_mismatch | same | same | same |
/// | e artifact deleted | vendor_artifact_missing | same | same | same |
#[test]
fn vendored_lockfile_only_matrix() {
    for flavor in FLAVORS {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let rel = vendored_checkout(cwd, flavor, PATCHED);
        assert!(!cwd.join(".socket/manifest.json").exists());
        assert!(!cwd.join(".socket/vendor/state.json").exists());

        let (rt, server) = serve_left_pad();
        let (code, env) = vex_json(cwd, &["--offline", "--proxy-url", &server.uri()]);
        let cell = format!("{flavor:?} vendored b) offline");
        assert_omitted(cwd, code, &env, "record_unavailable", &cell);
        assert_eq!(request_count(&rt, &server), 0, "{cell}: network call made");

        let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
        let cell = format!("{flavor:?} vendored a) online");
        assert_attested(cwd, code, &env, UUID, "vendored", &cell);

        // The installed tree of a vendored package is not the evidence (the
        // committed artifact is what the lock consumes).
        install(cwd, PATCHED);
        let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
        let cell = format!("{flavor:?} vendored a) online, installed");
        assert_attested(cwd, code, &env, UUID, "vendored", &cell);

        // e) the committed tarball's member no longer hashes to the record.
        write_member_tgz(&cwd.join(&rel), MEMBER, b"tampered vendored bytes\n");
        let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
        let cell = format!("{flavor:?} vendored e) tampered artifact");
        assert_omitted(cwd, code, &env, "vendor_hash_mismatch", &cell);

        // The committed artifact deleted while the lock still wires it.
        std::fs::remove_file(cwd.join(&rel)).unwrap();
        let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
        let cell = format!("{flavor:?} vendored e) artifact missing");
        assert_omitted(cwd, code, &env, "vendor_artifact_missing", &cell);
        drop(rt);
    }
}

// ──────────────────────────────────────────────────────────────────────
// LEDGER present, manifest absent (cell c) and reverted lock (cell d)
// ──────────────────────────────────────────────────────────────────────

/// c) the ledger's embedded record attests `--offline` (no API at all), and
/// d) once the lock is reverted to the registry the SAME ledger (and the
/// vendored artifact, still on disk) no longer attests — with or without
/// `--no-verify`.
#[test]
fn ledger_attests_offline_until_the_lock_is_reverted() {
    for flavor in FLAVORS {
        // ── hosted ──
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        hosted_checkout(cwd, flavor);
        write_redirect_ledger(cwd, flavor, record(UUID));
        let (rt, server) = serve_left_pad();
        // yarn 2/3 hosted needs an installed tree (no readable lock pin);
        // the others attest from the pin alone.
        if !flavor.hosted_pin_is_read() {
            install(cwd, PATCHED);
        }
        for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
            let mut args = extra.to_vec();
            let uri = server.uri();
            args.extend(["--proxy-url", uri.as_str()]);
            let (code, env) = vex_json(cwd, &args);
            let cell = format!("{flavor:?} hosted c) ledger {extra:?}");
            assert_attested(cwd, code, &env, UUID, "redirected", &cell);
        }
        put(cwd, "yarn.lock", registry_lock(flavor).as_bytes());
        // Even a still-patched stale node_modules cannot revive it: the next
        // install replaces it from the registry.
        install(cwd, PATCHED);
        for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
            let (code, env) = vex_json(cwd, extra);
            let cell = format!("{flavor:?} hosted d) reverted lock {extra:?}");
            assert_omitted(cwd, code, &env, "redirect_unwired", &cell);
        }
        // Online too: a reverted lock never sends vex to the API for the
        // stale ledger's uuid.
        let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
        assert_omitted(
            cwd,
            code,
            &env,
            "redirect_unwired",
            &format!("{flavor:?} hosted d) reverted lock online"),
        );
        assert_eq!(request_count(&rt, &server), 0, "{flavor:?}: network call");

        // ── vendored ──
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let rel = vendored_checkout(cwd, flavor, PATCHED);
        write_vendor_ledger(cwd, flavor, &rel, record(UUID));
        for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
            let (code, env) = vex_json(cwd, extra);
            let cell = format!("{flavor:?} vendored c) ledger {extra:?}");
            assert_attested(cwd, code, &env, UUID, "vendored", &cell);
        }
        // d) the lock reverted (berry: the `resolutions` mapping too, as
        // `vendor --revert` does) — artifact and ledger stay behind.
        put(cwd, "yarn.lock", registry_lock(flavor).as_bytes());
        put(cwd, "package.json", package_json(None).as_bytes());
        assert!(cwd.join(&rel).exists());
        for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
            let (code, env) = vex_json(cwd, extra);
            let cell = format!("{flavor:?} vendored d) reverted lock {extra:?}");
            assert_omitted(cwd, code, &env, "vendor_unwired", &cell);
        }
        if flavor.is_berry() {
            // Half-reverted berry: the lock still carries the `file:` entry
            // but nothing maps the package onto it (yarn installs the
            // registry copy) — dead wiring, the ledger must not revive it.
            put(cwd, "yarn.lock", vendored_lock(flavor, &rel).as_bytes());
            for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
                let (code, env) = vex_json(cwd, extra);
                let cell = format!("{flavor:?} vendored d) orphaned file: entry {extra:?}");
                assert_omitted(cwd, code, &env, "vendor_unwired", &cell);
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// SPOOFING (cell f)
// ──────────────────────────────────────────────────────────────────────

/// A uuid-shaped segment on a NON-Socket host is the user's own dependency
/// source, never a patch reference: nothing is discovered (exit 2,
/// `manifest_not_found`, no API call) — and a redirect ledger for that uuid
/// is `redirect_unwired`, never revived by the look-alike URL.
#[test]
fn uuid_on_a_foreign_host_is_not_a_hosted_reference() {
    for flavor in FLAVORS {
        for origin in [
            "https://evil.example",
            // Suffix / userinfo look-alikes of the Socket host.
            "https://patch.socket.dev.evil.example",
            "https://patch.socket.dev@evil.example",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let cwd = tmp.path();
            write_project(cwd, flavor, None);
            put(
                cwd,
                "yarn.lock",
                hosted_lock(flavor, origin, UUID).as_bytes(),
            );
            let (rt, server) = serve_left_pad();
            let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
            let cell = format!("{flavor:?} f) foreign host {origin}");
            assert_eq!(code, Some(2), "{cell}: {env}");
            assert_eq!(env["error"]["code"], "manifest_not_found", "{cell}: {env}");
            assert_eq!(request_count(&rt, &server), 0, "{cell}: network call");

            // DOCUMENTED FALLBACK (vex_sources `redirect_record_live`): a
            // uuid the discovery allowlist does not recognize is judged by
            // the ledger's raw-text fallback, which accepts ANY host so a
            // staging patch server used without `--patch-server-url` keeps
            // working. The fallback never trusts the look-alike lock's pin:
            // with verification on it attests only an installed tree that
            // hashes to the record. (`--no-verify` trusts the ledger by
            // definition — CLI_CONTRACT.md, "Patch hosts (manifest-less
            // VEX)".)
            write_redirect_ledger(cwd, flavor, record(UUID));
            let (code, env) = vex_json(cwd, &["--offline"]);
            assert_omitted(
                cwd,
                code,
                &env,
                "package_not_found",
                &format!("{cell} + ledger, not installed"),
            );
            install(cwd, b"tampered bytes\n");
            let (code, env) = vex_json(cwd, &["--offline"]);
            assert_omitted(
                cwd,
                code,
                &env,
                "hash_mismatch",
                &format!("{cell} + ledger, tampered"),
            );
            install(cwd, PATCHED);
            let (code, env) = vex_json(cwd, &["--offline"]);
            assert_attested(
                cwd,
                code,
                &env,
                UUID,
                "redirected",
                &format!("{cell} + ledger, verified"),
            );
        }
    }
}

/// A uuid-shaped directory OUTSIDE `.socket/vendor/` is not a vendored
/// reference (and a vendor ledger for it stays unwired).
#[test]
fn uuid_outside_socket_vendor_is_not_a_vendored_reference() {
    for flavor in FLAVORS {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let fake = format!("vendor/npm/{UUID}/{NAME}-{VERSION}.tgz");
        write_member_tgz(&cwd.join(&fake), MEMBER, PATCHED);
        write_project(cwd, flavor, flavor.is_berry().then_some(fake.as_str()));
        put(cwd, "yarn.lock", vendored_lock(flavor, &fake).as_bytes());
        let (code, env) = vex_json(cwd, &["--offline"]);
        let cell = format!("{flavor:?} f) uuid outside .socket/vendor");
        assert_eq!(code, Some(2), "{cell}: {env}");
        assert_eq!(env["error"]["code"], "manifest_not_found", "{cell}: {env}");

        // A ledger claiming that uuid for the real vendored path — whose
        // tarball exists — is still unwired: the lock wires something else.
        let rel = vendored_rel(UUID);
        write_member_tgz(&cwd.join(&rel), MEMBER, PATCHED);
        write_vendor_ledger(cwd, flavor, &rel, record(UUID));
        let (code, env) = vex_json(cwd, &["--offline", "--no-verify"]);
        assert_omitted(
            cwd,
            code,
            &env,
            "vendor_unwired",
            &format!("{cell} + ledger"),
        );
    }
}

/// The API's record for the wired uuid disagrees with the lock — it names
/// ANOTHER package, another version, or another patch uuid: never attested
/// (`record_mismatch`), hosted and vendored.
#[test]
fn record_disagreeing_with_the_lock_is_a_mismatch() {
    let spoofs: [(&str, Value); 3] = [
        (
            "another package",
            patch_view(UUID, "pkg:npm/minimist@1.2.5"),
        ),
        (
            "another version",
            patch_view(UUID, "pkg:npm/left-pad@1.2.0"),
        ),
        ("another uuid", patch_view(OTHER_UUID, PURL)),
    ];
    for flavor in FLAVORS {
        for (what, view) in &spoofs {
            for mode in ["hosted", "vendored"] {
                let tmp = tempfile::tempdir().unwrap();
                let cwd = tmp.path();
                if mode == "hosted" {
                    hosted_checkout(cwd, flavor);
                    install(cwd, PATCHED);
                } else {
                    vendored_checkout(cwd, flavor, PATCHED);
                }
                let (_rt, server) = serve_patch_views(vec![(UUID, view.clone())]);
                let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
                let cell = format!("{flavor:?} {mode} f) record names {what}");
                assert_omitted(cwd, code, &env, "record_mismatch", &cell);
            }
        }
    }
}

/// A LEDGER record for a different patch than the one the lock wires never
/// attests the lock's uuid: the lockfile uuid wins (design D4), so offline
/// the wired patch has no record (`record_unavailable` — the only event for
/// the purl; the stale ledger record is not borrowed), and online the API
/// record for the WIRED uuid is the one attested.
#[test]
fn ledger_record_for_another_uuid_is_not_borrowed() {
    for flavor in FLAVORS {
        for mode in ["hosted", "vendored"] {
            let tmp = tempfile::tempdir().unwrap();
            let cwd = tmp.path();
            let marker = if mode == "hosted" {
                hosted_checkout(cwd, flavor);
                install(cwd, PATCHED);
                write_redirect_ledger(cwd, flavor, record(OTHER_UUID));
                "redirected"
            } else {
                let rel = vendored_checkout(cwd, flavor, PATCHED);
                write_vendor_ledger(cwd, flavor, &rel, record(OTHER_UUID));
                "vendored"
            };
            let cell = format!("{flavor:?} {mode} f) ledger for another uuid");
            let (code, env) = vex_json(cwd, &["--offline"]);
            assert_omitted(cwd, code, &env, "record_unavailable", &cell);
            let skips = env["events"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|e| e["purl"] == PURL)
                .count();
            assert_eq!(skips, 1, "{cell}: one event for the purl: {env}");

            let (_rt, server) = serve_left_pad();
            let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
            assert_attested(cwd, code, &env, UUID, marker, &format!("{cell} online"));
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Pin spellings and yarn's last-block-wins parse (cell g, cell d)
// ──────────────────────────────────────────────────────────────────────

/// The lock-pin basis per spelling (not installed, API online):
///
/// * classic `integrity sha512-…` alone, or the `#<sha1>` `resolved`
///   fragment alone — yarn v1 enforces whichever is present → attests;
/// * classic with neither, berry 4 with no `checksum:` → not
///   Socket-written (both rewriters always pin), so `package_not_found`
///   until an installed tree verifies.
///
/// And yarn parses a lock into an object — a descriptor re-keyed by a
/// LATER block (a mangled merge re-adding the registry entry) shadows the
/// Socket block: nothing is discovered (exit 2), and a redirect ledger for
/// the shadowed uuid is `redirect_unwired` even with `--no-verify` (the
/// file still mentions the uuid, so it is recognized-but-rejected).
#[test]
fn pin_spellings_and_shadowed_blocks() {
    let url = classic_hosted_url("https://patch.socket.dev", UUID);
    let classic =
        |body: &str| format!("{CLASSIC_HEADER}left-pad@1.3.0:\n  version \"1.3.0\"\n{body}");
    let berry4_hosted = hosted_lock(Flavor::Berry4, "https://patch.socket.dev", UUID);
    let berry4_checksum_line = format!("  checksum: {}\n", Flavor::Berry4.berry_checksum('7'));
    assert!(berry4_hosted.contains(&berry4_checksum_line));
    let classic_registry_block = "\nleft-pad@1.3.0:\n  version \"1.3.0\"\n  resolved \
         \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e\"\n  \
         integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==\n";
    let berry_registry_block = format!(
        "\n\"left-pad@npm:1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  \
         checksum: {}\n  languageName: node\n  linkType: hard\n",
        Flavor::Berry4.berry_checksum('3')
    );

    enum Expect {
        Attest,
        NeedsInstall,
        Shadowed,
    }
    let cases: Vec<(&str, Flavor, String, Expect)> = vec![
        (
            "classic integrity only",
            Flavor::Classic,
            classic(&format!(
                "  resolved \"{url}\"\n  integrity sha512-UEFUQ0hFRHBhdGNoZWRQQVRDSEVEcGF0Y2hlZA==\n"
            )),
            Expect::Attest,
        ),
        (
            "classic sha1 fragment only",
            Flavor::Classic,
            classic(&format!(
                "  resolved \"{url}#abcdef0123456789abcdef0123456789abcdef01\"\n"
            )),
            Expect::Attest,
        ),
        (
            "classic no pin",
            Flavor::Classic,
            classic(&format!("  resolved \"{url}\"\n")),
            Expect::NeedsInstall,
        ),
        (
            "berry4 no checksum",
            Flavor::Berry4,
            berry4_hosted.replace(&berry4_checksum_line, ""),
            Expect::NeedsInstall,
        ),
        (
            "classic Socket block shadowed by a later registry block",
            Flavor::Classic,
            format!(
                "{}{classic_registry_block}",
                hosted_lock(Flavor::Classic, "https://patch.socket.dev", UUID)
            ),
            Expect::Shadowed,
        ),
        (
            "berry4 Socket block shadowed by a later registry block",
            Flavor::Berry4,
            format!("{berry4_hosted}{berry_registry_block}"),
            Expect::Shadowed,
        ),
    ];
    let (_rt, server) = serve_left_pad();
    for (name, flavor, lock, expect) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        write_project(cwd, flavor, None);
        put(cwd, "yarn.lock", lock.as_bytes());
        let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
        match expect {
            Expect::Attest => assert_attested(cwd, code, &env, UUID, "redirected", name),
            Expect::NeedsInstall => {
                assert_omitted(cwd, code, &env, "package_not_found", name);
                install(cwd, PATCHED);
                let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
                assert_attested(
                    cwd,
                    code,
                    &env,
                    UUID,
                    "redirected",
                    &format!("{name}, installed"),
                );
            }
            Expect::Shadowed => {
                assert_eq!(code, Some(2), "{name}: {env}");
                assert_eq!(env["error"]["code"], "manifest_not_found", "{name}: {env}");
                write_redirect_ledger(cwd, flavor, record(UUID));
                install(cwd, PATCHED);
                for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
                    let (code, env) = vex_json(cwd, extra);
                    assert_omitted(
                        cwd,
                        code,
                        &env,
                        "redirect_unwired",
                        &format!("{name} {extra:?}"),
                    );
                }
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Plug'n'Play (documented limitation)
// ──────────────────────────────────────────────────────────────────────

/// yarn berry's Plug'n'Play linker keeps packages inside `.yarn/cache/*.zip`
/// — socket-patch never reads those zips (`crawlers/pkg_managers.rs`), and
/// its installed-tree tooling refuses PnP projects (`apply` and `get`:
/// `yarn_pnp_unsupported`; the vendor backends:
/// `vendor_yarn_berry_unsupported`), so PnP is UNSUPPORTED. What each
/// surface does with a PnP checkout that nonetheless carries Socket lock
/// wiring (hand-made, or left behind by a linker switch):
///
/// * standalone `vex`, hosted: there is no crawlable installed tree, so the
///   ref is "not installed" and attests on the lock's integrity pin exactly
///   like a lockfile-only checkout (design D5 — yarn enforces the berry
///   `checksum:` on every fetch into the zip cache). Berry 2/3's bare-hex
///   checksum is no pin (module doc), so those are omitted
///   (`package_not_found`) — never a false attestation.
/// * standalone `vex`, vendored: the committed tarball is the evidence
///   whatever the linker; PnP consumes the same `file:` artifact.
/// * `apply --vex`: apply refuses a PnP layout outright, manifest or not
///   (`yarn_pnp_unsupported`, exit 1, no document).
#[test]
fn pnp_layout_contract() {
    for flavor in [Flavor::Berry2, Flavor::Berry3, Flavor::Berry4] {
        for mode in ["hosted", "vendored"] {
            let tmp = tempfile::tempdir().unwrap();
            let cwd = tmp.path();
            if mode == "hosted" {
                hosted_checkout(cwd, flavor);
            } else {
                vendored_checkout(cwd, flavor, PATCHED);
            }
            put(
                cwd,
                ".yarnrc.yml",
                b"nodeLinker: pnp\nenableGlobalCache: false\n",
            );
            put(cwd, ".pnp.cjs", b"/* yarn PnP loader */\n");
            assert!(!cwd.join("node_modules").exists());
            let (_rt, server) = serve_left_pad();
            let (code, env) = vex_json(cwd, &["--proxy-url", &server.uri()]);
            let cell = format!("{flavor:?} {mode} PnP vex");
            if mode == "vendored" {
                assert_attested(cwd, code, &env, UUID, "vendored", &cell);
            } else if flavor.hosted_pin_is_read() {
                assert_attested(cwd, code, &env, UUID, "redirected", &cell);
            } else {
                assert_omitted(cwd, code, &env, "package_not_found", &cell);
            }

            let vex_out = cwd.join("apply.vex.json");
            let out = cli()
                .args([
                    "apply",
                    "--cwd",
                    cwd.to_str().unwrap(),
                    "--json",
                    "--vex",
                    vex_out.to_str().unwrap(),
                    "--vex-product",
                    PRODUCT,
                    "--proxy-url",
                    &server.uri(),
                ])
                .output()
                .unwrap();
            let env = envelope(&out);
            let cell = format!("{flavor:?} {mode} PnP apply --vex");
            assert_eq!(out.status.code(), Some(1), "{cell}: {env}");
            assert_eq!(
                env["error"]["code"], "yarn_pnp_unsupported",
                "{cell}: {env}"
            );
            assert!(!vex_out.exists(), "{cell}: no document");
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// EMBEDDED — scan --vex / scan --redirect --vex / scan --vendor --vex /
// apply --vex, manifest-less
// ──────────────────────────────────────────────────────────────────────

/// Run `args` (a `scan` / `apply` invocation writing `--vex <cwd>/embed.vex.json`)
/// and return (exit, envelope, parsed document if written).
fn embedded(cwd: &Path, args: &[&str]) -> (Option<i32>, Value, Option<Value>) {
    let vex_out = cwd.join("embed.vex.json");
    let _ = std::fs::remove_file(&vex_out);
    let mut full: Vec<&str> = args.to_vec();
    full.extend([
        "--cwd",
        cwd.to_str().unwrap(),
        "--json",
        "--vex",
        vex_out.to_str().unwrap(),
        "--vex-product",
        PRODUCT,
    ]);
    let out = cli().args(&full).output().expect("invoke embedded vex");
    let env = envelope(&out);
    let doc = std::fs::read(&vex_out)
        .ok()
        .map(|b| serde_json::from_slice(&b).unwrap());
    (out.status.code(), env, doc)
}

fn assert_embedded_attested(doc: Option<Value>, env: &Value, marker: &str, cell: &str) {
    assert_eq!(env["vex"]["statements"], 1, "{cell}: {env}");
    let doc = doc.unwrap_or_else(|| panic!("{cell}: no document: {env}"));
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "{cell}: {doc}");
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA, "{cell}");
    assert_eq!(stmts[0]["vulnerability"]["aliases"][0], CVE, "{cell}");
    assert_eq!(
        stmts[0]["products"][0]["subcomponents"][0]["@id"], PURL,
        "{cell}"
    );
    assert_eq!(
        stmts[0]["impact_statement"],
        format!("Patched via Socket patch {UUID} ({marker})"),
        "{cell}"
    );
}

/// The in-run VEX of `scan` (agent mode, `--redirect`, `--vendor`) on an
/// already-wired, manifest-less checkout attests the lock's patch like the
/// standalone command, never rewrites the wiring, never writes a manifest,
/// and still refuses a tampered installed tree.
#[test]
fn embedded_scan_vex_attests_manifest_less_wiring() {
    for flavor in [Flavor::Classic, Flavor::Berry4] {
        for mode in ["hosted", "vendored"] {
            for scan_mode in [None, Some("--redirect"), Some("--vendor")] {
                let tmp = tempfile::tempdir().unwrap();
                let cwd = tmp.path();
                if mode == "hosted" {
                    hosted_checkout(cwd, flavor);
                } else {
                    vendored_checkout(cwd, flavor, PATCHED);
                }
                let lock_before = std::fs::read(cwd.join("yarn.lock")).unwrap();
                // Every scan route (batch search, by-package, view) is
                // served by one stand-in; only the view has a body.
                let (_rt, server) = serve_left_pad();
                let uri = server.uri();
                let mut args = vec![
                    "scan",
                    "--proxy-url",
                    uri.as_str(),
                    "--api-url",
                    uri.as_str(),
                ];
                args.extend(scan_mode);
                let cell = format!("{flavor:?} {mode} scan {scan_mode:?} --vex");
                let (code, env, doc) = embedded(cwd, &args);
                assert_eq!(code, Some(0), "{cell}: {env}");
                assert_embedded_attested(
                    doc,
                    &env,
                    if mode == "hosted" {
                        "redirected"
                    } else {
                        "vendored"
                    },
                    &cell,
                );
                assert_eq!(
                    std::fs::read(cwd.join("yarn.lock")).unwrap(),
                    lock_before,
                    "{cell}: the wiring is left untouched"
                );
                assert!(!cwd.join(".socket/manifest.json").exists(), "{cell}");

                if mode == "hosted" {
                    // The installed evidence wins in the embedded path too.
                    install(cwd, b"tampered bytes\n");
                    let (code, env, doc) = embedded(cwd, &args);
                    let cell = format!("{cell} tampered install");
                    assert_ne!(code, Some(0), "{cell}: {env}");
                    assert_eq!(
                        env["error"]["code"], "no_applicable_patches",
                        "{cell}: {env}"
                    );
                    assert!(doc.is_none(), "{cell}: no document");
                }
            }
        }
    }
}

/// `apply --vex` with no manifest: REGRESSION — the no-manifest early
/// return dropped a requested `--vex` (exit 0, no document) even though the
/// lockfile wires a patch standalone `vex` attests. Now: the document is
/// written (envelope `status: noManifest` + `vex` summary); a wired patch
/// that fails verification fails the command; and a project with nothing
/// to attest anywhere keeps the calm `noManifest` exit 0.
#[test]
fn embedded_apply_vex_attests_manifest_less_wiring() {
    for flavor in FLAVORS {
        for mode in ["hosted", "vendored"] {
            let tmp = tempfile::tempdir().unwrap();
            let cwd = tmp.path();
            if mode == "hosted" {
                hosted_checkout(cwd, flavor);
                install(cwd, PATCHED);
            } else {
                vendored_checkout(cwd, flavor, PATCHED);
            }
            let (_rt, server) = serve_left_pad();
            let uri = server.uri();
            let cell = format!("{flavor:?} {mode} apply --vex");
            let (code, env, doc) = embedded(cwd, &["apply", "--proxy-url", uri.as_str()]);
            assert_eq!(code, Some(0), "{cell}: {env}");
            assert_eq!(env["status"], "noManifest", "{cell}: {env}");
            assert_embedded_attested(
                doc,
                &env,
                if mode == "hosted" {
                    "redirected"
                } else {
                    "vendored"
                },
                &cell,
            );

            // Failing verification fails the command and leaves no document.
            if mode == "hosted" {
                install(cwd, b"tampered bytes\n");
            } else {
                write_member_tgz(&cwd.join(vendored_rel(UUID)), MEMBER, b"tampered\n");
            }
            let (code, env, doc) = embedded(cwd, &["apply", "--proxy-url", uri.as_str()]);
            let cell = format!("{cell} tampered");
            assert_eq!(code, Some(1), "{cell}: {env}");
            assert_eq!(
                env["error"]["code"], "no_applicable_patches",
                "{cell}: {env}"
            );
            assert!(doc.is_none(), "{cell}: no document");
        }
    }

    // Nothing wired anywhere: the calm no-manifest exit is unchanged.
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_project(cwd, Flavor::Berry4, None);
    put(cwd, "yarn.lock", registry_lock(Flavor::Berry4).as_bytes());
    let (code, env, doc) = embedded(cwd, &["apply", "--offline"]);
    assert_eq!(code, Some(0), "{env}");
    assert_eq!(env["status"], "noManifest", "{env}");
    assert!(env.get("vex").is_none(), "{env}");
    assert!(doc.is_none());
}
