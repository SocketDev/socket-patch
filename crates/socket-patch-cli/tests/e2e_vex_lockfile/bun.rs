//! Manifest-less VEX for Bun — the hermetic test matrix.
//!
//! `socket-patch vex` must attest a HOSTED patch (the lock resolves the
//! dependency from Socket's patch server) and a VENDORED patch (the lock
//! resolves it from a committed `.socket/vendor/npm/<uuid>/…` tarball) from
//! the project's Bun lockfile alone — no `.socket/manifest.json`, and no
//! `.socket/vendor/state.json` / `redirect-state.json` ledgers either — and
//! must never attest a patch the build does not consume.
//!
//! Flavors ([`FLAVORS`]): the text `bun.lock` in every grammar era Bun has
//! shipped (lockfileVersion 0 = the 1.1.39–1.1.45 opt-in, 1 = 1.2–1.3,
//! 2 = 1.4+; the templates are byte-for-byte what bun 1.1.45 / 1.2.23 /
//! 1.4.2 write for the fixture project) and the binary `bun.lockb` (the
//! committed real-Bun fixtures, rewired by the production binary rewriter —
//! [`rewrite_bun_binary`] — exactly as `scan --mode hosted|vendored` does).
//!
//! Cells, per flavor × {hosted, vendored}:
//!
//! * a) no manifest, no ledgers, online (a wiremock patch API) → attested
//!   with the right subcomponent purl, vulnerability id + CVE alias and
//!   `(redirected)` / `(vendored)` marker; exit 0; `verified` events.
//! * b) `--offline` with no local record → `record_unavailable`, exit 1,
//!   and the mock records ZERO requests.
//! * c) ledger present, manifest absent → attests offline from the ledger's
//!   embedded record (ledgers written by the REAL CLI: `scan --mode hosted`
//!   / `scan --mode vendored`, whose embedded `--vex` is asserted too).
//! * d) lock reverted to the registry while ledger + artifact remain →
//!   `redirect_unwired` / `vendor_unwired`, including under `--no-verify`.
//! * e) tampered installed tree (hosted) / tampered artifact member
//!   (vendored) → `hash_mismatch` / `vendor_hash_mismatch`.
//! * f) spoofs: a uuid on a non-Socket host (and look-alike hosts), a
//!   uuid-shaped vendor path outside `.socket/vendor`, and a patch record
//!   whose purl or uuid disagrees with the lock → never attested
//!   (`record_mismatch` for the latter).
//! * g) hosted, not installed → attests from the lock's sha512 pin (design
//!   D5); installed + patched → attests after hashing; installed pristine →
//!   `not_applied`; every installed copy must verify.
//!
//! Plus the Bun-specific edges: a stale `bun.lockb` beside a `bun.lock` is
//! debris bun never reads (it neither attests nor keeps a ledger alive), a
//! digest-less hosted 2-tuple (bun < 1.3.10 re-save) needs an installed tree,
//! aliased and scoped entries, a truncated binary lock, and `apply --vex`.
//!
//! The real-Bun capstones (a fresh `bun install` of the wired lock, then
//! standalone `vex` with the manifest and ledgers deleted) live in
//! `e2e_redirect_bun_build.rs` / `e2e_vendor_bun_build.rs` /
//! `e2e_bun_lockb.rs`, gated on a `bun` toolchain; this suite needs none.

use crate::vex_e2e_common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
use socket_patch_core::patch::redirect::{
    rewrite_bun_binary, DepOverride, Integrity, RedirectState, RewriteResult,
};
use vex_e2e_common::{assert_omitted_parts, read_doc};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const NAME: &str = "minimist";
const VERSION: &str = "1.2.2";
const PURL: &str = "pkg:npm/minimist@1.2.2";
const PRODUCT: &str = "pkg:npm/app@1.0.0";
const ORG: &str = "bun-vex-org";
const UUID: &str = "3b1f7c2a-8d4e-4f6a-9b0c-1d2e3f4a5b6c";
/// A second, unrelated patch uuid (spoofs and stale-ledger cells).
const OTHER_UUID: &str = "4c2a8d3b-9e5f-4a7b-8c1d-2e3f4a5b6c7d";
/// A uuid-SHAPED grant token: the patch uuid is the LAST uuid segment.
const TOKEN: &str = "11111111-2222-4333-8444-555555555555";
const GHSA: &str = "GHSA-bunv-lock-0001";
const CVE: &str = "CVE-2026-5150";
const PRISTINE: &[u8] = b"module.exports = function minimist(args) { return args; };\n";
const PATCHED: &[u8] =
    b"/* SOCKET-PATCHED */\nmodule.exports = function minimist(args) { return args; };\n";
const TAMPERED: &[u8] = b"/* NOT THE PATCH */\nmodule.exports = function () {};\n";
/// The registry pins bun wrote for the fixture project.
const MINIMIST_REGISTRY_SRI: &str = "sha512-rIqbOrKb8GJmx/5bc2M0QchhUouMXSpd1RTclXsB41JdL+VtnojfaJR+h7F9k18/4kHUsBFgk80Uk+q569vjPA==";
const IS_NUMBER_REGISTRY_SRI: &str = "sha512-41Cifkg6e8TylSpdtTpeLVMqvSBEVzTttHvERD741+pnZ8ANv0004MRL43QKPDlK9cGvNp6NZWZUBlbGXYxxng==";

// ── flavors ──────────────────────────────────────────────────────────────

/// One Bun lock format.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Flavor {
    /// `bun.lock` with this `lockfileVersion`.
    Text(u32),
    /// `bun.lockb` from the committed fixture written by this Bun release.
    Binary(&'static str),
}

/// The matrix every cell runs over: all three text grammars, the current
/// binary format and the oldest binary era with URL-bearing resolutions
/// the CI bun legs pin (1.1.45 is also the last v0 text writer).
const FLAVORS: [Flavor; 5] = [
    Flavor::Text(0),
    Flavor::Text(1),
    Flavor::Text(2),
    Flavor::Binary("1.1.45"),
    Flavor::Binary("1.4.2"),
];

impl Flavor {
    fn lock_file(self) -> &'static str {
        match self {
            Flavor::Text(_) => "bun.lock",
            Flavor::Binary(_) => "bun.lockb",
        }
    }
}

/// How the lock resolves minimist.
#[derive(Clone, Debug)]
enum Wiring {
    /// bun's own registry 4-tuple / record — no patch.
    Registry,
    /// Resolved from `url` (a hosted artifact url), pinned with `sri`
    /// unless `None` (the digest-less 2-tuple bun < 1.3.10 re-saves).
    Hosted { url: String, sri: Option<String> },
    /// Resolved from the committed tarball at `rel`, pinned with `sri`.
    Vendored { rel: String, sri: String },
}

fn fixture_dir(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../socket-patch-core/tests/fixtures")
        .join(rel)
}

/// The committed real-Bun binary lock of `release` (minimist@1.2.2 +
/// is-number@7.0.0, the same project as the text templates).
fn binary_fixture(release: &str) -> Vec<u8> {
    std::fs::read(fixture_dir(&format!("bun-lockb/{release}/bun.lockb")))
        .unwrap_or_else(|e| panic!("bun-lockb/{release} fixture: {e}"))
}

/// Every committed binary fixture that locks the direct-dependency project.
fn all_binary_releases() -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(fixture_dir("bun-lockb"))
        .expect("bun-lockb fixture dir")
        .filter_map(|e| {
            let dir = e.expect("fixture entry").path();
            let pkg = std::fs::read_to_string(dir.join("package.json")).ok()?;
            let pkg: Value = serde_json::from_str(&pkg).ok()?;
            (dir.join("bun.lockb").is_file()
                && pkg["dependencies"]["minimist"] == VERSION
                && pkg.get("workspaces").is_none())
            .then(|| dir.file_name().unwrap().to_string_lossy().into_owned())
        })
        .collect();
    out.sort();
    assert!(out.len() >= 10, "binary fixtures: {out:?}");
    out
}

/// A text `bun.lock` for the fixture project in lockfileVersion `version`'s
/// exact emitted grammar, with `minimist_tuple` as minimist's entry (and
/// `key` as its map key — the alias for an aliased install).
fn text_lock(version: u32, key: &str, minimist_tuple: &str) -> String {
    let config = if version >= 2 {
        "  \"configVersion\": 1,\n"
    } else {
        ""
    };
    let dep = if key == NAME {
        format!("\"{NAME}\": \"{VERSION}\"")
    } else {
        format!("\"{key}\": \"npm:{NAME}@{VERSION}\"")
    };
    format!(
        "{{\n  \"lockfileVersion\": {version},\n{config}  \"workspaces\": {{\n    \"\": {{\n      \
         \"name\": \"app\",\n      \"dependencies\": {{\n        \"is-number\": \"7.0.0\",\n        \
         {dep},\n      }},\n    }},\n  }},\n  \"packages\": {{\n    \"is-number\": \
         [\"is-number@7.0.0\", \"\", {{}}, \"{IS_NUMBER_REGISTRY_SRI}\"],\n\n    \"{key}\": \
         {minimist_tuple},\n  }}\n}}\n"
    )
}

fn text_tuple(wiring: &Wiring) -> String {
    match wiring {
        Wiring::Registry => {
            format!("[\"{NAME}@{VERSION}\", \"\", {{}}, \"{MINIMIST_REGISTRY_SRI}\"]")
        }
        Wiring::Hosted {
            url,
            sri: Some(sri),
        } => format!("[\"{NAME}@{url}\", {{}}, \"{sri}\"]"),
        Wiring::Hosted { url, sri: None } => format!("[\"{NAME}@{url}\", {{}}]"),
        Wiring::Vendored { rel, sri } => format!("[\"{NAME}@{rel}\", {{}}, \"{sri}\"]"),
    }
}

/// `bun.lockb` for `release`, rewired by the production binary rewriter.
fn binary_lock(release: &str, wiring: &Wiring) -> Vec<u8> {
    let fixture = binary_fixture(release);
    let (artifact_url, sri, uuid) = match wiring {
        Wiring::Registry => return fixture,
        Wiring::Hosted { url, sri } => (
            url.clone(),
            sri.clone()
                .expect("the binary rewriter always pins a sha512"),
            url_uuid(url),
        ),
        Wiring::Vendored { rel, sri } => (rel.clone(), sri.clone(), url_uuid(rel)),
    };
    let dep = DepOverride {
        ecosystem: "npm".into(),
        name: NAME.into(),
        namespace: None,
        version: VERSION.into(),
        token: TOKEN.into(),
        patch_uuid: uuid,
        artifact_url,
        berry_zip_url: None,
        registry_override: None,
        integrity: Integrity {
            sha512: Some(sri),
            ..Default::default()
        },
    };
    let mut result = RewriteResult::default();
    rewrite_bun_binary(&fixture, &[dep], &mut result);
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    result
        .binary_files
        .remove("bun.lockb")
        .expect("the binary rewriter changed the lock")
}

/// The second-to-last path segment (the uuid dir of both url shapes).
fn url_uuid(url: &str) -> String {
    let mut segs = url.rsplit('/');
    segs.next();
    segs.next().unwrap_or_default().to_string()
}

/// Write the project's lock for `flavor` with minimist resolved per
/// `wiring` (removing the other lock format so exactly one is read).
fn write_lock(cwd: &Path, flavor: Flavor, wiring: &Wiring) {
    write_lock_keyed(cwd, flavor, NAME, wiring);
}

fn write_lock_keyed(cwd: &Path, flavor: Flavor, key: &str, wiring: &Wiring) {
    let _ = std::fs::remove_file(cwd.join("bun.lock"));
    let _ = std::fs::remove_file(cwd.join("bun.lockb"));
    match flavor {
        Flavor::Text(v) => {
            std::fs::write(cwd.join("bun.lock"), text_lock(v, key, &text_tuple(wiring))).unwrap()
        }
        Flavor::Binary(release) => {
            assert_eq!(key, NAME, "binary cells use the fixture's own key");
            std::fs::write(cwd.join("bun.lockb"), binary_lock(release, wiring)).unwrap()
        }
    }
}

// ── artifacts, installs, records ─────────────────────────────────────────

fn git(bytes: &[u8]) -> String {
    compute_git_sha256_from_bytes(bytes)
}

fn sri(bytes: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

/// An npm tarball of minimist whose `index.js` is `index`.
fn tgz(index: &[u8]) -> Vec<u8> {
    let manifest = format!(r#"{{"name":"{NAME}","version":"{VERSION}","main":"index.js"}}"#);
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::new(6),
    ));
    for (member, bytes) in [
        ("package/package.json", manifest.as_bytes()),
        ("package/index.js", index),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        builder.append_data(&mut header, member, bytes).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

fn vendored_rel(uuid: &str) -> String {
    format!(".socket/vendor/npm/{uuid}/{NAME}-{VERSION}.tgz")
}

/// Commit the vendored tarball (index.js = `index`) for `uuid`; returns the
/// wiring that resolves it, pinned to the tarball's sha512.
fn commit_artifact(cwd: &Path, uuid: &str, index: &[u8]) -> Wiring {
    let rel = vendored_rel(uuid);
    let bytes = tgz(index);
    let dest = cwd.join(&rel);
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    std::fs::write(&dest, &bytes).unwrap();
    Wiring::Vendored {
        rel,
        sri: sri(&bytes),
    }
}

/// Production hosted artifact url for minimist's patch `uuid`.
fn socket_url(uuid: &str) -> String {
    hosted_url_on("https://patch.socket.dev", uuid)
}

fn hosted_url_on(origin: &str, uuid: &str) -> String {
    format!("{origin}/patch/npm/{NAME}/{VERSION}/{TOKEN}/{uuid}/{NAME}-{VERSION}.tgz")
}

/// Hosted wiring on the production host, pinned to the patched tarball.
fn hosted(uuid: &str) -> Wiring {
    Wiring::Hosted {
        url: socket_url(uuid),
        sri: Some(sri(&tgz(PATCHED))),
    }
}

/// The root manifest bun installs from (always present in a checkout).
fn package_json(cwd: &Path) {
    std::fs::write(
        cwd.join("package.json"),
        format!(
            r#"{{"name":"app","version":"1.0.0","dependencies":{{"{NAME}":"{VERSION}","is-number":"7.0.0"}}}}"#
        ),
    )
    .unwrap();
}

/// A fresh checkout: package.json only.
fn project() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    package_json(tmp.path());
    tmp
}

/// Lay down an installed minimist at `node_modules/<dir>` (bun's hoisted
/// layout) whose `index.js` is `index`.
fn install_at(cwd: &Path, dir: &str, index: &[u8]) {
    let pkg = cwd.join("node_modules").join(dir);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{"name":"{NAME}","version":"{VERSION}","main":"index.js"}}"#),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), index).unwrap();
}

fn install(cwd: &Path, index: &[u8]) {
    install_at(cwd, NAME, index);
}

/// The patch view (`record_from_patch_response`'s input) for `uuid`
/// claiming `purl`, with the blob so `scan --mode vendored` can build.
fn view(uuid: &str, purl: &str) -> Value {
    json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "Fri, 27 Mar 2026 00:00:00 GMT",
        "files": { "package/index.js": {
            "beforeHash": git(PRISTINE),
            "afterHash": git(PATCHED),
            "blobContent": base64::engine::general_purpose::STANDARD.encode(PATCHED),
        } },
        "vulnerabilities": { GHSA: {
            "cves": [CVE], "summary": "prototype pollution", "severity": "high",
            "description": "d"
        } },
        "description": "bun lockfile vex patch",
        "license": "MIT",
        "tier": "free",
    })
}

// ── the mock patch API ───────────────────────────────────────────────────

/// A wiremock patch API on its own runtime (kept alive for the CLI runs).
struct Api {
    rt: tokio::runtime::Runtime,
    server: MockServer,
}

impl Api {
    fn start() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(MockServer::start());
        Api { rt, server }
    }

    fn uri(&self) -> String {
        self.server.uri()
    }

    fn mount(&self, mock: Mock) {
        self.rt.block_on(mock.mount(&self.server));
    }

    /// Serve `body` as the patch view of `uuid` on both routes a record
    /// fetch can take (public proxy and the authenticated org route).
    fn serve_view(&self, uuid: &str, body: Value) {
        self.mount(
            Mock::given(method("GET"))
                .and(path(format!("/patch/view/{uuid}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(body.clone())),
        );
        self.mount(
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(body)),
        );
    }

    /// Everything `scan --mode hosted|vendored` needs for the minimist
    /// patch: search, grant (hosted url on THIS server) and the tarball.
    fn serve_scan(&self, hosted_tgz: Vec<u8>) {
        let url = hosted_url_on(&self.uri(), UUID);
        self.mount(
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "packages": [{ "purl": PURL, "patches": [{
                        "uuid": UUID, "purl": PURL, "tier": "free", "cveIds": [CVE],
                        "ghsaIds": [GHSA], "severity": "high", "title": "bun vex patch"
                    }] }],
                    "canAccessPaidPatches": false,
                }))),
        );
        self.mount(
            Mock::given(method("GET"))
                .and(path_regex(format!(
                    "^/v0/orgs/{ORG}/patches/by-package/.+$"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "patches": [{
                        "uuid": UUID, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
                        "description": "bun vex patch", "license": "MIT", "tier": "free",
                        "vulnerabilities": {}
                    }],
                    "canAccessPaidPatches": false,
                }))),
        );
        self.mount(
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/package")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "results": { UUID: {
                        "status": "granted", "url": url, "purl": PURL,
                        "artifacts": [{ "kind": "tarball", "url": url,
                            "integrity": { "sha512": sri(&hosted_tgz) } }],
                        "registryOverride": null
                    } }
                }))),
        );
        self.mount(
            Mock::given(method("GET"))
                .and(path_regex(format!("^/patch/npm/{NAME}/.*$")))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(hosted_tgz, "application/octet-stream"),
                ),
        );
        self.serve_view(UUID, view(UUID, PURL));
    }

    fn requests(&self) -> usize {
        self.rt
            .block_on(self.server.received_requests())
            .map(|r| r.len())
            .unwrap_or(0)
    }
}

// ── running the CLI ──────────────────────────────────────────────────────

/// The CLI with the ambient `SOCKET_*` environment scrubbed, telemetry and
/// socket-cli config off, and no ambient API token.
fn cli() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("SOCKET_NO_UPDATE_CHECK", "1");
    cmd
}

/// Parsed stdout envelope of a `--json` run.
fn envelope(out: &std::process::Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "envelope JSON on stdout ({e}). stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// Standalone `vex --json --output out.vex.json` (unauthenticated) in
/// `cwd`; returns (exit, envelope).
fn vex(cwd: &Path, extra: &[&str]) -> (Option<i32>, Value) {
    let out_path = cwd.join("out.vex.json");
    let _ = std::fs::remove_file(&out_path);
    let out = cli()
        .env("SOCKET_NO_API_TOKEN", "1")
        .args(["vex", "--cwd"])
        .arg(cwd)
        .args(["--json", "--output"])
        .arg(&out_path)
        .args(["--product", PRODUCT])
        .args(extra)
        .output()
        .expect("invoke vex");
    (out.status.code(), envelope(&out))
}

/// `vex` online against `api` (its public view route).
fn vex_online(cwd: &Path, api: &Api, extra: &[&str]) -> (Option<i32>, Value) {
    let uri = api.uri();
    let mut args = vec!["--proxy-url", uri.as_str()];
    args.extend_from_slice(extra);
    vex(cwd, &args)
}

/// Authenticated `socket-patch <args> --json --cwd <cwd>` against `api`.
fn socket_json(cwd: &Path, api: &Api, args: &[&str]) -> (Option<i32>, Value) {
    let uri = api.uri();
    // `--vex <relative path>` resolves against the process cwd.
    let out = cli()
        .current_dir(cwd)
        .args(args)
        .args(["--json", "--cwd"])
        .arg(cwd)
        .args(["--api-url", &uri, "--api-token", "fake", "--org", ORG])
        .output()
        .expect("invoke socket-patch");
    (out.status.code(), envelope(&out))
}

fn doc(cwd: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(cwd.join("out.vex.json")).expect("vex document"))
        .expect("vex document JSON")
}

fn marker(mode: &str) -> &'static str {
    match mode {
        "hosted" => "redirected",
        "vendored" => "vendored",
        other => panic!("mode {other}"),
    }
}

/// Exit 0 with exactly one statement: minimist's GHSA (CVE alias) under
/// `uuid` with `mode`'s provenance marker, plus the envelope's verified
/// event — and the run never wrote a manifest.
fn assert_attested(cwd: &Path, code: Option<i32>, env: &Value, uuid: &str, mode: &str, what: &str) {
    assert_eq!(code, Some(0), "{what}: {env}");
    let doc = doc(cwd);
    let stmts = doc["statements"].as_array().expect("statements");
    assert_eq!(stmts.len(), 1, "{what}: {doc}");
    let st = &stmts[0];
    assert_eq!(st["status"], "not_affected", "{what}: {doc}");
    assert_eq!(st["vulnerability"]["name"], GHSA, "{what}: {doc}");
    assert_eq!(
        st["vulnerability"]["aliases"],
        json!([CVE]),
        "{what}: {doc}"
    );
    assert_eq!(st["products"][0]["@id"], PRODUCT, "{what}: {doc}");
    assert_eq!(
        st["products"][0]["subcomponents"],
        json!([{ "@id": PURL }]),
        "{what}: {doc}"
    );
    assert_eq!(
        st["impact_statement"],
        format!("Patched via Socket patch {uuid} ({})", marker(mode)),
        "{what}: {doc}"
    );
    let verified: Vec<&Value> = env["events"]
        .as_array()
        .expect("events")
        .iter()
        .filter(|e| e["action"] == "verified")
        .collect();
    assert_eq!(verified.len(), 1, "{what}: {env}");
    assert_eq!(verified[0]["purl"], PURL, "{what}: {env}");
    assert_eq!(
        verified[0]["details"]["vulnerability"], GHSA,
        "{what}: {env}"
    );
    assert_eq!(
        verified[0]["details"]["aliases"],
        json!([CVE]),
        "{what}: {env}"
    );
    assert!(
        !cwd.join(".socket/manifest.json").exists(),
        "{what}: vex never writes the manifest"
    );
}

/// Exit 1 `no_applicable_patches`, no document, and minimist skipped with
/// `reason`.
fn assert_omitted(cwd: &Path, code: Option<i32>, env: &Value, reason: &str, what: &str) {
    let doc = read_doc(&cwd.join("out.vex.json"));
    assert_omitted_parts(code, env, doc.as_ref(), PURL, reason, what);
}

/// Exit 2 `manifest_not_found`: nothing was discovered at all.
fn assert_nothing_found(code: Option<i32>, env: &Value, what: &str) {
    assert_eq!(code, Some(2), "{what}: {env}");
    assert_eq!(env["error"]["code"], "manifest_not_found", "{what}: {env}");
}

fn modes() -> [&'static str; 2] {
    ["hosted", "vendored"]
}

/// Wire `uuid`'s patch for `mode` in `cwd` as a lockfile-only checkout:
/// hosted on the production host (pinned, nothing installed); vendored to
/// a committed tarball carrying the patched bytes.
fn wire(cwd: &Path, flavor: Flavor, mode: &str, uuid: &str) {
    let wiring = match mode {
        "hosted" => hosted(uuid),
        _ => commit_artifact(cwd, uuid, PATCHED),
    };
    write_lock(cwd, flavor, &wiring);
}

// ──────────────────────────────────────────────────────────────────────
// a) + b): lockfile only — online attests, offline is record_unavailable
// with no network traffic at all.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn a_b_lockfile_only_attests_online_and_is_record_unavailable_offline() {
    for flavor in FLAVORS {
        for mode in modes() {
            let what = format!("{flavor:?} {mode}");
            let tmp = project();
            let cwd = tmp.path();
            wire(cwd, flavor, mode, UUID);
            assert!(!cwd.join(".socket/manifest.json").exists());
            assert!(!cwd.join(".socket/vendor/state.json").exists());
            assert!(!cwd.join(".socket/vendor/redirect-state.json").exists());
            let api = Api::start();
            api.serve_view(UUID, view(UUID, PURL));

            // b) --offline: the wiring is found, no record exists locally,
            // and the API — even when configured — is never contacted.
            let uri = api.uri();
            let (code, env) = vex(cwd, &["--offline", "--proxy-url", &uri, "--api-url", &uri]);
            assert_omitted(cwd, code, &env, "record_unavailable", &what);
            assert_eq!(api.requests(), 0, "{what}: --offline made a network call");

            // a) online: the record comes from the API.
            let (code, env) = vex_online(cwd, &api, &[]);
            assert_attested(cwd, code, &env, UUID, mode, &what);
            assert!(api.requests() >= 1, "{what}");
        }
    }
}

/// a) across EVERY committed binary-lock era (0.1.x … 1.4.2): the binary
/// rewriter's hosted and vendored wiring both attest manifest-less.
#[test]
fn a_every_binary_lock_release_attests_both_modes() {
    let api = Api::start();
    api.serve_view(UUID, view(UUID, PURL));
    for release in all_binary_releases() {
        let release: &'static str = Box::leak(release.into_boxed_str());
        for mode in modes() {
            let what = format!("bun.lockb {release} {mode}");
            let tmp = project();
            let cwd = tmp.path();
            wire(cwd, Flavor::Binary(release), mode, UUID);
            let (code, env) = vex_online(cwd, &api, &[]);
            assert_attested(cwd, code, &env, UUID, mode, &what);
        }
    }
}

/// b) the API answering 404 / 403 is `record_unavailable` too — never an
/// abort, never an attestation.
#[test]
fn b_api_without_the_record_is_record_unavailable() {
    for status in [404u16, 403] {
        for mode in modes() {
            let what = format!("{status} {mode}");
            let tmp = project();
            let cwd = tmp.path();
            wire(cwd, Flavor::Text(1), mode, UUID);
            let api = Api::start();
            api.mount(
                Mock::given(method("GET"))
                    .and(path_regex(".*/view/.*"))
                    .respond_with(ResponseTemplate::new(status)),
            );
            let (code, env) = vex_online(cwd, &api, &[]);
            assert_omitted(cwd, code, &env, "record_unavailable", &what);
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// c) + d) + embedded: the ledgers written by the REAL CLI.
// ──────────────────────────────────────────────────────────────────────

/// `scan --mode hosted --vex` on a lock-only checkout (nothing installed):
/// the real engine rewires the lock to the mock server's hosted url, and
/// the in-run VEX attests `(redirected)`. Returns the pre-scan lock bytes.
fn scan_hosted(cwd: &Path, flavor: Flavor, api: &Api) -> Vec<u8> {
    write_lock(cwd, flavor, &Wiring::Registry);
    let registry_lock = std::fs::read(cwd.join(flavor.lock_file())).unwrap();
    api.serve_scan(tgz(PATCHED));
    let (code, env) = socket_json(
        cwd,
        api,
        &[
            "scan",
            "--mode",
            "hosted",
            "--yes",
            "--vex",
            "out.vex.json",
            "--vex-product",
            PRODUCT,
        ],
    );
    let what = format!("{flavor:?} scan --mode hosted --vex");
    assert_eq!(code, Some(0), "{what}: {env}");
    assert_eq!(env["redirect"]["redirected"], 1, "{what}: {env}");
    assert_eq!(env["vex"]["statements"], 1, "{what}: {env}");
    let stmt = &doc(cwd)["statements"][0];
    assert_eq!(stmt["vulnerability"]["name"], GHSA, "{what}");
    assert_eq!(
        stmt["impact_statement"],
        format!("Patched via Socket patch {UUID} (redirected)"),
        "{what}"
    );
    assert_ne!(
        std::fs::read(cwd.join(flavor.lock_file())).unwrap(),
        registry_lock,
        "{what}: the lock must be rewired"
    );
    assert!(
        cwd.join(".socket/vendor/redirect-state.json").is_file(),
        "{what}"
    );
    assert!(!cwd.join(".socket/manifest.json").exists(), "{what}");
    registry_lock
}

/// `scan --mode vendored --vendor-source build --vex` against an installed
/// pristine minimist: the real engine builds + commits the tarball, rewires
/// the lock, and the in-run VEX attests `(vendored)`. Vendored mode is
/// manifest-free, so neither spelling writes a manifest (`--detached` is a
/// hidden compatibility no-op). Returns the pre-scan lock bytes.
fn scan_vendored(cwd: &Path, flavor: Flavor, api: &Api, detached: bool) -> Vec<u8> {
    write_lock(cwd, flavor, &Wiring::Registry);
    install(cwd, PRISTINE);
    let registry_lock = std::fs::read(cwd.join(flavor.lock_file())).unwrap();
    api.serve_scan(tgz(PATCHED));
    let mut args = vec![
        "scan",
        "--mode",
        "vendored",
        "--vendor-source",
        "build",
        "--yes",
        "--vex",
        "out.vex.json",
        "--vex-product",
        PRODUCT,
    ];
    if detached {
        args.push("--detached");
    }
    let (code, env) = socket_json(cwd, api, &args);
    let what = format!("{flavor:?} scan --mode vendored detached={detached} --vex");
    assert_eq!(code, Some(0), "{what}: {env}");
    assert_eq!(env["vendor"]["summary"]["applied"], 1, "{what}: {env}");
    assert_eq!(env["vex"]["statements"], 1, "{what}: {env}");
    let stmt = &doc(cwd)["statements"][0];
    assert_eq!(
        stmt["impact_statement"],
        format!("Patched via Socket patch {UUID} (vendored)"),
        "{what}"
    );
    assert!(cwd.join(vendored_rel(UUID)).is_file(), "{what}");
    assert!(cwd.join(".socket/vendor/state.json").is_file(), "{what}");
    assert!(
        !cwd.join(".socket/manifest.json").exists(),
        "{what}: vendored mode never writes a manifest"
    );
    registry_lock
}

/// Remove the manifest + blobs (and the install) so only the lock, the
/// ledger and — vendored — the committed artifact remain.
fn drop_manifest_and_install(cwd: &Path) {
    let _ = std::fs::remove_file(cwd.join(".socket/manifest.json"));
    let _ = std::fs::remove_dir_all(cwd.join(".socket/blobs"));
    let _ = std::fs::remove_dir_all(cwd.join("node_modules"));
}

fn drop_ledgers(cwd: &Path) {
    let _ = std::fs::remove_file(cwd.join(".socket/vendor/state.json"));
    let _ = std::fs::remove_file(cwd.join(".socket/vendor/redirect-state.json"));
}

#[test]
fn c_d_hosted_ledger_from_real_scan_attests_offline_and_dies_with_the_lock() {
    for flavor in FLAVORS {
        let what = format!("{flavor:?} hosted");
        let tmp = project();
        let cwd = tmp.path();
        let api = Api::start();
        let registry_lock = scan_hosted(cwd, flavor, &api);
        drop_manifest_and_install(cwd);
        let origin = api.uri();
        let psu = ["--patch-server-url", origin.as_str()];

        // c) ledger present, manifest absent: offline, from the ledger.
        let (code, env) = vex(cwd, &[&["--offline"][..], &psu].concat());
        assert_attested(cwd, code, &env, UUID, "hosted", &format!("{what} ledger"));

        // The hosted url is on the operator's patch server, so without
        // `--patch-server-url` it is not a discovered Socket reference.
        // DELIBERATE (vex_sources' raw-text fallback, kept so staging
        // servers keep working): an off-allowlist origin still proves the
        // LEDGER claim live — but only a discovered pinned ref may attest
        // from the lock, so with nothing installed the claim is
        // `package_not_found`, never attested.
        let (code, env) = vex(cwd, &["--offline"]);
        assert_omitted(
            cwd,
            code,
            &env,
            "package_not_found",
            &format!("{what} no psu"),
        );
        install(cwd, PATCHED);
        let (code, env) = vex(cwd, &["--offline"]);
        assert_attested(
            cwd,
            code,
            &env,
            UUID,
            "hosted",
            &format!("{what} no psu, installed"),
        );
        install(cwd, PRISTINE);
        let (code, env) = vex(cwd, &["--offline"]);
        assert_omitted(
            cwd,
            code,
            &env,
            "not_applied",
            &format!("{what} no psu, pristine"),
        );
        std::fs::remove_dir_all(cwd.join("node_modules")).unwrap();

        // a) no ledger either: the record comes from the API.
        let saved = std::fs::read(cwd.join(".socket/vendor/redirect-state.json")).unwrap();
        drop_ledgers(cwd);
        let (code, env) = vex_online(cwd, &api, &psu);
        assert_attested(
            cwd,
            code,
            &env,
            UUID,
            "hosted",
            &format!("{what} lock only"),
        );
        std::fs::write(cwd.join(".socket/vendor/redirect-state.json"), &saved).unwrap();

        // d) lock reverted to the registry, ledger left behind: never
        // attested, not even under --no-verify, offline or online.
        std::fs::write(cwd.join(flavor.lock_file()), &registry_lock).unwrap();
        for extra in [
            &["--offline"][..],
            &["--offline", "--no-verify"][..],
            &[][..],
        ] {
            let (code, env) = vex_online(cwd, &api, &[extra, &psu].concat());
            assert_omitted(
                cwd,
                code,
                &env,
                "redirect_unwired",
                &format!("{what} reverted {extra:?}"),
            );
        }
    }
}

#[test]
fn c_d_e_vendored_ledger_from_real_scan() {
    for flavor in FLAVORS {
        for detached in [false, true] {
            let what = format!("{flavor:?} vendored detached={detached}");
            let tmp = project();
            let cwd = tmp.path();
            let api = Api::start();
            let registry_lock = scan_vendored(cwd, flavor, &api, detached);
            drop_manifest_and_install(cwd);

            // c) ledger + artifact, no manifest: offline.
            let (code, env) = vex(cwd, &["--offline"]);
            assert_attested(cwd, code, &env, UUID, "vendored", &format!("{what} ledger"));

            // a) no ledger either: online from the API.
            let saved = std::fs::read(cwd.join(".socket/vendor/state.json")).unwrap();
            drop_ledgers(cwd);
            let (code, env) = vex_online(cwd, &api, &[]);
            assert_attested(
                cwd,
                code,
                &env,
                UUID,
                "vendored",
                &format!("{what} lock only"),
            );
            let (code, env) = vex(cwd, &["--offline"]);
            assert_omitted(
                cwd,
                code,
                &env,
                "record_unavailable",
                &format!("{what} offline"),
            );
            std::fs::write(cwd.join(".socket/vendor/state.json"), &saved).unwrap();

            // e) a tampered member of the committed artifact: omitted with
            // the ledger and without it.
            let artifact = cwd.join(vendored_rel(UUID));
            let honest = std::fs::read(&artifact).unwrap();
            std::fs::write(&artifact, tgz(TAMPERED)).unwrap();
            let (code, env) = vex(cwd, &["--offline"]);
            assert_omitted(
                cwd,
                code,
                &env,
                "vendor_hash_mismatch",
                &format!("{what} tamper"),
            );
            drop_ledgers(cwd);
            let (code, env) = vex_online(cwd, &api, &[]);
            assert_omitted(
                cwd,
                code,
                &env,
                "vendor_hash_mismatch",
                &format!("{what} tamper lock only"),
            );
            std::fs::write(&artifact, honest).unwrap();
            std::fs::write(cwd.join(".socket/vendor/state.json"), &saved).unwrap();

            // d) lock reverted, ledger + artifact left behind.
            std::fs::write(cwd.join(flavor.lock_file()), &registry_lock).unwrap();
            for extra in [&[][..], &["--no-verify"][..]] {
                let (code, env) = vex(cwd, &[&["--offline"][..], extra].concat());
                assert_omitted(
                    cwd,
                    code,
                    &env,
                    "vendor_unwired",
                    &format!("{what} reverted {extra:?}"),
                );
            }
        }
    }
}

/// d) for hand-wired production-host ledgers on every flavor: a leftover
/// redirect ledger + a registry lock, and a leftover vendor artifact with
/// no ledger at all (nothing references it → nothing to attest).
#[test]
fn d_reverted_lock_with_leftover_redirect_ledger_or_artifact() {
    for flavor in FLAVORS {
        let what = format!("{flavor:?}");
        let tmp = project();
        let cwd = tmp.path();
        write_ledger_record(cwd, UUID);
        write_lock(cwd, flavor, &Wiring::Registry);
        for extra in [&[][..], &["--no-verify"][..]] {
            let (code, env) = vex(cwd, &[&["--offline"][..], extra].concat());
            assert_omitted(
                cwd,
                code,
                &env,
                "redirect_unwired",
                &format!("{what} {extra:?}"),
            );
        }

        let tmp = project();
        let cwd = tmp.path();
        commit_artifact(cwd, UUID, PATCHED);
        write_lock(cwd, flavor, &Wiring::Registry);
        let (code, env) = vex(cwd, &["--offline"]);
        assert_nothing_found(code, &env, &format!("{what} orphan artifact"));
    }
}

/// A `.socket/vendor/redirect-state.json` embedding the view's record for
/// minimist under patch `uuid` (the shape `scan --mode hosted` persists).
fn write_ledger_record(cwd: &Path, uuid: &str) {
    let mut files = HashMap::new();
    files.insert(
        "package/index.js".to_string(),
        PatchFileInfo {
            before_hash: git(PRISTINE),
            after_hash: git(PATCHED),
        },
    );
    let mut vulnerabilities = HashMap::new();
    vulnerabilities.insert(
        GHSA.to_string(),
        VulnerabilityInfo {
            cves: vec![CVE.to_string()],
            summary: "prototype pollution".to_string(),
            severity: "high".to_string(),
            description: "d".to_string(),
        },
    );
    let mut state = RedirectState::new();
    state.records.insert(
        PURL.to_string(),
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: "2026-03-27T00:00:00Z".to_string(),
            files,
            vulnerabilities,
            description: "bun lockfile vex patch".to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        },
    );
    let dir = cwd.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("redirect-state.json"),
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();
}

// ──────────────────────────────────────────────────────────────────────
// e) + g): the installed tree is the evidence once present.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn e_g_hosted_installed_tree_decides() {
    for flavor in FLAVORS {
        let api = Api::start();
        api.serve_view(UUID, view(UUID, PURL));
        for (index, expect) in [
            (PATCHED, None),
            (PRISTINE, Some("not_applied")),
            (TAMPERED, Some("hash_mismatch")),
        ] {
            let what = format!("{flavor:?} installed {expect:?}");
            let tmp = project();
            let cwd = tmp.path();
            wire(cwd, flavor, "hosted", UUID);
            install(cwd, index);
            let (code, env) = vex_online(cwd, &api, &[]);
            match expect {
                None => assert_attested(cwd, code, &env, UUID, "hosted", &what),
                Some(reason) => assert_omitted(cwd, code, &env, reason, &what),
            }
            // --no-verify skips hashing only: the wiring alone attests.
            let (code, env) = vex_online(cwd, &api, &["--no-verify"]);
            assert_attested(
                cwd,
                code,
                &env,
                UUID,
                "hosted",
                &format!("{what} --no-verify"),
            );
        }
    }
}

/// g) every installed copy is consumed, so every copy must verify: a
/// nested pristine copy beside a patched hoisted one is omitted.
#[test]
fn g_every_installed_copy_must_verify() {
    let api = Api::start();
    api.serve_view(UUID, view(UUID, PURL));
    for flavor in [Flavor::Text(1), Flavor::Binary("1.4.2")] {
        let tmp = project();
        let cwd = tmp.path();
        wire(cwd, flavor, "hosted", UUID);
        install(cwd, PATCHED);
        install_at(cwd, "consumer/node_modules/minimist", PRISTINE);
        let (code, env) = vex_online(cwd, &api, &[]);
        assert_omitted(
            cwd,
            code,
            &env,
            "not_applied",
            &format!("{flavor:?} nested"),
        );
    }
}

/// LIMITATION (documented in `vex/discover/bun.rs`): bun < 1.3.10 re-saves
/// the hosted 3-tuple as the digest-less 2-tuple, so the lock no longer
/// fixes which bytes the url serves. Not installed, it cannot attest
/// (`package_not_found`); an installed tree that verifies still does.
#[test]
fn g_digestless_hosted_text_tuple_needs_an_installed_tree() {
    for version in [0, 1, 2] {
        let flavor = Flavor::Text(version);
        let api = Api::start();
        api.serve_view(UUID, view(UUID, PURL));
        let tmp = project();
        let cwd = tmp.path();
        let wiring = Wiring::Hosted {
            url: socket_url(UUID),
            sri: None,
        };
        write_lock(cwd, flavor, &wiring);
        let (code, env) = vex_online(cwd, &api, &[]);
        assert_omitted(cwd, code, &env, "package_not_found", &format!("{flavor:?}"));
        install(cwd, PATCHED);
        let (code, env) = vex_online(cwd, &api, &[]);
        assert_attested(
            cwd,
            code,
            &env,
            UUID,
            "hosted",
            &format!("{flavor:?} installed"),
        );
    }
}

/// The vendored verdict is the committed artifact's: an installed tree the
/// build did not refresh does not change it, and `--no-verify` still
/// requires the wiring.
#[test]
fn g_vendored_is_judged_by_the_committed_artifact() {
    let api = Api::start();
    api.serve_view(UUID, view(UUID, PURL));
    for flavor in FLAVORS {
        let tmp = project();
        let cwd = tmp.path();
        wire(cwd, flavor, "vendored", UUID);
        install(cwd, PRISTINE);
        let (code, env) = vex_online(cwd, &api, &[]);
        assert_attested(cwd, code, &env, UUID, "vendored", &format!("{flavor:?}"));
    }
}

// ──────────────────────────────────────────────────────────────────────
// f) spoofs.
// ──────────────────────────────────────────────────────────────────────

/// A uuid-shaped segment on a host that is NOT Socket's patch server is
/// the user's own tarball dependency — never a patch reference — even on
/// look-alike hosts, and it cannot keep a redirect ledger alive.
#[test]
fn f_uuid_on_a_non_socket_host_is_not_a_patch() {
    let origins = [
        "https://evil.example",
        "https://patch.socket.dev.evil.example",
        "https://evil.example/patch.socket.dev",
        "https://patch.socket.dev@evil.example",
        "http://patch-socket.dev",
    ];
    for flavor in FLAVORS {
        for origin in origins {
            let what = format!("{flavor:?} {origin}");
            let tmp = project();
            let cwd = tmp.path();
            let api = Api::start();
            api.serve_view(UUID, view(UUID, PURL));
            let wiring = Wiring::Hosted {
                url: hosted_url_on(origin, UUID),
                sri: Some(sri(&tgz(PATCHED))),
            };
            write_lock(cwd, flavor, &wiring);
            install(cwd, PATCHED);
            let (code, env) = vex_online(cwd, &api, &[]);
            assert_nothing_found(code, &env, &what);
            assert_eq!(api.requests(), 0, "{what}: nothing to fetch");
            write_ledger_record(cwd, UUID);
            let (code, env) = vex_online(cwd, &api, &["--no-verify"]);
            assert_omitted(
                cwd,
                code,
                &env,
                "redirect_unwired",
                &format!("{what} ledger"),
            );
        }
    }
}

/// A uuid-shaped vendor path that is not the project's `.socket/vendor`
/// (another dir, a traversal out of the root) is not a vendored patch.
#[test]
fn f_vendor_path_outside_socket_vendor_is_not_a_patch() {
    for flavor in FLAVORS {
        for rel in [
            format!("vendor/npm/{UUID}/{NAME}-{VERSION}.tgz"),
            format!("../.socket/vendor/npm/{UUID}/{NAME}-{VERSION}.tgz"),
            format!("sub/.socket/vendor/npm/{UUID}/{NAME}-{VERSION}.tgz"),
        ] {
            let what = format!("{flavor:?} {rel}");
            let tmp = project();
            let cwd = tmp.path();
            let bytes = tgz(PATCHED);
            let inside = cwd.join(rel.trim_start_matches("../"));
            std::fs::create_dir_all(inside.parent().unwrap()).unwrap();
            std::fs::write(&inside, &bytes).unwrap();
            let api = Api::start();
            api.serve_view(UUID, view(UUID, PURL));
            write_lock(
                cwd,
                flavor,
                &Wiring::Vendored {
                    rel: rel.clone(),
                    sri: sri(&bytes),
                },
            );
            let (code, env) = vex_online(cwd, &api, &[]);
            assert_nothing_found(code, &env, &what);
        }
    }
}

/// The record the API returns for the wired uuid names ANOTHER package, or
/// is a DIFFERENT patch than the one requested: `record_mismatch`, for
/// both modes — a hand-edited lock cannot borrow another patch's record.
#[test]
fn f_record_that_disagrees_with_the_lock_is_a_mismatch() {
    for flavor in FLAVORS {
        for mode in modes() {
            for (label, body) in [
                ("other purl", view(UUID, "pkg:npm/lodash@4.17.21")),
                ("other version", view(UUID, "pkg:npm/minimist@1.2.8")),
                ("other uuid", view(OTHER_UUID, PURL)),
            ] {
                let what = format!("{flavor:?} {mode} {label}");
                let tmp = project();
                let cwd = tmp.path();
                wire(cwd, flavor, mode, UUID);
                let api = Api::start();
                api.serve_view(UUID, body);
                let (code, env) = vex_online(cwd, &api, &[]);
                assert_omitted(cwd, code, &env, "record_mismatch", &what);
            }
        }
    }
}

/// A leftover ledger record for a DIFFERENT patch of the same purl never
/// stands in for the uuid the lock wires: offline there is no record for
/// the wired uuid; online the wired uuid's own record attests.
#[test]
fn f_ledger_record_for_another_uuid_is_not_used() {
    for flavor in FLAVORS {
        let what = format!("{flavor:?}");
        let tmp = project();
        let cwd = tmp.path();
        wire(cwd, flavor, "hosted", UUID);
        write_ledger_record(cwd, OTHER_UUID);
        let (code, env) = vex(cwd, &["--offline"]);
        assert_eq!(code, Some(1), "{what}: {env}");
        assert!(
            !env["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["action"] == "verified"),
            "{what}: {env}"
        );
        let api = Api::start();
        api.serve_view(UUID, view(UUID, PURL));
        let (code, env) = vex_online(cwd, &api, &[]);
        assert_attested(cwd, code, &env, UUID, "hosted", &format!("{what} online"));
    }
}

/// A vendored leaf naming another package on minimist's entry is not
/// Socket-written: diagnosed, never a ref (the run finds nothing, and the
/// extractor's reason rides the error envelope).
#[test]
fn f_vendored_leaf_naming_another_package_is_diagnosed() {
    for flavor in FLAVORS {
        let what = format!("{flavor:?}");
        let tmp = project();
        let cwd = tmp.path();
        let rel = format!(".socket/vendor/npm/{UUID}/lodash-4.17.21.tgz");
        let bytes = tgz(PATCHED);
        std::fs::create_dir_all(cwd.join(&rel).parent().unwrap()).unwrap();
        std::fs::write(cwd.join(&rel), &bytes).unwrap();
        if let Flavor::Binary(_) = flavor {
            // The binary rewriter names the leaf after the dependency it
            // rewires; a mismatched leaf is only reachable by hand-editing
            // the text lock.
            continue;
        }
        write_lock(
            cwd,
            flavor,
            &Wiring::Vendored {
                rel,
                sri: sri(&bytes),
            },
        );
        let (code, env) = vex(cwd, &["--offline"]);
        assert_nothing_found(code, &env, &what);
        let warnings = env["warnings"].to_string();
        assert!(warnings.contains("patched_ref_invalid"), "{what}: {env}");
    }
}

// ──────────────────────────────────────────────────────────────────────
// Bun-specific edges.
// ──────────────────────────────────────────────────────────────────────

/// bun reads `bun.lock` whenever it exists, so a Socket-wired `bun.lockb`
/// left beside a registry `bun.lock` is debris: it attests nothing, and a
/// ledger it still names is dead. The reverse — a wired `bun.lock` beside a
/// stale registry `bun.lockb` — attests.
#[test]
fn stale_binary_lock_beside_a_text_lock_is_ignored() {
    for mode in modes() {
        let what = format!("{mode} debris");
        let tmp = project();
        let cwd = tmp.path();
        let api = Api::start();
        api.serve_view(UUID, view(UUID, PURL));
        let wiring = match mode {
            "hosted" => hosted(UUID),
            _ => commit_artifact(cwd, UUID, PATCHED),
        };
        std::fs::write(cwd.join("bun.lockb"), binary_lock("1.4.2", &wiring)).unwrap();
        std::fs::write(
            cwd.join("bun.lock"),
            text_lock(1, NAME, &text_tuple(&Wiring::Registry)),
        )
        .unwrap();
        let (code, env) = vex_online(cwd, &api, &[]);
        assert_nothing_found(code, &env, &what);
        if mode == "hosted" {
            write_ledger_record(cwd, UUID);
            let (code, env) = vex_online(cwd, &api, &["--no-verify"]);
            assert_omitted(
                cwd,
                code,
                &env,
                "redirect_unwired",
                &format!("{what} ledger"),
            );
            let _ = std::fs::remove_file(cwd.join(".socket/vendor/redirect-state.json"));
        }

        // Reverse: the text lock is the wired one.
        std::fs::write(cwd.join("bun.lockb"), binary_fixture("1.4.2")).unwrap();
        std::fs::write(
            cwd.join("bun.lock"),
            text_lock(1, NAME, &text_tuple(&wiring)),
        )
        .unwrap();
        let (code, env) = vex_online(cwd, &api, &[]);
        assert_attested(cwd, code, &env, UUID, mode, &format!("{mode} wired text"));
    }
}

/// A binary lock bun cannot read wires nothing — and the patch url it still
/// contains must not keep a redirect ledger alive either.
#[test]
fn truncated_binary_lock_attests_nothing() {
    let tmp = project();
    let cwd = tmp.path();
    let wired = binary_lock("1.4.2", &hosted(UUID));
    std::fs::write(cwd.join("bun.lockb"), &wired[..wired.len() / 2]).unwrap();
    let (code, env) = vex(cwd, &["--offline"]);
    assert_nothing_found(code, &env, "truncated");
    assert!(
        env["warnings"].to_string().contains("lockfile_unparseable"),
        "{env}"
    );
    write_ledger_record(cwd, UUID);
    let (code, env) = vex(cwd, &["--offline", "--no-verify"]);
    assert_omitted(cwd, code, &env, "redirect_unwired", "truncated + ledger");
}

/// An aliased install (`"mm": "npm:minimist@1.2.2"`): the map key is the
/// alias, the spec names the real package, so the purl is minimist's.
///
/// REGRESSION (hosted): bun installs the aliased hosted tarball at
/// `node_modules/mm`, which the npm crawler's name-keyed lookup never
/// probes — so the only installed copy read as "not installed" and a
/// tampered or pristine (not yet reinstalled) alias attested from the lock
/// pin. The alias copy is consumed evidence and must verify.
#[test]
fn aliased_text_entries_attest_the_real_package() {
    for version in [0, 1, 2] {
        for mode in modes() {
            let what = format!("v{version} {mode} alias");
            let tmp = project();
            let cwd = tmp.path();
            let wiring = match mode {
                "hosted" => hosted(UUID),
                _ => commit_artifact(cwd, UUID, PATCHED),
            };
            write_lock_keyed(cwd, Flavor::Text(version), "mm", &wiring);
            let api = Api::start();
            api.serve_view(UUID, view(UUID, PURL));
            let (code, env) = vex_online(cwd, &api, &[]);
            assert_attested(cwd, code, &env, UUID, mode, &what);
            if mode == "vendored" {
                // The committed artifact is the evidence, not the install.
                install_at(cwd, "mm", TAMPERED);
                let (code, env) = vex_online(cwd, &api, &[]);
                assert_attested(cwd, code, &env, UUID, mode, &format!("{what} install"));
                continue;
            }
            for (index, expect) in [
                (PATCHED, None),
                (PRISTINE, Some("not_applied")),
                (TAMPERED, Some("hash_mismatch")),
            ] {
                let what = format!("{what} installed {expect:?}");
                install_at(cwd, "mm", index);
                let (code, env) = vex_online(cwd, &api, &[]);
                match expect {
                    None => assert_attested(cwd, code, &env, UUID, mode, &what),
                    Some(reason) => assert_omitted(cwd, code, &env, reason, &what),
                }
            }
            // A patched alias beside a pristine canonical copy: both are
            // consumed, both must verify.
            install_at(cwd, "mm", PATCHED);
            install(cwd, PRISTINE);
            let (code, env) = vex_online(cwd, &api, &[]);
            assert_omitted(
                cwd,
                code,
                &env,
                "not_applied",
                &format!("{what} + canonical"),
            );
        }
    }
}

/// `--patch-server-url` (staging / self-hosted): the operator's origin
/// counts as a Socket host only when configured.
#[test]
fn configured_patch_server_origin_counts_only_when_configured() {
    for flavor in FLAVORS {
        let what = format!("{flavor:?}");
        let tmp = project();
        let cwd = tmp.path();
        let api = Api::start();
        api.serve_view(UUID, view(UUID, PURL));
        let wiring = Wiring::Hosted {
            url: hosted_url_on(&api.uri(), UUID),
            sri: Some(sri(&tgz(PATCHED))),
        };
        write_lock(cwd, flavor, &wiring);
        let (code, env) = vex_online(cwd, &api, &[]);
        assert_nothing_found(code, &env, &what);
        let uri = api.uri();
        let (code, env) = vex_online(cwd, &api, &["--patch-server-url", &uri]);
        assert_attested(
            cwd,
            code,
            &env,
            UUID,
            "hosted",
            &format!("{what} configured"),
        );
    }
}

/// `apply --json --vex out.vex.json` in `cwd` (unauthenticated, public
/// view route on `api`), plus `extra`; returns (exit, envelope).
fn apply_vex(cwd: &Path, api: &Api, extra: &[&str]) -> (Option<i32>, Value) {
    let uri = api.uri();
    let out = cli()
        .current_dir(cwd)
        .env("SOCKET_NO_API_TOKEN", "1")
        .args(["apply", "--json", "--cwd"])
        .arg(cwd)
        .args([
            "--proxy-url",
            &uri,
            "--vex",
            "out.vex.json",
            "--vex-product",
        ])
        .arg(PRODUCT)
        .args(extra)
        .output()
        .expect("invoke apply");
    (out.status.code(), envelope(&out))
}

/// REGRESSION: `apply --vex` in a manifest-less checkout whose Bun lock
/// carries the patch (hosted and vendored) — the embedded twin of
/// standalone `vex`. Before the fix apply's no-manifest early return
/// skipped VEX generation entirely: exit 0, `noManifest`, NO document.
#[test]
fn apply_vex_attests_lockfile_patches_without_a_manifest() {
    for flavor in [Flavor::Text(1), Flavor::Binary("1.4.2")] {
        for mode in modes() {
            let what = format!("{flavor:?} {mode} apply --vex");
            let tmp = project();
            let cwd = tmp.path();
            wire(cwd, flavor, mode, UUID);
            let api = Api::start();
            api.serve_view(UUID, view(UUID, PURL));
            let (code, env) = apply_vex(cwd, &api, &[]);
            assert_eq!(code, Some(0), "{what}: {env}");
            assert_eq!(env["status"], "noManifest", "{what}: {env}");
            assert_eq!(env["vex"]["statements"], 1, "{what}: {env}");
            assert_eq!(env["vex"]["path"], "out.vex.json", "{what}: {env}");
            let stmt = &doc(cwd)["statements"][0];
            assert_eq!(stmt["vulnerability"]["name"], GHSA, "{what}");
            assert_eq!(
                stmt["products"][0]["subcomponents"][0]["@id"], PURL,
                "{what}"
            );
            assert_eq!(
                stmt["impact_statement"],
                format!("Patched via Socket patch {UUID} ({})", marker(mode)),
                "{what}"
            );
            assert!(!cwd.join(".socket/manifest.json").exists(), "{what}");

            // --dry-run applies nothing, so it attests nothing.
            std::fs::remove_file(cwd.join("out.vex.json")).unwrap();
            let (code, env) = apply_vex(cwd, &api, &["--dry-run"]);
            assert_eq!(code, Some(0), "{what} dry-run: {env}");
            assert!(
                env.get("vex").is_none() || env["vex"].is_null(),
                "{what}: {env}"
            );
            assert!(!cwd.join("out.vex.json").exists(), "{what} dry-run");

            // Found but not attestable (tampered artifact / installed tree):
            // the fail-the-command contract — exit 1, error envelope, and a
            // previous run's document is removed.
            std::fs::write(cwd.join("out.vex.json"), doc_placeholder()).unwrap();
            match mode {
                "hosted" => install(cwd, TAMPERED),
                _ => std::fs::write(cwd.join(vendored_rel(UUID)), tgz(TAMPERED)).unwrap(),
            }
            let (code, env) = apply_vex(cwd, &api, &[]);
            assert_eq!(code, Some(1), "{what} tampered: {env}");
            assert_eq!(
                env["error"]["code"], "no_applicable_patches",
                "{what}: {env}"
            );
            assert!(
                !cwd.join("out.vex.json").exists(),
                "{what}: stale doc removed"
            );
        }
    }

    // Nothing discovered and no manifest: the historical calm no-op (exit 0,
    // noManifest) is kept, but a stale OpenVEX document is still removed.
    let tmp = project();
    let cwd = tmp.path();
    write_lock(cwd, Flavor::Text(1), &Wiring::Registry);
    std::fs::write(cwd.join("out.vex.json"), doc_placeholder()).unwrap();
    let api = Api::start();
    let (code, env) = apply_vex(cwd, &api, &[]);
    assert_eq!(code, Some(0), "{env}");
    assert_eq!(env["status"], "noManifest", "{env}");
    assert!(
        env.get("error").is_none() || env["error"].is_null(),
        "{env}"
    );
    assert!(!cwd.join("out.vex.json").exists(), "stale doc removed");
}

/// A previous run's (recognizably OpenVEX) document.
fn doc_placeholder() -> String {
    json!({ "@context": "https://openvex.dev/ns/v0.2.0", "statements": [] }).to_string()
}
