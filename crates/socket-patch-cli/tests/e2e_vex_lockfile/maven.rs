//! Manifest-less `socket-patch vex` for MAVEN: the hosted wiring
//! `scan --mode hosted` / `get --mode hosted` write (`redirect::
//! rewrite_maven_pom`: a `-socket.<hex8>` pinned version + a
//! `socket-patch-<uuid>` repository on the Socket patch server) and the
//! vendored wiring `vendor` writes (`vendor::maven_repo`: a
//! `socket-patch-vendor-<uuid>` file:// repository over the committed
//! `.socket/vendor/maven/<uuid>/` maven2 tree) are attested from the
//! project files alone — no `.socket/manifest.json` and (except where a cell
//! says otherwise) no `.socket/vendor/state.json` / `redirect-state.json`
//! ledger — and never falsely.
//!
//! Hermetic on every OS: the patch API is a wiremock stand-in serving the
//! public-proxy `GET /patch/view/<uuid>` route (`--proxy-url`), the maven
//! local repository is a per-test temp dir (`MAVEN_REPO_LOCAL`), and no real
//! Maven runs (the real-toolchain capstones are `e2e_redirect_maven_build`
//! and `e2e_vendor_maven_build`).
//!
//! Matrix (per wiring shape × {hosted, vendored}):
//!
//! | cell | shape | expectation |
//! |---|---|---|
//! | a | no manifest, no ledgers, online | attested `(redirected)` / `(vendored)` with the pom's purl, the record's vuln id + CVE alias, exit 0, a `verified` envelope event |
//! | b | `--offline` (and an unreachable API) with no local record | `record_unavailable`, exit 1, ZERO requests reach the API under `--offline` |
//! | c | ledger present, manifest absent, `--offline` | attested from the ledger's embedded record |
//! | d | wiring reverted to the registry, ledger (+ artifact) left behind | `redirect_unwired` / `vendor_unwired`, with and without `--no-verify` |
//! | e | tampered installed tree (hosted) / tampered artifact member (vendored) | omitted `hash_mismatch` / `vendor_hash_mismatch` |
//! | f | uuid-shaped segment on a non-Socket host / outside the vendor tree; a record naming another package or patch | not a reference (exit 2, nothing to attest, zero API requests) / `record_mismatch` |
//! | g | hosted not installed / installed + patched / installed pristine | attests from the pom pin (D5) / attests after hashing / omitted `not_applied` |
//!
//! Hosted shapes: every fail-closed golden the rewriter emits (direct
//! literal pin, managed pin, managed + versionless direct, merged
//! `.mvn/maven.config`, pre-existing `<repositories>`), CRLF and `${prop}`
//! hand edits, and a configured `--patch-server-url` origin. Vendored: every
//! `file:` url spelling the extractor accepts. Embedded: the REAL writers
//! (`vendor --vex`, `scan --mode hosted --vex`) produce the wiring, then the
//! manifest and ledgers are deleted and the standalone `vex` re-attests.
//!
//! Documented limitations are asserted explicitly (never skipped): the
//! legacy same-GAV hosted fallback, a staging (non-allowlisted) host kept
//! alive by a ledger under `--no-verify`, and agent-mode (`apply`) patches,
//! which have no lockfile wiring to discover.

use crate::vex_e2e_common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
use socket_patch_core::patch::redirect::{FileEdit, RedirectState};
use socket_patch_core::vendor::state::{
    VendorArtifact, VendorEntry, VendorState, WiringAction, WiringRecord,
};
use vex_e2e_common::{assert_omitted_parts, skipped_reason};

const PRODUCT: &str = "pkg:maven/com.example/app@1.0.0";

// The committed hosted goldens' patch identities.
const MVN_HOSTED_UUID: &str = "77777777-7777-7777-7777-777777777777";
const MVN_PURL: &str = "pkg:maven/org.slf4j/slf4j-api@1.7.36";
const MVN_SUFFIXED: &str = "1.7.36-socket.77777777";

const MVN_VENDOR_UUID: &str = "7b7b7b7b-1111-4111-8111-7b7b7b7b7b7b";
const MVN_VENDOR_PURL: &str = "pkg:maven/org.apache.commons/commons-text@1.10.0";

const GHSA: &str = "GHSA-mnd0-lock-vex0";
const CVE: &str = "CVE-2026-7100";

// ── process plumbing ─────────────────────────────────────────────────────

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_socket-patch")
}

/// The CLI with every ambient `SOCKET_*` variable scrubbed (explicit flags
/// are the only source of truth), telemetry/config/token off, and the
/// ecosystem stores the crawlers read pinned to `store` — an ambient
/// `~/.m2` must never become installed evidence.
fn cli(store: &Path) -> Command {
    let mut cmd = Command::new(binary());
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("MAVEN_REPO_LOCAL", store.join("m2"))
        .env_remove("M2_HOME")
        .env_remove("VIRTUAL_ENV");
    cmd
}

/// One hermetic project: `<tmp>/app` is the checkout, `<tmp>/store/{m2,
/// the maven local repository the crawler reads.
struct Fx {
    tmp: tempfile::TempDir,
    cwd: PathBuf,
}

impl Fx {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("app");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(tmp.path().join("store/m2")).unwrap();
        Fx { tmp, cwd }
    }

    fn store(&self) -> PathBuf {
        self.tmp.path().join("store")
    }

    fn m2(&self) -> PathBuf {
        self.store().join("m2")
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

    /// `socket-patch vex --json --output out.vex.json` → (exit, envelope).
    fn vex(&self, extra: &[&str]) -> (Option<i32>, Value) {
        let out_path = self.cwd.join("out.vex.json");
        let _ = std::fs::remove_file(&out_path);
        let mut cmd = cli(&self.store());
        cmd.env("SOCKET_NO_API_TOKEN", "1").args([
            "vex",
            "--cwd",
            self.cwd.to_str().unwrap(),
            "--json",
            "--output",
            out_path.to_str().unwrap(),
            "--product",
            PRODUCT,
        ]);
        cmd.args(extra);
        let out = cmd.output().expect("invoke vex");
        (out.status.code(), envelope(&out))
    }

    /// The OpenVEX document the last successful [`Fx::vex`] wrote.
    fn doc(&self) -> Value {
        doc_at(&self.cwd.join("out.vex.json"))
    }
}

fn put(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn envelope(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "envelope JSON on stdout ({e}). stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn doc_at(path: &Path) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap()
}

/// Cell (a)'s full oracle: exit 0, exactly one `not_affected` statement for
/// `uuid` with the `marker` provenance, `purl` (the record's purl) as the subcomponent, the record's vuln id + CVE alias, and a `verified` envelope event.
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

/// A public-proxy stand-in serving `GET /patch/view/<uuid>`. Keep the
/// runtime alive for the CLI invocations.
struct Api {
    rt: tokio::runtime::Runtime,
    server: wiremock::MockServer,
}

impl Api {
    fn serve(views: Vec<(&str, Value)>) -> Self {
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

    fn requests(&self) -> usize {
        self.rt
            .block_on(self.server.received_requests())
            .map_or(0, |r| r.len())
    }
}

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

/// A zip-family artifact (`.jar` / `.nupkg`) holding `members`.
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
// MAVEN — hosted (`rewrite_maven_pom`: `-socket.<hex8>` pin + Socket repo)
// ══════════════════════════════════════════════════════════════════════════

/// The maven patch's single file: the jar in the version dir (agent-mode
/// `apply` / the hosted served artifact key the record by the version-dir
/// file name; the consumed copy is the suffixed dir's renamed jar).
const MVN_JAR_KEY: &str = "slf4j-api-1.7.36.jar";
const MVN_PRISTINE: &[u8] = b"PK slf4j-api pristine jar";
const MVN_PATCHED: &[u8] = b"PK slf4j-api patched jar";

fn mvn_files() -> Vec<(&'static str, &'static [u8], &'static [u8])> {
    vec![(MVN_JAR_KEY, MVN_PRISTINE, MVN_PATCHED)]
}

fn mvn_hosted_view() -> Value {
    view(MVN_HOSTED_UUID, MVN_PURL, &mvn_files())
}

/// Every fail-closed hosted golden: each pins the suffixed version in a
/// different place of the pom.
const MVN_HOSTED_GOLDENS: &[&str] = &[
    "maven/pom/basic/expected",
    "maven/pom/existing-depmgmt/expected",
    "maven/pom/existing-repositories/expected",
    "maven/pom/mvn-config-merge/expected",
    "maven/pom/transitive-depmgmt/expected",
];

/// Hand-edited but Maven-equivalent spellings of the basic golden: CRLF
/// line endings, and the suffixed version behind a root `${property}`.
fn mvn_hosted_hand_edits() -> Vec<(&'static str, String)> {
    let basic = std::fs::read_to_string(fixture_dir("maven/pom/basic/expected/pom.xml")).unwrap();
    let crlf = basic.replace('\n', "\r\n");
    let prop = basic
        .replace(
            &format!("<version>{MVN_SUFFIXED}</version>"),
            "<version>${slf4j.version}</version>",
        )
        .replace(
            "  <dependencies>",
            &format!(
                "  <properties>\n    <slf4j.version>{MVN_SUFFIXED}</slf4j.version>\n  \
                 </properties>\n  <dependencies>"
            ),
        );
    assert!(prop.contains("${slf4j.version}") && prop.contains("<properties>"));
    vec![("crlf", crlf), ("property", prop)]
}

/// Cells a, b, c, d and f (record mismatch) for one hosted maven wiring.
/// `setup` lays the wiring down; `reverted` is what the registry-only pom
/// looks like.
fn maven_hosted_cells(what: &str, setup: &dyn Fn(&Fx)) {
    let reverted = std::fs::read_to_string(fixture_dir("maven/pom/basic/input/pom.xml")).unwrap();

    // (a) online, nothing installed: the fail-closed suffixed pin is the
    // evidence (maven's hosted `integrity_required` is false — the
    // suffixed version exists only on the Socket repository).
    let fx = Fx::new();
    setup(&fx);
    fx.assert_no_manifest();
    let api = Api::serve(vec![(MVN_HOSTED_UUID, mvn_hosted_view())]);
    let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(&fx, code, &env, MVN_HOSTED_UUID, MVN_PURL, "redirected");
    assert!(api.requests() >= 1, "{what}: the record came from the API");

    // (b) offline with no local record: omitted, and nothing is fetched.
    let before = api.requests();
    let (code, env) = fx.vex(&["--offline", "--proxy-url", &api.uri()]);
    assert_omitted(code, &env, MVN_PURL, "record_unavailable", what);
    assert_eq!(api.requests(), before, "{what}: --offline made a request");
    // ...and an unreachable API is the same omission, not an abort.
    let (code, env) = fx.vex(&["--proxy-url", "http://127.0.0.1:9"]);
    assert_omitted(code, &env, MVN_PURL, "record_unavailable", what);

    // (f) the API's record names another package / another patch.
    for (label, bad) in [
        (
            "other package",
            view(
                MVN_HOSTED_UUID,
                "pkg:maven/org.slf4j/slf4j-simple@1.7.36",
                &mvn_files(),
            ),
        ),
        (
            "other version",
            view(
                MVN_HOSTED_UUID,
                "pkg:maven/org.slf4j/slf4j-api@1.7.35",
                &mvn_files(),
            ),
        ),
        (
            "other uuid",
            view(
                "12121212-3434-4565-8787-909090909090",
                MVN_PURL,
                &mvn_files(),
            ),
        ),
    ] {
        let bad_api = Api::serve(vec![(MVN_HOSTED_UUID, bad)]);
        let (code, env) = fx.vex(&["--proxy-url", &bad_api.uri()]);
        assert_omitted(
            code,
            &env,
            MVN_PURL,
            "record_mismatch",
            &format!("{what}: {label}"),
        );
    }

    // (c) the redirect ledger's record, offline, no manifest.
    write_redirect_ledger(
        &fx,
        MVN_PURL,
        record(MVN_HOSTED_UUID, &mvn_files()),
        &[("pom.xml", "redirect_maven_pom")],
    );
    let (code, env) = fx.vex(&["--offline"]);
    assert_attested(&fx, code, &env, MVN_HOSTED_UUID, MVN_PURL, "redirected");

    // (d) the pom reverted to the registry version (the `.mvn` checksum
    // files and the ledger left behind): dead, even under --no-verify.
    fx.put("pom.xml", &reverted);
    for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
        let (code, env) = fx.vex(extra);
        assert_omitted(
            code,
            &env,
            MVN_PURL,
            "redirect_unwired",
            &format!("{what} reverted {extra:?}"),
        );
    }
}

#[test]
fn maven_hosted_goldens_attest_without_manifest_or_ledgers() {
    for golden in MVN_HOSTED_GOLDENS {
        maven_hosted_cells(golden, &|fx| {
            let files = copy_golden(fx, golden);
            assert!(files.contains(&"pom.xml".to_string()), "{golden}");
        });
    }
}

#[test]
fn maven_hosted_hand_edited_poms_attest_without_manifest_or_ledgers() {
    for (label, pom) in mvn_hosted_hand_edits() {
        maven_hosted_cells(label, &|fx| fx.put("pom.xml", &pom));
    }
}

/// `--patch-server-url` (staging / self-hosted): a pom whose Socket
/// repository lives on the operator's configured origin is hosted ONLY
/// with that override — without it the same pom is a user repository.
#[test]
fn maven_hosted_configured_origin_counts_only_with_the_override() {
    let fx = Fx::new();
    let api = Api::serve(vec![(MVN_HOSTED_UUID, mvn_hosted_view())]);
    let pom = std::fs::read_to_string(fixture_dir("maven/pom/basic/expected/pom.xml"))
        .unwrap()
        .replace("https://patch.socket.dev", &api.uri());
    assert!(pom.contains(&api.uri()));
    fx.put("pom.xml", &pom);
    let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
    assert_nothing_to_attest(code, &env, "foreign origin without the override");
    let (code, env) = fx.vex(&["--proxy-url", &api.uri(), "--patch-server-url", &api.uri()]);
    assert_attested(&fx, code, &env, MVN_HOSTED_UUID, MVN_PURL, "redirected");
}

/// Cells e and g: the installed tree maven CONSUMES is the suffixed
/// version dir (`<base>-socket.<hex8>/…-socket.<hex8>.jar`).
#[test]
fn maven_hosted_installed_tree_is_the_evidence_once_present() {
    let fx = Fx::new();
    copy_golden(&fx, "maven/pom/basic/expected");
    let api = Api::serve(vec![(MVN_HOSTED_UUID, mvn_hosted_view())]);
    let args = ["--proxy-url", &api.uri()];
    let base_dir = fx.m2().join("org/slf4j/slf4j-api/1.7.36");
    let sfx_dir = fx.m2().join(format!("org/slf4j/slf4j-api/{MVN_SUFFIXED}"));
    let sfx_jar = sfx_dir.join(format!("slf4j-api-{MVN_SUFFIXED}.jar"));

    // (g) not installed: attests from the pin.
    let (code, env) = fx.vex(&args);
    assert_attested(&fx, code, &env, MVN_HOSTED_UUID, MVN_PURL, "redirected");

    // (g) only the pristine BASE version is cached (e.g. resolved before
    // the redirect): maven never reads it under the suffixed pin, so it is
    // not evidence either way — still attested from the pin.
    put(&base_dir, "slf4j-api-1.7.36.pom", b"<project/>");
    put(&base_dir, "slf4j-api-1.7.36.jar", MVN_PRISTINE);
    let (code, env) = fx.vex(&args);
    assert_attested(&fx, code, &env, MVN_HOSTED_UUID, MVN_PURL, "redirected");

    // (g) installed and patched: verified against the consumed copy.
    put(
        &sfx_dir,
        &format!("slf4j-api-{MVN_SUFFIXED}.pom"),
        b"<project/>",
    );
    std::fs::write(&sfx_jar, MVN_PATCHED).unwrap();
    let (code, env) = fx.vex(&args);
    assert_attested(&fx, code, &env, MVN_HOSTED_UUID, MVN_PURL, "redirected");
    // --no-verify skips hashing but still attests the live wiring.
    std::fs::write(&sfx_jar, b"garbage").unwrap();
    let (code, env) = fx.vex(&["--proxy-url", &api.uri(), "--no-verify"]);
    assert_attested(&fx, code, &env, MVN_HOSTED_UUID, MVN_PURL, "redirected");

    // (e) the consumed copy tampered: installed evidence wins over the pin.
    let (code, env) = fx.vex(&args);
    assert_omitted(
        code,
        &env,
        MVN_PURL,
        "hash_mismatch",
        "tampered suffixed jar",
    );

    // (g) the consumed copy is PRISTINE (the Socket repo served unpatched
    // bytes): not applied, omitted.
    std::fs::write(&sfx_jar, MVN_PRISTINE).unwrap();
    let (code, env) = fx.vex(&args);
    assert_omitted(code, &env, MVN_PURL, "not_applied", "pristine suffixed jar");

    // The ledger's record changes nothing: the installed tree still wins.
    write_redirect_ledger(
        &fx,
        MVN_PURL,
        record(MVN_HOSTED_UUID, &mvn_files()),
        &[("pom.xml", "redirect_maven_pom")],
    );
    let (code, env) = fx.vex(&["--offline"]);
    assert_omitted(code, &env, MVN_PURL, "not_applied", "pristine + ledger");
}

/// Cell g (integrity): maven's hosted pin is the SUFFIXED version itself —
/// `<base>-socket.<hex8>` exists only on the Socket repository, so it is
/// fail-closed without the trusted-checksums summary (`integrity_required`
/// is false for maven; the rewriter writes `.mvn/checksums` only when the
/// grant carries both digests). Dropping `.mvn/` (a user who never
/// committed it) still attests from the pin; the installed tree stays the
/// evidence once present.
#[test]
fn maven_hosted_pin_without_trusted_checksums_still_attests() {
    let fx = Fx::new();
    copy_golden(&fx, "maven/pom/basic/expected");
    fx.rm(".mvn");
    let api = Api::serve(vec![(MVN_HOSTED_UUID, mvn_hosted_view())]);
    let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(&fx, code, &env, MVN_HOSTED_UUID, MVN_PURL, "redirected");

    let sfx_dir = fx.m2().join(format!("org/slf4j/slf4j-api/{MVN_SUFFIXED}"));
    put(
        &sfx_dir,
        &format!("slf4j-api-{MVN_SUFFIXED}.pom"),
        b"<project/>",
    );
    put(
        &sfx_dir,
        &format!("slf4j-api-{MVN_SUFFIXED}.jar"),
        b"tampered",
    );
    let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
    assert_omitted(code, &env, MVN_PURL, "hash_mismatch", "no .mvn, tampered");
}

/// Cell f: a `socket-patch-<uuid>` repository on a NON-Socket host (and a
/// Socket url whose uuid segment differs from the id) is not a patch
/// reference — with no manifest and no ledger there is nothing to attest,
/// and the API is never asked about the uuid. A ledger record for the
/// same uuid is kept dead by the rejected text (rule 11).
#[test]
fn maven_hosted_spoofed_repositories_never_attest() {
    let golden = std::fs::read_to_string(fixture_dir("maven/pom/basic/expected/pom.xml")).unwrap();
    let foreign = golden.replace("https://patch.socket.dev", "https://evil.example");
    let other_uuid = golden.replace(
        &format!("/{MVN_HOSTED_UUID}/maven2"),
        "/12121212-3434-4565-8787-909090909090/maven2",
    );
    let lookalike = golden.replace("patch.socket.dev", "patch.socket.dev.evil.example");
    for (label, pom) in [
        ("foreign host", &foreign),
        ("id/url uuid mismatch", &other_uuid),
        ("lookalike host", &lookalike),
    ] {
        assert_ne!(pom, &golden, "{label}");
        let fx = Fx::new();
        fx.put("pom.xml", pom);
        let api = Api::serve(vec![(MVN_HOSTED_UUID, mvn_hosted_view())]);
        let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
        assert_nothing_to_attest(code, &env, label);
        assert_eq!(api.requests(), 0, "{label}: no record fetch for a non-ref");

        write_redirect_ledger(
            &fx,
            MVN_PURL,
            record(MVN_HOSTED_UUID, &mvn_files()),
            &[("pom.xml", "redirect_maven_pom")],
        );
        if label == "id/url uuid mismatch" {
            // The Socket-host url names ANOTHER patch: the uuid is
            // recognized, the extractor rejected it, so the ledger claim is
            // dead whatever raw text survives (rule 11).
            for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
                let (code, env) = fx.vex(extra);
                assert_omitted(code, &env, MVN_PURL, "redirect_unwired", label);
            }
            continue;
        }
        // DOCUMENTED LIMITATION (vex_sources.rs module docs, "only for a
        // uuid no read file mentions ... patch servers outside the host
        // allowlist ... does the ledger's own recorded wiring decide"): a
        // NON-allowlisted host is how a staging patch server run without
        // `--patch-server-url` looks, so a ledger whose pom.xml still pins
        // `-socket.<hex8>` under a `socket-patch-<uuid>` repository keeps
        // the claim alive. With verification on, the installed tree is
        // still the evidence — nothing installed is `package_not_found`
        // (the not-installed lockfile basis is only for DISCOVERED refs)
        // and a pristine served jar is `not_applied` — so nothing attests.
        // Under `--no-verify` the ledger record attests: `--no-verify`
        // trusts the records, and the wiring gate cannot tell a staging
        // host from a hostile one — the limitation CLI_CONTRACT.md records
        // under "Patch hosts (manifest-less VEX)".
        let (code, env) = fx.vex(&["--offline"]);
        assert_omitted(code, &env, MVN_PURL, "package_not_found", label);
        let sfx_dir = fx.m2().join(format!("org/slf4j/slf4j-api/{MVN_SUFFIXED}"));
        put(
            &sfx_dir,
            &format!("slf4j-api-{MVN_SUFFIXED}.pom"),
            b"<project/>",
        );
        put(
            &sfx_dir,
            &format!("slf4j-api-{MVN_SUFFIXED}.jar"),
            MVN_PRISTINE,
        );
        let (code, env) = fx.vex(&["--offline"]);
        assert_omitted(code, &env, MVN_PURL, "not_applied", label);
        let (code, env) = fx.vex(&["--offline", "--no-verify"]);
        assert_eq!(code, Some(0), "{label}: documented staging fallback: {env}");
    }
}

/// DOCUMENTED LIMITATION (maven extractor, R6): the LEGACY same-GAV hosted
/// fallback (no `mavenSuffixedVersion`: the pom keeps the original version
/// and only adds the Socket repository) never yields a reference — Maven
/// may resolve that GAV from the local repo or Central, so it is no
/// fail-closed pin. Without a manifest it cannot attest, and a ledger
/// record for it is dead (the repository mentions the uuid, no pin does).
/// Missed attestation, never a false one.
#[test]
fn maven_legacy_same_gav_fallback_is_not_attested() {
    let fx = Fx::new();
    copy_golden(&fx, "maven/pom/no-suffix-fallback/expected");
    let api = Api::serve(vec![(MVN_HOSTED_UUID, mvn_hosted_view())]);
    let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
    assert_nothing_to_attest(code, &env, "legacy same-GAV");
    write_redirect_ledger(
        &fx,
        MVN_PURL,
        record(MVN_HOSTED_UUID, &mvn_files()),
        &[("pom.xml", "redirect_maven_pom")],
    );
    let (code, env) = fx.vex(&["--offline", "--no-verify"]);
    assert_omitted(code, &env, MVN_PURL, "redirect_unwired", "legacy + ledger");
}

// ══════════════════════════════════════════════════════════════════════════
// VENDORED — `vendor::maven_repo` (a committed maven2 file:// repository)
// ══════════════════════════════════════════════════════════════════════════

/// One vendored package: how to wire it, where its artifact lives, what its
/// record hashes (zip MEMBERS of the committed `.jar` / `.nupkg`).
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
    fn maven() -> Self {
        Vendored {
            eco: "maven",
            purl: MVN_VENDOR_PURL,
            record_purl: MVN_VENDOR_PURL,
            uuid: MVN_VENDOR_UUID,
            artifact_rel: format!(
                ".socket/vendor/maven/{MVN_VENDOR_UUID}/org/apache/commons/commons-text/\
                 1.10.0/commons-text-1.10.0.jar"
            ),
            member: "META-INF/NOTICE.txt",
            wiring_file: "pom.xml",
            wiring_kind: "maven_pom_repository",
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
        self.put_jar(fx, &bytes);
        bytes
    }

    /// Commit `bytes` as the artifact jar with the `.sha1` sidecar
    /// `vendor_maven` writes beside it (`checksumPolicy=fail` validates it,
    /// so it is part of the wiring).
    fn put_jar(&self, fx: &Fx, bytes: &[u8]) {
        use sha1::{Digest as _, Sha1};
        fx.put(&self.artifact_rel, bytes);
        fx.put(
            &format!("{}.sha1", self.artifact_rel),
            hex::encode(Sha1::digest(bytes)),
        );
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

/// `vendor_maven`'s pom: the ORIGINAL dependency version plus the
/// `socket-patch-vendor-<uuid>` file:// repository (`url` spelling varies).
fn vendored_pom(url: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
         <modelVersion>4.0.0</modelVersion>\n  <groupId>com.example</groupId>\n  \
         <artifactId>app</artifactId>\n  <version>1.0.0</version>\n  <dependencies>\n    \
         <dependency>\n      <groupId>org.apache.commons</groupId>\n      \
         <artifactId>commons-text</artifactId>\n      <version>1.10.0</version>\n    \
         </dependency>\n  </dependencies>\n  <repositories>\n    <repository>\n      \
         <id>socket-patch-vendor-{MVN_VENDOR_UUID}</id>\n      <url>{url}</url>\n      \
         <releases>\n        <enabled>true</enabled>\n        \
         <checksumPolicy>fail</checksumPolicy>\n      </releases>\n      \
         <snapshots>\n        <enabled>false</enabled>\n      </snapshots>\n    \
         </repository>\n  </repositories>\n</project>\n"
    )
}

fn registry_pom() -> String {
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
     <modelVersion>4.0.0</modelVersion>\n  <groupId>com.example</groupId>\n  \
     <artifactId>app</artifactId>\n  <version>1.0.0</version>\n  <dependencies>\n    \
     <dependency>\n      <groupId>org.apache.commons</groupId>\n      \
     <artifactId>commons-text</artifactId>\n      <version>1.10.0</version>\n    \
     </dependency>\n  </dependencies>\n</project>\n"
        .to_string()
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
    let other_purl = "pkg:maven/org.apache.commons/commons-lang3@1.10.0";
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

    // (e) with the ledger: a tampered member is caught too (the ledger's
    // whole-file sha256 is checked first for file-shaped artifacts).
    let good = std::fs::read(fx.cwd.join(&v.artifact_rel)).unwrap();
    let tampered = zip_bytes(&[
        (v.member, b"tampered NOTICE\n"),
        ("extra/unpatched.txt", b"x"),
    ]);
    v.put_jar(&fx, &tampered);
    let (code, env) = fx.vex(&["--offline"]);
    assert_eq!(code, Some(1), "{what}: {env}");
    let reason = skipped_reason(&env, v.purl);
    assert!(
        reason == "vendor_hash_mismatch" || reason == "vendor_sha256_mismatch",
        "{what}: tampered artifact with ledger: {reason}: {env}"
    );
    v.put_jar(&fx, &good);

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
fn maven_vendored_every_url_spelling_attests_without_manifest_or_ledgers() {
    let v = Vendored::maven();
    for prefix in [
        "file://${project.basedir}/",
        "file:${project.basedir}/",
        "file://${basedir}/",
        "file:${basedir}/",
    ] {
        for suffix in ["", "/"] {
            let url = format!("{prefix}.socket/vendor/maven/{MVN_VENDOR_UUID}{suffix}");
            vendored_cells(
                &v,
                &url,
                &|fx, _| fx.put("pom.xml", vendored_pom(&url)),
                &|fx| fx.put("pom.xml", registry_pom()),
            );
        }
    }
}

/// Cell e (vendored, the consumption gate): the committed jar intact (its
/// members still hash-verify) but its `.sha1` sidecar stale or missing.
/// Maven's `checksumPolicy=fail` rejects the file:// copy and resolves the
/// next repository — Central's pristine jar (proven against real Maven by
/// `e2e_vendor_maven_build`) — so the wiring is not what runs: no reference
/// without a ledger (nothing to attest, zero requests), and a ledger claim
/// is dead (`vendor_unwired`), with or without `--no-verify`.
#[test]
fn maven_vendored_stale_or_missing_sidecar_is_not_consumed() {
    let v = Vendored::maven();
    let sidecar = format!("{}.sha1", v.artifact_rel);
    for label in ["stale", "missing"] {
        let fx = Fx::new();
        v.write_artifact(&fx, MEMBER_PATCHED);
        fx.put(
            "pom.xml",
            vendored_pom(&format!(
                "file://${{project.basedir}}/.socket/vendor/maven/{MVN_VENDOR_UUID}"
            )),
        );
        if label == "stale" {
            fx.put(&sidecar, "0".repeat(40));
        } else {
            fx.rm(&sidecar);
        }
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

/// The vendored tree is the product the build consumes — an installed
/// store copy (pristine, e.g. from before vendoring) does not block the
/// attestation (it is disclosed as out of sync, never judged).
#[test]
fn vendored_attestation_ignores_a_pristine_store_copy() {
    let v = Vendored::maven();
    let fx = Fx::new();
    v.write_artifact(&fx, MEMBER_PATCHED);
    fx.put(
        "pom.xml",
        vendored_pom(&format!(
            "file://${{project.basedir}}/.socket/vendor/maven/{MVN_VENDOR_UUID}"
        )),
    );
    let dir = fx.m2().join("org/apache/commons/commons-text/1.10.0");
    put(&dir, "commons-text-1.10.0.pom", b"<project/>");
    put(
        &dir,
        "commons-text-1.10.0.jar",
        &zip_bytes(&[(v.member, MEMBER_PRISTINE)]),
    );
    let api = Api::serve(vec![(v.uuid, v.view())]);
    let (code, env) = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(&fx, code, &env, v.uuid, v.record_purl, "vendored");
}

/// Cell f (vendored): a `socket-patch-vendor-<uuid>` repository whose url leaves the project's `.socket/vendor/<eco>/<uuid>` tree
/// (absolute, `../`, another ecosystem's dir, another uuid's dir) is not
/// this project's committed artifact — not a reference; with a ledger for
/// the uuid the claim is dead.
#[test]
fn vendored_spoofed_locations_never_attest() {
    let mvn = Vendored::maven();
    let other = "12121212-3434-4565-8787-909090909090";
    let cases: Vec<(&Vendored, &str, &str, String)> = vec![
        (
            &mvn,
            "maven absolute",
            "pom.xml",
            vendored_pom(&format!(
                "file:///tmp/.socket/vendor/maven/{MVN_VENDOR_UUID}"
            )),
        ),
        (
            &mvn,
            "maven traversal",
            "pom.xml",
            vendored_pom(&format!(
                "file://${{project.basedir}}/../.socket/vendor/maven/{MVN_VENDOR_UUID}"
            )),
        ),
        (
            &mvn,
            "maven other ecosystem",
            "pom.xml",
            vendored_pom(&format!(
                "file://${{project.basedir}}/.socket/vendor/npm/{MVN_VENDOR_UUID}"
            )),
        ),
        (
            &mvn,
            "maven id/url uuid mismatch",
            "pom.xml",
            vendored_pom(&format!(
                "file://${{project.basedir}}/.socket/vendor/maven/{other}"
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

    /// Declare `eco` in the manifest's `setup.manual` (CLI_CONTRACT property
    /// 7): maven has no install hook, so agent-mode patches are attested
    /// only for an ecosystem the user declares they `apply` by hand.
    fn declare_manual(&self, eco: &str) {
        let path = self.cwd.join(".socket/manifest.json");
        let mut manifest: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        manifest["setup"] = serde_json::json!({ "manual": [eco] });
        std::fs::write(&path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
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

/// A plausible upstream pom for the cached artifact (the maven vendor
/// backend copies it verbatim next to the rebuilt jar).
const COMMONS_TEXT_POM: &str = "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
    <modelVersion>4.0.0</modelVersion>\n  <groupId>org.apache.commons</groupId>\n  \
    <artifactId>commons-text</artifactId>\n  <version>1.10.0</version>\n</project>\n";

#[test]
fn maven_vendor_command_wiring_reattests_without_manifest_or_ledger() {
    let fx = Fx::new();
    let v = Vendored::maven();
    let cached = fx.m2().join("org/apache/commons/commons-text/1.10.0");
    put(
        &cached,
        "commons-text-1.10.0.pom",
        COMMONS_TEXT_POM.as_bytes(),
    );
    put(
        &cached,
        "commons-text-1.10.0.jar",
        &zip_bytes(&[
            (v.member, MEMBER_PRISTINE),
            (
                "org/apache/commons/text/StringSubstitutor.class",
                b"\xca\xfe\xba\xbe",
            ),
        ]),
    );
    fx.put("pom.xml", registry_pom());
    fx.stage_manifest(MVN_VENDOR_PURL, MVN_VENDOR_UUID, &v.files());

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
        MVN_VENDOR_UUID,
        MVN_VENDOR_PURL,
        "vendored",
    );
    let pom = std::fs::read_to_string(fx.cwd.join("pom.xml")).unwrap();
    assert!(
        pom.contains(&format!("<id>socket-patch-vendor-{MVN_VENDOR_UUID}</id>")),
        "{pom}"
    );
    assert!(fx.cwd.join(&v.artifact_rel).is_file(), "{}", v.artifact_rel);

    standalone_after_writer(
        &fx,
        ".socket/vendor/state.json",
        MVN_VENDOR_UUID,
        MVN_VENDOR_PURL,
        "vendored",
        v.view(),
        &|fx| fx.put("pom.xml", registry_pom()),
        "vendor_unwired",
    );
}

/// The authenticated API `scan --mode hosted` drives: batch discovery, the
/// by-package listing, the hosted reference grant (from the committed
/// rewriter golden's `overrides.json`), and the patch view.
fn serve_hosted_api(golden: &str, purl: &str, uuid: &str, view_body: Value) -> Api {
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
    Api { rt, server }
}

fn scan_hosted_vex(fx: &Fx, api: &Api) -> (Option<i32>, Value, String) {
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

/// `scan --mode hosted --vex` against a project whose pristine base
/// version is cached: the real rewriter pins `-socket.<hex8>`, the in-run
/// VEX attests; the pristine base is never the consumed copy, so the
/// standalone vex keeps attesting from the pin with no manifest/ledger.
#[test]
fn maven_scan_hosted_wiring_reattests_without_manifest_or_ledger() {
    let golden = "maven/pom/basic";
    let fx = Fx::new();
    copy_golden(&fx, &format!("{golden}/input"));
    let base = fx.m2().join("org/slf4j/slf4j-api/1.7.36");
    put(&base, "slf4j-api-1.7.36.pom", b"<project><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>1.7.36</version></project>");
    put(&base, MVN_JAR_KEY, MVN_PRISTINE);
    let api = serve_hosted_api(golden, MVN_PURL, MVN_HOSTED_UUID, mvn_hosted_view());
    let (code, env, stderr) = scan_hosted_vex(&fx, &api);
    assert_eq!(code, Some(0), "scan --mode hosted --vex: {env}\n{stderr}");
    assert_doc_attests(&fx.embedded_doc(), MVN_HOSTED_UUID, MVN_PURL, "redirected");
    let pom = std::fs::read_to_string(fx.cwd.join("pom.xml")).unwrap();
    assert!(
        pom.contains(&format!("<version>{MVN_SUFFIXED}</version>")),
        "{pom}"
    );
    let reverted =
        std::fs::read_to_string(fixture_dir(&format!("{golden}/input/pom.xml"))).unwrap();
    standalone_after_writer(
        &fx,
        ".socket/vendor/redirect-state.json",
        MVN_HOSTED_UUID,
        MVN_PURL,
        "redirected",
        mvn_hosted_view(),
        &|fx| fx.put("pom.xml", &reverted),
        "redirect_unwired",
    );
}

/// DOCUMENTED LIMITATION (design scope): an AGENT-mode patch (`apply`
/// rewrites the installed jar in place) has no lockfile wiring — only the
/// manifest records it. `apply --vex` attests it; with the manifest gone
/// nothing names the patch, so the standalone vex has nothing to attest.
#[test]
fn maven_apply_vex_attests_but_agent_mode_needs_the_manifest() {
    let fx = Fx::new();
    fx.put(
        "pom.xml",
        std::fs::read(fixture_dir("maven/pom/basic/input/pom.xml")).unwrap(),
    );
    let base = fx.m2().join("org/slf4j/slf4j-api/1.7.36");
    put(&base, "slf4j-api-1.7.36.pom", b"<project><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>1.7.36</version></project>");
    put(&base, MVN_JAR_KEY, MVN_PRISTINE);
    fx.stage_manifest(MVN_PURL, MVN_HOSTED_UUID, &mvn_files());
    fx.declare_manual("maven");
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
        format!("Patched via Socket patch {MVN_HOSTED_UUID}"),
        "agent mode carries no provenance marker: {doc}"
    );
    assert_eq!(std::fs::read(base.join(MVN_JAR_KEY)).unwrap(), MVN_PATCHED);
    let (code, env) = fx.vex(&["--offline"]);
    assert_eq!(code, Some(0), "with the manifest: {env}");
    fx.rm(".socket/manifest.json");
    let (code, env) = fx.vex(&["--offline"]);
    assert_nothing_to_attest(code, &env, "agent mode without the manifest");
}
