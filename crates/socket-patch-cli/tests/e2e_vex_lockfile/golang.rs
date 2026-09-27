//! Manifest-less `socket-patch vex` for Go modules: hosted
//! (`patch.socket.dev/gopatch/<uuid>` replace pinned by go.sum) and vendored
//! (`./.socket/vendor/golang/<uuid>/M@v` replace) patches must attest from
//! `go.mod` / `go.work` alone, with NO `.socket/manifest.json` and (unless a
//! cell says otherwise) NO `.socket/vendor/state.json` or
//! `.socket/vendor/redirect-state.json` — and must never attest falsely.
//!
//! Hermetic: every run gets a private, EMPTY `GOMODCACHE` / `GOPATH` (an
//! ambient module-cache copy must not decide a verdict), the patch API is a
//! wiremock stand-in serving `GET /patch/view/<uuid>` (the unauthenticated
//! public-proxy route), and no `go` toolchain is needed. Runs on every OS in
//! the default `test` job; the real-toolchain flows (every Go release the
//! matrix pins) live in `e2e_golang_hosted_build.rs`,
//! `e2e_vendor_golang_build.rs`, `e2e_golang_build.rs` and
//! `e2e_golang_workspace_build.rs`.
//!
//! Cells, per the manifest-less VEX design:
//!
//! * **a** no manifest, no ledgers, online → one statement for the replaced
//!   module's purl with the record's vuln id + CVE alias and the
//!   `(redirected)` / `(vendored)` marker; exit 0; `verified` envelope events.
//! * **b** `--offline` (or an API that cannot serve the record) with no local
//!   record → `record_unavailable`, exit 1, and ZERO requests reach the API
//!   under `--offline`.
//! * **c** ledger present, manifest absent → attests offline from the
//!   ledger's embedded record.
//! * **d** wiring reverted / made inert while the ledger / artifact stay
//!   → `redirect_unwired` / `vendor_unwired`, with and without `--no-verify`.
//! * **e** tampered replacement module in the cache (hosted) / tampered
//!   committed artifact member (vendored) → omitted (`hash_mismatch` /
//!   `vendor_hash_mismatch`).
//! * **f** spoofing: a uuid-shaped segment outside the fixed
//!   `patch.socket.dev/gopatch/` namespace (hosted) or a non-root-anchored
//!   vendor path (vendored) is not a reference; a record whose purl or uuid
//!   differs from the wiring is `record_mismatch`.
//! * **g** (hosted) not installed → attests from the go.sum pin (design D5);
//!   the replacement module installed-and-patched → verified; that copy
//!   pristine → omitted; a pin-less reference needs a verifying copy.
//!
//! Flavors: `go.mod` single-line replace, `replace ( … )` block member,
//! hand-written `go.work` (+ `go.work.sum`), the committed hosted rewriter
//! golden, go.mod/go.work disagreement (`wiring_conflict`), and `apply`'s
//! go-patches redirect (no uuid — a documented limitation, asserted below).
//! Embedded: `scan --vex` and `apply --vex` on a manifest-less project.

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

const GO_MODULE: &str = "github.com/foo/bar";
const GO_VERSION: &str = "v1.4.2";
const GO_SVER: &str = "v1.4.2-socketpatch.1";
const GO_PURL: &str = "pkg:golang/github.com/foo/bar@v1.4.2";
/// Well-formed go.sum dirhashes (the committed rewriter golden's).
const GO_H1_ZIP: &str = "h1:mU9vN/n1hbXktM62lJ6MbRKOk3aI8NDH+szCf62RXtE=";
const GO_H1_MOD: &str = "h1:XgagPTRZSCprrzR+3Ro36/XJpibdovhAbsKThYI8bxg=";

const PRISTINE_GO: &[u8] = b"package bar // pristine\n";
const PATCHED_GO: &[u8] = b"package bar // patched\n";

// ── harness ───────────────────────────────────────────────────────────

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_socket-patch")
}

/// A project under `<tmp>/app` plus private (empty unless a test fills them)
/// module cache and GOPATH.
struct Fx {
    _tmp: tempfile::TempDir,
    cwd: PathBuf,
    gomodcache: PathBuf,
    gopath: PathBuf,
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
        let gomodcache = tmp.path().join("gomodcache");
        let gopath = tmp.path().join("gopath");
        for dir in [&cwd, &gomodcache, &gopath] {
            std::fs::create_dir_all(dir).unwrap();
        }
        Fx {
            _tmp: tmp,
            cwd,
            gomodcache,
            gopath,
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
            .env("GOMODCACHE", &self.gomodcache)
            .env("GOPATH", &self.gopath)
            .env_remove("GOFLAGS")
            .env_remove("VIRTUAL_ENV");
        cmd
    }

    /// `vex --cwd <app> --json --output <app>/out.vex.json --product …`.
    fn vex(&self, extra: &[&str]) -> Run {
        self.vex_in(&self.cwd, extra)
    }

    /// [`Self::vex`] with `--cwd <dir>` (a workspace member, say).
    fn vex_in(&self, dir: &Path, extra: &[&str]) -> Run {
        let out_path = dir.join("out.vex.json");
        let _ = std::fs::remove_file(&out_path);
        let mut args: Vec<String> = [
            "vex",
            "--cwd",
            dir.to_str().unwrap(),
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

    /// Install a Go module into the private module cache.
    fn install_module(&self, module: &str, version: &str, bar: &[u8]) {
        put(&self.gomodcache, &format!("{module}@{version}/bar.go"), bar);
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

fn go_view(uuid: &str) -> Value {
    view(uuid, GO_PURL, "bar.go", PRISTINE_GO, PATCHED_GO)
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

fn go_record(uuid: &str) -> PatchRecord {
    record(uuid, "bar.go", PRISTINE_GO, PATCHED_GO)
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

const GO_HOSTED_EDITS: &[(&str, &str)] = &[
    ("go.mod", "redirect_golang_replace"),
    ("go.sum", "redirect_golang_gosum"),
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

// ── golang fixtures ───────────────────────────────────────────────────

fn go_socket_module(uuid: &str) -> String {
    format!("patch.socket.dev/gopatch/{uuid}")
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(clippy::enum_variant_names)] // the Go file each flavor edits
enum GoFile {
    /// Single-line `replace` in `go.mod` (what both writers emit).
    GoMod,
    /// The same directive as a `replace ( … )` block member.
    GoModBlock,
    /// A hand-written `go.work` beside the module's `go.mod`.
    GoWork,
}

const GO_FILES: [GoFile; 3] = [GoFile::GoMod, GoFile::GoModBlock, GoFile::GoWork];

fn go_mod(require_version: &str, replace: Option<&str>, block: bool) -> String {
    let mut text =
        format!("module example.com/app\n\ngo 1.21\n\nrequire {GO_MODULE} {require_version}\n");
    match (replace, block) {
        (Some(rhs), false) => {
            text.push_str(&format!("\nreplace {GO_MODULE} {GO_VERSION} => {rhs}\n"))
        }
        (Some(rhs), true) => text.push_str(&format!(
            "\nreplace (\n\t{GO_MODULE} {GO_VERSION} => {rhs}\n)\n"
        )),
        (None, _) => {}
    }
    text
}

fn go_sum_lines(uuid: &str) -> String {
    let m = go_socket_module(uuid);
    format!("{m} {GO_SVER} {GO_H1_ZIP}\n{m} {GO_SVER}/go.mod {GO_H1_MOD}\n")
}

/// Wire `rhs` for `M v` in `file`'s shape; `sum` (the hosted pin lines) goes
/// to `go.sum` / `go.work.sum` accordingly.
fn write_go_replace(fx: &Fx, file: GoFile, rhs: &str, sum: Option<&str>) {
    match file {
        GoFile::GoMod | GoFile::GoModBlock => {
            fx.put(
                "go.mod",
                go_mod(GO_VERSION, Some(rhs), file == GoFile::GoModBlock),
            );
            if let Some(sum) = sum {
                fx.put("go.sum", sum);
            }
        }
        GoFile::GoWork => {
            fx.put("go.mod", go_mod(GO_VERSION, None, false));
            fx.put(
                "go.work",
                format!("go 1.21\n\nuse .\n\nreplace {GO_MODULE} {GO_VERSION} => {rhs}\n"),
            );
            if let Some(sum) = sum {
                fx.put("go.work.sum", sum);
            }
        }
    }
}

/// The hosted golang rewrite: `replace M v => patch.socket.dev/gopatch/<uuid>
/// <sver>` pinned by both go.sum lines.
fn write_go_hosted(fx: &Fx, uuid: &str, file: GoFile) {
    let rhs = format!("{} {GO_SVER}", go_socket_module(uuid));
    write_go_replace(fx, file, &rhs, Some(&go_sum_lines(uuid)));
}

fn go_artifact(uuid: &str) -> String {
    format!(".socket/vendor/golang/{uuid}/{GO_MODULE}@{GO_VERSION}")
}

/// The `vendor` golang backend: the patched module copy and the
/// `./.socket/vendor/golang/<uuid>/M@v` replace.
fn write_go_vendored(fx: &Fx, uuid: &str, file: GoFile, bar: &[u8]) {
    let rel = go_artifact(uuid);
    fx.put(&format!("{rel}/bar.go"), bar);
    fx.put(
        &format!("{rel}/go.mod"),
        format!("module {GO_MODULE}\n\ngo 1.21\n"),
    );
    write_go_replace(fx, file, &format!("./{rel}"), None);
}

/// The committed go.mod-only artifact file list the patch record names.
fn go_vendored_record(uuid: &str) -> PatchRecord {
    go_record(uuid)
}

/// A committed hosted-rewriter golden (`socket-patch-core/tests/fixtures/
/// redirect/<rel>`).
fn redirect_fixture(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../socket-patch-core/tests/fixtures/redirect")
        .join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// ══════════════════════════════════════════════════════════════════════
// golang × hosted
// ══════════════════════════════════════════════════════════════════════

/// a + g(not installed): go.mod (line / block) and go.work flavors attest
/// `(redirected)` for the ORIGINAL module's purl.
#[test]
fn golang_hosted_a_attests_every_flavor_without_manifest_or_ledgers() {
    let api = Api::start(vec![(U, go_view(U))]);
    for file in GO_FILES {
        let fx = Fx::new();
        write_go_hosted(&fx, U, file);
        let run = fx.vex(&["--proxy-url", &api.uri()]);
        assert_attested(&fx, &run, GO_PURL, U, "redirected", &format!("{file:?}"));
        assert!(warning_codes(&run).is_empty(), "{file:?}: {}", run.env);
    }
}

/// a: the committed rewriter golden (`golang/gomod/basic/expected`).
#[test]
fn golang_hosted_a_rewriter_golden_attests_its_uuid() {
    const GOLDEN_U: &str = "55555555-5555-5555-5555-555555555555";
    let fx = Fx::new();
    for file in ["go.mod", "go.sum"] {
        fx.put(
            file,
            redirect_fixture(&format!("golang/gomod/basic/expected/{file}")),
        );
    }
    let api = Api::start(vec![(GOLDEN_U, go_view(GOLDEN_U))]);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(&fx, &run, GO_PURL, GOLDEN_U, "redirected", "golden");
}

#[test]
fn golang_hosted_b_without_a_record_is_record_unavailable() {
    for file in GO_FILES {
        let fx = Fx::new();
        write_go_hosted(&fx, U, file);
        let api = Api::start(vec![(U, go_view(U))]);
        let run = fx.vex(&["--offline", "--proxy-url", &api.uri()]);
        assert_omitted(&run, GO_PURL, "record_unavailable", &format!("{file:?}"));
        assert_eq!(
            api.hits(),
            0,
            "{file:?}: --offline must make no network call"
        );
    }
    let fx = Fx::new();
    write_go_hosted(&fx, U, GoFile::GoMod);
    let empty = Api::start(vec![]);
    let run = fx.vex(&["--proxy-url", &empty.uri()]);
    assert_omitted(&run, GO_PURL, "record_unavailable", "API 404");
}

#[test]
fn golang_hosted_c_ledger_record_attests_offline() {
    let fx = Fx::new();
    write_go_hosted(&fx, U, GoFile::GoMod);
    write_redirect_ledger(&fx, GO_PURL, go_record(U), GO_HOSTED_EDITS);
    for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
        let run = fx.vex(extra);
        assert_attested(&fx, &run, GO_PURL, U, "redirected", &format!("{extra:?}"));
    }
    fx.install_module(&go_socket_module(U), GO_SVER, PATCHED_GO);
    let run = fx.vex(&["--offline"]);
    assert_attested(&fx, &run, GO_PURL, U, "redirected", "installed replacement");
}

/// d: the replace removed (go.sum lines left), the `require` bumped past the
/// replaced version (the replace is inert: go builds the unpatched
/// module), and the replace pointed back at a user fork → `redirect_unwired`.
#[test]
fn golang_hosted_d_reverted_wiring_never_keeps_the_ledger_alive() {
    let rhs = format!("{} {GO_SVER}", go_socket_module(U));
    let shapes: [(&str, String); 3] = [
        ("replace removed", go_mod(GO_VERSION, None, false)),
        ("require bumped", go_mod("v1.5.0", Some(&rhs), false)),
        (
            "replace re-pointed at a fork",
            go_mod(GO_VERSION, Some("github.com/me/bar v1.4.2-fork"), false),
        ),
    ];
    for (name, gomod) in shapes {
        let fx = Fx::new();
        write_go_hosted(&fx, U, GoFile::GoMod);
        fx.put("go.mod", gomod);
        write_redirect_ledger(&fx, GO_PURL, go_record(U), GO_HOSTED_EDITS);
        fx.install_module(&go_socket_module(U), GO_SVER, PATCHED_GO);
        for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
            let run = fx.vex(extra);
            assert_omitted(
                &run,
                GO_PURL,
                "redirect_unwired",
                &format!("{name} {extra:?}"),
            );
        }
    }
}

#[test]
fn golang_hosted_e_tampered_replacement_module_is_omitted() {
    let fx = Fx::new();
    write_go_hosted(&fx, U, GoFile::GoMod);
    fx.install_module(&go_socket_module(U), GO_SVER, b"package bar // tampered\n");
    let api = Api::start(vec![(U, go_view(U))]);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_omitted(&run, GO_PURL, "hash_mismatch", "tampered replacement");
    write_redirect_ledger(&fx, GO_PURL, go_record(U), GO_HOSTED_EDITS);
    let run = fx.vex(&["--offline"]);
    assert_omitted(&run, GO_PURL, "hash_mismatch", "tampered, ledger");
}

/// f: the Go hosted namespace is fixed (`patch.socket.dev/gopatch/<uuid>`):
/// a lookalike host, a grant-token path shape, or an upper-case uuid is not
/// something Socket writes and never a reference — even for the configured
/// `--patch-server-url` origin; records naming another package or patch are
/// `record_mismatch`.
#[test]
fn golang_hosted_f_spoofed_references_never_attest() {
    let api = Api::start(vec![(U, go_view(U))]);
    let upper = U.to_ascii_uppercase();
    for (name, module) in [
        ("lookalike host", format!("evil.example/gopatch/{U}")),
        (
            "grant-token shape",
            format!("patch.socket.dev/gopatch/{TOKEN}/{U}"),
        ),
        (
            "upper-case uuid",
            format!("patch.socket.dev/gopatch/{upper}"),
        ),
    ] {
        let fx = Fx::new();
        let rhs = format!("{module} {GO_SVER}");
        fx.put("go.mod", go_mod(GO_VERSION, Some(&rhs), false));
        fx.put(
            "go.sum",
            format!("{module} {GO_SVER} {GO_H1_ZIP}\n{module} {GO_SVER}/go.mod {GO_H1_MOD}\n"),
        );
        let run = fx.vex(&["--proxy-url", &api.uri()]);
        assert_ne!(run.code, Some(0), "{name}: {}", run.env);
        assert!(run.doc.is_none(), "{name}");
        let run = fx.vex(&["--proxy-url", &api.uri(), "--patch-server-url", &api.uri()]);
        assert_ne!(
            run.code,
            Some(0),
            "{name} + --patch-server-url: {}",
            run.env
        );
    }
    assert_eq!(api.hits(), 0, "no spoofed module was ever fetched");

    let other_pkg = view(
        U,
        "pkg:golang/github.com/foo/baz@v1.4.2",
        "bar.go",
        PRISTINE_GO,
        PATCHED_GO,
    );
    for (name, body) in [
        ("other package", other_pkg),
        ("other uuid", go_view(OTHER_U)),
    ] {
        let fx = Fx::new();
        write_go_hosted(&fx, U, GoFile::GoMod);
        let api = Api::start(vec![(U, body)]);
        let run = fx.vex(&["--proxy-url", &api.uri()]);
        assert_omitted(&run, GO_PURL, "record_mismatch", name);
    }
}

/// g: only the pristine ORIGINAL `M@v` cached → not installed (the build
/// never reads it) → the go.sum pin attests; the replacement patched →
/// verified; the replacement pristine → omitted; no go.sum pin → needs the
/// verifying replacement.
#[test]
fn golang_hosted_g_installed_copy_basis() {
    let api = Api::start(vec![(U, go_view(U))]);
    let uri = api.uri();
    let args = ["--proxy-url", uri.as_str()];

    let fx = Fx::new();
    write_go_hosted(&fx, U, GoFile::GoMod);
    fx.install_module(GO_MODULE, GO_VERSION, PRISTINE_GO);
    let run = fx.vex(&args);
    assert_attested(
        &fx,
        &run,
        GO_PURL,
        U,
        "redirected",
        "pristine original only",
    );

    fx.install_module(&go_socket_module(U), GO_SVER, PATCHED_GO);
    let run = fx.vex(&args);
    assert_attested(&fx, &run, GO_PURL, U, "redirected", "replacement patched");

    fx.install_module(&go_socket_module(U), GO_SVER, PRISTINE_GO);
    let run = fx.vex(&args);
    assert_omitted(&run, GO_PURL, "not_applied", "replacement pristine");

    // No (or an incomplete) go.sum pin.
    for (name, sum) in [
        ("no go.sum", None),
        (
            "zip line only",
            Some(format!("{} {GO_SVER} {GO_H1_ZIP}\n", go_socket_module(U))),
        ),
    ] {
        let fx = Fx::new();
        write_go_hosted(&fx, U, GoFile::GoMod);
        match &sum {
            Some(sum) => fx.put("go.sum", sum),
            None => fx.rm("go.sum"),
        }
        let run = fx.vex(&args);
        assert_omitted(&run, GO_PURL, "package_not_found", name);
        fx.install_module(&go_socket_module(U), GO_SVER, PATCHED_GO);
        let run = fx.vex(&args);
        assert_attested(
            &fx,
            &run,
            GO_PURL,
            U,
            "redirected",
            &format!("{name}, verified"),
        );
    }
}

// ══════════════════════════════════════════════════════════════════════
// golang × vendored
// ══════════════════════════════════════════════════════════════════════

#[test]
fn golang_vendored_a_attests_every_flavor_without_manifest_or_ledgers() {
    let api = Api::start(vec![(U, go_view(U))]);
    for file in GO_FILES {
        let fx = Fx::new();
        write_go_vendored(&fx, U, file, PATCHED_GO);
        let run = fx.vex(&["--proxy-url", &api.uri()]);
        assert_attested(&fx, &run, GO_PURL, U, "vendored", &format!("{file:?}"));
        assert!(warning_codes(&run).is_empty(), "{file:?}: {}", run.env);
    }
}

/// a: the vendored copy is what builds even with a pristine `M@v` in the
/// module cache (a directory replace bypasses the cache entirely).
#[test]
fn golang_vendored_a_ignores_a_pristine_module_cache_copy() {
    let fx = Fx::new();
    write_go_vendored(&fx, U, GoFile::GoMod, PATCHED_GO);
    fx.install_module(GO_MODULE, GO_VERSION, PRISTINE_GO);
    let api = Api::start(vec![(U, go_view(U))]);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(&fx, &run, GO_PURL, U, "vendored", "pristine cache copy");
    // …and that immutable cache copy is not "drift" to disclose.
    assert!(warning_codes(&run).is_empty(), "{}", run.env);
}

#[test]
fn golang_vendored_b_without_a_record_is_record_unavailable() {
    for file in GO_FILES {
        let fx = Fx::new();
        write_go_vendored(&fx, U, file, PATCHED_GO);
        let api = Api::start(vec![(U, go_view(U))]);
        let run = fx.vex(&["--offline", "--proxy-url", &api.uri()]);
        assert_omitted(&run, GO_PURL, "record_unavailable", &format!("{file:?}"));
        assert_eq!(
            api.hits(),
            0,
            "{file:?}: --offline must make no network call"
        );
    }
}

#[test]
fn golang_vendored_c_ledger_record_attests_offline() {
    let fx = Fx::new();
    write_go_vendored(&fx, U, GoFile::GoMod, PATCHED_GO);
    write_vendor_ledger(
        &fx,
        "golang",
        GO_PURL,
        U,
        &go_artifact(U),
        Some(go_vendored_record(U)),
        &[("go.mod", "go_replace")],
    );
    for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
        let run = fx.vex(extra);
        assert_attested(&fx, &run, GO_PURL, U, "vendored", &format!("{extra:?}"));
    }
}

/// d: the replace removed, the `require` bumped (inert replace), or the
/// replace re-pointed at another dir — artifact + ledger left behind →
/// `vendor_unwired`.
#[test]
fn golang_vendored_d_reverted_wiring_never_keeps_the_ledger_alive() {
    let rhs = format!("./{}", go_artifact(U));
    let shapes: [(&str, String); 3] = [
        ("replace removed", go_mod(GO_VERSION, None, false)),
        ("require bumped", go_mod("v1.5.0", Some(&rhs), false)),
        (
            "replace re-pointed",
            go_mod(GO_VERSION, Some("./third_party/bar"), false),
        ),
    ];
    for (name, gomod) in shapes {
        let fx = Fx::new();
        write_go_vendored(&fx, U, GoFile::GoMod, PATCHED_GO);
        fx.put("go.mod", gomod);
        write_vendor_ledger(
            &fx,
            "golang",
            GO_PURL,
            U,
            &go_artifact(U),
            Some(go_vendored_record(U)),
            &[("go.mod", "go_replace")],
        );
        for extra in [&["--offline"][..], &["--offline", "--no-verify"][..]] {
            let run = fx.vex(extra);
            assert_omitted(
                &run,
                GO_PURL,
                "vendor_unwired",
                &format!("{name} {extra:?}"),
            );
        }
    }
}

#[test]
fn golang_vendored_e_tampered_artifact_member_is_omitted() {
    let fx = Fx::new();
    write_go_vendored(&fx, U, GoFile::GoMod, b"package bar // tampered\n");
    let api = Api::start(vec![(U, go_view(U))]);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_omitted(&run, GO_PURL, "vendor_hash_mismatch", "ledger-less");
    write_vendor_ledger(
        &fx,
        "golang",
        GO_PURL,
        U,
        &go_artifact(U),
        Some(go_vendored_record(U)),
        &[("go.mod", "go_replace")],
    );
    let run = fx.vex(&["--offline"]);
    assert_omitted(&run, GO_PURL, "vendor_hash_mismatch", "ledger");
}

/// f: a replace target outside the root (`../`), a leaf naming another
/// module/version, and records that disagree with the wiring.
#[test]
fn golang_vendored_f_spoofed_references_never_attest() {
    let api = Api::start(vec![(U, go_view(U))]);
    for (name, rhs) in [
        ("parent-relative", format!("../other/{}", go_artifact(U))),
        (
            "leaf names another version",
            format!("./.socket/vendor/golang/{U}/{GO_MODULE}@v1.4.1"),
        ),
    ] {
        let fx = Fx::new();
        write_go_vendored(&fx, U, GoFile::GoMod, PATCHED_GO);
        fx.put("go.mod", go_mod(GO_VERSION, Some(&rhs), false));
        let run = fx.vex(&["--proxy-url", &api.uri()]);
        assert_ne!(run.code, Some(0), "{name}: {}", run.env);
        assert!(run.doc.is_none(), "{name}");
    }
    let other_pkg = view(
        U,
        "pkg:golang/github.com/foo/baz@v1.4.2",
        "bar.go",
        PRISTINE_GO,
        PATCHED_GO,
    );
    for (name, body) in [
        ("other package", other_pkg),
        ("other uuid", go_view(OTHER_U)),
    ] {
        let fx = Fx::new();
        write_go_vendored(&fx, U, GoFile::GoMod, PATCHED_GO);
        let api = Api::start(vec![(U, body)]);
        let run = fx.vex(&["--proxy-url", &api.uri()]);
        assert_omitted(&run, GO_PURL, "record_mismatch", name);
    }
}

// ══════════════════════════════════════════════════════════════════════
// golang × go-patches (apply's redirect) and go.work precedence
// ══════════════════════════════════════════════════════════════════════

/// LIMITATION (documented, golang extractor): `apply`'s
/// `./.socket/go-patches/M@v` replace carries NO patch uuid, so without a
/// manifest (or a ledger) there is nothing to resolve a record from —
/// `vex` finds no reference (exit 2). This is agent mode, whose record owner
/// IS the manifest; with the manifest present it attests (covered by
/// `e2e_vex_vendor::golang_go_patches_redirect_attested_without_module_cache`).
#[test]
fn golang_go_patches_without_manifest_is_not_discoverable() {
    let fx = Fx::new();
    let rel = format!(".socket/go-patches/{GO_MODULE}@{GO_VERSION}");
    fx.put(&format!("{rel}/bar.go"), PATCHED_GO);
    fx.put(
        "go.mod",
        go_mod(GO_VERSION, Some(&format!("./{rel}")), false),
    );
    let api = Api::start(vec![(U, go_view(U))]);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_nothing_discovered(&run, "go-patches, no manifest");
    assert_eq!(api.hits(), 0);
}

/// go.mod and go.work wiring the same module to DIFFERENT patches: which
/// one builds depends on how the build is invoked (`GOWORK=off`), so
/// neither attests — one `wiring_conflict` skip. The same patch in both
/// files is one consistent claim and attests.
#[test]
fn golang_go_mod_and_go_work_disagreeing_attest_neither() {
    let fx = Fx::new();
    write_go_hosted(&fx, U, GoFile::GoMod);
    let other_rhs = format!("./{}", go_artifact(OTHER_U));
    fx.put(
        "go.work",
        format!("go 1.21\n\nuse .\n\nreplace {GO_MODULE} {GO_VERSION} => {other_rhs}\n"),
    );
    fx.put(&format!("{}/bar.go", go_artifact(OTHER_U)), PATCHED_GO);
    let api = Api::start(vec![(U, go_view(U)), (OTHER_U, go_view(OTHER_U))]);
    let uri = api.uri();
    for extra in [&[][..], &["--no-verify"][..]] {
        let mut args = vec!["--proxy-url", uri.as_str()];
        args.extend_from_slice(extra);
        let run = fx.vex(&args);
        assert_omitted(&run, GO_PURL, "wiring_conflict", &format!("{extra:?}"));
    }

    let fx = Fx::new();
    write_go_hosted(&fx, U, GoFile::GoMod);
    fx.put(
        "go.work",
        format!(
            "go 1.21\n\nuse .\n\nreplace {GO_MODULE} {GO_VERSION} => {} {GO_SVER}\n",
            go_socket_module(U)
        ),
    );
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(
        &fx,
        &run,
        GO_PURL,
        U,
        "redirected",
        "same patch in both files",
    );
}

/// A hand-written go.work replace whose pin lines stayed in the root
/// go.sum (go reads both sum files in workspace mode): still pinned, still
/// attested; the vendored twin needs no pin.
#[test]
fn golang_go_work_replace_pinned_by_root_go_sum_attests() {
    let api = Api::start(vec![(U, go_view(U))]);
    let fx = Fx::new();
    write_go_hosted(&fx, U, GoFile::GoWork);
    let sums = fx_read(&fx, "go.work.sum");
    fx.rm("go.work.sum");
    fx.put("go.sum", sums);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_attested(&fx, &run, GO_PURL, U, "redirected", "go.work + go.sum pin");
}

/// LIMITATION (documented, root-only discovery): a Socket replace in a
/// workspace MEMBER's go.mod (e.g. `get --mode hosted --cwd tools`) is not
/// read from the workspace root — vex there finds nothing (exit 2, no false
/// document) — while `vex --cwd tools` (that module's root) attests it.
#[test]
fn golang_member_module_wiring_attests_from_its_own_root_only() {
    let api = Api::start(vec![(U, go_view(U)), (OTHER_U, go_view(OTHER_U))]);
    for vendored in [false, true] {
        let fx = Fx::new();
        fx.put("go.mod", "module example.com/app\n\ngo 1.21\n");
        fx.put("go.work", "go 1.21\n\nuse (\n\t.\n\t./tools\n)\n");
        let member = fx.cwd.join("tools");
        let rhs = if vendored {
            let rel = go_artifact(U);
            put(&member, &format!("{rel}/bar.go"), PATCHED_GO);
            put(
                &member,
                &format!("{rel}/go.mod"),
                format!("module {GO_MODULE}\n\ngo 1.21\n").as_bytes(),
            );
            format!("./{rel}")
        } else {
            put(&member, "go.sum", go_sum_lines(U).as_bytes());
            format!("{} {GO_SVER}", go_socket_module(U))
        };
        put(
            &member,
            "go.mod",
            go_mod(GO_VERSION, Some(&rhs), false).as_bytes(),
        );
        let what = if vendored { "vendored" } else { "hosted" };
        let run = fx.vex(&["--proxy-url", &api.uri()]);
        assert_nothing_discovered(&run, &format!("{what}: workspace root"));
        let run = fx.vex_in(&member, &["--proxy-url", &api.uri()]);
        let marker = if vendored { "vendored" } else { "redirected" };
        assert_eq!(run.code, Some(0), "{what}: member root: {}", run.env);
        let st = &run.doc.as_ref().unwrap()["statements"][0];
        assert_eq!(
            st["products"][0]["subcomponents"][0]["@id"], GO_PURL,
            "{st}"
        );
        assert_eq!(
            st["impact_statement"],
            format!("Patched via Socket patch {U} ({marker})"),
            "{st}"
        );
    }
}

fn fx_read(fx: &Fx, rel: &str) -> String {
    std::fs::read_to_string(fx.cwd.join(rel)).unwrap()
}

// ══════════════════════════════════════════════════════════════════════
// hosted + vendored together, and embedded VEX
// ══════════════════════════════════════════════════════════════════════

const GO_MODULE_2: &str = "github.com/foo/baz";
const GO_PURL_2: &str = "pkg:golang/github.com/foo/baz@v1.4.2";

/// One go.mod wiring `bar` hosted and `baz` vendored (the two backends
/// coexist per module): both attest, each with its own marker.
fn write_go_mixed(fx: &Fx, hosted_u: &str, vendored_u: &str) {
    let smod = go_socket_module(hosted_u);
    let art = format!(".socket/vendor/golang/{vendored_u}/{GO_MODULE_2}@{GO_VERSION}");
    fx.put(&format!("{art}/bar.go"), PATCHED_GO);
    fx.put(
        &format!("{art}/go.mod"),
        format!("module {GO_MODULE_2}\n\ngo 1.21\n"),
    );
    fx.put(
        "go.mod",
        format!(
            "module example.com/app\n\ngo 1.21\n\nrequire (\n\t{GO_MODULE} {GO_VERSION}\n\t{GO_MODULE_2} {GO_VERSION}\n)\n\n\
             replace {GO_MODULE} {GO_VERSION} => {smod} {GO_SVER}\n\n\
             replace {GO_MODULE_2} {GO_VERSION} => ./{art}\n"
        ),
    );
    fx.put("go.sum", go_sum_lines(hosted_u));
}

#[test]
fn golang_hosted_and_vendored_modules_attest_together() {
    const U2: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    let baz = view(U2, GO_PURL_2, "bar.go", PRISTINE_GO, PATCHED_GO);
    let api = Api::start(vec![(U, go_view(U)), (U2, baz)]);
    let fx = Fx::new();
    write_go_mixed(&fx, U, U2);
    let run = fx.vex(&["--proxy-url", &api.uri()]);
    assert_eq!(run.code, Some(0), "{}", run.env);
    let doc = run.doc.unwrap();
    // Both patches fix the same GHSA, so the builder emits ONE statement
    // naming both subcomponents, each patch's provenance in the impact.
    assert_eq!(
        subcomponents(&doc),
        vec![GO_PURL.to_string(), GO_PURL_2.to_string()],
        "{doc}"
    );
    let impact = doc["statements"][0]["impact_statement"].as_str().unwrap();
    assert!(
        impact.contains(&format!("Patched via Socket patch {U} (redirected)"))
            && impact.contains(&format!("Patched via Socket patch {U2} (vendored)")),
        "{impact}"
    );
}

/// Embedded `scan --vex` (read-only scan) on a manifest-less, ledger-less
/// go project: the scan attests the same patches standalone `vex` does,
/// and folds the summary into its envelope.
#[test]
fn embedded_scan_vex_attests_go_mod_wired_patches() {
    const U2: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    let baz = view(U2, GO_PURL_2, "bar.go", PRISTINE_GO, PATCHED_GO);
    let api = Api::start(vec![(U, go_view(U)), (U2, baz)]);
    let fx = Fx::new();
    write_go_mixed(&fx, U, U2);
    let out_path = fx.cwd.join("scan.vex.json");
    let scan = |uri: &str| {
        let out = fx
            .command()
            .args([
                "scan",
                "--cwd",
                fx.cwd.to_str().unwrap(),
                "--json",
                "--proxy-url",
                uri,
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
    assert_eq!(
        subcomponents(&doc),
        vec![GO_PURL.to_string(), GO_PURL_2.to_string()],
        "{doc}"
    );
    assert!(!fx.cwd.join(".socket/manifest.json").exists());

    // An API that serves no patch views (scan itself refuses `--offline`):
    // nothing can attest → the requested VEX fails the scan.
    let empty = Api::start(vec![]);
    let (code, env) = scan(&empty.uri());
    assert_eq!(code, Some(1), "{env}");
    assert_eq!(env["error"]["code"], "no_applicable_patches", "{env}");
    assert!(!out_path.exists(), "the stale document is removed");
}

/// Embedded `apply --vex` on a manifest-less go project (hosted `bar`,
/// vendored `baz`): there is nothing for `apply` itself to do, but the
/// requested document must still be produced; offline it fails the command.
#[test]
fn embedded_apply_vex_attests_go_mod_wired_patches_without_manifest() {
    const U2: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    let baz = view(U2, GO_PURL_2, "bar.go", PRISTINE_GO, PATCHED_GO);
    let api = Api::start(vec![(U, go_view(U)), (U2, baz)]);
    let fx = Fx::new();
    write_go_mixed(&fx, U, U2);
    let out_path = fx.cwd.join("apply.vex.json");
    let apply = |extra: &[&str]| {
        let _ = std::fs::remove_file(&out_path);
        let mut args = vec![
            "apply".to_string(),
            "--cwd".to_string(),
            fx.cwd.to_str().unwrap().to_string(),
            "--json".to_string(),
            "--vex".to_string(),
            out_path.to_str().unwrap().to_string(),
            "--vex-product".to_string(),
            PRODUCT.to_string(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        let out = fx.command().args(&args).output().expect("invoke apply");
        let env: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "apply JSON ({e}). stdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code(), env)
    };

    let (code, env) = apply(&["--proxy-url", &api.uri()]);
    assert_eq!(code, Some(0), "{env}");
    assert_eq!(env["status"], "noManifest", "{env}");
    assert_eq!(env["vex"]["statements"], 1, "one GHSA statement: {env}");
    let doc: Value = serde_json::from_slice(&std::fs::read(&out_path).unwrap()).unwrap();
    assert_eq!(
        subcomponents(&doc),
        vec![GO_PURL.to_string(), GO_PURL_2.to_string()],
        "{doc}"
    );
    assert!(!fx.cwd.join(".socket/manifest.json").exists());

    // Offline: nothing can attest — the requested VEX fails the command.
    let (code, env) = apply(&["--offline"]);
    assert_eq!(code, Some(1), "{env}");
    assert_eq!(env["error"]["code"], "no_applicable_patches", "{env}");
    assert!(!out_path.exists());
}
