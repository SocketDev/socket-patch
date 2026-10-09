//! v5 vendor over a HOSTED binary `bun.lockb` (Bun <= 1.1.x's default lock,
//! and the legacy lock Bun 1.2 keeps reading).
//!
//! Hosted mode keeps no ledger, so vendoring over a hosted pin first
//! restores the pin's upstream registry entry — for a binary lock, the
//! native codec rebuilds Bun's npm registry record from the registry's
//! `dist.tarball` / `dist.integrity`. Both entry points are covered: the
//! per-purl takeover (`vendor` with the patch record staged) and the eject
//! (`vendor` in a manifest-less hosted project). Each vendors, records the
//! REGISTRY record as the vendor ledger's pre-vendor original, and
//! `vendor --revert` returns the exact pre-hosted bytes (a format-1 lock the
//! hosted rewrite promoted is demoted back; a lock whose workspace behaviors
//! it normalized is refused with the checkout remedy). `rollback` of the
//! hosted pin still refuses with the `git checkout -- bun.lockb` remedy, as
//! does an offline vendor (the registry cannot be asked).
//!
//! The locks are real Bun-written fixtures
//! (`socket-patch-core/tests/fixtures/bun-lockb`), wired hosted by the
//! production binary rewriter; no `bun` binary is needed. Every run goes
//! through the built binary with a scrubbed environment: the API, the npm
//! registry (`SOCKET_NPM_REGISTRY`) and the patch-server origin
//! (`SOCKET_PATCH_SERVER_URL`) all point at a wiremock.

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use serde_json::{json, Value};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::patch::redirect::{rewrite_bun_binary, DepOverride, RewriteResult};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const GRANT: &str = "55555555-5555-4555-8555-555555555555";
const PURL: &str = "pkg:npm/minimist@1.2.2";
const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";
/// The public registry's `dist` for minimist@1.2.2 — what every fixture pins.
const UPSTREAM_TARBALL: &str = "https://registry.npmjs.org/minimist/-/minimist-1.2.2.tgz";
const UPSTREAM_INTEGRITY: &str =
    "sha512-rIqbOrKb8GJmx/5bc2M0QchhUouMXSpd1RTclXsB41JdL+VtnojfaJR+h7F9k18/4kHUsBFgk80Uk+q569vjPA==";

fn fixture(dir: &str, file: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../socket-patch-core/tests/fixtures/bun-lockb")
            .join(dir)
            .join(file),
    )
    .unwrap()
}

struct Project {
    tmp: tempfile::TempDir,
    server: MockServer,
    /// The Bun-written lock before the hosted rewrite.
    pristine: Vec<u8>,
}

impl Project {
    fn root(&self) -> &Path {
        self.tmp.path()
    }

    fn lock(&self) -> Vec<u8> {
        assert!(
            !self.root().join("bun.lock").exists(),
            "the CLI must never write a text bun.lock"
        );
        std::fs::read(self.root().join("bun.lockb")).unwrap()
    }

    fn hosted_url(&self) -> String {
        format!(
            "{}/patch/npm/minimist/1.2.2/{GRANT}/{UUID}/minimist-1.2.2.tgz",
            self.server.uri()
        )
    }

    fn run_json(&self, args: &[&str]) -> (i32, Value) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
        cmd.args(args)
            .args(["--json", "--cwd"])
            .arg(self.root())
            .current_dir(self.root());
        for (key, _) in std::env::vars() {
            if key.starts_with("SOCKET_") {
                cmd.env_remove(key);
            }
        }
        // A registry exported by npm (`npm_config_registry`) or Bun would
        // steer the takeover's restore off the fixtures' registry (#992).
        for key in [
            "BUN_CONFIG_REGISTRY",
            "NPM_CONFIG_REGISTRY",
            "npm_config_registry",
        ] {
            cmd.env_remove(key);
        }
        let uri = self.server.uri();
        cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
            .env("SOCKET_API_URL", &uri)
            .env("SOCKET_API_TOKEN", "fake-token")
            .env("SOCKET_ORG_SLUG", ORG)
            .env("SOCKET_NPM_REGISTRY", &uri)
            .env("SOCKET_PATCH_SERVER_URL", &uri)
            .env("SOCKET_VENDOR_SOURCE", "service");
        let out = cmd.output().expect("spawn socket-patch");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let env = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!(
                "--json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code().unwrap_or(-1), env)
    }
}

fn record() -> Value {
    json!({
        "uuid": UUID,
        "purl": PURL,
        "exportedAt": "2026-01-01T00:00:00Z",
        "publishedAt": "2026-01-01T00:00:00Z",
        "files": {
            "package/index.js": {
                "beforeHash": compute_git_sha256_from_bytes(ORIG_INDEX),
                "afterHash": compute_git_sha256_from_bytes(PATCHED_INDEX),
            }
        },
        "vulnerabilities": {},
        "description": "binary lock takeover fixture",
        "license": "MIT",
        "tier": "free"
    })
}

/// A project whose Bun-`writer`-written bun.lockb pins minimist@1.2.2 to the
/// mock hosted tarball (what `scan --mode hosted` leaves behind), with the
/// pristine package installed and the registry + record view mocked.
async fn hosted_project(writer: &str) -> Project {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let project = Project {
        tmp,
        server,
        pristine: fixture(writer, "bun.lockb"),
    };
    let root = project.root();
    std::fs::write(root.join("package.json"), fixture(writer, "package.json")).unwrap();
    for (name, version) in [("minimist", "1.2.2"), ("is-number", "7.0.0")] {
        let pkg = root.join("node_modules").join(name);
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            format!(r#"{{"name":"{name}","version":"{version}"}}"#),
        )
        .unwrap();
        std::fs::write(pkg.join("index.js"), ORIG_INDEX).unwrap();
    }
    let dep: DepOverride = serde_json::from_value(json!({
        "ecosystem": "npm",
        "name": "minimist",
        "version": "1.2.2",
        "token": GRANT,
        "patchUuid": UUID,
        "artifactUrl": project.hosted_url(),
        "integrity": { "sha512": format!(
            "sha512-{}", base64::engine::general_purpose::STANDARD.encode([42u8; 64])) }
    }))
    .unwrap();
    let mut rewrite = RewriteResult::default();
    rewrite_bun_binary(&project.pristine, &[dep], &mut rewrite);
    assert!(rewrite.warnings.is_empty(), "{:?}", rewrite.warnings);
    std::fs::write(root.join("bun.lockb"), &rewrite.binary_files["bun.lockb"]).unwrap();

    Mock::given(method("GET"))
        .and(path("/minimist/1.2.2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "minimist",
            "version": "1.2.2",
            "dist": { "tarball": UPSTREAM_TARBALL, "integrity": UPSTREAM_INTEGRITY }
        })))
        .mount(&project.server)
        .await;
    let mut view = record();
    view["files"]["package/index.js"]["blobContent"] =
        json!(base64::engine::general_purpose::STANDARD.encode(PATCHED_INDEX));
    prebuilt_common::mount_view(&project.server, &view, None).await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(view))
        .mount(&project.server)
        .await;
    project
}

/// `.socket/manifest.json` + the after-hash blob: the per-purl takeover
/// (instead of the manifest-less eject).
fn stage_record(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": { PURL: record() } })).unwrap(),
    )
    .unwrap();
    std::fs::write(
        socket
            .join("blobs")
            .join(compute_git_sha256_from_bytes(PATCHED_INDEX)),
        PATCHED_INDEX,
    )
    .unwrap();
}

fn codes(env: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["events", "warnings"] {
        for e in env[key].as_array().into_iter().flatten() {
            for field in ["errorCode", "code"] {
                if let Some(c) = e[field].as_str() {
                    out.push(c.to_string());
                }
            }
        }
    }
    out
}

/// The vendored project's shared assertions: the lock is wired to the
/// committed artifact with no hosted residue, and the vendor ledger's
/// recorded original is the REGISTRY record.
fn assert_vendored(p: &Project, env: &Value) {
    let lock = p.lock();
    let text = String::from_utf8_lossy(&lock);
    assert!(
        text.contains(&format!(".socket/vendor/npm/{UUID}/minimist-1.2.2.tgz")),
        "bun.lockb is wired to the vendored artifact: {env:#}"
    );
    assert!(
        !text.contains(&p.server.uri()) && !text.contains(GRANT),
        "no hosted residue is left in bun.lockb"
    );
    assert!(p
        .root()
        .join(format!(".socket/vendor/npm/{UUID}/minimist-1.2.2.tgz"))
        .is_file());
    let state: Value =
        serde_json::from_slice(&std::fs::read(p.root().join(".socket/vendor/state.json")).unwrap())
            .unwrap();
    let original = state["entries"][PURL]["wiring"]
        .as_array()
        .and_then(|w| w.iter().find(|r| r["kind"] == "bun_lockb_package"))
        .map(|r| r["original"].clone())
        .unwrap_or_else(|| panic!("bun_lockb_package wiring: {state:#}"));
    assert_eq!(original["name"], "minimist", "{original}");
    assert_eq!(original["version"], "1.2.2", "{original}");
    assert_eq!(original["resolution"], UPSTREAM_TARBALL, "{original}");
    assert_eq!(original["integrity"], UPSTREAM_INTEGRITY, "{original}");
}

/// Bun 0.1.1 / 0.1.6 (binary format 1, which the hosted rewrite promotes to
/// format 2 and the takeover's restore demotes again), 0.8.1 (uninitialized
/// record padding), 1.1.38 (the last binary-only writer) and 1.2.0 (the
/// legacy lock Bun 1.2 keeps): the takeover vendors over the hosted pin, and
/// the revert gives back the pre-hosted bytes.
#[tokio::test]
async fn takeover_vendors_over_a_hosted_bun_lockb_and_reverts_exactly() {
    for writer in ["0.1.1", "0.1.6", "0.8.1", "1.1.38", "1.2.0"] {
        let p = hosted_project(writer).await;
        stage_record(p.root());
        let hosted = p.lock();

        let (code, env) = p.run_json(&["vendor", "--dry-run"]);
        assert_eq!(code, 0, "{writer}: dry run: {env:#}");
        assert!(
            codes(&env)
                .iter()
                .any(|c| c == "vendor_would_revert_redirect"),
            "{writer}: {env:#}"
        );
        assert_eq!(p.lock(), hosted, "{writer}: a dry run writes nothing");

        let (code, env) = p.run_json(&["vendor"]);
        assert_eq!(code, 0, "{writer}: vendor over the hosted pin: {env:#}");
        assert_eq!(env["status"], "success", "{writer}: {env:#}");
        assert_eq!(env["summary"]["applied"], 1, "{writer}: {env:#}");
        let codes = codes(&env);
        assert!(
            codes
                .iter()
                .any(|c| c == "vendor_takeover_reverted_redirect"),
            "{writer}: {env:#}"
        );
        assert!(
            !codes.iter().any(|c| c == "redirect_revert_failed"),
            "{writer}: {env:#}"
        );
        assert_vendored(&p, &env);

        let (code, env) = p.run_json(&["vendor", "--revert"]);
        assert_eq!(code, 0, "{writer}: revert: {env:#}");
        assert!(
            p.lock() == p.pristine,
            "{writer}: the revert restores the pre-hosted bun.lockb byte for byte"
        );
        assert_reinstall_advised(&env);
    }
}

/// The manifest-less eject over a hosted bun.lockb.
#[tokio::test]
async fn eject_vendors_a_hosted_bun_lockb_and_reverts_exactly() {
    let p = hosted_project("1.1.38").await;
    let (code, env) = p.run_json(&["vendor"]);
    assert_eq!(code, 0, "eject must succeed: {env:#}");
    assert_eq!(env["summary"]["applied"], 1, "{env:#}");
    assert_vendored(&p, &env);
    assert!(!p.root().join(".socket/manifest.json").exists());
    let (code, env) = p.run_json(&["vendor", "--revert"]);
    assert_eq!(code, 0, "revert: {env:#}");
    assert!(p.lock() == p.pristine, "exact pre-hosted bytes");
    assert_reinstall_advised(&env);
}

/// #764: the revert put minimist's registry record back while the hoisted
/// `node_modules/minimist` still holds the vendored bytes, which a plain
/// `bun install` keeps: the envelope carries exactly one per-entry advisory
/// naming `bun install --force`.
fn assert_reinstall_advised(env: &Value) {
    let advisories: Vec<&Value> = env["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["errorCode"] == "vendor_bun_reinstall_required")
        .collect();
    assert_eq!(advisories.len(), 1, "{env:#}");
    assert_eq!(advisories[0]["purl"], PURL, "{env:#}");
    let detail = advisories[0]["reason"].as_str().unwrap_or_default();
    assert!(
        detail.contains("minimist@1.2.2") && detail.contains("`bun install --force`"),
        "{env:#}"
    );
}

/// A hosted lock whose workspace dependency behaviors the rewrite had to
/// normalize cannot be given back byte for byte: the takeover refuses with
/// the checkout remedy (dry and wet alike) and writes nothing.
#[tokio::test]
async fn takeover_refuses_a_workspace_normalized_hosted_bun_lockb() {
    let p = hosted_project("1.1.45-extensions").await;
    stage_record(p.root());
    let hosted = p.lock();
    for extra in [&["--dry-run"][..], &[][..]] {
        let mut args = vec!["vendor"];
        args.extend_from_slice(extra);
        let (code, env) = p.run_json(&args);
        assert_eq!(code, 1, "{extra:?}: {env:#}");
        let refused = env["events"]
            .as_array()
            .and_then(|events| {
                events
                    .iter()
                    .find(|e| e["errorCode"] == "redirect_revert_failed")
            })
            .unwrap_or_else(|| panic!("expected redirect_revert_failed: {env:#}"));
        assert!(
            refused["error"]
                .as_str()
                .is_some_and(|e| e.contains("workspace dependency behaviors")
                    && e.contains("git checkout -- bun.lockb")),
            "{env:#}"
        );
        assert_eq!(
            p.lock(),
            hosted,
            "{extra:?}: a refused vendor writes nothing"
        );
        assert!(!p.root().join(".socket/vendor").exists());
    }
}

/// `rollback` of the hosted pin, and a vendor that cannot reach the
/// registry, refuse with the checkout remedy and write nothing.
#[tokio::test]
async fn rollback_and_offline_vendor_refuse_with_the_checkout_remedy() {
    let p = hosted_project("1.1.38").await;
    stage_record(p.root());
    let hosted = p.lock();

    let (code, env) = p.run_json(&["vendor", "--offline"]);
    assert_eq!(code, 1, "{env:#}");
    let refused = env["events"]
        .as_array()
        .and_then(|events| {
            events
                .iter()
                .find(|e| e["errorCode"] == "redirect_revert_failed")
        })
        .unwrap_or_else(|| panic!("expected redirect_revert_failed: {env:#}"));
    assert!(
        refused["error"]
            .as_str()
            .is_some_and(|e| e.contains("offline") && e.contains("git checkout -- bun.lockb")),
        "{env:#}"
    );
    assert_eq!(p.lock(), hosted, "a refused vendor writes nothing");
    assert!(!p.root().join(".socket/vendor").exists());

    let (code, env) = p.run_json(&["rollback", "--yes"]);
    assert_eq!(code, 1, "{env:#}");
    let failed = env["hosted"]["failed"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        failed.iter().any(|f| f["purl"] == PURL
            && f["error"]
                .as_str()
                .is_some_and(|e| e.contains("git checkout -- bun.lockb"))),
        "{env:#}"
    );
    assert_eq!(p.lock(), hosted, "a refused rollback writes nothing");
}

/// #992: in a project whose `bunfig.toml` names a mirror, the takeover
/// rebuilds the binary record with the tarball URL the mirror's version
/// document advertises (Bun fetches from the URL the record holds), the
/// vendor ledger keeps it as the original, and `vendor --revert` writes it
/// back. A second hosted → vendored → revert round trip from that lock
/// lands on it byte for byte.
#[tokio::test]
async fn takeover_and_revert_keep_the_bunfig_registry_tarball_url() {
    let p = hosted_project("1.1.38").await;
    // An off-path (CDN-style) URL: a restore that fell back to the default
    // registry and re-based its conventional URL cannot produce it.
    let mirror_tarball = format!("{}/mirror-cdn/minimist-1.2.2.tgz", p.server.uri());
    Mock::given(method("GET"))
        .and(path("/mirror/minimist/1.2.2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "minimist",
            "version": "1.2.2",
            "dist": { "tarball": mirror_tarball, "integrity": UPSTREAM_INTEGRITY }
        })))
        .mount(&p.server)
        .await;
    std::fs::write(
        p.root().join("bunfig.toml"),
        format!("[install]\nregistry = \"{}/mirror/\"\n", p.server.uri()),
    )
    .unwrap();
    stage_record(p.root());

    let mut reverted: Option<Vec<u8>> = None;
    for round in 0..2 {
        if let Some(lock) = &reverted {
            // Pin the mirror lock hosted again, as `scan --mode hosted` does.
            let dep: DepOverride = serde_json::from_value(json!({
                "ecosystem": "npm",
                "name": "minimist",
                "version": "1.2.2",
                "token": GRANT,
                "patchUuid": UUID,
                "artifactUrl": p.hosted_url(),
                "integrity": { "sha512": format!(
                    "sha512-{}", base64::engine::general_purpose::STANDARD.encode([42u8; 64])) }
            }))
            .unwrap();
            let mut rewrite = RewriteResult::default();
            rewrite_bun_binary(lock, &[dep], &mut rewrite);
            assert!(rewrite.warnings.is_empty(), "{:?}", rewrite.warnings);
            std::fs::write(
                p.root().join("bun.lockb"),
                &rewrite.binary_files["bun.lockb"],
            )
            .unwrap();
        }

        let (code, env) = p.run_json(&["vendor"]);
        assert_eq!(
            code, 0,
            "round {round}: vendor over the hosted pin: {env:#}"
        );
        assert_eq!(env["summary"]["applied"], 1, "round {round}: {env:#}");
        let codes = codes(&env);
        assert!(
            codes
                .iter()
                .any(|c| c == "vendor_takeover_reverted_redirect"),
            "round {round}: {env:#}"
        );
        assert!(
            !codes.iter().any(|c| c == "upstream_registry_fallback"),
            "round {round}: the mirror was readable: {env:#}"
        );
        let original = vendored_original(p.root());
        assert_eq!(
            original["resolution"], mirror_tarball,
            "round {round}: {original}"
        );
        assert_eq!(
            original["integrity"], UPSTREAM_INTEGRITY,
            "round {round}: {original}"
        );

        let (code, env) = p.run_json(&["vendor", "--revert"]);
        assert_eq!(code, 0, "round {round}: revert: {env:#}");
        let lock = p.lock();
        let text = String::from_utf8_lossy(&lock);
        // The string pool keeps the replaced npmjs URL as dead bytes (the
        // codec appends); the record references the mirror's.
        assert!(
            text.contains(&mirror_tarball),
            "round {round}: the reverted record fetches from the mirror"
        );
        assert!(
            !text.contains(GRANT) && !text.contains(".socket/vendor"),
            "round {round}: no hosted or vendored residue"
        );
        if let Some(first) = &reverted {
            assert!(
                &lock == first,
                "a mirror lock round-trips through hosted, vendored and revert byte for byte"
            );
        }
        reverted = Some(lock);
    }

    // The reverted lock's own record (what a plain vendor snapshots from
    // it) is the mirror's, not just a string left in its pool.
    let reverted = reverted.unwrap();
    let (code, env) = p.run_json(&["vendor"]);
    assert_eq!(code, 0, "vendor over the reverted lock: {env:#}");
    assert_eq!(vendored_original(p.root())["resolution"], mirror_tarball);
    let (code, env) = p.run_json(&["vendor", "--revert"]);
    assert_eq!(code, 0, "{env:#}");
    assert!(p.lock() == reverted, "the plain revert is exact");
}

/// The vendor ledger's recorded pre-vendor `bun_lockb_package` record.
fn vendored_original(root: &Path) -> Value {
    let state: Value =
        serde_json::from_slice(&std::fs::read(root.join(".socket/vendor/state.json")).unwrap())
            .unwrap();
    state["entries"][PURL]["wiring"]
        .as_array()
        .and_then(|w| w.iter().find(|r| r["kind"] == "bun_lockb_package"))
        .map(|r| r["original"].clone())
        .unwrap_or_else(|| panic!("bun_lockb_package wiring: {state:#}"))
}

/// A Bun workspace's member-relative mirror of the vendored tarball goes
/// missing while the canonical tarball still matches its ledger SHA-256:
/// an offline re-vendor rewrites the mirror from the committed tarball
/// rather than refusing to redownload an artifact it already holds.
#[tokio::test]
async fn offline_vendor_rewrites_a_missing_workspace_mirror() {
    let p = hosted_project("1.1.45-extensions").await;
    // The pre-hosted lock (`git checkout -- bun.lockb`): a plain vendor.
    std::fs::write(p.root().join("bun.lockb"), &p.pristine).unwrap();
    stage_record(p.root());
    let (code, env) = p.run_json(&["vendor"]);
    assert_eq!(code, 0, "{env:#}");
    let canonical = p
        .root()
        .join(format!(".socket/vendor/npm/{UUID}/minimist-1.2.2.tgz"));
    let mirror = p.root().join(format!(
        "packages/helper/.socket/vendor/npm/{UUID}/minimist-1.2.2.tgz"
    ));
    let tarball = std::fs::read(&canonical).unwrap();
    assert_eq!(std::fs::read(&mirror).unwrap(), tarball, "{env:#}");
    std::fs::remove_file(&mirror).unwrap();

    let (code, env) = p.run_json(&["vendor", "--offline"]);
    assert_eq!(code, 0, "{env:#}");
    assert!(
        !codes(&env).iter().any(|c| c == "vendor_redownload_failed"),
        "{env:#}"
    );
    assert_eq!(std::fs::read(&mirror).unwrap(), tarball);
    assert_eq!(std::fs::read(&canonical).unwrap(), tarball);
}
