//! Bun hosted unwinds in a project with its own registries (#992), through
//! the built binary: `bunfig.toml` `[install] registry` for `left-pad` and
//! an `[install.scopes]` entry for `@corp/widget`. Bun writes the full
//! tarball URL into a `bun.lock` registry slot for any registry but npmjs,
//! and Bun 1.1.39–1.3.6 read an empty slot as npmjs whatever bunfig says,
//! so every unwind of a hosted pin — `remove <purl>`, and the hosted →
//! vendored takeover that `vendor --revert` later returns to — must give
//! back the URL Bun wrote, read from each package's own registry.
//!
//! Each registry's version document advertises an off-path (CDN-style)
//! tarball URL, so a restore that read the wrong registry, or fell back to
//! the default one and re-based its conventional URL, cannot land on the
//! pristine bytes by accident. The default registry (`SOCKET_NPM_REGISTRY`,
//! the shared mirror) does not know `@corp/widget` at all, and the scope's
//! registry is private: it answers 401 unless the restore sends the
//! `[install.scopes]` entry's token, as Bun does.

use std::path::Path;

use serde_json::{json, Value};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::{
    assert_no_event_code, find_event, hosted_line, line_integrity, lock_line, patch_record, read,
    run_json, vendor_cli, write_bun_project, HOSTED_URL, LEFT_PAD_REGISTRY_LINE, NAME,
    PATCHED_INDEX, PATCHED_SHA512, PURL, UUID, VERSION,
};

const SCOPED_NAME: &str = "@corp/widget";
const SCOPED_VERSION: &str = "2.0.0";
const SCOPED_PURL: &str = "pkg:npm/@corp/widget@2.0.0";
const SCOPED_UUID: &str = "3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f";
const SCOPED_HOSTED_URL: &str = "https://patch.socket.dev/patch/npm/@corp/widget/2.0.0/55555555-5555-4555-8555-555555555555/3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f/widget-2.0.0.tgz";
const SCOPED_INTEGRITY: &str = "sha512-corpWIDGETcorp0123456789==";
const SCOPED_PATCHED_SHA512: &str = "sha512-corpPATCHEDcorp0123456789==";
/// The `@corp` scope registry's token, from `bunfig.toml`.
const SCOPE_TOKEN: &str = "corp-secret-token";

/// The project's registries, all on one wiremock: the bunfig default
/// registry (`/mirror/`) and the `@corp` scope's (`/corp/`).
struct Registries {
    server: MockServer,
}

impl Registries {
    async fn start() -> Self {
        let server = MockServer::start().await;
        let registries = Self { server };
        let mirror_doc = json!({
            "name": NAME,
            "version": VERSION,
            "dist": {
                "tarball": registries.mirror_tarball(),
                "integrity": line_integrity(LEFT_PAD_REGISTRY_LINE),
            }
        });
        Mock::given(method("GET"))
            .and(path(format!("/mirror/{NAME}/{VERSION}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(mirror_doc))
            .mount(&registries.server)
            .await;
        // Bun and npm ask for a scoped document as `@scope%2fname`. The
        // private scope registry serves it only with the scope's token.
        Mock::given(method("GET"))
            .and(path_regex(r"^/corp/"))
            .respond_with(ResponseTemplate::new(401))
            .with_priority(10)
            .mount(&registries.server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/corp/@corp(%2[fF]|/)widget/2\.0\.0$"))
            .and(header(
                "authorization",
                format!("Bearer {SCOPE_TOKEN}").as_str(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": SCOPED_NAME,
                "version": SCOPED_VERSION,
                "dist": {
                    "tarball": registries.scoped_tarball(),
                    "integrity": SCOPED_INTEGRITY,
                }
            })))
            .with_priority(1)
            .mount(&registries.server)
            .await;
        registries
    }

    fn mirror_tarball(&self) -> String {
        format!(
            "{}/mirror-cdn/files/{NAME}-{VERSION}.tgz",
            self.server.uri()
        )
    }

    fn scoped_tarball(&self) -> String {
        format!("{}/corp-cdn/widget/{SCOPED_VERSION}.tgz", self.server.uri())
    }

    fn bunfig(&self) -> String {
        let uri = self.server.uri();
        format!(
            "[install]\nregistry = \"{uri}/mirror/\"\n\n\
             [install.scopes]\ncorp = {{ url = \"{uri}/corp/\", token = \"{SCOPE_TOKEN}\" }}\n"
        )
    }

    /// The registry lines Bun writes for this project: each slot holds the
    /// tarball URL of the registry the package resolved against.
    fn left_pad_line(&self) -> String {
        LEFT_PAD_REGISTRY_LINE.replace("\"\", {}", &format!("\"{}\", {{}}", self.mirror_tarball()))
    }

    fn scoped_line(&self) -> String {
        format!(
            "    \"{SCOPED_NAME}\": [\"{SCOPED_NAME}@{SCOPED_VERSION}\", \"{}\", {{}}, \"{SCOPED_INTEGRITY}\"],",
            self.scoped_tarball()
        )
    }

    /// The Bun-written registry lock (lockfileVersion 2) for both packages.
    fn pristine_lock(&self) -> String {
        format!(
            "{{\n  \"lockfileVersion\": 2,\n  \"configVersion\": 1,\n  \"workspaces\": {{\n    \"\": {{\n      \"name\": \"bun-takeover-fixture\",\n      \"dependencies\": {{\n        \"{SCOPED_NAME}\": \"{SCOPED_VERSION}\",\n        \"left-pad\": \"1.3.0\",\n      }},\n    }},\n  }},\n  \"packages\": {{\n{}\n\n{}\n  }}\n}}\n",
            self.scoped_line(),
            self.left_pad_line(),
        )
    }
}

/// A project with both packages pinned hosted, as `scan --mode hosted`
/// leaves it (the lock's URL 3-tuples, no ledger) beside its bunfig.toml;
/// returns the pristine registry lock.
fn write_hosted_project(root: &Path, registries: &Registries) -> String {
    let pristine = registries.pristine_lock();
    write_bun_project(
        root,
        &pristine,
        &[(NAME, VERSION), (SCOPED_NAME, SCOPED_VERSION)],
    );
    std::fs::write(root.join("bunfig.toml"), registries.bunfig()).unwrap();
    let hosted = pristine
        .replace(
            &registries.left_pad_line(),
            &hosted_line(NAME, NAME, HOSTED_URL, PATCHED_SHA512),
        )
        .replace(
            &registries.scoped_line(),
            &hosted_line(
                SCOPED_NAME,
                SCOPED_NAME,
                SCOPED_HOSTED_URL,
                SCOPED_PATCHED_SHA512,
            ),
        );
    assert!(
        !hosted.contains("/mirror-cdn/") && !hosted.contains("/corp-cdn/"),
        "both lines are hosted:\n{hosted}"
    );
    std::fs::write(root.join("bun.lock"), &hosted).unwrap();
    pristine
}

/// `.socket/manifest.json` with both records + the after-hash blob, the
/// records `vendor` takes over.
fn seed_manifest(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut bytes = serde_json::to_vec_pretty(&json!({ "patches": {
        PURL: patch_record(UUID),
        SCOPED_PURL: patch_record(SCOPED_UUID),
    }}))
    .unwrap();
    bytes.push(b'\n');
    std::fs::write(socket.join("manifest.json"), &bytes).unwrap();
    std::fs::write(
        socket
            .join("blobs")
            .join(compute_git_sha256_from_bytes(PATCHED_INDEX)),
        PATCHED_INDEX,
    )
    .unwrap();
}

fn assert_no_registry_fallback(env: &Value) {
    assert!(
        !env.to_string().contains("upstream_registry_fallback"),
        "every registry was readable: {env:#}"
    );
    assert!(
        !env.to_string().contains(SCOPE_TOKEN),
        "the scope's token is never reported: {env:#}"
    );
}

/// `remove <purl>` of each hosted pin in turn restores its line with the
/// tarball URL of the registry Bun resolved it against — the bunfig
/// default registry for `left-pad`, the `[install.scopes]` registry for
/// `@corp/widget` — landing on the pristine lock byte for byte.
#[tokio::test(flavor = "multi_thread")]
async fn bun_remove_restores_the_bunfig_and_scope_registry_tarball_urls() {
    let registries = Registries::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let pristine = write_hosted_project(root, &registries);
    let cwd = root.to_str().unwrap();

    let (code, env) = run_json(root, &["remove", PURL, "--yes", "--json", "--cwd", cwd]);
    assert_eq!(code, 0, "remove left-pad: {env:#}");
    assert!(env["error"].is_null(), "{env:#}");
    assert_no_registry_fallback(&env);
    let lock = read(root, "bun.lock");
    assert_eq!(
        lock_line(&lock, NAME),
        lock_line(&pristine, NAME),
        "left-pad's slot is the bunfig registry's tarball URL:\n{lock}"
    );
    assert!(
        lock_line(&lock, SCOPED_NAME).contains(SCOPED_HOSTED_URL),
        "the scoped pin stays hosted:\n{lock}"
    );

    let (code, env) = run_json(
        root,
        &["remove", SCOPED_PURL, "--yes", "--json", "--cwd", cwd],
    );
    assert_eq!(code, 0, "remove @corp/widget: {env:#}");
    assert!(env["error"].is_null(), "{env:#}");
    assert_no_registry_fallback(&env);
    assert_eq!(
        read(root, "bun.lock"),
        pristine,
        "the scope's tarball URL is restored and the lock is pristine"
    );
}

/// The hosted → vendored takeover restores both registry lines (with their
/// registries' tarball URLs) before vendoring, records them as the vendor
/// ledger's originals, and `vendor --revert` returns the pristine lock.
#[tokio::test(flavor = "multi_thread")]
async fn bun_takeover_then_vendor_revert_keeps_the_bunfig_and_scope_registry_urls() {
    let registries = Registries::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let pristine = write_hosted_project(root, &registries);
    seed_manifest(root);

    let (code, env) = vendor_cli(root, &[]);
    assert_eq!(code, 0, "vendor over the hosted pins: {env:#}");
    assert_eq!(env["summary"]["applied"], 2, "{env:#}");
    find_event(&env, "skipped", Some("vendor_takeover_reverted_redirect"));
    assert_no_event_code(&env, "redirect_revert_failed");
    assert_no_registry_fallback(&env);
    let lock = read(root, "bun.lock");
    assert!(
        !lock.contains(HOSTED_URL) && !lock.contains(SCOPED_HOSTED_URL),
        "no hosted pin is left:\n{lock}"
    );

    let state: Value = serde_json::from_str(&read(root, ".socket/vendor/state.json")).unwrap();
    for (purl, key) in [(PURL, NAME), (SCOPED_PURL, SCOPED_NAME)] {
        let original = state["entries"][purl]["wiring"]
            .as_array()
            .and_then(|w| w.iter().find(|r| r["kind"] == "bun_lock_package"))
            .map(|r| r["original"].clone())
            .unwrap_or_else(|| panic!("{purl}: bun_lock_package wiring: {state:#}"));
        assert_eq!(
            original,
            json!(lock_line(&pristine, key)),
            "{purl}: the ledger's original carries the registry's tarball URL: {state:#}"
        );
    }

    let (code, env) = vendor_cli(root, &["--revert"]);
    assert_eq!(code, 0, "vendor --revert: {env:#}");
    assert_eq!(
        read(root, "bun.lock"),
        pristine,
        "the revert lands on the Bun-written registry lock"
    );
}
