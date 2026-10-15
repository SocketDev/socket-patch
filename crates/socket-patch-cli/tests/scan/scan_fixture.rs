//! Fixtures and runners shared by `scan_failure_paths.rs` (the `--json`
//! contracts), `scan_render.rs` (the human output) and `scan_tty.rs` (scan
//! on a real terminal) (#1089).
//!
//! Every run spawns the built binary through `common::hermetic_command`, so
//! the ambient `SOCKET_*` surface can't reroute the branch under test and
//! the runs need no serialization. Network tests use wiremock.

use std::path::Path;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::{binary, git_sha256, hermetic_command};

pub const ORG_SLUG: &str = "test-org";
pub const UUID: &str = "11111111-1111-4111-8111-111111111111";
pub const UUID_B: &str = "22222222-2222-4222-8222-222222222222";
pub const OLD_UUID: &str = "99999999-9999-4999-8999-999999999999";
/// The npm package most fixtures install and patch.
pub const MINIMIST: &str = "pkg:npm/minimist@1.2.2";

pub fn write_root_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "covgap-scan-root", "version": "0.0.0" }"#,
    )
    .unwrap();
}

pub fn write_npm_package(root: &Path, name: &str, version: &str, content: &[u8]) {
    let pkg_dir = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
    std::fs::write(pkg_dir.join("index.js"), content).unwrap();
}

/// A root `package.json` plus `node_modules/minimist@1.2.2` holding
/// `content`, the project most tests scan.
pub fn minimist_project(content: &[u8]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2", content);
    tmp
}

/// Run `socket-patch scan` in `cwd` in the hermetic env, so the CLI
/// arguments are the sole source of truth (telemetry stays disabled so no
/// run phones home).
pub fn run_scan(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = hermetic_command(&binary());
    cmd.arg("scan").args(args).current_dir(cwd);
    // The unconditional python crawl consults VIRTUAL_ENV first, so an
    // activated host virtualenv would make "empty project" scans non-empty.
    cmd.env_remove("VIRTUAL_ENV");
    let out = cmd.output().expect("run socket-patch scan");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// [`run_scan`] against a mock API (human output unless `extra` has
/// `--json`).
pub fn run_scan_api(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec![
        "--api-url",
        api_url,
        "--api-token",
        "fake-token-for-test",
        "--org",
        ORG_SLUG,
    ];
    args.extend_from_slice(extra);
    run_scan(cwd, &args)
}

/// [`run_scan_api`] in agent mode: v5's bare scan is hosted, and these
/// fixtures exercise the in-place apply flow.
pub fn run_scan_agent(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec!["--mode", "agent"];
    args.extend_from_slice(extra);
    run_scan_api(cwd, api_url, &args)
}

pub async fn recorded(mock: &MockServer) -> Vec<wiremock::Request> {
    mock.received_requests()
        .await
        .expect("wiremock records requests by default")
}

fn count_requests(reqs: &[wiremock::Request], verb: &str, needle: &str) -> usize {
    reqs.iter()
        .filter(|r| format!("{}", r.method) == verb && r.url.path().contains(needle))
        .count()
}

pub fn by_package_gets(reqs: &[wiremock::Request]) -> usize {
    count_requests(reqs, "GET", "/patches/by-package/")
}

pub fn view_gets(reqs: &[wiremock::Request]) -> usize {
    count_requests(reqs, "GET", "/patches/view/")
}

pub fn reference_posts(reqs: &[wiremock::Request]) -> usize {
    reqs.iter()
        .filter(|r| format!("{}", r.method) == "POST" && r.url.path().ends_with("/patches/package"))
        .count()
}

pub fn batch_bodies(reqs: &[wiremock::Request]) -> Vec<String> {
    reqs.iter()
        .filter(|r| format!("{}", r.method) == "POST" && r.url.path().ends_with("/patches/batch"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect()
}

/// One batch-response patch record.
fn batch_patch(purl: &str, uuid: &str, tier: &str, cve_ids: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "uuid": uuid,
        "purl": purl,
        "tier": tier,
        "cveIds": cve_ids,
        "ghsaIds": [],
        "severity": "high",
        "title": "covgap test patch"
    })
}

/// Mount the batch endpoint answering with `packages` as given.
pub async fn mount_batch(mock: &MockServer, packages: serde_json::Value, can_access_paid: bool) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": packages,
            "canAccessPaidPatches": can_access_paid,
        })))
        .mount(mock)
        .await;
}

/// Mount a batch endpoint that finds no patches at all.
pub async fn mount_empty_batch(mock: &MockServer) {
    mount_batch(mock, serde_json::json!([]), false).await;
}

/// Mount the batch endpoint returning one free patch for each
/// `(purl, uuid)` pair.
pub async fn mount_batch_free(mock: &MockServer, pkgs: &[(&str, &str)]) {
    let packages: Vec<_> = pkgs
        .iter()
        .map(|(purl, uuid)| {
            serde_json::json!({ "purl": purl, "patches": [batch_patch(purl, uuid, "free", &[])] })
        })
        .collect();
    mount_batch(mock, serde_json::json!(packages), false).await;
}

/// Mount the batch endpoint returning one package with one patch of the
/// given tier and vuln ids.
pub async fn mount_batch_one(
    mock: &MockServer,
    purl: &str,
    uuid: &str,
    tier: &str,
    cve_ids: &[&str],
    can_access_paid: bool,
) {
    let packages = serde_json::json!([
        { "purl": purl, "patches": [batch_patch(purl, uuid, tier, cve_ids)] }
    ]);
    mount_batch(mock, packages, can_access_paid).await;
}

pub fn encode_purl(purl: &str) -> String {
    purl.replace(':', "%3A")
        .replace('/', "%2F")
        .replace('@', "%40")
}

fn by_package_path(purl: &str) -> String {
    format!(
        "/v0/orgs/{ORG_SLUG}/patches/by-package/{}",
        encode_purl(purl)
    )
}

/// Mount the by-package detail endpoint for `purl` answering `body`.
pub async fn mount_by_package_body(mock: &MockServer, purl: &str, body: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path(by_package_path(purl)))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(mock)
        .await;
}

/// Mount the by-package detail endpoint for `purl` with the given
/// vulnerabilities object.
pub async fn mount_by_package(
    mock: &MockServer,
    purl: &str,
    uuid: &str,
    vulnerabilities: serde_json::Value,
) {
    let body = serde_json::json!({
        "patches": [{
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "description": "Covgap test patch",
            "license": "MIT",
            "tier": "free",
            "vulnerabilities": vulnerabilities,
        }],
        "canAccessPaidPatches": false,
    });
    mount_by_package_body(mock, purl, body).await;
}

/// Mount a by-package response that succeeds with NO patch records (the
/// batch said the package has one; the detail query found none to offer).
pub async fn mount_by_package_empty(mock: &MockServer, purl: &str) {
    let body = serde_json::json!({ "patches": [], "canAccessPaidPatches": false });
    mount_by_package_body(mock, purl, body).await;
}

/// Mount a by-package detail endpoint for `purl` that fails with a 500.
pub async fn mount_by_package_500(mock: &MockServer, purl: &str) {
    Mock::given(method("GET"))
        .and(path(by_package_path(purl)))
        .respond_with(ResponseTemplate::new(500))
        .mount(mock)
        .await;
}

/// The patch view for `uuid` with an inline blob turning `before` into
/// `after\n` in `package/index.js`, so the apply step needs no blob endpoint.
async fn mount_view(mock: &MockServer, purl: &str, uuid: &str, before: &[u8]) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": git_sha256(before),
                    "afterHash": git_sha256(b"after\n"),
                    // base64 of "after\n"
                    "blobContent": "YWZ0ZXIK",
                }
            },
            "vulnerabilities": {},
            "description": "Covgap test patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(mock)
        .await;
}

/// Mount the three endpoints the full apply flow hits (batch, by-package,
/// and the patch view with an inline blob) for one free patch per
/// `(purl, uuid)` pair; each `index.js` goes from `before` to `after\n`.
pub async fn mount_patch_api(mock: &MockServer, pkgs: &[(&str, &str)], before: &[u8]) {
    mount_batch_free(mock, pkgs).await;
    for (purl, uuid) in pkgs {
        mount_by_package(mock, purl, uuid, serde_json::json!({})).await;
        mount_view(mock, purl, uuid, before).await;
    }
}

/// [`mount_patch_api`] for one patch, `UUID`, on `purl`.
pub async fn mount_one_patch_api(mock: &MockServer, purl: &str, before: &[u8]) {
    mount_patch_api(mock, &[(purl, UUID)], before).await;
}

/// Seed `.socket/manifest.json` with one entry per `(purl, uuid)` pair
/// (camelCase wire shape, mirroring `scan_invariants.rs`).
pub fn seed_manifest(root: &Path, entries: &[(&str, &str)]) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let patches: serde_json::Map<String, serde_json::Value> = entries
        .iter()
        .map(|(purl, uuid)| {
            (
                (*purl).to_string(),
                serde_json::json!({
                    "uuid": uuid,
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {},
                    "vulnerabilities": {},
                    "description": "seed",
                    "license": "MIT",
                    "tier": "free",
                }),
            )
        })
        .collect();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({ "patches": patches })).unwrap(),
    )
    .unwrap();
}

/// `.socket/manifest.json` parsed.
pub fn read_manifest(root: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(root.join(".socket/manifest.json")).expect("manifest");
    serde_json::from_str(&text).unwrap()
}

/// The patch target every apply-with-orphans run installs and patches.
pub const SILENT_TARGET: &str = "pkg:npm/silent-target@1.0.0";

/// One stale manifest entry and the fill char of its orphan blob's name.
pub type Orphan<'a> = (&'a str, &'a str, char);

/// The project behind [`run_apply_with_orphans`]: `silent-target@1.0.0`
/// installed (with its patch mounted on `mock`) and `orphans` pre-seeded as
/// manifest entries, each with one orphan blob file.
pub async fn orphans_project(mock: &MockServer, orphans: &[Orphan<'_>]) -> tempfile::TempDir {
    let before = b"before\n";
    mount_one_patch_api(mock, SILENT_TARGET, before).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "silent-target", "1.0.0", before);
    let entries: Vec<(&str, &str)> = orphans.iter().map(|(p, u, _)| (*p, *u)).collect();
    seed_manifest(tmp.path(), &entries);
    let blobs = tmp.path().join(".socket/blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    for (_, _, fill) in orphans {
        std::fs::write(blobs.join(orphan_blob_name(*fill)), b"orphan").unwrap();
    }
    tmp
}

/// The file name of the orphan blob seeded for `fill`.
pub fn orphan_blob_name(fill: char) -> String {
    fill.to_string().repeat(64)
}

/// Run the full apply pipeline with `flags` (e.g. `--sync --yes`) over an
/// [`orphans_project`] and return `(code, stdout, stderr, root)`.
pub async fn run_apply_with_orphans(
    mock: &MockServer,
    orphans: &[Orphan<'_>],
    flags: &[&str],
) -> (i32, String, String, tempfile::TempDir) {
    let tmp = orphans_project(mock, orphans).await;
    let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), flags);
    (code, stdout, stderr, tmp)
}

/// Write a `package-lock.json` resolving the npm `purl` to the hosted
/// patch server at `resolved_path` (relative to `https://patch.socket.dev/`).
fn write_hosted_lock(root: &Path, purl: &str, resolved_path: &str) {
    let (name, version) = purl
        .strip_prefix("pkg:npm/")
        .and_then(|rest| rest.rsplit_once('@'))
        .expect("an npm purl");
    let lock = serde_json::json!({
        "name": "covgap-scan-root",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "covgap-scan-root",
                "version": "0.0.0",
                "dependencies": { name: version }
            },
            format!("node_modules/{name}"): {
                "version": version,
                "resolved": format!("https://patch.socket.dev/{resolved_path}"),
                "integrity": "sha512-orig==",
            }
        }
    });
    std::fs::write(
        root.join("package-lock.json"),
        serde_json::to_string_pretty(&lock).unwrap(),
    )
    .unwrap();
}

/// A live hosted lock for `silent-target@1.0.0` (the inventory proof fires
/// on the patch.socket.dev host), the wiring an agent-mode apply leaves in
/// place and warns about.
pub fn write_live_hosted_lock(root: &Path) {
    write_hosted_lock(
        root,
        SILENT_TARGET,
        &format!("patch/npm/tok/{UUID}/silent-target-1.0.0.tgz"),
    );
}

/// Seed a hosted pin for the npm `purl` in `package-lock.json`: the
/// lockfile resolving it to the Socket patch server under `uuid`. v5 hosted
/// mode keeps its state only in lockfile pins, so this is update
/// detection's "old" side.
pub fn seed_hosted_pin(root: &Path, purl: &str, uuid: &str) {
    let (name, version) = purl
        .strip_prefix("pkg:npm/")
        .and_then(|rest| rest.rsplit_once('@'))
        .expect("an npm purl");
    write_hosted_lock(
        root,
        purl,
        &format!("patch/npm/{name}/{version}/tok/{uuid}/{name}-{version}.tgz"),
    );
}

/// Reference endpoint denying the grant: the hosted engine runs (proving
/// the hosted arm reached it) but rewrites nothing, so no lockfile fixture
/// is needed.
pub async fn mount_forbidden_reference(mock: &MockServer, purl: &str) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": { UUID: {
                "status": "forbidden", "url": null, "purl": purl,
                "artifacts": [], "registryOverride": null
            } }
        })))
        .mount(mock)
        .await;
}

/// A project whose only npm inventory is a corrupt `bun.lockb`.
pub fn write_invalid_bun_lockb_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "covgap-lockb-only", "version": "0.0.0", "dependencies": { "minimist": "1.2.2" } }"#,
    )
    .unwrap();
    std::fs::write(root.join("bun.lockb"), b"\0binary bun lockfile").unwrap();
}

/// A real bun 1.3.14 lockfileVersion-1 workspace lock resolving minimist
/// from the registry: the shape the vendored preflight refuses.
pub fn write_bun_v1_workspace_lock(root: &Path) {
    std::fs::write(
        root.join("bun.lock"),
        "{\n  \"lockfileVersion\": 1,\n  \"configVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \"name\": \"covgap-scan-root\",\n      \"dependencies\": {\n        \"consumer\": \"workspace:*\",\n      },\n    },\n    \"packages/consumer\": {\n      \"name\": \"consumer\",\n      \"version\": \"1.0.0\",\n      \"dependencies\": {\n        \"minimist\": \"1.2.2\",\n      },\n    },\n  },\n  \"packages\": {\n    \"consumer\": [\"consumer@workspace:packages/consumer\"],\n\n    \"minimist\": [\"minimist@1.2.2\", \"\", {}, \"sha512-AAAA==\"],\n  }\n}\n",
    )
    .unwrap();
}

/// A vendored state ledger claiming `purl` (camelCase wire shape), so scan
/// treats it as vendor-owned.
pub fn seed_vendored_entry(root: &Path, purl: &str) {
    let vendor_dir = root.join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(
        vendor_dir.join("state.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "version": 1,
            "entries": {
                purl: {
                    "ecosystem": "npm",
                    "basePurl": purl,
                    "uuid": UUID,
                    "artifact": {
                        "path": format!(".socket/vendor/npm/{UUID}/minimist-1.2.2.tgz"),
                    },
                    "wiring": [],
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
}
