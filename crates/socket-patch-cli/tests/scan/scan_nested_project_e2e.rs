//! #1534: a root `scan --mode vendored` over a repository that holds an
//! independent nested npm project (`tools/x/` with its own lock and
//! `node_modules`). The crawl reads `tools/x/node_modules`, but the root's
//! lock does not install it, so the root run must not hand those copies to
//! the root lock backend: it warns `nested_project_skipped` (naming the
//! project and the PATH to pass) instead of failing every run with
//! `vendor_lock_entry_not_found`, and the in-run VEX is still written.

use crate::common::envelope::{all_codes, parse_json_envelope};
use crate::common::{binary, git_sha256, hermetic_command};

use crate::prebuilt_common;

use std::path::Path;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG_SLUG: &str = "test-org";
const ROOT_PURL: &str = "pkg:npm/root-dep@1.0.0";
const ROOT_UUID: &str = "11111111-1111-4111-8111-111111111111";
const NESTED_PURL: &str = "pkg:npm/left-pad@1.3.0";
const NESTED_UUID: &str = "22222222-2222-4222-8222-222222222222";
const BEFORE: &[u8] = b"before\n";
const AFTER: &[u8] = b"after\n";
/// base64 of AFTER, inlined as the view response's blobContent.
const AFTER_B64: &str = "YWZ0ZXIK";
const WARNING: &str = "nested_project_skipped";

/// Write `name@version` installed under `<dir>/node_modules`.
fn install(dir: &Path, name: &str, version: &str) {
    let pkg = dir.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{"name":"{name}","version":"{version}"}}"#),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE).unwrap();
}

/// A v3 package-lock for project `project` whose only dependency is
/// `name@version`.
fn write_project(dir: &Path, project: &str, name: &str, version: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        serde_json::json!({
            "name": project,
            "version": "1.0.0",
            "private": true,
            "dependencies": { name: version },
        })
        .to_string(),
    )
    .unwrap();
    let lock = serde_json::json!({
        "name": project,
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": project,
                "version": "1.0.0",
                "dependencies": { name: version }
            },
            format!("node_modules/{name}"): {
                "version": version,
                "resolved": format!("https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"),
                "integrity": "sha512-orig==",
            }
        }
    });
    let mut bytes = serde_json::to_vec_pretty(&lock).unwrap();
    bytes.push(b'\n');
    std::fs::write(dir.join("package-lock.json"), bytes).unwrap();
    install(dir, name, version);
}

/// The repository root owns `root-dep@1.0.0`; `tools/x` is an independent
/// npm project (its own lock, not a workspace member) that installs
/// `left-pad@1.3.0`, which the root does not depend on.
fn write_repo(root: &Path) {
    std::fs::create_dir_all(root.join(".git")).unwrap();
    write_project(root, "root", "root-dep", "1.0.0");
    write_project(&root.join("tools/x"), "x", "left-pad", "1.3.0");
}

fn encode(purl: &str) -> String {
    purl.replace(':', "%3A")
        .replace('/', "%2F")
        .replace('@', "%40")
}

async fn mount_patch(mock: &MockServer, purl: &str, uuid: &str) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{}",
            encode(purl)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": uuid,
                "purl": purl,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "Vendor patch",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    let view = serde_json::json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "2026-01-01T00:00:00Z",
        "files": { "package/index.js": {
            "beforeHash": git_sha256(BEFORE),
            "afterHash": git_sha256(AFTER),
            "blobContent": AFTER_B64,
        } },
        "vulnerabilities": {
            "GHSA-aaaa-bbbb-cccc": {
                "cves": ["CVE-2026-0001"],
                "summary": "s",
                "severity": "high",
                "description": "d"
            }
        },
        "description": "Vendor patch",
        "license": "MIT",
        "tier": "free",
    });
    prebuilt_common::mount_view(mock, &view, None).await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(view))
        .mount(mock)
        .await;
}

/// The batch endpoint: like the real API, it answers only for the purls
/// the request asks about (a `scan . tools/x` leg queries its own copies).
struct BatchOffers(Vec<(String, String)>);

impl wiremock::Respond for BatchOffers {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let body = String::from_utf8_lossy(&request.body);
        let packages: Vec<_> = self
            .0
            .iter()
            .filter(|(purl, _)| body.contains(purl.as_str()))
            .map(|(purl, uuid)| {
                serde_json::json!({
                    "purl": purl,
                    "patches": [{
                        "uuid": uuid,
                        "purl": purl,
                        "tier": "free",
                        "cveIds": ["CVE-2026-0001"],
                        "ghsaIds": ["GHSA-aaaa-bbbb-cccc"],
                        "severity": "high",
                        "title": "vendor target"
                    }]
                })
            })
            .collect();
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": packages,
            "canAccessPaidPatches": false,
        }))
    }
}

/// Batch discovery offers a patch for each `(purl, uuid)`; each has its
/// by-package search and view.
async fn mount_offers(mock: &MockServer, offers: &[(&str, &str)]) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(BatchOffers(
            offers
                .iter()
                .map(|(p, u)| (p.to_string(), u.to_string()))
                .collect(),
        ))
        .mount(mock)
        .await;
    for (purl, uuid) in offers {
        mount_patch(mock, purl, uuid).await;
    }
}

/// [`mount_offers`] for both packages of [`write_repo`].
async fn mount_api(mock: &MockServer) {
    mount_offers(mock, &[(ROOT_PURL, ROOT_UUID), (NESTED_PURL, NESTED_UUID)]).await;
}

fn run_scan(root: &Path, mock_uri: &str, mode: &str, extra: &[&str]) -> (i32, String, String) {
    let mut cmd = hermetic_command(&binary());
    cmd.args([
        "scan",
        "--json",
        "--mode",
        mode,
        "--yes",
        "--api-url",
        mock_uri,
        "--api-token",
        "fake-token",
        "--org",
        ORG_SLUG,
    ])
    .args(extra)
    .current_dir(root);
    let out = cmd.output().expect("run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn warning<'a>(v: &'a serde_json::Value, code: &str) -> Option<&'a serde_json::Value> {
    v["warnings"].as_array()?.iter().find(|w| w["code"] == code)
}

fn assert_nested_skipped(v: &serde_json::Value) {
    let w = warning(v, WARNING).unwrap_or_else(|| panic!("no {WARNING} warning: {v:#}"));
    let detail = w["detail"].as_str().unwrap();
    assert!(detail.contains(NESTED_PURL), "{detail}");
    assert!(detail.contains("tools/x"), "names the project: {detail}");
    assert!(
        detail.contains("scan --mode vendored tools/x"),
        "names the PATH to pass: {detail}"
    );
    assert!(
        !all_codes(v)
            .iter()
            .any(|c| c == "vendor_lock_entry_not_found"),
        "no failed event: {v:#}"
    );
}

/// The bug: run 1 (and every later run) ended `partialFailure`, exit 1,
/// with `vendor_lock_entry_not_found` for the nested project's copy.
#[tokio::test]
async fn root_vendored_scan_warns_about_a_nested_projects_copies() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_repo(root);
    let nested_lock = std::fs::read(root.join("tools/x/package-lock.json")).unwrap();
    let mock = MockServer::start().await;
    mount_api(&mock).await;

    for run in 1..=2 {
        let (code, stdout, stderr) = run_scan(root, &mock.uri(), "vendored", &[]);
        let v = parse_json_envelope(&stdout);
        assert_eq!(
            code, 0,
            "run {run}: exit 0\nstdout={stdout}\nstderr={stderr}"
        );
        assert_eq!(v["status"], "success", "run {run}: {v:#}");
        assert_nested_skipped(&v);
    }
    // The root's own package was vendored; the nested lock is untouched.
    let root_lock = std::fs::read_to_string(root.join("package-lock.json")).unwrap();
    assert!(root_lock.contains(".socket/vendor"), "{root_lock}");
    assert_eq!(
        std::fs::read(root.join("tools/x/package-lock.json")).unwrap(),
        nested_lock
    );
}

/// The in-run VEX is written (it was dropped with the exit-1 run).
#[tokio::test]
async fn root_vendored_scan_with_vex_writes_the_document() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_repo(root);
    let mock = MockServer::start().await;
    mount_api(&mock).await;

    let out = root.join("out.vex.json");
    let out_arg = out.to_str().unwrap();
    let (code, stdout, stderr) = run_scan(
        root,
        &mock.uri(),
        "vendored",
        &["--vex", out_arg, "--vex-product", "pkg:npm/root@1.0.0"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert_nested_skipped(&parse_json_envelope(&stdout));
    let doc = std::fs::read_to_string(&out).expect("the in-run VEX is written");
    assert!(
        !doc.contains("left-pad"),
        "attests only the root's package: {doc}"
    );
}

/// `scan --mode vendored . tools/x`: the `tools/x` leg vendors the nested
/// project, and the `.` leg no longer fails on its copy.
#[tokio::test]
async fn vendored_scan_of_root_and_nested_path_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_repo(root);
    let mock = MockServer::start().await;
    mount_api(&mock).await;

    let mut cmd = hermetic_command(&binary());
    cmd.args([
        "scan",
        "--mode",
        "vendored",
        "--yes",
        "--api-url",
        &mock.uri(),
        "--api-token",
        "fake-token",
        "--org",
        ORG_SLUG,
        ".",
        "tools/x",
    ])
    .current_dir(root);
    let out = cmd.output().expect("run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout={}\nstderr={stderr}",
        String::from_utf8_lossy(&out.stdout)
    );
    let nested_lock = std::fs::read_to_string(root.join("tools/x/package-lock.json")).unwrap();
    assert!(nested_lock.contains(".socket/vendor"), "{nested_lock}");
}

/// A copy the root's own lock installs stays the root's, even when the
/// crawl kept the nested project's copy of the same package.
#[tokio::test]
async fn package_the_root_also_locks_is_still_vendored_at_the_root() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    write_project(root, "root", "left-pad", "1.3.0");
    write_project(&root.join("tools/x"), "x", "left-pad", "1.3.0");
    let mock = MockServer::start().await;
    mount_offers(&mock, &[(NESTED_PURL, NESTED_UUID)]).await;

    let (code, stdout, stderr) = run_scan(root, &mock.uri(), "vendored", &[]);
    let v = parse_json_envelope(&stdout);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(warning(&v, WARNING).is_none(), "{v:#}");
    let root_lock = std::fs::read_to_string(root.join("package-lock.json")).unwrap();
    assert!(root_lock.contains(".socket/vendor"), "{root_lock}");
}

/// A workspace member's stray lock does not make it an independent
/// project: npm installs the member from the root's lock.
#[tokio::test]
async fn workspace_member_with_stray_lock_is_not_a_nested_project() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    write_project(&root.join("packages/a"), "a", "left-pad", "1.3.0");
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"root","version":"1.0.0","private":true,"workspaces":["packages/*"]}"#,
    )
    .unwrap();
    let lock = serde_json::json!({
        "name": "root",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": { "name": "root", "version": "1.0.0", "workspaces": ["packages/*"] },
            "node_modules/a": { "resolved": "packages/a", "link": true },
            "packages/a": { "name": "a", "version": "1.0.0",
                            "dependencies": { "left-pad": "1.3.0" } },
            "packages/a/node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-orig==",
            }
        }
    });
    std::fs::write(
        root.join("package-lock.json"),
        serde_json::to_vec_pretty(&lock).unwrap(),
    )
    .unwrap();
    let mock = MockServer::start().await;
    mount_offers(&mock, &[(NESTED_PURL, NESTED_UUID)]).await;

    let (_, stdout, _) = run_scan(root, &mock.uri(), "vendored", &[]);
    let v = parse_json_envelope(&stdout);
    assert!(warning(&v, WARNING).is_none(), "{v:#}");
}

/// The PATH the warning names is relative to where the command runs, not
/// to `--cwd`: re-running it from the same shell reaches the project.
#[tokio::test]
async fn warning_names_the_path_from_the_shells_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    write_repo(&root);
    let mock = MockServer::start().await;
    mount_api(&mock).await;

    let root_arg = root.to_str().unwrap();
    let (code, stdout, stderr) =
        run_scan(tmp.path(), &mock.uri(), "vendored", &["--cwd", root_arg]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_json_envelope(&stdout);
    let detail = warning(&v, WARNING).unwrap()["detail"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        detail.contains("scan --mode vendored repo/tools/x`"),
        "{detail}"
    );
}

/// #1554: [`write_repo`], but `tools/x` was installed without a lock
/// (`package-lock=false` in its `.npmrc`, or `npm install
/// --no-package-lock`).
fn write_lockless_repo(root: &Path, npmrc: bool) {
    write_repo(root);
    std::fs::remove_file(root.join("tools/x/package-lock.json")).unwrap();
    if npmrc {
        std::fs::write(root.join("tools/x/.npmrc"), "package-lock=false\n").unwrap();
    }
}

/// #1554: a lockless nested project is as independent as a locked one.
/// Every run ended `partialFailure`, exit 1, with
/// `vendor_lock_entry_not_found`, and the in-run VEX was dropped.
#[tokio::test]
async fn root_vendored_scan_skips_a_lockless_nested_project() {
    for npmrc in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_lockless_repo(root, npmrc);
        let mock = MockServer::start().await;
        mount_api(&mock).await;

        for run in 1..=2 {
            let (code, stdout, stderr) = run_scan(root, &mock.uri(), "vendored", &[]);
            let v = parse_json_envelope(&stdout);
            assert_eq!(
                code, 0,
                "npmrc={npmrc} run {run}: exit 0\nstdout={stdout}\nstderr={stderr}"
            );
            assert_eq!(v["status"], "success", "npmrc={npmrc} run {run}: {v:#}");
            assert_nested_skipped(&v);
            let detail = warning(&v, WARNING).unwrap()["detail"].as_str().unwrap();
            assert!(detail.contains("without a lockfile"), "{detail}");
            assert!(
                detail.contains("npm install --package-lock")
                    && detail.contains("scan --mode agent tools/x"),
                "names a remedy that works without a lockfile: {detail}"
            );
        }
        let root_lock = std::fs::read_to_string(root.join("package-lock.json")).unwrap();
        assert!(root_lock.contains(".socket/vendor"), "{root_lock}");
        assert!(!root.join("tools/x/package-lock.json").exists());

        let out = root.join("out.vex.json");
        let (code, stdout, stderr) = run_scan(
            root,
            &mock.uri(),
            "vendored",
            &[
                "--vex",
                out.to_str().unwrap(),
                "--vex-product",
                "pkg:npm/root@1.0.0",
            ],
        );
        assert_eq!(code, 0, "npmrc={npmrc}: stdout={stdout}\nstderr={stderr}");
        let doc = std::fs::read_to_string(&out).expect("the in-run VEX is written");
        assert!(!doc.contains("left-pad"), "{doc}");
    }
}
