//! A bare hosted or vendored `scan` covers every project in the checkout
//! at or below `--cwd`, against a local `wiremock` server.
//!
//! Spawns the real binary (the `scan_paths_e2e.rs` recipe). The batch-POST
//! bodies are the oracle for which directories were scanned: each project
//! directory's run queries its own lockfile's packages.

use crate::common::hermetic::{self, Extra};
use crate::common::{binary, hermetic_command};

use std::path::Path;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";

fn run_scan(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, String, String) {
    let mut cmd = hermetic_command(&binary());
    cmd.arg("scan").current_dir(cwd);
    hermetic::scrub_extra(&mut cmd, &[Extra::Venv]);
    let out = cmd
        .args([
            "--dry-run",
            "--api-url",
            api_url,
            "--api-token",
            "fake-token-for-test",
            "--org",
            ORG,
        ])
        .args(extra)
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// An npm project whose lockfile resolves one registry package.
fn write_npm_project(dir: &Path, dep: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        format!(r#"{{ "name": "p", "version": "0.0.0", "dependencies": {{ "{dep}": "1.0.0" }} }}"#),
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        format!(
            r#"{{ "name": "p", "version": "0.0.0", "lockfileVersion": 3, "packages": {{
              "": {{ "name": "p", "version": "0.0.0", "dependencies": {{ "{dep}": "1.0.0" }} }},
              "node_modules/{dep}": {{ "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/{dep}/-/{dep}-1.0.0.tgz",
                "integrity": "sha512-{}==" }} }} }}"#,
            "A".repeat(86)
        ),
    )
    .unwrap();
}

/// A checkout with two projects in subdirectories, one more under a
/// fixture directory, one in git-ignored build output and an installed
/// package's own lockfile.
fn write_monorepo(root: &Path) {
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::write(root.join(".gitignore"), "dist/\n").unwrap();
    write_npm_project(&root.join("web"), "web-dep");
    write_npm_project(&root.join("services/api"), "api-dep");
    write_npm_project(&root.join("tests/fixtures/app"), "fixture-dep");
    write_npm_project(&root.join("dist"), "dist-dep");
    // A lockfile an installed package shipped: not a project.
    let installed = root.join("web/node_modules/installed");
    write_npm_project(&installed, "nested-dep");
    std::fs::remove_file(installed.join("package.json")).unwrap();
}

async fn mock_batch_empty(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [], "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

/// Every purl any batch query of the run asked about, sorted.
async fn queried(server: &MockServer) -> Vec<String> {
    let mut purls: Vec<String> = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().ends_with("/patches/batch"))
        .flat_map(|r| {
            let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
            body["components"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c["purl"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        })
        .collect();
    purls.sort();
    purls
}

/// The headline: from the repository root, where no lockfile sits, a bare
/// scan finds and scans each project, and leaves fixtures, ignored output
/// and installed trees alone.
#[tokio::test]
async fn bare_scan_covers_every_project_below_the_root() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_monorepo(tmp.path());

    let (code, stdout, stderr) = run_scan(tmp.path(), &server.uri(), &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(
        queried(&server).await,
        ["pkg:npm/api-dep@1.0.0", "pkg:npm/web-dep@1.0.0"],
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("== services/api =="), "{stdout}");
    assert!(stdout.contains("== web =="), "{stdout}");
    assert!(
        stderr.contains("1 project directory under ignored paths"),
        "the fixture project is counted, not scanned: {stderr}"
    );
}

/// `--cwd` is a project too: it is scanned first, as before, and the
/// projects below it follow.
#[tokio::test]
async fn a_root_project_is_scanned_with_the_projects_below_it() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_monorepo(tmp.path());
    write_npm_project(tmp.path(), "root-dep");

    let (code, stdout, stderr) = run_scan(tmp.path(), &server.uri(), &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(
        queried(&server).await,
        [
            "pkg:npm/api-dep@1.0.0",
            "pkg:npm/root-dep@1.0.0",
            "pkg:npm/web-dep@1.0.0"
        ]
    );
}

/// Nothing changes for a single project, a subdirectory, or a directory
/// outside any checkout (the checkout bounds the search).
#[tokio::test]
async fn a_lone_project_and_a_directory_outside_a_checkout_scan_as_before() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_monorepo(tmp.path());

    let (code, stdout, _) = run_scan(&tmp.path().join("web"), &server.uri(), &[]);
    assert_eq!(code, 0);
    assert_eq!(queried(&server).await, ["pkg:npm/web-dep@1.0.0"]);
    assert!(
        !stdout.contains("== "),
        "one project, no headings: {stdout}"
    );

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    std::fs::remove_dir_all(tmp.path().join(".git")).unwrap();
    let (code, _, _) = run_scan(tmp.path(), &server.uri(), &[]);
    assert_eq!(code, 0);
    assert_eq!(queried(&server).await, [""; 0], "no checkout, no search");
}

/// `--json` reports on one directory, so it scans `--cwd` alone and names
/// the projects it left; so does `--vex`. Agent mode and a global scan
/// never search.
#[tokio::test]
async fn one_document_forms_name_the_projects_they_left() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_monorepo(tmp.path());

    let (code, stdout, _) = run_scan(tmp.path(), &server.uri(), &["--json"]);
    assert_eq!(code, 0, "{stdout}");
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let warning = envelope["warnings"]
        .as_array()
        .and_then(|w| w.iter().find(|w| w["code"] == "projects_not_scanned"))
        .unwrap_or_else(|| panic!("no projects_not_scanned warning: {stdout}"));
    let detail = warning["detail"].as_str().unwrap();
    assert!(detail.contains("services/api, web"), "{detail}");
    assert!(
        detail.contains("socket-patch scan services/api"),
        "{detail}"
    );
    assert_eq!(queried(&server).await, [""; 0], "--cwd alone was scanned");

    for extra in [&["--mode", "agent"][..], &["--global-prefix", "."][..]] {
        let server = MockServer::start().await;
        mock_batch_empty(&server).await;
        let (_, stdout, _) = run_scan(tmp.path(), &server.uri(), extra);
        assert!(!stdout.contains("== web =="), "{extra:?}: {stdout}");
    }
}
