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
    // `--cwd` has a name among the headings, like every other directory.
    let headings: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("== "))
        .collect();
    assert_eq!(
        headings,
        ["== . ==", "== services/api ==", "== web =="],
        "{stdout}"
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
/// never scan the projects below.
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

/// A Bundler project with one gem installed under its own `vendor/bundle`.
fn write_gem_project(dir: &Path, gem: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("Gemfile"),
        format!("source \"https://rubygems.org\"\n\ngem \"{gem}\", \"1.0.0\"\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("Gemfile.lock"),
        format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    {gem} (1.0.0)\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  {gem} (= 1.0.0)\n\nBUNDLED WITH\n   2.5.22\n"
        ),
    )
    .unwrap();
    let home = dir.join("vendor/bundle/ruby/3.3.0");
    let lib = home.join(format!("gems/{gem}-1.0.0/lib"));
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::write(lib.join(format!("{gem}.rb")), "module Gem1; end\n").unwrap();
    std::fs::create_dir_all(home.join("specifications")).unwrap();
    std::fs::write(
        home.join(format!("specifications/{gem}-1.0.0.gemspec")),
        format!(
            "Gem::Specification.new do |s|\n  s.name = \"{gem}\"\n  s.version = \"1.0.0\"\nend\n"
        ),
    )
    .unwrap();
}

/// A checkout with two Bundler projects below a root that holds none.
fn write_gem_monorepo(root: &Path) {
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::write(root.join(".gitignore"), "**/vendor/bundle/\n.bundle/\n").unwrap();
    write_gem_project(&root.join("api"), "api-gem");
    write_gem_project(&root.join("web"), "web-gem");
}

/// [`run_scan`] for an agent-mode scan of a Bundler tree: no ambient
/// `BUNDLE_*` setting moves the gem crawl.
fn run_agent_scan(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, String, String) {
    let mut cmd = hermetic_command(&binary());
    cmd.arg("scan").current_dir(cwd);
    hermetic::scrub_extra(&mut cmd, &[Extra::Venv, Extra::Bundle]);
    // `--sync` is agent mode too, and takes no `--mode` beside it.
    if !extra.contains(&"--sync") {
        cmd.args(["--mode", "agent"]);
    }
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

/// The `projects_not_scanned` warning's detail in a `--json` envelope.
fn not_scanned_detail(stdout: &str) -> Option<String> {
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("not a JSON envelope ({e}): {stdout}"));
    envelope["warnings"]
        .as_array()?
        .iter()
        .find(|w| w["code"] == "projects_not_scanned")
        .map(|w| w["detail"].as_str().unwrap().to_string())
}

/// #2125, shape 1: an agent-mode scan patches the one project at `--cwd`.
/// From a root with nothing installed, above two Bundler projects with
/// their gems installed, it names the projects it left and the command
/// that reaches each, and does not send the user to run an install.
#[tokio::test]
async fn agent_scan_names_the_projects_below_it_left() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_monorepo(tmp.path());

    let (code, stdout, stderr) = run_agent_scan(tmp.path(), &server.uri(), &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stderr.contains("2 project directories below this one were not scanned (api, web)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("`socket-patch scan --mode agent --dry-run --cwd api`"),
        "{stderr}"
    );
    assert_eq!(
        stderr.matches("not scanned").count(),
        1,
        "said once: {stderr}"
    );
    assert!(
        !stdout.contains("Run your package manager's install first"),
        "an install is not what is missing: {stdout}"
    );
    assert!(
        stdout.contains("No packages found (see the warning)."),
        "{stdout}"
    );
    assert_eq!(queried(&server).await, [""; 0], "--cwd alone was scanned");

    let (code, stdout, stderr) = run_agent_scan(tmp.path(), &server.uri(), &["--json"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let detail = not_scanned_detail(&stdout)
        .unwrap_or_else(|| panic!("no projects_not_scanned warning: {stdout}"));
    assert!(detail.contains("(api, web)"), "{detail}");
    assert!(
        detail.contains("`socket-patch scan --mode agent --dry-run --cwd api`"),
        "{detail}"
    );

    // The command is asked as the run was: `--sync` stays `--sync`.
    let (_, stdout, _) = run_agent_scan(tmp.path(), &server.uri(), &["--json", "--sync"]);
    let detail = not_scanned_detail(&stdout)
        .unwrap_or_else(|| panic!("no projects_not_scanned warning: {stdout}"));
    assert!(
        detail.contains("`socket-patch scan --sync --dry-run --cwd api`"),
        "{detail}"
    );

    // The run the warning names scans that project and warns of nothing.
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let (code, stdout, stderr) =
        run_agent_scan(tmp.path(), &server.uri(), &["--json", "--cwd", "api"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(not_scanned_detail(&stdout), None, "{stdout}");
    assert_eq!(queried(&server).await, ["pkg:gem/api-gem@1.0.0"]);
}

/// #2125, shape 2: the root is a Bundler project too. Its gems are
/// scanned, and the projects below are still named: the run's success
/// summary is about the root alone.
#[tokio::test]
async fn agent_scan_of_a_root_project_names_the_projects_below_it_left() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_monorepo(tmp.path());
    write_gem_project(tmp.path(), "root-gem");

    let (code, stdout, stderr) = run_agent_scan(tmp.path(), &server.uri(), &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stderr.contains("2 project directories below this one were not scanned (api, web)"),
        "{stderr}"
    );
    assert_eq!(queried(&server).await, ["pkg:gem/root-gem@1.0.0"]);

    let (_, stdout, _) = run_agent_scan(tmp.path(), &server.uri(), &["--json"]);
    assert!(not_scanned_detail(&stdout).is_some(), "{stdout}");
}

/// A lookup that fails ends the run, and the projects below are still
/// named first: that this run would not have covered them is what the
/// user needs before running it again.
#[tokio::test]
async fn a_failed_lookup_still_names_the_projects_below() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream down"))
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_monorepo(tmp.path());
    write_gem_project(tmp.path(), "root-gem");

    let (code, stdout, stderr) = run_agent_scan(tmp.path(), &server.uri(), &[]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(
        stderr.contains("2 project directories below this one were not scanned (api, web)"),
        "{stderr}"
    );
    assert_eq!(
        stderr.matches("not scanned").count(),
        1,
        "said once: {stderr}"
    );
}

/// An agent-mode scan warns only of a project it did not reach. Its npm
/// crawl walks the `node_modules` below `--cwd`, so a nested npm project
/// is scanned from the root and is not named. Nor is a project with no
/// install directory of its own (a Python project with no environment),
/// nor any project when the scan names PATHs or runs outside a git
/// checkout.
#[tokio::test]
async fn agent_scan_does_not_name_a_project_it_reached() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    write_npm_project(&root.join("web"), "web-dep");
    let installed = root.join("web/node_modules/web-dep");
    std::fs::create_dir_all(&installed).unwrap();
    std::fs::write(
        installed.join("package.json"),
        r#"{ "name": "web-dep", "version": "1.0.0" }"#,
    )
    .unwrap();
    // Nothing was installed for it here: the machine's own Python is not
    // this project's install directory.
    std::fs::create_dir_all(root.join("docs")).unwrap();
    std::fs::write(root.join("docs/requirements.txt"), "six==1.16.0\n").unwrap();

    let (code, stdout, stderr) = run_agent_scan(root, &server.uri(), &["--json"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(not_scanned_detail(&stdout), None, "{stdout}");
    assert_eq!(queried(&server).await, ["pkg:npm/web-dep@1.0.0"]);

    // PATHs scope the scan to what the user named.
    let tmp = tempfile::tempdir().unwrap();
    write_gem_monorepo(tmp.path());
    let (_, stdout, _) = run_agent_scan(tmp.path(), &server.uri(), &["--json", "api"]);
    assert_eq!(not_scanned_detail(&stdout), None, "{stdout}");

    // Outside a checkout nothing bounds the search, so there is none.
    std::fs::remove_dir_all(tmp.path().join(".git")).unwrap();
    let (code, stdout, stderr) = run_agent_scan(tmp.path(), &server.uri(), &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(!stderr.contains("not scanned"), "{stderr}");
    assert!(
        stdout.contains("Run your package manager's install first"),
        "{stdout}"
    );
}

/// The same for a PyPI project below with its own `.venv`: a crawl from
/// the root reads no environment of its own, so the project is named.
#[tokio::test]
async fn agent_scan_names_a_python_project_below_with_its_own_venv() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::write(root.join(".gitignore"), ".venv/\n").unwrap();
    let svc = root.join("svc");
    let dist = svc.join(".venv/lib/python3.12/site-packages/six-1.16.0.dist-info");
    std::fs::create_dir_all(&dist).unwrap();
    std::fs::write(svc.join(".venv/pyvenv.cfg"), "version = 3.12.0\n").unwrap();
    std::fs::write(
        dist.join("METADATA"),
        "Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n",
    )
    .unwrap();
    std::fs::write(svc.join("requirements.txt"), "six==1.16.0\n").unwrap();

    let (code, stdout, stderr) = run_agent_scan(root, &server.uri(), &["--json"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let detail = not_scanned_detail(&stdout)
        .unwrap_or_else(|| panic!("no projects_not_scanned warning: {stdout}"));
    assert!(
        detail.starts_with("1 project directory below this one was not scanned (svc): "),
        "{detail}"
    );
    assert_eq!(queried(&server).await, [""; 0], "--cwd alone was scanned");

    let (code, stdout, stderr) = run_agent_scan(root, &server.uri(), &["--json", "--cwd", "svc"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(not_scanned_detail(&stdout), None, "{stdout}");
    assert_eq!(queried(&server).await, ["pkg:pypi/six@1.16.0"]);
}

/// The npm walk from `--cwd` skips hidden directories, so an npm project
/// in one (a GitHub action with its own lockfile and `node_modules`) is
/// not reached, and is named.
#[tokio::test]
async fn agent_scan_names_an_npm_project_its_walk_skips() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    let action = root.join(".github/actions/lint");
    write_npm_project(&action, "action-dep");
    let installed = action.join("node_modules/action-dep");
    std::fs::create_dir_all(&installed).unwrap();
    std::fs::write(
        installed.join("package.json"),
        r#"{ "name": "action-dep", "version": "1.0.0" }"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_agent_scan(root, &server.uri(), &["--json"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let detail = not_scanned_detail(&stdout)
        .unwrap_or_else(|| panic!("no projects_not_scanned warning: {stdout}"));
    assert!(detail.contains("(.github/actions/lint)"), "{detail}");
    assert_eq!(queried(&server).await, [""; 0], "the walk skipped it");
}
