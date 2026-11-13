//! Hermetic CLI tests: which directories of a Bazel workspace are
//! projects (design 2.2; hazard HZ-03 of design 3).
//!
//! Two rules, each with the checkout that has no Bazel file beside it, so
//! that a run there is seen to be what it was:
//!
//! - a Bazel root is a project when a run starts in it, also when it
//!   holds no lockfile and no manifest a native tool knows. A bare scan
//!   from such a root used to run only in the native projects below it;
//! - nothing in a vendor directory is a project, and nothing there is
//!   crawled or written, also when the directory is named only by a
//!   `--vendor_dir` line of a tracked rc file and holds no marker of
//!   Bazel's.
//!
//! The built binary runs against a fake Socket API that knows no patch:
//! which purls a run asks about is the oracle for what it took for a
//! package of a project, and nothing is ever written.

use std::path::{Path, PathBuf};

use serde_json::Value;
use socket_patch_core::bazel::codes::Code;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::bazel_common::{assert_same_tree, snapshot};
use crate::common::hermetic::{self, Extra};
use crate::common::jvm_env;
use crate::common::{
    binary, envelope_error_code, envelope_error_message, hermetic_command, parse_json_envelope,
};

const ORG: &str = "test-org";

/// A scratch checkout, canonical: the binary prints resolved paths. The
/// `.git` directory bounds every upward read, so the Bazel roots of a
/// test are the ones it writes.
fn checkout() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    (tmp, root)
}

/// `rel` below `root`, level by level.
fn at(root: &Path, rel: &str) -> PathBuf {
    let levels = rel.split('/').filter(|level| !level.is_empty());
    levels.fold(root.to_path_buf(), |dir, level| dir.join(level))
}

fn put(root: &Path, rel: &str, bytes: impl AsRef<[u8]>) {
    let file = at(root, rel);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, bytes).unwrap();
}

/// An npm project at `dir` (relative to `root`) whose lock resolves
/// `dep`, not installed.
fn npm_project(root: &Path, dir: &str, dep: &str) {
    let deps = format!(r#""dependencies": {{ "{dep}": "1.0.0" }}"#);
    let manifest = format!(r#"{{ "name": "p", "version": "0.0.0", {deps} }}"#);
    let lock = format!(
        r#"{{ "name": "p", "version": "0.0.0", "lockfileVersion": 3, "packages": {{
          "": {{ "name": "p", "version": "0.0.0", {deps} }},
          "node_modules/{dep}": {{ "version": "1.0.0",
            "resolved": "https://registry.npmjs.org/{dep}/-/{dep}-1.0.0.tgz",
            "integrity": "sha512-{}==" }} }} }}"#,
        "A".repeat(86)
    );
    let file = |name: &str| match dir.is_empty() {
        true => name.to_string(),
        false => format!("{dir}/{name}"),
    };
    put(root, &file("package.json"), manifest);
    put(root, &file("package-lock.json"), lock);
}

fn purl(dep: &str) -> String {
    format!("pkg:npm/{dep}@1.0.0")
}

/// The binary in `cwd`: `(exit code, stdout, stderr)`.
fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = hermetic_command(&binary());
    // No host virtualenv and no host JVM caches: an agent scan would
    // crawl them and ask the API about this machine's packages.
    hermetic::scrub_extra(&mut cmd, &[Extra::Venv]);
    jvm_env::isolate_cli(&mut cmd);
    cmd.args(args).current_dir(cwd);
    let out = cmd.output().expect("run socket-patch");
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    (
        out.status.code().unwrap_or(-1),
        text(&out.stdout),
        text(&out.stderr),
    )
}

/// `socket-patch scan <args>` against the fake Socket API.
fn scan(cwd: &Path, api: &MockServer, args: &[&str]) -> (i32, String, String) {
    let uri = api.uri();
    let fixed = [
        "scan",
        "--api-url",
        &uri,
        "--api-token",
        "fake",
        "--org",
        ORG,
    ];
    run(cwd, &[&fixed[..], args].concat())
}

/// A fake Socket API that knows no patch.
async fn fake_api() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [], "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    server
}

/// Every purl the runs so far asked the API about, sorted.
async fn queried(api: &MockServer) -> Vec<String> {
    let requests = api.received_requests().await.unwrap_or_default();
    let mut purls: Vec<String> = Vec::new();
    for request in requests {
        let body: Value = serde_json::from_slice(&request.body).expect("a JSON request");
        let components = body["components"].as_array().cloned().unwrap_or_default();
        let purl = |c: &Value| c["purl"].as_str().unwrap().to_string();
        purls.extend(components.iter().map(purl));
    }
    purls.sort();
    purls.dedup();
    purls
}

/// The project directories a bare scan ran in, as it headed them.
fn headings(stdout: &str) -> Vec<&str> {
    let headed = stdout.lines().filter_map(|line| line.strip_prefix("== "));
    headed.filter_map(|line| line.strip_suffix(" ==")).collect()
}

/// A bare hosted scan from `root`: the directories it ran in and the
/// purls it asked about. It must exit 0 and write nothing.
async fn bare_scan(root: &Path) -> (Vec<String>, Vec<String>, String) {
    let before = snapshot(root);
    let api = fake_api().await;
    let (code, stdout, stderr) = scan(root, &api, &["--mode", "hosted"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_same_tree(&before, &snapshot(root));
    let ran: Vec<String> = headings(&stdout).into_iter().map(str::to_string).collect();
    (ran, queried(&api).await, stderr)
}

/// Design 2.2: a workspace root that holds a boundary file and nothing a
/// native tool reads is a project all the same. A bare scan from it runs
/// in the root as well as in the native projects below it: before, the
/// root was passed over whenever a native project existed below, and
/// what its rulesets build was never looked at.
#[tokio::test]
async fn a_bazel_root_is_scanned_beside_the_native_projects_below_it() {
    for boundary in ["MODULE.bazel", "REPO.bazel", "WORKSPACE.bazel", "WORKSPACE"] {
        let (_tmp, root) = checkout();
        put(&root, boundary, "");
        put(&root, "maven_install.json", "{}");
        put(&root, "third_party/requirements_lock.txt", "");
        put(&root, "BUILD.bazel", "");
        npm_project(&root, "web", "web-only");
        npm_project(&root, "svc/api", "api-only");
        let (ran, asked, _) = bare_scan(&root).await;
        assert_eq!(ran, [".", "svc/api", "web"], "{boundary}");
        // The root holds no package a native reader finds; the projects
        // below are scanned as they were.
        assert_eq!(asked, [purl("api-only"), purl("web-only")], "{boundary}");

        // The same checkout without the boundary file is what it was to
        // every earlier release: the two projects, and not the root.
        std::fs::remove_file(root.join(boundary)).unwrap();
        let (ran, asked, _) = bare_scan(&root).await;
        assert_eq!(ran, ["svc/api", "web"], "no {boundary}");
        assert_eq!(asked, [purl("api-only"), purl("web-only")], "no {boundary}");
        // A directory of the name is no boundary file.
        std::fs::create_dir(root.join(boundary)).unwrap();
        let (ran, _, _) = bare_scan(&root).await;
        assert_eq!(ran, ["svc/api", "web"], "{boundary}/ is a directory");
    }
}

/// A root that was a project by a lockfile keeps exactly that: the
/// boundary file beside the lock adds no run and no marker.
#[tokio::test]
async fn a_bazel_root_with_a_lockfile_is_scanned_as_it_was() {
    let (_tmp, root) = checkout();
    npm_project(&root, "", "root-only");
    npm_project(&root, "web", "web-only");
    let plain = bare_scan(&root).await;
    assert_eq!(plain.0, [".", "web"]);
    put(&root, "MODULE.bazel", "module(name = \"ws\")\n");
    put(&root, ".bazelrc", "build --jobs=4\n");
    let bazel = bare_scan(&root).await;
    assert_eq!((&bazel.0, &bazel.1), (&plain.0, &plain.1));
    assert_eq!(bazel.1, [purl("root-only"), purl("web-only")]);
}

/// A workspace whose `.bazelrc` sends `bazel vendor` to
/// `third_party/bazel`, a directory that holds the repositories Bazel
/// fetched and no marker of Bazel's: `rc` is the content of the rc file.
fn lay_vendoring_workspace(root: &Path, rc: &str) {
    put(root, "MODULE.bazel", "module(name = \"ws\")\n");
    put(root, ".bazelrc", rc);
    npm_project(root, "", "root-only");
    npm_project(root, "web", "web-only");
    npm_project(root, "third_party/bazel/+npm+dep", "vendored-only");
    // A lock directly in the vendor directory, with no subdirectory
    // between the walk and it.
    npm_project(root, "third_party/bazel", "vendor-root-only");
    npm_project(root, "third_party/other", "other-only");
}

/// HZ-03 (ROUTED R-032): a vendor directory that only a tracked
/// `--vendor_dir` names is Bazel's before `bazel vendor` has written a
/// marker into it, and where git does not track the marker. Nothing in it
/// is a project, a scope inside it is refused, and the same directory
/// with no such line is a project like its neighbours.
#[tokio::test]
async fn a_vendor_dir_named_only_by_a_tracked_rc_file_holds_no_project() {
    let skipped = Code::WorkspaceOutputTreeSkipped.as_str();
    let note = "1 directory below this one was not searched for projects (third_party/bazel)";
    let kept = [purl("other-only"), purl("root-only"), purl("web-only")];
    // On the build chain, under a config, on another command, through an
    // import, and spelled with a `./` and a trailing slash.
    let rcs = [
        "common --vendor_dir=third_party/bazel\n",
        "build:ci --vendor_dir=third_party/bazel\n",
        "vendor --vendor_dir=./third_party/bazel/\n",
        "import %workspace%/tools/ci.bazelrc\n",
    ];
    for rc in rcs {
        let (_tmp, root) = checkout();
        lay_vendoring_workspace(&root, rc);
        put(
            &root,
            "tools/ci.bazelrc",
            "common --vendor_dir=third_party/bazel\n",
        );
        let (ran, asked, stderr) = bare_scan(&root).await;
        assert_eq!(ran, [".", "third_party/other", "web"], "{rc}");
        assert_eq!(asked, kept, "{rc}");
        assert_eq!(
            stderr.matches(&format!("Note: {note}")).count(),
            1,
            "{stderr}"
        );

        // `--json` takes one directory and says what the search left out.
        let api = fake_api().await;
        let (code, stdout, stderr) = scan(&root, &api, &["--mode", "hosted", "--json"]);
        assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
        let envelope = parse_json_envelope(&stdout);
        let warnings = envelope["warnings"].as_array().expect("warnings");
        let left_out = warnings.iter().find(|warning| warning["code"] == skipped);
        let detail = left_out.expect("the tree is reported")["detail"].as_str();
        assert!(
            detail.is_some_and(|detail| detail.starts_with(note)),
            "{stdout}"
        );

        // A scope inside the directory is in a tree Bazel owns, whatever
        // the mode: the run is refused before it reads or crawls there.
        let inside = "third_party/bazel/+npm+dep";
        let before = snapshot(&root);
        for command in [
            vec!["--mode", "hosted", "--json", "--cwd", inside],
            vec!["--mode", "agent", "--json", "--cwd", "third_party/bazel"],
        ] {
            let (code, stdout, _) = scan(&root, &api, &command);
            assert_eq!(code, 1, "{command:?}: {stdout}");
            let envelope = parse_json_envelope(&stdout);
            let refusal = Code::AgentOutputTree.as_str();
            assert_eq!(envelope_error_code(&envelope), Some(refusal), "{command:?}");
            let message = envelope_error_message(&envelope).expect("a message");
            assert!(message.contains("in a Bazel vendor directory"), "{message}");
        }
        assert_same_tree(&before, &snapshot(&root));
        assert_eq!(queried(&api).await, [purl("root-only")], "{rc}");
    }

    // No such line: the directory and what it holds are projects, as they
    // are to every earlier release. So is the checkout with the line and
    // no Bazel workspace file, where an rc file is nobody's.
    let vendored = [purl("vendor-root-only"), purl("vendored-only")];
    let all: Vec<String> = [&kept[..1], &kept[1..2], &vendored[..], &kept[2..]].concat();
    let everywhere = [
        ".",
        "third_party/bazel",
        "third_party/bazel/+npm+dep",
        "third_party/other",
        "web",
    ];
    for (rc, boundary) in [
        ("build --jobs=4\n", true),
        ("common --vendor_dir=third_party/bazel\n", false),
        // The empty value names the workspace root, which no flag makes a
        // tree: the projects of the workspace are still its projects.
        ("common --vendor_dir=\n", true),
    ] {
        let (_tmp, root) = checkout();
        lay_vendoring_workspace(&root, rc);
        if !boundary {
            std::fs::remove_file(root.join("MODULE.bazel")).unwrap();
        }
        let (ran, asked, stderr) = bare_scan(&root).await;
        assert_eq!(ran, everywhere, "{rc:?} boundary={boundary}");
        assert_eq!(asked, all, "{rc:?} boundary={boundary}");
        assert!(!stderr.contains("not searched for projects"), "{stderr}");
    }
}

/// A scan in `root` that must exit 0 and write nothing: the directories
/// it ran in, the purls it asked about, and what it said.
async fn clean_scan(root: &Path, args: &[&str]) -> (Vec<String>, Vec<String>, String) {
    let before = snapshot(root);
    let api = fake_api().await;
    let (code, stdout, stderr) = scan(root, &api, args);
    assert_eq!(code, 0, "{args:?}\nstdout:\n{stdout}\nstderr:\n{stderr}");
    assert_same_tree(&before, &snapshot(root));
    let ran: Vec<String> = headings(&stdout).into_iter().map(str::to_string).collect();
    (ran, queried(&api).await, stderr)
}

/// A checkout with a Bazel workspace in `ws/`, below the directory a scan
/// starts in, whose rc file sends `bazel vendor` to `ws/third_party/bazel`.
fn lay_nested_workspace(root: &Path, rc: &str) {
    npm_project(root, "web", "web-only");
    npm_project(root, "ws/app", "app-only");
    npm_project(root, "ws/third_party/bazel/+npm+dep", "vendored-only");
    put(root, "ws/MODULE.bazel", "");
    put(root, "ws/.bazelrc", rc);
}

/// HZ-03: the search for projects knows what each directory's own run
/// knows. A run in a directory reads the rc files of the Bazel roots
/// above it and refuses a scope inside a vendor directory they name; a
/// bare scan from above the workspace hands each project it found to such
/// a run. So the search reads the rc file of a Bazel root it meets below
/// the scanned directory too, and leaves that vendor directory out with a
/// note: found and then refused, it failed the scan of the whole checkout
/// (exit 1) where the same checkout without the rc line exits 0.
#[tokio::test]
async fn a_vendor_dir_of_a_bazel_root_below_the_scanned_directory_holds_no_project() {
    let note = "1 directory below this one was not searched for projects";
    let kept = [purl("app-only"), purl("web-only")];
    for mode in ["hosted", "vendored"] {
        let (_tmp, root) = checkout();
        lay_nested_workspace(&root, "common --vendor_dir=third_party/bazel\n");
        let (ran, asked, stderr) = clean_scan(&root, &["--mode", mode]).await;
        assert_eq!(ran, ["web", "ws/app"], "{mode}");
        assert_eq!(asked, kept, "{mode}");
        let named = format!("Note: {note} (ws/third_party/bazel)");
        assert_eq!(stderr.matches(&named).count(), 1, "{mode}: {stderr}");

        // The same search from inside the workspace, as before.
        let (ran, asked, stderr) = clean_scan(&at(&root, "ws"), &["--mode", mode]).await;
        assert_eq!(ran, [".", "app"], "{mode}");
        assert_eq!(asked, kept[..1], "{mode}");
        let named = format!("Note: {note} (third_party/bazel)");
        assert_eq!(stderr.matches(&named).count(), 1, "{mode}: {stderr}");

        // No such line: the directory is a project like its neighbours,
        // as it is to every earlier release.
        put(&root, "ws/.bazelrc", "build --jobs=4\n");
        let (ran, asked, stderr) = clean_scan(&root, &["--mode", mode]).await;
        let inside = "ws/third_party/bazel/+npm+dep";
        assert_eq!(ran, ["web", "ws/app", inside], "{mode}");
        assert_eq!(asked.len(), 3, "{mode}: {asked:?}");
        assert!(!stderr.contains("not searched for projects"), "{stderr}");
    }
}

/// The second look (`projects_below::discovered`): a Bazel root whose
/// boundary file git ignores is one the walk never lists, and a run
/// started in its vendor directory still finds it. The project the walk
/// returned there is asked the question its own run asks, and is left out
/// with the same note instead of failing the scan.
#[tokio::test]
async fn a_project_its_own_run_would_refuse_is_left_out_of_a_bare_scan() {
    let (_tmp, root) = checkout();
    lay_nested_workspace(&root, "common --vendor_dir=third_party/bazel\n");
    put(&root, ".gitignore", "MODULE.bazel\n");
    let inside = "ws/third_party/bazel/+npm+dep";
    let (ran, asked, stderr) = clean_scan(&root, &["--mode", "hosted"]).await;
    assert_eq!(ran, ["web", "ws/app"]);
    assert_eq!(asked, [purl("app-only"), purl("web-only")]);
    let note = format!("Note: 1 directory below this one was not searched for projects ({inside})");
    assert_eq!(stderr.matches(&note).count(), 1, "{stderr}");
    // Its own run refuses it, which is what the scan above was spared.
    let api = fake_api().await;
    let (code, stdout, _) = scan(
        &root,
        &api,
        &["--mode", "hosted", "--json", "--cwd", inside],
    );
    assert_eq!(code, 1, "{stdout}");
    let refusal = Code::AgentOutputTree.as_str();
    let envelope = parse_json_envelope(&stdout);
    assert_eq!(envelope_error_code(&envelope), Some(refusal));
}

/// A PATH glob takes the directories of as many workspaces as it matches,
/// and each workspace's rc file names a vendor directory of its own. Each
/// match is judged by the Bazel roots above it: judged by the roots of
/// the first match, the vendor directory of the second workspace was
/// scanned, and its own run refused it (exit 1).
#[tokio::test]
async fn a_glob_over_two_workspaces_leaves_out_the_vendor_dir_of_each() {
    let lay = |root: &Path, rc: &str| {
        for ws in ["a", "b"] {
            put(root, &format!("{ws}/MODULE.bazel"), "");
            put(root, &format!("{ws}/.bazelrc"), rc);
            npm_project(root, &format!("{ws}/app"), &format!("{ws}-app"));
            let vendored = format!("{ws}-vendored");
            npm_project(root, &format!("{ws}/third_party"), &vendored);
        }
    };
    let (_tmp, root) = checkout();
    lay(&root, "common --vendor_dir=third_party\n");
    let (ran, asked, stderr) = clean_scan(&root, &["--mode", "hosted", "*/*"]).await;
    assert_eq!(ran, ["a/app", "b/app"]);
    assert_eq!(asked, [purl("a-app"), purl("b-app")]);
    let note = "Note: 2 directories a PATH pattern matched were not scanned \
                (a/third_party, b/third_party)";
    assert_eq!(stderr.matches(note).count(), 1, "{stderr}");

    // Without the lines the four directories are four projects.
    let (_tmp, root) = checkout();
    lay(&root, "build --jobs=4\n");
    let (ran, asked, stderr) = clean_scan(&root, &["--mode", "hosted", "*/*"]).await;
    assert_eq!(ran, ["a/app", "a/third_party", "b/app", "b/third_party"]);
    assert_eq!(asked.len(), 4, "{asked:?}");
    assert!(!stderr.contains("were not scanned"), "{stderr}");
}

/// The agent crawl keeps out of such a directory too: a package that a
/// vendored repository has installed is no installed copy of the
/// project's.
#[tokio::test]
async fn the_agent_crawl_takes_no_package_from_a_tracked_vendor_dir() {
    let installed = |root: &Path, dir: &str, dep: &str| {
        let manifest = format!(r#"{{ "name": "{dep}", "version": "1.0.0" }}"#);
        put(
            root,
            &format!("{dir}/node_modules/{dep}/package.json"),
            manifest,
        );
        put(root, &format!("{dir}/node_modules/{dep}/index.js"), "");
    };
    for (rc, crawled) in [
        ("common --vendor_dir=third_party/bazel\n", false),
        ("build --jobs=4\n", true),
    ] {
        let (_tmp, root) = checkout();
        put(&root, "MODULE.bazel", "module(name = \"ws\")\n");
        put(&root, ".bazelrc", rc);
        put(
            &root,
            "package.json",
            r#"{ "name": "ws", "version": "0.0.0", "workspaces": ["apps/*", "third_party/bazel/*"] }"#,
        );
        installed(&root, "", "root-dep");
        installed(&root, "apps/web", "web-dep");
        put(
            &root,
            "apps/web/package.json",
            r#"{ "name": "web", "version": "0.0.0" }"#,
        );
        installed(&root, "third_party/bazel/+npm+dep", "vendored-dep");
        let vendored_manifest = r#"{ "name": "dep", "version": "0.0.0" }"#;
        put(
            &root,
            "third_party/bazel/+npm+dep/package.json",
            vendored_manifest,
        );
        let before = snapshot(&root);
        let api = fake_api().await;
        let (code, stdout, stderr) = scan(&root, &api, &["--mode", "agent", "--json"]);
        assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
        let asked = queried(&api).await;
        assert!(asked.contains(&purl("root-dep")), "{rc}: {asked:?}");
        assert!(asked.contains(&purl("web-dep")), "{rc}: {asked:?}");
        assert_eq!(
            asked.contains(&purl("vendored-dep")),
            crawled,
            "{rc}: {asked:?}"
        );
        assert_same_tree(&before, &snapshot(&root));
    }
}
