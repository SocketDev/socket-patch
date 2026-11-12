//! Hermetic CLI tests: output-tree refusals and pruning (hazards HZ-02,
//! HZ-03 and HZ-24 of design 3).
//!
//! Bazel owns four kinds of directory: an output base, an entry of the
//! repo contents cache, an entry of the repository cache and a vendor
//! directory. What is patched in one is replaced by a later build or
//! shared with other workspaces, so socket-patch neither writes nor crawls
//! there, and nothing in one is a project. The trees here are fabricated
//! as the probes recorded them (C7: the markers after a build and after
//! `clean` and a build; C8: a base kept in the checkout; C9: `--cwd
//! bazel-bin`; C11: a vendor directory, with the marker 7.1.2 to 7.2.1
//! write as well). The real-Bazel twin is `e2e_bazel_build::classifier`.

use std::path::{Path, PathBuf};

use serde_json::Value;
use socket_patch_core::bazel::codes::Code;
use socket_patch_core::patch::shared_store::BAZEL_TREE_REFUSAL_MARKER;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::bazel_common::{assert_same_tree, assert_write_policy, snapshot};
use crate::common::hermetic::{self, Extra};
use crate::common::jvm_env;
use crate::common::{
    binary, envelope_error_code, envelope_error_message, git_sha256, hermetic_command,
    parse_json_envelope, write_blob, write_minimal_manifest, PatchEntry,
};

const ORG: &str = "test-org";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const UPSTREAM: &[u8] = b"module.exports = 'upstream';\n";
const PATCHED: &[u8] = b"module.exports = 'patched';\n";

/// A scratch root, canonical: the binary prints resolved paths.
fn scratch() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    (tmp, root)
}

fn put(root: &Path, rel: &str, bytes: impl AsRef<[u8]>) {
    let file = root.join(rel);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, bytes).unwrap();
}

/// How the last Bazel commands left an output base (probe C7).
#[derive(Clone, Copy, Debug)]
enum Base {
    /// After a build: a marker in the base and one in `execroot`.
    Built,
    /// After `bazel clean` and a build on the same server: the second
    /// marker is gone and no build writes it again.
    CleanedAndBuilt,
}

/// An output base of `workspace` at `base`: the marker holds the
/// workspace path with no newline, as a server writes it.
fn lay_base(base: &Path, workspace: &Path, state: Base) {
    let marker = workspace.to_string_lossy().into_owned();
    put(base, "DO_NOT_BUILD_HERE", &marker);
    if matches!(state, Base::Built) {
        put(base, "execroot/DO_NOT_BUILD_HERE", &marker);
    }
    put(base, "external/bazel_tools/WORKSPACE", "");
    std::fs::create_dir_all(base.join("execroot/_main/bazel-out")).unwrap();
}

/// An npm project at `dir` whose lock resolves `dep`, not installed.
fn npm_project(dir: &Path, dep: &str, version: &str) {
    let deps = format!(r#""dependencies": {{ "{dep}": "{version}" }}"#);
    let manifest = format!(r#"{{ "name": "p", "version": "0.0.0", {deps} }}"#);
    put(dir, "package.json", &manifest);
    let lock = format!(
        r#"{{ "name": "p", "version": "0.0.0", "lockfileVersion": 3, "packages": {{
          "": {{ "name": "p", "version": "0.0.0", {deps} }},
          "node_modules/{dep}": {{ "version": "{version}",
            "resolved": "https://registry.npmjs.org/{dep}/-/{dep}-{version}.tgz",
            "integrity": "sha512-{}==" }} }} }}"#,
        "A".repeat(86)
    );
    put(dir, "package-lock.json", lock);
}

/// `left-pad@1.3.0` installed under `dir/node_modules`; returns its file.
fn install_left_pad(dir: &Path) -> PathBuf {
    let pkg = r#"{ "name": "left-pad", "version": "1.3.0" }"#;
    put(dir, "node_modules/left-pad/package.json", pkg);
    put(dir, "node_modules/left-pad/index.js", UPSTREAM);
    dir.join("node_modules/left-pad/index.js")
}

/// A manifest and blob under `project/.socket` that patch the file of
/// [`install_left_pad`], so that `apply --offline` has all it needs.
fn stage_patch(project: &Path) {
    let after = git_sha256(PATCHED);
    let entry = PatchEntry {
        file_name: "package/index.js",
        before_hash: &git_sha256(UPSTREAM),
        after_hash: &after,
    };
    let socket = project.join(".socket");
    write_minimal_manifest(
        &socket,
        PURL,
        "9c1f4a52-7d3e-4b8a-a6f0-2e5d8c7b1a90",
        &[entry],
    );
    write_blob(&socket, &after, PATCHED);
}

/// The binary in `cwd`: `(exit code, stdout, stderr)`.
fn run(cwd: &Path, args: &[&str], env: &[(&str, &Path)]) -> (i32, String, String) {
    let mut cmd = hermetic_command(&binary());
    // No host virtualenv and no host JVM caches: an agent scan would
    // crawl them and ask the API about this machine's packages.
    hermetic::scrub_extra(&mut cmd, &[Extra::Venv]);
    jvm_env::isolate_cli(&mut cmd);
    cmd.args(args).current_dir(cwd);
    for (name, value) in env {
        cmd.env(name, value);
    }
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
    run(cwd, &[&fixed[..], args].concat(), &[])
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

/// Every purl the runs so far asked the API about, sorted: the oracle for
/// what a scan took for a package of the project.
async fn queried(api: &MockServer) -> Vec<String> {
    let requests = api.received_requests().await.unwrap_or_default();
    let mut purls: Vec<String> = Vec::new();
    for request in requests {
        let body: Value = serde_json::from_slice(&request.body).expect("a JSON request");
        let components = body["components"].as_array().cloned().unwrap_or_default();
        purls.extend(
            components
                .iter()
                .map(|c| c["purl"].as_str().unwrap().to_string()),
        );
    }
    purls.sort();
    purls.dedup();
    purls
}

/// Asserts a refusal: exit 1, the coded error, the remedy, and that the
/// sentence ends the way every Bazel refusal does.
fn assert_refused(run: &(i32, String, String), what: &str) {
    let (code, stdout, stderr) = run;
    assert_eq!(*code, 1, "{what}\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let envelope = parse_json_envelope(stdout);
    let refusal = Code::AgentOutputTree.as_str();
    assert_eq!(envelope_error_code(&envelope), Some(refusal), "{what}");
    let message = envelope_error_message(&envelope).expect("a message");
    assert!(
        message.contains(BAZEL_TREE_REFUSAL_MARKER),
        "{what}: {message}"
    );
    assert!(message.contains("scan --mode hosted"), "{what}: {message}");
    assert!(
        message.ends_with("nothing was written"),
        "{what}: {message}"
    );
    assert_eq!(envelope["events"], serde_json::json!([]), "{what}");
}

/// A legacy `npm_install` / `yarn_install` repository rule runs the
/// project's lifecycle hooks inside `<output base>/external/<repo>`, so a
/// hook that runs `socket-patch apply` lands there. It must not fail (the
/// rule and every JS target would), and it must not patch: with no
/// manifest it is the no-op it always was, and with one it warns, writes
/// nothing and exits 0.
#[test]
fn apply_in_a_fabricated_external_npm_exits_0_with_and_without_a_manifest() {
    for state in [Base::Built, Base::CleanedAndBuilt] {
        let (_tmp, root) = scratch();
        let base = root.join("_bazel_u/6d82");
        lay_base(&base, &root.join("ws"), state);
        let repo = base.join("external/npm");
        npm_project(&repo, "left-pad", "1.3.0");
        let installed = install_left_pad(&repo);

        // No manifest: decided first, exactly as outside Bazel.
        let before = snapshot(&root);
        let (code, stdout, stderr) = run(&repo, &["apply"], &[]);
        assert_eq!((code, stderr.as_str()), (0, ""), "{state:?}: {stdout}");
        assert!(stdout.contains("No patch manifest found"), "{stdout}");
        let (code, stdout, _) = run(&repo, &["apply", "--json"], &[]);
        let envelope = parse_json_envelope(&stdout);
        assert_eq!((code, &envelope["status"]), (0, &Value::from("noManifest")));
        assert_eq!(envelope.get("warnings"), None, "{stdout}");
        assert_same_tree(&before, &snapshot(&root));

        // A manifest and its blob: everything an apply needs to patch.
        stage_patch(&repo);
        let before = snapshot(&root);
        let (code, stdout, stderr) = run(&repo, &["apply", "--offline"], &[]);
        assert_eq!((code, stdout.as_str()), (0, ""), "{state:?}: {stderr}");
        assert!(stderr.starts_with("Warning: "), "{stderr}");
        assert!(stderr.contains("in a Bazel output base"), "{stderr}");
        assert!(stderr.contains(BAZEL_TREE_REFUSAL_MARKER), "{stderr}");
        for flags in [&["--json"][..], &["--json", "--dry-run"]] {
            let (code, stdout, _) = run(&repo, &[&["apply", "--offline"], flags].concat(), &[]);
            let envelope = parse_json_envelope(&stdout);
            assert_eq!((code, &envelope["status"]), (0, &Value::from("success")));
            let warning = Code::WorkspaceInsideOutputTree.as_str();
            assert_eq!(envelope["warnings"][0]["code"], warning, "{stdout}");
            assert_eq!(envelope["warnings"].as_array().map(Vec::len), Some(1));
            assert_eq!(envelope["events"], serde_json::json!([]), "{stdout}");
        }
        // `--silent` is what a hook passes: nothing at all.
        let quiet = run(&repo, &["apply", "--offline", "--silent"], &[]);
        assert_eq!(quiet, (0, String::new(), String::new()), "{state:?}");
        // `--cwd .` names the directory the process is already in.
        let (code, _, stderr) = run(&repo, &["apply", "--offline", "--cwd", "."], &[]);
        assert!(code == 0 && stderr.starts_with("Warning: "), "{stderr}");
        // No patched file, no lock file, no staged file: the tree is as found.
        assert_eq!(std::fs::read(&installed).unwrap(), UPSTREAM);
        assert_same_tree(&before, &snapshot(&root));
    }

    // The same project outside any Bazel tree is patched: what was left
    // alone above was a patch the run could have applied.
    let (_tmp, root) = scratch();
    npm_project(&root, "left-pad", "1.3.0");
    let installed = install_left_pad(&root);
    stage_patch(&root);
    let (code, stdout, stderr) = run(&root, &["apply", "--offline"], &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(std::fs::read(&installed).unwrap(), PATCHED);
}

/// A directory the caller chose is refused: `--cwd`, its variable and
/// `--global-prefix`. So is `apply --check` wherever it runs, since
/// passing would say the patches are in place where nothing was checked.
#[test]
fn apply_aimed_at_a_bazel_tree_is_refused_and_writes_nothing() {
    let (_tmp, root) = scratch();
    let base = root.join("_bazel_u/6d82");
    lay_base(&base, &root.join("ws"), Base::CleanedAndBuilt);
    let repo = base.join("external/npm");
    install_left_pad(&repo);
    stage_patch(&repo);
    // A project of its own, for the run that only aims its prefix there.
    let project = root.join("project");
    let own = install_left_pad(&project);
    stage_patch(&project);
    let (repo_arg, prefix) = (repo.to_string_lossy(), repo.join("node_modules"));
    let prefix_arg = prefix.to_string_lossy();
    let before = snapshot(&root);

    let refused = |what: &str, cwd: &Path, args: &[&str], env: &[(&str, &Path)]| {
        let json = ["apply", "--offline", "--json"];
        assert_refused(&run(cwd, &[&json[..], args].concat(), env), what);
    };
    refused("--cwd", &root, &["--cwd", &repo_arg], &[]);
    refused("SOCKET_CWD", &root, &[], &[("SOCKET_CWD", &repo)]);
    let aimed = ["--global-prefix", &*prefix_arg];
    refused("--global-prefix", &project, &aimed, &[]);
    refused("--check in the tree", &repo, &["--check"], &[]);
    refused(
        "--check --cwd",
        &root,
        &["--check", "--cwd", &repo_arg],
        &[],
    );
    // Without `--json` the same refusal is one `Error:` line, also under
    // `--silent`.
    let (code, stdout, stderr) = run(&root, &["apply", "--silent", "--cwd", &repo_arg], &[]);
    assert_eq!((code, stdout.as_str()), (1, ""), "{stderr}");
    assert!(
        stderr.starts_with("Error: Refusing to apply in "),
        "{stderr}"
    );
    assert_eq!(std::fs::read(&own).unwrap(), UPSTREAM);
    assert_same_tree(&before, &snapshot(&root));
}

/// A package directory that is a link into an output base is refused by
/// itself, with the same code, while the run goes on for the others: no
/// scope root is in a tree here, only what one `node_modules` entry
/// resolves to.
#[cfg(unix)]
#[test]
fn a_package_linked_into_an_output_base_is_refused_and_left_alone() {
    let (_tmp, root) = scratch();
    let base = root.join("_bazel_u/6d82");
    lay_base(&base, &root.join("ws"), Base::Built);
    let store = base.join("execroot/_main/bazel-out/k8/bin");
    let stored = install_left_pad(&store);
    let project = root.join("project");
    npm_project(&project, "left-pad", "1.3.0");
    std::fs::create_dir_all(project.join("node_modules")).unwrap();
    let link = project.join("node_modules/left-pad");
    std::os::unix::fs::symlink(store.join("node_modules/left-pad"), &link).unwrap();
    stage_patch(&project);
    let before = snapshot(&base);

    let (code, stdout, stderr) = run(&project, &["apply", "--offline", "--json"], &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let envelope = parse_json_envelope(&stdout);
    let failed = &envelope["events"][0];
    let got = (&failed["action"], &failed["errorCode"], &failed["purl"]);
    let refusal = Value::from(Code::AgentOutputTree.as_str());
    assert_eq!(got, (&Value::from("failed"), &refusal, &Value::from(PURL)));
    let message = failed["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("a link into a Bazel output tree"),
        "{stdout}"
    );
    assert!(message.ends_with("nothing was written"), "{stdout}");
    assert_eq!(std::fs::read(&stored).unwrap(), UPSTREAM);
    assert_same_tree(&before, &snapshot(&base));
}

/// The directories inside trees that the scans below are aimed at, each
/// holding an npm project: `(what, directory)`.
fn lay_trees(root: &Path, state: Base) -> Vec<(&'static str, PathBuf)> {
    let (ws, base) = (root.join("ws"), root.join("_bazel_u/6d82"));
    put(&ws, "MODULE.bazel", "module(name = \"ws\")\n");
    npm_project(&ws, "left-pad", "1.3.0");
    lay_base(&base, &ws, state);
    put(&ws, "vendor_src/VENDOR.bazel", "");
    put(&ws, "third_party/.vendorignore", "");
    put(root, "cache/contents/cd12/26ed.recorded_inputs", "cd12\n");
    let scopes = vec![
        // What the convenience links lead to (probe C9).
        ("bazel-bin", base.join("execroot/_main/bazel-out/k8/bin")),
        ("external/<repo>", base.join("external/npm")),
        // A vendored repository (probe C11), under either marker.
        ("VENDOR.bazel", ws.join("vendor_src/+http_archive+dep")),
        (".vendorignore", ws.join("third_party/rules_x~")),
        ("contents cache", root.join("cache/contents/cd12/26ed")),
    ];
    for (_, dir) in &scopes {
        npm_project(dir, "in-a-tree", "9.9.9");
        install_left_pad(dir);
    }
    scopes
}

/// `scan` of a scope root inside a tree is refused in every mode, before
/// anything is crawled or asked of the API, whether the directory is
/// named by `--cwd`, is the working directory, or is a `--global-prefix`.
#[tokio::test]
async fn scan_of_a_bazel_tree_is_refused_before_any_crawl() {
    let api = fake_api().await;
    for state in [Base::Built, Base::CleanedAndBuilt] {
        let (_tmp, root) = scratch();
        let scopes = lay_trees(&root, state);
        let before = snapshot(&root);
        for (what, dir) in &scopes {
            let dir_arg = dir.to_string_lossy();
            for mode in [None, Some("agent"), Some("hosted"), Some("vendored")] {
                let mut args = vec!["--json", "--cwd", &dir_arg];
                args.extend(mode.iter().flat_map(|mode| ["--mode", mode]));
                let what = format!("{state:?}: {what}, mode {mode:?}");
                assert_refused(&scan(&root, &api, &args), &what);
            }
            assert_refused(&scan(dir, &api, &["--json"]), &format!("cd {what}"));
            let prefix = dir.join("node_modules");
            let args = ["--json", "--global-prefix", &prefix.to_string_lossy()];
            assert_refused(
                &scan(&root.join("ws"), &api, &args),
                &format!("prefix {what}"),
            );
        }
        let (code, _, stderr) = scan(&scopes[0].1, &api, &[]);
        assert!(
            code == 1 && stderr.starts_with("Error: Refusing to scan in "),
            "{stderr}"
        );
        assert_same_tree(&before, &snapshot(&root));
    }
    assert_eq!(queried(&api).await, [""; 0], "a refused scan asked the API");
}

/// `scan --cwd bazel-bin` (probe C9: today it patches the rules_js store
/// and the next build reverts it) in the state `bazel clean` and a build
/// leave, where one marker is all that says the tree is Bazel's; the same
/// under `--symlink_prefix=dist/`, below a link, and from inside.
#[cfg(unix)]
#[tokio::test]
async fn scan_cwd_bazel_bin_is_refused_after_clean_and_build() {
    use std::os::unix::fs::symlink;
    let api = fake_api().await;
    let (_tmp, root) = scratch();
    let scopes = lay_trees(&root, Base::CleanedAndBuilt);
    let (ws, bin) = (root.join("ws"), &scopes[0].1);
    std::fs::create_dir_all(ws.join("dist")).unwrap();
    symlink(bin, ws.join("bazel-bin")).unwrap();
    symlink(bin, ws.join("dist/bin")).unwrap();
    let before = snapshot(&root);
    for link in ["bazel-bin", "dist/bin", "bazel-bin/node_modules"] {
        for mode in ["agent", "hosted"] {
            let args = ["--json", "--mode", mode, "--cwd", link];
            assert_refused(
                &scan(&ws, &api, &args),
                &format!("--cwd {link} --mode {mode}"),
            );
        }
    }
    assert_refused(
        &scan(&ws.join("bazel-bin"), &api, &["--json"]),
        "cd bazel-bin",
    );
    assert_same_tree(&before, &snapshot(&root));
    assert_eq!(queried(&api).await, [""; 0]);
}

/// A Bazel workspace whose checkout holds, beside two projects of its
/// own, an output base (probe C8), two vendor directories (probe C11) and
/// the manifests socket-cli generates (HZ-24). Each holds a lockfile that
/// resolves a package named after it.
fn lay_workspace(ws: &Path) {
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    put(ws, "MODULE.bazel", "module(name = \"ws\")\n");
    npm_project(ws, "left-pad", "1.3.0");
    npm_project(&ws.join("apps/web"), "is-odd", "3.0.1");
    lay_base(&ws.join("out"), ws, Base::CleanedAndBuilt);
    npm_project(&ws.join("out/external/rules_nodejs~"), "base-only", "7.7.7");
    // The base mirrors the root's own lock, and holds what the build
    // installed (C8: today these count as the project's installed copies).
    npm_project(&ws.join("out/execroot/_main"), "left-pad", "1.3.0");
    install_left_pad(&ws.join("out/execroot/_main/bazel-out/k8/bin"));
    put(ws, "vendor_src/VENDOR.bazel", "");
    npm_project(
        &ws.join("vendor_src/+http_archive+dep"),
        "vendored-only",
        "9.9.9",
    );
    put(ws, "third_party/.vendorignore", "");
    npm_project(
        &ws.join("third_party/rules_x~"),
        "vendorignore-only",
        "8.8.8",
    );
    npm_project(&ws.join(".socket-auto-manifest"), "generated-only", "6.6.6");
}

/// HZ-03 and HZ-24 from the workspace root, by both entry points that
/// search for projects (the third, `--cwd` inside the vendored
/// repository, is refused above): nothing in a tree and nothing socket-cli
/// generated is scanned, and the run says which directories it left out.
#[tokio::test]
async fn a_workspace_scan_takes_no_project_from_a_bazel_tree() {
    let skipped = Code::WorkspaceOutputTreeSkipped.as_str();
    let (_tmp, ws) = scratch();
    lay_workspace(&ws);
    let before = snapshot(&ws);

    // `--json` takes one directory and names the others it found.
    let api = fake_api().await;
    let (code, stdout, stderr) = scan(&ws, &api, &["--json"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let envelope = parse_json_envelope(&stdout);
    let warning = |code: &str| -> Option<String> {
        let warnings = envelope["warnings"].as_array().expect("warnings");
        let found = warnings.iter().find(|warning| warning["code"] == code)?;
        Some(found["detail"].as_str().expect("detail").to_string())
    };
    let others = warning("projects_not_scanned").expect("the project below");
    assert!(others.starts_with("1 project directory below this one was not scanned (apps/web)"));
    let left_out = warning(skipped).expect("the trees are reported");
    let named = "3 directories below this one were not searched for projects \
                 (out, third_party, vendor_src)";
    assert!(left_out.starts_with(named), "{left_out}");
    // The copy the build left in the base is not this project's install.
    assert_eq!(envelope["lockfileOnlyPackages"], 1, "{stdout}");
    assert_eq!(queried(&api).await, [PURL]);

    // A bare scan runs once per project directory.
    let api = fake_api().await;
    let (code, stdout, stderr) = scan(&ws, &api, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let headings: Vec<&str> = stdout.lines().filter(|l| l.starts_with("== ")).collect();
    assert_eq!(headings, ["== . ==", "== apps/web =="], "{stdout}");
    assert_eq!(
        stderr.matches(&format!("Note: {named}")).count(),
        1,
        "{stderr}"
    );
    assert_eq!(queried(&api).await, ["pkg:npm/is-odd@3.0.1", PURL]);

    // Agent mode crawls for installed copies: none is taken from the base.
    let api = fake_api().await;
    let (code, stdout, stderr) = scan(&ws, &api, &["--mode", "agent", "--json"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let envelope = parse_json_envelope(&stdout);
    assert_eq!(envelope["lockfileOnlyPackages"], 1, "{stdout}");
    assert_eq!(queried(&api).await, [PURL]);

    let writes = assert_write_policy(&before, &snapshot(&ws));
    assert_eq!(
        writes,
        vec![],
        "no patch was offered, so nothing is written"
    );
}
