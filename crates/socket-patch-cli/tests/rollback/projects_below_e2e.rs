//! What a bare `scan` patched from a checkout's root is visible and
//! undoable from that root: with no patches at `--cwd` itself, `list` and
//! a bare `rollback` cover the patched projects below it, and the commands
//! that act on one project name them.
//!
//! Binary-driven over a checkout with nothing at its root and three patched
//! projects below it: `api` (agent mode: a manifest, blobs and an installed
//! patched package), `svc` and `web` (hosted pins in `yarn.lock`). A fourth
//! hosted-wired lockfile sits under `tests/fixtures/`, where the path
//! policy's built-in ignores keep it out of every run made from the root.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::common;
use crate::common::git_sha256;
use crate::rollback_fixture::{
    install_npm_pkg, manifest_entry, run_hosted, tree, write_root_package_json,
    write_socket_manifest, yarn_block_for, yarn_lock_content, yarn_original_block,
    yarn_redirected_block, yarn_upstream_block_for, NpmRegistry, IO_HOSTED_URL, IO_PURL, LP_PURL,
};

const AGENT_PURL: &str = "pkg:npm/covgap-target@1.0.0";
const AGENT_UUID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BEFORE: &[u8] = b"covgap-original-content\n";
const AFTER: &[u8] = b"covgap-patched-content\n";
/// The lockfile no run from the root may list or rewrite.
const FIXTURE_LOCK: &str = "tests/fixtures/app/yarn.lock";

fn is_odd_redirected_block() -> String {
    yarn_block_for("is-odd", "3.0.1", IO_HOSTED_URL, "sha512-PATCHEDpatched==")
}

fn write_hosted_project(dir: &Path, block: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("yarn.lock"), yarn_lock_content(block)).unwrap();
}

/// An agent-mode project: a lockfile (what makes it a project directory),
/// the installed package holding the patched bytes, and its manifest and
/// blobs. Returns the installed package's directory.
fn write_agent_project(dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    write_root_package_json(dir);
    std::fs::write(
        dir.join("package-lock.json"),
        format!(
            r#"{{ "name": "api", "version": "0.0.0", "lockfileVersion": 3, "packages": {{
              "": {{ "name": "api", "version": "0.0.0" }},
              "node_modules/covgap-target": {{ "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/covgap-target/-/covgap-target-1.0.0.tgz",
                "integrity": "sha512-{}==" }} }} }}"#,
            "A".repeat(86)
        ),
    )
    .unwrap();
    let pkg = install_npm_pkg(dir, "node_modules", "covgap-target", "1.0.0", AFTER);
    let (before, after) = (git_sha256(BEFORE), git_sha256(AFTER));
    let socket = write_socket_manifest(
        dir,
        &[manifest_entry(AGENT_PURL, AGENT_UUID, &before, &after)],
    );
    common::write_blob(&socket, &before, BEFORE);
    common::write_blob(&socket, &after, AFTER);
    pkg
}

/// The checkout described in the module docs. Returns its tempdir and the
/// agent project's installed package directory.
fn monorepo() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    let pkg = write_agent_project(&root.join("api"));
    write_hosted_project(&root.join("svc"), &is_odd_redirected_block());
    write_hosted_project(&root.join("web"), &yarn_redirected_block());
    write_hosted_project(&root.join("tests/fixtures/app"), &yarn_redirected_block());
    (tmp, pkg)
}

fn registry() -> NpmRegistry {
    NpmRegistry::start(&[("left-pad", "1.2.3"), ("is-odd", "3.0.1")])
}

fn read(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap()
}

/// The lines of `text` that are `== <dir> ==` headings, in order.
fn headings(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|line| line.starts_with("== ") && line.ends_with(" =="))
        .collect()
}

fn warning<'a>(envelope: &'a Value, code: &str) -> Option<&'a str> {
    envelope["warnings"]
        .as_array()?
        .iter()
        .find(|w| w["code"] == code)?["detail"]
        .as_str()
}

/// The headline: from the root, where scan left nothing, `list` shows each
/// project's patches under scan's heading and a total, never the false "no
/// patches" line, and never the fixture.
#[test]
fn list_shows_the_patches_of_each_project_below() {
    let (tmp, _) = monorepo();
    let (code, stdout, stderr) = run_hosted(tmp.path(), &["list"], None);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(
        headings(&stdout),
        ["== api ==", "== svc ==", "== web =="],
        "{stdout}"
    );
    for purl in [AGENT_PURL, IO_PURL, LP_PURL] {
        assert!(
            stdout.contains(&format!("Package: {purl}")),
            "{purl}: {stdout}"
        );
    }
    assert!(
        stdout
            .trim_end()
            .ends_with("3 patches in 3 project directories below this one."),
        "{stdout}"
    );
    assert!(!stdout.contains("No patches in this project"), "{stdout}");
    assert!(!stdout.contains("fixtures"), "{stdout}");
}

/// `list --json` stays one document: the envelope for `--cwd` as before,
/// with each project's own envelope beside it under `projects`.
#[test]
fn list_json_adds_the_projects_to_the_one_envelope() {
    let (tmp, _) = monorepo();
    let (code, stdout, stderr) = run_hosted(tmp.path(), &["list", "--json"], None);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("one JSON document");
    assert_eq!(envelope["command"], "list");
    assert_eq!(envelope["status"], "success");
    assert_eq!(envelope["events"], serde_json::json!([]));
    assert_eq!(envelope["summary"]["discovered"], 0);
    let projects = envelope["projects"].as_array().expect("projects[]");
    let seen: Vec<(&str, &str)> = projects
        .iter()
        .map(|p| {
            assert_eq!(p["status"], "success", "{p}");
            assert_eq!(p["summary"]["discovered"], 1, "{p}");
            (
                p["path"].as_str().unwrap(),
                p["events"][0]["purl"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [("api", AGENT_PURL), ("svc", IO_PURL), ("web", LP_PURL)]
    );
}

/// A project that cannot be listed fails as it does on its own: its error
/// is reported, the others are still listed, and the run exits 1 naming it.
#[test]
fn a_project_that_cannot_be_listed_does_not_hide_the_others() {
    let (tmp, _) = monorepo();
    std::fs::write(tmp.path().join("api/.socket/manifest.json"), b"{ not json").unwrap();

    let (code, stdout, stderr) = run_hosted(tmp.path(), &["list"], None);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(
        headings(&stdout),
        ["== api ==", "== svc ==", "== web =="],
        "{stdout}"
    );
    for purl in [IO_PURL, LP_PURL] {
        assert!(
            stdout.contains(&format!("Package: {purl}")),
            "{purl}: {stdout}"
        );
    }
    assert!(
        stderr.contains("Error: 1 project directory could not be listed: api"),
        "{stderr}"
    );

    let (code, stdout, stderr) = run_hosted(tmp.path(), &["list", "--json"], None);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("one JSON document");
    assert_eq!(envelope["status"], "partialFailure");
    let projects = envelope["projects"].as_array().expect("projects[]");
    assert_eq!(projects[0]["path"], "api");
    assert_eq!(projects[0]["status"], "error");
    assert_eq!(projects[0]["error"]["code"], "manifest_invalid");
    assert_eq!(projects[1]["status"], "success");
}

/// A dry run previews every project and writes nothing anywhere.
#[test]
fn rollback_dry_run_previews_every_project_and_writes_nothing() {
    let (tmp, _) = monorepo();
    let before = tree(tmp.path());
    let registry = registry();
    let (code, stdout, stderr) =
        run_hosted(tmp.path(), &["rollback", "--dry-run"], Some(&registry));
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(
        headings(&stdout),
        ["== api ==", "== svc ==", "== web =="],
        "{stdout}"
    );
    for purl in [IO_PURL, LP_PURL] {
        assert!(
            stdout.contains(&format!(
                "Would restore {purl} to its upstream registry entry"
            )),
            "{purl}: {stdout}"
        );
    }
    assert!(
        stdout.contains("Would roll back 3 project directories below this one."),
        "{stdout}"
    );
    assert_eq!(tree(tmp.path()), before, "a dry run writes nothing");
}

/// The undo of what scan did: each project is rolled back as if it were
/// `--cwd`, after one confirmation that names them all. The fixture's
/// lockfile is not a project of this run.
#[test]
fn rollback_undoes_every_project_below_and_asks_once() {
    let (tmp, pkg) = monorepo();
    let fixture = read(tmp.path(), FIXTURE_LOCK);
    let registry = registry();
    let (code, stdout, stderr) = run_hosted(tmp.path(), &["rollback"], Some(&registry));
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(
        headings(&stdout),
        ["== api ==", "== svc ==", "== web =="],
        "{stdout}"
    );
    assert_eq!(std::fs::read(pkg.join("index.js")).unwrap(), BEFORE);
    assert_eq!(
        read(tmp.path(), "svc/yarn.lock"),
        yarn_lock_content(&yarn_upstream_block_for("is-odd", "3.0.1"))
    );
    assert_eq!(
        read(tmp.path(), "web/yarn.lock"),
        yarn_lock_content(&yarn_original_block())
    );
    assert_eq!(read(tmp.path(), FIXTURE_LOCK), fixture);
    assert!(
        stdout.contains("Rolled back 3 project directories below this one."),
        "{stdout}"
    );
    // No terminal: the one question is answered for the user, once.
    assert_eq!(
        stderr.matches("proceeding automatically").count(),
        1,
        "{stderr}"
    );
}

#[cfg(unix)]
mod interactive {
    use super::*;
    use crate::common::hermetic;
    use crate::pty_io;
    use crate::rollback_fixture::PATCH_SERVER;
    use std::time::Duration;

    const QUESTION: &str = "Roll back every Socket patch in 3 project directories below this \
                            one (api, svc, web)? [Y/n]";

    /// One line of the terminal's output, however the question wrapped.
    fn unwrapped(output: &str) -> String {
        output.replace("\r\n", "").replace('\n', "")
    }

    /// On a terminal the run asks once, naming every directory it would
    /// reach; "no" leaves all of them as they were.
    #[test]
    fn declining_the_one_question_changes_nothing() {
        let (tmp, _) = monorepo();
        let before = tree(tmp.path());
        let (code, output) = pty_io::run(
            &["rollback", "--patch-server-url", PATCH_SERVER],
            tmp.path(),
            "n\n",
            Duration::from_secs(15),
        );
        assert_eq!(code, 0, "{output}");
        assert!(unwrapped(&output).contains(QUESTION), "{output}");
        assert_eq!(output.matches("[Y/n]").count(), 1, "{output}");
        assert!(output.contains("Cancelled; no changes made."), "{output}");
        assert!(headings(&output.replace('\r', "")).is_empty(), "{output}");
        assert_eq!(tree(tmp.path()), before);
    }

    /// "Yes" is asked for once and covers every project.
    #[test]
    fn accepting_the_one_question_rolls_back_every_project() {
        let (tmp, pkg) = monorepo();
        let registry = registry();
        let base = registry.base();
        let run = pty_io::run_command(
            hermetic::pty_binary_command(),
            &["rollback", "--patch-server-url", PATCH_SERVER],
            tmp.path(),
            &[("SOCKET_NPM_REGISTRY", base.as_str())],
            &[b"y\n"],
            Duration::from_secs(30),
        );
        assert_eq!(run.code, 0, "{}", run.output);
        assert_eq!(run.output.matches("[Y/n]").count(), 1, "{}", run.output);
        assert_eq!(std::fs::read(pkg.join("index.js")).unwrap(), BEFORE);
        assert_eq!(
            read(tmp.path(), "svc/yarn.lock"),
            yarn_lock_content(&yarn_upstream_block_for("is-odd", "3.0.1"))
        );
        assert_eq!(
            read(tmp.path(), "web/yarn.lock"),
            yarn_lock_content(&yarn_original_block())
        );
    }
}

/// A project whose rollback fails does not stop the others, and the run
/// says which one failed.
#[test]
fn a_failing_project_does_not_stop_the_others() {
    let (tmp, pkg) = monorepo();
    // The registry cannot resolve is-odd: `svc` cannot be restored.
    let registry = NpmRegistry::start(&[("left-pad", "1.2.3")]);
    let (code, stdout, stderr) = run_hosted(tmp.path(), &["rollback", "--yes"], Some(&registry));
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(
        read(tmp.path(), "svc/yarn.lock"),
        yarn_lock_content(&is_odd_redirected_block()),
        "the failed project keeps its wiring"
    );
    assert_eq!(std::fs::read(pkg.join("index.js")).unwrap(), BEFORE);
    assert_eq!(
        read(tmp.path(), "web/yarn.lock"),
        yarn_lock_content(&yarn_original_block()),
        "the project after the failed one is still rolled back"
    );
    assert!(
        stderr.contains("Error: Rollback failed in 1 of 3 project directories: svc"),
        "{stderr}"
    );
}

/// `--json` is one document, so it takes one project: with several below
/// it refuses the way scan does, naming them, before anything is written.
#[test]
fn rollback_json_refuses_several_projects() {
    let (tmp, _) = monorepo();
    let before = tree(tmp.path());
    let registry = registry();
    let (code, stdout, stderr) = run_hosted(
        tmp.path(),
        &["rollback", "--json", "--yes"],
        Some(&registry),
    );
    assert_eq!(code, 2, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("one JSON document");
    assert_eq!(envelope["error"]["code"], "invalid_args");
    let message = envelope["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("--json takes one project directory"),
        "{message}"
    );
    assert!(message.contains("api, svc, web"), "{message}");
    assert!(
        message.contains("socket-patch rollback --json --cwd api"),
        "{message}"
    );
    assert_eq!(tree(tmp.path()), before);
}

/// With one patched project below, `--json` rolls it back: its envelope is
/// the one document.
#[test]
fn rollback_json_takes_the_one_project_below() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
    write_hosted_project(&tmp.path().join("web"), &yarn_redirected_block());
    let registry = registry();
    let (code, stdout, stderr) = run_hosted(
        tmp.path(),
        &["rollback", "--json", "--yes"],
        Some(&registry),
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("one JSON document");
    assert_eq!(envelope["command"], "rollback");
    assert_eq!(envelope["status"], "success");
    assert_eq!(
        read(tmp.path(), "web/yarn.lock"),
        yarn_lock_content(&yarn_original_block())
    );
}

/// An identifier names one project's patch, so the run does not fan out:
/// it fails as before, and now says where that patch is.
#[test]
fn rollback_of_an_identifier_names_the_project_that_holds_it() {
    let (tmp, _) = monorepo();
    let before = tree(tmp.path());
    let registry = registry();
    let (code, stdout, stderr) =
        run_hosted(tmp.path(), &["rollback", "--yes", LP_PURL], Some(&registry));
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stderr.contains("Error: "), "{stderr}");
    assert!(
        stderr.contains(&format!("socket-patch rollback {LP_PURL} --cwd web")),
        "{stderr}"
    );
    assert!(!stderr.contains("--cwd svc"), "{stderr}");
    assert!(headings(&stdout).is_empty(), "{stdout}");
    assert_eq!(tree(tmp.path()), before);

    // The command named is the one that was run, flags included.
    let (code, stdout, _) = run_hosted(
        tmp.path(),
        &[
            "rollback",
            "--json",
            "--dry-run",
            "--preserve-state",
            LP_PURL,
        ],
        Some(&registry),
    );
    assert_eq!(code, 1, "{stdout}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("one JSON document");
    assert_eq!(envelope["error"]["code"], "manifest_not_found");
    let detail = warning(&envelope, "patched_projects_below").expect("the warning");
    assert!(
        detail.contains(&format!(
            "socket-patch rollback {LP_PURL} --preserve-state --dry-run --cwd web"
        )),
        "{detail}"
    );
}

/// The commands that act on one project do not fan out. Finding nothing at
/// the root, they name the projects below and the run that reaches each;
/// their exit codes are the ones they had.
#[test]
fn single_project_commands_name_the_projects_below() {
    let (tmp, _) = monorepo();
    let before = tree(tmp.path());
    let run = |args: &[&str]| run_hosted(tmp.path(), args, None);

    let (code, _, stderr) = run(&["vex", "--product", "pkg:generic/mono"]);
    assert_eq!(code, 2, "{stderr}");
    for dir in ["api", "svc", "web"] {
        assert!(
            stderr.contains(&format!("\n  socket-patch vex --cwd {dir}\n")),
            "{dir}: {stderr}"
        );
    }
    assert!(!stderr.contains("fixtures"), "{stderr}");

    // `apply` works from the manifest: only the agent-mode project has one.
    for (args, command) in [
        (&["apply"][..], "apply"),
        (&["apply", "--check"][..], "apply --check"),
    ] {
        let (code, _, stderr) = run(args);
        assert_eq!(code, 0, "{args:?}: {stderr}");
        assert!(
            stderr.contains(&format!("\n  socket-patch {command} --cwd api\n")),
            "{args:?}: {stderr}"
        );
        assert!(!stderr.contains("--cwd web"), "{args:?}: {stderr}");
    }

    // `repair` restores local artifacts, which hosted mode keeps none of.
    let (code, _, stderr) = run(&["repair"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains("\n  socket-patch repair --cwd api\n"),
        "{stderr}"
    );
    assert!(!stderr.contains("--cwd web"), "{stderr}");

    // The command named is the one that was run: a preview stays a preview.
    let (code, _, stderr) = run(&["remove", LP_PURL, "--dry-run", "--preserve-state"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains(&format!(
            "\n  socket-patch remove {LP_PURL} --preserve-state --dry-run --cwd web\n"
        )),
        "{stderr}"
    );
    assert!(!stderr.contains("--cwd svc"), "{stderr}");

    assert_eq!(tree(tmp.path()), before, "none of them writes anything");
}

/// Hosted projects keep no manifest and nothing local, so `apply` and
/// `repair` have no work in them and never send the user there. `repair`,
/// which fails at the root, still says the patches are below; `apply`,
/// which reads no lockfile, has nothing to add to its calm exit.
#[test]
fn hosted_projects_below_get_no_apply_or_repair_command() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
    write_hosted_project(&tmp.path().join("svc"), &is_odd_redirected_block());
    write_hosted_project(&tmp.path().join("web"), &yarn_redirected_block());

    let (code, _, stderr) = run_hosted(tmp.path(), &["repair", "--dry-run"], None);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains(
            "Note: 2 project directories below this one hold Socket patches (svc, web), all \
             hosted: there is nothing local to repair"
        ),
        "{stderr}"
    );
    assert!(!stderr.contains("--cwd"), "{stderr}");

    for args in [
        &["apply"][..],
        &["apply", "--check"][..],
        &["apply", "--silent"][..],
    ] {
        let (code, _, stderr) = run_hosted(tmp.path(), args, None);
        assert_eq!((code, stderr.as_str()), (0, ""), "{args:?}");
    }
}

/// Under `--json` the same advice is a `patched_projects_below` warning in
/// the document each command already prints; status and error are as before.
#[test]
fn single_project_commands_warn_in_their_json() {
    let (tmp, _) = monorepo();
    let run = |args: &[&str]| {
        let (code, stdout, stderr) = run_hosted(tmp.path(), args, None);
        let envelope: Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("{args:?}: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}"));
        (code, envelope)
    };

    let (code, envelope) = run(&["apply", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(envelope["status"], "noManifest");
    let detail = warning(&envelope, "patched_projects_below").expect("apply");
    assert!(detail.contains("socket-patch apply --cwd api"), "{detail}");

    let (code, envelope) = run(&["repair", "--json", "--dry-run"]);
    assert_eq!(code, 1);
    assert_eq!(envelope["error"]["code"], "manifest_not_found");
    let detail = warning(&envelope, "patched_projects_below").expect("repair");
    assert!(
        detail.contains("socket-patch repair --dry-run --cwd api"),
        "{detail}"
    );

    let (code, envelope) = run(&["remove", LP_PURL, "--json", "--dry-run"]);
    assert_eq!(code, 1);
    assert_eq!(envelope["error"]["code"], "manifest_not_found");
    let detail = warning(&envelope, "patched_projects_below").expect("remove");
    assert!(
        detail.contains(&format!(
            "socket-patch remove {LP_PURL} --dry-run --cwd web"
        )),
        "{detail}"
    );

    let out = tmp.path().join("out.vex.json");
    let (code, envelope) = run(&[
        "vex",
        "--json",
        "--product",
        "pkg:generic/mono",
        "--output",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 2);
    assert_eq!(envelope["error"]["code"], "manifest_not_found");
    let detail = warning(&envelope, "patched_projects_below").expect("vex");
    assert!(detail.contains("socket-patch vex --cwd web"), "{detail}");
}

/// The checkout bounds the search, as it does for scan: outside one, every
/// command is the single-directory run it was, with the exit code and the
/// output it has in a directory that holds nothing at all.
#[test]
fn outside_a_checkout_nothing_changes() {
    let (tmp, _) = monorepo();
    std::fs::remove_dir_all(tmp.path().join(".git")).unwrap();
    let before = tree(tmp.path());
    let empty = tempfile::tempdir().expect("tempdir");
    let registry = registry();

    for args in [
        &["list"][..],
        &["list", "--json"][..],
        &["rollback", "--yes"][..],
        &["rollback", "--yes", "--json"][..],
        &["rollback", "--dry-run", LP_PURL][..],
        &["vex", "--product", "pkg:generic/mono"][..],
        &["apply"][..],
        &["apply", "--check"][..],
        &["repair", "--dry-run"][..],
        &["remove", LP_PURL, "--dry-run"][..],
    ] {
        let here = run_hosted(tmp.path(), args, Some(&registry));
        let nothing = run_hosted(empty.path(), args, Some(&registry));
        assert_eq!(here, nothing, "{args:?}");
    }
    assert_eq!(tree(tmp.path()), before);
}

/// A directory with patches of its own is the project the run is about:
/// no headings, no projects below, as before.
#[test]
fn a_directory_with_its_own_patches_behaves_as_before() {
    let (tmp, _) = monorepo();
    let registry = registry();

    // A project directory of the checkout.
    let web = tmp.path().join("web");
    let (code, stdout, _) = run_hosted(&web, &["list"], None);
    assert_eq!(code, 0);
    assert!(headings(&stdout).is_empty(), "{stdout}");
    assert!(stdout.contains(&format!("Package: {LP_PURL}")), "{stdout}");

    // The root, once it holds a hosted pin itself.
    std::fs::write(
        tmp.path().join("yarn.lock"),
        yarn_lock_content(&is_odd_redirected_block()),
    )
    .unwrap();
    let (code, stdout, _) = run_hosted(tmp.path(), &["list"], None);
    assert_eq!(code, 0);
    assert!(headings(&stdout).is_empty(), "{stdout}");
    assert!(stdout.contains(&format!("Package: {IO_PURL}")), "{stdout}");
    assert!(!stdout.contains(LP_PURL), "{stdout}");

    let (code, stdout, stderr) = run_hosted(tmp.path(), &["rollback", "--yes"], Some(&registry));
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(headings(&stdout).is_empty(), "{stdout}");
    assert_eq!(
        read(tmp.path(), "yarn.lock"),
        yarn_lock_content(&yarn_upstream_block_for("is-odd", "3.0.1"))
    );
    assert_eq!(
        read(tmp.path(), "web/yarn.lock"),
        yarn_lock_content(&yarn_redirected_block()),
        "the project below is not this run's"
    );
}

/// The set is scan's: a project the repository's socket.yml leaves out of
/// a scan is left out here too.
#[test]
fn the_socket_yml_path_policy_applies() {
    let (tmp, _) = monorepo();
    std::fs::write(
        tmp.path().join("socket.yml"),
        "version: 2\nprojectIgnorePaths:\n  - \"svc/**\"\n",
    )
    .unwrap();
    let svc = read(tmp.path(), "svc/yarn.lock");
    let registry = registry();

    let (code, stdout, stderr) = run_hosted(tmp.path(), &["list"], None);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(headings(&stdout), ["== api ==", "== web =="], "{stdout}");

    let (code, stdout, stderr) = run_hosted(tmp.path(), &["rollback", "--yes"], Some(&registry));
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(read(tmp.path(), "svc/yarn.lock"), svc);
    assert_eq!(
        read(tmp.path(), "web/yarn.lock"),
        yarn_lock_content(&yarn_original_block())
    );
}
