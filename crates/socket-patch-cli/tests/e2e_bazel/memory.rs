//! Hermetic tests: the in-memory engine in a Bazel workspace (hazards
//! HZ-20 and HZ-03 of design 3).
//!
//! The engine patches nothing Bazel builds. Every test here goes the way
//! a host goes: path selection over a tree listing, then the real session
//! over exactly the files selection asked for, against a fake Socket API
//! that offers a patch for every npm package of the fixture. So a test
//! that sees no pin and no request saw the engine leave a package alone,
//! not a package nobody offered a patch for; each has a twin without the
//! Bazel files, where the same package is pinned as it always was.
//!
//! Nothing here runs the CLI binary, and nothing touches the disk: the
//! in-memory engine has none.

use std::collections::BTreeMap;

use socket_patch_cli::hosted_memory::{
    select_paths, HostedScanOutput, MarkKind, PathSelection, PresentKind, SelectOptions,
    SessionBuilder, TreeEntryInput,
};
use socket_patch_core::bazel::codes::Code;
use wiremock::MockServer;

#[path = "../hosted_memory_common/mod.rs"]
mod memory_common;

use memory_common::{fixtures_root, mount_api, options, patches_from_overrides, run_engine};

const NPM_FIXTURE: &str = "redirect/npm/package-lock-v3/basic";
/// The one package the fixture's lock resolves, and its patch.
const PATCHED: &str = "pkg:npm/left-pad@1.3.0";

/// rules_js over `//:pnpm-lock.yaml`: Bazel builds the npm packages of
/// the workspace root from that lock.
const RULES_JS: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"2.9.3\")\n\
    npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
    npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
    use_repo(npm, \"npm\")\n";
/// A workspace that builds no registry package at all.
const RULES_CC: &str =
    "module(name = \"app\")\nbazel_dep(name = \"rules_cc\", version = \"0.1.1\")\n";

/// A repository as a host lists it: path to content.
#[derive(Clone, Default)]
struct Repo {
    files: BTreeMap<String, Vec<u8>>,
    symlinks: Vec<String>,
}

impl Repo {
    fn with(mut self, path: &str, text: &str) -> Self {
        self.files
            .insert(path.to_string(), text.as_bytes().to_vec());
        self
    }

    /// The npm fixture project (one lock that resolves [`PATCHED`]) at
    /// `dir`.
    fn npm_project(mut self, dir: &str) -> Self {
        let lock = fixtures_root()
            .join(NPM_FIXTURE)
            .join("input/package-lock.json");
        let lock = std::fs::read(lock).expect("the fixture lock");
        let at = |name: &str| match dir.is_empty() {
            true => name.to_string(),
            false => format!("{dir}/{name}"),
        };
        self.files.insert(at("package-lock.json"), lock);
        self
    }

    /// Lists `path` as a symbolic link (git mode 120000).
    fn linked(mut self, path: &str) -> Self {
        self.symlinks.push(path.to_string());
        self
    }

    fn without(mut self, path: &str) -> Self {
        self.files.remove(path);
        self
    }

    fn listing(&self) -> Vec<TreeEntryInput> {
        let entry = |path: &String| TreeEntryInput {
            path: path.clone(),
            mode: match self.symlinks.contains(path) {
                true => "120000".to_string(),
                false => "100644".to_string(),
            },
            kind: "blob".to_string(),
            size: Some(self.files[path].len() as u64),
        };
        self.files.keys().map(entry).collect()
    }
}

/// How the session is told its roots.
#[derive(Clone, Copy, PartialEq)]
enum Roots {
    /// `projectRoots` unset: the session detects them over what it holds.
    Detected,
    /// `projectRoots` = the roots selection returned.
    Selected,
}

/// Path selection over `repo`, then the session over exactly what
/// selection asked for: each `fetchText` and `fetchBinary` path with its
/// content, each `presentOnly` path and each symbolic link as a mark.
async fn scan(server: &MockServer, repo: &Repo, roots: Roots) -> (PathSelection, HostedScanOutput) {
    let selection = select_paths(&repo.listing(), &SelectOptions::default());
    let mut opts = options(false);
    if roots == Roots::Selected {
        opts.project_roots = Some(selection.roots.clone());
    }
    let mut session = SessionBuilder::new(opts).expect("valid options");
    for path in &selection.fetch_text {
        session.push_chunk(path, &repo.files[path]).unwrap();
        session.end_file(path).unwrap();
    }
    for path in &selection.fetch_binary {
        session.add_binary(path, &repo.files[path]).unwrap();
    }
    for path in &selection.present_only {
        let kind = MarkKind::Present(PresentKind::Present);
        session.mark_present(path, kind).unwrap();
    }
    for path in &selection.symlinks {
        session.mark_present(path, MarkKind::Symlink).unwrap();
    }
    let output = run_engine(server, session.finish().unwrap()).await;
    (selection, output)
}

/// A fake Socket API with the fixture's patch for [`PATCHED`].
async fn api() -> MockServer {
    let server = MockServer::start().await;
    let overrides = fixtures_root().join(NPM_FIXTURE).join("overrides.json");
    mount_api(&server, &patches_from_overrides(&overrides, None)).await;
    server
}

/// Every purl the session asked the API about, sorted.
async fn queried(server: &MockServer) -> Vec<String> {
    let requests = server.received_requests().await.unwrap_or_default();
    let mut purls: Vec<String> = Vec::new();
    for request in requests.iter().filter(|r| r.url.path().ends_with("/batch")) {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
        let components = body["components"].as_array().cloned().unwrap_or_default();
        let purl = |c: &serde_json::Value| c["purl"].as_str().map(str::to_string);
        purls.extend(components.iter().filter_map(purl));
    }
    purls.sort();
    purls.dedup();
    purls
}

fn roots_of(output: &HostedScanOutput) -> Vec<&str> {
    output.projects.iter().map(|p| p.root.as_str()).collect()
}

fn changed(output: &HostedScanOutput) -> Vec<&str> {
    output
        .changed_files
        .iter()
        .map(|f| f.path.as_str())
        .collect()
}

/// The warnings of `code`, as `(project root, detail)`.
fn warned<'a>(output: &'a HostedScanOutput, code: Code) -> Vec<(Option<&'a str>, &'a str)> {
    let of_code = output.warnings.iter().filter(|w| w.code == code.as_str());
    of_code
        .map(|w| (w.project_root.as_deref(), w.detail.as_str()))
        .collect()
}

/// What a run says and does, less what only counts its input: for
/// comparing a run with and without files the engine reads and changes
/// nothing by.
fn outcome(output: &HostedScanOutput) -> serde_json::Value {
    let mut value = serde_json::to_value(output).unwrap();
    value["stats"]["phaseMs"] = serde_json::Value::Null;
    value["stats"]["filesInput"] = serde_json::Value::Null;
    value["stats"]["bytesInput"] = serde_json::Value::Null;
    value
}

/// HZ-20: an ecosystem a ruleset builds in a project is left alone
/// there. Not looked up, so not offered, not pinned, and no file of it
/// rewritten; the project says so once. The same lock in a project the
/// hub does not reach, and in a repository with no Bazel file, is pinned.
#[tokio::test]
async fn an_ecosystem_bazel_builds_is_not_looked_up_and_not_pinned() {
    let bazel = Repo::default()
        .with("MODULE.bazel", RULES_JS)
        .with(".bazelrc", "common --lockfile_mode=error\n")
        .npm_project("")
        .npm_project("tools/web");
    for roots in [Roots::Detected, Roots::Selected] {
        let server = api().await;
        let (selection, output) = scan(&server, &bazel, roots).await;
        assert_eq!(selection.roots, ["", "tools/web"]);
        // What says which ecosystems Bazel builds was asked for.
        for streamed in ["MODULE.bazel", ".bazelrc"] {
            assert!(selection.fetch_text.iter().any(|path| path == streamed));
        }
        assert_eq!(roots_of(&output), ["", "tools/web"]);
        let (root, web) = (&output.projects[0], &output.projects[1]);
        assert!(root.error.is_none() && web.error.is_none());
        // The root: nothing scanned, nothing pinned, nothing skipped as a
        // patch that was offered and refused.
        assert_eq!(root.summary.scanned_packages, 0);
        assert!(root.redirected.is_empty() && root.skipped.is_empty());
        // The project the hub's lock is not in: as always.
        assert_eq!(web.redirected.len(), 1);
        assert_eq!(web.redirected[0].purl, PATCHED);
        assert_eq!(
            changed(&output),
            ["tools/web/.npmrc", "tools/web/package-lock.json"]
        );
        // One warning, for the root, naming what was left alone.
        let said = warned(&output, Code::WorkspaceUnsupportedInMemory);
        let [(Some(""), detail)] = said.as_slice() else {
            panic!("one warning for the root: {said:?}");
        };
        assert!(detail.starts_with("MODULE.bazel makes this project part of a Bazel workspace"));
        assert!(
            detail.contains("1 package (npm) was not scanned"),
            "{detail}"
        );
        assert!(
            detail.contains("socket-patch scan --mode hosted"),
            "{detail}"
        );
        assert_eq!(
            queried(&server).await,
            [PATCHED],
            "asked for tools/web alone"
        );
    }

    // The twin with no Bazel file: both projects are pinned, no warning.
    let plain = bazel.clone().without("MODULE.bazel").without(".bazelrc");
    let server = api().await;
    let (_, output) = scan(&server, &plain, Roots::Detected).await;
    assert_eq!(roots_of(&output), ["", "tools/web"]);
    assert!(output.projects.iter().all(|p| p.redirected.len() == 1));
    assert!(warned(&output, Code::WorkspaceUnsupportedInMemory).is_empty());
    assert!(changed(&output).contains(&"package-lock.json"));
}

/// A Bazel workspace that builds no npm package changes nothing for npm:
/// the run is, to the byte of its output, the run of the same repository
/// without the Bazel files.
#[tokio::test]
async fn a_workspace_that_builds_no_package_of_the_ecosystem_changes_nothing() {
    let plain = Repo::default().npm_project("").npm_project("apps/web");
    let bazel = plain
        .clone()
        .with("MODULE.bazel", RULES_CC)
        .with(".bazelrc", "build --incompatible_strict_action_env\n")
        .with(
            "BUILD.bazel",
            "cc_binary(name = \"app\", srcs = [\"main.cc\"])\n",
        )
        .with(".bazelversion", "8.4.2\n");
    let server = api().await;
    let (plain_selection, plain_output) = scan(&server, &plain, Roots::Detected).await;
    let (selection, output) = scan(&server, &bazel, Roots::Detected).await;
    assert_eq!(selection.roots, plain_selection.roots);
    assert_eq!(outcome(&output), outcome(&plain_output));
    assert_eq!(output.projects.len(), 2);
    assert!(output.projects.iter().all(|p| p.redirected.len() == 1));
    // Selection asked for the two files that say so, and for no other
    // Bazel file.
    let extra: Vec<&String> = selection
        .fetch_text
        .iter()
        .filter(|path| !plain_selection.fetch_text.contains(path))
        .collect();
    assert_eq!(extra, [".bazelrc", "MODULE.bazel"]);
}

/// Unreadable is not absent: where the streamed files cannot say what the
/// workspace declares, every ecosystem a ruleset can build is left alone.
#[tokio::test]
async fn what_the_streamed_files_cannot_decide_is_left_alone() {
    let include = "include(\"//third_party:npm.MODULE.bazel\")\n";
    let macros = "load(\"//:deps.bzl\", \"deps\")\ndeps()\n";
    let undecided = [
        // The hub may be in the included file, which is not streamed.
        Repo::default().with("MODULE.bazel", include),
        // Or in the `.bzl` file of a WORKSPACE macro.
        Repo::default().with("WORKSPACE", macros),
        // A boundary file that is a link is never fetched.
        Repo::default()
            .with("MODULE.bazel", RULES_CC)
            .linked("MODULE.bazel"),
        // A nested root does not cut its directory out of the outer one.
        Repo::default()
            .with("MODULE.bazel", include)
            .with("svc/MODULE.bazel", RULES_CC),
    ];
    for (case, repo) in undecided.into_iter().enumerate() {
        let repo = repo.npm_project("svc/api");
        let server = api().await;
        let (_, output) = scan(&server, &repo, Roots::Detected).await;
        assert_eq!(roots_of(&output), ["svc/api"], "case {case}");
        assert!(output.projects[0].redirected.is_empty(), "case {case}");
        assert!(output.changed_files.is_empty(), "case {case}");
        let said = warned(&output, Code::WorkspaceUnsupportedInMemory);
        assert_eq!(said.len(), 1, "case {case}: {said:?}");
        assert_eq!(said[0].0, Some("svc/api"), "case {case}");
        assert_eq!(queried(&server).await, [""; 0], "case {case}");
    }
}

/// A workspace with an output base and a vendor directory kept in the
/// repository, each holding the lockfiles of what Bazel fetched.
fn with_trees() -> Repo {
    Repo::default()
        .with("MODULE.bazel", RULES_CC)
        .npm_project("")
        .npm_project("apps/web")
        .with("vendor_src/VENDOR.bazel", "")
        .npm_project("vendor_src/+http_archive+dep")
        .with(
            "vendor_src/+http_archive+dep/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        )
        .with("vendor_src/+http_archive+dep/java/pom.xml", "<project/>")
        .with("out/DO_NOT_BUILD_HERE", "/repo")
        .with("out/external/bazel_tools/WORKSPACE", "")
        .npm_project("out/external/rules_nodejs~")
        .npm_project("out/execroot/_main")
}

/// HZ-03 in memory (ROUTED R-030): the session detects roots over the
/// streamed files alone, so nothing in a tree Bazel owns may be streamed.
/// A lock streamed from inside one would be a project to the session,
/// which would ask the API about the packages of a fetched repository.
#[tokio::test]
async fn nothing_inside_a_bazel_tree_becomes_a_project() {
    let repo = with_trees();
    let in_tree = |path: &str| path.starts_with("vendor_src/") || path.starts_with("out/");
    for roots in [Roots::Detected, Roots::Selected] {
        let server = api().await;
        let (selection, output) = scan(&server, &repo, roots).await;
        assert_eq!(selection.roots, ["", "apps/web"]);
        let streamed = [
            &selection.fetch_text,
            &selection.fetch_binary,
            &selection.present_only,
            &selection.symlinks,
        ];
        let inside: Vec<&String> = streamed
            .into_iter()
            .flatten()
            .filter(|p| in_tree(p))
            .collect();
        assert!(inside.is_empty(), "streamed from a tree: {inside:?}");
        // The session's projects are selection's roots, and both are
        // pinned: rules_cc builds no npm package.
        assert_eq!(roots_of(&output), selection.roots);
        assert!(output.projects.iter().all(|p| p.redirected.len() == 1));
        assert!(changed(&output).iter().all(|path| !in_tree(path)));
        // What was left out is said: each lock inside a tree, by name.
        let skipped = Code::WorkspaceOutputTreeSkipped.as_str();
        let reported = |path: &str| {
            let mut sample = selection.ignored_sample.iter();
            sample.any(|ignored| ignored.path == path && ignored.reason == skipped)
        };
        assert!(reported("vendor_src/+http_archive+dep/package-lock.json"));
        assert!(reported("out/execroot/_main/package-lock.json"));
    }

    // Without the markers the same directories are projects, as before:
    // the markers are what the engine goes by.
    let unmarked = repo
        .without("vendor_src/VENDOR.bazel")
        .without("out/DO_NOT_BUILD_HERE");
    let server = api().await;
    let (selection, output) = scan(&server, &unmarked, Roots::Detected).await;
    assert!(selection
        .roots
        .iter()
        .any(|root| root == "vendor_src/+http_archive+dep"));
    assert_eq!(roots_of(&output), selection.roots);
}

/// HZ-17 in memory (ROUTED R-031): a vendor directory holds copies of
/// the fetched repositories, test fixtures included, and one malformed
/// `package.json` among them must not withhold every npm package of the
/// project. In memory the walk for user patches never sees the directory,
/// because nothing in it is streamed.
#[tokio::test]
async fn a_vendor_directory_withholds_no_npm_package_of_the_project() {
    const BAD: &str = "third_party/bazel/npm__resolve/package/test/bad/package.json";
    let repo = Repo::default()
        .with("MODULE.bazel", RULES_CC)
        .with(
            "package.json",
            r#"{ "name": "app", "version": "0.0.0", "workspaces": ["**"] }"#,
        )
        .npm_project("")
        .with("third_party/bazel/VENDOR.bazel", "")
        .with(BAD, "{");
    let server = api().await;
    let (selection, output) = scan(&server, &repo, Roots::Detected).await;
    assert!(!selection.fetch_text.iter().any(|path| path == BAD));
    assert_eq!(roots_of(&output), [""]);
    let root = &output.projects[0];
    assert!(root.error.is_none(), "{:?}", root.error);
    assert_eq!(root.redirected.len(), 1, "skipped: {:?}", root.skipped);
    assert!(root.skipped.is_empty(), "{:?}", root.skipped);

    // The directory with no marker is a workspace member like any other,
    // and the manifest nobody can read withholds the package: what the
    // marker spares the project.
    let server = api().await;
    let unmarked = repo.without("third_party/bazel/VENDOR.bazel");
    let (selection, output) = scan(&server, &unmarked, Roots::Detected).await;
    assert!(selection.fetch_text.iter().any(|path| path == BAD));
    let root = &output.projects[0];
    assert!(root.redirected.is_empty(), "{:?}", root.redirected);
    assert!(
        root.skipped
            .iter()
            .any(|s| s.reason == "user_patch_conflict"),
        "{:?}",
        root.skipped
    );
}

/// HZ-03 (ROUTED R-032): a vendor directory that only a tracked
/// `--vendor_dir` names has no marker in the listing: `bazel vendor` has
/// not run, or git does not track the marker. Selection reads no content
/// and cannot know it; the session reads the streamed `.bazelrc` and
/// makes no project of anything inside.
#[tokio::test]
async fn a_vendor_directory_only_an_rc_file_names_holds_no_project() {
    let repo = Repo::default()
        .with("MODULE.bazel", RULES_CC)
        .with(".bazelrc", "common:ci --vendor_dir=third_party/bazel\n")
        .npm_project("web")
        .npm_project("third_party/bazel/+npm+dep")
        .npm_project("third_party/other");
    let inside = "third_party/bazel/+npm+dep";
    let skipped = Code::WorkspaceOutputTreeSkipped;

    // Roots detected by the session: the directory is not among them.
    let server = api().await;
    let (selection, output) = scan(&server, &repo, Roots::Detected).await;
    assert!(selection.roots.iter().any(|root| root == inside));
    assert_eq!(roots_of(&output), ["third_party/other", "web"]);
    assert!(output.projects.iter().all(|p| p.redirected.len() == 1));
    assert!(changed(&output)
        .iter()
        .all(|path| !path.starts_with(inside)));

    // Roots named by the caller, as selection returned them: the one in
    // the vendor directory is left out, and the session says which.
    let server = api().await;
    let (_, output) = scan(&server, &repo, Roots::Selected).await;
    assert_eq!(roots_of(&output), ["third_party/other", "web"]);
    let said = warned(&output, skipped);
    let [(None, detail)] = said.as_slice() else {
        panic!("one run-level warning: {said:?}");
    };
    assert!(detail.starts_with(&format!("`{inside}` not scanned: Bazel owns")));
    assert!(changed(&output)
        .iter()
        .all(|path| !path.starts_with(inside)));

    // No rc line, or an rc file beside no Bazel workspace file: the
    // directory is a project like its neighbours.
    let no_line = repo.clone().with(".bazelrc", "build --jobs=4\n");
    let no_root = repo.without("MODULE.bazel");
    for (case, plain) in [no_line, no_root].into_iter().enumerate() {
        let server = api().await;
        let (_, output) = scan(&server, &plain, Roots::Selected).await;
        assert_eq!(
            roots_of(&output),
            [inside, "third_party/other", "web"],
            "case {case}"
        );
        assert!(warned(&output, skipped).is_empty(), "case {case}");
    }
}
