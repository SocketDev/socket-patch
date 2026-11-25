//! `SOCKET_NO_BAZEL=1` and the in-memory hosted engine, which judges a
//! Bazel hub from the files handed to it and looks for no workspace on
//! disk: with the variable set, the engine pins what it pins for the same
//! files without their `MODULE.bazel`, and its path selection asks the
//! host for what it asks for the tree without its Bazel files.
//!
//! The engine reads the variable from the environment of its process, so
//! each test holds it through the guard, set or unset, before any server
//! starts, and the two run one after the other. The target is theirs
//! alone: no other test reads the environment beside them.

use std::collections::BTreeMap;

use serde_json::Value;
use wiremock::MockServer;

#[path = "hosted_memory_common/mod.rs"]
mod common;

use common::*;
use socket_patch_cli::hosted_memory::{select_paths, PathSelection, SelectOptions, TreeEntryInput};

/// The core unit tests' env guard, compiled into this test binary too.
#[allow(dead_code)]
#[path = "../../socket-patch-core/src/test_env.rs"]
mod test_env;
use test_env::EnvGuard;

/// The switch for a project that Bazel does not build.
const OFF: &str = "SOCKET_NO_BAZEL";

/// The files of a tree, by path.
type Files = BTreeMap<String, Vec<u8>>;

/// What the engine asks its host to stream of a tree with the files
/// `files`.
fn selection(files: &Files) -> PathSelection {
    let blob = |(path, bytes): (&String, &Vec<u8>)| TreeEntryInput {
        path: path.clone(),
        mode: "100644".into(),
        kind: "blob".into(),
        size: Some(bytes.len() as u64),
    };
    let entries: Vec<TreeEntryInput> = files.iter().map(blob).collect();
    select_paths(&entries, &SelectOptions::default())
}

/// What the engine gives for `files` against the patch API at `server`:
/// the files it changed and the `redirect` block of the root project.
async fn pins(server: &MockServer, files: &Files) -> (Files, Value) {
    let mut opts = options(false);
    opts.trust_lockfile_config = Some(true);
    let output = run_engine(server, build_input(files, &[], opts)).await;
    let project = &output.projects[0];
    assert!(project.error.is_none(), "{:?}", project.error);
    (engine_changed(&output), sorted_redirect(&project.redirect))
}

/// Whether the pnpm lock among `changed` is routed through a named
/// registry: it keys a release by one (`name@socket-<id>:version`).
fn routed(changed: &Files) -> bool {
    let lock = changed.get("pnpm-lock.yaml");
    lock.is_some_and(|lock| String::from_utf8_lossy(lock).contains("@socket-"))
}

/// Trees whose root has every file that the path selection takes for one
/// of a Bazel workspace, beside what makes it ask for them: a pnpm lock, a
/// `pnpm-workspace.yaml` whose only lock is a member's, and a gem lock.
/// Each as the tree without those files and the tree with them.
fn trees_with_bazel_files() -> Vec<(Files, Files)> {
    let bazel = [
        "MODULE.bazel",
        "WORKSPACE",
        "WORKSPACE.bazel",
        "WORKSPACE.bzlmod",
        "tools/hubs.MODULE.bazel",
    ];
    let own: [&[&str]; 3] = [
        &["pnpm-lock.yaml", "package.json"],
        &[
            "pnpm-workspace.yaml",
            "package.json",
            "packages/a/package.json",
            "packages/a/pnpm-lock.yaml",
        ],
        &["Gemfile", "Gemfile.lock"],
    ];
    let tree = |names: &[&str]| -> Files {
        let file = |name: &&str| (name.to_string(), b"x\n".to_vec());
        names.iter().map(file).collect()
    };
    own.iter()
        .map(|own| (tree(own), tree(&[*own, &bazel[..]].concat())))
        .collect()
}

/// One project of the tests: what it is, the patch API that serves its
/// patch, its files without and with the `MODULE.bazel`, what the warnings
/// say beside the hub, and whether the patch service offers the patch's
/// registry (the directory its tarball is served from).
struct Project {
    row: String,
    server: MockServer,
    plain: Files,
    beside: Files,
    said: &'static str,
    offered: bool,
}

/// A gem lock beside a rules_ruby hub that holds the gem to its upstream
/// sha256, a pnpm lock beside a rules_js hub that hides
/// `pnpm-workspace.yaml` from pnpm 11, and a pnpm lock that a rules_js hub
/// reads, in a project that proves pnpm 12 and is offered the patch's
/// registry. Each starts its patch API: a test holds the variable before
/// it asks for them.
async fn projects() -> Vec<Project> {
    let ruby = format!(
        "bazel_dep(name = \"rules_ruby\", version = \"1.0.0-rc2\")\n\
         ruby = use_extension(\"@rules_ruby//ruby:extensions.bzl\", \"ruby\")\n\
         ruby.bundle_fetch(\n    name = \"bundle\",\n    gemfile = \"//:Gemfile\",\n    \
         gemfile_lock = \"//:Gemfile.lock\",\n    gem_checksums = {{\"rails-7.0.0\": \
         \"{}\"}},\n)\n",
        "2".repeat(64)
    );
    let js = "module(name = \"app\")\n\
              bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
              npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
              npm.npm_translate_lock(\n    name = \"npm\",\n    \
              pnpm_lock = \"//:pnpm-lock.yaml\",\n    update_pnpm_lock = True,\n)\n\
              pnpm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"pnpm\")\n\
              pnpm.pnpm(name = \"pnpm\", pnpm_version = \"11.28.10\")\n";
    // A hub that only reads the lock: its call is on line 4.
    let reads = "module(name = \"app\")\n\
                 bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
                 npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
                 npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n";
    let own: [(&str, &[u8]); 2] = [
        ("pnpm-workspace.yaml", b"# own\npackages:\n  - '.'\n"),
        ("package.json", br#"{ "name": "root", "private": true }"#),
    ];
    let pnpm_12: [(&str, &[u8]); 2] = [
        own[0],
        (
            "package.json",
            br#"{"name":"app","packageManager":"pnpm@12.22.0","dependencies":{"left-pad":"1.3.0"}}"#,
        ),
    ];
    // The fixture, the files added to it, its `MODULE.bazel`, what the
    // warnings say beside the hub, and whether the registry is offered.
    let rows = [
        (
            "redirect/gem/bundler/basic",
            &own[..0],
            ruby.as_str(),
            "redirect_bazel_gem_checksums_pinned",
            false,
        ),
        (
            "redirect/npm/pnpm/basic",
            &own[..],
            js,
            "redirect_pnpm_bazel_workspace_hidden",
            false,
        ),
        (
            "redirect/npm/pnpm/basic",
            &pnpm_12[..],
            reads,
            "a Bazel hub reads the pnpm lock (MODULE.bazel:4)",
            true,
        ),
    ];
    let mut projects = Vec::new();
    for (fixture, more, module, said, offered) in rows {
        let dir = fixtures_root().join(fixture);
        let server = MockServer::start().await;
        let mut patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
        for patch in patches.iter_mut().filter(|_| offered) {
            let url = patch.reference["url"].as_str().expect("a URL").to_string();
            let directory = &url[..=url.rfind('/').expect("the URL of a tarball")];
            patch.reference["npmRegistryUrl"] = directory.into();
        }
        mount_api(&server, &patches).await;
        let mut plain = fixture_files(&dir.join("input"));
        for (rel, bytes) in more {
            plain.insert(rel.to_string(), bytes.to_vec());
        }
        let mut beside = plain.clone();
        beside.insert("MODULE.bazel".to_string(), module.as_bytes().to_vec());
        let row = format!("{fixture}, {said}");
        projects.push(Project {
            row,
            server,
            plain,
            beside,
            said,
            offered,
        });
    }
    projects
}

/// Without the variable, whatever the shell of the test run exports: the
/// engine leaves the gem lock and the pnpm lock of the hub that hides
/// `pnpm-workspace.yaml` as they are and says why; the lock that a hub
/// only reads is pinned and not routed through the patch's registry, and
/// the engine says that the hub is why. Its selection asks for the
/// `MODULE.bazel` of each, and for every file of a Bazel workspace beside
/// a pnpm lock, a `pnpm-workspace.yaml` or a gem lock.
#[tokio::test]
#[serial_test::serial]
async fn a_hub_keeps_the_engine_from_pinning_or_routing() {
    let _unset = EnvGuard::unset(OFF);
    for project in projects().await {
        let Project { row, said, .. } = &project;
        let (changed, redirect) = pins(&project.server, &project.beside).await;
        // Beside the hub nothing is pinned, or, where the hub only keeps
        // the lock off the registry, the lock is pinned and not routed.
        let pinned = changed.contains_key("pnpm-lock.yaml");
        assert_eq!(pinned, project.offered, "{row}: {}", describe(&changed));
        assert!(!routed(&changed), "{row}: {}", describe(&changed));
        assert_eq!(changed.is_empty(), !project.offered, "{row}");
        let warned = redirect["warnings"].to_string();
        assert!(warned.contains(said), "{row}: {redirect:#}");
        let asked = selection(&project.beside).fetch_text;
        assert!(asked.iter().any(|path| path == "MODULE.bazel"), "{asked:?}");
    }
    for (plain, beside) in &trees_with_bazel_files() {
        let asked = selection(beside).fetch_text;
        for file in beside.keys().filter(|file| !plain.contains_key(*file)) {
            assert!(asked.contains(file), "{file}: {asked:?}");
        }
    }
}

/// With `SOCKET_NO_BAZEL=1` the engine pins each, and says, what it does
/// for the same files without the `MODULE.bazel`, so the third lock is
/// routed, and the selection is the one of the tree without its Bazel
/// files: no file is fetched, and counted against a session's limits, that
/// nothing judges.
#[tokio::test]
#[serial_test::serial]
async fn the_switch_makes_the_engine_pin_as_without_the_bazel_file() {
    let _set = EnvGuard::set(OFF, "1");
    for project in projects().await {
        let Project { row, server, .. } = &project;
        let without = pins(server, &project.plain).await;
        assert!(!without.0.is_empty(), "{row}: {:#}", without.1);
        // The route is taken where it is offered: the offer is live, and
        // the hub was what stood against it.
        let offered = project.offered;
        assert_eq!(routed(&without.0), offered, "{row}: {:#}", without.1);
        assert!(!without.1.to_string().contains("Bazel"), "{row}");
        assert_eq!(pins(server, &project.beside).await, without, "{row}");
        let asked = selection(&project.beside);
        assert_eq!(asked, selection(&project.plain), "{row}");
    }
    for (plain, beside) in &trees_with_bazel_files() {
        assert_eq!(selection(beside), selection(plain), "{:?}", plain.keys());
    }
}
