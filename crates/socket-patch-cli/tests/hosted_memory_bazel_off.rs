//! `SOCKET_NO_BAZEL=1` and the in-memory hosted engine, which judges a
//! Bazel hub from the files handed to it and looks for no workspace on
//! disk: with the variable set, the engine pins what it pins for the same
//! files without their `MODULE.bazel`, and its path selection asks the
//! host for what it asks for the tree without that file.
//!
//! The one test sets the variable for its own process, which is why it has
//! a test target to itself: no other test reads the environment beside it.

use std::collections::BTreeMap;

use serde_json::Value;
use wiremock::MockServer;

#[path = "hosted_memory_common/mod.rs"]
mod common;

use common::*;
use socket_patch_cli::hosted_memory::{select_paths, PathSelection, SelectOptions, TreeEntryInput};

/// What the engine asks its host to stream of a tree with the files
/// `files`.
fn selection(files: &BTreeMap<String, Vec<u8>>) -> PathSelection {
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
async fn pins(
    server: &MockServer,
    files: &BTreeMap<String, Vec<u8>>,
) -> (BTreeMap<String, Vec<u8>>, Value) {
    let mut opts = options(false);
    opts.trust_lockfile_config = Some(true);
    let output = run_engine(server, build_input(files, &[], opts)).await;
    let project = &output.projects[0];
    assert!(project.error.is_none(), "{:?}", project.error);
    (engine_changed(&output), sorted_redirect(&project.redirect))
}

/// A gem lock beside a rules_ruby hub that holds the gem to its upstream
/// sha256, and a pnpm lock beside a rules_js hub that hides
/// `pnpm-workspace.yaml` from pnpm 11: the engine leaves each as it is
/// and says why, and its selection asks for the `MODULE.bazel`. With
/// `SOCKET_NO_BAZEL=1` it pins each, and says, what it does for the same
/// files without the `MODULE.bazel`, and the selection is the one of the
/// tree without that file: no file is fetched, and counted against a
/// session's limits, that nothing judges.
#[tokio::test]
async fn the_switch_makes_the_engine_pin_as_without_the_bazel_file() {
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
    let own: [(&str, &[u8]); 2] = [
        ("pnpm-workspace.yaml", b"# own\npackages:\n  - '.'\n"),
        ("package.json", br#"{ "name": "root", "private": true }"#),
    ];
    let rows = [
        (
            "redirect/gem/bundler/basic",
            &own[..0],
            ruby.as_str(),
            "redirect_bazel_gem_checksums_pinned",
        ),
        (
            "redirect/npm/pnpm/basic",
            &own[..],
            js,
            "redirect_pnpm_bazel_workspace_hidden",
        ),
    ];
    let mut runs = Vec::new();
    for (fixture, more, module, code) in rows {
        let dir = fixtures_root().join(fixture);
        let server = MockServer::start().await;
        let patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
        mount_api(&server, &patches).await;
        let mut plain = fixture_files(&dir.join("input"));
        for (rel, bytes) in more {
            plain.insert(rel.to_string(), bytes.to_vec());
        }
        let mut beside = plain.clone();
        beside.insert("MODULE.bazel".to_string(), module.as_bytes().to_vec());
        let (changed, redirect) = pins(&server, &beside).await;
        assert!(changed.is_empty(), "{fixture}: {}", describe(&changed));
        let warned = redirect["warnings"].to_string();
        assert!(warned.contains(code), "{fixture}: {redirect:#}");
        let asked = selection(&beside).fetch_text;
        assert!(asked.iter().any(|path| path == "MODULE.bazel"), "{asked:?}");
        runs.push((fixture, server, plain, beside));
    }
    std::env::set_var("SOCKET_NO_BAZEL", "1");
    for (fixture, server, plain, beside) in &runs {
        let without = pins(server, plain).await;
        assert!(!without.0.is_empty(), "{fixture}: {:#}", without.1);
        assert_eq!(pins(server, beside).await, without, "{fixture}");
        assert_eq!(selection(beside), selection(plain), "{fixture}");
    }
}
