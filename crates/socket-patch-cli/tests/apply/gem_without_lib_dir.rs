//! A gem that ships neither `lib/` nor a `.gemspec` in its own dir.
//!
//! `cassandra-web` packs `app.rb`, `app/` and `bin/` at its root; RubyGems
//! writes its spec only to `<home>/specifications/<leaf>.gemspec`. The
//! crawler judged an installed gem dir by `lib/` or an in-dir `.gemspec`, so
//! such a gem was never found and `apply` exited 1 with "The targeted
//! manifest patch matched no installed package", in agent mode and under
//! `--global --global-prefix <home>/gems` alike.

use std::path::{Path, PathBuf};

use serde_json::json;

use crate::apply_fixture::{
    one_file, patch_record, run_gem, run_gem_apply, stage_blob, write_manifest,
};
use crate::common::git_sha256;

const PURL: &str = "pkg:gem/cassandra-web@0.5.0";
const LEAF: &str = "cassandra-web-0.5.0";
const ORIGINAL: &[u8] = b"class App < Sinatra::Base\n  disable :protection\nend\n";
const PATCHED: &[u8] = b"class App < Sinatra::Base\n  set :protection, :except => [:json_csrf]\nend\n";

/// The gem home `<root>/vendor/bundle/ruby/3.4.0` holding `gems/<LEAF>/app.rb`
/// (and nothing else in the gem dir), with `specifications/<LEAF>.gemspec`
/// when `with_spec`, plus a manifest patching `app.rb`. Returns the home
/// and the installed file.
fn lib_less_gem(root: &Path, with_spec: bool) -> (PathBuf, PathBuf) {
    let home = root.join("vendor/bundle/ruby/3.4.0");
    let gem_dir = home.join("gems").join(LEAF);
    std::fs::create_dir_all(gem_dir.join("bin")).unwrap();
    std::fs::write(gem_dir.join("bin/cassandra-web"), b"#!/usr/bin/env ruby\n").unwrap();
    let file = gem_dir.join("app.rb");
    std::fs::write(&file, ORIGINAL).unwrap();
    let specs = home.join("specifications");
    std::fs::create_dir_all(&specs).unwrap();
    if with_spec {
        std::fs::write(specs.join(format!("{LEAF}.gemspec")), b"# installed spec\n").unwrap();
    }
    write_manifest(
        root,
        json!({ PURL: patch_record(
            "63617373-616e-4472-a177-656200000000",
            one_file("app.rb", ORIGINAL, PATCHED),
        )}),
    );
    stage_blob(root, &git_sha256(PATCHED), PATCHED);
    (home, file)
}

#[test]
fn a_gem_with_no_lib_dir_is_patched_by_its_installed_spec() {
    let tmp = tempfile::tempdir().unwrap();
    let (_home, file) = lib_less_gem(tmp.path(), true);

    let (code, stdout, stderr) = run_gem_apply(tmp.path(), &[]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert_eq!(std::fs::read(&file).unwrap(), PATCHED);
}

#[test]
fn a_gem_with_no_lib_dir_is_patched_under_a_global_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, file) = lib_less_gem(tmp.path(), true);
    let cwd = tmp.path().to_str().unwrap();
    let prefix = home.join("gems");

    let (code, stdout, stderr) = run_gem(
        Path::new("."),
        &[
            "apply",
            "--offline",
            "--ecosystems",
            "gem",
            "--cwd",
            cwd,
            "--global",
            "--global-prefix",
            prefix.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert_eq!(std::fs::read(&file).unwrap(), PATCHED);
}

/// Without its spec, a lib-less dir is still no installed gem: RubyGems
/// cannot load it, so `apply` finds nothing and writes nothing.
#[test]
fn a_lib_less_dir_with_no_installed_spec_is_not_a_gem() {
    let tmp = tempfile::tempdir().unwrap();
    let (_home, file) = lib_less_gem(tmp.path(), false);

    let (code, stdout, stderr) = run_gem_apply(tmp.path(), &[]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    assert!(
        stderr.contains("The targeted manifest patch matched no installed package"),
        "stderr={stderr}"
    );
    assert_eq!(std::fs::read(&file).unwrap(), ORIGINAL);
}
