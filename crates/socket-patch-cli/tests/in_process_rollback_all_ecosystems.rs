//! In-process rollback tests for every ecosystem.
//!
//! Each test handcrafts an installed package directory with patched
//! content (the file's current bytes), stages the `beforeHash` blob in
//! `.socket/blobs/`, writes a manifest, then runs in-process
//! `rollback`. Verifies the file is restored to the original content.
//!
//! Exercises `find_packages_for_rollback` for every ecosystem — a
//! distinct code path from `find_packages_for_purls`.

use std::path::Path;

use serial_test::serial;
use sha2::{Digest, Sha256};
use socket_patch_cli::commands::rollback::{run as rollback_run, RollbackArgs};

const ORG_PURL_TEMPLATE: &str = "pkg:%s/%s@%s";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn write_manifest_with_patch(
    socket: &Path,
    purl: &str,
    uuid: &str,
    file_path: &str,
    before_hash: &str,
    after_hash: &str,
) {
    std::fs::create_dir_all(socket).unwrap();
    let body = format!(
        r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "{uuid}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "{file_path}": {{
          "beforeHash": "{before_hash}",
          "afterHash":  "{after_hash}"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "fixture",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), body).unwrap();
}

fn default_rollback_args(cwd: &Path, eco: &str) -> RollbackArgs {
    RollbackArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            dry_run: false,
            silent: true,
            manifest_path: ".socket/manifest.json".to_string(),
            offline: true,
            global: false,
            global_prefix: None,
            org: None,
                        api_token: None,
            ecosystems: Some(vec![eco.to_string()]),
            json: true,
            verbose: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: None,
        one_off: false,
    }
}

// ---------------------------------------------------------------------------
// npm
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn rollback_npm_restores_original_content() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "rb", "version": "0.0.0" }"#,
    )
    .unwrap();

    let pkg_dir = tmp.path().join("node_modules/rb-npm");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{ "name": "rb-npm", "version": "1.0.0" }"#,
    )
    .unwrap();
    let original = b"original\n";
    let patched = b"patched\n";
    let before_hash = git_sha256(original);
    let after_hash = git_sha256(patched);

    std::fs::write(pkg_dir.join("index.js"), patched).unwrap();

    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(
        &socket,
        "pkg:npm/rb-npm@1.0.0",
        "22222222-2222-4222-8222-222222222222",
        "package/index.js",
        &before_hash,
        &after_hash,
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), original).unwrap();

    // The whole point is restoring patched → original, so the two must
    // differ and the file must start patched. Otherwise a rollback that
    // does nothing would pass the post-condition vacuously.
    assert_ne!(original.to_vec(), patched.to_vec());
    assert_eq!(
        std::fs::read(pkg_dir.join("index.js")).unwrap(),
        patched.to_vec(),
        "precondition: file must be in patched state before rollback"
    );

    assert_eq!(
        rollback_run(default_rollback_args(tmp.path(), "npm")).await,
        0,
        "rollback must report success (exit 0)"
    );
    assert_eq!(
        std::fs::read(pkg_dir.join("index.js")).unwrap(),
        original.to_vec(),
        "npm rollback must restore original bytes"
    );
}

// ---------------------------------------------------------------------------
// pypi
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn rollback_pypi_restores_original_content() {
    let tmp = tempfile::tempdir().unwrap();
    // Pypi crawler probes .venv-style layouts. Set one up by hand —
    // create site-packages with a dist-info dir. The layout differs
    // per platform (PEP-405): Unix puts site-packages under
    // `lib/python<MAJOR>.<MINOR>/`, Windows puts it under `Lib/`
    // with no version subdirectory. The crawler at
    // crates/socket-patch-core/src/crawlers/python_crawler.rs:182
    // already branches on cfg!(windows); mirror that here so the
    // crawler actually finds the synthetic package on every runner.
    let site = if cfg!(windows) {
        tmp.path().join(".venv").join("Lib").join("site-packages")
    } else {
        tmp.path()
            .join(".venv")
            .join("lib")
            .join("python3.11")
            .join("site-packages")
    };
    std::fs::create_dir_all(&site).unwrap();
    let dist_info = site.join("rbpypi-1.0.0.dist-info");
    std::fs::create_dir_all(&dist_info).unwrap();
    std::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: rbpypi\nVersion: 1.0.0\n",
    )
    .unwrap();
    let pkg_dir = site.join("rbpypi");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    let original = b"def foo(): return 'before'\n";
    let patched = b"def foo(): return 'after'\n";
    let before_hash = git_sha256(original);
    let after_hash = git_sha256(patched);
    std::fs::write(pkg_dir.join("__init__.py"), patched).unwrap();

    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(
        &socket,
        "pkg:pypi/rbpypi@1.0.0",
        "33333333-3333-4333-8333-333333333333",
        "rbpypi/__init__.py",
        &before_hash,
        &after_hash,
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), original).unwrap();

    assert_ne!(original.to_vec(), patched.to_vec());
    assert_eq!(
        std::fs::read(pkg_dir.join("__init__.py")).unwrap(),
        patched.to_vec(),
        "precondition: file must be in patched state before rollback"
    );

    let code = rollback_run(default_rollback_args(tmp.path(), "pypi")).await;
    assert_eq!(code, 0, "pypi rollback must report success (exit 0)");
    let after = std::fs::read(pkg_dir.join("__init__.py")).unwrap();
    assert_eq!(
        after, original,
        "pypi rollback must restore original bytes"
    );
}

// ---------------------------------------------------------------------------
// gem
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn rollback_gem_restores_original_content() {
    let tmp = tempfile::tempdir().unwrap();
    let gem_root = tmp.path().join("vendor/bundle/ruby/3.2.0/gems/rbgem-1.0.0");
    std::fs::create_dir_all(gem_root.join("lib")).unwrap();
    std::fs::write(
        gem_root.join("rbgem.gemspec"),
        "Gem::Specification.new do |s| s.name='rbgem'; s.version='1.0.0' end",
    )
    .unwrap();
    let original = b"module Rbgem; VERSION = '1.0.0'; end\n";
    let patched = b"module Rbgem; VERSION = '1.0.0-PATCHED'; end\n";
    let before_hash = git_sha256(original);
    let after_hash = git_sha256(patched);
    std::fs::write(gem_root.join("lib/rbgem.rb"), patched).unwrap();

    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(
        &socket,
        "pkg:gem/rbgem@1.0.0",
        "44444444-4444-4444-8444-444444444444",
        "package/lib/rbgem.rb",
        &before_hash,
        &after_hash,
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), original).unwrap();

    assert_ne!(original.to_vec(), patched.to_vec());
    assert_eq!(
        std::fs::read(gem_root.join("lib/rbgem.rb")).unwrap(),
        patched.to_vec(),
        "precondition: file must be in patched state before rollback"
    );

    let code = rollback_run(default_rollback_args(tmp.path(), "gem")).await;
    assert_eq!(code, 0, "gem rollback must report success (exit 0)");
    assert_eq!(
        std::fs::read(gem_root.join("lib/rbgem.rb")).unwrap(),
        original.to_vec(),
        "gem rollback must restore original bytes"
    );
}

// ---------------------------------------------------------------------------
// cargo
// ---------------------------------------------------------------------------

#[cfg(feature = "cargo")]
#[tokio::test]
#[serial]
async fn rollback_cargo_restores_original_content() {
    let tmp = tempfile::tempdir().unwrap();
    // vendor layout — simpler than registry/src; the cargo crawler
    // probes both.
    let pkg_dir = tmp.path().join("vendor/rbcargo-1.0.0");
    std::fs::create_dir_all(pkg_dir.join("src")).unwrap();
    std::fs::write(
        pkg_dir.join("Cargo.toml"),
        r#"[package]
name = "rbcargo"
version = "1.0.0"
"#,
    )
    .unwrap();
    let original = b"pub fn version() -> &'static str { \"1.0.0\" }\n";
    let patched = b"pub fn version() -> &'static str { \"PATCHED\" }\n";
    let before_hash = git_sha256(original);
    let after_hash = git_sha256(patched);
    std::fs::write(pkg_dir.join("src/lib.rs"), patched).unwrap();

    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(
        &socket,
        "pkg:cargo/rbcargo@1.0.0",
        "55555555-5555-4555-8555-555555555555",
        "package/src/lib.rs",
        &before_hash,
        &after_hash,
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), original).unwrap();

    // Cargo crawler needs a Cargo.toml in cwd to engage.
    std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\n").unwrap();

    assert_ne!(original.to_vec(), patched.to_vec());
    assert_eq!(
        std::fs::read(pkg_dir.join("src/lib.rs")).unwrap(),
        patched.to_vec(),
        "precondition: file must be in patched state before rollback"
    );

    let code = rollback_run(default_rollback_args(tmp.path(), "cargo")).await;
    assert_eq!(code, 0, "cargo rollback must report success (exit 0)");
    assert_eq!(
        std::fs::read(pkg_dir.join("src/lib.rs")).unwrap(),
        original.to_vec(),
        "cargo (vendor) rollback must restore original bytes in place"
    );
}

// ---------------------------------------------------------------------------
// golang
// ---------------------------------------------------------------------------

#[cfg(feature = "golang")]
#[tokio::test]
#[serial]
async fn rollback_golang_restores_original_content() {
    let tmp = tempfile::tempdir().unwrap();
    let mod_dir = tmp.path().join("github.com/rbgolang/foo@v1.0.0");
    std::fs::create_dir_all(&mod_dir).unwrap();
    let original = b"package foo\n\nfunc Bar() string { return \"before\" }\n";
    let patched = b"package foo\n\nfunc Bar() string { return \"after\" }\n";
    let before_hash = git_sha256(original);
    let after_hash = git_sha256(patched);
    std::fs::write(mod_dir.join("foo.go"), patched).unwrap();

    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(
        &socket,
        "pkg:golang/github.com/rbgolang/foo@v1.0.0",
        "66666666-6666-4666-8666-666666666666",
        "package/foo.go",
        &before_hash,
        &after_hash,
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), original).unwrap();

    assert_ne!(original.to_vec(), patched.to_vec());
    assert_eq!(
        std::fs::read(mod_dir.join("foo.go")).unwrap(),
        patched.to_vec(),
        "precondition: file must be in patched state before rollback"
    );

    std::env::set_var("GOMODCACHE", tmp.path());
    let mut args = default_rollback_args(tmp.path(), "golang");
    args.common.global = true;
    let code = rollback_run(args).await;
    std::env::remove_var("GOMODCACHE");
    assert_eq!(code, 0, "golang rollback must report success (exit 0)");

    assert_eq!(
        std::fs::read(mod_dir.join("foo.go")).unwrap(),
        original.to_vec(),
        "golang rollback must restore original bytes"
    );
}

// ---------------------------------------------------------------------------
// maven
// ---------------------------------------------------------------------------

#[cfg(feature = "maven")]
#[tokio::test]
#[serial]
async fn rollback_maven_restores_original_content() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("m2");
    let version_dir = repo.join("org/example/rbmvn/1.0.0");
    std::fs::create_dir_all(&version_dir).unwrap();
    std::fs::write(version_dir.join("rbmvn-1.0.0.pom"), "<project/>").unwrap();
    let original = b"BEFORE";
    let patched = b"AFTER";
    let before_hash = git_sha256(original);
    let after_hash = git_sha256(patched);
    std::fs::write(version_dir.join("LICENSE.txt"), patched).unwrap();

    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(
        &socket,
        "pkg:maven/org.example/rbmvn@1.0.0",
        "77777777-7777-4777-8777-777777777777",
        "package/LICENSE.txt",
        &before_hash,
        &after_hash,
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), original).unwrap();

    assert_ne!(original.to_vec(), patched.to_vec());
    assert_eq!(
        std::fs::read(version_dir.join("LICENSE.txt")).unwrap(),
        patched.to_vec(),
        "precondition: file must be in patched state before rollback"
    );

    std::env::set_var("MAVEN_REPO_LOCAL", &repo);
    // Maven crawler is runtime-gated; opt in for the test.
    std::env::set_var("SOCKET_EXPERIMENTAL_MAVEN", "1");
    let mut args = default_rollback_args(tmp.path(), "maven");
    args.common.global = true;
    let code = rollback_run(args).await;
    std::env::remove_var("MAVEN_REPO_LOCAL");
    std::env::remove_var("SOCKET_EXPERIMENTAL_MAVEN");
    assert_eq!(code, 0, "maven rollback must report success (exit 0)");

    assert_eq!(
        std::fs::read(version_dir.join("LICENSE.txt")).unwrap(),
        original.to_vec(),
        "maven rollback must restore original bytes"
    );
}

// ---------------------------------------------------------------------------
// composer
// ---------------------------------------------------------------------------

#[cfg(feature = "composer")]
#[tokio::test]
#[serial]
async fn rollback_composer_restores_original_content() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    let pkg_dir = vendor.join("vendor-x/rbphp");
    std::fs::create_dir_all(pkg_dir.join("src")).unwrap();
    let original = b"<?php echo 'before';\n";
    let patched = b"<?php echo 'after';\n";
    let before_hash = git_sha256(original);
    let after_hash = git_sha256(patched);
    std::fs::write(pkg_dir.join("src/lib.php"), patched).unwrap();

    let installed = vendor.join("composer");
    std::fs::create_dir_all(&installed).unwrap();
    std::fs::write(
        installed.join("installed.json"),
        r#"{ "packages": [{ "name": "vendor-x/rbphp", "version": "1.0.0", "version_normalized": "1.0.0.0" }] }"#,
    )
    .unwrap();
    std::fs::write(tmp.path().join("composer.json"), r#"{ "name": "t/t" }"#).unwrap();

    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(
        &socket,
        "pkg:composer/vendor-x/rbphp@1.0.0",
        "88888888-8888-4888-8888-888888888888",
        "package/src/lib.php",
        &before_hash,
        &after_hash,
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), original).unwrap();

    assert_ne!(original.to_vec(), patched.to_vec());
    assert_eq!(
        std::fs::read(pkg_dir.join("src/lib.php")).unwrap(),
        patched.to_vec(),
        "precondition: file must be in patched state before rollback"
    );

    let code = rollback_run(default_rollback_args(tmp.path(), "composer")).await;
    assert_eq!(code, 0, "composer rollback must report success (exit 0)");
    assert_eq!(
        std::fs::read(pkg_dir.join("src/lib.php")).unwrap(),
        original.to_vec(),
        "composer rollback must restore original bytes"
    );
}

// ---------------------------------------------------------------------------
// nuget
// ---------------------------------------------------------------------------

#[cfg(feature = "nuget")]
#[tokio::test]
#[serial]
async fn rollback_nuget_restores_original_content() {
    let tmp = tempfile::tempdir().unwrap();
    let packages = tmp.path().join("nuget-pkgs");
    let pkg_dir = packages.join("rbnuget").join("1.0.0");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(pkg_dir.join("rbnuget.nuspec"), "<package/>").unwrap();
    let original = b"BEFORE\n";
    let patched = b"AFTER\n";
    let before_hash = git_sha256(original);
    let after_hash = git_sha256(patched);
    std::fs::write(pkg_dir.join("LICENSE.md"), patched).unwrap();

    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(
        &socket,
        "pkg:nuget/rbnuget@1.0.0",
        "99999999-9999-4999-8999-999999999999",
        "package/LICENSE.md",
        &before_hash,
        &after_hash,
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), original).unwrap();

    assert_ne!(original.to_vec(), patched.to_vec());
    assert_eq!(
        std::fs::read(pkg_dir.join("LICENSE.md")).unwrap(),
        patched.to_vec(),
        "precondition: file must be in patched state before rollback"
    );

    std::env::set_var("NUGET_PACKAGES", &packages);
    // NuGet crawler is runtime-gated; opt in for the test.
    std::env::set_var("SOCKET_EXPERIMENTAL_NUGET", "1");
    let mut args = default_rollback_args(tmp.path(), "nuget");
    args.common.global = true;
    let code = rollback_run(args).await;
    std::env::remove_var("NUGET_PACKAGES");
    std::env::remove_var("SOCKET_EXPERIMENTAL_NUGET");
    assert_eq!(code, 0, "nuget rollback must report success (exit 0)");

    assert_eq!(
        std::fs::read(pkg_dir.join("LICENSE.md")).unwrap(),
        original.to_vec(),
        "nuget rollback must restore original bytes"
    );
}

// Keep template constant usage
#[allow(dead_code)]
fn _unused() -> &'static str {
    ORG_PURL_TEMPLATE
}
