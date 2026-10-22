//! Fixtures and runners shared by `apply_failure_paths.rs` (the `--json`
//! contracts) and `apply_render.rs` (the human output) (#1089).
//!
//! Binary-driven throughout (`common::run_with_env`, `SOCKET_*`-scrubbed
//! children), hand-written camelCase manifests, git-sha256 oracle,
//! `--offline` wherever the network is not the subject under test.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::common::hermetic::{self, Extra};
use crate::common::{binary, git_sha256, hermetic_command, run_with_env};

pub const GO_PURL: &str = "pkg:golang/example.com/mod@v1.0.0";
pub const GO_COPY_DIR: &str = ".socket/go-patches/example.com/mod@v1.0.0";
pub const GEM_BASE_PURL: &str = "pkg:gem/rack@3.1.0";
pub const GEM_QUALIFIED_PURL: &str = "pkg:gem/rack@3.1.0?platform=ruby";
pub const GEM_PRISTINE: &[u8] = b"module Rack\n  VERSION = '3.1.0'\nend\n";

pub const MM_BEFORE: &[u8] = b"pristine content\n";
pub const MM_AFTER: &[u8] = b"patched content\n";
pub const MM_LOCAL: &[u8] = b"locally modified content\n";

/// Run `socket-patch apply <args>` in `cwd` with the hermetic `SOCKET_*`
/// environment (see `common::run_with_env`) and `extra_env` landing last
/// (so tests can inject API URLs / TMPDIR).
pub fn run_apply(cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> (i32, String, String) {
    let mut argv: Vec<&str> = vec!["apply"];
    argv.extend_from_slice(args);
    run_with_env(cwd, &argv, extra_env)
}

/// One camelCase manifest record (the TS-compatible on-disk schema).
pub fn patch_record(uuid: &str, files: Value) -> Value {
    json!({
        "uuid": uuid,
        "exportedAt": "2024-01-01T00:00:00Z",
        "files": files,
        "vulnerabilities": {},
        "description": "apply suite fixture",
        "license": "MIT",
        "tier": "free"
    })
}

/// The `files` map of a one-file patch from `before` to `after` bytes.
pub fn one_file(path: &str, before: &[u8], after: &[u8]) -> Value {
    json!({ path: { "beforeHash": git_sha256(before), "afterHash": git_sha256(after) } })
}

/// Write `.socket/manifest.json`, creating `.socket/blobs/` alongside as
/// a real project has it.
pub fn write_manifest(root: &Path, patches: Value) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).expect("create .socket/blobs");
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": patches })).unwrap(),
    )
    .expect("write manifest");
}

pub fn stage_blob(root: &Path, hash: &str, content: &[u8]) {
    let blobs = root.join(".socket").join("blobs");
    std::fs::create_dir_all(&blobs).expect("create blobs dir");
    std::fs::write(blobs.join(hash), content).expect("stage blob");
}

/// Install a fake npm package at `<root>/node_modules/<name>` with the
/// given `index.js` bytes (`None`: no `index.js`); returns the index.js
/// path.
pub fn install_npm_pkg(root: &Path, name: &str, version: &str, index_js: Option<&[u8]>) -> PathBuf {
    let pkg_dir = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg_dir).expect("create pkg dir");
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .expect("write package.json");
    let index = pkg_dir.join("index.js");
    if let Some(bytes) = index_js {
        std::fs::write(&index, bytes).expect("write index.js");
    }
    index
}

pub fn write_root_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "apply-suite-root", "version": "0.0.0" }"#,
    )
    .expect("write root package.json");
}

/// Synthesize an installed gem under the cwd's vendor/bundle tree (the
/// layout the ruby crawler scans in local mode; a real `gem install`
/// produces exactly this `gems/<name>-<version>[-<platform>]` leaf,
/// verified against RubyGems on ruby 3.4). Returns the patchable file
/// path.
pub fn install_gem(root: &Path, leaf: &str, file_rel: &str, contents: &[u8]) -> PathBuf {
    let gem_dir = root
        .join("vendor")
        .join("bundle")
        .join("ruby")
        .join("3.4.0")
        .join("gems")
        .join(leaf);
    let file = gem_dir.join(file_rel);
    std::fs::create_dir_all(file.parent().unwrap()).expect("create gem dir");
    std::fs::write(&file, contents).expect("write gem file");
    file
}

/// Valid manifest with one golang patch and NO committed copy / `go.mod`:
/// `--check` reports MissingCopy + MissingReplace drift (the
/// `cli_apply_silent.rs::write_drifted_go_manifest` shape).
pub fn write_drifted_go_manifest(root: &Path) {
    write_manifest(
        root,
        json!({
            GO_PURL: patch_record(
                "60606060-6060-4060-8060-606060606060",
                json!({ "file.go": {
                    "beforeHash": "a".repeat(64),
                    "afterHash": "b".repeat(64),
                }}),
            )
        }),
    );
}

/// Stale-redirect fixture: a socket-owned `replace` + committed copy for a
/// module the (empty) manifest no longer patches. Returns the `go.mod`
/// text.
pub fn write_stale_go_redirect(root: &Path) -> String {
    write_manifest(root, json!({}));
    let go_mod = "module example.com/app\n\ngo 1.21\n\n\
                  replace example.com/mod v1.0.0 => ./.socket/go-patches/example.com/mod@v1.0.0\n";
    std::fs::write(root.join("go.mod"), go_mod).unwrap();
    let copy_dir = root.join(GO_COPY_DIR);
    std::fs::create_dir_all(&copy_dir).unwrap();
    std::fs::write(copy_dir.join("file.go"), b"patched\n").unwrap();
    go_mod.to_string()
}

/// A root `package.json` plus a manifest patching `pkg:npm/<name>@1.0.0`'s
/// `package/index.js` from [`MM_BEFORE`] to [`MM_AFTER`], with the after
/// blob staged so staging succeeds offline. Nothing is installed.
pub fn write_npm_patch(root: &Path, name: &str, uuid: &str) {
    write_root_package_json(root);
    write_manifest(
        root,
        json!({
            format!("pkg:npm/{name}@1.0.0"):
                patch_record(uuid, one_file("package/index.js", MM_BEFORE, MM_AFTER)),
        }),
    );
    stage_blob(root, &git_sha256(MM_AFTER), MM_AFTER);
}

/// The `--verbose --strict` fixture: three single-file npm packages, one
/// already at afterHash (`valready`), one matching neither hash
/// (`vmismatch`) and one missing the patched file (`vmissing`).
pub fn write_three_state_npm_project(root: &Path) {
    write_root_package_json(root);
    install_npm_pkg(root, "valready", "1.0.0", Some(MM_AFTER));
    install_npm_pkg(root, "vmismatch", "1.0.0", Some(MM_LOCAL));
    install_npm_pkg(root, "vmissing", "1.0.0", None);
    let files = one_file("package/index.js", MM_BEFORE, MM_AFTER);
    write_manifest(
        root,
        json!({
            "pkg:npm/valready@1.0.0":
                patch_record("65656565-6565-4565-8565-656565656565", files.clone()),
            "pkg:npm/vmismatch@1.0.0":
                patch_record("66666666-6666-4666-8666-666666666666", files.clone()),
            "pkg:npm/vmissing@1.0.0":
                patch_record("67676767-6767-4767-8767-676767676767", files),
        }),
    );
    stage_blob(root, &git_sha256(MM_AFTER), MM_AFTER);
}

/// A yarn-PnP project (`.pnp.cjs`) whose manifest targets npm.
pub fn write_pnp_npm_project(root: &Path) {
    write_manifest(
        root,
        json!({
            "pkg:npm/blocked@1.0.0": patch_record(
                "68686868-6868-4868-8868-686868686868",
                one_file("package/index.js", MM_BEFORE, MM_AFTER),
            )
        }),
    );
    std::fs::write(root.join(".pnp.cjs"), "// pnp loader stub\n").unwrap();
}

/// An installed `rack-3.1.0` gem and a manifest patching
/// `lib/rack.rb` with `marker` appended, blob staged. Returns the
/// installed file.
pub fn write_gem_patch(root: &Path, uuid: &str, marker: &[u8]) -> PathBuf {
    let file = install_gem(root, "rack-3.1.0", "lib/rack.rb", GEM_PRISTINE);
    let patched = [GEM_PRISTINE, marker].concat();
    write_manifest(
        root,
        json!({ GEM_BASE_PURL: patch_record(uuid, one_file("lib/rack.rb", GEM_PRISTINE, &patched)) }),
    );
    stage_blob(root, &git_sha256(&patched), &patched);
    file
}

/// A root `package.json`, an empty `node_modules/` and a manifest of `n`
/// npm patches (`pkg:npm/miss-<i>@1.0.0`) with no blob, diff or package
/// artifact anywhere under `.socket/`, so staging has no usable source.
pub fn write_sourceless_npm_patches(root: &Path, n: u32) {
    write_root_package_json(root);
    std::fs::create_dir_all(root.join("node_modules")).expect("create node_modules");
    let patches: serde_json::Map<String, Value> = (0..n)
        .map(|i| {
            let uuid = format!("{i:08}-0000-4000-8000-{i:012}");
            let body = format!("sourceless {i}\n");
            (
                format!("pkg:npm/miss-{i}@1.0.0"),
                patch_record(&uuid, one_file("package/index.js", b"", body.as_bytes())),
            )
        })
        .collect();
    write_manifest(root, Value::Object(patches));
}

// ═══════════ gem release-variant mismatch fixtures ═══════════
//
// Shared by `cli_gem_variant_mismatch_policy.rs` (the `--json`
// contracts) and `apply_render.rs` (the human output).

/// The rack singleton's on-disk bytes after a local edit: they match
/// neither the record's beforeHash nor its afterHash.
pub const GEM_LOCAL: &[u8] = b"module Rack\n  VERSION = '3.1.0'\nend\n# local tweak\n";
pub const NOKOGIRI_LINUX_PRISTINE: &[u8] = b"module Nokogiri\n  VERSION = '1.16.5'\nend\n";
pub const NOKOGIRI_DARWIN_BEFORE: &[u8] = b"# nokogiri.rb from the arm64-darwin gem\n";
pub const NOKOGIRI_LINUX_MARKER: &[u8] = b"\n# SOCKET-LINUX-PATCH\n";
pub const NOKOGIRI_DARWIN_MARKER: &[u8] = b"\n# DARWIN-MARKER\n";

/// Run `socket-patch apply --offline --ecosystems gem <extra>` in `cwd`
/// with the hermetic `SOCKET_*` environment (`hermetic_command`) and the
/// ambient `BUNDLE_*` scrubbed, so only the argv decides behavior.
pub fn run_gem_apply(cwd: &Path, extra: &[&str]) -> (i32, String, String) {
    let mut cmd = hermetic_command(&binary());
    cmd.arg("apply")
        .args(["--offline", "--ecosystems", "gem"])
        .args(extra)
        .current_dir(cwd);
    hermetic::scrub_extra(&mut cmd, &[Extra::Bundle]);
    let out = cmd.output().expect("run socket-patch apply");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// `pkg:gem/nokogiri@1.16.5?platform=<platform>`.
pub fn nokogiri_purl(platform: &str) -> String {
    format!("pkg:gem/nokogiri@1.16.5?platform={platform}")
}

/// Singleton fixture: one bare-PURL gem record (`GEM_BASE_PURL`) whose
/// only file was locally modified on disk (`GEM_LOCAL`); the afterHash
/// blob is staged so the offline apply has the full patched bytes.
/// Returns the on-disk file path and the exact patched bytes a correct
/// warn-overwrite must produce.
pub fn gem_singleton_mismatch_fixture(root: &Path) -> (PathBuf, Vec<u8>) {
    let patched = [GEM_PRISTINE, b"\n# SOCKET-SINGLETON-PATCH\n"].concat();
    let file = install_gem(root, "rack-3.1.0", "lib/rack.rb", GEM_LOCAL);
    write_manifest(
        root,
        json!({
            GEM_BASE_PURL: patch_record(
                "31313131-3131-4131-8131-313131313131",
                one_file("lib/rack.rb", GEM_PRISTINE, &patched),
            )
        }),
    );
    stage_blob(root, &git_sha256(&patched), &patched);
    // Fixture sanity: the on-disk bytes must match neither hash, or the
    // mismatch path under test is never taken.
    assert_ne!(git_sha256(GEM_LOCAL), git_sha256(GEM_PRISTINE));
    assert_ne!(git_sha256(GEM_LOCAL), git_sha256(&patched));
    (file, patched)
}

/// The x86_64-linux nokogiri record (`lib/nokogiri.rb`, pristine →
/// pristine + `NOKOGIRI_LINUX_MARKER`), blob staged. Returns the
/// patched bytes.
fn write_nokogiri_linux_record(
    root: &Path,
    patches: &mut serde_json::Map<String, Value>,
) -> Vec<u8> {
    let patched = [NOKOGIRI_LINUX_PRISTINE, NOKOGIRI_LINUX_MARKER].concat();
    patches.insert(
        nokogiri_purl("x86_64-linux"),
        patch_record(
            "41414141-4141-4141-8141-414141414141",
            one_file("lib/nokogiri.rb", NOKOGIRI_LINUX_PRISTINE, &patched),
        ),
    );
    stage_blob(root, &git_sha256(&patched), &patched);
    patched
}

/// Qualified-singleton fixture: a lone `?platform=x86_64-linux` record
/// with the arm64-darwin gem installed, whose bytes match neither of the
/// record's hashes. Returns the on-disk file path.
pub fn gem_wrong_platform_fixture(root: &Path) -> PathBuf {
    let file = install_gem(
        root,
        "nokogiri-1.16.5-arm64-darwin",
        "lib/nokogiri.rb",
        NOKOGIRI_DARWIN_BEFORE,
    );
    let mut patches = serde_json::Map::new();
    let linux_patched = write_nokogiri_linux_record(root, &mut patches);
    write_manifest(root, Value::Object(patches));
    // Fixture sanity: the darwin bytes must match neither hash, or the
    // wrong-platform path under test is never taken.
    assert_ne!(
        git_sha256(NOKOGIRI_DARWIN_BEFORE),
        git_sha256(NOKOGIRI_LINUX_PRISTINE)
    );
    assert_ne!(
        git_sha256(NOKOGIRI_DARWIN_BEFORE),
        git_sha256(&linux_patched)
    );
    file
}

/// Multi-variant fixture: the x86_64-linux gem is installed with
/// `on_disk` bytes; the manifest has its record plus an arm64-darwin
/// sibling describing a DIFFERENT distribution whose beforeHash can never
/// match. Both afterHash blobs are staged. Returns the on-disk file path
/// and the linux and darwin patched bytes.
pub fn gem_multi_variant_fixture(root: &Path, on_disk: &[u8]) -> (PathBuf, Vec<u8>, Vec<u8>) {
    let file = install_gem(
        root,
        "nokogiri-1.16.5-x86_64-linux",
        "lib/nokogiri.rb",
        on_disk,
    );
    let mut patches = serde_json::Map::new();
    let linux_patched = write_nokogiri_linux_record(root, &mut patches);
    let darwin_patched = [NOKOGIRI_DARWIN_BEFORE, NOKOGIRI_DARWIN_MARKER].concat();
    patches.insert(
        nokogiri_purl("arm64-darwin"),
        patch_record(
            "42424242-4242-4242-8242-424242424242",
            one_file("lib/nokogiri.rb", NOKOGIRI_DARWIN_BEFORE, &darwin_patched),
        ),
    );
    stage_blob(root, &git_sha256(&darwin_patched), &darwin_patched);
    write_manifest(root, Value::Object(patches));
    (file, linux_patched, darwin_patched)
}
