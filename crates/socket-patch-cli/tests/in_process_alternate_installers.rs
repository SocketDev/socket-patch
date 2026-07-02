//! Tests for alternate install configurations within ecosystems.
//!
//! npm packages can be installed by `npm`, `yarn`, `pnpm`, or `bun` —
//! each writes to `node_modules/` in slightly different ways. pypi
//! supports venv, pyenv, conda, system installs. This file exercises
//! the layout variants the crawlers must handle in production.

use std::path::Path;
use std::process::Command;

use serial_test::serial;
use sha2::{Digest, Sha256};
use socket_patch_cli::commands::apply::{run as apply_run, ApplyArgs};

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Strong oracle: the file at `path` must now contain EXACTLY the expected
/// patched bytes, its git-sha256 must equal the manifest's afterHash, and
/// the patch must have been non-trivial (before != after). A broken apply
/// that no-ops, writes garbage, or silently reports success without touching
/// the file cannot satisfy all three.
fn assert_patched(path: &Path, expected: &[u8], before_hash: &str, after_hash: &str) {
    assert_ne!(
        before_hash, after_hash,
        "test fixture is degenerate: before/after hashes are equal"
    );
    let after = std::fs::read(path).expect("read patched file");
    assert_eq!(
        after, expected,
        "patched file content does not match the expected after-bytes at {path:?}"
    );
    assert_eq!(
        git_sha256(&after),
        after_hash,
        "patched file does not hash to the manifest afterHash at {path:?}"
    );
}

fn has(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn default_apply(cwd: &Path) -> ApplyArgs {
    ApplyArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            dry_run: false,
            silent: true,
            manifest_path: ".socket/manifest.json".to_string(),
            offline: true,
            global: false,
            global_prefix: None,
            ecosystems: Some(vec!["npm".to_string()]),
            json: true,
            verbose: false,
            download_mode: "diff".to_string(),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        force: false,
        check: false,
        vex: Default::default(),
    }
}

fn write_manifest(socket: &Path, purl: &str, before_hash: &str, after_hash: &str) {
    std::fs::create_dir_all(socket).unwrap();
    let body = format!(
        r#"{{ "patches": {{
            "{purl}": {{
                "uuid": "alt-installer-uuid-0000",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": {{ "package/index.js": {{
                    "beforeHash": "{before_hash}", "afterHash": "{after_hash}"
                }}}},
                "vulnerabilities": {{}}, "description": "x",
                "license": "MIT", "tier": "free"
            }}
        }}}}"#
    );
    std::fs::write(socket.join("manifest.json"), body).unwrap();
}

// ---------------------------------------------------------------------------
// Yarn install layout
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn yarn_install_then_apply_patches_file() {
    if !has("yarn") || !has("npm") {
        println!("SKIP: yarn or npm not on PATH");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "yarn-test", "version": "0.0.0", "dependencies": { "ms": "2.1.3" } }"#,
    )
    .unwrap();

    let status = Command::new("yarn")
        .args(["install", "--silent", "--no-progress"])
        .current_dir(tmp.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("yarn install");
    if !status.status.success() {
        println!(
            "SKIP: yarn install failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        return;
    }

    // yarn install reported success above, so the dependency MUST be on
    // disk. A missing file here is a real regression (broken/changed
    // install layout), not a reason to silently skip the assertions.
    let ms_index = tmp.path().join("node_modules/ms/index.js");
    assert!(
        ms_index.exists(),
        "yarn install succeeded but node_modules/ms/index.js is missing at {ms_index:?}"
    );

    let original = std::fs::read(&ms_index).expect("read ms/index.js");
    let before_hash = git_sha256(&original);
    let mut patched = original.clone();
    patched.extend_from_slice(b"\n// SOCKET-PATCH-YARN-MARKER\n");
    let after_hash = git_sha256(&patched);

    let socket = tmp.path().join(".socket");
    write_manifest(&socket, "pkg:npm/ms@2.1.3", &before_hash, &after_hash);
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), &patched).unwrap();

    let code = apply_run(default_apply(tmp.path())).await;
    assert_eq!(code, 0, "apply must succeed against yarn-installed package");
    assert_patched(&ms_index, &patched, &before_hash, &after_hash);
}

// ---------------------------------------------------------------------------
// pnpm install layout
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pnpm_install_then_apply_patches_file() {
    if !has("pnpm") {
        println!("SKIP: pnpm not on PATH");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "pnpm-test", "version": "0.0.0", "dependencies": { "ms": "2.1.3" } }"#,
    )
    .unwrap();

    let status = Command::new("pnpm")
        .args(["install", "--silent", "--no-frozen-lockfile"])
        .current_dir(tmp.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("pnpm install");
    if !status.status.success() {
        println!(
            "SKIP: pnpm install failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        return;
    }

    // pnpm creates node_modules/<pkg> as a symlink into .pnpm store.
    // The crawler should follow the symlink + find the package. This is
    // the entire point of the test, so assert the symlink layout is real
    // — if pnpm ever produced a hoisted (non-symlinked) layout instead,
    // we would not be exercising the symlink-following path and must know.
    let ms_dir = tmp.path().join("node_modules/ms");
    let ms_meta =
        std::fs::symlink_metadata(&ms_dir).expect("node_modules/ms must exist after pnpm install");
    assert!(
        ms_meta.file_type().is_symlink(),
        "pnpm test premise broken: node_modules/ms is not a symlink ({:?}); \
         the symlink-following path is not being exercised",
        ms_meta.file_type()
    );

    let ms_index = ms_dir.join("index.js");
    assert!(
        ms_index.exists(),
        "ms/index.js must resolve through the pnpm symlink"
    );

    let original = std::fs::read(&ms_index).expect("read ms/index.js");
    let before_hash = git_sha256(&original);
    let mut patched = original.clone();
    patched.extend_from_slice(b"\n// SOCKET-PATCH-PNPM-MARKER\n");
    let after_hash = git_sha256(&patched);

    let socket = tmp.path().join(".socket");
    write_manifest(&socket, "pkg:npm/ms@2.1.3", &before_hash, &after_hash);
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), &patched).unwrap();

    let code = apply_run(default_apply(tmp.path())).await;
    assert_eq!(
        code, 0,
        "apply must succeed against the pnpm symlinked layout"
    );
    // The crawler must have followed node_modules/ms -> .pnpm/... and the
    // patched bytes must be readable through that symlink. Exact-content +
    // hash check; a no-op or store-miss cannot pass.
    assert_patched(&ms_index, &patched, &before_hash, &after_hash);

    // Prove the symlink was genuinely followed into the .pnpm store rather
    // than apply creating a hoisted shadow copy beside the symlink: the
    // canonical (real, fully-resolved) path must live under .pnpm AND it is
    // that real file which must carry the patched bytes.
    let real = std::fs::canonicalize(&ms_index).expect("canonicalize pnpm symlink");
    assert_ne!(
        real, ms_index,
        "ms/index.js did not resolve through a symlink; pnpm store layout not exercised"
    );
    assert!(
        real.components().any(|c| c.as_os_str() == ".pnpm"),
        "pnpm symlink did not resolve into the .pnpm store: {real:?}"
    );
    assert_patched(&real, &patched, &before_hash, &after_hash);
}

// ---------------------------------------------------------------------------
// Monorepo workspace (npm workspaces)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn npm_workspaces_monorepo_apply() {
    if !has("npm") {
        println!("SKIP: npm not on PATH");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "monorepo", "version": "0.0.0",
             "workspaces": ["packages/*"] }"#,
    )
    .unwrap();
    let pkg_a = tmp.path().join("packages/a");
    std::fs::create_dir_all(&pkg_a).unwrap();
    std::fs::write(
        pkg_a.join("package.json"),
        r#"{ "name": "a", "version": "1.0.0", "dependencies": { "ms": "2.1.3" } }"#,
    )
    .unwrap();
    let status = Command::new("npm")
        .args(["install", "--silent", "--no-audit", "--no-fund"])
        .current_dir(tmp.path())
        .output()
        .expect("npm install");
    if !status.status.success() {
        println!("SKIP: npm install (monorepo) failed");
        return;
    }
    // npm workspaces normally hoist `ms` to the root node_modules, but some
    // npm versions nest it under the workspace package instead. Accept
    // either location, but do NOT silently skip: a successful install must
    // place ms *somewhere* — its total absence is a real regression.
    let root_ms = tmp.path().join("node_modules/ms/index.js");
    let nested_ms = pkg_a.join("node_modules/ms/index.js");
    let ms_index = if root_ms.exists() {
        root_ms
    } else if nested_ms.exists() {
        nested_ms
    } else {
        panic!(
            "npm install (monorepo) succeeded but ms/index.js exists at \
             neither {root_ms:?} nor {nested_ms:?}"
        );
    };

    let original = std::fs::read(&ms_index).expect("read");
    let before_hash = git_sha256(&original);
    let mut patched = original.clone();
    patched.extend_from_slice(b"\n// SOCKET-PATCH-WORKSPACE-MARKER\n");
    let after_hash = git_sha256(&patched);

    let socket = tmp.path().join(".socket");
    write_manifest(&socket, "pkg:npm/ms@2.1.3", &before_hash, &after_hash);
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), &patched).unwrap();

    let code = apply_run(default_apply(tmp.path())).await;
    assert_eq!(code, 0, "monorepo apply must succeed");
    // A zero exit code alone is not proof of work — verify the hoisted
    // file was actually rewritten with the patched bytes.
    assert_patched(&ms_index, &patched, &before_hash, &after_hash);
}

// ---------------------------------------------------------------------------
// Bundler (Gemfile + bundle install) for gem
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn bundler_install_then_apply_patches_gem() {
    if !has("bundle") || !has("gem") {
        println!("SKIP: bundle/gem not on PATH");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("Gemfile"),
        r#"source 'https://rubygems.org'
gem 'colorize', '1.1.0'
"#,
    )
    .unwrap();
    // Install into a local vendor/bundle path to avoid touching the
    // user's gem environment.
    let status = Command::new("bundle")
        .args(["install", "--path", "vendor/bundle", "--quiet"])
        .current_dir(tmp.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("bundle install");
    if !status.status.success() {
        println!(
            "SKIP: bundle install failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        return;
    }
    // Find the gem directory.
    let mut lib_file = None;
    let bundle_root = tmp.path().join("vendor/bundle/ruby");
    if let Ok(entries) = std::fs::read_dir(&bundle_root) {
        for entry in entries.flatten() {
            let candidate = entry.path().join("gems/colorize-1.1.0/lib/colorize.rb");
            if candidate.exists() {
                lib_file = Some(candidate);
                break;
            }
        }
    }
    // bundle install reported success, so the gem and its lib file MUST be
    // present under the vendored bundle. A miss here is a real regression
    // (changed vendor layout / gem-discovery break), not a skip.
    let lib_file = lib_file.unwrap_or_else(|| {
        panic!("bundle install succeeded but colorize-1.1.0/lib/colorize.rb was not found under {bundle_root:?}")
    });

    let original = std::fs::read(&lib_file).expect("read");
    let before_hash = git_sha256(&original);
    let mut patched = original.clone();
    patched.extend_from_slice(b"\n# SOCKET-PATCH-BUNDLER-MARKER\n");
    let after_hash = git_sha256(&patched);

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{ "patches": {{
                "pkg:gem/colorize@1.1.0": {{
                    "uuid": "bundler-uuid-0000",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/lib/colorize.rb": {{
                        "beforeHash": "{before_hash}", "afterHash": "{after_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "x",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    )
    .unwrap();
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), &patched).unwrap();

    let mut args = default_apply(tmp.path());
    args.common.ecosystems = Some(vec!["gem".to_string()]);
    let code = apply_run(args).await;
    assert_eq!(code, 0, "bundler-installed gem must be patchable");
    assert_patched(&lib_file, &patched, &before_hash, &after_hash);
}

// ---------------------------------------------------------------------------
// bun install layout
// ---------------------------------------------------------------------------

/// bun installs a hoisted node_modules by default (like npm), so this exercises
/// that a bun-installed package is patched in place by agent-mode apply. Gated
/// on `bun` on PATH like the other real-installer legs; a failed fixture
/// install skips, but a missing file after a *successful* install is a hard
/// regression.
#[tokio::test]
#[serial]
async fn bun_install_then_apply_patches_file() {
    if !has("bun") {
        println!("SKIP: bun not on PATH");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "bun-test", "version": "0.0.0", "dependencies": { "ms": "2.1.3" } }"#,
    )
    .unwrap();

    // Private cache so the fixture install never touches the user's bun cache.
    let cache = tmp.path().join("bun-cache");
    let status = Command::new("bun")
        .args(["install", "--no-progress"])
        .current_dir(tmp.path())
        .env("BUN_INSTALL_CACHE_DIR", &cache)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("bun install");
    if !status.status.success() {
        println!(
            "SKIP: bun install failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        return;
    }

    let ms_index = tmp.path().join("node_modules/ms/index.js");
    assert!(
        ms_index.exists(),
        "bun install succeeded but node_modules/ms/index.js is missing at {ms_index:?}"
    );

    let original = std::fs::read(&ms_index).expect("read ms/index.js");
    let before_hash = git_sha256(&original);
    let mut patched = original.clone();
    patched.extend_from_slice(b"\n// SOCKET-PATCH-BUN-MARKER\n");
    let after_hash = git_sha256(&patched);

    let socket = tmp.path().join(".socket");
    write_manifest(&socket, "pkg:npm/ms@2.1.3", &before_hash, &after_hash);
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), &patched).unwrap();

    let code = apply_run(default_apply(tmp.path())).await;
    assert_eq!(
        code, 0,
        "apply must succeed against a bun-installed package"
    );
    assert_patched(&ms_index, &patched, &before_hash, &after_hash);
}

// ---------------------------------------------------------------------------
// yarn berry (4.x) node-modules linker
// ---------------------------------------------------------------------------

fn has_corepack_pm(pm: &str) -> bool {
    Command::new("corepack")
        .args([pm, "--version"])
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// yarn berry with the **node-modules** linker (`.yarnrc.yml` `nodeLinker:
/// node-modules` + `packageManager: yarn@4.12.0` so corepack dispatches berry)
/// installs a real hoisted `node_modules/ms`, which agent-mode apply must
/// patch in place. This complements `e2e_safety_yarn_pnp.rs` (which asserts
/// berry's PnP linker is REFUSED because packages live in `.yarn/cache` zips):
/// under the node-modules linker the on-disk layout is patchable.
#[tokio::test]
#[serial]
async fn yarn_berry_node_modules_linker_apply_patches_file() {
    if !has_corepack_pm("yarn@4.12.0") {
        println!("SKIP: corepack yarn@4.12.0 unavailable");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "berry-nm-test", "version": "0.0.0", "packageManager": "yarn@4.12.0", "dependencies": { "ms": "2.1.3" } }"#,
    )
    .unwrap();
    std::fs::write(
        tmp.path().join(".yarnrc.yml"),
        "nodeLinker: node-modules\nenableGlobalCache: false\n",
    )
    .unwrap();

    let global = tmp.path().join("yarn-global");
    let status = Command::new("corepack")
        .args(["yarn@4.12.0", "install"])
        .current_dir(tmp.path())
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
        .env("YARN_GLOBAL_FOLDER", &global)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("corepack yarn install");
    if !status.status.success() {
        println!(
            "SKIP: yarn berry install failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        return;
    }

    // node-modules linker premise: ms is a real hoisted directory (NOT a PnP
    // .yarn/cache zip). If berry ever changed the default layout under this
    // linker we would not be exercising the in-place patch path and must know.
    let ms_index = tmp.path().join("node_modules/ms/index.js");
    assert!(
        ms_index.exists(),
        "yarn berry (node-modules linker) install succeeded but node_modules/ms/index.js \
         is missing at {ms_index:?} — layout premise broken"
    );

    let original = std::fs::read(&ms_index).expect("read ms/index.js");
    let before_hash = git_sha256(&original);
    let mut patched = original.clone();
    patched.extend_from_slice(b"\n// SOCKET-PATCH-BERRY-NM-MARKER\n");
    let after_hash = git_sha256(&patched);

    let socket = tmp.path().join(".socket");
    write_manifest(&socket, "pkg:npm/ms@2.1.3", &before_hash, &after_hash);
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), &patched).unwrap();

    let code = apply_run(default_apply(tmp.path())).await;
    assert_eq!(
        code, 0,
        "apply must succeed against the yarn-berry node-modules layout"
    );
    assert_patched(&ms_index, &patched, &before_hash, &after_hash);
}

// ---------------------------------------------------------------------------
// Rush pnpm symlink farm (hand-built, no real installer)
// ---------------------------------------------------------------------------

/// Hand-build the exact layout Rush + pnpm produce: a single canonical package
/// under `common/temp/node_modules/.pnpm/<pkg>@<v>/node_modules/<pkg>/` (real
/// files) plus per-project symlinks `apps/{a,b}/node_modules/<pkg>` pointing
/// into it, with `rush.json` at the repo root. Running agent-mode apply at the
/// repo root must patch the canonical file ONCE and have the patched bytes
/// visible through BOTH project symlinks.
///
/// This pins the discovery mechanism: `common/temp` is in the crawler's
/// SKIP_DIRS (`temp`), so the canonical `.pnpm` store is NOT walked directly —
/// the package is found via the `apps/*/node_modules` symlinks (which the
/// crawler follows into the farm), exactly as it must be for a real Rush repo.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn rush_pnpm_symlink_farm_apply_patches_through_both_projects() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // rush.json at the root marks this a Rush repo.
    std::fs::write(root.join("rush.json"), r#"{ "rushVersion": "5.100.0" }"#).unwrap();

    // The canonical package lives in the pnpm virtual store under common/temp.
    let canonical_dir = root.join("common/temp/node_modules/.pnpm/ms@2.1.3/node_modules/ms");
    std::fs::create_dir_all(&canonical_dir).unwrap();
    std::fs::write(
        canonical_dir.join("package.json"),
        r#"{ "name": "ms", "version": "2.1.3" }"#,
    )
    .unwrap();
    let original = b"module.exports = function ms() {}\n".to_vec();
    std::fs::write(canonical_dir.join("index.js"), &original).unwrap();

    // Two Rush projects, each with a node_modules/ms symlink INTO the farm.
    for app in ["a", "b"] {
        let nm = root.join(format!("apps/{app}/node_modules"));
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(
            root.join(format!("apps/{app}/package.json")),
            format!(r#"{{ "name": "app-{app}", "version": "1.0.0", "dependencies": {{ "ms": "2.1.3" }} }}"#),
        )
        .unwrap();
        symlink(&canonical_dir, nm.join("ms")).unwrap();
    }

    let before_hash = git_sha256(&original);
    let mut patched = original.clone();
    patched.extend_from_slice(b"\n// SOCKET-PATCH-RUSH-FARM-MARKER\n");
    let after_hash = git_sha256(&patched);

    let socket = root.join(".socket");
    write_manifest(&socket, "pkg:npm/ms@2.1.3", &before_hash, &after_hash);
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), &patched).unwrap();

    let code = apply_run(default_apply(root)).await;
    assert_eq!(
        code, 0,
        "apply must succeed against the Rush pnpm symlink farm (crawl found the package \
         via the apps/*/node_modules symlinks despite common/temp being skipped)"
    );

    // The canonical file under .pnpm is the one that must carry the patched
    // bytes — apply followed the symlink into the store rather than shadowing.
    assert_patched(
        &canonical_dir.join("index.js"),
        &patched,
        &before_hash,
        &after_hash,
    );
    // Both project symlinks resolve to the patched canonical file.
    for app in ["a", "b"] {
        let via = root.join(format!("apps/{app}/node_modules/ms/index.js"));
        assert_eq!(
            std::fs::read(&via).unwrap(),
            patched,
            "the patched bytes must be visible through apps/{app}'s symlink at {via:?}"
        );
        let real = std::fs::canonicalize(&via).expect("canonicalize symlink");
        assert!(
            real.components().any(|c| c.as_os_str() == ".pnpm"),
            "apps/{app}'s symlink must resolve into the .pnpm farm, not a shadow copy: {real:?}"
        );
    }
}
