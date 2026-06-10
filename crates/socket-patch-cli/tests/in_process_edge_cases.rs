//! Edge case tests for the install → scan → apply → rollback lifecycle.
//!
//! Covers scenarios that production CI workflows must handle robustly:
//! read-only files (cargo registry), nested directory structures,
//! multi-file patches, partial installs, missing blobs, hash mismatches,
//! and idempotent re-runs.

use std::path::Path;

use serial_test::serial;
use sha2::{Digest, Sha256};
use socket_patch_cli::commands::apply::{run as apply_run, ApplyArgs};
use socket_patch_cli::commands::rollback::{run as rollback_run, RollbackArgs};

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Identity fingerprint of a file that survives a byte-identical rewrite check.
///
/// A genuine short-circuit (`already_patched` / `already_original`) leaves the
/// file completely untouched. The atomic-write path used by every real
/// apply/rollback stages a temp file and `rename`s it over the target, which
/// allocates a NEW inode. So comparing the inode before/after is a
/// filesystem-observable proof that the short-circuit fired and the file was
/// not silently re-written with the same bytes (a regression that exit-code +
/// byte-equality checks alone cannot distinguish, because the staged blob
/// equals the on-disk content in these tests).
#[cfg(unix)]
fn file_identity(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).unwrap().ino()
}

/// Assert that no apply/rollback staging litter (`.socket-cow-*`, temp
/// `.tmp`/`~`-style files) was left behind in a directory tree.
fn assert_no_staging_litter(dir: &Path) {
    for entry in walk(dir) {
        let name = entry.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            !name.starts_with(".socket-cow-")
                && !name.starts_with(".socket-stage-")
                && !name.ends_with(".socket-tmp"),
            "unexpected staging litter left on disk: {}",
            entry.display()
        );
    }
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

fn write_npm_pkg(root: &Path, name: &str, version: &str, files: &[(&str, &[u8])]) {
    let pkg = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
    for (rel, content) in files {
        let p = pkg.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, content).unwrap();
    }
}

fn write_manifest(socket: &Path, body: &str) {
    std::fs::create_dir_all(socket).unwrap();
    std::fs::write(socket.join("manifest.json"), body).unwrap();
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
            ecosystems: None,
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

// ---------------------------------------------------------------------------
// Read-only file (mimics cargo registry source files)
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn apply_overwrites_read_only_file() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let original = b"before\n";
    let patched = b"patched\n";
    let before_hash = git_sha256(original);
    let after_hash = git_sha256(patched);

    std::fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"r","version":"0.0.0"}"#,
    )
    .unwrap();
    write_npm_pkg(tmp.path(), "ro-target", "1.0.0", &[("index.js", original)]);
    // Make the package file read-only — apply must make it writable to
    // overwrite. This mimics the cargo-registry-source layout.
    let file = tmp.path().join("node_modules/ro-target/index.js");
    let perms = std::fs::Permissions::from_mode(0o444);
    std::fs::set_permissions(&file, perms).unwrap();

    let socket = tmp.path().join(".socket");
    write_manifest(
        &socket,
        &format!(
            r#"{{ "patches": {{
                "pkg:npm/ro-target@1.0.0": {{
                    "uuid": "ro-target-uuid-0000",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/index.js": {{
                        "beforeHash": "{before_hash}", "afterHash": "{after_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "x",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), patched).unwrap();

    let code = apply_run(default_apply(tmp.path())).await;
    assert_eq!(code, 0);
    assert_eq!(std::fs::read(&file).unwrap(), patched);
}

// ---------------------------------------------------------------------------
// Nested directory patch
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn apply_creates_nested_directories_for_new_files() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"r","version":"0.0.0"}"#,
    )
    .unwrap();
    write_npm_pkg(tmp.path(), "nested", "1.0.0", &[]);
    let new_file_content = b"new file content\n";
    let after_hash = git_sha256(new_file_content);

    let socket = tmp.path().join(".socket");
    write_manifest(
        &socket,
        &format!(
            r#"{{ "patches": {{
                "pkg:npm/nested@1.0.0": {{
                    "uuid": "nested-uuid-0000",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/deep/nested/path/new.js": {{
                        "beforeHash": "", "afterHash": "{after_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "x",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), new_file_content).unwrap();

    let code = apply_run(default_apply(tmp.path())).await;
    assert_eq!(code, 0);
    let created = tmp
        .path()
        .join("node_modules/nested/deep/nested/path/new.js");
    assert_eq!(
        std::fs::read(&created).unwrap(),
        new_file_content,
        "nested new-file patch must create directories"
    );
}

// ---------------------------------------------------------------------------
// Multi-file patch
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn apply_patches_multiple_files_in_one_package() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"r","version":"0.0.0"}"#,
    )
    .unwrap();
    let orig_a = b"file a before\n";
    let orig_b = b"file b before\n";
    let patched_a = b"file a after\n";
    let patched_b = b"file b after\n";
    let before_a = git_sha256(orig_a);
    let before_b = git_sha256(orig_b);
    let after_a = git_sha256(patched_a);
    let after_b = git_sha256(patched_b);

    write_npm_pkg(
        tmp.path(),
        "multi",
        "1.0.0",
        &[("a.js", orig_a), ("lib/b.js", orig_b)],
    );

    let socket = tmp.path().join(".socket");
    write_manifest(
        &socket,
        &format!(
            r#"{{ "patches": {{
                "pkg:npm/multi@1.0.0": {{
                    "uuid": "multi-uuid-0000",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{
                        "package/a.js":     {{ "beforeHash": "{before_a}", "afterHash": "{after_a}" }},
                        "package/lib/b.js": {{ "beforeHash": "{before_b}", "afterHash": "{after_b}" }}
                    }},
                    "vulnerabilities": {{}}, "description": "x",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_a), patched_a).unwrap();
    std::fs::write(blobs.join(&after_b), patched_b).unwrap();

    let code = apply_run(default_apply(tmp.path())).await;
    assert_eq!(code, 0);
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/multi/a.js")).unwrap(),
        patched_a
    );
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/multi/lib/b.js")).unwrap(),
        patched_b
    );
}

// ---------------------------------------------------------------------------
// Hash mismatch on after_hash (post-write verify fails)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn apply_blob_after_hash_mismatch_reports_failure() {
    // Plant a blob whose CONTENT bytes don't match the claimed
    // afterHash — apply's post-write verify must catch this and mark
    // the patch failed.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"r","version":"0.0.0"}"#,
    )
    .unwrap();
    let original = b"before\n";
    let claimed_after_hash = git_sha256(b"different content"); // mismatched
    let actual_blob_bytes = b"this is what's on disk\n"; // doesn't hash to claimed_after_hash
    let before_hash = git_sha256(original);
    write_npm_pkg(tmp.path(), "mismatch", "1.0.0", &[("index.js", original)]);

    let socket = tmp.path().join(".socket");
    write_manifest(
        &socket,
        &format!(
            r#"{{ "patches": {{
                "pkg:npm/mismatch@1.0.0": {{
                    "uuid": "mm-uuid-0000",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/index.js": {{
                        "beforeHash": "{before_hash}", "afterHash": "{claimed_after_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "x",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&claimed_after_hash), actual_blob_bytes).unwrap();

    let pre = std::fs::read(tmp.path().join("node_modules/mismatch/index.js")).unwrap();
    let code = apply_run(default_apply(tmp.path())).await;
    // Apply detects the hash mismatch BEFORE any disk write (the
    // in-memory hash of the candidate blob doesn't match the
    // manifest's `afterHash`). The atomic-write rewrite of
    // `apply_file_patch` means the target file stays byte-identical
    // on the failure path — no half-written corruption.
    assert_eq!(code, 1, "afterHash mismatch must produce partial_failure");
    let post = std::fs::read(tmp.path().join("node_modules/mismatch/index.js")).unwrap();
    assert_eq!(
        post, pre,
        "atomic-write contract: hash-mismatch failure must leave the on-disk file byte-identical (no half-written corruption)"
    );
    // `actual_blob_bytes` is what the broken pre-rebase behavior would
    // have written (it trusted the blob without re-hashing). Assert it
    // explicitly NEVER landed on disk, rather than swallowing it with
    // `let _` — a regression that writes the unverified blob would now
    // fail here even if `post == pre` somehow still held.
    assert_ne!(
        post.as_slice(),
        actual_blob_bytes.as_slice(),
        "unverified blob bytes must never reach the target file"
    );
    assert_eq!(
        post.as_slice(),
        original,
        "file must remain the pristine original"
    );
}

// ---------------------------------------------------------------------------
// Re-apply is idempotent (AlreadyPatched short-circuit)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn apply_twice_second_run_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"r","version":"0.0.0"}"#,
    )
    .unwrap();
    let original = b"before\n";
    let patched = b"patched\n";
    let before_hash = git_sha256(original);
    let after_hash = git_sha256(patched);
    write_npm_pkg(tmp.path(), "idempotent", "1.0.0", &[("index.js", original)]);

    let socket = tmp.path().join(".socket");
    write_manifest(
        &socket,
        &format!(
            r#"{{ "patches": {{
                "pkg:npm/idempotent@1.0.0": {{
                    "uuid": "idem-uuid-0000",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/index.js": {{
                        "beforeHash": "{before_hash}", "afterHash": "{after_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "x",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), patched).unwrap();

    let target = tmp.path().join("node_modules/idempotent/index.js");
    assert_eq!(apply_run(default_apply(tmp.path())).await, 0);
    let mid = std::fs::read(&target).unwrap();
    assert_eq!(mid, patched);
    #[cfg(unix)]
    let ino_after_first = file_identity(&target);

    // Second run finds the file already at afterHash → marks as
    // already_patched → exits 0 WITHOUT touching the file. Because the
    // staged blob bytes equal the on-disk bytes, exit-0 + byte-equality
    // cannot tell a real short-circuit apart from a regression that blindly
    // re-writes the afterHash blob. The inode-stability check below is the
    // discriminator: a re-write goes through the atomic rename path and
    // allocates a fresh inode, so a lost short-circuit fails loudly here.
    assert_eq!(apply_run(default_apply(tmp.path())).await, 0);
    let after = std::fs::read(&target).unwrap();
    assert_eq!(
        after, patched,
        "idempotent re-apply preserves patched content"
    );
    #[cfg(unix)]
    assert_eq!(
        file_identity(&target),
        ino_after_first,
        "idempotent re-apply must short-circuit (already_patched), not re-write the file"
    );
    assert_no_staging_litter(&tmp.path().join("node_modules/idempotent"));
}

// ---------------------------------------------------------------------------
// Apply with file missing on disk (NotFound branch)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn apply_with_missing_target_file_reports_failure() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"r","version":"0.0.0"}"#,
    )
    .unwrap();
    // Install package WITHOUT the target file.
    write_npm_pkg(tmp.path(), "nofile", "1.0.0", &[]);
    let original = b"before\n";
    let patched = b"patched\n";
    let before_hash = git_sha256(original);
    let after_hash = git_sha256(patched);

    let socket = tmp.path().join(".socket");
    write_manifest(
        &socket,
        &format!(
            r#"{{ "patches": {{
                "pkg:npm/nofile@1.0.0": {{
                    "uuid": "nofile-uuid-0000",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/index.js": {{
                        "beforeHash": "{before_hash}", "afterHash": "{after_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "x",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), patched).unwrap();

    let target = tmp.path().join("node_modules/nofile/index.js");
    assert!(!target.exists(), "precondition: target file must be absent");

    let code = apply_run(default_apply(tmp.path())).await;
    assert_eq!(
        code, 1,
        "missing target file (non-empty beforeHash) must fail"
    );
    // The non-force failure path must not have conjured the file either.
    assert!(
        !target.exists(),
        "failed apply must not create the missing target file"
    );

    // --force should skip-and-continue rather than fail.
    let mut force_args = default_apply(tmp.path());
    force_args.force = true;
    let code = apply_run(force_args).await;
    assert_eq!(code, 0, "--force must skip missing files and exit 0");
    // "Skip" means SKIP: --force must not fabricate the missing file
    // from the afterHash blob. If it did, exit 0 alone would hide that
    // a non-existent file was silently materialized with patched bytes.
    assert!(
        !target.exists(),
        "--force must skip the missing file, not create it from the blob"
    );
}

// ---------------------------------------------------------------------------
// Rollback when on-disk file is already at beforeHash (already_original)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn rollback_already_original_short_circuits() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"r","version":"0.0.0"}"#,
    )
    .unwrap();
    let original = b"original\n";
    let patched = b"patched\n";
    let before_hash = git_sha256(original);
    let after_hash = git_sha256(patched);

    // File is ALREADY at the original (beforeHash) state.
    write_npm_pkg(
        tmp.path(),
        "already-orig",
        "1.0.0",
        &[("index.js", original)],
    );

    let socket = tmp.path().join(".socket");
    write_manifest(
        &socket,
        &format!(
            r#"{{ "patches": {{
                "pkg:npm/already-orig@1.0.0": {{
                    "uuid": "ao-uuid-0000",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/index.js": {{
                        "beforeHash": "{before_hash}", "afterHash": "{after_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "x",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    );
    // rollback --offline still requires the beforeHash blob to be
    // present on disk (the offline guard checks all blobs up-front
    // regardless of which files need rolling back). Stage it.
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), original).unwrap();

    let args = RollbackArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            dry_run: false,
            silent: true,
            manifest_path: ".socket/manifest.json".to_string(),
            offline: true,
            global: false,
            global_prefix: None,
            org: None,
            api_token: None,
            ecosystems: Some(vec!["npm".to_string()]),
            json: true,
            verbose: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: None,
        one_off: false,
    };
    let target = tmp.path().join("node_modules/already-orig/index.js");
    #[cfg(unix)]
    let ino_before = file_identity(&target);
    assert_eq!(rollback_run(args).await, 0);
    // File unchanged in content...
    assert_eq!(std::fs::read(&target).unwrap(), original);
    // ...AND not re-written. The staged beforeHash blob is byte-identical to
    // the on-disk content, so a regression that loses the `already_original`
    // short-circuit and instead re-writes the blob would still leave the file
    // == original and exit 0 — invisible to content/exit checks alone. Inode
    // stability proves the file was genuinely left untouched.
    #[cfg(unix)]
    assert_eq!(
        file_identity(&target),
        ino_before,
        "already-original rollback must short-circuit, not re-write the file"
    );
    assert_no_staging_litter(&tmp.path().join("node_modules/already-orig"));
}

// ---------------------------------------------------------------------------
// Empty manifest (no patches) — apply is a no-op
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn apply_empty_manifest_is_noop() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"r","version":"0.0.0"}"#,
    )
    .unwrap();
    let socket = tmp.path().join(".socket");
    write_manifest(&socket, r#"{ "patches": {} }"#);

    let code = apply_run(default_apply(tmp.path())).await;
    // Empty manifest → no patches in scope → there is genuinely nothing
    // to do, so `apply` is a clean no-op SUCCESS (exit 0). This must be
    // asserted exactly: `code == 0 || code == 1` accepts every outcome the
    // function can return and would stay green even if the empty-scope path
    // regressed back to the spurious `partialFailure`/exit-1 that broke the
    // npm `postinstall` hook (which runs `apply` on every install).
    assert_eq!(code, 0, "empty manifest has no work → clean no-op success");
    // A true no-op must not invent files. node_modules was never
    // created and the manifest must be untouched on disk.
    assert!(
        !tmp.path().join("node_modules").exists(),
        "empty-manifest apply must not create node_modules"
    );
    assert_eq!(
        std::fs::read_to_string(socket.join("manifest.json")).unwrap(),
        r#"{ "patches": {} }"#,
        "empty-manifest apply must not rewrite the manifest"
    );
}

// ---------------------------------------------------------------------------
// Invalid manifest JSON
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn apply_invalid_manifest_emits_error() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(socket.join("manifest.json"), "{ not json").unwrap();

    let code = apply_run(default_apply(tmp.path())).await;
    assert_eq!(code, 1);
}
