//! Integration tests for the v5.0 scan↔rollback duality: the default
//! full-state rollback (manifest cleanup + blob/archive GC), the
//! `--preserve-state` opt-out, path-glob targets, and the fail-closed
//! blob-pinning rules that keep revert data alive for out-of-scope and
//! not-installed entries.
//!
//! Same shape as `rollback_invariants.rs`: binary-driven, SOCKET_*-scrubbed
//! child processes, hand-written camelCase manifests, git-sha256 oracle,
//! `--offline` throughout (before-blobs are staged, so nothing fetches).

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// A `rollback` command with the full `SOCKET_*` environment scrubbed and
/// the working directory pinned (same rationale as the twin helper in
/// `rollback_invariants.rs`: an ambient `SOCKET_OFFLINE`/`SOCKET_DRY_RUN`/
/// `SOCKET_PRESERVE_STATE` must never satisfy — or sabotage — a test that
/// is named after the flag's real code path). Scrub by prefix, not list.
fn rollback_cmd(cwd: &Path) -> Command {
    let mut cmd = Command::new(binary());
    cmd.arg("rollback").current_dir(cwd);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_")
            && key.to_string_lossy() != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&key);
        }
    }
    cmd
}

fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let out = rollback_cmd(cwd)
        .args(args)
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Git-SHA256: SHA256("blob <len>\0" ++ content).
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// One hand-written camelCase manifest entry (single `package/index.js`
/// file row), matching the TS-compatible on-disk schema.
fn manifest_entry(purl: &str, uuid: &str, before_hash: &str, after_hash: &str) -> String {
    format!(
        r#""{purl}": {{
      "uuid": "{uuid}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{
          "beforeHash": "{before_hash}",
          "afterHash": "{after_hash}"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "synthetic duality test patch",
      "license": "MIT",
      "tier": "free"
    }}"#
    )
}

/// Write `.socket/manifest.json` from pre-rendered entries, optionally with
/// a persisted `setup` block (which the manifest-cleanup default must
/// preserve verbatim). Returns the `.socket` dir.
fn write_socket_manifest(root: &Path, entries: &[String], with_setup: bool) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let patches = entries.join(",\n    ");
    let setup = if with_setup {
        r#",
  "setup": { "exclude": ["packages/skip-me"] }"#
    } else {
        ""
    };
    std::fs::write(
        socket.join("manifest.json"),
        format!("{{\n  \"patches\": {{\n    {patches}\n  }}{setup}\n}}"),
    )
    .expect("write manifest");
    socket
}

/// Install a fake npm package at `<root>/<nm_rel>/<name>` with the given
/// `index.js` bytes (`nm_rel` names the node_modules dir, e.g.
/// `node_modules` or `packages/app/node_modules`). The crawler discovers
/// nested workspace trees, so both spellings work.
fn install_npm_pkg(root: &Path, nm_rel: &str, name: &str, index_js: &[u8]) -> PathBuf {
    let pkg_dir = root.join(nm_rel).join(name);
    std::fs::create_dir_all(&pkg_dir).expect("create package dir");
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "1.0.0" }}"#),
    )
    .expect("write package.json");
    std::fs::write(pkg_dir.join("index.js"), index_js).expect("write index.js");
    pkg_dir
}

fn write_root_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "duality-invariants-root", "version": "0.0.0" }"#,
    )
    .expect("write root package.json");
}

fn stage_blob(socket: &Path, hash: &str, content: &[u8]) {
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).expect("create blobs dir");
    std::fs::write(blobs.join(hash), content).expect("stage blob");
}

/// Stage `<uuid>.tar.gz` in both archive stores (`.socket/diffs` and
/// `.socket/packages`) — the per-patch download artifacts the default GC
/// must sweep once the entry leaves the manifest.
fn stage_archives(socket: &Path, uuid: &str) -> (PathBuf, PathBuf) {
    let diff = socket.join("diffs").join(format!("{uuid}.tar.gz"));
    let pkg = socket.join("packages").join(format!("{uuid}.tar.gz"));
    for path in [&diff, &pkg] {
        std::fs::create_dir_all(path.parent().expect("archive path has a parent"))
            .expect("create archive dir");
        std::fs::write(path, b"synthetic-archive-bytes").expect("stage archive");
    }
    (diff, pkg)
}

/// Sorted file names in `dir` (empty when the dir does not exist).
fn dir_entries(dir: &Path) -> Vec<String> {
    match std::fs::read_dir(dir) {
        Ok(rd) => {
            let mut v: Vec<String> = rd
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        }
        Err(_) => Vec::new(),
    }
}

/// The default single-package fixture: an installed npm package whose
/// `index.js` holds the PATCHED bytes, a manifest entry (with a `setup`
/// block), both blobs staged, and the entry's diff + package archives
/// staged. Returned paths/hashes drive the post-state assertions.
struct DefaultFixture {
    root: tempfile::TempDir,
    socket: PathBuf,
    pkg_dir: PathBuf,
    purl: &'static str,
    uuid: &'static str,
    before: &'static [u8],
    after: &'static [u8],
    before_hash: String,
    after_hash: String,
}

fn default_fixture() -> DefaultFixture {
    let before: &[u8] = b"duality-original-content\n";
    let after: &[u8] = b"duality-patched-content\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);
    let purl = "pkg:npm/duality-target@1.0.0";
    let uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    let root = tempfile::tempdir().expect("tempdir");
    write_root_package_json(root.path());
    let pkg_dir = install_npm_pkg(root.path(), "node_modules", "duality-target", after);
    let socket = write_socket_manifest(
        root.path(),
        &[manifest_entry(purl, uuid, &before_hash, &after_hash)],
        true,
    );
    stage_blob(&socket, &before_hash, before);
    stage_blob(&socket, &after_hash, after);
    stage_archives(&socket, uuid);

    DefaultFixture {
        root,
        socket,
        pkg_dir,
        purl,
        uuid,
        before,
        after,
        before_hash,
        after_hash,
    }
}

// ---------------------------------------------------------------------------
// 1. Default full-state rollback: restore + manifest cleanup + GC sweep
// ---------------------------------------------------------------------------

#[test]
fn default_rollback_removes_entry_and_sweeps_blobs() {
    let fx = default_fixture();
    let (code, stdout, stderr) = run(fx.root.path(), &["--json", "--offline", "--yes"]);
    assert_eq!(
        code, 0,
        "default rollback must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");
    assert_eq!(v["rolledBack"], 1);
    assert_eq!(v["failed"], 0);
    assert_eq!(v["dryRun"], false);

    // Envelope: the entry left the manifest and the GC actually swept.
    assert_eq!(
        v["manifest"]["removedEntries"],
        serde_json::json!([fx.purl]),
        "stdout=\n{stdout}"
    );
    assert_eq!(v["manifest"]["preserved"], false);
    assert_eq!(
        v["gc"]["removedBlobs"], 2,
        "both the before and after blob are orphaned by the removal; stdout=\n{stdout}"
    );
    assert_eq!(v["gc"]["removedDiffArchives"], 1, "stdout=\n{stdout}");
    assert_eq!(v["gc"]["removedPackageArchives"], 1, "stdout=\n{stdout}");
    assert!(
        v["gc"]["bytesFreed"].as_u64().expect("bytesFreed number") > 0,
        "a real sweep frees bytes; stdout=\n{stdout}"
    );
    assert_eq!(
        v["paths"],
        serde_json::json!([]),
        "no path targets were given; stdout=\n{stdout}"
    );

    // Disk: file restored to ORIGINAL bytes (independent hash oracle).
    let restored = std::fs::read(fx.pkg_dir.join("index.js")).expect("read restored file");
    assert_eq!(restored, fx.before, "rollback must restore BEFORE content");
    assert_eq!(git_sha256(&restored), fx.before_hash);

    // Manifest file still exists, `patches` is empty, and the persisted
    // `setup` block survived the rewrite (rollback never touches setup).
    let manifest_raw =
        std::fs::read_to_string(fx.socket.join("manifest.json")).expect("manifest still exists");
    let m: serde_json::Value = serde_json::from_str(&manifest_raw).expect("valid manifest JSON");
    assert_eq!(
        m["patches"],
        serde_json::json!({}),
        "the rolled-back entry must leave the manifest; manifest=\n{manifest_raw}"
    );
    assert_eq!(
        m["setup"]["exclude"],
        serde_json::json!(["packages/skip-me"]),
        "setup state must survive manifest cleanup; manifest=\n{manifest_raw}"
    );

    // Blobs dir swept EMPTY; both archives gone.
    assert_eq!(
        dir_entries(&fx.socket.join("blobs")),
        Vec::<String>::new(),
        "no manifest entry references any blob anymore"
    );
    assert_eq!(
        dir_entries(&fx.socket.join("diffs")),
        Vec::<String>::new(),
        "the entry's diff archive must be swept"
    );
    assert_eq!(
        dir_entries(&fx.socket.join("packages")),
        Vec::<String>::new(),
        "the entry's package archive must be swept"
    );
}

// ---------------------------------------------------------------------------
// 2. --preserve-state: restore the tree, keep ALL local state, skip GC
// ---------------------------------------------------------------------------

#[test]
fn preserve_state_keeps_everything() {
    let fx = default_fixture();
    let manifest_before =
        std::fs::read(fx.socket.join("manifest.json")).expect("read manifest bytes");

    let (code, stdout, stderr) = run(fx.root.path(), &["--json", "--offline", "--preserve-state"]);
    assert_eq!(
        code, 0,
        "preserve-state rollback must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");
    assert_eq!(v["rolledBack"], 1, "the file restore still happens");
    assert_eq!(
        v["manifest"]["preserved"], true,
        "envelope must flag the preserve; stdout=\n{stdout}"
    );
    assert_eq!(
        v["manifest"]["removedEntries"],
        serde_json::json!([]),
        "nothing leaves the manifest under --preserve-state; stdout=\n{stdout}"
    );
    assert_eq!(
        v["gc"],
        serde_json::json!({ "skipped": true }),
        "GC is skipped wholesale, not run-with-zero-removals; stdout=\n{stdout}"
    );

    // The system IS restored...
    let restored = std::fs::read(fx.pkg_dir.join("index.js")).expect("read restored file");
    assert_eq!(restored, fx.before);
    assert_eq!(git_sha256(&restored), fx.before_hash);

    // ...but every piece of local state survives byte-for-byte / on disk.
    let manifest_after =
        std::fs::read(fx.socket.join("manifest.json")).expect("manifest still exists");
    assert_eq!(
        manifest_after, manifest_before,
        "the manifest must not be rewritten at all under --preserve-state"
    );
    assert_eq!(
        dir_entries(&fx.socket.join("blobs")),
        {
            let mut expected = vec![fx.before_hash.clone(), fx.after_hash.clone()];
            expected.sort();
            expected
        },
        "both blobs must survive"
    );
    assert_eq!(
        dir_entries(&fx.socket.join("diffs")),
        vec![format!("{}.tar.gz", fx.uuid)],
        "the diff archive must survive"
    );
    assert_eq!(
        dir_entries(&fx.socket.join("packages")),
        vec![format!("{}.tar.gz", fx.uuid)],
        "the package archive must survive"
    );
}

// ---------------------------------------------------------------------------
// 3. --ecosystems scoping never sweeps another ecosystem's revert data
// ---------------------------------------------------------------------------

/// The data-loss regression pin: an eco-scoped rollback removes only the
/// in-scope entry, and the OUT-of-scope entry keeps both its manifest
/// record and its staged beforeHash blob — the revert data a later
/// (unscoped) rollback needs. Before the pinning rule, the GC reference
/// was the post-removal manifest alone, whose remaining entries only kept
/// afterHash blobs — the pypi before-blob was swept.
#[test]
fn eco_scoped_run_pins_other_ecosystems_revert_data() {
    let npm_before: &[u8] = b"eco-npm-original\n";
    let npm_after: &[u8] = b"eco-npm-patched\n";
    let npm_before_hash = git_sha256(npm_before);
    let npm_after_hash = git_sha256(npm_after);
    let npm_purl = "pkg:npm/eco-npm-target@1.0.0";
    let pypi_before: &[u8] = b"eco-pypi-original\n";
    let pypi_before_hash = git_sha256(pypi_before);
    let pypi_after_hash = git_sha256(b"eco-pypi-patched\n");
    let pypi_purl = "pkg:pypi/eco-pypi-ghost@2.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    let pkg_dir = install_npm_pkg(tmp.path(), "node_modules", "eco-npm-target", npm_after);
    let socket = write_socket_manifest(
        tmp.path(),
        &[
            manifest_entry(
                npm_purl,
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                &npm_before_hash,
                &npm_after_hash,
            ),
            manifest_entry(
                pypi_purl,
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                &pypi_before_hash,
                &pypi_after_hash,
            ),
        ],
        false,
    );
    stage_blob(&socket, &npm_before_hash, npm_before);
    stage_blob(&socket, &npm_after_hash, npm_after);
    // The pypi package is NOT installed; only its beforeHash blob is staged
    // — the only local copy of its revert data.
    stage_blob(&socket, &pypi_before_hash, pypi_before);

    let (code, stdout, stderr) = run(
        tmp.path(),
        &["--json", "--offline", "--yes", "--ecosystems", "npm"],
    );
    assert_eq!(
        code, 0,
        "eco-scoped rollback must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");
    assert_eq!(
        v["manifest"]["removedEntries"],
        serde_json::json!([npm_purl]),
        "only the in-scope npm entry is removed; stdout=\n{stdout}"
    );

    // npm: restored + removed.
    let restored = std::fs::read(pkg_dir.join("index.js")).expect("read restored file");
    assert_eq!(git_sha256(&restored), npm_before_hash);
    let m: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(socket.join("manifest.json")).expect("manifest exists"),
    )
    .expect("valid manifest JSON");
    assert!(
        m["patches"].get(npm_purl).is_none(),
        "npm entry must be removed; manifest={m}"
    );
    // pypi: entry REMAINS...
    assert!(
        m["patches"].get(pypi_purl).is_some(),
        "the out-of-scope pypi entry must remain in the manifest; manifest={m}"
    );
    // ...and its beforeHash blob SURVIVES the sweep, while the npm blobs
    // (referenced only by the removed entry) are gone.
    assert_eq!(
        dir_entries(&socket.join("blobs")),
        vec![pypi_before_hash.clone()],
        "the pypi revert blob must be pinned; the npm blobs must be swept"
    );
}

// ---------------------------------------------------------------------------
// 4. Not-installed entry: removed from the manifest, revert blob pinned
// ---------------------------------------------------------------------------

/// The crawler-miss pin (remove parity): a manifest-only entry with no
/// installed package is removed on a bare rollback (the tree is already
/// unpatched), but its beforeHash blob is KEPT — a crawler miss must not
/// destroy the only local revert data.
#[test]
fn not_installed_entry_is_removed_with_pinned_blobs() {
    let before: &[u8] = b"ghost-original\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(b"ghost-patched\n");
    let purl = "pkg:npm/duality-ghost@3.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    // No node_modules at all — the entry has nothing installed.
    let socket = write_socket_manifest(
        tmp.path(),
        &[manifest_entry(
            purl,
            "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            &before_hash,
            &after_hash,
        )],
        false,
    );
    stage_blob(&socket, &before_hash, before);

    let (code, stdout, stderr) = run(tmp.path(), &["--json", "--offline", "--yes"]);
    assert_eq!(
        code, 0,
        "all-not-installed exits 0 (the tree is already unpatched); \
         stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");
    assert_eq!(v["failed"], 0);

    // The entry surfaces as the skipped marker, never a failure.
    let results = v["results"].as_array().expect("results array");
    assert_eq!(results.len(), 1, "stdout=\n{stdout}");
    assert_eq!(results[0]["purl"], purl);
    assert_eq!(results[0]["skipped"], "package_not_installed");
    assert!(results[0]["path"].is_null());

    // Removed from the manifest...
    assert_eq!(
        v["manifest"]["removedEntries"],
        serde_json::json!([purl]),
        "stdout=\n{stdout}"
    );
    let m: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(socket.join("manifest.json")).expect("manifest exists"),
    )
    .expect("valid manifest JSON");
    assert_eq!(m["patches"], serde_json::json!({}), "manifest={m}");

    // ...but the beforeHash blob is pinned, not swept.
    assert_eq!(
        v["gc"]["removedBlobs"], 0,
        "the pinned revert blob is not sweepable; stdout=\n{stdout}"
    );
    assert!(
        socket.join("blobs").join(&before_hash).exists(),
        "the not-installed entry's beforeHash blob must survive on disk"
    );
}

// ---------------------------------------------------------------------------
// 5-6. Target classification and no-match errors leave state untouched
// ---------------------------------------------------------------------------

/// A bare word is NEVER silently reinterpreted as a path scope: it keeps
/// identifier semantics and fails with the familiar exit-1 error, plus a
/// hint showing the path spellings.
#[test]
fn bare_word_target_stays_identifier_error() {
    let before_hash = git_sha256(b"bare-original\n");
    let after_hash = git_sha256(b"bare-patched\n");
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = write_socket_manifest(
        tmp.path(),
        &[manifest_entry(
            "pkg:npm/bare-word-sibling@1.0.0",
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            &before_hash,
            &after_hash,
        )],
        false,
    );
    let manifest_before =
        std::fs::read(socket.join("manifest.json")).expect("read manifest bytes");

    let (code, stdout, stderr) = run(tmp.path(), &["--offline", "lodash"]);
    assert_eq!(
        code, 1,
        "a bare word matching nothing must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("No patch found matching identifier: lodash"),
        "the identifier error must fire, never a path scope; stderr=\n{stderr}"
    );
    assert!(
        stderr.contains("./lodash"),
        "the error must hint the path spelling; stderr=\n{stderr}"
    );

    let manifest_after =
        std::fs::read(socket.join("manifest.json")).expect("manifest still exists");
    assert_eq!(
        manifest_after, manifest_before,
        "a no-match error must leave the manifest byte-identical"
    );
}

/// A path-shaped target that selects no patched package is an error (not a
/// silent empty scope), naming the pattern — and mutates nothing.
#[test]
fn path_target_matching_nothing_errors() {
    let fx = default_fixture();
    let manifest_before =
        std::fs::read(fx.socket.join("manifest.json")).expect("read manifest bytes");

    let (code, stdout, stderr) = run(fx.root.path(), &["--offline", "no/such/dir"]);
    assert_eq!(
        code, 1,
        "a no-match path pattern must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("path pattern matched no patched packages")
            && stderr.contains("no/such/dir"),
        "the error must name the pattern; stderr=\n{stderr}"
    );

    let manifest_after =
        std::fs::read(fx.socket.join("manifest.json")).expect("manifest still exists");
    assert_eq!(
        manifest_after, manifest_before,
        "a no-match error must leave the manifest byte-identical"
    );
    let content = std::fs::read(fx.pkg_dir.join("index.js")).expect("read installed file");
    assert_eq!(content, fx.after, "the installed file must stay patched");
    assert!(
        fx.socket.join("blobs").join(&fx.before_hash).exists()
            && fx.socket.join("blobs").join(&fx.after_hash).exists(),
        "blobs must be untouched"
    );
}

// ---------------------------------------------------------------------------
// 7. Path-scoped rollback: select by installed path, leave siblings alone
// ---------------------------------------------------------------------------

#[test]
fn path_scoped_rollback_selects_by_installed_path() {
    let root_before: &[u8] = b"path-root-original\n";
    let root_after: &[u8] = b"path-root-patched\n";
    let root_before_hash = git_sha256(root_before);
    let root_after_hash = git_sha256(root_after);
    let root_purl = "pkg:npm/path-root-pkg@1.0.0";
    let app_before: &[u8] = b"path-app-original\n";
    let app_after: &[u8] = b"path-app-patched\n";
    let app_before_hash = git_sha256(app_before);
    let app_after_hash = git_sha256(app_after);
    let app_purl = "pkg:npm/path-app-pkg@1.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    let root_pkg = install_npm_pkg(tmp.path(), "node_modules", "path-root-pkg", root_after);
    let app_pkg = install_npm_pkg(
        tmp.path(),
        "packages/app/node_modules",
        "path-app-pkg",
        app_after,
    );
    let socket = write_socket_manifest(
        tmp.path(),
        &[
            manifest_entry(
                root_purl,
                "11111111-1111-4111-8111-111111111111",
                &root_before_hash,
                &root_after_hash,
            ),
            manifest_entry(
                app_purl,
                "22222222-2222-4222-8222-222222222222",
                &app_before_hash,
                &app_after_hash,
            ),
        ],
        false,
    );
    stage_blob(&socket, &root_before_hash, root_before);
    stage_blob(&socket, &root_after_hash, root_after);
    stage_blob(&socket, &app_before_hash, app_before);
    stage_blob(&socket, &app_after_hash, app_after);

    let (code, stdout, stderr) = run(
        tmp.path(),
        &["--json", "--offline", "--yes", "packages/app"],
    );
    assert_eq!(
        code, 0,
        "path-scoped rollback must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");
    assert_eq!(
        v["paths"],
        serde_json::json!(["packages/app"]),
        "the envelope echoes the pattern verbatim; stdout=\n{stdout}"
    );
    assert_eq!(
        v["manifest"]["removedEntries"],
        serde_json::json!([app_purl]),
        "only the in-scope entry is removed; stdout=\n{stdout}"
    );
    assert_eq!(
        v["warnings"],
        serde_json::json!([]),
        "the restored copy is inside the pattern — no out_of_scope warning; \
         stdout=\n{stdout}"
    );

    // The in-scope package is restored; the out-of-scope one stays patched.
    let app_content = std::fs::read(app_pkg.join("index.js")).expect("read app file");
    assert_eq!(git_sha256(&app_content), app_before_hash, "app restored");
    let root_content = std::fs::read(root_pkg.join("index.js")).expect("read root file");
    assert_eq!(
        root_content, root_after,
        "the out-of-scope package must stay patched"
    );

    // Manifest: out-of-scope entry stays, in-scope entry gone.
    let m: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(socket.join("manifest.json")).expect("manifest exists"),
    )
    .expect("valid manifest JSON");
    assert!(
        m["patches"].get(root_purl).is_some(),
        "out-of-scope entry must remain; manifest={m}"
    );
    assert!(
        m["patches"].get(app_purl).is_none(),
        "in-scope entry must be removed; manifest={m}"
    );

    // Blobs: the surviving entry keeps BOTH its blobs (afterHash via the
    // reference manifest, beforeHash via the still-active-entry pin); the
    // removed entry's blobs are swept.
    assert_eq!(
        dir_entries(&socket.join("blobs")),
        {
            let mut expected = vec![root_before_hash.clone(), root_after_hash.clone()];
            expected.sort();
            expected
        },
        "only the removed entry's blobs may be swept"
    );
}

// ---------------------------------------------------------------------------
// 8. Invalid glob = usage error
// ---------------------------------------------------------------------------

#[test]
fn invalid_glob_is_usage_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, stderr) = run(tmp.path(), &["packages/["]);
    assert_eq!(
        code, 2,
        "an unparseable glob is a usage error (exit 2, before any state \
         discovery); stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("invalid path pattern"),
        "stderr must name the problem; stderr=\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// 9. Dry-run previews everything, mutates nothing
// ---------------------------------------------------------------------------

#[test]
fn dry_run_mutates_nothing() {
    let fx = default_fixture();
    let manifest_before =
        std::fs::read(fx.socket.join("manifest.json")).expect("read manifest bytes");

    let (code, stdout, stderr) = run(fx.root.path(), &["--json", "--offline", "--dry-run"]);
    assert_eq!(
        code, 0,
        "dry-run must exit 0; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");
    assert_eq!(v["dryRun"], true);
    assert_eq!(v["rolledBack"], 0, "a dry run mutates nothing");
    assert_eq!(v["failed"], 0);

    // The preview REPORTS the full plan: would-be manifest removal and
    // would-be GC counts...
    assert_eq!(
        v["manifest"]["removedEntries"],
        serde_json::json!([fx.purl]),
        "dry-run previews the would-be removal; stdout=\n{stdout}"
    );
    assert!(
        v["gc"].get("skipped").is_none(),
        "dry-run GC is a preview, not a skip; stdout=\n{stdout}"
    );
    assert_eq!(v["gc"]["removedBlobs"], 2, "stdout=\n{stdout}");
    assert_eq!(v["gc"]["removedDiffArchives"], 1, "stdout=\n{stdout}");
    assert_eq!(v["gc"]["removedPackageArchives"], 1, "stdout=\n{stdout}");

    // ...while the disk is untouched: file still PATCHED, manifest
    // byte-identical, blobs and archives all present.
    let content = std::fs::read(fx.pkg_dir.join("index.js")).expect("read installed file");
    assert_eq!(content, fx.after, "dry-run must not restore the file");
    let manifest_after =
        std::fs::read(fx.socket.join("manifest.json")).expect("manifest still exists");
    assert_eq!(
        manifest_after, manifest_before,
        "dry-run must leave the manifest byte-identical"
    );
    assert_eq!(
        dir_entries(&fx.socket.join("blobs")),
        {
            let mut expected = vec![fx.before_hash.clone(), fx.after_hash.clone()];
            expected.sort();
            expected
        },
        "dry-run must not sweep blobs"
    );
    assert_eq!(
        dir_entries(&fx.socket.join("diffs")),
        vec![format!("{}.tar.gz", fx.uuid)],
        "dry-run must not sweep the diff archive"
    );
    assert_eq!(
        dir_entries(&fx.socket.join("packages")),
        vec![format!("{}.tar.gz", fx.uuid)],
        "dry-run must not sweep the package archive"
    );

    // No `.socket-stage-*` litter (the dry-run blob stage is a throwaway
    // tempdir that must be gone when the process exits).
    let stage_litter: Vec<String> = dir_entries(&fx.socket)
        .into_iter()
        .filter(|name| name.starts_with(".socket-stage"))
        .collect();
    assert!(
        stage_litter.is_empty(),
        "dry-run must clean up its blob stage; found: {stage_litter:?}"
    );
}

// ---------------------------------------------------------------------------
// 10. UUID and PURL targets keep their exact single-entry semantics
// ---------------------------------------------------------------------------

/// Build the two-entry fixture shared by both identifier sub-cases:
/// `dual-a` + `dual-b`, both installed and patched, all four blobs staged.
/// Returns (tempdir, socket, pkg_a_dir, pkg_b_dir).
fn two_entry_fixture(
    a_before: &[u8],
    a_after: &[u8],
    b_before: &[u8],
    b_after: &[u8],
) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    let pkg_a = install_npm_pkg(tmp.path(), "node_modules", "dual-a", a_after);
    let pkg_b = install_npm_pkg(tmp.path(), "node_modules", "dual-b", b_after);
    let socket = write_socket_manifest(
        tmp.path(),
        &[
            manifest_entry(
                "pkg:npm/dual-a@1.0.0",
                "33333333-3333-4333-8333-333333333333",
                &git_sha256(a_before),
                &git_sha256(a_after),
            ),
            manifest_entry(
                "pkg:npm/dual-b@1.0.0",
                "44444444-4444-4444-8444-444444444444",
                &git_sha256(b_before),
                &git_sha256(b_after),
            ),
        ],
        false,
    );
    stage_blob(&socket, &git_sha256(a_before), a_before);
    stage_blob(&socket, &git_sha256(a_after), a_after);
    stage_blob(&socket, &git_sha256(b_before), b_before);
    stage_blob(&socket, &git_sha256(b_after), b_after);
    (tmp, socket, pkg_a, pkg_b)
}

#[test]
fn uuid_and_purl_targets_still_work() {
    let a_before: &[u8] = b"dual-a-original\n";
    let a_after: &[u8] = b"dual-a-patched\n";
    let b_before: &[u8] = b"dual-b-original\n";
    let b_after: &[u8] = b"dual-b-patched\n";

    // ── UUID target removes exactly entry A ─────────────────────────────
    let (tmp, socket, pkg_a, pkg_b) = two_entry_fixture(a_before, a_after, b_before, b_after);
    let (code, stdout, stderr) = run(
        tmp.path(),
        &[
            "--json",
            "--offline",
            "--yes",
            "33333333-3333-4333-8333-333333333333",
        ],
    );
    assert_eq!(
        code, 0,
        "uuid-targeted rollback must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");
    assert_eq!(
        v["manifest"]["removedEntries"],
        serde_json::json!(["pkg:npm/dual-a@1.0.0"]),
        "exactly the uuid's entry is removed; stdout=\n{stdout}"
    );
    let a_content = std::fs::read(pkg_a.join("index.js")).expect("read a");
    assert_eq!(a_content, a_before, "dual-a restored");
    let b_content = std::fs::read(pkg_b.join("index.js")).expect("read b");
    assert_eq!(b_content, b_after, "dual-b must stay patched");
    let m: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(socket.join("manifest.json")).expect("manifest exists"),
    )
    .expect("valid manifest JSON");
    assert!(m["patches"].get("pkg:npm/dual-a@1.0.0").is_none(), "{m}");
    assert!(m["patches"].get("pkg:npm/dual-b@1.0.0").is_some(), "{m}");
    // B's blobs survive (afterHash via the reference, beforeHash via the
    // still-active pin); A's blobs are swept.
    assert_eq!(
        dir_entries(&socket.join("blobs")),
        {
            let mut expected = vec![git_sha256(b_before), git_sha256(b_after)];
            expected.sort();
            expected
        },
        "only the removed entry's blobs may be swept"
    );

    // ── PURL target removes exactly entry B (fresh fixture) ─────────────
    let (tmp, socket, pkg_a, pkg_b) = two_entry_fixture(a_before, a_after, b_before, b_after);
    let (code, stdout, stderr) = run(
        tmp.path(),
        &["--json", "--offline", "--yes", "pkg:npm/dual-b@1.0.0"],
    );
    assert_eq!(
        code, 0,
        "purl-targeted rollback must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");
    assert_eq!(
        v["manifest"]["removedEntries"],
        serde_json::json!(["pkg:npm/dual-b@1.0.0"]),
        "exactly the purl's entry is removed; stdout=\n{stdout}"
    );
    let b_content = std::fs::read(pkg_b.join("index.js")).expect("read b");
    assert_eq!(b_content, b_before, "dual-b restored");
    let a_content = std::fs::read(pkg_a.join("index.js")).expect("read a");
    assert_eq!(a_content, a_after, "dual-a must stay patched");
    let m: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(socket.join("manifest.json")).expect("manifest exists"),
    )
    .expect("valid manifest JSON");
    assert!(m["patches"].get("pkg:npm/dual-b@1.0.0").is_none(), "{m}");
    assert!(m["patches"].get("pkg:npm/dual-a@1.0.0").is_some(), "{m}");
}
