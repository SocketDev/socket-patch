//! End-to-end: `socket-patch apply` against a real pnpm install
//! does NOT corrupt the shared content store.
//!
//! pnpm installs packages into a global content-addressed store and
//! gives each project a symlink (or symlink + hardlinked file) into
//! that store. Without the copy-on-write defense in
//! `crates/socket-patch-core/src/patch/cow.rs`, patching a file in
//! project A would silently mutate the same on-disk bytes that
//! project B and every other project on the machine reference. This
//! suite proves that does NOT happen — patching A's view leaves B's
//! view and the store entry byte-identical.
//!
//! Fixture: minimist@1.2.2 + its Socket patch (UUID
//! `80630680-4da6-45f9-bba8-b888e0ffd58c`, CVE-2021-44906) — same
//! pair `e2e_npm.rs` uses, so the BEFORE/AFTER hashes are known.
//!
//! Network: yes (pnpm install + socket-patch get). Toolchain: pnpm.
//! `#[ignore]` gated.

use std::path::{Path, PathBuf};

#[path = "common/mod.rs"]
mod common;

use common::{assert_run_ok, git_sha256_file, has_command, pnpm_run, write_package_json};

const NPM_UUID: &str = "80630680-4da6-45f9-bba8-b888e0ffd58c";

/// Git-SHA-256 of the *unpatched* `index.js` shipped with minimist 1.2.2.
const BEFORE_HASH: &str = "311f1e893e6eac502693fad8617dcf5353a043ccc0f7b4ba9fe385e838b67a10";
/// Git-SHA-256 of the *patched* `index.js` after the security fix.
const AFTER_HASH: &str = "043f04d19e884aa5f8371428718d2a3f27a0d231afe77a2620ac6312f80aaa28";

// ── Setup helpers ─────────────────────────────────────────────────────

/// Layout produced by `setup_two_pnpm_projects`. Holds paths the
/// individual assertions need.
struct TwoProjectFixture {
    proj_a: PathBuf,
    proj_b: PathBuf,
    /// Pnpm content store, shared between the two projects.
    store_dir: PathBuf,
}

impl TwoProjectFixture {
    fn index_js_in(&self, proj: &Path) -> PathBuf {
        proj.join("node_modules/minimist/index.js")
    }
}

/// Stage two sibling projects under `root` that both `pnpm install`
/// minimist@1.2.2 into a shared store. Uses
/// `package-import-method=hardlink` so the resulting on-disk files
/// in `node_modules/<pkg>` are hardlinks into the store, not copies
/// — that's the exact topology the CoW defense was designed for.
fn setup_two_pnpm_projects(root: &Path) -> TwoProjectFixture {
    let proj_a = root.join("proj_a");
    let proj_b = root.join("proj_b");
    let store_dir = root.join(".pnpm-store");
    std::fs::create_dir_all(&proj_a).unwrap();
    std::fs::create_dir_all(&proj_b).unwrap();

    // Use a `package.json` that already pins minimist so the
    // `pnpm install` invocation is the "install from manifest"
    // shape (no positional args). With a positional arg pnpm
    // routes through `add` semantics, which has different flag
    // semantics.
    for proj in [&proj_a, &proj_b] {
        std::fs::write(
            proj.join("package.json"),
            r#"{"name":"pnpm-fixture","version":"0.0.0","private":true,"dependencies":{"minimist":"1.2.2"}}"#,
        )
        .unwrap();
    }
    let _ = write_package_json; // suppress unused-import warning

    let store_str = store_dir.to_str().unwrap();
    // Hardlink import method makes the assertion below ("store
    // entry hash is unchanged after apply") sharp: without CoW,
    // mutating one project would mutate the store's inode directly.
    let env_pairs: &[(&str, &str)] = &[];
    for proj in [&proj_a, &proj_b] {
        pnpm_run(
            proj,
            &[
                "install",
                "--store-dir",
                store_str,
                "--config.package-import-method=hardlink",
            ],
            env_pairs,
        );
    }

    TwoProjectFixture {
        proj_a,
        proj_b,
        store_dir,
    }
}

/// Find the pnpm store's canonical copy of minimist's `index.js`.
/// Store layout: `<store>/<v3-or-similar>/files/<sha512-prefix>/<rest>`.
/// We don't need to navigate that exactly — the simpler invariant is
/// "pick any single file inside the store that has the same content
/// as proj_a's index.js" and assert it stays unchanged.
///
/// To find that file robustly: read proj_a's `index.js` content as
/// our reference, then walk the store and find a file with matching
/// content. If pnpm's layout is hardlinked (our setup), the store's
/// matching inode IS the same physical bytes as proj_a's symlink
/// target — they hash identically.
fn find_store_file_with_content(store_dir: &Path, expected: &[u8]) -> Option<PathBuf> {
    walk_dir(store_dir, &mut |p| {
        if p.is_file() {
            if let Ok(c) = std::fs::read(p) {
                if c == expected {
                    return Some(p.to_path_buf());
                }
            }
        }
        None
    })
}

fn walk_dir<F>(dir: &Path, f: &mut F) -> Option<PathBuf>
where
    F: FnMut(&Path) -> Option<PathBuf>,
{
    let mut entries = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return None,
    };
    while let Some(Ok(entry)) = entries.next() {
        let p = entry.path();
        if let Some(hit) = f(&p) {
            return Some(hit);
        }
        if p.is_dir() {
            if let Some(hit) = walk_dir(&p, f) {
                return Some(hit);
            }
        }
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────

/// Sanity: post-install, `node_modules/minimist` in proj_a is a
/// symlink, the resolved `index.js` matches BEFORE_HASH, and the
/// same content exists somewhere in the store. Confirms the fixture
/// is wired correctly before the safety assertions below.
#[test]
#[ignore]
fn pnpm_install_produces_symlinked_layout() {
    if !has_command("pnpm") {
        eprintln!("SKIP: pnpm not on PATH");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let fx = setup_two_pnpm_projects(root.path());

    let nm_minimist = fx.proj_a.join("node_modules/minimist");
    let lstat = std::fs::symlink_metadata(&nm_minimist)
        .expect("node_modules/minimist should exist post-install");
    assert!(
        lstat.file_type().is_symlink(),
        "pnpm should produce a symlink at node_modules/minimist"
    );

    let index_a = fx.index_js_in(&fx.proj_a);
    assert_eq!(
        git_sha256_file(&index_a),
        BEFORE_HASH,
        "fresh pnpm install should give us the unpatched minimist"
    );

    let original_bytes = std::fs::read(&index_a).unwrap();
    assert!(
        find_store_file_with_content(&fx.store_dir, &original_bytes).is_some(),
        "store should contain a file matching proj_a's index.js"
    );
}

/// **Headline test**: socket-patch apply in proj_a patches proj_a,
/// but leaves proj_b and the pnpm store entry byte-unchanged.
///
/// Without the CoW defense in
/// `socket-patch-core::patch::cow::break_hardlink_if_needed`, this
/// test would fail: writing through proj_a's symlink would mutate
/// the shared store inode and, transitively, every other project
/// that points at the same store entry.
#[test]
#[ignore]
fn apply_in_a_does_not_mutate_b_or_store() {
    if !has_command("pnpm") {
        eprintln!("SKIP: pnpm not on PATH");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let fx = setup_two_pnpm_projects(root.path());

    let index_a = fx.index_js_in(&fx.proj_a);
    let index_b = fx.index_js_in(&fx.proj_b);
    assert_eq!(git_sha256_file(&index_a), BEFORE_HASH);
    assert_eq!(git_sha256_file(&index_b), BEFORE_HASH);

    // Find the store's view of the file BEFORE apply so we can
    // compare hashes after.
    let original_bytes = std::fs::read(&index_a).unwrap();
    let store_copy = find_store_file_with_content(&fx.store_dir, &original_bytes)
        .expect("store should contain the original minimist bytes pre-apply");
    let store_hash_before = git_sha256_file(&store_copy);
    assert_eq!(store_hash_before, BEFORE_HASH);

    // -- get + apply in proj_a only ----------------------------------
    assert_run_ok(&fx.proj_a, &["get", NPM_UUID], "socket-patch get");

    // proj_a is patched.
    assert_eq!(
        git_sha256_file(&index_a),
        AFTER_HASH,
        "proj_a's index.js should be patched"
    );
    // proj_b is NOT patched — the headline invariant.
    assert_eq!(
        git_sha256_file(&index_b),
        BEFORE_HASH,
        "proj_b's index.js must stay unpatched. CoW failure?"
    );
    // The store entry the pnpm install hardlinked into BOTH projects
    // is still the original bytes. (The file at `store_copy` is the
    // pre-apply view; CoW gave proj_a a new inode, so the original
    // store inode kept its original bytes.)
    assert_eq!(
        git_sha256_file(&store_copy),
        BEFORE_HASH,
        "pnpm store entry must stay unpatched. CoW failure?"
    );
}

/// After `apply_in_a_does_not_mutate_b_or_store`, running
/// `pnpm install --frozen-lockfile` in proj_b must NOT pull our
/// patched bytes into the store (because we broke the link rather
/// than mutating the store inode). This is the "deploy pipeline
/// installs B after we patched A; A's patch must survive" scenario.
#[test]
#[ignore]
fn pnpm_install_in_b_does_not_revert_a() {
    if !has_command("pnpm") {
        eprintln!("SKIP: pnpm not on PATH");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let fx = setup_two_pnpm_projects(root.path());
    assert_run_ok(&fx.proj_a, &["get", NPM_UUID], "socket-patch get");
    let index_a = fx.index_js_in(&fx.proj_a);
    assert_eq!(git_sha256_file(&index_a), AFTER_HASH);

    // Re-run pnpm install in proj_b with frozen lockfile — this
    // recomputes the install from cache; with CoW the cache is
    // unmodified, so proj_b stays BEFORE_HASH and proj_a stays
    // AFTER_HASH.
    let env_pairs: &[(&str, &str)] = &[];
    pnpm_run(
        &fx.proj_b,
        &[
            "install",
            "--store-dir",
            fx.store_dir.to_str().unwrap(),
            "--config.package-import-method=hardlink",
            "--frozen-lockfile",
        ],
        env_pairs,
    );

    assert_eq!(
        git_sha256_file(&index_a),
        AFTER_HASH,
        "proj_a's patch must survive `pnpm install --frozen-lockfile` in proj_b"
    );
    assert_eq!(
        git_sha256_file(&fx.index_js_in(&fx.proj_b)),
        BEFORE_HASH,
        "proj_b should still see the original minimist after frozen install"
    );
}

/// The pnpm layout produces an informational note on stderr (the
/// "pnpm layout detected" hint added by the apply command). Pin it
/// so a refactor that drops the note is obvious.
#[test]
#[ignore]
fn apply_in_pnpm_project_emits_layout_note() {
    if !has_command("pnpm") {
        eprintln!("SKIP: pnpm not on PATH");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let fx = setup_two_pnpm_projects(root.path());

    let (_stdout, stderr) =
        assert_run_ok(&fx.proj_a, &["get", NPM_UUID], "socket-patch get");

    // The exact phrasing is a stable contract — assert on the
    // distinctive substring "pnpm" appearing in the user-facing
    // stderr message. (apply.rs emits "Note: pnpm layout detected.
    // Copy-on-write will keep the global store untouched.")
    assert!(
        stderr.to_lowercase().contains("pnpm"),
        "apply against a pnpm project should mention pnpm in stderr.\nstderr:\n{stderr}"
    );
}
