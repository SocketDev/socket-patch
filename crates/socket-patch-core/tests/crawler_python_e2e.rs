//! Integration coverage for `crawlers::python_crawler` paths the
//! apply-CLI suite doesn't drive. Specifically:
//!
//!   - `find_python_dirs` wildcard segments (`python3.*` and `*`)
//!   - `find_python_dirs` recursive descent with intermediate
//!     non-directory entries
//!   - `find_local_venv_site_packages` with VIRTUAL_ENV env var
//!   - `get_global_python_site_packages` with stubbed HOME
//!
//! Built around `tempfile::tempdir()` + serial env-var mutation
//! (via `serial_test::serial`) so tests can rebind HOME / VIRTUAL_ENV
//! without racing each other.

use std::path::Path;

use serial_test::serial;
use socket_patch_core::crawlers::python_crawler::{
    find_local_venv_site_packages, find_python_dirs, get_global_python_site_packages,
    read_python_metadata,
};

/// Helper: stage a fake `python3.X/lib/python3.X/site-packages` tree
/// under `root` so `find_python_dirs(root, ["python3.*", "lib",
/// "python3.*", "site-packages"])` returns it.
async fn stage_python_layout(root: &Path, py_ver: &str) -> std::path::PathBuf {
    let sp = root
        .join(format!("python{py_ver}"))
        .join("lib")
        .join(format!("python{py_ver}"))
        .join("site-packages");
    tokio::fs::create_dir_all(&sp).await.unwrap();
    sp
}

// ── find_python_dirs wildcards ─────────────────────────────────

/// `python3.*` wildcard matches directories whose name starts with
/// `python3.`. Covers the wildcard arm + the `name.starts_with`
/// filter.
#[tokio::test]
async fn find_python_dirs_python3_wildcard_matches_versions() {
    let tmp = tempfile::tempdir().unwrap();
    let p1 = stage_python_layout(tmp.path(), "3.11").await;
    let _p2 = stage_python_layout(tmp.path(), "3.12").await;
    // Also create a non-matching subdir that should be filtered out.
    tokio::fs::create_dir_all(tmp.path().join("python2.7").join("lib"))
        .await
        .unwrap();

    let result =
        find_python_dirs(tmp.path(), &["python3.*", "lib", "python3.*", "site-packages"]).await;
    assert!(
        result.iter().any(|r| r == &p1),
        "must find python3.11 layout; got {result:?}"
    );
    assert_eq!(result.len(), 2, "must find exactly python3.11 + python3.12");
}

/// `*` generic wildcard matches every directory entry. Covers the
/// generic wildcard branch (L142-L160 of python_crawler.rs).
#[tokio::test]
async fn find_python_dirs_star_wildcard_matches_all() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::create_dir_all(tmp.path().join("pkg_a").join("lib").join("python3.11").join("site-packages"))
        .await
        .unwrap();
    tokio::fs::create_dir_all(tmp.path().join("pkg_b").join("lib").join("python3.11").join("site-packages"))
        .await
        .unwrap();

    let result =
        find_python_dirs(tmp.path(), &["*", "lib", "python3.*", "site-packages"]).await;
    assert_eq!(result.len(), 2, "* must match both pkg_a and pkg_b");
}

/// `*` wildcard skips non-directory entries (regular files). Covers
/// the `if !ft.is_dir() { continue; }` arm.
#[tokio::test]
async fn find_python_dirs_star_wildcard_skips_files() {
    let tmp = tempfile::tempdir().unwrap();
    // A regular file at the wildcard position must NOT cause issues.
    tokio::fs::write(tmp.path().join("not_a_dir.txt"), b"x").await.unwrap();
    // And one real match.
    tokio::fs::create_dir_all(tmp.path().join("real").join("lib").join("python3.11").join("site-packages"))
        .await
        .unwrap();

    let result =
        find_python_dirs(tmp.path(), &["*", "lib", "python3.*", "site-packages"]).await;
    assert_eq!(result.len(), 1, "regular file must be skipped");
}

/// `find_python_dirs` against a non-existent base path returns empty
/// — the early-return arm.
#[tokio::test]
async fn find_python_dirs_nonexistent_base_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let absent = tmp.path().join("does-not-exist");
    let result = find_python_dirs(&absent, &["python3.*", "site-packages"]).await;
    assert!(result.is_empty());
}

/// `find_python_dirs` with empty segments returns the base path
/// itself (terminal-recursion arm).
#[tokio::test]
async fn find_python_dirs_empty_segments_returns_base() {
    let tmp = tempfile::tempdir().unwrap();
    let result = find_python_dirs(tmp.path(), &[]).await;
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], tmp.path());
}

/// Literal segment branch: non-wildcard segment is treated as a
/// literal subdir.
#[tokio::test]
async fn find_python_dirs_literal_segment_descends() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("literal_subdir").join("more");
    tokio::fs::create_dir_all(&target).await.unwrap();

    let result = find_python_dirs(tmp.path(), &["literal_subdir", "more"]).await;
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], target);
}

// ── find_local_venv_site_packages ──────────────────────────────

/// VIRTUAL_ENV env var pointing at a real venv layout adds it to
/// the discovered list. Covers the first arm of
/// find_local_venv_site_packages.
#[tokio::test]
#[serial]
async fn find_local_venv_site_packages_honors_virtual_env_var() {
    let tmp = tempfile::tempdir().unwrap();
    let venv = tmp.path().join("custom-venv");
    let sp = venv.join("lib").join("python3.11").join("site-packages");
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let prev = std::env::var("VIRTUAL_ENV").ok();
    std::env::set_var("VIRTUAL_ENV", &venv);
    let result = find_local_venv_site_packages(tmp.path()).await;
    std::env::remove_var("VIRTUAL_ENV");
    if let Some(v) = prev {
        std::env::set_var("VIRTUAL_ENV", v);
    }

    assert!(
        result.iter().any(|p| p == &sp),
        "VIRTUAL_ENV path must surface; got {result:?}"
    );
}

/// `.venv` directory in cwd is discovered when VIRTUAL_ENV is unset.
#[tokio::test]
#[serial]
async fn find_local_venv_site_packages_discovers_dot_venv() {
    let tmp = tempfile::tempdir().unwrap();
    let sp = tmp.path().join(".venv").join("lib").join("python3.11").join("site-packages");
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let prev = std::env::var("VIRTUAL_ENV").ok();
    std::env::remove_var("VIRTUAL_ENV");
    let result = find_local_venv_site_packages(tmp.path()).await;
    if let Some(v) = prev {
        std::env::set_var("VIRTUAL_ENV", v);
    }
    assert!(
        result.iter().any(|p| p == &sp),
        ".venv must be discovered; got {result:?}"
    );
}

/// `venv` directory in cwd is discovered when neither VIRTUAL_ENV
/// nor .venv exists.
#[tokio::test]
#[serial]
async fn find_local_venv_site_packages_discovers_venv_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let sp = tmp.path().join("venv").join("lib").join("python3.11").join("site-packages");
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let prev = std::env::var("VIRTUAL_ENV").ok();
    std::env::remove_var("VIRTUAL_ENV");
    let result = find_local_venv_site_packages(tmp.path()).await;
    if let Some(v) = prev {
        std::env::set_var("VIRTUAL_ENV", v);
    }
    assert!(
        result.iter().any(|p| p == &sp),
        "venv must be discovered; got {result:?}"
    );
}

// ── get_global_python_site_packages ─────────────────────────────

/// With HOME stubbed to a tempdir containing a fake anaconda3 layout,
/// the global discovery includes the anaconda site-packages.
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_anaconda() {
    let tmp = tempfile::tempdir().unwrap();
    let anaconda_sp = tmp
        .path()
        .join("anaconda3")
        .join("lib")
        .join("python3.11")
        .join("site-packages");
    tokio::fs::create_dir_all(&anaconda_sp).await.unwrap();

    let prev_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", tmp.path());
    let result = get_global_python_site_packages().await;
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    }
    // Anaconda must surface; other production paths may also surface
    // since they're scanned unconditionally. The check is "at least
    // the staged path is in the result."
    assert!(
        result.iter().any(|p| p == &anaconda_sp),
        "staged anaconda path must surface; got {result:?}"
    );
}

// ── read_python_metadata ───────────────────────────────────────

/// Well-formed METADATA returns (name, version).
#[tokio::test]
async fn read_python_metadata_well_formed() {
    let tmp = tempfile::tempdir().unwrap();
    let dist_info = tmp.path().join("requests-2.28.0.dist-info");
    tokio::fs::create_dir(&dist_info).await.unwrap();
    tokio::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: requests\nVersion: 2.28.0\n",
    )
    .await
    .unwrap();

    let result = read_python_metadata(&dist_info).await;
    assert_eq!(
        result,
        Some(("requests".to_string(), "2.28.0".to_string()))
    );
}

/// Missing METADATA file → None.
#[tokio::test]
async fn read_python_metadata_missing_file_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let dist_info = tmp.path().join("requests-2.28.0.dist-info");
    tokio::fs::create_dir(&dist_info).await.unwrap();
    // No METADATA file.

    let result = read_python_metadata(&dist_info).await;
    assert_eq!(result, None);
}

/// METADATA missing Name field → None.
#[tokio::test]
async fn read_python_metadata_missing_name_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let dist_info = tmp.path().join("requests-2.28.0.dist-info");
    tokio::fs::create_dir(&dist_info).await.unwrap();
    tokio::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nVersion: 2.28.0\n",
    )
    .await
    .unwrap();

    let result = read_python_metadata(&dist_info).await;
    assert_eq!(result, None);
}

/// METADATA missing Version field → None.
#[tokio::test]
async fn read_python_metadata_missing_version_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let dist_info = tmp.path().join("requests-2.28.0.dist-info");
    tokio::fs::create_dir(&dist_info).await.unwrap();
    tokio::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: requests\n",
    )
    .await
    .unwrap();

    let result = read_python_metadata(&dist_info).await;
    assert_eq!(result, None);
}
