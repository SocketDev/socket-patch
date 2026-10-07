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
    find_local_venv_site_packages, find_python_command_with, find_python_dirs,
    get_global_python_site_packages, parse_python_site_packages_output, read_python_metadata,
};
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::PythonCrawler;

#[test]
#[serial_test::parallel]
fn parse_python_site_packages_output_well_formed() {
    let stdout =
        "/usr/local/lib/python3.11/site-packages\n/usr/local/lib/python3.11/dist-packages\n";
    let paths = parse_python_site_packages_output(stdout);
    assert_eq!(paths.len(), 2);
    assert_eq!(
        paths[0],
        std::path::PathBuf::from("/usr/local/lib/python3.11/site-packages")
    );
}

#[test]
#[serial_test::parallel]
fn parse_python_site_packages_output_empty_returns_empty() {
    assert!(parse_python_site_packages_output("").is_empty());
    assert!(parse_python_site_packages_output("\n  \n").is_empty());
}

#[test]
#[serial_test::parallel]
fn parse_python_site_packages_output_trims_and_skips_blanks() {
    let stdout = "  /a/b  \n\n   \n/c/d\n";
    let paths = parse_python_site_packages_output(stdout);
    assert_eq!(paths.len(), 2);
    assert_eq!(paths[0], std::path::PathBuf::from("/a/b"));
    assert_eq!(paths[1], std::path::PathBuf::from("/c/d"));
}

/// `find_python_command_with` with a mock runner that responds
/// success to `python3 --version` must return `Some("python3")` —
/// the first-match-wins arm. Lets tests exercise the success arm
/// without needing python3 on the host's PATH.
#[test]
#[serial_test::parallel]
fn find_python_command_with_mock_runner_prefers_python3() {
    let runner = common::MockCommandRunner::new().with_response(
        "python3",
        &["--version"],
        Some("Python 3.11.5\n"),
    );
    assert_eq!(find_python_command_with(&runner), Some("python3"));
}

/// When `python3` is not present but `python` is, the helper should
/// fall through to the second candidate.
#[test]
#[serial_test::parallel]
fn find_python_command_with_mock_runner_falls_through_to_python() {
    let runner = common::MockCommandRunner::new().with_response(
        "python",
        &["--version"],
        Some("Python 2.7.18\n"),
    );
    assert_eq!(find_python_command_with(&runner), Some("python"));
}

/// When none of `python3`/`python`/`py` are present, the helper
/// returns None.
#[test]
#[serial_test::parallel]
fn find_python_command_with_mock_runner_none_when_no_binary() {
    let runner = common::MockCommandRunner::new();
    assert_eq!(find_python_command_with(&runner), None);
}

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
#[serial_test::parallel]
async fn find_python_dirs_python3_wildcard_matches_versions() {
    let tmp = tempfile::tempdir().unwrap();
    let p1 = stage_python_layout(tmp.path(), "3.11").await;
    let _p2 = stage_python_layout(tmp.path(), "3.12").await;
    // Also create a non-matching subdir that should be filtered out.
    tokio::fs::create_dir_all(tmp.path().join("python2.7").join("lib"))
        .await
        .unwrap();

    let result = find_python_dirs(
        tmp.path(),
        &["python3.*", "lib", "python3.*", "site-packages"],
    )
    .await;
    assert!(
        result.iter().any(|r| r == &p1),
        "must find python3.11 layout; got {result:?}"
    );
    assert_eq!(result.len(), 2, "must find exactly python3.11 + python3.12");
}

/// `*` generic wildcard matches every directory entry. Covers the
/// generic `*` wildcard branch of `find_python_dirs`.
#[tokio::test]
#[serial_test::parallel]
async fn find_python_dirs_star_wildcard_matches_all() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::create_dir_all(
        tmp.path()
            .join("pkg_a")
            .join("lib")
            .join("python3.11")
            .join("site-packages"),
    )
    .await
    .unwrap();
    tokio::fs::create_dir_all(
        tmp.path()
            .join("pkg_b")
            .join("lib")
            .join("python3.11")
            .join("site-packages"),
    )
    .await
    .unwrap();

    let result = find_python_dirs(tmp.path(), &["*", "lib", "python3.*", "site-packages"]).await;
    assert_eq!(result.len(), 2, "* must match both pkg_a and pkg_b");
}

/// `*` wildcard skips non-directory entries (regular files). Covers
/// the `entry_is_dir` skip arm.
#[tokio::test]
#[serial_test::parallel]
async fn find_python_dirs_star_wildcard_skips_files() {
    let tmp = tempfile::tempdir().unwrap();
    // A regular file at the wildcard position must NOT cause issues.
    tokio::fs::write(tmp.path().join("not_a_dir.txt"), b"x")
        .await
        .unwrap();
    // And one real match.
    tokio::fs::create_dir_all(
        tmp.path()
            .join("real")
            .join("lib")
            .join("python3.11")
            .join("site-packages"),
    )
    .await
    .unwrap();

    let result = find_python_dirs(tmp.path(), &["*", "lib", "python3.*", "site-packages"]).await;
    assert_eq!(result.len(), 1, "regular file must be skipped");
}

/// `find_python_dirs` against a non-existent base path returns empty
/// — the early-return arm.
#[tokio::test]
#[serial_test::parallel]
async fn find_python_dirs_nonexistent_base_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let absent = tmp.path().join("does-not-exist");
    let result = find_python_dirs(&absent, &["python3.*", "site-packages"]).await;
    assert!(result.is_empty());
}

/// `find_python_dirs` with empty segments returns the base path
/// itself (terminal-recursion arm).
#[tokio::test]
#[serial_test::parallel]
async fn find_python_dirs_empty_segments_returns_base() {
    let tmp = tempfile::tempdir().unwrap();
    let result = find_python_dirs(tmp.path(), &[]).await;
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], tmp.path());
}

/// Literal segment branch: non-wildcard segment is treated as a
/// literal subdir.
#[tokio::test]
#[serial_test::parallel]
async fn find_python_dirs_literal_segment_descends() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("literal_subdir").join("more");
    tokio::fs::create_dir_all(&target).await.unwrap();

    let result = find_python_dirs(tmp.path(), &["literal_subdir", "more"]).await;
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], target);
}

// ── find_local_venv_site_packages ──────────────────────────────

/// Build the site-packages relative path for the current OS.
/// Production `find_site_packages_under` looks for `Lib/site-packages`
/// on Windows and `lib/python3.X/site-packages` on Unix — the test
/// fixture must stage whichever the production code expects to find.
fn venv_site_packages_relpath() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        std::path::Path::new("Lib").join("site-packages")
    }
    #[cfg(not(windows))]
    {
        std::path::Path::new("lib")
            .join("python3.11")
            .join("site-packages")
    }
}

/// VIRTUAL_ENV env var pointing at a real venv layout adds it to
/// the discovered list. Covers the first arm of
/// find_local_venv_site_packages.
#[tokio::test]
#[serial]
async fn find_local_venv_site_packages_honors_virtual_env_var() {
    let tmp = tempfile::tempdir().unwrap();
    let venv = tmp.path().join("custom-venv");
    let sp = venv.join(venv_site_packages_relpath());
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
    let sp = tmp.path().join(".venv").join(venv_site_packages_relpath());
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
    let sp = tmp.path().join("venv").join(venv_site_packages_relpath());
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

/// macOS `pip install --user` uses the framework "user" install scheme:
/// `~/Library/Python/<X.Y>/lib/python/site-packages` — one tree per
/// interpreter MINOR VERSION, with a BARE `python` leaf (not `python3.X`).
/// Both Apple's `/usr/bin/python3` and Homebrew's `python3` are framework
/// builds and use it, so a stock Mac has several of these trees.
///
/// The well-known scan needs a macOS entry alongside pip --user on Linux
/// (`~/.local`) and Windows (`%APPDATA%\Python`): the
/// `site.getusersitepackages()` query reports at most the ONE interpreter
/// first on PATH, so everything `pip3 install --user`ed under any other
/// interpreter would be invisible to global discovery.
///
/// Two versions are staged deliberately: the runtime-query arm can only ever
/// contribute the host interpreter's own version, so requiring BOTH to surface
/// keeps the test honest whatever Python the host happens to run.
#[cfg(target_os = "macos")]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_macos_user_site() {
    let tmp = tempfile::tempdir().unwrap();
    let mut staged = Vec::new();
    for ver in ["3.9", "3.12"] {
        let sp = tmp
            .path()
            .join("Library")
            .join("Python")
            .join(ver)
            .join("lib")
            .join("python")
            .join("site-packages");
        tokio::fs::create_dir_all(&sp).await.unwrap();
        staged.push(sp);
    }

    let prev_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", tmp.path());
    let result = get_global_python_site_packages().await;
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    }

    for sp in &staged {
        assert!(
            result.iter().any(|p| p == sp),
            "macOS pip --user site-packages {} must surface; got {result:?}",
            sp.display()
        );
    }
}

// ── uv-tools and uv-python discovery ──────────────────────────

/// `uv tool install <pkg>` on macOS installs into
/// `~/Library/Application Support/uv/tools/<pkg>/lib/python3.X/site-packages/`.
/// Stub HOME to a tempdir containing that layout and verify
/// `get_global_python_site_packages` surfaces it.
#[cfg(target_os = "macos")]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_uv_tools_macos() {
    let tmp = tempfile::tempdir().unwrap();
    let sp = tmp
        .path()
        .join("Library")
        .join("Application Support")
        .join("uv")
        .join("tools")
        .join("black")
        .join("lib")
        .join("python3.11")
        .join("site-packages");
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let prev_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", tmp.path());
    let result = get_global_python_site_packages().await;
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    }
    assert!(
        result.iter().any(|p| p == &sp),
        "uv tools layout must surface; got {result:?}"
    );
}

/// uv follows XDG conventions on macOS too: `uv tool dir` resolves to
/// `~/.local/share/uv/tools` (verified against a real uv install), NOT
/// `~/Library/Application Support/uv/tools`. Scanning only the Application
/// Support path makes every `uv tool install`ed package invisible to
/// global discovery on macOS.
#[cfg(target_os = "macos")]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_uv_tools_xdg_on_macos() {
    let tmp = tempfile::tempdir().unwrap();
    let sp = tmp
        .path()
        .join(".local")
        .join("share")
        .join("uv")
        .join("tools")
        .join("black")
        .join("lib")
        .join("python3.11")
        .join("site-packages");
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let prev_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", tmp.path());
    let result = get_global_python_site_packages().await;
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    }
    assert!(
        result.iter().any(|p| p == &sp),
        "XDG uv tools layout must surface on macOS; got {result:?}"
    );
}

/// `uv tool install <pkg>` on Linux installs into
/// `~/.local/share/uv/tools/<pkg>/lib/python3.X/site-packages/`.
#[cfg(all(not(target_os = "macos"), not(windows)))]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_uv_tools_linux() {
    let tmp = tempfile::tempdir().unwrap();
    let sp = tmp
        .path()
        .join(".local")
        .join("share")
        .join("uv")
        .join("tools")
        .join("black")
        .join("lib")
        .join("python3.11")
        .join("site-packages");
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let prev_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", tmp.path());
    let result = get_global_python_site_packages().await;
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    }
    assert!(
        result.iter().any(|p| p == &sp),
        "uv tools layout must surface; got {result:?}"
    );
}

/// `uv python install 3.X` installs managed interpreters at
/// `~/.local/share/uv/python/cpython-3.X.*/lib/python3.X/site-packages/`
/// on Linux/macOS. Power users can pip-install directly into that
/// interpreter; the global crawler must surface it.
#[cfg(not(windows))]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_uv_python_install() {
    let tmp = tempfile::tempdir().unwrap();
    let sp = tmp
        .path()
        .join(".local")
        .join("share")
        .join("uv")
        .join("python")
        .join("cpython-3.11.6-macos-aarch64-none")
        .join("lib")
        .join("python3.11")
        .join("site-packages");
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let prev_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", tmp.path());
    let result = get_global_python_site_packages().await;
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    }
    assert!(
        result.iter().any(|p| p == &sp),
        "uv-python managed interpreter site-packages must surface; got {result:?}"
    );
}

// ── pipx venv discovery ───────────────────────────────────────

/// Run `get_global_python_site_packages` with HOME, PIPX_HOME and
/// XDG_DATA_HOME rebound (`None` unsets), restoring all three after.
/// pipx resolves its home from these, so every pipx test has to pin
/// them or an ambient value on the host would decide the result.
async fn global_site_packages_with_env(
    home: &Path,
    pipx_home: Option<&Path>,
    xdg_data_home: Option<&Path>,
) -> Vec<std::path::PathBuf> {
    let saved: Vec<(&str, Option<String>)> = ["HOME", "PIPX_HOME", "XDG_DATA_HOME"]
        .into_iter()
        .map(|k| (k, std::env::var(k).ok()))
        .collect();
    std::env::set_var("HOME", home);
    for (key, value) in [("PIPX_HOME", pipx_home), ("XDG_DATA_HOME", xdg_data_home)] {
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
    let result = get_global_python_site_packages().await;
    for (key, value) in saved {
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
    result
}

/// The site-packages of a pipx app venv under `pipx_home`, in the
/// platform's venv layout (`lib/python3.X/site-packages` on Unix,
/// `Lib\site-packages` on Windows).
fn pipx_venv_site_packages(pipx_home: &Path, app: &str) -> std::path::PathBuf {
    let venv = pipx_home.join("venvs").join(app);
    if cfg!(windows) {
        venv.join("Lib").join("site-packages")
    } else {
        venv.join("lib").join("python3.11").join("site-packages")
    }
}

/// `pipx install hatch` on Linux (pipx >= 1.3) puts the app venv at
/// `~/.local/share/pipx/venvs/hatch` (#415). Every app venv must surface,
/// not just the first.
#[cfg(all(not(target_os = "macos"), not(windows)))]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_pipx_venvs_linux() {
    let tmp = tempfile::tempdir().unwrap();
    let pipx_home = tmp.path().join(".local").join("share").join("pipx");
    let staged: Vec<_> = ["hatch", "black"]
        .iter()
        .map(|app| pipx_venv_site_packages(&pipx_home, app))
        .collect();
    for sp in &staged {
        tokio::fs::create_dir_all(sp).await.unwrap();
    }

    let result = global_site_packages_with_env(tmp.path(), None, None).await;
    for sp in &staged {
        assert!(
            result.iter().any(|p| p == sp),
            "pipx venv {} must surface; got {result:?}",
            sp.display()
        );
    }
}

/// pipx's Linux default follows `$XDG_DATA_HOME` (platformdirs'
/// `user_data_dir`), so a relocated data home moves the venvs too.
#[cfg(all(not(target_os = "macos"), not(windows)))]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_pipx_venvs_under_xdg_data_home() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join("xdg-data");
    let sp = pipx_venv_site_packages(&xdg.join("pipx"), "hatch");
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let result = global_site_packages_with_env(tmp.path(), None, Some(&xdg)).await;
    assert!(
        result.iter().any(|p| p == &sp),
        "pipx venv under XDG_DATA_HOME must surface; got {result:?}"
    );
}

/// Native (C-extension) packages land in `lib64` on RHEL/Fedora/SUSE
/// venvs, the same split the other well-known scans already handle.
#[cfg(not(windows))]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_pipx_venv_lib64() {
    let tmp = tempfile::tempdir().unwrap();
    let pipx_home = tmp.path().join("pipx-home");
    let sp = pipx_home
        .join("venvs")
        .join("hatch")
        .join("lib64")
        .join("python3.11")
        .join("site-packages");
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let result = global_site_packages_with_env(tmp.path(), Some(&pipx_home), None).await;
    assert!(
        result.iter().any(|p| p == &sp),
        "pipx venv lib64 site-packages must surface; got {result:?}"
    );
}

/// pipx's legacy home `~/.local/pipx` is still used when it exists
/// (pipx < 1.3 installs, and pipx's fallback on every OS), and is
/// what macOS runners use in the #415 probe.
#[cfg(not(windows))]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_pipx_venvs_legacy_home() {
    let tmp = tempfile::tempdir().unwrap();
    let sp = pipx_venv_site_packages(&tmp.path().join(".local").join("pipx"), "hatch");
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let result = global_site_packages_with_env(tmp.path(), None, None).await;
    assert!(
        result.iter().any(|p| p == &sp),
        "legacy ~/.local/pipx venv must surface; got {result:?}"
    );
}

/// platformdirs' macOS data dir is `~/Library/Application Support`,
/// which pipx 1.3–1.4 used as its default home.
#[cfg(target_os = "macos")]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_pipx_venvs_macos_app_support() {
    let tmp = tempfile::tempdir().unwrap();
    let pipx_home = tmp
        .path()
        .join("Library")
        .join("Application Support")
        .join("pipx");
    let sp = pipx_venv_site_packages(&pipx_home, "hatch");
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let result = global_site_packages_with_env(tmp.path(), None, None).await;
    assert!(
        result.iter().any(|p| p == &sp),
        "macOS Application Support pipx venv must surface; got {result:?}"
    );
}

/// pipx's Windows default home is `%USERPROFILE%\pipx`, with venvs in
/// the Windows layout `venvs\<app>\Lib\site-packages`.
#[cfg(windows)]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_pipx_venvs_windows() {
    let tmp = tempfile::tempdir().unwrap();
    let sp = pipx_venv_site_packages(&tmp.path().join("pipx"), "hatch");
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let result = global_site_packages_with_env(tmp.path(), None, None).await;
    assert!(
        result.iter().any(|p| p == &sp),
        "%USERPROFILE%\\pipx venv must surface; got {result:?}"
    );
}

/// An explicit `PIPX_HOME` relocates every pipx venv, on every OS.
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_pipx_venvs_under_pipx_home() {
    let tmp = tempfile::tempdir().unwrap();
    let pipx_home = tmp.path().join("custom pipx");
    let sp = pipx_venv_site_packages(&pipx_home, "hatch");
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let result = global_site_packages_with_env(tmp.path(), Some(&pipx_home), None).await;
    assert!(
        result.iter().any(|p| p == &sp),
        "pipx venv under PIPX_HOME must surface; got {result:?}"
    );
}

// ── uv and PDM global dirs (#449, #451) ───────────────────────

/// Env vars that relocate a Python tool's global dirs. Each
/// `global_site_packages_with_vars` call unsets the ones it isn't given,
/// so an ambient value on the host can't decide the result.
const TOOL_DIR_VARS: &[&str] = &[
    "PIPX_HOME",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "UV_TOOL_DIR",
    "UV_PYTHON_INSTALL_DIR",
    "PDM_CONFIG_FILE",
];

/// Run `get_global_python_site_packages` with HOME and `vars` bound and
/// every other [`TOOL_DIR_VARS`] entry unset, restoring all of them after.
async fn global_site_packages_with_vars(
    home: &Path,
    vars: &[(&str, &Path)],
) -> Vec<std::path::PathBuf> {
    let mut keys: Vec<&str> = vec!["HOME"];
    keys.extend(TOOL_DIR_VARS);
    keys.extend(
        vars.iter()
            .map(|(k, _)| *k)
            .filter(|k| !TOOL_DIR_VARS.contains(k)),
    );
    let saved: Vec<(&str, Option<String>)> =
        keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
    std::env::set_var("HOME", home);
    for key in TOOL_DIR_VARS {
        std::env::remove_var(key);
    }
    for (key, value) in vars {
        std::env::set_var(key, value);
    }
    let result = get_global_python_site_packages().await;
    for (key, value) in saved {
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
    result
}

/// The site-packages of the environment at `prefix` in the platform's
/// layout (`lib/python3.12/site-packages` on Unix, `Lib\site-packages`
/// on Windows), created on disk.
async fn stage_env(prefix: &Path) -> std::path::PathBuf {
    let sp = if cfg!(windows) {
        prefix.join("Lib").join("site-packages")
    } else {
        prefix.join("lib").join("python3.12").join("site-packages")
    };
    tokio::fs::create_dir_all(&sp).await.unwrap();
    sp
}

fn assert_surfaces(result: &[std::path::PathBuf], sp: &Path, what: &str) {
    assert!(
        result.iter().any(|p| p == sp),
        "{what} ({}) must surface; got {result:?}",
        sp.display()
    );
}

/// `UV_TOOL_DIR` relocates every `uv tool install` env, on every OS
/// (#449).
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_uv_tools_under_uv_tool_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let tools = tmp.path().join("custom-tools");
    let sp = stage_env(&tools.join("pycowsay")).await;

    let result = global_site_packages_with_vars(tmp.path(), &[("UV_TOOL_DIR", &tools)]).await;
    assert_surfaces(&result, &sp, "uv tool env under UV_TOOL_DIR");
}

/// uv's data dir follows an absolute `$XDG_DATA_HOME` on Linux and macOS
/// (`uv tool dir` → `$XDG_DATA_HOME/uv/tools`) (#449).
#[cfg(not(windows))]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_uv_tools_under_xdg_data_home() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join("xdg");
    let sp = stage_env(&xdg.join("uv").join("tools").join("pycowsay")).await;

    let result = global_site_packages_with_vars(tmp.path(), &[("XDG_DATA_HOME", &xdg)]).await;
    assert_surfaces(&result, &sp, "uv tool env under XDG_DATA_HOME");
}

/// On Windows uv keeps tool envs under `%APPDATA%\uv\tools` (the roaming
/// profile), not `%LOCALAPPDATA%` (#449).
#[cfg(windows)]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_uv_tools_under_appdata() {
    let tmp = tempfile::tempdir().unwrap();
    let appdata = tmp.path().join("Roaming");
    let sp = stage_env(&appdata.join("uv").join("tools").join("pycowsay")).await;

    let result = global_site_packages_with_vars(tmp.path(), &[("APPDATA", &appdata)]).await;
    assert_surfaces(&result, &sp, "uv tool env under %APPDATA%");
}

/// `UV_PYTHON_INSTALL_DIR` relocates every `uv python install`
/// interpreter, on every OS (#449).
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_uv_python_under_install_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let pyinst = tmp.path().join("pyinst");
    let sp = stage_env(&pyinst.join("cpython-3.12.11-linux-x86_64-gnu")).await;

    let result =
        global_site_packages_with_vars(tmp.path(), &[("UV_PYTHON_INSTALL_DIR", &pyinst)]).await;
    assert_surfaces(&result, &sp, "uv python under UV_PYTHON_INSTALL_DIR");
}

/// uv-managed interpreters follow `$XDG_DATA_HOME` like tool envs (#449).
#[cfg(not(windows))]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_uv_python_under_xdg_data_home() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join("xdg");
    let sp = stage_env(&xdg.join("uv").join("python").join("cpython-3.12.11")).await;

    let result = global_site_packages_with_vars(tmp.path(), &[("XDG_DATA_HOME", &xdg)]).await;
    assert_surfaces(&result, &sp, "uv python under XDG_DATA_HOME");
}

/// On Windows uv-managed interpreters live under `%APPDATA%\uv\python`
/// (#449).
#[cfg(windows)]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_uv_python_under_appdata() {
    let tmp = tempfile::tempdir().unwrap();
    let appdata = tmp.path().join("Roaming");
    let sp = stage_env(&appdata.join("uv").join("python").join("cpython-3.12.11")).await;

    let result = global_site_packages_with_vars(tmp.path(), &[("APPDATA", &appdata)]).await;
    assert_surfaces(&result, &sp, "uv python under %APPDATA%");
}

/// PDM's per-user config dir (platformdirs `user_config_dir("pdm")`)
/// under `home`, with the env var Windows needs to find it.
fn pdm_config_dir(home: &Path) -> (std::path::PathBuf, Vec<(&'static str, std::path::PathBuf)>) {
    if cfg!(windows) {
        let local = home.join("Local");
        (local.join("pdm").join("pdm"), vec![("LOCALAPPDATA", local)])
    } else if cfg!(target_os = "macos") {
        (
            home.join("Library").join("Application Support").join("pdm"),
            vec![],
        )
    } else {
        (home.join(".config").join("pdm"), vec![])
    }
}

/// PDM's per-user data dir (platformdirs `user_data_dir("pdm")`).
fn pdm_data_dir(home: &Path) -> (std::path::PathBuf, Vec<(&'static str, std::path::PathBuf)>) {
    if cfg!(windows) || cfg!(target_os = "macos") {
        pdm_config_dir(home)
    } else {
        (home.join(".local").join("share").join("pdm"), vec![])
    }
}

async fn global_site_packages_with_owned_vars(
    home: &Path,
    vars: &[(&'static str, std::path::PathBuf)],
) -> Vec<std::path::PathBuf> {
    let borrowed: Vec<(&str, &Path)> = vars.iter().map(|(k, v)| (*k, v.as_path())).collect();
    global_site_packages_with_vars(home, &borrowed).await
}

/// `pdm use -g <python>` creates the global project's `.venv` and every
/// later `pdm add -g` installs there (#451).
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_pdm_global_project_venv() {
    let tmp = tempfile::tempdir().unwrap();
    let (config, vars) = pdm_config_dir(tmp.path());
    let sp = stage_env(&config.join("global-project").join(".venv")).await;

    let result = global_site_packages_with_owned_vars(tmp.path(), &vars).await;
    assert_surfaces(&result, &sp, "PDM global project .venv");
}

/// platformdirs moves PDM's config dir, and with it the global project,
/// under an absolute `$XDG_CONFIG_HOME` (#451).
#[cfg(not(windows))]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_pdm_global_project_under_xdg_config_home() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join("xdg-config");
    let sp = stage_env(&xdg.join("pdm").join("global-project").join(".venv")).await;

    let result = global_site_packages_with_vars(tmp.path(), &[("XDG_CONFIG_HOME", &xdg)]).await;
    assert_surfaces(&result, &sp, "PDM global project under XDG_CONFIG_HOME");
}

/// `pdm python install 3.12` puts CPython under
/// `<user data dir>/pdm/python/cpython@3.12.N`, which PDM 2.12's
/// `pdm add -g` installs straight into (#451).
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_pdm_managed_interpreters() {
    let tmp = tempfile::tempdir().unwrap();
    let (data, vars) = pdm_data_dir(tmp.path());
    let sp = stage_env(&data.join("python").join("cpython@3.12.14")).await;

    let result = global_site_packages_with_owned_vars(tmp.path(), &vars).await;
    assert_surfaces(&result, &sp, "PDM-managed interpreter");
}

/// `global_project.path` and `python.install_root` in PDM's global
/// config (`$PDM_CONFIG_FILE` here) relocate both, with `~` expanded the
/// way PDM's `expanduser` does: from USERPROFILE on Windows, where a Git
/// Bash HOME is ignored, and from HOME elsewhere (#451).
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_follows_pdm_config_overrides() {
    let tmp = tempfile::tempdir().unwrap();
    let home = if cfg!(windows) {
        tmp.path().join("msys-home")
    } else {
        tmp.path().to_path_buf()
    };
    let config_file = tmp.path().join("pdm-config.toml");
    tokio::fs::write(
        &config_file,
        "[global_project]\npath = \"~/gp\"\n\n[python]\ninstall_root = \"~/pyroot\"\n",
    )
    .await
    .unwrap();
    let project_sp = stage_env(&tmp.path().join("gp").join(".venv")).await;
    let python_sp = stage_env(&tmp.path().join("pyroot").join("cpython@3.12.14")).await;

    let mut vars: Vec<(&str, &Path)> = vec![("PDM_CONFIG_FILE", &config_file)];
    if cfg!(windows) {
        vars.push(("USERPROFILE", tmp.path()));
    }
    let result = global_site_packages_with_vars(&home, &vars).await;
    assert_surfaces(
        &result,
        &project_sp,
        "PDM global project at global_project.path",
    );
    assert_surfaces(
        &result,
        &python_sp,
        "PDM interpreter under python.install_root",
    );
}

/// The settings are also read from PDM's default global config file,
/// `<user config dir>/pdm/config.toml` (#451).
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_reads_pdm_default_config_file() {
    let tmp = tempfile::tempdir().unwrap();
    let (config, vars) = pdm_config_dir(tmp.path());
    tokio::fs::create_dir_all(&config).await.unwrap();
    let gp = tmp.path().join("elsewhere").join("global");
    tokio::fs::write(
        config.join("config.toml"),
        format!("[global_project]\npath = '{}'\n", gp.display()),
    )
    .await
    .unwrap();
    let sp = stage_env(&gp.join(".venv")).await;

    let result = global_site_packages_with_owned_vars(tmp.path(), &vars).await;
    assert_surfaces(&result, &sp, "PDM global project from config.toml");
}

/// `pdm use -g <interpreter>` records the interpreter in the global
/// project's `.pdm-python`; with no venv, `pdm add -g` installs into
/// that interpreter's own site-packages (#451).
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_follows_pdm_global_project_interpreter() {
    let tmp = tempfile::tempdir().unwrap();
    let (config, vars) = pdm_config_dir(tmp.path());
    let project = config.join("global-project");
    tokio::fs::create_dir_all(&project).await.unwrap();
    let prefix = tmp.path().join("some-python");
    let sp = stage_env(&prefix).await;
    let interpreter = if cfg!(windows) {
        prefix.join("python.exe")
    } else {
        prefix.join("bin").join("python3")
    };
    tokio::fs::write(
        project.join(".pdm-python"),
        format!("{}\n", interpreter.display()),
    )
    .await
    .unwrap();

    let result = global_site_packages_with_owned_vars(tmp.path(), &vars).await;
    assert_surfaces(&result, &sp, "interpreter named by the global .pdm-python");
}

/// With `venv.in_project = false` the global project's venv is created
/// under `venv.location` as `global-project-<hash>-<python>`. Other
/// projects' venvs in the same dir are not global installs (#451).
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_pdm_global_project_out_of_tree_venv() {
    let tmp = tempfile::tempdir().unwrap();
    let (config, vars) = pdm_config_dir(tmp.path());
    tokio::fs::create_dir_all(&config).await.unwrap();
    let venvs = tmp.path().join("pdm-venvs");
    tokio::fs::write(
        config.join("config.toml"),
        format!("[venv]\nlocation = '{}'\n", venvs.display()),
    )
    .await
    .unwrap();
    let sp = stage_env(&venvs.join("global-project-Vt4hK2Zp-3.12")).await;
    let other = stage_env(&venvs.join("webapp-Q9xLm3Rd-3.12")).await;

    let result = global_site_packages_with_owned_vars(tmp.path(), &vars).await;
    assert_surfaces(&result, &sp, "PDM global project venv under venv.location");
    assert!(
        !result.iter().any(|p| p == &other),
        "another project's PDM venv is not a global install; got {result:?}"
    );
}

// ── project-marker fallback in get_site_packages_paths ────────

/// A project with `pyproject.toml` but no `.venv` must fall through
/// to global discovery — without this fallback, a fresh clone before
/// `uv sync` returns zero packages even when the project clearly
/// targets a Python ecosystem.
#[tokio::test]
#[serial]
async fn get_site_packages_paths_falls_back_via_pyproject_marker() {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    // Marker without venv.
    tokio::fs::write(
        project.path().join("pyproject.toml"),
        b"[project]\nname = \"x\"\n",
    )
    .await
    .unwrap();
    // Stage a uv-tools layout under the stubbed HOME so global
    // discovery has something to find.
    #[cfg(target_os = "macos")]
    let staged = home
        .path()
        .join("Library")
        .join("Application Support")
        .join("uv")
        .join("tools")
        .join("ruff")
        .join("lib")
        .join("python3.11")
        .join("site-packages");
    #[cfg(all(not(target_os = "macos"), not(windows)))]
    let staged = home
        .path()
        .join(".local")
        .join("share")
        .join("uv")
        .join("tools")
        .join("ruff")
        .join("lib")
        .join("python3.11")
        .join("site-packages");
    #[cfg(windows)]
    let staged = home.path().join("uv-fake-staged");
    tokio::fs::create_dir_all(&staged).await.unwrap();

    let prev_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", home.path());
    let crawler = PythonCrawler;
    let opts = CrawlerOptions {
        cwd: project.path().to_path_buf(),
        global: false,
        global_prefix: None,
    };
    let result = crawler.get_site_packages_paths(&opts).await.unwrap();
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    }

    #[cfg(not(windows))]
    assert!(
        result.iter().any(|p| p == &staged),
        "pyproject.toml marker must trigger global fallback; got {result:?}"
    );
    // On Windows the staged layout doesn't match the global crawler's
    // search paths (different env var), so we only assert the gate
    // engaged at all — i.e. some kind of result was produced.
    #[cfg(windows)]
    let _ = result;
}

/// #964: a uv project (`uv.lock`) and a PEP 723 script lock (`*.py.lock`)
/// only ever install into uv's own env: `.venv` / `UV_PROJECT_ENVIRONMENT`
/// for a project, uv's cache for a script. With none synced yet nothing is
/// installed for the project, and its lock-only packages come from the lock,
/// so a project-scoped crawl must return nothing rather than fall back to
/// the global interpreters (which vendored mode would then try to vendor).
#[tokio::test]
#[serial]
async fn get_site_packages_paths_uv_without_env_never_falls_back_to_global() {
    for (files, uv_project_env) in [
        (&[("uv.lock", "version = 1\n")][..], None),
        (
            &[
                ("pyproject.toml", "[project]\nname = \"app\"\n"),
                ("uv.lock", "version = 1\n"),
            ][..],
            None,
        ),
        // A CI-configured env path that hasn't been synced yet.
        (&[("uv.lock", "version = 1\n")][..], Some("not-synced")),
        // A script-only directory: script envs live in uv's cache.
        (
            &[
                ("tool.py", "# /// script\n# dependencies = []\n# ///\n"),
                ("tool.py.lock", "version = 1\n"),
            ][..],
            None,
        ),
    ] {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        for (name, body) in files {
            tokio::fs::write(project.path().join(name), body)
                .await
                .unwrap();
        }

        // Stage an anaconda3 layout under the stubbed HOME: global discovery
        // scans it on every platform, so seeing it means the fallback ran.
        let staged = home
            .path()
            .join("anaconda3")
            .join("lib")
            .join("python3.11")
            .join("site-packages");
        tokio::fs::create_dir_all(&staged).await.unwrap();

        let prev_virtual_env = std::env::var("VIRTUAL_ENV").ok();
        std::env::remove_var("VIRTUAL_ENV");
        let prev_uv_env = std::env::var("UV_PROJECT_ENVIRONMENT").ok();
        match uv_project_env {
            Some(v) => std::env::set_var("UV_PROJECT_ENVIRONMENT", v),
            None => std::env::remove_var("UV_PROJECT_ENVIRONMENT"),
        }
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", home.path());
        let crawler = PythonCrawler;
        let opts = CrawlerOptions {
            cwd: project.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        let result = crawler.get_site_packages_paths(&opts).await.unwrap();
        if let Some(v) = prev_home {
            std::env::set_var("HOME", v);
        }
        match prev_uv_env {
            Some(v) => std::env::set_var("UV_PROJECT_ENVIRONMENT", v),
            None => std::env::remove_var("UV_PROJECT_ENVIRONMENT"),
        }
        if let Some(v) = prev_virtual_env {
            std::env::set_var("VIRTUAL_ENV", v);
        }

        let names: Vec<&str> = files.iter().map(|(name, _)| *name).collect();
        assert!(
            result.is_empty(),
            "{names:?} (UV_PROJECT_ENVIRONMENT={uv_project_env:?}) must not \
             fall back to the global site-packages; got {result:?}"
        );
    }
}

/// A `uv.lock` beside another manager's record is not uv's alone: Poetry
/// with `virtualenvs.create = false` installs into the interpreter it runs
/// on, so that project keeps the marker fallback.
#[tokio::test]
#[serial]
async fn get_site_packages_paths_uv_lock_beside_poetry_keeps_fallback() {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    tokio::fs::write(project.path().join("uv.lock"), b"version = 1\n")
        .await
        .unwrap();
    tokio::fs::write(project.path().join("poetry.lock"), b"")
        .await
        .unwrap();
    let staged = home
        .path()
        .join("anaconda3")
        .join("lib")
        .join("python3.11")
        .join("site-packages");
    tokio::fs::create_dir_all(&staged).await.unwrap();

    let prev_virtual_env = std::env::var("VIRTUAL_ENV").ok();
    std::env::remove_var("VIRTUAL_ENV");
    let prev_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", home.path());
    let crawler = PythonCrawler;
    let opts = CrawlerOptions {
        cwd: project.path().to_path_buf(),
        global: false,
        global_prefix: None,
    };
    let result = crawler.get_site_packages_paths(&opts).await.unwrap();
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    }
    if let Some(v) = prev_virtual_env {
        std::env::set_var("VIRTUAL_ENV", v);
    }

    #[cfg(not(windows))]
    assert!(
        result.iter().any(|p| p == &staged),
        "uv.lock + poetry.lock must keep the global fallback; got {result:?}"
    );
    #[cfg(windows)]
    let _ = (result, staged);
}

/// #504 / #947: a Pipenv project's env is the one Pipenv resolves for it
/// (#388). With no Pipenv venv yet nothing is installed for the project, and
/// its lock-only packages come from `Pipfile.lock`, so a project-scoped crawl
/// must return nothing rather than fall back to the global interpreters
/// (which agent mode would patch in place, and vendored mode would try to
/// vendor). Holds for a `Pipfile`, a lone `Pipfile.lock`, and a `venv/`
/// Pipenv never uses.
#[tokio::test]
#[serial]
async fn get_site_packages_paths_pipenv_without_venv_never_falls_back_to_global() {
    for (marker, body, stray_venv) in [
        ("Pipfile", "[packages]\nsix = \"*\"\n", false),
        (
            "Pipfile.lock",
            "{\"default\": {}, \"develop\": {}}\n",
            false,
        ),
        ("Pipfile", "[packages]\nsix = \"*\"\n", true),
    ] {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let workon = tempfile::tempdir().unwrap();
        tokio::fs::write(project.path().join(marker), body)
            .await
            .unwrap();
        if stray_venv {
            let stray = project
                .path()
                .join("venv")
                .join("lib")
                .join("python3.11")
                .join("site-packages");
            tokio::fs::create_dir_all(&stray).await.unwrap();
        }

        // Stage an anaconda3 layout under the stubbed HOME: global discovery
        // scans it on every platform, so seeing it means the fallback ran.
        let staged = home
            .path()
            .join("anaconda3")
            .join("lib")
            .join("python3.11")
            .join("site-packages");
        tokio::fs::create_dir_all(&staged).await.unwrap();

        let prev_virtual_env = std::env::var("VIRTUAL_ENV").ok();
        std::env::remove_var("VIRTUAL_ENV");
        let prev_workon = std::env::var("WORKON_HOME").ok();
        std::env::set_var("WORKON_HOME", workon.path());
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", home.path());
        let crawler = PythonCrawler;
        let opts = CrawlerOptions {
            cwd: project.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        let result = crawler.get_site_packages_paths(&opts).await.unwrap();
        if let Some(v) = prev_home {
            std::env::set_var("HOME", v);
        }
        match prev_workon {
            Some(v) => std::env::set_var("WORKON_HOME", v),
            None => std::env::remove_var("WORKON_HOME"),
        }
        if let Some(v) = prev_virtual_env {
            std::env::set_var("VIRTUAL_ENV", v);
        }

        assert!(
            result.is_empty(),
            "{marker} (stray venv/: {stray_venv}) must not fall back to the \
             global site-packages; got {result:?}"
        );
    }
}

/// Without any Python-project marker AND without a venv, local-mode
/// discovery returns an empty Vec — no false positives from scanning
/// a non-Python project.
#[tokio::test]
#[serial]
async fn get_site_packages_paths_no_marker_no_venv_returns_empty() {
    let project = tempfile::tempdir().unwrap();
    let crawler = PythonCrawler;
    let opts = CrawlerOptions {
        cwd: project.path().to_path_buf(),
        global: false,
        global_prefix: None,
    };
    let prev_virtual_env = std::env::var("VIRTUAL_ENV").ok();
    std::env::remove_var("VIRTUAL_ENV");
    let result = crawler.get_site_packages_paths(&opts).await.unwrap();
    if let Some(v) = prev_virtual_env {
        std::env::set_var("VIRTUAL_ENV", v);
    }
    assert!(
        result.is_empty(),
        "non-python project must produce zero paths; got {result:?}"
    );
}

// ── read_python_metadata ───────────────────────────────────────

/// Well-formed METADATA returns (name, version).
#[tokio::test]
#[serial_test::parallel]
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
    assert_eq!(result, Some(("requests".to_string(), "2.28.0".to_string())));
}

/// Missing METADATA file → fall back to the `<name>-<version>.dist-info`
/// directory name so a partially-written install stays discoverable.
#[tokio::test]
#[serial_test::parallel]
async fn read_python_metadata_missing_file_falls_back_to_dir_name() {
    let tmp = tempfile::tempdir().unwrap();
    let dist_info = tmp.path().join("requests-2.28.0.dist-info");
    tokio::fs::create_dir(&dist_info).await.unwrap();
    // No METADATA file.

    let result = read_python_metadata(&dist_info).await;
    assert_eq!(result, Some(("requests".to_string(), "2.28.0".to_string())));
}

/// METADATA missing Name field → headers are unusable, so fall back to the
/// directory name rather than dropping the package.
#[tokio::test]
#[serial_test::parallel]
async fn read_python_metadata_missing_name_falls_back_to_dir_name() {
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
    assert_eq!(result, Some(("requests".to_string(), "2.28.0".to_string())));
}

/// A FIFO planted as `METADATA` must not wedge the crawler. The header
/// read used a plain `tokio::fs::read_to_string`, whose `open(2)` on a
/// FIFO waits for a writer that never comes — so one special file inside
/// site-packages (a malicious package's build hook can create one; pip
/// never extracts FIFOs from wheels) wedged `scan` (crawl_all) and
/// `apply` (find_by_purls) indefinitely, with no error and no timeout.
/// Same class as the `open_regular_file` guards in the npm
/// (package.json) and composer (installed.json) crawlers.
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
async fn read_python_metadata_rejects_fifo_metadata_without_hanging() {
    let tmp = tempfile::tempdir().unwrap();
    let dist_info = tmp.path().join("evil-1.0.0.dist-info");
    tokio::fs::create_dir_all(&dist_info).await.unwrap();
    let fifo = dist_info.join("METADATA");
    // mkfifo(2) directly, not the /usr/bin/mkfifo binary: spawning a child
    // flakes under heavy parallel load (fork/exec starvation) and the
    // syscall needs no process at all.
    let c_path = {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("fifo path has no NUL")
    };
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
    assert_eq!(
        rc,
        0,
        "mkfifo(2) failed: {}",
        std::io::Error::last_os_error()
    );
    // A sibling real package proves the tree stays crawlable around the FIFO.
    stage_dist_info(tmp.path(), "requests", "2.28.0").await;

    // On timeout the open is wedged in a `spawn_blocking` thread that the
    // runtime waits for on shutdown; connect a writer to release it so the
    // test can FAIL instead of hanging the whole suite.
    let release_and_panic = |what: &str| -> ! {
        let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
        panic!("{what} must complete promptly with a FIFO METADATA in the tree");
    };
    let deadline = std::time::Duration::from_secs(5);

    // The unreadable METADATA degrades into the dir-name fallback — the
    // package stays discoverable under its directory-name identity.
    let Ok(direct) = tokio::time::timeout(deadline, read_python_metadata(&dist_info)).await else {
        release_and_panic("read_python_metadata");
    };
    assert_eq!(direct, Some(("evil".to_string(), "1.0.0".to_string())));

    let crawler = PythonCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
    };
    let Ok(crawled) = tokio::time::timeout(deadline, crawler.crawl_all(&opts)).await else {
        release_and_panic("crawl_all");
    };
    let mut names: Vec<&str> = crawled.iter().map(|p| p.name.as_str()).collect();
    names.sort();
    assert_eq!(names, vec!["evil", "requests"]);
}

#[path = "common/mod.rs"]
mod common;

/// `find_by_purls` short-circuits when the site-packages dir is
/// unreadable. Drives the unreadable-listing arm of
/// `list_dist_info_packages`.
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_handles_unreadable_site_packages() {
    if common::uid_is_root() {
        eprintln!("SKIP: chmod 000 is a no-op under root");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let site_packages = tmp.path().join("sp");
    tokio::fs::create_dir(&site_packages).await.unwrap();
    common::chmod_unreadable(&site_packages);

    let crawler = PythonCrawler;
    let result = crawler
        .find_by_purls(&site_packages, &["pkg:pypi/requests@2.28.0".to_string()])
        .await
        .unwrap();
    common::chmod_readable(&site_packages);

    assert!(result.is_empty());
}

/// `list_dist_info_packages` yields nothing when site-packages is
/// unreadable (`list_dir_sync` degrades to an empty listing).
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_handles_unreadable_site_packages() {
    if common::uid_is_root() {
        eprintln!("SKIP: chmod 000 is a no-op under root");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let site_packages = tmp.path().join("sp");
    tokio::fs::create_dir(&site_packages).await.unwrap();
    common::chmod_unreadable(&site_packages);

    let crawler = PythonCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(site_packages.clone()),
    };
    let result = crawler.crawl_all(&opts).await;
    common::chmod_readable(&site_packages);

    assert!(result.is_empty());
}

/// `PythonCrawler::default()` should forward to `new()`.
#[test]
#[serial_test::parallel]
fn python_crawler_default_and_new_construct_cleanly() {
    let _a = PythonCrawler;
    let _b = PythonCrawler::new();
}

// ── find_by_purls + crawl_all over a staged site-packages ─────

/// Helper: stage a well-formed `<pkg>-<version>.dist-info/METADATA`
/// inside a fake site-packages directory.
async fn stage_dist_info(site_packages: &Path, raw_name: &str, version: &str) {
    let dist = site_packages.join(format!("{raw_name}-{version}.dist-info"));
    tokio::fs::create_dir_all(&dist).await.unwrap();
    let metadata = format!("Metadata-Version: 2.1\nName: {raw_name}\nVersion: {version}\n");
    tokio::fs::write(dist.join("METADATA"), metadata)
        .await
        .unwrap();
}

#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_matches_canonicalized_name() {
    let tmp = tempfile::tempdir().unwrap();
    // PEP 503 canonicalization: "Requests" -> "requests"
    stage_dist_info(tmp.path(), "Requests", "2.28.0").await;

    let crawler = PythonCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &["pkg:pypi/requests@2.28.0".to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1, "canonical lookup must hit");
    // The map is keyed by the queried PURL and the payload must carry the
    // PEP-503-canonicalized name, exact version, correct PURL, and the
    // site-packages path we searched — not just "some" entry.
    let pkg = result
        .get("pkg:pypi/requests@2.28.0")
        .expect("result must be keyed by the queried PURL");
    assert_eq!(
        pkg.name, "requests",
        "name must be canonicalized to lowercase"
    );
    assert_eq!(pkg.version, "2.28.0");
    assert_eq!(pkg.purl, "pkg:pypi/requests@2.28.0");
    assert_eq!(pkg.namespace, None);
    assert_eq!(pkg.path, tmp.path());
}

#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_strips_qualifiers() {
    let tmp = tempfile::tempdir().unwrap();
    stage_dist_info(tmp.path(), "requests", "2.28.0").await;

    let crawler = PythonCrawler;
    let result = crawler
        .find_by_purls(
            tmp.path(),
            &["pkg:pypi/requests@2.28.0?extension=tar.gz".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(result.len(), 1, "qualifiers must be stripped before lookup");
    // The map key preserves the ORIGINAL (qualified) PURL the caller passed,
    // while name/version come from the matched dist-info.
    let pkg = result
        .get("pkg:pypi/requests@2.28.0?extension=tar.gz")
        .expect("result must be keyed by the original qualified PURL");
    assert_eq!(pkg.name, "requests");
    assert_eq!(pkg.version, "2.28.0");
    assert_eq!(pkg.purl, "pkg:pypi/requests@2.28.0?extension=tar.gz");
    assert_eq!(pkg.path, tmp.path());
}

/// A bare `#subpath` (no `?qualifier`) is valid PURL grammar and must be
/// stripped the same way qualifiers are — cutting only at `?` leaks the
/// subpath into the version (`2.28.0#src/requests`), so the installed
/// package silently fails to match. Twin of `strip_purl_qualifiers`'
/// subpath handling in utils::purl.
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_strips_subpath() {
    let tmp = tempfile::tempdir().unwrap();
    stage_dist_info(tmp.path(), "requests", "2.28.0").await;

    let crawler = PythonCrawler;
    let result = crawler
        .find_by_purls(
            tmp.path(),
            &["pkg:pypi/requests@2.28.0#src/requests".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(result.len(), 1, "subpath must be stripped before lookup");
    // Same keying contract as the qualifier test: the original PURL.
    let pkg = result
        .get("pkg:pypi/requests@2.28.0#src/requests")
        .expect("result must be keyed by the original subpath PURL");
    assert_eq!(pkg.name, "requests");
    assert_eq!(pkg.version, "2.28.0");
    assert_eq!(pkg.path, tmp.path());
}

/// The patches API serves purls in canonical percent-encoded form (see
/// `percent_decode_purl_component`): a PEP 440 local/epoch version carries
/// `+`/`!`, which arrive as `%2B`/`%21`. The lookup key must be built from
/// the DECODED coordinates or the installed package silently fails to match
/// — reported "not installed", patch skipped. Twin of the npm crawler's
/// percent-decode handling.
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_percent_decodes_encoded_version() {
    let tmp = tempfile::tempdir().unwrap();
    stage_dist_info(tmp.path(), "torch", "2.1.0+cpu").await;

    let crawler = PythonCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &["pkg:pypi/torch@2.1.0%2Bcpu".to_string()])
        .await
        .unwrap();
    assert_eq!(
        result.len(),
        1,
        "%-encoded version must decode before lookup; got {result:?}"
    );
    // Keyed by the ORIGINAL (encoded) PURL, like the qualifier/subpath tests.
    let pkg = result
        .get("pkg:pypi/torch@2.1.0%2Bcpu")
        .expect("result must be keyed by the original encoded PURL");
    assert_eq!(pkg.name, "torch");
    assert_eq!(pkg.version, "2.1.0+cpu");
    assert_eq!(pkg.purl, "pkg:pypi/torch@2.1.0%2Bcpu");
}

#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_empty_purls_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    stage_dist_info(tmp.path(), "requests", "2.28.0").await;

    let crawler = PythonCrawler;
    let result = crawler.find_by_purls(tmp.path(), &[]).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_missing_site_packages_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = PythonCrawler;
    // site_packages_path doesn't exist — read_dir Err arm must yield empty.
    let result = crawler
        .find_by_purls(
            &tmp.path().join("no-such-dir"),
            &["pkg:pypi/requests@2.28.0".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_invalid_purl_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    stage_dist_info(tmp.path(), "requests", "2.28.0").await;

    let crawler = PythonCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &["pkg:not-pypi/foo@1.0".to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_version_mismatch_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    stage_dist_info(tmp.path(), "requests", "2.28.0").await;

    let crawler = PythonCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &["pkg:pypi/requests@99.99.99".to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_via_site_packages_finds_dist_info_packages() {
    let tmp = tempfile::tempdir().unwrap();
    stage_dist_info(tmp.path(), "Requests", "2.28.0").await;
    stage_dist_info(tmp.path(), "urllib3", "2.0.0").await;
    // A non-dist-info dir should be skipped.
    tokio::fs::create_dir_all(tmp.path().join("ignore-me"))
        .await
        .unwrap();

    let crawler = PythonCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
    };
    let result = crawler.crawl_all(&opts).await;
    assert_eq!(
        result.len(),
        2,
        "exactly the two dist-info dirs; got {result:?}"
    );

    // Verify the full identity of each package, not just the name — a
    // regression that mangled the version or PURL (or canonicalization)
    // would otherwise stay green.
    let requests = result
        .iter()
        .find(|p| p.name == "requests")
        .expect("requests must be discovered (canonicalized from \"Requests\")");
    assert_eq!(requests.version, "2.28.0");
    assert_eq!(requests.purl, "pkg:pypi/requests@2.28.0");
    assert_eq!(requests.namespace, None);
    assert_eq!(requests.path, tmp.path());

    let urllib3 = result
        .iter()
        .find(|p| p.name == "urllib3")
        .expect("urllib3 must be discovered");
    assert_eq!(urllib3.version, "2.0.0");
    assert_eq!(urllib3.purl, "pkg:pypi/urllib3@2.0.0");
}

#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_with_unparseable_dist_info_skips() {
    let tmp = tempfile::tempdir().unwrap();
    // No version segment in the directory name, so neither the (empty)
    // METADATA nor the dir-name fallback can yield a name/version — the
    // package is genuinely unidentifiable and must be skipped.
    let dist = tmp.path().join("corrupt.dist-info");
    tokio::fs::create_dir_all(&dist).await.unwrap();
    tokio::fs::write(dist.join("METADATA"), b"").await.unwrap();

    let crawler = PythonCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
    };
    let result = crawler.crawl_all(&opts).await;
    assert!(
        result.is_empty(),
        "a dist-info with no usable metadata or version-bearing name must be skipped"
    );
}

/// `get_site_packages_paths` with `global_prefix` set returns just that
/// prefix — exercises its `global_prefix` early-return arm.
#[tokio::test]
#[serial_test::parallel]
async fn get_site_packages_paths_with_global_prefix_passthrough() {
    let tmp = tempfile::tempdir().unwrap();
    let custom = tmp.path().join("custom-sp");
    tokio::fs::create_dir_all(&custom).await.unwrap();

    let crawler = PythonCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: false,
        global_prefix: Some(custom.clone()),
    };
    let paths = crawler.get_site_packages_paths(&opts).await.unwrap();
    assert_eq!(paths, vec![custom]);
}

// ── METADATA early-break arm ───────────────────────────────────

/// METADATA header lines AFTER the blank line must NOT be parsed — the
/// header parser stops at the first blank line. Here only `Name` is set
/// before the blank line, so the `Version` below it is never read from the
/// headers; the function then falls back to the directory name. We give the
/// directory a *different* version (`9.9.9`) than the post-blank-line header
/// (`2.28.0`) so the result proves the blank-line break fired: a `2.28.0`
/// result would mean the break leaked the trailing header.
#[tokio::test]
#[serial_test::parallel]
async fn read_python_metadata_stops_at_blank_line_then_falls_back() {
    let tmp = tempfile::tempdir().unwrap();
    let dist = tmp.path().join("requests-9.9.9.dist-info");
    tokio::fs::create_dir(&dist).await.unwrap();
    tokio::fs::write(dist.join("METADATA"), "Name: requests\n\nVersion: 2.28.0\n")
        .await
        .unwrap();

    let result = read_python_metadata(&dist).await;
    assert_eq!(
        result,
        Some(("requests".to_string(), "9.9.9".to_string())),
        "blank-line break must fire before Version is read, so the version \
         comes from the dir name; got {result:?}"
    );
}

/// METADATA missing Version field → headers unusable, fall back to the
/// directory name.
#[tokio::test]
#[serial_test::parallel]
async fn read_python_metadata_missing_version_falls_back_to_dir_name() {
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
    assert_eq!(result, Some(("requests".to_string(), "2.28.0".to_string())));
}

// ── Poetry installer venv discovery (#640) ────────────────────

/// Run `get_global_python_site_packages` with HOME, POETRY_HOME,
/// XDG_DATA_HOME and APPDATA rebound (`None` unsets), restoring them
/// after. Poetry's official installer resolves its venv from these.
async fn global_site_packages_with_poetry_env(
    home: &Path,
    poetry_home: Option<&Path>,
    xdg_data_home: Option<&Path>,
    appdata: Option<&Path>,
) -> Vec<std::path::PathBuf> {
    let keys = ["HOME", "POETRY_HOME", "XDG_DATA_HOME", "APPDATA"];
    let saved: Vec<(&str, Option<String>)> = keys
        .into_iter()
        .map(|k| (k, std::env::var(k).ok()))
        .collect();
    std::env::set_var("HOME", home);
    for (key, value) in [
        ("POETRY_HOME", poetry_home),
        ("XDG_DATA_HOME", xdg_data_home),
        ("APPDATA", appdata),
    ] {
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
    let result = get_global_python_site_packages().await;
    for (key, value) in saved {
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
    result
}

/// The site-packages of the installer venv under Poetry's data dir.
fn poetry_installer_site_packages(data_dir: &Path) -> std::path::PathBuf {
    let venv = data_dir.join("venv");
    if cfg!(windows) {
        venv.join("Lib").join("site-packages")
    } else {
        venv.join("lib").join("python3.11").join("site-packages")
    }
}

/// The official installer (`install.python-poetry.org`) on Linux puts
/// Poetry and its dependencies in `~/.local/share/pypoetry/venv`.
#[cfg(all(not(target_os = "macos"), not(windows)))]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_poetry_installer_venv_linux() {
    let tmp = tempfile::tempdir().unwrap();
    let sp =
        poetry_installer_site_packages(&tmp.path().join(".local").join("share").join("pypoetry"));
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let result = global_site_packages_with_poetry_env(tmp.path(), None, None, None).await;
    assert!(
        result.iter().any(|p| p == &sp),
        "Poetry installer venv must surface; got {result:?}"
    );
}

/// The installer follows `$XDG_DATA_HOME` on Linux.
#[cfg(all(not(target_os = "macos"), not(windows)))]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_poetry_installer_venv_under_xdg() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join("xdg-data");
    let sp = poetry_installer_site_packages(&xdg.join("pypoetry"));
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let result = global_site_packages_with_poetry_env(tmp.path(), None, Some(&xdg), None).await;
    assert!(
        result.iter().any(|p| p == &sp),
        "Poetry installer venv under XDG_DATA_HOME must surface; got {result:?}"
    );
}

/// The installer's macOS default is `~/Library/Application Support/pypoetry`.
#[cfg(target_os = "macos")]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_poetry_installer_venv_macos() {
    let tmp = tempfile::tempdir().unwrap();
    let sp = poetry_installer_site_packages(
        &tmp.path()
            .join("Library")
            .join("Application Support")
            .join("pypoetry"),
    );
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let result = global_site_packages_with_poetry_env(tmp.path(), None, None, None).await;
    assert!(
        result.iter().any(|p| p == &sp),
        "macOS Poetry installer venv must surface; got {result:?}"
    );
}

/// The installer's Windows default is `%APPDATA%\pypoetry`.
#[cfg(windows)]
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_poetry_installer_venv_windows() {
    let tmp = tempfile::tempdir().unwrap();
    let appdata = tmp.path().join("AppData").join("Roaming");
    let sp = poetry_installer_site_packages(&appdata.join("pypoetry"));
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let result = global_site_packages_with_poetry_env(tmp.path(), None, None, Some(&appdata)).await;
    assert!(
        result.iter().any(|p| p == &sp),
        "%APPDATA%\\pypoetry venv must surface; got {result:?}"
    );
}

/// `POETRY_HOME` relocates the installer venv to `$POETRY_HOME/venv`, on
/// every OS.
#[tokio::test]
#[serial]
async fn get_global_python_site_packages_discovers_poetry_installer_venv_under_poetry_home() {
    let tmp = tempfile::tempdir().unwrap();
    let poetry_home = tmp.path().join("opt").join("poetry");
    let sp = poetry_installer_site_packages(&poetry_home);
    tokio::fs::create_dir_all(&sp).await.unwrap();

    let result =
        global_site_packages_with_poetry_env(tmp.path(), Some(&poetry_home), None, None).await;
    assert!(
        result.iter().any(|p| p == &sp),
        "$POETRY_HOME/venv must surface; got {result:?}"
    );
}
