//! Coverage-gap integration tests for `crawlers::composer_crawler`'s
//! global-home discovery chain: the fall-through when `COMPOSER_HOME` names
//! a nonexistent directory, and the `composer global config home` shell-out
//! success branches (driven by a fake `composer` shim on PATH — the real
//! production path on any machine with composer installed and COMPOSER_HOME
//! unset). Companion to `crawler_composer_e2e.rs`, whose serial env
//! stubbing conventions these tests mirror.

use std::path::Path;

use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::ComposerCrawler;

fn global_options_at(root: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: true,
        global_prefix: None,
    }
}

/// Saves an env var's prior value on construction and restores it on drop,
/// so a panicking assert can't leak a stubbed COMPOSER_HOME/HOME/PATH into
/// later serial tests in this binary.
struct EnvVarGuard {
    key: &'static str,
    prev: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &std::ffi::OsStr) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, value);
        EnvVarGuard { key, prev }
    }

    fn remove(key: &'static str) -> Self {
        let prev = std::env::var_os(key);
        std::env::remove_var(key);
        EnvVarGuard { key, prev }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

/// A set-but-BROKEN `COMPOSER_HOME` (naming a nonexistent directory) must
/// fall through the discovery chain — composer CLI, then platform defaults —
/// rather than yield the bogus path or bail empty.
/// `get_vendor_paths_global_via_composer_home_env` in the companion suite
/// pins the env var's success arm; this pins the failure arm's ordering.
#[tokio::test]
#[serial_test::serial]
async fn get_vendor_paths_global_nonexistent_composer_home_falls_back() {
    let tmp = tempfile::tempdir().unwrap();
    let dot_composer_vendor = tmp.path().join(".composer").join("vendor");
    tokio::fs::create_dir_all(&dot_composer_vendor)
        .await
        .unwrap();
    // PATH stubbed to a binary-free tempdir so `composer global config
    // home` on a machine with composer installed can't short-circuit the
    // fallback chain.
    let empty_path = tempfile::tempdir().unwrap();
    let bogus_home = tmp.path().join("does-not-exist");

    let _composer_home = EnvVarGuard::set("COMPOSER_HOME", bogus_home.as_os_str());
    let _home = EnvVarGuard::set("HOME", tmp.path().as_os_str());
    let _path = EnvVarGuard::set("PATH", empty_path.path().as_os_str());

    let crawler = ComposerCrawler;
    let paths = crawler
        .get_vendor_paths(&global_options_at(tmp.path()))
        .await
        .unwrap();

    assert_eq!(
        paths,
        vec![dot_composer_vendor],
        "a set-but-nonexistent COMPOSER_HOME must fall through to the \
         HOME/.composer platform default, not yield the bogus path or empty"
    );
}

/// Write an executable `composer` shim into `dir` that ignores its
/// arguments and echoes `echo_path` — a stand-in for `composer global
/// config home`. The shebang names /bin/sh by absolute path, so the script
/// executes even with PATH stripped down to the shim dir alone.
#[cfg(unix)]
fn write_composer_shim(dir: &Path, echo_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let shim = dir.join("composer");
    std::fs::write(&shim, format!("#!/bin/sh\necho '{}'\n", echo_path.display())).unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// `composer global config home` answering an EXISTING directory is the
/// production path on any machine with composer installed and
/// COMPOSER_HOME unset: the CLI's answer must win over the HOME/.composer
/// platform default.
#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn get_vendor_paths_global_composer_cli_answer_wins() {
    let tmp = tempfile::tempdir().unwrap();
    // What the fake CLI reports as the composer home; its vendor/ exists.
    let cli_home = tmp.path().join("cli-home");
    let cli_vendor = cli_home.join("vendor");
    tokio::fs::create_dir_all(&cli_vendor).await.unwrap();
    // HOME tripwire: if the CLI branch were skipped, discovery would land
    // here instead and the equality assert below would catch it.
    let home = tempfile::tempdir().unwrap();
    tokio::fs::create_dir_all(home.path().join(".composer").join("vendor"))
        .await
        .unwrap();
    let shim_dir = tempfile::tempdir().unwrap();
    write_composer_shim(shim_dir.path(), &cli_home);

    let _composer_home = EnvVarGuard::remove("COMPOSER_HOME");
    let _home = EnvVarGuard::set("HOME", home.path().as_os_str());
    let _path = EnvVarGuard::set("PATH", shim_dir.path().as_os_str());

    let crawler = ComposerCrawler;
    let paths = crawler
        .get_vendor_paths(&global_options_at(tmp.path()))
        .await
        .unwrap();

    assert_eq!(
        paths,
        vec![cli_vendor],
        "the composer CLI's home answer must win over the HOME/.composer fallback"
    );
}

/// The CLI answering a NONEXISTENT directory must fall through to the
/// platform defaults rather than yield the bogus path or bail empty.
#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn get_vendor_paths_global_composer_cli_nonexistent_home_falls_back() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let dot_composer_vendor = home.path().join(".composer").join("vendor");
    tokio::fs::create_dir_all(&dot_composer_vendor)
        .await
        .unwrap();
    // Each shim lives in its own tempdir; nothing rewrites a shim in place.
    let shim_dir = tempfile::tempdir().unwrap();
    write_composer_shim(shim_dir.path(), &tmp.path().join("cli-home-missing"));

    let _composer_home = EnvVarGuard::remove("COMPOSER_HOME");
    let _home = EnvVarGuard::set("HOME", home.path().as_os_str());
    let _path = EnvVarGuard::set("PATH", shim_dir.path().as_os_str());

    let crawler = ComposerCrawler;
    let paths = crawler
        .get_vendor_paths(&global_options_at(tmp.path()))
        .await
        .unwrap();

    assert_eq!(
        paths,
        vec![dot_composer_vendor],
        "a CLI answer naming a nonexistent home must fall through to HOME/.composer"
    );
}
