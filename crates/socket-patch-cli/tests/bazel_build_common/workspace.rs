//! The workspace copy of a cell: fixture copy-in, the shared probe rule,
//! the downloader config, and the rules for `MODULE.bazel.lock`.
//!
//! Lock rules (probes L6.c, L3.c, T7, C16). Bazel owns `MODULE.bazel.lock`
//! and a live server keeps its own view of it, so a test never just
//! writes the file:
//!
//! 1. [`Cell::write_module_lock`] shuts the server down first. On 7.2.0 to
//!    8.7.0 and 9.0.2 a live server that just rewrote the lock reverts an
//!    outside edit at its next `info` or `shutdown`.
//! 2. A lock snapshot is never restored onto an output base that already
//!    evaluated newer inputs (8.6 to 9.2 then hide stale facts): close the
//!    cell, open a new one and build its tree again
//!    ([`Cell::copy_fixture`], or [`Cell::copy_tree_from`] a saved copy).
//! 3. One tree yields three different locks (`query`; `build` / `cquery` /
//!    `fetch`; the `mod` commands). An oracle `mod` command therefore runs
//!    through [`Cell::mod_oracle`] (`--lockfile_mode=off`), and the
//!    stale-lock oracle is [`Cell::error_mode_build`], never `bazel mod
//!    deps --lockfile_mode=error` (exit 2 on a healthy lock made by builds).
//! 4. The repository cache lies outside the workspace copy (asserted when
//!    the scratch root is made).
//! 5. A cell that expects a fetch to fail runs one command through
//!    [`Cell::failing_fetch`] (no downloader retries): a failed repository
//!    fetch ends the build even under `--keep_going`.
//!
//! [`Cell::baseline`] runs every command class a scenario later runs
//! before the test takes its snapshot, so the lock Bazel leaves is the one
//! later steps reproduce. Lock equality after a rollback is asserted only
//! after [`Cell::shutdown`] and a second [`Cell::baseline`].

use std::path::{Path, PathBuf};

use super::env;
use super::fixture_server::FixtureServer;
use super::invoke::{Options, Run};
use super::server::Cell;
use crate::common::fs_tree;

/// The name fixtures load the shared probe rule by:
/// `load("//:probe.bzl", "socket_probe")`.
pub const PROBE_BZL: &str = "probe.bzl";

/// The file Bazel owns in a workspace root.
pub const MODULE_LOCK: &str = "MODULE.bazel.lock";

/// `tests/fixtures/bazel`.
pub fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bazel")
}

/// The downloader config for a fixture server on `port`, from the
/// committed template: every non-loopback URL is rewritten to the server
/// and nothing else is reachable.
pub fn render_downloader_config(port: u16) -> String {
    let template = fixtures_root().join("common/downloader.cfg.tmpl");
    let text = std::fs::read_to_string(&template)
        .unwrap_or_else(|e| panic!("read {}: {e}", template.display()));
    assert!(
        text.contains("<port>"),
        "{} has no <port>",
        template.display()
    );
    text.replace("<port>", &port.to_string())
}

impl Cell {
    /// Copy the fixture workspace `rel` (`core/bzlmod/e9`) into the cell,
    /// byte for byte, then install the shared probe rule.
    pub fn copy_fixture(&self, rel: &str) {
        let src = fixtures_root().join(rel);
        assert!(src.is_dir(), "{}: no fixture {}", self.test, src.display());
        self.copy_tree_from(&src);
        self.install_probe_rule();
    }

    /// Copy `src` over the workspace copy. For a tree that holds a
    /// `MODULE.bazel.lock` this is a lock write: the server is shut down
    /// first (lock rule 1).
    pub fn copy_tree_from(&self, src: &Path) {
        if src.join(MODULE_LOCK).exists() {
            self.shutdown();
        }
        fs_tree::copy_tree(src, &self.scratch.workspace);
    }

    /// Write `fixtures/bazel/common/probe.bzl` to the workspace root. A
    /// fixture that ships its own file of that name is a mistake: the
    /// proof ladder would then test a rule nobody reviewed.
    pub fn install_probe_rule(&self) {
        let dest = self.scratch.workspace.join(PROBE_BZL);
        assert!(
            !dest.exists(),
            "{}: the fixture carries its own {PROBE_BZL}",
            self.test
        );
        std::fs::copy(fixtures_root().join("common").join(PROBE_BZL), &dest)
            .unwrap_or_else(|e| panic!("install {}: {e}", dest.display()));
    }

    /// Write a workspace file. `MODULE.bazel.lock` goes through
    /// [`Cell::write_module_lock`].
    pub fn write(&self, rel: &str, bytes: impl AsRef<[u8]>) {
        assert!(
            Path::new(rel)
                .file_name()
                .is_some_and(|name| name != MODULE_LOCK),
            "{}: write {MODULE_LOCK} with write_module_lock",
            self.test
        );
        let path = self.scratch.workspace.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    }

    /// Replace the root `MODULE.bazel.lock` (a fixture lock, a hand edit),
    /// after `bazel shutdown` (lock rule 1).
    pub fn write_module_lock(&self, bytes: &[u8]) {
        self.shutdown();
        let path = self.scratch.workspace.join(MODULE_LOCK);
        std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    }

    /// The root `MODULE.bazel.lock` as Bazel left it; `None` when the
    /// line or the dependency system writes none.
    pub fn module_lock(&self) -> Option<Vec<u8>> {
        std::fs::read(self.scratch.workspace.join(MODULE_LOCK)).ok()
    }

    /// Route every download of this cell to `server`: write the downloader
    /// config beside the workspace copy and pass it on every command. With
    /// [`env::OFFLINE`] set this is the strict-404 phase: the proxies also
    /// point at a closed port, so only the fixture server is reachable, and
    /// the test asserts with [`FixtureServer::assert_not_requested`] that
    /// the package's own URL was never asked for. (`block *` on a warm
    /// cache is not an offline recipe before Bazel 9.3.0: it fails at the
    /// first archive without a `type`.)
    pub fn use_fixture_server(&mut self, server: &FixtureServer) {
        let config = self.scratch.root.join("downloader.cfg");
        std::fs::write(&config, render_downloader_config(server.port()))
            .unwrap_or_else(|e| panic!("write {}: {e}", config.display()));
        self.options.downloader_config = Some(config);
        self.options.closed_proxies = env::offline();
    }

    /// An oracle `bazel mod <args>` (`graph`, `show_repo`): with
    /// `--lockfile_mode=off`, so asking never rewrites the lock under test
    /// (lock rule 3). `None` on a line without the `mod` command (it ran
    /// on 6.6.0 and later; older 6.x releases are not pinned).
    pub fn mod_oracle(&self, args: &[&str]) -> Option<Run> {
        if !self.bazel.version.at_least(6, 6, 0) {
            return None;
        }
        let options = Options {
            lockfile_mode: "off",
            ..self.options.clone()
        };
        Some(self.bazel_with(&options, "mod", args))
    }

    /// The stale-lock oracle: `bazel build --lockfile_mode=error <targets>`
    /// of targets that consume the hub (lock rule 3).
    pub fn error_mode_build(&self, targets: &[&str]) -> Run {
        let options = Options {
            lockfile_mode: "error",
            ..self.options.clone()
        };
        self.bazel_with(&options, "build", targets)
    }

    /// The one Bazel command of a cell that expects a repository fetch to
    /// fail, with downloader retries off (lock rule 5). The caller asserts
    /// the failure and its text.
    pub fn failing_fetch(&self, command: &str, args: &[&str]) -> Run {
        let options = Options {
            no_retries: true,
            ..self.options.clone()
        };
        self.bazel_with(&options, command, args)
    }

    /// Step 1 of a scenario: build `targets`, and for a fixture with a
    /// committed lock also `bazel mod deps --lockfile_mode=update`, so
    /// every command class the test later runs has already written what it
    /// writes and the WORKS-AFTER command is idempotent. The test takes
    /// its snapshot after this.
    pub fn baseline(&self, targets: &[&str], lock_fixture: bool) {
        self.bazel_ok("build", targets);
        if lock_fixture && self.bazel.version.at_least(6, 6, 0) {
            let options = Options {
                lockfile_mode: "update",
                ..self.options.clone()
            };
            let run = self.bazel_with(&options, "mod", &["deps"]);
            assert!(run.ok(), "{}: {}", self.test, run.dump());
        }
    }
}
