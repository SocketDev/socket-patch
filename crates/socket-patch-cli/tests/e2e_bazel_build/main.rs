#![cfg(unix)]
//! `socket-patch` in a Bazel workspace, on a real Bazel.
//!
//! Each test copies a fixture workspace from `tests/fixtures/bazel/`, builds
//! it with the Bazel release it is given, runs the built `socket-patch`
//! binary in it the way a user does, and builds again. What a test asserts,
//! it reads from what Bazel built: the line `bazel run //:consumer` prints.
//!
//! Those tests are `#[ignore]`d: they need a Bazel release and the network
//! (the Bazel registry, the ruleset archives and the language toolchain),
//! and a host that does not answer fails them. The package under test and
//! every Socket host are loopback stand-ins.
//! `.github/workflows/bazel-compatibility.yml` runs them, one leg per Bazel
//! release, for the ecosystem of the workflow that calls it
//! (`bazel-go.yml`). Locally:
//!
//! ```sh
//! export "$(scripts/install-bazel.sh 9.3.2 "$HOME/.cache/socket-patch-bazel")"
//! cargo test -p socket-patch-cli --test e2e_bazel_build -- --ignored go:: --nocapture
//! ```
//!
//! The other tests of the target need neither and run with a plain
//! `cargo test`: the checks of the harness and of the fixtures, and in
//! `go.rs` the tests that run `socket-patch` in a checkout no Bazel builds
//! and read the files it wrote.
//!
//! An `#[ignore]`d test takes its release from the Bazel it runs: the one
//! `SOCKET_PATCH_BAZEL_E2E_BAZEL` names, else `bazel` on `PATH` (a bazelisk
//! there picks its release as it does anywhere, from `USE_BAZEL_VERSION`).
//! With no Bazel it prints `SKIP <why>` and passes; with
//! `SOCKET_PATCH_BAZEL_E2E_REQUIRED=1` (CI) it fails instead. `harness.rs`
//! lists the other variables.
//!
//! Every flow whose build is patched also holds `socket-patch` to the VEX
//! document it writes about that build. The command of the mode writes one
//! for its own run (`--vex`), in the checkout Bazel has built in; `vex`
//! writes one before the patched build and after it, and one with
//! `--no-verify`; after the undo `vex` writes none and removes the last;
//! and the command and `vex` write the same two in a checkout with the
//! same files that no Bazel has built in. Each document is one statement:
//! the package under test is `not_affected`, through the patch of this
//! run. The documents of a flow are also held to each other: they differ
//! in their id, their times and the mark of `--no-verify`, and in no other
//! string. Every form is told one product; `vex` without one, as a user
//! types it, runs once after the patched build, where it names the project
//! of the checkout's own `package.json` or `go.mod`, or writes no document
//! where the fixture has no such file.
//!
//! `socket-patch` reads `MODULE.bazel` for the calls that hand a lock to a
//! ruleset, and writes no statement for a patch that such a ruleset does
//! not build: one in the copy a package manager installed, or a PyPI or
//! RubyGems one in a copy committed under `.socket/vendor`. Two flows hold
//! it to that (`npm::agent_npm_translate_lock`,
//! `pypi::vendored_pip_parse`): the build is not the patched one, no form
//! of `vex` writes a document, each names the call and the file Bazel
//! builds from, and after what the warning says to do the build is patched
//! and the document is there. So these tests say for which workspaces the
//! document and the build agree, and for which there is no document.
//!
//! A flow is one `#[ignore]`d test in its ecosystem's module, and its
//! fixture is one directory of files that every release builds beside one
//! `MODULE.bazel` per era of rulesets; the fixture's table in the test code
//! says which releases build which era (`harness::Fixture`). So another
//! Bazel release is one line per platform in `scripts/bazel-pins.txt` and
//! one line of the ecosystem's workflow; another era is one `MODULE.bazel`
//! and one line of the table; another ecosystem is its module, its fixture
//! and a workflow of its own, which calls `bazel-compatibility.yml` as
//! `bazel-go.yml` does. `harness.rs` holds what the flows share: the
//! stand-in server, the steps of a flow, the downloader config for a
//! ruleset that fetches with Bazel's own downloader, and the environment
//! of every Bazel child.

#[path = "../common/envelope.rs"]
mod envelope;
#[path = "../common/fs_tree.rs"]
mod fs_tree;
// Also the home of `hermetic`, the environment every child is spawned with.
#[path = "../hosted_memory_common/mod.rs"]
mod hosted_memory_common;

mod go;
mod harness;
mod npm;
mod pypi;
mod ruby;
