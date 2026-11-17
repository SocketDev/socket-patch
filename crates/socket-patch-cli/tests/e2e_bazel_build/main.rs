#![cfg(unix)]
//! `socket-patch` in a Bazel workspace, on a real Bazel.
//!
//! Each test copies a fixture workspace from `tests/fixtures/bazel/`, builds
//! it with a pinned Bazel release, runs the built `socket-patch` binary in
//! it the way a user does, and builds again. What a test asserts, it reads
//! from what Bazel built: the line `bazel run //:consumer` prints.
//!
//! The tests are `#[ignore]`d: they need a Bazel release and the network
//! (the Bazel registry, the ruleset archives and the language toolchain),
//! and a host that does not answer fails them. The package under test and
//! every Socket host are loopback stand-ins.
//! `.github/workflows/bazel-compatibility.yml` runs them, one leg per Bazel
//! release and ecosystem. Locally:
//!
//! ```sh
//! eval "$(scripts/install-bazel.sh 9.3.2 "$HOME/.cache/socket-patch-bazel")"
//! export SOCKET_PATCH_BAZEL_E2E_BAZEL
//! cargo test -p socket-patch-cli --test e2e_bazel_build -- --ignored go::b9_ --nocapture
//! ```
//!
//! With `SOCKET_PATCH_BAZEL_E2E_BAZEL` unset the tests run `bazel` from
//! `PATH` with `USE_BAZEL_VERSION` set to the test's release, so a bazelisk
//! picks it. A test whose Bazel is missing or is another release prints
//! `SKIP <why>` and passes; with `SOCKET_PATCH_BAZEL_E2E_REQUIRED=1` (CI) it
//! fails instead. `harness.rs` lists the other variables.
//!
//! To add a test of a flow that is here: one fixture directory and one
//! test function in the ecosystem's module. A test's name starts with its
//! Bazel major (`b9_`), which is how a workflow leg selects its own, so a
//! major has one release here. A new Bazel major adds its lines in
//! `scripts/bazel-pins.txt` and one line in the workflow's matrix; a new
//! ecosystem adds its module and one matrix line per release.

#[path = "../common/envelope.rs"]
mod envelope;
#[path = "../common/fs_tree.rs"]
mod fs_tree;
// Also the home of `hermetic`, the environment every child is spawned with.
#[path = "../hosted_memory_common/mod.rs"]
mod hosted_memory_common;

mod go;
mod harness;
