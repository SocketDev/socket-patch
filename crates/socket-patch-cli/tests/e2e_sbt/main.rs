//! sbt / Mill / scala-cli — the hermetic CLI suites, one module per mode
//! (`docs/design/sbt-support.md` §8.3). No sbt, no JVM, no network: the
//! fixtures write the on-disk shapes the real tools leave
//! (`tests/sbt_common/`), every child gets `SbtHome::isolated_env` so the
//! developer's real caches are never crawled or patched, and the patch API
//! is a wiremock stand-in. Run one mode with a module filter, e.g.
//! `cargo test -p socket-patch-cli --test e2e_sbt agent::`.
//!
//! ONE integration-test binary on purpose (each `tests/` file is its own
//! optimized link in CI's `test-release` job): every mode adds a module
//! here rather than a binary.

#[path = "../common/mod.rs"]
mod common;
#[path = "../sbt_common/mod.rs"]
mod sbt_common;

mod agent;
