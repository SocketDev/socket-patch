//! Lock check detection (hazard HZ-09): `compile_pip_requirements`,
//! rules_uv `pip_compile` and `lock`, `gazelle_python_manifest` and a
//! checked-in `requirements.bzl`, found from the lock header and a bounded
//! BUILD scan. Such a test goes red after any rewrite and its `.update`
//! erases the pin, so the lane refuses.
//!
//! Stub until `wp-recog-python` (wave 3) replaces this file.

/// The lock checks found over one requirements lock. No value exists until
/// the scan does.
#[derive(Debug, Clone, PartialEq)]
pub enum PipCompileDetail {}
