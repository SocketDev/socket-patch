//! The binary under test and the Git-blob hash oracle (#824).
//!
//! `common/mod.rs` re-exports both. Shared modules whose includers don't
//! all declare `mod common` pull this file in on its own with
//! `#[path = "../common/oracle.rs"] mod oracle;`, so every test target
//! uses the one `binary()` and the one `git_sha256` that
//! `common::oracle_selftests` pins.

#![allow(dead_code)]

use std::path::PathBuf;

use sha2::{Digest, Sha256};

/// Absolute path to the built `socket-patch` binary that cargo
/// provides via the `CARGO_BIN_EXE_*` env var. Available because
/// these tests live in the same crate that produces the binary.
pub fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Compute Git-flavored SHA-256: `SHA256("blob <len>\0" ++ content)`.
/// This is the hash socket-patch records in manifests under
/// `before_hash` / `after_hash`. It is computed here, independently of
/// production's hasher, so a round trip through both can't agree on a
/// broken implementation.
pub fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}
