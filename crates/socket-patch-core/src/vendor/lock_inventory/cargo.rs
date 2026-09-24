//! `Cargo.lock`: the registry view.

use std::path::Path;

use crate::utils::digest::is_hex;
use crate::utils::purl::simple_purl;

use super::{dedup_prefer_integrity, LockIntegrity, LockfileEntry, SourceKind};

// ── registry view ──

/// Inventory `Cargo.lock` `[[package]]` entries, read through the vendor
/// backend's lock model ([`crate::vendor::cargo_lock::locked_packages`]; a v1 lock's
/// `[metadata]` checksums included). Only crates.io-sourced entries are
/// fetchable (their `checksum` is the sha256 of the `.crate` file);
/// workspace members (no `source`) are skipped, and git/custom-registry
/// sources stay listed for discovery without a verifier. A lock that is not
/// TOML yields nothing — cargo itself refuses to build from it.
pub(super) async fn inventory_cargo_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_cargo_lock_raw(project_root)
        .await
        .map(dedup_prefer_integrity)
}

/// [`inventory_cargo_lock`] before its collapse: every instance
/// ([`super::inventory_project_every_lock`]).
pub(super) async fn inventory_cargo_lock_raw(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let (_, doc) = crate::vendor::cargo_lock::read_lock(project_root)
        .await
        .ok()?;
    let mut out = Vec::new();
    for pkg in crate::vendor::cargo_lock::locked_packages(&doc) {
        let Some(source) = pkg.source else {
            continue; // workspace member
        };
        let Some(purl) = simple_purl("cargo", &pkg.name, &pkg.version) else {
            continue;
        };
        let crates_io = source.contains("github.com/rust-lang/crates.io-index")
            || source.contains("index.crates.io");
        // The crates.io provenance is recorded exactly where the checksum is
        // kept as the `.crate`'s sha256.
        let (integrity, source_kind) = match pkg.checksum {
            Some(c) if crates_io && is_hex(&c, 64) => {
                (LockIntegrity::Sha256Hex(c), SourceKind::CratesIo)
            }
            _ => (LockIntegrity::None, SourceKind::Unspecified),
        };
        out.push(LockfileEntry {
            ecosystem: "cargo",
            source_kind,
            purl,
            name: pkg.name,
            version: pkg.version,
            resolved: None,
            integrity,
        });
    }
    Some(out)
}
