//! Read-only lockfile inventories: the dependency set a project's lockfile
//! resolves, independent of what is installed on disk.
//!
//! Two consumers:
//!
//! * `scan` supplements its installed-tree crawl with lockfile-only entries
//!   (discovery on fresh clones and partial installs), warning that those
//!   packages are not yet installed;
//! * `vendor` fetches the pristine artifact for a lockfile-resolved package
//!   with no installed copy ([`super::registry_fetch`]), verifying the bytes
//!   against the integrity the lock records — FAIL-CLOSED: an entry whose
//!   lock carries no content verifier is never fetched.
//!
//! Parsing is fail-soft per entry (a malformed entry is skipped, never an
//! error; a malformed text file yields `None`, while a malformed binary Bun
//! lock emits `bun_lockb_invalid`) and fail-closed per value:
//! names/versions are path-safety-guarded before an entry is emitted — the
//! lockfile is committed, tamperable input that later feeds filesystem paths
//! and download URLs.

use std::collections::HashMap;
use std::path::Path;

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::purl::strip_purl_qualifiers;

pub(crate) mod bun;
pub(crate) mod cargo;
pub(crate) mod composer;
pub(crate) mod gem;
pub(crate) mod golang;
pub(crate) mod npm;
pub(crate) mod npm_family;
pub(crate) mod pnpm;
pub(crate) mod pypi;
pub(crate) mod recover;
pub(crate) mod wired;
pub(crate) mod yarn;

pub(crate) use self::npm_family::inventory_npm_lock;
pub use self::recover::recover_lock_entry;
pub use self::wired::wired_vendor_integrity;

// The per-format views `inventory_project_diagnosed` unions (and the test
// modules reach through `super::*`).
use self::cargo::inventory_cargo_lock;
use self::composer::inventory_composer_lock;
use self::gem::inventory_gemfile_lock;
use self::golang::inventory_go_sum;
use self::pypi::inventory_pypi_locks;
#[cfg(test)]
use self::{
    bun::inventory_bun,
    gem::gem_remotes,
    npm::inventory_package_lock,
    npm_family::finalize_npm,
    pnpm::{inventory_pnpm_lock, inventory_pnpm_lock_at},
    pypi::{is_public_pypi_url, python_lock_inventory, socket_reference_coords},
    recover::pure_wheel_from_uv_unit,
    yarn::{inventory_yarn_berry, inventory_yarn_classic},
};
#[cfg(test)]
use crate::vendor::npm_flavor::NpmLockFlavor;

/// The content verifier a lockfile records for an entry. The fetch layer
/// refuses entries whose verifier is [`LockIntegrity::None`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockIntegrity {
    /// SRI string (`sha512-<b64>`, possibly multi-hash space-separated) —
    /// npm family; verified against the raw tarball bytes.
    Sri(String),
    /// yarn classic `resolved "...#<sha1>"` fragment (40-hex) — verified
    /// against the raw tarball bytes.
    Sha1Hex(String),
    /// yarn berry cache-zip checksum (`<cacheKey>/<b64>`, e.g. `10c0/…`) —
    /// verified by rebuilding the deterministic cache zip from the fetched
    /// tarball and comparing (the lock never hashes the tarball itself).
    BerryChecksum(String),
    /// Hex sha256 of the artifact (Cargo.lock `checksum`, pypi file hashes,
    /// Gemfile.lock `CHECKSUMS`).
    Sha256Hex(String),
    /// One of several hex sha256 digests: the lock records every release
    /// file's digest without saying which file is which (Pipfile.lock
    /// `hashes`), so the fetcher picks the pure-Python wheel whose PyPI
    /// digest is in the set and verifies the download against that digest.
    Sha256AnyOf(Vec<String>),
    /// go.sum module-zip dirhash (`h1:<b64>`).
    GoH1(String),
    /// The lock records no content verifier.
    None,
}

/// One lockfile-resolved package.
#[derive(Debug, Clone)]
pub struct LockfileEntry {
    /// Vendor-ecosystem tag (`npm`, `cargo`, `golang`, `pypi`, `gem`,
    /// `composer`) — matches `VendorEntry::ecosystem`.
    pub ecosystem: &'static str,
    /// Literal (percent-decoded) package name, e.g. `@scope/name`.
    pub name: String,
    /// Exact resolved version.
    pub version: String,
    /// Canonical literal purl (`pkg:npm/@scope/name@1.0.0`) — the same form
    /// the crawlers emit.
    pub purl: String,
    /// Artifact URL when the lock records one (package-lock `resolved`,
    /// yarn `resolved` minus its `#sha1` fragment, pnpm `tarball:`); `None`
    /// means the fetcher constructs the conventional registry URL.
    pub resolved: Option<String>,
    pub integrity: LockIntegrity,
}

impl LockfileEntry {
    fn npm(
        name: impl Into<String>,
        version: impl Into<String>,
        resolved: Option<String>,
        integrity: LockIntegrity,
    ) -> Self {
        let (name, version) = (name.into(), version.into());
        let purl = format!("pkg:npm/{name}@{version}");
        LockfileEntry {
            ecosystem: "npm",
            name,
            version,
            purl,
            resolved,
            integrity,
        }
    }
}

/// A project layout or lockfile that cannot be inventoried safely.
/// Consumers surface these diagnoses instead of treating an unreadable
/// dependency graph as an empty project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedNpmLayout {
    /// Stable diagnosis code, including `bun_lockb_invalid` for malformed
    /// binary Bun locks and the flavor probe's Plug'n'Play refusal codes.
    pub code: &'static str,
    /// Human-readable diagnosis with format or filesystem error details.
    pub detail: String,
}

/// Match a manifest/API purl (possibly percent-encoded, possibly carrying
/// qualifiers) against the inventory: components decode via
/// [`crate::utils::purl::normalize_purl`], so `pkg:npm/%40scope/x@1`
/// matches the literal entry.
pub fn lookup<'a>(entries: &'a [LockfileEntry], purl: &str) -> Option<&'a LockfileEntry> {
    let decoded = crate::utils::purl::normalize_purl(strip_purl_qualifiers(purl)).into_owned();
    let rest = decoded.strip_prefix("pkg:")?;
    let (purl_type, rest) = rest.split_once('/')?;
    // purl types double as the vendor-ecosystem tags (same set the
    // dispatcher recognizes).
    let eco = match purl_type {
        "npm" | "cargo" | "golang" | "pypi" | "gem" | "composer" => purl_type,
        _ => return None,
    };
    let at = rest.rfind('@').filter(|&i| i > 0)?;
    let (name, version) = (&rest[..at], &rest[at + 1..]);
    // pypi names compare in PEP 503 normalized form.
    let name = if eco == "pypi" {
        canonicalize_pypi_name(name)
    } else {
        name.to_string()
    };
    entries
        .iter()
        .find(|e| e.ecosystem == eco && e.name == name && e.version == version)
}

/// Everything every recognized lockfile in the project resolves — the
/// union the scan supplement and the vendor auto-fetch consume. Drops the
/// npm-layout diagnosis; callers that must surface refusals (scan) use
/// [`inventory_project_diagnosed`].
pub async fn inventory_project(project_root: &Path) -> Vec<LockfileEntry> {
    inventory_project_diagnosed(project_root).await.0
}

/// [`inventory_project`] plus the npm-family layout refusals it hit: a
/// Plug'n'Play project yields no npm entries AND a diagnosis, so consumers
/// can tell "nothing to inventory" from "packages structurally unreachable"
/// and refuse explicitly instead of silently reporting an empty project.
pub async fn inventory_project_diagnosed(
    project_root: &Path,
) -> (Vec<LockfileEntry>, Vec<UnsupportedNpmLayout>) {
    let mut out: Vec<LockfileEntry> = Vec::new();
    let mut unsupported: Vec<UnsupportedNpmLayout> = Vec::new();
    match inventory_npm_lock(project_root).await {
        Ok(Some((_, entries))) => out.extend(entries),
        Ok(None) => {}
        Err(diag) => unsupported.push(diag),
    }
    if let Some(entries) = inventory_cargo_lock(project_root).await {
        out.extend(entries);
    }
    if let Some(entries) = inventory_go_sum(project_root).await {
        out.extend(entries);
    }
    if let Some(entries) = inventory_composer_lock(project_root).await {
        out.extend(entries);
    }
    if let Some(entries) = inventory_gemfile_lock(project_root).await {
        out.extend(entries);
    }
    if let Some(entries) = inventory_pypi_locks(project_root).await {
        out.extend(entries);
    }
    (out, unsupported)
}

/// Collapse duplicate (name, version) instances, preferring one that
/// carries a verifier.
fn dedup_prefer_integrity(raw: Vec<LockfileEntry>) -> Vec<LockfileEntry> {
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    let mut out: Vec<LockfileEntry> = Vec::new();
    for entry in raw {
        let key = (entry.name.clone(), entry.version.clone());
        match seen.get(&key) {
            Some(&i) => {
                if out[i].integrity == LockIntegrity::None && entry.integrity != LockIntegrity::None
                {
                    out[i] = entry;
                }
            }
            None => {
                seen.insert(key, out.len());
                out.push(entry);
            }
        }
    }
    out
}

/// Keep a lock-recorded URL only when it is a plain http(s) artifact URL
/// (drops `git+…`, `file:…`, `link:…` — content the registry conventions
/// cannot reproduce; such entries stay listed for discovery but the fetch
/// layer's integrity rule decides fetchability).
fn http_url(raw: &str) -> Option<String> {
    (raw.starts_with("https://") || raw.starts_with("http://")).then(|| raw.to_string())
}

fn is_hex_of_len(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod recover_tests;

#[cfg(test)]
mod python_lock_union_tests;
