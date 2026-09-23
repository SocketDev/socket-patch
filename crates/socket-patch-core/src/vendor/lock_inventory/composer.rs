//! `composer.lock`: the shared entry walk ([`composer_lock_packages`]) and
//! its registry view.

use std::path::Path;

use serde_json::Value;

use crate::crawlers::composer_crawler::normalize_version;
use crate::patch::path_safety;
use crate::utils::digest::sha1_hex;
use crate::utils::fs::read_regular_to_bytes;
use crate::vendor::path::{parse_vendor_path, VendorPathParts};

use super::{dedup_prefer_integrity, http_url, LockIntegrity, LockfileEntry, SourceKind};

// ── entry model ──

/// One entry of a parsed `composer.lock` (see [`composer_lock_packages`]).
pub(crate) struct ComposerLockPackage<'a> {
    /// `packages` or `packages-dev`.
    pub(crate) section: &'static str,
    /// The position in the section ARRAY, counting non-object elements too:
    /// what a writer indexes `lock[section][index]` with.
    pub(crate) index: usize,
    pub(crate) name: Option<&'a str>,
    /// As locked — the pretty `v`-prefixed spelling; callers normalize
    /// through [`normalize_version`].
    pub(crate) version: Option<&'a str>,
    /// The `dist` object: what composer's default `--prefer-dist` install
    /// consumes, and the block both backends rewrite.
    pub(crate) dist: Option<&'a Value>,
}

impl ComposerLockPackage<'_> {
    /// A string field of the entry's `dist`.
    pub(crate) fn dist_str(&self, key: &str) -> Option<&str> {
        self.dist?.get(key)?.as_str()
    }

    /// The `dist.shasum` pin: a 40-hex sha1 of the dist archive (any case,
    /// lowercased), whatever the dist `type` — the inventory additionally
    /// requires a `zip` dist at its call site.
    pub(crate) fn dist_sha1(&self) -> Option<LockIntegrity> {
        self.dist_str("shasum")
            .and_then(sha1_hex)
            .map(LockIntegrity::Sha1Hex)
    }

    /// The Socket-vendored path `dist.url` names, anchored anywhere
    /// ([`parse_vendor_path`]: the writers' ownership rule, not discovery's
    /// root-anchored attestation grammar).
    pub(crate) fn dist_vendor_path(&self) -> Option<VendorPathParts> {
        self.dist_str("url").and_then(parse_vendor_path)
    }
}

/// Every entry composer installs from a parsed `composer.lock`, in lock
/// order: `packages`, then `packages-dev` (composer installs both by
/// default; a missing or non-array section is empty). The one walk the
/// inventory and lockfile discovery (`vex::discover::composer`) share.
pub(crate) fn composer_lock_packages(doc: &Value) -> Vec<ComposerLockPackage<'_>> {
    let mut out = Vec::new();
    for section in ["packages", "packages-dev"] {
        for (index, pkg) in doc
            .get(section)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            out.push(ComposerLockPackage {
                section,
                index,
                name: pkg.get("name").and_then(Value::as_str),
                version: pkg.get("version").and_then(Value::as_str),
                dist: pkg.get("dist"),
            });
        }
    }
    out
}

// ── registry view ──

/// Inventory `composer.lock` `packages`/`packages-dev`. The `dist.shasum`
/// (sha1 of the dist zip) is frequently empty — such entries stay
/// discovery-only. Names lowercase to the canonical packagist form;
/// versions drop the pretty leading `v`/`V` through the crawler's
/// [`normalize_version`], so installed and lockfile rows agree.
pub(super) async fn inventory_composer_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_composer_lock_raw(project_root)
        .await
        .map(dedup_prefer_integrity)
}

/// [`inventory_composer_lock`] before its collapse: every instance
/// ([`super::inventory_project_every_lock`]).
pub(super) async fn inventory_composer_lock_raw(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let bytes = read_regular_to_bytes(&project_root.join("composer.lock"))
        .await
        .ok()?;
    let doc: Value = serde_json::from_slice(&bytes).ok()?;
    let mut out = Vec::new();
    for pkg in composer_lock_packages(&doc) {
        let (Some(name), Some(version)) = (pkg.name, pkg.version) else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        // Share the crawler's normalization rather than re-deriving it:
        // it strips `v` AND `V` (both are legal Composer tags), and a
        // lockfile row that normalizes differently from the installed
        // row double-counts the package — one installed `@1.2.3` plus a
        // phantom lockfile-only `@V1.2.3`, both POSTed.
        let version = normalize_version(version).to_string();
        if !path_safety::is_safe_multi_segment(&name)
            || name.split('/').count() != 2
            || !path_safety::is_safe_single_segment(&version)
        {
            continue;
        }
        // Our own vendored entries use a path dist — skip.
        if pkg.dist_str("type") == Some("path") || pkg.dist_vendor_path().is_some() {
            continue;
        }
        let dist_url = pkg.dist_str("url").unwrap_or("");
        let is_zip = pkg.dist_str("type") == Some("zip");
        let integrity = match pkg.dist_sha1() {
            Some(sha1) if is_zip => sha1,
            _ => LockIntegrity::None,
        };
        let purl = format!("pkg:composer/{name}@{version}");
        out.push(LockfileEntry {
            ecosystem: "composer",
            source_kind: SourceKind::Unspecified,
            name,
            version,
            purl,
            resolved: is_zip.then(|| http_url(dist_url)).flatten(),
            integrity,
        });
    }
    Some(out)
}
