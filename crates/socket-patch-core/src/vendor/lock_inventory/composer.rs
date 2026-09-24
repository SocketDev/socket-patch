//! `composer.lock`: the registry view.

use std::path::Path;

use serde_json::Value;

use crate::crawlers::composer_crawler::normalize_version;
use crate::patch::path_safety;
use crate::utils::fs::read_regular_to_bytes;
use crate::vendor::path::parse_vendor_path;

use super::{dedup_prefer_integrity, http_url, is_hex_of_len, LockIntegrity, LockfileEntry};

/// Inventory `composer.lock` `packages`/`packages-dev`. The `dist.shasum`
/// (sha1 of the dist zip) is frequently empty — such entries stay
/// discovery-only. Names lowercase to the canonical packagist form;
/// versions drop the pretty leading `v`/`V` through the crawler's
/// [`normalize_version`], so installed and lockfile rows agree.
pub(super) async fn inventory_composer_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let bytes = read_regular_to_bytes(&project_root.join("composer.lock"))
        .await
        .ok()?;
    let doc: Value = serde_json::from_slice(&bytes).ok()?;
    let mut out = Vec::new();
    for section in ["packages", "packages-dev"] {
        let Some(list) = doc.get(section).and_then(Value::as_array) else {
            continue;
        };
        for pkg in list {
            let Some(name) = pkg.get("name").and_then(Value::as_str) else {
                continue;
            };
            let Some(version) = pkg.get("version").and_then(Value::as_str) else {
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
            let dist = pkg.get("dist");
            let dist_url = dist
                .and_then(|d| d.get("url"))
                .and_then(Value::as_str)
                .unwrap_or("");
            // Our own vendored entries use a path dist — skip.
            if dist
                .and_then(|d| d.get("type"))
                .and_then(Value::as_str)
                .is_some_and(|t| t == "path")
                || parse_vendor_path(dist_url).is_some()
            {
                continue;
            }
            let is_zip = dist
                .and_then(|d| d.get("type"))
                .and_then(Value::as_str)
                .is_some_and(|t| t == "zip");
            let shasum = dist
                .and_then(|d| d.get("shasum"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let integrity = if is_zip && is_hex_of_len(shasum, 40) {
                LockIntegrity::Sha1Hex(shasum.to_ascii_lowercase())
            } else {
                LockIntegrity::None
            };
            let purl = format!("pkg:composer/{name}@{version}");
            out.push(LockfileEntry {
                ecosystem: "composer",
                name,
                version,
                purl,
                resolved: is_zip.then(|| http_url(dist_url)).flatten(),
                integrity,
            });
        }
    }
    Some(dedup_prefer_integrity(out))
}
