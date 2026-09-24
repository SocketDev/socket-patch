//! `package-lock.json` / `npm-shrinkwrap.json`: the registry view.

use std::path::Path;

use serde_json::Value;

use crate::utils::fs::read_regular_to_bytes;
use crate::vendor::path::parse_vendor_path;

use super::{http_url, LockIntegrity, LockfileEntry};

pub(super) async fn inventory_package_lock(root: &Path) -> Option<Vec<LockfileEntry>> {
    // Shrinkwrap wins, mirroring `npm_lock::select_lockfile`.
    let mut bytes = None;
    for lock in ["npm-shrinkwrap.json", "package-lock.json"] {
        if let Ok(b) = read_regular_to_bytes(&root.join(lock)).await {
            bytes = Some(b);
            break;
        }
    }
    let doc: Value = serde_json::from_slice(&bytes?).ok()?;
    // v1 legacy locks have no `packages` map — no inventory (documented).
    let packages = doc.get("packages")?.as_object()?;

    let mut out = Vec::new();
    for (key, node) in packages {
        // "" is the root project; keys without node_modules/ are workspace
        // members (mirrors npm_lock::scan_lock_matches' member rule).
        let Some((_, key_name)) = key.rsplit_once("node_modules/") else {
            continue;
        };
        if node.get("link").and_then(Value::as_bool).unwrap_or(false)
            || node
                .get("inBundle")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            continue;
        }
        let name = node
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(key_name)
            .to_string();
        let Some(version) = node.get("version").and_then(Value::as_str) else {
            continue;
        };
        let resolved_raw = node.get("resolved").and_then(Value::as_str);
        // Our own vendored spec: not a registry dependency.
        if resolved_raw.is_some_and(|r| parse_vendor_path(r).is_some()) {
            continue;
        }
        let integrity = node
            .get("integrity")
            .and_then(Value::as_str)
            .map(|i| LockIntegrity::Sri(i.to_string()))
            .unwrap_or(LockIntegrity::None);
        out.push(LockfileEntry::npm(
            name,
            version,
            resolved_raw.and_then(http_url),
            integrity,
        ));
    }
    Some(out)
}
