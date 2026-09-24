//! `go.sum`: the registry view.

use std::path::Path;

use crate::patch::path_safety;
use crate::utils::fs::read_regular_to_string;

use super::{dedup_prefer_integrity, LockIntegrity, LockfileEntry};

/// Inventory `go.sum` module-zip lines (`<module> <version> h1:<b64>`); the
/// `/go.mod`-suffixed lines hash only the manifest and are skipped. go.sum
/// may list more modules than the final build graph — acceptable for
/// discovery, and the manifest decides what actually gets vendored.
pub(super) async fn inventory_go_sum(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&project_root.join("go.sum"))
        .await
        .ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(module), Some(version), Some(hash)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if version.ends_with("/go.mod") || !hash.starts_with("h1:") {
            continue;
        }
        // SECURITY: module path segments and the version feed paths/URLs.
        if !path_safety::is_safe_multi_segment(module)
            || !path_safety::is_safe_single_segment(version)
        {
            continue;
        }
        out.push(LockfileEntry {
            ecosystem: "golang",
            name: module.to_string(),
            version: version.to_string(),
            purl: format!("pkg:golang/{module}@{version}"),
            resolved: None,
            integrity: LockIntegrity::GoH1(hash.to_string()),
        });
    }
    Some(dedup_prefer_integrity(out))
}
