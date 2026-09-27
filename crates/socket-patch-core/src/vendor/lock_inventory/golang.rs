//! `go.sum`: the registry view.

#[cfg(test)]
use std::path::Path;

use crate::utils::purl::golang_purl;
use crate::vendor::go_sum_edit::go_sum_lines;

use super::view::ProjectView;
use super::{dedup_prefer_integrity, LockIntegrity, LockfileEntry, SourceKind};

// ── registry view ──

/// Inventory `go.sum` module-zip lines (`<module> <version> h1:<b64>`); the
/// `/go.mod`-suffixed lines hash only the manifest and are skipped. go.sum
/// may list more modules than the final build graph — acceptable for
/// discovery, and the manifest decides what actually gets vendored.
#[cfg(test)]
pub(super) async fn inventory_go_sum(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_go_sum_in(&ProjectView::Disk(project_root)).await
}

/// [`inventory_go_sum`] over a [`ProjectView`].
pub(super) async fn inventory_go_sum_in(view: &ProjectView<'_>) -> Option<Vec<LockfileEntry>> {
    inventory_go_sum_raw_in(view)
        .await
        .map(dedup_prefer_integrity)
}

/// [`inventory_go_sum`] before its collapse: every instance
/// ([`super::inventory_project_every_lock`]).
pub(super) async fn inventory_go_sum_raw_in(view: &ProjectView<'_>) -> Option<Vec<LockfileEntry>> {
    let text = view.read_text("go.sum").await.ok()?;
    let mut out = Vec::new();
    for line in go_sum_lines(&text) {
        if line.go_mod || !line.hash.starts_with("h1:") {
            continue;
        }
        // SECURITY: module path segments and the version feed paths/URLs.
        let Some(purl) = golang_purl(line.module, line.version) else {
            continue;
        };
        out.push(LockfileEntry {
            ecosystem: "golang",
            source_kind: SourceKind::Unspecified,
            name: line.module.to_string(),
            version: line.version.to_string(),
            purl,
            resolved: None,
            integrity: LockIntegrity::GoH1(line.hash.to_string()),
        });
    }
    Some(out)
}
