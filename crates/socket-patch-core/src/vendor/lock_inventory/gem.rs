//! `Gemfile.lock`: the registry view and the GEM remote set ledger recovery
//! reads.

use std::path::Path;

pub(super) use crate::formats::gem::gem_download_url;
use crate::formats::gem::GemfileLock;
use crate::utils::fs::read_regular_to_string;

use super::view::ProjectView;
use super::{dedup_prefer_integrity, LockfileEntry};

// ── registry view ──

/// Inventory `Gemfile.lock`: `GEM`-section `specs:` entries (4-space
/// indent; deeper lines are dependency ranges) plus the bundler ≥ 2.6
/// `CHECKSUMS` section's sha256 values when present (older locks stay
/// discovery-only). Platform-suffixed specs (`nokogiri (1.16.5-arm64-…)`)
/// are skipped — platform gems are unsupported for vendoring anyway.
///
/// Multi-source locks: bundler ≥ 2 emits ONE GEM section per source
/// (Gemfile `source … do` blocks; verified against bundler 4.0.15) and
/// hard-errors on multiple global sources, so each spec resolves against
/// its OWN section's remote — never the first remote in the file, which
/// for a private-server section would 404 at best and leak private gem
/// names to the public registry at worst. A section carrying SEVERAL
/// distinct `remote:` lines is a legacy bundler 1.x multisource lock whose
/// per-spec origin is genuinely ambiguous: its specs stay discovery-only
/// (no resolved URL — the fetch layer then refuses), fail-closed.
#[cfg(test)]
pub(super) async fn inventory_gemfile_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_gemfile_lock_in(&ProjectView::Disk(project_root)).await
}

/// [`inventory_gemfile_lock`] over a [`ProjectView`].
pub(super) async fn inventory_gemfile_lock_in(
    view: &ProjectView<'_>,
) -> Option<Vec<LockfileEntry>> {
    inventory_gemfile_lock_raw_in(view)
        .await
        .map(dedup_prefer_integrity)
}

/// [`inventory_gemfile_lock`] before its collapse: every instance
/// ([`super::inventory_project_every_lock`]).
pub(super) async fn inventory_gemfile_lock_raw_in(
    view: &ProjectView<'_>,
) -> Option<Vec<LockfileEntry>> {
    let text = view.read_text("Gemfile.lock").await.ok()?;
    // The shared lock model (lockfile discovery reads it too); what bundler
    // would refuse (`problems`) still inventories whatever parsed — this is
    // read-only discovery.
    GemfileLock::parse(&text).entries()
}

/// The DISTINCT `GEM remote:` bases across ALL GEM sections of the
/// Gemfile.lock (trailing `/` trimmed), in first-appearance order. A
/// vendored gem's spec block moved into its PATH section, so which GEM
/// section it came from is unrecoverable — ledger recovery may only build
/// a download URL when the lock's GEM sources agree on a single remote.
/// Collected scheme-AGNOSTICALLY: a non-http remote (a `file://` gem repo —
/// bundler 4.0.15 locks one GEM section per `source "file://…" do` block)
/// still counts toward the ambiguity decision; filtering it out first would
/// collapse a mixed http+file lock to one "agreed" remote and send the
/// file-sourced gem's name to the http one. The caller requires the single
/// survivor to be http(s).
pub(super) async fn gem_remotes(project_root: &Path) -> Vec<String> {
    let Ok(text) = read_regular_to_string(&project_root.join("Gemfile.lock")).await else {
        return Vec::new();
    };
    GemfileLock::parse(&text)
        .gem_remote_bases()
        .into_iter()
        .map(str::to_string)
        .collect()
}
