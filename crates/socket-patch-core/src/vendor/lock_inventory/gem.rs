//! The Bundler lock (`Gemfile.lock`, or `gems.locked` for a `gems.rb`
//! project — whichever bundler loads): the registry view and the GEM remote
//! set ledger recovery reads.

use std::path::Path;

use crate::crawlers::ruby_crawler::{bundler_loaded_lock_diagnosed_in, bundler_loaded_lock_in};
pub(super) use crate::formats::gem::gem_download_url;
use crate::formats::gem::GemfileLock;
use crate::utils::fs::read_regular_to_string;

use super::view::ProjectView;
use super::{dedup_prefer_integrity, LockfileEntry, UnsupportedNpmLayout};

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
    // Only the lock bundler loads: a twin it ignores (a leftover
    // `Gemfile.lock` beside `gems.rb` + `gems.locked`) is not what installs.
    let lock = bundler_loaded_lock_in(view).await?;
    let text = view.read_text(lock).await.ok()?;
    // The shared lock model (lockfile discovery reads it too); what bundler
    // would refuse (`problems`) still inventories whatever parsed — this is
    // read-only discovery.
    GemfileLock::parse(&text).entries()
}

/// Why the project's Bundler lock was not inventoried, when it holds gem
/// files ([`GEM_FILES`]) but bundler loads no lock socket-patch reads
/// ([`bundler_loaded_lock_diagnosed_in`]): an unsupported `BUNDLE_GEMFILE`
/// or `BUNDLE_LOCKFILE`, or a `Gemfile` + `gems.rb` twin (which pair
/// loads depends on the bundler that runs). Without it a lockfile-only scan would
/// report the project's gems as absent rather than unscanned.
pub(super) async fn unsupported_gem_layout_in(
    view: &ProjectView<'_>,
) -> Option<UnsupportedNpmLayout> {
    if !GEM_FILES.iter().any(|rel| view.is_file(rel)) {
        return None;
    }
    let reason = bundler_loaded_lock_diagnosed_in(view).await.err()?;
    Some(UnsupportedNpmLayout {
        code: "gem_lock_unsupported",
        detail: format!(
            "lockfile-only gem dependencies were NOT scanned: bundler loads no Gemfile.lock \
             or gems.locked socket-patch can read here: {reason}"
        ),
    })
}

/// The manifest and lock spellings of the two default Bundler pairs.
const GEM_FILES: [&str; 4] = ["Gemfile", "Gemfile.lock", "gems.rb", "gems.locked"];

/// The DISTINCT `GEM remote:` bases across ALL GEM sections of the lock
/// bundler loads ([`bundler_loaded_lock_in`]; trailing `/` trimmed), in
/// first-appearance order. A vendored gem's spec block moved into its PATH
/// section, so which GEM section it came from is unrecoverable — ledger
/// recovery may only build a download URL when the lock's GEM sources
/// agree on a single remote.
/// Collected scheme-AGNOSTICALLY: a non-http remote (a `file://` gem repo —
/// bundler 4.0.15 locks one GEM section per `source "file://…" do` block)
/// still counts toward the ambiguity decision; filtering it out first would
/// collapse a mixed http+file lock to one "agreed" remote and send the
/// file-sourced gem's name to the http one. The caller requires the single
/// survivor to be http(s).
pub(super) async fn gem_remotes(project_root: &Path) -> Vec<String> {
    let Some(lock) = bundler_loaded_lock_in(&ProjectView::Disk(project_root)).await else {
        return Vec::new();
    };
    let Ok(text) = read_regular_to_string(&project_root.join(lock)).await else {
        return Vec::new();
    };
    GemfileLock::parse(&text)
        .gem_remote_bases()
        .into_iter()
        .map(str::to_string)
        .collect()
}
