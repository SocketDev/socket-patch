//! `Gemfile.lock`: the registry view and the GEM remote set ledger recovery
//! reads.

use std::path::Path;

use crate::utils::fs::read_regular_to_string;
use crate::utils::purl::simple_purl;
use crate::vendor::gemfile_lock::{self, Section};

use super::{dedup_prefer_integrity, http_url, LockIntegrity, LockfileEntry, SourceKind};

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
pub(super) async fn inventory_gemfile_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_gemfile_lock_raw(project_root)
        .await
        .map(dedup_prefer_integrity)
}

/// [`inventory_gemfile_lock`] before its collapse: every instance
/// ([`super::inventory_project_every_lock`]).
pub(super) async fn inventory_gemfile_lock_raw(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&project_root.join("Gemfile.lock"))
        .await
        .ok()?;
    // The shared lock model (lockfile discovery reads it too); what bundler
    // would refuse (`problems`) still inventories whatever parsed — this is
    // read-only discovery.
    let lock = gemfile_lock::parse(&text);
    let gem_sections: Vec<&Section<'_>> = lock.gem_sections().collect();
    let mut out = Vec::new();
    for section in &gem_sections {
        let remotes: Vec<&str> = section.remote_bases().collect();
        for spec in section.specs.iter().filter_map(|line| line.parsed) {
            // Platform-suffixed specs are unsupported for vendoring anyway.
            if spec.platform.is_some() {
                continue;
            }
            let Some(purl) = simple_purl("gem", spec.name, spec.version) else {
                continue;
            };
            let (name, version) = (spec.name, spec.version);
            let integrity = lock.integrity(name, version).unwrap_or(LockIntegrity::None);
            let resolved = match remotes.as_slice() {
                [base] => gem_download_url(base, name, version),
                // No remote (a missing `remote:` line defaults to rubygems.org
                // ONLY when the whole lock has one remote-less GEM section —
                // the pre-multisource shape) or several remotes: fail closed.
                [] if gem_sections.len() == 1 => {
                    gem_download_url("https://rubygems.org", name, version)
                }
                _ => None,
            };
            out.push(LockfileEntry {
                ecosystem: "gem",
                source_kind: SourceKind::Unspecified,
                purl,
                resolved,
                name: name.to_string(),
                version: version.to_string(),
                integrity,
            });
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

/// Where a rubygems-compatible registry at `base` (no trailing `/`) serves
/// `name`-`version`'s `.gem` — the inventory's resolved URL and ledger
/// recovery's fetch URL. `None` for a non-http(s) base.
pub(super) fn gem_download_url(base: &str, name: &str, version: &str) -> Option<String> {
    http_url(&format!("{base}/downloads/{name}-{version}.gem"))
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
    let lock = gemfile_lock::parse(&text);
    lock.gem_remote_bases()
        .into_iter()
        .map(str::to_string)
        .collect()
}
