//! npm-family routing: which lock the project's npm-family package manager
//! installs from ([`inventory_npm_lock`]), the migration-leftover sibling
//! probe, and the shared name/version guard + dedup of npm entries.

#[cfg(test)]
use std::path::Path;

use crate::constants::npm_family::{
    BUN_LOCK, BUN_LOCKB, NPM_LOCKS, PNPM_SHRINKWRAP_LEGACY, VLT_LOCK,
};
use crate::formats::yarn::{grammar as yarn_grammar, YarnLockGrammar};
use crate::utils::purl::npm_purl;
use crate::vendor::npm_flavor::NpmLockFlavor;

use super::bun::{bun_text_lock_present_in, inventory_bun_binary_in, inventory_bun_in};
use super::npm::inventory_package_lock_in;
use super::pnpm::{
    inventory_pnpm_lock_in, inventory_pnpm_lock_rel_in, inventory_rush_pnpm_locks_in,
};
use super::view::{detect_npm_lock_flavor_in, ProjectView};
use super::vlt::inventory_vlt_in;
use super::yarn::{inventory_yarn_berry_in, inventory_yarn_classic_in};
use super::{dedup_prefer_integrity, LockfileEntry, UnsupportedNpmLayout};

// ── registry view ──

/// Inventory the project's npm-family lockfile. Routes by
/// [`detect_npm_lock_flavor`]. `Ok(None)` means there is nothing to
/// inventory (missing lockfile, dep-less locks); `Err` propagates the
/// probe's Plug'n'Play diagnosis — a layout whose packages the inventory
/// can NEVER serve — and malformed binary Bun locks, which callers must
/// not conflate with the calm no-lockfile case. Two
/// pnpm-specific refusals fall back instead of
/// yielding `None`: an unsupported `lockfileVersion` reads the root
/// `pnpm-lock.yaml` directly — unless a live sibling lock the router would
/// otherwise have chosen sits beside it (a pnpm→yarn/npm migration
/// leftover), in which case the SIBLING is inventoried instead
/// ([`inventory_live_sibling_lock_in`]) — and `vendor_lockfile_missing` reads
/// the pnpm <=2-era `shrinkwrap.yaml` (same v5 grammar, older filename).
/// Any remaining probe failure falls back to Rush's common lock when
/// `rush.json` is present.
#[cfg(test)]
pub(crate) async fn inventory_npm_lock(
    project_root: &Path,
) -> Result<Option<(NpmLockFlavor, Vec<LockfileEntry>)>, UnsupportedNpmLayout> {
    inventory_npm_lock_in(&ProjectView::Disk(project_root)).await
}

/// [`inventory_npm_lock`] over a [`ProjectView`].
pub(super) async fn inventory_npm_lock_in(
    view: &ProjectView<'_>,
) -> Result<Option<(NpmLockFlavor, Vec<LockfileEntry>)>, UnsupportedNpmLayout> {
    inventory_npm_lock_raw_in(view)
        .await
        .map(|found| found.map(|(flavor, raw)| (flavor, dedup_prefer_integrity(raw))))
}

/// [`inventory_npm_lock`] before its collapse: every
/// guarded instance ([`super::inventory_project_every_lock`]).
pub(super) async fn inventory_npm_lock_raw_in(
    view: &ProjectView<'_>,
) -> Result<Option<(NpmLockFlavor, Vec<LockfileEntry>)>, UnsupportedNpmLayout> {
    let (flavor, _warnings) = match detect_npm_lock_flavor_in(view).await {
        Ok(found) => found,
        Err((code, detail)) => {
            // The PnP loaders are a refusal, not an absence: propagate the
            // diagnosis instead of discarding it. Under PnP the
            // installed-tree crawl is ALSO structurally empty, so
            // swallowing this here would make `scan` a silent success-0
            // no-op in every mode. Every other probe error keeps the fallbacks below
            // and the calm `Ok(None)`.
            if matches!(
                code,
                "vendor_yarn_berry_unsupported" | "vendor_pnpm_pnp_unsupported"
            ) {
                return Err(UnsupportedNpmLayout { code, detail });
            }
            // The flavor probe passes only pnpm locks the WIRING backends
            // support (lockfileVersion 5.4/6.0/9.0), but inventory is
            // read-only discovery — an out-of-family (pnpm <= 6-era or
            // future) lock still names the resolved set, so on the probe's
            // pnpm version refusal a present root lock is read directly
            // rather than leaving fresh clones of such projects blind. Only
            // that code: on any other refusal a root pnpm-lock.yaml is
            // stale debris from a migration, and inventorying it would
            // present dead resolutions as the live dependency set.
            // (`vendor_lockfile_version_unsupported` also covers the
            // unrecognizable-yarn.lock refusal, but the probe only sniffs
            // yarn.lock when no root pnpm-lock.yaml exists, so the direct
            // read is a no-op there.)
            if code == "vendor_lockfile_version_unsupported" {
                // The version refusal fires from the probe's pnpm step,
                // which runs BEFORE its yarn/npm steps — so it says nothing
                // about whether a LIVE sibling lock sits beside the refused
                // pnpm lock (a pnpm→yarn/npm migration leaves exactly that
                // shape behind). Prefer whichever sibling the router would
                // have chosen had the pnpm lock not shadowed it; only a
                // sibling-less project is a genuine old-pnpm project whose
                // lock the fallback may surface.
                match inventory_live_sibling_lock_in(view).await {
                    Some((flavor, entries)) if !entries.is_empty() => {
                        return Ok(Some((flavor, guard_npm(entries))));
                    }
                    // A sibling lock FILE exists but yields no entries
                    // (dep-less project, or a grammar we cannot read): the
                    // migration still happened, so the pnpm lock stays out —
                    // blind beats presenting dead resolutions as live.
                    Some(_) => {}
                    None => {
                        let pnpm = inventory_pnpm_lock_in(view).await.unwrap_or_default();
                        if !pnpm.is_empty() {
                            return Ok(Some((NpmLockFlavor::Pnpm, guard_npm(pnpm))));
                        }
                    }
                }
            }
            // pnpm 1/2 wrote the v5-era lock grammar under the name
            // `shrinkwrap.yaml` (shrinkwrapVersion 3) — pnpm 3 renamed the
            // file to pnpm-lock.yaml. The flavor probe doesn't know that
            // filename, so such a project refuses as
            // `vendor_lockfile_missing`; the lock still names the full
            // resolved set, so read it directly rather than leaving pnpm<=2
            // projects (and their fresh clones) lockfile-blind. Gated on
            // that ONE code: any other refusal means a DIFFERENT lock
            // family is present (bun markers, an unsupported recognized
            // lock), where a shrinkwrap.yaml is stale debris from a
            // long-ago migration whose dead resolutions must not pose as
            // the live dependency set.
            if code == "vendor_lockfile_missing" {
                let legacy = inventory_pnpm_lock_rel_in(view, PNPM_SHRINKWRAP_LEGACY)
                    .await
                    .unwrap_or_default();
                if !legacy.is_empty() {
                    return Ok(Some((NpmLockFlavor::PnpmLegacy, guard_npm(legacy))));
                }
            }
            // Rush monorepos have no root package.json/lock pair; their
            // single pnpm source-of-truth lives under common/config/rush/.
            // The flavor probe (root-relative) can't see it, so fall back
            // explicitly when the root lock is absent but rush.json is
            // present.
            let rush = inventory_rush_pnpm_locks_in(view).await;
            return Ok((!rush.is_empty()).then(|| (NpmLockFlavor::Pnpm, guard_npm(rush))));
        }
    };
    let raw = match flavor {
        NpmLockFlavor::PackageLock => inventory_package_lock_in(view).await,
        // The pnpm reader is grammar-agnostic (it also serves legacy
        // 5.4/6.0 locks through the version-refusal fallback above), so
        // both pnpm flavors share it.
        NpmLockFlavor::Pnpm | NpmLockFlavor::PnpmLegacy => inventory_pnpm_lock_in(view).await,
        NpmLockFlavor::YarnClassic => inventory_yarn_classic_in(view).await,
        NpmLockFlavor::YarnBerry => inventory_yarn_berry_in(view).await,
        NpmLockFlavor::Bun => {
            if bun_text_lock_present_in(view).await {
                inventory_bun_in(view).await
            } else {
                Some(inventory_bun_binary_in(view).await?)
            }
        }
        NpmLockFlavor::Vlt => inventory_vlt_in(view).await,
    };
    Ok(raw.map(|raw| (flavor, guard_npm(raw))))
}

/// The live sibling lock a version-refused root `pnpm-lock.yaml` may be
/// shadowing, or `None` when no sibling lock file exists at all.
///
/// [`detect_npm_lock_flavor`] cannot be re-asked (it already refused on its
/// pnpm step), so this mirrors the rest of its precedence by hand — vlt,
/// bun, then yarn, then npm — on file EXISTENCE, and returns the first present
/// sibling's inventory (possibly empty: presence alone proves the pnpm lock
/// is migration debris, so the caller must not fall back to it). Raw
/// entries — the caller guards and collapses them.
pub(super) async fn inventory_live_sibling_lock_in(
    view: &ProjectView<'_>,
) -> Option<(NpmLockFlavor, Vec<LockfileEntry>)> {
    if view.exists(VLT_LOCK).await {
        return Some((
            NpmLockFlavor::Vlt,
            inventory_vlt_in(view).await.unwrap_or_default(),
        ));
    }
    // bun.lock — router step 3. That step runs BEFORE the pnpm sniff, so
    // when the version refusal fired no bun.lock can actually be present;
    // probed anyway to keep this a literal transcription of the router's
    // order. The binary lock shares the same routing precedence.
    if view.exists(BUN_LOCK).await {
        return Some((
            NpmLockFlavor::Bun,
            inventory_bun_in(view).await.unwrap_or_default(),
        ));
    }
    if view.exists(BUN_LOCKB).await {
        return Some((
            NpmLockFlavor::Bun,
            inventory_bun_binary_in(view).await.unwrap_or_default(),
        ));
    }
    // yarn.lock — router step 5, where classic vs berry is a content
    // decision. The router refused the lock because it declares neither
    // grammar; the read-only fallback reads it the way yarn does, through
    // the one grammar decision ([`yarn_grammar`]: a header-less lock is
    // classic). Berry PnP needs no carve-out: a PnP marker would have
    // refused at the router's step 1 with a code this fallback ignores.
    if view.exists("yarn.lock").await {
        let text = view.read_text("yarn.lock").await.unwrap_or_default();
        return Some(match yarn_grammar(&text) {
            YarnLockGrammar::Berry => (
                NpmLockFlavor::YarnBerry,
                inventory_yarn_berry_in(view).await.unwrap_or_default(),
            ),
            YarnLockGrammar::Classic => (
                NpmLockFlavor::YarnClassic,
                inventory_yarn_classic_in(view).await.unwrap_or_default(),
            ),
        });
    }
    // npm — router step 6 (`inventory_package_lock` itself prefers the
    // shrinkwrap when both exist, mirroring npm).
    if view.exists(NPM_LOCKS[0]).await || view.exists(NPM_LOCKS[1]).await {
        return Some((
            NpmLockFlavor::PackageLock,
            inventory_package_lock_in(view).await.unwrap_or_default(),
        ));
    }
    None
}

/// Guard + dedup the raw npm entries: unsafe names/versions are dropped
/// fail-closed ([`guard_npm`]); duplicate (name, version) instances collapse
/// to one, preferring the instance that carries a verifier.
#[cfg(test)]
pub(super) fn finalize_npm(raw: Vec<LockfileEntry>) -> Vec<LockfileEntry> {
    dedup_prefer_integrity(guard_npm(raw))
}

/// Drop raw npm entries whose name/version is unsafe, fail-closed.
fn guard_npm(raw: Vec<LockfileEntry>) -> Vec<LockfileEntry> {
    raw.into_iter()
        .filter(|e| npm_purl(&e.name, &e.version).is_some())
        .collect()
}
