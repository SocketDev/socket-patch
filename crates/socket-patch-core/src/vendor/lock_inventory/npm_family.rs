//! npm-family routing: which lock the project's npm-family package manager
//! installs from ([`inventory_npm_lock`]), the migration-leftover sibling
//! probe, and the shared name/version guard + dedup of npm entries.

#[cfg(test)]
use std::path::Path;

use crate::constants::npm_family::{BUN_LOCK, PNPM_SHRINKWRAP_LEGACY};
use crate::formats::governing_locks::{npm_governing_family, npm_lock_files, NpmLockFamily};
use crate::formats::yarn::{grammar as yarn_grammar, YarnLockGrammar};
use crate::origin::hosted_patch_uuid;
use crate::utils::pnpm_workspace::lockfile_disabled;
use crate::utils::purl::npm_purl;
use crate::vendor::npm_flavor::NpmLockFlavor;

use super::bun::{bun_text_lock_drives, inventory_bun_binary_in, inventory_bun_in};
#[cfg(test)]
use super::dedup_prefer_integrity;
use super::npm::{invalid_package_lock_in, inventory_package_lock_in};
use super::pnpm::{
    inventory_pnpm_lock_in, inventory_pnpm_lock_rel_in, inventory_pnpm_member_locks_in,
    inventory_rush_pnpm_locks_in, is_rush,
};
use super::view::ProjectView;
use super::vlt::inventory_vlt_in;
use super::yarn::{inventory_yarn_berry_in, inventory_yarn_classic_in};
use super::{LockIntegrity, LockfileEntry, UnsupportedNpmLayout};
use crate::vendor::npm_flavor::detect_npm_lock_flavor_in;

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
/// the pnpm <=2-era `shrinkwrap.yaml` (same v5 grammar, older filename) or,
/// failing that, the workspace members' own locks. A pnpm workspace with
/// `sharedWorkspaceLockfile: false` reads those beside its root lock
/// ([`inventory_pnpm_member_locks_in`], #492). The flavor names that
/// routed lock; Rush's locks, which no flavor routes, are read beside it by
/// [`inventory_npm_trees_raw_in`].
#[cfg(test)]
pub(crate) async fn inventory_npm_lock(
    project_root: &Path,
) -> Result<Option<(NpmLockFlavor, Vec<LockfileEntry>)>, UnsupportedNpmLayout> {
    let view = ProjectView::Disk(project_root);
    let rush = is_rush(view).await;
    inventory_npm_lock_raw_in(&view, rush)
        .await
        .map(|found| found.map(|(flavor, raw)| (flavor, dedup_prefer_integrity(raw))))
}

/// Every npm-family tree the inventory reads, collapsed: what
/// [`super::inventory_project`] lists for npm.
#[cfg(test)]
pub(crate) async fn inventory_npm_trees(
    project_root: &Path,
) -> Result<Vec<LockfileEntry>, UnsupportedNpmLayout> {
    inventory_npm_trees_raw_in(&ProjectView::Disk(project_root))
        .await
        .map(dedup_prefer_integrity)
}

/// Every guarded npm-family instance, uncollapsed: the routed lock
/// ([`inventory_npm_lock`]) and, whenever `rush.json` is present, Rush's
/// common and subspace locks, separate install trees beside it as hosted
/// mode and lockfile discovery read them (before: only when the root had
/// no lock; lock-model divergence N12).
pub(super) async fn inventory_npm_trees_raw_in(
    view: &ProjectView<'_>,
) -> Result<Vec<LockfileEntry>, UnsupportedNpmLayout> {
    let rush = is_rush(*view).await;
    let mut out = inventory_npm_lock_raw_in(view, rush)
        .await?
        .map(|(_, entries)| entries)
        .unwrap_or_default();
    if rush {
        out.extend(guard_npm(inventory_rush_pnpm_locks_in(view).await));
    }
    Ok(out)
}

/// The routed lock's guarded instances ([`inventory_npm_lock`] before its
/// collapse). With pnpm's `lockfile` setting off ([`lockfile_disabled`];
/// not under Rush, `rush` being [`is_rush`], the gate discovery shares, which runs
/// pnpm with settings of its own, as in lockfile discovery's
/// `extract_pnpm`), pnpm neither reads nor writes the root or member
/// locks, so a Socket-hosted pin in them is no lockfile basis. Discovery
/// keeps such a ref but withholds its lock pin; here the entry stays
/// listed (what it names is still the dependency set, and its hosted url
/// still shows ledger liveness the wiring) with its integrity dropped, so
/// nothing verifies or fetches against the pin (N14). Registry entries
/// keep theirs: a registry release's integrity is its content verifier
/// whether or not pnpm reads the lock.
async fn inventory_npm_lock_raw_in(
    view: &ProjectView<'_>,
    rush: bool,
) -> Result<Option<(NpmLockFlavor, Vec<LockfileEntry>)>, UnsupportedNpmLayout> {
    let mut found = inventory_npm_router_lock_raw_in(view).await?;
    if let Some((NpmLockFlavor::Pnpm | NpmLockFlavor::PnpmLegacy, entries)) = &mut found {
        // The settings are read only for a lock that pins something.
        if !rush && entries.iter().any(is_hosted) && lockfile_disabled(view, false).await.is_some()
        {
            for entry in entries.iter_mut().filter(|e| is_hosted(e)) {
                entry.integrity = LockIntegrity::None;
            }
        }
    }
    Ok(found)
}

/// Whether `entry` resolves from Socket's patch server (see
/// [`inventory_npm_lock_raw_in`]).
fn is_hosted(entry: &LockfileEntry) -> bool {
    entry
        .resolved
        .as_deref()
        .and_then(|url| hosted_patch_uuid(url, &[]))
        .is_some()
}

/// The lock the npm flavor router picks, with its fallbacks (see
/// [`inventory_npm_lock`]).
async fn inventory_npm_router_lock_raw_in(
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
                // pnpm 7 under `shared-workspace-lockfile=false` writes no
                // root lock at all, only the members' own (#492).
                let members = inventory_pnpm_member_locks_in(view).await;
                if !members.is_empty() {
                    return Ok(Some((NpmLockFlavor::Pnpm, guard_npm(members))));
                }
            }
            // Rush's locks are read by the caller, whatever the probe says.
            return Ok(None);
        }
    };
    let raw = match flavor {
        NpmLockFlavor::PackageLock => match inventory_package_lock_in(view).await {
            Some(entries) => Some(entries),
            // A lock that is not JSON is unreadable, not empty: say so.
            None => match invalid_package_lock_in(view).await {
                Some(diagnosis) => return Err(diagnosis),
                None => None,
            },
        },
        // The pnpm reader is grammar-agnostic (it also serves legacy
        // 5.4/6.0 locks through the version-refusal fallback above), so
        // both pnpm flavors share it.
        // Under `sharedWorkspaceLockfile: false` the members install from
        // their own locks, read beside the root's (#492).
        NpmLockFlavor::Pnpm | NpmLockFlavor::PnpmLegacy => {
            let root = inventory_pnpm_lock_in(view).await;
            let members = inventory_pnpm_member_locks_in(view).await;
            if members.is_empty() {
                root
            } else {
                Some(root.into_iter().flatten().chain(members).collect())
            }
        }
        NpmLockFlavor::YarnClassic => inventory_yarn_classic_in(view).await,
        NpmLockFlavor::YarnBerry => inventory_yarn_berry_in(view).await,
        NpmLockFlavor::Bun => {
            if bun_text_lock_drives(view) {
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
/// [`detect_npm_lock_flavor_in`] cannot be re-asked (it already refused on
/// its pnpm step), so this asks the shared precedence table
/// ([`npm_governing_family`]) for the family the router would have chosen
/// with pnpm skipped, on file EXISTENCE, and returns that family's
/// inventory (possibly empty: presence alone proves the pnpm lock is
/// migration debris, so the caller must not fall back to it). Raw entries —
/// the caller guards and collapses them.
pub(super) async fn inventory_live_sibling_lock_in(
    view: &ProjectView<'_>,
) -> Option<(NpmLockFlavor, Vec<LockfileEntry>)> {
    // A `bun.lock` that exists but can't be stat'd (dangling symlink,
    // ELOOP, EACCES) still shadows `bun.lockb` for Bun, so its presence
    // comes from the same predicate the router uses.
    let bun_text = bun_text_lock_drives(view);
    let mut present = Vec::new();
    for file in npm_lock_files() {
        let here = if file == BUN_LOCK {
            bun_text
        } else {
            view.exists(file).await
        };
        if here {
            present.push(file);
        }
    }
    let family = npm_governing_family(|file| present.contains(&file), Some(NpmLockFamily::Pnpm))?;
    Some(match family {
        NpmLockFamily::Vlt => (
            NpmLockFlavor::Vlt,
            inventory_vlt_in(view).await.unwrap_or_default(),
        ),
        // The router's bun step runs BEFORE its pnpm sniff, so when the
        // version refusal fired no bun lock can actually be present; kept
        // for the table's sake. The text lock wins over the binary one.
        NpmLockFamily::Bun if bun_text => (
            NpmLockFlavor::Bun,
            inventory_bun_in(view).await.unwrap_or_default(),
        ),
        NpmLockFamily::Bun => (
            NpmLockFlavor::Bun,
            inventory_bun_binary_in(view).await.unwrap_or_default(),
        ),
        // Classic vs berry is a content decision in the router. The router
        // refused the lock because it declares neither grammar; the
        // read-only fallback reads it the way yarn does, through the one
        // grammar decision ([`yarn_grammar`]: a header-less lock is
        // classic). Berry PnP needs no carve-out: a PnP marker would have
        // refused at the router's step 1 with a code this fallback ignores.
        NpmLockFamily::Yarn => {
            let text = view.read_text("yarn.lock").await.unwrap_or_default();
            match yarn_grammar(&text) {
                YarnLockGrammar::Berry => (
                    NpmLockFlavor::YarnBerry,
                    inventory_yarn_berry_in(view).await.unwrap_or_default(),
                ),
                YarnLockGrammar::Classic => (
                    NpmLockFlavor::YarnClassic,
                    inventory_yarn_classic_in(view).await.unwrap_or_default(),
                ),
            }
        }
        // `inventory_package_lock` itself prefers the shrinkwrap when both
        // exist, mirroring npm.
        NpmLockFamily::Npm => (
            NpmLockFlavor::PackageLock,
            inventory_package_lock_in(view).await.unwrap_or_default(),
        ),
        // Skipped by the query above.
        NpmLockFamily::Pnpm => return None,
    })
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
