//! `bun.lock` / `bun.lockb`: the registry views.

use std::path::Path;

use crate::constants::npm_family::{BUN_LOCK, BUN_LOCKB};
use crate::formats::bun::{BunTextError, BunTextLock};
use crate::patch::redirect::hosted_url_version;
use crate::vendor::bun_lock_text::{self, BunEntry};
use crate::vendor::bun_lockb::BunLockb;

use super::view::ProjectView;
use super::{http_url, LockIntegrity, LockfileEntry, UnsupportedNpmLayout};

/// Every `packages` entry of a text `bun.lock`, read with the ONE
/// fail-closed line grammar the hosted and vendored backends splice with
/// ([`bun_lock_text`]): the version head gated by
/// [`bun_lock_text::check_lock_version`], then each single-line
/// `"key": [tuple]` entry with its raw (JSON-encoded, trimmed) tuple
/// elements. `Err` is the user-facing refusal detail (it names the file): a
/// lock the backends refuse — a hand re-indented one included — is one
/// neither the inventory nor lockfile discovery reads.
pub(crate) fn bun_text_entries(text: &str) -> Result<Vec<BunEntry>, String> {
    match BunTextLock::parse(text) {
        Ok(lock) => Ok(lock.entries),
        Err(BunTextError::Version(detail)) => Err(detail),
        Err(BunTextError::Packages(e)) => Err(format!("{BUN_LOCK}: {e}")),
    }
}

// ── file selection ──

/// Whether the project root has a text `bun.lock` (lstat, so a dangling
/// symlink counts): bun reads it whenever it exists, so the binary
/// `bun.lockb` beside it is not the live lock. Lockfile discovery answers
/// the same question with `DiscoverCtx::exists` (the same lstat).
pub(crate) async fn bun_text_lock_present(root: &Path) -> bool {
    bun_text_lock_present_in(&ProjectView::Disk(root)).await
}

/// [`bun_text_lock_present`] over a [`ProjectView`].
pub(crate) async fn bun_text_lock_present_in(view: &ProjectView<'_>) -> bool {
    view.exists_no_follow(BUN_LOCK).await
}

// ── registry view ──

pub(super) async fn inventory_bun_binary_in(
    view: &ProjectView<'_>,
) -> Result<Vec<LockfileEntry>, UnsupportedNpmLayout> {
    let invalid = |detail: String| UnsupportedNpmLayout {
        code: "bun_lockb_invalid",
        detail: format!("cannot inventory bun.lockb: {detail}"),
    };
    let bytes = view
        .read_bytes(BUN_LOCKB)
        .await
        .map_err(|error| invalid(error.to_string()))?;
    let packages = BunLockb::parse_packages(&bytes).map_err(invalid)?;
    Ok(packages
        .into_iter()
        .filter_map(|package| {
            // Only resolved registry versions participate, plus a hosted
            // pin: a tarball record whose URL leaf names the package's own
            // `<name>-<version>.tgz` (#720). Workspace, file and git sources
            // have no registry version; a local vendored tarball's pristine
            // metadata is recovered from its wiring ledger instead.
            let version = match package.version {
                Some(version) => version,
                None => hosted_url_version(&package.resolution, &package.name)?.to_string(),
            };
            if !version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return None;
            }
            Some(LockfileEntry::npm(
                package.name,
                version,
                http_url(&package.resolution),
                package
                    .integrity
                    .map(LockIntegrity::Sri)
                    .unwrap_or(LockIntegrity::None),
            ))
        })
        .collect())
}

#[cfg(test)]
pub(super) async fn inventory_bun(root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_bun_in(&ProjectView::Disk(root)).await
}

pub(super) async fn inventory_bun_in(view: &ProjectView<'_>) -> Option<Vec<LockfileEntry>> {
    let text = view.read_text(BUN_LOCK).await.ok()?;
    let entries = bun_text_entries(&text).ok()?;

    let mut out = Vec::new();
    for entry in entries {
        if let Some(hosted) = hosted_pin_entry(&entry) {
            out.push(hosted);
            continue;
        }
        // Registry entries are 4-tuples `[spec, registry, {deps}, sha512]`;
        // our vendored 3-tuples and other shapes are skipped.
        if entry.elems.len() != 4 || !entry.elems[2].starts_with('{') {
            continue;
        }
        let Some(spec) = entry
            .elems
            .first()
            .and_then(|e| bun_lock_text::decode_json_string(e))
        else {
            continue;
        };
        let Some((name, version)) = bun_lock_text::split_name_spec(&spec) else {
            continue;
        };
        if !version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        let Some(registry) = bun_lock_text::decode_json_string(&entry.elems[1]) else {
            continue;
        };
        let Some(integrity) = bun_lock_text::decode_json_string(&entry.elems[3]) else {
            continue;
        };
        // elem[1] is `""` for the default registry; a full `.tgz` URL is
        // used verbatim; any other base falls back to conventional URL
        // construction (the integrity check still gates the content).
        let resolved = (registry.ends_with(".tgz"))
            .then(|| http_url(&registry))
            .flatten();
        out.push(LockfileEntry::npm(
            name,
            version,
            resolved,
            LockIntegrity::Sri(integrity),
        ));
    }
    Some(out)
}

/// A hosted redirect's pin of a registry package: the URL tuple
/// `["name@https://…/<bare>-<version>.tgz", {deps}, "sha512-…"]` the hosted
/// text rewriter writes (the 2-tuple without the sha512 when Bun < 1.3.10
/// re-saved it). The version is the URL leaf's (`hosted_url_version`, the
/// rule lockfile discovery reads bun hosted refs by), so a lockfile-only
/// re-run still sees the package (#720), as the pnpm, vlt and yarn berry
/// views do. Our vendored 3-tuples carry a relative path, never an
/// http(s) URL, and stay out.
fn hosted_pin_entry(entry: &BunEntry) -> Option<LockfileEntry> {
    if !(2..=3).contains(&entry.elems.len()) || !entry.elems[1].starts_with('{') {
        return None;
    }
    let spec = bun_lock_text::decode_json_string(&entry.elems[0])?;
    let (name, url) = bun_lock_text::split_name_spec(&spec)?;
    let version = hosted_url_version(url, name)?;
    let integrity = match entry.elems.get(2) {
        Some(raw) => LockIntegrity::Sri(bun_lock_text::decode_json_string(raw)?),
        None => LockIntegrity::None,
    };
    Some(LockfileEntry::npm(name, version, http_url(url), integrity))
}
