//! `bun.lock` / `bun.lockb`: the registry views.

use std::path::Path;

use crate::constants::npm_family::{BUN_LOCK, BUN_LOCKB};
use crate::formats::bun::{BunTextError, BunTextLock};
use crate::patch::redirect::hosted_url_version;
use crate::vendor::bun_lock_text::{self, BunEntry};
use crate::vendor::bun_lockb::BunLockb;

use super::view::{DiskSnapshot, ProjectView};
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

/// Whether bun installs from the text `bun.lock` rather than a binary
/// `bun.lockb` beside it — the ONE answer every Bun-aware path routes
/// through (inventory, hosted, vendored, GC, repair, lockfile discovery).
///
/// Bun opens `bun.lock` following symlinks and falls back to `bun.lockb`
/// only when that open fails with ENOENT, so this is `stat`, not `lstat`,
/// and only `NotFound` means absent: a dangling link leaves the binary
/// lock live (#735). An open that fails with anything but ENOENT — a
/// self-referencing link (ELOOP), a link through a regular file
/// (ENOTDIR), a link into an unreadable directory (EACCES) — shadows the
/// binary lock just like an entry bun finds but cannot read (a directory,
/// a FIFO): bun then ignores BOTH locks ("Ignoring lockfile"), so the
/// text lock is chosen and its guarded read refuses rather than wiring a
/// `bun.lockb` bun would not install from. (Bun 1.2.23 and 1.3.14,
/// `bun install --frozen-lockfile`.) An in-memory link has no target to
/// follow, so it keeps shadowing.
pub fn bun_text_lock_drives(view: &ProjectView<'_>) -> bool {
    match view {
        ProjectView::Disk(root) | ProjectView::Snapshot(DiskSnapshot { root, .. }) => {
            match std::fs::metadata(root.join(BUN_LOCK)) {
                Ok(_) => true,
                Err(error) => error.kind() != std::io::ErrorKind::NotFound,
            }
        }
        ProjectView::Memory(project) => project.contains(BUN_LOCK) || project.is_dir(BUN_LOCK),
    }
}

/// Whether the binary `bun.lockb` is the lock bun installs from: present,
/// and not shadowed by [`bun_text_lock_drives`].
pub fn bun_binary_lock_drives(root: &Path) -> bool {
    !bun_text_lock_drives(&ProjectView::Disk(root)) && root.join(BUN_LOCKB).exists()
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
            let Some(version) = package.version else {
                let version = hosted_url_version(&package.resolution, &package.name)?;
                return Some(hosted_pin(&package.name, version));
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
    Some(hosted_pin(name, hosted_url_version(url, name)?))
}

/// The registry identity of a bun hosted pin, and nothing else. The pin's
/// URL and sha512 name the PATCHED artifact, so neither is a pristine
/// source a registry fetch could use, and this view cannot tell a Socket
/// host from a foreign one (that is the hosted-origin policy lockfile
/// discovery applies): a recorded URL carrying a uuid would read as proof
/// that a redirect ledger record is live (`vex::discover`). Like a yarn
/// berry hosted pin, the entry carries no location and no verifier.
fn hosted_pin(name: &str, version: &str) -> LockfileEntry {
    LockfileEntry::npm(name, version, None, LockIntegrity::None)
}
