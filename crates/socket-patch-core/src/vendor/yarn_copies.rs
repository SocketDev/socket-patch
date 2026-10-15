//! The yarn lock entries a vendored wiring of `name@version` cannot reach
//! because they install a copy of it under ANOTHER dependency name (#939,
//! #1236), shared by the classic and berry backends.
//!
//! Yarn keys a `file:` tarball or directory, a url tarball and a berry
//! `portal:` / `link:` dependency by the name the depender gave it
//! (`lp2@file:./left-pad-1.3.0.tgz`), so a re-lock or `resolutions` entry
//! for `left-pad` never moves it, and `node_modules/lp2` keeps the
//! unpatched left-pad bytes. Which package such a copy is comes from the
//! copy itself ([`CopyRef::identity`]), read exactly as lockfile discovery
//! reads it, so the scan names every copy `vex` refuses to attest beside.

use std::path::Path;

use crate::formats::yarn::blocks::{berry_field, classic_field};
use crate::formats::yarn::copy::{berry_copy_ref, classic_copy_ref, CopyRef};
use crate::formats::yarn::is_berry_lock;
use crate::formats::yarn::patterns::classic_key_real_name;
use crate::formats::yarn::source::{classic_copy_source, CopySource};
use crate::utils::fs::read_regular_to_bytes;

use super::lock_inventory::yarn::{berry_entries, classic_entries};
use super::lock_inventory::ProjectView;

/// A lock entry under another dependency name that installs, or may
/// install, `name@version` ([`other_name_copies`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OtherNameCopy {
    /// The lock entry's key, as the lock spells it.
    pub(crate) key: String,
    pub(crate) source: CopyRef,
    /// The copy itself says it is `name@version`. `false` for a copy of
    /// that version whose package cannot be read (a missing directory, a
    /// tarball with no readable `package.json`, a non-registry url, or an
    /// unread `portal:` / `link:` directory of any version): it may be
    /// `name`, so it is named, but never taken as proof that `name` is
    /// installed (#1516, #1540).
    pub(crate) identified: bool,
}

/// Every live entry of `lock_text` (either grammar) that installs
/// `name@version` under another dependency name, in lock order. A copy of
/// that version whose package cannot be read is kept, unidentified: it
/// may hold `name`, and leaving it out would let the scan and `vex` vouch
/// for a lock that installs it unpatched (#1516). So is a `portal:` /
/// `link:` copy whose package is unknown ([`linked_copy_unknown`]): its
/// version is its manifest's, so it may be `version` too (#1540, #1561).
/// One that holds no versioned package (a `link:` to a plain directory) is
/// left out.
pub(crate) async fn other_name_copies(
    project_root: &Path,
    lock_text: &str,
    name: &str,
    version: &str,
) -> Vec<OtherNameCopy> {
    let candidates: Vec<(String, CopyRef, String)> = if is_berry_lock(lock_text) {
        berry_entries(lock_text)
            .entries
            .into_iter()
            .filter(|e| e.live)
            .filter_map(|e| {
                let locator = e.locator()?;
                if locator.name == name {
                    return None;
                }
                let source = berry_copy_ref(locator.reference)?;
                let lock_version = berry_field(&e.block.lines, "version")?.to_string();
                Some((e.block.key.clone(), source, lock_version))
            })
            .collect()
    } else {
        classic_entries(lock_text)
            .into_iter()
            .filter(|e| e.live && classic_key_real_name(&e.patterns) != Some(name))
            .filter_map(|e| {
                let resolved = classic_field(&e.block.lines, "resolved");
                // A registry block under another name is an `npm:` alias
                // (named by the alias warnings); a git block names no
                // package in the lock.
                if !matches!(
                    classic_copy_source(&e.patterns, resolved),
                    CopySource::Directory | CopySource::RemoteTarball
                ) {
                    return None;
                }
                let source = classic_copy_ref(&e.patterns, resolved)?;
                let lock_version = classic_field(&e.block.lines, "version")?.to_string();
                Some((e.block.key.clone(), source, lock_version))
            })
            .collect()
    };
    let mut out = Vec::new();
    for (key, source, lock_version) in candidates {
        // Only a `portal:` / `link:` copy needs its manifest for the
        // version; any other copy of another version is no copy of this
        // one, and is never read (a `file:` tarball is unpacked to read).
        if !matches!(source, CopyRef::Linked(_)) && lock_version != version {
            continue;
        }
        // A path into `.socket/` is socket-patch's own wiring, which
        // discovery attributes as such, never a user's copy.
        if source
            .read_path()
            .is_some_and(|rel| rel.starts_with(".socket/"))
        {
            continue;
        }
        let bytes = match source.read_path() {
            Some(rel) => read_regular_to_bytes(&project_root.join(rel)).await.ok(),
            None => None,
        };
        let read = bytes.is_some();
        let identified = match copy_identity(&source, &lock_version, bytes).await {
            Some((n, v)) if n == name && v == version => true,
            Some(_) => continue,
            None if matches!(source, CopyRef::Linked(_))
                && !linked_copy_unknown(ProjectView::Disk(project_root), &source, read).await =>
            {
                continue
            }
            None => false,
        };
        out.push(OtherNameCopy {
            key,
            source,
            identified,
        });
    }
    out
}

/// Whether a `portal:` / `link:` copy whose manifest named no versioned
/// package may be any version of any package, given whether its
/// `package.json` was `read`. Its lock version is the placeholder
/// `0.0.0-use.local`, so only that manifest says what it is. One never
/// read (an absolute path, #1540) is unknown, and so is one whose target
/// can't be read: a missing directory (a git submodule CI never checked
/// out, a generated or gitignored directory) or a `package.json` that is
/// no readable regular file (#1561). Only a directory that exists with no
/// `package.json` at all (a `link:` to plain assets), or a manifest read
/// and found to name no versioned package, is no package copy.
pub(crate) async fn linked_copy_unknown(
    view: ProjectView<'_>,
    source: &CopyRef,
    read: bool,
) -> bool {
    let CopyRef::Linked(dir) = source else {
        return false;
    };
    if source.is_unread_linked() {
        return true;
    }
    if read {
        return false;
    }
    let Some(manifest) = source.read_path() else {
        return true;
    };
    let dir = if dir.is_empty() { "." } else { dir.as_str() };
    !view.is_dir(dir) || view.exists_no_follow(&manifest).await
}

/// [`CopyRef::identity`] off the async runtime when it unpacks a tarball (a
/// user's `file:` tarball can be large); lockfile discovery reads copies
/// through it too.
pub(crate) async fn copy_identity(
    source: &CopyRef,
    lock_version: &str,
    bytes: Option<Vec<u8>>,
) -> Option<(String, String)> {
    if !matches!(source, CopyRef::Tarball(_)) {
        return source.identity(lock_version, bytes.as_deref());
    }
    let source = source.clone();
    let lock_version = lock_version.to_string();
    tokio::task::spawn_blocking(move || source.identity(&lock_version, bytes.as_deref()))
        .await
        .ok()
        .flatten()
}

/// Where a copy installs from, for a vendored warning.
pub(crate) fn copy_origin(source: &CopyRef) -> &'static str {
    match source {
        CopyRef::Tarball(_) => "a file: tarball",
        CopyRef::Directory(_) => "a file: directory, which yarn copies into node_modules",
        CopyRef::Linked(_) => "a portal:/link: directory, which yarn links into node_modules",
        CopyRef::Url(_) => "a URL tarball",
    }
}
