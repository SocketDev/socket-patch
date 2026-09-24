//! `pnpm-lock.yaml` (every generation, pnpm <= 2's `shrinkwrap.yaml`) and
//! Rush's pnpm locks: the entry model lockfile discovery shares
//! ([`pnpm_packages`], [`classify_pnpm_key`]), Rush's lock enumeration and
//! the registry view.

use std::path::Path;

use crate::constants::npm_family::{PNPM_LOCK, RUSH_COMMON_LOCK_REL, RUSH_SUBSPACES_DIR};
use crate::patch::path_safety::is_safe_single_segment;
use crate::patch::redirect::pnpm;
use crate::utils::fs::read_regular_to_string;
use crate::vendor::path::parse_vendor_path;

use super::{http_url, LockIntegrity, LockfileEntry};

// ── entry model ──

/// One `packages:` entry of a pnpm lock, read with the hosted rewriter's
/// own grammar ([`pnpm::entries`] / [`pnpm::resolution`]: two-space keys, a
/// flat flow or block `resolution:` map, CRLF included).
pub(crate) struct PnpmPackage<'a> {
    /// The packages key, trimmed and unquoted.
    pub(crate) key: &'a str,
    pub(crate) entry: pnpm::Entry<'a>,
    /// The entry's `resolution:` map; `None` when it has none or the
    /// grammar refuses it (duplicate keys, nested values, aliases).
    pub(crate) resolution: Option<pnpm::Resolution<'a>>,
}

impl<'a> PnpmPackage<'a> {
    /// The unquoted tokens of the entry's raw `resolution:` text
    /// ([`pnpm::resolution_raw_lines`] split on whitespace and flow
    /// punctuation) — what a reader inspects when the grammar refused the
    /// map (`resolution` is `None`) and it must still tell a Socket-shaped
    /// value from anything else.
    pub(crate) fn resolution_tokens(&self) -> Vec<&'a str> {
        pnpm::resolution_raw_lines(&self.entry)
            .into_iter()
            .flat_map(|text| {
                text.split(|c: char| c.is_whitespace() || matches!(c, ',' | '{' | '}' | '[' | ']'))
            })
            .map(|token| pnpm::unquote(token.trim()))
            .filter(|token| !token.is_empty())
            .collect()
    }
}

/// Every `packages:` entry of a pnpm lock text, in lock order — the ONE
/// entry walk the lock inventory and lockfile discovery
/// (`vex::discover::npm`) share. Every entry is returned (registry, rekeyed
/// vendored, hosted, directory, git); each consumer applies its own key and
/// resolution rules.
pub(crate) fn pnpm_packages(text: &str) -> Vec<PnpmPackage<'_>> {
    pnpm::entries(text)
        .into_iter()
        .map(|entry| PnpmPackage {
            key: pnpm::unquote(entry.key.trim()),
            resolution: pnpm::resolution(&entry),
            entry,
        })
        .collect()
}

/// How a pnpm packages key names its package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PnpmKey<'a> {
    /// A registry key in any lock generation ([`pnpm_registry_key`]).
    Registry { name: &'a str, version: &'a str },
    /// v9's rekeyed vendored entry `name@file:<rel>` (`vendor::pnpm_lock`);
    /// `path` is the raw `file:<rel>` spec, peer suffix stripped.
    V9File { name: &'a str, path: &'a str },
    /// v5.4 / v6.0's rekeyed vendored entry, the bare `file:<rel>` key
    /// (`vendor::pnpm_lock_legacy`); the name is on the entry's `name:`
    /// line.
    LegacyFile { path: &'a str },
    /// Anything else (url, git, `link:`, v5 non-default-registry keys).
    Other,
}

/// Classify a packages key, in this order: a legacy `file:` key, a v9
/// `name@file:` key (the `@` after a scope's leading one), a registry key,
/// else [`PnpmKey::Other`]. The `file:` paths are returned raw — the CALLER
/// anchors them (lockfile discovery with its root-anchored `vendor_ref`,
/// the writers with `parse_vendor_path`).
pub(crate) fn classify_pnpm_key(key: &str) -> PnpmKey<'_> {
    let base = strip_pnpm_peer_suffix(key);
    if base.starts_with("file:") {
        PnpmKey::LegacyFile { path: base }
    } else if let Some(at) = base.get(1..).and_then(|rest| rest.find("@file:")) {
        PnpmKey::V9File {
            name: &base[..at + 1],
            path: &base[at + 2..],
        }
    } else {
        match pnpm_registry_key(base) {
            Some((name, version)) => PnpmKey::Registry { name, version },
            None => PnpmKey::Other,
        }
    }
}

/// A pnpm packages key without its v6+ peer suffix (`(peer@1.0.0)…`).
pub(crate) fn strip_pnpm_peer_suffix(key: &str) -> &str {
    key.find('(').map_or(key, |p| key[..p].trim_end())
}

/// `(name, version)` of a REGISTRY-form pnpm packages key, in every lock
/// generation's grammar — v9 `name@version`, v6 (pnpm 8) the same behind a
/// leading `/`, v5.4 (pnpm 7) and shrinkwrap `/name/version`; names may be
/// scoped in all of them. Peer suffixes are stripped: v6/v9 append
/// `(peer@1.2.3)…` after the version, v5 appends `_peer@x` / `_<hash>` to
/// the version itself. `None` for anything that is not a plain registry
/// version (digit-first): `file:` / `link:` / url / git keys and v5
/// non-default-registry keys. The ONE key rule the lock inventory and
/// lockfile discovery (`vex::discover::npm`) share, so both read a key as
/// the same package.
pub(crate) fn pnpm_registry_key(key: &str) -> Option<(&str, &str)> {
    let base = strip_pnpm_peer_suffix(key);
    let (base, legacy) = match base.strip_prefix('/') {
        Some(stripped) => (stripped, true),
        None => (base, false),
    };
    let (name, version) = split_pnpm_key(base, legacy)?;
    let version = version.split('_').next().unwrap_or(version);
    version
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_digit())
        .then_some((name, version))
}

/// Split a peer-paren-stripped, slash-stripped pnpm packages key into
/// `(name, version)`; `None` is skipped by the caller, never guessed.
/// `legacy` marks a key that carried the v5/v6 leading `/` — only those may
/// use the v5 `name/version` grammar. What tells v5 `/@scope/name/1.2.3`
/// apart from v6 `/@scope/name@1.2.3` is the segment after the last `/`:
/// a v5 version (its `_peer`/`_hash` suffix dropped) starts with a digit
/// and never contains `@`, while a v6 scoped key's trailing segment is
/// `name@version`. v5 non-default-registry keys (`example.com/name/1.2.3`)
/// carry no leading `/` and fall through to the `@` split, where they are
/// dropped fail-closed downstream.
fn split_pnpm_key(base: &str, legacy: bool) -> Option<(&str, &str)> {
    if legacy {
        if let Some((name, rest)) = base.rsplit_once('/') {
            let version = rest.split('_').next().unwrap_or(rest);
            if !name.is_empty()
                && version.chars().next().is_some_and(|c| c.is_ascii_digit())
                && !version.contains('@')
            {
                return Some((name, version));
            }
        }
    }
    let at = base.rfind('@').filter(|&p| p > 0)?;
    Some((&base[..at], &base[at + 1..]))
}

// ── file selection ──

/// A Rush monorepo's pnpm locks, root-relative, in lockfile discovery's
/// order: the single source-of-truth lock
/// ([`RUSH_COMMON_LOCK_REL`]), then every subspace's
/// `common/config/subspaces/<name>/pnpm-lock.yaml`, sorted by name — real
/// directories only (a symlinked subspace dir could point the read outside
/// the project) with traversal-safe UTF-8 names. Stat / list only; whether
/// the project IS a Rush monorepo (`rush.json`) is the caller's check.
pub(crate) async fn rush_lock_rels(root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(mut dir) = tokio::fs::read_dir(root.join(RUSH_SUBSPACES_DIR)).await {
        while let Ok(Some(entry)) = dir.next_entry().await {
            if !entry.file_type().await.is_ok_and(|t| t.is_dir()) {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                if is_safe_single_segment(name) {
                    names.push(name.to_string());
                }
            }
        }
    }
    names.sort();
    let mut rels = vec![RUSH_COMMON_LOCK_REL.to_string()];
    rels.extend(
        names
            .into_iter()
            .map(|name| format!("{RUSH_SUBSPACES_DIR}/{name}/{PNPM_LOCK}")),
    );
    rels
}

// ── registry view ──

pub(super) async fn inventory_pnpm_lock(root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_pnpm_lock_at(&root.join(PNPM_LOCK)).await
}

/// Inventory a specific `pnpm-lock.yaml` (path given explicitly so the Rush
/// fallback can point it at `common/config/rush/…` and subspace locks).
/// Entries come from the shared entry model ([`pnpm_packages`] — the walk
/// lockfile discovery uses too): flow and block `resolution:` maps, every
/// key generation ([`pnpm_registry_key`]), CRLF included. A resolution the
/// grammar refuses leaves the entry listed without a verifier. `None` when
/// the lock has no `packages:` section.
pub(super) async fn inventory_pnpm_lock_at(lock_path: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(lock_path).await.ok()?;
    if !text
        .lines()
        .any(|l| l.trim_end_matches('\r') == "packages:")
    {
        return None;
    }
    let mut out = Vec::new();
    for package in pnpm_packages(&text) {
        // Only plain registry versions: `file:`/`link:`/`https:`/git specs
        // are not registry-resolvable.
        let Some((name, version)) = pnpm_registry_key(package.key) else {
            continue;
        };
        let resolution = package.resolution;
        let integrity = resolution
            .as_ref()
            .and_then(|r| r.integrity())
            .map(|i| LockIntegrity::Sri(i.to_string()))
            .unwrap_or(LockIntegrity::None);
        let tarball = resolution.as_ref().and_then(|r| r.tarball());
        // Our own vendored spec: not a registry dependency.
        if tarball.is_some_and(|t| parse_vendor_path(t).is_some()) {
            continue;
        }
        out.push(LockfileEntry::npm(
            name,
            version,
            tarball.and_then(http_url),
            integrity,
        ));
    }
    Some(out)
}

/// Inventory a Rush monorepo's pnpm locks. Rush keeps a single
/// source-of-truth lock at `common/config/rush/pnpm-lock.yaml` and, when
/// subspaces are enabled, one lock per subspace under
/// `common/config/subspaces/<name>/pnpm-lock.yaml`. `rush install` copies
/// the source lock into common/temp and runs pnpm there.
///
/// Only called (via [`inventory_npm_lock`]) when there is NO root lock but
/// `rush.json` is present, so it never shadows a plain pnpm project. The
/// subspace directory is read sorted for deterministic output. Missing
/// files/dirs are skipped fail-soft; the caller drops the whole result when
/// it comes back empty.
pub(super) async fn inventory_rush_pnpm_locks(project_root: &Path) -> Vec<LockfileEntry> {
    if tokio::fs::metadata(project_root.join("rush.json"))
        .await
        .is_err()
    {
        return Vec::new();
    }
    let mut out = Vec::new();

    // The single source-of-truth lock.
    let common_lock = project_root.join(RUSH_COMMON_LOCK_REL);
    if let Some(entries) = inventory_pnpm_lock_at(&common_lock).await {
        out.extend(entries);
    }

    // Per-subspace locks, sorted for determinism.
    let subspaces_dir = project_root.join(RUSH_SUBSPACES_DIR);
    if let Ok(mut read_dir) = tokio::fs::read_dir(&subspaces_dir).await {
        let mut subspace_dirs: Vec<std::path::PathBuf> = Vec::new();
        while let Ok(Some(entry)) = read_dir.next_entry().await {
            if entry.file_type().await.is_ok_and(|t| t.is_dir()) {
                subspace_dirs.push(entry.path());
            }
        }
        subspace_dirs.sort();
        for dir in subspace_dirs {
            if let Some(entries) = inventory_pnpm_lock_at(&dir.join(PNPM_LOCK)).await {
                out.extend(entries);
            }
        }
    }
    out
}
