//! `pnpm-lock.yaml` and Rush's pnpm locks: the registry view.

use std::path::Path;

use crate::utils::fs::read_regular_to_string;
use crate::vendor::path::parse_vendor_path;
use crate::vendor::pnpm_lock;

use super::recover::inline_yaml_field;
use super::{http_url, LockIntegrity, LockfileEntry};

pub(super) async fn inventory_pnpm_lock(root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_pnpm_lock_at(&root.join("pnpm-lock.yaml")).await
}

/// Inventory a specific `pnpm-lock.yaml` (path given explicitly so the Rush
/// fallback can point it at `common/config/rush/…` and subspace locks).
pub(super) async fn inventory_pnpm_lock_at(lock_path: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(lock_path).await.ok()?;
    let lines = pnpm_lock::split_lines(&text);
    let (start, end) = pnpm_lock::section_bounds(&lines, "packages")?;

    let mut out = Vec::new();
    let mut i = start + 1;
    while let Some(block) = pnpm_lock::next_block(&lines, i, end) {
        i = block.end;
        // Key grammar by lock generation: v9 `name@version`, v6 (pnpm 8)
        // the same behind a leading `/`, v5.4 (pnpm 7) `/name/version` —
        // names may be scoped (`@scope/name`) in all three. Peer suffixes:
        // v6/v9 append `(peer@1.2.3)…` after the version; v5 appends
        // `_peer@x`/`_<hash>` to the version itself.
        let trimmed = match block.key.find('(') {
            Some(p) => block.key[..p].trim_end(),
            None => block.key.as_str(),
        };
        let (base, legacy) = match trimmed.strip_prefix('/') {
            Some(stripped) => (stripped, true),
            None => (trimmed, false),
        };
        let Some((name, version)) = split_pnpm_key(base, legacy) else {
            continue;
        };
        // Only plain registry versions: `file:`/`link:`/`https:`/git specs
        // are not registry-resolvable.
        if !version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        let mut integrity = LockIntegrity::None;
        let mut tarball: Option<String> = None;
        let entry_lines = &lines[block.header + 1..block.end];
        for (j, line) in entry_lines.iter().enumerate() {
            let t = line.trim();
            let Some(rest) = t.strip_prefix("resolution:") else {
                continue;
            };
            if rest.trim().is_empty() {
                // shrinkwrap.yaml (pnpm <=2, shrinkwrapVersion 3) nests the
                // resolution as a BLOCK mapping —
                //     resolution:
                //       integrity: sha512-…
                // — where every pnpm-lock.yaml generation writes the inline
                // `resolution: {…}` flow map. Its fields are exactly the
                // following deeper-indented lines (a shallower or blank
                // line ends the mapping).
                let indent = pnpm_lock::indent_of(line);
                for child in &entry_lines[j + 1..] {
                    if child.trim().is_empty() || pnpm_lock::indent_of(child) <= indent {
                        break;
                    }
                    if let Some(v) = inline_yaml_field(child, "integrity:") {
                        integrity = LockIntegrity::Sri(v);
                    }
                    if let Some(v) = inline_yaml_field(child, "tarball:") {
                        tarball = Some(v);
                    }
                }
            } else {
                if let Some(v) = inline_yaml_field(rest, "integrity:") {
                    integrity = LockIntegrity::Sri(v);
                }
                tarball = inline_yaml_field(rest, "tarball:");
            }
            break;
        }
        // Our own vendored spec: not a registry dependency.
        if tarball
            .as_deref()
            .is_some_and(|t| parse_vendor_path(t).is_some())
        {
            continue;
        }
        out.push(LockfileEntry::npm(
            name,
            version,
            tarball.as_deref().and_then(http_url),
            integrity,
        ));
    }
    Some(out)
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
    let common_lock = project_root.join(crate::constants::npm_family::RUSH_COMMON_LOCK_REL);
    if let Some(entries) = inventory_pnpm_lock_at(&common_lock).await {
        out.extend(entries);
    }

    // Per-subspace locks, sorted for determinism.
    let subspaces_dir = project_root.join("common/config/subspaces");
    if let Ok(mut read_dir) = tokio::fs::read_dir(&subspaces_dir).await {
        let mut subspace_dirs: Vec<std::path::PathBuf> = Vec::new();
        while let Ok(Some(entry)) = read_dir.next_entry().await {
            if entry.file_type().await.is_ok_and(|t| t.is_dir()) {
                subspace_dirs.push(entry.path());
            }
        }
        subspace_dirs.sort();
        for dir in subspace_dirs {
            if let Some(entries) = inventory_pnpm_lock_at(&dir.join("pnpm-lock.yaml")).await {
                out.extend(entries);
            }
        }
    }
    out
}
