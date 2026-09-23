//! `bun.lock` / `bun.lockb`: the registry views.

use std::path::Path;

use crate::constants::npm_family::{BUN_LOCK, BUN_LOCKB};
use crate::utils::fs::{read_regular_to_bytes, read_regular_to_string};
use crate::vendor::bun_lock_text::{self, BunEntry};
use crate::vendor::bun_lockb::BunLockb;

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
    bun_lock_text::check_lock_version(text)?;
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    bun_lock_text::parse_packages_section(&lines).map_err(|e| format!("{BUN_LOCK}: {e}"))
}

// ── file selection ──

/// Whether the project root has a text `bun.lock` (lstat, so a dangling
/// symlink counts): bun reads it whenever it exists, so the binary
/// `bun.lockb` beside it is not the live lock. Lockfile discovery answers
/// the same question with `DiscoverCtx::exists` (the same lstat).
pub(crate) async fn bun_text_lock_present(root: &Path) -> bool {
    tokio::fs::symlink_metadata(root.join(BUN_LOCK))
        .await
        .is_ok()
}

// ── registry view ──

pub(super) async fn inventory_bun_binary(
    root: &Path,
) -> Result<Vec<LockfileEntry>, UnsupportedNpmLayout> {
    let invalid = |detail: String| UnsupportedNpmLayout {
        code: "bun_lockb_invalid",
        detail: format!("cannot inventory bun.lockb: {detail}"),
    };
    let bytes = read_regular_to_bytes(&root.join(BUN_LOCKB))
        .await
        .map_err(|error| invalid(error.to_string()))?;
    let packages = BunLockb::parse_packages(&bytes).map_err(invalid)?;
    Ok(packages
        .into_iter()
        .filter_map(|package| {
            let version = package.version?;
            // Only resolved registry versions participate. Workspace, file and
            // git sources have no registry version; a local vendored tarball's
            // pristine metadata is recovered from its wiring ledger instead.
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

pub(super) async fn inventory_bun(root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&root.join(BUN_LOCK)).await.ok()?;
    let entries = bun_text_entries(&text).ok()?;

    let mut out = Vec::new();
    for entry in entries {
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
