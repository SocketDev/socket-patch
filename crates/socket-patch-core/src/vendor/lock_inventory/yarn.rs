//! `yarn.lock`, classic and berry: the entry models lockfile discovery
//! shares ([`classic_entries`], [`berry_entries`]) and the registry views.

use std::path::Path;

use crate::utils::digest::is_hex;
use crate::utils::fs::read_regular_to_string;
use crate::vendor::yarn_berry_lock::{
    berry_field, berry_metadata, parse_berry_locator, BerryLocator,
};
use crate::vendor::yarn_classic_lock::{
    self, classic_field, live_blocks, scan_blocks, split_berry_key_patterns, split_key_patterns,
    split_resolved_sha1, LockBlock,
};

use super::{http_url, LockIntegrity, LockfileEntry};

// ── entry model ──

/// One block of a `yarn.lock` (either grammar), read with the vendor
/// backends' own block scanner ([`scan_blocks`]).
pub(crate) struct YarnEntry {
    pub(crate) block: LockBlock,
    /// The key's patterns: [`split_key_patterns`] (classic, quotes dropped)
    /// or [`split_berry_key_patterns`] (berry).
    pub(crate) patterns: Vec<String>,
    /// Whether yarn keeps this block ([`live_blocks`], computed over EVERY
    /// block of the lock): last block wins per pattern, so never true for a
    /// block without patterns.
    pub(crate) live: bool,
}

impl YarnEntry {
    /// A berry block's `resolution:` value.
    pub(crate) fn resolution(&self) -> Option<&str> {
        berry_field(&self.block.lines, "resolution")
    }

    /// A berry block's `resolution:` locator.
    pub(crate) fn locator(&self) -> Option<BerryLocator<'_>> {
        parse_berry_locator(self.resolution()?)
    }
}

fn yarn_entries(blocks: Vec<LockBlock>, split: fn(&str) -> Vec<String>) -> Vec<YarnEntry> {
    let patterns: Vec<Vec<String>> = blocks.iter().map(|b| split(&b.key)).collect();
    let live = live_blocks(&patterns);
    blocks
        .into_iter()
        .zip(patterns)
        .zip(live)
        .map(|((block, patterns), live)| YarnEntry {
            block,
            patterns,
            live,
        })
        .collect()
}

/// Every block of a classic (v1) `yarn.lock` text, in lock order — the ONE
/// entry walk the lock inventory and lockfile discovery
/// (`vex::discover::yarn`) share. Every block is returned (registry, hosted,
/// vendored, `link:`, shadowed); each consumer applies its own filters.
pub(crate) fn classic_entries(text: &str) -> Vec<YarnEntry> {
    yarn_entries(scan_blocks(text), split_key_patterns)
}

/// A berry `yarn.lock` read into its entries.
pub(crate) struct BerryLock {
    /// The `__metadata` block's `cacheKey:` value.
    pub(crate) cache_key: Option<String>,
    /// Every block except the exact `__metadata` one, in lock order.
    pub(crate) entries: Vec<YarnEntry>,
}

/// A berry (yarn 2+) `yarn.lock` text — berry reuses the classic block
/// grammar — as the ONE entry walk the lock inventory and lockfile
/// discovery share (see [`classic_entries`]).
pub(crate) fn berry_entries(text: &str) -> BerryLock {
    let blocks = scan_blocks(text);
    let cache_key = berry_metadata(&blocks)
        .and_then(|meta| berry_field(&meta.lines, "cacheKey"))
        .map(str::to_string);
    let mut entries = yarn_entries(blocks, split_berry_key_patterns);
    entries.retain(|e| e.block.key != "__metadata");
    BerryLock { cache_key, entries }
}

/// A berry `checksum:` value as the pin yarn enforces: `<cacheKey>/<hex>`,
/// or — yarn 4.0.x's spelling under cacheKey `10c0` (4.1+ prefixes the
/// cache key) — bare 128-hex promoted to `10c0/<hex>`. `None` for anything
/// else.
pub(crate) fn berry_checksum_pin(value: &str, cache_key: Option<&str>) -> Option<LockIntegrity> {
    if value
        .split_once('/')
        .is_some_and(|(k, h)| !k.is_empty() && !h.is_empty())
    {
        Some(LockIntegrity::BerryChecksum(value.to_string()))
    } else if cache_key == Some("10c0") && is_hex(value, 128) {
        Some(LockIntegrity::BerryChecksum(format!("10c0/{value}")))
    } else {
        None
    }
}

// ── registry view ──

pub(super) async fn inventory_yarn_classic(root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&root.join("yarn.lock")).await.ok()?;
    Some(classic_registry_view(&text))
}

/// The registry packages of a classic lock text.
fn classic_registry_view(text: &str) -> Vec<LockfileEntry> {
    let mut out = Vec::new();
    for YarnEntry {
        block, patterns, ..
    } in classic_entries(text)
    {
        // Our own vendored block: not a registry dependency.
        if yarn_classic_lock::block_points_into_vendor(&block.lines) {
            continue;
        }
        let Some(name) = patterns
            .first()
            .and_then(|p| yarn_classic_lock::pattern_real_name(p))
        else {
            continue;
        };
        let Some(version) = classic_field(&block.lines, "version") else {
            continue;
        };
        // `resolved "url#sha1hex"` — the fragment is the legacy verifier.
        let (resolved, sha1_hex) = match classic_field(&block.lines, "resolved") {
            Some(raw) => {
                let (url, sha1) = split_resolved_sha1(raw);
                (http_url(url), sha1)
            }
            None => (None, None),
        };
        let integrity = classic_field(&block.lines, "integrity")
            .map(|i| LockIntegrity::Sri(i.to_string()))
            .or(sha1_hex.map(LockIntegrity::Sha1Hex))
            .unwrap_or(LockIntegrity::None);
        out.push(LockfileEntry::npm(name, version, resolved, integrity));
    }
    out
}

pub(super) async fn inventory_yarn_berry(root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&root.join("yarn.lock")).await.ok()?;
    Some(berry_registry_view(&text))
}

/// The registry packages of a berry lock text: `__metadata*` and
/// workspace/patch/file resolutions are not registry packages.
fn berry_registry_view(text: &str) -> Vec<LockfileEntry> {
    let mut out = Vec::new();
    for entry in berry_entries(text).entries {
        if entry.block.key.starts_with("__metadata") {
            continue;
        }
        // Registry resolutions are `name@npm:<version>` (a `::binding`
        // suffix may follow). Anything else (workspace:/patch:/file:/link:)
        // is skipped — including our own vendored file: resolutions.
        let Some(locator) = entry.locator() else {
            continue;
        };
        let Some((version_from_res, _)) = locator.npm() else {
            continue;
        };
        let lines = &entry.block.lines;
        let version = berry_field(lines, "version").unwrap_or(version_from_res);
        let integrity = berry_field(lines, "checksum")
            .map(|c| LockIntegrity::BerryChecksum(c.to_string()))
            .unwrap_or(LockIntegrity::None);
        out.push(LockfileEntry::npm(locator.name, version, None, integrity));
    }
    out
}
