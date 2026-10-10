//! `yarn.lock`, classic and berry: the entry models lockfile discovery
//! shares ([`classic_entries`], [`berry_entries`]) and the registry views.

#[cfg(test)]
use std::path::Path;

use crate::formats::yarn::blocks::{
    berry_field, classic_field, live_blocks, scan_blocks, LockBlock,
};
use crate::formats::yarn::patterns::{
    classic_pattern_real_name, parse_berry_locator, split_berry_key_patterns, split_key_patterns,
    split_pattern, split_resolved_sha1, BerryLocator,
};
use crate::formats::yarn::source::{classic_copy_source, CopySource};
use crate::utils::digest::is_hex;
use crate::vendor::yarn_classic_lock;

use super::view::ProjectView;
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
    let cache_key = crate::formats::yarn::berry_gates::cache_key(&blocks).map(str::to_string);
    let mut entries = yarn_entries(blocks, split_berry_key_patterns);
    entries.retain(|e| e.block.key != "__metadata");
    BerryLock { cache_key, entries }
}

/// Whether a root `package.json` `resolutions` selector routing to the
/// hosted `url` is leftover wiring the berry `lock` no longer installs
/// (#1203): no live entry resolves `url` (as its tarball locator or an
/// older pin's `__archiveUrl=` binding), and no live entry is keyed by a
/// descriptor the selector matches (`name@range` matches that exact
/// descriptor, a range-less selector any descriptor of the package). `yarn
/// remove` and `yarn up` leave such a selector behind: yarn never edits
/// `resolutions`, and a selector matching no descriptor is inert. A
/// selector that DOES match a descriptor the lock resolves elsewhere is not
/// leftover: the lock and the manifest disagree.
pub(crate) fn berry_selector_routes_nothing(lock: &BerryLock, selector: &str, url: &str) -> bool {
    use crate::formats::yarn::patterns::resolution_selector_target;
    let Some(target) = resolution_selector_target(selector) else {
        return false;
    };
    let selector = selector.trim();
    let last = selector
        .rfind(target)
        .map(|i| &selector[i..])
        .unwrap_or(target);
    let range = split_pattern(last).map(|(_, range)| range);
    for entry in lock.entries.iter().filter(|e| e.live) {
        if let Some(locator) = entry.locator() {
            if locator.reference == url
                || locator.archive_url().is_some_and(|archive| {
                    archive == url
                        || crate::utils::purl::percent_decode_purl_component(archive) == url
                })
            {
                return false;
            }
        }
        for pattern in &entry.patterns {
            let Some((name, descriptor)) = split_pattern(pattern) else {
                continue;
            };
            if name != target {
                continue;
            }
            match range {
                None => return false,
                Some(want) => {
                    if descriptor == want || descriptor.strip_prefix("npm:") == Some(want) {
                        return false;
                    }
                }
            }
        }
    }
    true
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

#[cfg(test)]
pub(super) async fn inventory_yarn_classic(root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_yarn_classic_in(&ProjectView::Disk(root)).await
}

pub(super) async fn inventory_yarn_classic_in(
    view: &ProjectView<'_>,
) -> Option<Vec<LockfileEntry>> {
    let text = view.read_text("yarn.lock").await.ok()?;
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
        let Some(name) = patterns.first().and_then(|p| classic_pattern_real_name(p)) else {
            continue;
        };
        let Some(version) = classic_field(&block.lines, "version") else {
            continue;
        };
        // `resolved "url#sha1hex"` — the fragment is the legacy verifier of
        // a registry tarball. A non-registry copy (git over any protocol, a
        // `file:` tarball, a URL or hosted-git tarball — the shared
        // [`classic_copy_source`] rule the rewriters use) records hashes of
        // an artifact no registry serves — a git fragment is a commit id —
        // so neither it nor an `integrity` field verifies a registry fetch.
        let (resolved, sha1_hex, registry) = match classic_field(&block.lines, "resolved") {
            Some(raw) => {
                let (url, sha1) = split_resolved_sha1(raw);
                let registry_copy = !matches!(
                    classic_copy_source(&patterns, Some(raw)),
                    CopySource::Git | CopySource::RemoteTarball
                );
                match http_url(url).filter(|_| registry_copy) {
                    Some(url) => (Some(url), sha1, true),
                    None => (None, None, false),
                }
            }
            None => (None, None, true),
        };
        let integrity = classic_field(&block.lines, "integrity")
            .filter(|_| registry)
            .map(|i| LockIntegrity::Sri(i.to_string()))
            .or(sha1_hex.map(LockIntegrity::Sha1Hex))
            .unwrap_or(LockIntegrity::None);
        out.push(LockfileEntry::npm(name, version, resolved, integrity));
    }
    out
}

#[cfg(test)]
pub(super) async fn inventory_yarn_berry(root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_yarn_berry_in(&ProjectView::Disk(root)).await
}

pub(super) async fn inventory_yarn_berry_in(view: &ProjectView<'_>) -> Option<Vec<LockfileEntry>> {
    let text = view.read_text("yarn.lock").await.ok()?;
    Some(berry_registry_view(&text))
}

/// The registry packages of a berry lock text: `__metadata*` and
/// workspace/patch/file resolutions are not registry packages.
/// Whether a berry entry resolving to `reference` (with `version:`
/// `version`) is a hosted redirect's tarball pin of a registry package:
/// an `http(s)://` locator whose leaf names the package version (the
/// hosted artifact layout), either keyed by that same tarball descriptor —
/// what the `resolutions` pin writes (#404) — or under `npm:` descriptor
/// keys (an earlier release's pin). A user's own URL dependency keeps a URL
/// whose leaf need not name the version; one that does is the same package
/// version anyway.
fn berry_hosted_tarball_entry(
    entry: &YarnEntry,
    name: &str,
    version: &str,
    reference: &str,
) -> bool {
    crate::patch::redirect::hosted_url::hosted_url_names(reference, name, version)
        && !entry.patterns.is_empty()
        && entry.patterns.iter().all(|p| {
            split_pattern(p)
                .is_some_and(|(_, range)| range.starts_with("npm:") || range == reference)
        })
}

fn berry_registry_view(text: &str) -> Vec<LockfileEntry> {
    let mut out = Vec::new();
    for entry in berry_entries(text).entries {
        if entry.block.key.starts_with("__metadata") {
            continue;
        }
        // Registry resolutions are `name@npm:<version>` (a `::binding`
        // suffix may follow). A Socket hosted pin is a tarball-URL locator
        // (`name@https://…/<name>-<version>.tgz`, #404) — still the registry
        // package, just fetched from the patch host (see
        // [`berry_hosted_tarball_entry`]). Anything else (workspace:/patch:/
        // file:/link:, a user's own URL dependency) is skipped — including
        // our own vendored file: resolutions.
        let Some(locator) = entry.locator() else {
            continue;
        };
        let lines = &entry.block.lines;
        let version = match locator.npm() {
            Some((version_from_res, _)) => {
                berry_field(lines, "version").unwrap_or(version_from_res)
            }
            None => match berry_field(lines, "version") {
                Some(v)
                    if berry_hosted_tarball_entry(&entry, locator.name, v, locator.reference) =>
                {
                    v
                }
                _ => continue,
            },
        };
        let integrity = berry_field(lines, "checksum")
            .map(|c| LockIntegrity::BerryChecksum(c.to_string()))
            .unwrap_or(LockIntegrity::None);
        out.push(LockfileEntry::npm(locator.name, version, None, integrity));
    }
    out
}
