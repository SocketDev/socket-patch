//! `yarn.lock`, classic and berry: the registry views.

use std::path::Path;

use crate::utils::fs::read_regular_to_string;
use crate::vendor::{yarn_berry_lock, yarn_classic_lock};

use super::{http_url, is_hex_of_len, LockIntegrity, LockfileEntry};

pub(super) async fn inventory_yarn_classic(root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&root.join("yarn.lock")).await.ok()?;
    let mut out = Vec::new();
    for block in yarn_classic_lock::scan_blocks(&text) {
        // Our own vendored block: not a registry dependency.
        if yarn_classic_lock::block_points_into_vendor(&block.lines) {
            continue;
        }
        let patterns = yarn_classic_lock::split_key_patterns(&block.key);
        let Some(name) = patterns
            .first()
            .and_then(|p| yarn_classic_lock::pattern_real_name(p))
        else {
            continue;
        };
        let Some(version) = yarn_classic_lock::classic_field(&block.lines, "version") else {
            continue;
        };
        let resolved_raw = yarn_classic_lock::classic_field(&block.lines, "resolved");
        // `resolved "url#sha1hex"` — the fragment is the legacy verifier.
        let (resolved, sha1_hex) = match resolved_raw {
            Some(raw) => match raw.split_once('#') {
                Some((url, frag)) => (
                    http_url(url),
                    is_hex_of_len(frag, 40).then(|| frag.to_ascii_lowercase()),
                ),
                None => (http_url(raw), None),
            },
            None => (None, None),
        };
        let integrity = yarn_classic_lock::classic_field(&block.lines, "integrity")
            .map(|i| LockIntegrity::Sri(i.to_string()))
            .or(sha1_hex.map(LockIntegrity::Sha1Hex))
            .unwrap_or(LockIntegrity::None);
        out.push(LockfileEntry::npm(name, version, resolved, integrity));
    }
    Some(out)
}

pub(super) async fn inventory_yarn_berry(root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&root.join("yarn.lock")).await.ok()?;
    let mut out = Vec::new();
    // Berry reuses classic's block grammar (same scanner the berry backend
    // imports); `__metadata` and workspace/patch/file resolutions are not
    // registry packages.
    for block in yarn_classic_lock::scan_blocks(&text) {
        if block.key.starts_with("__metadata") {
            continue;
        }
        let Some(resolution) = yarn_berry_lock::berry_field(&block.lines, "resolution") else {
            continue;
        };
        // Registry resolutions are `name@npm:<version>` (a `::binding`
        // suffix may follow). Anything else (workspace:/patch:/file:/link:)
        // is skipped — including our own vendored file: resolutions.
        let Some((name, reference)) = yarn_classic_lock::split_pattern(resolution) else {
            continue;
        };
        let Some(reference) = reference.strip_prefix("npm:") else {
            continue;
        };
        let version_from_res = reference.split("::").next().unwrap_or(reference);
        let version =
            yarn_berry_lock::berry_field(&block.lines, "version").unwrap_or(version_from_res);
        let integrity = yarn_berry_lock::berry_field(&block.lines, "checksum")
            .map(|c| LockIntegrity::BerryChecksum(c.to_string()))
            .unwrap_or(LockIntegrity::None);
        out.push(LockfileEntry::npm(name, version, None, integrity));
    }
    Some(out)
}
