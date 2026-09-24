//! `bun.lock` / `bun.lockb`: the registry views.

use std::path::Path;

use crate::utils::fs::{read_regular_to_bytes, read_regular_to_string};
use crate::vendor::bun_lock_text;

use super::{http_url, LockIntegrity, LockfileEntry, UnsupportedNpmLayout};

pub(super) async fn inventory_bun_binary(
    root: &Path,
) -> Result<Vec<LockfileEntry>, UnsupportedNpmLayout> {
    let invalid = |detail: String| UnsupportedNpmLayout {
        code: "bun_lockb_invalid",
        detail: format!("cannot inventory bun.lockb: {detail}"),
    };
    let bytes = read_regular_to_bytes(&root.join("bun.lockb"))
        .await
        .map_err(|error| invalid(error.to_string()))?;
    let lock = crate::vendor::bun_lockb::BunLockb::parse(&bytes).map_err(invalid)?;
    let packages = lock.packages().map_err(invalid)?;
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
    let text = read_regular_to_string(&root.join("bun.lock")).await.ok()?;
    bun_lock_text::check_lock_version(&text).ok()?;
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let entries = bun_lock_text::parse_packages_section(&lines).ok()?;

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
