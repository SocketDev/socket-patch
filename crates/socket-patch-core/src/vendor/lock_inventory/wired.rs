//! The integrity a rewired lockfile records for a vendored artifact
//! ([`wired_vendor_integrity`]).

use std::path::Path;

use toml_edit::{DocumentMut, Item, Value as TomlValue};

use crate::utils::fs::{read_regular_to_bytes, read_regular_to_string};

use super::recover::{inline_yaml_field, looks_like_sri};
use super::{is_hex_of_len, LockIntegrity};

/// The integrity the REWIRED npm-family lockfile records for a vendored
/// artifact at `artifact_rel` (forward-slashed, no `./` prefix). This is
/// the integrity of OUR deterministically packed tarball — the trust
/// anchor for repair's no-ledger reconstruction: a rebuilt tarball that
/// matches it is exactly what the package manager would have installed.
///
/// package-lock/shrinkwrap are parsed as JSON; the text formats (pnpm,
/// yarn classic/berry, bun) are scanned with a bounded forward window from
/// each reference line.
pub async fn wired_vendor_integrity(
    project_root: &Path,
    artifact_rel: &str,
) -> Option<LockIntegrity> {
    let rel = artifact_rel.trim_start_matches("./");

    if rel.starts_with(".socket/vendor/pypi/") {
        let mut pinned = None;
        for path in crate::utils::python_lock::python_lock_paths(project_root).ok()? {
            let Ok(text) = read_regular_to_string(&project_root.join(path)).await else {
                continue;
            };
            let Ok(document) = text.parse::<DocumentMut>() else {
                continue;
            };
            let collection = if document.contains_key("lock-version") {
                "packages"
            } else {
                "package"
            };
            let Some(packages) = document.get(collection).and_then(Item::as_array_of_tables) else {
                continue;
            };
            for package in packages.iter() {
                let archive = package.get("archive").and_then(Item::as_table_like);
                let source =
                    archive.or_else(|| package.get("source").and_then(Item::as_table_like));
                if source
                    .and_then(|source| source.get("path"))
                    .and_then(Item::as_str)
                    .is_none_or(|path| path.trim_start_matches("./") != rel)
                {
                    continue;
                }
                let sha = if let Some(archive) = archive {
                    archive
                        .get("hashes")
                        .and_then(Item::as_table_like)
                        .and_then(|hashes| hashes.get("sha256"))
                        .and_then(Item::as_str)
                } else {
                    package
                        .get("wheels")
                        .and_then(Item::as_array)
                        .and_then(|wheels| {
                            wheels
                                .iter()
                                .filter_map(TomlValue::as_inline_table)
                                .find_map(|wheel| {
                                    if wheel.get("filename").and_then(TomlValue::as_str)
                                        != rel.rsplit('/').next()
                                    {
                                        return None;
                                    }
                                    wheel
                                        .get("hash")
                                        .and_then(TomlValue::as_str)
                                        .and_then(|value| value.strip_prefix("sha256:"))
                                })
                        })
                };
                let sha = sha
                    .filter(|sha| is_hex_of_len(sha, 64))
                    .map(str::to_ascii_lowercase)?;
                if pinned.as_ref().is_some_and(|previous| previous != &sha) {
                    return None;
                }
                pinned = Some(sha);
            }
        }
        return pinned.map(LockIntegrity::Sha256Hex);
    }

    // Read active binary resolution records, never the append-only string
    // pool: it can retain paths and digests from earlier patch generations.
    if tokio::fs::symlink_metadata(project_root.join("bun.lock"))
        .await
        .is_err()
    {
        if let Ok(bytes) = read_regular_to_bytes(&project_root.join("bun.lockb")).await {
            if let Ok(lock) = crate::vendor::bun_lockb::BunLockb::parse(&bytes) {
                if let Ok(packages) = lock.packages() {
                    let mut pinned: Option<String> = None;
                    for package in packages {
                        if package
                            .resolution
                            .trim_start_matches("file:")
                            .trim_start_matches("./")
                            != rel
                        {
                            continue;
                        }
                        let sri = package.integrity.filter(|sri| looks_like_sri(sri))?;
                        if pinned.as_ref().is_some_and(|previous| previous != &sri) {
                            return None;
                        }
                        pinned = Some(sri);
                    }
                    if let Some(sri) = pinned {
                        return Some(LockIntegrity::Sri(sri));
                    }
                }
            }
        }
    }

    // JSON locks: resolved == "file:<rel>" (npm writes exactly this form).
    for lock in ["npm-shrinkwrap.json", "package-lock.json"] {
        let Ok(bytes) = read_regular_to_bytes(&project_root.join(lock)).await else {
            continue;
        };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if let Some(pkgs) = v.get("packages").and_then(serde_json::Value::as_object) {
            for entry in pkgs.values() {
                let resolved = entry.get("resolved").and_then(serde_json::Value::as_str);
                if resolved.is_some_and(|r| r.trim_start_matches("file:") == rel) {
                    if let Some(sri) = entry
                        .get("integrity")
                        .and_then(serde_json::Value::as_str)
                        .filter(|s| looks_like_sri(s))
                    {
                        return Some(LockIntegrity::Sri(sri.to_string()));
                    }
                }
            }
        }
    }

    // Text locks: any line referencing the artifact path, integrity within
    // a short forward window (the same block).
    for lock in ["pnpm-lock.yaml", "yarn.lock", "bun.lock"] {
        let Ok(text) = read_regular_to_string(&project_root.join(lock)).await else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.contains(rel) {
                continue;
            }
            for probe in lines.iter().take((i + 6).min(lines.len())).skip(i) {
                // pnpm `resolution: {integrity: …}` / classic `integrity …`
                // / bun tuple `"sha512-…"`.
                if let Some(v) = inline_yaml_field(probe, "integrity:") {
                    if looks_like_sri(&v) {
                        return Some(LockIntegrity::Sri(v));
                    }
                }
                if let Some(rest) = probe.trim().strip_prefix("integrity ") {
                    let v = rest.trim().trim_matches('"');
                    if looks_like_sri(v) {
                        return Some(LockIntegrity::Sri(v.to_string()));
                    }
                }
                if let Some(sri) = probe.split('"').rev().find(|tok| looks_like_sri(tok)) {
                    return Some(LockIntegrity::Sri(sri.to_string()));
                }
                // yarn berry: `checksum: 10c0/…`.
                if let Some(v) = inline_yaml_field(probe, "checksum:") {
                    if v.split_once('/')
                        .is_some_and(|(k, b)| !k.is_empty() && !b.is_empty())
                    {
                        return Some(LockIntegrity::BerryChecksum(v));
                    }
                }
            }
        }
    }
    None
}
