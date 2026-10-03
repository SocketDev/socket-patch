//! The integrity a rewired lockfile records for a vendored artifact
//! ([`wired_vendor_integrity`]).

use std::path::Path;

use toml_edit::{DocumentMut, Item};

use crate::constants::npm_family::{BUN_LOCK, BUN_LOCKB, NPM_LOCKS, PNPM_LOCK};
use crate::formats::pnpm::PnpmLock;
use crate::utils::digest::is_sri_pin;
use crate::utils::fs::{read_regular_to_bytes, read_regular_to_string};
use crate::utils::python_lock::{
    lock_artifact, lock_package_collection, package_artifacts, uv_source_location,
};
use crate::formats::yarn::is_berry_lock;
use crate::vendor::bun_lock_text::{decode_json_string, split_name_spec};
use crate::vendor::bun_lockb::BunLockb;
use crate::vendor::yarn_berry_lock::berry_field;
use crate::vendor::yarn_classic_lock::classic_field;
use crate::vex::discover::{vendor_ref, vendor_ref_decorated};

use super::bun::bun_text_entries;
use super::npm::npm_lock_nodes;
use super::yarn::{berry_checksum_pin, berry_entries, classic_entries};
use super::LockIntegrity;

/// The integrity the REWIRED npm-family lockfile records for a vendored
/// artifact at `artifact_rel` (forward-slashed, no `./` prefix). This is
/// the integrity of OUR deterministically packed tarball — the trust
/// anchor for repair's no-ledger reconstruction: a rebuilt tarball that
/// matches it is exactly what the package manager would have installed.
///
/// package-lock/shrinkwrap are parsed as JSON, pnpm through its format
/// model, yarn (classic and berry) and bun.lock through the entry models
/// lockfile discovery reads. vlt yields `None`: its `file` nodes pin no
/// integrity (slot [2] is `null`).
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
            // The shared lock model: the package array, pylock `archive`
            // paths, uv `source` locations and artifact tables.
            let (collection, pep751) = lock_package_collection(&document);
            let Some(packages) = document.get(collection).and_then(Item::as_array_of_tables) else {
                continue;
            };
            for package in packages.iter() {
                let archive = package
                    .get("archive")
                    .and_then(Item::as_table_like)
                    .map(lock_artifact);
                let location = match &archive {
                    Some(archive) => archive.path,
                    None if !pep751 => uv_source_location(package),
                    None => None,
                };
                if location.is_none_or(|path| path.trim_start_matches("./") != rel) {
                    continue;
                }
                let leaf = rel.rsplit('/').next();
                let sha = match archive {
                    Some(archive) => archive.sha256,
                    None => package_artifacts(package, &["wheels", "wheel", "sdist"])
                        .into_iter()
                        .find(|wheel| wheel.filename.is_some() && wheel.filename == leaf)
                        .and_then(|wheel| wheel.sha256),
                };
                let sha = sha?;
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
    if !super::bun::bun_text_lock_present(project_root).await {
        if let Ok(bytes) = read_regular_to_bytes(&project_root.join(BUN_LOCKB)).await {
            if let Ok(packages) = BunLockb::parse_packages(&bytes) {
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
                    let sri = package.integrity.filter(|sri| is_sri_pin(sri))?;
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

    // JSON locks: resolved == "file:<rel>" (npm writes exactly this form),
    // read through the inventory's own entry walk (v1 `dependencies`
    // included, which the legacy vendored backend rewires).
    for lock in NPM_LOCKS {
        let Ok(bytes) = read_regular_to_bytes(&project_root.join(lock)).await else {
            continue;
        };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        for node in npm_lock_nodes(&v) {
            if node
                .resolved
                .is_some_and(|r| r.trim_start_matches("file:") == rel)
            {
                if let Some(sri) = node.integrity.filter(|s| is_sri_pin(s)) {
                    return Some(LockIntegrity::Sri(sri.to_string()));
                }
            }
        }
    }

    // pnpm: the format model's vendored entry (every key generation).
    if let Ok(text) = read_regular_to_string(&project_root.join(PNPM_LOCK)).await {
        if let Some(sri) = PnpmLock::parse(&text).wired_integrity(rel) {
            return Some(LockIntegrity::Sri(sri));
        }
    }

    // yarn: the entry models lockfile discovery reads (live blocks only —
    // yarn keeps the last block per pattern), classic `integrity` SRI or
    // berry `checksum:` (yarn 4.0.x bare hex promoted under cacheKey 10c0).
    if let Ok(text) = read_regular_to_string(&project_root.join("yarn.lock")).await {
        let pins: Vec<LockIntegrity> = if is_berry_lock(&text) {
            let lock = berry_entries(&text);
            lock.entries
                .iter()
                .filter(|e| e.live)
                .filter(|e| {
                    e.locator()
                        .and_then(|l| vendor_ref_decorated(l.reference))
                        .is_some_and(|v| v.artifact_rel == rel)
                })
                .filter_map(|e| {
                    berry_field(&e.block.lines, "checksum")
                        .and_then(|c| berry_checksum_pin(c, lock.cache_key.as_deref()))
                })
                .collect()
        } else {
            classic_entries(&text)
                .iter()
                .filter(|e| e.live)
                .filter(|e| {
                    classic_field(&e.block.lines, "resolved")
                        .and_then(vendor_ref_decorated)
                        .is_some_and(|v| v.artifact_rel == rel)
                })
                .filter_map(|e| classic_field(&e.block.lines, "integrity"))
                .filter(|sri| is_sri_pin(sri))
                .map(|sri| LockIntegrity::Sri(sri.to_string()))
                .collect()
        };
        if let Some(pin) = unanimous(pins) {
            return Some(pin);
        }
    }

    // bun.lock: our tarball tuple `[spec, {meta}, "sha512-…"]` (bun
    // < 1.3.10 re-saves it digest-less, which pins nothing).
    if let Ok(text) = read_regular_to_string(&project_root.join(BUN_LOCK)).await {
        if let Ok(entries) = bun_text_entries(&text) {
            let pins: Vec<LockIntegrity> = entries
                .iter()
                .filter(|e| {
                    matches!(e.elems.len(), 2 | 3)
                        && e.elems[1].starts_with('{')
                        && e.elems
                            .first()
                            .and_then(|spec| decode_json_string(spec))
                            .is_some_and(|spec| {
                                split_name_spec(&spec)
                                    .and_then(|(_, target)| vendor_ref(target))
                                    .is_some_and(|v| v.artifact_rel == rel)
                            })
                })
                .filter_map(|e| e.elems.get(2).and_then(|sri| decode_json_string(sri)))
                .filter(|sri| is_sri_pin(sri))
                .map(LockIntegrity::Sri)
                .collect();
            if let Some(pin) = unanimous(pins) {
                return Some(pin);
            }
        }
    }
    None
}

/// The one pin every entry agrees on; `None` when there is none or the
/// entries disagree (no anchor beats a wrong one).
fn unanimous(pins: Vec<LockIntegrity>) -> Option<LockIntegrity> {
    let mut pins = pins.into_iter();
    let first = pins.next()?;
    pins.all(|p| p == first).then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::bun_lockb::BunLockb;
    use crate::vex::discover::testing::{fixture_path, Project, UUID_A};

    const SRI_A: &str = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    const SRI_B: &str = "sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA==";

    /// The `two-versions` bun.lockb with both `minimist` records pointed at
    /// ONE vendored artifact path: agreeing pins are the anchor, disagreeing
    /// ones (which record is the artifact?) are none.
    #[tokio::test]
    async fn bun_lockb_records_sharing_an_artifact_must_agree_on_its_pin() {
        let fixture = std::fs::read(fixture_path("bun-lockb/two-versions/bun.lockb"))
            .expect("two-versions fixture");
        let artifact = format!(".socket/vendor/npm/{UUID_A}/minimist-1.2.2.tgz");
        let minimist: Vec<usize> = BunLockb::parse_packages(&fixture)
            .expect("fixture parses")
            .iter()
            .enumerate()
            .filter(|(_, p)| p.name == "minimist")
            .map(|(id, _)| id)
            .collect();
        assert_eq!(minimist.len(), 2, "the fixture's two minimist records");
        for (second, want) in [
            (SRI_A, Some(LockIntegrity::Sri(SRI_A.to_string()))),
            (SRI_B, None),
        ] {
            let mut lock = BunLockb::parse(&fixture).expect("fixture parses");
            lock.set_package(minimist[0], &artifact, SRI_A)
                .expect("rewire the first record");
            lock.set_package(minimist[1], &artifact, second)
                .expect("rewire the second record");
            let p = Project::new();
            p.write("bun.lockb", lock.bytes());
            assert_eq!(wired_vendor_integrity(p.root(), &artifact).await, want);
        }
    }
}
