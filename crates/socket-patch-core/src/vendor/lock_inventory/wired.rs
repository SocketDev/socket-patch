//! The integrity a rewired lockfile records for a vendored artifact
//! ([`wired_vendor_integrity`]).

use std::path::Path;

use toml_edit::{DocumentMut, Item};

use crate::constants::npm_family::{BUN_LOCK, BUN_LOCKB, NPM_LOCKS, PNPM_LOCK};
use crate::utils::digest::is_sri_pin;
use crate::utils::fs::{read_regular_to_bytes, read_regular_to_string};
use crate::utils::python_lock::{
    lock_artifact, lock_package_collection, package_artifacts, uv_source_location,
};
use crate::vendor::bun_lockb::BunLockb;

use super::npm::npm_lock_nodes;
use super::recover::inline_yaml_field;
use super::LockIntegrity;

/// The integrity the REWIRED npm-family lockfile records for a vendored
/// artifact at `artifact_rel` (forward-slashed, no `./` prefix). This is
/// the integrity of OUR deterministically packed tarball — the trust
/// anchor for repair's no-ledger reconstruction: a rebuilt tarball that
/// matches it is exactly what the package manager would have installed.
///
/// package-lock/shrinkwrap are parsed as JSON; the text formats (pnpm,
/// yarn classic/berry, bun) are scanned with a bounded forward window from
/// each reference line. vlt yields `None`: its `file` nodes pin no
/// integrity (slot [2] is `null`), and `vlt-lock.json` is never scanned,
/// because the forward window would pick up a neighbouring node's sha512.
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

    // Text locks: any line referencing the artifact path, integrity within
    // a short forward window (the same block).
    for lock in [PNPM_LOCK, "yarn.lock", BUN_LOCK] {
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
                    if is_sri_pin(&v) {
                        return Some(LockIntegrity::Sri(v));
                    }
                }
                if let Some(rest) = probe.trim().strip_prefix("integrity ") {
                    let v = rest.trim().trim_matches('"');
                    if is_sri_pin(v) {
                        return Some(LockIntegrity::Sri(v.to_string()));
                    }
                }
                if let Some(sri) = probe.split('"').rev().find(|tok| is_sri_pin(tok)) {
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
