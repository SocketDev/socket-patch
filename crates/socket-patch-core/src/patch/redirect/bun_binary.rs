//! Native hosted redirects for bun.lockb. Structured package snapshots keep
//! scoped rollback independent of other packages in the same binary lock.
use super::{DepOverride, FileEdit, RewriteResult, RewriteWarning};
use crate::vendor::bun_lockb::BunLockb;
use serde_json::Value;

pub(crate) const KIND: &str = "redirect_bun_lockb_package";

pub fn preflight_bun_binary(content: &[u8]) -> Result<(), RewriteWarning> {
    BunLockb::parse(content)
        .and_then(|lock| lock.validate_mutation())
        .map(|_| ())
        .map_err(|detail| RewriteWarning {
            code: "redirect_bun_lockb_invalid".into(),
            detail,
        })
}

pub fn rewrite_bun_binary(content: &[u8], overrides: &[DepOverride], result: &mut RewriteResult) {
    let mut lock = match BunLockb::parse(content) {
        Ok(v) => v,
        Err(detail) => {
            result.warnings.push(RewriteWarning {
                code: "redirect_bun_lockb_invalid".into(),
                detail,
            });
            return;
        }
    };
    if let Err(detail) = lock.validate_mutation() {
        result.warnings.push(RewriteWarning {
            code: "redirect_bun_lockb_invalid".into(),
            detail,
        });
        return;
    }
    for dep in overrides.iter().filter(|o| o.ecosystem == "npm") {
        let name = super::full_name(dep);
        let Some(integrity) = dep.integrity.sha512.as_deref() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_bun_missing_sha512".into(),
                detail: format!("{name}@{} has no sha512 integrity", dep.version),
            });
            continue;
        };
        // Each dependency is transactional, including duplicates and aliases.
        let mut candidate = match BunLockb::parse(&lock.bytes()) {
            Ok(v) => v,
            Err(_) => unreachable!("validated lock"),
        };
        let attempt = (|| {
            let mut edits = Vec::new();
            let packages = candidate.packages()?;
            let matching: Vec<_> = packages
                .iter()
                .filter(|p| {
                    p.name == name
                        && (p.version.as_deref() == Some(&dep.version)
                            || p.resolution == dep.artifact_url
                            || super::is_prior_hosted_bun_spec(
                                &format!("{name}@{}", p.resolution),
                                &name,
                                &dep.artifact_url,
                            ))
                })
                .collect();
            if matching.is_empty() {
                return Err(format!(
                    "no rewritable bun.lockb entry for {name}@{}",
                    dep.version
                ));
            }
            for p in matching {
                if p.resolution == dep.artifact_url && p.integrity.as_deref() == Some(integrity) {
                    continue;
                }
                let original = candidate.snapshot(p.id)?;
                candidate.set_package(p.id, &dep.artifact_url, integrity)?;
                edits.push(FileEdit {
                    path: "bun.lockb".into(),
                    kind: KIND.into(),
                    action: "rewritten".into(),
                    key: Some(p.id.to_string()),
                    original: Some(original),
                    new: Some(candidate.snapshot(p.id)?),
                });
            }
            Ok::<_, String>(edits)
        })();
        match attempt {
            Ok(edits) => {
                lock = candidate;
                result.edits.extend(edits);
                result
                    .confirmed_bun_binary_uuids
                    .insert(dep.patch_uuid.clone());
            }
            Err(detail) => result.warnings.push(RewriteWarning {
                code: "redirect_bun_entry_not_found".into(),
                detail,
            }),
        }
    }
    let bytes = lock.bytes();
    if bytes != content {
        result.binary_files.insert("bun.lockb".into(), bytes);
    }
}

pub(crate) fn names(edit: &FileEdit, name: &str, version: &str) -> Result<bool, String> {
    let original = edit
        .original
        .as_ref()
        .ok_or("binary redirect is missing its original snapshot")?;
    let new = edit
        .new
        .as_ref()
        .ok_or("binary redirect is missing its rewritten snapshot")?;
    for snapshot in [original, new] {
        if snapshot.get("name").and_then(Value::as_str).is_none()
            || snapshot.get("resolution").and_then(Value::as_str).is_none()
            || !matches!(
                snapshot.get("version"),
                Some(Value::Null | Value::String(_))
            )
        {
            return Err("binary redirect snapshot cannot be attributed to a package; restore the ledger before scoped rollback".into());
        }
    }
    if original["name"] != new["name"] {
        return Err("binary redirect snapshots disagree about package ownership".into());
    }
    if original["name"].as_str() != Some(name) {
        return Ok(false);
    }
    let recover_version = |snapshot: &Value| -> Option<String> {
        if let Some(version) = snapshot["version"]
            .as_str()
            .filter(|version| semver::Version::parse(version).is_ok())
        {
            return Some(version.into());
        }
        let url = snapshot["resolution"].as_str()?;
        let bare = name.rsplit('/').next()?;
        let candidate = url
            .rsplit('/')
            .next()?
            .strip_prefix(&format!("{bare}-"))?
            .strip_suffix(".tgz")?;
        (semver::Version::parse(candidate).is_ok()
            && super::takeover::hosted_url_names(url, name, candidate))
        .then(|| candidate.into())
    };
    let versions: Vec<_> = [original, new]
        .into_iter()
        .filter_map(recover_version)
        .collect();
    let Some(first) = versions.first() else {
        return Err("binary redirect snapshot names this package but its version cannot be recovered; restore the ledger before scoped rollback".into());
    };
    if versions.iter().any(|value| value != first) {
        return Err("binary redirect snapshots disagree about package version".into());
    }
    Ok(first == version)
}

pub(crate) fn restore(content: &[u8], edit: &FileEdit) -> Result<Vec<u8>, String> {
    if edit.path != "bun.lockb" || edit.kind != KIND {
        return Err("unexpected binary lock edit path or kind".into());
    }
    let id = edit
        .key
        .as_deref()
        .and_then(|s| s.parse().ok())
        .ok_or("invalid binary package ID")?;
    let original = edit
        .original
        .as_ref()
        .ok_or("missing original binary package snapshot")?;
    let new = edit
        .new
        .as_ref()
        .ok_or("missing rewritten binary package snapshot")?;
    let mut lock = BunLockb::parse(content)?;
    // Another duplicate may already have been restored by the preceding
    // edit. Resolve the still-hosted record first, so that duplicate's
    // original cannot make us skip an active hosted resolution.
    let id = match lock.find_snapshot_id(id, new)? {
        Some(id) => id,
        None if lock.find_snapshot_id(id, original)?.is_some() => return Ok(content.to_vec()),
        None => {
            return Err("bun.lockb package has drifted from its recorded hosted resolution".into())
        }
    };
    lock.restore(id, original)?;
    Ok(lock.bytes())
}

#[cfg(test)]
mod tests {
    use super::super::{
        revert_npm_redirect_purl, revert_remaining_redirect_edits, Integrity, RedirectState,
    };
    use super::*;
    use base64::Engine;
    const FIXTURE: &[u8] =
        include_bytes!("../../../tests/fixtures/bun-lockb/two-versions/bun.lockb");

    fn dep(version: &str) -> DepOverride {
        DepOverride {
            ecosystem: "npm".into(),
            name: "minimist".into(),
            namespace: None,
            version: version.into(),
            token: String::new(),
            patch_uuid: version.into(),
            artifact_url: format!("https://patch.example.test/{version}/minimist-{version}.tgz"),
            berry_zip_url: None,
            registry_override: None,
            integrity: Integrity {
                sha512: Some(format!(
                    "sha512-{}",
                    base64::engine::general_purpose::STANDARD.encode([42; 64])
                )),
                ..Default::default()
            },
        }
    }

    fn state(edits: Vec<FileEdit>) -> RedirectState {
        let mut state = RedirectState::new();
        state.edits = edits;
        for version in ["1.2.2", "1.2.8"] {
            state.records.insert(
                format!("pkg:npm/minimist@{version}"),
                crate::manifest::schema::PatchRecord {
                    uuid: version.into(),
                    exported_at: String::new(),
                    files: Default::default(),
                    vulnerabilities: Default::default(),
                    description: String::new(),
                    license: String::new(),
                    tier: String::new(),
                },
            );
        }
        state
    }

    #[tokio::test]
    async fn scoped_revert_preserves_other_version_and_full_replay_restores_registry() {
        let mut result = RewriteResult::default();
        rewrite_bun_binary(FIXTURE, &[dep("1.2.2"), dep("1.2.8")], &mut result);
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        assert_eq!(result.edits.len(), 2);
        let bytes = &result.binary_files["bun.lockb"];
        let mut rerun = RewriteResult::default();
        rewrite_bun_binary(bytes, &[dep("1.2.2"), dep("1.2.8")], &mut rerun);
        assert!(rerun.edits.is_empty());
        assert!(rerun.binary_files.is_empty());
        assert_eq!(rerun.confirmed_bun_binary_uuids.len(), 2);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bun.lockb"), bytes).unwrap();
        let mut ledger = state(result.edits);
        revert_npm_redirect_purl(
            dir.path(),
            &mut ledger.clone(),
            "pkg:npm/minimist@1.2.2",
            true,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(dir.path().join("bun.lockb")).unwrap(), *bytes);
        revert_npm_redirect_purl(dir.path(), &mut ledger, "pkg:npm/minimist@1.2.2", false)
            .await
            .unwrap();
        assert_eq!(ledger.edits.len(), 1);
        assert!(ledger.records.contains_key("pkg:npm/minimist@1.2.8"));
        let partial =
            BunLockb::parse(&std::fs::read(dir.path().join("bun.lockb")).unwrap()).unwrap();
        let packages = partial.packages().unwrap();
        assert!(packages
            .iter()
            .any(|p| p.name == "minimist" && p.version.as_deref() == Some("1.2.2")));
        assert!(packages
            .iter()
            .any(|p| p.resolution == dep("1.2.8").artifact_url));
        let replay = revert_remaining_redirect_edits(dir.path(), &mut ledger, false).await;
        assert!(replay.refusals.is_empty(), "{:?}", replay.refusals);
        assert!(ledger.edits.is_empty());
        let restored =
            BunLockb::parse(&std::fs::read(dir.path().join("bun.lockb")).unwrap()).unwrap();
        assert_eq!(
            restored.packages().unwrap(),
            BunLockb::parse(FIXTURE).unwrap().packages().unwrap()
        );
    }

    #[tokio::test]
    async fn whole_replay_is_byte_exact_and_drift_is_transactional() {
        let mut result = RewriteResult::default();
        rewrite_bun_binary(FIXTURE, &[dep("1.2.2"), dep("1.2.8")], &mut result);
        let dir = tempfile::tempdir().unwrap();
        let bytes = result.binary_files["bun.lockb"].clone();
        std::fs::write(dir.path().join("bun.lockb"), &bytes).unwrap();
        let mut ledger = state(result.edits);
        let replay = revert_remaining_redirect_edits(dir.path(), &mut ledger.clone(), false).await;
        assert!(replay.refusals.is_empty(), "{:?}", replay.refusals);
        assert_eq!(
            std::fs::read(dir.path().join("bun.lockb")).unwrap(),
            FIXTURE
        );
        let mut drift = BunLockb::parse(&bytes).unwrap();
        let first_id = ledger.edits[0].key.as_ref().unwrap().parse().unwrap();
        drift
            .set_package(
                first_id,
                "https://other.test/minimist-1.2.2.tgz",
                dep("1.2.2").integrity.sha512.as_ref().unwrap(),
            )
            .unwrap();
        let drift = drift.bytes();
        std::fs::write(dir.path().join("bun.lockb"), &drift).unwrap();
        let before = ledger.edits.clone();
        let replay = revert_remaining_redirect_edits(dir.path(), &mut ledger, false).await;
        assert_eq!(replay.refusals.len(), 1);
        assert_eq!(ledger.edits, before);
        assert_eq!(std::fs::read(dir.path().join("bun.lockb")).unwrap(), drift);
        assert!(
            revert_npm_redirect_purl(dir.path(), &mut ledger, "pkg:npm/minimist@1.2.2", true)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn scoped_binary_revert_refuses_unattributable_snapshots_without_dropping_records() {
        let mut result = RewriteResult::default();
        rewrite_bun_binary(FIXTURE, &[dep("1.2.2")], &mut result);
        let root = tempfile::tempdir().unwrap();
        let bytes = &result.binary_files["bun.lockb"];
        std::fs::write(root.path().join("bun.lockb"), bytes).unwrap();
        for malformed in [
            serde_json::json!({"resolution": "https://patch.example.test/1.2.2/minimist-1.2.2.tgz", "version": null}),
            serde_json::json!({"name": "minimist", "version": 12, "resolution": "https://patch.example.test/1.2.2/minimist-1.2.2.tgz"}),
        ] {
            let mut ledger = state(result.edits.clone());
            ledger.edits[0].new = Some(malformed);
            let original = serde_json::to_value(&ledger).unwrap();
            for dry_run in [true, false] {
                assert!(revert_npm_redirect_purl(
                    root.path(),
                    &mut ledger,
                    "pkg:npm/minimist@1.2.2",
                    dry_run
                )
                .await
                .is_err());
                assert_eq!(serde_json::to_value(&ledger).unwrap(), original);
                assert_eq!(
                    std::fs::read(root.path().join("bun.lockb")).unwrap(),
                    *bytes
                );
            }
        }
    }

    #[test]
    fn malformed_metahash_cannot_confirm_an_existing_binary_redirect() {
        let mut result = RewriteResult::default();
        rewrite_bun_binary(FIXTURE, &[dep("1.2.2")], &mut result);
        let mut bytes = result.binary_files["bun.lockb"].clone();
        // The first 32 bytes after the format header contain the metahash.
        let header = b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n".len();
        bytes[header + 4] ^= 1;
        let mut rerun = RewriteResult::default();
        rewrite_bun_binary(&bytes, &[dep("1.2.2")], &mut rerun);
        assert!(rerun.edits.is_empty());
        assert!(rerun.binary_files.is_empty());
        assert!(rerun.confirmed_bun_binary_uuids.is_empty());
        assert!(rerun
            .warnings
            .iter()
            .any(|w| w.code == "redirect_bun_lockb_invalid"));
    }

    #[tokio::test]
    async fn scoped_binary_revert_refuses_same_name_without_a_recoverable_version() {
        let mut result = RewriteResult::default();
        rewrite_bun_binary(FIXTURE, &[dep("1.2.2")], &mut result);
        let root = tempfile::tempdir().unwrap();
        let bytes = &result.binary_files["bun.lockb"];
        std::fs::write(root.path().join("bun.lockb"), bytes).unwrap();
        let mut ledger = state(result.edits);
        let edit = &mut ledger.edits[0];
        for snapshot in [&mut edit.original, &mut edit.new] {
            let value = snapshot.as_mut().unwrap();
            value["version"] = Value::Null;
            value["resolution"] =
                Value::String("https://patch.example.test/unattributable.tgz".into());
        }
        let before = serde_json::to_value(&ledger).unwrap();
        for dry_run in [true, false] {
            assert!(revert_npm_redirect_purl(
                root.path(),
                &mut ledger,
                "pkg:npm/minimist@1.2.2",
                dry_run
            )
            .await
            .unwrap_err()
            .contains("version cannot be recovered"));
            assert_eq!(serde_json::to_value(&ledger).unwrap(), before);
            assert_eq!(
                std::fs::read(root.path().join("bun.lockb")).unwrap(),
                *bytes
            );
        }
        // A known sibling version remains attributable and is left untouched.
        let edit = &mut ledger.edits[0];
        for snapshot in [&mut edit.original, &mut edit.new] {
            snapshot.as_mut().unwrap()["resolution"] = Value::String(dep("1.2.8").artifact_url);
        }
        assert!(!names(&ledger.edits[0], "minimist", "1.2.2").unwrap());
        assert!(names(&ledger.edits[0], "minimist", "1.2.8").unwrap());
    }

    #[test]
    fn bad_digest_and_missing_version_leave_binary_untouched() {
        let mut invalid = dep("1.2.2");
        invalid.integrity.sha512 = Some("sha512-invalid".into());
        for dep in [invalid, dep("1.9.9")] {
            let mut result = RewriteResult::default();
            rewrite_bun_binary(FIXTURE, &[dep], &mut result);
            assert!(result.edits.is_empty());
            assert!(result.binary_files.is_empty());
            assert!(result.confirmed_bun_binary_uuids.is_empty());
            assert_eq!(result.warnings.len(), 1);
        }
    }

    #[tokio::test]
    async fn duplicate_binary_records_are_all_restored_before_dropping_the_ledger() {
        let mut duplicate = BunLockb::parse(FIXTURE).unwrap();
        let packages: Vec<_> = duplicate
            .packages()
            .unwrap()
            .into_iter()
            .filter(|p| p.name == "minimist")
            .collect();
        assert_eq!(packages.len(), 2);
        let first = packages
            .iter()
            .find(|p| p.version.as_deref() == Some("1.2.2"))
            .unwrap();
        let other = packages.iter().find(|p| p.id != first.id).unwrap();
        let original = duplicate.snapshot(first.id).unwrap();
        duplicate.restore(other.id, &original).unwrap();
        let before = duplicate.bytes();
        let mut rewritten = RewriteResult::default();
        rewrite_bun_binary(&before, &[dep("1.2.2")], &mut rewritten);
        assert_eq!(
            rewritten.edits.len(),
            2,
            "both identical package records are redirected"
        );
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("bun.lockb"),
            &rewritten.binary_files["bun.lockb"],
        )
        .unwrap();
        let mut ledger = state(rewritten.edits);
        let reverted = revert_remaining_redirect_edits(tmp.path(), &mut ledger, false).await;
        assert!(reverted.refusals.is_empty(), "{:?}", reverted.refusals);
        assert!(ledger.edits.is_empty());
        let restored =
            BunLockb::parse(&std::fs::read(tmp.path().join("bun.lockb")).unwrap()).unwrap();
        assert_eq!(restored.packages().unwrap(), duplicate.packages().unwrap());
    }
}
