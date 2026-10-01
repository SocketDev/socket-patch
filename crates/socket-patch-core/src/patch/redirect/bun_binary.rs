//! Native hosted redirects for bun.lockb. Structured package snapshots keep
//! scoped rollback independent of other packages in the same binary lock.
use super::{DepOverride, FileEdit, RewriteResult, RewriteWarning};
use crate::vendor::bun_lockb::BunLockb;

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

#[cfg(test)]
mod tests {
    use super::super::Integrity;
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
}
