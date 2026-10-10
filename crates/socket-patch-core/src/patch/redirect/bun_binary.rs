//! Native hosted redirects for bun.lockb. Structured package snapshots keep
//! scoped rollback independent of other packages in the same binary lock.
use super::{DepOverride, FileEdit, RewriteResult, RewriteWarning};
use crate::vendor::bun_lock_text::user_tarball_version;
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
        let mut skipped: Vec<RewriteWarning> = Vec::new();
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
            // A user URL / `file:` tarball record of this version installs
            // from its own resolution beside any redirected copy and stays
            // unpatched (#497): never rewired, always reported.
            for p in packages.iter().filter(|p| {
                p.name == name
                    && p.version.is_none()
                    && !matching.iter().any(|m| m.id == p.id)
                    && user_tarball_version(&name, &p.resolution) == Some(dep.version.as_str())
            }) {
                skipped.push(RewriteWarning {
                    code: "redirect_bun_non_registry_entry_skipped".into(),
                    detail: format!(
                        "bun.lockb package #{} installs {name}@{} from a URL or local tarball, \
                         not the registry, and CANNOT be redirected — bun installs it from that \
                         resolution, so that copy stays UNPATCHED; depend on the registry \
                         release to patch it",
                        p.id, dep.version,
                    ),
                });
            }
            if matching.is_empty() && !skipped.is_empty() {
                return Ok((Vec::new(), false));
            }
            if matching.is_empty() {
                return Err(format!(
                    "no rewritable bun.lockb entry for {name}@{}",
                    dep.version
                ));
            }
            let mut wired = false;
            for p in matching {
                // A bundled edge's copy is unpacked from its parent's
                // tarball, which no redirect reaches (#469). A record ONLY
                // bundled edges reach is skipped; one Bun shares with a
                // regular install is still redirected for that install.
                if p.bundled {
                    skipped.push(RewriteWarning {
                        code: "redirect_bun_bundled_instance_skipped".into(),
                        detail: format!(
                            "bun.lockb package #{} ({name}@{}) is {}bundled inside its \
                             parent's tarball and CANNOT be redirected there — that copy \
                             stays UNPATCHED; vendor or update the bundling parent to cover it",
                            p.id,
                            dep.version,
                            if p.bundled_only { "" } else { "also " },
                        ),
                    });
                    if p.bundled_only {
                        continue;
                    }
                }
                wired = true;
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
            Ok::<_, String>((edits, wired))
        })();
        if !skipped.is_empty() {
            result.bundled_skipped_uuids.insert(dep.patch_uuid.clone());
        }
        result.warnings.append(&mut skipped);
        match attempt {
            Ok((_, false)) => {}
            Ok((edits, true)) => {
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

    fn bundled_fixture(shape: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/bun-lockb-bundled")
                .join(shape)
                .join("bun.lockb"),
        )
        .unwrap()
    }

    fn is_number() -> DepOverride {
        DepOverride {
            name: "is-number".into(),
            artifact_url: "https://patch.example.test/7.0.0/is-number-7.0.0.tgz".into(),
            ..dep("7.0.0")
        }
    }

    /// REGRESSION (#469): a record only a bundled edge reaches is unpacked
    /// from the parent's tarball, so redirecting it installs nothing: it is
    /// skipped loudly, not counted, and the uuid is not confirmed. A record
    /// Bun shares between a regular and a bundled install IS redirected
    /// (the regular copy gets the patch) with the same loud warning, since
    /// the bundled copy stays unpatched.
    #[test]
    fn bundled_records_are_not_redirected_silently() {
        let only = bundled_fixture("only");
        let mut result = RewriteResult::default();
        rewrite_bun_binary(&only, &[is_number()], &mut result);
        assert!(result.binary_files.is_empty(), "lock untouched");
        assert!(result.edits.is_empty(), "{:?}", result.edits);
        assert!(result.confirmed_bun_binary_uuids.is_empty());
        let codes: Vec<_> = result.warnings.iter().map(|w| w.code.as_str()).collect();
        assert_eq!(
            codes,
            ["redirect_bun_bundled_instance_skipped"],
            "{:?}",
            result.warnings
        );
        assert!(result.warnings[0].detail.contains("UNPATCHED"));
        assert!(result.bundled_skipped_uuids.contains("7.0.0"));

        let both = bundled_fixture("both");
        let mut result = RewriteResult::default();
        rewrite_bun_binary(&both, &[is_number()], &mut result);
        assert_eq!(result.edits.len(), 1, "{:?}", result.edits);
        assert!(result.binary_files.contains_key("bun.lockb"));
        let codes: Vec<_> = result.warnings.iter().map(|w| w.code.as_str()).collect();
        assert_eq!(
            codes,
            ["redirect_bun_bundled_instance_skipped"],
            "{:?}",
            result.warnings
        );
        assert!(result.bundled_skipped_uuids.contains("7.0.0"));
    }

    /// REGRESSION (#497): Bun 1.1.45 locks a root URL / `file:` tarball
    /// dependency on is-number@6.0.0 beside is-odd's nested registry copy.
    /// Bun installs the tarball record from its own resolution, so only the
    /// registry record is redirected and the run says, loudly, that the
    /// tarball copy stays unpatched; the in-run VEX must not assume it.
    #[test]
    fn user_tarball_records_are_reported_unpatched() {
        let is_number_6 = DepOverride {
            name: "is-number".into(),
            artifact_url: "https://patch.example.test/6.0.0/is-number-6.0.0.tgz".into(),
            ..dep("6.0.0")
        };
        for shape in ["url", "file"] {
            let lock = std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/bun-lockb-user-tarball")
                    .join(shape)
                    .join("bun.lockb"),
            )
            .unwrap();
            let mut result = RewriteResult::default();
            rewrite_bun_binary(&lock, std::slice::from_ref(&is_number_6), &mut result);
            assert_eq!(result.edits.len(), 1, "{shape}: {:?}", result.edits);
            assert!(result.confirmed_bun_binary_uuids.contains("6.0.0"));
            let codes: Vec<_> = result.warnings.iter().map(|w| w.code.as_str()).collect();
            assert_eq!(
                codes,
                ["redirect_bun_non_registry_entry_skipped"],
                "{shape}: {:?}",
                result.warnings
            );
            assert!(result.warnings[0].detail.contains("UNPATCHED"));
            assert!(result.bundled_skipped_uuids.contains("6.0.0"), "{shape}");
            let rewired = BunLockb::parse_packages(&result.binary_files["bun.lockb"]).unwrap();
            assert!(
                rewired.iter().any(|p| p.name == "is-number"
                    && p.version.is_none()
                    && p.resolution.ends_with("is-number-6.0.0.tgz")
                    && !p.resolution.contains("patch.example.test")),
                "{shape}: the tarball record keeps its resolution: {rewired:?}"
            );
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
