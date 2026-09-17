//! Read-only installed-byte checks for hosted Python redirects.

use std::collections::{BTreeMap, BTreeSet};

use socket_patch_core::crawlers::{types::CrawlerOptions, PythonCrawler};
use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::vex::verify::verify_patch_record;

use super::{installed_stale_positive_evidence, StaleInstallOutcome};

/// A lock rewrite cannot prove a warm virtualenv has installed the wheel.
/// Use the same discovery as apply (including Poetry's out-of-tree venvs),
/// and inspect every interpreter rather than deduplicating by package name.
/// Missing/unreadable files are not positive evidence of stale bytes.
pub(super) async fn stale_install_warnings(
    common: &crate::args::GlobalArgs,
    confirmed: &[(String, String)],
    records: &BTreeMap<String, PatchRecord>,
    ledger_records: &BTreeMap<String, PatchRecord>,
) -> StaleInstallOutcome {
    let mut out = StaleInstallOutcome::default();
    let candidates: Vec<_> = confirmed
        .iter()
        .filter(|(purl, _)| purl.starts_with("pkg:pypi/"))
        .filter_map(|(purl, uuid)| {
            records
                .values()
                .chain(ledger_records.values())
                .find(|record| &record.uuid == uuid)
                .filter(|record| !record.files.is_empty())
                .map(|record| (purl, record))
        })
        .collect();
    if candidates.is_empty() {
        return out;
    }

    let crawler = PythonCrawler::new();
    let paths = crawler
        .get_site_packages_paths(&CrawlerOptions {
            cwd: common.cwd.clone(),
            global: common.global,
            global_prefix: common.global_prefix.clone(),
        })
        .await
        .unwrap_or_default();

    #[derive(Default)]
    struct Judgment {
        purls: BTreeSet<String>,
        patched: bool,
        stale: bool,
    }
    // Python distributions share site-packages, so the key must include
    // the package identity. Any matching artifact variant can prove this
    // package patched; a healthy *different* package cannot.
    let mut judgments = BTreeMap::new();
    for (purl, record) in candidates {
        let base = strip_purl_qualifiers(purl).to_string();
        for site in &paths {
            let found = crawler
                .find_by_purls(site, std::slice::from_ref(&base))
                .await
                .unwrap_or_default();
            let Some(pkg) = found.get(&base) else {
                continue;
            };
            let judgment: &mut Judgment = judgments
                .entry((pkg.path.clone(), pkg.name.clone(), pkg.version.clone()))
                .or_default();
            judgment.purls.insert(purl.clone());
            if verify_patch_record(&pkg.path, record).await.is_ok() {
                judgment.patched = true;
            } else if installed_stale_positive_evidence(&pkg.path, record).await {
                judgment.stale = true;
            }
        }
    }
    for ((site, _, _), judgment) in judgments {
        if judgment.patched || !judgment.stale {
            continue;
        }
        for purl in judgment.purls {
            out.warnings.push(serde_json::json!({
                "code": "redirect_pypi_stale_install",
                "detail": format!(
                    "{purl} was redirected to a hosted patch, but installed files in {} \
                     still differ from the patched hashes. Reinstall from the rewritten \
                     lock in this interpreter and verify with `socket-patch vex`. \
                     Poetry before 1.4 may keep same-version packages: recreate the \
                     project virtualenv or uninstall this package before installing. \
                     The installed files were left unchanged.",
                    site.display()
                ),
            }));
            out.stale_purls.insert(purl);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
    use socket_patch_core::manifest::schema::PatchFileInfo;

    fn record(uuid: &str, file: &str, patched: &[u8]) -> PatchRecord {
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: "2026-09-17T00:00:00Z".to_string(),
            files: [(
                file.to_string(),
                PatchFileInfo {
                    before_hash: compute_git_sha256_from_bytes(b"upstream"),
                    after_hash: compute_git_sha256_from_bytes(patched),
                },
            )]
            .into(),
            vulnerabilities: Default::default(),
            description: String::new(),
            license: String::new(),
            tier: "free".to_string(),
        }
    }

    #[tokio::test]
    async fn prefix_probe_groups_variants_by_package_and_uses_ledger_records() {
        let tmp = tempfile::tempdir().unwrap();
        let site = tmp.path().join("custom-site-packages");
        for name in ["first", "second"] {
            std::fs::create_dir_all(site.join(format!("{name}-1.0.dist-info"))).unwrap();
        }
        std::fs::write(site.join("first.py"), b"upstream").unwrap();
        std::fs::write(site.join("second.py"), b"patched").unwrap();
        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            global_prefix: Some(site.clone()),
            ..Default::default()
        };
        let first = "pkg:pypi/first@1.0?artifact_id=one";
        let second = "pkg:pypi/second@1.0";
        let mut confirmed = vec![
            (first.to_string(), "first-uuid".to_string()),
            (second.to_string(), "second-uuid".to_string()),
        ];
        // Deliberately unrelated keys: lookup must use each record's UUID.
        let mut ledger = BTreeMap::from([
            ("one".into(), record("first-uuid", "first.py", b"patched")),
            ("two".into(), record("second-uuid", "second.py", b"patched")),
        ]);
        let out = stale_install_warnings(&common, &confirmed, &BTreeMap::new(), &ledger).await;
        assert_eq!(out.stale_purls, BTreeSet::from([first.to_string()]));
        assert_eq!(out.warnings.len(), 1);
        assert!(out.warnings[0]["detail"]
            .as_str()
            .unwrap()
            .contains(&site.display().to_string()));

        // An installed package can match a different wheel variant. That
        // variant, unlike the healthy sibling distribution, proves it patched.
        confirmed.push((
            "pkg:pypi/first@1.0?artifact_id=two".into(),
            "variant".into(),
        ));
        ledger.insert("three".into(), record("variant", "first.py", b"upstream"));
        let out = stale_install_warnings(&common, &confirmed, &BTreeMap::new(), &ledger).await;
        assert!(out.stale_purls.is_empty());
        assert!(out.warnings.is_empty());
    }
}
