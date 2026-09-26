//! Read-only installed-byte checks for hosted Python redirects.

use std::collections::{BTreeMap, BTreeSet};

use socket_patch_core::crawlers::{types::CrawlerOptions, PythonCrawler};
use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::vex::verify::judge_installed_record;

use super::StaleInstallOutcome;

/// A lock rewrite cannot prove a warm virtualenv has installed the wheel.
/// Use the same discovery as apply (including Poetry's out-of-tree venvs),
/// and inspect every interpreter rather than deduplicating by package name.
/// Missing/unreadable files are not positive evidence of stale bytes.
pub(super) async fn stale_install_warnings(
    common: &crate::args::GlobalArgs,
    confirmed: &[(String, String)],
    pipenv_uuids: &BTreeSet<String>,
    // This run's fetched records MERGED with the ledger's persisted ones
    // (the caller hands the post-merge ledger map), looked up by uuid.
    records: &BTreeMap<String, PatchRecord>,
) -> StaleInstallOutcome {
    let mut out = StaleInstallOutcome::default();
    let candidates: Vec<_> = confirmed
        .iter()
        .filter(|(purl, _)| purl.starts_with("pkg:pypi/"))
        .filter_map(|(purl, uuid)| {
            records
                .values()
                .find(|record| &record.uuid == uuid)
                .filter(|record| !record.files.is_empty())
                .map(|record| (purl, record))
        })
        .collect();
    if candidates.is_empty() {
        return out;
    }

    let crawler = PythonCrawler::new();
    // Only venvs that belong to THIS project (VIRTUAL_ENV, ./.venv, ./venv,
    // Poetry's and Pipenv's out-of-tree venvs): the crawler's project-marker
    // fallback to the global interpreters would judge some unrelated Python's
    // copy of the release (a tool venv on PATH) and warn about a venv the
    // project's installer never touches — a false positive that also fails
    // the same-run --vex. --global / --global-prefix keep their meaning.
    let paths = if common.global || common.global_prefix.is_some() {
        crawler
            .get_site_packages_paths(&CrawlerOptions {
                cwd: common.cwd.clone(),
                global: common.global,
                global_prefix: common.global_prefix.clone(),
            })
            .await
            .unwrap_or_default()
    } else {
        socket_patch_core::crawlers::python_crawler::find_local_venv_site_packages(&common.cwd)
            .await
    };

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
    let mut pipenv_purls: BTreeSet<String> = BTreeSet::new();
    // Every candidate's installed copy in every site, from one listing per
    // site — the per-candidate lookups the loop below consumes, in the same
    // (candidate, site) order.
    let bases: Vec<String> = candidates
        .iter()
        .map(|(purl, _)| strip_purl_qualifiers(purl).to_string())
        .collect();
    let mut found_per_site = Vec::with_capacity(paths.len());
    for site in &paths {
        found_per_site.push(crawler.find_each_by_purl(site, &bases).await);
    }
    for (index, (purl, record)) in candidates.into_iter().enumerate() {
        if pipenv_uuids.contains(&record.uuid) {
            pipenv_purls.insert(purl.clone());
        }
        for found in &found_per_site {
            let Some(pkg) = &found[index] else {
                continue;
            };
            let judgment: &mut Judgment = judgments
                .entry((pkg.path.clone(), pkg.name.clone(), pkg.version.clone()))
                .or_default();
            judgment.purls.insert(purl.clone());
            let judged = judge_installed_record(&pkg.path, record).await;
            if judged.patched {
                judgment.patched = true;
            } else if judged.stale_evidence {
                judgment.stale = true;
            }
        }
    }
    for ((site, _, _), judgment) in judgments {
        if judgment.patched || !judgment.stale {
            continue;
        }
        for purl in judgment.purls {
            // Pipenv never reinstalls a release that is already present
            // (`install`, `install --deploy`, `sync` all keep the installed
            // bytes on every major), and `pipenv uninstall` rewrites the
            // Pipfile and re-locks the patch away — name the verified remedy.
            let remedy = if pipenv_purls.contains(&purl) {
                let name = strip_purl_qualifiers(&purl)
                    .strip_prefix("pkg:pypi/")
                    .and_then(|rest| rest.split('@').next())
                    .unwrap_or("<package>")
                    .to_string();
                format!(
                    "Pipenv does not reinstall a release that is already present (`pipenv \
                     install`, `pipenv install --deploy` and `pipenv sync` all keep those \
                     bytes), so the rewritten Pipfile.lock only protects fresh installs. \
                     Reinstall it from the lock without touching the Pipfile: `pipenv run pip \
                     uninstall -y {name} && pipenv sync` (`pipenv install --deploy` before \
                     Pipenv 2018), or `pipenv --rm && pipenv sync` for a clean virtualenv — \
                     NOT `pipenv uninstall`, which rewrites the Pipfile and re-locks the \
                     patch away; then `socket-patch vex --product <purl>` re-verifies the \
                     installed files."
                )
            } else {
                "Reinstall from the rewritten lock in this interpreter and verify with \
                 `socket-patch vex`. Poetry before 1.4 may keep same-version packages: \
                 recreate the project virtualenv or uninstall this package before \
                 installing."
                    .to_string()
            };
            out.warnings.push(serde_json::json!({
                "code": "redirect_pypi_stale_install",
                "detail": format!(
                    "{purl} was redirected to a hosted patch, but installed files in {} \
                     still differ from the patched hashes. {remedy} The installed files \
                     were left unchanged.",
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
        let out = stale_install_warnings(&common, &confirmed, &BTreeSet::new(), &ledger).await;
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
        let out = stale_install_warnings(&common, &confirmed, &BTreeSet::new(), &ledger).await;
        assert!(out.stale_purls.is_empty());
        assert!(out.warnings.is_empty());
    }
}
