//! The pre-batching (one tokio `is_dir` hop per package) Composer crawl and
//! PURL lookup, kept verbatim as the equivalence oracle for the parent
//! module. Test-only; never compiled into the binary.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::{
    normalize_version, read_installed_json, resolve_package_dir, resolve_project_root,
    ComposerCrawler, ComposerPackageEntry,
};
use crate::crawlers::types::{CrawledPackage, CrawlerOptions};
use crate::utils::fs::is_dir;

pub(super) struct LegacyComposerCrawler;

impl LegacyComposerCrawler {
    pub(super) async fn crawl_all(options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let vendor_paths = ComposerCrawler::new()
            .get_vendor_paths(options)
            .await
            .unwrap_or_default();

        for vendor_path in &vendor_paths {
            let project_root = resolve_project_root(vendor_path).await;
            let entries = read_installed_json(vendor_path).await;
            for entry in entries {
                if let Some((namespace, name)) = entry.name.split_once('/') {
                    let Some(pkg_path) = resolve_package_dir(vendor_path, &project_root, &entry)
                    else {
                        continue;
                    };
                    if !is_dir(&pkg_path).await {
                        continue;
                    }

                    let version = normalize_version(&entry.version).to_string();

                    let ns_canon = namespace.to_ascii_lowercase();
                    let name_canon = name.to_ascii_lowercase();
                    let purl =
                        crate::utils::purl::build_composer_purl(&ns_canon, &name_canon, &version);

                    if !seen.insert(purl.clone()) {
                        continue;
                    }

                    packages.push(CrawledPackage {
                        name: name_canon,
                        version,
                        namespace: Some(ns_canon),
                        purl,
                        path: pkg_path,
                    });
                }
            }
        }

        packages
    }

    pub(super) async fn find_by_purls(
        vendor_path: &Path,
        purls: &[String],
    ) -> HashMap<String, CrawledPackage> {
        let mut result: HashMap<String, CrawledPackage> = HashMap::new();

        let entries = read_installed_json(vendor_path).await;
        let installed: HashMap<String, ComposerPackageEntry> = entries
            .into_iter()
            .map(|e| (e.name.to_ascii_lowercase(), e))
            .collect();
        let project_root = resolve_project_root(vendor_path).await;

        for purl in purls {
            if let Some(((namespace, name), version)) =
                crate::utils::purl::parse_composer_purl(purl)
            {
                let (namespace, name, version) =
                    (namespace.as_ref(), name.as_ref(), version.as_ref());
                let full_name = format!("{namespace}/{name}").to_ascii_lowercase();

                let Some(entry) = installed.get(&full_name) else {
                    continue;
                };

                if normalize_version(&entry.version) != normalize_version(version) {
                    continue;
                }

                let Some(pkg_dir) = resolve_package_dir(vendor_path, &project_root, entry) else {
                    continue;
                };

                if !is_dir(&pkg_dir).await {
                    continue;
                }

                result.insert(
                    purl.clone(),
                    CrawledPackage {
                        name: name.to_ascii_lowercase(),
                        version: version.to_string(),
                        namespace: Some(namespace.to_ascii_lowercase()),
                        purl: purl.clone(),
                        path: pkg_dir,
                    },
                );
            }
        }

        result
    }
}
