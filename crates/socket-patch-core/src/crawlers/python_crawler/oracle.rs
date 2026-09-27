//! The pre-blocking-pool (one tokio hop per readdir/stat/read)
//! `site-packages` scan, kept verbatim as the equivalence oracle for the
//! parallel scan in the parent module. Test-only; never compiled into the
//! binary.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::{canonicalize_pypi_name, read_python_metadata, PythonCrawler};
use crate::crawlers::types::{CrawledPackage, CrawlerOptions};

pub(super) struct LegacyPythonCrawler;

impl LegacyPythonCrawler {
    pub(super) async fn crawl_all(options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let sp_paths = PythonCrawler::new()
            .get_site_packages_paths(options)
            .await
            .unwrap_or_default();

        for sp_path in &sp_paths {
            for (name, version) in list_dist_info_packages(sp_path).await {
                let purl = format!("pkg:pypi/{name}@{version}");
                if !seen.insert(purl.clone()) {
                    continue;
                }
                packages.push(CrawledPackage {
                    name,
                    version,
                    namespace: None,
                    purl,
                    path: sp_path.clone(),
                });
            }
        }

        packages
    }

    pub(super) async fn find_by_purls(
        site_packages_path: &Path,
        purls: &[String],
    ) -> HashMap<String, CrawledPackage> {
        let mut result = HashMap::new();

        let mut purl_lookup: HashMap<String, &str> = HashMap::new();
        for purl in purls {
            if let Some((name, version)) = crate::utils::purl::parse_pypi_purl(purl) {
                let key = format!("{}@{}", canonicalize_pypi_name(&name), version);
                purl_lookup.insert(key, purl.as_str());
            }
        }

        if purl_lookup.is_empty() {
            return result;
        }

        for (name, version) in list_dist_info_packages(site_packages_path).await {
            let key = format!("{name}@{version}");
            if let Some(&matched_purl) = purl_lookup.get(&key) {
                result.insert(
                    matched_purl.to_string(),
                    CrawledPackage {
                        name,
                        version,
                        namespace: None,
                        purl: matched_purl.to_string(),
                        path: site_packages_path.to_path_buf(),
                    },
                );
            }
        }

        result
    }
}

/// The old per-entry async `list_dist_info_packages`.
pub(super) async fn list_dist_info_packages(site_packages_path: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in crate::utils::fs::list_dir_entries(site_packages_path).await {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.ends_with(".dist-info") {
            continue;
        }
        let dist_info_path = site_packages_path.join(&*name_str);
        if let Some((raw_name, version)) = read_python_metadata(&dist_info_path).await {
            out.push((canonicalize_pypi_name(&raw_name), version));
        }
    }
    out
}
