//! The pre-blocking-pool (one tokio hop per readdir/stat) NuGet package
//! scan and PURL lookup, kept verbatim as the equivalence oracle for the
//! synchronous walkers in the parent module. Test-only; never compiled into
//! the binary.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::{is_safe_nuget_coordinate, parse_legacy_dir_name, NuGetCrawler};
use crate::crawlers::types::{CrawledPackage, CrawlerOptions};
use crate::utils::fs::is_dir;

pub(super) struct LegacyNuGetCrawler;

impl LegacyNuGetCrawler {
    pub(super) async fn crawl_all(options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let pkg_paths = NuGetCrawler::new()
            .get_nuget_package_paths(options)
            .await
            .unwrap_or_default();

        for pkg_path in &pkg_paths {
            let found = Self::scan_package_dir(pkg_path, &mut seen).await;
            packages.extend(found);
        }

        packages
    }

    pub(super) async fn find_by_purls(
        pkg_path: &Path,
        purls: &[String],
    ) -> HashMap<String, CrawledPackage> {
        let mut result: HashMap<String, CrawledPackage> = HashMap::new();

        for purl in purls {
            let Some((name, version)) = crate::utils::purl::parse_nuget_purl(purl) else {
                continue;
            };
            let (name, version) = (name.as_ref(), version.as_ref());
            if !is_safe_nuget_coordinate(name, version) {
                continue;
            }

            let global_dir = pkg_path
                .join(name.to_lowercase())
                .join(version.to_lowercase());
            let legacy_dir = pkg_path.join(format!("{name}.{version}"));

            let found = if Self::verify_nuget_package(&global_dir).await {
                Some(global_dir)
            } else if Self::verify_nuget_package(&legacy_dir).await {
                Some(legacy_dir)
            } else {
                Self::find_legacy_dir_case_insensitive(pkg_path, name, version).await
            };

            if let Some(path) = found {
                result.insert(
                    purl.clone(),
                    CrawledPackage {
                        name: name.to_string(),
                        version: version.to_string(),
                        namespace: None,
                        purl: purl.clone(),
                        path,
                    },
                );
            }
        }

        result
    }

    async fn scan_package_dir(pkg_path: &Path, seen: &mut HashSet<String>) -> Vec<CrawledPackage> {
        let mut results = Vec::new();

        for entry in crate::utils::fs::list_dir_entries(pkg_path).await {
            if !crate::utils::fs::entry_is_dir(&entry).await {
                continue;
            }

            let dir_name = entry.file_name();
            let dir_name_str = dir_name.to_string_lossy();

            if dir_name_str.starts_with('.') {
                continue;
            }

            let entry_path = pkg_path.join(&*dir_name_str);

            if let Some(pkgs) =
                Self::scan_global_cache_package(&entry_path, &dir_name_str, seen).await
            {
                results.extend(pkgs);
                continue;
            }

            if let Some((name, version)) = parse_legacy_dir_name(&dir_name_str) {
                if Self::verify_nuget_package(&entry_path).await {
                    let purl = crate::utils::purl::build_nuget_purl(&name, &version);
                    if !seen.contains(&purl) {
                        seen.insert(purl.clone());
                        results.push(CrawledPackage {
                            name,
                            version,
                            namespace: None,
                            purl,
                            path: entry_path,
                        });
                    }
                }
            }
        }

        results
    }

    async fn scan_global_cache_package(
        name_dir: &Path,
        name: &str,
        seen: &mut HashSet<String>,
    ) -> Option<Vec<CrawledPackage>> {
        let mut found_any = false;
        let mut results = Vec::new();

        for ver_entry in crate::utils::fs::list_dir_entries(name_dir).await {
            if !crate::utils::fs::entry_is_dir(&ver_entry).await {
                continue;
            }

            let ver_name = ver_entry.file_name();
            let ver_str = ver_name.to_string_lossy();

            if !ver_str.starts_with(|c: char| c.is_ascii_digit()) {
                continue;
            }

            let ver_path = name_dir.join(&*ver_str);

            if Self::verify_nuget_package(&ver_path).await {
                found_any = true;
                let purl = crate::utils::purl::build_nuget_purl(name, &ver_str);
                if !seen.contains(&purl) {
                    seen.insert(purl.clone());
                    results.push(CrawledPackage {
                        name: name.to_string(),
                        version: ver_str.to_string(),
                        namespace: None,
                        purl,
                        path: ver_path,
                    });
                }
            }
        }

        if found_any {
            Some(results)
        } else {
            None
        }
    }

    async fn verify_nuget_package(path: &Path) -> bool {
        if !is_dir(path).await {
            return false;
        }

        if is_dir(&path.join("lib")).await {
            return true;
        }

        for entry in crate::utils::fs::list_dir_entries(path).await {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".nuspec") {
                    return true;
                }
            }
        }

        false
    }

    async fn find_legacy_dir_case_insensitive(
        pkg_path: &Path,
        name: &str,
        version: &str,
    ) -> Option<PathBuf> {
        let target = format!("{}.{}", name.to_lowercase(), version.to_lowercase());

        for entry in crate::utils::fs::list_dir_entries(pkg_path).await {
            let dir_name = entry.file_name();
            let dir_name_str = dir_name.to_string_lossy();
            if dir_name_str.to_lowercase() == target {
                let path = pkg_path.join(&*dir_name_str);
                if Self::verify_nuget_package(&path).await {
                    return Some(path);
                }
            }
        }

        None
    }
}
