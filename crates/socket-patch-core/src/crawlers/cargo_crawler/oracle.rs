//! The pre-blocking-pool (one tokio hop per readdir/stat/read) crate source
//! scan, kept verbatim as the equivalence oracle for the parallel scan in
//! the parent module. Test-only; never compiled into the binary.

use std::collections::HashSet;
use std::path::Path;

use super::{parse_cargo_toml_name_version, CargoCrawler};
use crate::crawlers::types::{CrawledPackage, CrawlerOptions};

pub(super) struct LegacyCargoCrawler;

impl LegacyCargoCrawler {
    pub(super) async fn crawl_all(options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let src_paths = CargoCrawler::new()
            .get_crate_source_paths(options)
            .await
            .unwrap_or_default();

        for src_path in &src_paths {
            let found = Self::scan_crate_source(src_path, &mut seen).await;
            packages.extend(found);
        }

        packages
    }

    async fn scan_crate_source(src_path: &Path, seen: &mut HashSet<String>) -> Vec<CrawledPackage> {
        let mut results = Vec::new();

        for entry in crate::utils::fs::list_dir_entries(src_path).await {
            if !crate::utils::fs::entry_is_dir(&entry).await {
                continue;
            }

            let dir_name = entry.file_name();
            let dir_name_str = dir_name.to_string_lossy();

            if dir_name_str.starts_with('.') {
                continue;
            }

            let crate_path = src_path.join(&*dir_name_str);
            if let Some(pkg) = Self::read_crate_cargo_toml(&crate_path, &dir_name_str, seen).await {
                results.push(pkg);
            }
        }

        results
    }

    async fn read_crate_cargo_toml(
        crate_path: &Path,
        dir_name: &str,
        seen: &mut HashSet<String>,
    ) -> Option<CrawledPackage> {
        let cargo_toml_path = crate_path.join("Cargo.toml");
        let content = tokio::fs::read_to_string(&cargo_toml_path).await.ok()?;

        let (name, version) = parse_cargo_toml_name_version(&content)
            .or_else(|| CargoCrawler::parse_dir_name_version(dir_name))?;

        let purl = crate::utils::purl::build_cargo_purl(&name, &version);
        if !seen.insert(purl.clone()) {
            return None;
        }

        Some(CrawledPackage {
            name,
            version,
            namespace: None,
            purl,
            path: crate_path.to_path_buf(),
        })
    }
}
