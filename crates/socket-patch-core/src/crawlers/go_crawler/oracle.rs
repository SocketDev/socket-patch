//! The pre-blocking-pool (one tokio hop per readdir/stat) Go module cache
//! walk and PURL lookup, kept verbatim as the equivalence oracle for the
//! synchronous walkers in the parent module. Test-only; never compiled into
//! the binary.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::{
    decode_module_path, encode_module_path, is_safe_module_coordinate, split_module_path, GoCrawler,
};
use crate::crawlers::types::{CrawledPackage, CrawlerOptions};
use crate::utils::fs::is_dir;

pub(super) struct LegacyGoCrawler;

impl LegacyGoCrawler {
    pub(super) async fn crawl_all(options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let cache_paths = GoCrawler::new()
            .get_module_cache_paths(options)
            .await
            .unwrap_or_default();

        for cache_path in &cache_paths {
            Self::scan_dir_recursive(cache_path, cache_path, &mut seen, &mut packages).await;
        }

        packages
    }

    pub(super) async fn find_by_purls(
        cache_path: &Path,
        purls: &[String],
    ) -> HashMap<String, CrawledPackage> {
        let mut result: HashMap<String, CrawledPackage> = HashMap::new();

        for purl in purls {
            if let Some((module_path, version)) = crate::utils::purl::parse_golang_purl(purl) {
                let (module_path, version) = (module_path.as_ref(), version.as_ref());
                if !is_safe_module_coordinate(module_path, version) {
                    continue;
                }
                let encoded = encode_module_path(module_path);
                let encoded_version = encode_module_path(version);

                let module_dir = cache_path.join(format!("{encoded}@{encoded_version}"));

                if is_dir(&module_dir).await {
                    if is_partially_extracted(cache_path, &encoded, &encoded_version).await {
                        continue;
                    }
                    let (namespace, name) = split_module_path(module_path);

                    result.insert(
                        purl.clone(),
                        CrawledPackage {
                            name: name.to_string(),
                            version: version.to_string(),
                            namespace: Some(namespace.to_string()),
                            purl: purl.clone(),
                            path: module_dir,
                        },
                    );
                }
            }
        }

        result
    }

    fn scan_dir_recursive<'a>(
        base_path: &'a Path,
        current_path: &'a Path,
        seen: &'a mut HashSet<String>,
        results: &'a mut Vec<CrawledPackage>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
        Box::pin(async move {
            for entry in crate::utils::fs::list_dir_entries(current_path).await {
                if !crate::utils::fs::entry_is_dir(&entry).await {
                    continue;
                }

                let dir_name = entry.file_name();
                let dir_name_str = dir_name.to_string_lossy();

                if dir_name_str.starts_with('.')
                    || (dir_name_str == "cache" && current_path == base_path)
                {
                    continue;
                }

                let full_path = current_path.join(&dir_name);

                if dir_name_str.contains('@') {
                    if let Some(pkg) = Self::parse_versioned_dir(base_path, &full_path, seen).await
                    {
                        results.push(pkg);
                    }
                } else {
                    Self::scan_dir_recursive(base_path, &full_path, seen, results).await;
                }
            }
        })
    }

    async fn parse_versioned_dir(
        base_path: &Path,
        dir_path: &Path,
        seen: &mut HashSet<String>,
    ) -> Option<CrawledPackage> {
        let rel_path = dir_path.strip_prefix(base_path).ok()?;
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");

        let at_idx = rel_str.rfind('@')?;
        let encoded_module_path = &rel_str[..at_idx];
        let version = &rel_str[at_idx + 1..];

        if encoded_module_path.is_empty() || version.is_empty() {
            return None;
        }

        if is_partially_extracted(base_path, encoded_module_path, version).await {
            return None;
        }

        let module_path = decode_module_path(encoded_module_path);
        let version = decode_module_path(version);

        let purl = crate::utils::purl::build_golang_purl(&module_path, &version);

        if seen.contains(&purl) {
            return None;
        }
        seen.insert(purl.clone());

        let (namespace, name) = split_module_path(&module_path);

        Some(CrawledPackage {
            name: name.to_string(),
            version: version.to_string(),
            namespace: Some(namespace.to_string()),
            purl,
            path: dir_path.to_path_buf(),
        })
    }
}

async fn is_partially_extracted(
    cache_path: &Path,
    encoded_module: &str,
    encoded_version: &str,
) -> bool {
    let marker = cache_path
        .join("cache")
        .join("download")
        .join(encoded_module)
        .join("@v")
        .join(format!("{encoded_version}.partial"));
    tokio::fs::metadata(&marker).await.is_ok()
}
