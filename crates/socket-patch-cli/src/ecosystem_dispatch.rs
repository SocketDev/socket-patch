use socket_patch_core::crawlers::{
    CrawledPackage, CrawlerOptions, Ecosystem, NpmCrawler, PythonCrawler,
};
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[cfg(feature = "cargo")]
use socket_patch_core::crawlers::CargoCrawler;

/// Partition PURLs by ecosystem, filtering by the `--ecosystems` flag if set.
pub fn partition_purls(
    purls: &[String],
    allowed_ecosystems: Option<&[String]>,
) -> HashMap<Ecosystem, Vec<String>> {
    let mut map: HashMap<Ecosystem, Vec<String>> = HashMap::new();

    for purl in purls {
        if let Some(eco) = Ecosystem::from_purl(purl) {
            if let Some(allowed) = allowed_ecosystems {
                if !allowed.iter().any(|a| a == eco.cli_name()) {
                    continue;
                }
            }
            map.entry(eco).or_default().push(purl.clone());
        }
    }

    map
}

/// For each ecosystem in the partitioned map, create the crawler, discover
/// source paths, and look up the given PURLs. Returns a unified
/// `purl -> path` map.
pub async fn find_packages_for_purls(
    partitioned: &HashMap<Ecosystem, Vec<String>>,
    options: &CrawlerOptions,
    silent: bool,
) -> HashMap<String, PathBuf> {
    let mut all_packages: HashMap<String, PathBuf> = HashMap::new();

    // npm
    if let Some(npm_purls) = partitioned.get(&Ecosystem::Npm) {
        if !npm_purls.is_empty() {
            let npm_crawler = NpmCrawler;
            match npm_crawler.get_node_modules_paths(options).await {
                Ok(nm_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = nm_paths.first() {
                            println!("Using global npm packages at: {}", first.display());
                        }
                    }
                    for nm_path in &nm_paths {
                        if let Ok(packages) = npm_crawler.find_by_purls(nm_path, npm_purls).await {
                            for (purl, pkg) in packages {
                                all_packages.entry(purl).or_insert(pkg.path);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find npm packages: {e}");
                    }
                }
            }
        }
    }

    // pypi — deduplicate by base PURL (stripping qualifiers)
    if let Some(pypi_purls) = partitioned.get(&Ecosystem::Pypi) {
        if !pypi_purls.is_empty() {
            let python_crawler = PythonCrawler;
            let base_pypi_purls: Vec<String> = pypi_purls
                .iter()
                .map(|p| strip_purl_qualifiers(p).to_string())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            match python_crawler.get_site_packages_paths(options).await {
                Ok(sp_paths) => {
                    for sp_path in &sp_paths {
                        if let Ok(packages) =
                            python_crawler.find_by_purls(sp_path, &base_pypi_purls).await
                        {
                            for (purl, pkg) in packages {
                                all_packages.entry(purl).or_insert(pkg.path);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find Python packages: {e}");
                    }
                }
            }
        }
    }

    // cargo
    #[cfg(feature = "cargo")]
    if let Some(cargo_purls) = partitioned.get(&Ecosystem::Cargo) {
        if !cargo_purls.is_empty() {
            let cargo_crawler = CargoCrawler;
            match cargo_crawler.get_crate_source_paths(options).await {
                Ok(src_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = src_paths.first() {
                            println!("Using cargo crate sources at: {}", first.display());
                        }
                    }
                    for src_path in &src_paths {
                        if let Ok(packages) =
                            cargo_crawler.find_by_purls(src_path, cargo_purls).await
                        {
                            for (purl, pkg) in packages {
                                all_packages.entry(purl).or_insert(pkg.path);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find Cargo crates: {e}");
                    }
                }
            }
        }
    }

    all_packages
}

/// Crawl all enabled ecosystems and return all packages plus per-ecosystem counts.
pub async fn crawl_all_ecosystems(
    options: &CrawlerOptions,
) -> (Vec<CrawledPackage>, HashMap<Ecosystem, usize>) {
    let mut all_packages = Vec::new();
    let mut counts: HashMap<Ecosystem, usize> = HashMap::new();

    let npm_crawler = NpmCrawler;
    let npm_packages = npm_crawler.crawl_all(options).await;
    counts.insert(Ecosystem::Npm, npm_packages.len());
    all_packages.extend(npm_packages);

    let python_crawler = PythonCrawler;
    let python_packages = python_crawler.crawl_all(options).await;
    counts.insert(Ecosystem::Pypi, python_packages.len());
    all_packages.extend(python_packages);

    #[cfg(feature = "cargo")]
    {
        let cargo_crawler = CargoCrawler;
        let cargo_packages = cargo_crawler.crawl_all(options).await;
        counts.insert(Ecosystem::Cargo, cargo_packages.len());
        all_packages.extend(cargo_packages);
    }

    (all_packages, counts)
}

/// Variant of `find_packages_for_purls` for rollback, which needs to remap
/// pypi qualified PURLs (with `?artifact_id=...`) to the base PURL found
/// by the crawler.
pub async fn find_packages_for_rollback(
    partitioned: &HashMap<Ecosystem, Vec<String>>,
    options: &CrawlerOptions,
    silent: bool,
) -> HashMap<String, PathBuf> {
    let mut all_packages: HashMap<String, PathBuf> = HashMap::new();

    // npm
    if let Some(npm_purls) = partitioned.get(&Ecosystem::Npm) {
        if !npm_purls.is_empty() {
            let npm_crawler = NpmCrawler;
            match npm_crawler.get_node_modules_paths(options).await {
                Ok(nm_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = nm_paths.first() {
                            println!("Using global npm packages at: {}", first.display());
                        }
                    }
                    for nm_path in &nm_paths {
                        if let Ok(packages) = npm_crawler.find_by_purls(nm_path, npm_purls).await {
                            for (purl, pkg) in packages {
                                all_packages.entry(purl).or_insert(pkg.path);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find npm packages: {e}");
                    }
                }
            }
        }
    }

    // pypi — remap qualified PURLs to found base PURLs
    if let Some(pypi_purls) = partitioned.get(&Ecosystem::Pypi) {
        if !pypi_purls.is_empty() {
            let python_crawler = PythonCrawler;
            let base_pypi_purls: Vec<String> = pypi_purls
                .iter()
                .map(|p| strip_purl_qualifiers(p).to_string())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            if let Ok(sp_paths) = python_crawler.get_site_packages_paths(options).await {
                for sp_path in &sp_paths {
                    if let Ok(packages) =
                        python_crawler.find_by_purls(sp_path, &base_pypi_purls).await
                    {
                        for (base_purl, pkg) in packages {
                            for qualified_purl in pypi_purls {
                                if strip_purl_qualifiers(qualified_purl) == base_purl
                                    && !all_packages.contains_key(qualified_purl)
                                {
                                    all_packages
                                        .insert(qualified_purl.clone(), pkg.path.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // cargo
    #[cfg(feature = "cargo")]
    if let Some(cargo_purls) = partitioned.get(&Ecosystem::Cargo) {
        if !cargo_purls.is_empty() {
            let cargo_crawler = CargoCrawler;
            match cargo_crawler.get_crate_source_paths(options).await {
                Ok(src_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = src_paths.first() {
                            println!("Using cargo crate sources at: {}", first.display());
                        }
                    }
                    for src_path in &src_paths {
                        if let Ok(packages) =
                            cargo_crawler.find_by_purls(src_path, cargo_purls).await
                        {
                            for (purl, pkg) in packages {
                                all_packages.entry(purl).or_insert(pkg.path);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find Cargo crates: {e}");
                    }
                }
            }
        }
    }

    all_packages
}
