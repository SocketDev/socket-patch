use socket_patch_core::crawlers::{
    CrawledPackage, CrawlerOptions, Ecosystem, NpmCrawler, PythonCrawler,
};
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[cfg(feature = "cargo")]
use socket_patch_core::crawlers::CargoCrawler;
#[cfg(feature = "gem")]
use socket_patch_core::crawlers::RubyCrawler;
#[cfg(feature = "golang")]
use socket_patch_core::crawlers::GoCrawler;
#[cfg(feature = "maven")]
use socket_patch_core::crawlers::MavenCrawler;
#[cfg(feature = "composer")]
use socket_patch_core::crawlers::ComposerCrawler;
#[cfg(feature = "nuget")]
use socket_patch_core::crawlers::NuGetCrawler;

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

    // gem
    #[cfg(feature = "gem")]
    if let Some(gem_purls) = partitioned.get(&Ecosystem::Gem) {
        if !gem_purls.is_empty() {
            let ruby_crawler = RubyCrawler;
            match ruby_crawler.get_gem_paths(options).await {
                Ok(gem_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = gem_paths.first() {
                            println!("Using ruby gem paths at: {}", first.display());
                        }
                    }
                    for gem_path in &gem_paths {
                        if let Ok(packages) =
                            ruby_crawler.find_by_purls(gem_path, gem_purls).await
                        {
                            for (purl, pkg) in packages {
                                all_packages.entry(purl).or_insert(pkg.path);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find Ruby gems: {e}");
                    }
                }
            }
        }
    }

    // golang
    #[cfg(feature = "golang")]
    if let Some(golang_purls) = partitioned.get(&Ecosystem::Golang) {
        if !golang_purls.is_empty() {
            let go_crawler = GoCrawler;
            match go_crawler.get_module_cache_paths(options).await {
                Ok(cache_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = cache_paths.first() {
                            println!("Using Go module cache at: {}", first.display());
                        }
                    }
                    for cache_path in &cache_paths {
                        if let Ok(packages) =
                            go_crawler.find_by_purls(cache_path, golang_purls).await
                        {
                            for (purl, pkg) in packages {
                                all_packages.entry(purl).or_insert(pkg.path);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find Go modules: {e}");
                    }
                }
            }
        }
    }

    // maven
    #[cfg(feature = "maven")]
    if let Some(maven_purls) = partitioned.get(&Ecosystem::Maven) {
        if !maven_purls.is_empty() {
            let maven_crawler = MavenCrawler;
            match maven_crawler.get_maven_repo_paths(options).await {
                Ok(repo_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = repo_paths.first() {
                            println!("Using Maven repository at: {}", first.display());
                        }
                    }
                    for repo_path in &repo_paths {
                        if let Ok(packages) =
                            maven_crawler.find_by_purls(repo_path, maven_purls).await
                        {
                            for (purl, pkg) in packages {
                                all_packages.entry(purl).or_insert(pkg.path);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find Maven packages: {e}");
                    }
                }
            }
        }
    }

    // composer
    #[cfg(feature = "composer")]
    if let Some(composer_purls) = partitioned.get(&Ecosystem::Composer) {
        if !composer_purls.is_empty() {
            let composer_crawler = ComposerCrawler;
            match composer_crawler.get_vendor_paths(options).await {
                Ok(vendor_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = vendor_paths.first() {
                            println!("Using PHP vendor packages at: {}", first.display());
                        }
                    }
                    for vendor_path in &vendor_paths {
                        if let Ok(packages) =
                            composer_crawler.find_by_purls(vendor_path, composer_purls).await
                        {
                            for (purl, pkg) in packages {
                                all_packages.entry(purl).or_insert(pkg.path);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find PHP packages: {e}");
                    }
                }
            }
        }
    }

    // nuget
    #[cfg(feature = "nuget")]
    if let Some(nuget_purls) = partitioned.get(&Ecosystem::Nuget) {
        if !nuget_purls.is_empty() {
            let nuget_crawler = NuGetCrawler;
            match nuget_crawler.get_nuget_package_paths(options).await {
                Ok(pkg_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = pkg_paths.first() {
                            println!("Using NuGet packages at: {}", first.display());
                        }
                    }
                    for pkg_path in &pkg_paths {
                        if let Ok(packages) =
                            nuget_crawler.find_by_purls(pkg_path, nuget_purls).await
                        {
                            for (purl, pkg) in packages {
                                all_packages.entry(purl).or_insert(pkg.path);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find NuGet packages: {e}");
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

    #[cfg(feature = "gem")]
    {
        let ruby_crawler = RubyCrawler;
        let gem_packages = ruby_crawler.crawl_all(options).await;
        counts.insert(Ecosystem::Gem, gem_packages.len());
        all_packages.extend(gem_packages);
    }

    #[cfg(feature = "golang")]
    {
        let go_crawler = GoCrawler;
        let go_packages = go_crawler.crawl_all(options).await;
        counts.insert(Ecosystem::Golang, go_packages.len());
        all_packages.extend(go_packages);
    }

    #[cfg(feature = "maven")]
    {
        let maven_crawler = MavenCrawler;
        let maven_packages = maven_crawler.crawl_all(options).await;
        counts.insert(Ecosystem::Maven, maven_packages.len());
        all_packages.extend(maven_packages);
    }

    #[cfg(feature = "composer")]
    {
        let composer_crawler = ComposerCrawler;
        let composer_packages = composer_crawler.crawl_all(options).await;
        counts.insert(Ecosystem::Composer, composer_packages.len());
        all_packages.extend(composer_packages);
    }

    #[cfg(feature = "nuget")]
    {
        let nuget_crawler = NuGetCrawler;
        let nuget_packages = nuget_crawler.crawl_all(options).await;
        counts.insert(Ecosystem::Nuget, nuget_packages.len());
        all_packages.extend(nuget_packages);
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

    // gem
    #[cfg(feature = "gem")]
    if let Some(gem_purls) = partitioned.get(&Ecosystem::Gem) {
        if !gem_purls.is_empty() {
            let ruby_crawler = RubyCrawler;
            match ruby_crawler.get_gem_paths(options).await {
                Ok(gem_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = gem_paths.first() {
                            println!("Using ruby gem paths at: {}", first.display());
                        }
                    }
                    for gem_path in &gem_paths {
                        if let Ok(packages) =
                            ruby_crawler.find_by_purls(gem_path, gem_purls).await
                        {
                            for (purl, pkg) in packages {
                                all_packages.entry(purl).or_insert(pkg.path);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find Ruby gems: {e}");
                    }
                }
            }
        }
    }

    // golang
    #[cfg(feature = "golang")]
    if let Some(golang_purls) = partitioned.get(&Ecosystem::Golang) {
        if !golang_purls.is_empty() {
            let go_crawler = GoCrawler;
            match go_crawler.get_module_cache_paths(options).await {
                Ok(cache_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = cache_paths.first() {
                            println!("Using Go module cache at: {}", first.display());
                        }
                    }
                    for cache_path in &cache_paths {
                        if let Ok(packages) =
                            go_crawler.find_by_purls(cache_path, golang_purls).await
                        {
                            for (purl, pkg) in packages {
                                all_packages.entry(purl).or_insert(pkg.path);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find Go modules: {e}");
                    }
                }
            }
        }
    }

    // maven
    #[cfg(feature = "maven")]
    if let Some(maven_purls) = partitioned.get(&Ecosystem::Maven) {
        if !maven_purls.is_empty() {
            let maven_crawler = MavenCrawler;
            match maven_crawler.get_maven_repo_paths(options).await {
                Ok(repo_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = repo_paths.first() {
                            println!("Using Maven repository at: {}", first.display());
                        }
                    }
                    for repo_path in &repo_paths {
                        if let Ok(packages) =
                            maven_crawler.find_by_purls(repo_path, maven_purls).await
                        {
                            for (purl, pkg) in packages {
                                all_packages.entry(purl).or_insert(pkg.path);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find Maven packages: {e}");
                    }
                }
            }
        }
    }

    // composer
    #[cfg(feature = "composer")]
    if let Some(composer_purls) = partitioned.get(&Ecosystem::Composer) {
        if !composer_purls.is_empty() {
            let composer_crawler = ComposerCrawler;
            match composer_crawler.get_vendor_paths(options).await {
                Ok(vendor_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = vendor_paths.first() {
                            println!("Using PHP vendor packages at: {}", first.display());
                        }
                    }
                    for vendor_path in &vendor_paths {
                        if let Ok(packages) =
                            composer_crawler.find_by_purls(vendor_path, composer_purls).await
                        {
                            for (purl, pkg) in packages {
                                all_packages.entry(purl).or_insert(pkg.path);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find PHP packages: {e}");
                    }
                }
            }
        }
    }

    // nuget
    #[cfg(feature = "nuget")]
    if let Some(nuget_purls) = partitioned.get(&Ecosystem::Nuget) {
        if !nuget_purls.is_empty() {
            let nuget_crawler = NuGetCrawler;
            match nuget_crawler.get_nuget_package_paths(options).await {
                Ok(pkg_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = pkg_paths.first() {
                            println!("Using NuGet packages at: {}", first.display());
                        }
                    }
                    for pkg_path in &pkg_paths {
                        if let Ok(packages) =
                            nuget_crawler.find_by_purls(pkg_path, nuget_purls).await
                        {
                            for (purl, pkg) in packages {
                                all_packages.entry(purl).or_insert(pkg.path);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find NuGet packages: {e}");
                    }
                }
            }
        }
    }

    all_packages
}
