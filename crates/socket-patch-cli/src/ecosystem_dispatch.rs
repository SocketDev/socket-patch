use socket_patch_core::crawlers::{
    CrawledPackage, CrawlerOptions, Ecosystem, NpmCrawler, PythonCrawler,
};
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[cfg(feature = "cargo")]
use socket_patch_core::crawlers::CargoCrawler;
use socket_patch_core::crawlers::RubyCrawler;
#[cfg(feature = "golang")]
use socket_patch_core::crawlers::GoCrawler;
#[cfg(feature = "maven")]
use socket_patch_core::crawlers::MavenCrawler;
#[cfg(feature = "composer")]
use socket_patch_core::crawlers::ComposerCrawler;
#[cfg(feature = "nuget")]
use socket_patch_core::crawlers::NuGetCrawler;
#[cfg(feature = "deno")]
use socket_patch_core::crawlers::DenoCrawler;

/// Runtime opt-in gate for experimental Maven support.
///
/// Even when the binary is compiled with `--features maven`, the
/// crawler does NOT run unless `SOCKET_EXPERIMENTAL_MAVEN=1` (or
/// `=true`). Applying a Maven patch corrupts the jar sidecar
/// checksums (`<jar>.jar.sha1`, `<jar>.jar.md5`) that the local
/// Maven repository keeps next to each artifact, and there is no
/// recovery — the user has to re-download the jar.
#[cfg(feature = "maven")]
fn maven_runtime_enabled() -> bool {
    std::env::var("SOCKET_EXPERIMENTAL_MAVEN")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// One-line stderr warning for the "Maven patches present, but
/// experimental gate is off" path.
#[cfg(feature = "maven")]
fn warn_maven_disabled(skipped: usize) {
    eprintln!(
        "Warning: {} Maven patch(es) skipped — Maven support is experimental.",
        skipped
    );
    eprintln!("  Maven patches corrupt jar sidecar checksums (sha1/md5).");
    eprintln!("  Set SOCKET_EXPERIMENTAL_MAVEN=1 to enable at your own risk.");
}

/// Runtime opt-in gate for experimental NuGet support.
///
/// Same shape as the Maven gate. Even with the sidecar fixup
/// deleting `.nupkg.metadata`, signed packages still carry a
/// `.nupkg.sha512` marker that NuGet treats as tamper-evidence
/// at restore time. The fixup cannot honestly rewrite this
/// without the original `.nupkg` (which we don't have post-
/// extraction). Refuse to dispatch unless the operator has
/// explicitly opted in to the experimental tier.
#[cfg(feature = "nuget")]
fn nuget_runtime_enabled() -> bool {
    std::env::var("SOCKET_EXPERIMENTAL_NUGET")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// One-line stderr warning for the "NuGet patches present, but
/// experimental gate is off" path.
#[cfg(feature = "nuget")]
fn warn_nuget_disabled(skipped: usize) {
    eprintln!(
        "Warning: {} NuGet patch(es) skipped — NuGet support is experimental.",
        skipped
    );
    eprintln!("  NuGet patches corrupt the .nupkg.sha512 signature sidecar that");
    eprintln!("  `dotnet restore` reads as tamper-evidence.");
    eprintln!("  Set SOCKET_EXPERIMENTAL_NUGET=1 to enable at your own risk.");
}

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
                        match npm_crawler.find_by_purls(nm_path, npm_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", nm_path.display(), e);
                                }
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
                        match python_crawler.find_by_purls(sp_path, &base_pypi_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", sp_path.display(), e);
                                }
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
                        match cargo_crawler.find_by_purls(src_path, cargo_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", src_path.display(), e);
                                }
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
                        match ruby_crawler.find_by_purls(gem_path, gem_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", gem_path.display(), e);
                                }
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
                        match go_crawler.find_by_purls(cache_path, golang_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", cache_path.display(), e);
                                }
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

    // maven — experimental, double-gated. See `maven_runtime_enabled`.
    #[cfg(feature = "maven")]
    if let Some(maven_purls) = partitioned.get(&Ecosystem::Maven) {
        if !maven_purls.is_empty() && !maven_runtime_enabled() {
            if !silent {
                warn_maven_disabled(maven_purls.len());
            }
        } else if !maven_purls.is_empty() {
            let maven_crawler = MavenCrawler;
            match maven_crawler.get_maven_repo_paths(options).await {
                Ok(repo_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = repo_paths.first() {
                            println!("Using Maven repository at: {}", first.display());
                        }
                    }
                    for repo_path in &repo_paths {
                        match maven_crawler.find_by_purls(repo_path, maven_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", repo_path.display(), e);
                                }
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
                        match composer_crawler.find_by_purls(vendor_path, composer_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", vendor_path.display(), e);
                                }
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

    // nuget — experimental, double-gated. See `nuget_runtime_enabled`.
    #[cfg(feature = "nuget")]
    if let Some(nuget_purls) = partitioned.get(&Ecosystem::Nuget) {
        if !nuget_purls.is_empty() && !nuget_runtime_enabled() {
            if !silent {
                warn_nuget_disabled(nuget_purls.len());
            }
        } else if !nuget_purls.is_empty() {
            let nuget_crawler = NuGetCrawler;
            match nuget_crawler.get_nuget_package_paths(options).await {
                Ok(pkg_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = pkg_paths.first() {
                            println!("Using NuGet packages at: {}", first.display());
                        }
                    }
                    for pkg_path in &pkg_paths {
                        match nuget_crawler.find_by_purls(pkg_path, nuget_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", pkg_path.display(), e);
                                }
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

    // deno — JSR registry packages cached under DENO_DIR/npm/jsr.io/.
    #[cfg(feature = "deno")]
    if let Some(deno_purls) = partitioned.get(&Ecosystem::Deno) {
        if !deno_purls.is_empty() {
            let deno_crawler = DenoCrawler;
            match deno_crawler.get_jsr_cache_paths(options).await {
                Ok(cache_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = cache_paths.first() {
                            println!("Using Deno JSR cache at: {}", first.display());
                        }
                    }
                    for cache_path in &cache_paths {
                        match deno_crawler.find_by_purls(cache_path, deno_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", cache_path.display(), e);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    if !silent {
                        eprintln!("Failed to find Deno JSR packages: {e}");
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
    if maven_runtime_enabled() {
        // Same runtime gate as `find_packages_for_purls` — `scan`
        // walks the Maven repo only when the operator has explicitly
        // opted into experimental support.
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
    if nuget_runtime_enabled() {
        // Same runtime gate as `find_packages_for_purls`.
        let nuget_crawler = NuGetCrawler;
        let nuget_packages = nuget_crawler.crawl_all(options).await;
        counts.insert(Ecosystem::Nuget, nuget_packages.len());
        all_packages.extend(nuget_packages);
    }

    #[cfg(feature = "deno")]
    {
        let deno_crawler = DenoCrawler;
        let deno_packages = deno_crawler.crawl_all(options).await;
        counts.insert(Ecosystem::Deno, deno_packages.len());
        all_packages.extend(deno_packages);
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
                        match npm_crawler.find_by_purls(nm_path, npm_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", nm_path.display(), e);
                                }
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
                    match python_crawler.find_by_purls(sp_path, &base_pypi_purls).await {
                        Ok(packages) => {
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
                        Err(e) => {
                            if !silent {
                                eprintln!("Warning: Failed to scan {}: {}", sp_path.display(), e);
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
                        match cargo_crawler.find_by_purls(src_path, cargo_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", src_path.display(), e);
                                }
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
                        match ruby_crawler.find_by_purls(gem_path, gem_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", gem_path.display(), e);
                                }
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
                        match go_crawler.find_by_purls(cache_path, golang_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", cache_path.display(), e);
                                }
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

    // maven — experimental, double-gated. See `maven_runtime_enabled`.
    #[cfg(feature = "maven")]
    if let Some(maven_purls) = partitioned.get(&Ecosystem::Maven) {
        if !maven_purls.is_empty() && !maven_runtime_enabled() {
            if !silent {
                warn_maven_disabled(maven_purls.len());
            }
        } else if !maven_purls.is_empty() {
            let maven_crawler = MavenCrawler;
            match maven_crawler.get_maven_repo_paths(options).await {
                Ok(repo_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = repo_paths.first() {
                            println!("Using Maven repository at: {}", first.display());
                        }
                    }
                    for repo_path in &repo_paths {
                        match maven_crawler.find_by_purls(repo_path, maven_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", repo_path.display(), e);
                                }
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
                        match composer_crawler.find_by_purls(vendor_path, composer_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", vendor_path.display(), e);
                                }
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

    // nuget — experimental, double-gated. See `nuget_runtime_enabled`.
    #[cfg(feature = "nuget")]
    if let Some(nuget_purls) = partitioned.get(&Ecosystem::Nuget) {
        if !nuget_purls.is_empty() && !nuget_runtime_enabled() {
            if !silent {
                warn_nuget_disabled(nuget_purls.len());
            }
        } else if !nuget_purls.is_empty() {
            let nuget_crawler = NuGetCrawler;
            match nuget_crawler.get_nuget_package_paths(options).await {
                Ok(pkg_paths) => {
                    if (options.global || options.global_prefix.is_some()) && !silent {
                        if let Some(first) = pkg_paths.first() {
                            println!("Using NuGet packages at: {}", first.display());
                        }
                    }
                    for pkg_path in &pkg_paths {
                        match nuget_crawler.find_by_purls(pkg_path, nuget_purls).await {
                            Ok(packages) => {
                                for (purl, pkg) in packages {
                                    all_packages.entry(purl).or_insert(pkg.path);
                                }
                            }
                            Err(e) => {
                                if !silent {
                                    eprintln!("Warning: Failed to scan {}: {}", pkg_path.display(), e);
                                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_purls_no_filter_single_npm() {
        let purls = vec!["pkg:npm/foo@1.0".to_string()];
        let map = partition_purls(&purls, None);
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.get(&Ecosystem::Npm),
            Some(&vec!["pkg:npm/foo@1.0".to_string()])
        );
    }

    #[test]
    fn partition_purls_no_filter_mixed_ecosystems() {
        let purls = vec![
            "pkg:npm/foo@1.0".to_string(),
            "pkg:pypi/bar@2.0".to_string(),
            "pkg:cargo/baz@3.0".to_string(),
        ];
        let map = partition_purls(&purls, None);
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.get(&Ecosystem::Npm),
            Some(&vec!["pkg:npm/foo@1.0".to_string()])
        );
        assert_eq!(
            map.get(&Ecosystem::Pypi),
            Some(&vec!["pkg:pypi/bar@2.0".to_string()])
        );
        #[cfg(feature = "cargo")]
        assert_eq!(
            map.get(&Ecosystem::Cargo),
            Some(&vec!["pkg:cargo/baz@3.0".to_string()])
        );
    }

    #[test]
    fn partition_purls_no_filter_empty_input() {
        let purls: Vec<String> = Vec::new();
        let map = partition_purls(&purls, None);
        assert!(map.is_empty());
    }

    #[test]
    fn partition_purls_no_filter_duplicate_purls_preserved() {
        let purls = vec![
            "pkg:npm/foo@1.0".to_string(),
            "pkg:npm/foo@1.0".to_string(),
        ];
        let map = partition_purls(&purls, None);
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.get(&Ecosystem::Npm),
            Some(&vec![
                "pkg:npm/foo@1.0".to_string(),
                "pkg:npm/foo@1.0".to_string(),
            ])
        );
    }

    #[test]
    fn partition_purls_no_filter_unknown_ecosystem_dropped() {
        let purls = vec!["pkg:weirdo/x@1".to_string()];
        let map = partition_purls(&purls, None);
        assert!(map.is_empty());
    }

    #[test]
    fn partition_purls_allow_list_excludes_one() {
        let purls = vec![
            "pkg:npm/foo@1.0".to_string(),
            "pkg:pypi/bar@2.0".to_string(),
        ];
        let allowed = vec!["npm".to_string()];
        let map = partition_purls(&purls, Some(allowed.as_slice()));
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.get(&Ecosystem::Npm),
            Some(&vec!["pkg:npm/foo@1.0".to_string()])
        );
        assert!(!map.contains_key(&Ecosystem::Pypi));
    }

    #[test]
    fn partition_purls_allow_list_matches_none() {
        let purls = vec!["pkg:npm/foo@1.0".to_string()];
        let allowed = vec!["pypi".to_string()];
        let map = partition_purls(&purls, Some(allowed.as_slice()));
        assert!(map.is_empty());
    }

    #[test]
    fn partition_purls_allow_list_matches_all() {
        let purls = vec![
            "pkg:npm/foo@1.0".to_string(),
            "pkg:pypi/bar@2.0".to_string(),
        ];
        let allowed = vec!["npm".to_string(), "pypi".to_string()];
        let map = partition_purls(&purls, Some(allowed.as_slice()));
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get(&Ecosystem::Npm),
            Some(&vec!["pkg:npm/foo@1.0".to_string()])
        );
        assert_eq!(
            map.get(&Ecosystem::Pypi),
            Some(&vec!["pkg:pypi/bar@2.0".to_string()])
        );
    }

    #[test]
    fn partition_purls_empty_allow_list_matches_nothing() {
        let purls = vec![
            "pkg:npm/foo@1.0".to_string(),
            "pkg:pypi/bar@2.0".to_string(),
        ];
        let allowed: Vec<String> = Vec::new();
        let map = partition_purls(&purls, Some(allowed.as_slice()));
        assert!(map.is_empty());
    }
}
