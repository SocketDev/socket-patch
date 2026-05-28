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
    env_truthy("SOCKET_EXPERIMENTAL_MAVEN")
}

#[cfg(feature = "maven")]
fn warn_maven_disabled(skipped: usize) {
    eprintln!(
        "Warning: {} Maven patch(es) skipped — Maven support is experimental.",
        skipped
    );
    eprintln!("  Maven patches corrupt jar sidecar checksums (sha1/md5).");
    eprintln!("  Set SOCKET_EXPERIMENTAL_MAVEN=1 to enable at your own risk.");
}

/// Runtime opt-in gate for experimental NuGet support. Same shape as
/// the Maven gate. Even with the sidecar fixup deleting
/// `.nupkg.metadata`, signed packages still carry a `.nupkg.sha512`
/// marker that NuGet treats as tamper-evidence at restore time. The
/// fixup cannot honestly rewrite this without the original `.nupkg`
/// (which we don't have post-extraction). Refuse to dispatch unless
/// the operator has explicitly opted in to the experimental tier.
#[cfg(feature = "nuget")]
fn nuget_runtime_enabled() -> bool {
    env_truthy("SOCKET_EXPERIMENTAL_NUGET")
}

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

#[cfg(any(feature = "maven", feature = "nuget"))]
fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
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

/// Standard scan-one-ecosystem pattern: discover source paths, run
/// `find_by_purls` on each, and merge results into `$out` keyed by PURL
/// (first wins). Used by every ecosystem except pypi (which dedups
/// PURLs and, on rollback, remaps base PURLs back to qualified ones).
///
/// `$using_label` is the noun in "Using <X> at: <path>" for global
/// scans; pass `""` to suppress that line.
macro_rules! scan_ecosystem {
    (
        out = $out:ident,
        partitioned = $partitioned:expr,
        eco = $eco:expr,
        options = $options:expr,
        silent = $silent:expr,
        crawler = $crawler:expr,
        get_paths = $get_paths:ident,
        using_label = $using_label:expr,
        err_label = $err_label:expr,
        purls_override = $purls_override:expr,
        on_match = $on_match:expr $(,)?
    ) => {{
        if let Some(purls) = $partitioned.get(&$eco) {
            if !purls.is_empty() {
                let crawler = $crawler;
                let purls_to_use: Vec<String> = $purls_override(purls);
                match crawler.$get_paths($options).await {
                    Ok(paths) => {
                        let using: &str = $using_label;
                        if !using.is_empty()
                            && ($options.global || $options.global_prefix.is_some())
                            && !$silent
                        {
                            if let Some(first) = paths.first() {
                                println!("Using {} at: {}", using, first.display());
                            }
                        }
                        for path in &paths {
                            match crawler.find_by_purls(path, &purls_to_use).await {
                                Ok(packages) => {
                                    $on_match(&mut $out, purls, packages);
                                }
                                Err(e) => {
                                    if !$silent {
                                        eprintln!(
                                            "Warning: Failed to scan {}: {}",
                                            path.display(),
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if !$silent {
                            eprintln!("Failed to find {}: {}", $err_label, e);
                        }
                    }
                }
            }
        }
    }};
}

/// Signature shared by `merge_first_wins` and `merge_qualified`.
/// `dispatch_find` swaps between them so the rollback path can fan one
/// crawler result back out to every caller-supplied qualified PURL.
type MergeFn =
    fn(&mut HashMap<String, PathBuf>, &[String], HashMap<String, CrawledPackage>);

/// Default merge: insert the crawler-returned PURL → first wins.
fn merge_first_wins(
    out: &mut HashMap<String, PathBuf>,
    _purls: &[String],
    packages: HashMap<String, socket_patch_core::crawlers::CrawledPackage>,
) {
    for (purl, pkg) in packages {
        out.entry(purl).or_insert(pkg.path);
    }
}

/// Release-variant merge: the crawler is queried with base PURLs (no
/// `?qualifiers`); fan the resulting paths back out to every qualified
/// caller-supplied PURL that strips to the same base. Used for the
/// release-variant ecosystems (PyPI / RubyGems / Maven) so a single
/// installed package directory is mapped to every manifest variant for
/// later hash-based selection.
fn merge_qualified(
    out: &mut HashMap<String, PathBuf>,
    purls: &[String],
    packages: HashMap<String, socket_patch_core::crawlers::CrawledPackage>,
) {
    for (base_purl, pkg) in packages {
        for qualified in purls {
            if strip_purl_qualifiers(qualified) == base_purl
                && !out.contains_key(qualified)
            {
                out.insert(qualified.clone(), pkg.path.clone());
            }
        }
    }
}

/// Strip qualifiers and dedupe — the crawler only needs the base PURL of
/// a release-variant ecosystem; the variant is resolved later by hashing
/// the installed files.
fn dedup_qualified_purls(purls: &[String]) -> Vec<String> {
    purls
        .iter()
        .map(|p| strip_purl_qualifiers(p).to_string())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

fn passthrough_purls(purls: &[String]) -> Vec<String> {
    purls.to_vec()
}

/// Drive every enabled ecosystem's find-by-purls path, accumulating
/// into one `purl -> path` map.
///
/// `variant_merge` lets the rollback variant fan a single crawler result
/// out to every caller-supplied qualified PURL; everything else just
/// inserts the crawler-returned PURL with first-wins semantics. It is
/// applied to the release-variant ecosystems (PyPI / RubyGems / Maven),
/// which are also queried with deduped base PURLs.
async fn dispatch_find(
    partitioned: &HashMap<Ecosystem, Vec<String>>,
    options: &CrawlerOptions,
    silent: bool,
    variant_merge: MergeFn,
) -> HashMap<String, PathBuf> {
    let mut out: HashMap<String, PathBuf> = HashMap::new();

    scan_ecosystem!(
        out = out,
        partitioned = partitioned,
        eco = Ecosystem::Npm,
        options = options,
        silent = silent,
        crawler = NpmCrawler,
        get_paths = get_node_modules_paths,
        using_label = "global npm packages",
        err_label = "npm packages",
        purls_override = passthrough_purls,
        on_match = merge_first_wins,
    );

    scan_ecosystem!(
        out = out,
        partitioned = partitioned,
        eco = Ecosystem::Pypi,
        options = options,
        silent = silent,
        crawler = PythonCrawler,
        get_paths = get_site_packages_paths,
        using_label = "",
        err_label = "Python packages",
        purls_override = dedup_qualified_purls,
        on_match = variant_merge,
    );

    #[cfg(feature = "cargo")]
    scan_ecosystem!(
        out = out,
        partitioned = partitioned,
        eco = Ecosystem::Cargo,
        options = options,
        silent = silent,
        crawler = CargoCrawler,
        get_paths = get_crate_source_paths,
        using_label = "cargo crate sources",
        err_label = "Cargo crates",
        purls_override = passthrough_purls,
        on_match = merge_first_wins,
    );

    scan_ecosystem!(
        out = out,
        partitioned = partitioned,
        eco = Ecosystem::Gem,
        options = options,
        silent = silent,
        crawler = RubyCrawler,
        get_paths = get_gem_paths,
        using_label = "ruby gem paths",
        err_label = "Ruby gems",
        // RubyGems has per-platform release variants (`?platform=`); the
        // crawler emits the base PURL and the platform is resolved by
        // hashing the installed files, same as PyPI.
        purls_override = dedup_qualified_purls,
        on_match = variant_merge,
    );

    #[cfg(feature = "golang")]
    scan_ecosystem!(
        out = out,
        partitioned = partitioned,
        eco = Ecosystem::Golang,
        options = options,
        silent = silent,
        crawler = GoCrawler,
        get_paths = get_module_cache_paths,
        using_label = "Go module cache",
        err_label = "Go modules",
        purls_override = passthrough_purls,
        on_match = merge_first_wins,
    );

    #[cfg(feature = "maven")]
    if let Some(maven_purls) = partitioned.get(&Ecosystem::Maven) {
        if !maven_purls.is_empty() && !maven_runtime_enabled() {
            if !silent {
                warn_maven_disabled(maven_purls.len());
            }
        } else {
            scan_ecosystem!(
                out = out,
                partitioned = partitioned,
                eco = Ecosystem::Maven,
                options = options,
                silent = silent,
                crawler = MavenCrawler,
                get_paths = get_maven_repo_paths,
                using_label = "Maven repository",
                err_label = "Maven packages",
                // Maven has per-classifier release variants
                // (`?classifier=&ext=`) that coexist as distinct jars in
                // one version dir; the crawler emits the base PURL and
                // each variant is resolved by hashing its jar file.
                purls_override = dedup_qualified_purls,
                on_match = variant_merge,
            );
        }
    }

    #[cfg(feature = "composer")]
    scan_ecosystem!(
        out = out,
        partitioned = partitioned,
        eco = Ecosystem::Composer,
        options = options,
        silent = silent,
        crawler = ComposerCrawler,
        get_paths = get_vendor_paths,
        using_label = "PHP vendor packages",
        err_label = "PHP packages",
        purls_override = passthrough_purls,
        on_match = merge_first_wins,
    );

    #[cfg(feature = "nuget")]
    if let Some(nuget_purls) = partitioned.get(&Ecosystem::Nuget) {
        if !nuget_purls.is_empty() && !nuget_runtime_enabled() {
            if !silent {
                warn_nuget_disabled(nuget_purls.len());
            }
        } else {
            scan_ecosystem!(
                out = out,
                partitioned = partitioned,
                eco = Ecosystem::Nuget,
                options = options,
                silent = silent,
                crawler = NuGetCrawler,
                get_paths = get_nuget_package_paths,
                using_label = "NuGet packages",
                err_label = "NuGet packages",
                purls_override = passthrough_purls,
                on_match = merge_first_wins,
            );
        }
    }

    #[cfg(feature = "deno")]
    scan_ecosystem!(
        out = out,
        partitioned = partitioned,
        eco = Ecosystem::Deno,
        options = options,
        silent = silent,
        crawler = DenoCrawler,
        get_paths = get_jsr_cache_paths,
        using_label = "Deno JSR cache",
        err_label = "Deno JSR packages",
        purls_override = passthrough_purls,
        on_match = merge_first_wins,
    );

    out
}

/// For each ecosystem in the partitioned map, create the crawler, discover
/// source paths, and look up the given PURLs. Returns a unified
/// `purl -> path` map.
pub async fn find_packages_for_purls(
    partitioned: &HashMap<Ecosystem, Vec<String>>,
    options: &CrawlerOptions,
    silent: bool,
) -> HashMap<String, PathBuf> {
    dispatch_find(partitioned, options, silent, merge_first_wins).await
}

/// Variant of `find_packages_for_purls` for rollback and narrow-release
/// resolution, which needs to remap qualified PURLs (PyPI
/// `?artifact_id=`, RubyGems `?platform=`, Maven `?classifier=&ext=`) to
/// the base PURL found by the crawler.
pub async fn find_packages_for_rollback(
    partitioned: &HashMap<Ecosystem, Vec<String>>,
    options: &CrawlerOptions,
    silent: bool,
) -> HashMap<String, PathBuf> {
    dispatch_find(partitioned, options, silent, merge_qualified).await
}

/// Crawl all enabled ecosystems and return all packages plus per-ecosystem counts.
pub async fn crawl_all_ecosystems(
    options: &CrawlerOptions,
) -> (Vec<CrawledPackage>, HashMap<Ecosystem, usize>) {
    let mut all_packages = Vec::new();
    let mut counts: HashMap<Ecosystem, usize> = HashMap::new();

    macro_rules! crawl {
        ($eco:expr, $crawler:expr) => {{
            let pkgs = $crawler.crawl_all(options).await;
            counts.insert($eco, pkgs.len());
            all_packages.extend(pkgs);
        }};
    }

    crawl!(Ecosystem::Npm, NpmCrawler);
    crawl!(Ecosystem::Pypi, PythonCrawler);
    #[cfg(feature = "cargo")]
    crawl!(Ecosystem::Cargo, CargoCrawler);
    crawl!(Ecosystem::Gem, RubyCrawler);
    #[cfg(feature = "golang")]
    crawl!(Ecosystem::Golang, GoCrawler);
    #[cfg(feature = "maven")]
    if maven_runtime_enabled() {
        // Same runtime gate as `find_packages_for_purls` — `scan`
        // walks the Maven repo only when the operator has explicitly
        // opted into experimental support.
        crawl!(Ecosystem::Maven, MavenCrawler);
    }
    #[cfg(feature = "composer")]
    crawl!(Ecosystem::Composer, ComposerCrawler);
    #[cfg(feature = "nuget")]
    if nuget_runtime_enabled() {
        crawl!(Ecosystem::Nuget, NuGetCrawler);
    }
    #[cfg(feature = "deno")]
    crawl!(Ecosystem::Deno, DenoCrawler);

    (all_packages, counts)
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
