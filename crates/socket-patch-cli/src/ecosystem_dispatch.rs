use socket_patch_core::crawlers::{
    CrawledPackage, CrawlerOptions, Ecosystem, NpmCrawler, PythonCrawler, RubyCrawler,
};
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::args::GlobalArgs;

use socket_patch_core::crawlers::CargoCrawler;
use socket_patch_core::crawlers::ComposerCrawler;
use socket_patch_core::crawlers::DenoCrawler;
use socket_patch_core::crawlers::GoCrawler;
use socket_patch_core::crawlers::MavenCrawler;
use socket_patch_core::crawlers::NuGetCrawler;

/// Whether [`crawl_all_ecosystems`] actually visits this PURL's ecosystem
/// in THIS process. An unrecognized `pkg:<type>/` (a newer CLI's ecosystem
/// in a committed manifest) has no crawler at all — for those, absence
/// from the crawl carries no information about whether the package is
/// installed. Callers that read "not in the crawl" as "no longer
/// installed" (scan's prune GC) must not judge them.
pub fn crawl_covers_purl(purl: &str) -> bool {
    Ecosystem::from_purl(purl).is_some()
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
/// crawler result back out to every caller-supplied qualified PURL. The
/// output map holds a `Vec` of paths per PURL: most ecosystems install one
/// physical copy of a `name@version`, but npm genuinely nests duplicates
/// (see `merge_npm_copies`), so the type itself must be able to carry more
/// than one.
type MergeFn = fn(&mut HashMap<String, Vec<PathBuf>>, &[String], HashMap<String, CrawledPackage>);

/// Push `path` under `purl` unless that exact path is already recorded —
/// keeps discovery order (root/first-found first) while deduping a path
/// reached twice across the macro's per-source-path calls.
fn push_path(out: &mut HashMap<String, Vec<PathBuf>>, purl: String, path: PathBuf) {
    let paths = out.entry(purl).or_default();
    if !paths.contains(&path) {
        paths.push(path);
    }
}

/// Default merge for the single-copy ecosystems (cargo / go / composer /
/// nuget / deno): keep the FIRST path discovered per PURL, matching the
/// historical `HashMap<String, PathBuf>` first-wins contract exactly. These
/// ecosystems resolve one logical install per `name@version`, but the same
/// install is legitimately reachable from several source roots (e.g. NuGet's
/// global cache *and* a project-local packages folder). Patching each root
/// would re-apply to what is effectively the same package — a scope-expanding
/// behavior change that is out of scope for the npm multi-copy fix and would,
/// for a shared global cache, mutate state other projects rely on. Fanning out
/// to genuinely-distinct installs is npm-only (`merge_npm_copies`); if a
/// per-root fan-out is ever wanted for these ecosystems it must be an explicit,
/// separately-tested decision.
fn merge_first_wins(
    out: &mut HashMap<String, Vec<PathBuf>>,
    _purls: &[String],
    packages: HashMap<String, CrawledPackage>,
) {
    for (purl, pkg) in packages {
        // First source root to resolve this PURL wins; later roots that
        // resolve the same PURL are ignored (true first-wins).
        let paths = out.entry(purl).or_default();
        if paths.is_empty() {
            paths.push(pkg.path);
        }
    }
}

/// Release-variant merge for the APPLY path: keyed by the crawler-returned
/// base PURL (apply's variant loop groups by base), accumulating EVERY
/// distinct path discovered across the ecosystem's source roots in
/// discovery (precedence) order. The gem crawler legitimately discovers
/// several coexisting stores holding REAL physical copies of one
/// `gem@version` (bundler's scoped `<engine>/<abi>/gems` beside the flat
/// `gems/` layout, or an env `BUNDLE_PATH` store) — first-wins here
/// dropped the second copy, so apply patched one store and reported
/// success while the other bundler loaded pristine bytes (the gem sibling
/// of the npm multi-copy P0). Collapsing consumers still take the first
/// (highest-precedence) path, so this changes nothing for
/// vendor/vex/setup/get/repair-vendor; apply fans out per-copy for gem
/// only (PyPI/Maven keep their one-install-dir contract — see the apply
/// variant loop).
fn merge_variant_copies(
    out: &mut HashMap<String, Vec<PathBuf>>,
    _purls: &[String],
    packages: HashMap<String, CrawledPackage>,
) {
    for (purl, pkg) in packages {
        push_path(out, purl, pkg.path);
    }
}

/// npm merge: the npm crawler returns EVERY physical copy of each PURL
/// (nested duplicates, diamonds, `file:` dups), so fold every path in.
/// This is the type shape that carries the second copy the old
/// `HashMap<String, PathBuf>` could not — the fix for the multi-copy silent
/// partial P0.
fn merge_npm_copies(
    out: &mut HashMap<String, Vec<PathBuf>>,
    _purls: &[String],
    packages: HashMap<String, Vec<CrawledPackage>>,
) {
    for (purl, pkgs) in packages {
        for pkg in pkgs {
            push_path(out, purl.clone(), pkg.path);
        }
    }
}

/// Release-variant merge: the crawler is queried with base PURLs (no
/// `?qualifiers`); fan the resulting paths back out to every qualified
/// caller-supplied PURL that strips to the same base. Used for the
/// release-variant ecosystems (PyPI / RubyGems / Maven) so a single
/// installed package directory is mapped to every manifest variant for
/// later hash-based selection.
fn merge_qualified(
    out: &mut HashMap<String, Vec<PathBuf>>,
    purls: &[String],
    packages: HashMap<String, CrawledPackage>,
) {
    for (base_purl, pkg) in packages {
        for qualified in purls {
            if strip_purl_qualifiers(qualified) == base_purl {
                push_path(out, qualified.clone(), pkg.path.clone());
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
) -> HashMap<String, Vec<PathBuf>> {
    let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();

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
        // npm's crawler returns EVERY physical copy per PURL; fold them all
        // in (multi-copy silent-partial fix) rather than first-wins.
        on_match = merge_npm_copies,
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

/// Collapse a multi-copy map to one representative path per PURL (the
/// first-discovered — root-copy-first for npm). Consumers that only need
/// "is it installed / where is a representative copy" (`vendor`, `vex`,
/// `setup`, `get`, `repair vendor`) use the collapsing wrappers below and
/// keep the old `HashMap<String, PathBuf>` contract unchanged. `apply` and
/// `rollback` — which must touch EVERY copy — use the `_all` variants.
fn collapse_to_first(multi: HashMap<String, Vec<PathBuf>>) -> HashMap<String, PathBuf> {
    multi
        .into_iter()
        .filter_map(|(purl, paths)| paths.into_iter().next().map(|p| (purl, p)))
        .collect()
}

/// For each ecosystem in the partitioned map, create the crawler, discover
/// source paths, and look up the given PURLs. Returns a unified `purl ->
/// [paths]` map carrying EVERY physical copy (npm nests duplicates). Used
/// by `apply`, which patches all copies.
pub async fn find_all_packages_for_purls(
    partitioned: &HashMap<Ecosystem, Vec<String>>,
    options: &CrawlerOptions,
    silent: bool,
) -> HashMap<String, Vec<PathBuf>> {
    // Release-variant ecosystems accumulate every distinct discovered copy
    // (base-PURL keyed) instead of first-wins: the gem crawler surfaces
    // coexisting bundler stores whose copies apply must ALL patch. The
    // rollback variant below gets the same multi-copy carry from
    // `merge_qualified`'s `push_path`. Single-copy ecosystems keep true
    // first-wins via their own `merge_first_wins` wiring in
    // `dispatch_find`.
    dispatch_find(partitioned, options, silent, merge_variant_copies).await
}

/// Multi-copy variant of `find_packages_for_rollback` (qualified-aware
/// merge). Used by `rollback`, which restores every physical copy.
pub async fn find_all_packages_for_rollback(
    partitioned: &HashMap<Ecosystem, Vec<String>>,
    options: &CrawlerOptions,
    silent: bool,
) -> HashMap<String, Vec<PathBuf>> {
    dispatch_find(partitioned, options, silent, merge_qualified).await
}

/// For each ecosystem in the partitioned map, create the crawler, discover
/// source paths, and look up the given PURLs. Returns a unified
/// `purl -> path` map (one representative copy per PURL).
pub async fn find_packages_for_purls(
    partitioned: &HashMap<Ecosystem, Vec<String>>,
    options: &CrawlerOptions,
    silent: bool,
) -> HashMap<String, PathBuf> {
    collapse_to_first(find_all_packages_for_purls(partitioned, options, silent).await)
}

/// Variant of `find_packages_for_purls` for rollback and narrow-release
/// resolution, which needs to remap qualified PURLs (PyPI
/// `?artifact_id=`, RubyGems `?platform=`, Maven `?classifier=&ext=`) to
/// the base PURL found by the crawler. Returns one representative copy per
/// PURL.
pub async fn find_packages_for_rollback(
    partitioned: &HashMap<Ecosystem, Vec<String>>,
    options: &CrawlerOptions,
    silent: bool,
) -> HashMap<String, PathBuf> {
    collapse_to_first(find_all_packages_for_rollback(partitioned, options, silent).await)
}

/// Resolve manifest PURLs to their installed on-disk paths (partition,
/// build crawler options from the global args, dispatch). Uses the
/// rollback (qualified-aware) resolver, NOT `find_packages_for_purls`:
/// release-variant ecosystems (PyPI / RubyGems / Maven) key the manifest
/// by *qualified* PURLs (`?artifact_id=`, `?platform=`,
/// `?classifier=&ext=`), but the crawler only knows the *base* PURL.
/// `find_packages_for_purls` would key the result map by the base PURL,
/// so qualified manifest lookups would all miss and every PyPI/Gem/Maven
/// patch would silently resolve as `package_not_found`. The rollback
/// variant fans each base path back out to every qualified manifest PURL
/// — the same mapping the manifest was written with (`get` uses the same
/// resolver).
pub async fn find_manifest_package_paths(
    purls: &[String],
    common: &GlobalArgs,
    quiet: bool,
) -> HashMap<String, PathBuf> {
    let partitioned = partition_purls(purls, common.ecosystems.as_deref());
    let crawler_options = CrawlerOptions {
        cwd: common.cwd.clone(),
        global: common.global,
        global_prefix: common.global_prefix.clone(),
    };
    find_packages_for_rollback(&partitioned, &crawler_options, quiet).await
}

/// Crawl all ecosystems and return all packages plus per-ecosystem counts.
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
    crawl!(Ecosystem::Cargo, CargoCrawler);
    crawl!(Ecosystem::Gem, RubyCrawler);
    crawl!(Ecosystem::Golang, GoCrawler);
    crawl!(Ecosystem::Maven, MavenCrawler);
    crawl!(Ecosystem::Composer, ComposerCrawler);
    crawl!(Ecosystem::Nuget, NuGetCrawler);
    crawl!(Ecosystem::Deno, DenoCrawler);

    (all_packages, counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `CrawledPackage` keyed by `purl` whose `path` encodes the
    /// supplied directory, for exercising the merge helpers in isolation.
    fn pkg(purl: &str, path: &str) -> CrawledPackage {
        CrawledPackage {
            name: "n".to_string(),
            version: "v".to_string(),
            namespace: None,
            purl: purl.to_string(),
            path: PathBuf::from(path),
        }
    }

    fn packages(entries: &[(&str, &str)]) -> HashMap<String, CrawledPackage> {
        entries
            .iter()
            .map(|(purl, path)| (purl.to_string(), pkg(purl, path)))
            .collect()
    }

    // ---- merge_first_wins -------------------------------------------------

    #[test]
    fn merge_first_wins_inserts_crawler_keyed_purls() {
        let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
        merge_first_wins(
            &mut out,
            &[],
            packages(&[("pkg:npm/foo@1.0", "/a"), ("pkg:npm/bar@2.0", "/b")]),
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out.get("pkg:npm/foo@1.0"), Some(&vec![PathBuf::from("/a")]));
        assert_eq!(out.get("pkg:npm/bar@2.0"), Some(&vec![PathBuf::from("/b")]));
    }

    #[test]
    fn merge_first_wins_keeps_first_path_across_source_roots() {
        // The macro calls on_match once per discovered source path. A
        // single-copy ecosystem that resolves the same PURL from two source
        // roots (e.g. NuGet's global cache + a project-local packages folder)
        // keeps ONLY the first — matching the historical first-wins contract.
        // Fanning out to every root re-patches what is effectively one install
        // (the docker_e2e_nuget `already_patched` regression); genuine
        // multi-copy fan-out is npm-only via `merge_npm_copies`.
        let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
        merge_first_wins(&mut out, &[], packages(&[("pkg:cargo/foo@1.0", "/first")]));
        merge_first_wins(&mut out, &[], packages(&[("pkg:cargo/foo@1.0", "/second")]));
        assert_eq!(
            out.get("pkg:cargo/foo@1.0"),
            Some(&vec![PathBuf::from("/first")])
        );
    }

    #[test]
    fn merge_first_wins_dedups_identical_path() {
        // The same physical path re-observed across calls is recorded once.
        let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
        merge_first_wins(&mut out, &[], packages(&[("pkg:cargo/foo@1.0", "/same")]));
        merge_first_wins(&mut out, &[], packages(&[("pkg:cargo/foo@1.0", "/same")]));
        assert_eq!(
            out.get("pkg:cargo/foo@1.0"),
            Some(&vec![PathBuf::from("/same")])
        );
    }

    #[test]
    fn merge_first_wins_keeps_only_first_of_two_distinct_paths() {
        // A single-copy ecosystem (e.g. NuGet) reaches the same logical
        // install from two source roots — global cache + project-local. Only
        // the first is kept, so apply does not double-patch (the regression
        // that broke docker_e2e_nuget with a spurious `already_patched` skip).
        let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
        merge_first_wins(
            &mut out,
            &[],
            packages(&[("pkg:nuget/foo@1.0", "/global/foo")]),
        );
        merge_first_wins(
            &mut out,
            &[],
            packages(&[("pkg:nuget/foo@1.0", "/local/foo")]),
        );
        assert_eq!(
            out.get("pkg:nuget/foo@1.0"),
            Some(&vec![PathBuf::from("/global/foo")])
        );
    }

    #[test]
    fn merge_first_wins_ignores_purls_arg() {
        // The `purls` slice must not influence first-wins merging — only
        // the crawler-returned keys matter.
        let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let unrelated = vec!["pkg:npm/unrelated@9.9".to_string()];
        merge_first_wins(&mut out, &unrelated, packages(&[("pkg:npm/foo@1.0", "/a")]));
        assert_eq!(out.len(), 1);
        assert!(out.contains_key("pkg:npm/foo@1.0"));
    }

    // ---- merge_npm_copies -------------------------------------------------

    #[test]
    fn merge_npm_copies_carries_every_copy_per_purl() {
        // The npm crawler returns EVERY physical copy of a PURL; the merge
        // must carry them all (root-first ordering preserved) so apply
        // patches each — the multi-copy silent-partial fix.
        let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let mut packages: HashMap<String, Vec<CrawledPackage>> = HashMap::new();
        packages.insert(
            "pkg:npm/dup@1.0.0".to_string(),
            vec![
                pkg("pkg:npm/dup@1.0.0", "/nm/dup"),
                pkg("pkg:npm/dup@1.0.0", "/nm/parent/node_modules/dup"),
            ],
        );
        merge_npm_copies(&mut out, &[], packages);
        assert_eq!(
            out.get("pkg:npm/dup@1.0.0"),
            Some(&vec![
                PathBuf::from("/nm/dup"),
                PathBuf::from("/nm/parent/node_modules/dup"),
            ]),
            "both physical copies must be carried, root-first"
        );
    }

    // ---- merge_variant_copies ----------------------------------------------

    #[test]
    fn merge_variant_copies_accumulates_distinct_store_copies() {
        // The gem crawler resolves the same base PURL from two coexisting
        // stores (scoped + flat) across the macro's per-source-path calls;
        // both copies must be carried, discovery (precedence) order kept,
        // and an identical re-observed path deduped.
        let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
        merge_variant_copies(
            &mut out,
            &[],
            packages(&[("pkg:gem/rack@3.1.0", "/scoped/rack-3.1.0")]),
        );
        merge_variant_copies(
            &mut out,
            &[],
            packages(&[("pkg:gem/rack@3.1.0", "/flat/rack-3.1.0")]),
        );
        merge_variant_copies(
            &mut out,
            &[],
            packages(&[("pkg:gem/rack@3.1.0", "/flat/rack-3.1.0")]),
        );
        assert_eq!(
            out.get("pkg:gem/rack@3.1.0"),
            Some(&vec![
                PathBuf::from("/scoped/rack-3.1.0"),
                PathBuf::from("/flat/rack-3.1.0"),
            ]),
            "every distinct copy carried, precedence order kept, dup deduped"
        );
    }

    // ---- merge_qualified --------------------------------------------------

    #[test]
    fn merge_qualified_fans_base_out_to_every_variant() {
        // Crawler is queried with the base PURL and returns it keyed to a
        // single install dir; every caller-supplied qualified variant that
        // strips to that base must map to the same path.
        let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let qualified = vec![
            "pkg:pypi/requests@2.28.0?artifact_id=wheel".to_string(),
            "pkg:pypi/requests@2.28.0?artifact_id=sdist".to_string(),
        ];
        merge_qualified(
            &mut out,
            &qualified,
            packages(&[("pkg:pypi/requests@2.28.0", "/site-packages")]),
        );
        assert_eq!(out.len(), 2);
        assert_eq!(
            out.get("pkg:pypi/requests@2.28.0?artifact_id=wheel"),
            Some(&vec![PathBuf::from("/site-packages")])
        );
        assert_eq!(
            out.get("pkg:pypi/requests@2.28.0?artifact_id=sdist"),
            Some(&vec![PathBuf::from("/site-packages")])
        );
    }

    #[test]
    fn merge_qualified_matches_bare_base_identifier() {
        // A caller may supply the bare base PURL (no `?`); it strips to
        // itself and must still map to the crawler result.
        let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let purls = vec!["pkg:pypi/requests@2.28.0".to_string()];
        merge_qualified(
            &mut out,
            &purls,
            packages(&[("pkg:pypi/requests@2.28.0", "/sp")]),
        );
        assert_eq!(
            out.get("pkg:pypi/requests@2.28.0"),
            Some(&vec![PathBuf::from("/sp")])
        );
    }

    #[test]
    fn merge_qualified_does_not_cross_versions() {
        // A variant of a *different* version must not be mapped to the
        // crawler result for 2.28.0.
        let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let purls = vec!["pkg:pypi/requests@2.29.0?artifact_id=wheel".to_string()];
        merge_qualified(
            &mut out,
            &purls,
            packages(&[("pkg:pypi/requests@2.28.0", "/sp")]),
        );
        assert!(out.is_empty());
    }

    #[test]
    fn merge_qualified_drops_base_with_no_caller_variant() {
        // Rollback semantics: the result map must contain only
        // caller-supplied (manifest) PURLs. A crawler-returned base PURL
        // with no qualified caller variant that strips to it must be
        // dropped, never inserted under its bare base key. Guards against
        // a regression that leaks the raw crawler key into the output.
        let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let purls = vec!["pkg:pypi/flask@3.0.0?artifact_id=wheel".to_string()];
        merge_qualified(
            &mut out,
            &purls,
            packages(&[("pkg:pypi/requests@2.28.0", "/sp")]),
        );
        assert!(out.is_empty());
        assert!(!out.contains_key("pkg:pypi/requests@2.28.0"));
    }

    #[test]
    fn merge_qualified_isolates_distinct_bases_in_one_call() {
        // Two unrelated installed packages returned together must each map
        // only to their own qualified variant — no cross-base bleed.
        let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let purls = vec![
            "pkg:pypi/requests@2.28.0?artifact_id=wheel".to_string(),
            "pkg:pypi/flask@3.0.0?artifact_id=sdist".to_string(),
        ];
        merge_qualified(
            &mut out,
            &purls,
            packages(&[
                ("pkg:pypi/requests@2.28.0", "/req"),
                ("pkg:pypi/flask@3.0.0", "/flask"),
            ]),
        );
        assert_eq!(out.len(), 2);
        assert_eq!(
            out.get("pkg:pypi/requests@2.28.0?artifact_id=wheel"),
            Some(&vec![PathBuf::from("/req")])
        );
        assert_eq!(
            out.get("pkg:pypi/flask@3.0.0?artifact_id=sdist"),
            Some(&vec![PathBuf::from("/flask")])
        );
    }

    #[test]
    fn merge_qualified_keeps_first_path_per_qualified_key() {
        // First discovered path leads for a given qualified key, mirroring
        // the per-path iteration in the scan macro. A distinct second path
        // accumulates after it (release-variant ecosystems install one dir,
        // so in practice the second is the same path and dedups away).
        let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let purls = vec!["pkg:gem/nokogiri@1.16.5?platform=arm64-darwin".to_string()];
        merge_qualified(
            &mut out,
            &purls,
            packages(&[("pkg:gem/nokogiri@1.16.5", "/first")]),
        );
        merge_qualified(
            &mut out,
            &purls,
            packages(&[("pkg:gem/nokogiri@1.16.5", "/second")]),
        );
        let paths = out
            .get("pkg:gem/nokogiri@1.16.5?platform=arm64-darwin")
            .expect("qualified key present");
        assert_eq!(paths.first(), Some(&PathBuf::from("/first")));
    }

    // ---- purls_override helpers ------------------------------------------

    #[test]
    fn dedup_qualified_purls_strips_and_dedupes() {
        let purls = vec![
            "pkg:pypi/requests@2.28.0?artifact_id=wheel".to_string(),
            "pkg:pypi/requests@2.28.0?artifact_id=sdist".to_string(),
            "pkg:pypi/requests@2.28.0".to_string(),
        ];
        let mut out = dedup_qualified_purls(&purls);
        out.sort();
        assert_eq!(out, vec!["pkg:pypi/requests@2.28.0".to_string()]);
    }

    #[test]
    fn dedup_qualified_purls_keeps_distinct_bases() {
        let purls = vec![
            "pkg:pypi/requests@2.28.0?artifact_id=wheel".to_string(),
            "pkg:pypi/flask@3.0.0?artifact_id=wheel".to_string(),
        ];
        let mut out = dedup_qualified_purls(&purls);
        out.sort();
        assert_eq!(
            out,
            vec![
                "pkg:pypi/flask@3.0.0".to_string(),
                "pkg:pypi/requests@2.28.0".to_string(),
            ]
        );
    }

    #[test]
    fn merge_first_wins_accumulates_distinct_keys_across_calls() {
        // The shared `out` map is fed once per discovered path and once per
        // ecosystem; distinct keys from separate calls must all survive.
        let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
        merge_first_wins(&mut out, &[], packages(&[("pkg:npm/foo@1.0", "/a")]));
        merge_first_wins(&mut out, &[], packages(&[("pkg:cargo/bar@2.0", "/b")]));
        merge_first_wins(&mut out, &[], packages(&[("pkg:gem/baz@3.0", "/c")]));
        assert_eq!(out.len(), 3);
        assert_eq!(out.get("pkg:npm/foo@1.0"), Some(&vec![PathBuf::from("/a")]));
        assert_eq!(
            out.get("pkg:cargo/bar@2.0"),
            Some(&vec![PathBuf::from("/b")])
        );
        assert_eq!(out.get("pkg:gem/baz@3.0"), Some(&vec![PathBuf::from("/c")]));
    }

    #[test]
    fn passthrough_purls_is_identity() {
        let purls = vec!["pkg:npm/foo@1.0".to_string(), "pkg:npm/bar@2.0".to_string()];
        assert_eq!(passthrough_purls(&purls), purls);
    }

    /// The dedup/merge release-variant treatment must stay aligned with
    /// `Ecosystem::supports_release_variants()`. If a new ecosystem flips
    /// that predicate, this test flags that `dispatch_find` needs the
    /// matching `dedup_qualified_purls` + `variant_merge` wiring.
    #[test]
    fn release_variant_predicate_matches_dispatch_expectations() {
        assert!(Ecosystem::Pypi.supports_release_variants());
        assert!(Ecosystem::Gem.supports_release_variants());
        assert!(Ecosystem::Maven.supports_release_variants());
        assert!(!Ecosystem::Npm.supports_release_variants());
        assert!(!Ecosystem::Cargo.supports_release_variants());
        assert!(!Ecosystem::Golang.supports_release_variants());
        assert!(!Ecosystem::Composer.supports_release_variants());
        assert!(!Ecosystem::Nuget.supports_release_variants());
        assert!(!Ecosystem::Deno.supports_release_variants());
    }

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
        let purls = vec!["pkg:npm/foo@1.0".to_string(), "pkg:npm/foo@1.0".to_string()];
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
    fn partition_purls_allow_list_is_exact_match() {
        // The `--ecosystems` filter must compare against `cli_name()`
        // exactly: neither a prefix (`"np"`) nor a different case (`"NPM"`)
        // may smuggle an out-of-scope PURL through. Guards the dispatch
        // filter against becoming a loose/catch-all match.
        let purls = vec!["pkg:npm/foo@1.0".to_string()];
        for bad in ["np", "npmm", "NPM", "Npm", " npm", "npm "] {
            let allowed = vec![bad.to_string()];
            let map = partition_purls(&purls, Some(allowed.as_slice()));
            assert!(
                map.is_empty(),
                "allow-list entry {bad:?} must not match cli_name \"npm\""
            );
        }
        // The exact name still matches.
        let allowed = vec!["npm".to_string()];
        let map = partition_purls(&purls, Some(allowed.as_slice()));
        assert!(map.contains_key(&Ecosystem::Npm));
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

    // ---- dispatch_find orchestration (end-to-end via real crawlers) ------
    //
    // The pure merge/override helpers above are covered in isolation. These
    // exercise the full `dispatch_find` wiring — discover-paths → find_by_purls
    // → unified `purl -> path` map — through the real npm crawler against a
    // temp `node_modules`, so a regression in the macro plumbing (wrong
    // crawler/path method, dropped result, swapped merge) is caught.

    use std::io::Write as _;

    /// Lay down `node_modules/<name>/package.json` under `root` with the
    /// given version, returning the package directory the crawler should
    /// resolve the PURL to.
    fn write_npm_package(root: &std::path::Path, name: &str, version: &str) -> PathBuf {
        let pkg_dir = root.join("node_modules").join(name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let mut f = std::fs::File::create(pkg_dir.join("package.json")).unwrap();
        write!(f, r#"{{"name":"{name}","version":"{version}"}}"#).unwrap();
        pkg_dir
    }

    fn local_options(cwd: PathBuf) -> CrawlerOptions {
        CrawlerOptions {
            cwd,
            global: false,
            global_prefix: None,
        }
    }

    #[tokio::test]
    async fn find_packages_for_purls_maps_npm_purl_to_install_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = write_npm_package(tmp.path(), "foo", "1.0.0");

        let partitioned = partition_purls(&["pkg:npm/foo@1.0.0".to_string()], None);
        let out =
            find_packages_for_purls(&partitioned, &local_options(tmp.path().to_path_buf()), true)
                .await;

        // The unified map must key the result by the exact PURL handed in
        // (npm = passthrough + first-wins) and point at the install dir.
        assert_eq!(out.get("pkg:npm/foo@1.0.0"), Some(&pkg_dir));
    }

    /// Multi-copy P0 at the dispatch layer: `find_all_packages_for_purls`
    /// must carry EVERY physical copy of a duplicated npm PURL (a root copy
    /// plus a nested duplicate), root-copy-first — the second path the old
    /// `HashMap<String, PathBuf>` return type could not hold. `apply`
    /// iterates this to patch both copies.
    #[tokio::test]
    async fn find_all_packages_for_purls_carries_every_duplicate_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let root_copy = write_npm_package(tmp.path(), "dup", "1.0.0");
        // A genuine second physical copy nested under `parent`.
        let parent_nm = tmp.path().join("node_modules").join("parent");
        write_npm_package(&parent_nm, "dup", "1.0.0");
        let nested_copy = parent_nm.join("node_modules").join("dup");
        // `parent`'s own package.json so the nested node_modules has an owner.
        std::fs::write(
            parent_nm.join("package.json"),
            r#"{"name":"parent","version":"1.0.0"}"#,
        )
        .unwrap();

        let partitioned = partition_purls(&["pkg:npm/dup@1.0.0".to_string()], None);
        let out = find_all_packages_for_purls(
            &partitioned,
            &local_options(tmp.path().to_path_buf()),
            true,
        )
        .await;

        let copies = out.get("pkg:npm/dup@1.0.0").expect("dup resolves");
        assert_eq!(
            copies.len(),
            2,
            "both copies must be carried; got {copies:?}"
        );
        assert_eq!(copies[0], root_copy, "root copy first");
        assert!(copies.contains(&nested_copy), "nested copy must be present");

        // The collapsing wrapper (used by vendor/vex/setup/get) keeps the
        // old one-path contract: exactly the root-preferred representative.
        let single =
            find_packages_for_purls(&partitioned, &local_options(tmp.path().to_path_buf()), true)
                .await;
        assert_eq!(single.get("pkg:npm/dup@1.0.0"), Some(&root_copy));
    }

    /// Multi-copy P0 for gem (mirrors the npm test above): bundler's scoped
    /// (`<engine>/<abi>/gems`) and flat (`gems/`) store layouts coexist under
    /// one `vendor/bundle` root — a bundler-2 `--path` install beside a
    /// bundler-1 env install — each holding a REAL physical copy of the same
    /// `gem@version`. `find_all_packages_for_purls` (apply's resolver) must
    /// carry BOTH copies, highest-precedence store first. First-wins merging
    /// resolved ONE copy, apply patched it and reported success while the
    /// other bundler loaded the pristine (vulnerable) sibling.
    #[tokio::test]
    async fn find_all_packages_for_purls_carries_every_gem_store_copy() {
        let tmp = tempfile::tempdir().unwrap();
        // No Gemfile on purpose: env/config bundle roots are manifest-gated,
        // so an ambient BUNDLE_PATH on the dev machine cannot perturb this
        // test; the implicit vendor/bundle probe is ungated.
        let bundle = tmp.path().join("vendor").join("bundle");
        let scoped_copy = bundle
            .join("ruby")
            .join("3.2.0")
            .join("gems")
            .join("rack-3.1.0");
        let flat_copy = bundle.join("gems").join("rack-3.1.0");
        std::fs::create_dir_all(scoped_copy.join("lib")).unwrap();
        std::fs::create_dir_all(flat_copy.join("lib")).unwrap();
        // The specifications/ sibling marks the flat layout as a real gem home.
        std::fs::create_dir_all(bundle.join("specifications")).unwrap();

        let purl = "pkg:gem/rack@3.1.0".to_string();
        let partitioned = partition_purls(std::slice::from_ref(&purl), None);
        let opts = local_options(tmp.path().to_path_buf());

        let out = find_all_packages_for_purls(&partitioned, &opts, true).await;
        let copies = out.get(&purl).expect("gem resolves");
        assert_eq!(
            copies.len(),
            2,
            "both coexisting store copies must be carried; got {copies:?}"
        );
        assert_eq!(copies[0], scoped_copy, "scoped store copy first");
        assert!(copies.contains(&flat_copy), "flat store copy present");

        // The collapsing wrapper (vendor/vex/setup/get/repair-vendor) keeps
        // the one-representative contract: the first store's copy.
        let single = find_packages_for_purls(&partitioned, &opts, true).await;
        assert_eq!(single.get(&purl), Some(&scoped_copy));
    }

    #[tokio::test]
    async fn find_packages_for_purls_skips_version_mismatch() {
        // The crawler only matches an installed dir whose version equals the
        // PURL's; a mismatched version must yield no mapping (guards against
        // the dispatch returning a path for the wrong release).
        let tmp = tempfile::tempdir().unwrap();
        write_npm_package(tmp.path(), "foo", "2.0.0");

        let partitioned = partition_purls(&["pkg:npm/foo@1.0.0".to_string()], None);
        let out =
            find_packages_for_purls(&partitioned, &local_options(tmp.path().to_path_buf()), true)
                .await;
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn find_packages_for_rollback_keeps_full_npm_key() {
        // Non-variant ecosystems use `merge_first_wins` even on the rollback
        // path, so a qualified npm PURL must round-trip under its exact key
        // (a regression that routed npm through `merge_qualified` would drop
        // it, since the crawler echoes the verbatim PURL back).
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = write_npm_package(tmp.path(), "foo", "1.0.0");

        let qualified = "pkg:npm/foo@1.0.0?vcs_url=git@github.com".to_string();
        let partitioned = partition_purls(std::slice::from_ref(&qualified), None);
        let out = find_packages_for_rollback(
            &partitioned,
            &local_options(tmp.path().to_path_buf()),
            true,
        )
        .await;
        assert_eq!(out.get(&qualified), Some(&pkg_dir));
    }

    #[tokio::test]
    async fn find_packages_for_rollback_resolves_installed_qualified_gem() {
        // Regression for the vendor lookup path (vendor.rs): every real
        // production gem/pypi patch PURL is QUALIFIED (`?platform=` /
        // `?artifact_id=`), but the crawler only knows the BASE PURL.
        // `vendor` must resolve installed packages via the qualified-aware
        // rollback resolver so its `all_packages.contains_key(qualified)`
        // check recognizes the installed gem. Using `find_packages_for_purls`
        // (base-keyed) misses the qualified key, falsely classifying the
        // installed gem "not installed" — the bug that produced spurious
        // `vendor_fetched_missing` events and the gem platform coin-flip.
        let tmp = tempfile::tempdir().unwrap();
        // A platform gem installs into a `<name>-<version>` dir (with an
        // optional `-<platform>` suffix); lay down the plain-platform case.
        let gem_dir = tmp.path().join("activestorage-7.0.2.2");
        std::fs::create_dir_all(gem_dir.join("lib")).unwrap();

        // `global_prefix` makes the gem crawler treat `tmp` as the gems root
        // directly (same shortcut the ruby crawler's own tests use).
        let options = CrawlerOptions {
            cwd: tmp.path().to_path_buf(),
            global: false,
            global_prefix: Some(tmp.path().to_path_buf()),
        };

        let qualified = "pkg:gem/activestorage@7.0.2.2?platform=ruby".to_string();
        let partitioned = partition_purls(std::slice::from_ref(&qualified), None);

        // The vendor lookup path: the qualified manifest PURL is resolved to
        // the installed dir under its EXACT qualified key.
        let rollback = find_packages_for_rollback(&partitioned, &options, true).await;
        assert_eq!(
            rollback.get(&qualified),
            Some(&gem_dir),
            "installed qualified gem must resolve under its qualified key"
        );

        // The old resolver keyed by the BASE PURL only, so a `contains_key`
        // on the qualified PURL missed — the exact false "not installed".
        let base_keyed = find_packages_for_purls(&partitioned, &options, true).await;
        assert!(
            !base_keyed.contains_key(&qualified),
            "find_packages_for_purls must NOT be used by vendor: it keys by \
             the base PURL, so the qualified lookup falsely misses"
        );
    }

    #[tokio::test]
    async fn dispatch_find_empty_partition_yields_empty_map() {
        let tmp = tempfile::tempdir().unwrap();
        let empty: HashMap<Ecosystem, Vec<String>> = HashMap::new();
        let opts = local_options(tmp.path().to_path_buf());
        assert!(find_packages_for_purls(&empty, &opts, true)
            .await
            .is_empty());
        assert!(find_packages_for_rollback(&empty, &opts, true)
            .await
            .is_empty());
    }

    // ---- Maven/NuGet are first-class ecosystems ---------------------------
    //
    // Maven and NuGet used to sit behind `SOCKET_EXPERIMENTAL_MAVEN` /
    // `SOCKET_EXPERIMENTAL_NUGET` runtime gates. The gates are gone: every
    // ecosystem is crawled unconditionally in every flow. The observable
    // pin is the per-ecosystem `counts` map — a crawled-but-empty ecosystem
    // gets a `0` entry, so presence proves the crawler ran without needing
    // a real Maven repo / NuGet cache fixture.

    /// Every ecosystem must appear in `counts` unconditionally — guards
    /// against one being accidentally moved behind a runtime gate (the
    /// regression this test replaces: maven/nuget were env-gated).
    #[tokio::test]
    async fn crawl_all_includes_every_ecosystem_unconditionally() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, counts) = crawl_all_ecosystems(&local_options(tmp.path().to_path_buf())).await;
        for eco in [
            Ecosystem::Npm,
            Ecosystem::Pypi,
            Ecosystem::Cargo,
            Ecosystem::Gem,
            Ecosystem::Golang,
            Ecosystem::Maven,
            Ecosystem::Composer,
            Ecosystem::Nuget,
            Ecosystem::Deno,
        ] {
            assert!(
                counts.contains_key(&eco),
                "{eco:?} must be crawled unconditionally — no runtime gates"
            );
        }
    }

    /// Deno is the ONE dispatch branch no other test drives end-to-end
    /// (lcov: every other ecosystem's `scan_ecosystem!` invocation has
    /// executed, deno's never has). Stage the JSR cache layout
    /// `<root>/@<scope>/<name>/<version>/` and resolve a `pkg:jsr/` PURL
    /// through the full dispatch — partition → `get_jsr_cache_paths`
    /// (returns `global_prefix` verbatim) → `find_by_purls` → merge.
    /// `silent = false` also executes the "Using Deno JSR cache at:"
    /// banner branch for the deno invocation.
    #[tokio::test]
    async fn dispatch_find_deno_global_prefix_resolves_jsr_purl() {
        let tmp = tempfile::tempdir().unwrap();
        // JSR cache layout: <root>/@scope/name/version/ (scope keeps '@').
        let pkg_dir = tmp.path().join("@std").join("path").join("0.220.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("mod.ts"), b"export default 1;").unwrap();

        let purl = "pkg:jsr/@std/path@0.220.0".to_string();
        let partitioned = partition_purls(std::slice::from_ref(&purl), None);
        // `pkg:jsr/` is the one PURL type whose token differs from its
        // cli_name — it must partition to Ecosystem::Deno, not vanish.
        assert_eq!(partitioned.len(), 1);
        assert_eq!(partitioned.get(&Ecosystem::Deno), Some(&vec![purl.clone()]));

        let options = CrawlerOptions {
            cwd: tmp.path().to_path_buf(),
            global: false,
            global_prefix: Some(tmp.path().to_path_buf()),
        };

        let out = find_packages_for_purls(&partitioned, &options, false).await;
        assert_eq!(
            out.get(&purl),
            Some(&pkg_dir),
            "deno dispatch must resolve the jsr PURL to its cache dir"
        );

        // Deno is wired to `merge_first_wins` on the ROLLBACK path too (it
        // has no release variants), so the same verbatim key must resolve.
        // A refactor routing deno through `merge_qualified` would drop the
        // key (the crawler echoes the verbatim input PURL, and rollback's
        // qualified fan-out only re-keys stripped bases) — caught here.
        let rb = find_packages_for_rollback(&partitioned, &options, false).await;
        assert_eq!(
            rb.get(&purl),
            Some(&pkg_dir),
            "deno rollback dispatch must keep the verbatim jsr key"
        );
    }

    /// The `!silent` banner branch — "Using <label> at: <prefix>", printed
    /// on global/global-prefix runs (`apply --global` shows it) — has never
    /// executed for ANY labeled ecosystem: every existing dispatch test
    /// passes `silent = true`. Drive it for all eight labeled ecosystems
    /// (pypi's label is "" — deliberately suppressed) and pin the real
    /// output contract: an empty prefix resolves NOTHING, so the banner
    /// path must not fabricate phantom mappings. Every crawler's
    /// `get_paths` returns `global_prefix` verbatim (verified per-crawler),
    /// so no env vars are consulted and no serial guard is needed.
    #[tokio::test]
    async fn dispatch_global_prefix_nonsilent_prints_using_banner_for_labeled_ecosystems() {
        for purl in [
            "pkg:npm/foo@1.0.0",
            "pkg:cargo/foo@1.0.0",
            "pkg:gem/foo@1.0.0",
            "pkg:golang/example.com/foo@v1.0.0",
            "pkg:maven/org.example/foo@1.0.0",
            "pkg:composer/vendor/foo@1.0.0",
            "pkg:nuget/Foo@1.0.0",
            "pkg:jsr/@std/foo@1.0.0",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let options = CrawlerOptions {
                cwd: tmp.path().to_path_buf(),
                global: false,
                global_prefix: Some(tmp.path().to_path_buf()),
            };
            let partitioned = partition_purls(&[purl.to_string()], None);
            assert_eq!(
                partitioned.len(),
                1,
                "{purl} must partition to exactly one ecosystem"
            );
            let out = find_packages_for_purls(&partitioned, &options, false).await;
            assert!(
                out.is_empty(),
                "empty global prefix must resolve nothing for {purl}, got {out:?}"
            );
        }
    }

    /// The PURL-lookup path (`find_packages_for_purls` — apply/vendor's
    /// resolver) must resolve a maven package from a local repository with
    /// no env opt-in of any kind.
    #[tokio::test]
    #[serial_test::serial(maven_repo_env)]
    async fn find_packages_resolves_maven_without_any_opt_in() {
        let tmp = tempfile::tempdir().unwrap();

        // Minimal local Maven repository layout the crawler recognizes:
        // <repo>/org/example/foo/1.0.0/foo-1.0.0.pom (+ project marker).
        std::fs::write(tmp.path().join("pom.xml"), "<project></project>\n").unwrap();
        let artifact_dir = tmp
            .path()
            .join("m2repo")
            .join("org")
            .join("example")
            .join("foo")
            .join("1.0.0");
        std::fs::create_dir_all(&artifact_dir).unwrap();
        std::fs::write(artifact_dir.join("foo-1.0.0.pom"), "<project/>").unwrap();
        std::env::set_var("MAVEN_REPO_LOCAL", tmp.path().join("m2repo"));

        let purl = "pkg:maven/org.example/foo@1.0.0".to_string();
        let partitioned = partition_purls(std::slice::from_ref(&purl), None);
        let opts = local_options(tmp.path().to_path_buf());

        let out = find_packages_for_purls(&partitioned, &opts, true).await;
        std::env::remove_var("MAVEN_REPO_LOCAL");
        assert_eq!(
            out.get(&purl),
            Some(&artifact_dir),
            "maven lookup must resolve without any experimental opt-in"
        );
    }
}
