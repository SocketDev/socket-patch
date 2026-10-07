use socket_patch_core::crawlers::{
    CrawledPackage, CrawlerOptions, Ecosystem, NpmCrawler, PythonCrawler, RubyCrawler,
};
use socket_patch_core::utils::purl::{canonical_purl, normalize_purl, strip_purl_qualifiers};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::args::GlobalArgs;

use socket_patch_core::crawlers::npm_crawler::with_store_peer_variant_copies;
use socket_patch_core::crawlers::walk_pool;
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
/// scans; pass `""` to suppress that line. The banner is progress chrome
/// and goes to STDERR like the macro's two warnings: stdout belongs to
/// `--json` envelopes and the VEX document, so a caller that forgets to
/// fold `json` into `$silent` cannot corrupt them.
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
                            // Status chrome: stderr, so it can never reach a
                            // machine stream (`--json` envelope, vex document).
                            if let Some(first) = paths.first() {
                                eprintln!("Using {} at: {}", using, first.display());
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
                            eprintln!("Warning: Failed to find {}: {}", $err_label, e);
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
/// `gems/` layout, or an env `BUNDLE_PATH` store) — first-wins would drop
/// the second copy, so apply would patch one store while the other bundler
/// loads pristine bytes. Collapsing consumers still take the first
/// (highest-precedence) path; apply fans out per-copy for gem and Maven
/// (`~/.m2` and each Gradle cache are distinct installs some build reads;
/// PyPI keeps its one-install-dir contract — see the apply variant loop).
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
/// A one-path `HashMap<String, PathBuf>` would silently drop every copy
/// after the first.
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

/// `paths` in order with every path that resolves to an already-listed
/// directory dropped: two discovered site-packages paths can name ONE
/// directory (a `lib64 -> lib` symlink, a symlinked venv), as can two npm
/// copies (see [`distinct_npm_copies`]), and patching it twice would report
/// the second pass `already_patched`. A path that can't be canonicalized is
/// kept as-is.
pub(crate) async fn distinct_install_dirs(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let key = tokio::fs::canonicalize(path)
            .await
            .unwrap_or_else(|_| path.clone());
        if seen.insert(key) {
            out.push(path.clone());
        }
    }
    out
}

/// Collapse each npm PURL's copies to distinct physical directories, in
/// discovery order (the first spelling of each directory wins). The
/// resolver walks every `node_modules` root, so a pnpm / Bun isolated
/// workspace yields one copy twice: as the root's `.pnpm` store entry and
/// as a member's `packages/a/node_modules/<dep>` link to it. Visiting both
/// patched (or restored) it once and reported the second visit as a
/// phantom `already_patched` / already-original event (#633). The map
/// itself keeps every spelling, because path targets (`scan` / `rollback
/// packages/a`) select a copy by the member's link; only the commands that
/// act per copy collapse it. Genuinely distinct copies (nested duplicates,
/// store peer variants) have distinct real paths and are all kept.
pub(crate) async fn distinct_npm_copies(map: &mut HashMap<String, Vec<PathBuf>>) {
    for (purl, paths) in map.iter_mut() {
        if paths.len() > 1 && Ecosystem::from_purl(purl) == Some(Ecosystem::Npm) {
            *paths = distinct_install_dirs(paths).await;
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
///
/// `npm_roots`, when given, are the `node_modules` roots an earlier crawl of
/// the same options and (untouched) tree walked — used instead of walking
/// the tree for them again ([`NpmRootsCrawler`]).
async fn dispatch_find(
    partitioned: &HashMap<Ecosystem, Vec<String>>,
    options: &CrawlerOptions,
    silent: bool,
    variant_merge: MergeFn,
    npm_roots: Option<&[PathBuf]>,
) -> HashMap<String, Vec<PathBuf>> {
    let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();

    scan_ecosystem!(
        out = out,
        partitioned = partitioned,
        eco = Ecosystem::Npm,
        options = options,
        silent = silent,
        crawler = NpmRootsCrawler { roots: npm_roots },
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
        // Every cache holding a copy: `~/.m2` first, then each Gradle
        // `files-2.1` (the user home's and the read-only one), whose
        // version dirs every join site expands through
        // `gradle_cache::installed_copies`. `variant_merge` keeps every
        // distinct copy (`push_path`), and the Maven join sites
        // ([`JvmScope`]) split them into the copies a build consumes.
        get_paths = get_maven_copy_paths,
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
/// `get`, `repair vendor`) use the collapsing wrappers below
/// (`HashMap<String, PathBuf>`). `apply` and
/// `rollback` — which must touch EVERY copy — use the `_all` variants.
pub(crate) fn collapse_to_first(multi: HashMap<String, Vec<PathBuf>>) -> HashMap<String, PathBuf> {
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
    dispatch_find(partitioned, options, silent, merge_variant_copies, None).await
}

/// Multi-copy variant of `find_packages_for_rollback` (qualified-aware
/// merge). Used by `rollback`, which restores every physical copy.
pub async fn find_all_packages_for_rollback(
    partitioned: &HashMap<Ecosystem, Vec<String>>,
    options: &CrawlerOptions,
    silent: bool,
) -> HashMap<String, Vec<PathBuf>> {
    find_all_packages_for_rollback_reusing(partitioned, options, silent, None).await
}

/// [`find_all_packages_for_rollback`], taking the npm `node_modules` roots
/// from `prior` as [`find_packages_for_rollback_reusing`] does. Used by
/// `scan`'s path scoping, which must see the same copies `rollback`'s path
/// targets do.
pub async fn find_all_packages_for_rollback_reusing(
    partitioned: &HashMap<Ecosystem, Vec<String>>,
    options: &CrawlerOptions,
    silent: bool,
    prior: Option<&NpmCrawlSnapshot>,
) -> HashMap<String, Vec<PathBuf>> {
    let npm_roots = prior
        .filter(|p| p.taken_with(options))
        .map(|p| p.roots.as_slice());
    dispatch_find(partitioned, options, silent, merge_qualified, npm_roots).await
}

/// Qualified-aware PURL resolution for rollback, vendor, repair and
/// narrow-release lookups: remaps qualified PURLs (PyPI `?artifact_id=`,
/// RubyGems `?platform=`, Maven `?classifier=&ext=`) to the base PURL the
/// crawler found, keyed back by the caller's qualified spelling. Returns one
/// representative copy per PURL. (Its base-keyed twin,
/// `collapse_to_first(find_all_packages_for_purls(..))`, has no production
/// caller: manifest and ledger keys are qualified for the release-variant
/// ecosystems, and a base-keyed map never matched them — the in-file tests
/// pin that contrast.)
pub async fn find_packages_for_rollback(
    partitioned: &HashMap<Ecosystem, Vec<String>>,
    options: &CrawlerOptions,
    silent: bool,
) -> HashMap<String, PathBuf> {
    find_packages_for_rollback_reusing(partitioned, options, silent, None).await
}

/// [`find_packages_for_rollback`], taking the npm `node_modules` roots from
/// `prior` (a crawl of the same options earlier in this process, over a
/// tree nothing has touched since) instead of walking the tree for them
/// again. Only the root discovery is reused: each root is still searched
/// by `find_by_purls`, so copy choice and order are unchanged. A snapshot
/// taken with other options is ignored.
pub async fn find_packages_for_rollback_reusing(
    partitioned: &HashMap<Ecosystem, Vec<String>>,
    options: &CrawlerOptions,
    silent: bool,
    prior: Option<&NpmCrawlSnapshot>,
) -> HashMap<String, PathBuf> {
    let npm_roots = prior
        .filter(|p| p.taken_with(options))
        .map(|p| p.roots.as_slice());
    collapse_to_first(dispatch_find(partitioned, options, silent, merge_qualified, npm_roots).await)
}

/// The npm half of one [`crawl_ecosystems_with_npm`] run: the packages
/// the npm crawler found (its whole output, in crawl order) and the
/// `node_modules` roots it walked, with the options they were taken with.
/// Handed from `scan`'s crawl to its vendor step so the vendor engine does
/// not walk the same untouched tree again ([`npm_paths_by_identity_in`],
/// [`find_packages_for_rollback_reusing`]).
#[derive(Debug, Clone)]
pub struct NpmCrawlSnapshot {
    cwd: PathBuf,
    global: bool,
    global_prefix: Option<PathBuf>,
    roots: Vec<PathBuf>,
    packages: Vec<CrawledPackage>,
}

impl NpmCrawlSnapshot {
    /// Whether this snapshot was crawled with exactly `options`.
    fn taken_with(&self, options: &CrawlerOptions) -> bool {
        // Destructured, not field-by-field: a new crawler option that
        // changes what the crawler walks has to be answered here, and the
        // compiler is what asks. Everything this snapshot stands in for
        // was crawled with these options and nothing else.
        let CrawlerOptions {
            cwd,
            global,
            global_prefix,
        } = options;
        self.cwd == *cwd && self.global == *global && self.global_prefix == *global_prefix
    }

    /// The crawled npm packages, when crawled with exactly `options`.
    pub(crate) fn packages_for(&self, options: &CrawlerOptions) -> Option<&[CrawledPackage]> {
        self.taken_with(options).then_some(self.packages.as_slice())
    }

    /// The `node_modules` roots the crawl walked — exactly what
    /// `NpmCrawler::get_node_modules_paths` returns for the same options and
    /// tree — when crawled with exactly `options`.
    pub(crate) fn roots_for(&self, options: &CrawlerOptions) -> Option<&[PathBuf]> {
        self.taken_with(options).then_some(self.roots.as_slice())
    }
}

/// [`NpmCrawler`] for [`dispatch_find`], answering its root discovery from
/// an earlier crawl's roots when it has them.
struct NpmRootsCrawler<'a> {
    roots: Option<&'a [PathBuf]>,
}

impl NpmRootsCrawler<'_> {
    async fn get_node_modules_paths(
        &self,
        options: &CrawlerOptions,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        match self.roots {
            Some(roots) => Ok(roots.to_vec()),
            None => NpmCrawler.get_node_modules_paths(options).await,
        }
    }

    async fn find_by_purls(
        &self,
        node_modules_path: &std::path::Path,
        purls: &[String],
    ) -> Result<HashMap<String, Vec<CrawledPackage>>, std::io::Error> {
        NpmCrawler.find_by_purls(node_modules_path, purls).await
    }
}

/// The installed copy of each npm purl in `purls`, found by its
/// `package.json` identity (a full npm crawl) instead of its install path.
/// An npm ALIAS dependency (`"lp": "npm:left-pad@1.3.0"`) is installed under
/// its dependency key (`node_modules/lp`), which the name-keyed resolvers
/// above never probe; callers use this as the last lookup before calling a
/// package missing (`vendor`, and `vex` for a purl nothing else found).
/// The crawl dedups by name@version, so this yields ONE copy per purl — the
/// first the crawl reaches — never every alias beside a normal install
/// (`vex`'s per-dir alias walk, `vex_consumed::npm_alias_copies`, finds
/// those). Keyed by the caller's spelling; a purl with no copy has no
/// entry. No crawl runs when `purls` is empty.
pub(crate) async fn npm_paths_by_identity(
    options: &CrawlerOptions,
    purls: &[&String],
) -> HashMap<String, Vec<PathBuf>> {
    if purls.is_empty() {
        return HashMap::new();
    }
    let installed = NpmCrawler::new().crawl_all(options).await;
    npm_paths_by_identity_in(&installed, purls)
}

/// [`npm_paths_by_identity`] over an npm crawl already in hand (the whole
/// output of `NpmCrawler::crawl_all` for the same options, over a tree
/// nothing has touched since) instead of crawling again.
pub(crate) fn npm_paths_by_identity_in(
    installed: &[CrawledPackage],
    purls: &[&String],
) -> HashMap<String, Vec<PathBuf>> {
    let mut out = HashMap::new();
    for purl in purls {
        let want = canonical_purl(purl);
        let paths: Vec<PathBuf> = installed
            .iter()
            .filter(|pkg| normalize_purl(&pkg.purl) == want)
            .map(|pkg| pkg.path.clone())
            .collect();
        if !paths.is_empty() {
            out.insert((*purl).clone(), paths);
        }
    }
    out
}

/// Resolve manifest PURLs to every installed on-disk copy (crawl order;
/// partition, build crawler options from the global args, dispatch). Uses
/// the rollback (qualified-aware) resolver, never a base-keyed collapse of
/// [`find_all_packages_for_purls`]: release-variant ecosystems (PyPI /
/// RubyGems / Maven) key the manifest by *qualified* PURLs
/// (`?artifact_id=`, `?platform=`, `?classifier=&ext=`), but the crawler
/// only knows the *base* PURL. A base-keyed result map would make every
/// qualified manifest lookup miss, so every PyPI/Gem/Maven
/// patch would silently resolve as `package_not_found`. The rollback
/// variant fans each base path back out to every qualified manifest PURL
/// — the same mapping the manifest was written with (`get` uses the same
/// resolver). `vex` hashes every copy of a manifest purl and of a hosted
/// one from this one lookup; npm copies include their store variants.
///
/// With `prior`, the npm `node_modules` roots come
/// from it (a crawl of the same options earlier in this process, over
/// a tree whose directories nothing has touched since) instead of walking
/// the tree for them again — the every-copy twin of
/// [`find_packages_for_rollback_reusing`]. Only the root discovery is
/// reused: each root is still searched by `find_by_purls`, so copy choice
/// and order are unchanged. A snapshot taken with other options is ignored.
///
/// Read-only by contract (its one caller is `vex`), so it also searches the
/// gem stores under a refused out-of-tree `.bundle/config` path
/// (`RubyCrawler::verification_only_gem_paths`), which the write paths never
/// see.
pub async fn find_manifest_package_copies_reusing(
    purls: &[String],
    common: &GlobalArgs,
    quiet: bool,
    prior: Option<&NpmCrawlSnapshot>,
) -> HashMap<String, Vec<PathBuf>> {
    let partitioned = partition_purls(purls, common.ecosystems.as_deref());
    let crawler_options = common.crawler_options();
    let npm_roots = prior.and_then(|p| p.roots_for(&crawler_options));
    let mut copies = dispatch_find(
        &partitioned,
        &crawler_options,
        quiet,
        merge_qualified,
        npm_roots,
    )
    .await;
    // `apply` also writes every store variant of each npm copy (a pnpm peer
    // suffix, a Deno `_N` copy index, a vlt peer extra), so "every copy"
    // includes them (#603).
    for (purl, paths) in copies.iter_mut() {
        if purl.starts_with("pkg:npm/") {
            *paths = with_store_peer_variant_copies(std::mem::take(paths)).await;
        }
    }
    // Verification also READS a `.bundle/config` bundle path the crawler
    // refused as a write root (it resolves outside the project): bundler
    // installs into and loads from it, so a copy there must verify too —
    // skipping it would leave an unpatched gem looking "not installed",
    // which the hosted lockfile basis then attests (#709).
    if let Some(gem_purls) = partitioned.get(&Ecosystem::Gem) {
        let stores = RubyCrawler
            .verification_only_gem_paths(&crawler_options)
            .await;
        let bases = dedup_qualified_purls(gem_purls);
        for store in &stores {
            if let Ok(found) = RubyCrawler.find_by_purls(store, &bases).await {
                merge_qualified(&mut copies, gem_purls, found);
            }
        }
    }
    copies
}

// ── JVM copies ──────────────────────────────────────────────────────────

/// What the Maven join sites (apply, rollback, vex) need to know about the
/// run's JVM caches, resolved once per run: which copies a build consumes,
/// which are read-only, and whether the build verifies its dependencies.
#[derive(Debug, Clone)]
pub(crate) struct JvmScope {
    pub env: socket_patch_core::crawlers::maven_crawler::JvmEnv,
    /// The local Gradle build's `m2_gate` (local mode only; `None` in a
    /// global run, where every cache counts).
    pub gate: Option<socket_patch_core::crawlers::maven_crawler::M2Gate>,
    /// `gradle/verification-metadata.xml` of the cwd's build (or the
    /// ancestor build it belongs to), local mode only.
    pub verification_metadata: Option<PathBuf>,
}

/// The installed copies of one Maven purl, split by how a build reads them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MavenCopies {
    /// Writable copies some build consumes: `~/.m2` version dirs (unless
    /// ignored) and Gradle user-home version dirs, in lookup order.
    pub consumed: Vec<PathBuf>,
    /// Copies in the read-only Gradle cache (`GRADLE_RO_DEP_CACHE`): read
    /// by Gradle, never written.
    pub read_only: Vec<PathBuf>,
    /// `~/.m2` copies a Gradle-only build never reads (no `mavenLocal()`).
    /// A Coursier or Ivy copy (sbt, Mill, scala-cli) is never one: the
    /// `mavenLocal()` gate is about `~/.m2` alone.
    pub m2_ignored: Vec<PathBuf>,
}

impl JvmScope {
    /// The scope of a run with `common`'s flags, over the process
    /// environment.
    pub(crate) async fn of(common: &GlobalArgs) -> Self {
        use socket_patch_core::crawlers::gradle_cache;
        use socket_patch_core::crawlers::maven_crawler::{m2_gate, JvmEnv};
        let env = JvmEnv::from_process();
        if common.is_global() {
            return Self {
                env,
                gate: None,
                verification_metadata: None,
            };
        }
        let cwd = common.cwd.clone();
        let probe_env = env.clone();
        let probe = move || {
            let gate = m2_gate(&cwd, &probe_env);
            let metadata = gradle_cache::build_roots(&cwd)
                .into_iter()
                .map(|root| root.join("gradle").join("verification-metadata.xml"))
                .find(|p| p.is_file());
            (gate, metadata)
        };
        // Script reads and stats: off the async workers.
        let (gate, verification_metadata) = tokio::task::spawn_blocking(probe)
            .await
            .expect("JVM scope probe panicked");
        Self {
            env,
            gate: Some(gate),
            verification_metadata,
        }
    }

    /// Whether a build of this run reads `~/.m2` (always, except a local
    /// Gradle-only build that never declares `mavenLocal()`).
    pub(crate) fn m2_consumed(&self) -> bool {
        use socket_patch_core::crawlers::maven_crawler::M2Gate;
        self.gate.as_ref() != Some(&M2Gate::Ignored)
    }

    /// Whether `path` lies in the read-only Gradle cache.
    pub(crate) fn is_read_only(&self, path: &std::path::Path) -> bool {
        self.env
            .gradle
            .as_ref()
            .and_then(|h| h.ro_files21.as_deref())
            .is_some_and(|ro| path.starts_with(ro))
    }

    /// Split the copies the resolver found for one purl.
    pub(crate) fn split(&self, paths: &[PathBuf]) -> MavenCopies {
        let mut out = MavenCopies::default();
        for path in paths {
            if self.is_read_only(path) {
                out.read_only.push(path.clone());
            } else if path.starts_with(&self.env.m2_repo) && !self.m2_consumed() {
                out.m2_ignored.push(path.clone());
            } else {
                out.consumed.push(path.clone());
            }
        }
        out
    }
}

/// Box the future `make` returns, constructing it inside this (non-async)
/// frame so the caller's poll frame only ever holds the pointer.
fn boxed<'a, T, F, Fut>(make: F) -> std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T> + 'a,
{
    Box::pin(make())
}

/// Crawl all ecosystems and return all packages, per-ecosystem counts and
/// the gem crawl's refused config-sourced `BUNDLE_PATH`
/// (`BundleStoreDiscovery::skipped_config_path`, local mode only) —
/// recovered from the crawl that hit it, so callers surfacing the advisory
/// never probe the Bundler roots a second time.
pub async fn crawl_all_ecosystems(
    options: &CrawlerOptions,
) -> (
    Vec<CrawledPackage>,
    HashMap<Ecosystem, usize>,
    Option<String>,
) {
    crawl_ecosystems(options, None).await
}

/// [`crawl_all_ecosystems`] over only the ecosystems `only` names
/// (`--ecosystems` spellings; `None` crawls every one). A crawler that is
/// not selected never runs: it contributes no packages and no `counts`
/// entry. Each crawler reports only its own ecosystem's purls, so the
/// selected ecosystems' packages, their order and their counts are exactly
/// the full crawl's.
pub async fn crawl_ecosystems(
    options: &CrawlerOptions,
    only: Option<&[String]>,
) -> (
    Vec<CrawledPackage>,
    HashMap<Ecosystem, usize>,
    Option<String>,
) {
    let (packages, counts, skipped_config_path, _) = crawl_every_ecosystem(options, only).await;
    (packages, counts, skipped_config_path)
}

/// [`crawl_all_ecosystems`], also handing back the npm half of the crawl as
/// an [`NpmCrawlSnapshot`] (its packages are the leading `counts[Npm]`
/// entries of the package list).
#[cfg(test)]
pub async fn crawl_all_ecosystems_with_npm(
    options: &CrawlerOptions,
) -> (
    Vec<CrawledPackage>,
    HashMap<Ecosystem, usize>,
    Option<String>,
    NpmCrawlSnapshot,
) {
    let (packages, counts, skipped_config_path, snapshot) =
        crawl_ecosystems_with_npm(options, None).await;
    let snapshot = snapshot.expect("a crawl of every ecosystem crawls npm");
    (packages, counts, skipped_config_path, snapshot)
}

/// [`crawl_ecosystems`], also handing back the npm half of the crawl as an
/// [`NpmCrawlSnapshot`] — `None` when `only` leaves npm out, so nothing
/// mistakes the skipped crawl for an empty `node_modules`.
pub async fn crawl_ecosystems_with_npm(
    options: &CrawlerOptions,
    only: Option<&[String]>,
) -> (
    Vec<CrawledPackage>,
    HashMap<Ecosystem, usize>,
    Option<String>,
    Option<NpmCrawlSnapshot>,
) {
    let (packages, counts, skipped_config_path, npm_roots) =
        crawl_every_ecosystem(options, only).await;
    let snapshot = counts
        .get(&Ecosystem::Npm)
        .map(|&npm_count| NpmCrawlSnapshot {
            cwd: options.cwd.clone(),
            global: options.global,
            global_prefix: options.global_prefix.clone(),
            roots: npm_roots,
            packages: packages[..npm_count].to_vec(),
        });
    (packages, counts, skipped_config_path, snapshot)
}

/// Whether a crawl limited to `only` visits `eco` (`None`: every one).
fn crawl_selects(only: Option<&[String]>, eco: Ecosystem) -> bool {
    only.is_none_or(|list| list.iter().any(|name| name == eco.cli_name()))
}

/// The crawl behind the entry points above; the fourth element is the npm
/// crawler's `node_modules` roots (empty when npm was not selected).
async fn crawl_every_ecosystem(
    options: &CrawlerOptions,
    only: Option<&[String]>,
) -> (
    Vec<CrawledPackage>,
    HashMap<Ecosystem, usize>,
    Option<String>,
    Vec<PathBuf>,
) {
    // The nine crawlers are independent (none prints, none mutates shared
    // state), so they run concurrently; their blocking walks and
    // subprocesses sit on the blocking pool. Results are consumed in the
    // fixed order below, so packages and counts are exactly the serial
    // run's. Each future is heap-allocated through `boxed` (constructed
    // in that helper's frame) so joining nine does not grow the caller's
    // poll frame by their combined size. Under a tight descriptor limit
    // they run one at a time instead, keeping the serial run's descriptor
    // profile (see `walk_pool`): a crawler treats a failed open as an
    // absent dir, so extra concurrent descriptors could silently drop
    // packages there. A crawler `only` leaves out resolves to its empty
    // result without running.
    macro_rules! crawl {
        ($eco:expr, $crawl:expr) => {
            boxed(move || async move {
                if crawl_selects(only, $eco) {
                    Some($crawl.await)
                } else {
                    None
                }
            })
        };
    }
    let (npm, pypi, cargo, gems, golang, maven, composer, nuget, deno) =
        if walk_pool::fd_limit_is_tight() {
            (
                crawl!(Ecosystem::Npm, NpmCrawler.crawl_all_with_roots(options)).await,
                crawl!(Ecosystem::Pypi, PythonCrawler.crawl_all(options)).await,
                crawl!(Ecosystem::Cargo, CargoCrawler.crawl_all(options)).await,
                crawl!(
                    Ecosystem::Gem,
                    RubyCrawler.crawl_all_with_discovery(options)
                )
                .await,
                crawl!(Ecosystem::Golang, GoCrawler.crawl_all(options)).await,
                crawl!(Ecosystem::Maven, MavenCrawler.crawl_all(options)).await,
                crawl!(Ecosystem::Composer, ComposerCrawler.crawl_all(options)).await,
                crawl!(Ecosystem::Nuget, NuGetCrawler.crawl_all(options)).await,
                crawl!(Ecosystem::Deno, DenoCrawler.crawl_all(options)).await,
            )
        } else {
            tokio::join!(
                crawl!(Ecosystem::Npm, NpmCrawler.crawl_all_with_roots(options)),
                crawl!(Ecosystem::Pypi, PythonCrawler.crawl_all(options)),
                crawl!(Ecosystem::Cargo, CargoCrawler.crawl_all(options)),
                crawl!(
                    Ecosystem::Gem,
                    RubyCrawler.crawl_all_with_discovery(options)
                ),
                crawl!(Ecosystem::Golang, GoCrawler.crawl_all(options)),
                crawl!(Ecosystem::Maven, MavenCrawler.crawl_all(options)),
                crawl!(Ecosystem::Composer, ComposerCrawler.crawl_all(options)),
                crawl!(Ecosystem::Nuget, NuGetCrawler.crawl_all(options)),
                crawl!(Ecosystem::Deno, DenoCrawler.crawl_all(options)),
            )
        };
    let (npm, npm_roots) = match npm {
        Some((packages, roots)) => (Some(packages), roots),
        None => (None, Vec::new()),
    };
    let (gems, gem_discovery) = match gems {
        Some((packages, discovery)) => (Some(packages), discovery),
        None => (None, None),
    };

    let mut all_packages = Vec::new();
    let mut counts: HashMap<Ecosystem, usize> = HashMap::new();
    for (eco, pkgs) in [
        (Ecosystem::Npm, npm),
        (Ecosystem::Pypi, pypi),
        (Ecosystem::Cargo, cargo),
        (Ecosystem::Gem, gems),
        (Ecosystem::Golang, golang),
        (Ecosystem::Maven, maven),
        (Ecosystem::Composer, composer),
        (Ecosystem::Nuget, nuget),
        (Ecosystem::Deno, deno),
    ] {
        let Some(pkgs) = pkgs else {
            continue;
        };
        counts.insert(eco, pkgs.len());
        all_packages.extend(pkgs);
    }

    let skipped_config_path = gem_discovery.and_then(|d| d.skipped_config_path);
    (all_packages, counts, skipped_config_path, npm_roots)
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

    /// #633: a pnpm workspace member's link into the root store is the
    /// copy the root walk already found, so it collapses to the first
    /// spelling; a genuine second copy, a missing path and a non-npm PURL
    /// are kept as they are.
    #[cfg(unix)]
    #[tokio::test]
    async fn distinct_npm_copies_drops_a_second_spelling_of_one_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("node_modules/.pnpm/a@1.0.0/node_modules/a");
        let nested = tmp.path().join("node_modules/b/node_modules/a");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::create_dir_all(&nested).unwrap();
        let member_nm = tmp.path().join("packages/m/node_modules");
        std::fs::create_dir_all(&member_nm).unwrap();
        let link = member_nm.join("a");
        std::os::unix::fs::symlink(&store, &link).unwrap();
        let missing = tmp.path().join("gone");
        let mut map: HashMap<String, Vec<PathBuf>> = HashMap::new();
        map.insert(
            "pkg:npm/a@1.0.0".into(),
            vec![store.clone(), link.clone(), nested.clone(), missing.clone()],
        );
        map.insert("pkg:gem/a@1.0.0".into(), vec![store.clone(), link.clone()]);
        distinct_npm_copies(&mut map).await;
        assert_eq!(map["pkg:npm/a@1.0.0"], vec![store.clone(), nested, missing]);
        assert_eq!(map["pkg:gem/a@1.0.0"], vec![store, link]);
    }

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

    /// The base-keyed PURL lookup (`find_all_packages_for_purls` collapsed
    /// to one copy per PURL). No production caller — every resolver keys by
    /// the caller's qualified spelling — kept here so the tests below can
    /// pin the contrast with [`find_packages_for_rollback`].
    async fn find_packages_for_purls(
        partitioned: &HashMap<Ecosystem, Vec<String>>,
        options: &CrawlerOptions,
        silent: bool,
    ) -> HashMap<String, PathBuf> {
        collapse_to_first(find_all_packages_for_purls(partitioned, options, silent).await)
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

    /// The dispatch wiring over a vlt store: a direct dep resolves at its
    /// importer link, a transitive-only dep at its `.vlt/<DepID>` store
    /// copy (here a legacy-era modifier-extra id), and both come back keyed
    /// by the exact PURLs handed in.
    #[tokio::test]
    async fn find_packages_for_purls_maps_npm_purl_to_vlt_store_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        let store = nm.join(".vlt");
        let direct = write_npm_package(&store.join("~npm~foo@1.0.0"), "foo", "1.0.0");
        let transitive = write_npm_package(
            &store.join("··ms@2.1.3·%3Aroot%20%3E%20%23debug%20%3E%20%23ms"),
            "ms",
            "2.1.3",
        );
        #[cfg(unix)]
        std::os::unix::fs::symlink(&direct, nm.join("foo")).unwrap();

        let purls = [
            "pkg:npm/foo@1.0.0".to_string(),
            "pkg:npm/ms@2.1.3".to_string(),
        ];
        let partitioned = partition_purls(&purls, None);
        let out =
            find_packages_for_purls(&partitioned, &local_options(tmp.path().to_path_buf()), true)
                .await;
        #[cfg(unix)]
        assert_eq!(out.get("pkg:npm/foo@1.0.0"), Some(&nm.join("foo")));
        #[cfg(not(unix))]
        assert_eq!(out.get("pkg:npm/foo@1.0.0"), Some(&direct));
        assert_eq!(out.get("pkg:npm/ms@2.1.3"), Some(&transitive));
    }

    /// Multi-copy at the dispatch layer: `find_all_packages_for_purls`
    /// must carry EVERY physical copy of a duplicated npm PURL (a root copy
    /// plus a nested duplicate), root-copy-first. `apply` iterates this to
    /// patch both copies.
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

        // The collapsing wrapper (test-only; pins the one-representative
        // contract) keeps exactly the root-preferred copy.
        let single =
            find_packages_for_purls(&partitioned, &local_options(tmp.path().to_path_buf()), true)
                .await;
        assert_eq!(single.get("pkg:npm/dup@1.0.0"), Some(&root_copy));
    }

    /// Multi-copy for gem (mirrors the npm test above): bundler's scoped
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

        // The collapsing wrapper (test-only; pins the one-representative
        // contract) keeps the first store's copy.
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
        // Non-variant ecosystems keep their own crawler-keyed merge (npm:
        // `merge_npm_copies`) even on the rollback path, so a qualified npm PURL must round-trip under its exact key
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
        // installed gem "not installed" (spurious `vendor_fetched_missing`
        // events and a gem platform coin-flip).
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

        // A base-keyed collapse keys by the BASE PURL only, so a
        // `contains_key` on the qualified PURL misses — the exact false
        // "not installed" the retired resolver produced.
        let base_keyed = find_packages_for_purls(&partitioned, &options, true).await;
        assert!(
            !base_keyed.contains_key(&qualified),
            "a base-keyed lookup must NOT serve vendor: it keys by the base \
             PURL, so the qualified lookup falsely misses"
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
    // Every ecosystem is crawled unconditionally in every flow. The observable
    // pin is the per-ecosystem `counts` map — a crawled-but-empty ecosystem
    // gets a `0` entry, so presence proves the crawler ran without needing
    // a real Maven repo / NuGet cache fixture.

    /// Every ecosystem must appear in `counts` unconditionally — guards
    /// against one being accidentally moved behind a runtime gate (the
    /// regression this test replaces: maven/nuget were env-gated).
    #[tokio::test]
    async fn crawl_all_includes_every_ecosystem_unconditionally() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, counts, _) = crawl_all_ecosystems(&local_options(tmp.path().to_path_buf())).await;
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

    /// The vendor engine's reuse of scan's npm crawl is an oracle-equal
    /// substitute: over one tree (a hoisted dep, a nested duplicate, an
    /// alias install, a workspace member's own `node_modules`), the
    /// snapshot's roots and packages equal what the engine's own discovery
    /// and identity crawl find, and both lookups built on it answer
    /// exactly as the crawling ones do. A snapshot taken with other
    /// options is never used.
    #[tokio::test]
    async fn npm_crawl_snapshot_matches_the_crawls_it_replaces() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let write = |dir: &std::path::Path, name: &str, version: &str| {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(
                dir.join("package.json"),
                format!(r#"{{"name":"{name}","version":"{version}"}}"#),
            )
            .unwrap();
        };
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"root","version":"1.0.0","workspaces":["packages/*"]}"#,
        )
        .unwrap();
        write(&root.join("node_modules/foo"), "foo", "1.0.0");
        write(&root.join("node_modules/bar"), "bar", "2.0.0");
        write(
            &root.join("node_modules/bar/node_modules/foo"),
            "foo",
            "0.9.0",
        );
        write(&root.join("node_modules/@s/qux"), "@s/qux", "4.0.0");
        // `"lp": "npm:left-pad@1.3.0"` installs under the alias key.
        write(&root.join("node_modules/lp"), "left-pad", "1.3.0");
        write(&root.join("packages/app"), "app", "0.1.0");
        write(&root.join("packages/app/node_modules/baz"), "baz", "3.0.0");
        write(&root.join("packages/app/node_modules/foo"), "foo", "0.9.0");
        let options = local_options(root.to_path_buf());

        let (packages, counts, _, snapshot) = crawl_all_ecosystems_with_npm(&options).await;
        let npm_count = counts[&Ecosystem::Npm];
        let pairs = |pkgs: &[CrawledPackage]| -> Vec<(String, PathBuf)> {
            pkgs.iter()
                .map(|p| (p.purl.clone(), p.path.clone()))
                .collect()
        };
        assert_eq!(
            snapshot.roots,
            NpmCrawler.get_node_modules_paths(&options).await.unwrap()
        );
        assert_eq!(
            pairs(snapshot.packages_for(&options).unwrap()),
            pairs(&NpmCrawler.crawl_all(&options).await)
        );
        assert_eq!(pairs(&snapshot.packages), pairs(&packages[..npm_count]));
        assert!(snapshot.roots.len() >= 2, "roots={:?}", snapshot.roots);

        let purls: Vec<String> = [
            "pkg:npm/foo@1.0.0",
            "pkg:npm/foo@0.9.0",
            "pkg:npm/bar@2.0.0",
            "pkg:npm/baz@3.0.0",
            "pkg:npm/%40s/qux@4.0.0",
            "pkg:npm/left-pad@1.3.0",
            "pkg:npm/absent@9.9.9",
        ]
        .map(String::from)
        .to_vec();
        let partitioned = partition_purls(&purls, None);
        let crawled = find_packages_for_rollback(&partitioned, &options, true).await;
        let reused =
            find_packages_for_rollback_reusing(&partitioned, &options, true, Some(&snapshot)).await;
        assert_eq!(reused, crawled);
        assert!(crawled.contains_key("pkg:npm/baz@3.0.0"), "{crawled:?}");
        // The multi-copy twin keeps every copy, the member's nested one too.
        let all_crawled = find_all_packages_for_rollback(&partitioned, &options, true).await;
        let all_reused =
            find_all_packages_for_rollback_reusing(&partitioned, &options, true, Some(&snapshot))
                .await;
        assert_eq!(all_reused, all_crawled);
        assert!(
            all_crawled
                .get("pkg:npm/foo@0.9.0")
                .is_some_and(|paths| paths.len() == 2),
            "{all_crawled:?}"
        );
        // The resolver finds the alias install itself (#356).
        let left_pad = "pkg:npm/left-pad@1.3.0".to_string();
        assert_eq!(crawled.get(&left_pad), Some(&root.join("node_modules/lp")));

        let missing: Vec<&String> = purls.iter().filter(|p| !crawled.contains_key(*p)).collect();
        assert_eq!(missing, vec!["pkg:npm/absent@9.9.9"]);
        let lookup: Vec<&String> = missing.into_iter().chain([&left_pad]).collect();
        let by_crawl = npm_paths_by_identity(&options, &lookup).await;
        let by_snapshot =
            npm_paths_by_identity_in(snapshot.packages_for(&options).unwrap(), &lookup);
        assert_eq!(by_snapshot, by_crawl);
        assert_eq!(
            by_crawl.get("pkg:npm/left-pad@1.3.0"),
            Some(&vec![root.join("node_modules/lp")])
        );

        let elsewhere = local_options(root.join("packages/app"));
        assert!(snapshot.packages_for(&elsewhere).is_none());
        let app_purls = vec!["pkg:npm/foo@1.0.0".to_string()];
        let app_partitioned = partition_purls(&app_purls, None);
        assert_eq!(
            find_packages_for_rollback_reusing(&app_partitioned, &elsewhere, true, Some(&snapshot))
                .await,
            find_packages_for_rollback(&app_partitioned, &elsewhere, true).await,
            "a snapshot of another root must not answer for this one"
        );
        assert_eq!(
            find_all_packages_for_rollback_reusing(
                &app_partitioned,
                &elsewhere,
                true,
                Some(&snapshot)
            )
            .await,
            find_all_packages_for_rollback(&app_partitioned, &elsewhere, true).await,
            "a snapshot of another root must not answer for this one"
        );
    }

    /// Stage one installed package for EVERY ecosystem under `root`, the
    /// dir handed to all nine crawlers verbatim as `--global-prefix`. Each
    /// layout is the one that crawler's own global-prefix tests use, and
    /// they do not collide: a cargo crate dir has no `lib/` (so it is no
    /// gem), a gem dir has no `Cargo.toml`, a NuGet id dir carries its
    /// version as a child rather than a `-` suffix, and the jsr scope dir
    /// holds no package.json.
    fn stage_every_ecosystem(root: &std::path::Path) {
        let dir = |path: PathBuf| std::fs::create_dir_all(path).unwrap();
        let file = |path: PathBuf, body: String| {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        };

        // npm: <root>/<name>/package.json
        for (name, version) in [("zeta", "1.0.0"), ("alpha", "2.0.0"), ("mid", "3.0.0")] {
            file(
                root.join(name).join("package.json"),
                format!(r#"{{"name":"{name}","version":"{version}"}}"#),
            );
        }
        // pypi: <root>/<name>-<version>.dist-info/METADATA
        for (name, version) in [("requests", "2.31.0"), ("attrs", "23.1.0")] {
            file(
                root.join(format!("{name}-{version}.dist-info"))
                    .join("METADATA"),
                format!("Name: {name}\nVersion: {version}\n"),
            );
        }
        // cargo: <root>/<name>-<version>/Cargo.toml
        for (name, version) in [("serde", "1.0.0"), ("anyhow", "1.0.75")] {
            file(
                root.join(format!("{name}-{version}")).join("Cargo.toml"),
                format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n"),
            );
        }
        // gem: <root>/<name>-<version>/ verified by a .gemspec (a `lib/`
        // would also make NuGet's legacy `<Name>.<Version>` reading of the
        // same dir stick).
        file(
            root.join("rgem-2.0.0").join("rgem.gemspec"),
            "Gem::Specification.new\n".to_string(),
        );
        // golang: <root>/<host>/<path>@<version>/
        dir(root.join("example.com").join("gomod@v1.2.3"));
        // maven: <root>/<group path>/<artifact>/<version>/<artifact>-<version>.pom
        file(
            root.join("org")
                .join("example")
                .join("mlib")
                .join("4.0.0")
                .join("mlib-4.0.0.pom"),
            "<project><groupId>org.example</groupId>\
             <artifactId>mlib</artifactId><version>4.0.0</version></project>"
                .to_string(),
        );
        // composer: the prefix IS the vendor dir — its metadata plus the
        // install dir, which crawl_all requires to exist.
        dir(root.join("acme").join("phplib"));
        file(
            root.join("composer").join("installed.json"),
            serde_json::json!({"packages": [{"name": "acme/phplib", "version": "3.0.0"}]})
                .to_string(),
        );
        // nuget: <root>/<id>/<version>/ verified by a lib/
        dir(root.join("nugetlib").join("5.0.0").join("lib"));
        // deno (jsr): <root>/@<scope>/<name>/<version>/
        dir(root.join("@denoscope").join("jsrlib").join("6.0.0"));
    }

    /// A crawl scoped to some ecosystems runs only their crawlers — a
    /// skipped one leaves no `counts` entry, the pin that it never ran —
    /// and yields exactly the full crawl's packages of those ecosystems,
    /// in the full crawl's order, with the full crawl's counts. Scoped to
    /// every ecosystem (or `None`) it IS the full crawl. The npm snapshot
    /// exists exactly when npm was crawled.
    #[tokio::test(flavor = "multi_thread")]
    async fn scoped_crawl_is_the_full_crawl_filtered_to_its_ecosystems() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        stage_every_ecosystem(root);
        let options = CrawlerOptions {
            cwd: root.to_path_buf(),
            global: false,
            global_prefix: Some(root.to_path_buf()),
        };
        let key = |p: &CrawledPackage| (p.purl.clone(), p.path.clone());
        let (full, full_counts, _, full_snapshot) = crawl_all_ecosystems_with_npm(&options).await;
        assert_eq!(full_counts.len(), Ecosystem::all().len());

        let every: Vec<String> = Ecosystem::all()
            .iter()
            .map(|e| e.cli_name().to_string())
            .collect();
        let mut scopes: Vec<Vec<String>> = every.iter().map(|e| vec![e.clone()]).collect();
        scopes.push(vec!["maven".into(), "npm".into()]);
        scopes.push(vec!["pypi".into(), "deno".into(), "gem".into()]);
        scopes.push(every.clone());
        for scope in &scopes {
            let selected = |eco: &Ecosystem| scope.iter().any(|name| name == eco.cli_name());
            let (packages, counts, _, snapshot) =
                crawl_ecosystems_with_npm(&options, Some(scope)).await;
            let expected: Vec<_> = full
                .iter()
                .filter(|p| Ecosystem::from_purl(&p.purl).is_some_and(|e| selected(&e)))
                .map(key)
                .collect();
            assert_eq!(
                packages.iter().map(key).collect::<Vec<_>>(),
                expected,
                "{scope:?}"
            );
            let expected_counts: HashMap<Ecosystem, usize> = full_counts
                .iter()
                .filter(|(eco, _)| selected(eco))
                .map(|(eco, n)| (*eco, *n))
                .collect();
            assert_eq!(counts, expected_counts, "{scope:?}");
            assert_eq!(
                snapshot.is_some(),
                scope.iter().any(|name| name == "npm"),
                "{scope:?}"
            );
            if let Some(snapshot) = snapshot {
                assert_eq!(snapshot.roots, full_snapshot.roots, "{scope:?}");
                assert_eq!(
                    snapshot.packages.iter().map(key).collect::<Vec<_>>(),
                    full_snapshot.packages.iter().map(key).collect::<Vec<_>>(),
                    "{scope:?}"
                );
            }
        }

        let (unscoped, unscoped_counts, _) = crawl_ecosystems(&options, None).await;
        assert_eq!(
            unscoped.iter().map(key).collect::<Vec<_>>(),
            full.iter().map(key).collect::<Vec<_>>()
        );
        assert_eq!(unscoped_counts, full_counts);
    }

    /// The concurrent crawl must yield exactly the serial run's packages,
    /// in the fixed ecosystem order, with the same counts. A
    /// `--global-prefix` root is handed to every crawler verbatim, so one
    /// polyglot dir exercises every ecosystem at once — and it has to:
    /// an ecosystem that finds nothing contributes nothing to the
    /// concatenation, so its POSITION in the consumption array is
    /// unobservable and a reordering would ship silently. That order is
    /// shipped behavior: `scan` chunks the crawl-ordered purls into
    /// batches, so it decides batch composition, the `API batch N of M failed`
    /// warning text and order, and `last_batch_error`.
    #[tokio::test(flavor = "multi_thread")]
    async fn crawl_all_ecosystems_matches_serial_order() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        stage_every_ecosystem(root);
        let options = CrawlerOptions {
            cwd: root.to_path_buf(),
            global: false,
            global_prefix: Some(root.to_path_buf()),
        };

        let (packages, counts, _) = crawl_all_ecosystems(&options).await;

        let mut serial: Vec<CrawledPackage> = Vec::new();
        let mut serial_counts: HashMap<Ecosystem, usize> = HashMap::new();
        macro_rules! serial {
            ($eco:expr, $pkgs:expr) => {{
                let pkgs = $pkgs;
                serial_counts.insert($eco, pkgs.len());
                serial.extend(pkgs);
            }};
        }
        serial!(Ecosystem::Npm, NpmCrawler.crawl_all(&options).await);
        serial!(Ecosystem::Pypi, PythonCrawler.crawl_all(&options).await);
        serial!(Ecosystem::Cargo, CargoCrawler.crawl_all(&options).await);
        serial!(Ecosystem::Gem, RubyCrawler.crawl_all(&options).await);
        serial!(Ecosystem::Golang, GoCrawler.crawl_all(&options).await);
        serial!(Ecosystem::Maven, MavenCrawler.crawl_all(&options).await);
        serial!(
            Ecosystem::Composer,
            ComposerCrawler.crawl_all(&options).await
        );
        serial!(Ecosystem::Nuget, NuGetCrawler.crawl_all(&options).await);
        serial!(Ecosystem::Deno, DenoCrawler.crawl_all(&options).await);

        let key = |p: &CrawledPackage| (p.purl.clone(), p.path.clone());
        assert_eq!(
            packages.iter().map(key).collect::<Vec<_>>(),
            serial.iter().map(key).collect::<Vec<_>>()
        );
        assert_eq!(counts, serial_counts);
        // Non-vacuous for EVERY ecosystem, or the ones that found nothing
        // are pinned only by this test's own copy of the order.
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
                counts.get(&eco).is_some_and(|&n| n >= 1),
                "{eco:?} found nothing — its position is unobservable: {counts:?}"
            );
        }
        assert!(counts[&Ecosystem::Npm] >= 3, "{counts:?}");
        assert!(counts[&Ecosystem::Pypi] >= 2, "{counts:?}");
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
    /// on global/global-prefix runs (`apply --global` shows it). Drive it
    /// for all eight labeled ecosystems
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

    /// The PURL-lookup path (`find_all_packages_for_purls`, the dispatch
    /// behind every resolver) must resolve a maven package from a local
    /// repository with no env opt-in of any kind.
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
