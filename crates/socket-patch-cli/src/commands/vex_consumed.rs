//! Which installed copies a HOSTED-basis purl's build actually consumes.
//!
//! `vex` verifies a dependency wired to Socket's patch server against its
//! installed tree when one exists ("installed evidence wins") and otherwise,
//! for a pinned discovered reference, attests from the lockfile wiring. Both
//! halves hinge on WHICH installed copy is the evidence, and the crawler's
//! generic "first copy of `name@version`" answer is wrong in both
//! directions for hosted wiring:
//!
//! * where the package manager stores the hosted artifact APART from the
//!   registry's copy of the same `name@version`, the registry copy (cached
//!   before the redirect, or pulled by another project) is a pristine
//!   SIBLING the build never reads — hashing it reports a patched project
//!   unpatched and skips an attestation the pinned wiring earned;
//! * where hosted and registry bytes share one install location, a pristine
//!   copy there IS what runs — and when the crawler finds several copies,
//!   hashing only the first can attest a tree another consumer bypasses.
//!
//! So each hosted purl gets a [`HostedCopies`] resolved per package manager:
//!
//! | ecosystem | copies the hosted build consumes | never evidence |
//! |---|---|---|
//! | golang | the REPLACEMENT module `$GOMODCACHE/patch.socket.dev/gopatch/<uuid>@<sver>` (the ref's `url`, else go.mod's hosted `replace`) | the original `M@v` |
//! | cargo | `registry/src/<host>-<hash>/<name>-<version>` for the lock source's host; several such registries (one per patch uuid) are narrowed to the one whose cached `.crate` has the lock's pinned checksum. A `vendor/` source tree or `--global-prefix` is taken as given | crates.io's / any other registry's extraction |
//! | maven | `<repo>/<g>/<a>/<base>-socket.<hex8>/` (the version the pom or the hosted Gradle wiring pins) in `~/.m2` and every Gradle `files-2.1` holding it (hash dirs expanded), its artifact files matched under the suffixed name | the `<base>` version dir |
//! | npm | every `node_modules` copy the crawler finds (pnpm and vlt store copies included), every peer / modifier / registry variant of those in the same `.pnpm` / `.vlt` store, alias installs (`node_modules/<alias>` holding the package) in the root's and every workspace member's tree included | — each serves some dependent: ALL must verify |
//! | pypi | every copy in the crawler's environment set (the project's venvs when it has any, else the interpreters) | — any may be the one that runs the project: ALL must verify |
//! | gem | every copy in bundler's gem path; under an explicit or deployment `path` the `gem env` homes hold only default gems bundler loads (#1098) | a non-default gem's `gem env` copy when bundler doesn't use system gems; otherwise bundler loads whichever `Gem.path` home it hits first: ALL must verify |
//!
//! composer and nuget have ONE install location shared by every source
//! (`vendor/`, the global packages folder — which restore reuses whatever
//! source a same-version copy came from), so the crawler's copy is the
//! consumed one; they keep the default path and get no entry here.
//!
//! An EMPTY copy list means "not installed": the purl is
//! `package_not_found`, which the lockfile basis excuses for a pinned
//! discovered ref (and nothing else does). A purl outside `--ecosystems`
//! gets no entry at all — it stays uninspected, exactly like the crawl.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

#[cfg(not(test))]
use socket_patch_core::crawlers::npm_crawler::with_store_peer_variant_copies;
use socket_patch_core::crawlers::{
    CargoCrawler, CrawlerOptions, Ecosystem, GoCrawler, MavenCrawler,
};
use socket_patch_core::utils::purl::purl_parts;
use socket_patch_core::vendor::go_mod_edit::{
    read_replace_entries, ReplaceOwner, HOSTED_GO_MODULE_PREFIX,
};
use socket_patch_core::vendor::lock_inventory::LockIntegrity;
use socket_patch_core::vex::HostedCopies;
#[cfg(test)]
use tests::recording_store_variants as with_store_peer_variant_copies;

use crate::args::GlobalArgs;
use crate::commands::vex_sources::HostedWiring;
use crate::ecosystem_dispatch::{
    npm_paths_by_identity, npm_paths_by_identity_in, partition_purls, NpmCrawlSnapshot,
};

/// Resolve [`HostedCopies`] for every hosted-basis purl of `hosted` (see the
/// module docs), under the same crawler options and `--ecosystems` scope as
/// the installed-tree lookup. `installed` is that lookup's every-copy
/// result ([`crate::ecosystem_dispatch::find_manifest_package_copies_reusing`] over
/// the record view, which holds every hosted purl), including npm store
/// variants. The shared-location ecosystems read it instead of crawling
/// the tree a second time. `prior`
/// (embedded hosted `scan --vex` only) is scan's npm crawl of the same
/// tree: the identity fallback takes its packages instead of crawling the
/// tree again.
pub(crate) async fn hosted_consumed_copies(
    common: &GlobalArgs,
    hosted: &BTreeMap<String, HostedWiring>,
    installed: &HashMap<String, Vec<PathBuf>>,
    prior: Option<&NpmCrawlSnapshot>,
) -> HashMap<String, HostedCopies> {
    let mut out = HashMap::new();
    if hosted.is_empty() {
        return out;
    }
    let options = common.crawler_options();
    let purls: Vec<String> = hosted.keys().cloned().collect();
    let partitioned = partition_purls(&purls, common.ecosystems.as_deref());

    // Shared-location ecosystems: every physical copy is consumed by someone.
    let shared: HashMap<Ecosystem, Vec<String>> = partitioned
        .iter()
        .filter(|(eco, _)| matches!(eco, Ecosystem::Npm | Ecosystem::Pypi | Ecosystem::Gem))
        .map(|(eco, purls)| (*eco, purls.clone()))
        .collect();
    if !shared.is_empty() {
        let mut all: HashMap<String, Vec<PathBuf>> = shared
            .values()
            .flatten()
            .filter_map(|purl| Some((purl.clone(), installed.get(purl)?.clone())))
            .collect();
        npm_identity_fallback_reusing(shared.get(&Ecosystem::Npm), &options, &mut all, prior).await;
        let npm: Vec<&String> = shared.get(&Ecosystem::Npm).into_iter().flatten().collect();
        for purl in shared.values().flatten() {
            let mut paths = all.remove(purl).unwrap_or_default();
            // The installed lookup already resolved every copy, importer
            // tree aliases included, and expanded their store variants.
            // Without installed copies the identity fallback's have not
            // had their store variants enumerated yet.
            if npm.contains(&purl) && installed.get(purl).is_none_or(Vec::is_empty) {
                paths = with_store_peer_variant_copies(paths).await;
            }
            out.insert(
                purl.clone(),
                HostedCopies {
                    paths,
                    rename: None,
                },
            );
        }
        // An orphaned Bun store entry is no consumed copy (#599); the
        // installed lookup dropped its own, this drops the ones the alias
        // and identity fallbacks' variant expansion added.
        socket_patch_core::crawlers::npm_crawler::retain_live_store_copies(
            out.iter_mut()
                .filter(|(purl, _)| npm.contains(purl))
                .map(|(_, copies)| &mut copies.paths),
        )
        .await;
    }

    // Distinct-store ecosystems: only the hosted artifact's own store entry.
    for (eco, purls) in &partitioned {
        for purl in purls {
            let wiring = &hosted[purl];
            let copies = match eco {
                Ecosystem::Golang => golang_copies(&options, purl, wiring).await,
                Ecosystem::Cargo => cargo_copies(&options, purl, wiring).await,
                Ecosystem::Maven => maven_copies(&options, purl, wiring).await,
                _ => continue,
            };
            out.insert(purl.clone(), copies);
        }
    }
    out
}

fn not_installed() -> HostedCopies {
    HostedCopies::default()
}

// ── npm identity fallback ────────────────────────────────────────────────

/// Last-resort identity lookup for an npm purl the targeted resolver did
/// not find. The resolver takes real alias dirs (`node_modules/lp` holding
/// `left-pad@1.3.0`) as copies, but not an alias reached through a symlinked
/// importer entry (yarn's pnpm linker, `npm link`, a global
/// `--global-prefix` tree). For a hosted purl "not installed" is exactly what
/// the lockfile basis excuses, so such a copy must still be hash-verified
/// ("installed evidence wins"). Resolve every npm purl the targeted lookup
/// missed by the installed `package.json` identity instead — the same
/// fallback `vendor` uses before declaring a package missing.
#[cfg(test)]
async fn npm_identity_fallback(
    npm: Option<&Vec<String>>,
    options: &CrawlerOptions,
    all: &mut HashMap<String, Vec<PathBuf>>,
) {
    npm_identity_fallback_reusing(npm, options, all, None).await
}

/// [`npm_identity_fallback`], answering from `prior`'s crawled packages
/// when it was crawled with `options` (the whole `NpmCrawler::crawl_all`
/// output for them) instead of crawling again.
async fn npm_identity_fallback_reusing(
    npm: Option<&Vec<String>>,
    options: &CrawlerOptions,
    all: &mut HashMap<String, Vec<PathBuf>>,
    prior: Option<&NpmCrawlSnapshot>,
) {
    let missing: Vec<&String> = npm
        .into_iter()
        .flatten()
        .filter(|purl| all.get(*purl).is_none_or(Vec::is_empty))
        .collect();
    match prior.and_then(|p| p.packages_for(options)) {
        Some(installed) => all.extend(npm_paths_by_identity_in(installed, &missing)),
        None => all.extend(npm_paths_by_identity(options, &missing).await),
    }
}

// ── golang ───────────────────────────────────────────────────────────────

/// Under `replace M v => patch.socket.dev/gopatch/<uuid> <sver>` the build
/// fetches and compiles the REPLACEMENT module; the module cache's `M@v` (if
/// any) is pristine by construction and never read. The served module keeps
/// the original module's layout (only the zip prefix uses the socket path),
/// so the patch record's files are verified inside the replacement's dir.
async fn golang_copies(
    options: &CrawlerOptions,
    purl: &str,
    wiring: &HostedWiring,
) -> HostedCopies {
    let Some((_, module, version)) = purl_parts(purl) else {
        return not_installed();
    };
    let Some((rhs_module, rhs_version)) =
        golang_replacement(options, &module, &version, wiring).await
    else {
        return not_installed();
    };
    let target = format!("pkg:golang/{rhs_module}@{rhs_version}");
    let crawler = GoCrawler::new();
    for cache in crawler
        .get_module_cache_paths(options)
        .await
        .unwrap_or_default()
    {
        let found = crawler
            .find_by_purls(&cache, std::slice::from_ref(&target))
            .await
            .unwrap_or_default();
        if let Some(pkg) = found.get(&target) {
            return HostedCopies {
                paths: vec![pkg.path.clone()],
                rename: None,
            };
        }
    }
    not_installed()
}

/// The replacement `(module, version)` the hosted wiring routes `M@v` to:
/// a discovered ref's `url` (`<rhs module>@<rhs version>`), else the root
/// go.mod's hosted `replace` for `M v` (a ledger-only record). The module
/// must be THIS patch's socket module — a replace naming another patch is
/// not this wiring.
async fn golang_replacement(
    options: &CrawlerOptions,
    module: &str,
    version: &str,
    wiring: &HostedWiring,
) -> Option<(String, String)> {
    let ours = |rhs: &str| {
        rhs.strip_prefix(HOSTED_GO_MODULE_PREFIX)
            .is_some_and(|rest| {
                rest == wiring.uuid || rest.starts_with(&format!("{}/", wiring.uuid))
            })
    };
    let from_ref = wiring.refs.iter().find_map(|r| {
        let (rhs, sver) = r.url.as_deref()?.rsplit_once('@')?;
        ours(rhs).then(|| (rhs.to_string(), sver.to_string()))
    });
    if from_ref.is_some() {
        return from_ref;
    }
    read_replace_entries(&options.cwd)
        .await
        .into_iter()
        .filter(|e| e.owner == Some(ReplaceOwner::Hosted) && e.module == module)
        .filter(|e| e.version.as_deref().is_none_or(|v| v == version))
        .find_map(|e| {
            let rhs = e.rhs_module?;
            ours(&rhs).then_some((rhs, e.rhs_version?))
        })
}

// ── cargo ────────────────────────────────────────────────────────────────

/// Cargo extracts every registry's crates into its OWN
/// `registry/src/<host>-<hash>/` dir, and a locked package builds from the
/// dir of the registry its `Cargo.lock` source names — so for a hosted pin
/// only copies under the Socket registry host count; crates.io's
/// (`index.crates.io-*`) copy of the same `name-version` is a pristine
/// sibling. Each patch uuid is its own registry (its index url carries the
/// uuid), so several same-host dirs can hold the crate (a superseded patch
/// built on this machine): the one whose cached `.crate` hashes to the
/// lock's pinned checksum is the consumed copy; when none can be singled out
/// every same-host copy must verify (fail closed). A `vendor/` source tree
/// (`cargo vendor`) or an explicit `--global-prefix` is what the build or
/// the operator points at, and is taken as given.
async fn cargo_copies(options: &CrawlerOptions, purl: &str, wiring: &HostedWiring) -> HostedCopies {
    let Some((_, name, version)) = purl_parts(purl) else {
        return not_installed();
    };
    let base = format!("pkg:cargo/{name}@{version}");
    let pinned = wiring.refs.iter().find_map(|r| match &r.locked_integrity {
        Some(LockIntegrity::Sha256Hex(sum)) => Some(sum.to_ascii_lowercase()),
        _ => None,
    });
    let source = match wiring.refs.iter().find_map(|r| r.url.clone()) {
        Some(url) => Some(url),
        None => match socket_patch_core::vendor::cargo_lock::probe_lock_entry(
            &options.cwd,
            &name,
            &version,
        )
        .await
        {
            socket_patch_core::vendor::cargo_lock::LockEntryProbe::Source(source) => Some(source),
            _ => None,
        },
    };
    let Some(host) = source.as_deref().and_then(registry_host) else {
        return not_installed();
    };
    let crawler = CargoCrawler::new();
    let mut copies: Vec<(PathBuf, PathBuf)> = Vec::new();
    for src in crawler
        .get_crate_source_paths(options)
        .await
        .unwrap_or_default()
    {
        if registry_src_dir_name(&src).is_some_and(|dir| !is_registry_dir_for_host(dir, &host)) {
            continue;
        }
        let found = crawler
            .find_by_purls(&src, std::slice::from_ref(&base))
            .await
            .unwrap_or_default();
        if let Some(pkg) = found.get(&base) {
            copies.push((src, pkg.path.clone()));
        }
    }
    if let (true, Some(sum)) = (copies.len() > 1, pinned) {
        let mut exact = Vec::new();
        for (src, path) in &copies {
            let Some(cache) = cached_crate(src, &name, &version) else {
                continue;
            };
            if socket_patch_core::vendor::file_sha256_hex(&cache)
                .await
                .as_deref()
                == Some(&sum)
            {
                exact.push((src.clone(), path.clone()));
            }
        }
        if !exact.is_empty() {
            copies = exact;
        }
    }
    HostedCopies {
        paths: copies.into_iter().map(|(_, path)| path).collect(),
        rename: None,
    }
}

/// The host of a `Cargo.lock` registry source (`sparse+https://host/…`,
/// `registry+https://host/…`), lowercased — the `host_str` cargo names the
/// registry's src dir after (userinfo and port dropped; an IPv6 literal
/// keeps its brackets).
fn registry_host(source: &str) -> Option<String> {
    let source = source.trim();
    let url = source
        .strip_prefix("sparse+")
        .or_else(|| source.strip_prefix("registry+"))?;
    if !url.contains("://") {
        return None;
    }
    socket_patch_core::utils::redact::url_hostname(url).map(str::to_ascii_lowercase)
}

/// The `<host>-<hash>` name of a `…/registry/src/<host>-<hash>` source dir,
/// `None` for any other source root (`vendor/`, a `--global-prefix`).
fn registry_src_dir_name(src: &Path) -> Option<&str> {
    let parent = src.parent()?;
    let is_registry_src = parent.file_name().is_some_and(|n| n == "src")
        && parent
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|n| n == "registry");
    is_registry_src.then(|| src.file_name()?.to_str()).flatten()
}

/// Whether registry dir `name` is cargo's `<host>-<16 hex>` for `host`.
fn is_registry_dir_for_host(name: &str, host: &str) -> bool {
    name.strip_prefix(host)
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|hash| {
            hash.len() == 16
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// `registry/cache/<same dir>/<name>-<version>.crate` beside a registry src
/// dir — the downloaded archive the extraction came from.
fn cached_crate(src: &Path, name: &str, version: &str) -> Option<PathBuf> {
    let dir = registry_src_dir_name(src)?;
    let registry = src.parent()?.parent()?;
    Some(
        registry
            .join("cache")
            .join(dir)
            .join(format!("{name}-{version}.crate")),
    )
}

// ── maven ────────────────────────────────────────────────────────────────

/// The fail-closed hosted pom pins `<base>-socket.<first 8 hex of the patch
/// uuid>`, a version only the Socket repository serves: maven resolves
/// `~/.m2/…/<a>/<suffixed>/`, never the `<base>` dir (whose copy predates
/// the redirect or belongs to another project), and the hosted Gradle
/// wiring pins the same version into `files-2.1/<g>/<a>/<suffixed>/`. Every
/// cache holding the suffixed version (`get_maven_copy_paths`: `~/.m2`,
/// then each Gradle cache, the read-only one included) is a consumed copy;
/// a Gradle version dir is expanded into its hash dirs at verify time
/// (`installed_copies`). The served files carry the suffixed version in
/// their names, so the record's `<a>-<base>…` files are matched as
/// `<a>-<suffixed>…` — a member-keyed record checks the jar of that name.
async fn maven_copies(options: &CrawlerOptions, purl: &str, wiring: &HostedWiring) -> HostedCopies {
    let Some((_, name, version)) = purl_parts(purl) else {
        return not_installed();
    };
    let Some((group, artifact)) = name.split_once('/') else {
        return not_installed();
    };
    let Some(hex8) = wiring.uuid.get(..8) else {
        return not_installed();
    };
    let suffixed = format!("{version}-socket.{hex8}");
    let target = format!("pkg:maven/{group}/{artifact}@{suffixed}");
    let crawler = MavenCrawler::new();
    let mut paths = Vec::new();
    // A hosted sbt build resolves the pin from its own download dir first.
    let sbt_hosted = socket_patch_core::hosted::sbt_reads::hosted_repo_dirs(&options.cwd);
    for repo in sbt_hosted.into_iter().chain(
        crawler
            .get_maven_copy_paths(options)
            .await
            .unwrap_or_default(),
    ) {
        let found = crawler
            .find_by_purls(&repo, std::slice::from_ref(&target))
            .await
            .unwrap_or_default();
        if let Some(pkg) = found.get(&target) {
            if !paths.contains(&pkg.path) {
                paths.push(pkg.path.clone());
            }
        }
    }
    if paths.is_empty() {
        return not_installed();
    }
    HostedCopies {
        paths,
        rename: Some((
            format!("{artifact}-{version}"),
            format!("{artifact}-{suffixed}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::crawlers::NpmCrawler;

    tokio::task_local! {
        // Observe real expansion work only in the regression's own task;
        // concurrent tests keep calling the production helper normally.
        static VARIANT_INPUTS: std::cell::RefCell<Vec<Vec<PathBuf>>>;
    }

    pub(super) async fn recording_store_variants(paths: Vec<PathBuf>) -> Vec<PathBuf> {
        let _ = VARIANT_INPUTS.try_with(|calls| calls.borrow_mut().push(paths.clone()));
        socket_patch_core::crawlers::npm_crawler::with_store_peer_variant_copies(paths).await
    }

    #[cfg(unix)]
    async fn tracked_npm_hosted(
        common: &GlobalArgs,
        installed: &HashMap<String, Vec<PathBuf>>,
    ) -> (Vec<PathBuf>, Vec<Vec<PathBuf>>) {
        let purl = "pkg:npm/left-pad@1.3.0".to_string();
        let hosted = BTreeMap::from([(
            purl.clone(),
            HostedWiring {
                uuid: "11111111-1111-4111-8111-111111111111".to_string(),
                refs: Vec::new(),
            },
        )]);
        VARIANT_INPUTS
            .scope(std::cell::RefCell::new(Vec::new()), async {
                let mut found = hosted_consumed_copies(common, &hosted, installed, None).await;
                let paths = found.remove(&purl).unwrap().paths;
                let calls = VARIANT_INPUTS.with(|inputs| inputs.borrow().clone());
                (paths, calls)
            })
            .await
    }

    /// The installed-tree lookup `vex` hands [`hosted_consumed_copies`].
    async fn installed_copies(common: &GlobalArgs, purl: &str) -> HashMap<String, Vec<PathBuf>> {
        crate::ecosystem_dispatch::find_manifest_package_copies_reusing(
            &[purl.to_string()],
            common,
            true,
            None,
        )
        .await
    }

    #[cfg(unix)]
    fn peer_copies(store: &Path, count: usize) -> Vec<PathBuf> {
        (0..count)
            .map(|i| {
                let path = store.join(format!(
                    "left-pad@1.3.0(peer@1.0.{i})/node_modules/left-pad"
                ));
                pkg(&path, "left-pad", "1.3.0");
                path
            })
            .collect()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hosted_reuses_expanded_npm_copies_and_merges_alias_variants() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().canonicalize().unwrap().join("node_modules");
        let peers = peer_copies(&nm.join(".pnpm"), 8);
        std::os::unix::fs::symlink(&peers[0], nm.join("left-pad")).unwrap();
        let common = GlobalArgs {
            cwd: tmp.path().canonicalize().unwrap(),
            ecosystems: Some(vec!["npm".to_string()]),
            ..GlobalArgs::default()
        };
        let purl = "pkg:npm/left-pad@1.3.0".to_string();
        let installed = installed_copies(&common, &purl).await;
        assert_eq!(installed[&purl].len(), peers.len());
        let (paths, calls) = tracked_npm_hosted(&common, &installed).await;
        assert_eq!(paths, installed[&purl]);
        assert!(
            calls.is_empty(),
            "already-expanded copies were rescanned: {calls:?}"
        );

        // The resolver takes a real alias as a copy and expands its store
        // variants, which overlap the set canonically (the importer link's
        // physical copy included): the alias is listed once, the importer
        // link stays first, and nothing is expanded again.
        let alias = nm.join("lp");
        pkg(&alias, "left-pad", "1.3.0");
        let with_alias = installed_copies(&common, &purl).await;
        let (paths, calls) = tracked_npm_hosted(&common, &with_alias).await;
        assert!(calls.is_empty(), "{calls:?}");
        assert_eq!(paths, with_alias[&purl]);
        assert_eq!(paths[0], installed[&purl][0]);
        let mut expected = installed[&purl].clone();
        expected.push(alias);
        expected.sort();
        assert_eq!(sorted(paths), expected);

        // An alias beneath a real nested host can reach another store. The
        // installed root copy does not keep the resolver from that store's
        // peers.
        let host = nm.join("host");
        pkg(&host, "host", "1.0.0");
        let host_nm = host.join("node_modules");
        let nested_peers = peer_copies(&host_nm.join(".pnpm"), 2);
        let nested_alias = host_nm.join("lp");
        pkg(&nested_alias, "left-pad", "1.3.0");
        let installed_again = installed_copies(&common, &purl).await;
        let (paths, calls) = tracked_npm_hosted(&common, &installed_again).await;
        assert!(calls.is_empty(), "{calls:?}");
        assert_eq!(paths, installed_again[&purl]);
        assert_eq!(paths[0], installed[&purl][0]);
        expected.push(nested_alias);
        expected.extend(nested_peers);
        let mut actual = paths.clone();
        actual.sort();
        expected.sort();
        assert_eq!(actual, expected, "the resolver's own copy set");
        assert_eq!(
            paths
                .iter()
                .map(|path| path.canonicalize().unwrap())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            paths.len()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hosted_expands_alias_only_copies() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp
            .path()
            .canonicalize()
            .unwrap()
            .join("node_modules/.pnpm");
        let peers = peer_copies(&store, 2);
        // Run within a store package whose nested dependency is an alias.
        // The sibling peer copies are outside its project-root search.
        let root = store.join("host@1.0.0/node_modules/host");
        let alias = root.join("node_modules/lp");
        pkg(&alias, "left-pad", "1.3.0");
        let common = GlobalArgs {
            cwd: root,
            ecosystems: Some(vec!["npm".to_string()]),
            ..GlobalArgs::default()
        };
        let purl = "pkg:npm/left-pad@1.3.0".to_string();
        let installed = installed_copies(&common, &purl).await;
        // The resolver reaches the alias and its sibling peers on its own.
        // With no installed set, the identity fallback's alias copy must
        // still expand to the same copies.
        let (mut paths, calls) = tracked_npm_hosted(&common, &HashMap::new()).await;
        assert_eq!(calls, vec![vec![alias.clone()]]);
        let mut expected = peers;
        expected.push(alias);
        paths.sort();
        expected.sort();
        assert_eq!(paths, expected);
        let (mut resolved, _) = tracked_npm_hosted(&common, &installed).await;
        resolved.sort();
        assert_eq!(resolved, expected, "the resolver's own copy set");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hosted_expands_identity_fallback_with_empty_installed_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let peers = peer_copies(
            &tmp.path()
                .canonicalize()
                .unwrap()
                .join("external/node_modules/.pnpm"),
            2,
        );
        let root = tmp.path().canonicalize().unwrap().join("project");
        let alias = root.join("node_modules/lp");
        std::fs::create_dir_all(alias.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&peers[0], &alias).unwrap();
        let common = GlobalArgs {
            cwd: root,
            ecosystems: Some(vec!["npm".to_string()]),
            ..GlobalArgs::default()
        };
        let purl = "pkg:npm/left-pad@1.3.0".to_string();
        // The resolver never takes a link as a copy.
        assert!(installed_copies(&common, &purl)
            .await
            .get(&purl)
            .is_none_or(Vec::is_empty));
        let installed = HashMap::from([(purl, Vec::new())]);
        let (mut paths, calls) = tracked_npm_hosted(&common, &installed).await;
        assert_eq!(calls, vec![vec![alias.clone()]]);
        let mut expected = vec![alias, peers[1].clone()];
        paths.sort();
        expected.sort();
        assert_eq!(paths, expected);
    }

    fn pkg(dir: &Path, name: &str, version: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            format!(r#"{{"name":"{name}","version":"{version}"}}"#),
        )
        .unwrap();
    }

    fn write_pkg(root: &Path, dir: &str, name: &str, version: &str) {
        pkg(&root.join(dir), name, version);
    }

    fn local(root: &Path) -> CrawlerOptions {
        CrawlerOptions {
            cwd: root.to_path_buf(),
            global: false,
            global_prefix: None,
        }
    }

    /// An npm alias install (`node_modules/lp` holding left-pad@1.3.0) is a
    /// consumed copy of the hosted purl, though the targeted lookup probes
    /// only `node_modules/left-pad`.
    #[tokio::test]
    async fn npm_identity_fallback_fills_only_misses() {
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(tmp.path(), "node_modules/lp", "left-pad", "1.3.0");
        write_pkg(tmp.path(), "node_modules/other", "other", "1.0.0");
        let options = CrawlerOptions {
            cwd: tmp.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        let purls = vec![
            "pkg:npm/left-pad@1.3.0".to_string(),
            "pkg:npm/absent@2.0.0".to_string(),
        ];
        let mut all: HashMap<String, Vec<PathBuf>> = HashMap::new();
        npm_identity_fallback(Some(&purls), &options, &mut all).await;
        assert_eq!(
            all.get("pkg:npm/left-pad@1.3.0"),
            Some(&vec![tmp.path().join("node_modules/lp")])
        );
        assert!(!all.contains_key("pkg:npm/absent@2.0.0"), "{all:?}");

        // A copy the targeted lookup already found is kept as-is (the alias
        // fallback only fills misses).
        let found = tmp.path().join("node_modules/left-pad");
        let mut all = HashMap::from([(purls[0].clone(), vec![found.clone()])]);
        npm_identity_fallback(Some(&purls), &options, &mut all).await;
        assert_eq!(all[&purls[0]], vec![found.clone()]);
    }

    /// The identity fallback answered from the crawl snapshot finds the
    /// same copies as crawling again — here an alias installed through a
    /// symlink (yarn's pnpm linker, `npm link`), which the targeted lookup
    /// does not take as a copy (it skips symlinks), among other
    /// crawled packages so it is not the snapshot's first entry.
    #[cfg(unix)]
    #[tokio::test]
    async fn npm_identity_fallback_from_the_snapshot_matches_the_crawl() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_pkg(root, "node_modules/aaa", "aaa", "1.0.0");
        write_pkg(root, "node_modules/left-pad", "left-pad", "1.2.0");
        write_pkg(root, "node_modules/zzz", "zzz", "1.0.0");
        // Two such packages, so an answer drawn from only part of the
        // snapshot (whatever its directory order) cannot match.
        for (store, link, name) in [
            ("store/a", "node_modules/lp", "left-pad"),
            ("store/b", "node_modules/odd", "is-odd"),
        ] {
            write_pkg(root, store, name, "1.3.0");
            std::os::unix::fs::symlink(root.join(store), root.join(link)).unwrap();
        }
        let options = local(root);
        let purls = vec![
            "pkg:npm/left-pad@1.3.0".to_string(),
            "pkg:npm/is-odd@1.3.0".to_string(),
            "pkg:npm/absent@2.0.0".to_string(),
        ];
        let resolved = installed_copies(
            &GlobalArgs {
                cwd: root.to_path_buf(),
                ecosystems: Some(vec!["npm".to_string()]),
                ..GlobalArgs::default()
            },
            &purls[0],
        )
        .await;
        assert!(
            resolved.get(&purls[0]).is_none_or(Vec::is_empty),
            "the resolver skips symlinks: {resolved:?}"
        );

        let (_, _, _, snapshot) =
            crate::ecosystem_dispatch::crawl_ecosystems_with_npm(&options, None).await;
        let snapshot = snapshot.expect("npm crawled");
        assert!(
            snapshot.packages_for(&options).is_some_and(|p| p.len() > 1),
            "several crawled packages"
        );

        let mut walked: HashMap<String, Vec<PathBuf>> = HashMap::new();
        npm_identity_fallback(Some(&purls), &options, &mut walked).await;
        let mut reused: HashMap<String, Vec<PathBuf>> = HashMap::new();
        npm_identity_fallback_reusing(Some(&purls), &options, &mut reused, Some(&snapshot)).await;
        assert_eq!(reused, walked);
        for purl in &purls[..2] {
            assert_eq!(
                reused.get(purl).map(Vec::len),
                Some(1),
                "{purl}: {reused:?}"
            );
        }
        assert!(!reused.contains_key("pkg:npm/absent@2.0.0"), "{reused:?}");
    }

    fn npm_scope(root: &Path) -> GlobalArgs {
        GlobalArgs {
            cwd: root.to_path_buf(),
            ecosystems: Some(vec!["npm".to_string()]),
            ..GlobalArgs::default()
        }
    }

    fn sorted(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
        paths.sort();
        paths
    }

    /// The installed lookup `vex` judges hosted npm purls by takes alias
    /// installs as copies beside the own-name one: scoped keys, nested trees
    /// and scoped targets count; hidden dirs, other versions and symlinks do
    /// not (#856: no second alias walk backs it up).
    #[tokio::test]
    async fn npm_alias_copies_finds_only_alias_installs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let nm = root.join("node_modules");
        pkg(&nm.join("minimist"), "minimist", "1.2.2");
        pkg(&nm.join("mm"), "minimist", "1.2.2");
        pkg(&nm.join("@me/mm"), "minimist", "1.2.2");
        pkg(&nm.join("dep/node_modules/deep"), "minimist", "1.2.2");
        pkg(&nm.join("old"), "minimist", "1.2.8");
        pkg(
            &nm.join(".pnpm/minimist@1.2.2/node_modules/x"),
            "minimist",
            "1.2.2",
        );
        pkg(&nm.join("sc"), "@scope/pkg", "1.0.0");
        #[cfg(unix)]
        std::os::unix::fs::symlink(nm.join("mm"), nm.join("linked")).unwrap();

        let purls = vec![
            "pkg:npm/minimist@1.2.2".to_string(),
            "pkg:npm/%40scope/pkg@1.0.0".to_string(),
        ];
        let found = crate::ecosystem_dispatch::find_manifest_package_copies_reusing(
            &purls,
            &npm_scope(root),
            true,
            None,
        )
        .await;
        assert_eq!(
            sorted(found["pkg:npm/minimist@1.2.2"].clone()),
            sorted(vec![
                nm.join("@me/mm"),
                nm.join("dep/node_modules/deep"),
                nm.join("minimist"),
                nm.join("mm"),
            ])
        );
        assert_eq!(found["pkg:npm/%40scope/pkg@1.0.0"], vec![nm.join("sc")]);
    }

    /// A workspace member's alias install is a consumed copy even when the
    /// root holds the package under its own name: every importer tree the
    /// crawler enumerates is searched, and `--global-prefix` searches the
    /// prefix.
    #[tokio::test]
    async fn npm_alias_copies_walks_every_workspace_members_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        pkg(&root.join("node_modules/left-pad"), "left-pad", "1.3.0");
        pkg(
            &root.join("packages/a/node_modules/lp"),
            "left-pad",
            "1.3.0",
        );
        pkg(
            &root.join("packages/a/node_modules/dep/node_modules/deep"),
            "left-pad",
            "1.3.0",
        );
        pkg(
            &root.join("apps/web/node_modules/@me/lp"),
            "left-pad",
            "1.3.0",
        );
        pkg(
            &root.join("apps/web/node_modules/left-pad"),
            "left-pad",
            "1.3.0",
        );

        let purl = "pkg:npm/left-pad@1.3.0";
        let got = installed_copies(&npm_scope(root), purl).await;
        assert_eq!(
            sorted(got[purl].clone()),
            sorted(vec![
                root.join("apps/web/node_modules/@me/lp"),
                root.join("apps/web/node_modules/left-pad"),
                root.join("node_modules/left-pad"),
                root.join("packages/a/node_modules/dep/node_modules/deep"),
                root.join("packages/a/node_modules/lp"),
            ])
        );

        let prefix = root.join("packages/a/node_modules");
        let under_prefix = GlobalArgs {
            global_prefix: Some(prefix.clone()),
            ..npm_scope(root)
        };
        let got = installed_copies(&under_prefix, purl).await;
        assert_eq!(
            sorted(got[purl].clone()),
            vec![prefix.join("dep/node_modules/deep"), prefix.join("lp")]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn store_variants_of_a_consumed_copy_are_consumed_too() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        for id in [
            "~npm~left-pad@1.3.0",
            "~npm~left-pad@1.3.0~peer.0df72515a50372ba",
            "~acme~left-pad@1.3.0",
            "~npm~left-pad@1.4.0",
        ] {
            let version = if id.contains("1.4.0") {
                "1.4.0"
            } else {
                "1.3.0"
            };
            pkg(
                &nm.join(format!(".vlt/{id}/node_modules/left-pad")),
                "left-pad",
                version,
            );
        }
        std::os::unix::fs::symlink(
            ".vlt/~npm~left-pad@1.3.0/node_modules/left-pad",
            nm.join("left-pad"),
        )
        .unwrap();
        let mut got = with_store_peer_variant_copies(vec![nm.join("left-pad")]).await;
        got.sort();
        let mut want = vec![
            nm.join("left-pad"),
            nm.join(".vlt/~acme~left-pad@1.3.0/node_modules/left-pad"),
            nm.join(".vlt/~npm~left-pad@1.3.0~peer.0df72515a50372ba/node_modules/left-pad"),
        ];
        want.sort();
        assert_eq!(got, want);
        assert!(with_store_peer_variant_copies(Vec::new()).await.is_empty());
    }

    /// vlt twin of the `.pnpm` case: every importer entry is a link into
    /// the `.vlt` store (the alias `lp` too), so no importer dir is an alias
    /// nothing, while the crawler resolves the alias's package from its
    /// store copy, which is named after the real package. That store copy
    /// is the consumed evidence.
    #[cfg(unix)]
    #[tokio::test]
    async fn vlt_alias_is_consumed_through_its_store_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let nm = root.join("node_modules");
        let store_copy = nm.join(".vlt/~npm~left-pad@1.1.3/node_modules/left-pad");
        pkg(&store_copy, "left-pad", "1.1.3");
        pkg(
            &nm.join(".vlt/~npm~left-pad@1.3.0/node_modules/left-pad"),
            "left-pad",
            "1.3.0",
        );
        std::os::unix::fs::symlink(
            ".vlt/~npm~left-pad@1.1.3/node_modules/left-pad",
            nm.join("lp"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            ".vlt/~npm~left-pad@1.3.0/node_modules/left-pad",
            nm.join("left-pad"),
        )
        .unwrap();

        let purls = vec!["pkg:npm/left-pad@1.1.3".to_string()];

        let found = NpmCrawler::new().find_by_purls(&nm, &purls).await.unwrap();
        assert_eq!(
            found["pkg:npm/left-pad@1.1.3"]
                .iter()
                .map(|p| p.path.clone())
                .collect::<Vec<_>>(),
            vec![store_copy.clone()]
        );

        let mut all: HashMap<String, Vec<PathBuf>> = HashMap::new();
        npm_identity_fallback(Some(&purls), &local(root), &mut all).await;
        assert_eq!(all.get(&purls[0]), Some(&vec![nm.join("lp")]));
    }

    #[test]
    fn cargo_registry_dirs_are_matched_by_host_and_hash_shape() {
        assert!(is_registry_dir_for_host(
            "patch.socket.dev-1949cf8c6b5b557f",
            "patch.socket.dev"
        ));
        assert!(!is_registry_dir_for_host(
            "index.crates.io-1949cf8c6b5b557f",
            "patch.socket.dev"
        ));
        // A look-alike host, a wrong hash length, uppercase hex: not cargo's.
        assert!(!is_registry_dir_for_host(
            "patch.socket.dev.evil-1949cf8c6b5b557f",
            "patch.socket.dev"
        ));
        assert!(!is_registry_dir_for_host(
            "patch.socket.dev-1949cf8c",
            "patch.socket.dev"
        ));
        assert!(!is_registry_dir_for_host(
            "patch.socket.dev-1949CF8C6B5B557F",
            "patch.socket.dev"
        ));
        assert_eq!(
            registry_host("sparse+https://Patch.Socket.dev/patch-registry/cargo/t/u/index/")
                .as_deref(),
            Some("patch.socket.dev")
        );
        assert_eq!(
            registry_host("registry+https://github.com/rust-lang/crates.io-index").as_deref(),
            Some("github.com")
        );
        assert_eq!(registry_host("git+https://patch.socket.dev/x"), None);
        let src = Path::new("/h/.cargo/registry/src/patch.socket.dev-1949cf8c6b5b557f");
        assert_eq!(
            registry_src_dir_name(src),
            Some("patch.socket.dev-1949cf8c6b5b557f")
        );
        assert_eq!(registry_src_dir_name(Path::new("/proj/vendor")), None);
        assert_eq!(
            cached_crate(src, "serde", "1.0.0"),
            Some(PathBuf::from(
                "/h/.cargo/registry/cache/patch.socket.dev-1949cf8c6b5b557f/serde-1.0.0.crate"
            ))
        );
    }
}
