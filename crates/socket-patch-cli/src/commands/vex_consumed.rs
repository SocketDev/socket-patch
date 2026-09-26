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
//! | maven | `<repo>/<g>/<a>/<base>-socket.<hex8>/` (the version the pom pins), its artifact files matched under the suffixed name | the `<base>` version dir |
//! | npm | every `node_modules` copy the crawler finds (pnpm and vlt store copies included), plus alias installs (`node_modules/<alias>` holding the package) in the root's and every workspace member's tree | — each serves some dependent: ALL must verify |
//! | pypi | every copy in the crawler's environment set (the project's venvs when it has any, else the interpreters) | — any may be the one that runs the project: ALL must verify |
//! | gem | every copy in bundler's gem path | — bundler loads whichever `Gem.path` home it hits first: ALL must verify |
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

use socket_patch_core::crawlers::{
    CargoCrawler, CrawlerOptions, Ecosystem, GoCrawler, MavenCrawler, NpmCrawler,
};
use socket_patch_core::utils::purl::purl_parts;
use socket_patch_core::vendor::go_mod_edit::{
    read_replace_entries, ReplaceOwner, HOSTED_GO_MODULE_PREFIX,
};
use socket_patch_core::vendor::lock_inventory::LockIntegrity;
use socket_patch_core::vex::HostedCopies;

use crate::args::GlobalArgs;
use crate::commands::vex_sources::HostedWiring;
use crate::ecosystem_dispatch::{npm_paths_by_identity, partition_purls};

/// Resolve [`HostedCopies`] for every hosted-basis purl of `hosted` (see the
/// module docs), under the same crawler options and `--ecosystems` scope as
/// the installed-tree lookup. `installed` is that lookup's every-copy
/// result ([`crate::ecosystem_dispatch::find_manifest_package_copies`] over
/// the record view, which holds every hosted purl): the shared-location
/// ecosystems read it instead of crawling the tree a second time.
pub(crate) async fn hosted_consumed_copies(
    common: &GlobalArgs,
    hosted: &BTreeMap<String, HostedWiring>,
    installed: &HashMap<String, Vec<PathBuf>>,
) -> HashMap<String, HostedCopies> {
    let mut out = HashMap::new();
    if hosted.is_empty() {
        return out;
    }
    let options = CrawlerOptions {
        cwd: common.cwd.clone(),
        global: common.global,
        global_prefix: common.global_prefix.clone(),
    };
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
        let mut aliases = match shared.get(&Ecosystem::Npm) {
            Some(npm) => npm_alias_copies(&options, npm).await,
            None => HashMap::new(),
        };
        npm_identity_fallback(shared.get(&Ecosystem::Npm), &options, &mut all, &aliases).await;
        for purl in shared.values().flatten() {
            let mut paths = all.remove(purl).unwrap_or_default();
            paths.extend(aliases.remove(purl).unwrap_or_default());
            out.insert(
                purl.clone(),
                HostedCopies {
                    paths,
                    rename: None,
                },
            );
        }
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

// ── npm aliases ──────────────────────────────────────────────────────────

/// Upper bound on the package dirs [`npm_alias_copies`] inspects: a
/// pathological (or hostile) tree cannot turn one `vex` run into an
/// unbounded walk.
const ALIAS_WALK_MAX_DIRS: usize = 200_000;

/// ALIAS installs of the hosted npm `purls`, keyed by purl: a dependency
/// declared `"mm": "npm:minimist@1.2.2"` (npm, yarn and bun alike) lands in
/// `node_modules/mm`, a dir the crawler's name-keyed lookup never probes
/// (it matches `node_modules/<name>` by design, so apply cannot patch the
/// wrong package). For a hosted ref that copy is what the aliased import
/// loads, so it is consumed evidence like any other: without it an alias
/// that is the ONLY copy read as "not installed" and a tampered or stale
/// (pre-reinstall) tree attested from the lock pin alone.
///
/// Walks EVERY importer `node_modules` tree the crawler resolves the
/// installed copies from ([`NpmCrawler::get_node_modules_paths`]: the
/// root's AND each workspace member's in a project, the prefix under
/// `--global-prefix`) once, matching each package dir's `package.json`
/// `(name, version)`; only dirs whose on-disk key DIFFERS from the
/// package's name are aliases (the crawler already returns the rest).
/// Walking the root tree alone left a workspace member's alias
/// (`packages/a/node_modules/lp`) unhashed whenever the root or a hoisted
/// copy existed — the identity fallback only fills purls with NO copy —
/// so a stale or tampered member alias attested from the good root copy.
/// Hidden entries (`.bin`, pnpm's `.pnpm` and vlt's `.vlt` stores — the
/// crawler probes them) and symlinks (pnpm's and vlt's importer links,
/// `npm link` targets) are not traversed. Under vlt EVERY importer entry,
/// an alias included, is a link into `.vlt/<DepID>/node_modules/<name>`,
/// so this walk finds no vlt alias at all: the store copy is named after
/// the real package, and the crawler's store pass resolves it (the
/// identity fallback covers the rest). A plain `--global` run is not
/// walked: its roots come from spawning every package manager again, and
/// the identity fallback covers an alias that is the only global copy.
async fn npm_alias_copies(
    options: &CrawlerOptions,
    purls: &[String],
) -> HashMap<String, Vec<PathBuf>> {
    let wanted: HashMap<(String, String), &String> = purls
        .iter()
        .filter_map(|purl| {
            let (ty, name, version) = purl_parts(purl)?;
            (ty == "npm").then_some(((name, version), purl))
        })
        .collect();
    let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
    if wanted.is_empty() {
        return out;
    }
    if options.global && options.global_prefix.is_none() {
        return out;
    }
    let roots = NpmCrawler::new()
        .get_node_modules_paths(options)
        .await
        .unwrap_or_default();
    let mut queue = std::collections::VecDeque::from(roots);
    let mut visited = 0usize;
    while let Some(nm) = queue.pop_front() {
        // (package dir, the key it is installed under)
        let mut packages: Vec<(PathBuf, String)> = Vec::new();
        for (path, name) in real_subdirs(&nm).await {
            if name.starts_with('@') {
                for (pkg, bare) in real_subdirs(&path).await {
                    packages.push((pkg, format!("{name}/{bare}")));
                }
            } else {
                packages.push((path, name));
            }
        }
        for (pkg, key) in packages {
            visited += 1;
            if visited > ALIAS_WALK_MAX_DIRS {
                return out;
            }
            let found = socket_patch_core::crawlers::npm_crawler::read_package_json(
                &pkg.join("package.json"),
            )
            .await;
            if let Some((name, version)) = found {
                if name != key {
                    if let Some(purl) = wanted.get(&(name, version)) {
                        let copies = out.entry((*purl).clone()).or_default();
                        if !copies.contains(&pkg) {
                            copies.push(pkg.clone());
                        }
                    }
                }
            }
            queue.push_back(pkg.join("node_modules"));
        }
    }
    out
}

/// `(path, name)` of the non-hidden, non-symlink directories directly in
/// `dir` (empty when `dir` is missing or unreadable).
async fn real_subdirs(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return out;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        // `DirEntry::file_type` does not follow symlinks: a link is skipped.
        if entry.file_type().await.is_ok_and(|t| t.is_dir()) {
            out.push((entry.path(), name));
        }
    }
    out
}

/// Last-resort identity lookup for an npm purl that neither the targeted
/// resolver nor the [`npm_alias_copies`] walk found. An npm ALIAS dependency
/// (`"lp": "npm:left-pad@1.3.0"`) is installed under its dependency key
/// (`node_modules/lp`), not its package name, so the targeted resolver —
/// which probes `node_modules/<name>` — reports it not installed, and the
/// walk skips symlinked importer entries (yarn's pnpm linker, a global
/// `--global-prefix` tree). For a hosted purl that is not a harmless miss: "not
/// installed" is exactly what the lockfile basis excuses, so a stale or
/// tampered alias install was attested from the lock pin instead of being
/// hash-verified ("installed evidence wins"). Resolve every npm purl the
/// targeted lookup missed by the installed `package.json` identity instead
/// — the same fallback `vendor` uses before declaring a package missing.
async fn npm_identity_fallback(
    npm: Option<&Vec<String>>,
    options: &CrawlerOptions,
    all: &mut HashMap<String, Vec<PathBuf>>,
    aliases: &HashMap<String, Vec<PathBuf>>,
) {
    let missing: Vec<&String> = npm
        .into_iter()
        .flatten()
        .filter(|purl| {
            all.get(*purl).is_none_or(Vec::is_empty) && aliases.get(*purl).is_none_or(Vec::is_empty)
        })
        .collect();
    all.extend(npm_paths_by_identity(options, &missing).await);
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
    let (_, rest) = url.split_once("://")?;
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if hostport.starts_with('[') {
        &hostport[..=hostport.find(']')?]
    } else {
        hostport.split(':').next()?
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
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
/// the redirect or belongs to another project). The served files carry the
/// suffixed version in their names, so the record's `<a>-<base>…` files are
/// matched as `<a>-<suffixed>…`.
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
    for repo in crawler
        .get_maven_repo_paths(options)
        .await
        .unwrap_or_default()
    {
        let found = crawler
            .find_by_purls(&repo, std::slice::from_ref(&target))
            .await
            .unwrap_or_default();
        if let Some(pkg) = found.get(&target) {
            return HostedCopies {
                paths: vec![pkg.path.clone()],
                rename: Some((
                    format!("{artifact}-{version}"),
                    format!("{artifact}-{suffixed}"),
                )),
            };
        }
    }
    not_installed()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// REGRESSION: an npm alias install (`node_modules/lp` holding
    /// left-pad@1.3.0) is a consumed copy of the hosted purl. The targeted
    /// lookup probes `node_modules/left-pad` only, so it used to come back
    /// "not installed" — which the lockfile basis excuses — and a tampered or
    /// stale alias install was attested from the lock pin unverified.
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
        npm_identity_fallback(Some(&purls), &options, &mut all, &HashMap::new()).await;
        assert_eq!(
            all.get("pkg:npm/left-pad@1.3.0"),
            Some(&vec![tmp.path().join("node_modules/lp")])
        );
        assert!(!all.contains_key("pkg:npm/absent@2.0.0"), "{all:?}");

        // A copy the targeted lookup already found is kept as-is (the alias
        // fallback only fills misses).
        let found = tmp.path().join("node_modules/left-pad");
        let mut all = HashMap::from([(purls[0].clone(), vec![found.clone()])]);
        npm_identity_fallback(Some(&purls), &options, &mut all, &HashMap::new()).await;
        assert_eq!(all[&purls[0]], vec![found.clone()]);

        // A purl the alias walk already found is not re-resolved.
        let mut all: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let walked = HashMap::from([(purls[0].clone(), vec![found.clone()])]);
        npm_identity_fallback(Some(&purls), &options, &mut all, &walked).await;
        assert!(!all.contains_key(&purls[0]), "{all:?}");
    }

    /// Only dirs whose install key differs from the package name are
    /// aliases; scoped keys, nested trees and scoped targets are walked;
    /// hidden dirs, other versions and symlinks are not copies.
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
        let found = npm_alias_copies(&local(root), &purls).await;
        let mut got: Vec<PathBuf> = found["pkg:npm/minimist@1.2.2"].clone();
        got.sort();
        let mut want = vec![
            nm.join("@me/mm"),
            nm.join("dep/node_modules/deep"),
            nm.join("mm"),
        ];
        want.sort();
        assert_eq!(got, want);
        assert_eq!(found["pkg:npm/%40scope/pkg@1.0.0"], vec![nm.join("sc")]);
    }

    /// REGRESSION: a workspace member's alias install is a consumed copy
    /// even when the root holds the package under its own name. The walk
    /// used to start at the root `node_modules` only, and the identity
    /// fallback only fills purls with NO copy — so beside a root (or
    /// hoisted) install the member alias went unhashed and a tampered one
    /// attested from the good root copy. Every importer tree the crawler
    /// enumerates is walked; `--global-prefix` walks the prefix; a plain
    /// `--global` run walks nothing (the fallback covers it).
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
        // Not an alias: the member's own-name copy is the crawler's.
        pkg(
            &root.join("apps/web/node_modules/left-pad"),
            "left-pad",
            "1.3.0",
        );

        let purls = vec!["pkg:npm/left-pad@1.3.0".to_string()];
        let mut got =
            npm_alias_copies(&local(root), &purls).await["pkg:npm/left-pad@1.3.0"].clone();
        got.sort();
        let mut want = vec![
            root.join("apps/web/node_modules/@me/lp"),
            root.join("packages/a/node_modules/dep/node_modules/deep"),
            root.join("packages/a/node_modules/lp"),
        ];
        want.sort();
        assert_eq!(got, want);

        let prefix = root.join("packages/a/node_modules");
        let under_prefix = CrawlerOptions {
            global_prefix: Some(prefix.clone()),
            ..local(root)
        };
        let mut got =
            npm_alias_copies(&under_prefix, &purls).await["pkg:npm/left-pad@1.3.0"].clone();
        got.sort();
        assert_eq!(
            got,
            vec![prefix.join("dep/node_modules/deep"), prefix.join("lp")]
        );

        let global = CrawlerOptions {
            global: true,
            ..local(root)
        };
        assert!(npm_alias_copies(&global, &purls).await.is_empty());
    }

    /// vlt twin of the `.pnpm` case: every importer entry is a link into
    /// the `.vlt` store (the alias `lp` too), so the alias walk yields
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
        assert!(npm_alias_copies(&local(root), &purls).await.is_empty());

        let found = NpmCrawler::new().find_by_purls(&nm, &purls).await.unwrap();
        assert_eq!(
            found["pkg:npm/left-pad@1.1.3"]
                .iter()
                .map(|p| p.path.clone())
                .collect::<Vec<_>>(),
            vec![store_copy.clone()]
        );

        let mut all: HashMap<String, Vec<PathBuf>> = HashMap::new();
        npm_identity_fallback(Some(&purls), &local(root), &mut all, &HashMap::new()).await;
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
