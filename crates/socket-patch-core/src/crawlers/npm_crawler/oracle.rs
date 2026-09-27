//! The pre-parallel (one tokio `spawn_blocking` hop per filesystem call)
//! npm crawler, kept verbatim as the equivalence oracle for the
//! blocking-pool walkers in the parent module: the randomized fixture
//! tests assert both produce identical `crawl_all` / `find_by_purls` /
//! store-enumeration output. Test-only; never compiled into the binary.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use super::{
    build_npm_purl, decode_pnpm_store_entry_name, is_legacy_pnpm_store_dir_name,
    is_safe_npm_component, parse_package_name, read_package_json, NpmCrawler, Target,
    NESTED_STORE_MAX_DEPTH, NESTED_STORE_MAX_DIRS, SKIP_DIRS,
};
use crate::crawlers::types::{CrawledPackage, CrawlerOptions};
use crate::utils::fs::is_dir;

/// Which kind of `node_modules` directory a scan pass is walking — the one
/// traversal-policy bit that differs between them.
#[derive(Clone, Copy)]
enum ScanPolicy<'a> {
    /// An importer's or package's `node_modules`: symlinked entries are
    /// recorded (pnpm links direct deps; `npm link` targets) but never
    /// traversed into, and a `.pnpm` child is the virtual store, scanned
    /// in a deferred pass.
    Importer,
    /// One pnpm virtual-store entry's `node_modules`: only REAL
    /// directories are inventoried — a symlinked entry here is the
    /// package's dependency pointing at a sibling `.pnpm` store entry,
    /// which is inventoried via that entry; following it would record the
    /// same package under a path owned by a different store entry.
    /// `identity_seen` optionally carries the entry's own package name
    /// (what the store dir name decodes to) when its name@version is
    /// already inventoried — the importer pass wins the `seen` dedup for
    /// every root-linked direct dep — so that child's package.json is not
    /// read a second time; everything below it is still scanned.
    StoreEntry { identity_seen: Option<&'a str> },
}

pub(super) struct LegacyNpmCrawler;

impl LegacyNpmCrawler {
    /// The old `NpmCrawler::crawl_all`: global roots come from the (shared,
    /// unchanged) global-path logic; local roots from the old async walk.
    pub(super) async fn crawl_all(options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let nm_paths = if options.global || options.global_prefix.is_some() {
            NpmCrawler::new()
                .get_node_modules_paths(options)
                .await
                .unwrap_or_default()
        } else {
            Self::find_local_node_modules_dirs(&options.cwd).await
        };

        for nm_path in &nm_paths {
            let found = Self::scan_node_modules(nm_path, &mut seen, ScanPolicy::Importer).await;
            packages.extend(found);
        }

        packages
    }

    pub(super) async fn find_by_purls(
        node_modules_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, Vec<CrawledPackage>>, std::io::Error> {
        let mut result: HashMap<String, Vec<CrawledPackage>> = HashMap::new();

        let mut pending: Vec<Target> = Vec::new();
        for purl in purls {
            let Some((namespace, name, version)) = NpmCrawler::parse_purl_components(purl) else {
                continue;
            };

            // SECURITY: `namespace`/`name` come straight from the (untrusted)
            // manifest PURL and are joined onto `node_modules_path` below,
            // then patched in place. A real npm scope/name is a single
            // path segment, so reject any that could traverse out of the
            // tree (`pkg:npm/../../evil@1.0.0`). Fail closed — twin of the
            // deno/go/maven coordinate gates.
            let ns_safe = namespace
                .as_deref()
                .map(is_safe_npm_component)
                .unwrap_or(true);
            if !ns_safe || !is_safe_npm_component(&name) {
                continue;
            }

            let dir_key = match &namespace {
                Some(ns) => format!("{ns}/{name}"),
                None => name.clone(),
            };
            pending.push(Target {
                namespace,
                name,
                version,
                purl: purl.clone(),
                dir_key,
            });
        }

        // Pass 1 — filtered: `.pnpm` virtual-store entries are enqueued
        // only when their dir name decodes to a still-pending target's
        // name (a manifest routinely lists packages that simply aren't
        // installed here, and probing every entry of a large monorepo
        // store for them would add a readdir+stat storm to every
        // apply/rollback run).
        let pending =
            Self::resolve_pending_targets(node_modules_path, pending, &mut result, true).await;

        // Pass 2 — unfiltered fallback, only for targets pass 1 could not
        // resolve: a target can physically exist ONLY inside another
        // package's store entry (a bundled dependency at
        // `.pnpm/host@1.0.0/node_modules/host/node_modules/<target>`),
        // whose entry name decodes to the HOST's name — the pass-1 filter
        // skips it, leaving an installed, scan-visible package invisible
        // to apply (fail-open: apply reported it not installed). Probe
        // every store entry for just the leftovers; the common all-
        // resolved case never reaches this pass, so its perf is intact.
        if !pending.is_empty() {
            Self::resolve_pending_targets(node_modules_path, pending, &mut result, false).await;
        }

        Ok(result)
    }

    /// One breadth-first resolution pass over the tree rooted at
    /// `node_modules_path`: the root `node_modules` first (so a root-level
    /// install always wins), then — only while targets remain unresolved —
    /// each nested `node_modules`. npm nests a conflicting version under
    /// the dependent package, so a patched version can exist *only*
    /// nested; CLI_CONTRACT ("Deeply nested transitive dependencies are
    /// fully supported") promises those are patched identically to direct
    /// deps, and `crawl_all` (scan) already discovers them at unbounded
    /// depth.
    ///
    /// EVERY matching physical copy of each target lands in `result`
    /// (keyed by the target's verbatim PURL, root-copy-first). Targets are
    /// kept live across the whole walk — a duplicate copy can live at any
    /// depth — so the traversal continues past the first match rather than
    /// stopping. Targets for which NO copy was found anywhere are returned
    /// (the pass-2 fallback re-probes them with the unfiltered store walk).
    /// `filter_store_entries` selects whether pnpm virtual-store entries are
    /// bounded by the still-unmatched-name filter (pass 1) or all probed
    /// (the pass-2 fallback) — see `find_by_purls`.
    async fn resolve_pending_targets(
        node_modules_path: &Path,
        mut pending: Vec<Target>,
        result: &mut HashMap<String, Vec<CrawledPackage>>,
        filter_store_entries: bool,
    ) -> Vec<Target> {
        if pending.is_empty() {
            return pending;
        }
        let mut queue: VecDeque<PathBuf> = VecDeque::from([node_modules_path.to_path_buf()]);
        while let Some(nm_path) = queue.pop_front() {
            for target in &pending {
                let pkg_path = nm_path.join(&target.dir_key);
                let pkg_json_path = pkg_path.join("package.json");

                match read_package_json(&pkg_json_path).await {
                    // The on-disk *name* must match too: an alias install
                    // (`npm i foo@npm:bar@1.0.0`) puts a different package
                    // in `node_modules/foo`, so matching on version alone
                    // would misidentify it and patch the wrong package's
                    // files.
                    Some((found_name, found_version))
                        if found_name == target.dir_key && found_version == target.version =>
                    {
                        let copies = result.entry(target.purl.clone()).or_default();
                        // Record each physical copy once — a path reached
                        // twice (defensive against overlapping walks) is not
                        // double-counted.
                        if !copies.iter().any(|c| c.path == pkg_path) {
                            copies.push(CrawledPackage {
                                name: target.name.clone(),
                                version: found_version,
                                namespace: target.namespace.clone(),
                                purl: target.purl.clone(),
                                path: pkg_path,
                            });
                        }
                    }
                    _ => {}
                }
            }
            // Descend importer-tree nested `node_modules` for ALL targets
            // (a duplicate copy lives at an unknown depth), but probe the
            // pnpm virtual store only for targets NOT YET found anywhere: a
            // matched direct dep's store peer-variants are the apply
            // engine's fan-out job, and re-probing the store for it would
            // add a readdir storm. A target with no importer-tree copy
            // (transitive-only) still gets its store entries probed.
            let unmatched_names: HashSet<&str> = pending
                .iter()
                .filter(|t| !result.contains_key(&t.purl))
                .map(|t| t.dir_key.as_str())
                .collect();
            let filter = filter_store_entries.then_some(&unmatched_names);
            Self::collect_nested_node_modules(&nm_path, filter, &mut queue).await;
        }
        // Only the targets with zero copies remain "pending" for pass 2.
        pending.retain(|t| !result.contains_key(&t.purl));
        pending
    }

    /// Append the `node_modules` dirs living one level below `nm_path`
    /// (inside each of its package dirs, scoped or not) to `queue`.
    /// Mirrors `scan_node_modules`' traversal policy: hidden entries are
    /// skipped and symlinked packages are never traversed — a symlink here
    /// points into pnpm's content-addressed store or an `npm link` target
    /// outside the project. The one exception is pnpm's `.pnpm` virtual
    /// store (see below); `pending_names` — `Some(the still-unresolved
    /// targets' full package names)` — bounds which store entries get
    /// enqueued, while `None` (the pass-2 fallback of `find_by_purls`)
    /// enqueues every store entry.
    async fn collect_nested_node_modules(
        nm_path: &Path,
        pending_names: Option<&HashSet<&str>>,
        queue: &mut VecDeque<PathBuf>,
    ) {
        for entry in crate::utils::fs::list_dir_entries(nm_path).await {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            // pnpm's virtual store. Under the isolated linker the store is
            // the ONLY physical home of transitive dependencies: the
            // importer's node_modules holds symlinks for direct deps only,
            // so a transitive-only target (installed at
            // `.pnpm/<x>/node_modules/<name>`, runtime-loaded) is
            // unreachable through the symlink-free walk above — invisible
            // to apply despite being importable. Probe REAL store entries'
            // `node_modules`; the name+version match in `find_by_purls`
            // keeps aliases and multi-version store entries distinct, and
            // BFS order guarantees a root-linked install has already been
            // probed (and removed from `pending`) before these are
            // dequeued, so a package is never resolved twice.
            if name_str == ".pnpm" {
                let Some(file_type) = crate::utils::fs::entry_file_type(&entry).await else {
                    continue;
                };
                if !file_type.is_dir() {
                    continue;
                }
                let store_path = nm_path.join(&name);
                let entries = Self::list_pnpm_store_entries(&store_path).await;
                Self::enqueue_pending_store_entries(entries, pending_names, queue);
                continue;
            }
            // pnpm <=3: the virtual store is a hidden `.<registry-host>` dir
            // (there is no `.pnpm` at all) with the same
            // transitive-only-deps property, so it gets the same probing.
            // Must run before the generic hidden-entry skip below, which
            // would otherwise swallow it — leaving every transitive-only
            // install unpatchable on those layouts.
            if is_legacy_pnpm_store_dir_name(&name_str) {
                let Some(file_type) = crate::utils::fs::entry_file_type(&entry).await else {
                    continue;
                };
                if !file_type.is_dir() {
                    continue;
                }
                let mut entries = Vec::new();
                Self::collect_nested_store_entries(&nm_path.join(&name), &mut entries).await;
                Self::enqueue_pending_store_entries(entries, pending_names, queue);
                continue;
            }
            if name_str.starts_with('.') || name_str == "node_modules" {
                continue;
            }
            let Some(file_type) = crate::utils::fs::entry_file_type(&entry).await else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let entry_path = nm_path.join(&name);

            if name_str.starts_with('@') {
                for scoped in crate::utils::fs::list_dir_entries(&entry_path).await {
                    let scoped_name = scoped.file_name();
                    if scoped_name.to_string_lossy().starts_with('.') {
                        continue;
                    }
                    let Some(scoped_type) = crate::utils::fs::entry_file_type(&scoped).await else {
                        continue;
                    };
                    if !scoped_type.is_dir() {
                        continue;
                    }
                    let nested = entry_path.join(&scoped_name).join("node_modules");
                    if is_dir(&nested).await {
                        queue.push_back(nested);
                    }
                }
            } else {
                let nested = entry_path.join("node_modules");
                if is_dir(&nested).await {
                    queue.push_back(nested);
                }
            }
        }
    }

    /// Enqueue virtual-store entries that can still hold a pending target.
    /// A manifest routinely lists packages that simply aren't installed
    /// here, and probing every entry of a large monorepo store for them
    /// would add a readdir+stat storm to every apply/rollback run. The
    /// entry name advertises the entry's package, so filter by PENDING
    /// NAME only — the version is deliberately NOT matched at this stage
    /// (dir-name versions can carry peer/build decorations; the
    /// package.json probe stays the authority). An undecodable name
    /// (truncated/hash-suffixed dirs, git/URL deps, `_`-bearing names)
    /// reveals nothing about what's inside, so it stays probeable.
    ///
    /// `pending_names = None` disables the filter entirely: the entry name
    /// only advertises the entry's OWN package, so a target present solely
    /// as a bundled dependency INSIDE another package's entry hides behind
    /// a non-matching name — `find_by_purls`' pass-2 fallback probes every
    /// entry for exactly those. Both enumerators only yield entries whose
    /// `node_modules` exists, so no re-stat here.
    fn enqueue_pending_store_entries(
        entries: Vec<(String, PathBuf)>,
        pending_names: Option<&HashSet<&str>>,
        queue: &mut VecDeque<PathBuf>,
    ) {
        for (entry_name, entry_nm) in entries {
            if let Some(filter) = pending_names {
                if let Some((entry_pkg, _version)) = decode_pnpm_store_entry_name(&entry_name) {
                    if !filter.contains(entry_pkg.as_str()) {
                        continue;
                    }
                }
            }
            queue.push_back(entry_nm);
        }
    }

    /// Find `node_modules` directories within the project root.
    /// Recursively searches for workspace `node_modules` but stays within the
    /// project.
    async fn find_local_node_modules_dirs(start_path: &Path) -> Vec<PathBuf> {
        let mut results = Vec::new();

        // Direct node_modules in start_path
        let direct = start_path.join("node_modules");
        if is_dir(&direct).await {
            results.push(direct);
        }

        // Recursively search for workspace node_modules
        Self::find_workspace_node_modules(start_path, &mut results).await;

        results
    }

    /// Recursively find `node_modules` in subdirectories (for monorepos / workspaces).
    /// Skips symlinks, hidden dirs, and well-known non-workspace dirs.
    fn find_workspace_node_modules<'a>(
        dir: &'a Path,
        results: &'a mut Vec<PathBuf>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
        Box::pin(async move {
            for entry in crate::utils::fs::list_dir_entries(dir).await {
                let Some(file_type) = crate::utils::fs::entry_file_type(&entry).await else {
                    continue;
                };
                if !file_type.is_dir() {
                    continue;
                }

                let name = entry.file_name();
                let name_str = name.to_string_lossy();

                // Skip node_modules, hidden dirs, and well-known build dirs
                if name_str == "node_modules"
                    || name_str.starts_with('.')
                    || SKIP_DIRS.contains(&name_str.as_ref())
                {
                    continue;
                }

                let full_path = dir.join(&name);

                // Check if this subdirectory has its own node_modules
                let sub_nm = full_path.join("node_modules");
                if is_dir(&sub_nm).await {
                    results.push(sub_nm);
                }

                // Recurse
                Self::find_workspace_node_modules(&full_path, results).await;
            }
        })
    }

    // ------------------------------------------------------------------
    // Private helpers – scanning
    // ------------------------------------------------------------------

    /// Scan a `node_modules` directory, returning all valid packages found.
    /// Recurses into each package's own nested `node_modules`. The one
    /// policy bit distinguishing an importer/package tree from a pnpm
    /// virtual-store entry is carried by [`ScanPolicy`].
    fn scan_node_modules<'a>(
        node_modules_path: &'a Path,
        seen: &'a mut HashSet<String>,
        policy: ScanPolicy<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<CrawledPackage>> + 'a>> {
        Box::pin(async move {
            let mut results = Vec::new();
            let mut pnpm_store: Option<PathBuf> = None;
            let mut legacy_stores: Vec<PathBuf> = Vec::new();
            let (store_entry, identity_seen) = match policy {
                ScanPolicy::Importer => (false, None),
                ScanPolicy::StoreEntry { identity_seen } => (true, identity_seen),
            };

            for entry in crate::utils::fs::list_dir_entries(node_modules_path).await {
                let name = entry.file_name();
                let name_str = name.to_string_lossy().to_string();

                // pnpm's virtual store: under the isolated linker it is the
                // ONLY physical home of transitive dependencies (the
                // importer's node_modules symlinks direct deps only), so
                // skipping it as just-another-hidden-dir leaves every
                // transitive-only install invisible to scan. Deferred until
                // after this loop so root-level entries are inventoried
                // first and win the `seen` name@version dedup at their
                // importer-root paths. (A store entry's own children never
                // include a nested `.pnpm`; under `StoreEntry` policy the
                // name falls through to the hidden-entry skip below.)
                if !store_entry && name_str == ".pnpm" {
                    let Some(file_type) = crate::utils::fs::entry_file_type(&entry).await else {
                        continue;
                    };
                    if file_type.is_dir() {
                        pnpm_store = Some(node_modules_path.join(&name_str));
                    }
                    continue;
                }

                // pnpm <=3 virtual store (a hidden `.<registry-host>` dir;
                // no `.pnpm` exists on those layouts): same
                // transitive-only-home property, same deferred scan so
                // root-level entries win the `seen` dedup. Must run before
                // the hidden-entry skip below, which would otherwise leave
                // every transitive-only install invisible to scan.
                if !store_entry && is_legacy_pnpm_store_dir_name(&name_str) {
                    let Some(file_type) = crate::utils::fs::entry_file_type(&entry).await else {
                        continue;
                    };
                    if file_type.is_dir() {
                        legacy_stores.push(node_modules_path.join(&name_str));
                    }
                    continue;
                }

                // Skip hidden files and node_modules
                if name_str.starts_with('.') || name_str == "node_modules" {
                    continue;
                }

                let Some(file_type) = crate::utils::fs::entry_file_type(&entry).await else {
                    continue;
                };

                // Importer trees allow both directories and symlinks (pnpm
                // links direct deps); a store entry accepts REAL dirs only
                // (see `ScanPolicy::StoreEntry`).
                let acceptable = if store_entry {
                    file_type.is_dir()
                } else {
                    file_type.is_dir() || file_type.is_symlink()
                };
                if !acceptable {
                    continue;
                }

                let entry_path = node_modules_path.join(&name_str);

                if name_str.starts_with('@') {
                    // Scoped packages
                    let scoped = Self::scan_scoped_packages(&entry_path, seen, policy).await;
                    results.extend(scoped);
                } else {
                    // Regular package. `identity_seen` marks this exact dir
                    // as already inventoried by the importer pass — skip
                    // the redundant package.json read, but still descend
                    // below: bundled dependencies are real dirs nested
                    // inside the package itself (pnpm cannot link them
                    // out), physically present only here.
                    if identity_seen != Some(name_str.as_str()) {
                        if let Some(pkg) = Self::check_package(&entry_path, seen).await {
                            results.push(pkg);
                        }
                    }
                    // Recurse into nested node_modules only for real
                    // directories (not symlinks). Following a symlink here
                    // would walk into pnpm's content-addressed store (or an
                    // `npm link` target outside the project).
                    if file_type.is_dir() {
                        let nested = Self::scan_node_modules(
                            &entry_path.join("node_modules"),
                            seen,
                            ScanPolicy::Importer,
                        )
                        .await;
                        results.extend(nested);
                    }
                }
            }

            if let Some(store_path) = pnpm_store {
                let entries = Self::list_pnpm_store_entries(&store_path).await;
                results.extend(Self::scan_store_entries(entries, seen).await);
            }
            for store_path in legacy_stores {
                let mut entries = Vec::new();
                Self::collect_nested_store_entries(&store_path, &mut entries).await;
                results.extend(Self::scan_store_entries(entries, seen).await);
            }

            results
        })
    }

    /// Enumerate pnpm virtual-store (`node_modules/.pnpm`) entries,
    /// yielding `(entry_name, <entry>/node_modules)` for every entry whose
    /// `node_modules` actually exists. The child literally named
    /// `node_modules` is pnpm's internal hoist dir (nothing but symlinks
    /// into sibling entries) and hidden children are store metadata — both
    /// skipped. A REAL directory child with a `node_modules` of its own is
    /// a flat (pnpm 6+) entry; one *without* is the pnpm 4/5 nested layout
    /// — the child is a registry-host dir
    /// (`.pnpm/<registry-host>/<name>/<version>/node_modules/<name>`), so
    /// treating it as an empty entry silently hid every transitive-only
    /// install (apply exited 0 claiming success with nothing written) —
    /// descend it instead. Shared by the resolver
    /// (`collect_nested_node_modules`) and the scan pass
    /// (`scan_store_entries` callers) so the store-layout policy lives
    /// once.
    pub(super) async fn list_pnpm_store_entries(store_path: &Path) -> Vec<(String, PathBuf)> {
        let mut entries = Vec::new();
        for entry in crate::utils::fs::list_dir_entries(store_path).await {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') || name_str == "node_modules" {
                continue;
            }
            let Some(file_type) = crate::utils::fs::entry_file_type(&entry).await else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let entry_path = store_path.join(&name);
            let entry_nm = entry_path.join("node_modules");
            if is_dir(&entry_nm).await {
                entries.push((name_str.into_owned(), entry_nm));
            } else {
                Self::collect_nested_store_entries(&entry_path, &mut entries).await;
            }
        }
        entries
    }

    /// Descend a *nested* virtual-store host dir, yielding
    /// `(name@version, <version-dir>/node_modules)` for each package home
    /// found. Covers the two pre-flat layouts (both confirmed against
    /// captured real installs):
    /// - pnpm 4/5: `.pnpm/<registry-host>/…` — called on a `.pnpm` child
    ///   that has no `node_modules` of its own;
    /// - pnpm <=3: `node_modules/.<registry-host>/…` — called on the
    ///   hidden store root directly.
    ///
    /// Below the host, path components are registry coordinates (`@scope`,
    /// name, version), NOT package dirs, so the importer-walk hidden-name
    /// skip does not apply here — but symlinks are never traversed (a link
    /// inside the store points at a sibling entry or out of tree, and
    /// following one could cycle), and both depth and total fan-out are
    /// bounded. Each found dir's host-relative path is synthesized into
    /// the flat `name@version` entry-name form so downstream consumers
    /// (the pending-name filter, the `identity_seen` dedup) treat nested
    /// and flat entries identically; a shape that doesn't fit stays an
    /// undecodable — always-probed — name, the conservative direction.
    pub(super) async fn collect_nested_store_entries(
        host_path: &Path,
        entries: &mut Vec<(String, PathBuf)>,
    ) {
        let mut remaining = NESTED_STORE_MAX_DIRS;
        let mut queue: VecDeque<(PathBuf, String, usize)> =
            VecDeque::from([(host_path.to_path_buf(), String::new(), 0)]);
        while let Some((dir, rel, depth)) = queue.pop_front() {
            for entry in crate::utils::fs::list_dir_entries(&dir).await {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                // A `node_modules` here belongs to a parent entry (already
                // yielded), never a name/version coordinate.
                if name_str == "node_modules" {
                    continue;
                }
                let Some(file_type) = crate::utils::fs::entry_file_type(&entry).await else {
                    continue;
                };
                if !file_type.is_dir() {
                    continue;
                }
                if remaining == 0 {
                    return;
                }
                remaining -= 1;
                let child = dir.join(&name);
                let child_rel = if rel.is_empty() {
                    name_str.into_owned()
                } else {
                    format!("{rel}/{name_str}")
                };
                let child_nm = child.join("node_modules");
                if is_dir(&child_nm).await {
                    // `<name>/<version>/node_modules` — a package home.
                    // Anything deeper belongs to that package's own tree,
                    // which the store-entry scan walks itself.
                    let entry_name = match child_rel.rsplit_once('/') {
                        Some((pkg, version)) => format!("{pkg}@{version}"),
                        // Directly under the host there is no name/version
                        // split; the raw component stays the entry name
                        // (undecodable ⇒ probed).
                        None => child_rel,
                    };
                    entries.push((entry_name, child_nm));
                    continue;
                }
                if depth + 1 < NESTED_STORE_MAX_DEPTH {
                    queue.push_back((child, child_rel, depth + 1));
                }
            }
        }
    }

    /// Inventory the packages under each virtual-store entry's
    /// `node_modules` (entries come from `list_pnpm_store_entries` or
    /// `collect_nested_store_entries`). An entry whose name decodes to a
    /// name@version the importer pass already inventoried (every
    /// root-linked direct dep) skips the redundant package.json re-read
    /// via `identity_seen` — the entry is still walked, because
    /// bundled/injected dependencies are real dirs that physically live
    /// only inside the store entry.
    async fn scan_store_entries(
        entries: Vec<(String, PathBuf)>,
        seen: &mut HashSet<String>,
    ) -> Vec<CrawledPackage> {
        let mut results = Vec::new();

        for (entry_name, entry_nm) in entries {
            let identity_seen = decode_pnpm_store_entry_name(&entry_name)
                .filter(|(full_name, version)| {
                    let (ns, bare) = parse_package_name(full_name);
                    seen.contains(&build_npm_purl(ns.as_deref(), &bare, version))
                })
                .map(|(full_name, _version)| full_name);
            let found = Self::scan_node_modules(
                &entry_nm,
                seen,
                ScanPolicy::StoreEntry {
                    identity_seen: identity_seen.as_deref(),
                },
            )
            .await;
            results.extend(found);
        }

        results
    }

    /// Scan a scoped packages directory (`@scope/`). `policy` carries the
    /// caller's traversal rules (see [`ScanPolicy`]); nested `node_modules`
    /// below a scoped package are always regular importer-style trees.
    fn scan_scoped_packages<'a>(
        scope_path: &'a Path,
        seen: &'a mut HashSet<String>,
        policy: ScanPolicy<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<CrawledPackage>> + 'a>> {
        Box::pin(async move {
            let mut results = Vec::new();
            let (store_entry, identity_seen) = match policy {
                ScanPolicy::Importer => (false, None),
                ScanPolicy::StoreEntry { identity_seen } => (true, identity_seen),
            };
            // `identity_seen` names the full `@scope/name`; this dir is the
            // `@scope` half.
            let scope_name = scope_path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();

            for entry in crate::utils::fs::list_dir_entries(scope_path).await {
                let name = entry.file_name();
                let name_str = name.to_string_lossy().to_string();

                if name_str.starts_with('.') {
                    continue;
                }

                let Some(file_type) = crate::utils::fs::entry_file_type(&entry).await else {
                    continue;
                };

                let acceptable = if store_entry {
                    file_type.is_dir()
                } else {
                    file_type.is_dir() || file_type.is_symlink()
                };
                if !acceptable {
                    continue;
                }

                let pkg_path = scope_path.join(&name_str);
                let already_inventoried =
                    identity_seen.is_some_and(|full| full == format!("{scope_name}/{name_str}"));
                if !already_inventoried {
                    if let Some(pkg) = Self::check_package(&pkg_path, seen).await {
                        results.push(pkg);
                    }
                }

                // Nested node_modules only for real directories
                if file_type.is_dir() {
                    let nested = Self::scan_node_modules(
                        &pkg_path.join("node_modules"),
                        seen,
                        ScanPolicy::Importer,
                    )
                    .await;
                    results.extend(nested);
                }
            }

            results
        })
    }

    /// Check a package directory and return `CrawledPackage` if valid.
    /// Deduplicates by PURL via the `seen` set.
    async fn check_package(pkg_path: &Path, seen: &mut HashSet<String>) -> Option<CrawledPackage> {
        let pkg_json_path = pkg_path.join("package.json");
        let (full_name, version) = read_package_json(&pkg_json_path).await?;
        let (namespace, name) = parse_package_name(&full_name);
        let purl = build_npm_purl(namespace.as_deref(), &name, &version);

        if seen.contains(&purl) {
            return None;
        }
        seen.insert(purl.clone());

        Some(CrawledPackage {
            name,
            version,
            namespace,
            purl,
            path: pkg_path.to_path_buf(),
        })
    }
}

/// Equivalence of the blocking-pool walkers against the oracle above, over
/// randomized fixture trees exercising every layout rule the walks encode:
/// flat/nested/legacy pnpm stores, scoped packages, symlinks (live,
/// dangling, into the store), duplicate identities, aliases, broken / BOM'd
/// / FIFO / directory package.json, unreadable and unsearchable dirs, and
/// case variants of `node_modules`.
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    type Row = (String, String, String, Option<String>, PathBuf);

    fn rows(pkgs: &[CrawledPackage]) -> Vec<Row> {
        pkgs.iter()
            .map(|p| {
                (
                    p.purl.clone(),
                    p.name.clone(),
                    p.version.clone(),
                    p.namespace.clone(),
                    p.path.clone(),
                )
            })
            .collect()
    }

    fn map_rows(map: &HashMap<String, Vec<CrawledPackage>>) -> BTreeMap<String, Vec<Row>> {
        map.iter().map(|(k, v)| (k.clone(), rows(v))).collect()
    }

    const NAMES: &[&str] = &[
        "foo",
        "bar",
        "baz",
        "dup",
        "Foo",
        "lodash._x",
        "@s/a",
        "@s/b",
        "@t/c",
    ];
    const VERSIONS: &[&str] = &["1.0.0", "1.0.1", "2.0.0"];
    const WS_NAMES: &[&str] = &[
        "packages", "apps", "a", "b", "lib", "dist", "vendor", ".git", "tmp",
    ];

    /// Restores permissions the generator stripped, before the tempdir is
    /// removed (declare it AFTER the tempdir so it drops first). Only Unix
    /// strips permissions.
    #[cfg_attr(not(unix), allow(dead_code))]
    struct PermGuard(Vec<PathBuf>);
    impl Drop for PermGuard {
        fn drop(&mut self) {
            #[cfg(unix)]
            for p in self.0.iter().rev() {
                use std::os::unix::fs::PermissionsExt as _;
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
            }
        }
    }

    // Symlinks, FIFOs and permission stripping are generated on Unix only.
    #[cfg_attr(not(unix), allow(dead_code))]
    struct Gen {
        state: u64,
        /// Out-of-tree dir for symlink targets that get traversed.
        scratch: PathBuf,
        /// Real package dirs created so far (symlink targets).
        pkg_dirs: Vec<PathBuf>,
        /// Real `node_modules` dirs created so far (symlink targets).
        nm_dirs: Vec<PathBuf>,
        /// Dirs whose permissions were stripped; applied at the END (a
        /// stripped dir must not block the rest of the generation).
        lock_plan: Vec<(PathBuf, u32)>,
        uniq: usize,
    }

    impl Gen {
        fn new(seed: u64, scratch: PathBuf) -> Self {
            Self {
                state: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
                scratch,
                pkg_dirs: Vec::new(),
                nm_dirs: Vec::new(),
                lock_plan: Vec::new(),
                uniq: 0,
            }
        }

        fn next(&mut self) -> u64 {
            // xorshift64*
            let mut x = self.state;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.state = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        fn chance(&mut self, pct: usize) -> bool {
            self.below(100) < pct
        }

        fn pick<'a>(&mut self, items: &'a [&'a str]) -> &'a str {
            items[self.below(items.len())]
        }

        fn uniq(&mut self) -> usize {
            self.uniq += 1;
            self.uniq
        }

        #[allow(unused_variables)]
        fn symlink(target: &Path, link: &Path) {
            #[cfg(unix)]
            {
                if let Some(parent) = link.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::os::unix::fs::symlink(target, link);
            }
        }

        #[allow(unused_variables)]
        fn plan_lock(&mut self, dir: &Path, mode: u32) {
            #[cfg(unix)]
            self.lock_plan.push((dir.to_path_buf(), mode));
        }

        fn apply_locks(&mut self, guard: &mut PermGuard) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                // Deepest first, so a stripped parent never blocks a child.
                let mut plan = std::mem::take(&mut self.lock_plan);
                plan.sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
                for (dir, mode) in plan {
                    if std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir())
                        && std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode))
                            .is_ok()
                    {
                        guard.0.push(dir);
                    }
                }
            }
            #[cfg(not(unix))]
            let _ = guard;
        }

        /// Write `dir/package.json` in one of many shapes.
        fn package_json(&mut self, dir: &Path, name: &str, version: &str) {
            let _ = std::fs::create_dir_all(dir);
            let pj = dir.join("package.json");
            if pj.symlink_metadata().is_ok() {
                // Never write through an existing one (it may be a FIFO).
                return;
            }
            let valid = format!(r#"{{"name": "{name}", "version": "{version}"}}"#);
            match self.below(100) {
                0..=69 => {
                    let _ = std::fs::write(&pj, valid);
                }
                70..=74 => {
                    let _ = std::fs::write(&pj, format!("\u{feff}{valid}"));
                }
                75..=78 => {
                    let _ = std::fs::write(&pj, "not json");
                }
                79..=82 => {
                    let _ = std::fs::write(&pj, format!(r#"{{"name": "{name}"}}"#));
                }
                83..=85 => {
                    let _ =
                        std::fs::write(&pj, format!(r#"{{"name": "", "version": "{version}"}}"#));
                }
                86..=90 => {
                    #[cfg(unix)]
                    {
                        let c = std::ffi::CString::new(pj.to_str().unwrap()).unwrap();
                        // SAFETY: plain libc call on a valid C string.
                        unsafe { libc::mkfifo(c.as_ptr(), 0o644) };
                    }
                    #[cfg(not(unix))]
                    let _ = std::fs::write(&pj, valid);
                }
                91..=93 => {
                    let _ = std::fs::create_dir_all(&pj);
                }
                _ => {}
            }
        }

        /// A package dir `nm/<dir_name>` (maybe with nested node_modules).
        fn package(&mut self, nm: &Path, depth: usize) {
            let dir_name = self.pick(NAMES).to_string();
            // Mostly the dir's own name; sometimes an alias install.
            let pkg_name = if self.chance(88) {
                dir_name.clone()
            } else {
                self.pick(NAMES).to_string()
            };
            let version = self.pick(VERSIONS).to_string();
            let dir = nm.join(&dir_name);
            if dir.exists() {
                return;
            }
            self.package_json(&dir, &pkg_name, &version);
            self.pkg_dirs.push(dir.clone());
            if depth < 3 && self.chance(30) {
                let store_ok = self.chance(10);
                self.node_modules(&dir.join("node_modules"), depth + 1, store_ok);
            }
            if self.chance(4) {
                self.plan_lock(&dir, 0o000);
            }
        }

        fn node_modules(&mut self, nm: &Path, depth: usize, store_ok: bool) {
            let _ = std::fs::create_dir_all(nm);
            self.nm_dirs.push(nm.to_path_buf());
            let mut store_pkgs: Vec<(String, PathBuf)> = Vec::new();
            if store_ok && self.chance(60) {
                store_pkgs = self.pnpm_store(&nm.join(".pnpm"), depth);
            } else if self.chance(5) {
                let _ = std::fs::write(nm.join(".pnpm"), "not a store");
            }
            if store_ok && self.chance(15) {
                self.legacy_store(&nm.join(".registry.npmjs.org"), depth);
            }
            let n = self.below(6);
            for _ in 0..n {
                match self.below(100) {
                    0..=54 => self.package(nm, depth),
                    55..=62 => {
                        // Symlinked entry: live, into the store, or dangling.
                        let name = self.pick(NAMES);
                        let link = nm.join(name);
                        if link.symlink_metadata().is_ok() {
                            continue;
                        }
                        let target = if !store_pkgs.is_empty() && self.chance(50) {
                            {
                                let i = self.below(store_pkgs.len());
                                store_pkgs[i].1.clone()
                            }
                        } else if !self.pkg_dirs.is_empty() && self.chance(80) {
                            {
                                let i = self.below(self.pkg_dirs.len());
                                self.pkg_dirs[i].clone()
                            }
                        } else {
                            nm.join(format!("dangling-{}", self.uniq()))
                        };
                        Self::symlink(&target, &link);
                    }
                    63..=66 => {
                        let hidden = nm.join(format!(".cache{}", self.uniq()));
                        self.package_json(&hidden.join("foo"), "foo", "1.0.0");
                    }
                    67..=70 => {
                        let _ = std::fs::write(nm.join(format!("README{}", self.uniq())), "x");
                    }
                    71..=74 => {
                        // A symlinked scope dir (to a scope living outside
                        // the tree, so the followed walk cannot cycle).
                        let id = self.uniq();
                        let target = self.scratch.join(format!("scope{id}"));
                        let version = self.pick(VERSIONS).to_string();
                        self.package_json(&target.join("x"), "@link/x", &version);
                        let link = nm.join(format!("@link{}", self.uniq()));
                        Self::symlink(&target, &link);
                    }
                    75..=79 => {
                        let bin = nm.join(".bin");
                        let _ = std::fs::create_dir_all(&bin);
                        if let Some(target) = self.pkg_dirs.first().cloned() {
                            let link = bin.join(format!("tool{}", self.uniq()));
                            Self::symlink(&target, &link);
                        }
                    }
                    80..=82 => {
                        // A nested `node_modules` entry inside node_modules.
                        self.package_json(&nm.join("node_modules").join("foo"), "foo", "1.0.0");
                    }
                    _ => {
                        let scoped = self.pick(&["@s/a", "@s/b", "@t/c"]).to_string();
                        let dir = nm.join(&scoped);
                        if !dir.exists() {
                            let version = self.pick(VERSIONS).to_string();
                            self.package_json(&dir, &scoped, &version);
                            self.pkg_dirs.push(dir.clone());
                            if depth < 3 && self.chance(25) {
                                self.node_modules(&dir.join("node_modules"), depth + 1, false);
                            }
                        }
                    }
                }
            }
            // Root-linked direct deps: importer symlinks into the store.
            for (name, target) in store_pkgs {
                let link = nm.join(&name);
                if self.chance(50) && link.symlink_metadata().is_err() {
                    Self::symlink(&target, &link);
                }
            }
            if self.chance(3) {
                self.plan_lock(nm, 0o000);
            }
        }

        fn store_entry_name(&mut self, name: &str, version: &str) -> String {
            let escaped = name.replace('/', "+");
            match self.below(10) {
                0 => format!("{escaped}@{version}(peer@1.0.0)"),
                1 => format!("{escaped}@{version}_peer@1.0.0"),
                2 => format!("{escaped}@github.com+u+r@abc{}", self.uniq()),
                3 => format!("truncated-{}_abcdef", self.uniq()),
                _ => format!("{escaped}@{version}"),
            }
        }

        /// A `.pnpm` virtual store; returns `(name, package dir)` of the
        /// flat entries' own packages (importer symlink targets).
        fn pnpm_store(&mut self, store: &Path, depth: usize) -> Vec<(String, PathBuf)> {
            let _ = std::fs::create_dir_all(store);
            let _ = std::fs::write(store.join("lock.yaml"), "x");
            let mut own = Vec::new();
            let n = 1 + self.below(6);
            for _ in 0..n {
                let name = self.pick(NAMES).to_string();
                let version = self.pick(VERSIONS).to_string();
                match self.below(100) {
                    0..=59 => {
                        let entry = store.join(self.store_entry_name(&name, &version));
                        let entry_nm = entry.join("node_modules");
                        let pkg_name = if self.chance(90) {
                            name.clone()
                        } else {
                            self.pick(NAMES).to_string()
                        };
                        let pkg = entry_nm.join(&name);
                        self.package_json(&pkg, &pkg_name, &version);
                        self.pkg_dirs.push(pkg.clone());
                        own.push((name.clone(), pkg.clone()));
                        // Dependencies: symlinks to sibling entries.
                        for _ in 0..self.below(3) {
                            if let Some((dep, target)) = own.first().cloned() {
                                Self::symlink(&target, &entry_nm.join(format!("{dep}-dep")));
                            }
                        }
                        // Another real package in the entry (injected dep).
                        if self.chance(20) {
                            self.package(&entry_nm, depth + 1);
                        }
                        // Bundled deps below the package itself.
                        if depth < 2 && self.chance(25) {
                            self.node_modules(&pkg.join("node_modules"), depth + 1, false);
                        }
                        match self.below(100) {
                            0..=3 => self.plan_lock(&entry_nm, 0o000),
                            4..=6 => self.plan_lock(&entry, 0o000),
                            7..=9 => self.plan_lock(&entry_nm, 0o300),
                            _ => {}
                        }
                    }
                    60..=67 => {
                        // pnpm 4/5 nested host layout.
                        let pkg = store
                            .join("registry.npmjs.org")
                            .join(&name)
                            .join(&version)
                            .join("node_modules")
                            .join(&name);
                        self.package_json(&pkg, &name, &version);
                        self.pkg_dirs.push(pkg);
                    }
                    68..=71 => {
                        let _ = std::fs::create_dir_all(
                            store.join(format!("empty{}@1.0.0", self.uniq())),
                        );
                    }
                    72..=75 => {
                        let entry = store.join(self.store_entry_name(&name, &version));
                        let _ = std::fs::create_dir_all(&entry);
                        let _ = std::fs::write(entry.join("node_modules"), "file");
                    }
                    76..=79 => {
                        // An entry whose node_modules is a symlink.
                        if let Some(target) = self.nm_dirs.first().cloned() {
                            let entry = store.join(self.store_entry_name(&name, &version));
                            let _ = std::fs::create_dir_all(&entry);
                            Self::symlink(&target, &entry.join("node_modules"));
                        }
                    }
                    80..=83 => {
                        // The entry itself is a symlink (skipped).
                        if let Some(target) = self.pkg_dirs.first().cloned() {
                            let link = store.join(format!("{name}@9.9.{}", self.uniq()));
                            Self::symlink(&target, &link);
                        }
                    }
                    84..=89 => {
                        // pnpm's hoist dir: symlinks only.
                        let hoist = store.join("node_modules");
                        let _ = std::fs::create_dir_all(&hoist);
                        if let Some((dep, target)) = own.first().cloned() {
                            Self::symlink(&target, &hoist.join(dep));
                        }
                    }
                    _ => {
                        // Nested host with a scoped coordinate.
                        let pkg = store
                            .join("registry.npmjs.org")
                            .join("@s")
                            .join("a")
                            .join(&version)
                            .join("node_modules")
                            .join("@s")
                            .join("a");
                        self.package_json(&pkg, "@s/a", &version);
                    }
                }
            }
            own
        }

        /// A pnpm <=3 `.registry.npmjs.org` store.
        fn legacy_store(&mut self, store: &Path, depth: usize) {
            for _ in 0..1 + self.below(4) {
                let name = self.pick(NAMES).to_string();
                let version = self.pick(VERSIONS).to_string();
                let home = store.join(&name).join(&version).join("node_modules");
                self.package_json(&home.join(&name), &name, &version);
                if depth < 2 && self.chance(20) {
                    self.package(&home, depth + 1);
                }
            }
        }

        fn workspace(&mut self, dir: &Path, depth: usize) {
            let _ = std::fs::create_dir_all(dir);
            if self.chance(70) {
                self.node_modules(&dir.join("node_modules"), 0, true);
            }
            if depth >= 3 {
                return;
            }
            for _ in 0..self.below(5) {
                let child = dir.join(format!("{}{}", self.pick(WS_NAMES), self.uniq()));
                match self.below(100) {
                    0..=49 => self.workspace(&child, depth + 1),
                    50..=57 => {
                        // Skipped by name (dist/vendor/.git/tmp as-is).
                        let skipped = dir.join(self.pick(&["dist", "vendor", ".git", "tmp"]));
                        self.workspace(&skipped, depth + 1);
                    }
                    58..=63 => {
                        // A symlinked workspace dir (never walked).
                        if let Some(target) = self.nm_dirs.first().and_then(|p| p.parent()) {
                            let target = target.to_path_buf();
                            Self::symlink(&target, &child);
                        }
                    }
                    64..=69 => {
                        // node_modules itself a symlink.
                        let _ = std::fs::create_dir_all(&child);
                        if let Some(target) = self.nm_dirs.first().cloned() {
                            Self::symlink(&target, &child.join("node_modules"));
                        }
                    }
                    70..=73 => {
                        let _ = std::fs::create_dir_all(&child);
                        let _ = std::fs::write(child.join("node_modules"), "file");
                    }
                    74..=79 => {
                        // Case variant (aliases node_modules on APFS/NTFS).
                        let _ = std::fs::create_dir_all(&child);
                        let variant = self.pick(&["Node_Modules", "NODE_MODULES"]);
                        self.node_modules(&child.join(variant), 1, false);
                    }
                    80..=85 => {
                        self.workspace(&child, depth + 1);
                        self.plan_lock(&child, 0o000);
                    }
                    86..=91 => {
                        // Readable but not searchable: lists fine, stats fail.
                        self.workspace(&child, depth + 1);
                        self.plan_lock(&child, 0o600);
                    }
                    _ => {
                        let _ = std::fs::create_dir_all(&child);
                        let _ = std::fs::write(child.join("package.json"), "{}");
                    }
                }
            }
        }
    }

    /// Every purl worth resolving against a tree: all crawled identities,
    /// qualified / percent-encoded spellings, absent versions, and names
    /// that only exist inside store entries or aliases.
    fn probe_purls(crawled: &[CrawledPackage]) -> Vec<String> {
        let mut purls: Vec<String> = crawled.iter().map(|p| p.purl.clone()).collect();
        for name in NAMES {
            for version in VERSIONS {
                purls.push(format!("pkg:npm/{name}@{version}"));
            }
        }
        purls.push("pkg:npm/%40s/a@1.0.0".to_string());
        purls.push("pkg:npm/foo@1.0.0?vcs_url=git@x".to_string());
        purls.push("pkg:npm/absent@1.0.0".to_string());
        purls.push("pkg:npm/casedir@1.0.0".to_string());
        purls.push("pkg:npm/@cs/x@1.0.0".to_string());
        purls.push("pkg:npm/../evil@1.0.0".to_string());
        purls.sort();
        purls.dedup();
        purls
    }

    async fn assert_equivalent(root: &Path, label: &str) {
        let options = CrawlerOptions {
            cwd: root.to_path_buf(),
            global: false,
            global_prefix: None,
        };
        let crawler = NpmCrawler::new();

        let new_paths = crawler.get_node_modules_paths(&options).await.unwrap();
        let old_paths = LegacyNpmCrawler::find_local_node_modules_dirs(root).await;
        assert_eq!(new_paths, old_paths, "{label}: node_modules roots differ");

        let new_pkgs = crawler.crawl_all(&options).await;
        let old_pkgs = LegacyNpmCrawler::crawl_all(&options).await;
        assert_eq!(
            rows(&new_pkgs),
            rows(&old_pkgs),
            "{label}: crawl_all differs"
        );

        let purls = probe_purls(&new_pkgs);
        for nm in &new_paths {
            let new_found = crawler.find_by_purls(nm, &purls).await.unwrap();
            let old_found = LegacyNpmCrawler::find_by_purls(nm, &purls).await.unwrap();
            assert_eq!(
                map_rows(&new_found),
                map_rows(&old_found),
                "{label}: find_by_purls differs under {}",
                nm.display()
            );

            let store = nm.join(".pnpm");
            assert_eq!(
                NpmCrawler::list_pnpm_store_entries(&store).await,
                LegacyNpmCrawler::list_pnpm_store_entries(&store).await,
                "{label}: store entries differ under {}",
                store.display()
            );
            let legacy = nm.join(".registry.npmjs.org");
            let mut new_nested = Vec::new();
            NpmCrawler::collect_nested_store_entries(&legacy, &mut new_nested).await;
            let mut old_nested = Vec::new();
            LegacyNpmCrawler::collect_nested_store_entries(&legacy, &mut old_nested).await;
            assert_eq!(
                new_nested, old_nested,
                "{label}: nested store entries differ"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn randomized_trees_match_the_sequential_oracle() {
        let mut nonempty = 0;
        for seed in 0..64u64 {
            let tmp = tempfile::tempdir().unwrap();
            let mut guard = PermGuard(Vec::new());
            let root = tmp.path().join("proj");
            let mut gen = Gen::new(seed, tmp.path().join("scratch"));
            gen.workspace(&root, 0);
            gen.apply_locks(&mut guard);

            assert_equivalent(&root, &format!("seed {seed}")).await;
            let options = CrawlerOptions {
                cwd: root.clone(),
                global: false,
                global_prefix: None,
            };
            if !NpmCrawler::new().crawl_all(&options).await.is_empty() {
                nonempty += 1;
            }
            drop(guard);
        }
        // The generator must actually produce packages most of the time,
        // or the comparison above is vacuous.
        assert!(nonempty > 32, "only {nonempty} non-empty trees");
    }

    /// A store entry whose own child's package.json disagrees with the
    /// entry's name@version, for a root-installed package: the sequential
    /// walk skips that child by name (`identity_seen`) without reading it,
    /// so the foreign identity must never surface.
    #[tokio::test]
    async fn store_entry_child_with_a_foreign_identity_is_skipped_like_the_oracle() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("proj");
        let nm = root.join("node_modules");
        let write = |dir: &Path, name: &str, version: &str| {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(
                dir.join("package.json"),
                format!(r#"{{"name": "{name}", "version": "{version}"}}"#),
            )
            .unwrap();
        };
        write(&nm.join("qux"), "qux", "1.0.0");
        write(&nm.join("@s").join("q"), "@s/q", "1.0.0");
        let store = nm.join(".pnpm");
        let q = store.join("qux@1.0.0").join("node_modules");
        write(&q.join("qux"), "qux", "9.9.9");
        // Below the skipped child is still walked.
        write(
            &q.join("qux").join("node_modules").join("inner"),
            "inner",
            "1.0.0",
        );
        // A sibling of the skipped child is not skipped.
        write(&q.join("sib"), "sib", "1.0.0");
        write(
            &store
                .join("@s+q@1.0.0")
                .join("node_modules")
                .join("@s")
                .join("q"),
            "@s/q",
            "9.9.9",
        );
        // Not root-installed: its child is read, foreign identity and all.
        write(
            &store.join("free@1.0.0").join("node_modules").join("free"),
            "free",
            "7.7.7",
        );

        assert_equivalent(&root, "foreign identity").await;

        let options = CrawlerOptions {
            cwd: root.clone(),
            global: false,
            global_prefix: None,
        };
        let purls: Vec<String> = NpmCrawler::new()
            .crawl_all(&options)
            .await
            .into_iter()
            .map(|p| p.purl)
            .collect();
        for present in [
            "pkg:npm/qux@1.0.0",
            "pkg:npm/@s/q@1.0.0",
            "pkg:npm/inner@1.0.0",
            "pkg:npm/sib@1.0.0",
            "pkg:npm/free@7.7.7",
        ] {
            assert!(
                purls.iter().any(|p| p == present),
                "missing {present}: {purls:?}"
            );
        }
        for absent in ["pkg:npm/qux@9.9.9", "pkg:npm/@s/q@9.9.9"] {
            assert!(
                !purls.iter().any(|p| p == absent),
                "{absent} must be skipped: {purls:?}"
            );
        }
    }

    /// With no walk pool (the OS refused every walk thread) the walk runs
    /// sequentially on the calling thread and still matches the oracle.
    #[tokio::test]
    async fn walk_without_a_pool_matches_the_sequential_oracle() {
        let _off = crate::crawlers::walk_pool::test_hooks::DisablePool::new();
        for seed in 0..16u64 {
            let tmp = tempfile::tempdir().unwrap();
            let mut guard = PermGuard(Vec::new());
            let root = tmp.path().join("proj");
            let mut gen = Gen::new(seed, tmp.path().join("scratch"));
            gen.workspace(&root, 0);
            gen.apply_locks(&mut guard);
            assert_equivalent(&root, &format!("no pool, seed {seed}")).await;
            drop(guard);
        }
    }

    /// Hand-built tree with one of every tricky shape (so each is covered
    /// regardless of what the random generator happens to draw), asserting
    /// equivalence and pinning a few load-bearing outcomes.
    #[tokio::test]
    async fn kitchen_sink_tree_matches_the_sequential_oracle() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("proj");
        let nm = root.join("node_modules");
        let write = |dir: &Path, name: &str, version: &str| {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(
                dir.join("package.json"),
                format!(r#"{{"name": "{name}", "version": "{version}"}}"#),
            )
            .unwrap();
        };
        // Importer tree: plain, scoped, nested duplicate, alias.
        write(&nm.join("foo"), "foo", "1.0.0");
        write(&nm.join("@s").join("a"), "@s/a", "1.0.0");
        write(
            &nm.join("bar").join("node_modules").join("foo"),
            "foo",
            "1.0.0",
        );
        write(&nm.join("bar"), "bar", "1.0.0");
        write(&nm.join("alias"), "baz", "2.0.0");
        // Flat store: a root-linked dep's own entry (identity_seen skip) with
        // a bundled dep, a transitive-only entry, peer variants.
        let store = nm.join(".pnpm");
        let q = store.join("qux@1.0.0").join("node_modules");
        write(&q.join("qux"), "qux", "1.0.0");
        write(
            &q.join("qux").join("node_modules").join("bundled"),
            "bundled",
            "3.0.0",
        );
        write(
            &store.join("t@1.0.0").join("node_modules").join("t"),
            "t",
            "1.0.0",
        );
        write(
            &store
                .join("p@1.0.0(r@17.0.0)")
                .join("node_modules")
                .join("p"),
            "p",
            "1.0.0",
        );
        write(
            &store
                .join("p@1.0.0(r@18.0.0)")
                .join("node_modules")
                .join("p"),
            "p",
            "1.0.0",
        );
        write(
            &store
                .join("@s+b@1.0.0")
                .join("node_modules")
                .join("@s")
                .join("b"),
            "@s/b",
            "1.0.0",
        );
        // Nested (pnpm 4/5) host and legacy (pnpm <=3) store.
        write(
            &store
                .join("registry.npmjs.org")
                .join("n")
                .join("1.0.0")
                .join("node_modules")
                .join("n"),
            "n",
            "1.0.0",
        );
        write(
            &nm.join(".registry.npmjs.org")
                .join("l")
                .join("1.0.0")
                .join("node_modules")
                .join("l"),
            "l",
            "1.0.0",
        );
        // A dir whose spelling differs from its package's name only by case
        // (resolves under the lowercase name on case-insensitive volumes),
        // and a scope spelled likewise.
        write(&nm.join("CaseDir"), "casedir", "1.0.0");
        write(&nm.join("@Cs").join("x"), "@cs/x", "1.0.0");
        // Broken / BOM'd package.json.
        std::fs::create_dir_all(nm.join("broken")).unwrap();
        std::fs::write(nm.join("broken").join("package.json"), "{").unwrap();
        std::fs::create_dir_all(nm.join("bom")).unwrap();
        std::fs::write(
            nm.join("bom").join("package.json"),
            "\u{feff}{\"name\":\"bom\",\"version\":\"1.0.0\"}",
        )
        .unwrap();
        // Workspaces: plain, skipped, case variant, node_modules-as-file.
        write(
            &root
                .join("packages")
                .join("w")
                .join("node_modules")
                .join("w"),
            "w",
            "1.0.0",
        );
        write(
            &root.join("dist").join("node_modules").join("d"),
            "d",
            "1.0.0",
        );
        write(
            &root.join("cv").join("Node_Modules").join("cv"),
            "cv",
            "1.0.0",
        );
        std::fs::create_dir_all(root.join("nf")).unwrap();
        std::fs::write(root.join("nf").join("node_modules"), "file").unwrap();

        let tmp_guard;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt as _};
            // Root-linked direct dep into the store, a dangling link.
            symlink(q.join("qux"), nm.join("qux")).unwrap();
            symlink(root.join("nowhere"), nm.join("dangling")).unwrap();
            // FIFO package.json.
            std::fs::create_dir_all(nm.join("fifo")).unwrap();
            let c = std::ffi::CString::new(nm.join("fifo").join("package.json").to_str().unwrap())
                .unwrap();
            // SAFETY: plain libc call on a valid C string.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
            // A workspace whose node_modules is a symlink.
            std::fs::create_dir_all(root.join("ln")).unwrap();
            symlink(
                root.join("packages").join("w").join("node_modules"),
                root.join("ln").join("node_modules"),
            )
            .unwrap();
            // Unreadable store entry node_modules; unsearchable workspace.
            let locked_nm = store.join("z@1.0.0").join("node_modules");
            write(&locked_nm.join("z"), "z", "1.0.0");
            write(
                &root.join("rw").join("node_modules").join("r"),
                "r",
                "1.0.0",
            );
            std::fs::set_permissions(&locked_nm, std::fs::Permissions::from_mode(0o000)).unwrap();
            std::fs::set_permissions(root.join("rw"), std::fs::Permissions::from_mode(0o600))
                .unwrap();
            tmp_guard = PermGuard(vec![locked_nm, root.join("rw")]);
        }
        #[cfg(not(unix))]
        {
            tmp_guard = PermGuard(Vec::new());
        }

        assert_equivalent(&root, "kitchen sink").await;

        let options = CrawlerOptions {
            cwd: root.clone(),
            global: false,
            global_prefix: None,
        };
        let purls: Vec<String> = NpmCrawler::new()
            .crawl_all(&options)
            .await
            .into_iter()
            .map(|p| p.purl)
            .collect();
        for expected in [
            "pkg:npm/foo@1.0.0",
            "pkg:npm/@s/a@1.0.0",
            "pkg:npm/bundled@3.0.0",
            "pkg:npm/t@1.0.0",
            "pkg:npm/p@1.0.0",
            "pkg:npm/@s/b@1.0.0",
            "pkg:npm/n@1.0.0",
            "pkg:npm/l@1.0.0",
            "pkg:npm/bom@1.0.0",
            "pkg:npm/w@1.0.0",
        ] {
            assert!(
                purls.iter().any(|p| p == expected),
                "missing {expected}: {purls:?}"
            );
        }
        assert!(
            !purls.iter().any(|p| p == "pkg:npm/d@1.0.0"),
            "dist/ must be skipped"
        );
        drop(tmp_guard);
    }
}
