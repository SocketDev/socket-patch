use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::types::{CrawledPackage, CrawlerOptions};
use crate::patch::path_safety;
use crate::utils::fs::is_dir;
use crate::utils::purl::{percent_decode_purl_component, strip_purl_qualifiers};

/// Directories to skip when searching for workspace node_modules.
const SKIP_DIRS: &[&str] = &[
    "dist",
    "build",
    "coverage",
    "tmp",
    "temp",
    "__pycache__",
    "vendor",
];

// ---------------------------------------------------------------------------
// Helper: read and parse package.json
// ---------------------------------------------------------------------------

/// Minimal fields we need from package.json.
#[derive(Deserialize)]
struct PackageJsonPartial {
    name: Option<String>,
    version: Option<String>,
}

/// Read and parse a `package.json` file, returning `(name, version)` if valid.
pub async fn read_package_json(pkg_json_path: &Path) -> Option<(String, String)> {
    use tokio::io::AsyncReadExt;

    // The path lives inside the (untrusted) package tree: a planted FIFO
    // would make a plain `read_to_string` open block forever waiting for a
    // writer, wedging scan (crawl_all) and apply (find_by_purls). Open via
    // `open_regular_file` — non-blocking on Unix, rejecting
    // FIFOs/devices/directories (see its docs).
    let (mut file, metadata) = crate::utils::fs::open_regular_file(pkg_json_path)
        .await
        .ok()?;
    let mut content = String::with_capacity(metadata.len() as usize);
    file.read_to_string(&mut content).await.ok()?;
    // npm and Node both tolerate a leading UTF-8 BOM in package.json
    // (Windows-authored packages ship them), but serde_json rejects it —
    // a BOM'd install would be invisible to scan and unpatchable.
    let pkg: PackageJsonPartial =
        serde_json::from_str(crate::package_json::detect::strip_bom(&content)).ok()?;
    let name = pkg.name?;
    let version = pkg.version?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

// ---------------------------------------------------------------------------
// Helper: parse package name into (namespace, name)
// ---------------------------------------------------------------------------

/// Parse a full npm package name into optional namespace and bare name.
///
/// Examples:
/// - `"@types/node"` -> `(Some("@types"), "node")`
/// - `"lodash"` -> `(None, "lodash")`
pub fn parse_package_name(full_name: &str) -> (Option<String>, String) {
    if full_name.starts_with('@') {
        if let Some(slash_idx) = full_name.find('/') {
            let namespace = full_name[..slash_idx].to_string();
            let name = full_name[slash_idx + 1..].to_string();
            return (Some(namespace), name);
        }
    }
    (None, full_name.to_string())
}

// ---------------------------------------------------------------------------
// Helper: build PURL
// ---------------------------------------------------------------------------

/// Build a PURL string for an npm package.
pub fn build_npm_purl(namespace: Option<&str>, name: &str, version: &str) -> String {
    match namespace {
        Some(ns) => format!("pkg:npm/{ns}/{name}@{version}"),
        None => format!("pkg:npm/{name}@{version}"),
    }
}

// ---------------------------------------------------------------------------
// Helper: decode a pnpm virtual-store entry directory name
// ---------------------------------------------------------------------------

/// Decode a `.pnpm` virtual-store entry directory name into the
/// `(package_name, version)` it advertises.
///
/// Store entry names follow `<escaped-name>@<version><suffix>` where:
/// - a scoped name's `/` is written as `+` (`@scope+leaf@2.0.0`),
/// - pnpm 9+ appends peer/qualifier suffixes in parentheses
///   (`foo@1.0.0(bar@2.0.0)(@babel+core@7.21.0)`),
/// - pnpm 6–8 appended peer suffixes after `_` (`foo@1.0.0_bar@2.0.0`),
/// - over-long names are truncated (the cut can land ANYWHERE, even
///   mid-name or mid-version) and end in `_<hash>`.
///
/// Returns `None` for anything that does not cleanly parse as
/// `name@X.Y.Z…`: store metadata files (`lock.yaml`), git/URL dependency
/// entries (`foo@github.com+user+repo@<sha>` — a sha is not a semver
/// triple), truncated long-name dirs, and names containing a literal `_`
/// (indistinguishable from a legacy peer suffix). Callers MUST treat
/// `None` as "identity unknowable from the dir name", not "no package
/// here", and keep such entries probeable/scannable. A `Some` can still
/// be a truncation artifact (a cut that happens to land after a
/// `name@X.Y.Z` prefix is undetectable), so the decoded pair is
/// advisory: resolution authority stays with the package.json probe.
pub fn decode_pnpm_store_entry_name(entry_name: &str) -> Option<(String, String)> {
    // pnpm 9+ peer/qualifier suffix: everything from the first `(`.
    let base = &entry_name[..entry_name.find('(').unwrap_or(entry_name.len())];
    // Legacy (pnpm 6–8) `_` peer suffix, doubling as the long-name
    // truncation hash separator. Real package names may contain `_` too
    // — those then fail the version parse below and fall to the
    // conservative `None` path, which is the safe direction.
    let base = &base[..base.find('_').unwrap_or(base.len())];

    let at = base.rfind('@')?;
    // `at == 0` would leave an empty name (`@1.0.0`).
    if at == 0 {
        return None;
    }
    let version = &base[at + 1..];
    if !is_semver_triple(version) {
        return None;
    }
    // Scope escaping: `/` in the (possibly scoped) name is written `+`.
    // `+` cannot appear in a real npm name, so a bare replace is exact.
    let name = base[..at].replace('+', "/");
    Some((name, version.to_string()))
}

/// Whether `v` starts with a numeric `MAJOR.MINOR.PATCH` triple
/// (pre-release/build tails allowed). Registry versions — the only kind
/// pnpm writes into decodable store entry names — always do; git shas
/// and URL fragments never do, so requiring the triple keeps those
/// entries on `decode_pnpm_store_entry_name`'s conservative `None` path.
fn is_semver_triple(v: &str) -> bool {
    let mut parts = v.splitn(3, '.');
    let (Some(major), Some(minor), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let patch = &rest[..rest.find(['-', '+']).unwrap_or(rest.len())];
    let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    all_digits(major) && all_digits(minor) && all_digits(patch)
}

// ---------------------------------------------------------------------------
// Helpers: pnpm virtual-store layout knowledge
// ---------------------------------------------------------------------------

/// Maximum directory depth probed below a *nested* virtual-store host dir.
/// pnpm 4/5 (layoutVersion 3) nest store entries by registry host —
/// `.pnpm/<registry-host>/<name>/<version>/node_modules/<name>` — and
/// pnpm <=3 (layoutVersion <=2) use the same shape directly under a hidden
/// `node_modules/.<registry-host>` dir (both confirmed against captured
/// real installs). Relative to the host dir the deepest package home is
/// `@scope/<name>/<version>` — three levels.
const NESTED_STORE_MAX_DEPTH: usize = 3;

/// Upper bound on directories visited while descending one nested-store
/// host, so a corrupted (or adversarial) tree cannot turn the bounded
/// descent into an unbounded readdir storm. A real store holds one dir per
/// scope/name and one per version — orders of magnitude below this.
/// Hitting the cap can only make the walk miss packages (fail toward "not
/// installed", the same answer the pre-descent code gave for every nested
/// entry), never patch the wrong one: the package.json probe stays the
/// authority.
const NESTED_STORE_MAX_DIRS: usize = 16_384;

/// Whether a hidden `node_modules` child is a pnpm <=3 virtual store.
/// Before the `.pnpm` dir existed (layoutVersion <=2: pnpm 1/2/3) the
/// store lived at `node_modules/.<registry-host>` — `.registry.npmjs.org`
/// for the default registry (confirmed byte-for-byte in captured pnpm
/// 1.x/2.x/3.8 trees, whose `.modules.yaml` names
/// `registries.default: https://registry.npmjs.org/`). Matching the
/// `.registry.` prefix also covers other `registry.*` hosts while never
/// mistaking unrelated hidden dirs (`.bin`, `.cache`, `.git`) for a store;
/// a custom registry on a host not starting with `registry.` would need
/// its own entry here — deliberately NOT "any hidden dir", which would
/// walk arbitrary tool caches.
fn is_legacy_pnpm_store_dir_name(name: &str) -> bool {
    name.starts_with(".registry.")
}

// ---------------------------------------------------------------------------
// Global prefix detection helpers
// ---------------------------------------------------------------------------

use crate::utils::process::{CommandRunner, SystemCommandRunner};

/// Get the npm global `node_modules` path via `npm root -g`.
pub fn get_npm_global_prefix() -> Result<String, String> {
    get_npm_global_prefix_with(&SystemCommandRunner)
}

/// Version of `get_npm_global_prefix` that accepts an injected
/// `CommandRunner`. Tests use this with a `MockCommandRunner` to
/// exercise the success arm (binary present, stdout parsed) without
/// requiring npm on the host's PATH.
pub fn get_npm_global_prefix_with(runner: &dyn CommandRunner) -> Result<String, String> {
    parse_npm_root_output(runner.run("npm", &["root", "-g"]).as_deref().unwrap_or("")).ok_or_else(
        || {
            "Failed to determine npm global prefix. Ensure npm is installed and in PATH."
                .to_string()
        },
    )
}

/// Pure parser for `npm root -g` stdout. Returns the trimmed path or
/// `None` on empty input. Extracted so the helper logic is unit-
/// testable without shelling out.
pub fn parse_npm_root_output(stdout: &str) -> Option<String> {
    let path = stdout.trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

/// Get the yarn global `node_modules` path via `yarn global dir`.
pub fn get_yarn_global_prefix() -> Option<String> {
    get_yarn_global_prefix_with(&SystemCommandRunner)
}

/// Version of `get_yarn_global_prefix` that accepts an injected
/// `CommandRunner`. See `get_npm_global_prefix_with`.
pub fn get_yarn_global_prefix_with(runner: &dyn CommandRunner) -> Option<String> {
    parse_yarn_dir_output(
        runner
            .run("yarn", &["global", "dir"])
            .as_deref()
            .unwrap_or(""),
    )
}

/// Pure parser for `yarn global dir` stdout. Returns `<dir>/node_modules`
/// or `None` on empty input. Extracted so the path-derivation logic is
/// unit-testable without shelling out.
pub fn parse_yarn_dir_output(stdout: &str) -> Option<String> {
    let dir = stdout.trim().to_string();
    if dir.is_empty() {
        return None;
    }
    Some(
        PathBuf::from(dir)
            .join("node_modules")
            .to_string_lossy()
            .to_string(),
    )
}

/// Get the pnpm global `node_modules` path via `pnpm root -g`.
pub fn get_pnpm_global_prefix() -> Option<String> {
    get_pnpm_global_prefix_with(&SystemCommandRunner)
}

/// Version of `get_pnpm_global_prefix` that accepts an injected
/// `CommandRunner`. See `get_npm_global_prefix_with`.
pub fn get_pnpm_global_prefix_with(runner: &dyn CommandRunner) -> Option<String> {
    parse_pnpm_root_output(runner.run("pnpm", &["root", "-g"]).as_deref().unwrap_or(""))
}

/// Pure parser for `pnpm root -g` stdout. Returns the trimmed path or
/// `None` on empty input.
pub fn parse_pnpm_root_output(stdout: &str) -> Option<String> {
    let path = stdout.trim().to_string();
    if path.is_empty() {
        return None;
    }
    Some(path)
}

/// Get the bun global `node_modules` path via `bun pm bin -g`.
pub fn get_bun_global_prefix() -> Option<String> {
    get_bun_global_prefix_with(&SystemCommandRunner)
}

/// Version of `get_bun_global_prefix` that accepts an injected
/// `CommandRunner`. See `get_npm_global_prefix_with`.
pub fn get_bun_global_prefix_with(runner: &dyn CommandRunner) -> Option<String> {
    parse_bun_bin_output(
        runner
            .run("bun", &["pm", "bin", "-g"])
            .as_deref()
            .unwrap_or(""),
    )
}

/// Pure parser for `bun pm bin -g` stdout. Extracted so the
/// derive-the-global-node_modules-path logic is unit-testable
/// without shelling out.
///
/// Given output like `"/Users/foo/.bun/bin\n"` returns
/// `Some("/Users/foo/.bun/install/global/node_modules")`. Returns
/// `None` on empty input or a root-only path with no parent.
pub fn parse_bun_bin_output(stdout: &str) -> Option<String> {
    let bin_path = stdout.trim().to_string();
    if bin_path.is_empty() {
        return None;
    }

    let bun_root = PathBuf::from(&bin_path);
    let bun_root = bun_root.parent()?;
    Some(
        bun_root
            .join("install")
            .join("global")
            .join("node_modules")
            .to_string_lossy()
            .to_string(),
    )
}

// ---------------------------------------------------------------------------
// Helpers: synchronous wildcard directory resolver
// ---------------------------------------------------------------------------

/// Resolve a path with `"*"` wildcard segments synchronously.
///
/// Each segment is either a literal directory name or `"*"` which matches any
/// directory entry. Symlinks are followed via `std::fs::metadata`.
///
/// Production callers live inside `#[cfg(target_os = "macos")]` blocks of
/// `get_global_node_modules_paths` (Homebrew/nvm/volta/fnm fallbacks).
/// `#[allow(dead_code)]` keeps the function visible to the inline
/// `#[cfg(test)] mod tests` callers on every target without tripping
/// `-D dead_code` on non-macOS clippy runs.
#[allow(dead_code)]
fn find_node_dirs_sync(base: &Path, segments: &[&str]) -> Vec<PathBuf> {
    if !base.is_dir() {
        return Vec::new();
    }
    if segments.is_empty() {
        return vec![base.to_path_buf()];
    }

    let first = segments[0];
    let rest = &segments[1..];

    if first == "*" {
        let mut results = Vec::new();
        if let Ok(entries) = std::fs::read_dir(base) {
            for entry in entries.flatten() {
                // Follow symlinks: `DirEntry::metadata()` does NOT traverse
                // symlinks (it stats the link itself), so a symlinked version
                // dir — fnm's per-version layout, nvm `default`/`current`
                // aliases — would be missed. Stat the joined path with the
                // free `std::fs::metadata`, which resolves the link target.
                let child = base.join(entry.file_name());
                let is_dir = std::fs::metadata(&child)
                    .map(|m| m.is_dir())
                    .unwrap_or(false);
                if is_dir {
                    results.extend(find_node_dirs_sync(&child, rest));
                }
            }
        }
        results
    } else {
        find_node_dirs_sync(&base.join(first), rest)
    }
}

// ---------------------------------------------------------------------------
// NpmCrawler
// ---------------------------------------------------------------------------

/// NPM ecosystem crawler for discovering packages in `node_modules`.
pub struct NpmCrawler;

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

impl NpmCrawler {
    /// Create a new `NpmCrawler`.
    pub fn new() -> Self {
        Self
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Get `node_modules` paths based on options.
    ///
    /// In global mode returns well-known global paths; in local mode walks
    /// the project tree looking for `node_modules` directories (including
    /// workspace packages).
    pub async fn get_node_modules_paths(
        &self,
        options: &CrawlerOptions,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return Ok(vec![custom.clone()]);
            }
            return Ok(self.get_global_node_modules_paths());
        }

        Ok(self.find_local_node_modules_dirs(&options.cwd).await)
    }

    /// Crawl all discovered `node_modules` and return every package found.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let nm_paths = self
            .get_node_modules_paths(options)
            .await
            .unwrap_or_default();

        for nm_path in &nm_paths {
            let found = Self::scan_node_modules(nm_path, &mut seen, ScanPolicy::Importer).await;
            packages.extend(found);
        }

        packages
    }

    /// Find specific packages by PURL inside a single `node_modules` tree.
    ///
    /// This is an efficient O(n) lookup where n = number of PURLs: we parse
    /// each PURL to derive the expected directory path, then do a direct stat
    /// + `package.json` read.
    pub async fn find_by_purls(
        &self,
        node_modules_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, CrawledPackage>, std::io::Error> {
        let mut result: HashMap<String, CrawledPackage> = HashMap::new();

        // `purl` is the *verbatim* caller-supplied PURL, including any
        // `?qualifiers`. The result map is keyed by this exact string: the
        // dispatcher drives npm with `passthrough_purls` + `merge_first_wins`,
        // so it looks results back up under the PURL it handed in. Keying by a
        // reconstructed/stripped PURL silently loses every qualified PURL
        // (e.g. `pkg:npm/foo@1.0.0?vcs_url=...`).
        struct Target {
            namespace: Option<String>,
            name: String,
            version: String,
            purl: String,
            /// Install dir relative to a `node_modules` root
            /// (`@scope/name` or `name`) — which is also exactly what the
            /// package.json `name` field must say for this dir to BE that
            /// package.
            dir_key: String,
        }

        let mut pending: Vec<Target> = Vec::new();
        for purl in purls {
            let Some((namespace, name, version)) = Self::parse_purl_components(purl) else {
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

        // Probe trees breadth-first: the root `node_modules` first (so a
        // root-level install always wins), then — only while targets remain
        // unresolved — each nested `node_modules`. npm nests a conflicting
        // version under the dependent package, so a patched version can
        // exist *only* nested; CLI_CONTRACT ("Deeply nested transitive
        // dependencies are fully supported") promises those are patched
        // identically to direct deps, and `crawl_all` (scan) already
        // discovers them at unbounded depth.
        let mut queue: VecDeque<PathBuf> = VecDeque::from([node_modules_path.to_path_buf()]);
        while let Some(nm_path) = queue.pop_front() {
            if pending.is_empty() {
                break;
            }
            let mut unresolved = Vec::with_capacity(pending.len());
            for target in pending {
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
                        result.insert(
                            target.purl.clone(),
                            CrawledPackage {
                                name: target.name,
                                version: found_version,
                                namespace: target.namespace,
                                purl: target.purl,
                                path: pkg_path,
                            },
                        );
                    }
                    _ => unresolved.push(target),
                }
            }
            pending = unresolved;
            if !pending.is_empty() {
                // The still-unresolved names bound which `.pnpm` store
                // entries are worth enqueuing (see the store branch of
                // `collect_nested_node_modules`). Rebuilt per level:
                // targets resolved at shallower depths drop out.
                let pending_names: HashSet<&str> =
                    pending.iter().map(|t| t.dir_key.as_str()).collect();
                Self::collect_nested_node_modules(&nm_path, &pending_names, &mut queue).await;
            }
        }

        Ok(result)
    }

    /// Append the `node_modules` dirs living one level below `nm_path`
    /// (inside each of its package dirs, scoped or not) to `queue`.
    /// Mirrors `scan_node_modules`' traversal policy: hidden entries are
    /// skipped and symlinked packages are never traversed — a symlink here
    /// points into pnpm's content-addressed store or an `npm link` target
    /// outside the project. The one exception is pnpm's `.pnpm` virtual
    /// store (see below); `pending_names` — the still-unresolved targets'
    /// full package names — bounds which store entries get enqueued.
    async fn collect_nested_node_modules(
        nm_path: &Path,
        pending_names: &HashSet<&str>,
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
    /// reveals nothing about what's inside, so it stays probeable. Both
    /// enumerators only yield entries whose `node_modules` exists, so no
    /// re-stat here.
    fn enqueue_pending_store_entries(
        entries: Vec<(String, PathBuf)>,
        pending_names: &HashSet<&str>,
        queue: &mut VecDeque<PathBuf>,
    ) {
        for (entry_name, entry_nm) in entries {
            if let Some((entry_pkg, _version)) = decode_pnpm_store_entry_name(&entry_name) {
                if !pending_names.contains(entry_pkg.as_str()) {
                    continue;
                }
            }
            queue.push_back(entry_nm);
        }
    }

    // ------------------------------------------------------------------
    // Private helpers – global paths
    // ------------------------------------------------------------------

    /// Collect global `node_modules` paths from all known package managers.
    fn get_global_node_modules_paths(&self) -> Vec<PathBuf> {
        let mut seen = HashSet::new();
        let mut paths = Vec::new();

        let mut add = |p: PathBuf| {
            if p.is_dir() && seen.insert(p.clone()) {
                paths.push(p);
            }
        };

        if let Ok(npm_path) = get_npm_global_prefix() {
            add(PathBuf::from(npm_path));
        }
        if let Some(pnpm_path) = get_pnpm_global_prefix() {
            add(PathBuf::from(pnpm_path));
        }
        if let Some(yarn_path) = get_yarn_global_prefix() {
            add(PathBuf::from(yarn_path));
        }
        if let Some(bun_path) = get_bun_global_prefix() {
            add(PathBuf::from(bun_path));
        }

        // macOS-specific fallback paths
        #[cfg(target_os = "macos")]
        {
            let home = std::env::var("HOME").unwrap_or_default();

            // Homebrew Apple Silicon
            add(PathBuf::from("/opt/homebrew/lib/node_modules"));
            // Homebrew Intel / default npm
            add(PathBuf::from("/usr/local/lib/node_modules"));

            if !home.is_empty() {
                // nvm
                for p in find_node_dirs_sync(
                    &PathBuf::from(&home).join(".nvm/versions/node"),
                    &["*", "lib", "node_modules"],
                ) {
                    add(p);
                }
                // volta
                for p in find_node_dirs_sync(
                    &PathBuf::from(&home).join(".volta/tools/image/node"),
                    &["*", "lib", "node_modules"],
                ) {
                    add(p);
                }
                // fnm
                for p in find_node_dirs_sync(
                    &PathBuf::from(&home).join(".fnm/node-versions"),
                    &["*", "installation", "lib", "node_modules"],
                ) {
                    add(p);
                }
            }
        }

        paths
    }

    // ------------------------------------------------------------------
    // Private helpers – local node_modules discovery
    // ------------------------------------------------------------------

    /// Find `node_modules` directories within the project root.
    /// Recursively searches for workspace `node_modules` but stays within the
    /// project.
    async fn find_local_node_modules_dirs(&self, start_path: &Path) -> Vec<PathBuf> {
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
    async fn list_pnpm_store_entries(store_path: &Path) -> Vec<(String, PathBuf)> {
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
    async fn collect_nested_store_entries(host_path: &Path, entries: &mut Vec<(String, PathBuf)>) {
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

    // ------------------------------------------------------------------
    // Private helpers – PURL parsing
    // ------------------------------------------------------------------

    /// Parse a PURL string to extract namespace, name, and version.
    fn parse_purl_components(purl: &str) -> Option<(Option<String>, String, String)> {
        let base = strip_purl_qualifiers(purl);

        let rest = base.strip_prefix("pkg:npm/")?;
        let at_idx = rest.rfind('@')?;
        let name_part = &rest[..at_idx];
        let version = &rest[at_idx + 1..];

        if name_part.is_empty() || version.is_empty() {
            return None;
        }

        // SECURITY: components are percent-decoded AFTER the `/`/`@` splits
        // above (so an encoded `%2f` cannot create a new path segment here)
        // and BEFORE the `is_safe_npm_component` guards in `find_by_purls`
        // (so `%2e%2e` cannot smuggle a traversal past them). The API serves
        // scoped purls as `pkg:npm/%40scope/name@version`, which must match
        // the literal `node_modules/@scope/name` install.
        let version = percent_decode_purl_component(version);

        if let Some(slash_idx) = name_part.find('/') {
            let namespace = percent_decode_purl_component(&name_part[..slash_idx]);
            let name = percent_decode_purl_component(&name_part[slash_idx + 1..]);
            // An npm namespace is always an `@scope` (checked post-decode).
            if name.is_empty() || !namespace.starts_with('@') {
                return None;
            }
            Some((
                Some(namespace.into_owned()),
                name.into_owned(),
                version.into_owned(),
            ))
        } else {
            let name = percent_decode_purl_component(name_part);
            // A bare `@scope` with no `/name` is not a package name.
            if name.starts_with('@') {
                return None;
            }
            Some((None, name.into_owned(), version.into_owned()))
        }
    }
}

impl Default for NpmCrawler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Whether a PURL-derived path component is safe to join onto the
/// `node_modules` root. An npm package's scope (`@types`) and bare name
/// (`node`) are each a single path segment, so a real one never contains a
/// separator, a `.`/`..` segment, a backslash, a colon, or a NUL.
/// `find_by_purls` joins these straight from the (untrusted) manifest PURL
/// onto the `node_modules` root and then patches the resolved package in
/// place, so a tampered PURL like `pkg:npm/../../evil@1.0.0` would otherwise
/// read (and later write) out of tree. Delegates to
/// [`path_safety::is_safe_single_segment`], which also rejects `:` — a
/// Windows drive-relative component (`C:evil`) joins as an absolute path.
/// Fails closed. Twin of the deno (`is_safe_jsr_component`), go, and maven
/// coordinate gates.
fn is_safe_npm_component(component: &str) -> bool {
    path_safety::is_safe_single_segment(component)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_package_name_scoped() {
        let (ns, name) = parse_package_name("@types/node");
        assert_eq!(ns.as_deref(), Some("@types"));
        assert_eq!(name, "node");
    }

    #[test]
    fn test_parse_package_name_unscoped() {
        let (ns, name) = parse_package_name("lodash");
        assert!(ns.is_none());
        assert_eq!(name, "lodash");
    }

    #[test]
    fn test_build_npm_purl_scoped() {
        assert_eq!(
            build_npm_purl(Some("@types"), "node", "20.0.0"),
            "pkg:npm/@types/node@20.0.0"
        );
    }

    #[test]
    fn test_build_npm_purl_unscoped() {
        assert_eq!(
            build_npm_purl(None, "lodash", "4.17.21"),
            "pkg:npm/lodash@4.17.21"
        );
    }

    #[test]
    fn test_parse_purl_components_scoped() {
        let (ns, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/@types/node@20.0.0").unwrap();
        assert_eq!(ns.as_deref(), Some("@types"));
        assert_eq!(name, "node");
        assert_eq!(ver, "20.0.0");
    }

    #[test]
    fn test_parse_purl_components_unscoped() {
        let (ns, name, ver) = NpmCrawler::parse_purl_components("pkg:npm/lodash@4.17.21").unwrap();
        assert!(ns.is_none());
        assert_eq!(name, "lodash");
        assert_eq!(ver, "4.17.21");
    }

    #[test]
    fn test_parse_purl_components_invalid() {
        assert!(NpmCrawler::parse_purl_components("pkg:pypi/requests@2.0").is_none());
        assert!(NpmCrawler::parse_purl_components("not-a-purl").is_none());
    }

    /// The `?qualifier` is stripped *before* `rfind('@')` splits the
    /// version, so an `@` living inside a qualifier value
    /// (`vcs_url=git@github.com:...`) must not be mistaken for the
    /// version separator. Reordering those two steps would parse the
    /// version as `github.com:...` and break apply/rollback for any
    /// PURL whose qualifier carries an `@`.
    #[test]
    fn test_parse_purl_components_qualifier_with_at_sign() {
        let (ns, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/foo@1.0.0?vcs_url=git@github.com:x/y.git")
                .unwrap();
        assert!(ns.is_none());
        assert_eq!(name, "foo");
        assert_eq!(ver, "1.0.0");

        let (ns, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/@types/node@20.0.0?maintainer=a@b.com")
                .unwrap();
        assert_eq!(ns.as_deref(), Some("@types"));
        assert_eq!(name, "node");
        assert_eq!(ver, "20.0.0");
    }

    #[tokio::test]
    async fn test_read_package_json_valid() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        tokio::fs::write(&pkg_json, r#"{"name": "test-pkg", "version": "1.0.0"}"#)
            .await
            .unwrap();

        let result = read_package_json(&pkg_json).await;
        assert!(result.is_some());
        let (name, version) = result.unwrap();
        assert_eq!(name, "test-pkg");
        assert_eq!(version, "1.0.0");
    }

    #[tokio::test]
    async fn test_read_package_json_missing() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        assert!(read_package_json(&pkg_json).await.is_none());
    }

    #[tokio::test]
    async fn test_read_package_json_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        tokio::fs::write(&pkg_json, "not json").await.unwrap();
        assert!(read_package_json(&pkg_json).await.is_none());
    }

    #[tokio::test]
    async fn test_crawl_all_basic() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        let pkg_dir = nm.join("foo");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.2.3"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "foo");
        assert_eq!(packages[0].version, "1.2.3");
        assert_eq!(packages[0].purl, "pkg:npm/foo@1.2.3");
        assert!(packages[0].namespace.is_none());
    }

    #[tokio::test]
    async fn test_crawl_all_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        let scope_dir = nm.join("@types").join("node");
        tokio::fs::create_dir_all(&scope_dir).await.unwrap();
        tokio::fs::write(
            scope_dir.join("package.json"),
            r#"{"name": "@types/node", "version": "20.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "node");
        assert_eq!(packages[0].namespace.as_deref(), Some("@types"));
        assert_eq!(packages[0].purl, "pkg:npm/@types/node@20.0.0");
    }

    #[test]
    fn test_find_node_dirs_sync_wildcard() {
        // Create an nvm-like layout: base/v18.0.0/lib/node_modules
        let dir = tempfile::tempdir().unwrap();
        let nm1 = dir.path().join("v18.0.0/lib/node_modules");
        let nm2 = dir.path().join("v20.1.0/lib/node_modules");
        std::fs::create_dir_all(&nm1).unwrap();
        std::fs::create_dir_all(&nm2).unwrap();

        let results = find_node_dirs_sync(dir.path(), &["*", "lib", "node_modules"]);
        assert_eq!(results.len(), 2);
        assert!(results.contains(&nm1));
        assert!(results.contains(&nm2));
    }

    #[test]
    fn test_find_node_dirs_sync_empty() {
        // Non-existent base path should return empty
        let results = find_node_dirs_sync(Path::new("/nonexistent/path/xyz"), &["*", "lib"]);
        assert!(results.is_empty());
    }

    /// Regression: a wildcard segment that matches a *symlinked*
    /// directory must be followed. `DirEntry::metadata()` stats the link
    /// itself (reports `is_dir == false`), so the resolver previously
    /// skipped symlinked version dirs — exactly the layout fnm produces
    /// and the `current`/`default` aliases nvm creates. The fix stats the
    /// joined path with `std::fs::metadata`, which resolves the target.
    #[cfg(unix)]
    #[test]
    fn test_find_node_dirs_sync_follows_symlinked_segment() {
        use std::os::unix::fs::symlink;

        // Real version layout lives in its own tree, away from `base`,
        // so the only way to reach it is through the symlink.
        let real = tempfile::tempdir().unwrap();
        let real_nm = real.path().join("lib").join("node_modules");
        std::fs::create_dir_all(&real_nm).unwrap();

        // `base` holds only a symlink standing in for a version dir.
        let base = tempfile::tempdir().unwrap();
        let alias = base.path().join("current");
        symlink(real.path(), &alias).unwrap();

        let results = find_node_dirs_sync(base.path(), &["*", "lib", "node_modules"]);
        assert_eq!(
            results.len(),
            1,
            "a symlinked version dir must be followed, not skipped"
        );
        assert_eq!(results[0], alias.join("lib").join("node_modules"));
    }

    #[test]
    fn test_find_node_dirs_sync_literal() {
        // All literal segments (no wildcard)
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("lib/node_modules");
        std::fs::create_dir_all(&target).unwrap();

        let results = find_node_dirs_sync(dir.path(), &["lib", "node_modules"]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], target);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_get_global_node_modules_paths_no_panic() {
        let crawler = NpmCrawler::new();
        // Should not panic, even if no package managers are installed
        let _paths = crawler.get_global_node_modules_paths();
    }

    #[tokio::test]
    async fn test_find_by_purls() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");

        // Create foo@1.0.0
        let foo_dir = nm.join("foo");
        tokio::fs::create_dir_all(&foo_dir).await.unwrap();
        tokio::fs::write(
            foo_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        // Create @types/node@20.0.0
        let types_dir = nm.join("@types").join("node");
        tokio::fs::create_dir_all(&types_dir).await.unwrap();
        tokio::fs::write(
            types_dir.join("package.json"),
            r#"{"name": "@types/node", "version": "20.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let purls = vec![
            "pkg:npm/foo@1.0.0".to_string(),
            "pkg:npm/@types/node@20.0.0".to_string(),
            "pkg:npm/not-installed@0.0.1".to_string(),
        ];

        let result = crawler.find_by_purls(&nm, &purls).await.unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains_key("pkg:npm/foo@1.0.0"));
        assert!(result.contains_key("pkg:npm/@types/node@20.0.0"));
        assert!(!result.contains_key("pkg:npm/not-installed@0.0.1"));
    }

    /// Regression: the patches API serves scoped purls percent-encoded
    /// (`pkg:npm/%40scope/name@version`) and `scan` stores them verbatim as
    /// manifest keys. `find_by_purls` must decode the components to match
    /// the literal `node_modules/@scope/name` install — while keeping the
    /// result keyed by the *verbatim* encoded input (downstream contract).
    #[test]
    fn test_parse_purl_components_percent_encoded_scope() {
        let (ns, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/%40modelcontextprotocol/sdk@1.12.0")
                .unwrap();
        assert_eq!(ns.as_deref(), Some("@modelcontextprotocol"));
        assert_eq!(name, "sdk");
        assert_eq!(ver, "1.12.0");
        // An encoded bare scope with no `/name` is still not a package.
        assert!(NpmCrawler::parse_purl_components("pkg:npm/%40scope@1.0.0").is_none());
        // A `#subpath` without a qualifier must not bleed into the version.
        let (_, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/foo@1.0.0#lib/util").unwrap();
        assert_eq!(name, "foo");
        assert_eq!(ver, "1.0.0");
    }

    #[tokio::test]
    async fn test_find_by_purls_percent_encoded_scope_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");

        let sdk_dir = nm.join("@modelcontextprotocol").join("sdk");
        tokio::fs::create_dir_all(&sdk_dir).await.unwrap();
        tokio::fs::write(
            sdk_dir.join("package.json"),
            r#"{"name": "@modelcontextprotocol/sdk", "version": "1.12.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let encoded = "pkg:npm/%40modelcontextprotocol/sdk@1.12.0".to_string();
        let result = crawler
            .find_by_purls(&nm, std::slice::from_ref(&encoded))
            .await
            .unwrap();

        assert_eq!(result.len(), 1, "encoded scope must resolve: {result:?}");
        let pkg = result
            .get(&encoded)
            .expect("result keyed by the verbatim encoded input purl");
        assert_eq!(pkg.path, sdk_dir);
        assert_eq!(pkg.name, "sdk");
        assert_eq!(pkg.namespace.as_deref(), Some("@modelcontextprotocol"));
    }

    /// SECURITY regression: percent-encoded traversal sequences must be
    /// rejected by the post-decode guards — `%2e%2e` decodes to `..` and
    /// `%2f` to `/`, so guarding the *encoded* form would be a bypass.
    #[tokio::test]
    async fn test_find_by_purls_rejects_encoded_traversal() {
        let root = tempfile::tempdir().unwrap();
        let nm = root.path().join("node_modules");
        // A real scope dir so a scoped traversal's kernel walk could resolve.
        tokio::fs::create_dir_all(nm.join("@x")).await.unwrap();

        // A victim package OUTSIDE node_modules, reachable only via `..`.
        let evil_dir = root.path().join("evil");
        tokio::fs::create_dir_all(&evil_dir).await.unwrap();
        tokio::fs::write(
            evil_dir.join("package.json"),
            r#"{"name": "evil", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let purls = vec![
            "pkg:npm/%2e%2e/evil@1.0.0".to_string(),
            "pkg:npm/@x/%2e%2e@1.0.0".to_string(),
            "pkg:npm/@x/%2e%2e%2f%2e%2e%2fevil@1.0.0".to_string(),
            "pkg:npm/..%2fevil@1.0.0".to_string(),
        ];
        let result = crawler.find_by_purls(&nm, &purls).await.unwrap();

        assert!(
            result.is_empty(),
            "encoded traversal must not escape node_modules; got {result:?}"
        );
    }

    /// Regression: a qualified PURL (carrying `?qualifiers`) must resolve and
    /// be keyed by the *verbatim* input PURL — not a reconstructed, stripped
    /// form. The dispatcher drives npm with `passthrough_purls` +
    /// `merge_first_wins`, so it looks the result back up under the exact PURL
    /// it passed in. Keying by the stripped PURL silently dropped every
    /// qualified npm PURL from apply/rollback.
    #[tokio::test]
    async fn test_find_by_purls_resolves_qualified_purl_keyed_by_input() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");

        let foo_dir = nm.join("foo");
        tokio::fs::create_dir_all(&foo_dir).await.unwrap();
        tokio::fs::write(
            foo_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        // Scoped package with a qualifier too.
        let types_dir = nm.join("@types").join("node");
        tokio::fs::create_dir_all(&types_dir).await.unwrap();
        tokio::fs::write(
            types_dir.join("package.json"),
            r#"{"name": "@types/node", "version": "20.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let unscoped_q = "pkg:npm/foo@1.0.0?vcs_url=https://github.com/x/foo".to_string();
        let scoped_q = "pkg:npm/@types/node@20.0.0?repository_url=https://npmjs.org".to_string();
        let purls = vec![unscoped_q.clone(), scoped_q.clone()];

        let result = crawler.find_by_purls(&nm, &purls).await.unwrap();

        assert_eq!(result.len(), 2);
        // Keyed by the verbatim qualified input, and the stored PURL matches.
        let foo = result
            .get(&unscoped_q)
            .expect("qualified unscoped resolved");
        assert_eq!(foo.purl, unscoped_q);
        assert_eq!(foo.name, "foo");
        assert_eq!(foo.version, "1.0.0");

        let node = result.get(&scoped_q).expect("qualified scoped resolved");
        assert_eq!(node.purl, scoped_q);
        assert_eq!(node.namespace.as_deref(), Some("@types"));
        assert_eq!(node.name, "node");
    }

    /// Two distinct qualifiers over the same base package must each resolve
    /// to their own entry (the dispatcher passes them through verbatim).
    #[tokio::test]
    async fn test_find_by_purls_distinct_qualifiers_same_base() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        let foo_dir = nm.join("foo");
        tokio::fs::create_dir_all(&foo_dir).await.unwrap();
        tokio::fs::write(
            foo_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let q1 = "pkg:npm/foo@1.0.0?a=1".to_string();
        let q2 = "pkg:npm/foo@1.0.0?b=2".to_string();

        let crawler = NpmCrawler::new();
        let result = crawler
            .find_by_purls(&nm, &[q1.clone(), q2.clone()])
            .await
            .unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result.get(&q1).unwrap().path, foo_dir);
        assert_eq!(result.get(&q2).unwrap().path, foo_dir);
    }

    /// SECURITY regression: a tampered manifest PURL whose *name* carries a
    /// `..` traversal must not let `find_by_purls` resolve a package outside
    /// the `node_modules` root. The crawler joins the PURL-derived directory
    /// key straight onto `node_modules_path` and the resolved path is then
    /// patched in place, so an unguarded join would read (and later write)
    /// out of tree. Twin of the deno/go/maven `is_safe_*_coordinate` gates.
    #[tokio::test]
    async fn test_find_by_purls_rejects_traversal_in_name() {
        let root = tempfile::tempdir().unwrap();
        let nm = root.path().join("node_modules");
        tokio::fs::create_dir_all(&nm).await.unwrap();

        // A victim package living OUTSIDE node_modules, reachable only via
        // `..`. `node_modules/../evil` == `<root>/evil`.
        let evil_dir = root.path().join("evil");
        tokio::fs::create_dir_all(&evil_dir).await.unwrap();
        tokio::fs::write(
            evil_dir.join("package.json"),
            r#"{"name": "evil", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let traversal = "pkg:npm/../evil@1.0.0".to_string();
        let result = crawler
            .find_by_purls(&nm, std::slice::from_ref(&traversal))
            .await
            .unwrap();

        assert!(
            result.is_empty(),
            "a `..` in the PURL name must not escape node_modules; got {result:?}"
        );
    }

    /// SECURITY regression: a `..` smuggled through the *name* half of a
    /// scoped PURL must also be rejected. `@x/../../evil` parses to scope
    /// `@x` + name `../../evil`; with a real `@x` dir on disk for the kernel
    /// to walk, the join climbs clean out of node_modules to `<root>/evil`.
    #[tokio::test]
    async fn test_find_by_purls_rejects_traversal_via_scope() {
        let root = tempfile::tempdir().unwrap();
        let nm = root.path().join("node_modules");
        // A real scope dir so the kernel can resolve the leading `@x` before
        // the `..` segments climb — otherwise the walk would ENOENT and the
        // test would pass vacuously.
        tokio::fs::create_dir_all(nm.join("@x")).await.unwrap();

        let evil_dir = root.path().join("evil");
        tokio::fs::create_dir_all(&evil_dir).await.unwrap();
        tokio::fs::write(
            evil_dir.join("package.json"),
            r#"{"name": "evil", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let traversal = "pkg:npm/@x/../../evil@1.0.0".to_string();
        let result = crawler
            .find_by_purls(&nm, std::slice::from_ref(&traversal))
            .await
            .unwrap();

        assert!(
            result.is_empty(),
            "a `..` smuggled through the scope must not escape node_modules; got {result:?}"
        );
    }

    #[test]
    fn test_is_safe_npm_component() {
        // Legitimate components.
        assert!(is_safe_npm_component("lodash"));
        assert!(is_safe_npm_component("@types"));
        assert!(is_safe_npm_component("node"));
        assert!(is_safe_npm_component("some.pkg"));

        // Traversal / separator / NUL / empty.
        assert!(!is_safe_npm_component(""));
        assert!(!is_safe_npm_component("."));
        assert!(!is_safe_npm_component(".."));
        assert!(!is_safe_npm_component("../evil"));
        assert!(!is_safe_npm_component("a/b"));
        assert!(!is_safe_npm_component("a\\b"));
        assert!(!is_safe_npm_component("a\0b"));
        // Windows drive-relative escape: a `:` (e.g. `C:evil`) makes the
        // joined path absolute under `Path::join`.
        assert!(!is_safe_npm_component("C:evil"));
        assert!(!is_safe_npm_component("c:"));
    }

    // ── decode_pnpm_store_entry_name ───────────────────────────────

    /// Helper: decode and unwrap into owned strings for terse asserts.
    fn decoded(entry: &str) -> Option<(String, String)> {
        decode_pnpm_store_entry_name(entry)
    }

    #[test]
    fn test_decode_pnpm_store_entry_plain() {
        assert_eq!(
            decoded("mkdirp@0.5.5"),
            Some(("mkdirp".into(), "0.5.5".into()))
        );
    }

    #[test]
    fn test_decode_pnpm_store_entry_scoped_plus_escape() {
        assert_eq!(
            decoded("@scope+leaf@2.0.0"),
            Some(("@scope/leaf".into(), "2.0.0".into()))
        );
    }

    #[test]
    fn test_decode_pnpm_store_entry_v9_peer_parens() {
        // Single and stacked peer suffixes, including a scoped peer whose
        // own name carries `@`/`+` — everything from the first `(` goes.
        assert_eq!(
            decoded("foo@1.0.0(bar@2.0.0)"),
            Some(("foo".into(), "1.0.0".into()))
        );
        assert_eq!(
            decoded("foo@1.0.0(bar@2.0.0)(@babel+core@7.21.0)"),
            Some(("foo".into(), "1.0.0".into()))
        );
        assert_eq!(
            decoded("@scope+leaf@2.0.0(@peer+dep@3.0.0)"),
            Some(("@scope/leaf".into(), "2.0.0".into()))
        );
    }

    #[test]
    fn test_decode_pnpm_store_entry_legacy_underscore_suffix() {
        // pnpm 6–8 peer suffix — everything from the first `_` goes, even
        // when the suffix itself carries `@version` fragments that would
        // otherwise confuse the rfind('@') split.
        assert_eq!(
            decoded("foo@1.0.0_bar@2.0.0"),
            Some(("foo".into(), "1.0.0".into()))
        );
        assert_eq!(
            decoded("@scope+name@1.0.0_@peer+dep@2.0.0"),
            Some(("@scope/name".into(), "1.0.0".into()))
        );
    }

    #[test]
    fn test_decode_pnpm_store_entry_prerelease_version() {
        assert_eq!(
            decoded("foo@1.0.0-rc.1(bar@2.0.0)"),
            Some(("foo".into(), "1.0.0-rc.1".into()))
        );
    }

    /// pnpm truncates over-long dir names ANYWHERE and appends `_<hash>`.
    /// A cut mid-name leaves no `@X.Y.Z` tail → None (conservative: the
    /// entry stays probeable). A cut that lands after a `name@X.Y.Z`
    /// prefix is an undetectable artifact — it decodes, pinned here so
    /// the contract ("decoded is advisory, probe is authority") is
    /// explicit. A cut mid-version (`@1.2`) fails the semver-triple
    /// check → None.
    #[test]
    fn test_decode_pnpm_store_entry_truncation_hash_tail() {
        assert_eq!(decoded("some-truncated-name-prefix_abc123def456"), None);
        assert_eq!(decoded("foo@1.2_abc123def456"), None);
        assert_eq!(
            decoded("foo@1.2.3_abc123def456"),
            Some(("foo".into(), "1.2.3".into())),
            "truncation after a full name@X.Y.Z prefix is indistinguishable \
             from a legacy peer suffix — decodes, and that is acceptable \
             because the package.json probe stays the authority"
        );
    }

    /// Names that are not registry package entries at all.
    #[test]
    fn test_decode_pnpm_store_entry_non_package_names() {
        // Store metadata file.
        assert_eq!(decoded("lock.yaml"), None);
        // The internal hoist dir (also skipped by the enumerator).
        assert_eq!(decoded("node_modules"), None);
        // No version at all.
        assert_eq!(decoded("foo"), None);
        // Empty name half.
        assert_eq!(decoded("@1.0.0"), None);
        // Empty version half.
        assert_eq!(decoded("foo@"), None);
    }

    /// A real npm name containing `_` is indistinguishable from a legacy
    /// peer suffix, so it must fall to the conservative None (the entry
    /// stays reachable via the fallback rule).
    #[test]
    fn test_decode_pnpm_store_entry_underscore_name_falls_back() {
        assert_eq!(decoded("lodash._baseclone@1.0.0"), None);
    }

    /// Git/URL dependency entries carry a sha or URL fragment where the
    /// version would be — not a semver triple → None → still probeable.
    #[test]
    fn test_decode_pnpm_store_entry_git_url_deps_fall_back() {
        assert_eq!(decoded("foo@github.com+user+repo@4a3b2c1d9e8f"), None);
        assert_eq!(
            decoded("foo@https+++codeload.github.com+x+tar.gz+abc"),
            None
        );
    }

    /// A PURL whose version is not the one on disk must be skipped, while a
    /// sibling PURL for the installed version is kept.
    #[tokio::test]
    async fn test_find_by_purls_skips_absent_version_keeps_present() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        let foo_dir = nm.join("foo");
        tokio::fs::create_dir_all(&foo_dir).await.unwrap();
        tokio::fs::write(
            foo_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let result = crawler
            .find_by_purls(
                &nm,
                &[
                    "pkg:npm/foo@1.0.0".to_string(),
                    "pkg:npm/foo@9.9.9".to_string(),
                ],
            )
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:npm/foo@1.0.0"));
        assert!(!result.contains_key("pkg:npm/foo@9.9.9"));
    }
}
