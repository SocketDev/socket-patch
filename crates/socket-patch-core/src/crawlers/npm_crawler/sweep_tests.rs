//! Seeded npm project trees, pinned by golden (see `crate::golden`):
//! flat/nested/legacy pnpm stores, scoped packages, symlinks (live,
//! dangling, into the store), duplicate identities, aliases, broken / BOM'd
//! / FIFO / directory package.json, unreadable and unsearchable dirs, and
//! case variants of `node_modules`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::NpmCrawler;
use crate::crawlers::types::{CrawledPackage, CrawlerOptions};
use crate::test_rng::Rng;

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
    rng: Rng,
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
            rng: Rng::new(seed),
            scratch,
            pkg_dirs: Vec::new(),
            nm_dirs: Vec::new(),
            lock_plan: Vec::new(),
            uniq: 0,
        }
    }

    fn below(&mut self, n: usize) -> usize {
        self.rng.below(n)
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.rng.chance(percent)
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        self.rng.pick(items)
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
        if store_ok && self.chance(20) {
            let vlt_pkgs = self.vlt_store(&nm.join(".vlt"), depth);
            store_pkgs.extend(vlt_pkgs);
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

    /// A `.vlt` store; returns `(name, package dir)` of the entries'
    /// own packages (importer link targets). DepIDs of every era and
    /// shape, with the store's hoist dir, rollback staging, metadata
    /// file, dependency links and a linked `node_modules` mixed in.
    fn vlt_store(&mut self, store: &Path, depth: usize) -> Vec<(String, PathBuf)> {
        let _ = std::fs::create_dir_all(store);
        let _ = std::fs::write(store.join("vlt.json"), "{}");
        let mut own = Vec::new();
        for _ in 0..1 + self.below(6) {
            let name = self.pick(NAMES).to_string();
            let version = self.pick(VERSIONS).to_string();
            let escaped = name.replace('/', "+");
            let id = match self.below(10) {
                0 => format!("~npm~{escaped}@{version}~peer.{}", self.uniq()),
                1 => format!("··{}@{version}", name.replace('/', "§")),
                2 => format!("·npm·{}@{version}", name.replace('/', "§")),
                3 => format!("git~github_cu+r~v{}", self.uniq()),
                4 => format!(".VLT.DELETE.{}.~npm~{escaped}@{version}", self.uniq()),
                5 => "node_modules".to_string(),
                _ => format!("~npm~{escaped}@{version}"),
            };
            let entry = store.join(&id);
            if entry.symlink_metadata().is_ok() {
                continue;
            }
            let entry_nm = entry.join("node_modules");
            if self.chance(5) {
                let _ = std::fs::create_dir_all(&entry);
                let id = self.uniq();
                let elsewhere = self.scratch.join(format!("vlt-nm{id}"));
                self.package_json(&elsewhere.join(&name), &name, &version);
                Self::symlink(&elsewhere, &entry_nm);
                continue;
            }
            let pkg_name = if self.chance(90) {
                name.clone()
            } else {
                self.pick(NAMES).to_string()
            };
            let pkg = entry_nm.join(&name);
            self.package_json(&pkg, &pkg_name, &version);
            self.pkg_dirs.push(pkg.clone());
            own.push((name.clone(), pkg.clone()));
            for _ in 0..self.below(3) {
                if let Some((dep, target)) = own.first().cloned() {
                    Self::symlink(&target, &entry_nm.join(&dep));
                }
            }
            if depth < 2 && self.chance(25) {
                self.node_modules(&pkg.join("node_modules"), depth + 1, false);
            }
            if self.chance(4) {
                self.plan_lock(&entry_nm, 0o000);
            }
        }
        own
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

async fn check(root: &Path) {
    let base = root.parent().unwrap();
    let rel = |p: &Path| crate::crawlers::test_tree::rel(base, p);
    let rel_rows = |pkgs: &[CrawledPackage]| crate::crawlers::test_tree::rel_rows(base, pkgs);
    let rel_pairs = |v: &[(String, PathBuf)]| -> Vec<(String, String)> {
        v.iter().map(|(k, p)| (k.clone(), rel(p))).collect()
    };
    let input = crate::crawlers::test_tree::tree_listing(base);
    let mut per_nm = Vec::new();
    let options = CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
    };
    let crawler = NpmCrawler::new();

    let new_paths = crawler.get_node_modules_paths(&options).await.unwrap();
    let new_pkgs = crawler.crawl_all(&options).await;

    let purls = probe_purls(&new_pkgs);
    for nm in &new_paths {
        let new_found = crawler.find_by_purls(nm, &purls).await.unwrap();
        let store = nm.join(".pnpm");
        let vlt = nm.join(".vlt");
        let legacy = nm.join(".registry.npmjs.org");
        let mut new_nested = Vec::new();
        NpmCrawler::collect_nested_store_entries(&legacy, &mut new_nested).await;
        let found: BTreeMap<String, Vec<_>> = new_found
            .iter()
            .map(|(k, v)| (k.clone(), rel_rows(v)))
            .collect();
        let vlt: Vec<(String, String)> = NpmCrawler::list_vlt_store_entries(&vlt)
            .await
            .iter()
            .map(|(k, p)| (k.to_string_lossy().into_owned(), rel(p)))
            .collect();
        per_nm.push((
            rel(nm),
            found,
            rel_pairs(&NpmCrawler::list_pnpm_store_entries(&store).await),
            vlt,
            rel_pairs(&new_nested),
        ));
    }
    let paths: Vec<String> = new_paths.iter().map(|p| rel(p)).collect();
    crate::golden::record(&input, &(paths, rel_rows(&new_pkgs), per_nm));
}

#[tokio::test(flavor = "multi_thread")]
async fn randomized_trees_match_golden() {
    let sweep = crate::golden::Sweep::start(
        "crawl_npm_trees",
        "One seeded project tree: node_modules roots, crawl_all, find_by_purls and store listings.",
    );
    let mut nonempty = 0;
    for seed in 0..64u64 {
        let tmp = tempfile::tempdir().unwrap();
        let mut guard = PermGuard(Vec::new());
        let root = tmp.path().join("proj");
        let mut gen = Gen::new(seed, tmp.path().join("scratch"));
        gen.workspace(&root, 0);
        gen.apply_locks(&mut guard);

        check(&root).await;
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
    // or the golden above is vacuous.
    assert!(nonempty > 32, "only {nonempty} non-empty trees");
    if crate::crawlers::test_tree::crawl_goldens_apply(true) {
        sweep.finish();
    }
}

/// A store entry whose own child's package.json disagrees with the
/// entry's name@version, for a root-installed package: the sequential
/// walk skips that child by name (`identity_seen`) without reading it,
/// so the foreign identity must never surface.
#[tokio::test]
async fn store_entry_child_with_a_foreign_identity_is_skipped() {
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

    let sweep = crate::golden::Sweep::start(
        "crawl_npm_foreign_identity",
        "A pnpm store entry whose child names a foreign identity.",
    );
    check(&root).await;
    if crate::crawlers::test_tree::crawl_goldens_apply(false) {
        sweep.finish();
    }

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
/// sequentially on the calling thread and still matches the golden.
#[tokio::test]
async fn walk_without_a_pool_matches_golden() {
    let _off = crate::crawlers::walk_pool::test_hooks::DisablePool::new();
    let sweep = crate::golden::Sweep::start(
        "crawl_npm_no_pool",
        "One seeded project tree, walked with no walk pool.",
    );
    for seed in 0..16u64 {
        let tmp = tempfile::tempdir().unwrap();
        let mut guard = PermGuard(Vec::new());
        let root = tmp.path().join("proj");
        let mut gen = Gen::new(seed, tmp.path().join("scratch"));
        gen.workspace(&root, 0);
        gen.apply_locks(&mut guard);
        check(&root).await;
        drop(guard);
    }
    if crate::crawlers::test_tree::crawl_goldens_apply(true) {
        sweep.finish();
    }
}

/// Hand-built tree with one of every tricky shape (so each is covered
/// regardless of what the random generator happens to draw), pinned by
/// golden, with a few load-bearing outcomes asserted outright.
#[tokio::test]
async fn kitchen_sink_tree_matches_golden() {
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

    let sweep = crate::golden::Sweep::start(
        "crawl_npm_kitchen_sink",
        "A hand-built project tree with one of every tricky shape.",
    );
    check(&root).await;
    if crate::crawlers::test_tree::crawl_goldens_apply(true) {
        sweep.finish();
    }

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
