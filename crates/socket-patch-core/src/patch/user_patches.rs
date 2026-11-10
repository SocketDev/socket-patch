//! Read-only evidence of patches owned by the project, not Socket.
//!
//! A matching declaration is sufficient: the patch need not have been installed
//! yet, and need not touch the same file as the Socket fix. Never execute hooks
//! or fetch patch URLs to establish ownership.

use std::collections::{BTreeSet, VecDeque};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::formats::package_json::Workspaces;
use crate::formats::text::strip_bom;
use crate::utils::fs::read_regular_to_string;
use crate::utils::npm_range::npm_range_admits;
use crate::utils::purl::{normalize_purl, strip_purl_qualifiers};
use crate::utils::relpath::normalize_lexically_keeping_escapes;
use crate::utils::workspace_globs::{workspaces_include_as, WorkspacesDialect};
use crate::vendor::lock_inventory::ProjectView;

#[derive(Default, Debug)]
pub struct UserPatchIndex {
    entries: Vec<Evidence>,
}

#[derive(Debug)]
struct Evidence {
    ecosystem: &'static str,
    name: String,
    version: Option<String>,
    source: String,
    /// The file could not be read or parsed, so what it declares is not
    /// known: it protects its ecosystem, and the remedy is to fix the
    /// file (see [`UserPatchIndex::unreadable_only`]).
    unreadable: bool,
}

impl UserPatchIndex {
    /// Inspect the project, declared workspace members and ancestor workspace
    /// settings. Errors in a potentially governing file protect its ecosystem;
    /// unreadable metadata must not silently disable the consent check.
    ///
    /// A workspace run: nothing outside the git repository root is read
    /// (see [`Self::discover_scoped`]).
    pub async fn discover(root: &Path) -> Self {
        Self::discover_scoped(root, ReadScope::Workspace).await
    }

    /// [`Self::discover`] in the read scope the run's mode fixes. A
    /// [`ReadScope::Workspace`] run never reads a project file outside the
    /// git repository root: a workspace member or `--patch-dir` beyond it
    /// protects every npm package instead. A [`ReadScope::Global`] run reads
    /// the evidence wherever it lives, with no repository bound and no
    /// such fallback.
    pub async fn discover_scoped(root: &Path, reads: ReadScope) -> Self {
        let root = std::path::absolute(root).unwrap_or_else(|_| root.to_path_buf());
        Self::walk(&ProjectView::Disk(&root), Some(&root), Scope::Gate, reads)
            .await
            .0
    }

    /// The patches a project's pnpm, yarn or patch-package setup applies
    /// to its npm dependencies, read through `view` as the hosted engine
    /// and `vex` discovery read the project, by the very walk of
    /// [`Self::discover`] (the CLI's consent gate): the project, its
    /// declared workspace members and (on disk) the ancestor workspace
    /// settings up to the git repository root. Each directory's
    /// `package.json` (`pnpm.patchedDependencies`, yarn `patch:`
    /// descriptors, patch-package directories: `patches/` and every
    /// `--patch-dir` its scripts name), `pnpm-workspace.yaml`
    /// (`patchedDependencies`), pnpm lock (its `patchedDependencies` map and
    /// `(patch_hash=…)` keys) and `yarn.lock` (user `patch:` locators) are
    /// read, plus `locks` (root-relative path and text: a Rush or member
    /// lock outside the walk). Left out: npm's and Bun's own top-level
    /// `patchedDependencies` and npm's lock-entry `patched` records, which
    /// no other package manager reads and which their own rewriters and
    /// discovery judge per resolution (#711, #367), and the other
    /// ecosystems' declarations. vlt has no patch mechanism of its own, so
    /// a vlt project patches a dependency only through a postinstall tool
    /// such as patch-package. Sources are reported root-relative.
    pub(crate) async fn npm_family_in(view: &ProjectView<'_>, locks: &[(&str, &str)]) -> Self {
        // Discovery and the hosted engine only ever run on a workspace.
        let (mut index, walked) =
            Self::walk(view, None, Scope::NpmFamily, ReadScope::Workspace).await;
        // A directory the walk visited had its pnpm and yarn locks read
        // already; only the others (a Rush lock, `shrinkwrap.yaml`, a lock
        // in a directory the walk never reached) are parsed here.
        let fresh: Vec<(&str, &str)> = locks
            .iter()
            .copied()
            .filter(|(rel, _)| {
                let path = Path::new(rel);
                let dir = path.parent().unwrap_or(Path::new(""));
                !(walked.contains(dir)
                    && matches!(
                        path.file_name().and_then(|n| n.to_str()),
                        Some("pnpm-lock.yaml" | "yarn.lock")
                    ))
            })
            .collect();
        index.add_locks(&fresh);
        index
    }

    /// The patches the pnpm locks (`pnpm-lock.yaml`, `shrinkwrap.yaml`) and
    /// yarn locks among `locks` (root-relative path and text) record, as
    /// [`Self::npm_family_in`] reads them: for a lock no walk reaches, such
    /// as a Rush lock.
    pub fn from_locks(locks: &[(&str, &str)]) -> Self {
        let mut index = Self::default();
        index.add_locks(locks);
        index
    }

    fn add_locks(&mut self, locks: &[(&str, &str)]) {
        for (rel, text) in locks {
            let path = Path::new(rel);
            match rel.rsplit('/').next() {
                Some("pnpm-lock.yaml" | "shrinkwrap.yaml") => {
                    self.pnpm_yaml(strip_bom(text), path, true, false);
                }
                Some("yarn.lock") => self.yarn_lock(text, path),
                _ => {}
            }
        }
    }

    /// Record that the lock at root-relative `rel` exists but could not be
    /// read (a permission error, a FIFO, non-UTF-8 text): its patches are
    /// unknown, so every npm package is protected, as the walk protects
    /// one for a governing file it cannot read. A missing lock is no
    /// evidence and records nothing.
    pub fn unreadable_lock(&mut self, rel: &str, e: &std::io::Error) {
        // A read the repository bound refused carries the `NotFound` kind,
        // but the lock is there.
        if crate::utils::repo_root::is_refused_read(e) || e.kind() != std::io::ErrorKind::NotFound {
            self.unreadable("npm", Path::new(rel), &format!("cannot be read: {e}"));
        }
    }

    /// Whether the index holds no evidence at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The walk [`Self::discover`] and [`Self::npm_family_in`] share. Every
    /// project file is read through `view` at its root-relative path, or,
    /// for an ancestor directory, at its absolute path. `shown_root` is
    /// where reported sources are anchored: the absolute project root for
    /// the gate, `None` for root-relative sources. Also returns the
    /// directories visited (as read: root-relative, or absolute).
    ///
    /// The ancestor walk is git's own repository lookup
    /// ([`crate::utils::repo_root::search_dirs`]: through the directory
    /// holding `.git`, never into the home directory or a
    /// `GIT_CEILING_DIRECTORIES` entry), and each ancestor is checked and
    /// read at the same (canonical) path. In a [`ReadScope::Workspace`] run
    /// nothing outside that git repository root is read: a workspace
    /// member or patch-package directory beyond it protects every package
    /// of the ecosystem that named it instead of being read. An in-memory
    /// project is its own repository root. A [`ReadScope::Global`] run
    /// reads members and patch-package directories wherever they are.
    async fn walk(
        view: &ProjectView<'_>,
        shown_root: Option<&Path>,
        scope: Scope,
        reads: ReadScope,
    ) -> (Self, BTreeSet<std::path::PathBuf>) {
        let mut index = Self::default();
        let shown_base = shown_root.unwrap_or(Path::new(""));
        let at = |rel: &Path| Dir {
            rel: rel.to_path_buf(),
            shown: normalize_lexically_keeping_escapes(&shown_base.join(rel)),
        };
        // Each pending directory with the ecosystem whose declaration
        // brought it in.
        let mut pending = VecDeque::from([(at(Path::new("")), "npm")]);
        let mut bound = Bound::Memory;
        if let Some(root) = view.disk_root_reading(std::iter::empty::<&Path>()) {
            // A member invocation still inherits the workspace's patch
            // policy.
            let dirs = crate::utils::repo_root::search_dirs(root);
            let root_canon = dirs.first().cloned().unwrap_or_else(|| root.to_path_buf());
            // The root's own `.git` decides the bound, so its appearing or
            // going away invalidates a snapshot too.
            let mut probes: Vec<std::path::PathBuf> = vec![root_canon.join(".git")];
            let home = crate::utils::repo_root::home();
            for (depth, parent) in dirs.iter().enumerate().skip(1) {
                // Never the home directory or any directory above it (a
                // project outside home, with no checkout, stops there too),
                // as before the repository bound.
                if home.as_deref().is_some_and(|h| h.starts_with(parent)) {
                    break;
                }
                const MARKERS: [&str; 7] = [
                    "pnpm-workspace.yaml",
                    "go.work",
                    ".cargo/config.toml",
                    ".cargo/config",
                    "package.json",
                    "Cargo.toml",
                    ".git",
                ];
                probes.extend(MARKERS.iter().map(|m| parent.join(m)));
                // Any workspace marker brings the directory in, whichever
                // scope reads it, so both scopes walk the same directories.
                if parent.join("pnpm-workspace.yaml").exists()
                    || parent.join("go.work").exists()
                    || parent.join(".cargo/config.toml").exists()
                    || parent.join(".cargo/config").exists()
                    || read_regular_to_string(&parent.join("package.json"))
                        .await
                        .is_ok_and(|s| s.contains("\"workspaces\""))
                    || read_regular_to_string(&parent.join("Cargo.toml"))
                        .await
                        .is_ok_and(|s| s.contains("[workspace]"))
                {
                    let up: std::path::PathBuf = std::iter::repeat_n("..", depth).collect();
                    pending.push_back((
                        Dir {
                            rel: parent.clone(),
                            shown: shown_root.map_or(up, |_| parent.clone()),
                        },
                        "npm",
                    ));
                }
            }
            // Fingerprint what the probes read for a snapshot's reuse.
            let _ = view.disk_root_reading(&probes);
            bound = match crate::utils::repo_root::find_git_repo(root) {
                Some(repo) => Bound::Disk {
                    root: root_canon,
                    repo: repo.root,
                },
                None => Bound::None,
            };
        }
        // The read bound: the repository root in a workspace run, none in a
        // global one.
        if reads == ReadScope::Global {
            bound = Bound::None;
        }
        let mut seen = BTreeSet::new();
        while let Some((dir, ecosystem)) = pending.pop_front() {
            if !seen.insert(dir.rel.clone()) {
                continue;
            }
            if seen.len() > 4096 {
                index.unknown("npm", &dir.shown, "workspace inspection limit exceeded");
                break;
            }
            if bound.outside(&dir.rel) {
                index.unknown(
                    ecosystem,
                    &dir.shown,
                    "workspace outside the git repository is not inspected",
                );
                continue;
            }
            let mut globs = Vec::new();
            let manifest = dir.file("package.json");
            if let Some(value) = index.json_view(view, &manifest).await {
                if scope == Scope::Gate {
                    index.native(&value, &manifest.shown);
                } else {
                    index.patched_dependencies(
                        &value["pnpm"]["patchedDependencies"],
                        &manifest.shown,
                    );
                }
                index.yarn_manifest(&value, &manifest.shown);
                // A malformed field still names its string items (#1900):
                // walking them can only find more patches.
                globs.extend(Workspaces::of(&value).into_listed().into_iter().flatten());
                index
                    .list_patch_directory(view, &dir.file("patches"), false, &Bound::None)
                    .await;
                for patch_dir in index.patch_package_dirs(&manifest.shown, &value) {
                    let patch_dir = dir.file(&patch_dir);
                    index
                        .list_patch_directory(view, &patch_dir, true, &bound)
                        .await;
                }
            } else {
                index
                    .list_patch_directory(view, &dir.file("patches"), false, &Bound::None)
                    .await;
            }
            let yarn_lock = dir.file("yarn.lock");
            if let Some(text) = index.read_view(view, &yarn_lock, "npm").await {
                index.yarn_lock(&text, &yarn_lock.shown);
            }
            for file in ["pnpm-workspace.yaml", "pnpm-lock.yaml"] {
                let path = dir.file(file);
                if let Some(text) = index.read_view(view, &path, "npm").await {
                    let lock = file == "pnpm-lock.yaml";
                    let any_map = scope == Scope::Gate;
                    for value in index.pnpm_yaml(&text, &path.shown, lock, any_map) {
                        if !lock {
                            if let Some(packages) = value["packages"].as_array() {
                                globs.extend(
                                    packages.iter().filter_map(Value::as_str).map(str::to_owned),
                                );
                            }
                        }
                    }
                }
            }
            if scope == Scope::Gate {
                for member in index.gate_only(view, &dir).await {
                    pending.push_back((at(&member), "golang"));
                }
            }
            for pattern in globs
                .iter()
                .filter(|g| !g.starts_with('!') || g.starts_with("!("))
            {
                for rel in index.workspace_members(view, &dir, pattern, &bound).await {
                    pending.push_back((at(&rel), "npm"));
                }
            }
        }
        (index, seen)
    }

    /// The declarations only the consent gate reads in each directory:
    /// npm's and Bun's lock-entry `patched` records and mirrored maps, and
    /// the Composer, Cargo and Go overrides. Returns a `go.work`'s `use`
    /// members, which join the walk for the Go ecosystem.
    async fn gate_only(&mut self, view: &ProjectView<'_>, dir: &Dir) -> Vec<std::path::PathBuf> {
        let mut members = Vec::new();
        for file in ["package-lock.json", "npm-shrinkwrap.json", "bun.lock"] {
            let path = dir.file(file);
            // Like the pnpm lock: a lock that never says `patched` holds
            // no patch evidence, so an unparseable one can't hide any.
            let Some(text) = self
                .read_view(view, &path, "npm")
                .await
                .filter(|text| text.contains("patched"))
            else {
                continue;
            };
            if let Some(value) = self.parse_json(&text, &path.shown, "npm") {
                self.native(&value, &path.shown);
                if let Some(packages) = value["packages"].as_object() {
                    for (key, entry) in packages {
                        if !entry["patched"].is_null() {
                            let name = entry["name"]
                                .as_str()
                                .or_else(|| key.rsplit_once("node_modules/").map(|(_, name)| name));
                            if let Some(name) = name {
                                self.add("npm", name, entry["version"].as_str(), &path.shown);
                            } else {
                                self.unknown("npm", &path.shown, "unidentified patched lock entry");
                            }
                        }
                    }
                }
            }
        }
        self.composer(&dir.shown).await;
        self.cargo(&dir.shown).await;
        for file in ["go.mod", "go.work"] {
            let path = dir.file(file);
            if let Some(text) = self.read_view(view, &path, "golang").await {
                for entry in crate::vendor::go_mod_edit::parse_replace_entries(&text) {
                    if !entry.socket_owned() {
                        self.add(
                            "golang",
                            &entry.module,
                            entry.version.as_deref(),
                            &path.shown,
                        );
                    }
                }
                // Workspace members' go.mod replaces still apply under go.work.
                if file == "go.work" {
                    for member in crate::vendor::go_mod_edit::parse_use_dirs(&text) {
                        members.push(normalize_lexically_keeping_escapes(&dir.rel.join(member)));
                    }
                }
            }
        }
        members
    }

    /// [`Self::read`] through a project view.
    async fn read_view(
        &mut self,
        view: &ProjectView<'_>,
        file: &Dir,
        ecosystem: &'static str,
    ) -> Option<String> {
        let rel = file.view_rel();
        // An ancestor workspace file or a member outside the project root:
        // the walk's own [`Bound`] already admitted it, so read it straight
        // from disk. The view's reads stay inside the project root (or the
        // repository), which would silently drop this evidence and fail
        // open.
        let outside_root = file.rel.is_absolute()
            || matches!(
                file.rel.components().next(),
                Some(std::path::Component::ParentDir)
            );
        // Ask for the disk root only then: a snapshot takes that as a read
        // around its overlay.
        let outside = if outside_root {
            view.disk_root_reading([&file.rel])
        } else {
            None
        };
        let mut read = match outside {
            Some(root) => read_regular_to_string(&root.join(&file.rel)).await,
            None => view.read_text(&rel).await,
        };
        // A file the view refused because its real path (through a
        // symlink) leaves the repository is still a file the package
        // manager reads. The refusal carries the `NotFound` kind, so it is
        // caught here and the file is read through the link straight from
        // disk, as the walk does for an ancestor file: its declarations
        // still protect their packages, while a file that declares nothing
        // (a lock with no `patched` entry) does not withhold every package
        // ahead of the writer's own symlinked-file refusal.
        let refused = matches!(&read, Err(e) if crate::utils::repo_root::is_refused_read(e));
        if refused {
            if let Some(root) = view.disk_root_reading([&rel]) {
                read = read_regular_to_string(&root.join(&rel)).await;
            }
        }
        match read {
            Ok(text) => Some(strip_bom(&text).to_owned()),
            // Fail closed when the refused file can't be read through the
            // link either, instead of reading as absent.
            Err(e) if refused || crate::utils::repo_root::is_refused_read(&e) => {
                self.unreadable(ecosystem, &file.shown, &format!("cannot be read: {e}"));
                None
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            // An in-memory link has no content to read. A linked lock or
            // `pnpm-workspace.yaml` is a file the engine refuses on its
            // own, so it is not taken for unknown metadata, which would
            // withhold every package ahead of that refusal. A linked
            // `package.json` is not refused (the npm rewriter reads around
            // a manifest it can't read), and its declarations and
            // `--patch-dir` scripts are unknown: it fails closed below.
            Err(_)
                if matches!(view, ProjectView::Memory(_))
                    && view.is_symlink(&rel)
                    && (file.rel.file_name().and_then(|n| n.to_str()) != Some("package.json")
                        || refused_linked_manifest(view, &file.rel).await) =>
            {
                None
            }
            Err(e) => {
                self.unreadable(ecosystem, &file.shown, &format!("cannot be read: {e}"));
                None
            }
        }
    }

    /// [`Self::json`] through a project view.
    async fn json_view(&mut self, view: &ProjectView<'_>, file: &Dir) -> Option<Value> {
        let text = self.read_view(view, file, "npm").await?;
        self.parse_json(&text, &file.shown, "npm")
    }

    /// The patch-package files of directory `dir`, and of every directory
    /// below it: patch-package collects its patches recursively and reads
    /// each one's path relative to `dir`, so `@scope/name+1.0.0.patch`
    /// patches `@scope/name`. `required`: a directory a script names,
    /// which must exist (on disk: an in-memory project holds a directory
    /// only through a file below it, and path selection supplies every
    /// `*.patch` file, so one with no listing holds no patch); `bound`
    /// keeps it inside the git repository ([`Self::walk`]). A listing that
    /// can't be read in full, or a tree past the walk's limits, protects
    /// every npm package.
    async fn list_patch_directory(
        &mut self,
        view: &ProjectView<'_>,
        dir: &Dir,
        required: bool,
        bound: &Bound,
    ) {
        /// How deep and how many entries one patch directory is walked.
        const MAX_DEPTH: usize = 16;
        const MAX_ENTRIES: usize = 10_000;
        if bound.outside(&dir.rel) {
            self.unknown(
                "npm",
                &dir.shown,
                "patch-package directory outside the git repository is not inspected",
            );
            return;
        }
        let in_memory = matches!(view, ProjectView::Memory(_));
        // Each directory to list, with its path below `dir` (`/`-separated,
        // as patch-package reads it).
        let mut pending = vec![(dir.clone(), String::new(), 0usize)];
        let mut listed = 0usize;
        while let Some((current, below, depth)) = pending.pop() {
            // A directory a script names is listed in full; the default
            // `patches/` skips what it can't see, as before.
            let listing = if required {
                view.list_dir_strict(&current.view_rel()).await
            } else {
                view.list_dir(&current.view_rel()).await
            };
            let entries = match listing {
                Ok(entries) => entries,
                Err(e)
                    if below.is_empty()
                        && (!required || in_memory)
                        && e.kind() == std::io::ErrorKind::NotFound =>
                {
                    return;
                }
                Err(e) => {
                    self.unknown(
                        "npm",
                        &current.shown,
                        &format!("cannot inspect patch-package directory: {e}"),
                    );
                    continue;
                }
            };
            listed += entries.len();
            if listed > MAX_ENTRIES || (depth >= MAX_DEPTH && entries.iter().any(|e| e.is_dir)) {
                self.unknown(
                    "npm",
                    &dir.shown,
                    "patch-package directory inspection limit exceeded",
                );
                return;
            }
            for entry in entries {
                let rel = if below.is_empty() {
                    entry.name.clone()
                } else {
                    format!("{below}/{}", entry.name)
                };
                let file = current.file(&entry.name);
                // patch-package walks through a linked directory too. The
                // walk's own skip list (an installed `node_modules` under
                // `--patch-dir .`) is left out, as path selection leaves
                // it out of the in-memory project.
                let is_dir = entry.is_dir
                    || (!entry.name.ends_with(".patch") && view.is_dir(&file.view_rel()));
                if is_dir {
                    if !WALK_SKIP.contains(&entry.name.as_str()) {
                        pending.push((file, rel, depth + 1));
                    }
                } else {
                    self.patch_file(&rel, &file.shown, required);
                }
            }
        }
    }

    // Use the existing npm/Yarn glob grammar, with a bounded, link-free walk.
    // Positive patterns are a conservative union: a patch in an excluded member
    // may still protect the same release elsewhere, never silently lose it.
    // Returns the members' root-relative paths.
    async fn workspace_members(
        &mut self,
        view: &ProjectView<'_>,
        dir: &Dir,
        pattern: &str,
        bound: &Bound,
    ) -> Vec<std::path::PathBuf> {
        if Path::new(pattern).is_absolute() {
            self.unknown("npm", &dir.shown, "workspace outside the inspection root");
            return Vec::new();
        }
        // Resolve `..` lexically: `packages/b/../a` is `packages/a`, and a
        // leading `../shared/*` re-roots the walk at the parent.
        let mut root = dir.clone();
        let mut segments: Vec<&str> = Vec::new();
        for segment in pattern.split('/') {
            match segment {
                "" | "." => {}
                ".." => match segments.last() {
                    Some(last) if last.contains(['*', '?', '{', '[', '(']) => {
                        self.unknown("npm", &root.shown, "workspace glob traverses a wildcard");
                        return Vec::new();
                    }
                    Some(_) => {
                        segments.pop();
                    }
                    None => {
                        if root.shown.is_absolute() && root.shown.parent().is_none() {
                            self.unknown(
                                "npm",
                                &root.shown,
                                "workspace outside the filesystem root",
                            );
                            return Vec::new();
                        }
                        root = root.file("..");
                    }
                },
                _ => segments.push(segment),
            }
        }
        let pattern = segments.join("/");
        let pattern = pattern.as_str();
        let prefix: std::path::PathBuf = pattern
            .split('/')
            .take_while(|p| !p.contains(['*', '?', '{', '[', '(']))
            .collect();
        if bound.outside(&root.rel) {
            self.unknown(
                "npm",
                &root.shown,
                "workspace outside the git repository is not inspected",
            );
            return Vec::new();
        }
        let base = root.file(&prefix.to_string_lossy());
        let base_rel = base.view_rel();
        if !view.is_dir(&base_rel) && !view.is_file(&base_rel) && !view.is_symlink(&base_rel) {
            return Vec::new();
        }
        let max_depth = if pattern.contains("**") {
            32
        } else {
            pattern
                .split('/')
                .count()
                .saturating_sub(prefix.components().count())
        };
        let skipped = |name: &str| WALK_SKIP.contains(&name);
        let mut out = Vec::new();
        let patterns = vec![pattern.to_string()];
        // Depth-first, as `walkdir` walked it: (directory, depth, its
        // components below `root`).
        let base_name = prefix.file_name().map(|n| n.to_string_lossy().into_owned());
        if base_name.as_deref().is_some_and(skipped) {
            return Vec::new();
        }
        let mut stack: Vec<(Dir, usize, Vec<String>)> = vec![(
            base.clone(),
            0,
            prefix
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect(),
        )];
        let mut count = 0usize;
        while let Some((entry, depth, components)) = stack.pop() {
            count += 1;
            if count > 16384 {
                self.unknown("npm", &root.shown, "workspace inspection limit exceeded");
                break;
            }
            let rel = entry.view_rel();
            let is_link = view.is_symlink(&rel);
            if !is_link && !view.is_dir(&rel) {
                continue;
            }
            if depth == 32 && !is_link {
                self.unknown("npm", &entry.shown, "workspace inspection depth exceeded");
            }
            // Package managers only treat a directory with a package.json as
            // a workspace; anything else under a `**` glob is just source.
            let member = view.is_file(&entry.file("package.json").view_rel());
            if is_link {
                // The walk doesn't follow links, so a link that is (or leads
                // to) a member can't be inspected.
                if depth == 0
                    || (view.is_dir(&rel)
                        && (member
                            || workspaces_include_as(
                                &patterns,
                                &components,
                                WorkspacesDialect::YARN_BERRY,
                            ) && !pattern.contains("**")))
                {
                    self.unknown(
                        "npm",
                        &entry.shown,
                        "linked workspace cannot be inspected safely",
                    );
                }
                continue;
            }
            if member
                && workspaces_include_as(&patterns, &components, WorkspacesDialect::YARN_BERRY)
            {
                out.push(entry.rel.clone());
            }
            if depth >= max_depth {
                continue;
            }
            match view.list_dir_strict(&rel).await {
                Ok(children) => {
                    for child in children.into_iter().rev() {
                        let child_dir = entry.file(&child.name);
                        if skipped(&child.name)
                            || !child.is_dir && !view.is_symlink(&child_dir.view_rel())
                        {
                            continue;
                        }
                        let mut below = components.clone();
                        below.push(child.name.clone());
                        stack.push((child_dir, depth + 1, below));
                    }
                }
                Err(error) => {
                    self.unknown(
                        "npm",
                        &root.shown,
                        &format!("cannot inspect workspace: {error}"),
                    );
                }
            }
        }
        out
    }

    /// All evidence for this release, sorted and deduplicated. Unknown ranges
    /// protect every version of that name; known exact versions don't block an
    /// unrelated release. Scoped npm identities remain case-sensitive.
    pub fn conflicts(&self, purl: &str) -> Vec<String> {
        self.evidence_for(purl)
            .into_iter()
            .map(|e| e.source.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Whether `purl` is protected only by files that could not be read or
    /// parsed (invalid JSON or YAML, a permission error), and by no patch or
    /// replacement the project is known to declare. Its
    /// [`Self::conflicts`] then name a broken file, not a conflict: the
    /// remedy is to fix the file. False when nothing protects `purl`.
    pub fn unreadable_only(&self, purl: &str) -> bool {
        let evidence = self.evidence_for(purl);
        !evidence.is_empty() && evidence.iter().all(|e| e.unreadable)
    }

    /// Every entry that protects this release.
    fn evidence_for(&self, purl: &str) -> Vec<&Evidence> {
        let normalized = normalize_purl(purl);
        let base = strip_purl_qualifiers(&normalized);
        let Some((ecosystem, coordinate)) =
            base.strip_prefix("pkg:").and_then(|s| s.split_once('/'))
        else {
            return Vec::new();
        };
        let Some((name, version)) = coordinate.rsplit_once('@') else {
            return Vec::new();
        };
        self.entries
            .iter()
            .filter(|e| {
                e.ecosystem == ecosystem
                    && (e.name.is_empty()
                        || if ecosystem == "composer" {
                            e.name.eq_ignore_ascii_case(name)
                        } else if ecosystem == "cargo" {
                            // crates.io names are unique ignoring case and -/_.
                            e.name.len() == name.len()
                                && e.name.bytes().zip(name.bytes()).all(|(a, b)| {
                                    let fold = |c: u8| {
                                        if c == b'_' {
                                            b'-'
                                        } else {
                                            c.to_ascii_lowercase()
                                        }
                                    };
                                    fold(a) == fold(b)
                                })
                        } else {
                            e.name == name
                        })
                    && e.version.as_deref().is_none_or(|selector| {
                        selector == version
                            || if ecosystem == "npm" {
                                // pnpm treats an explicit * as its all-versions
                                // bucket, including prereleases, rather than as
                                // an ordinary semver range.
                                selector.trim() == "*"
                                    || npm_range_admits(selector, version).unwrap_or(true)
                            } else {
                                false
                            }
                    })
            })
            .collect()
    }

    fn add(&mut self, ecosystem: &'static str, name: &str, version: Option<&str>, path: &Path) {
        self.entries.push(Evidence {
            ecosystem,
            name: name.into(),
            version: version.map(str::to_owned),
            source: path.display().to_string(),
            unreadable: false,
        });
    }

    /// Metadata that was read but cannot be resolved to packages (a
    /// malformed declaration, a dynamic patch directory): it protects every
    /// package of `ecosystem`.
    fn unknown(&mut self, ecosystem: &'static str, path: &Path, reason: &str) {
        self.entries.push(Evidence {
            ecosystem,
            name: String::new(),
            version: None,
            source: format!("{} ({reason})", path.display()),
            unreadable: false,
        });
    }

    /// A file that could not be read or parsed (`reason` says which, with
    /// the error): what it declares is not known, so it protects every
    /// package of `ecosystem` until it is fixed.
    fn unreadable(&mut self, ecosystem: &'static str, path: &Path, reason: &str) {
        self.entries.push(Evidence {
            ecosystem,
            name: String::new(),
            version: None,
            source: format!("{} ({reason})", path.display()),
            unreadable: true,
        });
    }

    async fn read(&mut self, path: &Path, ecosystem: &'static str) -> Option<String> {
        match read_regular_to_string(path).await {
            Ok(text) => Some(strip_bom(&text).to_owned()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                self.unreadable(ecosystem, path, &format!("cannot be read: {e}"));
                None
            }
        }
    }

    async fn json(&mut self, path: &Path, ecosystem: &'static str) -> Option<Value> {
        let text = self.read(path, ecosystem).await?;
        self.parse_json(&text, path, ecosystem)
    }

    fn parse_json(&mut self, text: &str, path: &Path, ecosystem: &'static str) -> Option<Value> {
        match serde_json::from_str(&crate::vendor::bun_lock_text::strip_jsonc(text)) {
            Ok(value) => Some(value),
            Err(e) => {
                self.unreadable(ecosystem, path, &format!("not valid JSON: {e}"));
                None
            }
        }
    }

    fn native(&mut self, value: &Value, path: &Path) {
        self.patched_dependencies(&value["patchedDependencies"], path);
        self.patched_dependencies(&value["pnpm"]["patchedDependencies"], path);
        self.pnpm_lock_patches(value, path);
    }

    /// A `patchedDependencies` map's keys (`name`, `name@version`,
    /// `name@range`, or Bun's `name@<resolution>`), as npm, Bun and pnpm
    /// all spell them.
    fn patched_dependencies(&mut self, field: &Value, path: &Path) {
        if let Some(map) = field.as_object() {
            for key in map.keys() {
                let (name, version) = split_selector(key);
                self.add("npm", name, version, path);
            }
        } else if !field.is_null() {
            self.unknown("npm", path, "invalid patchedDependencies");
        }
    }

    /// The pnpm lock entries pnpm patches: a `(patch_hash=…)` key suffix,
    /// or an older lock's `patched: true`.
    fn pnpm_lock_patches(&mut self, value: &Value, path: &Path) {
        // Older pnpm locks can carry patch hashes without a mirrored map.
        for field in ["packages", "snapshots"] {
            if let Some(map) = value[field].as_object() {
                for (key, entry) in map {
                    if key.contains("patch_hash=") || !entry["patched"].is_null() {
                        if let Some((name, version)) = crate::formats::pnpm::pnpm_registry_key(key)
                        {
                            self.add("npm", name, Some(version), path);
                        }
                    }
                }
            }
        }
    }

    /// The pnpm declarations of `pnpm-workspace.yaml` (`lock` false) or of
    /// a pnpm lock (`lock` true): the top-level `patchedDependencies` map
    /// (pnpm 10+'s workspace setting, and the copy every lock records) and
    /// the lock's patched entries. A lock that never spells a patch is not
    /// parsed. `any_map` also reads a `pnpm.patchedDependencies` map, which
    /// only `package.json` defines. Returns the parsed documents.
    fn pnpm_yaml(&mut self, text: &str, path: &Path, lock: bool, any_map: bool) -> Vec<Value> {
        if lock
            && !text.contains("patchedDependencies")
            && !text.contains("patch_hash")
            && !text.contains("patched:")
        {
            return Vec::new();
        }
        match serde_saphyr::from_multiple_with_options::<Value>(text, lock_options()) {
            Ok(documents) => {
                for value in &documents {
                    self.patched_dependencies(&value["patchedDependencies"], path);
                    if any_map {
                        self.patched_dependencies(&value["pnpm"]["patchedDependencies"], path);
                    }
                    self.pnpm_lock_patches(value, path);
                }
                documents
            }
            Err(e) => {
                self.unreadable("npm", path, &format!("not valid YAML: {e}"));
                Vec::new()
            }
        }
    }

    /// The yarn `patch:` descriptors a `package.json` declares, in its
    /// dependency maps and `resolutions`.
    fn yarn_manifest(&mut self, value: &Value, path: &Path) {
        for field in [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "resolutions",
        ] {
            if let Some(map) = value[field].as_object() {
                for spec in map.values().filter_map(Value::as_str) {
                    self.yarn(spec, path);
                }
            }
        }
    }

    /// The user `patch:` locators a yarn berry lock resolves (a classic
    /// lock has none).
    fn yarn_lock(&mut self, text: &str, path: &Path) {
        // Only Berry has patch: locators. Every Berry lock carries builtin
        // compat patches, so scan the resolution lines rather than parse
        // what can be a very large lockfile, and visit only the few lines
        // that can hold one.
        for line in lines_containing(text, "@patch:") {
            let Some(value) = line.trim_start().strip_prefix("resolution:") else {
                continue;
            };
            let value = value.trim().trim_matches('"');
            // A locator has an ident before @patch:.
            if let Some((_, source)) = value.split_once("@patch:") {
                self.yarn(&format!("patch:{source}"), path);
            }
        }
    }

    fn yarn(&mut self, spec: &str, path: &Path) {
        if !spec.starts_with("patch:") {
            return;
        }
        match crate::formats::yarn::patterns::patch_layers(spec) {
            Ok(Some(layers)) if layers.user_patch => {
                let (name, version) = locator_target(&layers.source);
                self.add("npm", name, version, path);
            }
            Ok(_) => {}
            Err(reason) => self.unknown("npm", path, reason),
        }
    }

    /// The `--patch-dir` directories the `patch-package` scripts of the
    /// `package.json` at `manifest` name, relative to its directory. A
    /// script whose directory can't be read without running it protects
    /// every npm package instead.
    fn patch_package_dirs(&mut self, manifest: &Path, value: &Value) -> Vec<String> {
        // Compiled once, and only for a project whose scripts run patch-package.
        static FLAG: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r#"--patch-dir(?:=|\s+)(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))"#).unwrap()
        });
        // `cd` as a command, not the tail of a word like `abcd`.
        static CD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:^|[\s;&|(])cd\s").unwrap());
        let mut dirs = Vec::new();
        if let Some(scripts) = value["scripts"].as_object() {
            for script in scripts
                .values()
                .filter_map(Value::as_str)
                .filter(|s| s.contains("patch-package"))
            {
                // A `cd` after patch-package (`patch-package && cd ios && pod
                // install`) can't move the directory it already read.
                let moved = CD
                    .find(script)
                    .is_some_and(|cd| cd.start() < script.rfind("patch-package").unwrap_or(0));
                if moved || (script.contains("--patch-dir") && !FLAG.is_match(script)) {
                    self.unknown(
                        "npm",
                        manifest,
                        "cannot resolve patch-package directory without executing the script",
                    );
                }
                for captures in FLAG.captures_iter(script) {
                    let path = captures.iter().skip(1).flatten().next().unwrap().as_str();
                    if path.contains(['$', '`']) || moved {
                        self.unknown(
                            "npm",
                            manifest,
                            "dynamic patch-package directory; inspect it before opting in",
                        );
                    } else {
                        dirs.push(path.to_string());
                    }
                }
            }
        }
        dirs
    }

    /// One file of a patch-package directory, at `file` below it:
    /// `[<parent>++]<name>+<version>[+<sequence>][.dev].patch`, its name
    /// scoped as `@scope+name` or by a `@scope/` directory. patch-package
    /// applies a patch to whichever version of the package is installed
    /// (a version that differs from the file name's is only a warning), so
    /// the evidence protects every version of the package.
    fn patch_file(&mut self, file: &str, path: &Path, required: bool) {
        static VERSION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+\.\d+\.\d+").unwrap());
        let Some(stem) = file.strip_suffix(".patch") else {
            return;
        };
        let stem = stem.strip_suffix(".dev").unwrap_or(stem);
        // patch-package's own parse of the installed (last) package.
        let leaf = stem.rsplit("++").next().unwrap_or(stem);
        let parts: Vec<&str> = leaf
            .split('+')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .collect();
        let name = match parts.iter().position(|p| VERSION.is_match(p)) {
            Some(1) => Some(parts[0].to_string()),
            Some(2) => Some(format!("{}/{}", parts[0], parts[1])),
            _ => None,
        };
        if let Some(name) = name {
            self.add("npm", &name, None, path);
        } else if required {
            self.unknown("npm", path, "unrecognized patch-package filename");
        }
    }

    async fn composer(&mut self, dir: &Path) {
        let manifest = dir.join("composer.json");
        let Some(value) = self.json(&manifest, "composer").await else {
            return;
        };
        self.composer_map(&value["extra"]["patches"], &manifest);
        let file = value["extra"]["composer-patches"]["patches-file"]
            .as_str()
            .or_else(|| value["extra"]["patches-file"].as_str())
            .unwrap_or("patches.json");
        if file != "patches.json" && !dir.join(file).exists() {
            self.unknown(
                "composer",
                &dir.join(file),
                "configured patch definitions are missing",
            );
        }
        for path in [dir.join(file), dir.join("patches.lock.json")] {
            if let Some(patches) = self.json(&path, "composer").await {
                self.composer_map(&patches["patches"], &path);
            }
        }
        let lock = dir.join("composer.lock");
        if let Some(value) = self.json(&lock, "composer").await {
            for field in ["packages", "packages-dev"] {
                if let Some(packages) = value[field].as_array() {
                    for package in packages {
                        self.composer_map(&package["extra"]["patches"], &lock);
                    }
                }
            }
        }
    }

    fn composer_map(&mut self, value: &Value, path: &Path) {
        if let Some(map) = value.as_object() {
            for name in map.keys() {
                self.add("composer", name, None, path);
            }
        } else if let Some(patches) = value.as_array() {
            for patch in patches {
                if let Some(name) = patch["package"].as_str() {
                    self.add("composer", name, None, path);
                } else {
                    self.unknown("composer", path, "unidentified Composer patch target");
                }
            }
        } else if !value.is_null() {
            self.unknown("composer", path, "unrecognized Composer patch definitions");
        }
    }

    async fn cargo(&mut self, dir: &Path) {
        for file in ["Cargo.toml", ".cargo/config.toml", ".cargo/config"] {
            let path = dir.join(file);
            let Some(text) = self.read(&path, "cargo").await else {
                continue;
            };
            if !text.contains("patch") && !text.contains("replace") && !text.contains("paths") {
                continue;
            }
            let doc = match text.parse::<toml_edit::DocumentMut>() {
                Ok(doc) => doc,
                Err(e) => {
                    self.unknown("cargo", &path, &e.to_string());
                    continue;
                }
            };
            if let Some(tables) = doc.get("patch").and_then(toml_edit::Item::as_table_like) {
                for (_, table) in tables.iter() {
                    if let Some(table) = table.as_table_like() {
                        for (key, entry) in table.iter() {
                            // Socket's managed paths/registries must remain eligible for updates.
                            let target = entry.get("path").and_then(toml_edit::Item::as_str);
                            if target.is_some_and(crate::vendor::cargo_config::path_is_socket_owned)
                            {
                                continue;
                            }
                            let name = entry
                                .get("package")
                                .and_then(toml_edit::Item::as_str)
                                .unwrap_or(key);
                            self.add("cargo", name, None, &path);
                        }
                    }
                }
            }
            if let Some(table) = doc.get("replace").and_then(toml_edit::Item::as_table_like) {
                for (key, _) in table.iter() {
                    let (name, version) = key
                        .split_once(':')
                        .map_or((key, None), |(n, v)| (n, Some(v)));
                    self.add("cargo", name, version, &path);
                }
            }
            if doc
                .get("paths")
                .and_then(toml_edit::Item::as_array)
                .is_some_and(|a| !a.is_empty())
            {
                self.unknown(
                    "cargo",
                    &path,
                    "Cargo paths overrides may replace registry packages",
                );
            }
        }
    }
}

/// Which project files a run may read, chosen once from the CLI mode
/// (never inferred from the filesystem): #2025's shared scope.
pub use crate::utils::repo_root::ReadScope;

/// What a [`UserPatchIndex::walk`] reads.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Everything the CLI's consent gate protects.
    Gate,
    /// The npm-family declarations of [`UserPatchIndex::npm_family_in`].
    NpmFamily,
}

/// A directory or file of a [`UserPatchIndex::walk`]: its path relative to
/// the project root (lexically normalized; leading `..` reach an
/// ancestor), and the path its evidence is reported under.
#[derive(Clone, Debug)]
struct Dir {
    rel: std::path::PathBuf,
    shown: std::path::PathBuf,
}

impl Dir {
    fn file(&self, name: &str) -> Dir {
        Dir {
            rel: normalize_lexically_keeping_escapes(&self.rel.join(name)),
            shown: normalize_lexically_keeping_escapes(&self.shown.join(name)),
        }
    }

    /// The `/`-separated path a [`ProjectView`] reads it at (`""` for the
    /// root; an absolute path as is).
    fn view_rel(&self) -> String {
        if self.rel.is_absolute() {
            return self.rel.to_string_lossy().into_owned();
        }
        self.rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
    }
}

/// Whether the engine refuses the in-memory linked `package.json` at
/// root-relative `manifest` on its own: the root manifest beside a yarn
/// berry lock is a yarn rewrite target, read strictly.
async fn refused_linked_manifest(view: &ProjectView<'_>, manifest: &Path) -> bool {
    manifest == Path::new("package.json")
        && view
            .read_text("yarn.lock")
            .await
            .is_ok_and(|lock| crate::formats::yarn::is_berry_lock(&lock))
}

/// The directories the user-patch walk never enters, which path selection
/// skips too.
pub(crate) const WALK_SKIP: [&str; 5] = ["node_modules", ".git", ".socket", "target", ".venv"];

/// What bounds a [`UserPatchIndex::walk`]'s reads.
enum Bound {
    /// Nothing: a global run, or a disk project with no git repository
    /// above it (the ancestor walk's home rule still applies).
    None,
    /// A disk project at `root` inside the checkout at `repo` (both
    /// canonical, as [`crate::utils::repo_root::search_dirs`] spells them).
    Disk {
        root: std::path::PathBuf,
        repo: std::path::PathBuf,
    },
    /// An in-memory project, its own repository root.
    Memory,
}

impl Bound {
    /// Whether `rel` (root-relative, or absolute) lies outside the bound.
    /// An absolute path is inside when it lexically lies under the
    /// repository root.
    fn outside(&self, rel: &Path) -> bool {
        match self {
            Bound::None => false,
            Bound::Memory => {
                rel.is_absolute()
                    || matches!(
                        rel.components().next(),
                        Some(std::path::Component::ParentDir)
                    )
            }
            Bound::Disk { root, repo } => {
                // `repo` is canonical (`\\?\C:\...` on Windows) while a
                // script names a directory as users type it (`C:\...`), and
                // `starts_with` treats the two prefixes as different.
                use crate::utils::pnpm_workspace::without_verbatim_prefix;
                !without_verbatim_prefix(normalize_lexically_keeping_escapes(&root.join(rel)))
                    .starts_with(without_verbatim_prefix(repo.clone()))
            }
        }
    }
}

/// The package a Yarn locator installs. An alias (`alias@npm:real@1.0.0`)
/// installs `real`, which is the name the crawler reports.
fn locator_target(locator: &str) -> (&str, Option<&str>) {
    let at = locator
        .char_indices()
        .skip(1)
        .find(|&(_, c)| c == '@')
        .map(|(i, _)| i);
    let Some(at) = at else {
        return (locator, None);
    };
    let (name, range) = (&locator[..at], &locator[at + 1..]);
    match range.strip_prefix("npm:") {
        Some(target) if target.get(1..).is_some_and(|t| t.contains('@')) => split_selector(target),
        Some(version) => (name, Some(version)),
        None => (name, Some(range)),
    }
}

/// The lines of `text` that contain `needle`, each once, as `str::lines`
/// spells them (a `\r` before a `\n` is dropped, a final bare one kept). Searching for the
/// needle skips the rest of the text instead of splitting every line.
/// `needle` must be non-empty and on one line, so each match moves on.
fn lines_containing<'a>(text: &'a str, needle: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    debug_assert!(!needle.is_empty() && !needle.contains('\n'));
    let mut from = 0;
    std::iter::from_fn(move || {
        let at = from + text.get(from..)?.find(needle)?;
        let start = text[..at].rfind('\n').map_or(0, |i| i + 1);
        let Some(end) = text[at..].find('\n').map(|i| at + i) else {
            // Past the end: the next call finds nothing.
            from = text.len() + 1;
            return Some(&text[start..]);
        };
        from = end + 1;
        let line = &text[start..end];
        Some(line.strip_suffix('\r').unwrap_or(line))
    })
}

fn lock_options() -> serde_saphyr::Options {
    // Lockfiles of large monorepos exceed the default 250k-node budget, and a
    // parse failure would protect every npm package.
    let mut budget = serde_saphyr::Budget::default();
    budget.max_events = 64_000_000;
    budget.max_nodes = 32_000_000;
    budget.max_total_scalar_bytes = 1 << 30;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    options
}

/// An npm `name@selector` key split at the first `@` past a scope, as Bun
/// and pnpm split it: the selector may hold an `@` of its own, such as the
/// hosted URL or vendored path Bun 1.4 keys a patch by after a rewire
/// (`@s/p@.socket/vendor/npm/<uuid>/@s/p-1.0.0.tgz`, #1019).
fn split_selector(key: &str) -> (&str, Option<&str>) {
    match crate::vendor::bun_lock_text::split_name_spec(key) {
        Some((name, selector)) => (name, Some(selector)),
        None => (key, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lock that exists but can't be read protects every npm package; a
    /// missing one is no evidence.
    #[test]
    fn an_unreadable_lock_protects_every_npm_package() {
        let mut index = UserPatchIndex::from_locks(&[]);
        index.unreadable_lock(
            "common/config/rush/pnpm-lock.yaml",
            &std::io::Error::from(std::io::ErrorKind::NotFound),
        );
        assert!(index.is_empty());
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::InvalidData,
        ] {
            let mut index = UserPatchIndex::from_locks(&[]);
            index.unreadable_lock("shrinkwrap.yaml", &std::io::Error::from(kind));
            assert_eq!(
                index.conflicts("pkg:npm/left-pad@1.3.0").len(),
                1,
                "{kind:?}"
            );
            assert!(index.conflicts("pkg:pypi/requests@2.0.0").is_empty());
        }
    }

    fn write(root: &Path, path: &str, text: &str) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// #1019: after a rewire, Bun 1.4 keys a later `bun patch` by the
    /// package's resolution. A hosted URL or vendored path can hold an `@`
    /// of its own, so the key splits at the first `@` past a scope, as Bun
    /// splits it.
    #[tokio::test]
    async fn bun_resolution_keys_protect_scoped_and_unscoped_packages() {
        for (key, purl) in [
            ("plainpkg@https://patch.socket.dev/patch/npm/plainpkg/1.0.0/tok/u1/plainpkg-1.0.0.tgz", "pkg:npm/plainpkg@1.0.0"),
            ("plainpkg@.socket/vendor/npm/u1/plainpkg-1.0.0.tgz", "pkg:npm/plainpkg@1.0.0"),
            ("@s/p@https://patch.socket.dev/patch/npm/@s/p/1.0.0/tok/u1/p-1.0.0.tgz", "pkg:npm/%40s/p@1.0.0"),
            ("@s/p@.socket/vendor/npm/u1/@s/p-1.0.0.tgz", "pkg:npm/%40s/p@1.0.0"),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let manifest = format!(r#"{{"patchedDependencies":{{"{key}":"patches/x.patch"}}}}"#);
            write(tmp.path(), "package.json", &manifest);
            let index = UserPatchIndex::discover(tmp.path()).await;
            assert!(!index.conflicts(purl).is_empty(), "{key}: {index:?}");
            assert!(index.conflicts("pkg:npm/other@1.0.0").is_empty(), "{key}");
        }
    }

    #[tokio::test]
    async fn native_declarations_match_scopes_ranges_and_exact_versions_without_patch_files() {
        for (file, text) in [
            ("package.json", r#"{"pnpm":{"patchedDependencies":{"@s/pkg@^1.0.0":"missing.patch","all":"all.patch","exact@2.0.0":"exact.patch"}}}"#),
            ("pnpm-workspace.yaml", "patchedDependencies:\n  '@s/pkg@^1.0.0': missing.patch\n  all: all.patch\n  exact@2.0.0: exact.patch\n"),
            ("pnpm-lock.yaml", "lockfileVersion: '9.0'\npatchedDependencies:\n  '@s/pkg@^1.0.0': {hash: abc, path: missing.patch}\n  all: all.patch\n  exact@2.0.0: exact.patch\n"),
            ("bun.lock", r#"{ // root mirror
              "patchedDependencies": {"@s/pkg@^1.0.0":"missing.patch","all":"all.patch","exact@2.0.0":"exact.patch"},
            }"#),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(tmp.path(), file, text);
            let index = UserPatchIndex::discover(tmp.path()).await;
            for purl in ["pkg:npm/%40s/pkg@1.2.0", "pkg:npm/all@4.0.0", "pkg:npm/exact@2.0.0"] {
                assert!(!index.conflicts(purl).is_empty(), "{file}: {purl}");
            }
            for purl in ["pkg:npm/@s/pkg@2.0.0", "pkg:npm/exact@2.0.1", "pkg:npm/other@1.0.0", "pkg:pypi/all@4.0.0"] {
                assert!(index.conflicts(purl).is_empty(), "{file}: {purl}: {index:?}");
            }
        }
    }

    #[tokio::test]
    async fn pnpm_lock_hashes_cover_legacy_and_multidocument_locks() {
        for text in [
            "lockfileVersion: '6.0'\npackages:\n  /@s/pkg@1.2.0(patch_hash=abc): {}\n",
            "lockfileVersion: 5.4\npackages:\n  /@s/pkg/1.2.0_patch_hash=abc:\n    patched: true\n",
            "lockfileVersion: '9.0'\n---\nlockfileVersion: '9.0'\nsnapshots:\n  '@s/pkg@1.2.0(patch_hash=abc)': {}\n",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(tmp.path(), "pnpm-lock.yaml", text);
            let index = UserPatchIndex::discover(tmp.path()).await;
            assert!(!index.conflicts("pkg:npm/%40s/pkg@1.2.0").is_empty(), "{index:?}");
            assert!(index.conflicts("pkg:npm/@s/pkg@2.0.0").is_empty());
        }
    }

    #[tokio::test]
    async fn pnpm_all_versions_selector_protects_prereleases() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "pnpm-workspace.yaml",
            "patchedDependencies:\n  'all@*': missing.patch\n  'range@^1.0.0': missing.patch\n",
        );
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(!index.conflicts("pkg:npm/all@2.0.0-beta.1").is_empty());
        assert!(index.conflicts("pkg:npm/range@2.0.0-beta.1").is_empty());
    }

    #[tokio::test]
    async fn npm_lock_marker_is_sufficient_without_manifest_declaration() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package-lock.json",
            r#"{"packages":{"node_modules/parent/node_modules/@s/pkg":{"version":"1.2.0","patched":{"path":"patches/fix.patch"}}}}"#,
        );
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(!index.conflicts("pkg:npm/@s/pkg@1.2.0").is_empty());
        assert!(index.conflicts("pkg:npm/parent@1.2.0").is_empty());
    }

    #[tokio::test]
    async fn yarn_protects_custom_patches_but_not_builtin_only_compatibility_patches() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"resolutions":{"alias":"patch:@s/pkg@npm%3A1.2.0#./fix.patch","typescript":"patch:typescript@npm%3A5.0.0#optional!builtin<compat/typescript>","plugin":"patch:plugin@npm%3A1.0.0#builtin<custom/fix>","nested":"patch:nested@patch%3Anested@npm%253A1.0.0%23optional!builtin%3Ccompat/nested%3E#./outer.patch","wrapped":"patch:wrapped@patch%3Awrapped@npm%253A1.0.0%23./inner.patch#optional!builtin<compat/wrapped>"}}"#,
        );
        write(tmp.path(), "yarn.lock", "__metadata:\n  version: 8\nentry:\n  resolution: \"transitive@patch:transitive@npm%3A2.0.0#./fix.patch::version=2.0.0&hash=abc\"\n");
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(!index.conflicts("pkg:npm/@s/pkg@1.2.0").is_empty());
        assert!(!index.conflicts("pkg:npm/transitive@2.0.0").is_empty());
        assert!(index.conflicts("pkg:npm/typescript@5.0.0").is_empty());
        assert!(!index.conflicts("pkg:npm/plugin@1.0.0").is_empty());
        assert!(!index.conflicts("pkg:npm/nested@1.0.0").is_empty());
        assert!(!index.conflicts("pkg:npm/wrapped@1.0.0").is_empty());
        assert!(index.conflicts("pkg:npm/alias@1.2.0").is_empty());
        assert!(index.conflicts("pkg:npm/@s/pkg@1.3.0").is_empty());
    }

    #[test]
    fn lines_containing_matches_a_filtered_lines_walk() {
        for text in [
            "",
            "@patch:",
            "a\nb@patch:c\n",
            "x@patch:y@patch:z\r\nno\r\n  q@patch:\r\n",
            "\n\n@patch:\n\n",
            "a@patch:\nb@patch:",
            "@patch:@patch:\r",
            "lone\rcarriage@patch:\r\rx\n",
            "\u{e9}@patch:\u{e9}\n\u{e9}",
        ] {
            let slow: Vec<&str> = text.lines().filter(|l| l.contains("@patch:")).collect();
            let fast: Vec<&str> = lines_containing(text, "@patch:").collect();
            assert_eq!(fast, slow, "{text:?}");
        }
        // The documented contract, independent of the toolchain's `lines`.
        let got: Vec<&str> = lines_containing("a@patch:\r\nb@patch:\r", "@patch:").collect();
        assert_eq!(got, ["a@patch:", "b@patch:\r"]);
    }

    #[tokio::test]
    async fn yarn_lock_patches_are_found_among_many_unpatched_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let mut lock = String::from("__metadata:\r\n  version: 8\r\n");
        for i in 0..200 {
            lock.push_str(&format!(
                "\"dep-{i}@npm:1.0.0\":\r\n  version: 1.0.0\r\n  resolution: \"dep-{i}@npm:1.0.0\"\r\n"
            ));
        }
        lock.push_str("\"first@patch:first@npm%3A1.0.0#./a.patch\":\r\n  resolution: \"first@patch:first@npm%3A1.0.0#./a.patch::version=1.0.0&hash=a\"\r\n");
        lock.push_str("\"ts@patch:ts@npm%3A5.0.0#optional!builtin<compat/typescript>\":\r\n  resolution: \"ts@patch:ts@npm%3A5.0.0#optional!builtin<compat/typescript>::version=5.0.0&hash=b\"\r\n");
        lock.push_str("\"last@patch:last@npm%3A2.0.0#./b.patch\":\n  resolution: \"last@patch:last@npm%3A2.0.0#./b.patch::version=2.0.0&hash=c\"");
        write(tmp.path(), "yarn.lock", &lock);
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(!index.conflicts("pkg:npm/first@1.0.0").is_empty());
        assert!(!index.conflicts("pkg:npm/last@2.0.0").is_empty());
        assert!(index.conflicts("pkg:npm/ts@5.0.0").is_empty());
        assert!(index.conflicts("pkg:npm/dep-7@1.0.0").is_empty());
    }

    #[tokio::test]
    async fn patch_package_supports_scoped_nested_sequenced_dev_and_custom_directories() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"patch-package --patch-dir='custom fixes'"}}"#,
        );
        write(
            tmp.path(),
            "custom fixes/parent++@s+pkg+1.2.0+001+fix.dev.patch",
            "user diff",
        );
        write(tmp.path(), "patches/plain+3.0.0.dev.patch", "user diff");
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(!index.conflicts("pkg:npm/@s/pkg@1.2.0").is_empty());
        assert!(!index.conflicts("pkg:npm/plain@3.0.0").is_empty());
        assert!(index.conflicts("pkg:npm/parent@1.2.0").is_empty());
    }

    /// Review (#2018): patch-package applies `<name>+<version>.patch` to
    /// whichever version is installed (a mismatch is only a warning), so a
    /// lock bumped past the patch's version still installs the user's
    /// diff; and it collects patches recursively, reading
    /// `@scope/name+1.0.0.patch` as `@scope/name`. On disk and in memory,
    /// through the gate and the npm-family index alike.
    #[tokio::test]
    async fn patch_package_protects_every_version_and_scoped_subdirectories() {
        use crate::vendor::lock_inventory::{MemoryEntry, MemoryProject};

        let files = [
            (
                "package.json",
                r#"{"scripts":{"postinstall":"patch-package --patch-dir fixes"}}"#,
            ),
            ("patches/left-pad+1.3.0.patch", "diff"),
            ("patches/@scope/name+1.0.0.patch", "diff"),
            ("fixes/@other/pkg+2.0.0+001+first.dev.patch", "diff"),
            ("patches/README.md", "notes"),
        ];
        let tmp = tempfile::tempdir().unwrap();
        let mut memory = MemoryProject::new();
        for (path, text) in files {
            write(tmp.path(), path, text);
            memory.insert(path, MemoryEntry::Text(text.into()));
        }
        let gate = UserPatchIndex::discover(tmp.path()).await;
        let disk = UserPatchIndex::npm_family_in(&ProjectView::Disk(tmp.path()), &[]).await;
        let mem = UserPatchIndex::npm_family_in(&ProjectView::Memory(&memory), &[]).await;
        for index in [&gate, &disk, &mem] {
            for purl in [
                "pkg:npm/left-pad@1.3.0",
                "pkg:npm/left-pad@1.3.1",
                "pkg:npm/@scope/name@1.0.0",
                "pkg:npm/@scope/name@2.0.0",
                "pkg:npm/@other/pkg@9.9.9",
            ] {
                assert!(!index.conflicts(purl).is_empty(), "{purl}: {index:?}");
            }
            assert!(
                index.conflicts("pkg:npm/name@1.0.0").is_empty(),
                "{index:?}"
            );
        }
        // A `--patch-dir` file whose name patch-package can't read
        // protects every npm package; one in the default `patches/` is
        // left alone, as before.
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"patch-package --patch-dir fixes"}}"#,
        );
        write(tmp.path(), "fixes/sub/not-a-patch-name.patch", "diff");
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(
            !index.conflicts("pkg:npm/unrelated@1.0.0").is_empty(),
            "{index:?}"
        );
    }

    /// Review (#2018): the recursive patch-package walk follows a linked
    /// subdirectory (patch-package does), and a `--patch-dir .` skips the
    /// installed `node_modules` instead of listing it, so an unrelated
    /// package stays patchable.
    #[cfg(unix)]
    #[tokio::test]
    async fn patch_package_walk_follows_links_and_skips_installed_trees() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "shared/@scope/name+1.0.0.patch", "diff");
        write(tmp.path(), "patches/plain+1.0.0.patch", "diff");
        std::os::unix::fs::symlink(
            tmp.path().join("shared/@scope"),
            tmp.path().join("patches/@scope"),
        )
        .unwrap();
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(
            !index.conflicts("pkg:npm/@scope/name@1.0.0").is_empty(),
            "{index:?}"
        );

        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"patch-package --patch-dir ."}}"#,
        );
        write(tmp.path(), "left-pad+1.3.0.patch", "diff");
        write(
            tmp.path(),
            "node_modules/x/odd.patch",
            "not patch-package's",
        );
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(
            !index.conflicts("pkg:npm/left-pad@1.3.0").is_empty(),
            "{index:?}"
        );
        assert!(
            index.conflicts("pkg:npm/other@1.0.0").is_empty(),
            "{index:?}"
        );
    }

    /// Review (#2018): an in-memory `package.json` that is a link has no
    /// content, so its `pnpm.patchedDependencies`, `patch:` descriptors and
    /// `--patch-dir` scripts are unknown. The engine does not refuse a
    /// linked manifest, so it protects every npm package instead of
    /// reading as "no patches". A linked lock stays the engine's own
    /// refusal.
    #[tokio::test]
    async fn an_in_memory_linked_manifest_fails_closed() {
        use crate::vendor::lock_inventory::{MemoryEntry, MemoryProject};

        let mut memory = MemoryProject::new();
        memory.insert("package.json", MemoryEntry::Symlink);
        memory.insert(
            "fixes/left-pad+1.3.0.patch",
            MemoryEntry::Text("diff".into()),
        );
        let index = UserPatchIndex::npm_family_in(&ProjectView::Memory(&memory), &[]).await;
        assert!(
            !index.conflicts("pkg:npm/other@1.0.0").is_empty(),
            "{index:?}"
        );

        let mut memory = MemoryProject::new();
        memory.insert("package.json", MemoryEntry::Text("{}".into()));
        memory.insert("pnpm-lock.yaml", MemoryEntry::Symlink);
        let index = UserPatchIndex::npm_family_in(&ProjectView::Memory(&memory), &[]).await;
        assert!(index.is_empty(), "{index:?}");

        // Beside a yarn berry lock the root manifest is a rewrite target
        // the engine refuses as a link: left to that refusal.
        let mut memory = MemoryProject::new();
        memory.insert("package.json", MemoryEntry::Symlink);
        memory.insert(
            "yarn.lock",
            MemoryEntry::Text("__metadata:\n  version: 8\n".into()),
        );
        let index = UserPatchIndex::npm_family_in(&ProjectView::Memory(&memory), &[]).await;
        assert!(index.is_empty(), "{index:?}");

        // On disk the link is read through, and its `--patch-dir` found.
        #[cfg(unix)]
        {
            let tmp = tempfile::tempdir().unwrap();
            write(
                tmp.path(),
                "config/package.json",
                r#"{"scripts":{"postinstall":"patch-package --patch-dir fixes"}}"#,
            );
            write(tmp.path(), "fixes/left-pad+1.3.0.patch", "diff");
            std::os::unix::fs::symlink("config/package.json", tmp.path().join("package.json"))
                .unwrap();
            for index in [
                UserPatchIndex::discover(tmp.path()).await,
                UserPatchIndex::npm_family_in(&ProjectView::Disk(tmp.path()), &[]).await,
            ] {
                assert!(
                    !index.conflicts("pkg:npm/left-pad@1.3.0").is_empty(),
                    "{index:?}"
                );
                assert!(
                    index.conflicts("pkg:npm/other@1.0.0").is_empty(),
                    "{index:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn workspace_members_and_parent_settings_are_both_consulted() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "pnpm-workspace.yaml",
            "packages: ['packages/*']\npatchedDependencies:\n  root@1.0.0: missing.patch\n",
        );
        write(tmp.path(), "packages/a/package.json", "{}");
        write(
            tmp.path(),
            "packages/a/patches/child+2.0.0.patch",
            "user diff",
        );
        for root in [tmp.path().to_path_buf(), tmp.path().join("packages/a")] {
            let index = UserPatchIndex::discover(&root).await;
            assert!(!index.conflicts("pkg:npm/root@1.0.0").is_empty());
            assert!(!index.conflicts("pkg:npm/child@2.0.0").is_empty());
            assert!(index.conflicts("pkg:npm/other@1.0.0").is_empty());
        }
    }

    #[tokio::test]
    async fn workspace_globs_do_not_block_unrelated_packages() {
        for pattern in [
            "packages/{a,b}",
            "packages/[ab]",
            "packages/@(a|b)",
            "packages/**",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(
                tmp.path(),
                "package.json",
                &serde_json::json!({"workspaces":[pattern]}).to_string(),
            );
            write(tmp.path(), "packages/a/package.json", "{}");
            write(
                tmp.path(),
                "packages/a/patches/child+2.0.0.patch",
                "user diff",
            );
            let index = UserPatchIndex::discover(tmp.path()).await;
            assert!(
                !index.conflicts("pkg:npm/child@2.0.0").is_empty(),
                "{pattern}: {index:?}"
            );
            assert!(
                index.conflicts("pkg:npm/other@1.0.0").is_empty(),
                "{pattern}: {index:?}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn linked_workspace_is_not_silently_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"workspaces":["packages/*"]}"#,
        );
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("packages")).unwrap();
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(!index.conflicts("pkg:npm/child@1.0.0").is_empty());
    }

    #[tokio::test]
    async fn composer_covers_external_locked_and_dependency_provided_patches() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "composer.json",
            r#"{"extra":{"composer-patches":{"patches-file":"custom.json"},"patches":{"a/root":{"fix":"x.patch"}}}}"#,
        );
        write(
            tmp.path(),
            "custom.json",
            r#"{"patches":{"a/external":[{"url":"x.patch"}]}}"#,
        );
        write(
            tmp.path(),
            "patches.lock.json",
            r#"{"patches":[{"package":"a/locked","url":"x.patch"}]}"#,
        );
        write(
            tmp.path(),
            "composer.lock",
            r#"{"packages":[{"extra":{"patches":{"a/transitive":{"fix":"x.patch"}}}}]}"#,
        );
        let index = UserPatchIndex::discover(tmp.path()).await;
        for name in ["root", "external", "locked", "transitive"] {
            assert!(!index
                .conflicts(&format!("pkg:composer/a/{name}@1.0.0"))
                .is_empty());
        }
        assert!(index.conflicts("pkg:composer/a/other@1.0.0").is_empty());
    }

    #[tokio::test]
    async fn cargo_and_go_preserve_user_overrides_and_recognize_socket_ownership() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "Cargo.toml", "[patch.crates-io]\nrenamed = { package = 'real', path = '../fork' }\nowned = { path = './.socket/vendor/cargo/uuid/owned' }\n[replace]\n'old:1.0.0' = { path = '../old' }\n");
        write(tmp.path(), "go.work", "go 1.23\nreplace (\n example.com/user v1.0.0 => ../fork\n example.com/owned v1.0.0 => ./.socket/go-patches/owned\n)\n");
        let index = UserPatchIndex::discover(tmp.path()).await;
        for purl in [
            "pkg:cargo/real@1.0.0",
            "pkg:cargo/Real@1.0.0",
            "pkg:cargo/old@1.0.0",
            "pkg:golang/example.com/user@v1.0.0",
        ] {
            assert!(!index.conflicts(purl).is_empty(), "{purl}: {index:?}");
        }
        for purl in [
            "pkg:cargo/renamed@1.0.0",
            "pkg:cargo/owned@1.0.0",
            "pkg:cargo/old@2.0.0",
            "pkg:golang/example.com/owned@v1.0.0",
        ] {
            assert!(index.conflicts(purl).is_empty(), "{purl}: {index:?}");
        }
    }

    #[tokio::test]
    async fn cd_after_patch_package_keeps_the_default_directory() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"patch-package && cd ios && pod install"}}"#,
        );
        write(tmp.path(), "patches/plain+1.0.0.patch", "user diff");
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(!index.conflicts("pkg:npm/plain@1.0.0").is_empty());
        assert!(
            index.conflicts("pkg:npm/other@1.0.0").is_empty(),
            "{index:?}"
        );

        write(
            tmp.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"cd app && patch-package"}}"#,
        );
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(!index.conflicts("pkg:npm/other@1.0.0").is_empty());
    }

    #[tokio::test]
    async fn a_word_ending_in_cd_is_not_a_directory_change() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"tsc -p ./src/abcd && patch-package"}}"#,
        );
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(
            index.conflicts("pkg:npm/other@1.0.0").is_empty(),
            "{index:?}"
        );
    }

    #[tokio::test]
    async fn yarn_alias_patch_protects_the_real_package() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"dependencies":{"alias":"patch:alias@npm%3Areal%401.0.0#./fix.patch"}}"#,
        );
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(
            !index.conflicts("pkg:npm/real@1.0.0").is_empty(),
            "{index:?}"
        );
        assert!(
            index.conflicts("pkg:npm/real@2.0.0").is_empty(),
            "{index:?}"
        );
    }

    #[test]
    fn locator_target_reads_plain_scoped_and_aliased_locators() {
        assert_eq!(locator_target("real@npm:1.0.0"), ("real", Some("1.0.0")));
        assert_eq!(locator_target("@s/p@npm:1.0.0"), ("@s/p", Some("1.0.0")));
        assert_eq!(locator_target("a@npm:real@1.0.0"), ("real", Some("1.0.0")));
        assert_eq!(locator_target("a@npm:@s/p@1.0.0"), ("@s/p", Some("1.0.0")));
        assert_eq!(locator_target("a@npm:"), ("a", Some("")));
        assert_eq!(locator_target("bare"), ("bare", None));
    }

    #[tokio::test]
    async fn cargo_path_merely_under_socket_vendor_is_still_a_user_override() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[patch.crates-io]\nserde = { path = '.socket/vendor/../../forks/serde' }\n",
        );
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(!index.conflicts("pkg:cargo/serde@1.0.0").is_empty());
    }

    #[tokio::test]
    async fn double_star_workspace_ignores_non_member_directories() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "pnpm-workspace.yaml",
            "packages: ['packages/**']\n",
        );
        write(tmp.path(), "packages/a/package.json", "{}");
        write(
            tmp.path(),
            "packages/a/src/fixtures/bad/package.json",
            "{broken",
        );
        write(tmp.path(), "packages/a/dist/x.js", "");
        let index = UserPatchIndex::discover(tmp.path()).await;
        // pnpm itself reads that broken manifest as a project, so it still
        // protects npm; directories without one are not inspected at all.
        assert!(!index.conflicts("pkg:npm/x@1.0.0").is_empty());
        std::fs::remove_file(tmp.path().join("packages/a/src/fixtures/bad/package.json")).unwrap();
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(index.conflicts("pkg:npm/x@1.0.0").is_empty(), "{index:?}");
    }

    /// #1900: a `workspaces` list with a non-string item is read through
    /// the shared package.json reader, which keeps its string patterns,
    /// so the members they name are still searched for patches, and
    /// unrelated npm packages are not marked as user-patched.
    #[tokio::test]
    async fn malformed_workspaces_still_walk_their_string_patterns() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"workspaces":["packages/*", 1]}"#,
        );
        write(tmp.path(), "packages/a/package.json", "{}");
        write(
            tmp.path(),
            "packages/a/patches/one+1.0.0.patch",
            "user diff",
        );
        let index = UserPatchIndex::discover(tmp.path()).await;
        assert!(
            !index.conflicts("pkg:npm/one@1.0.0").is_empty(),
            "{index:?}"
        );
        assert!(
            index.conflicts("pkg:npm/other@1.0.0").is_empty(),
            "{index:?}"
        );
    }

    #[tokio::test]
    async fn dot_dot_workspace_globs_resolve_lexically() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "app/package.json",
            r#"{"workspaces":["packages/b/../a", "../shared/*"]}"#,
        );
        write(tmp.path(), "app/packages/a/package.json", "{}");
        write(
            tmp.path(),
            "app/packages/a/patches/one+1.0.0.patch",
            "user diff",
        );
        write(tmp.path(), "shared/s/package.json", "{}");
        write(tmp.path(), "shared/s/patches/two+2.0.0.patch", "user diff");
        let index = UserPatchIndex::discover(&tmp.path().join("app")).await;
        assert!(
            !index.conflicts("pkg:npm/one@1.0.0").is_empty(),
            "{index:?}"
        );
        assert!(
            !index.conflicts("pkg:npm/two@2.0.0").is_empty(),
            "{index:?}"
        );
        assert!(
            index.conflicts("pkg:npm/other@1.0.0").is_empty(),
            "{index:?}"
        );
    }

    #[tokio::test]
    async fn go_work_members_replaces_are_consulted() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "go.work", "go 1.23\nuse (\n ./app\n)\n");
        write(
            tmp.path(),
            "app/go.mod",
            "module example.com/app\nreplace example.com/user => ../fork\n",
        );
        for root in [tmp.path().to_path_buf(), tmp.path().join("app")] {
            let index = UserPatchIndex::discover(&root).await;
            assert!(!index
                .conflicts("pkg:golang/example.com/user@v1.0.0")
                .is_empty());
            assert!(index
                .conflicts("pkg:golang/example.com/other@v1.0.0")
                .is_empty());
        }
    }

    /// A file that cannot be parsed protects its ecosystem like any
    /// unknown metadata, but it is told apart from a patch the project
    /// declares: the remedy is to fix the file, and the source says what is
    /// wrong with it.
    #[tokio::test]
    async fn an_unparseable_file_is_told_apart_from_a_declared_patch() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "package.json", "{ \"name\": ");
        let index = UserPatchIndex::discover(tmp.path()).await;
        let sources = index.conflicts("pkg:npm/lodash@4.17.20");
        assert_eq!(sources.len(), 1, "{sources:?}");
        assert!(
            sources[0].ends_with(
                "package.json (not valid JSON: EOF while parsing a value at line 1 column 10)"
            ),
            "{sources:?}"
        );
        assert!(index.unreadable_only("pkg:npm/lodash@4.17.20"));
        assert!(!index.unreadable_only("pkg:pypi/lodash@4.17.20"));

        // A declared patch, and metadata that is readable but not
        // understood, are not "fix the file" cases.
        for text in [
            r#"{"pnpm":{"patchedDependencies":{"lodash":"x.patch"}}}"#,
            r#"{"patchedDependencies": "invalid"}"#,
            r#"{"scripts":{"postinstall":"patch-package --patch-dir $PATCH_DIR"}}"#,
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(tmp.path(), "package.json", text);
            let index = UserPatchIndex::discover(tmp.path()).await;
            assert!(
                !index.conflicts("pkg:npm/lodash@4.17.20").is_empty(),
                "{text}"
            );
            assert!(!index.unreadable_only("pkg:npm/lodash@4.17.20"), "{text}");
        }

        // An unreadable lock is the same class.
        let mut index = UserPatchIndex::default();
        index.unreadable_lock(
            "pnpm-lock.yaml",
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert!(index.unreadable_only("pkg:npm/lodash@4.17.20"));
        assert!(
            index.conflicts("pkg:npm/lodash@4.17.20")[0]
                .starts_with("pnpm-lock.yaml (cannot be read: "),
            "{:?}",
            index.conflicts("pkg:npm/lodash@4.17.20")
        );
    }

    #[tokio::test]
    async fn unknown_metadata_does_not_silently_allow_patching() {
        for text in [
            r#"{"patchedDependencies": "invalid"}"#,
            r#"{"scripts":{"postinstall":"patch-package --patch-dir $PATCH_DIR"}}"#,
            r#"{"scripts":{"postinstall":"patch-package --patch-dir missing"}}"#,
            "{broken json",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(tmp.path(), "package.json", text);
            let index = UserPatchIndex::discover(tmp.path()).await;
            assert!(
                !index.conflicts("pkg:npm/anything@1.0.0").is_empty(),
                "{text}"
            );
            assert!(index.conflicts("pkg:pypi/anything@1.0.0").is_empty());
        }
    }

    /// The repository-root bound is a workspace-run rule only. A workspace
    /// run reads no workspace member or `--patch-dir` outside the git
    /// repository: each protects every npm package instead. A global run
    /// reads both wherever they are and protects exactly the packages they
    /// patch.
    #[tokio::test]
    async fn the_repository_bound_holds_for_workspace_runs_only() {
        let outer = tempfile::tempdir().unwrap();
        let repo = outer.path().join("repo");
        write(&repo, ".git/HEAD", "ref: refs/heads/main\n");
        write(
            &repo,
            "package.json",
            r#"{"workspaces":["../shared/*"],"scripts":{"postinstall":"patch-package --patch-dir ../fixes"}}"#,
        );
        write(outer.path(), "fixes/left-pad+1.3.0.patch", "diff\n");
        write(outer.path(), "shared/a/package.json", "{}");
        write(
            outer.path(),
            "shared/a/patches/is-number+7.0.0.patch",
            "diff\n",
        );

        let workspace = UserPatchIndex::discover_scoped(&repo, ReadScope::Workspace).await;
        let sources = workspace.conflicts("pkg:npm/other@1.0.0");
        for what in [
            "workspace outside the git repository",
            "patch-package directory outside",
        ] {
            assert!(
                sources.iter().any(|s| s.contains(what)),
                "{what}: {sources:?}"
            );
        }
        assert!(
            !sources.iter().any(|s| s.ends_with(".patch")),
            "{sources:?}"
        );
        assert_eq!(
            UserPatchIndex::discover(&repo)
                .await
                .conflicts("pkg:npm/other@1.0.0"),
            sources,
            "discover() is the workspace scope"
        );

        let global = UserPatchIndex::discover_scoped(&repo, ReadScope::Global).await;
        assert!(
            global.conflicts("pkg:npm/other@1.0.0").is_empty(),
            "{global:?}"
        );
        let left_pad = global.conflicts("pkg:npm/left-pad@1.3.0");
        assert!(
            left_pad
                .iter()
                .any(|s| s.replace('\\', "/").ends_with("fixes/left-pad+1.3.0.patch")),
            "{left_pad:?}"
        );
        let is_number = global.conflicts("pkg:npm/is-number@7.0.0");
        assert!(
            is_number.iter().any(|s| s
                .replace('\\', "/")
                .ends_with("shared/a/patches/is-number+7.0.0.patch")),
            "{is_number:?}"
        );
        assert!(global.conflicts("pkg:npm/right-pad@1.3.0").is_empty());
        assert_eq!(ReadScope::of_global(true), ReadScope::Global);
        assert_eq!(ReadScope::of_global(false), ReadScope::Workspace);
    }

    /// Review (#2018): a `go.work` `use` member outside the git repository
    /// is not read in a workspace run, and protects every Go module (the
    /// ecosystem whose declaration named it), not every npm package.
    #[tokio::test]
    async fn an_out_of_repo_go_member_protects_go_not_npm() {
        let outer = tempfile::tempdir().unwrap();
        let repo = outer.path().join("repo");
        write(&repo, ".git/HEAD", "ref: refs/heads/main\n");
        write(&repo, "go.work", "go 1.22\n\nuse (\n\t.\n\t../shared\n)\n");
        write(&repo, "go.mod", "module example.com/app\n\ngo 1.22\n");
        write(
            outer.path(),
            "shared/go.mod",
            "module example.com/shared\n\ngo 1.22\n\nreplace example.com/dep => ../dep\n",
        );
        let index = UserPatchIndex::discover(&repo).await;
        let go = index.conflicts("pkg:golang/example.com/other@v1.0.0");
        assert!(
            go.iter().any(|s| s.contains("outside the git repository")),
            "{go:?}"
        );
        assert!(
            index.conflicts("pkg:npm/left-pad@1.3.0").is_empty(),
            "{index:?}"
        );
        // A global run reads it: only the replaced module is protected.
        let global = UserPatchIndex::discover_scoped(&repo, ReadScope::Global).await;
        assert!(!global
            .conflicts("pkg:golang/example.com/dep@v1.0.0")
            .is_empty());
        assert!(global
            .conflicts("pkg:golang/example.com/other@v1.0.0")
            .is_empty());
    }

    /// Review (#2018): an absolute `--patch-dir` inside the repository is
    /// read like a relative one (it is not "outside" for being absolute).
    #[tokio::test]
    async fn an_absolute_patch_dir_inside_the_repository_is_read() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = std::fs::canonicalize(tmp.path()).unwrap();
        write(&repo, ".git/HEAD", "ref: refs/heads/main\n");
        // Spelled as a user types it: on Windows without the `\\?\` prefix
        // `canonicalize` adds to `repo`, quoted in case the temp dir has a
        // space, and built as JSON so its backslashes are escaped.
        let fixes =
            crate::utils::pnpm_workspace::without_verbatim_prefix(repo.clone()).join("fixes");
        let manifest = serde_json::json!({
            "scripts": {
                "postinstall": format!("patch-package --patch-dir \"{}\"", fixes.display())
            }
        });
        write(&repo, "package.json", &manifest.to_string());
        write(&repo, "fixes/left-pad+1.3.0.patch", "diff\n");
        let index = UserPatchIndex::discover(&repo).await;
        assert!(
            !index.conflicts("pkg:npm/left-pad@1.3.0").is_empty(),
            "{index:?}"
        );
        assert!(
            index.conflicts("pkg:npm/other@1.0.0").is_empty(),
            "{index:?}"
        );
    }

    /// Review (#2018): through a symlinked project root, the ancestor
    /// workspace settings are found and read where the directory really is
    /// (where a `..` read lands), not at the link's lexical parent.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_root_reads_its_real_ancestors() {
        let outer = tempfile::tempdir().unwrap();
        let real = outer.path().join("real");
        write(&real, ".git/HEAD", "ref: refs/heads/main\n");
        write(
            &real,
            "pnpm-workspace.yaml",
            "packages:\n  - 'app'\npatchedDependencies:\n  left-pad@1.3.0: p.patch\n",
        );
        write(&real, "app/package.json", "{}");
        let link = outer.path().join("link");
        std::os::unix::fs::symlink(real.join("app"), &link).unwrap();
        for view_root in [&link, &real.join("app")] {
            let index = UserPatchIndex::discover(view_root).await;
            assert!(
                !index.conflicts("pkg:npm/left-pad@1.3.0").is_empty(),
                "{}: {index:?}",
                view_root.display()
            );
            let view = ProjectView::Disk(view_root);
            let index = UserPatchIndex::npm_family_in(&view, &[]).await;
            assert!(!index.conflicts("pkg:npm/left-pad@1.3.0").is_empty());
            assert!(index.conflicts("pkg:npm/other@1.0.0").is_empty());
        }
    }

    /// Final review (#2018): a project file symlinked to a target outside
    /// the repository is refused by the view's bound, but the package
    /// manager still reads it, so it is read through the link: its
    /// declarations protect their packages instead of reading as "no
    /// patches", and a package it does not name stays patchable (the
    /// writer's own symlinked-file refusal handles the link).
    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_file_outside_the_repository_is_read_through_the_link() {
        let outer = tempfile::tempdir().unwrap();
        let repo = outer.path().join("repo");
        write(&repo, ".git/HEAD", "ref: refs/heads/main\n");
        write(&repo, "package.json", "{}");
        write(
            outer.path(),
            "shared/pnpm-workspace.yaml",
            "patchedDependencies:\n  left-pad@1.3.0: p.patch\n",
        );
        std::os::unix::fs::symlink(
            outer.path().join("shared/pnpm-workspace.yaml"),
            repo.join("pnpm-workspace.yaml"),
        )
        .unwrap();
        let view = ProjectView::Disk(&repo);
        let index = UserPatchIndex::npm_family_in(&view, &[]).await;
        assert!(
            !index.conflicts("pkg:npm/left-pad@1.3.0").is_empty(),
            "{index:?}"
        );
        assert!(
            index.conflicts("pkg:npm/other@1.0.0").is_empty(),
            "{index:?}"
        );
    }

    /// A refused symlink that can't be read through the link either (its
    /// target outside the repository is not a regular file) fails closed:
    /// unknown metadata protects every npm package.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_unreadable_symlinked_file_outside_the_repository_fails_closed() {
        let outer = tempfile::tempdir().unwrap();
        let repo = outer.path().join("repo");
        write(&repo, ".git/HEAD", "ref: refs/heads/main\n");
        write(&repo, "package.json", "{}");
        std::fs::create_dir_all(outer.path().join("shared/pnpm-workspace.yaml")).unwrap();
        std::os::unix::fs::symlink(
            outer.path().join("shared/pnpm-workspace.yaml"),
            repo.join("pnpm-workspace.yaml"),
        )
        .unwrap();
        let view = ProjectView::Disk(&repo);
        let index = UserPatchIndex::npm_family_in(&view, &[]).await;
        assert!(
            !index.conflicts("pkg:npm/other@1.0.0").is_empty(),
            "{index:?}"
        );
    }

    /// The view-based index the hosted engine and `vex` discovery read
    /// ([`UserPatchIndex::npm_family_in`]) protects exactly what the CLI's
    /// consent gate ([`UserPatchIndex::discover`]) protects for a root
    /// project's pnpm, yarn and patch-package declarations, so hosted,
    /// vendored and discovery never disagree about one, in memory and on
    /// disk. npm's and Bun's own top-level `patchedDependencies` are the
    /// gate's alone: their rewriters and extractors judge them per
    /// resolution.
    #[tokio::test]
    async fn npm_family_view_index_agrees_with_the_consent_gate() {
        use crate::vendor::lock_inventory::{MemoryEntry, MemoryProject};

        const LOCK: &str = "pnpm-lock.yaml";
        let pnpm_lock = "lockfileVersion: '9.0'\n\npatchedDependencies:\n  left-pad@1.3.0:\n    hash: abc\n    path: patches/left-pad.patch\n\npackages:\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n\nsnapshots:\n  left-pad@1.3.0(patch_hash=abc): {}\n";
        let berry_lock = "__metadata:\n  version: 8\n\n\"left-pad@patch:left-pad@npm%3A1.3.0#./.yarn/patches/lp.patch\":\n  version: 1.3.0\n  resolution: \"left-pad@patch:left-pad@npm%3A1.3.0#./.yarn/patches/lp.patch::version=1.3.0&hash=abc\"\n";
        let cases: &[(&[(&str, &str)], bool)] = &[
            (&[(LOCK, pnpm_lock)], true),
            (&[("yarn.lock", berry_lock)], true),
            (
                &[(
                    "pnpm-workspace.yaml",
                    "patchedDependencies:\n  left-pad: p.patch\n",
                )],
                true,
            ),
            (
                &[(
                    "package.json",
                    r#"{"pnpm":{"patchedDependencies":{"left-pad@^1":"p.patch"}}}"#,
                )],
                true,
            ),
            (
                &[(
                    "package.json",
                    r#"{"resolutions":{"left-pad":"patch:left-pad@npm%3A1.3.0#./p.patch"}}"#,
                )],
                true,
            ),
            (&[("patches/left-pad+1.3.0.patch", "diff")], true),
            (
                &[
                    (
                        "package.json",
                        r#"{"scripts":{"postinstall":"patch-package --patch-dir fixes"}}"#,
                    ),
                    ("fixes/left-pad+1.3.0.patch", "diff"),
                ],
                true,
            ),
            // patch-package applies a patch to any installed version.
            (&[("patches/left-pad+1.2.0.patch", "diff")], true),
            (&[("patches/@scope/left-pad+1.3.0.patch", "diff")], false),
            (
                &[(
                    "package.json",
                    r#"{"resolutions":{"x":"patch:x@npm%3A1.0.0#~/.yarn/patches/x.patch"}}"#,
                )],
                false,
            ),
            (&[("package.json", "{broken json")], true),
        ];
        for (files, protected) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let mut memory = MemoryProject::new();
            for (path, text) in *files {
                write(tmp.path(), path, text);
                memory.insert(*path, MemoryEntry::Text((*text).into()));
            }
            let gate = UserPatchIndex::discover(tmp.path()).await;
            let locks: Vec<(&str, &str)> = files
                .iter()
                .copied()
                .filter(|(p, _)| *p == LOCK || *p == "yarn.lock")
                .collect();
            for view in [ProjectView::Disk(tmp.path()), ProjectView::Memory(&memory)] {
                let index = UserPatchIndex::npm_family_in(&view, &locks).await;
                for purl in ["pkg:npm/left-pad@1.3.0", "pkg:npm/other@1.0.0"] {
                    let want =
                        *protected && (purl.contains("left-pad") || files[0].1 == "{broken json");
                    assert_eq!(
                        !gate.conflicts(purl).is_empty(),
                        want,
                        "gate {files:?} {purl}"
                    );
                    assert_eq!(
                        !index.conflicts(purl).is_empty(),
                        want,
                        "{files:?} {purl}: {index:?}"
                    );
                }
            }
        }
        // npm's and Bun's own map: the gate's alone.
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"patchedDependencies":{"left-pad@1.3.0":"p.patch"}}"#,
        );
        let purl = "pkg:npm/left-pad@1.3.0";
        assert!(!UserPatchIndex::discover(tmp.path())
            .await
            .conflicts(purl)
            .is_empty());
        let index = UserPatchIndex::npm_family_in(&ProjectView::Disk(tmp.path()), &[]).await;
        assert!(index.is_empty(), "{index:?}");
    }
}
