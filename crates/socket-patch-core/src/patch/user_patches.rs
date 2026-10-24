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

use crate::formats::text::strip_bom;
use crate::utils::fs::read_regular_to_string;
use crate::utils::npm_range::npm_range_admits;
use crate::utils::purl::{normalize_purl, percent_decode_purl_component, strip_purl_qualifiers};
use crate::utils::workspace_globs::{workspaces_include_as, WorkspacesDialect};

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
}

impl UserPatchIndex {
    /// Inspect the project, declared workspace members and ancestor workspace
    /// settings. Errors in a potentially governing file protect its ecosystem;
    /// unreadable metadata must not silently disable the consent check.
    pub async fn discover(root: &Path) -> Self {
        let mut index = Self::default();
        let root = std::path::absolute(root).unwrap_or_else(|_| root.to_path_buf());
        let mut pending = VecDeque::from([root.clone()]);
        // A member invocation still inherits the workspace's patch policy.
        // The walk stops at the checkout's `.git`, and never reaches the home
        // directory (whose `~/.cargo/config.toml` is user-wide, not a
        // workspace) or above it, as in a container build with no `.git`.
        let home = crate::utils::fs::home_dir();
        for parent in root
            .ancestors()
            .skip(1)
            .take_while(|_| !root.join(".git").exists())
            .take_while(|parent| home.as_deref().is_none_or(|home| !home.starts_with(parent)))
        {
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
                pending.push_back(parent.to_path_buf());
            }
            if parent.join(".git").exists() {
                break;
            }
        }
        let mut seen = BTreeSet::new();
        while let Some(dir) = pending.pop_front() {
            if !seen.insert(dir.clone()) {
                continue;
            }
            if seen.len() > 4096 {
                index.unknown("npm", &dir, "workspace inspection limit exceeded");
                break;
            }
            let mut globs = Vec::new();
            if let Some(value) = index.json(&dir.join("package.json"), "npm").await {
                index.native(&value, &dir.join("package.json"));
                for field in [
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                    "resolutions",
                ] {
                    if let Some(map) = value[field].as_object() {
                        for spec in map.values().filter_map(Value::as_str) {
                            index.yarn(spec, &dir.join("package.json"));
                        }
                    }
                }
                let workspaces = value["workspaces"]
                    .as_array()
                    .or_else(|| value["workspaces"]["packages"].as_array());
                if let Some(workspaces) = workspaces {
                    globs.extend(
                        workspaces
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned),
                    );
                }
                index.patch_package(&dir, &value).await;
            } else {
                index.patch_directory(&dir.join("patches"), false).await;
            }
            let yarn_lock = dir.join("yarn.lock");
            if let Some(text) = index.read(&yarn_lock, "npm").await {
                // Only Berry has patch: locators. Every Berry lock carries
                // builtin compat patches, so scan the resolution lines rather
                // than parse what can be a very large lockfile, and visit
                // only the few lines that can hold one.
                for line in lines_containing(&text, "@patch:") {
                    let Some(value) = line.trim_start().strip_prefix("resolution:") else {
                        continue;
                    };
                    let value = value.trim().trim_matches('"');
                    // A locator has an ident before @patch:.
                    if let Some((_, source)) = value.split_once("@patch:") {
                        index.yarn(&format!("patch:{source}"), &yarn_lock);
                    }
                }
            }
            for file in ["pnpm-workspace.yaml", "pnpm-lock.yaml"] {
                let path = dir.join(file);
                if let Some(text) = index.read(&path, "npm").await {
                    if file == "pnpm-lock.yaml"
                        && !text.contains("patchedDependencies")
                        && !text.contains("patch_hash")
                        && !text.contains("patched:")
                    {
                        continue;
                    }
                    match serde_saphyr::from_multiple_with_options::<Value>(&text, lock_options()) {
                        Ok(documents) => {
                            for value in documents {
                                index.native(&value, &path);
                                if file == "pnpm-workspace.yaml" {
                                    if let Some(packages) = value["packages"].as_array() {
                                        globs.extend(
                                            packages
                                                .iter()
                                                .filter_map(Value::as_str)
                                                .map(str::to_owned),
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => index.unknown(
                            "npm",
                            &path,
                            &format!("cannot inspect patch metadata: {e}"),
                        ),
                    }
                }
            }
            for file in ["package-lock.json", "npm-shrinkwrap.json", "bun.lock"] {
                let path = dir.join(file);
                // Like the pnpm lock: a lock that never says `patched` holds
                // no patch evidence, so an unparseable one can't hide any.
                let Some(text) = index
                    .read(&path, "npm")
                    .await
                    .filter(|text| text.contains("patched"))
                else {
                    continue;
                };
                if let Some(value) = index.parse_json(&text, &path, "npm") {
                    index.native(&value, &path);
                    if let Some(packages) = value["packages"].as_object() {
                        for (key, entry) in packages {
                            if !entry["patched"].is_null() {
                                let name = entry["name"].as_str().or_else(|| {
                                    key.rsplit_once("node_modules/").map(|(_, name)| name)
                                });
                                if let Some(name) = name {
                                    index.add("npm", name, entry["version"].as_str(), &path);
                                } else {
                                    index.unknown("npm", &path, "unidentified patched lock entry");
                                }
                            }
                        }
                    }
                }
            }
            index.composer(&dir).await;
            index.cargo(&dir).await;
            for file in ["go.mod", "go.work"] {
                let path = dir.join(file);
                if let Some(text) = index.read(&path, "golang").await {
                    for entry in crate::vendor::go_mod_edit::parse_replace_entries(&text) {
                        if !entry.socket_owned() {
                            index.add("golang", &entry.module, entry.version.as_deref(), &path);
                        }
                    }
                    // Workspace members' go.mod replaces still apply under go.work.
                    if file == "go.work" {
                        pending.extend(
                            crate::vendor::go_mod_edit::parse_use_dirs(&text)
                                .into_iter()
                                .map(|member| dir.join(member)),
                        );
                    }
                }
            }
            for pattern in globs
                .iter()
                .filter(|g| !g.starts_with('!') || g.starts_with("!("))
            {
                pending.extend(index.workspace_members(&dir, pattern));
            }
        }
        index
    }

    // Use the existing npm/Yarn glob grammar, with a bounded, link-free walk.
    // Positive patterns are a conservative union: a patch in an excluded member
    // may still protect the same release elsewhere, never silently lose it.
    fn workspace_members(&mut self, root: &Path, pattern: &str) -> Vec<std::path::PathBuf> {
        if Path::new(pattern).is_absolute() {
            self.unknown("npm", root, "workspace outside the inspection root");
            return Vec::new();
        }
        // Resolve `..` lexically: `packages/b/../a` is `packages/a`, and a
        // leading `../shared/*` re-roots the walk at the parent.
        let mut root = root.to_path_buf();
        let mut segments: Vec<&str> = Vec::new();
        for segment in pattern.split('/') {
            match segment {
                "" | "." => {}
                ".." => match segments.last() {
                    Some(last) if last.contains(['*', '?', '{', '[', '(']) => {
                        self.unknown("npm", &root, "workspace glob traverses a wildcard");
                        return Vec::new();
                    }
                    Some(_) => {
                        segments.pop();
                    }
                    None => {
                        if !root.pop() {
                            self.unknown("npm", &root, "workspace outside the filesystem root");
                            return Vec::new();
                        }
                    }
                },
                _ => segments.push(segment),
            }
        }
        let pattern = segments.join("/");
        let (root, pattern) = (root.as_path(), pattern.as_str());
        let prefix: std::path::PathBuf = pattern
            .split('/')
            .take_while(|p| !p.contains(['*', '?', '{', '[', '(']))
            .collect();
        let base = root.join(&prefix);
        if !base.exists() && !base.is_symlink() {
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
        let walk = walkdir::WalkDir::new(&base)
            .follow_links(false)
            .max_depth(max_depth)
            .into_iter()
            .filter_entry(|entry| {
                (entry.file_type().is_dir() || entry.path_is_symlink())
                    && !matches!(
                        entry.file_name().to_str(),
                        Some("node_modules" | ".git" | ".socket" | "target" | ".venv")
                    )
            });
        let mut out = Vec::new();
        let patterns = vec![pattern.to_string()];
        for (count, entry) in walk.enumerate() {
            if count >= 16384 {
                self.unknown("npm", root, "workspace inspection limit exceeded");
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    self.unknown("npm", root, &format!("cannot inspect workspace: {error}"));
                    continue;
                }
            };
            let components: Vec<_> = entry
                .path()
                .strip_prefix(root)
                .unwrap_or(entry.path())
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            if entry.depth() == 32 && entry.file_type().is_dir() {
                self.unknown("npm", entry.path(), "workspace inspection depth exceeded");
            }
            // Package managers only treat a directory with a package.json as
            // a workspace; anything else under a `**` glob is just source.
            let member = entry.path().join("package.json").is_file();
            if entry.file_type().is_symlink() {
                // The walk doesn't follow links, so a link that is (or leads
                // to) a member can't be inspected.
                if entry.depth() == 0
                    || (entry.path().is_dir()
                        && (member
                            || workspaces_include_as(
                                &patterns,
                                &components,
                                WorkspacesDialect::YARN_BERRY,
                            ) && !pattern.contains("**")))
                {
                    self.unknown(
                        "npm",
                        entry.path(),
                        "linked workspace cannot be inspected safely",
                    );
                }
                continue;
            }
            if member
                && workspaces_include_as(&patterns, &components, WorkspacesDialect::YARN_BERRY)
            {
                out.push(entry.path().to_path_buf());
            }
        }
        out
    }

    /// All evidence for this release, sorted and deduplicated. Unknown ranges
    /// protect every version of that name; known exact versions don't block an
    /// unrelated release. Scoped npm identities remain case-sensitive.
    pub fn conflicts(&self, purl: &str) -> Vec<String> {
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
            .map(|e| e.source.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn add(&mut self, ecosystem: &'static str, name: &str, version: Option<&str>, path: &Path) {
        self.entries.push(Evidence {
            ecosystem,
            name: name.into(),
            version: version.map(str::to_owned),
            source: path.display().to_string(),
        });
    }

    fn unknown(&mut self, ecosystem: &'static str, path: &Path, reason: &str) {
        self.entries.push(Evidence {
            ecosystem,
            name: String::new(),
            version: None,
            source: format!("{} ({reason})", path.display()),
        });
    }

    async fn read(&mut self, path: &Path, ecosystem: &'static str) -> Option<String> {
        match read_regular_to_string(path).await {
            Ok(text) => Some(strip_bom(&text).to_owned()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                self.unknown(
                    ecosystem,
                    path,
                    &format!("cannot inspect patch metadata: {e}"),
                );
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
                self.unknown(
                    ecosystem,
                    path,
                    &format!("cannot inspect patch metadata: {e}"),
                );
                None
            }
        }
    }

    fn native(&mut self, value: &Value, path: &Path) {
        for field in [
            &value["patchedDependencies"],
            &value["pnpm"]["patchedDependencies"],
        ] {
            if let Some(map) = field.as_object() {
                for key in map.keys() {
                    let (name, version) = split_selector(key);
                    self.add("npm", name, version, path);
                }
            } else if !field.is_null() {
                self.unknown("npm", path, "invalid patchedDependencies");
            }
        }
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

    fn yarn(&mut self, spec: &str, path: &Path) {
        if !spec.starts_with("patch:") {
            return;
        }
        let mut source = spec.to_owned();
        let mut user_patch = false;
        // Inspect every layer: a compatibility patch can wrap a user patch,
        // or vice versa. Both still belong to the original package.
        for _ in 0..16 {
            if let Some(inner) = source
                .strip_prefix("patch:")
                .or_else(|| source.split_once("@patch:").map(|(_, rest)| rest))
            {
                let Some((original, patches)) = inner.split_once('#') else {
                    self.unknown("npm", path, "unrecognized patch: reference");
                    return;
                };
                // Only Yarn's compatibility namespace is exempt. Plugins can
                // supply their own builtin patches through getBuiltinPatch.
                let patches = percent_decode_purl_component(patches);
                user_patch |= !patches
                    .split("::")
                    .next()
                    .unwrap_or(&patches)
                    .split('&')
                    .all(|p| {
                        let p = p.rsplit('!').next().unwrap_or(p).trim_start_matches('~');
                        p.starts_with("builtin<compat/") && p.ends_with('>')
                    });
                source = percent_decode_purl_component(original).into_owned();
                continue;
            }
            if user_patch {
                let (name, version) = locator_target(&source);
                self.add("npm", name, version, path);
            }
            return;
        }
        self.unknown(
            "npm",
            path,
            "patch locator nesting exceeds inspection limit",
        );
    }

    async fn patch_package(&mut self, dir: &Path, value: &Value) {
        self.patch_directory(&dir.join("patches"), false).await;
        // Compiled once, and only for a project whose scripts run patch-package.
        static FLAG: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r#"--patch-dir(?:=|\s+)(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))"#).unwrap()
        });
        // `cd` as a command, not the tail of a word like `abcd`.
        static CD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:^|[\s;&|(])cd\s").unwrap());
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
                        &dir.join("package.json"),
                        "cannot resolve patch-package directory without executing the script",
                    );
                }
                for captures in FLAG.captures_iter(script) {
                    let path = captures.iter().skip(1).flatten().next().unwrap().as_str();
                    if path.contains(['$', '`']) || moved {
                        self.unknown(
                            "npm",
                            &dir.join("package.json"),
                            "dynamic patch-package directory; inspect it before opting in",
                        );
                    } else {
                        self.patch_directory(&dir.join(path), true).await;
                    }
                }
            }
        }
    }

    async fn patch_directory(&mut self, dir: &Path, required: bool) {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if !required && e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                self.unknown(
                    "npm",
                    dir,
                    &format!("cannot inspect patch-package directory: {e}"),
                );
                return;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    self.unknown("npm", dir, &e.to_string());
                    continue;
                }
            };
            let file = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = file.strip_suffix(".patch") else {
                continue;
            };
            let leaf = stem.rsplit("++").next().unwrap_or(stem);
            let parts: Vec<_> = leaf.split('+').collect();
            let scoped = leaf.starts_with('@');
            let version_idx = if scoped { 2 } else { 1 };
            if let Some(version) = parts.get(version_idx) {
                let version = version.trim_end_matches(".dev");
                let name = if scoped {
                    format!("{}/{}", parts[0], parts[1])
                } else {
                    parts[0].to_string()
                };
                self.add("npm", &name, Some(version), &entry.path());
            } else if required {
                self.unknown("npm", &entry.path(), "unrecognized patch-package filename");
            }
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
        assert!(index.conflicts("pkg:npm/@s/pkg@1.3.0").is_empty());
        assert!(index.conflicts("pkg:npm/parent@1.2.0").is_empty());
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
}
