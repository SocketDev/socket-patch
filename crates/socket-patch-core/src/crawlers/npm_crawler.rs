use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::FileType;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::types::{CrawledPackage, CrawlerOptions};
use super::walk_pool::{par_map, run_walk};
use crate::formats::text::strip_bom;
use crate::patch::path_safety;
use crate::utils::fs::{is_dir, is_dir_sync, read_dir_entries_sync};
use crate::utils::purl::{percent_decode_purl_component, strip_purl_qualifiers};
use crate::vendor::vlt_lock_text::decode_vlt_dep_id;

#[cfg(test)]
mod oracle;

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
// Helper: package-manager-configured install roots
// ---------------------------------------------------------------------------

/// The `node_modules`-equivalent dirs a package manager is CONFIGURED to
/// install the project at `start_path` into, which the workspace walk
/// cannot find by name (it only collects dirs literally named
/// `node_modules`, and prunes `temp`):
/// - yarn classic's effective modules folder from the `.yarnrc` files at
///   or above the project (see [`yarnrc_modules_folder`]);
/// - Rush's `common/temp/node_modules` when `rush.json` is at the root:
///   rush runs pnpm there, so every transitive dep lives in its `.pnpm`
///   store and the projects' own `node_modules` hold only links to their
///   direct deps.
///
/// - pnpm's `modulesDir` (see [`pnpm_modules_dirs`]): pnpm installs the
///   project there instead of `node_modules`, and from pnpm 10.12 its
///   virtual store follows (`<modulesDir>/.pnpm`), so nothing of the
///   install is under a dir named `node_modules` (#661).
///
/// Only existing directories are returned.
pub(super) fn configured_install_roots(start_path: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(folder) = yarnrc_modules_folder(start_path) {
        roots.push(start_path.join(folder));
    }
    if start_path.join("rush.json").is_file() {
        roots.push(start_path.join("common").join("temp").join("node_modules"));
    }
    roots.extend(pnpm_modules_dirs(start_path));
    roots.retain(|root| root.is_dir());
    let mut seen = HashSet::new();
    roots.retain(|root| seen.insert(root.clone()));
    roots
}

/// The project's pnpm `modulesDir` install roots, other than
/// `node_modules` itself:
/// - the configured setting ([`pnpm_modules_dir_setting`]), resolved
///   against the project like pnpm does, and honored only strictly inside
///   it (the value comes from the scanned project and names a tree apply
///   WRITES into; see [`resolve_modules_folder`]);
/// - any direct child dir holding pnpm's `.modules.yaml` install record,
///   which pnpm writes into whatever modules dir it used. That finds an
///   install whose `modulesDir` came from pnpm's global config or the
///   environment, which the project's files do not show.
fn pnpm_modules_dirs(start_path: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) =
        pnpm_modules_dir_setting(start_path).and_then(|raw| resolve_modules_folder(&[], &raw))
    {
        dirs.push(start_path.join(dir));
    }
    let Some((entries, _)) = read_dir_entries_sync(start_path) else {
        return dirs;
    };
    for entry in entries {
        let name = entry.file_name();
        if name == OsStr::new("node_modules") || !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let dir = start_path.join(name);
        if std::fs::symlink_metadata(dir.join(PNPM_MODULES_YAML)).is_ok_and(|m| m.is_file()) {
            dirs.push(dir);
        }
    }
    dirs
}

/// The raw pnpm `modulesDir` setting that applies to the project at
/// `start_path`: `modulesDir:` in the nearest `pnpm-workspace.yaml` at or
/// above it (the workspace's settings file on pnpm 10+, which wins over
/// `.npmrc`), else `modules-dir` from the nearest `.npmrc` at or above it
/// that sets it (pnpm up to 10). Read with
/// [`crate::utils::fs::read_regular_to_string_sync`]: the files belong to
/// the (untrusted) project.
fn pnpm_modules_dir_setting(start_path: &Path) -> Option<String> {
    let read = |path: PathBuf| crate::utils::fs::read_regular_to_string_sync(&path).ok();
    let from_workspace = start_path
        .ancestors()
        .find_map(|dir| read(dir.join("pnpm-workspace.yaml")))
        .and_then(|yaml| {
            crate::formats::text::strip_bom(&yaml)
                .lines()
                .filter_map(crate::formats::pnpm::workspace::top_level_key)
                .rfind(|(key, _)| key == "modulesDir")
                .map(|(_, value)| unquote_yaml_scalar(value))
        });
    from_workspace
        .or_else(|| {
            start_path.ancestors().find_map(|dir| {
                let npmrc = read(dir.join(".npmrc"))?;
                crate::patch::redirect::npmrc::npmrc_top_level_value(&npmrc, "modules-dir")
            })
        })
        .filter(|value| !value.is_empty())
}

/// A YAML flow scalar's value: quotes removed (`''` is a literal quote
/// inside single quotes), a plain scalar as is.
fn unquote_yaml_scalar(raw: &str) -> String {
    if raw.starts_with('"') {
        if let Ok(value) = serde_json::from_str::<String>(raw) {
            return value;
        }
    } else if let Some(inner) = raw.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')) {
        return inner.replace("''", "'");
    }
    raw.to_string()
}

/// Whether the installed pnpm tree of the project at `project` keeps its
/// virtual store where the crawler does not look: a `.modules.yaml` in
/// `node_modules` or a pnpm modules dir ([`pnpm_modules_dirs`]) records a
/// `virtualStoreDir` outside the project, as pnpm's global virtual store
/// (`enableGlobalVirtualStore`) and a `virtualStoreDir` that climbs out
/// do. Only direct deps are linked into the project then, so a package
/// the crawler does not find may still be installed (as a transitive dep)
/// and must not be read as absent (#696). `false` with no pnpm install.
pub fn pnpm_store_outside_project(project: &Path) -> bool {
    let mut modules_dirs = vec![project.join("node_modules")];
    modules_dirs.extend(pnpm_modules_dirs(project));
    modules_dirs.iter().any(|nm| {
        let Ok(text) = crate::utils::fs::read_regular_to_string_sync(&nm.join(PNPM_MODULES_YAML))
        else {
            return false;
        };
        let Some(recorded) = parse_modules_yaml_virtual_store_dir(&text) else {
            return false;
        };
        let importer = crate::utils::relpath::normalize_lexically_keeping_escapes(project);
        let store = crate::utils::relpath::normalize_lexically_keeping_escapes(&nm.join(recorded));
        store_below_importer(&importer, &store).is_none()
    })
}

/// Append the `configured` roots to the walk's `walked` roots. A walked
/// root inside a configured one is a package's nested `node_modules` the
/// walk mistook for a workspace (the walk descends into a modules folder
/// that is not named `node_modules`); it is dropped, since crawling the
/// configured root inventories it as a nested tree. A configured root the
/// walk already found is not repeated.
pub(super) fn merge_configured_install_roots(
    mut walked: Vec<PathBuf>,
    configured: Vec<PathBuf>,
) -> Vec<PathBuf> {
    if configured.is_empty() {
        return walked;
    }
    walked.retain(|root| configured.iter().all(|c| root == c || !root.starts_with(c)));
    for root in configured {
        if !walked.contains(&root) {
            walked.push(root);
        }
    }
    walked
}

/// The modules folder yarn classic installs the project at `start_path`
/// into, as a path relative to the project, from the `.yarnrc` files at or
/// above it. Mirrors yarn 1.x's rc handling:
/// - each key merges through the rc hierarchy on its own, the nearest
///   `.yarnrc` defining it winning;
/// - a path value is resolved against the directory of the `.yarnrc` that
///   defines it, not the project (`/repo/.yarnrc` with
///   `--modules-folder project/deps` installs `/repo/project` into
///   `/repo/project/deps`);
/// - `--install.modules-folder` wins over `--modules-folder` wherever
///   either is defined, since yarn appends command-scoped args after the
///   general ones.
///
/// The resolved folder must lie strictly inside the project (see
/// [`resolve_modules_folder`]), else `None`. Read with
/// [`crate::utils::fs::read_regular_to_string_sync`]: the files belong to
/// the (untrusted) project, and a FIFO planted there would wedge a plain
/// read forever.
fn yarnrc_modules_folder(start_path: &Path) -> Option<String> {
    let mut general: Option<(&Path, String)> = None;
    let mut install: Option<(&Path, String)> = None;
    for dir in start_path.ancestors() {
        if general.is_some() && install.is_some() {
            break;
        }
        let Ok(rc) = crate::utils::fs::read_regular_to_string_sync(&dir.join(".yarnrc")) else {
            continue;
        };
        let found = parse_yarnrc_modules_folder(&rc);
        if general.is_none() {
            general = found.general.map(|value| (dir, value));
        }
        if install.is_none() {
            install = found.install.map(|value| (dir, value));
        }
    }
    let (rc_dir, value) = install.or(general)?;
    let project_in_rc_dir = start_path
        .strip_prefix(rc_dir)
        .ok()?
        .components()
        .map(|c| c.as_os_str().to_str().map(str::to_string))
        .collect::<Option<Vec<_>>>()?;
    resolve_modules_folder(&project_in_rc_dir, &value)
}

/// Resolve a `.yarnrc` modules-folder `raw` value against the directory of
/// the `.yarnrc` that defines it, given the project's path below that
/// directory (`project_in_rc_dir`, empty when the `.yarnrc` is the
/// project's own), into plain `a/b` segments relative to the project, or
/// `None`. The value comes from the project being scanned and names a
/// tree apply later WRITES patch content into, so (like composer's
/// `config.vendor-dir`) only a relative value resolving strictly inside
/// the project is honored: `./deps` and `lib/./deps` resolve, `..` is
/// resolved lexically, and a value that is absolute, drive-qualified, or
/// resolves outside the project or to the project itself fails closed —
/// the project then discovers nothing there, as before.
fn resolve_modules_folder(project_in_rc_dir: &[String], raw: &str) -> Option<String> {
    if raw.starts_with(['/', '\\']) {
        return None;
    }
    let resolved = crate::utils::relpath::resolve_rel("", raw, 0)?;
    let segments: Vec<&str> = resolved.split('/').filter(|s| !s.is_empty()).collect();
    let inside = segments.get(project_in_rc_dir.len()..)?;
    let at_project = segments.iter().zip(project_in_rc_dir).all(|(s, p)| s == p);
    if !at_project || inside.is_empty() {
        return None;
    }
    let joined = inside.join("/");
    path_safety::is_safe_multi_segment(&joined).then_some(joined)
}

/// The modules-folder settings of one yarn classic `.yarnrc`, kept apart
/// because yarn merges and applies them separately.
#[derive(Debug, Default, PartialEq)]
struct YarnrcModulesFolder {
    /// `--modules-folder`.
    general: Option<String>,
    /// `--install.modules-folder`.
    install: Option<String>,
}

/// The `--modules-folder` and command-scoped `--install.modules-folder`
/// values of a yarn classic `.yarnrc`. The file is yarn's lockfile
/// syntax: one `key value` pair per line, either side optionally
/// double-quoted, an optional `:` after the key, `#` comment lines. For
/// each key the last setting wins.
fn parse_yarnrc_modules_folder(rc: &str) -> YarnrcModulesFolder {
    let mut found = YarnrcModulesFolder::default();
    for line in strip_bom(rc).lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, rest)) = split_yarnrc_token(line, true) else {
            continue;
        };
        let slot = match key.as_str() {
            "--modules-folder" => &mut found.general,
            "--install.modules-folder" => &mut found.install,
            _ => continue,
        };
        let rest = rest.trim_start();
        let rest = rest.strip_prefix(':').unwrap_or(rest).trim_start();
        if let Some((value, _)) = split_yarnrc_token(rest, false) {
            if !value.is_empty() {
                *slot = Some(value);
            }
        }
    }
    found
}

/// Split the leading token off `s`: a double-quoted string (with `\"` and
/// `\\` escapes) or a run of non-whitespace — for a key (`is_key`) also
/// ending at a `:`, which a value may contain (`C:\deps`). Returns the
/// unquoted token and the remainder.
fn split_yarnrc_token(s: &str, is_key: bool) -> Option<(String, &str)> {
    if let Some(quoted) = s.strip_prefix('"') {
        let mut value = String::new();
        let mut chars = quoted.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => value.push(chars.next()?.1),
                '"' => return Some((value, &quoted[i + 1..])),
                c => value.push(c),
            }
        }
        return None;
    }
    let end = s
        .find(|c: char| c.is_whitespace() || (is_key && c == ':'))
        .unwrap_or(s.len());
    (end > 0).then(|| (s[..end].to_string(), &s[end..]))
}

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
    // The path lives inside the (untrusted) package tree: a planted FIFO
    // would make a plain `read_to_string` open block forever waiting for a
    // writer, wedging scan (crawl_all) and apply (find_by_purls). Read via
    // `read_regular_to_string` — non-blocking open on Unix, rejecting
    // FIFOs/devices/directories (see its docs).
    let content = crate::utils::fs::read_regular_to_string(pkg_json_path)
        .await
        .ok()?;
    parse_package_json_identity(&content)
}

/// Blocking twin of [`read_package_json`] for the walks that run whole on
/// the blocking pool: the same FIFO-safe `read_regular_to_string_sync`
/// open and the same parse.
fn read_package_json_sync(pkg_json_path: &Path) -> Option<(String, String)> {
    let content = crate::utils::fs::read_regular_to_string_sync(pkg_json_path).ok()?;
    parse_package_json_identity(&content)
}

/// `(name, version)` from package.json text, if both are present and
/// non-empty.
fn parse_package_json_identity(content: &str) -> Option<(String, String)> {
    // npm and Node both tolerate a leading UTF-8 BOM in package.json
    // (Windows-authored packages ship them), but serde_json rejects it —
    // a BOM'd install would be invisible to scan and unpatchable.
    let pkg: PackageJsonPartial =
        serde_json::from_str(crate::formats::text::strip_bom(content)).ok()?;
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

/// The `node_modules` child that is vlt's per-project package store.
const VLT_STORE_NAME: &str = ".vlt";

/// The `node_modules` children that are pnpm-shaped isolated stores:
/// every package lives at `<store>/<name>@<version><suffix>/node_modules/<name>`
/// (a scoped name's `/` written `+`), the importer links direct deps only,
/// and a transitive dependency's only physical home is its entry. pnpm's
/// virtual store, Bun's isolated linker (`.bun`, Bun >= 1.2) and Deno's
/// isolated `nodeModulesDir` (`.deno`) all write this shape; each store
/// also holds a `node_modules` hoist dir of links and hidden metadata,
/// which the entry enumeration skips.
const PNPM_SHAPED_STORES: [(&str, StoreLayout); 3] = [
    (".pnpm", StoreLayout::Pnpm),
    (".bun", StoreLayout::Bun),
    (".deno", StoreLayout::Deno),
];

/// The entry dirs of a pnpm-shaped store: every real dir but the hidden
/// metadata and the `node_modules` hoist dir, and for Bun each link into
/// its global store (#635).
fn pnpm_shaped_store_candidates_sync(store_path: &Path, layout: StoreLayout) -> Vec<ListedEntry> {
    list_dir_sync(store_path)
        .entries
        .into_iter()
        .filter(|entry| {
            !(entry.name_str.starts_with('.') || entry.name_str == "node_modules")
                && entry.file_type.is_some_and(|ft| {
                    ft.is_dir()
                        || (ft.is_symlink()
                            && layout == StoreLayout::Bun
                            && is_bun_global_store_link_sync(store_path, &entry.name_str))
                })
        })
        .collect()
}

/// The pnpm-shaped store layout a `node_modules` child named `name` is.
fn pnpm_shaped_store_layout(name: &str) -> Option<StoreLayout> {
    PNPM_SHAPED_STORES
        .iter()
        .find(|(store, _)| *store == name)
        .map(|(_, layout)| *layout)
}

/// Decode a `.bun` store entry name (`<name>@<version>`, a peer set
/// appended as `+<hash>`, scoped `@scope+leaf@…`). The pnpm decoder reads
/// the name exactly, but would keep a `+<hash>` tail as part of the
/// version, and a `+` is also how a real build-metadata version is
/// spelled: such names are left undecoded (probeable), never guessed.
fn decode_bun_store_entry_name(entry_name: &str) -> Option<(String, String)> {
    decode_pnpm_store_entry_name(entry_name).filter(|(_, version)| !version.contains('+'))
}

/// Whether the `.bun` entry `entry_name` of `store` is a link into Bun's
/// global store (`[install] globalStore`, Bun >= 1.3.14, #635): every
/// entry is then a link to `<cache>/links/<entry_name>-<hash>`, a dir
/// shared by every project on the machine. The entry is still this
/// project's installed copy (its transitive dependencies live nowhere
/// else), so it is walked: VEX must see its bytes, and agent apply and
/// rollback refuse it as shared (see [`crate::patch::shared_store`])
/// instead of reporting it as not installed. Other links are skipped.
fn is_bun_global_store_link_sync(store: &Path, entry_name: &str) -> bool {
    std::fs::canonicalize(store.join(entry_name)).is_ok_and(|real| {
        real.is_dir() && crate::patch::shared_store::is_bun_global_store_entry(&real, entry_name)
    })
}

/// Whether `project_root` was installed with Bun's global store (#635):
/// some `node_modules/.bun/<entry>` is a link into
/// `<cache>/links/<entry>-<hash>`. Read from the installed tree rather
/// than bunfig.toml or `BUN_INSTALL_GLOBAL_STORE`, which may not match
/// the layout the last install actually wrote. Stops at the first such
/// link; only links are resolved.
pub fn bun_uses_global_store(project_root: &Path) -> bool {
    let store = project_root.join("node_modules").join(".bun");
    let Ok(entries) = std::fs::read_dir(&store) else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry.file_type().is_ok_and(|ft| ft.is_symlink())
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| is_bun_global_store_link_sync(&store, name))
    })
}

/// The `.bun` store entries an install can still load (#599), with the
/// `node_modules` listings of the entries the walk read (by entry name,
/// so the scan does not list them a second time); `None` when the walk
/// cannot tell, and every entry must be kept. Bun never prunes its store:
/// an in-place `bun install` that re-resolves a package (a hosted tarball
/// rewire, a version bump) writes a new entry, re-links every dependent
/// to it and leaves the old `<name>@<version>` dir behind with nothing
/// pointing at it. Such an orphan is not an installed copy, and a
/// judgement of the live install (the scan, `vex`) must not count it.
/// Restoring operations still must (rollback, remove): a later install
/// that resolves back to that version re-links the orphan as it is, so
/// only those judgement callers use this.
///
/// An entry is live when a link reaches it from the `node_modules`
/// holding the store, from Bun's hidden hoist dir `.bun/node_modules`
/// (every store package resolves through it), from a workspace member's
/// `node_modules`, or from a live entry's `node_modules`. The members are
/// the ones Bun itself installs (see
/// [`bun_workspace_member_node_modules_sync`]), read only when the cheaper
/// seeds leave some entry unreached; when they cannot be read, nothing
/// is dropped. A stale link Bun left behind still counts: the runtime
/// resolves through it. A store no link reaches at all gives no evidence
/// either way, so every entry is kept.
///
/// A first, quick walk guesses link targets by name (see
/// [`BunStoreNames`]), which keeps a clean store's walk to the listings
/// the scan reads anyway. The guesses only ever over-reach, except that an
/// alias link can defeat one (`lp` linking `left-pad@…` while an `lp@…`
/// entry exists), so when the quick walk leaves any entry unreached, the
/// store is walked again reading every link before anything is dropped.
///
/// With Bun's global store (#635) the entries are links into the shared
/// `<cache>/links`, whose entries link their dependencies to one another
/// there, never back into this `.bun`: the walk follows them through the
/// cache, mapping each cache entry back to the `.bun` link naming it (see
/// [`BunStoreDirs`]). Bun leaves an orphaned link behind exactly as it
/// leaves an orphaned dir, and judges liveness the same way.
fn live_bun_store_entries_sync(
    store_path: &Path,
    candidates: &[ListedEntry],
) -> Option<LiveBunStore> {
    if candidates.is_empty() {
        return None;
    }
    let dirs = BunStoreDirs::new(store_path, candidates)?;
    let importer = store_path.parent()?;
    let root = match importer.parent() {
        Some(root) if !root.as_os_str().is_empty() => root,
        _ => Path::new("."),
    };
    let names = BunStoreNames::new(candidates);
    // The quick walk reads every entry's listing (the scan reads them
    // anyway) in one parallel pass up front, instead of one pass per
    // frontier: each pass costs a round of the walk pool waking and
    // parking for little work (#578).
    let mut quick_reads: Vec<Option<BunStoreRead>> =
        par_map((0..candidates.len()).collect::<Vec<usize>>(), |index| {
            let nm = dirs.entry_node_modules(&Reached::Entry(index));
            Some(read_bun_store_node_modules_sync(&nm, &dirs, Some(&names)))
        });
    // Read at most once, shared by both walks.
    let mut members: Option<Option<Vec<PathBuf>>> = None;
    let mut walk = |unique: Option<&BunStoreNames>,
                    mut read: Option<&mut [Option<BunStoreRead>]>| {
        let mut live = LiveBunStore::new(candidates.len());
        let seeds = [store_path.join("node_modules"), importer.to_path_buf()];
        reach_bun_store_entries_sync(&seeds, &dirs, unique, &mut live, read.as_deref_mut())?;
        if live.unreached() {
            let members = members
                .get_or_insert_with(|| bun_workspace_member_node_modules_sync(root))
                .as_deref()?;
            reach_bun_store_entries_sync(members, &dirs, unique, &mut live, read)?;
        }
        live.any().then_some(live)
    };
    let quick = walk(Some(&names), Some(&mut quick_reads))?;
    if !quick.unreached() {
        return Some(quick);
    }
    walk(None, None)
}

/// The packages pnpm's current lockfile (`<virtual store>/lock.yaml`,
/// rewritten on every install) says the install uses; `None` when there
/// is none or it cannot be read in full, and then no entry is dropped.
fn pnpm_current_lockfile_sync(
    store_path: &Path,
) -> Option<crate::formats::pnpm::InstalledPackages> {
    let text = crate::utils::fs::read_regular_to_string_sync(&store_path.join("lock.yaml")).ok()?;
    crate::formats::pnpm::InstalledPackages::from_lock_text(&text)
}

/// Whether the pnpm store entry `entry_name` is an orphan (#1197): pnpm
/// 7–11 keep a removed or upgraded-away package's entry until
/// `modules-cache-max-age` (7 days) expires and pnpm 12 until `pnpm prune`,
/// with nothing linking to it. It is one when the package it holds — named
/// by the entry (a registry `name@version` entry, or a `name@file+…`
/// tarball entry) and confirmed by its package.json — is not in the
/// current lockfile. An entry that cannot be named or read stays.
fn orphaned_pnpm_store_entry_sync(
    store_path: &Path,
    entry_name: &str,
    installed: &crate::formats::pnpm::InstalledPackages,
) -> bool {
    let (name, version) = match decode_pnpm_store_entry_name(entry_name) {
        Some((name, version)) => (name, Some(version)),
        None => match entry_name.get(1..).and_then(|rest| rest.find("@file+")) {
            Some(at) => (entry_name[..at + 1].replace('+', "/"), None),
            None => return false,
        },
    };
    // The common case, a live registry entry, costs no read.
    if version
        .as_deref()
        .is_some_and(|version| installed.contains(&name, version))
    {
        return false;
    }
    let manifest = store_path
        .join(entry_name)
        .join("node_modules")
        .join(&name)
        .join("package.json");
    let Some((found_name, found_version)) = read_package_json_sync(&manifest) else {
        return false;
    };
    found_name == name
        && version.is_none_or(|version| version == found_version)
        && !installed.contains(&name, &found_version)
}

/// What [`live_bun_store_entries_sync`] found, by index into the
/// candidates it was given: the scan walks thousands of entries, so they
/// are tracked by position instead of hashed and cloned by name (#578).
struct LiveBunStore {
    /// Whether each candidate is live.
    live: Vec<bool>,
    /// How many of `live` are set.
    count: usize,
    /// Reached names that are no candidate (walked all the same).
    other: HashSet<OsString>,
    /// The `node_modules` listing of each candidate the walk read.
    listings: Vec<Option<Listing>>,
}

impl LiveBunStore {
    fn new(candidates: usize) -> Self {
        Self {
            live: vec![false; candidates],
            count: 0,
            other: HashSet::new(),
            listings: std::iter::repeat_with(|| None).take(candidates).collect(),
        }
    }

    /// Mark `entry` live: whether it was not already.
    fn insert(&mut self, entry: &Reached) -> bool {
        match entry {
            Reached::Entry(index) => {
                let fresh = !std::mem::replace(&mut self.live[*index], true);
                self.count += usize::from(fresh);
                fresh
            }
            Reached::Other(name) => !self.other.contains(name) && self.other.insert(name.clone()),
        }
    }

    /// Some candidate is not live.
    fn unreached(&self) -> bool {
        self.count < self.live.len()
    }

    /// Anything is live.
    fn any(&self) -> bool {
        self.count > 0 || !self.other.is_empty()
    }

    /// The names of every live entry.
    fn into_names(self, candidates: &[ListedEntry]) -> HashSet<OsString> {
        let mut names = self.other;
        names.extend(
            candidates
                .iter()
                .zip(self.live)
                .filter(|(_, live)| *live)
                .map(|(entry, _)| entry.name.clone()),
        );
        names
    }
}

/// A `.bun` entry a link reaches: a candidate (by index) or some other
/// name in the store.
enum Reached {
    Entry(usize),
    Other(OsString),
}

/// The `node_modules` dirs of the workspace members a Bun install at
/// `root` links: every member `bun.lock` lists under `workspaces`, plus
/// every dir the root `package.json` `workspaces` patterns match (the only
/// source for a binary `bun.lockb`). A pattern's `*` and `?` match any
/// name, dot-names included, and `!` exclusions are ignored: an extra
/// member can only keep an entry, never drop one. When the patterns cannot
/// be read (an unreadable or unparseable `package.json`, a `workspaces`
/// field of another shape, a `**` walk past its budget), a `bun.lock`
/// whose `workspaces` section parses is the member set on its own: Bun
/// rewrites it on every install, so it names every member the install
/// linked. Without one the member set cannot be known: `None`, and the
/// caller keeps every entry.
fn bun_workspace_member_node_modules_sync(root: &Path) -> Option<Vec<PathBuf>> {
    use crate::vendor::bun_lock_text::{is_plain_member_dir, workspace_member_dirs};

    // `Some` once the lock's `workspaces` section parsed (it always lists
    // the root, `""`).
    let locked: Option<Vec<PathBuf>> =
        match crate::utils::fs::read_regular_to_string_sync(&root.join("bun.lock")) {
            Ok(text) => {
                let lines: Vec<String> = text.lines().map(str::to_string).collect();
                let dirs = workspace_member_dirs(&lines);
                (!dirs.is_empty()).then(|| {
                    dirs.into_iter()
                        .filter(|dir| !dir.is_empty() && is_plain_member_dir(dir))
                        .map(|dir| root.join(dir))
                        .collect()
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return None,
        };
    let members = match bun_workspace_pattern_members_sync(root) {
        Some(mut members) => {
            members.extend(locked.into_iter().flatten());
            members
        }
        None => locked?,
    };
    let mut seen = HashSet::new();
    Some(
        members
            .into_iter()
            .map(|member| member.join("node_modules"))
            .filter(|nm| seen.insert(nm.clone()) && is_dir_sync(nm))
            .collect(),
    )
}

/// The dirs the root `package.json` `workspaces` patterns match (see
/// [`bun_workspace_member_node_modules_sync`]); `None` when they cannot be
/// read. No `package.json` has no members.
fn bun_workspace_pattern_members_sync(root: &Path) -> Option<Vec<PathBuf>> {
    let text = match crate::utils::fs::read_regular_to_string_sync(&root.join("package.json")) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(Vec::new()),
        Err(_) => return None,
    };
    let text = strip_bom(&text);
    let doc: serde_json::Value = serde_json::from_str(text).ok()?;
    let patterns = match doc.get("workspaces") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(list)) => list.clone(),
        Some(serde_json::Value::Object(map)) => match map.get("packages") {
            None => Vec::new(),
            Some(packages) => packages.as_array()?.clone(),
        },
        Some(_) => return None,
    };
    let mut members = Vec::new();
    for pattern in &patterns {
        let pattern = pattern.as_str()?;
        if pattern.starts_with('!') {
            continue;
        }
        members.extend(expand_workspace_pattern_sync(root, pattern)?);
    }
    Some(members)
}

/// The dirs below `root` a `workspaces` glob matches (`/`-separated; `*`,
/// `?` and `[...]` classes within one component, `**` any number of them), never inside a
/// `node_modules` and never through a link for `**`. `None` when a `**`
/// walk passes [`WORKSPACE_GLOB_DIR_BUDGET`] dirs.
fn expand_workspace_pattern_sync(root: &Path, pattern: &str) -> Option<Vec<PathBuf>> {
    let segments: Vec<&str> = pattern
        .trim()
        .split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    let mut dirs = vec![root.to_path_buf()];
    let mut budget = WORKSPACE_GLOB_DIR_BUDGET;
    for segment in segments {
        let mut next = Vec::new();
        for dir in dirs {
            if segment == "**" {
                // Zero or more components: `dir` itself and every real dir
                // below it.
                let mut stack = vec![dir];
                while let Some(dir) = stack.pop() {
                    budget = budget.checked_sub(1)?;
                    for entry in list_dir_sync(&dir).entries {
                        if entry.name_str != "node_modules"
                            && entry.file_type.is_some_and(|ft| ft.is_dir())
                        {
                            stack.push(dir.join(&entry.name));
                        }
                    }
                    next.push(dir);
                }
            } else if segment.contains(['*', '?', '[']) {
                let pattern: Vec<char> = segment.chars().collect();
                for entry in list_dir_sync(&dir).entries {
                    let name: Vec<char> = entry.name_str.chars().collect();
                    if entry.name_str != "node_modules"
                        && crate::utils::workspace_globs::segment_glob_matches(&pattern, &name)
                        && is_dir_sync(&dir.join(&entry.name))
                    {
                        next.push(dir.join(&entry.name));
                    }
                }
            } else {
                next.push(dir.join(segment));
            }
        }
        dirs = next;
    }
    Some(dirs)
}

/// How many dirs one `workspaces` `**` pattern may walk before the member
/// set is called unknown (see [`bun_workspace_member_node_modules_sync`]).
const WORKSPACE_GLOB_DIR_BUDGET: usize = 20_000;

/// Paths among `paths` that are copies inside an orphaned `.bun` store
/// entry (see [`live_bun_store_entries_sync`]), judged by where each
/// canonicalizes, or, when that is out of every store (a global store
/// entry's shared dir, #635), by the `.bun` entry the path itself names;
/// each store is walked once.
fn orphaned_bun_store_copies_sync(paths: &[PathBuf]) -> HashSet<PathBuf> {
    let mut stores: HashMap<PathBuf, Option<HashSet<OsString>>> = HashMap::new();
    let mut orphans = HashSet::new();
    for path in paths {
        let Ok(real) = std::fs::canonicalize(path) else {
            continue;
        };
        let Some((store, entry)) = bun_store_entry_of(&real).or_else(|| {
            let (store, entry) = bun_store_entry_of(
                &crate::utils::relpath::normalize_lexically_keeping_escapes(path),
            )?;
            Some((std::fs::canonicalize(store).ok()?, entry))
        }) else {
            continue;
        };
        let live = stores.entry(store).or_insert_with_key(|store| {
            let candidates = pnpm_shaped_store_candidates_sync(store, StoreLayout::Bun);
            live_bun_store_entries_sync(store, &candidates).map(|live| live.into_names(&candidates))
        });
        if live.as_ref().is_some_and(|live| !live.contains(&entry)) {
            orphans.insert(path.clone());
        }
    }
    orphans
}

/// The `node_modules/.bun` store a real path lies in, and the name of the
/// entry holding it.
fn bun_store_entry_of(real: &Path) -> Option<(PathBuf, OsString)> {
    let mut child: Option<&OsStr> = None;
    for dir in real.ancestors() {
        if dir
            .file_name()
            .and_then(OsStr::to_str)
            .and_then(pnpm_shaped_store_layout)
            == Some(StoreLayout::Bun)
            && dir.parent().and_then(Path::file_name) == Some(OsStr::new("node_modules"))
        {
            return Some((dir.to_path_buf(), child?.to_os_string()));
        }
        child = dir.file_name();
    }
    None
}

/// Drop from each list every copy that sits in an orphaned Bun store entry
/// (#599): one no link from the install reaches, which nothing can load.
/// For a check of the live install (`vex`), never for an operation that
/// restores copies. Each store is walked once across all the lists.
pub async fn retain_live_store_copies<'a>(lists: impl IntoIterator<Item = &'a mut Vec<PathBuf>>) {
    let lists: Vec<&mut Vec<PathBuf>> = lists.into_iter().collect();
    let paths: Vec<PathBuf> = lists.iter().flat_map(|list| list.iter().cloned()).collect();
    if paths.is_empty() {
        return;
    }
    let orphans = run_walk(move || orphaned_bun_store_copies_sync(&paths)).await;
    if orphans.is_empty() {
        return;
    }
    for list in lists {
        list.retain(|path| !orphans.contains(path));
    }
}

/// The quick walk's guesses: a link named for a package only one `.bun`
/// entry holds points at that entry, and a `@scope` dir none of whose
/// packages has a second entry links (at most) that scope's entries, so
/// neither is read. Only a package with several entries (where an orphan
/// hides) needs its links read.
struct BunStoreNames {
    /// Package name to the one candidate (by index) holding it.
    unique: HashMap<String, usize>,
    scopes: HashMap<String, Vec<usize>>,
}

impl BunStoreNames {
    fn new(candidates: &[ListedEntry]) -> Self {
        let mut by_package: HashMap<String, Option<usize>> = HashMap::new();
        for (index, entry) in candidates.iter().enumerate() {
            if let Some(package) = bun_store_entry_package(&entry.name_str) {
                by_package
                    .entry(package)
                    .and_modify(|only| *only = None)
                    .or_insert(Some(index));
            }
        }
        let mut unique = HashMap::new();
        let mut scopes: HashMap<String, Option<Vec<usize>>> = HashMap::new();
        for (package, only) in by_package {
            let scope = package.split_once('/').map(|(scope, _)| scope.to_string());
            match only {
                Some(entry) => {
                    if let Some(scope) = scope {
                        if let Some(entries) = scopes.entry(scope).or_insert(Some(Vec::new())) {
                            entries.push(entry);
                        }
                    }
                    unique.insert(package, entry);
                }
                None => {
                    if let Some(scope) = scope {
                        scopes.insert(scope, None);
                    }
                }
            }
        }
        let scopes = scopes
            .into_iter()
            .filter_map(|(scope, entries)| Some((scope, entries?)))
            .collect();
        Self { unique, scopes }
    }
}

/// The package a `.bun` entry name is for, spelled the way a link to it
/// is named (`@scope+leaf@…` is `@scope/leaf`); `None` without a version.
fn bun_store_entry_package(entry_name: &str) -> Option<String> {
    let skip = usize::from(entry_name.starts_with('@'));
    let at = skip + entry_name.get(skip..)?.find('@')?;
    let package = entry_name.get(..at).filter(|p| p.len() > skip)?;
    Some(if skip == 1 {
        package.replacen('+', "/", 1)
    } else {
        package.to_string()
    })
}

/// A `node_modules` dir's listing and the `.bun` entries its links reach
/// (see [`bun_store_link_targets_sync`]).
type BunStoreRead = (Option<Listing>, Option<Vec<Reached>>);

/// Read the `node_modules` dir `nm` for the orphan walk.
fn read_bun_store_node_modules_sync(
    nm: &Path,
    dirs: &BunStoreDirs,
    names: Option<&BunStoreNames>,
) -> BunStoreRead {
    let listing = read_dir_entries_sync(nm)
        .map(|(entries, complete)| Listing::from_entries(entries, complete));
    let targets = match &listing {
        Some(listing) => bun_store_link_targets_sync(nm, listing, dirs, names),
        None => Some(Vec::new()),
    };
    (listing, targets)
}

/// Add to `live` every `.bun` entry reachable through links from the
/// `seeds` dirs, following each reached entry's own `node_modules` links,
/// and record each candidate's listing. A candidate already read into
/// `read` is taken from there; the rest are read one frontier at a time,
/// each frontier's dirs in parallel. With `names`, targets are guessed by
/// name where they can be. `None` when a link reaches a global store
/// entry this store does not link (see [`BunStoreDirs::entry_of`]): what
/// lies past it cannot be told.
fn reach_bun_store_entries_sync(
    seeds: &[PathBuf],
    dirs: &BunStoreDirs,
    names: Option<&BunStoreNames>,
    live: &mut LiveBunStore,
    mut read: Option<&mut [Option<BunStoreRead>]>,
) -> Option<()> {
    let mut frontier: Vec<(Option<Reached>, Option<PathBuf>)> = seeds
        .iter()
        .filter_map(|nm| Some((None, Some(std::fs::canonicalize(nm).ok()?))))
        .collect();
    while !frontier.is_empty() {
        let mut visited = Vec::with_capacity(frontier.len());
        let mut unread = Vec::new();
        for (entry, nm) in frontier {
            let cached = match (&entry, read.as_deref_mut()) {
                (Some(Reached::Entry(index)), Some(read)) => read[*index].take(),
                _ => None,
            };
            match cached {
                Some((listing, targets)) => visited.push((entry, listing, targets)),
                None => {
                    let nm = match (nm, &entry) {
                        (Some(nm), _) => nm,
                        (None, Some(entry)) => dirs.entry_node_modules(entry),
                        (None, None) => continue,
                    };
                    unread.push((entry, nm));
                }
            }
        }
        visited.extend(par_map(unread, |(entry, nm)| {
            let (listing, targets) = read_bun_store_node_modules_sync(&nm, dirs, names);
            (entry, listing, targets)
        }));
        frontier = Vec::new();
        for (entry, listing, targets) in visited {
            if let (Some(Reached::Entry(index)), Some(listing)) = (entry, listing) {
                live.listings[index] = Some(listing);
            }
            for target in targets? {
                if live.insert(&target) {
                    frontier.push((Some(target), None));
                }
            }
        }
    }
    Some(())
}

/// Where a `.bun` store's entries really live, for the orphan walk: in the
/// (canonical) store dir itself, or, for each entry that is a link into
/// Bun's global store (#635), in its shared `<cache>/links/<entry>-<hash>`
/// dir, whose dependency links point at sibling cache dirs.
struct BunStoreDirs<'a> {
    real_store: PathBuf,
    /// The store's candidate entries, which [`Reached::Entry`] indexes.
    candidates: &'a [ListedEntry],
    /// Each candidate's index, by name.
    index: HashMap<&'a OsStr, usize>,
    /// The real dir of each global store entry, and the entry linking it.
    global: HashMap<PathBuf, usize>,
    /// The same, by entry.
    global_dirs: HashMap<usize, PathBuf>,
    /// The `links` dirs those real dirs sit in.
    global_links: HashSet<PathBuf>,
}

impl<'a> BunStoreDirs<'a> {
    /// `None` when the store or one of its global store links does not
    /// resolve.
    fn new(store_path: &Path, candidates: &'a [ListedEntry]) -> Option<Self> {
        let real_store = std::fs::canonicalize(store_path).ok()?;
        let mut global = HashMap::new();
        let mut global_dirs = HashMap::new();
        let mut global_links = HashSet::new();
        for (index, entry) in candidates.iter().enumerate() {
            if entry.file_type.is_some_and(|ft| ft.is_symlink()) {
                let real = std::fs::canonicalize(store_path.join(&entry.name)).ok()?;
                global_links.insert(real.parent()?.to_path_buf());
                global.insert(real.clone(), index);
                global_dirs.insert(index, real);
            }
        }
        let index = candidates
            .iter()
            .enumerate()
            .map(|(index, entry)| (entry.name.as_os_str(), index))
            .collect();
        Some(Self {
            real_store,
            candidates,
            index,
            global,
            global_dirs,
            global_links,
        })
    }

    /// The real `node_modules` dir of `entry`.
    fn entry_node_modules(&self, entry: &Reached) -> PathBuf {
        let name = match entry {
            Reached::Entry(index) => {
                if let Some(dir) = self.global_dirs.get(index) {
                    return dir.join("node_modules");
                }
                self.candidates[*index].name.as_os_str()
            }
            Reached::Other(name) => name.as_os_str(),
        };
        let mut nm = PathBuf::with_capacity(
            self.real_store.as_os_str().len() + name.len() + "/node_modules".len() + 1,
        );
        nm.push(&self.real_store);
        nm.push(name);
        nm.push("node_modules");
        nm
    }

    /// The entry named `name` of this store.
    fn reached(&self, name: &OsStr) -> Reached {
        match self.index.get(name) {
            Some(&index) => Reached::Entry(index),
            None => Reached::Other(name.to_os_string()),
        }
    }

    /// The entry a (lexical or real) path lies in: `Some(Some(entry))` in
    /// this store or one of its global store entries, `Some(None)` in some
    /// other entry of the same global store (not linked from this store,
    /// so its reach is unknown), `None` anywhere else.
    fn entry_of(&self, path: &Path) -> Option<Option<Reached>> {
        if let Ok(below) = path.strip_prefix(&self.real_store) {
            return match below.components().next() {
                Some(std::path::Component::Normal(name)) => Some(Some(self.reached(name))),
                _ => None,
            };
        }
        if self.global.is_empty() {
            return None;
        }
        for dir in path.ancestors() {
            if let Some(&entry) = self.global.get(dir) {
                return Some(Some(Reached::Entry(entry)));
            }
            if dir
                .parent()
                .is_some_and(|links| self.global_links.contains(links))
            {
                return Some(None);
            }
        }
        None
    }
}

/// The `.bun` entries the package links in `listing` (of the real dir
/// `nm`; scoped ones under `@scope/`) point into. With `names`, a link
/// or scope dir it can guess is not read (see [`BunStoreNames`]); any
/// other link is read and
/// resolved lexically first (Bun writes relative targets, and `nm` is
/// real, so each `..` climbs a real dir), and one that lands outside the
/// store's entries that way (an absolute Windows junction, a linked
/// `node_modules`) is canonicalized instead. `None` when a link reaches
/// an unknown global store entry (see [`BunStoreDirs::entry_of`]).
fn bun_store_link_targets_sync(
    nm: &Path,
    listing: &Listing,
    dirs: &BunStoreDirs,
    names: Option<&BunStoreNames>,
) -> Option<Vec<Reached>> {
    let mut targets = Vec::new();
    // A link whose package name guesses its entry is never read, and is
    // looked up before any path is built: a quick walk visits every link
    // of every live entry, so the allocations add up (#578).
    let guess = |package: &str| names.and_then(|names| names.unique.get(package));
    let mut links: Vec<PathBuf> = Vec::new();
    for entry in &listing.entries {
        let Some(file_type) = entry.file_type else {
            continue;
        };
        if entry.name_str.starts_with('.') {
            continue;
        }
        if file_type.is_symlink() {
            match guess(&entry.name_str) {
                Some(&target) => targets.push(Reached::Entry(target)),
                None => links.push(nm.join(&entry.name)),
            }
        } else if file_type.is_dir() && entry.name_str.starts_with('@') {
            if let Some(entries) = names.and_then(|names| names.scopes.get(&entry.name_str)) {
                targets.extend(entries.iter().map(|&entry| Reached::Entry(entry)));
                continue;
            }
            let scope = nm.join(&entry.name);
            for scoped in list_dir_sync(&scope).entries {
                if scoped.file_type.is_some_and(|ft| ft.is_symlink()) {
                    let package = format!("{}/{}", entry.name_str, scoped.name_str);
                    match guess(&package) {
                        Some(&target) => targets.push(Reached::Entry(target)),
                        None => links.push(scope.join(&scoped.name)),
                    }
                }
            }
        }
    }
    for link in &links {
        let lexical = std::fs::read_link(link)
            .ok()
            .and_then(|target| {
                Some(crate::utils::relpath::normalize_lexically_keeping_escapes(
                    &link.parent()?.join(target),
                ))
            })
            .and_then(|path| dirs.entry_of(&path));
        if let Some(Some(entry)) = lexical {
            targets.push(entry);
            continue;
        }
        let real = std::fs::canonicalize(link)
            .ok()
            .and_then(|path| dirs.entry_of(&path));
        match real.or(lexical) {
            Some(Some(entry)) => targets.push(entry),
            Some(None) => return None,
            None => {}
        }
    }
    Some(targets)
}

/// The `node_modules` child that is npm's `install-strategy=linked` store,
/// also written by Yarn 4's pnpm linker (see
/// [`store_entry_own_package_sync`]).
const NPM_LINKED_STORE_NAME: &str = ".store";

/// Length of the hash suffix npm's linked strategy appends to a store key:
/// the base64url of a 16-byte shake256 digest, unpadded (arborist's
/// `isolated-reifier.js` `getKey`).
const NPM_STORE_KEY_HASH_LEN: usize = 22;

/// Decode an npm linked-store key (`<name>@<version>-<hash>`, scoped
/// `@scope/<leaf>@<version>-<hash>`) into the `(package_name, version)` it
/// advertises. The hash is base64url, so it may itself hold `-`/`_`: it
/// is cut by its fixed length, never by searching for a separator.
///
/// `None` for anything else, e.g. the un-hashed `<name>@<version>` dir
/// npm extracts a shrinkwrapped dependency into, or a non-semver version.
/// Like the pnpm decoder the result is advisory: the package.json probe
/// stays the authority, and `None` means "unknowable", never "empty".
fn decode_npm_store_entry_name(entry_name: &str) -> Option<(String, String)> {
    let cut = entry_name.len().checked_sub(NPM_STORE_KEY_HASH_LEN + 1)?;
    let (key, hash) = (entry_name.get(..cut)?, entry_name.get(cut..)?);
    let hash = hash.strip_prefix('-')?;
    if !hash
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    let at = key.rfind('@')?;
    if at == 0 || key[..at].ends_with('/') {
        return None;
    }
    let version = &key[at + 1..];
    if !is_semver_triple(version) {
        return None;
    }
    Some((key[..at].to_string(), version.to_string()))
}

/// The `node_modules` child in which pnpm records its install state,
/// including where the virtual store lives.
const PNPM_MODULES_YAML: &str = ".modules.yaml";

/// The `virtualStoreDir` value of a `.modules.yaml`: JSON on pnpm 10+,
/// YAML before (a top-level `virtualStoreDir:` scalar, maybe quoted).
fn parse_modules_yaml_virtual_store_dir(text: &str) -> Option<String> {
    let text = crate::formats::text::strip_bom(text);
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        return value
            .get("virtualStoreDir")?
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string);
    }
    let raw = text
        .lines()
        .find_map(|line| line.strip_prefix("virtualStoreDir:"))?
        .trim();
    let value = if raw.starts_with('"') {
        serde_json::from_str::<String>(raw).ok()?
    } else if let Some(inner) = raw.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')) {
        inner.replace("''", "'")
    } else {
        raw.to_string()
    };
    (!value.is_empty()).then_some(value)
}

/// `store` relative to `importer`, when it names a directory strictly
/// below it by plain child names only. A bare `strip_prefix` is not
/// enough: the CLI's default `--cwd .` makes the importer the empty path,
/// which is a prefix of everything, including an absolute store (`/…`,
/// `C:\…`) or one that climbs out (`../…`).
fn path_below(importer: &Path, store: &Path) -> Option<PathBuf> {
    let below = store.strip_prefix(importer).ok()?;
    let plain = below
        .components()
        .all(|c| matches!(c, std::path::Component::Normal(_)));
    (plain && !below.as_os_str().is_empty()).then(|| below.to_path_buf())
}

/// [`path_below`] for a recorded `virtualStoreDir`, which old pnpm writes
/// as an absolute path. A relative importer (the default `--cwd .` makes
/// it the empty path) is never a lexical prefix of an absolute store, and
/// an absolute one may be spelled through a link (macOS `/var` →
/// `/private/var`), so an absolute store is also compared with both sides
/// canonicalized. A store that resolves outside the importer, such as
/// pnpm's global virtual store or a link planted at the recorded path,
/// still gets `None`.
fn store_below_importer(importer: &Path, store: &Path) -> Option<PathBuf> {
    if let Some(below) = path_below(importer, store) {
        return Some(below);
    }
    if !store.is_absolute() {
        return None;
    }
    let importer = if importer.as_os_str().is_empty() {
        Path::new(".")
    } else {
        importer
    };
    path_below(
        &std::fs::canonicalize(importer).ok()?,
        &std::fs::canonicalize(store).ok()?,
    )
}

/// A pnpm virtual store that `node_modules/.modules.yaml` relocates away
/// from the default `node_modules/.pnpm` (pnpm's `virtualStoreDir`
/// setting, stored relative to `node_modules`, or absolute on old pnpm).
///
/// Only a store INSIDE the importer (the directory holding `nm`) counts,
/// reached through real directories only. Anything else, notably pnpm's
/// global virtual store (`<store-dir>/v10/links`), is shared by other
/// projects on the machine: patching it would patch them too, so agent
/// mode leaves it alone. `None` also for the default location, which the
/// walks already handle by name.
fn relocated_pnpm_virtual_store_sync(nm: &Path) -> Option<PathBuf> {
    let text = crate::utils::fs::read_regular_to_string_sync(&nm.join(PNPM_MODULES_YAML)).ok()?;
    let recorded = parse_modules_yaml_virtual_store_dir(&text)?;
    let importer = crate::utils::relpath::normalize_lexically_keeping_escapes(nm.parent()?);
    let store = crate::utils::relpath::normalize_lexically_keeping_escapes(&nm.join(recorded));
    let below = store_below_importer(&importer, &store)?;
    // The default location (or `node_modules` itself), however it is
    // spelled: compared on the importer-relative tail, so an absolute
    // recording of `<importer>/node_modules/.pnpm` is not walked a second
    // time beside the by-name `.pnpm` handling.
    let nm_name = Path::new(nm.file_name()?);
    if below == nm_name || below == nm_name.join(".pnpm") {
        return None;
    }
    let mut dir = importer;
    for component in below.components() {
        dir.push(component);
        if !std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
            return None;
        }
    }
    Some(dir)
}

/// The entries of pnpm's global virtual store (`enableGlobalVirtualStore`)
/// that the importer holding `nm` actually loads (#362).
///
/// `.modules.yaml` then records `virtualStoreDir` as `<store>/v<N>/links`,
/// outside the project, which [`relocated_pnpm_virtual_store_sync`]
/// rightly refuses to walk: the dir is shared by every project on the
/// machine, so listing it would report other projects' packages. But a
/// transitive dependency lives ONLY there, at
/// `links/<scope|@>/<name>/<version>/<hash>/node_modules/<name>`, so
/// skipping the store makes it read as "not installed", which apply takes
/// for a calm lockfile-only skip while Node loads the unpatched copy.
///
/// So walk just this project's part of the store: start from the
/// importer's links into it (its direct deps), then follow each entry's
/// dependency links to sibling entries. Every entry found is returned
/// (its `node_modules`, and the `(name, version)` its path advertises),
/// so the walks report each copy at its real path in the store, where
/// apply and rollback refuse it as shared (see
/// [`crate::patch::shared_store`]) instead of passing it by.
fn reachable_pnpm_global_virtual_store_entries_sync(nm: &Path) -> Vec<StoreEntry> {
    let Some(links) = pnpm_global_virtual_store_of_sync(nm) else {
        return Vec::new();
    };
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut entries: Vec<StoreEntry> = Vec::new();
    let mut queue: VecDeque<PathBuf> = gvs_link_targets_sync(nm, &links).into();
    while let Some(entry_nm) = queue.pop_front() {
        if !seen.insert(entry_nm.clone()) {
            continue;
        }
        queue.extend(gvs_link_targets_sync(&entry_nm, &links));
        entries.push(StoreEntry {
            advertised: gvs_entry_advertised(&entry_nm, &links),
            node_modules: entry_nm,
        });
    }
    entries
}

/// The real `links` dir of pnpm's global virtual store when `nm`'s
/// `.modules.yaml` records one as its `virtualStoreDir`; `None` for the
/// default store, a store inside the project, or any other outside dir.
///
/// A workspace member's `node_modules` has no `.modules.yaml`: pnpm
/// writes it only at the workspace root. So when `nm` has none, the
/// nearest enclosing `node_modules/.modules.yaml` is read instead. That
/// record only names the store; the walk is still seeded from `nm`'s own
/// links, so a record from some unrelated enclosing project can at worst
/// let `nm`'s real links into a real global store be followed.
fn pnpm_global_virtual_store_of_sync(nm: &Path) -> Option<PathBuf> {
    let own = nm.join(PNPM_MODULES_YAML);
    let modules_yaml = if std::fs::symlink_metadata(&own).is_ok() {
        own
    } else {
        enclosing_pnpm_modules_yaml_sync(nm)?
    };
    let text = crate::utils::fs::read_regular_to_string_sync(&modules_yaml).ok()?;
    let recorded = parse_modules_yaml_virtual_store_dir(&text)?;
    let links = std::fs::canonicalize(modules_yaml.parent()?.join(recorded)).ok()?;
    crate::patch::shared_store::is_pnpm_global_virtual_store_dir(&links).then_some(links)
}

/// The nearest `<ancestor>/node_modules/.modules.yaml` above the importer
/// holding `nm` (a pnpm workspace root's record, for a member). The
/// importer is resolved to its real path first: under the default
/// `--cwd .` `nm` is the relative `node_modules`, whose lexical
/// ancestors never reach the workspace root.
fn enclosing_pnpm_modules_yaml_sync(nm: &Path) -> Option<PathBuf> {
    let parent = nm.parent()?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let importer = std::fs::canonicalize(parent).ok()?;
    importer.ancestors().skip(1).find_map(|dir| {
        let candidate = dir.join("node_modules").join(PNPM_MODULES_YAML);
        std::fs::symlink_metadata(&candidate)
            .is_ok_and(|m| m.is_file())
            .then_some(candidate)
    })
}

/// Whether an importer `node_modules` listing without a `.modules.yaml`
/// may still be a pnpm workspace member linked into the global virtual
/// store (see [`pnpm_global_virtual_store_of_sync`]): it holds a package
/// link or a scope dir. Keeps the enclosing-record lookup off plain
/// npm/yarn trees, whose nested `node_modules` hold real dirs only.
fn may_be_gvs_workspace_member(listing: &Listing) -> bool {
    !listing
        .entries
        .iter()
        .any(|e| e.name_str == PNPM_MODULES_YAML)
        && listing.entries.iter().any(|e| {
            !e.name_str.starts_with('.')
                && e.file_type.is_some_and(|ft| {
                    ft.is_symlink() || (ft.is_dir() && e.name_str.starts_with('@'))
                })
        })
}

/// The global-virtual-store entries `nm`'s package links point into: for
/// each link (scoped ones under `@scope/`), the `node_modules` of the
/// entry holding its real target. Real dirs (an entry's own package) and
/// links resolving anywhere else are skipped.
fn gvs_link_targets_sync(nm: &Path, links: &Path) -> Vec<PathBuf> {
    let mut targets = Vec::new();
    for entry in list_dir_sync(nm).entries {
        let Some(file_type) = entry.file_type else {
            continue;
        };
        if entry.name_str.starts_with('@') && file_type.is_dir() && !file_type.is_symlink() {
            for scoped in list_dir_sync(&nm.join(&entry.name)).entries {
                if scoped.file_type.is_some_and(|ft| ft.is_symlink()) {
                    let path = nm.join(&entry.name).join(&scoped.name);
                    targets.extend(gvs_entry_node_modules(&path, links));
                }
            }
        } else if file_type.is_symlink() && !entry.name_str.starts_with('.') {
            targets.extend(gvs_entry_node_modules(&nm.join(&entry.name), links));
        }
    }
    targets
}

/// The `links/<scope|@>/<name>/<version>/<hash>/node_modules` dir that
/// `link`'s real target sits in, when it is inside `links`.
fn gvs_entry_node_modules(link: &Path, links: &Path) -> Option<PathBuf> {
    let real = std::fs::canonicalize(link).ok()?;
    let below = real.strip_prefix(links).ok()?;
    let parts: Vec<_> = below.components().take(5).collect();
    let [scope, name, version, hash, nm] = parts.as_slice() else {
        return None;
    };
    if nm.as_os_str() != "node_modules" {
        return None;
    }
    let entry_nm = links
        .join(scope)
        .join(name)
        .join(version)
        .join(hash)
        .join(nm);
    is_dir_sync(&entry_nm).then_some(entry_nm)
}

/// `(name, version)` a global-virtual-store entry's path advertises:
/// `links/@/<name>/<version>/…` or `links/@scope/<name>/<version>/…`.
fn gvs_entry_advertised(entry_nm: &Path, links: &Path) -> Option<(String, String)> {
    let below = entry_nm.strip_prefix(links).ok()?;
    let mut parts = below.components().map(|c| c.as_os_str().to_str());
    let (scope, name, version) = (parts.next()??, parts.next()??, parts.next()??);
    let full_name = if scope == "@" {
        name.to_string()
    } else {
        format!("{scope}/{name}")
    };
    Some((full_name, version.to_string()))
}

/// `(name, version)` a `.vlt/<DepID>` entry name advertises: the vlt store
/// decoder over the lossless name, `None` for git/file/remote/workspace
/// ids and for anything undecodable (which stays probeable). The pnpm
/// decoder must never see these names: it reads `··foo@1.0.0` as a package
/// named `··foo`, so the pending-name filter would skip the real `foo`.
fn decode_vlt_store_entry_name(entry_name: &OsStr) -> Option<(String, String)> {
    entry_name.to_str().and_then(decode_vlt_dep_id)
}

/// One virtual-store entry (pnpm or vlt): the `node_modules` holding its
/// package, and the `(name, version)` its dir name advertises. The
/// advertisement is advisory (the package.json probe is the authority), and
/// `None` means "unknowable from the name", never "empty".
struct StoreEntry {
    advertised: Option<(String, String)>,
    node_modules: PathBuf,
}

impl StoreEntry {
    fn pnpm(entries: Vec<(String, PathBuf)>) -> Vec<StoreEntry> {
        entries
            .into_iter()
            .map(|(name, node_modules)| StoreEntry {
                advertised: decode_pnpm_store_entry_name(&name),
                node_modules,
            })
            .collect()
    }

    fn npm(entries: Vec<(String, PathBuf)>) -> Vec<StoreEntry> {
        entries
            .into_iter()
            .map(|(name, node_modules)| StoreEntry {
                advertised: decode_npm_store_entry_name(&name),
                node_modules,
            })
            .collect()
    }

    fn vlt(entries: Vec<(OsString, PathBuf)>) -> Vec<StoreEntry> {
        entries
            .into_iter()
            .map(|(name, node_modules)| StoreEntry {
                advertised: decode_vlt_store_entry_name(&name),
                node_modules,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Blocking-pool walk primitives
// ---------------------------------------------------------------------------

/// One entry of a directory listing read on the blocking pool.
struct ListedEntry {
    /// The raw name — what the walks join wherever they always joined the
    /// `OsString`.
    name: OsString,
    /// The lossy UTF-8 spelling every name test (and the joins that always
    /// used it) goes through.
    name_str: String,
    /// The entry's own, symlink-unaware kind; `None` when that stat failed,
    /// which every walk treats as "skip this entry".
    file_type: Option<FileType>,
}

/// A directory listing plus whether it is known complete (see
/// [`read_dir_entries_sync`]). A directory that cannot be opened lists as
/// empty and incomplete.
#[derive(Default)]
struct Listing {
    entries: Vec<ListedEntry>,
    complete: bool,
}

impl Listing {
    fn from_entries(entries: Vec<std::fs::DirEntry>, complete: bool) -> Self {
        let entries = entries
            .into_iter()
            .map(|entry| {
                let name = entry.file_name();
                ListedEntry {
                    name_str: name.to_string_lossy().into_owned(),
                    file_type: entry.file_type().ok(),
                    name,
                }
            })
            .collect();
        Self { entries, complete }
    }
}

/// The file a [Cache Directory Tagging](https://bford.info/cachedir/)
/// cache directory carries, and the signature it must begin with.
const CACHEDIR_TAG: &str = "CACHEDIR.TAG";
const CACHEDIR_TAG_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";

/// Whether `dir` (whose `listing` the walk already holds) is a tagged cache
/// directory: its listing names a regular `CACHEDIR.TAG` that begins with
/// the standard signature. Only a dir whose listing carries the name costs
/// a read; the name alone is not enough (the specification asks readers to
/// check the signature, so an unrelated file of that name prunes nothing).
fn is_tagged_cache_dir(dir: &Path, listing: &Listing) -> bool {
    let tagged = listing
        .entries
        .iter()
        .any(|e| e.name_str == CACHEDIR_TAG && e.file_type.is_some_and(|t| t.is_file()));
    if !tagged {
        return false;
    }
    // FIFO-safe open (a FIFO planted under the name must not wedge the
    // walk), and only the signature's bytes are read.
    let mut head = [0u8; CACHEDIR_TAG_SIGNATURE.len()];
    crate::utils::fs::open_regular_file_sync(&dir.join(CACHEDIR_TAG))
        .and_then(|(mut f, _)| std::io::Read::read_exact(&mut f, &mut head))
        .is_ok_and(|()| head == CACHEDIR_TAG_SIGNATURE)
}

/// List `path` (empty when it cannot be read — the walks' long-standing
/// tolerate-and-skip contract).
fn list_dir_sync(path: &Path) -> Listing {
    match read_dir_entries_sync(path) {
        Some((entries, complete)) => Listing::from_entries(entries, complete),
        None => Listing::default(),
    }
}

/// The `node_modules` roots a global prefix stands for. pnpm 11+ gives
/// every `pnpm add -g` its own install, `$PNPM_HOME/global/v11/<hash>/`,
/// each with its own `node_modules` (and its own `.pnpm` on pnpm 12, or
/// with `enableGlobalVirtualStore: false`), and `pnpm root -g` prints
/// their parent. Walked as one root, the installs share one
/// `resolve_pending_targets` pass, whose store-entry filter drops a
/// target from every later `.pnpm` once any install matched it, so the
/// other installs' copies were silently missed (#435). Each install is
/// therefore its own root.
///
/// `prefix` splits only when it is a layout-version dir (`v<N>`) that is
/// not itself a `node_modules` (no `.modules.yaml` or `.pnpm`) and at
/// least one child's `node_modules` carries pnpm's `.modules.yaml`. Every
/// child `node_modules` is then a root, marked or not, so an interrupted
/// install is still walked, in sorted order and deduplicated by real
/// path. Anything else (pnpm <= 10's `global/5/node_modules`, an npm or
/// custom prefix) is returned as the single root it always was.
fn pnpm_isolated_global_install_roots(prefix: &Path) -> Vec<PathBuf> {
    let single = || vec![prefix.to_path_buf()];
    let is_version_dir = prefix
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(crate::patch::shared_store::is_pnpm_store_version_dir);
    if !is_version_dir || prefix.join(".modules.yaml").exists() || prefix.join(".pnpm").exists() {
        return single();
    }
    let mut installs: Vec<PathBuf> = list_dir_sync(prefix)
        .entries
        .into_iter()
        .map(|entry| prefix.join(entry.name).join("node_modules"))
        .filter(|nm| is_dir_sync(nm))
        .collect();
    if !installs.iter().any(|nm| nm.join(".modules.yaml").is_file()) {
        return single();
    }
    installs.sort();
    let mut seen = HashSet::new();
    installs.retain(|nm| seen.insert(std::fs::canonicalize(nm).unwrap_or_else(|_| nm.clone())));
    installs
}

/// Whether `dir/node_modules` is a directory, following symlinks — the
/// workspace roots walk's `is_dir` probe — skipping the stat when `dir`'s
/// own listing (which the walk reads anyway) already proves the answer is
/// no: the listing is complete and holds no entry that could be
/// `node_modules`, even on a case-insensitive filesystem (APFS, NTFS; see
/// [`may_alias_ascii_name`]). The stat then could only have failed.
///
/// Every other case stats, including a listed real-directory
/// `node_modules`: a directory readable but not searchable (mode `r--`)
/// lists its entries' kinds while a stat through it still fails, so a
/// positive answer is never taken from the listing. Only the negative
/// case is common (most walked dirs have no `node_modules`).
fn has_node_modules_dir(dir: &Path, listing: &Listing) -> bool {
    if listing.complete
        && !listing
            .entries
            .iter()
            .any(|e| may_alias_ascii_name(&e.name, "node_modules"))
    {
        return false;
    }
    is_dir_sync(&dir.join("node_modules"))
}

/// Whether a directory entry called `name` could be what a lookup of the
/// plain-ASCII `target` resolves to on a case-insensitive filesystem: an
/// ASCII-case-insensitive match — or, conservatively, any name that is not
/// plain ASCII (Unicode case folding and normalization can map non-ASCII
/// spellings such as `ſ` or the Kelvin sign onto ASCII letters) or not
/// UTF-8 at all.
fn may_alias_ascii_name(name: &OsStr, target: &str) -> bool {
    match name.to_str() {
        Some(name) if name.is_ascii() => name.eq_ignore_ascii_case(target),
        _ => true,
    }
}

/// Which first path components a `nm_path.join(dir_key)` lookup could
/// resolve through, given `nm_path`'s listing — lets the resolver skip the
/// package.json probes that could only fail, instead of opening
/// `<nm>/<target>/package.json` for every pending target in every visited
/// `node_modules`.
///
/// A superset by construction: filtering is on only for a complete listing
/// whose names are all plain ASCII, and then matches
/// ASCII-case-insensitively (so APFS/NTFS case-insensitive lookups are
/// covered). Components a filesystem may resolve to a differently spelled
/// entry — non-ASCII (Unicode folding / normalization), `~` (Windows 8.3
/// short-name aliases) or a trailing `.`/space (stripped by Win32 path
/// normalization) — are always probed.
struct ProbeFilter {
    /// `None` = the listing cannot prove absence; probe everything.
    lower_names: Option<HashSet<String>>,
}

impl ProbeFilter {
    fn new(listing: &Listing) -> Self {
        let exhaustive = listing.complete
            && listing
                .entries
                .iter()
                .all(|e| e.name.to_str().is_some_and(|name| name.is_ascii()));
        let lower_names = exhaustive.then(|| {
            listing
                .entries
                .iter()
                .map(|e| e.name_str.to_ascii_lowercase())
                .collect()
        });
        Self { lower_names }
    }

    fn may_resolve(&self, component: &str) -> bool {
        let Some(lower_names) = &self.lower_names else {
            return true;
        };
        if !component.is_ascii() || component.contains('~') || component.ends_with(['.', ' ']) {
            return true;
        }
        lower_names.contains(&component.to_ascii_lowercase())
    }
}

/// The read-only result of one `find_by_purls` resolver visit (see
/// [`NpmCrawler::visit_resolver_dir`]). `matched` indexes the pending
/// targets this dir holds a copy of, in target order — sparse, because
/// every dir of a BFS level carries one of these at once.
struct ResolverVisit {
    /// The visited dir is a store entry's `node_modules`.
    store_entry: bool,
    /// Each matched target's index and the path of its copy: below the
    /// visited dir, or its store entry's own `package` dir (Yarn 4).
    matched: Vec<(usize, PathBuf)>,
    nested: Vec<NestedNodeModules>,
}

/// One contribution to the resolver's next BFS level: a nested importer
/// `node_modules`, or a virtual store's entries, still to be narrowed by
/// the pending-name filter when the visit is replayed.
enum NestedNodeModules {
    Dir(PathBuf),
    StoreEntries(Vec<StoreEntry>),
}

/// What the blocking-pool scan of one `node_modules` tree records, in the
/// exact order the sequential walk visits it;
/// [`NpmCrawler::merge_scan_events`] then replays the order-dependent
/// `seen` dedup single-threaded.
enum ScanEvent {
    /// A `check_package` candidate: the package dir, its package.json
    /// identity (`None` = unreadable/invalid), and — for a direct child of
    /// a virtual-store entry's `node_modules` only — the dir's package key
    /// (`name` or `@scope/name`), which the entry's `identity_seen` skip
    /// compares against.
    Package {
        path: PathBuf,
        identity: Option<(String, String)>,
        entry_key: Option<String>,
    },
    /// One virtual-store entry: its dir name decoded, and the events of its
    /// `node_modules` walked under the store-entry policy.
    StoreEntry {
        decoded: Option<(String, String)>,
        events: Vec<ScanEvent>,
    },
}

/// A virtual-store entry found by
/// [`NpmCrawler::list_pnpm_store_entries_sync`] or
/// [`NpmCrawler::vlt_store_entry_dirs`]: its flat (or synthesized nested)
/// name, what that name advertises under its store layout, its
/// `node_modules`, and — when the caller asked for listings and the dir
/// opened — that `node_modules`' listing.
struct StoreEntryDir {
    name: String,
    advertised: Option<(String, String)>,
    node_modules: PathBuf,
    listing: Option<Listing>,
}

// ---------------------------------------------------------------------------
// Global prefix detection helpers
// ---------------------------------------------------------------------------

use crate::utils::process::{CommandRunner, GlobalProbeRunner};

/// Get the npm global `node_modules` path via `npm root -g`.
///
/// This and the yarn / pnpm / bun probes below run through
/// [`GlobalProbeRunner`]: the tool is resolved through `PATHEXT` (the
/// Windows `npm.cmd` shim) and asked from a neutral directory, never from
/// the scanned project, whose own scripts and config must not answer a
/// question about the machine-wide install.
pub fn get_npm_global_prefix() -> Result<String, String> {
    get_npm_global_prefix_with(&GlobalProbeRunner)
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
    get_yarn_global_prefix_with(&GlobalProbeRunner)
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
    get_pnpm_global_prefix_with(&GlobalProbeRunner)
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

/// Get the bun global `node_modules` path: the global dir `bun pm ls -g`
/// reports, else (no `bun` to ask, or an answer we can't read) the one
/// Bun's own resolution picks from the environment, see
/// [`bun_global_dir_from_env`]. `None` when neither names a dir; see
/// [`resolve_bun_global_prefix`] for why.
///
/// The packages' dir is never derived from `bun pm bin -g` (#443): Bun
/// moves its bin dir (`BUN_INSTALL_BIN`, bunfig `globalBinDir`) and its
/// global dir (`BUN_INSTALL_GLOBAL_DIR`) independently, so `<bin>/..`
/// named a dir that didn't exist and every Bun global vanished from a
/// global scan.
pub fn get_bun_global_prefix() -> Option<String> {
    resolve_bun_global_prefix().ok().flatten()
}

/// [`get_bun_global_prefix`], telling "Bun is not in use" (`Ok(None)`)
/// apart from "Bun is in use but its global dir can't be told" (`Err` with
/// the reason, #443), so a global scan can say so instead of reporting a
/// clean, empty result.
pub fn resolve_bun_global_prefix() -> Result<Option<String>, String> {
    resolve_bun_global_prefix_with(
        &GlobalProbeRunner,
        &|var| std::env::var_os(var),
        crate::utils::process::resolve_tool("bun").is_some(),
    )
}

/// [`resolve_bun_global_prefix`] over an injected runner and environment.
/// Bun counts as in use when `bun_on_path`, or when `BUN_INSTALL_GLOBAL_DIR`
/// or `BUN_INSTALL` is set; otherwise an undeterminable dir is `Ok(None)`.
pub fn resolve_bun_global_prefix_with(
    runner: &dyn CommandRunner,
    var: &impl Fn(&str) -> Option<OsString>,
    bun_on_path: bool,
) -> Result<Option<String>, String> {
    if let Some(prefix) = get_bun_global_prefix_with(runner) {
        return Ok(Some(prefix));
    }
    match bun_global_dir_from_env(var) {
        Ok(dir) => Ok(Some(dir.join("node_modules").to_string_lossy().to_string())),
        Err(why)
            if bun_on_path
                || var("BUN_INSTALL_GLOBAL_DIR").is_some()
                || var("BUN_INSTALL").is_some() =>
        {
            Err(why)
        }
        Err(_) => Ok(None),
    }
}

/// Version of `get_bun_global_prefix` that accepts an injected
/// `CommandRunner` and only asks `bun` (no environment fallback). See
/// `get_npm_global_prefix_with`.
pub fn get_bun_global_prefix_with(runner: &dyn CommandRunner) -> Option<String> {
    parse_bun_ls_global_output(
        runner
            .run("bun", &["pm", "ls", "-g"])
            .as_deref()
            .unwrap_or(""),
    )
}

/// Pure parser for `bun pm ls -g` stdout, whose first line names the
/// global dir: `<dir> node_modules (N)` (Bun 1.0 - 1.3) or
/// `<dir> node_modules (N installed)` (1.4). Returns `<dir>/node_modules`,
/// or `None` when the first line has no such shape. The dir may itself
/// contain spaces, so the LAST ` node_modules (` splits it off.
pub fn parse_bun_ls_global_output(stdout: &str) -> Option<String> {
    let first = stdout.trim().lines().next()?;
    let (dir, _) = first.rsplit_once(" node_modules (")?;
    let dir = dir.trim();
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

/// The global dir Bun installs `bun add -g` packages into, resolved the way
/// Bun does it (`openGlobalDir`): `BUN_INSTALL_GLOBAL_DIR`, else
/// `$BUN_INSTALL/install/global`, else `.bun/install/global` under
/// `XDG_CACHE_HOME` or the home dir (`USERPROFILE` on Windows).
///
/// Bunfig is not consulted: measured on Bun 1.0.36 - 1.4.2, `bun add -g`
/// ignores `install.globalDir` in the global (`~/.bunfig.toml`,
/// `$XDG_CONFIG_HOME/.bunfig.toml`) and the local bunfig alike (it does
/// honor `globalBinDir`, which moves only the bins), and so does
/// `bun pm ls -g`.
///
/// Bun uses a set variable as it is, so the first one set decides. One that
/// is empty or relative names a dir relative to wherever `bun add -g` ran,
/// which can't be known here: that is an `Err` naming the variable, as is
/// having no home dir at all.
pub fn bun_global_dir_from_env(var: &impl Fn(&str) -> Option<OsString>) -> Result<PathBuf, String> {
    let lookup = |name: &str| {
        let value = var(name)?;
        let path = PathBuf::from(&value);
        Some(if path.is_absolute() {
            Ok(path)
        } else {
            Err(format!("{name} is {value:?}, not an absolute path"))
        })
    };
    let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    if let Some(dir) = lookup("BUN_INSTALL_GLOBAL_DIR") {
        return dir;
    }
    if let Some(dir) = lookup("BUN_INSTALL") {
        return dir.map(|dir| dir.join("install").join("global"));
    }
    lookup("XDG_CACHE_HOME")
        .or_else(|| lookup(home_var))
        .unwrap_or_else(|| Err(format!("neither XDG_CACHE_HOME nor {home_var} is set")))
        .map(|dir| dir.join(".bun").join("install").join("global"))
}

/// Say once (muted only by `--silent`) that a global scan left Bun's global
/// packages out because their dir can't be told (#443), instead of
/// reporting a clean, empty result for them.
fn warn_bun_global_dir_undetermined(why: &str) {
    static SHOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    crate::utils::notice::notice_once(crate::utils::notice::Notice::Warning, &SHOWN, || {
        format!(
            "Warning: could not determine Bun's global package directory ({why}), so Bun's \
             global packages were not scanned. Pass --global-prefix <dir>/node_modules to scan \
             them."
        )
    });
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
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
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

/// One still-unresolved `find_by_purls` lookup.
///
/// `purl` is the *verbatim* caller-supplied PURL, including any
/// `?qualifiers`. The result map is keyed by this exact string: the
/// dispatcher drives npm with `passthrough_purls` + `merge_npm_copies`,
/// so it looks results back up under the PURL it handed in. Keying by a
/// reconstructed/stripped PURL silently loses every qualified PURL
/// (e.g. `pkg:npm/foo@1.0.0?vcs_url=...`).
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
        let options = options.clone();
        Ok(run_walk(move || Self::node_modules_paths_sync(&options)).await)
    }

    /// Crawl all discovered `node_modules` and return every package found.
    ///
    /// The whole walk runs as ONE task on the walk pool (instead of one
    /// `spawn_blocking` round trip per readdir/stat/read; see
    /// [`super::walk_pool`]): directory I/O is
    /// gathered in parallel into per-root [`ScanEvent`] trees that record
    /// the sequential visit order, then [`Self::merge_scan_events`] replays
    /// them single-threaded so the order-dependent `seen` dedup (and the
    /// store entries' `identity_seen` decisions) see exactly the state the
    /// sequential walk would have — same packages, same paths, same order.
    ///
    /// Buffering costs memory the sequential walk did not pay: every root's
    /// events are resident before the merge starts, so peak memory scales
    /// with dirs VISITED (duplicates included) rather than with the unique
    /// packages that survive the dedup — about +18% on a depscan-sized
    /// tree. Merging each root as its gather finishes would barely help,
    /// because the tree is one root: 5,080 of depscan's 5,520 packages
    /// live in the root's virtual store, so the largest root's events —
    /// which no per-root scheme shrinks — are the peak. The resolver's
    /// per-level buffering is the one that grew without bound, and that is
    /// [`Self::visit_resolver_dir`]'s to keep sparse.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        self.crawl_all_with_roots(options).await.0
    }

    /// [`Self::crawl_all`], also handing back the `node_modules` roots it
    /// walked — exactly what [`Self::get_node_modules_paths`] returns for
    /// the same options and tree — so a caller that resolves purls against
    /// the same untouched tree later in the process can skip rediscovering
    /// them.
    pub async fn crawl_all_with_roots(
        &self,
        options: &CrawlerOptions,
    ) -> (Vec<CrawledPackage>, Vec<PathBuf>) {
        let options = options.clone();
        run_walk(move || Self::crawl_all_sync(&options)).await
    }

    fn crawl_all_sync(options: &CrawlerOptions) -> (Vec<CrawledPackage>, Vec<PathBuf>) {
        let nm_paths = Self::node_modules_paths_sync(options);
        let gathered: Vec<Vec<ScanEvent>> = par_map(&nm_paths, |nm_path| {
            Self::gather_node_modules(nm_path, None, false)
        });

        let mut packages = Vec::new();
        let mut seen = HashSet::new();
        for events in gathered {
            Self::merge_scan_events(events, None, &mut seen, &mut packages);
        }
        (packages, nm_paths)
    }

    /// Find specific packages by PURL inside a single `node_modules` tree.
    ///
    /// Returns **every** physical copy of each PURL, keyed by the verbatim
    /// input PURL. npm genuinely materializes more than one on-disk copy of
    /// a single `name@version` — a nested duplicate (npm 2's always-nested
    /// layout), a diamond dependency that cannot hoist past a conflicting
    /// top slot, or a `file:` dup — and a security tool MUST patch (and
    /// later restore) all of them: patching only one leaves a live,
    /// vulnerable copy while reporting success (a silent partial). The
    /// per-PURL `Vec` is ordered root-copy-first (breadth-first), so callers
    /// that only need one representative (`vendor`, `vex`) can take
    /// the first and get the root copy.
    ///
    /// pnpm's and vlt's store peer-variant copies are deliberately NOT
    /// enumerated here for a copy already found in an importer tree (a
    /// symlinked direct dep): those are handled by the apply engine's
    /// [`find_store_peer_variant_copies`] fan-out, and a caller that checks
    /// every copy without applying (`vex`) adds them with
    /// [`with_store_peer_variant_copies`]. A transitive-only package
    /// that lives ONLY in the store is still resolved (its store copies are
    /// probed because no importer-tree copy was found). A copy BUNDLED
    /// inside another package's store entry is always returned, found or
    /// not elsewhere: no fan-out reaches it (#601).
    pub async fn find_by_purls(
        &self,
        node_modules_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, Vec<CrawledPackage>>, std::io::Error> {
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

        // Both passes run as one walk-pool task: each visited dir is
        // listed once, and that listing both bounds which targets are
        // probed there and drives the descent (see
        // `resolve_pending_targets`).
        let node_modules_path = node_modules_path.to_path_buf();
        Ok(run_walk(move || {
            let mut result: HashMap<String, Vec<CrawledPackage>> = HashMap::new();

            // Pass 1 — filtered: `.pnpm` virtual-store entries are enqueued
            // only when their dir name decodes to a still-pending target's
            // name (a manifest routinely lists packages that simply aren't
            // installed here, and probing every entry of a large monorepo
            // store for them would add a readdir+stat storm to every
            // apply/rollback run).
            let pending =
                Self::resolve_pending_targets(&node_modules_path, pending, &mut result, true);

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
                Self::resolve_pending_targets(&node_modules_path, pending, &mut result, false);
            }

            result
        })
        .await)
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
    ///
    /// Each visited dir is listed ONCE: a target is probed there only if
    /// the listing could hold its first path component (see
    /// [`ProbeFilter`]; a skipped probe could only have failed), and the
    /// same listing drives the descent.
    ///
    /// The walk runs level by level — exactly the FIFO queue's order, since
    /// everything a dir enqueues lands behind the rest of its level. What a
    /// visit READS depends only on the dir and the (fixed) target list, not
    /// on what earlier dirs resolved, so each level's visits are gathered
    /// in parallel ([`Self::visit_resolver_dir`]); the order-dependent part
    /// — folding matches into `result` and the unmatched-name store filter
    /// — is then replayed sequentially in queue order.
    fn resolve_pending_targets(
        node_modules_path: &Path,
        mut pending: Vec<Target>,
        result: &mut HashMap<String, Vec<CrawledPackage>>,
        filter_store_entries: bool,
    ) -> Vec<Target> {
        if pending.is_empty() {
            return pending;
        }
        // Each dir is tagged `true` when it is a pnpm or vlt store entry's
        // `node_modules`.
        let mut level: Vec<(PathBuf, bool)> = vec![(node_modules_path.to_path_buf(), false)];
        let mut visited = HashSet::new();
        while !level.is_empty() {
            // A bundled node_modules may link back to an ancestor (or to
            // another already-visited tree). Keep the first/root-first
            // spelling without traversing the same physical tree again.
            // Store and importer visits have different link policies, so
            // retain both modes; each resolution pass gets its own set.
            level.retain(|(path, store_entry)| {
                let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
                visited.insert((canonical, *store_entry))
            });
            let visits: Vec<ResolverVisit> = par_map(level, |(nm_path, store_entry)| {
                Self::visit_resolver_dir(nm_path, store_entry, &pending)
            });
            let mut next_level: Vec<(PathBuf, bool)> = Vec::new();
            for visit in visits {
                for (index, pkg_path) in visit.matched {
                    let target = &pending[index];
                    let copies = result.entry(target.purl.clone()).or_default();
                    // Record each physical copy once — a path reached twice
                    // (defensive against overlapping walks) is not
                    // double-counted, and a store copy an importer link
                    // already resolves to keeps the importer path.
                    let recorded = copies.iter().any(|c| c.path == pkg_path)
                        || (visit.store_entry && resolves_to_any_sync(&pkg_path, copies));
                    if !recorded {
                        copies.push(CrawledPackage {
                            name: target.name.clone(),
                            // The probe matched it verbatim (see
                            // `visit_resolver_dir`).
                            version: target.version.clone(),
                            namespace: target.namespace.clone(),
                            purl: target.purl.clone(),
                            path: pkg_path,
                        });
                    }
                }
                // Descend importer-tree nested `node_modules` for ALL targets
                // (a duplicate copy lives at an unknown depth), but probe the
                // pnpm virtual store only for targets NOT YET found anywhere: a
                // matched direct dep's store peer-variants are the apply
                // engine's fan-out job, and re-probing the store for it would
                // add a readdir storm. A target with no importer-tree copy
                // (transitive-only) still gets its store entries probed.
                // The filter is walk-wide, so it is only sound within ONE
                // install: separate pnpm installs must be separate roots
                // (see `pnpm_isolated_global_install_roots`, #435).
                let unmatched_names: HashSet<&str> = pending
                    .iter()
                    .filter(|t| !result.contains_key(&t.purl))
                    .map(|t| t.dir_key.as_str())
                    .collect();
                let filter = filter_store_entries.then_some(&unmatched_names);
                for nested in visit.nested {
                    match nested {
                        NestedNodeModules::Dir(dir) => next_level.push((dir, false)),
                        NestedNodeModules::StoreEntries(entries) => {
                            let (probed, skipped): (Vec<StoreEntry>, Vec<StoreEntry>) = entries
                                .into_iter()
                                .partition(|entry| Self::store_entry_may_hold(entry, filter));
                            next_level.extend(probed.into_iter().map(|e| (e.node_modules, true)));
                            // A skipped entry's own package can still
                            // carry a BUNDLED copy of a target that was
                            // already found elsewhere (#601): Node loads
                            // that copy for the host, so apply and vex
                            // need it too. Only the bundled tree is
                            // walked, and only where one exists.
                            next_level.extend(
                                par_map(skipped, Self::skipped_entry_bundled_tree)
                                    .into_iter()
                                    .flatten()
                                    .map(|dir| (dir, false)),
                            );
                        }
                    }
                }
            }
            level = next_level;
        }
        // Only the targets with zero copies remain "pending" for pass 2.
        pending.retain(|t| !result.contains_key(&t.purl));
        pending
    }

    /// The read-only half of one resolver visit to `nm_path`: which of
    /// `pending` this dir holds a copy of (indices, in target order), and
    /// the nested `node_modules` the dir contributes, in listing order.
    ///
    /// Whether a probe matches depends only on the dir and the target, so
    /// it is decided HERE rather than handed to the sequential fold: a
    /// visit then carries one `usize` per MATCH instead of one probe slot
    /// per target. Every level's visits are live at once, so per-target
    /// slots made the resolver's peak memory
    /// `level_dirs × pending_targets` — hundreds of megabytes on a big
    /// pnpm store probed by pass 2, which enqueues every entry.
    ///
    /// Inside a store entry (`store_entry`) a link is a dependency edge into
    /// a sibling entry, whose own visit records that copy, so only a real
    /// directory there matches, or a link to the entry's own `package` dir
    /// (Yarn 4, see [`store_entry_own_package_sync`]), recorded at that dir.
    /// That `package` dir's own `node_modules` (its bundled dependencies,
    /// which the scan reaches through the same link) is enqueued too: the
    /// link-free walk below would never descend into it.
    fn visit_resolver_dir(
        nm_path: PathBuf,
        store_entry: bool,
        pending: &[Target],
    ) -> ResolverVisit {
        let listing = list_dir_sync(&nm_path);
        let probe_filter = ProbeFilter::new(&listing);
        let mut matched: Vec<(usize, PathBuf)> = pending
            .iter()
            .enumerate()
            .filter_map(|(index, target)| {
                let first_component = target.namespace.as_deref().unwrap_or(&target.name);
                if !probe_filter.may_resolve(first_component) {
                    return None;
                }
                let pkg_path =
                    if !store_entry || is_real_package_dir_sync(&nm_path, &target.dir_key) {
                        nm_path.join(&target.dir_key)
                    } else {
                        store_entry_own_package_sync(&nm_path, &target.dir_key)?
                    };
                // The on-disk *name* must match too: an alias install
                // (`npm i foo@npm:bar@1.0.0`) puts a different package in
                // `node_modules/foo`, so matching on version alone would
                // misidentify it and patch the wrong package's files.
                read_package_json_sync(&pkg_path.join("package.json"))
                    .is_some_and(|(found_name, found_version)| {
                        found_name == target.dir_key && found_version == target.version
                    })
                    .then_some((index, pkg_path))
            })
            .collect();
        // npm's linked store keeps an alias install in an entry named after
        // the alias, its real dir `node_modules/<alias>` (#852), so those
        // entries are searched for alias copies like an importer tree.
        if !store_entry || is_npm_linked_store_entry(&nm_path) {
            let aliases = Self::alias_copies(&nm_path, &listing, pending, &matched);
            matched.extend(aliases);
        }
        let gvs_member = !store_entry && may_be_gvs_workspace_member(&listing);
        let mut nested = Self::collect_nested_node_modules(&nm_path, listing);
        if store_entry {
            nested.extend(own_package_nested_node_modules_sync(&nm_path));
        }
        if gvs_member {
            let entries = reachable_pnpm_global_virtual_store_entries_sync(&nm_path);
            if !entries.is_empty() {
                nested.push(NestedNodeModules::StoreEntries(entries));
            }
        }
        ResolverVisit {
            store_entry,
            matched,
            nested,
        }
    }

    /// The alias installs in an importer-tree `node_modules` that are copies
    /// of a pending target: `"lp": "npm:left-pad@1.3.0"` puts the real
    /// `left-pad@1.3.0` (its own `package.json` says so) at
    /// `node_modules/lp`, and npm, yarn, Bun and pnpm's hoisted linker
    /// all do this. `require('lp')` loads those bytes, so the dir is an
    /// installed copy of `pkg:npm/left-pad@1.3.0` that apply must patch
    /// and VEX must verify, beside any plain `node_modules/left-pad` copy.
    ///
    /// Only real package dirs count (links are dependency edges into a
    /// store or into first-party source, never copies of their own), and
    /// a dir whose name is its package's own name is the direct probe's
    /// job, so it is skipped here. A dir whose name differs only by case
    /// (`node_modules/Left-Pad` holding `left-pad`) is an alias on a
    /// case-sensitive file system, where the probe misses it; it is skipped
    /// only when it IS the dir the probe already returned (`probed`, a
    /// case-insensitive file system folding the probe's path onto it), so
    /// one physical dir is never recorded twice (#856).
    fn alias_copies(
        nm_path: &Path,
        listing: &Listing,
        pending: &[Target],
        probed: &[(usize, PathBuf)],
    ) -> Vec<(usize, PathBuf)> {
        let mut by_identity: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
        for (index, target) in pending.iter().enumerate() {
            by_identity
                .entry((target.dir_key.as_str(), target.version.as_str()))
                .or_default()
                .push(index);
        }
        if by_identity.is_empty() {
            return Vec::new();
        }
        let is_package_dir = |entry: &ListedEntry| {
            !entry.name_str.starts_with('.')
                && entry.name_str != "node_modules"
                && entry.file_type.is_some_and(|ft| ft.is_dir())
        };
        let mut candidates: Vec<(String, PathBuf)> = Vec::new();
        for entry in listing.entries.iter().filter(|e| is_package_dir(e)) {
            let entry_path = nm_path.join(&entry.name);
            if entry.name_str.starts_with('@') {
                for scoped in list_dir_sync(&entry_path).entries {
                    if is_package_dir(&scoped) {
                        candidates.push((
                            format!("{}/{}", entry.name_str, scoped.name_str),
                            entry_path.join(&scoped.name),
                        ));
                    }
                }
            } else {
                candidates.push((entry.name_str.clone(), entry_path));
            }
        }
        let mut found = Vec::new();
        for (dir_key, pkg_path) in candidates {
            let Some((name, version)) = read_package_json_sync(&pkg_path.join("package.json"))
            else {
                continue;
            };
            if name == dir_key {
                continue;
            }
            let case_only = name.eq_ignore_ascii_case(&dir_key);
            if let Some(indices) = by_identity.get(&(name.as_str(), version.as_str())) {
                for &index in indices {
                    let already_probed = case_only
                        && probed.iter().any(|(probed_index, probed_path)| {
                            *probed_index == index
                                && same_file::is_same_file(probed_path, &pkg_path).unwrap_or(false)
                        });
                    if !already_probed {
                        found.push((index, pkg_path.clone()));
                    }
                }
            }
        }
        found
    }

    /// The `node_modules` dirs living one level below `nm_path` (inside each
    /// of its package dirs, scoped or not), given `nm_path`'s listing.
    /// Mirrors the scan's traversal policy: hidden entries are skipped and
    /// symlinked packages are never traversed — a symlink here points into
    /// pnpm's content-addressed store or an `npm link` target outside the
    /// project. The one exception is pnpm's virtual store (see below),
    /// whose entries are returned whole: which of them get enqueued is
    /// decided by the caller's pending-name filter
    /// ([`Self::store_entry_may_hold`]) at replay time.
    ///
    /// Entries are examined in parallel; their contributions keep listing
    /// order.
    fn collect_nested_node_modules(nm_path: &Path, listing: Listing) -> Vec<NestedNodeModules> {
        let found: Vec<Vec<NestedNodeModules>> = par_map(listing.entries, |entry| {
            Self::nested_node_modules_of(nm_path, entry)
        });
        found.into_iter().flatten().collect()
    }

    /// What one listing entry of `nm_path` contributes to the resolver's
    /// next level (see [`Self::collect_nested_node_modules`]).
    fn nested_node_modules_of(nm_path: &Path, entry: ListedEntry) -> Vec<NestedNodeModules> {
        let name_str = entry.name_str.as_str();
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
        // Bun's `.bun` and Deno's `.deno` stores share the shape and the
        // property (see `PNPM_SHAPED_STORES`).
        if let Some(layout) = pnpm_shaped_store_layout(name_str) {
            if !entry.file_type.is_some_and(|ft| ft.is_dir()) {
                return Vec::new();
            }
            let store = nm_path.join(&entry.name);
            let entries = Self::list_pnpm_shaped_store_entries_sync(&store, layout, false, false)
                .into_iter()
                .map(|e| StoreEntry {
                    advertised: e.advertised,
                    node_modules: e.node_modules,
                })
                .collect();
            return vec![NestedNodeModules::StoreEntries(entries)];
        }
        // vlt's store has the same transitive-only-home property: every
        // package lives at `.vlt/<DepID>/node_modules/<name>` and the
        // importer holds only links into it.
        if name_str == VLT_STORE_NAME {
            if !entry.file_type.is_some_and(|ft| ft.is_dir()) {
                return Vec::new();
            }
            let entries = Self::list_vlt_store_entries_sync(&nm_path.join(&entry.name));
            return vec![NestedNodeModules::StoreEntries(StoreEntry::vlt(entries))];
        }
        // npm's `install-strategy=linked` store: the same transitive-only
        // home, at `.store/<name>@<version>-<hash>/node_modules/<name>`.
        if name_str == NPM_LINKED_STORE_NAME {
            if !entry.file_type.is_some_and(|ft| ft.is_dir()) {
                return Vec::new();
            }
            let entries = Self::list_npm_store_entries_sync(&nm_path.join(&entry.name), false)
                .into_iter()
                .map(|e| StoreEntry {
                    advertised: e.advertised,
                    node_modules: e.node_modules,
                })
                .collect();
            return vec![NestedNodeModules::StoreEntries(entries)];
        }
        // A pnpm virtual store relocated by `virtualStoreDir`, found
        // through the `.modules.yaml` pnpm writes next to it. It may sit
        // outside this `node_modules` or under a hidden name the skip
        // below would swallow.
        if name_str == PNPM_MODULES_YAML {
            if !entry.file_type.is_some_and(|ft| ft.is_file()) {
                return Vec::new();
            }
            let Some(store) = relocated_pnpm_virtual_store_sync(nm_path) else {
                let entries = reachable_pnpm_global_virtual_store_entries_sync(nm_path);
                return vec![NestedNodeModules::StoreEntries(entries)];
            };
            let entries = Self::list_pnpm_store_entries_sync(&store, false)
                .into_iter()
                .map(|e| StoreEntry {
                    advertised: e.advertised,
                    node_modules: e.node_modules,
                })
                .collect();
            return vec![NestedNodeModules::StoreEntries(entries)];
        }
        // pnpm <=3: the virtual store is a hidden `.<registry-host>` dir
        // (there is no `.pnpm` at all) with the same
        // transitive-only-deps property, so it gets the same probing.
        // Must run before the generic hidden-entry skip below, which
        // would otherwise swallow it — leaving every transitive-only
        // install unpatchable on those layouts.
        if is_legacy_pnpm_store_dir_name(name_str) {
            if !entry.file_type.is_some_and(|ft| ft.is_dir()) {
                return Vec::new();
            }
            let entries = Self::collect_nested_store_entries_sync(&nm_path.join(&entry.name));
            return vec![NestedNodeModules::StoreEntries(StoreEntry::pnpm(entries))];
        }
        if name_str.starts_with('.') || name_str == "node_modules" {
            return Vec::new();
        }
        if !entry.file_type.is_some_and(|ft| ft.is_dir()) {
            return Vec::new();
        }
        let entry_path = nm_path.join(&entry.name);

        if name_str.starts_with('@') {
            list_dir_sync(&entry_path)
                .entries
                .into_iter()
                .filter(|scoped| {
                    !scoped.name_str.starts_with('.')
                        && scoped.file_type.is_some_and(|ft| ft.is_dir())
                })
                .map(|scoped| entry_path.join(&scoped.name).join("node_modules"))
                .filter(|nested| is_dir_sync(nested))
                .map(NestedNodeModules::Dir)
                .collect()
        } else {
            let nested = entry_path.join("node_modules");
            if is_dir_sync(&nested) {
                vec![NestedNodeModules::Dir(nested)]
            } else {
                Vec::new()
            }
        }
    }

    /// Whether a virtual-store entry can still hold a pending target.
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
    /// entry for exactly those. (An entry skipped here still has its own
    /// package's bundled tree walked, see
    /// [`Self::skipped_entry_bundled_tree`].)
    fn store_entry_may_hold(entry: &StoreEntry, pending_names: Option<&HashSet<&str>>) -> bool {
        match (pending_names, &entry.advertised) {
            (Some(filter), Some((entry_pkg, _version))) => filter.contains(entry_pkg.as_str()),
            _ => true,
        }
    }

    /// The bundled-dependency tree of a store entry the pending-name filter
    /// skipped: `<entry>/node_modules/<own package>/node_modules`, the same
    /// dir an unfiltered visit of the entry would enqueue. The entry's own
    /// package is the one its name advertises, a real dir there (pnpm, vlt,
    /// Bun, Deno) or a link to the entry's `package` dir (Yarn 4). One stat
    /// for an entry without bundled dependencies, which is nearly all of
    /// them.
    fn skipped_entry_bundled_tree(entry: StoreEntry) -> Option<PathBuf> {
        let (own_name, _version) = entry.advertised?;
        if !own_name.split('/').all(is_safe_npm_component) {
            return None;
        }
        let own = if is_real_package_dir_sync(&entry.node_modules, &own_name) {
            entry.node_modules.join(&own_name)
        } else {
            store_entry_own_package_sync(&entry.node_modules, &own_name)?
        };
        let nested = own.join("node_modules");
        is_dir_sync(&nested).then_some(nested)
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
            for root in pnpm_isolated_global_install_roots(Path::new(&pnpm_path)) {
                add(root);
            }
        }
        if let Some(yarn_path) = get_yarn_global_prefix() {
            add(PathBuf::from(yarn_path));
        }
        match resolve_bun_global_prefix() {
            Ok(Some(bun_path)) => add(PathBuf::from(bun_path)),
            Ok(None) => {}
            Err(why) => warn_bun_global_dir_undetermined(&why),
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

    /// Blocking body of [`Self::get_node_modules_paths`].
    fn node_modules_paths_sync(options: &CrawlerOptions) -> Vec<PathBuf> {
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return pnpm_isolated_global_install_roots(custom);
            }
            return NpmCrawler.get_global_node_modules_paths();
        }

        Self::find_local_node_modules_dirs(&options.cwd)
    }

    /// Find `node_modules` directories within the project root.
    /// Recursively searches for workspace `node_modules` but stays within the
    /// project.
    fn find_local_node_modules_dirs(start_path: &Path) -> Vec<PathBuf> {
        let mut results = Vec::new();
        let listing = list_dir_sync(start_path);

        // Direct node_modules in start_path
        if has_node_modules_dir(start_path, &listing) {
            results.push(start_path.join("node_modules"));
        }

        // Recursively search for workspace node_modules
        results.extend(Self::find_workspace_node_modules(start_path, listing));

        merge_configured_install_roots(results, configured_install_roots(start_path))
    }

    /// Find `node_modules` in subdirectories (for monorepos / workspaces),
    /// at any depth, given `dir`'s own listing. Skips symlinks, hidden
    /// dirs, and well-known non-workspace dirs.
    ///
    /// The result is in the sequential depth-first order: children in
    /// listing order, each contributing its own `node_modules` first and
    /// then its subtree's. The tree is read one level at a time, each
    /// level's dirs in parallel, and the order is reassembled from the
    /// recorded child ranges afterwards — no recursion, so an arbitrarily
    /// deep directory chain cannot exhaust a thread's stack. A child whose
    /// listing (which the walk needs anyway) proves it has no
    /// `node_modules` skips the stat; see [`has_node_modules_dir`].
    fn find_workspace_node_modules(dir: &Path, listing: Listing) -> Vec<PathBuf> {
        /// One walked dir: its `node_modules` (if any) and the indices of
        /// its walked children in `nodes`.
        struct WalkedDir {
            node_modules: Option<PathBuf>,
            children: std::ops::Range<usize>,
        }

        // Dirs are numbered in visit order, level by level, so each dir's
        // children occupy a contiguous range of the next level.
        let mut nodes: Vec<WalkedDir> = Vec::new();
        let mut level = Self::workspace_children(dir, listing);
        let roots = 0..level.len();
        while !level.is_empty() {
            let visits: Vec<(Option<PathBuf>, Vec<PathBuf>)> = par_map(level, |full_path| {
                let listing = list_dir_sync(&full_path);
                // A tagged cache directory (a cargo `target/`, a tool's
                // cache) is pruned whole: neither its `node_modules` nor
                // anything below it is a workspace.
                if is_tagged_cache_dir(&full_path, &listing) {
                    return (None, Vec::new());
                }
                // Check if this subdirectory has its own node_modules
                let node_modules = has_node_modules_dir(&full_path, &listing)
                    .then(|| full_path.join("node_modules"));
                (node_modules, Self::workspace_children(&full_path, listing))
            });
            let next_base = nodes.len() + visits.len();
            let mut next_level = Vec::new();
            for (node_modules, children) in visits {
                let start = next_base + next_level.len();
                next_level.extend(children);
                nodes.push(WalkedDir {
                    node_modules,
                    children: start..next_base + next_level.len(),
                });
            }
            level = next_level;
        }

        // Pre-order emission with an explicit stack.
        let mut results = Vec::new();
        let mut stack: Vec<usize> = roots.rev().collect();
        while let Some(index) = stack.pop() {
            let node = &mut nodes[index];
            results.extend(node.node_modules.take());
            stack.extend(node.children.clone().rev());
        }
        results
    }

    /// The subdirectories of `dir` the workspace walk descends into, in
    /// listing order: real dirs only (symlinks are never followed), minus
    /// `node_modules`, hidden dirs and well-known build dirs.
    fn workspace_children(dir: &Path, listing: Listing) -> Vec<PathBuf> {
        listing
            .entries
            .into_iter()
            .filter(|entry| {
                entry.file_type.is_some_and(|ft| ft.is_dir())
                    && !(entry.name_str == "node_modules"
                        || entry.name_str.starts_with('.')
                        || SKIP_DIRS.contains(&entry.name_str.as_str()))
            })
            .map(|entry| dir.join(&entry.name))
            .collect()
    }

    // ------------------------------------------------------------------
    // Private helpers – scanning
    // ------------------------------------------------------------------

    /// Gather one `node_modules` directory's scan into [`ScanEvent`]s, in
    /// the exact order the sequential walk visits it: the directory's own
    /// entries (each package followed by its nested `node_modules`), then
    /// the deferred pnpm and vlt store(s). `listing` is the directory's
    /// listing when the caller already read it. `store_entry` selects the
    /// one policy bit distinguishing an importer/package tree from a pnpm
    /// or vlt store entry's `node_modules`:
    /// - importer trees accept both directories and symlinks (pnpm and vlt
    ///   link direct deps; `npm link` targets) but never traverse a symlink,
    ///   and a `.pnpm` (or pnpm <=3 `.<registry-host>`) or `.vlt` child is
    ///   the virtual store, walked after the loop;
    /// - a store entry accepts REAL directories only — a symlinked (or, on
    ///   Windows, junctioned) entry there is the package's dependency
    ///   pointing at a sibling store entry, inventoried via that entry, and
    ///   following it would record the same package under a path owned by a
    ///   different store entry — and its direct children carry
    ///   their package key so the merge can apply the entry's
    ///   `identity_seen` skip.
    ///
    /// Sibling packages (and their subtrees) are gathered in parallel; the
    /// results are concatenated back in listing order.
    fn gather_node_modules(
        node_modules_path: &Path,
        listing: Option<Listing>,
        store_entry: bool,
    ) -> Vec<ScanEvent> {
        let listing = listing.unwrap_or_else(|| list_dir_sync(node_modules_path));
        let gvs_member = !store_entry && may_be_gvs_workspace_member(&listing);
        let mut pnpm_shaped_stores: Vec<(PathBuf, StoreLayout)> = Vec::new();
        let mut vlt_store: Option<PathBuf> = None;
        let mut npm_store: Option<PathBuf> = None;
        let mut relocated_pnpm_store: Option<PathBuf> = None;
        let mut global_store_entries: Vec<StoreEntry> = Vec::new();
        let mut legacy_stores: Vec<PathBuf> = Vec::new();
        let mut children: Vec<(PathBuf, String, FileType)> = Vec::new();
        // A store entry's links, kept only to find a link to the entry's
        // own `package` dir (Yarn 4, see `store_entry_own_package_sync`).
        let mut own_packages: Vec<String> = Vec::new();

        for entry in listing.entries {
            let name_str = entry.name_str;

            // pnpm's virtual store: under the isolated linker it is the
            // ONLY physical home of transitive dependencies (the
            // importer's node_modules symlinks direct deps only), so
            // skipping it as just-another-hidden-dir leaves every
            // transitive-only install invisible to scan. Deferred until
            // after this loop so root-level entries are inventoried
            // first and win the `seen` name@version dedup at their
            // importer-root paths. (A store entry's own children never
            // include a nested `.pnpm`; under the store-entry policy the
            // name falls through to the hidden-entry skip below.)
            // Bun's `.bun` and Deno's `.deno` share both the shape and
            // the property (see `PNPM_SHAPED_STORES`).
            if let Some(layout) = pnpm_shaped_store_layout(&name_str).filter(|_| !store_entry) {
                if entry.file_type.is_some_and(|ft| ft.is_dir()) {
                    pnpm_shaped_stores.push((node_modules_path.join(&name_str), layout));
                }
                continue;
            }

            // vlt's store, deferred for the same reason: importer links
            // win the `seen` dedup at their importer-root paths.
            if !store_entry && name_str == VLT_STORE_NAME {
                if entry.file_type.is_some_and(|ft| ft.is_dir()) {
                    vlt_store = Some(node_modules_path.join(&name_str));
                }
                continue;
            }

            // npm's linked-strategy store, deferred for the same reason.
            if !store_entry && name_str == NPM_LINKED_STORE_NAME {
                if entry.file_type.is_some_and(|ft| ft.is_dir()) {
                    npm_store = Some(node_modules_path.join(&name_str));
                }
                continue;
            }

            // A pnpm virtual store relocated by `virtualStoreDir` (see
            // `relocated_pnpm_virtual_store_sync`), deferred like `.pnpm`.
            if !store_entry && name_str == PNPM_MODULES_YAML {
                if entry.file_type.is_some_and(|ft| ft.is_file()) {
                    relocated_pnpm_store = relocated_pnpm_virtual_store_sync(node_modules_path);
                    if relocated_pnpm_store.is_none() {
                        global_store_entries =
                            reachable_pnpm_global_virtual_store_entries_sync(node_modules_path);
                    }
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
                if entry.file_type.is_some_and(|ft| ft.is_dir()) {
                    legacy_stores.push(node_modules_path.join(&name_str));
                }
                continue;
            }

            // Skip hidden files and node_modules
            if name_str.starts_with('.') || name_str == "node_modules" {
                continue;
            }

            let Some(file_type) = entry.file_type else {
                continue;
            };
            if !Self::acceptable_package_entry(file_type, store_entry) {
                if store_entry && file_type.is_symlink() {
                    own_packages.push(name_str);
                }
                continue;
            }

            children.push((node_modules_path.join(&name_str), name_str, file_type));
        }

        let mut events: Vec<ScanEvent> = par_map(children, |(entry_path, name_str, file_type)| {
            if name_str.starts_with('@') {
                // Scoped packages
                Self::gather_scoped_packages(&entry_path, &name_str, store_entry)
            } else {
                Self::gather_package(
                    entry_path,
                    store_entry.then_some(name_str),
                    file_type.is_dir(),
                )
            }
        })
        .into_iter()
        .flatten()
        .collect();
        events.extend(Self::gather_own_packages(node_modules_path, own_packages));
        if gvs_member {
            global_store_entries =
                reachable_pnpm_global_virtual_store_entries_sync(node_modules_path);
        }

        for (store_path, layout) in pnpm_shaped_stores {
            let entries =
                Self::list_pnpm_shaped_store_entries_sync(&store_path, layout, true, true);
            events.extend(Self::gather_store_entries(entries));
        }
        for store_path in legacy_stores {
            let entries = Self::collect_nested_store_entries_sync(&store_path)
                .into_iter()
                .map(|(name, node_modules)| StoreEntryDir {
                    advertised: decode_pnpm_store_entry_name(&name),
                    name,
                    node_modules,
                    listing: None,
                })
                .collect();
            events.extend(Self::gather_store_entries(entries));
        }
        if let Some(store_path) = relocated_pnpm_store {
            let entries = Self::list_pnpm_shaped_store_entries_sync(
                &store_path,
                StoreLayout::Pnpm,
                true,
                true,
            );
            events.extend(Self::gather_store_entries(entries));
        }
        if !global_store_entries.is_empty() {
            let entries = global_store_entries
                .into_iter()
                .map(|e| StoreEntryDir {
                    name: e.node_modules.display().to_string(),
                    advertised: e.advertised,
                    node_modules: e.node_modules,
                    listing: None,
                })
                .collect();
            events.extend(Self::gather_store_entries(entries));
        }
        if let Some(store_path) = vlt_store {
            let entries = Self::vlt_store_entry_dirs(&store_path);
            events.extend(Self::gather_store_entries(entries));
        }
        if let Some(store_path) = npm_store {
            let entries = Self::list_npm_store_entries_sync(&store_path, true);
            events.extend(Self::gather_store_entries(entries));
        }

        events
    }

    /// Importer trees allow both directories and symlinks (pnpm links
    /// direct deps); a store entry accepts REAL dirs only (see
    /// [`Self::gather_node_modules`]).
    fn acceptable_package_entry(file_type: FileType, store_entry: bool) -> bool {
        if store_entry {
            file_type.is_dir()
        } else {
            file_type.is_dir() || file_type.is_symlink()
        }
    }

    /// One package dir: its `check_package` candidate event, then — only
    /// for a real directory (`recurse`), never a symlink, which would walk
    /// into pnpm's content-addressed store or an `npm link` target outside
    /// the project — its nested `node_modules`, always an importer-style
    /// tree. `entry_key` is set for a store entry's direct children (see
    /// [`ScanEvent::Package`]); the dir is still descended when the merge
    /// skips its package.json, because bundled dependencies are real dirs
    /// nested inside the package itself (pnpm cannot link them out),
    /// physically present only there.
    ///
    /// The identity is read even for the child the merge will skip, which
    /// the sequential walk avoided (it knew `identity_seen` as it went).
    /// The gather cannot: the skip depends on the dedup state at merge
    /// time. Deferring that one read to the merge thread would move the
    /// store's transitive-only reads — the ones that are NEVER skipped,
    /// and the bulk of a virtual store — onto the serial path, to save one
    /// open per root-linked direct dep. So the read stays here.
    fn gather_package(path: PathBuf, entry_key: Option<String>, recurse: bool) -> Vec<ScanEvent> {
        let identity = read_package_json_sync(&path.join("package.json"));
        let nested = recurse.then(|| path.join("node_modules"));
        let mut events = vec![ScanEvent::Package {
            path,
            identity,
            entry_key,
        }];
        if let Some(nested) = nested {
            events.extend(Self::gather_node_modules(&nested, None, false));
        }
        events
    }

    /// Gather a scoped packages directory (`@scope/`). `store_entry`
    /// carries the caller's traversal policy; nested `node_modules` below a
    /// scoped package are always regular importer-style trees. A store
    /// entry's `identity_seen` names the full `@scope/name`, so that is the
    /// key recorded for its direct children.
    fn gather_scoped_packages(
        scope_path: &Path,
        scope_name: &str,
        store_entry: bool,
    ) -> Vec<ScanEvent> {
        let mut own_packages: Vec<String> = Vec::new();
        let children: Vec<(String, FileType)> = list_dir_sync(scope_path)
            .entries
            .into_iter()
            .filter_map(|entry| {
                if entry.name_str.starts_with('.') {
                    return None;
                }
                let file_type = entry.file_type?;
                if !Self::acceptable_package_entry(file_type, store_entry) {
                    if store_entry && file_type.is_symlink() {
                        own_packages.push(format!("{scope_name}/{}", entry.name_str));
                    }
                    return None;
                }
                Some((entry.name_str, file_type))
            })
            .collect();

        let mut events: Vec<ScanEvent> = par_map(children, |(name_str, file_type)| {
            Self::gather_package(
                scope_path.join(&name_str),
                store_entry.then(|| format!("{scope_name}/{name_str}")),
                file_type.is_dir(),
            )
        })
        .into_iter()
        .flatten()
        .collect();
        if let Some(entry_nm) = scope_path.parent() {
            events.extend(Self::gather_own_packages(entry_nm, own_packages));
        }
        events
    }

    /// The store entry's own package (Yarn 4): of the links `dir_keys`
    /// found in the entry's `node_modules`, the one that resolves to the
    /// entry's `package` dir is gathered there, a real dir, with its key;
    /// the rest are dependency edges into other entries.
    fn gather_own_packages(entry_nm: &Path, dir_keys: Vec<String>) -> Vec<ScanEvent> {
        if dir_keys.is_empty() {
            return Vec::new();
        }
        let Some((own, canonical_own)) = store_entry_package_dir_sync(entry_nm) else {
            return Vec::new();
        };
        dir_keys
            .into_iter()
            .find(|key| std::fs::canonicalize(entry_nm.join(key)).is_ok_and(|t| t == canonical_own))
            .map(|key| Self::gather_package(own, Some(key), true))
            .unwrap_or_default()
    }

    /// Gather each virtual-store entry's `node_modules` (entries come from
    /// [`Self::list_pnpm_store_entries_sync`],
    /// [`Self::collect_nested_store_entries_sync`] or
    /// [`Self::vlt_store_entry_dirs`]) under the store-entry
    /// policy, in parallel, preserving entry order.
    fn gather_store_entries(entries: Vec<StoreEntryDir>) -> Vec<ScanEvent> {
        par_map(entries, |entry| ScanEvent::StoreEntry {
            decoded: entry.advertised,
            events: Self::gather_node_modules(&entry.node_modules, entry.listing, true),
        })
    }

    /// Replay gathered [`ScanEvent`]s in order against `seen`, exactly as
    /// the sequential walk's `check_package` calls would have: a package
    /// is recorded only if its package.json parsed and its PURL is new.
    ///
    /// A store entry whose name decodes to a name@version already
    /// inventoried (every root-linked direct dep — the importer pass wins
    /// the `seen` dedup) gets `identity_seen` = that name, decided HERE,
    /// against the dedup state at this point of the replay: its matching
    /// direct child is skipped — its gathered identity discarded unread,
    /// the one read the parallel gather cannot avoid (see
    /// [`Self::gather_package`]); the sequential walk did not even open
    /// that package.json. Everything below the entry is still replayed.
    fn merge_scan_events(
        events: Vec<ScanEvent>,
        identity_seen: Option<&str>,
        seen: &mut HashSet<String>,
        packages: &mut Vec<CrawledPackage>,
    ) {
        for event in events {
            match event {
                ScanEvent::Package {
                    path,
                    identity,
                    entry_key,
                } => {
                    if identity_seen.is_some() && entry_key.as_deref() == identity_seen {
                        continue;
                    }
                    let Some((full_name, version)) = identity else {
                        continue;
                    };
                    let (namespace, name) = parse_package_name(&full_name);
                    let purl = build_npm_purl(namespace.as_deref(), &name, &version);
                    if !seen.insert(purl.clone()) {
                        continue;
                    }
                    packages.push(CrawledPackage {
                        name,
                        version,
                        namespace,
                        purl,
                        path,
                    });
                }
                ScanEvent::StoreEntry { decoded, events } => {
                    let identity_seen = decoded
                        .filter(|(full_name, version)| {
                            let (ns, bare) = parse_package_name(full_name);
                            seen.contains(&build_npm_purl(ns.as_deref(), &bare, version))
                        })
                        .map(|(full_name, _version)| full_name);
                    Self::merge_scan_events(events, identity_seen.as_deref(), seen, packages);
                }
            }
        }
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
    /// (`collect_nested_node_modules`), the scan pass and the peer-variant
    /// finder so the store-layout policy lives once.
    ///
    /// Entries are probed in parallel and yielded in listing order. With
    /// `read_listings` (the scan, which lists every entry's `node_modules`
    /// next anyway) the existence probe IS that readdir: a `node_modules`
    /// that opens as a directory is one, and its listing rides along in
    /// [`StoreEntryDir::listing`]; one that does not open falls back to
    /// the `is_dir` stat so an unreadable-but-present dir keeps its
    /// flat-entry classification.
    fn list_pnpm_store_entries_sync(store_path: &Path, read_listings: bool) -> Vec<StoreEntryDir> {
        Self::list_pnpm_shaped_store_entries_sync(
            store_path,
            StoreLayout::Pnpm,
            read_listings,
            false,
        )
    }

    /// [`Self::list_pnpm_store_entries_sync`] for any pnpm-shaped store
    /// (see [`PNPM_SHAPED_STORES`]), entry names decoded under `layout`.
    ///
    /// With `live_only` (the scan) a Bun store's orphaned entries are
    /// skipped (see [`live_bun_store_entries_sync`]), and so are the pnpm
    /// store entries its current lockfile no longer installs (see
    /// [`orphaned_pnpm_store_entry_sync`]); the resolver and the
    /// peer-variant finder keep them, since rollback must still restore a
    /// patched orphan a later install can re-link.
    fn list_pnpm_shaped_store_entries_sync(
        store_path: &Path,
        layout: StoreLayout,
        read_listings: bool,
        live_only: bool,
    ) -> Vec<StoreEntryDir> {
        let decode = |name: &str| layout.decode_pnpm_shaped(name);
        let candidates = pnpm_shaped_store_candidates_sync(store_path, layout);
        // Bun never prunes its store (#599), and pnpm 7–12 keep a removed
        // or upgraded-away entry for a while (#1197), so the scan, a
        // judgement of the live install, skips their orphans.
        let mut candidates = candidates;
        if layout == StoreLayout::Pnpm && live_only {
            if let Some(installed) = pnpm_current_lockfile_sync(store_path) {
                candidates.retain(|entry| {
                    !orphaned_pnpm_store_entry_sync(store_path, &entry.name_str, &installed)
                });
            }
        }
        let live = (layout == StoreLayout::Bun && live_only)
            .then(|| live_bun_store_entries_sync(store_path, &candidates))
            .flatten();
        let candidates: Vec<(ListedEntry, Option<Listing>)> = match live {
            Some(walked) => candidates
                .into_iter()
                .zip(walked.live)
                .zip(walked.listings)
                .filter(|((_, live), _)| *live)
                .map(|((entry, _), listing)| (entry, listing.filter(|_| read_listings)))
                .collect(),
            None => candidates.into_iter().map(|entry| (entry, None)).collect(),
        };

        let entry_dirs = |(entry, listing): (ListedEntry, Option<Listing>)| {
            let entry_path = store_path.join(&entry.name);
            let entry_nm = entry_path.join("node_modules");
            if read_listings {
                let listing = listing.or_else(|| {
                    read_dir_entries_sync(&entry_nm)
                        .map(|(entries, complete)| Listing::from_entries(entries, complete))
                });
                if let Some(listing) = listing {
                    return vec![StoreEntryDir {
                        advertised: decode(&entry.name_str),
                        name: entry.name_str,
                        node_modules: entry_nm,
                        listing: Some(listing),
                    }];
                }
            }
            if is_dir_sync(&entry_nm) {
                vec![StoreEntryDir {
                    advertised: decode(&entry.name_str),
                    name: entry.name_str,
                    node_modules: entry_nm,
                    listing: None,
                }]
            } else {
                Self::collect_nested_store_entries_sync(&entry_path)
                    .into_iter()
                    .map(|(name, node_modules)| StoreEntryDir {
                        advertised: decode(&name),
                        name,
                        node_modules,
                        listing: None,
                    })
                    .collect()
            }
        };
        // With every listing already read (a live Bun walk) nothing is
        // left to read, and a parallel pass would only wake the pool.
        if read_listings && candidates.iter().all(|(_, listing)| listing.is_some()) {
            return candidates.into_iter().flat_map(entry_dirs).collect();
        }
        par_map(candidates, entry_dirs)
            .into_iter()
            .flatten()
            .collect()
    }

    /// Async `(name, node_modules)` view of
    /// [`Self::list_pnpm_store_entries_sync`] (the oracle tests' view).
    #[cfg(test)]
    async fn list_pnpm_store_entries(store_path: &Path) -> Vec<(String, PathBuf)> {
        let store_path = store_path.to_path_buf();
        run_walk(move || {
            Self::list_pnpm_store_entries_sync(&store_path, false)
                .into_iter()
                .map(|entry| (entry.name, entry.node_modules))
                .collect()
        })
        .await
    }

    /// Async [`StoreEntry`] view of
    /// [`Self::list_pnpm_shaped_store_entries_sync`].
    async fn list_pnpm_shaped_store_entries(
        store_path: &Path,
        layout: StoreLayout,
    ) -> Vec<StoreEntry> {
        let store_path = store_path.to_path_buf();
        run_walk(move || {
            Self::list_pnpm_shaped_store_entries_sync(&store_path, layout, false, false)
                .into_iter()
                .map(|entry| StoreEntry {
                    advertised: entry.advertised,
                    node_modules: entry.node_modules,
                })
                .collect()
        })
        .await
    }

    /// Enumerate vlt's store (`node_modules/.vlt`), yielding the lossless
    /// entry name and `<entry>/node_modules` for every REAL entry dir whose
    /// `node_modules` is a real dir. Skipped: dot-names (store metadata and
    /// the `.VLT.DELETE.<key>.<DepID>` rollback staging that lingers on
    /// Windows), the `node_modules` child (vlt's internal hoist dir: links
    /// plus real `@scope` dirs holding links), files (`vlt.json`) and links.
    /// The store is always flat; every entry holds exactly one real package
    /// dir named after the package (never the alias). Entries are probed in
    /// parallel and yielded in listing order.
    fn list_vlt_store_entries_sync(store_path: &Path) -> Vec<(OsString, PathBuf)> {
        let candidates: Vec<ListedEntry> = list_dir_sync(store_path)
            .entries
            .into_iter()
            .filter(|entry| {
                !(entry.name.as_encoded_bytes().starts_with(b".") || entry.name == "node_modules")
                    && entry.file_type.is_some_and(|ft| ft.is_dir())
            })
            .collect();
        par_map(candidates, |entry| {
            let entry_nm = store_path.join(&entry.name).join("node_modules");
            std::fs::symlink_metadata(&entry_nm)
                .is_ok_and(|m| m.is_dir())
                .then_some((entry.name, entry_nm))
        })
        .into_iter()
        .flatten()
        .collect()
    }

    /// [`Self::list_vlt_store_entries_sync`] as the scan's
    /// [`StoreEntryDir`]s, each with its `node_modules`' listing (the scan
    /// lists every entry's `node_modules` next anyway).
    fn vlt_store_entry_dirs(store_path: &Path) -> Vec<StoreEntryDir> {
        par_map(
            Self::list_vlt_store_entries_sync(store_path),
            |(name, node_modules)| StoreEntryDir {
                advertised: decode_vlt_store_entry_name(&name),
                name: name.to_string_lossy().into_owned(),
                listing: Some(list_dir_sync(&node_modules)),
                node_modules,
            },
        )
    }

    /// Async view of [`Self::list_vlt_store_entries_sync`].
    async fn list_vlt_store_entries(store_path: &Path) -> Vec<(OsString, PathBuf)> {
        let store_path = store_path.to_path_buf();
        run_walk(move || Self::list_vlt_store_entries_sync(&store_path)).await
    }

    /// Enumerate npm's linked store (`node_modules/.store`, written by
    /// `install-strategy=linked`), yielding every REAL entry dir whose
    /// `node_modules` is a real dir, named by its store key. A scoped
    /// package's entry sits one level down (`.store/@scope/<leaf>@<v>-<h>`),
    /// so a real `@scope` dir is descended once and its entries are named
    /// `@scope/<leaf>@<v>-<h>`. Skipped: dot-names, a `node_modules` child,
    /// files and links (a link is never a store entry). Entries are probed
    /// in parallel and yielded in listing order; with `read_listings` each
    /// entry's `node_modules` listing rides along, as for pnpm.
    fn list_npm_store_entries_sync(store_path: &Path, read_listings: bool) -> Vec<StoreEntryDir> {
        let is_candidate = |entry: &ListedEntry| {
            !(entry.name_str.starts_with('.') || entry.name_str == "node_modules")
                && entry.file_type.is_some_and(|ft| ft.is_dir())
        };
        let mut candidates: Vec<(String, PathBuf)> = Vec::new();
        for entry in list_dir_sync(store_path).entries {
            if !is_candidate(&entry) {
                continue;
            }
            let path = store_path.join(&entry.name);
            // Yarn 4 names a scoped entry `@scope-leaf-npm-<v>-<h>`: an
            // entry itself (it has a `node_modules`, which an npm scope
            // dir never holds, `node_modules` being no valid package name).
            if entry.name_str.starts_with('@') && !is_dir_sync(&path.join("node_modules")) {
                for scoped in list_dir_sync(&path).entries {
                    if is_candidate(&scoped) && !scoped.name_str.starts_with('@') {
                        let name = format!("{}/{}", entry.name_str, scoped.name_str);
                        candidates.push((name, path.join(&scoped.name)));
                    }
                }
            } else {
                candidates.push((entry.name_str, path));
            }
        }
        par_map(candidates, |(name, entry_path)| {
            let node_modules = entry_path.join("node_modules");
            if !std::fs::symlink_metadata(&node_modules).is_ok_and(|m| m.is_dir()) {
                return None;
            }
            Some(StoreEntryDir {
                advertised: decode_npm_store_entry_name(&name),
                name,
                listing: read_listings.then(|| list_dir_sync(&node_modules)),
                node_modules,
            })
        })
        .into_iter()
        .flatten()
        .collect()
    }

    /// Async `(name, node_modules)` view of
    /// [`Self::list_npm_store_entries_sync`].
    async fn list_npm_store_entries(store_path: &Path) -> Vec<(String, PathBuf)> {
        let store_path = store_path.to_path_buf();
        run_walk(move || {
            Self::list_npm_store_entries_sync(&store_path, false)
                .into_iter()
                .map(|entry| (entry.name, entry.node_modules))
                .collect()
        })
        .await
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
    ///
    /// Deliberately sequential: the `NESTED_STORE_MAX_DIRS` budget is
    /// spent in breadth-first listing order, which decides exactly which
    /// entries survive when it runs out.
    fn collect_nested_store_entries_sync(host_path: &Path) -> Vec<(String, PathBuf)> {
        let mut entries = Vec::new();
        let mut remaining = NESTED_STORE_MAX_DIRS;
        let mut queue: VecDeque<(PathBuf, String, usize)> =
            VecDeque::from([(host_path.to_path_buf(), String::new(), 0)]);
        while let Some((dir, rel, depth)) = queue.pop_front() {
            for entry in list_dir_sync(&dir).entries {
                let name_str = entry.name_str;
                // A `node_modules` here belongs to a parent entry (already
                // yielded), never a name/version coordinate.
                if name_str == "node_modules" {
                    continue;
                }
                let Some(file_type) = entry.file_type else {
                    continue;
                };
                if !file_type.is_dir() {
                    continue;
                }
                if remaining == 0 {
                    return entries;
                }
                remaining -= 1;
                let child = dir.join(&entry.name);
                let child_rel = if rel.is_empty() {
                    name_str
                } else {
                    format!("{rel}/{name_str}")
                };
                let child_nm = child.join("node_modules");
                if is_dir_sync(&child_nm) {
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
        entries
    }

    /// Async view of [`Self::collect_nested_store_entries_sync`], appending
    /// to `entries`.
    #[cfg(test)]
    async fn collect_nested_store_entries(host_path: &Path, entries: &mut Vec<(String, PathBuf)>) {
        let host_path = host_path.to_path_buf();
        entries.extend(run_walk(move || Self::collect_nested_store_entries_sync(&host_path)).await);
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
// Store peer-variant duplicate discovery (used by the apply engine)
// ---------------------------------------------------------------------------

/// Which store layout a candidate store directory uses.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum StoreLayout {
    Pnpm,
    Bun,
    Deno,
    Vlt,
    NpmLinked,
}

impl StoreLayout {
    /// The `(name, version)` a pnpm-shaped store's entry name advertises
    /// (see [`PNPM_SHAPED_STORES`]); `None` = unknowable, stays probeable.
    fn decode_pnpm_shaped(self, entry_name: &str) -> Option<(String, String)> {
        match self {
            StoreLayout::Bun => decode_bun_store_entry_name(entry_name),
            _ => decode_pnpm_store_entry_name(entry_name),
        }
    }
}

/// Find every OTHER physical copy of the package installed at `pkg_path`
/// inside the pnpm or vlt store(s) reachable from it.
///
/// Both managers materialize one store copy PER PEER (or modifier)
/// COMBINATION: `.pnpm/foo@1.0.0(react@17…)/` and `…(react@18…)/`, or
/// `.vlt/~npm~foo@1.0.0~peer.2/` and `~peer.3/` (plus vlt's modifier
/// `~_croot…` extras and the legacy `··foo@1.0.0` / `·npm·foo@1.0.0` pair),
/// are all real directories holding the same `foo@1.0.0`, each
/// runtime-loaded by whichever importer resolves to it. The purl-keyed
/// resolver hands apply exactly ONE primary path (root-install-wins), so
/// the apply engine calls this to fan every write out to the remaining
/// physical copies — patching (or restoring) only one of them would leave
/// a live vulnerable copy behind while reporting success (fail-open).
///
/// Discovery, all bounded and read-only:
/// 1. Candidate stores come from the ancestor chains of `pkg_path` AND of
///    its canonicalized form (the root-linked primary is a link into the
///    store, and in a workspace the store lives beside the ROOT
///    `node_modules`, on the canonical chain only): any ancestor named
///    `.pnpm` or `.vlt`, plus any `node_modules` ancestor's `.pnpm` and
///    `.vlt` children. Other layouts (npm/yarn trees, cargo/go/vendor dirs)
///    have neither and return early — the cheap common case. pnpm <=3
///    legacy stores are keyed by plain `name/version` and cannot hold
///    peer-variant duplicates, so they are deliberately not probed.
/// 2. pnpm entries come from the shared layout walker
///    (`list_pnpm_store_entries`, flat + nested); an entry whose name
///    decodes to a DIFFERENT name@version is skipped and an undecodable
///    name stays probeable. vlt entries come from `list_vlt_store_entries`
///    and must decode to exactly the primary's name@version: an
///    undecodable vlt id (git, remote, `file:`) is never a peer variant.
///    A matching copy inside one is still installed, and
///    `NpmCrawler::find_by_purls` returns it as a primary of its own (it
///    probes every undecodable entry), so it is patched like any other.
///    The package.json probe is the authority either way.
/// 3. Only REAL directories count (a link inside a store entry is another
///    entry's copy, already yielded via that entry), the copy `pkg_path`
///    itself canonicalizes to is excluded, and results are deduped by
///    canonical path (both sides canonicalized, so Windows `\\?\` paths
///    compare consistently).
///
/// The returned paths are the copies' package roots (each in its own
/// store entry). Callers write through the hardened per-file pipeline,
/// which breaks content-store hardlinks per copy — CoW safety holds for
/// every copy independently.
pub async fn find_store_peer_variant_copies(pkg_path: &Path) -> Vec<PathBuf> {
    find_store_peer_variant_copies_reusing(pkg_path, &mut HashSet::new()).await
}

/// Discover candidate stores for every input path, but enumerate a
/// physical store only once per layout and package identity in one
/// aggregate expansion. Alias ancestry can expose additional stores even
/// when the input's canonical package was already seen.
async fn find_store_peer_variant_copies_reusing(
    pkg_path: &Path,
    scanned: &mut HashSet<(PathBuf, StoreLayout, String, String)>,
) -> Vec<PathBuf> {
    // 1. Candidate stores from both ancestor chains (cheap stats only —
    //    no file reads until a store is actually found).
    let canonical_pkg = tokio::fs::canonicalize(pkg_path).await.ok();
    let mut stores: Vec<(StoreLayout, PathBuf)> = Vec::new();
    let mut seen_stores: HashSet<PathBuf> = HashSet::new();
    let chains = [Some(pkg_path), canonical_pkg.as_deref()];
    for start in chains.into_iter().flatten() {
        let mut cur = start.parent();
        while let Some(dir) = cur {
            let name = dir.file_name().and_then(OsStr::to_str);
            if let Some(layout) = name.and_then(pnpm_shaped_store_layout) {
                if seen_stores.insert(dir.to_path_buf()) {
                    stores.push((layout, dir.to_path_buf()));
                }
                cur = dir.parent();
                continue;
            }
            match name {
                Some(VLT_STORE_NAME) => {
                    if seen_stores.insert(dir.to_path_buf()) {
                        stores.push((StoreLayout::Vlt, dir.to_path_buf()));
                    }
                }
                // `.store` is npm's only when it sits in a `node_modules`.
                Some(NPM_LINKED_STORE_NAME)
                    if dir.parent().and_then(Path::file_name)
                        == Some(OsStr::new("node_modules")) =>
                {
                    if seen_stores.insert(dir.to_path_buf()) {
                        stores.push((StoreLayout::NpmLinked, dir.to_path_buf()));
                    }
                }
                Some("node_modules") => {
                    let others = [
                        (VLT_STORE_NAME, StoreLayout::Vlt),
                        (NPM_LINKED_STORE_NAME, StoreLayout::NpmLinked),
                    ];
                    for (child, layout) in PNPM_SHAPED_STORES.into_iter().chain(others) {
                        let store = dir.join(child);
                        if is_dir(&store).await && seen_stores.insert(store.clone()) {
                            stores.push((layout, store));
                        }
                    }
                }
                _ => {}
            }
            cur = dir.parent();
        }
    }
    // A pnpm store relocated by `virtualStoreDir` has no fixed name; the
    // importer's `node_modules/.modules.yaml` says where it is. Only a
    // store that holds the primary itself counts (a transitive copy, or a
    // direct dep's link target on the canonical chain): an enclosing
    // project's `.modules.yaml` further up names a store this project
    // does not use. Containment is also checked canonically, so a store
    // named through a linked ancestor (macOS `/var` → `/private/var`)
    // is kept in the same spelling as the other layouts' stores.
    let canonical_start = canonical_pkg.clone();
    let candidates: Vec<(PathBuf, PathBuf)> = chains
        .into_iter()
        .flatten()
        .flat_map(|start| {
            start
                .ancestors()
                .skip(1)
                .map(move |dir| (start.to_path_buf(), dir.join("node_modules")))
        })
        .collect();
    let relocated = run_walk(move || {
        candidates
            .iter()
            .filter_map(|(start, nm)| {
                relocated_pnpm_virtual_store_sync(nm).filter(|store| {
                    start.starts_with(store)
                        || canonical_start.as_ref().is_some_and(|canon| {
                            std::fs::canonicalize(store).is_ok_and(|s| canon.starts_with(s))
                        })
                })
            })
            .collect::<Vec<_>>()
    })
    .await;
    for store in relocated {
        if seen_stores.insert(store.clone()) {
            stores.push((StoreLayout::Pnpm, store));
        }
    }
    if stores.is_empty() {
        return Vec::new();
    }

    // 2. The primary's identity — the package.json is the authority, same
    //    as the resolver. Unreadable/invalid ⇒ no safe way to identify
    //    twins ⇒ none reported (the primary itself is still handled by
    //    the caller).
    let Some((full_name, version)) = read_package_json(&pkg_path.join("package.json")).await else {
        return Vec::new();
    };

    let mut copies: Vec<PathBuf> = Vec::new();
    let mut seen_copies: HashSet<PathBuf> = HashSet::new();
    for (layout, store) in stores {
        let canonical_store = tokio::fs::canonicalize(&store)
            .await
            .unwrap_or_else(|_| store.clone());
        if !scanned.insert((canonical_store, layout, full_name.clone(), version.clone())) {
            continue;
        }
        #[cfg(test)]
        let _ = tests::VARIANT_STORE_SCANS.try_with(|scans| {
            scans.borrow_mut().push(store.clone());
        });
        let entries = match layout {
            StoreLayout::Pnpm | StoreLayout::Bun | StoreLayout::Deno => {
                NpmCrawler::list_pnpm_shaped_store_entries(&store, layout).await
            }
            StoreLayout::Vlt => StoreEntry::vlt(NpmCrawler::list_vlt_store_entries(&store).await),
            StoreLayout::NpmLinked => {
                StoreEntry::npm(NpmCrawler::list_npm_store_entries(&store).await)
            }
        };
        for StoreEntry {
            advertised,
            node_modules: entry_nm,
        } in entries
        {
            // Fast advertisement filter; undecodable pnpm names stay
            // probeable, undecodable vlt ids are never variants. npm's
            // linked store names an alias install's entry after the ALIAS
            // (`.store/lp@1.3.0-<hash>/node_modules/lp` holds the real
            // `left-pad@1.3.0`, #852), so there a same-version entry under
            // another name is probed at its own dir.
            let dir_key = match (advertised, layout) {
                (Some((n, v)), StoreLayout::NpmLinked)
                    if n != full_name
                        && v == version
                        && n.split('/').all(is_safe_npm_component) =>
                {
                    n
                }
                (Some((n, v)), _) if n != full_name || v != version => continue,
                (None, StoreLayout::Vlt) => continue,
                _ => full_name.clone(),
            };
            let alias_entry = dir_key != full_name;
            // `dir_key` may be scoped (`@s/n`) — Path::join handles the
            // two-segment relative form.
            let mut candidate = entry_nm.join(&dir_key);
            // Real dirs only: a link here is another entry's physical
            // copy, reached via that entry, unless it is the entry's own
            // `package` dir (Yarn 4), the physical copy itself.
            let Ok(meta) = tokio::fs::symlink_metadata(&candidate).await else {
                continue;
            };
            if !meta.is_dir() {
                if alias_entry {
                    continue;
                }
                let (nm, key) = (entry_nm.clone(), full_name.clone());
                match run_walk(move || store_entry_own_package_sync(&nm, &key)).await {
                    Some(own) => candidate = own,
                    None => continue,
                }
            }
            match read_package_json(&candidate.join("package.json")).await {
                Some((n, v)) if n == full_name && v == version => {}
                _ => continue,
            }
            let canon = tokio::fs::canonicalize(&candidate)
                .await
                .unwrap_or_else(|_| candidate.clone());
            if canonical_pkg.as_ref() == Some(&canon) {
                continue;
            }
            if seen_copies.insert(canon) {
                copies.push(candidate);
            }
        }
    }
    copies
}

/// `paths` plus every store variant of each (a pnpm peer suffix, a Deno
/// copy index, a vlt peer or modifier extra, a vlt registry-alias instance
/// of the same `name@version`), deduped by canonical path. This is the
/// copy set `apply` writes: [`NpmCrawler::find_by_purls`] resolves a store
/// copy only for a package with no importer copy and leaves the variants
/// to apply's [`find_store_peer_variant_copies`] fan-out, but each variant
/// is what some dependent loads, so a check of "every installed copy"
/// (`vex`) must see them too.
pub async fn with_store_peer_variant_copies(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for path in &paths {
        seen.insert(tokio::fs::canonicalize(path).await.unwrap_or(path.clone()));
    }
    let mut out = paths.clone();
    // `out` already holds every primary, including the primary excluded
    // by a store's first scan. Sharing scan state therefore loses no copy.
    let mut scanned = HashSet::new();
    for path in &paths {
        for copy in find_store_peer_variant_copies_reusing(path, &mut scanned).await {
            let canonical = tokio::fs::canonicalize(&copy).await.unwrap_or(copy.clone());
            if seen.insert(canonical) {
                out.push(copy);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Whether every component of `dir_key` (`name` or `@scope/name`) below
/// `nm_path` is a real directory: links and junctions do not count.
fn is_real_package_dir_sync(nm_path: &Path, dir_key: &str) -> bool {
    let mut path = nm_path.to_path_buf();
    for component in dir_key.split('/') {
        path.push(component);
        if !std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
            return false;
        }
    }
    true
}

/// The physical copy behind a store entry's link to its OWN package, the
/// way Yarn 4's pnpm linker lays out `node_modules/.store`: the entry
/// holds the package at `<entry>/package` (its only physical copy) and
/// `<entry>/node_modules/<dir_key>` is a link to it, beside links to the
/// entry's dependencies in OTHER entries. Returns `<entry>/package` when
/// it is a real dir that `entry_nm/<dir_key>` resolves to; any other link
/// (a dependency edge, inventoried via its own entry) gives `None`.
fn store_entry_own_package_sync(entry_nm: &Path, dir_key: &str) -> Option<PathBuf> {
    let (own, canonical_own) = store_entry_package_dir_sync(entry_nm)?;
    let target = std::fs::canonicalize(entry_nm.join(dir_key)).ok()?;
    (target == canonical_own).then_some(own)
}

/// The `node_modules` inside a store entry's own `package` dir (Yarn 4),
/// where that package's bundled dependencies live. The entry's
/// `node_modules/<name>` is a link to `package`, so a walk that never
/// follows links misses this tree, though Node loads a bundled copy from
/// it. `None` on every other layout, or when the entry holds no link to
/// its own package.
fn own_package_nested_node_modules_sync(entry_nm: &Path) -> Option<NestedNodeModules> {
    let (own, _) = store_entry_package_dir_sync(entry_nm)?;
    let (name, _version) = read_package_json_sync(&own.join("package.json"))?;
    if !name.split('/').all(is_safe_npm_component) {
        return None;
    }
    store_entry_own_package_sync(entry_nm, &name)?;
    let nested = own.join("node_modules");
    is_dir_sync(&nested).then_some(NestedNodeModules::Dir(nested))
}

/// A store entry's real `package` dir beside `entry_nm` (Yarn 4's
/// layout), with its canonical path; `None` on every other layout.
fn store_entry_package_dir_sync(entry_nm: &Path) -> Option<(PathBuf, PathBuf)> {
    let own = entry_nm.parent()?.join("package");
    if !std::fs::symlink_metadata(&own).is_ok_and(|m| m.is_dir()) {
        return None;
    }
    let canonical = std::fs::canonicalize(&own).ok()?;
    Some((own, canonical))
}

/// Whether `entry_nm` is the `node_modules` of an entry in npm's
/// `install-strategy=linked` store: `node_modules/.store/<entry>/node_modules`,
/// or `node_modules/.store/@scope/<entry>/node_modules` for a scoped package.
fn is_npm_linked_store_entry(entry_nm: &Path) -> bool {
    let is_named =
        |dir: Option<&Path>, name: &str| dir.and_then(Path::file_name) == Some(OsStr::new(name));
    let Some(mut parent) = entry_nm.parent().and_then(Path::parent) else {
        return false;
    };
    if parent
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.starts_with('@'))
    {
        match parent.parent() {
            Some(store) => parent = store,
            None => return false,
        }
    }
    is_named(Some(entry_nm), "node_modules")
        && is_named(Some(parent), NPM_LINKED_STORE_NAME)
        && is_named(parent.parent(), "node_modules")
}

/// Whether `pkg_path` is the physical dir one of `copies` resolves to.
fn resolves_to_any_sync(pkg_path: &Path, copies: &[CrawledPackage]) -> bool {
    let Ok(canon) = std::fs::canonicalize(pkg_path) else {
        return false;
    };
    copies
        .iter()
        .any(|copy| std::fs::canonicalize(&copy.path).ok().as_ref() == Some(&canon))
}

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

    tokio::task_local! {
        pub(super) static VARIANT_STORE_SCANS: std::cell::RefCell<Vec<PathBuf>>;
    }

    async fn tracked_store_expansion(paths: Vec<PathBuf>) -> (Vec<PathBuf>, Vec<PathBuf>) {
        VARIANT_STORE_SCANS
            .scope(std::cell::RefCell::new(Vec::new()), async {
                let expanded = with_store_peer_variant_copies(paths).await;
                let scans = VARIANT_STORE_SCANS.with(|scans| scans.borrow().clone());
                (expanded, scans)
            })
            .await
    }

    fn listing_of(names: &[&str], complete: bool) -> Listing {
        Listing {
            entries: names
                .iter()
                .map(|name| ListedEntry {
                    name: OsString::from(name),
                    name_str: name.to_string(),
                    file_type: None,
                })
                .collect(),
            complete,
        }
    }

    /// A complete all-ASCII listing proves plain-ASCII absence (matched
    /// ASCII-case-insensitively), but components a filesystem may resolve
    /// to a differently spelled entry — `~` (8.3 short names), a trailing
    /// `.`/space (Win32 stripping), non-ASCII (Unicode folding) — are
    /// probed even when absent.
    #[test]
    fn probe_filter_only_skips_provably_absent_plain_ascii_names() {
        let filter = ProbeFilter::new(&listing_of(&["foo", "Bar", "@scope"], true));
        assert!(filter.may_resolve("foo"));
        assert!(filter.may_resolve("FOO"));
        assert!(filter.may_resolve("bar"));
        assert!(filter.may_resolve("@Scope"));
        assert!(!filter.may_resolve("absent"));
        assert!(!filter.may_resolve("fo"));
        for alias in [
            "FOO~1",
            "absent~2",
            "absent.",
            "absent ",
            "foo.",
            "caf\u{e9}",
            "\u{212a}elvin",
        ] {
            assert!(filter.may_resolve(alias), "{alias:?} must be probed");
        }

        // An incomplete listing, or one holding a non-ASCII name, proves
        // nothing: everything is probed.
        let partial = ProbeFilter::new(&listing_of(&["foo"], false));
        assert!(partial.may_resolve("absent"));
        let unicode = ProbeFilter::new(&listing_of(&["foo", "caf\u{e9}"], true));
        assert!(unicode.may_resolve("absent"));
    }

    fn target_of(dir_key: &str, version: &str) -> Target {
        let (namespace, name) = parse_package_name(dir_key);
        Target {
            purl: build_npm_purl(namespace.as_deref(), &name, version),
            namespace,
            name,
            version: version.to_string(),
            dir_key: dir_key.to_string(),
        }
    }

    /// A resolver visit records one entry per MATCH, not one probe slot
    /// per pending target: every dir of a BFS level holds its visit at
    /// once, so per-target slots made peak memory `dirs × targets` —
    /// hundreds of megabytes on a large pnpm store, which pass 2 enqueues
    /// whole. The match itself is unchanged: the dir name, the
    /// package.json `name` and the version must all agree.
    #[test]
    fn a_resolver_visit_records_only_the_targets_it_matched() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        for (dir, name, version) in [
            ("present", "present", "1.0.0"),
            ("other-version", "other-version", "1.0.0"),
            // An alias install: a different package under this dir name.
            ("aliased", "underlying", "1.0.0"),
        ] {
            std::fs::create_dir_all(nm.join(dir)).unwrap();
            std::fs::write(
                nm.join(dir).join("package.json"),
                format!(r#"{{"name":"{name}","version":"{version}"}}"#),
            )
            .unwrap();
        }

        let mut pending: Vec<Target> = (0..200)
            .map(|i| target_of(&format!("absent{i}"), "1.0.0"))
            .collect();
        pending.push(target_of("other-version", "2.0.0"));
        pending.push(target_of("aliased", "1.0.0"));
        pending.push(target_of("present", "1.0.0"));
        let matched_index = pending.len() - 1;

        let visit = NpmCrawler::visit_resolver_dir(nm.clone(), false, &pending);
        assert_eq!(visit.matched, vec![(matched_index, nm.join("present"))]);
    }

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
    /// itself (reports `is_dir == false`), which would skip symlinked
    /// version dirs — exactly the layout fnm produces and the
    /// `current`/`default` aliases nvm creates. The resolver stats the
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

    fn copy_paths(found: &HashMap<String, Vec<CrawledPackage>>, purl: &str) -> Vec<PathBuf> {
        found
            .get(purl)
            .map(|copies| copies.iter().map(|c| c.path.clone()).collect())
            .unwrap_or_default()
    }

    /// #356: an npm alias (`"lp": "npm:left-pad@1.3.0"`) installs the real
    /// `left-pad@1.3.0` at `node_modules/lp`. With no plain copy beside
    /// it, that dir is the purl's only installed copy, so apply must not
    /// report it `package_not_installed`.
    #[tokio::test]
    async fn find_by_purls_resolves_an_alias_only_install() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        write_pkg(&nm.join("lp"), "left-pad", "1.3.0");

        let purl = "pkg:npm/left-pad@1.3.0".to_string();
        let found = NpmCrawler::new()
            .find_by_purls(&nm, std::slice::from_ref(&purl))
            .await
            .unwrap();
        assert_eq!(copy_paths(&found, &purl), vec![nm.join("lp")]);
        let copy = &found[&purl][0];
        assert_eq!(
            (copy.name.as_str(), copy.version.as_str()),
            ("left-pad", "1.3.0")
        );
    }

    /// #356: a plain copy plus an alias of the same `name@version` are two
    /// copies of the purl. Resolving only the plain one left `require('lp')`
    /// loading unpatched bytes while apply reported success and VEX
    /// attested `not_affected`. The plain copy stays first.
    #[tokio::test]
    async fn find_by_purls_returns_alias_copies_beside_the_plain_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        write_pkg(&nm.join("left-pad"), "left-pad", "1.3.0");
        write_pkg(&nm.join("lp"), "left-pad", "1.3.0");
        // A nested alias under another package is a copy too.
        write_pkg(&nm.join("host"), "host", "1.0.0");
        write_pkg(&nm.join("host/node_modules/pad"), "left-pad", "1.3.0");
        // Another version under an alias is not.
        write_pkg(&nm.join("lp2"), "left-pad", "1.2.0");

        let purl = "pkg:npm/left-pad@1.3.0".to_string();
        let found = NpmCrawler::new()
            .find_by_purls(&nm, std::slice::from_ref(&purl))
            .await
            .unwrap();
        assert_eq!(
            copy_paths(&found, &purl),
            vec![
                nm.join("left-pad"),
                nm.join("lp"),
                nm.join("host/node_modules/pad"),
            ]
        );
    }

    /// #356: a scoped alias dir (`"@x/pad": "npm:left-pad@1.3.0"`) and an
    /// unscoped alias of a scoped package (`"sp": "npm:@s/pkg@2.0.0"`).
    #[tokio::test]
    async fn find_by_purls_resolves_scoped_alias_installs() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        write_pkg(&nm.join("@x/pad"), "left-pad", "1.3.0");
        write_pkg(&nm.join("sp"), "@s/pkg", "2.0.0");

        let pad = "pkg:npm/left-pad@1.3.0".to_string();
        let scoped = "pkg:npm/%40s/pkg@2.0.0".to_string();
        let found = NpmCrawler::new()
            .find_by_purls(&nm, &[pad.clone(), scoped.clone()])
            .await
            .unwrap();
        assert_eq!(copy_paths(&found, &pad), vec![nm.join("@x/pad")]);
        assert_eq!(copy_paths(&found, &scoped), vec![nm.join("sp")]);
        let copy = &found[&scoped][0];
        assert_eq!(copy.namespace.as_deref(), Some("@s"));
        assert_eq!(copy.name, "pkg");
    }

    /// #856: a key differing from the package's name only by case
    /// (`node_modules/Left-Pad` holding `left-pad@1.3.0`, a legacy-valid
    /// npm name) is an alias copy. On a case-sensitive file system the
    /// direct probe of `node_modules/left-pad` misses it, so the alias pass
    /// must return it; where the file system folds case the probe already
    /// returned that physical dir, and it is reported exactly once.
    #[tokio::test]
    async fn find_by_purls_resolves_a_case_only_alias_once() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        write_pkg(&nm.join("Left-Pad"), "left-pad", "1.3.0");
        write_pkg(&nm.join("mm"), "minimist", "1.2.2");
        let case_folding = nm.join("left-pad").exists();

        let pad = "pkg:npm/left-pad@1.3.0".to_string();
        let mm = "pkg:npm/minimist@1.2.2".to_string();
        let found = NpmCrawler::new()
            .find_by_purls(&nm, &[pad.clone(), mm.clone()])
            .await
            .unwrap();
        let pad_copies = copy_paths(&found, &pad);
        assert_eq!(pad_copies.len(), 1, "{pad_copies:?}");
        if !case_folding {
            assert_eq!(pad_copies, vec![nm.join("Left-Pad")]);
        }
        assert_eq!(copy_paths(&found, &mm), vec![nm.join("mm")]);

        // Beside a plain copy (case-sensitive file systems only: a folding
        // one cannot hold both names), both dirs are copies.
        if !case_folding {
            write_pkg(&nm.join("left-pad"), "left-pad", "1.3.0");
            let found = NpmCrawler::new()
                .find_by_purls(&nm, std::slice::from_ref(&pad))
                .await
                .unwrap();
            assert_eq!(
                copy_paths(&found, &pad),
                vec![nm.join("left-pad"), nm.join("Left-Pad")]
            );
        }
    }

    /// A link is a dependency edge (into a store, a workspace member or an
    /// `npm link` target), never an alias copy of its own; pnpm's isolated
    /// alias link resolves through the store entry instead.
    #[cfg(unix)]
    #[tokio::test]
    async fn find_by_purls_does_not_take_a_link_as_an_alias_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        let elsewhere = tmp.path().join("src/left-pad");
        write_pkg(&elsewhere, "left-pad", "1.3.0");
        std::fs::create_dir_all(&nm).unwrap();
        std::os::unix::fs::symlink(&elsewhere, nm.join("lp")).unwrap();

        let purl = "pkg:npm/left-pad@1.3.0".to_string();
        let found = NpmCrawler::new()
            .find_by_purls(&nm, std::slice::from_ref(&purl))
            .await
            .unwrap();
        assert!(copy_paths(&found, &purl).is_empty());
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
        let pkg = &result
            .get(&encoded)
            .expect("result keyed by the verbatim encoded input purl")[0];
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

    /// A qualified PURL (carrying `?qualifiers`) must resolve and be keyed by
    /// the *verbatim* input PURL — not a reconstructed, stripped form. The
    /// dispatcher drives npm with `passthrough_purls` + `merge_npm_copies`,
    /// so it looks the result back up under the exact PURL it passed in.
    /// Keying by the stripped PURL drops every qualified npm PURL from
    /// apply/rollback.
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
        let foo = &result
            .get(&unscoped_q)
            .expect("qualified unscoped resolved")[0];
        assert_eq!(foo.purl, unscoped_q);
        assert_eq!(foo.name, "foo");
        assert_eq!(foo.version, "1.0.0");

        let node = &result.get(&scoped_q).expect("qualified scoped resolved")[0];
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
        assert_eq!(result.get(&q1).unwrap()[0].path, foo_dir);
        assert_eq!(result.get(&q2).unwrap()[0].path, foo_dir);
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

    /// Multi-copy P0: two REAL on-disk copies of the SAME `name@version`
    /// (a root/hoisted copy and a nested duplicate) must BOTH be returned
    /// under the one PURL, root-copy-first. Returning only the root copy is
    /// the silent partial that leaves a live vulnerable copy on disk.
    #[tokio::test]
    async fn test_find_by_purls_returns_every_copy_root_first() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");

        // Root/hoisted copy.
        let root_copy = nm.join("dup");
        tokio::fs::create_dir_all(&root_copy).await.unwrap();
        tokio::fs::write(
            root_copy.join("package.json"),
            r#"{"name": "dup", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        // Nested duplicate under another package (npm's conflict-nesting).
        let nested_copy = nm.join("parent").join("node_modules").join("dup");
        tokio::fs::create_dir_all(&nested_copy).await.unwrap();
        tokio::fs::write(
            nested_copy.join("package.json"),
            r#"{"name": "dup", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();
        tokio::fs::write(
            nm.join("parent").join("package.json"),
            r#"{"name": "parent", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let purl = "pkg:npm/dup@1.0.0".to_string();
        let result = crawler
            .find_by_purls(&nm, std::slice::from_ref(&purl))
            .await
            .unwrap();

        let copies = result.get(&purl).expect("dup must resolve");
        assert_eq!(
            copies.len(),
            2,
            "both physical copies must be returned; got {copies:?}"
        );
        // Root-copy-first ordering (breadth-first): callers needing one
        // representative take [0] and get the root copy.
        assert_eq!(copies[0].path, root_copy, "root copy must be first");
        let paths: HashSet<&Path> = copies.iter().map(|c| c.path.as_path()).collect();
        assert!(paths.contains(root_copy.as_path()));
        assert!(paths.contains(nested_copy.as_path()));
    }

    /// A single (non-duplicated) install resolves to a one-element Vec — the
    /// common case must not regress into a spurious duplicate.
    #[tokio::test]
    async fn test_find_by_purls_single_copy_is_one_element() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        let foo = nm.join("solo");
        tokio::fs::create_dir_all(&foo).await.unwrap();
        tokio::fs::write(
            foo.join("package.json"),
            r#"{"name": "solo", "version": "2.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let purl = "pkg:npm/solo@2.0.0".to_string();
        let result = crawler
            .find_by_purls(&nm, std::slice::from_ref(&purl))
            .await
            .unwrap();
        let copies = result.get(&purl).expect("solo must resolve");
        assert_eq!(copies.len(), 1, "single install must be one copy");
        assert_eq!(copies[0].path, foo);
    }

    /// The `NESTED_STORE_MAX_DIRS` cap must terminate a nested-store
    /// descent over a corrupted/adversarial tree instead of turning it
    /// into an unbounded readdir storm. Stages one more child than the
    /// cap (each shaped as a depth-1 package home so every one passes the
    /// filters and consumes cap budget) and pins that the walk stops at
    /// exactly the cap — failing toward "not installed", never patching
    /// the wrong package. Deliberately does NOT assert WHICH entries
    /// survive: readdir order is unspecified. (~16.4k staged dirs; a
    /// couple of seconds of mkdir churn is the price of firing the cap.)
    #[tokio::test]
    async fn test_collect_nested_store_entries_respects_dir_cap() {
        let host = tempfile::tempdir().unwrap();
        let over = NESTED_STORE_MAX_DIRS + 16;
        for i in 0..over {
            std::fs::create_dir_all(host.path().join(format!("d{i:05}")).join("node_modules"))
                .unwrap();
        }

        let mut entries = Vec::new();
        NpmCrawler::collect_nested_store_entries(host.path(), &mut entries).await;

        assert_eq!(
            entries.len(),
            NESTED_STORE_MAX_DIRS,
            "the walk must stop at exactly the dir cap"
        );
        // Every yielded entry is a real staged package home.
        for (name, nm) in &entries {
            assert!(name.starts_with('d'), "unexpected entry name {name:?}");
            assert_eq!(nm, &host.path().join(name).join("node_modules"));
        }
    }

    /// Save and restore an env var around a test body (drop-safe).
    #[cfg(target_os = "macos")]
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }
    #[cfg(target_os = "macos")]
    impl EnvGuard {
        fn set(key: &'static str, value: &std::ffi::OsStr) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prev }
        }
    }
    #[cfg(target_os = "macos")]
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    /// Pins the literal volta (`.volta/tools/image/node/*/lib/
    /// node_modules`) and fnm (`.fnm/node-versions/*/installation/lib/
    /// node_modules`) global-install layouts on macOS — the nvm sibling
    /// loop is exercised on any nvm-carrying host, but nothing pins these
    /// two unless the dev machine happens to have the tools installed.
    /// `HOME` is process-global, hence `serial` + guard.
    #[cfg(target_os = "macos")]
    #[test]
    #[serial_test::serial]
    fn test_macos_global_paths_pick_up_volta_and_fnm_layouts() {
        let home = tempfile::tempdir().unwrap();
        let volta_nm = home
            .path()
            .join(".volta/tools/image/node/v20.0.0/lib/node_modules");
        let fnm_nm = home
            .path()
            .join(".fnm/node-versions/v20.0.0/installation/lib/node_modules");
        std::fs::create_dir_all(&volta_nm).unwrap();
        std::fs::create_dir_all(&fnm_nm).unwrap();

        let _home_guard = EnvGuard::set("HOME", home.path().as_os_str());
        let paths = NpmCrawler::new().get_global_node_modules_paths();

        // `contains`, not equality: host npm/nvm/homebrew paths may also
        // appear.
        assert!(
            paths.contains(&volta_nm),
            "volta layout must be discovered under $HOME; got {paths:?}"
        );
        assert!(
            paths.contains(&fnm_nm),
            "fnm layout must be discovered under $HOME; got {paths:?}"
        );
    }

    /// The workspace roots walk is iterative: a directory chain far deeper
    /// than a small stack can recurse through completes on walk threads
    /// with only 256 KiB of stack (the recursive walk overflowed there),
    /// and still yields depth-first order — each dir's `node_modules`
    /// before anything below it.
    #[test]
    fn test_workspace_walk_deep_chain_small_stack() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        // Stay well inside macOS's 1024-byte PATH_MAX.
        let depth = 400.min(900usize.saturating_sub(root.as_os_str().len()) / 2);
        assert!(depth >= 200, "temp dir path too long: {}", root.display());

        let mut expected = vec![root.join("node_modules")];
        let mut chain = root.clone();
        for level in 1..=depth {
            chain.push("a");
            if level == depth / 2 || level == depth {
                expected.push(chain.join("node_modules"));
            }
        }
        std::fs::create_dir_all(&chain).unwrap();
        for nm in &expected {
            std::fs::create_dir_all(nm).unwrap();
        }

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .stack_size(256 * 1024)
            .build()
            .unwrap();
        let found = pool.install(|| NpmCrawler::find_local_node_modules_dirs(&root));
        assert_eq!(found, expected);
    }

    /// A directory carrying a signed `CACHEDIR.TAG` (a cargo `target/`, a
    /// tool cache) is pruned from the workspace roots walk whole: its own
    /// `node_modules` and every workspace below it. An untagged sibling,
    /// the scan root itself, and a tag that is not a valid one (no
    /// signature, a directory, a symlink) prune nothing.
    #[tokio::test]
    async fn test_workspace_walk_prunes_tagged_cache_dirs() {
        const TAG: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55\n# a cache\n";
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let nm = |rel: &str| {
            let path = root.join(rel).join("node_modules");
            std::fs::create_dir_all(&path).unwrap();
            path
        };
        // The scan root is tagged too: it is still scanned.
        std::fs::write(root.join("CACHEDIR.TAG"), TAG).unwrap();
        let root_nm = nm("");
        let app = nm("apps/web");
        // Pruned: the tagged dir's own node_modules and everything below.
        nm("target");
        nm("target/debug/deps/pkg");
        std::fs::write(root.join("target/CACHEDIR.TAG"), TAG).unwrap();
        nm("apps/web/cache");
        nm("apps/web/cache/deep/ws");
        std::fs::write(root.join("apps/web/cache/CACHEDIR.TAG"), TAG).unwrap();
        // Not tags: kept.
        let unsigned = nm("libs/unsigned");
        std::fs::write(root.join("libs/unsigned/CACHEDIR.TAG"), b"not a tag\n").unwrap();
        let short = nm("libs/short");
        std::fs::write(root.join("libs/short/CACHEDIR.TAG"), &TAG[..10]).unwrap();
        let as_dir = nm("libs/as-dir");
        std::fs::create_dir_all(root.join("libs/as-dir/CACHEDIR.TAG")).unwrap();
        #[cfg(unix)]
        let linked = {
            let linked = nm("libs/linked");
            std::fs::write(root.join("real.tag"), TAG).unwrap();
            std::os::unix::fs::symlink(
                root.join("real.tag"),
                root.join("libs/linked/CACHEDIR.TAG"),
            )
            .unwrap();
            linked
        };

        let options = CrawlerOptions {
            cwd: root.clone(),
            global: false,
            global_prefix: None,
        };
        let mut found = NpmCrawler::new()
            .get_node_modules_paths(&options)
            .await
            .unwrap();
        found.sort();
        let mut want = vec![root_nm, app, unsigned, short, as_dir];
        #[cfg(unix)]
        want.push(linked);
        want.sort();
        assert_eq!(found, want);

        // Removing the tag un-prunes the directory.
        std::fs::remove_file(root.join("target/CACHEDIR.TAG")).unwrap();
        let found = NpmCrawler::new()
            .get_node_modules_paths(&options)
            .await
            .unwrap();
        assert!(
            found.contains(&root.join("target/node_modules")),
            "{found:?}"
        );
        assert!(
            found.contains(&root.join("target/debug/deps/pkg/node_modules")),
            "{found:?}"
        );
    }
    /// and undecodable ids are `None` (still probed by package.json).
    #[test]
    fn test_decode_vlt_dep_id_table() {
        let some = |n: &str, v: &str| Some((n.to_string(), v.to_string()));
        let rows: &[(&str, Option<(String, String)>)] = &[
            ("··ms@2.1.3", some("ms", "2.1.3")),
            (
                "·npm·@isaacs§string-locale-compare@1.1.0",
                some("@isaacs/string-locale-compare", "1.1.0"),
            ),
            (
                "··@sindresorhus§is@4.6.0",
                some("@sindresorhus/is", "4.6.0"),
            ),
            ("·npm·u@1.0.0%2Bbuild.1", some("u", "1.0.0+build.1")),
            (
                "··ms@2.1.3·%3Aroot%20%3E%20%23debug%20%3E%20%23ms",
                some("ms", "2.1.3"),
            ),
            ("·npm·x@1.0.0·%E1%B9%97%3A3", some("x", "1.0.0")),
            ("~npm~@a+b@1.0.0", some("@a/b", "1.0.0")),
            ("~npm~a__b@1.0.0", some("a_b", "1.0.0")),
            ("~npm~u@1.0.0_pbuild.1", some("u", "1.0.0+build.1")),
            (
                "~npm~is-number@6.0.0~_croot_s_g_s#to-regex-range_s_g_s#is-number",
                some("is-number", "6.0.0"),
            ),
            (
                "~npm~react-dom@18.2.0~peer.ace93b147498ef7a",
                some("react-dom", "18.2.0"),
            ),
            ("~npm~x@1.0.0~peer.2", some("x", "1.0.0")),
            ("~npm~x@1~peer.2", None),
            ("~acme~left-pad@1.3.0", some("left-pad", "1.3.0")),
            ("~http_c++127.0.0.1_c4873+~x@1.0.0", some("x", "1.0.0")),
            ("·http%3A§§127.0.0.1%3A4873§·x@1.0.0", some("x", "1.0.0")),
            (
                "~jsr~@jsr+std____semver@1.0.8",
                some("@jsr/std__semver", "1.0.8"),
            ),
            ("git~github_cisaacs+string-locale-compare~v1.1.0", None),
            ("git·github%3Aisaacs§string-locale-compare·v1.1.0", None),
            ("file~vendor+ms-2.1.2.tgz", None),
            ("file·vendor§ms-2.1.2.tgz", None),
            (
                "remote~https_c++registry.npmjs.org+left-pad+-+left-pad-1.2.0.tgz",
                None,
            ),
            ("workspace~packages+a", None),
            ("workspace·packages§a", None),
            ("··m%ZZs@1.0.0", None),
            ("·npm·ms@2.1.3·%4", None),
            ("ms@2.1.3", None),
            ("node_modules", None),
        ];
        for (id, want) in rows {
            assert_eq!(&decode_vlt_store_entry_name(OsStr::new(id)), want, "{id}");
        }
    }

    /// The hazard the separate decoders exist for: the pnpm decoder reads
    /// legacy vlt names as packages named `··foo` / `·npm·@s§p`, so a vlt
    /// entry run through it would be skipped by the pending-name filter.
    /// vlt entries are advertised through the vlt decoder only.
    #[test]
    fn test_vlt_store_entries_never_reach_the_pnpm_decoder() {
        assert_eq!(
            decode_pnpm_store_entry_name("··foo@1.0.0"),
            Some(("··foo".to_string(), "1.0.0".to_string()))
        );
        let entries = || {
            vec![
                (OsString::from("··foo@1.0.0"), PathBuf::from("a")),
                (OsString::from("·npm·@s§p@2.0.0"), PathBuf::from("b")),
                (OsString::from("~npm~@s+p@2.0.0~peer.1"), PathBuf::from("c")),
            ]
        };
        let pending: HashSet<&str> = ["foo", "@s/p"].into_iter().collect();
        let kept = |entries: Vec<StoreEntry>| -> Vec<PathBuf> {
            entries
                .into_iter()
                .filter(|e| NpmCrawler::store_entry_may_hold(e, Some(&pending)))
                .map(|e| e.node_modules)
                .collect()
        };
        assert_eq!(
            kept(StoreEntry::vlt(entries())),
            vec![PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")]
        );
        let as_pnpm = entries()
            .into_iter()
            .map(|(n, p)| (n.into_string().unwrap(), p))
            .collect();
        assert!(
            !kept(StoreEntry::pnpm(as_pnpm)).contains(&PathBuf::from("a")),
            "the pnpm decoder misreads the legacy name"
        );
    }

    #[test]
    fn test_vlt_store_is_not_a_legacy_pnpm_store() {
        for name in [".vlt", ".vlt-lock.json", ".VLT.DELETE.1.~npm~a@1.0.0"] {
            assert!(!is_legacy_pnpm_store_dir_name(name), "{name}");
        }
    }

    /// `list_vlt_store_entries` yields only real entry dirs with a real
    /// `node_modules`, keeping the raw (legacy `·`/`§`) names.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_list_vlt_store_entries_skips_hoist_meta_links_and_files() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join(".vlt");
        for dir in [
            "··ms@2.1.3/node_modules/ms",
            "~npm~a@1.0.0/node_modules/a",
            "node_modules/@scope",
            "node_modules/node_modules/hoist-decoy",
            ".VLT.DELETE.9.~npm~b@1.0.0/node_modules/b",
            "~npm~no-nm@1.0.0/no-nm",
            "elsewhere/node_modules",
            "~npm~nm-link@1.0.0",
        ] {
            std::fs::create_dir_all(store.join(dir)).unwrap();
        }
        std::fs::write(store.join("vlt.json"), "{}").unwrap();
        std::os::unix::fs::symlink(store.join("~npm~a@1.0.0"), store.join("~npm~linked@1.0.0"))
            .unwrap();
        std::os::unix::fs::symlink(
            store.join("elsewhere/node_modules"),
            store.join("~npm~nm-link@1.0.0/node_modules"),
        )
        .unwrap();

        let mut got: Vec<(OsString, PathBuf)> = NpmCrawler::list_vlt_store_entries(&store).await;
        got.sort();
        assert_eq!(
            got,
            vec![
                (
                    OsString::from("elsewhere"),
                    store.join("elsewhere/node_modules")
                ),
                (
                    OsString::from("~npm~a@1.0.0"),
                    store.join("~npm~a@1.0.0/node_modules")
                ),
                (
                    OsString::from("··ms@2.1.3"),
                    store.join("··ms@2.1.3/node_modules")
                ),
            ]
        );
    }

    fn write_pkg(dir: &Path, name: &str, version: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            format!(r#"{{"name":"{name}","version":"{version}"}}"#),
        )
        .unwrap();
    }

    /// A directory link the way vlt writes it: a symlink on Unix, an
    /// absolute-target NTFS junction on Windows (vlt >= 1.0.0-rc.22).
    fn link_dir(target: &Path, link: &Path) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        {
            // Rebuilt from components so every separator is `\`: `mklink`
            // reads a `/` inside a path (`a@1/node_modules/b`) as a switch.
            let link: PathBuf = link.components().collect();
            let target: PathBuf = target.components().collect();
            let status = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&link)
                .arg(&target)
                .status()
                .unwrap();
            assert!(status.success(), "mklink /J failed");
        }
    }

    /// A small vlt tree on the host's own link kind (junctions on Windows):
    /// the importer link resolves at the importer root, a dependency link
    /// inside a store entry is an edge (never a second inventory entry),
    /// the legacy `·npm·@scope§bar@2.0.0` name round-trips through the
    /// filesystem, and the fan-out finds the peer twin from the link.
    #[tokio::test]
    async fn test_vlt_store_links_are_edges_on_every_platform() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let store = nm.join(".vlt");
        let bar = store
            .join("·npm·@scope§bar@2.0.0")
            .join("node_modules")
            .join("@scope")
            .join("bar");
        write_pkg(&bar, "@scope/bar", "2.0.0");
        let foo_entry = store.join("~npm~foo@1.0.0~peer.2").join("node_modules");
        write_pkg(&foo_entry.join("foo"), "foo", "1.0.0");
        std::fs::create_dir_all(foo_entry.join("@scope")).unwrap();
        link_dir(&bar, &foo_entry.join("@scope").join("bar"));
        let twin = store
            .join("~npm~foo@1.0.0~peer.3")
            .join("node_modules")
            .join("foo");
        write_pkg(&twin, "foo", "1.0.0");
        link_dir(&foo_entry.join("foo"), &nm.join("foo"));

        let options = CrawlerOptions {
            cwd: root.clone(),
            global: false,
            global_prefix: None,
        };
        let mut scanned: Vec<(String, PathBuf)> = NpmCrawler::new()
            .crawl_all(&options)
            .await
            .into_iter()
            .map(|p| (p.purl, p.path))
            .collect();
        scanned.sort();
        assert_eq!(
            scanned,
            vec![
                ("pkg:npm/@scope/bar@2.0.0".to_string(), bar.clone()),
                ("pkg:npm/foo@1.0.0".to_string(), nm.join("foo")),
            ]
        );

        let found = NpmCrawler::new()
            .find_by_purls(&nm, &["pkg:npm/foo@1.0.0".to_string()])
            .await
            .unwrap();
        let primary = &found["pkg:npm/foo@1.0.0"][0].path;
        assert_eq!(primary, &nm.join("foo"));
        assert_eq!(find_store_peer_variant_copies(primary).await, vec![twin]);
    }

    /// vlt fan-out gates: every real copy whose DepID decodes to the
    /// primary's `name@version` (peer counters, hashed peers, modifier
    /// extras, the legacy `··`/`·npm·` pair) is returned once; the primary,
    /// dependency links, the hoist dir, rollback staging, an imposter
    /// package.json and git/remote/file ids (distinct artifacts, not
    /// variants) are not.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_find_store_peer_variant_copies_vlt_gates() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        let store = nm.join(".vlt");
        let copy = |id: &str| store.join(id).join("node_modules").join("foo");
        let primary = copy("~npm~foo@1.0.0~peer.2");
        let twins = [
            copy("~npm~foo@1.0.0~peer.3"),
            copy("~npm~foo@1.0.0~peer.dbd5ca8b03a66489"),
            copy("~npm~foo@1.0.0~_croot_s_g_s#foo"),
            copy("··foo@1.0.0"),
            copy("·npm·foo@1.0.0"),
        ];
        for dir in std::iter::once(&primary).chain(&twins) {
            write_pkg(dir, "foo", "1.0.0");
        }
        for id in [
            "git~github_cu+foo~v1.0.0",
            "remote~https_c++e.com+foo-1.0.0.tgz",
            "file~vendor+foo-1.0.0.tgz",
            ".VLT.DELETE.1.~npm~foo@1.0.0",
        ] {
            write_pkg(&copy(id), "foo", "1.0.0");
        }
        write_pkg(&copy("~npm~foo@1.0.0~peer.9"), "foo", "1.0.1");
        write_pkg(&store.join("node_modules/foo"), "foo", "1.0.0");
        let dependent = store.join("~npm~dep@1.0.0/node_modules");
        write_pkg(&dependent.join("dep"), "dep", "1.0.0");
        std::os::unix::fs::symlink(&twins[0], dependent.join("foo")).unwrap();
        std::os::unix::fs::symlink(&primary, nm.join("foo")).unwrap();

        for start in [primary.clone(), nm.join("foo")] {
            let mut got = find_store_peer_variant_copies(&start).await;
            got.sort();
            let mut want = twins.to_vec();
            want.sort();
            assert_eq!(got, want, "from {}", start.display());
        }
    }

    #[tokio::test]
    async fn test_store_expansion_scans_transitive_peer_store_once() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().canonicalize().unwrap().join("node_modules");
        let store = nm.join(".pnpm");
        let peers: Vec<_> = (0..8)
            .map(|i| store.join(format!("foo@1.0.0(peer@1.0.{i})/node_modules/foo")))
            .collect();
        for path in &peers {
            write_pkg(path, "foo", "1.0.0");
        }
        // Without an importer link the resolver already returns every
        // peer. Agent VEX passes this entire set to variant expansion.
        let purl = "pkg:npm/foo@1.0.0".to_string();
        let found = NpmCrawler::new()
            .find_by_purls(&nm, std::slice::from_ref(&purl))
            .await
            .unwrap();
        let paths: Vec<_> = found[&purl].iter().map(|pkg| pkg.path.clone()).collect();
        assert_eq!(paths.len(), peers.len());
        let (expanded, scans) = tracked_store_expansion(paths.clone()).await;
        assert_eq!(
            expanded, paths,
            "all original copies and their order survive"
        );
        assert_eq!(
            scans.len(),
            1,
            "one enumeration per store/identity: {scans:?}"
        );
    }

    #[tokio::test]
    async fn test_store_expansion_keeps_distinct_identities_and_alias_stores() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let store = root.join("main/node_modules/.pnpm");
        let mut inputs = Vec::new();
        let mut expected = HashSet::new();
        for (name, version) in [("foo", "1.0.0"), ("foo", "2.0.0"), ("bar", "1.0.0")] {
            for i in 0..2 {
                let path = store.join(format!(
                    "{name}@{version}(peer@1.0.{i})/node_modules/{name}"
                ));
                write_pkg(&path, name, version);
                expected.insert(path.canonicalize().unwrap());
                if i == 0 {
                    inputs.push(path);
                }
            }
        }
        let alias_nm = root.join("alias/node_modules");
        let alias_store = alias_nm.join(".pnpm");
        for i in 0..2 {
            let path = alias_store.join(format!("foo@1.0.0(peer@1.0.{i})/node_modules/foo"));
            write_pkg(&path, "foo", "1.0.0");
            expected.insert(path.canonicalize().unwrap());
        }
        let alias = alias_nm.join("foo");
        link_dir(&inputs[0], &alias);
        inputs.push(alias);
        // Another lexical route to the same primary AND alias store.
        // Candidate discovery must run, but this physical store/identity
        // has already been scanned through the preceding alias.
        let linked_nm = root.join("linked/node_modules");
        std::fs::create_dir_all(&linked_nm).unwrap();
        link_dir(&alias_store, &linked_nm.join(".pnpm"));
        let linked_alias = linked_nm.join("foo");
        link_dir(&inputs[0], &linked_alias);
        inputs.push(linked_alias);

        let (expanded, scans) = tracked_store_expansion(inputs.clone()).await;
        assert_eq!(&expanded[..inputs.len()], inputs);
        assert_eq!(
            expanded.len(),
            expected.len() + 2,
            "retain initial alias paths"
        );
        assert_eq!(
            expanded
                .iter()
                .map(|p| p.canonicalize().unwrap())
                .collect::<HashSet<_>>(),
            expected
        );
        let scans: Vec<_> = scans.iter().map(|p| p.canonicalize().unwrap()).collect();
        assert_eq!(scans.iter().filter(|p| **p == store).count(), 3);
        assert_eq!(scans.iter().filter(|p| **p == alias_store).count(), 1);

        // Standalone apply/rollback discovery gets a fresh scan and still
        // excludes only its own primary copy.
        let copies = find_store_peer_variant_copies(&inputs[0]).await;
        assert_eq!(copies.len(), 1);
        assert_ne!(
            copies[0].canonicalize().unwrap(),
            inputs[0].canonicalize().unwrap()
        );
    }

    /// D19: a vendored copy's `.socket/vendor/npm/<uuid>/<leaf>/node_modules`
    /// is never a crawl root (hidden dirs are skipped), so the only
    /// inventory entry is the importer link that points at it.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_socket_vendor_node_modules_is_never_crawled() {
        let tmp = tempfile::tempdir().unwrap();
        let vendored = tmp.path().join(
            ".socket/vendor/npm/0b6f8a1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b/left-pad-1.3.0/node_modules/left-pad",
        );
        write_pkg(&vendored, "left-pad", "1.3.0");
        write_pkg(&vendored.join("node_modules/inner"), "inner", "1.0.0");
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(nm.join(".vlt")).unwrap();
        std::os::unix::fs::symlink(&vendored, nm.join("left-pad")).unwrap();
        let options = CrawlerOptions {
            cwd: tmp.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        assert_eq!(
            NpmCrawler::new()
                .get_node_modules_paths(&options)
                .await
                .unwrap(),
            vec![nm.clone()]
        );
        let scanned: Vec<(String, PathBuf)> = NpmCrawler::new()
            .crawl_all(&options)
            .await
            .into_iter()
            .map(|p| (p.purl, p.path))
            .collect();
        assert_eq!(
            scanned,
            vec![("pkg:npm/left-pad@1.3.0".to_string(), nm.join("left-pad"))]
        );
    }

    fn scan_paths(root: &Path) -> impl std::future::Future<Output = Vec<(String, PathBuf)>> {
        let options = CrawlerOptions {
            cwd: root.to_path_buf(),
            global: false,
            global_prefix: None,
        };
        async move {
            let mut scanned: Vec<(String, PathBuf)> = NpmCrawler::new()
                .crawl_all(&options)
                .await
                .into_iter()
                .map(|p| (p.purl, p.path))
                .collect();
            scanned.sort();
            scanned
        }
    }

    #[test]
    fn test_decode_npm_store_entry_name() {
        let hash = "Pqc5my552wJdjE6sp0MCIg";
        assert_eq!(
            decode_npm_store_entry_name(&format!("is-number@6.0.0-{hash}")),
            Some(("is-number".to_string(), "6.0.0".to_string()))
        );
        // The hash is base64url, so it can hold `-` and `_` itself.
        assert_eq!(
            decode_npm_store_entry_name("escape-string-regexp@1.0.5-YUOzcg-PmWvuNTSNPuN4qw"),
            Some(("escape-string-regexp".to_string(), "1.0.5".to_string()))
        );
        assert_eq!(
            decode_npm_store_entry_name(&format!("@babel/code-frame@7.0.0-beta.1-{hash}")),
            Some(("@babel/code-frame".to_string(), "7.0.0-beta.1".to_string()))
        );
        // A shrinkwrapped dependency's un-hashed `name@version` dir, a
        // missing hash, and a non-semver version stay undecodable.
        assert_eq!(decode_npm_store_entry_name("foo@1.0.0"), None);
        assert_eq!(decode_npm_store_entry_name(&format!("foo-{hash}")), None);
        assert_eq!(
            decode_npm_store_entry_name(&format!("foo@abc-{hash}")),
            None
        );
        assert_eq!(decode_npm_store_entry_name(&format!("@1.0.0-{hash}")), None);
    }

    /// #359: npm's `install-strategy=linked` keeps every package in
    /// `node_modules/.store/<name>@<version>-<hash>/node_modules/<name>`
    /// (scoped: `.store/@scope/<leaf>@…/node_modules/@scope/<leaf>`). The
    /// importer links direct deps only, so a transitive package is a real
    /// dir ONLY inside the store. Scan, the resolver and the peer-variant
    /// fan-out must all see it; dependency links inside an entry stay
    /// edges.
    #[tokio::test]
    async fn test_npm_linked_store_transitive_packages_are_found() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let store = nm.join(".store");

        let odd_entry = store.join("is-odd@3.0.1-6I_Y0S8g8dpI-_3nzyUbcQ/node_modules");
        write_pkg(&odd_entry.join("is-odd"), "is-odd", "3.0.1");
        let number = store.join("is-number@6.0.0-Pqc5my552wJdjE6sp0MCIg/node_modules/is-number");
        write_pkg(&number, "is-number", "6.0.0");
        // Same name@version, different dependency graph: a second hash.
        let number_twin =
            store.join("is-number@6.0.0-AAAAAAAAAAAAAAAAAAAAAA/node_modules/is-number");
        write_pkg(&number_twin, "is-number", "6.0.0");
        link_dir(&number, &odd_entry.join("is-number"));
        let frame = store
            .join("@babel/code-frame@7.0.0-wERilBtYXgdUWVgsD7hGnw/node_modules/@babel/code-frame");
        write_pkg(&frame, "@babel/code-frame", "7.0.0");
        link_dir(&odd_entry.join("is-odd"), &nm.join("is-odd"));

        let scanned = scan_paths(&root).await;
        let purls: Vec<&str> = scanned.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(
            purls,
            vec![
                "pkg:npm/@babel/code-frame@7.0.0",
                "pkg:npm/is-number@6.0.0",
                "pkg:npm/is-odd@3.0.1",
            ],
            "{scanned:?}"
        );
        assert!(scanned.contains(&("pkg:npm/is-odd@3.0.1".to_string(), nm.join("is-odd"))));

        let targets = [
            "pkg:npm/is-number@6.0.0".to_string(),
            "pkg:npm/@babel/code-frame@7.0.0".to_string(),
        ];
        let found = NpmCrawler::new()
            .find_by_purls(&nm, &targets)
            .await
            .unwrap();
        let mut numbers: Vec<PathBuf> = found["pkg:npm/is-number@6.0.0"]
            .iter()
            .map(|p| p.path.clone())
            .collect();
        numbers.sort();
        let mut want = vec![number.clone(), number_twin.clone()];
        want.sort();
        assert_eq!(numbers, want);
        assert_eq!(found["pkg:npm/@babel/code-frame@7.0.0"][0].path, frame);

        assert_eq!(
            find_store_peer_variant_copies(&number).await,
            vec![number_twin.clone()]
        );
    }

    /// #852: under `install-strategy=linked`, npm 9–11 store an alias
    /// install (`"lp": "npm:left-pad@1.3.0"`) in an entry named after the
    /// ALIAS: `.store/lp@1.3.0-<hash>/node_modules/lp` holds the real
    /// `left-pad@1.3.0`, and the importer's `node_modules/lp` links to it.
    /// Beside a plain copy, the plain copy is the resolver's primary and
    /// the alias entry is the peer-variant fan-out's to find, or apply
    /// leaves `require('lp')` unpatched while VEX attests `not_affected`.
    #[tokio::test]
    async fn test_npm_linked_store_alias_entry_beside_a_plain_copy_is_a_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let store = nm.join(".store");

        let plain = store.join("left-pad@1.3.0-iv4j8hdajpqgDc7lVr5hdA/node_modules/left-pad");
        write_pkg(&plain, "left-pad", "1.3.0");
        let alias = store.join("lp@1.3.0-NCKE2NXgCY5tgWWRE6qdYA/node_modules/lp");
        write_pkg(&alias, "left-pad", "1.3.0");
        // A scoped alias name, and an unscoped alias of a scoped package.
        let scoped_alias = store.join("@x/pad@1.3.0-AAAAAAAAAAAAAAAAAAAAAA/node_modules/@x/pad");
        write_pkg(&scoped_alias, "left-pad", "1.3.0");
        // An alias of another version, and an alias entry whose own dir is
        // a link (a dependency edge), are not copies.
        let other = store.join("lp2@1.2.0-BBBBBBBBBBBBBBBBBBBBBB/node_modules/lp2");
        write_pkg(&other, "left-pad", "1.2.0");
        let edge_entry = store.join("lp3@1.3.0-CCCCCCCCCCCCCCCCCCCCCC/node_modules");
        std::fs::create_dir_all(&edge_entry).unwrap();
        link_dir(&plain, &edge_entry.join("lp3"));
        link_dir(&plain, &nm.join("left-pad"));
        link_dir(&alias, &nm.join("lp"));

        let purl = "pkg:npm/left-pad@1.3.0".to_string();
        let found = NpmCrawler::new()
            .find_by_purls(&nm, std::slice::from_ref(&purl))
            .await
            .unwrap();
        assert_eq!(copy_paths(&found, &purl), vec![nm.join("left-pad")]);

        let mut variants = find_store_peer_variant_copies(&nm.join("left-pad")).await;
        variants.sort();
        let mut want = vec![alias.clone(), scoped_alias.clone()];
        want.sort();
        assert_eq!(variants, want);

        // VEX's every-installed-copy set sees the alias entries too.
        let mut all = with_store_peer_variant_copies(vec![nm.join("left-pad")]).await;
        all.sort();
        let mut want = vec![nm.join("left-pad"), alias.clone(), scoped_alias.clone()];
        want.sort();
        assert_eq!(all, want);
    }

    /// #852: with only the alias installed, the alias-named linked store
    /// entry is the purl's only copy. Apply reported it "not found on
    /// disk" (exit 0) and VEX refused with `package_not_found`.
    #[tokio::test]
    async fn test_npm_linked_store_alias_only_install_is_resolved() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let store = nm.join(".store");

        let alias = store.join("lp@1.3.0-NCKE2NXgCY5tgWWRE6qdYA/node_modules/lp");
        write_pkg(&alias, "left-pad", "1.3.0");
        let scoped = store.join("sp@2.0.0-DDDDDDDDDDDDDDDDDDDDDD/node_modules/sp");
        write_pkg(&scoped, "@s/pkg", "2.0.0");
        link_dir(&alias, &nm.join("lp"));
        link_dir(&scoped, &nm.join("sp"));

        let pad = "pkg:npm/left-pad@1.3.0".to_string();
        let scoped_purl = "pkg:npm/%40s/pkg@2.0.0".to_string();
        let found = NpmCrawler::new()
            .find_by_purls(&nm, &[pad.clone(), scoped_purl.clone()])
            .await
            .unwrap();
        assert_eq!(copy_paths(&found, &pad), vec![alias.clone()]);
        let copy = &found[&pad][0];
        assert_eq!(
            (copy.name.as_str(), copy.version.as_str()),
            ("left-pad", "1.3.0")
        );
        assert_eq!(copy_paths(&found, &scoped_purl), vec![scoped.clone()]);
        assert_eq!(found[&scoped_purl][0].namespace.as_deref(), Some("@s"));
    }

    /// #362: pnpm's `virtualStoreDir` moves the virtual store, and
    /// `node_modules/.modules.yaml` records where (relative to
    /// `node_modules`: JSON on pnpm 10+, YAML before). A relocated store
    /// inside the project is walked like `.pnpm`, wherever it sits.
    #[tokio::test]
    async fn test_pnpm_relocated_virtual_store_dir_is_walked() {
        for (modules_yaml, store_rel) in [
            (
                "{\n  \"layoutVersion\": 5,\n  \"virtualStoreDir\": \"../.vstore\"\n}",
                ".vstore",
            ),
            // Older pnpm wrote an absolute path.
            (
                "layoutVersion: 5\nvirtualStoreDir: \"<ROOT>/.abs-store\"\n",
                ".abs-store",
            ),
            (
                "layoutVersion: 5\nvirtualStoreDir: '.custom'\n",
                "node_modules/.custom",
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let base: PathBuf = tmp.path().components().collect();
            // Reach the project through a linked ancestor, as macOS's
            // `/var` → `/private/var` temp dirs do: reported copies keep
            // the spelling the caller used.
            let real = base.join("real");
            std::fs::create_dir_all(&real).unwrap();
            let root = base.join("linked");
            link_dir(&real, &root);
            let nm = root.join("node_modules");
            let store = root.join(store_rel);
            let odd_entry = store.join("is-odd@3.0.1/node_modules");
            write_pkg(&odd_entry.join("is-odd"), "is-odd", "3.0.1");
            let number = store.join("is-number@6.0.0/node_modules/is-number");
            write_pkg(&number, "is-number", "6.0.0");
            link_dir(&number, &odd_entry.join("is-number"));
            let foo = store.join("foo@1.0.0(react@17.0.2)/node_modules/foo");
            let foo_twin = store.join("foo@1.0.0(react@18.2.0)/node_modules/foo");
            write_pkg(&foo, "foo", "1.0.0");
            write_pkg(&foo_twin, "foo", "1.0.0");
            std::fs::create_dir_all(nm.join(".pnpm")).unwrap();
            let modules_yaml =
                modules_yaml.replace("<ROOT>", &root.display().to_string().replace('\\', "\\\\"));
            std::fs::write(nm.join(".modules.yaml"), modules_yaml).unwrap();
            link_dir(&odd_entry.join("is-odd"), &nm.join("is-odd"));

            let scanned = scan_paths(&root).await;
            assert!(
                scanned.contains(&("pkg:npm/is-number@6.0.0".to_string(), number.clone())),
                "{store_rel}: {scanned:?}"
            );
            assert!(scanned.iter().any(|(p, _)| p == "pkg:npm/foo@1.0.0"));

            let found = NpmCrawler::new()
                .find_by_purls(&nm, &["pkg:npm/is-number@6.0.0".to_string()])
                .await
                .unwrap();
            assert_eq!(
                found
                    .get("pkg:npm/is-number@6.0.0")
                    .map(|c| c.iter().map(|p| p.path.clone()).collect::<Vec<_>>()),
                Some(vec![number.clone()]),
                "{store_rel}"
            );

            let mut variants = find_store_peer_variant_copies(&foo).await;
            variants.sort();
            assert_eq!(variants, vec![foo_twin.clone()], "{store_rel}");
            // From a direct dep's importer link into the store too.
            link_dir(&foo, &nm.join("foo"));
            assert_eq!(
                find_store_peer_variant_copies(&nm.join("foo")).await,
                vec![foo_twin.clone()],
                "{store_rel}"
            );
        }
    }

    /// The peer-variant fan-out only uses a relocated store that holds
    /// the primary: an ENCLOSING project's `.modules.yaml` names a store
    /// this project never loads from, and its copies are not ours to
    /// patch.
    #[tokio::test]
    async fn test_enclosing_projects_relocated_store_is_not_a_peer_variant_source() {
        let tmp = tempfile::tempdir().unwrap();
        let outer: PathBuf = tmp.path().components().collect();
        let outer_nm = outer.join("node_modules");
        std::fs::create_dir_all(&outer_nm).unwrap();
        std::fs::write(
            outer_nm.join(".modules.yaml"),
            "{\"virtualStoreDir\": \"../.vstore\"}",
        )
        .unwrap();
        write_pkg(
            &outer.join(".vstore/foo@1.0.0(react@18.2.0)/node_modules/foo"),
            "foo",
            "1.0.0",
        );

        let inner_store = outer.join("app/node_modules/.pnpm");
        let primary = inner_store.join("foo@1.0.0(react@17.0.2)/node_modules/foo");
        let twin = inner_store.join("foo@1.0.0(react@16.14.0)/node_modules/foo");
        write_pkg(&primary, "foo", "1.0.0");
        write_pkg(&twin, "foo", "1.0.0");
        assert_eq!(find_store_peer_variant_copies(&primary).await, vec![twin]);
    }

    /// A relocated store counts only when it sits strictly below the
    /// importer by plain child names. With the CLI's default `--cwd .` the
    /// importer is the empty path, which `strip_prefix` accepts as a
    /// prefix of anything, absolute or climbing out.
    #[test]
    fn test_path_below_accepts_only_plain_children() {
        let p = Path::new;
        assert_eq!(
            path_below(p(""), p(".vstore")),
            Some(PathBuf::from(".vstore"))
        );
        assert_eq!(
            path_below(p(""), p("node_modules/.custom")),
            Some(PathBuf::from("node_modules/.custom"))
        );
        assert_eq!(
            path_below(p("/proj"), p("/proj/.vstore")),
            Some(PathBuf::from(".vstore"))
        );
        for (importer, store) in [
            ("", "/home/u/.local/share/pnpm/store/v10/links"),
            ("", "../other/.vstore"),
            ("", ""),
            ("/proj", "/proj"),
            ("/proj", "/other/.vstore"),
            ("../proj", "../other"),
        ] {
            assert_eq!(
                path_below(p(importer), p(store)),
                None,
                "{importer:?} {store:?}"
            );
        }
        #[cfg(windows)]
        assert_eq!(path_below(p(""), p(r"C:\pnpm\links")), None);
    }

    /// A `virtualStoreDir` outside the project (pnpm's global virtual
    /// store, `<store>/v10/links`, is shared by every project on the
    /// machine) is NOT walked: agent mode must not patch a shared store
    /// (#361). Nor is a link planted at the recorded path.
    #[tokio::test]
    async fn test_pnpm_virtual_store_dir_outside_project_is_ignored() {
        let outside = tempfile::tempdir().unwrap();
        let shared: PathBuf = outside.path().components().collect();
        let number = shared.join("is-number@6.0.0/node_modules/is-number");
        write_pkg(&number, "is-number", "6.0.0");

        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        let rel = format!("{}", shared.display()).replace('\\', "\\\\");
        std::fs::write(
            nm.join(".modules.yaml"),
            format!("{{\"virtualStoreDir\": \"{rel}\"}}"),
        )
        .unwrap();
        assert!(scan_paths(&root).await.is_empty());

        // A link inside the project pointing at the shared store.
        std::fs::write(
            nm.join(".modules.yaml"),
            "{\"virtualStoreDir\": \"../.vstore\"}",
        )
        .unwrap();
        link_dir(&shared, &root.join(".vstore"));
        assert!(scan_paths(&root).await.is_empty());
        let found = NpmCrawler::new()
            .find_by_purls(&nm, &["pkg:npm/is-number@6.0.0".to_string()])
            .await
            .unwrap();
        assert!(found.is_empty(), "{found:?}");

        // The same link recorded as an absolute path, the form old pnpm
        // writes, is still refused.
        let abs = format!("{}", root.join(".vstore").display()).replace('\\', "\\\\");
        std::fs::write(
            nm.join(".modules.yaml"),
            format!("{{\"virtualStoreDir\": \"{abs}\"}}"),
        )
        .unwrap();
        assert!(scan_paths(&root).await.is_empty());
    }

    /// #362: pnpm's global virtual store (`enableGlobalVirtualStore`)
    /// records `virtualStoreDir` as `<store>/v<N>/links`, outside the
    /// project. A transitive dependency lives only there, so the walks
    /// follow this project's links into the store (and each entry's
    /// dependency links on to sibling entries) and report every copy at
    /// its real store path, where apply refuses it as shared. Entries no
    /// link of this project reaches (another project's packages) stay
    /// invisible.
    #[tokio::test]
    async fn test_pnpm_global_virtual_store_reachable_entries_are_walked() {
        let tmp = tempfile::tempdir().unwrap();
        let base: PathBuf = std::fs::canonicalize(tmp.path())
            .unwrap()
            .components()
            .collect();
        let v10 = base.join("store").join("v10");
        std::fs::create_dir_all(v10.join("files")).unwrap();
        let links = v10.join("links");
        let odd_nm = links.join("@/is-odd/3.0.1/aaa/node_modules");
        write_pkg(&odd_nm.join("is-odd"), "is-odd", "3.0.1");
        let number_nm = links.join("@/is-number/6.0.0/bbb/node_modules");
        let number = number_nm.join("is-number");
        write_pkg(&number, "is-number", "6.0.0");
        link_dir(&number, &odd_nm.join("is-number"));
        // A scoped transitive dep, linked back to is-odd (a cycle).
        let frame = links.join("@babel/code-frame/7.0.0/ccc/node_modules/@babel/code-frame");
        write_pkg(&frame, "@babel/code-frame", "7.0.0");
        std::fs::create_dir_all(number_nm.join("@babel")).unwrap();
        link_dir(&frame, &number_nm.join("@babel/code-frame"));
        let frame_nm = links.join("@babel/code-frame/7.0.0/ccc/node_modules");
        link_dir(&odd_nm.join("is-odd"), &frame_nm.join("is-odd"));
        // Another project's package in the same store.
        let other = links.join("@/left-pad/1.3.0/ddd/node_modules/left-pad");
        write_pkg(&other, "left-pad", "1.3.0");

        let root = base.join("proj");
        let nm = root.join("node_modules");
        std::fs::create_dir_all(nm.join(".pnpm/node_modules")).unwrap();
        std::fs::write(
            nm.join(".modules.yaml"),
            "{\"layoutVersion\": 5, \"virtualStoreDir\": \"../../store/v10/links\"}",
        )
        .unwrap();
        link_dir(&odd_nm.join("is-odd"), &nm.join("is-odd"));

        let scanned = scan_paths(&root).await;
        let purls: Vec<&str> = scanned.iter().map(|(p, _)| p.as_str()).collect();
        assert!(
            scanned.contains(&("pkg:npm/is-number@6.0.0".to_string(), number.clone())),
            "{scanned:?}"
        );
        assert!(
            scanned.contains(&("pkg:npm/@babel/code-frame@7.0.0".to_string(), frame.clone())),
            "{scanned:?}"
        );
        assert_eq!(
            purls
                .iter()
                .filter(|p| **p == "pkg:npm/is-odd@3.0.1")
                .count(),
            1,
            "{scanned:?}"
        );
        assert!(!purls.contains(&"pkg:npm/left-pad@1.3.0"), "{scanned:?}");

        let found = NpmCrawler::new()
            .find_by_purls(
                &nm,
                &[
                    "pkg:npm/is-number@6.0.0".to_string(),
                    "pkg:npm/@babel/code-frame@7.0.0".to_string(),
                    "pkg:npm/left-pad@1.3.0".to_string(),
                ],
            )
            .await
            .unwrap();
        let paths = |purl: &str| {
            found
                .get(purl)
                .map(|c| c.iter().map(|p| p.path.clone()).collect::<Vec<_>>())
        };
        assert_eq!(paths("pkg:npm/is-number@6.0.0"), Some(vec![number]));
        assert_eq!(paths("pkg:npm/@babel/code-frame@7.0.0"), Some(vec![frame]));
        assert_eq!(paths("pkg:npm/left-pad@1.3.0"), None);

        // Without the store's `files/` beside `links` it is not pnpm's
        // global virtual store, so the outside dir is not walked at all.
        std::fs::remove_dir(v10.join("files")).unwrap();
        let scanned = scan_paths(&root).await;
        assert!(
            !scanned.iter().any(|(p, _)| p == "pkg:npm/is-number@6.0.0"),
            "{scanned:?}"
        );
    }

    /// #362 in a workspace: pnpm writes `.modules.yaml` only at the
    /// workspace root, so a member's `node_modules` (holding just its
    /// own links into the global virtual store) has none. The member's
    /// transitive deps must still be found through the root's record,
    /// seeded from the member's own links only.
    #[tokio::test]
    async fn test_pnpm_global_virtual_store_workspace_member_entries_are_walked() {
        let tmp = tempfile::tempdir().unwrap();
        let base: PathBuf = std::fs::canonicalize(tmp.path())
            .unwrap()
            .components()
            .collect();
        let v11 = base.join("store").join("v11");
        std::fs::create_dir_all(v11.join("files")).unwrap();
        let links = v11.join("links");
        let odd_nm = links.join("@/is-odd/3.0.1/aaa/node_modules");
        write_pkg(&odd_nm.join("is-odd"), "is-odd", "3.0.1");
        let number = links.join("@/is-number/6.0.0/bbb/node_modules/is-number");
        write_pkg(&number, "is-number", "6.0.0");
        link_dir(&number, &odd_nm.join("is-number"));
        // Another project's package in the same store.
        let other = links.join("@/left-pad/1.3.0/ddd/node_modules/left-pad");
        write_pkg(&other, "left-pad", "1.3.0");

        let root = base.join("proj");
        let root_nm = root.join("node_modules");
        std::fs::create_dir_all(root_nm.join(".pnpm/node_modules")).unwrap();
        std::fs::write(
            root_nm.join(".modules.yaml"),
            "{\"layoutVersion\": 5, \"virtualStoreDir\": \"../../store/v11/links\"}",
        )
        .unwrap();
        // The root's hoisted links live under `.pnpm/node_modules`.
        link_dir(&other, &root_nm.join(".pnpm/node_modules/left-pad"));
        std::fs::write(root.join("package.json"), "{\"name\": \"root\"}").unwrap();
        let member_nm = root.join("packages/a/node_modules");
        std::fs::create_dir_all(&member_nm).unwrap();
        link_dir(&odd_nm.join("is-odd"), &member_nm.join("is-odd"));

        let scanned = scan_paths(&root).await;
        assert!(
            scanned.contains(&("pkg:npm/is-number@6.0.0".to_string(), number.clone())),
            "{scanned:?}"
        );
        assert!(
            !scanned.iter().any(|(p, _)| p == "pkg:npm/left-pad@1.3.0"),
            "{scanned:?}"
        );

        let found = NpmCrawler::new()
            .find_by_purls(
                &member_nm,
                &[
                    "pkg:npm/is-number@6.0.0".to_string(),
                    "pkg:npm/left-pad@1.3.0".to_string(),
                ],
            )
            .await
            .unwrap();
        let paths = |purl: &str| {
            found
                .get(purl)
                .map(|c| c.iter().map(|p| p.path.clone()).collect::<Vec<_>>())
        };
        assert_eq!(paths("pkg:npm/is-number@6.0.0"), Some(vec![number]));
        assert_eq!(paths("pkg:npm/left-pad@1.3.0"), None);
    }

    /// Old pnpm records `virtualStoreDir` as an absolute path. A store
    /// inside the project must still be walked when the project is
    /// reached through a different spelling than the recorded one (a
    /// linked ancestor, like macOS's `/var` → `/private/var`), which no
    /// lexical prefix check can match.
    #[tokio::test]
    async fn test_absolute_in_project_store_is_walked_through_any_spelling() {
        let tmp = tempfile::tempdir().unwrap();
        let real: PathBuf = std::fs::canonicalize(tmp.path())
            .unwrap()
            .join("real")
            .components()
            .collect();
        let store = real.join(".vstore");
        write_pkg(
            &store.join("is-number@6.0.0/node_modules/is-number"),
            "is-number",
            "6.0.0",
        );
        let nm = real.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        let abs = format!("{}", store.display()).replace('\\', "\\\\");
        std::fs::write(
            nm.join(".modules.yaml"),
            format!("{{\"virtualStoreDir\": \"{abs}\"}}"),
        )
        .unwrap();

        // Recorded and walked spellings agree.
        let scanned = scan_paths(&real).await;
        assert_eq!(scanned.len(), 1, "{scanned:?}");

        // Walked through a linked ancestor: the recorded absolute path is
        // no lexical prefix match, but both resolve to the same store.
        let alias = tmp.path().join("alias");
        link_dir(&real, &alias);
        let scanned = scan_paths(&alias).await;
        assert_eq!(scanned.len(), 1, "{scanned:?}");
        assert!(scanned[0].1.starts_with(&alias), "{scanned:?}");
        let found = NpmCrawler::new()
            .find_by_purls(
                &alias.join("node_modules"),
                &["pkg:npm/is-number@6.0.0".to_string()],
            )
            .await
            .unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
    }

    /// An absolute recording of the DEFAULT store (`node_modules/.pnpm`),
    /// or of `node_modules` itself, is not a relocated store, however the
    /// project path is spelled: the by-name `.pnpm` handling already walks
    /// it, and a second walk would report every store copy twice.
    #[test]
    fn test_absolute_default_store_is_not_a_relocated_store() {
        let tmp = tempfile::tempdir().unwrap();
        let real: PathBuf = std::fs::canonicalize(tmp.path())
            .unwrap()
            .join("real")
            .components()
            .collect();
        let real_nm = real.join("node_modules");
        std::fs::create_dir_all(real_nm.join(".pnpm")).unwrap();
        let alias = tmp.path().join("alias");
        link_dir(&real, &alias);
        for recorded in [real_nm.join(".pnpm"), real_nm.clone()] {
            let abs = format!("{}", recorded.display()).replace('\\', "\\\\");
            std::fs::write(
                real_nm.join(".modules.yaml"),
                format!("{{\"virtualStoreDir\": \"{abs}\"}}"),
            )
            .unwrap();
            for nm in [real_nm.clone(), alias.join("node_modules")] {
                assert_eq!(
                    relocated_pnpm_virtual_store_sync(&nm),
                    None,
                    "{recorded:?} via {nm:?}"
                );
            }
        }
    }

    /// The scan, the resolver and the peer-variant fan-out over one store
    /// tree: every expected purl is scanned, each `targets` purl resolves to
    /// exactly its `want` copies, and the fan-out from `primary` finds
    /// `twins`.
    async fn assert_store_copies_found(
        root: &Path,
        want_scan: &[&str],
        targets: &[(&str, Vec<PathBuf>)],
        primary: &Path,
        twins: Vec<PathBuf>,
    ) {
        let nm = root.join("node_modules");
        let scanned = scan_paths(root).await;
        let purls: Vec<&str> = scanned.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(purls, want_scan, "{scanned:?}");

        let purls: Vec<String> = targets.iter().map(|(p, _)| p.to_string()).collect();
        let found = NpmCrawler::new().find_by_purls(&nm, &purls).await.unwrap();
        for (purl, want) in targets {
            let mut got: Vec<PathBuf> = found
                .get(*purl)
                .map(|copies| copies.iter().map(|p| p.path.clone()).collect())
                .unwrap_or_default();
            got.sort();
            let mut want = want.clone();
            want.sort();
            assert_eq!(got, want, "{purl}");
        }

        assert_eq!(find_store_peer_variant_copies(primary).await, twins);
    }

    /// #366 / #405: Bun's isolated linker keeps every package in
    /// `node_modules/.bun/<name>@<version>[+<hash>]/node_modules/<name>`
    /// (scoped `@scope+leaf@…/node_modules/@scope/leaf`), pnpm-shaped. The
    /// importer links direct deps only, so a transitive package is a real
    /// dir ONLY in the store; `.bun/node_modules` is Bun's hoist dir of
    /// links, and a hosted tarball entry's name (`is-number@http+++…`)
    /// does not decode but must stay probeable.
    #[tokio::test]
    async fn test_bun_isolated_store_transitive_packages_are_found() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let store = nm.join(".bun");

        let odd_entry = store.join("is-odd@3.0.1/node_modules");
        write_pkg(&odd_entry.join("is-odd"), "is-odd", "3.0.1");
        let number = store.join("is-number@6.0.0/node_modules/is-number");
        write_pkg(&number, "is-number", "6.0.0");
        let number_twin = store.join("is-number@6.0.0+3c4e1d2a/node_modules/is-number");
        write_pkg(&number_twin, "is-number", "6.0.0");
        let hosted =
            store.join("to-regex-range@http+++127.0.0.1+t.tgz/node_modules/to-regex-range");
        write_pkg(&hosted, "to-regex-range", "5.0.1");
        link_dir(&number, &odd_entry.join("is-number"));
        let frame = store.join("@babel+code-frame@7.0.0/node_modules/@babel/code-frame");
        write_pkg(&frame, "@babel/code-frame", "7.0.0");
        std::fs::create_dir_all(store.join("node_modules/@babel")).unwrap();
        link_dir(&number, &store.join("node_modules/is-number"));
        link_dir(&hosted, &store.join("node_modules/to-regex-range"));
        link_dir(&frame, &store.join("node_modules/@babel/code-frame"));
        link_dir(&odd_entry.join("is-odd"), &nm.join("is-odd"));
        // Every entry is linked from somewhere, as Bun writes it (an
        // unlinked one is an orphan, #599); the peer twin from a workspace
        // member's importer.
        std::fs::write(
            root.join("package.json"),
            r#"{"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        let member_nm = root.join("packages/a/node_modules");
        std::fs::create_dir_all(&member_nm).unwrap();
        link_dir(&number_twin, &member_nm.join("is-number"));

        assert_store_copies_found(
            &root,
            &[
                "pkg:npm/@babel/code-frame@7.0.0",
                "pkg:npm/is-number@6.0.0",
                "pkg:npm/is-odd@3.0.1",
                "pkg:npm/to-regex-range@5.0.1",
            ],
            &[
                (
                    "pkg:npm/is-number@6.0.0",
                    vec![number.clone(), number_twin.clone()],
                ),
                ("pkg:npm/@babel/code-frame@7.0.0", vec![frame.clone()]),
                ("pkg:npm/to-regex-range@5.0.1", vec![hosted.clone()]),
                ("pkg:npm/is-odd@3.0.1", vec![nm.join("is-odd")]),
            ],
            &number,
            vec![number_twin.clone()],
        )
        .await;
    }

    /// #635: with Bun's global store (`[install] globalStore`, Bun >=
    /// 1.3.14) every `.bun/<entry>` is a link to
    /// `<cache>/links/<entry>-<hash>`, shared across projects. The project's
    /// transitive packages live only there, so the walks follow those links
    /// (reporting each copy under `.bun`, where apply then refuses it as
    /// shared), and still skip a `.bun` link to anything else.
    #[tokio::test]
    async fn test_bun_global_store_transitive_packages_are_found() {
        let dir = tempfile::tempdir().unwrap();
        let tmp: PathBuf = dir.path().components().collect();
        let root = tmp.join("proj");
        let nm = root.join("node_modules");
        let store = nm.join(".bun");
        std::fs::create_dir_all(&store).unwrap();
        let links = tmp.join("bun-cache").join("links");
        let link_entry = |entry: &str, name: &str, version: &str| {
            let shared = links.join(format!("{entry}-6a490709ba3c5c8f"));
            write_pkg(&shared.join("node_modules").join(name), name, version);
            link_dir(&shared, &store.join(entry));
            store.join(entry).join("node_modules").join(name)
        };

        let odd = link_entry("is-odd@3.0.1", "is-odd", "3.0.1");
        let number = link_entry("is-number@6.0.0", "is-number", "6.0.0");
        let number_twin = link_entry("is-number@6.0.0+3c4e1d2a", "is-number", "6.0.0");
        let frame = link_entry("@babel+code-frame@7.0.0", "@babel/code-frame", "7.0.0");
        link_dir(&number, &odd.parent().unwrap().join("is-number"));
        link_dir(&odd, &nm.join("is-odd"));
        // Bun's hoist dir links every package (#599: an entry nothing
        // links is an orphan).
        let hoist_scope = store.join("node_modules/@babel");
        std::fs::create_dir_all(&hoist_scope).unwrap();
        link_dir(&frame, &hoist_scope.join("code-frame"));
        // A `.bun` link that is not into a global store entry.
        let elsewhere = tmp.join("elsewhere");
        write_pkg(
            &elsewhere.join("node_modules/left-pad"),
            "left-pad",
            "1.3.0",
        );
        link_dir(&elsewhere, &store.join("left-pad@1.3.0"));

        assert_store_copies_found(
            &root,
            &[
                "pkg:npm/@babel/code-frame@7.0.0",
                "pkg:npm/is-number@6.0.0",
                "pkg:npm/is-odd@3.0.1",
            ],
            &[
                (
                    "pkg:npm/is-number@6.0.0",
                    vec![number.clone(), number_twin.clone()],
                ),
                ("pkg:npm/@babel/code-frame@7.0.0", vec![frame.clone()]),
                ("pkg:npm/is-odd@3.0.1", vec![nm.join("is-odd")]),
                ("pkg:npm/left-pad@1.3.0", vec![]),
            ],
            &number,
            vec![number_twin.clone()],
        )
        .await;
    }

    /// A link at `link` to `target`, relative where the platform allows
    /// (Bun writes its `node_modules` links relative); a junction to the
    /// resolved target on Windows.
    fn rel_link(target: &str, link: &Path) {
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        link_dir(
            &crate::utils::relpath::normalize_lexically_keeping_escapes(
                &link.parent().unwrap().join(target),
            ),
            link,
        );
    }

    /// #599 with #635: Bun's global store (`globalStore = true`) never
    /// prunes `.bun` either. The layout real Bun 1.3.14 and 1.4.2 write
    /// after member `a` goes from `{is-odd 3.0.1, left-pad 1.3.0}` to
    /// `{is-odd 3.0.1, is-number 7.0.0, left-pad 1.2.0}` with an in-place
    /// `bun install`: every `.bun` entry is an absolute link into
    /// `<cache>/links/<entry>-<hash>`, the member and hoist links are
    /// relative into `.bun`, and is-odd's cache entry links is-number
    /// 6.0.0 at its sibling cache dir, never back into `.bun`. The hoist
    /// names is-number 7.0.0, so 6.0.0 is reached only through the cache;
    /// the `left-pad@1.3.0` link is left behind with nothing reaching it.
    /// The walk follows the cache links: the transitive 6.0.0 stays live,
    /// and the orphan is dropped by the scan and the live-copy filter.
    #[tokio::test]
    async fn test_bun_global_store_orphaned_entries_are_not_live_copies() {
        let dir = tempfile::tempdir().unwrap();
        let tmp: PathBuf = dir.path().components().collect();
        let root = tmp.join("proj");
        let nm = root.join("node_modules");
        let store = nm.join(".bun");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"root","version":"1.0.0","private":true,"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        let links = tmp.join("bun-cache").join("links");
        let link_entry = |entry: &str, hash: &str, name: &str, version: &str| {
            let shared = links.join(format!("{entry}-{hash}"));
            write_pkg(&shared.join("node_modules").join(name), name, version);
            link_dir(&shared, &store.join(entry));
            store.join(entry).join("node_modules").join(name)
        };
        let odd = link_entry("is-odd@3.0.1", "630ebdaa4b425d00", "is-odd", "3.0.1");
        let number6 = link_entry("is-number@6.0.0", "fe514fa0667977a7", "is-number", "6.0.0");
        let number7 = link_entry("is-number@7.0.0", "d7644ee3a163df00", "is-number", "7.0.0");
        let pad12 = link_entry("left-pad@1.2.0", "4791bc564980741c", "left-pad", "1.2.0");
        let pad13 = link_entry("left-pad@1.3.0", "6a490709ba3c5c8f", "left-pad", "1.3.0");
        rel_link(
            "../../is-number@6.0.0-fe514fa0667977a7/node_modules/is-number",
            &links.join("is-odd@3.0.1-630ebdaa4b425d00/node_modules/is-number"),
        );
        let member = root.join("packages/a");
        write_pkg(&member, "a", "1.0.0");
        for (name, entry) in [
            ("is-odd", "is-odd@3.0.1"),
            ("is-number", "is-number@7.0.0"),
            ("left-pad", "left-pad@1.2.0"),
        ] {
            rel_link(
                &format!("../{entry}/node_modules/{name}"),
                &store.join("node_modules").join(name),
            );
            rel_link(
                &format!("../../../node_modules/.bun/{entry}/node_modules/{name}"),
                &member.join("node_modules").join(name),
            );
        }

        let candidates = pnpm_shaped_store_candidates_sync(&store, StoreLayout::Bun);
        assert_eq!(candidates.len(), 5);
        let live = live_bun_store_entries_sync(&store, &candidates).unwrap();
        let mut live: Vec<String> = live
            .into_names(&candidates)
            .into_iter()
            .map(|e| e.into_string().unwrap())
            .collect();
        live.sort();
        assert_eq!(
            live,
            [
                "is-number@6.0.0",
                "is-number@7.0.0",
                "is-odd@3.0.1",
                "left-pad@1.2.0"
            ]
        );
        let scanned = scan_paths(&root).await;
        let purls: Vec<&str> = scanned.iter().map(|(p, _)| p.as_str()).collect();
        for purl in [
            "pkg:npm/is-number@6.0.0",
            "pkg:npm/is-number@7.0.0",
            "pkg:npm/is-odd@3.0.1",
            "pkg:npm/left-pad@1.2.0",
        ] {
            assert!(purls.contains(&purl), "{purl}: {scanned:?}");
        }
        assert!(!purls.contains(&"pkg:npm/left-pad@1.3.0"), "{scanned:?}");

        // vex's filter judges a copy by the `.bun` entry its path names.
        let mut copies = vec![
            number6.clone(),
            number7.clone(),
            pad13,
            pad12.clone(),
            odd.clone(),
        ];
        retain_live_store_copies([&mut copies]).await;
        assert_eq!(copies, vec![number6, number7, pad12, odd]);
    }

    /// #599 with #635: a cache entry linking a dependency at a global store
    /// entry this project's `.bun` does not link cannot be followed (what
    /// it reaches is unknown), so nothing is dropped.
    #[tokio::test]
    async fn test_bun_global_store_unknown_cache_entry_keeps_every_entry() {
        let dir = tempfile::tempdir().unwrap();
        let tmp: PathBuf = dir.path().components().collect();
        let root = tmp.join("proj");
        let nm = root.join("node_modules");
        let store = nm.join(".bun");
        std::fs::create_dir_all(&store).unwrap();
        let links = tmp.join("bun-cache").join("links");
        for (entry, hash, name) in [
            ("is-odd@3.0.1", "630ebdaa4b425d00", "is-odd"),
            ("is-number@6.0.0", "fe514fa0667977a7", "is-number"),
        ] {
            let shared = links.join(format!("{entry}-{hash}"));
            write_pkg(&shared.join("node_modules").join(name), name, "1.0.0");
            link_dir(&shared, &store.join(entry));
        }
        let foreign = links.join("x@1.0.0-0123456789abcdef/node_modules/x");
        write_pkg(&foreign, "x", "1.0.0");
        rel_link(
            "../../x@1.0.0-0123456789abcdef/node_modules/x",
            &links.join("is-odd@3.0.1-630ebdaa4b425d00/node_modules/x"),
        );
        rel_link(".bun/is-odd@3.0.1/node_modules/is-odd", &nm.join("is-odd"));

        let candidates = pnpm_shaped_store_candidates_sync(&store, StoreLayout::Bun);
        assert_eq!(candidates.len(), 2);
        assert!(live_bun_store_entries_sync(&store, &candidates).is_none());
    }

    /// #1197: pnpm 7–11 keep a removed (or upgraded-away) package's
    /// `.pnpm/<name>@<version>` entry for days, and pnpm 12 keeps an
    /// upgraded-away one until `pnpm prune`. The current lockfile pnpm
    /// writes beside the entries (`.pnpm/lock.yaml`) no longer lists it, so
    /// the scan skips it; a vendored entry it lists by its `version:` stays,
    /// as does every entry when there is no current lockfile. Restoring
    /// operations still reach the orphan.
    #[tokio::test]
    async fn test_pnpm_store_entries_the_current_lockfile_drops_are_not_scanned() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let store = nm.join(".pnpm");
        std::fs::write(root.join("package.json"), r#"{"name":"app"}"#).unwrap();
        let number = store.join("is-number@7.0.0/node_modules/is-number");
        write_pkg(&number, "is-number", "7.0.0");
        link_dir(&number, &nm.join("is-number"));
        let vendored =
            store.join("@s+lp@file+.socket+vendor+npm+u+s-lp-1.0.0.tgz/node_modules/@s/lp");
        write_pkg(&vendored, "@s/lp", "1.0.0");
        std::fs::create_dir_all(nm.join("@s")).unwrap();
        link_dir(&vendored, &nm.join("@s/lp"));
        // Orphans: a removed package, an upgraded-away version and a
        // vendored entry of the old version.
        let removed = store.join("left-pad@1.3.0/node_modules/left-pad");
        write_pkg(&removed, "left-pad", "1.3.0");
        let old = store.join("@s+lp@0.9.0/node_modules/@s/lp");
        write_pkg(&old, "@s/lp", "0.9.0");
        let old_vendored = store.join("ms@file+.socket+vendor+npm+v+ms-2.1.3.tgz/node_modules/ms");
        write_pkg(&old_vendored, "ms", "2.1.3");
        let ms = store.join("ms@2.1.2/node_modules/ms");
        write_pkg(&ms, "ms", "2.1.2");
        link_dir(&ms, &nm.join("ms"));

        let unfiltered = scan_paths(&root).await;
        for orphan in [&removed, &old, &old_vendored] {
            assert!(
                unfiltered.iter().any(|(_, path)| path == orphan),
                "no current lockfile, nothing dropped: {unfiltered:?}"
            );
        }

        std::fs::write(
            store.join("lock.yaml"),
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      \
             is-number:\n        specifier: 7.0.0\n        version: 7.0.0\n\npackages:\n\n  \
             '@s/lp@file:.socket/vendor/npm/u/s-lp-1.0.0.tgz':\n    resolution: {integrity: \
             sha512-x, tarball: file:.socket/vendor/npm/u/s-lp-1.0.0.tgz}\n    version: 1.0.0\n\n  \
             is-number@7.0.0:\n    resolution: {integrity: sha512-y}\n\n  \
             ms@2.1.2:\n    resolution: {integrity: sha512-z}\n\nsnapshots:\n\n  \
             '@s/lp@file:.socket/vendor/npm/u/s-lp-1.0.0.tgz': {}\n\n  is-number@7.0.0: {}\n\n  \
             ms@2.1.2: {}\n",
        )
        .unwrap();
        let scanned = scan_paths(&root).await;
        assert_eq!(
            scanned,
            vec![
                ("pkg:npm/@s/lp@1.0.0".to_string(), nm.join("@s/lp")),
                ("pkg:npm/is-number@7.0.0".to_string(), nm.join("is-number")),
                ("pkg:npm/ms@2.1.2".to_string(), nm.join("ms")),
            ]
        );

        // The pnpm 7 (v5.4) and pnpm 8 (v6.0) key grammars read the same.
        for packages in [
            "packages:\n\n  /is-number/7.0.0:\n    resolution: {integrity: sha512-y}\n\n  \
             /ms/2.1.2:\n    resolution: {integrity: sha512-z}\n\n  \
             file:.socket/vendor/npm/u/s-lp-1.0.0.tgz:\n    resolution: {integrity: sha512-x}\n    \
             name: '@s/lp'\n    version: 1.0.0\n",
            "packages:\n\n  /is-number@7.0.0:\n    resolution: {integrity: sha512-y}\n\n  \
             /ms@2.1.2:\n    resolution: {integrity: sha512-z}\n\n  \
             file:.socket/vendor/npm/u/s-lp-1.0.0.tgz:\n    resolution: {integrity: sha512-x}\n    \
             name: '@s/lp'\n    version: 1.0.0\n",
        ] {
            std::fs::write(
                store.join("lock.yaml"),
                format!("lockfileVersion: '6.0'\n\n{packages}"),
            )
            .unwrap();
            assert_eq!(scan_paths(&root).await, scanned, "{packages}");
        }

        // Restoring operations still reach the orphan.
        let purls = vec!["pkg:npm/left-pad@1.3.0".to_string()];
        let found = NpmCrawler::new().find_by_purls(&nm, &purls).await.unwrap();
        assert_eq!(
            found
                .get("pkg:npm/left-pad@1.3.0")
                .map(|copies| copies.iter().map(|p| p.path.clone()).collect::<Vec<_>>()),
            Some(vec![removed.clone()])
        );
    }

    /// #599: Bun never prunes `.bun`. After an in-place `bun install` that
    /// rewires packages to hosted tarballs (or bumps a version), the old
    /// `<name>@<version>` entries stay on disk with nothing linking to
    /// them, while the importers, the `.bun/node_modules` hoist links and
    /// the dependents' entries all point at the new entries (the layout
    /// real Bun 1.3.14 / 1.4.2 writes). An orphan is no installed copy, so
    /// the scan and the live-copy filter `vex` uses skip it. The resolver
    /// and the peer-variant finder keep it: rollback must restore a patched
    /// orphan, which a later install that resolves back re-links as is.
    ///
    /// A live entry linked only from a workspace member (an unhoisted
    /// second version) stays live wherever the member sits: under a dir
    /// the workspace walk skips (`vendor/`), under a hidden dir listed only
    /// by `bun.lock`'s `workspaces`, or under `packages/`.
    #[tokio::test]
    async fn test_bun_isolated_store_orphaned_entries_are_not_live_copies() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let store = nm.join(".bun");
        let hoist = store.join("node_modules");
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"app","workspaces":["packages/*","vendor/*"]}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("bun.lock"),
            "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \
             \"name\": \"app\",\n    },\n    \".internal/c\": {\n      \"name\": \"c\",\n    \
             },\n  },\n  \"packages\": {\n  }\n}\n",
        )
        .unwrap();
        let member_a = root.join("packages/a/node_modules");
        let member_b = root.join("vendor/b/node_modules");
        let member_c = root.join(".internal/c/node_modules");
        for dir in [&hoist.join("@s"), &member_a, &member_b, &member_c] {
            std::fs::create_dir_all(dir).unwrap();
        }

        // Live: the hosted rewires, and three left-pad versions (1.3.0
        // hoisted, 1.2.0 and 1.0.0 each linked only from one member).
        let odd = store.join("is-odd@http+++127.0.0.1+is-odd.tgz/node_modules");
        write_pkg(&odd.join("is-odd"), "is-odd", "3.0.1");
        let number = store.join("is-number@http+++127.0.0.1+is-number.tgz/node_modules/is-number");
        write_pkg(&number, "is-number", "6.0.0");
        link_dir(&number, &odd.join("is-number"));
        let pad = store.join("left-pad@1.3.0/node_modules/left-pad");
        write_pkg(&pad, "left-pad", "1.3.0");
        let vendor_pad = store.join("left-pad@1.2.0/node_modules/left-pad");
        write_pkg(&vendor_pad, "left-pad", "1.2.0");
        let hidden_pad = store.join("left-pad@1.0.0/node_modules/left-pad");
        write_pkg(&hidden_pad, "left-pad", "1.0.0");
        link_dir(&odd.join("is-odd"), &nm.join("is-odd"));
        link_dir(&odd.join("is-odd"), &hoist.join("is-odd"));
        link_dir(&number, &hoist.join("is-number"));
        link_dir(&pad, &hoist.join("left-pad"));
        link_dir(&number, &member_a.join("is-number"));
        link_dir(&pad, &member_a.join("left-pad"));
        link_dir(&vendor_pad, &member_b.join("left-pad"));
        link_dir(&hidden_pad, &member_c.join("left-pad"));
        let frame = store.join("@s+frame@http+++127.0.0.1+frame.tgz/node_modules/@s/frame");
        write_pkg(&frame, "@s/frame", "7.0.0");
        link_dir(&frame, &hoist.join("@s/frame"));

        // Orphans: the pre-rewire registry entries (still linked to each
        // other) and a churned-away version.
        let stale_odd = store.join("is-odd@3.0.1/node_modules");
        write_pkg(&stale_odd.join("is-odd"), "is-odd", "3.0.1");
        let stale_number = store.join("is-number@6.0.0/node_modules/is-number");
        write_pkg(&stale_number, "is-number", "6.0.0");
        link_dir(&stale_number, &stale_odd.join("is-number"));
        let stale_frame = store.join("@s+frame@7.0.0/node_modules/@s/frame");
        write_pkg(&stale_frame, "@s/frame", "7.0.0");
        let churned = store.join("left-pad@1.1.0/node_modules/left-pad");
        write_pkg(&churned, "left-pad", "1.1.0");

        let scanned = scan_paths(&root).await;
        for (purl, path) in &scanned {
            assert!(
                !path.starts_with(&stale_odd)
                    && !path.starts_with(stale_number.parent().unwrap())
                    && !path.starts_with(&stale_frame)
                    && purl != "pkg:npm/left-pad@1.1.0",
                "an orphaned entry was scanned: {scanned:?}"
            );
        }
        for (purl, path) in [
            ("pkg:npm/left-pad@1.2.0", &vendor_pad),
            ("pkg:npm/left-pad@1.0.0", &hidden_pad),
        ] {
            assert!(
                scanned.contains(&(purl.to_string(), path.clone())),
                "{purl}: {scanned:?}"
            );
        }

        // Restoring operations still reach the orphans.
        let purls: Vec<String> = ["pkg:npm/is-number@6.0.0", "pkg:npm/left-pad@1.1.0"]
            .map(String::from)
            .to_vec();
        let found = NpmCrawler::new().find_by_purls(&nm, &purls).await.unwrap();
        let paths = |purl: &str| -> Vec<PathBuf> {
            found
                .get(purl)
                .map(|copies| copies.iter().map(|p| p.path.clone()).collect())
                .unwrap_or_default()
        };
        assert!(
            paths("pkg:npm/is-number@6.0.0").contains(&stale_number),
            "{found:?}"
        );
        assert_eq!(paths("pkg:npm/left-pad@1.1.0"), vec![churned.clone()]);
        assert_eq!(
            find_store_peer_variant_copies(&number).await,
            vec![stale_number.clone()]
        );

        // The live-copy filter drops exactly the orphans.
        let mut copies = vec![
            number.clone(),
            stale_number.clone(),
            churned.clone(),
            vendor_pad.clone(),
            hidden_pad.clone(),
            stale_frame.clone(),
            frame.clone(),
            nm.join("is-odd"),
            stale_odd.join("is-odd"),
        ];
        let mut other = vec![pad.clone(), churned.clone()];
        retain_live_store_copies([&mut copies, &mut other]).await;
        assert_eq!(
            copies,
            vec![
                number.clone(),
                vendor_pad.clone(),
                hidden_pad.clone(),
                frame.clone(),
                nm.join("is-odd"),
            ]
        );
        assert_eq!(other, vec![pad.clone()]);
    }

    /// #599: when the workspace members cannot be known (a root
    /// `package.json` that does not parse), an entry no other seed reaches
    /// may be a member's, so nothing is dropped.
    #[tokio::test]
    async fn test_bun_isolated_store_unknown_members_keep_every_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let store = nm.join(".bun");
        std::fs::create_dir_all(store.join("node_modules")).unwrap();
        std::fs::write(root.join("package.json"), "{ not json").unwrap();
        let pad = store.join("left-pad@1.3.0/node_modules/left-pad");
        write_pkg(&pad, "left-pad", "1.3.0");
        let member_pad = store.join("left-pad@1.2.0/node_modules/left-pad");
        write_pkg(&member_pad, "left-pad", "1.2.0");
        link_dir(&pad, &store.join("node_modules/left-pad"));
        let member_nm = root.join("weird/place/node_modules");
        std::fs::create_dir_all(&member_nm).unwrap();
        link_dir(&member_pad, &member_nm.join("left-pad"));

        let scanned = scan_paths(&root).await;
        assert!(
            scanned.contains(&("pkg:npm/left-pad@1.2.0".to_string(), member_pad.clone())),
            "{scanned:?}"
        );
        let mut copies = vec![pad.clone(), member_pad.clone()];
        retain_live_store_copies([&mut copies]).await;
        assert_eq!(copies, vec![pad, member_pad]);
    }

    /// #599: a root `package.json` that does not parse leaves the
    /// `bun.lock` `workspaces` section, which Bun rewrites on every
    /// install, as the member set: an entry linked only from a member it
    /// lists stays live, and an orphan is still dropped.
    #[tokio::test]
    async fn test_bun_isolated_store_lock_members_stand_in_for_package_json() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let store = nm.join(".bun");
        std::fs::create_dir_all(store.join("node_modules")).unwrap();
        std::fs::write(root.join("package.json"), "{ not json").unwrap();
        std::fs::write(
            root.join("bun.lock"),
            "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \
             \"name\": \"app\",\n    },\n    \"weird/place\": {\n      \"name\": \"w\",\n    \
             },\n  },\n  \"packages\": {\n  }\n}\n",
        )
        .unwrap();
        let pad = store.join("left-pad@1.3.0/node_modules/left-pad");
        write_pkg(&pad, "left-pad", "1.3.0");
        let member_pad = store.join("left-pad@1.2.0/node_modules/left-pad");
        write_pkg(&member_pad, "left-pad", "1.2.0");
        let churned = store.join("left-pad@1.1.0/node_modules/left-pad");
        write_pkg(&churned, "left-pad", "1.1.0");
        link_dir(&pad, &store.join("node_modules/left-pad"));
        let member_nm = root.join("weird/place/node_modules");
        std::fs::create_dir_all(&member_nm).unwrap();
        link_dir(&member_pad, &member_nm.join("left-pad"));

        let mut copies = vec![pad.clone(), member_pad.clone(), churned];
        retain_live_store_copies([&mut copies]).await;
        assert_eq!(copies, vec![pad, member_pad]);
    }

    /// #599: the orphan filter's quick walk takes a link named for a
    /// package only one entry holds to be that entry. An alias link
    /// (`node_modules/lp` -> `left-pad@1.3.0`) beside an unrelated `lp@…`
    /// entry defeats the guess, so the entry it really reaches must still
    /// count as live (by the exact re-walk) and the never-linked `lp@`
    /// not.
    #[tokio::test]
    async fn test_bun_isolated_store_alias_link_is_resolved_exactly() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let store = nm.join(".bun");
        let pad = store.join("left-pad@1.3.0/node_modules/left-pad");
        write_pkg(&pad, "left-pad", "1.3.0");
        let lp = store.join("lp@2.0.0/node_modules/lp");
        write_pkg(&lp, "lp", "2.0.0");
        std::fs::create_dir_all(store.join("node_modules")).unwrap();
        link_dir(&pad, &nm.join("lp"));

        let scanned = scan_paths(&root).await;
        assert!(
            scanned.iter().all(|(purl, _)| purl != "pkg:npm/lp@2.0.0"),
            "{scanned:?}"
        );
        assert!(
            scanned
                .iter()
                .any(|(purl, _)| purl == "pkg:npm/left-pad@1.3.0"),
            "{scanned:?}"
        );
        let mut copies = vec![pad.clone(), lp];
        retain_live_store_copies([&mut copies]).await;
        assert_eq!(copies, vec![pad]);
    }

    #[test]
    fn test_expand_workspace_pattern() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for dir in [
            "packages/a",
            "packages/b",
            ".github/actions/x",
            "apps/web/sub",
            "apps/node_modules/skip",
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("packages/file"), "").unwrap();
        let expand = |pattern: &str| {
            let mut got: Vec<PathBuf> = expand_workspace_pattern_sync(root, pattern)
                .unwrap()
                .into_iter()
                .map(|p| p.strip_prefix(root).unwrap().to_path_buf())
                .collect();
            got.sort();
            got
        };
        assert_eq!(
            expand("packages/*"),
            ["packages/a", "packages/b"].map(PathBuf::from)
        );
        assert_eq!(expand("./packages/a"), [PathBuf::from("packages/a")]);
        assert_eq!(expand(".github/*/*"), [PathBuf::from(".github/actions/x")]);
        assert_eq!(
            expand("apps/**"),
            ["apps", "apps/web", "apps/web/sub"].map(PathBuf::from)
        );
    }

    #[test]
    fn test_bun_store_entry_package() {
        for (entry, want) in [
            ("is-number@6.0.0", Some("is-number")),
            ("is-number@http+++127.0.0.1+t.tgz", Some("is-number")),
            ("@babel+code-frame@7.0.0", Some("@babel/code-frame")),
            (
                "@babel+code-frame@7.0.0+3c4e1d2a",
                Some("@babel/code-frame"),
            ),
            ("no-version", None),
            ("@scope+only", None),
            ("@1.0.0", None),
        ] {
            assert_eq!(bun_store_entry_package(entry).as_deref(), want, "{entry}");
        }
    }

    /// #373: Deno's isolated `nodeModulesDir` keeps every npm package in
    /// `node_modules/.deno/<name>@<version>[_<peers>]/node_modules/<name>`
    /// (scoped `@scope+leaf@…`), beside `.deno/.deno.lock` and the
    /// `.deno/node_modules` hoist dir of links.
    #[tokio::test]
    async fn test_deno_node_modules_store_transitive_packages_are_found() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let store = nm.join(".deno");

        let odd_entry = store.join("is-odd@3.0.1/node_modules");
        write_pkg(&odd_entry.join("is-odd"), "is-odd", "3.0.1");
        let number = store.join("is-number@6.0.0/node_modules/is-number");
        write_pkg(&number, "is-number", "6.0.0");
        let number_twin = store.join("is-number@6.0.0_react@18.2.0/node_modules/is-number");
        write_pkg(&number_twin, "is-number", "6.0.0");
        link_dir(&number, &odd_entry.join("is-number"));
        let frame = store.join("@babel+code-frame@7.0.0/node_modules/@babel/code-frame");
        write_pkg(&frame, "@babel/code-frame", "7.0.0");
        std::fs::write(store.join(".deno.lock"), "").unwrap();
        std::fs::create_dir_all(store.join("node_modules")).unwrap();
        link_dir(&number, &store.join("node_modules/is-number"));
        link_dir(&odd_entry.join("is-odd"), &nm.join("is-odd"));

        assert_store_copies_found(
            &root,
            &[
                "pkg:npm/@babel/code-frame@7.0.0",
                "pkg:npm/is-number@6.0.0",
                "pkg:npm/is-odd@3.0.1",
            ],
            &[
                (
                    "pkg:npm/is-number@6.0.0",
                    vec![number.clone(), number_twin.clone()],
                ),
                ("pkg:npm/@babel/code-frame@7.0.0", vec![frame.clone()]),
            ],
            &number,
            vec![number_twin.clone()],
        )
        .await;
    }

    /// A store-entry self-link the way Yarn 4 writes it: relative
    /// (`../package`) on Unix, a junction on Windows.
    fn link_own_package(entry: &Path, dir_key: &str) {
        let link = entry.join("node_modules").join(dir_key);
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        #[cfg(unix)]
        {
            let up = "../".repeat(dir_key.split('/').count());
            std::os::unix::fs::symlink(format!("{up}package"), &link).unwrap();
        }
        #[cfg(windows)]
        link_dir(&entry.join("package"), &link);
    }

    /// #495: Yarn 4's pnpm linker reuses npm's `.store` name, but the only
    /// physical copy is `.store/<slug>-npm-<version>-<hash>/package`; the
    /// entry's `node_modules/<name>` is a link to that sibling `package`
    /// dir, and its other `node_modules` links are edges into other
    /// entries. The copy is found at its `package` path, never twice.
    #[tokio::test]
    async fn test_yarn4_pnpm_linker_store_transitive_packages_are_found() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let store = nm.join(".store");

        let odd_entry = store.join("is-odd-npm-3.0.1-3e1a2b4c5d");
        write_pkg(&odd_entry.join("package"), "is-odd", "3.0.1");
        link_own_package(&odd_entry, "is-odd");
        let number_entry = store.join("is-number-npm-6.0.0-9f8e7d6c5b");
        let number = number_entry.join("package");
        write_pkg(&number, "is-number", "6.0.0");
        link_own_package(&number_entry, "is-number");
        let twin_entry = store.join("is-number-npm-6.0.0-0a1b2c3d4e");
        let number_twin = twin_entry.join("package");
        write_pkg(&number_twin, "is-number", "6.0.0");
        link_own_package(&twin_entry, "is-number");
        link_dir(&number, &odd_entry.join("node_modules/is-number"));
        let frame_entry = store.join("@babel-code-frame-npm-7.0.0-1234567890");
        let frame = frame_entry.join("package");
        write_pkg(&frame, "@babel/code-frame", "7.0.0");
        link_own_package(&frame_entry, "@babel/code-frame");
        link_dir(&odd_entry.join("package"), &nm.join("is-odd"));

        assert_store_copies_found(
            &root,
            &[
                "pkg:npm/@babel/code-frame@7.0.0",
                "pkg:npm/is-number@6.0.0",
                "pkg:npm/is-odd@3.0.1",
            ],
            &[
                (
                    "pkg:npm/is-number@6.0.0",
                    vec![number.clone(), number_twin.clone()],
                ),
                ("pkg:npm/@babel/code-frame@7.0.0", vec![frame.clone()]),
                ("pkg:npm/is-odd@3.0.1", vec![nm.join("is-odd")]),
            ],
            &number,
            vec![number_twin.clone()],
        )
        .await;
        // The fan-out from the importer link reaches the same store.
        assert_eq!(
            find_store_peer_variant_copies(&nm.join("is-odd")).await,
            Vec::<PathBuf>::new()
        );
    }

    /// #496 review: a Yarn 4 store entry's `package` dir carries the
    /// package's bundled dependencies in `package/node_modules`, which Node
    /// loads in preference to the regular store copy. The entry reaches
    /// that tree only through its `node_modules/<name> -> ../package`
    /// link, so the resolver must enqueue it like the scan does, or apply
    /// patches the regular copy and leaves the loaded one untouched.
    #[tokio::test]
    async fn test_yarn4_pnpm_linker_bundled_copy_inside_store_package_is_resolved() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let store = nm.join(".store");

        let number_entry = store.join("is-number-npm-7.0.0-9f8e7d6c5b");
        let number = number_entry.join("package");
        write_pkg(&number, "is-number", "7.0.0");
        link_own_package(&number_entry, "is-number");
        let parent_entry = store.join("parent-file-1.0.0-1234567890");
        let parent = parent_entry.join("package");
        write_pkg(&parent, "parent", "1.0.0");
        link_own_package(&parent_entry, "parent");
        let bundled = parent.join("node_modules/is-number");
        write_pkg(&bundled, "is-number", "7.0.0");
        let scoped_entry = store.join("@acme-tool-file-2.0.0-abcdef0123");
        let scoped = scoped_entry.join("package");
        write_pkg(&scoped, "@acme/tool", "2.0.0");
        link_own_package(&scoped_entry, "@acme/tool");
        let scoped_bundled = scoped.join("node_modules/is-number");
        write_pkg(&scoped_bundled, "is-number", "7.0.0");
        link_dir(&parent, &nm.join("parent"));
        link_dir(&number, &nm.join("is-number"));

        let scanned = scan_paths(&root).await;
        let mut scan_purls: Vec<&str> = scanned.iter().map(|(p, _)| p.as_str()).collect();
        scan_purls.sort();
        assert_eq!(
            scan_purls,
            [
                "pkg:npm/@acme/tool@2.0.0",
                "pkg:npm/is-number@7.0.0",
                "pkg:npm/parent@1.0.0",
            ],
            "{scanned:?}"
        );

        let found = NpmCrawler::new()
            .find_by_purls(&nm, &["pkg:npm/is-number@7.0.0".to_string()])
            .await
            .unwrap();
        let mut got: Vec<PathBuf> = found["pkg:npm/is-number@7.0.0"]
            .iter()
            .map(|p| p.path.clone())
            .collect();
        got.sort();
        let mut want = vec![nm.join("is-number"), bundled, scoped_bundled];
        want.sort();
        assert_eq!(got, want);
    }

    /// A sibling `package` dir alone does not make an entry Yarn 4's: with
    /// no link from the entry's `node_modules` to it, its tree is not
    /// walked.
    #[tokio::test]
    async fn test_store_package_dir_without_own_link_is_not_walked() {
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        let nm = root.join("node_modules");
        let entry = nm.join(".store/parent-file-1.0.0-1234567890");
        write_pkg(&entry.join("node_modules/parent"), "parent", "1.0.0");
        write_pkg(
            &entry.join("package/node_modules/is-number"),
            "is-number",
            "7.0.0",
        );
        write_pkg(&entry.join("package"), "parent", "1.0.0");

        let found = NpmCrawler::new()
            .find_by_purls(&nm, &["pkg:npm/is-number@7.0.0".to_string()])
            .await
            .unwrap();
        assert!(
            found
                .get("pkg:npm/is-number@7.0.0")
                .is_none_or(|copies| copies.is_empty()),
            "{found:?}"
        );
    }

    /// The `.yarnrc` and Bun `package.json` workspace readers skip one
    /// leading BOM (`formats::text`); a second one is content.
    #[test]
    fn yarnrc_and_bun_workspaces_read_past_one_bom_only() {
        let rc = "--modules-folder deps\n";
        for bom in ["", "\u{feff}"] {
            assert_eq!(
                parse_yarnrc_modules_folder(&format!("{bom}{rc}"))
                    .general
                    .as_deref(),
                Some("deps")
            );
        }
        assert_eq!(
            parse_yarnrc_modules_folder(&format!("\u{feff}\u{feff}{rc}")),
            YarnrcModulesFolder::default()
        );

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("a")).unwrap();
        let manifest = r#"{"workspaces":["a"]}"#;
        for bom in ["", "\u{feff}"] {
            std::fs::write(dir.path().join("package.json"), format!("{bom}{manifest}")).unwrap();
            assert_eq!(
                bun_workspace_pattern_members_sync(dir.path()),
                Some(vec![dir.path().join("a")])
            );
        }
        std::fs::write(
            dir.path().join("package.json"),
            format!("\u{feff}\u{feff}{manifest}"),
        )
        .unwrap();
        assert_eq!(bun_workspace_pattern_members_sync(dir.path()), None);
    }

    /// `.yarnrc` `--modules-folder` parsing: bare and quoted keys and
    /// values, an optional `:`, the command-scoped form, comments, a BOM,
    /// CRLF, a Windows drive path, and last-setting-wins.
    #[test]
    fn test_parse_yarnrc_modules_folder() {
        let parse = |rc: &str| parse_yarnrc_modules_folder(rc).general;
        assert_eq!(parse("--modules-folder deps\n").as_deref(), Some("deps"));
        assert_eq!(
            parse("\"--modules-folder\" \"./my deps\"\n").as_deref(),
            Some("./my deps")
        );
        assert_eq!(parse("--modules-folder: lib\n").as_deref(), Some("lib"));
        // The command-scoped key is kept apart from the general one, in
        // either line order: yarn merges and applies them separately.
        for rc in [
            "--install.modules-folder specific\n--modules-folder general\n",
            "--modules-folder general\n--install.modules-folder specific\n",
        ] {
            assert_eq!(
                parse_yarnrc_modules_folder(rc),
                YarnrcModulesFolder {
                    general: Some("general".into()),
                    install: Some("specific".into()),
                },
                "{rc:?}"
            );
        }
        assert_eq!(
            parse_yarnrc_modules_folder("--install.modules-folder vendor_modules"),
            YarnrcModulesFolder {
                general: None,
                install: Some("vendor_modules".into()),
            }
        );
        // Other command scopes are not the install's.
        assert_eq!(
            parse_yarnrc_modules_folder("--add.modules-folder x\n"),
            YarnrcModulesFolder::default()
        );
        assert_eq!(
            parse("\u{feff}# comment\r\nyarn-offline-mirror \"./m\"\r\n--modules-folder deps\r\n")
                .as_deref(),
            Some("deps")
        );
        assert_eq!(
            parse("--modules-folder \"C:\\\\deps\"\n").as_deref(),
            Some("C:\\deps")
        );
        assert_eq!(
            parse("--modules-folder C:\\deps\n").as_deref(),
            Some("C:\\deps")
        );
        assert_eq!(
            parse("--modules-folder a\n--modules-folder b\n").as_deref(),
            Some("b")
        );
        // Not the key, a comment, or no value.
        for rc in [
            "",
            "# --modules-folder deps\n",
            "--modules-folder-x deps\n",
            "modules-folder deps\n",
            "--modules-folder\n",
            "--modules-folder \"unterminated\n",
        ] {
            assert_eq!(
                parse_yarnrc_modules_folder(rc),
                YarnrcModulesFolder::default(),
                "{rc:?}"
            );
        }
    }

    fn local_options(cwd: &Path) -> CrawlerOptions {
        CrawlerOptions {
            cwd: cwd.to_path_buf(),
            global: false,
            global_prefix: None,
        }
    }

    /// REGRESSION (#493): yarn classic's `.yarnrc` `--modules-folder deps`
    /// installs into `deps/`, which is a crawl root: its packages (and
    /// their nested `node_modules`) are inventoried at their real paths.
    /// The walk used to skip it, so agent mode reported them not installed
    /// and hosted `vex` read the unpatched copy as absent. A nested
    /// `deps/<pkg>/node_modules` is not reported as a workspace root.
    #[tokio::test]
    async fn test_yarnrc_modules_folder_is_a_crawl_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("package.json"), r#"{"name":"app"}"#).unwrap();
        write_pkg(&root.join("deps/left-pad"), "left-pad", "1.3.0");
        write_pkg(
            &root.join("deps/outer/node_modules/inner"),
            "inner",
            "2.0.0",
        );
        write_pkg(&root.join("deps/outer"), "outer", "1.0.0");

        let crawler = NpmCrawler::new();
        let options = local_options(root);
        let names = |pkgs: &[CrawledPackage]| {
            let mut v: Vec<String> = pkgs.iter().map(|p| p.purl.clone()).collect();
            v.sort();
            v
        };
        // Control: without the .yarnrc, deps/ is not an install root.
        assert!(!names(&crawler.crawl_all(&options).await)
            .contains(&"pkg:npm/left-pad@1.3.0".to_string()));

        std::fs::write(root.join(".yarnrc"), "--modules-folder deps\n").unwrap();
        let roots = crawler.get_node_modules_paths(&options).await.unwrap();
        assert_eq!(roots, vec![root.join("deps")]);
        let pkgs = crawler.crawl_all(&options).await;
        assert_eq!(
            names(&pkgs),
            vec![
                "pkg:npm/inner@2.0.0".to_string(),
                "pkg:npm/left-pad@1.3.0".to_string(),
                "pkg:npm/outer@1.0.0".to_string(),
            ]
        );
        let left_pad = pkgs.iter().find(|p| p.name == "left-pad").unwrap();
        assert_eq!(left_pad.path, root.join("deps/left-pad"));
        let found = crawler
            .find_by_purls(&root.join("deps"), &["pkg:npm/left-pad@1.3.0".to_string()])
            .await
            .unwrap();
        assert_eq!(found.len(), 1);

        // An ancestor's .yarnrc applies too (its value resolved against
        // its own directory); the nearest one wins.
        let member = root.join("packages/member");
        write_pkg(&member.join("lib/ms"), "ms", "2.1.3");
        std::fs::write(member.join("package.json"), r#"{"name":"member"}"#).unwrap();
        std::fs::write(
            root.join(".yarnrc"),
            "--modules-folder packages/member/lib\n",
        )
        .unwrap();
        let roots = crawler
            .get_node_modules_paths(&local_options(&member))
            .await
            .unwrap();
        assert_eq!(roots, vec![member.join("lib")]);
        std::fs::write(member.join(".yarnrc"), "--modules-folder deps\n").unwrap();
        let roots = crawler
            .get_node_modules_paths(&local_options(&member))
            .await
            .unwrap();
        assert!(roots.is_empty(), "member/deps does not exist: {roots:?}");
    }

    /// REGRESSION (#518): in a Rush repo pnpm installs into
    /// `common/temp/node_modules` (the walk prunes `temp`), so a
    /// TRANSITIVE dep lives only in its `.pnpm` store. It is a crawl root
    /// when `rush.json` is present, and only then.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_rush_common_temp_is_a_crawl_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let temp_nm = root.join("common/temp/node_modules");
        let store = temp_nm.join(".pnpm");
        let direct = store.join("to-regex-range@5.0.1/node_modules/to-regex-range");
        write_pkg(&direct, "to-regex-range", "5.0.1");
        write_pkg(
            &store.join("is-number@7.0.0/node_modules/is-number"),
            "is-number",
            "7.0.0",
        );
        std::os::unix::fs::symlink(
            store.join("is-number@7.0.0/node_modules/is-number"),
            store.join("to-regex-range@5.0.1/node_modules/is-number"),
        )
        .unwrap();
        let app_nm = root.join("apps/app/node_modules");
        std::fs::create_dir_all(&app_nm).unwrap();
        std::os::unix::fs::symlink(&direct, app_nm.join("to-regex-range")).unwrap();

        let crawler = NpmCrawler::new();
        let options = local_options(root);
        let has = |pkgs: &[CrawledPackage], purl: &str| pkgs.iter().any(|p| p.purl == purl);
        // Control: not a Rush repo, common/temp stays pruned.
        let pkgs = crawler.crawl_all(&options).await;
        assert!(has(&pkgs, "pkg:npm/to-regex-range@5.0.1"));
        assert!(!has(&pkgs, "pkg:npm/is-number@7.0.0"));

        std::fs::write(root.join("rush.json"), "{}").unwrap();
        let roots = crawler.get_node_modules_paths(&options).await.unwrap();
        assert_eq!(roots, vec![app_nm.clone(), temp_nm.clone()]);
        let pkgs = crawler.crawl_all(&options).await;
        assert!(has(&pkgs, "pkg:npm/to-regex-range@5.0.1"), "{pkgs:?}");
        let is_number: Vec<_> = pkgs.iter().filter(|p| p.name == "is-number").collect();
        assert_eq!(is_number.len(), 1, "{pkgs:?}");
        assert_eq!(
            std::fs::canonicalize(&is_number[0].path).unwrap(),
            std::fs::canonicalize(store.join("is-number@7.0.0/node_modules/is-number")).unwrap()
        );
        let found = crawler
            .find_by_purls(&temp_nm, &["pkg:npm/is-number@7.0.0".to_string()])
            .await
            .unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
    }

    /// The configured roots merge: a walked root inside one is dropped,
    /// one the walk already found is not repeated, and order is kept.
    #[test]
    fn test_merge_configured_install_roots() {
        let p = PathBuf::from;
        assert_eq!(
            merge_configured_install_roots(vec![p("/r/node_modules")], vec![]),
            vec![p("/r/node_modules")]
        );
        assert_eq!(
            merge_configured_install_roots(
                vec![
                    p("/r/node_modules"),
                    p("/r/deps/a/node_modules"),
                    p("/r/deps-x/node_modules"),
                    p("/r/lib/node_modules"),
                ],
                vec![p("/r/deps"), p("/r/lib/node_modules")],
            ),
            vec![
                p("/r/node_modules"),
                p("/r/deps-x/node_modules"),
                p("/r/lib/node_modules"),
                p("/r/deps"),
            ]
        );
    }

    /// `--modules-folder` names a patch WRITE target, so only a relative
    /// subpath of the project is honored (the composer `vendor-dir` rule):
    /// `.`/`..` resolve lexically, and an absolute, drive-qualified,
    /// escaping or empty value is refused.
    #[test]
    fn test_resolve_modules_folder() {
        let n = |raw: &str| resolve_modules_folder(&[], raw);
        assert_eq!(n("deps").as_deref(), Some("deps"));
        assert_eq!(n("./deps/").as_deref(), Some("deps"));
        assert_eq!(n("lib/./deps").as_deref(), Some("lib/deps"));
        assert_eq!(n("lib\\deps").as_deref(), Some("lib/deps"));
        assert_eq!(n("a/../deps").as_deref(), Some("deps"));
        for raw in [
            "/abs/deps",
            "\\abs",
            "..",
            "../outside",
            "a/../..",
            ".",
            "./",
            "",
            "C:\\deps",
            "C:deps",
        ] {
            assert_eq!(n(raw), None, "{raw:?}");
        }
        // Defined by an ancestor `.yarnrc`: resolved against that file's
        // directory, then kept only when strictly inside the project.
        let project = ["project".to_string()];
        let a = |raw: &str| resolve_modules_folder(&project, raw);
        assert_eq!(a("project/deps").as_deref(), Some("deps"));
        assert_eq!(a("./project/./lib\\deps").as_deref(), Some("lib/deps"));
        assert_eq!(a("x/../project/deps").as_deref(), Some("deps"));
        for raw in [
            "deps",
            "project",
            "project/..",
            "../project/deps",
            "projectx/deps",
            "..",
        ] {
            assert_eq!(a(raw), None, "{raw:?}");
        }
    }

    /// REVIEW (#520): a modules folder inherited from an ancestor
    /// `.yarnrc` resolves against that file's directory, as yarn 1.x does:
    /// `/repo/.yarnrc` `--modules-folder project/deps` installs
    /// `/repo/project` into `/repo/project/deps`, not
    /// `/repo/project/project/deps`. A value resolving outside the project
    /// (here the sibling `/repo/deps`) is still refused.
    #[tokio::test]
    async fn test_inherited_yarnrc_modules_folder_resolves_against_its_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        let project = repo.join("project");
        write_pkg(&project.join("deps/ms"), "ms", "2.1.3");
        write_pkg(&repo.join("deps/ms"), "ms", "2.1.3");
        let crawler = NpmCrawler::new();

        std::fs::write(repo.join(".yarnrc"), "--modules-folder project/deps\n").unwrap();
        let roots = crawler
            .get_node_modules_paths(&local_options(&project))
            .await
            .unwrap();
        assert_eq!(roots, vec![project.join("deps")]);

        std::fs::write(repo.join(".yarnrc"), "--modules-folder deps\n").unwrap();
        let roots = crawler
            .get_node_modules_paths(&local_options(&project))
            .await
            .unwrap();
        assert!(roots.is_empty(), "{roots:?}");
    }

    /// REGRESSION (#661, #696): pnpm's `modulesDir` (`modulesDir:` in
    /// `pnpm-workspace.yaml`, `modules-dir=` in `.npmrc` up to pnpm 10)
    /// renames `node_modules`, and from pnpm 10.12 the virtual store moves
    /// with it to `<modulesDir>/.pnpm`. The walk only collects dirs named
    /// `node_modules`, so agent mode read the install as absent and hosted
    /// `vex` attested the lock over it. The configured dir is a crawl root,
    /// as is a project child holding pnpm's `.modules.yaml` (a value from
    /// pnpm's global config or the environment).
    #[tokio::test]
    async fn test_pnpm_modules_dir_is_a_crawl_root() {
        let configs = [
            ("pnpm-workspace.yaml", "modulesDir: deps\n"),
            (
                "pnpm-workspace.yaml",
                "packages:\n  - packages/*\n'modulesDir' : \"./deps\" # moved\n",
            ),
            (".npmrc", "modules-dir=deps\n"),
            ("deps/.modules.yaml", "{\"virtualStoreDir\": \".pnpm\"}"),
        ];
        for (file, text) in configs {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            std::fs::write(root.join("package.json"), r#"{"name":"app"}"#).unwrap();
            let store_copy = root.join("deps/.pnpm/left-pad@1.3.0/node_modules/left-pad");
            write_pkg(&store_copy, "left-pad", "1.3.0");
            let crawler = NpmCrawler::new();
            let options = local_options(root);
            let has_left_pad = |pkgs: &[CrawledPackage]| {
                pkgs.iter()
                    .any(|p| p.purl == "pkg:npm/left-pad@1.3.0" && p.path == store_copy)
            };
            // Control: unconfigured, deps/ is not an install root.
            assert!(!has_left_pad(&crawler.crawl_all(&options).await), "{file}");

            std::fs::write(root.join(file), text).unwrap();
            let roots = crawler.get_node_modules_paths(&options).await.unwrap();
            assert_eq!(roots, vec![root.join("deps")], "{file}: {text}");
            assert!(has_left_pad(&crawler.crawl_all(&options).await), "{file}");
            let found = crawler
                .find_by_purls(&root.join("deps"), &["pkg:npm/left-pad@1.3.0".to_string()])
                .await
                .unwrap();
            assert_eq!(found.len(), 1, "{file}: {found:?}");
        }
    }

    /// The `modulesDir` setting is read from the nearest
    /// `pnpm-workspace.yaml` (pnpm resolves it against each project, so a
    /// workspace member installs into its own `deps/`), wins over `.npmrc`,
    /// and fails closed when it leaves the project.
    #[test]
    fn test_pnpm_modules_dir_setting_resolution() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        let member = repo.join("packages/member");
        std::fs::create_dir_all(member.join("deps")).unwrap();
        std::fs::create_dir_all(member.join("lib")).unwrap();
        std::fs::create_dir_all(repo.join("deps")).unwrap();
        std::fs::write(repo.join("pnpm-workspace.yaml"), "modulesDir: deps\n").unwrap();
        assert_eq!(configured_install_roots(&member), vec![member.join("deps")]);
        assert_eq!(configured_install_roots(repo), vec![repo.join("deps")]);

        std::fs::write(member.join(".npmrc"), "modules-dir=lib\n").unwrap();
        assert_eq!(configured_install_roots(&member), vec![member.join("deps")]);
        std::fs::write(repo.join("pnpm-workspace.yaml"), "packages: [packages/*]\n").unwrap();
        assert_eq!(configured_install_roots(&member), vec![member.join("lib")]);

        for outside in ["../deps", "/tmp/deps", "."] {
            std::fs::write(member.join(".npmrc"), format!("modules-dir={outside}\n")).unwrap();
            assert!(configured_install_roots(&member).is_empty(), "{outside}");
        }
    }

    /// REGRESSION (#696): an installed pnpm tree whose virtual store pnpm
    /// recorded OUTSIDE the project (the global virtual store, or a
    /// `virtualStoreDir` that climbs out) holds copies the crawler never
    /// sees, so "not found" there does not mean "not installed". A store
    /// inside the project, or no install at all, is not such a blind spot.
    #[test]
    fn test_pnpm_store_outside_project() {
        let outside = tempfile::tempdir().unwrap();
        let shared: PathBuf = outside.path().components().collect();
        let tmp = tempfile::tempdir().unwrap();
        let root: PathBuf = tmp.path().components().collect();
        assert!(!pnpm_store_outside_project(&root), "nothing installed");

        let nm = root.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        assert!(!pnpm_store_outside_project(&root), "not a pnpm install");
        let record = |dir: &Path, store: &str| {
            let store = store.replace('\\', "\\\\");
            std::fs::write(
                dir.join(".modules.yaml"),
                format!("{{\"virtualStoreDir\": \"{store}\"}}"),
            )
            .unwrap();
        };
        record(&nm, ".pnpm");
        assert!(!pnpm_store_outside_project(&root), "default store");
        std::fs::create_dir_all(root.join(".vstore")).unwrap();
        record(&nm, "../.vstore");
        assert!(
            !pnpm_store_outside_project(&root),
            "store inside the project"
        );
        record(&nm, &format!("{}", shared.join("v11/links").display()));
        assert!(pnpm_store_outside_project(&root), "global virtual store");
        record(&nm, "../../outside-vs");
        assert!(
            pnpm_store_outside_project(&root),
            "virtualStoreDir climbs out"
        );
        std::fs::write(
            nm.join(".modules.yaml"),
            "layoutVersion: 5\nvirtualStoreDir: ../../outside-vs\n",
        )
        .unwrap();
        assert!(pnpm_store_outside_project(&root), "YAML .modules.yaml");

        // The same record under a configured `modulesDir`.
        std::fs::remove_dir_all(&nm).unwrap();
        std::fs::write(root.join("pnpm-workspace.yaml"), "modulesDir: deps\n").unwrap();
        let deps = root.join("deps");
        std::fs::create_dir_all(&deps).unwrap();
        record(&deps, ".pnpm");
        assert!(
            !pnpm_store_outside_project(&root),
            "modulesDir default store"
        );
        record(&deps, "../../outside-vs");
        assert!(
            pnpm_store_outside_project(&root),
            "modulesDir, store outside"
        );
    }

    /// REVIEW (#520): `--install.modules-folder` wins over
    /// `--modules-folder` whatever their line order, and when they come
    /// from different `.yarnrc` files (yarn merges each key through the
    /// hierarchy on its own, then appends install-scoped args after the
    /// general ones).
    #[test]
    fn test_install_scoped_modules_folder_takes_precedence() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        let project = repo.join("project");
        write_pkg(&project.join("specific/ms"), "ms", "2.1.3");
        write_pkg(&project.join("general/ms"), "ms", "2.1.3");
        let roots_for = |project_rc: Option<&str>, repo_rc: Option<&str>| {
            for (dir, rc) in [(&project, project_rc), (&repo.to_path_buf(), repo_rc)] {
                let path = dir.join(".yarnrc");
                match rc {
                    Some(rc) => std::fs::write(&path, rc).unwrap(),
                    None => {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
            NpmCrawler::find_local_node_modules_dirs(&project)
        };
        let want = vec![project.join("specific")];
        for (project_rc, repo_rc) in [
            (
                Some("--install.modules-folder specific\n--modules-folder general\n"),
                None,
            ),
            (
                Some("--modules-folder general\n--install.modules-folder specific\n"),
                None,
            ),
            (
                Some("--modules-folder general\n"),
                Some("--install.modules-folder project/specific\n"),
            ),
            (
                Some("--install.modules-folder specific\n"),
                Some("--modules-folder project/general\n"),
            ),
        ] {
            assert_eq!(
                roots_for(project_rc, repo_rc),
                want,
                "{project_rc:?} / {repo_rc:?}"
            );
        }
    }

    /// An escaping or absolute `--modules-folder` is not a crawl root
    /// even when the directory exists: the crawl (and apply's writes)
    /// stays inside the project.
    #[tokio::test]
    async fn test_escaping_modules_folder_is_not_a_crawl_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let outside = tmp.path().join("outside");
        write_pkg(&outside.join("left-pad"), "left-pad", "1.3.0");
        std::fs::create_dir_all(&root).unwrap();
        let crawler = NpmCrawler::new();
        let abs = format!("{}", outside.display()).replace('\\', "\\\\");
        for rc in [
            "--modules-folder ../outside\n".to_string(),
            format!("--modules-folder \"{abs}\"\n"),
        ] {
            std::fs::write(root.join(".yarnrc"), &rc).unwrap();
            let roots = crawler
                .get_node_modules_paths(&local_options(&root))
                .await
                .unwrap();
            assert!(roots.is_empty(), "{rc:?}: {roots:?}");
            assert!(crawler.crawl_all(&local_options(&root)).await.is_empty());
        }
    }

    /// A FIFO planted at `.yarnrc` must not wedge the crawl: it is read
    /// with the regular-file guard and ignored.
    #[cfg(unix)]
    #[test]
    fn test_fifo_yarnrc_does_not_block_the_crawl() {
        use std::os::unix::ffi::OsStrExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        write_pkg(&root.join("node_modules/ms"), "ms", "2.1.3");
        let c_path = std::ffi::CString::new(root.join(".yarnrc").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let probe = root.clone();
        std::thread::spawn(move || {
            let _ = tx.send(NpmCrawler::find_local_node_modules_dirs(&probe));
        });
        let roots = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("a FIFO .yarnrc must not block root discovery");
        assert_eq!(roots, vec![root.join("node_modules")]);
    }

    /// One pnpm 11+ isolated global install, `<v11>/<hash>/node_modules`,
    /// with its `.modules.yaml` marker (when `marked`) and its own
    /// `.pnpm` virtual store holding a real `left-pad@1.3.0`. `direct`
    /// links `left-pad` at the install's top level; otherwise it is
    /// reached only through `lp-wrapper` (a transitive-only copy).
    fn write_pnpm_global_install(v11: &Path, hash: &str, direct: bool, marked: bool) -> PathBuf {
        let nm = v11.join(hash).join("node_modules");
        let store = nm.join(".pnpm");
        let pad = store.join("left-pad@1.3.0/node_modules/left-pad");
        write_pkg(&pad, "left-pad", "1.3.0");
        std::fs::write(v11.join(hash).join("package.json"), "{}").unwrap();
        if marked {
            std::fs::write(nm.join(".modules.yaml"), "layoutVersion: 5\n").unwrap();
        }
        if direct {
            link_dir(&pad, &nm.join("left-pad"));
        } else {
            let wrapper = store.join("lp-wrapper@1.0.0/node_modules/lp-wrapper");
            write_pkg(&wrapper, "lp-wrapper", "1.0.0");
            link_dir(&pad, &store.join("lp-wrapper@1.0.0/node_modules/left-pad"));
            link_dir(&wrapper, &nm.join("lp-wrapper"));
        }
        nm
    }

    fn global_prefix_options(prefix: &Path) -> CrawlerOptions {
        CrawlerOptions {
            cwd: prefix.to_path_buf(),
            global: true,
            global_prefix: Some(prefix.to_path_buf()),
        }
    }

    /// #435: pnpm 11+ gives every `pnpm add -g` its own install dir under
    /// `pnpm root -g` (`$PNPM_HOME/global/v11`). Each install is its own
    /// root, so one walk's matches can never hide another install's copy;
    /// an unmarked sibling (an interrupted install) is still walked.
    #[test]
    fn global_prefix_splits_pnpm_isolated_global_installs() {
        let tmp = tempfile::tempdir().unwrap();
        let v11 = tmp.path().join("global").join("v11");
        let b = write_pnpm_global_install(&v11, "bbb", true, true);
        let a = write_pnpm_global_install(&v11, "aaa", false, true);
        let c = write_pnpm_global_install(&v11, "ccc", false, false);
        // Neither a stray file nor a dir without `node_modules` is a root.
        std::fs::write(v11.join("stray"), "").unwrap();
        std::fs::create_dir_all(v11.join("empty")).unwrap();
        let roots = NpmCrawler::node_modules_paths_sync(&global_prefix_options(&v11));
        assert_eq!(roots, vec![a, b, c]);
    }

    /// The split only applies to pnpm's layout-version dir: pnpm <= 10's
    /// `global/5/node_modules`, an npm prefix and a `v1` dir with no
    /// marked install are each still the single root they always were.
    #[test]
    fn global_prefix_keeps_non_isolated_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("global/5/node_modules");
        write_pkg(&legacy.join("left-pad"), "left-pad", "1.3.0");
        std::fs::write(legacy.join(".modules.yaml"), "layoutVersion: 5\n").unwrap();
        let npm = tmp.path().join("npm/lib/node_modules");
        write_pkg(&npm.join("left-pad"), "left-pad", "1.3.0");
        let v1 = tmp.path().join("other/v1");
        write_pkg(&v1.join("pkg/node_modules/left-pad"), "left-pad", "1.3.0");
        // A `v<N>` dir that IS a pnpm node_modules is never split.
        let nm_v2 = tmp.path().join("nm/v2");
        write_pnpm_global_install(&nm_v2, "aaa", true, true);
        std::fs::write(nm_v2.join(".modules.yaml"), "layoutVersion: 5\n").unwrap();
        for root in [legacy, npm, v1, nm_v2] {
            let roots = NpmCrawler::node_modules_paths_sync(&global_prefix_options(&root));
            assert_eq!(roots, vec![root]);
        }
    }

    /// #435 end to end through the crawler: one install links `left-pad`
    /// directly and the other holds it only transitively in its own
    /// `.pnpm`. Walking `global/v11` as one root let whichever install
    /// listed first remove `left-pad` from the store filter, so the other
    /// install's copy was silently skipped. Both orientations are built
    /// so the guard fails whatever the directory listing order.
    #[tokio::test]
    async fn global_prefix_finds_every_pnpm_isolated_install_copy() {
        for direct_first in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            let v11 = tmp.path().join("global").join("v11");
            let a = write_pnpm_global_install(&v11, "aaa", direct_first, true);
            let b = write_pnpm_global_install(&v11, "bbb", !direct_first, true);
            let crawler = NpmCrawler::new();
            let purl = "pkg:npm/left-pad@1.3.0".to_string();
            let mut real: Vec<PathBuf> = Vec::new();
            for root in crawler
                .get_node_modules_paths(&global_prefix_options(&v11))
                .await
                .unwrap()
            {
                let found = crawler
                    .find_by_purls(&root, std::slice::from_ref(&purl))
                    .await
                    .unwrap();
                for pkg in found.get(&purl).into_iter().flatten() {
                    let canon = std::fs::canonicalize(&pkg.path).unwrap();
                    if !real.contains(&canon) {
                        real.push(canon);
                    }
                }
            }
            real.sort();
            let want = |nm: &Path| {
                std::fs::canonicalize(nm.join(".pnpm/left-pad@1.3.0/node_modules/left-pad"))
                    .unwrap()
            };
            let mut expected = vec![want(&a), want(&b)];
            expected.sort();
            assert_eq!(real, expected, "direct_first={direct_first}");
        }
    }
}
