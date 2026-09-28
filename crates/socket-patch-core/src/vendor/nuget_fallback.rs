//! NuGet vendor backend, "fallback" layout: the patched package is committed
//! EXTRACTED, at a Socket version of its own, as a NuGet fallback package
//! folder that every SDK project restores from in place.
//!
//! Opt-in (the default stays [`super::nuget_feed`]): selected by
//! `SOCKET_PATCH_NUGET_LAYOUT=fallback`, and automatically for a project whose
//! ledger already carries a `nuget-fallback` entry, so a repo that opted in
//! stays opted in. A purl the ledger holds as a legacy feed entry keeps the
//! feed layout ([`fallback_layout_for`]).
//!
//! Mechanism (validated against .NET SDK 8 with real nuget.org fixtures):
//!
//! * identity — the id is unchanged and the version becomes
//!   `V′ = A.B.C.N` ([`super::nuget_version`]), so the patched bytes never
//!   share an id+version with the upstream package in any global packages
//!   folder, HTTP cache or feed;
//! * seed — `.socket/vendor/nuget/<uuid>/<idlower>/<V′>/` holds
//!   `.nupkg.metadata`, `<idlower>.nuspec` (version rewritten) and the
//!   package files ([`super::nuget_seed`]); the uuid dir is the fallback
//!   folder NuGet reads it from;
//! * redirect — `socket-patch.targets` ([`super::nuget_targets`]) appends the
//!   uuid dir to `RestoreAdditionalProjectFallbackFolders`, `Update`s every
//!   `PackageReference` / `PackageVersion` of the id at a literal spelling of
//!   V to `[V′, )`, checks the seed's inventory at restore
//!   (`SOCKETPATCH001/002`) and fails any build that still resolves the
//!   upstream V (`SOCKETPATCH005`);
//! * import — a block in the nearest `Directory.Build.props` of every SDK
//!   project imports the targets through `CustomAfterDirectoryBuildTargets`
//!   and fails restore `SOCKETPATCH007` when they were not imported (the
//!   vendored tree is missing), instead of silently relocking to upstream;
//! * locks — every `packages.lock.json` is spliced to what
//!   `dotnet restore --force-evaluate` writes after the redirect
//!   ([`super::nuget_lock`]), so `--locked-mode` passes with a cold or warm
//!   global packages folder.
//!
//! The targets, the `.gitattributes` / `.gitignore` of `.socket/vendor/nuget/`
//! and the props blocks are shared by every fallback seed and re-rendered by
//! [`sync_shared`] from the seeds on disk (each uuid dir's marker) after every
//! vendor and revert; removing the last seed removes them all, deleting a
//! `Directory.Build.props` socket-patch created (its block is tagged). Only
//! the lock edits are recorded per entry (`nuget_lock_file_v2`: the whole
//! pre/post text); a revert un-splices that entry's values alone
//! ([`super::nuget_lock::unsplice_lock`]), so seeds sharing a lock revert
//! in any order.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::constants::SOCKET_DIR;
use crate::hash::git_sha256::compute_git_sha256_from_bytes;
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{normalize_file_path, PatchSources};
use crate::patch::copy_tree::remove_tree;
use crate::patch::path_safety::{is_canonical_uuid, is_safe_multi_segment, is_safe_single_segment};
use crate::utils::fs::{
    atomic_write_artifact, atomic_write_bytes_preserving_mode, read_regular_to_string, run_blocking,
};
use crate::utils::purl::{build_nuget_purl, parse_nuget_purl};
use crate::utils::socket_dir::{prune_empty_dirs, remove_tree_and_prune};

use super::common::{
    already_patched_result, done, failed_result, prune_empty_vendor_levels, refused, stage_dir_for,
    swap_stage_into_place, synthesized_result,
};
use super::nuget_config::{parse_config, CONFIG_NAMES};
use super::nuget_feed::{is_plain_nuget_token, normalize_nuget_version, patched_nupkg_bytes};
use super::nuget_lock::{splice_lock, unsplice_lock, LockTarget};
use super::nuget_seed::build_seed;
use super::nuget_targets::{
    blank_comments, created_dbp, inject_dbp_block, render_gitattributes, render_gitignore,
    render_targets, unwire_dbp, NugetSeedMarker, GITATTRIBUTES_FILE, GITIGNORE_FILE, TARGETS_FILE,
};
use super::nuget_version::{parse_socket_nuget_version, socket_nuget_version};
use super::path::vendor_uuid_dir_rel;
use super::state::{
    load_state, write_marker, VendorArtifact, VendorEntry, VendorMarker, WiringAction,
    WiringRecord, VENDOR_MARKER_FILE,
};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

/// `VendorEntry::flavor` of a fallback-layout entry.
pub const NUGET_FALLBACK_FLAVOR: &str = "nuget-fallback";

/// The environment variable that opts a project into the fallback layout.
pub const NUGET_LAYOUT_ENV: &str = "SOCKET_PATCH_NUGET_LAYOUT";

/// The per-lock wiring record: the WHOLE pre/post `packages.lock.json` text.
pub(crate) const LOCK_WIRING_KIND: &str = "nuget_lock_file_v2";

const LOCK_FILE: &str = "packages.lock.json";
const DBP_FILE: &str = "Directory.Build.props";
const NUGET_VENDOR_REL: &str = ".socket/vendor/nuget";
const PROJECT_EXTS: &[&str] = &["csproj", "fsproj", "vbproj"];
const SKIP_DIRS: &[&str] = &["bin", "obj", "node_modules"];
const MAX_WALK_DEPTH: usize = 24;
const MAX_WALK_FILES: usize = 100_000;
/// A project / props file bigger than this is not a hand-written MSBuild
/// file; it is skipped by the text scans.
const MAX_MSBUILD_TEXT_BYTES: u64 = 4 * 1024 * 1024;

/// Whether `entry` is a fallback-layout entry (its revert routes here).
pub fn is_fallback_entry(entry: &VendorEntry) -> bool {
    entry.ecosystem == "nuget" && entry.flavor.as_deref() == Some(NUGET_FALLBACK_FLAVOR)
}

/// Whether vendoring the NuGet `purl` in `project_root` uses the fallback
/// layout: the environment opts in, or the project already carries fallback
/// state — unless the ledger holds this purl as a legacy feed entry, which
/// keeps its own layout (migration is not supported).
pub async fn fallback_layout_for(purl: &str, project_root: &Path) -> bool {
    let state = load_state(project_root).await.ok();
    if let (Some(state), Some((name, version))) = (&state, parse_nuget_purl(purl)) {
        let base = build_nuget_purl(&name, &version);
        if state.entries.values().any(|e| {
            e.ecosystem == "nuget"
                && !is_fallback_entry(e)
                && e.base_purl.eq_ignore_ascii_case(&base)
        }) {
            return false;
        }
    }
    std::env::var(NUGET_LAYOUT_ENV).is_ok_and(|v| v.trim().eq_ignore_ascii_case("fallback"))
        || state.is_some_and(|s| s.entries.values().any(is_fallback_entry))
}

// ── project discovery ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Project {
    /// Root-relative, forward-slashed project file path.
    rel: String,
    /// Root-relative dir of the project (`""` at the root).
    dir: String,
    text: String,
    sdk: bool,
}

#[derive(Debug, Default, Clone)]
struct Discovery {
    projects: Vec<Project>,
    /// Every `Directory.Build.props` (root-relative).
    dbps: BTreeSet<String>,
    /// Every project / `.props` / `.targets` text, comments blanked.
    msbuild_texts: Vec<(String, String)>,
    packages_config: Option<String>,
    /// Symbolic links named like a project, props file or lock
    /// (root-relative): a rewrite would replace the link, and MSBuild reads
    /// through it.
    symlinks: Vec<String>,
    /// The walk stopped at [`MAX_WALK_FILES`]: projects may be missing.
    truncated: bool,
}

impl Discovery {
    fn sdk_projects(&self) -> impl Iterator<Item = &Project> {
        self.projects.iter().filter(|p| p.sdk)
    }

    /// The nearest `Directory.Build.props` of `project` inside the root
    /// (`Directory.Build.props` at the root when none exists yet).
    fn nearest_dbp(&self, project: &Project) -> String {
        let mut dir = project.dir.as_str();
        loop {
            let candidate = if dir.is_empty() {
                DBP_FILE.to_string()
            } else {
                format!("{dir}/{DBP_FILE}")
            };
            if self.dbps.contains(&candidate) {
                return candidate;
            }
            if dir.is_empty() {
                return DBP_FILE.to_string();
            }
            dir = dir.rfind('/').map_or("", |i| &dir[..i]);
        }
    }
}

/// `../` once per directory level of the root-relative file `dbp_rel`.
fn dbp_rel_prefix(dbp_rel: &str) -> String {
    "../".repeat(dbp_rel.matches('/').count())
}

fn is_sdk_project(text: &str) -> bool {
    text.contains(" Sdk=\"") || text.contains(" Sdk='") || text.contains("<Sdk ")
}

fn discover_sync(root: &Path) -> Discovery {
    let mut out = Discovery::default();
    let mut stack: Vec<(PathBuf, String, usize)> = vec![(root.to_path_buf(), String::new(), 0)];
    let mut seen = 0usize;
    while let Some((abs, rel, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&abs) else {
            continue;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            seen += 1;
            if seen > MAX_WALK_FILES {
                out.truncated = true;
                return out;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let child_rel = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.is_dir() {
                if depth < MAX_WALK_DEPTH
                    && !name.starts_with('.')
                    && !SKIP_DIRS.iter().any(|d| d.eq_ignore_ascii_case(&name))
                {
                    stack.push((entry.path(), child_rel, depth + 1));
                }
                continue;
            }
            let lower = name.to_ascii_lowercase();
            if meta.file_type().is_symlink() {
                let ext = lower.rsplit('.').next().unwrap_or_default();
                if PROJECT_EXTS.contains(&ext)
                    || lower == DBP_FILE.to_ascii_lowercase()
                    || lower == LOCK_FILE
                {
                    out.symlinks.push(child_rel);
                }
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            if lower == "packages.config" {
                out.packages_config.get_or_insert(child_rel.clone());
                continue;
            }
            let ext = lower.rsplit('.').next().unwrap_or_default();
            let is_project = PROJECT_EXTS.contains(&ext);
            if !is_project && ext != "props" && ext != "targets" {
                continue;
            }
            if name == DBP_FILE {
                out.dbps.insert(child_rel.clone());
            }
            if meta.len() > MAX_MSBUILD_TEXT_BYTES {
                continue;
            }
            let Ok(text) = crate::utils::fs::read_regular_to_string_sync(&entry.path()) else {
                continue;
            };
            let text = blank_comments(&text);
            if is_project {
                out.projects.push(Project {
                    rel: child_rel.clone(),
                    dir: rel.clone(),
                    sdk: is_sdk_project(&text),
                    text: text.clone(),
                });
            }
            out.msbuild_texts.push((child_rel, text));
        }
    }
    out.projects.sort_by(|a, b| a.rel.cmp(&b.rel));
    out.msbuild_texts.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

async fn discover(root: &Path) -> Discovery {
    let root = root.to_path_buf();
    run_blocking(move || discover_sync(&root)).await
}

// ── MSBuild text scans ─────────────────────────────────────────────────────

/// The attributes of the open tag starting right after `<name`, and whether
/// it self-closes, plus the byte offset just past its `>`.
/// An open tag's attributes, whether it self-closes, and its length.
type OpenTag = (Vec<(String, String)>, bool, usize);

fn open_tag_attrs(s: &str) -> Option<OpenTag> {
    let mut attrs = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    loop {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        match b.get(i)? {
            b'>' => return Some((attrs, false, i + 1)),
            b'/' if b.get(i + 1) == Some(&b'>') => return Some((attrs, true, i + 2)),
            _ => {}
        }
        let start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && !matches!(b[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        let name = &s[start..i];
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if b.get(i) != Some(&b'=') || name.is_empty() {
            return None;
        }
        i += 1;
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let quote = *b.get(i)?;
        if quote != b'"' && quote != b'\'' {
            return None;
        }
        let close = s[i + 1..].find(quote as char)?;
        attrs.push((name.to_string(), s[i + 1..i + 1 + close].to_string()));
        i += close + 2;
    }
}

/// The trimmed inner text of every simple `<tag>text</tag>` element.
fn element_values<'a>(text: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(&open) {
        let after = &rest[at + open.len()..];
        let Some(end) = after.find(&close) else { break };
        out.push(after[..end].trim());
        rest = &after[end..];
    }
    out
}

/// What the project files say about the patched id.
#[derive(Debug, Default)]
struct VersionScan {
    /// Literal spellings of V (beyond V and `V.0`).
    spellings: BTreeSet<String>,
    /// `CentralPackageTransitivePinningEnabled` is on somewhere.
    pinning: bool,
}

fn scan_msbuild(
    texts: &[(String, String)],
    id: &str,
    v: &str,
) -> Result<VersionScan, (&'static str, String)> {
    let mut scan = VersionScan::default();
    for (rel, text) in texts {
        if element_values(text, "ImportDirectoryBuildProps")
            .iter()
            .any(|v| v.eq_ignore_ascii_case("false"))
        {
            return Err((
                "vendor_nuget_dbp_disabled",
                format!("{rel} sets ImportDirectoryBuildProps=false; the vendored redirect is imported through Directory.Build.props"),
            ));
        }
        if element_values(text, "CentralPackageTransitivePinningEnabled")
            .iter()
            .any(|v| v.eq_ignore_ascii_case("true"))
        {
            scan.pinning = true;
        }
        for tag in [
            "PackageReference",
            "PackageVersion",
            "GlobalPackageReference",
        ] {
            let open = format!("<{tag}");
            let mut rest = text.as_str();
            while let Some(at) = rest.find(&open) {
                let after = &rest[at + open.len()..];
                rest = after;
                if !after.starts_with(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>') {
                    continue;
                }
                let Some((attrs, self_closing, consumed)) = open_tag_attrs(after) else {
                    continue;
                };
                let attr = |name: &str| {
                    attrs
                        .iter()
                        .find(|(n, _)| n == name)
                        .map(|(_, v)| v.trim().to_string())
                };
                let names_id = ["Include", "Update"].iter().any(|a| {
                    attr(a).is_some_and(|v| v.split(';').any(|i| i.trim().eq_ignore_ascii_case(id)))
                });
                if !names_id {
                    continue;
                }
                let body = if self_closing {
                    ""
                } else {
                    let inner = &after[consumed..];
                    let end = inner.find(&format!("</{tag}>")).unwrap_or(0);
                    &inner[..end]
                };
                if attr("VersionOverride").is_some()
                    || !element_values(body, "VersionOverride").is_empty()
                {
                    return Err((
                        "vendor_nuget_version_override",
                        format!("{rel} overrides the version of {id} (VersionOverride)"),
                    ));
                }
                let mut versions: Vec<String> = attr("Version").into_iter().collect();
                versions.extend(
                    element_values(body, "Version")
                        .iter()
                        .map(|s| s.to_string()),
                );
                for version in versions {
                    classify_version(&version, rel, id, v, &mut scan)?;
                }
            }
        }
    }
    Ok(scan)
}

fn classify_version(
    version: &str,
    rel: &str,
    id: &str,
    v: &str,
    scan: &mut VersionScan,
) -> Result<(), (&'static str, String)> {
    if version.is_empty() {
        return Ok(());
    }
    if version.contains(['$', '@', '%']) {
        return Err((
            "vendor_nuget_version_literal_unknown",
            format!(
                "{rel} spells the version of {id} as {version:?}; only literal versions can be \
                 redirected"
            ),
        ));
    }
    if version.starts_with(['[', '(']) || version.contains([',', '*']) {
        let bounds_v = version
            .trim_matches(|c| matches!(c, '[' | ']' | '(' | ')'))
            .split(',')
            .map(str::trim)
            .any(|b| !b.is_empty() && (normalize_nuget_version(b) == v || b.contains('*')));
        if bounds_v {
            return Err((
                "vendor_nuget_range_unsupported",
                format!(
                    "{rel} references {id} as {version:?}; only a plain `{v}` can be redirected"
                ),
            ));
        }
        return Ok(());
    }
    if is_plain_nuget_token(version) && normalize_nuget_version(version) == v {
        scan.spellings.insert(version.to_string());
    }
    Ok(())
}

/// The first config (the root's ancestors, every project dir's chain, and
/// the user-level files) that sets `signatureValidationMode` to `require`.
async fn signature_require(root: &Path, discovery: &Discovery) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    for p in discovery.projects.iter().filter(|p| p.sdk) {
        // Every dir from the project's up to (excluding) the root.
        let mut dir = p.dir.as_str();
        while !dir.is_empty() {
            dirs.push(root.join(dir));
            dir = dir.rfind('/').map_or("", |i| &dir[..i]);
        }
    }
    dirs.extend(root.ancestors().map(Path::to_path_buf));
    let mut files: Vec<PathBuf> = Vec::new();
    for dir in &dirs {
        for name in CONFIG_NAMES {
            files.push(dir.join(name));
        }
    }
    let home = crate::utils::fs::home_dir();
    files.push(home.join(".nuget/NuGet/NuGet.Config"));
    if let Some(appdata) = std::env::var_os("APPDATA").filter(|v| !v.is_empty()) {
        files.push(PathBuf::from(appdata).join("NuGet/NuGet.Config"));
    }
    let mut seen = BTreeSet::new();
    for file in files {
        if !seen.insert(file.clone()) {
            continue;
        }
        let Ok(text) = read_regular_to_string(&file).await else {
            continue;
        };
        if parse_config(&text)
            .and_then(|c| c.signature_validation_mode)
            .is_some_and(|m| m.eq_ignore_ascii_case("require"))
        {
            return Some(file);
        }
    }
    None
}

// ── the shared render ──────────────────────────────────────────────────────

/// Which seeds a shared render covers beyond "every wired seed on disk".
#[derive(Debug, Default, Clone, Copy)]
struct RenderScope<'a> {
    /// The seed this vendor run just wrote: its marker is rendered as is.
    fresh: Option<&'a str>,
    /// Seeds left out of the render (an earlier uuid of the package being
    /// re-vendored, swept once the new entry is committed).
    exclude: &'a [String],
}

/// Every rendered fallback seed on disk: `(uuid, marker)`, sorted by uuid.
///
/// The marker is not a trust input: when the ledger records a fallback
/// entry for the uuid, its `file_inventory` (the seed hashes vendor
/// recorded) replaces the marker's, so an edited marker never re-baselines
/// the restore-time seed check.
async fn fallback_seeds(
    project_root: &Path,
    scope: RenderScope<'_>,
) -> Vec<(String, NugetSeedMarker)> {
    let dir = project_root.join(NUGET_VENDOR_REL);
    let ledger: BTreeMap<String, BTreeMap<String, String>> = load_state(project_root)
        .await
        .map(|s| {
            s.entries
                .into_values()
                .filter(is_fallback_entry)
                .filter_map(|e| Some((e.uuid, e.artifact.file_inventory?)))
                .collect()
        })
        .unwrap_or_default();
    let mut out = Vec::new();
    for entry in crate::utils::fs::list_dir_entries(&dir).await {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_canonical_uuid(&name) || scope.exclude.contains(&name) {
            continue;
        }
        if !entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let Some(mut marker) = read_seed_marker(&entry.path()).await else {
            continue;
        };
        if !marker.wired {
            continue;
        }
        if scope.fresh != Some(name.as_str()) {
            if let Some(inventory) = ledger.get(&name).filter(|i| !i.is_empty()) {
                marker.inventory = inventory.clone();
            }
        }
        if marker.is_renderable() {
            out.push((name, marker));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

async fn read_marker(uuid_dir: &Path) -> Option<VendorMarker> {
    let text = read_regular_to_string(&uuid_dir.join(VENDOR_MARKER_FILE))
        .await
        .ok()?;
    serde_json::from_str::<VendorMarker>(&text).ok()
}

async fn read_seed_marker(uuid_dir: &Path) -> Option<NugetSeedMarker> {
    read_marker(uuid_dir)
        .await?
        .nuget
        .filter(NugetSeedMarker::is_renderable)
}

/// One planned shared-file change: the desired bytes, or `None` to delete.
type SharedWrite = (PathBuf, Option<String>);

/// The shared-file changes that bring `project_root` in line with its seeds.
async fn plan_shared(
    project_root: &Path,
    discovery: &Discovery,
    scope: RenderScope<'_>,
) -> Result<Vec<SharedWrite>, String> {
    if discovery.truncated {
        return Err(format!(
            "the project tree has more than {MAX_WALK_FILES} entries; the Directory.Build.props \
             files the NuGet fallback layout wires cannot all be found"
        ));
    }
    if let Some(link) = discovery.symlinks.first() {
        return Err(format!(
            "{link} is a symbolic link; the NuGet fallback layout cannot rewrite it in place"
        ));
    }
    let seeds = fallback_seeds(project_root, scope).await;
    let vendor_dir = project_root.join(NUGET_VENDOR_REL);
    let mut desired: Vec<SharedWrite> = Vec::new();
    if seeds.is_empty() {
        for f in [TARGETS_FILE, GITATTRIBUTES_FILE, GITIGNORE_FILE] {
            desired.push((vendor_dir.join(f), None));
        }
        for dbp in &discovery.dbps {
            let path = project_root.join(dbp);
            let Ok(text) = read_regular_to_string(&path).await else {
                continue;
            };
            desired.push((path, unwire_dbp(&text)));
        }
    } else {
        let uuids: Vec<String> = seeds.iter().map(|(u, _)| u.clone()).collect();
        desired.push((vendor_dir.join(TARGETS_FILE), Some(render_targets(&seeds))));
        desired.push((
            vendor_dir.join(GITATTRIBUTES_FILE),
            Some(render_gitattributes()),
        ));
        desired.push((
            vendor_dir.join(GITIGNORE_FILE),
            Some(render_gitignore(&uuids)),
        ));
        let nearest: BTreeSet<String> = discovery
            .sdk_projects()
            .map(|p| discovery.nearest_dbp(p))
            .collect();
        for dbp in nearest {
            let path = project_root.join(&dbp);
            let wired = match read_regular_to_string(&path).await {
                Ok(current) => inject_dbp_block(&current, &dbp_rel_prefix(&dbp))
                    .map_err(|e| format!("{dbp}: {e}"))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    created_dbp(&dbp_rel_prefix(&dbp))
                }
                Err(e) => return Err(format!("unreadable {dbp}: {e}")),
            };
            desired.push((path, Some(wired)));
        }
    }
    let mut changes = Vec::new();
    for (path, want) in desired {
        let have = match read_regular_to_string(&path).await {
            Ok(t) => Some(t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("unreadable {}: {e}", path.display())),
        };
        if have != want {
            changes.push((path, want));
        }
    }
    Ok(changes)
}

/// The previous contents of every file [`sync_shared`] changed (`None` =
/// it did not exist), for an unwind.
pub(crate) type SharedSnapshot = Vec<(PathBuf, Option<Vec<u8>>)>;

/// Re-render the shared outputs — `socket-patch.targets`, `.gitattributes`,
/// `.gitignore` and the `Directory.Build.props` blocks — from the fallback
/// seeds on disk. With no seed left, every block is excised (a props file
/// socket-patch created is deleted) and the generated files are removed.
/// Idempotent; `dry_run` computes without writing. Returns what it changed.
pub async fn sync_shared(project_root: &Path, dry_run: bool) -> Result<Vec<PathBuf>, String> {
    let discovery = discover(project_root).await;
    let snapshot =
        sync_shared_with(project_root, &discovery, RenderScope::default(), dry_run).await?;
    Ok(snapshot.into_iter().map(|(p, _)| p).collect())
}

async fn sync_shared_with(
    project_root: &Path,
    discovery: &Discovery,
    scope: RenderScope<'_>,
    dry_run: bool,
) -> Result<SharedSnapshot, String> {
    let changes = plan_shared(project_root, discovery, scope).await?;
    let mut snapshot: SharedSnapshot = Vec::new();
    for (path, want) in changes {
        let prev = tokio::fs::read(&path).await.ok();
        if !dry_run {
            let outcome = match &want {
                Some(text) => {
                    if let Some(parent) = path.parent() {
                        let _ = tokio::fs::create_dir_all(parent).await;
                    }
                    atomic_write_bytes_preserving_mode(&path, text.as_bytes()).await
                }
                None => crate::utils::fs::remove_file(&path).await,
            };
            if let Err(e) = outcome {
                restore_snapshot(&snapshot).await;
                return Err(format!("cannot write {}: {e}", path.display()));
            }
        }
        snapshot.push((path, prev));
    }
    if !dry_run && fallback_seeds(project_root, scope).await.is_empty() {
        let vendor_dir = project_root.join(NUGET_VENDOR_REL);
        prune_empty_dirs(&vendor_dir, &project_root.join(SOCKET_DIR)).await;
    }
    Ok(snapshot)
}

async fn restore_snapshot(snapshot: &SharedSnapshot) {
    for (path, prev) in snapshot.iter().rev() {
        let _ = match prev {
            Some(bytes) => atomic_write_bytes_preserving_mode(path, bytes).await,
            None => crate::utils::fs::remove_file(path).await,
        };
    }
}

// ── the prelude (shared with the download plan) ────────────────────────────

struct PlannedLock {
    /// Root-relative lock path.
    rel: String,
    text: String,
}

struct Prelude {
    name: String,
    version_norm: String,
    socket_version: String,
    base_purl: String,
    uuid_dir: PathBuf,
    /// `.socket/vendor/nuget/<uuid>/<idlower>/<V′>`.
    seed_rel: String,
    spellings: Vec<String>,
    pinning: bool,
    locks: Vec<PlannedLock>,
    discovery: Discovery,
    in_sync: bool,
}

/// A contentHash-shaped placeholder: refusal planning does not depend on the
/// hash value.
const PLACEHOLDER_HASH: &str = "socket-patch-placeholder";

async fn fallback_prelude(
    purl: &str,
    project_root: &Path,
    record: &PatchRecord,
) -> Result<Prelude, VendorOutcome> {
    let Some((name, version)) = parse_nuget_purl(purl) else {
        return Err(refused(
            "unsafe_coordinates",
            format!("not a nuget purl: {purl}"),
        ));
    };
    let (name, version) = (name.to_string(), version.to_string());
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("nuget", &record.uuid) else {
        return Err(refused(
            "unsafe_coordinates",
            format!("non-canonical patch uuid {:?}", record.uuid),
        ));
    };
    if !is_safe_single_segment(&name)
        || !is_safe_single_segment(&version)
        || !is_plain_nuget_token(&name)
        || !is_plain_nuget_token(&version)
        || name.contains("--")
        || version.contains("--")
    {
        return Err(refused(
            "unsafe_coordinates",
            format!("unsafe nuget coordinates `{name}` @ `{version}`"),
        ));
    }
    let version_norm = normalize_nuget_version(&version);
    let Some(socket_version) = socket_nuget_version(&version_norm, &record.uuid) else {
        return Err(refused(
            "vendor_nuget_version_unsuffixable",
            format!(
                "{name} {version} has no free 4th version part for a Socket version (prereleases \
                 and 4-part versions are not supported by the fallback layout)"
            ),
        ));
    };
    let id_lower = name.to_ascii_lowercase();
    let uuid_dir = project_root.join(&uuid_dir_rel);
    let seed_rel = format!("{uuid_dir_rel}/{id_lower}/{socket_version}");
    let base_purl = build_nuget_purl(&name, &version);

    if record.files.is_empty() {
        return Err(done(
            synthesized_result(purl, &uuid_dir, Vec::new(), true, None),
            None,
            Vec::new(),
        ));
    }
    if record
        .files
        .keys()
        .map(|k| normalize_file_path(k))
        .any(|k| !k.contains('/') && k.to_ascii_lowercase().ends_with(".nuspec"))
    {
        return Err(refused(
            "vendor_nuget_nuspec_patched",
            "the patch rewrites the package nuspec, which the fallback layout re-versions",
        ));
    }
    if let Ok(state) = load_state(project_root).await {
        let mixed = state.entries.values().any(|e| {
            e.ecosystem == "nuget"
                && !is_fallback_entry(e)
                && e.base_purl.eq_ignore_ascii_case(&base_purl)
        });
        if mixed {
            return Err(refused(
                "vendor_nuget_layout_mixed",
                format!(
                    "{base_purl} is vendored with the legacy NuGet feed layout; revert it first \
                     (`vendor --revert`) before vendoring it with the fallback layout"
                ),
            ));
        }
    }

    let discovery = discover(project_root).await;
    if discovery.truncated {
        return Err(refused(
            "vendor_nuget_repo_too_large",
            format!(
                "the project tree has more than {MAX_WALK_FILES} entries; the fallback layout \
                 must see every SDK project to wire it"
            ),
        ));
    }
    if let Some(link) = discovery.symlinks.first() {
        return Err(refused(
            "vendor_nuget_symlink_unsupported",
            format!(
                "{link} is a symbolic link; the fallback layout rewrites project props and locks \
                 in place and cannot follow a link"
            ),
        ));
    }
    if let Some(pc) = &discovery.packages_config {
        return Err(refused(
            "vendor_nuget_packages_config",
            format!("{pc}: packages.config projects cannot use the fallback layout"),
        ));
    }
    if discovery.sdk_projects().next().is_none() {
        return Err(refused(
            "vendor_nuget_no_projects",
            "no SDK-style .csproj/.fsproj/.vbproj under the project root",
        ));
    }
    if let Some(p) = discovery
        .projects
        .iter()
        .find(|p| !p.sdk && p.text.contains("<PackageReference"))
    {
        return Err(refused(
            "vendor_nuget_non_sdk_project",
            format!("{} is not an SDK-style project; its PackageReferences would bypass the vendored redirect", p.rel),
        ));
    }
    if let Some(cfg) = signature_require(project_root, &discovery).await {
        return Err(refused(
            "vendor_nuget_signature_require",
            format!(
                "{} sets signatureValidationMode=require; a re-versioned unsigned package cannot \
                 satisfy it",
                cfg.display()
            ),
        ));
    }
    let scan = scan_msbuild(&discovery.msbuild_texts, &name, &version_norm)
        .map_err(|(code, detail)| refused(code, detail))?;
    let default_spellings = [version_norm.clone(), format!("{version_norm}.0")];
    let spellings: Vec<String> = scan
        .spellings
        .iter()
        .filter(|s| !default_spellings.contains(s))
        .cloned()
        .collect();

    let marker = read_marker(&uuid_dir).await.and_then(|m| m.nuget);
    let hash = marker
        .as_ref()
        .filter(|m| m.socket_version == socket_version)
        .map(|m| m.content_hash.clone());
    let mut locks = Vec::new();
    let mut locks_in_sync = true;
    for project in discovery.sdk_projects() {
        let rel = if project.dir.is_empty() {
            LOCK_FILE.to_string()
        } else {
            format!("{}/{LOCK_FILE}", project.dir)
        };
        let text = match read_regular_to_string(&project_root.join(&rel)).await {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(refused(
                    "vendor_nuget_lock_unreadable",
                    format!("unreadable {rel}: {e}"),
                ))
            }
        };
        let target = LockTarget {
            id: &name,
            version: &version_norm,
            socket_version: &socket_version,
            content_hash: hash.as_deref().unwrap_or(PLACEHOLDER_HASH),
            transitive_pinning: scan.pinning,
        };
        let splice = splice_lock(&text, &target)
            .map_err(|(code, detail)| refused(code, format!("{rel}: {detail}")))?;
        if splice.edits > 0 {
            locks_in_sync = false;
        }
        locks.push(PlannedLock { rel, text });
    }

    let in_sync = match &marker {
        Some(m) if hash.is_some() && m.wired && locks_in_sync => {
            let seed_dir = project_root.join(&seed_rel);
            let inventory_ok = super::verify::compute_dir_inventory(&seed_dir)
                .await
                .is_ok_and(|inv| inv == m.inventory);
            inventory_ok
                && seed_has_patched_files(&seed_dir, record).await
                && plan_shared(project_root, &discovery, RenderScope::default())
                    .await
                    .is_ok_and(|c| c.is_empty())
        }
        _ => false,
    };

    Ok(Prelude {
        name,
        version_norm,
        socket_version,
        base_purl,
        uuid_dir,
        seed_rel,
        spellings,
        pinning: scan.pinning,
        locks,
        discovery,
        in_sync,
    })
}

/// Whether every file the patch rewrites sits in the seed at its afterHash
/// (the fast path never trusts the marker's own inventory alone).
async fn seed_has_patched_files(seed_dir: &Path, record: &PatchRecord) -> bool {
    for (key, info) in &record.files {
        let rel = normalize_file_path(key);
        if !is_safe_multi_segment(rel) {
            return false;
        }
        let Ok(bytes) = crate::utils::fs::read_regular_to_bytes(&seed_dir.join(rel)).await else {
            return false;
        };
        if compute_git_sha256_from_bytes(&bytes) != info.after_hash {
            return false;
        }
    }
    true
}

/// Whether [`vendor_nuget_fallback`] — a wet run with the service enabled —
/// asks the patch service for `record` (see `nuget_feed::service_preflight`).
pub(crate) async fn service_preflight(
    purl: &str,
    project_root: &Path,
    record: &PatchRecord,
) -> Option<crate::api::client::PlannedDownload> {
    fallback_prelude(purl, project_root, record)
        .await
        .ok()
        .filter(|p| !p.in_sync)?;
    Some(crate::api::client::PlannedDownload {
        stage: Some(super::prestage::PrestageRecipe::verify_zip(&record.files)),
        ..crate::api::client::PlannedDownload::archive(record.uuid.clone())
    })
}

// ── vendor ─────────────────────────────────────────────────────────────────

/// Vendor a NuGet package with the fallback layout (see the module doc).
/// Same contract and arguments as `nuget_feed::vendor_nuget`.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_nuget_fallback(
    purl: &str,
    installed_dir: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&VendorServiceConfig>,
) -> VendorOutcome {
    let prelude = match fallback_prelude(purl, project_root, record).await {
        Ok(p) => p,
        Err(outcome) => return outcome,
    };
    let seed_dir = project_root.join(&prelude.seed_rel);
    if prelude.in_sync {
        return done(
            already_patched_result(purl, &seed_dir, &record.files),
            None,
            Vec::new(),
        );
    }
    let mut warnings: Vec<VendorWarning> = Vec::new();
    if dry_run {
        let mut result = super::force_apply_staged(
            purl,
            installed_dir,
            record,
            sources,
            true,
            force,
            &prelude.name,
            &prelude.version_norm,
            &mut warnings,
        )
        .await;
        result.package_path = seed_dir.display().to_string();
        return done(result, None, warnings);
    }

    // ── the patched same-version nupkg, then the seed ────────────────────
    let (nupkg, mut result) = match patched_nupkg_bytes(
        purl,
        installed_dir,
        &prelude.name,
        &prelude.version_norm,
        record,
        sources,
        force,
        service,
        &mut warnings,
    )
    .await
    {
        Ok(pair) => pair,
        Err(outcome) => return *outcome,
    };
    if !result.success {
        return done(result, None, warnings);
    }
    result.package_path = seed_dir.display().to_string();
    let seed = match build_seed(
        &nupkg,
        &prelude.name,
        &prelude.version_norm,
        &prelude.socket_version,
    ) {
        Ok(seed) => seed,
        Err((code, detail)) => return refused(code, detail),
    };
    drop(nupkg);
    for (key, info) in &record.files {
        let rel = normalize_file_path(key);
        let ok = seed
            .files
            .get(rel)
            .is_some_and(|bytes| compute_git_sha256_from_bytes(bytes) == info.after_hash);
        if !ok {
            return done(
                failed_result(
                    purl,
                    &seed_dir,
                    format!("the extracted seed's {rel} does not hash to the patch's afterHash"),
                ),
                None,
                warnings,
            );
        }
    }

    // ── plan every lock at the seed's hash ───────────────────────────────
    let target = LockTarget {
        id: &prelude.name,
        version: &prelude.version_norm,
        socket_version: &prelude.socket_version,
        content_hash: &seed.content_hash,
        transitive_pinning: prelude.pinning,
    };
    // Every lock that pins the id (edited now or spliced by an earlier run):
    // `(rel, pre-edit text, spliced text)`. Each gets a record, so a
    // re-vendor keeps the revert of a lock it did not need to touch.
    let mut lock_writes: Vec<(String, String, String)> = Vec::new();
    for lock in &prelude.locks {
        let splice = match splice_lock(&lock.text, &target) {
            Ok(s) => s,
            Err((code, detail)) => return refused(code, format!("{}: {detail}", lock.rel)),
        };
        if splice.references_id {
            lock_writes.push((lock.rel.clone(), lock.text.clone(), splice.text));
        }
    }
    if lock_writes.is_empty() {
        warnings.push(VendorWarning::new(
            "vendor_nuget_no_lockfile",
            format!(
                "no packages.lock.json references {} {}; the vendored redirect and its build \
                 guard still apply, but nothing pins the patched contentHash",
                prelude.name, prelude.version_norm
            ),
        ));
    }

    // ── write: seed, locks, shared outputs (unwound on any failure) ──────
    let marker = VendorMarker {
        nuget: Some(NugetSeedMarker {
            id: prelude.name.clone(),
            version: prelude.version_norm.clone(),
            socket_version: prelude.socket_version.clone(),
            content_hash: seed.content_hash.clone(),
            spellings: prelude.spellings.clone(),
            inventory: seed.inventory(),
            wired: true,
        }),
        ..VendorMarker::new("nuget", &prelude.base_purl, record, vendored_at)
    };
    let created_seed = tokio::fs::symlink_metadata(&prelude.uuid_dir)
        .await
        .is_err();
    if let Err(e) = write_seed_dir(&prelude.uuid_dir, &seed, &marker).await {
        if created_seed {
            let _ = remove_tree(&prelude.uuid_dir).await;
            prune_empty_vendor_levels(&prelude.uuid_dir).await;
        }
        result.success = false;
        result.error = Some(e);
        return done(result, None, warnings);
    }
    let unwind_seed = || async {
        if created_seed {
            let _ = remove_tree(&prelude.uuid_dir).await;
            prune_empty_vendor_levels(&prelude.uuid_dir).await;
        }
    };
    let mut written: Vec<(String, String)> = Vec::new();
    for (rel, original, new) in lock_writes.iter().filter(|(_, o, n)| o != n) {
        if let Err(e) =
            atomic_write_bytes_preserving_mode(&project_root.join(rel), new.as_bytes()).await
        {
            unwind_locks(project_root, &written).await;
            unwind_seed().await;
            result.success = false;
            result.error = Some(format!("failed to write {rel}: {e}"));
            return done(result, None, warnings);
        }
        written.push((rel.clone(), original.clone()));
    }
    // An earlier uuid's seed of this same package is swept once the new
    // entry is committed; it must not render beside this one meanwhile.
    let superseded = superseded_seeds(project_root, &record.uuid, &prelude).await;
    let scope = RenderScope {
        fresh: Some(record.uuid.as_str()),
        exclude: &superseded,
    };
    if let Err(e) = sync_shared_with(project_root, &prelude.discovery, scope, false).await {
        unwind_locks(project_root, &written).await;
        unwind_seed().await;
        // The shared render of the seeds that remain (the unwound one gone).
        let _ = sync_shared_with(
            project_root,
            &prelude.discovery,
            RenderScope::default(),
            false,
        )
        .await;
        result.success = false;
        result.error = Some(e);
        return done(result, None, warnings);
    }

    // ── the ledger entry ─────────────────────────────────────────────────
    let wiring = lock_writes
        .into_iter()
        .map(|(rel, original, new)| {
            // A lock already carrying a Socket version was spliced by an
            // earlier vendoring: its text is not the pre-vendor original
            // (`carry_forward_wiring` fills that from the replaced entry).
            let pristine = !original.contains(&prelude.socket_version)
                && !lock_mentions_socket_version(&original, &prelude.version_norm);
            WiringRecord {
                file: rel,
                kind: LOCK_WIRING_KIND.to_string(),
                action: WiringAction::Rewritten,
                key: Some(prelude.name.clone()),
                original: pristine.then_some(Value::String(original)),
                new: Some(Value::String(new)),
            }
        })
        .collect();
    let entry = VendorEntry {
        ecosystem: "nuget".to_string(),
        base_purl: prelude.base_purl.clone(),
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
            path: prelude.seed_rel.clone(),
            sha256: String::new(),
            size: None,
            platform_locked: None,
            file_inventory: Some(seed.inventory()),
        },
        wiring,
        lock: None,
        took_over_go_patches: false,
        detached: false,
        record: None,
        flavor: Some(NUGET_FALLBACK_FLAVOR.to_string()),
        uv: None,
        pnpm: None,
        poetry: None,
        pdm: None,
        pipenv: None,
    };
    done(result, Some(entry), warnings)
}

/// The other uuid dirs holding a wired seed of the same id and upstream
/// version as `prelude` (an earlier patch of this package).
async fn superseded_seeds(project_root: &Path, uuid: &str, prelude: &Prelude) -> Vec<String> {
    fallback_seeds(project_root, RenderScope::default())
        .await
        .into_iter()
        .filter(|(u, m)| {
            u != uuid
                && m.id.eq_ignore_ascii_case(&prelude.name)
                && m.version == prelude.version_norm
        })
        .map(|(u, _)| u)
        .collect()
}

/// Whether any string of a lock names a Socket version of upstream `v`
/// (as a version or a `[X, )` floor), i.e. an earlier vendoring spliced it.
fn lock_mentions_socket_version(text: &str, v: &str) -> bool {
    fn walk(value: &Value, v: &str) -> bool {
        match value {
            Value::String(s) => {
                let bare = s
                    .strip_prefix('[')
                    .and_then(|r| r.strip_suffix(", )"))
                    .unwrap_or(s);
                parse_socket_nuget_version(bare).is_some_and(|(up, _)| up == v)
            }
            Value::Object(m) => m.values().any(|x| walk(x, v)),
            Value::Array(a) => a.iter().any(|x| walk(x, v)),
            _ => false,
        }
    }
    serde_json::from_str::<Value>(text.trim_start_matches('\u{feff}'))
        .is_ok_and(|doc| walk(&doc, v))
}

async fn unwind_locks(project_root: &Path, written: &[(String, String)]) {
    for (rel, original) in written.iter().rev() {
        let _ =
            atomic_write_bytes_preserving_mode(&project_root.join(rel), original.as_bytes()).await;
    }
}

/// Materialise `<uuid>/` (marker + `<idlower>/<V′>/` seed) in a sibling stage
/// and swap it into place.
async fn write_seed_dir(
    uuid_dir: &Path,
    seed: &super::nuget_seed::Seed,
    marker: &VendorMarker,
) -> Result<(), String> {
    let stage = stage_dir_for(uuid_dir);
    remove_tree(&stage)
        .await
        .map_err(|e| format!("cannot clear {}: {e}", stage.display()))?;
    let seed_root = stage.join(seed.dir_rel());
    for (rel, bytes) in seed.tree() {
        let path = seed_root.join(&rel);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        if let Err(e) = atomic_write_artifact(&path, &bytes).await {
            let _ = remove_tree(&stage).await;
            return Err(format!("cannot write {}: {e}", path.display()));
        }
    }
    if let Err(e) = write_marker(&stage, marker).await {
        let _ = remove_tree(&stage).await;
        return Err(format!("cannot write the vendor marker: {e}"));
    }
    if let Err(e) = swap_stage_into_place(&stage, uuid_dir).await {
        let _ = remove_tree(&stage).await;
        return Err(format!(
            "cannot move the seed into {}: {e}",
            uuid_dir.display()
        ));
    }
    Ok(())
}

// ── revert ─────────────────────────────────────────────────────────────────

/// Revert a fallback-layout entry: restore every spliced lock (a lock that
/// no longer holds what vendor wrote is left alone with a
/// `vendor_lock_entry_drifted` warning), delete the seed, and re-render the
/// shared outputs from the seeds that remain (removing them with the last).
///
/// Drift-keep: when a drifted lock still resolves this entry's Socket
/// version, the seed is kept (`kept_artifact`) — a restore of that lock
/// still needs it.
pub async fn revert_nuget_fallback_opts(
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
) -> RevertOutcome {
    let RevertOpts {
        dry_run,
        keep_artifact,
    } = opts;
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("nuget", &entry.uuid) else {
        return RevertOutcome::failed(format!(
            "refusing revert: non-canonical patch uuid {:?}",
            entry.uuid
        ));
    };
    let uuid_dir = project_root.join(&uuid_dir_rel);
    let socket_version = entry
        .artifact
        .path
        .rsplit('/')
        .next()
        .filter(|v| parse_socket_nuget_version(v).is_some())
        .map(str::to_string);
    let coords = parse_nuget_purl(&entry.base_purl)
        .map(|(name, version)| (name.to_string(), normalize_nuget_version(&version)));
    let discovery = discover(project_root).await;
    if !dry_run {
        if let Some(link) = discovery.symlinks.first() {
            return RevertOutcome::failed(format!(
                "refusing revert: {link} is a symbolic link; the fallback layout cannot rewrite \
                 it in place"
            ));
        }
        if discovery.truncated {
            return RevertOutcome::failed(format!(
                "refusing revert: the project tree has more than {MAX_WALK_FILES} entries; the \
                 wired Directory.Build.props files cannot all be found"
            ));
        }
    }
    let mut warnings = Vec::new();
    let mut live_drift = false;
    for w in entry.wiring.iter().rev() {
        if w.kind != LOCK_WIRING_KIND {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!("unrecognized wiring kind {:?}; fragment left alone", w.kind),
            ));
            continue;
        }
        let target = match (&coords, &socket_version) {
            (Some((name, version)), Some(vp)) => Some(LockTarget {
                id: name,
                version,
                socket_version: vp,
                content_hash: "",
                transitive_pinning: false,
            }),
            _ => None,
        };
        match revert_lock_file(project_root, w, target.as_ref(), dry_run).await {
            Ok(LockRevert::Restored) => {}
            Ok(LockRevert::Drifted(live)) => {
                if socket_version
                    .as_deref()
                    .is_some_and(|vp| live.as_deref().is_some_and(|t| t.contains(vp)))
                {
                    live_drift = true;
                }
                warnings.push(VendorWarning::new(
                    "vendor_lock_entry_drifted",
                    format!(
                        "{} still pins {} at its Socket version and its upstream value could not \
                         be recovered; left alone",
                        w.file,
                        w.key.as_deref().unwrap_or("<unknown>")
                    ),
                ));
            }
            Err(e) => {
                return RevertOutcome {
                    success: false,
                    warnings,
                    error: Some(e),
                    kept_artifact: false,
                }
            }
        }
    }
    let mut outcome = RevertOutcome {
        success: true,
        warnings,
        error: None,
        kept_artifact: false,
    };
    if dry_run {
        return outcome;
    }
    if outcome.drift_skipped() && live_drift {
        outcome.keep_artifact(&uuid_dir_rel);
        return outcome;
    }
    if keep_artifact {
        // The seed stays on disk (the caller keeps the ledger entry) but is
        // no longer rendered into the shared redirect.
        if let Some(mut marker) = read_marker(&uuid_dir).await {
            if let Some(n) = marker.nuget.as_mut() {
                n.wired = false;
            }
            let _ = write_marker(&uuid_dir, &marker).await;
        }
    } else if let Err(e) = remove_tree_and_prune(&uuid_dir, &project_root.join(SOCKET_DIR)).await {
        outcome.success = false;
        outcome.error = Some(format!("failed to remove {}: {e}", uuid_dir.display()));
        return outcome;
    }
    if let Err(e) = sync_shared_with(project_root, &discovery, RenderScope::default(), false).await
    {
        outcome.success = false;
        outcome.error = Some(e);
    }
    outcome
}

enum LockRevert {
    Restored,
    /// Left alone; the live text (when readable).
    Drifted(Option<String>),
}

/// Un-splice one lock for one entry: only this entry's values go back to
/// the upstream V (see [`unsplice_lock`]); whatever else changed in the lock
/// since — another seed's splice, a new package — is kept.
async fn revert_lock_file(
    project_root: &Path,
    w: &WiringRecord,
    target: Option<&LockTarget<'_>>,
    dry_run: bool,
) -> Result<LockRevert, String> {
    if !is_safe_multi_segment(&w.file)
        || !(w.file == LOCK_FILE || w.file.ends_with(&format!("/{LOCK_FILE}")))
    {
        return Ok(LockRevert::Drifted(None));
    }
    let Some(target) = target else {
        return Ok(LockRevert::Drifted(None));
    };
    let path = project_root.join(&w.file);
    if tokio::fs::symlink_metadata(&path)
        .await
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        return Ok(LockRevert::Drifted(None));
    }
    let live = match read_regular_to_string(&path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(LockRevert::Restored),
        Err(e) => return Err(format!("unreadable {}: {e}", w.file)),
    };
    let original = match &w.original {
        Some(Value::String(o)) => Some(o.as_str()),
        _ => None,
    };
    let Ok((restored, complete)) = unsplice_lock(&live, original, target) else {
        return Ok(LockRevert::Drifted(Some(live)));
    };
    if restored != live && !dry_run {
        atomic_write_bytes_preserving_mode(&path, restored.as_bytes())
            .await
            .map_err(|e| format!("failed to restore {}: {e}", w.file))?;
    }
    Ok(if complete {
        LockRevert::Restored
    } else {
        LockRevert::Drifted(Some(restored))
    })
}

/// The uuid dirs of every fallback seed the generated targets still render
/// (for the orphan sweep's liveness scan): `(uuid, seed path)`.
pub async fn rendered_seed_references(project_root: &Path) -> Vec<(String, String)> {
    let Ok(text) =
        read_regular_to_string(&project_root.join(NUGET_VENDOR_REL).join(TARGETS_FILE)).await
    else {
        return Vec::new();
    };
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let needle = "Include=\"$(SocketPatchNuGetDir)";
    for line in text.lines() {
        let Some(at) = line.find(needle) else {
            continue;
        };
        let rest = &line[at + needle.len()..];
        let mut parts = rest.splitn(4, '/');
        let (Some(uuid), Some(id), Some(ver)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if is_canonical_uuid(uuid)
            && is_plain_nuget_token(id)
            && is_plain_nuget_token(ver)
            && is_safe_single_segment(id)
            && is_safe_single_segment(ver)
        {
            out.entry(uuid.to_string())
                .or_insert_with(|| format!("{NUGET_VENDOR_REL}/{uuid}/{id}/{ver}"));
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DBP_BEGIN_TEST: &str = "<!-- socket-patch:begin";
    const UUID: &str = "3f9a01bc-1111-4222-8333-444455556666";
    const UUID2: &str = "0a0b0c0d-1111-4222-8333-444455556666";
    const SOCKET_V: &str = "13.0.1.1340506223";

    fn marker(id: &str, version: &str, uuid: &str) -> VendorMarker {
        let socket_version = socket_nuget_version(version, uuid).unwrap();
        VendorMarker {
            schema_version: 1,
            purl: format!("pkg:nuget/{id}@{version}"),
            patch_uuid: uuid.to_string(),
            ecosystem: "nuget".into(),
            vulnerabilities: Vec::new(),
            vendored_at: String::new(),
            nuget: Some(NugetSeedMarker {
                id: id.into(),
                version: version.into(),
                socket_version,
                content_hash: "aGFzaA==".into(),
                spellings: Vec::new(),
                inventory: BTreeMap::from([
                    (".nupkg.metadata".to_string(), "a".repeat(64)),
                    ("lib/x.dll".to_string(), "b".repeat(64)),
                ]),
                wired: true,
            }),
        }
    }

    async fn plant_seed(root: &Path, id: &str, version: &str, uuid: &str) {
        let dir = root.join(NUGET_VENDOR_REL).join(uuid);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        write_marker(&dir, &marker(id, version, uuid))
            .await
            .unwrap();
    }

    fn project(root: &Path, rel: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            path,
            "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <ItemGroup>\n    <PackageReference \
             Include=\"Newtonsoft.Json\" Version=\"13.0.1\" />\n  </ItemGroup>\n</Project>\n",
        )
        .unwrap();
    }

    #[tokio::test]
    async fn sync_shared_zero_one_two_seeds() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        project(root, "src/Lib/Lib.csproj");
        project(root, "tests/T/T.csproj");
        std::fs::write(
            root.join("tests/Directory.Build.props"),
            "<Project>\r\n  <PropertyGroup>\r\n    <A>1</A>\r\n  </PropertyGroup>\r\n</Project>\r\n",
        )
        .unwrap();
        let nested_before = std::fs::read(root.join("tests/Directory.Build.props")).unwrap();

        // 0 seeds, nothing wired: a no-op.
        assert!(sync_shared(root, false).await.unwrap().is_empty());
        assert!(!root.join(DBP_FILE).exists());

        // 1 seed: targets + git files + the root DBP created, the nested one
        // (nearest of tests/T) edited with a `../` prefix, CRLF kept.
        plant_seed(root, "Newtonsoft.Json", "13.0.1", UUID).await;
        let changed = sync_shared(root, false).await.unwrap();
        assert_eq!(changed.len(), 5, "{changed:?}");
        let targets =
            std::fs::read_to_string(root.join(NUGET_VENDOR_REL).join(TARGETS_FILE)).unwrap();
        assert!(targets.contains(UUID));
        assert_eq!(
            std::fs::read_to_string(root.join(DBP_FILE)).unwrap(),
            super::super::nuget_targets::created_dbp("")
        );
        let nested = std::fs::read_to_string(root.join("tests/Directory.Build.props")).unwrap();
        assert!(nested.contains("$(MSBuildThisFileDirectory)../.socket/vendor/nuget/socket-patch."));
        assert!(!nested.replace("\r\n", "").contains('\n'), "CRLF kept");
        assert!(
            sync_shared(root, false).await.unwrap().is_empty(),
            "idempotent"
        );

        // 2 seeds: both rendered, sorted by uuid.
        plant_seed(root, "Humanizer.Core", "2.14.1", UUID2).await;
        let changed = sync_shared(root, false).await.unwrap();
        assert_eq!(changed.len(), 2, "targets + gitignore: {changed:?}");
        let targets =
            std::fs::read_to_string(root.join(NUGET_VENDOR_REL).join(TARGETS_FILE)).unwrap();
        assert!(targets.find(UUID2).unwrap() < targets.find(UUID).unwrap());
        let gitignore =
            std::fs::read_to_string(root.join(NUGET_VENDOR_REL).join(GITIGNORE_FILE)).unwrap();
        assert!(gitignore.contains(UUID) && gitignore.contains(UUID2));

        // Dry run of the last removal writes nothing.
        remove_tree(&root.join(NUGET_VENDOR_REL).join(UUID))
            .await
            .unwrap();
        remove_tree(&root.join(NUGET_VENDOR_REL).join(UUID2))
            .await
            .unwrap();
        let planned = sync_shared(root, true).await.unwrap();
        assert_eq!(planned.len(), 5);
        assert!(root.join(DBP_FILE).exists());

        // Back to 0: the created DBP deleted, the nested one byte-restored,
        // the generated files gone and the vendor dir pruned.
        sync_shared(root, false).await.unwrap();
        assert!(!root.join(DBP_FILE).exists());
        assert_eq!(
            std::fs::read(root.join("tests/Directory.Build.props")).unwrap(),
            nested_before
        );
        assert!(!root.join(NUGET_VENDOR_REL).exists());
    }

    #[tokio::test]
    async fn an_edited_root_dbp_survives_the_last_revert() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        project(root, "App.csproj");
        plant_seed(root, "Newtonsoft.Json", "13.0.1", UUID).await;
        sync_shared(root, false).await.unwrap();
        let wired = std::fs::read_to_string(root.join(DBP_FILE)).unwrap();
        let edited = wired.replace(
            "<Project>\n",
            "<Project>\n  <PropertyGroup><B>2</B></PropertyGroup>\n",
        );
        std::fs::write(root.join(DBP_FILE), &edited).unwrap();
        remove_tree(&root.join(NUGET_VENDOR_REL).join(UUID))
            .await
            .unwrap();
        sync_shared(root, false).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join(DBP_FILE)).unwrap(),
            "<Project>\n  <PropertyGroup><B>2</B></PropertyGroup>\n</Project>\n"
        );
    }

    #[tokio::test]
    async fn a_users_empty_dbp_survives_the_last_revert() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        project(root, "a/A/A.csproj");
        project(root, "b/B/B.csproj");
        std::fs::write(root.join(DBP_FILE), "<Project>\n</Project>\n").unwrap();
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::write(root.join("a").join(DBP_FILE), "<Project>\r\n</Project>\r\n").unwrap();
        plant_seed(root, "Newtonsoft.Json", "13.0.1", UUID).await;
        sync_shared(root, false).await.unwrap();
        assert!(std::fs::read_to_string(root.join("a").join(DBP_FILE))
            .unwrap()
            .contains(DBP_BEGIN_TEST));
        remove_tree(&root.join(NUGET_VENDOR_REL).join(UUID))
            .await
            .unwrap();
        sync_shared(root, false).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join(DBP_FILE)).unwrap(),
            "<Project>\n</Project>\n"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("a").join(DBP_FILE)).unwrap(),
            "<Project>\r\n</Project>\r\n"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_props_and_locks_refuse() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        project(root, "src/Lib/Lib.csproj");
        std::fs::create_dir_all(root.join("shared")).unwrap();
        std::fs::write(root.join("shared/common.props"), "<Project>\n</Project>\n").unwrap();
        std::os::unix::fs::symlink("../shared/common.props", root.join("src").join(DBP_FILE))
            .unwrap();
        plant_seed(root, "Newtonsoft.Json", "13.0.1", UUID).await;
        let err = sync_shared(root, false).await.unwrap_err();
        assert!(err.contains("src/Directory.Build.props"), "{err}");
        assert!(!root.join(DBP_FILE).exists(), "nothing written");
        let d = discover(root).await;
        assert_eq!(d.symlinks, vec!["src/Directory.Build.props".to_string()]);
    }

    #[tokio::test]
    async fn the_ledger_inventory_outranks_an_edited_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        project(root, "App.csproj");
        plant_seed(root, "Newtonsoft.Json", "13.0.1", UUID).await;
        let recorded = marker("Newtonsoft.Json", "13.0.1", UUID)
            .nuget
            .unwrap()
            .inventory;
        let mut state = super::super::state::VendorState::new();
        state.entries.insert(
            "pkg:nuget/Newtonsoft.Json@13.0.1".into(),
            VendorEntry {
                ecosystem: "nuget".into(),
                base_purl: "pkg:nuget/Newtonsoft.Json@13.0.1".into(),
                uuid: UUID.into(),
                artifact: VendorArtifact {
                    path: format!(".socket/vendor/nuget/{UUID}/newtonsoft.json/{SOCKET_V}"),
                    sha256: String::new(),
                    size: None,
                    platform_locked: None,
                    file_inventory: Some(recorded),
                },
                wiring: Vec::new(),
                lock: None,
                took_over_go_patches: false,
                detached: false,
                record: None,
                flavor: Some(NUGET_FALLBACK_FLAVOR.into()),
                uv: None,
                pnpm: None,
                poetry: None,
                pdm: None,
                pipenv: None,
            },
        );
        super::super::state::save_state(root, &state).await.unwrap();
        let dir = root.join(NUGET_VENDOR_REL).join(UUID);
        let mut tampered = marker("Newtonsoft.Json", "13.0.1", UUID);
        tampered
            .nuget
            .as_mut()
            .unwrap()
            .inventory
            .insert("lib/x.dll".into(), "c".repeat(64));
        write_marker(&dir, &tampered).await.unwrap();
        sync_shared(root, false).await.unwrap();
        let targets =
            std::fs::read_to_string(root.join(NUGET_VENDOR_REL).join(TARGETS_FILE)).unwrap();
        assert!(targets.contains(&"B".repeat(64)) && !targets.contains(&"C".repeat(64)));
        // The seed this run just wrote renders from its own marker.
        let fresh = fallback_seeds(
            root,
            RenderScope {
                fresh: Some(UUID),
                exclude: &[],
            },
        )
        .await;
        assert_eq!(fresh[0].1.inventory["lib/x.dll"], "c".repeat(64));
        // A superseded uuid is left out.
        let excluded = [UUID.to_string()];
        let none = fallback_seeds(
            root,
            RenderScope {
                fresh: None,
                exclude: &excluded,
            },
        )
        .await;
        assert!(none.is_empty());
    }

    #[tokio::test]
    async fn signature_require_is_found_between_a_project_and_the_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        project(&root, "src/Lib/Lib.csproj");
        std::fs::write(
            root.join("src/nuget.config"),
            "<configuration><config><add key=\"signatureValidationMode\" value=\"require\" \
             /></config></configuration>",
        )
        .unwrap();
        let d = discover(&root).await;
        assert_eq!(
            signature_require(&root, &d).await,
            Some(root.join("src/nuget.config"))
        );
    }

    #[tokio::test]
    async fn a_legacy_feed_entry_keeps_its_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let entry = |purl: &str, flavor: Option<&str>, uuid: &str| VendorEntry {
            ecosystem: "nuget".into(),
            base_purl: purl.into(),
            uuid: uuid.into(),
            artifact: VendorArtifact {
                path: String::new(),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: flavor.map(str::to_string),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        };
        let mut state = super::super::state::VendorState::new();
        state
            .entries
            .insert("a".into(), entry("pkg:nuget/A@1.0.0", None, UUID));
        state.entries.insert(
            "b".into(),
            entry("pkg:nuget/B@1.0.0", Some(NUGET_FALLBACK_FLAVOR), UUID2),
        );
        super::super::state::save_state(root, &state).await.unwrap();
        assert!(!fallback_layout_for("pkg:nuget/A@1.0.0", root).await);
        assert!(fallback_layout_for("pkg:nuget/C@1.0.0", root).await);
    }

    #[tokio::test]
    async fn unwired_and_unrenderable_markers_are_not_rendered() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        project(root, "App.csproj");
        let dir = root.join(NUGET_VENDOR_REL).join(UUID);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut m = marker("Newtonsoft.Json", "13.0.1", UUID);
        m.nuget.as_mut().unwrap().wired = false;
        write_marker(&dir, &m).await.unwrap();
        assert!(fallback_seeds(root, RenderScope::default())
            .await
            .is_empty());
        m.nuget.as_mut().unwrap().wired = true;
        m.nuget.as_mut().unwrap().id = "Evil\"".into();
        write_marker(&dir, &m).await.unwrap();
        assert!(fallback_seeds(root, RenderScope::default())
            .await
            .is_empty());
    }

    #[test]
    fn msbuild_scan_classifies_versions() {
        let texts = |s: &str| vec![("x.csproj".to_string(), blank_comments(s))];
        let scan = scan_msbuild(
            &texts(
                "<PackageReference Include=\"newtonsoft.json\" Version=\"13.0.01\" />\
                 <!-- <PackageReference Include=\"Newtonsoft.Json\" Version=\"$(X)\" /> -->\
                 <PackageVersion Include=\"Newtonsoft.Json\"><Version>13.0.1.0</Version></PackageVersion>\
                 <PackageReference Include=\"Other\" Version=\"$(Y)\" />\
                 <PackageReference Include=\"Newtonsoft.Json\" Version=\"12.0.3\" />\
                 <CentralPackageTransitivePinningEnabled> true </CentralPackageTransitivePinningEnabled>",
            ),
            "Newtonsoft.Json",
            "13.0.1",
        )
        .unwrap();
        assert_eq!(
            scan.spellings.iter().cloned().collect::<Vec<_>>(),
            ["13.0.01", "13.0.1.0"]
        );
        assert!(scan.pinning);
        for (text, code) in [
            (
                "<PackageReference Include=\"Newtonsoft.Json\" Version=\"$(NjVersion)\" />",
                "vendor_nuget_version_literal_unknown",
            ),
            (
                "<PackageReference Include=\"Newtonsoft.Json\" Version=\"[13.0.1]\" />",
                "vendor_nuget_range_unsupported",
            ),
            (
                "<PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.*\" />",
                "vendor_nuget_range_unsupported",
            ),
            (
                "<PackageReference Include=\"Newtonsoft.Json\" VersionOverride=\"13.0.1\" />",
                "vendor_nuget_version_override",
            ),
            (
                "<PropertyGroup><ImportDirectoryBuildProps>False</ImportDirectoryBuildProps></PropertyGroup>",
                "vendor_nuget_dbp_disabled",
            ),
        ] {
            let err = scan_msbuild(&texts(text), "Newtonsoft.Json", "13.0.1").unwrap_err();
            assert_eq!(err.0, code, "{text}");
        }
    }

    #[test]
    fn nearest_dbp_and_rel_prefix() {
        let mut d = Discovery::default();
        d.dbps.insert("src/Directory.Build.props".into());
        let p = |rel: &str, dir: &str| Project {
            rel: rel.into(),
            dir: dir.into(),
            text: String::new(),
            sdk: true,
        };
        assert_eq!(
            d.nearest_dbp(&p("src/Lib/Lib.csproj", "src/Lib")),
            "src/Directory.Build.props"
        );
        assert_eq!(d.nearest_dbp(&p("t/T/T.csproj", "t/T")), DBP_FILE);
        assert_eq!(d.nearest_dbp(&p("A.csproj", "")), DBP_FILE);
        assert_eq!(dbp_rel_prefix("Directory.Build.props"), "");
        assert_eq!(dbp_rel_prefix("a/b/Directory.Build.props"), "../../");
    }

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/nuget-fallback");

    fn fixture(rel: &str) -> String {
        std::fs::read_to_string(format!("{FIXTURES}/{rel}")).unwrap()
    }

    fn lock_target() -> LockTarget<'static> {
        LockTarget {
            id: "Newtonsoft.Json",
            version: "13.0.1",
            socket_version: SOCKET_V,
            content_hash: "",
            transitive_pinning: false,
        }
    }

    #[tokio::test]
    async fn lock_revert_unsplices_this_entry_and_tolerates_crlf() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("src/Lib")).unwrap();
        let before = fixture("sln/before/src/Lib/packages.lock.json");
        let after = fixture("sln/after/src/Lib/packages.lock.json");
        let w = WiringRecord {
            file: "src/Lib/packages.lock.json".into(),
            kind: LOCK_WIRING_KIND.into(),
            action: WiringAction::Rewritten,
            key: Some("Newtonsoft.Json".into()),
            original: Some(Value::String(before.clone())),
            new: Some(Value::String(after.clone())),
        };
        let path = root.join(&w.file);
        let t = lock_target();
        std::fs::write(&path, after.replace('\n', "\r\n")).unwrap();
        assert!(matches!(
            revert_lock_file(root, &w, Some(&t), false).await.unwrap(),
            LockRevert::Restored
        ));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            before.replace('\n', "\r\n")
        );
        // Already reverted: a no-op.
        assert!(matches!(
            revert_lock_file(root, &w, Some(&t), false).await.unwrap(),
            LockRevert::Restored
        ));
        // No recorded original: the ranges and versions revert, the hash
        // cannot — the lock is left pinning V′ (drift).
        let mut bare = w.clone();
        bare.original = None;
        std::fs::write(&path, &after).unwrap();
        assert!(matches!(
            revert_lock_file(root, &bare, Some(&t), false).await.unwrap(),
            LockRevert::Drifted(Some(live)) if live.contains(SOCKET_V)
        ));
        let mut bad = w.clone();
        bad.file = "../packages.lock.json".into();
        assert!(matches!(
            revert_lock_file(root, &bad, Some(&t), false).await.unwrap(),
            LockRevert::Drifted(None)
        ));
    }

    /// Two seeds share a lock: each revert takes back only its own values,
    /// in either order.
    #[tokio::test]
    async fn shared_lock_reverts_in_any_order() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("src/Lib")).unwrap();
        let before = "{\n  \"version\": 1,\n  \"dependencies\": {\n    \"net8.0\": {\n      \
                      \"Humanizer.Core\": {\n        \"type\": \"Direct\",\n        \
                      \"requested\": \"[2.14.1, )\",\n        \"resolved\": \"2.14.1\",\n        \
                      \"contentHash\": \"aHVt\"\n      },\n      \"Newtonsoft.Json\": {\n        \
                      \"type\": \"Direct\",\n        \"requested\": \"[13.0.1, )\",\n        \
                      \"resolved\": \"13.0.1\",\n        \"contentHash\": \"bmo=\"\n      }\n    \
                      }\n  }\n}";
        let b_vp = socket_nuget_version("2.14.1", UUID2).unwrap();
        let a = LockTarget {
            content_hash: "QQ==",
            ..lock_target()
        };
        let b = LockTarget {
            id: "Humanizer.Core",
            version: "2.14.1",
            socket_version: &b_vp,
            content_hash: "Qg==",
            transitive_pinning: false,
        };
        let a_only = splice_lock(before, &a).unwrap().text;
        let both = splice_lock(&a_only, &b).unwrap().text;
        let b_only = splice_lock(before, &b).unwrap().text;
        let path = root.join("src/Lib/packages.lock.json");
        let rec = |original: &str| WiringRecord {
            file: "src/Lib/packages.lock.json".into(),
            kind: LOCK_WIRING_KIND.into(),
            action: WiringAction::Rewritten,
            key: None,
            original: Some(Value::String(original.to_string())),
            new: None,
        };
        let (rec_a, rec_b) = (rec(before), rec(&a_only));
        for (first, second, middle) in [
            ((&rec_a, &a), (&rec_b, &b), &b_only),
            ((&rec_b, &b), (&rec_a, &a), &a_only),
        ] {
            std::fs::write(&path, &both).unwrap();
            for ((w, t), want) in [(first, middle.as_str()), (second, before)] {
                assert!(matches!(
                    revert_lock_file(root, w, Some(t), false).await.unwrap(),
                    LockRevert::Restored
                ));
                assert_eq!(std::fs::read_to_string(&path).unwrap(), want);
            }
        }
    }

    #[tokio::test]
    async fn lock_records_round_trip_through_the_compressed_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let original = format!(
            "{{\n  \"pad\": \"{}\",\n  \"v\": \"13.0.1\"\n}}",
            "x".repeat(2048)
        );
        let new = original.replace("13.0.1", SOCKET_V);
        let mut state = super::super::state::VendorState::new();
        state.entries.insert(
            "pkg:nuget/Newtonsoft.Json@13.0.1".into(),
            VendorEntry {
                ecosystem: "nuget".into(),
                base_purl: "pkg:nuget/Newtonsoft.Json@13.0.1".into(),
                uuid: UUID.into(),
                artifact: VendorArtifact {
                    path: format!(".socket/vendor/nuget/{UUID}/newtonsoft.json/{SOCKET_V}"),
                    sha256: String::new(),
                    size: None,
                    platform_locked: None,
                    file_inventory: Some(BTreeMap::new()),
                },
                wiring: vec![WiringRecord {
                    file: "src/Lib/packages.lock.json".into(),
                    kind: LOCK_WIRING_KIND.into(),
                    action: WiringAction::Rewritten,
                    key: Some("Newtonsoft.Json".into()),
                    original: Some(Value::String(original)),
                    new: Some(Value::String(new)),
                }],
                lock: None,
                took_over_go_patches: false,
                detached: false,
                record: None,
                flavor: Some(NUGET_FALLBACK_FLAVOR.into()),
                uv: None,
                pnpm: None,
                poetry: None,
                pdm: None,
                pipenv: None,
            },
        );
        super::super::state::save_state(root, &state).await.unwrap();
        let on_disk = std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap();
        assert!(
            on_disk.contains("\"snapshot\""),
            "the large `new` is stored as an edit"
        );
        assert_eq!(load_state(root).await.unwrap(), state);
    }

    #[tokio::test]
    async fn rendered_references_name_every_seed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        project(root, "App.csproj");
        plant_seed(root, "Newtonsoft.Json", "13.0.1", UUID).await;
        sync_shared(root, false).await.unwrap();
        assert_eq!(
            rendered_seed_references(root).await,
            vec![(
                UUID.to_string(),
                format!(".socket/vendor/nuget/{UUID}/newtonsoft.json/13.0.1.1340506223")
            )]
        );
    }
}
